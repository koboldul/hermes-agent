import assert from 'node:assert/strict'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { describe, test } from 'vitest'

import {
  supplyChainAllowsUnverified,
  desktopActivationDecision,
  desktopBundleDigest,
  atomicSwapWithRollback
} from './desktop-plugin-install'

describe('desktop plugin atomic publication (WP4 item 2: backup + rollback)', () => {
  async function seed() {
    const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'hermes-swap-'))
    const targetDir = path.join(root, 'plug')
    const stageDir = `${targetDir}.stage`
    const backupDir = `${targetDir}.backup`
    // Existing (old, working) install.
    await fsp.mkdir(targetDir, { recursive: true })
    await fsp.writeFile(path.join(targetDir, 'plugin.js'), 'OLD\n')
    await fsp.writeFile(path.join(targetDir, 'meta.json'), '{"v":1}\n')
    // Staged (new) install.
    await fsp.mkdir(stageDir, { recursive: true })
    await fsp.writeFile(path.join(stageDir, 'plugin.js'), 'NEW\n')
    return { root, targetDir, stageDir, backupDir }
  }

  test('successful swap replaces the tree and clears the backup', async () => {
    const { root, targetDir, stageDir, backupDir } = await seed()
    try {
      const res = await atomicSwapWithRollback({
        stageDir, targetDir, backupDir, hadExisting: true,
        rename: (a, b) => fsp.rename(a, b),
        rm: (p) => fsp.rm(p, { recursive: true, force: true }).then(() => undefined)
      })
      assert.equal(res.ok, true)
      assert.equal(await fsp.readFile(path.join(targetDir, 'plugin.js'), 'utf8'), 'NEW\n')
    } finally {
      await fsp.rm(root, { recursive: true, force: true })
    }
  })

  test('injected rename failure preserves the OLD tree and its metadata', async () => {
    const { root, targetDir, stageDir, backupDir } = await seed()
    try {
      let call = 0
      const res = await atomicSwapWithRollback({
        stageDir, targetDir, backupDir, hadExisting: true,
        // First rename (target->backup) succeeds; second (stage->target) throws.
        rename: async (a, b) => {
          call += 1
          if (call === 2) throw new Error('simulated rename failure')
          await fsp.rename(a, b)
        },
        rm: (p) => fsp.rm(p, { recursive: true, force: true }).then(() => undefined)
      })
      assert.equal(res.ok, false)
      // The old working plugin + metadata must be intact at targetDir.
      assert.equal(await fsp.readFile(path.join(targetDir, 'plugin.js'), 'utf8'), 'OLD\n')
      assert.equal(await fsp.readFile(path.join(targetDir, 'meta.json'), 'utf8'), '{"v":1}\n')
    } finally {
      await fsp.rm(root, { recursive: true, force: true })
    }
  })
})

describe('desktop plugin activation (WP4 item 4: exact ref + expected digest)', () => {
  test('exact ref + matching expected digest activates without break-glass', () => {
    const d = desktopActivationDecision({
      pinnedRef: 'a'.repeat(40),
      expectedDigest: 'deadbeef',
      computedDigest: 'deadbeef',
      breakGlass: false
    })
    assert.equal(d.allow, true)
  })

  test('mutation: a tampered bundle (digest mismatch) is denied', () => {
    const d = desktopActivationDecision({
      pinnedRef: 'a'.repeat(40),
      expectedDigest: 'deadbeef',
      computedDigest: 'feedface',
      breakGlass: false
    })
    assert.equal(d.allow, false)
    assert.match(d.reason, /digest mismatch/)
  })

  test('commit alone (no expected digest) is NOT sufficient', () => {
    const d = desktopActivationDecision({
      pinnedRef: 'a'.repeat(40),
      expectedDigest: null,
      computedDigest: 'x',
      breakGlass: false
    })
    assert.equal(d.allow, false)
  })

  test('a non-40-char ref with a digest is rejected', () => {
    const d = desktopActivationDecision({
      pinnedRef: 'main',
      expectedDigest: 'x',
      computedDigest: 'x',
      breakGlass: false
    })
    assert.equal(d.allow, false)
    assert.match(d.reason, /40-char/)
  })

  test('break-glass opt-in activates (labelled unverified)', () => {
    const d = desktopActivationDecision({ pinnedRef: null, expectedDigest: null, computedDigest: 'x', breakGlass: true })
    assert.equal(d.allow, true)
  })

  test('default (no digest, no break-glass) is denied', () => {
    const d = desktopActivationDecision({ pinnedRef: null, expectedDigest: null, computedDigest: 'x', breakGlass: false })
    assert.equal(d.allow, false)
  })

  test('desktopBundleDigest is deterministic and mutation-sensitive', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'hermes-dpd-'))
    try {
      await fsp.writeFile(path.join(dir, 'plugin.js'), 'export default {}\n')
      await fsp.mkdir(path.join(dir, 'lib'))
      await fsp.writeFile(path.join(dir, 'lib', 'a.js'), 'const x = 1\n')
      const d1 = await desktopBundleDigest(dir)
      const d2 = await desktopBundleDigest(dir)
      assert.equal(d1, d2, 'digest must be deterministic')
      // Mutate one byte -> digest changes.
      await fsp.writeFile(path.join(dir, 'lib', 'a.js'), 'const x = 2\n')
      const d3 = await desktopBundleDigest(dir)
      assert.notEqual(d1, d3, 'digest must change when content changes')
    } finally {
      await fsp.rm(dir, { recursive: true, force: true })
    }
  })
})

describe('desktop plugin supply-chain gate', () => {
  const withBlock = (body: string) => `security:\n  supply_chain:\n${body}`

  test('denies by default when no supply_chain block', () => {
    assert.equal(supplyChainAllowsUnverified('plugins', 'security:\n  redact_secrets: true\n'), false)
  })

  test('denies when enforce is true and no allow-list', () => {
    assert.equal(
      supplyChainAllowsUnverified('plugins', withBlock('    enforce: true\n    allow_unverified_components: []\n')),
      false
    )
  })

  test('enforce:false alone does NOT authorize (scoped-consent rule, item 5)', () => {
    assert.equal(supplyChainAllowsUnverified('plugins', withBlock('    enforce: false\n')), false)
    // even with enforce:false, authorization needs the explicit allow-list
    assert.equal(
      supplyChainAllowsUnverified('plugins', withBlock('    enforce: false\n    allow_unverified_components: ["plugins"]\n')),
      true
    )
  })

  test('inline allow-list containing plugins opts in', () => {
    assert.equal(
      supplyChainAllowsUnverified('plugins', withBlock('    enforce: true\n    allow_unverified_components: ["plugins"]\n')),
      true
    )
  })

  test('scoped: allowing another component does NOT enable plugins', () => {
    assert.equal(
      supplyChainAllowsUnverified('plugins', withBlock('    allow_unverified_components: ["uv", "node"]\n')),
      false
    )
  })

  test('wildcard allows any component', () => {
    assert.equal(supplyChainAllowsUnverified('plugins', withBlock('    allow_unverified_components: ["*"]\n')), true)
  })

  test('block/dash list form is honored', () => {
    assert.equal(
      supplyChainAllowsUnverified('plugins', withBlock('    allow_unverified_components:\n      - plugins\n')),
      true
    )
  })

  test('enforce:false elsewhere (not under supply_chain) does not leak', () => {
    const cfg = 'other:\n  enforce: false\nsecurity:\n  supply_chain:\n    enforce: true\n'
    assert.equal(supplyChainAllowsUnverified('plugins', cfg), false)
  })
})
