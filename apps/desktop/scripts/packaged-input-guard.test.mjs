// packaged-input-guard.test.mjs — A5/A4 packaged-input identity behavior tests
// (complete transitive closure + shadow-file exploit coverage).

import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  assertPackagedInputClean,
  DESKTOP_PACKAGED_INPUT_PATHS,
  DESKTOP_SHADOW_PATHS,
  desktopPackagedInputPaths,
  workspaceManifestPaths
} from './packaged-input-guard.mjs'

const FULL = 'a'.repeat(40)

function git({ head = FULL, status = '', ignored = '' } = {}) {
  return (cmd) => {
    if (cmd.includes('rev-parse HEAD')) return head
    if (cmd.includes('--ignored')) return ignored
    if (cmd.startsWith('git status')) return status
    return ''
  }
}

test('passes for a clean tree whose HEAD matches the pinned commit', () => {
  const res = assertPackagedInputClean({ stampedCommit: FULL, execFn: git() })
  assert.equal(res.head, FULL)
})

test('scopes the status check to the packaged paths', () => {
  const calls = []
  const execFn = (cmd) => {
    calls.push(cmd)
    if (cmd.includes('rev-parse HEAD')) return FULL
    if (cmd.startsWith('git status')) return ''
    return ''
  }
  assertPackagedInputClean({ stampedCommit: FULL, packagedPaths: ['apps/desktop', 'scripts'], execFn })
  assert.ok(calls.some((c) => c.includes('--untracked-files=all -- apps/desktop scripts')))
})

test('fails closed when git is unavailable (rev-parse null)', () => {
  assert.throws(() => assertPackagedInputClean({ stampedCommit: FULL, execFn: () => null }), /git is unavailable/)
})

test('rejects a HEAD that is not a full 40-char SHA', () => {
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, execFn: git({ head: 'abc1234' }) }),
    /not a full 40-char/
  )
})

test('rejects a HEAD that does not match the stamped commit', () => {
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, execFn: git({ head: 'b'.repeat(40) }) }),
    /does NOT match the stamped/
  )
})

test('rejects a tracked change in the packaged paths', () => {
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, execFn: git({ status: ' M apps/desktop/electron/main.ts' }) }),
    /not clean/i
  )
})

test('rejects an untracked file (--untracked-files=all) in the packaged paths', () => {
  assert.throws(
    () =>
      assertPackagedInputClean({
        stampedCommit: FULL,
        execFn: git({ status: '?? apps/desktop/src/plugins/evil/plugin.ts' })
      }),
    /not clean/i
  )
})

test('fails closed when git status is unavailable', () => {
  const execFn = (cmd) => {
    if (cmd.includes('rev-parse HEAD')) return FULL
    if (cmd.startsWith('git status')) return null
    return ''
  }
  assert.throws(() => assertPackagedInputClean({ stampedCommit: FULL, execFn }), /git status is unavailable/)
})

test('without a stampedCommit, only clean-tree is required (HEAD compare skipped)', () => {
  const res = assertPackagedInputClean({ execFn: git({ head: 'c'.repeat(40) }) })
  assert.equal(res.head, 'c'.repeat(40))
})

// ── A4/A5 complete-closure + shadow-file exploit coverage ──────────────────

test('the closure includes apps/desktop, apps/shared, root manifests, lock, supply-chain', () => {
  for (const p of ['apps/desktop', 'apps/shared', 'package.json', 'package-lock.json', 'supply-chain/manifest.json']) {
    assert.ok(DESKTOP_PACKAGED_INPUT_PATHS.includes(p), `closure must include ${p}`)
  }
})

test('workspaceManifestPaths expands the workspaces globs', () => {
  const paths = workspaceManifestPaths('/repo', {
    read: () => JSON.stringify({ workspaces: ['apps/*', 'web'] }),
    exists: () => true,
    readdir: (dir) =>
      dir.endsWith('apps')
        ? [{ name: 'desktop', isDirectory: () => true }, { name: 'shared', isDirectory: () => true }]
        : []
  })
  assert.ok(paths.includes('apps/desktop/package.json'))
  assert.ok(paths.includes('apps/shared/package.json'))
  assert.ok(paths.includes('web/package.json'))
})

test('desktopPackagedInputPaths appends non-desktop/shared workspace manifests', () => {
  const paths = desktopPackagedInputPaths('/repo', {
    read: () => JSON.stringify({ workspaces: ['apps/*', 'web'] }),
    exists: () => true,
    readdir: (dir) =>
      dir.endsWith('apps')
        ? [{ name: 'desktop', isDirectory: () => true }, { name: 'bootstrap-installer', isDirectory: () => true }]
        : []
  })
  assert.ok(paths.includes('apps/bootstrap-installer/package.json'))
  assert.ok(paths.includes('web/package.json'))
  // apps/desktop/package.json is already covered by the apps/desktop dir entry.
  assert.ok(!paths.includes('apps/desktop/package.json'))
})

test('EXPLOIT: an untracked apps/shared/src/index.js shadowing index.ts is REJECTED (ignored scan)', () => {
  // The main scan is CLEAN — the .js is gitignored, so --untracked-files=all
  // misses it. Only the --ignored shadow scan catches it.
  assert.throws(
    () =>
      assertPackagedInputClean({
        stampedCommit: FULL,
        shadowPaths: DESKTOP_SHADOW_PATHS,
        execFn: git({ status: '', ignored: '!! apps/shared/src/index.js' })
      }),
    /SHADOW|shadow/
  )
})

test('EXPLOIT: a changed root package-lock.json is REJECTED', () => {
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, execFn: git({ status: ' M package-lock.json' }) }),
    /not clean/i
  )
})

test('EXPLOIT: a changed root package.json is REJECTED', () => {
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, execFn: git({ status: ' M package.json' }) }),
    /not clean/i
  )
})

test('EXPLOIT: an untracked native staging script/config is REJECTED', () => {
  assert.throws(
    () =>
      assertPackagedInputClean({
        stampedCommit: FULL,
        execFn: git({ status: '?? apps/desktop/scripts/evil-stage.mjs' })
      }),
    /not clean/i
  )
})

test('a clean tree passes even with the shadow scan enabled', () => {
  const res = assertPackagedInputClean({
    stampedCommit: FULL,
    shadowPaths: DESKTOP_SHADOW_PATHS,
    execFn: git({ status: '', ignored: '' })
  })
  assert.equal(res.head, FULL)
})

test('the shadow scan fails closed when git --ignored is unavailable', () => {
  const execFn = (cmd) => {
    if (cmd.includes('rev-parse HEAD')) return FULL
    if (cmd.includes('--ignored')) return null
    if (cmd.startsWith('git status')) return ''
    return ''
  }
  assert.throws(
    () => assertPackagedInputClean({ stampedCommit: FULL, shadowPaths: DESKTOP_SHADOW_PATHS, execFn }),
    /--ignored is unavailable/
  )
})
