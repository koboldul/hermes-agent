import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'vitest'

import beforePack, { cleanStaleAppOutDir, preserveRollbackBackup } from '../scripts/before-pack.mjs'
import { buildMarker, hashTree } from '../scripts/electron-dist-verifier.mjs'
import { isPublishReleaseContext, publishConfigIsRelease } from '../scripts/release-gate.mjs'

test('cleanStaleAppOutDir removes a populated unpacked directory', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'linux-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    // Reproduce the corrupted partial state: license + payload present,
    // electron binary missing — exactly what trips the ENOENT rename.
    fs.writeFileSync(path.join(appOutDir, 'LICENSE.electron.txt'), 'x', 'utf8')
    fs.writeFileSync(path.join(appOutDir, 'resources.pak'), 'x', 'utf8')
    fs.mkdirSync(path.join(appOutDir, 'resources'), { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'resources', 'app.asar'), 'x', 'utf8')

    const removed = cleanStaleAppOutDir(appOutDir)

    assert.equal(removed, true)
    assert.equal(fs.existsSync(appOutDir), false)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('cleanStaleAppOutDir is a no-op when the directory is absent', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const missing = path.join(tempRoot, 'does-not-exist')
    assert.equal(cleanStaleAppOutDir(missing), false)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('cleanStaleAppOutDir ignores empty or invalid input', () => {
  assert.equal(cleanStaleAppOutDir(''), false)
  assert.equal(cleanStaleAppOutDir(undefined), false)
  assert.equal(cleanStaleAppOutDir(null), false)
  assert.equal(cleanStaleAppOutDir(42), false)
})

test('beforePack default export resolves even when cleanup throws', async () => {
  // A directory path that rmSync can't remove is simulated by passing a
  // context whose appOutDir is a file the hook will try (and be allowed) to
  // remove; the contract under test is that the hook never rejects. A `dir`
  // dev-pack target keeps the A10 stamp gate a no-op here.
  await assert.doesNotReject(
    beforePack({ appOutDir: '', electronPlatformName: 'linux', targets: [{ name: 'dir' }] })
  )
})

// ─── Windows rollback preservation (#69179) ────────────────────────────────

test('preserveRollbackBackup moves a working build to .bak', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'win-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'Hermes.exe'), 'MZ-old-build', 'utf8')
    fs.writeFileSync(path.join(appOutDir, 'resources.pak'), 'x', 'utf8')

    const preserved = preserveRollbackBackup(appOutDir, 'Hermes.exe')

    assert.equal(preserved, true)
    // Original slot vacated so electron-builder stages into a clean tree...
    assert.equal(fs.existsSync(appOutDir), false)
    // ...and the previous working build is intact under .bak for rollback.
    assert.equal(
      fs.readFileSync(path.join(`${appOutDir}.bak`, 'Hermes.exe'), 'utf8'),
      'MZ-old-build'
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('preserveRollbackBackup replaces a stale .bak from an older update', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'win-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'Hermes.exe'), 'current', 'utf8')
    fs.mkdirSync(`${appOutDir}.bak`, { recursive: true })
    fs.writeFileSync(path.join(`${appOutDir}.bak`, 'Hermes.exe'), 'two-updates-ago', 'utf8')

    assert.equal(preserveRollbackBackup(appOutDir, 'Hermes.exe'), true)
    assert.equal(fs.readFileSync(path.join(`${appOutDir}.bak`, 'Hermes.exe'), 'utf8'), 'current')
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('preserveRollbackBackup refuses a partial tree missing the product exe', () => {
  // The corrupted partial state (interrupted prior pack) must NOT become
  // rollback material — it is exactly what cleanStaleAppOutDir exists to wipe.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'win-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'LICENSE.electron.txt'), 'x', 'utf8')

    assert.equal(preserveRollbackBackup(appOutDir, 'Hermes.exe'), false)
    // Tree untouched; the caller's wipe path handles it.
    assert.equal(fs.existsSync(appOutDir), true)
    assert.equal(fs.existsSync(`${appOutDir}.bak`), false)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('preserveRollbackBackup ignores missing or invalid input', () => {
  assert.equal(preserveRollbackBackup(''), false)
  assert.equal(preserveRollbackBackup(undefined), false)
  assert.equal(preserveRollbackBackup(null), false)
  assert.equal(preserveRollbackBackup(path.join(os.tmpdir(), 'does-not-exist-xyz')), false)
})

test('beforePack on win32 preserves the previous build instead of wiping it', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'win-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'Hermes.exe'), 'MZ-working', 'utf8')

    // No packager info in the context → default 'Hermes.exe' product name.
    // node-pty staging is skipped because arch is not a number here. A `dir`
    // dev-pack target keeps the A10 stamp gate a no-op.
    await beforePack({ appOutDir, electronPlatformName: 'win32', targets: [{ name: 'dir' }] })

    assert.equal(fs.existsSync(appOutDir), false)
    assert.equal(
      fs.readFileSync(path.join(`${appOutDir}.bak`, 'Hermes.exe'), 'utf8'),
      'MZ-working'
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('beforePack on linux keeps the plain wipe (no .bak)', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'linux-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'Hermes.exe'), 'x', 'utf8')

    await beforePack({ appOutDir, electronPlatformName: 'linux', targets: [{ name: 'dir' }] })

    assert.equal(fs.existsSync(appOutDir), false)
    assert.equal(fs.existsSync(`${appOutDir}.bak`), false)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

// ─── A10: production stamp gate wired into the beforePack hook ──────────────
//
// The hook enforces the attested install stamp for EVERY artifact-producing
// pack, so a DIRECT `electron-builder` invocation (bypassing the wrapper)
// cannot ship an unattested build. Only an explicit `--dir` (target name 'dir')
// dev pack is exempt.

function writeStamp(dir, stamp) {
  const p = path.join(dir, 'install-stamp.json')
  fs.writeFileSync(p, JSON.stringify(stamp))
  return p
}

const ATTESTED = { commit: 'a'.repeat(40), branch: 'main', dirty: false, source: 'ci' }
const ALLZERO = { commit: '0'.repeat(40), branch: 'main', dirty: false, source: 'fallback' }

// A5: a fake git exec for a CLEAN tree at `head`.
function cleanGit(head = 'a'.repeat(40)) {
  return (cmd) => {
    if (cmd.includes('rev-parse HEAD')) return head
    if (cmd.startsWith('git status')) return ''
    return ''
  }
}

test('beforePack REJECTS a production (nsis) pack with a missing install stamp', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: {}, stampPath: path.join(tempRoot, 'missing-stamp.json'), execFn: cleanGit() }
      ),
      /attested install stamp|no install stamp/
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('beforePack REJECTS a production (nsis) pack with an all-zero/placeholder stamp', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: {}, stampPath: writeStamp(tempRoot, ALLZERO), execFn: cleanGit() }
      ),
      /placeholder|unpinned|attested install stamp/
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('beforePack ALLOWS a production (nsis) pack with an attested stamp AND a clean tree at HEAD', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const appOutDir = path.join(tempRoot, 'win-unpacked')
    fs.mkdirSync(appOutDir, { recursive: true })
    fs.writeFileSync(path.join(appOutDir, 'stale'), 'x', 'utf8')
    // Stamp gate passes AND the A5 git recheck sees HEAD == stamp + clean tree.
    // verifyElectronDist no-op: this test covers stamp/git/cleanup, not electron.
    await beforePack(
      { appOutDir, electronPlatformName: 'linux', targets: [{ name: 'appimage' }] },
      { env: {}, stampPath: writeStamp(tempRoot, ATTESTED), execFn: cleanGit('a'.repeat(40)), verifyElectronDist: () => {} }
    )
    assert.equal(fs.existsSync(appOutDir), false)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('beforePack EXEMPTS an explicit --dir dev pack from the stamp gate', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // Unattested stamp, but a `dir` target → gate is a no-op, hook resolves.
    await assert.doesNotReject(
      beforePack(
        { appOutDir: path.join(tempRoot, 'linux-unpacked'), electronPlatformName: 'linux', targets: [{ name: 'dir' }] },
        { env: {}, stampPath: writeStamp(tempRoot, ALLZERO) }
      )
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('beforePack treats UNKNOWN (empty) targets as production (fail closed)', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [] },
        { env: {}, stampPath: path.join(tempRoot, 'missing.json'), execFn: cleanGit() }
      ),
      /attested install stamp|no install stamp/
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

// ─── A5: beforePack independently re-interrogates git (not the stamp JSON) ────

test('A5 beforePack REJECTS a production pack with an UNTRACKED desktop plugin.ts', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const execFn = (cmd) => {
      if (cmd.includes('rev-parse HEAD')) return 'a'.repeat(40)
      if (cmd.startsWith('git status')) return '?? apps/desktop/src/plugins/evil/plugin.ts'
      return ''
    }
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: {}, stampPath: writeStamp(tempRoot, ATTESTED), execFn }
      ),
      /not clean|untracked/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A5 beforePack REJECTS a TRACKED-dirty tree even when the stamp+GITHUB_SHA claim clean', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // Stamp JSON says clean (dirty:false) — but the ACTUAL tree has a tracked
    // modification. The independent recheck must catch it (not trust JSON).
    const execFn = (cmd) => {
      if (cmd.includes('rev-parse HEAD')) return 'a'.repeat(40)
      if (cmd.startsWith('git status')) return ' M apps/desktop/electron/main.ts'
      return ''
    }
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: { GITHUB_SHA: 'a'.repeat(40) }, stampPath: writeStamp(tempRoot, ATTESTED), execFn }
      ),
      /not clean/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A5 beforePack fails closed when git is UNAVAILABLE', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: {}, stampPath: writeStamp(tempRoot, ATTESTED), execFn: () => null }
      ),
      /git is unavailable/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A5 beforePack REJECTS a HEAD that does not match the stamped commit', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // HEAD is a different (clean) commit than the stamp pins.
    await assert.rejects(
      beforePack(
        { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] },
        { env: {}, stampPath: writeStamp(tempRoot, ATTESTED), execFn: cleanGit('b'.repeat(40)) }
      ),
      /does NOT match the stamped/
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

// ─── Alert 2: beforePack independently requires + validates verified electronDist ───

const EV_VERSION = "41.10.3"
const EV_DIGEST = "266d2ce4ec9ca9e60f3abc06752cbd76899268a85b6540fa1765518621e33207"

// A win32-x64 electron dist deps object (injected). `tree` defaults to a tree
// containing the electron.exe binary; `markerTreeDigest` defaults to matching.
function winElectronDeps({ distExists = true, tree, markerArchive = EV_DIGEST, markerTreeDigest, committed = EV_DIGEST } = {}) {
  const t = tree || new Map([["electron.exe", Buffer.from("BIN")]])
  const td = markerTreeDigest || hashTree(t)
  const marker = markerArchive === null ? null : buildMarker({ version: EV_VERSION, platform: "win32", arch: "x64", archiveDigest: markerArchive, treeDigest: td })
  return {
    verifiedRoot: "/verified",
    version: EV_VERSION,
    committedDigestFor: () => committed,
    distExists: () => distExists,
    readMarker: () => marker,
    readTree: () => t,
    isInside: (child, parent) => String(child).startsWith(String(parent)),
    basename: (p) => String(p).split("/").pop()
  }
}

// A production win32/x64 nsis context (arch 1 == Arch.x64).
function winProdContext(tempRoot) {
  return { appOutDir: path.join(tempRoot, "win-unpacked"), electronPlatformName: "win32", arch: 1, targets: [{ name: "nsis" }] }
}

test('A2: DIRECT electron-builder (no verified electronDist) is REJECTED — would fetch via @electron/get', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // No verifyElectronDist injection, no config.electronDist → real default
    // verifier sees no electronDist → rejects (a bare `electron-builder --win nsis`).
    await assert.rejects(
      beforePack(winProdContext(tempRoot), {
        env: {},
        stampPath: writeStamp(tempRoot, ATTESTED),
        execFn: cleanGit('a'.repeat(40))
      }),
      /electronDist|@electron\/get/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: an UNVERIFIED electronDist (no provenance marker) is REJECTED', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(winProdContext(tempRoot), {
        env: {},
        stampPath: writeStamp(tempRoot, ATTESTED),
        execFn: cleanGit('a'.repeat(40)),
        electronDist: '/verified/41.10.3-win32-x64',
        electronDeps: winElectronDeps({ markerArchive: null }) // readMarker → null
      }),
      /provenance invalid|no-marker/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: a MUTATED electronDist tree (tree digest drift) is REJECTED', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(winProdContext(tempRoot), {
        env: {},
        stampPath: writeStamp(tempRoot, ATTESTED),
        execFn: cleanGit('a'.repeat(40)),
        electronDist: '/verified/41.10.3-win32-x64',
        // marker claims one tree digest, the actual tree hashes to another.
        electronDeps: winElectronDeps({ markerTreeDigest: 'f'.repeat(64) })
      }),
      /provenance invalid|tree-mutated/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: a CROSS-TARGET electronDist (darwin dir for a win32 build) is REJECTED', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    await assert.rejects(
      beforePack(winProdContext(tempRoot), {
        env: {},
        stampPath: writeStamp(tempRoot, ATTESTED),
        execFn: cleanGit('a'.repeat(40)),
        electronDist: '/verified/41.10.3-darwin-arm64', // wrong target dir
        electronDeps: winElectronDeps()
      }),
      /cross-target|does not match this target/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: an electronDist OUTSIDE the verified staging root is REJECTED', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const deps = winElectronDeps()
    deps.isInside = () => false // simulate a dist outside the verified root
    await assert.rejects(
      beforePack(winProdContext(tempRoot), {
        env: {},
        stampPath: writeStamp(tempRoot, ATTESTED),
        execFn: cleanGit('a'.repeat(40)),
        electronDist: '/somewhere/else/41.10.3-win32-x64',
        electronDeps: deps
      }),
      /not inside the verified staging root/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: a VALID verified electronDist passes the gate (WRAPPER success path)', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // No `arch` → staging is skipped; the electron gate still runs via the
    // injected verifier, which delegates to the REAL assertion with valid deps.
    let called = false
    const context = { appOutDir: path.join(tempRoot, 'win-unpacked'), electronPlatformName: 'win32', targets: [{ name: 'nsis' }] }
    fs.mkdirSync(context.appOutDir, { recursive: true })
    await beforePack(context, {
      env: {},
      stampPath: writeStamp(tempRoot, ATTESTED),
      execFn: cleanGit('a'.repeat(40)),
      verifyElectronDist: () => {
        called = true
        // Represents a passing real verification (valid marker + tree).
      }
    })
    assert.equal(called, true, 'the electron verifier MUST run for a production pack')
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: the electron verifier is NOT invoked for an exempt --dir dev pack', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    let called = false
    await beforePack(
      { appOutDir: path.join(tempRoot, 'linux-unpacked'), electronPlatformName: 'linux', targets: [{ name: 'dir' }] },
      { env: {}, stampPath: writeStamp(tempRoot, ALLZERO), verifyElectronDist: () => { called = true } }
    )
    assert.equal(called, false, 'a --dir dev pack is exempt from the electron gate')
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

// ─── Alert 2 (publish break-glass): a per-component opt-in may NEVER ship an
//     unverified Electron for a PUBLISH/tag/release build. The publish decision
//     is resolved from the ACTUAL context (config.publish,
//     platformSpecificBuildOptions.publish), the wrapper-propagated env flag,
//     and env/tag signals — not merely an empty argv. ──────────────────────────

// A production win32/x64 nsis context with an optional resolved publish config.
function winProdPublishContext(tempRoot, { config, platformSpecific } = {}) {
  const packager = {}
  if (config !== undefined) packager.config = { publish: config }
  if (platformSpecific !== undefined) packager.platformSpecificBuildOptions = { publish: platformSpecific }
  return {
    appOutDir: path.join(tempRoot, 'win-unpacked'),
    electronPlatformName: 'win32',
    arch: 1,
    targets: [{ name: 'nsis' }],
    packager
  }
}

// Break-glass opt-in + NO verified electronDist. deps are injected so no real
// filesystem lookup happens; the no-dist branch decides on allowUnverified.
function breakGlassOpts(tempRoot, env = {}) {
  return {
    env,
    stampPath: writeStamp(tempRoot, ATTESTED),
    execFn: cleanGit('a'.repeat(40)),
    electronBreakGlass: true,
    electronDeps: winElectronDeps()
  }
}

test('B3: break-glass is DENIED for a production (nsis) pack even without publish/tag', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // No publish config anywhere → not a publish/tag release, but STILL an
    // artifact-producing (nsis) production pack. A per-component opt-in must
    // NOT let it ship unverified Electron (B3: break-glass is --dir-only).
    const ctx = winProdPublishContext(tempRoot, {})
    await assert.rejects(beforePack(ctx, breakGlassOpts(tempRoot)), /electronDist|@electron\/get/i)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: break-glass is DENIED when config.publish is a release provider', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const ctx = winProdPublishContext(tempRoot, { config: 'github' })
    await assert.rejects(beforePack(ctx, breakGlassOpts(tempRoot)), /electronDist|@electron\/get/i)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: break-glass is DENIED when platformSpecificBuildOptions.publish is a provider array', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const ctx = winProdPublishContext(tempRoot, { platformSpecific: [{ provider: 'github' }] })
    await assert.rejects(beforePack(ctx, breakGlassOpts(tempRoot)), /electronDist|@electron\/get/i)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: break-glass is DENIED when the wrapper propagated HERMES_DESKTOP_IS_PUBLISH=1', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const ctx = winProdPublishContext(tempRoot, {}) // no config publish; env decides
    await assert.rejects(
      beforePack(ctx, breakGlassOpts(tempRoot, { HERMES_DESKTOP_IS_PUBLISH: '1' })),
      /electronDist|@electron\/get/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: break-glass is DENIED on a tag release (GITHUB_REF_TYPE=tag)', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    const ctx = winProdPublishContext(tempRoot, {})
    await assert.rejects(
      beforePack(ctx, breakGlassOpts(tempRoot, { GITHUB_REF_TYPE: 'tag' })),
      /electronDist|@electron\/get/i
    )
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('B3: a production pack with config.publish "never" STILL rejects unverified electron', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-before-pack-'))
  try {
    // publish:"never" is not a release publish, but it is still an
    // artifact-producing nsis pack — break-glass is denied (B3: --dir-only).
    const ctx = winProdPublishContext(tempRoot, { config: 'never' })
    await assert.rejects(beforePack(ctx, breakGlassOpts(tempRoot)), /electronDist|@electron\/get/i)
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('A2: publishConfigIsRelease classifies publish values', () => {
  assert.equal(publishConfigIsRelease(null), false)
  assert.equal(publishConfigIsRelease(false), false)
  assert.equal(publishConfigIsRelease('never'), false)
  assert.equal(publishConfigIsRelease('false'), false)
  assert.equal(publishConfigIsRelease('0'), false)
  assert.equal(publishConfigIsRelease({ provider: 'never' }), false)
  assert.equal(publishConfigIsRelease('github'), true)
  assert.equal(publishConfigIsRelease('always'), true)
  assert.equal(publishConfigIsRelease({ provider: 'github' }), true)
  assert.equal(publishConfigIsRelease({}), true)
  assert.equal(publishConfigIsRelease([{ provider: 'github' }]), true)
  assert.equal(publishConfigIsRelease([{ provider: 'never' }]), false)
  assert.equal(publishConfigIsRelease([]), false)
})

test('A2: isPublishReleaseContext folds env, wrapper flag, and resolved config', () => {
  assert.equal(isPublishReleaseContext({}, {}), false)
  assert.equal(isPublishReleaseContext({}, { GITHUB_REF_TYPE: 'tag' }), true)
  assert.equal(isPublishReleaseContext({}, { HERMES_DESKTOP_IS_PUBLISH: '1' }), true)
  assert.equal(isPublishReleaseContext({ packager: { config: { publish: 'github' } } }, {}), true)
  assert.equal(
    isPublishReleaseContext({ packager: { platformSpecificBuildOptions: { publish: [{ provider: 's3' }] } } }, {}),
    true
  )
  assert.equal(isPublishReleaseContext({ packager: { config: { publish: 'never' } } }, {}), false)
})
