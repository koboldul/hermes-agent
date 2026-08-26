import assert from 'node:assert/strict'
import fs, { existsSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { test } from 'vitest'

import {
  assertBindingVerified,
  getWindowsArchiveDigest,
  getWindowsPinnedDigest,
  publishGetWindowsFinal,
  stageGetWindows,
  stageGetWindowsInto,
  stageNodePtyInto,
  classifyNativeBinary
} from '../scripts/stage-native-deps.mjs'
import * as stageModule from '../scripts/stage-native-deps.mjs'

const { join } = path

// A8: the get-windows lifecycle install (`node-pre-gyp install
// --fallback-to-build`) is DISABLED in the root allowScripts allowlist, and the
// staging path no longer spawns node-pre-gyp at all — the network/build
// installer helpers were removed.
test('A8: no get-windows network/build installer surface survives', () => {
  assert.equal(stageModule.installGetWindowsNativeBinding, undefined)
  assert.equal(stageModule.getWindowsNetworkInstallAllowed, undefined)
})

test('A8: get-windows lifecycle script is DENIED in the root allowScripts allowlist', () => {
  const pkgPath = fileURLToPath(new URL('../../../package.json', import.meta.url))
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  assert.equal(
    pkg.allowScripts['get-windows@9.3.0'],
    false,
    'get-windows install script must be denied so npm ci never spawns node-pre-gyp'
  )
})

test('A8: the get-windows binding digest is pinned per supported target in the manifest', () => {
  // win32-x64 is pinned (PE .node); macOS is pinned (universal Mach-O helper).
  assert.match(getWindowsPinnedDigest('win32', 'x64'), /^[0-9a-f]{64}$/)
  assert.match(getWindowsPinnedDigest('darwin', 'x64'), /^[0-9a-f]{64}$/)
  assert.match(getWindowsPinnedDigest('darwin', 'arm64'), /^[0-9a-f]{64}$/)
  // No prebuild / no native binary → no pin → feature disabled, no fallback.
  assert.equal(getWindowsPinnedDigest('win32', 'arm64'), null)
  assert.equal(getWindowsPinnedDigest('linux', 'x64'), null)
})

// A10 provenance split: `digest` authenticates the ARCHIVE (URL bytes) and
// `member_digests` the EXTRACTED file. stage-native MUST verify the MEMBER
// digest; a download verifier the ARCHIVE digest. These MUST NOT be confused.
const WIN_MEMBER_SHA = '528cf76b3d7b85bcaf9c0fac928b3150bb338de41c9185ce1f06e2a4d998ebbf'
const WIN_ARCHIVE_SHA = '3eecfad06ed44f379bc50e02d738fa5dde274ce0206ced4c58b8f776ec9d76b0'
const MAC_MEMBER_SHA = '687d4f4d69428f91fcd576887a34e9a0778756868f705e644cbc48cd76a9d4aa'
const MAC_ARCHIVE_SHA512 = '0eb39f41298872c15ac76f057d25236cb4df78e9001bbc9e87a3426fff73cd1903b829576aa62a1ee4013d4a9ca9dd6e612ef4ca0604452a2869c300c2f6f257'

test('A10 split: stage-native pins the MEMBER digest, NOT the archive digest', () => {
  // The member digest (extracted file) is what the stager verifies.
  assert.equal(getWindowsPinnedDigest('win32', 'x64'), WIN_MEMBER_SHA)
  assert.equal(getWindowsPinnedDigest('darwin', 'arm64'), MAC_MEMBER_SHA)
  // It must NOT be the archive digest — substituting one for the other fails.
  assert.notEqual(getWindowsPinnedDigest('win32', 'x64'), WIN_ARCHIVE_SHA)
  assert.notEqual(getWindowsPinnedDigest('darwin', 'arm64'), MAC_ARCHIVE_SHA512)
})

test('A10 split: the archive digest authenticates the URL bytes, NOT the member', () => {
  const win = getWindowsArchiveDigest('win32', 'x64')
  assert.equal(win.algorithm, 'sha256')
  assert.equal(win.value, WIN_ARCHIVE_SHA)
  assert.notEqual(win.value, WIN_MEMBER_SHA)

  const mac = getWindowsArchiveDigest('darwin', 'x64')
  assert.equal(mac.algorithm, 'sha512')
  assert.equal(mac.value, MAC_ARCHIVE_SHA512)
  assert.notEqual(mac.value, MAC_MEMBER_SHA)
})

test('A10 split: the mac ARCHIVE digest equals the package-lock integrity (lock ↔ archive)', () => {
  const lockPath = fileURLToPath(new URL('../../../package-lock.json', import.meta.url))
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'))
  let integrity = null
  for (const [key, value] of Object.entries(lock.packages || {})) {
    if (key.endsWith('node_modules/get-windows') && value && value.integrity) {
      integrity = value.integrity
    }
  }
  assert.ok(integrity && integrity.startsWith('sha512-'), 'get-windows must be lock-integrity-bound')
  const hex = Buffer.from(integrity.replace(/^sha512-/, ''), 'base64').toString('hex')
  // The macOS archive is the npm tarball; its committed sha512 MUST equal the
  // lock integrity for the same package (a mirror cannot change this).
  assert.equal(getWindowsArchiveDigest('darwin', 'x64').value, hex)
  assert.equal(getWindowsArchiveDigest('darwin', 'arm64').value, hex)
})

// ─── fixtures ──────────────────────────────────────────────────────
//
// Create minimal fake .node files with correct magic bytes so the
// binary classifier and the staging validator exercise real code paths
// without needing actual native modules.

/** Write a fake .node file with the given platform's magic bytes. */
function makeFakeNode(filePath, platform) {
  const headers = {
    linux:   Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00, 0x00]), // ELF
    // On x64/arm64 Darwin, Mach-O binaries are stored little-endian on disk
    // (MH_CIGAM_64 = cffaedfe). This is the form node-pty's prebuilds ship in.
    darwin:  Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00]), // Mach-O 64-bit LE (CIGAM_64)
    win32:   Buffer.from([0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  // MZ (PE)
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, headers[platform] ?? headers.linux)
}

/** Create a minimal fake node-pty source tree in a temp dir. */
function makeFakeNodePty(srcRoot, { prebuildPlatform, prebuildArch } = {}) {
  fs.mkdirSync(srcRoot, { recursive: true })
  fs.writeFileSync(join(srcRoot, 'package.json'), JSON.stringify({ name: 'node-pty', main: 'lib/index.js' }))
  fs.mkdirSync(join(srcRoot, 'lib'), { recursive: true })
  fs.writeFileSync(join(srcRoot, 'lib', 'index.js'), 'module.exports = {};')

  if (prebuildPlatform && prebuildArch) {
    const prebuildDir = join(srcRoot, 'prebuilds', `${prebuildPlatform}-${prebuildArch}`)
    makeFakeNode(join(prebuildDir, 'pty.node'), prebuildPlatform)
  }
}

function makeFakeUnixTerminal(srcRoot) {
  fs.writeFileSync(
    join(srcRoot, 'lib', 'unixTerminal.js'),
    [
      "exports.resolveHelper = function (helperPath) {",
      "  helperPath = helperPath.replace('app.asar', 'app.asar.unpacked');",
      "  helperPath = helperPath.replace('node_modules.asar', 'node_modules.asar.unpacked');",
      '  return helperPath;',
      '};'
    ].join('\n')
  )
}

// ─── classifyNativeBinary tests ─────────────────────────────────────

test('classifyNativeBinary detects ELF as linux', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'linux')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Mach-O 64-bit BE as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Mach-O 64-bit LE (CIGAM_64) as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Mach-O 32-bit BE as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Mach-O 32-bit LE (CIGAM) as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xce, 0xfa, 0xed, 0xfe, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Fat/Universal BE (cafebabe) as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects Fat/Universal LE (bebafeca / FAT_CIGAM) as darwin', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0xbe, 0xba, 0xfe, 0xca, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'darwin')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary detects PE (MZ) as win32', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), 'win32')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary returns null for unrecognized magic', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const f = join(tmp, 'test.node')
    fs.writeFileSync(f, Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    assert.equal(classifyNativeBinary(f), null)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('classifyNativeBinary returns null for a missing file', () => {
  assert.equal(classifyNativeBinary('/nonexistent/path/to/thing.node'), null)
})

// ─── cross-target regression tests ──────────────────────────────────
//
// The core bug: stageNodePty receives { platform, arch } from
// electron-builder but unconditionally copies host build/Release, staging
// a host binary for a foreign target. These tests prove the fix:
//
// 1. A host build/Release must NOT be staged for a foreign platform.
// 2. A matching prebuild IS staged for a foreign target.
// 3. A foreign target with no prebuild throws (fail closed).
// 4. A host build/Release IS staged for a matching target.
// 5. Validation rejects a binary whose magic bytes don't match the target.

test('cross-target: host build/Release is NOT staged for a foreign platform', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'node-pty')
    const destRoot = join(tmp, 'dest')

    // Create a node-pty tree with ONLY a host build/Release (no prebuild).
    makeFakeNodePty(srcRoot)
    const buildReleaseDir = join(srcRoot, 'build', 'Release')
    makeFakeNode(join(buildReleaseDir, 'pty.node'), process.platform)

    // Request a foreign platform (different from the host).
    const foreignPlatform = process.platform === 'linux' ? 'darwin' : 'linux'

    assert.throws(
      () => stageNodePtyInto(srcRoot, destRoot, { platform: foreignPlatform, arch: 'x64' }),
      /cannot cross-compile/i
    )

    // build/Release must NOT have been copied to the dest tree.
    assert.equal(
      existsSync(join(destRoot, 'build', 'Release', 'pty.node')),
      false,
      'host build/Release .node must not be staged for a foreign target'
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('cross-target: matching prebuild IS staged for a foreign target', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'node-pty')
    const destRoot = join(tmp, 'dest')

    // Host is (say) darwin. Request linux-x64, which has a prebuild.
    const foreignPlatform = process.platform === 'linux' ? 'darwin' : 'linux'
    makeFakeNodePty(srcRoot, { prebuildPlatform: foreignPlatform, prebuildArch: 'x64' })

    // Also create a host build/Release that should NOT be staged.
    makeFakeNode(join(srcRoot, 'build', 'Release', 'pty.node'), process.platform)

    stageNodePtyInto(srcRoot, destRoot, { platform: foreignPlatform, arch: 'x64' })

    // The foreign prebuild must be staged.
    const stagedPrebuild = join(destRoot, 'prebuilds', `${foreignPlatform}-x64`, 'pty.node')
    assert.equal(existsSync(stagedPrebuild), true, 'foreign prebuild must be staged')

    // The host build/Release must NOT be staged.
    assert.equal(
      existsSync(join(destRoot, 'build', 'Release', 'pty.node')),
      false,
      'host build/Release must not be staged for a foreign target'
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('cross-target: foreign target with no prebuild throws (fail closed)', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'node-pty')
    const destRoot = join(tmp, 'dest')

    // Create a tree with a host build/Release but no foreign prebuild.
    makeFakeNodePty(srcRoot)
    makeFakeNode(join(srcRoot, 'build', 'Release', 'pty.node'), process.platform)

    const foreignPlatform = process.platform === 'linux' ? 'darwin' : 'linux'

    assert.throws(
      () => stageNodePtyInto(srcRoot, destRoot, { platform: foreignPlatform, arch: 'x64' }),
      /cannot cross-compile/i
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('host-target: host build/Release IS staged for a matching target', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'node-pty')
    const destRoot = join(tmp, 'dest')

    makeFakeNodePty(srcRoot)
    makeFakeNode(join(srcRoot, 'build', 'Release', 'pty.node'), process.platform)

    stageNodePtyInto(srcRoot, destRoot, { platform: process.platform, arch: process.arch })

    assert.equal(
      existsSync(join(destRoot, 'build', 'Release', 'pty.node')),
      true,
      'host build/Release must be staged for a matching target'
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test.skipIf(process.platform === 'win32')(
  'host-target: staged node-pty resolves an already-unpacked helper and preserves executable helpers',
  async () => {
    const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
    try {
      const srcRoot = join(tmp, 'node-pty')
      const destRoot = join(tmp, 'dest')
      const prebuildDir = join(srcRoot, 'prebuilds', `${process.platform}-${process.arch}`)
      const buildReleaseDir = join(srcRoot, 'build', 'Release')

      makeFakeNodePty(srcRoot, {
        prebuildPlatform: process.platform,
        prebuildArch: process.arch
      })
      makeFakeUnixTerminal(srcRoot)
      makeFakeNode(join(buildReleaseDir, 'pty.node'), process.platform)
      fs.writeFileSync(join(prebuildDir, 'spawn-helper'), 'prebuild helper')
      fs.writeFileSync(join(buildReleaseDir, 'spawn-helper'), 'build helper')
      fs.chmodSync(join(prebuildDir, 'spawn-helper'), 0o644)
      fs.chmodSync(join(buildReleaseDir, 'spawn-helper'), 0o644)

      stageNodePtyInto(srcRoot, destRoot, { platform: process.platform, arch: process.arch })

      const stagedUnixTerminalUrl = pathToFileURL(join(destRoot, 'lib', 'unixTerminal.js'))
      stagedUnixTerminalUrl.searchParams.set('t', String(Date.now()))
      const stagedUnixTerminal = await import(stagedUnixTerminalUrl.href)
      const unpackedHelper = join(
        tmp,
        'Hermes.app',
        'Contents',
        'Resources',
        'app.asar.unpacked',
        'dist',
        'node_modules',
        'node-pty',
        'prebuilds',
        `${process.platform}-${process.arch}`,
        'spawn-helper'
      )
      const nodeModulesUnpackedHelper = unpackedHelper.replace(
        `${path.sep}node_modules${path.sep}`,
        `${path.sep}node_modules.asar.unpacked${path.sep}`
      )

      assert.equal(stagedUnixTerminal.resolveHelper(unpackedHelper), unpackedHelper)
      assert.equal(
        stagedUnixTerminal.resolveHelper(nodeModulesUnpackedHelper),
        nodeModulesUnpackedHelper
      )
      assert.equal(
        fs.statSync(join(destRoot, 'prebuilds', `${process.platform}-${process.arch}`, 'spawn-helper')).mode & 0o777,
        0o755
      )
      assert.equal(fs.statSync(join(destRoot, 'build', 'Release', 'spawn-helper')).mode & 0o777, 0o755)
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true })
    }
  }
)

test('validation rejects a staged binary with the wrong platform magic', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'node-pty')
    const destRoot = join(tmp, 'dest')

    // Create a prebuild dir that claims to be linux-x64 but contains
    // a darwin (Mach-O) binary. This simulates the original bug where
    // a host binary ends up in a foreign target's prebuild slot.
    makeFakeNodePty(srcRoot, { prebuildPlatform: 'linux', prebuildArch: 'x64' })
    // Overwrite the prebuild .node with the WRONG platform magic.
    makeFakeNode(join(srcRoot, 'prebuilds', 'linux-x64', 'pty.node'), 'darwin')

    assert.throws(
      () => stageNodePtyInto(srcRoot, destRoot, { platform: 'linux', arch: 'x64' }),
      /platform mismatch/i
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

// ─── stageGetWindowsInto tests ──────────────────────────────────────

// Fake native-binary magic bytes shared with makeFakeNode, so a test can
// compute the exact sha256 the staging path will see and inject it as the
// pinned manifest digest.
const FAKE_MAGIC = {
  linux: [0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00, 0x00], // ELF
  darwin: [0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00], // Mach-O 64 LE
  win32: [0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] // MZ (PE)
}
// The macOS "main" helper is a universal (FAT) Mach-O in the real tarball.
const FAKE_MAIN = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x00]

function shaOfBytes(bytes) {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex')
}
// A pinnedDigestFor that ACCEPTS the fake binding for `platform` (its bytes'
// real sha256) and returns null for everything else.
function acceptFake(platform) {
  const digest = shaOfBytes(platform === 'main' ? FAKE_MAIN : FAKE_MAGIC[platform])
  return () => digest
}

/** Create a minimal fake get-windows source tree in a temp dir. */
function makeFakeGetWindows(srcRoot, { version = '9.3.0', bindings = [] } = {}) {
  fs.mkdirSync(join(srcRoot, 'lib'), { recursive: true })
  fs.writeFileSync(join(srcRoot, 'package.json'), JSON.stringify({ name: 'get-windows', version, main: 'index.js' }))
  fs.writeFileSync(join(srcRoot, 'index.js'), 'export {};')
  fs.writeFileSync(join(srcRoot, 'lib', 'windows.js'), '// upstream pre-gyp loader')
  // A universal Mach-O helper (real get-windows ships a FAT binary here).
  fs.writeFileSync(join(srcRoot, 'main'), Buffer.from(FAKE_MAIN))

  for (const { dir, platform } of bindings) {
    makeFakeNode(join(srcRoot, 'lib', 'binding', dir, 'node-get-windows.node'), platform)
  }
}

test('win32 staging byte-verifies and stages a PINNED win32 binding, skips the bundled darwin one', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    // The shape every real Windows build host has: the darwin binding
    // committed into the published tarball PLUS the win32 binding.
    makeFakeGetWindows(srcRoot, {
      bindings: [
        { dir: 'napi-9-darwin-unknown-arm64', platform: 'darwin' },
        { dir: 'napi-9-win32-unknown-x64', platform: 'win32' }
      ]
    })

    // Pin = the fake win32 binding's real sha256 → accepted (staged).
    stageGetWindowsInto(srcRoot, destRoot, { platform: 'win32', arch: 'x64', pinnedDigestFor: acceptFake('win32') })

    assert.ok(existsSync(join(destRoot, 'lib', 'binding', 'napi-9-win32-unknown-x64', 'node-get-windows.node')))
    assert.ok(!existsSync(join(destRoot, 'lib', 'binding', 'napi-9-darwin-unknown-arm64')))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('win32 staging REJECTS a mutated binding (digest mismatch) — fail closed, no staging', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')
    makeFakeGetWindows(srcRoot, { bindings: [{ dir: 'napi-9-win32-unknown-x64', platform: 'win32' }] })

    // The manifest pins a DIFFERENT digest than the on-disk (mutated) binding.
    assert.throws(
      () =>
        stageGetWindowsInto(srcRoot, destRoot, {
          platform: 'win32',
          arch: 'x64',
          pinnedDigestFor: () => 'f'.repeat(64)
        }),
      /does not match the committed manifest digest/
    )
    assert.ok(!existsSync(join(destRoot, 'lib', 'binding', 'napi-9-win32-unknown-x64')))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('win32 staging REJECTS an unmarked binding (no manifest pin) — fail closed', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')
    makeFakeGetWindows(srcRoot, { bindings: [{ dir: 'napi-9-win32-unknown-x64', platform: 'win32' }] })

    assert.throws(
      () =>
        stageGetWindowsInto(srcRoot, destRoot, {
          platform: 'win32',
          arch: 'x64',
          pinnedDigestFor: () => null
        }),
      /no committed manifest digest for this target/
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('win32 staging rejects a binding dir that claims win32 but holds a foreign (Mach-O) binary', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    makeFakeGetWindows(srcRoot, {
      bindings: [{ dir: 'napi-9-win32-unknown-x64', platform: 'darwin' }]
    })

    // Even with a matching digest, the PE/Mach-O format check rejects it first.
    assert.throws(
      () =>
        stageGetWindowsInto(srcRoot, destRoot, {
          platform: 'win32',
          arch: 'x64',
          pinnedDigestFor: acceptFake('darwin')
        }),
      /is not the expected win32 \(PE\/Mach-O only\)/
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('win32-x64 staging with only foreign-named bindings disables the feature (no throw, no binding staged)', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    makeFakeGetWindows(srcRoot, {
      bindings: [{ dir: 'napi-9-darwin-unknown-arm64', platform: 'darwin' }]
    })

    // No win32-named binding → nothing to verify → fail soft (feature disabled).
    stageGetWindowsInto(srcRoot, destRoot, { platform: 'win32', arch: 'x64' })
    assert.ok(existsSync(join(destRoot, 'lib', 'windows.js')))
    assert.ok(!existsSync(join(destRoot, 'lib', 'binding')))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('win32-arm64 staging omits incompatible bindings and keeps the fail-soft JS surface', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    makeFakeGetWindows(srcRoot, {
      bindings: [
        { dir: 'napi-9-darwin-unknown-arm64', platform: 'darwin' },
        { dir: 'napi-9-win32-unknown-x64', platform: 'win32' }
      ]
    })

    stageGetWindowsInto(srcRoot, destRoot, { platform: 'win32', arch: 'arm64' })

    assert.ok(existsSync(join(destRoot, 'lib', 'windows.js')))
    assert.ok(!existsSync(join(destRoot, 'lib', 'binding')))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('staging refuses a get-windows version the lib/windows.js rewrite was not verified against', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    makeFakeGetWindows(srcRoot, { version: '9.4.0' })

    assert.throws(
      () => stageGetWindowsInto(srcRoot, destRoot, { platform: 'darwin' }),
      /verified against 9\.3\.0/
    )
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('darwin staging byte-verifies + ships the Swift helper and the rewritten windows.js', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')

    makeFakeGetWindows(srcRoot)

    // Pin = the fake FAT Mach-O helper's real sha256 → accepted.
    stageGetWindowsInto(srcRoot, destRoot, { platform: 'darwin', arch: 'arm64', pinnedDigestFor: acceptFake('main') })

    assert.ok(existsSync(join(destRoot, 'main')))
    // The exec bit only round-trips on POSIX hosts.
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(join(destRoot, 'main')).mode & 0o777, 0o755)
    }
    const staged = fs.readFileSync(join(destRoot, 'lib', 'windows.js'), 'utf8')
    assert.match(staged, /Rewritten by stage-native-deps\.mjs/)
    assert.ok(!staged.includes('node-pre-gyp'), 'pre-gyp loader must not survive staging')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('darwin staging REJECTS a mutated Swift helper (digest mismatch) — fail closed', () => {
  const tmp = fs.mkdtempSync(join(os.tmpdir(), 'hermes-stage-'))
  try {
    const srcRoot = join(tmp, 'get-windows')
    const destRoot = join(tmp, 'dest')
    makeFakeGetWindows(srcRoot)

    assert.throws(
      () => stageGetWindowsInto(srcRoot, destRoot, { platform: 'darwin', arch: 'arm64', pinnedDigestFor: () => 'a'.repeat(64) }),
      /does not match the committed manifest digest/
    )
    assert.ok(!existsSync(join(destRoot, 'main')))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

// ─── stageGetWindows (optionalDependency gate) ──────────────────────
//
// get-windows is an optionalDependency: on Linux its node-pre-gyp install
// script fails because no prebuilt exists. Windows ARM64 has the same package
// state: its prebuilt URL returns 404 and npm may omit the optional dependency.
// Staging skips those unsupported targets, but supported native targets remain
// a hard failure when the package is missing.

test('linux staging skips when get-windows is absent (optional dep skipped by npm)', () => {
  assert.equal(stageGetWindows({ platform: 'linux', resolveRoot: () => null }), undefined)
})

test('darwin staging fails when get-windows is absent', () => {
  assert.throws(
    () => stageGetWindows({ platform: 'darwin', arch: 'arm64', resolveRoot: () => null }),
    /get-windows is not installed/
  )
})

test('win32-arm64 staging skips when get-windows is absent after its optional install fails', () => {
  assert.equal(
    stageGetWindows({ platform: 'win32', arch: 'arm64', resolveRoot: () => null }),
    undefined
  )
})

test('win32-x64 staging fails when get-windows is absent', () => {
  assert.throws(
    () => stageGetWindows({ platform: 'win32', arch: 'x64', resolveRoot: () => null }),
    /get-windows is not installed/
  )
})

// A6: the get-windows FINAL dest swap is routed through the shared Python
// kernel-locked transaction (publishGetWindowsFinal), not an in-place build of
// destRoot. The staged tree (member-digest verified by stageGetWindowsInto) is
// swapped atomically; the committed ARCHIVE digest is passed as staged_sha256.

test('A6: publishGetWindowsFinal routes the swap through the transaction with the archive digest', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-gw-pub-'))
  try {
    const stageRoot = join(tmp, 'get-windows.stage')
    const destRoot = join(tmp, 'dist', 'node_modules', 'get-windows')
    fs.mkdirSync(stageRoot, { recursive: true })
    fs.writeFileSync(join(stageRoot, 'index.js'), 'x')
    const seen = []
    const out = publishGetWindowsFinal({
      stageRoot,
      destRoot,
      platform: 'win32',
      arch: 'x64',
      isRelease: true,
      publish: (opts) => {
        seen.push(opts)
        return { ok: true, published: true, committed: true }
      }
    })
    assert.equal(out, destRoot)
    assert.equal(seen.length, 1)
    const call = seen[0]
    assert.equal(call.component, 'get-windows')
    assert.equal(call.stageDir, stageRoot)
    assert.equal(call.targetDir, destRoot)
    assert.equal(call.statePath, null) // Python default: state OUTSIDE node_modules
    assert.equal(call.isRelease, true)
    // staged_sha256 is the committed ARCHIVE digest for win32-x64.
    const archive = getWindowsArchiveDigest('win32', 'x64')
    assert.equal(call.stagedSha256, archive.value)
    // The stage dir is cleaned up regardless (the transaction moved/kept it).
    assert.ok(!fs.existsSync(stageRoot), 'stage dir removed after publish')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('A6: publishGetWindowsFinal cleans the stage dir even when the transaction throws (fail closed)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-gw-pub-'))
  try {
    const stageRoot = join(tmp, 'get-windows.stage')
    const destRoot = join(tmp, 'dist', 'get-windows')
    fs.mkdirSync(stageRoot, { recursive: true })
    assert.throws(
      () =>
        publishGetWindowsFinal({
          stageRoot,
          destRoot,
          platform: 'win32',
          arch: 'x64',
          isRelease: true,
          publish: () => {
            throw new Error('helper unavailable')
          }
        }),
      /helper unavailable/
    )
    assert.ok(!fs.existsSync(stageRoot), 'stage dir removed on failure')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
