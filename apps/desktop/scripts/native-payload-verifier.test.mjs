import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  verifyElectronPin,
  verifyChecksums,
  verifyTarget,
  verifyAll,
  nativeBindingDecision,
  nativePrebuildDecision,
  supplyChainAllowsUnverified,
  ELECTRON_ALLOWED_TARGETS
} from './native-payload-verifier.mjs'

const VERSION = '41.10.3'
const GOOD_DIGEST = 'a'.repeat(64)

function goodPkg() {
  return {
    build: { electronVersion: VERSION },
    devDependencies: { electron: VERSION }
  }
}

function goodLock() {
  return {
    packages: {
      'node_modules/electron': {
        version: VERSION,
        integrity: 'sha512-MJuSODPw8sivABC',
        resolved: `https://registry.npmjs.org/electron/-/electron-${VERSION}.tgz`
      }
    }
  }
}

function goodChecksums(platform = 'linux', arch = 'x64', digest = GOOD_DIGEST) {
  return { [`electron-v${VERSION}-${platform}-${arch}.zip`]: digest }
}

// --- electron pin -----------------------------------------------------------

test('verifyElectronPin passes for a lock-bound, version-matched electron', () => {
  assert.deepEqual(verifyElectronPin({ pkg: goodPkg(), lock: goodLock(), expectedVersion: VERSION }), [])
})

test('verifyElectronPin fails when package.json electronVersion drifts', () => {
  const pkg = goodPkg()
  pkg.build.electronVersion = '40.0.0'
  const findings = verifyElectronPin({ pkg, lock: goodLock(), expectedVersion: VERSION })
  assert.ok(findings.some((f) => f.includes('electronVersion')))
})

test('verifyElectronPin fails when the lock integrity is missing', () => {
  const lock = goodLock()
  delete lock.packages['node_modules/electron'].integrity
  const findings = verifyElectronPin({ pkg: goodPkg(), lock, expectedVersion: VERSION })
  assert.ok(findings.some((f) => f.includes('integrity')))
})

test('verifyElectronPin fails when electron is not resolved from the npm registry', () => {
  const lock = goodLock()
  lock.packages['node_modules/electron'].resolved = 'https://evil.example/electron.tgz'
  const findings = verifyElectronPin({ pkg: goodPkg(), lock, expectedVersion: VERSION })
  assert.ok(findings.some((f) => f.includes('registry.npmjs.org')))
})

// --- checksums vs the COMMITTED manifest digest (the authority) --------------

test('verifyChecksums passes when checksums.json matches the committed manifest digest', () => {
  assert.deepEqual(
    verifyChecksums({
      checksums: goodChecksums('linux', 'x64', GOOD_DIGEST),
      expectedVersion: VERSION, platform: 'linux', arch: 'x64', manifestDigest: GOOD_DIGEST
    }),
    []
  )
})

test('verifyChecksums fails closed when the manifest has no committed digest (not the authority)', () => {
  const findings = verifyChecksums({
    checksums: goodChecksums(), expectedVersion: VERSION, platform: 'linux', arch: 'x64', manifestDigest: null
  })
  assert.ok(findings.some((f) => f.includes('committed manifest sha256')))
})

test('verifyChecksums fails closed when checksums.json is missing', () => {
  const findings = verifyChecksums({
    checksums: null, expectedVersion: VERSION, platform: 'linux', arch: 'x64', manifestDigest: GOOD_DIGEST
  })
  assert.ok(findings.some((f) => f.includes('checksums.json')))
})

test('verifyChecksums fails when the target archive has no checksum entry', () => {
  const findings = verifyChecksums({
    checksums: goodChecksums('linux', 'x64'),
    expectedVersion: VERSION, platform: 'win32', arch: 'arm64', manifestDigest: GOOD_DIGEST
  })
  assert.ok(findings.some((f) => f.includes('win32-arm64')))
})

test('mirror cannot alter the digest: a drifted checksums.json entry is rejected', () => {
  // A mirror serves a checksums.json whose value differs by one byte from the
  // committed manifest digest — must be refused.
  const drifted = 'a'.repeat(63) + 'b'
  const findings = verifyChecksums({
    checksums: goodChecksums('linux', 'x64', drifted),
    expectedVersion: VERSION, platform: 'linux', arch: 'x64', manifestDigest: GOOD_DIGEST
  })
  assert.ok(findings.some((f) => f.includes('does NOT match the committed')))
})

// --- target -----------------------------------------------------------------

test('verifyTarget accepts known electron targets and rejects unknown', () => {
  assert.deepEqual(verifyTarget({ platform: 'linux', arch: 'x64' }), [])
  assert.ok(verifyTarget({ platform: 'solaris', arch: 'sparc' }).length > 0)
})

test('every allowed target verifies fully with matching manifest digest', () => {
  for (const [platform, arch] of ELECTRON_ALLOWED_TARGETS) {
    const findings = verifyAll({
      pkg: goodPkg(),
      lock: goodLock(),
      checksums: goodChecksums(platform, arch, GOOD_DIGEST),
      expectedVersion: VERSION,
      platform,
      arch,
      manifestDigest: GOOD_DIGEST
    })
    assert.deepEqual(findings, [], `${platform}-${arch}: ${findings.join('; ')}`)
  }
})

// --- native prebuild decision (node-pty / get-windows) ----------------------

test('nativePrebuildDecision uses a lock-bound bundled prebuild when present', () => {
  const d = nativePrebuildDecision({ prebuildPresent: true, hostMatches: true, allowUnverifiedNativeRebuild: false })
  assert.equal(d.action, 'use_prebuild')
})

test('nativePrebuildDecision fails closed with no prebuild and no opt-in', () => {
  const d = nativePrebuildDecision({ prebuildPresent: false, hostMatches: true, allowUnverifiedNativeRebuild: false })
  assert.equal(d.action, 'fail_closed')
})

test('nativePrebuildDecision allows the rebuild ONLY on explicit opt-in', () => {
  const d = nativePrebuildDecision({ prebuildPresent: false, hostMatches: true, allowUnverifiedNativeRebuild: true })
  assert.equal(d.action, 'rebuild_allowed')
})

test('nativePrebuildDecision never rebuilds cross-platform even with opt-in', () => {
  const d = nativePrebuildDecision({ prebuildPresent: false, hostMatches: false, allowUnverifiedNativeRebuild: true })
  assert.equal(d.action, 'fail_closed')
})

// --- config opt-in (scoped; enforce:false alone does NOT authorize) ----------

test('supplyChainAllowsUnverified requires the explicit allow-list', () => {
  const scoped = 'security:\n  supply_chain:\n    enforce: true\n    allow_unverified_components: ["electron-native"]\n'
  assert.equal(supplyChainAllowsUnverified('electron-native', scoped), true)
  assert.equal(supplyChainAllowsUnverified('plugins', scoped), false)
})

test('supplyChainAllowsUnverified: enforce:false alone does NOT authorize', () => {
  const enforceFalse = 'security:\n  supply_chain:\n    enforce: false\n'
  assert.equal(supplyChainAllowsUnverified('electron-native', enforceFalse), false)
})

test('supplyChainAllowsUnverified honors the "*" sentinel', () => {
  const star = 'security:\n  supply_chain:\n    allow_unverified_components: ["*"]\n'
  assert.equal(supplyChainAllowsUnverified('electron-native', star), true)
})

// --- A8 get-windows native binding decision (PE/Mach-O + digest) ----------

const WIN_DIGEST = '5'.repeat(64)

test('nativeBindingDecision stages a PE win32 binding whose digest matches the pin', () => {
  const d = nativeBindingDecision({ classified: 'win32', platform: 'win32', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'stage')
})

test('nativeBindingDecision stages a Mach-O darwin helper whose digest matches the pin', () => {
  const d = nativeBindingDecision({ classified: 'darwin', platform: 'darwin', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST.toUpperCase() })
  assert.equal(d.action, 'stage')
})

test('nativeBindingDecision REJECTS a mutated binding (digest mismatch)', () => {
  const d = nativeBindingDecision({ classified: 'win32', platform: 'win32', actualSha256: '6'.repeat(64), pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'reject')
  assert.match(d.reason, /does not match the committed manifest digest/)
})

test('nativeBindingDecision REJECTS an unmarked binding (no pin)', () => {
  const d = nativeBindingDecision({ classified: 'win32', platform: 'win32', actualSha256: WIN_DIGEST, pinnedDigest: null })
  assert.equal(d.action, 'reject')
  assert.match(d.reason, /no committed manifest digest/)
})

test('nativeBindingDecision REJECTS a wrong-format binary (PE/Mach-O only)', () => {
  // An ELF where a PE is expected.
  const d = nativeBindingDecision({ classified: 'linux', platform: 'win32', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'reject')
  assert.match(d.reason, /PE\/Mach-O only/)
})

test('nativeBindingDecision REJECTS an unknown-magic binary', () => {
  const d = nativeBindingDecision({ classified: null, platform: 'darwin', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'reject')
})

test('nativeBindingDecision REJECTS a cross-platform binary (darwin where win32 expected)', () => {
  const d = nativeBindingDecision({ classified: 'darwin', platform: 'win32', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'reject')
  assert.match(d.reason, /not the expected win32/)
})

test('nativeBindingDecision REJECTS a platform with no native binding format (linux)', () => {
  const d = nativeBindingDecision({ classified: 'linux', platform: 'linux', actualSha256: WIN_DIGEST, pinnedDigest: WIN_DIGEST })
  assert.equal(d.action, 'reject')
  assert.match(d.reason, /no supported native binding format/)
})
