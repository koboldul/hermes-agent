// electron-dist-verifier.test.mjs — A8 byte-verification behavior tests.
//
// Exercises the real orchestration against injected fakes: malicious mirror/
// cache (byte mismatch), malicious archive (bad members), extracted mutation
// (tree drift), forged/drifted marker, and cross-target resolution. No network,
// no real archive.

import assert from 'node:assert/strict'
import { describe, it } from 'vitest'

import {
  archiveName,
  assertVerifiedElectronDist,
  buildMarker,
  expectedBinaryMember,
  hashTree,
  ProvenanceError,
  resolveElectronTargets,
  resolveVerifiedElectronDist,
  sha256Hex,
  validateZipEntries,
  verifyArchiveBytes,
  verifyMarker
} from './electron-dist-verifier.mjs'

// A tiny "archive" is just a Buffer; its sha256 is the committed digest we pin.
function archive(content = 'ELECTRON-BYTES') {
  const bytes = Buffer.from(content)
  return { bytes, digest: sha256Hex(bytes) }
}

function goodEntries(platform = 'win32') {
  return [{ name: expectedBinaryMember(platform) }, { name: 'resources/app.asar' }]
}

// Build a dependency object for resolveVerifiedElectronDist. `state` lets a test
// simulate a pre-existing verified tree + marker.
function makeDeps({
  platform = 'win32',
  arch = 'x64',
  version = '30.0.0',
  committedDigest,
  bytes,
  entries,
  extractedTree,
  existing = null // { marker, tree }
} = {}) {
  const distDir = `/verified/${version}-${platform}-${arch}`
  const written = {}
  const deps = {
    version,
    committedDigestFor: () => committedDigest,
    verifiedDistDir: () => distDir,
    distExists: (d) => existing != null && d === distDir,
    readMarker: () => existing?.marker ?? null,
    readTree: () => existing?.tree ?? new Map(),
    locateArchiveBytes: () => bytes ?? null,
    listZipEntries: () => entries ?? goodEntries(platform),
    extract: (_b, _d) => extractedTree ?? new Map([[expectedBinaryMember(platform), Buffer.from('bin')]]),
    writeMarker: (_d, m) => {
      written.marker = m
    }
  }
  return { deps, distDir, written }
}

describe('resolveElectronTargets — target, not host', () => {
  it('cross-target: --win on a linux host resolves to win32', () => {
    const targets = resolveElectronTargets(['--win', '--x64'], { hostPlatform: 'linux', hostArch: 'x64' })
    assert.deepEqual(targets, [{ platform: 'win32', arch: 'x64' }])
  })

  it('no platform flag falls back to the host', () => {
    const targets = resolveElectronTargets(['-c.electronDist=/x'], { hostPlatform: 'darwin', hostArch: 'arm64' })
    assert.deepEqual(targets, [{ platform: 'darwin', arch: 'arm64' }])
  })

  it('mac + explicit arm64', () => {
    const targets = resolveElectronTargets(['--mac', '--arm64'], { hostPlatform: 'linux', hostArch: 'x64' })
    assert.deepEqual(targets, [{ platform: 'darwin', arch: 'arm64' }])
  })

  it('multiple platforms produce a cartesian target list', () => {
    const targets = resolveElectronTargets(['--win', '--linux', '--x64'], { hostPlatform: 'linux', hostArch: 'x64' })
    assert.deepEqual(targets, [
      { platform: 'win32', arch: 'x64' },
      { platform: 'linux', arch: 'x64' }
    ])
  })
})

describe('verifyArchiveBytes', () => {
  it('accepts bytes matching the committed digest', () => {
    const a = archive()
    assert.deepEqual(verifyArchiveBytes(a.bytes, a.digest), [])
  })

  it('rejects a substituted (mirror/cache) archive', () => {
    const a = archive()
    const findings = verifyArchiveBytes(Buffer.from('EVIL'), a.digest)
    assert.equal(findings.length, 1)
    assert.match(findings[0], /does NOT match committed manifest digest/)
  })

  it('rejects when no committed digest is pinned', () => {
    assert.match(verifyArchiveBytes(Buffer.from('x'), '')[0], /no committed manifest sha256/)
  })
})

describe('validateZipEntries', () => {
  it('accepts a well-formed archive with the expected binary', () => {
    assert.deepEqual(validateZipEntries(goodEntries('linux'), { platform: 'linux' }), [])
  })

  it('rejects path traversal', () => {
    const findings = validateZipEntries([{ name: '../evil' }, { name: expectedBinaryMember('win32') }], {
      platform: 'win32'
    })
    assert.ok(findings.some((f) => /escapes the tree/.test(f)))
  })

  it('rejects absolute paths', () => {
    const findings = validateZipEntries([{ name: '/etc/passwd' }, { name: expectedBinaryMember('linux') }], {
      platform: 'linux'
    })
    assert.ok(findings.some((f) => /absolute path/.test(f)))
  })

  it('rejects symlink members', () => {
    const findings = validateZipEntries([{ name: 'electron', isSymlink: true }], { platform: 'linux' })
    assert.ok(findings.some((f) => /symlink/.test(f)))
  })

  it('rejects a hollow archive missing the binary', () => {
    const findings = validateZipEntries([{ name: 'resources/app.asar' }], { platform: 'win32' })
    assert.ok(findings.some((f) => /missing the expected electron binary/.test(f)))
  })
})

describe('verifyMarker', () => {
  const version = '30.0.0'
  const platform = 'win32'
  const arch = 'x64'

  it('accepts a marker whose archive digest and tree digest both hold', () => {
    const treeDigest = 'c'.repeat(64)
    const md = 'a'.repeat(64)
    const marker = buildMarker({ version, platform, arch, archiveDigest: md, treeDigest })
    const verdict = verifyMarker({ marker, committedDigest: md, currentTreeDigest: treeDigest, version, platform, arch })
    assert.deepEqual(verdict, { ok: true, reason: 'marker-valid' })
  })

  it('rejects a marker whose archive digest drifted from the committed manifest', () => {
    const treeDigest = 'c'.repeat(64)
    const marker = buildMarker({ version, platform, arch, archiveDigest: 'a'.repeat(64), treeDigest })
    const verdict = verifyMarker({ marker, committedDigest: 'b'.repeat(64), currentTreeDigest: treeDigest, version, platform, arch })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.reason, 'archive-digest-drift')
  })

  it('rejects a mutated tree (marker tree digest != current)', () => {
    const md = 'a'.repeat(64)
    const marker = buildMarker({ version, platform, arch, archiveDigest: md, treeDigest: 'c'.repeat(64) })
    const verdict = verifyMarker({ marker, committedDigest: md, currentTreeDigest: 'd'.repeat(64), version, platform, arch })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.reason, 'tree-mutated')
  })

  it('rejects a marker for the wrong target', () => {
    const md = 'a'.repeat(64)
    const marker = buildMarker({ version, platform: 'linux', arch, archiveDigest: md, treeDigest: 'c'.repeat(64) })
    const verdict = verifyMarker({ marker, committedDigest: md, currentTreeDigest: 'c'.repeat(64), version, platform, arch })
    assert.equal(verdict.reason, 'marker-target')
  })
})

describe('resolveVerifiedElectronDist — orchestrator', () => {
  it('stages a fresh verified tree from a byte-matching cached archive', () => {
    const a = archive()
    const { deps, distDir, written } = makeDeps({ committedDigest: a.digest, bytes: a.bytes })
    const res = resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps)
    assert.equal(res.source, 'staged')
    assert.equal(res.verified, true)
    assert.equal(res.distDir, distDir)
    assert.equal(written.marker.archiveDigest, a.digest)
  })

  it('rejects a malicious mirror/cache archive whose bytes do not match', () => {
    const a = archive()
    const { deps } = makeDeps({ committedDigest: a.digest, bytes: Buffer.from('EVIL-SUBSTITUTE') })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'archive-bytes'
    )
  })

  it('rejects a malicious archive whose members fail validation', () => {
    const a = archive()
    const { deps } = makeDeps({
      committedDigest: a.digest,
      bytes: a.bytes,
      entries: [{ name: '../../escape' }]
    })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'archive-members'
    )
  })

  it('rejects when the extracted tree is missing the binary', () => {
    const a = archive()
    const { deps } = makeDeps({
      committedDigest: a.digest,
      bytes: a.bytes,
      extractedTree: new Map([['resources/app.asar', Buffer.from('x')]])
    })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'tree-missing-binary'
    )
  })

  it('re-accepts a valid existing verified tree without re-staging (no archive needed)', () => {
    const a = archive()
    const tree = new Map([[expectedBinaryMember('win32'), Buffer.from('bin')]])
    const treeDigest = hashTree(tree)
    const marker = buildMarker({
      version: '30.0.0',
      platform: 'win32',
      arch: 'x64',
      archiveDigest: a.digest,
      treeDigest
    })
    // No bytes provided: if staging were attempted it would fail. It must not.
    const { deps } = makeDeps({ committedDigest: a.digest, bytes: null, existing: { marker, tree } })
    const res = resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps)
    assert.equal(res.source, 'marker')
    assert.equal(res.verified, true)
  })

  it('does NOT reuse a mutated existing tree; re-stages from the archive', () => {
    const a = archive()
    // Marker claims a tree digest, but the on-disk tree differs (mutation).
    const marker = buildMarker({
      version: '30.0.0',
      platform: 'win32',
      arch: 'x64',
      archiveDigest: a.digest,
      treeDigest: 'f'.repeat(64)
    })
    const mutatedTree = new Map([[expectedBinaryMember('win32'), Buffer.from('TAMPERED')]])
    const { deps, written } = makeDeps({
      committedDigest: a.digest,
      bytes: a.bytes,
      existing: { marker, tree: mutatedTree }
    })
    const res = resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps)
    // Fell through to a fresh, byte-verified staging.
    assert.equal(res.source, 'staged')
    assert.equal(written.marker.archiveDigest, a.digest)
  })

  it('fails closed when no committed digest is pinned for the target', () => {
    const { deps } = makeDeps({ committedDigest: null, bytes: Buffer.from('x') })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'no-committed-digest'
    )
  })

  it('fails closed when no verified archive is available (no post-gate fetch)', () => {
    const a = archive()
    const { deps } = makeDeps({ committedDigest: a.digest, bytes: null })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'win32', arch: 'x64' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'no-archive'
    )
  })

  it('rejects an unknown/unsupported target before any staging', () => {
    const { deps } = makeDeps({ committedDigest: 'a'.repeat(64), bytes: Buffer.from('x') })
    assert.throws(
      () => resolveVerifiedElectronDist({ platform: 'plan9', arch: 'sparc' }, deps),
      (err) => err instanceof ProvenanceError && err.reason === 'unknown-target'
    )
  })

  it('archiveName follows the @electron/get naming', () => {
    assert.equal(archiveName('30.0.0', 'win32', 'x64'), 'electron-v30.0.0-win32-x64.zip')
  })
})

describe('assertVerifiedElectronDist (Alert 2: beforePack-side independent check)', () => {
  const V = '41.10.3'
  const DIGEST = 'a'.repeat(64)
  const target = { platform: 'win32', arch: 'x64' }

  function deps({ distExists = true, tree, markerArchive = DIGEST, markerTreeDigest, committed = DIGEST } = {}) {
    const t = tree || new Map([['electron.exe', Buffer.from('BIN')]])
    const td = markerTreeDigest || hashTree(t)
    const marker = markerArchive === null ? null : buildMarker({ version: V, platform: 'win32', arch: 'x64', archiveDigest: markerArchive, treeDigest: td })
    return {
      verifiedRoot: '/verified',
      version: V,
      committedDigestFor: () => committed,
      distExists: () => distExists,
      readMarker: () => marker,
      readTree: () => t,
      isInside: (child, parent) => String(child).startsWith(String(parent)),
      basename: (p) => String(p).split('/').pop()
    }
  }
  const DIST = '/verified/41.10.3-win32-x64'

  it('accepts a valid verified dist inside the staging root', () => {
    assert.deepEqual(assertVerifiedElectronDist(target, DIST, deps()), { verified: true })
  })

  it('rejects a missing/default electronDist (@electron/get)', () => {
    assert.throws(() => assertVerifiedElectronDist(target, undefined, deps()), (e) => e.reason === 'no-electron-dist')
  })

  it('rejects a dist outside the verified staging root', () => {
    assert.throws(
      () => assertVerifiedElectronDist(target, '/elsewhere/41.10.3-win32-x64', { ...deps(), isInside: () => false }),
      (e) => e.reason === 'dist-outside-root'
    )
  })

  it('rejects a cross-target dist dir', () => {
    assert.throws(
      () => assertVerifiedElectronDist(target, '/verified/41.10.3-darwin-arm64', deps()),
      (e) => e.reason === 'dist-target-mismatch'
    )
  })

  it('rejects a missing marker (unverified dist)', () => {
    assert.throws(() => assertVerifiedElectronDist(target, DIST, deps({ markerArchive: null })), (e) => /marker-no-marker/.test(e.reason))
  })

  it('rejects an archive-digest drift from the committed manifest', () => {
    assert.throws(
      () => assertVerifiedElectronDist(target, DIST, deps({ markerArchive: 'b'.repeat(64), committed: DIGEST })),
      (e) => /archive-digest-drift/.test(e.reason)
    )
  })

  it('rejects a mutated tree (marker tree digest != current)', () => {
    assert.throws(
      () => assertVerifiedElectronDist(target, DIST, deps({ markerTreeDigest: 'f'.repeat(64) })),
      (e) => /tree-mutated/.test(e.reason)
    )
  })

  it('rejects when the dist does not exist (no marker on disk)', () => {
    assert.throws(() => assertVerifiedElectronDist(target, DIST, deps({ distExists: false })), (e) => e.reason === 'dist-missing')
  })

  it('rejects when the expected binary is absent from the tree', () => {
    const t = new Map([['resources/app.asar', Buffer.from('x')]])
    assert.throws(() => assertVerifiedElectronDist(target, DIST, deps({ tree: t })), (e) => e.reason === 'dist-missing-binary')
  })

  it('rejects an unknown/universal target unless break-glass', () => {
    assert.throws(() => assertVerifiedElectronDist({ platform: 'darwin', arch: 'universal' }, DIST, deps()), (e) => e.reason === 'unknown-target')
    const r = assertVerifiedElectronDist({ platform: 'darwin', arch: 'universal' }, DIST, deps(), { allowUnverified: true })
    assert.equal(r.verified, false)
  })

  it('break-glass allows a missing dist but marks it unverified', () => {
    const r = assertVerifiedElectronDist(target, undefined, deps(), { allowUnverified: true })
    assert.equal(r.verified, false)
    assert.equal(r.reason, 'break-glass-no-dist')
  })
})
