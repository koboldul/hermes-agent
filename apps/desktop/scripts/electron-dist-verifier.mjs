// electron-dist-verifier.mjs — A8 (Electron/native byte verification).
//
// The metadata gate (native-payload-verifier.mjs) proves the CHECKSUM file
// matches the committed manifest. This module proves the BYTES: it resolves the
// actual electron-builder TARGET (not the build host), takes the exact electron
// archive @electron/get already downloaded + checksum-verified into its cache,
// re-hashes those bytes against the committed manifest digest, validates the ZIP
// members, extracts to a private verified tree, verifies the expected binary,
// and writes a provenance marker. electron-builder is then handed ONLY that
// verified electronDist — it never fetches electron itself.
//
// A previously-staged verified tree is re-accepted only when its marker's
// archive digest still equals the committed manifest digest AND the tree still
// hashes to the marker's recorded value (any on-disk mutation fails closed).
//
// Everything here is pure over injected dependencies (archive bytes, extract,
// filesystem) so the whole policy is unit-tested without a network, a build, or
// a 200 MB download.

import crypto from 'node:crypto'

import { ELECTRON_ALLOWED_TARGETS } from './native-payload-verifier.mjs'

export const PROVENANCE_MARKER = '.hermes-electron-provenance.json'

export class ProvenanceError extends Error {
  constructor(message, reason) {
    super(message)
    this.name = 'ProvenanceError'
    this.reason = reason || 'provenance-error'
  }
}

function normVersion(v) {
  return String(v || '').replace(/^[^\d]*/, '').trim()
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex')
}

// ---------------------------------------------------------------------------
// (1) Resolve the electron-builder TARGET(s) from argv — target, not host.
//
// electron-builder platform flags: -w/--win/--windows, -m/--mac/--macos/--osx,
// -l/--linux. Arch flags: --x64, --arm64, --armv7l, --ia32. With no platform
// flag, electron-builder builds for the current HOST platform; with no arch
// flag, the host arch. A cross-target invocation (--win on linux) therefore
// resolves to win32 and is verified as win32.
// ---------------------------------------------------------------------------
const _PLATFORM_FLAGS = new Map([
  ['-w', 'win32'],
  ['--win', 'win32'],
  ['--windows', 'win32'],
  ['-m', 'darwin'],
  ['--mac', 'darwin'],
  ['--macos', 'darwin'],
  ['-o', 'darwin'],
  ['--osx', 'darwin'],
  ['-l', 'linux'],
  ['--linux', 'linux']
])

const _ARCH_FLAGS = new Map([
  ['--x64', 'x64'],
  ['--arm64', 'arm64'],
  ['--armv7l', 'armv7l'],
  ['--ia32', 'ia32']
])

export function resolveElectronTargets(argv, { hostPlatform, hostArch } = {}) {
  const platforms = new Set()
  const archs = new Set()
  for (const raw of argv || []) {
    const token = String(raw)
    // Support "--win=..." / bare flags. electron-builder also accepts platform
    // flags with an attached target list ("--win nsis"); the value is a target
    // NAME, not another flag, so only the flag token itself matters here.
    const flag = token.split('=', 1)[0]
    if (_PLATFORM_FLAGS.has(flag)) platforms.add(_PLATFORM_FLAGS.get(flag))
    if (_ARCH_FLAGS.has(flag)) archs.add(_ARCH_FLAGS.get(flag))
  }
  const plat = platforms.size ? [...platforms] : [hostPlatform || process.platform]
  const arch = archs.size ? [...archs] : [hostArch || process.arch]
  const out = []
  for (const p of plat) for (const a of arch) out.push({ platform: p, arch: a })
  return out
}

export function isKnownTarget(platform, arch) {
  return ELECTRON_ALLOWED_TARGETS.some(([p, a]) => p === platform && a === arch)
}

export function archiveName(version, platform, arch) {
  return `electron-v${normVersion(version)}-${platform}-${arch}.zip`
}

// The binary path INSIDE the extracted dist for a target. Also the ZIP member
// the archive must contain (mac keeps its .app bundle path).
export function expectedBinaryMember(platform) {
  if (platform === 'darwin') return 'Electron.app/Contents/MacOS/Electron'
  if (platform === 'win32') return 'electron.exe'
  return 'electron'
}

// ---------------------------------------------------------------------------
// (2) Archive byte verification.
// ---------------------------------------------------------------------------
export function verifyArchiveBytes(bytes, committedDigest) {
  const findings = []
  const md = String(committedDigest || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(md)) {
    findings.push('no committed manifest sha256 for the target archive')
    return findings
  }
  if (!bytes || bytes.length === 0) {
    findings.push('archive bytes missing/empty')
    return findings
  }
  const got = sha256Hex(bytes)
  if (!crypto.timingSafeEqual(Buffer.from(got, 'hex'), Buffer.from(md, 'hex'))) {
    findings.push(
      `archive sha256 ${got.slice(0, 12)}… does NOT match committed manifest digest ` +
        `${md.slice(0, 12)}… — refusing a mirror/cache-substituted archive`
    )
  }
  return findings
}

// ---------------------------------------------------------------------------
// (3) ZIP member validation. Entries: [{ name, isSymlink }]. Rejects path
// traversal / absolute paths / symlink members, and requires the expected
// electron binary to be present so a hollow archive can't pass.
// ---------------------------------------------------------------------------
export function validateZipEntries(entries, { platform }) {
  const findings = []
  if (!Array.isArray(entries) || entries.length === 0) {
    findings.push('archive has no entries')
    return findings
  }
  for (const entry of entries) {
    const name = String(entry?.name || '')
    const normalized = name.replace(/\\/g, '/')
    if (!name) {
      findings.push('archive contains an unnamed entry')
      continue
    }
    if (normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)) {
      findings.push(`archive entry is an absolute path: ${name}`)
    }
    if (normalized.split('/').some((seg) => seg === '..')) {
      findings.push(`archive entry escapes the tree: ${name}`)
    }
    if (entry?.isSymlink) {
      findings.push(`archive entry is a symlink (rejected): ${name}`)
    }
  }
  const wantBinary = expectedBinaryMember(platform)
  const hasBinary = entries.some((e) => String(e?.name || '').replace(/\\/g, '/') === wantBinary)
  if (!hasBinary) {
    findings.push(`archive is missing the expected electron binary member: ${wantBinary}`)
  }
  return findings
}

// ---------------------------------------------------------------------------
// (4) Extracted-tree digest — sorted relative POSIX path + sha256(content).
// Matches the whole-bundle digest style used elsewhere; injectable tree reader
// keeps it testable in-memory. Detects any post-extraction mutation.
// ---------------------------------------------------------------------------
export function hashTree(files) {
  // files: array of { path, content(Buffer|string) } OR a Map<path, content>.
  const entries = Array.isArray(files)
    ? files.map((f) => [f.path, f.content])
    : [...files.entries()]
  const digest = crypto.createHash('sha256')
  for (const [rel, content] of entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8')
    digest.update(String(rel).replace(/\\/g, '/'), 'utf8')
    digest.update(Buffer.from([0]))
    digest.update(crypto.createHash('sha256').update(buf).digest())
  }
  return digest.digest('hex')
}

// ---------------------------------------------------------------------------
// (5) Provenance marker. Written after a verified staging; re-checked to accept
// an existing verified tree without re-staging.
// ---------------------------------------------------------------------------
export function buildMarker({ version, platform, arch, archiveDigest, treeDigest }) {
  return {
    schema: 'hermes-electron-provenance/1',
    version: normVersion(version),
    platform,
    arch,
    archiveDigest: String(archiveDigest).toLowerCase(),
    treeDigest: String(treeDigest).toLowerCase(),
    stagedAt: new Date().toISOString()
  }
}

export function verifyMarker({ marker, committedDigest, currentTreeDigest, version, platform, arch }) {
  const md = String(committedDigest || '').trim().toLowerCase()
  if (!marker || typeof marker !== 'object') return { ok: false, reason: 'no-marker' }
  if (marker.schema !== 'hermes-electron-provenance/1') return { ok: false, reason: 'marker-schema' }
  if (normVersion(marker.version) !== normVersion(version)) return { ok: false, reason: 'marker-version' }
  if (marker.platform !== platform || marker.arch !== arch) return { ok: false, reason: 'marker-target' }
  if (!/^[0-9a-f]{64}$/.test(md)) return { ok: false, reason: 'no-committed-digest' }
  if (String(marker.archiveDigest || '').toLowerCase() !== md) {
    // The committed manifest moved (or the marker was forged) — the staged tree
    // is no longer provably the accepted archive.
    return { ok: false, reason: 'archive-digest-drift' }
  }
  if (String(marker.treeDigest || '').toLowerCase() !== String(currentTreeDigest || '').toLowerCase()) {
    return { ok: false, reason: 'tree-mutated' }
  }
  return { ok: true, reason: 'marker-valid' }
}

// ---------------------------------------------------------------------------
// (6) Orchestrator. Returns { distDir, source } or throws ProvenanceError.
//
// deps:
//   committedDigestFor(target) -> hex | null      (manifest authority)
//   readMarker(distDir)        -> marker | null   (parsed JSON)
//   readTree(distDir)          -> Map<path,content> | array   (for hashTree)
//   distExists(distDir)        -> bool
//   locateArchiveBytes(target) -> Buffer | null   (the cached, already-verified archive)
//   listZipEntries(bytes)      -> [{name,isSymlink}]
//   extract(bytes, destDir)    -> Map<path,content> | array   (the extracted tree)
//   writeMarker(distDir, marker)-> void
//   verifiedDistDir(target)    -> string          (where the verified tree lives)
// ---------------------------------------------------------------------------
export function resolveVerifiedElectronDist(target, deps, { allowUnverified = false } = {}) {
  const { platform, arch } = target
  if (!isKnownTarget(platform, arch)) {
    throw new ProvenanceError(`unsupported electron target ${platform}-${arch}`, 'unknown-target')
  }

  const committed = deps.committedDigestFor(target)
  const md = String(committed || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(md)) {
    if (allowUnverified) {
      return { distDir: deps.verifiedDistDir(target), source: 'break-glass', verified: false }
    }
    throw new ProvenanceError(
      `no committed manifest digest for electron ${platform}-${arch} — cannot byte-verify`,
      'no-committed-digest'
    )
  }

  const distDir = deps.verifiedDistDir(target)

  // Fast path: an already-staged verified tree whose marker still matches the
  // committed digest and whose bytes on disk are unchanged.
  if (deps.distExists(distDir)) {
    const marker = deps.readMarker(distDir)
    const currentTreeDigest = hashTree(deps.readTree(distDir))
    const verdict = verifyMarker({
      marker,
      committedDigest: md,
      currentTreeDigest,
      version: deps.version,
      platform,
      arch
    })
    if (verdict.ok) {
      return { distDir, source: 'marker', verified: true }
    }
    // A present-but-invalid tree (mutated / drifted / forged marker) must not be
    // silently reused — fall through to a fresh verified staging, and if that
    // can't happen, fail closed below.
  }

  // Stage: take the exact cached archive bytes, byte-verify, validate members,
  // extract, verify the binary, hash the tree, write the marker.
  const bytes = deps.locateArchiveBytes(target)
  if (!bytes) {
    if (allowUnverified) {
      return { distDir, source: 'break-glass', verified: false }
    }
    throw new ProvenanceError(
      `no verified electron archive available for ${platform}-${arch}; the @electron/get ` +
        'cache has no matching archive to byte-verify. Pre-stage the target archive or opt in ' +
        'explicitly (security.supply_chain.allow_unverified_components: ["electron"]).',
      'no-archive'
    )
  }

  const byteFindings = verifyArchiveBytes(bytes, md)
  if (byteFindings.length) {
    throw new ProvenanceError(`electron archive byte verification failed: ${byteFindings.join('; ')}`, 'archive-bytes')
  }

  const entries = deps.listZipEntries(bytes)
  const memberFindings = validateZipEntries(entries, { platform })
  if (memberFindings.length) {
    throw new ProvenanceError(`electron archive member validation failed: ${memberFindings.join('; ')}`, 'archive-members')
  }

  const tree = deps.extract(bytes, distDir)
  const treeDigest = hashTree(tree)
  // The extracted tree must actually contain the binary (extract could differ
  // from the listed members if extraction dropped/filtered entries).
  const treeMap = tree instanceof Map ? tree : new Map(tree.map((f) => [f.path, f.content]))
  const wantBinary = expectedBinaryMember(platform)
  if (![...treeMap.keys()].some((k) => String(k).replace(/\\/g, '/') === wantBinary)) {
    throw new ProvenanceError(`extracted electron tree is missing ${wantBinary}`, 'tree-missing-binary')
  }

  const marker = buildMarker({
    version: deps.version,
    platform,
    arch,
    archiveDigest: md,
    treeDigest
  })
  deps.writeMarker(distDir, marker)
  return { distDir, source: 'staged', verified: true }
}

// ---------------------------------------------------------------------------
// (7) beforePack-side INDEPENDENT verification (Alert 2). A direct
// `electron-builder` invocation bypasses the wrapper's staging, so the hook must
// itself REQUIRE and VALIDATE a target-specific verified electronDist for every
// production target — not merely trust the stamp/source. Pure over injected
// deps so it is unit-tested without a real build.
//
// deps:
//   verifiedRoot            -> absolute path of the verified staging root
//   version                 -> committed manifest electron version
//   committedDigestFor(target) -> hex | null   (manifest authority)
//   distExists(distDir)     -> bool            (marker present)
//   readMarker(distDir)     -> marker | null
//   readTree(distDir)       -> Map<path,content> | array
//   isInside(child, parent) -> bool            (path containment; injectable)
//   basename(p)             -> string
// ---------------------------------------------------------------------------
export function assertVerifiedElectronDist(target, electronDist, deps, { allowUnverified = false } = {}) {
  const { platform, arch } = target || {}
  if (!isKnownTarget(platform, arch)) {
    // Universal / unknown arch cannot be independently verified per-arch here.
    if (allowUnverified) return { verified: false, reason: 'break-glass-unknown-target' }
    throw new ProvenanceError(
      `electron target ${platform}-${arch} cannot be independently verified in beforePack; ` +
        `build per-arch through the wrapper or opt in explicitly`,
      'unknown-target'
    )
  }
  // 1. A missing/default electronDist means electron-builder would resolve
  //    electron itself via @electron/get (unverified network) — REJECT.
  if (!electronDist) {
    if (allowUnverified) return { verified: false, reason: 'break-glass-no-dist' }
    throw new ProvenanceError(
      `no electronDist for ${platform}-${arch}: electron-builder would fetch electron via @electron/get ` +
        `(unverified). Build via scripts/run-electron-builder.mjs, or supply a verified dist.`,
      'no-electron-dist'
    )
  }
  // 2. Must point INSIDE the verified staging root (not an arbitrary dir).
  if (!deps.isInside(electronDist, deps.verifiedRoot)) {
    throw new ProvenanceError(
      `electronDist '${electronDist}' is not inside the verified staging root '${deps.verifiedRoot}'`,
      'dist-outside-root'
    )
  }
  // 3. The dist dir name must match THIS exact target (catches cross-target).
  const expectedDir = `${normVersion(deps.version)}-${platform}-${arch}`
  if (deps.basename(electronDist) !== expectedDir) {
    throw new ProvenanceError(
      `electronDist target dir '${deps.basename(electronDist)}' does not match this target ` +
        `(${expectedDir}) — cross-target dist`,
      'dist-target-mismatch'
    )
  }
  // 4. Dist must exist with a provenance marker validating against the manifest.
  if (!deps.distExists(electronDist)) {
    throw new ProvenanceError(`verified electronDist '${electronDist}' does not exist (no marker)`, 'dist-missing')
  }
  const marker = deps.readMarker(electronDist)
  const tree = deps.readTree(electronDist)
  const currentTreeDigest = hashTree(tree)
  const committedDigest = deps.committedDigestFor(target)
  const verdict = verifyMarker({
    marker,
    committedDigest,
    currentTreeDigest,
    version: deps.version,
    platform,
    arch
  })
  if (!verdict.ok) {
    throw new ProvenanceError(
      `electronDist provenance invalid (${verdict.reason}) — refuse a mutated/forged/mismatched dist`,
      `marker-${verdict.reason}`
    )
  }
  // 5. The expected binary must actually be present in the verified tree.
  const treeMap = tree instanceof Map ? tree : new Map((tree || []).map((f) => [f.path, f.content]))
  const wantBinary = expectedBinaryMember(platform)
  if (![...treeMap.keys()].some((k) => String(k).replace(/\\/g, '/') === wantBinary)) {
    throw new ProvenanceError(`verified electronDist is missing ${wantBinary}`, 'dist-missing-binary')
  }
  return { verified: true }
}
