// native-payload-verifier.mjs — WP4 item 2.
//
// Pure, dependency-free verification logic for the Desktop native/electron
// executable payloads. Ties together the pieces the plan names: package.json
// electronVersion, package-lock integrity, node_modules/electron/checksums.json,
// the target platform/arch, and the @electron/get download identity — plus the
// node-pty / get-windows native prebuild decision.
//
// The functions are pure (inputs -> findings) so they can be unit-tested
// without a network, a build, or a filesystem. A thin CLI wrapper
// (verify-native-payloads.mjs) reads the real files and calls verifyAll().

// Electron platform archives @electron/get may resolve. A target outside this
// set is refused (an unknown platform/arch cannot be checksum-matched).
export const ELECTRON_ALLOWED_TARGETS = [
  ['darwin', 'x64'],
  ['darwin', 'arm64'],
  ['linux', 'x64'],
  ['linux', 'arm64'],
  ['win32', 'x64'],
  ['win32', 'arm64']
]

function normVersion(v) {
  return String(v || '').replace(/^[^\d]*/, '').trim()
}

// (1) package.json electronVersion + devDependency pin, tied to the manifest.
export function verifyElectronPin({ pkg, lock, expectedVersion }) {
  const findings = []
  const exp = normVersion(expectedVersion)
  if (!exp) findings.push('no expected electron version supplied (manifest pin missing)')

  const buildVer = normVersion(pkg?.build?.electronVersion)
  if (buildVer !== exp) {
    findings.push(`package.json build.electronVersion ${buildVer || '(none)'} != ${exp}`)
  }
  const devVer = normVersion(pkg?.devDependencies?.electron ?? pkg?.dependencies?.electron)
  if (devVer && devVer !== exp) {
    findings.push(`package.json electron dependency ${devVer} != ${exp}`)
  }

  // (2) lock integrity: the electron npm tarball must be pinned + hashed +
  // resolved from the canonical registry (a mirror may change location only,
  // never the accepted integrity).
  const lockEntry = lock?.packages?.['node_modules/electron']
  if (!lockEntry) {
    findings.push('package-lock has no node_modules/electron entry (tarball not lock-anchored)')
  } else {
    if (normVersion(lockEntry.version) !== exp) {
      findings.push(`package-lock electron version ${lockEntry.version} != ${exp}`)
    }
    if (!/^sha(?:512|256)-.+/.test(String(lockEntry.integrity || ''))) {
      findings.push('package-lock electron entry has no sha integrity')
    }
    if (!String(lockEntry.resolved || '').startsWith('https://registry.npmjs.org/')) {
      findings.push('package-lock electron not resolved from registry.npmjs.org')
    }
  }
  return findings
}

// (3) checksums.json (from node_modules/electron at build time) is the
// @electron/get download identity. The AUTHORITY is the COMMITTED manifest
// digest for the exact target: the package-bundled checksums.json entry MUST
// equal ``manifestDigest``. A generated/mirror-supplied checksum file alone is
// NOT trusted — matching the committed digest is what stops a mirror altering
// the accepted archive.
export function verifyChecksums({ checksums, expectedVersion, platform, arch, manifestDigest }) {
  const findings = []
  const exp = normVersion(expectedVersion)
  const md = String(manifestDigest || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(md)) {
    findings.push(
      `no committed manifest sha256 for electron-v${exp}-${platform}-${arch}.zip — the release ` +
      'manifest is the authority and must pin this target before a verified build'
    )
    return findings
  }
  if (!checksums || typeof checksums !== 'object' || Array.isArray(checksums) || Object.keys(checksums).length === 0) {
    findings.push(
      'electron checksums.json missing/empty — cannot confirm the @electron/get platform archive identity'
    )
    return findings
  }
  const key = `electron-v${exp}-${platform}-${arch}.zip`
  const value = checksums[key]
  if (value === undefined) {
    findings.push(`checksums.json has no entry for ${key} (target archive identity unresolved)`)
  } else if (!/^[0-9a-f]{64}$/i.test(String(value))) {
    findings.push(`checksums.json ${key} is not a sha256 digest`)
  } else if (String(value).trim().toLowerCase() !== md) {
    findings.push(
      `checksums.json ${key} (${String(value).slice(0, 12)}…) does NOT match the committed ` +
      `manifest digest (${md.slice(0, 12)}…) — refusing a mirror/drifted archive`
    )
  }
  return findings
}

// (4) target platform/arch must be a known electron target.
export function verifyTarget({ platform, arch }) {
  const ok = ELECTRON_ALLOWED_TARGETS.some(([p, a]) => p === platform && a === arch)
  return ok ? [] : [`unsupported/unknown electron target ${platform}-${arch}`]
}

// (5) node-pty / get-windows native prebuild decision. Only a lock-bound
// bundled prebuild (already present in node_modules from the lock-anchored
// tarball) may be staged. Any NETWORK fallback — prebuild-install fetching a
// binary, electron-rebuild downloading headers + compiling — lacks a manifest
// identity and must fail closed unless the operator explicitly opts in
// (break-glass), never automatically.
export function nativePrebuildDecision({
  prebuildPresent,
  hostMatches,
  allowUnverifiedNativeRebuild
}) {
  if (prebuildPresent) return { action: 'use_prebuild', reason: 'lock-bound bundled prebuild present' }
  if (allowUnverifiedNativeRebuild && hostMatches) {
    return { action: 'rebuild_allowed', reason: 'explicit operator break-glass opt-in' }
  }
  return {
    action: 'fail_closed',
    reason:
      'no lock-bound bundled prebuild for the target and no manifest identity for the ' +
      'network native rebuild/fetch (prebuild-install / electron-rebuild). Provide a ' +
      'prebuild, build on the target platform, or opt in explicitly ' +
      '(security.supply_chain.allow_unverified_components: ["electron-native"]).'
  }
}

// Expected on-disk binary format per target platform. get-windows ships a PE
// (node-get-windows.node) on Windows and a universal Mach-O helper ("main") on
// macOS; Linux has no native binary (it shells out to xprop). classifyNativeBinary
// returns these same platform strings.
export const NATIVE_BINDING_FORMAT = { win32: 'win32', darwin: 'darwin' }

// A8 (get-windows): decide whether a native binding PRESENT on disk may be
// staged. Pure over its inputs so it is unit-tested without real binaries.
//   classified   — classifyNativeBinary() result ('win32'|'darwin'|'linux'|null)
//   platform     — target platform ('win32'|'darwin'|'linux')
//   actualSha256 — sha256 of the on-disk binding bytes
//   pinnedDigest — committed manifest digest for this target, or null/undefined
// Returns { action: 'stage'|'reject', reason }. 'reject' means FAIL CLOSED —
// the caller must not stage the binding and must not fall back to a
// network/build path. An ABSENT binding (nothing on disk) is the caller's
// concern (feature disabled), not this function's.
export function nativeBindingDecision({ classified, platform, actualSha256, pinnedDigest }) {
  const expected = NATIVE_BINDING_FORMAT[platform]
  if (!expected) {
    return { action: 'reject', reason: `platform ${platform} has no supported native binding format (PE/Mach-O only)` }
  }
  // PE/Mach-O ONLY: reject anything whose magic isn't the expected format for
  // the target (an ELF, an unknown blob, or a cross-platform binary).
  if (classified !== expected) {
    return {
      action: 'reject',
      reason: `binary format ${classified ?? 'unknown'} is not the expected ${expected} (PE/Mach-O only)`
    }
  }
  const pin = String(pinnedDigest || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(pin)) {
    return { action: 'reject', reason: 'no committed manifest digest for this target — unmarked native binding' }
  }
  if (String(actualSha256 || '').trim().toLowerCase() !== pin) {
    return {
      action: 'reject',
      reason: 'native binding sha256 does not match the committed manifest digest (mutated/substituted)'
    }
  }
  return { action: 'stage', reason: 'native binding byte-verified against the committed manifest digest' }
}

// Roll-up for the pre-build gate. Returns [] when the electron payload chain is
// fully anchored for the target, else the list of findings (fail closed).
export function verifyAll({ pkg, lock, checksums, expectedVersion, platform, arch, manifestDigest }) {
  return [
    ...verifyTarget({ platform, arch }),
    ...verifyElectronPin({ pkg, lock, expectedVersion }),
    ...verifyChecksums({ checksums, expectedVersion, platform, arch, manifestDigest })
  ]
}

// Pure config-only opt-in reader (mirrors the backend gate and
// desktop-plugin-install.supplyChainAllowsUnverified). `enforce: false` alone
// does NOT authorize (WP4 item 5) — authorization requires the explicit
// per-component allow-list (or the "*" sentinel).
export function supplyChainAllowsUnverified(component, configText) {
  const lines = String(configText || '').split(/\r?\n/)
  const start = lines.findIndex((l) => /^\s*supply_chain\s*:/.test(l))
  if (start < 0) return false
  const indent = lines[start].match(/^(\s*)/)?.[1].length ?? 0
  const block = []
  for (let j = start + 1; j < lines.length; j++) {
    const line = lines[j]
    if (line.trim() === '') {
      block.push(line)
      continue
    }
    const lineIndent = line.match(/^(\s*)/)?.[1].length ?? 0
    if (lineIndent <= indent) break
    block.push(line)
  }
  const text = block.join('\n')
  const listMatch = text.match(/allow_unverified_components\s*:\s*(\[[^\]]*\]|(?:\r?\n\s+-\s+[^\r\n]+)+)/i)
  if (!listMatch) return false
  const listText = listMatch[1].toLowerCase()
  const wanted = component.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(^|[\\[,"'\\s-])(${wanted}|\\*)([\\],"'\\s]|$)`).test(listText)
}
