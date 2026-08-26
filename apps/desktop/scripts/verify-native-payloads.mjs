#!/usr/bin/env node
// verify-native-payloads.mjs — WP4 item 2 pre-build gate.
//
// Fails closed BEFORE electron-builder packages the app when the electron /
// native payload chain is not fully anchored for the target: the pinned
// electron version (package.json) must match the reviewed manifest, the npm
// tarball must be lock-integrity-bound, and node_modules/electron/checksums.json
// (the @electron/get download identity) must carry the target archive's SHA256.
//
// Usage:
//   node scripts/verify-native-payloads.mjs                 # host target
//   node scripts/verify-native-payloads.mjs win32 arm64      # explicit target
//
// A mirror (ELECTRON_MIRROR) may change WHERE the archive is fetched from, never
// the accepted checksum — this gate reads the checksum, not the location.

import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { verifyAll } from './native-payload-verifier.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const desktopRoot = resolve(here, '..')
const repoRoot = resolve(desktopRoot, '..', '..')

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function firstExisting(paths) {
  for (const p of paths) if (existsSync(p)) return p
  return null
}

function expectedElectronComponent() {
  const manifest = readJson(join(repoRoot, 'supply-chain', 'manifest.json'))
  const comp = (manifest.components || []).find((c) => c.name === 'electron')
  if (!comp || !comp.version) {
    throw new Error('supply-chain/manifest.json has no electron component/version to pin against')
  }
  return comp
}

// Map electron's platform/arch (darwin/win32/linux, x64/arm64) to the manifest's
// canonical naming (macos/windows/linux, x86_64/aarch64).
const _PLATFORM_MAP = { darwin: 'macos', win32: 'windows', linux: 'linux' }
const _ARCH_MAP = { x64: 'x86_64', arm64: 'aarch64' }

function committedDigestFor(comp, platform, arch) {
  const mp = _PLATFORM_MAP[platform] ?? platform
  const ma = _ARCH_MAP[arch] ?? arch
  const art = (comp.artifacts || []).find((a) => a.platform === mp && a.arch === ma)
  const value = art?.digest?.value
  return art && art.digest?.status === 'present' && typeof value === 'string' ? value : null
}

function main() {
  const platform = process.argv[2] || process.platform
  const arch = process.argv[3] || process.arch

  const pkg = readJson(join(desktopRoot, 'package.json'))

  const lockPath = firstExisting([
    join(repoRoot, 'package-lock.json'),
    join(desktopRoot, 'package-lock.json')
  ])
  if (!lockPath) {
    console.error('[verify-native-payloads] no package-lock.json found — cannot verify lock integrity')
    process.exit(1)
  }
  const lock = readJson(lockPath)

  const checksumsPath = firstExisting([
    join(desktopRoot, 'node_modules', 'electron', 'checksums.json'),
    join(repoRoot, 'node_modules', 'electron', 'checksums.json')
  ])
  const checksums = checksumsPath ? readJson(checksumsPath) : null

  let comp
  try {
    comp = expectedElectronComponent()
  } catch (err) {
    console.error(`[verify-native-payloads] ${err.message}`)
    process.exit(1)
  }
  const expectedVersion = comp.version
  const manifestDigest = committedDigestFor(comp, platform, arch)

  const findings = verifyAll({ pkg, lock, checksums, expectedVersion, platform, arch, manifestDigest })
  if (findings.length > 0) {
    console.error(
      `[verify-native-payloads] FAIL CLOSED for ${platform}-${arch} (electron ${expectedVersion}):`
    )
    for (const f of findings) console.error(`  - ${f}`)
    console.error('  See docs/security/supply-chain-migration.md.')
    process.exit(1)
  }
  console.log(
    `[verify-native-payloads] OK: electron ${expectedVersion} archive matches the committed ` +
    `manifest digest for ${platform}-${arch}`
  )
}

main()
