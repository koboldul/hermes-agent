/**
 * before-pack.mjs — electron-builder beforePack hook.
 *
 * Two responsibilities:
 *
 * 1. Removes any stale unpacked app directory (`appOutDir`) before
 *    electron-builder stages the Electron binaries into it.
 *
 * WHY THIS EXISTS
 * ---------------
 * electron-builder's final packaging step copies the stock `electron`
 * binary into `release/<platform>-unpacked/` and then renames it to the
 * product name (`Hermes`). If a PREVIOUS `npm run pack` was interrupted
 * (Ctrl-C, OOM kill, crash, full disk) the unpacked directory is left in a
 * corrupted partial state: it keeps the already-renamed `LICENSE.electron.txt`
 * and the Chromium payload (.pak/.so/icudtl.dat/chrome-sandbox) but is MISSING
 * the `electron` binary itself.
 *
 * On the next run, electron-builder sees the destination directory already
 * populated, skips re-copying the binary it thinks is present, then tries to
 * rename a `electron` file that no longer exists. The build dies with:
 *
 *   ENOENT: no such file or directory, rename
 *   '.../release/linux-unpacked/electron' -> '.../release/linux-unpacked/Hermes'
 *
 * This is a hard failure with no obvious cause for the user — `hermes desktop`
 * just prints "Desktop GUI build failed" and the only fix is to manually
 * `rm -rf` the release directory, which a normal user has no way to know.
 *
 * The packaging step is not idempotent across an interrupted run, so we make
 * it idempotent ourselves: wipe the target unpacked directory up front so
 * electron-builder always stages into a clean tree. This is safe — the
 * directory is a pure build artifact that electron-builder fully recreates
 * on every pack; nothing else depends on its prior contents.
 *
 * Cross-platform: the same partial-state trap exists on macOS
 * (the mac-unpacked Hermes.app bundle) and Windows (win-unpacked), so we
 * clean whatever `appOutDir` electron-builder hands us regardless of platform.
 *
 * Best-effort: a cleanup failure must never mask the real build. We log and
 * resolve rather than throw — worst case electron-builder hits the original
 * ENOENT, which is no worse than not having this hook at all.
 *
 * 2. Re-stages node-pty's native files for the ACTUAL target platform/arch
 *    of this pack. `npm run build` already staged node-pty once for the
 *    host machine (see scripts/stage-native-deps.mjs), which is correct for
 *    single-arch builds matching the host. But electron-builder can target
 *    a different arch than the host (cross-build), or pack multiple archs
 *    from one `npm run build` (e.g. `dist:mac` => x64 + arm64). Only this
 *    hook knows the real per-target arch, via `context.arch` /
 *    `context.electronPlatformName` — so it re-stages on top of whatever
 *    `npm run build` left behind, per target, right before files are read
 *    for packing.
 *
 * electron-builder passes a context with:
 *   - appOutDir:            the unpacked app directory about to be staged
 *   - electronPlatformName: 'win32' | 'darwin' | 'linux'
 *   - arch:                 Arch enum (0=ia32, 1=x64, 2=armv7l, 3=arm64, 4=universal)
 */
import { existsSync, readdirSync, readFileSync, rmSync, renameSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { Arch } from 'electron-builder'
import { stageNodePty, stageGetWindows } from './stage-native-deps.mjs'
import { assertProductionStampForTargets, electronBreakGlassAllowedForTargets, isProductionBuildFromTargets, isPublishReleaseContext, readStamp } from './release-gate.mjs'
import {
  assertPackagedInputClean,
  defaultGitExec,
  DESKTOP_SHADOW_PATHS,
  desktopPackagedInputPaths
} from './packaged-input-guard.mjs'
import { assertVerifiedElectronDist, PROVENANCE_MARKER } from './electron-dist-verifier.mjs'
import { supplyChainAllowsUnverified } from './native-payload-verifier.mjs'

const _desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const _repoRoot = path.resolve(_desktopRoot, '..', '..')

// ── Alert 2: independent verified-electronDist enforcement helpers ────────────

function _readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'))
}

// Independent (not the wrapper's) reader of the committed electron manifest.
function _electronManifestComponent() {
  const manifest = _readJson(path.join(_repoRoot, 'supply-chain', 'manifest.json'))
  const comp = (manifest.components || []).find((c) => c.name === 'electron')
  if (!comp || !comp.version) throw new Error('supply-chain/manifest.json has no electron component')
  return comp
}

const _MANIFEST_PLATFORM = { darwin: 'macos', win32: 'windows', linux: 'linux' }
const _MANIFEST_ARCH = { x64: 'x86_64', arm64: 'aarch64' }

function _committedElectronDigest(comp, platform, arch) {
  const mp = _MANIFEST_PLATFORM[platform] ?? platform
  const ma = _MANIFEST_ARCH[arch] ?? arch
  const art = (comp.artifacts || []).find((a) => a.platform === mp && a.arch === ma)
  const value = art && art.digest && art.digest.value
  return art && art.digest && art.digest.status === 'present' && typeof value === 'string' ? value : null
}

function _pathIsInside(child, parent) {
  const rel = path.relative(parent, child)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

function _readElectronTree(distDir) {
  const map = new Map()
  const walk = (dir, base) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (base === '' && e.name === PROVENANCE_MARKER) continue
      const full = path.join(dir, e.name)
      const rel = base ? `${base}/${e.name}` : e.name
      if (e.isDirectory()) walk(full, rel)
      else if (e.isFile()) map.set(rel, readFileSync(full))
    }
  }
  if (existsSync(distDir)) walk(distDir, '')
  return map
}

function _realElectronDeps() {
  const comp = _electronManifestComponent()
  return {
    verifiedRoot: path.join(_desktopRoot, 'node_modules', '.cache', 'hermes-electron-verified'),
    version: comp.version,
    committedDigestFor: (t) => _committedElectronDigest(comp, t.platform, t.arch),
    distExists: (d) => existsSync(path.join(d, PROVENANCE_MARKER)),
    readMarker: (d) => {
      try {
        return _readJson(path.join(d, PROVENANCE_MARKER))
      } catch {
        return null
      }
    },
    readTree: _readElectronTree,
    isInside: _pathIsInside,
    basename: path.basename
  }
}

function _configElectronDist(context) {
  return (
    (context && context.packager && context.packager.config && context.packager.config.electronDist) ||
    (context && context.packager && context.packager.info && context.packager.info.config && context.packager.info.config.electronDist) ||
    (context && context.config && context.config.electronDist) ||
    undefined
  )
}

function _electronBreakGlass() {
  try {
    const home = process.env.HERMES_HOME || path.join(process.env.HOME || process.env.USERPROFILE || '', '.hermes')
    return supplyChainAllowsUnverified('electron', readFileSync(path.join(home, 'config.yaml'), 'utf8'))
  } catch {
    return false
  }
}

/**
 * B3: INDEPENDENTLY require + validate a target-specific verified electronDist
 * for the current production target. A direct `electron-builder` (no wrapper)
 * reaches here with no verified electronDist and is REJECTED. Break-glass on
 * unverified Electron is limited to explicit `--dir` development packs — EVERY
 * artifact-producing (production) target rejects unverified Electron, derived
 * from isProductionBuildFromTargets and independent of --publish/tag. Because
 * this gate only runs for production builds (the caller checks
 * isProductionBuildFromTargets), allowUnverified resolves to false here; the
 * decision is computed explicitly so it stays correct if ever called directly.
 */
function verifyElectronDistForContext(context, { env = process.env, opts = {} } = {}) {
  const platform = context && context.electronPlatformName
  const archName = context && typeof context.arch === 'number' ? Arch[context.arch] : context && context.arch
  const target = { platform, arch: archName }

  let electronDist = opts.electronDist != null ? opts.electronDist : _configElectronDist(context)
  if (electronDist && !path.isAbsolute(electronDist)) {
    electronDist = path.resolve(_desktopRoot, electronDist)
  }

  const deps = opts.electronDeps || _realElectronDeps()
  const optIn = opts.electronBreakGlass != null ? opts.electronBreakGlass : _electronBreakGlass()
  // B3: derive the break-glass decision from the RESOLVED targets, not from
  // --publish/tag. Every artifact-producing target (NSIS/MSI/DMG/AppImage/…)
  // denies unverified Electron; only an all-`dir` dev pack (which never reaches
  // this gate) may opt in.
  const targetNames = (context && Array.isArray(context.targets) ? context.targets : [])
    .map((t) => t && t.name)
    .filter(Boolean)
  const allowUnverified = electronBreakGlassAllowedForTargets(targetNames, env, optIn)

  const res = assertVerifiedElectronDist(target, electronDist, deps, { allowUnverified })
  if (res && res.verified === false) {
    console.warn(
      `[before-pack] ⚠ UNVERIFIED ELECTRON (break-glass): packaging ${platform}-${archName} with an ` +
        `unverified electron dist — this artifact is NOT release-grade (${res.reason}).`
    )
  }
  return res
}

export function cleanStaleAppOutDir(appOutDir) {
  if (!appOutDir || typeof appOutDir !== 'string') {
    return false
  }
  if (!existsSync(appOutDir)) {
    return false
  }
  // Recursive + force so a half-written tree (read-only bits, partial files)
  // can't block the wipe. retry/maxRetries rides out transient EBUSY on
  // Windows where an AV/indexer may briefly hold a handle.
  rmSync(appOutDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
  return true
}

/**
 * Windows rollback material (#69179): before wiping the previous unpacked
 * tree, preserve it as `<appOutDir>.bak` — but ONLY when it holds the product
 * exe (i.e. it is a previously-working build, not the corrupted partial state
 * cleanStaleAppOutDir exists to remove). If the fresh pack then produces a
 * Hermes.exe that Windows can't load (truncated PE from a corrupt cached
 * Electron zip, wrong arch), the updater's integrity gate in
 * `hermes desktop --build-only` (hermes_cli/main.py
 * `_ensure_desktop_exe_launchable`) restores this .bak instead of leaving the
 * user with "This app can't run on your computer".
 *
 * Returns true when the tree was preserved (appOutDir no longer exists), false
 * when there was nothing worth preserving (caller falls through to the wipe).
 * A rename failure (AV holding a handle) also returns false — the wipe is the
 * safe fallback and matches pre-#69179 behavior exactly.
 */
export function preserveRollbackBackup(appOutDir, productExeName = 'Hermes.exe') {
  if (!appOutDir || typeof appOutDir !== 'string' || !existsSync(appOutDir)) {
    return false
  }
  if (!existsSync(path.join(appOutDir, productExeName))) {
    // Partial/corrupt tree (interrupted prior pack) — not rollback material.
    return false
  }
  const backupDir = `${appOutDir}.bak`
  try {
    rmSync(backupDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
    renameSync(appOutDir, backupDir)
    return true
  } catch {
    return false
  }
}

export default async function beforePack(context, opts = {}) {
  // A10: enforce the attested install stamp for EVERY artifact-producing pack,
  // right here in the electron-builder hook — so a DIRECT `electron-builder`
  // invocation (bypassing scripts/run-electron-builder.mjs) is still gated. The
  // resolved targets decide production vs. the exempt `--dir` dev pack. Throwing
  // fails the build closed before any artifact is written.
  const env = opts.env || process.env
  const stampPath = opts.stampPath || path.join(_desktopRoot, 'build', 'install-stamp.json')
  {
    const targetNames = (context && Array.isArray(context.targets) ? context.targets : [])
      .map((t) => t && t.name)
      .filter(Boolean)
    assertProductionStampForTargets({ targetNames, env, stampPath })

    // A5: for a production pack, INDEPENDENTLY re-interrogate git over the FULL
    // input closure — do not trust the stamp JSON alone. Prove HEAD == the
    // stamped commit and that the packaged/build-input tree (apps/desktop,
    // apps/shared, root package.json/lock, every workspace manifest, native
    // staging scripts, supply-chain manifest) has no tracked changes AND no
    // untracked files, AND that the source dirs have no IGNORED shadow files
    // (e.g. a stray apps/shared/src/index.js over the committed index.ts). git
    // unavailable → fail closed.
    if (isProductionBuildFromTargets(targetNames, env)) {
      const stamp = readStamp(stampPath)
      const cwd = opts.cwd || _repoRoot
      assertPackagedInputClean({
        stampedCommit: stamp && stamp.commit,
        packagedPaths: opts.packagedPaths || desktopPackagedInputPaths(cwd),
        shadowPaths: opts.shadowPaths || DESKTOP_SHADOW_PATHS,
        execFn: opts.execFn || defaultGitExec,
        cwd,
        label: 'before-pack'
      })

      // Alert 2: INDEPENDENTLY require + validate a target-specific verified
      // electronDist. A direct `electron-builder` (bypassing the wrapper) has no
      // verified dist and is REJECTED here — it would otherwise fetch electron
      // via @electron/get (unverified). opts.verifyElectronDist overrides the
      // default for unit tests that focus on other gates.
      const verifyElectron = opts.verifyElectronDist || verifyElectronDistForContext
      verifyElectron(context, { env, opts })
    }
  }

  const appOutDir = context && context.appOutDir
  const platformName = context && context.electronPlatformName
  try {
    // Windows: keep the previous working build as rollback material for the
    // post-build integrity gate (#69179) instead of destroying it. Falls
    // through to the plain wipe when the old tree is partial/corrupt or the
    // rename fails.
    const productExe = `${(context && context.packager?.appInfo?.productFilename) || 'Hermes'}.exe`
    if (platformName === 'win32' && preserveRollbackBackup(appOutDir, productExe)) {
      console.log(`[before-pack] preserved previous unpacked dir for rollback: ${appOutDir}.bak`)
    } else if (cleanStaleAppOutDir(appOutDir)) {
      console.log(`[before-pack] removed stale unpacked dir before staging: ${appOutDir}`)
    }
  } catch (err) {
    // Never fail the build over cleanup; surface why so a genuinely stuck
    // directory (permissions, mount) is still diagnosable.
    console.warn(`[before-pack] could not clean ${appOutDir} (${err.message}); continuing`)
  }

  try {
    const platform = context && context.electronPlatformName
    const archName = context && typeof context.arch === 'number' ? Arch[context.arch] : undefined
    if (platform && archName) {
      if (archName === 'universal') {
        console.warn(
          '[before-pack] target arch is "universal" — node-pty has no universal prebuild; ' +
            'staged binary will be whichever single-arch copy npm run build left behind. ' +
            'lipo-merge x64/arm64 .node files manually if you need a true universal build.'
        )
      } else {
        await stageNodePty({ platform, arch: archName })
        console.log(`[before-pack] re-staged node-pty for target ${platform}-${archName}`)
      }
      // The macOS helper is universal, while Windows bindings are arch-specific.
      // Pass the target arch so an ARM64 package never stages an x64 binding.
      // A6: for a publish/tag release the get-windows FINAL swap is fail-closed
      // if the shared Python transaction is unavailable (isPublishReleaseContext).
      stageGetWindows({ platform, arch: archName, isRelease: isPublishReleaseContext(context, env) })
      console.log(`[before-pack] re-staged get-windows for target ${platform}-${archName}`)
    }
  } catch (err) {
    // This one SHOULD fail the build — a missing/wrong native binary for the
    // target arch means a broken package shipped to users, which is worse
    // than a build that fails loudly here.
    throw new Error(`[before-pack] failed to stage native deps for this target: ${err.message}`)
  }
}