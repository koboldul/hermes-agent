// run-electron-builder.mjs — A8 verified electron staging.
//
// Before electron-builder packages the app, this:
//   1. Resolves the actual builder TARGET(s) from argv — target, not host, so a
//      cross-target build (`--win` on linux) is verified as win32.
//   2. Runs the metadata gate (verify-native-payloads.mjs) for that target.
//   3. Byte-verifies the exact electron archive @electron/get already downloaded
//      and checksum-verified into its cache: SHA-256 the bytes against the
//      COMMITTED manifest digest, validate the ZIP members, extract to a private
//      verified tree, verify the electron binary, and write a provenance marker.
//   4. Hands electron-builder ONLY that verified electronDist — the builder /
//      @electron/get never fetch electron themselves.
//
// A previously-staged verified tree is re-accepted only when its marker's
// archive digest still equals the committed manifest digest AND the tree still
// hashes to the recorded value (any mutation fails closed). Missing verified
// bytes fail closed unless the operator explicitly opts in
// (security.supply_chain.allow_unverified_components: ["electron"]).

import fs from "node:fs"
import path from "node:path"
import crypto from "node:crypto"
import { spawnSync } from "node:child_process"
import { createRequire } from "node:module"
import { fileURLToPath } from "node:url"
import { homedir } from "node:os"

import {
  PROVENANCE_MARKER,
  ProvenanceError,
  resolveElectronTargets,
  resolveVerifiedElectronDist
} from "./electron-dist-verifier.mjs"
import { extractAll, listEntries } from "./electron-zip.mjs"
import { supplyChainAllowsUnverified } from "./native-payload-verifier.mjs"
import { publishThroughPythonTransaction, sha256Hex } from "./python-publish.mjs"
import {
  electronBreakGlassAllowedForArgv,
  enforceProductionStamp,
  isProductionBuild,
  isProductionPublish
} from "./release-gate.mjs"

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const desktopRoot = path.resolve(here, "..")
const repoRoot = path.resolve(desktopRoot, "..", "..")

// --- manifest authority (canonical electron version + committed target digest) --
const _PLATFORM_MAP = { darwin: "macos", win32: "windows", linux: "linux" }
const _ARCH_MAP = { x64: "x86_64", arm64: "aarch64" }

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"))
}

function electronManifestComponent() {
  const manifest = readJson(path.join(repoRoot, "supply-chain", "manifest.json"))
  const comp = (manifest.components || []).find((c) => c.name === "electron")
  if (!comp || !comp.version) {
    throw new Error("supply-chain/manifest.json has no electron component/version to pin against")
  }
  return comp
}

function committedDigestFor(comp, platform, arch) {
  const mp = _PLATFORM_MAP[platform] ?? platform
  const ma = _ARCH_MAP[arch] ?? arch
  const art = (comp.artifacts || []).find((a) => a.platform === mp && a.arch === ma)
  const value = art?.digest?.value
  return art && art.digest?.status === "present" && typeof value === "string" ? value : null
}

// --- manifest anti-rollback state is owned by the shared Python transaction ---
// The electron dist swap routes through
// `python -m hermes_cli.supply_chain.publish_cli`, which reads the manifest
// sequence + component floor itself and commits the anti-rollback high-water to
// the profile state file OUTSIDE node_modules — the JS side no longer computes a
// sequence or a state path.

// --- break-glass opt-in (config-only, mirrors stage-native-deps) ----------------
function electronDistOptIn() {
  try {
    const home = process.env.HERMES_HOME || path.join(homedir(), ".hermes")
    return supplyChainAllowsUnverified("electron", fs.readFileSync(path.join(home, "config.yaml"), "utf8"))
  } catch {
    return false
  }
}

// --- cached electron archive locator (the exact bytes @electron/get verified) ---
function cacheRoots() {
  const roots = []
  if (process.env.ELECTRON_CACHE) roots.push(process.env.ELECTRON_CACHE)
  if (process.env.electron_config_cache) roots.push(process.env.electron_config_cache)
  if (process.platform === "win32") {
    if (process.env.LOCALAPPDATA) roots.push(path.join(process.env.LOCALAPPDATA, "electron", "Cache"))
    if (process.env.APPDATA) roots.push(path.join(process.env.APPDATA, "electron", "Cache"))
  } else if (process.platform === "darwin") {
    roots.push(path.join(homedir(), "Library", "Caches", "electron"))
  } else {
    roots.push(path.join(homedir(), ".cache", "electron"))
  }
  return roots.filter(Boolean)
}

function findFileByName(root, name, maxDepth = 4) {
  if (!fs.existsSync(root)) return null
  const stack = [[root, 0]]
  while (stack.length) {
    const [dir, depth] = stack.pop()
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      const full = path.join(dir, e.name)
      if (e.isFile() && e.name === name) return full
      if (e.isDirectory() && depth < maxDepth) stack.push([full, depth + 1])
    }
  }
  return null
}

function locateArchiveBytes(version, platform, arch) {
  // Explicit override for deterministic/air-gapped CI staging.
  if (process.env.ELECTRON_ARCHIVE_PATH && fs.existsSync(process.env.ELECTRON_ARCHIVE_PATH)) {
    return fs.readFileSync(process.env.ELECTRON_ARCHIVE_PATH)
  }
  const ver = String(version).replace(/^[^\d]*/, "")
  const name = `electron-v${ver}-${platform}-${arch}.zip`
  for (const root of cacheRoots()) {
    const hit = findFileByName(root, name)
    if (hit) return fs.readFileSync(hit)
  }
  return null
}

// --- verified tree location + marker/tree IO ------------------------------------
function verifiedDistDir(version, platform, arch) {
  return path.join(
    desktopRoot,
    "node_modules",
    ".cache",
    "hermes-electron-verified",
    `${version}-${platform}-${arch}`
  )
}

function readTree(dir) {
  const map = new Map()
  const walk = (d, base) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      // The marker itself is not part of the archive tree it certifies.
      if (base === "" && e.name === PROVENANCE_MARKER) continue
      const full = path.join(d, e.name)
      const rel = base ? `${base}/${e.name}` : e.name
      if (e.isDirectory()) walk(full, rel)
      else if (e.isFile()) map.set(rel, fs.readFileSync(full))
    }
  }
  if (fs.existsSync(dir)) walk(dir, "")
  return map
}

function writeExtractedFile(destDir, rel, data, mode) {
  const full = path.join(destDir, rel)
  fs.mkdirSync(path.dirname(full), { recursive: true })
  fs.writeFileSync(full, data, { mode })
}

function makeDeps(comp, target, { isRelease = false } = {}) {
  const version = comp.version
  const { platform, arch } = target
  const distDir = verifiedDistDir(version, platform, arch)
  return {
    version,
    committedDigestFor: () => committedDigestFor(comp, platform, arch),
    verifiedDistDir: () => distDir,
    // A directory only counts as an existing verified tree when it carries a
    // marker — a partial/aborted extraction must not be reused.
    distExists: (d) => fs.existsSync(path.join(d, PROVENANCE_MARKER)),
    readMarker: (d) => {
      try {
        return readJson(path.join(d, PROVENANCE_MARKER))
      } catch {
        return null
      }
    },
    readTree,
    locateArchiveBytes: () => locateArchiveBytes(version, platform, arch),
    listZipEntries: (bytes) => listEntries(bytes),
    // A6: the swap into the electron-builder-consumed dist goes through the
    // SHARED Python kernel-locked (fcntl/msvcrt) transaction — NOT a
    // JS-reimplemented O_EXCL file lock. Extract to a sibling stage OUTSIDE the
    // live target, then hand the final publication to
    // `python -m hermes_cli.supply_chain.publish_cli`, which under one kernel
    // advisory lock reloads the anti-rollback state (kept OUTSIDE node_modules),
    // rechecks the electron high-water, re-verifies the archive digest against
    // the committed manifest, atomically swaps the stage into place WITH
    // rollback (the previous verified dist is preserved on any failure), and
    // commits the high-water AFTER the publish. Release builds FAIL CLOSED when
    // the Python helper is unavailable.
    extract: (bytes, dest) => {
      const stage = `${dest}.stage-${process.pid}-${crypto.randomBytes(3).toString("hex")}`
      fs.rmSync(stage, { recursive: true, force: true })
      const tree = extractAll(bytes, { destDir: stage, writeFile: writeExtractedFile })
      try {
        publishThroughPythonTransaction({
          component: "electron",
          platform,
          arch,
          stagedSha256: sha256Hex(bytes),
          stageDir: stage,
          targetDir: dest,
          statePath: null, // Python default: profile state, OUTSIDE node_modules
          isRelease,
          repoRoot,
          env: process.env
        })
        return tree
      } finally {
        fs.rmSync(stage, { recursive: true, force: true })
      }
    },
    writeMarker: (d, marker) => {
      fs.mkdirSync(d, { recursive: true })
      fs.writeFileSync(path.join(d, PROVENANCE_MARKER), JSON.stringify(marker, null, 2))
    }
  }
}

// --- metadata gate per target ---------------------------------------------------
function runMetadataGate(platform, arch) {
  const verifier = path.join(here, "verify-native-payloads.mjs")
  const res = spawnSync(process.execPath, [verifier, platform, arch], { stdio: "inherit" })
  if (res.status !== 0) {
    console.error(
      `[run-electron-builder] native payload metadata gate failed for ${platform}-${arch} — refusing to build.`
    )
    process.exit(res.status == null ? 1 : res.status)
  }
}

// --- legacy local dist (only under break-glass) ---------------------------------
function localElectronDistDir() {
  try {
    return path.join(path.dirname(require.resolve("electron/package.json")), "dist")
  } catch {
    return null
  }
}

function distBinary(dist) {
  if (process.platform === "darwin") return path.join(dist, "Electron.app", "Contents", "MacOS", "Electron")
  if (process.platform === "win32") return path.join(dist, "electron.exe")
  return path.join(dist, "electron")
}

function electronBuilderCli() {
  const pkgJson = require.resolve("electron-builder/package.json")
  const bin = require(pkgJson).bin
  const rel = typeof bin === "string" ? bin : bin["electron-builder"]
  return path.join(path.dirname(pkgJson), rel)
}

// -------------------------------------------------------------------------------
function main() {
  const argv = process.argv.slice(2)
  const optIn = electronDistOptIn()

  // A10: a production/publish build must ship an attested install stamp. This is
  // enforced here (not only in the CI workflow) so packaging can never proceed
  // with an all-zero/dirty/branch-only stamp regardless of how it was invoked.
  enforceProductionStamp({
    argv,
    env: process.env,
    stampPath: path.join(desktopRoot, "build", "install-stamp.json")
  })

  let comp
  try {
    comp = electronManifestComponent()
  } catch (err) {
    console.error(`[run-electron-builder] ${err.message}`)
    process.exit(1)
  }

  const targets = resolveElectronTargets(argv)

  // B3: break-glass (unverified Electron) is permitted ONLY for an explicit
  // `--dir` dev pack. EVERY artifact-producing (production) target — NSIS/MSI/
  // DMG/AppImage/deb/rpm/a bare build — rejects unverified Electron, derived
  // from isProductionBuild and independent of --publish/tag.
  const isProd = isProductionBuild(argv, process.env)
  const allowUnverified = electronBreakGlassAllowedForArgv(argv, process.env, optIn)

  // A single electronDist cannot correctly serve more than one (platform,arch),
  // and post-gate fetch is forbidden — require one target per invocation.
  if (targets.length !== 1) {
    if (!allowUnverified) {
      console.error(
        "[run-electron-builder] refusing a multi-target build in one invocation: a single " +
          "verified electronDist cannot serve multiple targets and electron fetch is disabled. " +
          (isProd
            ? "This is a production (artifact-producing) build — break-glass is limited to `--dir` dev packs. "
            : "") +
          "Build one platform/arch per invocation, or opt in for a `--dir` dev pack " +
          '(security.supply_chain.allow_unverified_components: ["electron"]).'
      )
      process.exit(1)
    }
    console.warn(
      "[run-electron-builder] break-glass: multi-target `--dir` dev pack; letting electron-builder resolve electron."
    )
    return spawnBuilder(argv)
  }

  const target = targets[0]
  runMetadataGate(target.platform, target.arch)

  // A6: a publish/tag release routes the electron dist swap through the shared
  // kernel-locked transaction with fail-closed-when-unavailable semantics.
  const isRelease = isProductionPublish(argv, process.env)

  let electronDistArg = null
  try {
    const res = resolveVerifiedElectronDist(target, makeDeps(comp, target, { isRelease }), {
      allowUnverified
    })
    if (res.verified) {
      electronDistArg = res.distDir
      console.log(
        `[run-electron-builder] verified electronDist (${res.source}) for ` +
          `${target.platform}-${target.arch}: ${res.distDir}`
      )
    } else {
      // Break-glass path: no verified bytes; fall back to the local dist.
      const local = localElectronDistDir()
      if (local && fs.existsSync(distBinary(local))) {
        electronDistArg = local
        console.warn(`[run-electron-builder] break-glass: using unverified local electron dist ${local}`)
      } else {
        console.warn("[run-electron-builder] break-glass: no verified or local dist; electron-builder may fetch.")
      }
    }
  } catch (err) {
    if (err instanceof ProvenanceError) {
      console.error(`[run-electron-builder] electron byte verification failed: ${err.message}`)
    } else {
      console.error(`[run-electron-builder] electron staging error: ${err.message}`)
    }
    process.exit(1)
  }

  const args = []
  if (electronDistArg) args.push(`-c.electronDist=${electronDistArg}`)
  args.push(...argv)
  spawnBuilder(args)
}

function spawnBuilder(args) {
  // Alert 2: propagate the wrapper's publish decision (resolved from the FULL
  // original argv/env) to the spawned electron-builder child, where beforePack
  // runs. beforePack then denies break-glass on unverified Electron for any
  // publish/tag release even when it can only see the electron-builder-resolved
  // publish config. Never clears an already-set flag.
  const childEnv = { ...process.env }
  if (isProductionPublish(process.argv.slice(2), process.env)) {
    childEnv.HERMES_DESKTOP_IS_PUBLISH = "1"
  }
  const result = spawnSync(process.execPath, [electronBuilderCli(), ...args], { stdio: "inherit", env: childEnv })
  if (result.error) {
    console.error(`[run-electron-builder] spawn failed: ${result.error.message}`)
    process.exit(1)
  }
  process.exit(result.status == null ? 1 : result.status)
}

main()
