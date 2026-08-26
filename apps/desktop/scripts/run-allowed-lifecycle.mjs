// run-allowed-lifecycle.mjs -- A4 allowlisted lifecycle-script orchestrator.
//
// npm's package.json `allowScripts` allowlist is NOT honored by every supported
// npm (npm 10 ignores it and runs ALL lifecycle scripts). The robust,
// version-independent posture is therefore:
//
//   1. Install with `npm ci --ignore-scripts` (NO package runs arbitrary code).
//   2. Run this orchestrator, which executes ONLY the reviewed, allowlisted
//      lifecycle scripts (root package.json `allowScripts` entries set to
//      `true`) -- after verifying each package's identity against the lockfile --
//      via `npm rebuild <name>`. Anything set to `false` (get-windows) is NEVER
//      rebuilt, so its `node-pre-gyp install --fallback-to-build` never runs.
//
// The required Electron/native setup (electron's binary download, node-pty's
// prebuild, esbuild, fsevents, electron-winstaller) still happens -- but only
// through these explicit, audited steps.
//
// Usage (from repo root, after `npm ci --ignore-scripts`):
//   node apps/desktop/scripts/run-allowed-lifecycle.mjs

import { spawnSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

// The deny-list is authoritative regardless of allowScripts truthiness: these
// packages' lifecycle scripts must NEVER run, even if an allowlist entry is
// flipped by mistake. get-windows is staged from a manifest-pinned, digest-
// verified binding (stage-native-deps.mjs), never from its install script.
export const NEVER_RUN = new Set(["get-windows"])

/** Split `name@version` into { name, version }. Scoped names keep their @scope. */
export function parsePackageKey(key) {
  const at = key.lastIndexOf("@")
  if (at <= 0) return { name: key, version: null } // no version, or bare @scope
  return { name: key.slice(0, at), version: key.slice(at + 1) }
}

/** Partition the allowScripts map into allowed / denied package descriptors. */
export function parseAllowlist(allowScripts = {}) {
  const allowed = []
  const denied = []
  for (const [key, value] of Object.entries(allowScripts || {})) {
    const entry = { key, ...parsePackageKey(key) }
    ;(value === true ? allowed : denied).push(entry)
  }
  return { allowed, denied }
}

/**
 * Decide which packages to rebuild. Pure over `lockVersionOf(name) -> version|null`.
 * A package is rebuilt ONLY when it is allowlisted `true`, is NOT on NEVER_RUN,
 * and its lockfile version matches the allowlisted version (identity check).
 * Everything else is skipped with a reason (fail-safe: skipping never runs code).
 */
export function rebuildDecision({ allowScripts, lockVersionOf, neverRun = NEVER_RUN }) {
  const { allowed, denied } = parseAllowlist(allowScripts)
  const rebuild = []
  const skipped = []
  for (const { name, version } of allowed) {
    if (neverRun.has(name)) {
      skipped.push({ name, reason: "on the NEVER_RUN deny-list" })
      continue
    }
    const locked = lockVersionOf(name)
    if (version && !locked) {
      skipped.push({ name, reason: "not present in the lockfile" })
      continue
    }
    if (version && locked && locked !== version) {
      skipped.push({ name, reason: `lockfile version ${locked} != allowlisted ${version}` })
      continue
    }
    rebuild.push(name)
  }
  return {
    rebuild,
    skipped,
    denied: denied.map((d) => d.name),
    neverRun: [...neverRun]
  }
}

function lockVersionLookup(lock) {
  return (name) => {
    const entry = (lock.packages || {})[`node_modules/${name}`]
    return entry && typeof entry.version === "string" ? entry.version : null
  }
}

/**
 * Run the allowlisted lifecycle. `spawn`/`readJson` are injectable for tests.
 * Returns the decision (so a caller/test can assert what ran).
 */
export function runAllowedLifecycle({
  repoRoot,
  spawn = spawnSync,
  readJson = (p) => JSON.parse(readFileSync(p, "utf8")),
  npm = process.platform === "win32" ? "npm.cmd" : "npm",
  log = console.log
} = {}) {
  const pkg = readJson(join(repoRoot, "package.json"))
  const lock = readJson(join(repoRoot, "package-lock.json"))
  const decision = rebuildDecision({
    allowScripts: pkg.allowScripts || {},
    lockVersionOf: lockVersionLookup(lock)
  })

  log(`[allowed-lifecycle] deny-list (never run): ${decision.neverRun.join(", ") || "(none)"}`)
  log(`[allowed-lifecycle] allowScripts:false -> never rebuilt: ${decision.denied.join(", ") || "(none)"}`)
  for (const s of decision.skipped) {
    log(`[allowed-lifecycle] skipped ${s.name}: ${s.reason}`)
  }

  if (decision.rebuild.length === 0) {
    log("[allowed-lifecycle] no allowlisted lifecycle scripts to run")
    return decision
  }

  // `npm rebuild <names>` runs ONLY the named packages' install/postinstall.
  // get-windows is never in this list, so its script never executes.
  log(`[allowed-lifecycle] rebuilding (running audited lifecycle): ${decision.rebuild.join(", ")}`)
  const res = spawn(npm, ["rebuild", ...decision.rebuild], {
    cwd: repoRoot,
    stdio: "inherit",
    shell: process.platform === "win32"
  })
  if (res && res.status !== 0) {
    throw new Error(`[allowed-lifecycle] npm rebuild failed with status ${res && res.status}`)
  }
  return decision
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const repoRoot = resolve(here, "..", "..", "..")
  try {
    runAllowedLifecycle({ repoRoot })
  } catch (err) {
    console.error(`[allowed-lifecycle] ${err.message}`)
    process.exit(1)
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main()
}
