#!/usr/bin/env node
// release-build.mjs — A10 repository release command for the Hermes-Setup
// (Tauri bootstrap) installer.
//
// A production (release-profile) installer MUST bake an attested identity: an
// exact FULL 40-char commit pin plus both install-script digests (build.rs
// enforces this and fails a release `tauri build` without the pin). This
// command resolves that pin from a CLEAN git checkout and sets it, then runs
// `tauri build` in release profile — so producing a release installer requires
// nothing more than `npm run tauri:build:release`, and a bare `tauri build`
// release (no pin) fails closed.
//
// Usage:
//   npm run tauri:build:release            # from apps/bootstrap-installer
//   node scripts/release-build.mjs [extra tauri args]

import { spawnSync } from "node:child_process"
import crypto from "node:crypto"
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync
} from "node:fs"
import { tmpdir } from "node:os"
import { dirname, isAbsolute, join, relative, resolve } from "node:path"
import { fileURLToPath } from "node:url"

function defaultExec(cmd, opts) {
  try {
    return spawnSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], shell: true, ...opts })
      .stdout
  } catch {
    return null
  }
}

// The COMPLETE Tauri release build-input closure (repo-relative): root manifests
// + lock (whole dependency graph), the install scripts whose digests are baked,
// the entire installer app INCLUDING Cargo.lock, and the shared build inputs.
export const BOOTSTRAP_INPUT_PATHS = [
  "package.json",
  "package-lock.json",
  "scripts/install.ps1",
  "scripts/install.sh",
  "apps/bootstrap-installer",
  "apps/shared"
]
// Source trees where a gitignored `.js`/`.d.ts` could shadow committed `.ts`.
export const BOOTSTRAP_SHADOW_PATHS = ["apps/bootstrap-installer/src", "apps/shared/src"]

/**
 * Resolve the exact full-commit release pin from a CLEAN working tree, verified
 * over the COMPLETE closure. `cwd` MUST be the repo root so the repo-relative
 * pathspecs resolve. Throws when HEAD is not a full 40-char SHA, when the
 * closure has tracked/untracked changes, or when a source tree has an IGNORED
 * shadow file. Pure over an injected `execFn`.
 */
export function resolveReleasePin({ execFn = defaultExec, cwd } = {}) {
  const opts = cwd ? { cwd } : {}
  const commit = String(execFn("git rev-parse HEAD", opts) || "").trim()
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error(
      "A10 release build: could not resolve a full 40-char HEAD commit. Run from a git checkout " +
        "at the exact release commit."
    )
  }
  const status = execFn(
    `git status --porcelain --untracked-files=all -- ${BOOTSTRAP_INPUT_PATHS.join(" ")}`,
    opts
  )
  if (status == null) {
    throw new Error("A10 release build: git status unavailable — cannot prove clean release inputs")
  }
  if (String(status).trim().length > 0) {
    throw new Error(
      "A10 release build: packaged inputs are dirty (tracked or untracked files differ from HEAD across " +
        `the closure: ${String(status).trim().split(/\r?\n/)[0]}). Commit or remove them.`
    )
  }
  const ignored = execFn(
    `git status --porcelain --ignored --untracked-files=all -- ${BOOTSTRAP_SHADOW_PATHS.join(" ")}`,
    opts
  )
  if (ignored == null) {
    throw new Error("A10 release build: git status --ignored unavailable — cannot rule out shadow files")
  }
  if (String(ignored).trim().length > 0) {
    throw new Error(
      "A10 release build: a source tree contains an ignored/untracked SHADOW file (e.g. a stray .js over " +
        `a committed .ts): ${String(ignored).trim().split(/\r?\n/)[0]}. Build from a fresh clean checkout.`
    )
  }
  return { commit, clean: true }
}

/**
 * Build the `npm run tauri -- build …` argv for a RELEASE build. `--frozen`
 * (= --locked + --offline) is forwarded to cargo so the release build can never
 * re-resolve or mutate the pinned Cargo.lock. Exported for testing.
 */
export function releaseTauriArgs(extra = []) {
  return ["run", "tauri", "--", "build", ...extra, "--", "--frozen"]
}

// ── B2: persistent external release output (survives worktree cleanup) ─────────
//
// The release build runs inside a throwaway git worktree that cleanup removes.
// Artifacts written under that worktree's `src-tauri/target/.../bundle` would be
// destroyed with it. These helpers copy the built artifacts into an EXTERNAL,
// caller-specified-or-deterministic output directory and hash-verify each copy
// BEFORE cleanup runs, so the reported paths are real and persistent.

function isInside(child, parent) {
  const rel = relative(parent, child)
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))
}

/**
 * Split `--out <dir>` / `--out=<dir>` out of the argv. The remaining args are
 * forwarded to `tauri build` (tauri does not understand an output flag).
 * Returns { outDir: string|null, rest: string[] }.
 */
export function extractOutputArg(argv = []) {
  const args = Array.isArray(argv) ? argv.map(String) : []
  const rest = []
  let outDir = null
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === "--out") {
      if (i + 1 < args.length) {
        outDir = args[i + 1]
        i++
      }
    } else if (a.startsWith("--out=")) {
      outDir = a.slice("--out=".length)
    } else {
      rest.push(a)
    }
  }
  return { outDir: outDir && String(outDir).length ? String(outDir) : null, rest }
}

/**
 * Resolve the persistent, EXTERNAL output directory release artifacts are copied
 * into so they survive the staging-worktree cleanup. Precedence:
 *   1. an explicit `--out <dir>` (or the `HERMES_RELEASE_OUT` env) — absolute;
 *   2. a deterministic default under the MAIN checkout,
 *      `apps/bootstrap-installer/release/<shortSha>` (gitignored, so it never
 *      trips the clean-closure pre-check).
 * Throws when the resolved dir is inside `stagingDir` (cleanup would delete it).
 */
export function resolveReleaseOutputDir({ outDir = null, env = process.env, repoRoot, commit, stagingDir = null } = {}) {
  const raw = (outDir && String(outDir)) || (env && env.HERMES_RELEASE_OUT) || null
  let resolved
  if (raw) {
    resolved = resolve(String(raw))
  } else {
    const shortSha = /^[0-9a-f]{7,40}$/i.test(String(commit || "")) ? String(commit).slice(0, 12) : "unknown"
    resolved = join(repoRoot, "apps", "bootstrap-installer", "release", shortSha)
  }
  if (stagingDir && isInside(resolved, resolve(String(stagingDir)))) {
    throw new Error(
      `release output dir '${resolved}' is inside the staging worktree '${stagingDir}' — it would be ` +
        "destroyed by cleanup. Choose an external --out/HERMES_RELEASE_OUT."
    )
  }
  return resolved
}

/** Parse a `--target <triple>` from the tauri extra args, or null. */
export function parseTargetTriple(tauriExtra = []) {
  const args = Array.isArray(tauriExtra) ? tauriExtra.map(String) : []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && i + 1 < args.length) return args[i + 1]
    if (args[i].startsWith("--target=")) return args[i].slice("--target=".length)
  }
  return null
}

/**
 * Candidate Tauri bundle roots inside the staging worktree. Tauri writes release
 * bundles to `src-tauri/target/release/bundle`, or
 * `src-tauri/target/<triple>/release/bundle` when `--target <triple>` is given.
 */
export function candidateBundleDirs(stagingDir, buildCwdRel, tauriExtra = []) {
  const targetRoot = join(stagingDir, buildCwdRel, "src-tauri", "target")
  const dirs = []
  const triple = parseTargetTriple(tauriExtra)
  if (triple) dirs.push(join(targetRoot, triple, "release", "bundle"))
  dirs.push(join(targetRoot, "release", "bundle"))
  return dirs
}

/** Recursively list files under `root`, returning { abs, rel } (POSIX rel). */
function listFilesRecursive(root) {
  const out = []
  if (!existsSync(root)) return out
  const walk = (dir, base) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const abs = join(dir, e.name)
      const rel = base ? `${base}/${e.name}` : e.name
      if (e.isDirectory()) walk(abs, rel)
      else if (e.isFile()) out.push({ abs, rel })
    }
  }
  walk(root, "")
  return out
}

/** sha256 of a file's bytes, hex. */
export function sha256File(p) {
  return crypto.createHash("sha256").update(readFileSync(p)).digest("hex")
}

/** Throw when the source and destination digests differ after a copy. */
export function assertHashMatch(rel, srcHash, destHash) {
  if (String(srcHash) !== String(destHash)) {
    throw new Error(
      `release artifact '${rel}' failed hash verification after copy: source sha256 ` +
        `${String(srcHash).slice(0, 12)}… != destination ${String(destHash).slice(0, 12)}…`
    )
  }
  return true
}

/**
 * Copy every artifact under the first EXISTING candidate bundle dir into
 * `outputDir` (preserving the bundle-relative layout) and verify each file's
 * sha256 AFTER the copy. Returns [{ rel, src, dest, sha256, bytes }] for the
 * persisted files. Throws when no artifacts are found (a release build that
 * produced nothing to persist is a failure) or any hash mismatches.
 *
 * `hashFn`/`copyFn` are injectable so the verify path is unit-testable.
 */
export function persistBuildArtifacts({ bundleDirs = [], outputDir, hashFn = sha256File, copyFn = copyFileSync } = {}) {
  const srcRoot = (bundleDirs || []).find((d) => existsSync(d)) || null
  if (!srcRoot) {
    throw new Error(
      `no Tauri bundle output found to persist (looked in: ${(bundleDirs || []).join(", ")}) — the release ` +
        "build produced no artifacts"
    )
  }
  const files = listFilesRecursive(srcRoot)
  if (files.length === 0) {
    throw new Error(`Tauri bundle dir '${srcRoot}' is empty — the release build produced no artifacts`)
  }
  mkdirSync(outputDir, { recursive: true })
  const persisted = []
  for (const { abs, rel } of files) {
    const dest = join(outputDir, rel)
    mkdirSync(dirname(dest), { recursive: true })
    const srcHash = hashFn(abs)
    copyFn(abs, dest)
    const destHash = hashFn(dest)
    assertHashMatch(rel, srcHash, destHash)
    persisted.push({ rel, src: abs, dest, sha256: destHash, bytes: statSync(dest).size })
  }
  return persisted
}

/**
 * Filter a persisted-artifact list to those whose destination still EXISTS
 * (report only real, persistent paths) and log them. Returns the existing
 * subset. `existsFn`/`log` injectable for tests.
 */
export function reportPersistedArtifacts(persisted = [], { existsFn = existsSync, log = console.log } = {}) {
  const existing = (persisted || []).filter((a) => a && a.dest && existsFn(a.dest))
  for (const a of existing) {
    log(
      `[release-build] persisted ${a.rel} (${a.bytes} bytes, sha256 ${String(a.sha256).slice(0, 12)}…) -> ${a.dest}`
    )
  }
  return existing
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const bootstrapRoot = resolve(here, "..")
  const repoRoot = resolve(bootstrapRoot, "..", "..")

  // `--out <dir>` is consumed here; the remaining args are forwarded to tauri.
  const { outDir: outArg, rest: tauriExtra } = extractOutputArg(process.argv.slice(2))

  let pin
  try {
    // Fast pre-check on the working tree (from the repo root so the closure
    // pathspecs resolve). The authoritative clean-checkout guarantee is the
    // fresh worktree staged below.
    pin = resolveReleasePin({ cwd: repoRoot })
  } catch (err) {
    console.error(`[release-build] ${err.message}`)
    process.exit(1)
    return
  }

  const env = {
    ...process.env,
    HERMES_BUILD_PIN_COMMIT: pin.commit,
    HERMES_SETUP_REQUIRE_ATTESTED: "1"
  }
  const npm = process.platform === "win32" ? "npm.cmd" : "npm"

  // A4: PREFER a fresh git-worktree staging checkout so no uncommitted source
  // and no uncommitted node_modules can enter the package — the worktree is a
  // pristine checkout of the pinned commit, deps are reinstalled from the lock
  // (`npm ci --ignore-scripts`), and ONLY audited lifecycle scripts run.
  const staging = mkdtempSync(join(tmpdir(), "hermes-release-"))
  const stagingDir = join(staging, "checkout")

  // B2: resolve the EXTERNAL, persistent output directory up front and refuse
  // one inside the staging worktree (cleanup would delete it).
  let outputDir
  try {
    outputDir = resolveReleaseOutputDir({ outDir: outArg, env: process.env, repoRoot, commit: pin.commit, stagingDir })
  } catch (err) {
    console.error(`[release-build] ${err.message}`)
    try {
      rmSync(staging, { recursive: true, force: true })
    } catch {
      /* best-effort */
    }
    process.exit(1)
    return
  }

  console.log(`[release-build] staging clean worktree at ${pin.commit.slice(0, 12)} -> ${stagingDir}`)
  console.log(`[release-build] release artifacts will persist to ${outputDir}`)

  const buildCwdRel = "apps/bootstrap-installer"
  const plan = planCleanWorktreeRelease({
    head: pin.commit,
    stagingDir,
    buildCwdRel,
    build: { cmd: npm, args: releaseTauriArgs(tauriExtra) },
    node: process.execPath,
    npm
  })

  let code = 0
  let persisted = []
  try {
    const result = runCleanWorktreeRelease({
      plan,
      cleanup: cleanupWorktreePlan({ stagingDir }),
      spawn: spawnSync,
      env,
      // Copy + hash-verify the built artifacts into the EXTERNAL output dir
      // BEFORE cleanup removes the staging worktree — this is the fix for the
      // successful artifacts being deleted along with the worktree.
      afterBuild: () =>
        persistBuildArtifacts({
          bundleDirs: candidateBundleDirs(stagingDir, buildCwdRel, tauriExtra),
          outputDir
        })
    })
    persisted = Array.isArray(result.afterResult) ? result.afterResult : []
  } catch (err) {
    console.error(`[release-build] ${err.message}`)
    code = 1
  } finally {
    try {
      rmSync(staging, { recursive: true, force: true })
    } catch {
      /* best-effort temp cleanup; the worktree itself is removed by the plan */
    }
  }

  if (code === 0) {
    // Report ONLY paths that still exist AFTER cleanup — proving they persisted
    // outside the removed worktree.
    const existing = reportPersistedArtifacts(persisted)
    if (existing.length === 0) {
      console.error("[release-build] no persistent release artifacts survived cleanup — failing")
      code = 1
    } else {
      console.log(`[release-build] ${existing.length} release artifact(s) persisted under ${outputDir}`)
    }
  }
  process.exit(code)
}

// ── Fresh git-worktree release staging (A4: clean-checkout packaging) ─────────

/**
 * Ordered command plan for a clean-worktree release: check out the pinned commit
 * into an isolated worktree, reinstall deps from the lock WITHOUT scripts, run
 * ONLY the audited lifecycle, then build there. Pure/testable.
 */
export function planCleanWorktreeRelease({ head, stagingDir, buildCwdRel, build, node, npm }) {
  return [
    { label: "worktree-add", cmd: "git", args: ["worktree", "add", "--detach", stagingDir, head] },
    { label: "npm-ci", cmd: npm, args: ["ci", "--ignore-scripts"], cwd: stagingDir },
    {
      label: "allowed-lifecycle",
      cmd: node,
      args: [join("apps", "desktop", "scripts", "run-allowed-lifecycle.mjs")],
      cwd: stagingDir
    },
    { label: "build", cmd: build.cmd, args: build.args, cwd: join(stagingDir, buildCwdRel) }
  ]
}

/** Cleanup plan: always remove the worktree (even on failure). */
export function cleanupWorktreePlan({ stagingDir }) {
  return [{ label: "worktree-remove", cmd: "git", args: ["worktree", "remove", "--force", stagingDir] }]
}

/**
 * Execute a worktree release plan, ALWAYS running the cleanup afterwards (even
 * when a step fails). When every plan step succeeds, `afterBuild()` runs INSIDE
 * the try — AFTER the build, BEFORE cleanup — so artifacts can be copied out of
 * the worktree before it is removed; its return value is surfaced as
 * `afterResult`. A throwing `afterBuild` still triggers cleanup and propagates.
 * `spawn` is injectable for testing.
 */
export function runCleanWorktreeRelease({ plan, cleanup = [], spawn, env, afterBuild = null }) {
  const failures = []
  let afterResult
  try {
    for (const step of plan) {
      const res = spawn(step.cmd, step.args, {
        cwd: step.cwd,
        stdio: "inherit",
        env: step.env || env,
        shell: process.platform === "win32"
      })
      const status = res && typeof res.status === "number" ? res.status : res && res.error ? 1 : 0
      if (status !== 0) {
        throw new Error(`release step '${step.label}' failed (exit ${status})`)
      }
    }
    if (typeof afterBuild === "function") afterResult = afterBuild()
  } finally {
    for (const step of cleanup) {
      const res = spawn(step.cmd, step.args, {
        stdio: "inherit",
        shell: process.platform === "win32"
      })
      if (res && res.status !== 0) failures.push(step.label)
    }
  }
  return { cleanupFailures: failures, afterResult }
}

// Only run the build when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main()
}
