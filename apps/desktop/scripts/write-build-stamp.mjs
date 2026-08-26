/**
 * Writes apps/desktop/build/install-stamp.json with the git ref the desktop
 * .exe should pin to at first-launch bootstrap time.  This file ships inside
 * the packaged app via electron-builder's extraResources entry and is read
 * by electron/main.ts to drive the install.ps1 stage bootstrap flow.
 *
 * Schema (subject to bump via STAMP_SCHEMA_VERSION):
 *   {
 *     "schemaVersion": 1,
 *     "commit":        "<40-char SHA>",
 *     "branch":        "<branch name>",
 *     "builtAt":       "<ISO 8601 UTC timestamp>",
 *     "dirty":         true|false,
 *     "source":        "ci" | "local" | "fallback"
 *   }
 *
 * Source preference order:
 *   1. CI env vars ($GITHUB_SHA / $GITHUB_REF_NAME) -- avoid edge cases with
 *      shallow clones, detached HEADs, etc. in CI.
 *   2. Local `git rev-parse` against the parent repo (../..).
 *   3. Fallback stamp for local/personal builds from non-git source trees
 *      (ZIP extract, interrupted clone with no HEAD, etc.).
 *
 * Dev / out-of-repo builds without git produce an explicit fallback stamp
 * rather than aborting the whole build.  Bootstrap treats the all-zero
 * commit as unpinned and follows the branch instead of fetching a fake SHA.
 */

import { mkdirSync, writeFileSync } from "fs"
import { resolve, join, relative } from "path"
import { execSync } from "child_process"

import { isMain } from "./utils.mjs"

const STAMP_SCHEMA_VERSION = 1

/** All-zero placeholder used when no real commit can be resolved. */
export const FALLBACK_COMMIT = "0000000000000000000000000000000000000000"
export const FALLBACK_BRANCH = "main"

const DESKTOP_ROOT = resolve(import.meta.dirname, "..")
const REPO_ROOT = resolve(DESKTOP_ROOT, "..", "..")
const OUT_DIR = join(DESKTOP_ROOT, "build")
const OUT_FILE = join(OUT_DIR, "install-stamp.json")

function tryExec(cmd, opts) {
  try {
    return execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], ...opts }).trim()
  } catch {
    return null
  }
}

export function fromCI(env = process.env) {
  const sha = env.GITHUB_SHA
  if (!sha) return null
  const branch = env.GITHUB_REF_NAME || env.GITHUB_HEAD_REF || null
  return {
    commit: sha,
    branch: branch,
    // A5: NEVER assume a CI checkout is clean just because GITHUB_SHA is set —
    // the tree can be modified after checkout and before packaging. `dirty` is
    // left UNKNOWN here and resolved by a REAL git clean check in resolveStamp.
    dirty: null,
    source: "ci"
  }
}

/**
 * A5: run a REAL git clean check. Returns true (dirty), false (clean), or null
 * when git is unavailable. With ``untracked: true`` untracked files also count
 * as dirty (``--untracked-files=all``); default ``-uno`` is tracked-only.
 */
export function isWorkingTreeDirty(repoRoot = REPO_ROOT, execFn = tryExec, { untracked = false } = {}) {
  const flag = untracked ? "--untracked-files=all" : "-uno"
  const status = execFn(`git status --porcelain ${flag}`, { cwd: repoRoot })
  if (status === null) return null // git unavailable
  return status.length > 0
}

export function fromLocalGit(repoRoot = REPO_ROOT, execFn = tryExec) {
  const sha = execFn("git rev-parse HEAD", { cwd: repoRoot })
  if (!sha) return null
  const branch = execFn("git rev-parse --abbrev-ref HEAD", { cwd: repoRoot })
  // `git status --porcelain -uno` is empty iff tracked files match HEAD.
  // We exclude untracked files (-uno) intentionally: a developer who's
  // checked out an installer scratch dir alongside the repo shouldn't
  // poison every local build with a [DIRTY] stamp.  We DO care about
  // tracked-but-modified files because those mean the .exe content
  // differs from the commit being pinned.
  const status = execFn("git status --porcelain -uno", { cwd: repoRoot })
  const dirty = status !== null && status.length > 0
  return {
    commit: sha,
    branch: branch === "HEAD" ? null : branch, // detached HEAD -> null
    dirty: dirty,
    source: "local"
  }
}

export function fromFallback(branch = FALLBACK_BRANCH) {
  // Non-git builds (ZIP download, bootstrap installer without a resolvable
  // HEAD) cannot determine a real commit.  Use a placeholder so local /
  // personal builds can still complete.  The desktop bootstrap treats the
  // all-zero commit as "unknown" and falls back to an unpinned branch
  // bootstrap instead of trying to fetch a non-existent GitHub commit.
  return {
    commit: FALLBACK_COMMIT,
    branch: branch || FALLBACK_BRANCH,
    dirty: false,
    source: "fallback"
  }
}

/**
 * Resolve the install stamp without writing it.  Pure enough for unit tests:
 * inject env / execFn / repoRoot to simulate CI, local git, or no-git trees.
 */
export function resolveStamp({
  env = process.env,
  repoRoot = REPO_ROOT,
  execFn = tryExec,
  fallbackBranch = FALLBACK_BRANCH
} = {}) {
  const base = fromCI(env) || fromLocalGit(repoRoot, execFn) || fromFallback(fallbackBranch)
  if (base.source === "fallback") {
    return base
  }
  // A5: the AUTHORITATIVE clean signal is a real git check — GITHUB_SHA never
  // implies a clean tree. git unavailable (null) is treated as DIRTY so a
  // production build fails closed rather than stamping a false "clean".
  const dirty = isWorkingTreeDirty(repoRoot, execFn)
  base.dirty = dirty === null ? true : dirty
  return base
}

export function isFallbackCommit(commit) {
  return typeof commit === "string" && /^0{7,40}$/.test(commit)
}

/**
 * A10 — a production/publish build must ship an ATTESTED identity: a real, full
 * 40-char commit from a clean tree. The publish workflow sets
 * HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP=1 to enforce this.
 */
export function requireAttestedStamp(env = process.env) {
  return env.HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP === "1"
}

/**
 * Reason a stamp is NOT acceptable for a production build, or null when it is.
 * Rejects missing, all-zero/placeholder (unpinned branch), non-full-SHA, and
 * dirty stamps — the exact classes A10 requires production builds to refuse.
 */
export function stampRejectionReason(stamp) {
  if (!stamp || !stamp.commit) {
    return "no commit could be resolved"
  }
  if (isFallbackCommit(stamp.commit)) {
    return "placeholder/all-zero commit — this is an unpinned branch build (branch-only stamp)"
  }
  if (!/^[0-9a-f]{40}$/i.test(stamp.commit)) {
    return "commit is not a full 40-character git SHA"
  }
  if (stamp.dirty) {
    return "working tree is dirty — the packaged code differs from the pinned commit"
  }
  return null
}

function main() {
  const stamp = resolveStamp()
  if (!stamp || !stamp.commit) {
    // Should not happen — fromFallback() always provides a commit.
    console.error(
      "[write-build-stamp] ERROR: could not determine git commit.\n" +
        "  - $GITHUB_SHA not set\n" +
        "  - `git rev-parse HEAD` failed at " +
        REPO_ROOT +
        "\n" +
        "Packaged builds require a git ref to pin first-launch install.ps1\n" +
        "against. Run from a git checkout or set $GITHUB_SHA explicitly."
    )
    process.exit(1)
  }

  if (isFallbackCommit(stamp.commit)) {
    console.warn(
      "[write-build-stamp] WARNING: no git commit found (non-git checkout?).\n" +
        "  Using placeholder commit — the packaged app will fall back to the\n" +
        "  default branch for first-launch bootstrap.  For production builds,\n" +
        "  run from a git checkout or set $GITHUB_SHA."
    )
  }

  if (stamp.dirty) {
    console.warn(
      "[write-build-stamp] WARNING: working tree is dirty.\n" +
        "  Pinning to " +
        stamp.commit.slice(0, 12) +
        " but the packaged code may differ from that commit.\n" +
        "  Commit your changes before publishing this build."
    )
  }

  // A10 production gate: a publish/production build must not ship a
  // missing/all-zero/branch-only/dirty stamp. The warnings above are advisory
  // for local/dev builds; when attestation is required we FAIL CLOSED instead.
  if (requireAttestedStamp()) {
    const reason = stampRejectionReason(stamp)
    if (reason) {
      console.error(
        "[write-build-stamp] ERROR: production build requires an attested install stamp.\n" +
          "  Rejected: " +
          reason +
          ".\n" +
          "  A production Desktop build must pin an exact, full commit SHA from a clean\n" +
          "  tree so first-launch bootstrap has an attested installer identity — no\n" +
          "  branch-raw-script or unpinned-branch fallback is permitted."
      )
      process.exit(1)
    }
  }

  const payload = {
    schemaVersion: STAMP_SCHEMA_VERSION,
    commit: stamp.commit,
    branch: stamp.branch,
    builtAt: new Date().toISOString(),
    dirty: stamp.dirty,
    source: stamp.source
  }

  mkdirSync(OUT_DIR, { recursive: true })
  writeFileSync(OUT_FILE, JSON.stringify(payload, null, 2) + "\n", "utf8")
  console.log(
    "[write-build-stamp] wrote " +
      relative(REPO_ROOT, OUT_FILE) +
      " -> " +
      stamp.commit.slice(0, 12) +
      (stamp.branch ? " (" + stamp.branch + ")" : "") +
      (stamp.dirty ? " [DIRTY]" : "") +
      (stamp.source === "fallback" ? " [FALLBACK]" : "")
  )
}

if (isMain(import.meta.url)) {
  main()
}
