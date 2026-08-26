// packaged-input-guard.mjs — A5/A4 packaged-input identity check (COMPLETE
// transitive source/config closure).
//
// The install stamp records a commit, but a JSON field is not proof the tree on
// disk IS that commit. This guard INDEPENDENTLY interrogates git at pack time
// over the FULL closure of files that flow into the package:
//
//   1. HEAD resolves to a full 40-char commit (git must be available — a build
//      that cannot prove its input identity fails closed).
//   2. HEAD == the stamped/pinned commit (the packaged tree is the pinned one).
//   3. The packaged/build-input paths have NO tracked changes AND NO untracked
//      files (`git status --porcelain --untracked-files=all -- <paths>`).
//   4. The shadow-prone SOURCE dirs have NO IGNORED files either
//      (`git status --porcelain --ignored -- <src dirs>`). This catches the
//      classic exploit where a gitignored `apps/shared/src/index.js` shadows the
//      committed `index.ts` at bundle time — `--untracked-files=all` alone MISSES
//      it because the `.js` is gitignored.
//
// Pure over an injected `execFn` so every branch is unit-tested without a real
// repo. The real caller passes a git-backed exec.

import { execSync } from "node:child_process"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"

export function defaultGitExec(cmd, opts) {
  try {
    return execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], ...opts }).trim()
  } catch {
    return null
  }
}

const FULL_SHA = /^[0-9a-f]{40}$/

// The DESKTOP build's complete input closure: its own tree, the shared package
// it bundles, the root manifests + lock (the whole dependency graph), the
// native staging scripts/config (under apps/desktop/scripts), and the
// supply-chain manifest whose digests the build consumes. Workspace manifests
// are appended at call time via desktopPackagedInputPaths().
export const DESKTOP_PACKAGED_INPUT_PATHS = [
  "apps/desktop",
  "apps/shared",
  "package.json",
  "package-lock.json",
  "supply-chain/manifest.json"
]

// Source trees where a gitignored `.js`/`.d.ts` emit could SHADOW the committed
// `.ts` source at bundle time. A release tree must contain none.
export const DESKTOP_SHADOW_PATHS = ["apps/desktop/src", "apps/shared/src"]

/**
 * Resolve every workspace package.json declared in the root package.json
 * `workspaces` field (globs expanded). Pure over injected fs for testing.
 */
export function workspaceManifestPaths(repoRoot, { read = readFileSync, exists = existsSync, readdir = readdirSync } = {}) {
  let pkg
  try {
    pkg = JSON.parse(read(join(repoRoot, "package.json"), "utf8"))
  } catch {
    return []
  }
  const out = []
  for (const w of pkg.workspaces || []) {
    if (w.includes("*")) {
      const base = w.replace(/\/\*.*$/, "")
      let names = []
      try {
        names = readdir(join(repoRoot, base), { withFileTypes: true })
          .filter((e) => e.isDirectory())
          .map((e) => e.name)
      } catch {
        names = []
      }
      for (const name of names) {
        const rel = `${base}/${name}/package.json`
        if (exists(join(repoRoot, rel))) out.push(rel)
      }
    } else {
      const rel = `${w}/package.json`
      if (exists(join(repoRoot, rel))) out.push(rel)
    }
  }
  return out
}

/**
 * The full desktop packaged-input closure: the static core plus every workspace
 * package manifest not already covered by the apps/desktop + apps/shared dir
 * entries.
 */
export function desktopPackagedInputPaths(repoRoot, deps = {}) {
  const manifests = workspaceManifestPaths(repoRoot, deps)
  const extra = manifests.filter((m) => !m.startsWith("apps/desktop/") && !m.startsWith("apps/shared/"))
  return [...DESKTOP_PACKAGED_INPUT_PATHS, ...extra]
}

/**
 * Assert the packaged/build-input tree is exactly the pinned commit and clean
 * across the FULL closure. Throws on any failure. Returns { head } on success.
 */
export function assertPackagedInputClean({
  stampedCommit,
  packagedPaths = DESKTOP_PACKAGED_INPUT_PATHS,
  shadowPaths = [],
  execFn = defaultGitExec,
  cwd,
  label = "before-pack"
} = {}) {
  const opts = cwd ? { cwd } : {}

  const headRaw = execFn("git rev-parse HEAD", opts)
  if (headRaw == null) {
    throw new Error(
      `[${label}] A5: git is unavailable — cannot verify the packaged-input identity of a ` +
        `production build. A production package MUST be built from a git checkout at the pinned commit.`
    )
  }
  const head = String(headRaw).trim().toLowerCase()
  if (!FULL_SHA.test(head)) {
    throw new Error(`[${label}] A5: HEAD '${head}' is not a full 40-char commit SHA`)
  }

  if (stampedCommit != null) {
    const pin = String(stampedCommit).trim().toLowerCase()
    if (!FULL_SHA.test(pin)) {
      throw new Error(`[${label}] A5: stamped/pinned commit '${pin}' is not a full 40-char SHA`)
    }
    if (head !== pin) {
      throw new Error(
        `[${label}] A5: HEAD ${head.slice(0, 12)} does NOT match the stamped/pinned commit ` +
          `${pin.slice(0, 12)} — the packaged tree is not the reviewed commit`
      )
    }
  }

  const scope = packagedPaths && packagedPaths.length ? ` -- ${packagedPaths.join(" ")}` : ""
  const status = execFn(`git status --porcelain --untracked-files=all${scope}`, opts)
  if (status == null) {
    throw new Error(`[${label}] A5: git status is unavailable — cannot prove a clean packaged tree`)
  }
  const lines = String(status)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
  if (lines.length) {
    throw new Error(
      `[${label}] A5: the packaged/build-input tree is NOT clean (${lines.length} tracked/untracked ` +
        `change(s) across the closure, e.g. "${lines[0]}") — refuse to package a tree that differs from the pinned commit`
    )
  }

  // Shadow scan: a gitignored .js/.d.ts in a SOURCE dir can shadow the committed
  // .ts at bundle time. `--ignored` surfaces these (invisible to the scan above).
  // A clean source tree yields nothing.
  if (shadowPaths && shadowPaths.length) {
    const shScope = ` -- ${shadowPaths.join(" ")}`
    const ignored = execFn(`git status --porcelain --ignored --untracked-files=all${shScope}`, opts)
    if (ignored == null) {
      throw new Error(`[${label}] A5: git status --ignored is unavailable — cannot rule out shadow files`)
    }
    const shLines = String(ignored)
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
    if (shLines.length) {
      throw new Error(
        `[${label}] A5: source tree contains ignored/untracked file(s) that could SHADOW committed ` +
          `sources (${shLines.length}, e.g. "${shLines[0]}") — e.g. a stray .js over a committed .ts. ` +
          `Build a production package from a fresh clean checkout at the pinned commit.`
      )
    }
  }

  return { head }
}
