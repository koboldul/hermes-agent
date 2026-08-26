// python-publish.mjs — A6 JS→Python kernel-locked publication caller.
//
// The desktop BUILD stages the exact verified bytes OUTSIDE the live target,
// then routes the FINAL publication (the atomic swap into the electron dist /
// get-windows dist directory) through the SHARED Python kernel-locked
// (fcntl.flock / msvcrt.locking) transaction —
// `python -m hermes_cli.supply_chain.publish_cli` — rather than a
// JS-reimplemented O_EXCL file lock (which unlinked its own inode and reclaimed
// on a PID-liveness heuristic). One transaction/lock/commit-ordering
// implementation is shared across Python and JS. The anti-rollback STATE the
// transaction commits lives OUTSIDE node_modules (the profile state file).
//
// Fail-closed rule: if the Python helper is unavailable (no interpreter / the
// module cannot be imported) during a RELEASE build, this THROWS — a
// release-verified artifact is never published without the kernel-locked
// transaction. A non-release (dev) build degrades to a single-process,
// same-volume atomic swap that is clearly labeled NOT release-grade.
//
// No shebang / no __dirname-in-a-string (vitest rolldown transform constraints).

import { spawnSync } from "node:child_process"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"

export function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex")
}

export class PublishHelperUnavailable extends Error {
  constructor(message) {
    super(message)
    this.name = "PublishHelperUnavailable"
    this.reason = "helper-unavailable"
  }
}

export class PublishTransactionError extends Error {
  constructor(message, reason = "not-published") {
    super(message)
    this.name = "PublishTransactionError"
    this.reason = reason
  }
}

// electron-builder → manifest artifact naming.
const PLATFORM_MAP = { darwin: "macos", win32: "windows", linux: "linux" }
const ARCH_MAP = { x64: "x86_64", arm64: "aarch64" }
export function manifestPlatform(p) {
  return PLATFORM_MAP[p] ?? p
}
export function manifestArch(a) {
  return ARCH_MAP[a] ?? a
}

/**
 * Resolve a Python interpreter for the shared transaction. HERMES_PYTHON wins;
 * otherwise a repo virtualenv (.venv / venv), then python3/python on PATH.
 */
export function resolvePython(env = process.env, repoRoot = null) {
  if (env.HERMES_PYTHON) return env.HERMES_PYTHON
  const win = process.platform === "win32"
  const rel = win ? ["Scripts", "python.exe"] : ["bin", "python"]
  if (repoRoot) {
    for (const venv of [".venv", "venv"]) {
      const p = path.join(repoRoot, venv, ...rel)
      try {
        if (fs.existsSync(p)) return p
      } catch {
        /* ignore */
      }
    }
  }
  return win ? "python" : "python3"
}

// A spawn result signals the helper is UNAVAILABLE (not a transaction verdict)
// when the interpreter is missing (ENOENT) or the module cannot be imported /
// located. A real transaction failure (digest mismatch, replay) exits non-zero
// but prints a JSON verdict and never these import/interpreter signals.
function looksUnavailable(res) {
  if (!res) return true
  if (res.error) return true // ENOENT: interpreter missing
  if (res.status === 0) return false
  const blob = `${res.stderr || ""}${res.stdout || ""}`
  return /No module named hermes_cli|ModuleNotFoundError|can't open file|is not recognized as|command not found/i.test(
    blob
  )
}

function parseResult(stdout) {
  const lines = String(stdout || "")
    .trim()
    .split("\n")
    .filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i])
    } catch {
      /* not the JSON line */
    }
  }
  return null
}

// DEV-ONLY single-process, same-volume atomic swap (no lock). Used only when
// the shared transaction is unavailable AND this is not a release build.
function devFallbackPublish(stageDir, targetDir) {
  const token = crypto.randomBytes(4).toString("hex")
  const backup = `${targetDir}.old-${token}`
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(path.dirname(targetDir), { recursive: true })
    fs.renameSync(stageDir, targetDir)
    return { ok: true, published: true, committed: false, fallback: true }
  }
  fs.renameSync(targetDir, backup)
  try {
    fs.renameSync(stageDir, targetDir)
  } catch (err) {
    try {
      fs.renameSync(backup, targetDir)
    } catch {
      /* leave backup for manual recovery */
    }
    throw err
  }
  fs.rmSync(backup, { recursive: true, force: true })
  return { ok: true, published: true, committed: false, fallback: true }
}

/**
 * Route the final publication of a staged, verified tree through the shared
 * Python kernel-locked transaction. `stageDir` is an already-verified tree
 * OUTSIDE the live target; `stagedSha256` is the sha256 the manifest artifact
 * digest authenticates (the archive bytes' sha256). On success the transaction
 * has atomically swapped `stageDir` into `targetDir` and committed the
 * anti-rollback high-water AFTER the swap.
 *
 * Throws PublishHelperUnavailable (release + no helper) or
 * PublishTransactionError (any non-published verdict) — fail closed.
 */
export function publishThroughPythonTransaction({
  component,
  platform,
  arch,
  stagedSha256,
  stageDir,
  targetDir,
  statePath = null,
  isRelease = false,
  repoRoot,
  env = process.env,
  python = null,
  _spawn = spawnSync
}) {
  const mplat = manifestPlatform(platform)
  const march = manifestArch(arch)
  const py = python || resolvePython(env, repoRoot)
  const args = [
    "-m",
    "hermes_cli.supply_chain.publish_cli",
    "--component",
    component,
    "--target",
    targetDir,
    "--staged-dir",
    stageDir,
    "--staged-sha256",
    stagedSha256,
    "--platform",
    mplat,
    "--arch",
    march
  ]
  if (statePath) args.push("--state", statePath)

  let res
  try {
    res = _spawn(py, args, { cwd: repoRoot, encoding: "utf8", env })
  } catch (err) {
    res = { error: err }
  }

  if (looksUnavailable(res)) {
    const detail =
      res && res.error
        ? res.error.message
        : ((res && (res.stderr || res.stdout)) || "spawn failed").toString().trim()
    if (isRelease) {
      throw new PublishHelperUnavailable(
        `the shared Python release transaction (hermes_cli.supply_chain.publish_cli) is unavailable ` +
          `(${detail}); refusing to publish release-verified ${component} for ${mplat}-${march} ` +
          `without the kernel-locked transaction`
      )
    }
    console.warn(
      `[python-publish] helper unavailable (${detail}); DEV fallback atomic swap for ` +
        `${component} ${mplat}-${march} — NOT release-grade`
    )
    return devFallbackPublish(stageDir, targetDir)
  }

  const out = parseResult(res.stdout)
  if (res.status !== 0 || !out || out.ok !== true || out.published !== true) {
    const reason = (out && (out.reason || out.error)) || (res.stderr || "").toString().trim() || `exit ${res.status}`
    throw new PublishTransactionError(
      `[python-publish] ${component} ${mplat}-${march} did not publish: ${reason}`,
      (out && out.reason) || "not-published"
    )
  }
  return out
}
