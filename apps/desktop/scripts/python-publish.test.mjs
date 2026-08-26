// python-publish.test.mjs — A6 JS→Python kernel-locked publication caller.
//
// Behavior only (no source-text reads): the caller invokes the SHARED Python
// transaction, propagates its verdict, FAILS CLOSED for a release when the
// helper is unavailable, and degrades to a labeled dev swap otherwise.

import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "vitest"

import {
  PublishHelperUnavailable,
  PublishTransactionError,
  manifestArch,
  manifestPlatform,
  publishThroughPythonTransaction,
  resolvePython,
  sha256Hex
} from "../scripts/python-publish.mjs"

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pypub-"))
}

// A fake spawn that records the argv and returns a canned result.
function fakeSpawn(result) {
  const calls = []
  const fn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts })
    return typeof result === "function" ? result(cmd, args, opts) : result
  }
  fn.calls = calls
  return fn
}

const OK_JSON = JSON.stringify({ ok: true, kind: "publish", published: true, committed: true, manifest_sequence: 1 })

test("maps electron-builder platform/arch names to manifest names", () => {
  assert.equal(manifestPlatform("win32"), "windows")
  assert.equal(manifestPlatform("darwin"), "macos")
  assert.equal(manifestPlatform("linux"), "linux")
  assert.equal(manifestArch("x64"), "x86_64")
  assert.equal(manifestArch("arm64"), "aarch64")
  // Already-canonical names pass through.
  assert.equal(manifestPlatform("windows"), "windows")
  assert.equal(manifestArch("x86_64"), "x86_64")
})

test("resolvePython honors HERMES_PYTHON", () => {
  assert.equal(resolvePython({ HERMES_PYTHON: "/opt/py/bin/python" }), "/opt/py/bin/python")
})

test("success: the helper verdict is returned and the CLI argv is exact", () => {
  const spawn = fakeSpawn({ status: 0, stdout: `${OK_JSON}\n`, stderr: "" })
  const out = publishThroughPythonTransaction({
    component: "electron",
    platform: "win32",
    arch: "x64",
    stagedSha256: "a".repeat(64),
    stageDir: "/stage",
    targetDir: "/dist",
    statePath: "/state.json",
    isRelease: true,
    repoRoot: "/repo",
    python: "python3",
    _spawn: spawn
  })
  assert.equal(out.published, true)
  assert.equal(out.committed, true)
  const { args } = spawn.calls[0]
  assert.deepEqual(args, [
    "-m",
    "hermes_cli.supply_chain.publish_cli",
    "--component",
    "electron",
    "--target",
    "/dist",
    "--staged-dir",
    "/stage",
    "--staged-sha256",
    "a".repeat(64),
    "--platform",
    "windows",
    "--arch",
    "x86_64",
    "--state",
    "/state.json"
  ])
})

test("A6 fail-closed: a RELEASE build throws when the interpreter is missing (ENOENT)", () => {
  const spawn = fakeSpawn({ error: Object.assign(new Error("spawn python ENOENT"), { code: "ENOENT" }) })
  assert.throws(
    () =>
      publishThroughPythonTransaction({
        component: "electron",
        platform: "win32",
        arch: "x64",
        stagedSha256: "a".repeat(64),
        stageDir: "/stage",
        targetDir: "/dist",
        isRelease: true,
        repoRoot: "/repo",
        _spawn: spawn
      }),
    (err) => err instanceof PublishHelperUnavailable && /kernel-locked transaction/.test(err.message)
  )
})

test("A6 fail-closed: a RELEASE build throws when the module cannot be imported", () => {
  const spawn = fakeSpawn({ status: 1, stdout: "", stderr: "No module named hermes_cli" })
  assert.throws(
    () =>
      publishThroughPythonTransaction({
        component: "get-windows",
        platform: "win32",
        arch: "x64",
        stagedSha256: "b".repeat(64),
        stageDir: "/stage",
        targetDir: "/dist",
        isRelease: true,
        repoRoot: "/repo",
        _spawn: spawn
      }),
    PublishHelperUnavailable
  )
})

test("A6 dev fallback: a NON-release build swaps the staged tree when the helper is unavailable", () => {
  const root = tmp()
  try {
    const stage = path.join(root, "stage")
    const target = path.join(root, "dist")
    fs.mkdirSync(stage, { recursive: true })
    fs.writeFileSync(path.join(stage, "electron.exe"), "BIN")
    const spawn = fakeSpawn({ error: Object.assign(new Error("ENOENT"), { code: "ENOENT" }) })
    const out = publishThroughPythonTransaction({
      component: "electron",
      platform: "win32",
      arch: "x64",
      stagedSha256: "a".repeat(64),
      stageDir: stage,
      targetDir: target,
      isRelease: false, // dev
      repoRoot: root,
      _spawn: spawn
    })
    assert.equal(out.fallback, true)
    assert.equal(fs.readFileSync(path.join(target, "electron.exe"), "utf8"), "BIN")
    assert.ok(!fs.existsSync(stage), "the staged tree was moved into the target")
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("A6 dev fallback: swaps over an EXISTING target (backup + replace)", () => {
  const root = tmp()
  try {
    const stage = path.join(root, "stage")
    const target = path.join(root, "dist")
    fs.mkdirSync(stage, { recursive: true })
    fs.mkdirSync(target, { recursive: true })
    fs.writeFileSync(path.join(stage, "electron.exe"), "NEW")
    fs.writeFileSync(path.join(target, "electron.exe"), "OLD")
    const spawn = fakeSpawn({ error: Object.assign(new Error("ENOENT"), { code: "ENOENT" }) })
    publishThroughPythonTransaction({
      component: "electron",
      platform: "linux",
      arch: "x64",
      stagedSha256: "a".repeat(64),
      stageDir: stage,
      targetDir: target,
      isRelease: false,
      repoRoot: root,
      _spawn: spawn
    })
    assert.equal(fs.readFileSync(path.join(target, "electron.exe"), "utf8"), "NEW")
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("a transaction VERDICT of not-published throws PublishTransactionError (fail closed)", () => {
  const verdict = JSON.stringify({ ok: false, kind: "publish", published: false, reason: "digest-mismatch" })
  const spawn = fakeSpawn({ status: 1, stdout: `${verdict}\n`, stderr: "" })
  assert.throws(
    () =>
      publishThroughPythonTransaction({
        component: "electron",
        platform: "win32",
        arch: "x64",
        stagedSha256: "a".repeat(64),
        stageDir: "/stage",
        targetDir: "/dist",
        isRelease: true,
        repoRoot: "/repo",
        _spawn: spawn
      }),
    (err) => err instanceof PublishTransactionError && /digest-mismatch/.test(err.message)
  )
})

test("an error-kind verdict (fail closed inside the CLI) throws PublishTransactionError", () => {
  const verdict = JSON.stringify({ ok: false, kind: "error", error_type: "ManifestError", error: "replay/downgrade" })
  const spawn = fakeSpawn({ status: 1, stdout: `${verdict}\n`, stderr: "" })
  assert.throws(
    () =>
      publishThroughPythonTransaction({
        component: "electron",
        platform: "win32",
        arch: "x64",
        stagedSha256: "a".repeat(64),
        stageDir: "/stage",
        targetDir: "/dist",
        isRelease: true,
        repoRoot: "/repo",
        _spawn: spawn
      }),
    (err) => err instanceof PublishTransactionError && /replay\/downgrade/.test(err.message)
  )
})

test("sha256Hex hashes bytes", () => {
  assert.equal(sha256Hex(Buffer.from("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
})

test("--state is omitted when statePath is null (Python default: profile state outside node_modules)", () => {
  const spawn = fakeSpawn({ status: 0, stdout: `${OK_JSON}\n`, stderr: "" })
  publishThroughPythonTransaction({
    component: "electron",
    platform: "win32",
    arch: "x64",
    stagedSha256: "a".repeat(64),
    stageDir: "/stage",
    targetDir: "/dist",
    statePath: null,
    isRelease: true,
    repoRoot: "/repo",
    python: "python3",
    _spawn: spawn
  })
  assert.ok(!spawn.calls[0].args.includes("--state"), "no --state → Python default_state_path()")
})
