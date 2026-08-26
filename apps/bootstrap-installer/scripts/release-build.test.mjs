// release-build.test.mjs — A10/A4 release-pin + clean-worktree staging tests.
// Runnable via `node --test scripts/release-build.test.mjs`.

import assert from "node:assert/strict"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"

import {
  assertHashMatch,
  BOOTSTRAP_INPUT_PATHS,
  candidateBundleDirs,
  cleanupWorktreePlan,
  extractOutputArg,
  parseTargetTriple,
  persistBuildArtifacts,
  planCleanWorktreeRelease,
  releaseTauriArgs,
  reportPersistedArtifacts,
  resolveReleaseOutputDir,
  resolveReleasePin,
  runCleanWorktreeRelease,
  sha256File
} from "./release-build.mjs"

const FULL = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

// A fake `git` exec answering rev-parse / status / status --ignored.
function fakeExec({ commit = FULL, status = "", ignored = "" } = {}) {
  return (cmd) => {
    if (cmd.includes("rev-parse HEAD")) return `${commit}\n`
    if (cmd.includes("--ignored")) return ignored
    if (cmd.includes("status --porcelain")) return status
    return ""
  }
}

test("resolves a full-commit pin over the complete clean closure", () => {
  const pin = resolveReleasePin({ execFn: fakeExec() })
  assert.equal(pin.commit, FULL)
  assert.equal(pin.clean, true)
})

test("the closure scope includes root manifests, lock, install scripts, installer app, shared", () => {
  for (const p of [
    "package.json",
    "package-lock.json",
    "scripts/install.ps1",
    "scripts/install.sh",
    "apps/bootstrap-installer",
    "apps/shared"
  ]) {
    assert.ok(BOOTSTRAP_INPUT_PATHS.includes(p), `closure must include ${p}`)
  }
})

test("rejects a dirty closure (e.g. changed root package-lock.json)", () => {
  assert.throws(
    () => resolveReleasePin({ execFn: fakeExec({ status: " M package-lock.json\n" }) }),
    /packaged inputs are dirty/
  )
})

test("rejects an IGNORED shadow file in a source tree", () => {
  assert.throws(
    () => resolveReleasePin({ execFn: fakeExec({ ignored: "!! apps/shared/src/index.js" }) }),
    /SHADOW/
  )
})

test("fails closed when git status is unavailable", () => {
  const execFn = (cmd) => {
    if (cmd.includes("rev-parse HEAD")) return `${FULL}\n`
    return null
  }
  assert.throws(() => resolveReleasePin({ execFn }), /git status unavailable/)
})

test("rejects a non-full / unresolved HEAD commit", () => {
  assert.throws(() => resolveReleasePin({ execFn: fakeExec({ commit: "a1b2c3d" }) }), /full 40-char HEAD commit/)
  assert.throws(() => resolveReleasePin({ execFn: () => "" }), /full 40-char HEAD commit/)
})

test("the release build forwards --frozen to cargo", () => {
  const args = releaseTauriArgs(["--target", "x86_64-pc-windows-msvc"])
  const dashDash = args.lastIndexOf("--")
  assert.deepEqual(args.slice(dashDash), ["--", "--frozen"])
  assert.ok(args.includes("--target"))
})

// ── Fresh git-worktree release staging ──────────────────────────────────────

test("planCleanWorktreeRelease checks out HEAD, npm ci --ignore-scripts, orchestrator, then builds", () => {
  const plan = planCleanWorktreeRelease({
    head: FULL,
    stagingDir: "/tmp/stage/checkout",
    buildCwdRel: "apps/bootstrap-installer",
    build: { cmd: "npm", args: ["run", "tauri", "--", "build", "--", "--frozen"] },
    node: "/usr/bin/node",
    npm: "npm"
  })
  const labels = plan.map((s) => s.label)
  assert.deepEqual(labels, ["worktree-add", "npm-ci", "allowed-lifecycle", "build"])

  const add = plan[0]
  assert.deepEqual(add.args, ["worktree", "add", "--detach", "/tmp/stage/checkout", FULL])

  const ci = plan[1]
  assert.deepEqual(ci.args, ["ci", "--ignore-scripts"])
  assert.equal(ci.cwd, "/tmp/stage/checkout")

  const orch = plan[2]
  assert.ok(orch.args[0].includes("run-allowed-lifecycle.mjs"))

  const build = plan[3]
  assert.ok(build.args.includes("--frozen"))
  assert.ok(build.cwd.includes("apps"))
})

test("runCleanWorktreeRelease runs steps in order and ALWAYS cleans up the worktree", () => {
  const calls = []
  const spawn = (cmd, args) => {
    calls.push([cmd, ...args])
    return { status: 0 }
  }
  const plan = planCleanWorktreeRelease({
    head: FULL,
    stagingDir: "/s",
    buildCwdRel: "apps/bootstrap-installer",
    build: { cmd: "npm", args: ["run", "tauri"] },
    node: "node",
    npm: "npm"
  })
  runCleanWorktreeRelease({ plan, cleanup: cleanupWorktreePlan({ stagingDir: "/s" }), spawn })
  assert.deepEqual(calls[calls.length - 1], ["git", "worktree", "remove", "--force", "/s"])
})

test("runCleanWorktreeRelease still removes the worktree when a build step FAILS", () => {
  const calls = []
  const spawn = (cmd, args) => {
    calls.push([cmd, ...args])
    if (cmd === "npm" && args[0] === "ci") return { status: 1 }
    return { status: 0 }
  }
  const plan = planCleanWorktreeRelease({
    head: FULL,
    stagingDir: "/s",
    buildCwdRel: "apps/bootstrap-installer",
    build: { cmd: "npm", args: ["run", "tauri"] },
    node: "node",
    npm: "npm"
  })
  assert.throws(
    () => runCleanWorktreeRelease({ plan, cleanup: cleanupWorktreePlan({ stagingDir: "/s" }), spawn }),
    /npm-ci.*failed/
  )
  assert.deepEqual(calls[calls.length - 1], ["git", "worktree", "remove", "--force", "/s"])
  assert.ok(!calls.some((c) => c[0] === "npm" && c[1] === "run" && c[2] === "tauri"))
})

test("EXPLOIT: Tauri root manifest drift (apps/bootstrap-installer/package.json) is REJECTED", () => {
  assert.throws(
    () => resolveReleasePin({ execFn: fakeExec({ status: " M apps/bootstrap-installer/package.json\n" }) }),
    /packaged inputs are dirty/
  )
})

test("EXPLOIT: Tauri Cargo.lock drift is REJECTED", () => {
  assert.throws(
    () => resolveReleasePin({ execFn: fakeExec({ status: " M apps/bootstrap-installer/src-tauri/Cargo.lock\n" }) }),
    /packaged inputs are dirty/
  )
})

test("EXPLOIT: an untracked install-script config is REJECTED", () => {
  assert.throws(
    () => resolveReleasePin({ execFn: fakeExec({ status: "?? scripts/install.ps1.evil\n" }) }),
    /packaged inputs are dirty/
  )
})

// ── B2: persistent external release output (survives worktree cleanup) ────────

test("extractOutputArg strips --out <dir> and --out=<dir>, forwarding the rest to tauri", () => {
  assert.deepEqual(extractOutputArg(["--out", "/o", "--target", "x86_64-pc-windows-msvc"]), {
    outDir: "/o",
    rest: ["--target", "x86_64-pc-windows-msvc"]
  })
  assert.deepEqual(extractOutputArg(["--out=/o2", "--debug"]), { outDir: "/o2", rest: ["--debug"] })
  assert.deepEqual(extractOutputArg(["--target", "aarch64-apple-darwin"]), {
    outDir: null,
    rest: ["--target", "aarch64-apple-darwin"]
  })
  // A trailing bare --out with no value is dropped, not forwarded as garbage.
  assert.deepEqual(extractOutputArg(["--out"]), { outDir: null, rest: [] })
})

test("resolveReleaseOutputDir: --out wins over env, env over the deterministic default", () => {
  const repoRoot = "/repo"
  const commit = FULL
  // explicit --out wins (resolved to an absolute path)
  assert.equal(
    resolveReleaseOutputDir({ outDir: "/explicit/out", env: { HERMES_RELEASE_OUT: "/env/out" }, repoRoot, commit }),
    resolve("/explicit/out")
  )
  // env used when no --out
  assert.equal(resolveReleaseOutputDir({ env: { HERMES_RELEASE_OUT: "/env/out" }, repoRoot, commit }), resolve("/env/out"))
  // deterministic default under the MAIN checkout, keyed by short SHA
  const def = resolveReleaseOutputDir({ env: {}, repoRoot, commit })
  assert.equal(def, join(repoRoot, "apps", "bootstrap-installer", "release", commit.slice(0, 12)))
})

test("resolveReleaseOutputDir REFUSES an output dir inside the staging worktree", () => {
  const stagingDir = join(tmpdir(), "hermes-release-xyz", "checkout")
  assert.throws(
    () =>
      resolveReleaseOutputDir({
        outDir: join(stagingDir, "apps", "bootstrap-installer", "release"),
        env: {},
        repoRoot: "/repo",
        commit: FULL,
        stagingDir
      }),
    /inside the staging worktree/
  )
})

test("parseTargetTriple + candidateBundleDirs cover default and --target layouts", () => {
  assert.equal(parseTargetTriple(["--debug"]), null)
  assert.equal(parseTargetTriple(["--target", "x86_64-pc-windows-msvc"]), "x86_64-pc-windows-msvc")
  assert.equal(parseTargetTriple(["--target=aarch64-apple-darwin"]), "aarch64-apple-darwin")

  const dirs = candidateBundleDirs("/s/checkout", "apps/bootstrap-installer", ["--target", "x86_64-pc-windows-msvc"])
  assert.equal(dirs[0], join("/s/checkout", "apps/bootstrap-installer", "src-tauri", "target", "x86_64-pc-windows-msvc", "release", "bundle"))
  assert.equal(dirs[1], join("/s/checkout", "apps/bootstrap-installer", "src-tauri", "target", "release", "bundle"))
})

test("assertHashMatch throws on a post-copy digest mismatch", () => {
  assert.equal(assertHashMatch("x.msi", "abc", "abc"), true)
  assert.throws(() => assertHashMatch("x.msi", "abc123", "def456"), /failed hash verification after copy/)
})

// Populate a fake Tauri bundle tree under a staging worktree.
function seedBundle(stagingDir) {
  const bundle = join(stagingDir, "apps/bootstrap-installer", "src-tauri", "target", "release", "bundle")
  mkdirSync(join(bundle, "nsis"), { recursive: true })
  mkdirSync(join(bundle, "msi"), { recursive: true })
  writeFileSync(join(bundle, "nsis", "Hermes_0.0.1_x64-setup.exe"), "NSIS-INSTALLER-BYTES")
  writeFileSync(join(bundle, "msi", "Hermes_0.0.1_x64_en-US.msi"), "MSI-INSTALLER-BYTES")
  return bundle
}

test("persistBuildArtifacts copies + hash-verifies artifacts; outputs SURVIVE worktree cleanup", () => {
  const root = mkdtempSync(join(tmpdir(), "hermes-b2-"))
  try {
    const stagingDir = join(root, "checkout")
    seedBundle(stagingDir)
    const outputDir = join(root, "out") // EXTERNAL to stagingDir

    const persisted = persistBuildArtifacts({
      bundleDirs: candidateBundleDirs(stagingDir, "apps/bootstrap-installer", []),
      outputDir
    })
    assert.equal(persisted.length, 2)
    for (const a of persisted) {
      assert.match(a.sha256, /^[0-9a-f]{64}$/)
      assert.equal(existsSync(a.dest), true)
    }

    // Simulate the worktree cleanup: destroy the staging tree entirely.
    rmSync(stagingDir, { recursive: true, force: true })
    assert.equal(existsSync(stagingDir), false)

    // The persisted artifacts still exist and still hash to the recorded value.
    for (const a of persisted) {
      assert.equal(existsSync(a.dest), true, `${a.rel} must survive cleanup`)
      assert.equal(sha256File(a.dest), a.sha256, `${a.rel} content must be intact`)
    }
    // And the content matches the original artifact bytes.
    assert.equal(
      readFileSync(join(outputDir, "nsis", "Hermes_0.0.1_x64-setup.exe"), "utf8"),
      "NSIS-INSTALLER-BYTES"
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test("persistBuildArtifacts THROWS when the build produced no bundle output", () => {
  const root = mkdtempSync(join(tmpdir(), "hermes-b2-"))
  try {
    const stagingDir = join(root, "checkout")
    assert.throws(
      () =>
        persistBuildArtifacts({
          bundleDirs: candidateBundleDirs(stagingDir, "apps/bootstrap-installer", []),
          outputDir: join(root, "out")
        }),
      /no Tauri bundle output found to persist/
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test("persistBuildArtifacts FAILS CLOSED on a corrupted copy (hash verification)", () => {
  const root = mkdtempSync(join(tmpdir(), "hermes-b2-"))
  try {
    const stagingDir = join(root, "checkout")
    seedBundle(stagingDir)
    assert.throws(
      () =>
        persistBuildArtifacts({
          bundleDirs: candidateBundleDirs(stagingDir, "apps/bootstrap-installer", []),
          outputDir: join(root, "out"),
          // A tampering copy that writes different bytes than the source.
          copyFn: (_src, dest) => writeFileSync(dest, "TAMPERED-BYTES")
        }),
      /failed hash verification after copy/
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test("reportPersistedArtifacts reports ONLY paths that still exist", () => {
  const logged = []
  const persisted = [
    { rel: "a.exe", dest: "/exists/a.exe", sha256: "a".repeat(64), bytes: 10 },
    { rel: "b.msi", dest: "/gone/b.msi", sha256: "b".repeat(64), bytes: 20 }
  ]
  const existing = reportPersistedArtifacts(persisted, {
    existsFn: (p) => p === "/exists/a.exe",
    log: (m) => logged.push(m)
  })
  assert.deepEqual(existing.map((a) => a.rel), ["a.exe"])
  assert.equal(logged.length, 1)
  assert.match(logged[0], /a\.exe/)
})

test("runCleanWorktreeRelease runs afterBuild AFTER the plan but BEFORE cleanup", () => {
  const order = []
  const spawn = (cmd, args) => {
    order.push(`spawn ${cmd} ${(args || []).join(" ")}`)
    return { status: 0 }
  }
  const plan = [{ label: "build", cmd: "npm", args: ["run", "tauri"] }]
  const cleanup = cleanupWorktreePlan({ stagingDir: "/s" })
  const res = runCleanWorktreeRelease({
    plan,
    cleanup,
    spawn,
    afterBuild: () => {
      order.push("afterBuild")
      return ["artifact"]
    }
  })
  assert.deepEqual(order, ["spawn npm run tauri", "afterBuild", "spawn git worktree remove --force /s"])
  assert.deepEqual(res.afterResult, ["artifact"])
})

test("runCleanWorktreeRelease does NOT run afterBuild when a build step fails, still cleans up", () => {
  const order = []
  const spawn = (cmd, args) => {
    order.push(`${cmd} ${(args || []).join(" ")}`)
    if (cmd === "npm") return { status: 1 }
    return { status: 0 }
  }
  const plan = [{ label: "build", cmd: "npm", args: ["run", "tauri"] }]
  let afterCalled = false
  assert.throws(
    () =>
      runCleanWorktreeRelease({
        plan,
        cleanup: cleanupWorktreePlan({ stagingDir: "/s" }),
        spawn,
        afterBuild: () => {
          afterCalled = true
        }
      }),
    /build.*failed/
  )
  assert.equal(afterCalled, false)
  assert.deepEqual(order[order.length - 1], "git worktree remove --force /s")
})
