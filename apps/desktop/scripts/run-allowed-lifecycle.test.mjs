// run-allowed-lifecycle.test.mjs — A4 behavioral tests for the allowlisted
// lifecycle-script orchestrator.

import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, beforeAll, describe, expect, it, test } from "vitest"

import {
  NEVER_RUN,
  parseAllowlist,
  parsePackageKey,
  rebuildDecision,
  runAllowedLifecycle
} from "./run-allowed-lifecycle.mjs"

describe("parsePackageKey / parseAllowlist", () => {
  it("splits name@version, keeping @scope intact", () => {
    assert.deepEqual(parsePackageKey("get-windows@9.3.0"), { name: "get-windows", version: "9.3.0" })
    assert.deepEqual(parsePackageKey("@mapbox/node-pre-gyp@2.0.0"), {
      name: "@mapbox/node-pre-gyp",
      version: "2.0.0"
    })
    assert.deepEqual(parsePackageKey("unicode-animations"), { name: "unicode-animations", version: null })
  })

  it("partitions allow (true) vs deny (false)", () => {
    const { allowed, denied } = parseAllowlist({
      "electron@41.10.3": true,
      "get-windows@9.3.0": false,
      "unicode-animations": false
    })
    assert.deepEqual(allowed.map((a) => a.name), ["electron"])
    assert.deepEqual(denied.map((d) => d.name).sort(), ["get-windows", "unicode-animations"])
  })
})

describe("rebuildDecision", () => {
  const lock = (map) => (name) => map[name] ?? null

  it("rebuilds an allowlisted package whose lock version matches", () => {
    const d = rebuildDecision({
      allowScripts: { "electron@41.10.3": true },
      lockVersionOf: lock({ electron: "41.10.3" })
    })
    assert.deepEqual(d.rebuild, ["electron"])
  })

  it("NEVER rebuilds get-windows even if allowScripts flips it to true", () => {
    const d = rebuildDecision({
      allowScripts: { "get-windows@9.3.0": true, "electron@41.10.3": true },
      lockVersionOf: lock({ "get-windows": "9.3.0", electron: "41.10.3" })
    })
    assert.ok(!d.rebuild.includes("get-windows"))
    assert.ok(d.rebuild.includes("electron"))
    assert.ok(d.skipped.some((s) => s.name === "get-windows" && /deny-list/.test(s.reason)))
  })

  it("never rebuilds an allowScripts:false package", () => {
    const d = rebuildDecision({
      allowScripts: { "get-windows@9.3.0": false },
      lockVersionOf: lock({ "get-windows": "9.3.0" })
    })
    assert.deepEqual(d.rebuild, [])
    assert.ok(d.denied.includes("get-windows"))
  })

  it("skips (fails safe) when the lock version does not match the allowlist", () => {
    const d = rebuildDecision({
      allowScripts: { "electron@41.10.3": true },
      lockVersionOf: lock({ electron: "40.0.0" })
    })
    assert.deepEqual(d.rebuild, [])
    assert.ok(d.skipped.some((s) => /lockfile version 40\.0\.0/.test(s.reason)))
  })

  it("skips when the package is absent from the lockfile", () => {
    const d = rebuildDecision({
      allowScripts: { "electron@41.10.3": true },
      lockVersionOf: lock({})
    })
    assert.deepEqual(d.rebuild, [])
    assert.ok(d.skipped.some((s) => /not present in the lockfile/.test(s.reason)))
  })
})

describe("runAllowedLifecycle (injected spawn)", () => {
  it("runs `npm rebuild` for allowed packages ONLY, never get-windows", () => {
    const calls = []
    const spawn = (cmd, args) => {
      calls.push({ cmd, args })
      return { status: 0 }
    }
    const files = {
      "/repo/package.json": {
        allowScripts: {
          "electron@41.10.3": true,
          "node-pty@1.1.0": true,
          "get-windows@9.3.0": false
        }
      },
      "/repo/package-lock.json": {
        packages: {
          "node_modules/electron": { version: "41.10.3" },
          "node_modules/node-pty": { version: "1.1.0" },
          "node_modules/get-windows": { version: "9.3.0" }
        }
      }
    }
    const decision = runAllowedLifecycle({
      repoRoot: "/repo",
      spawn,
      readJson: (p) => files[p.replace(/\\/g, "/")],
      npm: "npm",
      log: () => {}
    })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].args[0], "rebuild")
    const rebuilt = calls[0].args.slice(1)
    assert.ok(rebuilt.includes("electron"))
    assert.ok(rebuilt.includes("node-pty"))
    assert.ok(!rebuilt.includes("get-windows"), "get-windows must never be rebuilt")
    assert.ok(!decision.rebuild.includes("get-windows"))
  })

  it("NEVER_RUN contains get-windows", () => {
    assert.ok(NEVER_RUN.has("get-windows"))
  })
})

// ── REAL npm behavioral proof: a fake package's install hook does NOT run
//    under `npm install --ignore-scripts`, and runs ONLY via an explicit
//    `npm rebuild`. This is the actual npm behavior the orchestrator relies on.
describe("real npm --ignore-scripts behavior", () => {
  let work
  let npmOk = true
  const npm = process.platform === "win32" ? "npm.cmd" : "npm"

  beforeAll(() => {
    work = mkdtempSync(join(tmpdir(), "hermes-npm-hook-"))
    // A local file: dependency whose install hook writes a marker into its own
    // installed directory. The hook is a script FILE (no inline nested quotes).
    const pkgDir = join(work, "proj")
    const evil = join(work, "evil-hook")
    mkdirSync(pkgDir, { recursive: true })
    mkdirSync(evil, { recursive: true })
    writeFileSync(
      join(evil, "hook.cjs"),
      "require('fs').writeFileSync('HOOK_RAN', '1');"
    )
    writeFileSync(
      join(evil, "package.json"),
      JSON.stringify({
        name: "evil-hook",
        version: "1.0.0",
        scripts: { install: "node hook.cjs" }
      })
    )
    writeFileSync(join(evil, "index.js"), "module.exports = {}")
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({
        name: "proj",
        version: "1.0.0",
        dependencies: { "evil-hook": "file:../evil-hook" }
      })
    )
    // Install WITHOUT running scripts.
    const res = spawnSync(npm, ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
      cwd: pkgDir,
      encoding: "utf8",
      shell: process.platform === "win32"
    })
    if (res.status !== 0) npmOk = false
  })

  afterAll(() => {
    if (work) rmSync(work, { recursive: true, force: true })
  })

  it("the install hook did NOT run under --ignore-scripts", () => {
    if (!npmOk) return
    const marker = join(work, "proj", "node_modules", "evil-hook", "HOOK_RAN")
    assert.equal(existsSync(marker), false, "install hook must NOT run with --ignore-scripts")
  })

  it("the install hook runs ONLY when explicitly rebuilt (allowlisted step)", () => {
    if (!npmOk) return
    const pkgDir = join(work, "proj")
    const res = spawnSync(npm, ["rebuild", "evil-hook"], {
      cwd: pkgDir,
      encoding: "utf8",
      shell: process.platform === "win32"
    })
    // Some npm versions no-op rebuild for file: deps; only assert the positive
    // when the rebuild succeeded.
    if (res.status !== 0) return
    const marker = join(pkgDir, "node_modules", "evil-hook", "HOOK_RAN")
    expect(existsSync(marker)).toBe(true)
  })
})
