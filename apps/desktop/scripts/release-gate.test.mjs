// release-gate.test.mjs — A10 production packaging enforcement behavior tests.

import assert from "node:assert/strict"
import { describe, it } from "vitest"

import {
  assertProductionStampForTargets,
  electronBreakGlassAllowedForArgv,
  electronBreakGlassAllowedForTargets,
  enforceProductionStamp,
  isDevDirPack,
  isProductionBuild,
  isProductionBuildFromTargets,
  isProductionPublish,
  productionGateRejection
} from "./release-gate.mjs"

const FULL = "a".repeat(40)
const attested = { commit: FULL, branch: "main", dirty: false, source: "ci" }
const allZero = { commit: "0".repeat(40), branch: "main", dirty: false, source: "fallback" }
const dirty = { commit: FULL, branch: "main", dirty: true, source: "local" }
const short = { commit: "a1b2c3d", branch: "main", dirty: false, source: "local" }

describe("isProductionPublish", () => {
  it("detects the explicit require-attested env", () => {
    assert.equal(isProductionPublish([], { HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: "1" }), true)
  })
  it("detects a release tag build", () => {
    assert.equal(isProductionPublish([], { GITHUB_REF_TYPE: "tag" }), true)
  })
  it("detects --publish always / onTag", () => {
    assert.equal(isProductionPublish(["--publish", "always"], {}), true)
    assert.equal(isProductionPublish(["--publish=onTag"], {}), true)
    assert.equal(isProductionPublish(["-p", "onTagOrDraft"], {}), true)
  })
  it("does NOT treat --publish never as production", () => {
    assert.equal(isProductionPublish(["--publish", "never"], {}), false)
    assert.equal(isProductionPublish(["--publish=never"], {}), false)
  })
  it("a plain dev build is not a *publish*", () => {
    assert.equal(isProductionPublish(["--win", "--x64"], {}), false)
  })
})

describe("isProductionBuild / isDevDirPack (A10 re-review: artifact-producing = production)", () => {
  it("a bare electron-builder invocation is production", () => {
    assert.equal(isProductionBuild([], {}), true)
  })
  it("--win/--mac/--linux target builds are production", () => {
    assert.equal(isProductionBuild(["--win", "--x64"], {}), true)
    assert.equal(isProductionBuild(["--mac"], {}), true)
    assert.equal(isProductionBuild(["--linux"], {}), true)
  })
  it("only an explicit --dir dev pack is exempt", () => {
    assert.equal(isDevDirPack(["--dir"]), true)
    assert.equal(isProductionBuild(["--dir"], {}), false)
    assert.equal(isProductionBuild(["--win", "--dir"], {}), false)
  })
  it("publish/tag/env force production even with --dir", () => {
    assert.equal(isProductionBuild(["--dir"], { GITHUB_REF_TYPE: "tag" }), true)
    assert.equal(isProductionBuild(["--dir", "--publish", "always"], {}), true)
  })
})

describe("isProductionBuildFromTargets (beforePack hook)", () => {
  it("all-dir targets are exempt", () => {
    assert.equal(isProductionBuildFromTargets(["dir"], {}), false)
  })
  it("any installer target is production", () => {
    assert.equal(isProductionBuildFromTargets(["nsis"], {}), true)
    assert.equal(isProductionBuildFromTargets(["dir", "nsis"], {}), true)
    assert.equal(isProductionBuildFromTargets(["appimage"], {}), true)
    assert.equal(isProductionBuildFromTargets(["dmg"], {}), true)
  })
  it("unknown/empty targets fail closed (production)", () => {
    assert.equal(isProductionBuildFromTargets([], {}), true)
  })
  it("env forces production regardless of targets", () => {
    assert.equal(isProductionBuildFromTargets(["dir"], { HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: "1" }), true)
  })
})

describe("electron break-glass gating (B3: --dir-only, not --publish/tag)", () => {
  it("argv: allowed ONLY for an explicit --dir dev pack with opt-in", () => {
    assert.equal(electronBreakGlassAllowedForArgv(["--dir"], {}, true), true)
    assert.equal(electronBreakGlassAllowedForArgv(["--win", "--dir"], {}, true), true)
  })
  it("argv: denied for every artifact-producing (production) build even with opt-in", () => {
    assert.equal(electronBreakGlassAllowedForArgv([], {}, true), false) // bare = production
    assert.equal(electronBreakGlassAllowedForArgv(["--win", "--x64"], {}, true), false)
    assert.equal(electronBreakGlassAllowedForArgv(["--mac"], {}, true), false)
    assert.equal(electronBreakGlassAllowedForArgv(["--linux"], {}, true), false)
  })
  it("argv: denied without opt-in, and denied when publish/tag force production over --dir", () => {
    assert.equal(electronBreakGlassAllowedForArgv(["--dir"], {}, false), false)
    assert.equal(electronBreakGlassAllowedForArgv(["--dir"], { GITHUB_REF_TYPE: "tag" }, true), false)
    assert.equal(electronBreakGlassAllowedForArgv(["--dir", "--publish", "always"], {}, true), false)
  })
  it("targets: allowed ONLY for an all-dir dev pack with opt-in", () => {
    assert.equal(electronBreakGlassAllowedForTargets(["dir"], {}, true), true)
  })
  it("targets: denied for any installer target, unknown/empty (fail closed), or forced production", () => {
    assert.equal(electronBreakGlassAllowedForTargets(["nsis"], {}, true), false)
    assert.equal(electronBreakGlassAllowedForTargets(["dir", "nsis"], {}, true), false)
    assert.equal(electronBreakGlassAllowedForTargets(["dmg"], {}, true), false)
    assert.equal(electronBreakGlassAllowedForTargets([], {}, true), false) // unknown → production
    assert.equal(electronBreakGlassAllowedForTargets(["dir"], {}, false), false) // no opt-in
    assert.equal(
      electronBreakGlassAllowedForTargets(["dir"], { HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: "1" }, true),
      false
    )
  })
})

describe("productionGateRejection", () => {
  const prod = { argv: [], env: { HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: "1" } }

  it("allows an attested stamp", () => {
    assert.equal(productionGateRejection(attested, prod), null)
  })
  it("rejects an all-zero/placeholder stamp", () => {
    assert.match(productionGateRejection(allZero, prod), /placeholder|unpinned/)
  })
  it("rejects a dirty stamp", () => {
    assert.match(productionGateRejection(dirty, prod), /dirty/)
  })
  it("rejects a short (non-full) commit", () => {
    assert.match(productionGateRejection(short, prod), /full 40-character/)
  })
  it("rejects a missing stamp", () => {
    assert.match(productionGateRejection(null, prod), /no install stamp/)
  })
  it("allows anything for a non-production (--dir dev pack) build", () => {
    assert.equal(productionGateRejection(allZero, { argv: ["--dir"], env: {} }), null)
    assert.equal(productionGateRejection(null, { argv: ["--dir"], env: {} }), null)
  })
  it("a bare build is now production and rejects an unattested stamp", () => {
    assert.match(productionGateRejection(allZero, { argv: [], env: {} }), /placeholder|unpinned/)
  })
})

describe("enforceProductionStamp", () => {
  it("passes a production build through when the stamp is attested (no exit)", () => {
    // stampPath unreadable would fail; so write a temp file.
    let exited = false
    const ok = enforceProductionStamp({
      argv: [],
      env: { HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: "1" },
      stampPath: writeTempStamp(attested),
      exit: () => {
        exited = true
      },
      log: () => {}
    })
    assert.equal(ok, true)
    assert.equal(exited, false)
  })

  it("exits(1) on a production build with a missing/unattested stamp", () => {
    const codes = []
    const ok = enforceProductionStamp({
      argv: ["--publish", "always"],
      env: {},
      stampPath: "/does/not/exist/install-stamp.json",
      exit: (c) => codes.push(c),
      log: () => {}
    })
    assert.equal(ok, false)
    assert.deepEqual(codes, [1])
  })

  it("is a no-op for an explicit --dir dev build", () => {
    let exited = false
    const ok = enforceProductionStamp({
      argv: ["--dir"],
      env: {},
      stampPath: "/whatever",
      exit: () => {
        exited = true
      },
      log: () => {}
    })
    assert.equal(ok, true)
    assert.equal(exited, false)
  })

  it("exits(1) on a bare (no-flag) build with an unattested stamp — bare = production", () => {
    const codes = []
    enforceProductionStamp({
      argv: [],
      env: {},
      stampPath: writeTempStamp(allZero),
      exit: (c) => codes.push(c),
      log: () => {}
    })
    assert.deepEqual(codes, [1])
  })
})

describe("assertProductionStampForTargets (hook)", () => {
  it("throws on a production target with a missing stamp", () => {
    assert.throws(
      () => assertProductionStampForTargets({ targetNames: ["nsis"], env: {}, stampPath: "/nope.json" }),
      /attested install stamp|no install stamp/
    )
  })
  it("passes on a production target with an attested stamp", () => {
    assert.equal(
      assertProductionStampForTargets({ targetNames: ["nsis"], env: {}, stampPath: writeTempStamp(attested) }),
      true
    )
  })
  it("is a no-op for an all-dir dev pack", () => {
    assert.equal(
      assertProductionStampForTargets({ targetNames: ["dir"], env: {}, stampPath: writeTempStamp(allZero) }),
      true
    )
  })
})

// --- helpers ---
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

function writeTempStamp(stamp) {
  const dir = mkdtempSync(join(tmpdir(), "hermes-stamp-"))
  const p = join(dir, "install-stamp.json")
  writeFileSync(p, JSON.stringify(stamp))
  return p
}
