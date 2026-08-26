// cargo-lock-gate.test.mjs — A3 release-gate coverage.
//
// Packaging/declaration invariants (asserts about config files, not runtime
// source behavior): the signed-installer Cargo.lock must be tracked (not
// gitignored), present, and every Tauri build/test/release must run with
// --locked (--frozen in the release path).

import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import test from "node:test"

import { releaseTauriArgs } from "./release-build.mjs"

const here = dirname(fileURLToPath(import.meta.url))
const bootstrapRoot = resolve(here, "..")
const repoRoot = resolve(bootstrapRoot, "..", "..")

test("Cargo.lock is tracked-eligible: not ignored, and present on disk", () => {
  const gitignore = readFileSync(join(bootstrapRoot, ".gitignore"), "utf8")
  const ignoresLock = gitignore
    .split(/\r?\n/)
    .map((l) => l.trim())
    .some((l) => l && !l.startsWith("#") && /(^|\/)Cargo\.lock$/.test(l))
  assert.equal(ignoresLock, false, ".gitignore must NOT exclude Cargo.lock")
  assert.ok(existsSync(join(bootstrapRoot, "src-tauri", "Cargo.lock")), "Cargo.lock must exist")
})

test("Tauri build/debug scripts pass --locked to cargo", () => {
  const pkg = JSON.parse(readFileSync(join(bootstrapRoot, "package.json"), "utf8"))
  assert.match(pkg.scripts["tauri:build"], /--\s+--locked/)
  assert.match(pkg.scripts["tauri:build:debug"], /--\s+--locked/)
})

test("the release build forwards --frozen to cargo", () => {
  const args = releaseTauriArgs(["--target", "x86_64-pc-windows-msvc"])
  // Trailing "-- --frozen" forwards --frozen to cargo build.
  const dashDash = args.lastIndexOf("--")
  assert.ok(dashDash >= 0)
  assert.deepEqual(args.slice(dashDash), ["--", "--frozen"])
  // The caller's extra args are preserved before the cargo separator.
  assert.ok(args.includes("--target"))
})

test("the rust-tests workflow runs cargo test --locked and keys cache on Cargo.lock", () => {
  const wf = readFileSync(join(repoRoot, ".github", "workflows", "rust-tests.yml"), "utf8")
  assert.match(wf, /cargo test --locked/)
  assert.match(wf, /hashFiles\('apps\/bootstrap-installer\/src-tauri\/Cargo\.lock'\)/)
})
