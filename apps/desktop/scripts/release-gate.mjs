// release-gate.mjs — A10 production packaging enforcement.
//
// The install stamp (write-build-stamp.mjs) can be written as an unattested
// (all-zero / dirty / branch-only) stamp for local dev. This gate makes the
// attested-stamp requirement NON-OPTIONAL for a production build, independent
// of whether the CI workflow set any env var — so a production package can
// never ship with an unpinned installer identity.
//
// Production policy (A10 re-review): EVERY artifact-producing electron-builder
// invocation is production — `--win`/`--mac`/`--linux`, any NSIS/MSI/AppImage/
// deb/rpm/dmg target, a bare `electron-builder`, or a `--publish`/tag build.
// The ONLY exemption is an explicit `--dir` dev pack (unpacked, no installer).
// Enforced in BOTH the wrapper (argv) and the electron-builder beforePack hook
// (resolved targets), so a direct builder invocation cannot bypass it.

import { readFileSync } from "node:fs"

import { stampRejectionReason } from "./write-build-stamp.mjs"

// electron-builder publish flags. A publish target other than "never"/"false"
// means real artifacts are being produced for distribution.
function publishValueIsRelease(value) {
  if (value == null) return false
  const v = String(value).toLowerCase()
  return v !== "never" && v !== "false" && v !== "0"
}

/**
 * True when explicit publish/tag/env signals mark this as a release build.
 * (Kept as a distinct predicate; the broader isProductionBuild subsumes it.)
 */
export function isProductionPublish(argv = [], env = process.env) {
  if (env.HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP === "1") return true
  if (env.HERMES_DESKTOP_PRODUCTION === "1") return true
  if (env.GITHUB_REF_TYPE === "tag") return true

  const args = Array.isArray(argv) ? argv.map(String) : []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === "-p" || a === "--publish") {
      if (publishValueIsRelease(args[i + 1])) return true
    } else if (a.startsWith("--publish=")) {
      if (publishValueIsRelease(a.slice("--publish=".length))) return true
    } else if (a.startsWith("-p=")) {
      if (publishValueIsRelease(a.slice("-p=".length))) return true
    }
  }
  return false
}

/**
 * Alert 2: classify a RESOLVED electron-builder `publish` config value as a
 * release publish. electron-builder normalizes `--publish <v>` into
 * `config.publish` and reads `publish:` from electron-builder.yml /
 * package.json build config as a provider string ("github"/"s3"/"never"),
 * an object ({provider}), or an array of those. Only `never`/`false`/`0`
 * (string or `{provider:"never"}`) is NOT a release publish; anything else —
 * including a bare object or a non-empty array — publishes real artifacts.
 */
export function publishConfigIsRelease(publish) {
  if (publish == null || publish === false) return false
  if (typeof publish === "string") return publishValueIsRelease(publish)
  if (Array.isArray(publish)) return publish.some(publishConfigIsRelease)
  if (typeof publish === "object") {
    if (typeof publish.provider === "string") return publishValueIsRelease(publish.provider)
    return true
  }
  return Boolean(publish)
}

/**
 * Alert 2: TRUE when the CURRENT electron-builder pack context is a release
 * publish, resolved from the ACTUAL context — not merely env/argv. It folds
 * together, in order:
 *   1. env/tag/attested signals (isProductionPublish with no argv), and
 *   2. the wrapper's propagated decision (HERMES_DESKTOP_IS_PUBLISH=1, set by
 *      run-electron-builder when it detects a `--publish` release so the
 *      spawned electron-builder child — where beforePack runs — inherits it), and
 *   3. the electron-builder-RESOLVED publish config that a direct
 *      `electron-builder --publish always` (no wrapper) still produces:
 *      packager.platformSpecificBuildOptions.publish, packager.config.publish,
 *      packager.info.config.publish, and context.config.publish.
 * ANY of these being a release publish denies break-glass on unverified
 * Electron, regardless of a per-component opt-in.
 */
export function isPublishReleaseContext(context, env = process.env) {
  if (isProductionPublish([], env)) return true
  if (env && env.HERMES_DESKTOP_IS_PUBLISH === "1") return true
  const packager = context && context.packager
  const candidates = [
    packager && packager.platformSpecificBuildOptions && packager.platformSpecificBuildOptions.publish,
    packager && packager.config && packager.config.publish,
    packager && packager.info && packager.info.config && packager.info.config.publish,
    context && context.config && context.config.publish
  ]
  return candidates.some(publishConfigIsRelease)
}

/**
 * True when the invocation is an explicit `--dir` unpacked dev pack. This is
 * the ONLY build shape exempt from the production attestation requirement.
 */
export function isDevDirPack(argv = []) {
  const args = Array.isArray(argv) ? argv.map(String) : []
  return args.some((a) => a === "--dir" || a === "-c.target=dir" || a.startsWith("--dir="))
}

/**
 * The broad production gate (argv-based, for the wrapper). Every invocation is
 * production UNLESS it is an explicit `--dir` dev pack. Publish/tag/env signals
 * force production even alongside `--dir`.
 */
export function isProductionBuild(argv = [], env = process.env) {
  if (isProductionPublish(argv, env)) return true
  if (isDevDirPack(argv)) return false
  return true
}

/**
 * The production gate for the electron-builder beforePack HOOK, which receives
 * the RESOLVED targets (Target[].name) rather than argv. Production unless
 * EVERY resolved target is the unpacked dev `dir` target. Unknown/empty targets
 * fail closed (treated as production). Env signals force production.
 */
export function isProductionBuildFromTargets(targetNames = [], env = process.env) {
  if (env.HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP === "1") return true
  if (env.HERMES_DESKTOP_PRODUCTION === "1") return true
  if (env.GITHUB_REF_TYPE === "tag") return true
  const names = (Array.isArray(targetNames) ? targetNames : [])
    .map((n) => String(n || "").toLowerCase())
    .filter(Boolean)
  if (names.length === 0) return true // unknown targets → fail closed
  return !names.every((n) => n === "dir")
}

/**
 * B3: whether an UNVERIFIED (break-glass) Electron dist may be used for an
 * ARGV-resolved build (the wrapper). Break-glass is limited to an explicit
 * `--dir` development pack: EVERY artifact-producing (production) build must
 * reject unverified Electron, derived from isProductionBuild — NOT only from
 * --publish/tag. `optIn` is the per-component config opt-in
 * (security.supply_chain.allow_unverified_components: ["electron"]).
 */
export function electronBreakGlassAllowedForArgv(argv = [], env = process.env, optIn = false) {
  return Boolean(optIn) && !isProductionBuild(argv, env)
}

/**
 * B3 (beforePack hook): the resolved-targets form. Break-glass is allowed only
 * for an all-`dir` dev pack — every artifact-producing production target rejects
 * unverified Electron, derived from isProductionBuildFromTargets, independent of
 * --publish/tag. Unknown/empty targets fail closed (treated as production).
 */
export function electronBreakGlassAllowedForTargets(targetNames = [], env = process.env, optIn = false) {
  return Boolean(optIn) && !isProductionBuildFromTargets(targetNames, env)
}

/**
 * Reason a build must be refused, or null when it may proceed. `production` can
 * be passed explicitly (from a target-based detector) or computed from argv/env.
 *   - Non-production builds are always allowed (dev packaging).
 *   - Production builds require a stamp that passes stampRejectionReason
 *     (full 40-char commit, clean tree, not the all-zero placeholder).
 */
export function productionGateRejection(stamp, { argv = [], env = process.env, production } = {}) {
  const isProd = production !== undefined ? production : isProductionBuild(argv, env)
  if (!isProd) return null
  if (!stamp) return "production build has no install stamp (build/install-stamp.json missing)"
  return stampRejectionReason(stamp)
}

/** Read the stamp written by write-build-stamp.mjs; null when absent/unreadable. */
export function readStamp(stampPath) {
  try {
    return JSON.parse(readFileSync(stampPath, "utf8"))
  } catch {
    return null
  }
}

/**
 * Enforce the gate for a real build from ARGV (the wrapper). `exit`/`log` are
 * injected for tests. Returns true when the build may proceed. On a production
 * build with a non-attested stamp it logs the reason and calls exit(1).
 */
export function enforceProductionStamp({ argv = [], env = process.env, stampPath, exit, log } = {}) {
  const _exit = exit || process.exit
  const _log = log || console.error
  if (!isProductionBuild(argv, env)) return true

  const reason = productionGateRejection(readStamp(stampPath), { argv, env, production: true })
  if (reason) {
    _log(
      "[release-gate] refusing production package: " +
        reason +
        ".\n  A production/publish Desktop build must ship an attested install stamp — an exact, " +
        "full 40-char commit SHA from a clean tree. Only an explicit `--dir` dev pack is exempt."
    )
    _exit(1)
    return false
  }
  return true
}

/**
 * Enforce the gate from the electron-builder beforePack HOOK, using the
 * resolved target names. THROWS on a production build with a non-attested stamp
 * (electron-builder hooks fail the build by throwing) so a DIRECT builder
 * invocation — bypassing the wrapper — is still gated. Returns true when OK.
 */
export function assertProductionStampForTargets({ targetNames = [], env = process.env, stampPath } = {}) {
  const production = isProductionBuildFromTargets(targetNames, env)
  const reason = productionGateRejection(readStamp(stampPath), { production })
  if (reason) {
    throw new Error(
      "[before-pack] refusing to package a production Desktop build: " +
        reason +
        ". A production build must ship an attested install stamp (exact full 40-char commit " +
        "SHA from a clean tree). Only an explicit `--dir` dev pack is exempt."
    )
  }
  return true
}
