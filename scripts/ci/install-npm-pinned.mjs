// install-npm-pinned.mjs -- trusted, digest-pinned npm CI bootstrap.
//
// A global registry install of npm by version (npm@12.0.2) is version-exact but
// still trusts registry METADATA to resolve the tarball. This installer removes
// that trust: it downloads the EXACT canonical tarball URL, follows only a
// bounded number of redirects whose hosts are on an approved list, hashes the
// downloaded bytes, and refuses to install unless the sha256 matches the
// committed digest. Only then does it hand the verified LOCAL tarball to the
// existing npm with `-g --ignore-scripts --offline` (no registry resolution, no
// lifecycle scripts).
//
// Identity (version/url/sha256/hosts) comes from supply-chain/npm-bootstrap.json,
// which tests validate against nix/npm-12-0-2.nix -- one source of truth.
//
// Usage (CI): node scripts/ci/install-npm-pinned.mjs
// Test hooks (args only -- never env, per repo policy):
//   --identity <path>  --url <url>  --sha256 <hex>  --host <h> (repeatable)
//   --npm <bin>  --out <path>  --verify-only  --max-redirects <n>

import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { readFileSync, rmSync, writeFileSync, mkdtempSync } from "node:fs"
import { get as httpGet } from "node:http"
import { get as httpsGet } from "node:https"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(HERE, "..", "..")
const DEFAULT_IDENTITY = join(REPO_ROOT, "supply-chain", "npm-bootstrap.json")

export function parseArgs(argv) {
  const out = { hosts: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "--verify-only") out.verifyOnly = true
    else if (a === "--host") out.hosts.push(argv[++i])
    else if (a === "--identity") out.identity = argv[++i]
    else if (a === "--url") out.url = argv[++i]
    else if (a === "--sha256") out.sha256 = argv[++i]
    else if (a === "--npm") out.npm = argv[++i]
    else if (a === "--out") out.out = argv[++i]
    else if (a === "--max-redirects") out.maxRedirects = Number(argv[++i])
  }
  return out
}

export function loadIdentity(path) {
  const raw = JSON.parse(readFileSync(path, "utf8"))
  const value = raw && raw.digest && raw.digest.value
  if (!raw.version || !raw.url || !value) {
    throw new Error(`npm-bootstrap identity ${path} is missing version/url/digest`)
  }
  return {
    version: String(raw.version),
    url: String(raw.url),
    sha256: String(value).toLowerCase(),
    hosts: Array.isArray(raw.canonical_hosts) ? raw.canonical_hosts.map(String) : [],
  }
}

// A request target is approved only when its host is on the allow-list AND its
// scheme is https -- with a single carve-out for loopback (127.0.0.1 / ::1 /
// localhost), which lets tests serve fixtures over plain http without ever
// weakening the production posture (registry.npmjs.org is https-only).
export function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "::1" || host === "[::1]" || host === "localhost"
}

export function isApprovedTarget(urlObj, approvedHosts) {
  const host = urlObj.hostname
  if (!approvedHosts.includes(host)) return false
  if (urlObj.protocol === "https:") return true
  if (urlObj.protocol === "http:" && isLoopbackHost(host)) return true
  return false
}

export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex")
}

export function buildInstallArgs(tarball) {
  // Install the VERIFIED LOCAL tarball -- never `npm@<spec>` (that would re-trust
  // the registry). --offline forbids any network resolution; --ignore-scripts
  // forbids lifecycle code.
  return ["install", "-g", "--ignore-scripts", "--offline", tarball]
}

function fetchOnce(urlObj) {
  const getter = urlObj.protocol === "https:" ? httpsGet : httpGet
  return new Promise((resolvePromise, reject) => {
    const req = getter(urlObj, (res) => {
      const status = res.statusCode || 0
      const location = res.headers.location
      if (status >= 300 && status < 400 && location) {
        res.resume() // drain
        resolvePromise({ redirect: new URL(location, urlObj) })
        return
      }
      if (status !== 200) {
        res.resume()
        reject(new Error(`unexpected HTTP status ${status} for ${urlObj.href}`))
        return
      }
      const chunks = []
      res.on("data", (c) => chunks.push(c))
      res.on("end", () => resolvePromise({ body: Buffer.concat(chunks) }))
      res.on("error", reject)
    })
    req.on("error", reject)
  })
}

export async function downloadVerified({ url, sha256, approvedHosts, maxRedirects = 5 }) {
  let current = new URL(url)
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (!isApprovedTarget(current, approvedHosts)) {
      throw new Error(
        `refusing request to ${current.href}: host/scheme not on the approved ` +
          `list (${approvedHosts.join(", ")}; https required off-loopback)`,
      )
    }
    const res = await fetchOnce(current)
    if (res.redirect) {
      current = res.redirect
      continue
    }
    const actual = sha256Hex(res.body).toLowerCase()
    if (actual !== sha256.toLowerCase()) {
      throw new Error(
        `sha256 mismatch for ${url}: expected ${sha256}, got ${actual} ` +
          `(${res.body.length} bytes) -- refusing to install`,
      )
    }
    return res.body
  }
  throw new Error(`too many redirects (> ${maxRedirects}) resolving ${url}`)
}

export async function run(argv = process.argv.slice(2), { log = console.error } = {}) {
  const args = parseArgs(argv)
  const identity = loadIdentity(args.identity || DEFAULT_IDENTITY)
  const url = args.url || identity.url
  const sha256 = (args.sha256 || identity.sha256).toLowerCase()
  const approvedHosts = [...new Set([...identity.hosts, ...args.hosts])]
  const maxRedirects = Number.isFinite(args.maxRedirects) ? args.maxRedirects : 5

  log(`[npm-bootstrap] downloading pinned npm@${identity.version} from ${url}`)
  const body = await downloadVerified({ url, sha256, approvedHosts, maxRedirects })
  log(`[npm-bootstrap] verified sha256 ${sha256} over ${body.length} bytes`)

  const dir = mkdtempSync(join(tmpdir(), "hermes-npm-"))
  const tarball = args.out || join(dir, `npm-${identity.version}.tgz`)
  writeFileSync(tarball, body)
  try {
    if (args.verifyOnly) {
      log(`[npm-bootstrap] verify-only: wrote verified tarball to ${tarball}`)
      return { tarball, verified: true, installed: false }
    }
    const npm = args.npm || (process.platform === "win32" ? "npm.cmd" : "npm")
    const cmdArgs = buildInstallArgs(tarball)
    log(`[npm-bootstrap] installing verified local tarball: ${npm} ${cmdArgs.join(" ")}`)
    const res = spawnSync(npm, cmdArgs, {
      stdio: "inherit",
      shell: process.platform === "win32",
    })
    if (res.status !== 0) {
      throw new Error(`npm install of the verified tarball failed (status ${res && res.status})`)
    }
    return { tarball, verified: true, installed: true }
  } finally {
    if (!args.out) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* best-effort temp cleanup */
      }
    }
  }
}

async function main() {
  try {
    await run()
  } catch (err) {
    console.error(`[npm-bootstrap] ${err.message}`)
    process.exit(1)
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main()
}
