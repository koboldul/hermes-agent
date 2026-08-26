// Main-process link-title / favicon fetch policy.
//
// SECURITY (SEC-AUDIT-003): metadata fetches are a confused-deputy SSRF and
// privacy primitive. The renderer is untrusted; the MAIN process is
// authoritative. Every page, redirect hop, manifest, and icon URL is parsed,
// its destination address classified, and the connection PINNED to a validated
// address while preserving the original hostname for the TLS SNI and HTTP Host
// header. A DNS check followed by an unpinned hostname request is vulnerable to
// rebinding; a system proxy or PAC resolver could likewise bypass validation,
// so this uses node's http/https directly with NO proxy agent and an explicit
// pinning `lookup` — if a connection cannot be pinned it fails closed rather
// than claiming protection.
//
// Everything is pure / dependency-injectable: URL parsing, address
// classification, and the request executor take injected DNS + classifier so
// the policy is testable against a real local socket without a network.

import http from 'node:http'
import https from 'node:https'

export type PolicyErrorCode =
  | 'aborted'
  | 'blocked-address'
  | 'blocked-scheme'
  | 'dns-empty'
  | 'has-userinfo'
  | 'invalid-url'
  | 'peer-mismatch'
  | 'peer-unverified'
  | 'redirect-no-location'
  | 'request-failed'
  | 'response-too-large'
  | 'timeout'
  | 'too-many-redirects'

export class LinkPolicyError extends Error {
  code: PolicyErrorCode

  constructor(code: PolicyErrorCode, message?: string) {
    super(message ?? code)
    this.name = 'LinkPolicyError'
    this.code = code
  }
}

// ── URL parsing ──────────────────────────────────────────────────────────────

/**
 * Parse an http(s) URL for the policy. Rejects any non-http(s) scheme and any
 * URL carrying userinfo (`user:pass@host`) — a classic credential-smuggling /
 * confused-host vector.
 */
export function parseHttpUrl(raw: string): URL {
  let url: URL

  try {
    url = new URL(String(raw ?? '').trim())
  } catch {
    throw new LinkPolicyError('invalid-url')
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new LinkPolicyError('blocked-scheme', `scheme ${url.protocol} is not allowed`)
  }

  if (url.username || url.password) {
    throw new LinkPolicyError('has-userinfo')
  }

  return url
}

// ── IPv4 classification ──────────────────────────────────────────────────────

// [network, prefix-bits] pairs covering loopback, RFC1918, CGNAT, link-local
// (incl. cloud metadata 169.254.169.254), IETF protocol / documentation /
// benchmark space, multicast, and reserved/broadcast.
const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
]

/** inet_aton-style parse: dotted quad plus decimal/hex/octal and shorthand forms
 *  (`2130706433`, `0x7f000001`, `127.1`). Returns the 32-bit int or null. */
export function parseIpv4(host: string): number | null {
  const raw = String(host ?? '').trim()

  if (!raw || /[^0-9a-fx.]/i.test(raw)) {
    return null
  }

  const parts = raw.split('.')

  if (parts.length === 0 || parts.length > 4) {
    return null
  }

  const nums: number[] = []

  for (const part of parts) {
    if (part === '') {
      return null
    }

    let value: number

    if (/^0x[0-9a-f]+$/i.test(part)) {
      value = parseInt(part, 16)
    } else if (/^0[0-7]+$/.test(part)) {
      value = parseInt(part, 8)
    } else if (/^[0-9]+$/.test(part)) {
      value = parseInt(part, 10)
    } else {
      return null
    }

    if (!Number.isFinite(value) || value < 0) {
      return null
    }

    nums.push(value)
  }

  // The final part absorbs the remaining bytes (inet_aton semantics).
  const last = nums.pop() as number
  const maxLast = 2 ** (8 * (4 - nums.length))

  if (last >= maxLast) {
    return null
  }

  for (const n of nums) {
    if (n > 255) {
      return null
    }
  }

  let result = last >>> 0

  for (let i = 0; i < nums.length; i++) {
    result += nums[i] * 2 ** (8 * (3 - i))
  }

  return result >>> 0
}

function ipv4IntToString(value: number): string {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.')
}

function ipv4InRange(value: number, network: string, bits: number): boolean {
  const base = parseIpv4(network) as number
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0

  return (value & mask) >>> 0 === (base & mask) >>> 0
}

export function isBlockedIpv4Int(value: number): boolean {
  return V4_BLOCKED.some(([network, bits]) => ipv4InRange(value, network, bits))
}

// ── IPv6 classification ──────────────────────────────────────────────────────

/** Expand an IPv6 address to a 128-bit BigInt, or null when malformed. Handles
 *  `::` compression and a trailing embedded IPv4 (`::ffff:1.2.3.4`). */
export function parseIpv6(host: string): bigint | null {
  let raw = String(host ?? '')
    .trim()
    .replace(/^\[/, '')
    .replace(/\]$/, '')

  if (!raw.includes(':')) {
    return null
  }

  // Strip a zone id (fe80::1%eth0).
  raw = raw.split('%')[0]

  const halves = raw.split('::')

  if (halves.length > 2) {
    return null
  }

  const expandSide = (side: string): number[] | null => {
    if (side === '') {
      return []
    }

    const groups: number[] = []
    const tokens = side.split(':')

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]

      // Embedded IPv4 (only valid as the final token).
      if (token.includes('.')) {
        if (i !== tokens.length - 1) {
          return null
        }

        const v4 = parseIpv4(token)

        if (v4 === null || /[^0-9.]/.test(token)) {
          return null
        }

        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff)

        continue
      }

      if (!/^[0-9a-f]{1,4}$/i.test(token)) {
        return null
      }

      groups.push(parseInt(token, 16))
    }

    return groups
  }

  const head = expandSide(halves[0])
  const tail = halves.length === 2 ? expandSide(halves[1]) : []

  if (head === null || tail === null) {
    return null
  }

  let groups: number[]

  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length

    if (fill < 0) {
      return null
    }

    groups = [...head, ...new Array(fill).fill(0), ...tail]
  } else {
    groups = head
  }

  if (groups.length !== 8) {
    return null
  }

  let value = 0n

  for (const group of groups) {
    value = (value << 16n) | BigInt(group & 0xffff)
  }

  return value
}

function ipv6InRange(value: bigint, network: string, bits: number): boolean {
  const base = parseIpv6(network)

  if (base === null) {
    return false
  }

  const shift = BigInt(128 - bits)
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << shift

  return (value & mask) === (base & mask)
}

const V6_BLOCKED: [string, number][] = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['fc00::', 7], // unique-local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // deprecated site-local (RFC3879) — still routable on legacy nets
  ['ff00::', 8], // multicast
  ['2001:db8::', 32], // documentation
  ['2001::', 32], // Teredo tunneling (embeds an arbitrary IPv4 server/client)
  ['2002::', 16], // 6to4 (embeds an arbitrary, possibly private, IPv4)
  ['3ffe::', 16], // 6bone (deprecated test space)
  ['5f00::', 8], // former 6bone / reserved
  ['100::', 64], // discard-only
  // NAT64 translation prefixes. The connection is routed by the LOCAL NAT64
  // gateway, so the real post-translation IPv4 destination cannot be proven
  // from the address alone — a hostile/DNS64 network can map the well-known or
  // RFC8215 local-use prefix onto loopback/metadata/private space. Without an
  // egress-validation channel we FAIL CLOSED on the whole ranges rather than
  // trusting a standard embedding (SEC-AUDIT-003 / A3).
  ['64:ff9b::', 96], // RFC6052 well-known NAT64
  ['64:ff9b:1::', 48] // RFC8215 local-use NAT64 translation
]

const V4_MAPPED_MASK = ((1n << 96n) - 1n) << 32n
const V4_MAPPED_BASE = 0xffffn << 32n // ::ffff:0:0/96

export function isBlockedIpv6BigInt(value: bigint): boolean {
  // IPv4-mapped (::ffff:a.b.c.d) is a direct REPRESENTATION of an IPv4 address
  // (no translation gateway), so classify the embedded IPv4 and pin to it.
  if ((value & V4_MAPPED_MASK) === V4_MAPPED_BASE) {
    return isBlockedIpv4Int(Number(value & 0xffffffffn))
  }

  // Everything else, including every NAT64/tunnel translation prefix above,
  // is matched by range — no embedded-IPv4 extraction, so a translated
  // destination we cannot prove fails closed.
  return V6_BLOCKED.some(([network, bits]) => ipv6InRange(value, network, bits))
}

/** True when an address string is in a private/reserved/loopback/metadata range
 *  that a metadata fetch must never reach. Unparseable input fails closed. */
export function isBlockedAddress(address: string): boolean {
  const raw = String(address ?? '').trim()

  const v4 = parseIpv4(raw)

  if (v4 !== null && !raw.includes(':')) {
    return isBlockedIpv4Int(v4)
  }

  const v6 = parseIpv6(raw)

  if (v6 !== null) {
    return isBlockedIpv6BigInt(v6)
  }

  // Not an address we can classify → fail closed.
  return true
}

/**
 * Canonicalize a peer address for identity comparison: strip an IPv4-mapped IPv6
 * prefix and a zone id, then reduce IPv4 (any numeric form) and IPv6 to a single
 * canonical representation. Returns '' when the value is not a parseable address
 * so a comparison against it can never spuriously succeed.
 */
export function normalizePeerAddress(address: null | string | undefined): string {
  let raw = String(address ?? '')
    .trim()
    .toLowerCase()

  if (!raw) {
    return ''
  }

  // Drop an IPv6 zone id (fe80::1%eth0) and an IPv4-mapped prefix.
  raw = raw.replace(/%.*$/, '')

  const mapped = raw.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)

  if (mapped) {
    raw = mapped[1]
  }

  const v4 = parseIpv4(raw)

  if (v4 !== null && !raw.includes(':')) {
    return `v4:${v4 >>> 0}`
  }

  const v6 = parseIpv6(raw)

  if (v6 !== null) {
    return `v6:${v6.toString(16)}`
  }

  return ''
}

/**
 * Whether the actual socket peer is the address we validated and pinned. A
 * mismatch means the connection was retargeted after validation (a transparent
 * proxy, a PAC/agent override, a rebinding race), and an unparseable/empty peer
 * means identity cannot be proven — both fail closed.
 */
export function peerMatchesPinned(peer: null | string | undefined, pinned: string): boolean {
  const normalizedPeer = normalizePeerAddress(peer)

  return normalizedPeer !== '' && normalizedPeer === normalizePeerAddress(pinned)
}

// ── DNS resolution + pinning ─────────────────────────────────────────────────

export interface AddressInfo {
  address: string
  family: number
}

export type DnsResolver = (hostname: string) => Promise<AddressInfo[]>

const defaultResolveDns: DnsResolver = async hostname => {
  const { lookup } = await import('node:dns')

  return new Promise((resolve, reject) => {
    lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
      if (error) {
        reject(error)

        return
      }

      resolve(addresses as AddressInfo[])
    })
  })
}

export interface PolicyDeps {
  resolveDns?: DnsResolver
  isBlockedAddress?: (address: string) => boolean
  httpRequest?: typeof http.request
  httpsRequest?: typeof https.request
}

/**
 * Resolve a URL's host to a single validated, pinned address. A literal IP host
 * is classified directly (no DNS); a name is resolved and rejected if the answer
 * is empty or if ANY returned address is blocked (covers mixed public/private
 * DNS answers and rebinding attempts).
 */
export async function resolveAndValidate(url: URL, deps: PolicyDeps = {}): Promise<AddressInfo> {
  const blocked = deps.isBlockedAddress ?? isBlockedAddress
  const host = url.hostname.replace(/^\[/, '').replace(/\]$/, '')

  // Literal IP host: classify directly and pin to the normalized address.
  const v4 = parseIpv4(host)

  if (v4 !== null && !host.includes(':')) {
    const address = ipv4IntToString(v4)

    if (blocked(address)) {
      throw new LinkPolicyError('blocked-address', address)
    }

    return { address, family: 4 }
  }

  if (parseIpv6(host) !== null) {
    if (blocked(host)) {
      throw new LinkPolicyError('blocked-address', host)
    }

    return { address: host, family: 6 }
  }

  const resolve = deps.resolveDns ?? defaultResolveDns
  const answers = await resolve(host)

  if (!Array.isArray(answers) || answers.length === 0) {
    throw new LinkPolicyError('dns-empty', host)
  }

  for (const answer of answers) {
    if (blocked(answer.address)) {
      throw new LinkPolicyError('blocked-address', answer.address)
    }
  }

  return answers[0]
}

// ── Request execution ────────────────────────────────────────────────────────

export interface PolicyLimits {
  maxRedirects?: number
  connectTimeoutMs?: number
  totalTimeoutMs?: number
  maxBytes?: number
}

const DEFAULT_LIMITS: Required<PolicyLimits> = {
  maxRedirects: 3,
  connectTimeoutMs: 4000,
  totalTimeoutMs: 8000,
  maxBytes: 256 * 1024
}

interface RequestOptions {
  headers: Record<string, string>
  hostname: string
  lookup: (hostname: string, options: any, callback: (err: null | Error, address: any, family?: number) => void) => void
  method: string
  path: string
  port: number
  protocol: string
  servername?: string
}

/**
 * Build node request options that connect to the PINNED address while presenting
 * the original hostname for TLS SNI (`servername`) and the HTTP `Host` header.
 */
export function buildRequestOptions(
  url: URL,
  pinned: AddressInfo,
  extraHeaders: Record<string, string> = {}
): RequestOptions {
  const isHttps = url.protocol === 'https:'
  const port = url.port ? Number(url.port) : isHttps ? 443 : 80

  const options: RequestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    port,
    method: 'GET',
    path: `${url.pathname}${url.search}`,
    headers: {
      // Preserve the real host identity even though we connect to the pinned IP.
      Host: url.host,
      'Accept-Encoding': 'identity',
      Connection: 'close',
      ...extraHeaders
    },
    // Pin every connection to the validated address — DNS cannot change between
    // validation and connect (rebinding), and no proxy/PAC can retarget it.
    lookup: (_hostname, lookupOptions, callback) => {
      if (lookupOptions && lookupOptions.all) {
        callback(null, [{ address: pinned.address, family: pinned.family }])

        return
      }

      callback(null, pinned.address, pinned.family)
    }
  }

  if (isHttps) {
    options.servername = url.hostname
  }

  return options
}

interface RawResponse {
  status: number
  headers: Record<string, string | string[] | undefined>
  body: Buffer
  peerAddress: null | string
  contentType: string
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308
}

function requestOnce(
  url: URL,
  pinned: AddressInfo,
  deps: PolicyDeps,
  limits: Required<PolicyLimits>,
  extraHeaders: Record<string, string>,
  signal?: AbortSignal,
  truncate = false
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new LinkPolicyError('aborted'))

      return
    }

    const isHttps = url.protocol === 'https:'
    const request = isHttps ? deps.httpsRequest ?? https.request : deps.httpRequest ?? http.request
    const options = buildRequestOptions(url, pinned, extraHeaders)

    let settled = false
    let peerAddress: null | string = null
    const totalTimer = setTimeout(() => fail(new LinkPolicyError('timeout')), limits.totalTimeoutMs)

    const cleanup = () => {
      clearTimeout(totalTimer)
      signal?.removeEventListener('abort', onAbort)
    }

    const fail = (error: Error) => {
      if (settled) {
        return
      }

      settled = true
      cleanup()

      try {
        req.destroy()
      } catch {
        // best-effort
      }

      reject(error)
    }

    const onAbort = () => fail(new LinkPolicyError('aborted'))

    signal?.addEventListener('abort', onAbort)

    const req = request(options as any, res => {
      peerAddress = res.socket?.remoteAddress ?? peerAddress

      // Fail closed unless the ACTUAL socket peer is the address we validated
      // and pinned. This catches any post-validation retargeting — a transparent
      // or env/PAC-configured proxy, an injected agent, or a rebinding race —
      // and refuses to read a response we cannot attribute to the checked host.
      if (!peerMatchesPinned(peerAddress, pinned.address)) {
        fail(new LinkPolicyError(peerAddress ? 'peer-mismatch' : 'peer-unverified', peerAddress ?? undefined))

        return
      }

      const chunks: Buffer[] = []
      let bytes = 0

      const succeed = () => {
        if (settled) {
          return
        }

        settled = true
        cleanup()
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks),
          peerAddress,
          contentType: String(res.headers['content-type'] ?? '')
        })
      }

      res.on('data', (chunk: Buffer) => {
        if (settled) {
          return
        }

        const remaining = limits.maxBytes - bytes

        if (chunk.length >= remaining) {
          if (remaining > 0) {
            chunks.push(chunk.subarray(0, remaining))
            bytes = limits.maxBytes
          }

          if (truncate) {
            // Read only the head — a redirect/title/favicon lives near the top.
            succeed()

            try {
              req.destroy()
            } catch {
              // best-effort
            }

            return
          }

          fail(new LinkPolicyError('response-too-large'))

          return
        }

        chunks.push(chunk)
        bytes += chunk.length
      })

      res.on('end', succeed)
      res.on('error', fail)
    })

    req.on('socket', socket => {
      socket.on('connect', () => {
        peerAddress = socket.remoteAddress ?? peerAddress
      })
    })

    req.setTimeout(limits.connectTimeoutMs, () => fail(new LinkPolicyError('timeout')))
    req.on('error', error => fail(error instanceof LinkPolicyError ? error : new LinkPolicyError('request-failed', String((error as Error)?.message ?? error))))
    req.end()
  })
}

export interface PolicyFetchResult {
  finalUrl: string
  status: number
  body: Buffer
  contentType: string
  peerAddress: null | string
}

export interface PolicyFetchOptions {
  deps?: PolicyDeps
  limits?: PolicyLimits
  headers?: Record<string, string>
  signal?: AbortSignal
  /** Read only up to `maxBytes` and return the head instead of erroring. Use for
   *  title/favicon/manifest fetches where the useful markup is near the top. */
  truncate?: boolean
}

/**
 * Fetch a URL through the full policy: parse → resolve+validate → pin+connect,
 * following redirects MANUALLY so every hop repeats the entire parse, DNS,
 * address-classification, and pinning sequence. Never follows a redirect to a
 * blocked destination; never exposes response headers or internal errors beyond
 * a typed error code.
 */
export async function fetchThroughPolicy(rawUrl: string, options: PolicyFetchOptions = {}): Promise<PolicyFetchResult> {
  const deps = options.deps ?? {}
  const limits = { ...DEFAULT_LIMITS, ...(options.limits ?? {}) }
  const headers = options.headers ?? {}

  let current = parseHttpUrl(rawUrl)

  for (let hop = 0; ; hop++) {
    if (hop > limits.maxRedirects) {
      throw new LinkPolicyError('too-many-redirects')
    }

    const pinned = await resolveAndValidate(current, deps)
    const response = await requestOnce(current, pinned, deps, limits, headers, options.signal, options.truncate)

    if (!isRedirect(response.status)) {
      return {
        finalUrl: current.href,
        status: response.status,
        body: response.body,
        contentType: response.contentType,
        peerAddress: response.peerAddress
      }
    }

    const location = response.headers.location

    if (!location) {
      throw new LinkPolicyError('redirect-no-location')
    }

    const locationValue = Array.isArray(location) ? location[0] : location
    let nextHref: string

    try {
      nextHref = new URL(locationValue, current.href).href
    } catch {
      throw new LinkPolicyError('invalid-url')
    }

    // Re-parse the full URL so a redirect to a non-http(s) scheme or a userinfo
    // URL is rejected exactly like the initial request.
    current = parseHttpUrl(nextHref)
  }
}

/** Fetch text (title/HTML/manifest), size-capped and decoded as UTF-8. */
export async function fetchTextThroughPolicy(
  rawUrl: string,
  accept: string,
  options: PolicyFetchOptions = {}
): Promise<{ text: string; finalUrl: string; status: number }> {
  const result = await fetchThroughPolicy(rawUrl, {
    ...options,
    headers: { Accept: accept, ...(options.headers ?? {}) }
  })

  return { text: result.body.toString('utf8'), finalUrl: result.finalUrl, status: result.status }
}
