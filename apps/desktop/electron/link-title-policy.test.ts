import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import http from 'node:http'
import net from 'node:net'

import { afterEach, describe, expect, test } from 'vitest'

import type { DnsResolver, PolicyDeps } from './link-title-policy'
import {
  type AddressInfo,
  buildRequestOptions,
  fetchThroughPolicy,
  isBlockedAddress,
  LinkPolicyError,
  normalizePeerAddress,
  parseHttpUrl,
  parseIpv4,
  peerMatchesPinned,
  resolveAndValidate
} from './link-title-policy'

function portOf(server: http.Server | net.Server): number {
  return (server.address() as { port: number }).port
}

// ── URL parsing ──────────────────────────────────────────────────────────────

describe('parseHttpUrl', () => {
  test('accepts http(s) and rejects other schemes / userinfo', () => {
    assert.equal(parseHttpUrl('https://example.com/x').hostname, 'example.com')
    assert.throws(
      () => parseHttpUrl('ftp://example.com'),
      (e: LinkPolicyError) => e.code === 'blocked-scheme'
    )
    assert.throws(
      () => parseHttpUrl('file:///etc/passwd'),
      (e: LinkPolicyError) => e.code === 'blocked-scheme'
    )
    assert.throws(
      () => parseHttpUrl('javascript:alert(1)'),
      (e: LinkPolicyError) => e.code === 'blocked-scheme'
    )
    assert.throws(
      () => parseHttpUrl('http://user:pass@example.com'),
      (e: LinkPolicyError) => e.code === 'has-userinfo'
    )
    assert.throws(
      () => parseHttpUrl('not a url'),
      (e: LinkPolicyError) => e.code === 'invalid-url'
    )
  })
})

// ── Address classification ───────────────────────────────────────────────────

describe('isBlockedAddress', () => {
  test('blocks loopback, RFC1918, CGNAT, link-local + metadata, reserved', () => {
    for (const ip of [
      '127.0.0.1',
      '127.5.5.5',
      '10.0.0.1',
      '172.16.5.5',
      '172.31.255.255',
      '192.168.1.1',
      '100.64.0.1', // CGNAT
      '169.254.0.1',
      '169.254.169.254', // cloud metadata
      '0.0.0.0',
      '192.0.2.5', // TEST-NET-1
      '198.51.100.5', // TEST-NET-2
      '203.0.113.5', // TEST-NET-3
      '198.18.0.5', // benchmark
      '224.0.0.1', // multicast
      '255.255.255.255' // broadcast/reserved
    ]) {
      assert.equal(isBlockedAddress(ip), true, `${ip} must be blocked`)
    }
  })

  test('blocks alternate numeric forms after normalization', () => {
    assert.equal(parseIpv4('2130706433'), 0x7f000001) // 127.0.0.1
    assert.equal(isBlockedAddress('2130706433'), true) // decimal 127.0.0.1
    assert.equal(isBlockedAddress('0x7f000001'), true) // hex 127.0.0.1
    assert.equal(isBlockedAddress('127.1'), true) // shorthand 127.0.0.1
    assert.equal(isBlockedAddress('0177.0.0.1'), true) // octal 127
  })

  test('blocks IPv6 loopback/local/mapped/NAT64, allows public', () => {
    assert.equal(isBlockedAddress('::1'), true)
    assert.equal(isBlockedAddress('::'), true)
    assert.equal(isBlockedAddress('fe80::1'), true)
    assert.equal(isBlockedAddress('fc00::1'), true)
    assert.equal(isBlockedAddress('fd12:3456::1'), true)
    assert.equal(isBlockedAddress('ff02::1'), true)
    assert.equal(isBlockedAddress('2001:db8::1'), true) // documentation
    assert.equal(isBlockedAddress('::ffff:127.0.0.1'), true) // IPv4-mapped loopback
    assert.equal(isBlockedAddress('::ffff:10.0.0.1'), true) // IPv4-mapped private
    assert.equal(isBlockedAddress('64:ff9b::a00:1'), true) // NAT64 -> 10.0.0.1
    assert.equal(isBlockedAddress('2606:4700:4700::1111'), false) // public (cloudflare)
  })

  test('allows public IPv4 and fails closed on garbage', () => {
    assert.equal(isBlockedAddress('8.8.8.8'), false)
    assert.equal(isBlockedAddress('1.1.1.1'), false)
    assert.equal(isBlockedAddress('93.184.216.34'), false) // example.com
    assert.equal(isBlockedAddress('not-an-ip'), true) // unclassifiable -> fail closed
    assert.equal(isBlockedAddress(''), true)
  })

  // A3: standardized translated / local / site-local IPv6 ranges must fail closed.
  test('blocks NAT64 (well-known + RFC8215 local-use), 6to4, Teredo, site-local, 6bone', () => {
    // Well-known NAT64 embedding cloud metadata / private v4 — whole range blocked.
    assert.equal(isBlockedAddress('64:ff9b::a9fe:a9fe'), true) // -> 169.254.169.254
    assert.equal(isBlockedAddress('64:ff9b::808:808'), true) // even a "public" v4 fails closed now
    // RFC8215 local-use NAT64 (64:ff9b:1::/48) — whole range blocked regardless of embedding.
    assert.equal(isBlockedAddress('64:ff9b:1::1'), true)
    assert.equal(isBlockedAddress('64:ff9b:1:a9fe:a9:fe00::'), true) // RFC8215 /48 encoding of 169.254.169.254
    assert.equal(isBlockedAddress('64:ff9b:1:ffff:ffff:ffff:ffff:ffff'), true)
    // Deprecated site-local.
    assert.equal(isBlockedAddress('fec0::1'), true)
    assert.equal(isBlockedAddress('fec0:dead:beef::1'), true)
    // 6to4 embedding loopback/private v4.
    assert.equal(isBlockedAddress('2002:7f00:0001::1'), true) // 127.0.0.1
    assert.equal(isBlockedAddress('2002:c0a8:0101::1'), true) // 192.168.1.1
    // Teredo + 6bone.
    assert.equal(isBlockedAddress('2001::1'), true)
    assert.equal(isBlockedAddress('3ffe::1'), true)
    // But real IPv4-mapped public addresses (a representation, not a translation) still pass.
    assert.equal(isBlockedAddress('::ffff:93.184.216.34'), false)
  })

  // A3: IPv4-mapped IPv6 forms of private/metadata ranges must be blocked.
  test('blocks IPv4-mapped private/metadata ranges', () => {
    for (const ip of [
      '::ffff:169.254.169.254', // cloud metadata
      '::ffff:192.168.1.1',
      '::ffff:172.16.0.5',
      '::ffff:127.0.0.1',
      '::ffff:100.64.0.1'
    ]) {
      assert.equal(isBlockedAddress(ip), true, ip)
    }
  })
})

// ── DNS resolution + validation ──────────────────────────────────────────────

function dnsReturning(map: Record<string, AddressInfo[]>): DnsResolver {
  return async host => map[host] ?? []
}

describe('resolveAndValidate', () => {
  test('rejects a public name that resolves to a private address', async () => {
    const deps: PolicyDeps = { resolveDns: dnsReturning({ 'evil.test': [{ address: '10.0.0.5', family: 4 }] }) }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://evil.test/'), deps),
      (e: LinkPolicyError) => e.code === 'blocked-address'
    )
  })

  test('rejects mixed public/private DNS answers', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({
        'mixed.test': [
          { address: '93.184.216.34', family: 4 },
          { address: '169.254.169.254', family: 4 }
        ]
      })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://mixed.test/'), deps),
      (e: LinkPolicyError) => e.code === 'blocked-address'
    )
  })

  test('rejects an empty DNS answer', async () => {
    const deps: PolicyDeps = { resolveDns: dnsReturning({}) }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://nowhere.test/'), deps),
      (e: LinkPolicyError) => e.code === 'dns-empty'
    )
  })

  test('classifies a literal IP host without DNS and blocks private', async () => {
    await assert.rejects(
      resolveAndValidate(parseHttpUrl('http://10.0.0.9/'), {}),
      (e: LinkPolicyError) => e.code === 'blocked-address'
    )
  })
})

// ── buildRequestOptions ──────────────────────────────────────────────────────

describe('buildRequestOptions', () => {
  test('pins the connection while preserving Host + TLS servername', () => {
    const url = parseHttpUrl('https://pinned.example/path?q=1')
    const options = buildRequestOptions(url, { address: '203.0.113.7', family: 4 })

    assert.equal(options.hostname, 'pinned.example')
    assert.equal(options.headers.Host, 'pinned.example')
    assert.equal(options.servername, 'pinned.example')
    assert.equal(options.port, 443)
    assert.equal(options.path, '/path?q=1')

    // The lookup pins to the validated IP regardless of the hostname passed.
    let pinned: string | null = null
    options.lookup('pinned.example', {}, (_e, address) => {
      pinned = address as string
    })
    assert.equal(pinned, '203.0.113.7')
  })
})

// ── Real-socket boundary tests ───────────────────────────────────────────────

const servers: { close: () => Promise<void> }[] = []

afterEach(async () => {
  while (servers.length) {
    await servers.pop()!.close()
  }
})

function startHttpServer(
  handler: http.RequestListener
): Promise<{ port: number; hits: () => number; hostHeaders: () => string[] }> {
  const hostHeaders: string[] = []
  let hits = 0

  const server = http.createServer((req, res) => {
    hits += 1
    hostHeaders.push(req.headers.host ?? '')
    handler(req, res)
  })

  servers.push({
    close: () =>
      new Promise<void>(resolve => {
        server.close(() => resolve())
      })
  })

  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const port = portOf(server)
      resolve({ port, hits: () => hits, hostHeaders: () => hostHeaders })
    })
  })
}

// Allow-loopback classifier so the real fixture on 127.0.0.1 is reachable; the
// default classifier is proven strict by the pure tests above.
const allowLoopback = (address: string) => !(address === '127.0.0.1' || address.endsWith(':127.0.0.1'))

describe('fetchThroughPolicy — real socket', () => {
  test('pins to the validated IP, preserves the Host header, returns the body', async () => {
    const server = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<title>Pinned Page</title>')
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    const result = await fetchThroughPolicy(`http://example.test:${server.port}/page`, { deps })

    assert.equal(result.status, 200)
    assert.equal(result.body.toString('utf8'), '<title>Pinned Page</title>')
    assert.equal(result.peerAddress, '127.0.0.1')
    // Host header carried the real name, not the pinned IP.
    assert.deepEqual(server.hostHeaders(), [`example.test:${server.port}`])
  })

  test('revalidates each redirect hop and refuses a redirect to a private address', async () => {
    const server = await startHttpServer((req, res) => {
      if (req.url === '/start') {
        res.writeHead(302, { location: 'http://blocked.test/internal' })
        res.end()

        return
      }

      res.writeHead(200)
      res.end('should not reach')
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({
        'example.test': [{ address: '127.0.0.1', family: 4 }],
        'blocked.test': [{ address: '10.0.0.9', family: 4 }]
      }),
      // Loopback allowed (first hop), 10.x blocked (redirect target).
      isBlockedAddress: address => address.startsWith('10.')
    }

    await assert.rejects(
      fetchThroughPolicy(`http://example.test:${server.port}/start`, { deps }),
      (e: LinkPolicyError) => e.code === 'blocked-address'
    )

    // The blocked hop was never connected to — only the first hop was hit.
    assert.equal(server.hits(), 1)
  })

  test('follows a relative redirect through a fresh pinned connection', async () => {
    const server = await startHttpServer((req, res) => {
      if (req.url === '/a') {
        res.writeHead(302, { location: '/b' })
        res.end()

        return
      }

      res.writeHead(200)
      res.end('final body')
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    const result = await fetchThroughPolicy(`http://example.test:${server.port}/a`, { deps })

    assert.equal(result.body.toString('utf8'), 'final body')
    assert.equal(result.peerAddress, '127.0.0.1')
    assert.equal(server.hits(), 2)
  })

  test('enforces the redirect budget', async () => {
    const server = await startHttpServer((_req, res) => {
      res.writeHead(302, { location: '/next' })
      res.end()
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    await assert.rejects(
      fetchThroughPolicy(`http://example.test:${server.port}/loop`, { deps, limits: { maxRedirects: 2 } }),
      (e: LinkPolicyError) => e.code === 'too-many-redirects'
    )
  })

  test('enforces the response byte budget', async () => {
    const server = await startHttpServer((_req, res) => {
      res.writeHead(200)
      res.end(Buffer.alloc(64 * 1024, 0x61))
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    await assert.rejects(
      fetchThroughPolicy(`http://example.test:${server.port}/big`, { deps, limits: { maxBytes: 1024 } }),
      (e: LinkPolicyError) => e.code === 'response-too-large'
    )
  })

  test('aborts an in-flight request', async () => {
    const server = await startHttpServer((_req, res) => {
      // Never respond — hold the socket open so the abort is what settles it.
      res.writeHead(200)
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    const controller = new AbortController()

    const pending = fetchThroughPolicy(`http://example.test:${server.port}/hang`, {
      deps,
      signal: controller.signal
    })

    setTimeout(() => controller.abort(), 50)

    await assert.rejects(pending, (e: LinkPolicyError) => e.code === 'aborted')
  })
})

// ── TLS SNI on a real socket ─────────────────────────────────────────────────

function parseClientHelloSni(buffer: Buffer): null | string {
  if (buffer[0] !== 0x16 || buffer[5] !== 0x01) {
    return null
  }

  let p = 5 + 4 + 2 + 32 // record header + handshake header + version + random
  const sidLen = buffer[p]
  p += 1 + sidLen
  const csLen = buffer.readUInt16BE(p)
  p += 2 + csLen
  const compLen = buffer[p]
  p += 1 + compLen

  if (p + 2 > buffer.length) {
    return null
  }

  const extEnd = p + 2 + buffer.readUInt16BE(p)
  p += 2

  while (p + 4 <= extEnd && p + 4 <= buffer.length) {
    const type = buffer.readUInt16BE(p)
    const len = buffer.readUInt16BE(p + 2)
    p += 4

    if (type === 0x0000) {
      let sp = p + 2 // server_name_list length
      const nameType = buffer[sp]
      sp += 1
      const nameLen = buffer.readUInt16BE(sp)
      sp += 2

      if (nameType === 0) {
        return buffer.toString('utf8', sp, sp + nameLen)
      }
    }

    p += len
  }

  return null
}

describe('fetchThroughPolicy — TLS SNI', () => {
  test('presents the original hostname as the TLS server name over a real socket', async () => {
    let captured: null | string = null

    const server = net.createServer(socket => {
      socket.once('data', chunk => {
        captured = parseClientHelloSni(chunk)
        socket.destroy()
      })
    })

    servers.push({
      close: () =>
        new Promise<void>(resolve => {
          server.close(() => resolve())
        })
    })

    const port = await new Promise<number>(resolve => {
      server.listen(0, '127.0.0.1', () => resolve(portOf(server)))
    })

    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'sni.test': [{ address: '127.0.0.1', family: 4 }] }),
      isBlockedAddress: allowLoopback
    }

    // The handshake fails (the server speaks no TLS), but the ClientHello — with
    // SNI = the ORIGINAL hostname, not the pinned IP — reaches the socket first.
    await fetchThroughPolicy(`https://sni.test:${port}/`, { deps }).catch(() => undefined)

    await expect.poll(() => captured, { timeout: 2000 }).toBe('sni.test')
  })
})

// ── Peer-identity verification & translated networks ─────────────────────────

/** A transport that returns a response whose socket reports `peer` (or no
 *  socket when `peer` is undefined), driving the real requestOnce peer check. */
function fakeTransport(options: {
  peer?: string
  status?: number
  headers?: Record<string, string>
  body?: string
}): typeof http.request {
  return ((_reqOptions: unknown, callback: (res: unknown) => void) => {
    const req = new EventEmitter() as any

    req.setTimeout = () => {}

    req.destroy = () => {
      req.destroyed = true
    }

    req.end = () => {
      setImmediate(() => {
        const res = new EventEmitter() as any
        res.socket = options.peer === undefined ? undefined : { remoteAddress: options.peer }
        res.statusCode = options.status ?? 200
        res.headers = options.headers ?? {}
        callback(res)
        setImmediate(() => {
          if (options.body) {
            res.emit('data', Buffer.from(options.body))
          }

          res.emit('end')
        })
      })
    }

    return req
  }) as unknown as typeof http.request
}

const pinLoopback = (host: string): PolicyDeps => ({
  resolveDns: dnsReturning({ [host]: [{ address: '127.0.0.1', family: 4 }] }),
  isBlockedAddress: allowLoopback
})

describe('normalizePeerAddress / peerMatchesPinned', () => {
  test('treats IPv4-mapped IPv6 and numeric forms as the pinned address', () => {
    assert.equal(normalizePeerAddress('::ffff:127.0.0.1'), normalizePeerAddress('127.0.0.1'))
    assert.equal(normalizePeerAddress('2130706433'), normalizePeerAddress('127.0.0.1'))
    assert.equal(peerMatchesPinned('::ffff:203.0.113.7', '203.0.113.7'), true)
    assert.equal(peerMatchesPinned('fe80::1%eth0', 'fe80::1'), true)
  })

  test('fails a different peer and an unparseable/empty peer', () => {
    assert.equal(peerMatchesPinned('203.0.113.9', '203.0.113.7'), false)
    assert.equal(peerMatchesPinned('', '127.0.0.1'), false)
    assert.equal(peerMatchesPinned(null, '127.0.0.1'), false)
    assert.equal(peerMatchesPinned('garbage', '127.0.0.1'), false)
  })
})

describe('fetchThroughPolicy — peer identity fails closed', () => {
  test('rejects when the socket peer differs from the validated pin (retargeted connection)', async () => {
    const deps: PolicyDeps = {
      ...pinLoopback('example.test'),
      // Validation pins 127.0.0.1, but the connection landed on a different host
      // (a transparent proxy / agent override / rebinding race).
      httpRequest: fakeTransport({ peer: '203.0.113.9', body: 'leaked' })
    }

    await assert.rejects(
      fetchThroughPolicy('http://example.test/', { deps }),
      (error: LinkPolicyError) => error instanceof LinkPolicyError && error.code === 'peer-mismatch'
    )
  })

  test('rejects when the peer identity cannot be proven', async () => {
    const deps: PolicyDeps = {
      ...pinLoopback('example.test'),
      httpRequest: fakeTransport({ peer: undefined, body: 'leaked' })
    }

    await assert.rejects(
      fetchThroughPolicy('http://example.test/', { deps }),
      (error: LinkPolicyError) => error instanceof LinkPolicyError && error.code === 'peer-unverified'
    )
  })

  test('accepts a peer reported as the IPv4-mapped form of the pinned address', async () => {
    const deps: PolicyDeps = {
      ...pinLoopback('example.test'),
      httpRequest: fakeTransport({ peer: '::ffff:127.0.0.1', body: 'ok' })
    }

    const result = await fetchThroughPolicy('http://example.test/', { deps })
    assert.equal(result.body.toString('utf8'), 'ok')
  })
})

describe('ambient proxy / PAC cannot redirect metadata traffic', () => {
  const PROXY_ENV = [
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'NO_PROXY',
    'no_proxy'
  ]

  test('an env-configured proxy is ignored; the request hits the pinned host directly', async () => {
    // A "proxy" that records every connection. If node honored the proxy env,
    // the metadata request would land here instead of the fixture.
    let proxyConnections = 0

    const proxy = net.createServer(socket => {
      proxyConnections += 1
      socket.destroy()
    })

    servers.push({
      close: () =>
        new Promise<void>(resolve => {
          proxy.close(() => resolve())
        })
    })

    const proxyPort = await new Promise<number>(resolve => {
      proxy.listen(0, '127.0.0.1', () => resolve(portOf(proxy)))
    })

    const fixture = await startHttpServer((_req, res) => {
      res.writeHead(200)
      res.end('direct')
    })

    const saved: Record<string, string | undefined> = {}

    for (const key of PROXY_ENV) {
      saved[key] = process.env[key]
    }

    try {
      const proxyUrl = `http://127.0.0.1:${proxyPort}`
      process.env.HTTP_PROXY = proxyUrl
      process.env.HTTPS_PROXY = proxyUrl
      process.env.ALL_PROXY = proxyUrl
      process.env.http_proxy = proxyUrl
      process.env.https_proxy = proxyUrl
      process.env.all_proxy = proxyUrl
      delete process.env.NO_PROXY
      delete process.env.no_proxy

      const deps: PolicyDeps = {
        resolveDns: dnsReturning({ 'example.test': [{ address: '127.0.0.1', family: 4 }] }),
        isBlockedAddress: allowLoopback
      }

      const result = await fetchThroughPolicy(`http://example.test:${fixture.port}/page`, { deps })

      assert.equal(result.body.toString('utf8'), 'direct')
      assert.equal(result.peerAddress, '127.0.0.1')
      assert.equal(fixture.hits(), 1)
      // The proxy was never contacted — the pinned direct connection stands.
      assert.equal(proxyConnections, 0)
    } finally {
      for (const key of PROXY_ENV) {
        if (saved[key] === undefined) {
          delete process.env[key]
        } else {
          process.env[key] = saved[key]
        }
      }
    }
  })
})

describe('resolveAndValidate — translated networks (NAT64 / DNS64 / mapped)', () => {
  test('rejects a DNS64/NAT64 answer that translates to a private IPv4', async () => {
    // A DNS64 resolver may return ONLY a NAT64 address embedding a private v4.
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'dns64.test': [{ address: '64:ff9b::a00:1', family: 6 }] })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://dns64.test/'), deps),
      (error: LinkPolicyError) => error.code === 'blocked-address'
    )
  })

  test('rejects an IPv4-mapped private answer', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'mapped.test': [{ address: '::ffff:10.0.0.1', family: 6 }] })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://mapped.test/'), deps),
      (error: LinkPolicyError) => error.code === 'blocked-address'
    )
  })

  test('accepts an IPv4-mapped public answer and pins to it', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'ok.test': [{ address: '::ffff:93.184.216.34', family: 6 }] })
    }

    const pinned = await resolveAndValidate(parseHttpUrl('https://ok.test/'), deps)
    assert.equal(pinned.address, '::ffff:93.184.216.34')
  })

  test('rejects a NAT64 answer even when a later answer is public (any-blocked)', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({
        'mixed64.test': [
          { address: '64:ff9b::a9fe:a9fe', family: 6 }, // -> 169.254.169.254 metadata
          { address: '93.184.216.34', family: 4 }
        ]
      })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://mixed64.test/'), deps),
      (error: LinkPolicyError) => error.code === 'blocked-address'
    )
  })

  // A3: cloud metadata reached via an RFC8215 LOCAL-use NAT64 prefix must be
  // rejected — the whole /48 fails closed because the post-translation
  // destination cannot be proven without egress validation.
  test('rejects 169.254.169.254 reached via a local-use NAT64 (RFC8215) prefix', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({
        // 64:ff9b:1:a9fe:a9:fe00:: is the RFC8215 /48 encoding of 169.254.169.254.
        'localnat64.test': [{ address: '64:ff9b:1:a9fe:a9:fe00::', family: 6 }]
      })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://localnat64.test/'), deps),
      (error: LinkPolicyError) => error.code === 'blocked-address'
    )
  })

  test('rejects an IPv4-mapped metadata answer', async () => {
    const deps: PolicyDeps = {
      resolveDns: dnsReturning({ 'metamapped.test': [{ address: '::ffff:169.254.169.254', family: 6 }] })
    }

    await assert.rejects(
      resolveAndValidate(parseHttpUrl('https://metamapped.test/'), deps),
      (error: LinkPolicyError) => error.code === 'blocked-address'
    )
  })
})
