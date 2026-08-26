import assert from 'node:assert/strict'

import { describe, test } from 'vitest'

import {
  applyDesktopCsp,
  desktopContentSecurityPolicy,
  isAppOriginUrl,
  scriptSrcTokens,
  withCspHeader
} from './desktop-csp'

const DEV_SERVER = 'http://127.0.0.1:5174'

// The provider script origins SEC-AUDIT-005 forbids, plus generic remote forms.
const REMOTE_SCRIPT_MARKERS = [
  'instagram.com',
  'platform.twitter.com',
  'tiktok.com',
  'http:',
  'https:',
  '*'
]

function scriptSrcDirective(policy: string): string {
  return policy.split(';').map(part => part.trim()).find(part => part.startsWith('script-src ')) ?? ''
}

describe('desktop CSP policy', () => {
  test('production script-src is self-hosted only and admits no remote origin', () => {
    const directive = scriptSrcDirective(desktopContentSecurityPolicy())

    assert.ok(directive.includes("'self'"))
    // Local plugin loader mechanism must survive.
    assert.ok(directive.includes('blob:'))

    for (const marker of REMOTE_SCRIPT_MARKERS) {
      assert.ok(!directive.includes(marker), `script-src must not include ${marker}: ${directive}`)
    }
  })

  test('hardening directives are present', () => {
    const policy = desktopContentSecurityPolicy()

    assert.ok(policy.includes("object-src 'none'"))
    assert.ok(policy.includes("base-uri 'self'"))
    assert.ok(policy.includes("frame-ancestors 'none'"))
  })

  test('dev pins the vite origin for scripts but never a wildcard', () => {
    const tokens = scriptSrcTokens({ devServer: DEV_SERVER })

    assert.ok(tokens.includes(DEV_SERVER))
    assert.ok(!tokens.some(token => token.includes('*')))
  })

  test('a provider script origin is not permitted by the parsed directive', () => {
    // Model the CSP source-expression match for `script-src` against a remote
    // src: only 'self'/blob:/keywords/dev-origin are listed, so an external
    // https origin has no matching source expression and is blocked.
    const tokens = scriptSrcTokens()
    const allowedOrigin = (src: string) => tokens.some(token => token === src)

    assert.equal(allowedOrigin('https://www.instagram.com'), false)
    assert.equal(allowedOrigin('https://platform.twitter.com'), false)
  })
})

describe('CSP app-origin scoping', () => {
  test('app documents and assets are app origin', () => {
    assert.equal(isAppOriginUrl('file:///opt/app/dist/index.html'), true)
    assert.equal(isAppOriginUrl('file:///opt/app/dist/assets/index-abc.js'), true)
    assert.equal(isAppOriginUrl(`${DEV_SERVER}/src/main.tsx`, { devServer: DEV_SERVER }), true)
  })

  test('cross-origin embed documents are not app origin', () => {
    assert.equal(isAppOriginUrl('https://www.youtube.com/embed/x'), false)
    assert.equal(isAppOriginUrl('https://www.instagram.com/embed.js'), false)
    assert.equal(isAppOriginUrl(`${DEV_SERVER}/x`), false)
  })
})

describe('withCspHeader', () => {
  test('replaces any upstream CSP with a single enforcing header', () => {
    const merged = withCspHeader(
      {
        'content-security-policy': ["script-src *"],
        'Content-Security-Policy-Report-Only': ['default-src *'],
        'X-Frame-Options': ['DENY']
      },
      "script-src 'self'"
    )

    assert.deepEqual(merged['Content-Security-Policy'], ["script-src 'self'"])
    assert.ok(!('content-security-policy' in merged))
    assert.ok(!('Content-Security-Policy-Report-Only' in merged))
    assert.deepEqual(merged['X-Frame-Options'], ['DENY'])
  })
})

describe('applyDesktopCsp', () => {
  function fakeSession() {
    let listener: any = null

    return {
      session: {
        webRequest: {
          onHeadersReceived: (fn: any) => {
            listener = fn
          }
        }
      },
      emit: (details: any) =>
        new Promise<any>(resolve => {
          listener(details, resolve)
        })
    }
  }

  test('injects the enforcing CSP on app-origin responses', async () => {
    const { session, emit } = fakeSession()
    applyDesktopCsp(session as any, { devServer: DEV_SERVER })

    const result = await emit({ url: 'file:///opt/app/dist/index.html', responseHeaders: { 'X-Test': ['1'] } })
    const policy = result.responseHeaders['Content-Security-Policy'][0]

    assert.ok(policy.startsWith('script-src '))
    assert.ok(!policy.includes('https:'))
    assert.deepEqual(result.responseHeaders['X-Test'], ['1'])
  })

  test('leaves cross-origin embed responses untouched', async () => {
    const { session, emit } = fakeSession()
    applyDesktopCsp(session as any, { devServer: DEV_SERVER })

    const headers = { 'content-type': ['text/html'] }
    const result = await emit({ url: 'https://www.youtube.com/embed/x', responseHeaders: headers })

    assert.equal(result.responseHeaders, headers)
    assert.ok(!('Content-Security-Policy' in result.responseHeaders))
  })
})
