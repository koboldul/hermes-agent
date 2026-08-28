import { describe, expect, it } from 'vitest'

import { evaluateHubMessage } from './hub-proposal'

const ORIGIN = 'https://hermes-agent.nousresearch.com'
// A stand-in for iframe.contentWindow — identity comparison is what matters.
const IFRAME_WINDOW = { name: 'hub-iframe' } as unknown

const ctx = { expectedOrigin: ORIGIN, expectedSource: IFRAME_WINDOW }

function pick(overrides: Record<string, unknown> = {}) {
  return {
    type: 'hermes-skill-pick',
    name: 'Weather',
    identifier: 'official/weather',
    source: 'official',
    ...overrides
  }
}

describe('evaluateHubMessage (A4 XPIA)', () => {
  it('accepts a well-formed pick from the exact window + origin', () => {
    const proposal = evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: pick() }, ctx)

    expect(proposal).toEqual({
      identifier: 'official/weather',
      name: 'Weather',
      source: 'official',
      installCmd: ''
    })
  })

  // A malicious page auto-posting the message from a DIFFERENT window must be
  // ignored even though it uses the right origin string.
  it('rejects a message from the wrong source window (malicious auto-post)', () => {
    const evil = { name: 'evil-window' } as unknown
    expect(evaluateHubMessage({ origin: ORIGIN, source: evil, data: pick() }, ctx)).toBeNull()
  })

  it('rejects a null / missing source window', () => {
    expect(
      evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: pick() }, { ...ctx, expectedSource: null })
    ).toBeNull()
    expect(evaluateHubMessage({ origin: ORIGIN, source: null, data: pick() }, ctx)).toBeNull()
  })

  it('rejects a wrong / spoofed origin', () => {
    expect(evaluateHubMessage({ origin: 'https://evil.example', source: IFRAME_WINDOW, data: pick() }, ctx)).toBeNull()
    // Even a look-alike subdomain is not the exact origin.
    expect(
      evaluateHubMessage(
        { origin: 'https://hermes-agent.nousresearch.com.evil.example', source: IFRAME_WINDOW, data: pick() },
        ctx
      )
    ).toBeNull()
  })

  it('rejects a wrong message type or malformed payload', () => {
    expect(evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: pick({ type: 'other' }) }, ctx)).toBeNull()
    expect(evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: pick({ name: '' }) }, ctx)).toBeNull()
    expect(evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: null }, ctx)).toBeNull()
    expect(evaluateHubMessage({ origin: ORIGIN, source: IFRAME_WINDOW, data: 'string' }, ctx)).toBeNull()
  })

  it('falls back to the name as identifier when none is supplied', () => {
    const proposal = evaluateHubMessage(
      { origin: ORIGIN, source: IFRAME_WINDOW, data: pick({ identifier: '   ' }) },
      ctx
    )

    expect(proposal?.identifier).toBe('Weather')
  })
})
