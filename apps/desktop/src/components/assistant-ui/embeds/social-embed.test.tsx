import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { EmbedDescriptor } from './providers/types'
import SocialEmbedRenderer from './social-embed'
import { UrlEmbed } from './url-embed'

const desktopWindow = window as unknown as { hermesDesktop?: Window['hermesDesktop'] }
const initialHermesDesktop = desktopWindow.hermesDesktop

// The provider script origins SEC-AUDIT-005 forbids in the privileged renderer.
const FORBIDDEN_SCRIPT_HOSTS = ['instagram.com', 'tiktok.com', 'platform.twitter.com', 'twitter.com']

const TWEET: EmbedDescriptor = {
  id: 'twitter:1',
  label: 'X',
  maxWidth: 480,
  provider: 'twitter',
  renderer: 'tweet',
  sourceUrl: 'https://x.com/nous/status/1',
  tweetId: '1'
}

const INSTAGRAM: EmbedDescriptor = {
  embedUrl: 'https://www.instagram.com/p/abc/embed',
  height: 450,
  id: 'instagram:abc',
  label: 'Instagram',
  maxWidth: 400,
  provider: 'instagram',
  renderer: 'frame',
  sourceUrl: 'https://www.instagram.com/p/abc/'
}

function remoteScriptCount(): number {
  return [...window.document.querySelectorAll('script[src]')].filter(script =>
    FORBIDDEN_SCRIPT_HOSTS.some(host => (script.getAttribute('src') ?? '').includes(host))
  ).length
}

beforeEach(() => {
  desktopWindow.hermesDesktop = {
    fetchLinkTitle: vi.fn().mockResolvedValue(''),
    openExternal: vi.fn().mockResolvedValue(undefined)
  } as unknown as Window['hermesDesktop']
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()

  if (initialHermesDesktop) {
    desktopWindow.hermesDesktop = initialHermesDesktop
  } else {
    delete desktopWindow.hermesDesktop
  }
})

describe('inert social embeds', () => {
  it('renders an X post as a static link and appends no remote script', () => {
    render(<SocialEmbedRenderer descriptor={TWEET} />)

    const link = screen.getByRole('link')
    expect(link.getAttribute('href')).toBe(TWEET.sourceUrl)
    expect(link.textContent).toContain('X')
    expect(remoteScriptCount()).toBe(0)
  })

  it('renders an Instagram post as a static link and appends no remote script', () => {
    render(<SocialEmbedRenderer descriptor={INSTAGRAM} />)

    const link = screen.getByRole('link')
    expect(link.getAttribute('href')).toBe(INSTAGRAM.sourceUrl)
    expect(remoteScriptCount()).toBe(0)
  })

  // The whole point of the fix: even a legacy "always allow"/global-always
  // grant must not resurrect the same-document provider script.
  it('stays inert through UrlEmbed even when embeds are globally auto-loaded', async () => {
    const { $embedMode } = await import('@/store/embed-consent')
    $embedMode.set('always')

    try {
      render(<UrlEmbed descriptor={TWEET} />)

      // LazyRenderer resolves the inert card asynchronously (React.lazy).
      const link = await screen.findByRole('link')
      expect(link.getAttribute('href')).toBe(TWEET.sourceUrl)
      expect(remoteScriptCount()).toBe(0)
    } finally {
      $embedMode.set('ask')
    }
  })

  it('never appends a script even when a provider is on the always-allow list', async () => {
    const { $embedAllowed } = await import('@/store/embed-consent')
    $embedAllowed.set(['instagram'])

    try {
      render(<UrlEmbed descriptor={INSTAGRAM} />)

      expect(remoteScriptCount()).toBe(0)
    } finally {
      $embedAllowed.set([])
    }
  })
})
