import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { $resolveLinkMetadata } from '@/store/link-metadata'

import { Favicon } from './favicon'

const desktopWindow = window as unknown as { hermesDesktop?: Window['hermesDesktop'] }
const initialHermesDesktop = desktopWindow.hermesDesktop

function installBridge(resolveFavicon: ReturnType<typeof vi.fn>) {
  desktopWindow.hermesDesktop = {
    resolveFavicon: resolveFavicon as unknown as Window['hermesDesktop']['resolveFavicon']
  } as unknown as Window['hermesDesktop']
}

afterEach(() => {
  $resolveLinkMetadata.set(false)
  vi.restoreAllMocks()
  cleanup()

  if (initialHermesDesktop) {
    desktopWindow.hermesDesktop = initialHermesDesktop
  } else {
    delete desktopWindow.hermesDesktop
  }
})

describe('Favicon opt-in', () => {
  // SEC-AUDIT-003: rendering a remote favicon candidate performs no network
  // request under the secure default; the local fallback shows instead.
  it('makes no request and shows the fallback when link previews are off', async () => {
    const resolveFavicon = vi.fn().mockResolvedValue('data:image/png;base64,AAAA')
    installBridge(resolveFavicon)

    render(<Favicon fallback={<span data-testid="fallback">FB</span>} url="https://off.example/page" />)

    expect(screen.getByTestId('fallback')).toBeTruthy()
    await Promise.resolve()
    expect(resolveFavicon).not.toHaveBeenCalled()
  })

  it('resolves a validated data URL once when the user opts in', async () => {
    $resolveLinkMetadata.set(true)
    const resolveFavicon = vi.fn().mockResolvedValue('data:image/png;base64,BBBB')
    installBridge(resolveFavicon)

    render(<Favicon fallback={<span data-testid="fallback">FB</span>} url="https://on.example/page" />)

    await waitFor(() => expect(resolveFavicon).toHaveBeenCalledTimes(1))
    await waitFor(() => {
      const img = window.document.querySelector('img')
      expect(img?.getAttribute('src')).toBe('data:image/png;base64,BBBB')
    })
  })

  it('keeps the fallback when opted-in resolution returns no icon', async () => {
    $resolveLinkMetadata.set(true)
    const resolveFavicon = vi.fn().mockResolvedValue('')
    installBridge(resolveFavicon)

    render(<Favicon fallback={<span data-testid="fallback">FB</span>} url="https://empty.example/page" />)

    await waitFor(() => expect(resolveFavicon).toHaveBeenCalledTimes(1))
    expect(screen.getByTestId('fallback')).toBeTruthy()
    expect(window.document.querySelector('img')).toBeNull()
  })
})
