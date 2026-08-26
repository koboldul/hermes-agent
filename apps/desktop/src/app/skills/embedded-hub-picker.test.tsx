import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { map } from 'nanostores'
import { afterEach, describe, expect, it, vi } from 'vitest'

const proposeHubSkill = vi.fn((..._args: unknown[]) => Promise.resolve<Record<string, unknown>>({}))
const activateHubSkill = vi.fn((..._args: unknown[]) => Promise.resolve())
const notify = vi.fn((..._args: unknown[]) => {})
const notifyError = vi.fn((..._args: unknown[]) => {})

// Real atom so the component's useStoreSelector subscription works; the actions
// are stubbed so we can assert whether/when propose/activate are triggered.
vi.mock('@/store/hub-actions', () => ({
  $hubActions: map<Record<string, unknown>>({}),
  UPDATE_ALL_KEY: '__update_all__',
  activateHubSkill: (...args: unknown[]) => activateHubSkill(...args),
  proposeHubSkill: (...args: unknown[]) => proposeHubSkill(...args),
  updateHubSkills: vi.fn()
}))

vi.mock('@/store/notifications', () => ({
  notify: (...args: unknown[]) => notify(...args),
  notifyError: (...args: unknown[]) => notifyError(...args)
}))

import { EmbeddedHubPicker } from './embedded-hub-picker'

const HUB_ORIGIN = 'https://hermes-agent.nousresearch.com'
const COMMIT = 'a'.repeat(40)
const DIGEST = 'b'.repeat(64)

// The server-resolved proposal the propose RPC returns.
const RESOLVED = {
  proposal_id: 'prop-1',
  identifier: 'official/weather',
  name: 'Weather',
  source: 'official',
  commit: COMMIT,
  digest: DIGEST,
  policy: 'allow',
  policy_reason: 'allow'
}

function renderPicker() {
  return render(<EmbeddedHubPicker installedNames={new Set()} />)
}

function post(source: unknown, origin: string, data: unknown) {
  fireEvent(window, new MessageEvent('message', { source: source as Window, origin, data }))
}

const PICK = { type: 'hermes-skill-pick', name: 'Weather', identifier: 'official/weather', source: 'official' }

afterEach(() => {
  vi.clearAllMocks()
  cleanup()
})

describe('EmbeddedHubPicker — A4 propose → confirm → activate', () => {
  it('resolves a valid pick on the server (propose), never auto-installs', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)

    await waitFor(() => expect(proposeHubSkill).toHaveBeenCalledWith('official/weather', undefined))
    await screen.findByTestId('hub-install-confirm')
    expect(activateHubSkill).not.toHaveBeenCalled()
  })

  it('shows the server-resolved commit AND digest in the confirm dialog', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)

    await screen.findByTestId('hub-install-confirm')
    expect(screen.getByText(new RegExp(COMMIT))).toBeTruthy()
    expect(screen.getByTestId('hub-confirm-digest').textContent).toContain(DIGEST)
  })

  it('activates only after confirm, echoing the exact resolved proposal', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)
    await screen.findByTestId('hub-install-confirm')

    fireEvent.click(screen.getByRole('button', { name: 'Install skill' }))

    await waitFor(() => expect(activateHubSkill).toHaveBeenCalledTimes(1))
    expect(activateHubSkill).toHaveBeenCalledWith(RESOLVED, undefined)
  })

  it('cancel dismisses the resolved proposal without activating', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)
    await screen.findByTestId('hub-install-confirm')

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.queryByTestId('hub-install-confirm')).toBeNull())
    expect(activateHubSkill).not.toHaveBeenCalled()
  })

  it('ignores a message from a WRONG source window (malicious auto-post)', async () => {
    renderPicker()

    // A different window object posting the same payload with the right origin.
    post({ name: 'evil' } as unknown, HUB_ORIGIN, PICK)

    await new Promise(resolve => setTimeout(resolve, 20))
    expect(proposeHubSkill).not.toHaveBeenCalled()
    expect(screen.queryByTestId('hub-install-confirm')).toBeNull()
  })

  it('ignores a message from a WRONG origin', async () => {
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, 'https://evil.example', PICK)

    await new Promise(resolve => setTimeout(resolve, 20))
    expect(proposeHubSkill).not.toHaveBeenCalled()
    expect(screen.queryByTestId('hub-install-confirm')).toBeNull()
  })

  it('fails closed on server COMMIT drift: error surfaced, dialog closed, not installed', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    activateHubSkill.mockRejectedValueOnce(new Error('commit-drift'))
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)
    await screen.findByTestId('hub-install-confirm')
    fireEvent.click(screen.getByRole('button', { name: 'Install skill' }))

    await waitFor(() => expect(notifyError).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByTestId('hub-install-confirm')).toBeNull())
    expect(activateHubSkill).toHaveBeenCalledTimes(1)
  })

  it('fails closed on server DIGEST drift', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    activateHubSkill.mockRejectedValueOnce(new Error('digest-drift'))
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)
    await screen.findByTestId('hub-install-confirm')
    fireEvent.click(screen.getByRole('button', { name: 'Install skill' }))

    await waitFor(() => expect(notifyError).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByTestId('hub-install-confirm')).toBeNull())
  })

  it('fails closed on server REPLAY (consumed proposal)', async () => {
    proposeHubSkill.mockResolvedValueOnce(RESOLVED)
    activateHubSkill.mockRejectedValueOnce(new Error('replay'))
    renderPicker()
    const iframe = screen.getByTitle('Skills Hub') as HTMLIFrameElement

    post(iframe.contentWindow, HUB_ORIGIN, PICK)
    await screen.findByTestId('hub-install-confirm')
    fireEvent.click(screen.getByRole('button', { name: 'Install skill' }))

    await waitFor(() => expect(notifyError).toHaveBeenCalled())
    expect(activateHubSkill).toHaveBeenCalledTimes(1)
  })

  it('ignores a DIFFERENT iframe window even with the right origin', async () => {
    proposeHubSkill.mockResolvedValue(RESOLVED)
    renderPicker()

    // A separate window object (e.g. a nested/sibling frame) is not the hub
    // iframe.contentWindow, so it is rejected before any propose.
    const otherWindow = {} as Window
    post(otherWindow, HUB_ORIGIN, PICK)

    await new Promise(resolve => setTimeout(resolve, 20))
    expect(proposeHubSkill).not.toHaveBeenCalled()
    expect(screen.queryByTestId('hub-install-confirm')).toBeNull()
  })
})
