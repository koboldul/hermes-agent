'use client'

import { resolveBrandIcon } from '@/lib/brand-icon'
import { ExternalLink } from '@/lib/external-link'

import type { EmbedDescriptor } from './providers/types'

// SECURITY (SEC-AUDIT-005): this renderer is INERT. It must never inject a
// third-party <script>, touch innerHTML, or make a provider network request.
//
// Instagram and X/Twitter ship no cross-origin iframe embed — only a mutable
// widget script (instagram.com/embed.js, platform.twitter.com/widgets.js).
// Running that script in THIS document would hand a compromised provider CDN
// the renderer's `window.hermesDesktop` bridge (files, terminal, clipboard,
// gateway). So the Desktop app degrades these to a static, self-hosted link
// card. There is deliberately no "load the real embed" path here: an
// interactive embed is a follow-up that must live in a bridge-less guest
// webContents, not in the privileged application renderer.

function hostLabel(descriptor: EmbedDescriptor): string {
  // x.com posts frequently arrive as twitter.com links — show the current brand.
  if (descriptor.provider === 'twitter') {
    return 'x.com'
  }

  try {
    return new URL(descriptor.sourceUrl).hostname.replace(/^www\./, '')
  } catch {
    return descriptor.label
  }
}

export default function SocialEmbedRenderer({ descriptor }: { descriptor: EmbedDescriptor }) {
  const Icon = resolveBrandIcon(hostLabel(descriptor))

  return (
    <ExternalLink
      className="my-0 flex w-full items-center gap-3 rounded-lg border border-(--ui-stroke-tertiary) bg-(--ui-bg-quinary)/30 px-3 py-2.5 no-underline transition-colors hover:bg-(--ui-bg-quinary)/60"
      href={descriptor.sourceUrl}
    >
      {Icon ? (
        <Icon aria-hidden className="size-5 shrink-0 opacity-80" title="" />
      ) : (
        <span aria-hidden className="size-5 shrink-0" />
      )}
      <span className="flex min-w-0 flex-col">
        <span className="text-sm font-medium text-(--ui-text-primary)">View this post on {descriptor.label}</span>
        <span className="truncate text-[0.6875rem] text-(--ui-text-tertiary)">{hostLabel(descriptor)}</span>
      </span>
    </ExternalLink>
  )
}
