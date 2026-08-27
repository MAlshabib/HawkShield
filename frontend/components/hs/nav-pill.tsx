"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * N5 · Floating pill nav.
 *
 * A rounded, content-sized bar that floats clear of the page edges with a
 * blurred backdrop. It is the one sanctioned use of `backdrop-filter` in this
 * system — glass is banned as a *card* style, but a pill that has to sit over
 * scrolling content and stay legible is the case the effect was invented for.
 *
 * The pill must stay content-sized. A "pill" at 95% of the viewport is just a
 * full-width nav with rounded ends, which defeats the point; `max-w` caps it
 * and the link row drops out below `md` rather than being allowed to stretch
 * it. Everything positional is a logical property, so the whole bar mirrors
 * under RTL without a single `[dir="rtl"]` override — centring is done with
 * `inset-inline: 0` plus `margin-inline: auto` rather than the usual
 * `left: 50%; translateX(-50%)`, which would push the pill off-screen in
 * Arabic.
 *
 * Every string is a prop. This component contains no user-facing copy.
 */

export interface NavPillLink {
  href: string
  label: React.ReactNode
  /** Marks `aria-current="page"`. */
  active?: boolean
}

export interface NavPillProps extends React.ComponentPropsWithoutRef<"nav"> {
  /** Accessible name for the landmark. Required — pages have several navs. */
  label: string
  /** Mark + wordmark. Wrap it in the router's `Link` at the call site. */
  brand: React.ReactNode
  links?: readonly NavPillLink[]
  /**
   * Renders each link. The router owns navigation, not this component, so the
   * consumer supplies the element; the default is a plain anchor for the
   * `/design` sheet and anywhere else without a router.
   */
  renderLink?: (link: NavPillLink, className: string) => React.ReactNode
  /** Inline-end slot: the locale + theme controls, a menu trigger. */
  actions?: React.ReactNode
  /** The one filled control. Keep the label to two words — it must not wrap. */
  cta?: React.ReactNode
}

const linkClass = cn(
  "rounded-full px-3.5 py-2 text-sm font-medium whitespace-nowrap",
  "text-ink-1 transition-colors",
  "hover:bg-paper-2 hover:text-ink-0",
  "aria-[current=page]:bg-paper-2 aria-[current=page]:text-ink-0"
)

const NavPill = React.forwardRef<HTMLElement, NavPillProps>(function NavPill(
  { label, brand, links = [], renderLink, actions, cta, className, ...props },
  ref
) {
  const render =
    renderLink ??
    ((link: NavPillLink, cls: string) => (
      <a href={link.href} aria-current={link.active ? "page" : undefined} className={cls}>
        {link.label}
      </a>
    ))

  return (
    <nav
      ref={ref}
      data-slot="nav-pill"
      aria-label={label}
      className={cn(
        // `start-0 end-0` + `mx-auto` is the direction-agnostic centring. The
        // usual `left-1/2 -translate-x-1/2` would throw the pill off-screen the
        // moment the document flips to RTL.
        "fixed top-4 start-0 end-0 z-50 mx-auto w-fit max-w-[calc(100%-1.5rem)]",
        "border-rule-soft hs-float flex items-center gap-1.5 rounded-full border",
        "bg-[color-mix(in_oklch,var(--color-paper-0)_82%,transparent)] py-1.5 ps-4 pe-1.5",
        "[backdrop-filter:blur(18px)_saturate(130%)] [-webkit-backdrop-filter:blur(18px)_saturate(130%)]",
        className
      )}
      {...props}
    >
      {/* `line-height: 1` on the brand row: without it the mark and the
          wordmark inherit the body's 1.6 and the pill grows a few px taller
          than its own padding, which reads as a misaligned bar. */}
      <div className="me-1 flex shrink-0 items-center gap-2 leading-none">{brand}</div>

      {links.length > 0 && (
        <ul className="hidden items-center gap-0.5 md:flex">
          {links.map((link) => (
            <li key={link.href}>{render(link, linkClass)}</li>
          ))}
        </ul>
      )}

      {(actions || cta) && (
        <div className="ms-1 flex shrink-0 items-center gap-1.5">
          {actions}
          {cta}
        </div>
      )}
    </nav>
  )
})

export { NavPill, linkClass as navPillLinkClass }
