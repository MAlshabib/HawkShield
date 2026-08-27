import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The repeating container of the whole UI: a hairline card on paper.
 *
 * Replaces the old `Module`. The difference is not cosmetic — a Module was a
 * 2px-cornered rectangle on a dark substrate whose header strip was the only
 * thing separating it from its neighbours. A Panel is a piece of paper: soft
 * radius, one hairline edge, a single shadow step that resolves to nothing in
 * dark, and a header rule that stops short of being a title bar.
 *
 * There is still no coloured left border, no nested card and no second shadow
 * tier. Nine of these have to sit on one screen without the page turning into
 * confetti, and the only reason that works is that they are all identical.
 */

// `title` is overridden deliberately: a panel's title is rendered content, not
// the browser's tooltip attribute of the same name.
export interface PanelProps extends Omit<React.ComponentPropsWithoutRef<"section">, "title"> {
  /** Uppercase mono micro-label. The panel's permanent identity. */
  label?: React.ReactNode
  /** Secondary line in ink, for a subject that changes (an SSID, a date range). */
  title?: React.ReactNode
  /** Inline-end header slot: filters, a menu, a live indicator. */
  actions?: React.ReactNode
  /**
   * Drop the body padding so a table can sit flush to the hairline. Tables
   * carry their own cell rhythm and double padding reads as a misalignment.
   */
  flush?: boolean
  /** Paint the loading scan over the body. Content stays mounted underneath. */
  loading?: boolean
  /**
   * `plain` is the default card. `sunken` drops to the page paper for a panel
   * that holds other panels — the one nesting case the system allows, and only
   * because it is a *container*, not a card inside a card.
   */
  surface?: "plain" | "sunken"
}

const Panel = React.forwardRef<HTMLElement, PanelProps>(function Panel(
  {
    label,
    title,
    actions,
    flush = false,
    loading = false,
    surface = "plain",
    className,
    children,
    ...props
  },
  ref
) {
  const hasHeader = Boolean(label || title || actions)

  return (
    <section
      ref={ref}
      data-slot="panel"
      data-loading={loading || undefined}
      className={cn(
        "border-rule-soft flex min-w-0 flex-col rounded-lg border",
        surface === "plain" ? "bg-paper-1 hs-elev" : "bg-paper-0",
        className
      )}
      {...props}
    >
      {hasHeader && (
        <header
          data-slot="panel-header"
          className="border-rule flex min-h-12 items-center gap-3 border-b px-4 py-3"
        >
          {/* The label stacks ABOVE the title, in one column. An eyebrow set
              beside a heading on the same row is the templated-editorial tell
              this system will not emit — not in a section head, and not here. */}
          <div className="flex min-w-0 flex-col gap-1">
            {label && <span className="hs-label">{label}</span>}
            {title && (
              <h3 className="text-ink-0 truncate text-base leading-tight font-medium">{title}</h3>
            )}
          </div>
          {actions && <div className="ms-auto flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}

      <div
        data-slot="panel-body"
        className={cn("min-w-0 flex-1", !flush && "p-4", loading && "hs-scan")}
      >
        {children}
      </div>
    </section>
  )
})

/**
 * A run of panels on the 4pt grid. Kept here rather than in each page so the
 * gutter between them is defined once — an inconsistent gutter is the fastest
 * way to make a grid look assembled rather than built.
 *
 * Every track is `minmax(0, 1fr)` by convention at the call site: a bare `1fr`
 * resolves its minimum to the widest content, which on a panel holding a wide
 * table or an image pushes the whole grid past a phone viewport.
 */
const PanelGrid = React.forwardRef<HTMLDivElement, React.ComponentPropsWithoutRef<"div">>(
  function PanelGrid({ className, ...props }, ref) {
    return (
      <div
        ref={ref}
        data-slot="panel-grid"
        className={cn("grid gap-3 sm:gap-4", className)}
        {...props}
      />
    )
  }
)

export { Panel, PanelGrid }
