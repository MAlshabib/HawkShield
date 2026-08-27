import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The core repeating unit of the whole UI: a bounded panel with a dense header
 * strip.
 *
 * A module is a hairline rectangle on a lifted surface. There is no card
 * shadow, no rounded corner past 2px, and no coloured left border — structure
 * comes from the rule under the header and from the surface step, which is what
 * lets nine of these sit side by side without the screen turning into confetti.
 */

// `title` is overridden deliberately: the module's title is rendered content,
// not the browser's tooltip attribute of the same name.
export interface ModuleProps extends Omit<React.ComponentPropsWithoutRef<"section">, "title"> {
  /** Uppercase mono micro-label. The module's permanent identity. */
  label?: React.ReactNode
  /** Optional secondary line in ink, for a subject that changes (an SSID, a date range). */
  title?: React.ReactNode
  /** Right-aligned (inline-end) header slot: filters, a menu, a live indicator. */
  actions?: React.ReactNode
  /**
   * Drop the body padding so a table can sit flush against the hairline. Tables
   * carry their own cell rhythm and double padding reads as a misalignment.
   */
  flush?: boolean
  /** Paint the loading scan over the body. Content stays mounted underneath. */
  loading?: boolean
}

const Module = React.forwardRef<HTMLElement, ModuleProps>(function Module(
  { label, title, actions, flush = false, loading = false, className, children, ...props },
  ref
) {
  const hasHeader = Boolean(label || title || actions)

  return (
    <section
      ref={ref}
      data-slot="module"
      data-loading={loading || undefined}
      className={cn(
        "bg-surface border-hairline flex min-w-0 flex-col rounded-md border",
        className
      )}
      {...props}
    >
      {hasHeader && (
        <header
          data-slot="module-header"
          className="border-hairline flex min-h-9 items-center gap-3 border-b px-3 py-2"
        >
          <div className="flex min-w-0 items-baseline gap-2">
            {label && <span className="hs-label shrink-0">{label}</span>}
            {title && (
              <h3 className="text-ink truncate text-sm leading-none font-medium">{title}</h3>
            )}
          </div>
          {actions && (
            <div className="ms-auto flex shrink-0 items-center gap-1.5">{actions}</div>
          )}
        </header>
      )}

      <div
        data-slot="module-body"
        className={cn("min-w-0 flex-1", !flush && "p-3", loading && "hs-scan")}
      >
        {children}
      </div>
    </section>
  )
})

/**
 * A run of modules on the 8pt grid. Kept here rather than in each page so the
 * gutter between instruments is defined once — an inconsistent gutter is the
 * fastest way to make a panel grid look assembled rather than built.
 */
const ModuleGrid = React.forwardRef<HTMLDivElement, React.ComponentPropsWithoutRef<"div">>(
  function ModuleGrid({ className, ...props }, ref) {
    return (
      <div
        ref={ref}
        data-slot="module-grid"
        className={cn("grid gap-2 sm:gap-3", className)}
        {...props}
      />
    )
  }
)

export { Module, ModuleGrid }
