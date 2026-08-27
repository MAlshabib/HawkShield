import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Ft5 · Statement footer.
 *
 * One large display sentence closes the page, with the wordmark, a short link
 * row and the legal line set small beneath it. Not a sitemap: the four-column
 * Product / Company / Resources / Legal grid is the most recognisable footer
 * fingerprint there is, and this product has five destinations, not forty.
 *
 * The statement is the page's last argument, so it says what HawkShield does
 * and — just as importantly — what it does not. The copy is a prop; the
 * component owns none of it, because it has to be translatable.
 */

export interface StatementFooterProps extends React.ComponentPropsWithoutRef<"footer"> {
  /** The closing sentence. Short. Use `AccentWord` for the emphasis. */
  statement: React.ReactNode
  /** Wordmark, or wordmark + mark. */
  brand?: React.ReactNode
  /** A handful of links, rendered by the caller so the router owns navigation. */
  links?: React.ReactNode
  /**
   * Accessible name for the link row. Required whenever `links` is passed —
   * the page already has a primary nav, and two unnamed `<nav>` landmarks are
   * indistinguishable to a screen-reader user. Caller-owned so it localises.
   */
  linksLabel?: string
  /** The legal / provenance line. Mono, dim, last. */
  meta?: React.ReactNode
}

const StatementFooter = React.forwardRef<HTMLElement, StatementFooterProps>(
  function StatementFooter(
    { statement, brand, links, linksLabel, meta, className, ...props },
    ref
  ) {
    return (
      <footer
        ref={ref}
        data-slot="statement-footer"
        className={cn("border-rule border-t pt-14 pb-10", className)}
        {...props}
      >
        <p
          className={cn(
            "font-display text-ink-0 text-4xl font-bold",
            // 26ch keeps the sentence to two or three lines at every width. A
            // statement that runs to five lines stops being a statement.
            "max-w-[26ch] min-w-0 [overflow-wrap:anywhere] [text-wrap:balance]"
          )}
        >
          {statement}
        </p>

        <div className="border-rule mt-12 flex flex-wrap items-center gap-x-6 gap-y-4 border-t pt-6">
          {brand && <div className="flex shrink-0 items-center gap-2 leading-none">{brand}</div>}
          {links && (
            <nav
              aria-label={linksLabel}
              className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm"
            >
              {links}
            </nav>
          )}
          {meta && <span className="hs-label ms-auto">{meta}</span>}
        </div>
      </footer>
    )
  }
)

export { StatementFooter }
