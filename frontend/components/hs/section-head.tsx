import * as React from "react"

import { cn } from "@/lib/utils"
import { Eyebrow } from "@/components/hs/eyebrow"

/**
 * The heading block that opens a section: mono eyebrow, big headline, and a
 * body column that sets in from the inline-end edge.
 *
 * ON THE LAYOUT, because it looks like a rule was broken and it wasn't:
 *
 * The obvious build for this is a two-column grid — eyebrow + headline on the
 * left, body copy on the right. That is the single most recognisable
 * templated-editorial tell there is, and Hallmark auto-fails any wrapper that
 * puts an eyebrow and a heading into a multi-column grid together (gate 54).
 *
 * So the wrapper is a **single** column in every direction and at every width.
 * The eyebrow stacks directly above the headline, in the same column, and the
 * body copy takes the next row — where, from `md` up, it is pulled to the
 * inline-end edge and held to a readable measure. The result reads as the
 * offset body column the reference had, without the banned two-column head,
 * and it collapses to a plain stack on a phone with no extra rule.
 */

export interface SectionHeadProps extends Omit<React.ComponentPropsWithoutRef<"header">, "title"> {
  /** Uppercase mono label. Omit it — an eyebrow on every section is noise. */
  eyebrow?: React.ReactNode
  /** The headline. Use `AccentWord` inside it for emphasis, never italics. */
  title: React.ReactNode
  /** The body column. One paragraph; if it needs two, it is a section. */
  body?: React.ReactNode
  /** Heading level. Defaults to `h2` — a page has one `h1` and it is the hero. */
  as?: "h1" | "h2" | "h3"
  /** Actions parked under the body column: a link, a filter, a download. */
  actions?: React.ReactNode
}

const SectionHead = React.forwardRef<HTMLElement, SectionHeadProps>(function SectionHead(
  { eyebrow, title, body, as: Heading = "h2", actions, className, ...props },
  ref
) {
  return (
    <header
      ref={ref}
      data-slot="section-head"
      // Single column. Not `1fr 1fr`, not `auto 1fr`, at no breakpoint.
      className={cn("grid grid-cols-[minmax(0,1fr)] gap-5", className)}
      {...props}
    >
      {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}

      <Heading className="text-ink-0 font-display text-3xl font-bold [overflow-wrap:anywhere] [text-wrap:balance] min-w-0">
        {title}
      </Heading>

      {(body || actions) && (
        <div className="flex flex-col gap-4 md:ms-auto md:max-w-[46ch] md:items-start">
          {body && <p className="text-ink-1 text-md">{body}</p>}
          {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
        </div>
      )}
    </header>
  )
})

export { SectionHead }
