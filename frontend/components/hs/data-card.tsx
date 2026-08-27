import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The hero object: one real reading from the sensor, printed like a slip.
 *
 * This is the piece of the page that has to convince a judge in four seconds
 * that something is actually running. It does that by being *specific* — named
 * rows, right-aligned figures in the mono face, a total set large in the
 * display face, and a thin bar that shows how the total splits by severity.
 *
 * Every value is a prop. The component holds no numbers, no labels and no
 * copy, which is the only way to guarantee it can never show something the
 * sensor did not report. Where it is used with sample values — the `/design`
 * style sheet — the caller is required to say so on the card itself.
 *
 * It is *not* a re-drawn window. There is no title bar, no traffic lights, no
 * fake chrome: it is a card with a header rule, the same one `Panel` uses.
 */

/* -------------------------------------------------------------------------- */
/* Card                                                                       */
/* -------------------------------------------------------------------------- */

export interface DataCardProps extends Omit<React.ComponentPropsWithoutRef<"aside">, "title"> {
  /** Mono identifier for the reading — an interface name, a capture id. */
  label?: React.ReactNode
  /** Human subject line: which sensor, which window. */
  title?: React.ReactNode
  /** Inline-end header slot. Usually a `StatusPill` or a live `Eyebrow`. */
  status?: React.ReactNode
}

const DataCard = React.forwardRef<HTMLElement, DataCardProps>(function DataCard(
  { label, title, status, className, children, ...props },
  ref
) {
  return (
    <aside
      ref={ref}
      data-slot="data-card"
      className={cn(
        "bg-paper-0 border-rule-soft hs-float flex min-w-0 flex-col rounded-xl border p-5",
        className
      )}
      {...props}
    >
      {(label || title || status) && (
        <header className="border-rule flex items-start gap-3 border-b pb-3">
          <div className="flex min-w-0 flex-col gap-1">
            {label && <span className="hs-num text-ink-0 text-sm font-medium">{label}</span>}
            {title && <span className="text-ink-2 truncate text-xs">{title}</span>}
          </div>
          {status && <div className="ms-auto shrink-0">{status}</div>}
        </header>
      )}
      {children}
    </aside>
  )
})

/* -------------------------------------------------------------------------- */
/* Rows                                                                       */
/* -------------------------------------------------------------------------- */

const DataCardRows = React.forwardRef<HTMLDListElement, React.ComponentPropsWithoutRef<"dl">>(
  function DataCardRows({ className, ...props }, ref) {
    return (
      <dl
        ref={ref}
        data-slot="data-card-rows"
        className={cn("flex flex-col gap-2.5 py-3.5", className)}
        {...props}
      />
    )
  }
)

export type DataCardRowTone = "default" | "accent" | "critical" | "companion"

export interface DataCardRowProps extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  label: React.ReactNode
  value: React.ReactNode
  tone?: DataCardRowTone
}

const rowToneClass: Record<DataCardRowTone, string> = {
  default: "text-ink-0",
  accent: "text-accent-cta",
  critical: "text-critical",
  companion: "text-companion-ink",
}

/**
 * A label / figure pair. The figure is `text-end`, which is inline-end and so
 * lands on the correct side under RTL; the figure itself is pinned LTR by
 * `.hs-num` because a MAC or a signed dBm reading reverses otherwise.
 */
const DataCardRow = React.forwardRef<HTMLDivElement, DataCardRowProps>(function DataCardRow(
  { label, value, tone = "default", className, ...props },
  ref
) {
  return (
    <div
      ref={ref}
      data-slot="data-card-row"
      data-tone={tone}
      className={cn("flex items-baseline justify-between gap-4 text-sm", className)}
      {...props}
    >
      <dt className="text-ink-2 min-w-0 truncate">{label}</dt>
      <dd className={cn("hs-num shrink-0 text-end font-medium", rowToneClass[tone])}>{value}</dd>
    </div>
  )
})

/* -------------------------------------------------------------------------- */
/* Total                                                                      */
/* -------------------------------------------------------------------------- */

export interface DataCardTotalProps
  extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  label: React.ReactNode
  value: React.ReactNode
  /** Trailing unit, set small and dim beside the figure. */
  unit?: React.ReactNode
}

/**
 * The one big number on the card. Set in the display face rather than the mono
 * one — at this size the mono's fixed advance widths read as a spreadsheet, and
 * this figure is a headline.
 */
const DataCardTotal = React.forwardRef<HTMLDivElement, DataCardTotalProps>(
  function DataCardTotal({ label, value, unit, className, ...props }, ref) {
    return (
      <div
        ref={ref}
        data-slot="data-card-total"
        className={cn(
          "border-rule flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t pt-3.5",
          className
        )}
        {...props}
      >
        <span className="text-ink-2 text-sm">{label}</span>
        <span className="flex items-baseline gap-1.5">
          <span className="font-display text-ink-0 text-2xl leading-none font-bold tabular-nums">
            {value}
          </span>
          {unit && <span className="hs-label text-ink-2">{unit}</span>}
        </span>
      </div>
    )
  }
)

/* -------------------------------------------------------------------------- */
/* Severity bar                                                               */
/* -------------------------------------------------------------------------- */

export interface DataCardBarSegment {
  /** Accessible name for the segment — required, this is not decoration. */
  label: string
  /** Share of the whole, in the same unit as its siblings. */
  value: number
  /** Any CSS colour. Pass a class token via `attackColorVar()`. */
  color: string
}

export interface DataCardBarProps
  extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  segments: readonly DataCardBarSegment[]
  /** Accessible summary of the whole bar. */
  label: string
}

/**
 * A thin stacked bar: how the total splits by severity.
 *
 * Widths are percentages of the summed values, so the caller passes counts and
 * never has to compute a ratio. A zero-valued segment is dropped rather than
 * rendered at 0% — a 0px sliver between two others reads as a hairline and
 * makes the bar look broken. Segments are ordered by the caller; the canonical
 * order is most-severe-first, matching `attackTypes`.
 */
const DataCardBar = React.forwardRef<HTMLDivElement, DataCardBarProps>(function DataCardBar(
  { segments, label, className, ...props },
  ref
) {
  const shown = segments.filter((s) => s.value > 0)
  const total = shown.reduce((sum, s) => sum + s.value, 0)

  return (
    <div
      ref={ref}
      data-slot="data-card-bar"
      role="img"
      aria-label={label}
      className={cn("bg-paper-2 mt-4 flex h-1.5 gap-px overflow-hidden rounded-full", className)}
      {...props}
    >
      {total > 0 &&
        shown.map((segment) => (
          <span
            key={segment.label}
            className="block h-full first:rounded-s-full last:rounded-e-full"
            style={{ inlineSize: `${(segment.value / total) * 100}%`, background: segment.color }}
          />
        ))}
    </div>
  )
})

/* -------------------------------------------------------------------------- */
/* Note                                                                       */
/* -------------------------------------------------------------------------- */

/** The mono footnote under the bar. Scale, window, or a sampling caveat. */
const DataCardNote = React.forwardRef<HTMLParagraphElement, React.ComponentPropsWithoutRef<"p">>(
  function DataCardNote({ className, ...props }, ref) {
    return (
      <p
        ref={ref}
        data-slot="data-card-note"
        className={cn("hs-label mt-2.5 leading-relaxed", className)}
        {...props}
      />
    )
  }
)

export { DataCard, DataCardRows, DataCardRow, DataCardTotal, DataCardBar, DataCardNote }
