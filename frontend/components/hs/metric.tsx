"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * A big-number readout: label, value, optional delta.
 *
 * The count-up is not ornament — it is how a number that changed announces that
 * it changed, in a UI with no toasts. It runs on `requestAnimationFrame` rather
 * than a motion library because this ships to a Pi 4B, and it starts from the
 * previous value (not zero) on subsequent updates, so a metric that ticks
 * 1,204 -> 1,205 does not perform a full re-count for a single event.
 */

export interface MetricProps extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  /** Uppercase mono micro-label. */
  label: React.ReactNode
  value: number
  /** Formatter for the displayed figure. Locale-aware formatting belongs here. */
  format?: (value: number) => string
  /** Trailing unit, set small and dim beside the figure. */
  unit?: React.ReactNode
  /**
   * Signed change against the previous period. Sign drives the arrow; the
   * caller decides whether a rise is good, since a rise in detections is not.
   */
  delta?: number
  /** Formatter for the delta. Defaults to the value formatter. */
  formatDelta?: (value: number) => string
  /** Context for the delta ("vs. last hour") — caller-owned so it can localise. */
  deltaLabel?: React.ReactNode
  /** Tint the figure with a severity token. Off by default; most metrics are neutral. */
  tone?: "neutral" | "critical" | "high" | "info"
  /** Disable the count-up for a figure that is not a running total. */
  animate?: boolean
  /** Anything that belongs under the figure — usually a `<Sparkline />`. */
  footer?: React.ReactNode
}

const toneClass: Record<NonNullable<MetricProps["tone"]>, string> = {
  neutral: "text-ink-0",
  critical: "text-sev-critical",
  high: "text-sev-high",
  info: "text-sev-info",
}

/** Read once per mount; the OS setting changing mid-session is not worth a listener. */
function usePrefersReducedMotion() {
  const [reduced, setReduced] = React.useState(true)
  React.useEffect(() => {
    setReduced(window.matchMedia("(prefers-reduced-motion: reduce)").matches)
  }, [])
  return reduced
}

/**
 * Eases the displayed figure toward `target`. Returns `target` verbatim under
 * reduced motion and on first paint, so the server-rendered markup and the
 * hydrated markup agree.
 */
function useCountUp(target: number, enabled: boolean, duration: number) {
  const reduced = usePrefersReducedMotion()
  const [display, setDisplay] = React.useState(target)
  const fromRef = React.useRef(target)

  React.useEffect(() => {
    if (!enabled || reduced || !Number.isFinite(target)) {
      fromRef.current = target
      setDisplay(target)
      return
    }

    const from = fromRef.current
    if (from === target) return

    const start = performance.now()
    let frame = 0

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      // Matches --ease-out (0.16, 1, 0.3, 1) closely enough at this scale.
      const eased = 1 - Math.pow(1 - t, 4)
      setDisplay(from + (target - from) * eased)
      if (t < 1) {
        frame = requestAnimationFrame(tick)
      } else {
        fromRef.current = target
      }
    }

    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target, enabled, reduced, duration])

  return display
}

const defaultFormat = (value: number) => Math.round(value).toLocaleString()

const Metric = React.forwardRef<HTMLDivElement, MetricProps>(function Metric(
  {
    label,
    value,
    format = defaultFormat,
    unit,
    delta,
    formatDelta,
    deltaLabel,
    tone = "neutral",
    animate = true,
    footer,
    className,
    ...props
  },
  ref
) {
  const shown = useCountUp(value, animate, 400)
  const deltaFormat = formatDelta ?? format
  const rising = typeof delta === "number" && delta > 0
  const falling = typeof delta === "number" && delta < 0

  return (
    <div
      ref={ref}
      data-slot="metric"
      className={cn("flex min-w-0 flex-col gap-2", className)}
      {...props}
    >
      <span className="hs-label">{label}</span>

      <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        {/* aria-live is deliberately absent: a dashboard of these would narrate
            continuously. The figure is polled, not announced. */}
        {/* Display face, not mono. The mono's fixed advance widths read as a
            spreadsheet at 34px+; `tabular-nums` alone gives the column
            alignment a running total needs, without the ledger texture. */}
        <span
          className={cn(
            "font-display text-3xl leading-none font-bold tabular-nums",
            toneClass[tone]
          )}
        >
          {format(shown)}
        </span>
        {unit && <span className="hs-label text-ink-2">{unit}</span>}
      </span>

      {typeof delta === "number" && (
        <span className="text-ink-2 flex items-baseline gap-1.5 text-xs">
          <span
            className="hs-num text-ink-1"
            // The glyph is direction, not language, so it is not a translated
            // string; it also needs no RTL flip because it points vertically.
            // It is left uncoloured on purpose: whether a rise is good depends
            // on the metric, and this component does not get to decide.
            aria-hidden="true"
          >
            {rising ? "▲" : falling ? "▼" : "—"}
          </span>
          <span className="hs-num">{deltaFormat(Math.abs(delta))}</span>
          {deltaLabel && <span className="truncate">{deltaLabel}</span>}
        </span>
      )}

      {footer && <div className="mt-1.5">{footer}</div>}
    </div>
  )
})

export { Metric }
