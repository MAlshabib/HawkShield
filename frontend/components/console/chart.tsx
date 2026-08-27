"use client"

/**
 * Recharts, re-cut for paper.
 *
 * The dark console drew charts the way a console draws them: a full grid, an
 * axis line on every edge, a filled gradient under the area, and a tooltip that
 * was a small dark box. On paper every one of those is ink spent on furniture
 * rather than on data, and the gradient in particular is the single most
 * generated-looking thing a chart can wear.
 *
 * So: no axis lines, no tick marks, gridlines only across the value axis and
 * only at the 8% hairline, a flat low-opacity fill instead of a gradient, and a
 * tooltip that is a real paper card built from the system's own tokens rather
 * than an inline style object. Series colour comes from `lib/colors.ts` — the
 * one part of the palette that cannot be theme-split, because recharts consumes
 * it as a literal.
 *
 * The whole thing is themed through custom properties, so a chart re-themes
 * with the page instead of freezing at whatever the palette was on mount.
 */
import * as React from "react"
import { ResponsiveContainer } from "recharts"

import type { Direction } from "@/lib/i18n"

/**
 * Tick styling for both axes. Mono, at the eyebrow's size, in secondary ink —
 * an axis label is a caption for the data, never a peer of it.
 */
export const paperTick = {
  fill: "var(--color-ink-2)",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
} as const

/** Every axis in the system: no rule, no tick marks, just the labels. */
export const paperAxis = {
  tickLine: false as const,
  axisLine: false as const,
  tick: paperTick,
}

/** The 8% hairline, and only ever across one axis. */
export const paperGrid = {
  stroke: "var(--color-rule)",
  strokeDasharray: "0",
} as const

/** The hover band. A tint of the accent, never a fill that hides the bar. */
export const paperCursor = {
  fill: "color-mix(in oklch, var(--color-accent) 10%, transparent)",
} as const

/**
 * Recharts draws into an SVG whose coordinate system does not mirror, and whose
 * `<text>` nodes inherit `direction` from CSS — so a tick reading `-64 dBm` or
 * `1,284` can be visually reordered inside an Arabic page while the data is
 * perfectly correct. Pinning the chart's subtree to LTR fixes that at the root;
 * the axes are then mirrored explicitly with `reversed` / `orientation`, which
 * is the part a reader actually wants flipped. The tooltip is a plain div in
 * this subtree, so it is handed its real direction back by `dir` on its own
 * content.
 */
export function ChartFrame({
  height,
  children,
}: {
  height: number
  children: React.ReactElement
}) {
  return (
    <div dir="ltr" style={{ blockSize: height }} className="w-full min-w-0">
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  )
}

/** What recharts injects into a `content` renderer, narrowed to what we read. */
export type TooltipInjected = {
  active?: boolean
  label?: unknown
  payload?: ReadonlyArray<{ value?: unknown; payload?: unknown }>
}

/**
 * The tooltip as a paper card: the same surface, hairline and radius as a
 * `Panel`, one elevation step up because it floats. The figure goes through
 * `hs-num` so it cannot reorder, and the caption is handed back the reader's
 * own direction — the card is prose sitting inside an LTR-pinned SVG frame.
 */
export function PaperTooltip({
  dir,
  caption,
  unit,
  value,
  swatch,
}: {
  dir: Direction
  /** The bucket this reading belongs to — an hour, a date, a class name. */
  caption: React.ReactNode
  /** What the figure counts. */
  unit: React.ReactNode
  /** Already formatted by the caller's locale formatter. */
  value: React.ReactNode
  /** Class colour, when the series carries a class identity. */
  swatch?: string
}) {
  return (
    <div
      dir={dir}
      className="bg-paper-1 border-rule-soft hs-float pointer-events-none flex flex-col gap-1 rounded-md border px-3 py-2"
    >
      <span className="flex items-center gap-2">
        {swatch && (
          <span
            aria-hidden="true"
            className="size-2 shrink-0 rounded-full"
            style={{ background: swatch }}
          />
        )}
        <span className="hs-label">{caption}</span>
      </span>
      <span className="flex items-baseline gap-1.5">
        <span className="hs-num text-ink-0 text-sm font-medium">{value}</span>
        <span className="text-ink-2 text-xs">{unit}</span>
      </span>
    </div>
  )
}
