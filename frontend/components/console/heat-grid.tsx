"use client"

/**
 * Detections by day and hour — a quiet tinted grid.
 *
 * The console version of this was a glowing one: every cell carried a saturated
 * azure fill and the busiest ones lit up. On a dark substrate that is legible;
 * on paper it is a bruise. Here a cell is a piece of paper that has been tinted,
 * the tint tops out well short of the full accent, and an *empty* hour is drawn
 * as an empty cell with a hairline rather than as a filled dark square — so the
 * eye reads "nothing happened here" instead of "something did".
 *
 * The hour ruler is labelled every third hour. Twenty-four mono labels over a
 * grid this fine is more ink in the axis than in the data, and the unlabelled
 * columns are still countable from the ones that are.
 *
 * At 320px the grid keeps its cell size and scrolls **inside its own box**. A
 * heatmap that reflows to fit a phone stops being a heatmap; a page that scrolls
 * sideways because of one module is a bug.
 */
import * as React from "react"

import { cn } from "@/lib/utils"

export type HeatRow = { day: string; hours: { hour: number; intensity: number }[] }

const HOURS = Array.from({ length: 24 }, (_, hour) => hour)

/**
 * Tint strength for a cell, as a percentage of the accent.
 *
 * Floors at 14% for any non-zero hour so a single detection is still visible,
 * and ceilings at 66% so the busiest cell reads as tinted paper rather than as
 * a painted swatch. `Math.sqrt` opens up the bottom of the range: real capture
 * data is heavily skewed, and a linear ramp renders every quiet hour identically
 * pale against one saturated peak.
 */
function tintFor(ratio: number): string {
  const pct = 14 + Math.sqrt(Math.max(0, Math.min(1, ratio))) * 52
  return `color-mix(in oklch, var(--color-accent) ${pct.toFixed(1)}%, transparent)`
}

export function HeatGrid({
  rows,
  max,
  dayLabel,
  cellLabel,
  axisLabel,
  scrollHint,
}: {
  rows: readonly HeatRow[]
  /** The busiest cell in the window. Zero means nothing was detected at all. */
  max: number
  dayLabel: (day: string) => string
  cellLabel: (day: string, hour: number, n: number) => string
  /** Mono label over the day column — "Day × Hour". */
  axisLabel: string
  /** Shown under the grid only where the grid cannot fit; see the note above. */
  scrollHint: string
}) {
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="min-w-0 overflow-x-auto px-4 pt-4">
        <div
          role="img"
          aria-label={axisLabel}
          className="grid min-w-[40rem] grid-cols-[3rem_repeat(24,minmax(0,1fr))] gap-[3px]"
        >
          {/* The corner stays empty. "Day × Hour" wrapped to two lines in a 48px
              cell and said nothing the panel title had not already said. */}
          <span aria-hidden="true" />
          {HOURS.map((hour) => (
            <span
              key={`ruler-${hour}`}
              aria-hidden="true"
              className="hs-num text-ink-2 pb-1 text-center text-[0.625rem] leading-none"
            >
              {hour % 3 === 0 ? String(hour).padStart(2, "0") : ""}
            </span>
          ))}

          {rows.map((row) => (
            <React.Fragment key={row.day}>
              <span className="text-ink-1 self-center truncate pe-2 text-xs">
                {dayLabel(row.day)}
              </span>
              {row.hours.map((cell) => {
                const n = cell.intensity ?? 0
                const ratio = max > 0 ? n / max : 0
                return (
                  <span
                    key={`${row.day}-${cell.hour}`}
                    title={cellLabel(row.day, cell.hour, n)}
                    className={cn(
                      "h-5 rounded-xs border",
                      n > 0 ? "border-transparent" : "border-rule"
                    )}
                    style={n > 0 ? { background: tintFor(ratio) } : undefined}
                  />
                )
              })}
            </React.Fragment>
          ))}
        </div>
      </div>

      <p className="text-ink-2 px-4 pb-4 text-xs sm:hidden">{scrollHint}</p>
    </div>
  )
}

/**
 * The density key, as five discrete swatches rather than a `linear-gradient`.
 *
 * A gradient's direction keyword is physical (`to right`), so it would have to
 * be flipped by hand under RTL; a flex row of swatches mirrors itself for free
 * and stays honest about the fact that the scale is read in five steps.
 */
export function HeatLegend({ low, high }: { low: string; high: string }) {
  return (
    <div className="hidden items-center gap-1.5 sm:flex">
      <span className="hs-label">{low}</span>
      {[0, 0.25, 0.5, 0.75, 1].map((step) => (
        <span
          key={step}
          aria-hidden="true"
          className={cn("size-2.5 rounded-xs border", step === 0 ? "border-rule" : "border-transparent")}
          style={step === 0 ? undefined : { background: tintFor(step) }}
        />
      ))}
      <span className="hs-label">{high}</span>
    </div>
  )
}
