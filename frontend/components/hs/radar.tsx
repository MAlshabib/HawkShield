import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The live-status indicator: a conic wedge sweeping a ring, 4s per revolution.
 *
 * This is the only ambient loop in the product, and it is load-bearing rather
 * than decorative — it is the answer to "is the sensor still listening?", which
 * is the one question an operator asks without being asked to. It must only be
 * mounted with `active` when a capture really is running; a sweep over a dead
 * sensor is a lie the UI tells continuously.
 *
 * When the sweep is stopped the ring stays, so the component never collapses
 * and shifts the layout around it.
 */

export interface RadarProps extends Omit<React.ComponentPropsWithoutRef<"span">, "children"> {
  /** Diameter in px. Reads down to 10px; below that the wedge is invisible. */
  size?: number
  /** Whether the sensor is live. `false` freezes the ring with no wedge. */
  active?: boolean
  /**
   * Accessible name for the state. Required — the indicator is not decoration,
   * and the copy is caller-owned so it can be localised.
   */
  label: string
}

const Radar = React.forwardRef<HTMLSpanElement, RadarProps>(function Radar(
  { size = 14, active = true, label, className, style, ...props },
  ref
) {
  return (
    <span
      ref={ref}
      data-slot="radar"
      data-active={active || undefined}
      role="img"
      aria-label={label}
      className={cn(
        "relative inline-grid shrink-0 place-items-center rounded-full border align-middle",
        active
          ? "border-[color-mix(in_oklab,var(--hs-azure)_45%,transparent)]"
          : "border-hairline-strong",
        className
      )}
      style={{ inlineSize: size, blockSize: size, ...style }}
      {...props}
    >
      {active && <span aria-hidden="true" className="hs-radar absolute inset-0" />}
      {/* The hub. Solid azure while live, hollow ink-faint when not, so the
          state survives a monochrome print and reduced-motion alike. */}
      <span
        aria-hidden="true"
        className={cn(
          "relative rounded-full",
          active ? "bg-hs-azure" : "bg-ink-faint"
        )}
        style={{ inlineSize: Math.max(2, Math.round(size * 0.25)), blockSize: Math.max(2, Math.round(size * 0.25)) }}
      />
    </span>
  )
})

export { Radar }
