import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The live-capture indicator.
 *
 * V2 drew this as a conic wedge sweeping a ring, four seconds a revolution —
 * a radar scope, which is exactly the tactical-console register Falcon Paper
 * was built to get away from. The device it answers ("is the sensor still
 * listening?") is real, so it stays; the drawing does not. It is now the same
 * pulsing hub the rest of the system uses for liveness, inside a quiet ring,
 * so a live badge in a table and a live dot on the hero read as one idea.
 *
 * It must only be mounted with `active` when a capture really is running. A
 * pulse over a dead sensor is a lie the UI tells continuously.
 *
 * When stopped, the ring stays and the hub goes hollow, so the component never
 * collapses and shifts the layout around it — and the state survives both a
 * monochrome print and `prefers-reduced-motion`, where the pulse freezes at its
 * widest legible halo rather than disappearing.
 *
 * Retained from V2 rather than replaced: `app/(app)/dashboard`, `app/(app)/page`
 * and `app/(app)/threats` all still import it, and those pages belong to other
 * engineers.
 */

export interface RadarProps extends Omit<React.ComponentPropsWithoutRef<"span">, "children"> {
  /** Diameter in px. Reads down to 10px. */
  size?: number
  /** Whether the sensor is live. `false` freezes the ring with a hollow hub. */
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
  const hub = Math.max(3, Math.round(size * 0.38))

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
          ? "border-[color-mix(in_oklch,var(--color-accent)_45%,transparent)]"
          : "border-rule-soft",
        className
      )}
      style={{ inlineSize: size, blockSize: size, ...style }}
      {...props}
    >
      <span
        aria-hidden="true"
        className={cn(
          "rounded-full",
          active ? "bg-accent text-accent hs-live-dot" : "bg-ink-3"
        )}
        style={{ inlineSize: hub, blockSize: hub }}
      />
    </span>
  )
})

export { Radar }
