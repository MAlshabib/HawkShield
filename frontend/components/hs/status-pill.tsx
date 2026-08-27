import * as React from "react"

import type { Severity } from "@/lib/colors"
import { cn } from "@/lib/utils"

/**
 * Severity / state pill.
 *
 * On paper, everything is already softly rounded, so the pill can no longer
 * rely on its radius alone to separate itself from the cell it sits in. It
 * earns the distinction with a tint plus a same-hue hairline instead — the tint
 * is the grade, the border keeps it legible on a tinted panel.
 *
 * `neutral` exists because the absence of a finding is not a green light.
 * HawkShield detects and classifies; it does not certify a network clean.
 * There is deliberately no success tone in this component.
 */

export type PillTone = Severity | "neutral"

export interface StatusPillProps extends React.ComponentPropsWithoutRef<"span"> {
  tone?: PillTone
  /** `quiet` tints; `solid` fills. Solid is for the one pill that must win a row. */
  variant?: "quiet" | "solid"
  /** Leading state dot. Off by default — most pills already carry a word. */
  dot?: boolean
  /** Pulse the dot. Only when the state it names is genuinely live. */
  live?: boolean
}

/**
 * Tints are `color-mix` against the live severity token rather than baked
 * values, so a pill re-themes with its subtree instead of needing a `dark:`
 * twin. The mix percentages are higher than they were on the dark substrate:
 * a 12% tint that read clearly on graphite is invisible on paper.
 */
const quietTone: Record<PillTone, string> = {
  critical:
    "text-sev-critical border-[color-mix(in_oklch,var(--sev-critical)_32%,transparent)] bg-[color-mix(in_oklch,var(--sev-critical)_14%,transparent)]",
  high: "text-sev-high border-[color-mix(in_oklch,var(--sev-high)_32%,transparent)] bg-[color-mix(in_oklch,var(--sev-high)_14%,transparent)]",
  info: "text-sev-info border-[color-mix(in_oklch,var(--sev-info)_32%,transparent)] bg-[color-mix(in_oklch,var(--sev-info)_12%,transparent)]",
  neutral: "text-ink-2 border-rule-soft bg-paper-2",
}

/** `--on-*` carries the readable foreground for each fill; see `globals.css`. */
const solidTone: Record<PillTone, string> = {
  critical: "border-transparent bg-sev-critical text-[color:var(--on-critical)]",
  high: "border-transparent bg-sev-high text-[color:var(--on-high)]",
  info: "border-transparent bg-sev-info text-[color:var(--on-info)]",
  neutral: "border-transparent bg-ink-2 text-[color:var(--on-neutral)]",
}

const StatusPill = React.forwardRef<HTMLSpanElement, StatusPillProps>(function StatusPill(
  { tone = "neutral", variant = "quiet", dot = false, live = false, className, children, ...props },
  ref
) {
  const showDot = dot || live

  return (
    <span
      ref={ref}
      data-slot="status-pill"
      data-tone={tone}
      className={cn(
        "hs-label inline-flex w-fit shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 whitespace-nowrap",
        variant === "solid" ? solidTone[tone] : quietTone[tone],
        className
      )}
      {...props}
    >
      {showDot && (
        <span
          aria-hidden="true"
          className={cn("size-1.5 shrink-0 rounded-full bg-current", live && "hs-live-dot")}
        />
      )}
      {children}
    </span>
  )
})

export { StatusPill }
