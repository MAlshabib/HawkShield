import * as React from "react"

import type { Severity } from "@/lib/colors"
import { cn } from "@/lib/utils"

/**
 * Severity / state pill.
 *
 * `rounded-full` is the one place in the system where a full radius is allowed:
 * a pill is a token, not a container, and the shape is what separates it from
 * the table cell it sits in. Everything else keeps 0-2px.
 *
 * `neutral` exists because the absence of a finding is not a green light —
 * HawkShield detects and classifies, it does not certify a network clean.
 */

export type PillTone = Severity | "neutral"

export interface StatusPillProps extends React.ComponentPropsWithoutRef<"span"> {
  tone?: PillTone
  /** `quiet` tints; `solid` fills. Solid is for the one pill that must win a row. */
  variant?: "quiet" | "solid"
  /** Leading state dot. Off by default — most pills already carry a word. */
  dot?: boolean
}

/**
 * Tints are `color-mix` against the live severity token rather than baked hexes,
 * so a pill re-themes with its subtree instead of needing a dark: twin.
 */
const quietTone: Record<PillTone, string> = {
  critical:
    "text-sev-critical border-[color-mix(in_oklab,var(--sev-critical)_38%,transparent)] bg-[color-mix(in_oklab,var(--sev-critical)_12%,transparent)]",
  high: "text-sev-high border-[color-mix(in_oklab,var(--sev-high)_38%,transparent)] bg-[color-mix(in_oklab,var(--sev-high)_12%,transparent)]",
  info: "text-sev-info border-[color-mix(in_oklab,var(--sev-info)_38%,transparent)] bg-[color-mix(in_oklab,var(--sev-info)_12%,transparent)]",
  neutral: "text-ink-dim border-hairline-strong bg-surface-sunken",
}

/** `--on-*` carries the readable foreground for each fill; see `globals.css`. */
const solidTone: Record<PillTone, string> = {
  critical: "border-transparent bg-sev-critical text-[var(--on-critical)]",
  high: "border-transparent bg-sev-high text-[var(--on-high)]",
  info: "border-transparent bg-sev-info text-[var(--on-info)]",
  neutral: "border-transparent bg-ink-dim text-[var(--on-neutral)]",
}

const StatusPill = React.forwardRef<HTMLSpanElement, StatusPillProps>(function StatusPill(
  { tone = "neutral", variant = "quiet", dot = false, className, children, ...props },
  ref
) {
  return (
    <span
      ref={ref}
      data-slot="status-pill"
      data-tone={tone}
      className={cn(
        "hs-label inline-flex w-fit shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 whitespace-nowrap",
        variant === "solid" ? solidTone[tone] : quietTone[tone],
        className
      )}
      {...props}
    >
      {dot && (
        <span
          aria-hidden="true"
          className="size-1.5 shrink-0 rounded-full bg-current"
        />
      )}
      {children}
    </span>
  )
})

export { StatusPill }
