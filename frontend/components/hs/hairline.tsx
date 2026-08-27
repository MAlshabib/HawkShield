import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * A rule, optionally carrying a label.
 *
 * Falcon Paper builds structure from two rule weights and nothing else, so a
 * labelled rule is how a long column gets sectioned without introducing a
 * second nested panel. The rule continues past the label on both sides, which
 * is what makes the label read as sitting *on* the line rather than as a
 * heading that happens to have a line next to it.
 *
 * Retained from V2 rather than replaced: `app/(app)/page.tsx` and
 * `components/threats/detection-drawer.tsx` both still import it, and both are
 * owned by other engineers. Only the tokens changed.
 */

export interface HairlineProps extends React.ComponentPropsWithoutRef<"div"> {
  /** Uppercase mono micro-label, centred on the rule by default. */
  label?: React.ReactNode
  orientation?: "horizontal" | "vertical"
  /** Where the label sits along the rule. Ignored when vertical. */
  align?: "start" | "center"
  /** Emphasise the rule — use once per screen at most. */
  strong?: boolean
}

const Hairline = React.forwardRef<HTMLDivElement, HairlineProps>(function Hairline(
  { label, orientation = "horizontal", align = "start", strong = false, className, ...props },
  ref
) {
  const line = strong ? "bg-rule-soft" : "bg-rule"

  if (orientation === "vertical") {
    return (
      <div
        ref={ref}
        data-slot="hairline"
        role="separator"
        aria-orientation="vertical"
        className={cn("w-px self-stretch", line, className)}
        {...props}
      />
    )
  }

  if (!label) {
    return (
      <div
        ref={ref}
        data-slot="hairline"
        role="separator"
        className={cn("h-px w-full", line, className)}
        {...props}
      />
    )
  }

  return (
    <div
      ref={ref}
      data-slot="hairline"
      role="separator"
      aria-label={typeof label === "string" ? label : undefined}
      className={cn("flex w-full items-center gap-2", className)}
      {...props}
    >
      {align === "center" && <span className={cn("h-px flex-1", line)} aria-hidden="true" />}
      <span className="hs-label shrink-0">{label}</span>
      <span className={cn("h-px flex-1", line)} aria-hidden="true" />
    </div>
  )
})

export { Hairline }
