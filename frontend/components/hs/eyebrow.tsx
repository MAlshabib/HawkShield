import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The uppercase mono micro-label — the most repeated typographic move in the
 * system, and the thing that makes a section head, a table head and a data-card
 * row read as parts of one instrument.
 *
 * Two shapes. `bare` is the section eyebrow: type on the page, nothing around
 * it. `pill` is the bordered chip used where the label has to survive sitting
 * on a photograph or a tinted panel — the hero's live indicator, a status
 * marker on a data card.
 *
 * The live dot is the one ambient loop the product allows, and it is
 * load-bearing rather than decorative: it answers "is the sensor still
 * listening?" — the question an operator asks without being asked to. Passing
 * `live` over a surface that is not actually live makes the UI lie
 * continuously, so don't.
 *
 * Arabic: `globals.css` handles the script switch for `.hs-label` — the mono
 * face carries no Arabic at all and the wide tracking shatters the joins of a
 * cursive script, so an Arabic label falls to the body face at normal tracking.
 * Nothing is needed at the call site.
 */

export type EyebrowTone = "default" | "accent" | "critical" | "companion"

export interface EyebrowProps extends React.ComponentPropsWithoutRef<"span"> {
  variant?: "bare" | "pill"
  tone?: EyebrowTone
  /**
   * Show the pulsing state dot. Only pass this when the thing it labels is
   * genuinely live. Its colour follows `tone`, and the pulse halo is drawn from
   * `currentColor`, so no extra token is needed.
   */
  live?: boolean
  /** A static dot — same footprint as `live`, no animation. */
  dot?: boolean
}

const toneClass: Record<EyebrowTone, string> = {
  default: "text-ink-2",
  accent: "text-accent-cta",
  critical: "text-critical",
  companion: "text-companion-ink",
}

const Eyebrow = React.forwardRef<HTMLSpanElement, EyebrowProps>(function Eyebrow(
  { variant = "bare", tone = "default", live = false, dot = false, className, children, ...props },
  ref
) {
  const showDot = live || dot

  return (
    <span
      ref={ref}
      data-slot="eyebrow"
      data-tone={tone}
      className={cn(
        "hs-label inline-flex w-fit items-center gap-2",
        toneClass[tone],
        variant === "pill" &&
          "border-rule-soft bg-paper-1 rounded-full border py-1.5 ps-2.5 pe-3.5",
        className
      )}
      {...props}
    >
      {showDot && (
        <span
          aria-hidden="true"
          className={cn("size-2 shrink-0 rounded-full bg-current", live && "hs-live-dot")}
        />
      )}
      {children}
    </span>
  )
})

export { Eyebrow }
