"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The tracked-uppercase strip that runs under the hero.
 *
 * A single horizontal loop, in one place on the site. It exists because the
 * hero is otherwise entirely static, and a page about a *live* sensor that
 * shows no movement at all reads as a screenshot.
 *
 * Three things make it not-annoying:
 *  · It is `aria-hidden`. Nothing here is information — the same words appear
 *    as real content elsewhere — so it is removed from the accessibility tree
 *    rather than read out on a loop.
 *  · The track is duplicated in the DOM and translated exactly -50%, so the
 *    seam is invisible. Any other distance shows a visible jump each cycle.
 *  · Under `prefers-reduced-motion: reduce` it stops dead (`globals.css`) and
 *    the first copy stays legible standing still.
 *
 * The animation is CSS. There is no rAF loop, no library, and nothing to tick:
 * the deploy target is a Raspberry Pi 4 and this must cost the compositor a
 * transform and nothing else.
 */

export interface MarqueeProps extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  /** Phrases, in order. Kept short — this is a strip, not a sentence. */
  items: readonly string[]
  /** Seconds for one full pass. Longer for more items, or it reads as a blur. */
  duration?: number
}

const Marquee = React.forwardRef<HTMLDivElement, MarqueeProps>(function Marquee(
  { items, duration = 42, className, ...props },
  ref
) {
  // Two copies, so translating the track -50% lands copy 2 exactly where copy 1
  // began. `React.Children`-style keys are safe here: the array is static copy.
  const run = [...items, ...items]

  return (
    <div
      ref={ref}
      data-slot="marquee"
      aria-hidden="true"
      className={cn("hs-marquee border-rule border-y py-3.5", className)}
      {...props}
    >
      <div
        className="hs-marquee__track flex items-center"
        style={{ animationDuration: `${duration}s` }}
      >
        {run.map((item, index) => (
          <span
            key={`${item}-${index}`}
            className="hs-label text-ink-2 flex items-center gap-6 pe-6 whitespace-nowrap"
          >
            {item}
            {/* Punctuation, not an icon and not an emoji. It is the separator
                between phrases and carries the one drop of accent on the strip. */}
            <span className="text-accent">✦</span>
          </span>
        ))}
      </div>
    </div>
  )
})

export { Marquee }
