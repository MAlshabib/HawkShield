import * as React from "react"
import Image from "next/image"

import { cn } from "@/lib/utils"

/**
 * The HawkShield mark, flat.
 *
 * `/hawkshield-mark.png` rather than `/logo-neon.png`: the original raster
 * carries ~17% dead margin, which makes optical sizing at small sizes
 * unreliable. The mark ships with no filter stack — V1 wrapped it in three cyan
 * `drop-shadow`s, which overwrote the two brand colours the logo is actually
 * drawn in with a colour it does not contain.
 */

export interface LogoProps extends Omit<React.ComponentPropsWithoutRef<"span">, "children"> {
  /** Rendered edge length in px. The mark is square. */
  size?: number
  /**
   * Accessible name. The mark is a proper noun, so the default is not a
   * translatable string; pass one when the logo has a role in a sentence.
   * Set `decorative` instead when a `Wordmark` beside it already names it.
   */
  alt?: string
  /** Hide from the accessibility tree — use when adjacent text already names it. */
  decorative?: boolean
}

const Logo = React.forwardRef<HTMLSpanElement, LogoProps>(function Logo(
  { size = 32, alt = "HawkShield", decorative = false, className, style, ...props },
  ref
) {
  return (
    <span
      ref={ref}
      data-slot="logo"
      className={cn("inline-block shrink-0 align-middle", className)}
      style={{ inlineSize: size, blockSize: size, ...style }}
      {...props}
    >
      <Image
        src="/hawkshield-mark.png"
        width={size}
        height={size}
        alt={decorative ? "" : alt}
        aria-hidden={decorative || undefined}
        priority={size >= 64}
        className="block h-full w-full object-contain"
      />
    </span>
  )
})

export type WordmarkSize = "sm" | "md" | "lg"

/**
 * "HawkShield" set in the display face.
 *
 * V2 set this uppercase at 0.2-0.28em tracking, borrowed off the project
 * poster. Falcon Paper drops both: on paper, wide-tracked all-caps reads as a
 * defence-contractor letterhead, which is the exact register this system exists
 * to leave behind. The wordmark is now sentence-case at weight 700 with a
 * tight optical tracking — the same treatment every headline gets, which is
 * what makes the mark feel like it belongs to the page rather than sitting on
 * top of it.
 *
 * `split` paints "Shield" in azure, the way the poster splits it. Colour, not
 * spacing, now carries the identity.
 */
export interface WordmarkProps extends Omit<React.ComponentPropsWithoutRef<"span">, "children"> {
  size?: WordmarkSize
  /** Paint "Shield" in azure, as the poster splits it. */
  split?: boolean
}

const wordmarkSizes: Record<WordmarkSize, string> = {
  sm: "text-base tracking-[-0.02em]",
  md: "text-xl tracking-[-0.025em]",
  lg: "text-3xl tracking-[-0.03em]",
}

const Wordmark = React.forwardRef<HTMLSpanElement, WordmarkProps>(function Wordmark(
  { size = "md", split = false, className, ...props },
  ref
) {
  return (
    <span
      ref={ref}
      data-slot="wordmark"
      // Always LTR: the wordmark is a logotype, and a logotype does not reorder
      // under RTL even though the page around it does.
      dir="ltr"
      className={cn(
        "font-display inline-block leading-none font-bold whitespace-nowrap",
        wordmarkSizes[size],
        className
      )}
      {...props}
    >
      Hawk
      <span className={cn(split && "text-accent")}>Shield</span>
    </span>
  )
})

export { Logo, Wordmark }
