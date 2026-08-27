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
      {/* Two rasters, not one raster plus a filter.
       *
       * The head is drawn in #01285A, which sits almost on top of the dark
       * theme's own paper — on a dark navbar the bird disappears and only the
       * arcs survive. An outline welded around the shape would be a fifth
       * colour the mark does not contain, and a CSS `invert()` would swing the
       * azure arcs to orange. So the dark surface gets a recoloured copy of the
       * same artwork: the head lifted to the dark theme's ink, the arcs lifted
       * one step so the two parts keep their relationship. Nothing is redrawn.
       *
       * Both are rendered and one is hidden, rather than swapped on a theme
       * value, so the correct mark is present in the very first paint — a
       * swap that waits for React would flash the wrong one on every load. */}
      <Image
        src="/hawkshield-mark.png"
        width={size}
        height={size}
        alt={decorative ? "" : alt}
        aria-hidden={decorative || undefined}
        priority={size >= 64}
        className="block h-full w-full object-contain dark:hidden"
      />
      <Image
        src="/hawkshield-mark-dark.png"
        width={size}
        height={size}
        alt=""
        aria-hidden
        priority={size >= 64}
        className="hidden h-full w-full object-contain dark:block"
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
