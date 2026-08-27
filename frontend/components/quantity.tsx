"use client"

/**
 * A figure with its unit — isolating the figure, and only the figure.
 *
 * The dashboard's idiom wraps the whole run in `hs-num`:
 *
 *     <span className="hs-num">{f.number(freq)} {t("units.mhz")}</span>
 *
 * which is right for `5180 MHz`, because `hs-num` pins the run to LTR and both
 * halves are Latin. It is wrong the moment the unit is an Arabic word, and it
 * fails twice over:
 *
 * 1. **Direction.** `hs-num` sets `direction: ltr`, so `86 بايت` is laid out
 *    left-to-right. An Arabic reader scans right-to-left and therefore meets
 *    `بايت` before `86` — "bytes 86", the mirror image of the bug the isolation
 *    was added to prevent.
 * 2. **Font.** `hs-num` also switches to IBM Plex Mono, which carries no Arabic
 *    coverage. The word fell through to a system fallback and lost its cursive
 *    joins, rendering as `بـايـت` — the same failure `globals.css` documents for
 *    `.hs-label` under `[lang="ar"]`.
 *
 * Isolating only the numeral fixes both and is correct for a Latin unit too: in
 * an RTL paragraph the figure lands on the right and the unit to its left, which
 * reads as `-57 dBm` in Arabic reading order; in LTR it is plainly `-57 dBm`.
 * The unit keeps the body font and the ambient direction, which is all it ever
 * wanted.
 */
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function Quantity({
  value,
  unit,
  className,
}: {
  /** The already-formatted figure. Locale formatting belongs to the caller. */
  value: ReactNode
  /** The unit, in whichever script the dictionary gives it. */
  unit: ReactNode
  className?: string
}) {
  return (
    <span className={cn("whitespace-nowrap", className)}>
      <span className="hs-num">{value}</span> {unit}
    </span>
  )
}
