import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * The emphasis word inside a headline.
 *
 * The reference this system is cut from sets its emphasis word in an italic
 * serif. We cannot: Thmanyah Sans has no italic, Arabic script has no italics
 * at all so the device could not survive translation, and italic emphasis
 * inside an upright heading is one of the most reliable "generated" tells
 * there is. So the emphasis is carried by **weight and colour** instead —
 * black (900) azure against bold ink siblings.
 *
 * It exists as a primitive rather than a class so the device is identical
 * everywhere and cannot drift into a second, nearly-identical variant on the
 * next page someone writes.
 *
 * Scope: display type only — a headline, a section head, the footer statement.
 * The azure clears 3:1 against paper, which is the threshold for large text
 * and not the 4.5:1 body text needs. Setting an `AccentWord` at 16px would be
 * a contrast failure, so don't.
 */

export interface AccentWordProps extends React.ComponentPropsWithoutRef<"span"> {
  /**
   * Carry the emphasis in the amber companion instead of azure. One use only:
   * an accent word sitting on an azure-filled surface, where azure-on-azure
   * would vanish. Never two colours of emphasis in one headline.
   */
  tone?: "accent" | "companion"
}

const AccentWord = React.forwardRef<HTMLSpanElement, AccentWordProps>(function AccentWord(
  { tone = "accent", className, children, ...props },
  ref
) {
  return (
    <span
      ref={ref}
      data-slot="accent-word"
      data-tone={tone}
      className={cn(
        // `font-style: normal` is declared, not assumed: an ancestor `<em>` or
        // a stray global would otherwise reintroduce exactly the italic this
        // component exists to replace.
        "font-display font-black not-italic",
        tone === "accent" ? "text-accent" : "text-companion-ink",
        className
      )}
      {...props}
    >
      {children}
    </span>
  )
})

export { AccentWord }
