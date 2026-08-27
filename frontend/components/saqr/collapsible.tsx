"use client"

/**
 * The one disclosure idiom on this page.
 *
 * A step opens, and an archived run's work opens, and both have to behave
 * identically or the page teaches two different gestures for the same thing.
 * This is the shared half: the region that grows and shrinks. Each call site
 * owns its own trigger, because a step's trigger is a whole summary row —
 * number, tool, verdict chips, duration — and an archived run's is a word.
 *
 * Three decisions, each of which is a bug if made the other way:
 *
 * **`grid-template-rows` from `0fr` to `1fr`, not `height`.** The content's
 * height is not known until it is laid out, and `height: auto` does not
 * animate. The alternative is measuring in JavaScript on every stream frame,
 * which is both slower and wrong the moment a result table reflows. This
 * transitions to a content-derived height with no measurement at all, and the
 * surrounding document never jumps to a final size on the first frame.
 *
 * **React state, not a native `<details>`.** `<details>` does not render its
 * content while closed, so there is nothing to animate open; and the SQL block
 * inside a step has to survive the document re-rendering on every animation
 * frame while tokens stream, which it does here because the row is keyed
 * `(step, call_id)` and is never remounted. The keyboard behaviour `<details>`
 * would have given for free is reproduced at the trigger instead: a real
 * `<button>` with `aria-expanded` and `aria-controls`, which is the pattern
 * assistive technology announces most clearly anyway.
 *
 * **`inert` while closed.** The content stays in the DOM so it can animate, and
 * that is exactly how a collapsed disclosure becomes eleven invisible tab stops
 * and a screen reader reading out a table nobody opened. `inert` removes the
 * subtree from the tab order and from the accessibility tree without touching
 * layout, so the animation survives and the collapsed row is one stop.
 *
 * Under `prefers-reduced-motion: reduce` the transition is dropped and the
 * region resolves instantly to its complete state, which is the test every
 * motion in this system has to pass.
 */
import * as React from "react"

import { cn } from "@/lib/utils"

export function CollapsibleRegion({
  id,
  open,
  children,
  className,
  innerClassName,
}: {
  /** Must match the trigger's `aria-controls`. */
  id: string
  open: boolean
  children: React.ReactNode
  className?: string
  /** Applied to the padded inner box, so a caller can add its own rule/indent. */
  innerClassName?: string
}) {
  return (
    <div
      id={id}
      inert={!open}
      className={cn(
        "grid transition-[grid-template-rows] duration-200 ease-out",
        "motion-reduce:transition-none",
        open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
        className
      )}
    >
      {/* `min-h-0` is what lets the grid row actually shrink below the content's
          intrinsic height; without it the row refuses to go to zero and the
          disclosure simply never closes. */}
      <div className="min-h-0 overflow-hidden">
        <div className={cn("min-w-0", innerClassName)}>{children}</div>
      </div>
    </div>
  )
}
