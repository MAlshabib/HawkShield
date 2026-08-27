import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * A field is a slip of paper laid on the card: `--color-paper-0` inside a
 * `--color-paper-1` panel, edged with the heavier of the two rules. The lift is
 * the whole affordance — there is no inner shadow and no filled well doing it.
 *
 * Focus comes from the global `:focus-visible` outline, so no ring is declared
 * here and `outline-none` is deliberately absent.
 */
function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "bg-paper-0 border-rule-soft text-ink-0 placeholder:text-ink-3 flex h-10 w-full min-w-0 rounded-md border px-3.5 py-2 text-sm transition-colors",
        "selection:bg-[color-mix(in_oklch,var(--color-accent)_28%,transparent)]",
        "hover:border-ink-3 focus:border-accent",
        "file:text-ink-0 file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-xs file:font-medium",
        "disabled:cursor-not-allowed disabled:opacity-45",
        "aria-invalid:border-destructive",
        className
      )}
      {...props}
    />
  )
}

export { Input }
