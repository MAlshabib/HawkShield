import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * A field is a slot cut into the surface, so it sits on `--surface-sunken` with
 * a square corner — the inverse of a Module, which is lifted with a 2px radius.
 * That inversion is the whole affordance; there is no inner shadow doing it.
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
        "bg-surface-sunken border-hairline-strong text-ink placeholder:text-ink-faint flex h-8 w-full min-w-0 rounded-sm border px-2.5 py-1 text-sm transition-colors",
        "selection:bg-[color-mix(in_oklab,var(--hs-azure)_30%,transparent)]",
        "hover:border-ink-faint",
        "file:text-ink file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-xs file:font-medium",
        "disabled:cursor-not-allowed disabled:opacity-45",
        "aria-invalid:border-destructive",
        className
      )}
      {...props}
    />
  )
}

export { Input }
