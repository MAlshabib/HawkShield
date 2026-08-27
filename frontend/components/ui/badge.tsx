import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * A square-cornered tag, set in the mono micro-label.
 *
 * Deliberately distinct from `components/hs/status-pill`: a Badge names a thing
 * (a class, an interface, a build), a StatusPill grades one. The radius is what
 * tells them apart at a glance — a soft-cornered label against a fully round
 * grade — so a Badge must never take `rounded-full`.
 */
const badgeVariants = cva(
  "hs-label inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-sm border px-2 py-1 whitespace-nowrap transition-colors [&>svg]:pointer-events-none [&>svg]:size-3 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default:
          "bg-paper-2 border-transparent text-ink-1",
        secondary: "bg-transparent border-rule-soft text-ink-2",
        destructive:
          "border-[color-mix(in_oklch,var(--sev-critical)_32%,transparent)] bg-[color-mix(in_oklch,var(--sev-critical)_14%,transparent)] text-sev-critical",
        outline: "text-ink-0 border-rule-soft bg-transparent",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span"

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  )
}

export { Badge, badgeVariants }
