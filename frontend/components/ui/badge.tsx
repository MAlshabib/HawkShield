import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * A square-cornered tag, set in the mono micro-label.
 *
 * Deliberately distinct from `components/hs/status-pill`: a Badge names a thing
 * (a class, an interface, a build), a StatusPill grades one. The radius is what
 * tells them apart at a glance — square labels, round grades — so a Badge must
 * never take `rounded-full`.
 */
const badgeVariants = cva(
  "hs-label inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-sm border px-1.5 py-0.5 whitespace-nowrap transition-colors [&>svg]:pointer-events-none [&>svg]:size-3 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default:
          "bg-surface-sunken border-hairline-strong text-ink",
        secondary: "bg-transparent border-hairline text-ink-dim",
        destructive:
          "border-[color-mix(in_oklab,var(--sev-critical)_38%,transparent)] bg-[color-mix(in_oklab,var(--sev-critical)_12%,transparent)] text-sev-critical",
        outline: "text-ink border-hairline-strong bg-transparent",
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
