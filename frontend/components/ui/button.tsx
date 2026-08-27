import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * Controls are instrument controls: 2px radius, hairline borders, and heights
 * one step tighter than stock shadcn so a toolbar sits on the 8pt grid rather
 * than dominating the module it belongs to.
 *
 * No component defines its own focus ring. `globals.css` owns a single
 * `:focus-visible` outline for the whole app, so `outline-none` is deliberately
 * absent here — adding it back would silently remove keyboard focus.
 *
 * Hover states mix toward `--ink` rather than using a fixed tint, so the same
 * class reads as "stronger" in both themes without a `dark:` twin.
 */
const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md border font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-45 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground border-transparent hover:bg-[color-mix(in_oklab,var(--primary)_88%,var(--ink))]",
        destructive:
          "bg-destructive text-destructive-foreground border-transparent hover:bg-[color-mix(in_oklab,var(--destructive)_88%,var(--ink))]",
        outline:
          "border-hairline-strong text-ink hover:bg-surface-raised bg-transparent",
        secondary:
          "bg-surface-sunken border-hairline text-ink hover:bg-surface-raised",
        ghost:
          "text-ink-dim hover:bg-surface-raised hover:text-ink border-transparent bg-transparent",
        link: "text-hs-azure border-transparent bg-transparent underline-offset-4 hover:underline",
      },
      size: {
        default: "h-8 px-3 text-sm",
        sm: "h-7 gap-1 px-2.5 text-xs",
        lg: "h-9 px-4 text-sm",
        icon: "size-8",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : "button"

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
