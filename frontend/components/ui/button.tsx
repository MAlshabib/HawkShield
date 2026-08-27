import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * Buttons are pills.
 *
 * That is the whole rule, and it is what makes a toolbar in this system read as
 * paper stationery rather than as a control panel. There is no square button
 * anywhere; the only square things left are rules and table cells.
 *
 * `default` is the navy CTA — the mark's own colour, doing the mark's job.
 * That token *inverts* between themes (navy on paper in light, paper on ink in
 * dark), because navy on a near-black page is invisible; the variant does not
 * need to know, it just reads `--color-cta`.
 *
 * No component defines its own focus ring. `globals.css` owns a single
 * `:focus-visible` outline for the whole app, so `outline-none` is deliberately
 * absent here — adding it back would silently remove keyboard focus. That ring
 * also has no transition, by design: a keyboard user needs it the instant
 * focus lands, not 140ms later.
 *
 * All eight states are present: default, hover, `:focus-visible` (global),
 * `:active`, `:disabled`, plus `aria-busy` (loading), `aria-invalid` (error)
 * and `data-state="success"`.
 */
const buttonVariants = cva(
  cn(
    "inline-flex shrink-0 items-center justify-center gap-2 rounded-full border font-medium",
    // Never `transition-all`: it animates layout properties nobody asked for.
    "transition-[background-color,border-color,color,transform]",
    // The label of a button must never wrap to two lines — it reads as a bug,
    // not as a style. Shorten the label instead; the pill will not stretch.
    "whitespace-nowrap",
    "active:translate-y-px",
    "disabled:pointer-events-none disabled:opacity-45 disabled:active:translate-y-0",
    "aria-busy:pointer-events-none aria-busy:opacity-70",
    "aria-invalid:border-destructive aria-invalid:text-destructive",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4"
  ),
  {
    variants: {
      variant: {
        default: "bg-cta text-cta-ink border-transparent hover:bg-cta-hover",
        accent: "bg-accent-cta text-on-accent border-transparent hover:bg-accent",
        destructive:
          "bg-destructive text-destructive-foreground border-transparent hover:bg-[color-mix(in_oklch,var(--destructive)_86%,var(--color-ink-0))]",
        outline: "border-rule-soft text-ink-0 bg-paper-0 hover:bg-paper-2",
        secondary: "bg-paper-2 border-transparent text-ink-0 hover:bg-paper-3",
        ghost: "text-ink-1 hover:bg-paper-2 hover:text-ink-0 border-transparent bg-transparent",
        link: "text-accent-cta border-transparent bg-transparent underline-offset-4 hover:underline active:translate-y-0",
      },
      size: {
        default: "h-10 px-4 text-sm",
        sm: "h-8 gap-1.5 px-3 text-xs",
        lg: "h-12 px-6 text-base",
        icon: "size-10",
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
