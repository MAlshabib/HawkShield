"use client"

/**
 * Page furniture shared by the four operational routes.
 *
 * These four pages were each carrying their own copy of the same three things:
 * a max-width container, a toolbar row, and a label/value line. Three copies of
 * a rule is how a rule drifts, and the drift here would be visible — the
 * toolbar and the readout are the two places where every page in the console
 * has to look like the same instrument.
 *
 * Nothing in this file holds copy, a figure or a colour of its own.
 */
import * as React from "react"

import { ltr, toISO, useFormatters, type DateLike } from "@/lib/format"
import { useLocale, useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/**
 * The measure every operational page is set to.
 *
 * `min-w-0` on the column is load-bearing rather than defensive: a grid child
 * resolves its minimum to its content, so one wide table inside would otherwise
 * push the whole page past a 320px viewport and give the *document* a
 * horizontal scrollbar. Dense content scrolls inside its own container here.
 */
export function PageFrame({ className, ...props }: React.ComponentPropsWithoutRef<"div">) {
  return (
    <div
      className={cn(
        "mx-auto flex w-full max-w-[1240px] min-w-0 flex-col gap-6 px-4 pt-10 pb-20 sm:px-6 lg:px-8",
        className
      )}
      {...props}
    />
  )
}

/**
 * The control strip: the page's own instruments, set between two hairlines
 * directly under the heading block.
 *
 * A toolbar on paper is a rule with things resting on it, not a filled bar. The
 * two rules are the same 8% hairline the rest of the system uses, so the strip
 * reads as part of the page rather than as a chrome band bolted to the top of
 * it — which is exactly what the dark console's toolbar was.
 */
export function ControlStrip({ className, ...props }: React.ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="control-strip"
      className={cn("border-rule flex flex-wrap items-center gap-2 border-y py-3", className)}
      {...props}
    />
  )
}

/** Pushes everything after it to the inline-end edge of a control strip. */
export function ControlSpacer() {
  return <span className="ms-auto" aria-hidden="true" />
}

/* -------------------------------------------------------------------------- */
/* Time that is prose in one language and machine output in the other          */
/* -------------------------------------------------------------------------- */

/**
 * A formatted instant — the two formats that are not pure digits.
 *
 * `lib/format`'s `<Timestamp>` sets every timestamp in the mono face and pins it
 * `dir="ltr"`. That is exactly right for `14:02:11` and for `27 Aug 2026`, which
 * are machine output in Latin script. It is wrong for the Arabic renderings of
 * the same two values: `f.relative()` returns **`قبل 15 ساعة`** and `f.date()`
 * returns an Arabic month name, and both then hit the two failures
 * `components/quantity.tsx` documents —
 *
 *   1. IBM Plex Mono has no Arabic coverage at all, so the words fall through to
 *      a system face and lose their cursive joins; and
 *   2. `direction: ltr` lays the words out left-to-right, so an Arabic reader
 *      meets them in reverse.
 *
 * Observed on `/dashboard` in Arabic: `قبل 15 ساعة` rendered as disconnected
 * glyphs running the wrong way. So the treatment is chosen per locale rather
 * than per component: Latin keeps the isolated mono, Arabic gets the body face
 * at the ambient direction and lets the bidi algorithm place the digits, which
 * is the one case where it gets the answer right on its own.
 *
 * The `<time>` element and its machine-readable `dateTime` are identical either
 * way. `suppressHydrationWarning` is honest rather than lazy: the static export
 * is rendered at build time in the default locale, and the operator's locale is
 * only known once the client has read `localStorage`.
 */
export function Moment({
  value,
  format = "dateTime",
  className,
}: {
  value: DateLike
  format?: "dateTime" | "date" | "relative"
  className?: string
}) {
  const f = useFormatters()
  const { locale } = useLocale()
  const text = f[format](value)
  const iso = toISO(value)

  if (locale === "ar") {
    // `dir="auto"` and an explicit body face rather than plain inheritance: this
    // may be rendered inside a slot that is itself pinned to the mono face and
    // `direction: ltr` — `DataCardRow` sets `hs-num` on its own `<dd>`, because
    // the figure it was designed for genuinely needs both. Arabic prose in that
    // slot came out as disconnected glyphs running backwards. `auto` takes the
    // direction from the first strong character, which for `قبل 15 ساعة` is the
    // Arabic, so this is correct in an LTR ancestor as well as an RTL one.
    return (
      <time dateTime={iso} dir="auto" suppressHydrationWarning className={cn("font-sans", className)}>
        {text}
      </time>
    )
  }

  return (
    <time
      dateTime={iso}
      dir="ltr"
      suppressHydrationWarning
      className={cn(ltr, "font-mono tabular-nums", className)}
    >
      {text}
    </time>
  )
}

/**
 * Prose that has to survive being placed in a slot built for a figure.
 *
 * Same problem as `Moment` above, one level more general: a `DataCardRow` value
 * is mono and LTR-pinned by design, and a word — `Reachable`, `متاحة` — put
 * there loses its Arabic joins and its reading direction. Wrapping it hands the
 * body face and `dir="auto"` back. Use it for words, never for figures: a MAC
 * or a dBm reading wants exactly the treatment this undoes.
 */
export function Phrase({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <span dir="auto" className={cn("font-sans", className)}>
      {children}
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* The readout                                                                */
/* -------------------------------------------------------------------------- */

/**
 * A printed list of label/value pairs — the sensor readout, the estimate, the
 * backend slip.
 *
 * A real `<dl>`, because that is what this is: the label names the term and the
 * value defines it. The four hand-rolled `<div>` versions this replaces were
 * each announced to a screen reader as an unstructured run of text.
 */
export function Readout({ className, ...props }: React.ComponentPropsWithoutRef<"dl">) {
  return <dl data-slot="readout" className={cn("flex min-w-0 flex-col", className)} {...props} />
}

/**
 * One line. The value sits on the inline-end edge, so a column of figures lines
 * up in both directions without a single physical property.
 */
export function ReadoutRow({
  label,
  children,
  className,
}: {
  label: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "border-rule flex items-baseline justify-between gap-4 border-b py-2 last:border-b-0",
        className
      )}
    >
      <dt className="hs-label min-w-0 shrink-0">{label}</dt>
      <dd className="text-ink-0 min-w-0 text-end text-sm break-words">{children}</dd>
    </div>
  )
}

/**
 * "Not reported", in words.
 *
 * Never an em dash in a readout: a dash beside a figure teaches an operator
 * that it means zero, and `null` from this sensor means nobody measured it.
 * Set in ink-2 rather than ink-3 — this is a statement about the data, not a
 * placeholder, and it has to be readable at 12px.
 */
export function Unreported() {
  const t = useT()
  // Wrapped in `Phrase` for the same reason `Moment` carries its own face: this
  // lands inside `hs-num` cells and `DataCardRow` values constantly, and it is a
  // sentence about the data rather than a figure.
  return <Phrase className="text-ink-2 text-xs">{t("landing.notReported")}</Phrase>
}

/**
 * A module that could not be read. One line, in the critical hue, occupying the
 * footprint the content would have — nothing jumps when the retry lands.
 */
export function LoadError({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-sev-critical hs-label grid min-h-20 place-items-center px-4 py-6 text-center">
      {children}
    </p>
  )
}

/** Nothing to show, which on this product is a finding rather than a failure. */
export function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="hs-label grid min-h-20 place-items-center px-4 py-6 text-center">{children}</p>
  )
}
