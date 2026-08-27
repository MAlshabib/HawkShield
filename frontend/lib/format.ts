"use client"

/**
 * Locale-aware formatting, and the bidi isolation that keeps a MAC address from
 * lying to the reader.
 *
 * Two rules run through everything here:
 *
 * 1. **Every timestamp is Asia/Riyadh.** The sensor, the database and the
 *    operator are all in one timezone; rendering in the browser's zone would
 *    quietly disagree with the packet capture. This replaces the hardcoded
 *    `en-GB` + `Asia/Riyadh` formatter that used to live inside the attacks
 *    table, where only that one table could reach it.
 *
 * 2. **Latin digits in both locales** (`-u-nu-latn`). Arabic-Indic numerals are
 *    correct Arabic, but this UI is a dense instrument — MACs, channels, RSSI,
 *    counts — and mixing numeral systems down a column destroys scanability.
 *    The Arabic-reading operator and the English-reading one compare the same
 *    glyphs.
 *
 * The `<Ltr>` family exists because of the single highest-risk display bug in
 * this project: a MAC address, hex value, timestamp or SQL fragment placed in
 * RTL text without isolation is *visually reordered* by the bidi algorithm.
 * `00:1A:2B:3C:4D:5E` can render with its groups out of order while the DOM,
 * the clipboard and every test still say it is correct. Always wrap technical
 * strings — that is what `<Mac>`, `<Timestamp>` and `<Code>` are for, so page
 * authors get it right without having to remember the rule.
 *
 * JSX is deliberately absent: these helpers belong beside the formatters in
 * `lib/`, and `createElement` keeps this a `.ts` file for the four thin
 * wrappers that need it.
 */
import { createElement, useMemo, type ReactNode } from "react"

import { useLocale } from "@/components/providers/locale-provider"
import { intlLocale, type Locale } from "@/lib/i18n/types"
import { cn } from "@/lib/utils"

/** The sensor's timezone. Not the browser's, and not configurable. */
export const TIMEZONE = "Asia/Riyadh"

export type DateLike = Date | string | number | null | undefined

/** Placeholder for anything that will not parse. Never invent a value. */
const EMPTY = "—"

/**
 * Lenient parse for what the API actually sends: epoch seconds, epoch millis,
 * ISO, and `YYYY-MM-DD HH:mm:ss` with a space instead of a `T`.
 */
export function toDate(value: DateLike): Date {
  if (value == null) return new Date(NaN)
  if (value instanceof Date) return value
  if (typeof value === "number") return new Date(value < 10_000_000_000 ? value * 1000 : value)

  const asNumber = Number(value)
  if (value !== "" && !Number.isNaN(asNumber)) {
    return new Date(asNumber < 10_000_000_000 ? asNumber * 1000 : asNumber)
  }

  let s = String(value).trim().replace(/\//g, "-")
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) s = s.replace(" ", "T")

  /* `packets.ts` is a naive UTC column, and the API serialises it without a
     zone designator. `new Date("2026-08-27T21:20:11")` reads a bare ISO string
     as *browser-local*, so every timestamp in the UI was silently shifted by
     the viewer's offset — three hours in Riyadh. Nothing looked broken; the
     clock was just wrong. Anything already carrying a zone is left alone. */
  if (!/(z|[+-]\d{2}:?\d{2})$/i.test(s)) s = `${s}Z`

  return new Date(s)
}

export function isValidDate(d: Date): boolean {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

/** ISO-8601 for the `datetime` attribute, or `undefined` when unparseable. */
export function toISO(value: DateLike): string | undefined {
  const d = toDate(value)
  return isValidDate(d) ? d.toISOString() : undefined
}

export type Formatters = {
  /** `26 Aug 2026, 14:32:05` — the table workhorse. */
  dateTime: (value: DateLike) => string
  /** `14:32:05` */
  time: (value: DateLike) => string
  /** `26 Aug 2026` */
  date: (value: DateLike) => string
  /** `5 minutes ago` / `منذ ٥ دقائق`, relative to now. */
  relative: (value: DateLike, now?: number) => string
  number: (value: number | null | undefined) => string
  /** Takes a fraction (0.93), renders a percentage (93%). */
  percent: (value: number | null | undefined, fractionDigits?: number) => string
}

const RELATIVE_UNITS: ReadonlyArray<readonly [Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 31_557_600_000],
  ["month", 2_629_800_000],
  ["week", 604_800_000],
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
  ["second", 1_000],
]

/**
 * Build the formatter set for a locale. Exported separately from the hook so
 * non-React code (report filenames, CSV export, the SSE reducer) can format
 * without pulling in a component.
 */
export function createFormatters(locale: Locale): Formatters {
  const tag = intlLocale(locale)

  const dateTimeFmt = new Intl.DateTimeFormat(tag, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: TIMEZONE,
  })
  const timeFmt = new Intl.DateTimeFormat(tag, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: TIMEZONE,
  })
  const dateFmt = new Intl.DateTimeFormat(tag, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: TIMEZONE,
  })
  const relativeFmt = new Intl.RelativeTimeFormat(tag, { numeric: "auto" })
  const numberFmt = new Intl.NumberFormat(tag)

  const guard = (value: DateLike, fmt: Intl.DateTimeFormat) => {
    const d = toDate(value)
    return isValidDate(d) ? fmt.format(d) : EMPTY
  }

  return {
    dateTime: (value) => guard(value, dateTimeFmt),
    time: (value) => guard(value, timeFmt),
    date: (value) => guard(value, dateFmt),

    relative: (value, now = Date.now()) => {
      const d = toDate(value)
      if (!isValidDate(d)) return EMPTY
      const deltaMs = d.getTime() - now
      const abs = Math.abs(deltaMs)
      for (const [unit, ms] of RELATIVE_UNITS) {
        if (abs >= ms || unit === "second") {
          return relativeFmt.format(Math.round(deltaMs / ms), unit)
        }
      }
      return EMPTY
    },

    number: (value) => (typeof value === "number" && Number.isFinite(value) ? numberFmt.format(value) : EMPTY),

    percent: (value, fractionDigits = 1) => {
      if (typeof value !== "number" || !Number.isFinite(value)) return EMPTY
      return new Intl.NumberFormat(tag, {
        style: "percent",
        minimumFractionDigits: 0,
        maximumFractionDigits: fractionDigits,
      }).format(value)
    },
  }
}

/**
 * `Intl` constructors are not free, so the set is memoised per locale and
 * rebuilt only when the operator actually switches language.
 */
export function useFormatters(): Formatters {
  const { locale } = useLocale()
  return useMemo(() => createFormatters(locale), [locale])
}

/* ────────────────────────────── Bidi isolation ─────────────────────────── */

/**
 * Utility classes for a technical string that has to stay left-to-right inside
 * Arabic prose. Prefer the `<Ltr>` component — it also sets `dir="ltr"`, which
 * is what assistive technology and text selection actually read. Use this class
 * only where you cannot add an attribute (a `title`, a chart label, a cell
 * rendered by a third-party table).
 */
export const ltr = "[direction:ltr] [unicode-bidi:isolate]"

type LtrProps = {
  children: ReactNode
  className?: string
  /** Defaults to `span`; pass `div` when the content is block-level. */
  as?: "span" | "div" | "code" | "bdi"
  title?: string
}

/**
 * Isolate a run of text as left-to-right. `dir="ltr"` gives the isolation on its
 * own in every modern engine; the class is belt-and-braces for anything that
 * reaches this markup through a stylesheet reset that drops the UA rule.
 */
export function Ltr({ children, className, as = "span", title }: LtrProps) {
  return createElement(as, { dir: "ltr", className: cn(ltr, className), title }, children)
}

/** A MAC / BSSID. Monospaced, upper-case, and never reordered by the bidi run. */
export function Mac({ value, className }: { value: string | null | undefined; className?: string }) {
  const text = value ? String(value).toUpperCase() : EMPTY
  return createElement(
    "span",
    { dir: "ltr", className: cn(ltr, "font-mono tabular-nums", className), title: text },
    text,
  )
}

/**
 * A formatted timestamp inside a real `<time>` element, so the machine-readable
 * value stays ISO/UTC while the human-readable one is Asia/Riyadh.
 *
 * `suppressHydrationWarning` is honest here rather than lazy: the static export
 * is rendered at build time in the default locale, and the operator's locale is
 * only known once the client has read `localStorage`.
 */
export function Timestamp({
  value,
  format = "dateTime",
  className,
}: {
  value: DateLike
  format?: "dateTime" | "time" | "date" | "relative"
  className?: string
}) {
  const { locale } = useLocale()
  const f = useFormatters()
  const text = f[format](value)

  /* Only a clock is a pure Latin run. `14:02:11` must be pinned LTR and set in
     the figure face, or an Arabic paragraph reorders it.

     Everything else that carries Arabic words must NOT be pinned. Forcing
     `direction: ltr` on `28 أغسطس 2026، 02:19:30` breaks it: bidi rule W2
     retypes each European number following an Arabic letter as an Arabic
     number, so the month, year and clock collapse into one right-to-left run
     and swap ends — the measured visual order was `28  02:19:30  ،  2026
     أغسطس`. The DOM is correct and the date on screen is nonsense.

     So those get `dir="auto"` — isolated from the surrounding text, but with
     the direction inferred from the first strong character — and the body
     face, because the mono face carries no Arabic at all and the glyphs would
     fall through to whatever the system offers. */
  const isLatinRun = locale !== "ar" || format === "time"

  return createElement(
    "time",
    {
      dateTime: toISO(value),
      dir: isLatinRun ? "ltr" : "auto",
      suppressHydrationWarning: true,
      className: cn(
        isLatinRun ? cn(ltr, "font-mono tabular-nums") : "[unicode-bidi:isolate]",
        className,
      ),
    },
    text,
  )
}

/** Any other technical literal: SQL, JSON, a hex value, an interface name. */
export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return createElement("code", { dir: "ltr", className: cn(ltr, "font-mono", className) }, children)
}
