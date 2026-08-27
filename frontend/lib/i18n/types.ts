import type { en } from "./en"

/** The two locales the product ships. There is no runtime locale negotiation. */
export type Locale = "en" | "ar"

/** Canonical order — used by the command bar and by any locale picker. */
export const LOCALES = ["en", "ar"] as const

export type Direction = "ltr" | "rtl"

/**
 * Every legal translation key, derived from the English dictionary rather than
 * hand-maintained. `useT()` takes this type, so a typo is a compile error and a
 * key that only exists in one dictionary cannot ship.
 */
export type TranslationKey = keyof typeof en

/**
 * The shape every dictionary must satisfy. `ar.ts` is annotated with this, which
 * makes a missing Arabic string fail `tsc` instead of silently rendering
 * English inside an Arabic page.
 */
export type Dictionary = Record<TranslationKey, string>

/** `{name}` placeholders. Numbers are stringified by the caller's formatter. */
export type TranslationVars = Record<string, string | number>

/** Direction for a locale. Arabic is the only RTL locale we ship. */
export function dirFor(locale: Locale): Direction {
  return locale === "ar" ? "rtl" : "ltr"
}

/**
 * BCP-47 tag used for `Intl`. Both locales are pinned to Latin digits
 * (`-u-nu-latn`): Arabic-Indic numerals in a dense packet table destroy
 * scanability, and every surface in this product is tabular.
 */
export function intlLocale(locale: Locale): string {
  return locale === "ar" ? "ar-SA-u-nu-latn" : "en-GB-u-nu-latn"
}

/** Everything the operator can change is namespaced, so we never collide. */
export const STORAGE_KEYS = {
  locale: "hawkshield.locale",
  theme: "hawkshield.theme",
} as const

/** Narrow an untrusted string (localStorage, `navigator.language`) to a Locale. */
export function coerceLocale(value: string | null | undefined): Locale | null {
  if (!value) return null
  const head = value.toLowerCase().split("-")[0]
  if (head === "ar") return "ar"
  if (head === "en") return "en"
  return null
}
