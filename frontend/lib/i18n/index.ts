"use client"

/**
 * The public face of the i18n layer. Page authors import from here and never
 * need to know where the context physically lives.
 *
 * The provider itself is implemented in `components/providers/locale-provider`
 * next to the theme provider, because the two are mounted together in
 * `app/layout.tsx` and behave identically (client-only state, one namespaced
 * `localStorage` key, `<html>` attributes stamped before first paint). This
 * module re-exports it rather than defining a second copy — two providers for
 * one context is exactly the bug that makes a locale toggle work in one half of
 * the tree and not the other.
 */
export { LocaleProvider, useLocale, useT } from "@/components/providers/locale-provider"
export type { LocaleContextValue, Translate } from "@/components/providers/locale-provider"

export { en } from "./en"
export { ar } from "./ar"

export {
  LOCALES,
  STORAGE_KEYS,
  coerceLocale,
  dirFor,
  intlLocale,
} from "./types"
export type { Dictionary, Direction, Locale, TranslationKey, TranslationVars } from "./types"
