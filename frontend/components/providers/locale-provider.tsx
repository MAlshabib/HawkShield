"use client"

/**
 * Locale state for a fully static export.
 *
 * `next.config.ts` sets `output: "export"`, so there is no server to negotiate a
 * locale and no middleware to rewrite a `[locale]` segment. Locale therefore
 * lives entirely on the client: one context, one `localStorage` key, and the
 * inline script in `app/layout.tsx` that stamps `lang`/`dir` on `<html>` before
 * first paint so nobody sees an LTR flash on the way to an Arabic page.
 *
 * The provider deliberately does NOT read `localStorage` during render — the
 * static HTML is generated at build time with the English/LTR defaults, and any
 * divergence at render time is a hydration mismatch. It reads storage in a
 * layout effect instead, which lands in the same frame the browser paints.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react"

import { ar } from "@/lib/i18n/ar"
import { en } from "@/lib/i18n/en"
import {
  coerceLocale,
  dirFor,
  STORAGE_KEYS,
  type Dictionary,
  type Direction,
  type Locale,
  type TranslationKey,
  type TranslationVars,
} from "@/lib/i18n/types"

/**
 * `useLayoutEffect` warns when React renders on the server, and a static export
 * still renders once at build time. Picking the hook at module scope (not during
 * render) keeps the build quiet and the browser flash-free.
 */
const useIsomorphicLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect

const DICTIONARIES: Record<Locale, Dictionary> = { en, ar }

/** Build-time default. The inline head script overrides this before first paint. */
const DEFAULT_LOCALE: Locale = "en"

export type LocaleContextValue = {
  locale: Locale
  setLocale: (next: Locale) => void
  dir: Direction
  isRTL: boolean
}

const LocaleContext = createContext<LocaleContextValue | null>(null)

/** Substitute `{name}` placeholders. Unknown placeholders are left untouched. */
function interpolate(template: string, vars?: TranslationVars): string {
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = vars[name]
    return value === undefined ? match : String(value)
  })
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE)

  // Adopt whatever the head script already resolved. Reading it back (rather
  // than recomputing) guarantees the React tree and the painted DOM agree.
  useIsomorphicLayoutEffect(() => {
    let stored: Locale | null = null
    try {
      stored = coerceLocale(window.localStorage.getItem(STORAGE_KEYS.locale))
    } catch {
      // Private-mode Safari and some kiosk builds throw on localStorage access.
      // A missing preference is not an error; fall through to the browser's.
    }
    const resolved = stored ?? coerceLocale(navigator.language) ?? DEFAULT_LOCALE
    setLocaleState(resolved)
  }, [])

  // Keep the document in step with the state. This is the single place that
  // touches `<html>`, so the head script and React can never disagree for long.
  useIsomorphicLayoutEffect(() => {
    const root = document.documentElement
    root.lang = locale
    root.dir = dirFor(locale)
  }, [locale])

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    try {
      window.localStorage.setItem(STORAGE_KEYS.locale, next)
    } catch {
      // Preference simply will not survive a reload; the UI still switches.
    }
  }, [])

  const value = useMemo<LocaleContextValue>(
    () => ({ locale, setLocale, dir: dirFor(locale), isRTL: locale === "ar" }),
    [locale, setLocale],
  )

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
}

export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext)
  if (!ctx) throw new Error("useLocale must be used inside <LocaleProvider>")
  return ctx
}

export type Translate = (key: TranslationKey, vars?: TranslationVars) => string

/**
 * `t(key, vars?)`. The key type is the English dictionary's key union, so a
 * typo does not compile, and `ar.ts` is typed `Record<TranslationKey, string>`,
 * so a missing translation does not compile either. There is no runtime
 * fallback path to English because there is no way to reach one.
 */
export function useT(): Translate {
  const { locale } = useLocale()
  return useCallback(
    (key: TranslationKey, vars?: TranslationVars) => interpolate(DICTIONARIES[locale][key], vars),
    [locale],
  )
}
