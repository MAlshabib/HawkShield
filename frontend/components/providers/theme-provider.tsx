"use client"

/**
 * Dark/light state, hand-rolled for the same reason as the locale provider:
 * `output: "export"` means there is no server, and the project takes no new
 * dependencies for ~60 lines of work.
 *
 * `theme` is the operator's *choice* ("system" included); `resolved` is what is
 * actually on screen. The dashboard needs the second one — chart and severity
 * colours differ between fields — and the command bar needs the first, so both
 * are exposed rather than collapsed into one value.
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

import { STORAGE_KEYS } from "@/lib/i18n/types"

const useIsomorphicLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect

export type Theme = "light" | "dark" | "system"
export type ResolvedTheme = "light" | "dark"

/** Build-time default, matching the inline head script's own fallback. */
const DEFAULT_THEME: Theme = "system"
const DARK_QUERY = "(prefers-color-scheme: dark)"

export type ThemeContextValue = {
  theme: Theme
  setTheme: (next: Theme) => void
  resolved: ResolvedTheme
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function coerceTheme(value: string | null | undefined): Theme | null {
  return value === "light" || value === "dark" || value === "system" ? value : null
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(DEFAULT_THEME)
  // Dark is the build-time assumption so the static HTML matches the head
  // script's most common outcome; the layout effect corrects it immediately.
  const [systemDark, setSystemDark] = useState(true)

  useIsomorphicLayoutEffect(() => {
    let stored: Theme | null = null
    try {
      stored = coerceTheme(window.localStorage.getItem(STORAGE_KEYS.theme))
    } catch {
      // Storage can throw outright in locked-down browsers. Not fatal.
    }
    setThemeState(stored ?? DEFAULT_THEME)
    setSystemDark(window.matchMedia(DARK_QUERY).matches)
  }, [])

  // Follow the OS while the choice is "system" — and keep listening even when
  // it is not, so flipping back to "system" is instantly correct.
  useEffect(() => {
    const mql = window.matchMedia(DARK_QUERY)
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches)
    mql.addEventListener("change", onChange)
    return () => mql.removeEventListener("change", onChange)
  }, [])

  const resolved: ResolvedTheme = theme === "system" ? (systemDark ? "dark" : "light") : theme

  useIsomorphicLayoutEffect(() => {
    const root = document.documentElement
    root.classList.toggle("dark", resolved === "dark")
    // Tells the UA which field to paint form controls and scrollbars against;
    // without it a light page keeps dark native widgets.
    root.style.colorScheme = resolved
  }, [resolved])

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next)
    try {
      window.localStorage.setItem(STORAGE_KEYS.theme, next)
    } catch {
      // Preference will not survive a reload; the UI still switches.
    }
  }, [])

  const value = useMemo<ThemeContextValue>(() => ({ theme, setTheme, resolved }), [theme, setTheme, resolved])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>")
  return ctx
}
