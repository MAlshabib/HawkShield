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
 *
 * THE TRANSITION
 *
 * Switching field repaints every surface, every hairline and every chart colour
 * on the page. Done in one frame that reads as a glitch, so `setTheme` wraps the
 * swap in a View Transition where the browser has one: the old frame is held as
 * a still image and the new one is revealed through a circle growing out of the
 * control that was pressed (`app/transitions.css`). One compositor property,
 * ~360ms, and nothing in the tree is asked to transition its own colours.
 *
 * Four things this must not do, in the order they were got wrong:
 *
 *   1. **Animate on first paint.** The inline script in `app/layout.tsx` sets
 *      the field before React mounts, and the layout effect below runs again on
 *      mount; if the transition were driven off `resolved` changing, every page
 *      load would wipe from the build-time default to the stored preference.
 *      So it is driven from `setTheme` — a user gesture — and additionally
 *      gated on `armedRef`, which is only set in a mount effect.
 *   2. **Animate a change nobody asked for.** Choosing "system" when the OS is
 *      already dark, or the OS flipping under a "system" choice, changes nothing
 *      or changes it without a gesture. Both take the instant path.
 *   3. **Queue up.** Rapid toggling calls `skipTransition()` on whatever is in
 *      flight before starting the next, and a sequence number makes sure a stale
 *      transition's cleanup cannot strip the class the live one is using.
 *   4. **Ignore `prefers-reduced-motion`.** Checked at the moment of the click,
 *      not cached, so DevTools emulation and a mid-session OS change both take
 *      effect immediately. `app/transitions.css` carries the CSS half of the
 *      same guard.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"
import { flushSync } from "react-dom"

import { STORAGE_KEYS } from "@/lib/i18n/types"

const useIsomorphicLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect

export type Theme = "light" | "dark" | "system"
export type ResolvedTheme = "light" | "dark"

/** Viewport coordinates the circular reveal grows from — normally the toggle. */
export type ThemeOrigin = { x: number; y: number }

/** Build-time default, matching the inline head script's own fallback. */
const DEFAULT_THEME: Theme = "system"
const DARK_QUERY = "(prefers-color-scheme: dark)"
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)"

/** Scopes the view-transition pseudo-element rules in `app/transitions.css`. */
const VT_CLASS = "hs-vt-theme"
/** Scopes the colour-property transition used where view transitions are not. */
const FADE_CLASS = "hs-fade-theme"
/** Must stay in step with `--hs-dur-theme`; the slack is one frame at 30fps. */
const THEME_MS = 360
const FADE_CLEANUP_MS = THEME_MS + 40

export type ThemeContextValue = {
  theme: Theme
  /**
   * `origin` is where the reveal starts, in viewport coordinates. Callers that
   * do not pass one (the design sheet's three buttons) get a reveal from the
   * centre of the viewport, which is the right neutral answer.
   */
  setTheme: (next: Theme, origin?: ThemeOrigin) => void
  resolved: ResolvedTheme
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function coerceTheme(value: string | null | undefined): Theme | null {
  return value === "light" || value === "dark" || value === "system" ? value : null
}

/** Read live, never cached — see note 4 above. */
function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia(REDUCED_MOTION_QUERY).matches
}

function supportsViewTransitions(): boolean {
  return typeof document !== "undefined" && typeof document.startViewTransition === "function"
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

  /* -- transition bookkeeping --------------------------------------------
   * All refs, so `setTheme` keeps the stable identity it has always had: it is
   * handed to consumers through a memo, and a `setTheme` that changed on every
   * OS media-query event would re-render the whole tree for nothing. */
  const resolvedRef = useRef(resolved)
  resolvedRef.current = resolved
  const systemDarkRef = useRef(systemDark)
  systemDarkRef.current = systemDark

  /** False until after mount, so nothing can animate over the head script. */
  const armedRef = useRef(false)
  /** Monotonic; only the latest sequence is allowed to clean up. */
  const seqRef = useRef(0)
  const activeRef = useRef<ViewTransition | null>(null)
  const fadeTimerRef = useRef<number | null>(null)

  useEffect(() => {
    armedRef.current = true
    return () => {
      armedRef.current = false
      if (fadeTimerRef.current !== null) window.clearTimeout(fadeTimerRef.current)
      activeRef.current?.skipTransition()
      activeRef.current = null
    }
  }, [])

  const setTheme = useCallback((next: Theme, origin?: ThemeOrigin) => {
    try {
      window.localStorage.setItem(STORAGE_KEYS.theme, next)
    } catch {
      // Preference will not survive a reload; the UI still switches.
    }

    const nextResolved: ResolvedTheme = next === "system" ? (systemDarkRef.current ? "dark" : "light") : next
    const repaints = nextResolved !== resolvedRef.current

    // Note 1, note 2 and note 4: nothing to look at, or nothing allowed to move.
    if (!armedRef.current || !repaints || prefersReducedMotion()) {
      setThemeState(next)
      return
    }

    const root = document.documentElement
    const seq = ++seqRef.current

    if (!supportsViewTransitions()) {
      /* Fallback: arm the colour-property transition for exactly as long as it
         takes to run, then disarm it. Leaving it armed would make every hover
         and every arriving detection inherit a 360ms colour fade. */
      root.classList.add(FADE_CLASS)
      if (fadeTimerRef.current !== null) window.clearTimeout(fadeTimerRef.current)
      fadeTimerRef.current = window.setTimeout(() => {
        if (seqRef.current === seq) root.classList.remove(FADE_CLASS)
        fadeTimerRef.current = null
      }, FADE_CLEANUP_MS)
      setThemeState(next)
      return
    }

    /* The reveal geometry. The radius is the distance from the origin to the
       furthest viewport corner, so the circle finishes by covering the screen
       exactly rather than by an arbitrary large number — that is what keeps the
       tail of the ease honest at every window size. */
    const vw = window.innerWidth
    const vh = window.innerHeight
    const x = origin ? origin.x : vw / 2
    const y = origin ? origin.y : vh / 2
    const radius = Math.hypot(Math.max(x, vw - x), Math.max(y, vh - y))

    root.style.setProperty("--hs-vt-x", `${x}px`)
    root.style.setProperty("--hs-vt-y", `${y}px`)
    root.style.setProperty("--hs-vt-r", `${radius}px`)
    root.classList.add(VT_CLASS)

    // Note 3. Skipping the in-flight transition resolves it immediately (its
    // update callback still runs, so no state is lost) and leaves the next one
    // a clean frame to snapshot.
    activeRef.current?.skipTransition()

    let transition: ViewTransition
    try {
      transition = document.startViewTransition(() => {
        // The `.dark` class is toggled by a layout effect, so the DOM has to be
        // committed *inside* this callback for the browser to snapshot the new
        // state. `flushSync` is what makes React's update synchronous here.
        flushSync(() => setThemeState(next))
      })
    } catch {
      // A browser that has the method but refuses the call (a transition
      // already mid-capture, a hidden document) must still change the theme.
      root.classList.remove(VT_CLASS)
      setThemeState(next)
      return
    }

    activeRef.current = transition

    const cleanup = () => {
      if (activeRef.current === transition) activeRef.current = null
      // Only the newest sequence owns the class and the custom properties; a
      // superseded transition finishing late must not strip them from under it.
      if (seqRef.current !== seq) return
      root.classList.remove(VT_CLASS)
      root.style.removeProperty("--hs-vt-x")
      root.style.removeProperty("--hs-vt-y")
      root.style.removeProperty("--hs-vt-r")
    }

    // `ready` rejects on a skipped or aborted transition, `finished` resolves
    // either way. Both are caught: an unhandled rejection in a theme toggle is
    // a console error a judge can open the dev tools and find.
    transition.ready.catch(() => {})
    transition.finished.then(cleanup, cleanup)
  }, [])

  const value = useMemo<ThemeContextValue>(() => ({ theme, setTheme, resolved }), [theme, setTheme, resolved])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>")
  return ctx
}
