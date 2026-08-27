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
 *
 * THE TRANSITION
 *
 * Switching language flips `dir`, so the content genuinely changes sides — it
 * is a different layout, not a moved one. Tweening that is both expensive and
 * wrong-looking mid-flight, so `setLocale` does the only honest thing: the page
 * leaves, swaps, and comes back. A ~10px exit toward the old start edge and a
 * ~14px entrance from the new one tell the eye which way it went; `main` trails
 * the chrome by 70ms so there is an order to read it in. 430ms end to end, and
 * opacity and transform are the only properties involved (`app/transitions.css`
 * carries all of it).
 *
 * Where the browser has view transitions, the swap happens behind a snapshot of
 * the old frame — which matters more here than for the field, because reflowing
 * a whole page from LTR to RTL is not free and this way the cost lands in a
 * frame nobody is looking at. Elsewhere the same shape runs off two classes and
 * a pair of timers.
 *
 * INTERRUPTION
 *
 * This is a control someone will toggle repeatedly in front of an audience, so
 * it must not queue and must not stick. Exactly one transition is ever in
 * flight; a click arriving during one is remembered as *the* pending target,
 * overwriting any previous one, and is run when the current transition
 * finishes. Clicking back to where the page already is simply drops the pending
 * target. The queue is therefore never longer than one, whatever the click rate.
 *
 * `localStorage` is written on every click rather than at the end of a
 * transition, so a reload mid-flight lands on the language last asked for.
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

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)"

/** Scopes the view-transition pseudo-element rules in `app/transitions.css`. */
const VT_CLASS = "hs-vt-locale"
/** The two phases of the no-view-transition path, in the same stylesheet. */
const FADE_OUT_CLASS = "hs-fade-locale-out"
const FADE_IN_CLASS = "hs-fade-locale-in"

/* Must stay in step with `--dur-fast`, `--dur-base` and `--hs-locale-stagger`.
 * The cleanup timers carry a frame of slack so a class is never stripped out
 * from under the last frame of its own animation. */
const OUT_MS = 140
const IN_MS = 240
const STAGGER_MS = 70
const IN_CLEANUP_MS = IN_MS + STAGGER_MS + 24

/* How far the page moves. Small on purpose: this is a cue about direction, not
 * a slide. Anything larger reads as the page being thrown, and on a 1280-wide
 * display it starts to expose the paper edge. */
const OUT_SHIFT_PX = 10
const IN_SHIFT_PX = 14

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

/** Read live, never cached, so DevTools emulation takes effect immediately. */
function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia(REDUCED_MOTION_QUERY).matches
}

function supportsViewTransitions(): boolean {
  return typeof document !== "undefined" && typeof document.startViewTransition === "function"
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

  /* -- transition bookkeeping ---------------------------------------------
   * Refs throughout, so `setLocale` keeps a stable identity: it goes into a
   * memo that half the tree reads. */
  const localeRef = useRef(locale)
  localeRef.current = locale

  /** False until after mount, so nothing animates over the pre-hydration script. */
  const armedRef = useRef(false)
  const runningRef = useRef(false)
  /** At most one, always the latest — this is what keeps the queue from growing. */
  const queuedRef = useRef<Locale | null>(null)
  const activeRef = useRef<ViewTransition | null>(null)
  const timersRef = useRef<number[]>([])

  useEffect(() => {
    armedRef.current = true
    return () => {
      armedRef.current = false
      for (const id of timersRef.current) window.clearTimeout(id)
      timersRef.current = []
      const root = document.documentElement
      root.classList.remove(VT_CLASS, FADE_OUT_CLASS, FADE_IN_CLASS)
      activeRef.current?.skipTransition()
      activeRef.current = null
    }
  }, [])

  const setLocale = useCallback((next: Locale) => {
    // Persist first and unconditionally: the stored preference is the last one
    // asked for, not the last one finished animating.
    try {
      window.localStorage.setItem(STORAGE_KEYS.locale, next)
    } catch {
      // Preference simply will not survive a reload; the UI still switches.
    }

    const root = document.documentElement

    const track = (id: number) => {
      timersRef.current.push(id)
      return id
    }
    const clearTimers = () => {
      for (const id of timersRef.current) window.clearTimeout(id)
      timersRef.current = []
    }
    const clearShift = () => {
      root.style.removeProperty("--hs-locale-out-shift")
      root.style.removeProperty("--hs-locale-in-shift")
    }

    /** One transition has ended. Run the pending target, if it is still worth running. */
    const finish = () => {
      runningRef.current = false
      clearTimers()
      const pending = queuedRef.current
      queuedRef.current = null
      if (pending !== null && pending !== localeRef.current) request(pending)
    }

    const run = (target: Locale) => {
      runningRef.current = true

      /* A translate is physical; `dir` is logical. The sign has to come from the
         direction of travel, so it is computed here rather than left to the
         document: going to RTL the page leaves toward the left (where LTR
         started) and arrives from the right (where RTL starts), and going the
         other way it is mirrored. */
      const toRTL = dirFor(target) === "rtl"
      root.style.setProperty("--hs-locale-out-shift", `${toRTL ? -OUT_SHIFT_PX : OUT_SHIFT_PX}px`)
      root.style.setProperty("--hs-locale-in-shift", `${toRTL ? IN_SHIFT_PX : -IN_SHIFT_PX}px`)

      if (!supportsViewTransitions()) {
        root.classList.add(FADE_OUT_CLASS)
        track(
          window.setTimeout(() => {
            // The swap has to be committed and the classes exchanged in the same
            // frame, or the outgoing copy is briefly seen fading back in.
            flushSync(() => setLocaleState(target))
            root.classList.remove(FADE_OUT_CLASS)
            root.classList.add(FADE_IN_CLASS)
            track(
              window.setTimeout(() => {
                root.classList.remove(FADE_IN_CLASS)
                clearShift()
                finish()
              }, IN_CLEANUP_MS),
            )
          }, OUT_MS),
        )
        return
      }

      // The class also assigns `main` its own `view-transition-name`, so it has
      // to be on the element before the browser captures the old frame.
      root.classList.add(VT_CLASS)

      let transition: ViewTransition
      try {
        transition = document.startViewTransition(() => {
          // `lang` and `dir` are stamped by a layout effect, so the DOM must be
          // committed inside this callback for the new frame to be captured
          // with the reflowed layout. `flushSync` is what makes that synchronous.
          flushSync(() => setLocaleState(target))
        })
      } catch {
        // A browser that has the method but refuses the call must still switch.
        root.classList.remove(VT_CLASS)
        clearShift()
        setLocaleState(target)
        runningRef.current = false
        return
      }

      activeRef.current = transition

      const done = () => {
        if (activeRef.current === transition) activeRef.current = null
        root.classList.remove(VT_CLASS)
        clearShift()
        finish()
      }

      // `ready` rejects when a transition is skipped or when a duplicate
      // `view-transition-name` aborts capture. In both cases the update callback
      // has still run, so the language changed — only the motion was lost, which
      // is exactly the right way for this to fail.
      transition.ready.catch(() => {})
      transition.finished.then(done, done)
    }

    function request(target: Locale): void {
      if (runningRef.current) {
        // Latest wins; nothing accumulates.
        queuedRef.current = target
        return
      }
      if (target === localeRef.current) return
      if (!armedRef.current || prefersReducedMotion()) {
        setLocaleState(target)
        return
      }
      run(target)
    }

    request(next)
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
