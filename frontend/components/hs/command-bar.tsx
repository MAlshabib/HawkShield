"use client"

/**
 * The two controls that live in the top-inline-end corner of every page:
 * language, then field.
 *
 * Restrained on purpose — the design engineer owns the visual system, so this
 * only ever reads the tokens (`--ink`, `--ink-dim`, `--hairline`, `--surface`,
 * `--hs-azure`) and invents no colour of its own. Both controls are real
 * `<button>`s carrying `aria-pressed`, because a locale switch that only works
 * with a mouse is not a locale switch for the people most likely to need it.
 */
import { Moon, Sun } from "lucide-react"

import { useLocale, useT } from "@/lib/i18n"
import { useTheme } from "@/components/providers/theme-provider"
import { cn } from "@/lib/utils"

/** One segment of the locale switch. */
const segment = cn(
  "px-2.5 py-1 text-xs font-medium leading-none transition-colors",
  "text-[color:var(--ink-dim)] hover:text-[color:var(--ink)]",
  "aria-pressed:text-[color:var(--ink)]",
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--hs-azure)]",
)

export function CommandBar({ className }: { className?: string }) {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const { resolved, setTheme } = useTheme()

  const isDark = resolved === "dark"

  return (
    <div
      className={cn("flex items-center gap-2", className)}
      role="group"
      aria-label={t("command.label")}
    >
      {/* Locale: ع | EN. Each half is independently pressable so the current
          language is announced, rather than a single opaque "toggle". */}
      <div
        className={cn(
          "flex items-stretch overflow-hidden rounded-md border",
          "border-[color:var(--hairline)] bg-[color:var(--surface)]",
        )}
      >
        {/* The divider is a border on the inline-END edge, so it lands between
            the two segments in Arabic exactly as it does in English. */}
        <button
          type="button"
          onClick={() => setLocale("ar")}
          aria-pressed={locale === "ar"}
          aria-label={t("command.locale.ar")}
          lang="ar"
          className={cn(segment, "border-e border-[color:var(--hairline)]")}
        >
          ع
        </button>
        <button
          type="button"
          onClick={() => setLocale("en")}
          aria-pressed={locale === "en"}
          aria-label={t("command.locale.en")}
          lang="en"
          className={segment}
        >
          EN
        </button>
      </div>

      {/* Field. A two-state toggle: it always writes an explicit choice, so the
          operator's decision survives a change in the OS setting. */}
      <button
        type="button"
        onClick={() => setTheme(isDark ? "light" : "dark")}
        aria-pressed={isDark}
        aria-label={t("command.theme.toggle")}
        title={isDark ? t("command.theme.dark") : t("command.theme.light")}
        className={cn(
          "inline-flex h-7 w-7 items-center justify-center rounded-md border transition-colors",
          "border-[color:var(--hairline)] bg-[color:var(--surface)]",
          "text-[color:var(--ink-dim)] hover:text-[color:var(--ink)]",
          "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--hs-azure)]",
        )}
      >
        {isDark ? <Sun className="h-3.5 w-3.5" aria-hidden /> : <Moon className="h-3.5 w-3.5" aria-hidden />}
      </button>
    </div>
  )
}
