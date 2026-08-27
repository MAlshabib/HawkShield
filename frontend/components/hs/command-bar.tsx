"use client"

/**
 * The two controls that ride in the nav pill: language, then field.
 *
 * Re-cut for the floating pill — both controls are now pills themselves, at the
 * pill's own 32px height, so they sit inside it without pushing it taller than
 * its padding. Nothing here invents a colour or a font: it reads the tokens
 * (`--color-paper-*`, `--color-ink-*`, `--color-rule*`, `--color-accent`) and
 * nothing else.
 *
 * Both are real `<button>`s carrying `aria-pressed`. A locale switch that only
 * works with a mouse is not a locale switch for the people most likely to need
 * it, and a theme toggle that does not announce its state is a toggle only for
 * people who can see the icon.
 */
import { Moon, Sun } from "lucide-react"

import { useLocale, useT } from "@/lib/i18n"
import { useTheme } from "@/components/providers/theme-provider"
import { cn } from "@/lib/utils"

/**
 * One half of the locale switch. `ع` and `EN` are the two labels: each is
 * independently pressable, so the current language is announced rather than
 * hidden inside a single opaque "toggle".
 */
const segment = cn(
  "px-2.5 py-1.5 text-xs leading-none font-medium transition-colors",
  "text-ink-2 hover:text-ink-0",
  "aria-pressed:bg-paper-2 aria-pressed:text-ink-0"
)

export function CommandBar({ className }: { className?: string }) {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const { resolved, setTheme } = useTheme()

  const isDark = resolved === "dark"

  return (
    <div
      className={cn("flex items-center gap-1.5", className)}
      role="group"
      aria-label={t("command.label")}
    >
      <div className="border-rule-soft bg-paper-0 flex items-stretch overflow-hidden rounded-full border">
        {/* The divider is a border on the inline-END edge, so it lands between
            the two segments in Arabic exactly as it does in English. */}
        <button
          type="button"
          onClick={() => setLocale("ar")}
          aria-pressed={locale === "ar"}
          aria-label={t("command.locale.ar")}
          lang="ar"
          className={cn(segment, "border-rule border-e")}
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
          "border-rule-soft bg-paper-0 text-ink-2 inline-flex size-8 items-center justify-center rounded-full border",
          "transition-colors hover:bg-paper-2 hover:text-ink-0"
        )}
      >
        {isDark ? (
          <Sun className="size-3.5" aria-hidden />
        ) : (
          <Moon className="size-3.5" aria-hidden />
        )}
      </button>
    </div>
  )
}
