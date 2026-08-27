"use client"

/**
 * What the console says before it has been asked anything.
 *
 * Three jobs: say who Saqr is, say what it can actually reach, and give a way
 * in. The middle one is the reason the catalogue is fetched rather than listed
 * here — with the shipped configuration `run_sql` is gated off and the agent
 * has **seven** tools, not the eight in the source, and both gates are settings
 * an operator can change without a frontend rebuild. A hardcoded list would
 * start lying the first time one moved.
 */
import * as React from "react"

import { TechnicalText } from "@/components/saqr/markdown"
import { StatusPill } from "@/components/hs/status-pill"
import { Code } from "@/lib/format"
import { useLocale, useT, type Locale, type TranslationKey } from "@/lib/i18n"
import { ar } from "@/lib/i18n/ar"
import { en } from "@/lib/i18n/en"
import { toolLabelKey, type SaqrToolInfo } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/**
 * The starter questions, chosen to reach four different tools rather than four
 * phrasings of the same one: a broad opener (`threat_overview`), a conceptual
 * question (`explain_attack_class`), a bounded listing (`query_threats`), an
 * aggregation (`aggregate_threats`) and a time bucket.
 */
const SUGGESTIONS: readonly TranslationKey[] = [
  "saqr.suggested.q1",
  "saqr.suggested.q5",
  "saqr.suggested.q3",
  "saqr.suggested.q4",
  "saqr.suggested.q2",
]

/** Filled with a MAC the sensor has actually seen; omitted when there is none. */
const MAC_SUGGESTION: TranslationKey = "saqr.suggested.q6"

const DICTIONARIES: Record<Locale, Record<string, string>> = { en, ar }

function Chip({ text, onPick }: { text: string; onPick: (text: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onPick(text)}
      className={cn(
        "border-hairline bg-surface-sunken text-ink-dim rounded-sm border px-2.5 py-1.5 text-start text-xs",
        "hover:border-hairline-strong hover:text-ink transition-colors",
        "focus-visible:outline-hs-azure focus-visible:outline-2 focus-visible:outline-offset-2"
      )}
    >
      {/* A starter question can name a MAC. Unisolated, its octets are
          reordered on screen inside Arabic text while the DOM stays correct. */}
      <TechnicalText text={text} />
    </button>
  )
}

export function SaqrEmptyState({
  tools,
  catalogueFailed,
  topMac,
  onPick,
  className,
}: {
  tools: readonly SaqrToolInfo[]
  catalogueFailed: boolean
  /** The busiest source MAC the sensor has stored, for the specific-MAC chip. */
  topMac: string | null
  onPick: (question: string) => void
  className?: string
}) {
  const t = useT()
  const { locale } = useLocale()
  const other: Locale = locale === "ar" ? "en" : "ar"

  const questions = React.useMemo(() => {
    const build = (dict: Record<string, string>) => {
      const list = SUGGESTIONS.map((key) => dict[key]).filter(Boolean)
      if (topMac) list.splice(2, 0, dict[MAC_SUGGESTION].replace("{mac}", topMac))
      return list
    }
    return { here: build(DICTIONARIES[locale]), there: build(DICTIONARIES[other]) }
  }, [locale, other, topMac])

  return (
    <div className={cn("flex flex-col gap-5", className)}>
      <section className="flex flex-col gap-2">
        <p className="text-ink text-sm leading-relaxed">{t("saqr.empty.who")}</p>
        <p className="text-ink-dim text-sm leading-relaxed">{t("saqr.empty.how")}</p>
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="hs-label">{t("saqr.empty.reach")}</h2>
        {catalogueFailed ? (
          <p className="text-ink-dim text-xs">{t("saqr.empty.reachFailed")}</p>
        ) : tools.length === 0 ? (
          <p className="text-ink-faint text-xs">{t("saqr.empty.reachLoading")}</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {tools.map((tool) => (
              <li key={tool.name} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs">
                <Code className="text-hs-azure">{tool.name}</Code>
                <span className="text-ink-dim">{t(toolLabelKey(tool.label_key))}</span>
                {tool.mutating && (
                  <StatusPill tone="high" className="text-[10px]">
                    {t("saqr.trace.mutating")}
                  </StatusPill>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="hs-label">{t("saqr.suggested.title")}</h2>
        <div className="flex flex-wrap gap-1.5">
          {questions.here.map((question) => (
            <Chip key={question} text={question} onPick={onPick} />
          ))}
        </div>
      </section>

      <section className="flex flex-col gap-2">
        {/* The same questions in the other language. Saqr answers in the
            language of the interface, so this is a way to see it read Arabic
            without changing the whole UI first — and a way to see it read
            English from an Arabic console. */}
        <h2 className="hs-label">{t("saqr.suggested.otherLang")}</h2>
        <div
          className="flex flex-wrap gap-1.5"
          dir={other === "ar" ? "rtl" : "ltr"}
          lang={other}
        >
          {questions.there.map((question) => (
            <Chip key={question} text={question} onPick={onPick} />
          ))}
        </div>
      </section>
    </div>
  )
}
