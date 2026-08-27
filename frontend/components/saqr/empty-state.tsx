"use client"

/**
 * What the page says before it has been asked anything.
 *
 * Three jobs: say who Saqr is, say what it can actually reach, and give a way
 * in. The middle one is the reason the catalogue is fetched rather than listed
 * here — with the shipped configuration `run_sql` is gated off and the agent
 * has **seven** tools, not the eight in the source, and both gates are settings
 * an operator can change without a frontend rebuild. A hardcoded list would
 * start lying the first time one moved, which is exactly the kind of quiet
 * untruth this product does not get to tell.
 *
 * The starter questions are offered in both languages at once. Saqr answers in
 * the language of the interface, so the second block is how a judge sees it
 * read Arabic without first switching the whole console — and how they see it
 * read English from an Arabic one.
 */
import * as React from "react"

import { Eyebrow } from "@/components/hs/eyebrow"
import { StatusPill } from "@/components/hs/status-pill"
import { TechnicalText } from "@/components/saqr/markdown"
import { Code } from "@/lib/format"
import { useLocale, useT, type Locale, type TranslationKey } from "@/lib/i18n"
import { ar } from "@/lib/i18n/ar"
import { en } from "@/lib/i18n/en"
import { toolLabelKey, type SaqrToolInfo } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/**
 * Chosen to reach five different tools rather than five phrasings of one: a
 * broad opener (`threat_overview`), a conceptual question
 * (`explain_attack_class`), a bounded listing (`query_threats`), an aggregation
 * (`aggregate_threats`) and a second aggregation over a different dimension.
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

/**
 * A paper slip, not a pill: a starter question is a whole sentence and wraps to
 * two lines on a 320px viewport, where a fully rounded capsule reads as a
 * mistake rather than as a control.
 */
function Chip({ text, onPick }: { text: string; onPick: (text: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onPick(text)}
      className={cn(
        "border-rule-soft bg-paper-1 text-ink-1 hs-elev max-w-full min-w-0 rounded-lg border",
        "px-3.5 py-2 text-start text-sm transition-colors",
        "hover:bg-paper-2 hover:text-ink-0"
      )}
    >
      {/* A starter question can name a MAC. Unisolated, its octets are visually
          reordered inside Arabic text while the DOM stays perfectly correct. */}
      <TechnicalText text={text} />
    </button>
  )
}

function Block({
  label,
  children,
  ...props
}: { label: React.ReactNode; children: React.ReactNode } & React.ComponentPropsWithoutRef<"section">) {
  return (
    <section className="flex min-w-0 flex-col gap-4" {...props}>
      <header className="border-rule border-b pb-2">
        <Eyebrow>{label}</Eyebrow>
      </header>
      {children}
    </section>
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
    <div className={cn("flex min-w-0 flex-col gap-10", className)}>
      <div className="flex max-w-[64ch] flex-col gap-4">
        <p className="text-ink-1 text-md">{t("saqr.empty.who")}</p>
        <p className="text-ink-2 text-sm">{t("saqr.empty.how")}</p>
      </div>

      <Block label={t("saqr.empty.reach")}>
        {catalogueFailed ? (
          <p className="text-ink-2 text-sm">{t("saqr.empty.reachFailed")}</p>
        ) : tools.length === 0 ? (
          <p className="text-ink-3 text-sm">{t("saqr.empty.reachLoading")}</p>
        ) : (
          <ul className="grid min-w-0 gap-x-8 gap-y-3 sm:grid-cols-2">
            {tools.map((tool) => (
              <li key={tool.name} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="text-ink-0 text-sm">{t(toolLabelKey(tool.label_key))}</span>
                {/* The wire name beside the localised one: it is what appears in
                    every step below, so the two have to be introduced together. */}
                <Code className="text-ink-2 text-xs">{tool.name}</Code>
                {tool.mutating && (
                  <StatusPill tone="high">{t("saqr.trace.mutating")}</StatusPill>
                )}
              </li>
            ))}
          </ul>
        )}
      </Block>

      <Block label={t("saqr.suggested.title")}>
        <div className="flex flex-wrap gap-2">
          {questions.here.map((question) => (
            <Chip key={question} text={question} onPick={onPick} />
          ))}
        </div>
      </Block>

      <Block label={t("saqr.suggested.otherLang")}>
        {/* `dir` and `lang` on the container, not on each chip: the block is a
            run of text in the other language and its punctuation belongs to it. */}
        <div className="flex flex-wrap gap-2" dir={other === "ar" ? "rtl" : "ltr"} lang={other}>
          {questions.there.map((question) => (
            <Chip key={question} text={question} onPick={onPick} />
          ))}
        </div>
      </Block>
    </div>
  )
}
