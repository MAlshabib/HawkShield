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
 * The starter questions are offered **in the reading language only**. Saqr
 * answers in the language it was asked in, so an English chip on an Arabic page
 * switches the language of the answer without switching the language of the
 * interface — the reader ends up with an English report inside an Arabic
 * console and no way to tell why. Switching locale switches the questions with
 * it, which is the honest version of the same demonstration.
 *
 * The catalogue is filtered to what a **visitor** may be shown: `advertisedTools`
 * drops anything flagged `mutating`. A tool that writes is not something to
 * advertise on a console somebody is reading over the operator's shoulder, and
 * the backend already gates the writing tools behind the admin header — this is
 * the second lock on the same door, and it is still a filter over the fetched
 * catalogue rather than a hardcoded exclusion.
 *
 * The six are chosen to reach six different tools rather than six phrasings of
 * one, and three of them need two tools to answer: an opener over the current
 * picture, a bounded listing, a located source, a knowledge question that also
 * has to check the data, an aggregation, and the sensor's own health.
 */
import * as React from "react"

import { Eyebrow } from "@/components/hs/eyebrow"
import { TechnicalText } from "@/components/saqr/markdown"
import { Code } from "@/lib/format"
import { useT, type TranslationKey } from "@/lib/i18n"
import { advertisedTools, toolLabelKey, type SaqrToolInfo } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/**
 * The five that are always offered, in reading order. `q2` is the stand-in for
 * the located-source question when the sensor has no source to name.
 */
const SUGGESTIONS: readonly TranslationKey[] = [
  "saqr.suggested.q1",
  "saqr.suggested.q3",
  "saqr.suggested.q5",
  "saqr.suggested.q4",
  "saqr.suggested.q7",
]

/** Slot 2, filled with a MAC the sensor has actually seen. */
const MAC_SUGGESTION: TranslationKey = "saqr.suggested.q6"

/** What takes that slot when there is no such MAC. Never a fabricated one. */
const MAC_FALLBACK: TranslationKey = "saqr.suggested.q2"

/** Where the located-source question sits among the others. */
const MAC_SLOT = 2

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
  /** The busiest source MAC the sensor has stored, for the located-source chip. */
  topMac: string | null
  onPick: (question: string) => void
  className?: string
}) {
  const t = useT()

  const shown = React.useMemo(() => advertisedTools(tools), [tools])

  // Built from `t()` and therefore always in the reading language: the whole
  // list re-renders through the locale context the moment the operator
  // switches, with no second dictionary looked up by hand.
  const questions = React.useMemo(() => {
    const list = SUGGESTIONS.map((key) => t(key))
    list.splice(
      MAC_SLOT,
      0,
      topMac ? t(MAC_SUGGESTION, { mac: topMac }) : t(MAC_FALLBACK)
    )
    return list
  }, [t, topMac])

  return (
    <div className={cn("flex min-w-0 flex-col gap-10", className)}>
      <div className="flex max-w-[64ch] flex-col gap-4">
        <p className="text-ink-1 text-md">{t("saqr.empty.who")}</p>
        <p className="text-ink-2 text-sm">{t("saqr.empty.how")}</p>
      </div>

      <Block label={t("saqr.suggested.title")}>
        <p className="text-ink-2 -mt-1 text-sm">{t("saqr.suggested.hint")}</p>
        <div className="flex flex-wrap gap-2">
          {questions.map((question) => (
            <Chip key={question} text={question} onPick={onPick} />
          ))}
        </div>
      </Block>

      <Block label={t("saqr.empty.reach")}>
        {catalogueFailed ? (
          <p className="text-ink-2 text-sm">{t("saqr.empty.reachFailed")}</p>
        ) : shown.length === 0 ? (
          <p className="text-ink-3 text-sm">{t("saqr.empty.reachLoading")}</p>
        ) : (
          <ul className="grid min-w-0 gap-x-8 gap-y-3 sm:grid-cols-2">
            {shown.map((tool) => (
              <li key={tool.name} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="text-ink-0 text-sm">{t(toolLabelKey(tool.label_key))}</span>
                {/* The wire name beside the localised one: it is what appears in
                    every step below, so the two have to be introduced together. */}
                <Code className="text-ink-2 text-xs">{tool.name}</Code>
              </li>
            ))}
          </ul>
        )}
      </Block>
    </div>
  )
}
