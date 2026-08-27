"use client"

/**
 * One run of Saqr, rendered as a document.
 *
 * The shape is a short report and not a chat log: the **question** as a
 * heading, then **the work** as numbered labelled steps, then **the answer** as
 * prose, then a footer that states what the run cost. A judge reading this for
 * the first time should be able to follow it top to bottom without being told
 * what a tool call is.
 *
 * A finished run keeps its place on the page but collapses to its answer — the
 * steps are one disclosure away, because five runs unfolded is not a document
 * anybody reads. Nothing is discarded and nothing is re-fetched: the collapsed
 * form renders the same events from the same object.
 */
import * as React from "react"

import { Eyebrow } from "@/components/hs/eyebrow"
import { SaqrAnswer } from "@/components/saqr/answer"
import { TechnicalText } from "@/components/saqr/markdown"
import { SaqrWork, stopKey } from "@/components/saqr/work"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import type { SaqrPhase, SaqrRun } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/* ── The question ────────────────────────────────────────────────────────── */

/**
 * The operator's own words, as the document's heading.
 *
 * It may be in either language and frequently names a MAC or a class
 * identifier. `TechnicalText` isolates the string as a whole — so it cannot
 * reorder the line around it — and isolates each Latin island inside it,
 * without forcing a direction on the sentence itself.
 */
function Question({ text, level = "h2" }: { text: string; level?: "h2" | "h3" }) {
  const t = useT()
  const Heading = level

  return (
    <header className="flex min-w-0 flex-col gap-2">
      <Eyebrow>{t("saqr.doc.question")}</Eyebrow>
      <Heading
        className={cn(
          "font-display text-ink-0 min-w-0 font-bold [overflow-wrap:anywhere]",
          level === "h2" ? "text-xl sm:text-2xl" : "text-lg"
        )}
      >
        <TechnicalText text={text} />
      </Heading>
    </header>
  )
}

/* ── The footer ──────────────────────────────────────────────────────────── */

/**
 * What the run cost, in the wire's own figures.
 *
 * `done.elapsed_ms` is the server's own and always wins when it arrived; the
 * client's measurement is the fallback for a run that ended without `done`
 * (cancelled, refused, disconnected), which still owes the reader a duration.
 */
function RunFooter({
  run,
  elapsed,
  isRunning = false,
}: {
  run: SaqrRun
  elapsed: number
  isRunning?: boolean
}) {
  const t = useT()
  const f = useFormatters()

  const toolCalls =
    run.done?.tool_calls ?? run.events.filter((event) => event.type === "tool_call").length

  return (
    <footer className="border-rule text-ink-2 flex flex-wrap items-center gap-x-3 gap-y-1 border-t pt-3 text-xs">
      {/* Elapsed is a figure an operator compares against another figure. */}
      <span className="hs-num">{t("saqr.footer.elapsed", { s: (elapsed / 1000).toFixed(1) })}</span>
      <span aria-hidden="true">·</span>
      <span>{t("saqr.footer.toolCalls", { n: f.number(toolCalls) })}</span>
      <span aria-hidden="true">·</span>
      <span>{t("saqr.footer.events", { n: f.number(run.events.length) })}</span>
      {run.done && (
        <>
          <span aria-hidden="true">·</span>
          <span className="text-ink-1">{t(stopKey(run.done.stop_reason))}</span>
        </>
      )}
      {/* A run that STOPPED with neither `done` nor a failure was aborted by
          the operator — `done` is the only legitimate end of a stream. The
          `isRunning` guard is load-bearing: without it an open run, which has
          no `done` yet by definition, reports itself as cancelled from its
          first frame. */}
      {!isRunning && !run.done && !run.failure && (
        <>
          <span aria-hidden="true">·</span>
          <span className="text-ink-1">{t("saqr.stop.cancelled")}</span>
        </>
      )}
    </footer>
  )
}

/* ── The open run ────────────────────────────────────────────────────────── */

export function SaqrRunDocument({
  run,
  phase,
  isRunning,
  answer,
  elapsed,
  className,
}: {
  run: SaqrRun
  phase: SaqrPhase | null
  isRunning: boolean
  /** The live text: token deltas while streaming, the settled `answer` after. */
  answer: string
  elapsed: number
  className?: string
}) {
  const t = useT()

  // Tokens are still arriving while the run is open and no `answer` event has
  // settled the text. The caret follows this and nothing else.
  const streaming = isRunning && !run.events.some((event) => event.type === "answer")

  return (
    <article className={cn("flex min-w-0 flex-col gap-8", className)}>
      <Question text={run.question} />

      <SaqrWork run={run} phase={phase} isRunning={isRunning} />

      {(answer || streaming) && (
        <SaqrAnswer
          text={answer}
          usedTools={run.usedTools}
          streaming={streaming && answer.length > 0}
        />
      )}

      {/* Nothing came back at all. The fault itself is already stated in the
          work section; this keeps the document from ending mid-sentence. */}
      {!answer && !isRunning && run.failure && (
        <p className="text-ink-2 text-sm">{t("saqr.answer.none")}</p>
      )}

      <RunFooter run={run} elapsed={elapsed} isRunning={isRunning} />
    </article>
  )
}

/* ── A finished run, kept on the page ────────────────────────────────────── */

export function SaqrRunArchive({ run, className }: { run: SaqrRun; className?: string }) {
  const t = useT()

  return (
    <article className={cn("flex min-w-0 flex-col gap-5", className)}>
      <Question text={run.question} level="h3" />

      {/* Native `<details>`: keyboard-operable and find-in-page-searchable for
          free, and it survives the live run above it re-rendering on every
          animation frame while tokens stream. */}
      <details className="group min-w-0">
        <summary
          className={cn(
            "hs-label text-ink-2 hover:text-ink-0 w-fit cursor-pointer list-none",
            "rounded-sm transition-colors",
            "[&::-webkit-details-marker]:hidden"
          )}
        >
          <span className="group-open:hidden">{t("saqr.doc.showWork")}</span>
          <span className="hidden group-open:inline">{t("saqr.doc.hideWork")}</span>
        </summary>
        <div className="mt-4 min-w-0">
          <SaqrWork run={run} phase={null} isRunning={false} />
        </div>
      </details>

      {run.answer ? <SaqrAnswer text={run.answer} usedTools={run.usedTools} /> : null}

      <RunFooter run={run} elapsed={run.done?.elapsed_ms ?? run.elapsedMs} />
    </article>
  )
}
