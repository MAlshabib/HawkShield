"use client"

/**
 * The Saqr console.
 *
 * Saqr is a tool-calling agent over the detection database, and the whole point
 * of this page is that its work is *visible*: which tool it reached for, with
 * which arguments, the literal SELECT that ran, what came back, and only then
 * the answer. That is why the centre of the page is a terminal-style run trace
 * and not a column of chat bubbles — a bubble hides every one of those.
 *
 * Everything on screen came off the wire. There is no simulated typing, no
 * placeholder tool call, no canned transcript. If the stream did not send it,
 * it is not here.
 *
 * Three behaviours are deliberate and easy to get wrong:
 *
 * **Autoscroll yields to the reader.** The trace follows the stream only while
 * the viewport is already at the bottom. The moment the operator scrolls up to
 * read a result table, following stops and a control appears to resume it. A
 * trace that yanks itself away mid-read is worse than no autoscroll at all.
 *
 * **A run can be stopped.** `cancel()` aborts the request, the backend sees the
 * disconnect and collects the run rather than continuing to bill for it.
 *
 * **Failures are three different sentences.** The server refusing before
 * anything ran, the connection dying part-way, and the run reporting its own
 * error are not the same event and are not reported as one.
 */
import * as React from "react"

import { Module } from "@/components/hs/module"
import { StatusPill } from "@/components/hs/status-pill"
import { TerminalLine } from "@/components/hs/terminal-line"
import { SaqrAnswer } from "@/components/saqr/answer"
import { SaqrComposer } from "@/components/saqr/composer"
import { SaqrEmptyState } from "@/components/saqr/empty-state"
import { TechnicalText } from "@/components/saqr/markdown"
import { SaqrTrace, stopKey } from "@/components/saqr/trace"
import { Button } from "@/components/ui/button"
import { apiFetchSafe } from "@/lib/api"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { STICK_THRESHOLD_PX, useSaqrRun, useSaqrTools, type SaqrRun } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/** `/top-offenders` — reused rather than adding an endpoint for one chip. */
type OffenderRow = { wlan_sa?: string | null; count?: number }

/* ── A finished run in the transcript ────────────────────────────────────── */

function TranscriptEntry({ run }: { run: SaqrRun }) {
  const t = useT()
  const f = useFormatters()

  return (
    <article className="border-hairline flex flex-col gap-2 border-b pb-4">
      <QuestionLine question={run.question} />

      {/* Collapsed to its answer: the trace is still here, one click away, but
          a transcript of five runs unfolded is unreadable. */}
      <details className="group">
        <summary
          className={cn(
            "hs-label text-ink-faint hover:text-ink-dim cursor-pointer list-none",
            "focus-visible:outline-hs-azure rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2",
            "[&::-webkit-details-marker]:hidden"
          )}
        >
          <span className="group-open:hidden">{t("saqr.trace.show")}</span>
          <span className="hidden group-open:inline">{t("saqr.trace.hide")}</span>
        </summary>
        <div className="mt-2">
          <SaqrTrace run={run} phase={null} isRunning={false} />
        </div>
      </details>

      {run.answer ? <SaqrAnswer text={run.answer} usedTools={run.usedTools} /> : null}

      <RunFooter run={run} elapsed={run.done?.elapsed_ms ?? run.elapsedMs} f={f} />
    </article>
  )
}

function QuestionLine({ question }: { question: string }) {
  const t = useT()
  return (
    <div className="flex items-baseline gap-2">
      <span className="hs-label shrink-0">{t("saqr.you")}</span>
      {/* The question is the operator's own words and may be in either
          language, and frequently names a MAC. `TechnicalText` isolates the
          whole string (so it cannot reorder the line around it) without forcing
          a direction on it, and isolates the technical runs inside it. */}
      <TechnicalText text={question} className="text-ink min-w-0 text-sm font-medium break-words" />
    </div>
  )
}

function RunFooter({
  run,
  elapsed,
  f,
}: {
  run: SaqrRun
  elapsed: number
  f: ReturnType<typeof useFormatters>
}) {
  const t = useT()
  const toolCalls = run.done?.tool_calls ?? run.events.filter((e) => e.type === "tool_call").length

  return (
    <footer className="text-ink-faint flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span className="hs-num" dir="ltr">
        {t("saqr.footer.elapsed", { s: (elapsed / 1000).toFixed(1) })}
      </span>
      <span>·</span>
      <span>{t("saqr.footer.toolCalls", { n: f.number(toolCalls) })}</span>
      <span>·</span>
      <span>{t("saqr.footer.events", { n: f.number(run.events.length) })}</span>
      {run.done && (
        <>
          <span>·</span>
          <span>{t(stopKey(run.done.stop_reason))}</span>
        </>
      )}
    </footer>
  )
}

/* ── The page ────────────────────────────────────────────────────────────── */

export default function SaqrPage() {
  const t = useT()
  const f = useFormatters()

  const { phase, answer, error, elapsed, isRunning, run, history, ask, cancel, retry, reset } =
    useSaqrRun()
  const { tools: catalogue, failed: catalogueFailed } = useSaqrTools()

  const [draft, setDraft] = React.useState("")
  const [topMac, setTopMac] = React.useState<string | null>(null)

  const scrollRef = React.useRef<HTMLDivElement>(null)
  /** True while the viewport is at the bottom, i.e. still following the run. */
  const [following, setFollowing] = React.useState(true)

  // The busiest source MAC the sensor has stored, so the specific-MAC starter
  // question names an address that actually exists. If the call fails the chip
  // is simply absent — inventing a plausible MAC would be worse than omitting.
  React.useEffect(() => {
    let alive = true
    void apiFetchSafe<OffenderRow[]>("/top-offenders", []).then((rows) => {
      if (!alive) return
      const mac = Array.isArray(rows) ? rows.find((r) => r?.wlan_sa)?.wlan_sa : null
      if (mac) setTopMac(String(mac))
    })
    return () => {
      alive = false
    }
  }, [])

  const onScroll = React.useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    setFollowing(el.scrollHeight - el.scrollTop - el.clientHeight <= STICK_THRESHOLD_PX)
  }, [])

  const jumpToLatest = React.useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    // `scrollTop`, never `scrollIntoView`: the latter scrolls every scrollable
    // ancestor, so it drags the whole page as well as this pane.
    el.scrollTop = el.scrollHeight
    setFollowing(true)
  }, [])

  // Follow the stream only while the reader has not taken over.
  React.useEffect(() => {
    if (!following) return
    const el = scrollRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [following, run?.events.length, run?.answer, history.length, isRunning])

  const send = React.useCallback(
    (question: string) => {
      const text = question.trim()
      if (!text || isRunning) return
      setDraft("")
      setFollowing(true)
      ask(text)
    },
    [ask, isRunning]
  )

  const isEmpty = run === null && history.length === 0
  // Tokens are still arriving while the run is open and no `answer` has settled.
  const streaming = isRunning && !run?.events.some((e) => e.type === "answer")

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-3 px-4 py-6 sm:gap-4 lg:px-8">
      {/* ---- page head ---------------------------------------------------- */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-ink font-display text-2xl leading-none font-medium sm:text-3xl">
            {t("saqr.title")}
          </h1>
          <p className="text-ink-dim text-sm">{t("saqr.subtitle")}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <StatusPill tone={catalogueFailed ? "critical" : "info"} dot>
            {catalogueFailed
              ? t("saqr.status.offline")
              : t("saqr.status.tools", { n: f.number(catalogue.length) })}
          </StatusPill>

          {!isEmpty && (
            <Button size="sm" variant="secondary" onClick={reset} disabled={isRunning}>
              {t("saqr.newSession")}
            </Button>
          )}
        </div>
      </header>

      {/* ---- the console -------------------------------------------------- */}
      <Module label={t("saqr.console")} flush>
        <div className="relative">
          <div
            ref={scrollRef}
            onScroll={onScroll}
            // A bounded, self-scrolling pane: the composer stays reachable
            // without the operator scrolling the whole document to find it.
            className="flex max-h-[62vh] min-h-64 flex-col gap-4 overflow-y-auto p-3 sm:p-4"
          >
            {isEmpty ? (
              <SaqrEmptyState
                tools={catalogue}
                catalogueFailed={catalogueFailed}
                topMac={topMac}
                onPick={(question) => setDraft(question)}
              />
            ) : (
              <>
                {history.map((entry) => (
                  <TranscriptEntry key={entry.localId} run={entry} />
                ))}

                {run && (
                  <article className="flex flex-col gap-3">
                    <QuestionLine question={run.question} />

                    <SaqrTrace run={run} phase={phase} isRunning={isRunning} />

                    {(answer || streaming) && (
                      <SaqrAnswer
                        text={answer}
                        usedTools={run.usedTools}
                        streaming={streaming && answer.length > 0}
                      />
                    )}

                    {/* Nothing came back at all: the run failed before it could
                        say anything. The fault line is already in the trace;
                        this keeps the pane from ending on an empty answer box. */}
                    {!answer && !isRunning && error && (
                      <TerminalLine tone="muted" marker="·">
                        {/* font-sans: the mono face has no Arabic glyphs. */}
                        <span className="font-sans">{t("saqr.answer.none")}</span>
                      </TerminalLine>
                    )}

                    <RunFooter run={run} elapsed={elapsed} f={f} />
                  </article>
                )}
              </>
            )}
          </div>

          {!following && !isEmpty && (
            <div className="pointer-events-none absolute inset-x-0 bottom-2 flex justify-center">
              <Button
                size="sm"
                variant="secondary"
                onClick={jumpToLatest}
                className="pointer-events-auto shadow-sm"
              >
                {t("saqr.jumpToLatest")}
              </Button>
            </div>
          )}
        </div>
      </Module>

      {/* ---- controls ----------------------------------------------------- */}
      <SaqrComposer
        value={draft}
        onChange={setDraft}
        onSend={() => send(draft)}
        onCancel={cancel}
        onRetry={retry}
        isRunning={isRunning}
        canRetry={Boolean(run)}
      />

      <p className="text-ink-faint text-xs">{t("saqr.disclaimer")}</p>
    </div>
  )
}
