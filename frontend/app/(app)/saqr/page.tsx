"use client"

/**
 * Saqr — the agent console, read as a document.
 *
 * Saqr is a tool-calling agent over the detection database, and the whole point
 * of this page is that its work is *visible*: which tool it reached for, with
 * which arguments, the literal SELECT that ran, what came back, and only then
 * the answer. V2 showed exactly that as a terminal transcript. On paper the
 * register is wrong — a console frame on a document reads as a screenshot
 * pasted into a report — so the same material is set as a short report instead:
 * the question as a heading, the work as steps, the answer as prose, and a
 * footer stating what the run cost.
 *
 * Nothing is hidden to achieve that, but the weighting is now explicit: each
 * step is **one row that opens**, and the answer is the only thing on the page
 * set at reading size in full measure. The SQL, the arguments and the result
 * tables are all still here, one click into the step they belong to — and a
 * step that failed, was cached, writes data or is waiting on a confirmation
 * says so on its collapsed row, because those are the ones a reader must not
 * have to open the row to notice.
 *
 * Everything on screen came off the wire. There is no simulated typing, no
 * placeholder tool call and no canned transcript. If the stream did not send
 * it, it is not here. Which language model does the reasoning is not on the
 * wire and is not on the page: it says nothing about whether the detection it
 * reports is real, and a badge is not evidence.
 *
 * Five behaviours are deliberate and easy to get wrong:
 *
 * **Autoscroll yields to the reader.** The page follows the stream only while
 * it is already at the bottom. The moment the operator scrolls up to read a
 * result table, following stops and a control appears to resume it. A page that
 * yanks itself away mid-read is worse than no autoscroll at all. It is driven
 * by `scrollTop` on the scrolling element and never by `scrollIntoView`, which
 * scrolls *every* scrollable ancestor and would drag unrelated containers.
 *
 * **A run can be stopped.** `cancel()` aborts the request; the backend sees the
 * disconnect and collects the run rather than continuing to bill for it.
 *
 * **Failures are three different sentences.** The server refusing before
 * anything ran, the connection dying part-way, and the run reporting its own
 * error are not the same event and are not reported as one.
 *
 * **The question carries the UI locale**, which `lib/saqr.ts` puts in the
 * request body, so Saqr answers in the language the operator is reading — which
 * is also why the starter questions are offered in that language and only that
 * language.
 *
 * **A destructive action is never taken without a click.** An admin-gated tool
 * answers with a plan and a one-shot token instead of acting; the card that
 * spends the token is rendered outside the collapsed region, and nothing in
 * this page or in `lib/saqr.ts` reaches the confirm path on its own.
 */
import * as React from "react"

import { AccentWord } from "@/components/hs/accent-word"
import { Eyebrow } from "@/components/hs/eyebrow"
import { SectionHead } from "@/components/hs/section-head"
import { StatusPill } from "@/components/hs/status-pill"
import { SaqrComposer } from "@/components/saqr/composer"
import { SaqrEmptyState } from "@/components/saqr/empty-state"
import { SaqrRunArchive, SaqrRunDocument } from "@/components/saqr/run"
import type { SaqrConfirmBinding } from "@/components/saqr/work"
import { Button } from "@/components/ui/button"
import { apiFetchSafe } from "@/lib/api"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import {
  advertisedTools,
  STICK_THRESHOLD_PX,
  useSaqrRun,
  useSaqrTools,
  type SaqrRun,
} from "@/lib/saqr"

/** `/top-offenders` — reused rather than adding an endpoint for one chip. */
type OffenderRow = { wlan_sa?: string | null; count?: number }

/**
 * The element that actually scrolls the document.
 *
 * `document.scrollingElement` is `<html>` in standards mode and `<body>` in
 * quirks mode; reading it rather than assuming one is what keeps this correct
 * if the page is ever served without a doctype.
 */
function scroller(): Element | null {
  if (typeof document === "undefined") return null
  return document.scrollingElement ?? document.documentElement
}

export default function SaqrPage() {
  const t = useT()
  const f = useFormatters()

  const {
    phase,
    answer,
    elapsed,
    isRunning,
    run,
    history,
    confirmations,
    confirmAction,
    dismissAction,
    ask,
    cancel,
    retry,
    reset,
  } = useSaqrRun()
  const { tools: catalogue, failed: catalogueFailed } = useSaqrTools()

  // The count has to describe the same set the empty state lists, or the
  // header contradicts the page under it. `advertisedTools` drops the writing
  // tools: they are gated behind the admin header server-side and are not
  // something to name on a console a visitor is reading.
  const advertised = React.useMemo(() => advertisedTools(catalogue), [catalogue])

  /**
   * What a confirmation card needs, bound to the run it belongs to.
   *
   * Per-run rather than per-page: confirming re-sends **that** run's question
   * with the token, and an archived card that re-sent the newest question
   * instead would authorise an action the operator never read.
   */
  const confirmBinding = React.useCallback(
    (entry: SaqrRun): SaqrConfirmBinding => ({
      question: entry.question,
      states: confirmations,
      busy: isRunning,
      onConfirm: confirmAction,
      onCancel: dismissAction,
    }),
    [confirmations, isRunning, confirmAction, dismissAction]
  )

  const [draft, setDraft] = React.useState("")
  const [topMac, setTopMac] = React.useState<string | null>(null)
  /** True while the page is at the bottom, i.e. still following the run. */
  const [following, setFollowing] = React.useState(true)

  // The busiest source MAC the sensor has stored, so the specific-MAC starter
  // question names an address that actually exists. If the call fails the chip
  // is simply absent — inventing a plausible MAC would be worse than omitting.
  React.useEffect(() => {
    let alive = true
    void apiFetchSafe<OffenderRow[]>("/top-offenders", []).then((rows) => {
      if (!alive) return
      const mac = Array.isArray(rows) ? rows.find((row) => row?.wlan_sa)?.wlan_sa : null
      if (mac) setTopMac(String(mac))
    })
    return () => {
      alive = false
    }
  }, [])

  // Following is a fact about where the page is, so it is recomputed from the
  // scroll position rather than tracked as a gesture — a keyboard End, a
  // scrollbar drag and a wheel all have to reach the same conclusion.
  React.useEffect(() => {
    const onScroll = () => {
      const el = scroller()
      if (!el) return
      setFollowing(el.scrollHeight - el.scrollTop - el.clientHeight <= STICK_THRESHOLD_PX)
    }
    window.addEventListener("scroll", onScroll, { passive: true })
    return () => window.removeEventListener("scroll", onScroll)
  }, [])

  const jumpToLatest = React.useCallback(() => {
    const el = scroller()
    if (!el) return
    el.scrollTop = el.scrollHeight
    setFollowing(true)
  }, [])

  // Follow the stream only while the reader has not taken over. When they have,
  // this is a no-op by construction: `following` is false until they come back.
  //
  // Gated on there being a run at all: without it the very first paint scrolls
  // the empty state — a page of tool descriptions and starter questions nobody
  // has read yet — straight to its own bottom.
  React.useEffect(() => {
    if (!following || !run) return
    const el = scroller()
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [following, run, run?.events.length, run?.answer, history.length, isRunning])

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

  return (
    <div className="mx-auto flex w-full max-w-[980px] min-w-0 flex-col px-4 pt-10 pb-6 sm:px-6 lg:px-8">
      <SectionHead
        as="h1"
        eyebrow={t("saqr.title")}
        title={
          <>
            {t("saqr.head.lead")} <AccentWord>{t("saqr.head.accent")}</AccentWord>.
          </>
        }
        body={t("saqr.subtitle")}
        actions={
          <>
            <StatusPill tone={catalogueFailed ? "critical" : "info"} dot>
              {catalogueFailed
                ? t("saqr.status.offline")
                : t("saqr.status.tools", { n: f.number(advertised.length) })}
            </StatusPill>
            {!isEmpty && (
              <Button size="sm" variant="outline" onClick={reset} disabled={isRunning}>
                {t("saqr.newSession")}
              </Button>
            )}
          </>
        }
      />

      <div className="mt-14 flex min-w-0 flex-col gap-14">
        {isEmpty ? (
          <SaqrEmptyState
            tools={catalogue}
            catalogueFailed={catalogueFailed}
            topMac={topMac}
            onPick={(question) => setDraft(question)}
          />
        ) : (
          <>
            {history.length > 0 && (
              <section className="flex min-w-0 flex-col gap-10">
                <Eyebrow>{t("saqr.doc.earlier")}</Eyebrow>
                {history.map((entry) => (
                  <SaqrRunArchive
                    key={entry.localId}
                    run={entry}
                    confirm={confirmBinding(entry)}
                    className="border-rule border-b pb-10 last:border-b-0 last:pb-0"
                  />
                ))}
              </section>
            )}

            {run && (
              <SaqrRunDocument
                run={run}
                phase={phase}
                isRunning={isRunning}
                answer={answer}
                elapsed={elapsed}
                confirm={confirmBinding(run)}
              />
            )}
          </>
        )}
      </div>

      {/* The composer floats on the same elevation tier as the nav pill, so the
          control stays reachable however long the document grows. It is in flow
          and merely sticky, which is why nothing below needs a spacer. */}
      <div className="sticky bottom-4 z-30 mt-14 flex min-w-0 flex-col items-center gap-2">
        {!following && !isEmpty && (
          <Button size="sm" variant="secondary" className="hs-float" onClick={jumpToLatest}>
            {t("saqr.jumpToLatest")}
          </Button>
        )}
        <SaqrComposer
          className="w-full"
          value={draft}
          onChange={setDraft}
          onSend={() => send(draft)}
          onCancel={cancel}
          onRetry={retry}
          isRunning={isRunning}
          canRetry={Boolean(run)}
        />
      </div>

      <p className="text-ink-3 mt-6 text-xs">{t("saqr.disclaimer")}</p>
    </div>
  )
}
