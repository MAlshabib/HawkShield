"use client"

/**
 * The work Saqr did — the middle section of the run document.
 *
 * V2 drew this as a terminal transcript. On paper that register is wrong: a
 * console frame on a document reads as a screenshot pasted into a report. The
 * mechanism is identical and nothing is hidden — which tool was reached for,
 * with which arguments, the literal SELECT that ran and what came back — but it
 * is set as **numbered, labelled steps**: a heading row naming the tool, the
 * arguments under it, and the result on its own hairline card.
 *
 * Everything here comes off the wire. There is no simulated typing, no
 * placeholder tool call and no demo transcript: if the stream did not send it,
 * it is not on screen.
 *
 * Four wire facts are load-bearing in here:
 *
 * - **`call_id` repeats within a run.** It is the model's own id, so the
 *   identity of an invocation is `(step, call_id)` and never the id alone.
 * - **`args` omits unset optionals** rather than sending nulls, so the argument
 *   line renders what is present and never paints a column of `null`.
 * - **`row_count` is `null` for every aggregation**, which reports its size as
 *   `group_count`. `resultCount` picks whichever answered and the wording
 *   follows it.
 * - **`data` is a capped preview, not the result.** Over the cap it becomes
 *   `{ omitted: true }`, which is stated as an omission rather than rendered as
 *   an empty table.
 *
 * IBM Plex Mono carries no Arabic at all, so every localised string set inside
 * a mono context here carries `font-sans` explicitly; conversely every Latin
 * technical run (a model id, a tool name, a SQL fragment, the backend's own
 * summary) is wrapped in `<Ltr>` so its neutral punctuation cannot mirror
 * inside an Arabic paragraph.
 */
import * as React from "react"
import { ChevronDown } from "lucide-react"

import { Eyebrow } from "@/components/hs/eyebrow"
import { Panel } from "@/components/hs/panel"
import { StatusPill } from "@/components/hs/status-pill"
import { TerminalLine } from "@/components/hs/terminal-line"
import { SaqrResultPreview, SaqrValue } from "@/components/saqr/result-preview"
import { Code, Ltr, useFormatters } from "@/lib/format"
import { useT, type Translate, type TranslationKey } from "@/lib/i18n"
import {
  failureKey,
  isOmitted,
  resultCount,
  toolLabelKey,
  type SaqrEvent,
  type SaqrFailure,
  type SaqrPhase,
  type SaqrRun,
  type SaqrToolActivity,
  type SaqrToolResultEvent,
} from "@/lib/saqr"
import { cn } from "@/lib/utils"

/** Locally narrowed members of the event union, for `find` / `filter` guards. */
type SaqrRunStartEvent = Extract<SaqrEvent, { type: "run_start" }>
type SaqrErrorEvent = Extract<SaqrEvent, { type: "error" }>

/* ── Disclosure ──────────────────────────────────────────────────────────── */

/**
 * A native `<details>`, restyled onto paper.
 *
 * Native rather than React state for two reasons: an open SQL block has to
 * survive the document re-rendering on every animation frame while tokens
 * stream, and `<details>` stays keyboard-operable and find-in-page-searchable
 * for free. The chevron points along the reading direction when closed, which
 * is why the rotation is mirrored rather than fixed.
 */
function Disclosure({
  summary,
  children,
  className,
}: {
  summary: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <details className={cn("group min-w-0", className)}>
      <summary
        className={cn(
          "hs-label text-ink-2 hover:text-ink-0 flex w-fit cursor-pointer list-none items-center gap-1.5",
          "rounded-sm transition-colors",
          "[&::-webkit-details-marker]:hidden"
        )}
      >
        <ChevronDown
          aria-hidden="true"
          className={cn(
            "size-3 shrink-0 transition-transform",
            "-rotate-90 group-open:rotate-0 rtl:rotate-90 rtl:group-open:rotate-0"
          )}
        />
        {summary}
      </summary>
      <div className="mt-2.5 min-w-0">{children}</div>
    </details>
  )
}

/* ── Arguments ───────────────────────────────────────────────────────────── */

/**
 * `tool_call.args`, exactly as sent.
 *
 * Optionals the model did not set are absent from the payload, so an empty
 * object means the tool was called with its defaults — which is worth saying in
 * words, and is not the same thing as a row of nulls.
 *
 * The whole strip is one `<Ltr>` island rather than one per pair. The `=` and
 * the separators are bidi-neutral: isolated individually they would leave the
 * glue between them taking the paragraph's RTL direction, and the argument list
 * would render in the wrong order with every character correct.
 */
function ToolArgs({ args }: { args: Record<string, unknown> }) {
  const t = useT()
  const entries = Object.entries(args ?? {})

  if (entries.length === 0) {
    return <span className="text-ink-3 text-xs">{t("saqr.doc.defaults")}</span>
  }

  return (
    <span className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
      <span className="hs-label shrink-0">{t("saqr.doc.calledWith")}</span>
      <Ltr className="min-w-0 font-mono text-xs break-words">
        {entries.map(([key, value], index) => (
          <React.Fragment key={key}>
            {index > 0 && <span className="text-ink-3">{"  ·  "}</span>}
            <span className="text-ink-2">{key}</span>
            <span className="text-ink-3">{"="}</span>
            <SaqrValue value={value} />
          </React.Fragment>
        ))}
      </Ltr>
    </span>
  )
}

/* ── One step ────────────────────────────────────────────────────────────── */

function countLabel(t: Translate, result: SaqrToolResultEvent, formatted: (n: number) => string) {
  const count = resultCount(result)
  if (count === null) return null
  // `row_count` is null for every aggregation — `resultCount` falls back to
  // `group_count`/`total`, so the wording follows whichever field answered.
  const key = typeof result.row_count === "number" ? "saqr.trace.rows" : "saqr.trace.groups"
  return t(key, { n: formatted(count) })
}

function Step({ activity }: { activity: SaqrToolActivity }) {
  const t = useT()
  const f = useFormatters()
  const result = activity.result

  const rows = result ? countLabel(t, result, f.number) : null
  const hasPreview = Boolean(
    result && !isOmitted(result.data) && Object.keys(result.data ?? {}).length > 0
  )

  return (
    <li className="flex min-w-0 flex-col gap-3">
      {/* The step head. The number is the wire's own `step`, not a running
          index: two calls the model issued in one step legitimately share it,
          and renumbering them would misreport the loop. */}
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1.5">
        <span className="hs-label text-accent-cta shrink-0">
          {t("saqr.trace.step", { n: activity.step })}
        </span>
        <span className="text-ink-0 min-w-0 text-base font-medium">
          {t(toolLabelKey(activity.labelKey))}
        </span>
        <Code className="text-ink-2 text-xs">{activity.tool}</Code>
        {activity.mutating && (
          <StatusPill tone="high">{t("saqr.trace.mutating")}</StatusPill>
        )}
      </div>

      <ToolArgs args={activity.args} />

      {!result ? (
        // The documented loading affordance: a line travelling down the card
        // that is filling in, rather than a spinner that says "somewhere".
        <Panel loading className="min-h-16">
          <span className="text-ink-2 text-sm">{t("saqr.trace.running")}</span>
        </Panel>
      ) : (
        <Panel className="min-w-0">
          <div className="flex min-w-0 flex-col gap-3">
            {/* What came back, read left to right: verdict, how long, how much. */}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              {result.ok ? (
                <Eyebrow>{t("saqr.doc.reported")}</Eyebrow>
              ) : (
                <StatusPill tone="critical">{t("saqr.trace.failed")}</StatusPill>
              )}
              <span className="hs-num text-ink-2 text-xs">
                {t("saqr.trace.duration", { ms: f.number(result.duration_ms) })}
              </span>
              {result.ok && rows && (
                <>
                  <span className="text-ink-3 text-xs" aria-hidden="true">
                    ·
                  </span>
                  <span className="text-ink-2 text-xs">{rows}</span>
                </>
              )}
              {result.cached && <StatusPill tone="info">{t("saqr.trace.cached")}</StatusPill>}
            </div>

            {/* The backend's own one-line description of the result. It is
                evidence beside the answer rather than part of it, and is
                deliberately English in both locales — so it is isolated. */}
            {result.summary && (
              <p className="min-w-0">
                <Ltr className="text-ink-1 font-mono text-xs break-words">{result.summary}</Ltr>
              </p>
            )}

            {result.error?.hint && (
              <p className="min-w-0">
                <Ltr className="text-ink-2 font-mono text-xs break-words">
                  {result.error.hint}
                </Ltr>
              </p>
            )}

            {(hasPreview || isOmitted(result.data)) && (
              <SaqrResultPreview result={result} />
            )}

            {result.sql_preview && (
              // Kept, because seeing the literal SELECT is the strongest single
              // piece of evidence that this is a real query and not a narrated
              // one — and kept quiet, because it is evidence, not the point.
              <Disclosure summary={t("saqr.trace.sql")}>
                <pre
                  dir="ltr"
                  className="bg-paper-2 border-rule overflow-x-auto rounded-md border p-3"
                >
                  <Code className="text-ink-1 text-xs whitespace-pre">{result.sql_preview}</Code>
                </pre>
              </Disclosure>
            )}
          </div>
        </Panel>
      )}
    </li>
  )
}

/* ── Notices ─────────────────────────────────────────────────────────────── */

const PHASE_KEY = {
  calling_model: "saqr.phase.calling_model",
  executing_tool: "saqr.phase.executing_tool",
  composing: "saqr.phase.composing",
} as const

/**
 * The one live line in the document. A `TerminalLine` is exactly right here and
 * nowhere else on the page: it is a line, not a window, and this is genuinely a
 * line still being written.
 */
function PhaseLine({ phase }: { phase: SaqrPhase }) {
  const t = useT()
  return (
    <TerminalLine pending tone="accent" aria-live="polite">
      {/* The mono face has no Arabic; a localised phase set in it would render
          as a row of disconnected glyphs. */}
      <span className="font-sans text-sm">{t(PHASE_KEY[phase])}</span>
    </TerminalLine>
  )
}

/**
 * An instrument fault, not a blank space and never a raw code.
 *
 * The three failure kinds are three different sentences: the server refused
 * before anything ran, the connection died part-way through, or the run itself
 * reported an error. `failureKey` picks the localised text; the raw server
 * detail is kept underneath as secondary operator text rather than shown as the
 * headline a person reads.
 */
export function SaqrFault({ failure, className }: { failure: SaqrFailure; className?: string }) {
  const t = useT()
  const detail =
    failure.kind === "agent"
      ? failure.message
      : failure.kind === "stream"
        ? failure.detail
        : `HTTP ${failure.status} · ${failure.detail}`

  return (
    <div
      role="alert"
      className={cn(
        "flex min-w-0 flex-col gap-2 rounded-lg border p-4",
        "border-[color-mix(in_oklch,var(--sev-critical)_32%,transparent)]",
        "bg-[color-mix(in_oklch,var(--sev-critical)_7%,transparent)]",
        className
      )}
    >
      <p className="text-sev-critical text-sm font-medium">{t(failureKey(failure))}</p>
      {detail && (
        <p className="min-w-0">
          <Ltr className="text-ink-2 font-mono text-xs break-words">{detail}</Ltr>
        </p>
      )}
      {failure.kind === "preflight" && failure.retryAfterS !== null && (
        <p className="text-ink-2 text-xs">
          {t("saqr.error.retryAfter", { s: failure.retryAfterS })}
        </p>
      )}
    </div>
  )
}

/** A soft, non-fatal notice: part of the record is missing but the run stands. */
function Notice({ children }: { children: React.ReactNode }) {
  return (
    <p
      className={cn(
        "rounded-md border px-3 py-2 text-xs",
        "border-[color-mix(in_oklch,var(--sev-high)_32%,transparent)]",
        "bg-[color-mix(in_oklch,var(--sev-high)_10%,transparent)]",
        "text-ink-1"
      )}
    >
      {children}
    </p>
  )
}

/* ── The work section ────────────────────────────────────────────────────── */

/**
 * Fold each `tool_call` together with its `tool_result`.
 *
 * Keyed `(step, call_id)`: the id belongs to the model and repeats within a
 * run, so keying on it alone silently merges two invocations into one row.
 */
function foldActivities(events: readonly SaqrEvent[]): SaqrToolActivity[] {
  const order: SaqrToolActivity[] = []
  const index = new Map<string, SaqrToolActivity>()

  for (const event of events) {
    if (event.type === "tool_call") {
      const key = `${event.step}:${event.call_id}`
      const activity: SaqrToolActivity = {
        key,
        step: event.step,
        callId: event.call_id,
        tool: event.tool,
        labelKey: event.label_key,
        mutating: Boolean(event.mutating),
        args: event.args ?? {},
        result: null,
      }
      index.set(key, activity)
      order.push(activity)
    } else if (event.type === "tool_result") {
      const found = index.get(`${event.step}:${event.call_id}`)
      if (found) found.result = event
    }
  }
  return order
}

export function SaqrWork({
  run,
  phase,
  isRunning,
  className,
}: {
  run: SaqrRun
  phase: SaqrPhase | null
  isRunning: boolean
  className?: string
}) {
  const t = useT()
  const f = useFormatters()

  const activities = React.useMemo(() => foldActivities(run.events), [run.events])
  // Narrowed with explicit predicates: `find`/`filter` on a discriminated union
  // return the union, and reading `.model` off it would not compile.
  const start = React.useMemo(
    () => run.events.find((event): event is SaqrRunStartEvent => event.type === "run_start"),
    [run.events]
  )
  const agentErrors = React.useMemo(
    () => run.events.filter((event): event is SaqrErrorEvent => event.type === "error"),
    [run.events]
  )

  return (
    <section className={cn("flex min-w-0 flex-col gap-4", className)}>
      <header className="border-rule flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b pb-2">
        <Eyebrow>{t("saqr.doc.work")}</Eyebrow>
        {/* The count describes the list below it, so it counts invocations and
            not loop steps. `done.steps` is the wire's own figure and is larger
            whenever the model issued two calls in one step — which it does —
            and a header reading "2 steps" over two rows both labelled "Step 1"
            is a contradiction the reader has to resolve. The loop's own step
            figure is still reported, in the footer's event tally. */}
        {activities.length > 0 && (
          <span className="hs-label ms-auto">
            {t("saqr.footer.toolCalls", { n: f.number(activities.length) })}
          </span>
        )}
      </header>

      {start && (
        <p className="text-ink-2 flex min-w-0 flex-wrap items-baseline gap-x-2.5 gap-y-1 text-xs">
          <span className="hs-label">{t("saqr.doc.model")}</span>
          <Ltr className="font-mono break-words">{start.model}</Ltr>
          <span aria-hidden="true">·</span>
          <span>{t("saqr.trace.toolsAvailable", { n: f.number(start.tools.length) })}</span>
        </p>
      )}

      {activities.length > 0 && (
        <ol className="flex min-w-0 flex-col gap-7">
          {activities.map((activity) => (
            <Step key={activity.key} activity={activity} />
          ))}
        </ol>
      )}

      {/* The honest empty case: the loop finished without reaching for a tool,
          which happens for a definitional question and is worth stating. */}
      {activities.length === 0 && !isRunning && start && !run.failure && (
        <p className="text-ink-2 text-sm">{t("saqr.doc.noWork")}</p>
      )}

      {isRunning && !start && <p className="text-ink-3 text-sm">{t("saqr.doc.awaiting")}</p>}

      {isRunning && phase && <PhaseLine phase={phase} />}

      {agentErrors.map((event, index) => (
        <SaqrFault
          key={`${event.seq}-${index}`}
          failure={{
            kind: "agent",
            code: event.code,
            message: event.message,
            fatal: Boolean(event.fatal),
          }}
        />
      ))}

      {run.gap && <Notice>{t("saqr.trace.gap")}</Notice>}

      {/* A transport failure the run itself never reported. An `error` event is
          already rendered above, in its own place in the sequence. */}
      {run.failure && run.failure.kind !== "agent" && <SaqrFault failure={run.failure} />}
    </section>
  )
}

const STOP_KEYS = {
  answered: "saqr.stop.answered",
  step_limit: "saqr.stop.step_limit",
  call_limit: "saqr.stop.call_limit",
  timeout: "saqr.stop.timeout",
  error: "saqr.stop.error",
  cancelled: "saqr.stop.cancelled",
} as const

/**
 * `stop_reason` is a server string, and a value added to the loop without a key
 * added here must not render a raw identifier — it falls back to a sentence.
 */
export function stopKey(reason: string): TranslationKey {
  return STOP_KEYS[reason as keyof typeof STOP_KEYS] ?? "saqr.stop.unknown"
}
