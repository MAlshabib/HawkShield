"use client"

/**
 * The work Saqr did — the middle section of the run document.
 *
 * V2 drew this as a terminal transcript. On paper that register is wrong: a
 * console frame on a document reads as a screenshot pasted into a report. The
 * mechanism is identical and nothing is hidden — which tool was reached for,
 * with which arguments, the literal SELECT that ran and what came back — but it
 * is set as **numbered, labelled steps**.
 *
 * Each step is now **one row that opens**. Every step used to render its
 * arguments, its result panel, its table and its SQL inline, and the effect was
 * that the answer — the thing a reader actually came for — arrived after two
 * screens of evidence. So the evidence is one click away instead of in the way:
 * a summary row carries the step number, the tool, a one-line result and the
 * duration, and opening it reveals the arguments, the result table and the SQL.
 *
 * What a reader must not have to open the row to learn is **on** the row: a
 * step that **failed**, one that was answered from **cache**, one that
 * **writes data**, and one that is **waiting for a confirmation** all say so
 * while collapsed. Those are precisely the steps somebody needs to notice, and
 * a disclosure that hides them is a disclosure that lies by omission.
 *
 * A confirmation card is never inside the collapsed region. Consent that has to
 * be found is not consent.
 *
 * Everything here comes off the wire. There is no simulated typing, no
 * placeholder tool call and no demo transcript: if the stream did not send it,
 * it is not on screen. Which language model answers is **not** on the wire and
 * is not on screen either.
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
 * technical run (a tool name, a SQL fragment, the backend's own summary) is
 * wrapped in `<Ltr>` so its neutral punctuation cannot mirror inside an Arabic
 * paragraph.
 */
import * as React from "react"
import { ChevronDown } from "lucide-react"

import { Eyebrow } from "@/components/hs/eyebrow"
import { StatusPill } from "@/components/hs/status-pill"
import { TerminalLine } from "@/components/hs/terminal-line"
import { CollapsibleRegion } from "@/components/saqr/collapsible"
import { SaqrConfirmCard } from "@/components/saqr/confirm"
import { SaqrResultPreview, SaqrValue } from "@/components/saqr/result-preview"
import { Code, Ltr, useFormatters } from "@/lib/format"
import { useT, type Translate, type TranslationKey } from "@/lib/i18n"
import {
  deletedCount,
  failureKey,
  isOmitted,
  readConfirmation,
  resultCount,
  toolErrorKey,
  toolLabelKey,
  type SaqrConfirmState,
  type SaqrEvent,
  type SaqrFailure,
  type SaqrPhase,
  type SaqrRun,
  type SaqrToolActivity,
  type SaqrToolResultEvent,
} from "@/lib/saqr"
import { cn } from "@/lib/utils"

/** Locally narrowed members of the event union, for `find` / `filter` guards. */
type SaqrErrorEvent = Extract<SaqrEvent, { type: "error" }>

/**
 * Everything a step needs to offer a confirmation, in one prop.
 *
 * Optional throughout: with today's backend no result carries a confirmation,
 * so nothing here is reachable and nothing renders. It is wired now so that the
 * day the field appears on the wire the card appears with it, rather than the
 * page quietly performing a destructive action or quietly dropping it.
 */
export type SaqrConfirmBinding = {
  /** The question the action belongs to; re-sent verbatim with the token. */
  question: string
  /** Where each token stands, keyed by the token itself. */
  states: Record<string, SaqrConfirmState>
  /** A run is open, so a confirmation would be refused. */
  busy: boolean
  onConfirm: (token: string, question: string) => void
  onCancel: (token: string) => void
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

function Step({
  activity,
  confirm,
}: {
  activity: SaqrToolActivity
  confirm?: SaqrConfirmBinding
}) {
  const t = useT()
  const f = useFormatters()
  // React state rather than a native `<details>`: the open height is animated
  // from `0fr` to `1fr`, which needs the content measured, and `<details>` does
  // not render its content while closed. The state survives the document
  // re-rendering on every animation frame while tokens stream, because the row
  // is keyed `(step, call_id)` and is never remounted.
  const [open, setOpen] = React.useState(false)
  const regionId = React.useId()

  const result = activity.result
  const rows = result ? countLabel(t, result, f.number) : null
  const hasPreview = Boolean(
    result && !isOmitted(result.data) && Object.keys(result.data ?? {}).length > 0
  )
  const confirmation = readConfirmation(result)
  const confirmState = confirmation?.token ? confirm?.states[confirmation.token] : undefined
  const awaitingConfirmation = Boolean(confirmation) && confirmState === undefined
  // The count of rows a destructive tool actually removed. Present only on
  // the call a person authorised; a proposal carries an estimate instead.
  const deleted = deletedCount(result)
  // A localised sentence for a tool-level refusal, when the code is one this
  // build knows. Otherwise the server's own text stands.
  const errorKey = result?.ok === false ? toolErrorKey(result.error?.code) : null

  // The one line a reader gets without opening the row.
  //
  // A **proposal takes precedence over every other line**, including the
  // backend's own summary. `summary` on a proposal is phrased conditionally
  // — "would delete 128 rows" — and a reader scanning a column of rows reads
  // the number, not the mood of the verb. Saying it in words is the only way
  // this row cannot be mistaken for a deletion that happened.
  const serverLine = result?.summary?.trim() ?? ""
  const headline = confirmation ? t("saqr.confirm.proposalRow") : serverLine

  return (
    <li className="flex min-w-0 flex-col gap-2">
      <h3 className="min-w-0">
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          aria-expanded={open}
          aria-controls={regionId}
          className={cn(
            "border-rule-soft bg-paper-1 hs-elev group flex w-full min-w-0 items-start gap-3",
            "rounded-lg border px-3 py-2.5 text-start transition-colors",
            "hover:bg-paper-2",
            // The row is a heading and a control at once; the label spells out
            // which of the two actions the click performs.
            "cursor-pointer"
          )}
        >
          <ChevronDown
            aria-hidden="true"
            className={cn(
              "text-ink-2 mt-1 size-3.5 shrink-0 transition-transform duration-200",
              "motion-reduce:transition-none",
              open ? "rotate-0" : "-rotate-90 rtl:rotate-90"
            )}
          />

          <span className="flex min-w-0 flex-1 flex-col gap-1.5">
            {/* The number is the wire's own `step`, not a running index: two
                calls the model issued in one step legitimately share it, and
                renumbering them would misreport the loop. */}
            <span className="flex min-w-0 flex-wrap items-baseline gap-x-2.5 gap-y-1.5">
              <span className="hs-label text-accent-cta shrink-0">
                {t("saqr.trace.step", { n: activity.step })}
              </span>
              <span className="text-ink-0 min-w-0 text-sm font-medium">
                {t(toolLabelKey(activity.labelKey))}
              </span>
              <Code className="text-ink-2 hidden text-xs sm:inline">{activity.tool}</Code>

              {/* The four states a reader must not have to open the row to see. */}
              {activity.mutating && (
                <StatusPill tone="high">{t("saqr.trace.mutating")}</StatusPill>
              )}
              {awaitingConfirmation && (
                <StatusPill tone="high" dot>
                  {t("saqr.confirm.pending")}
                </StatusPill>
              )}
              {result && !result.ok && (
                <StatusPill tone="critical">{t("saqr.trace.failed")}</StatusPill>
              )}
              {/* A real deletion, and only ever a real one: `deleted` appears
                  on the authorised call and never on the proposal. */}
              {deleted !== null && (
                <StatusPill tone="critical" variant="solid">
                  {t("saqr.confirm.deleted", { n: f.number(deleted) })}
                </StatusPill>
              )}
              {result?.cached && <StatusPill tone="info">{t("saqr.trace.cached")}</StatusPill>}
              {!result && (
                <StatusPill tone="info" live>
                  {t("saqr.trace.running")}
                </StatusPill>
              )}
            </span>

            {/* One line, always one line. The backend's summary is English in
                both locales, so it is a mono Latin island; it is clipped rather
                than wrapped, because a summary row that grows to four lines is
                not a summary row. */}
            <span className="text-ink-2 block min-w-0 truncate text-xs">
              {headline ? (
                <Ltr className="font-mono">{headline}</Ltr>
              ) : result ? (
                (rows ?? t(result.ok ? "saqr.step.done" : "saqr.trace.failed"))
              ) : (
                t("saqr.step.pending")
              )}
            </span>
          </span>

          <span className="flex shrink-0 flex-col items-end gap-1.5">
            {result && (
              <span className="hs-num text-ink-2 text-xs">
                {t("saqr.trace.duration", { ms: f.number(result.duration_ms) })}
              </span>
            )}
            {/* The accessible name of the toggle. Visually redundant with the
                chevron, which is why it is only here. */}
            <span className="sr-only">{open ? t("saqr.step.close") : t("saqr.step.open")}</span>
          </span>
        </button>
      </h3>

      {/* Consent is never behind a disclosure. This card sits outside the
          collapsible region on purpose: a destructive action a reader has to go
          looking for is a destructive action they will confirm without reading. */}
      {confirmation && confirm && (
        <SaqrConfirmCard
          confirmation={confirmation}
          question={confirm.question}
          state={confirmState}
          busy={confirm.busy}
          onConfirm={confirm.onConfirm}
          onCancel={confirm.onCancel}
        />
      )}

      {/* The disclosure itself — see `collapsible.tsx` for why it is built this
          way rather than as a native `<details>`. */}
      <CollapsibleRegion
        id={regionId}
        open={open}
        // The hairline is the only thing tying the detail to the row above it,
        // and it is drawn on the inline-start edge in both directions because
        // `border-s` is logical.
        // `ms-5` puts the rule under the chevron column and `ps-4` brings the
        // detail's text back out to where the row's own label sits, so the
        // opened block reads as a continuation of the row rather than as a
        // second card that happens to be underneath it.
        innerClassName="border-rule ms-5 flex flex-col gap-3 border-s ps-4 pt-3 pb-2"
      >
        <ToolArgs args={activity.args} />

        {!result ? (
          <p className="text-ink-3 text-xs">{t("saqr.trace.running")}</p>
        ) : (
          <>
            {/* What came back: the verdict, and how much of it there was. The
                duration is on the collapsed row and is not repeated here. */}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              {result.ok ? (
                <Eyebrow>{t("saqr.doc.reported")}</Eyebrow>
              ) : (
                <StatusPill tone="critical">{t("saqr.trace.failed")}</StatusPill>
              )}
              {result.ok && rows && <span className="text-ink-2 text-xs">{rows}</span>}
            </div>

            {/* The refusal in the reader's language, with the server's own
                English kept underneath as operator text rather than shown as
                the headline a person reads. */}
            {errorKey && <p className="text-ink-1 text-sm">{t(errorKey)}</p>}

            {(result.error?.message || result.error?.hint) && (
              <p className="min-w-0">
                <Ltr className="text-ink-2 font-mono text-xs break-words">
                  {[result.error?.message, result.error?.hint].filter(Boolean).join(" — ")}
                </Ltr>
              </p>
            )}

            {/* The server's own sentence about the result. On a proposal it is
                the conditional "would delete…" wording, which belongs here
                beside the card and not on the collapsed row. */}
            {serverLine && (
              <p className="min-w-0">
                <Ltr className="text-ink-1 font-mono text-xs break-words">{serverLine}</Ltr>
              </p>
            )}

            {(hasPreview || isOmitted(result.data)) && <SaqrResultPreview result={result} />}

            {result.sql_preview && (
              // The literal SELECT is the strongest single piece of evidence
              // that this is a real query and not a narrated one, so once the
              // step is open it is shown rather than hidden behind a second
              // disclosure inside the first.
              <div className="flex min-w-0 flex-col gap-1.5">
                <span className="hs-label">{t("saqr.trace.sql")}</span>
                {/* `tabIndex` is what makes a scrolling region reachable from
                    the keyboard; the block scrolls itself so the document
                    column never widens. */}
                <pre
                  dir="ltr"
                  tabIndex={0}
                  className="bg-paper-2 border-rule overflow-x-auto rounded-md border p-3"
                >
                  <Code className="text-ink-1 text-xs whitespace-pre">{result.sql_preview}</Code>
                </pre>
              </div>
            )}
          </>
        )}
      </CollapsibleRegion>
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
  confirm,
  className,
}: {
  run: SaqrRun
  phase: SaqrPhase | null
  isRunning: boolean
  confirm?: SaqrConfirmBinding
  className?: string
}) {
  const t = useT()
  const f = useFormatters()

  const activities = React.useMemo(() => foldActivities(run.events), [run.events])
  const started = React.useMemo(
    () => run.events.some((event) => event.type === "run_start"),
    [run.events]
  )
  // Narrowed with an explicit predicate: `filter` on a discriminated union
  // returns the union, and reading `.code` off it would not compile.
  const agentErrors = React.useMemo(
    () => run.events.filter((event): event is SaqrErrorEvent => event.type === "error"),
    [run.events]
  )

  return (
    <section className={cn("flex min-w-0 flex-col gap-3", className)}>
      <header className="border-rule flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b pb-2">
        <Eyebrow>{t("saqr.doc.work")}</Eyebrow>
        {/* The count describes the list below it, so it counts invocations and
            not loop steps. `done.steps` is the wire's own figure and is larger
            whenever the model issued two calls in one step — which it does —
            and a header reading "2 steps" over two rows both labelled "Step 1"
            is a contradiction the reader has to resolve. The loop's own step
            figure is still reported, in the footer's event tally. */}
        {/* Descriptive, not a capability. The server decided this before the
            run started and reported it; the console repeats it so a reader
            knows why a step could touch data, and nothing here reads it back
            as permission for anything. */}
        {run.isAdmin && <StatusPill tone="high">{t("saqr.doc.operator")}</StatusPill>}
        {activities.length > 0 && (
          <span className="hs-label ms-auto">
            {t("saqr.footer.toolCalls", { n: f.number(activities.length) })}
          </span>
        )}
      </header>

      {activities.length > 0 && (
        <ol className="flex min-w-0 flex-col gap-2">
          {activities.map((activity) => (
            <Step key={activity.key} activity={activity} confirm={confirm} />
          ))}
        </ol>
      )}

      {/* The honest empty case: the loop finished without reaching for a tool,
          which happens for a definitional question and is worth stating. */}
      {activities.length === 0 && !isRunning && started && !run.failure && (
        <p className="text-ink-2 text-sm">{t("saqr.doc.noWork")}</p>
      )}

      {isRunning && !started && <p className="text-ink-3 text-sm">{t("saqr.doc.awaiting")}</p>}

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
