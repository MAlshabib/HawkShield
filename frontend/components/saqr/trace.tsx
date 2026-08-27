"use client"

/**
 * The run trace — the centrepiece of the console.
 *
 * Everything here comes off the wire. There is no simulated typing, no
 * placeholder tool call and no demo transcript: if the stream did not send it,
 * it is not on screen.
 *
 * The idiom is a terminal transcript rather than chat bubbles, because what a
 * judge needs to see is the *mechanism* — which tool was reached for, with
 * which arguments, what SQL it actually ran, and what came back. A bubble hides
 * all four behind a sentence.
 *
 * Two wire facts are load-bearing in here:
 *
 * - **`call_id` repeats within a run.** It is the model's own id. Every row is
 *   keyed `(step, call_id)`, which `lib/saqr.ts` folds for us.
 * - **`args` omits unset optionals** rather than sending nulls, so the argument
 *   strip renders what is present and never paints a column of `null`.
 */
import * as React from "react"
import { ChevronDown } from "lucide-react"

import { SaqrResultPreview, SaqrValue } from "@/components/saqr/result-preview"
import { StatusPill } from "@/components/hs/status-pill"
import { TerminalLine, type TerminalTone } from "@/components/hs/terminal-line"
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

/**
 * IBM Plex Mono carries no Arabic coverage, and `TerminalLine` is `font-mono`
 * by construction. Every localised string rendered inside one therefore carries
 * `font-sans` explicitly, or an Arabic console renders it as a row of
 * disconnected, unjoined glyphs — `globals.css` corrects this for `.hs-label`,
 * but nothing corrects a bare mono line. Latin technical runs (a model id, a
 * tool name, a SQL fragment, a backend summary) keep `font-mono` for the same
 * reason, spelled out rather than inherited.
 */

/* ── Disclosure ──────────────────────────────────────────────────────────── */

/**
 * A native `<details>`, restyled.
 *
 * Native rather than React state because a collapsed SQL preview has to survive
 * the trace re-rendering on every animation frame while tokens stream, and
 * because it stays keyboard- and search-accessible for free. The chevron points
 * along the reading direction when closed, hence the `rtl:` mirror.
 */
function Disclosure({
  summary,
  children,
  defaultOpen = false,
}: {
  summary: React.ReactNode
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  return (
    <details className="group min-w-0" open={defaultOpen}>
      <summary
        className={cn(
          "hs-label text-ink-dim hover:text-ink flex cursor-pointer list-none items-center gap-1.5",
          "focus-visible:outline-hs-azure rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2",
          "[&::-webkit-details-marker]:hidden"
        )}
      >
        <ChevronDown
          aria-hidden="true"
          className={cn(
            "size-3 shrink-0 transition-transform",
            "-rotate-90 rtl:rotate-90 group-open:rotate-0 rtl:group-open:rotate-0"
          )}
        />
        {summary}
      </summary>
      <div className="mt-2 min-w-0">{children}</div>
    </details>
  )
}

/* ── Arguments ───────────────────────────────────────────────────────────── */

/**
 * `tool_call.args`, exactly as sent.
 *
 * Optionals the model did not set are absent from the payload, so an empty
 * strip means the tool was called with its defaults — which is worth seeing,
 * and is not the same thing as a row of nulls.
 */
function ToolArgs({ args }: { args: Record<string, unknown> }) {
  const entries = Object.entries(args ?? {})
  if (entries.length === 0) return <span className="text-ink-faint">()</span>

  return (
    <span className="text-ink-faint inline">
      {/* The parentheses, commas and equals signs are bidi-neutral, so under an
          Arabic page they take the paragraph's direction and the whole call
          renders backwards — `(10=top_n ,label=group_by)`. The caller wraps
          this and the tool name in one `<Ltr>` run, which fixes the lot. */}
      {"("}
      {entries.map(([key, value], index) => (
        <React.Fragment key={key}>
          {index > 0 && <span>{", "}</span>}
          <Ltr className="text-ink-dim font-mono">{key}</Ltr>
          <span>{"="}</span>
          <SaqrValue value={value} />
        </React.Fragment>
      ))}
      {")"}
    </span>
  )
}

/* ── One tool invocation ─────────────────────────────────────────────────── */

function countLabel(t: Translate, result: SaqrToolResultEvent, formatted: (n: number) => string) {
  const count = resultCount(result)
  if (count === null) return null
  // `row_count` is null for every aggregation — `resultCount` falls back to
  // `group_count`/`total`, so the wording follows which field answered.
  const key = typeof result.row_count === "number" ? "saqr.trace.rows" : "saqr.trace.groups"
  return t(key, { n: formatted(count) })
}

function ToolBlock({ activity }: { activity: SaqrToolActivity }) {
  const t = useT()
  const f = useFormatters()
  const result = activity.result

  const label = t(toolLabelKey(activity.labelKey))
  const stamp = `${activity.step}`

  const hasPreview = Boolean(
    result && !isOmitted(result.data) && Object.keys(result.data ?? {}).length > 0
  )

  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <TerminalLine stamp={stamp} tone={activity.mutating ? "high" : "accent"} marker="»">
        <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="text-ink font-sans">{label}</span>
          {/* `tool(args…)` is one technical expression and is isolated as one:
              its punctuation is bidi-neutral and would otherwise mirror. */}
          <Ltr className="min-w-0 font-mono">
            <Code className="text-hs-azure">{activity.tool}</Code>
            <ToolArgs args={activity.args} />
          </Ltr>
          {activity.mutating && (
            <StatusPill tone="high" className="text-[10px]">
              {t("saqr.trace.mutating")}
            </StatusPill>
          )}
        </span>
      </TerminalLine>

      {!result ? (
        <TerminalLine depth={1} pending tone="muted">
          <span className="font-sans">{t("saqr.trace.running")}</span>
        </TerminalLine>
      ) : (
        <>
          <TerminalLine depth={1} marker="‹" tone={result.ok ? "muted" : "critical"}>
            <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              {!result.ok && (
                <span className="text-sev-critical font-sans">{t("saqr.trace.failed")}</span>
              )}
              {/* The summary is the backend's own one-line description of the
                  result. It is a debugging affordance beside the answer, not
                  part of it, and is deliberately English in both locales. */}
              <Ltr className="font-mono">{result.summary}</Ltr>
              {result.ok && countLabel(t, result, f.number) && (
                <span className="text-ink-faint font-sans">· {countLabel(t, result, f.number)}</span>
              )}
              <span className="text-ink-faint font-sans">
                · {t("saqr.trace.duration", { ms: f.number(result.duration_ms) })}
              </span>
              {result.cached && (
                <StatusPill tone="info" className="text-[10px]">
                  {t("saqr.trace.cached")}
                </StatusPill>
              )}
            </span>
          </TerminalLine>

          {result.error?.hint && (
            <TerminalLine depth={1} marker="·" tone="muted">
              <Ltr className="font-mono">{result.error.hint}</Ltr>
            </TerminalLine>
          )}

          {(result.sql_preview || hasPreview || isOmitted(result.data)) && (
            <div className="flex min-w-0 flex-col gap-2 ps-[3ch]">
              {result.sql_preview && (
                <Disclosure summary={t("saqr.trace.sql")}>
                  {/* Seeing the literal SELECT is the strongest single piece of
                      evidence that this is a real query and not a narrated one. */}
                  <pre
                    dir="ltr"
                    className="bg-surface-sunken border-hairline overflow-x-auto rounded-sm border p-2.5"
                  >
                    <Code className="text-ink-dim text-xs whitespace-pre">
                      {result.sql_preview}
                    </Code>
                  </pre>
                </Disclosure>
              )}

              {(hasPreview || isOmitted(result.data)) && (
                <Disclosure summary={t("saqr.trace.result")}>
                  <SaqrResultPreview result={result} />
                </Disclosure>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

/* ── Non-tool lines ──────────────────────────────────────────────────────── */

const PHASE_KEY = {
  calling_model: "saqr.phase.calling_model",
  executing_tool: "saqr.phase.executing_tool",
  composing: "saqr.phase.composing",
} as const

function PhaseIndicator({ phase }: { phase: SaqrPhase }) {
  const t = useT()
  return (
    <TerminalLine pending tone="accent" aria-live="polite">
      <span className="font-sans">{t(PHASE_KEY[phase])}</span>
    </TerminalLine>
  )
}

/**
 * An instrument fault, not a blank bubble and not a raw code.
 *
 * The three failure kinds are three different sentences: the server refused
 * before anything ran, the connection died part-way through, or the run itself
 * reported an error. `failureKey` picks the localised text; the raw server
 * detail is kept as secondary operator text underneath.
 */
export function SaqrFault({ failure }: { failure: SaqrFailure }) {
  const t = useT()
  const detail =
    failure.kind === "agent"
      ? failure.message
      : failure.kind === "stream"
        ? failure.detail
        : `HTTP ${failure.status} · ${failure.detail}`

  return (
    <div className="border-sev-critical/40 bg-sev-critical/5 flex flex-col gap-1 rounded-sm border p-3">
      <TerminalLine marker="!" tone="critical">
        <span className="font-sans">{t(failureKey(failure))}</span>
      </TerminalLine>
      {detail && (
        <TerminalLine depth={1} marker="·" tone="muted">
          <Ltr className="text-ink-faint font-mono">{detail}</Ltr>
        </TerminalLine>
      )}
      {failure.kind === "preflight" && failure.retryAfterS !== null && (
        <TerminalLine depth={1} marker="·" tone="muted">
          <span className="font-sans">{t("saqr.error.retryAfter", { s: failure.retryAfterS })}</span>
        </TerminalLine>
      )}
    </div>
  )
}

/* ── The trace ───────────────────────────────────────────────────────────── */

const TONE_BY_STOP: Record<string, TerminalTone> = {
  answered: "muted",
  step_limit: "high",
  call_limit: "high",
  timeout: "high",
  error: "critical",
  cancelled: "muted",
}

export function SaqrTrace({
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

  /**
   * Walk the events in arrival order and render each one in place.
   *
   * `status` lines are shown for `calling_model` and `composing` only. Every
   * `executing_tool` is immediately followed by the `tool_call` it announces,
   * and that call renders its own line — printing both would double every tool
   * in the trace. Nothing is dropped from the record: the footer reports the
   * total event count, and the live indicator shows `executing_tool` while it
   * is the current phase.
   */
  const lines: React.ReactNode[] = []

  /**
   * Fold each `tool_call` together with its `tool_result` before walking, so a
   * block can be emitted at the position of its call with the result already
   * attached. Keyed `(step, call_id)`: the id alone is the model's and repeats,
   * and keying on it would merge two invocations into one row.
   */
  const activityByKey = new Map<string, SaqrToolActivity>()
  for (const event of run.events) {
    if (event.type === "tool_call") {
      activityByKey.set(`${event.step}:${event.call_id}`, {
        key: `${event.step}:${event.call_id}`,
        step: event.step,
        callId: event.call_id,
        tool: event.tool,
        labelKey: event.label_key,
        mutating: Boolean(event.mutating),
        args: event.args ?? {},
        result: null,
      })
    } else if (event.type === "tool_result") {
      const found = activityByKey.get(`${event.step}:${event.call_id}`)
      if (found) found.result = event
    }
  }

  run.events.forEach((event: SaqrEvent, index) => {
    const key = `${event.seq}-${index}`
    switch (event.type) {
      case "run_start":
        lines.push(
          <TerminalLine key={key} tone="muted" marker="·">
            <span className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-sans">{t("saqr.trace.started")}</span>
              <Ltr className="text-ink-faint font-mono">{event.model}</Ltr>
              <span className="text-ink-faint font-sans">
                · {t("saqr.trace.toolsAvailable", { n: f.number(event.tools.length) })}
              </span>
            </span>
          </TerminalLine>
        )
        break

      case "status":
        if (event.phase === "executing_tool") break
        lines.push(
          <TerminalLine key={key} tone="muted" marker="·">
            <span className="font-sans">{t(PHASE_KEY[event.phase])}</span>
          </TerminalLine>
        )
        break

      case "tool_call": {
        const activity = activityByKey.get(`${event.step}:${event.call_id}`)
        if (activity) lines.push(<ToolBlock key={key} activity={activity} />)
        break
      }

      case "error":
        lines.push(<SaqrFault key={key} failure={{ kind: "agent", ...event }} />)
        break

      default:
        // `tool_result` is rendered inside its call's block; `answer` and `done`
        // are the answer pane and the footer, not trace lines.
        break
    }
  })

  return (
    <div className={cn("flex min-w-0 flex-col gap-2.5", className)}>
      {lines}

      {isRunning && phase && <PhaseIndicator phase={phase} />}

      {run.gap && (
        <TerminalLine marker="!" tone="high">
          <span className="font-sans">{t("saqr.trace.gap")}</span>
        </TerminalLine>
      )}

      {/* A transport failure the run itself never reported. An `error` event is
          already rendered above, in its own place in the sequence. */}
      {run.failure && run.failure.kind !== "agent" && <SaqrFault failure={run.failure} />}

      {run.done && (
        <TerminalLine tone={TONE_BY_STOP[run.done.stop_reason] ?? "muted"} marker="·">
          <span className="font-sans">{t(stopKey(run.done.stop_reason))}</span>
        </TerminalLine>
      )}

      {!run.done && !isRunning && !run.failure && (
        <TerminalLine tone="muted" marker="·">
          <span className="font-sans">{t("saqr.stop.cancelled")}</span>
        </TerminalLine>
      )}
    </div>
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
