"use client"

/**
 * The Saqr wire: `POST /agent/ask` as a live Server-Sent Event stream.
 *
 * `EventSource` is not usable here — it can only issue a GET, and the run *is*
 * the response body of a POST (the backend chose that deliberately: no run
 * registry, no GC timer, no orphaned run when a tab closes). So this module
 * does the three things `EventSource` would otherwise have done for us:
 * `fetch` + `ReadableStream`, a frame parser, and an `AbortController` for
 * cancellation.
 *
 * Five properties of the stream shape everything below, and each one is a bug
 * if it is assumed away:
 *
 * 1. **Pre-flight happens before the stream opens.** A 503 (no key / disabled),
 *    429 (rate limit) or 400 (bad body) comes back as `application/json` even
 *    though we asked for `text/event-stream`. `response.ok` *and*
 *    `content-type` are both checked before a reader is ever attached.
 * 2. **Keep-alives are SSE comments (`: ka`), not events.** A block whose lines
 *    all begin `:` is discarded; it never reaches `JSON.parse`.
 * 3. **`done` is the only termination signal**, including after `error`. A
 *    stream that stops without it was truncated, and that is reported as a
 *    different failure than a server-side error.
 * 4. **`seq` is gapless from 0.** A jump means a dropped frame, so the trace on
 *    screen is incomplete — the consumer is told rather than shown a plausible
 *    lie.
 * 5. **`call_id` is the model's own id and repeats within a run.** Nothing here
 *    keys on it alone; the identity of a tool invocation is `(step, call_id)`.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { apiUrl } from "@/lib/api"
import { useLocale } from "@/lib/i18n"
import type { Locale, TranslationKey } from "@/lib/i18n"
import { en } from "@/lib/i18n/en"

/* ── Vocabulary ──────────────────────────────────────────────────────────── */

/** Mirrors `PHASES` in `backend/app/agent/events.py`. */
export type SaqrPhase = "calling_model" | "executing_tool" | "composing"

/** Mirrors `ERROR_CODES` in `backend/app/agent/events.py`. */
export type SaqrErrorCode =
  | "no_api_key"
  | "no_credit"
  | "model_error"
  | "tool_error"
  | "bad_args"
  | "step_limit"
  | "timeout"
  | "internal"

/** `stop_reason` values the loop reports. `cancelled` is client-side only. */
export type SaqrStopReason =
  | "answered"
  | "step_limit"
  | "call_limit"
  | "timeout"
  | "error"
  | "cancelled"

type Base = { run_id: string; seq: number }

export type SaqrEvent =
  | (Base & {
      type: "run_start"
      ts: string
      question: string
      locale: string
      max_steps: number
      tools: string[]
      /**
       * Whether the *server* decided this request was an operator request.
       *
       * A report of a decision already made, never an input to one. It may
       * change how the console describes itself; it may never be what lets
       * something happen. Every capability question was settled server-side
       * before this event was written, and a browser that lied about this
       * field would gain exactly nothing. Optional, so an older build that
       * does not send it simply reads as not-admin.
       */
      is_admin?: boolean
      /**
       * The language-model identifier the backend used to be sent here.
       *
       * It is being removed from the wire, and it is deliberately **not typed**
       * and never read: which model answers is an implementation detail of the
       * sensor, not a fact about the detection it reports, and putting it on
       * screen invited the reader to grade the answer by its badge. If a build
       * still sends the field it is simply ignored.
       */
    })
  | (Base & { type: "status"; ts: string; phase: SaqrPhase; step: number })
  | (Base & {
      type: "tool_call"
      ts: string
      step: number
      call_id: string
      tool: string
      label_key: string
      mutating: boolean
      /** Unset optionals are **omitted**, not sent as null. Render what is here. */
      args: Record<string, unknown>
    })
  | (Base & {
      type: "tool_result"
      ts: string
      step: number
      call_id: string
      tool: string
      ok: boolean
      duration_ms: number
      summary: string
      /**
       * A capped *preview* of the result, not the result. Over `SAQR_UI_ROWS`
       * rows or 8 KB it becomes `{ omitted: true, reason }` — which must be
       * rendered as such, never as an empty table.
       */
      data: Record<string, unknown>
      /** `null` for every aggregation. Only `query_threats` / `run_sql` set it. */
      row_count: number | null
      truncated: boolean
      sql_preview: string | null
      /**
       * `code` is the vocabulary half — `not_authorised`,
       * `confirmation_required` and the rest of `ERROR_CODES` — and is what
       * the UI translates. `message` and `hint` are the server's own English
       * and are shown beside it as operator text, never as the headline.
       */
      error: { code?: string; type?: string; message?: string; hint?: string } | null
      cached: boolean
    })
  | (Base & { type: "token"; delta: string })
  | (Base & { type: "answer"; ts: string; text: string; used_tools: string[] })
  | (Base & {
      type: "error"
      ts: string
      code: SaqrErrorCode
      message: string
      fatal: boolean
    })
  | (Base & {
      type: "done"
      ts: string
      steps: number
      tool_calls: number
      elapsed_ms: number
      stop_reason: SaqrStopReason
    })

export type SaqrToolCallEvent = Extract<SaqrEvent, { type: "tool_call" }>
export type SaqrToolResultEvent = Extract<SaqrEvent, { type: "tool_result" }>
export type SaqrDoneEvent = Extract<SaqrEvent, { type: "done" }>

/** One entry of `GET /agent/tools`. The catalogue honours the config switches. */
export type SaqrToolInfo = {
  name: string
  label_key: string
  description: string
  mutating: boolean
  /** Published only to a request that proved the admin token. */
  admin?: boolean
  /** Changes or removes stored data. Always also `admin`. */
  destructive?: boolean
  tags: string[]
  args_schema: Record<string, unknown>
}

/* ── Failures ────────────────────────────────────────────────────────────── */

/**
 * The three ways a run can fail, kept apart because they are three different
 * things to tell the operator:
 *
 * - `preflight` — the server refused before streaming (503/429/400). Nothing ran.
 * - `stream` — the connection died mid-run, or ended without `done`. Part of
 *   the trace on screen is real; the rest was lost.
 * - `agent` — the run itself reported an `error` event. The server is fine.
 */
export type SaqrFailure =
  | { kind: "preflight"; status: number; detail: string; retryAfterS: number | null }
  | { kind: "stream"; detail: string }
  | { kind: "agent"; code: SaqrErrorCode; message: string; fatal: boolean }

/**
 * The localised sentence for a failure.
 *
 * Agent errors map straight onto `saqr.error.<code>`, which is the vocabulary
 * the backend guarantees. Pre-flight statuses have no wire code — they are HTTP
 * — so they map by status, with the raw server `detail` kept for the operator
 * as secondary text rather than shown as the headline.
 */
export function failureKey(failure: SaqrFailure): TranslationKey {
  if (failure.kind === "agent") {
    const key = `saqr.error.${failure.code}`
    return key in en ? (key as TranslationKey) : "saqr.error.internal"
  }
  if (failure.kind === "stream") return "saqr.error.disconnected"
  switch (failure.status) {
    case 503:
      return "saqr.error.no_api_key"
    case 429:
      return "saqr.error.rate_limited"
    case 400:
      return "saqr.error.bad_request"
    case 0:
      return "saqr.error.network"
    default:
      return "saqr.error.unavailable"
  }
}

/**
 * The localised sentence for a **tool-level** failure code.
 *
 * `tool_result.error.code` shares its vocabulary with the run-level `error`
 * event, so the same `saqr.error.*` keys serve both. A code with no key falls
 * back to `null` and the caller shows the server's own text instead of
 * inventing a sentence for something it does not understand.
 */
export function toolErrorKey(code: string | null | undefined): TranslationKey | null {
  if (!code) return null
  const key = `saqr.error.${code}`
  return key in en ? (key as TranslationKey) : null
}

/** Localised label for a tool, driven by the `label_key` the server published. */
export function toolLabelKey(labelKey: string | null | undefined): TranslationKey {
  if (labelKey && labelKey in en) return labelKey as TranslationKey
  return "saqr.tool.unknown"
}

/* ── Frame parsing ───────────────────────────────────────────────────────── */

type RawFrame = { event: string; data: string }

/**
 * Incremental SSE block decoder.
 *
 * A network chunk has no relationship to a frame boundary: one `read()` can
 * carry half an event, or nine of them. Everything is buffered until a blank
 * line is seen, which is the only thing that actually terminates a block.
 */
class SseDecoder {
  private buffer = ""

  /** Feed a decoded text chunk; get back whatever complete frames it finished. */
  push(chunk: string): RawFrame[] {
    // Normalise the three legal line terminators so one delimiter search works.
    this.buffer += chunk.replace(/\r\n/g, "\n").replace(/\r/g, "\n")

    const frames: RawFrame[] = []
    let cut = this.buffer.indexOf("\n\n")
    while (cut !== -1) {
      const block = this.buffer.slice(0, cut)
      this.buffer = this.buffer.slice(cut + 2)
      const frame = decodeBlock(block)
      if (frame) frames.push(frame)
      cut = this.buffer.indexOf("\n\n")
    }
    return frames
  }

  /** Anything left after the stream ended. Non-empty means a truncated frame. */
  get pending(): string {
    return this.buffer
  }
}

function decodeBlock(block: string): RawFrame | null {
  let event = "message"
  const dataLines: string[] = []

  for (const line of block.split("\n")) {
    if (line === "") continue
    // A comment. This is what a keep-alive is: `: ka`. It carries no payload
    // and must never reach JSON.parse.
    if (line.startsWith(":")) continue

    const colon = line.indexOf(":")
    const field = colon === -1 ? line : line.slice(0, colon)
    // One optional space after the colon is part of the framing, not the value.
    let value = colon === -1 ? "" : line.slice(colon + 1)
    if (value.startsWith(" ")) value = value.slice(1)

    if (field === "event") event = value
    else if (field === "data") dataLines.push(value)
    // `id` and `retry` are legal fields this stream does not use; ignoring them
    // is correct, and ignoring an unknown field is what the spec requires.
  }

  if (dataLines.length === 0) return null
  return { event, data: dataLines.join("\n") }
}

const EVENT_NAMES = new Set([
  "run_start",
  "status",
  "tool_call",
  "tool_result",
  "token",
  "answer",
  "error",
  "done",
])

/** Turn a frame into a typed event, or `null` if it is not one we understand. */
function toEvent(frame: RawFrame): SaqrEvent | null {
  if (!EVENT_NAMES.has(frame.event)) return null
  let payload: unknown
  try {
    payload = JSON.parse(frame.data)
  } catch {
    // A frame we cannot parse is a dropped frame. The seq check downstream is
    // what tells the user the trace is incomplete; guessing here would not.
    return null
  }
  if (!payload || typeof payload !== "object") return null
  return { ...(payload as Record<string, unknown>), type: frame.event } as SaqrEvent
}

/* ── Derived shapes ──────────────────────────────────────────────────────── */

/**
 * One tool invocation, call and result folded together.
 *
 * `key` is `${step}:${call_id}` and never `call_id` alone: the id belongs to
 * the model, and a model that calls the same tool twice in one run frequently
 * reuses it. Keying on the id alone silently merges two rows into one.
 */
export type SaqrToolActivity = {
  key: string
  step: number
  callId: string
  tool: string
  labelKey: string
  mutating: boolean
  args: Record<string, unknown>
  result: SaqrToolResultEvent | null
}

function foldTools(events: readonly SaqrEvent[]): SaqrToolActivity[] {
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
      const activity = index.get(`${event.step}:${event.call_id}`)
      if (activity) activity.result = event
    }
  }
  return order
}

/**
 * The row count worth showing.
 *
 * `row_count` is populated by `query_threats` and `run_sql` only; every
 * aggregation leaves it `null` and reports its size as `group_count` (with
 * `total` as the sum). Falling back to `0` would report "0 rows" for a
 * successful aggregation over thousands of frames.
 */
export function resultCount(result: SaqrToolResultEvent): number | null {
  if (typeof result.row_count === "number") return result.row_count
  const data = result.data ?? {}
  const groups = data["group_count"]
  if (typeof groups === "number") return groups
  const total = data["total"]
  if (typeof total === "number") return total
  return null
}

/** True when the preview was replaced by the "too large" marker. */
export function isOmitted(data: Record<string, unknown> | null | undefined): boolean {
  return Boolean(data && data["omitted"] === true)
}

/**
 * The catalogue as a **visitor** may be shown it.
 *
 * A tool that writes is not something to advertise on a console a visitor is
 * reading over the operator's shoulder — naming it tells them the attacks on
 * screen might have been put there. The backend gates the writing tools behind
 * the admin header, so for an ordinary request they are already absent from
 * `GET /agent/tools`; this is the second lock on the same door, and it is a
 * filter over whatever the endpoint returned rather than a list of names — a
 * hardcoded exclusion would go stale the first time a tool was renamed, and
 * would start lying the first time a new one was added.
 *
 * This governs **advertising only**. A write that actually happened is still
 * rendered in the trace, with its badge, because hiding one would be a lie.
 */
export function advertisedTools(tools: readonly SaqrToolInfo[]): SaqrToolInfo[] {
  return tools.filter((tool) => !tool.mutating && !tool.admin && !tool.destructive)
}

/**
 * Fields of `tool_result.data` that belong to the **protocol**, not to the
 * result, and are therefore never painted into the generic preview.
 *
 * Two of them matter more than the tidiness: `confirm_token` is a live
 * single-use authorisation and must not end up in a screenshot or a shoulder
 * surfer's view, and `note` is a sentence addressed to the *model* telling it
 * what it may not do — rendering it as though it were addressed to the reader
 * would be both confusing and, in the untrusted case, the exact mistake this
 * whole layer exists to avoid.
 */
export const PROTOCOL_FIELDS: readonly string[] = [
  "requires_confirmation",
  "confirm_token",
  "expires_in_s",
  "action",
  "affected_estimate",
  "note",
  "untrusted",
]

/**
 * How many rows a destructive tool **actually removed**, or `null`.
 *
 * `data.deleted` exists only on the second call — the one a person authorised.
 * A proposal carries `affected_estimate` instead, and the two must never be
 * read as the same number: one is a count of rows that are gone, the other is
 * a guess about rows that are still there.
 */
export function deletedCount(result: SaqrToolResultEvent | null | undefined): number | null {
  const value = result?.data?.["deleted"]
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

/**
 * The `untrusted` block a row-returning result carries.
 *
 * Every one of these fields is chosen by whoever transmitted the frame: in a
 * Wi-Fi IDS an SSID is adversary-controlled *by design*, and `HawkShield-Guest`
 * and `ignore previous instructions` arrive through exactly the same code path.
 * The names are used to mark the columns; the block's `note` is aimed at the
 * model and is not shown.
 */
export function untrustedFields(data: Record<string, unknown> | null | undefined): string[] {
  const block = data?.["untrusted"]
  if (!block || typeof block !== "object") return []
  const names = (block as Record<string, unknown>)["untrusted_fields"]
  return Array.isArray(names) ? names.filter((n): n is string => typeof n === "string") : []
}

/* ── The confirmation protocol ───────────────────────────────────────────── */

/** The header a confirmation token rides back in. See `backend/app/agent/guard.py`. */
export const CONFIRM_HEADER = "X-HawkShield-Confirm"

/**
 * A destructive tool that **did not act**.
 *
 * An admin-gated tool answers a request to change data with a description of
 * what it *would* do plus a one-shot token, instead of doing it:
 *
 * ```json
 * { "requires_confirmation": true, "action": "delete_detections",
 *   "summary": "...", "affected_estimate": 128,
 *   "confirm_token": "...", "expires_in_s": 120 }
 * ```
 *
 * The token travels **outside the conversation**: the server mints it, hands
 * it to this client, and it comes back in the `X-HawkShield-Confirm` header on
 * a replay of the identical question — never as a tool argument, and never in
 * the transcript the model reads. That is what makes it impossible for a model
 * to confirm its own destructive action, rather than merely forbidden.
 *
 * It is also bound to the arguments and single-use, so re-asking the question
 * without it produces another proposal and never an action — the property that
 * makes this safe against a reload, a retry or a stale tab.
 *
 * Nothing in this file ever sends a token by itself. A token only leaves the
 * browser because a person pressed a button.
 */
export type SaqrConfirmation = {
  /** Machine name of what would happen, e.g. `delete_detections`. */
  action: string
  /** The server's own sentence describing it. Shown verbatim, never rewritten. */
  summary: string
  /** How many rows it would touch. `null` when the tool did not estimate. */
  affectedEstimate: number | null
  /** Seconds the token stays valid, or `null` when the server did not say. */
  expiresInS: number | null
  /** `null` means the proposal cannot be completed — the card says so. */
  token: string | null
}

/** Where a confirmation stands, client-side. Keyed by `confirm_token`. */
export type SaqrConfirmState = "pending" | "confirmed" | "cancelled"

function readNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

function readString(value: unknown): string {
  return typeof value === "string" ? value : ""
}

/**
 * The confirmation carried by a tool result, or `null` for the ordinary case.
 *
 * Written to be inert until the backend finishes wiring the feature in: with
 * today's stream every result fails the first test and this returns `null`, so
 * nothing on the page changes. Both the result payload and the event envelope
 * are checked, because the flag could reasonably land in either and a card that
 * fails to appear is the one failure mode this must not have.
 */
export function readConfirmation(
  result: SaqrToolResultEvent | null | undefined
): SaqrConfirmation | null {
  if (!result) return null
  const candidates: unknown[] = [result.data, result]

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue
    const source = candidate as Record<string, unknown>
    if (source["requires_confirmation"] !== true) continue

    const token = readString(source["confirm_token"])
    return {
      action: readString(source["action"]),
      summary: readString(source["summary"]) || readString(result.summary),
      affectedEstimate: readNumber(source["affected_estimate"]),
      expiresInS: readNumber(source["expires_in_s"]),
      token: token || null,
    }
  }
  return null
}

/* ── A finished run ──────────────────────────────────────────────────────── */

export type SaqrRun = {
  /** Client-side id; the server's `run_id` lands in `runId` once `run_start` arrives. */
  localId: string
  runId: string | null
  question: string
  locale: Locale
  /**
   * The token this run carried, when it was started by confirming a destructive
   * action rather than by a question typed into the composer.
   */
  confirmToken: string | null
  /** The server reported this run as an operator run. Descriptive only. */
  isAdmin: boolean
  /** Every event except `token` — the deltas are folded into `answer` instead. */
  events: SaqrEvent[]
  answer: string
  usedTools: string[]
  failure: SaqrFailure | null
  done: SaqrDoneEvent | null
  /** A `seq` jump was observed: part of this trace was dropped in transit. */
  gap: boolean
  startedAt: number
  elapsedMs: number
}

/* ── The catalogue ───────────────────────────────────────────────────────── */

/**
 * `GET /agent/tools`.
 *
 * Fetched, never hardcoded: with the shipped configuration `run_sql` is gated
 * off and the catalogue has **seven** entries, not eight, and both switches are
 * things an operator can change without a frontend rebuild.
 */
export function useSaqrTools(): { tools: SaqrToolInfo[]; failed: boolean } {
  const [tools, setTools] = useState<SaqrToolInfo[]>([])
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    fetch(apiUrl("/agent/tools"), { signal: controller.signal })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
      .then((body: unknown) => {
        if (Array.isArray(body)) setTools(body as SaqrToolInfo[])
        else setFailed(true)
      })
      .catch((err: unknown) => {
        if ((err as { name?: string })?.name === "AbortError") return
        setFailed(true)
      })
    return () => controller.abort()
  }, [])

  return { tools, failed }
}

/* ── The run hook ────────────────────────────────────────────────────────── */

/** How often the live elapsed clock repaints while a run is open. */
const ELAPSED_TICK_MS = 200

/** Distance from the bottom, in px, still counted as "following the trace". */
export const STICK_THRESHOLD_PX = 48

export type UseSaqrRun = {
  /** Ordered events of the current run, `token` excluded (see `answer`). */
  events: SaqrEvent[]
  /** Latest `status.phase`, or `null` when nothing is in flight. */
  phase: SaqrPhase | null
  /** The answer so far: token deltas while streaming, the final text after. */
  answer: string
  /** Tool invocations of this run, in call order, keyed `(step, call_id)`. */
  tools: SaqrToolActivity[]
  error: SaqrFailure | null
  /** Live while running; the server's authoritative figure once `done` lands. */
  elapsed: number
  isRunning: boolean
  /** The run being watched, including a finished one. `null` before the first ask. */
  run: SaqrRun | null
  /** Completed runs, oldest first. The page collapses these to their answers. */
  history: SaqrRun[]
  /**
   * Where every confirmation seen this session stands, keyed by its token.
   * A token absent from this map has never been acted on.
   */
  confirmations: Record<string, SaqrConfirmState>
  /**
   * Authorise one destructive action and re-ask its question carrying the
   * token. Only ever called from a click handler — there is no path in this
   * module that reaches it on its own.
   */
  confirmAction: (token: string, question: string) => void
  /** Decline one. Purely client-side: nothing is sent, so nothing can run. */
  dismissAction: (token: string) => void
  ask: (question: string) => void
  cancel: () => void
  /** Re-ask the current run's question. No-op while a run is open. */
  retry: () => void
  /** Drop the transcript and the current run. */
  reset: () => void
}

let localRunCounter = 0

export function useSaqrRun(): UseSaqrRun {
  const { locale } = useLocale()

  const [run, setRun] = useState<SaqrRun | null>(null)
  const [history, setHistory] = useState<SaqrRun[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [tick, setTick] = useState(0)
  const [confirmations, setConfirmations] = useState<Record<string, SaqrConfirmState>>({})

  const abortRef = useRef<AbortController | null>(null)
  /** Set when *we* aborted, so a cancelled read is not reported as a drop. */
  const cancelledRef = useRef(false)
  /** Token deltas buffered between animation frames — see `flushTokens`. */
  const tokenBufferRef = useRef("")
  const rafRef = useRef<number | null>(null)
  const localeRef = useRef<Locale>(locale)
  localeRef.current = locale

  /**
   * The committed value of `run`, for `ask` to archive without reaching into a
   * state updater. Written in an effect so it is only ever the run that has
   * actually rendered.
   */
  const runRef = useRef<SaqrRun | null>(null)
  useEffect(() => {
    runRef.current = run
  }, [run])

  /** Tokens already confirmed or declined this session. See `confirmAction`. */
  const settledTokensRef = useRef<Set<string>>(new Set())

  /** One session id per mount, so a backend that groups runs can. */
  const sessionIdRef = useRef<string>("")
  if (!sessionIdRef.current) {
    sessionIdRef.current = `saqr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
  }

  /**
   * Tokens arrive far faster than the screen refreshes — one `setState` per
   * delta would re-render the whole trace dozens of times a second for no
   * visible gain. They are accumulated and applied once per animation frame,
   * which is exactly as often as the browser can show the difference.
   */
  const flushTokens = useCallback(() => {
    rafRef.current = null
    const pending = tokenBufferRef.current
    if (!pending) return
    tokenBufferRef.current = ""
    setRun((prev) => (prev ? { ...prev, answer: prev.answer + pending } : prev))
  }, [])

  const scheduleFlush = useCallback(() => {
    if (rafRef.current !== null) return
    rafRef.current =
      typeof window === "undefined"
        ? null
        : window.requestAnimationFrame(() => flushTokens())
  }, [flushTokens])

  // Live elapsed clock. Stopped the moment the run is not running, so an idle
  // page schedules nothing at all.
  useEffect(() => {
    if (!isRunning) return
    const id = window.setInterval(() => setTick((n) => n + 1), ELAPSED_TICK_MS)
    return () => window.clearInterval(id)
  }, [isRunning])

  useEffect(
    () => () => {
      abortRef.current?.abort()
      if (rafRef.current !== null && typeof window !== "undefined") {
        window.cancelAnimationFrame(rafRef.current)
      }
    },
    []
  )

  const cancel = useCallback(() => {
    if (!abortRef.current) return
    cancelledRef.current = true
    abortRef.current.abort()
  }, [])

  const ask = useCallback(
    (rawQuestion: string, options?: { confirmToken?: string }) => {
      const question = rawQuestion.trim()
      if (!question || abortRef.current) return
      const confirmToken = options?.confirmToken ?? null

      const controller = new AbortController()
      abortRef.current = controller
      cancelledRef.current = false
      tokenBufferRef.current = ""

      const askedLocale = localeRef.current
      const started: SaqrRun = {
        localId: `run-${++localRunCounter}`,
        runId: null,
        question,
        locale: askedLocale,
        confirmToken,
        isAdmin: false,
        events: [],
        answer: "",
        usedTools: [],
        failure: null,
        done: null,
        gap: false,
        startedAt: Date.now(),
        elapsedMs: 0,
      }

      // Archive whatever finished before this one, so the page keeps a
      // transcript without the hook owning the page's layout decisions.
      //
      // Read from a ref rather than from inside a `setRun` updater. A state
      // updater must be pure, and `setHistory` inside one is a side effect that
      // React is entitled to run more than once — which it does, in StrictMode,
      // producing two identical entries in the transcript for every run after
      // the first. The ref is written after commit, so by the time `ask` can be
      // called it holds exactly the run that is on screen.
      const previous = runRef.current
      if (previous) setHistory((all) => [...all, previous])
      setRun(started)
      setIsRunning(true)

      const finish = () => {
        abortRef.current = null
        // Every path that ends a run without a `done` event — cancelled,
        // refused, disconnected — still owes the footer an elapsed figure.
        // `done.elapsed_ms` is the server's own and always wins when it arrived.
        setRun((prev) =>
          prev && prev.localId === started.localId && !prev.done
            ? { ...prev, elapsedMs: Date.now() - prev.startedAt }
            : prev
        )
        setIsRunning(false)
      }

      const fail = (failure: SaqrFailure) => {
        flushTokens()
        setRun((prev) =>
          prev && prev.localId === started.localId
            ? { ...prev, failure: prev.failure ?? failure }
            : prev
        )
      }

      void (async () => {
        let expectedSeq = 0
        /**
         * Set once a reader is attached. It is what separates the two failures
         * a thrown `fetch` can mean: before this point nothing ran and the
         * sensor was never reached; after it, part of the trace on screen is
         * real and the rest was lost. A server that dies mid-stream does not
         * politely end the body — `read()` throws `TypeError: network error` —
         * so without this flag a disconnect is reported as "could not reach the
         * sensor", which sends the operator to check a service that is fine.
         */
        let streamOpened = false

        try {
          const response = await fetch(apiUrl("/agent/ask"), {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              // Naming the media type is what selects the streaming transport.
              // A bare */* deliberately gets the JSON envelope instead.
              Accept: "text/event-stream",
              // Present only on a run a person authorised by pressing Confirm.
              // It rides in a header rather than in the body precisely so it is
              // never part of the conversation the model can see or influence.
              // A backend that does not know the header ignores it, and the run
              // is simply an unconfirmed one — which proposes again.
              ...(confirmToken ? { [CONFIRM_HEADER]: confirmToken } : {}),
              // NOTE: `X-HawkShield-Admin` is deliberately **not** sent, and
              // this is the only place it could be. The browser has nowhere to
              // keep an admin token that is not also somewhere an attacker who
              // gets script execution on this origin can read, so putting one
              // here would trade a real secret for a convenience. Every run
              // from this console is therefore a non-admin run: the operator
              // tools are absent from its catalogue, `is_admin` reads false,
              // and the confirmation card is built and ready for the day that
              // token is supplied by something that can hold it safely.
              // If that changes, it changes here and nowhere else.
            },
            body: JSON.stringify({
              question,
              locale: askedLocale,
              session_id: sessionIdRef.current,
            }),
            signal: controller.signal,
          })

          // --- pre-flight -------------------------------------------------- //
          // Everything the server refuses is decided *before* the stream opens,
          // and comes back as JSON regardless of the Accept header. Attaching a
          // reader to it would spin over a body that contains no SSE frames and
          // report a phantom disconnect.
          if (!response.ok) {
            fail({
              kind: "preflight",
              status: response.status,
              detail: await readDetail(response),
              retryAfterS: parseRetryAfter(response.headers.get("retry-after")),
            })
            finish()
            return
          }

          const contentType = (response.headers.get("content-type") ?? "").toLowerCase()
          if (!contentType.includes("text/event-stream") || !response.body) {
            fail({
              kind: "preflight",
              status: response.status,
              detail: await readDetail(response),
              retryAfterS: null,
            })
            finish()
            return
          }

          // --- the stream --------------------------------------------------- //
          const reader = response.body.getReader()
          streamOpened = true
          const decoder = new TextDecoder()
          const sse = new SseDecoder()
          let sawDone = false

          for (;;) {
            const { value, done: streamEnded } = await reader.read()
            if (streamEnded) break

            const frames = sse.push(decoder.decode(value, { stream: true }))
            let batch: SaqrEvent[] = []
            let sawGap = false

            for (const frame of frames) {
              const event = toEvent(frame)
              if (!event) continue
              if (typeof event.seq === "number") {
                if (event.seq !== expectedSeq) sawGap = true
                expectedSeq = event.seq + 1
              }
              if (event.type === "token") {
                tokenBufferRef.current += event.delta
                continue
              }
              batch.push(event)
              if (event.type === "done") sawDone = true
            }

            if (tokenBufferRef.current) scheduleFlush()

            if (batch.length > 0 || sawGap) {
              const applied = batch
              const gapped = sawGap
              // The answer text is authoritative over the accumulated deltas —
              // apply any buffered tokens first so `answer` cannot end up as a
              // token tail appended after the settled text.
              flushTokens()
              setRun((prev) => {
                if (!prev || prev.localId !== started.localId) return prev
                const next: SaqrRun = {
                  ...prev,
                  events: [...prev.events, ...applied],
                  gap: prev.gap || gapped,
                }
                for (const event of applied) {
                  if (event.type === "run_start") {
                    next.runId = event.run_id
                    next.isAdmin = Boolean(event.is_admin)
                  } else if (event.type === "answer") {
                    next.answer = event.text
                    next.usedTools = event.used_tools ?? []
                  } else if (event.type === "error") {
                    next.failure = next.failure ?? {
                      kind: "agent",
                      code: event.code,
                      message: event.message,
                      fatal: Boolean(event.fatal),
                    }
                  } else if (event.type === "done") {
                    next.done = event
                    next.elapsedMs = event.elapsed_ms
                  }
                }
                return next
              })
              batch = []
            }
          }

          flushTokens()

          // `done` is the *only* legitimate end of a run. A stream that stopped
          // without it lost the rest of the answer, and saying so is the whole
          // point of distinguishing this from a server-side error.
          if (!sawDone && !cancelledRef.current) {
            fail({
              kind: "stream",
              detail: sse.pending
                ? "the stream ended mid-frame"
                : "the stream ended before the run reported done",
            })
          }
        } catch (err: unknown) {
          flushTokens()
          const name = (err as { name?: string })?.name
          const message = (err as { message?: string })?.message ?? "network error"

          if (name === "AbortError" || cancelledRef.current) {
            // A cancellation is a user decision, not a fault. `finish` records
            // the elapsed time so the footer can say why the trace stops here.
          } else if (streamOpened) {
            fail({ kind: "stream", detail: message })
          } else {
            fail({
              kind: "preflight",
              // No response ever arrived — DNS, TLS, offline, CORS. `0` is the
              // conventional "no HTTP status" and maps to its own message.
              status: 0,
              detail: message,
              retryAfterS: null,
            })
          }
        } finally {
          finish()
        }
      })()
    },
    [flushTokens, scheduleFlush]
  )

  const retry = useCallback(() => {
    if (isRunning || !run) return
    ask(run.question)
  }, [ask, isRunning, run])

  /**
   * Authorise one destructive action.
   *
   * The token is marked spent *before* the request goes out, so a double-click
   * or a re-render cannot produce two authorised runs from one decision. It is
   * only reachable from a click handler: nothing in this module calls it, and
   * there is deliberately no "confirm automatically" path to disable.
   */
  const confirmAction = useCallback(
    (token: string, question: string) => {
      if (!token || !question) return
      if (isRunning || abortRef.current) return
      // A ref, not the state above: a `setState` updater does not run before
      // the next line, so reading the decision back out of it would let a
      // double-click authorise the same action twice.
      if (settledTokensRef.current.has(token)) return
      settledTokensRef.current.add(token)
      setConfirmations((prev) => ({ ...prev, [token]: "confirmed" }))
      ask(question, { confirmToken: token })
    },
    [ask, isRunning]
  )

  /** Decline one. Nothing is sent — a token that never leaves cannot act. */
  const dismissAction = useCallback((token: string) => {
    if (!token || settledTokensRef.current.has(token)) return
    settledTokensRef.current.add(token)
    setConfirmations((prev) => ({ ...prev, [token]: "cancelled" }))
  }, [])

  const reset = useCallback(() => {
    cancel()
    setRun(null)
    runRef.current = null
    setHistory([])
    setConfirmations({})
    settledTokensRef.current = new Set()
  }, [cancel])

  const tools = useMemo(() => foldTools(run?.events ?? []), [run?.events])

  const phase = useMemo<SaqrPhase | null>(() => {
    if (!isRunning || !run) return null
    for (let i = run.events.length - 1; i >= 0; i -= 1) {
      const event = run.events[i]
      if (event.type === "status") return event.phase
    }
    return null
  }, [isRunning, run])

  // `tick` is read here on purpose: it is what advances the live clock.
  const elapsed = useMemo(() => {
    void tick
    if (!run) return 0
    if (run.done) return run.done.elapsed_ms
    if (!isRunning) return run.elapsedMs
    return Date.now() - run.startedAt
  }, [run, isRunning, tick])

  return {
    events: run?.events ?? [],
    phase,
    answer: run?.answer ?? "",
    tools,
    error: run?.failure ?? null,
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
  }
}

/**
 * `Retry-After`, in seconds, or `null` when the header says nothing useful.
 *
 * `Number(null)` is `0`, not `NaN` — so a plain `Number.isFinite` guard on a
 * missing header passes and every 503 grows a "Retry in 0s." line. Only the
 * rate limiter sets this header, and only ever to a positive integer.
 */
function parseRetryAfter(header: string | null): number | null {
  if (!header) return null
  const seconds = Number(header.trim())
  return Number.isFinite(seconds) && seconds > 0 ? seconds : null
}

/**
 * Best-effort human text out of a refusal body.
 *
 * FastAPI answers `{"detail": ...}`, where `detail` is a sentence for 503/429
 * and a list of validation objects for 400. Both are reduced to one line, and
 * anything unrecognised falls back to the raw body — this is operator-facing
 * secondary text, never the headline the user reads.
 */
async function readDetail(response: Response): Promise<string> {
  let text = ""
  try {
    text = await response.text()
  } catch {
    return `HTTP ${response.status}`
  }
  if (!text) return `HTTP ${response.status}`
  try {
    const body = JSON.parse(text) as { detail?: unknown }
    const detail = body?.detail
    if (typeof detail === "string") return detail
    // A rejected question now answers `{reason, message}`. Both shapes are
    // handled rather than one, so this keeps working against a backend that
    // is older than this build as well as one that is newer.
    if (detail && typeof detail === "object" && !Array.isArray(detail)) {
      const entry = detail as { reason?: unknown; message?: unknown }
      const message = typeof entry.message === "string" ? entry.message : ""
      const reason = typeof entry.reason === "string" ? entry.reason : ""
      if (message || reason) return [message, reason && `(${reason})`].filter(Boolean).join(" ")
    }
    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          const entry = item as { loc?: unknown[]; msg?: string }
          const where = Array.isArray(entry.loc) ? entry.loc.join(".") : ""
          return where ? `${where}: ${entry.msg ?? ""}` : (entry.msg ?? "")
        })
        .filter(Boolean)
        .join("; ")
    }
  } catch {
    /* not JSON — fall through to the raw body */
  }
  return text.slice(0, 500)
}
