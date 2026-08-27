"use client"

/**
 * What came back from one tool, rendered honestly.
 *
 * `tool_result.data` is a **preview**, not the result: the backend caps it at
 * `SAQR_UI_ROWS` rows and 8 KB of JSON, and past that replaces the whole blob
 * with `{ omitted: true, reason }`. Three things follow, and each is a bug this
 * component exists to avoid:
 *
 * - An omitted preview is rendered as a stated omission. Falling through to a
 *   table would paint an empty rectangle over a tool that returned thousands of
 *   rows, which reads as "nothing found".
 * - A truncated list says so. `truncated` on the event and the row cap are two
 *   different reasons the list on screen is shorter than the tool's own answer.
 * - Not every tool returns a list. `threat_overview`, `system_status` and
 *   `explain_attack_class` return nested objects; those get a field list, not a
 *   table with one row in it.
 *
 * Every value goes through `<Mac>` / `<Timestamp>` / `<Code>` / `hs-num`.
 * These are database values landing inside prose that may be Arabic, and an
 * unisolated MAC is reordered on screen while the DOM stays correct.
 *
 * Two things are deliberately **not** painted from `data`.
 *
 * The **protocol fields** (`confirm_token`, `note`, `requires_confirmation`
 * and friends) are stripped by `PROTOCOL_FIELDS`. A live single-use
 * authorisation token has no business being on screen where a photograph or a
 * shoulder can take it, and `note` is a sentence written *to the model* about
 * what it may not do — showing it to the reader would be confusing at best.
 *
 * The **`untrusted` block** is read for its field names and nothing else. In a
 * Wi-Fi IDS an SSID and a MAC are adversary-controlled by design: anyone can
 * name an access point `ignore previous instructions`, stand near the sensor,
 * and have that string arrive here. Those columns are marked so a reader knows
 * the value is a claim rather than a fact, and the block's own note — also
 * addressed to the model — is not rendered.
 */
import * as React from "react"

import { DataTable, type DataTableColumn } from "@/components/hs/data-table"
import { Code, Ltr, Mac, Timestamp } from "@/lib/format"
import { useT } from "@/lib/i18n"
import {
  isOmitted,
  PROTOCOL_FIELDS,
  untrustedFields,
  type SaqrToolResultEvent,
} from "@/lib/saqr"
import { cn } from "@/lib/utils"

/** The list fields the backend trims — mirrors `_DATA_LIST_FIELDS` in tools.py. */
const LIST_FIELDS = ["rows", "groups", "rssi_points", "used", "classes"] as const

const MAC_RE = /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/
const ISO_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/
/** Printable ASCII only: an identifier, an interface name, hex, a SQL fragment. */
const ASCII_RE = /^[\x20-\x7E]*$/

/**
 * Past this many characters a string stops being a value and starts being a
 * document. `explain_attack_class` returns a whole knowledge-base section —
 * around two thousand characters of Markdown with newlines — in a single field,
 * and rendered inline it swallows the step it belongs to.
 */
const LONG_TEXT_CHARS = 160

/**
 * A long value in a box that scrolls itself.
 *
 * Nothing is truncated: the whole value is present and selectable, and the
 * document around it keeps its shape. `span` rather than `div` because this can
 * land inside an inline run (an argument value), where a block-level element
 * would be invalid nesting; `display: block` gives the same box either way.
 * `bdi` lets the run pick its own direction — a knowledge-base section is
 * English, an SSID may not be — while isolating it from the paragraph around it.
 */
function LongText({ value }: { value: string }) {
  return (
    <span className="border-rule bg-paper-2 block max-h-48 min-w-0 overflow-auto rounded-md border p-2.5">
      <bdi className="text-ink-1 block text-xs leading-relaxed whitespace-pre-wrap">{value}</bdi>
    </span>
  )
}

/* ── One scalar ──────────────────────────────────────────────────────────── */

export function SaqrValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-ink-3">—</span>
  }
  if (typeof value === "boolean") {
    return <Code className="text-ink-2">{value ? "true" : "false"}</Code>
  }
  if (typeof value === "number") {
    /*
     * Verbatim, never through a locale formatter.
     *
     * The rule across this whole surface is: **a value off the wire is
     * reproduced exactly; only a figure the UI computed itself is formatted.**
     * A trace is evidence, and thousands separators quietly falsify it. Two
     * real cases from this page: `minutes=10080` is the argument the model
     * sent, and rendering it `10,080` misreports the call; `channel_freq=5180`
     * is a frequency in MHz, and rendering it `5,180` makes an identifier look
     * like a count of five thousand things. The footer's "3 tool calls" is
     * UI-computed and does go through the formatter.
     */
    return <Ltr className="hs-num">{String(value)}</Ltr>
  }
  if (typeof value === "string") {
    if (MAC_RE.test(value)) return <Mac value={value} />
    if (ISO_RE.test(value)) return <Timestamp value={value} />
    // Checked before the ASCII branch: a knowledge-base section is pure ASCII
    // apart from its newlines, and `<Code>` would set the whole of it as one
    // unwrapped monospace line running out of the card.
    if (value.length > LONG_TEXT_CHARS || value.includes("\n")) return <LongText value={value} />
    // Pure-ASCII strings out of the database are technical literals — class
    // identifiers, interface names, SSIDs, hex. Anything else (an Arabic SSID,
    // a knowledge-base sentence) gets `bdi`: isolated, but free to pick its own
    // direction rather than being forced left-to-right.
    if (ASCII_RE.test(value)) return <Code className="text-ink-2">{value}</Code>
    return <bdi>{value}</bdi>
  }
  // An object or array nested inside a cell. Compact JSON keeps the row height
  // stable; the full structure is one `sql_preview` or one answer away.
  return (
    <Code className="text-ink-3">{truncate(JSON.stringify(value), 120)}</Code>
  )
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text
}

/* ── Field list ──────────────────────────────────────────────────────────── */

function FieldList({ entries }: { entries: [string, unknown][] }) {
  return (
    <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
      {entries.map(([key, value]) => (
        <React.Fragment key={key}>
          <dt className="hs-label pt-px">
            <Ltr>{key}</Ltr>
          </dt>
          <dd className="min-w-0 text-xs break-words">
            {isPlainObject(value) ? (
              <FieldList entries={Object.entries(value).slice(0, 12)} />
            ) : Array.isArray(value) ? (
              <span className="flex flex-wrap gap-1.5">
                {value.slice(0, 24).map((item, i) => (
                  <SaqrValue key={i} value={item} />
                ))}
              </span>
            ) : (
              <SaqrValue value={value} />
            )}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/* ── The preview ─────────────────────────────────────────────────────────── */

type Row = Record<string, unknown>

/** The first trimmed list field actually present, with its name. */
function pickList(data: Record<string, unknown>): { field: string; items: unknown[] } | null {
  for (const field of LIST_FIELDS) {
    const value = data[field]
    if (Array.isArray(value) && value.length > 0) return { field, items: value }
  }
  return null
}

export function SaqrResultPreview({
  result,
  className,
}: {
  result: SaqrToolResultEvent
  className?: string
}) {
  const t = useT()
  const untrusted = untrustedFields(result.data)
  // The protocol's own fields are stripped before anything is painted; see the
  // note at the top of this file for why `confirm_token` in particular must
  // never reach the screen. Keyed on `result.data` rather than on a defaulted
  // local, so the memo does not re-run on every render for a result that has no
  // data at all.
  const data = React.useMemo(() => {
    const source = result.data ?? {}
    // `summary` is an ordinary result field for most tools, and part of the
    // protocol for a proposal — where it is already quoted on the confirmation
    // card and would otherwise appear twice under one step.
    const drop =
      source["requires_confirmation"] === true
        ? [...PROTOCOL_FIELDS, "summary"]
        : PROTOCOL_FIELDS
    return Object.fromEntries(Object.entries(source).filter(([key]) => !drop.includes(key)))
  }, [result.data])

  if (isOmitted(data)) {
    const reason = typeof data["reason"] === "string" ? (data["reason"] as string) : ""
    return (
      <p className={cn("text-ink-1 text-sm", className)}>
        {t("saqr.trace.omitted")}
        {reason ? (
          <>
            {" "}
            <Ltr className="text-ink-2">({reason})</Ltr>
          </>
        ) : null}
      </p>
    )
  }

  const list = pickList(data)

  if (!list) {
    const entries = Object.entries(data)
    if (entries.length === 0) {
      return <p className={cn("text-ink-3 text-sm", className)}>{t("saqr.trace.noData")}</p>
    }
    return (
      <div className={cn("text-xs", className)}>
        <FieldList entries={entries} />
      </div>
    )
  }

  // A list of scalars (`classes`, `used`) becomes a one-column table so the
  // caller never has to branch on shape.
  const rows: Row[] = list.items.map((item) =>
    isPlainObject(item) ? item : { [list.field]: item }
  )

  // Union of keys across the preview, not just the first row: a tool result can
  // omit a null column on one row and carry it on the next.
  const keys: string[] = []
  for (const row of rows) {
    for (const key of Object.keys(row)) if (!keys.includes(key)) keys.push(key)
  }

  const columns: DataTableColumn<Row>[] = keys.map((key) => ({
    id: key,
    header: untrusted.includes(key) ? (
      // A dashed rule under the column name, not a badge: the mark has to
      // survive in a header cell at 11px on a 320px viewport, and a pill
      // there would push the table wider for a caveat, not for data.
      <Ltr
        className="decoration-sev-high/70 underline decoration-dashed underline-offset-4"
        title={t("saqr.trace.untrusted")}
      >
        {key}
      </Ltr>
    ) : (
      <Ltr>{key}</Ltr>
    ),
    cell: (row) => <SaqrValue value={row[key]} />,
  }))

  const rest = Object.entries(data).filter(([key]) => key !== list.field)
  // Only the fields this preview actually shows are worth naming in the note.
  const marked = untrusted.filter((field) => keys.includes(field))

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {/* `Table` owns its own `overflow-x-auto` container, so a wide result
          scrolls inside this card and the document column never widens. */}
      <div className="border-rule min-w-0 overflow-hidden rounded-md border">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(_, index) => index}
          emptyLabel={t("saqr.trace.noData")}
        />
      </div>

      <p className="text-ink-2 text-xs">
        {t("saqr.trace.previewOf", { n: rows.length })}
        {result.truncated ? ` · ${t("saqr.trace.truncated")}` : ""}
      </p>

      {/* Which of these columns came off the air. The field names are Latin
          identifiers and are isolated as one island so the list cannot
          reorder inside an Arabic sentence. */}
      {marked.length > 0 && (
        <p className="text-ink-2 text-xs">
          {t("saqr.trace.untrustedNote", { fields: marked.join(", ") })}
        </p>
      )}

      {rest.length > 0 && (
        <div className="text-xs">
          <FieldList entries={rest} />
        </div>
      )}
    </div>
  )
}
