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
 */
import * as React from "react"

import { DataTable, type DataTableColumn } from "@/components/hs/data-table"
import { Code, Ltr, Mac, Timestamp } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { isOmitted, type SaqrToolResultEvent } from "@/lib/saqr"
import { cn } from "@/lib/utils"

/** The list fields the backend trims — mirrors `_DATA_LIST_FIELDS` in tools.py. */
const LIST_FIELDS = ["rows", "groups", "rssi_points", "used", "classes"] as const

const MAC_RE = /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/
const ISO_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/
/** Printable ASCII only: an identifier, an interface name, hex, a SQL fragment. */
const ASCII_RE = /^[\x20-\x7E]*$/

/* ── One scalar ──────────────────────────────────────────────────────────── */

export function SaqrValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-ink-faint">—</span>
  }
  if (typeof value === "boolean") {
    return <Code className="text-ink-dim">{value ? "true" : "false"}</Code>
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
    // Pure-ASCII strings out of the database are technical literals — class
    // identifiers, interface names, SSIDs, hex. Anything else (an Arabic SSID,
    // a knowledge-base sentence) gets `bdi`: isolated, but free to pick its own
    // direction rather than being forced left-to-right.
    if (ASCII_RE.test(value)) return <Code className="text-ink-dim">{value}</Code>
    return <bdi>{value}</bdi>
  }
  // An object or array nested inside a cell. Compact JSON keeps the row height
  // stable; the full structure is one `sql_preview` or one answer away.
  return (
    <Code className="text-ink-faint">
      {truncate(JSON.stringify(value), 120)}
    </Code>
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
  const data = result.data ?? {}

  if (isOmitted(data)) {
    const reason = typeof data["reason"] === "string" ? (data["reason"] as string) : ""
    return (
      <p className={cn("text-ink-dim text-xs", className)}>
        {t("saqr.trace.omitted")}
        {reason ? (
          <>
            {" "}
            <Ltr className="text-ink-faint">({reason})</Ltr>
          </>
        ) : null}
      </p>
    )
  }

  const list = pickList(data)

  if (!list) {
    const entries = Object.entries(data)
    if (entries.length === 0) {
      return <p className={cn("text-ink-faint text-xs", className)}>{t("saqr.trace.noData")}</p>
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
    header: <Ltr>{key}</Ltr>,
    cell: (row) => <SaqrValue value={row[key]} />,
  }))

  const rest = Object.entries(data).filter(([key]) => key !== list.field)

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {/* The table owns the horizontal overflow; the trace column never widens. */}
      <div className="border-hairline overflow-x-auto rounded-sm border">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(_, index) => index}
          emptyLabel={t("saqr.trace.noData")}
        />
      </div>

      <p className="text-ink-faint text-xs">
        {t("saqr.trace.previewOf", { n: rows.length })}
        {result.truncated ? ` · ${t("saqr.trace.truncated")}` : ""}
      </p>

      {rest.length > 0 && (
        <div className="text-xs">
          <FieldList entries={rest} />
        </div>
      )}
    </div>
  )
}
