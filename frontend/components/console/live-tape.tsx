"use client"

/**
 * The live tape — the newest detections, printed.
 *
 * This was a `DataTable` with six columns, which is the right shape for the
 * ledger on `/threats` and the wrong one here. A tape is not a table: nobody
 * sorts it, nobody compares column to column down it, and at 320px a six-column
 * grid sheds four of them and stops being either. What an operator reads off a
 * tape is *what just happened* and *how bad it is*, so those two are the line,
 * and the machine detail sits under them in mono at caption size.
 *
 * Each entry is therefore two lines inside one hairline row: the class and its
 * grade, then the time, the address and the model's confidence. That fits 320px
 * without hiding anything, and it reads as a document rather than as a grid with
 * most of its columns missing.
 *
 * Arrival is the system's own `hs-arrival`: the row enters, tints itself with
 * its class colour and the tint decays to nothing over 900ms. The wash IS the
 * notification — there is no toast, and nothing is left glowing to compete with
 * the next arrival. Under `prefers-reduced-motion` it resolves to the settled
 * row, which is the complete frame.
 */
import * as React from "react"

import { StatusPill } from "@/components/hs/status-pill"
import { EmptyNote, LoadError } from "@/components/console/frame"
import { attackColorVar, attackLabels, severityOf, type AttackType } from "@/lib/colors"
import { Mac, Timestamp } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

export type TapeRow = {
  id: string
  ms: number | null
  type: AttackType
  mac: string | null
  /** Model confidence as a fraction, or `null` when it was not reported. */
  conf: number | null
  sim: boolean
}

export type TapeState = "ready" | "loading" | "error"

export function LiveTape({
  rows,
  state = "ready",
  emptyLabel,
  loadingLabel,
  errorLabel,
  isArriving,
  formatPercent,
  label,
}: {
  rows: readonly TapeRow[]
  state?: TapeState
  emptyLabel: React.ReactNode
  loadingLabel: React.ReactNode
  errorLabel: React.ReactNode
  /** True for rows this session actually watched arrive over the stream. */
  isArriving?: (row: TapeRow) => boolean
  formatPercent: (value: number) => string
  /** Accessible name for the list. */
  label: string
}) {
  const t = useT()

  if (state === "loading") {
    return (
      <div className="hs-scan grid min-h-40 place-items-center px-4 py-8">
        <span className="hs-label">{loadingLabel}</span>
      </div>
    )
  }

  if (state === "error") return <LoadError>{errorLabel}</LoadError>
  if (rows.length === 0) return <EmptyNote>{emptyLabel}</EmptyNote>

  return (
    <ol aria-label={label} className="flex min-w-0 flex-col">
      {rows.map((row) => {
        const severity = severityOf(row.type)
        const arriving = isArriving?.(row) ?? false

        return (
          <li
            key={row.id}
            className={cn(
              "border-rule flex min-w-0 flex-col gap-1 border-b px-4 py-2.5 last:border-b-0",
              arriving && "hs-arrival"
            )}
            style={
              arriving
                ? ({ "--hs-arrival-tint": attackColorVar(row.type) } as React.CSSProperties)
                : undefined
            }
          >
            <div className="flex min-w-0 items-center gap-2">
              <span
                aria-hidden="true"
                className="size-2 shrink-0 rounded-full"
                style={{ background: attackColorVar(row.type) }}
              />
              {/* The class identifier is what the model and the database emit.
                  It is Latin in both locales and must not be reordered. */}
              <span className="hs-ltr text-ink-0 min-w-0 flex-1 truncate text-sm font-medium">
                {attackLabels[row.type]}
              </span>
              <StatusPill tone={severity} className="shrink-0">
                {t(`severity.${severity}`)}
              </StatusPill>
            </div>

            <div className="text-ink-2 flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5 text-xs">
              {row.ms === null ? (
                <span>{t("landing.notReported")}</span>
              ) : (
                <Timestamp value={row.ms} format="time" className="text-ink-2 text-xs" />
              )}
              {row.mac && <Mac value={row.mac} className="min-w-0 truncate text-xs" />}
              {row.conf !== null && <span className="hs-num">{formatPercent(row.conf)}</span>}
              {row.sim && (
                <StatusPill tone="neutral" className="py-0.5">
                  {t("common.simulated")}
                </StatusPill>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
