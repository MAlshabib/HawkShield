"use client"

/**
 * The detection ledger.
 *
 * One thing shapes every data decision on this page: `GET /attacks` takes
 * `limit` and `offset` and nothing else. There is no `?type=`, no `?since=`, no
 * `?sa=` and no count of matching rows — so time range, class, severity and MAC
 * search cannot be pushed to the sensor, and paging cannot be either. The page
 * pulls one bounded window and filters it in the browser.
 *
 * That is a compromise, and it is stated on screen rather than hidden: the
 * footer says how many rows the filters actually ran over and how many the
 * sensor holds in total. V1 pulled 5000 rows every fifteen seconds and said
 * nothing; this pulls a smaller window on a slower clock and tells the operator
 * what it is looking at. If a `GET /attacks?since=&label=&sa=` ever lands, the
 * `filtered` memo collapses into query parameters.
 *
 * The layout is a printed ledger, not a terminal grid. The filter controls sit
 * in a *sunken* panel — the page's own paper, the one nesting case the system
 * allows — so they read as a control tray resting on the page rather than as a
 * second card competing with the table. The table itself is the only card here,
 * and it is flush to its hairline because a table carries its own cell rhythm.
 */
import * as React from "react"
import { RefreshCw } from "lucide-react"

import { AccentWord } from "@/components/hs/accent-word"
import { DataTable, type DataTableColumn, type DataTableSort } from "@/components/hs/data-table"
import { Panel } from "@/components/hs/panel"
import { Radar } from "@/components/hs/radar"
import { SectionHead } from "@/components/hs/section-head"
import { StatusPill } from "@/components/hs/status-pill"
import {
  ControlSpacer,
  ControlStrip,
  Moment,
  PageFrame,
  Unreported,
} from "@/components/console/frame"
import { Button } from "@/components/ui/button"
import { DetectionDrawer } from "@/components/threats/detection-drawer"
import { ReportDialog } from "@/components/threats/report-dialog"
import {
  EMPTY_FILTERS,
  THREAT_RANGES,
  ThreatsFilters,
  filtersAreEmpty,
  type ThreatFilters,
} from "@/components/threats/threats-filters"
import { toDetection, type Detection, type PacketRow } from "@/components/threats/detection"
import { useEventSource } from "@/hooks/use-event-source"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { apiFetchJson } from "@/lib/api"
import { attackColorVar, attackLabels } from "@/lib/colors"
import { Mac, useFormatters } from "@/lib/format"
import { useT, type TranslationKey, type Translate } from "@/lib/i18n"

/* ── Cadence ─────────────────────────────────────────────────────────────── */

const POLL_OK_MS = 20_000
const POLL_RETRY_MS = 8_000

/**
 * The window the filters run over. A quarter of V1's 5000: the sensor holds a
 * few thousand rows today, the page is honest about the ceiling in its footer,
 * and the whole thing has to stay comfortable over Wi-Fi to a Pi 4B.
 */
const FETCH_LIMIT = 1500

const PAGE_SIZE = 25

const STATE_KEY: Record<ConnectionState, TranslationKey> = {
  unknown: "dashboard.sensor.unknown",
  online: "dashboard.sensor.online",
  degraded: "dashboard.sensor.degraded",
  offline: "dashboard.sensor.offline",
}

const STATE_TONE = {
  unknown: "neutral",
  online: "info",
  degraded: "high",
  offline: "critical",
} as const

/** Same contract as the dashboard: `null` is "never loaded", not "empty". */
type Res<T> = { data: T | null; failed: boolean }
const idle = <T,>(): Res<T> => ({ data: null, failed: false })

/** Strip separators and case so `5a:11` and `5A11` both match a stored MAC. */
const squash = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "")

export default function ThreatsPage() {
  const t: Translate = useT()
  const f = useFormatters()

  const { state: connState, refresh: refreshHealth } = useHealth()
  const { state: streamState, events: streamEvents } = useEventSource("/stream", { limit: 40 })

  const [rows, setRows] = React.useState<Res<PacketRow[]>>(idle)
  const [stored, setStored] = React.useState<number | null>(null)
  const [filters, setFilters] = React.useState<ThreatFilters>(EMPTY_FILTERS)
  const [sort, setSort] = React.useState<DataTableSort>({ columnId: "time", direction: "desc" })
  const [page, setPage] = React.useState(1)
  const [selected, setSelected] = React.useState<Detection | null>(null)
  const [tick, setTick] = React.useState(0)

  const refresh = React.useCallback(() => setTick((n) => n + 1), [])

  /* ---- one bounded pull, plus the sensor's own total ---------------------- */
  React.useEffect(() => {
    let mounted = true

    void (async () => {
      try {
        const data = await apiFetchJson<PacketRow[]>(`/attacks?limit=${FETCH_LIMIT}&offset=0`, {
          cache: "no-store",
        })
        if (mounted) setRows({ data: Array.isArray(data) ? data : [], failed: false })
      } catch {
        // A failed refresh must not throw away the last good page.
        if (mounted) setRows((prev) => ({ data: prev.data, failed: true }))
      }

      try {
        const c = await apiFetchJson<{ count?: number }>("/packets/count", { cache: "no-store" })
        if (mounted && typeof c?.count === "number") setStored(c.count)
      } catch {
        /* the total is a footnote; its absence must not blank the table */
      }
    })()

    return () => {
      mounted = false
    }
  }, [tick])

  React.useEffect(() => {
    const every = connState === "online" ? POLL_OK_MS : POLL_RETRY_MS
    const timer = setInterval(refresh, every)
    return () => clearInterval(timer)
  }, [connState, refresh])

  /** A row arriving over SSE is a row the poll has not fetched yet. */
  React.useEffect(() => {
    if (streamEvents.length > 0) refresh()
  }, [streamEvents.length, refresh])

  /* ---- normalise --------------------------------------------------------- */

  const detections = React.useMemo(
    () => (rows.data ?? []).map(toDetection).filter((d) => d.id !== ""),
    [rows.data]
  )

  /* ---- filter ------------------------------------------------------------ */

  const filtered = React.useMemo(() => {
    const range = THREAT_RANGES.find((r) => r.id === filters.range) ?? THREAT_RANGES[0]
    const cutoff = range.ms === null ? null : Date.now() - range.ms
    const needle = squash(filters.search)

    return detections.filter((d) => {
      // A row with no timestamp is kept: we cannot prove it falls outside the
      // window, and silently dropping it would understate the count.
      if (cutoff !== null && d.ms !== null && d.ms < cutoff) return false
      if (filters.classes.length > 0 && !filters.classes.includes(d.type)) return false
      if (filters.severities.length > 0 && !filters.severities.includes(d.severity)) return false
      if (needle && !squash(d.srcMac ?? "").includes(needle)) return false
      return true
    })
  }, [detections, filters])

  /* ---- sort -------------------------------------------------------------- */

  const sorted = React.useMemo(() => {
    const dir = sort.direction === "asc" ? 1 : -1
    const key = sort.columnId

    // Nulls sort last in BOTH directions: "not reported" is not the smallest
    // value, it is the absence of one, and it should never head the table.
    const cmp = (a: number | null, b: number | null) => {
      if (a === null && b === null) return 0
      if (a === null) return 1
      if (b === null) return -1
      return (a - b) * dir
    }

    const pick = (d: Detection): number | null =>
      key === "confidence" ? d.confidence : key === "channel" ? d.channel : key === "rssi" ? d.rssi : d.ms

    return [...filtered].sort((a, b) => cmp(pick(a), pick(b)) || (b.ms ?? -1) - (a.ms ?? -1))
  }, [filtered, sort])

  /* ---- page -------------------------------------------------------------- */

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)

  React.useEffect(() => setPage(1), [filters, sort])

  const pageRows = React.useMemo(
    () => sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
    [sorted, currentPage]
  )

  /* ---- columns ----------------------------------------------------------- */

  /**
   * Nine columns is more than a phone can carry, so the table sheds the widest
   * ones as the viewport narrows and says so under the table. At 320px what
   * survives is time, class and severity — the three questions a ledger is read
   * for — and the row itself opens the drawer, which holds everything.
   */
  const columns: DataTableColumn<Detection>[] = React.useMemo(
    () => [
      {
        id: "time",
        header: t("threats.column.time"),
        sortable: true,
        width: "11rem",
        cell: (d) =>
          d.ms === null ? <Unreported /> : <Moment value={d.ms} className="text-ink-2 text-xs" />,
      },
      {
        id: "class",
        header: t("threats.column.class"),
        cell: (d) => (
          <span className="inline-flex items-center gap-2">
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ background: attackColorVar(d.type) }}
            />
            {/* Latin in both locales — this is what the model emits. */}
            <span className="hs-ltr text-ink-0 text-sm">{attackLabels[d.type]}</span>
          </span>
        ),
      },
      {
        id: "severity",
        header: t("threats.column.severity"),
        width: "7rem",
        cell: (d) => <StatusPill tone={d.severity}>{t(`severity.${d.severity}`)}</StatusPill>,
      },
      {
        id: "source",
        header: t("threats.column.sourceMac"),
        hideBelow: "sm",
        cell: (d) => (d.srcMac ? <Mac value={d.srcMac} className="text-ink-2 text-xs" /> : <Unreported />),
      },
      {
        id: "dest",
        header: t("threats.column.destMac"),
        hideBelow: "lg",
        cell: (d) => (d.dstMac ? <Mac value={d.dstMac} className="text-ink-2 text-xs" /> : <Unreported />),
      },
      {
        id: "channel",
        header: t("threats.column.channel"),
        numeric: true,
        sortable: true,
        width: "5.5rem",
        hideBelow: "md",
        cell: (d) => (d.channel === null ? <Unreported /> : f.number(d.channel)),
      },
      {
        id: "rssi",
        header: t("threats.column.rssi"),
        numeric: true,
        sortable: true,
        width: "6.5rem",
        hideBelow: "md",
        // `hs-num` on the cell (via `numeric`) isolates the run, so a negative
        // dBm figure cannot render as `64-` inside the Arabic page. `rssi` is
        // already `null` rather than `0` where the sensor reported nothing —
        // see the `num()` guard in `components/threats/detection.ts`.
        cell: (d) => (d.rssi === null ? <Unreported /> : f.number(d.rssi)),
      },
      {
        id: "confidence",
        header: t("threats.column.confidence"),
        numeric: true,
        sortable: true,
        width: "6.5rem",
        hideBelow: "sm",
        cell: (d) => (d.confidence === null ? <Unreported /> : f.percent(d.confidence, 0)),
      },
      {
        id: "origin",
        header: "",
        width: "6rem",
        hideBelow: "sm",
        cell: (d) => (d.sim ? <StatusPill tone="neutral">{t("common.simulated")}</StatusPill> : null),
      },
    ],
    [t, f]
  )

  /* ---- render ------------------------------------------------------------ */

  const never = rows.data === null
  const tableState = never && rows.failed ? "error" : never ? "loading" : "ready"
  const windowSize = detections.length

  return (
    <PageFrame>
      <SectionHead
        as="h1"
        eyebrow={t("threats.title")}
        title={
          <>
            {t("threats.head.lead")}
            <AccentWord>{t("threats.head.accent")}</AccentWord>
          </>
        }
        body={t("threats.subtitle")}
      />

      <ControlStrip>
        <StatusPill tone={STATE_TONE[connState]} dot>
          {t(STATE_KEY[connState])}
        </StatusPill>
        <Radar size={12} active={streamState === "open"} label={t("conn.streaming")} />
        <span className="hs-label hidden sm:inline">
          {streamState === "open" ? t("conn.streaming") : t("conn.polling")}
        </span>

        <ControlSpacer />

        <ReportDialog />
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            refreshHealth()
            refresh()
          }}
        >
          <RefreshCw aria-hidden="true" />
          {t("common.refresh")}
        </Button>
      </ControlStrip>

      {/* The control tray. `sunken` drops it to the page paper so it reads as
          the page's own furniture rather than as a card of its own. */}
      <Panel label={t("common.filters")} surface="sunken">
        <ThreatsFilters filters={filters} onChange={setFilters} />
      </Panel>

      <Panel
        label={t("threats.title")}
        title={t("common.showing", {
          shown: f.number(sorted.length),
          total: f.number(windowSize),
        })}
        flush
      >
        <DataTable
          columns={columns}
          rows={pageRows}
          rowKey={(d) => d.id}
          state={tableState}
          emptyLabel={filtersAreEmpty(filters) ? t("threats.empty") : t("threats.noResults")}
          loadingLabel={t("threats.loading")}
          errorLabel={t("threats.error.load")}
          sort={sort}
          onSortChange={setSort}
          selectedKey={selected?.id ?? null}
          onRowSelect={(d) => setSelected(d)}
          tintOf={(d) => attackColorVar(d.type)}
        />

        {/* Paging lives inside the panel, under the table's own hairline, so it
            reads as part of the instrument rather than as page furniture. */}
        {tableState === "ready" && sorted.length > 0 && (
          <div className="border-rule flex flex-wrap items-center justify-between gap-3 border-t px-4 py-2.5">
            <span className="hs-label">
              {t("common.pageOf", { page: f.number(currentPage), total: f.number(totalPages) })}
            </span>
            <div className="flex items-center gap-1.5">
              <Button
                size="sm"
                variant="secondary"
                disabled={currentPage <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                {t("common.previous")}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={currentPage >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                {t("common.next")}
              </Button>
            </div>
          </div>
        )}
      </Panel>

      <div className="text-ink-2 flex max-w-[86ch] flex-col gap-1 text-xs">
        <p>
          {t("threats.window", { n: f.number(windowSize) })}{" "}
          {stored !== null && t("threats.stored", { n: f.number(stored) })}
        </p>
        <p className="lg:hidden">{t("threats.tableScroll")}</p>
        <p className="hs-label mt-1">{t("time.timezone")}</p>
      </div>

      <DetectionDrawer detection={selected} onClose={() => setSelected(null)} />
    </PageFrame>
  )
}
