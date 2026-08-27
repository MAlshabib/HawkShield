"use client"

/**
 * The ops console.
 *
 * Eight instruments over one polling loop. Three rules shaped every decision in
 * here:
 *
 * **Nothing is recomputed in the browser that the sensor can answer itself.**
 * The V1 dashboard pulled `/attacks?limit=5000` on every refresh and derived
 * the offender table, the channel table and the activity series from it, then
 * labelled them "local" — a quarter of a megabyte over the wire, on a Pi 4B, to
 * recompute GROUP BYs the database had already indexed for. Every one of those
 * is now a server-side aggregate: `/top-offenders`, `/channel-usage`,
 * `/heatmap-attack` and `/attacks/series`, alongside `/reports/summary`.
 *
 * **The range selector governs the whole page.** Every aggregate here takes
 * `days`, so there is no module left that quietly answers for all time while
 * the ones beside it answer for the last 24 hours.
 *
 * **A figure the sensor did not report is not a zero.** Every resource carries
 * its own `failed` flag, a failed refresh leaves the last good value on screen,
 * and a module that has never loaded says so rather than rendering an empty
 * instrument that looks like a quiet network. That extends to the sensor
 * readout: `/health.capture` reports `null` for anything it could not measure,
 * and `null` is rendered as *not reported*, never as a healthy default.
 */
import * as React from "react"
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { RefreshCw } from "lucide-react"

import { DataTable, type DataTableColumn } from "@/components/hs/data-table"
import { Metric } from "@/components/hs/metric"
import { Module, ModuleGrid } from "@/components/hs/module"
import { Radar } from "@/components/hs/radar"
import { StatusPill } from "@/components/hs/status-pill"
import { Quantity } from "@/components/quantity"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useEventSource } from "@/hooks/use-event-source"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { apiFetchJson } from "@/lib/api"
import {
  attackColorVar,
  attackLabels,
  attackTypes,
  severityOf,
  type AttackType,
  type Severity,
} from "@/lib/colors"
import { apiTimeMs, freqToChannel, riyadhParts, toAttackType } from "@/lib/detections"
import { Mac, TIMEZONE, Timestamp, useFormatters } from "@/lib/format"
import { useLocale, useT, type TranslationKey, type Translate } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/* ── Cadence ─────────────────────────────────────────────────────────────── */

/** Relaxed while healthy, brisk while trying to recover. Unchanged from V1. */
const POLL_OK_MS = 20_000
const POLL_RETRY_MS = 8_000

/** Enough rows for the live tape without pulling the table. */
const TAPE_LIMIT = 60

/**
 * How many offenders the table shows. `/top-offenders` defaults to 50 and ties
 * break on `wlan_sa` ascending, so asking for exactly what is rendered is both
 * smaller on the wire and deterministic — the page must not depend on the
 * endpoint handing back every distinct source MAC, which it no longer does.
 */
const OFFENDER_LIMIT = 20

/**
 * The sensor buckets on this wall clock, so the heatmap and the activity series
 * agree with the timestamps `lib/format` prints in the tape beside them. An
 * unknown zone is a 400 from the backend, never a silent fall back to UTC.
 */
const TZ = encodeURIComponent(TIMEZONE)

/* ── Range ───────────────────────────────────────────────────────────────── */

type RangeId = "24h" | "7d" | "30d"

const RANGES: readonly { id: RangeId; days: number; key: TranslationKey }[] = [
  { id: "24h", days: 1, key: "time.range.hours24" },
  { id: "7d", days: 7, key: "time.range.days7" },
  { id: "30d", days: 30, key: "time.range.days30" },
]

const rangeOf = (id: RangeId) => RANGES.find((r) => r.id === id) ?? RANGES[0]

type SeriesBucket = "hour" | "day"

/**
 * `/attacks/series` answers **400** past these ceilings rather than clamping
 * quietly (CONTRACT §4), so the page clamps the request instead of firing one
 * it already knows will fail, and says on the chart that it did. No range in
 * `RANGES` reaches either ceiling today; this is what keeps that true when one
 * is added.
 */
const SERIES_MAX_DAYS: Record<SeriesBucket, number> = { hour: 31, day: 366 }

/** A day of detections is legible hour by hour; a month of them is not. */
const bucketFor = (days: number): SeriesBucket => (days <= 1 ? "hour" : "day")

/* ── Wire shapes ─────────────────────────────────────────────────────────── */

type ReportSummary = {
  period?: string
  totals?: Record<string, number>
  summary?: {
    totalAttacks?: number
    mostFrequentType?: string
    peakHour?: number
    uniqueSources?: number
  }
}

type PacketRow = {
  id: number | string
  ts?: string | null
  src_mac?: string | null
  bssid?: string | null
  predicted_label?: string | null
  proba_attack?: number | null
  raw?: { sim?: boolean } | null
}

type OffenderRow = { wlan_sa: string; count: number }
type ChannelRow = { channel_freq: number; count: number }
type HeatRow = { day: string; hours: { hour: number; intensity: number }[] }

/**
 * `/attacks/series`. Zero-filled by the backend — a quiet hour is a `0` and
 * never a gap — and `t` carries the local UTC offset, so it parses to the right
 * instant without being re-stamped.
 */
type SeriesPayload = {
  bucket?: SeriesBucket
  tz?: string
  days?: number
  total?: number
  outside_range?: number
  points?: { t?: string | null; count?: number | null }[] | null
}

/**
 * `data: null` means "never loaded", which is not the same as an empty result;
 * `failed` records that the most recent attempt did not land, without throwing
 * away the last value that did.
 */
type Res<T> = { data: T | null; failed: boolean }

const idle = <T,>(): Res<T> => ({ data: null, failed: false })

async function read<T>(path: string, set: (r: Res<T>) => void, alive: () => boolean) {
  try {
    const data = await apiFetchJson<T>(path, { cache: "no-store" })
    if (alive()) set({ data, failed: false })
  } catch {
    if (alive()) set({ data: null, failed: true })
  }
}

/* ── Sensor vocabulary ───────────────────────────────────────────────────── */

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

/** Sun-first, matching the order `/heatmap-attack` returns. */
const DAY_KEYS: Record<string, TranslationKey> = {
  Sun: "day.sun",
  Mon: "day.mon",
  Tue: "day.tue",
  Wed: "day.wed",
  Thu: "day.thu",
  Fri: "day.fri",
  Sat: "day.sat",
}

/**
 * A packet arriving within this window is what makes the radar sweep. A sweep
 * over a sensor that stopped capturing an hour ago is a lie told continuously —
 * see the note in `components/hs/radar.tsx`.
 */
const LIVE_WINDOW_MS = 10 * 60_000

/* ── Local scaffolding ───────────────────────────────────────────────────── */

/** One label/value line of the sensor readout. */
function Field({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-hairline flex items-center justify-between gap-4 border-b py-1.5 last:border-0">
      <span className="hs-label shrink-0">{label}</span>
      <span className="text-ink min-w-0 truncate text-end text-sm">{children}</span>
    </div>
  )
}

/** "Not reported" rather than a dash that could be mistaken for a zero. */
function Unreported() {
  const t = useT()
  return <span className="text-ink-faint text-xs">{t("landing.notReported")}</span>
}

/**
 * Recharts draws into an SVG whose coordinate system does not mirror, and whose
 * `<text>` nodes inherit `direction` from CSS — so an axis tick reading
 * `-64 dBm` or `1,284` can be reordered by the bidi algorithm inside an Arabic
 * page while the data is perfectly correct. Pinning the chart's own subtree to
 * LTR fixes that at the root; the axes themselves are then mirrored explicitly
 * with `reversed` / `orientation`, which is the part a reader actually wants
 * flipped. The tooltip is a plain div inside this wrapper, so it inherits the
 * same isolation and is given back its real direction by `dir` on its content.
 */
function ChartFrame({ height, children }: { height: number; children: React.ReactElement }) {
  return (
    <div dir="ltr" style={{ blockSize: height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  )
}

const AXIS = {
  stroke: "var(--hairline-strong)",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
} as const

const tooltipStyles = (dir: "ltr" | "rtl") => ({
  contentStyle: {
    background: "var(--surface-raised)",
    border: "1px solid var(--hairline-strong)",
    borderRadius: 2,
    padding: "6px 10px",
    fontSize: 12,
    direction: dir,
  } as React.CSSProperties,
  labelStyle: { color: "var(--ink)", fontFamily: "var(--font-mono)" } as React.CSSProperties,
  itemStyle: { color: "var(--ink-dim)" } as React.CSSProperties,
  cursor: { fill: "color-mix(in oklab, var(--hs-azure) 8%, transparent)" },
})

/* ── Page ────────────────────────────────────────────────────────────────── */

export default function DashboardPage() {
  const t: Translate = useT()
  const f = useFormatters()
  const { dir } = useLocale()
  const isRTL = dir === "rtl"

  const [rangeId, setRangeId] = React.useState<RangeId>("24h")
  const range = rangeOf(rangeId)

  const { state: connState, health, refresh: refreshHealth } = useHealth()
  const { state: streamState, events: streamEvents } = useEventSource("/stream", { limit: 40 })

  const [summary, setSummary] = React.useState<Res<ReportSummary>>(idle)
  const [tape, setTape] = React.useState<Res<PacketRow[]>>(idle)
  const [series, setSeries] = React.useState<Res<SeriesPayload>>(idle)
  const [heat, setHeat] = React.useState<Res<HeatRow[]>>(idle)
  const [offenders, setOffenders] = React.useState<Res<OffenderRow[]>>(idle)
  const [channels, setChannels] = React.useState<Res<ChannelRow[]>>(idle)
  const [updatedAt, setUpdatedAt] = React.useState<number | null>(null)
  const [tick, setTick] = React.useState(0)

  const refresh = React.useCallback(() => setTick((n) => n + 1), [])

  /** The series request the selected range maps to, clamped to what the bucket allows. */
  const seriesQuery = React.useMemo(() => {
    const bucket = bucketFor(range.days)
    const days = Math.min(range.days, SERIES_MAX_DAYS[bucket])
    return { bucket, days, clamped: days < range.days }
  }, [range.days])

  /* ---- one loop: every module, one range --------------------------------- */
  React.useEffect(() => {
    let mounted = true
    const alive = () => mounted

    void (async () => {
      await Promise.all([
        read<ReportSummary>(`/reports/summary?days=${range.days}`, setSummary, alive),
        read<PacketRow[]>(`/attacks?limit=${TAPE_LIMIT}&offset=0`, setTape, alive),
        read<SeriesPayload>(
          `/attacks/series?days=${seriesQuery.days}&bucket=${seriesQuery.bucket}&tz=${TZ}`,
          setSeries,
          alive
        ),
        read<HeatRow[]>(`/heatmap-attack?days=${range.days}&tz=${TZ}`, setHeat, alive),
        read<OffenderRow[]>(`/top-offenders?days=${range.days}&limit=${OFFENDER_LIMIT}`, setOffenders, alive),
        read<ChannelRow[]>(`/channel-usage?days=${range.days}`, setChannels, alive),
      ])
      if (mounted) setUpdatedAt(Date.now())
    })()

    return () => {
      mounted = false
    }
  }, [tick, range.days, seriesQuery])

  React.useEffect(() => {
    const every = connState === "online" ? POLL_OK_MS : POLL_RETRY_MS
    const timer = setInterval(refresh, every)
    return () => clearInterval(timer)
  }, [connState, refresh])

  /* ---- sensor ------------------------------------------------------------ */

  const newest = tape.data?.[0] ?? null
  const lastPacketMs = apiTimeMs(health?.latest_packet_ts ?? newest?.ts ?? null)
  const sensorLive =
    connState === "online" && lastPacketMs !== null && Date.now() - lastPacketMs < LIVE_WINDOW_MS

  /**
   * What the sensor is set to, and what the API process could actually measure
   * of it. This replaces reading `iface` and `channel_freq` off the newest
   * stored packet — an inference the page then had to caption. `capture` is
   * absent on a backend older than the block, which is a third state: neither
   * measured nor "measured as null".
   */
  const capture = health?.capture ?? null
  // `source` is `"config"` when nothing could be measured. Each field is still
  // rendered from its own value, so a `null` reads as unreported either way.
  const captureMeasured = capture?.source ? capture.source !== "config" : false
  const observedChannel = freqToChannel(capture?.observed_channel_freq)
  const configuredChannel =
    typeof capture?.channel === "number" && Number.isFinite(capture.channel) ? capture.channel : null

  /* ---- ledger + class distribution (server-side, range-aware) ------------ */

  const totals = summary.data?.totals ?? null

  const bySeverity = React.useMemo(() => {
    const acc: Record<Severity, number> = { critical: 0, high: 0, info: 0 }
    if (!totals) return acc
    for (const [key, n] of Object.entries(totals)) {
      acc[severityOf(toAttackType(key))] += Number(n) || 0
    }
    return acc
  }, [totals])

  const classRows = React.useMemo(() => {
    if (!totals) return []
    // Every class the spec defines is listed even at zero: "we looked and found
    // none" is a finding, and a legend that silently drops a class reads as a
    // model that cannot detect it. `other` only appears when it is non-empty,
    // since it is a catch-all bucket rather than a ninth class.
    const rows = attackTypes
      .filter((type) => type !== "other" || Number(totals.other) > 0)
      .map((type) => ({
        type,
        label: attackLabels[type],
        value: Number(totals[type]) || 0,
        color: attackColorVar(type),
      }))
    return rows.sort((a, b) => b.value - a.value || attackTypes.indexOf(a.type) - attackTypes.indexOf(b.type))
  }, [totals])

  const classTotal = classRows.reduce((n, r) => n + r.value, 0)

  /* ---- activity over time ------------------------------------------------ */

  /**
   * The series arrives zero-filled and already bucketed on Riyadh wall clock,
   * so a bar labelled 14:00 holds exactly the rows the tape prints as 14:xx.
   * Nothing is folded here — a point is only dropped when it carries no
   * parseable instant or no finite count, which is a malformed point rather
   * than a quiet one, and plotting it as a zero would invent a reading.
   */
  const activity = React.useMemo(() => {
    const payload = series.data
    if (!payload) return null

    const hourly = seriesQuery.bucket === "hour"
    const points = (payload.points ?? []).flatMap((p) => {
      const ms = apiTimeMs(p.t)
      if (ms === null) return []
      if (typeof p.count !== "number" || !Number.isFinite(p.count)) return []
      return [
        {
          ms,
          count: p.count,
          label: hourly ? `${String(riyadhParts(ms).hour).padStart(2, "0")}:00` : f.date(ms),
        },
      ]
    })

    return { empty: points.every((p) => p.count === 0), hourly, points }
  }, [series.data, seriesQuery.bucket, f])

  /* ---- live tape --------------------------------------------------------- */

  // Ids the stream delivered while this page has been open. Only those rows get
  // the arrival wash; a polled backlog must not flash on every refresh.
  const arrived = React.useRef<Set<string>>(new Set())
  for (const e of streamEvents) arrived.current.add(String(e.id))

  const tapeRows = React.useMemo(() => {
    type Row = {
      id: string
      ms: number | null
      type: AttackType
      mac: string | null
      conf: number | null
      sim: boolean
    }

    const fromStream: Row[] = streamEvents.map((e) => ({
      id: String(e.id ?? ""),
      ms: apiTimeMs(e.ts),
      type: toAttackType(e.predicted_label),
      mac: e.src_mac || e.bssid || null,
      conf: typeof e.p2 === "number" ? e.p2 : null,
      sim: Boolean(e.sim),
    }))

    const fromPoll: Row[] = (tape.data ?? []).map((r) => ({
      id: String(r.id ?? ""),
      ms: apiTimeMs(r.ts),
      type: toAttackType(r.predicted_label),
      mac: r.src_mac || r.bssid || null,
      conf: typeof r.proba_attack === "number" ? r.proba_attack : null,
      sim: Boolean(r.raw?.sim),
    }))

    const seen = new Set<string>()
    return [...fromStream, ...fromPoll]
      .filter((r) => {
        if (!r.id || seen.has(r.id)) return false
        seen.add(r.id)
        return true
      })
      .sort((a, b) => (b.ms ?? -1) - (a.ms ?? -1))
      .slice(0, 25)
  }, [streamEvents, tape.data])

  const tapeColumns: DataTableColumn<(typeof tapeRows)[number]>[] = React.useMemo(
    () => [
      {
        id: "time",
        header: t("threats.column.time"),
        width: "9rem",
        cell: (row) =>
          row.ms === null ? <Unreported /> : <Timestamp value={row.ms} format="time" className="text-ink-dim" />,
      },
      {
        id: "class",
        header: t("dashboard.column.class"),
        cell: (row) => (
          <span className="inline-flex items-center gap-2">
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ background: attackColorVar(row.type) }}
            />
            {/* A class identifier is what the model and the database emit; it is
                Latin in both locales and must not be reordered. */}
            <span className="text-ink hs-ltr">{attackLabels[row.type]}</span>
          </span>
        ),
      },
      {
        id: "severity",
        header: t("severity.label"),
        hideBelow: "sm",
        cell: (row) => (
          <StatusPill tone={severityOf(row.type)}>{t(`severity.${severityOf(row.type)}`)}</StatusPill>
        ),
      },
      {
        id: "source",
        header: t("dashboard.column.sourceMac"),
        hideBelow: "md",
        cell: (row) => (row.mac ? <Mac value={row.mac} className="text-ink-dim text-xs" /> : <Unreported />),
      },
      {
        id: "confidence",
        header: t("threats.column.confidence"),
        numeric: true,
        width: "6rem",
        hideBelow: "sm",
        cell: (row) => (row.conf === null ? <Unreported /> : f.percent(row.conf, 0)),
      },
      {
        id: "origin",
        header: "",
        width: "5.5rem",
        cell: (row) =>
          row.sim ? (
            <StatusPill tone="neutral">{t("common.simulated")}</StatusPill>
          ) : null,
      },
    ],
    [t, f]
  )

  /* ---- heatmap ----------------------------------------------------------- */

  const heatRows = heat.data ?? []
  const heatMax = React.useMemo(
    () => heatRows.reduce((m, r) => r.hours.reduce((n, c) => Math.max(n, c.intensity ?? 0), m), 0),
    [heatRows]
  )

  /* ---- tables ------------------------------------------------------------ */

  // Already limited on the wire — `OFFENDER_LIMIT` rows is the whole response.
  const offenderRows = offenders.data ?? []
  const offenderColumns: DataTableColumn<OffenderRow>[] = React.useMemo(
    () => [
      {
        id: "rank",
        header: t("common.rank"),
        numeric: true,
        width: "3.5rem",
        cell: (_row, i) => f.number(i + 1),
      },
      {
        id: "mac",
        header: t("dashboard.column.sourceMac"),
        cell: (row) => <Mac value={row.wlan_sa} className="text-ink text-xs" />,
      },
      {
        id: "count",
        header: t("dashboard.column.count"),
        numeric: true,
        width: "6rem",
        cell: (row) => f.number(row.count),
      },
    ],
    [t, f]
  )

  const channelRows = channels.data ?? []
  const channelTotal = channelRows.reduce((n, r) => n + (Number(r.count) || 0), 0)
  const channelColumns: DataTableColumn<ChannelRow>[] = React.useMemo(
    () => [
      {
        id: "channel",
        header: t("units.channel"),
        numeric: true,
        width: "5rem",
        cell: (row) => {
          const ch = freqToChannel(row.channel_freq)
          return ch === null ? <Unreported /> : f.number(ch)
        },
      },
      {
        id: "freq",
        header: t("units.frequency"),
        numeric: true,
        width: "8rem",
        // `hs-num` isolates the run, so `5180 MHz` cannot render as `MHz 5180`.
        cell: (row) => (
          <span className="hs-num">
            {f.number(row.channel_freq)} {t("units.mhz")}
          </span>
        ),
      },
      {
        id: "count",
        header: t("dashboard.column.count"),
        numeric: true,
        width: "6rem",
        cell: (row) => f.number(row.count),
      },
      {
        id: "share",
        header: t("dashboard.channels.share"),
        hideBelow: "sm",
        cell: (row) => {
          const share = channelTotal > 0 ? row.count / channelTotal : 0
          return (
            <span className="flex items-center gap-2">
              {/* `inline-size` on a flex track, so the bar grows from the
                  inline-start edge in both directions with no override. */}
              <span className="bg-surface-sunken border-hairline h-1.5 w-full min-w-16 overflow-hidden rounded-full border">
                <span
                  className="bg-hs-azure block h-full"
                  style={{ inlineSize: `${Math.max(2, share * 100)}%` }}
                />
              </span>
              <span className="hs-num text-ink-dim w-12 shrink-0 text-end text-xs">
                {f.percent(share, 0)}
              </span>
            </span>
          )
        },
      },
    ],
    [t, f, channelTotal]
  )

  /* ---- render ------------------------------------------------------------ */

  const tone = STATE_TONE[connState]
  const tip = tooltipStyles(dir)
  const rangeLabel = t(range.key)

  /**
   * The count, set just past the bar's own tip.
   *
   * Derived from the geometry recharts actually emitted rather than from a
   * `position` keyword or from `isRTL`: a reversed value axis makes the bar
   * rect's `width` NEGATIVE and anchors `x` at the baseline, so `x + width` is
   * the tip in both directions and the sign of `width` gives the side to hang
   * the text on. `props.x/width` are the plotting area, not the bar — the bar's
   * box only arrives as `viewBox`.
   */
  const BarValue = (props: unknown) => {
    const { viewBox, value } = props as {
      viewBox?: { x?: number; y?: number; width?: number; height?: number }
      value?: number
    }
    if (!viewBox) return null
    const { x, y, width, height } = viewBox
    if (x == null || y == null || width == null || height == null) return null
    const side = width < 0 ? -1 : 1
    return (
      <text
        x={x + width + side * 6}
        y={y + height / 2}
        dy={4}
        textAnchor={side < 0 ? "end" : "start"}
        style={{ fill: "var(--ink-dim)", fontSize: 11, fontFamily: "var(--font-mono)" }}
      >
        {f.number(Number(value))}
      </text>
    )
  }

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-6 sm:gap-4 lg:px-8">
      {/* ---- page head ---------------------------------------------------- */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-ink font-display text-2xl leading-none font-medium sm:text-3xl">
            {t("dashboard.title")}
          </h1>
          <p className="text-ink-dim text-sm">{t("dashboard.subtitle")}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <StatusPill tone={tone} dot>
            {t(STATE_KEY[connState])}
          </StatusPill>

          {updatedAt !== null && (
            <span className="text-ink-faint hidden text-xs sm:inline">
              {t("common.updatedAgo", { ago: "" }).trim()}{" "}
              <Timestamp value={updatedAt} format="relative" className="text-ink-faint" />
            </span>
          )}

          <Select dir={dir} value={rangeId} onValueChange={(v) => setRangeId(v as RangeId)}>
            <SelectTrigger className="w-40" aria-label={t("time.range.label")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RANGES.map((r) => (
                <SelectItem key={r.id} value={r.id}>
                  {t(r.key)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              refreshHealth()
              refresh()
            }}
          >
            <RefreshCw aria-hidden="true" />
            {t("common.refresh")}
          </Button>
        </div>
      </header>

      {/* ---- 1. sensor · 2. live tape ------------------------------------- */}
      <ModuleGrid className="lg:grid-cols-3">
        <Module
          label={t("dashboard.sensor.title")}
          actions={
            <Radar
              size={11}
              active={sensorLive}
              label={sensorLive ? t("dashboard.sensor.live") : t("dashboard.sensor.idle")}
            />
          }
        >
          <div className="flex flex-col">
            <Field label={t("dashboard.sensor.state")}>
              <StatusPill tone={tone} dot>
                {t(STATE_KEY[connState])}
              </StatusPill>
            </Field>
            <Field label={t("dashboard.sensor.interface")}>
              {capture?.iface ? (
                <span className="inline-flex items-center gap-2">
                  <span className="hs-ltr font-mono">{capture.iface}</span>
                  {/* `present` is only ever `false` when sysfs was actually read
                      and the interface was not there — a measured absence, not
                      an unknown, and the one capture fault worth a pill. */}
                  {capture.present === false && (
                    <StatusPill tone="critical">{t("dashboard.sensor.notPresent")}</StatusPill>
                  )}
                </span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.channel")}>
              {configuredChannel === null ? (
                <Unreported />
              ) : (
                <span className="hs-num">{f.number(configuredChannel)}</span>
              )}
            </Field>
            <Field label={t("dashboard.sensor.monitorMode")}>
              {/* Three states, not two: `true`, a measured `false` that means the
                  radio is not capturing, and `null` — nothing was measured. */}
              {capture?.monitor_mode === true ? (
                <StatusPill tone="info">{t("common.yes")}</StatusPill>
              ) : capture?.monitor_mode === false ? (
                <StatusPill tone="high">{t("common.no")}</StatusPill>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.linkState")}>
              {/* `up` / `down` / `dormant` are kernel identifiers: Latin in both
                  locales, and isolated so they never join the Arabic run. */}
              {capture?.operstate ? (
                <span className="hs-ltr font-mono">{capture.operstate}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.observedIface")}>
              {capture?.observed_iface ? (
                <span className="hs-ltr font-mono">{capture.observed_iface}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.observedChannel")}>
              {observedChannel === null ? (
                <Unreported />
              ) : (
                <span className="inline-flex items-center gap-2">
                  <span className="hs-num">{f.number(observedChannel)}</span>
                  <span className="text-ink-faint text-xs">
                    <Quantity value={f.number(capture?.observed_channel_freq)} unit={t("units.mhz")} />
                  </span>
                </span>
              )}
            </Field>
            <Field label={t("dashboard.sensor.model")}>
              {health?.model_version && health.model_version !== "none" ? (
                <span className="hs-ltr font-mono">{health.model_version}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.spec")}>
              {health?.spec_version ? (
                <span className="hs-num">{health.spec_version}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.packets")}>
              {typeof health?.packets === "number" ? (
                <span className="hs-num">{f.number(health.packets)}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("dashboard.sensor.lastSeen")}>
              {lastPacketMs === null ? <Unreported /> : <Timestamp value={lastPacketMs} format="relative" />}
            </Field>
          </div>
          {capture && (
            <p className="text-ink-faint mt-3 text-xs">
              {captureMeasured ? t("dashboard.sensor.measured") : t("dashboard.sensor.configOnly")}
            </p>
          )}
        </Module>

        <Module
          className="lg:col-span-2"
          label={t("dashboard.tape.title")}
          title={t("dashboard.tape.subtitle")}
          flush
          actions={
            <>
              <Radar size={11} active={streamState === "open"} label={t("conn.streaming")} />
              <StatusPill tone={streamState === "open" ? "info" : "neutral"}>
                {streamState === "open" ? t("conn.streaming") : t("conn.polling")}
              </StatusPill>
            </>
          }
        >
          <DataTable
            columns={tapeColumns}
            rows={tapeRows}
            rowKey={(row) => row.id}
            state={tape.data === null && tape.failed ? "error" : tape.data === null ? "loading" : "ready"}
            emptyLabel={t("dashboard.empty.feed")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
            isArriving={(row) => arrived.current.has(row.id)}
            tintOf={(row) => attackColorVar(row.type)}
          />
        </Module>
      </ModuleGrid>

      {/* ---- 3. severity ledger ------------------------------------------- */}
      <Module label={t("dashboard.ledger.title")} title={rangeLabel} loading={summary.data === null && !summary.failed}>
        {summary.data === null && summary.failed ? (
          <p className="text-sev-critical hs-label py-4">{t("dashboard.error.load")}</p>
        ) : (
          <div className="grid grid-cols-2 gap-6 py-1 lg:grid-cols-4">
            <Metric
              label={t("dashboard.ledger.total")}
              value={Number(summary.data?.summary?.totalAttacks ?? 0)}
              format={f.number}
            />
            <Metric label={t("severity.critical")} value={bySeverity.critical} format={f.number} tone="critical" />
            <Metric label={t("severity.high")} value={bySeverity.high} format={f.number} tone="high" />
            <Metric
              label={t("dashboard.ledger.uniqueSources")}
              value={Number(summary.data?.summary?.uniqueSources ?? 0)}
              format={f.number}
            />
          </div>
        )}
      </Module>

      {/* ---- 4. class distribution · 5. activity --------------------------- */}
      <ModuleGrid className="lg:grid-cols-2">
        <Module
          label={t("dashboard.classes.title")}
          title={rangeLabel}
          loading={summary.data === null && !summary.failed}
        >
          {summary.data === null && summary.failed ? (
            <p className="text-sev-critical hs-label py-4">{t("dashboard.error.load")}</p>
          ) : classRows.length === 0 ? (
            <p className="hs-label py-8 text-center">{t("dashboard.empty.summary")}</p>
          ) : (
            <>
              <ChartFrame height={Math.max(240, classRows.length * 30 + 24)}>
                <BarChart
                  data={classRows}
                  layout="vertical"
                  // The value labels sit past the bar's tip, so the gutter they
                  // need is on the inline-END side — which is the left margin
                  // once the value axis has been reversed for Arabic.
                  margin={{ top: 4, right: isRTL ? 8 : 44, bottom: 4, left: isRTL ? 44 : 8 }}
                  barCategoryGap="22%"
                >
                  <CartesianGrid horizontal={false} stroke="var(--hairline)" />
                  {/* Under RTL the value axis runs right-to-left and the
                      category axis moves to the right edge, so the bars grow
                      away from the labels in the reader's own direction. */}
                  <XAxis
                    type="number"
                    reversed={isRTL}
                    orientation="bottom"
                    tickLine={false}
                    axisLine={false}
                    tick={{ fill: "var(--ink-faint)", ...AXIS }}
                    allowDecimals={false}
                    domain={[0, (max: number) => Math.max(1, Math.ceil(max * 1.18))]}
                  />
                  <YAxis
                    type="category"
                    dataKey="label"
                    orientation={isRTL ? "right" : "left"}
                    // Wide enough for `Disassociation`, the longest class name,
                    // in the mono face at 11px. At 78 it clipped under RTL.
                    width={98}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fill: "var(--ink-dim)", ...AXIS }}
                  />
                  <Tooltip
                    {...tip}
                    formatter={(value) => [f.number(Number(value)), t("dashboard.classes.axis")]}
                  />
                  <Bar dataKey="value" radius={1} isAnimationActive={false}>
                    {classRows.map((row) => (
                      <Cell key={row.type} fill={row.color} />
                    ))}
                    {/* Recharts' `position` keywords are resolved against a
                        viewBox that a reversed axis turns inside out, which put
                        every figure on top of the category labels in Arabic.
                        Placing the text from the bar's own geometry is exact in
                        both directions and needs no keyword at all. */}
                    <LabelList dataKey="value" content={BarValue} />
                  </Bar>
                </BarChart>
              </ChartFrame>
              {classTotal === 0 && (
                <p className="text-ink-faint mt-2 text-xs">{t("dashboard.classes.lookedNotSeen")}</p>
              )}
            </>
          )}
        </Module>

        <Module
          label={t("dashboard.activity.title")}
          // Bucket size is a property of the selected range, not of whether
          // any rows arrived — an empty 24h view is still an hourly view.
          title={
            seriesQuery.bucket === "hour" ? t("dashboard.activity.hourly") : t("dashboard.activity.daily")
          }
          loading={series.data === null && !series.failed}
        >
          {series.data === null && series.failed ? (
            <p className="text-sev-critical hs-label py-4">{t("dashboard.error.load")}</p>
          ) : !activity || activity.empty ? (
            <p className="hs-label py-8 text-center">{t("dashboard.activity.empty")}</p>
          ) : (
            <ChartFrame height={Math.max(240, classRows.length * 30 + 24)}>
              <AreaChart data={activity.points} margin={{ top: 8, right: 8, bottom: 4, left: 0 }}>
                <defs>
                  <linearGradient id="hs-activity" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--hs-azure)" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="var(--hs-azure)" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} stroke="var(--hairline)" />
                <XAxis
                  dataKey="label"
                  reversed={isRTL}
                  tickLine={false}
                  axisLine={{ stroke: "var(--hairline-strong)" }}
                  tick={{ fill: "var(--ink-faint)", ...AXIS }}
                  minTickGap={18}
                />
                <YAxis
                  orientation={isRTL ? "right" : "left"}
                  width={44}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                  tick={{ fill: "var(--ink-faint)", ...AXIS }}
                />
                <Tooltip
                  {...tip}
                  formatter={(value) => [f.number(Number(value)), t("dashboard.classes.axis")]}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="var(--hs-azure)"
                  strokeWidth={1.5}
                  fill="url(#hs-activity)"
                  isAnimationActive={false}
                  dot={false}
                />
              </AreaChart>
            </ChartFrame>
          )}
          {/* Stated whatever the chart shows: the window on screen is not the
              window the operator picked, and that has to be visible. */}
          {seriesQuery.clamped && (
            <p className="text-ink-faint mt-2 text-xs">{t("dashboard.activity.clamped")}</p>
          )}
        </Module>
      </ModuleGrid>

      {/* ---- 6. day × hour heatmap ---------------------------------------- */}
      <Module
        label={t("dashboard.heatmap")}
        title={rangeLabel}
        loading={heat.data === null && !heat.failed}
        actions={
          // Discrete swatches rather than a `linear-gradient`, whose direction
          // keyword is physical: a flex row mirrors itself under RTL for free.
          <div className="hidden items-center gap-1.5 sm:flex">
            <span className="hs-label">{t("dashboard.heatmap.legendLow")}</span>
            {[0, 0.25, 0.5, 0.75, 1].map((step) => (
              <span
                key={step}
                aria-hidden="true"
                className="border-hairline size-2.5 rounded-[1px] border"
                style={{ background: `color-mix(in oklab, var(--hs-azure) ${step * 88}%, transparent)` }}
              />
            ))}
            <span className="hs-label">{t("dashboard.heatmap.legendHigh")}</span>
          </div>
        }
      >
        {heat.data === null && heat.failed ? (
          <p className="text-sev-critical hs-label py-4">{t("dashboard.error.load")}</p>
        ) : heatRows.length === 0 ? (
          <p className="hs-label py-8 text-center">{t("dashboard.empty.heatmap")}</p>
        ) : (
          <div className="overflow-x-auto">
            <div className="grid min-w-[46rem] grid-cols-[4.5rem_repeat(24,minmax(0,1fr))] gap-[2px]">
              <span className="hs-label self-center">{t("dashboard.heatmapAxis")}</span>
              {Array.from({ length: 24 }, (_, hour) => (
                <span key={`h-${hour}`} className="hs-num text-ink-faint text-center text-[0.625rem]">
                  {String(hour).padStart(2, "0")}
                </span>
              ))}

              {heatRows.map((row) => (
                <React.Fragment key={row.day}>
                  <span className="text-ink-dim self-center truncate text-xs">
                    {DAY_KEYS[row.day] ? t(DAY_KEYS[row.day]) : row.day}
                  </span>
                  {row.hours.map((cell) => {
                    const n = cell.intensity ?? 0
                    const ratio = heatMax > 0 ? n / heatMax : 0
                    return (
                      <span
                        key={`${row.day}-${cell.hour}`}
                        className={cn(
                          "border-hairline h-4 rounded-[1px] border",
                          n > 0 && "border-transparent"
                        )}
                        title={t("dashboard.heatmap.cell", {
                          day: DAY_KEYS[row.day] ? t(DAY_KEYS[row.day]) : row.day,
                          hour: String(cell.hour).padStart(2, "0"),
                          n: f.number(n),
                        })}
                        style={{
                          background:
                            n > 0
                              ? `color-mix(in oklab, var(--hs-azure) ${Math.round(12 + ratio * 76)}%, transparent)`
                              : "var(--surface-sunken)",
                        }}
                      />
                    )
                  })}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}
      </Module>

      {/* ---- 7. top offenders · 8. channel occupancy ---------------------- */}
      <ModuleGrid className="lg:grid-cols-2">
        <Module label={t("dashboard.topSources")} title={rangeLabel} flush>
          <DataTable
            columns={offenderColumns}
            rows={offenderRows}
            rowKey={(row) => row.wlan_sa}
            state={
              offenders.data === null && offenders.failed
                ? "error"
                : offenders.data === null
                  ? "loading"
                  : "ready"
            }
            emptyLabel={t("dashboard.empty.sources")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
          />
        </Module>

        <Module label={t("dashboard.channelUsage")} title={rangeLabel} flush>
          <DataTable
            columns={channelColumns}
            rows={channelRows}
            rowKey={(row) => row.channel_freq}
            state={
              channels.data === null && channels.failed
                ? "error"
                : channels.data === null
                  ? "loading"
                  : "ready"
            }
            emptyLabel={t("dashboard.empty.channels")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
          />
        </Module>
      </ModuleGrid>

      <p className="text-ink-faint text-xs">{t("time.timezone")}</p>
    </div>
  )
}
