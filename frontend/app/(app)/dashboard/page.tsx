"use client"

/**
 * The ops console, cut for paper.
 *
 * Four rules shaped every decision in here. The first three are about the data
 * and are unchanged from the build this replaces — they were hard-won and they
 * are still correct. The fourth is what the rebuild is for.
 *
 * **Nothing is recomputed in the browser that the sensor can answer itself.**
 * V1 pulled `/attacks?limit=5000` on every refresh and derived the offender
 * table, the channel table and the activity series from it — a quarter of a
 * megabyte over the wire, on a Pi 4B, to recompute GROUP BYs the database had
 * already indexed for. Every one of those is a server-side aggregate now.
 *
 * **The range selector governs the whole page.** Every aggregate takes `days`,
 * so no module quietly answers for all time while the one beside it answers for
 * the last 24 hours.
 *
 * **A figure the sensor did not report is not a zero.** Every resource carries
 * its own `failed` flag, a failed refresh leaves the last good value on screen,
 * and a module that has never loaded says so rather than rendering an empty
 * instrument that looks like a quiet network. `/health.capture` reports `null`
 * for anything it could not measure, and `null` renders as *not reported*.
 *
 * **It is a document, not a console.** Nine instruments used to sit in one
 * undifferentiated stack of dark boxes. They are four passages now — capture,
 * classification, rhythm, sources — separated by labelled rules. The hero is a
 * `DataCard`: one printed slip saying what the sensor is and what it found,
 * because that is the four-second question and no bar chart answers it.
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
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { RefreshCw } from "lucide-react"

import { AccentWord } from "@/components/hs/accent-word"
import {
  DataCard,
  DataCardBar,
  DataCardNote,
  DataCardRow,
  DataCardRows,
  DataCardTotal,
} from "@/components/hs/data-card"
import { DataTable, type DataTableColumn } from "@/components/hs/data-table"
import { Hairline } from "@/components/hs/hairline"
import { Metric } from "@/components/hs/metric"
import { Panel, PanelGrid } from "@/components/hs/panel"
import { Radar } from "@/components/hs/radar"
import { SectionHead } from "@/components/hs/section-head"
import { Sparkline } from "@/components/hs/sparkline"
import { StatusPill } from "@/components/hs/status-pill"
import {
  ChartFrame,
  PaperTooltip,
  paperAxis,
  paperCursor,
  paperGrid,
} from "@/components/console/chart"
import {
  ControlSpacer,
  ControlStrip,
  EmptyNote,
  LoadError,
  Moment,
  PageFrame,
  Readout,
  ReadoutRow,
  Unreported,
} from "@/components/console/frame"
import { HeatGrid, HeatLegend, type HeatRow } from "@/components/console/heat-grid"
import { LiveTape, type TapeRow } from "@/components/console/live-tape"
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
import { attackColorVar, attackLabels, attackTypes, severityOf, type Severity } from "@/lib/colors"
import { apiTimeMs, freqToChannel, riyadhParts, toAttackType } from "@/lib/detections"
import { Mac, TIMEZONE, useFormatters } from "@/lib/format"
import { useLocale, useT, type TranslationKey, type Translate } from "@/lib/i18n"

/* ── Cadence ─────────────────────────────────────────────────────────────── */

/** Relaxed while healthy, brisk while trying to recover. */
const POLL_OK_MS = 20_000
const POLL_RETRY_MS = 8_000

/** Enough rows for the live tape without pulling the ledger. */
const TAPE_LIMIT = 60

/**
 * How many entries the tape prints. Past this it stops being a tape — and it is
 * also what makes the tape column stand roughly level with the slip and the
 * readout beside it, so the capture passage reads as one block of paper.
 */
const TAPE_ROWS = 14

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
 * it already knows will fail, and says on the chart that it did.
 */
const SERIES_MAX_DAYS: Record<SeriesBucket, number> = { hour: 31, day: 366 }

/** A day of detections is legible hour by hour; a month of them is not. */
const bucketFor = (days: number): SeriesBucket => (days <= 1 ? "hour" : "day")

/**
 * A RadioTap centre frequency as a bare integer.
 *
 * Deliberately NOT through the locale number formatter: `5180` is an identifier
 * on a frequency plan, and `5,180 MHz` reads as five thousand of something. The
 * grouping separator belongs on counts, not on radio channels.

 */
const freqLabel = (mhz: unknown): string | null => {
  const n = Number(mhz)
  return mhz == null || !Number.isFinite(n) ? null : String(Math.round(n))
}

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
 * A packet arriving within this window is what makes the radar pulse. A pulse
 * over a sensor that stopped capturing an hour ago is a lie told continuously —
 * see the note in `components/hs/radar.tsx`.
 */
const LIVE_WINDOW_MS = 10 * 60_000

/**
 * The three severity anchors, as chart colours.
 *
 * Taken from the class ramp rather than from `--sev-*`: the severity bar sits on
 * the same card as a class legend, and two different reds for one grade is the
 * fastest way to make a legend stop being read.
 */
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: attackColorVar("evil_twin"),
  high: attackColorVar("deauth"),
  info: attackColorVar("ssdp"),
}

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

  /** The series request the range maps to, clamped to what the bucket allows. */
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
        read<OffenderRow[]>(
          `/top-offenders?days=${range.days}&limit=${OFFENDER_LIMIT}`,
          setOffenders,
          alive
        ),
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
    return rows.sort(
      (a, b) => b.value - a.value || attackTypes.indexOf(a.type) - attackTypes.indexOf(b.type)
    )
  }, [totals])

  const classTotal = classRows.reduce((n, r) => n + r.value, 0)
  const totalDetections =
    typeof summary.data?.summary?.totalAttacks === "number"
      ? summary.data.summary.totalAttacks
      : null
  const uniqueSources =
    typeof summary.data?.summary?.uniqueSources === "number"
      ? summary.data.summary.uniqueSources
      : null

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

  /** The same series, as the shape beside the headline figure. */
  const spark = React.useMemo(
    () => (activity && activity.points.length > 1 ? activity.points.map((p) => p.count) : null),
    [activity]
  )

  /* ---- live tape --------------------------------------------------------- */

  // Ids the stream delivered while this page has been open. Only those rows get
  // the arrival wash; a polled backlog must not flash on every refresh.
  const arrived = React.useRef<Set<string>>(new Set())
  for (const e of streamEvents) arrived.current.add(String(e.id))

  const tapeRows = React.useMemo<TapeRow[]>(() => {
    const fromStream: TapeRow[] = streamEvents.map((e) => ({
      id: String(e.id ?? ""),
      ms: apiTimeMs(e.ts),
      type: toAttackType(e.predicted_label),
      mac: e.src_mac || e.bssid || null,
      conf: typeof e.p2 === "number" ? e.p2 : null,
      sim: Boolean(e.sim),
    }))

    const fromPoll: TapeRow[] = (tape.data ?? []).map((r) => ({
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
      .slice(0, TAPE_ROWS)
  }, [streamEvents, tape.data])

  /* ---- heatmap ----------------------------------------------------------- */

  // Memoised rather than derived inline: a fresh `[]` on every render would
  // re-run the reduce below on every poll tick for no new information.
  const heatRows = React.useMemo(() => heat.data ?? [], [heat.data])
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
        width: "3rem",
        cell: (_row, i) => <span className="text-ink-2 text-xs">{f.number(i + 1)}</span>,
      },
      {
        id: "mac",
        header: t("dashboard.column.sourceMac"),
        cell: (row) => <Mac value={row.wlan_sa} className="text-ink-0 text-xs" />,
      },
      {
        id: "count",
        header: t("dashboard.column.count"),
        numeric: true,
        width: "6rem",
        cell: (row) => <span className="text-ink-0 text-sm">{f.number(row.count)}</span>,
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
        width: "4.5rem",
        cell: (row) => {
          const ch = freqToChannel(row.channel_freq)
          return ch === null ? <Unreported /> : f.number(ch)
        },
      },
      {
        id: "freq",
        header: t("units.frequency"),
        numeric: true,
        width: "7.5rem",
        hideBelow: "sm",
        // The figure is isolated and the unit is not, so `5180 MHz` cannot
        // render as `MHz 5180` — see `components/quantity.tsx`.
        cell: (row) => {
          const mhz = freqLabel(row.channel_freq)
          return mhz === null ? <Unreported /> : <Quantity value={mhz} unit={t("units.mhz")} />
        },
      },
      {
        id: "count",
        header: t("dashboard.column.count"),
        numeric: true,
        width: "5.5rem",
        cell: (row) => f.number(row.count),
      },
      {
        id: "share",
        header: t("dashboard.channels.share"),
        hideBelow: "md",
        cell: (row) => {
          const share = channelTotal > 0 ? row.count / channelTotal : 0
          return (
            <span className="flex items-center gap-2">
              {/* `inline-size` on a flex track, so the bar grows from the
                  inline-start edge in both directions with no override. */}
              <span className="bg-paper-2 border-rule h-1.5 w-full min-w-14 overflow-hidden rounded-full border">
                <span
                  className="bg-accent block h-full"
                  style={{ inlineSize: `${Math.max(2, share * 100)}%` }}
                />
              </span>
              <span className="hs-num text-ink-2 w-11 shrink-0 text-end text-xs">
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
  const rangeLabel = t(range.key)
  const stateOf = <T,>(res: Res<T>) =>
    res.data === null && res.failed ? "error" : res.data === null ? "loading" : "ready"

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
        x={x + width + side * 8}
        y={y + height / 2}
        dy={4}
        textAnchor={side < 0 ? "end" : "start"}
        style={{ fill: "var(--color-ink-1)", fontSize: 11, fontFamily: "var(--font-mono)" }}
      >
        {f.number(Number(value))}
      </text>
    )
  }

  return (
    <PageFrame>
      {/* ---- the page head ------------------------------------------------ */}
      <SectionHead
        as="h1"
        eyebrow={t("dashboard.title")}
        title={
          <>
            {t("dashboard.head.lead")}
            <AccentWord>{t("dashboard.head.accent")}</AccentWord>
          </>
        }
        body={t("dashboard.subtitle")}
      />

      {/* ---- the control strip -------------------------------------------- */}
      <ControlStrip>
        <Radar
          size={12}
          active={sensorLive}
          label={sensorLive ? t("dashboard.sensor.live") : t("dashboard.sensor.idle")}
        />
        <StatusPill tone={tone}>{t(STATE_KEY[connState])}</StatusPill>

        {updatedAt !== null && (
          <span className="text-ink-2 hidden text-xs md:inline">
            {t("common.updatedAgo", { ago: "" }).trim()}{" "}
            <Moment value={updatedAt} format="relative" className="text-ink-2 text-xs" />
          </span>
        )}

        <ControlSpacer />

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

      {/* ══ Capture ═══════════════════════════════════════════════════════ */}
      <Hairline label={t("dashboard.section.capture")} />

      {/* The tape runs the full height of the passage; the slip and the readout
          stack beside it. `row-span-2` only from `lg`, so the phone gets three
          panels in reading order with no spanning at all. */}
      <PanelGrid className="lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <Panel
          className="lg:row-span-2"
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
          <LiveTape
            rows={tapeRows}
            state={stateOf(tape)}
            label={t("dashboard.tape.aria")}
            emptyLabel={t("dashboard.empty.feed")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
            isArriving={(row) => arrived.current.has(row.id)}
            formatPercent={(v) => f.percent(v, 0)}
          />
        </Panel>

        {/* The hero object: one printed slip, every figure off the sensor. */}
        <DataCard
          label={capture?.iface ?? t("common.unknown")}
          title={rangeLabel}
          status={
            <StatusPill tone={sensorLive ? "info" : "neutral"} live={sensorLive}>
              {sensorLive ? t("dashboard.sensor.live") : t("dashboard.sensor.idle")}
            </StatusPill>
          }
          className="h-fit"
        >
          <DataCardRows>
            <DataCardRow
              label={t("dashboard.sensor.packets")}
              value={typeof health?.packets === "number" ? f.number(health.packets) : <Unreported />}
            />
            <DataCardRow
              label={t("dashboard.sensor.lastSeen")}
              value={
                lastPacketMs === null ? (
                  <Unreported />
                ) : (
                  <Moment value={lastPacketMs} format="relative" className="text-sm" />
                )
              }
            />
            <DataCardRow
              label={t("severity.critical")}
              value={totals ? f.number(bySeverity.critical) : "—"}
              tone="critical"
            />
            <DataCardRow
              label={t("severity.high")}
              value={totals ? f.number(bySeverity.high) : "—"}
              tone="companion"
            />
            <DataCardRow
              label={t("severity.info")}
              value={totals ? f.number(bySeverity.info) : "—"}
            />
          </DataCardRows>

          <DataCardTotal
            label={t("dashboard.ledger.total")}
            value={totalDetections === null ? "—" : f.number(totalDetections)}
            unit={t("units.events")}
          />

          <DataCardBar
            label={t("dashboard.card.split")}
            segments={[
              {
                label: t("severity.critical"),
                value: bySeverity.critical,
                color: SEVERITY_COLOR.critical,
              },
              { label: t("severity.high"), value: bySeverity.high, color: SEVERITY_COLOR.high },
              { label: t("severity.info"), value: bySeverity.info, color: SEVERITY_COLOR.info },
            ]}
          />

          <DataCardNote>{t("dashboard.card.note")}</DataCardNote>
        </DataCard>

        <Panel
          label={t("dashboard.sensor.title")}
          title={capture?.iface ?? undefined}
          actions={
            <StatusPill tone={tone} dot>
              {t(STATE_KEY[connState])}
            </StatusPill>
          }
        >
          {/* One printed list. It sat in two columns while it was a full-width
              module; in the narrower track beside the tape a second column would
              leave every label fighting its own value for space. */}
          <Readout>
            <ReadoutRow label={t("dashboard.sensor.interface")}>
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
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.channel")}>
              {configuredChannel === null ? (
                <Unreported />
              ) : (
                <span className="hs-num">{f.number(configuredChannel)}</span>
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.monitorMode")}>
              {/* Three states, not two: `true`, a measured `false` that means the
                  radio is not capturing, and `null` — nothing was measured. */}
              {capture?.monitor_mode === true ? (
                <StatusPill tone="info">{t("common.yes")}</StatusPill>
              ) : capture?.monitor_mode === false ? (
                <StatusPill tone="high">{t("common.no")}</StatusPill>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.linkState")}>
              {/* `up` / `down` / `dormant` are kernel identifiers: Latin in both
                  locales, and isolated so they never join the Arabic run. */}
              {capture?.operstate ? (
                <span className="hs-ltr font-mono">{capture.operstate}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.observedIface")}>
              {capture?.observed_iface ? (
                <span className="hs-ltr font-mono">{capture.observed_iface}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.observedChannel")}>
              {observedChannel === null ? (
                <Unreported />
              ) : (
                <span className="inline-flex flex-wrap items-baseline justify-end gap-2">
                  <span className="hs-num">{f.number(observedChannel)}</span>
                  <span className="text-ink-2 text-xs">
                    <Quantity
                      value={freqLabel(capture?.observed_channel_freq) ?? "—"}
                      unit={t("units.mhz")}
                    />
                  </span>
                </span>
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.model")}>
              {health?.model_version && health.model_version !== "none" ? (
                <span className="hs-ltr font-mono">{health.model_version}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.spec")}>
              {health?.spec_version ? (
                <span className="hs-num">{health.spec_version}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.packets")}>
              {typeof health?.packets === "number" ? (
                <span className="hs-num">{f.number(health.packets)}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("dashboard.sensor.lastSeen")}>
              {lastPacketMs === null ? (
                <Unreported />
              ) : (
                <Moment value={lastPacketMs} format="relative" className="text-sm" />
              )}
            </ReadoutRow>
          </Readout>

          {capture && (
            <p className="text-ink-2 mt-4 text-xs">
              {captureMeasured ? t("dashboard.sensor.measured") : t("dashboard.sensor.configOnly")}
            </p>
          )}
        </Panel>
      </PanelGrid>

      {/* ══ Classification ════════════════════════════════════════════════ */}
      <Hairline label={t("dashboard.section.classification")} />

      <PanelGrid className="sm:grid-cols-2 lg:grid-cols-4">
        <Panel>
          <Metric
            label={t("dashboard.ledger.total")}
            value={totalDetections ?? 0}
            format={totalDetections === null ? () => "—" : f.number}
            footer={
              spark ? (
                <Sparkline values={spark} area label={t("dashboard.activity.title")} />
              ) : undefined
            }
          />
        </Panel>
        <Panel>
          <Metric
            label={t("severity.critical")}
            value={bySeverity.critical}
            format={totals ? f.number : () => "—"}
            tone="critical"
          />
        </Panel>
        <Panel>
          <Metric
            label={t("severity.high")}
            value={bySeverity.high}
            format={totals ? f.number : () => "—"}
            tone="high"
          />
        </Panel>
        <Panel>
          <Metric
            label={t("dashboard.ledger.uniqueSources")}
            value={uniqueSources ?? 0}
            format={uniqueSources === null ? () => "—" : f.number}
          />
        </Panel>
      </PanelGrid>

      <PanelGrid className="lg:grid-cols-2">
        <Panel
          label={t("dashboard.classes.title")}
          title={rangeLabel}
          loading={summary.data === null && !summary.failed}
        >
          {summary.data === null && summary.failed ? (
            <LoadError>{t("dashboard.error.load")}</LoadError>
          ) : classRows.length === 0 ? (
            <EmptyNote>{t("dashboard.empty.summary")}</EmptyNote>
          ) : (
            <>
              <ChartFrame height={Math.max(240, classRows.length * 32 + 16)}>
                <BarChart
                  data={classRows}
                  layout="vertical"
                  // The value labels sit past each bar's tip, so the gutter they
                  // need is on the inline-END side — which is the left margin
                  // once the value axis has been reversed for Arabic.
                  margin={{ top: 4, right: isRTL ? 4 : 48, bottom: 4, left: isRTL ? 48 : 4 }}
                  barCategoryGap="26%"
                >
                  {/* No grid and no value axis. Every bar carries its own figure,
                      so a ruler underneath would be a second way of reading the
                      same number — the definition of chartjunk. The axis still
                      exists to own the scale; it just does not draw itself. */}
                  <XAxis
                    type="number"
                    hide
                    reversed={isRTL}
                    allowDecimals={false}
                    domain={[0, (max: number) => Math.max(1, Math.ceil(max * 1.2))]}
                  />
                  {/* Under RTL the value axis runs right-to-left and the category
                      axis moves to the right edge, so the bars grow away from the
                      labels in the reader's own direction. */}
                  <YAxis
                    type="category"
                    dataKey="label"
                    orientation={isRTL ? "right" : "left"}
                    // Wide enough for `Disassociation`, the longest class name,
                    // in the mono face at 11px. At 78 it clipped under RTL.
                    width={98}
                    {...paperAxis}
                  />
                  <Tooltip
                    cursor={paperCursor}
                    content={(raw) => {
                      const p = raw as unknown as {
                        active?: boolean
                        label?: unknown
                        payload?: ReadonlyArray<{ value?: unknown; payload?: unknown }>
                      }
                      const entry = p.payload?.[0]
                      if (!p.active || !entry) return null
                      const row = entry.payload as (typeof classRows)[number] | undefined
                      return (
                        <PaperTooltip
                          dir={dir}
                          caption={String(p.label ?? "")}
                          unit={t("dashboard.classes.axis")}
                          value={f.number(Number(entry.value))}
                          swatch={row?.color}
                        />
                      )
                    }}
                  />
                  <Bar dataKey="value" radius={2} isAnimationActive={false}>
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
                <p className="text-ink-2 mt-3 text-xs">{t("dashboard.classes.lookedNotSeen")}</p>
              )}
            </>
          )}
        </Panel>

        <Panel
          label={t("dashboard.activity.title")}
          // Bucket size is a property of the selected range, not of whether any
          // rows arrived — an empty 24h view is still an hourly view.
          title={
            seriesQuery.bucket === "hour"
              ? t("dashboard.activity.hourly")
              : t("dashboard.activity.daily")
          }
          loading={series.data === null && !series.failed}
        >
          {series.data === null && series.failed ? (
            <LoadError>{t("dashboard.error.load")}</LoadError>
          ) : !activity || activity.empty ? (
            <EmptyNote>{t("dashboard.activity.empty")}</EmptyNote>
          ) : (
            <ChartFrame height={Math.max(240, classRows.length * 32 + 16)}>
              <AreaChart data={activity.points} margin={{ top: 8, right: 18, bottom: 4, left: 0 }}>
                {/* One set of gridlines, across the value axis only, at the 8%
                    hairline. The vertical set said nothing the tick labels had
                    not already said. */}
                <CartesianGrid vertical={false} {...paperGrid} />
                <XAxis dataKey="label" reversed={isRTL} minTickGap={20} {...paperAxis} />
                <YAxis
                  orientation={isRTL ? "right" : "left"}
                  width={40}
                  allowDecimals={false}
                  {...paperAxis}
                />
                <Tooltip
                  cursor={{ stroke: "var(--color-rule-soft)", strokeWidth: 1 }}
                  content={(raw) => {
                    const p = raw as unknown as {
                      active?: boolean
                      label?: unknown
                      payload?: ReadonlyArray<{ value?: unknown }>
                    }
                    const entry = p.payload?.[0]
                    if (!p.active || !entry) return null
                    return (
                      <PaperTooltip
                        dir={dir}
                        caption={String(p.label ?? "")}
                        unit={t("dashboard.classes.axis")}
                        value={f.number(Number(entry.value))}
                      />
                    )
                  }}
                />
                {/* A flat tint, not a gradient. A vertical gradient under an area
                    is decoration that reads as depth the data does not have, and
                    it is the most recognisable stock-chart tell there is. */}
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="var(--color-accent)"
                  strokeWidth={1.5}
                  fill="var(--color-accent)"
                  fillOpacity={0.1}
                  isAnimationActive={false}
                  dot={false}
                  activeDot={{ r: 3, fill: "var(--color-accent)", stroke: "none" }}
                />
              </AreaChart>
            </ChartFrame>
          )}
          {/* Stated whatever the chart shows: the window on screen is not the
              window the operator picked, and that has to be visible. */}
          {seriesQuery.clamped && (
            <p className="text-ink-2 mt-3 text-xs">{t("dashboard.activity.clamped")}</p>
          )}
        </Panel>
      </PanelGrid>

      {/* ══ Rhythm ════════════════════════════════════════════════════════ */}
      <Hairline label={t("dashboard.section.rhythm")} />

      <Panel
        label={t("dashboard.heatmap")}
        title={rangeLabel}
        loading={heat.data === null && !heat.failed}
        actions={
          <HeatLegend
            low={t("dashboard.heatmap.legendLow")}
            high={t("dashboard.heatmap.legendHigh")}
          />
        }
        flush
      >
        {heat.data === null && heat.failed ? (
          <LoadError>{t("dashboard.error.load")}</LoadError>
        ) : heatRows.length === 0 ? (
          <EmptyNote>{t("dashboard.empty.heatmap")}</EmptyNote>
        ) : (
          <HeatGrid
            rows={heatRows}
            max={heatMax}
            axisLabel={t("dashboard.heatmapAxis")}
            scrollHint={t("dashboard.heatmap.scrollHint")}
            dayLabel={(day) => (DAY_KEYS[day] ? t(DAY_KEYS[day]) : day)}
            cellLabel={(day, hour, n) =>
              t("dashboard.heatmap.cell", {
                day: DAY_KEYS[day] ? t(DAY_KEYS[day]) : day,
                hour: String(hour).padStart(2, "0"),
                n: f.number(n),
              })
            }
          />
        )}
      </Panel>

      {/* ══ Sources and spectrum ══════════════════════════════════════════ */}
      <Hairline label={t("dashboard.section.sources")} />

      <PanelGrid className="lg:grid-cols-2">
        <Panel
          label={t("dashboard.topSources")}
          title={rangeLabel}
          flush
        >
          <DataTable
            columns={offenderColumns}
            rows={offenderRows}
            rowKey={(row) => row.wlan_sa}
            state={stateOf(offenders)}
            emptyLabel={t("dashboard.empty.sources")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
          />
        </Panel>

        <Panel
          label={t("dashboard.channelUsage")}
          title={rangeLabel}
          flush
        >
          <DataTable
            columns={channelColumns}
            rows={channelRows}
            rowKey={(row) => row.channel_freq}
            state={stateOf(channels)}
            emptyLabel={t("dashboard.empty.channels")}
            loadingLabel={t("state.loadingData")}
            errorLabel={t("dashboard.error.load")}
          />
        </Panel>
      </PanelGrid>

      <p className="hs-label">{t("time.timezone")}</p>
    </PageFrame>
  )
}
