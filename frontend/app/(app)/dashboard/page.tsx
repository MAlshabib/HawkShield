"use client"

import { useEffect, useMemo, useState } from "react"
import dynamic from "next/dynamic"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { apiFetchSafe } from "@/lib/api"

// Declared locally to avoid a cross-module type import.
type TimeRange = "day" | "week" | "month"

// Import the map dynamically to avoid SSR issues (Leaflet needs `window`).
const MapTrilateration = dynamic(() => import("@/components/MapTrilateration"), { ssr: false })

const toDate = (ts: any): Date => {
  if (ts == null) return new Date(NaN)
  if (typeof ts === "number") return new Date(ts < 10_000_000_000 ? ts * 1000 : ts)
  const asNum = Number(ts)
  if (!Number.isNaN(asNum)) return new Date(asNum < 10_000_000_000 ? asNum * 1000 : asNum)
  let s = String(ts).trim().replace(/\//g, "-")
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) s = s.replace(" ", "T")
  const d = new Date(s)
  return isNaN(d.getTime()) ? new Date(NaN) : d
}

const withinRange = (d: Date, range: TimeRange) => {
  if (!(d instanceof Date) || isNaN(d.getTime())) return true
  const now = Date.now()
  const windowMs = range === "day" ? 86_400_000 : range === "week" ? 604_800_000 : 2_592_000_000
  return d.getTime() >= now - windowMs
}

const isNormalLike = (row: any): boolean => {
  const t = String(row?.attack_type ?? row?.type ?? "").trim().toLowerCase()
  return t === "normal" || t === "benign" || t === "none" || row?.label === 0
}

const freqToChannel = (freq: any): number => {
  const f = Number(freq)
  if (!Number.isFinite(f)) return 0
  if (f >= 2412 && f <= 2484) return f === 2484 ? 14 : Math.round((f - 2412) / 5) + 1
  if (f >= 5000 && f <= 5900) return Math.round((f - 5000) / 5)
  if (f > 0 && f <= 200) return f
  return 0
}

type AnalysisMap = Record<string, number>
type OffenderRow = { wlan_sa: string; count: number }
type ChannelRow = { channel_freq: number; channel: number; count: number }
type HeatHour = { hour: number; intensity: number }
type HeatRow = { day: string; hours: HeatHour[] }

type AttackRaw = {
  id: string | number
  timestamp: number | string
  attack_type?: string
  type?: string
  wlan_sa?: string
  wlan_da?: string
  radiotap_channel_freq?: number | string
  rssi?: number | string
  severity?: "Low" | "Medium" | "High"
  label?: number
  proba_attack?: number
}

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("day")

  const [analysis, setAnalysis] = useState<AnalysisMap>({})
  const [offenders, setOffenders] = useState<OffenderRow[]>([])
  const [channels, setChannels] = useState<ChannelRow[]>([])
  const [heatmap, setHeatmap] = useState<HeatRow[]>([])
  const [attacks, setAttacks] = useState<(AttackRaw & { __date: Date })[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    ;(async () => {
      setLoading(true)

      const attacksData = await apiFetchSafe<any>("/attacks?limit=5000&offset=0", [])
      const analysisData = await apiFetchSafe<AnalysisMap>("/attacks/analysis", {})
      const heatmapData = await apiFetchSafe<HeatRow[]>("/heatmap-attack", [])

      if (!mounted) return

      const arr: AttackRaw[] = Array.isArray(attacksData)
        ? attacksData
        : (attacksData?.attacks ?? attacksData?.data ?? [])
      const mapped = arr
        .filter((row) => !isNormalLike(row))
        .map((a) => ({ ...a, __date: toDate(a.timestamp) }))
        .filter((a) => withinRange(a.__date, timeRange))

      setAttacks(mapped)

      const offenderCounts = new Map<string, number>()
      for (const a of mapped) {
        const mac = String(a.wlan_sa ?? "").toUpperCase()
        if (!mac) continue
        offenderCounts.set(mac, (offenderCounts.get(mac) ?? 0) + 1)
      }
      const offendersLocal: OffenderRow[] = Array.from(offenderCounts.entries())
        .map(([wlan_sa, count]) => ({ wlan_sa, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 20)
      setOffenders(offendersLocal)

      const channelCounts = new Map<number, number>()
      for (const a of mapped) {
        const f = Number(a.radiotap_channel_freq)
        if (!Number.isFinite(f)) continue
        channelCounts.set(f, (channelCounts.get(f) ?? 0) + 1)
      }
      const channelsLocal: ChannelRow[] = Array.from(channelCounts.entries())
        .map(([freq, count]) => ({ channel_freq: freq, channel: freqToChannel(freq), count }))
        .sort((a, b) => b.count - a.count)
      setChannels(channelsLocal)

      const filteredAnalysis = Object.fromEntries(
        Object.entries(analysisData ?? {}).filter(([k]) => !/^(normal|benign|none)$/i.test(String(k)))
      )
      setAnalysis(filteredAnalysis)

      setHeatmap(Array.isArray(heatmapData) ? heatmapData : [])

      setLoading(false)
    })()
    return () => {
      mounted = false
    }
  }, [timeRange])

  const timeline = useMemo(() => {
    const byKey = new Map<string, number>()
    for (const a of attacks) {
      const d = a.__date
      if (!(d instanceof Date) || isNaN(d.getTime())) continue
      const key = timeRange === "day" ? d.toISOString().slice(0, 13) + ":00" : d.toISOString().slice(0, 10)
      byKey.set(key, (byKey.get(key) ?? 0) + 1)
    }
    return Array.from(byKey.entries()).sort((x, y) => x[0].localeCompare(y[0]))
  }, [attacks, timeRange])

  const peakHours = useMemo(() => {
    const h = Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0 }))
    for (const a of attacks) {
      const d = a.__date
      if (!(d instanceof Date) || isNaN(d.getTime())) continue
      h[d.getHours()].count++
    }
    return h
  }, [attacks])

  const liveFeed = useMemo(() => {
    return [...attacks]
      .sort((A, B) => (B.__date?.getTime?.() ?? -1) - (A.__date?.getTime?.() ?? -1))
      .slice(0, 20)
  }, [attacks])

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400 mt-1">Real-time WiFi intrusion monitoring and analytics</p>
        </div>
        <Select value={timeRange} onValueChange={(v: TimeRange) => setTimeRange(v)}>
          <SelectTrigger className="w-32 glassmorphism border-cyan-500/30">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="glassmorphism border-cyan-500/30">
            <SelectItem value="day">Day</SelectItem>
            <SelectItem value="week">Week</SelectItem>
            <SelectItem value="month">Month</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <div className="text-center text-gray-400">Loading dashboard…</div>
      ) : (
        <>
          {/* Attack Summary */}
          <section>
            <h2 className="text-xl font-semibold text-white mb-4">Attack Summary</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(analysis)
                .sort((a, b) => b[1] - a[1])
                .map(([name, count]) => (
                  <div key={name} className="rounded-2xl bg-[#0F1629] border border-white/5 p-5">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-400">{name}</span>
                      <span className="text-xs text-gray-500">
                        {timeRange === "day" ? "24h" : timeRange === "week" ? "7d" : "30d"}
                      </span>
                    </div>
                    <div className="mt-2 text-4xl font-bold text-white">{count}</div>
                  </div>
                ))}
              {Object.keys(analysis).length === 0 && <div className="text-gray-400">No analysis data.</div>}
            </div>
          </section>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="rounded-2xl bg-[#0F1629] border border-white/5 p-4">
              <h3 className="text-white font-semibold mb-3">Timeline</h3>
              <div className="max-h-80 overflow-auto space-y-2">
                {timeline.length === 0 ? (
                  <div className="text-gray-400">No events.</div>
                ) : (
                  timeline.map(([label, count]) => (
                    <div key={label} className="flex items-center justify-between text-white/90">
                      <span className="text-sm">{label}</span>
                      <span className="font-semibold">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="rounded-2xl bg-[#0F1629] border border-white/5 p-4">
              <h3 className="text-white font-semibold mb-3">Peak Hours</h3>
              <div className="grid grid-cols-6 gap-2 text-white/90">
                {peakHours.map((row) => (
                  <div key={row.hour} className="rounded-xl border border-white/5 p-3 text-center">
                    <div className="text-xs text-gray-400">Hour {row.hour}</div>
                    <div className="text-xl font-bold">{row.count}</div>
                  </div>
                ))}
              </div>
            </section>
          </div>

          {/* Heatmap + Local stats */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <section className="lg:col-span-2 rounded-2xl bg-[#0F1629] border border-white/5 p-4 overflow-x-auto">
              <h3 className="text-white font-semibold mb-3">Attack Heatmap (by day/hour)</h3>
              <div className="min-w-[720px]">
                {/* header */}
                <div className="grid grid-cols-[80px_repeat(24,minmax(20px,1fr))] gap-1 mb-2">
                  <div className="text-xs text-gray-500 px-1">Day\Hr</div>
                  {Array.from({ length: 24 }).map((_, h) => (
                    <div key={"h" + h} className="text-xs text-gray-500 text-center">
                      {h}
                    </div>
                  ))}
                </div>
                {/* rows */}
                <div className="space-y-1">
                  {heatmap.length === 0 ? (
                    <div className="text-gray-400">No heatmap data.</div>
                  ) : (
                    heatmap.map((row) => (
                      <div
                        key={row.day}
                        className="grid grid-cols-[80px_repeat(24,minmax(20px,1fr))] gap-1 items-center"
                      >
                        <div className="text-sm text-gray-300 px-1">{row.day}</div>
                        {row.hours.map((cell) => (
                          <div
                            key={row.day + "-" + cell.hour}
                            className="h-4 rounded"
                            title={`${row.day} ${cell.hour}:00 → ${cell.intensity}`}
                            style={{
                              background: `rgba(56,189,248,${Math.min(1, (cell.intensity ?? 0) / 10)})`,
                            }}
                          />
                        ))}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </section>

            {/* Top Offenders */}
            <section className="rounded-2xl bg-[#0F1629] border border-white/5 overflow-hidden">
              <div className="p-4 flex items-center justify-between">
                <h3 className="text-white font-semibold">Top Offenders (wlan_sa)</h3>
                <span className="text-xs text-cyan-400">local</span>
              </div>
              <table className="w-full text-left">
                <thead className="text-gray-400 text-sm border-y border-white/5">
                  <tr>
                    <th className="px-4 py-3">#</th>
                    <th className="px-4 py-3">Source MAC</th>
                    <th className="px-4 py-3">Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {offenders.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-6 text-gray-400">
                        No offenders.
                      </td>
                    </tr>
                  ) : (
                    offenders.map((row, i) => (
                      <tr key={row.wlan_sa + i} className="text-white/90">
                        <td className="px-4 py-3">{i + 1}</td>
                        <td className="px-4 py-3 font-mono">{row.wlan_sa || "-"}</td>
                        <td className="px-4 py-3">{row.count}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </section>
          </div>

          {/* Channel Usage */}
          <section className="rounded-2xl bg-[#0F1629] border border-white/5 overflow-hidden">
            <div className="p-4 flex items-center justify-between">
              <h3 className="text-white font-semibold">Channel Usage</h3>
              <span className="text-xs text-cyan-400">local</span>
            </div>
            <table className="w-full text-left">
              <thead className="text-gray-400 text-sm border-y border-white/5">
                <tr>
                  <th className="px-4 py-3">Channel</th>
                  <th className="px-4 py-3">Freq (MHz)</th>
                  <th className="px-4 py-3">Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {channels.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-gray-400">
                      No channel data.
                    </td>
                  </tr>
                ) : (
                  channels.map((row, i) => (
                    <tr key={row.channel_freq + "-" + i} className="text-white/90">
                      <td className="px-4 py-3">{row.channel || "-"}</td>
                      <td className="px-4 py-3">{row.channel_freq}</td>
                      <td className="px-4 py-3">{row.count}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </section>

          {/* Live Feed */}
          <section className="rounded-2xl bg-[#0F1629] border border-white/5 p-4">
            <h3 className="text-white font-semibold mb-3">Live Feed (latest)</h3>
            <div className="space-y-2 max-h-80 overflow-auto">
              {liveFeed.length === 0 ? (
                <div className="text-gray-400">No recent events.</div>
              ) : (
                liveFeed.map((a, i) => (
                  <div key={String(a.id) + i} className="flex items-center justify-between text-white/90 text-sm">
                    <span className="font-mono">{a.wlan_sa ?? "-"}</span>
                    <span className="text-gray-400">
                      {a.__date instanceof Date && !isNaN(a.__date.getTime()) ? a.__date.toLocaleString() : "-"}
                    </span>
                  </div>
                ))
              )}
            </div>
          </section>
        </>
      )}

      {/* Map / Trilateration */}
      <div className="grid grid-cols-1 gap-6">
        <MapTrilateration />
      </div>
    </div>
  )
}
