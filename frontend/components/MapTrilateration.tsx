"use client"

import { useEffect, useMemo, useState } from "react"
import dynamic from "next/dynamic"
import { apiFetchSafe, apiPostJson } from "@/lib/api"

// Load the map without SSR (Leaflet needs `window`).
const LeafletMap = dynamic(() => import("./LeafletMap"), {
  ssr: false,
  loading: () => (
    <div className="h-[480px] rounded-lg bg-gradient-to-br from-gray-800 to-gray-900 flex items-center justify-center border border-white/10">
      <div className="text-cyan-400">Loading interactive map...</div>
    </div>
  ),
})

type AP = { bssid: string; name?: string; lat: number; lng: number }
type RSSIPoint = { bssid: string; avg_rssi: number; n: number }
type SourceRSSIResponse = { sa: string; points: RSSIPoint[] }
type EstimateResponse =
  | { sa: string; method: string; used: number; center: { lat: number; lng: number } | null; note?: string }
  | { detail: string }

export default function MapTrilateration() {
  // Attack source MAC (SA) to trilaterate.
  const [sa, setSa] = useState("AA:BB:CC:DD:EE:FF")

  const [apData, setApData] = useState<AP[]>([])
  const [rssiData, setRssiData] = useState<SourceRSSIResponse | null>(null)
  const [estimate, setEstimate] = useState<EstimateResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let alive = true
    ;(async () => {
      setLoading(true)
      setError(null)

      // 1) APs
      const apRaw = await apiFetchSafe<any[]>("/map/ap-locations", [])
      const aps: AP[] = (Array.isArray(apRaw) ? apRaw : [])
        .map((a) => ({
          bssid: String(a.bssid || "").toUpperCase(),
          name: String(a.name || ""),
          lat: Number(a.lat),
          lng: Number(a.lng),
        }))
        .filter(
          (a) => Number.isFinite(a.lat) && Number.isFinite(a.lng) && !!a.bssid
        )

      if (!alive) return
      setApData(aps)

      // 2) RSSI readings for the same SA
      const rssi = await apiFetchSafe<SourceRSSIResponse>(
        `/map/source-rssi?sa=${encodeURIComponent(sa)}&minutes=1440`,
        { sa, points: [] }
      )
      if (!alive) return
      rssi.points = (rssi.points || []).map((p) => ({
        ...p,
        bssid: String(p.bssid || "").toUpperCase(),
      }))
      setRssiData(rssi)

      // 3) Estimated origin
      const estimateRes: EstimateResponse = await apiPostJson<EstimateResponse>(
        "/map/estimate-origin",
        { sa, minutes: 1440, ap_locations: aps }
      ).catch((e: unknown) => ({ detail: String((e as Error)?.message ?? e) }))

      if (!alive) return
      setEstimate(estimateRes)
      setLoading(false)
    })()
    return () => {
      alive = false
    }
  }, [sa])

  // Map centre taken from the estimate response.
  const center = useMemo(() => {
    const c = (estimate as any)?.center
    if (c && Number.isFinite(Number(c.lat)) && Number.isFinite(Number(c.lng))) {
      return { lat: Number(c.lat), lng: Number(c.lng) }
    }
    return null
  }, [estimate])

  // Rough confidence based on how many APs contributed.
  const confidence = useMemo(() => {
    const used = (estimate as any)?.used ?? 0
    if (!used) return 0
    return Math.min(1, used / 5) // 1..5 APs
  }, [estimate])

  const note =
    (estimate as any)?.note ||
    ((estimate as any)?.used === 0
      ? "No matching RSSI/AP pairs in the selected window."
      : null)

  return (
    <div className="space-y-3">
      {/* Toolbar: pick the source MAC (SA) */}
      <div className="flex items-center gap-2 text-sm">
        <div className="text-gray-300">Tracking:</div>
        <input
          className="px-2 py-1 rounded bg-transparent border border-white/10 text-cyan-300 font-mono w-[220px]"
          value={sa}
          onChange={(e) => setSa(e.target.value.trim())}
        />
        <div className="ml-auto text-yellow-400">
          Confidence: {Math.round(confidence * 100)}%
        </div>
      </div>

      {error && <div className="text-red-400">{error}</div>}

      {/* Map */}
      {apData.length === 0 ? (
        <div className="text-center text-red-400 py-10">
          No access points (APs) available. Check <code>/map/ap-locations</code>.
        </div>
      ) : (
        <LeafletMap
          center={center ?? undefined}
          aps={apData}
          points={rssiData?.points || []}
          height={480}
          zoom={17}
          confidence={confidence}
        />
      )}

      {/* Status / note */}
      {loading ? (
        <div className="text-gray-400 text-sm">Loading data…</div>
      ) : note ? (
        <div className="text-gray-400 text-sm">{note}</div>
      ) : null}
    </div>
  )
}
