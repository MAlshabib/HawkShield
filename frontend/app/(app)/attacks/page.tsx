"use client"

import { useEffect, useMemo, useState } from "react"
import { AttacksTable } from "@/components/attacks/attacks-table"
import { AttacksFiltersComponent } from "@/components/attacks/attacks-filters"
import { AttackDetailDrawer } from "@/components/attacks/attack-detail-drawer"
import { ReportModal } from "@/components/attacks/report-modal"
import { attackColors, type AttackType } from "@/lib/colors"
import { apiFetchJson } from "@/lib/api"

/* ================== Config ================== */
const PAGE_SIZE = 20
const AUTO_REFRESH_MS = 15_000

/* ================== Types ================== */
export interface AttackEvent {
  id: string
  timestamp: Date
  type: AttackType
  sourceMac: string
  destMac: string
  severity: "Low" | "Medium" | "High"
  channel: number
  rssi: number
  /** Optional enrichment; the /attacks endpoint does not currently provide it. */
  details?: {
    vendor?: string
    protocol?: string
    duration?: number
    packets?: number
  }
}

export interface AttacksFilters {
  search: string
  timeRange: "all" | "1h" | "6h" | "24h" | "7d" | "30d"
  types: AttackType[]
  severities: AttackEvent["severity"][]
}

/* ================== Utils ================== */
// Timestamp parsing: accepts seconds / milliseconds / ISO / "YYYY-MM-DD HH:mm:ss[.fff]" and "/" separators.
const toDate = (ts: any): Date => {
  if (ts == null) return new Date(NaN)
  if (typeof ts === "number") return new Date(ts < 10_000_000_000 ? ts * 1000 : ts)
  const asNum = Number(ts)
  if (!Number.isNaN(asNum)) return new Date(asNum < 10_000_000_000 ? asNum * 1000 : asNum)
  let s = String(ts).trim().replace(/\//g, "-")
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?/.test(s)) s = s.replace(" ", "T")
  const d = new Date(s)
  return isNaN(d.getTime()) ? new Date(NaN) : d
}

const normKey = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim()
const allowedTypes = Object.keys(attackColors) as AttackType[]
const normalizedAllowed = new Map(allowedTypes.map(k => [normKey(k), k]))

// Normalise the backend attack label so it matches an attackColors key.
const normalizeAttackType = (raw: any): AttackType => {
  const r = String(raw ?? "").trim()
  if (!r) return allowedTypes[0]
  const n = normKey(r)

  const direct = normalizedAllowed.get(n)
  if (direct) return direct as AttackType

  // NOTE: deliberately no alias for "normal" here, so benign traffic is never mapped onto a real attack type.
  const alias: Record<string, string> = {
    "evil twin": "Evil Twin",
    eviltwin: "Evil Twin",
    evil_twin: "Evil Twin",
    "rogue ap": "Rogue AP",
    rogueap: "Rogue AP",
    "re assoc": "(Re)Assoc",
    reassoc: "(Re)Assoc",
    "re-assoc": "(Re)Assoc",
    "re/assoc": "(Re)Assoc",
    deauth: "Deauth",
    ssdp: "SSDP",
    krack: "Krack",
  }

  const cleaned = r.toLowerCase().replace(/[^a-z0-9]+/g, "")
  const candidate = alias[n] || alias[n.replace(/\s+/g, "")] || alias[cleaned]
  if (candidate) {
    const found = normalizedAllowed.get(normKey(candidate))
    if (found) return found as AttackType
  }

  for (const k of allowedTypes) if (normKey(k) === n) return k
  return allowedTypes[0]
}

// Convert a frequency (MHz) into a channel number (2.4 / 5 GHz).
const freqToChannel = (freq: any): number => {
  const f = Number(freq)
  if (!Number.isFinite(f) || f <= 0) return 0
  if (f >= 2412 && f <= 2484) {
    if (f === 2484) return 14
    return Math.round((f - 2412) / 5) + 1
  }
  if (f >= 5000 && f <= 5900) {
    return Math.round((f - 5000) / 5)
  }
  if (f <= 200) return f // already a channel number
  return 0
}

// Format a MAC address (shown in full, not masked).
const normalizeMac = (raw: any): string => {
  let s = String(raw ?? "").trim()
  if (!s) return "Unknown"
  s = s.replace(/[^a-fA-F0-9]/g, "")
  if (s.length !== 12) return "Unknown"
  return s.toUpperCase().match(/.{1,2}/g)!.join(":")
}

// Sanity-check the RSSI value.
const normalizeRssi = (v: any): number | null => {
  const n = Number(v)
  if (!Number.isFinite(n)) return null
  if (n < -100 || n > -10) return null
  return Math.round(n)
}

// Derive a severity when the server does not send one (uses label / proba_attack when present).
const HIGH_TYPES: AttackType[] = ["deauth"]
const MEDIUM_TYPES: AttackType[] = ["krack"]
const deriveSeverity = (
  raw: any,
  attackType: AttackType,
  rssi: number | null,
  label?: number,
  proba?: number
): AttackEvent["severity"] => {
  const s = String(raw ?? "").trim()
  if (s === "Low" || s === "Medium" || s === "High") return s as AttackEvent["severity"]

  // If the server sends `label`: 0 = benign, 1 = attack.
  if (label === 0) return "Low"
  if (label === 1) return Number(proba) >= 0.8 ? "High" : "Medium"

  if (HIGH_TYPES.includes(attackType)) return "High"
  if (MEDIUM_TYPES.includes(attackType)) return "Medium"
  if (rssi !== null && rssi > -45) return "High"
  return "Low"
}

/* ================== Component ================== */
type RangeKey = Exclude<AttacksFilters["timeRange"], "all">

export default function AttacksPage() {
  const [selectedAttack, setSelectedAttack] = useState<AttackEvent | null>(null)
  const [allAttacks, setAllAttacks] = useState<AttackEvent[]>([])
  const [filters, setFilters] = useState<AttacksFilters>({
    search: "",
    timeRange: "24h",
    types: [] as AttackType[],
    severities: [] as AttackEvent["severity"][],
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchAttacks = () => {
    setLoading(true)
    setError(null)

    apiFetchJson<any>("/attacks?limit=5000&offset=0")
      .then((data) => {
        const arr: any[] = Array.isArray(data) ? data : (data?.attacks ?? data?.data ?? [])

        // Filter out Normal / Benign / None rows and label=0.
        const onlyAttacks = arr.filter((a) => {
          const rawType = String(a.attack_type ?? a.type ?? "").trim().toLowerCase()
          if (a.label === 0) return false
          if (rawType === "normal" || rawType === "benign" || rawType === "none") return false
          return true
        })

        const mapped: AttackEvent[] = onlyAttacks.map((a, idx) => {
          const ts = a.timestamp ?? a.frame_time_epoch ?? a.time ?? a.ts
          const type = normalizeAttackType(a.attack_type ?? a.type)

          const sourceMac = normalizeMac(a.wlan_sa ?? a.source_mac ?? a.src ?? a.sourceMac ?? a.sa ?? a.src_mac)
          const destMac   = normalizeMac(a.wlan_da ?? a.dst_mac ?? a.dst ?? a.destMac ?? a.da)

          const channel = freqToChannel(a.radiotap_channel_freq ?? a.channel ?? a.raw["radiotap.length"])
          const rssi = normalizeRssi(a.radiotap_dbm_antsignal ?? a.rssi ?? -67)
          const severity = deriveSeverity(a.severity, type, rssi, a.label, a.proba_attack)

          return {
            id: String(a.id ?? a.frame_number ?? `${ts}-${idx}`),
            timestamp: toDate(ts),
            type,
            sourceMac,
            destMac,
            severity,
            channel,
            rssi: rssi ?? 0,
          }
        })

        // Sort newest first by epoch millis.
        mapped.sort((a, b) => {
          const ta = a.timestamp instanceof Date ? a.timestamp.getTime() : Number.NaN
          const tb = b.timestamp instanceof Date ? b.timestamp.getTime() : Number.NaN
          const fa = Number.isFinite(ta), fb = Number.isFinite(tb)
          if (!fa && !fb) return 0
          if (!fa) return 1
          if (!fb) return -1
          return tb - ta
        })

        setAllAttacks(mapped)
        setLoading(false)
      })
      .catch((err) => {
        console.error(err)
        setError(err.message || "Failed to load")
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchAttacks()
    const t = setInterval(fetchAttacks, AUTO_REFRESH_MS)
    return () => clearInterval(t)
  }, [])

  const filteredAttacks = useMemo(() => {
    let filtered = allAttacks

    if (filters.timeRange !== "all") {
      const ranges: Record<RangeKey, number> = {
        "1h": 60 * 60 * 1000,
        "6h": 6 * 60 * 60 * 1000,
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
        "30d": 30 * 24 * 60 * 60 * 1000,
      }
      const windowMs = ranges[filters.timeRange as RangeKey]
      const cutoffMs = Date.now() - windowMs

      filtered = filtered.filter((a) => {
        const ts = a.timestamp instanceof Date ? a.timestamp.getTime() : Number.NaN
        if (!Number.isFinite(ts)) return true
        return ts >= cutoffMs
      })
    }

    if (filters.search) {
      const s = filters.search.toLowerCase()
      filtered = filtered.filter(
        (a) =>
          a.sourceMac.toLowerCase().includes(s) ||
          a.destMac.toLowerCase().includes(s) ||
          a.type.toLowerCase().includes(s) ||
          a.id.toLowerCase().includes(s),
      )
    }

    if (filters.types.length > 0) filtered = filtered.filter((a) => filters.types.includes(a.type))
    if (filters.severities.length > 0) filtered = filtered.filter((a) => filters.severities.includes(a.severity))

    return filtered
  }, [allAttacks, filters])

  // Paging
  const [currentPage, setPage] = useState(1)
  useEffect(() => setPage(1), [filters])
  const totalPages = Math.max(1, Math.ceil(filteredAttacks.length / PAGE_SIZE))
  const paginatedAttacks = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE
    return filteredAttacks.slice(start, start + PAGE_SIZE)
  }, [filteredAttacks, currentPage])

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-bold text-white">Attack Events</h1>
          <p className="text-gray-400 mt-1">
            Showing {filteredAttacks.length.toLocaleString()} of {allAttacks.length.toLocaleString()} total events
          </p>
        </div>
        <ReportModal />
      </div>

      {/* Filters */}
      <AttacksFiltersComponent
        filters={filters}
        onFiltersChange={(f) => {
          setPage(1)
          setFilters(f)
        }}
      />

      {/* Table / states */}
      {loading ? (
        <div className="text-center text-gray-400">Loading attack events…</div>
      ) : error ? (
        <div className="text-center text-red-400">Failed to load: {error}</div>
      ) : allAttacks.length === 0 ? (
        <div className="text-center text-gray-400">No attack events found.</div>
      ) : (
        <AttacksTable
          attacks={paginatedAttacks}
          onAttackClick={(a) => setSelectedAttack(a)}
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setPage}
        />
      )}

      {/* Detail Drawer */}
      <AttackDetailDrawer attack={selectedAttack} onClose={() => setSelectedAttack(null)} />
    </div>
  )
}
