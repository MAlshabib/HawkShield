"use client"

/**
 * Poll `GET /health` and turn it into one calm connection state.
 *
 * The dashboard uses this to degrade gracefully rather than to alarm: when the
 * API or its database drops out we keep the last good numbers on screen and
 * show a quiet "reconnecting…" chip. We never synthesise data to fill the gap —
 * composure, not fabrication.
 */
import { useCallback, useEffect, useRef, useState } from "react"
import { apiUrl } from "@/lib/api"

/**
 * What the sensor is *set to*, and — only where the API process can actually
 * measure it — what the interface is doing. See CONTRACT §4.
 *
 * `iface`, `channel`, `target_ssid` and `source` are always present. **Every
 * other field is `null` when it genuinely cannot be known** — off Linux there
 * is no `/sys/class/net`, so nothing is measured and `source` is `"config"`.
 * `null` never means "probably fine", so a consumer must render it as *not
 * reported* rather than as a healthy default.
 */
export type CapturePayload = {
  /** Configured `CAPTURE_IFACE`. */
  iface?: string | null
  /** Configured `CAPTURE_CHANNEL` — what the radio was set to, not a readback. */
  channel?: number | null
  /** Configured `TARGET_SSID`; null when unset (no filter). */
  target_ssid?: string | null
  /** Interface exists in sysfs. */
  present?: boolean | null
  /** Link type is a radiotap/prism monitor interface. */
  monitor_mode?: boolean | null
  link_type?: string | null
  /** Kernel operstate (`up`, `down`, …). */
  operstate?: string | null
  /** Interface on the newest stored packet — what the sensor is actually delivering. */
  observed_iface?: string | null
  observed_channel_freq?: number | null
  /** `"config+sysfs"` when something was measured, `"config"` when nothing was. */
  source?: string | null
}

export type HealthPayload = {
  status?: string
  database?: boolean
  packets?: number
  latest_packet_ts?: string | null
  models?: Record<string, boolean>
  model_version?: string
  /** Feature-contract version this build implements; see backend/app/schemas.py. */
  spec_version?: string
  /** Version the on-disk artefact claims — differs from `spec_version` when the export is stale. */
  artefact_spec_version?: string
  /** Capture-interface state. Absent on a backend older than the `capture` block. */
  capture?: CapturePayload | null
  version?: string
}

/**
 * - `online`   — API answered and its database is reachable.
 * - `degraded` — API answered but `database:false`; reads will be thin.
 * - `offline`  — API did not answer at all.
 * - `unknown`  — first probe still in flight.
 */
export type ConnectionState = "unknown" | "online" | "degraded" | "offline"

export type HealthStatus = {
  state: ConnectionState
  health: HealthPayload | null
  /** Epoch ms of the last fully-healthy probe, or null if we never saw one. */
  lastOkAt: number | null
  /** Consecutive failed/degraded probes — used only to soften the copy. */
  failures: number
  /** True while a probe is in flight after at least one earlier probe. */
  probing: boolean
  refresh: () => void
}

const OK_INTERVAL_MS = 15_000
const RETRY_INTERVAL_MS = 5_000
const PROBE_TIMEOUT_MS = 6_000

export function useHealth(): HealthStatus {
  const [state, setState] = useState<ConnectionState>("unknown")
  const [health, setHealth] = useState<HealthPayload | null>(null)
  const [lastOkAt, setLastOkAt] = useState<number | null>(null)
  const [failures, setFailures] = useState(0)
  const [probing, setProbing] = useState(false)
  const [tick, setTick] = useState(0)

  const mounted = useRef(true)
  const refresh = useCallback(() => setTick((n) => n + 1), [])

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const probe = async () => {
      setProbing(true)
      let next: ConnectionState = "offline"
      let payload: HealthPayload | null = null

      // AbortSignal.timeout is not in every browser we might demo on.
      const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null
      const killer = ctrl ? setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS) : undefined
      try {
        const res = await fetch(apiUrl("/health"), {
          cache: "no-store",
          signal: ctrl?.signal,
        })
        if (res.ok) {
          const txt = await res.text()
          payload = txt ? (JSON.parse(txt) as HealthPayload) : {}
          next = payload?.database === false ? "degraded" : "online"
        }
      } catch {
        next = "offline"
      } finally {
        if (killer) clearTimeout(killer)
      }

      if (cancelled || !mounted.current) return

      setState(next)
      setProbing(false)
      if (payload) setHealth(payload)
      if (next === "online") {
        setLastOkAt(Date.now())
        setFailures(0)
      } else {
        setFailures((n) => n + 1)
      }

      timer = setTimeout(probe, next === "online" ? OK_INTERVAL_MS : RETRY_INTERVAL_MS)
    }

    void probe()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [tick])

  return { state, health, lastOkAt, failures, probing, refresh }
}
