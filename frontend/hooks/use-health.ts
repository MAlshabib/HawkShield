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

export type HealthPayload = {
  status?: string
  database?: boolean
  packets?: number
  latest_packet_ts?: string | null
  models?: Record<string, boolean>
  model_version?: string
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
