"use client"

/**
 * Optional live upgrade: `GET /stream` (Server-Sent Events, one event per new
 * detection row).
 *
 * Strictly additive. The dashboard already polls `/attacks`, so this hook is
 * allowed to fail silently: on any error it closes the socket, reports
 * `"fallback"` and the caller keeps polling. It is deliberately self-contained
 * so it cannot take the dashboard down with it.
 */
import { useEffect, useRef, useState } from "react"
import { apiUrl } from "@/lib/api"

/** One detection row as the backend streams it. */
export type StreamDetection = {
  id: string | number
  ts: string | number
  predicted_label?: string
  p1?: number
  p2?: number
  src_mac?: string
  bssid?: string
  sim?: boolean
}

export type StreamState = "idle" | "connecting" | "open" | "fallback"

export type UseEventSourceResult = {
  state: StreamState
  /** Newest first, capped at `limit`. Empty whenever we are on the fallback. */
  events: StreamDetection[]
  clear: () => void
}

export function useEventSource(
  path = "/stream",
  opts: { enabled?: boolean; limit?: number } = {},
): UseEventSourceResult {
  const { enabled = true, limit = 25 } = opts
  const [state, setState] = useState<StreamState>("idle")
  const [events, setEvents] = useState<StreamDetection[]>([])
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!enabled) {
      setState("idle")
      return
    }
    if (typeof window === "undefined" || typeof window.EventSource === "undefined") {
      setState("fallback")
      return
    }

    let es: EventSource | null = null
    let closed = false

    try {
      setState("connecting")
      es = new EventSource(apiUrl(path))
      esRef.current = es

      es.onopen = () => {
        if (!closed) setState("open")
      }

      es.onmessage = (ev: MessageEvent<string>) => {
        if (closed) return
        let row: StreamDetection | null = null
        try {
          row = JSON.parse(ev.data) as StreamDetection
        } catch {
          return // a keep-alive / non-JSON frame; ignore it
        }
        if (!row || typeof row !== "object") return
        setState("open")
        setEvents((prev) => {
          const id = String(row.id ?? "")
          const deduped = id ? prev.filter((e) => String(e.id) !== id) : prev
          return [row as StreamDetection, ...deduped].slice(0, limit)
        })
      }

      es.onerror = () => {
        // EventSource retries on its own, but a static export served next to a
        // backend without /stream would retry forever. One strike, then poll.
        if (closed) return
        closed = true
        try {
          es?.close()
        } catch {
          /* already closed */
        }
        setState("fallback")
      }
    } catch {
      setState("fallback")
    }

    return () => {
      closed = true
      try {
        es?.close()
      } catch {
        /* already closed */
      }
      esRef.current = null
    }
  }, [path, enabled, limit])

  return { state, events, clear: () => setEvents([]) }
}
