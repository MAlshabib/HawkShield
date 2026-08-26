/**
 * Single source of truth for talking to the HawkShield FastAPI backend.
 *
 * In production the API serves this static export itself (same-origin), so the
 * default base is an empty string and every request is a relative URL such as
 * `/attacks`. For laptop development against a remote Pi, set
 * `NEXT_PUBLIC_API_BASE=http://<pi-ip>:8000` in `.env.local`.
 *
 * NOTE: `NEXT_PUBLIC_*` values are inlined at build time, so a change requires a
 * rebuild (or a `next dev` restart).
 */

/** Base URL for every API call. Empty string means "same origin". */
export const API_BASE: string = (process.env.NEXT_PUBLIC_API_BASE || "").replace(/\/+$/, "")

/** Build an absolute (or same-origin relative) URL for an API path. */
export function apiUrl(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`
  return `${API_BASE}${p}`
}

/** Error thrown by `apiFetch` / `apiFetchJson` on a non-2xx response. */
export class ApiError extends Error {
  readonly status: number
  readonly statusText: string
  readonly body: string

  constructor(status: number, statusText: string, body: string, url: string) {
    super(`HTTP ${status}${statusText ? ` ${statusText}` : ""} for ${url}${body ? ` — ${body}` : ""}`)
    this.name = "ApiError"
    this.status = status
    this.statusText = statusText
    this.body = body
  }
}

/**
 * `fetch` against the API base. Throws `ApiError` on a non-2xx response.
 * Returns the raw `Response` — use it for blobs / streams (e.g. PDF export).
 */
export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = apiUrl(path)
  const res = await fetch(url, init)
  if (!res.ok) {
    let body = ""
    try {
      body = await res.text()
    } catch {
      /* body already consumed or unreadable */
    }
    throw new ApiError(res.status, res.statusText, body, url)
  }
  return res
}

/** `apiFetch` + JSON parsing. Throws `ApiError` on a non-2xx response. */
export async function apiFetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init)
  const txt = await res.text()
  return (txt ? (JSON.parse(txt) as T) : (undefined as T))
}

/** POST a JSON body and parse the JSON response. Throws `ApiError` on non-2xx. */
export async function apiPostJson<T>(path: string, body: unknown, init?: RequestInit): Promise<T> {
  return apiFetchJson<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    body: JSON.stringify(body),
    ...init,
  })
}

/**
 * Never-throwing variant: returns `fallback` on any network error, non-2xx
 * response or unparseable body. Used by the dashboard / map so a backend that
 * is down renders an empty state instead of crashing the page.
 */
export async function apiFetchSafe<T>(path: string, fallback: T, init?: RequestInit): Promise<T> {
  try {
    const res = await fetch(apiUrl(path), init)
    if (!res.ok) return fallback
    const txt = await res.text()
    return txt ? (JSON.parse(txt) as T) : fallback
  } catch {
    return fallback
  }
}
