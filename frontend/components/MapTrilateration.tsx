"use client"

/**
 * RSSI trilateration: pick a source the sensor has seen, and place it against
 * the configured access points.
 *
 * Four failure modes are handled explicitly here, because each of them has
 * rendered as a success at least once.
 *
 * 1. **`/map/ap-locations` can be empty.** It reads a configuration file that
 *    may not exist. V1 drew the map anyway, centred on Riyadh, which looked
 *    exactly like "we searched and found nothing" rather than "nothing was ever
 *    configured". An empty list says so in words and the map is not drawn.
 *
 * 2. **`POST /map/estimate-origin` answers `{"detail": "..."}` with HTTP 200.**
 *    Not 400, not 422 — a 200 carrying an error object. Anything that only
 *    checks `res.ok` renders a success state over a failure, which is how V1
 *    showed "Confidence: 0%" instead of "the request was rejected". The shape
 *    is discriminated on `method` before anything is read off it.
 *
 * 3. **A valid response can still carry `used: 0, center: null`.** That is the
 *    normal answer when none of the configured BSSIDs appear in the source's
 *    frames, and it is a finding, not an error. It gets its own copy, and the
 *    sensor's own `note` is printed verbatim beside it.
 *
 * 4. **The configured anchors may not be anchors at all.** On this deployment
 *    `/map/ap-locations` returns placeholder BSSIDs that no captured frame ever
 *    names, so a fix is arithmetically impossible. Rather than leaving that to
 *    be inferred from an empty readout, the page compares the two BSSID sets
 *    itself and states the mismatch. **No position is ever drawn that the sensor
 *    did not compute.**
 *
 * The V1 "Confidence: 62%" readout is gone. It was `min(1, used / 5)` — the
 * number of contributing access points, rescaled and relabelled as a
 * probability. The count itself is reported instead, alongside the uncertainty
 * ring it drives, because that is the thing the sensor actually knows.
 */
import * as React from "react"
import dynamic from "next/dynamic"

import { DataTable, type DataTableColumn } from "@/components/hs/data-table"
import { Panel, PanelGrid } from "@/components/hs/panel"
import { StatusPill } from "@/components/hs/status-pill"
import { LoadError, Readout, ReadoutRow, Unreported } from "@/components/console/frame"
import { Quantity } from "@/components/quantity"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiFetchJson, apiPostJson } from "@/lib/api"
import { Mac, useFormatters } from "@/lib/format"
import { useLocale, useT, type TranslationKey } from "@/lib/i18n"
import type { AP, LatLng, RSSIPoint } from "@/components/LeafletMap"

const MAP_HEIGHT = 460

const LeafletMap = dynamic(() => import("@/components/LeafletMap"), {
  ssr: false,
  loading: function MapLoading() {
    return (
      <div className="hs-scan bg-paper-0 grid place-items-center" style={{ blockSize: MAP_HEIGHT }} />
    )
  },
})

/* ── Wire shapes ─────────────────────────────────────────────────────────── */

type SourceRSSI = { sa: string; points: RSSIPoint[] }
type OffenderRow = { wlan_sa: string; count: number }

/** The success shape. Note that `center` is null far more often than not. */
type EstimateOk = {
  sa?: string
  method?: string
  used?: number
  center?: { lat: number; lng: number } | null
  note?: string
}

/** The HTTP-200 rejection shape. Discriminated on `method` being absent. */
type EstimateAny = EstimateOk & { detail?: string }

/** What the readout renders, once the response has been interpreted. */
type Estimate =
  | { kind: "ok"; method: string | null; used: number; centre: LatLng | null; note: string | null }
  | { kind: "rejected"; detail: string | null }
  | { kind: "failed" }

const WINDOWS: readonly { minutes: number; key: TranslationKey }[] = [
  { minutes: 60, key: "time.range.hour1" },
  { minutes: 1440, key: "time.range.hours24" },
  { minutes: 10080, key: "time.range.days7" },
]

/**
 * A coordinate, or `null`.
 *
 * `Number(null)` is `0` and `0` is a perfectly finite latitude, so a bare
 * `Number.isFinite(Number(x))` check accepts a missing coordinate and plots it
 * at the Gulf of Guinea — a confident pin in the ocean rather than an admission
 * that the field was empty. Null and empty string are rejected before the cast.
 */
function coord(value: unknown): number | null {
  if (value == null || value === "") return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

/**
 * Uncertainty ring in metres, from the number of access points that actually
 * contributed. Fewer anchors, wider ring. Zero anchors draws nothing at all
 * rather than a circle the size of the district.
 */
function uncertaintyFor(used: number): number {
  if (used >= 4) return 25
  if (used === 3) return 50
  if (used >= 1) return 100
  return 0
}

export default function MapTrilateration() {
  const t = useT()
  const f = useFormatters()
  const { dir } = useLocale()

  const [aps, setAps] = React.useState<AP[] | null>(null)
  const [apsFailed, setApsFailed] = React.useState(false)
  const [sources, setSources] = React.useState<OffenderRow[] | null>(null)
  const [sa, setSa] = React.useState<string>("")
  const [minutes, setMinutes] = React.useState(1440)

  const [rssi, setRssi] = React.useState<RSSIPoint[] | null>(null)
  const [estimate, setEstimate] = React.useState<Estimate | null>(null)
  const [busy, setBusy] = React.useState(false)

  /* ---- the fixed inputs: access points, and the sources worth asking about - */
  React.useEffect(() => {
    let alive = true

    void (async () => {
      try {
        const raw = await apiFetchJson<unknown[]>("/map/ap-locations", { cache: "no-store" })
        const parsed: AP[] = (Array.isArray(raw) ? raw : []).flatMap((a) => {
          const r = a as Record<string, unknown>
          const bssid = String(r.bssid ?? "").toUpperCase()
          const lat = coord(r.lat)
          const lng = coord(r.lng)
          // An access point without a usable coordinate is dropped rather than
          // anchored somewhere invented; it cannot contribute to a fix anyway.
          if (!bssid || lat === null || lng === null) return []
          return [{ bssid, name: r.name ? String(r.name) : null, lat, lng }]
        })
        if (alive) setAps(parsed)
      } catch {
        if (alive) {
          setAps(null)
          setApsFailed(true)
        }
      }

      try {
        const raw = await apiFetchJson<OffenderRow[]>("/top-offenders", { cache: "no-store" })
        const rows = (Array.isArray(raw) ? raw : []).filter((r) => r?.wlan_sa)
        if (!alive) return
        setSources(rows)
        // Default to the busiest source: the one an operator would pick anyway.
        setSa((current) => current || rows[0]?.wlan_sa || "")
      } catch {
        if (alive) setSources([])
      }
    })()

    return () => {
      alive = false
    }
  }, [])

  /* ---- the query: readings for this source, and where they place it ------- */
  React.useEffect(() => {
    if (!sa || aps === null || aps.length === 0) return
    let alive = true
    setBusy(true)

    void (async () => {
      try {
        const res = await apiFetchJson<SourceRSSI>(
          `/map/source-rssi?sa=${encodeURIComponent(sa)}&minutes=${minutes}`,
          { cache: "no-store" }
        )
        const pts = (res?.points ?? []).map((p) => ({
          ...p,
          bssid: String(p.bssid ?? "").toUpperCase(),
        }))
        if (alive) setRssi(pts)
      } catch {
        if (alive) setRssi(null)
      }

      try {
        const res = await apiPostJson<EstimateAny>("/map/estimate-origin", {
          sa,
          minutes,
          ap_locations: aps,
        })

        if (!alive) return

        // The rejection shape arrives with HTTP 200, so the status told us
        // nothing. `method` is present on every real answer and on no rejection.
        if (!res || (res.detail != null && res.method == null)) {
          setEstimate({ kind: "rejected", detail: res?.detail ? String(res.detail) : null })
          return
        }

        const used = Number(res.used) || 0
        const lat = coord(res.center?.lat)
        const lng = coord(res.center?.lng)
        const centre = lat !== null && lng !== null ? { lat, lng } : null

        setEstimate({
          kind: "ok",
          method: res.method ? String(res.method) : null,
          used,
          centre,
          note: res.note ? String(res.note) : null,
        })
      } catch {
        if (alive) setEstimate({ kind: "failed" })
      } finally {
        if (alive) setBusy(false)
      }
    })()

    return () => {
      alive = false
    }
  }, [sa, minutes, aps])

  /**
   * Whether any configured anchor appears among the BSSIDs this source was
   * actually heard on. When it does not, no arithmetic can produce a fix, and
   * saying that plainly is more useful than an empty readout the reader has to
   * interpret.
   */
  const anchorsMatch = React.useMemo(() => {
    if (!aps || aps.length === 0 || !rssi || rssi.length === 0) return null
    const heard = new Set(rssi.map((p) => p.bssid.toUpperCase()))
    return aps.some((ap) => heard.has(ap.bssid.toUpperCase()))
  }, [aps, rssi])

  /* ---- readings table ---------------------------------------------------- */

  const rssiColumns: DataTableColumn<RSSIPoint>[] = React.useMemo(
    () => [
      {
        id: "bssid",
        header: t("threats.detail.bssid"),
        cell: (p) => <Mac value={p.bssid} className="text-ink-0 text-xs" />,
      },
      {
        id: "rssi",
        header: t("map.avgRssi"),
        numeric: true,
        width: "8rem",
        // Figure isolated, unit not — see `components/quantity.tsx`.
        cell: (p) => (
          <Quantity value={f.number(Math.round(p.avg_rssi))} unit={t("units.dbm")} />
        ),
      },
      {
        id: "n",
        header: t("map.samples"),
        numeric: true,
        width: "6rem",
        cell: (p) => f.number(p.n),
      },
    ],
    [t, f]
  )

  /* ---- render ------------------------------------------------------------ */

  // Nothing is configured: say that, and draw no map. An empty map centred on a
  // default coordinate reads as a result, and it is not one.
  if (aps !== null && aps.length === 0) {
    return (
      <Panel label={t("map.apLocations")} title={t("map.noApLocations")}>
        <p className="text-ink-1 max-w-[72ch] text-sm">{t("map.noApDetail")}</p>
      </Panel>
    )
  }

  if (apsFailed && aps === null) {
    return (
      <Panel label={t("map.apLocations")}>
        <LoadError>{t("map.error.load")}</LoadError>
      </Panel>
    )
  }

  const centre = estimate?.kind === "ok" ? estimate.centre : null
  const used = estimate?.kind === "ok" ? estimate.used : 0

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <Panel
        label={t("map.controls")}
        actions={
          <StatusPill tone="neutral">
            {t("map.apConfigured", { n: f.number(aps?.length ?? 0) })}
          </StatusPill>
        }
      >
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex min-w-0 flex-1 basis-56 flex-col gap-1.5">
            <span className="hs-label">{t("map.source")}</span>
            {sources !== null && sources.length === 0 ? (
              <span className="text-ink-2 text-xs">{t("map.sourceEmpty")}</span>
            ) : (
              <Select dir={dir} value={sa} onValueChange={setSa}>
                <SelectTrigger className="w-full" aria-label={t("map.sourcePick")}>
                  <SelectValue placeholder={t("map.sourcePick")} />
                </SelectTrigger>
                <SelectContent>
                  {(sources ?? []).map((row) => (
                    <SelectItem key={row.wlan_sa} value={row.wlan_sa}>
                      {/* A MAC beside a count: the MAC is pinned LTR, the count
                          is a plain figure in the reader's own direction. */}
                      <span className="flex items-center gap-2">
                        <span className="hs-num">{row.wlan_sa.toUpperCase()}</span>
                        <span className="hs-num text-ink-2 text-xs">{f.number(row.count)}</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          <div className="flex min-w-0 flex-1 basis-44 flex-col gap-1.5">
            <span className="hs-label">{t("map.window")}</span>
            <Select dir={dir} value={String(minutes)} onValueChange={(v) => setMinutes(Number(v))}>
              <SelectTrigger className="w-full" aria-label={t("map.window")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {WINDOWS.map((w) => (
                  <SelectItem key={w.minutes} value={String(w.minutes)}>
                    {t(w.key)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* The plainest statement this page can make, and the true one today. */}
        {anchorsMatch === false && (
          <p className="text-sev-high mt-4 max-w-[72ch] text-sm">{t("map.anchorsUnmatched")}</p>
        )}
      </Panel>

      {/* The map lives inside a panel like every other instrument, flush to the
          hairline so the canvas meets the paper edge with nothing between. */}
      <Panel label={t("map.panel")} title={t("map.mapLabel")} flush>
        <LeafletMap
          centre={centre}
          aps={aps ?? []}
          points={rssi ?? []}
          height={MAP_HEIGHT}
          uncertaintyMetres={uncertaintyFor(used)}
        />
      </Panel>

      <PanelGrid className="lg:grid-cols-2">
        <Panel label={t("map.readout")} loading={busy && estimate === null}>
          {estimate === null ? (
            <p className="hs-label py-4">{t("map.loadingData")}</p>
          ) : estimate.kind === "failed" ? (
            <LoadError>{t("map.error.load")}</LoadError>
          ) : estimate.kind === "rejected" ? (
            <div className="flex flex-col gap-2">
              <p className="text-sev-high text-sm">{t("map.rejected")}</p>
              {/* The sensor's own words, verbatim and untranslated — inventing
                  an Arabic rendering of a server message we did not write would
                  be putting words in its mouth. Pinned LTR: machine prose. */}
              {estimate.detail && (
                <p className="hs-ltr text-ink-2 font-mono text-xs">{estimate.detail}</p>
              )}
            </div>
          ) : (
            <>
              <Readout>
                <ReadoutRow label={t("map.source")}>
                  <Mac value={sa} className="text-sm" />
                </ReadoutRow>
                <ReadoutRow label={t("map.method")}>
                  {estimate.method ? (
                    <span className="hs-ltr font-mono text-sm">{estimate.method}</span>
                  ) : (
                    <Unreported />
                  )}
                </ReadoutRow>
                <ReadoutRow label={t("map.apsUsed")}>
                  <span className="hs-num">{f.number(estimate.used)}</span>
                </ReadoutRow>
                {estimate.centre && (
                  <>
                    <ReadoutRow label={t("map.latitude")}>
                      <span className="hs-num">{estimate.centre.lat.toFixed(6)}</span>
                    </ReadoutRow>
                    <ReadoutRow label={t("map.longitude")}>
                      <span className="hs-num">{estimate.centre.lng.toFixed(6)}</span>
                    </ReadoutRow>
                    <ReadoutRow label={t("map.uncertainty")}>
                      <Quantity
                        value={f.number(uncertaintyFor(estimate.used))}
                        unit={t("map.metres")}
                      />
                    </ReadoutRow>
                  </>
                )}
              </Readout>

              {!estimate.centre && (
                <div className="mt-4 flex flex-col gap-2">
                  <p className="text-ink-0 text-sm font-medium">{t("map.noEstimate")}</p>
                  <p className="text-ink-1 max-w-[72ch] text-sm">{t("map.noEstimateDetail")}</p>
                </div>
              )}

              {/* Whatever the sensor said about this answer, in its own words. */}
              {estimate.note && (
                <p className="border-rule mt-4 flex flex-col gap-1 border-t pt-3">
                  <span className="hs-label">{t("map.sensorNote")}</span>
                  <span className="hs-ltr text-ink-2 font-mono text-xs">{estimate.note}</span>
                </p>
              )}
            </>
          )}
        </Panel>

        <Panel label={t("map.rssiTitle")} flush>
          <DataTable
            columns={rssiColumns}
            rows={rssi ?? []}
            rowKey={(p) => p.bssid}
            state={rssi === null ? (busy ? "loading" : "error") : "ready"}
            emptyLabel={t("map.rssiEmpty")}
            loadingLabel={t("map.loadingData")}
            errorLabel={t("map.error.load")}
          />
        </Panel>
      </PanelGrid>
    </div>
  )
}
