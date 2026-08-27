"use client"

/**
 * The Leaflet canvas: access points, the estimated origin, and the links
 * between them.
 *
 * Three things about this component are deliberate and easy to undo by accident.
 *
 * **The map is pinned `dir="ltr"`, the chrome around it is not.** Leaflet's own
 * stylesheet is physically left/right — the zoom control is `.leaflet-top
 * .leaflet-left`, the attribution is bottom-right, and the pane transforms are
 * computed in screen pixels. Under `dir="rtl"` the control column detached from
 * the corner it belongs to and the attribution collided with the zoom buttons.
 * Mirroring is also the wrong fix conceptually: a map is a spatial artefact, and
 * north-up/east-right does not flip with the reading direction. So the container
 * is LTR and only the *text inside popups* is handed back its real direction.
 *
 * **Colours come from CSS, never from `pathOptions.color`.** Leaflet writes
 * path colours as SVG presentation attributes, and `var(--sev-critical)` in an
 * attribute does not resolve — it silently renders black. Every path therefore
 * carries a `className` and is painted by the scoped rules below, which means
 * the map re-themes with the rest of the page instead of freezing at whatever
 * the palette was on mount.
 *
 * **Tiles are treated, not replaced.** OSM ships one light basemap; a white
 * rectangle inside the dark console is unreadable next to it. The dark theme
 * inverts the tile pane, which is a rendering treatment of the same tiles — no
 * geometry, label or coordinate changes.
 */
import * as React from "react"
import {
  Circle,
  CircleMarker,
  MapContainer,
  Marker,
  Polyline,
  Popup,
  TileLayer,
  Tooltip,
} from "react-leaflet"
import L from "leaflet"
import "leaflet/dist/leaflet.css"

import { Quantity } from "@/components/quantity"
import { useFormatters } from "@/lib/format"
import { useLocale, useT } from "@/lib/i18n"

/**
 * Leaflet resolves its default icon URLs relative to the CSS bundle, which
 * breaks under Next. These point at `public/leaflet/`, vendored so the Pi demo
 * works with no internet at all.
 */
const DefaultIcon = L.icon({
  iconUrl: "/leaflet/marker-icon.png",
  iconRetinaUrl: "/leaflet/marker-icon-2x.png",
  shadowUrl: "/leaflet/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
})
L.Marker.prototype.options.icon = DefaultIcon

export type LatLng = { lat: number; lng: number }
export type AP = { bssid: string; name?: string | null; lat: number; lng: number }
export type RSSIPoint = { bssid: string; avg_rssi: number; n: number }

/** Riyadh, used only when there is nothing at all to centre on. */
const FALLBACK_CENTRE: LatLng = { lat: 24.7136, lng: 46.6753 }

/**
 * Scoped Leaflet overrides. A `<style>` element rather than an edit to
 * `app/globals.css`: these rules exist only where a map is mounted, and the
 * design system's stylesheet should not carry a third-party library's reset.
 */
const MAP_CSS = `
/* The basemap, treated for paper in BOTH themes.

   Light: OSM's own palette is a saturated road atlas — beside four paper steps
   and one azure it reads as a photograph pasted into a document. Desaturating
   and lifting it lands the tiles on the same paper the panels are cut from,
   without touching a single label, road or coordinate.

   Dark: the same tiles inverted. A white rectangle inside a graphite page is
   unreadable, and there is no dark OSM tile server to reach for offline. Both
   are rendering treatments of identical geometry. */
.hs-map .leaflet-container {
  background: var(--color-paper-2);
  font-family: var(--font-body);
  font-size: 0.75rem;
}
.hs-map .leaflet-tile-pane {
  filter: saturate(0.62) contrast(0.9) brightness(1.04);
}
.dark .hs-map .leaflet-tile-pane {
  filter: invert(1) hue-rotate(180deg) brightness(0.86) contrast(0.9) saturate(0.55);
}

/* Controls, popups and tooltips are paper objects: the card surface, the soft
   hairline, the system radius. Nothing here invents a colour. */
.hs-map .leaflet-bar,
.hs-map .leaflet-bar a {
  background: var(--color-paper-1);
  color: var(--color-ink-0);
  border-color: var(--color-rule-soft);
  border-radius: var(--radius-sm);
}
.hs-map .leaflet-bar a:hover {
  background: var(--color-paper-2);
  color: var(--color-ink-0);
}
.hs-map .leaflet-control-attribution {
  background: color-mix(in oklch, var(--color-paper-1) 88%, transparent);
  color: var(--color-ink-2);
  border-start-start-radius: var(--radius-sm);
}
.hs-map .leaflet-control-attribution a {
  color: var(--color-accent-cta);
}
.hs-map .leaflet-popup-content-wrapper,
.hs-map .leaflet-popup-tip {
  background: var(--color-paper-1);
  color: var(--color-ink-0);
  border: 1px solid var(--color-rule-soft);
  border-radius: var(--radius-md);
  box-shadow: none;
}
.hs-map .leaflet-popup-content {
  margin: 0.625rem 0.75rem;
}
.hs-map .leaflet-popup-close-button {
  color: var(--color-ink-2);
}
.hs-map .leaflet-tooltip {
  background: var(--color-paper-1);
  color: var(--color-ink-0);
  border: 1px solid var(--color-rule-soft);
  border-radius: var(--radius-sm);
  box-shadow: none;
  font-family: var(--font-mono);
  font-size: 0.6875rem;
  padding: 2px 6px;
}
.hs-map .leaflet-tooltip-top::before {
  border-top-color: var(--color-rule-soft);
}

/* Paths are painted HERE, never through pathOptions.color.

   Leaflet writes a path's colour as an SVG *presentation attribute*, and a
   var() in a presentation attribute does not resolve — the path silently
   renders black, which on a light basemap looks deliberate and on a dark one
   disappears. Every path therefore carries a className and is coloured by
   these rules, which also means the map re-themes with the page instead of
   freezing at whatever the palette was when it mounted.

   NOTE: no backticks anywhere in this string. It is a template literal, and a
   backtick in a comment inside it terminates the CSS halfway through. */
.hs-map .hs-path-estimate {
  stroke: var(--color-critical);
  fill: var(--color-critical);
}
.hs-map .hs-path-uncertainty {
  stroke: var(--color-critical);
  fill: var(--color-critical);
}
.hs-map .hs-path-link {
  stroke: var(--color-accent);
}
`

/** One label/value line inside a popup. */
function PopupLine({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="hs-label">{label}</span>
      <span className="text-ink-0 text-xs">{children}</span>
    </div>
  )
}

export default function LeafletMap({
  centre,
  aps = [],
  points = [],
  height = 460,
  zoom = 17,
  uncertaintyMetres = 0,
}: {
  /** The estimated origin, or `null` when the sensor could not compute one. */
  centre?: LatLng | null
  aps?: AP[]
  points?: RSSIPoint[]
  height?: number
  zoom?: number
  /** Radius of the uncertainty ring in metres. `0` draws no ring. */
  uncertaintyMetres?: number
}) {
  const t = useT()
  const f = useFormatters()
  const { dir } = useLocale()

  // Once a tile has landed we never flip back: a single failed tile at the edge
  // of a pan is not the same as having no basemap.
  const [tiles, setTiles] = React.useState<"pending" | "ok" | "failed">("pending")

  const rssiByBssid = React.useMemo(() => {
    const m = new Map<string, RSSIPoint>()
    for (const p of points) if (p?.bssid) m.set(String(p.bssid).toUpperCase(), p)
    return m
  }, [points])

  /** Estimate first, then the first access point, then Riyadh. */
  const view: LatLng = centre ?? aps[0] ?? FALLBACK_CENTRE
  const hasEstimate = centre !== null && centre !== undefined

  return (
    <>
      <style>{MAP_CSS}</style>
      {/* `dir="ltr"` stops here. Everything outside this box mirrors normally. */}
      <div
        dir="ltr"
        className="hs-map bg-paper-0 relative min-w-0 overflow-hidden"
        style={{ blockSize: height }}
        role="img"
        aria-label={t("map.mapLabel")}
      >
        {tiles === "failed" && (
          <div
            // `dir` is restored here because this is prose, not geography.
            dir={dir}
            className="border-rule bg-paper-1 pointer-events-none absolute inset-x-0 top-0 z-[1000] border-b px-3 py-1.5 text-center"
          >
            <span className="hs-label text-sev-high">{t("map.tilesOffline")}</span>
          </div>
        )}

        <MapContainer
          center={[view.lat, view.lng]}
          zoom={zoom}
          scrollWheelZoom
          style={{ height: "100%", width: "100%" }}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            eventHandlers={{
              tileload: () => setTiles("ok"),
              tileerror: () => setTiles((s) => (s === "ok" ? s : "failed")),
            }}
          />

          {aps.map((ap) => {
            const reading = rssiByBssid.get(ap.bssid.toUpperCase())
            return (
              <Marker key={`${ap.bssid}-${ap.lat}-${ap.lng}`} position={[ap.lat, ap.lng]}>
                {/* Permanent, so the access points stay identifiable even with
                    no basemap under them. A name or a BSSID is Latin either
                    way, so this label needs no direction of its own. */}
                <Tooltip direction="top" offset={[0, -38]} permanent>
                  {ap.name || ap.bssid}
                </Tooltip>
                <Popup>
                  <div dir={dir} className="flex min-w-44 flex-col gap-1">
                    <span className="text-ink-0 text-sm font-medium">
                      {ap.name ? <span className="hs-ltr">{ap.name}</span> : t("map.apLocations")}
                    </span>
                    <PopupLine label={t("threats.detail.bssid")}>
                      <span className="hs-num">{ap.bssid.toUpperCase()}</span>
                    </PopupLine>
                    {reading ? (
                      <>
                        <PopupLine label={t("map.avgRssi")}>
                          {/* The figure is isolated, the unit is not — see
                              `components/quantity.tsx`. */}
                          <Quantity
                            value={f.number(Math.round(reading.avg_rssi))}
                            unit={t("units.dbm")}
                          />
                        </PopupLine>
                        <PopupLine label={t("map.samples")}>
                          <span className="hs-num">{f.number(reading.n)}</span>
                        </PopupLine>
                      </>
                    ) : (
                      <span className="text-ink-2 text-xs">{t("map.rssiEmpty")}</span>
                    )}
                  </div>
                </Popup>
              </Marker>
            )
          })}

          {hasEstimate && (
            <>
              <CircleMarker
                center={[centre.lat, centre.lng]}
                radius={9}
                pathOptions={{ className: "hs-path-estimate", weight: 2, fillOpacity: 0.55 }}
              >
                <Popup>
                  <div dir={dir} className="flex min-w-44 flex-col gap-1">
                    <span className="text-ink-0 text-sm font-medium">{t("map.estimatedSource")}</span>
                    <PopupLine label={t("map.latitude")}>
                      <span className="hs-num">{centre.lat.toFixed(6)}</span>
                    </PopupLine>
                    <PopupLine label={t("map.longitude")}>
                      <span className="hs-num">{centre.lng.toFixed(6)}</span>
                    </PopupLine>
                  </div>
                </Popup>
              </CircleMarker>

              {uncertaintyMetres > 0 && (
                <Circle
                  center={[centre.lat, centre.lng]}
                  radius={uncertaintyMetres}
                  pathOptions={{ className: "hs-path-uncertainty", weight: 1, fillOpacity: 0.1 }}
                />
              )}

              {/* One link per access point that actually contributed a reading —
                  drawing a line to an AP with no samples would imply it did. */}
              {aps.map((ap) =>
                rssiByBssid.has(ap.bssid.toUpperCase()) ? (
                  <Polyline
                    key={`link-${ap.bssid}`}
                    positions={[
                      [centre.lat, centre.lng],
                      [ap.lat, ap.lng],
                    ]}
                    pathOptions={{ className: "hs-path-link", weight: 1.5, opacity: 0.7 }}
                  />
                ) : null
              )}
            </>
          )}
        </MapContainer>
      </div>
    </>
  )
}
