"use client"

import { useMemo, useState } from "react"
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Tooltip,
  CircleMarker,
  Polyline,
  Circle,
} from "react-leaflet"
import L from "leaflet"
import "leaflet/dist/leaflet.css"

// Leaflet's default icon URLs are resolved relative to the CSS bundle, which
// breaks under Next.js. Point them at the copies in `public/leaflet/` so the map
// keeps working with no internet access (offline Pi demo).
const DefaultIcon = L.icon({
  iconUrl: "/leaflet/marker-icon.png",
  iconRetinaUrl: "/leaflet/marker-icon-2x.png",
  shadowUrl: "/leaflet/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
})
// Leaflet exposes the prototype default icon at runtime.
L.Marker.prototype.options.icon = DefaultIcon

type LatLng = { lat: number; lng: number }

type AP = {
  bssid: string
  name?: string
  lat: number | string
  lng: number | string
}

type RSSIPoint = {
  bssid: string
  avg_rssi: number
  n: number
}

export default function LeafletMap({
  center,
  aps = [],
  points = [],
  height = 480,
  zoom = 17,
  confidence = 0, // 0..1
}: {
  center?: Partial<LatLng> | null
  aps?: AP[]
  points?: RSSIPoint[]
  height?: number
  zoom?: number
  confidence?: number
}) {
  // OSM basemap tiles need internet. Track failures so we can degrade
  // gracefully instead of showing a silently blank map.
  // Once a tile has loaded we never flip back to the degraded state.
  const [tileState, setTileState] = useState<"pending" | "ok" | "failed">("pending")
  const tilesFailed = tileState === "failed"

  // Coerce AP coordinates to numbers and drop invalid entries.
  const apsNorm = useMemo(() => {
    return (aps || [])
      .map((a) => ({
        ...a,
        lat: Number(a.lat),
        lng: Number(a.lng),
      }))
      .filter((a) => Number.isFinite(a.lat) && Number.isFinite(a.lng))
  }, [aps])

  // BSSID -> RSSI reading
  const rssiByBssid = useMemo(() => {
    const m = new Map<string, RSSIPoint>()
    for (const p of points || []) {
      if (p?.bssid) m.set(String(p.bssid).toUpperCase(), p)
    }
    return m
  }, [points])

  // Safe map centre: estimate -> first AP -> Riyadh.
  const safeCenter: LatLng = useMemo(() => {
    const cLat = Number((center as any)?.lat)
    const cLng = Number((center as any)?.lng)
    if (Number.isFinite(cLat) && Number.isFinite(cLng)) {
      return { lat: cLat, lng: cLng }
    }
    if (apsNorm.length > 0) {
      return { lat: apsNorm[0].lat, lng: apsNorm[0].lng }
    }
    return { lat: 24.7136, lng: 46.6753 } // fallback
  }, [center, apsNorm])

  // Only draw the estimated origin when the centre is valid.
  const showEstimated =
    Number.isFinite(Number((center as any)?.lat)) &&
    Number.isFinite(Number((center as any)?.lng))

  // Uncertainty circle radius (metres) derived from the confidence score.
  const radiusMeters =
    confidence >= 0.8 ? 25 :
    confidence >= 0.5 ? 50 :
    confidence >  0   ? 100 :
                        0

  if (apsNorm.length === 0) {
    return (
      <div className="text-center text-red-400 py-10">
        No access points to display. Check /map/ap-locations.
      </div>
    )
  }

  return (
    <div className="relative rounded-2xl overflow-hidden border border-white/10" style={{ height }}>
      {tilesFailed && (
        <div className="pointer-events-none absolute inset-x-0 top-0 z-[1000] px-3 py-2 text-center text-xs text-amber-300 bg-amber-950/80 border-b border-amber-500/40">
          Basemap tiles unavailable (no internet). Access points and the estimated
          origin are still plotted to scale.
        </div>
      )}

      <MapContainer
        center={[safeCenter.lat, safeCenter.lng]}
        zoom={zoom}
        style={{ height: "100%", width: "100%", background: "#0b1220" }}
        scrollWheelZoom
      >
        <TileLayer
          // Dark alternative: https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
          eventHandlers={{
            tileload: () => setTileState("ok"),
            tileerror: () => setTileState((s) => (s === "ok" ? s : "failed")),
          }}
        />

        {/* APs */}
        {apsNorm.map((ap) => {
          const key = String(ap.bssid || "").toUpperCase()
          const p = rssiByBssid.get(key)
          return (
            <Marker key={ap.bssid + ap.lat + ap.lng} position={[ap.lat, ap.lng]}>
              {/* Permanent label so APs stay identifiable without a basemap. */}
              <Tooltip direction="top" offset={[0, -38]} permanent>
                {ap.name || ap.bssid}
              </Tooltip>
              <Popup>
                <div className="space-y-1">
                  <div><strong>{ap.name || "AP"}</strong></div>
                  <div className="text-xs">BSSID: {ap.bssid}</div>
                  {p ? (
                    <>
                      <div className="text-xs">avg RSSI: {p.avg_rssi.toFixed(1)} dBm</div>
                      <div className="text-xs">samples: {p.n}</div>
                    </>
                  ) : (
                    <div className="text-xs text-gray-500">No RSSI samples for this access point.</div>
                  )}
                </div>
              </Popup>
            </Marker>
          )
        })}

        {/* Estimated source */}
        {showEstimated && (
          <CircleMarker
            center={[Number((center as any).lat), Number((center as any).lng)]}
            radius={10}
            pathOptions={{ weight: 2 }}
          >
            <Popup>
              <div className="space-y-1">
                <div><strong>Estimated Source</strong></div>
                <div className="text-xs">
                  lat: {Number((center as any).lat).toFixed(6)}, lng: {Number((center as any).lng).toFixed(6)}
                </div>
              </div>
            </Popup>
          </CircleMarker>
        )}

        {/* Uncertainty circle */}
        {showEstimated && radiusMeters > 0 && (
          <Circle
            center={[Number((center as any).lat), Number((center as any).lng)]}
            radius={radiusMeters}
            pathOptions={{ weight: 1, fillOpacity: 0.15 }}
          />
        )}

        {/* Lines from the estimated source to every AP that has an RSSI reading */}
        {showEstimated &&
          apsNorm.map((ap) => {
            const p = rssiByBssid.get(String(ap.bssid || "").toUpperCase())
            if (!p) return null
            return (
              <Polyline
                key={"ln-" + ap.bssid}
                positions={[
                  [Number((center as any).lat), Number((center as any).lng)],
                  [ap.lat, ap.lng],
                ]}
                pathOptions={{ weight: 1.5, opacity: 0.7 }}
              />
            )
          })}
      </MapContainer>
    </div>
  )
}
