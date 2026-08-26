# HawkShield — Frontend

Next.js 15 (App Router) / React 19 / Tailwind v4 dashboard for the HawkShield WiFi
intrusion detection system.

It is built as a **fully static export**. In production there is no Node process:
`next build` writes `frontend/out/`, and the FastAPI service on the Raspberry Pi
serves that directory at `/`. The UI therefore calls the API **same-origin**
(`/attacks`, `/ask`, …) — no CORS, no proxy, no second web server.

See `docs/CONTRACT.md` §1 (topology) and §4 (the frozen HTTP contract).

---

## Pages

| Route | File | Talks to |
|---|---|---|
| `/` | `app/page.tsx` | — (client redirect to `/home`) |
| `/home` | `app/(app)/home/page.tsx` | — |
| `/dashboard` | `app/(app)/dashboard/page.tsx` | `/attacks`, `/attacks/analysis`, `/heatmap-attack`, `/map/*` |
| `/attacks` | `app/(app)/attacks/page.tsx` | `/attacks`, `/reports/summary`, `/reports/export` |
| `/rag` | `app/(app)/rag/page.tsx` | `/ask` |

---

## Configuration

One variable, documented in `.env.example`:

| Variable | Value | Meaning |
|---|---|---|
| `NEXT_PUBLIC_API_BASE` | *(empty / unset)* | **Production default.** Same-origin — requests go to `/attacks`, etc. |
| | `http://<pi-ip>:8000` | Laptop dev against the API running on the Pi. |
| | `http://localhost:8000` | Laptop dev with the API running locally. |

It is read in exactly one place, `lib/api.ts`, which exports:

- `API_BASE` — the normalised base (trailing slashes stripped);
- `apiUrl(path)` — path → full URL;
- `apiFetch(path, init?)` — `fetch` that throws `ApiError` on non-2xx, returns the raw `Response` (used for the PDF export blob);
- `apiFetchJson<T>(path, init?)` — the same plus JSON parsing;
- `apiPostJson<T>(path, body, init?)` — JSON POST;
- `apiFetchSafe<T>(path, fallback, init?)` — never throws; returns `fallback` on any error so the dashboard/map render an empty state instead of crashing when the backend is down.

> `NEXT_PUBLIC_*` values are **inlined at build time**. Changing one requires a
> rebuild (or a `next dev` restart) — it is not read at runtime.

---

## Development against a Pi

```bash
cd frontend
npm install
cp .env.example .env.local
# edit .env.local:  NEXT_PUBLIC_API_BASE=http://192.168.1.42:8000
npm run dev            # http://localhost:3000
```

The Pi's API must allow the dev origin — its `CORS_ORIGINS` needs to include
`http://localhost:3000` (see `docs/CONTRACT.md` §3).

`.env.local` is git-ignored; never commit it.

---

## Production build (static export)

```bash
cd frontend
npm install
npm run build          # -> frontend/out/
```

**Make sure `frontend/.env.example` is the only env file present, or that
`.env.local` sets `NEXT_PUBLIC_API_BASE=` (empty).** A leftover
`NEXT_PUBLIC_API_BASE=http://localhost:8000` gets baked into the JS bundle and the
deployed UI will try to reach the browser's own machine instead of the Pi. Verify
with:

```bash
grep -r "localhost:800" out | wc -l    # must be 0
```

The export contains a directory-per-route (`trailingSlash: true`), which is what
FastAPI's `StaticFiles(..., html=True)` mount expects:

```
frontend/out/
├── index.html            # /  -> redirects to /home
├── home/index.html
├── dashboard/index.html
├── attacks/index.html
├── rag/index.html
├── 404.html
├── leaflet/              # marker PNGs, bundled for offline use
└── _next/static/…
```

FastAPI reads this path from `FRONTEND_DIST` (default `<repo>/frontend/out`).

Copy the whole `out/` directory to the Pi, or run `npm run build` there.

---

## Map / offline behaviour

`components/LeafletMap.tsx` renders AP locations and the trilaterated attack
origin.

- **Marker images are local.** The three Leaflet PNGs are committed to
  `public/leaflet/` (copied from `node_modules/leaflet/dist/images/`), so markers
  render with no internet access. If Leaflet is ever upgraded, re-copy them.
- **Basemap tiles still need internet.** They come from OpenStreetMap and are not
  bundled (tile sets are gigabytes). When tiles fail to load the map shows a
  "Basemap tiles unavailable" banner and keeps working: AP markers carry permanent
  name labels, and the estimated-origin marker, uncertainty circle and AP lines
  are all still drawn to scale on a dark background.

---

## Checks

```bash
npx tsc --noEmit    # clean
npm run lint        # 0 errors, 37 warnings (35 × no-explicit-any, 1 hook dep, 1 <img>)
```

The API responses are loosely typed on purpose — the backend returns raw `packets`
rows with several legacy field aliases — so `@typescript-eslint/no-explicit-any` is
configured as a warning rather than a build-breaking error in `eslint.config.mjs`.

On a memory-constrained machine, prefix with
`NODE_OPTIONS=--max-old-space-size=4096`.
