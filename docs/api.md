# HawkShield — HTTP API

Every endpoint the FastAPI service exposes, with parameters and a real response captured from a
running instance.

* **Base URL** — `http://<pi-ip>:8000`. In production the dashboard is served from the same origin,
  so it calls `/attacks`, not an absolute URL.
* **No prefix.** Routes are registered flat: `/attacks`, not `/api/attacks`.
* **Interactive docs** — `GET /docs` (Swagger UI) and `GET /openapi.json`, both provided by FastAPI.
* **Content type** — every endpoint below returns `application/json` except `POST /reports/export`,
  which returns `application/pdf`.
* **Auth** — none. HawkShield binds to `0.0.0.0:8000` and has no authentication layer. Put it on a
  trusted network segment, or in front of a reverse proxy that does.

These shapes are **frozen**: the dashboard depends on the exact field names, including the legacy
ones (`wlan_sa`, `avg_rssi`). See [`CONTRACT.md` §4](CONTRACT.md).

---

## Endpoint index

| Method | Path | Router |
|---|---|---|
| GET | [`/health`](#get-health) | `health.py` |
| GET | [`/attacks`](#get-attacks) | `attacks.py` |
| GET | [`/packets/count`](#get-packetscount) | `attacks.py` |
| GET | [`/attacks/analysis`](#get-attacksanalysis) | `attacks.py` |
| GET | [`/top-offenders`](#get-top-offenders) | `attacks.py` |
| GET | [`/channel-usage`](#get-channel-usage) | `attacks.py` |
| GET | [`/heatmap-attack`](#get-heatmap-attack) | `attacks.py` |
| GET | [`/map/ap-locations`](#get-mapap-locations) | `maps.py` |
| GET | [`/map/source-rssi`](#get-mapsource-rssi) | `maps.py` |
| POST | [`/map/estimate-origin`](#post-mapestimate-origin) | `maps.py` |
| GET | [`/reports/summary`](#get-reportssummary) | `reports.py` |
| POST | [`/reports/export`](#post-reportsexport) | `reports.py` |
| POST | [`/ask`](#post-ask) | `ask.py` |
| GET | [static dashboard](#static-dashboard) | `StaticFiles` mount |

---

## GET `/health`

Liveness and readiness, **and which detection model the files on disk would give you**. Deliberately
dependency-free — it never imports the detector, model presence is a plain filesystem check, and the
v2 artefact is judged by reading its meta JSON rather than loading the graph. It never raises: a
database failure is reported, not thrown.

**Parameters:** none.

```bash
curl -s http://localhost:8000/health
```

```json
{
  "status": "ok",
  "database": true,
  "packets": 1,
  "latest_packet_ts": "2026-08-24T14:05:00",
  "models": { "stage1": true, "stage2": true, "v2": false },
  "model_version": "v1",
  "spec_version": "2.1.0",
  "artefact_spec_version": null,
  "model_problems": [],
  "version": "1.0.0"
}
```

| Field | Meaning |
|---|---|
| `status` | `"ok"` when the database is reachable **and** `model_version` is not `"none"`; otherwise `"degraded"` |
| `database` | a `COUNT(*)` against `packets` succeeded |
| `packets` | total persisted attack rows (`0` on a healthy but idle system) |
| `latest_packet_ts` | ISO-8601, or `null` when the table is empty |
| `models.stage1` / `.stage2` | `MODEL_DIR/STAGE1_MODEL` and `MODEL_DIR/STAGE2_MODEL` exist on disk |
| `models.v2` | the v2 ONNX **and** its meta exist **and** the meta matches the running `feature_spec` |
| `model_version` | `"v2"` \| `"v1"` \| `"none"` — what the detector *would* load, honouring `MODEL_VERSION` |
| `spec_version` | the feature contract **this build of the code** implements, e.g. `"2.1.0"` |
| `artefact_spec_version` | the spec version the on-disk v2 artefact claims, or `null` when there is none |
| `model_problems` | why `models.v2` is `false` when a v2 artefact is present but unusable; `[]` otherwise |
| `version` | `APP_VERSION` from `backend/app/config.py` |

`status` is always HTTP **200**, including when degraded — read the body, not the status line.

> **`model_version` is advisory.** This endpoint runs in the API process, which does no inference, so
> it reports what the *files* imply. The detector's own startup line — `ACTIVE MODEL: v2 (causal TCN,
> ONNX) spec=…` or `ACTIVE MODEL: v1 (two-stage LightGBM) …` — is authoritative. The two disagree only
> if the artefacts changed after the detector started, which is itself worth noticing.

> **Expected today:** `models.v2` is `false`, `artefact_spec_version` is `null` and `model_version` is
> `"v1"`, because no trained v2 artefact exists in this repository yet. `spec_version` still reports
> `"2.1.0"` — that is the contract the *code* implements, not a claim that a matching model exists.
> When `spec_version` and `artefact_spec_version` differ, `models.v2` is `false` and `model_problems`
> says exactly why.

---

## GET `/attacks`

Raw dump of the `packets` table, newest first. This is the endpoint the dashboard's attack table and
most charts are built on.

| Parameter | Type | Default | Range |
|---|---|---|---|
| `limit` | int | `5000` | 1 – 100000 |
| `offset` | int | `0` | ≥ 0 |

Out-of-range values return **422** with FastAPI's standard validation body.

Implemented as a raw `SELECT * FROM packets ORDER BY id DESC`, so a column added to the model appears
in the response without a code change. A normalisation pass makes the JSON identical across drivers
(psycopg2 hands back a `dict`/`datetime` for `raw`/`ts`; SQLite hands back TEXT).

```bash
curl -s "http://localhost:8000/attacks?limit=2&offset=0"
```

```json
[
  {
    "id": 1,
    "ts": "2026-08-24T14:05:00",
    "iface": "wlan1",
    "src_mac": "9c:b6:d0:1f:44:a2",
    "dst_mac": "ff:ff:ff:ff:ff:ff",
    "bssid": "e8:9f:80:3c:12:70",
    "frame_len": 39,
    "channel_freq": 2437,
    "datarate": 1.0,
    "signal_dbm": -47.0,
    "wlan_ds": 0,
    "wlan_retry": 0,
    "wlan_type": 0,
    "wlan_subtype": 12,
    "wlan_duration": 0,
    "proba_anomaly": 0.9731,
    "proba_attack": 0.8842,
    "predicted_label": "Deauth",
    "raw": {
      "iface": "wlan1",
      "sa": "9c:b6:d0:1f:44:a2",
      "da": "ff:ff:ff:ff:ff:ff",
      "bssid": "e8:9f:80:3c:12:70",
      "len": 39,
      "type": 0,
      "subtype": 12,
      "rate": 1.0,
      "sig": -47.0,
      "ssid": null
    }
  }
]
```

Notes:

* `proba_anomaly` is the "is this an attack at all" score and `proba_attack` the confidence in
  `predicted_label`. Under v1 those are the stage-1 and stage-2 probabilities; under v2 they are
  `1 − P(Normal)` and `P(predicted_label)` from the single network. Both are always ≥
  `STAGE1_THRESHOLD` / `STAGE2_THRESHOLD`, or the row would not exist.
* `wlan_duration` from a **v1** detector is byte-swapped — scapy declares the 802.11 Duration/ID field
  big-endian while the header is little-endian, so 314 µs was recorded as 14849. Fixed for v2; historical
  rows are not.
* `ts` is set by the detector at classification time, in UTC. On PostgreSQL the offset is included
  (`2026-08-24T14:05:00+00:00`); the SQLite example above is naive.
* `raw` holds the identity fields the model was never allowed to see, plus the parsed SSID when the
  frame was a beacon or probe.
* Every column except `id` is nullable — a frame that did not carry a field yields `null` here.

---

## GET `/packets/count`

Total persisted attack rows. Cheap; safe to poll.

```bash
curl -s http://localhost:8000/packets/count
```

```json
{ "count": 1 }
```

Remember this counts **attacks only** — normal traffic is classified and dropped, never stored.

---

## GET `/attacks/analysis`

Count per `predicted_label`. **All eight attack keys are always present**, zero-filled, so the
dashboard never has to branch on a missing category. Labels outside the eight are ignored, and
`Normal` is never a key — only attacks are persisted.

The keys and their order are **derived from `feature_spec.ATTACK_CLASSES`**, not hand-maintained, so
a class added to the spec appears here with no code change. v2 added `Disas` and `Kr00k` to v1's six.

```bash
curl -s http://localhost:8000/attacks/analysis
```

```json
{
  "Deauth": 1,
  "Disas": 0,
  "(Re)Assoc": 0,
  "RogueAP": 0,
  "Krack": 0,
  "Kr00k": 0,
  "Evil_Twin": 0,
  "SSDP": 0
}
```

> **A v1 rendering bug worth knowing about if you have historical screenshots.** The dashboard used
> to render every `(Re)Assoc` row as `SSDP` — an alias table round-tripped a key through its display
> string and never closed the loop, falling back to the first allowed type. **Any SSDP figure read
> off the attacks page before that fix was inflated**, and `(Re)Assoc` understated. This endpoint's
> JSON was always correct; only the rendering was wrong.

---

## GET `/top-offenders`

Source MACs by frame count, descending. Rows with a null `src_mac` are dropped.

> The key is **`wlan_sa`**, not `src_mac`. This is a legacy name the frontend depends on; do not
> "fix" it.

```bash
curl -s http://localhost:8000/top-offenders
```

```json
[
  { "wlan_sa": "9c:b6:d0:1f:44:a2", "count": 1 }
]
```

Unbounded — it returns one entry per distinct source MAC in the table.

---

## GET `/channel-usage`

Frame counts per RadioTap frequency (MHz), descending. Rows with a null `channel_freq` are dropped.

```bash
curl -s http://localhost:8000/channel-usage
```

```json
[
  { "channel_freq": 2437, "count": 1 }
]
```

`2437` is 2.4 GHz channel 6, the default capture channel.

---

## GET `/heatmap-attack`

Week × hour intensity grid built from `packets.ts`. Always exactly 7 entries of 24 hours, zero-filled,
**Sunday first** — which is the order the frontend heatmap renders, not `datetime.weekday()` order.

```bash
curl -s http://localhost:8000/heatmap-attack
```

```json
[
  {
    "day": "Sun",
    "hours": [
      { "hour": 0, "intensity": 0 },
      { "hour": 1, "intensity": 0 },
      "… 24 entries, hour 0 through 23 …"
    ]
  },
  { "day": "Mon", "hours": ["…"] },
  "… Tue, Wed, Thu, Fri, Sat …"
]
```

Bucketing is in **UTC**. Naive timestamps are treated as UTC. Note that this aggregates the whole
table in Python — it is fine for an attack log, but it is not a windowed query.

---

## GET `/map/ap-locations`

The configured access-point inventory, read from `AP_LOCATIONS_FILE` (default
`backend/config/ap_locations.json`) on every request, so edits take effect without a restart.

```bash
curl -s http://localhost:8000/map/ap-locations
```

```json
[
  { "bssid": "AA:AA:AA:AA:AA:01", "name": "AP-1", "lat": 24.7136, "lng": 46.6753 },
  { "bssid": "AA:AA:AA:AA:AA:02", "name": "AP-2", "lat": 24.7139, "lng": 46.6758 },
  { "bssid": "AA:AA:AA:AA:AA:03", "name": "AP-3", "lat": 24.7142, "lng": 46.6751 }
]
```

The shipped file is **placeholder data** — three APs at coordinates in Riyadh. Replace it with your
own BSSIDs and positions before the map means anything.

Degrades rather than fails: a missing file, malformed JSON, or a non-list top level all return `[]`
with a warning in the log. A single malformed entry is skipped; the rest are returned. The file may
also be an object with an `"aps"` key.

---

## GET `/map/source-rssi`

Average signal strength per BSSID for one source MAC, over a recent time window. This is the input to
origin estimation.

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `sa` | string | — | **required**; source MAC, matched against `packets.src_mac` |
| `minutes` | int | `10` | look-back window ending now |

```bash
curl -s "http://localhost:8000/map/source-rssi?sa=9c:b6:d0:1f:44:a2&minutes=10"
```

```json
{ "sa": "9c:b6:d0:1f:44:a2", "points": [] }
```

With frames inside the window:

```json
{
  "sa": "9c:b6:d0:1f:44:a2",
  "points": [
    { "bssid": "e8:9f:80:3c:12:70", "avg_rssi": -47.0, "n": 132 },
    { "bssid": "e8:9f:80:3c:12:71", "avg_rssi": -68.5, "n": 44 }
  ]
}
```

`avg_rssi` is the mean of `packets.signal_dbm` (the strongest antenna chain), `n` the number of frames
it averages. An unknown MAC or an empty window returns `points: []`, not a 404. Averaging is over
persisted **attack** frames only.

---

## POST `/map/estimate-origin`

Rough position estimate for a source MAC: the centroid of the supplied AP coordinates, weighted by
`1 / (|avg_rssi| + 1)` so stronger signals pull harder. It is a coarse heuristic, not trilateration —
the `method` field says so.

**Request**

```json
{
  "sa": "9c:b6:d0:1f:44:a2",
  "minutes": 10,
  "ap_locations": [
    { "bssid": "e8:9f:80:3c:12:70", "name": "AP-1", "lat": 24.7136, "lng": 46.6753 }
  ]
}
```

`ap_locations` is passed in by the caller (the dashboard forwards what `/map/ap-locations` gave it);
the endpoint does not read the file itself.

**Response — no overlap between the supplied APs and the RSSI window**

```json
{
  "sa": "9c:b6:d0:1f:44:a2",
  "method": "weighted-centroid",
  "used": 0,
  "center": null,
  "note": "No matching RSSI/AP pairs in the selected window."
}
```

**Response — success**

```json
{
  "sa": "9c:b6:d0:1f:44:a2",
  "method": "weighted-centroid",
  "used": 3,
  "center": { "lat": 24.713873, "lng": 46.675402 }
}
```

`used` is how many APs contributed — those present in **both** the request body and the RSSI window.
APs with unusable coordinates are skipped with a warning. A missing `sa` or an empty `ap_locations`
returns `{"detail": "Missing sa or ap_locations"}` with HTTP **200**, not a 4xx.

---

## GET `/reports/summary`

Totals by attack type plus headline figures for a look-back window.

| Parameter | Type | Default |
|---|---|---|
| `days` | int | `30` |

```bash
curl -s "http://localhost:8000/reports/summary?days=30"
```

```json
{
  "period": "Last 30 day(s)",
  "totals": {
    "deauth": 1,
    "ssdp": 0,
    "evil_twin": 0,
    "reassoc": 0,
    "rogueap": 0,
    "krack": 0,
    "disas": 0,
    "kr00k": 0,
    "other": 0
  },
  "summary": {
    "totalAttacks": 1,
    "mostFrequentType": "deauth",
    "peakHour": 14,
    "uniqueSources": 1
  }
}
```

The `totals` keys are **lower-case frontend names**, not the DB labels. The mapping is *derived* from
`feature_spec.ATTACK_CLASSES` by `backend/app/config.py` — lower-case, punctuation dropped — rather
than hand-maintained, so a class added to the spec appears here automatically. The six v1 keys keep
their historical positions; v2 appends `disas` and `kr00k`:

| DB label | `totals` key |
|---|---|
| `Deauth` | `deauth` |
| `SSDP` | `ssdp` |
| `Evil_Twin` | `evil_twin` |
| `(Re)Assoc` | `reassoc` |
| `RogueAP` | `rogueap` |
| `Krack` | `krack` |
| `Disas` | `disas` |
| `Kr00k` | `kr00k` |
| anything else, incl. `null` | `other` |

`(Re)Assoc` maps to plain `reassoc` — punctuation is dropped, not escaped, so no key ever needs URL-
or JSON-quoting. The `other` bucket catches labels the current spec does not define, which is where
v1 rows left in the table after a v2 upgrade land.

`peakHour` is a UTC hour 0–23 (`0` when there is nothing in the window). `mostFrequentType` is
`"other"` when the window is empty. `uniqueSources` counts distinct `src_mac`.

---

## POST `/reports/export`

The same summary rendered as a one-page A4 PDF by ReportLab, streamed as an attachment.

**Request**

```json
{ "days": 30 }
```

**Response**

```
200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="hawkshield_report_30d.pdf"
```

```bash
curl -s -X POST http://localhost:8000/reports/export \
     -H 'Content-Type: application/json' \
     -d '{"days":7}' -o report.pdf
```

The page contains the period, totals by type (the eight labels plus `other`), and the four headline
figures. It is generated in memory — nothing is written to disk on the Pi.

---

## POST `/ask`

Natural-language question over the `packets` table and a bundled attack knowledge base, answered by a
model hosted on [OpenRouter](https://openrouter.ai) (default `deepseek/deepseek-v4-flash`).
**Optional**: with no `OPENROUTER_API_KEY`, this endpoint — and only this endpoint — is unavailable.

**Request**

```json
{ "question": "how many deauth attacks today?", "session_id": "dash-1" }
```

`session_id` is optional and defaults to `"default-session"`. The last 5 turns of a session are
prepended to the question as context, and answers are cached for 600 s (200 entries, keyed on
`sha256(session_id || question)`).

**Response — 200, `SQL` mode**

```json
{
  "cached": false,
  "mode": "SQL",
  "sql": "SELECT COUNT(*) AS n FROM packets WHERE predicted_label = 'Deauth' AND ts >= NOW() - INTERVAL '1 day' LIMIT 500",
  "answer": "There were 1 deauthentication frames flagged in the last 24 hours.",
  "cols": ["n"],
  "rows": [{ "n": 1 }],
  "error": null
}
```

**Response — 503, no API key** (verified):

```json
{ "detail": "OPENROUTER_API_KEY is not configured; the assistant is disabled." }
```

| Field | Meaning |
|---|---|
| `cached` | the answer came from the TTL cache; the rest of the object is the cached response |
| `mode` | `SQL` — a query was generated and run · `DOCS` — answered from the knowledge base · `OOS` — out of scope · `ERROR` — generation or execution failed |
| `sql` | the generated query (`""` for `DOCS` / `OOS`) |
| `answer` | prose answer; humanised by a second model call when `HUMANIZE_SQL=1`, otherwise a deterministic template |
| `cols` / `rows` | the result set (empty for `DOCS` / `OOS`) |
| `error` | present only in `ERROR` mode |

Safety rails, all env-tunable: generated SQL must be a **single read-only `SELECT`**; an unbounded
`SELECT` gets a `LIMIT` appended (`RAG_MAX_ROWS`, default 500); on PostgreSQL every query runs under a
`statement_timeout` (`RAG_SQL_TIMEOUT_MS`, default 15000 ms). The knowledge base is
`backend/app/rag/knowledge/attacks.md`, overridable with `ATTACKS_FILE`.

An `ERROR` mode is still HTTP **200** with the message in `error`. A **500** means an unhandled
failure — check `journalctl -u hawkshield-api`.

### The SQL matches the database

`/ask` is dialect-aware. `packet_qa._sql_dialect()` reads `DATABASE_URL` and picks the notes that go
into the system prompt, so the model writes **PostgreSQL** on the Pi and **SQLite** on a laptop demo
(where `run.py` falls back to a local file). The executor follows: SQLite runs through the app's
SQLAlchemy engine, PostgreSQL through `psycopg` with the statement timeout applied.

| | PostgreSQL | SQLite |
|---|---|---|
| last 24 h | `ts >= NOW() - INTERVAL '24 hours'` | `ts >= datetime('now', '-24 hours')` |
| today | `ts >= date_trunc('day', NOW())` | `ts >= date('now')` |
| hour bucket | `date_trunc('hour', ts)`, `EXTRACT(HOUR FROM ts)` | `strftime('%H', ts)` |
| JSON | `raw->>'ssid'` | `json_extract(raw, '$.ssid')` |
| cast | `(raw->>'sig')::float` | `CAST(x AS REAL)` |

Verified on the SQLite demo database: the model emitted `datetime('now', '-24 hours')`, not the
PostgreSQL form, which would have failed outright.

### Configuration

| Variable | Default | Notes |
|---|---|---|
| `OPENROUTER_API_KEY` | *(empty)* | empty ⇒ this endpoint is 503. Keys: <https://openrouter.ai/keys> |
| `GEN_MODEL` | `deepseek/deepseek-v4-flash` | alternatives: `z-ai/glm-5.3-flash`, `qwen/qwen3.7-flash` (cheapest), `qwen/qwen3-235b-a22b-2507` (largest) |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | change only for a proxy or a self-hosted OpenAI-compatible API |
| `OPENROUTER_SITE_URL` / `OPENROUTER_APP_NAME` | repo URL / `HawkShield` | attribution headers OpenRouter shows on its dashboard |
| `HUMANIZE_SQL` | `1` | `0` ⇒ deterministic template answers, one fewer model call |
| `RAG_MAX_ROWS` | `500` | `LIMIT` appended to unbounded `SELECT`s |
| `RAG_SQL_TIMEOUT_MS` | `15000` | PostgreSQL `statement_timeout` |
| `ATTACKS_FILE` | *(empty = packaged)* | knowledge-base override |

### Pre-flight: `check_rag.py`

Run this before you demo `/ask`. It exercises the whole path so a failure tells you *which* part is
broken, instead of a 503 or an `ERROR` mode with no context.

```bash
python backend/scripts/check_rag.py
python backend/scripts/check_rag.py --skip-db     # model only; generate the SQL, do not run it
```

| Step | Checks |
|---|---|
| configuration | `OPENROUTER_API_KEY` is set and a client can be built |
| catalogue | `GEN_MODEL` exists on OpenRouter; prints its context length and live per-million price |
| `DOCS` mode | a knowledge-base question comes back with a real answer, routed as `DOCS` |
| `SQL` mode | a text-to-SQL question is routed as `SQL` and produces a query |
| execution | that query runs against the live database and is humanised |

| Exit | Meaning |
|---|---:|
| `0` | `POST /ask` will work |
| `2` | no key, or `GEN_MODEL` is not a real OpenRouter model id (it suggests near matches) |
| `3` | the `DOCS` call failed or returned an empty answer |
| `4` | the `SQL` call misrouted, failed to generate, or the query would not execute |

An exit of `4` with a database error means the model is fine and your database is not — re-run with
`--skip-db` to confirm.

---

## Static dashboard

When `FRONTEND_DIST` (default `<repo>/frontend/out`) exists, it is mounted at `/` with
`StaticFiles(html=True)` **after** all API routes, so the catch-all can never shadow an endpoint.

| Path | Serves |
|---|---|
| `/` | `index.html` — client-side redirect to `/home` |
| `/home/` `/dashboard/` `/attacks/` `/rag/` | the four dashboard pages |
| `/_next/static/…` | JS/CSS bundles |
| `/leaflet/marker-icon.png` etc. | committed Leaflet marker images, so the map works offline |

The export uses `trailingSlash: true`, which is what the `html=True` mount expects. Verified:
`/`, `/home/`, `/dashboard/`, `/attacks/`, `/rag/` return **200 `text/html`** and
`/leaflet/marker-icon.png` returns **200 `image/png`**.

If the directory is absent the mount is skipped entirely: the API starts and works, and the dashboard
paths 404. Note the ordering consequence — with no frontend mounted, an unknown path is a normal
FastAPI 404; with one mounted, it is the export's `404.html`.

---

## Removed endpoints

Two endpoints that existed in the original codebase are **gone and will not come back**. If you find
a reference to either, it is stale.

| Removed | Why |
|---|---|
| `POST /detector/start` | The detector is a systemd service (`hawkshield-detector.service`), not an HTTP-controlled subprocess. Starting a root-privileged sniffer from an unauthenticated web request was never defensible. Use `systemctl start hawkshield-detector`. |
| `POST /reports/email` | It was a stub. It returned a note and never sent an email — there is no SMTP configuration, no mail client, and no alerting path anywhere in the codebase. Use `POST /reports/export` and send the PDF yourself. |

Email/webhook alerting is listed under Roadmap in the [root README](../README.md); it is not
implemented.

---

## Errors

| Status | When |
|---|---|
| **200** | success — including `/ask` in `ERROR` mode and `/map/estimate-origin` with nothing to estimate |
| **422** | request validation failed (e.g. `limit=0`, `limit=200000`, a missing `question`) — FastAPI's standard body |
| **404** | unknown path; served by the static export's `404.html` when a frontend is mounted |
| **500** | unhandled server error — read `journalctl -u hawkshield-api -n 50` |
| **503** | `/ask` only: no `OPENROUTER_API_KEY`, or the RAG module failed to import |

There is no rate limiting and no authentication. `/attacks` with `limit=100000` will happily build a
100 000-row JSON array on a Raspberry Pi; page it.
