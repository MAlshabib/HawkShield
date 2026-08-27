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
| GET | `/attacks/series` | `attacks.py` — zero-filled time series. See `docs/CONTRACT.md` section 4 |
| GET | [`/map/ap-locations`](#get-mapap-locations) | `maps.py` |
| GET | [`/map/source-rssi`](#get-mapsource-rssi) | `maps.py` |
| POST | [`/map/estimate-origin`](#post-mapestimate-origin) | `maps.py` |
| GET | [`/reports/summary`](#get-reportssummary) | `reports.py` |
| POST | [`/reports/export`](#post-reportsexport) | `reports.py` |
| POST | [`/ask`](#post-ask) | `ask.py` |
| POST | `/agent/ask` | `agent.py` — the Saqr agent; JSON or SSE. See `docs/CONTRACT.md` section 10 |
| GET | `/agent/tools` | `agent.py` — the tool catalogue the UI builds its labels from |
| POST | [`/simulate`](#post-simulate) | `simulate.py` |
| GET | [`/stream`](#get-stream) | `stream.py` |
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

> **Expected today:** `model_version` is `"v2-gbdt"` — the LightGBM model won the held-out
> head-to-head (0.9907 vs the TCN's 0.9856), so `auto` selects it. `spec_version` and
> `artefact_spec_version` both report `"2.1.0"`. When they differ, the artefact is refused,
> `model_version` falls back, and `model_problems` says exactly why — a mismatched model is never
> served silently, which is the failure v1 shipped with.

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

A thin shim over the Saqr agent. It predates the agent and the already-built `frontend/out` bundle calls
it, so the route and its envelope survive; everything behind it is now the same loop, the same eight
tools and the same guards that serve `POST /agent/ask`. The text-to-SQL RAG that used to back it
(`backend/app/rag/packet_qa.py`) was deleted — see `docs/CONTRACT.md` section 10.8.

```bash
curl -s -X POST localhost:8000/ask -H 'content-type: application/json'   -d '{"question":"how many Deauth attacks in the last 24 hours?","session_id":"demo"}'
```

```json
{
  "cached": false,
  "mode": "SQL",
  "sql": "SELECT packets.predicted_label AS \"key\", count(packets.id) AS count FROM packets GROUP BY ...",
  "answer": "Deauth is the most frequent detected class, with 42 frames in the window.",
  "cols": ["key", "count"],
  "rows": [{"key": "Deauth", "count": 42}],
  "error": null
}
```

| Field | Meaning |
|---|---|
| `cached` | served from the TTL cache (200 entries / 600 s, key = sha256 of `session_id\|\|question`) |
| `mode` | `SQL` \| `DOCS` \| `OOS` \| `ERROR` — see below |
| `sql` | the last tabular tool's real `SELECT`, values inlined; `""` when no tool ran SQL |
| `answer` | the prose answer |
| `cols` / `rows` | the last tabular result; `rows` are objects keyed by column name |
| `error` | `null` on success; a string when the run failed (`mode` is then `ERROR`) |

**`mode` is derived from which tools actually executed**, never from anything the model says about itself:
`SQL` when any tool that reads packet data ran, `DOCS` when only `explain_attack_class` ran, `OOS` when no
tool ran, `ERROR` on failure. That matters because the shipped dashboard branches on the literal string
`"SQL"` and only that branch renders the rows table — a wrong `mode` shows a plausible answer with the
table silently missing. `backend/scripts/check_frontend.py` asserts it.

An `ERROR` mode is still HTTP **200** with the message in `error`. **503** means no `OPENROUTER_API_KEY`
or `SAQR_ENABLED=0`. A **500** means an unhandled failure — check `journalctl -u hawkshield-api`.

### What it can reach

Only the `packets` table. Every statement the agent runs — including the `run_sql` escape hatch — must be
a single `SELECT`/`WITH`, may name only `packets` and CTEs defined in the same statement, is row-capped by
`SAQR_MAX_ROWS` and, on PostgreSQL, bounded by `SAQR_SQL_TIMEOUT_MS`. `documents`, `sqlite_master`,
`pg_catalog.*` and `information_schema.*` are unreachable. (The old RAG path enforced SELECT-only but had
no table allow-list; that gap closed when `/ask` was flipped.)

The knowledge base is still `backend/app/rag/knowledge/attacks.md`, overridable with `ATTACKS_FILE`.

### Configuration

`/ask` and `/agent/ask` share one configuration block — see `docs/CONTRACT.md` section 3 for the full
table. The ones that matter here:

| Variable | Default | Notes |
|---|---|---|
| `OPENROUTER_API_KEY` | *(empty)* | empty ⇒ this endpoint is 503. Keys: <https://openrouter.ai/keys> |
| `SAQR_ENABLED` | `1` | `0` ⇒ both `/ask` and `/agent/*` answer 503 |
| `SAQR_MODEL` | *(empty ⇒ `GEN_MODEL`)* | must be a tool-calling model |
| `SAQR_MAX_ROWS` | `500` | `LIMIT` appended to unbounded `SELECT`s (`RAG_MAX_ROWS` is a deprecated alias) |
| `SAQR_SQL_TIMEOUT_MS` | `15000` | PostgreSQL `statement_timeout` (`RAG_SQL_TIMEOUT_MS` is a deprecated alias) |
| `SAQR_ALLOW_RAW_SQL` | `1` | publish the guarded `run_sql` tool, so eight tools rather than seven |
| `ATTACKS_FILE` | *(empty = packaged)* | knowledge-base override |

`/ask` has no rate limit and no concurrency gate, matching its historical behaviour; `/agent/ask` has both.

### Pre-flight

```bash
python backend/scripts/check_saqr.py        # the assistant end to end (needs a key + network)
python backend/scripts/check_frontend.py    # the shipped frontend/out build against this backend
```

`check_saqr.py` verifies key → model exists in the OpenRouter catalogue → it advertises `tools` → a live
one-tool round-trip. `check_frontend.py` is the go/no-go gate for the built bundle and asserts this exact
envelope, including `mode == "SQL"`. Both exit `0` on success and name what broke otherwise; both degrade
to a clear "not verified" block with no API key. See `docs/CONTRACT.md` section 8.6.

## POST `/simulate`

Replay held-out AWID3 frames through the **real** detector pipeline and persist whatever it actually
flags. This is the testing / demo control — it does **not** fabricate detections. It loads
`data/sim/awid3_sim_corpus.parquet` (real, held-out AWID3 feature rows), pushes them through the same
`build_pipeline` the live detector runs, and writes results through the same `PacketSink`, so the
`packets` schema is untouched. Operator runbook: [`docs/demo.md`](demo.md). Design and corpus rationale:
[`CONTRACT.md` §9](CONTRACT.md), [`data/sim/README.md`](../data/sim/README.md).

**Body**

```json
{ "attacks": "all", "count": 25, "intensity": "burst" }
```

| Field | Type | Meaning |
|---|---|---|
| `attacks` | `"all"` \| `[str]` | `"all"` expands to every attack class in the corpus (**eight**). A list may mix class names and frontend keys (`"deauth"`, `"Kr00k"`, …). Default `"all"`. |
| `count` | int | Target *persisted detections per class*. Schema-bounded `1..10000`, then hard-capped at `SIM_MAX_COUNT` (default **500**). Default `50`. |
| `intensity` | `"burst"` \| `"trickle"` | `burst` runs flat out; `trickle` inserts a small pause (~20 ms per replay pass) so a live tail visibly ticks. Cosmetic — it does not change the result. Default `burst`. |

**Response** — nested. `per_class` reports what the model **did**, not what was asked, so an
under-detecting class shows in the numbers.

```json
{
  "sim_batch": "9f3c1a…",
  "model_version": "v2-gbdt",
  "intensity": "burst",
  "classes": ["Deauth", "Disas", "(Re)Assoc", "RogueAP", "Krack", "Kr00k", "Evil_Twin", "SSDP"],
  "count_per_class": 25,
  "total_persisted": 200,
  "per_class": {
    "Deauth": {
      "requested": 25, "frames_pushed": 344, "detected": 25,
      "persisted": 25, "top_label": "Deauth", "labels": {"Deauth": 25}
    }
  }
}
```

| Field | Meaning |
|---|---|
| `sim_batch` | hex uuid stamped on every row of this run as `raw.sim_batch` |
| `model_version` | the pipeline that scored the frames (`v2-gbdt` \| `v2-tcn` \| `v1`) |
| `count_per_class` | the effective per-class target after the `SIM_MAX_COUNT` cap |
| `total_persisted` | sum of `persisted` across classes |
| `per_class[cls].requested` | the per-class target |
| `per_class[cls].frames_pushed` | corpus frames replayed to reach it |
| `per_class[cls].detected` | frames that cleared both thresholds (a real label) |
| `per_class[cls].persisted` | rows written to `packets` |
| `per_class[cls].top_label` | most common label assigned |
| `per_class[cls].labels` | full `{label: count}` breakdown |

**The persisted rows.** Each is written through the detector's own `PacketSink` and carries, in the
`packets.raw` JSON column, `sim = true`, `sim_batch = <uuid>`, `sim_class`, plus locally-administered
synthetic MACs (`02:5a:11:…`). They are indistinguishable from real detections in the normal UI shape
(because they *are* real model output) yet trivially filtered or purged:

```sql
DELETE FROM packets WHERE json_extract(raw,'$.sim') = 1;   -- SQLite
DELETE FROM packets WHERE raw->>'sim' = 'true';            -- PostgreSQL
```

**Status codes**

| Status | When |
|---|---|
| **200** | run completed; the body reports what was persisted |
| **400** | an unknown class name in `attacks` |
| **403** | `ALLOW_SIMULATION=0` — simulation is disabled |
| **429** | rate limit — more than 30 calls in 60 s |
| **503** | no model can load, or the corpus is missing/unreadable (same posture as `/ask`) |

Verified live against the committed corpus: `attacks: "all"`, all eight classes returned
`persisted == requested`, every `top_label` correct.

---

## GET `/stream`

Server-Sent Events — one event per new `packets` row, live, without polling the REST endpoints. A
dashboard (or `curl -N`) opens it once and receives each detection as it lands. Used by the dashboard
to upgrade its live feed; it falls back to polling on error.

**Query**

| Param | Default | Meaning |
|---|---|---|
| `since_id` | `-1` | Resume after this packet id. `-1` (or any negative) starts from the current tail, so a fresh listener only sees genuinely new rows. A non-negative value replays every row after that id. |

**Response** — `text/event-stream`. The stream opens with a `hello` event carrying the resume
boundary, then one `data:` event per row, and an SSE keep-alive comment while idle.

```
event: hello
data: {"since_id": 4021}

data: {"id": 4022, "ts": "2026-08-27T09:41:02.117000", "predicted_label": "Deauth", "p1": 0.998, "p2": 0.994, "src_mac": "02:5a:11:…", "bssid": "02:5a:11:…", "sim": true}

: keep-alive
```

| Field | Meaning |
|---|---|
| `id` | `packets.id` |
| `ts` | classification timestamp, ISO 8601 |
| `predicted_label` | attack class |
| `p1` / `p2` | the two model probabilities (`proba_anomaly` / `proba_attack`) |
| `src_mac` / `bssid` | 802.11 addresses |
| `sim` | `true` for a row written by `POST /simulate` |

The endpoint polls `MAX(packets.id)` server-side, opens a short session per poll (never holding one
open across the wait), stops on client disconnect, and sends `X-Accel-Buffering: no` so a reverse
proxy does not buffer events. It works same-origin through the static mount, so the browser needs no
CORS preflight.

---

## Static dashboard

When `FRONTEND_DIST` (default `<repo>/frontend/out`) exists, it is mounted at `/` with
`StaticFiles(html=True)` **after** all API routes, so the catch-all can never shadow an endpoint.

| Path | Serves |
|---|---|
| `/` | `index.html` — client-side redirect to `/home` |
| `/home/` `/dashboard/` `/attacks/` `/control/` `/rag/` | the five dashboard pages (`/control/` hosts the Simulate control and a live backend readout) |
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
| **400** | `/simulate` only: an unknown attack class name |
| **403** | `/simulate` only: `ALLOW_SIMULATION=0` |
| **422** | request validation failed (e.g. `limit=0`, `limit=200000`, a missing `question`) — FastAPI's standard body |
| **404** | unknown path; served by the static export's `404.html` when a frontend is mounted |
| **429** | `/simulate` only: more than 30 calls in 60 s |
| **500** | unhandled server error — read `journalctl -u hawkshield-api -n 50` |
| **503** | `/ask`: no `OPENROUTER_API_KEY` or the RAG module failed to import. `/simulate`: no model or no corpus can load |

There is no authentication, and no rate limiting except the light guard on `/simulate`. `/attacks`
with `limit=100000` will happily build a 100 000-row JSON array on a Raspberry Pi; page it.

> **`raw.sim`.** Rows written by `POST /simulate` carry `sim = true` in the `packets.raw` JSON column
> (with `sim_batch` and `sim_class`). Every read endpoint above returns them exactly like real
> detections — they are real model output — so they are invisible in the normal UI shape but filterable
> by that flag. See [`POST /simulate`](#post-simulate).
