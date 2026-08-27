# HawkShield — Interface Contract

**This file is normative.** Every agent working on this repo codes against it. If you believe something here
is wrong, report it — do not silently deviate. Nothing outside your assigned file ownership may be edited.

Repo root: `D:\HawkShield`. Target runtime: Raspberry Pi 4, Raspberry Pi OS Bookworm, Python 3.11.

---

## 1. Deployment topology

Everything runs **on the Pi**, as a single web process:

```
Raspberry Pi 4                                  Laptop
┌──────────────────────────────────────────┐
│ hawkshield-detector.service  (root)      │
│   scapy monitor-mode capture → causal    │
│   TCN (ONNX) → INSERT into packets       │
│              ↓ PostgreSQL :5432          │   ┌─────────┐
│ hawkshield-api.service       (unpriv)    │ ◀─│ browser │
│   uvicorn :8000                          │   └─────────┘
│     /api endpoints  +  static frontend   │
└──────────────────────────────────────────┘
```

The built Next.js static export is served **by FastAPI itself** at `/`, so the frontend calls the API
same-origin — no second web server, no CORS in production, and no `next dev` on the Pi.

Development alternative (documented, not default): run the API and `next dev` on a laptop against
`DATABASE_URL` pointing at the Pi, with `NEXT_PUBLIC_API_BASE=http://<pi>:8000`.

---

## 2. Database schema — table `packets`

The single source of truth. This is the table the detector writes and every endpoint reads.
Defined once in `backend/app/models.py`; nobody else declares an ORM model or a `declarative_base()`.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | |
| `ts` | DateTime, indexed | UTC, set by the detector at classification time |
| `iface` | String(64), indexed, nullable | capture interface, e.g. `wlan1` |
| `src_mac` | String(32), nullable | 802.11 addr2 |
| `dst_mac` | String(32), nullable | 802.11 addr1 |
| `bssid` | String(32), nullable | 802.11 addr3 |
| `frame_len` | Integer, nullable | |
| `channel_freq` | Integer, nullable | MHz, from RadioTap |
| `datarate` | Float, nullable | |
| `signal_dbm` | Float, nullable | |
| `wlan_ds` | Integer, nullable | ToDS/FromDS 2-bit value 0–3 |
| `wlan_retry` | Integer, nullable | |
| `wlan_type` | Integer, nullable | |
| `wlan_subtype` | Integer, nullable | |
| `wlan_duration` | Integer, nullable | |
| `proba_anomaly` | Float, nullable | v1: stage-1 probability. v2: `1 − P(Normal)` |
| `proba_attack` | Float, nullable | v1: stage-2 confidence. v2: `P(chosen attack class)` |
| `predicted_label` | String(64), nullable | one of `feature_spec.ATTACK_CLASSES` (eight as of spec 2.1.0) |
| `raw` | JSON, nullable | small dict: iface, sa, da, bssid, len, type, subtype, rate, sig, ssid |

**Only attack packets are persisted.** Normal traffic is classified and dropped.

Second table `documents` (id, title, text, tags, created_at, updated_at) exists in the legacy schema; keep the
model for compatibility but no endpoint depends on it.

---

## 3. Environment variables

All configuration is env-driven via `pydantic-settings` in `backend/app/config.py`. No hardcoded paths,
credentials, or thresholds anywhere in the codebase. `backend/detector/*` reads the same settings object.

| Variable | Default | Used by |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg2://hawkshield:CHANGE_ME@localhost:5432/hawkshield` | app, detector, RAG |
| `MODEL_DIR` | `<repo>/models` | detector, scripts |
| `STAGE1_MODEL` | `stage1_binary_bundle.joblib` | detector |
| `STAGE2_MODEL` | `stage2_multiclass_bundle.joblib` | detector |
| `STAGE1_THRESHOLD` | `0.40` | detector — v1 *and* v2 ("is it an attack") |
| `STAGE2_THRESHOLD` | `0.80` | detector — v1 *and* v2 ("confident which class") |
| `MODEL_VERSION` | `auto` | detector — `auto` \| `v1` \| `v2-tcn` \| `v2-gbdt`; see §5. `v2` is accepted and means `v2-tcn` |
| `V2_MODEL` | `hawkshield_v2.onnx` | detector (v2-tcn) |
| `V2_GBDT` | `hawkshield_v2_gbdt.txt` | detector (v2-gbdt) |
| `V2_META` | `hawkshield_v2_meta.json` | detector (both v2 targets), `/health` |
| `V2_BATCH_FRAMES` | `32` | detector — frames per inference call, both v2 targets |
| `V2_ORT_THREADS` | `2` | detector — onnxruntime intra-op threads (`0` = runtime default) |
| `GBDT_NUM_THREADS` | `2` | detector — LightGBM predict threads for v2-gbdt |
| `CAPTURE_IFACE` | `wlan1` | detector |
| `CAPTURE_CHANNEL` | `6` | detector |
| `TARGET_SSID` | *(empty = no filter)* | detector |
| `BATCH_SIZE` | `20` | detector sink |
| `BATCH_FLUSH_SECONDS` | `2.0` | detector sink |
| `ALLOW_SIMULATION` | `1` | app — master switch for `POST /simulate`; `0` ⇒ 403 |
| `SIM_MAX_COUNT` | `500` | app — hard cap on the per-class `count` a `/simulate` call may request |
| `SIM_CORPUS` | *(empty = packaged `data/sim/awid3_sim_corpus.parquet`)* | app — held-out AWID3 rows `/simulate` replays |
| `OPENROUTER_API_KEY` | *(empty = RAG disabled)* | RAG — key from <https://openrouter.ai/keys> |
| `GEN_MODEL` | `deepseek/deepseek-v4-flash` | RAG — any OpenRouter model id |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | RAG — OpenAI-compatible endpoint override |
| `OPENROUTER_SITE_URL` | `https://github.com/MAlshabib/HawkShield` | RAG — sent as `HTTP-Referer` |
| `OPENROUTER_APP_NAME` | `HawkShield` | RAG — sent as `X-Title` |
| `RAG_MAX_ROWS` | `500` | RAG — `LIMIT` safety net appended to unbounded `SELECT`s. **Deprecated:** also read as a fallback for `SAQR_MAX_ROWS` |
| `RAG_SQL_TIMEOUT_MS` | `15000` | RAG — Postgres `statement_timeout` for `/ask` queries (PostgreSQL only). **Deprecated:** also read as a fallback for `SAQR_SQL_TIMEOUT_MS` |
| `ATTACKS_FILE` | *(empty = packaged `app/rag/knowledge/attacks.md`)* | RAG *and* agent — knowledge-base override |
| `SAQR_ENABLED` | `1` | agent — master switch; `0` ⇒ every `/agent/*` request answers 503 |
| `SAQR_MODEL` | *(empty = reuse `GEN_MODEL`)* | agent — must be a tool-calling model |
| `SAQR_DEFAULT_LOCALE` | `en` | agent — `en` \| `ar`, used when the body omits `locale` |
| `SAQR_TEMPERATURE` | `0.1` | agent |
| `SAQR_MAX_STEPS` | `6` | agent — model turns that may call tools, then a forced prose turn |
| `SAQR_MAX_TOOL_CALLS` | `12` | agent — total tool executions per question |
| `SAQR_RUN_TIMEOUT_S` | `90` | agent — wall clock for one `/agent/ask` |
| `SAQR_TOOL_TIMEOUT_S` | `20` | agent — wall clock for one tool |
| `SAQR_MAX_ROWS` | `500` | agent — `LIMIT` appended to an unbounded agent `SELECT` |
| `SAQR_UI_ROWS` | `50` | agent — rows returned in the response envelope |
| `SAQR_MAX_TOOL_CHARS` | `12000` | agent — cap on the JSON one tool result adds to the conversation |
| `SAQR_SQL_TIMEOUT_MS` | `15000` | agent — Postgres `statement_timeout` (PostgreSQL only) |
| `SAQR_ALLOW_RAW_SQL` | `0` | agent — publish the `run_sql` escape hatch |
| `SAQR_ALLOW_SIMULATION_TOOL` | `1` | agent — publish `run_simulation`; also requires `ALLOW_SIMULATION=1` |
| `SAQR_SIM_TOOL_MAX_COUNT` | `50` | agent — per-class cap; effective cap is `min(requested, this, SIM_MAX_COUNT)` |
| `SAQR_STREAM_KEEPALIVE_S` | `15` | agent — seconds between liveness beats while streaming (`status` event + `: ka` comment) |
| `SAQR_RATE_MAX` | `20` | agent — calls per `SAQR_RATE_WINDOW_S`; over it ⇒ 429 |
| `SAQR_RATE_WINDOW_S` | `60` | agent |
| `SAQR_MAX_CONCURRENT_RUNS` | `2` | agent — runs in flight at once; over it ⇒ 429 |
| `CORS_ORIGINS` | `http://localhost:3000` (comma-separated) | app |
| `FRONTEND_DIST` | `<repo>/frontend/out` | app |
| `AP_LOCATIONS_FILE` | `<repo>/backend/config/ap_locations.json` | app |
| `LOG_LEVEL` | `INFO` | all |

`.env` is loaded from the repo root. **Never commit a real `.env`** — only `.env.example` with placeholders.

**Blank means default.** For the three path variables `MODEL_DIR`, `FRONTEND_DIST` and `AP_LOCATIONS_FILE`,
a value that is empty or whitespace-only MUST resolve to the packaged default in the table above, never to
`Path("")` / the repo root. `.env.example` ships all three blank, so this is the normal case, not an edge one.
Enforced by `Settings._blank_means_default` in `backend/app/config.py`; pinned by
`backend/tests/test_runtime_config.py`. Relative values are resolved against the repo root, not the CWD.
*(This was a real defect: a blank `FRONTEND_DIST` resolved to the repo root and FastAPI served the entire
checkout — including `.env` — as static files.)*

**`DATABASE_URL` selects the SQL dialect** that `/ask` generates and executes: `sqlite:` prefix ⇒ SQLite,
anything else ⇒ PostgreSQL. See §8.

Note: `RAG_MAX_ROWS` and `RAG_SQL_TIMEOUT_MS` are **deprecated aliases** for `SAQR_MAX_ROWS` and
`SAQR_SQL_TIMEOUT_MS`, kept working so an `.env` written before the agent existed still tunes the same
limits. `ATTACKS_FILE` is read from the environment by `backend/app/agent/knowledge.py` rather than being a
field on `Settings`; behaviour is identical (`.env` is loaded process-wide and `Settings` uses
`extra="ignore"`), and it is documented in `.env.example`.

---

## 4. HTTP contract (frozen)

The existing frontend already depends on these exact shapes. Do not rename fields.
All routes are registered on the app **without** a prefix (the frontend calls `${API_BASE}/attacks`, etc.).

| Method | Path | Response |
|---|---|---|
| GET | `/attacks?limit=5000&offset=0` | `[ {…full packets row…}, … ]`, newest first. `limit` 1–100000, `offset` ≥ 0 |
| GET | `/packets/count` | `{"count": int}` |
| GET | `/attacks/analysis` | `{"Deauth": int, "Disas": int, "(Re)Assoc": int, "RogueAP": int, "Krack": int, "Kr00k": int, "Evil_Twin": int, "SSDP": int}` — always all **eight** attack keys, zero-filled, in `feature_spec.ATTACK_CLASSES` order. `Normal` is never a key: only attacks are persisted |
| GET | `/top-offenders?days=&limit=50` | `[{"wlan_sa": mac, "count": int}, …]` desc by count (key name is `wlan_sa`, kept for the frontend). `days` 1–3650, omitted ⇒ all time. `limit` 1–500, **default 50** — the one added default that changes an existing response: this used to return every distinct source MAC. Ties break on `wlan_sa` ascending, which is what makes `limit` deterministic |
| GET | `/channel-usage?days=` | `[{"channel_freq": int, "count": int}, …]` desc by count. `days` 1–3650, omitted ⇒ all time. Never truncated, so no tie-breaker and the no-parameter response is byte-identical to before |
| GET | `/heatmap-attack?days=&tz=UTC` | `[{"day": "Sun".."Sat", "hours": [{"hour": 0..23, "intensity": int} × 24]}, …]` — Sun-first order. `days` 1–3650, omitted ⇒ all time. `tz` is an IANA name (default `UTC`) and buckets on that wall clock; an unknown zone is **400**, never a silent fall back to UTC. `tz=UTC` is byte-identical to omitting it |
| GET | `/attacks/series?days=7&bucket=hour&tz=UTC&label=` | `{"bucket": "hour"\|"day", "tz": str, "days": int, "label": str\|null, "start": iso8601\|null, "end": iso8601\|null, "total": int, "outside_range": int, "points": [{"t": iso8601, "count": int}, …]}`. Zero-filled: every bucket in the window is present, so a quiet hour is a `0` and not a gap. `t` carries the local UTC offset and is directly `new Date(t)`-parseable. `bucket=hour` allows `days` 1–31, `bucket=day` allows 1–366; over that is **400** rather than a silent clamp. Unknown `tz` or unknown `label` is **400** |
| GET | `/map/ap-locations` | `[{"bssid": str, "name": str, "lat": float, "lng": float}, …]` from `AP_LOCATIONS_FILE` |
| GET | `/map/source-rssi?sa=<mac>&minutes=10` | `{"sa": str, "points": [{"bssid": str, "avg_rssi": float, "n": int}, …]}` |
| POST | `/map/estimate-origin` | body `{"sa","minutes","ap_locations":[…]}` → `{"sa","method":"weighted-centroid","used":int,"center":{"lat","lng"}|null}` |
| GET | `/reports/summary?days=30` | `{"period": str, "totals": {deauth,ssdp,evil_twin,reassoc,rogueap,krack,disas,kr00k,other}, "summary": {"totalAttacks","mostFrequentType","peakHour","uniqueSources"}}` |
| POST | `/reports/export` | body `{"days": int}` → `application/pdf` stream, `Content-Disposition: attachment; filename="hawkshield_report_<days>d.pdf"` |
| POST | `/ask` | body `{"question": str, "session_id": str?}` -> `{"cached": bool, "mode": "SQL"\|"DOCS"\|"OOS"\|"ERROR", "sql": str, "answer": str, "cols": [str], "rows": [obj], "error": str?}`; **503** `{"detail": "..."}` when no `OPENROUTER_API_KEY` or `SAQR_ENABLED=0`. **A shim over the Saqr agent** since S5 -- same loop, same eight tools, same guards as `/agent/ask`. `mode` is derived from which tools actually executed, never from a model self-report: `SQL` when any tool that reads packet data ran, `DOCS` when only `explain_attack_class` ran, `OOS` when none ran, `ERROR` on failure. `sql` is the last tabular tool `sql_preview`. See section 10.8 |
| GET | `/health` | `{"status":"ok"\|"degraded", "database": bool, "packets": int, "latest_packet_ts": iso8601\|null, "models": {"stage1": bool, "stage2": bool, "v2": bool, "v2_gbdt": bool}, "model_version": "v2-gbdt"\|"v2-tcn"\|"v1"\|"none", "spec_version": str, "artefact_spec_version": str\|null, "model_problems": [str], "capture": {…see below…}, "version": str}` |
| POST | `/simulate` | body `{"attacks": "all"\|[str], "count": int, "intensity": "burst"\|"trickle"}` → `{"sim_batch": hex, "model_version": str, "intensity": str, "classes": [str], "count_per_class": int, "total_persisted": int, "per_class": {cls: {"requested","frames_pushed","detected","persisted","top_label","labels":{lbl:int}}}}`. **403** when `ALLOW_SIMULATION=0`; **400** on an unknown class; **429** over the rate limit; **503** when no model or no corpus loads. See §9 |
| GET | `/stream?since_id=-1` | `text/event-stream`. One SSE `data:` event per new `packets` row: `{"id","ts","predicted_label","p1","p2","src_mac","bssid","sim"}`. `since_id=-1` (default) starts from the current tail; a non-negative value resumes after that id. Opens with an `event: hello` carrying `{"since_id": int}` |
| POST | `/agent/ask` | **Two transports on one route, chosen by `Accept`.** Body `{"question": str (1–4000), "locale": "en"\|"ar"?, "session_id": str?}`.<br>*Default (`Accept` anything but `text/event-stream`)* → JSON `{"answer": str, "locale": str, "model": str, "steps": int, "run_id": str, "stop_reason": "answered"\|"step_limit"\|"call_limit"\|"timeout"\|"error", "elapsed_ms": int, "sql": str\|null, "cols": [str], "rows": [obj], "tool_calls": [{"step","name","arguments","ok","duration_ms","cached","sql_preview","row_count","error"}], "error": str?}`.<br>*`Accept: text/event-stream`* → `text/event-stream`, the run as it happens; see §10.7.<br>Both: **400** on a malformed body (validated in the handler, so FastAPI's 422 is not used here); **429** over `SAQR_RATE_MAX` or `SAQR_MAX_CONCURRENT_RUNS`, with `Retry-After`; **503** when `SAQR_ENABLED=0`, when no `OPENROUTER_API_KEY` is set (same `detail` string `/ask` returns), or when no model is configured. Every rejection is decided **before** the stream opens, because a started `StreamingResponse` is 200 forever. See §10 |
| GET | `/agent/tools` | `[{"name": str, "label_key": str, "description": str, "mutating": bool, "tags": [str], "args_schema": {JSON Schema}}, …]` — the tools the agent can currently call, honouring `SAQR_ALLOW_RAW_SQL` / `SAQR_ALLOW_SIMULATION_TOOL`. Published unconditionally, so a UI can render the catalogue and explain why the agent is unavailable. `label_key` is `saqr.tool.<name>`: **the frontend generates its label table from this**, it does not hand-copy one |

Label mapping used by `/reports/summary` (DB label → frontend key). **Derived, not hand-maintained** —
`backend/app/config.py` builds it from `feature_spec.ATTACK_CLASSES` by lower-casing and dropping
punctuation, so a class added to the spec appears in `/attacks/analysis` and `/reports/summary` with no
further edit. The six v1 keys are unchanged and keep their historical positions; v2 appends two:

```python
TYPE_MAP_DB_TO_FRONT = {
    "Deauth": "deauth", "Disas": "disas", "(Re)Assoc": "reassoc", "RogueAP": "rogueap",
    "Krack": "krack", "Kr00k": "kr00k", "Evil_Twin": "evil_twin", "SSDP": "ssdp",
}
FRONT_TYPES = ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack", "disas", "kr00k"]
```

`(Re)Assoc` maps to plain `reassoc` — punctuation is dropped, not escaped, so no key ever needs
URL- or JSON-quoting. `totals` still carries the extra `"other"` bucket for labels the spec does not
define (v1 rows left in the table after a v2 upgrade land there).

**`/health` model reporting.** `model_version` is what the *detector would load from the files on disk*,
computed by the API process from `MODEL_DIR` without importing `backend.detector.pipeline`. It is
advisory: the detector's own `ACTIVE MODEL: …` startup log is authoritative. `spec_version` is the
contract this build of the code implements; `artefact_spec_version` is what the on-disk v2 artefact
claims. When they differ, `models.v2` is `false` and `model_problems` says exactly why. Both v2 targets
share that meta file, so a stale export usually rules out both; each entry in `model_problems` is
prefixed with the target it rules out (`v2-tcn:` / `v2-gbdt:`) so one fault does not read as two.

**`/health.capture`** reports what the sensor is set to and, where the API process can actually know it,
what the interface is doing. Added after Phase 1 shipped a dashboard that inferred the interface and channel
from the newest stored packet and had to caption that it had.

```json
"capture": {
  "iface": "wlan1",            // configured CAPTURE_IFACE
  "channel": 6,                // configured CAPTURE_CHANNEL - what the radio was SET to, not a readback
  "target_ssid": null,         // configured TARGET_SSID; null when unset (no filter)
  "present": true,             // interface exists in sysfs
  "monitor_mode": true,        // link type is a radiotap/prism monitor interface
  "link_type": "monitor-radiotap",
  "operstate": "up",           // kernel operstate
  "observed_iface": "wlan1",   // iface on the NEWEST stored packet - what the sensor is actually delivering
  "observed_channel_freq": 2437,
  "source": "config+sysfs"     // "config" when nothing could be measured
}
```

`iface`, `channel`, `target_ssid` and `source` are always present. **Every other field is `null` when it
genuinely cannot be known from inside the API process** — off Linux there is no `/sys/class/net`, so
`present`, `monitor_mode`, `link_type` and `operstate` are all `null` and `source` is `"config"`. `null`
never means "probably fine": reporting `monitor_mode: false` when nothing was measured would be the same
guess the dashboard is making today, wearing a better label. The channel the radio is *actually* parked on
needs an ioctl or a shell out to `iw` and is deliberately not guessed — `channel` is configuration, and
`observed_channel_freq` is the last frequency a stored frame arrived on.

`models.v2_gbdt` is checked without loading LightGBM: a LightGBM text model states its own
`feature_names` and `num_class` in its header, and `/health` reads those. That check is structural
(the 46 spec features first, in order, then well-formed rolling-aggregate names, then the right class
count); the exact column-by-column check is the detector's, at load time.

`/ask` keeps the existing TTL cache (200 entries / 600 s, key = sha256 of `session_id||question`) and the
5-turn per-session memory.

**Removed:** `POST /detector/start` and `POST /reports/email`. The detector is a systemd service, not an
HTTP-controlled subprocess. Do not reintroduce them.

---

## 5. Models

HawkShield ships **three targets**: two v2 models trained on the same spec, and the v1 fallback.
`MODEL_VERSION` (or `--model-version`) selects between them:

| value | behaviour |
|---|---|
| `auto` *(default)* | the first of `v2-gbdt`, `v2-tcn`, `v1` whose artefacts are present **and** match the running `feature_spec`. Every skip is logged with its reason — a missing artefact at INFO, a rejected one at ERROR |
| `v2-gbdt` | the LightGBM booster in §5.1 or nothing |
| `v2-tcn` | the ONNX TCN in §5.2 or nothing (`v2` is accepted and means this) |
| `v1` | the two-stage LightGBM bundles in §5.3 |

An explicit choice **never downgrades**: a missing artefact raises `FileNotFoundError`, a mismatch raises
`SpecMismatchError`, and the process exits `2`. Only `auto` falls through, and only loudly.

Whichever loads, it logs one line — `ACTIVE MODEL: v2-gbdt (LightGBM + causal rolling aggregates) ...` —
naming the target, the spec version and why it was chosen. That line is the authoritative record of what
is running; `/health` reports what the *files on disk* would produce, which is not the same claim.

**Why `auto` prefers the GBDT.** Both v2 models were trained on the full AWID3 archive and scored on the
same 5,943,908 held-out frames:

| | test macro-F1 | Krack | (Re)Assoc | RogueAP | Disas | size | runtime dependency |
|---|---:|---:|---:|---:|---:|---:|---|
| **v2-gbdt** | **0.9907** | 0.9999 | 0.9975 | 1.0000 | 0.9578 | 3.0 MB | `lightgbm` |
| v2-tcn | 0.9856 | 0.9644 | 0.9671 | 0.9955 | **0.9738** | 348 KB | `onnxruntime` |

The committed rule is that whichever model wins on measurement ships, so the GBDT is first. The TCN is
not deprecated: it wins on `Disas`, is 9x smaller, and needs no LightGBM wheel, which is the deciding
factor on a box where one is not available. Both consume the *same* 46-feature extractor output, so
switching between them changes nothing upstream of the pipeline.

### 5.1 v2-gbdt — `models/hawkshield_v2_gbdt.txt` (default)

One LightGBM multiclass booster: 49 boosting rounds x 9 classes = 441 trees, over **82** columns.

```
input   (n, 82) float32   NaN = the frame does not carry that field
output  (n,  9) float64   class probabilities, softmax already applied
```

The 82 columns are `feature_spec.FEATURE_ORDER` (46) **followed by 36 causal rolling aggregates**, in
that exact order. The booster's own `feature_names=` header records them, and `GBDTPipeline` refuses to
start unless that header equals `pipeline.GBDT_FEATURE_NAMES` element for element — which catches a
renamed aggregate, a changed window, a feature added to or removed from the spec, and the one nothing
else would catch: the same 82 names in a different order.

**The rolling aggregates.** A tree sees one row at a time, so on its own it cannot represent "sixty
deauths in the last second". For each window `w in {16, 64}`:

```
roll{w}.{c}.mean   c in frame.len, frame.dt_log, radio.signal_dbm,
roll{w}.{c}.std         wlan.duration, wlan.seq_delta, radio.datarate
roll{w}.{c}.rate   c in mgmt.has_reason, fc.retry, addr.da_broadcast,
                        eapol.present, fc.protected, addr.da_multicast
```

Three properties are normative, and each of them is a way to silently ship a wrong model:

1. **Causal.** The window for frame *i* ends at frame *i*. Nothing looks forward, because a live detector
   has no forward to look at.
2. **The window is `w + 1` frames, not `w`.** `roll16` aggregates rows `[i-16, i]` inclusive —
   seventeen frames. This is what `ml/windows.py::causal_rollups` computes, so it is what the model was
   fitted on. A live buffer holding "the last 16 frames" is off by one on every row, does not crash, and
   does not log.
3. **Bounded.** No aggregate spans a `block_id` in training, and none spans a detector restart or a new
   capture file live — `RollupState.reset()` is that boundary, and `replay_pcap` calls it per file.

**NaN is excluded, never zeroed.** A NaN input does not count toward the numerator or the denominator.
`mean` is NaN when the window held no values; `std` is NaN when it held fewer than two. The model was
fitted with those NaNs present and reads them as information.

`backend/detector/pipeline.py::RollupState` builds these live, one frame at a time, and is
**bit-for-bit identical** to `ml/windows.py::causal_rollups` — not merely close. It keeps running float64
prefix sums and a ring of the last `max(w) + 2` prefix snapshots, and subtracts exactly the two numbers
training subtracted; re-summing the window instead would be correct maths and different rounding, and
`std` is computed as `E[x^2] - E[x]^2`, where a 1e-9 difference becomes 3e-5 after the square root.
`backend/tests/test_pipeline_v2.py::test_streaming_rollups_reproduce_the_training_matrix` runs N frames
through the training builder and through the live state and asserts `np.array_equal`. That test is the
reason this path can be trusted; if it is ever relaxed to `allclose`, the guarantee is gone.

The runtime does **not** import `ml.windows` (it pulls in pyarrow, which has no business on a capture
box). `pipeline.py` holds its own copy of the spec, and
`test_pipeline_v2.py::test_rollup_spec_matches_the_training_module` pins the two together.

**Batching** is a pure cost decision here, with no correctness component at all: the rolling state
advances at `push()` time, one frame at a time, so a frame's 82-column row is fixed before any prediction
happens. `V2_BATCH_FRAMES` (32) rows go into one `Booster.predict` call; `GBDT_NUM_THREADS` (2) is passed
to it, for the same reason `V2_ORT_THREADS` is pinned.

**Measured**, 5000 frames of `data/samples/deauth_raw_decrypted.pcapng`, dev CPU, batch 32, feature
extraction excluded so the two models are compared and not scapy:

| | µs/frame | of which |
|---|---:|---|
| **v2-gbdt total** | **38.9** | rollup state 20.1, `Booster.predict` 5.4, vectorise 4.7, buffering/verdicts ~9 |
| v2-tcn total | 25.9 | `onnxruntime.run` ~15, vectorise 4.7, buffering/verdicts ~6 |

End to end through scapy (`replay_pcap --limit 5000`, dominated by parsing rather than inference):
957 frame/s for the GBDT against 1013 frame/s for the TCN, inference 7.3% vs 3.7% of wall time. The GBDT
costs ~1.5x the TCN per frame and ~6% of end-to-end throughput. Per-packet scoring (`--per-packet`) costs
103 µs/frame for the GBDT and 467 µs/frame for the TCN — the GBDT degrades far more gracefully there,
because a tree ensemble has no context window to re-feed.

**Raspberry Pi 4 caveat.** The risk is the *wheel*, not the model. PyPI has no `manylinux aarch64` wheel
for LightGBM, so on 64-bit Raspberry Pi OS `pip install lightgbm` falls back to piwheels (that image's
default extra index, which usually has a prebuilt one) or to a source build — CMake plus a C++ toolchain,
tens of minutes. **Verify `python -c "import lightgbm"` on the target before choosing `auto`.** Memory is
a non-issue and is measured, not assumed: loading the booster costs **+7.6 MB RSS**, against **+9.7 MB**
for the onnxruntime session — the GBDT is the *lighter* of the two at runtime despite the larger file.
Expect 4-8x the per-frame cost above, i.e. roughly 300-600 µs/frame for the GBDT against 145-290 µs/frame
for the TCN; at 1000 frame/s that is ~30-60% of one core against ~15-30%, on a board with four cores that
also run scapy, the API and Postgres.

**If lightgbm will not install, `--model-version v2-tcn` is the supported answer**: half a point of
macro-F1 for a 348 KB artefact, half the CPU, and a dependency that does ship an aarch64 wheel.

### 5.2 v2-tcn — `models/hawkshield_v2.onnx`

One causal dilated TCN replacing both v1 stages. Contract:

```
input   "frames"  (batch, 46, T) float32   NaN = the frame does not carry that field
output  "logits"  (batch,  9, T) float32   one prediction per frame; streaming reads the last position
```

46 = `feature_spec.FEATURE_ORDER`, in that exact order. 9 = `feature_spec.CLASSES`
(`Normal` + the eight attack classes). Normalisation constants and the mask-channel indices live **inside
the graph** as initialisers and are copied into `models/hawkshield_v2_meta.json`; the graph is the
authority and the meta copy exists so the runtime can check it.

**NaN is signal, never imputed.** The graph replaces NaN with a learned per-feature sentinel and raises a
companion mask channel. Any code that fills a missing feature with a mean, a median or `0.0` before
handing it to this model has reintroduced the v1 defect.

**Load-time validation is mandatory.** `V2Pipeline` refuses to start unless the meta's `spec_version`,
class list, feature list *and feature order*, `n_features` and normalisation vector lengths all match the
running `backend/detector/feature_spec.py`, **and** the ONNX graph's own declared input/output channel
dims match too. All faults are reported at once, naming the artefact and the fix. This is the v1
post-mortem made executable: v1 shipped a model whose feature space was not the one the extractor
produced, and nothing anywhere said so.

**Streaming.** The net is causal, so the prediction for the newest frame is valid from past context only.
The detector keeps a ring buffer of the last `context` (126) frames, appends new frames, and reads the
predictions at the last positions — the same arithmetic as `ml.windows.inference_chunks`, so a frame
scored offline and the same frame scored live see the same history. At the head of a stream the sequence
is simply shorter; there is no synthetic padding.

**Batching.** `V2_BATCH_FRAMES` (32) frames are scored per onnxruntime call, by feeding
`context + N` positions and reading the last `N` outputs. Every scored frame still sees a full `context`,
so batching is a cost decision and never a correctness one — pinned by
`backend/tests/test_pipeline_v2.py::test_streaming_equivalence`. Measured over 5000 frames of
`data/samples/deauth_raw_decrypted.pcapng` through the full capture path (`V2_ORT_THREADS=2`, dev CPU):

| N | calls | per-frame inference | throughput | inference share of wall time |
|---|---|---|---|---|
| 1 | 5000 | 1347.5 µs | 292 frame/s | 39% |
| **32** | **157** | **54.7 µs** | **723 frame/s** | **4%** |
| 64 | 79 | 41.4 µs | 716 frame/s | 3% |

N=32 costs at most 32 frames of added detection delay (~32 ms at 1000 frame/s). N=64 halves the
remaining 4% and doubles the delay, which buys nothing measurable — the other 96% is scapy parsing and
feature derivation. For reference, v1 on the same 5000 frames runs at 780 frame/s, so v2 costs ~7% of
end-to-end throughput.

`V2_ORT_THREADS` is **2, not 0**. Left at the onnxruntime default (one thread per core, spin-waiting
between calls) the same replay ran at 302 frame/s and 166 µs/frame — 2.4x slower end to end. A capture
loop calling a small graph every 32 frames is not a batch job.

**Verdict mapping** (so `sink.py` and the `packets` schema are unchanged):

```
p1    = 1 - P(Normal)                        compared against STAGE1_THRESHOLD
label = argmax over the eight attack classes (never "Normal")
p2    = P(label)                             compared against STAGE2_THRESHOLD
stage = 1 when p1 < thr1, else 2; 0 when inference failed
```

`packet_to_features_v2()` feeds **both** v2 targets; `packet_to_row()` feeds v1. The pipeline's
`feature_space` attribute (`"v2"` / `"v1"`) decides, in one place, which extractor the capture loop uses
— pairing a v2 model with v1 rows must be impossible by construction, not by review. It is
`feature_space` and not `model_version` precisely because there are now two v2 models: matching on the
model name would need an edit every time a target is added, and that edit failing is silent.

### 5.3 v1 — the two-stage LightGBM bundles (fallback)

`models/stage1_binary_bundle.joblib` (md5 `d67bfee99f1188513eb46f9c3a83f1cb`, was `binary_classifier_final.joblib`)

```
{ "model": lightgbm.Booster, "best_iteration": 245, "best_threshold": 0.4,
  "imputer": SimpleImputer, "scaler": StandardScaler,
  "num_cols": [29 names], "cat_cols": ["wlan.country_info.fnm", "wlan.country_info.code"],
  "feature_order": [31 names] }
```

`models/stage2_multiclass_bundle.joblib` (md5 `4ef700bd22eed51dea526e03f77befe0`, was `multiclass_lightgbm_bundle.joblib`)

```
{ "model": lightgbm.Booster, "best_iteration": 116,
  "num_imputer": SimpleImputer, "scaler": StandardScaler,     # note: num_imputer, not imputer
  "num_cols": [same 29], "cat_cols": [same 2], "feature_order": [same 31],
  "class_order": ["SSDP","Evil_Twin","Krack","Deauth","(Re)Assoc","RogueAP"],
  "id_to_class": {0:"SSDP",1:"Evil_Twin",2:"Krack",3:"Deauth",4:"(Re)Assoc",5:"RogueAP"},
  "class_weights": {...} }
```

Both stages share **one identical feature space**, so one extractor feeds both. Feature order (31):

```
frame.encap_type, frame.len, frame.time_delta, frame.time_delta_displayed, frame.time_relative,
radiotap.channel.flags.cck, radiotap.channel.flags.ofdm, radiotap.channel.freq, radiotap.datarate,
radiotap.dbm_antsignal, radiotap.length, radiotap.rxflags, wlan.duration, wlan.fc.ds, wlan.fc.frag,
wlan.fc.order, wlan.fc.moredata, wlan.fc.protected, wlan.fc.pwrmgt, wlan.fc.type, wlan.fc.retry,
wlan.fc.subtype, wlan_radio.duration, wlan.seq, wlan_radio.channel, wlan_radio.data_rate,
wlan_radio.frequency, wlan_radio.signal_dbm, wlan_radio.phy,
wlan.country_info.fnm, wlan.country_info.code          ← the 2 cat_cols; the imputer was fit on the 29 only
```

Transform order, exactly as the working detector does it: build a DataFrame with the **imputer's own**
`feature_names_in_` (29) → `imputer.transform` → `scaler.transform` (keep it a DataFrame the whole way, or
StandardScaler warns about missing feature names) → reindex into the 31-name model space, filling absent
columns with `0.0` → `Booster.predict(X.values, num_iteration=best_iteration)`.

Decision rule: `p1 = P(attack)`; if `p1 < STAGE1_THRESHOLD` → drop. Else stage 2 → `(label, p2)`;
if `p2 < STAGE2_THRESHOLD` → drop. Else persist.

---

## 6. Python module boundaries

```
backend/
  app/          FastAPI only.  MUST NOT import backend.detector.*
    config.py     Settings (owned by Backend agent; all agents read from it)
    db.py         engine, SessionLocal, Base, get_db(), init_db()
    models.py     Packet, Document ORM
    schemas.py    pydantic response models
    routers/      attacks.py reports.py maps.py ask.py agent.py health.py
                  simulate.py stream.py
    rag/          knowledge/attacks.md  -- the attack knowledge base ONLY.
                  packet_qa.py was the text-to-SQL RAG; deleted at S6. The
                  directory stays because ATTACKS_FILE (.env.example and the
                  Pi's live .env) points at this path.
    agent/        Saqr, the tool-calling assistant behind /agent/*
      sqlguard.py   read-only SQL guards, table allow-list, dialect, row normalisation
      knowledge.py  section index over rag/knowledge/attacks.md, by class
      schemas.py    one pydantic arg model per tool (the single schema source)
      tools.py      the tool registry: name -> (arg model, executor, flags)
      llm.py        OpenRouter client factory, SaqrUnavailable, chat(), chat_stream()
      prompts.py    build_system_prompt(locale, dialect)
      events.py     SSE vocabulary, the Emitter, seq/run_id ordering
      ratelimit.py  rolling-window limiter + concurrency gate
      loop.py       run_agent() -> AgentResult
  detector/     Capture + inference only.  MUST NOT import backend.app.routers.*
    pipeline.py   GBDTPipeline + RollupState (v2-gbdt), V2Pipeline (v2-tcn),
                  Stage1/Stage2/TwoStagePipeline (v1), build_pipeline()
    feature_spec.py  THE feature + class contract; stdlib-only, imported by app and ml alike
    features.py   packet_to_row() (v1), packet_to_features_v2() (v2)
    capture.py    monitor mode, sniff loop, heartbeat
    sink.py       batched DB writer
    cli.py        argparse entrypoint
  scripts/      init_db.py, verify_models.py, replay_pcap.py,
                check_saqr.py, check_frontend.py
  tests/        pytest
```

Both packages may import `backend.app.config` and `backend.app.db` / `backend.app.models`.

**One carve-out to `app MUST NOT import backend.detector.*`:** `backend/app/config.py` imports
`backend.detector.feature_spec`, and only that module. `feature_spec` is a stdlib-only leaf — it imports
`math`, `re` and `typing` and nothing else — so it brings neither scapy nor lightgbm into the web process,
which is what the rule exists to prevent. In exchange, the class list, the feature list and the spec
version have exactly one definition in the repository. The routers and `/health` read them from
`config`, never from `backend.detector` directly, and never by re-listing them. Adding a class to
`feature_spec.ATTACK_CLASSES` is sufficient to make it appear in `/attacks/analysis` and
`/reports/summary`.
Run everything from the repo root; `backend/` is a package (`backend/__init__.py`, `backend/app/__init__.py`, …).

### Shared signatures (do not change)

```python
# backend/detector/features.py
def packet_to_row(pkt, iface: str, state: "ExtractState") -> tuple[dict, dict]:
    """Returns (row_for_model, raw_min_for_db). row keys are the 31 feature names above.
    `state` carries prev-packet timestamp and capture-start time for the delta features."""

# backend/detector/features.py  (v2)
def packet_to_features_v2(pkt, iface: str, state: "FrameState") -> tuple[dict, dict]:
    """Returns (features, raw_min_for_db). features keys are feature_spec.FEATURE_ORDER;
    an absent field is NaN for a magnitude and 0.0 for a flag - never imputed."""

# backend/detector/pipeline.py
def build_pipeline(model_version="auto", model_dir=None, thr1=None, thr2=None,
                   batch_frames=None) -> "V2Pipeline | TwoStagePipeline":
    """Selects per section 5 and logs ACTIVE MODEL. Every return exposes .model_version,
    .thr1, .thr2 and .predict(row) -> Verdict."""

class GBDTPipeline:            # model_version == "v2-gbdt", feature_space == "v2"
    def build_row(self, features) -> np.ndarray:   # (82,) = 46 spec + 36 rollups
    def push(self, features) -> list[Verdict]      # buffers; returns on batch completion
    def flush(self) -> list[Verdict]
    def reset(self) -> None                        # stream boundary: clears the rollups
    def predict(self, row) -> Verdict

class RollupState:             # bit-identical to ml.windows.causal_rollups
    def update(self, vec) -> np.ndarray            # (36,) float32, causal
    def reset(self) -> None

class V2Pipeline:              # model_version == "v2-tcn", feature_space == "v2"
    def push(self, features: dict) -> list["Verdict"]:
        """Buffer one frame; [] until the batch fills, then one verdict per buffered
        frame, oldest first. The caller keeps the matching packets."""
    def flush(self) -> list["Verdict"]: ...   # score a partial batch; call when idle
    def reset(self) -> None: ...              # drop the ring buffer at a stream boundary
    def predict(self, row: dict) -> "Verdict": ...   # single frame, forces a flush

class TwoStagePipeline:        # model_version == "v1", feature_space == "v1"
    def __init__(self, model_dir: Path, thr1: float, thr2: float) -> None: ...
    def predict(self, row: dict) -> "Verdict":
        """Verdict(is_attack: bool, label: str|None, p1: float|None, p2: float|None, stage: int)"""

# backend/detector/sink.py
class PacketSink:
    def write(self, raw: dict, row: dict, verdict: Verdict, iface: str) -> None:
        """Accepts a v1 *or* a v2 feature row: the `packets` columns are looked up
        through an alias table, so the schema did not change for v2."""
    def flush(self) -> None: ...
    def close(self) -> None: ...

# backend/app/routers/ask.py   (a shim over the agent since S6; packet_qa is gone)
async def ask(payload: AskPayload, db: Session) -> dict:
    """-> {"cached","mode","sql","answer","cols","rows","error"}; 503 with no API key.
    `mode` comes from which tools executed, never from a model self-report."""

# backend/app/agent/sqlguard.py
def assert_select_only(sql: str) -> str: ...       # one read-only SELECT, or ValueError
def assert_tables_allowed(sql: str, allowed=None) -> str:
    """Allow-list over every FROM/JOIN target, plus CTE names defined in the same
    statement. Defaults to {"packets"}; rejects documents, sqlite_master,
    pg_catalog.*, information_schema.*."""
def apply_row_limit(sql: str, max_rows: int | None = None) -> str: ...
def run_select(statement, *, db=None, dialect=None, timeout_ms=None, db_url=None)\
        -> tuple[list[str], list[tuple]]: ...
def normalise_packet_row(row: dict) -> dict:
    """`raw` is a dict on PostgreSQL and TEXT on SQLite; `ts` likewise. ONE
    implementation -- routers.attacks and routers.stream each grew their own."""
def sql_dialect(database_url: str | None = None) -> str: ...   # "sqlite" | "postgresql"

# backend/app/agent/llm.py
class SaqrUnavailable(RuntimeError): ...
def chat(messages, *, tools=None, tool_choice=None, temperature=None, model=None):
    """One chat completion. Returns the assistant *message* (.content and .tool_calls)."""
def chat_stream(messages, *, tools=None, tool_choice=None, temperature=None,
                model=None) -> Iterator[str]:
    """Text deltas only. Use ONLY for the tool_choice="none" composing turn --
    never for a tool-selection turn; see section 10.7."""

# backend/app/agent/events.py
class Emitter:
    """Stamps run_id + a gapless seq on every payload; buffered=True adds a queue
    that .stream() drains as SSE frames. Typed methods per event (section 10.7)."""
def sse(event: str, data: dict) -> str: ...
def coerce_emitter(emitter, run_id=None) -> Emitter: ...   # None | callable | Emitter

# backend/app/agent/loop.py
async def run_agent(question: str, *, locale=None, session_factory=None, emitter=None,
                    registry=None, model=None, run_id=None,
                    stream_tokens=False) -> "AgentResult":
    """`session_factory` is a sessionmaker bound to the request's engine, so a
    get_db override is honoured. `emitter` is an Emitter, a plain
    (event, payload) callable, or None. `stream_tokens` additionally emits the
    final answer as `token` events. Emits `done` exactly once, always last."""
```

---

## 7. Ground rules

- Python 3.11 target (the Pi). Do not use 3.12+ syntax.
- Type hints on public functions; `logging` (module-level logger), **never `print()`** in library code —
  CLI scripts may print their report output.
- No secrets, no absolute paths from anyone's machine, no `localhost:8001` leftovers.
- Reference data lives at `_archive/source/Comprehensive_Capstone-main/` — read it freely to port logic,
  never write there.
- Sample captures for testing: `data/samples/*.pcapng` (6 files).
- A prepared virtualenv with all pinned deps is at `.venv/` (use `.venv/Scripts/python.exe` on this Windows
  laptop). Use it to actually run and verify your code — do not hand back untested work.
- Report honestly: if something does not work, say so with the error output.

---

## 8. Launcher and target detection

`run.py` at the repo root is **the** entry point for both machines. It is stdlib-only, imports nothing from
`backend`, and runs everything else as a subprocess of `sys.executable`. Keep it that way: a launcher that
cannot start because a dependency is broken cannot report that a dependency is broken.

### 8.1 Mode

`detect_mode()` returns exactly `"pi"` or `"laptop"`:

1. `/proc/device-tree/model` exists and contains `raspberry pi` (case-insensitive) ⇒ `pi`
2. else `platform.system() == "Linux"` and `platform.machine() in {aarch64, armv7l, armv6l}` ⇒ `pi`
3. else ⇒ `laptop`

`--mode auto|pi|laptop` overrides the result; `auto` is the default. The detector runs when the mode is `pi`,
and `--detector` / `--no-detector` override that independently.

| | `pi` | `laptop` |
|---|---|---|
| Processes | `backend.detector.cli` + uvicorn | uvicorn only |
| Database | PostgreSQL, required | PostgreSQL if configured, else SQLite |

### 8.2 Database selection — normative

`resolve_database_url(mode)` reads `DATABASE_URL` from the environment, falling back to the `DATABASE_URL=`
line in `.env`.

* Non-empty **and** not containing `CHANGE_ME` ⇒ use it, unchanged, in both modes.
* Otherwise, `mode == "laptop"` ⇒ set `DATABASE_URL=sqlite:///<repo>/hawkshield.db` in the launcher's own
  process environment (never written to `.env`), warn, and continue.
* Otherwise, `mode == "pi"` ⇒ **exit 2.** There is no SQLite fallback on the Pi, by design: an attack log is
  the sensor's product and must not land in an unmanaged file because a password was left unset.

Consequence, and the point of the whole arrangement: **the same checkout runs on both machines with no
configuration edits on the laptop.**

### 8.3 SQL dialect

`agent.sqlguard.sql_dialect()` returns `"sqlite"` when `DATABASE_URL` starts with `sqlite`, else `"postgresql"`.
It governs two things, which MUST stay in agreement:

* the dialect notes appended to `SYSTEM_PROMPT` (`_SQLITE_NOTES` / `_POSTGRES_NOTES`);
* the executor in `_run_sql()` — SQLite goes through `backend.app.db.engine`, PostgreSQL through `psycopg`
  with `statement_timeout` applied.

The `SELECT`-only assertion and the `RAG_MAX_ROWS` cap sit above the split and apply to both.

### 8.4 Preflight, in order

`.env` created from `.env.example` if absent → database chosen (§8.2) → **both v1 bundles** present in
`MODEL_DIR` → `frontend/out/index.html` present (warn only) → `python -m backend.scripts.init_db` →
port free → root, if the detector is wanted. Failures exit `2`. Losing root downgrades to dashboard-only with
a `sudo` hint rather than failing. `SIGINT`/`SIGTERM` terminate children in reverse start order with an
8-second grace period before `kill()`.

**Known gap.** That third check still looks only for the two v1 `.joblib` bundles, so a checkout
carrying a valid v2 artefact and no v1 bundles is refused by `run.py` even though the detector would
run fine on v2. Harmless today (both bundles ship), but `run.py` should accept *either* generation —
v2 ONNX + meta, or both v1 bundles. Owner of `run.py`, not of the detector.

### 8.5 Flags

`--mode`, `--host` (`0.0.0.0`), `--port` (`8000`), `--demo`, `--demo-capture`
(`data/samples/assoc_flood_raw_decrypted.pcapng`), `--demo-frames` (`4000`), `--detector` / `--no-detector`,
`--iface`, `--channel`, `--reload`. `run.py --help` is authoritative.

### 8.6 Assistant pre-flight

`backend/scripts/check_saqr.py` verifies the assistant end to end (it serves both `/agent/ask` and,
since S5, `/ask`): key present and a client built → the
configured model (`SAQR_MODEL`, else `GEN_MODEL`) exists in the catalogue → that entry advertises the
`tools` parameter → a live one-tool round-trip (the model requests a tool, is handed a result, and answers
in prose quoting it). Exit `0` means `POST /agent/ask` will work; `2` = key/client, `3` = model id,
`4` = tool calling unsupported, `5` = the round-trip, `6` = catalogue unreachable with `--skip-live`.
With no key it prints exactly which checks it could **not** perform and exits non-zero — it never reports a
pass it did not observe. `--skip-live` stops before the billed call.

`backend/scripts/check_frontend.py` is the **go/no-go gate for the shipped `frontend/out` build**, and the
check to run before and after `POST /ask` is reimplemented as a shim over the agent. It boots the real
application over a throwaway seeded SQLite database and verifies, in order: the built bundle is present and
its pages are served by the API process; every endpoint the bundle actually calls answers with the *shape*
it consumes (checked field by field, not by status); and `POST /ask` returns the exact envelope the built
RAG page destructures. Exit `0` means the shipped build still works; `2` = bundle missing or not served,
`3` = an API endpoint broke, `4` = the `/ask` envelope broke, `5` = the live round-trip broke.

Steps 1-3 need no key, no network and no PostgreSQL - the model is faked at `agent.llm.chat` while the
tools, and therefore the SQL, run for real against the seeded database. Before S5 it faked *both* that and
`packet_qa._get_client`, which is how the same gate gave the same verdict on both sides of the flip; that
is why it was written before the flip rather than after. The live round-trip
runs only when `OPENROUTER_API_KEY` is set; without one the script names what it could not verify and still
exits `0`, because this has to be runnable on an offline Pi. `--skip-live` forces that path.

The endpoint list and the `/ask` field list were extracted from `frontend/out/_next/static/chunks/` - from
what the bundle *does*, not from this document. That is the point: the contract can be right while the
shipped build still breaks. **The assertion that matters most is `mode === "SQL"`**: the built RAG page
branches on that exact string and only that branch renders the sample-rows table. Any other value falls
through to `answer || "(no answer)"`, so a wrong mode still shows a fluent, plausible reply while the rows
table silently disappears - no error, nothing red, and a human watching a demo cannot tell. The gate fails
loudly and explains that consequence in its output.

`backend/tests/test_ask_shim_contract.py` is the CI half of the same contract, with each assertion keyed to
the line of the bundle's handler it protects. `/stream` and `/simulate` are proven by the script rather
than by pytest: `/stream` is an endless generator that no in-process transport can close cleanly (a
`TestClient` never signals a disconnect, and `httpx.ASGITransport` buffers the whole body before returning),
so the script drives the ASGI app directly on a daemon thread with a deadline and hands the endpoint a real
`http.disconnect` once its opening `event: hello` frame arrives.

---

## 9. Simulation and live streaming

Two features let the system be exercised and watched without a radio: `POST /simulate`
generates real detections from held-out data, and `GET /stream` pushes new rows to a client live.
They share the `packets` table and the model with the live detector; neither is a mock.

### 9.1 The simulation corpus — `data/sim/awid3_sim_corpus.parquet`

`POST /simulate` replays **held-out AWID3 feature rows**, not crafted frames and not the
`data/samples/*.pcapng` captures. That choice is a measurement, not a preference:

- **Crafted scapy frames** (`attack_sim.build_frames`) score `p1 ≈ 0.96` — the model is sure they are
  *an attack* — but stage-2 confidence sits at ~0.36 and mislabels, because the booster's single most
  important feature is `roll64.frame.dt_log.mean` (inter-frame timing) and frames built in a loop carry
  no timing. They are honest for `--self-test` (they prove the model loads and yields a full 46-feature
  vector and a `p1`) and for `tools/inject_attack.py` (a real radio supplies the timing), **not** for a demo.
- **`data/samples/*.pcapng`** are out of domain — the original project's testbed, not AWID3. The
  AWID3-trained model flags them and then labels almost all of them Krack: the cross-deployment gap of
  `models/README.md` §2.7.1, made concrete. A finding, not a demo source.
- **Held-out AWID3 rows** are the model's own domain and classify correctly (~99–100% per class). This
  is the honest source, and it is what the corpus holds.

**How it is built** (`data/sim/build_sim_corpus.py`, and `data/sim/README.md`): one contiguous *segment*
per attack class, taken from a `block_id` in the training split's `test` set — the same held-out data the
reported macro-F1 was measured on. The segment keeps the **Normal frames interleaved with the attack**,
and that is the whole design: the GBDT's 36 rolling aggregates are causal over the frame stream, so
filtering a block down to only its attack rows produces a stream that never existed and the aggregates
then describe *that*. Measured on seven held-out Kr00k blocks, label-filtered rows persist correctly
0.1–4.2% of the time; the contiguous segment, 97–100%. Same model, same frames — the only difference is
whether the benign frames between attacks were kept. So they are kept, pushed through the pipeline like
everything else, and legitimately come back `Normal` and unpersisted. For each class the builder picks
the held-out block the model handles most cleanly and records it; the segment grows from 2 000 frames up
to a cap when a class is sparse (RogueAP is 1 310 rows in all of AWID3). The `_work/` inputs are
build-time only and uncommitted; the ~300 KB parquet is committed.

**Kr00k.** In earlier label-filtered experiments Kr00k confused to Disas (the documented Disas↔Kr00k
adjacency), so it was a candidate for exclusion. With the contiguous-segment corpus it self-classifies at
100% and is kept in the default `all` menu. If a future spec regresses it, the honest fallback is to drop
it from the default set with this note — never to relabel it.

### 9.2 `POST /simulate` semantics

- `attacks` is `"all"` or a list of class names / frontend keys (`"deauth"`, `"Kr00k"`, …). `"all"`
  expands to **every** attack class in the corpus (eight), which is wider than `attack_sim.resolve_classes`
  ("all" = the six craftable classes).
- `count` is the **target persisted detections per class**, capped at `SIM_MAX_COUNT`. The corpus segment
  is replayed (reset each pass) until that many detections persist or a pass yields none.
- Every persisted row is written through the **same `PacketSink`** the detector uses — the schema does not
  change — and carries `raw.sim = true`, `raw.sim_batch = <uuid>`, `raw.sim_class`, and locally-administered
  synthetic MACs (`02:5a:11:…`). Simulated rows are therefore invisible in the normal UI shape yet trivially
  filterable and purgeable: `DELETE FROM packets WHERE json_extract(raw,'$.sim') = 1` (SQLite) /
  `WHERE raw->>'sim' = 'true'` (Postgres).
- The `per_class` summary reports what the model **did**, not what was asked, so an under-detecting class
  shows in the numbers. Measured per-class correct-persist over the committed corpus is 100% for all eight
  classes; `RogueAP` occasionally mixes a Disas into its persisted rows, which the summary shows honestly.
- Gated by `ALLOW_SIMULATION` (403 when off), capped by `SIM_MAX_COUNT`, lightly rate-limited (429), and
  503 when no model or no corpus can load — the same posture as `/ask`.

### 9.3 `GET /stream`

Server-Sent Events. The endpoint polls `MAX(packets.id)` server-side and emits each new row as it lands;
it opens a short session per poll (never holding one open across the wait), stops on client disconnect, and
sends an SSE keep-alive comment while idle. Works same-origin through the static mount.

### 9.4 `--self-test` and `live_monitor`

`python -m backend.detector.cli --self-test` builds the pipeline and pushes crafted frames through
`packet_to_features_v2` + the inference path, asserting the model loaded and every frame produced a
complete feature vector and a finite `p1` (never class labels — see §9.1). Exit 0 = the model is live and
predicting on this machine; non-zero names the missing/corrupt artefact.

`python -m backend.scripts.live_monitor --follow` is the terminal twin of `/stream`: it tails the `packets`
table (reusing `backend.app.db` + `Packet`), printing one coloured line per row with a `SIM` tag when
`raw.sim` is set. `--since-id` resumes from an id; `--sim-only` shows only simulated rows.

---

## 10. Saqr — the tool-calling agent

`POST /agent/ask` is the second-generation assistant. Instead of asking a model to author SQL, it gives the
model a fixed menu of **tools** and lets it choose. Each tool is a Python function over a
`sqlalchemy.orm.Session`; several of them call the very same functions the dashboard endpoints call
(`reports.compute_summary`, `attacks.read_attack_analysis`, `maps._avg_rssi_rows`, `health.health`), so the
agent's numbers and the dashboard's numbers cannot disagree.

`POST /ask` is a thin shim over this same loop (section 10.8), and `backend/app/rag/packet_qa.py` has been
deleted. There is one assistant in this system, not two.

### 10.1 Tools call Python, never HTTP

HawkShield runs as **one** uvicorn process. A tool that issued an HTTP request back into the same app would
occupy the only worker while waiting for its own response. Tools therefore call the handler functions
directly, on a worker thread (`asyncio.to_thread`), using a `sessionmaker` bound to the *request's* engine —
the pattern `stream.py` and `simulate.py` already use, which also keeps a `get_db` dependency override
working under test. **Do not reintroduce self-HTTP.**

### 10.2 The tool registry

Eight tools, in this order. The menu is deliberately short: a cheap model degrades as it grows, picking a
plausible wrong tool rather than composing the right one. `aggregate_threats` therefore absorbs what would
otherwise be four separate tools (top offenders, channel usage, per-class counts, the hour/day heatmap).

| # | Tool | Reads | Notes |
|---|---|---|---|
| 1 | `query_threats` | `packets` | Individual detections. Window / label / MAC / BSSID / iface / channel / confidence filters, `order`, `limit ≤ 200`. Parameterised `select()`, never model-authored SQL |
| 2 | `aggregate_threats` | `packets` | Counts by `group_by ∈ {label, src_mac, bssid, channel_freq, iface, hour_of_day, day_of_week, none}`, `top_n ≤ 50`. `hour_of_day`/`day_of_week` are bucketed **in Python**, exactly as `attacks.heatmap_attack` does, so there is no `date_trunc`/`strftime` dialect split |
| 3 | `threat_overview` | `packets` | `reports.compute_summary` + `attacks.read_attack_analysis` + stored packet count and first/last timestamps |
| 4 | `explain_attack_class` | knowledge base | `agent/knowledge.py`; no database access |
| 5 | `locate_source` | `packets` + `AP_LOCATIONS_FILE` | `maps._avg_rssi_rows` + `_load_ap_locations` + the same weighted-centroid maths as `POST /map/estimate-origin` |
| 6 | `system_status` | — | `health(db)` + model/spec versions + the agent's own configuration and available tools, so "why are you broken?" is self-answerable |
| 7 | `run_simulation` | **writes** `packets` | The **only** mutating tool (`mutating: true` in the registry and in `GET /agent/tools`). Calls `simulate.simulate`; count capped at `min(requested, SAQR_SIM_TOOL_MAX_COUNT, SIM_MAX_COUNT)`. Hidden unless `SAQR_ALLOW_SIMULATION_TOOL=1` **and** `ALLOW_SIMULATION=1` |
| 8 | `run_sql` | `packets` | Guarded escape hatch, listed last so the model reaches for it last. Hidden unless `SAQR_ALLOW_RAW_SQL=1` |

Argument schemas have exactly one definition: a pydantic model in `backend/app/agent/schemas.py`.
`Model.model_json_schema()` both feeds the OpenRouter `tools=` payload and validates the model's arguments,
so what the model is shown and what its call is checked against cannot drift.

Every tool that runs SQL returns `sql_preview` — the statement with values inlined
(`stmt.compile(compile_kwargs={"literal_binds": True})`) — so the UI can show the real `SELECT` even for the
structured tools, and an answer is checkable rather than merely plausible.

### 10.3 The loop

Up to `SAQR_MAX_STEPS` model turns may call tools, then one final turn with `tool_choice="none"`. Every
bound has a defined outcome, and none of them is a blank answer:

- **step limit / call limit / run timeout** → the forced final prose turn; `stop_reason` says which;
- **bad tool name, or arguments that fail pydantic** → `{"ok": false, "error": {...}}` fed back as a
  `role: "tool"` message so the model self-corrects. Never an exception;
- **repeat call** → keyed on `(tool, canonical JSON of args)`; a repeat returns the cached result plus a note
  saying the identical call was already made, instead of re-executing. An *error* would just make the model
  retry with a cosmetic tweak, which is the loop this prevents;
- **`ar` answer with no Arabic codepoint** → one corrective turn, budgeted *outside* `SAQR_MAX_STEPS`
  because it is a formatting fix, not another chance to reason.

All turns are non-streaming. `run_agent` already accepts an `emitter(event, payload)` and calls it at
`run_start` / `step` / `tool_call` / `tool_result` / `answer` / `run_end`, so the streaming transport can be
added without restructuring the loop.

### 10.4 Prompt injection is in scope

`src_mac`, `bssid`, `dst_mac` and `raw.ssid` are **attacker-controlled by design** — anyone can name their
SSID `ignore previous instructions`. Two structural rules, both pinned by tests:

1. Tool output goes into `role: "tool"` messages as JSON. It is **never** spliced into the system prompt.
2. The system prompt states that tool output is data and never instruction, names those fields as
   attacker-controlled, and forbids calling the mutating tool because a tool result asked for it.

### 10.5 Table allow-list

`assert_select_only` proves a statement only *reads*; it says nothing about *what*. `documents`,
`sqlite_master`, `pg_catalog.*` and `information_schema.*` were all reachable. `assert_tables_allowed`
parses every `FROM`/`JOIN` target (after blanking string literals and comments) and permits only `packets`
plus CTE names defined in the same statement, so
`WITH recent AS (SELECT … FROM packets) SELECT … FROM recent` passes and the rest do not.

### 10.6 Failure posture

`503` when `SAQR_ENABLED=0`, when there is no `OPENROUTER_API_KEY` (the *same* `detail` string `/ask`
returns), or when no model is configured. `429` over `SAQR_RATE_MAX` or `SAQR_MAX_CONCURRENT_RUNS`, with
`Retry-After`. `400` on a malformed body — validated inside the handler, so FastAPI's default 422 handler is
left alone for every other route. Anything the run itself survives is reported inside a 200 response
(`stop_reason`, `error`), because a partially answered question tells an operator more than an opaque 500.

### 10.7 Streaming — `Accept: text/event-stream`

`POST /agent/ask` returns `text/event-stream` when the client's `Accept` header names it, and the JSON
envelope otherwise. Same route, same loop, same tools. A bare `*/*` gets JSON, so nothing that worked
before streaming existed starts receiving a stream it cannot parse.

**Not POST-then-GET with a run id.** That needs a run registry, a GC timer, and it leaks an orphaned run
every time a browser tab closes mid-answer. Here the run *is* the response body: cancellation is an
`AbortController` client-side and `await request.is_disconnected()` server-side, exactly as
`routers/stream.py` already does, and the run task is cancelled when the drain ends.

Headers are `stream.py`'s, `X-Accel-Buffering: no` included — without it a reverse proxy buffers the whole
body and the agent pane looks frozen, which is the exact opposite of why this streams.

#### Event vocabulary

Every payload carries `run_id` (uuid4 hex) and `seq`, **strictly increasing from 0 with no gaps**, so a
client can detect a dropped frame instead of silently rendering an incomplete transcript.

| Event | Payload |
|---|---|
| `run_start` | `{run_id, seq, ts, question, locale, model, max_steps, tools: [name]}` |
| `status` | `{run_id, seq, ts, phase, step}` — `phase` ∈ `calling_model` \| `executing_tool` \| `composing`; also emitted as a liveness beat every `SAQR_STREAM_KEEPALIVE_S` during a long model call |
| `tool_call` | `{run_id, seq, ts, step, call_id, tool, label_key, mutating, args}` — `args` are the **validated** arguments with unset optionals omitted, so a hallucinated field never renders as though the tool accepted it |
| `tool_result` | `{run_id, seq, ts, step, call_id, tool, ok, duration_ms, summary, data, row_count, truncated, sql_preview, error, cached}` |
| `token` | `{run_id, seq, delta}` — a fragment of the final answer. No `ts`: it is the highest-volume event |
| `answer` | `{run_id, seq, ts, text, used_tools}` — the complete text, so a client never has to reassemble tokens to persist a transcript |
| `error` | `{run_id, seq, ts, code, message, fatal}` |
| `done` | `{run_id, seq, ts, steps, tool_calls, elapsed_ms, stop_reason}` |

`done` is **always last, including after `error`**, and is emitted at most once — one termination condition,
never a guess about whether a stream that stopped was finished or broken. The transport emits it even if
the loop somehow does not. Idle ticks send a `: ka` SSE comment, which resets a proxy's idle timer without
reaching the client's message handler.

`phase` values are `saqr.phase.<phase>` on the frontend and `code` values are `saqr.error.<code>`; both
vocabularies are closed. `code` ∈ `no_api_key` \| `no_credit` \| `model_error` \| `tool_error` \|
`bad_args` \| `step_limit` \| `timeout` \| `internal`. Internal tool-error types (`invalid_arguments`,
`rejected_sql`, `tool_timeout`, …) are mapped onto that fixed set in `tool_result.error.code`, with the
finer `type` kept alongside for an operator reading the raw stream. A tool the registry does not know
reports `label_key: "saqr.tool.unknown"`.

#### Only the composing turn streams from the provider

Intermediate tool-selection turns are **never** streamed. With `stream=True` the SDK delivers a tool call
in fragments — `id` and `function.name` only on the first chunk, `function.arguments` as partial JSON
spread across many chunks indexed by `delta.tool_calls[i].index` — and a wrong accumulator silently
produces calls with truncated arguments. The `status` / `tool_call` / `tool_result` events already give the
UI its motion during those turns, so there is nothing to buy.

The consequence, which a live run exposed and which is worth stating plainly: **the answer usually does not
come from the composing turn at all.** Whenever the model decides it has enough, it just returns prose on a
tool-selection turn, and the forced `tool_choice="none"` turn never runs. So the loop emits `token` events
on both paths — streamed from the provider when the composing turn ran, replayed locally (split on word
boundaries) when the answer arrived whole. A client cannot tell and must not need to: a `token` is defined
as *a fragment of the final answer*, not as a provider-side chunk. The honest-looking alternative — throwing
away a paid-for answer and re-asking with `stream=True` — would double the cost and latency of every
question on a Pi. If a provider refuses `stream=True` the answer is still delivered, replayed the same way.

`run_start` is emitted and flushed before the first model call, so the pane never sits blank through the
1–3 s of first-token latency.

#### Notes for a client

- Correlate `tool_call` → `tool_result` on `call_id`, but key UI rows on `(step, call_id)`: `call_id` is the
  model's own id, and uniqueness across a run is the provider's promise, not this API's.
- `row_count` is `null` for aggregations; use `data.group_count` / `data.total` there.
- `data` is a trimmed preview capped at `SAQR_UI_ROWS` rows and 8 KB. Over that it becomes
  `{"omitted": true, "reason": …}` rather than half a JSON object. It never repeats `sql_preview`,
  `row_count`, `truncated` or `error`, which the event already carries as its own fields.
- `stop_reason` on `done` is the same field, with the same vocabulary, as `stop_reason` in the JSON
  envelope: one concept, one name, both transports.

### 10.8 `POST /ask` is a shim over this agent

`/ask` predates the agent. The already-built `frontend/out` bundle calls it, so the route survives; since S5
everything behind it is `run_agent(..., emitter=None)` — the same loop, the same eight tools, the same
guards. `backend/app/rag/packet_qa.py` and `backend/tests/test_rag.py` were deleted at S6, along with
`backend/scripts/check_rag.py`, which could not function without them.

The router still owns exactly what it owned before: the TTL cache (200 entries / 600 s, key =
sha256 of `session_id||question`), the five-turn per-session memory, and a 503 when the assistant is not
configured. Nothing else about the envelope moved.

**`mode` is derived from which tools actually executed**, never from anything the model says about itself:

| value | condition |
|---|---|
| `ERROR` | the run failed (`AgentResult.error` is set) |
| `SQL` | at least one tool that reads packet data ran successfully |
| `DOCS` | only `explain_attack_class` ran |
| `OOS` | no tool ran at all |

That indirection is not fussiness. The bundle's handler branches on the literal string `"SQL"` and **only**
that branch renders the sample-rows table; every other value falls through to `answer || "(no answer)"`. A
wrong `mode` therefore shows a fluent, plausible reply with the rows table silently missing — no error,
nothing red. `backend/scripts/check_frontend.py` asserts it explicitly and explains that consequence when it
fails. `sql` is the last tabular tool's `sql_preview`, so the panel still shows the query behind the numbers.

Two behaviours changed with the flip, both deliberate:

- **`assert_tables_allowed` now covers `/ask`.** The RAG path enforced SELECT-only but never a table
  allow-list, so `documents`, `sqlite_master`, `pg_catalog.*` and `information_schema.*` were reachable
  through it. They are not reachable from either route now.
- **`SAQR_ENABLED=0` disables `/ask` too.** After the flip there is one assistant, so its master switch
  governs both routes. The missing-key 503 carries the identical `detail` string it always did.

`/ask` deliberately has **no** rate limit and **no** concurrency gate, matching its previous behaviour;
`/agent/ask` has both. A run through `/ask` is now materially more expensive than the old two-call RAG path
(up to `SAQR_MAX_STEPS` model turns), so a host exposing `/ask` to untrusted callers should put the limit in
front of it. The TTL cache absorbs repeats, which is what made this acceptable for the one legacy bundle it
serves.
