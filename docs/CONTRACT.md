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
| `MODEL_VERSION` | `auto` | detector — `auto` \| `v1` \| `v2`; see §5 |
| `V2_MODEL` | `hawkshield_v2.onnx` | detector |
| `V2_META` | `hawkshield_v2_meta.json` | detector, `/health` |
| `V2_BATCH_FRAMES` | `32` | detector — frames per onnxruntime call |
| `V2_ORT_THREADS` | `2` | detector — onnxruntime intra-op threads (`0` = runtime default) |
| `CAPTURE_IFACE` | `wlan1` | detector |
| `CAPTURE_CHANNEL` | `6` | detector |
| `TARGET_SSID` | *(empty = no filter)* | detector |
| `BATCH_SIZE` | `20` | detector sink |
| `BATCH_FLUSH_SECONDS` | `2.0` | detector sink |
| `OPENROUTER_API_KEY` | *(empty = RAG disabled)* | RAG — key from <https://openrouter.ai/keys> |
| `GEN_MODEL` | `deepseek/deepseek-v4-flash` | RAG — any OpenRouter model id |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | RAG — OpenAI-compatible endpoint override |
| `OPENROUTER_SITE_URL` | `https://github.com/MAlshabib/HawkShield` | RAG — sent as `HTTP-Referer` |
| `OPENROUTER_APP_NAME` | `HawkShield` | RAG — sent as `X-Title` |
| `HUMANIZE_SQL` | `1` | RAG |
| `RAG_MAX_ROWS` | `500` | RAG — `LIMIT` safety net appended to unbounded `SELECT`s |
| `RAG_SQL_TIMEOUT_MS` | `15000` | RAG — Postgres `statement_timeout` for `/ask` queries (PostgreSQL only) |
| `ATTACKS_FILE` | *(empty = packaged `app/rag/knowledge/attacks.md`)* | RAG — knowledge-base override |
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

Note: `RAG_MAX_ROWS`, `RAG_SQL_TIMEOUT_MS` and `ATTACKS_FILE` are read directly from the environment by
`backend/app/rag/packet_qa.py` rather than being fields on the `Settings` class. Behaviour is identical
(`.env` is loaded process-wide and `Settings` uses `extra="ignore"`); they are documented in `.env.example`.

---

## 4. HTTP contract (frozen)

The existing frontend already depends on these exact shapes. Do not rename fields.
All routes are registered on the app **without** a prefix (the frontend calls `${API_BASE}/attacks`, etc.).

| Method | Path | Response |
|---|---|---|
| GET | `/attacks?limit=5000&offset=0` | `[ {…full packets row…}, … ]`, newest first. `limit` 1–100000, `offset` ≥ 0 |
| GET | `/packets/count` | `{"count": int}` |
| GET | `/attacks/analysis` | `{"Deauth": int, "Disas": int, "(Re)Assoc": int, "RogueAP": int, "Krack": int, "Kr00k": int, "Evil_Twin": int, "SSDP": int}` — always all **eight** attack keys, zero-filled, in `feature_spec.ATTACK_CLASSES` order. `Normal` is never a key: only attacks are persisted |
| GET | `/top-offenders` | `[{"wlan_sa": mac, "count": int}, …]` desc by count (key name is `wlan_sa`, kept for the frontend) |
| GET | `/channel-usage` | `[{"channel_freq": int, "count": int}, …]` desc by count |
| GET | `/heatmap-attack` | `[{"day": "Sun".."Sat", "hours": [{"hour": 0..23, "intensity": int} × 24]}, …]` — Sun-first order |
| GET | `/map/ap-locations` | `[{"bssid": str, "name": str, "lat": float, "lng": float}, …]` from `AP_LOCATIONS_FILE` |
| GET | `/map/source-rssi?sa=<mac>&minutes=10` | `{"sa": str, "points": [{"bssid": str, "avg_rssi": float, "n": int}, …]}` |
| POST | `/map/estimate-origin` | body `{"sa","minutes","ap_locations":[…]}` → `{"sa","method":"weighted-centroid","used":int,"center":{"lat","lng"}|null}` |
| GET | `/reports/summary?days=30` | `{"period": str, "totals": {deauth,ssdp,evil_twin,reassoc,rogueap,krack,disas,kr00k,other}, "summary": {"totalAttacks","mostFrequentType","peakHour","uniqueSources"}}` |
| POST | `/reports/export` | body `{"days": int}` → `application/pdf` stream, `Content-Disposition: attachment; filename="hawkshield_report_<days>d.pdf"` |
| POST | `/ask` | body `{"question": str, "session_id": str?}` → `{"cached": bool, "mode": "SQL"\|"DOCS"\|"OOS"\|"ERROR", "sql": str, "answer": str, "cols": [str], "rows": [obj], "error": str?}`; **503** `{"detail": "..."}` when no `OPENROUTER_API_KEY` |
| GET | `/health` | `{"status":"ok"\|"degraded", "database": bool, "packets": int, "latest_packet_ts": iso8601\|null, "models": {"stage1": bool, "stage2": bool, "v2": bool}, "model_version": "v2"\|"v1"\|"none", "spec_version": str, "artefact_spec_version": str\|null, "model_problems": [str], "version": str}` |

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
claims. When they differ, `models.v2` is `false` and `model_problems` says exactly why.

`/ask` keeps the existing TTL cache (200 entries / 600 s, key = sha256 of `session_id||question`) and the
5-turn per-session memory.

**Removed:** `POST /detector/start` and `POST /reports/email`. The detector is a systemd service, not an
HTTP-controlled subprocess. Do not reintroduce them.

---

## 5. Models

HawkShield ships **two generations**. `MODEL_VERSION` (or `--model-version`) selects between them:

| value | behaviour |
|---|---|
| `auto` *(default)* | v2 when `models/hawkshield_v2.onnx` + its meta exist **and** the meta matches the running `feature_spec`; otherwise v1, with the reason logged at ERROR |
| `v2` | v2 or nothing — a mismatch raises `SpecMismatchError` and the process exits `2`. Never a silent downgrade |
| `v1` | the two-stage LightGBM bundles in §5.2 |

Whichever loads, it logs one line — `ACTIVE MODEL: v2 (causal TCN, ONNX) spec=...` or
`ACTIVE MODEL: v1 (two-stage LightGBM) ...` — and that line is the authoritative record of what is running.

### 5.1 v2 — `models/hawkshield_v2.onnx` (current)

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

`packet_to_features_v2()` feeds v2; `packet_to_row()` feeds v1. The pipeline's `model_version` decides,
in one place, which extractor the capture loop uses — pairing a v2 model with v1 rows must be impossible
by construction, not by review.

### 5.2 v1 — the two-stage LightGBM bundles (fallback)

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
    routers/      attacks.py reports.py maps.py ask.py health.py
    rag/          packet_qa.py + knowledge/attacks.md   (RAG agent)
  detector/     Capture + inference only.  MUST NOT import backend.app.routers.*
    pipeline.py   V2Pipeline (v2), Stage1/Stage2/TwoStagePipeline (v1), build_pipeline()
    feature_spec.py  THE feature + class contract; stdlib-only, imported by app and ml alike
    features.py   packet_to_row() (v1), packet_to_features_v2() (v2)
    capture.py    monitor mode, sniff loop, heartbeat
    sink.py       batched DB writer
    cli.py        argparse entrypoint
  scripts/      init_db.py, verify_models.py, replay_pcap.py
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
    """Selects per section 5 and logs ACTIVE MODEL. Both returns expose .model_version,
    .thr1, .thr2 and .predict(row) -> Verdict."""

class V2Pipeline:              # model_version == "v2"
    def push(self, features: dict) -> list["Verdict"]:
        """Buffer one frame; [] until the batch fills, then one verdict per buffered
        frame, oldest first. The caller keeps the matching packets."""
    def flush(self) -> list["Verdict"]: ...   # score a partial batch; call when idle
    def reset(self) -> None: ...              # drop the ring buffer at a stream boundary
    def predict(self, row: dict) -> "Verdict": ...   # single frame, forces a flush

class TwoStagePipeline:        # model_version == "v1"
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

# backend/app/rag/packet_qa.py
class RagUnavailable(RuntimeError): ...
def packet_ask(question: str) -> dict:
    """-> {"mode","sql","answer","cols","rows","error"?}; raises RagUnavailable if no API key."""
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

`packet_qa._sql_dialect()` returns `"sqlite"` when `DATABASE_URL` starts with `sqlite`, else `"postgresql"`.
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

`backend/scripts/check_rag.py` verifies `/ask` end to end: key present → `GEN_MODEL` exists in the OpenRouter
catalogue (with its live price) → a `DOCS` answer → a `SQL` generation → that SQL executed. Exit `0` means
`POST /ask` will work; `2` = key/model id, `3` = `DOCS` call, `4` = `SQL` generation or execution.
`--skip-db` stops before execution.
