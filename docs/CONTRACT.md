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
│   scapy monitor-mode capture → 2-stage   │
│   LightGBM → INSERT into packets         │
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
| `proba_anomaly` | Float, nullable | stage-1 probability |
| `proba_attack` | Float, nullable | stage-2 confidence of the chosen class |
| `predicted_label` | String(64), nullable | one of the six class names below |
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
| `STAGE1_THRESHOLD` | `0.40` | detector |
| `STAGE2_THRESHOLD` | `0.80` | detector |
| `CAPTURE_IFACE` | `wlan1` | detector |
| `CAPTURE_CHANNEL` | `6` | detector |
| `TARGET_SSID` | *(empty = no filter)* | detector |
| `BATCH_SIZE` | `20` | detector sink |
| `BATCH_FLUSH_SECONDS` | `2.0` | detector sink |
| `OPENAI_API_KEY` | *(empty = RAG disabled)* | RAG |
| `GEN_MODEL` | `gpt-4o` | RAG |
| `HUMANIZE_SQL` | `1` | RAG |
| `RAG_MAX_ROWS` | `500` | RAG — `LIMIT` safety net appended to unbounded `SELECT`s |
| `RAG_SQL_TIMEOUT_MS` | `15000` | RAG — Postgres `statement_timeout` for `/ask` queries |
| `ATTACKS_FILE` | *(empty = packaged `app/rag/knowledge/attacks.md`)* | RAG — knowledge-base override |
| `CORS_ORIGINS` | `http://localhost:3000` (comma-separated) | app |
| `FRONTEND_DIST` | `<repo>/frontend/out` | app |
| `AP_LOCATIONS_FILE` | `<repo>/backend/config/ap_locations.json` | app |
| `LOG_LEVEL` | `INFO` | all |

`.env` is loaded from the repo root. **Never commit a real `.env`** — only `.env.example` with placeholders.

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
| GET | `/attacks/analysis` | `{"Deauth": int, "SSDP": int, "Evil_Twin": int, "(Re)Assoc": int, "RogueAP": int, "Krack": int}` — always all six keys, zero-filled |
| GET | `/top-offenders` | `[{"wlan_sa": mac, "count": int}, …]` desc by count (key name is `wlan_sa`, kept for the frontend) |
| GET | `/channel-usage` | `[{"channel_freq": int, "count": int}, …]` desc by count |
| GET | `/heatmap-attack` | `[{"day": "Sun".."Sat", "hours": [{"hour": 0..23, "intensity": int} × 24]}, …]` — Sun-first order |
| GET | `/map/ap-locations` | `[{"bssid": str, "name": str, "lat": float, "lng": float}, …]` from `AP_LOCATIONS_FILE` |
| GET | `/map/source-rssi?sa=<mac>&minutes=10` | `{"sa": str, "points": [{"bssid": str, "avg_rssi": float, "n": int}, …]}` |
| POST | `/map/estimate-origin` | body `{"sa","minutes","ap_locations":[…]}` → `{"sa","method":"weighted-centroid","used":int,"center":{"lat","lng"}|null}` |
| GET | `/reports/summary?days=30` | `{"period": str, "totals": {deauth,ssdp,evil_twin,reassoc,rogueap,krack,other}, "summary": {"totalAttacks","mostFrequentType","peakHour","uniqueSources"}}` |
| POST | `/reports/export` | body `{"days": int}` → `application/pdf` stream, `Content-Disposition: attachment; filename="hawkshield_report_<days>d.pdf"` |
| POST | `/ask` | body `{"question": str, "session_id": str?}` → `{"cached": bool, "mode": "SQL"\|"DOCS"\|"OOS"\|"ERROR", "sql": str, "answer": str, "cols": [str], "rows": [obj], "error": str?}`; **503** `{"detail": "..."}` when no `OPENAI_API_KEY` |
| GET | `/health` | `{"status":"ok"\|"degraded", "database": bool, "packets": int, "latest_packet_ts": iso8601\|null, "models": {"stage1": bool, "stage2": bool}, "version": str}` |

Label mapping used by `/reports/summary` (DB label → frontend key), keep verbatim:

```python
TYPE_MAP_DB_TO_FRONT = {
    "Deauth": "deauth", "SSDP": "ssdp", "Evil_Twin": "evil_twin",
    "(Re)Assoc": "reassoc", "RogueAP": "rogueap", "Krack": "krack",
}
FRONT_TYPES = ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack"]
```

`/ask` keeps the existing TTL cache (200 entries / 600 s, key = sha256 of `session_id||question`) and the
5-turn per-session memory.

**Removed:** `POST /detector/start` and `POST /reports/email`. The detector is a systemd service, not an
HTTP-controlled subprocess. Do not reintroduce them.

---

## 5. Model bundles

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
    pipeline.py   Stage1, Stage2, TwoStagePipeline
    features.py   packet_to_row()
    capture.py    monitor mode, sniff loop, heartbeat
    sink.py       batched DB writer
    cli.py        argparse entrypoint
  scripts/      init_db.py, verify_models.py, replay_pcap.py
  tests/        pytest
```

Both packages may import `backend.app.config` and `backend.app.db` / `backend.app.models`.
Run everything from the repo root; `backend/` is a package (`backend/__init__.py`, `backend/app/__init__.py`, …).

### Shared signatures (do not change)

```python
# backend/detector/features.py
def packet_to_row(pkt, iface: str, state: "ExtractState") -> tuple[dict, dict]:
    """Returns (row_for_model, raw_min_for_db). row keys are the 31 feature names above.
    `state` carries prev-packet timestamp and capture-start time for the delta features."""

# backend/detector/pipeline.py
class TwoStagePipeline:
    def __init__(self, model_dir: Path, thr1: float, thr2: float) -> None: ...
    def predict(self, row: dict) -> "Verdict":
        """Verdict(is_attack: bool, label: str|None, p1: float|None, p2: float|None, stage: int)"""

# backend/detector/sink.py
class PacketSink:
    def write(self, raw: dict, row: dict, verdict: Verdict, iface: str) -> None: ...
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
