# HawkShield — architecture

How one 802.11 frame becomes a row on a dashboard.

This document describes what the code does. The normative interface definitions live in
[`CONTRACT.md`](CONTRACT.md); the model card and its limitations live in
[`../models/README.md`](../models/README.md); the same flow drawn as diagrams is in
[`model-pipeline.md`](model-pipeline.md).

> **Two generations.** The detector loads either the **v2** causal TCN (ONNX) or the **v1** two-stage
> LightGBM pair, chosen by `MODEL_VERSION`. Steps 1, 4 and 5 below are identical for both; steps 2
> and 3 differ, and both are described. The trained v2 artefacts ship in `models/`, so `auto`
> resolves to **`v2-gbdt`** (the measured winner) — see [`models.md`](models.md).

---

## 1. The shape of the system

Two processes on one Raspberry Pi, sharing one PostgreSQL database and nothing else.

*(That is the deployed shape. The same code also runs on a laptop with no radio, where the detector
is simply not started and the database may be SQLite — see §3.)*

| Process | Unit | User | Job |
|---|---|---|---|
| Detector | `hawkshield-detector.service` | root (`CAP_NET_RAW`, `CAP_NET_ADMIN`) | capture → classify → write |
| Web | `hawkshield-api.service` | unprivileged | read → serve JSON **and** the dashboard on `:8000` |

They never import each other. `backend/app/*` must not import `backend.detector.*`, and
`backend/detector/*` must not import `backend.app.routers.*`. Both may import
`backend.app.config`, `backend.app.db` and `backend.app.models` — the settings object and the ORM are
the only shared surface. The database is the seam.

That separation is not decoration. The detector needs raw-socket privileges and a radio; the web
service needs neither. Killing one does not affect the other, and either can be run by hand for
debugging without dragging the rest of the system along.

---

## 2. The frame path, step by step

```
802.11 frame + RadioTap header
        │
        ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 1. capture.py — Detector.on_packet(pkt)                             │
 │      scapy sniff(iface=wlan1, prn=on_packet, store=False)           │
 └─────────────────────────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 2. features.py — packet_to_features_v2(pkt, iface, state)     [v2]  │
 │      scapy_to_raw()  →  dict keyed by tshark column names           │
 │      feature_spec.derive_frame_features()  →  46 floats             │
 │      -> (row: 46 features, raw_min: 10-key dict for the DB)         │
 │    [v1]  packet_to_row()  →  31 named features                      │
 └─────────────────────────────────────────────────────────────────────┘
        │
        ▼  optional SSID soft filter (TARGET_SSID)
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 3. pipeline.py — V2Pipeline.predict(row) -> Verdict           [v2]  │
 │      ring buffer: the last 126 frames of causal context             │
 │      onnxruntime, 32 frames per call → 9 logits per frame           │
 │      p1 = 1 − P(Normal)                                             │
 │        p1 <  STAGE1_THRESHOLD  →  Verdict(is_attack=False, stage=1) │
 │      label = argmax over the 8 attack classes;  p2 = P(label)       │
 │        p2 <  STAGE2_THRESHOLD  →  Verdict(is_attack=False, stage=2) │
 │        otherwise               →  Verdict(is_attack=True, ...)      │
 │    [v1]  TwoStagePipeline: impute → scale → reindex → 2 × Booster   │
 └─────────────────────────────────────────────────────────────────────┘
        │ is_attack only
        ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 4. sink.py — PacketSink.write(raw, row, verdict, iface)             │
 │      buffer; flush at BATCH_SIZE rows or BATCH_FLUSH_SECONDS        │
 └─────────────────────────────────────────────────────────────────────┘
        │ INSERT
        ▼
   PostgreSQL — table `packets`
        │ SELECT
        ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 5. backend/app/routers/* — aggregate into the frozen JSON shapes    │
 └─────────────────────────────────────────────────────────────────────┘
        │ fetch (same origin)
        ▼
   frontend/out — Next.js static export, served by the same FastAPI process
```

### Step 1 — capture

`Detector.prepare_interface()` runs `iw <iface> set monitor none`, pins the channel with
`iw <iface> set channel <n>`, and brings the link up. If the interface is already in monitor mode the
switch is skipped.

The sniff loop is deliberately sliced rather than infinite: `sniff()` is called with a short timeout
inside a `while not self._stop.is_set()` loop, so a `SIGTERM` is honoured promptly instead of being
swallowed by libpcap. An `OSError` with `errno == ENETDOWN` — a USB adapter that briefly vanished —
is caught, the interface is brought back up and re-pinned, and the loop continues. Every other
exception is logged and retried after a second; a single malformed frame can never kill the service.

A daemon heartbeat thread logs `status=LIVE seen=N saved=N filtered=N` every 2 s and calls
`sink.maybe_flush()`, so the tail of a burst is not stranded in the buffer waiting for the next attack
to arrive.

`packets seen` is counted for every frame; only frames that clear both thresholds increment `saved`.

### Step 2 — feature extraction

Both generations return the same *pair*:

* **`row`** — a dict keyed by that generation's feature names, built from the RadioTap and Dot11
  headers.
* **`raw_min`** — a small dict (`iface`, `sa`, `da`, `bssid`, `len`, `type`, `subtype`, `rate`, `sig`,
  `ssid`) stored verbatim in the `packets.raw` JSON column. It exists so an analyst can see the
  identity fields the model was never allowed to look at.

#### v2 — `packet_to_features_v2(pkt, iface, state)`

Two steps, and the second one is the whole design:

```
scapy packet
  → scapy_to_raw()                        a dict keyed by tshark / AWID3 column names
  → feature_spec.derive_frame_features()  46 floats, in FEATURE_ORDER
```

`derive_frame_features()` lives in `backend/detector/feature_spec.py` and is called by **both** this
path and `ml/prepare_awid3.py`, the AWID3 preprocessor. Training and inference cannot derive features
differently, because there is only one derivation. In v1 they were two separate implementations and
16 of 29 features were silently absent live — see §7.

The governing rule is: **a field the frame does not carry becomes NaN (for a magnitude) or `0.0` (for
a flag), never invented and never imputed.** NaN reaches the model as a learned per-feature sentinel
plus a companion mask channel, so "absent" is information the network can use rather than a value it
is told equals the average.

`FrameState` carries the only cross-frame state the contract allows: the previous frame's sequence
number and BSSID (for `wlan.seq_delta` and `addr.same_bssid_as_prev`), plus the previous epoch, used
only to reconstruct `frame.dt` when the source supplied no delta. It is O(1) by design and **cannot
leak absolute session time into the features** — which is exactly what v1's `ExtractState` did.

No raw identifier is in the v2 feature space. Addresses appear only as derived semantics
(`addr.da_broadcast`, `addr.sa_is_bssid`, `addr.sa_local_admin`, …) and the SSID only as a length.
The feature groups and the banned-field list are in [`models.md` §3](models.md).

#### v1 — `packet_to_row(pkt, iface, state)`

31 features: 29 numeric ones the bundle's imputer and scaler were fit on, plus
`wlan.country_info.fnm` and `wlan.country_info.code`, two tshark-parsed categoricals with no scapy
equivalent that are always absent at inference and filled with `0.0` when the row is reindexed.

Here a field the frame does not carry stays `None`, so the bundle's `SimpleImputer` fills it with the
training median. `ExtractState` carries `frame.time_delta` and `frame.time_relative`; the latter
resets on every detector restart and is the leaked feature described in §7.

### Step 3 — classification

#### v2 — one causal TCN

`V2Pipeline` loads `models/hawkshield_v2.onnx` through onnxruntime and keeps a **ring buffer of the
last 126 frames**. The network is causal — every convolution is left-padded only — so the prediction
for the newest frame is valid from past context alone, and the buffer holds exactly the receptive
field it needs. At the head of a stream the sequence is simply shorter; there is no synthetic padding.

```
input   "frames"  (batch, 46, T) float32     NaN = the frame does not carry that field
output  "logits"  (batch,  9, T) float32     one prediction per frame
```

Decision rule:

| Quantity | Definition | Cutoff |
|---|---|---|
| `p1` | `1 − P(Normal)` | `STAGE1_THRESHOLD` = **0.40** — below it the frame is dropped |
| `label` | argmax over the **eight** attack classes — never `Normal` | — |
| `p2` | `P(label)` | `STAGE2_THRESHOLD` = **0.80** — below it the frame is dropped |

The result is the same `Verdict(is_attack, label, p1, p2, stage)` v1 produced, so `sink.py` and the
`packets` schema are unchanged. `stage` records where the decision was made — `0` means inference
failed outright, `1` means rejected at the attack gate, `2` means it reached the naming step.

**Batching.** `V2_BATCH_FRAMES` (default **32**) frames are scored per onnxruntime call, by feeding
`context + N` positions and reading the last `N` outputs. Every scored frame still sees a full
context, so batching is a cost decision and never a correctness one —
`backend/tests/test_pipeline_v2.py::test_streaming_equivalence` pins that. Measured over 5000 frames
of the deauth sample through the full capture path, per-frame inference falls from **1347.5 µs**
(N=1) to **54.7 µs** (N=32), lifting end-to-end throughput from 292 to 723 frame/s and dropping
inference from 39 % of wall time to 4 %. The cost is at most 32 frames of added detection delay —
about 32 ms at 1000 frame/s. N=64 buys nothing measurable: the remaining 96 % is scapy parsing and
feature derivation, not the model.

**Threading.** `V2_ORT_THREADS` defaults to **2, not 0**. Left at the onnxruntime default — one
thread per core, spin-waiting between calls — the same replay ran at 302 frame/s, **2.4× slower end
to end**. That default is tuned for a batch job that owns the machine; a capture loop calling a small
graph every 32 frames is the opposite, and on a four-core Pi the spin-wait competes directly with the
sniffer.

**Load-time validation.** `V2Pipeline` refuses to start unless the artefact's spec version, class
list, feature list *and feature order*, feature count and normalisation vector lengths all match the
running `feature_spec`, and the ONNX graph's own declared channel dimensions match too. All faults
are reported at once. Under `MODEL_VERSION=v2` a mismatch raises `SpecMismatchError` and exits `2`;
under `auto` it falls back (v2-tcn, then v1) and logs the reason at ERROR. The check caught a stale artefact on
its first run, which is the entire justification for its existence.

The ring-buffer arithmetic mirrors `ml.windows.inference_chunks` exactly, so a frame scored offline
during evaluation and the same frame scored live see the same history.

**Which extractor feeds which model is decided in one place.** The pipeline's `model_version` selects
the extractor and the classifier together, so pairing a v2 model with v1 rows is impossible by
construction rather than by review.

#### v1 — the two-stage LightGBM fallback

Both bundles share **one identical feature space**, which is why one extractor can feed both. The
transform is the same for each stage and must be done in this order:

```
DataFrame(imputer.feature_names_in_)   # 29 named columns, NaN where the row had None
  → imputer.transform                  # median fill
  → scaler.transform                   # kept as a DataFrame, or StandardScaler warns
  → reindex onto feature_order          # 31 columns; the 2 categoricals become 0.0
  → Booster.predict(X.values, num_iteration=best_iteration)
```

Decision rule:

| Stage | Model | Output | Cutoff | On failure |
|---|---|---|---|---|
| 1 | LightGBM binary, `best_iteration=245` | `p1 = P(attack)` | `STAGE1_THRESHOLD` = **0.40** | drop, nothing persisted |
| 2 | LightGBM multiclass, `best_iteration=116` | `(label, p2)` = argmax of a 6-way softmax | `STAGE2_THRESHOLD` = **0.80** | drop, nothing persisted |

The six classes, in the bundle's own id order: `SSDP`, `Evil_Twin`, `Krack`, `Deauth`, `(Re)Assoc`,
`RogueAP`. It produces the same `Verdict` shape as v2.

**Why v1 was two stages, and why v2 is one network.** The gate existed for cost — stage 1 was the
only model that saw every frame, and a cheap binary classifier kept the expensive multiclass model
off the overwhelmingly normal majority — and for independent knobs. v2 collapses both stages because
the same 80 k-parameter graph scores every frame in 54.7 µs, which makes the gate unnecessary. The two
thresholds survive unchanged as the operator-facing knobs, so a value tuned on v1 means the same
thing on v2.

The one thing the split could never fix: stage 2 has **no "none of the above" class**. Anything that
clears stage 1 is forced into one of six labels, and the 0.80 floor is the only guard. v2 fixes this
structurally — `Normal` is one of its nine classes, so the model can decline.

### Step 4 — why only attacks are stored

`PacketSink.write()` is called **only** when `verdict.is_attack` is true. Normal traffic is scored and
discarded.

| Reason | Detail |
|---|---|
| Write volume | A busy 2.4 GHz channel is thousands of frames per second. Persisting all of them would saturate a microSD card in hours and make every dashboard query a full table scan. |
| Storage | The Pi's storage is small and usually removable. An attack log grows at human scale; a full packet log does not. |
| Privacy | Frames from every device in radio range include identity fields. Storing only what the model flagged keeps the retained set to what is operationally relevant. |
| Query shape | Every endpoint asks "what attacks happened?" None asks "what was the total traffic?" The table is exactly the working set. |

The cost is explicit and worth stating: **the `packets` table cannot be used to compute a false-positive
rate after the fact**, because the denominator was never written. To measure that, replay a capture
with `backend/scripts/replay_pcap.py`, which reports the stage-1 hit rate over *all* frames read.

Writes are batched. `PacketSink` buffers rows and flushes on whichever comes first: `BATCH_SIZE` rows
(default 20) or `BATCH_FLUSH_SECONDS` (default 2.0) since the oldest buffered row. One `INSERT` per
attack frame would mean one network round-trip per frame during a flood, which is precisely when the
detector can least afford it. The buffer is lock-guarded because the heartbeat thread can also trigger
a flush. `flush()` **never raises**: a failed commit is rolled back, the rows are counted as `failed`,
and capture continues. Losing a row is preferable to losing the sniffer.

### Step 5 — the API

Routers are thin. `attacks.py` aggregates with SQLAlchemy; `/attacks` itself uses a raw
`SELECT * FROM packets` so a new column appears in the response without a code change, with a
`_normalise_row()` pass that undoes driver differences (psycopg2 returns `dict`/`datetime` for `raw`
and `ts`; SQLite returns TEXT for both).

`/health` is deliberately dependency-free: it never imports `backend.detector.*`, and model
availability is a plain `Path.exists()` check. A health endpoint that needs LightGBM loaded to answer
is not a health endpoint.

`/ask` is the only endpoint with an external dependency. The router owns the TTL cache (200 entries,
600 s, key = sha256 of `session_id||question`) and the 5-turn session memory, then delegates to
`backend/app/rag/packet_qa.py`. That module is imported inside a `try` at module load: if the import
fails, or if `OPENROUTER_API_KEY` is empty, `/ask` answers **503** and every other endpoint is
unaffected. Generated SQL is checked to be a single read-only `SELECT`, has a `LIMIT` appended when
unbounded (`RAG_MAX_ROWS`, default 500), and on PostgreSQL runs under a `statement_timeout`
(`RAG_SQL_TIMEOUT_MS`, default 15 000 ms).

The model is hosted on OpenRouter, which speaks the OpenAI wire protocol; `GEN_MODEL` defaults to
`deepseek/deepseek-v4-flash`. Which model answers is a configuration detail — the SQL it writes is
not, because it has to match whichever database is configured. See §4.

---

## 3. One repo, two targets

HawkShield runs on a Raspberry Pi with a radio and on a laptop with none, from the same checkout,
with no configuration difference between them. `run.py` is what makes that true.

### Mode detection

```
/proc/device-tree/model contains "raspberry pi"     ─┐
                    or                               ├─►  pi
platform.system() == "Linux" and machine in
    {aarch64, armv7l, armv6l}                       ─┘

anything else                                       ────►  laptop
```

The device tree is checked first because it is definitive; the architecture check is the fallback for
a Pi-class board that does not expose one. `--mode pi|laptop` overrides both, and the banner prints
`(forced)` when it has been. Everything downstream is a consequence of that one word.

| | Pi | Laptop |
|---|---|---|
| Detector | started (`backend.detector.cli`) | not started — nothing to capture from |
| API + dashboard | started | started |
| Database | PostgreSQL, **required** | PostgreSQL if configured, else SQLite |
| Missing/`CHANGE_ME` `DATABASE_URL` | exit 2 with instructions | falls back to `hawkshield.db`, warns, continues |
| Not root | detector cannot open a raw socket → falls back to dashboard-only with a `sudo` hint | irrelevant |
| Not Linux | n/a | live capture is refused outright; `--demo` is the way to get data |

`--detector` / `--no-detector` override the process choice independently of the mode, which is how
you get a dashboard-only Pi or force a capture attempt on a Linux laptop with a monitor-mode adapter.

### Why the laptop gets SQLite

The alternative is asking a demo machine to install and configure PostgreSQL before it can show
anything, which is a setup step that fails in front of an audience. So: if `DATABASE_URL` is unset or
still carries the `CHANGE_ME` placeholder that `.env.example` ships, laptop mode writes to a SQLite
file in the repo root and says so in the preflight output. Nothing is silently *reconfigured* — the
fallback lives in the launcher's process environment for that session only.

The Pi does not get the same courtesy, deliberately. A sensor's attack log is the product; putting it
in an unmanaged file that no backup or `pg_dump` covers, because someone forgot to set a password, is
worse than refusing to start. Pi mode exits 2 and points at `deploy/README.md`.

### The consequence: dialect-aware SQL

Two databases means `/ask` cannot assume one SQL dialect. `packet_qa._sql_dialect()` reads
`DATABASE_URL`, and two things follow from it:

1. **The prompt.** `_POSTGRES_NOTES` or `_SQLITE_NOTES` is appended to the system prompt, spelling out
   time filters, bucketing, JSON access and casts for that dialect — `NOW() - INTERVAL '24 hours'`
   versus `datetime('now', '-24 hours')`, `date_trunc` versus `strftime`, `raw->>'ssid'` versus
   `json_extract`.
2. **The executor.** SQLite reuses the app's SQLAlchemy engine, because `psycopg` cannot parse a
   `sqlite://` URL at all. PostgreSQL keeps the `psycopg` path with its server-side statement timeout.

The `SELECT`-only check and the `LIMIT` cap sit above the split and apply to both.

### Preflight

Everything the launcher checks before it starts a process, in order — each is a failure mode that
otherwise surfaces as a blank dashboard or a stack trace minutes later:

| Check | On failure |
|---|---|
| `.env` exists | copied from `.env.example` |
| `DATABASE_URL` usable | SQLite fallback (laptop) / exit 2 (Pi) |
| both model bundles in `MODEL_DIR` | fatal only if the detector was going to run |
| `frontend/out/index.html` exists | warn; the API runs without a UI |
| `python -m backend.scripts.init_db` succeeds | exit 2, with the last lines of the error and a `systemctl status postgresql` hint on the Pi |
| the port is free | exit 2, suggesting the next port |
| root, if the detector is wanted | drop to dashboard-only, print the `sudo` command |

Then it prints the local URL, the LAN URL, `/docs` and `/health`, supervises both children, and on
`SIGINT`/`SIGTERM` terminates them in reverse order with an 8-second grace period before `kill()`.
If either child exits on its own, the launcher stops the other and returns that exit code.

`run.py` is stdlib-only and imports nothing from `backend`, so a broken dependency shows up as a
child process failing with a readable traceback rather than as the launcher failing to start.

---

## 4. One process serves both the API and the UI

This is the single most consequential design decision in the deployment, and it was forced by the
hardware.

**The Pi could not run `next dev` alongside the detector.** A Next.js dev server on a Pi 4 is a Node
process with a file watcher, an incremental compiler and a JIT, competing for the same four cores and
the same RAM as a scapy sniffer that must not drop frames and a LightGBM model doing inference on
every one of them. Capture is the one part of the system with a hard real-time constraint: a frame
missed is gone. Giving that budget to a bundler is indefensible.

So the frontend is compiled away entirely:

```
next build  →  frontend/out/   (static HTML/CSS/JS, trailingSlash: true)
                     │
                     ▼
FastAPI:  app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True))
```

In production there is **no Node process at all**. `frontend/out/` is a directory of files, and
serving files is something uvicorn already does for free.

Consequences, all of them good:

| | |
|---|---|
| **One port, one service** | `http://<pi-ip>:8000` serves both `/dashboard/` and `/attacks`. Nothing to reverse-proxy. |
| **No CORS in production** | The UI calls `/attacks`, not `http://<pi>:8000/attacks`. `NEXT_PUBLIC_API_BASE` is empty in a production build, so every request is same-origin. `CORS_ORIGINS` only matters for laptop `next dev`. |
| **No second web server** | No nginx, no Caddy, no systemd unit to keep in sync. |
| **Ordering is load-bearing** | Routers are registered **first** in `create_app()`, and the `/` mount **last**. A catch-all mount registered first would shadow every API route. |
| **Absence degrades cleanly** | `frontend_dist.is_dir()` is checked before mounting. On a dev box with no build, the API starts normally and simply has no UI. |

The costs are real too, and they are documented where they bite:

* The export must be built on a machine with internet, because `app/layout.tsx` imports `Inter` from
  `next/font/google` and that font is fetched at build time. See
  [`deployment-pi.md`](deployment-pi.md).
* `NEXT_PUBLIC_*` values are inlined at build time. A stray `.env.local` with
  `NEXT_PUBLIC_API_BASE=http://localhost:8000` bakes the wrong origin into the bundle and the deployed
  dashboard tries to reach the *browser's* machine. `frontend/README.md` documents the `grep` that
  catches it.
* Leaflet marker PNGs are committed to `frontend/public/leaflet/` so markers render offline; only the
  OpenStreetMap basemap tiles need internet, and the map degrades to a labelled dark background
  without them.

---

## 5. Configuration

Every tunable is environment-driven through one `pydantic-settings` object,
`backend/app/config.py::settings`, loaded from the repo-root `.env`. There are no hardcoded paths,
credentials or thresholds anywhere in the codebase, and `backend/detector/*` reads the same object
via `backend/detector/_config.py::get_settings()`.

The full table is in [`CONTRACT.md` §3](CONTRACT.md) and every variable is commented in
`.env.example`. The ones that change behaviour rather than location:

| Variable | Default | Effect |
|---|---|---|
| `MODEL_VERSION` | `auto` | `auto` \| `v1` \| `v2`. `auto` prefers a valid v2 artefact and falls back to v1; `v2` refuses to downgrade silently and exits `2` on a spec mismatch |
| `V2_MODEL` / `V2_META` | `hawkshield_v2.onnx` / `hawkshield_v2_meta.json` | the v2 artefact and its metadata inside `MODEL_DIR` |
| `V2_BATCH_FRAMES` | `32` | frames per onnxruntime call — throughput vs. up to N frames of detection delay |
| `V2_ORT_THREADS` | `2` | onnxruntime intra-op threads. `0` = the runtime default, which spin-waits between calls and measured 2.4× slower end to end |
| `STAGE1_THRESHOLD` | `0.40` | raise to cut volume, lower to catch more (and log more noise). v1: `P(attack)`; v2: `1 − P(Normal)` |
| `STAGE2_THRESHOLD` | `0.80` | confidence floor on the attack name — in v1, the only guard against its missing "unknown" class |
| `CAPTURE_IFACE` / `CAPTURE_CHANNEL` | `wlan1` / `6` | must match what `monitor_mode.sh` was given |
| `TARGET_SSID` | *(empty)* | soft filter — frames whose parsed SSID differs are skipped |
| `BATCH_SIZE` / `BATCH_FLUSH_SECONDS` | `20` / `2.0` | write latency vs. round-trip count |
| `OPENROUTER_API_KEY` | *(empty)* | empty ⇒ `/ask` returns 503, everything else works |
| `GEN_MODEL` | `deepseek/deepseek-v4-flash` | which OpenRouter model answers `/ask` |
| `DATABASE_URL` | `postgresql+psycopg2://…CHANGE_ME…` | also selects the SQL dialect `/ask` generates (§3) |

One rule is worth stating because it used to be a security bug: for `MODEL_DIR`, `FRONTEND_DIST` and
`AP_LOCATIONS_FILE`, **a blank value means "use the packaged default"**, not "the repo root".
`.env.example` ships those three blank on purpose. A blank `FRONTEND_DIST` previously resolved to the
repo root and FastAPI happily served the entire checkout — `.env` included — as static files.
`Settings._blank_means_default` now intercepts that, and
`backend/tests/test_runtime_config.py` pins it.

---

## 6. Data model

One table matters: `packets`, declared once in `backend/app/models.py`. Its columns are the identity
and radio fields from `raw_min`, the two model probabilities, the predicted label, and the `raw` JSON
blob. Full column list in [`CONTRACT.md` §2](CONTRACT.md).

A second table, `documents`, exists for legacy-schema compatibility. No endpoint depends on it.

`ts` is set by the detector at classification time, in UTC, not parsed from the frame — so the column
means "when HawkShield decided this was an attack", which is what the heatmap and report windows are
asking about.

---

## 7. Where the accuracy actually comes from

The architecture above was always sound. The **v1 models** plugged into step 3 were not, for two
reasons that are now understood, fixed in v2, and worth keeping on the page because they are the
reason the v2 design looks the way it does.

**v1 failure 1 — training and inference derived features in different code.** The models were trained
on tshark columns; the detector runs scapy. **16 of the 29 numeric features could not be produced
live at all.** They arrived `None` on every frame and were imputed to training medians that happen to
sit where the model expects attack traffic — so the original detector flagged almost everything and
looked like it worked. Fixing the extractor removed that accident and exposed the real behaviour: on
the 20 000-frame deauth sample, ~97 % of which are genuine deauthentication frames, stage 1 flags 82,
and stage 2 labels every frame of every sample capture `Krack`.

**v1 failure 2 — `frame.time_relative` was leakage.** A feature computed in step 2 purely as a
bookkeeping value carried **41.9 % of stage-1's split gain**, while encoding which capture session a
row came from rather than whether the traffic is malicious. `radiotap.channel.freq` carried another
~8.9 % and encoded the band. Together they meant stage 1 was largely answering "does this look like
my training capture?" Nulling `frame.time_relative` on the deauth sample flips detection from 0.41 %
of frames to 100 %; nulling `radiotap.channel.freq` flips it to 0 %.

**What step 2 and step 3 do about it now.** Both failures shared one root cause — training features
and inference features were defined in different places by different code — so v2 defines them once.
`feature_spec.derive_frame_features()` is the only derivation, called by the AWID3 preprocessor and by
the live extractor alike; a feature that cannot be produced live cannot enter the spec.
`feature_spec.EXCLUDED_COLUMNS` names every banned field *with its reason, in code*, and a test
enforces it: session identity, raw identifiers, and everything above the MAC layer. Nothing is
imputed — NaN reaches the model as a learned sentinel plus a mask channel. Evaluation holds out whole
50 000-frame blocks rather than shuffling rows. And `V2Pipeline` refuses to load an artefact whose
feature space is not the one the extractor produces, which is the specific condition that went
unnoticed in v1 for its entire life.

**What that does not entitle anyone to claim.** No v2 weights have been trained yet, so there is no
v2 accuracy number, and this document will not invent one. When training completes, the measurements
land in `ml/reports/eval_report.md`. Read them against the protocol's own limit: whole blocks are held
out, but they share the session and testbed of the training blocks, so the numbers say "generalises
across time within this testbed", not "generalises to your network".

The full v1 post-mortem, the ablation table and the reproduction commands are in
[`../models/README.md` §3.5](../models/README.md); the design that replaces it is in
[`models.md`](models.md) and drawn in [`model-pipeline.md`](model-pipeline.md).
