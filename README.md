# HawkShield

**Wi-Fi intrusion *detection* for the Raspberry Pi 4** — monitor-mode 802.11 capture, a causal
temporal CNN over a 46-feature contract shared by training and inference, a PostgreSQL attack log,
and a dashboard plus natural-language assistant served from a single FastAPI process. One launcher,
`python run.py`, runs it on the Pi or on a laptop.

![Python](https://img.shields.io/badge/python-3.11-3776AB)
![FastAPI](https://img.shields.io/badge/FastAPI-0.116-009688)
![Next.js](https://img.shields.io/badge/Next.js-15-000000)
![ONNX Runtime](https://img.shields.io/badge/ONNX%20Runtime-causal%20TCN-005CED)
![LightGBM](https://img.shields.io/badge/LightGBM-4.6-9ACD32)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%204%20%2F%20Bookworm-C51A4A)
![Licence](https://img.shields.io/badge/licence-proprietary-lightgrey)

> **Scope note — this is an IDS, not an IPS.** HawkShield observes, classifies, stores and presents.
> It does **not** disconnect clients, block MACs, talk to a WLAN controller, or send alerts. Earlier
> descriptions of this project claimed "real-time prevention" and an email-report endpoint; neither
> exists in this codebase. See [Roadmap — not yet implemented](#roadmap--not-yet-implemented).

> **Model status — read this before trusting a label.**
> **v1 leaked, and it is understood exactly how.** Training and inference derived features in
> different code (16 of 29 features were permanently NULL live and mean-imputed to training medians),
> and `frame.time_relative` — seconds since capture start — was 42 % of stage-1's decision while
> encoding nothing but which capture session a row came from.
> **v2 is the answer to both**, and it is described throughout this README: one derivation function
> called by training *and* inference, 46 features that can all actually be produced on a
> monitor-mode Pi, 9 classes, whole capture blocks held out of the split, and a runtime that refuses
> to load a model whose feature space is not the one the extractor produces.
> **v2 is trained and shipping.** On 5,943,908 held-out frames across all nine classes:
> **LightGBM 0.9907 macro-F1**, causal TCN 0.9856 — the tree won a fair head-to-head on the same
> grouped split, so the tree is what the detector loads. Ablating the top feature costs 0.0007
> retrained (v1's equivalent flipped detection between 0 % and 100 %).
> **Read the caveat that comes with it:** AWID3 recorded each attack once, so held-out blocks share
> the session, testbed and radio hardware of the training blocks. That figure measures generalisation
> across time within one recording, not across deployments — an upper bound on field performance.
> Post-mortem and design: [Model status](#model-status--v1-post-mortem-and-the-v2-answer),
> [`models/README.md`](models/README.md), [`docs/models.md`](docs/models.md).
> Diagrams: [`docs/model-pipeline.md`](docs/model-pipeline.md).

![HawkShield project poster](docs/assets/Project_Poster.jpg)

---

## Quickstart — one command

```bash
python run.py
```

`run.py` is the only thing you have to run. It works out where it is, checks everything that can go
wrong before it goes wrong, and starts the right processes for that machine:

| Detected | What starts | Database |
|---|---|---|
| **Raspberry Pi** — `/proc/device-tree/model`, then Linux + `aarch64` / `armv7l` | detector (live 802.11 capture) **+** API **+** dashboard | PostgreSQL, **required** — the launcher refuses to start without one |
| **Anything else** — laptop | API **+** dashboard, reading whatever is already in the database | PostgreSQL if configured, otherwise a local SQLite file it creates for you |

That split is the whole point: **the same checkout runs on both machines, with no config edits on the
laptop.** Use the project's own interpreter — `.venv/bin/python run.py`, or
`.venv/Scripts/python.exe run.py` on Windows — and run it **from the repo root**.

### Try it without hardware

No Wi-Fi adapter, no database, no configuration:

```bash
python run.py --demo                    # replay a sample attack capture, then serve the dashboard
python backend/scripts/check_saqr.py    # optional: verify the assistant is configured
```

Open the URL it prints. `--demo` replays one of the bundled `.pcapng` captures through the real
detection pipeline — whichever generation `MODEL_VERSION` resolves to — and stores the results, so the
dashboard, the reports and the assistant all have genuine data to work with.

```
  HawkShield
  Windows AMD64
  detected: LAPTOP

-- checks ------------------------------------------------------------
  OK    .env found
  WARN  no usable DATABASE_URL -- using a local SQLite file for this session
        sqlite:///D:/HawkShield/hawkshield.db
  OK    model bundles present
  OK    dashboard build found (frontend/out)
  OK    database reachable, schema ready

-- demo data ---------------------------------------------------------
        replaying assoc_flood_raw_decrypted.pcapng (1500 frames) into the database...
        persisted (p2>=0.80): 592 (39.47%)

-- starting ----------------------------------------------------------
        detector off -- dashboard reads existing data only

  Dashboard   http://localhost:8000
              http://192.168.3.11:8000   (from another device on this network)
  API docs    http://localhost:8000/docs
  Health      http://localhost:8000/health

  Ctrl-C to stop
```

*(that run was `python run.py --demo --demo-frames 1500`; the default is 4000 frames)*

### What it does before starting anything

1. Creates `.env` from `.env.example` if it is missing.
2. Picks a database. If `DATABASE_URL` is unset or still contains `CHANGE_ME`: **laptop** mode falls
   back to a local SQLite file (`hawkshield.db` in the repo root) and says so; **Pi** mode stops with
   exit 2 and tells you to configure PostgreSQL.
3. Checks both **v1** `.joblib` bundles are in `models/`. **Known gap:** this check has not been
   updated for v2, so a checkout carrying a valid v2 ONNX artefact and no v1 bundles would be refused
   even though the detector would run fine on it. Harmless today, since both bundles ship — but do not
   delete them. Recorded in [`docs/CONTRACT.md` §8.4](docs/CONTRACT.md).
4. Checks for a dashboard build at `frontend/out` — warns, does not fail, if there is none.
5. Runs the schema migration (`python -m backend.scripts.init_db`).
6. Checks the port is free, and suggests the next one if it is not.
7. On the Pi, checks for root. Without it, the detector cannot open a raw socket, so it falls back to
   dashboard-only and prints the `sudo` hint.

Then it prints the dashboard URL, the LAN URL to open on a phone, `/docs` and `/health`.
**Ctrl-C stops everything cleanly.**

### Flags

| Flag | Default | Effect |
|---|---|---|
| `--mode auto\|pi\|laptop` | `auto` | override the detection — e.g. force laptop behaviour on the Pi |
| `--host` | `0.0.0.0` | bind address |
| `--port` | `8000` | serve somewhere else |
| `--demo` | off | replay a sample capture into the database before starting |
| `--demo-capture PATH` | `data/samples/assoc_flood_raw_decrypted.pcapng` | which capture `--demo` replays |
| `--demo-frames N` | `4000` | how many frames `--demo` replays |
| `--detector` / `--no-detector` | on for Pi, off for laptop | force live capture on or off |
| `--iface` / `--channel` | from `.env` | passed straight to the detector CLI |
| `--reload` | off | uvicorn auto-reload, for development |

The systemd path is still the right answer for an unattended Pi — see
[Full Raspberry Pi install](#full-raspberry-pi-install-systemd).

---

## Contents

| Document | What is in it |
|---|---|
| [`docs/model-pipeline.md`](docs/model-pipeline.md) | **The diagrams** — whole system, feature derivation, the network, the split, the live path |
| [`docs/architecture.md`](docs/architecture.md) | Frame-by-frame data flow, both model generations, why one process serves both API and UI |
| [`docs/deployment-pi.md`](docs/deployment-pi.md) | Full Raspberry Pi walkthrough — OS, adapter, PostgreSQL, systemd, model copy, verification |
| [`docs/api.md`](docs/api.md) | Every endpoint, with parameters and real example responses |
| [`docs/demo.md`](docs/demo.md) | **Demo & real-time-testing runbook** — the two-command laptop demo, `/simulate`, the failover, the over-the-air test |
| [`docs/models.md`](docs/models.md) | v2 pipeline, the 46-feature contract, the 9 classes, thresholds, excluded classes |
| [`models/README.md`](models/README.md) | Full model card — v2 design and evaluation protocol, **and the v1 post-mortem** |
| [`ml/README.md`](ml/README.md) | The training pipeline: one command, the split protocol, how to read the reports |
| [`deploy/README.md`](deploy/README.md) | Operator runbook: installer flags, day-to-day commands, troubleshooting |
| [`frontend/README.md`](frontend/README.md) | Dashboard pages, static-export build, offline map behaviour |
| [`data/README.md`](data/README.md) | The six sample captures, AWID3, and the legacy v1 dataset |
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Normative interface contract (schema, env vars, HTTP shapes, model layout) |

---

## Features

| | Capability | Where |
|---|---|---|
| 📡 | **Monitor-mode capture** — scapy `sniff(store=False)` on a pinned channel, with ENETDOWN recovery and a 2 s heartbeat | `backend/detector/capture.py` |
| 📜 | **One feature contract** — 46 features and one `derive_frame_features()`, called by **both** the AWID3 preprocessor and the live extractor. A feature that cannot be produced on a monitor-mode Pi cannot enter the spec, and `EXCLUDED_COLUMNS` names every banned field with its reason | `backend/detector/feature_spec.py` |
| 🧮 | **Honest feature extraction** — a field the frame does not carry becomes NaN, never invented and never imputed; NaN reaches the model as a learned sentinel plus a mask channel | `backend/detector/features.py` |
| 🧠 | **Causal dilated TCN** — 80 471 parameters, ONNX fp32, a 127-frame **past-only** receptive field, one prediction per frame. A unit test perturbs the future and asserts the past output is bit-identical | `ml/model.py`, `backend/detector/pipeline.py` |
| 🏷️ | **Nine classes** — `Normal` + `Deauth`, `Disas`, `(Re)Assoc`, `RogueAP`, `Krack`, `Kr00k`, `Evil_Twin`, `SSDP`, gated by `STAGE1_THRESHOLD` (0.40) and `STAGE2_THRESHOLD` (0.80) | `backend/detector/feature_spec.py` |
| 🛡️ | **A runtime that refuses a mismatch** — `V2Pipeline` will not load an artefact whose spec version, class list, feature list or feature order disagrees with the running code. v1 is selectable and is the automatic fallback | `backend/detector/pipeline.py` |
| 🎓 | **Reproducible training** — one command from the AWID3 zip to an ONNX artefact, with whole capture blocks held out and a standing leakage ablation | `ml/run_training.ps1`, `ml/train.py` |
| 💾 | **Attack-only persistence** — batched inserts into PostgreSQL `packets`; normal traffic is classified and dropped | `backend/detector/sink.py` |
| 🌐 | **Analytics API** — counts, per-label breakdown, top offenders, channel usage, day×hour heatmap | `backend/app/routers/attacks.py` |
| 🗺️ | **Map utilities** — AP inventory, per-source average RSSI, RSSI-weighted centroid origin estimate | `backend/app/routers/maps.py` |
| 🧾 | **Reports** — JSON summary and a one-page A4 PDF export (ReportLab) | `backend/app/routers/reports.py` |
| 🧠 | **Saqr, the assistant (optional)** — a tool-calling agent over **OpenRouter** (default DeepSeek V4 Flash) with eight tools that call the same Python the dashboard endpoints call, so its numbers and the dashboard's cannot disagree. Bilingual (en/ar), streams over SSE, and refuses to reach any table but `packets`. Serves both `POST /agent/ask` and the legacy `POST /ask` | `backend/app/agent/` |
| 🖥️ | **Dashboard** — Next.js 15 static export served by FastAPI itself at `/`, same-origin, no second web server | `frontend/` |
| 🔁 | **Offline replay** — score any `.pcapng` through the exact live code path, no radio required | `backend/scripts/replay_pcap.py` |
| 🚀 | **One launcher** — auto-detects Pi vs laptop, preflights `.env`/database/models/build/port, starts what that machine needs | `run.py` |

---

## Architecture

```
                Raspberry Pi 4  (Raspberry Pi OS Bookworm, Python 3.11)
   ┌──────────────────────────────────────────────────────────────────────┐
   │                                                                      │
   │  USB Wi-Fi adapter (wlan1, monitor mode, pinned channel)             │
   │            │                                                         │
   │            │  802.11 frames + RadioTap                               │
   │            ▼                                                         │
   │  ┌───────────────────────── hawkshield-detector.service (root) ───┐  │
   │  │  scapy sniff                                                   │  │
   │  │      → scapy_to_raw()                                          │  │
   │  │      → feature_spec.derive_frame_features()  →  46 features    │  │
   │  │                          │   (the same call training makes)    │  │
   │  │                          ▼                                     │  │
   │  │      ring buffer: 126 frames of past-only context              │  │
   │  │      causal TCN, ONNX fp32, 32 frames per call                 │  │
   │  │                          │  9 class scores per frame           │  │
   │  │                          ▼                                     │  │
   │  │        p1 = 1 − P(Normal)                                      │  │
   │  │                   p1 < 0.40 ──────────────► drop (not stored)  │  │
   │  │                          │ p1 ≥ 0.40                           │  │
   │  │                          ▼                                     │  │
   │  │        label = argmax over the 8 attack classes;  p2 = P(label)│  │
   │  │                   p2 < 0.80 ──────────────► drop (not stored)  │  │
   │  │                          │ p2 ≥ 0.80                           │  │
   │  │                          ▼                                     │  │
   │  │              PacketSink  (batch 20 rows / 2.0 s)               │  │
   │  └───────────────────────────┬────────────────────────────────────┘ │
   │                              │ INSERT                               │
   │                              ▼                                      │
   │                    PostgreSQL :5432   table `packets`                │
   │                              ▲                                      │
   │                              │ SELECT                               │
   │  ┌───────────────────────────┴──── hawkshield-api.service ────────┐  │
   │  │  uvicorn :8000                                                 │  │
   │  │    JSON API   /health /attacks /reports/* /map/* /ask …        │  │
   │  │    StaticFiles mount at "/"  →  frontend/out  (Next.js export) │  │
   │  └────────────────────────────────────────────────────────────────┘  │
   │                              ▲                                       │
   └──────────────────────────────┼───────────────────────────────────────┘
                                  │  http://<pi-ip>:8000   (same origin)
                          ┌───────┴────────┐
                          │  laptop browser │
                          └────────────────┘
```

One web process, one port. The API routes are registered first and the static export is mounted last
at `/`, so the catch-all can never shadow an endpoint. Full narrative in
[`docs/architecture.md`](docs/architecture.md); the same flow **drawn**, including the training side
that shares `derive_frame_features()` with the live path, is in
[`docs/model-pipeline.md`](docs/model-pipeline.md).

The detector box above is **v2**. Selected by `MODEL_VERSION` (`auto` | `v1` | `v2-tcn` | `v2-gbdt`),
`auto` resolves to **`v2-gbdt`** — the trained LightGBM winner ships in `models/`. The v1 two-stage
path and the v2 TCN remain selectable, and `auto` falls back to them only if the GBDT artefact is
absent or fails its spec check.

---

## Hardware

| Item | Requirement |
|---|---|
| Board | Raspberry Pi 4 (4 GB or more recommended), Raspberry Pi OS **Bookworm**, Python 3.11 |
| Storage | microSD ≥ 16 GB, or USB SSD |
| **Capture radio** | **A USB Wi-Fi adapter that supports monitor mode.** |
| Uplink | The Pi's built-in `wlan0` or Ethernet, for management/SSH |

> ⚠️ **The Pi 4's built-in `wlan0` generally cannot do monitor mode.** Its Broadcom/Cypress firmware
> either refuses the mode switch or silently captures nothing. You need a second, external adapter.
> Known-good chipsets: **Atheros AR9271**, **Ralink RT3070 / RT5372**, **MediaTek MT7601U**,
> **Realtek RTL8812AU** with the aircrack-ng driver. It normally enumerates as `wlan1` — confirm with
> `ip -br link`.

The default configuration pins the adapter to **2.4 GHz channel 6**. The adapter's channel,
`CAPTURE_CHANNEL` in `.env`, and the argument given to `monitor_mode.sh` must all agree.

---

## Full Raspberry Pi install (systemd)

`python run.py` is enough to demo on a Pi, and it is what you want when you are standing next to it.
For an unattended sensor that comes back after a reboot, install the two systemd units instead.

Note the one hard difference from the laptop: **the Pi expects PostgreSQL.** There is no SQLite
fallback there — `run.py` exits 2 if `DATABASE_URL` is unset or still says `CHANGE_ME`, rather than
quietly writing a sensor's attack log to a file that nothing backs up.

```bash
# 1. Clone
git clone <your-repo-url> ~/HawkShield
cd ~/HawkShield

# 2. Install. The FIRST run stops on purpose (exit 3) after copying .env.example -> .env,
#    because the installer will not invent a database password.
sudo ./deploy/install_pi.sh

# 3. Configure
nano .env          # set the DATABASE_URL password, confirm CAPTURE_IFACE / CAPTURE_CHANNEL

# 4. Install for real: apt deps, PostgreSQL role + DB, venv, schema, systemd units
sudo ./deploy/install_pi.sh

# 5. Put the capture adapter into monitor mode on the channel you configured
sudo ./deploy/monitor_mode.sh wlan1 6

# 6. Start the two services
sudo systemctl start hawkshield-api
sudo systemctl start hawkshield-detector

# 7. Verify
curl -s http://localhost:8000/health
hostname -I                     # then open http://<pi-ip>:8000 in a browser
```

Steps 5–7 have a launcher equivalent, useful when a unit will not start and you want the output in
front of you — stop `hawkshield-api` first, or port 8000 is taken:

```bash
sudo ./deploy/monitor_mode.sh wlan1 6
sudo .venv/bin/python run.py            # detector + API + dashboard, in the foreground
```

### Build the frontend on a machine with internet

`frontend/out/` is **git-ignored**, so a fresh clone has no dashboard until you build it — and the
build **needs network access**: `app/layout.tsx` imports `Inter` from `next/font/google`, which is
fetched at build time. An offline Pi build fails there.

```bash
# on any networked machine (laptop is fine)
cd frontend && npm ci && npm run build      # -> frontend/out/
# then copy frontend/out/ to the Pi at $FRONTEND_DIST (default <repo>/frontend/out)
```

If the dashboard 404s but `/health` answers, the export is simply missing. See
[`frontend/README.md`](frontend/README.md) for the `NEXT_PUBLIC_API_BASE` caveat before you build.

---

## Laptop / development mode

Nothing about HawkShield requires a Pi except the radio. You can run the whole stack on a laptop and
feed it captures instead of live frames.

```bash
python -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt      # runtime + pytest + httpx

.venv/bin/python run.py --demo                             # .env, database, schema, data, server
```

That is the whole setup. `run.py` copies `.env.example` to `.env`, falls back to a SQLite file
because the shipped `DATABASE_URL` still says `CHANGE_ME`, creates the schema and loads sample
attacks. You only need a `DATABASE_URL` of your own if you want the laptop to read the Pi's
PostgreSQL.

Doing it by hand is still supported, and is what `run.py` runs underneath:

```bash
cp .env.example .env
.venv/bin/python -m backend.scripts.init_db                # create the schema
.venv/bin/uvicorn backend.app.main:app --reload --port 8000
```

On Windows use `.venv/Scripts/python.exe`. Run **everything from the repo root** — `backend` is a
package and the module paths (`backend.app.main:app`, `python -m backend.detector.cli`) assume it.
`run.py --reload` is the launcher's equivalent of `uvicorn --reload`.

Two frontend options:

| Mode | Command | `NEXT_PUBLIC_API_BASE` |
|---|---|---|
| Static export served by FastAPI (production shape) | `cd frontend && npm run build` | empty — same origin |
| `next dev` hot reload against a running API | `cd frontend && npm run dev` | `http://localhost:8000` or `http://<pi-ip>:8000` |

`next dev` needs the API's `CORS_ORIGINS` to include `http://localhost:3000` (it does by default).
Interactive API docs are at `http://localhost:8000/docs`.

---

## Endpoints

All routes are registered **without a prefix**. Full request/response detail in
[`docs/api.md`](docs/api.md).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | DB reachability, packet count, latest timestamp, **`model_version` / `spec_version` / `artefact_spec_version`**, version |
| GET | `/attacks?limit=&offset=` | Raw `packets` rows, newest first |
| GET | `/packets/count` | `{"count": int}` |
| GET | `/attacks/analysis` | Count per label — always all **eight** attack keys, zero-filled |
| GET | `/top-offenders` | Source MACs by volume (key is `wlan_sa`) |
| GET | `/channel-usage` | Frame counts per RadioTap frequency |
| GET | `/heatmap-attack` | 7 days × 24 hours intensity grid, Sunday first |
| GET | `/map/ap-locations` | Configured AP inventory |
| GET | `/map/source-rssi?sa=&minutes=` | Average RSSI per BSSID for one source MAC |
| POST | `/map/estimate-origin` | RSSI-weighted centroid of the supplied APs |
| GET | `/reports/summary?days=` | Totals by type + headline figures |
| POST | `/reports/export` | One-page A4 PDF (`application/pdf`) |
| POST | `/ask` | Natural-language question → SQL or knowledge-base answer. **503 without `OPENROUTER_API_KEY`** |
| POST | `/simulate` | Replay held-out AWID3 rows through the **real** model and persist genuine detections — the testing / demo control, not a mock |
| GET | `/stream` | Server-Sent Events, one event per new detection row — the dashboard's live feed |
| GET | `/` `/home/` `/dashboard/` `/attacks/` `/control/` `/rag/` | The static dashboard (`/control/` hosts the Simulate control) |

**Removed on purpose:** `POST /detector/start` and `POST /reports/email`. The detector is a systemd
service, not an HTTP-controlled subprocess, and the email endpoint was a stub that never sent
anything. Do not look for them.

### Verified integration results

Against a live instance with the frontend built:

```
/health /packets/count /attacks/analysis /top-offenders /channel-usage
/heatmap-attack /map/ap-locations /attacks            -> 200 application/json
/ /home/ /dashboard/ /attacks/ /rag/                  -> 200 text/html
/leaflet/marker-icon.png                              -> 200 image/png
/reports/export                                       -> 200 application/pdf
/ask (no OPENROUTER_API_KEY)                          -> 503
```

---

## The `/ask` assistant

Optional, and the only part of HawkShield that talks to anything outside the box. It runs through
[OpenRouter](https://openrouter.ai), which speaks the OpenAI wire protocol, so one key reaches every
model below. Get one at <https://openrouter.ai/keys> and put it in `.env`:

```ini
OPENROUTER_API_KEY=sk-or-v1-...
```

With the key empty or unset, the API starts normally and **only** `POST /ask` returns 503. No other
endpoint and no other dashboard page is affected.

### Model choice

`GEN_MODEL` picks the model. The default was chosen for two things this workload leans on hard —
clean SQL generation and strict JSON adherence, because the router's whole contract is a single JSON
object containing one `SELECT`.

| `GEN_MODEL` | Why you would pick it | ~$ / M tokens (in / out) |
|---|---|---|
| **`deepseek/deepseek-v4-flash`** *(default)* | DeepSeek V4 Flash. Strong SQL, strict JSON, 1M-token context | 0.08 / 0.16 |
| `z-ai/glm-5.3-flash` | GLM 5.3 Flash — close second, different failure modes | 0.075 / 0.25 |
| `qwen/qwen3.7-flash` | cheapest of the four | 0.03 / 0.13 |
| `qwen/qwen3-235b-a22b-2507` | largest and slowest; reach for it only if the small models misroute | 0.09 / 0.55 |

Prices move; `check_saqr.py` prints the live figure from OpenRouter's catalogue.

Three more optional variables: `OPENROUTER_BASE_URL` (default `https://openrouter.ai/api/v1` —
change it only for a proxy or a self-hosted OpenAI-compatible endpoint), and `OPENROUTER_SITE_URL` /
`OPENROUTER_APP_NAME`, which are the attribution headers OpenRouter shows on its dashboard.

> **This has nothing to do with the detection model.** The assistant is a hosted LLM that reads the
> `packets` table. The *detector* is the model in `models/` — the v2 ONNX graph, or the v1 bundles
> while no v2 artefact exists — and it runs entirely offline on every frame. Changing `GEN_MODEL`
> does not make a label more trustworthy: a better assistant reads the same rows more fluently. See
> [Model status](#model-status--v1-post-mortem-and-the-v2-answer).

### Pre-flight check

```bash
python backend/scripts/check_saqr.py
```

It verifies, in order: a key is configured → the configured model actually exists on OpenRouter (and
prints its context length and live price) → the model answers a knowledge-base question in `DOCS`
mode → it generates valid SQL against the real schema in `SQL` mode → that SQL executes against your
database. **Exit code 0 means `POST /ask` will work.** Anything else prints what to fix.

`--skip-db` checks the model only, generating the SQL without running it — use it when the database
is not up yet, or to tell "the model is broken" apart from "the database is unreachable".

Verified against the live API on the SQLite demo database:

| Question | Generated SQL | Answer |
|---|---|---|
| *How many attacks have been detected in total?* | `SELECT COUNT(*) AS count FROM packets` | "The total number of attacks detected is 592." |
| *Which source MAC address is the top offender?* | `SELECT src_mac, COUNT(*) AS count FROM packets GROUP BY src_mac ORDER BY count DESC LIMIT 1` | — |

### It knows which database it is talking to

The generated SQL matches whatever `DATABASE_URL` points at: **PostgreSQL** on the Pi, **SQLite** on
a laptop demo. The system prompt carries dialect-specific notes, and the executor runs SQLite through
the app's SQLAlchemy engine instead of psycopg. Verified: on SQLite it emits
`ts >= datetime('now', '-24 hours')` rather than the PostgreSQL `NOW() - INTERVAL '24 hours'`, which
would simply have failed.

---

## Repository layout

```
HawkShield/
├── backend/
│   ├── app/                    FastAPI only — must not import backend.detector.*
│   │   ├── config.py             pydantic-settings; every component reads this object
│   │   ├── db.py                 engine, SessionLocal, Base, get_db(), init_db()
│   │   ├── models.py             Packet / Document ORM — the only schema declaration
│   │   ├── schemas.py            pydantic request/response models
│   │   ├── main.py               app factory: routers first, static mount last
│   │   ├── routers/              health.py attacks.py reports.py maps.py ask.py simulate.py stream.py
│   │   ├── agent/                Saqr: tools, loop, guards, SSE events
│   │   └── rag/                  knowledge/attacks.md (the RAG module is gone)
│   ├── detector/               capture + inference — must not import backend.app.routers.*
│   │   ├── feature_spec.py       THE CONTRACT: 46 features, 9 classes, derive_frame_features()
│   │   ├── features.py           scapy_to_raw() + packet_to_features_v2(); v1's packet_to_row()
│   │   ├── pipeline.py           V2Pipeline (ONNX) + Stage1/Stage2/TwoStagePipeline, Verdict
│   │   ├── capture.py            monitor mode, sniff loop, heartbeat, signal handling
│   │   ├── sink.py               PacketSink — batched writes
│   │   └── cli.py                argparse entrypoint
│   ├── scripts/                init_db.py, verify_models.py, replay_pcap.py,
│   │                           check_saqr.py, check_frontend.py
│   ├── config/                 ap_locations.json
│   ├── tests/                  pytest suites (301 tests)
│   └── requirements*.txt
├── ml/                         training — runs on a laptop/GPU, never on the Pi
│   ├── run_training.ps1 / .sh    one command: deps → data → train → evaluate → export
│   ├── prepare_awid3.py          streams the AWID3 zip → Parquet, via feature_spec
│   ├── windows.py                grouped split, causal windowing, inference tiling
│   ├── model.py                  the causal dilated TCN + assert_causal()
│   ├── train.py                  TCN and the LightGBM baseline on the identical split
│   ├── evaluate.py               held-out blocks + the leakage ablation
│   ├── export_onnx.py            → models/hawkshield_v2.onnx (+ int8, + meta)
│   └── reports/                  train_report.md, eval_report.md
├── frontend/                   Next.js 15 / React 19 / Tailwind v4 → static export in out/
├── models/                     v1 bundles + README.md (the model card). v2 ONNX lands here
├── data/                       samples/*.pcapng (6 captures) + README.md
├── deploy/                     install_pi.sh, monitor_mode.sh, postgres_setup.sql, 2 × .service
├── docs/                       CONTRACT.md, model-pipeline.md, architecture.md, deployment-pi.md,
│                               api.md, models.md
├── notebooks/                  v1 only: EDA.ipynb, binary_classifier.ipynb, multiclass_classifier.ipynb
├── run.py                      the launcher — auto-detects Pi vs laptop, starts what it needs
├── .env.example                every variable, documented — copy to .env
└── LICENSE
```

`_work/` (git-ignored) is where training puts its intermediates: `_work/awid3_v2/` for the Parquet
shards and `_work/models_v2/` for checkpoints and `split.json`.

---

## Training the model

Training runs on a laptop or workstation with a GPU. **Never on the Pi** — it reads a 14.7 GB archive,
wants PyTorch and ~4.5 GB of RAM, and the Pi's job is to load a finished model, not to build one.

```powershell
.\ml\run_training.ps1 -Fresh          # Windows
```
```bash
./ml/run_training.sh --fresh          # Git Bash / WSL
```

One command: dependency check → preprocess AWID3 → train → evaluate → export. Each stage is echoed
and a failure stops the run with the exit code and the stage name. **~50–90 minutes** end to end on an
RTX 4070 SUPER with 16 cores; 4–6 hours CPU-only.

`-Fresh` / `--fresh` re-runs AWID3 preprocessing; drop it to reuse `_work/awid3_v2/`. Other useful
variants: `--model gbdt` (tree baseline, no GPU needed), `--max-rows 2000000 --epochs 3` (fast sanity
pass on a subset of blocks), `--device cpu`, `--skip-export`.

**PyTorch is not installed for you** — it is a 2.5 GB wheel and the CUDA build is your choice:

```
.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu126
```

The run produces `models/hawkshield_v2.onnx` and `models/hawkshield_v2_meta.json` — copy both to the
Pi and restart the detector ([`docs/deployment-pi.md` §4.5](docs/deployment-pi.md)) — plus
`ml/reports/train_report.md` and `ml/reports/eval_report.md`, **which is where every accuracy number
lives**. Full detail: [`ml/README.md`](ml/README.md).

An int8 variant is also exported. **Do not ship it**: 2.6× smaller, measured ~4× *slower* — onnxruntime
has no fast int8 Conv1d kernel at these shapes.

---

## Model status — v1 post-mortem, and the v2 answer

> **Where things stand: v2 is trained and `MODEL_VERSION=auto` resolves to `v2-gbdt`.** `models/`
> holds the LightGBM winner (0.9907 held-out macro-F1), the causal TCN (0.9856, selectable), and the
> v1 bundles as a last-resort fallback. Full tables: [`models/README.md` §2.7](models/README.md) and
> [`ml/reports/eval_report.md`](ml/reports/eval_report.md).
>
> The section below is kept as the post-mortem it always was. It is the most instructive thing in
> this repository: two failures that produced a model scoring ~99 % on a random shuffle and detecting
> nothing real. Everything in v2's design is a direct response to one of them.

### What went wrong in v1

**The engineering was always sound; the v1 models did not generalise**, for two reasons that are now
measured, understood, and structurally fixed.

**1. Training and inference derived features in different code.** The bundles were trained on tshark
columns; the detector runs scapy. **16 of the 29 numeric features could not be produced live at all.**
They arrived NULL on every frame and were mean-imputed by the bundle's own `SimpleImputer` to training
medians — and the model keyed on those constants. Nothing in the system reported it.

**2. `frame.time_relative` was leakage.** Seconds since capture start carried **41.9 % of stage-1's
split gain** while encoding nothing but *which capture session a row came from*. It also drifts: a
detector up for a day feeds values near 86 400 where the model saw ~583, and restarting resets it.
`radiotap.channel.freq` carried another ~8.9 % and encoded the band — training captures were mostly
5 GHz, the Pi is pinned to 2.4 GHz.

Ablation on `data/samples/deauth_raw_decrypted.pcapng` — a 20 000-frame capture that is ~97 % genuine
deauthentication frames:

| Stage-1 input | Frames flagged |
|---|---:|
| all features correctly populated | 82 / 20 000 (**0.41 %**) |
| `frame.time_relative` forced null → imputed to 583 s | 20 000 (**100 %**) |
| `radiotap.channel.freq` forced null → imputed to 5180 MHz | 0 (**0 %**) |

Reproduce any row with the shipped tooling:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --model-version v1 --dry-run --null-feature frame.time_relative
```

A model whose output swings between 0 % and 100 % on the presence of one bookkeeping column is not
detecting anything. The original detector appeared to catch attacks because its extractor left
features null and the imputer filled them with medians that happen to sit where the model expects
attack traffic — the right answer for the wrong reason. Stage 2, correspondingly, answers `Krack` for
every frame of all six sample captures.

### What v2 does about it

| v1 failure | v2 response |
|---|---|
| two feature implementations that could drift apart | **one** `derive_frame_features()` in `backend/detector/feature_spec.py`, called by both `ml/prepare_awid3.py` and `backend/detector/features.py` |
| 16 of 29 features permanently NULL live | a feature that cannot be produced live may not enter the spec — all 46 populate across the sample captures |
| missing values mean-imputed to a training constant | NaN reaches the model as a learned sentinel plus a mask channel; nothing is imputed |
| session- and band-identity features in the model | `EXCLUDED_COLUMNS` bans them **by name, with the reason, in code**, enforced by a test |
| random row shuffle across the train/test split | whole 50 000-frame `block_id` groups held out; no window crosses a block boundary |
| feature space could silently disagree with the artefact | `V2Pipeline` refuses to load on any spec / class / feature / order mismatch — it caught a stale artefact on its first run |
| six classes, no way to say "normal" | nine classes, `Normal` among them |
| nothing would have noticed any of this | the leakage ablation is a standing part of `ml/evaluate.py` |

**What that does *not* entitle anyone to claim.** None of it is evidence that v2 works. That requires
numbers, and the numbers do not exist yet. When they do, read them against the protocol's own limit:
whole blocks are held out, but they share the session, testbed and radios of the training blocks, so
the numbers say **"generalises across time within this testbed"**, not "generalises to your network".
AWID3 recorded each attack exactly once, so leave-one-capture-out would delete the class — that is a
real constraint, stated wherever the numbers are.

### Two v1 bugs that may have misled you

* **`wlan.duration` was byte-swapped.** scapy declares the 802.11 Duration/ID field big-endian; the
  header is little-endian. A real 314 µs duration was fed to the model — and written to
  `packets.wlan_duration` — as **14 849**, on every frame since day one.
* **The dashboard rendered every `(Re)Assoc` row as `SSDP`.** An alias table round-tripped a key
  through its display string and never closed the loop, falling back to the first allowed type.
  **Any SSDP figure read off the attacks page before this fix was inflated**, and `(Re)Assoc`
  understated. The stored rows were always correct; only the rendering was wrong.

Full analysis both ways: [`models/README.md`](models/README.md). Design and rationale:
[`docs/models.md`](docs/models.md). Diagrams: [`docs/model-pipeline.md`](docs/model-pipeline.md).

---

## Offline demo — no radio needed

`data/samples/` holds six 20 000-frame `.pcapng` captures. `replay_pcap.py` pushes them through the
*same* extractor and pipeline the live detector uses — including v2's ring buffer, if a v2 artefact is
present — so what it prints is what the Pi would have done with those frames. `--model-version`
(`auto` | `v1` | `v2-tcn` | `v2-gbdt`) chooses the generation; `auto` is `v2-gbdt` in this checkout.

The launcher wraps this for you — `python run.py --demo` replays a capture into the database and then
serves the dashboard, with `--demo-capture` and `--demo-frames` to choose which and how many. Drive
the script directly when you want the analysis report rather than a dashboard:

```bash
# score one capture; --dry-run is the default, nothing touches the database
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng

# all six, first 5000 frames each, machine-readable
python -m backend.scripts.replay_pcap data/samples/*.pcapng --limit 5000 --json

# populate the database so the dashboard has something to draw
python -m backend.scripts.replay_pcap data/samples/beacon_raw_decrypted.pcapng --to-db
```

The report prints packets read, capture span, the attack-gate hit rate, persisted count, the label
distribution, and per-feature non-null coverage — that last table is the fastest way to tell whether
extraction is doing its job on a new capture. Useful flags: `--limit N`, `--threshold1/2`,
`--null-feature NAME` (repeatable — this is the leakage ablation), `--model-version`,
`--batch-frames N`, `--per-packet`, `--json`, `--model-dir`. See
[`data/README.md`](data/README.md).

---

## Real-time testing & demo mode

Two jobs: **prove the model predicts in real time**, and **never let a dead Pi ruin a demo.** The
whole layer is honest by construction — every simulated detection is a *real* model prediction on
held-out AWID3 data run through the same pipeline the Pi runs, tagged `raw.sim = true` so it can never
be confused with a live capture. It is a within-testbed result, not proof of field generalisation
([`models/README.md` §2.7.1](models/README.md)). Full operator runbook:
[`docs/demo.md`](docs/demo.md).

**`POST /simulate`** replays `data/sim/awid3_sim_corpus.parquet` (contiguous held-out AWID3 segments,
~306 KB, committed, all eight classes self-classifying at ~100%) through the real `build_pipeline` and
writes what the model flags via the same `PacketSink` the detector uses. The response is nested and
reports what the model *did*, not what was asked. Gated by `ALLOW_SIMULATION` (403 when off), capped by
`SIM_MAX_COUNT` (default 500), lightly rate-limited (429), 503 when no model or corpus loads. The
`/control` page (new, in the navbar) drives it next to a live backend readout.

**`GET /stream`** is Server-Sent Events, one event per new detection row (`id`, `ts`,
`predicted_label`, `p1`, `p2`, `src_mac`, `bssid`, `sim`), with `?since_id=N` to resume. The dashboard
uses it to upgrade its live feed and falls back to polling on error.

**Watch and self-test from the terminal:**

```bash
python -m backend.detector.cli --self-test          # exit 0 = model loads and predicts on this box
python -m backend.scripts.live_monitor --follow      # coloured console tail of detections as they land
python -m backend.scripts.live_monitor --follow --sim-only   # only /simulate rows
```

`--self-test` asserts the model loads and every crafted frame yields a complete 46-feature vector and
a finite `p1`. It deliberately does **not** assert class labels — crafted frames carry no realistic
inter-frame timing, the booster's most important feature, so a mislabel there is expected.

**Failover (plan B).** When the Pi/API is unreachable or `/health` reports `database: false`, the
dashboard shows a calm "Reconnecting…" chip, keeps the last good data on screen with an "Updated Ns
ago" stamp, and keeps the Simulate control usable — so an operator can repopulate believable,
real-model data on the spot. Composure, never fabricated numbers.

**The real proof — over the air.** `tools/inject_attack.py` transmits real 802.11 frames from a second
monitor-mode adapter against your **own** testbed and grades what the Pi detected (PASS/PARTIAL/FAIL).
It is the one test that exercises antenna → capture → model → database end to end.

> **⚠️ Legal note.** Transmitting deauth/disassoc frames against networks you do not own is illegal in
> most jurisdictions — this is for your own testbed only. The tool refuses without both
> `--i-own-this-network` and an explicit `--target-bssid`, and caps count/rate in code. A PARTIAL
> verdict (attack seen, different label) is the expected shape of the AWID3 cross-deployment gap, not a
> bug. Full guide: [`tools/README.md`](tools/README.md).

---

## Testing

```bash
python -m pytest backend/tests            # from the repo root
```

| Suite | Tests | Covers |
|---|---:|---|
| `backend/tests/test_pipeline_v2.py` | 86 | spec-mismatch refusal, streaming/batching equivalence, the GBDT rolling-aggregate reproduction, the verdict mapping, threading |
| `backend/tests/test_features_v2.py` | 57 | the v2 feature contract: derivation from real frames, the multi-value cell parser, NaN conventions, no banned field reachable |
| `backend/tests/test_rag.py` | 51 | routing, `SELECT`-only enforcement, row limiting, humanisation, error paths |
| `backend/tests/test_inject_attack.py` | 25 | the over-the-air tool: argument parsing, the safety gate, the count/rate caps, frame building — all without a radio or root |
| `backend/tests/test_features.py` | 22 | v1 feature extraction from real frames |
| `backend/tests/test_api.py` | 16 | every endpoint against a temporary database, including the `/ask` 503 path |
| `backend/tests/test_attack_sim.py` | 13 | the frame factory, class resolution, and the simulation corpus loader |
| `backend/tests/test_runtime_config.py` | 13 | dual-target regressions: blank `.env` values fall back to defaults, SQL dialect follows `DATABASE_URL`, SQLite `SELECT`s run without psycopg |
| `backend/tests/test_pipeline_pcap.py` | 9 | v1 bundle transform order, replay over the samples |
| `backend/tests/test_simulate.py` | 9 | `POST /simulate` end to end: real detections persisted, `raw.sim` tagging, the gates and caps |

**All 301 pass** (v1 shipped with 111). The one worth singling out is the causality probe: it perturbs
every *future* frame and asserts the past outputs are **bit-identical**, so a model that can see
forward fails the suite rather than quietly inflating a score.

Three more checks worth running:

```bash
python -m backend.scripts.verify_models     # v1 bundle digests, feature counts, class map
python ml/model.py                          # the causality probe, standalone (needs torch)
python backend/scripts/check_saqr.py        # the assistant end to end (needs a key + network)
python backend/scripts/check_frontend.py    # the shipped frontend/out build against this backend
cd frontend && npx tsc --noEmit             # static export builds with zero TypeScript errors
```

---

## Roadmap / not yet implemented

None of the following exists in this codebase. They are listed as future work, not as features.

- [ ] **Prevention (the "P" in IPS)** — deauthenticating or blocking a malicious source, MAC
      denylisting, WLAN-controller or RADIUS integration. HawkShield currently only observes.
- [ ] **Alerting** — email, webhooks, Slack, syslog. There is no notification path of any kind.
- [ ] **Trained v2 weights** — the pipeline, the contract and the runtime are in place; the model is
      not. Run [`ml/run_training.ps1`](ml/run_training.ps1) and commit the ONNX artefact with its
      measured numbers. Highest-value item on the list; see
      [Model status](#model-status--v1-post-mortem-and-the-v2-answer).
- [ ] **`run.py` accepting either model generation** — its preflight still hard-requires both v1
      `.joblib` bundles, so a v2-only checkout would be refused even though the detector would run
      fine. Known gap, recorded in [`docs/CONTRACT.md` §8.4](docs/CONTRACT.md).
- [ ] **A `verify_models` v2 mode** — the script inspects the joblib bundles only; the v2 check today
      is `V2Pipeline`'s own load-time validation, surfaced by `/health`.
- [ ] **Evaluation beyond one testbed** — AWID3 recorded each attack once, so the split measures
      generalisation across time within a single recording, not across deployments.
- [ ] **Channel hopping** — the adapter is pinned to one channel for the life of the process.
- [ ] **Normal-traffic sampling** — only attacks are persisted, so the table cannot be used to
      estimate a false-positive rate after the fact.
- [ ] **Multi-sensor aggregation**, mobile dashboard, cloud sync, SIEM export.

---

## Credits

Built by **Yasser**, **Mohammed**, **Haya**, **Ghala** and **Lena** as a capstone project.
Original repository: [`YasserAlbogami/Comprehensive_Capstone`](https://github.com/YasserAlbogami/Comprehensive_Capstone).

Built on FastAPI, SQLAlchemy, PyTorch, ONNX Runtime, LightGBM, scikit-learn, scapy, ReportLab,
Next.js, React, Tailwind CSS, Recharts and Leaflet. The v2 model is trained on **AWID3** (University
of the Aegean).

---

## Licence

Proprietary. Copyright (c) 2025 Yasser, Mohammed, Haya, Ghala, Lena. All rights reserved.
See [`LICENSE`](LICENSE).

Capturing 802.11 traffic you are not authorised to monitor is illegal in many jurisdictions. Run
HawkShield only against networks you own or have written permission to test.
