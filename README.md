# HawkShield

**Wi-Fi intrusion *detection* for the Raspberry Pi 4** — monitor-mode 802.11 capture, a two-stage
LightGBM classifier, a PostgreSQL attack log, and a dashboard plus natural-language assistant served
from a single FastAPI process.

![Python](https://img.shields.io/badge/python-3.11-3776AB)
![FastAPI](https://img.shields.io/badge/FastAPI-0.116-009688)
![Next.js](https://img.shields.io/badge/Next.js-15-000000)
![LightGBM](https://img.shields.io/badge/LightGBM-4.6-9ACD32)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%204%20%2F%20Bookworm-C51A4A)
![Licence](https://img.shields.io/badge/licence-proprietary-lightgrey)

> **Scope note — this is an IDS, not an IPS.** HawkShield observes, classifies, stores and presents.
> It does **not** disconnect clients, block MACs, talk to a WLAN controller, or send alerts. Earlier
> descriptions of this project claimed "real-time prevention" and an email-report endpoint; neither
> exists in this codebase. See [Roadmap — not yet implemented](#roadmap--not-yet-implemented).

> **Model status — read before trusting a label.** The pipeline works; the shipped models leak.
> Stage 1 depends heavily on `frame.time_relative`, a capture-session artefact, and stage 2 currently
> answers `Krack` for every frame of every sample capture. Details and the reproduction command are in
> [Model status](#model-status--known-training-data-leakage) and, in full, in
> [`models/README.md` §5](models/README.md).

![HawkShield project poster](docs/assets/Project_Poster.jpg)

---

## Contents

| Document | What is in it |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Frame-by-frame data flow, the two-stage design, why one process serves both API and UI |
| [`docs/deployment-pi.md`](docs/deployment-pi.md) | Full Raspberry Pi walkthrough — OS, adapter, PostgreSQL, systemd, verification |
| [`docs/api.md`](docs/api.md) | Every endpoint, with parameters and real example responses |
| [`docs/models.md`](docs/models.md) | Pipeline, classes, thresholds, feature space — short; points at the model card |
| [`models/README.md`](models/README.md) | Full model card, bundle internals, **and the leakage analysis** |
| [`deploy/README.md`](deploy/README.md) | Operator runbook: installer flags, day-to-day commands, troubleshooting |
| [`frontend/README.md`](frontend/README.md) | Dashboard pages, static-export build, offline map behaviour |
| [`data/README.md`](data/README.md) | The six sample captures and the external training dataset |
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Normative interface contract (schema, env vars, HTTP shapes, bundle layout) |

---

## Features

| | Capability | Where |
|---|---|---|
| 📡 | **Monitor-mode capture** — scapy `sniff(store=False)` on a pinned channel, with ENETDOWN recovery and a 2 s heartbeat | `backend/detector/capture.py` |
| 🧮 | **Honest feature extraction** — 29 numeric 802.11/RadioTap features per frame; a field the frame does not carry stays `None` and is imputed by the bundle, never invented | `backend/detector/features.py` |
| 🔍 | **Stage 1 — binary** LightGBM `P(attack)` against `STAGE1_THRESHOLD` (0.40) | `backend/detector/pipeline.py` |
| 🏷️ | **Stage 2 — multiclass** LightGBM over six labels (`SSDP`, `Evil_Twin`, `Krack`, `Deauth`, `(Re)Assoc`, `RogueAP`) with a `STAGE2_THRESHOLD` (0.80) confidence floor | `backend/detector/pipeline.py` |
| 💾 | **Attack-only persistence** — batched inserts into PostgreSQL `packets`; normal traffic is classified and dropped | `backend/detector/sink.py` |
| 🌐 | **Analytics API** — counts, per-label breakdown, top offenders, channel usage, day×hour heatmap | `backend/app/routers/attacks.py` |
| 🗺️ | **Map utilities** — AP inventory, per-source average RSSI, RSSI-weighted centroid origin estimate | `backend/app/routers/maps.py` |
| 🧾 | **Reports** — JSON summary and a one-page A4 PDF export (ReportLab) | `backend/app/routers/reports.py` |
| 🧠 | **`/ask` assistant (optional)** — OpenAI-backed text-to-SQL over `packets` plus Q&A from a bundled attack knowledge base; read-only `SELECT` enforcement, row cap and statement timeout | `backend/app/rag/packet_qa.py` |
| 🖥️ | **Dashboard** — Next.js 15 static export served by FastAPI itself at `/`, same-origin, no second web server | `frontend/` |
| 🔁 | **Offline replay** — score any `.pcapng` through the exact live code path, no radio required | `backend/scripts/replay_pcap.py` |

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
   │  │  scapy sniff  →  packet_to_row()  →  29 numeric features       │  │
   │  │                          │                                     │  │
   │  │                          ▼                                     │  │
   │  │        stage 1  LightGBM binary   p1 = P(attack)               │  │
   │  │                   p1 < 0.40 ──────────────► drop (not stored)  │  │
   │  │                          │ p1 ≥ 0.40                           │  │
   │  │                          ▼                                     │  │
   │  │        stage 2  LightGBM multiclass  (label, p2)               │  │
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
[`docs/architecture.md`](docs/architecture.md).

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

## Quickstart (Raspberry Pi)

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
cp .env.example .env                                       # SQLite/Postgres URL of your choice

.venv/bin/python -m backend.scripts.init_db                # create the schema
.venv/bin/uvicorn backend.app.main:app --reload --port 8000
```

On Windows use `.venv/Scripts/python.exe`. Run **everything from the repo root** — `backend` is a
package and the module paths (`backend.app.main:app`, `python -m backend.detector.cli`) assume it.

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
| GET | `/health` | DB reachability, packet count, latest timestamp, model presence, version |
| GET | `/attacks?limit=&offset=` | Raw `packets` rows, newest first |
| GET | `/packets/count` | `{"count": int}` |
| GET | `/attacks/analysis` | Count per label — always all six keys, zero-filled |
| GET | `/top-offenders` | Source MACs by volume (key is `wlan_sa`) |
| GET | `/channel-usage` | Frame counts per RadioTap frequency |
| GET | `/heatmap-attack` | 7 days × 24 hours intensity grid, Sunday first |
| GET | `/map/ap-locations` | Configured AP inventory |
| GET | `/map/source-rssi?sa=&minutes=` | Average RSSI per BSSID for one source MAC |
| POST | `/map/estimate-origin` | RSSI-weighted centroid of the supplied APs |
| GET | `/reports/summary?days=` | Totals by type + headline figures |
| POST | `/reports/export` | One-page A4 PDF (`application/pdf`) |
| POST | `/ask` | Natural-language question → SQL or knowledge-base answer. **503 without `OPENAI_API_KEY`** |
| GET | `/` `/home/` `/dashboard/` `/attacks/` `/rag/` | The static dashboard |

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
/ask (no OPENAI_API_KEY)                              -> 503
```

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
│   │   ├── routers/              health.py attacks.py reports.py maps.py ask.py
│   │   └── rag/                  packet_qa.py + knowledge/attacks.md
│   ├── detector/               capture + inference — must not import backend.app.routers.*
│   │   ├── features.py           packet_to_row(): scapy frame -> 29 numeric features
│   │   ├── pipeline.py           Stage1, Stage2, TwoStagePipeline, Verdict
│   │   ├── capture.py            monitor mode, sniff loop, heartbeat, signal handling
│   │   ├── sink.py               PacketSink — batched writes
│   │   └── cli.py                argparse entrypoint
│   ├── scripts/                init_db.py, verify_models.py, replay_pcap.py
│   ├── config/                 ap_locations.json
│   ├── tests/                  pytest suites
│   └── requirements*.txt
├── frontend/                   Next.js 15 / React 19 / Tailwind v4 → static export in out/
├── models/                     stage1_binary_bundle.joblib, stage2_multiclass_bundle.joblib, README.md
├── data/                       samples/*.pcapng (6 captures) + README.md
├── deploy/                     install_pi.sh, monitor_mode.sh, postgres_setup.sql, 2 × .service
├── docs/                       CONTRACT.md, architecture.md, deployment-pi.md, api.md, models.md
├── notebooks/                  EDA.ipynb, binary_classifier.ipynb, multiclass_classifier.ipynb
├── .env.example                every variable, documented — copy to .env
└── LICENSE
```

---

## Model status — known training-data leakage

**The engineering works. The models do not generalise.** Capture, feature extraction, storage, the
API and the dashboard all behave correctly and are covered by tests. The problem is confined to the
two shipped LightGBM bundles, and it is measured, not suspected.

* **`frame.time_relative` — seconds since capture start — carries 41.9 % of stage-1's split gain**,
  with a training median of ~583 s. That feature encodes *which capture session a row came from*, not
  whether the traffic is malicious. It also drifts: a detector up for a day feeds values near 86 400
  where the model was trained on ~583, and restarting the service resets it.
* **`radiotap.channel.freq` carries ~8.9 % of stage-1's gain**, with a training median of 5180 MHz —
  the training captures were mostly 5 GHz, while the Pi is pinned to 2.4 GHz.
* **Stage 2 answers `Krack` for every frame of all six sample captures.** Before the feature-extraction
  fix, the old code answered `SSDP` for everything. Neither is a real prediction.

Ablation on `data/samples/deauth_raw_decrypted.pcapng` — a 20 000-frame capture that is ~97 % genuine
deauthentication frames:

| Stage-1 input | Frames flagged |
|---|---:|
| all features correctly populated | 82 / 20 000 (0.41 %) |
| `frame.time_relative` forced null → imputed to 583 s | 20 000 (100 %) |
| `radiotap.channel.freq` forced null → imputed to 5180 MHz | 0 (0 %) |

Reproduce any row with the shipped tooling:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --dry-run --null-feature frame.time_relative
```

**What this means.** The original detector appeared to catch attacks largely because its extractor left
features null, and the bundle's imputer filled them with training medians that happen to sit in the
region the model associates with attack traffic — the right answer for the wrong reason. Honest
feature extraction removed that accident and exposed the underlying problem.

**Remedy.** Retrain with **capture sessions held out of the train/test split** — the notebooks shuffle
rows across sessions, so frames from one capture land on both sides and the reported accuracy is
optimistic — and **drop the session-encoding features** (`frame.time_relative`, `frame.time_delta*`)
and the **band-encoding** ones (`radiotap.channel.freq`, `wlan_radio.frequency`, `wlan_radio.channel`).
Training data is the CSV described in [`data/README.md`](data/README.md).

Until then, treat live labels as indicative, not authoritative. Full analysis, per-capture replay
numbers and the second known limitation (two tshark-only categorical features that scapy cannot
supply) are in [`models/README.md` §5](models/README.md).

---

## Offline demo — no radio needed

`data/samples/` holds six 20 000-frame `.pcapng` captures. `replay_pcap.py` pushes them through the
*same* `packet_to_row()` and `TwoStagePipeline` the live detector uses, so what it prints is what the
Pi would have done with those frames.

```bash
# score one capture; --dry-run is the default, nothing touches the database
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng

# all six, first 5000 frames each, machine-readable
python -m backend.scripts.replay_pcap data/samples/*.pcapng --limit 5000 --json

# populate the database so the dashboard has something to draw
python -m backend.scripts.replay_pcap data/samples/beacon_raw_decrypted.pcapng --to-db
```

The report prints packets read, capture span, stage-1 hit rate, persisted count, the stage-2 label
distribution, and per-feature non-null coverage. Useful flags: `--limit N`, `--threshold1/2`,
`--null-feature NAME` (repeatable — this is the leakage ablation), `--per-packet`, `--json`,
`--model-dir`. See [`data/README.md`](data/README.md).

---

## Testing

```bash
python -m pytest backend/tests            # from the repo root
```

| Suite | Tests | Covers |
|---|---:|---|
| `backend/tests/test_api.py` | 16 | every endpoint against a temporary database, including the `/ask` 503 path |
| `backend/tests/test_rag.py` | 51 | routing, `SELECT`-only enforcement, row limiting, humanisation, error paths |
| `backend/tests/test_features.py` + `test_pipeline_pcap.py` | 31 | feature extraction from real frames, bundle transform order, replay over the samples |

All 98 pass. Two more checks worth running:

```bash
python -m backend.scripts.verify_models     # bundle digests, feature counts, class map
cd frontend && npx tsc --noEmit             # static export builds with zero TypeScript errors
```

---

## Roadmap / not yet implemented

None of the following exists in this codebase. They are listed as future work, not as features.

- [ ] **Prevention (the "P" in IPS)** — deauthenticating or blocking a malicious source, MAC
      denylisting, WLAN-controller or RADIUS integration. HawkShield currently only observes.
- [ ] **Alerting** — email, webhooks, Slack, syslog. There is no notification path of any kind.
- [ ] **Retrained models** — session-held-out split, session- and band-encoding features dropped.
      This is the highest-value item on the list; see [Model status](#model-status--known-training-data-leakage).
- [ ] **Channel hopping** — the adapter is pinned to one channel for the life of the process.
- [ ] **Normal-traffic sampling** — only attacks are persisted, so the table cannot be used to
      estimate a false-positive rate after the fact.
- [ ] **Multi-sensor aggregation**, mobile dashboard, cloud sync, SIEM export.

---

## Credits

Built by **Yasser**, **Mohammed**, **Haya**, **Ghala** and **Lena** as a capstone project.
Original repository: [`YasserAlbogami/Comprehensive_Capstone`](https://github.com/YasserAlbogami/Comprehensive_Capstone).

Built on FastAPI, SQLAlchemy, LightGBM, scikit-learn, scapy, ReportLab, Next.js, React, Tailwind CSS,
Recharts and Leaflet.

---

## Licence

Proprietary. Copyright (c) 2025 Yasser, Mohammed, Haya, Ghala, Lena. All rights reserved.
See [`LICENSE`](LICENSE).

Capturing 802.11 traffic you are not authorised to monitor is illegal in many jurisdictions. Run
HawkShield only against networks you own or have written permission to test.
