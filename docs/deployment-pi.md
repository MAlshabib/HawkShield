# HawkShield — Raspberry Pi deployment

End-to-end walkthrough for putting HawkShield on a Pi and proving it works.

This is the **narrative** guide. The **reference** — installer flags, every day-to-day command, the
full troubleshooting matrix, the uninstall procedure — is [`../deploy/README.md`](../deploy/README.md),
which is maintained by the deployment owner. This page does not restate it; it links to it. When the
two disagree, `deploy/README.md` wins on operational detail.

> [!IMPORTANT]
> **The Pi does not train anything.** Model training runs on a laptop or workstation with a GPU and
> produces an ONNX artefact you copy across — see [§4.5](#45-the-detection-model). The Pi only ever
> loads a model. It has no PyTorch, no CUDA, no AWID3 archive, and nothing on this page will put them
> there.

---

## 1. What you need

| | |
|---|---|
| **Board** | Raspberry Pi 4, 4 GB or more. The detector holds two LightGBM boosters plus scapy in memory while the API and PostgreSQL run alongside. |
| **OS** | **Raspberry Pi OS Bookworm (64-bit)**. This gives you Python **3.11**, which is the pinned target. Bullseye ships 3.9 and will not run the code. |
| **Storage** | microSD ≥ 16 GB (Class 10 / A1 or better), or a USB SSD. The database only grows with attacks, but PostgreSQL plus a Python venv with LightGBM, numpy, scipy and pandas is several GB. |
| **Power** | The official 5 V / 3 A USB-C supply. A USB Wi-Fi adapter under load plus an undersized supply causes brown-outs that look exactly like driver crashes. |
| **Capture radio** | A **USB Wi-Fi adapter that supports monitor mode** — see below. |
| **Management link** | Ethernet or the built-in `wlan0`, for SSH and for the browser to reach `:8000`. |

Confirm the OS and Python before anything else:

```bash
cat /etc/os-release | head -2       # expect: Debian GNU/Linux 12 (bookworm)
python3 --version                    # expect: Python 3.11.x
uname -m                             # expect: aarch64
```

### Choosing the adapter

**The Pi 4's built-in `wlan0` cannot be used for capture.** Its Broadcom/Cypress firmware does not
support monitor mode; it will either refuse `iw set monitor none` outright or accept it and then
silently deliver nothing. If you point `CAPTURE_IFACE` at `wlan0`, the detector will start cleanly,
log a healthy heartbeat, and never see a frame.

Known-good chipsets:

| Chipset | Band | Notes |
|---|---|---|
| Atheros **AR9271** | 2.4 GHz | `ath9k_htc`, in-tree, works out of the box. The safest choice. |
| Ralink **RT3070 / RT5372** | 2.4 GHz | `rt2800usb`, in-tree. |
| MediaTek **MT7601U** | 2.4 GHz | in-tree, widely available and cheap. |
| Realtek **RTL8812AU** | 2.4 / 5 GHz | needs the out-of-tree aircrack-ng driver; dual-band but more setup. |

Plug it in and find its name — it is almost always `wlan1`:

```bash
ip -br link
iw dev
```

Confirm the chipset actually advertises monitor mode before you go further:

```bash
iw phy | grep -A 10 "Supported interface modes"
```

If `* monitor` is not in that list, stop here and get a different adapter. Nothing downstream can
compensate.

---

## 2. Install

```bash
git clone <your-repo-url> ~/HawkShield
cd ~/HawkShield
sudo ./deploy/install_pi.sh
```

**The first run stops on purpose, with exit code 3.** It copies `.env.example` to `.env` and hands the
file back to you, because it will not invent a database password.

The installer is idempotent — run it as often as you like. It detects the repo root from its own
location, so the checkout can live anywhere; if you move it later, re-run the installer so the systemd
unit templates get rewritten with the new path.

What it does, and the flags it accepts (`--skip-apt`, `--no-enable`, `--help`), are listed in
[`deploy/README.md`](../deploy/README.md).

---

## 3. Configure `.env`

```bash
nano ~/HawkShield/.env
```

Every variable is documented inline in `.env.example`. Two are genuinely required:

```ini
DATABASE_URL=postgresql+psycopg2://hawkshield:YOUR_PASSWORD@localhost:5432/hawkshield
CAPTURE_IFACE=wlan1
```

and one usually needs attention:

```ini
CAPTURE_CHANNEL=6
```

Rules that will save you an evening:

* **Whatever password you write into `DATABASE_URL` becomes the PostgreSQL role's password.** The
  installer reads it back out of `.env` and passes it to `postgres_setup.sql`, so the two cannot
  drift on a first install.
* **Pick a password without `@`, `:`, `/` or `#`.** Those characters must be percent-encoded inside a
  URL (`@` → `%40`); it is easier not to use them.
* **`.env` is read by systemd's `EnvironmentFile`, which is not a shell.** No `export`, no command
  substitution, no quoting unless the quotes are genuinely part of the value. A trailing `# comment`
  on the same line becomes part of the value.
* `CAPTURE_CHANNEL` must match the channel of the network you are monitoring **and** the channel you
  hand to `monitor_mode.sh`. Two places, one number.
* Leave `OPENROUTER_API_KEY` empty unless you want `/ask`. Everything else works without it.
* `MODEL_DIR`, `FRONTEND_DIST` and `AP_LOCATIONS_FILE` ship blank and should stay blank unless you
  keep those files outside the checkout. Blank means "use the packaged default", explicitly.

**Model selection**, all optional and all sane by default:

```ini
MODEL_VERSION=auto        # auto | v1 | v2. auto prefers a valid v2 artefact, falls back to v1
V2_BATCH_FRAMES=32        # frames per onnxruntime call
V2_ORT_THREADS=2          # onnxruntime intra-op threads -- see below
```

> [!TIP]
> **`V2_ORT_THREADS` matters more on a Pi than anywhere else.** `0` means "the onnxruntime default",
> which is one thread per core *and which spin-waits between calls*. On a four-core Pi running the
> sniffer, the sink and uvicorn on the same silicon, that busy-wait competes directly with capture. On
> the dev box the default measured **2.4× slower end to end** than pinning it to 2 (302 vs 723
> frame/s). Leave it at `2`. Raise it only with a measurement in hand.
>
> `V2_BATCH_FRAMES=32` costs at most 32 frames of detection delay — about 32 ms at 1000 frame/s — and
> cuts per-frame inference from 1347.5 µs to 54.7 µs. `1` is the honest worst case if you ever need to
> rule batching out while debugging.
>
> Both are ignored while v1 is the active model.

> [!IMPORTANT]
> **`DATABASE_URL` is not optional on the Pi.** A laptop can run the whole stack with the shipped
> `CHANGE_ME` placeholder — `run.py` quietly falls back to a local SQLite file so a demo works with
> zero setup. **The Pi deliberately does not do this.** `run.py` exits 2 and tells you to configure
> PostgreSQL, rather than writing a sensor's attack log to an unmanaged file that no backup covers.
> If you see `DATABASE_URL is unset or still contains CHANGE_ME`, that is this check, working.

Then run the installer again — this is the pass that does the real work:

```bash
sudo ./deploy/install_pi.sh
```

It installs the apt dependencies (including **`libgomp1`**, without which the aarch64 `lightgbm`
wheel cannot even import), starts PostgreSQL and proves a connection, creates the role and database,
builds `.venv` from `backend/requirements.txt`, runs `python -m backend.scripts.init_db`, and installs
and starts the two systemd units.

---

## 4. Build the frontend — on a machine with internet

> ⚠️ **This is the step people get wrong.** `frontend/out/` is git-ignored, so a fresh clone has no
> dashboard. And the build **requires network access**: `frontend/app/layout.tsx` does
> `import { Inter } from "next/font/google"`, and Next fetches that font from Google at build time.
> An offline Pi build fails there, with an error about fetching the font rather than anything
> obviously network-related.

Two options, in order of preference:

**Build on a laptop and copy the result.**

```bash
# laptop
cd HawkShield/frontend
npm ci
npm run build                      # -> frontend/out/
grep -r "localhost:800" out | wc -l   # MUST print 0 — see frontend/README.md
scp -r out/ pi@<pi-ip>:~/HawkShield/frontend/
```

**Or build on the Pi, while it has internet.**

```bash
cd ~/HawkShield/frontend
npm ci
NODE_OPTIONS=--max-old-space-size=2048 npm run build
```

It is slow on a Pi and memory-tight; the `NODE_OPTIONS` cap is there for a reason. If the Pi's only
network link is the one you are about to put into monitor mode, build elsewhere.

`FRONTEND_DIST` in `.env` points at the export (default `<repo>/frontend/out`). FastAPI checks the
directory exists before mounting it, so a missing export means "API works, dashboard 404s" rather
than a crash. Details and the `NEXT_PUBLIC_API_BASE` trap are in
[`frontend/README.md`](../frontend/README.md).

---

### 4.5 The detection model

The same "build elsewhere, copy the result" rule applies to the model, and for the same reason: the
build needs a machine the Pi is not.

**Training runs on a laptop or workstation with a GPU. Never on the Pi.** It reads the 14.7 GB AWID3
archive, needs PyTorch and ~4.5 GB of RAM for the feature array, and takes 50–90 minutes on an
RTX 4070 SUPER (4–6 hours CPU-only). None of that belongs on a sensor.

```powershell
# laptop / workstation, from the repo root
.\ml\run_training.ps1 -Fresh
```
```bash
./ml/run_training.sh --fresh
```

That writes three files into `models/`, and those are the only artefacts the Pi needs:

```bash
scp models/hawkshield_v2.onnx      pi@<pi-ip>:~/HawkShield/models/
scp models/hawkshield_v2_meta.json pi@<pi-ip>:~/HawkShield/models/
sudo systemctl restart hawkshield-detector
```

`models/hawkshield_v2.int8.onnx` is also produced. **Do not deploy it.** It is 2.6× smaller
(348 KB → 134 KB) but measured ~4× *slower* — onnxruntime has no fast int8 Conv1d kernel at these
shapes and dequantises on every call. If the Pi's storage is genuinely the constraint, re-measure on
the Pi itself before switching; the arithmetic there is not the arithmetic on x86.

Confirm what the Pi picked up:

```bash
curl -s http://localhost:8000/health          # model_version, spec_version, artefact_spec_version
journalctl -u hawkshield-detector | grep "ACTIVE MODEL"
```

The detector refuses to load an artefact whose spec version, class list, feature list or feature
order disagrees with the code in the checkout, and says exactly which. If you copied a model across
without also pulling the matching code, that is the message you will get — and under
`MODEL_VERSION=auto` it will quietly fall back to v1 rather than run something it cannot verify.

> [!TIP]
> **What a healthy fresh install reports.** All four v2 artefacts ship in `models/`, so a new Pi runs
> the booster: `/health` returns `"model_version": "v2-gbdt"` with `spec_version` and
> `artefact_spec_version` both `"2.1.0"`. Anything else — a fallback to `v1`, or a non-empty
> `model_problems` — means the artefacts and the code in this checkout disagree. Training details
> are in [`../ml/README.md`](../ml/README.md); the model card is
> [`../models/README.md`](../models/README.md).

> [!NOTE]
> **`run.py`'s preflight accepts any one generation.** It passes on `hawkshield_v2_gbdt.txt` + meta,
> or `hawkshield_v2.onnx` + meta, or the two v1 `.joblib` bundles — a v2-only checkout is no longer
> refused. The systemd units call `backend.detector.cli` directly and were never affected either
> way.

---

## 5. Monitor mode

The detector unit is enabled but will not usefully run until the adapter is in monitor mode on the
right channel.

```bash
sudo ./deploy/monitor_mode.sh wlan1 6        # <interface> <channel>
sudo systemctl start hawkshield-detector
```

To hand the adapter back to NetworkManager:

```bash
sudo ./deploy/monitor_mode.sh --restore wlan1
```

**Monitor mode does not survive a reboot.** Either re-run `monitor_mode.sh` after each boot, or
uncomment the `ExecStartPre=` line in `deploy/hawkshield-detector.service` and re-run the installer so
systemd does it on every detector start. That line is commented out by default because a failure
there blocks the service, and the mode usually persists across a service restart.

---

## 6. Verify it works

Work down this list. Each step assumes the previous one passed.

**1 — Both units are up.**

```bash
systemctl status hawkshield-api
systemctl status hawkshield-detector
```

**2 — The adapter really is in monitor mode, on the right channel.**

```bash
iw dev wlan1 info        # "type monitor" and the channel you configured
```

**3 — The API answers, and a model loaded.**

```bash
curl -s http://localhost:8000/health
```

```json
{"status":"ok","database":true,"packets":0,"latest_packet_ts":null,
 "models":{"stage1":true,"stage2":true,"v2":false},
 "model_version":"v1","spec_version":"2.1.0","artefact_spec_version":null,
 "model_problems":[],"version":"1.0.0"}
```

`"status":"degraded"` means either the database is unreachable or **no** model is usable — the
`database`, `models` and `model_problems` fields say which.

Read `model_version` carefully: it is what the *files on disk* imply, computed by the API process,
which does no inference. `"v1"` with `"v2": false` and a `null` `artefact_spec_version` is the
expected state until a trained v2 artefact is copied across (§4.5). If a v2 artefact **is** present
but `models.v2` is `false`, `model_problems` names the mismatch — usually a spec version that does not
match the checkout.

**3b — What the detector actually loaded.** The authoritative record is one line in its own log:

```bash
journalctl -u hawkshield-detector | grep "ACTIVE MODEL"
```

```
ACTIVE MODEL: v1 (two-stage LightGBM) ...
```

If `/health` and this line disagree, the artefacts changed after the detector started — restart it.

**4 — The v1 bundles on disk are the ones the detector expects.**

```bash
cd ~/HawkShield && .venv/bin/python -m backend.scripts.verify_models
```

Non-zero exit means a bundle is missing, unreadable, or internally inconsistent. Note that this tool
checks the **v1 joblib bundles only** — it has no v2 mode. The v2 equivalent is the detector's own
load-time validation, reported by `/health` as above.

**5 — The detector is actually seeing frames.** The heartbeat logs every 2 seconds:

```bash
journalctl -u hawkshield-detector -f
```

```
status=LIVE seen=18422 saved=3 filtered=0 iface=wlan1 ch=6
```

`seen` climbing is the thing to watch. If `seen` stays at 0, you are not capturing — go to failure
mode 1 below. `saved` is frames that cleared both thresholds and were written.

**6 — Rows are landing in the database.**

```bash
curl -s http://localhost:8000/packets/count
```

**7 — The dashboard loads.**

```bash
hostname -I                       # the Pi's address
```

Open `http://<pi-ip>:8000` from a laptop on the same network. It should redirect to `/home`.

**8 — No radio handy?** Replay a sample capture into the database and the dashboard fills up:

```bash
cd ~/HawkShield
.venv/bin/python -m backend.scripts.replay_pcap data/samples/beacon_raw_decrypted.pcapng --to-db
```

See [`../data/README.md`](../data/README.md).

**9 — The model predicts on *this* box.** Independent of capture, confirm the artefacts on disk load
and score:

```bash
cd ~/HawkShield
.venv/bin/python -m backend.detector.cli --self-test
```

It builds the pipeline and pushes crafted frames through the feature extractor and inference path,
asserting the model loaded and every frame produced a complete 46-feature vector and a finite `p1`
(never the class label — crafted frames carry no realistic timing). **Exit 0 means the model is live
and predicting here;** a non-zero exit names the missing or corrupt artefact.

**10 — Watch detections land, live.** The terminal twin of `GET /stream` — one coloured line per row,
a `SIM` tag on rows written by `POST /simulate`:

```bash
.venv/bin/python -m backend.scripts.live_monitor --follow
```

**11 — The whole chain, over the air (optional).** `tools/inject_attack.py` is the only test that
exercises antenna → capture → model → database: it transmits real 802.11 frames from a *second*
monitor-mode adapter against your own AP and grades what the Pi wrote.

> [!CAUTION]
> **⚠️ Legal note — read first.** Transmitting deauthentication / disassociation frames against
> networks you do not own is **illegal in most jurisdictions.** This is for your own testbed only.
> The tool refuses to transmit unless you pass **both** `--i-own-this-network` and an explicit,
> well-formed `--target-bssid`, and it caps count/rate in code.

```bash
sudo .venv/bin/python tools/inject_attack.py \
    --iface wlan1mon --target-bssid <your-ap-bssid> \
    --attack all --count 50 --rate 20 --i-own-this-network \
    --verify postgresql://hawk:password@localhost:5432/hawkshield
```

`--verify` grades each injected class **PASS / PARTIAL / FAIL**. A **PARTIAL** (the Pi saw attack
traffic but under a different label) is expected, not a bug: the shipped model is AWID3-trained and
validated across time within one recording, not across radio hardware
([`../models/README.md` §2.7.1](../models/README.md)). A **FAIL** (nothing written) is the real red
flag — check the adapter injects and everything is on the same channel. Full guide:
[`../tools/README.md`](../tools/README.md). Runbook framing: [`demo.md`](demo.md).

---

## 7. Logs

Everything goes to the journal. Neither service writes a log file.

```bash
journalctl -u hawkshield-detector -f              # live
journalctl -u hawkshield-api -f
journalctl -u hawkshield-detector -n 100 --no-pager
journalctl -u hawkshield-detector -b              # since boot
journalctl -u hawkshield-api --since "1 hour ago"
sudo journalctl -u postgresql -n 50
```

The units set `SyslogIdentifier=hawkshield-detector` / `hawkshield-api`, so `journalctl -t
hawkshield-detector` works too.

Raise verbosity with `LOG_LEVEL=DEBUG` in `.env` followed by a restart. At `DEBUG` the sink logs every
commit and the detector logs per-packet extraction failures with tracebacks — useful for an hour, far
too noisy to leave on.

Signals worth knowing:

| Log line | Meaning |
|---|---|
| `sniffer armed: iface=… type=monitor channel=6 …` | startup succeeded; note `type=` |
| `status=LIVE seen=N saved=N filtered=N` | 2 s heartbeat; `seen` must climb |
| `ATTACK <label> p1=… p2=… sa=… bssid=…` | a frame cleared both thresholds |
| `interface went down; bringing wlan1 up and retrying` | ENETDOWN recovery — a flapping USB adapter |
| `[db] commit failed, dropped N rows` | the sink could not write; capture continues |
| `[db] sink closed: written=N failed=N` | clean shutdown |

Restart policy: `hawkshield-api` is `Restart=on-failure`, so a deliberate `systemctl stop` stays
stopped. `hawkshield-detector` is `Restart=always` with `RestartSec=10` and **no start-rate limit**, so
a flapping adapter cannot wedge it into a permanently failed state.

---

## 8. The three failure modes

Between them these account for nearly everything that goes wrong. Full diagnostic trees, including
the PostgreSQL `pg_hba.conf` cases, are in [`deploy/README.md` → Troubleshooting](../deploy/README.md).

### 8.1 The detector runs but no attacks ever appear — adapter not in monitor mode

**By far the most common.** The service starts cleanly, the heartbeat ticks, and `/packets/count`
never moves. The tell is `seen=0` in the heartbeat.

```bash
iw dev wlan1 info | grep type
```

`type managed` means you are not capturing 802.11 frames at all.

```bash
sudo ./deploy/monitor_mode.sh wlan1 6
sudo systemctl restart hawkshield-detector
```

If the script reports success and `iw dev` says `managed` again a moment later, something re-claimed
the interface — almost always NetworkManager:

```bash
nmcli dev status                     # wlan1 should be "unmanaged"
sudo nmcli dev set wlan1 managed no
systemctl status wpa_supplicant
```

If `iw dev wlan1 set monitor none` fails outright, the chipset does not support monitor mode (§1). If
`CAPTURE_IFACE` is `wlan0`, that is the built-in radio and it will never work.

And if the mode is right but `seen` is still flat: **check the channel.** Attack traffic on channel 11
is invisible to an adapter pinned to 6.

```bash
iw dev wlan1 info | grep channel
grep CAPTURE_CHANNEL ~/HawkShield/.env
```

### 8.2 PostgreSQL authentication failure

Symptoms: the API returns 500s, `/health` reports `"database": false`, or the detector log shows
`OperationalError: FATAL: password authentication failed for user "hawkshield"`.

Reproduce it over TCP, which is what SQLAlchemy uses — a `psql` that works over the unix socket proves
nothing:

```bash
psql -h localhost -U hawkshield -d hawkshield -c "SELECT 1"
```

The usual cause is drift: you edited `.env` **after** the first install, and `postgres_setup.sql`
never resets an existing role's password. Fix the role to match the file:

```bash
sudo -u postgres psql -c "ALTER ROLE hawkshield WITH PASSWORD 'the-password-in-your-env';"
```

If the error says *ident* or *peer* authentication instead, `pg_hba.conf` needs password auth on the
loopback (`host all all 127.0.0.1/32 scram-sha-256`, plus the `::1/128` line), then
`sudo systemctl reload postgresql`.

Also worth a look before anything else — a stray quote or an inline `#` comment silently becomes part
of the password:

```bash
grep DATABASE_URL ~/HawkShield/.env
```

### 8.3 `POST /ask` returns 503

**This is expected behaviour, not a bug.** `/ask` is the only endpoint that needs an API key. With
`OPENROUTER_API_KEY` empty the API starts normally, every other endpoint works, and the dashboard
works — only the assistant page reports the service as unavailable.

To enable it, get a key from <https://openrouter.ai/keys>:

```bash
nano ~/HawkShield/.env      # OPENROUTER_API_KEY=sk-or-v1-...
sudo systemctl restart hawkshield-api

.venv/bin/python backend/scripts/check_rag.py     # proves the whole path before you trust it

curl -s -X POST http://localhost:8000/ask \
     -H 'Content-Type: application/json' \
     -d '{"question":"how many deauth attacks today?"}'
```

`check_rag.py` is the fast way to tell *which* thing is wrong: it checks the key, confirms `GEN_MODEL`
exists on OpenRouter and prints its live price, then runs a knowledge-base question and a
text-to-SQL question and executes the SQL. Exit 0 means `/ask` will work; exit 2 is a key or model-id
problem, 3 is the knowledge-base call, 4 is SQL generation or execution. `--skip-db` checks the model
alone, which separates "the model is broken" from "the database is unreachable". It needs outbound
HTTPS from the Pi.

Still 503 after setting the key? The service is not seeing it:

```bash
sudo systemctl show hawkshield-api -p Environment
grep OPENROUTER ~/HawkShield/.env
```

Usual causes: the line was written as `export OPENROUTER_API_KEY=...` (drop the `export` — systemd's
`EnvironmentFile` is not a shell), the value was quoted when it should not have been, or the service
was never restarted after the edit.

A different symptom — 200s in `ERROR` mode with SQL that will not parse — usually means `GEN_MODEL`
points at a model that is bad at strict JSON or at SQL. The default is
`deepseek/deepseek-v4-flash`; `z-ai/glm-5.3-flash` and `qwen/qwen3.7-flash` also work here. See
[`api.md`](api.md) for the full table.

Note that the Pi generates **PostgreSQL**, because `DATABASE_URL` points at PostgreSQL. A laptop demo
on the SQLite fallback generates SQLite. That is automatic and needs no configuration; it is
described in [`architecture.md` §3](architecture.md).

A **500** rather than a 503 means the opposite: the key is present but was rejected upstream, or the
generated SQL failed. Read the traceback with `journalctl -u hawkshield-api -n 50`.

---

## 9. Updating

```bash
cd ~/HawkShield
git pull
sudo systemctl restart hawkshield-api hawkshield-detector
```

If `backend/requirements.txt` changed, reinstall into the venv first. If the schema, the unit files or
the checkout path changed, just re-run `sudo ./deploy/install_pi.sh --skip-apt` — it is idempotent and
will not touch your `.env`. If the frontend changed, rebuild the export on a networked machine (§4).

**If the model changed**, copy the new `hawkshield_v2.onnx` **and** `hawkshield_v2_meta.json` across
together (§4.5) and restart the detector. Copy them as a pair and pull the matching code: the runtime
compares the artefact's spec version, class list and feature order against the checkout and refuses a
mismatch rather than serving a model whose feature space is not the one the extractor produces. A
`git pull` that changes `backend/detector/feature_spec.py` without a matching artefact will drop the
detector back to v1 — visible immediately in `/health` and in the `ACTIVE MODEL:` log line.

Uninstall instructions are at the end of [`deploy/README.md`](../deploy/README.md).

---

## 10. Running things by hand

When a unit will not start and you want the traceback in front of you. Always from the repo root,
always with the venv's Python, and stop the corresponding unit first or port 8000 is already taken.

```bash
cd ~/HawkShield
.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
sudo .venv/bin/python -m backend.detector.cli --iface wlan1 --channel 6
sudo .venv/bin/python -m backend.detector.cli --iface wlan1 --channel 6 --dry-run --log-level DEBUG
.venv/bin/python -m backend.scripts.init_db
.venv/bin/python -m backend.scripts.verify_models
.venv/bin/python backend/scripts/check_rag.py
```

`--dry-run` classifies and logs without opening a database connection at all — exactly what you want
when checking a new radio. The detector CLI also accepts `--ssid`, `--threshold1`, `--threshold2`,
`--model-dir`, `--model-version`, `--batch-frames` and `--log-level`; each defaults to the matching
`.env` value. `--model-version v2` is the way to make a mismatch loud: it exits `2` with the reason
instead of falling back to v1.

### Or use the launcher

`run.py` starts the same two processes in the foreground, after running the preflight checks above
for you. It is the quickest way to see what is broken, and the right way to demo a Pi you are
standing next to.

```bash
sudo systemctl stop hawkshield-api hawkshield-detector   # or port 8000 is taken
sudo ./deploy/monitor_mode.sh wlan1 6
sudo .venv/bin/python run.py
```

It prints one line per check — `.env`, database, model bundles, dashboard build, schema, port — then
the dashboard URL and the LAN URL, and Ctrl-C stops both children cleanly.

| Situation | What the launcher does |
|---|---|
| a v1 `.joblib` bundle missing from `models/` | exits 2 — even if a valid v2 artefact is present. Known gap, [`CONTRACT.md` §8.4](CONTRACT.md); do not delete the bundles |
| `DATABASE_URL` unset or `CHANGE_ME` | exits 2; **no SQLite fallback on the Pi** |
| `init_db` fails | exits 2, prints the last lines of the error and `sudo systemctl status postgresql` |
| not run with `sudo` | warns, starts the dashboard only, prints the `sudo` command to get capture |
| port 8000 busy (a unit is still running) | exits 2 and suggests `--port 8001` |
| no `frontend/out` | warns and serves the API without a UI |

Useful flags here: `--no-detector` (dashboard only), `--iface` / `--channel` (override `.env` for one
run), `--port`, and `--mode laptop` to force laptop behaviour on the Pi. `--demo` replays a sample
capture into the database first — handy for proving the dashboard before the radio works, but note
it writes to the **real** PostgreSQL database on a Pi.

Systemd remains the right answer for an unattended sensor: it restarts on failure and comes back
after a reboot. `run.py` does neither.
