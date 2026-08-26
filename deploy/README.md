# HawkShield — deployment runbook

Operator guide for the Raspberry Pi. Everything here assumes **Raspberry Pi 4 /
Raspberry Pi OS Bookworm / Python 3.11**.

| File | What it is |
|---|---|
| `install_pi.sh` | One-shot, idempotent installer. Run it, re-run it, it is safe. |
| `monitor_mode.sh` | Put the capture adapter into monitor mode on a fixed channel (`--restore` to undo). |
| `postgres_setup.sql` | Creates the `hawkshield` role + database. Called by the installer; safe to re-run. |
| `hawkshield-api.service` | uvicorn on `:8000`, unprivileged. |
| `hawkshield-detector.service` | scapy capture + LightGBM inference, root. |

---

## Hardware

You need a **USB Wi-Fi adapter**. The Pi 4's built-in `wlan0` uses a
Broadcom/Cypress chip whose firmware does not support monitor mode — it will
either refuse the mode switch or silently capture nothing. Known-good chipsets:
Atheros AR9271, Ralink RT3070/RT5372, MediaTek MT7601U, Realtek RTL8812AU with
the aircrack-ng driver. The adapter normally comes up as `wlan1`; confirm with
`ip -br link`.

---

## Install

```bash
git clone <repo-url> ~/HawkShield
cd ~/HawkShield
sudo ./deploy/install_pi.sh
```

The install path is wherever you cloned it. The installer detects the repo root
from its own location and rewrites the `/opt/hawkshield` placeholder inside the
two systemd unit templates before copying them to `/etc/systemd/system/`. If you
move the checkout later, re-run the installer.

**The first run stops on purpose** (exit code 3). It copies `.env.example` to
`.env` and hands the file back to you, because it will not invent a database
password. Edit `.env`, then run the installer again:

```bash
nano .env          # set DATABASE_URL password + confirm CAPTURE_IFACE
sudo ./deploy/install_pi.sh
```

Whatever password you put in `DATABASE_URL` becomes the PostgreSQL role's
password — the installer reads it back out of `.env` and passes it to
`postgres_setup.sql`, so the two can never drift apart.

What the installer does, in order:

1. Preflight — Linux, root, systemd, Python ≥ 3.11, repo layout.
2. apt: `python3-venv python3-dev build-essential libpq-dev postgresql iw
   wireless-tools libpcap0.8 libgomp1 git curl`.
   (`libgomp1` is a hard requirement — the aarch64 `lightgbm` wheel fails to
   import without it. `build-essential`/`libpq-dev`/`python3-dev` are only used
   if a wheel is missing and pip has to build from source.)
3. Enable + start PostgreSQL, and prove a real connection.
4. `.env` — copy from the template on first run, then stop.
5. Create the role + database via `postgres_setup.sql`, then verify the app's
   own credentials work over TCP.
6. Create `.venv` and `pip install -r backend/requirements.txt`.
7. `python -m backend.scripts.init_db`.
8. Install, enable and start the two systemd units.

Flags: `--skip-apt` (fast re-run), `--no-enable` (install units without starting
them), `--help`.

### Monitor mode

The detector unit is enabled but is only auto-started when the adapter is
already in monitor mode. After the first install:

```bash
sudo ./deploy/monitor_mode.sh wlan1 6
sudo systemctl start hawkshield-detector
```

The channel must match `CAPTURE_CHANNEL` in `.env` and the interface must match
`CAPTURE_IFACE`, or the detector listens to the wrong thing. To hand the adapter
back to NetworkManager:

```bash
sudo ./deploy/monitor_mode.sh --restore wlan1
```

Monitor mode does **not** survive a reboot. Either re-run `monitor_mode.sh`
after each boot, or uncomment the `ExecStartPre=` line in
`hawkshield-detector.service` (and re-run the installer) to have systemd do it
on every detector start.

### Frontend

FastAPI serves the built Next.js static export at `/` — there is no second web
server and no `next dev` on the Pi. If the dashboard 404s, the export has not
been built:

```bash
cd ~/HawkShield/frontend && npm ci && npm run build
```

`FRONTEND_DIST` in `.env` points at it (default `<repo>/frontend/out`).

---

## Day-to-day

```bash
# status
systemctl status hawkshield-api
systemctl status hawkshield-detector
curl -s http://localhost:8000/health

# start / stop / restart
sudo systemctl restart hawkshield-api
sudo systemctl stop hawkshield-detector

# logs (live)
journalctl -u hawkshield-detector -f
journalctl -u hawkshield-api -f

# logs (last 100 lines, no pager)
journalctl -u hawkshield-detector -n 100 --no-pager

# logs since boot / since a time
journalctl -u hawkshield-detector -b
journalctl -u hawkshield-api --since "1 hour ago"
```

Dashboard: `http://<pi-ip>:8000` (find the IP with `hostname -I`).

`hawkshield-api` restarts `on-failure` — a deliberate `systemctl stop` stays
stopped. `hawkshield-detector` restarts `always` with `RestartSec=10` and no
start-rate limit, so a flapping USB adapter cannot wedge it into a dead state.

### Running things by hand

Useful when a service will not start and you want the traceback in front of you.
Always from the repo root, always with the venv's Python:

```bash
cd ~/HawkShield
.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
sudo .venv/bin/python -m backend.detector.cli --iface wlan1 --channel 6
.venv/bin/python -m backend.scripts.init_db
```

Stop the corresponding systemd unit first, or port 8000 will already be taken.

---

## Update

```bash
cd ~/HawkShield
git pull
sudo systemctl restart hawkshield-api hawkshield-detector
```

If `backend/requirements.txt` changed:

```bash
.venv/bin/pip install -r backend/requirements.txt
sudo systemctl restart hawkshield-api hawkshield-detector
```

If the schema or the unit files changed, or you moved the checkout, just re-run
the installer — it is idempotent and will not touch your `.env`:

```bash
sudo ./deploy/install_pi.sh --skip-apt
```

---

## Troubleshooting

### 1. The detector runs but no attacks ever appear — adapter not in monitor mode

The single most common failure. The detector starts cleanly, the log shows the
capture loop running, and `/packets/count` never moves.

```bash
iw dev wlan1 info          # look at the "type" line
```

`type managed` means you are not capturing 802.11 frames.

```bash
sudo ./deploy/monitor_mode.sh wlan1 6
sudo systemctl restart hawkshield-detector
```

If `monitor_mode.sh` reports success and `iw dev` still says `managed` a moment
later, something re-claimed the interface — almost always NetworkManager:

```bash
nmcli dev status                    # should show wlan1 as "unmanaged"
sudo nmcli dev set wlan1 managed no
systemctl status wpa_supplicant
```

If `iw dev wlan1 set monitor none` fails outright, the chipset does not support
monitor mode:

```bash
iw phy | grep -A 10 "Supported interface modes"
```

If `monitor` is not in that list, you need a different adapter. If you pointed
`CAPTURE_IFACE` at `wlan0`, that is the built-in radio — it will never work.

Also worth checking: the channel. If the attack traffic is on channel 11 and
you pinned channel 6, you will see nothing:

```bash
iw dev wlan1 info | grep channel
```

### 2. PostgreSQL authentication failure

Symptoms — the API returns 500s, `/health` reports `"database": false`, or the
detector log shows
`OperationalError: FATAL: password authentication failed for user "hawkshield"`.

First, reproduce it directly over TCP, which is what SQLAlchemy uses:

```bash
psql -h localhost -U hawkshield -d hawkshield -c "SELECT 1"
```

**Wrong password.** The role's password and the one in `DATABASE_URL` have
drifted. `postgres_setup.sql` never resets an existing role's password, so if
you edited `.env` after the first install, fix the role:

```bash
sudo -u postgres psql -c "ALTER ROLE hawkshield WITH PASSWORD 'the-password-in-your-env';"
```

**`ident`/`peer` authentication.** The error mentions "Ident authentication
failed" or "peer authentication failed". `pg_hba.conf` needs to allow
password auth on the loopback:

```bash
sudo nano /etc/postgresql/*/main/pg_hba.conf
```

```
host    all    all    127.0.0.1/32    scram-sha-256
host    all    all    ::1/128         scram-sha-256
```

```bash
sudo systemctl reload postgresql
```

**Server not running.**

```bash
sudo pg_lsclusters                     # is the cluster "online"?
sudo systemctl status postgresql
sudo journalctl -u postgresql -n 50
```

**Role or database missing entirely** (a half-finished first install):

```bash
sudo -u postgres psql -v hs_password=yourpassword -f deploy/postgres_setup.sql
cd ~/HawkShield && .venv/bin/python -m backend.scripts.init_db
```

Sanity-check what `.env` actually contains — a stray quote or a `#` comment on
the same line will silently become part of the password, since systemd's
`EnvironmentFile` does no shell parsing:

```bash
grep DATABASE_URL ~/HawkShield/.env
```

A password containing `@`, `:`, `/` or `#` must be percent-encoded in the URL
(`@` → `%40`). Easiest fix is to pick a password without them.

### 3. `POST /ask` returns 503 — missing OpenAI key

This is **expected behaviour, not a bug**. The RAG endpoint is the only thing
that needs an API key. With `OPENAI_API_KEY` empty, the API starts normally,
every other endpoint works, the dashboard works, and only `/ask` returns:

```
503  {"detail": "..."}
```

To enable it:

```bash
nano ~/HawkShield/.env      # OPENAI_API_KEY=sk-...
sudo systemctl restart hawkshield-api
```

Then re-test:

```bash
curl -s -X POST http://localhost:8000/ask \
     -H 'Content-Type: application/json' \
     -d '{"question":"how many deauth attacks today?"}'
```

Still 503 after setting the key? The service is not seeing it:

```bash
sudo systemctl show hawkshield-api -p Environment      # is the key loaded?
grep OPENAI ~/HawkShield/.env
```

Common causes: the key was written as `export OPENAI_API_KEY=...` (systemd's
`EnvironmentFile` is not a shell — drop the `export`), the value was quoted when
it should not be, or the service was never restarted after the edit.

If you get a 500 rather than a 503, the key is present but rejected upstream —
check the traceback with `journalctl -u hawkshield-api -n 50`.

---

## Reference

**Placeholders in the unit files.** Both `.service` files ship with the literal
install path `/opt/hawkshield` and, for the API, `User=hawkshield`. The
installer rewrites both with `sed` on its way to `/etc/systemd/system/`. Never
edit the installed copies — edit the templates in `deploy/` and re-run the
installer, or your changes vanish on the next install.

**Privileges.** `hawkshield-api` runs as the account that owns the checkout with
an empty capability bounding set. `hawkshield-detector` runs as **root** with
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN` — root in uid only; it cannot
load modules or override file permissions. The rationale for root over an
unprivileged account with `AmbientCapabilities` is commented at the top of
`hawkshield-detector.service`.

**Uninstall.**

```bash
sudo systemctl disable --now hawkshield-api hawkshield-detector
sudo rm /etc/systemd/system/hawkshield-{api,detector}.service
sudo systemctl daemon-reload
sudo -u postgres psql -c "DROP DATABASE hawkshield;"
sudo -u postgres psql -c "DROP ROLE hawkshield;"
sudo ./deploy/monitor_mode.sh --restore wlan1
```
