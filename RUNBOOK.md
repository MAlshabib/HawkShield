# Running HawkShield — the whole thing, plainly

You do not start HawkShield. It starts itself.

Capture, the model, and the dashboard are all system services enabled at boot.
**Power the Pi on and wait about a minute** — everything comes up on its own,
and it comes back the same way after any reboot or power cut. There is no
command to "launch" it and nothing to leave running in a terminal.

Everything below is for the few things that genuinely need a human at a venue:
telling it which network to watch, and checking it is healthy.

---

## Open it

From any device on the same network:

> **http://hawkshield.local:8000**

That address works even when the Pi's IP changes, so it is the one to trust.
(If `.local` ever fails on a locked-down network, the numeric `http://<ip>:8000`
is printed by `hawkshield` and in the login banner.)

Pages: `/` overview · `/dashboard` live detections · `/threats` the log ·
`/map` source location · `/saqr` ask the AI analyst · `/admin` operator controls
(unlisted).

---

## The one command: `hawkshield`

SSH into the Pi (`ssh pi@hawkshield.local`) and the login banner reminds you of these.

| Command | What it does |
|---|---|
| `hawkshield` | full status — services, capture, detections, network, and the URL |
| `hawkshield channel auto` | **the important one at a venue.** Listen on the channel your Wi-Fi is actually on |
| `hawkshield wifi <SSID>` | join a network on `wlan0` (asks for the password) |
| `hawkshield reset` | re-bind the capture adapter if the radio goes silent |
| `hawkshield restart` | restart both services |
| `hawkshield logs` | watch the detector live |
| `hawkshield hotspot` | serve a network from the Pi if the venue has none |

`hawkshield` on its own is safe to run any time — it only reads.

---

## At the conference — the whole sequence

1. **Plug in ethernet** (its internet feeds the AI analyst) and **power on**.
   Wait ~1 minute.
2. **`hawkshield wifi <target-SSID>`** — puts the Pi on the network you are
   demoing against.
3. **`hawkshield channel auto`** — points the capture radio at that network's
   channel. *This is the step people forget, and without it the sensor hears
   nothing while looking perfectly healthy.*
4. **`hawkshield`** — confirm every line is green.
5. Open **http://hawkshield.local:8000** on the projector.

If you already know the channel, skip step 2 and just run
`hawkshield channel 6`.

---

## Showing an attack

**Live (best):** from the repo on the Pi,

```bash
./attack/attack.sh          # a real deauth burst at your own router
```

Watch `/dashboard` — new detections appear within seconds. See
`attack/README.md` for classes and options. It only attacks the AP your `wlan0`
is joined to; it will not touch anything else.

**Fallback (no radio needed):** `/admin` → **Simulate**. Replays real frames
through the model in software. Use this if you cannot transmit in the room.

**Reset the board** between runs: `/admin` → **Delete all detections** (red
button, Danger Zone). Type `DELETE` to confirm. Every chart goes back to zero.

---

## If something looks wrong

| Symptom | Do this |
|---|---|
| Dashboard reachable but no new detections | `hawkshield channel auto` — the Wi-Fi likely changed channel |
| Still nothing, and `hawkshield` says "radio is silent" | `hawkshield reset` — the USB adapter stalled; this always fixes it |
| Saqr says it is not configured / no answer | it needs internet; check the ethernet cable. Everything else still works offline |
| A page will not load at all | `hawkshield restart` |
| Totally stuck | pull the power, plug back in, wait a minute — it all comes back on its own |

"Sensor idle / last packet N hours ago" is **not** an error. Only *attack*
frames are stored; ordinary Wi-Fi traffic is classified and dropped. The
sensor is listening the whole time — `hawkshield` shows the live frame count.

---

## One security note for the venue

The `/admin` page is unlisted but not password-protected, and it can delete the
database. On an untrusted network, set `ALLOW_PURGE=0` in `~/HawkShield/.env`
and `hawkshield restart` to disable the delete button. The AI analyst's own
delete tools stay locked behind a token regardless.
