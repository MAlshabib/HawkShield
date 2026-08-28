# attack/ — over-the-air proof

The live version of the demo: transmit real 802.11 attack frames at **your own
router** and watch HawkShield catch them on the dashboard a few seconds later.

The `/admin` **Simulate** button replays frames through the model in software —
no radio, always works, good as a fallback. This is the real thing: frames go
out the antenna, the sensor hears them off the air, and the detection you see
was genuinely captured, not injected into the database.

> [!CAUTION]
> **Legal.** Transmitting deauthentication / disassociation frames at a network
> you do not own is illegal in most jurisdictions. This script attacks the
> access point your Pi's `wlan0` is associated with, on the assumption that it
> is yours. Point it at nothing else. The underlying tool refuses to run without
> an explicit own-network assertion and a specific target — there is no
> broadcast-at-the-room mode, by design.

## What it needs (already true on the deployed Pi)

- **A monitor-mode adapter.** The capture radio (`wlan1`) is already in monitor
  mode on the target channel, and a monitor interface can transmit and receive
  at once — so the same card that fires the attack is the one that hears it. One
  adapter does both.
- **`wlan0` associated to your router**, so the script knows the target BSSID
  without you typing it. `hawkshield wifi <ssid>` if it isn't.
- **The capture channel matching the router's channel.** `hawkshield channel
  auto` sets that. If the sensor is listening on the wrong channel it will
  transmit fine and hear nothing — the frames are real, they just miss the ear.

## Use it

From the repo on the Pi:

```bash
./attack/attack.sh                 # deauth × 30 at your connected router
./attack/attack.sh evil_twin       # a different class
./attack/attack.sh all 50          # every class, 50 frames each
./attack/attack.sh deauth 100 40   # class, count, frames-per-second
```

Positional arguments: **class**, **count** (default 30), **rate** in frames/sec
(default 20). Classes: `deauth`, `disas`, `reassoc`, `rogueap`, `evil_twin`,
`krack`, or `all`.

It prints the target, the radio and a link to the dashboard, then transmits.
Open **http://pi.local:8000/dashboard** and watch the live tape.

### Overrides (rarely needed)

| Variable | Effect |
|---|---|
| `ATTACK_BSSID=aa:bb:…` | attack a specific AP instead of the one `wlan0` is on |
| `ATTACK_IFACE=wlan1` | transmit from a different monitor interface |
| `HAWKSHIELD_REPO=/path` | run from outside the repo |

## What "caught it" looks like

Seconds after transmitting, the dashboard's **live tape** shows new rows for
the class you sent, the class-distribution bars move, and `/health` packet count
climbs. Ask **Saqr** *"what was detected in the last minute?"* and it will read
them back.

### If the label is not exactly the class you sent

Expected, and not a bug. The shipped model is AWID3-trained and validated across
time *within one recording*, not across hardware (see `models/README.md` §2.7.1).
Frames from a different radio, antenna and driver than AWID3's may be detected
as *an* attack but often mislabelled. The detection is real; the exact class is
where the documented hardware-domain gap shows. In bench testing a `deauth`
burst was caught reliably but frequently logged as `Evil_Twin` — the frames were
detected, the label drifted. Lead with *"the sensor caught the attack"*, not
*"it named it deauth"*; the honest, verifiable claim is the detection.

## Safety, enforced in code (not just here)

`tools/inject_attack.py`, which this script drives, hard-caps at **1000 frames
per class** and **100 frames/second**, requires `--i-own-this-network` and a
specific non-broadcast `--target-bssid`, and only touches the radio on Linux as
root with the interface actually in monitor mode. There is no flag to raise the
caps. This launcher passes those guards through; it does not weaken them.

## Nothing to clean up

The attack transmits and exits — it changes nothing on the Pi. The detections it
produced are ordinary rows; clear them from **`/admin` → delete all** if you want
a clean board before the next run.
