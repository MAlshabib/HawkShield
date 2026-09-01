# HawkShield `tools/` — over-the-air self-test

`inject_attack.py` is the antenna-to-dashboard proof for a HawkShield
deployment. It transmits **real** 802.11 attack frames from a monitor-mode
adapter against **your own** testbed AP, then queries the Pi's `packets` table
to confirm the detector actually saw them. This is the one test that exercises
the whole chain — RF → capture → feature extraction → model → database — instead
of pushing frames through the pipeline in software (`POST /simulate`) or
asserting the model in-process (`--self-test`).

---

## ⚠️ Legal note — read first

**Transmitting deauthentication / disassociation frames against networks you do
not own is illegal in most jurisdictions.** This tool is for testing your own
equipment only. It refuses to transmit unless you both pass
`--i-own-this-network` and name an explicit `--target-bssid` — there is no
default and frames are never broadcast blindly to the room. The legal warning
prints on every run.

---

## What it does (and does not) craft

The frames are **not** crafted here. They come byte-for-byte from
`backend/detector/attack_sim.py` — the same `build_frames` / `ATTACK_SPECS`
factory that `POST /simulate` and `--self-test` use, so the over-the-air test
and the in-process tests are the *same frames*. A crafted deauth carries reason
code 7 (class-3 frame from a nonassociated station), exactly what a real deauth
flood looks like on the air.

This tool only: (1) retargets each built frame's BSSID to your `--target-bssid`
so injection is scoped to your AP, (2) puts them on the antenna with scapy's
`sendp`, and (3) reports what the Pi detected.

Attack classes it can build (`--attack`):
`deauth`, `disas`, `reassoc`, `rogueap`, `evil_twin`, `krack`, or `all`.

---

## Requirements

- **Linux + root** (target: Raspberry Pi OS). Build, `--help` and the safety
  gate run on any OS, but transmission does not.
- A **monitor-mode injecting adapter** — the same external USB adapters
  `deploy/monitor_mode.sh` documents (Atheros AR9271, Ralink RT3070/RT5372,
  MediaTek MT7601U, RTL8812AU with the aircrack-ng driver). The Pi's built-in
  `wlan0` cannot do monitor mode.
- The interface must already be in monitor mode. Put it there first:

  ```bash
  sudo ./deploy/monitor_mode.sh wlan1 6      # monitor mode, channel 6
  ```

  Use the **same channel your test AP is on**, or the Pi's detector (also pinned
  to that channel) will never hear the frames.

---

## Usage

```bash
sudo python tools/inject_attack.py \
    --iface wlan1mon \
    --target-bssid de:ad:be:ef:00:01 \
    --attack all \
    --count 50 \
    --rate 20 \
    --i-own-this-network \
    --verify postgresql://hawk:password@hawkshield.local:5432/hawkshield
```

| Flag | Meaning |
|---|---|
| `--iface` | Monitor-mode interface to transmit from (e.g. `wlan1mon`). |
| `--target-bssid` | BSSID (MAC) of the AP **you own**. Every frame is scoped to it. Required. |
| `--attack` | One of `deauth`, `disas`, `reassoc`, `rogueap`, `evil_twin`, `krack`, or `all`. |
| `--count` | Frames per class. Capped at **1000**. |
| `--rate` | Frames per second. Capped at **100/s**. |
| `--i-own-this-network` | Required ownership assertion. Without it the tool refuses. |
| `--verify DB_URL` | After injecting, poll the Pi's `packets` table and print what it detected. |
| `--verify-timeout` | Seconds to wait for the detector to write rows (default 20). |

Single class instead of `all`:

```bash
sudo python tools/inject_attack.py --iface wlan1mon \
    --target-bssid de:ad:be:ef:00:01 --attack deauth \
    --count 100 --rate 25 --i-own-this-network
```

### Safety rails (enforced in code, not just docs)

- Refuses to transmit without **both** `--i-own-this-network` and an explicit,
  well-formed `--target-bssid` (broadcast `ff:ff:ff:ff:ff:ff` is rejected).
- Hard caps: `--count ≤ 1000`, `--rate ≤ 100/s`. There is no flag to raise them.
- Fails clearly if not Linux, not root, or the interface is not in monitor mode
  (checked via `iw dev <iface> info`, the same idiom as `monitor_mode.sh`).

---

## Reading the `--verify` output

`--verify` captures the highest `packets.id` before injecting, then polls for
rows written afterward and grades each injected class:

```
=== HawkShield verify: what the Pi detected ===
new rows since inject: 300
labels seen: Deauth=150, Disas=90, RogueAP=60

injected class as-itself  verdict  note
------------------------- -------- ----
Deauth               150  PASS     detected as the injected class
Disas                 90  PASS     detected as the injected class
...
------------------------- -------- ----
OVERALL: PASS
```

- **PASS** — the Pi labelled at least one new frame as that exact class.
- **PARTIAL** — the Pi saw attack traffic but under a *different* label.
- **FAIL** — the Pi wrote nothing new for that class.

The overall verdict is PASS only when every injected class was detected as
itself; PARTIAL when attacks were seen but not all labels matched; FAIL when the
Pi wrote nothing.

### Why PARTIAL is expected, not a bug — the hardware-domain caveat

The shipped model is **AWID3-trained**. Its 0.9907 accuracy measures
generalisation *across time within one recording*, not across deployments
(`models/README.md` §2.7.1). Frames from a different radio, antenna, driver or
RF environment than AWID3's testbed may be detected as *an* attack but
mislabelled (e.g. a deauth read as a disassoc). That is a documented
cross-deployment gap, not a capture failure.

So `--verify` **reports what the Pi actually detected and does not assert a
perfect match.** Over real hardware, a PARTIAL — the Pi clearly seeing attack
traffic but not pinning every class — is the honest, expected outcome. A FAIL
(nothing written at all) is the real red flag: check that the adapter is
injecting, the detector is running, and the AP, adapter and detector are all on
the same channel.

---

## Tests

`backend/tests/test_inject_attack.py` covers argument parsing, the safety gate,
the count/rate caps, and frame building — all without a radio or root, so they
run on any OS:

```bash
pytest backend/tests/test_inject_attack.py -v
```
