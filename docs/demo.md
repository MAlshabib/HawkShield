# HawkShield — demo & real-time testing runbook

The doc to read ten minutes before you present. It covers the laptop demo, the `/control` page, how to
read the result table, what the failover looks like when the Pi drops, and the over-the-air test that
is the real proof.

> **The one thing to know, and to say out loud.** Every detection the **Simulate** button produces is
> a *real* model prediction on held-out AWID3 data — the same `build_pipeline` the live Pi runs, the
> same `PacketSink`, the same `packets` table. Nothing is fabricated. It is not a mock feed and it is
> not random numbers. What it is *not* is proof of field generalisation: AWID3 recorded each attack
> once, so this is a within-testbed result, an upper bound on real-world performance
> ([`models/README.md` §2.7.1](../models/README.md)). Lead with the first sentence; keep the second
> honest.

---

## The two-command laptop demo

No Wi-Fi adapter, no PostgreSQL, no configuration. From the repo root, using the project interpreter:

```bash
python run.py --demo
```

`run.py` detects the laptop, falls back to a local SQLite file because the shipped `DATABASE_URL`
still says `CHANGE_ME`, creates the schema, and — because of `--demo` — replays a sample capture into
the database so the charts are not empty on first load. Then it prints the dashboard URL.

Open the URL it prints and go to the **Control** page (`http://localhost:8000/control`, also in the
navbar). Click **Run simulation**. That is the demo.

> **`--demo` vs Simulate — worth knowing before someone asks.** `--demo` replays one of the bundled
> `data/samples/*.pcapng` captures. Those are *out-of-domain* — the original project's testbed, not
> AWID3 — so the AWID3-trained model flags them and labels almost all of them `Krack` (the
> cross-deployment gap, [`models/README.md` §2.7.1](../models/README.md)). That is a genuine finding,
> not a bug, but it is not a clean class breakdown. **Simulate is the clean demonstration:** held-out
> AWID3 rows, all eight classes classifying at ~99–100%. If you want the dashboard to open on a tidy
> eight-class picture, launch with plain `python run.py` (no `--demo`) and let Simulate populate it.

Use the project's own interpreter — `.venv/bin/python run.py`, or `.venv/Scripts/python.exe run.py`
on Windows — and run it **from the repo root**.

---

## The `/control` page

A page (new, in the navbar) that hosts the full **Simulate** control next to a live backend readout.
The same control also sits at the top of the dashboard. It talks only to the API — no capture source,
no detector — so it stays usable even when the Pi is unreachable (see [Failover](#failover--plan-b)).

### The Simulate control

| Control | What it does |
|---|---|
| **Attack checkboxes** | Pick which classes to generate: `deauth`, `disas`, `reassoc`, `rogueap`, `krack`, `kr00k`, `evil_twin`, `ssdp`. Default selection is `deauth` + `disas`. |
| **All** | Generate every class in the corpus (all eight). Wider than the crafted-frame path, which only covers six. |
| **Count** | Target *persisted detections per class*. Presets plus a free field, capped at `SIM_MAX_COUNT` (default **500**). |
| **Intensity** | `burst` runs flat out; `trickle` adds a small pause (~20 ms per replay pass) so the live tail visibly ticks over — cosmetic, it does not change the result. |
| **Run simulation** | `POST /simulate`. Returns when the run is done and the result table fills in. |

Under the hood each requested class replays its held-out AWID3 segment through the real pipeline
(reset each pass) until `count` detections persist or a full pass yields nothing new. Every persisted
row is written through the same `PacketSink` the detector uses, tagged `raw.sim = true`,
`raw.sim_batch = <uuid>`, `raw.sim_class`, with locally-administered synthetic MACs (`02:5a:11:…`).

### Reading the result table

The summary reports **what the model did**, not what you asked for — so an under-detecting class shows
in the numbers rather than being smoothed over. Per class:

| Column | Meaning |
|---|---|
| `requested` | the per-class `count` you asked for |
| `frames_pushed` | how many corpus frames were replayed to reach it |
| `detected` | frames that cleared both thresholds (stage 2, a real label) |
| `persisted` | rows actually written to `packets` |
| `top_label` | the most common label the model assigned |
| `labels` | the full `{label: count}` breakdown |

**A good run:** every class `persisted == requested`, and `top_label` equal to the class you asked
for. Over the committed corpus all eight classes hit 100% correct-persist. The one honest wrinkle:
`RogueAP` is the sparsest class in all of AWID3, so its segment occasionally mixes a `Disas` into its
persisted rows — the `labels` map shows it. That is the summary being honest, not a fault.

The simulated rows carry `raw.sim = true` but are **invisible in the normal dashboard shape by
design** — they look exactly like real detections, because they *are* real model output. They are
trivially filterable and purgeable when you want a clean slate:

```sql
-- SQLite (laptop demo)
DELETE FROM packets WHERE json_extract(raw,'$.sim') = 1;
-- PostgreSQL (Pi)
DELETE FROM packets WHERE raw->>'sim' = 'true';
```

### Watching it land in real time

Two ways to watch detections arrive as they are written, both live:

```bash
# terminal tail, coloured, one line per detection; SIM tag on simulated rows
python -m backend.scripts.live_monitor --follow
python -m backend.scripts.live_monitor --follow --sim-only      # simulated rows only

# raw Server-Sent Events, one JSON event per new row
curl -N http://localhost:8000/stream
```

The dashboard consumes `GET /stream` itself to upgrade its live feed, and falls back to polling if the
stream errors — so the on-screen numbers move on their own while a `trickle` run is in flight.

---

## Failover — plan B

The failure a live demo actually fears is a dead Pi, not a wrong label. HawkShield's answer is
composure, never fabricated numbers.

When the API is unreachable, or `/health` reports `database: false`, the dashboard:

- shows a calm chip — **"Reconnecting…"** (backend gone) or **"Reconnecting to storage…"** (API up,
  database not answering) — instead of blanking or erroring;
- **keeps the last good data on screen**, stamped **"Updated Ns ago"**, so it is obvious the view is
  frozen and *why*, rather than the numbers silently going stale;
- keeps the **Simulate** control enabled, because it needs only the API. If the API is reachable you
  can repopulate believable, real-model data on the spot.

So the recovery move during a demo is: if the Pi's capture stops, go to `/control` and **Run
simulation** — the dashboard refills with genuine model output and the presentation continues. The
system never shows a number it cannot stand behind.

---

## The real proof — over-the-air (`tools/inject_attack.py`)

> **⚠️ Legal note — read first.** Transmitting deauthentication / disassociation frames against
> networks you do not own is **illegal in most jurisdictions.** This is for your own testbed only.
> `inject_attack.py` refuses to transmit unless you pass **both** `--i-own-this-network` and an
> explicit `--target-bssid`, and it prints the legal warning on every run.

Everything above pushes frames through the pipeline *in software*. The one test that exercises the
whole chain — **antenna → capture → feature extraction → model → database** — is transmitting real
802.11 frames over the air from a second monitor-mode adapter and confirming the Pi saw them.

The frames are not crafted in the tool; they come byte-for-byte from `backend/detector/attack_sim.py`,
the same factory `POST /simulate` and `--self-test` use. The tool retargets each frame's BSSID to your
own AP, transmits with scapy's `sendp`, and (with `--verify`) grades what the Pi wrote.

```bash
sudo python tools/inject_attack.py \
    --iface wlan1mon \
    --target-bssid de:ad:be:ef:00:01 \
    --attack all --count 50 --rate 20 \
    --i-own-this-network \
    --verify postgresql://hawk:password@pi.local:5432/hawkshield
```

**Safety gates (enforced in code, cannot be bypassed):** refuses without both
`--i-own-this-network` and a well-formed, non-broadcast `--target-bssid`; hard caps `--count ≤ 1000`
and `--rate ≤ 100/s` with no flag to raise them; requires Linux, root, and an interface actually in
monitor mode (checked via `iw dev`). Build, `--help` and the safety gate run on any OS.

**Reading `--verify`:** it grades each injected class **PASS / PARTIAL / FAIL**.

- **PASS** — the Pi labelled at least one new frame as that exact class.
- **PARTIAL** — the Pi saw attack traffic but under a *different* label. **This is expected, not a
  bug:** the shipped model is AWID3-trained and validated across time within one recording, not across
  radio hardware ([`models/README.md` §2.7.1](../models/README.md)). Frames from a different antenna,
  driver or RF environment may be detected as *an* attack but mislabelled. A PARTIAL over the air is
  the honest shape of that documented cross-deployment gap.
- **FAIL** — the Pi wrote nothing. That is the real red flag: check the adapter is injecting, the
  detector is running, and the AP, adapter and detector are all on the same channel.

Full setup, adapter requirements and the flag table are in [`tools/README.md`](../tools/README.md).

---

## Before you present — a 60-second checklist

```bash
# 1. The model actually loads and predicts on this machine (exit 0 = live)
python -m backend.detector.cli --self-test

# 2. Launch (laptop, SQLite, no config)
python run.py --demo            # or plain `python run.py` for a clean eight-class start

# 3. Open the printed URL → Control page → Run simulation
# 4. Optional: a terminal tail to show rows landing live
python -m backend.scripts.live_monitor --follow --sim-only
```

`--self-test` builds the pipeline and pushes crafted frames through the feature extractor and
inference path, asserting the model loaded and every frame produced a complete 46-feature vector and a
finite `p1`. It does **not** assert class labels — crafted frames carry no realistic inter-frame
timing, and timing is the booster's single most important feature, so a mislabel there is expected and
documented. Exit 0 means the model is live; a non-zero exit names the missing or corrupt artefact.

---

## Related docs

- [`docs/api.md`](api.md) — `POST /simulate`, `GET /stream` and the exact response shapes.
- [`tools/README.md`](../tools/README.md) — the over-the-air self-test in full.
- [`data/sim/README.md`](../data/sim/README.md) — why the corpus is contiguous held-out AWID3, and the
  per-class self-classification numbers.
- [`models/README.md` §2.7.1](../models/README.md) — what the accuracy numbers do and do not say.
