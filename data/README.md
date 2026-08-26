# HawkShield — data

Two different things live under this heading:

1. **`data/samples/`** — six small 802.11 captures, committed to this repository. They are what the
   tests run against and what lets you demo HawkShield with no radio.
2. **The training dataset** — a large merged tshark CSV, hosted externally and **not** in this repo.
   It is what the two model bundles were trained on, and what you would need to retrain them.

---

## 1. Sample captures

`data/samples/` holds six `.pcapng` files, **20 000 frames each**, one per attack scenario. They are
raw monitor-mode captures from the project's own lab sessions, decrypted, and they are committed on
purpose (`.gitignore` excludes `.pcapng` everywhere else).

| File | Scenario | Capture span | Size |
|---|---|---:|---:|
| `assoc_flood_raw_decrypted.pcapng` | Association / reassociation request flood | 23 156 s | 3.8 MB |
| `auth_flood_raw_decrypted.pcapng` | Authentication request flood | 3 261 s | 4.8 MB |
| `beacon_raw_decrypted.pcapng` | Beacon flood / rogue-AP beaconing | 2 830 s | 4.6 MB |
| `deauth_raw_decrypted.pcapng` | Deauthentication flood — **~97 % genuine deauth frames** | 79 s | 2.6 MB |
| `disassoc_raw_decrypted.pcapng` | Disassociation flood | 2 328 s | 9.0 MB |
| `probe_raw_decrypted.pcapng` | Probe-request flood / active scanning | 2 105 s | 9.4 MB |

Every frame carries a RadioTap header, so `packet_to_row()` can populate the radio features exactly as
it would live. The `deauth` capture is the most useful of the six: it is short, densely malicious, and
it is the one the leakage ablation in [`../models/README.md` §5](../models/README.md) is built on.

> ⚠️ These are **attack captures**, not a labelled train/test set. They contain no ground-truth column
> and no clean-traffic baseline. Use them to exercise the pipeline, not to measure accuracy.

### Replaying them

`backend/scripts/replay_pcap.py` pushes a capture through the *same* `packet_to_row()` and
`TwoStagePipeline` the live detector uses, so what it prints is what the Pi would have done with those
frames. **This is the offline demo path — no radio, no monitor mode, no Raspberry Pi.**

You do not need to call it directly. `run.py --demo` replays a capture into the database
and then serves the dashboard on top of the result — on a laptop with no configuration at all, since
it falls back to a local SQLite file:

```bash
python run.py --demo                                    # 4000 frames of assoc_flood, then the dashboard
python run.py --demo --demo-capture data/samples/deauth_raw_decrypted.pcapng --demo-frames 20000
```

Call the script directly when you want the analysis report rather than a dashboard:

```bash
# one capture; --dry-run is the DEFAULT, nothing touches the database
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng

# all six, capped at 5000 frames each, machine-readable
python -m backend.scripts.replay_pcap data/samples/*.pcapng --limit 5000 --json

# write the detections to the database so the dashboard has something to draw
python -m backend.scripts.replay_pcap data/samples/beacon_raw_decrypted.pcapng --to-db

# reproduce a row of the leakage ablation
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --dry-run --null-feature frame.time_relative
```

Run everything **from the repo root** — `backend` is a package. On the Pi, prefix with
`.venv/bin/python`; on Windows use `.venv/Scripts/python.exe`.

| Flag | Effect |
|---|---|
| `--dry-run` | never open a database connection (**default**) |
| `--to-db` | write detected attacks through `PacketSink`, exactly as the live detector does |
| `--limit N` | stop after N packets per file |
| `--threshold1` / `--threshold2` | override the decision thresholds for this run |
| `--null-feature NAME` | force a feature to null before scoring; repeatable — this is the ablation switch |
| `--per-packet` | score one row at a time instead of in chunks (slower, identical result) |
| `--iface NAME` | the interface name recorded on the rows |
| `--model-dir PATH` | load bundles from somewhere other than `MODEL_DIR` |
| `--json` | machine-readable output |
| `--log-level` | `DEBUG` … `CRITICAL` |

The report prints packets read, throughput, capture span, the stage-1 hit rate, the persisted count,
the stage-2 label distribution over stage-1 hits, and **per-feature non-null coverage** — that last
table is the fastest way to tell whether extraction is doing its job on a new capture.

### Using your own capture

Anything with RadioTap headers works:

```bash
sudo tcpdump -i wlan1 -w mycapture.pcapng      # adapter already in monitor mode
python -m backend.scripts.replay_pcap mycapture.pcapng
```

---

## 2. Training dataset (external)

The models in `models/` were **not** trained on the sample captures above. They were trained on a
merged tshark CSV export of a larger set of capture sessions, covering both normal activity and attack
scenarios.

**Download:**
[Wi-Fi Intrusion Dataset (Google Drive)](https://drive.google.com/file/d/1bcwa-lyhl1WRI4PfzhDu0HSR8479_ki4/view?usp=sharing)

The merged file is `merged_shuffled_20250822_185836.csv`. The training notebooks read it from a
mounted Google Drive path in Colab:

```
/content/drive/MyDrive/Bootcamp_ML_Data_Science/Capstone_Project/
    model_with_out_source_data/data_extraction/merged_shuffled_20250822_185836.csv
```

To re-run `notebooks/binary_classifier.ipynb` or `notebooks/multiclass_classifier.ipynb` anywhere
else, download the file and change that one path. The notebooks are committed with their outputs
stripped.

**How the feature space was built.** Columns were kept only if they began with `frame.`, `radiotap.`,
`wlan.` or `wlan_radio.`. All identity fields (BSSID, SSID, MAC, addr), payload fields and
upper-layer protocols were **blocked** — the models never see who sent a frame. Numeric columns were
median-imputed and z-scored; the two categorical columns were kept as pandas categoricals and handed
to LightGBM's native categorical support. That yields the 29 + 2 = 31 column space described in
[`../docs/models.md`](../docs/models.md).

### If you are retraining — read this first

The shipped models have a **documented training-data leakage problem**, measured and reproducible.
Do not retrain by re-running the notebooks unchanged; you will reproduce the same failure.

* **Hold capture sessions out of the train/test split.** The notebooks shuffle rows, so frames from a
  single capture appear on both sides of the split and the reported accuracy is optimistic.
* **Drop the session-encoding features**: `frame.time_relative`, `frame.time_delta`,
  `frame.time_delta_displayed`. `frame.time_relative` alone carries 41.9 % of stage-1's split gain and
  encodes which capture session a row came from.
* **Drop the band-encoding features**: `radiotap.channel.freq`, `wlan_radio.frequency`,
  `wlan_radio.channel`. The training captures were mostly 5 GHz; the Pi captures on 2.4 GHz.
* **Consider dropping the two categoricals** (`wlan.country_info.fnm`, `wlan.country_info.code`).
  scapy cannot produce them, so they are constant `0.0` at inference regardless of what the model
  learned — and `fnm` carries 15.5 % of stage-2's gain.
* **Capture some normal traffic on the deployment band** and include it. The current stage-1 gate has
  no idea what benign 2.4 GHz traffic looks like.

Full analysis: [`../models/README.md` §5](../models/README.md).

---

## 3. Notes on use

* The dataset is provided **as-is, for research and educational purposes**.
* Ensure compliance with your institution's policies and with local law regarding the capture,
  storage and use of wireless traffic data. Capturing 802.11 traffic on networks you do not own or
  have written permission to test is illegal in many jurisdictions.
* The sample captures were taken in a controlled lab environment. They still contain real MAC
  addresses from the devices involved; treat them as you would any other network capture.
