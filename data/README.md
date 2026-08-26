# HawkShield — data

Three different things live under this heading:

1. **`data/samples/`** — six small 802.11 captures, committed to this repository. They are what the
   tests run against and what lets you demo HawkShield with no radio.
2. **AWID3** — the **v2** training dataset, hosted externally and **not** in this repo. §2.
3. **The legacy merged tshark CSV** — what the **v1** bundles were trained on, also external. §3.

Neither training archive is in the repository and neither is needed to run HawkShield. They are only
needed to retrain.

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

Every frame carries a RadioTap header, so the extractor can populate the radio features exactly as it
would live. The `deauth` capture is the most useful of the six: it is short, densely malicious, and it
is the one both the v1 leakage ablation and the v2 batching benchmark in
[`../models/README.md`](../models/README.md) are built on.

Taken together the six captures exercise **all 46** of the v2 features at least once — 40 to 46 per
individual capture, since a capture with no EAPOL handshake and no reason-coded management frames
cannot exercise those groups. Measure it yourself with the coverage table
`replay_pcap.py` prints at the end of every run.

> ⚠️ These are **attack captures**, not a labelled train/test set. They contain no ground-truth column
> and no clean-traffic baseline. Use them to exercise the pipeline, not to measure accuracy.

### Replaying them

`backend/scripts/replay_pcap.py` pushes a capture through the *same* extractor and pipeline the live
detector uses, so what it prints is what the Pi would have done with those frames. **This is the
offline demo path — no radio, no monitor mode, no Raspberry Pi.**

It honours `--model-version` (`auto` | `v1` | `v2`), so the replay follows whichever generation the
detector would: v2 goes through `packet_to_features_v2` and the same ring buffer the capture loop
uses, v1 through `packet_to_row` and `TwoStagePipeline`. With no v2 artefact on disk, `auto` is v1.

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

# reproduce a row of the v1 leakage ablation
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --model-version v1 --dry-run --null-feature frame.time_relative
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
| `--model-dir PATH` | load artefacts from somewhere other than `MODEL_DIR` |
| `--model-version` | `auto` (default) \| `v1` \| `v2` — which generation to replay through |
| `--batch-frames N` | v2 only: frames scored per onnxruntime call (default 32) |
| `--json` | machine-readable output |
| `--log-level` | `DEBUG` … `CRITICAL` |

The report prints packets read, throughput, capture span, the attack-gate hit rate, the persisted count,
the stage-2 label distribution over stage-1 hits, and **per-feature non-null coverage** — that last
table is the fastest way to tell whether extraction is doing its job on a new capture.

### Using your own capture

Anything with RadioTap headers works:

```bash
sudo tcpdump -i wlan1 -w mycapture.pcapng      # adapter already in monitor mode
python -m backend.scripts.replay_pcap mycapture.pcapng
```

---

## 2. AWID3 — the v2 training dataset (external)

The **v2** model is trained on **AWID3**, the Wi-Fi attack dataset published by the University of the
Aegean. It is **not in this repository** and is not needed to run HawkShield — only to retrain.

| | |
|---|---|
| Archive | ~**14.7 GB** zip, containing ~46 GB of tshark CSV |
| Scale | ~37 M frames, 254 tshark columns |
| Structure | one folder per attack, each split into `<Attack>_0.csv`, `<Attack>_1.csv`, … of 50 000 frames |
| Expected path | `D:/AWID3.zip` by default — override with `-Zip` / `--zip` on the training runner |

`ml/prepare_awid3.py` **streams the zip without extracting it** (~24 M frames in about 4 minutes
across 6 workers) and writes Parquet shards of 46 features + label + `block_id` — roughly 300 MB — to
`_work/awid3_v2/`. You never need 46 GB of free disk.

**Nine of AWID3's fourteen classes are used**: `Normal`, `Deauth`, `Disas`, `(Re)Assoc`, `RogueAP`,
`Krack`, `Kr00k`, `Evil_Twin`, `SSDP`. The five application-layer classes — `SSH`, `Botnet`,
`Malware`, `SQL_Injection`, `Website_spoofing` — are **deliberately excluded**: they are separable
only through decrypted TCP/TLS payload fields, which a monitor-mode Pi with no keys never sees.
Training on them would rebuild the exact train/inference gap that made v1 useless. This is a
documented non-goal, recorded in code in `backend/detector/feature_spec.py`.

**One block = one 50 000-frame source file**, and whole blocks are held out for evaluation.
`frame.number` runs continuously across an attack's chunk files, so each attack in AWID3 is a
*single* recording session and leave-one-capture-out would delete the class. That limit is real and
is stated wherever the numbers are: see [`../models/README.md` §2.6](../models/README.md).

Everything about running the pipeline — the one-command runner, wall-clock expectations, RAM,
the split protocol, the NaN decision, how to read the reports — is in
[`../ml/README.md`](../ml/README.md).

---

## 3. The v1 training dataset (external, legacy)

The **v1** bundles in `models/` were **not** trained on AWID3 and not on the sample captures above.
They were trained on a merged tshark CSV export of the project's own capture sessions, covering both
normal activity and attack scenarios.

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
[`../models/README.md` §3.3](../models/README.md). The v2 contract that replaces it is 46 features
derived by one shared function; see [`../docs/models.md` §3](../docs/models.md).

### Do not retrain on this

> ⚠️ **This dataset and these notebooks are the v1 failure, kept for the record.** The notebooks
> shuffle rows across the train/test split, so frames from a single capture land on both sides and the
> reported ~99 % accuracy is meaningless. The feature space contains `frame.time_relative` (41.9 % of
> stage-1's split gain, and pure capture-session identity), `radiotap.channel.freq` (band identity),
> and two categoricals scapy cannot produce at all. Re-running them unchanged reproduces the same
> failure exactly.
>
> **Retrain with `ml/run_training.ps1` on AWID3 (§2) instead.** That pipeline holds out whole blocks,
> derives training and inference features with the same function, and bans the session- and
> band-encoding fields by name in `feature_spec.EXCLUDED_COLUMNS`.

Full analysis of what went wrong and how v2 answers it:
[`../models/README.md` §3.5](../models/README.md).

---

## 4. Notes on use

* The dataset is provided **as-is, for research and educational purposes**.
* Ensure compliance with your institution's policies and with local law regarding the capture,
  storage and use of wireless traffic data. Capturing 802.11 traffic on networks you do not own or
  have written permission to test is illegal in many jurisdictions.
* The sample captures were taken in a controlled lab environment. They still contain real MAC
  addresses from the devices involved; treat them as you would any other network capture.
