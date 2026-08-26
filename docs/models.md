# HawkShield — models

A short orientation to the two LightGBM bundles the detector loads.

> **The full model card lives in [`../models/README.md`](../models/README.md)** — provenance and
> digests, bundle internals, the exact transform order, per-capture replay results, and **§5, the
> leakage analysis**. This page is the map; that file is the territory. Nothing here is duplicated
> from it beyond what you need to find your way.

---

## 1. Pipeline

One extractor, two models, two thresholds.

```
scapy frame
   → packet_to_row()            29 numeric features (+2 always-absent categoricals)
   → stage 1  binary LightGBM   p1 = P(attack)
        p1 < STAGE1_THRESHOLD  → drop, nothing persisted
   → stage 2  multiclass LightGBM   (label, p2)
        p2 < STAGE2_THRESHOLD  → drop, nothing persisted
   → INSERT into packets
```

Both bundles share **one identical feature space**, which is the whole reason a single extractor can
feed both. The transform is the same for each stage:

```
DataFrame(imputer.feature_names_in_)   # 29 named columns, NaN where the frame had nothing
  → imputer.transform                   # median fill
  → scaler.transform                    # kept as a DataFrame throughout
  → reindex onto feature_order          # 31 columns; the 2 categoricals become 0.0
  → Booster.predict(X.values, num_iteration=best_iteration)
```

Getting that order wrong is the single most likely way to break inference silently. It is specified
normatively in [`CONTRACT.md` §5](CONTRACT.md) and explained in
[`../models/README.md` §2](../models/README.md).

Implementation: `backend/detector/features.py` (extraction) and `backend/detector/pipeline.py`
(`Stage1`, `Stage2`, `TwoStagePipeline`, `Verdict`).

---

## 2. The six classes

Stage 2's `id_to_class`, in the bundle's own order:

| id | Label | What it is meant to represent |
|---:|---|---|
| 0 | `SSDP` | SSDP/UPnP-based flooding and amplification traffic |
| 1 | `Evil_Twin` | An AP impersonating a legitimate SSID to capture clients |
| 2 | `Krack` | Key-reinstallation attack against the WPA2 4-way handshake |
| 3 | `Deauth` | Deauthentication flood — forced disconnects |
| 4 | `(Re)Assoc` | Association / reassociation request flooding |
| 5 | `RogueAP` | An unauthorised access point on the monitored network |

Two properties worth internalising:

* **There is no seventh "none of the above" class.** Anything that clears stage 1 is forced into one
  of these six. The stage-2 confidence floor is the only guard against a confident wrong name.
* **The training set was extremely skewed.** The bundle's own class weights run from `SSDP 0.29` to
  `RogueAP 99.94` — a ~340× spread.

The label is written verbatim to `packets.predicted_label`, and every API aggregation keys off these
exact strings, punctuation included (`(Re)Assoc`, `Evil_Twin`).

---

## 3. Thresholds

| Setting | Default | Applies to | Effect |
|---|---|---|---|
| `STAGE1_THRESHOLD` | `0.40` | `p1 = P(attack)` | below it the frame is dropped and never stored |
| `STAGE2_THRESHOLD` | `0.80` | `p2`, the confidence of the chosen class | below it the frame is dropped even though stage 1 flagged it |

Both are environment variables read through `backend/app/config.py`; nothing is hardcoded. Stage 1's
bundle carries its own `best_threshold` of `0.4`, so the shipped default and the bundle agree.

Raising `STAGE1_THRESHOLD` cuts volume and false positives; lowering it catches more and logs more
noise. Raising `STAGE2_THRESHOLD` reduces mislabelling without changing sensitivity — it is the knob
to reach for first, because it is the only defence against the missing "unknown" class.

To see what a threshold change does before deploying it, replay a sample capture with the values you
are considering:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --threshold1 0.6 --threshold2 0.9
```

---

## 4. Feature space

**31 features**: positions 1–29 are the numeric columns the imputer and scaler were fit on, positions
30–31 are categoricals.

| Group | Features |
|---|---|
| Frame | `frame.encap_type`, `frame.len`, `frame.time_delta`, `frame.time_delta_displayed`, `frame.time_relative` |
| RadioTap | `radiotap.channel.flags.cck`, `radiotap.channel.flags.ofdm`, `radiotap.channel.freq`, `radiotap.datarate`, `radiotap.dbm_antsignal`, `radiotap.length`, `radiotap.rxflags` |
| 802.11 header | `wlan.duration`, `wlan.fc.ds`, `wlan.fc.frag`, `wlan.fc.order`, `wlan.fc.moredata`, `wlan.fc.protected`, `wlan.fc.pwrmgt`, `wlan.fc.type`, `wlan.fc.retry`, `wlan.fc.subtype`, `wlan.seq` |
| Radio metadata | `wlan_radio.duration`, `wlan_radio.channel`, `wlan_radio.data_rate`, `wlan_radio.frequency`, `wlan_radio.signal_dbm`, `wlan_radio.phy` |
| Categorical (always absent live) | `wlan.country_info.fnm`, `wlan.country_info.code` |

The exact ordered list is in [`../models/README.md` §3](../models/README.md) and, normatively, in
[`CONTRACT.md` §5](CONTRACT.md). `backend/detector/features.py::FEATURE_ORDER` is the code's copy and
must match both.

**No identity fields are in the feature space.** No MAC, no BSSID, no SSID, no payload, no
upper-layer protocol — those were blocked during dataset construction and are only kept alongside the
prediction, in the `packets` row and the `raw` JSON blob, for the analyst.

The extraction rule is: **a field the frame does not actually carry stays `None`** so the bundle's
imputer fills it with the training median. Nothing is invented. The two categoricals have no scapy
equivalent, are always absent at inference, and are filled with `0.0` when the row is reindexed —
which matters, because `wlan.country_info.fnm` carries 15.5 % of stage-2's split gain.

---

## 5. Where the bundles came from

| Stage | File | Original name | Booster | `best_iteration` |
|---|---|---|---|---|
| 1 | `models/stage1_binary_bundle.joblib` | `binary_classifier_final.joblib` | LightGBM binary | 245 |
| 2 | `models/stage2_multiclass_bundle.joblib` | `multiclass_lightgbm_bundle.joblib` | LightGBM multiclass (6) | 116 |

They were trained in Colab from a merged **tshark CSV export** of the project's own capture sessions —
`merged_shuffled_20250822_185836.csv`, which is **not in this repository**. Columns were kept only if
they began with `frame.`, `radiotap.`, `wlan.` or `wlan_radio.`, with all identity, payload and
upper-layer fields blocked; numeric columns were median-imputed and z-scored, and the two categoricals
were handed to LightGBM's native categorical support. The notebooks are committed with outputs
stripped:

```
notebooks/EDA.ipynb                    exploration of the merged export
notebooks/binary_classifier.ipynb      stage 1
notebooks/multiclass_classifier.ipynb  stage 2
```

Dataset access and the Colab path are documented in [`../data/README.md`](../data/README.md).

Digests, sizes and the sha256 values the detector logs on every start are in
[`../models/README.md` §1](../models/README.md). Check what is actually on disk at any time:

```bash
python -m backend.scripts.verify_models
python -m backend.scripts.verify_models --model-dir /srv/hawkshield/models --json
```

It exits non-zero if a bundle is missing, unreadable, or internally inconsistent — mismatched feature
counts, a missing imputer or scaler, an empty class map — and warns if the md5 differs from the
contract.

Bundle locations are environment-driven: `MODEL_DIR` (default `<repo>/models`), `STAGE1_MODEL`,
`STAGE2_MODEL`.

---

## 6. Known limitations — read before trusting a label

Summarised here so nobody deploys without seeing it. **The measurements, the ablation table and the
reproduction commands are in [`../models/README.md` §5](../models/README.md).**

**The pipeline is sound; the models are not.** Capture, extraction, storage, the API and the dashboard
are correct and tested. The problem is confined to the two bundles.

1. **`frame.time_relative` is a leaked feature.** Seconds since capture start carries **41.9 % of
   stage-1's split gain** (16.7 % of stage-2's), with a training median of ~583 s. It encodes *which
   capture session a row came from*, not whether traffic is malicious. It also drifts monotonically:
   a detector up for a day feeds values near 86 400 where the model saw ~583, and restarting resets
   it to zero.
2. **`radiotap.channel.freq` is a leaked feature.** ~8.9 % of stage-1's gain, training median
   5180 MHz. The training captures were mostly 5 GHz; the Pi captures on 2.4 GHz.
3. **The dependence is measurable, not theoretical.** On the 20 000-frame `deauth` sample — ~97 %
   genuine deauthentication frames — stage 1 flags 82 frames (0.41 %) with everything populated,
   **20 000 (100 %)** with `frame.time_relative` forced null, and **0** with `radiotap.channel.freq`
   forced null. Reproduce with
   `python -m backend.scripts.replay_pcap <capture> --dry-run --null-feature <name>`.
4. **Stage 2 answers `Krack` for every frame of all six sample captures.** Before the
   feature-extraction fix the old code answered `SSDP` for everything. Neither is a real prediction.
5. **The two categoricals are permanently constant live.** `wlan.country_info.fnm` (15.5 % of
   stage-2's gain) and `wlan.country_info.code` cannot be produced by scapy and are always `0.0`, so
   stage 2 evaluates a constant where it was trained on a varying signal.

**Why the original looked like it worked.** The old extractor left 13 of the 29 numeric features
permanently `None`, and every one was imputed to a training median that happens to sit where the model
expects attack traffic. It flagged nearly everything — the right answer for the wrong reason. Honest
extraction removed the accident and exposed the real behaviour.

**Recommended remedy.** Retrain with **capture sessions held out of the train/test split** — the
notebooks shuffle rows, so frames from one capture land on both sides and the reported accuracy is
optimistic — and **drop the session-encoding features** (`frame.time_relative`,
`frame.time_delta*`) and the **band-encoding** ones (`radiotap.channel.freq`, `wlan_radio.frequency`,
`wlan_radio.channel`).

Until then, treat live labels as **indicative, not authoritative**, particularly when the deployment
band (2.4 GHz) or the run length differs from the training captures.

One further structural caveat: only frames clearing both thresholds are persisted, so the `packets`
table cannot be used to estimate a false-positive rate after the fact. Use
`backend/scripts/replay_pcap.py`, which reports the stage-1 hit rate over every frame read.

---

## 7. Not to be confused with the `/ask` assistant

"The model" is ambiguous in this repo, and the distinction matters when reading a label.

| | Detection models | `/ask` assistant |
|---|---|---|
| What | the two LightGBM bundles in `models/` | a hosted LLM, `GEN_MODEL`, default `deepseek/deepseek-v4-flash` via OpenRouter |
| Runs | on the Pi, offline, on every frame | only when someone asks a question, over the network |
| Produces | `predicted_label`, `proba_anomaly`, `proba_attack` | prose, and read-only `SELECT`s over rows the detectors already wrote |
| Required | yes — no bundles, no detection | no — with no key, `/ask` returns 503 and nothing else changes |

**The leakage described in §6 is a property of the LightGBM bundles alone.** Which LLM answers `/ask`
has no bearing on it whatsoever: a better assistant reads the same mislabelled rows more fluently.
Retraining the bundles is the only fix, and it has not happened yet.
