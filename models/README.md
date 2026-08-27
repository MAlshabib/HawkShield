# HawkShield model card

Two generations live under this heading.

| | **v2 — current design** | **v1 — superseded** |
|---|---|---|
| Model | one causal dilated TCN, ONNX fp32 | two LightGBM `Booster`s in joblib bundles |
| Features | 46, from `feature_spec.FEATURE_ORDER` | 31 (29 numeric + 2 categorical) |
| Classes | 9 (`Normal` + 8 attacks) | 6 attacks, no `Normal` class |
| Split | grouped by 50k-frame block, whole blocks held out | random row shuffle |
| Status | **weights not yet trained — see §2.7** | on disk, selectable, and the automatic fallback |

> **What is actually in this directory right now:**
> ```
> models/stage1_binary_bundle.joblib      v1 stage 1
> models/stage2_multiclass_bundle.joblib  v1 stage 2
> models/README.md                        this file
> ```
> `MODEL_VERSION=auto` resolves to **`v2-gbdt`**: the LightGBM model won the held-out head-to-head
> (0.9907 macro-F1 against the TCN's 0.9856) and is what the detector serves. The TCN remains
> selectable with `--model-version v2-tcn`, and the v1 bundles remain as a last-resort fallback.
> Measured results are in §2.7.

Diagrams of both the training and the live path: [`../docs/model-pipeline.md`](../docs/model-pipeline.md).
Normative interface: [`../docs/CONTRACT.md` §5](../docs/CONTRACT.md). Orientation:
[`../docs/models.md`](../docs/models.md).

---

## 1. Selection

`MODEL_VERSION` (env, or `--model-version` on `backend.detector.cli` and
`backend.scripts.replay_pcap`):

| value | behaviour |
|---|---|
| `auto` *(default)* | v2 when `models/hawkshield_v2.onnx` + `models/hawkshield_v2_meta.json` exist **and** the meta matches the running `feature_spec`; otherwise v1, with the reason logged at ERROR |
| `v2` | v2 or nothing — a mismatch raises `SpecMismatchError` and the process exits `2` |
| `v1` | the two-stage LightGBM bundles in §3 |

Whichever loads logs `ACTIVE MODEL: …` once at startup. That line is authoritative;
`GET /health` reports the same thing advisorily.

---

## 2. v2 — causal TCN over the 46-feature contract

### 2.1 Intended use

Per-frame classification of 802.11 management, control and data frames captured in **monitor mode
without decryption keys**, on a Raspberry Pi 4, in real time. It answers "is this frame part of an
attack, and which one" for the eight attack classes in §2.3. It is a *detector*: it observes,
classifies and logs. It never blocks, disconnects or alerts.

**Out of scope by construction:** anything requiring decrypted payload. See §2.4.

### 2.2 Architecture

```
input   "frames"  (batch, 46, T) float32    NaN = the frame does not carry that field
output  "logits"  (batch,  9, T) float32    one prediction per frame
```

* Causal dilated temporal CNN — 6 residual blocks, kernel 3, dilations 1·2·4·8·16·32.
* **Receptive field 127 past frames.** Left-padded convolutions only.
* Normalisation is `ChannelNorm` (LayerNorm across channels at a single timestep). `BatchNorm1d` and
  `GroupNorm` both average over the time axis, which would make frame *t*'s statistics depend on
  frames *t+1…T* — future leakage hidden inside a normalisation layer.
* **80,471 parameters**; 348 KB as fp32 ONNX.
* Normalisation constants and mask-channel indices are baked into the graph as initialisers **and**
  copied into `hawkshield_v2_meta.json` so the runtime can assert the two agree.
* Source: `ml/model.py`. Export: `ml/export_onnx.py`.

**Causality is tested, not assumed.** `assert_causal()` perturbs every frame after *t* and requires
the output at *t* to be **bit-identical** (`max_delta_past == 0.0`), and separately requires the
future side to move so the probe cannot pass vacuously. It runs at the start of every training run
and again before every export. Run it standalone with `python ml/model.py`.

**Precision: fp32 ships.** An int8 dynamic-quantised variant is exported and is 2.6× smaller
(348 KB → 134 KB), but measures **~4× slower**: onnxruntime has no fast int8 Conv1d kernel at these
shapes and dequantises per call. Quantise only if flash-bound, and re-measure on the Pi first.

**A LightGBM baseline** (per-frame features + 36 causal rolling aggregates) trains on the identical
split. Whichever wins on macro-F1 ships.

### 2.3 Classes (9)

`Normal`, `Deauth`, `Disas`, `(Re)Assoc`, `RogueAP`, `Krack`, `Kr00k`, `Evil_Twin`, `SSDP`.

`Disas` and `Kr00k` are new in v2. `Normal` is a real class the model can choose, so unlike v1 there
is a genuine "none of the above" position rather than an absence inferred from a threshold.

Only the eight attack labels are ever written to `packets.predicted_label`; `Normal` frames are
classified and dropped.

### 2.4 Features (46) — the contract

Defined once, in `backend/detector/feature_spec.py`, and consumed by **both**
`ml/prepare_awid3.py` (training) and `backend/detector/features.py` (inference) through one function,
`derive_frame_features()`. There is no second implementation to drift.

| Group | n |
|---|---:|
| radio / PHY | 7 |
| radio presence flags | 3 |
| frame basics | 3 |
| 802.11 frame control | 11 |
| address semantics (derived — never a raw MAC) | 6 |
| management body (unencrypted) | 7 |
| security / RSN | 3 |
| EAPOL handshake (unencrypted) | 6 |

The ordered list is in `feature_spec.FEATURE_ORDER`; the artefact carries a copy and the runtime
compares them element by element. Group-by-group detail is in
[`../docs/models.md` §3](../docs/models.md).

**Deployment assumption, stated in the module docstring:** available at inference are radiotap
headers, the 802.11 MAC header, the bodies of unencrypted management frames (beacon, probe, auth,
assoc, deauth, disassoc) and EAPOL handshake frames. **Not** available: any IP/TCP/UDP/TLS field, and
the payload of protected data frames. Nothing in `FEATURE_ORDER` may depend on those.

**Banned fields are named in code.** `feature_spec.EXCLUDED_COLUMNS` maps every excluded column to the
reason it is excluded, and a training test enforces it — session-identity fields
(`frame.time_relative` and friends, raw TSF counters), identifiers (`wlan.sa`, `wlan.bssid`,
`wlan.ssid`, …) and everything above the MAC layer.

**Missing values are never imputed.** A field the frame does not carry becomes NaN for a magnitude or
`0.0` for a flag, with the same convention in training and inference. At the tensor boundary the
graph standardises with train-split-only mean/std, clamps to ±8σ, replaces NaN with a **learned
per-feature scalar**, and raises a **companion mask channel** so "absent" and "happens to equal the
sentinel" stay distinguishable. v1's mean-imputation is the specific thing this design exists to
prevent.

**Removed in spec 2.1.0:** `frame.fcs_bad`. `wlan.fcs.bad_checksum` is empty on 100 % of AWID3 rows,
so it would have been a constant in training while varying in the field — worse than no feature.

**Live coverage:** replaying all six captures in `data/samples/` through `packet_to_features_v2`
populates **all 46** features at least once (40–46 per individual capture — a capture with no EAPOL
handshake and no reason-coded management frames cannot exercise those six). The comparable v1 figure
is **13 of 29 producible at all**.

### 2.5 Training data

**AWID3** — the Wi-Fi attack dataset from the University of the Aegean. A 14.7 GB zip containing
~46 GB of tshark CSV, ~37 M frames across 254 columns. It is **not** in this repository; see
[`../data/README.md` §2](../data/README.md).

`ml/prepare_awid3.py` streams the zip without extracting it (~24 M frames in ~4 minutes across
6 workers) and writes Parquet shards of 46 features + label + `block_id`, ~300 MB.

**Five AWID3 classes are deliberately excluded**: `SSH`, `Botnet`, `Malware`, `SQL_Injection`,
`Website_spoofing`. They are separable only through decrypted TCP/TLS payload fields, which a
monitor-mode Pi never sees; training on them would rebuild the exact train/inference gap that killed
v1. This is a documented non-goal, recorded in code above `feature_spec.ATTACK_CLASSES`.

**Class balance** is handled twice, deliberately split so the two mechanisms do not double-count:
window subsampling (every attack-bearing window kept, plus `--normal-ratio` × as many Normal-only
windows — 90 % of frames are Normal) and capped inverse-frequency cross-entropy computed on the
*sampled* distribution.

### 2.6 Evaluation protocol

**Grouped by `block_id`.** One block is one contiguous 50,000-frame AWID3 source file. Whole blocks
are assigned to train / val / test; no row of a block appears in two splits, and no training window
spans a block boundary (`ml/windows.py` asserts this).

Assignment is a deterministic greedy pass, not `GroupShuffleSplit`: offer blocks rarest-class-first,
send each to whichever split is furthest below its per-class row target. `GroupShuffleSplit` on a
class living in two blocks routinely lands both in the same split and silently reports F1 = 0.

**Why not leave-one-capture-out.** `frame.number` runs continuously across AWID3's
`Deauth_0.csv → Deauth_1.csv → …`. Each attack was captured exactly once, so holding out "the
capture" removes the entire class from training. The split would be unrunnable, not stricter.

**What this protocol is worth — read before quoting any number.** It is **weaker than
leave-one-capture-out**. Held-out blocks share the session, testbed, radios and ambient traffic of the
training blocks. What is measured is generalisation *across time within one recording*, not across
deployments. Treat the reported macro-F1 as an **upper bound** on field performance.

What it does buy is that frame *i* in train and near-identical frame *i+1* in test can no longer
happen. A random row shuffle puts every attack burst on both sides of the split, which is how v1
scored ~99 % and was worthless on real air.

**Leakage probe.** `ml/evaluate.py` removes the top-gain feature and re-measures, three ways:
LightGBM retrained without the column (is the signal recoverable elsewhere?), LightGBM score-only
with the feature set to NaN (how brittle are the deployed weights?), and the TCN score-only. Ablation
sets the feature to **NaN, not zero** — zero post-normalises to the training mean, which is exactly
the silent imputation that broke v1. Watch for both failure shapes: a **cliff** (the model is one
feature in a trenchcoat) and **no movement at all** (ten other columns encode the same artefact).

### 2.7 Results

Trained 2026-08-27 on the full AWID3 archive: **23,716,279 frames** across **478 blocks**, split by
whole block into 287 train / 72 val / 119 test. All nine classes are present in the held-out set.
Reproduced by `ml/run_training.ps1 -Fresh`; raw output in
[`ml/reports/eval_report.md`](../ml/reports/eval_report.md).

**Held-out test macro-F1 over 5,943,908 frames:**

| model | macro-F1 | file | ships |
|---|---:|---|:--:|
| **LightGBM** (49 rounds × 9 classes = 441 trees) | **0.9907** | `hawkshield_v2_gbdt.txt`, 3.0 MB | **yes** |
| Causal TCN (80,471 params) | 0.9856 | `hawkshield_v2.onnx`, 348 KB | selectable |

The tree ensemble wins. That was a genuine measurement, not a foregone conclusion — the plan was
always that whichever model won on the same grouped split would ship, and the neural network lost.

**Per class, LightGBM (the shipped model):**

| class | precision | recall | F1 | support |
|---|---:|---:|---:|---:|
| Normal | 0.9997 | 0.9986 | 0.9992 | 4,449,777 |
| RogueAP | 1.0000 | 1.0000 | 1.0000 | 331 |
| Krack | 0.9999 | 0.9999 | 0.9999 | 16,009 |
| SSDP | 0.9960 | 0.9994 | 0.9977 | 1,374,169 |
| (Re)Assoc | 0.9971 | 0.9979 | 0.9975 | 1,401 |
| Evil_Twin | 0.9930 | 0.9871 | 0.9900 | 26,218 |
| Kr00k | 0.9915 | 0.9836 | 0.9875 | 47,332 |
| Deauth | 0.9760 | 0.9969 | 0.9863 | 9,851 |
| Disas | 0.9464 | 0.9694 | 0.9578 | 18,820 |

Where the two models differ most: LightGBM is far better on **Krack** (0.9999 vs 0.9644 — the TCN
loses 559 Krack frames to Normal), **(Re)Assoc** (0.9975 vs 0.9671) and **RogueAP** (1.0000 vs
0.9955). The TCN is better on **Disas** (0.9738 vs 0.9578) and marginally on Kr00k.

**Dominant error: Disas ↔ Kr00k**, in both models. 778 of 47,332 Kr00k frames (1.6 %) are called
Disas, and 342 of 18,820 Disas frames are called Kr00k. This is semantically reasonable — Kr00k is
*triggered* by a disassociation, and 100 % of both classes carry `mgmt.reason_code` — but it is the
single largest contributor to the macro-F1 gap. In an earlier run where each class had only one or
two blocks the same confusion consumed ~46 % of Kr00k; with tens of blocks per class it is 1.6 %.

**Top-gain features** — these are the sanity check that matters. Ranked 3, 4 and 5 are
`mgmt.reason_code`, `mgmt.tag_len` and `mgmt.has_reason`: real 802.11 management-frame evidence,
exactly what a human analyst would look at. None of the session artefacts that dominated v1 appear.

| rank | feature | note |
|---:|---|---|
| 1 | `roll64.frame.dt_log.mean` | inter-frame timing over the last 65 frames — rate, which is what makes a flood a flood |
| 2 | `addr.ta_eq_sa` | transmitter ≠ source: a relay/spoof indicator |
| 3 | `mgmt.reason_code` | present on 100 % of Deauth/Disas/Kr00k attack frames, 0.3 % of Normal |
| 4 | `mgmt.tag_len` | total tag-body size; was dead until the spec-2.1.0 parser fix |
| 5 | `mgmt.has_reason` | |

**Leakage probe.** Removing the top-gain feature and re-measuring:

| ablated | model | macro-F1 | Δ |
|---|---|---:|---:|
| `roll64.frame.dt_log.mean` | LightGBM, **retrained** without it | 0.9899 | **−0.0007** |
| `roll64.frame.dt_log.mean` | LightGBM, score-only (set to NaN) | 0.9876 | −0.0030 |
| `addr.ta_eq_sa` | TCN, score-only | 0.8912 | −0.0944 |

Graceful degradation on both failure shapes: no cliff, and movement rather than the suspicious zero
that would mean ten other columns encode the same artefact. Compare v1, where nulling
`frame.time_relative` flipped detection on a deauth capture from 0.41 % of frames to 100 %, and
nulling `radiotap.channel.freq` flipped it to 0 %.

### 2.7.1 What these numbers do not say

AWID3 recorded **each attack exactly once**, and `frame.number` runs continuously across an attack's
chunk files, so leave-one-capture-out would delete the class outright. Held-out blocks therefore share
the session, testbed, radio hardware and RF environment of the training blocks.

**0.9907 measures generalisation across time within one recording, not across deployments.** Read it
as an upper bound on field performance. A model that has only ever seen one testbed's hardware has
not been shown to survive different antennas, drivers, channel conditions or a different attacker's
tooling. Validating that needs a second, independently captured dataset — see §2.9.

### 2.7.2 Runtime cost, measured

5,000 frames of `data/samples/deauth_raw_decrypted.pcapng`, 2 threads, on an x86 laptop:

| model | µs/frame | throughput | share of the capture loop |
|---|---:|---:|---:|
| v2-gbdt *(selected by `auto`)* | 75.9 | 947 pkt/s | 7.2 % |
| v2-tcn | 35.9 | 1023 pkt/s | 3.7 % |
| v1 | — | 1101 pkt/s | — |

Scapy parsing and feature derivation dominate either way. Within the GBDT's 75.9 µs, `Booster.predict`
is only 5.4 µs — the causal rollup state is the larger half at 20.1 µs. At runtime the booster is the
**lighter** of the two models: +7.6 MB RSS against onnxruntime's +9.7 MB, despite the 3 MB file.

Expect roughly 4–8× these figures on a Pi 4, i.e. ~300–600 µs/frame, ~30–60 % of one core at
1,000 frames/s. If that budget is tight, `--model-version v2-tcn` is supported and costs about half.

### 2.8 Runtime behaviour

**Load-time validation is mandatory.** `V2Pipeline` refuses to start unless the meta's `spec_version`,
class list, feature list *and feature order*, `n_features` and normalisation vector lengths all match
the running `feature_spec`, **and** the ONNX graph's own declared input/output channel dims match too.
All faults are reported at once, naming the artefact and the fix. It rejected a stale artefact on its
first run, which is the whole point. This is the v1 post-mortem made executable.

**Streaming.** The detector keeps a ring buffer of the last `context` (126) frames, appends new frames
and reads the predictions at the last positions — the same arithmetic as
`ml.windows.inference_chunks`, so a frame scored offline and the same frame scored live see the same
history. At the head of a stream the sequence is simply shorter; there is no synthetic padding.

**Batching**, measured over 5000 frames of `data/samples/deauth_raw_decrypted.pcapng` through the
full capture path (`V2_ORT_THREADS=2`, dev CPU):

| `V2_BATCH_FRAMES` | calls | per-frame inference | throughput |
|---:|---:|---:|---:|
| 1 | 5000 | 1347.5 µs | 292 frame/s |
| **32** (default) | **157** | **54.7 µs** | **723 frame/s** |
| 64 | 79 | 41.4 µs | 716 frame/s |

Every scored frame still sees a full context, so batching is a cost decision and never a correctness
one. v1 on the same 5000 frames runs at 780 frame/s, so v2 costs ~7 % of end-to-end throughput.

**`V2_ORT_THREADS` is 2, not 0.** At the onnxruntime default (one thread per core, spin-waiting
between calls) the same replay ran at 302 frame/s — **2.4× slower end to end**. Matters more on a
four-core Pi than on a desktop.

**Verdict mapping** (so `sink.py` and the `packets` schema are unchanged):

```
p1    = 1 - P(Normal)                        compared against STAGE1_THRESHOLD (0.40)
label = argmax over the eight attack classes (never "Normal")
p2    = P(label)                             compared against STAGE2_THRESHOLD (0.80)
stage = 1 when p1 < thr1, else 2; 0 when inference failed
```

### 2.9 Known limitations

* **The evaluation split bounds performance from above** (§2.6). One testbed, one session per attack.
* **Five AWID3 attack families are not modelled at all** (§2.5). If your threat model includes
  application-layer attacks, this is not the detector for them, and no amount of retraining on a
  monitor-mode capture will change that.
* **Class supports are wildly uneven.** `RogueAP` is measured in tens of frames.
* **Only attacks are persisted**, so the `packets` table cannot be used to estimate a false-positive
  rate after the fact. Use `backend/scripts/replay_pcap.py`, which reports the hit rate over every
  frame read.
* **`STAGE1_THRESHOLD` / `STAGE2_THRESHOLD` were tuned for v1**, a two-stage LightGBM gate. They apply
  unchanged to v2's nine-way softmax and should be re-checked against `ml/reports/eval_report.md`.
* **`backend/scripts/verify_models.py` has no v2 mode** — it inspects the joblib bundles only. The v2
  check is `V2Pipeline`'s own load-time validation, surfaced by `GET /health`.
* **`run.py`'s preflight still hard-requires both v1 `.joblib` bundles**, so a checkout carrying a
  valid v2 artefact and no v1 bundles would be refused even though the detector would run fine.
  Recorded as a known gap in [`../docs/CONTRACT.md` §8.4](../docs/CONTRACT.md).

---

## 3. v1 — superseded, and why

The two LightGBM bundles are still on disk, still selectable with `MODEL_VERSION=v1`, and still the
automatic fallback while no v2 artefact exists. **They do not generalise**, for two reasons that are
now understood and fixed. The analysis is kept in full because it is the most instructive artefact in
this repository.

Verify what is on disk at any time:

```bash
python -m backend.scripts.verify_models
```

### 3.1 Provenance

| Stage | File | Original name | md5 | size |
|---|---|---|---|---|
| 1 | `stage1_binary_bundle.joblib` | `binary_classifier_final.joblib` | `d67bfee99f1188513eb46f9c3a83f1cb` | 1 643 071 B |
| 2 | `stage2_multiclass_bundle.joblib` | `multiclass_lightgbm_bundle.joblib` | `4ef700bd22eed51dea526e03f77befe0` | 436 996 B |

sha256 (logged by the detector on every start):

```
stage1  9c0437bdc2523d4964b664704edcb8017dd5585de2c339443f9b28be197012f9
stage2  f04ec48418bfce2b539053c694ca73caea0788a1668e7942d706ad26afbe74cd
```

Training notebooks (outputs stripped, source intact): `notebooks/EDA.ipynb`,
`notebooks/binary_classifier.ipynb`, `notebooks/multiclass_classifier.ipynb`.

Source data was a merged tshark CSV export (`merged_shuffled_20250822_185836.csv`, not in this repo).
Columns were kept only if they started with `frame.`, `radiotap.`, `wlan.` or `wlan_radio.`, with all
identity, payload and upper-layer fields blocked. Numeric columns were median-imputed then z-scored;
two categorical columns were handed to LightGBM's native categorical support.

**Rows were shuffled across the train/test split**, so frames from a single capture appear on both
sides. That is the first reason the reported ~99 % accuracy meant nothing.

### 3.2 Bundle structure

```python
# stage 1                                    # stage 2
{ "model":          lightgbm.Booster,        { "model":          lightgbm.Booster,
  "best_iteration": 245,                       "best_iteration": 116,
  "best_threshold": 0.4,                       "num_imputer":    SimpleImputer,   # NOTE the name
  "imputer":        SimpleImputer,             "scaler":         StandardScaler,
  "scaler":         StandardScaler,            "num_cols":       [29],
  "num_cols":       [29],                      "cat_cols":       [2],
  "cat_cols":       [2],                       "feature_order":  [31],
  "feature_order":  [31] }                     "class_order":    [6],
                                               "id_to_class":    {0..5},
                                               "class_weights":  {0..5} }
```

The imputer key differs between the two bundles (`imputer` vs `num_imputer`) — the loader accepts
either.

**The imputer and scaler were fit on the 29 numeric columns only, while the Booster expects 31.** The
transform order is therefore:

```
DataFrame(imputer.feature_names_in_)          # 29 named columns, NaN where absent
  -> imputer.transform                        # median fill
  -> scaler.transform                         # keep it a DataFrame or StandardScaler
                                              #   warns about missing feature names
  -> reindex onto feature_order               # 31 columns, the 2 cat_cols filled 0.0
  -> Booster.predict(X.values, num_iteration=best_iteration)
```

### 3.3 Feature order (31)

Positions 1–29 are `num_cols` (imputed + scaled); positions 30–31 are `cat_cols`.

```
 1 frame.encap_type              11 radiotap.length              21 wlan.fc.retry
 2 frame.len                     12 radiotap.rxflags             22 wlan.fc.subtype
 3 frame.time_delta              13 wlan.duration                23 wlan_radio.duration
 4 frame.time_delta_displayed    14 wlan.fc.ds                   24 wlan.seq
 5 frame.time_relative           15 wlan.fc.frag                 25 wlan_radio.channel
 6 radiotap.channel.flags.cck    16 wlan.fc.order                26 wlan_radio.data_rate
 7 radiotap.channel.flags.ofdm   17 wlan.fc.moredata             27 wlan_radio.frequency
 8 radiotap.channel.freq         18 wlan.fc.protected            28 wlan_radio.signal_dbm
 9 radiotap.datarate             19 wlan.fc.pwrmgt               29 wlan_radio.phy
10 radiotap.dbm_antsignal        20 wlan.fc.type                 30 wlan.country_info.fnm
                                                                 31 wlan.country_info.code
```

### 3.4 Classes and thresholds

`id_to_class = {0: SSDP, 1: Evil_Twin, 2: Krack, 3: Deauth, 4: (Re)Assoc, 5: RogueAP}` — six classes,
and **no "none of the above" option**. Anything clearing stage 1 is forced into one of the six.

```
p1 = P(attack)                     ; p1 < 0.40  -> drop, nothing persisted
label, p2 = stage2(row)            ; p2 < 0.80  -> drop, nothing persisted
otherwise                                       -> INSERT into packets
```

Stage-1's own `best_threshold` (0.4) matches the `STAGE1_THRESHOLD` default. Training-set class
weights show how skewed the source data was: `SSDP 0.29, Evil_Twin 0.52, Krack 2.18, Deauth 11.49,
(Re)Assoc 29.89, RogueAP 99.94` — a ~340× spread.

### 3.5 Why v1 does not work

#### Root cause 1 — training and inference derived features in different code

The models were trained on tshark output. The detector runs scapy. **16 of the 29 numeric features
could not be produced by the live extractor at all.** They arrived NULL on every frame and were
mean-imputed by the bundle's own `SimpleImputer` to training medians, and the model keyed on those
constants. Nothing in the system reported it.

Two columns are structurally unproducible even after the extractor was fixed:

| Feature | Why | Effect |
|---|---|---|
| `wlan.country_info.fnm` | tshark's parsed country-IE first-channel-number, exported as a category | filled with `0.0` when reindexing into the model space |
| `wlan.country_info.code` | tshark's parsed country string, exported as a category | filled with `0.0` |

`wlan.country_info.fnm` carries **15.5 % of stage-2's total split gain**, so stage 2 is permanently
evaluating a constant where it was trained on a varying signal.

#### Root cause 2 — `frame.time_relative` was pure leakage

Seconds since the first packet of the capture: **41.9 % of stage-1's split gain and 16.7 % of
stage-2's**. Training median 582.7 s, standard deviation 50.4 s. It is a property of *which capture
session a row came from*, not of the traffic. It also drifts monotonically — a detector up for a day
feeds values near 86 400 where the model saw ~583, and restarting resets it to zero.

`radiotap.channel.freq` (8.9 % / 18.1 % of gain, training median 5180 MHz) encodes the band: the
training captures were predominantly 5 GHz, while the Pi's monitor interface is pinned to a 2.4 GHz
channel by default.

#### The measurement

Leave-one-out ablation over the full 20 000-frame `deauth_raw_decrypted.pcapng` (~97 % of which *are*
deauthentication frames):

| Row fed to stage 1 | frames flagged attack |
|---|---:|
| every feature populated (current behaviour) | 82 (**0.41 %**) |
| same, but `frame.time_relative` forced null → imputed to 582.7 s | 20 000 (**100 %**) |
| same, but `radiotap.channel.freq` forced null → imputed to 5180 MHz | 0 (**0 %**) |
| all 16 newly-populated features forced null (original behaviour) | 19 976 (99.9 %) |

Reproduce any row:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --model-version v1 --dry-run --null-feature frame.time_relative
```

Read that carefully: the original detector "detected" this deauth flood only because
`frame.time_relative` was `None` and got imputed to the training median, which happens to sit in the
region the model associates with attack traffic. It was **right for the wrong reason**, and the same
accident classified the flood as `SSDP`. Filling the feature honestly removed the accident and
exposed that the model does not generalise off its training sessions.

The effect shows up across the whole sample set. Full 20 000-frame replay of each capture in
`data/samples/`, every feature populated, thresholds 0.40 / 0.80:

| capture | capture span | stage-1 flagged | persisted | stage-2 label |
|---|---:|---:|---:|---|
| `assoc_flood` | 23 156 s | 97.6 % | 16 150 | Krack (100 %) |
| `auth_flood`  |  3 261 s | 91.6 % | 10 788 | Krack (100 %) |
| `beacon`      |  2 830 s | 96.3 % | 12 841 | Krack (100 %) |
| `deauth`      |     79 s |  0.4 % |      0 | Krack (100 %) |
| `disassoc`    |  2 328 s | 94.7 % |  3 806 | Krack (100 %) |
| `probe`       |  2 105 s | 94.9 % |  3 313 | Krack (100 %) |

The one capture that is 79 seconds long is the one stage 1 stays silent on, and it is the one that is
97 % deauthentication frames. Stage 2 answers `Krack` for every frame of every capture, so the
multiclass stage carries no usable signal on 2.4 GHz traffic.

### 3.6 Two v1 bugs that may have misled you

Both were found while building v2. If you drew a conclusion from a v1 number, check it against these
first.

* **`wlan.duration` was byte-swapped.** scapy declares the 802.11 Duration/ID field big-endian; the
  header is little-endian. A real **314 µs** duration was read as **14 849**, on *every frame since
  day one*, and some frames exceeded the field's maximum possible value. `wlan.duration` was fed to
  both stages in that state, and `packets.wlan_duration` recorded it.
* **The dashboard rendered every `(Re)Assoc` row as `SSDP`.** An alias table round-tripped a key
  through its display string and never closed the loop; the fallback was `allowedTypes[0]`, which is
  `SSDP`. **Any SSDP figure read off the attacks page before this fix was inflated**, and the
  corresponding `(Re)Assoc` count was understated. The stored rows were always correct — only the
  rendering was wrong.

A third, smaller one: `wlan_radio.signal_dbm` was taken from the *first* antenna chain where tshark
reports the *last*. Verified against tshark, the two disagreed on **97.6 %** of frames.

### 3.7 Other v1 limitations

* Stage 2 has no "not one of my six classes" option; the `STAGE2_THRESHOLD` of 0.80 is the only guard.
* Only frames clearing both thresholds are persisted, so the `packets` table cannot be used to
  estimate a false-positive rate after the fact.
* `frame.encap_type` is constant `23` in the training data (`StandardScaler` records variance 0.0 for
  it) — tshark's encapsulation id for 802.11-plus-radiotap, and therefore a dead feature.

### 3.8 How v2 answers each of these

| v1 failure | v2 response |
|---|---|
| two feature implementations that could drift | one `derive_frame_features()`, called by both training and inference |
| 16 of 29 features permanently NULL live | a feature that cannot be produced live may not enter the spec; all 46 populate on the real sample captures |
| missing values mean-imputed to a training constant | NaN carried to the model as a learned sentinel + mask channel; nothing imputed |
| session- and band-identity features in the model | `EXCLUDED_COLUMNS` bans them by name, with reasons, enforced by a test |
| random row shuffle across the split | whole `block_id` groups held out; no window crosses a block boundary |
| feature space could silently disagree with the artefact | `V2Pipeline` refuses to load on any spec / class / feature / order mismatch |
| six classes, no `Normal` | nine classes including `Normal` |
| no mechanism to notice any of the above | the leakage ablation is a standing part of `ml/evaluate.py` |

None of which is a claim that v2 works. **That claim requires numbers, and the numbers do not exist
yet** (§2.7).
