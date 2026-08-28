# HawkShield — models

HawkShield ships **two generations** of detector. v2 is a causal temporal CNN over a 46-feature
contract shared by training and inference. v1 is the two-stage LightGBM pair it replaces, kept as a
fallback and as a post-mortem.

> **Diagrams live in [`model-pipeline.md`](model-pipeline.md)** — the whole system, feature
> derivation, the network, the split protocol and the live path, as rendered flowcharts. This page is
> the prose; that page is the picture. The **normative** definitions are in
> [`CONTRACT.md` §5](CONTRACT.md), and the model card with provenance and per-generation detail is
> [`../models/README.md`](../models/README.md).

> **Status — v2 is trained and shipping.** `models/` holds `hawkshield_v2_gbdt.txt` (LightGBM,
> **0.9907** held-out macro-F1, the model `auto` selects), `hawkshield_v2.onnx` (causal TCN, 0.9856,
> selectable with `--model-version v2-tcn`) and the v1 bundles for fallback. Full per-class tables,
> confusion matrices and the leakage ablation are in
> [`ml/reports/eval_report.md`](../ml/reports/eval_report.md) and
> [`models/README.md` §2.7](../models/README.md). The numbers are an upper bound on field
> performance: AWID3 recorded each attack once, so the held-out blocks share the training blocks'
> session and hardware.

---

## 1. Which generation runs

`MODEL_VERSION` (or `--model-version` on `backend.detector.cli` and `backend.scripts.replay_pcap`)
selects:

| value | behaviour |
|---|---|
| `auto` *(default)* | v2 when `models/hawkshield_v2.onnx` **and** its meta exist and the meta matches the running `feature_spec`; otherwise v1, with the reason logged at ERROR |
| `v2` | v2 or nothing — a mismatch raises `SpecMismatchError` and the process exits `2`. Never a silent downgrade |
| `v1` | the two-stage LightGBM bundles |

Whichever loads logs one line at startup — `ACTIVE MODEL: v2 (causal TCN, ONNX) spec=…` or
`ACTIVE MODEL: v1 (two-stage LightGBM) …` — and **that line is the authoritative record of what is
running.** `/health` reports the same thing advisorily as `model_version`, `spec_version` and
`artefact_spec_version`.

---

## 2. The v2 pipeline

```
scapy frame
   → scapy_to_raw()            802.11 + radiotap → a tshark-named dict
   → derive_frame_features()   the SAME function training calls
   → 46 floats; a field the frame does not carry is NaN, never invented
   → ring buffer of the last 126 frames (causal context)
   → causal dilated TCN, ONNX fp32   → 9 class scores per frame
        p1 = 1 − P(Normal)     ; p1 < STAGE1_THRESHOLD → drop
        label = argmax over the eight attack classes (never "Normal")
        p2 = P(label)          ; p2 < STAGE2_THRESHOLD → drop
   → INSERT into packets
```

Implementation: `backend/detector/feature_spec.py` (the contract),
`backend/detector/features.py::scapy_to_raw` / `packet_to_features_v2` (extraction),
`backend/detector/pipeline.py::V2Pipeline` (inference).

Three properties are worth stating explicitly, because each one is a v1 failure made impossible:

**One derivation, two callers.** `ml/prepare_awid3.py` (training) and
`backend/detector/features.py` (inference) both call `feature_spec.derive_frame_features()`. There is
no second implementation to drift from the first. A feature that cannot be produced live is not
allowed into the spec.

**Load-time validation is mandatory.** `V2Pipeline` refuses to start unless the artefact's
`spec_version`, class list, feature list *and feature order*, feature count and normalisation vector
lengths all match the running `feature_spec`, and the ONNX graph's own declared channel dimensions
match too. All faults are reported at once, naming the artefact and the fix. This is not theoretical:
it rejected a stale artefact on its first run, which is exactly the job.

**NaN is signal, never imputed.** The graph replaces NaN with a *learned per-feature sentinel* and
raises a companion mask channel, so "absent" is a position the network chose rather than "absent ==
average". Any code that fills a missing feature with a mean, a median or `0.0` before handing it to
this model has reintroduced the v1 defect.

### Batching and threading

The prediction for the newest frame is valid from past context alone, so the detector keeps a ring
buffer and scores `V2_BATCH_FRAMES` (default **32**) frames per onnxruntime call by feeding
`context + N` positions and reading the last `N` outputs. Every scored frame still sees a full
context, so batching is a cost decision and never a correctness one —
`backend/tests/test_pipeline_v2.py::test_streaming_equivalence` pins that.

Measured over 5000 frames of `data/samples/deauth_raw_decrypted.pcapng` through the full capture path
(`V2_ORT_THREADS=2`, dev CPU):

| `V2_BATCH_FRAMES` | calls | per-frame inference | throughput | inference share of wall time |
|---:|---:|---:|---:|---:|
| 1 | 5000 | 1347.5 µs | 292 frame/s | 39 % |
| **32** | **157** | **54.7 µs** | **723 frame/s** | **4 %** |
| 64 | 79 | 41.4 µs | 716 frame/s | 3 % |

N=32 costs at most 32 frames of added detection delay (~32 ms at 1000 frame/s). N=64 halves the
remaining 4 % and doubles the delay, which buys nothing measurable — the other 96 % is scapy parsing
and feature derivation.

`V2_ORT_THREADS` defaults to **2, not 0**. Left at the onnxruntime default (one thread per core,
spin-waiting between calls) the same replay ran at 302 frame/s and 166 µs/frame — **2.4× slower end to
end**. A capture loop calling a small graph every 32 frames is not a batch job. This matters more on
a four-core Pi than on a desktop.

---

## 3. The 46-feature contract, and why it exists

`feature_spec.FEATURE_ORDER` is 46 features in nine groups. Every one is derivable from a
monitor-mode frame with **no decryption keys**.

| Group | n | Features |
|---|---:|---|
| Radio / PHY | 7 | `radio.freq_mhz`, `radio.is_5ghz`, `radio.cck`, `radio.ofdm`, `radio.datarate`, `radio.signal_dbm`, `radio.rt_len` |
| Radio presence flags | 3 | `radio.has_tsft`, `radio.has_rate`, `radio.has_signal` |
| Frame basics | 3 | `frame.len`, `frame.dt`, `frame.dt_log` |
| 802.11 frame control | 11 | `fc.type`, `fc.subtype`, `fc.ds`, `fc.retry`, `fc.protected`, `fc.pwrmgt`, `fc.moredata`, `fc.frag`, `fc.order`, `wlan.duration`, `wlan.seq_delta` |
| Address semantics | 6 | `addr.da_broadcast`, `addr.da_multicast`, `addr.sa_is_bssid`, `addr.sa_local_admin`, `addr.ta_eq_sa`, `addr.same_bssid_as_prev` |
| Management body | 7 | `mgmt.has_reason`, `mgmt.reason_code`, `mgmt.beacon_interval`, `mgmt.cap_ess`, `mgmt.cap_ibss`, `mgmt.ssid_len`, `mgmt.tag_len` |
| Security / RSN | 3 | `rsn.mfpc`, `rsn.has_pmkid`, `rsn.country_present` |
| EAPOL handshake | 6 | `eapol.present`, `eapol.type`, `eapol.len`, `eapol.msgnr`, `eapol.key_len`, `eapol.replay_counter` |

The ordered list is authoritative in `backend/detector/feature_spec.py::FEATURE_ORDER`; the artefact
carries a copy in `models/hawkshield_v2_meta.json` and the runtime asserts the two agree.

**No raw identity is in the feature space.** Addresses appear only as *semantics* — is the
destination broadcast, is the source also the BSSID, is the locally-administered bit set (most
injection tools set it), did the BSSID change since the previous frame. SSID appears only as a
length. The model can never memorise the testbed's MACs or network name.

**The management and EAPOL groups are the point.** v1's feature space contained neither, and they are
where the signal lives: `mgmt.has_reason` is set on 100 % of Deauth, Disas and Kr00k frames in AWID3
and on 0.3 % of Normal ones. The 802.11 reason code that carries most of it — 7, "class-3 frame from
a nonassociated station" — is in the clear on every management frame, key or no key.

### What is banned, and why it is banned in code

`feature_spec.EXCLUDED_COLUMNS` is a dict from field name to the reason it may never be a feature.
A training test enforces it. Three families:

* **Session identity** — `frame.time_relative`, `frame.time`, `frame.time_epoch`, `frame.number`,
  and every raw TSF counter (`radiotap.mactime`, `wlan_radio.start_tsf`, `wlan.fixed.timestamp`, …).
  These encode *which capture a row came from*, or which device's clock stamped it.
  `frame.time_relative` alone was 42 % of v1's stage-1 split gain.
* **Identifiers** — `wlan.sa`, `wlan.da`, `wlan.ta`, `wlan.ra`, `wlan.bssid`, `wlan.ssid`. Memorising
  the attacker's address is not detection.
* **Anything above the MAC layer** — `ip.*`, `tcp.*`, `udp.*`, `data.data`, payloads. A monitor-mode
  Pi without keys never sees them, so training on them rebuilds the v1 train/inference gap.

Two of these are read for derivation and grouping (the address semantics above need `wlan.sa` to
compute `addr.sa_is_bssid`) but none reaches the model.

### Feature coverage, live

The measure that mattered most in the v1 post-mortem was *how many features the live extractor can
actually produce*. Replaying `data/samples/*.pcapng` through `packet_to_features_v2` populates
**all 46** v2 features at least once — 40 to 46 per individual capture, depending on whether that
capture carries EAPOL handshakes and reason-coded management frames. v1's live extractor populated
**13 of its 29**; the other 16 were permanently NULL and mean-imputed to training medians. Reproduce
the count with:

```bash
python -m backend.scripts.replay_pcap data/samples/*.pcapng --model-version v2
```

The report's last table is per-feature non-null coverage — for v2 it counts NaN as absent, which is
the same convention the model is trained under. Read it over the *whole* capture set: an individual
capture reaches only 40–46, because one that contains no EAPOL handshake and no reason-coded
management frame cannot exercise those groups no matter how good the extractor is.

> `--model-version v2` needs a v2 artefact on disk and will fail without one. Until training
> completes, use `--model-version v1` to exercise the replay path; the v2 coverage figures above were
> measured by calling `packet_to_features_v2` directly, which needs no model.

---

## 4. The nine classes

`feature_spec.CLASSES` = `Normal` + `feature_spec.ATTACK_CLASSES`:

| # | Label | Evidence it is detected from |
|---:|---|---|
| 0 | `Normal` | — the majority class; classified and dropped, never persisted |
| 1 | `Deauth` | deauthentication flood — unencrypted management frame + reason code |
| 2 | `Disas` | disassociation flood — unencrypted management frame + reason code |
| 3 | `(Re)Assoc` | (re)association request flood — unencrypted management frames |
| 4 | `RogueAP` | unauthorised AP — beacon / SSID / BSSID inconsistency |
| 5 | `Krack` | key reinstallation — EAPOL message-3 replay, unencrypted |
| 6 | `Kr00k` | all-zero temporal key after disassociation — data-frame pattern |
| 7 | `Evil_Twin` | SSID impersonation — beacon / capability / radio mismatch |
| 8 | `SSDP` | SSDP amplification — volumetric data-frame pattern |

`Disas` and `Kr00k` are **new in v2**; v1 had six classes and no way to name either. The label is
written verbatim to `packets.predicted_label`, and every API aggregation keys off these exact strings,
punctuation included.

Unlike v1's stage 2, v2 **does** have a "none of the above" position: `Normal` is a real class the
model can choose, rather than an absence that has to be inferred from a threshold. `STAGE2_THRESHOLD`
remains as a confidence floor on the attack name.

### The five AWID3 classes that are deliberately excluded

AWID3 also labels `SSH`, `Botnet`, `Malware`, `SQL_Injection` and `Website_spoofing`. HawkShield does
not train on them, and that is a decision rather than an oversight.

Those labels are separable **only** through decrypted TCP/TLS payload fields. On a monitor-mode Pi
with no keys, every column that distinguishes them is NULL on every frame. A model trained on them
would learn from columns that do not exist at inference time — which is precisely the train/inference
gap that made v1 useless. Excluding them costs five class names and buys the guarantee that every
class the model can emit is one it can actually see evidence for.

This is recorded in code in the comment block above `feature_spec.ATTACK_CLASSES`, and in
[`../ml/README.md`](../ml/README.md) under *Non-goals*.

---

## 5. Thresholds

| Setting | Default | Applies to | Effect |
|---|---|---|---|
| `STAGE1_THRESHOLD` | `0.40` | v1: `p1 = P(attack)`. v2: `p1 = 1 − P(Normal)` | below it the frame is dropped and never stored |
| `STAGE2_THRESHOLD` | `0.80` | the confidence of the chosen attack class | below it the frame is dropped even though stage 1 flagged it |

Both env vars apply to **both generations**, so a threshold you tuned on v1 means the same thing on
v2. Nothing is hardcoded; they are read through `backend/app/config.py`.

To see what a threshold change does before deploying it, replay a sample capture with the values you
are considering:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --threshold1 0.6 --threshold2 0.9
```

Once v2 weights exist, the thresholds should be re-checked against
`ml/reports/eval_report.md` rather than inherited on faith — they were chosen for a two-stage
LightGBM gate, not for a nine-way softmax.

---

## 6. The model, and why fp32 ships

A causal dilated temporal CNN (`ml/model.py`), exported to ONNX.

```
input   "frames"  (batch, 46, T) float32    NaN = the frame does not carry that field
output  "logits"  (batch,  9, T) float32    one prediction per frame
```

* **6 residual blocks**, kernel 3, dilations 1·2·4·8·16·32 → a **127-frame past-only receptive
  field**. ~**80,527 parameters**, 348 KB as fp32 ONNX.
* **Causal, provably.** Every convolution is left-padded only, and normalisation is `ChannelNorm`
  (LayerNorm across channels at one timestep) rather than `BatchNorm1d`/`GroupNorm`, both of which
  average over the time axis and would leak the future into frame *t*'s statistics.
  `ml/model.py::assert_causal()` perturbs every frame after *t* and asserts the output at *t* is
  **bit-identical**; it runs at the start of every training run and again before every ONNX export.
* **Per-frame output.** Every frame gets its own label — which is what `packets` stores and the
  dashboard shows — with no window-level smearing.

**Why a rate-aware model at all.** A single deauthentication frame is legitimate; sixty per second is
an attack. The class lives in the rate and the pattern, not in the individual frame, so the model
needs temporal context — but a live sensor may only ever look backwards.

**fp32 ships, not int8.** `ml/export_onnx.py` also emits an int8 dynamic-quantised variant. It is
2.6× smaller (348 KB → 134 KB) and measured **~4× slower**: onnxruntime has no fast int8 Conv1d
kernel at these shapes and dequantises per call. The export prints the ratio. Quantise only if you are
flash-bound, and **re-measure on the Pi first** — the arithmetic there is different.

**A LightGBM baseline trains on the identical split** (per-frame features plus 36 causal rolling
aggregates, because a tree sees one row at a time and otherwise cannot represent "sixty deauths in
the last second"). Whichever wins on macro-F1 ships. A ~1 MB tree model that beats the network is the
better answer for a Pi, and `ml/reports/eval_report.md` says so rather than hiding it.

---

## 7. Training v2

Training happens on a laptop or workstation with a GPU, **never on the Pi**. The Pi only ever loads
the exported ONNX artefact.

```powershell
.\ml\run_training.ps1 -Fresh          # Windows; -Fresh re-runs AWID3 preprocessing
```
```bash
./ml/run_training.sh --fresh          # Git Bash / WSL
```

One command: dependency check → preprocess AWID3 → train → evaluate → export. Roughly **50–90 min**
end to end on an RTX 4070 SUPER with 16 cores; 4–6 h CPU-only. PyTorch is deliberately *not*
installed for you.

Full details — the stage table, the flag variants, RAM requirements, the split protocol, the NaN
decision and how to read the reports — are in [`../ml/README.md`](../ml/README.md). The source data is
AWID3; see [`../data/README.md`](../data/README.md).

### Evaluation protocol, and its honest limit

Evaluation is **grouped by `block_id`** — one block is one contiguous 50,000-frame AWID3 source file —
and whole blocks are held out. No row of a held-out block was seen in training, and no training window
spans a block boundary.

It is **not** leave-one-capture-out, and it cannot be: `frame.number` runs continuously across AWID3's
`Deauth_0.csv → Deauth_1.csv → …`, so each attack folder is a *single* recording. Holding out the
capture would delete the entire class from training.

Read the resulting numbers accordingly. Held-out blocks share the session, testbed, radios and ambient
traffic of the training blocks, so what is measured is **generalisation across time within one
testbed**, not generalisation to your network. Treat the reported macro-F1 as an **upper bound** on
field performance.

What the protocol does buy is that frame *i* in train and near-identical frame *i+1* in test can no
longer happen — which is how v1 reported ~99 % accuracy while being worthless on real air.

### Results

**Pending.** No trained v2 weights exist in this repository yet, so no v2 accuracy figure is quoted
anywhere in these docs. When `run_training` completes it writes:

| File | Contents |
|---|---|
| `ml/reports/train_report.md` | rows per class per split, the causality probe (`max_delta_past` must be exactly `0.0`), the per-epoch table |
| `ml/reports/eval_report.md` | per-class precision / recall / F1 / support, macro-F1, the 9×9 confusion matrix, the head-to-head against LightGBM, and the leakage-ablation probe |

> Both files currently contain output from an earlier **smoke run on a 2.4 M-row subset at spec
> `2.0.0`**, not the shipping model. They are overwritten by the real run. Do not quote them.

---

## 8. v1 — what it was, and exactly how it failed

The two LightGBM bundles in `models/` are still on disk, still selectable with `MODEL_VERSION=v1`,
and still the automatic fallback while no v2 artefact exists. They are also the most instructive
thing in this repository, so the post-mortem is kept in full rather than deleted.

**Shape.** `models/stage1_binary_bundle.joblib` gates (`p1 = P(attack)`), then
`models/stage2_multiclass_bundle.joblib` names one of six classes. Both share one 31-column feature
space — 29 numeric plus two categoricals — so one extractor feeds both. The transform order
(`imputer` → `scaler` → reindex → `Booster.predict`) is specified in
[`CONTRACT.md` §5.2](CONTRACT.md) and [`../models/README.md`](../models/README.md).

**Failure 1 — training and inference derived features in different code.** The models were trained on
tshark columns. The detector runs scapy. **16 of the 29 numeric features could not be produced live**,
arrived NULL on every frame, and were mean-imputed by the bundle's own `SimpleImputer` to training
medians. The model then keyed on those constants. Nothing anywhere reported this.

**Failure 2 — `frame.time_relative` was leakage.** Seconds since capture start carried **41.9 % of
stage-1's split gain** and **16.7 % of stage-2's**, while encoding nothing but which capture session a
row came from. It also drifts monotonically: a detector up for a day feeds values near 86,400 where
the model saw ~583, and restarting resets it to zero. `radiotap.channel.freq` carried another ~8.9 %
and encoded the band — the training captures were mostly 5 GHz, the Pi is pinned to 2.4 GHz.

**The measurement.** Leave-one-out ablation on the 20,000-frame `deauth_raw_decrypted.pcapng`, which
is ~97 % genuine deauthentication frames:

| Stage-1 input | Frames flagged attack |
|---|---:|
| every feature correctly populated | 82 / 20 000 (**0.41 %**) |
| `frame.time_relative` forced null → imputed to 582.7 s | 20 000 (**100 %**) |
| `radiotap.channel.freq` forced null → imputed to 5180 MHz | 0 (**0 %**) |
| all 16 newly-populated features forced null (original behaviour) | 19 976 (99.9 %) |

Reproduce any row:

```bash
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --model-version v1 --dry-run --null-feature frame.time_relative
```

A model whose output flips between 0 % and 100 % on the presence of one bookkeeping column is not
detecting anything. Stage 2, correspondingly, answered `Krack` for every frame of all six sample
captures.

**How v2 answers each of these.**

| v1 failure | v2 response |
|---|---|
| two feature implementations | one `derive_frame_features()`, called by both `ml/prepare_awid3.py` and `backend/detector/features.py` |
| 16 features permanently NULL live | a feature that cannot be produced live may not enter the spec; all 46 populate on the real sample captures |
| missing values mean-imputed to a constant | NaN carried to the model as a learned sentinel plus a mask channel; nothing is imputed |
| session-identity features in the model | `EXCLUDED_COLUMNS` bans them by name, with the reason, enforced by a test |
| random row shuffle across the split | whole `block_id` groups held out; no window crosses a block boundary |
| feature space could silently disagree with the artefact | `V2Pipeline` refuses to load on any spec, class, feature or order mismatch |
| no way to notice any of the above | the leakage ablation is a standing part of `ml/evaluate.py` |

### Two v1 bugs that may have misled you

* **`wlan.duration` was byte-swapped.** scapy declares the 802.11 Duration/ID field big-endian; the
  header is little-endian. A real 314 µs duration was fed to the model as **14849** on every single
  frame since day one, and some frames exceeded the field's maximum possible value. Any conclusion
  drawn from a v1 `wlan_duration` column is wrong.
* **The dashboard rendered every `(Re)Assoc` row as `SSDP`.** An alias table round-tripped a key
  through its display string and never closed the loop, falling back to `allowedTypes[0]`. **Any SSDP
  figure read off the attacks page before this fix was inflated**, and the corresponding `(Re)Assoc`
  count was understated. The database rows were always correct; only the rendering was wrong.

`wlan_radio.signal_dbm` was also being read as the *first* antenna chain when tshark reports the
*last* — the two disagreed on 97.6 % of frames.

---

## 9. Not to be confused with the `/ask` assistant

"The model" is ambiguous in this repo, and the distinction matters when reading a label.

| | Detection model | `/ask` assistant |
|---|---|---|
| What | the ONNX TCN in `models/` (or the v1 bundles) | a hosted LLM, `GEN_MODEL`, default `deepseek/deepseek-v4-flash`, via OpenRouter |
| Runs | on the Pi, offline, on every frame | only when someone asks a question, over the network |
| Produces | `predicted_label`, `proba_anomaly`, `proba_attack` | prose, and read-only `SELECT`s over rows the detector already wrote |
| Required | yes — no model, no detection | no — with no key, `/ask` returns 503 and nothing else changes |

The v1 leakage described in §8 is a property of the LightGBM bundles alone. Which LLM answers `/ask`
has no bearing on it whatsoever: a better assistant reads the same rows more fluently.

---

## 10. Verifying what is on disk

```bash
python -m backend.scripts.verify_models
python -m backend.scripts.verify_models --model-dir /srv/hawkshield/models --json
```

It exits non-zero if a **v1** bundle is missing, unreadable or internally inconsistent — mismatched
feature counts, a missing imputer or scaler, an empty class map — and warns if the md5 differs from
the contract.

> **Gap:** `verify_models` inspects only the v1 joblib bundles. It has no v2 mode. To check a v2
> artefact, load it — `V2Pipeline`'s startup validation is the check, and
> `GET /health` reports the result as `model_version`, `artefact_spec_version` and `model_problems`
> without importing the detector.

Artefact locations are environment-driven: `MODEL_DIR` (default `<repo>/models`), `STAGE1_MODEL`,
`STAGE2_MODEL`, `V2_MODEL`, `V2_META`. See [`CONTRACT.md` §3](CONTRACT.md).
