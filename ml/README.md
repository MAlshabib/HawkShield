# HawkShield v2 — training pipeline

Everything that turns the AWID3 archive into a detector the Raspberry Pi can run,
and — more importantly — everything that stops us shipping another v1.

```
D:/AWID3.zip                 46 GB of CSV inside a 14.7 GB zip
   │
   │  ml/prepare_awid3.py            ~4 min, 16 cores
   ▼
_work/awid3_v2/**.parquet    ~24M rows × (46 float32 + label + block_id)
   │
   │  ml/train.py --model both       grouped split, never a random shuffle
   ▼
_work/models_v2/{tcn.pt, gbdt.txt, split.json}
   │
   ├── ml/evaluate.py        held-out blocks + leakage probe → ml/reports/eval_report.md
   └── ml/export_onnx.py     → models/hawkshield_v2.onnx, .int8.onnx, _meta.json
```

---

## One command

```powershell
# Windows
.\ml\run_training.ps1
```
```bash
# Git Bash / WSL
./ml/run_training.sh
```

It checks dependencies, preprocesses AWID3 if `_work/awid3_v2` is missing (or
`--fresh`/`-Fresh` is passed), trains, evaluates, and exports. Each stage is
echoed and a failure stops the run with the exit code and the stage name.

**PyTorch is not installed by default and the script will not install it for
you** — it is a 2.5 GB wheel and the choice of CUDA build is yours to make. For
the RTX 4070 SUPER:

```
.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu126
```

Without it the runner refuses `--model tcn`/`both` with that exact line printed,
and `--model gbdt` still works (LightGBM needs no torch).

### Useful variants

| goal | command |
|---|---|
| rebuild the parquet from the zip first | `./ml/run_training.sh --fresh` |
| tree baseline only, no GPU needed | `./ml/run_training.sh --model gbdt` |
| fast sanity pass on a subset of blocks | `./ml/run_training.sh --max-rows 2000000 --epochs 3` |
| force CPU | `./ml/run_training.sh --device cpu` |
| skip ONNX | `./ml/run_training.sh --skip-export` |

### Expected wall clock

Extrapolated from a measured end-to-end run on the 2.4 M-row smoke sample
(48 blocks, 16-core CPU, no GPU): 12 TCN epochs at ~60 s each plus LightGBM =
**13.2 min** total training; evaluation with the retrain probe ~2 min; export
<1 min. The full dataset is ~10× larger.

| stage | RTX 4070 SUPER + 16 cores | CPU only |
|---|---|---|
| `prepare_awid3.py` (full, 46 GB CSV) | ~4 min | ~4 min (I/O bound) |
| `train.py --model tcn --epochs 12` (24M rows) | ~20–40 min | 2–4 h |
| `train.py --model gbdt` (3M sampled rows) | ~10–20 min | same (CPU-only library) |
| `evaluate.py` + leakage probe | ~10–20 min | ~20–30 min |
| `export_onnx.py` | <1 min | <1 min |
| **full `run_training` end to end** | **~50–90 min** | ~4–6 h |

The GPU speedup on the TCN is real but bounded: batches are gathered by numpy on
the CPU, so above a few hundred windows per step the loader, not the GPU, is the
limit. Raising `--batch-size` past ~512 buys little.

RAM: the full dataset is held in one array — about 4.5 GB for features plus
overhead. 32 GB is comfortable; 16 GB wants `--max-rows 12000000`.

---

## The split protocol — read this before reading any number

### Why not leave-one-capture-out

`frame.number` is **continuous across an attack's chunk files**: `Deauth_0.csv`
through `Deauth_N.csv` are sequential slices of a single recording session. Each
attack in AWID3 was captured exactly once. Holding out "a capture" therefore
removes the entire class from training, which makes the split unrunnable rather
than strict.

### What we do instead

One **`block_id`** = one 50,000-frame contiguous source file. Whole blocks are
assigned to train / val / test; no row of a block ever appears in two splits, and
**no window ever spans a block boundary** (`ml/windows.py` asserts this).

Assignment is a deterministic greedy pass, not `GroupShuffleSplit`. With 48
blocks in the smoke sample and a class that lives in two of them,
`GroupShuffleSplit` routinely lands every one of them in the same split and
silently reports F1 = 0. The greedy version offers blocks rarest-class-first and
sends each to whichever split is furthest below its per-class row target. It is
still a strictly grouped split — it just does not gamble the rare classes on a
coin flip.

### What this protocol is worth

**It is weaker than leave-one-capture-out, and you must read the numbers with
that in mind.** Held-out blocks share the session, the testbed, the radios and
the ambient traffic of the training blocks. What is measured is generalisation
*across time within one recording*, not across deployments. Treat the reported
macro-F1 as an **upper bound** on field performance.

What it does buy — and this is the whole reason it exists — is that frame *i* in
train and near-identical frame *i+1* in test can no longer happen. A random row
shuffle makes every attack burst appear on both sides of the split, which is how
the predecessor model scored ~99% and was worthless on real air. Do not relax
this to make the numbers look better. If the numbers drop, the numbers were
always this low and the old split was lying.

---

## What gets built

### `ml/windows.py` — the grouping contract

Shared by training, evaluation and (by construction) the live detector.

* `load_blocks()` — shards → one contiguous array plus block boundaries. Row
  order inside a block is capture order and is never shuffled.
* `grouped_split()` / `split_report()` — the assignment above, plus a markdown
  table that **warns loudly** when a class has too few blocks to appear in every
  split. An absent class is reported as `-` and "absent from split", never as a
  score of 0.
* `training_windows()` — window start indices, each fully inside one block.
* `inference_chunks()` — exactly-one-prediction-per-frame tiling as
  `(ctx_start, pred_start, pred_end)`. Rows before `pred_start` are causal
  context whose predictions are discarded. **The live detector mirrors this with
  a ring buffer**: keep the last `context` frames, append the new one, take the
  prediction at the final position — identical arithmetic, so a frame scored
  offline sees exactly the history it would see online.
* `causal_rollups()` — strictly causal rolling mean/std/rate over the last 16 and
  64 frames of the same block, for the tree baseline.

### `ml/model.py` — the causal TCN

`(batch, 46, T) → (batch, 9, T)`, one prediction per frame.

> Spec **2.1.0** dropped `frame.fcs_bad`, taking the contract from 47 features to
> [!NOTE]
> **46**. The channel count is read from the checkpoint's normalisation vectors at
> construction time, so the network follows the spec automatically — but several
> docstrings in `ml/model.py` still say 47, and `assert_causal()`'s *default*
> `n_features` is still 47. That default only affects the standalone probe
> (`python ml/model.py`), not training or export, both of which pass the real
> width. `backend/detector/feature_spec.py` and
> [`../docs/CONTRACT.md` §5.1](../docs/CONTRACT.md) are the authority: **46**.

* 6 residual blocks, kernel 3, dilations 1·2·4·8·16·32 → **receptive field 127
  past frames**; ~81k parameters at the default width of 56 channels.
* **Every convolution is left-padded only.** Normalisation is `ChannelNorm` —
  LayerNorm across channels at a single timestep. `BatchNorm1d` and `GroupNorm`
  both average over the time axis, which means the statistics used to normalise
  frame *t* depend on frames *t+1…T*: future leakage hidden inside a
  normalisation layer.
* `assert_causal()` is the unit test: perturb every frame after *t*, assert the
  output at *t* is **bit-identical** (`max_delta_past == 0.0`), and assert the
  future side *did* move so the probe cannot pass vacuously. It runs
  automatically at the start of every training run and again before every ONNX
  export. Run it standalone with `python ml/model.py`.

#### NaN handling — the decision, stated plainly

The feature contract emits **NaN when a field is genuinely absent** (a data frame
has no `mgmt.reason_code`; absence is information). v1 mean-imputed those to a
training constant and then keyed on the constant. Here, at the tensor boundary:

1. standardise with **train-split-only** mean/std, then clamp to ±8σ;
2. replace NaN with a **learned per-feature scalar** (`FeatureFront.missing`),
   so the network chooses its own location in feature space for "absent" instead
   of being told absent == average;
3. append a **companion mask channel** for every feature that is ever NaN in
   training, so "absent" and "happens to equal the sentinel" stay distinguishable.

Nothing is imputed silently and nothing is imputed with a statistic. The mean/std
constants are saved in the checkpoint, baked into the ONNX graph as initialisers,
**and** written to `models/hawkshield_v2_meta.json` so the runtime can assert the
two agree and refuse to start if they do not.

### `ml/train.py` — both candidates, same data, same split

```
python ml/train.py --data _work/awid3_v2 --out _work/models_v2 \
    --model both --epochs 12 --batch-size 256 --window 128 \
    --device auto --max-rows 0 --seed 1337
```

Class imbalance is handled twice over, deliberately split between the two
mechanisms so they do not double-count:

* **window subsampling** — every attack-bearing window is kept, plus
  `--normal-ratio` (default 3) times as many Normal-only windows. 90% of frames
  are Normal; training on the raw mix spends nearly all compute on the majority
  class.
* **capped inverse-frequency cross-entropy**, with the weights computed on the
  *sampled* distribution. Uncapped weights on a 68-row class turn the loss
  surface into a cliff; `--weight-cap` trades a little rare-class recall for
  convergence.

The LightGBM baseline gets the 46 per-frame features plus 36 causal rolling
aggregates (a tree sees one row at a time and otherwise cannot represent "sixty
deauths in the last second").

`--max-rows` drops **whole blocks**, rarest-class-first — it never subsamples
rows, because that would destroy the contiguity the whole design rests on.

### `ml/evaluate.py` — held-out blocks and the leakage probe

```
python ml/evaluate.py --models _work/models_v2
```

Reloads `split.json`, so the test blocks are byte-identical to the ones training
never saw. Reports per-class precision/recall/F1/support, macro-F1 over classes
actually present, and a full 9×9 confusion matrix for each model.

Then the **leakage probe**. The top-gain feature is removed and the model
re-measured, in three variants:

| variant | what it tells you |
|---|---|
| LightGBM, retrained without the column | the honest one: is the signal recoverable elsewhere? |
| LightGBM, score-only (feature → NaN) | how brittle the *deployed* weights are if that field goes missing on a real capture |
| TCN, score-only (feature → NaN) | same, for the network |

Ablation sets the feature to **NaN, not zero** — NaN is a state the contract
defines and the model has a mask channel for, whereas zeroing post-normalises to
the training mean, which is exactly the silent imputation that broke v1.

This is the test that exposed v1: `frame.time_relative` carried 42% of stage-1
split gain while encoding nothing but which capture session a row came from, and
deleting it collapsed the model. A healthy detector degrades gracefully. Watch
for both failure shapes: a **cliff** (the model is one feature in a trenchcoat)
and **no movement at all** (ten other columns encode the same artefact).

### `ml/export_onnx.py` — ship it

```
python ml/export_onnx.py --models _work/models_v2 --out models
```

Exports with dynamic batch **and** time axes, verifies the ONNX graph against
PyTorch on **real AWID3 frames** (random noise does not reproduce the real NaN
*pattern* — `eapol.*` is NaN on every non-EAPOL frame, not 15% of the time),
applies int8 dynamic quantisation, re-verifies, and measures CPU latency for both
a full window and a single streaming decision. Writes
`models/hawkshield_v2_meta.json` with spec version, class list, feature order,
window/context, and the normalisation constants.

The latency benchmark runs in a **clean subprocess**. It has to: in-process, the
16-thread pools of the verification sessions spin-wait and torch's allocator adds
noise, and the same graph measured 0.35 ms standalone and 5 ms inside the export
process. A subprocess importing nothing but numpy and onnxruntime reproduces.
`--latency-threads` defaults to 4 to mirror a Pi rather than a 16-core desktop.

Note on int8: it cuts the file 2.6× (348 KB → 134 KB) but onnxruntime has no fast
int8 Conv1d kernel for these shapes and dequantises per call, so on x86 it
measures **~4× slower** than fp32. The export prints the ratio. Ship fp32 unless
you are flash-bound, and re-measure on the Pi before deciding — the arithmetic
there is different.

---

## Reading the reports

> ⚠️ **Both files in `ml/reports/` today are from an earlier smoke run** — a
> 2.4 M-row subset at spec **2.0.0**, on CPU, with several classes absent from the
> test split. They are shape examples, not results. **Do not quote a number out of
> them**, and do not copy one into a README or a slide: no v2 weights have been
> trained yet, and no v2 accuracy figure appears anywhere else in this repository
> for exactly that reason. A real `run_training` overwrites both.

`ml/reports/train_report.md`

* **Rows per class per split** — check this first. Any `Warning — too few blocks`
  line means a class could not be represented in some split and its metrics there
  are *undefined, not zero*. On the smoke sample this fires for several classes;
  on the full preprocessing pass it should not.
* **Causality probe** — `max_delta_past` must be exactly `0.0`. Anything else
  means the model can see the future and every number below it is fiction.
* **Per-epoch table** — train macro-F1 far above val macro-F1 is the block split
  doing its job, not a bug to tune away.

`ml/reports/eval_report.md`

* **Support column** — a class with support in the hundreds gives an F1 with an
  enormous confidence interval. `RogueAP` is the extreme case. Do not quote a
  three-decimal F1 on 68 frames as if it were measured.
* **Confusion matrix** — read the off-diagonals. Deauth ↔ Disas confusion is
  meaningful (near-identical management frames); anything ↔ Normal is the number
  that decides whether the box is usable.
* **Head to head** — if LightGBM wins, LightGBM wins. A ~1 MB tree model that
  beats the network on macro-F1 is the better answer for a Pi, and the report
  says so rather than hiding it.

---

## Shipping the result

`export_onnx.py` writes three files into `models/`. Two of them are what the Pi
needs:

```
models/hawkshield_v2.onnx         fp32 graph  -- SHIP THIS
models/hawkshield_v2_meta.json    spec version, classes, feature order, norm constants
models/hawkshield_v2.int8.onnx    exported for measurement -- do NOT ship
```

Copy the **pair** across and restart the detector:

```bash
scp models/hawkshield_v2.onnx      pi@<pi-ip>:~/HawkShield/models/
scp models/hawkshield_v2_meta.json pi@<pi-ip>:~/HawkShield/models/
ssh pi@<pi-ip> sudo systemctl restart hawkshield-detector
```

They travel together and they travel with the code. `V2Pipeline` compares the
meta's spec version, class list, feature list and **feature order** against the
running `backend/detector/feature_spec.py` and refuses a mismatch, naming the
artefact and the fix. Under `MODEL_VERSION=auto` it then falls back to v1 and logs
the reason at ERROR — visible in `GET /health` as `models.v2: false` plus a
`model_problems` list. Under `MODEL_VERSION=v2` it exits `2` instead of
downgrading.

Nothing here runs on the Pi. Training is a laptop/GPU job; the Pi loads an
artefact. See [`../docs/deployment-pi.md` §4.5](../docs/deployment-pi.md).

## Non-goals

SSH, Botnet, Malware, SQL_Injection and Website_spoofing are excluded from
AWID3 preprocessing. They are separable only through decrypted TCP/TLS payload
fields, which a monitor-mode Pi with no keys never sees. Training on them would
rebuild the exact train/inference gap that killed v1. See the comment block in
`backend/detector/feature_spec.py`.
