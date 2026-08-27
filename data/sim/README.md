# `data/sim/` — the simulation corpus

`awid3_sim_corpus.parquet` is the data `POST /simulate` replays. It is a small,
committed slice of **held-out AWID3 feature rows** — the model's own domain — so
that the simulate button demonstrates the detector on data it genuinely
classifies correctly, not on a stub and not on out-of-domain traffic.

## What is in the file

One row per frame, `~300 KB`, `zstd`-compressed:

| column | meaning |
|---|---|
| `cls` | attack class name (`Deauth`, `Kr00k`, …) — the segment this row belongs to |
| `seq` | position within the segment, so capture order is preserved |
| `<46 feature columns>` | `feature_spec.FEATURE_ORDER`, exactly the vector the model scores |
| `label` | integer class id (`feature_spec.CLASSES` index); `0` = `Normal` |
| `block_id` | the held-out AWID3 block the segment came from |

Each class is one **contiguous segment** of a held-out block, benign frames
included. The attack-labelled rows are what self-classify; the interleaved
`Normal` rows legitimately come back `Normal` and are not persisted — which is
also what a real capture looks like.

## Why held-out AWID3, and not the obvious alternatives

Three sources were measured as candidates. Only one tells the truth:

- **Crafted scapy frames** (`backend/detector/attack_sim.build_frames`) score
  `p1 ≈ 0.96` — the model is sure they are *an attack* — but stage-2 confidence
  sits at `~0.36` and mislabels, because the booster's single most important
  feature is `roll64.frame.dt_log.mean` (inter-frame timing) and frames built in
  a loop carry no timing. They are kept for `--self-test` and for
  `tools/inject_attack.py` (a radio supplies the timing), not for a demo.
- **`data/samples/*.pcapng`** are out of domain — the original project's testbed,
  not AWID3. The AWID3-trained model flags them and then labels almost all of
  them Krack: the cross-deployment gap of `models/README.md` §2.7.1.
- **Held-out AWID3 rows** classify at `~99–100%` per class, because they are the
  model's own domain. This file.

## Why the benign frames between attacks are kept

The GBDT reads 36 causal rolling aggregates over the frame stream. Filtering a
block down to only its attack-labelled rows produces a stream that never existed
on any air, and the aggregates then describe *that*. Measured on the seven
held-out Kr00k blocks:

```
label-filtered rows only ....   0.1% –   4.2% correctly persisted as Kr00k
contiguous segment .........  97.0% – 100.0%
```

Same model, same frames, same order — the only difference is whether the benign
frames were kept. So they are kept.

## Per-class correct-persist over the committed corpus

Every class self-classifies at 100% (measured through the real `build_pipeline`,
the same one the detector runs):

```
Deauth      100%      Krack       100%
Disas       100%      Kr00k       100%
(Re)Assoc   100%      Evil_Twin   100%
RogueAP     100%      SSDP        100%
```

**Kr00k** was the one at risk — in earlier label-filtered experiments it confused
to Disas (the documented Disas↔Kr00k adjacency), and excluding it from the
default menu was on the table. With the contiguous-segment corpus it self-
classifies cleanly, so it stays in the default `all` set. If a future spec
regresses it, the honest move is to drop it from the default with a note here —
never to relabel it.

**RogueAP** is the sparsest class in all of AWID3 (1 310 rows total, never more
than 143 in a 50 000-frame block), so its segment is the longest and holds only a
few dozen attack rows; on replay a small number of Disas can appear among its
persisted rows. `POST /simulate` reports that in the per-class `labels`, honestly.

## Rebuilding

```
python data/sim/build_sim_corpus.py            # default window 2000, grows for sparse classes
```

The builder needs the prepared AWID3 parquets and the training split under
`_work/`, which are **build-time inputs and are not committed** (they are large
and derived). It scores candidate segments through the real pipeline and keeps,
per class, the held-out block the model handles most cleanly. See the module
docstring in `build_sim_corpus.py` for the full selection rule. Only the
`~300 KB` parquet is committed.
