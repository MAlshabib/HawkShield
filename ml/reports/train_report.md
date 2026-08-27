# HawkShield v2 -- training report

- spec version: `2.1.0` | features: 46 | classes: 9
- data: `D:\HawkShield\_work\awid3_v2` -- 23,716,279 rows in 478 blocks
- device: `cuda` | seed: 1337 | generated 2026-08-27 08:23
- command: `python ml/train.py --data D:\HawkShield\_work\awid3_v2 --out D:\HawkShield\_work\models_v2 --model both --epochs 12 --batch-size 256 --window 128 --device auto --seed 1337`

## Split protocol

Whole **`block_id`** groups are assigned to train/val/test; a block is one contiguous 50,000-frame AWID3 source file and no row of a block ever appears in two splits. Windows never cross a block boundary.

This is **weaker than leave-one-capture-out**, and deliberately so: AWID3 records each attack exactly once, `frame.number` runs continuously across an attack's chunk files, so holding out a capture deletes the class outright. Held-out blocks are therefore from the same session, same testbed, same hardware as the training blocks -- what these numbers measure is generalisation across time within one recording, not across deployments. Read them as an upper bound on field performance.

### Rows per class per split

| class | blocks | train | val | test |
|---|---:|---:|---:|---:|
| Normal | 478 | 10,657,793 | 2,641,353 | 4,449,777 |
| Deauth | 12 | 23,444 | 5,647 | 9,851 |
| Disas | 13 | 44,934 | 11,377 | 18,820 |
| (Re)Assoc | 15 | 3,292 | 809 | 1,401 |
| RogueAP | 17 | 777 | 202 | 331 |
| Krack | 4 | 21,669 | 12,312 | 16,009 |
| Kr00k | 27 | 115,508 | 28,963 | 47,332 |
| Evil_Twin | 48 | 62,878 | 15,731 | 26,218 |
| SSDP | 137 | 3,298,771 | 826,911 | 1,374,169 |
| **blocks** | 478 | 287 | 72 | 119 |

## Models

### TCN

- parameters: **80,527**, receptive field **127** past frames, window 128, stride 64
- NaN handling: learned per-feature sentinel + 11 companion mask channels (11 of 46 features are NaN-capable in train)
- causality probe: max output delta at t from perturbing t+1.. = `0.000e+00` (must be 0.0); future-side delta `1.627e+00` (proves the probe bites)
- best val macro-F1: **0.9711** (epoch 10)

| epoch | loss | train macro-F1 | val macro-F1 | sec |
|---:|---:|---:|---:|---:|
| 1 | 0.2921 | 0.5458 | 0.7377 | 11.6 |
| 2 | 0.0613 | 0.8786 | 0.8380 | 10.1 |
| 3 | 0.0495 | 0.9265 | 0.9559 | 11.2 |
| 4 | 0.0387 | 0.9456 | 0.9586 | 10.4 |
| 5 | 0.0275 | 0.9622 | 0.9205 | 10.7 |
| 6 | 0.0246 | 0.9679 | 0.9529 | 10.6 |
| 7 | 0.0216 | 0.9801 | 0.9610 | 10.5 |
| 8 | 0.0199 | 0.9734 | 0.9648 | 10.5 |
| 9 | 0.0177 | 0.9880 | 0.9671 | 10.4 |
| 10 | 0.0164 | 0.9903 | 0.9711 | 10.4 |
| 11 | 0.0153 | 0.9919 | 0.9703 | 10.2 |
| 12 | 0.0148 | 0.9937 | 0.9695 | 10.4 |

### LightGBM baseline

- features: 46 per-frame + 36 causal rolling aggregates (windows [16, 64]) = 82
- trees: 49 x 9 classes, 63 leaves
- val macro-F1: **0.9752**

| rank | feature | gain |
|---:|---|---:|
| 1 | `roll64.frame.dt_log.mean` | 11,847,648 |
| 2 | `addr.ta_eq_sa` | 9,218,501 |
| 3 | `mgmt.reason_code` | 6,552,831 |
| 4 | `mgmt.tag_len` | 3,056,212 |
| 5 | `mgmt.has_reason` | 2,547,320 |
| 6 | `roll16.fc.protected.rate` | 2,412,737 |
| 7 | `fc.subtype` | 2,336,176 |
| 8 | `rsn.country_present` | 2,067,500 |
| 9 | `radio.signal_dbm` | 2,062,260 |
| 10 | `frame.len` | 2,006,984 |
| 11 | `roll64.radio.signal_dbm.std` | 1,900,261 |
| 12 | `radio.ofdm` | 1,501,397 |
| 13 | `radio.has_rate` | 1,436,524 |
| 14 | `fc.protected` | 1,396,917 |
| 15 | `radio.freq_mhz` | 1,276,951 |

## Head to head (validation macro-F1)

| model | val macro-F1 |
|---|---:|
| TCN | 0.9711 |
| LightGBM | 0.9752 |

**LightGBM leads on validation by 0.0040 macro-F1.** Test-set numbers and the leakage probe are in `eval_report.md`; decide on those, not on this.


---
Wall clock: 4.2 min
