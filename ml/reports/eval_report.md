# HawkShield v2 -- evaluation on held-out test blocks

- spec `2.1.0` | models `D:\HawkShield\_work\models_v2` | data `D:\HawkShield\_work\awid3_v2`
- generated 2026-08-27 08:27 | device `cuda`
- held-out blocks: `Deauth:0010`, `Deauth:0011`, `Deauth:0002`, `Deauth:0022`, `Deauth:0025`, `Deauth:0026`, `Deauth:0004`, `SSDP:0000`, `SSDP:0001`, `SSDP:0104`, `SSDP:0106`, `SSDP:0108`, `SSDP:0109`, `SSDP:0113`, `SSDP:0124`, `SSDP:0142`, `SSDP:0015`, `SSDP:0158`, `SSDP:0020`, `SSDP:0022`, `SSDP:0028`, `SSDP:0030`, `SSDP:0036`, `SSDP:0037`, `SSDP:0039`, `SSDP:0041`, `SSDP:0042`, `SSDP:0043`, `SSDP:0044`, `SSDP:0046`, `SSDP:0049`, `SSDP:0050`, `SSDP:0052`, `SSDP:0053`, `SSDP:0054`, `SSDP:0056`, `SSDP:0059`, `SSDP:0060`, `SSDP:0061`, `SSDP:0064`, `SSDP:0067`, `SSDP:0078`, `SSDP:0079`, `SSDP:0090`, `SSDP:0091`, `SSDP:0096`, `Evil_Twin:0010`, `Evil_Twin:0011`, `Evil_Twin:0014`, `Evil_Twin:0015`, `Evil_Twin:0016`, `Evil_Twin:0021`, `Evil_Twin:0027`, `Evil_Twin:0028`, `Evil_Twin:0029`, `Evil_Twin:0035`, `Evil_Twin:0040`, `Evil_Twin:0046`, `Evil_Twin:0047`, `Evil_Twin:0049`, `Evil_Twin:0057`, `Evil_Twin:0060`, `Evil_Twin:0071`, `Disas:0010`, `Disas:0014`, `Disas:0015`, `Disas:0017`, `Disas:0029`, `Disas:0031`, `Disas:0032`, `Disas:0037`, `Disas:0004`, `Disas:0007`, `(Re)Assoc:0010`, `(Re)Assoc:0015`, `(Re)Assoc:0017`, `(Re)Assoc:0002`, `(Re)Assoc:0020`, `(Re)Assoc:0026`, `(Re)Assoc:0029`, `(Re)Assoc:0030`, `(Re)Assoc:0036`, `(Re)Assoc:0004`, `(Re)Assoc:0005`, `(Re)Assoc:0008`, `Rogue_AP:0000`, `Rogue_AP:0012`, `Rogue_AP:0018`, `Rogue_AP:0002`, `Rogue_AP:0021`, `Rogue_AP:0030`, `Rogue_AP:0032`, `Rogue_AP:0035`, `Rogue_AP:0036`, `Rogue_AP:0005`, `Rogue_AP:0008`, `Krack:0001`, `Krack:0010`, `Krack:0014`, `Krack:0015`, `Krack:0017`, `Krack:0027`, `Krack:0007`, `Kr00k:0000`, `Kr00k:0010`, `Kr00k:0011`, `Kr00k:0014`, `Kr00k:0015`, `Kr00k:0024`, `Kr00k:0027`, `Kr00k:0028`, `Kr00k:0035`, `Kr00k:0039`, `Kr00k:0004`, `Kr00k:0044`, `Kr00k:0046`, `Kr00k:0050`, `Kr00k:0052`, `Kr00k:0056`

> **Protocol.** Whole `block_id` groups are held out -- one block is one contiguous 50,000-frame AWID3 source file, and no row of a held-out block was seen in training. This is weaker than leave-one-capture-out: AWID3 recorded each attack exactly once and `frame.number` runs continuously across an attack's chunk files, so removing a capture removes the class. The held-out blocks share the session, testbed and radio hardware of the training blocks, so these numbers bound field performance from above.

## TCN (causal dilated temporal CNN)

- checkpoint `tcn.pt` from epoch 10 (val macro-F1 0.9711)
- causality probe at train time: past-side delta `0.0` (0.0 required), future-side delta `1.6270711421966553`
- **test macro-F1: 0.9856** over 5,943,908 frames

| class | precision | recall | f1 | support |
|---|---:|---:|---:|---:|
| Normal | 0.9997 | 0.9988 | 0.9992 | 4,449,777 |
| Deauth | 0.9924 | 0.9935 | 0.9929 | 9,851 |
| Disas | 0.9592 | 0.9887 | 0.9738 | 18,820 |
| (Re)Assoc | 0.9383 | 0.9979 | 0.9671 | 1,401 |
| RogueAP | 0.9940 | 0.9970 | 0.9955 | 331 |
| Krack | 0.9639 | 0.9650 | 0.9644 | 16,009 |
| Kr00k | 0.9924 | 0.9870 | 0.9897 | 47,332 |
| Evil_Twin | 0.9943 | 0.9844 | 0.9893 | 26,218 |
| SSDP | 0.9968 | 0.9997 | 0.9982 | 1,374,169 |
| **macro-F1 (present classes)** | | | **0.9856** | 5,943,908 |

### Confusion matrix

| true \ pred | Normal | Deauth | Disas | (Re)Assoc | RogueAP | Krack | Kr00k | Evil_Twin | SSDP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Normal** | 4,444,251 | 32 | 168 | 33 | 1 | 579 | 141 | 145 | 4,427 |
| **Deauth** | 2 | 9,787 | 7 | . | . | . | 55 | . | . |
| **Disas** | 10 | 41 | 18,608 | . | . | . | 161 | . | . |
| **(Re)Assoc** | 3 | . | . | 1,398 | . | . | . | . | . |
| **RogueAP** | . | . | . | . | 330 | . | . | 1 | . |
| **Krack** | 559 | . | . | . | . | 15,449 | . | 1 | . |
| **Kr00k** | . | 2 | 615 | . | . | . | 46,715 | . | . |
| **Evil_Twin** | 346 | . | 1 | 59 | 1 | . | 1 | 25,809 | 1 |
| **SSDP** | 468 | . | . | . | . | . | 1 | . | 1,373,700 |

## LightGBM baseline

- 441 trees, model file 3029 KB on disk
- **test macro-F1: 0.9907** over 5,943,908 frames

| class | precision | recall | f1 | support |
|---|---:|---:|---:|---:|
| Normal | 0.9997 | 0.9986 | 0.9992 | 4,449,777 |
| Deauth | 0.9760 | 0.9969 | 0.9863 | 9,851 |
| Disas | 0.9464 | 0.9694 | 0.9578 | 18,820 |
| (Re)Assoc | 0.9971 | 0.9979 | 0.9975 | 1,401 |
| RogueAP | 1.0000 | 1.0000 | 1.0000 | 331 |
| Krack | 0.9999 | 0.9999 | 0.9999 | 16,009 |
| Kr00k | 0.9915 | 0.9836 | 0.9875 | 47,332 |
| Evil_Twin | 0.9930 | 0.9871 | 0.9900 | 26,218 |
| SSDP | 0.9960 | 0.9994 | 0.9977 | 1,374,169 |
| **macro-F1 (present classes)** | | | **0.9907** | 5,943,908 |

### Confusion matrix

| true \ pred | Normal | Deauth | Disas | (Re)Assoc | RogueAP | Krack | Kr00k | Evil_Twin | SSDP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Normal** | 4,443,750 | 8 | 231 | 4 | . | 2 | 45 | 182 | 5,555 |
| **Deauth** | . | 9,820 | 25 | . | . | . | 6 | . | . |
| **Disas** | . | 233 | 18,245 | . | . | . | 342 | . | . |
| **(Re)Assoc** | 3 | . | . | 1,398 | . | . | . | . | . |
| **RogueAP** | . | . | . | . | 331 | . | . | . | . |
| **Krack** | 1 | . | . | . | . | 16,008 | . | . | . |
| **Kr00k** | . | . | 778 | . | . | . | 46,554 | . | . |
| **Evil_Twin** | 335 | . | . | . | . | . | 4 | 25,879 | . |
| **SSDP** | 802 | . | . | . | . | . | . | . | 1,373,367 |

### Top gain features

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

## Head to head (held-out test macro-F1)

| model | test macro-F1 |
|---|---:|
| TCN | 0.9856 |
| LightGBM | 0.9907 |

**LightGBM wins by 0.0051.** A tree ensemble beating the network is a legitimate result, not a bug to tune away -- it is smaller, faster and easier to reason about on a Pi.

## Leakage probe -- ablate the top-importance feature

v1 scored ~99% under a random shuffle and was worthless in the field. The test that exposed it: delete its single most important feature and re-measure. `frame.time_relative` carried 42% of stage-1 split gain while encoding nothing but *which capture the row came from* -- removing it collapsed the model. A healthy detector degrades gracefully; a leaky one falls off a cliff or, worse, does not move at all because ten other columns encode the same artefact.

| ablated feature | model | macro-F1 | delta |
|---|---|---:|---:|
| `roll64.frame.dt_log.mean` | LightGBM (score-only) | 0.9876 | -0.0030 |
| `roll64.frame.dt_log.mean` | LightGBM (**retrained** without it) | 0.9899 | -0.0007 |
| `addr.ta_eq_sa` | TCN (score-only) | 0.8912 | -0.0944 |

_The GBDT's top feature is `roll64.frame.dt_log.mean`, a causal rolling aggregate the TCN does not take as input -- the network builds its own temporal context through dilated convolutions. The TCN row therefore ablates `addr.ta_eq_sa`, the highest-gain feature that is actually in the 47-feature contract._


_Score-only ablation sets the feature to **NaN**, not zero: NaN is a state the feature contract defines and the model has a mask channel for, whereas zeroing post-normalises to the training mean -- the exact silent imputation that broke v1. The retrained row is the stronger evidence; the score-only rows show how brittle the *deployed* weights are to that field going missing on a real capture._
