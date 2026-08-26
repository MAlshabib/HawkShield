# HawkShield model card — two-stage 802.11 attack detector

Two LightGBM `Booster` models in joblib bundles. Stage 1 decides *attack or not*;
stage 2 names the attack. Both share one 31-column feature space, so a single
extractor (`backend/detector/features.py`) feeds both.

Verify what is on disk at any time:

```
python -m backend.scripts.verify_models
```

---

## 1. Provenance

| Stage | File | Original name | md5 | size |
|---|---|---|---|---|
| 1 | `stage1_binary_bundle.joblib` | `binary_classifier_final.joblib` | `d67bfee99f1188513eb46f9c3a83f1cb` | 1 643 071 B |
| 2 | `stage2_multiclass_bundle.joblib` | `multiclass_lightgbm_bundle.joblib` | `4ef700bd22eed51dea526e03f77befe0` | 436 996 B |

sha256 (logged by the detector on every start):

```
stage1  9c0437bdc2523d4964b664704edcb8017dd5585de2c339443f9b28be197012f9
stage2  f04ec48418bfce2b539053c694ca73caea0788a1668e7942d706ad26afbe74cd
```

Training notebooks (outputs stripped, source intact):

* `notebooks/EDA.ipynb` — exploration of the merged tshark export.
* `notebooks/binary_classifier.ipynb` — stage 1.
* `notebooks/multiclass_classifier.ipynb` — stage 2.

Source data was a merged tshark CSV export (`merged_shuffled_20250822_185836.csv`,
not in this repo — see `_archive/source/.../Data/data_link.md`). Columns were kept
only if they started with `frame.`, `radiotap.`, `wlan.` or `wlan_radio.`, with all
identity fields (BSSID/SSID/MAC/addr), payload fields and upper-layer protocols
blocked. Numeric columns were median-imputed then z-scored; the two categorical
columns were kept as pandas categoricals and handed to LightGBM's native
categorical support.

---

## 2. Bundle structure

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

The imputer key differs between the two bundles (`imputer` vs `num_imputer`) — the
loader accepts either.

**The imputer and the scaler were fit on the 29 numeric columns only, while the
Booster expects 31.** The transform order is therefore:

```
DataFrame(imputer.feature_names_in_)          # 29 named columns, NaN where absent
  -> imputer.transform                        # median fill
  -> scaler.transform                         # keep it a DataFrame or StandardScaler
                                              #   warns about missing feature names
  -> reindex onto feature_order               # 31 columns, the 2 cat_cols filled 0.0
  -> Booster.predict(X.values, num_iteration=best_iteration)
```

## 3. Feature order (31)

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

## 4. Classes and thresholds

`id_to_class = {0: SSDP, 1: Evil_Twin, 2: Krack, 3: Deauth, 4: (Re)Assoc, 5: RogueAP}`

Decision rule (`STAGE1_THRESHOLD` / `STAGE2_THRESHOLD`, defaults 0.40 / 0.80):

```
p1 = P(attack)                     ; p1 < 0.40  -> drop, nothing persisted
label, p2 = stage2(row)            ; p2 < 0.80  -> drop, nothing persisted
otherwise                                       -> INSERT into packets
```

Stage-1's own `best_threshold` (0.4) matches the default, so the env default and
the bundle agree.

Training-set class weights show how skewed the source data was:
`SSDP 0.29, Evil_Twin 0.52, Krack 2.18, Deauth 11.49, (Re)Assoc 29.89, RogueAP 99.94`.

---

## 5. Known limitations

### 5.1 Live scapy extraction still cannot supply every tshark field

The models were trained on tshark output. The detector runs scapy. Two of the 31
columns have no scapy equivalent and are always absent at inference time:

| Feature | Why | Effect |
|---|---|---|
| `wlan.country_info.fnm` | tshark's parsed country-IE first-channel-number, exported as a category | filled with `0.0` when reindexing into the model space |
| `wlan.country_info.code` | tshark's parsed country string, exported as a category | filled with `0.0` |

`wlan.country_info.fnm` carries **15.5 % of stage-2's total split gain**, so stage 2
is permanently evaluating a constant where it was trained on a varying signal.

Everything else *is* now supplied. `backend/detector/features.py` populates all 29
numeric columns from the RadioTap and Dot11 headers; the original `scapy_to_row()`
left 13 of them permanently `None` and hardcoded `wlan.fc.ds = 0`.

Two extraction details worth recording, both inferred from the bundles' own
`SimpleImputer.statistics_` / `StandardScaler.mean_`:

* `radiotap.dbm_antsignal` is the **sum over antenna chains** (training median
  −129 dBm = 3 × the −43 dBm median of `wlan_radio.signal_dbm`; the sample captures
  carry exactly three `dBm_AntSignal` fields per frame, in three radiotap
  namespaces). Scapy decodes only the first, so `features.all_dbm_antsignal()`
  walks the raw presence masks. `wlan_radio.signal_dbm` keeps the strongest chain,
  and that is the value written to the `packets.signal_dbm` column.
* `frame.encap_type` is constant `23` in the training data (`StandardScaler` records
  variance 0.0 for it), which is tshark's encapsulation id for 802.11-plus-radiotap.

### 5.2 `frame.time_relative` and `radiotap.channel.freq` are leaked features

This is the significant one.

`frame.time_relative` — seconds since the first packet of the capture — is
**41.9 % of stage-1's split gain and 16.7 % of stage-2's**. In the training data it
has median 582.7 s and standard deviation 50.4 s, i.e. a ~±100 s band. It is a
property of *which capture session a row came from*, not of the traffic. Likewise
`radiotap.channel.freq` (8.9 % / 18.1 % of gain) has training median 5180 MHz: the
training captures were predominantly 5 GHz, while the Pi's monitor interface is
pinned to a 2.4 GHz channel by default.

The consequence is measurable. Leave-one-out ablation over the full 20 000-frame
`deauth_raw_decrypted.pcapng` (of which 97 % *are* deauthentication frames):

| Row fed to stage 1 | frames flagged attack |
|---|---|
| every feature populated (current behaviour) | 82 (0.41 %) |
| same, but `frame.time_relative` forced null -> imputed to 582.7 s | 20 000 (100 %) |
| same, but `radiotap.channel.freq` forced null -> imputed to 5180 MHz | 0 (0 %) |
| all 16 newly-populated features forced null (original behaviour) | 19 976 (99.9 %) |

Reproduce any row of that table with:

```
python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng \
    --null-feature frame.time_relative
```

Read that carefully: the original detector "detected" this deauth flood only
because `frame.time_relative` was `None` and got imputed to the training median,
which happens to sit in the region the model associates with attack traffic. It
was right for the wrong reason, and the same accident classified the flood as
`SSDP`. Filling the feature honestly removes the accident and exposes that the
model does not generalise off its training sessions.

The same effect shows up across the whole sample set. Full 20 000-frame replay of
each capture in `data/samples/`, every feature populated, thresholds 0.40 / 0.80:

| capture | capture span | stage-1 flagged | persisted | stage-2 label |
|---|---:|---:|---:|---|
| `assoc_flood` | 23 156 s | 97.6 % | 16 150 | Krack (100 %) |
| `auth_flood`  |  3 261 s | 91.6 % | 10 788 | Krack (100 %) |
| `beacon`      |  2 830 s | 96.3 % | 12 841 | Krack (100 %) |
| `deauth`      |     79 s |  0.4 % |      0 | Krack (100 %) |
| `disassoc`    |  2 328 s | 94.7 % |  3 806 | Krack (100 %) |
| `probe`       |  2 105 s | 94.9 % |  3 313 | Krack (100 %) |

The one capture that is 79 seconds long is the one stage 1 stays silent on, and it
is the one that is 97 % deauthentication frames. Stage 2 answers `Krack` for every
frame of every capture (mean probability 0.58–0.87 for `Krack`, ~0.000 for both
`Deauth` and `(Re)Assoc`), so the multiclass stage carries no usable signal on
2.4 GHz traffic.

There is a second, operational consequence: `frame.time_relative` is measured from
detector start, so a service that stays up for a day feeds the model values around
86 400 while it was trained on ~583. The feature drifts monotonically out of the
training range for as long as the process runs, and restarting the detector resets
it. Nothing in the feature itself is wrong — it is exactly what tshark reports —
the problem is that the model should never have been allowed to depend on it.

**Recommendation: retrain without `frame.time_relative`,
`frame.time_delta*` and `radiotap.channel.freq` / `wlan_radio.frequency` /
`wlan_radio.channel`, and with capture sessions held out of the train/test split
rather than shuffled across it** (the notebook shuffles rows, so frames from a
single capture appear on both sides of the split). Until then, treat live labels
as indicative, not authoritative, whenever the deployment band (2.4 GHz) or run
length differs from the training captures.

### 5.3 Other

* Stage 2 has no "not one of my six classes" option; anything that clears stage 1
  is forced into one of the six labels, and the `STAGE2_THRESHOLD` of 0.80 is the
  only guard against that.
* The `packets` table stores only frames that clear both thresholds; normal traffic
  is classified and dropped, so the table cannot be used to estimate a false-positive
  rate after the fact.
