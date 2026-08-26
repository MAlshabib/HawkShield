# HawkShield v2 — model pipeline

How a Wi-Fi frame becomes a labelled attack, from antenna to dashboard, and how the
same code path is used to train the model. Diagrams render natively on GitHub.

---

## 1. The whole system

```mermaid
flowchart LR
    subgraph TRAIN["TRAINING  (laptop / GPU, offline)"]
        A1["AWID3 archive<br/>14.7 GB zip · 46 GB CSV<br/>37M frames · 254 tshark columns"]
        A2["prepare_awid3.py<br/>streams the zip, 6 workers"]
        A3[("Parquet shards<br/>46 features + label<br/>+ block_id · ~300 MB")]
        A4["train.py<br/>grouped split by block"]
        A5["ONNX export<br/>+ int8 variant"]
        A1 --> A2 --> A3 --> A4 --> A5
    end

    subgraph SPEC["THE CONTRACT"]
        S1{{"feature_spec.py<br/><b>derive_frame_features()</b><br/>46 features · 9 classes"}}
    end

    subgraph LIVE["INFERENCE  (Raspberry Pi 4, real time)"]
        B1["USB adapter<br/>monitor mode, no keys"]
        B2["scapy sniff<br/>802.11 + radiotap"]
        B3["scapy_to_raw()<br/>tshark-named dict"]
        B4["causal TCN<br/>ONNX fp32"]
        B5[("PostgreSQL<br/>packets table")]
        B6["FastAPI + dashboard<br/>one process, :8000"]
        B1 --> B2 --> B3 --> B4 --> B5 --> B6
    end

    A2 -. "calls" .-> S1
    B3 -. "calls" .-> S1

    style S1 fill:#1f6feb,stroke:#58a6ff,color:#fff
    style A5 fill:#238636,stroke:#3fb950,color:#fff
    style B4 fill:#238636,stroke:#3fb950,color:#fff
```

**The single most important property of this design**: training and inference call the
*same function* to turn a frame into features. In v1 they were two separate
implementations, 16 of 29 features were silently NULL in the field, and the model
keyed on the mean-imputed constants that replaced them. That failure is now
structurally impossible — if a feature cannot be produced live, it is not in the spec.

---

## 2. Feature derivation — one frame in, 46 numbers out

```mermaid
flowchart TD
    F["802.11 frame + radiotap header"]

    F --> R["radiotap<br/>freq · rate · RSSI · flags"]
    F --> H["MAC header<br/>frame control · duration · seq · addresses"]
    F --> M["management body<br/><i>unencrypted</i>"]
    F --> E["EAPOL body<br/><i>unencrypted</i>"]
    F --> X["data payload<br/><b>encrypted — unusable</b>"]

    R --> R1["7 radio values<br/>+ 3 presence flags"]
    H --> H1["11 frame-control<br/>+ seq delta"]
    H --> H2["6 address semantics<br/><i>derived, never raw MACs</i>"]
    M --> M1["reason code · beacon interval<br/>capabilities · SSID length · tags"]
    M --> M2["RSN: MFPC · PMKID · country"]
    E --> E1["type · len · msgnr<br/>key len · replay counter"]

    R1 & H1 & H2 & M1 & M2 & E1 --> V["46-feature vector<br/>absent field ⇒ NaN, never invented"]
    X -.->|excluded by design| V

    style X fill:#6e1423,stroke:#f85149,color:#fff
    style V fill:#1f6feb,stroke:#58a6ff,color:#fff
    style M1 fill:#9e6a03,stroke:#d29922,color:#fff
    style E1 fill:#9e6a03,stroke:#d29922,color:#fff
```

The two amber boxes are what v1 never looked at, and they carry most of the signal:

| feature | Deauth | Disas | Kr00k | RogueAP | Normal |
|---|---:|---:|---:|---:|---:|
| `mgmt.has_reason` | **100%** | **100%** | **100%** | 0% | 0.3% |
| `addr.da_broadcast` | 0% | 0% | 0% | **100%** | 1.0% |
| mean `frame.len` | 86 | 86 | 86 | 263 | 454 |

Measured on AWID3, 2.4M frames. Reason code 7 ("class-3 frame from a nonassociated
station") accounts for 6,977 of 8,125 Deauth frames and all 19,061 Kr00k frames.

**Deliberately excluded**, with reasons enforced in code by
`feature_spec.EXCLUDED_COLUMNS`: `frame.time_relative` and friends (session identity —
this single feature was 42% of v1's stage-1 decision), raw TSF counters (device
identity), raw MAC addresses and SSID strings (memorising the testbed), and everything
above the MAC layer (needs decryption keys the Pi does not have).

---

## 3. The model — causal temporal CNN

A single deauthentication frame is legitimate; sixty per second is an attack. The class
lives in the *rate and pattern*, not the individual frame, so the model needs temporal
context — but on a live sensor it may only look **backwards**.

```mermaid
flowchart LR
    I["window<br/>(46 × 128 frames)"] --> N["normalise + missing-mask"]
    N --> C1["causal conv<br/>d=1"] --> C2["causal conv<br/>d=2"] --> C3["causal conv<br/>d=4"]
    C3 --> C4["causal conv<br/>d=8"] --> C5["causal conv<br/>d=16"] --> C6["causal conv<br/>d=32"]
    C6 --> O["1×1 conv → 9 classes<br/><b>per frame</b>"]

    style O fill:#238636,stroke:#3fb950,color:#fff
```

- **Causal + dilated**: receptive field ≈127 past frames from 6 layers, no future leakage.
  A unit test perturbs frame *t+1* and asserts the output at *t* is unchanged.
- **Per-frame output**: every frame gets its own label, which is what the `packets`
  table stores and what the dashboard shows — no window-level smearing.
- **80,471 parameters**, 348 KB as fp32 ONNX. Small enough that the Pi's four
  Cortex-A72 cores are not the bottleneck; a 128-frame window is one inference call.
- **NaN is information**, not something to average away: absent fields are flagged to
  the network through a mask channel rather than silently mean-imputed.
- **fp32 ships, not int8.** An int8 variant is exported and is 2.6x smaller (134 KB),
  but measured *4x slower* on this hardware: onnxruntime has no fast int8 kernel for
  Conv1d at these shapes. Quantise only if flash-constrained, and re-measure first.

A LightGBM model on causal rolling aggregates is trained on the identical split as a
baseline. If the tree model wins on macro-F1, it ships — a 90 KB model that is right
beats a neural one that is fashionable.

---

## 4. Why the evaluation split looks the way it does

```mermaid
flowchart TD
    C["one attack capture<br/>e.g. Deauth: 1.6M frames"]
    C --> B0["block 0<br/>50k frames"]
    C --> B1["block 1"]
    C --> B2["block 2"]
    C --> BN["... block N"]

    B0 --> TR["TRAIN"]
    B2 --> TR
    BN --> TR
    B1 --> TE["TEST<br/><i>whole blocks held out</i>"]

    style TE fill:#9e6a03,stroke:#d29922,color:#fff
```

`frame.number` runs continuously across AWID3's `Deauth_0.csv → Deauth_1.csv → …`, so
each attack folder is **one capture**, recorded once. Leave-one-capture-out is therefore
impossible: holding out the capture removes the entire class.

The protocol is **grouped by block** — one block is 50,000 contiguous frames, and whole
blocks are held out. That stops the leak that actually matters (frame *i* in train,
near-identical frame *i+1* in test), which is how v1 reported ~99% accuracy while being
useless on real traffic.

This is weaker than leave-one-capture-out, and the numbers should be read with that in
mind: they say "generalises across time within this testbed", not "generalises to your
office". Honest reporting of that limit is part of the deliverable.

---

## 5. Live path on the Pi

```mermaid
sequenceDiagram
    participant A as adapter (monitor)
    participant D as detector service
    participant M as ONNX fp32
    participant P as PostgreSQL
    participant U as dashboard

    A->>D: frame
    D->>D: scapy_to_raw + derive_frame_features
    D->>D: append to 128-frame ring buffer
    D->>M: window (46 × 128)
    M-->>D: 9 class scores per frame
    D->>D: threshold; drop Normal
    D->>P: batched insert (attacks only)
    U->>P: /attacks, /attacks/analysis, ...
```

Only attacks are persisted — normal traffic is classified and dropped, which is what
keeps the database small enough for a Pi to serve the dashboard from the same box.

---

*Diagrams describe `backend/detector/feature_spec.py`, `ml/prepare_awid3.py`,
`ml/model.py` and `ml/train.py`. Measured figures come from the AWID3 preprocessing
run; model results live in `ml/reports/`.*
