#!/usr/bin/env python3
"""
AWID3 -> HawkShield v2 training data.

Streams the AWID3 CSV archive, runs every frame through the *same*
``derive_frame_features()`` the live detector uses, and writes compact Parquet
shards. Nothing is fully extracted: the 46 GB of CSV is read straight out of the
zip, one file at a time, across all cores.

    python ml/prepare_awid3.py --limit-files-per-class 2      # smoke run
    python ml/prepare_awid3.py                                # full run

Grouping (this is the important part)
-------------------------------------
``frame.number`` is continuous across the ``<Attack>_0.csv, _1.csv, ...`` chunks,
so each attack folder is ONE capture split into sequential 50k-frame pieces.
That makes leave-one-capture-out impossible for the attack classes -- each attack
was recorded exactly once, so holding out its capture removes the class entirely.

Instead each source file becomes one ``block_id``: 50,000 contiguous frames.
Whole blocks are held out at validation time, which is what stops the real leak
(frame *i* in train, near-identical frame *i+1* in test). Windows must never span
a block boundary. See ml/README.md for why this is weaker than leave-one-capture-out
and what that means when reading the numbers.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
import zipfile
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detector.feature_spec import (  # noqa: E402
    AWID3_SOURCE_COLUMNS,
    normalise_label,
    CLASSES,
    FEATURE_ORDER,
    SPEC_VERSION,
    FrameState,
    derive_frame_features,
)

DEFAULT_ZIP = Path("D:/AWID3.zip")
DEFAULT_OUT = REPO_ROOT / "_work" / "awid3_v2"

# App-layer attacks: separable only through decrypted TCP/TLS payload, which a
# monitor-mode Pi never sees. Including them would rebuild the v1 train/inference
# gap. Documented non-goal.
SKIP_FOLDERS = {"7.SSH", "8.Botnet", "9.Malware", "10.SQL_Injection", "13.Website_spoofing"}

CLASS_TO_IDX = {c: i for i, c in enumerate(CLASSES)}
csv.field_size_limit(1 << 24)  # tcp.payload cells are large


def list_targets(zip_path: Path, limit_per_class: Optional[int]) -> List[str]:
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".csv")]
    by_folder: Dict[str, List[str]] = {}
    for n in names:
        parts = n.split("/")
        if len(parts) < 3:
            continue
        folder = parts[1]
        if folder in SKIP_FOLDERS:
            continue
        by_folder.setdefault(folder, []).append(n)

    out: List[str] = []
    for folder in sorted(by_folder, key=lambda f: int(f.split(".")[0])):
        files = sorted(by_folder[folder], key=_file_index)
        if limit_per_class and limit_per_class < len(files):
            # Spread the sample across the capture. Chunk _0 is always the
            # pre-attack period, so taking the FIRST n files yields 100% Normal
            # and a smoke test that proves nothing.
            step = len(files) / limit_per_class
            picks = sorted({int(i * step) for i in range(limit_per_class)})
            files = [files[i] for i in picks]
        out.extend(files)
    return out


def _file_index(name: str) -> int:
    """`Deauth_12.csv` -> 12. Sorting by this keeps capture order intact."""
    stem = name.split("/")[-1].rsplit(".", 1)[0]
    try:
        return int(stem.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def shard_path(out_dir: Path, member: str) -> Path:
    folder, fname = member.split("/")[1], member.split("/")[-1]
    return out_dir / folder / (fname.rsplit(".", 1)[0] + ".parquet")


# One ZipFile handle per worker process. Re-opening a 14.7 GB archive for every
# one of 400+ members re-reads the central directory each time and, on a machine
# under memory pressure, is enough to raise MemoryError.
_ZIP_CACHE: Dict[str, zipfile.ZipFile] = {}


def _get_zip(zip_path: str) -> zipfile.ZipFile:
    z = _ZIP_CACHE.get(zip_path)
    if z is None:
        z = zipfile.ZipFile(zip_path)
        _ZIP_CACHE[zip_path] = z
    return z


def process_file(args: Tuple[str, str, str]) -> Dict[str, Any]:
    """Convert one AWID3 CSV member into one Parquet shard. Runs in a worker."""
    zip_path, member, out_dir_s = args
    out_path = shard_path(Path(out_dir_s), member)
    if out_path.exists():
        return {"member": member, "skipped": True, "rows": 0, "malformed": 0}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    folder = member.split("/")[1]
    session_id = folder.split(".", 1)[1]          # "1.Deauth" -> "Deauth"
    block_id = f"{session_id}:{_file_index(member):04d}"

    malformed = 0
    unknown_labels: Dict[str, int] = {}
    state = FrameState()                          # per-file: chunks are contiguous

    t0 = time.time()
    with _get_zip(zip_path).open(member) as fh:
        reader = csv.reader(io.TextIOWrapper(fh, encoding="ISO-8859-1", newline=""))
        try:
            header = next(reader)
        except StopIteration:
            return {"member": member, "rows": 0, "malformed": 0, "error": "empty file"}

        # Column order is verified per file rather than assumed.
        idx = {name: i for i, name in enumerate(header)}
        if "Label" not in idx:
            return {"member": member, "rows": 0, "malformed": 0, "error": "no Label column"}
        label_i = idx["Label"]
        fnum_i = idx.get("frame.number")
        ncols = len(header)

        # Format guard. AWID3 was exported with an older tshark that writes 1/0
        # for booleans and plain text for wlan.ssid. tshark 4.x writes
        # True/False and hex-encodes the SSID. If anyone regenerates or augments
        # this data with a modern tshark, every boolean feature silently becomes
        # 0 and mgmt.ssid_len doubles -- a corruption that trains cleanly and
        # fails in the field. Fail loudly instead.
        _bool_cols = [c for c in ("wlan.fc.retry", "wlan.fc.protected",
                                  "radiotap.channel.flags.cck") if c in idx]

        def _check_format(row: List[str]) -> Optional[str]:
            for col in _bool_cols:
                val = row[idx[col]].strip()
                if val[:4].lower() in ("true", "fals"):
                    return (f"{col}={val!r}: booleans are True/False, not 1/0. "
                            "This CSV came from tshark 4.x; re-export with "
                            "-E aggregator=, and legacy boolean formatting, or "
                            "the whole feature set silently reads as zero.")
            return None

        checked = False

        # Only the columns the spec actually consumes. Building a dict of all 254
        # per row costs ~5x the memory and is the difference between running and
        # MemoryError on a loaded machine.
        needed = [(name, idx[name]) for name in AWID3_SOURCE_COLUMNS if name in idx]

        n_feat = len(FEATURE_ORDER)
        # Stream in small row groups. Peak memory is one CHUNK, not one file,
        # so this runs on a machine with almost no commit headroom left.
        CHUNK = 4096
        buf = np.empty((CHUNK, n_feat), dtype=np.float32)
        writer: Optional[pq.ParquetWriter] = None
        schema = pa.schema(
            [(name, pa.float32()) for name in FEATURE_ORDER]
            + [("label", pa.int8()), ("frame_number", pa.int64()),
               ("session_id", pa.string()), ("block_id", pa.string())]
        )
        n = 0          # rows in buf
        total = 0      # rows written
        counts = np.zeros(len(CLASSES), dtype=np.int64)
        chunk_labels: List[int] = []
        chunk_fnums: List[int] = []

        def flush() -> None:
            nonlocal writer, n, total
            if n == 0:
                return
            table = pa.table(
                {name: pa.array(buf[:n, i], type=pa.float32())
                 for i, name in enumerate(FEATURE_ORDER)}
                | {
                    "label": pa.array(np.asarray(chunk_labels, dtype=np.int8), type=pa.int8()),
                    "frame_number": pa.array(np.asarray(chunk_fnums, dtype=np.int64), type=pa.int64()),
                    "session_id": pa.array([session_id] * n, type=pa.string()),
                    "block_id": pa.array([block_id] * n, type=pa.string()),
                },
                schema=schema,
            )
            if writer is None:
                writer = pq.ParquetWriter(out_path, schema, compression="zstd")
            writer.write_table(table)
            total += n
            n = 0
            chunk_labels.clear()
            chunk_fnums.clear()

        for row in reader:
            if len(row) != ncols:
                malformed += 1
                continue
            if not checked:
                problem = _check_format(row)
                checked = True
                if problem:
                    return {"member": member, "rows": 0, "malformed": malformed,
                            "error": f"format mismatch -- {problem}"}
            raw_label = row[label_i].strip()
            cls = normalise_label(raw_label)
            if cls is None:
                unknown_labels[raw_label] = unknown_labels.get(raw_label, 0) + 1
                continue

            raw = {name: row[i] for name, i in needed}
            d = derive_frame_features(raw, state)
            buf[n] = [d[k] for k in FEATURE_ORDER]
            li = CLASS_TO_IDX[cls]
            chunk_labels.append(li)
            counts[li] += 1
            if fnum_i is not None:
                try:
                    chunk_fnums.append(int(float(row[fnum_i])))
                except ValueError:
                    chunk_fnums.append(total + n)
            else:
                chunk_fnums.append(total + n)
            n += 1
            if n == CHUNK:
                flush()

        flush()
        if writer is not None:
            writer.close()

    if total == 0:
        return {"member": member, "rows": 0, "malformed": malformed, "error": "no usable rows"}

    return {
        "member": member,
        "rows": total,
        "malformed": malformed,
        "unknown_labels": unknown_labels,
        "counts": counts.tolist(),
        "seconds": round(time.time() - t0, 1),
        "bytes": out_path.stat().st_size,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert AWID3 CSVs to HawkShield v2 Parquet.")
    ap.add_argument("--zip", type=Path, default=DEFAULT_ZIP)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--limit-files-per-class", type=int, default=None,
                    help="only the first N chunks of each capture (smoke runs)")
    ap.add_argument("--workers", type=int, default=4,
                    help="parallel readers (default 6; each holds one zip handle)")
    ap.add_argument("--overwrite", action="store_true", help="ignore existing shards")
    args = ap.parse_args()

    if not args.zip.exists():
        print(f"[FAIL] archive not found: {args.zip}", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    members = list_targets(args.zip, args.limit_files_per_class)
    if args.overwrite:
        for m in members:
            p = shard_path(args.out, m)
            if p.exists():
                p.unlink()

    print(f"HawkShield AWID3 preprocessing | spec {SPEC_VERSION}")
    print(f"  archive : {args.zip}")
    print(f"  output  : {args.out}")
    print(f"  files   : {len(members)} (skipping {sorted(SKIP_FOLDERS)})")
    print(f"  workers : {args.workers}\n", flush=True)

    totals = np.zeros(len(CLASSES), dtype=np.int64)
    rows = malformed = done = nbytes = 0
    unknown: Dict[str, int] = {}
    errors: List[str] = []
    t0 = time.time()

    payload = [(str(args.zip), m, str(args.out)) for m in members]
    with Pool(processes=args.workers) as pool:
        for res in pool.imap_unordered(process_file, payload, chunksize=1):
            done += 1
            if res.get("error"):
                errors.append(f"{res['member']}: {res['error']}")
            if res.get("skipped"):
                print(f"  [{done}/{len(members)}] skip (exists) {res['member'].split('/')[-1]}", flush=True)
                continue
            rows += res["rows"]
            malformed += res["malformed"]
            nbytes += res.get("bytes", 0)
            for k, v in (res.get("unknown_labels") or {}).items():
                unknown[k] = unknown.get(k, 0) + v
            if res.get("counts"):
                totals += np.asarray(res["counts"], dtype=np.int64)
            elapsed = time.time() - t0
            eta = (elapsed / done) * (len(members) - done)
            print(f"  [{done}/{len(members)}] {res['member'].split('/')[-1]:28} "
                  f"rows={res['rows']:>6} bad={res['malformed']:>3} "
                  f"{res.get('seconds', 0):>5.1f}s  ETA {eta/60:.1f}m", flush=True)

    elapsed = time.time() - t0
    print(f"\n-- summary {'-' * 58}")
    print(f"  rows written    : {rows:,}")
    print(f"  malformed rows  : {malformed:,} (skipped)")
    print(f"  output size     : {nbytes / 1e6:.1f} MB")
    print(f"  wall clock      : {elapsed / 60:.1f} min")
    if unknown:
        print(f"  unmapped labels : {unknown}")
    if errors:
        print(f"  errors ({len(errors)}):")
        for e in errors[:10]:
            print(f"    {e}")
    print("\n  class distribution:")
    for i, c in enumerate(CLASSES):
        pct = (totals[i] / rows * 100) if rows else 0
        print(f"    {c:12} {totals[i]:>12,}  {pct:6.3f}%")

    meta = {
        "spec_version": SPEC_VERSION,
        "classes": CLASSES,
        "features": FEATURE_ORDER,
        "rows": int(rows),
        "malformed": int(malformed),
        "class_counts": {c: int(totals[i]) for i, c in enumerate(CLASSES)},
        "files": len(members),
        "seconds": round(elapsed, 1),
        "grouping": "block_id = one 50k-frame source file; hold out whole blocks",
    }
    (args.out / "_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\n  wrote {args.out / '_meta.json'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
