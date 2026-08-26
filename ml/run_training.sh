#!/usr/bin/env bash
# HawkShield v2 -- one command: deps -> data -> train -> evaluate -> export.
#
#   ./ml/run_training.sh
#   ./ml/run_training.sh --fresh              # re-run AWID3 preprocessing first
#   ./ml/run_training.sh --model gbdt --epochs 4
#   ./ml/run_training.sh --max-rows 2000000   # quick pass on a subset of blocks
#
# GPU: PyTorch is NOT installed by default and the CPU wheel will not touch the
# RTX 4070 SUPER. Install the CUDA build once:
#
#     .venv/Scripts/python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu126
#
# Without it this script falls back to CPU and says so. It never installs a
# multi-gigabyte wheel behind your back.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$ROOT/.venv/bin/python"
DATA="$ROOT/_work/awid3_v2"
OUT="$ROOT/_work/models_v2"

FRESH=0; MODEL="both"; EPOCHS=12; BATCH=256; WINDOW=128; DEVICE="auto"
MAX_ROWS=0; SEED=1337; ZIP="D:/AWID3.zip"; SKIP_EXPORT=0
STAGE=0

die() { printf '\n\033[31m[FAIL] %s\033[0m\n' "$*" >&2; exit 1; }
stage() { STAGE=$((STAGE + 1)); printf '\n\033[36m%s\n  STAGE %d  %s\n%s\033[0m\n' \
          "$(printf '=%.0s' {1..72})" "$STAGE" "$1" "$(printf '=%.0s' {1..72})"; }
run() { printf '\033[90m  > %s %s\033[0m\n' "$PY" "$*"; "$PY" "$@" \
        || die "stage $STAGE failed with exit code $?"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --fresh) FRESH=1; shift ;;
    --model) MODEL="$2"; shift 2 ;;
    --epochs) EPOCHS="$2"; shift 2 ;;
    --batch-size) BATCH="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --device) DEVICE="$2"; shift 2 ;;
    --max-rows) MAX_ROWS="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --zip) ZIP="$2"; shift 2 ;;
    --skip-export) SKIP_EXPORT=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

printf '\n\033[32mHawkShield v2 training pipeline\033[0m\n'
echo "  repo   : $ROOT"
echo "  python : $PY"
[ -x "$PY" ] || die "no virtualenv python at $PY. Create it, then re-run."

# --------------------------------------------------------------------------- #
stage "dependencies"
NEED=()
for m in numpy pyarrow lightgbm onnx onnxruntime; do
  "$PY" -c "import $m" >/dev/null 2>&1 || NEED+=("$m")
done
if [ ${#NEED[@]} -gt 0 ]; then
  echo "  installing: ${NEED[*]}"
  "$PY" -m pip install --quiet "${NEED[@]}" || die "pip install failed for: ${NEED[*]}"
fi

if TORCH_INFO="$("$PY" -c 'import torch;print(torch.__version__, torch.cuda.is_available())' 2>/dev/null)"; then
  echo "  torch ${TORCH_INFO% *}  cuda_available=${TORCH_INFO#* }"
  if [ "${TORCH_INFO#* }" != "True" ]; then
    printf '\033[33m  [warn] CUDA not available -- training on CPU. That is 20-50x slower.\n'
    printf '         CUDA build: %s -m pip install --force-reinstall torch --index-url https://download.pytorch.org/whl/cu126\033[0m\n' "$PY"
  else
    "$PY" -c "import torch;print('  gpu    :', torch.cuda.get_device_name(0), round(torch.cuda.get_device_properties(0).total_memory/1e9,1),'GB')"
  fi
else
  printf '\n\033[33m  PyTorch is not installed.\n'
  printf '  For the RTX 4070 SUPER (12 GB) install the CUDA build:\n\n'
  printf '      %s -m pip install torch --index-url https://download.pytorch.org/whl/cu126\n\n\033[0m' "$PY"
  [ "$MODEL" = "gbdt" ] || die "torch required for --model $MODEL. Run the pip line above (~2.5 GB), then re-run. Or use --model gbdt."
  echo "  --model gbdt does not need torch; continuing."
fi

# --------------------------------------------------------------------------- #
stage "AWID3 -> parquet"
SHARDS=0
[ -d "$DATA" ] && SHARDS=$(find "$DATA" -name '*.parquet' 2>/dev/null | wc -l | tr -d ' ')
if [ "$FRESH" = "1" ] || [ "$SHARDS" = "0" ]; then
  [ -f "$ZIP" ] || die "AWID3 archive not found at $ZIP (pass --zip <path>)."
  if [ "$FRESH" = "1" ] && [ -d "$DATA" ]; then
    echo "  --fresh: removing existing shards"; rm -rf "$DATA"
  fi
  echo "  full pass over 46 GB of CSV, expect ~4 minutes on 16 cores"
  run "$ROOT/ml/prepare_awid3.py" --zip "$ZIP" --out "$DATA" --workers 6
else
  echo "  reusing $SHARDS existing shards in $DATA (pass --fresh to rebuild)"
fi

# --------------------------------------------------------------------------- #
stage "train"
TRAIN_ARGS=(--data "$DATA" --out "$OUT" --model "$MODEL" --epochs "$EPOCHS"
            --batch-size "$BATCH" --window "$WINDOW" --device "$DEVICE" --seed "$SEED")
[ "$MAX_ROWS" != "0" ] && TRAIN_ARGS+=(--max-rows "$MAX_ROWS")
run "$ROOT/ml/train.py" "${TRAIN_ARGS[@]}"

# --------------------------------------------------------------------------- #
stage "evaluate (held-out blocks + leakage probe)"
run "$ROOT/ml/evaluate.py" --models "$OUT" --device "$DEVICE"

# --------------------------------------------------------------------------- #
if [ "$SKIP_EXPORT" = "0" ] && [ "$MODEL" != "gbdt" ]; then
  stage "export ONNX + int8"
  run "$ROOT/ml/export_onnx.py" --models "$OUT" --out "$ROOT/models" --data "$DATA"
fi

printf '\n\033[32m%s\n  DONE\033[0m\n' "$(printf '=%.0s' {1..72})"
echo "    training report : $ROOT/ml/reports/train_report.md"
echo "    eval report     : $ROOT/ml/reports/eval_report.md"
echo "    checkpoints     : $OUT"
[ "$SKIP_EXPORT" = "0" ] && [ "$MODEL" != "gbdt" ] && echo "    onnx            : $ROOT/models"
printf '\033[32m%s\033[0m\n' "$(printf '=%.0s' {1..72})"
