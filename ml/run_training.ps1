<#
.SYNOPSIS
    HawkShield v2 -- one command: deps -> data -> train -> evaluate -> export.

.EXAMPLE
    .\ml\run_training.ps1
    .\ml\run_training.ps1 -Fresh              # re-run AWID3 preprocessing first
    .\ml\run_training.ps1 -Model gbdt -Epochs 4
    .\ml\run_training.ps1 -MaxRows 2000000    # quick pass on a subset of blocks

.NOTES
    GPU: this box has an RTX 4070 SUPER (12 GB). PyTorch is NOT installed by
    default and the CPU wheel will NOT use it. Install the CUDA build once:

        .\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu126

    Without it the script falls back to CPU and says so. It never installs a
    multi-gigabyte wheel behind your back.
#>
[CmdletBinding()]
param(
    [switch]$Fresh,
    [ValidateSet('tcn', 'gbdt', 'both')][string]$Model = 'both',
    [int]$Epochs = 12,
    [int]$BatchSize = 256,
    [int]$Window = 128,
    [ValidateSet('auto', 'cuda', 'cpu')][string]$Device = 'auto',
    [int]$MaxRows = 0,
    [int]$Seed = 1337,
    [string]$Zip = 'D:/AWID3.zip',
    [switch]$SkipExport
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root '.venv\Scripts\python.exe'
$Data = Join-Path $Root '_work\awid3_v2'
$Out = Join-Path $Root '_work\models_v2'
$stageNo = 0

function Stage([string]$msg) {
    $script:stageNo++
    Write-Host ''
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host ("  STAGE $script:stageNo  $msg") -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Die([string]$msg) {
    Write-Host ''
    Write-Host "[FAIL] $msg" -ForegroundColor Red
    exit 1
}

function Run([string[]]$argv) {
    Write-Host "  > $Py $($argv -join ' ')" -ForegroundColor DarkGray
    & $Py @argv
    if ($LASTEXITCODE -ne 0) { Die "stage $script:stageNo failed with exit code $LASTEXITCODE" }
}

Write-Host ''
Write-Host 'HawkShield v2 training pipeline' -ForegroundColor Green
Write-Host "  repo   : $Root"
Write-Host "  python : $Py"
if (-not (Test-Path $Py)) { Die "no virtualenv at $Py. Create it, then re-run." }

# --------------------------------------------------------------------------- #
Stage 'dependencies'
$need = @()
foreach ($m in @('numpy', 'pyarrow', 'lightgbm', 'onnx', 'onnxruntime')) {
    & $Py -c "import $m" 2>$null
    if ($LASTEXITCODE -ne 0) { $need += $m }
}
if ($need.Count -gt 0) {
    Write-Host "  installing: $($need -join ', ')" -ForegroundColor Yellow
    & $Py -m pip install --quiet @need
    if ($LASTEXITCODE -ne 0) { Die "pip install failed for: $($need -join ', ')" }
}

$torchInfo = & $Py -c "import torch,sys; print(torch.__version__, torch.cuda.is_available())" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host '  PyTorch is not installed.' -ForegroundColor Yellow
    Write-Host '  For the RTX 4070 SUPER (12 GB) install the CUDA build:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "      $Py -m pip install torch --index-url https://download.pytorch.org/whl/cu126" -ForegroundColor White
    Write-Host ''
    if ($Model -eq 'gbdt') {
        Write-Host '  --Model gbdt does not need torch; continuing.' -ForegroundColor Yellow
    }
    else {
        Die "torch required for --Model $Model. Run the pip line above (~2.5 GB), then re-run this script. Or use -Model gbdt."
    }
}
else {
    $parts = $torchInfo -split '\s+'
    Write-Host "  torch $($parts[0])  cuda_available=$($parts[1])"
    if ($parts[1] -ne 'True') {
        Write-Host '  [warn] CUDA not available -- training on CPU. That is 20-50x slower.' -ForegroundColor Yellow
        Write-Host "         CUDA build: $Py -m pip install --force-reinstall torch --index-url https://download.pytorch.org/whl/cu126" -ForegroundColor Yellow
    }
    else {
        & $Py -c "import torch; print('  gpu    :', torch.cuda.get_device_name(0), round(torch.cuda.get_device_properties(0).total_memory/1e9,1), 'GB')"
    }
}

# --------------------------------------------------------------------------- #
Stage 'AWID3 -> parquet'
$shardCount = 0
if (Test-Path $Data) { $shardCount = (Get-ChildItem $Data -Recurse -Filter *.parquet).Count }
if ($Fresh -or $shardCount -eq 0) {
    if (-not (Test-Path $Zip)) { Die "AWID3 archive not found at $Zip (pass -Zip <path>)." }
    if ($Fresh -and (Test-Path $Data)) {
        Write-Host '  -Fresh: removing existing shards' -ForegroundColor Yellow
        Remove-Item -Recurse -Force $Data
    }
    Write-Host '  full pass over 46 GB of CSV, expect ~4 minutes on 16 cores'
    Run @((Join-Path $Root 'ml\prepare_awid3.py'), '--zip', $Zip, '--out', $Data, '--workers', '6')
}
else {
    Write-Host "  reusing $shardCount existing shards in $Data (pass -Fresh to rebuild)"
}

# --------------------------------------------------------------------------- #
Stage 'train'
$trainArgs = @((Join-Path $Root 'ml\train.py'),
    '--data', $Data, '--out', $Out, '--model', $Model,
    '--epochs', $Epochs, '--batch-size', $BatchSize, '--window', $Window,
    '--device', $Device, '--seed', $Seed)
if ($MaxRows -gt 0) { $trainArgs += @('--max-rows', $MaxRows) }
Run $trainArgs

# --------------------------------------------------------------------------- #
Stage 'evaluate (held-out blocks + leakage probe)'
Run @((Join-Path $Root 'ml\evaluate.py'), '--models', $Out, '--device', $Device)

# --------------------------------------------------------------------------- #
if (-not $SkipExport -and $Model -ne 'gbdt') {
    Stage 'export ONNX + int8'
    Run @((Join-Path $Root 'ml\export_onnx.py'), '--models', $Out,
        '--out', (Join-Path $Root 'models'), '--data', $Data)
}

Write-Host ''
Write-Host ("=" * 72) -ForegroundColor Green
Write-Host '  DONE' -ForegroundColor Green
Write-Host "    training report : $(Join-Path $Root 'ml\reports\train_report.md')"
Write-Host "    eval report     : $(Join-Path $Root 'ml\reports\eval_report.md')"
Write-Host "    checkpoints     : $Out"
if (-not $SkipExport -and $Model -ne 'gbdt') {
    Write-Host "    onnx            : $(Join-Path $Root 'models')"
}
Write-Host ("=" * 72) -ForegroundColor Green
