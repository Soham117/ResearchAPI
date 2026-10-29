# ──────────────────────────────────────────────────────────────
# run_experiments.ps1 — Windows PowerShell Experiment Orchestrator
#
# Equivalent to run_experiments.sh for Windows environments.
#
# Usage:
#   .\run_experiments.ps1              # Run full suite
#   .\run_experiments.ps1 -Algorithm fixed  # Run only fixed window
#
# Author: Soham Adsare (SY MCA, ICEM Pune)
# Guide:  Dr. Dhanashree Patil
# ──────────────────────────────────────────────────────────────

param(
    [string]$Algorithm = ""
)

$ErrorActionPreference = "Stop"

function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[ERROR] $args" -ForegroundColor Red }

# Navigate to script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# ══════════════════════════════════════════════════════════════
# STEP 1: Build & Start Containers
# ══════════════════════════════════════════════════════════════
Write-Info "Building Docker images..."
docker compose build --quiet

Write-Info "Starting Redis and FastAPI containers..."
docker compose up -d

# ══════════════════════════════════════════════════════════════
# STEP 2: Wait for Services
# ══════════════════════════════════════════════════════════════
Write-Info "Waiting for FastAPI to become healthy..."
$maxRetries = 30
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            Write-Ok "FastAPI is ready (attempt $i/$maxRetries)"
            break
        }
    } catch {
        if ($i -eq $maxRetries) {
            Write-Err "FastAPI failed to start after $maxRetries attempts"
            docker compose logs api
            exit 1
        }
        Start-Sleep -Seconds 1
    }
}

# ══════════════════════════════════════════════════════════════
# STEP 3: Clean State
# ══════════════════════════════════════════════════════════════
Write-Info "Flushing Redis state..."
docker compose exec -T redis redis-cli FLUSHALL | Out-Null
Write-Ok "Redis flushed"

Write-Info "Clearing previous experiment logs..."
if (Test-Path "logs\experiment_runs.jsonl") {
    Remove-Item "logs\experiment_runs.jsonl" -Force
}
Write-Ok "Logs cleared"

# ══════════════════════════════════════════════════════════════
# STEP 4: Run Traffic Generator
# ══════════════════════════════════════════════════════════════
Write-Info "Starting traffic generation..."
Write-Host ""
Write-Host "========================================================"
Write-Host "  EXPERIMENT SUITE - Traffic Generation Phase"
Write-Host "========================================================"
Write-Host ""

if ($Algorithm -ne "") {
    Write-Info "Running subset of algorithms: $Algorithm"
    python -m simulators.traffic_generator $Algorithm
} else {
    python -m simulators.traffic_generator
}

if ($LASTEXITCODE -ne 0) {
    Write-Err "Traffic generation failed"
    exit 1
}
Write-Ok "Traffic generation complete"

# ══════════════════════════════════════════════════════════════
# STEP 5: Run Analysis
# ══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "========================================================"
Write-Host "  EXPERIMENT SUITE - Analysis Phase"
Write-Host "========================================================"
Write-Host ""

Write-Info "Computing metrics and generating outputs..."
python -m analysis.compute_metrics

if ($LASTEXITCODE -ne 0) {
    Write-Err "Analysis failed"
    exit 1
}
Write-Ok "Analysis complete"

# ══════════════════════════════════════════════════════════════
# STEP 6: Summary
# ══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "========================================================"
Write-Host "  EXPERIMENT COMPLETE"
Write-Host "========================================================"
Write-Host ""
Write-Host "  Outputs:"
Write-Host "    * logs/experiment_runs.jsonl     - Raw request logs"
Write-Host "    * analysis/output/*.png          - Visualisation plots"
Write-Host "    * analysis/output/latex_tables.tex - LaTeX tables"
Write-Host ""

if (Test-Path "logs\experiment_runs.jsonl") {
    $lineCount = (Get-Content "logs\experiment_runs.jsonl" | Measure-Object -Line).Lines
    Write-Ok "Total logged requests: $lineCount"
}

# Prompt for teardown
$teardown = Read-Host "Tear down Docker containers? (y/N)"
if ($teardown -eq "y" -or $teardown -eq "Y") {
    docker compose down
    Write-Ok "Containers stopped and removed"
} else {
    Write-Info "Containers left running. Stop with: docker compose down"
}
