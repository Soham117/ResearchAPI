# run_demo.ps1 - One-Click Live Demo Launcher
#
# This is the ONLY script you need to run.
# It handles: Docker build, container startup, health checks,
# opens Grafana, and launches the Interactive Demo Menu.
#
# Usage:
#   .\run_demo.ps1
#
# Author: Soham Adsare (SY MCA, ICEM Pune)
# Guide:  Dr. Dhanashree Patil

$ErrorActionPreference = 'Continue'

function Write-Info  { param([string]$msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param([string]$msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host '  API Rate-Limiter - Live Demo Launcher' -ForegroundColor White
Write-Host '  Author: Soham Adsare | Guide: Dr. Dhanashree Patil' -ForegroundColor DarkGray
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

# STEP 1: Build and Start All Containers
Write-Info 'Building Docker images...'
docker compose build
if ($LASTEXITCODE -ne 0) {
    Write-Err 'Docker build failed. Is Docker Desktop running?'
    exit 1
}
Write-Ok 'Images built'

Write-Info 'Starting all services...'
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Err 'Failed to start containers'
    exit 1
}
Write-Ok 'Containers started'

# STEP 2: Wait for FastAPI
Write-Info 'Waiting for FastAPI...'
$maxRetries = 40
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $response = Invoke-WebRequest -Uri 'http://localhost:8000/health' -UseBasicParsing -TimeoutSec 3 2>$null
        if ($response.StatusCode -eq 200) {
            Write-Ok "FastAPI is ready - attempt $i of $maxRetries"
            break
        }
    } catch {
        if ($i -eq $maxRetries) {
            Write-Err 'FastAPI failed to start'
            docker compose logs api --tail 20
            exit 1
        }
        Write-Host "  Waiting... $i of $maxRetries" -ForegroundColor DarkGray
        Start-Sleep -Seconds 2
    }
}

# STEP 3: Wait for Prometheus
Write-Info 'Waiting for Prometheus...'
for ($i = 1; $i -le 20; $i++) {
    try {
        $response = Invoke-WebRequest -Uri 'http://localhost:9090/-/ready' -UseBasicParsing -TimeoutSec 3 2>$null
        if ($response.StatusCode -eq 200) {
            Write-Ok 'Prometheus is ready'
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

# STEP 4: Wait for Grafana
Write-Info 'Waiting for Grafana...'
for ($i = 1; $i -le 30; $i++) {
    try {
        $response = Invoke-WebRequest -Uri 'http://localhost:3000/api/health' -UseBasicParsing -TimeoutSec 3 2>$null
        if ($response.StatusCode -eq 200) {
            Write-Ok 'Grafana is ready'
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

# STEP 5: Flush Redis
Write-Info 'Flushing Redis...'
docker compose exec -T redis redis-cli FLUSHALL 2>$null | Out-Null
Write-Ok 'Redis flushed'

# STEP 6: Summary and open Grafana
Write-Host ''
Write-Host '========================================================' -ForegroundColor Green
Write-Host '  ALL SERVICES READY' -ForegroundColor Green
Write-Host '========================================================' -ForegroundColor Green
Write-Host ''
Write-Host '  Grafana Dashboard:  http://localhost:3000' -ForegroundColor Blue
Write-Host '  API Swagger Docs:   http://localhost:8000/docs' -ForegroundColor Blue
Write-Host '  Prometheus:         http://localhost:9090' -ForegroundColor Blue
Write-Host '  Metrics Endpoint:   http://localhost:8000/metrics' -ForegroundColor Blue
Write-Host ''

Write-Info 'Opening Grafana in your browser...'
Start-Process 'http://localhost:3000'
Start-Sleep -Seconds 2

# STEP 7: Launch Interactive Demo Controller
Write-Info 'Launching Interactive Demo Controller...'
Write-Host ''

python demo_controller.py

Write-Host ''
Write-Ok 'Demo session ended'
