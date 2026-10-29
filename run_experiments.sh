#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# run_experiments.sh — Automated Experiment Orchestrator
#
# This script:
#   1. Builds and starts Docker containers (Redis + FastAPI)
#   2. Waits for services to become healthy
#   3. Flushes all Redis state for a clean baseline
#   4. Clears any previous experiment logs
#   5. Runs the traffic generator for all 3 algorithms × 5 profiles
#   6. Executes the analysis pipeline to compute metrics
#   7. Optionally tears down containers
#
# Usage:
#   chmod +x run_experiments.sh
#   ./run_experiments.sh          # Run full suite
#   ./run_experiments.sh fixed    # Run only fixed window algorithm
#
# Author: Soham Adsare (SY MCA, ICEM Pune)
# Guide:  Dr. Dhanashree Patil
# ──────────────────────────────────────────────────────────────

set -euo pipefail
IFS=$'\n\t'

# ── Colour output helpers ────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ALGORITHM_FILTER="${1:-}"  # Optional: "fixed", "sliding", "token", or comma-separated

# ══════════════════════════════════════════════════════════════
# STEP 1: Build & Start Containers
# ══════════════════════════════════════════════════════════════
log_info "Building Docker images..."
docker compose build --quiet

log_info "Starting Redis and FastAPI containers..."
docker compose up -d

# ══════════════════════════════════════════════════════════════
# STEP 2: Wait for Services
# ══════════════════════════════════════════════════════════════
log_info "Waiting for FastAPI to become healthy..."
MAX_RETRIES=30
for i in $(seq 1 $MAX_RETRIES); do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        log_ok "FastAPI is ready (attempt $i/$MAX_RETRIES)"
        break
    fi
    if [ "$i" -eq "$MAX_RETRIES" ]; then
        log_err "FastAPI failed to start after $MAX_RETRIES attempts"
        docker compose logs api
        exit 1
    fi
    sleep 1
done

# ══════════════════════════════════════════════════════════════
# STEP 3: Clean State
# ══════════════════════════════════════════════════════════════
log_info "Flushing Redis state..."
docker compose exec -T redis redis-cli FLUSHALL > /dev/null
log_ok "Redis flushed"

log_info "Clearing previous experiment logs..."
rm -f logs/experiment_runs.jsonl
log_ok "Logs cleared"

# ══════════════════════════════════════════════════════════════
# STEP 4: Run Traffic Generator
# ══════════════════════════════════════════════════════════════
log_info "Starting traffic generation..."
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  EXPERIMENT SUITE — Traffic Generation Phase            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

if [ -n "$ALGORITHM_FILTER" ]; then
    log_info "Running subset of algorithms: $ALGORITHM_FILTER"
    python -m simulators.traffic_generator "$ALGORITHM_FILTER"
else
    python -m simulators.traffic_generator
fi

log_ok "Traffic generation complete"

# ══════════════════════════════════════════════════════════════
# STEP 5: Run Analysis
# ══════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  EXPERIMENT SUITE — Analysis Phase                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

log_info "Computing metrics and generating outputs..."
python -m analysis.compute_metrics

log_ok "Analysis complete"

# ══════════════════════════════════════════════════════════════
# STEP 6: Summary
# ══════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  EXPERIMENT COMPLETE                                    ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Outputs:                                               ║"
echo "║    • logs/experiment_runs.jsonl    — Raw request logs   ║"
echo "║    • analysis/output/*.png         — Visualisation plots║"
echo "║    • analysis/output/latex_tables.tex — LaTeX tables    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Count results
if [ -f "logs/experiment_runs.jsonl" ]; then
    LINE_COUNT=$(wc -l < logs/experiment_runs.jsonl)
    log_ok "Total logged requests: $LINE_COUNT"
fi

# ── Optional: Tear down containers ───────────────────────────
read -p "Tear down Docker containers? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker compose down
    log_ok "Containers stopped and removed"
else
    log_info "Containers left running. Stop with: docker compose down"
fi
