# API Rate-Limiting Effectiveness Against Credential Stuffing Attacks

> **A Comparative Study of Fixed Window, Sliding Window, and Token Bucket Algorithms**

**Authors:** Soham Adsare · Aditya Agarwal · Snehal Shinde — SY MCA (Sem III), Indira College of Engineering & Management, Pune  
**Guide:** Dr. Dhanashree Patil, Asst. Professor, Dept. of MCA

---

## Overview

This project is a fully automated, containerised benchmarking suite that evaluates three rate-limiting algorithms against multiple credential stuffing attack profiles. It generates:

- **Raw experiment logs** with sub-millisecond precision
- **Confusion matrices** (TP, FP, TN, FN) per algorithm
- **Detection metrics** (Recall, FPR, Precision, F1-Score, Accuracy)
- **Latency statistics** (Mean, Median, P95, P99)
- **Publication-ready LaTeX tables** for direct Overleaf inclusion
- **Visualisation plots** (heatmaps, box plots, confusion matrices, ROC-style scatter)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Traffic Generator (httpx)                │
│  5 Profiles: Legit / Burst / Distributed / Slow / Boundary │
└──────────────────┬──────────────────────────────────────┘
                   │ POST /api/login + metadata headers
                   ▼
┌─────────────────────────────────────────────────────────┐
│              FastAPI Middleware (rate_limiters.py)       │
│  X-Algorithm header → Fixed / Sliding / Token Bucket    │
│  Evaluate IP → Allow or 429                             │
└──────────┬───────────────────────┬──────────────────────┘
           │ Allowed               │ Blocked (429)
           ▼                       ▼
┌──────────────────┐    ┌──────────────────────────┐
│  Login Endpoint  │    │  JSON-Lines Logger        │
│  Mock Credential │    │  logs/experiment_runs.jsonl│
│  Verification    │    └──────────────────────────┘
└──────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│              Analysis Engine (compute_metrics.py)        │
│  Confusion Matrices → Metrics → LaTeX → Plots           │
└──────────────────────────────────────────────────────────┘
```

## Project Structure

```
rate-limit-study/
├── docker-compose.yml          # Redis + FastAPI orchestration
├── Dockerfile                  # FastAPI container build
├── requirements.txt            # Pinned Python dependencies
├── run_experiments.sh          # Bash orchestrator (Linux/macOS)
├── run_experiments.ps1         # PowerShell orchestrator (Windows)
├── app/
│   ├── __init__.py
│   ├── config.py               # Pydantic Settings + mock user store
│   ├── main.py                 # FastAPI app + middleware + logging
│   └── rate_limiters.py        # Fixed Window / Sliding Window / Token Bucket
├── simulators/
│   ├── __init__.py
│   └── traffic_generator.py    # 5 attack profile generators
├── analysis/
│   ├── __init__.py
│   └── compute_metrics.py      # Confusion matrix + LaTeX + plots
└── logs/
    └── .gitkeep
```

## Rate-Limiting Algorithms

| Algorithm | Mechanism | Key Strength | Known Weakness |
|-----------|-----------|-------------|----------------|
| **Fixed Window** | `INCR` counter per `floor(t/W)` | Simple, O(1) | 2× burst at boundary |
| **Sliding Window** | Weighted `prev × overlap + curr` | Smooth boundaries | Approximation |
| **Token Bucket** | `B` capacity, `r` refill/sec | Controlled bursts | More state per client |

## Attack Profiles

| # | Profile | Description | Tests |
|---|---------|-------------|-------|
| 1 | **Legitimate Baseline** | 50 IPs, Poisson arrivals, 85% valid creds | False positive baseline |
| 2 | **Concentrated Burst** | 1 IP, 500 req, 50-100 req/s | Basic per-IP blocking |
| 3 | **Distributed Many-IP** | 500+ IPs, 1-3 req each | IP-rotation evasion |
| 4 | **Low-and-Slow** | 20 IPs, 1 req/15s (below threshold) | Threshold sensitivity |
| 5 | **Boundary Exploit** | Requests at :59s and :01s | Window reset vulnerability |

## Quick Start

### Prerequisites

- Docker Desktop (with `docker compose` v2)
- Python 3.11+ (for running generators/analysis locally)

### Option A: Full Docker Pipeline

```bash
# Linux/macOS
chmod +x run_experiments.sh
./run_experiments.sh

# Windows PowerShell
.\run_experiments.ps1
```

### Option B: Manual Step-by-Step

```bash
# 1. Start infrastructure
docker compose up -d

# 2. Wait for API health
curl http://localhost:8000/health

# 3. Install Python deps (for generator + analysis)
pip install -r requirements.txt

# 4. Run traffic generator
python -m simulators.traffic_generator

# 5. Run analysis
python -m analysis.compute_metrics

# 6. View outputs
cat analysis/output/latex_tables.tex
ls analysis/output/*.png
```

### Option C: Single Algorithm

```bash
python -m simulators.traffic_generator fixed
python -m analysis.compute_metrics
```

## Configuration

All rate-limit parameters are tuneable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `RATE_LIMIT_REQUESTS` | `5` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window duration (seconds) |
| `TOKEN_BUCKET_CAPACITY` | `5` | Maximum burst capacity |
| `TOKEN_BUCKET_REFILL_RATE` | `0.0833` | Tokens replenished per second |

## Outputs

| File | Description |
|------|-------------|
| `logs/experiment_runs.jsonl` | JSON-lines log of every request |
| `analysis/output/latex_tables.tex` | 4 LaTeX tables for the paper |
| `analysis/output/detection_metrics_comparison.png` | Grouped bar chart |
| `analysis/output/latency_distribution.png` | Box plot per algorithm |
| `analysis/output/detection_heatmap.png` | Algorithm × Profile heatmap |
| `analysis/output/confusion_matrix_*.png` | Per-algorithm confusion matrix |
| `analysis/output/fpr_vs_detection_rate.png` | ROC-style scatter plot |

## License

Academic research project — Indira College of Engineering & Management, Pune.
