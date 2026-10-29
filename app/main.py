"""
main.py — FastAPI application with rate-limited authentication endpoint.

Architecture:
  1. Middleware intercepts every request, extracts client IP + algorithm header.
  2. Rate limiter (selected via X-Algorithm header) checks if the IP is allowed.
  3. If allowed, the login endpoint validates credentials against the mock store.
  4. Every request is logged as a JSON-lines entry with sub-millisecond precision.
  5. Prometheus metrics are exported at /metrics for real-time Grafana dashboards.

Author: Soham Adsare (SY MCA, ICEM Pune)
Guide:  Dr. Dhanashree Patil
"""

import hashlib
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import orjson
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

# Prometheus instrumentation
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    REGISTRY,
)

from app.config import MOCK_USERS, settings
from app.rate_limiters import get_limiter


# ── Prometheus Metrics ───────────────────────────────────────
# These are registered globally and survive across requests.
# Labels enable per-dimension slicing in Grafana queries.

rate_limit_requests_total = Counter(
    "rate_limit_requests_total",
    "Total rate-limited requests processed",
    labelnames=["algorithm", "traffic_type", "http_status", "is_attack", "outcome"],
)

rate_limit_latency_seconds = Histogram(
    "rate_limit_latency_seconds",
    "Request processing latency in seconds (rate-limiter + auth)",
    labelnames=["algorithm"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

rate_limit_active_blocks_total = Counter(
    "rate_limit_active_blocks_total",
    "Total HTTP 429 rate-limited responses",
    labelnames=["algorithm", "traffic_type", "is_attack"],
)


# ── Pydantic Models ──────────────────────────────────────────

class LoginRequest(BaseModel):
    """Payload schema for the login endpoint."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Successful authentication response."""
    status: str
    message: str
    username: str


class ErrorResponse(BaseModel):
    """Error response for rate-limiting or auth failure."""
    status: str
    message: str


# ── Application Lifespan (Redis connection pool) ─────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the async Redis connection pool across the application lifespan.
    Connection is created on startup and cleanly closed on shutdown.
    """
    app.state.redis = aioredis.from_url(
        settings.redis_url,
        decode_responses=False,  # Lua scripts return integers
        max_connections=50,
    )
    # Ensure logs directory exists
    Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)
    yield
    await app.state.redis.aclose()


app = FastAPI(
    title="Rate-Limiter Benchmarking API",
    description=(
        "Comparative study of Fixed Window, Sliding Window, and Token Bucket "
        "algorithms against credential stuffing attack profiles. "
        "Includes Prometheus instrumentation for real-time Grafana dashboards."
    ),
    version="2.0.0",
    lifespan=lifespan,
)


# ── Structured Logger ────────────────────────────────────────

async def log_request(entry: dict) -> None:
    """
    Append a single JSON-lines entry to the experiment log file.

    Uses orjson for high-throughput serialization (5-10× faster than
    stdlib json). File is opened in append mode per-write to ensure
    crash-safe durability without holding a persistent file handle
    across async context switches.
    """
    log_path = settings.log_file
    line = orjson.dumps(entry) + b"\n"
    # Synchronous write is acceptable here — the OS buffer flush
    # is sub-microsecond for a single ~300-byte line, and avoids
    # the complexity of an async file I/O library for log lines.
    with open(log_path, "ab") as f:
        f.write(line)


# ── Middleware: Rate Limiting & Request Logging ──────────────

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next) -> Response:
    """
    Intercept every request to:
      1. Determine the active algorithm from X-Algorithm header.
      2. Evaluate the rate limiter for the client's IP.
      3. Log the full request lifecycle with timing data.
      4. Update Prometheus counters and histograms.

    The middleware sits BEFORE the route handler, so blocked requests
    never reach the authentication logic — this is architecturally
    identical to how production API gateways operate.
    """
    # ── Skip instrumentation for /metrics and /health endpoints ──
    if request.url.path in ("/metrics", "/health", "/docs", "/openapi.json"):
        return await call_next(request)

    # ── Extract metadata ─────────────────────────────────────
    request_id = str(uuid.uuid4())
    # X-Algorithm header selects which limiter to use (default: fixed)
    algorithm_name = request.headers.get("X-Algorithm", "fixed").lower()
    # X-Traffic-Type is injected by the traffic generator for labelling
    traffic_type = request.headers.get("X-Traffic-Type", "unknown")
    # X-Is-Attack: ground-truth label for confusion matrix computation
    is_attack = request.headers.get("X-Is-Attack", "false").lower() == "true"
    # Client IP (support X-Forwarded-For for proxied setups)
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)

    start_time = time.perf_counter()  # Sub-millisecond precision timer

    # ── Rate-limit evaluation ────────────────────────────────
    redis_client = request.app.state.redis
    limiter = get_limiter(algorithm_name, redis_client)
    blocked = not await limiter.is_allowed(client_ip)

    is_attack_str = str(is_attack).lower()

    if blocked:
        # Request is rate-limited — return 429 without reaching the endpoint
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        elapsed_s = elapsed_ms / 1000

        # ── Prometheus instrumentation ───────────────────────
        rate_limit_requests_total.labels(
            algorithm=limiter.algorithm_name(),
            traffic_type=traffic_type,
            http_status="429",
            is_attack=is_attack_str,
            outcome="blocked",
        ).inc()
        rate_limit_active_blocks_total.labels(
            algorithm=limiter.algorithm_name(),
            traffic_type=traffic_type,
            is_attack=is_attack_str,
        ).inc()
        rate_limit_latency_seconds.labels(
            algorithm=limiter.algorithm_name(),
        ).observe(elapsed_s)

        await log_request({
            "timestamp": time.time(),
            "request_id": request_id,
            "client_ip": client_ip,
            "username": "",  # Never reached auth
            "algorithm": limiter.algorithm_name(),
            "traffic_type": traffic_type,
            "http_status": 429,
            "is_attack": is_attack,
            "blocked_by_limiter": True,
            "auth_success": False,
            "latency_ms": round(elapsed_ms, 4),
        })

        return JSONResponse(
            status_code=429,
            content={"status": "error", "message": "Rate limit exceeded"},
        )

    # ── Forward to endpoint ──────────────────────────────────
    # Stash metadata on the request state for the endpoint to use
    request.state.request_id = request_id
    request.state.algorithm = limiter.algorithm_name()
    request.state.traffic_type = traffic_type
    request.state.is_attack = is_attack
    request.state.is_attack_str = is_attack_str
    request.state.client_ip = client_ip
    request.state.start_time = start_time

    response = await call_next(request)
    return response


# ── Login Endpoint ───────────────────────────────────────────

@app.post(
    "/api/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        429: {"model": ErrorResponse, "description": "Rate limited"},
    },
    summary="Authenticate user credentials",
    description="Simulates real credential checking against an in-memory mock user store.",
)
async def login(body: LoginRequest, request: Request) -> Response:
    """
    Authenticate against the mock user store.

    This endpoint is only reached if the rate limiter permits the request.
    The middleware has already attached timing and metadata to request.state.
    """
    start_time = request.state.start_time

    # ── Credential verification ──────────────────────────────
    password_hash = hashlib.sha256(body.password.encode()).hexdigest()
    stored_hash = MOCK_USERS.get(body.username)

    if stored_hash and stored_hash == password_hash:
        # Valid credentials
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        elapsed_s = elapsed_ms / 1000

        # ── Prometheus instrumentation ───────────────────────
        rate_limit_requests_total.labels(
            algorithm=request.state.algorithm,
            traffic_type=request.state.traffic_type,
            http_status="200",
            is_attack=request.state.is_attack_str,
            outcome="allowed",
        ).inc()
        rate_limit_latency_seconds.labels(
            algorithm=request.state.algorithm,
        ).observe(elapsed_s)

        await log_request({
            "timestamp": time.time(),
            "request_id": request.state.request_id,
            "client_ip": request.state.client_ip,
            "username": body.username,
            "algorithm": request.state.algorithm,
            "traffic_type": request.state.traffic_type,
            "http_status": 200,
            "is_attack": request.state.is_attack,
            "blocked_by_limiter": False,
            "auth_success": True,
            "latency_ms": round(elapsed_ms, 4),
        })
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Authentication successful",
                "username": body.username,
            },
        )
    else:
        # Invalid credentials
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        elapsed_s = elapsed_ms / 1000

        # ── Prometheus instrumentation ───────────────────────
        rate_limit_requests_total.labels(
            algorithm=request.state.algorithm,
            traffic_type=request.state.traffic_type,
            http_status="401",
            is_attack=request.state.is_attack_str,
            outcome="allowed",
        ).inc()
        rate_limit_latency_seconds.labels(
            algorithm=request.state.algorithm,
        ).observe(elapsed_s)

        await log_request({
            "timestamp": time.time(),
            "request_id": request.state.request_id,
            "client_ip": request.state.client_ip,
            "username": body.username,
            "algorithm": request.state.algorithm,
            "traffic_type": request.state.traffic_type,
            "http_status": 401,
            "is_attack": request.state.is_attack,
            "blocked_by_limiter": False,
            "auth_success": False,
            "latency_ms": round(elapsed_ms, 4),
        })
        return JSONResponse(
            status_code=401,
            content={
                "status": "error",
                "message": "Invalid username or password",
            },
        )


# ── Prometheus Metrics Endpoint ──────────────────────────────

@app.get(
    "/metrics",
    summary="Prometheus metrics endpoint",
    description="Exposes Prometheus-format metrics for scraping.",
    include_in_schema=False,
)
async def metrics():
    """Serve Prometheus metrics in exposition format."""
    return PlainTextResponse(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Admin: Flush Redis & Reset ───────────────────────────────

@app.post(
    "/api/admin/flush",
    summary="Flush Redis state and reset for next demo",
    description="Clears all rate-limiter counters in Redis for a clean demo restart.",
)
async def admin_flush(request: Request):
    """
    Flush all Redis keys to reset rate-limiter state between demo runs.
    Called by the demo controller between attack scenarios.
    """
    try:
        await request.app.state.redis.flushdb()
        return JSONResponse(
            status_code=200,
            content={"status": "flushed", "message": "Redis state cleared successfully"},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Flush failed: {str(e)}"},
        )


# ── Health Check ─────────────────────────────────────────────

@app.get("/health")
async def health():
    """Readiness probe for Docker health checks."""
    return {"status": "ok"}
