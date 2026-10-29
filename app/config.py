"""
Configuration — Pydantic Settings for the benchmarking suite.
All values can be overridden via environment variables or docker-compose.
"""

from pydantic_settings import BaseSettings
from typing import Literal
import hashlib


class Settings(BaseSettings):
    """Centralised, validated configuration loaded from the environment."""

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Rate-Limiter Defaults ────────────────────────────────
    # Maximum requests permitted within the rate-limit window
    rate_limit_requests: int = 5
    # Window duration in seconds (applies to Fixed & Sliding Window)
    rate_limit_window_seconds: int = 60
    # Token Bucket: maximum burst capacity
    token_bucket_capacity: int = 5
    # Token Bucket: tokens replenished per second (≈5 per 60s)
    token_bucket_refill_rate: float = 0.0833

    # ── Logging ──────────────────────────────────────────────
    log_file: str = "logs/experiment_runs.jsonl"

    # ── Server ───────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# ── Mock User Store ──────────────────────────────────────────
# Simulates a real credential database with hashed passwords.
# Credentials are intentionally simple for reproducible experiments.
_RAW_USERS = {
    "alice":    "P@ssw0rd1",
    "bob":      "Secur3!ty",
    "charlie":  "Cr3dent!al",
    "dave":     "Tr0ub4dor",
    "eve":      "Hunt3r2k",
    "frank":    "B4nk$afe",
    "grace":    "N3tw0rk!",
    "heidi":    "Cl0ud#99",
    "ivan":     "D3f3nd3r",
    "judy":     "Sh13ld!X",
}

def _hash(pw: str) -> str:
    """SHA-256 hash — sufficient for simulation, not production auth."""
    return hashlib.sha256(pw.encode()).hexdigest()

# Exported store: username → sha256(password)
MOCK_USERS: dict[str, str] = {u: _hash(p) for u, p in _RAW_USERS.items()}

# Valid usernames list (used by traffic generator for legitimate requests)
VALID_USERNAMES = list(_RAW_USERS.keys())
# Correct raw passwords (used by traffic generator to build valid payloads)
VALID_CREDENTIALS = dict(_RAW_USERS)


settings = Settings()
