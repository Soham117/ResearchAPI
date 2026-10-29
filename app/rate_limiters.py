"""
rate_limiters.py — Pure, atomic Redis-backed rate-limiter implementations.

Each algorithm is encapsulated as an async class implementing the common
`is_allowed(key: str) -> bool` interface, enabling dependency-injection
toggling via the X-Algorithm request header.

Lua scripts execute atomically inside Redis to prevent race conditions
under concurrent traffic, which is critical for accurate benchmarking.

Author: Soham Adsare (SY MCA, ICEM Pune)
Guide:  Dr. Dhanashree Patil
"""

import time
import redis.asyncio as aioredis
from abc import ABC, abstractmethod
from app.config import settings


class BaseRateLimiter(ABC):
    """Abstract interface — all limiters must implement `is_allowed`."""

    def __init__(self, client: aioredis.Redis):
        self.client = client

    @abstractmethod
    async def is_allowed(self, key: str) -> bool:
        """Return True if the request should be allowed, False if rate-limited."""
        ...

    @abstractmethod
    def algorithm_name(self) -> str:
        """Human-readable algorithm identifier for logging."""
        ...


# ═════════════════════════════════════════════════════════════
# 1. FIXED WINDOW COUNTER
# ═════════════════════════════════════════════════════════════
# Mechanism:
#   - Divide time into discrete windows of size W seconds.
#   - Each window is identified by floor(epoch / W).
#   - A Redis key "fw:{client_key}:{window_id}" tracks the count.
#   - INCR atomically increments; EXPIRE auto-cleans after W seconds.
#
# Strengths:  Simple, O(1), minimal memory.
# Weaknesses: Burst at window boundaries can allow 2× the limit
#             (the "boundary exploitation" attack profile tests this).
# ═════════════════════════════════════════════════════════════

# Lua script for atomic increment + conditional expire in a single RTT.
# KEYS[1] = the window key
# ARGV[1] = max requests allowed
# ARGV[2] = window TTL in seconds
# Returns: 1 if allowed, 0 if blocked
_FIXED_WINDOW_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if current <= tonumber(ARGV[1]) then
    return 1
else
    return 0
end
"""


class FixedWindowLimiter(BaseRateLimiter):
    """Fixed Window Counter using atomic Redis Lua script."""

    def __init__(self, client: aioredis.Redis):
        super().__init__(client)
        self.max_requests = settings.rate_limit_requests
        self.window_seconds = settings.rate_limit_window_seconds
        self._script = client.register_script(_FIXED_WINDOW_LUA)

    def algorithm_name(self) -> str:
        return "fixed_window"

    async def is_allowed(self, key: str) -> bool:
        # Compute the current window ID: floor(epoch / window_size)
        window_id = int(time.time()) // self.window_seconds
        redis_key = f"fw:{key}:{window_id}"

        result = await self._script(
            keys=[redis_key],
            args=[self.max_requests, self.window_seconds],
        )
        # Lua returns 1 (allowed) or 0 (blocked)
        return result == 1


# ═════════════════════════════════════════════════════════════
# 2. SLIDING WINDOW COUNTER (Weighted Linear Approximation)
# ═════════════════════════════════════════════════════════════
# Mechanism:
#   - Maintains counters for both the current AND previous window.
#   - Computes a weighted estimate:
#       effective_count = prev_count × overlap_ratio + curr_count
#     where overlap_ratio = 1 - (elapsed_seconds_in_current_window / W)
#   - This smooths out boundary spikes that plague Fixed Window.
#
# Strengths:  Better boundary behaviour, still O(1) storage.
# Weaknesses: Approximation — not perfectly accurate per-request.
# ═════════════════════════════════════════════════════════════

# Lua script: atomically reads prev-window count, increments current,
# and returns the weighted total for the caller to decide.
# KEYS[1] = current window key   ("sw:{key}:{curr_id}")
# KEYS[2] = previous window key  ("sw:{key}:{prev_id}")
# ARGV[1] = max requests
# ARGV[2] = window TTL seconds
# ARGV[3] = overlap_ratio (float string, e.g., "0.73")
# Returns: 1 if allowed, 0 if blocked
_SLIDING_WINDOW_LUA = """
local prev_count = tonumber(redis.call('GET', KEYS[2]) or "0")
local curr_count = redis.call('INCR', KEYS[1])
if curr_count == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]) * 2)
end
local overlap = tonumber(ARGV[3])
local weighted = prev_count * overlap + curr_count
if weighted <= tonumber(ARGV[1]) then
    return 1
else
    return 0
end
"""


class SlidingWindowLimiter(BaseRateLimiter):
    """Sliding Window Counter with weighted linear approximation."""

    def __init__(self, client: aioredis.Redis):
        super().__init__(client)
        self.max_requests = settings.rate_limit_requests
        self.window_seconds = settings.rate_limit_window_seconds
        self._script = client.register_script(_SLIDING_WINDOW_LUA)

    def algorithm_name(self) -> str:
        return "sliding_window"

    async def is_allowed(self, key: str) -> bool:
        now = time.time()
        # Current and previous window identifiers
        curr_window = int(now) // self.window_seconds
        prev_window = curr_window - 1

        # How far into the current window we are (0.0 → 1.0)
        elapsed_fraction = (now - curr_window * self.window_seconds) / self.window_seconds
        # Overlap ratio: how much of the previous window still "counts"
        overlap_ratio = 1.0 - elapsed_fraction

        curr_key = f"sw:{key}:{curr_window}"
        prev_key = f"sw:{key}:{prev_window}"

        result = await self._script(
            keys=[curr_key, prev_key],
            args=[self.max_requests, self.window_seconds, f"{overlap_ratio:.6f}"],
        )
        return result == 1


# ═════════════════════════════════════════════════════════════
# 3. TOKEN BUCKET
# ═════════════════════════════════════════════════════════════
# Mechanism:
#   - Each client has a bucket with capacity B tokens.
#   - Tokens refill at rate r tokens/second.
#   - On each request: compute tokens_to_add since last_refill,
#     update bucket level (capped at B), then try to consume 1 token.
#   - If tokens >= 1: allowed (consume 1). Else: blocked.
#
# Strengths:  Allows controlled bursts, smooth steady-state limiting.
# Weaknesses: Slightly more state per client (tokens + timestamp).
# ═════════════════════════════════════════════════════════════

# Lua script: atomic read-compute-update in a single Redis call.
# KEYS[1] = bucket state hash key ("tb:{key}")
# ARGV[1] = bucket capacity B
# ARGV[2] = refill rate r (tokens/second)
# ARGV[3] = current epoch time (float string)
# Returns: 1 if allowed, 0 if blocked
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Retrieve current bucket state
local tokens = tonumber(redis.call('HGET', key, 'tokens'))
local last_refill = tonumber(redis.call('HGET', key, 'last_refill'))

-- Initialise bucket on first access
if tokens == nil then
    tokens = capacity
    last_refill = now
end

-- Calculate tokens to add based on elapsed time since last refill
local delta = math.max(0, now - last_refill)
tokens = math.min(capacity, tokens + delta * refill_rate)
last_refill = now

-- Try to consume one token
if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HSET', key, 'tokens', tostring(tokens))
    redis.call('HSET', key, 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, 300)  -- Auto-cleanup idle buckets after 5 min
    return 1
else
    redis.call('HSET', key, 'tokens', tostring(tokens))
    redis.call('HSET', key, 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, 300)
    return 0
end
"""


class TokenBucketLimiter(BaseRateLimiter):
    """Token Bucket with capacity B and refill rate r, stored atomically in Redis."""

    def __init__(self, client: aioredis.Redis):
        super().__init__(client)
        self.capacity = settings.token_bucket_capacity
        self.refill_rate = settings.token_bucket_refill_rate
        self._script = client.register_script(_TOKEN_BUCKET_LUA)

    def algorithm_name(self) -> str:
        return "token_bucket"

    async def is_allowed(self, key: str) -> bool:
        now = time.time()
        redis_key = f"tb:{key}"

        result = await self._script(
            keys=[redis_key],
            args=[self.capacity, self.refill_rate, f"{now:.6f}"],
        )
        return result == 1


# ═════════════════════════════════════════════════════════════
# FACTORY — Dependency-injection toggle
# ═════════════════════════════════════════════════════════════

_REGISTRY: dict[str, type[BaseRateLimiter]] = {
    "fixed":   FixedWindowLimiter,
    "sliding": SlidingWindowLimiter,
    "token":   TokenBucketLimiter,
}


def get_limiter(algorithm: str, client: aioredis.Redis) -> BaseRateLimiter:
    """
    Factory function: instantiate the requested rate-limiter.

    Parameters
    ----------
    algorithm : str
        One of "fixed", "sliding", or "token".
    client : aioredis.Redis
        Shared async Redis connection pool.

    Returns
    -------
    BaseRateLimiter
        The configured limiter instance.

    Raises
    ------
    ValueError
        If the algorithm name is not recognised.
    """
    cls = _REGISTRY.get(algorithm.lower())
    if cls is None:
        valid = ", ".join(sorted(_REGISTRY.keys()))
        raise ValueError(
            f"Unknown algorithm '{algorithm}'. Valid options: {valid}"
        )
    return cls(client)
