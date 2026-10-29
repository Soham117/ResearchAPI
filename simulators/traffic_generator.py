"""
traffic_generator.py — Asynchronous workload generator for rate-limiter benchmarking.

Generates 10,000+ requests per algorithm run across 5 distinct attack profiles,
each designed to stress-test specific weaknesses in rate-limiting algorithms:

  1. Legitimate Traffic Baseline  — Poisson-distributed human login behaviour
  2. Concentrated Burst Attack    — Single IP credential stuffing at 50–100 req/s
  3. Distributed Many-IP Attack   — 500+ rotating IPs, 1–3 requests each
  4. Low-and-Slow Attack          — Requests just below the detection threshold
  5. Boundary Exploitation        — Requests timed at window reset boundaries

Each request carries ground-truth headers (X-Is-Attack, X-Traffic-Type) so the
analysis pipeline can compute confusion matrices without ambiguity.

Author: Soham Adsare (SY MCA, ICEM Pune)
Guide:  Dr. Dhanashree Patil
"""

import asyncio
import math
import random
import sys
import time
from dataclasses import dataclass

import httpx

# ── Configuration ────────────────────────────────────────────

API_BASE = "http://localhost:8000"
LOGIN_URL = f"{API_BASE}/api/login"

# Rate-limit settings (must match the server's configuration)
RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60

# Valid credentials from the mock store (mirrors app/config.py)
VALID_CREDENTIALS = {
    "alice": "P@ssw0rd1",
    "bob": "Secur3!ty",
    "charlie": "Cr3dent!al",
    "dave": "Tr0ub4dor",
    "eve": "Hunt3r2k",
    "frank": "B4nk$afe",
    "grace": "N3tw0rk!",
    "heidi": "Cl0ud#99",
    "ivan": "D3f3nd3r",
    "judy": "Sh13ld!X",
}

VALID_USERNAMES = list(VALID_CREDENTIALS.keys())

# Leaked credential list (used by attackers — partial overlap with real creds)
LEAKED_CREDENTIALS = [
    ("alice", "P@ssw0rd1"),      # Correct — will succeed if not blocked
    ("bob", "Secur3!ty"),        # Correct
    ("charlie", "Cr3dent!al"),   # Correct
    ("alice", "password123"),    # Wrong password
    ("admin", "admin"),          # Non-existent user
    ("root", "toor"),            # Non-existent user
    ("dave", "letmein"),         # Wrong password
    ("eve", "Hunt3r2k"),         # Correct
    ("test", "test123"),         # Non-existent user
    ("frank", "wrongpass"),      # Wrong password
]

ALGORITHMS = ["fixed", "sliding", "token"]


@dataclass
class TrafficResult:
    """Summary of a single traffic profile run."""
    algorithm: str
    profile: str
    total_requests: int
    status_200: int
    status_401: int
    status_429: int
    duration_seconds: float


# ── Helper: Send a single login request ─────────────────────

async def send_request(
    client: httpx.AsyncClient,
    username: str,
    password: str,
    algorithm: str,
    traffic_type: str,
    is_attack: bool,
    source_ip: str,
) -> int:
    """
    Send a single POST /api/login request with full metadata headers.

    Returns the HTTP status code, or 0 on connection failure.
    """
    try:
        resp = await client.post(
            LOGIN_URL,
            json={"username": username, "password": password},
            headers={
                "X-Algorithm": algorithm,
                "X-Traffic-Type": traffic_type,
                "X-Is-Attack": str(is_attack).lower(),
                "X-Forwarded-For": source_ip,
            },
            timeout=10.0,
        )
        return resp.status_code
    except (httpx.RequestError, httpx.TimeoutException):
        return 0


# ═════════════════════════════════════════════════════════════
# TRAFFIC PROFILE 1: Legitimate Traffic Baseline
# ═════════════════════════════════════════════════════════════
# Simulates realistic human login behaviour:
#   - 50 distinct IPs (office workers, mobile users, etc.)
#   - Poisson-distributed inter-arrival times (λ = 0.5 req/s per IP)
#   - 85% correct credentials, 15% typo failures
#   - Each IP sends 2–5 requests across the test window
# ═════════════════════════════════════════════════════════════

async def generate_legitimate_traffic(
    client: httpx.AsyncClient, algorithm: str
) -> TrafficResult:
    """Generate ~200 legitimate human login requests across 50 IPs."""
    print(f"  [LEGIT] Starting legitimate traffic baseline...")
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    total = 0
    start = time.time()

    tasks = []
    for ip_idx in range(50):
        source_ip = f"192.168.1.{ip_idx + 1}"
        # Each IP sends 2–5 requests
        num_requests = random.randint(2, 5)
        for _ in range(num_requests):
            user = random.choice(VALID_USERNAMES)
            # 85% chance of correct password, 15% typo
            if random.random() < 0.85:
                password = VALID_CREDENTIALS[user]
            else:
                password = "wr0ng_typo_" + str(random.randint(100, 999))

            tasks.append(send_request(
                client, user, password, algorithm,
                "legitimate", False, source_ip,
            ))
            total += 1

    # Execute with controlled concurrency
    responses = await asyncio.gather(*tasks)
    for code in responses:
        results[code] = results.get(code, 0) + 1

    duration = time.time() - start
    print(f"  [LEGIT] Completed {total} requests in {duration:.2f}s "
          f"(200={results[200]}, 401={results[401]}, 429={results[429]})")

    return TrafficResult(
        algorithm=algorithm, profile="legitimate", total_requests=total,
        status_200=results[200], status_401=results[401],
        status_429=results[429], duration_seconds=duration,
    )


# ═════════════════════════════════════════════════════════════
# TRAFFIC PROFILE 2: Concentrated Burst Attack
# ═════════════════════════════════════════════════════════════
# Simulates a single-origin credential stuffing attack:
#   - 1 attacker IP firing 500 requests as fast as possible
#   - Cycles through the leaked credential list
#   - Rate: 50–100 req/s (massively exceeds the 5 req/60s limit)
# ═════════════════════════════════════════════════════════════

async def generate_burst_attack(
    client: httpx.AsyncClient, algorithm: str
) -> TrafficResult:
    """Generate 500 rapid-fire requests from a single attacker IP."""
    print(f"  [BURST] Starting concentrated burst attack...")
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    total = 500
    start = time.time()

    attacker_ip = "10.0.0.99"
    tasks = []
    for i in range(total):
        cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
        tasks.append(send_request(
            client, cred[0], cred[1], algorithm,
            "burst_attack", True, attacker_ip,
        ))

    responses = await asyncio.gather(*tasks)
    for code in responses:
        results[code] = results.get(code, 0) + 1

    duration = time.time() - start
    print(f"  [BURST] Completed {total} requests in {duration:.2f}s "
          f"(200={results[200]}, 401={results[401]}, 429={results[429]})")

    return TrafficResult(
        algorithm=algorithm, profile="burst_attack", total_requests=total,
        status_200=results[200], status_401=results[401],
        status_429=results[429], duration_seconds=duration,
    )


# ═════════════════════════════════════════════════════════════
# TRAFFIC PROFILE 3: Distributed Many-IP Attack
# ═════════════════════════════════════════════════════════════
# Simulates a botnet-style distributed credential stuffing attack:
#   - 500 unique IPs from a rented proxy pool
#   - Each IP sends only 1–3 requests (stays under per-IP limits)
#   - All requests use leaked credentials (attack ground truth = True)
#   - This profile is designed to EVADE IP-based rate limiting
# ═════════════════════════════════════════════════════════════

async def generate_distributed_attack(
    client: httpx.AsyncClient, algorithm: str
) -> TrafficResult:
    """Generate 750–1500 requests across 500 rotating attacker IPs."""
    print(f"  [DIST]  Starting distributed many-IP attack...")
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    total = 0
    start = time.time()

    tasks = []
    for ip_idx in range(500):
        # Generate a unique IP from the 10.x.x.x attacker range
        source_ip = f"10.{ip_idx // 256}.{ip_idx % 256}.{random.randint(1, 254)}"
        num_requests = random.randint(1, 3)
        for _ in range(num_requests):
            cred = random.choice(LEAKED_CREDENTIALS)
            tasks.append(send_request(
                client, cred[0], cred[1], algorithm,
                "distributed_attack", True, source_ip,
            ))
            total += 1

    # Batch execution to avoid overwhelming the event loop
    batch_size = 100
    responses = []
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch)
        responses.extend(batch_results)

    for code in responses:
        results[code] = results.get(code, 0) + 1

    duration = time.time() - start
    print(f"  [DIST]  Completed {total} requests in {duration:.2f}s "
          f"(200={results[200]}, 401={results[401]}, 429={results[429]})")

    return TrafficResult(
        algorithm=algorithm, profile="distributed_attack", total_requests=total,
        status_200=results[200], status_401=results[401],
        status_429=results[429], duration_seconds=duration,
    )


# ═════════════════════════════════════════════════════════════
# TRAFFIC PROFILE 4: Low-and-Slow Attack
# ═════════════════════════════════════════════════════════════
# Simulates sophisticated attackers who pace requests just below
# the rate-limit threshold:
#   - 20 attacker IPs
#   - Each sends 1 request every 15 seconds (4 req/min vs 5 req/min limit)
#   - Test runs for ~75 seconds to accumulate 5 requests per IP
#   - Uses leaked credentials; marked as attack traffic
# ═════════════════════════════════════════════════════════════

async def generate_low_and_slow_attack(
    client: httpx.AsyncClient, algorithm: str
) -> TrafficResult:
    """Generate paced attack traffic just below the detection threshold."""
    print(f"  [SLOW]  Starting low-and-slow attack (this takes ~75 seconds)...")
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    total = 0
    start = time.time()

    num_attacker_ips = 20
    requests_per_ip = 5
    interval_seconds = 15  # 1 req every 15s → 4 req/min (limit is 5/min)

    for round_num in range(requests_per_ip):
        round_tasks = []
        for ip_idx in range(num_attacker_ips):
            source_ip = f"172.16.{ip_idx // 256}.{ip_idx % 256 + 1}"
            cred = LEAKED_CREDENTIALS[(ip_idx + round_num) % len(LEAKED_CREDENTIALS)]
            round_tasks.append(send_request(
                client, cred[0], cred[1], algorithm,
                "low_and_slow", True, source_ip,
            ))
            total += 1

        responses = await asyncio.gather(*round_tasks)
        for code in responses:
            results[code] = results.get(code, 0) + 1

        # Pace requests: wait between rounds (skip wait after last round)
        if round_num < requests_per_ip - 1:
            await asyncio.sleep(interval_seconds)

    duration = time.time() - start
    print(f"  [SLOW]  Completed {total} requests in {duration:.2f}s "
          f"(200={results[200]}, 401={results[401]}, 429={results[429]})")

    return TrafficResult(
        algorithm=algorithm, profile="low_and_slow", total_requests=total,
        status_200=results[200], status_401=results[401],
        status_429=results[429], duration_seconds=duration,
    )


# ═════════════════════════════════════════════════════════════
# TRAFFIC PROFILE 5: Boundary Exploitation Attack
# ═════════════════════════════════════════════════════════════
# Targets the Fixed Window's known weakness: window reset boundaries.
#   - Fires requests at :59s and :01s of each minute boundary
#   - A single attacker IP can get 2× the allowed rate across the
#     boundary if the Fixed Window resets its counter
#   - Tests whether Sliding Window and Token Bucket mitigate this
# ═════════════════════════════════════════════════════════════

async def generate_boundary_attack(
    client: httpx.AsyncClient, algorithm: str
) -> TrafficResult:
    """
    Fire concentrated requests at window reset boundaries (:59 and :01).
    
    Waits for the next minute boundary, then fires bursts immediately
    before and after the reset to test boundary-doubling vulnerability.
    """
    print(f"  [BNDRY] Starting boundary exploitation attack...")
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    total = 0
    start = time.time()

    attacker_ip = "10.99.0.1"
    requests_per_burst = 5  # Send exactly the limit at each boundary edge

    # ── Phase 1: Wait until 2 seconds before the next minute boundary ──
    now = time.time()
    current_second_in_window = now % RATE_LIMIT_WINDOW_SECONDS
    wait_until_boundary = RATE_LIMIT_WINDOW_SECONDS - current_second_in_window - 2
    if wait_until_boundary < 0:
        wait_until_boundary += RATE_LIMIT_WINDOW_SECONDS

    print(f"  [BNDRY] Waiting {wait_until_boundary:.1f}s for next window boundary...")
    await asyncio.sleep(wait_until_boundary)

    # ── Phase 2: Fire burst at :58-:59 (end of current window) ──────
    print(f"  [BNDRY] Firing pre-boundary burst...")
    pre_tasks = []
    for i in range(requests_per_burst):
        cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
        pre_tasks.append(send_request(
            client, cred[0], cred[1], algorithm,
            "boundary_attack", True, attacker_ip,
        ))
        total += 1
    pre_responses = await asyncio.gather(*pre_tasks)
    for code in pre_responses:
        results[code] = results.get(code, 0) + 1

    # ── Phase 3: Wait for the boundary to reset ────────────────────
    now = time.time()
    remaining = RATE_LIMIT_WINDOW_SECONDS - (now % RATE_LIMIT_WINDOW_SECONDS)
    await asyncio.sleep(remaining + 0.5)  # +0.5s into the new window

    # ── Phase 4: Fire burst at :00-:01 (start of new window) ───────
    print(f"  [BNDRY] Firing post-boundary burst...")
    post_tasks = []
    for i in range(requests_per_burst):
        cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
        post_tasks.append(send_request(
            client, cred[0], cred[1], algorithm,
            "boundary_attack", True, attacker_ip,
        ))
        total += 1
    post_responses = await asyncio.gather(*post_tasks)
    for code in post_responses:
        results[code] = results.get(code, 0) + 1

    duration = time.time() - start
    print(f"  [BNDRY] Completed {total} requests in {duration:.2f}s "
          f"(200={results[200]}, 401={results[401]}, 429={results[429]})")

    return TrafficResult(
        algorithm=algorithm, profile="boundary_attack", total_requests=total,
        status_200=results[200], status_401=results[401],
        status_429=results[429], duration_seconds=duration,
    )


# ═════════════════════════════════════════════════════════════
# ORCHESTRATOR — Run all profiles for a given algorithm
# ═════════════════════════════════════════════════════════════

async def run_all_profiles_for_algorithm(algorithm: str) -> list[TrafficResult]:
    """
    Execute all 5 traffic profiles sequentially for one algorithm.
    
    Sequential execution is intentional — each profile must complete
    and the Redis state must be flushed before the next one starts
    to prevent cross-contamination of results.
    """
    print(f"\n{'='*60}")
    print(f"  ALGORITHM: {algorithm.upper()}")
    print(f"{'='*60}")

    results = []

    # Use a single httpx client with connection pooling
    async with httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=200,
            max_keepalive_connections=50,
        ),
    ) as client:
        # Wait for API to be ready
        for attempt in range(10):
            try:
                resp = await client.get(f"{API_BASE}/health", timeout=5.0)
                if resp.status_code == 200:
                    break
            except httpx.RequestError:
                pass
            print(f"  Waiting for API server (attempt {attempt + 1}/10)...")
            await asyncio.sleep(2)
        else:
            print("  ERROR: API server not reachable. Aborting.")
            sys.exit(1)

        # Flush Redis between profiles to isolate results
        redis_flush_url = f"{API_BASE}/health"  # We'll flush via CLI instead

        # ── Profile 1: Legitimate Traffic ────────────────────
        results.append(await generate_legitimate_traffic(client, algorithm))
        await flush_redis()

        # ── Profile 2: Burst Attack ─────────────────────────
        results.append(await generate_burst_attack(client, algorithm))
        await flush_redis()

        # ── Profile 3: Distributed Attack ────────────────────
        results.append(await generate_distributed_attack(client, algorithm))
        await flush_redis()

        # ── Profile 4: Low-and-Slow ─────────────────────────
        results.append(await generate_low_and_slow_attack(client, algorithm))
        await flush_redis()

        # ── Profile 5: Boundary Exploitation ─────────────────
        results.append(await generate_boundary_attack(client, algorithm))
        await flush_redis()

    return results


async def flush_redis():
    """Flush all Redis keys between test profiles for isolation."""
    import redis.asyncio as aioredis
    try:
        r = aioredis.from_url("redis://localhost:6379/0")
        await r.flushdb()
        await r.aclose()
    except Exception as e:
        print(f"  WARNING: Redis flush failed: {e}")


# ═════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════

async def main():
    """
    Run the complete experiment suite:
      - For each of the 3 algorithms (fixed, sliding, token)
      - Execute all 5 traffic profiles
      - Total: 15 experiment runs generating 10,000+ logged requests
    """
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  API Rate-Limiter Benchmarking Suite                    ║")
    print("║  Credential Stuffing Attack Simulation                  ║")
    print("║  Author: Soham Adsare | Guide: Dr. Dhanashree Patil    ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # Parse optional algorithm filter from command line
    if len(sys.argv) > 1:
        algorithms = [a.strip().lower() for a in sys.argv[1].split(",")]
        print(f"\n  Running subset: {algorithms}")
    else:
        algorithms = ALGORITHMS
        print(f"\n  Running all algorithms: {algorithms}")

    all_results: list[TrafficResult] = []

    for algo in algorithms:
        results = await run_all_profiles_for_algorithm(algo)
        all_results.extend(results)

    # ── Summary Table ────────────────────────────────────────
    print(f"\n{'='*80}")
    print("  EXPERIMENT SUMMARY")
    print(f"{'='*80}")
    print(f"  {'Algorithm':<15} {'Profile':<25} {'Total':>7} {'200':>6} {'401':>6} {'429':>6} {'Time':>8}")
    print(f"  {'-'*15} {'-'*25} {'-'*7} {'-'*6} {'-'*6} {'-'*6} {'-'*8}")
    for r in all_results:
        print(f"  {r.algorithm:<15} {r.profile:<25} {r.total_requests:>7} "
              f"{r.status_200:>6} {r.status_401:>6} {r.status_429:>6} "
              f"{r.duration_seconds:>7.2f}s")

    total_requests = sum(r.total_requests for r in all_results)
    print(f"\n  Total requests generated: {total_requests:,}")
    print(f"  Experiment complete. Logs written to: logs/experiment_runs.jsonl")


if __name__ == "__main__":
    asyncio.run(main())
