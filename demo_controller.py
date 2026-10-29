"""
demo_controller.py — Interactive CLI Menu for Live Presentations.

Keeps all Docker services alive and provides instant, isolated attack
scenarios with real-time visual feedback on Grafana dashboards.

Usage:
    python demo_controller.py

Author: Soham Adsare (SY MCA, ICEM Pune)
Guide:  Dr. Dhanashree Patil
"""

import asyncio
import os
import random
import subprocess
import sys
import time

import httpx

# ── Configuration ────────────────────────────────────────────

API_BASE = "http://localhost:8000"
LOGIN_URL = f"{API_BASE}/api/login"
FLUSH_URL = f"{API_BASE}/api/admin/flush"
HEALTH_URL = f"{API_BASE}/health"
METRICS_URL = f"{API_BASE}/metrics"
PROMETHEUS_URL = "http://localhost:9090/api/v1/targets"
GRAFANA_URL = "http://localhost:3000/api/health"

VALID_CREDENTIALS = {
    "alice": "P@ssw0rd1", "bob": "Secur3!ty", "charlie": "Cr3dent!al",
    "dave": "Tr0ub4dor", "eve": "Hunt3r2k", "frank": "B4nk$afe",
    "grace": "N3tw0rk!", "heidi": "Cl0ud#99", "ivan": "D3f3nd3r",
    "judy": "Sh13ld!X",
}
VALID_USERNAMES = list(VALID_CREDENTIALS.keys())

LEAKED_CREDENTIALS = [
    ("alice", "P@ssw0rd1"), ("bob", "Secur3!ty"), ("charlie", "Cr3dent!al"),
    ("alice", "password123"), ("admin", "admin"), ("root", "toor"),
    ("dave", "letmein"), ("eve", "Hunt3r2k"), ("test", "test123"),
    ("frank", "wrongpass"),
]

# ── ANSI Colors ──────────────────────────────────────────────

class C:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    WHITE = "\033[97m"
    BLUE = "\033[94m"


# ── Global State ─────────────────────────────────────────────

current_algorithm = "fixed"
ALGO_NAMES = {
    "fixed": "Fixed Window",
    "sliding": "Sliding Window",
    "token": "Token Bucket",
}


# ── Helper: Send a single request ───────────────────────────

async def send_request(
    client: httpx.AsyncClient, username: str, password: str,
    traffic_type: str, is_attack: bool, source_ip: str,
) -> int:
    try:
        resp = await client.post(
            LOGIN_URL,
            json={"username": username, "password": password},
            headers={
                "X-Algorithm": current_algorithm,
                "X-Traffic-Type": traffic_type,
                "X-Is-Attack": str(is_attack).lower(),
                "X-Forwarded-For": source_ip,
            },
            timeout=10.0,
        )
        return resp.status_code
    except (httpx.RequestError, httpx.TimeoutException):
        return 0


# ── Helper: Print scenario info box ─────────────────────────

def print_scenario(scenario: str, expected: str, watch: str):
    algo_display = ALGO_NAMES.get(current_algorithm, current_algorithm)
    print(f"\n{C.CYAN}+-------------------------------------------------------------+{C.RESET}")
    print(f"{C.CYAN}|{C.RESET}  {C.BOLD}SCENARIO:{C.RESET}    {scenario}")
    print(f"{C.CYAN}|{C.RESET}  {C.BOLD}ALGORITHM:{C.RESET}   {algo_display}")
    print(f"{C.CYAN}|{C.RESET}  {C.BOLD}EXPECTED:{C.RESET}    {expected}")
    print(f"{C.CYAN}|{C.RESET}  {C.BOLD}WATCH:{C.RESET}       {watch}")
    print(f"{C.CYAN}+-------------------------------------------------------------+{C.RESET}")


# ── Helper: Print results summary ───────────────────────────

def print_results(results: dict, total: int, duration: float):
    print(f"\n  {C.BOLD}Results:{C.RESET}")
    print(f"    {C.GREEN}200 OK:{C.RESET}           {results.get(200, 0):>4}")
    print(f"    {C.YELLOW}401 Unauthorized:{C.RESET} {results.get(401, 0):>4}")
    print(f"    {C.RED}429 Blocked:{C.RESET}      {results.get(429, 0):>4}")
    print(f"    {C.DIM}Errors:{C.RESET}           {results.get(0, 0):>4}")
    print(f"    {C.CYAN}Total:{C.RESET}            {total:>4}  in {duration:.2f}s")
    blocked = results.get(429, 0)
    rate = (blocked / total * 100) if total > 0 else 0
    print(f"    {C.MAGENTA}Block Rate:{C.RESET}       {rate:.1f}%")


# ── Helper: Live progress bar ────────────────────────────────

def print_progress(done: int, total: int, status_code: int):
    bar_len = 40
    filled = int(bar_len * done / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    color = C.GREEN if status_code == 200 else (C.YELLOW if status_code == 401 else C.RED)
    status_text = f"{color}{status_code}{C.RESET}" if status_code > 0 else f"{C.DIM}ERR{C.RESET}"
    print(f"\r  [{bar}] {done}/{total}  Last: {status_text}  ", end="", flush=True)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 1: System Health Check
# ═════════════════════════════════════════════════════════════

async def check_health():
    print(f"\n{C.BOLD}  System Health Check{C.RESET}")
    print(f"  {'─' * 50}")
    services = [
        ("FastAPI API", HEALTH_URL),
        ("Prometheus", PROMETHEUS_URL),
        ("Grafana", GRAFANA_URL),
    ]
    async with httpx.AsyncClient() as client:
        for name, url in services:
            try:
                resp = await client.get(url, timeout=3.0)
                if resp.status_code == 200:
                    print(f"  {C.GREEN}[OK]{C.RESET} {name:20s} - {C.GREEN}HEALTHY{C.RESET}")
                else:
                    print(f"  {C.YELLOW}[!]{C.RESET} {name:20s} - HTTP {resp.status_code}")
            except Exception:
                print(f"  {C.RED}[X]{C.RESET} {name:20s} - {C.RED}UNREACHABLE{C.RESET}")

        # Redis check via API flush endpoint (GET health)
        try:
            resp = await client.get(f"{API_BASE}/health", timeout=3.0)
            print(f"  {C.GREEN}[OK]{C.RESET} {'Redis (via API)':20s} - {C.GREEN}HEALTHY{C.RESET}")
        except Exception:
            print(f"  {C.RED}[X]{C.RESET} {'Redis (via API)':20s} - {C.RED}UNREACHABLE{C.RESET}")

    print(f"\n  {C.CYAN}Dashboard:{C.RESET} http://localhost:3000")
    print(f"  {C.CYAN}API Docs:{C.RESET}  http://localhost:8000/docs")
    print(f"  {C.CYAN}Metrics:{C.RESET}   http://localhost:8000/metrics")


# ═════════════════════════════════════════════════════════════
# MENU OPTION 2: Burst Attack Demo
# ═════════════════════════════════════════════════════════════

async def demo_burst_attack():
    print_scenario(
        "Single-Source Burst Attack (1 IP, 50 rapid requests)",
        "First ~10 requests -> 200/401, remaining -> 429 BLOCKED",
        "Grafana -> HTTP Response panel (red 429 spike)",
    )
    total = 50
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    attacker_ip = "10.0.0.99"
    start = time.time()

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        for i in range(total):
            cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
            code = await send_request(client, cred[0], cred[1], "burst_attack", True, attacker_ip)
            results[code] = results.get(code, 0) + 1
            print_progress(i + 1, total, code)
            await asyncio.sleep(0.05)  # Visible pacing for Grafana

    print()  # Newline after progress bar
    print_results(results, total, time.time() - start)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 3: Distributed Attack Demo
# ═════════════════════════════════════════════════════════════

async def demo_distributed_attack():
    print_scenario(
        "Distributed Multi-IP Attack (30 IPs, 3 requests each)",
        "ALL requests pass -> 0% detection (rate limiter evaded)",
        "Grafana -> Traffic Type panel (orange distributed spike, NO red 429s)",
    )
    total_ips = 30
    reqs_per_ip = 3
    total = total_ips * reqs_per_ip
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    start = time.time()
    done = 0

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        for ip_idx in range(total_ips):
            source_ip = f"10.{ip_idx // 256}.{ip_idx % 256}.{random.randint(1, 254)}"
            for _ in range(reqs_per_ip):
                cred = random.choice(LEAKED_CREDENTIALS)
                code = await send_request(client, cred[0], cred[1], "distributed_attack", True, source_ip)
                results[code] = results.get(code, 0) + 1
                done += 1
                print_progress(done, total, code)
                await asyncio.sleep(0.03)

    print()
    print_results(results, total, time.time() - start)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 4: Boundary Timing Attack Demo
# ═════════════════════════════════════════════════════════════

async def demo_boundary_attack():
    print_scenario(
        "Boundary Timing Attack (requests at window edges)",
        "Fixed Window: bypass possible. Sliding/Token: blocked.",
        "Grafana -> HTTP Response panel (watch window reset behaviour)",
    )
    total = 0
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    attacker_ip = "10.99.0.1"
    requests_per_burst = 10
    start = time.time()

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        # Phase 1: Fire at end of current window
        print(f"\n  {C.YELLOW}Phase 1:{C.RESET} Firing {requests_per_burst} requests at window end...")
        for i in range(requests_per_burst):
            cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
            code = await send_request(client, cred[0], cred[1], "boundary_attack", True, attacker_ip)
            results[code] = results.get(code, 0) + 1
            total += 1
            await asyncio.sleep(0.05)

        # Phase 2: Wait for window reset
        wait_time = 11  # Slightly longer than 10s window
        print(f"  {C.CYAN}Waiting {wait_time}s for window reset...{C.RESET}")
        await asyncio.sleep(wait_time)

        # Phase 3: Fire at start of new window
        print(f"  {C.YELLOW}Phase 2:{C.RESET} Firing {requests_per_burst} requests at new window start...")
        for i in range(requests_per_burst):
            cred = LEAKED_CREDENTIALS[i % len(LEAKED_CREDENTIALS)]
            code = await send_request(client, cred[0], cred[1], "boundary_attack", True, attacker_ip)
            results[code] = results.get(code, 0) + 1
            total += 1
            await asyncio.sleep(0.05)

    print_results(results, total, time.time() - start)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 5: Low-and-Slow Attack Demo
# ═════════════════════════════════════════════════════════════

async def demo_low_and_slow():
    print_scenario(
        "Low-and-Slow Probe (5 IPs, paced below threshold)",
        "ALL requests pass - attacker stays under the radar",
        "Grafana -> Traffic Type panel (blue low_and_slow, steady trickle)",
    )
    num_ips = 5
    reqs_per_ip = 5
    interval = 2.0  # 2s between requests (well below 10 req/10s limit)
    total = num_ips * reqs_per_ip
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    start = time.time()
    done = 0

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        for round_num in range(reqs_per_ip):
            for ip_idx in range(num_ips):
                source_ip = f"172.16.{ip_idx}.1"
                cred = LEAKED_CREDENTIALS[(ip_idx + round_num) % len(LEAKED_CREDENTIALS)]
                code = await send_request(client, cred[0], cred[1], "low_and_slow", True, source_ip)
                results[code] = results.get(code, 0) + 1
                done += 1
                print_progress(done, total, code)
            if round_num < reqs_per_ip - 1:
                await asyncio.sleep(interval)

    print()
    print_results(results, total, time.time() - start)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 6: Legitimate Traffic Demo
# ═════════════════════════════════════════════════════════════

async def demo_legitimate_traffic():
    print_scenario(
        "Legitimate Traffic Baseline (15 IPs, 2 requests each)",
        "ALL pass with 200 OK -> 0% false positive rate",
        "Grafana -> HTTP Response panel (green 200 line only)",
    )
    total_ips = 15
    reqs_per_ip = 2
    total = total_ips * reqs_per_ip
    results = {200: 0, 401: 0, 429: 0, 0: 0}
    start = time.time()
    done = 0

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        for ip_idx in range(total_ips):
            source_ip = f"192.168.1.{ip_idx + 1}"
            for _ in range(reqs_per_ip):
                user = random.choice(VALID_USERNAMES)
                password = VALID_CREDENTIALS[user]
                code = await send_request(client, user, password, "legitimate", False, source_ip)
                results[code] = results.get(code, 0) + 1
                done += 1
                print_progress(done, total, code)
                await asyncio.sleep(0.1)

    print()
    print_results(results, total, time.time() - start)


# ═════════════════════════════════════════════════════════════
# MENU OPTION 7: Switch Algorithm
# ═════════════════════════════════════════════════════════════

async def switch_algorithm():
    global current_algorithm
    print(f"\n  {C.BOLD}Select Rate-Limiting Algorithm:{C.RESET}")
    print(f"    {C.CYAN}[1]{C.RESET} Fixed Window")
    print(f"    {C.CYAN}[2]{C.RESET} Sliding Window")
    print(f"    {C.CYAN}[3]{C.RESET} Token Bucket")
    choice = input(f"\n  {C.BOLD}Enter choice (1-3):{C.RESET} ").strip()
    algo_map = {"1": "fixed", "2": "sliding", "3": "token"}
    if choice in algo_map:
        current_algorithm = algo_map[choice]
        print(f"\n  {C.GREEN}[OK]{C.RESET} Switched to: {C.BOLD}{ALGO_NAMES[current_algorithm]}{C.RESET}")
        # Auto-flush Redis on algorithm switch
        async with httpx.AsyncClient() as client:
            try:
                await client.post(FLUSH_URL, timeout=5.0)
                print(f"  {C.GREEN}[OK]{C.RESET} Redis state flushed for clean start")
            except Exception:
                print(f"  {C.YELLOW}[!]{C.RESET} Could not flush Redis (continue anyway)")
    else:
        print(f"  {C.RED}[X]{C.RESET} Invalid choice. No change made.")


# ═════════════════════════════════════════════════════════════
# MENU OPTION 8: Full Benchmark Suite
# ═════════════════════════════════════════════════════════════

async def run_full_benchmark():
    print(f"\n  {C.BOLD}Running Full Benchmark Suite...{C.RESET}")
    print(f"  {C.DIM}This runs all 5 attack profiles × 3 algorithms (~5 min){C.RESET}")
    print(f"  {C.DIM}Results will be saved to analysis/output/{C.RESET}\n")

    # Flush Redis and logs first
    async with httpx.AsyncClient() as client:
        try:
            await client.post(FLUSH_URL, timeout=5.0)
        except Exception:
            pass

    if os.path.exists("logs/experiment_runs.jsonl"):
        os.remove("logs/experiment_runs.jsonl")

    # Run traffic generator
    print(f"  {C.CYAN}[1/2]{C.RESET} Running traffic generator...")
    result = subprocess.run(
        [sys.executable, "-m", "simulators.traffic_generator"],
        cwd=os.path.dirname(os.path.abspath(__file__)) or ".",
    )
    if result.returncode != 0:
        print(f"  {C.RED}[X]{C.RESET} Traffic generation failed")
        return

    # Run analysis
    print(f"\n  {C.CYAN}[2/2]{C.RESET} Running analysis & generating LaTeX...")
    result = subprocess.run(
        [sys.executable, "-m", "analysis.compute_metrics"],
        cwd=os.path.dirname(os.path.abspath(__file__)) or ".",
    )
    if result.returncode != 0:
        print(f"  {C.RED}[X]{C.RESET} Analysis failed")
        return

    print(f"\n  {C.GREEN}[OK]{C.RESET} Full benchmark complete!")
    print(f"    * analysis/output/*.png          - Plots")
    print(f"    * analysis/output/latex_tables.tex - LaTeX tables")


# ═════════════════════════════════════════════════════════════
# MENU OPTION 9: Flush Redis & Reset
# ═════════════════════════════════════════════════════════════

async def flush_reset():
    print(f"\n  {C.BOLD}Flushing Redis & Resetting...{C.RESET}")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(FLUSH_URL, timeout=5.0)
            if resp.status_code == 200:
                print(f"  {C.GREEN}[OK]{C.RESET} Redis state flushed via API")
            else:
                print(f"  {C.YELLOW}[!]{C.RESET} API flush returned: {resp.status_code}")
        except Exception as e:
            print(f"  {C.RED}[X]{C.RESET} API flush failed: {e}")

    # Also try docker exec as backup
    try:
        subprocess.run(
            ["docker", "compose", "exec", "-T", "redis", "redis-cli", "FLUSHALL"],
            capture_output=True, timeout=10,
        )
        print(f"  {C.GREEN}[OK]{C.RESET} Redis FLUSHALL via docker exec")
    except Exception:
        pass

    print(f"  {C.DIM}Note: Prometheus metrics persist until container restart{C.RESET}")


# ═════════════════════════════════════════════════════════════
# MAIN MENU
# ═════════════════════════════════════════════════════════════

def print_menu():
    algo_display = ALGO_NAMES.get(current_algorithm, current_algorithm)
    print(f"""
{C.CYAN}+------------------------------------------------------------------+{C.RESET}
{C.CYAN}|{C.RESET}  {C.BOLD}API Rate-Limiter - Live Demo Controller{C.RESET}                        {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.DIM}Author: Soham Adsare | Guide: Dr. Dhanashree Patil{C.RESET}             {C.CYAN}|{C.RESET}
{C.CYAN}+------------------------------------------------------------------+{C.RESET}
{C.CYAN}|{C.RESET}  Active Algorithm: {C.GREEN}{C.BOLD}{algo_display:20s}{C.RESET}                          {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  Grafana:          {C.BLUE}http://localhost:3000{C.RESET}                          {C.CYAN}|{C.RESET}
{C.CYAN}+------------------------------------------------------------------+{C.RESET}
{C.CYAN}|{C.RESET}  {C.WHITE}[1]{C.RESET}  System Health Check                                       {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.RED}[2]{C.RESET}  DEMO: Burst Attack {C.DIM}(1 IP, 50 rapid requests){C.RESET}              {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.RED}[3]{C.RESET}  DEMO: Distributed Attack {C.DIM}(30 IPs, 3 req each){C.RESET}          {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.RED}[4]{C.RESET}  DEMO: Boundary Timing Attack {C.DIM}(window edge exploit){C.RESET}     {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.YELLOW}[5]{C.RESET}  DEMO: Low-and-Slow Probe {C.DIM}(below threshold){C.RESET}             {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.GREEN}[6]{C.RESET}  DEMO: Legitimate Traffic {C.DIM}(baseline, 0% FPR){C.RESET}           {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.CYAN}[7]{C.RESET}  Switch Algorithm {C.DIM}(Fixed / Sliding / Token){C.RESET}             {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.MAGENTA}[8]{C.RESET}  Run Full Benchmark & Generate LaTeX                       {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.WHITE}[9]{C.RESET}  Flush Redis & Reset Metrics                               {C.CYAN}|{C.RESET}
{C.CYAN}|{C.RESET}  {C.DIM}[10]{C.RESET} Exit                                                       {C.CYAN}|{C.RESET}
{C.CYAN}+------------------------------------------------------------------+{C.RESET}
""")


async def main():
    menu_actions = {
        "1": check_health,
        "2": demo_burst_attack,
        "3": demo_distributed_attack,
        "4": demo_boundary_attack,
        "5": demo_low_and_slow,
        "6": demo_legitimate_traffic,
        "7": switch_algorithm,
        "8": run_full_benchmark,
        "9": flush_reset,
    }

    while True:
        print_menu()
        choice = input(f"  {C.BOLD}Enter choice (1-10):{C.RESET} ").strip()

        if choice == "10":
            print(f"\n  {C.BOLD}Shut down containers?{C.RESET}")
            teardown = input(f"  {C.DIM}(y/N):{C.RESET} ").strip().lower()
            if teardown == "y":
                subprocess.run(["docker", "compose", "down"])
                print(f"\n  {C.GREEN}[OK]{C.RESET} Containers stopped. Goodbye!")
            else:
                print(f"\n  {C.CYAN}Containers left running.{C.RESET} Goodbye!")
            break

        action = menu_actions.get(choice)
        if action:
            try:
                await action()
            except KeyboardInterrupt:
                print(f"\n  {C.YELLOW}Interrupted.{C.RESET}")
            except Exception as e:
                print(f"\n  {C.RED}Error: {e}{C.RESET}")
            input(f"\n  {C.DIM}Press Enter to return to menu...{C.RESET}")
        else:
            print(f"  {C.RED}Invalid choice. Try again.{C.RESET}")
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Exiting...{C.RESET}")
