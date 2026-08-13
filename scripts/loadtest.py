#!/usr/bin/env python3
"""Load test: 100 paid requests inside 60 seconds, measured against `prd.md` §8.

Measures rather than asserts. Latency targets are reported and marked when missed, never gated
on — `plan.md` A8 is explicit that missing one is a tuning problem, not a broken MVP. The single
hard assertion is that spend never exceeds the root cap, because caps are the whole product.

    python3 scripts/loadtest.py

Needs the stack up (./scripts/dev.sh), the gateway, and the mock upstream.

**The gateway's percentiles are cumulative over its lifetime.** `/v1/stats` parses the same
Prometheus histograms `/metrics` exports (NOTES.md D19) and those accumulate from process start,
so a gateway that has already served other traffic reports that traffic here too. Restart it
before a run whose numbers you intend to quote.
"""

import os
import secrets
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import httpx
from eth_account import Account

from tollgate import GatewayError, Session

GATEWAY = os.environ.get("TOLLGATE_GATEWAY", "http://localhost:8080")
PROVIDER = os.environ.get("LOADTEST_PROVIDER", "mock-ok")
REQUESTS = int(os.environ.get("LOADTEST_REQUESTS", "100"))
WORKERS = int(os.environ.get("LOADTEST_WORKERS", "5"))
PER_REQUEST = "0.005"

# `prd.md` §8. Seconds, except the last two.
TARGETS = [
    ("gateway added latency p50", 0.015, "s"),
    ("gateway added latency p99", 0.050, "s"),
    ("end-to-end p50 (incl. upstream)", 0.150, "s"),
    ("100 requests wall clock", 60.0, "s"),
]


def preflight() -> Decimal:
    for url, hint in [
        (f"{GATEWAY}/health", "cargo run -p tollgate-gateway"),
        (f"{GATEWAY}/v1/providers/{PROVIDER}", "./scripts/seed_providers.sh"),
    ]:
        try:
            httpx.get(url, timeout=5).raise_for_status()
        except (httpx.HTTPError, httpx.HTTPStatusError):
            sys.exit(f"{url} is not answering — run: {hint}")
    price_wei = httpx.get(f"{GATEWAY}/v1/providers/{PROVIDER}", timeout=5).json()["price_wei"]
    return Decimal(price_wei) / Decimal(10**6)


def delegate(price: Decimal):
    """One root sized to exactly REQUESTS charges, and one capability per parallel worker.

    Every worker's cap equals the root's, so the root is the only binding limit and the run is
    a direct test of one shared pool under concurrency.
    """
    root_cap = price * REQUESTS
    supervisor_key = "0x" + secrets.token_bytes(32).hex()
    supervisor = Session(signer=supervisor_key, gateway=GATEWAY)
    root = supervisor.delegate(
        subject=supervisor.address, max_total=f"{root_cap:f}", max_per_request=PER_REQUEST,
        allowlist=[PROVIDER], expiry_seconds=3600, max_depth=3,
    )
    team = Session(signer=supervisor_key, capability=root, gateway=GATEWAY)

    sessions = []
    for _ in range(WORKERS):
        key = "0x" + secrets.token_bytes(32).hex()
        chain = team.delegate(
            subject=Account.from_key(key).address, max_total=f"{root_cap:f}",
            max_per_request=PER_REQUEST, allowlist=[PROVIDER], expiry_seconds=1800, max_depth=2,
        )
        sessions.append(Session(signer=key, capability=chain, gateway=GATEWAY))
    return team, root_cap, sessions


def run_worker(session, count):
    """`count` sequential paid calls on one session. Sessions are not shared across threads."""
    latencies, failures = [], []
    for _ in range(count):
        started = time.perf_counter()
        try:
            session.get(f"{GATEWAY}/v1/proxy/{PROVIDER}/ok")
            latencies.append(time.perf_counter() - started)
        except GatewayError as refusal:
            failures.append(refusal.code or type(refusal).__name__)
        except Exception as error:  # noqa: BLE001 — a transport failure is a result, not a crash
            failures.append(type(error).__name__)
    return latencies, failures


def drain_settled(team, expected, deadline=15.0):
    """Wait for the reservation drain to land every charge, then return the signed report.

    The drain is asynchronous by design (`architecture.md` §9.3), so a report read the instant
    the last response arrives can legitimately be short a few rows.
    """
    until = time.monotonic() + deadline
    report = team.expense_report()
    while len(report["charges"]) < expected and time.monotonic() < until:
        time.sleep(0.5)
        report = team.expense_report()
    return report


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(int(fraction * len(ordered)), len(ordered) - 1)]


def stage_mean(stage):
    """Mean of a stage from the exported histogram's own sum and count.

    Worth printing beside the percentiles because the bucket layout (Task 2.5) jumps straight
    from 0.01 to 0.05, and this system's gateway latency sits inside that gap. When every sample
    lands in one bucket, an interpolated p50 is the bucket's midpoint rather than a measurement,
    and the mean is the only figure in `/metrics` carrying real resolution.
    """
    totals = {}
    for line in httpx.get(f"{GATEWAY}/metrics", timeout=10).text.splitlines():
        for suffix in ("sum", "count"):
            if line.startswith(f"tollgate_stage_seconds_{suffix}{{stage=\"{stage}\"}}"):
                totals[suffix] = float(line.rsplit(" ", 1)[1])
    if totals.get("count"):
        return totals["sum"] / totals["count"], int(totals["count"])
    return None, 0


def main() -> int:
    price = preflight()
    team, root_cap, sessions = delegate(price)
    share, extra = divmod(REQUESTS, WORKERS)

    print(f"{REQUESTS} paid requests, {WORKERS} parallel workers, {price} USDC each, "
          f"root cap {root_cap} USDC")
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(
            lambda i: run_worker(sessions[i], share + (1 if i < extra else 0)), range(WORKERS)
        ))
    elapsed = time.perf_counter() - started

    latencies = [value for batch, _ in results for value in batch]
    failures = [reason for _, batch in results for reason in batch]
    report = drain_settled(team, len(latencies))
    stats = httpx.get(f"{GATEWAY}/v1/stats", timeout=10).json()

    by_status = {}
    for charge in report["charges"]:
        by_status[charge["status"]] = by_status.get(charge["status"], 0) + 1

    print(f"\n{len(latencies)}/{REQUESTS} paid in {elapsed:.1f}s "
          f"({len(latencies) / elapsed:.1f}/s)")
    print(f"ledger    {by_status} across {len(report['charges'])} charges, "
          f"{report['failed_count']} failed")
    print(f"settled   {by_status.get('settled', 0)} "
          f"(0 is expected until Task 6.6 deploys to Base Sepolia)")
    if failures:
        counts = {reason: failures.count(reason) for reason in sorted(set(failures))}
        print(f"errors    {counts}")
    else:
        print("errors    none")

    measured = [
        stats["gateway_p50"], stats["gateway_p99"],
        percentile(latencies, 0.50), elapsed,
    ]
    print(f"\n{'metric':34s} {'target':>10s} {'measured':>10s}  verdict")
    missed = 0
    for (label, target, unit), value in zip(TARGETS, measured):
        if value is None:
            print(f"{label:34s} {target:>9.3f}{unit} {'—':>10s}  not observed")
            continue
        ok = value <= target
        missed += 0 if ok else 1
        print(f"{label:34s} {target:>9.3f}{unit} {value:>9.3f}{unit}  "
              f"{'PASS' if ok else 'MISSED'}")
    upstream = stats["upstream_p50"]
    if upstream is not None:
        print(f"{'upstream p50 (not ours)':34s} {'—':>10s} {upstream:>9.3f}s")

    mean, observed = stage_mean("gateway")
    if mean is not None:
        print(f"\ngateway mean {mean * 1000:.1f} ms over {observed} requests. The p50 and p99 "
              f"above are\ninterpolated from buckets that jump 0.01 -> 0.05, so read the mean "
              f"as the real figure.")

    # The one hard assertion. `total_spent` is the ledger's own figure: Postgres rather than the
    # Redis counters, excluding `voided` and including `failed` (NOTES.md D8, D16) — which is
    # exactly "settled + queued + reserved" plus the charges whose settlement later reverted.
    spent = Decimal(report["total_spent"])
    if spent > root_cap:
        print(f"\nOVERSPEND: ledger records {spent} USDC against a root cap of {root_cap}")
        return 1
    print(f"\nno overspend: {spent} USDC spent against a root cap of {root_cap} USDC")
    if missed:
        print(f"{missed} latency target(s) missed — recorded, not fatal (plan.md A8)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
