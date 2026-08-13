#!/usr/bin/env python3
"""The supervisor half of the `prd.md` §9 demo: three delegations, then the expense report.

Run through `run_demo.sh`. `setup` signs the delegations, `report` prints the signed report.

**Resolution A funding is a documented prerequisite, not something this script does.** Under
`architecture.md` §5.3 the parent funds each child wallet with USDC up front and the chain is
then pure policy over money the child already holds. Worker wallets need that USDC only for
*settlement*, deferred with Task 6.6 — the gateway verifies signatures and caps and never reads
a balance, so every step of the demo short of an on-chain settle runs unfunded.
"""

import json
import os
import pathlib
import secrets
import sys
from decimal import Decimal

from eth_account import Account

from tollgate import Session

GATEWAY = os.environ.get("TOLLGATE_GATEWAY", "http://localhost:8080")
HANDOFF = pathlib.Path(os.environ.get("TOLLGATE_DEMO_HANDOFF", "/tmp/tollgate-demo.json"))

PER_REQUEST = "0.005"  # the price is 0.001, so no single call ever trips this
ROOT_TOTAL = "0.100"   # deliberately ample: the demo is about a *worker* capping, not the root
ALLOWLIST = ["mock-ok"]

# name, its own total cap, how many calls it will attempt.
# worker-2's cap covers exactly two of its six calls, so it runs out partway through and stops
# while its siblings keep going. That is `prd.md` §9 step 3, the moment worth showing.
WORKERS = [("worker-1", "0.010", 6), ("worker-2", "0.002", 6), ("worker-3", "0.010", 6)]


def setup():
    supervisor_key = "0x" + secrets.token_bytes(32).hex()
    # Two levels, three workers (`prd.md` §8). The root's subject is the supervisor itself, so
    # the worker links hang off one shared pool and every charge draws the root down too.
    supervisor = Session(signer=supervisor_key, gateway=GATEWAY)
    root = supervisor.delegate(
        subject=supervisor.address, max_total=ROOT_TOTAL, max_per_request=PER_REQUEST,
        allowlist=ALLOWLIST, expiry_seconds=3600, max_depth=3,
    )

    team = Session(signer=supervisor_key, capability=root, gateway=GATEWAY)
    workers = []
    for name, max_total, calls in WORKERS:
        key = "0x" + secrets.token_bytes(32).hex()
        address = Account.from_key(key).address
        # One local signature each. No server round-trip, which is the feature.
        chain = team.delegate(
            subject=address, max_total=max_total, max_per_request=PER_REQUEST,
            allowlist=ALLOWLIST, expiry_seconds=1800, max_depth=2,
        )
        workers.append({
            "name": name, "key": key, "address": address, "max_total": max_total,
            "calls": calls, "capability": str(chain),
        })
        print(f"delegated {name:9s} {address}  cap {max_total} USDC  allowlist {ALLOWLIST}")

    HANDOFF.write_text(json.dumps({
        "supervisor_key": supervisor_key, "capability": str(root),
        "root_hash": root.root_hash(), "workers": workers,
    }))
    print(f"\nroot capability {root.root_hash()}")
    print(f"delegation tree http://localhost:3000/agent?capability={root.root_hash()}")


def report():
    state = json.loads(HANDOFF.read_text())
    supervisor = Session(
        signer=state["supervisor_key"], capability=state["capability"], gateway=GATEWAY
    )
    data = supervisor.expense_report()
    print(json.dumps(data, indent=2))

    # Per-endpoint totals, summed from the signed charge list rather than served alongside it:
    # each charge names its provider and the signature covers them, so this is checkable.
    totals = {}
    for charge in data["charges"]:
        entry = totals.setdefault(charge["provider"], [0, Decimal(0)])
        entry[0] += 1
        entry[1] += Decimal(charge["amount"])
    print("\nper-endpoint totals")
    for provider, (calls, spent) in sorted(totals.items()):
        print(f"  {provider:12s} {calls:2d} calls  {spent} USDC")


if __name__ == "__main__":
    MODE = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if MODE not in ("setup", "report"):
        sys.exit(f"usage: {sys.argv[0]} [setup|report]")
    (setup if MODE == "setup" else report)()
