#!/usr/bin/env python3
"""One worker agent: call the paid endpoint until the budget says stop, then show the receipts.

    worker.py worker-2

Reads its key and its capability chain from the handoff file the supervisor wrote. The three
workers run concurrently under `run_demo.sh`, which is the point — worker-2 hits its own cap and
stops while workers 1 and 3 carry on.
"""

import json
import os
import pathlib
import sys

from tollgate import CapExceeded, InsufficientBudget, Session

GATEWAY = os.environ.get("TOLLGATE_GATEWAY", "http://localhost:8080")
HANDOFF = pathlib.Path(os.environ.get("TOLLGATE_DEMO_HANDOFF", "/tmp/tollgate-demo.json"))
PROVIDER = "mock-ok"


def main() -> None:
    name = sys.argv[1]
    state = json.loads(HANDOFF.read_text())
    me = next(w for w in state["workers"] if w["name"] == name)

    session = Session(signer=me["key"], capability=me["capability"], gateway=GATEWAY)
    done = 0
    for attempt in range(1, me["calls"] + 1):
        try:
            response = session.get(f"{GATEWAY}/v1/proxy/{PROVIDER}/ok")
        # Two different refusals, and the difference matters. An exhausted *total* cap is a 402
        # `insufficient_funds` and means stop; a *per-request* cap violation is a 429 and means
        # this call was too big. NOTES.md D11 records the same split on the gateway side.
        except InsufficientBudget as refusal:
            print(f"{name}: capped after {done} calls — budget exhausted at chain level "
                  f"{refusal.tripped_level} ({refusal.capability_hash})")
            break
        except CapExceeded as refusal:
            print(f"{name}: call {attempt} too large for the per-request cap at level "
                  f"{refusal.tripped_level} (limit {refusal.limit})")
            break
        done += 1
        print(f"{name}: call {attempt} -> {response.status_code} {response.json()}")

    print(f"{name}: {done}/{me['calls']} calls paid, {len(session.receipts())} receipts")
    for receipt in session.receipts():
        print(f"{name}:   receipt {receipt['nonce'][:18]}… {receipt['signature'][:18]}…")


if __name__ == "__main__":
    main()
