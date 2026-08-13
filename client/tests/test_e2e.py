"""The `architecture.md` §7.3 code sample, run end to end.

That sample is the promise the client makes: a supervisor delegates with one local signature,
a worker pays a 402 transparently, and both a receipt and a rolled-up expense report come
back. This runs it and prints what it prints.

**Two substitutions, and why each is forced.** The sample is written against a deployment
that does not exist, so it cannot run character-for-character:

1. `https://gw.tollgate.dev` → `http://localhost:8080`. There is no deployed Tollgate; the
   README records this as mocked. The supervisor's `Session` is *not* modified to carry the
   URL — `TOLLGATE_GATEWAY` is set in the environment instead — so the sample's own two
   `Session(...)` constructions are unchanged.
2. `/v1/proxy/geocode/lookup` → `/v1/proxy/geocode/echo`. `examples/mock_upstream.py` serves
   `/ok`, `/slow`, `/fail` and `/echo`, and 404s anything else. `geocode` and `weather` are
   registered here as real providers pointing at that upstream, so the sample's
   `allowlist=["geocode", "weather"]` is genuinely enforced rather than sidestepped — a
   request outside it is refused, which `test_capability.py` asserts separately.

Everything else — every method call, every argument, the order of operations — is the sample
verbatim. Needs the stack from `test_session.py`'s docstring.
"""

from __future__ import annotations

import os
import secrets

import httpx
import pytest
from eth_account import Account

GATEWAY = "http://localhost:8080"
UPSTREAM = "http://127.0.0.1:9000"


def stack_is_up() -> bool:
    try:
        return httpx.get(f"{GATEWAY}/health", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def register(slug: str) -> None:
    """Registers a provider, ignoring a 409 if a previous run already did."""
    httpx.post(
        f"{GATEWAY}/v1/providers",
        json={
            "slug": slug,
            "upstream_url": UPSTREAM,
            "price": "0.001",
            "payout_address": "0x0000000000000000000000000000000000000001",
        },
        timeout=5.0,
    )


@pytest.fixture(scope="module")
def providers():
    # The sample's allowlist names these two, so they have to exist for the chain to permit
    # the call at all.
    register("geocode")
    register("weather")


@pytest.fixture()
def gateway_env(monkeypatch):
    # Substitution 1: the sample's Session construction stays verbatim; the environment says
    # where the gateway is.
    monkeypatch.setenv("TOLLGATE_GATEWAY", GATEWAY)


@pytest.mark.skipif(not stack_is_up(), reason="needs a running gateway; see test_session.py")
def test_the_architecture_7_3_sample_runs(providers, gateway_env, capsys):
    parent_key = "0x" + secrets.token_bytes(32).hex()
    worker_key = "0x" + secrets.token_bytes(32).hex()
    worker_address = Account.from_key(worker_key).address

    # ---- architecture.md §7.3, from here ----
    from tollgate import Session

    # Supervisor
    sup = Session(signer=parent_key, network="base-sepolia")

    worker_budget = sup.delegate(
        subject=worker_address,
        max_total="1.00",
        max_per_request="0.05",
        allowlist=["geocode", "weather"],
        expiry_seconds=600,
    )

    # Worker
    w = Session(signer=worker_key, capability=worker_budget)
    r = w.get(f"{GATEWAY}/v1/proxy/geocode/echo?q=Panaji")

    print(w.receipts())         # signed, per-charge, with tx hashes
    print(sup.expense_report())  # rolled up across the whole delegation tree
    # ---- to here ----

    assert r.status_code == 200
    # The mock echoes `parse_qs` output, so values are lists.
    assert r.json()["query"] == {"q": ["Panaji"]}, "the upstream's own body came back"

    receipts = w.receipts()
    assert len(receipts) == 1
    assert receipts[0]["provider_slug"] == "geocode"
    assert receipts[0]["amount"] == "1000"
    assert receipts[0]["upstream_status"] == 200
    # tx_hash is null until the settler runs; the receipt is signed and valid regardless.
    assert receipts[0]["signature"].startswith("0x")

    report = sup.expense_report()
    assert report["root"] == worker_budget.root_hash()
    assert report["total_spent"] == "0.001"
    assert len(report["charges"]) == 1
    assert report["charges"][0]["provider"] == "geocode"
    assert report["nodes"][0]["subject"].lower() == worker_address.lower()
    assert report["nodes"][0]["remaining"] == "0.999"
    assert report["signature"].startswith("0x")

    printed = capsys.readouterr().out
    assert "geocode" in printed, "the sample prints its receipts and report"


@pytest.mark.skipif(not stack_is_up(), reason="needs a running gateway; see test_session.py")
def test_delegate_still_makes_no_request_in_the_sample_flow(providers, gateway_env):
    """The claim that sells the feature, asserted inside the end-to-end flow rather than only
    in isolation: the supervisor never talks to the gateway to grant a budget."""

    class Recording(httpx.BaseTransport):
        def __init__(self):
            self.requests = []
            self.inner = httpx.HTTPTransport()

        def handle_request(self, request):
            self.requests.append(request)
            return self.inner.handle_request(request)

    from tollgate import Session

    transport = Recording()
    sup = Session(
        signer="0x" + secrets.token_bytes(32).hex(),
        client=httpx.Client(transport=transport, timeout=30.0),
    )

    sup.delegate(
        subject=Account.from_key("0x" + secrets.token_bytes(32).hex()).address,
        max_total="1.00",
        max_per_request="0.05",
        allowlist=["geocode", "weather"],
        expiry_seconds=600,
    )

    assert transport.requests == []
    assert os.environ["TOLLGATE_GATEWAY"] == GATEWAY
