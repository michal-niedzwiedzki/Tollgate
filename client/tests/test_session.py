"""Tests for `tollgate.session`.

Two groups. The unit tests drive `Session` against `httpx.MockTransport`, so they pin the
retry rule and the exception mapping without needing a stack. `TestIntegration` runs against
a live gateway and mock upstream and is what `pytest -k integration` selects; it skips with a
reason if the stack is not up, so a missing stack can never look like a pass.

Bringing the stack up:

    ./scripts/dev.sh                                   # postgres + redis
    python3 examples/mock_upstream.py &                # the upstream on :9000
    TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true \\
        cargo run -p tollgate-gateway &                # the gateway on :8080
    ./scripts/seed_providers.sh                        # mock-ok / mock-slow / mock-fail

Note `cargo run -p tollgate-gateway`, not `--workspace`: NOTES.md records that building both
binaries in one invocation links a gateway whose rustls has two crypto providers and panics.
"""

from __future__ import annotations

import base64
import json
import secrets
import time

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

from tollgate import signing
from tollgate.errors import (
    CapabilityExpired,
    CapExceeded,
    InsufficientBudget,
    NonceReplay,
    PaymentFailed,
    UpstreamFailed,
)
from tollgate.session import Session

GATEWAY = "http://localhost:8080"
PROVIDER = f"{GATEWAY}/v1/proxy/mock-ok/ok"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PRICE = 1000  # 0.001 USDC, what seed_providers.sh registers for mock-ok.


# -- helpers ---------------------------------------------------------------------


class RecordingTransport(httpx.BaseTransport):
    """Counts the requests that actually leave the client.

    "Exactly two HTTP requests" is a claim about the wire, so it is asserted at the transport
    rather than by counting calls into `Session`.
    """

    def __init__(self, inner: httpx.BaseTransport):
        self.inner = inner
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.inner.handle_request(request)


def quote_body(amount: int = PRICE, pay_to: str = "0x" + "01" * 20) -> dict:
    return {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:84532",
                "maxAmountRequired": str(amount),
                "asset": USDC,
                "payTo": pay_to,
                "resource": PROVIDER,
                "description": "",
                "mimeType": "",
                "maxTimeoutSeconds": 300,
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
        "error": "payment required",
    }


def capability_header(max_per_request: int, expiry: int, max_total: int = 1_000_000) -> str:
    """A chain header shaped like the real one. Only the leaf's limits matter to the mirror,
    and the mirror never checks signatures — the gateway does that."""
    link = {
        "capability": {
            "issuer": "0x" + "11" * 20,
            "subject": "0x" + "22" * 20,
            "parent": "0x" + "00" * 32,
            "maxTotal": str(max_total),
            "maxPerRequest": str(max_per_request),
            "allowlistHash": "0x" + "00" * 32,
            "notBefore": 0,
            "expiry": expiry,
            "maxDepth": 1,
            "salt": "0x" + "33" * 32,
        },
        "signature": "0x" + "44" * 65,
        "allowlist": [],
    }
    return base64.b64encode(json.dumps([link]).encode()).decode()


def mock_session(handler, **kwargs) -> tuple[Session, RecordingTransport]:
    transport = RecordingTransport(httpx.MockTransport(handler))
    client = httpx.Client(transport=transport)
    session = Session(signer="0x" + "22" * 32, client=client, **kwargs)
    return session, transport


def pay_then_ok(paid_response):
    """A handler that quotes on the unpaid request and returns `paid_response` on the paid
    one."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "X-PAYMENT" not in request.headers:
            return httpx.Response(402, json=quote_body())
        return paid_response

    return handler


# -- unit tests ------------------------------------------------------------------


class TestRetryLoop:
    def test_pays_the_quote_and_returns_the_upstream_response(self):
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"}))
        )

        response = session.get(PROVIDER)

        assert response.status_code == 200
        assert response.json() == {"result": "ok"}
        assert len(transport.requests) == 2

    def test_the_payment_header_is_a_signed_payload_for_the_quoted_amount(self):
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"}))
        )

        session.get(PROVIDER)

        header = transport.requests[1].headers["X-PAYMENT"]
        payload = json.loads(base64.b64decode(header))
        authorization = payload["payload"]["authorization"]
        assert authorization["value"] == str(PRICE)
        assert authorization["to"] == to_checksum_address("0x" + "01" * 20)
        assert authorization["from"] == session.address
        assert payload["scheme"] == "exact"

    def test_a_capability_is_sent_only_on_the_paid_request(self):
        header = capability_header(max_per_request=50_000, expiry=int(time.time()) + 600)
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"})), capability=header
        )

        session.get(PROVIDER)

        assert "X-Tollgate-Capability" not in transport.requests[0].headers
        assert transport.requests[1].headers["X-Tollgate-Capability"] == header

    def test_a_second_402_raises_rather_than_looping(self):
        # The rule that keeps this client from becoming the runaway loop the product exists
        # to prevent.
        def always_402(request: httpx.Request) -> httpx.Response:
            return httpx.Response(402, json=quote_body())

        session, transport = mock_session(always_402)

        with pytest.raises(PaymentFailed):
            session.get(PROVIDER)
        assert len(transport.requests) == 2

    def test_an_unpaid_200_is_returned_without_paying(self):
        session, transport = mock_session(
            lambda request: httpx.Response(200, json={"free": True})
        )

        assert session.get(PROVIDER).json() == {"free": True}
        assert len(transport.requests) == 1


class TestErrorMapping:
    def test_429_becomes_cap_exceeded_with_the_tripped_level_and_remaining(self):
        body = {
            "reason": "cap_exceeded",
            "tripped_level": 1,
            "capability_hash": "0x" + "ab" * 32,
            "limit": "50000",
            "chain": [
                {"hash": "0x" + "aa" * 32, "remaining": "900000"},
                {"hash": "0x" + "ab" * 32, "remaining": "100000"},
            ],
        }
        session, _ = mock_session(pay_then_ok(httpx.Response(429, json=body)))

        with pytest.raises(CapExceeded) as caught:
            session.get(PROVIDER)

        assert caught.value.tripped_level == 1
        assert caught.value.remaining == "100000"
        assert caught.value.limit == "50000"

    def test_402_insufficient_funds_becomes_insufficient_budget(self):
        body = {**quote_body(), "reason": "insufficient_funds", "tripped_level": 0,
                "chain": [{"hash": "0x" + "aa" * 32, "remaining": "0"}]}
        session, _ = mock_session(pay_then_ok(httpx.Response(402, json=body)))

        with pytest.raises(InsufficientBudget) as caught:
            session.get(PROVIDER)

        assert caught.value.tripped_level == 0
        assert caught.value.remaining == "0"

    def test_409_becomes_nonce_replay(self):
        body = {"error": {"code": "nonce_replayed", "message": "already used"}}
        session, _ = mock_session(pay_then_ok(httpx.Response(409, json=body)))

        with pytest.raises(NonceReplay):
            session.get(PROVIDER)

    @pytest.mark.parametrize("status,code", [(502, "upstream_error"), (504, "upstream_timeout")])
    def test_upstream_failures_become_upstream_failed(self, status, code):
        body = {"error": {"code": code, "message": "upstream said no"}}
        session, _ = mock_session(pay_then_ok(httpx.Response(status, json=body)))

        with pytest.raises(UpstreamFailed) as caught:
            session.get(PROVIDER)
        assert caught.value.code == code

    def test_a_revoked_capability_becomes_capability_revoked(self):
        from tollgate.errors import CapabilityRevoked

        body = {"error": {"code": "capability_revoked", "message": "revoked"}}
        session, _ = mock_session(
            pay_then_ok(httpx.Response(403, json=body)),
            capability=capability_header(50_000, int(time.time()) + 600),
        )

        with pytest.raises(CapabilityRevoked):
            session.get(PROVIDER)


class TestLocalMirror:
    def test_an_expired_capability_raises_before_any_http_call(self):
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"})),
            capability=capability_header(50_000, expiry=int(time.time()) - 1),
        )

        with pytest.raises(CapabilityExpired):
            session.get(PROVIDER)
        assert transport.requests == []

    def test_a_quote_above_the_per_request_cap_raises_without_paying(self):
        # The quote is the first moment the price is known, so this is the earliest the
        # refusal can happen — and it still saves the payment round trip.
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"})),
            capability=capability_header(max_per_request=PRICE - 1, expiry=int(time.time()) + 600),
        )

        with pytest.raises(CapExceeded) as caught:
            session.get(PROVIDER)

        assert len(transport.requests) == 1, "the payment request must not be sent"
        assert "X-PAYMENT" not in transport.requests[0].headers
        assert caught.value.limit == str(PRICE - 1)

    def test_a_quote_within_the_cap_is_paid(self):
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"})),
            capability=capability_header(max_per_request=PRICE, expiry=int(time.time()) + 600),
        )

        assert session.get(PROVIDER).status_code == 200
        assert len(transport.requests) == 2

    def test_no_capability_means_no_mirror(self):
        # The payer path (NOTES.md D1) has no local limits to copy; the gateway decides.
        session, transport = mock_session(
            pay_then_ok(httpx.Response(200, json={"result": "ok"}))
        )

        assert session.get(PROVIDER).status_code == 200
        assert len(transport.requests) == 2


class TestReceipts:
    def test_the_receipt_header_is_collected(self):
        receipt = {
            "nonce": "0x" + "23" * 32,
            "payer": "0x" + "22" * 20,
            "capability_hash": "0x" + "00" * 32,
            "provider_slug": "mock-ok",
            "amount": "1000",
            "upstream_status": 200,
            "timestamp": 1_700_000_000,
            "signature": "0x" + "ab" * 65,
        }
        response = httpx.Response(
            200,
            json={"result": "ok"},
            headers={"X-Tollgate-Receipt": base64.b64encode(
                json.dumps(receipt).encode()).decode()},
        )
        session, _ = mock_session(pay_then_ok(response))

        session.get(PROVIDER)

        assert session.receipts() == [receipt]

    def test_receipts_are_empty_when_the_gateway_sends_none(self):
        session, _ = mock_session(pay_then_ok(httpx.Response(200, json={"result": "ok"})))
        session.get(PROVIDER)
        assert session.receipts() == []


# -- integration -----------------------------------------------------------------


def stack_is_up() -> bool:
    try:
        return httpx.get(f"{GATEWAY}/health", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def seed_budget(payer: str, max_total: str, max_per_request: str) -> None:
    response = httpx.post(
        f"{GATEWAY}/v1/budgets",
        json={"payer": payer, "max_total": max_total, "max_per_request": max_per_request},
        timeout=5.0,
    )
    response.raise_for_status()


def new_session(max_total: str = "1.00", max_per_request: str = "0.05", **kwargs):
    """A session with a fresh key, so each test gets a budget nothing else has spent."""
    key = "0x" + secrets.token_bytes(32).hex()
    transport = RecordingTransport(httpx.HTTPTransport())
    session = Session(signer=key, client=httpx.Client(transport=transport, timeout=30.0), **kwargs)
    seed_budget(session.address, max_total, max_per_request)
    return session, transport


def verify_receipt(receipt: dict, chain_id: int = 84532) -> str:
    """Recovers the signer of a receipt, so the caller can compare it to /v1/gateway-key.

    Mirrors the `Receipt` struct in `crates/tollgate-gateway/src/ledger.rs` and the Tollgate
    domain from `capability.rs`.
    """
    message = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "Receipt": [
                {"name": "nonce", "type": "bytes32"},
                {"name": "payer", "type": "address"},
                {"name": "capabilityHash", "type": "bytes32"},
                {"name": "providerSlug", "type": "string"},
                {"name": "amount", "type": "uint256"},
                {"name": "upstreamStatus", "type": "uint16"},
                {"name": "timestamp", "type": "uint64"},
            ],
        },
        "primaryType": "Receipt",
        "domain": {"name": "Tollgate", "version": "1", "chainId": chain_id},
        "message": {
            "nonce": receipt["nonce"],
            "payer": receipt["payer"],
            "capabilityHash": receipt["capability_hash"],
            "providerSlug": receipt["provider_slug"],
            "amount": int(receipt["amount"]),
            "upstreamStatus": int(receipt["upstream_status"]),
            "timestamp": int(receipt["timestamp"]),
        },
    }
    return Account.recover_message(
        encode_typed_data(full_message=message), signature=receipt["signature"]
    )


@pytest.mark.skipif(not stack_is_up(), reason="needs a running gateway; see this module's docstring")
class TestIntegration:
    def test_a_paid_request_returns_the_upstream_body(self):
        session, transport = new_session()

        response = session.get(PROVIDER)

        assert response.status_code == 200
        assert response.json() == {"result": "ok"}, "the real upstream's body, not the gateway's"

    def test_exactly_two_http_requests_are_made(self):
        session, transport = new_session()

        session.get(PROVIDER)

        assert len(transport.requests) == 2
        assert "X-PAYMENT" not in transport.requests[0].headers
        assert "X-PAYMENT" in transport.requests[1].headers

    def test_the_receipt_verifies_against_the_gateway_key(self):
        session, _ = new_session()

        session.get(PROVIDER)

        assert len(session.receipts()) == 1
        receipt = session.receipts()[0]
        assert receipt["provider_slug"] == "mock-ok"
        assert receipt["upstream_status"] == 200
        assert receipt["amount"] == str(PRICE)

        gateway_key = httpx.get(f"{GATEWAY}/v1/gateway-key", timeout=5.0).json()
        published = gateway_key.get("address") or gateway_key.get("gateway_key")
        assert verify_receipt(receipt) == published

    def test_exceeding_the_per_request_cap_raises_cap_exceeded(self):
        # Server-side 429: the budget's per-request cap is below the provider's price, and
        # this session mirrors nothing (no capability), so the refusal comes from the gateway.
        session, _ = new_session(max_total="1.00", max_per_request="0.0005")

        with pytest.raises(CapExceeded) as caught:
            session.get(PROVIDER)

        assert caught.value.status_code == 429
        assert caught.value.tripped_level == 0
        assert caught.value.remaining is not None
        assert caught.value.limit == "500"

    def test_exhausting_the_total_budget_raises_insufficient_budget(self):
        session, _ = new_session(max_total="0.001", max_per_request="0.05")

        assert session.get(PROVIDER).status_code == 200
        with pytest.raises(InsufficientBudget) as caught:
            session.get(PROVIDER)

        assert caught.value.status_code == 402
        assert caught.value.remaining == "0"

    def test_a_locally_mirrored_cap_refuses_before_the_payment_request(self):
        session, transport = new_session(
            capability=capability_header(max_per_request=PRICE - 1, expiry=int(time.time()) + 600)
        )

        with pytest.raises(CapExceeded) as caught:
            session.get(PROVIDER)

        assert caught.value.status_code is None, "refused locally, so there is no HTTP status"
        assert len(transport.requests) == 1, "only the quote; the payment was never sent"

    def test_an_expired_capability_refuses_before_any_http_call(self):
        session, transport = new_session(
            capability=capability_header(max_per_request=PRICE, expiry=int(time.time()) - 1)
        )
        before = len(transport.requests)

        with pytest.raises(CapabilityExpired):
            session.get(PROVIDER)

        assert len(transport.requests) == before

    def test_an_upstream_failure_raises_upstream_failed(self):
        session, _ = new_session()

        with pytest.raises(UpstreamFailed) as caught:
            session.get(f"{GATEWAY}/v1/proxy/mock-fail/fail")

        assert caught.value.status_code == 502
