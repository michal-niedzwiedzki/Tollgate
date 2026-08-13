"""Tests for `tollgate.capability` and `Session.delegate`.

The golden-vector tests are the important ones. A capability's struct hash is its identity —
the Redis counter key, the `capabilities` primary key, and the `parent` pointer of the link
below it — so Python and Rust disagreeing about the encoding would not fail loudly. It would
produce chains that hash differently on each side and charge the wrong counters. The vectors
in `crates/tollgate-gateway/tests/fixtures/capability_vectors.json` are emitted by the Rust
implementation; this file asserts Python reproduces them exactly.

`TestIntegration` needs a live gateway (see `test_session.py`'s docstring for the stack).
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import httpx
import pytest
from eth_account import Account

from tollgate import signing
from tollgate.capability import (
    Capability,
    CapabilityChain,
    allowlist_hash,
)
from tollgate.errors import AttenuationError
from tollgate.session import Session

REPO = Path(__file__).resolve().parents[2]
VECTORS = json.loads(
    (REPO / "crates/tollgate-gateway/tests/fixtures/capability_vectors.json").read_text()
)
VECTOR_CHAIN_ID = VECTORS["domain"]["chainId"]

GATEWAY = "http://localhost:8080"


class RecordingTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport):
        self.inner = inner
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.inner.handle_request(request)


def recording_session(**kwargs) -> tuple[Session, RecordingTransport]:
    transport = RecordingTransport(httpx.HTTPTransport())
    client = httpx.Client(transport=transport, timeout=30.0)
    key = kwargs.pop("signer", "0x" + secrets.token_bytes(32).hex())
    return Session(signer=key, client=client, **kwargs), transport


# -- golden vectors --------------------------------------------------------------


class TestGoldenVectors:
    @pytest.mark.parametrize("index", range(len(VECTORS["capabilities"])))
    def test_struct_hash_matches_the_rust_value(self, index):
        entry = VECTORS["capabilities"][index]
        capability = Capability.from_json(entry["capability"])

        assert capability.struct_hash(VECTOR_CHAIN_ID).lower() == entry["structHash"].lower()

    @pytest.mark.parametrize("index", range(len(VECTORS["capabilities"])))
    def test_signing_hash_matches_the_rust_value(self, index):
        entry = VECTORS["capabilities"][index]
        capability = Capability.from_json(entry["capability"])

        assert capability.signing_hash(VECTOR_CHAIN_ID).lower() == entry["signingHash"].lower()

    @pytest.mark.parametrize("index", range(len(VECTORS["capabilities"])))
    def test_signature_matches_the_rust_value(self, index):
        # Same key, same struct, same domain: the bytes must be identical, not merely both
        # valid. Anything else means the two sides are signing different messages.
        entry = VECTORS["capabilities"][index]
        capability = Capability.from_json(entry["capability"])

        signature = capability.sign(entry["signerPrivateKey"], VECTOR_CHAIN_ID)
        assert signature.lower() == entry["signature"].lower()

    def test_allowlist_hash_matches_the_declared_hash(self):
        for entry in VECTORS["capabilities"]:
            if entry.get("allowlist"):
                assert (
                    allowlist_hash(entry["allowlist"]).lower()
                    == entry["capability"]["allowlistHash"].lower()
                )

    def test_allowlist_hash_is_order_independent(self):
        assert allowlist_hash(["b", "a"]) == allowlist_hash(["a", "b"])

    def test_an_empty_allowlist_is_the_inherit_sentinel(self):
        # Not the hash of the empty string: 0x0 means "inherit from the parent", which is a
        # different thing from "an allowlist with nothing in it".
        assert allowlist_hash([]) == "0x" + "00" * 32

    def test_changing_a_field_changes_the_hash(self):
        entry = VECTORS["capabilities"][0]
        capability = Capability.from_json(entry["capability"])
        before = capability.struct_hash(VECTOR_CHAIN_ID)

        capability.max_total += 1

        assert capability.struct_hash(VECTOR_CHAIN_ID) != before


class TestSerialisation:
    def test_a_chain_round_trips_through_the_header_format(self):
        session, _ = recording_session()
        chain = session.delegate(
            subject="0x" + "33" * 20,
            max_total="1.00",
            max_per_request="0.05",
            allowlist=["geocode", "weather"],
            expiry_seconds=600,
        )

        restored = CapabilityChain.deserialize(chain.serialize(), chain.chain_id)

        assert len(restored) == len(chain)
        assert restored.root_hash() == chain.root_hash()
        assert restored.leaf.allowlist == ["geocode", "weather"]

    def test_str_is_the_header_so_a_chain_can_be_passed_straight_to_a_session(self):
        session, _ = recording_session()
        chain = session.delegate(
            subject="0x" + "33" * 20, max_total="1.00", max_per_request="0.05",
            allowlist=["mock-ok"], expiry_seconds=600,
        )

        assert str(chain) == chain.serialize()
        assert Session(signer="0x" + "44" * 32, capability=chain).capability == chain.serialize()


# -- delegation ------------------------------------------------------------------


class TestDelegate:
    def test_delegate_makes_zero_http_requests(self):
        # This is the claim: one local signature, no server round-trip
        # (architecture.md §7.3). Asserted at the transport, so nothing can slip through.
        session, transport = recording_session()

        session.delegate(
            subject="0x" + "33" * 20,
            max_total="1.00",
            max_per_request="0.05",
            allowlist=["geocode"],
            expiry_seconds=600,
        )

        assert transport.requests == []

    def test_a_root_link_has_a_zero_parent_and_the_issuer_is_the_signer(self):
        session, _ = recording_session()

        chain = session.delegate(
            subject="0x" + "33" * 20, max_total="1.00", max_per_request="0.05",
            allowlist=["geocode"], expiry_seconds=600,
        )

        assert len(chain) == 1
        assert chain.root.capability.parent == "0x" + "00" * 32
        assert chain.root.capability.issuer == session.address

    def test_a_child_link_points_at_its_parent_and_extends_the_chain(self):
        supervisor, _ = recording_session()
        worker_key = "0x" + secrets.token_bytes(32).hex()
        worker_address = Account.from_key(worker_key).address

        parent_chain = supervisor.delegate(
            subject=worker_address, max_total="1.00", max_per_request="0.05",
            allowlist=["geocode", "weather"], expiry_seconds=600, max_depth=2,
        )
        worker = Session(signer=worker_key, capability=parent_chain)
        child_chain = worker.delegate(
            subject="0x" + "55" * 20, max_total="0.50", max_per_request="0.01",
            allowlist=["geocode"], expiry_seconds=300, max_depth=1,
        )

        assert len(child_chain) == 2
        assert child_chain.links[1].capability.parent == parent_chain.root_hash()
        assert child_chain.links[1].capability.issuer == worker_address
        # The root is unchanged, so both chains draw on the same supervisor counter.
        assert child_chain.root_hash() == parent_chain.root_hash()

    def test_amounts_are_converted_to_base_units(self):
        session, _ = recording_session()

        chain = session.delegate(
            subject="0x" + "33" * 20, max_total="1.00", max_per_request="0.05",
            allowlist=["geocode"], expiry_seconds=600,
        )

        assert chain.leaf.capability.max_total == 1_000_000
        assert chain.leaf.capability.max_per_request == 50_000

    def test_the_signature_recovers_to_the_issuer(self):
        session, _ = recording_session()

        chain = session.delegate(
            subject="0x" + "33" * 20, max_total="1.00", max_per_request="0.05",
            allowlist=["geocode"], expiry_seconds=600,
        )

        link = chain.root
        from eth_account.messages import encode_typed_data

        recovered = Account.recover_message(
            encode_typed_data(full_message=link.capability.full_message(chain.chain_id)),
            signature=link.signature,
        )
        assert recovered == session.address


class TestAttenuation:
    """One test per rule in architecture.md §5.2 rule 4, refused locally before signing."""

    def setup_method(self):
        self.supervisor, _ = recording_session()
        self.worker_key = "0x" + secrets.token_bytes(32).hex()
        self.parent = self.supervisor.delegate(
            subject=Account.from_key(self.worker_key).address,
            max_total="1.00",
            max_per_request="0.05",
            allowlist=["geocode", "weather"],
            expiry_seconds=600,
            max_depth=2,
        )
        self.worker = Session(signer=self.worker_key, capability=self.parent)

    def delegate(self, **overrides):
        kwargs = dict(
            subject="0x" + "55" * 20,
            max_total="0.50",
            max_per_request="0.01",
            allowlist=["geocode"],
            expiry_seconds=300,
            max_depth=1,
        )
        kwargs.update(overrides)
        return self.worker.delegate(**kwargs)

    def test_a_valid_delegation_is_signed(self):
        assert len(self.delegate()) == 2

    def test_more_max_total_than_the_parent_holds_is_refused(self):
        with pytest.raises(AttenuationError, match="maxTotal"):
            self.delegate(max_total="2.00")

    def test_more_max_per_request_than_the_parent_holds_is_refused(self):
        with pytest.raises(AttenuationError, match="maxPerRequest"):
            self.delegate(max_per_request="0.10")

    def test_a_later_expiry_than_the_parent_is_refused(self):
        with pytest.raises(AttenuationError, match="expiry"):
            self.delegate(expiry_seconds=7200)

    def test_a_max_depth_not_below_the_parent_is_refused(self):
        with pytest.raises(AttenuationError, match="maxDepth"):
            self.delegate(max_depth=2)

    def test_an_allowlist_the_parent_does_not_hold_is_refused(self):
        with pytest.raises(AttenuationError, match="allowlist"):
            self.delegate(allowlist=["geocode", "elsewhere"])

    def test_a_subset_allowlist_is_allowed(self):
        assert len(self.delegate(allowlist=["weather"])) == 2

    def test_an_inheriting_allowlist_is_allowed(self):
        # Empty means inherit, not "grant everything", so it cannot be an escalation.
        assert len(self.delegate(allowlist=[])) == 2

    def test_nothing_was_signed_when_attenuation_fails(self):
        # The refusal has to happen before the signature exists, otherwise a caller could
        # ignore the exception and still hold usable bytes.
        before = len(self.worker._issued_roots)
        with pytest.raises(AttenuationError):
            self.delegate(max_total="2.00")
        assert len(self.worker._issued_roots) == before


# -- integration -----------------------------------------------------------------


def stack_is_up() -> bool:
    try:
        return httpx.get(f"{GATEWAY}/health", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not stack_is_up(), reason="needs a running gateway; see test_session.py")
class TestIntegration:
    def test_a_delegated_chain_is_accepted_by_the_live_gateway(self):
        supervisor = Session(signer="0x" + secrets.token_bytes(32).hex(), gateway=GATEWAY)
        worker_key = "0x" + secrets.token_bytes(32).hex()

        chain = supervisor.delegate(
            subject=Account.from_key(worker_key).address,
            max_total="1.00",
            max_per_request="0.05",
            allowlist=["mock-ok"],
            expiry_seconds=600,
        )
        worker = Session(signer=worker_key, capability=chain, gateway=GATEWAY)

        response = worker.get(f"{GATEWAY}/v1/proxy/mock-ok/ok")

        assert response.status_code == 200
        assert response.json() == {"result": "ok"}
        # The charge drew on the capability, not on a payer budget: no POST /v1/budgets was
        # ever made for this worker. The capability is self-describing, which is what makes
        # delegate() a pure local signature.
        assert worker.receipts()[0]["capability_hash"] == chain.leaf_hash()

    def test_a_provider_outside_the_allowlist_is_refused(self):
        from tollgate.errors import CapabilityRejected

        supervisor = Session(signer="0x" + secrets.token_bytes(32).hex(), gateway=GATEWAY)
        worker_key = "0x" + secrets.token_bytes(32).hex()
        chain = supervisor.delegate(
            subject=Account.from_key(worker_key).address,
            max_total="1.00", max_per_request="0.05",
            allowlist=["mock-ok"], expiry_seconds=600,
        )
        worker = Session(signer=worker_key, capability=chain, gateway=GATEWAY)

        with pytest.raises(CapabilityRejected) as caught:
            worker.get(f"{GATEWAY}/v1/proxy/mock-fail/fail")

        assert caught.value.code == "provider_not_allowed"

    def test_every_level_of_the_chain_is_charged(self):
        # architecture.md §5.2: "Every charge decrements every capability in the chain."
        supervisor = Session(signer="0x" + secrets.token_bytes(32).hex(), gateway=GATEWAY)
        lead_key = "0x" + secrets.token_bytes(32).hex()
        worker_key = "0x" + secrets.token_bytes(32).hex()

        to_lead = supervisor.delegate(
            subject=Account.from_key(lead_key).address,
            max_total="1.00", max_per_request="0.05",
            allowlist=["mock-ok"], expiry_seconds=600, max_depth=2,
        )
        lead = Session(signer=lead_key, capability=to_lead, gateway=GATEWAY)
        to_worker = lead.delegate(
            subject=Account.from_key(worker_key).address,
            max_total="0.50", max_per_request="0.01",
            allowlist=["mock-ok"], expiry_seconds=300, max_depth=1,
        )
        worker = Session(signer=worker_key, capability=to_worker, gateway=GATEWAY)

        assert worker.get(f"{GATEWAY}/v1/proxy/mock-ok/ok").status_code == 200

        for link in to_worker.links:
            state = httpx.get(
                f"{GATEWAY}/v1/capabilities/{link.capability.struct_hash(to_worker.chain_id)}",
                timeout=5.0,
            ).json()
            assert state["spent_wei"] == "1000", "every level pays for the same charge"
