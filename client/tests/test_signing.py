"""Tests for `tollgate.signing`, and the writer of the cross-language payment vector.

The last test in this file writes
`crates/tollgate-gateway/tests/fixtures/payment_vector.json`, which the Rust test
`verify::python_vector` reads back and recovers a payer from. That pair is the point of
Task 8.1: a Python-produced header that the Rust gateway accepts is the only evidence the
two EIP-712 encodings actually agree, and neither side's own unit tests can supply it.

The vector is deterministic — fixed key, fixed nonce, fixed validity window — so re-running
pytest rewrites the file byte for byte and leaves no diff. Nothing here reads the clock
except the tests that are specifically about the clock-derived defaults.
"""

import base64
import json
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from tollgate import signing

# Repo root: client/tests/test_signing.py -> tests -> client -> repo.
REPO = Path(__file__).resolve().parents[2]
VECTOR_PATH = REPO / "crates/tollgate-gateway/tests/fixtures/payment_vector.json"

# Test-only key. Controls no funds; it exists so the vector is reproducible.
SIGNER_KEY = "0x" + "22" * 32
PAYOUT = "0x0101010101010101010101010101010101010101"
# Native USDC on Base Sepolia, confirmed on-chain (NOTES.md, Task 6.6 write-up).
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
CHAIN_ID = 84532
VALUE = 1000  # 0.001 USDC, the price the seed script registers.
VALID_AFTER = 0
VALID_BEFORE = 1_800_000_000
NONCE = "0x" + "23" * 32


def deterministic_payload():
    return signing.sign_payment(
        private_key=SIGNER_KEY,
        to=PAYOUT,
        value=VALUE,
        usdc_address=USDC,
        chain_id=CHAIN_ID,
        valid_after=VALID_AFTER,
        valid_before=VALID_BEFORE,
        nonce=NONCE,
    )


class TestToBaseUnits:
    @pytest.mark.parametrize(
        "amount,expected",
        [
            ("0.001", 1000),
            ("1", 1_000_000),
            ("1.00", 1_000_000),
            ("0.000001", 1),
            ("0", 0),
            (".5", 500_000),
            ("12.345678", 12_345_678),
        ],
    )
    def test_converts_decimal_usdc_to_base_units(self, amount, expected):
        assert signing.to_base_units(amount) == expected

    def test_rejects_more_precision_than_usdc_has(self):
        with pytest.raises(ValueError, match="at most 6 decimal places"):
            signing.to_base_units("0.0000001")

    @pytest.mark.parametrize("amount", ["abc", "", "-1", "1.2.3", "1e6"])
    def test_rejects_non_decimal_input(self, amount):
        with pytest.raises(ValueError):
            signing.to_base_units(amount)


class TestDefaults:
    def test_valid_before_defaults_to_now_plus_the_quote_validity_window(self):
        # architecture.md §9.2 rule 1: the gateway rejects a window longer than this.
        auth = signing.build_authorization(payer=PAYOUT, to=PAYOUT, value=1, now=1_700_000_000)
        assert auth["validBefore"] == 1_700_000_000 + 300
        assert signing.DEFAULT_VALIDITY_SECONDS == 300

    def test_nonce_defaults_to_32_random_bytes(self):
        first = signing.build_authorization(payer=PAYOUT, to=PAYOUT, value=1)["nonce"]
        second = signing.build_authorization(payer=PAYOUT, to=PAYOUT, value=1)["nonce"]

        assert first.startswith("0x")
        assert len(bytes.fromhex(first[2:])) == 32
        # The nonce is the end-to-end idempotency key; two authorisations must never collide.
        assert first != second

    def test_rejects_a_non_positive_value(self):
        with pytest.raises(ValueError, match="value must be positive"):
            signing.build_authorization(payer=PAYOUT, to=PAYOUT, value=0)


class TestPayloadShape:
    def test_matches_the_x402_exact_wire_shape(self):
        payload = deterministic_payload()

        assert payload["x402Version"] == 1
        assert payload["scheme"] == "exact"
        assert payload["network"] == "eip155:84532"
        assert set(payload["payload"]) == {"signature", "authorization"}

    def test_numeric_fields_are_decimal_strings(self):
        # The gateway's decoder treats the string form as canonical; a uint256 `value` would
        # not survive being a JSON number.
        auth = deterministic_payload()["payload"]["authorization"]

        assert auth["value"] == "1000"
        assert auth["validAfter"] == "0"
        assert auth["validBefore"] == "1800000000"
        assert auth["nonce"] == NONCE

    def test_signature_is_65_bytes(self):
        signature = deterministic_payload()["payload"]["signature"]
        assert len(bytes.fromhex(signature[2:])) == 65

    def test_from_is_the_signer(self):
        payload = deterministic_payload()
        assert payload["payload"]["authorization"]["from"] == Account.from_key(SIGNER_KEY).address


class TestSignature:
    def test_recovers_the_signer_locally(self):
        payload = deterministic_payload()
        authorization = {
            **payload["payload"]["authorization"],
            "value": VALUE,
            "validAfter": VALID_AFTER,
            "validBefore": VALID_BEFORE,
        }
        message = encode_typed_data(
            full_message=signing.transfer_with_authorization_message(
                authorization, usdc_address=USDC, chain_id=CHAIN_ID
            )
        )

        recovered = Account.recover_message(
            message, signature=payload["payload"]["signature"]
        )
        assert recovered == Account.from_key(SIGNER_KEY).address

    def test_the_signature_is_bound_to_the_amount(self):
        # Not a restatement of the test above: it is the property the gateway relies on when
        # it checks `value == provider.price_wei`. Tampering after signing must change who
        # recovers, so an inflated amount can never carry a valid signature.
        payload = deterministic_payload()
        tampered = {
            **payload["payload"]["authorization"],
            "value": VALUE + 1,
            "validAfter": VALID_AFTER,
            "validBefore": VALID_BEFORE,
        }
        message = encode_typed_data(
            full_message=signing.transfer_with_authorization_message(
                tampered, usdc_address=USDC, chain_id=CHAIN_ID
            )
        )

        recovered = Account.recover_message(
            message, signature=payload["payload"]["signature"]
        )
        assert recovered != Account.from_key(SIGNER_KEY).address


class TestHeader:
    def test_header_is_base64_of_the_compact_payload(self):
        payload = deterministic_payload()
        header = signing.encode_payment_header(payload)

        assert json.loads(base64.b64decode(header)) == payload
        assert " " not in base64.b64decode(header).decode()

    def test_the_header_is_stable_for_a_fixed_payload(self):
        payload = deterministic_payload()
        assert signing.encode_payment_header(payload) == signing.encode_payment_header(payload)


def test_writes_the_cross_language_payment_vector():
    """Writes the fixture `verify::python_vector` reads. See this module's docstring."""
    payload = deterministic_payload()
    vector = {
        "_comment": (
            "Generated by the Python client's tests/test_signing.py. Read by "
            "tollgate-gateway's verify::python_vector, which decodes the header and recovers "
            "expectedPayer from it: the cross-language check that the Python and Rust EIP-712 "
            "encodings of TransferWithAuthorization agree. Deterministic, so re-running pytest "
            "produces no diff. The private key is test-only and controls no funds."
        ),
        "chainId": CHAIN_ID,
        "domain": {
            "name": signing.USDC_EIP712_NAME,
            "version": signing.USDC_EIP712_VERSION,
        },
        "expectedPayer": Account.from_key(SIGNER_KEY).address,
        "header": signing.encode_payment_header(payload),
        "payload": payload,
        "signerPrivateKey": SIGNER_KEY,
        "usdcAddress": USDC,
    }

    VECTOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTOR_PATH.write_text(json.dumps(vector, indent=2, sort_keys=True) + "\n")

    written = json.loads(VECTOR_PATH.read_text())
    assert written["expectedPayer"] == Account.from_key(SIGNER_KEY).address
    assert json.loads(base64.b64decode(written["header"])) == payload
