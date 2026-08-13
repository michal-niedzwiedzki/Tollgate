"""EIP-3009 payment signing: the half of x402 the client owns.

The gateway quotes a price in a 402 body and then verifies whatever `X-PAYMENT` header
comes back (`crates/tollgate-gateway/src/verify.rs`). This module produces that header.

Everything here has to agree byte for byte with the Rust side, because a signature is over
an encoding, not over a meaning:

- the EIP-712 domain is USDC's own — `name` and `version` come from the 402 body's `extra`,
  which is why they are parameters with the gateway's constants as defaults rather than
  hardcoded (`x402.rs::USDC_EIP712_NAME` / `USDC_EIP712_VERSION`);
- `TransferWithAuthorization`'s field order is part of its type hash, so it matches the
  `sol!` block in `verify.rs` exactly;
- the wire payload serialises `value`, `validAfter` and `validBefore` as decimal strings,
  which is the x402 convention the gateway's decoder treats as canonical.

`tests/test_signing.py` writes a signed vector to
`crates/tollgate-gateway/tests/fixtures/payment_vector.json`, and the Rust test
`verify::python_vector` recovers the payer from it. That cross-language fixture is what
actually holds the two implementations together; the prose above only explains it.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Dict, Optional

from eth_account import Account
from eth_utils import to_checksum_address

#: USDC has six decimals on every chain Circle deploys it to natively.
USDC_DECIMALS = 6

#: EIP-712 domain fields for native USDC. The gateway publishes these in the 402 body's
#: `extra` object; they are defaults here so a caller can follow the quote instead.
USDC_EIP712_NAME = "USDC"
USDC_EIP712_VERSION = "2"

#: Base Sepolia. The only chain this MVP settles on (`prd.md` decision #3).
DEFAULT_CHAIN_ID = 84532

#: `architecture.md` §9.2 rule 1: quotes are issued with `validBefore <= now + 300`, and the
#: gateway rejects a longer window because its Redis nonce TTL has to cover the whole of it.
DEFAULT_VALIDITY_SECONDS = 300

X402_VERSION = 1
SCHEME = "exact"

#: Field order is part of the EIP-712 type hash and must match the `sol!` block in
#: `crates/tollgate-gateway/src/verify.rs` exactly.
TRANSFER_WITH_AUTHORIZATION_TYPE = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]

EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


def caip2_network(chain_id: int = DEFAULT_CHAIN_ID) -> str:
    """`84532` -> `"eip155:84532"`, the CAIP-2 identifier x402 puts on the wire."""
    return f"eip155:{chain_id}"


def to_base_units(amount: str, decimals: int = USDC_DECIMALS) -> int:
    """`"0.001"` -> `1000`.

    Decimal-string in, integer out, with no float ever constructed: `float("0.07")` is not
    0.07, and a rounding error here would be a rounding error inside a signature.
    """
    whole, _, frac = str(amount).partition(".")
    if len(frac) > decimals:
        raise ValueError(f"{amount}: at most {decimals} decimal places")
    if whole and not whole.isdigit():
        raise ValueError(f"{amount}: not a non-negative decimal amount")
    if frac and not frac.isdigit():
        raise ValueError(f"{amount}: not a non-negative decimal amount")
    if not whole and not frac:
        raise ValueError(f"{amount}: not a non-negative decimal amount")
    return int((whole or "0") + frac.ljust(decimals, "0"))


def random_nonce() -> str:
    """A fresh 32-byte EIP-3009 nonce.

    The nonce is the idempotency key end to end — gateway replay guard, Redis key, Postgres
    primary key and USDC's own `authorizationState` (`architecture.md` §9.4) — so it is
    drawn from `secrets`, never from a counter or a timestamp.
    """
    return "0x" + secrets.token_bytes(32).hex()


def build_authorization(
    *,
    payer: str,
    to: str,
    value: int,
    valid_after: int = 0,
    valid_before: Optional[int] = None,
    nonce: Optional[str] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """The `TransferWithAuthorization` message, with integer fields still integers.

    `valid_before` defaults to `now + 300` (`DEFAULT_VALIDITY_SECONDS`) and `nonce` to 32
    random bytes. `now` is injectable so a test can pin a vector.
    """
    if value <= 0:
        raise ValueError("value must be positive")

    current = int(time.time()) if now is None else int(now)
    return {
        "from": to_checksum_address(payer),
        "to": to_checksum_address(to),
        "value": int(value),
        "validAfter": int(valid_after),
        "validBefore": (
            current + DEFAULT_VALIDITY_SECONDS if valid_before is None else int(valid_before)
        ),
        "nonce": nonce or random_nonce(),
    }


def transfer_with_authorization_message(
    authorization: Dict[str, Any],
    *,
    usdc_address: str,
    chain_id: int = DEFAULT_CHAIN_ID,
    domain_name: str = USDC_EIP712_NAME,
    domain_version: str = USDC_EIP712_VERSION,
) -> Dict[str, Any]:
    """The full EIP-712 message USDC verifies on-chain and the gateway verifies off it."""
    return {
        "types": {
            "EIP712Domain": EIP712_DOMAIN_TYPE,
            "TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION_TYPE,
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": domain_name,
            "version": domain_version,
            "chainId": int(chain_id),
            # USDC itself is the verifying contract: this signature authorises a transfer of
            # that specific token and is meaningless against any other.
            "verifyingContract": to_checksum_address(usdc_address),
        },
        "message": authorization,
    }


def sign_payment(
    *,
    private_key: str,
    to: str,
    value: int,
    usdc_address: str,
    chain_id: int = DEFAULT_CHAIN_ID,
    valid_after: int = 0,
    valid_before: Optional[int] = None,
    nonce: Optional[str] = None,
    now: Optional[int] = None,
    domain_name: str = USDC_EIP712_NAME,
    domain_version: str = USDC_EIP712_VERSION,
) -> Dict[str, Any]:
    """Signs an EIP-3009 authorisation and returns the x402 payment payload.

    `value` is in base units — the integer the 402 body quotes as `maxAmountRequired` — so
    the amount signed is the amount quoted, with no conversion in between to get wrong. Use
    `to_base_units` at the edge where a human types "0.001".

    The returned dict is the x402 `exact` payload; `encode_payment_header` turns it into the
    header value. The two are separate so a caller can inspect or log the payload without
    base64-decoding it back.
    """
    account = Account.from_key(private_key)
    authorization = build_authorization(
        payer=account.address,
        to=to,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
        now=now,
    )

    signed = Account.sign_typed_data(
        private_key,
        full_message=transfer_with_authorization_message(
            authorization,
            usdc_address=usdc_address,
            chain_id=chain_id,
            domain_name=domain_name,
            domain_version=domain_version,
        ),
    )

    return {
        "x402Version": X402_VERSION,
        "scheme": SCHEME,
        "network": caip2_network(chain_id),
        "payload": {
            "signature": "0x" + signed.signature.hex(),
            "authorization": {
                **authorization,
                # x402 carries the numeric fields as decimal strings. `value` in particular
                # is a uint256 and would lose precision as a JSON number.
                "value": str(authorization["value"]),
                "validAfter": str(authorization["validAfter"]),
                "validBefore": str(authorization["validBefore"]),
            },
        },
    }


def encode_payment_header(payload: Dict[str, Any]) -> str:
    """Base64 of the compact JSON payload — the `X-PAYMENT` header value.

    Compact separators because the header travels on every paid request and the whitespace
    is pure overhead; the gateway parses JSON, so the framing is free to be tight.
    """
    compact = json.dumps(payload, separators=(",", ":"))
    return base64.b64encode(compact.encode()).decode()
