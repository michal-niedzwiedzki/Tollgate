#!/usr/bin/env python3
"""Signing harness for verifying Tollgate by hand.

This exists because the Phase 5 verification blocks are `curl` commands that need a signed
`X-PAYMENT` header and a signed `X-Tollgate-Capability` chain, and nothing in the repo could
produce either. It is a **test harness, not a client**: `client/tollgate/` in Phase 8 is the
real library, and it replaces this.

Requires `eth-account` (`python3 -m venv .venv && .venv/bin/pip install eth-account`).

    ./sign.py verify-fixture
    ./sign.py address --key 0x11..11
    ./sign.py payment --key 0x..  --to 0x.. --value 0.10 --usdc 0x.. --chain-id 84532
    ./sign.py chain --spec chain.json --chain-id 84532

`verify-fixture` checks this file's EIP-712 encoding against
`crates/tollgate-gateway/tests/fixtures/capability_vectors.json`, the cross-language vectors
the Rust side emits. Run it first: if it passes, this harness and the gateway agree on the
domain, the type hash and the struct hash, and any later disagreement is a real bug rather
than a harness artefact.
"""

import argparse
import base64
import json
import secrets
import sys
import time
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address

USDC_DECIMALS = 6

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "crates/tollgate-gateway/tests/fixtures/capability_vectors.json"

# Field order is part of the EIP-712 type hash and must match the `sol!` block in
# crates/tollgate-gateway/src/capability.rs exactly.
CAPABILITY_TYPE = [
    {"name": "issuer", "type": "address"},
    {"name": "subject", "type": "address"},
    {"name": "parent", "type": "bytes32"},
    {"name": "maxTotal", "type": "uint256"},
    {"name": "maxPerRequest", "type": "uint256"},
    {"name": "allowlistHash", "type": "bytes32"},
    {"name": "notBefore", "type": "uint64"},
    {"name": "expiry", "type": "uint64"},
    {"name": "maxDepth", "type": "uint32"},
    {"name": "salt", "type": "bytes32"},
]

TRANSFER_TYPE = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]

ZERO32 = "0x" + "00" * 32


def base_units(amount: str) -> int:
    """`"0.10"` -> 100000. USDC has six decimals."""
    whole, _, frac = amount.partition(".")
    if len(frac) > USDC_DECIMALS:
        raise SystemExit(f"{amount}: at most {USDC_DECIMALS} decimal places")
    return int((whole or "0") + frac.ljust(USDC_DECIMALS, "0"))


def allowlist_hash(slugs):
    """keccak of the slugs sorted lexicographically and joined with newlines.

    `0x0` means inherit, which is why an empty list is spelled as the zero hash here rather
    than hashed: they are different things and the gateway rejects confusing them.
    """
    if not slugs:
        return ZERO32
    return "0x" + keccak(text="\n".join(sorted(slugs))).hex()


def capability_message(capability, chain_id):
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "Capability": CAPABILITY_TYPE,
        },
        "primaryType": "Capability",
        # No verifyingContract: a capability is never verified on-chain.
        "domain": {"name": "Tollgate", "version": "1", "chainId": chain_id},
        "message": capability,
    }


def signable(full_message):
    return encode_typed_data(full_message=full_message)


def struct_hash(capability, chain_id):
    """EIP-712 hashStruct — the capability's identity, domain-free.

    `SignableMessage.body` is exactly hashStruct; `.header` is the domain separator.
    """
    return "0x" + signable(capability_message(capability, chain_id)).body.hex()


def signing_hash(capability, chain_id):
    msg = signable(capability_message(capability, chain_id))
    return "0x" + keccak(b"\x19\x01" + msg.header + msg.body).hex()


def sign_capability(capability, chain_id, key):
    message = signable(capability_message(capability, chain_id))
    return "0x" + Account.sign_message(message, key).signature.hex()


def cmd_address(args):
    print(Account.from_key(args.key).address)


def cmd_verify_fixture(_args):
    """Cross-check this harness against the Rust-emitted vectors."""
    vectors = json.loads(VECTORS.read_text())
    chain_id = vectors["domain"]["chainId"]
    failures = 0

    for index, entry in enumerate(vectors["capabilities"]):
        capability = dict(entry["capability"])
        # JSON carries the uint256s as decimal strings; EIP-712 encoding needs integers.
        capability["maxTotal"] = int(capability["maxTotal"])
        capability["maxPerRequest"] = int(capability["maxPerRequest"])

        checks = {
            "structHash": (struct_hash(capability, chain_id), entry["structHash"]),
            "signingHash": (signing_hash(capability, chain_id), entry["signingHash"]),
            "signature": (
                sign_capability(capability, chain_id, entry["signerPrivateKey"]),
                entry["signature"],
            ),
            "allowlistHash": (
                allowlist_hash(entry["allowlist"]),
                capability["allowlistHash"],
            ),
        }
        for name, (got, want) in checks.items():
            if got.lower() != want.lower():
                failures += 1
                print(f"link {index} {name}: got {got}, want {want}", file=sys.stderr)

    if failures:
        raise SystemExit(f"{failures} mismatch(es): this harness disagrees with the gateway")
    print(f"ok: {len(vectors['capabilities'])} vectors reproduced exactly")


def cmd_chain(args):
    """Signs a chain from a JSON spec and emits the base64 X-Tollgate-Capability header.

    Each spec entry: issuer_key, subject, max_total, max_per_request, allowlist,
    expiry_seconds, max_depth. `parent` is computed from the previous link, so the spec
    describes intent and the harness cannot emit a chain that fails rule 3 by accident.
    """
    spec = json.loads(Path(args.spec).read_text())
    now = int(time.time())
    links = []
    parent = ZERO32

    for entry in spec:
        slugs = entry.get("allowlist", [])
        capability = {
            "issuer": Account.from_key(entry["issuer_key"]).address,
            "subject": to_checksum_address(entry["subject"]),
            "parent": parent,
            "maxTotal": base_units(entry["max_total"]),
            "maxPerRequest": base_units(entry["max_per_request"]),
            "allowlistHash": allowlist_hash(slugs),
            "notBefore": entry.get("not_before", now - 60),
            # Absolute `expiry` wins over a relative one. Two sibling chains that share a
            # root must produce a byte-identical root — same fields, same struct hash, same
            # counter — and a relative expiry computed at invocation time would not.
            "expiry": entry.get("expiry", now + entry.get("expiry_seconds", 3600)),
            "maxDepth": entry["max_depth"],
            "salt": entry.get("salt", "0x" + secrets.token_bytes(32).hex()),
        }
        links.append(
            {
                "capability": {
                    **capability,
                    "maxTotal": str(capability["maxTotal"]),
                    "maxPerRequest": str(capability["maxPerRequest"]),
                },
                "signature": sign_capability(capability, args.chain_id, entry["issuer_key"]),
                "allowlist": slugs,
            }
        )
        parent = struct_hash(capability, args.chain_id)

    if args.hashes:
        for index, link in enumerate(links):
            print(f"level {index} {link['capability']['subject']}", file=sys.stderr)
    print(base64.b64encode(json.dumps(links).encode()).decode())


def cmd_payment(args):
    """Signs an EIP-3009 transferWithAuthorization and emits the base64 X-PAYMENT header."""
    now = int(time.time())
    account = Account.from_key(args.key)
    authorization = {
        "from": account.address,
        "to": to_checksum_address(args.to),
        "value": base_units(args.value),
        "validAfter": 0,
        "validBefore": now + args.valid_seconds,
        "nonce": args.nonce or ("0x" + secrets.token_bytes(32).hex()),
    }
    full_message = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": TRANSFER_TYPE,
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": "USDC",
            "version": "2",
            "chainId": args.chain_id,
            "verifyingContract": to_checksum_address(args.usdc),
        },
        "message": authorization,
    }
    signature = Account.sign_message(signable(full_message), args.key).signature

    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": f"eip155:{args.chain_id}",
        "payload": {
            "signature": "0x" + signature.hex(),
            "authorization": {
                **authorization,
                "value": str(authorization["value"]),
                "validAfter": str(authorization["validAfter"]),
                "validBefore": str(authorization["validBefore"]),
            },
        },
    }
    print(base64.b64encode(json.dumps(payload).encode()).decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("address")
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_address)

    p = sub.add_parser("verify-fixture")
    p.set_defaults(func=cmd_verify_fixture)

    p = sub.add_parser("chain")
    p.add_argument("--spec", required=True)
    p.add_argument("--chain-id", type=int, default=84532)
    p.add_argument("--hashes", action="store_true")
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("payment")
    p.add_argument("--key", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--value", required=True)
    p.add_argument("--usdc", required=True)
    p.add_argument("--chain-id", type=int, default=84532)
    p.add_argument("--valid-seconds", type=int, default=240)
    p.add_argument("--nonce")
    p.set_defaults(func=cmd_payment)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
