"""EIP-712 capabilities: the delegation half of the client.

`architecture.md` §7.3 — "`delegate()` is one local signature. No server round-trip. That is
the line that sells the feature." Everything in this module exists to make that literally
true: a parent signs a struct, hands the bytes to a child, and the gateway accepts the child's
first request on the strength of that signature alone.

The encoding has to match `crates/tollgate-gateway/src/capability.rs` exactly, because the
struct hash *is* the capability's identity — it is the Redis counter key, the `capabilities`
primary key, and the `parent` pointer of the next link down. A field-order difference here
would not fail loudly; it would produce a chain that hashes differently on each side and
silently charges the wrong counters. `tests/test_capability.py` pins it against the Rust-
emitted golden vectors for exactly that reason.

Naming note: the task calls for `serialize()`/`deserialize()` producing the Task 5.2 header
format. That format is a JSON *array* of links, so the serialisable object is the chain —
`CapabilityChain` — while `Capability` is the single EIP-712 struct the array holds.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address

from tollgate.errors import AttenuationError

#: The Tollgate EIP-712 domain. No `verifyingContract`: a capability is policy, never verified
#: on-chain. `chainId` is still present and is the cross-chain replay guard (`architecture.md`
#: §10) — the same capability bytes are meaningless against a gateway on another chain.
DOMAIN_NAME = "Tollgate"
DOMAIN_VERSION = "1"

ZERO32 = "0x" + "00" * 32

#: architecture.md §5.2 rule 1. Four links total, not four plus a funding root (NOTES.md D2).
MAX_CHAIN_DEPTH = 4

#: Field order is part of the EIP-712 type hash and must match the `sol!` block in
#: `crates/tollgate-gateway/src/capability.rs` exactly.
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

EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
]


def domain(chain_id: int) -> Dict[str, Any]:
    return {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": int(chain_id)}


def allowlist_hash(slugs: Sequence[str]) -> str:
    """keccak of the slugs sorted lexicographically and joined with newlines.

    An empty list is the zero hash, which means *inherit from the parent* — not "an empty
    allowlist". They are different things and the gateway rejects confusing them, so this
    returns the sentinel rather than hashing the empty string (assumption A9).
    """
    if not slugs:
        return ZERO32
    return "0x" + keccak(text="\n".join(sorted(slugs))).hex()


@dataclass
class Capability:
    """One link: the EIP-712 struct a parent signs to grant a child a scoped budget."""

    issuer: str
    subject: str
    parent: str
    max_total: int
    max_per_request: int
    allowlist_hash: str
    not_before: int
    expiry: int
    max_depth: int
    salt: str

    def message(self) -> Dict[str, Any]:
        """The EIP-712 message: uint256s as Python ints, which is what the encoder wants."""
        return {
            "issuer": to_checksum_address(self.issuer),
            "subject": to_checksum_address(self.subject),
            "parent": self.parent,
            "maxTotal": int(self.max_total),
            "maxPerRequest": int(self.max_per_request),
            "allowlistHash": self.allowlist_hash,
            "notBefore": int(self.not_before),
            "expiry": int(self.expiry),
            "maxDepth": int(self.max_depth),
            "salt": self.salt,
        }

    def to_json(self) -> Dict[str, Any]:
        """The wire form: identical to `message()` except the uint256s are decimal strings,
        which is how the gateway's decoder expects them (they do not survive a JSON number)."""
        message = self.message()
        message["maxTotal"] = str(self.max_total)
        message["maxPerRequest"] = str(self.max_per_request)
        return message

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "Capability":
        return cls(
            issuer=raw["issuer"],
            subject=raw["subject"],
            parent=raw["parent"],
            max_total=int(raw["maxTotal"]),
            max_per_request=int(raw["maxPerRequest"]),
            allowlist_hash=raw["allowlistHash"],
            not_before=int(raw["notBefore"]),
            expiry=int(raw["expiry"]),
            max_depth=int(raw["maxDepth"]),
            salt=raw["salt"],
        )

    def full_message(self, chain_id: int) -> Dict[str, Any]:
        return {
            "types": {"EIP712Domain": EIP712_DOMAIN_TYPE, "Capability": CAPABILITY_TYPE},
            "primaryType": "Capability",
            "domain": domain(chain_id),
            "message": self.message(),
        }

    def struct_hash(self, chain_id: int) -> str:
        """EIP-712 hashStruct — the capability's identity, domain-free.

        `SignableMessage.body` is exactly hashStruct; `.header` is the domain separator. This
        is the value the gateway keys Redis counters and `capabilities` rows on, and the value
        a child link carries as its `parent`.
        """
        return "0x" + encode_typed_data(full_message=self.full_message(chain_id)).body.hex()

    def signing_hash(self, chain_id: int) -> str:
        signable = encode_typed_data(full_message=self.full_message(chain_id))
        return "0x" + keccak(b"\x19\x01" + signable.header + signable.body).hex()

    def sign(self, private_key: str, chain_id: int) -> str:
        signable = encode_typed_data(full_message=self.full_message(chain_id))
        return "0x" + Account.sign_message(signable, private_key).signature.hex()


@dataclass
class ChainLink:
    """A signed capability plus the plaintext allowlist that hashes to its `allowlistHash`.

    The plaintext rides along because the hash is one-way and the gateway's subset check
    (`architecture.md` §5.2 rule 4) needs the slugs themselves — the presenter is the only
    party that has them.
    """

    capability: Capability
    signature: str
    allowlist: List[str]

    def to_json(self) -> Dict[str, Any]:
        return {
            "capability": self.capability.to_json(),
            "signature": self.signature,
            "allowlist": list(self.allowlist),
        }

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "ChainLink":
        return cls(
            capability=Capability.from_json(raw["capability"]),
            signature=raw["signature"],
            allowlist=list(raw.get("allowlist") or []),
        )


class CapabilityChain:
    """An ordered chain, root first — the thing an `X-Tollgate-Capability` header carries."""

    def __init__(self, links: Sequence[ChainLink], chain_id: int):
        self.links = list(links)
        self.chain_id = chain_id

    def __len__(self) -> int:
        return len(self.links)

    def __iter__(self):
        return iter(self.links)

    @property
    def leaf(self) -> ChainLink:
        return self.links[-1]

    @property
    def root(self) -> ChainLink:
        return self.links[0]

    def root_hash(self) -> str:
        return self.root.capability.struct_hash(self.chain_id)

    def leaf_hash(self) -> str:
        return self.leaf.capability.struct_hash(self.chain_id)

    def effective_allowlist(self) -> List[str]:
        """The nearest declared allowlist, walking up from the leaf.

        An empty `allowlistHash` means inherit, so the constraint a leaf actually operates
        under may be several links above it.
        """
        for link in reversed(self.links):
            if link.allowlist:
                return list(link.allowlist)
        return []

    def serialize(self) -> str:
        """Base64 of the JSON array — exactly the Task 5.2 header format."""
        return base64.b64encode(
            json.dumps([link.to_json() for link in self.links]).encode()
        ).decode()

    @classmethod
    def deserialize(cls, header: str, chain_id: int) -> "CapabilityChain":
        raw = json.loads(base64.b64decode(header))
        if not isinstance(raw, list) or not raw:
            raise ValueError("capability chain must be a non-empty JSON array")
        return cls([ChainLink.from_json(link) for link in raw], chain_id)

    def __str__(self) -> str:
        # So a chain can be handed straight to `Session(capability=...)`, or to any HTTP
        # client, without the caller remembering to call serialize().
        return self.serialize()


def check_attenuation(parent: ChainLink, child: Capability, child_allowlist: Sequence[str],
                      parent_allowlist: Sequence[str]) -> None:
    """`architecture.md` §5.2 rule 4, applied locally before signing.

    The gateway enforces all of this anyway and remains the security boundary. Checking here
    buys a good error message at the moment the mistake is made, rather than a 400 on the
    child's first request — by which point the parent that made the mistake is elsewhere.
    """
    limits = parent.capability
    if child.max_total > limits.max_total:
        raise AttenuationError(
            f"maxTotal {child.max_total} exceeds the parent's {limits.max_total}"
        )
    if child.max_per_request > limits.max_per_request:
        raise AttenuationError(
            f"maxPerRequest {child.max_per_request} exceeds the parent's {limits.max_per_request}"
        )
    if child.expiry > limits.expiry:
        raise AttenuationError(
            f"expiry {child.expiry} is later than the parent's {limits.expiry}"
        )
    if child.not_before < limits.not_before:
        raise AttenuationError(
            f"notBefore {child.not_before} is earlier than the parent's {limits.not_before}"
        )
    if child.max_depth >= limits.max_depth:
        raise AttenuationError(
            f"maxDepth {child.max_depth} must be strictly below the parent's {limits.max_depth}"
        )
    if child_allowlist and parent_allowlist:
        extra = sorted(set(child_allowlist) - set(parent_allowlist))
        if extra:
            raise AttenuationError(
                f"allowlist adds {extra}, which the parent does not hold"
            )


def build_capability(
    *,
    issuer: str,
    subject: str,
    parent_hash: str,
    max_total: int,
    max_per_request: int,
    allowlist: Sequence[str],
    expiry_seconds: int,
    max_depth: int,
    now: Optional[int] = None,
    not_before: Optional[int] = None,
    salt: Optional[str] = None,
) -> Capability:
    """Assembles an unsigned capability. Split out from signing so tests can pin a vector."""
    current = int(time.time()) if now is None else int(now)
    return Capability(
        issuer=issuer,
        subject=subject,
        parent=parent_hash,
        max_total=max_total,
        max_per_request=max_per_request,
        allowlist_hash=allowlist_hash(allowlist),
        # A minute of slack, so a clock a little behind the gateway's does not produce a
        # capability that is not yet valid at the instant it is handed over.
        not_before=(current - 60) if not_before is None else int(not_before),
        expiry=current + int(expiry_seconds),
        max_depth=max_depth,
        salt=salt or ("0x" + secrets.token_bytes(32).hex()),
    )
