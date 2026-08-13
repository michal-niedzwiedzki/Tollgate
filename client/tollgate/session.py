"""`Session`: 402 → sign → retry → data, in one call.

`prd.md` user story 7 is that an agent "calls a paid endpoint, gets a 402 with
machine-readable payment requirements, signs, retries, and gets the data in the same round
trip". This module is that loop, and nothing more: it holds a signer, pays quotes, and turns
the gateway's refusals into exceptions worth catching.

Two rules shape the design.

**Exactly one retry.** A 402 answered with a payment either succeeds or fails; a second 402
raises rather than looping. An agent that loops on payment failures is the runaway this whole
product exists to prevent, so the client must not be able to become one.

**The server is the security boundary** (`architecture.md` §7.3). The local mirror covers the
per-request cap and expiry only — enough to fail fast with a good message, not a second copy
of the policy engine. Anything it lets through, the gateway still checks.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx
from eth_account import Account

from tollgate import signing
from tollgate.capability import (
    CapabilityChain,
    ChainLink,
    allowlist_hash,
    build_capability,
    check_attenuation,
)
from tollgate.errors import (
    CapabilityExpired,
    CapabilityRejected,
    CapabilityRevoked,
    CapExceeded,
    GatewayError,
    InsufficientBudget,
    NonceReplay,
    PaymentFailed,
    UpstreamFailed,
)

#: Human-facing network names to the CAIP-2 identifiers x402 puts on the wire.
NETWORKS = {
    "base-sepolia": "eip155:84532",
}

_ZERO32 = "0x" + "00" * 32

PAYMENT_HEADER = "X-PAYMENT"
CAPABILITY_HEADER = "X-Tollgate-Capability"
RECEIPT_HEADER = "X-Tollgate-Receipt"

#: Chain-level refusals that name the capability rather than the budget. The gateway sends
#: these as `{"error": {"code": ...}}` with a 400 or 403 (`architecture.md` §4.3).
_CAPABILITY_ERRORS = {
    "capability_expired": CapabilityExpired,
    "capability_revoked": CapabilityRevoked,
    "subject_mismatch": CapabilityRejected,
    "provider_not_allowed": CapabilityRejected,
    "attenuation": CapabilityRejected,
    "broken_chain": CapabilityRejected,
    "invalid_capability_chain": CapabilityRejected,
    "invalid_capability": CapabilityRejected,
}


class Session:
    """A signer, an optional capability, and the 402 loop that uses them.

    `signer` is a private key: this client never holds custody of anything and never talks to
    a wallet service, so the key is the whole identity (`prd.md` §5, "the agent brings its own
    signer").

    `capability` is the base64 chain header a parent produced with `delegate()`. Omitted, the
    session pays as a bare payer, which is the permanent no-delegation path (NOTES.md D1).
    """

    def __init__(
        self,
        signer: str,
        network: str = "base-sepolia",
        capability: Optional[Any] = None,
        *,
        client: Optional[httpx.Client] = None,
        timeout: float = 30.0,
        gateway: Optional[str] = None,
    ):
        if network not in NETWORKS:
            raise ValueError(f"unsupported network {network!r}; known: {sorted(NETWORKS)}")

        self.signer = signer
        self.address = Account.from_key(signer).address
        self.network = network
        self.caip2_network = NETWORKS[network]
        self.chain_id = int(self.caip2_network.split(":")[1])
        # Accepts either the base64 header or the `CapabilityChain` `delegate()` returns, so
        # the architecture.md §7.3 sample's `Session(capability=worker_budget)` just works.
        self.capability = str(capability) if capability is not None else None

        # Where `expense_report()` looks. `get`/`post` take full URLs, so a session that has
        # made a request already knows; one that has only delegated — the supervisor in
        # architecture.md §7.3 — does not, and needs this or the environment to say.
        self.gateway = gateway or os.environ.get("TOLLGATE_GATEWAY")
        self._last_origin: Optional[str] = None

        self._client = client or httpx.Client(timeout=timeout)
        self._receipts: List[Dict[str, Any]] = []
        self._chain = _parse_chain(self.capability, self.chain_id)
        # Roots this session has issued, so `expense_report()` knows what tree to ask about.
        self._issued_roots: List[str] = []
        # The mirror: the leaf's per-request cap and expiry, and nothing else.
        self._max_per_request, self._expiry = _mirror(self._chain)

    # -- public API ---------------------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Sends `method url`, paying for it if the gateway asks.

        Returns the upstream's response. Raises a `TollgateError` subclass if the gateway
        refuses at any point — the response is never handed back with a refusal still in it,
        because a caller checking `.status_code` for that is a caller that will forget to.
        """
        # Expiry is the half of the mirror that needs no quote, so it costs zero requests.
        # Sending a payment under an expired capability is a guaranteed 403.
        self._check_not_expired()
        self._remember_origin(url)

        unpaid = self._client.request(method, url, **kwargs)
        if unpaid.status_code != 402:
            return self._finish(unpaid)

        quote = _parse_quote(unpaid)
        # A 402 carrying a `reason` is a refusal, not a quote. On an unpaid request this is
        # the gateway saying the budget could not cover the charge in the first place.
        self._raise_for_body(unpaid, quote.body)

        # The other half of the mirror. The quote is the first moment the price is known, so
        # this is the earliest an over-cap request can be refused — and refusing here still
        # saves the payment round trip, which is the expensive one.
        self._check_within_per_request_cap(quote)

        paid = self._client.request(
            method, url, **_with_headers(kwargs, self._payment_headers(quote))
        )
        if paid.status_code == 402:
            # Never a second retry: the loop stops here whatever the reason.
            self._raise_for_body(paid, _parse_quote(paid).body, repeat=True)
        return self._finish(paid)

    def delegate(
        self,
        subject: str,
        max_total: str,
        max_per_request: str,
        allowlist: Optional[List[str]] = None,
        expiry_seconds: int = 600,
        max_depth: int = 1,
    ) -> CapabilityChain:
        """Grants `subject` a scoped budget. One local signature, zero HTTP requests.

        That last clause is the feature, not an optimisation: a supervisor can fan out to a
        hundred workers without the gateway ever being in the loop, and the gateway still
        enforces every limit because the limits are inside the signature it will verify.

        Returns the parent's chain plus the new link, root first — ready to hand to a worker
        as `Session(capability=...)`.
        """
        allowlist = list(allowlist or [])
        parent = self._chain.leaf if self._chain else None

        capability = build_capability(
            issuer=self.address,
            subject=subject,
            # A root's parent is 0x0 (NOTES.md D6: not a row, just the sentinel).
            parent_hash=(
                parent.capability.struct_hash(self.chain_id) if parent else _ZERO32
            ),
            max_total=signing.to_base_units(max_total),
            max_per_request=signing.to_base_units(max_per_request),
            allowlist=allowlist,
            expiry_seconds=expiry_seconds,
            max_depth=max_depth,
        )

        if parent is not None:
            check_attenuation(
                parent,
                capability,
                child_allowlist=allowlist,
                parent_allowlist=self._chain.effective_allowlist(),
            )

        link = ChainLink(
            capability=capability,
            signature=capability.sign(self.signer, self.chain_id),
            allowlist=allowlist,
        )
        links = ([*self._chain.links] if self._chain else []) + [link]
        chain = CapabilityChain(links, self.chain_id)
        self._issued_roots.append(chain.root_hash())
        return chain

    def expense_report(self, capability: Optional[Any] = None) -> Dict[str, Any]:
        """The signed spend rollup for this session's tree (`prd.md` user story 8).

        Which tree that is depends on what the session is. A worker holding a chain reports on
        its root. A supervisor holding none reports on the root it issued — and if it issued
        several, it has several trees and must say which, because the endpoint aggregates one
        subtree at a time. A session that has neither reports on its own payer budget.
        """
        params = {"capability": _root_param(capability, self.chain_id)} if capability else None
        if params is None:
            params = {"capability": self._report_root()} if self._report_root() else {
                "payer": self.address
            }

        response = self._client.get(f"{self._gateway_base()}/v1/expense-report", params=params)
        if response.status_code >= 400:
            self._raise_for_body(response, _json_or_none(response))
        return response.json()

    def _report_root(self) -> Optional[str]:
        if self._chain:
            return self._chain.root_hash()
        unique = list(dict.fromkeys(self._issued_roots))
        if len(unique) == 1:
            return unique[0]
        if len(unique) > 1:
            raise ValueError(
                f"this session issued {len(unique)} root capabilities, which are separate "
                f"delegation trees; pass one explicitly as "
                f"expense_report(capability=...): {unique}"
            )
        return None

    def _remember_origin(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            self._last_origin = f"{parts.scheme}://{parts.netloc}"

    def _gateway_base(self) -> str:
        """The gateway this session talks to: explicit, then the environment, then wherever
        its last request went."""
        base = self.gateway or self._last_origin
        if base is None:
            raise ValueError(
                "no gateway known: pass Session(gateway=...), set TOLLGATE_GATEWAY, or make "
                "a request first"
            )
        return base.rstrip("/")

    def receipts(self) -> List[Dict[str, Any]]:
        """Every receipt this session collected, oldest first.

        Each is the decoded `X-Tollgate-Receipt` body: the signed fields plus the gateway's
        signature over them, verifiable against `GET /v1/gateway-key`.
        """
        return list(self._receipts)

    # -- the local mirror ---------------------------------------------------------

    def _check_not_expired(self) -> None:
        if self._expiry is not None and time.time() >= self._expiry:
            raise CapabilityExpired(
                f"capability expired at {self._expiry}; the gateway would refuse this request"
            )

    def _check_within_per_request_cap(self, quote: "Quote") -> None:
        if self._max_per_request is None:
            return
        if quote.amount > self._max_per_request:
            raise CapExceeded(
                f"quoted {quote.amount} exceeds this capability's per-request cap "
                f"{self._max_per_request}",
                status_code=None,
                code="cap_exceeded",
                # Shaped like the gateway's own 429 so a caller's handler does not have to
                # care whether the refusal came from here or from the server.
                body={
                    "reason": "cap_exceeded",
                    "tripped_level": self._leaf_level,
                    "limit": str(self._max_per_request),
                    "chain": [],
                },
            )

    @property
    def _leaf_level(self) -> Optional[int]:
        """Index of the link the mirror describes: the leaf, which is the one this session
        signs as."""
        return len(self._chain) - 1 if self._chain else None

    # -- request plumbing ---------------------------------------------------------

    def _payment_headers(self, quote: "Quote") -> Dict[str, str]:
        payload = signing.sign_payment(
            private_key=self.signer,
            to=quote.pay_to,
            value=quote.amount,
            usdc_address=quote.asset,
            chain_id=quote.chain_id,
            domain_name=quote.domain_name,
            domain_version=quote.domain_version,
        )
        headers = {PAYMENT_HEADER: signing.encode_payment_header(payload)}
        if self.capability:
            headers[CAPABILITY_HEADER] = self.capability
        return headers

    def _finish(self, response: httpx.Response) -> httpx.Response:
        self._collect_receipt(response)
        if response.status_code >= 400:
            self._raise_for_body(response, _json_or_none(response))
        return response

    def _collect_receipt(self, response: httpx.Response) -> None:
        header = response.headers.get(RECEIPT_HEADER)
        if not header:
            return
        try:
            self._receipts.append(json.loads(base64.b64decode(header)))
        except (ValueError, json.JSONDecodeError):
            # A receipt this client cannot parse is worth ignoring rather than failing the
            # request over: the caller already has its data, and the ledger has its own copy.
            pass

    def _raise_for_body(
        self,
        response: httpx.Response,
        body: Optional[Dict[str, Any]],
        *,
        repeat: bool = False,
    ) -> None:
        """Maps a refusal onto its exception. Returns without raising if there is none."""
        body = body or {}
        status = response.status_code
        reason = body.get("reason")
        error = body.get("error") or {}
        code = error.get("code") if isinstance(error, dict) else None
        message = (
            error.get("message") if isinstance(error, dict) else None
        ) or body.get("error")

        # A 402 with no `reason` is the quote itself, which is the protocol working, not a
        # refusal. Only a repeat 402 — one that answered a payment — is an error.
        if status == 402 and reason is None and not repeat:
            return

        if status == 402 and reason == "insufficient_funds":
            raise InsufficientBudget(
                message or "insufficient budget", status_code=status, code=reason, body=body
            )
        if status == 402 and repeat:
            raise PaymentFailed(
                message or "the gateway did not accept the payment",
                status_code=status,
                code=reason or code,
                body=body,
            )
        if status == 429 and reason == "cap_exceeded":
            raise CapExceeded(
                message or "per-request cap exceeded",
                status_code=status,
                code=reason,
                body=body,
            )
        if status == 409:
            raise NonceReplay(
                message or "payment authorization already used",
                status_code=status,
                code=code,
                body=body,
            )
        if code in _CAPABILITY_ERRORS:
            raise _CAPABILITY_ERRORS[code](
                message or code, status_code=status, code=code, body=body
            )
        if status in (502, 504):
            raise UpstreamFailed(
                message or "upstream failed", status_code=status, code=code, body=body
            )
        if status >= 400:
            raise GatewayError(
                message or f"gateway returned {status}",
                status_code=status,
                code=code or reason,
                body=body,
            )


class Quote:
    """The one payment requirement this client pays: `accepts[0]` of a 402 body.

    Everything needed to sign comes from here rather than from client configuration — the
    asset, the chain and the EIP-712 domain included — which is what lets the same client pay
    a gateway it was never configured for. That is the x402 interop claim in miniature.
    """

    def __init__(self, body: Dict[str, Any], requirement: Dict[str, Any]):
        self.body = body
        self.requirement = requirement
        self.amount = int(requirement["maxAmountRequired"])
        self.pay_to = requirement["payTo"]
        self.asset = requirement["asset"]
        self.network = requirement["network"]
        extra = requirement.get("extra") or {}
        self.domain_name = extra.get("name", signing.USDC_EIP712_NAME)
        self.domain_version = extra.get("version", signing.USDC_EIP712_VERSION)

    @property
    def chain_id(self) -> int:
        return int(self.network.split(":")[1])


def _parse_quote(response: httpx.Response) -> Quote:
    body = _json_or_none(response) or {}
    accepts = body.get("accepts") or []
    if not accepts:
        raise PaymentFailed(
            "402 response carried no payment requirements",
            status_code=response.status_code,
            body=body,
        )
    return Quote(body, accepts[0])


def _json_or_none(response: httpx.Response) -> Optional[Dict[str, Any]]:
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return None
    return body if isinstance(body, dict) else None


def _with_headers(kwargs: Dict[str, Any], extra: Dict[str, str]) -> Dict[str, Any]:
    merged = dict(kwargs)
    merged["headers"] = {**(kwargs.get("headers") or {}), **extra}
    return merged


def _parse_chain(capability: Optional[str], chain_id: int) -> Optional[CapabilityChain]:
    """Deliberately forgiving: a chain this cannot parse yields `None` rather than raising,
    because everything the client does with it is an optimisation and the gateway is the
    authority. A malformed chain still gets rejected, just one round trip later and by the
    component whose job it is to decide."""
    if not capability:
        return None
    try:
        return CapabilityChain.deserialize(capability, chain_id)
    except (ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None


def _mirror(chain: Optional[CapabilityChain]):
    """The leaf's per-request cap and expiry — the only policy this client copies."""
    if chain is None:
        return None, None
    leaf = chain.leaf.capability
    return leaf.max_per_request, leaf.expiry


def _root_param(capability: Any, chain_id: int) -> str:
    """A capability hash for the expense-report query, from a hash, a chain, or a header."""
    if isinstance(capability, CapabilityChain):
        return capability.root_hash()
    text = str(capability)
    if text.startswith("0x") and len(text) == 66:
        return text
    chain = _parse_chain(text, chain_id)
    if chain is None:
        raise ValueError(f"not a capability hash or chain: {text[:32]}…")
    return chain.root_hash()
