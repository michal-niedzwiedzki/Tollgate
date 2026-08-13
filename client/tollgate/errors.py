"""Typed exceptions, one per way the gateway says no.

An agent that catches a refusal has to be able to act on it, and the useful distinction is
not the HTTP status but *what ran out*. A per-request cap violation (429) means "this call
was too big, a smaller one would work"; an exhausted total budget (402) means "stop". Both
are "cap" in casual speech and they call for opposite behaviour, so they are separate types
here. NOTES.md D11 records the same split on the gateway side.

Every exception carries the parsed response body, so a caller that wants a field this module
did not promote to an attribute can still reach it without re-parsing anything.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class TollgateError(Exception):
    """Base class for every error this client raises."""


class GatewayError(TollgateError):
    """A refusal from the gateway, carrying the response that explained it."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        body: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.body = body or {}


class InsufficientBudget(GatewayError):
    """402 `insufficient_funds`: a total cap is exhausted. Retrying will not help.

    `tripped_level` names which link of the capability chain said no — the supervisor's
    root, not the worker's own leaf, when a shared pool is what emptied.
    """

    def __init__(self, message: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.tripped_level: Optional[int] = self.body.get("tripped_level")
        self.capability_hash: Optional[str] = self.body.get("capability_hash")
        self.chain: List[Dict[str, Any]] = self.body.get("chain", [])
        self.remaining: Optional[str] = _remaining_at(self.chain, self.tripped_level)


class CapExceeded(GatewayError):
    """429 `cap_exceeded`: this single charge is larger than a per-request cap allows.

    Distinct from `InsufficientBudget` because the budget is not gone — a smaller request
    would still succeed.
    """

    def __init__(self, message: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.tripped_level: Optional[int] = self.body.get("tripped_level")
        self.capability_hash: Optional[str] = self.body.get("capability_hash")
        self.limit: Optional[str] = self.body.get("limit")
        self.chain: List[Dict[str, Any]] = self.body.get("chain", [])
        self.remaining: Optional[str] = _remaining_at(self.chain, self.tripped_level)


class CapabilityExpired(GatewayError):
    """403 `capability_expired`, or the same conclusion reached locally before sending."""


class CapabilityRevoked(GatewayError):
    """403 `capability_revoked`. An ancestor's revocation refuses its descendants too."""


class CapabilityRejected(GatewayError):
    """Any other refusal of the chain itself: `subject_mismatch`, `provider_not_allowed`,
    `attenuation`, `broken_chain`, `invalid_capability_chain`."""


class NonceReplay(GatewayError):
    """409: this authorisation was already claimed. Signing a fresh nonce is the fix."""


class UpstreamFailed(GatewayError):
    """502/504: the provider's own service failed or timed out.

    The reservation is voided and the budget credited back, so nothing was spent — but the
    nonce stays claimed, so the *same* payment cannot be re-presented (`plan.md` Task 4.4).
    """


class PaymentFailed(GatewayError):
    """A payment the gateway would not accept: a second 402 that is not `insufficient_funds`.

    Task 8.2 forbids retrying more than once, so this is where an unexpected repeat 402
    surfaces rather than becoming a loop. In practice it means the signed payload was
    rejected — a stale quote, a clock far out of skew, or a signature over the wrong domain.
    """


def _remaining_at(chain: List[Dict[str, Any]], level: Optional[int]) -> Optional[str]:
    """The tripped level's remaining budget, lifted out of the per-level chain snapshot."""
    if level is None or not isinstance(level, int):
        return None
    if 0 <= level < len(chain):
        return chain[level].get("remaining")
    return None
