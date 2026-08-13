"""tollgate-client — the Python client for the Tollgate x402 payment gateway.

Signing, the 402 retry loop, and local capability delegation.
"""

from tollgate.capability import (
    Capability,
    CapabilityChain,
    ChainLink,
    allowlist_hash,
)
from tollgate.errors import (
    AttenuationError,
    CapabilityExpired,
    CapabilityRejected,
    CapabilityRevoked,
    CapExceeded,
    GatewayError,
    InsufficientBudget,
    NonceReplay,
    PaymentFailed,
    TollgateError,
    UpstreamFailed,
)
from tollgate.session import Session
from tollgate.signing import (
    DEFAULT_CHAIN_ID,
    DEFAULT_VALIDITY_SECONDS,
    USDC_DECIMALS,
    USDC_EIP712_NAME,
    USDC_EIP712_VERSION,
    build_authorization,
    caip2_network,
    encode_payment_header,
    random_nonce,
    sign_payment,
    to_base_units,
    transfer_with_authorization_message,
)

__all__ = [
    "AttenuationError",
    "Capability",
    "CapabilityChain",
    "ChainLink",
    "allowlist_hash",
    "CapExceeded",
    "CapabilityExpired",
    "CapabilityRejected",
    "CapabilityRevoked",
    "GatewayError",
    "InsufficientBudget",
    "NonceReplay",
    "PaymentFailed",
    "Session",
    "TollgateError",
    "UpstreamFailed",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_VALIDITY_SECONDS",
    "USDC_DECIMALS",
    "USDC_EIP712_NAME",
    "USDC_EIP712_VERSION",
    "build_authorization",
    "caip2_network",
    "encode_payment_header",
    "random_nonce",
    "sign_payment",
    "to_base_units",
    "transfer_with_authorization_message",
]
