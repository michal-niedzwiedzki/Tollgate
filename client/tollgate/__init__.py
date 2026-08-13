"""tollgate-client — the Python client for the Tollgate x402 payment gateway.

Task 8.1 ships the signing layer only. `Session`, the 402 retry loop and `delegate()`
arrive in Tasks 8.2 and 8.3.
"""

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
