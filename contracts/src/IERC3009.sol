// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice The one EIP-3009 method BatchSettler calls.
///
/// Declared here rather than inside BatchSettler.sol so that file contains exactly one
/// function, which is the property Task 6.1's verification greps for.
///
/// Circle's USDC implements this. The signature is checked by the token, against the payer's
/// own EIP-712 signature over (from, to, value, validAfter, validBefore, nonce) — which is
/// why BatchSettler can be permissionless and untrusted (architecture.md §3.1).
interface IERC3009 {
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}
