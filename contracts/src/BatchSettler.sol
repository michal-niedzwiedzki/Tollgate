// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC3009} from "./IERC3009.sol";

/// @title BatchSettler
/// @notice Submits many EIP-3009 authorisations in one transaction. It is a pass-through and
///         nothing else: every authorisation was signed by its payer, naming the recipient and
///         the amount, and USDC verifies that signature itself when this contract forwards it.
///
/// What this contract deliberately does not have, and why (architecture.md §6):
///
/// - **No owner, no admin role.** There is no privileged caller, so there is no key whose loss
///   or compromise matters. `settle` is permissionless: anyone may submit a batch, which is safe
///   because every item is signature-gated by the token. This is also why the settler's hot key
///   (architecture.md §12) is not a trusted component.
/// - **No pause.** A pause would be a way for one party to stop other people's signed payments
///   from settling, which is the opposite of what a pass-through is for.
/// - **No upgradeability, no proxy.** The bytecode that gets audited is the bytecode that runs.
/// - **No withdraw, and no balance to withdraw.** The contract never holds funds: USDC moves
///   directly from the payer to the payee named inside the payer's own signature. There is no
///   custody here, which is the regulatory shape prd.md §11 depends on.
/// - **It cannot redirect a payment.** `to` and `value` live inside the payer's signature and
///   are checked by USDC, not by this contract.
///
/// The one piece of real logic is **skip and continue, not revert all**. A batch of 50 in which
/// one nonce is already spent must settle the other 49. Reverting the batch would make a single
/// stale authorisation a griefing vector against every other charge in it — the v1 design flaw
/// this contract exists to fix. Failures emit an event and are requeued individually off-chain.
contract BatchSettler {
    struct Auth {
        address token; // USDC
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    event Settled(bytes32 indexed nonce);
    event SettleFailed(bytes32 indexed nonce, bytes reason);

    function settle(Auth[] calldata auths) external {
        for (uint256 i; i < auths.length; ++i) {
            try IERC3009(auths[i].token).transferWithAuthorization(
                auths[i].from,
                auths[i].to,
                auths[i].value,
                auths[i].validAfter,
                auths[i].validBefore,
                auths[i].nonce,
                auths[i].v,
                auths[i].r,
                auths[i].s
            ) {
                emit Settled(auths[i].nonce);
            } catch (bytes memory reason) {
                emit SettleFailed(auths[i].nonce, reason);
            }
        }
    }
}
