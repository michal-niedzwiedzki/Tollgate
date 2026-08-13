// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {BatchSettler} from "../src/BatchSettler.sol";

interface IUSDC {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function balanceOf(address account) external view returns (uint256);
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
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

/// Run against real native USDC on a Base Sepolia fork rather than a mock token.
///
/// The mock option the task allows would prove skip-and-continue just as well, but the gas it
/// reported would be the gas of a token nobody settles against, and prd.md §8 asks for the
/// settlement cost to be measured rather than estimated. Against the real token the EIP-712
/// verification, the `authorizationState` storage write and the balance writes are all the ones
/// that will actually execute in Task 6.6.
contract BatchSettlerTest is Test {
    /// Native USDC on Base Sepolia (84532), not bridged USDC.e — prd.md decision #3.
    /// Confirmed on-chain before use: symbol "USDC", EIP-712 domain version "2".
    address constant USDC = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    /// FiatToken keeps balances in `balanceAndBlacklistStates` at slot 9: the top bit is the
    /// blacklist flag and the low bits are the balance, so writing a plain value both funds the
    /// account and leaves it un-blacklisted. This is how the tests get USDC without a faucet.
    uint256 constant BALANCE_SLOT = 9;

    bytes32 constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /// 0.001 USDC in base units — the price scripts/seed_providers.sh registers.
    uint256 constant PRICE = 1000;

    bytes32 constant SETTLED_TOPIC = keccak256("Settled(bytes32)");
    bytes32 constant SETTLE_FAILED_TOPIC = keccak256("SettleFailed(bytes32,bytes)");

    BatchSettler settler;
    address payee = makeAddr("provider-payout");

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("base_sepolia"));
        settler = new BatchSettler();
    }

    function _fund(address who, uint256 amount) internal {
        vm.store(USDC, keccak256(abi.encode(who, BALANCE_SLOT)), bytes32(amount));
    }

    /// Builds one authorisation signed by `pk`, exactly as the gateway's payers sign it.
    function _auth(uint256 pk, bytes32 nonce) internal view returns (BatchSettler.Auth memory) {
        address from = vm.addr(pk);
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 300;

        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, payee, PRICE, validAfter, validBefore, nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", IUSDC(USDC).DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        return BatchSettler.Auth({
            token: USDC,
            from: from,
            to: payee,
            value: PRICE,
            validAfter: validAfter,
            validBefore: validBefore,
            nonce: nonce,
            v: v,
            r: r,
            s: s
        });
    }

    /// One funded payer plus its signed authorisation.
    ///
    /// The payer is derived from a label rather than a small fixed key on purpose. Low-numbered
    /// private keys have contracts deployed at their addresses on real Base Sepolia, and USDC's
    /// SignatureChecker routes any `from` that has code to ERC-1271 instead of `ecrecover` — so
    /// such a payer fails with "invalid signature" no matter how the payload is signed. The
    /// assertion below keeps that from ever silently reappearing.
    function _fundedAuth(string memory label, bytes32 nonce) internal returns (BatchSettler.Auth memory) {
        (address payer, uint256 pk) = makeAddrAndKey(label);
        assertEq(payer.code.length, 0, "payer must be an EOA on the fork, not a deployed contract");
        _fund(payer, PRICE);
        return _auth(pk, nonce);
    }

    function _countEvents() internal view returns (uint256 settled, uint256 failed) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(settler)) continue;
            if (logs[i].topics[0] == SETTLED_TOPIC) settled++;
            if (logs[i].topics[0] == SETTLE_FAILED_TOPIC) failed++;
        }
    }

    function test_three_valid_auths_all_settle() public {
        BatchSettler.Auth[] memory auths = new BatchSettler.Auth[](3);
        auths[0] = _fundedAuth("payer-a1", bytes32(uint256(1)));
        auths[1] = _fundedAuth("payer-a2", bytes32(uint256(2)));
        auths[2] = _fundedAuth("payer-a3", bytes32(uint256(3)));

        vm.recordLogs();
        settler.settle(auths);
        (uint256 settled, uint256 failed) = _countEvents();

        assertEq(settled, 3, "three Settled events");
        assertEq(failed, 0, "no failures");
        assertEq(IUSDC(USDC).balanceOf(payee), 3 * PRICE, "payee received all three charges");
        for (uint256 i; i < 3; ++i) {
            assertEq(IUSDC(USDC).balanceOf(auths[i].from), 0, "payer debited");
        }
    }

    /// The griefing case. In v1 one stale nonce reverted the whole batch, so any agent able to
    /// get one into a batch of 200 could block the other 199. Skip-and-continue is the fix, and
    /// this is the test that proves it.
    function test_a_used_nonce_does_not_revert_the_batch() public {
        BatchSettler.Auth[] memory auths = new BatchSettler.Auth[](3);
        auths[0] = _fundedAuth("payer-b1", bytes32(uint256(11)));
        auths[1] = _fundedAuth("payer-b2", bytes32(uint256(12)));
        auths[2] = _fundedAuth("payer-b3", bytes32(uint256(13)));

        // Spend item 2's nonce on-chain first, the way a duplicate submission would.
        BatchSettler.Auth memory used = auths[1];
        IUSDC(USDC).transferWithAuthorization(
            used.from, used.to, used.value, used.validAfter, used.validBefore, used.nonce, used.v, used.r, used.s
        );
        assertTrue(IUSDC(USDC).authorizationState(used.from, used.nonce), "nonce is spent before the batch");
        _fund(used.from, PRICE); // refund it, so only the nonce — not the balance — can fail

        vm.recordLogs();
        settler.settle(auths); // must not revert
        (uint256 settled, uint256 failed) = _countEvents();

        assertEq(settled, 2, "items 1 and 3 still settle");
        assertEq(failed, 1, "one SettleFailed for the spent nonce");
        assertEq(IUSDC(USDC).balanceOf(auths[0].from), 0, "item 1 was debited");
        assertEq(IUSDC(USDC).balanceOf(auths[2].from), 0, "item 3 was debited");
        assertEq(IUSDC(USDC).balanceOf(used.from), PRICE, "item 2 was not charged twice");
    }

    function test_a_batch_of_fifty_valid_auths_succeeds() public {
        uint256 n = 50;
        BatchSettler.Auth[] memory auths = new BatchSettler.Auth[](n);
        for (uint256 i; i < n; ++i) {
            auths[i] = _fundedAuth(string.concat("payer-batch-", vm.toString(i)), bytes32(uint256(0x5000 + i)));
        }

        vm.recordLogs();
        uint256 before = gasleft();
        settler.settle(auths);
        uint256 gasUsed = before - gasleft();
        (uint256 settled, uint256 failed) = _countEvents();

        assertEq(settled, n, "all fifty settle");
        assertEq(failed, 0, "no failures");
        assertEq(IUSDC(USDC).balanceOf(payee), n * PRICE, "payee received all fifty charges");

        // The number the README's cost arithmetic is built from. Execution gas only: the ~21k
        // intrinsic cost of the transaction is on top, and amortised across the batch.
        console2.log("settle(50) execution gas:", gasUsed);
        console2.log("execution gas per charge:", gasUsed / n);
    }

    function test_an_empty_batch_is_a_noop() public {
        BatchSettler.Auth[] memory auths = new BatchSettler.Auth[](0);

        vm.recordLogs();
        settler.settle(auths); // must not revert
        (uint256 settled, uint256 failed) = _countEvents();

        assertEq(settled, 0, "nothing settled");
        assertEq(failed, 0, "nothing failed");
    }
}
