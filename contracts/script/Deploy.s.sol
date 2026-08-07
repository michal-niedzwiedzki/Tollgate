// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {BatchSettler} from "../src/BatchSettler.sol";

/// Deploys BatchSettler and logs the address.
///
/// The same script serves the anvil fork and real Base Sepolia (Task 6.6) — there is nothing
/// chain-specific to configure, because the contract takes no constructor arguments and holds
/// no addresses. It learns which token to move from each authorisation it is handed.
///
///   forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast \
///     --private-key $ANVIL_KEY
contract Deploy is Script {
    function run() external returns (BatchSettler settler) {
        vm.startBroadcast();
        settler = new BatchSettler();
        vm.stopBroadcast();

        console2.log("BatchSettler deployed at:", address(settler));
        console2.log("Set BATCH_SETTLER_ADDRESS to that value in .env");
    }
}
