#!/usr/bin/env bash
#
# Starts a local anvil fork of Base Sepolia and funds a test EOA with ETH and real forked USDC,
# so integration tests get genuine USDC semantics (EIP-712 verification, authorizationState
# replay guard, balance accounting) without waiting on a faucet.
#
# Runs in the foreground once the fork is ready, so `./scripts/anvil.sh &` backgrounds the chain
# and `kill %1` stops it. anvil's own output goes to $ANVIL_LOG.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# `plan.md` Task 6.3 names BASE_SEPOLIA_RPC; the gateway's own config calls the same thing
# RPC_URL. Kept under the plan's name here, defaulted to the public endpoint so no key is needed.
: "${BASE_SEPOLIA_RPC:=https://sepolia.base.org}"
: "${ANVIL_PORT:=8545}"
: "${ANVIL_LOG:=/tmp/tollgate-anvil.log}"
: "${USDC_ADDRESS:=0x036CbD53842c5426634e7929541eC2318f3dCF7e}"
: "${USDC_FUND_UNITS:=1000000000}" # 1,000 USDC at 6 decimals

# A throwaway key used only against this fork. It is committed deliberately: it holds nothing on
# any real chain, and the address must be stable so tests and the seed data agree on who pays.
#
# It is NOT one of anvil's ten default accounts. Every one of those has EIP-7702 delegation code
# deployed at its address on real Base Sepolia, and USDC's SignatureChecker sends any `from` with
# code down the ERC-1271 path instead of ecrecover — so an anvil default cannot sign a working
# EIP-3009 payment on a fork of this chain. The check below enforces that this one stays clean.
: "${TEST_EOA_KEY:=0x0014a3fee49588a8c064872feda5362fc74656295fc0de7b80c8edd0c2e9de6c}"

RPC="http://127.0.0.1:${ANVIL_PORT}"

# FiatToken packs balance and blacklist flag into `balanceAndBlacklistStates` at slot 9. Writing
# a plain value funds the account and leaves the top (blacklist) bit clear.
USDC_BALANCE_SLOT=9

for binary in anvil cast; do
  command -v "$binary" >/dev/null 2>&1 || {
    echo "$binary is not on PATH. Install Foundry (https://getfoundry.sh) or add ~/.foundry/bin." >&2
    exit 1
  }
done

TEST_EOA="$(cast wallet address --private-key "$TEST_EOA_KEY")"

# --chain-id 84532 is required, not cosmetic. anvil would otherwise report 31337, and every
# EIP-3009 and capability signature this project makes commits to chain 84532 inside its EIP-712
# domain, so they would all fail to verify against the forked USDC.
anvil --fork-url "$BASE_SEPOLIA_RPC" --chain-id 84532 --port "$ANVIL_PORT" >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true' EXIT INT TERM

attempts=0
until cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 60 ] || ! kill -0 "$ANVIL_PID" 2>/dev/null; then
    echo "anvil did not become ready; see $ANVIL_LOG" >&2
    exit 1
  fi
  sleep 1
done

CHAIN_ID="$(cast chain-id --rpc-url "$RPC")"
if [ "$CHAIN_ID" != "84532" ]; then
  echo "fork reports chain id $CHAIN_ID, expected 84532" >&2
  exit 1
fi

# 1 ETH for gas.
cast rpc anvil_setBalance "$TEST_EOA" 0xDE0B6B3A7640000 --rpc-url "$RPC" >/dev/null

# USDC. `anvil_dealERC20` cannot do this one — it fails with "no slot found" because native USDC
# is a FiatToken behind a proxy — so the balance slot is written directly.
SLOT="$(cast index address "$TEST_EOA" "$USDC_BALANCE_SLOT")"
cast rpc anvil_setStorageAt "$USDC_ADDRESS" "$SLOT" "$(cast to-uint256 "$USDC_FUND_UNITS")" \
  --rpc-url "$RPC" >/dev/null

FUNDED="$(cast call "$USDC_ADDRESS" 'balanceOf(address)(uint256)' "$TEST_EOA" --rpc-url "$RPC")"
if [ "${FUNDED%% *}" != "$USDC_FUND_UNITS" ]; then
  echo "USDC funding failed: balanceOf returned '$FUNDED', expected $USDC_FUND_UNITS" >&2
  exit 1
fi

CODE="$(cast code "$TEST_EOA" --rpc-url "$RPC")"
if [ "$CODE" != "0x" ]; then
  echo "test EOA $TEST_EOA has code on the fork, so USDC will treat its signatures as ERC-1271" >&2
  echo "and every EIP-3009 payment from it will fail. Choose a different TEST_EOA_KEY." >&2
  exit 1
fi

cat <<EOF

  anvil fork of Base Sepolia is up
  ---------------------------------------------------------------
  RPC            $RPC
  chain id       $CHAIN_ID
  forked from    $BASE_SEPOLIA_RPC
  anvil log      $ANVIL_LOG

  test EOA       $TEST_EOA
  private key    $TEST_EOA_KEY
  ETH            1
  USDC           $USDC_FUND_UNITS ($USDC_ADDRESS)

  Deploy BatchSettler into it:
    cd contracts && forge script script/Deploy.s.sol --rpc-url $RPC --broadcast \\
      --private-key \$ANVIL_KEY

  Ctrl-C, or kill %1 if you backgrounded this, stops the chain.

EOF

wait "$ANVIL_PID"
