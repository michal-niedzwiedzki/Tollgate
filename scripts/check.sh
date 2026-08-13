#!/usr/bin/env bash
# Every check, across all four languages. Task 9.5.
#
# `CLAUDE.md` names the Rust two as the pre-commit bar and says later phases add `forge test`,
# `pytest` and `npm run build` here. This is that file.
#
# What it does not do: bring the stack up. `cargo test` runs only the non-ignored tests, and the
# Python suite skips its live-gateway tests when nothing is listening (each module guards with
# `stack_is_up` — 71 passed, 13 skipped with the gateway down). So it runs green without Postgres,
# Redis or the gateway; it just does not exercise the integration paths. For those, run
# ./scripts/dev.sh and the gateway first, then `cargo test --workspace -- --ignored` and
# `pytest client/tests/ -k integration`.
#
# It does need the network. `forge test` forks Base Sepolia through the public endpoint in
# contracts/foundry.toml (Task 6.2 runs against real native USDC rather than a mock), which is
# also why that section takes ~60s and why it is the one that fails offline.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

section() {
  echo
  echo "=== $1 ==="
}

section "rust: clippy"
cargo clippy --workspace -- -D warnings

section "rust: tests"
cargo test --workspace

section "solidity: forge test"
if command -v forge >/dev/null; then
  (cd contracts && forge test)
else
  echo "forge not installed; skipping (see README for foundryup)" >&2
fi

section "python: pytest"
# Prefer the repo's virtualenv when it exists, so the client is importable without the caller
# having activated anything.
if [ -x .venv/bin/pytest ]; then
  .venv/bin/pytest client/tests/
elif command -v pytest >/dev/null; then
  pytest client/tests/
else
  echo "pytest not installed; skipping (pip install -e 'client/[dev]')" >&2
fi

section "typescript: lint, types, build"
cd dashboard
npm run lint
npx tsc --noEmit
npm run build

echo
echo "all checks passed"
