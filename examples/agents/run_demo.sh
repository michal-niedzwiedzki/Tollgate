#!/usr/bin/env bash
#
# The `prd.md` §9 demo, end to end: a supervisor signs three delegations, three workers run
# concurrently, worker-2 hits its cap and stops while 1 and 3 finish, and the supervisor prints
# a signed expense report covering the whole tree.
#
# Expects the stack already running — ./scripts/dev.sh, the gateway, and the mock upstream. It
# checks for all three rather than starting them, so a failure says which one is missing instead
# of leaving orphaned processes behind. Open the delegation tree it prints before the workers
# start if you want to watch the budgets drain live.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

GATEWAY="${TOLLGATE_GATEWAY:-http://localhost:8080}"
MOCK_UPSTREAM="${MOCK_UPSTREAM:-http://127.0.0.1:9000}"
PYTHON="${PYTHON:-python3}"
export TOLLGATE_GATEWAY="$GATEWAY"

require() {
  curl -sf -m 5 -o /dev/null "$1" || {
    echo "$2" >&2
    exit 1
  }
}

require "$GATEWAY/health" "gateway is not answering at $GATEWAY — run: cargo run -p tollgate-gateway"
require "$MOCK_UPSTREAM/ok" "mock upstream is not answering at $MOCK_UPSTREAM — run: python3 examples/mock_upstream.py &"

if ! curl -sf -m 5 -o /dev/null "$GATEWAY/v1/providers/mock-ok"; then
  echo "registering the mock providers"
  ../../scripts/seed_providers.sh
fi

echo
echo "=== supervisor: signing three delegations ==="
"$PYTHON" supervisor.py setup

echo
echo "=== workers: running concurrently ==="
pids=()
for worker in worker-1 worker-2 worker-3; do
  "$PYTHON" worker.py "$worker" &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done
[ "$status" -eq 0 ] || {
  echo "a worker exited non-zero" >&2
  exit 1
}

echo
echo "=== supervisor: signed expense report ==="
"$PYTHON" supervisor.py report
