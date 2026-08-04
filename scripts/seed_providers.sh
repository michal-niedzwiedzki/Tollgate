#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
PAYOUT_ADDRESS="${PAYOUT_ADDRESS:-0x0000000000000000000000000000000000000001}"

register() {
  local slug="$1" price="$2" timeout_ms="$3"
  local body
  body=$(cat <<EOF
{"slug":"$slug","upstream_url":"http://127.0.0.1:9000","price":"$price","payout_address":"$PAYOUT_ADDRESS","timeout_ms":$timeout_ms}
EOF
)
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/v1/providers" \
    -H 'content-type: application/json' \
    -d "$body")
  echo "registered $slug -> $status"
}

register "mock-ok" "0.001" 30000
register "mock-slow" "0.001" 1000
register "mock-fail" "0.001" 30000
