#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose up -d

wait_healthy() {
  local service="$1"
  local attempts=0
  local max_attempts=30
  until [ "$(docker compose ps -q "$service" | xargs docker inspect -f '{{.State.Health.Status}}')" = "healthy" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$max_attempts" ]; then
      echo "timed out waiting for $service to become healthy" >&2
      exit 1
    fi
    sleep 1
  done
  echo "$service is healthy"
}

wait_healthy postgres
wait_healthy redis

: "${DATABASE_URL:=postgres://postgres:postgres@localhost:5432/tollgate}"
sqlx migrate run --database-url "$DATABASE_URL"
