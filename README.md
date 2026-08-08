# Tollgate

**Spend control and provable receipts for agent API payments, on x402.**

Tollgate is an x402-compatible API gateway that adds the three things the x402 protocol leaves out:
hard spend caps enforced before the upstream call, sub-agent budget delegation via signed EIP-712
capability chains, and signed per-charge receipts.

The payment rail is x402. Tollgate is the control plane on top of it. See `prd.md` for the product
case, `architecture.md` for the design, and `plan.md` for the build plan.

---

## Build status

Phases 0–5 of `plan.md` are complete and committed. The gateway serves the full paid-request path
with delegation; **settlement is not built yet**, so charges reach `status = 'queued'` in Postgres
and stop there.

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, Docker Compose, config, pools, `/health` | ✅ complete |
| 1 | Postgres schema, provider registry, mock upstream | ✅ complete |
| 2 | x402 402 responder, header decode, field validation, EIP-3009 recovery, metrics | ✅ complete |
| 3 | Atomic Lua claim, policy module, status codes, reservation-stream drain | ✅ complete |
| 4 | SSRF resolve/validate/pin, streaming proxy, promote-or-void | ✅ complete |
| 5 | Capability EIP-712 type, chain decode + verification, multi-level decrement, revocation, boot rebuild | ✅ complete |
| 6 | `BatchSettler` contract and settler worker | ⬜ not started |
| 7 | Signed receipts and expense report | ⬜ not started |
| 8 | Python client library | ⬜ not started |
| 9 | Dashboard | ⬜ not started |
| 10 | Demo agents and hardening | ⬜ not started |

`crates/tollgate-settler` is still the `cargo new` stub. `GATEWAY_SIGNING_KEY`,
`BATCH_SETTLER_ADDRESS` and `RPC_URL` are read at startup but nothing consumes them yet, so
placeholders are fine until Phase 6.

**Requirements status:** `prd.md` F1, F2, F3, F4 and F7 are implemented. F5 (settlement), F6
(receipts), F8 (dashboard) and F9 (client) are not.

---

## What works today

A worker agent with its own keypair calls a paid endpoint through the gateway and gets data back,
having paid for it, with every cap in its delegation chain enforced atomically before the upstream
was ever contacted:

```
1.  GET /v1/proxy/mock-ok/ok                    -> 402 + x402 payment requirements
2.  same request
    X-PAYMENT: <base64 EIP-3009 authorisation>
    X-Tollgate-Capability: <base64 capability chain>   (optional)
                                                -> 200 + real upstream body
```

Between those two lines the gateway does, in this order — cheap checks before crypto, crypto before
the Redis round-trip, and never an upstream call before the claim succeeds:

1. decode the `X-PAYMENT` header (base64 → JSON → typed)
2. seven cheap field checks (expiry, validity window, network, scheme, `payTo`, amount)
3. EIP-3009 signature recovery with `alloy`, high-`s` rejected, recovered address must equal
   `authorization.from`
4. capability chain walk: depth, signatures, parent links, attenuation, subject binding, revocation,
   expiry, allowlist
5. **one** Lua script: nonce claim + per-level cap checks + per-level decrement + reservation
   `XADD`, all atomic
6. proxy to the upstream over a pinned-IP connector, response streamed back
7. 2xx promotes the reservation to `queued`; anything else voids it and credits every level back

---

## Quick start

### Prerequisites

- Rust stable (built against 1.93.1; `rust-toolchain.toml` pins the channel)
- Docker and Docker Compose
- `sqlx-cli` (`cargo install sqlx-cli --no-default-features --features postgres`)
- Python 3 with `eth-account`, for the signing harness (`.venv` in this repo has it)

### 1. Bring up Postgres and Redis

```bash
./scripts/dev.sh
```

This runs `docker compose up -d`, waits for both healthchecks, and applies the migrations with
`sqlx migrate run`. Redis runs with `--appendonly yes --appendfsync everysec`, which
`architecture.md` §9.3 requires — the reservation stream is a crash bridge and an unflushed AOF
would defeat it.

### 2. Configure the environment

There is no dotenv loader in the binary — `Config::from_env` reads the process environment only, and
fails loudly at startup on any missing required variable rather than defaulting a secret. Copy the
template and source it:

```bash
cp .env.example .env
set -a; source .env; set +a
```

`.env` is gitignored. Every variable is documented in `.env.example`; the full reference is
[below](#configuration).

### 3. Run the gateway

```bash
cargo run -p tollgate-gateway
curl -s localhost:8080/health     # {"status":"ok","postgres":true,"redis":true}
```

The gateway self-migrates on boot (`sqlx::migrate!`), `SCRIPT LOAD`s the claim script so the first
paid request pays for an `EVALSHA` and not a `NOSCRIPT` round-trip, rebuilds every capability spend
counter from Postgres **before** binding the listener, then starts the reservation drain.

### 4. Start the mock upstream and register providers

```bash
python3 examples/mock_upstream.py &
TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true cargo run -p tollgate-gateway   # see the SSRF note
./scripts/seed_providers.sh
```

`examples/mock_upstream.py` is a stdlib-only server on `http://127.0.0.1:9000`:

| Route | Behaviour |
|---|---|
| `GET /ok` | `200 {"result":"ok"}` |
| `GET /slow` | sleeps 5s, then `200` — exercises the timeout path |
| `GET /fail` | `500` — exercises the void path |
| `GET /echo` | `200`, echoing received headers and query |

`scripts/seed_providers.sh` registers `mock-ok`, `mock-slow` (`timeout_ms: 1000`) and `mock-fail`
against it, all priced at `0.001` USDC.

---

## Walkthrough: an unpaid request becomes a paid one

### The 402

```bash
curl -si localhost:8080/v1/proxy/mock-ok/ok
```

```json
{
  "x402Version": 1,
  "accepts": [{
    "scheme": "exact",
    "network": "eip155:84532",
    "maxAmountRequired": "1000",
    "asset": "0x…USDC",
    "payTo": "0x…provider payout address",
    "resource": "http://localhost:8080/v1/proxy/mock-ok/ok",
    "description": "",
    "mimeType": "",
    "maxTimeoutSeconds": 300,
    "extra": { "name": "USDC", "version": "2" }
  }],
  "error": "payment required"
}
```

Spec-shaped deliberately: `network` is CAIP-2 and comes from `CHAIN_ID`, amounts are base-unit
decimal strings, `extra` carries the EIP-712 domain a client needs to sign against USDC, and
`maxTimeoutSeconds` is `QUOTE_VALIDITY_SECONDS`. The exact key casing is pinned by a fixture at
`crates/tollgate-gateway/tests/fixtures/x402_402_response.json`, so a field rename breaks a test.

> **Interop check outstanding.** The Phase 2 Gate asks that an off-the-shelf x402 client — one
> nobody wrote for Tollgate — parse this 402 and produce a header the gateway accepts. That has not
> been recorded as run. The shape is asserted against the fixture and against the published schema,
> which the gate allows as a substitution, but the live third-party-client demonstration is still
> owed.

### Paying it

`examples/sign.py` is a throwaway signing harness (stdlib + `eth-account`) that exists so the
verification steps in `plan.md` can actually be run. It is **not** the Phase 8 client library.

```bash
export PAYER_KEY=0x…                       # a funded test key
export PAYOUT=0x0000000000000000000000000000000000000001   # the provider's payout address

P=$(python3 examples/sign.py payment \
      --key "$PAYER_KEY" --to "$PAYOUT" --value 0.001 \
      --usdc "$USDC_ADDRESS" --chain-id 84532)

curl -si localhost:8080/v1/proxy/mock-ok/ok -H "X-PAYMENT: $P"
```

Without a capability header this charges a single payer-level budget, seeded with
`POST /v1/budgets`. Replay the same header and you get `409`; exhaust the budget and you get `402
insufficient_funds`; exceed the per-request cap and you get `429 cap_exceeded`.

`sign.py` subcommands: `address`, `payment`, `chain`, `revoke`, `verify-fixture`. The last one
re-derives `tests/fixtures/capability_vectors.json` in Python and asserts it matches the Rust
implementation byte for byte — a cross-language check on the EIP-712 encoding, a phase before the
Python client needs it.

---

## Walkthrough: delegation

This is the headline feature (`prd.md` decision #4, F4). A supervisor signs a capability for a
worker **offline, with no server round-trip**; the worker presents the chain on every request; every
charge draws down every ancestor.

### The capability

EIP-712 typed data, signed by the issuer, presented by the subject:

```solidity
struct Capability {
    address issuer;          // who is granting
    address subject;         // who may spend
    bytes32 parent;          // hash of the parent capability, 0x0 for a root
    uint256 maxTotal;        // cumulative ceiling, in token base units
    uint256 maxPerRequest;
    bytes32 allowlistHash;   // keccak of the sorted provider-slug list, 0x0 = inherit
    uint64  notBefore;
    uint64  expiry;
    uint32  maxDepth;
    bytes32 salt;
}
```

Domain: `name: "Tollgate"`, `version: "1"`, `chainId` from config, no `verifyingContract`. The
`chainId` in the domain is the cross-chain replay guard. `allowlistHash` is
`keccak256(slugs sorted lexicographically, joined with "\n")` — a plain sorted-list hash, not a
merkle root (`plan.md` A9).

### Signing a chain

Write a spec describing intent; the harness computes each `parent` from the previous link, so it
cannot accidentally emit a chain that fails the parent-link rule:

```json
[
  {"issuer_key": "0xSUPERVISOR", "subject": "0xSupervisorAddr", "max_total": "1.00",
   "max_per_request": "0.05", "allowlist": ["mock-ok", "mock-fail"],
   "expiry_seconds": 3600, "max_depth": 3},
  {"issuer_key": "0xSUPERVISOR", "subject": "0xWorkerAddr", "max_total": "0.10",
   "max_per_request": "0.05", "allowlist": ["mock-ok"],
   "expiry_seconds": 1800, "max_depth": 2}
]
```

```bash
CHAIN=$(python3 examples/sign.py chain --spec worker_a.json --chain-id 84532 --hashes)
curl -si localhost:8080/v1/proxy/mock-ok/ok \
  -H "X-PAYMENT: $P" -H "X-Tollgate-Capability: $CHAIN"
```

### The rules the gateway enforces

Walked root-first, rejecting on the first failure (`architecture.md` §5.2):

| # | Rule | Failure |
|---|---|---|
| 1 | depth ≤ 4, checked **before any signature work** | `400 chain_too_deep` |
| 2 | every link's signature recovers to its declared `issuer` | `400 bad_signature` |
| 3 | `issuer(i) == subject(i-1)` and `parent(i) == hash(link i-1)`; root's `parent == 0x0` | `400 broken_chain` |
| 4 | attenuation only: `maxTotal`, `maxPerRequest`, `expiry` non-increasing; `notBefore` non-decreasing; `maxDepth` strictly decreasing; allowlist a subset | `400 attenuation` |
| 5 | `subject(last) == the EIP-3009 payment signer` | `403 subject_mismatch` |
| 6 | no link's hash in `tg:revoked` | `403 capability_revoked` |
| 7 | `now` within every link's `[notBefore, expiry]` | `403 capability_expired` / `capability_not_yet_valid` |
| 8 | the requested slug is in the effective allowlist | `403 provider_not_allowed` |

Rule 1 comes first because it is a denial-of-service guard: a 500-link chain must be refused without
500 signature recoveries. An attenuation violation is a **400**, not a 403 — a child claiming more
than its parent granted is a malformed chain, not a policy decision.

### Every level drains

One charge increments the spend counter of **every** link in the chain, inside the same Lua
execution. That is what makes a supervisor's pool visibly drain as three workers spend in parallel,
and what makes all three stop at once when the supervisor empties even though none of them hit its
own cap.

Both refusals name the level that said no, and carry the same diagnostic body:

```json
{
  "reason": "cap_exceeded",
  "tripped_level": 1,
  "capability_hash": "0x…",
  "limit": "50000",
  "chain": [
    {"hash": "0x…", "subject": "0x…", "max_total": "1000000", "spent": "300000", "remaining": "700000"},
    {"hash": "0x…", "subject": "0x…", "max_total": "100000",  "spent": "100000", "remaining": "0"}
  ]
}
```

The `402` carries `reason`, `tripped_level`, `capability_hash` and the same per-level `chain`
alongside the full payment-requirements body, so either refusal is equally diagnosable — a
supervisor whose pool emptied needs to know it was the root that stopped its workers and not their
own caps. One exception: a payer who never seeded a budget at all gets a plain `402
insufficient_funds` with no `chain`, since there are no levels to report.

**Which code you get depends on which cap tripped**, and the distinction is deliberate
(`architecture.md` §4.3, and NOTES.md decision D11):

- exhausting a **total** cap → `402 insufficient_funds`, plus the requirements body
- violating a **per-request** cap → `429 cap_exceeded`

### The capability header is optional, permanently

Without `X-Tollgate-Capability` a request charges exactly one level — a payer-level budget keyed by
`keccak(payer)` and seeded by `POST /v1/budgets`. `prd.md` F3 (caps) is a standalone requirement
that does not mention delegation, so both paths build the same `Vec<CapLevel>` through one function
and nothing downstream branches on whether delegation was used. See NOTES.md decision D1.

### Revocation

Off-chain, in a Redis set, and that is sufficient because the gateway is the enforcement point —
nothing needs to reach a chain for a revocation to take effect.

```bash
BODY=$(python3 examples/sign.py revoke --key 0xISSUER --hash 0x<capability hash> --chain-id 84532)
curl -X POST localhost:8080/v1/capabilities/0x<hash>/revoke \
     -H 'content-type: application/json' -d "$BODY"
```

Signed by the capability's issuer **or any ancestor issuer** — an ancestor can revoke a descendant,
and revoking a parent blocks every child whose chain includes it. A revocation from an unrelated key
is `403 not_authorised_to_revoke`. Revocations may not be future-dated.

---

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness of Postgres and Redis. `200` both up, `503` with the failing component `false` |
| `GET` | `/metrics` | Prometheus text format |
| `POST` | `/v1/providers` | Register an upstream. `201`; `409 duplicate_slug`; `400 invalid_price` / `invalid_address` / `unsafe_upstream` |
| `GET` | `/v1/providers` | List providers |
| `GET` | `/v1/providers/{slug}` | One provider; `404 provider_not_found` |
| `POST` | `/v1/budgets` | **Dev only.** Seed a payer-level budget: `{payer, max_total, max_per_request}` |
| `GET` | `/v1/capabilities/{hash}` | Stored capability with `revoked_at` and live spend from Redis |
| `POST` | `/v1/capabilities/{hash}/revoke` | Signed EIP-712 revocation |
| `ANY` | `/v1/proxy/{slug}/{*path}` | The paid path |

Every error uses one shared body, defined once in `tollgate-core/src/error.rs`:

```json
{"error": {"code": "invalid_price", "message": "price must be greater than zero"}}
```

Prices are submitted as decimal USDC strings (`"0.001"`) and converted server-side to base units
(6 decimals) — that request registers a provider charging `1000` wei of USDC per call.

### Status codes on the paid path

| Situation | Response |
|---|---|
| No payment header | `402` + payment requirements |
| Signature invalid, expired, wrong network/scheme/`payTo`/amount | `402` + requirements + an `error` naming the reason |
| Nonce already claimed | `409 nonce_replayed`, no budget change |
| Total cap exhausted | `402 insufficient_funds` + tripped level + per-level chain |
| Per-request cap exceeded | `429 cap_exceeded` + tripped level + per-level chain |
| Capability expired or revoked | `403` |
| Capability chain malformed or attenuation violated | `400` |
| Provider not in allowlist | `403 provider_not_allowed` |
| Upstream 2xx | passed through as-is, reservation promoted to `queued` — the only path that becomes settleable |
| Upstream 5xx | `502 upstream_error`, reservation **voided**, every level credited back. The upstream's own error detail is not leaked verbatim |
| Upstream timeout or connector failure | `504` / `502`, reservation **voided**, every level credited back |
| Upstream 3xx/4xx | forwarded to the caller as-is, but the reservation is **voided** — the agent is not charged for a redirect or a `404` |

A voided charge **does not release the nonce**. The EIP-3009 signature stays replayable until its
`validBefore`, so freeing the nonce would reopen the free-shopping window; re-presenting a voided
payment gets `409`, not a retry.

---

## Data model

### Postgres

Three tables from `architecture.md` §8, in `migrations/0001_init.sql`:

- **`providers`** — `slug` PK, `upstream_url`, `price_wei`, `max_price_wei`, `scheme`,
  `payout_address`, `timeout_ms`. `max_price_wei`/`scheme` exist so the P1 `upto` scheme needs no
  migration; the gateway implements `exact` only and rejects anything else by name.
- **`capabilities`** — `hash` PK (the EIP-712 struct hash), issuer, subject, `parent_hash` (self-FK,
  NULL at a root — never 32 zero bytes, because `0x0` is not a row), depth, limits, allowlist,
  signature, `revoked_at`.
- **`authorisations`** — `nonce` PK (the EIP-3009 nonce, the idempotency key end to end), payer,
  `capability_hash`, `provider_slug`, `amount_wei`, full `payload` JSONB, signature, `status`,
  `upstream_status`, `batch_id`, `tx_hash`, `receipt_sig`.

`status` is `CHECK`-constrained to `reserved | voided | queued | settled | failed`, and transitions
are one-way — the promotion `UPDATE` carries `WHERE status = 'reserved'`.

`migrations/0002_chain_hashes.sql` adds `chain_hashes BYTEA[]`: the full root-first chain that was
charged. `capability_hash` keeps its meaning — the leaf, i.e. *which agent spent* — and stays the
indexed column; ancestors live only in `chain_hashes`, which carries no FK and so can never poison
the drain. Written for every charge including the single-level payer case, so the boot rebuild has
exactly one code path (NOTES.md D4, D5).

### Redis

| Key | Contents |
|---|---|
| `tg:nonce:{nonce}` | replay guard, TTL = `validBefore - now + clock_skew` |
| `tg:cap:{hash}:spent` | cumulative spend against one capability level |
| `tg:cap:{hash}:meta` | `max_total`, `max_per_request`, `expiry` |
| `tg:revoked` | set of revoked capability hashes |
| `tg:reservations` | stream, `XADD`ed inside the claim script |
| `tg:outcome:{nonce}` | promote-or-void marker the drain applies |

There is no `tg:window:*` key — time-window budgets are P1 and out of scope (`plan.md` A4). There is
no `tg:cb:*` circuit breaker either (A10).

---

## How the correctness-critical parts work

### One atomic claim

The nonce claim, every level's cap check, every level's decrement, and the reservation `XADD` happen
in a single Lua script (`crates/tollgate-gateway/src/lua/claim.lua`). All reads and all checks
complete before any write, so the script can never leave Redis half-updated.

The naive version — `SETNX`, then check, then `DECRBY` — is three round-trips and, more importantly,
not atomic: two concurrent requests both pass the cap check before either decrements. Under
concurrency that fires. The regression test drives **100 concurrent claims against a budget that
permits exactly 50** and asserts exactly 50 succeed.

### Nonce TTL is derived, never constant

A flat TTL that expires while the EIP-3009 signature is still valid lets the same payload replay for
a free upstream call, and you find out when settlement reverts. The TTL is computed as
`validBefore - now + clock_skew` and asserted `> 0`; quotes are refused if their validity window
exceeds `QUOTE_VALIDITY_SECONDS + clock_skew`, because the TTL has to be able to cover them.

### Redis is a projection, Postgres is the truth, the stream bridges them

The claim script `XADD`s the reservation in the same atomic execution as the decrement, so balance
and reservation live or die together. A Tokio task drains `tg:reservations` through the `tg-writer`
consumer group, inserts with `ON CONFLICT (nonce) DO NOTHING`, and `XACK`s **only after** the
Postgres commit. Kill Postgres mid-run and the entries stay pending; bring it back and they land.

At boot, before the listener binds, every capability counter is rebuilt from Postgres by summing
`amount_wei` over `unnest(chain_hashes)`. The sum includes `reserved`, `queued`, `settled` **and
`failed`** — `voided` is the only exclusion, because it is the only status where the caller got
nothing. Counting `failed` as spent is a deliberate divergence from `architecture.md` §9.3, which
would otherwise hand an agent its budget back at every restart (NOTES.md D8).

The startup replay pages forward with `XREADGROUP ... <last_id>` rather than re-reading from `0`.
Re-reading from `0` wedged the drain permanently on any entry that could never be applied — see the
"Fixed" section of `NOTES.md` for the full post-mortem; it is the reason
`ledger::replay::a_poison_entry_does_not_wedge_the_startup_replay` exists.

---

## Security

| Concern | Handling |
|---|---|
| Replay | Redis nonce with a TTL tied to `validBefore`; USDC's `authorizationState` is the on-chain finality guard |
| Cross-chain replay | `chainId` inside the EIP-712 domain of both the payment payload and the capability |
| Signature malleability | High-`s` signatures rejected before recovery |
| Gateway inflating the price | Impossible — the amount is inside the payer's signature |
| Free shopping | No upstream call is reachable before the claim returns `Ok`; the proxy call lives inside the `Ok` match arm, not after the match |
| Sub-agent escalating its budget | Attenuation-only verification; a child claiming more than its parent is rejected as malformed |
| Stolen capability | Bound to the subject — the last link's `subject` must equal the EIP-3009 signer, so the capability is useless without the subject's key |
| Provider looping to drain an agent | Per-request and total caps at every level, all evaluated before the upstream call |
| SSRF via provider registration | Resolve → validate every IP → **pin the connection**. See below |

### SSRF

String-based URL validation does not defend this, so the gateway does three things:

1. **Resolve and validate at registration.** `POST /v1/providers` rejects with `400 unsafe_upstream`
   if *any* resolved address falls in RFC 1918, loopback, link-local, `169.254.169.254`, IPv4-mapped
   IPv6 (checked after unmapping), unique-local IPv6, `0.0.0.0/8`, multicast, or CGNAT. A hostname
   resolving to a mix of public and private addresses is rejected outright.
2. **Pin the connection at request time.** Registration-time validation is necessary but *not*
   sufficient — DNS can change between registration and request. The custom `tower` connector
   resolves once, validates, then dials the validated `SocketAddr` directly, never handing the
   hostname back to the resolver. TLS SNI and the `Host` header are set from the original hostname.
   A rebinding test drives a stub resolver that returns a public IP first and `127.0.0.1` second and
   asserts the connector dials the validated address both times.
3. **Do not follow redirects.** 3xx responses are returned to the caller as-is. `architecture.md`
   §10 asks for re-validation on every hop; not following at all is the simpler correct choice here.

The proxy strips `X-PAYMENT`, `X-Tollgate-*`, `Host` and hop-by-hop headers on the way upstream, and
adds `X-Forwarded-For`. A provider never sees the payment header.

> ⚠️ **`TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true`** permits `127.0.0.1` so the local mock upstream
> works. It defaults to false and **must never be true in a deployed configuration.** It is the one
> switch that turns the SSRF defence off.

`architecture.md` §10 also asks for a deny-by-default egress network policy. That is a deployment
control rather than application code, and is not implemented here — it is an operational
requirement on whoever runs this (`plan.md` A12).

### Front-running, stated rather than hidden

Settlement will use `transferWithAuthorization`, not `receiveWithAuthorization`, because the latter
requires `msg.sender == to` and that breaks batching (`plan.md` A6). The consequence is bounded: an
observer who replays the payload from the mempool executes exactly the transfer the payer signed, to
the recipient the payer signed, and pays the gas themselves. It affects ordering, not custody.

---

## Observability

Per-stage Prometheus histograms named `tollgate_stage_seconds`, with a `stage` label:

| Stage | Covers |
|---|---|
| `decode` | header decode and the cheap field checks |
| `recover` | EIP-3009 signature recovery |
| `capability` | the chain walk, including the revocation lookup |
| `claim` | the Lua round-trip |
| `upstream` | the proxy hop |
| `total` | the whole request |

```bash
curl -s localhost:8080/metrics | grep tollgate_stage_seconds
```

`upstream` is recorded separately and never folded into the others — `prd.md` §8 targets p50 under
15 ms of *added gateway* latency, and conflating the two would make the number meaningless. Per
`plan.md` A8 no phase gate is conditioned on hitting the target; missing it is a tuning problem.

---

## Testing

```bash
cargo test --workspace                 # 85 unit tests, no external dependencies
cargo test --workspace -- --ignored    # 19 integration tests, needs Postgres + Redis up
cargo clippy --workspace -- -D warnings
```

Last run on this tree: **85 passed / 0 failed** unit, **19 passed / 0 failed** integration, clippy
clean.

The integration tests read `DATABASE_URL` and `REDIS_URL` from the environment and each build a
throwaway Redis stream, so they neither touch `tg:reservations` nor race one another. That is
deliberate: two test modules once shared the real stream and made the suite flaky about one run in
three — see `NOTES.md`.

Notable tests, if you want to read the ones that carry the weight:

- `policy::claim::one_hundred_concurrent_claims_stop_exactly_at_max_total` — the concurrency proof
- `capability::verify` — one test per attenuation and binding rule, each asserting the exact variant
- `ssrf::denylist` — table test over every denied range plus mixed-resolution hostnames
- `proxy::rebinding` — proves the connector pins rather than re-resolves
- `ledger::replay::a_poison_entry_does_not_wedge_the_startup_replay` — the drain-wedge regression

---

## Local chain: anvil fork and deploy

Settlement needs a chain. For everything short of Task 6.6's live run, that chain is a local
anvil fork of Base Sepolia, which gives real USDC semantics — EIP-712 verification, the
`authorizationState` replay guard, real balance accounting — with no faucet and no waiting.

```bash
./scripts/anvil.sh &        # forks Base Sepolia, funds a test EOA with ETH and USDC
```

It prints the RPC, the funded test EOA and its key. anvil's own output goes to
`/tmp/tollgate-anvil.log`. `kill %1` stops it. Overridable by environment:

| Variable | Default | |
|---|---|---|
| `BASE_SEPOLIA_RPC` | `https://sepolia.base.org` | what to fork; the public endpoint needs no key |
| `ANVIL_PORT` | `8545` | |
| `USDC_ADDRESS` | `0x036CbD…dCF7e` | native USDC on Base Sepolia |
| `USDC_FUND_UNITS` | `1000000000` | 1,000 USDC at 6 decimals |
| `TEST_EOA_KEY` | committed test key | throwaway, fork-only, holds nothing real |

Then deploy `BatchSettler` into it and point `.env` at the result:

```bash
cd contracts
export ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80  # anvil account 0
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast --private-key $ANVIL_KEY
# BatchSettler deployed at: 0x…

cast code <address> --rpc-url http://localhost:8545     # non-empty confirms it
```

Put that address in `.env` as `BATCH_SETTLER_ADDRESS`, and set `RPC_URL=http://localhost:8545`
so the settler talks to the fork rather than a public endpoint.

**Two things about this fork that will bite if you do not know them.**

The fork must run with `--chain-id 84532`, which `anvil.sh` passes. anvil defaults to 31337, and
every EIP-3009 payment and every capability in this project commits to chain 84532 inside its
EIP-712 domain — on a 31337 fork all of them fail to verify, for a reason the error messages do
not make obvious.

The funded test EOA is **not** one of anvil's ten default accounts. All ten have EIP-7702
delegation code deployed at their addresses on real Base Sepolia, and USDC's `SignatureChecker`
routes any `from` that has code to ERC-1271 rather than `ecrecover`. An anvil default therefore
cannot make a working EIP-3009 payment against forked USDC — it fails with
`FiatTokenV2: invalid signature` however correctly the payload is signed. `anvil.sh` refuses to
start if its test EOA ever has code. The same constraint applies to the real payer wallet in a
live run: it must be a plain EOA.

---

## Settlement worker

A separate binary and a separate process. Nothing it does is on the request path — the caller
already has the upstream's response by the time a row becomes visible to it.

```bash
cargo run -p tollgate-settler
```

It flushes at `SETTLER_BATCH_SIZE` authorisations or `SETTLER_FLUSH_SECONDS`, whichever comes
first, submits one `BatchSettler.settle` transaction, and writes back `status='settled'`,
`tx_hash` and `settled_at` for every nonce the chain reported as `Settled`.

Three properties worth knowing:

- **It reads only `status = 'queued'`.** A `reserved` row — one whose upstream call has not
  returned 2xx yet — is invisible to it by construction. That is what closes the v1 race where a
  flush could settle a charge the request handler was about to void.
- **`batch_id` is `keccak256` over the sorted nonce set**, stamped inside the same transaction
  that selects the rows, with `FOR UPDATE SKIP LOCKED`. The same set of charges always produces
  the same id, so a duplicate submission is recognisable rather than looking like new work.
- **Gas is EIP-1559 with a fixed multiplier — twice the latest base fee, plus a constant
  priority fee.** There is no gas oracle and no dependency on one.

**Throughput ceiling, stated rather than hidden.** One in-flight transaction at a time, awaited
to completion before the next batch, so the settler EOA's nonces stay sequential. That is roughly
one batch per block: at 50 per batch and Base's 2-second blocks, **~25 settlements per second
sustained**. That is comfortably above `prd.md` §8's target of 100 requests in 60 seconds, but it
is a real ceiling. The production fix is several settler EOAs behind a nonce allocator, which is
not built.

---

## Settlement cost

`prd.md` §8 claims settlement costs under $0.001 per request after batching, "verified with `forge`
gas snapshots, not estimated". Here is the measurement rather than the estimate.

Run `cd contracts && forge test -vv`; the 50-item test measures the `settle` call with `gasleft()`
and logs it. `contracts/.gas-snapshot` is committed alongside.

```
settle(50) execution gas: 2042281
execution gas per charge:   40845
```

Per charge, for a full batch of 50:

| Component | Gas | Note |
|---|---:|---|
| Execution | 40,846 | measured, real USDC on a Base Sepolia fork |
| Intrinsic | 420 | 21,000 amortised across 50 |
| Calldata | 3,248 | one `Auth` is 320 bytes; 156 zero @ 4, 164 non-zero @ 16 |
| **Total** | **44,514** | |

At Base's gas price of 0.006 gwei (`cast gas-price`, live at time of writing):

| ETH price | Cost per charge |
|---|---:|
| $2,000 | $0.00053 |
| $3,000 | $0.00080 |
| $4,000 | $0.00107 |

**The claim holds, but not by an order of magnitude.** At this gas price it breaks even with
$0.001 at an ETH price around **$3,744**. Two caveats worth stating rather than burying:

- This excludes Base's **L1 data-availability fee**, which a calldata-heavy batch does incur. The
  real all-in figure comes from Task 6.6's live Base Sepolia settlement, and this section will be
  replaced by that measurement.
- Execution gas came in at ~41k per charge against `architecture.md` §6's 60–80k estimate, so the
  batch lands near 2.0M gas rather than the 3.5M that section predicted.

---

## Configuration

| Variable | Required | Default | Used by |
|---|---|---|---|
| `DATABASE_URL` | yes | — | pool, migrations |
| `REDIS_URL` | yes | — | claim, budgets, drain |
| `BIND_ADDR` | yes | — | listener |
| `CHAIN_ID` | no | `84532` | CAIP-2 network, both EIP-712 domains |
| `RPC_URL` | yes | — | Phase 6 (unused today) |
| `USDC_ADDRESS` | yes | — | `asset` in the 402, `verifyingContract` in the payment domain |
| `BATCH_SETTLER_ADDRESS` | yes | — | Phase 6 (unused today) |
| `SETTLER_PRIVATE_KEY` | yes | — | Phase 6 (unused today) |
| `GATEWAY_SIGNING_KEY` | yes | — | Phase 7 receipts (unused today) |
| `QUOTE_VALIDITY_SECONDS` | no | `300` | `maxTimeoutSeconds`, validity-window ceiling |
| `CLOCK_SKEW_SECONDS` | no | `60` | timestamp tolerance, nonce TTL |
| `SETTLER_BATCH_SIZE` | no | `50` | Phase 6 |
| `SETTLER_FLUSH_SECONDS` | no | `10` | Phase 6 |
| `TOLLGATE_ALLOW_LOOPBACK_UPSTREAM` | no | `false` | SSRF test-mode escape hatch — see above |
| `RUST_LOG` | no | — | `tracing_subscriber` env filter |

`USDC_ADDRESS` must match what payers sign against: it is the `verifyingContract` of the
`TransferWithAuthorization` domain, so a mismatch makes every signature recover to the wrong address
and fail the `from` check. Native USDC on Base Sepolia (84532) is
`0x036CbD53842c5426634e7929541eC2318f3dCF7e` — verified on-chain as `name "USDC"`, `symbol "USDC"`,
`decimals 6`, EIP-712 `version "2"`, with `authorizationState` present. Native, not bridged
USDC.e, which does not implement EIP-3009 compatibly.

---

## Repository layout

```
Cargo.toml                       workspace root
docker-compose.yml               postgres 16 + redis 7 (AOF, everysec)
migrations/                      0001_init.sql, 0002_chain_hashes.sql
crates/
  tollgate-core/                 config, types, db + redis pools, error body, stage timer
  tollgate-gateway/              the axum binary
    src/x402.rs                  402 construction, header decode, field validation
    src/verify.rs                EIP-3009 recovery via alloy
    src/capability.rs            capability type, hashing, chain decode, chain verification
    src/policy.rs                typed driver for the claim script
    src/lua/claim.lua            the atomic claim
    src/proxy.rs                 pinned-IP connector, streaming passthrough
    src/ssrf.rs                  resolve + IP denylist
    src/ledger.rs                stream drain, promote/void, boot rebuild
    src/routes/                  providers, budgets, capabilities, proxy, health, metrics
  tollgate-settler/              stub until Phase 6
examples/
  mock_upstream.py               deterministic paid upstream
  sign.py                        throwaway EIP-712/EIP-3009 signing harness
scripts/dev.sh                   compose up + wait + migrate
scripts/seed_providers.sh        register the three mock providers
```

---

## Known boundaries

Stated up front, because a stated boundary reads better than a discovered one
(`architecture.md` §12).

- **Testnet only.** Base Sepolia, testnet USDC, no mainnet, no real value.
- **One chain.** Multichain is described in the design, not deployed. The design is per-chain
  isolated with no bridge.
- **Nothing settles yet.** Charges reach `queued` and stop; Phase 6 builds `BatchSettler` and the
  settler worker.
- **Delegation funds children up front** (Resolution A): the parent sends USDC to each child wallet,
  and the capability chain is pure policy constraining money the child already holds. The parent
  cannot claw back unspent funds without the child's cooperation, and each child costs one on-chain
  transfer. Channel-backed delegation (Resolution B) is designed and described, not built.
- **The settler key will be a hot key in an env var.** This matters less than it looks: the settler
  cannot invent, inflate or redirect a charge, because all three are inside the payer's signature
  and checked by USDC. Production still wants a KMS or a threshold signer.
- **Provider onboarding is a form.** No email, no verification, no reputation.
- **Exactly-once, honestly.** The EIP-3009 nonce is the idempotency key at every layer — gateway
  dedup, stream dedup, Postgres PK, and USDC's `authorizationState` on-chain. On-chain that is
  at-most-once and the chain enforces it; off-chain the settler will be at-least-once with
  idempotent retries. Composed, it is effectively-once. A full Redis wipe loses only in-flight
  reservations not yet drained — a bounded window of seconds.
- **Out of scope by decision:** the `upto` scheme, time-window budgets, circuit breakers, on-chain
  refunds of settled charges, and the `tollgate wrap` CLI.

### Open items carried forward

- The off-the-shelf x402 client interop demonstration (Phase 2 Gate) is not recorded as run.
- The request path does not tolerate a Postgres outage: provider lookup hits Postgres before any
  Redis logic, so a blip makes in-flight requests `500` rather than degrading. Fail-closed, no data
  loss, no mis-attribution. See the "Deferred" section of `NOTES.md`.

---

## Documents

| File | What it is |
|---|---|
| `prd.md` | Product requirements, target users, success metrics, the honest business case |
| `architecture.md` | The design: request lifecycle, delegation, concurrency, security, data model |
| `plan.md` | The 46-task build plan, phase by phase, with a gate per phase |
| `NOTES.md` | Decisions taken during execution (D1–D11), post-mortems on bugs found and fixed, and deferred items |
| `EXECUTING.md` | How this repo is built with Claude Code, and the git policy |

**Git policy:** the agent never runs git write commands. Every commit in this repository was made by
a human after review.
