# Architecture v2 - Tollgate

Read alongside prd.md.

## 1. Two design principles

**Nothing touches a chain inside the request path.** Unchanged from v1 and still the rule everything
else follows from. The gateway verifies a signature locally, claims budget in Redis, and proxies.
Settlement runs on a separate timer, in batches. Break this and your p99 becomes block time.

**Do not invent a protocol.** New in v2. x402 already defines the 402 response shape, the payment
header, the `exact` and `upto` schemes, and a `batch-settlement` payment-channel scheme that matches
v1's escrow design almost exactly. Speak x402 on the wire. Spend your build days on the layer x402
does not have: capability-based delegation, atomic cap enforcement, and signed receipts.

## 2. Component map

```
                            ┌────────────────────────────┐
  Supervisor agent          │      TOLLGATE GATEWAY      │
      │ signs EIP-712       │      Rust / Axum / Tower   │
      │ capability          │                            │──► Upstream API
      ▼                     │  · x402 402 responder      │    (provider's service)
  Worker agents ── HTTP ───►│  · EIP-3009 verifier       │
  (+ tollgate-client)       │  · capability chain walker │
      ▲                     │  · atomic policy claim     │
      │  402 + requirements │  · SSRF-pinned proxy       │
      └─────────────────────│  · receipt signer          │
                            └──────┬─────────────────────┘
                                   │
                    ┌──────────────┼───────────────┐
                    ▼              ▼               ▼
             ┌───────────┐  ┌───────────┐  ┌──────────────┐
             │  Redis    │  │ Postgres  │  │  SETTLER     │
             │  budgets  │  │ ledger    │  │  worker      │
             │  nonces   │  │ providers │  │  (Rust)      │
             │  caps     │  │ capabs    │  └──────┬───────┘
             │  reserve  │  │ receipts  │         │ one tx per batch
             │  stream   │  └───────────┘         ▼
             └───────────┘         ▲       ┌─────────────────┐
                                   │       │  BASE SEPOLIA   │
                           ┌───────┴────┐  │  USDC (EIP-3009)│
                           │ DASHBOARD  │  │  BatchSettler   │
                           │ Next.js 14 │  │  (holds nothing)│
                           └────────────┘  └─────────────────┘
                                   ▲               ▲
                                   └── wagmi/viem ─┘
```

What is gone from v1: `MeterEscrow`, `balanceOf`, `earningsOf`, `spentNonce`, `claim()`,
`emergencyWithdraw()`, the settler trust assumption, and the second chain.

What replaces it: Circle's USDC contract does the signature verification and the replay protection.
`BatchSettler` is a ~50 line pass-through that holds no funds and cannot redirect one.

## 3. Payment model

### 3.1 Default: EIP-3009 direct pull

The agent signs a `transferWithAuthorization` payload naming the provider's payout address, the
amount, a validity window, and a nonce. USDC verifies that signature on-chain when the settler
submits it. Three consequences:

- The settler is untrusted by construction. It cannot invent a charge, inflate an amount, or
  redirect a payment, because all three are inside the payer's signature.
- You write no signature-verification contract code. v1's "Option A, ecrecover per charge" is
  deleted.
- USDC's own `authorizationState` mapping is the on-chain replay guard. v1's `spentNonce` is
  deleted.

Native USDC implements EIP-3009 on Base, Arbitrum, Optimism, Polygon and Ethereum. Bridged USDC.e on
Polygon does not implement it compatibly. Use native USDC on Base Sepolia (chain 84532) and nothing
else.

**`transferWithAuthorization` or `receiveWithAuthorization`.** `receiveWithAuthorization` requires
`msg.sender == to`, which closes a front-running path but also means only the provider can submit it,
which breaks batching. Use `transferWithAuthorization` for the batched path. The front-running
concern is bounded here: an observer who replays the payload from the mempool executes exactly the
transfer the payer signed, to the recipient the payer signed. They pay the gas, you do not lose
funds. It affects ordering, not custody. Say this rather than pretending it does not exist.

### 3.2 Variable pricing: `upto`

For endpoints whose cost is not known at quote time, x402's `upto` scheme lets the client authorise a
maximum and the server settle the actual, lower amount. This is the answer to streaming and
unknown-size responses. P1, not P0.

### 3.3 Session and delegated spend: payment channel

A sub-agent has its own keypair and no money. That is the one real problem with direct-pull, and
section 5 covers both resolutions. When you need a pooled budget that several signers draw against,
use x402's `batch-settlement` channel rather than an escrow contract of your own design: the payer
funds a channel once, spenders sign cumulative vouchers, and the manager claims the highest voucher
per channel in one transaction. Borrow its cumulative-voucher semantics. Do not reimplement them.

## 4. Request lifecycle

### 4.1 Unpaid request

```
1. Agent    -> GET /v1/proxy/{provider_slug}/{path}
2. Gateway  -> look up provider, compute price
3. Gateway  -> 402 Payment Required, x402 payment-requirements body:
               scheme, network (CAIP-2), maxAmountRequired, asset,
               payTo, resource, maxTimeoutSeconds, extra
```

The 402 body is spec-shaped, so an off-the-shelf x402 client pays it with no Tollgate-specific code.
That is the interop claim, and it is worth demonstrating live with a client you did not write.

### 4.2 Paid request

```
1. Agent    -> same request
               X-PAYMENT: <base64 x402 payload>
               X-Tollgate-Capability: <base64 capability chain>   (optional)
2. Gateway  -> decode payload, cheap checks first:
               expiry, network, asset, payTo, amount <= quoted     (~10 µs)
3. Gateway  -> recover signer from EIP-3009 payload via alloy      (~50 µs)
4. Gateway  -> walk capability chain, verify each link             (~200 µs)
5. Gateway  -> ONE Lua script: nonce claim + cap checks against
               every capability in the chain + decrement + XADD
               reservation to the Redis stream                     (~0.5 ms)
6. Gateway  -> proxy to upstream with a pinned-IP connector, stream back
7. Gateway  -> on 2xx: promote reservation reserved -> queued
               on 5xx/timeout: void, credit budget back, never settle
8. Settler  -> every 50 authorisations or 10 seconds, one batch tx
```

Steps 2 to 5 are your added latency. Budget under 15 ms p50 for gateway work. Everything past step 6
is the upstream, which the caller was paying anyway. Report the two separately.

**Ordering matters.** Do the cheap validation before the crypto, and the crypto before the Redis
round-trip. Never proxy before step 5 returns success. Releasing the upstream response before the
authorisation is replay-claimed is the documented "free shopping" bug class found in production x402
facilitators, and it is the easiest way for someone to get a free response with curl.

### 4.3 Failure handling

| Failure | Behaviour |
|---------|-----------|
| Upstream 5xx | Reservation voided, budget credited back, never enters the settlement queue |
| Upstream timeout | Same. Provider-configured, default 30 s |
| Signature invalid | 402 with `x402Version` and requirements, log the attempt |
| Nonce reused | 409, no budget change. Redis is the fast guard, USDC's `authorizationState` is the finality guard |
| Insufficient budget | 402 with `reason: insufficient_funds` |
| Cap exceeded | 429 with `reason: cap_exceeded`, which cap tripped, which capability in the chain owns it, and how much is left |
| Capability expired or revoked | 403 with `reason: capability_expired` / `capability_revoked` |
| Attenuation violated | 400. A child claiming more than its parent granted is a malformed chain, not a policy failure |
| Settlement item reverts | That item alone requeues with a retry counter. The other 49 settle. Alert after 3 failures |

The 429 body is worth getting right. Make it good: include the capability hash, the parent chain,
remaining budget at each level, and which level said no.

## 5. Delegation

This is the headline feature. It is also where the direct-pull model has a genuine tension, so read
this section before you start building.

### 5.1 The capability

EIP-712 typed data, signed by the issuer, presented by the subject on every request.

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
    uint32  maxDepth;        // how many further links may be issued below this one
    bytes32 salt;
}
```

The subject presents the whole chain, root first, plus the plaintext allowlist when
`allowlistHash != 0`. A merkle root would be the privacy-preserving version. For a first build a
plain sorted-list hash is enough and much less to debug.

### 5.2 Verification rules

Walk the chain root-first and reject on the first failure.

1. Depth at most 4. Reject deeper chains before doing any signature work.
2. Link 0's issuer is the funding address (the wallet that signs the EIP-3009 payload, or the channel
   owner in channel mode).
3. For link *i > 0*: `issuer == subject(i-1)` and `parent == hash(link i-1)`.
4. Attenuation only. `maxTotal(i) <= maxTotal(i-1)`, `maxPerRequest(i) <= maxPerRequest(i-1)`,
   `expiry(i) <= expiry(i-1)`, `notBefore(i) >= notBefore(i-1)`, `maxDepth(i) < maxDepth(i-1)`, and
   the allowlist of *i* is a subset of *i-1*'s. A capability can never grant more than it holds.
5. The final link's subject is the address that signed the EIP-3009 payment payload.
6. No link is in the revocation set.

**Every charge decrements every capability in the chain, not just the leaf.** A worker spending 5
cents draws 5 cents from its own budget, from its team lead's budget, and from the supervisor's
budget. This is what makes the delegation tree easy to follow: the supervisor's remaining balance
visibly drains as three workers spend in parallel, and when the supervisor's pool empties, all three
stop at once even though none of them individually hit its own cap. At most four counters, all inside
one Lua script.

**Revocation is off-chain and that is fine.** The gateway is the enforcement point, so a signed
revocation posted to the gateway and stored in a Redis set is sufficient. Nothing needs to reach a
chain for a revocation to take effect.

### 5.3 The funding tension, and the two resolutions

In direct-pull, the EIP-3009 payload must be signed by a wallet that actually holds USDC. A sub-agent
has a keypair and no money. Two ways out.

**Resolution A, funded child.** The parent sends USDC to each child wallet up front. The capability
chain is then pure policy: it constrains what the child may do with money it already has. No
contract, no channel, ships on Day 2. The weakness is that the parent cannot claw back unspent funds
without the child cooperating, and each child costs one on-chain transfer.

**Resolution B, channel-backed.** The parent funds a payment channel once with a single EIP-3009
signature. Children sign vouchers drawn against the parent's channel balance, and the gateway
verifies voucher plus capability chain together. Settlement claims the highest cumulative voucher.
Unused balance refunds cooperatively, or after a timeout if the settler disappears. This is the
correct version and it is x402's `batch-settlement` scheme with an attenuation layer bolted on.

**Ship A, design for B.** A gets you a working system with zero contract risk. B is the P1 upgrade and
the thing you describe as the production shape. Do not start with B early on and discover partway
through that the channel contract has a bug.

## 6. On-chain surface

One contract, and it is almost nothing.

```solidity
contract BatchSettler {
    struct Auth {
        address token;      // USDC
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        uint8 v; bytes32 r; bytes32 s;
    }

    event Settled(bytes32 indexed nonce);
    event SettleFailed(bytes32 indexed nonce, bytes reason);

    function settle(Auth[] calldata auths) external {
        for (uint256 i; i < auths.length; ++i) {
            try IERC3009(auths[i].token).transferWithAuthorization(
                auths[i].from, auths[i].to, auths[i].value,
                auths[i].validAfter, auths[i].validBefore, auths[i].nonce,
                auths[i].v, auths[i].r, auths[i].s
            ) {
                emit Settled(auths[i].nonce);
            } catch (bytes memory reason) {
                emit SettleFailed(auths[i].nonce, reason);
            }
        }
    }
}
```

Properties worth highlighting:

- It holds no funds, ever. There is no balance to drain and no withdraw function.
- It cannot redirect a payment. `to` is inside the payer's signature and USDC checks it.
- It has no owner, no admin, no pause, no upgradeability, no proxy.
- **Skip and continue, not revert all.** This is a direct fix to v1, where one bad charge reverted a
  batch of 200. That design was a griefing vector: any agent able to get one stale nonce into a batch
  could block 199 good charges. Failures now emit an event and requeue individually.
- `settle` is permissionless. Anyone can submit a batch. That is not a bug, because every item is
  signature-gated by USDC. It also means the settler key is not a trusted component.

**Batch size 50, not 200.** A `transferWithAuthorization` costs roughly 60k to 80k gas including the
EIP-712 verification and the storage write to `authorizationState`. 200 of them is on the order of 14M
gas, which is an uncomfortably large single transaction. 50 lands near 3.5M gas, which is safe and
still puts per-request settlement cost well under $0.001 on Base. Confirm with `forge snapshot`
before you rely on that number anywhere. Do not cite my estimate.

## 7. Off-chain services

### 7.1 Gateway (Rust, Axum, Tower, Hyper)

Carries over directly from your OneInbox gateway: the Tower middleware stack, Redis token buckets
(now metering money), circuit breakers on upstreams, and priority queueing.

| Module | Responsibility |
|--------|----------------|
| `x402` | 402 payment-requirements construction, payment-header decode, scheme dispatch |
| `verify` | EIP-3009 payload recovery via `alloy`, expiry and field checks |
| `capability` | Chain decode, attenuation verification, revocation lookup |
| `policy` | The single Lua script: nonce claim, per-level caps, window budgets, decrements |
| `proxy` | Hyper reverse proxy with a pinned-IP connector and streaming passthrough |
| `ledger` | Postgres writes, reservation-stream drain, receipt signing |

Use `alloy` for EIP-712 and signature recovery. No FFI, no Node sidecar. A service hop here eats the
whole latency budget.

### 7.2 Settler worker (Rust)

Separate binary, separate process.

- Flush at 50 authorisations or 10 seconds, whichever first
- Reads only `status = 'queued'`. A reservation that has not been confirmed by a 2xx upstream is
  never visible to it. This closes v1's race where a 15-second flush could settle a charge the
  request handler was about to void
- One in-flight transaction per chain, sequential EOA nonces. This is a throughput ceiling of roughly
  one batch per block. At 50 per batch and 2-second blocks on Base that is ~25 settlements per second
  sustained, comfortably above a target of 100 requests in 60 seconds. State the ceiling rather than
  hiding it; the production fix is multiple settler EOAs behind a nonce allocator
- EIP-1559 with a fixed multiplier. Do not build a gas oracle
- Before resubmitting after an ambiguous timeout, read `authorizationState(from, nonce)` on-chain. Do
  not blind-retry
- Batch id is deterministic from the sorted nonce set, so a duplicate submission is a no-op

### 7.3 Client library (`tollgate-client`, Python first)

```python
from tollgate import Session

# Supervisor
sup = Session(signer=parent_key, network="base-sepolia")

worker_budget = sup.delegate(
    subject=worker_address,
    max_total="1.00",
    max_per_request="0.05",
    allowlist=["geocode", "weather"],
    expiry_seconds=600,
)

# Worker
w = Session(signer=worker_key, capability=worker_budget)
r = w.get("https://gw.tollgate.dev/v1/proxy/geocode/lookup?q=Panaji")

print(w.receipts())        # signed, per-charge, with tx hashes
print(sup.expense_report()) # rolled up across the whole delegation tree
```

`delegate()` is one local signature. No server round-trip, no wallet funding step in channel mode.
That is the line that sells the feature.

The client mirrors caps locally so failures are fast and error messages are good, but the server is
the security boundary. Do not mirror the whole policy engine. Per-request cap and expiry are enough.

### 7.4 Dashboard (Next.js 14, wagmi, viem, Tailwind)

Three views:

1. **Provider.** Register endpoint, set price, live request log with payer, upstream status, and
   transaction hash.
2. **Agent.** The delegation tree as an actual tree, with each node's remaining budget draining live.
   This is the screen that matters most: it shows a worker hitting its cap and stopping while the
   others keep going.
3. **Public feed.** Every settled charge, streaming, plus a live latency panel showing gateway p50
   and p99 separated from upstream time.

The delegation tree is the product surface. Without it this reads as invisible infrastructure.

## 8. Data model

```sql
CREATE TABLE providers (
  slug            TEXT PRIMARY KEY,
  upstream_url    TEXT NOT NULL,
  price_wei       NUMERIC NOT NULL,
  max_price_wei   NUMERIC,                    -- for the upto scheme
  scheme          TEXT NOT NULL DEFAULT 'exact',
  payout_address  BYTEA NOT NULL,
  timeout_ms      INT DEFAULT 30000,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE capabilities (
  hash            BYTEA PRIMARY KEY,          -- EIP-712 struct hash
  issuer          BYTEA NOT NULL,
  subject         BYTEA NOT NULL,
  parent_hash     BYTEA REFERENCES capabilities(hash),
  depth           INT NOT NULL,
  max_total_wei   NUMERIC NOT NULL,
  max_per_req_wei NUMERIC NOT NULL,
  allowlist       TEXT[],
  not_before      TIMESTAMPTZ NOT NULL,
  expiry          TIMESTAMPTZ NOT NULL,
  signature       BYTEA NOT NULL,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE authorisations (
  nonce           BYTEA PRIMARY KEY,          -- the EIP-3009 nonce
  payer           BYTEA NOT NULL,             -- signer of the payment payload
  capability_hash BYTEA REFERENCES capabilities(hash),
  provider_slug   TEXT REFERENCES providers(slug),
  amount_wei      NUMERIC NOT NULL,
  payload         JSONB NOT NULL,             -- full EIP-3009 payload
  signature       BYTEA NOT NULL,
  status          TEXT NOT NULL,              -- reserved | voided | queued | settled | failed
  upstream_status INT,
  batch_id        BYTEA,
  tx_hash         BYTEA,
  receipt_sig     BYTEA,
  created_at      TIMESTAMPTZ DEFAULT now(),
  settled_at      TIMESTAMPTZ
);

CREATE INDEX ON authorisations (status) WHERE status = 'queued';
CREATE INDEX ON authorisations (payer, created_at DESC);
CREATE INDEX ON authorisations (capability_hash, created_at DESC);
```

Redis keys:

```
tg:nonce:{nonce}              -> 1, TTL = validBefore - now + skew  (see 9.2)
tg:cap:{cap_hash}:spent       -> cumulative spend against this capability
tg:cap:{cap_hash}:meta        -> hash of max_total, max_per_req, expiry, allowlist hash
tg:revoked                    -> set of revoked capability hashes
tg:window:{cap_hash}:{bucket} -> spend in this time bucket, TTL = window
tg:cb:{provider_slug}         -> circuit breaker state
tg:reservations               -> stream, XADD'd inside the claim script (see 9.1)
```

## 9. Concurrency and crash consistency

This section is the largest correctness change from v1.

### 9.1 One atomic claim

v1 did `SETNX` for the nonce, then a cap check, then `DECRBY`. Three round-trips and, more
importantly, not atomic: two concurrent requests can both pass the cap check before either
decrements. Under a test load of 100 requests in 60 seconds with parallel workers, this will fire.

Replace all of it with one Lua script (or a Redis function). Keys are the nonce plus the spend
counter for every capability in the chain. In one execution it:

1. returns `replay` if the nonce key exists
2. returns `cap_exceeded` with the offending level if `amount > max_per_request` at any level
3. returns `insufficient` with the offending level if `spent + amount > max_total` at any level
4. checks the window bucket
5. sets the nonce key with its TTL
6. increments the spend counter at every level and the window bucket
7. `XADD`s the reservation to `tg:reservations`
8. returns `ok`

Steps 1 through 7 succeed or none of them do. It is also one round-trip instead of three, which helps
the latency target.

### 9.2 Nonce TTL must not be shorter than signature validity

v1 set a flat one-hour TTL on the Redis nonce. An EIP-3009 authorisation is valid until its
`validBefore`. If the TTL expires while the signature is still valid, the same payload replays
against the gateway and gets a free upstream call, and you only find out when the settlement reverts.

Two rules, both enforced at quote time:

- Issue quotes with `validBefore <= now + 300s`.
- Set the Redis nonce TTL to `validBefore - now + clock_skew`, never a fixed constant, and never
  shorter than the remaining validity.

### 9.3 Redis is a projection, Postgres is the truth, the stream bridges them

v1's failure mode: Redis `DECRBY` succeeds, the process dies before the Postgres insert, Redis is
rebuilt from Postgres at boot, and the decrement vanishes. The agent silently gets its budget back.
That is not a theft of real funds (USDC enforces per-nonce settlement on-chain) but it is a
cap-accounting leak, and caps are the whole product.

The fix is that the claim script `XADD`s the reservation into a Redis stream in the same atomic
execution as the decrement. A writer task drains the stream into Postgres and acknowledges. Balance
and reservation now live or die together.

Recovery:

- Gateway restart: rebuild capability counters from Postgres `settled + queued + reserved`, then
  replay any unacknowledged stream entries.
- Redis loss: rebuild from Postgres. You lose only in-flight reservations that had not yet been
  drained, which is a bounded window of seconds. State this limit; do not claim exactly-once across a
  Redis wipe.
- Run Redis with AOF and `appendfsync everysec`.

Rebuild at boot, not lazily. A cold-start miss that lets an agent overspend is exactly the bug that
surfaces later, once it's in use.

### 9.4 Exactly-once, honestly

The EIP-3009 nonce is the idempotency key end to end: gateway dedup, stream dedup, Postgres primary
key, and USDC's `authorizationState` on-chain. On-chain it is at-most-once and the chain enforces it.
Off-chain the settler is at-least-once with idempotent retries. Composed, that is effectively-once.
Say it that way rather than claiming exactly-once, which you cannot deliver and someone will ask
about.

## 10. Security

| Concern | Handling |
|---------|----------|
| Replay | Redis nonce with a TTL tied to `validBefore`, USDC `authorizationState` for finality |
| Cross-chain replay | `chainId` is inside the EIP-712 domain separator of both the payment payload and the capability |
| Signature malleability | EIP-712 typed data, reject high-s signatures |
| Gateway inflates the price | The amount is inside the payer's signature. The gateway cannot change it after the fact |
| Settler steals or redirects | It cannot. `to` and `value` are signed by the payer and checked by USDC. `BatchSettler` holds nothing |
| Free shopping | Never proxy before the atomic claim returns ok. This bug class is documented in production x402 facilitators |
| Provider loops to drain an agent | Per-request cap and window budget at every level of the capability chain, all evaluated before the upstream call |
| Sub-agent escalates its own budget | Attenuation-only verification. A child capability claiming more than its parent is rejected as malformed |
| Stolen capability | Bind it to the subject address. The final link's subject must equal the EIP-3009 signer, so a stolen capability is useless without the subject's key |
| SSRF via provider registration | See below. This is the one most likely to be found live |
| Front-running the payment payload | Bounded. An observer executes exactly the signed transfer to the signed recipient and pays the gas. Ordering changes, custody does not |
| Dependency CVEs | A March 2026 advisory (GHSA-qr2g-p6q7-w82m) was a signature-verification bypass in the x402 Solana SDK letting attackers get paid resources for free. Pin versions, read changelogs |

### SSRF, in detail

You accept an arbitrary `upstream_url` from a provider and proxy to it. String-based URL validation
does not defend this. The 2026 pattern is:

1. Resolve the hostname yourself, through a public resolver, never an internal one.
2. Validate every resolved IP against a denylist: RFC 1918, loopback, link-local, the cloud metadata
   endpoint at 169.254.169.254, unique-local and IPv6 equivalents, and IPv4-mapped IPv6.
3. **Pin the connection to the validated `SocketAddr`.** Without pinning you have a
   time-of-check-to-time-of-use bug: the hostname resolves public at validation and to the metadata
   endpoint at connect. DNS rebinding bypasses of exactly this shape are still shipping as CVEs, for
   example CVE-2026-27826 in MCP Atlassian.
4. Run the proxy's egress under a deny-by-default network policy so a bypass reaches nothing.
5. Do not follow redirects blindly. Re-validate on every hop.

In Rust, this means a custom `hyper` connector that dials the validated address rather than handing
the hostname to the resolver a second time. Test it with a rebinding payload before you rely on it.

## 11. Observability

You are claiming latency numbers, so instrument for them from the start.

Per-stage histograms, exported to Prometheus or OTel and rendered live on the public feed:

- `decode` (cheap field checks)
- `recover` (EIP-3009 signature recovery)
- `capability` (chain walk)
- `claim` (the Lua round-trip)
- `upstream` (the proxy hop, reported separately and never folded into your number)
- `total`

Also track: settlement batch size, gas used per batch, gas per charge, queue depth, and time from
`queued` to `settled`. Put gas per charge on the dashboard so the "under $0.001" claim is measured,
not asserted.

## 12. What gets mocked

State these in the README. A stated boundary reads far better than a discovered one.

- Base Sepolia only. Testnet USDC. No mainnet, no real value.
- One chain. Multichain is described, not deployed. The design is per-chain isolated with no bridge,
  so it is an afternoon of work later, not an architectural change.
- The paid APIs are two real public APIs wrapped by you, plus one deliberately slow one to show the
  timeout path.
- Provider onboarding is a form. No email, no verification, no reputation.
- The settler key is a hot key in an env var. Say so, and say production wants a KMS or a threshold
  signer. Note that this matters less than it did in v1, because the settler cannot steal.
- Delegation ships with Resolution A funding (see 5.3). Channel-backed delegation is designed and
  described, not built.

## 13. Stack summary

| Layer | Choice | Why |
|-------|--------|-----|
| Gateway | Rust, Axum, Tower, Hyper | You have built this shape before. The latency budget demands it |
| Signatures | `alloy` | Native EIP-712 and EIP-3009, no FFI, no service hop |
| Protocol | x402, `exact` scheme (`upto` if P1 lands) | Interop with clients you did not write. No Rust reference facilitator exists yet, which is an opening |
| Hot state | Redis with one Lua claim script and a reservation stream | Atomicity and a crash bridge in one round-trip |
| Durable state | Postgres | The ledger must survive a restart while in use |
| Contract | Solidity + Foundry, one ~50 line pass-through | Small enough to read in one sitting |
| Chain access | `alloy` provider (settler), viem (dashboard) | |
| Dashboard | Next.js 14, wagmi, viem, Tailwind | |
| Client | Python (`httpx` + `eth-account`) | Agent frameworks are Python |
| Sample agents | One supervisor, three workers, under 150 lines total | Simple enough to read end to end |

## 14. Build order

Four phases. Cut down, not across.

**Phase 1.** x402 402 responder and payment-header decode. EIP-3009 verification with `alloy`. The
Lua claim script. SSRF-pinned proxy connector. Postgres schema. Prove an off-the-shelf x402 client can
pay you before moving on.

**Phase 2.** Capability struct, chain verification, multi-level decrement in the claim script. Settler
worker and `BatchSettler`, deployed to Base Sepolia. First end-to-end settled charge. Decide at the
end of this phase whether delegation is on track; if it is not, drop to receipts only.

**Phase 3.** Dashboard: provider view, delegation tree with live draining budgets, public feed,
latency panel. Signed receipts and the expense report endpoint. Python client with `delegate()`.

**Phase 4.** The `tollgate wrap` CLI if there is room. Sample agents that exercise the whole flow.
Walk through it end to end at least a few times, including the failure where a worker hits its cap,
before calling it done.

Cut first, in this order: the CLI, the `upto` scheme, window budgets, the refund path, channel mode,
the second chain. Do not cut: the atomic claim, SSRF pinning, or the delegation tree view.
