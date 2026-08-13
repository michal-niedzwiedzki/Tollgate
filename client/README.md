# tollgate-client

Python client for [Tollgate](../README.md), an x402-compatible payment gateway.

It does three things: handles the 402 → sign → retry loop so a paid endpoint looks like an
ordinary HTTP call, signs EIP-712 capabilities so a supervisor can hand a sub-agent a scoped budget
with **one local signature and no server round-trip**, and collects the gateway's signed receipts.

```python
from tollgate import Session

s = Session(signer=private_key, gateway="http://localhost:8080")
r = s.get("http://localhost:8080/v1/proxy/geocode/lookup?q=Panaji")   # pays automatically
```

---

## Install

```bash
pip install -e client/          # from the repo root
```

Requires Python 3.9+. Dependencies: `httpx`, `eth-account`, `eth-utils`.

---

## Quickstart

Four commands and a script. Everything runs locally; nothing touches a chain.

### 1. Start the stack

```bash
./scripts/dev.sh                                    # postgres + redis, migrations applied
cp .env.example .env && set -a && . ./.env && set +a
python3 examples/mock_upstream.py &                 # a fake upstream on :9000
TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true cargo run -p tollgate-gateway &
```

There is no dotenv loader in the binary: `Config::from_env` reads the process environment and fails
loudly on a missing variable rather than defaulting a secret, so the `.env` has to be sourced into
the shell that starts the gateway.

Build the gateway with `-p tollgate-gateway`, not `--workspace`: building both binaries in one
invocation links a gateway whose rustls has two crypto providers and panics on its first TLS
connection. See `NOTES.md`.

`TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true` is what lets a provider point at `127.0.0.1`. It exists for
local development and **must never be true in a deployed config** — it disables the loopback half of
the SSRF denylist.

### 2. Register an endpoint — the provider path

One curl. No signup, no account, no billing code:

```bash
curl -s -X POST localhost:8080/v1/providers \
  -H 'content-type: application/json' \
  -d '{"slug":"quickstart","upstream_url":"http://127.0.0.1:9000",
       "price":"0.001","payout_address":"0x0000000000000000000000000000000000000001"}'
```

`price` is decimal USDC, converted to base units server-side. `payout_address` is where the money
lands: Tollgate never holds it.

### 3. Pay for a call — the agent path

```bash
python3 client/examples/quickstart.py
```

```
status : 200
body   : {'result': 'ok'}
receipt: 0x9a1f…
```

That script seeds a budget for a fresh keypair, calls the paid endpoint, and prints the upstream's
body and the receipt signature. The `Session.get` in it made two HTTP requests — one that got a 402
quote, one that carried the payment — and never looped.

---

## Delegation

The feature the gateway exists for. A supervisor grants a worker a scoped budget by signing a
capability; the worker presents the chain on every request; every charge draws down **every** level
of the chain, so a supervisor's pool visibly drains as its workers spend.

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

print(w.receipts())         # signed, per-charge, with tx hashes
print(sup.expense_report())  # rolled up across the whole delegation tree
```

This is `architecture.md` §7.3 verbatim, and `client/tests/test_e2e.py` runs it — against
`http://localhost:8080` with a path the mock upstream serves, since `gw.tollgate.dev` is not a
deployment that exists. `Session` reads `TOLLGATE_GATEWAY` from the environment, which is what lets
`sup.expense_report()` work above without the supervisor having made a request first.

`delegate()` issues **zero** HTTP requests. The capability is self-describing — its limits are
inside the signature the gateway verifies — so there is nothing to register.

**Attenuation is checked locally before signing.** A link may never grant more than its parent
holds, on any axis: `max_total`, `max_per_request`, `expiry`, `not_before`, `max_depth`, and the
allowlist. Violating one raises `AttenuationError` before a signature exists. The gateway enforces
the same rules and remains the security boundary; the local check just moves the error to where the
mistake was made.

Chains are at most **4 links** deep, and a stolen chain is useless: the last link's `subject` must
be the address that signs the payment.

---

## Exceptions

Every refusal is a typed exception carrying the response that explained it — `.status_code`,
`.code` and the parsed `.body`. All inherit from `TollgateError`.

| Exception | Raised when | Extra attributes |
|---|---|---|
| `InsufficientBudget` | 402 `insufficient_funds` — a **total** cap is exhausted. Retrying will not help | `tripped_level`, `capability_hash`, `remaining`, `chain` |
| `CapExceeded` | 429 `cap_exceeded` — this one charge is above a **per-request** cap. A smaller call would still work | `tripped_level`, `capability_hash`, `limit`, `remaining`, `chain` |
| `NonceReplay` | 409 — this authorisation was already claimed. Sign a fresh nonce | |
| `CapabilityExpired` | 403 `capability_expired`, or the local mirror reaching the same conclusion first | |
| `CapabilityRevoked` | 403 `capability_revoked`. Revoking a parent refuses its children too | |
| `CapabilityRejected` | 400/403 for the chain itself: `subject_mismatch`, `provider_not_allowed`, `attenuation`, `broken_chain` | |
| `UpstreamFailed` | 502/504 — the provider's service failed or timed out. Nothing was spent; the budget is credited back | |
| `AttenuationError` | Locally, before signing: the delegation would grant more than the delegator holds | |
| `PaymentFailed` | A second 402 answering a payment. **The client never retries twice** — an agent that loops on payment failures is the runaway this product exists to prevent | |

The two cap errors are deliberately distinct. Exhausting a total budget means stop; exceeding a
per-request cap means this call was too big. Casual speech calls both "hitting the cap", and they
call for opposite behaviour.

### The local mirror

A `Session` holding a capability copies exactly two things from it: the per-request cap and the
expiry. An expired capability is refused with **zero** HTTP requests; a quote above the per-request
cap is refused after the 402 and before the payment, saving the expensive round trip.

That is all it mirrors. `architecture.md` §7.3 — "the client mirrors caps locally so failures are
fast and error messages are good, but the server is the security boundary. Do not mirror the whole
policy engine." Total spend, revocation, allowlists and chain validity are all the gateway's call.

---

## Receipts

Every successful charge returns an `X-Tollgate-Receipt` header, collected into `session.receipts()`:

```python
{"nonce": "0x…", "payer": "0x…", "capability_hash": "0x…", "provider_slug": "geocode",
 "amount": "1000", "upstream_status": 200, "timestamp": 1786598490, "signature": "0x…"}
```

It is EIP-712 typed data signed by the gateway under the `Tollgate` domain. Recover the signature
and compare against `GET /v1/gateway-key` to verify it — the chain shows a transfer, but only the
receipt shows which endpoint, which sub-agent, and whether the upstream actually returned 200.

`capability_hash` is `0x0` for a charge that carried no capability chain. `tx_hash` is null until
the settler runs; look it up later with `GET /v1/receipts/{nonce}`.

---

## What is mocked

Stated plainly, because a stated boundary reads better than a discovered one:

- **Testnet only.** Base Sepolia, testnet USDC, no real value. One chain.
- **The payer needs USDC only for settlement, not for the gateway.** The gateway verifies
  signatures; it never checks a balance. A request signed by an unfunded key is served and then
  fails on-chain at settlement.
- **Budgets without a capability are seeded by a dev endpoint**, `POST /v1/budgets`. There is no
  authentication on it. It exists so the no-delegation path is usable locally.
- **Delegation funds children up front** (`architecture.md` §5.3 Resolution A). The parent sends
  USDC to each child wallet; the capability chain is pure policy on top. Channel-backed delegation,
  where children draw on a pooled parent balance, is designed and described but not built.
- **Settlement has not been run against live Base Sepolia** as of this writing — see `NOTES.md`.
  `tx_hash` is populated by a settler run against a local anvil fork.
- **No `upto` scheme.** Fixed per-request pricing only; a variable-cost endpoint cannot yet quote a
  maximum and settle less.

---

## Tests

```bash
pip install -e "client/[dev]"
pytest client/tests/                     # everything
pytest client/tests/ -k integration      # only the live-gateway tests
```

Integration tests skip with a reason when no gateway is reachable, so a missing stack can never look
like a pass. `client/tests/test_capability.py` checks Python's capability hashes against the
Rust-emitted golden vectors in `crates/tollgate-gateway/tests/fixtures/capability_vectors.json`, and
`client/tests/test_signing.py` writes `payment_vector.json`, which the Rust test `verify::python_vector`
reads back — the two cross-language fixtures are what keep the encodings honest.
