# NOTES

## Decisions

Ambiguities and doc conflicts resolved before executing a phase, so no task has to re-litigate
one mid-build. The same role `plan.md`'s "Assumptions and ambiguities discovered" section plays
for the plan as a whole, for things the plan itself left open.

### Phase 5 — capability delegation

Settled 2026-08-06 from a read of `plan.md` §Phase 5, `architecture.md` §5 and §9.3, and the
Phase 0–4 code as built. Eleven decisions: D1–D10 before Task 5.1, and D11 after the Phase 5 Gate
run, which is the one that surfaced it.

**D1. The capability header stays optional, permanently. This is the load-bearing one.**

`architecture.md` §4.2 marks `X-Tollgate-Capability` optional, `prd.md` F3 (per-request cap, total
cap, allowlist) is a standalone P0 that does not mention delegation, and every Phase 2–4 gate item
pays with no capability header at all. So Task 5.4's "**replace** the single payer-level key list"
is read as *extend*, not *replace*:

- No header → exactly one level, keyed by `policy::payer_cap_hash(payer)`, seeded by
  `POST /v1/budgets`. Byte-for-byte the Phase 3 behaviour.
- Header present → one level per verified chain link, root first.

`POST /v1/budgets` and `payer_cap_hash` therefore **survive Phase 5**. Their current doc comments
predicting their own removal (`routes/budgets.rs`, `policy.rs`) are wrong and get corrected in
Task 5.4. The payer hash is not a "stand-in" — it is the degenerate one-level chain.

Both paths build the same `Vec<CapLevel>` through one function, so `claim.lua`, `policy::void`,
the ledger drain, the Phase 6 settler and the Phase 9 dashboard see one shape and never branch on
whether delegation was used. This is what keeps Phase 5 from reaching backwards or forwards.

**D2. Maximum chain depth is 4 links total, and therefore at most 4 counters.**

Task 5.4's "up to 4 levels + the funding root" implies five. It is wrong. `architecture.md` §5.2
rule 1 caps total depth at 4, and §5.3 Resolution A — the locked funding decision — makes the
chain "pure policy": the parent funds the child wallet on-chain up front, so there is no separate
funding-root capability to count. Link 0's issuer *is* the funding wallet. `maxDepth` constrains
how many further links may be issued below a link; it is not a fifth counter.

**D3. `architecture.md` §5.2 rule 2 is deliberately not enforced.**

Rule 2 ("link 0's issuer is the wallet that signs the EIP-3009 payload") and rule 5 ("the final
link's subject is that same signer") cannot both hold for any chain of depth ≥ 2 under Resolution
A, where the worker holds its own USDC and signs its own payments. `plan.md`'s Task 5.3 already
omits rule 2 and keeps rule 5; that omission is correct, and this records it as intentional rather
than an oversight.

Rule 5 is the property that matters — it is what makes a stolen capability useless. A root issuer
is unconstrained because a root capability grants nothing it must hold: the money that moves is
the payer's own, by the payer's own signature. Under Resolution B (channel mode, P1) the parent
does hold the pooled balance, rule 2 becomes both meaningful and enforceable, and it should be
reinstated at that point.

**D4. The drain writes the chain. `chain_hashes` lands in Task 5.4, not Task 5.6.**

`claim.lua` already puts `cap_hashes` into every stream entry; `ledger::insert_reservation`
currently discards it. Task 5.6 assumes the column is populated but never says who populates it.

Resolution: `migrations/0002_chain_hashes.sql` and the drain change both move **into Task 5.4** —
the task that first creates multi-level charges — so no charge is ever written that Task 5.6
cannot rebuild from. Task 5.6 becomes a pure consumer. The migration keeps the filename
`plan.md` names, so the plan's text still resolves.

The drain writes `chain_hashes` for **every** charge, including the D1 single-level payer case.
One write path, one rebuild path, no NULL special-casing — and Phase 3/4 payer budgets gain
boot-time rebuild for free.

**D5. `authorisations.capability_hash` gets the leaf hash; ancestors live only in `chain_hashes`.**

The existing column is singular and indexed `(capability_hash, created_at DESC)`. The question it
answers is "which agent spent this", so the leaf is the right occupant: it is the subject that
made the request. NULL under D1. Ancestor attribution is `chain_hashes`, which needs no index
until Phase 9 asks for one. Phase 7's receipts and expense report and Phase 9's agent view both
get what they need with no further migration.

**D6. Capability rows are a hard precondition for the claim, so the drain can never be poisoned.**

`authorisations.capability_hash` is `REFERENCES capabilities(hash)` and the drain inserts
asynchronously. If a capability row were ever missing, the drain would take a permanent FK
violation — a poison entry, which is exactly the wedge below.

So Task 5.4 persists the whole chain into `capabilities` **synchronously, before the claim**, and
a failure there fails the request closed (500) rather than proceeding. A stream entry can then
never reference a capability row that does not exist. `chain_hashes` carries no FK and so cannot
poison the drain under any circumstance.

Row shape: insert root-first, `ON CONFLICT (hash) DO NOTHING`; a root's `parent_hash` is **NULL**,
never 32 zero bytes, because the column is a self-FK and `0x0` is not a row; `allowlist` NULL
means inherit.

**D7. No Redis TTL on `tg:cap:*:meta` or `tg:cap:*:spent`.**

Task 5.4 says to seed meta with an "expiry TTL". Doing so is wrong twice over: expiring `:meta`
while `:spent` survives orphans the counter, and an expired capability would surface as the claim
script's `missing_meta` — which maps to 402 `insufficient_funds`, not the 403 `capability_expired`
that `architecture.md` §4.3 requires.

Expiry is enforced in Rust by Task 5.3 rule 7, before the claim, where it produces the correct
403. `expiry` is still *written* into `:meta` as a plain field for the rebuild and the dashboard,
but nothing reads it on the hot path and `claim.lua` is unchanged — it still reads only
`max_total` and `max_per_request`. Key growth is bounded by capability count, not by time;
a sweep for long-dead capabilities is a Post-MVP concern, not an MVP one.

Meta is upserted **only after `verify_chain` returns Ok**, so meta can only ever be written from a
chain that has already passed attenuation. That ordering is an invariant, and gets a comment
saying so.

**D8. The boot rebuild counts `failed`, and excludes only `voided`.**

`plan.md` Task 5.6 and `architecture.md` §9.3 both say `reserved + queued + settled`. That drops
`failed`, which is a charge whose upstream work *was* delivered to the caller and whose on-chain
settlement later reverted. Excluding it hands the agent its budget back at every restart — the
cap-accounting leak §9.3 itself warns about, in the one product area §9.3 calls "the whole
product". So the sum is `status IN ('reserved','queued','settled','failed')`, and `voided` — the
only status where the caller got nothing — is the sole exclusion.

Task 5.6's step 1 (`GROUP BY capability_hash`) is superseded by its own step 2 and dropped: it
would under-count every ancestor. One query, `unnest(chain_hashes)`, grouped by the unnested hash.

**D9. Revocation is one `SMISMEMBER`, and a revocation may not be future-dated.**

Task 5.3's `revoked_set` parameter implies a pre-fetch. It is one pipelined `SMISMEMBER tg:revoked
h1..hn` for the whole chain — a single round-trip, inside the `capability` histogram — not
`SMEMBERS`, whose transfer is unbounded. `verify_chain` stays a sync pure function over the
already-fetched result, exactly as the plan's signature implies, and so stays trivially testable.

Task 5.5's `Revocation.issuedAt` is checked as `issuedAt <= now + clock_skew`. No lower bound:
revocation is idempotent and monotonic, so replaying an old one can only re-revoke something
already revoked, but a future-dated one is meaningless and cheap to refuse.

**D10. A committed signing harness, `examples/sign.py`, lands in Task 5.1.**

Every `curl` line in Tasks 5.3–5.6 and half the Phase 5 Gate needs `$P`, `$CHAIN` and
`$SIGNED_REVOCATION`, and the repo contains no committed tool that can produce any of them. That
makes a signer a *verification prerequisite*, not scope creep — `CLAUDE.md` forbids claiming a
verification passed without running it.

It is a throwaway test harness (stdlib + `eth-account`), explicitly labelled as such, and it is
**not** the Phase 8 client: `client/tollgate/` is the real library and Phase 8 replaces this. It
also gives Task 5.1's `capability_vectors.json` the cross-language check that fixture exists for,
a phase before the Python client needs it.

**Amended while executing Task 5.1 (2026-08-06): the harness moves to Task 5.3.** Task 5.1's own
Implementation section does not mention it and its Verification block is entirely Rust unit tests,
which passed without it. Building it during 5.1 would have been scope this project's rules
explicitly forbid. Task 5.3 is the first task whose verification actually needs a signed chain on
the wire, so it lands there. `capability_vectors.json` exists as of 5.1 either way, so the harness
has vectors to check itself against whenever it is written.

**D11. Exhausting a total cap is 402, not 429. The Phase 5 Gate's wording was corrected, the
code was not.**

Settled 2026-08-06, after the Phase 5 Gate run, which failed on exactly this line.

The gate said worker 2 "hits its cap and receives **429**". It receives **402
`insufficient_funds`**. Four sources agree the code is right and the gate line was wrong:

- `architecture.md` §4.3 — *Insufficient budget* → 402 `insufficient_funds`; *Cap exceeded* → 429
  `cap_exceeded`. A **total** cap running out is the former; a **per-request** cap violation is
  the latter.
- `plan.md` Task 3.3 — implements precisely that split, and is committed.
- The **Phase 3 Gate** asserts both halves: "50 `insufficient_funds`" for budget exhaustion and
  "Cap exceeded returns 429" for the per-request cap. Making worker 2's refusal a 429 would have
  broken the first.
- **`prd.md` §9 step 3, the requirement the gate line claims to encode, specifies no status code
  at all** — only that worker 2 "hits its cap mid-task and stops". Nothing in the product spec
  ever asked for 429 here.

So the Phase 5 Gate line was the lone outlier and has been corrected in `plan.md`, with the
reasoning inline there. This is the only edit made to `plan.md` in this project.

What the gate actually cares about — *which* level said no — holds either way, because Task 5.4
gave the 402 body the same `tripped_level`, `capability_hash` and per-level `chain` the 429
carries. Observed under real concurrency: workers 1 and 3 succeed 6/6, worker 2 succeeds exactly
twice against its 0.10 cap and is then refused with `tripped_level: 1`, its own capability.

### Phase 7 — receipts and expense report

Settled 2026-08-12, before Task 7.1, from a read of `plan.md` §Phase 7 and the Phase 0–6 code as
built. Both are things Task 7.1's Implementation section leaves open that its own Verification
block then depends on.

**D12. `receipt_issued_at` is a fourth migration, because a receipt must be reproducible from
its row.**

Task 7.1 says to store the signature in `authorisations.receipt_sig` and to serve
`GET /v1/receipts/{nonce}`. Those two only compose if the endpoint can hand back the exact body
the signature covers — a signature over a body the server cannot reproduce is not a receipt,
and `prd.md` F6 is specifically about an artifact a third party can check without trusting this
gateway.

Every other signed field is already a column: `nonce` is the primary key, and `payer`,
`capability_hash`, `provider_slug`, `amount_wei` and `upstream_status` all exist from 0001.
`timestamp` is the only one with nowhere to live, so `migrations/0004_receipt_issued_at.sql`
adds it. `BIGINT`, not `TIMESTAMPTZ`: the signed field is a `uint64` of unix seconds and
storing the integer that was actually signed removes any chance of a timezone or sub-second
round trip changing the value between signing and verification.

**D13. `capabilityHash` is `0x0` for a payer-level charge, mirroring the column exactly.**

Under D1 the no-capability path is permanent, and under D5 those rows carry
`capability_hash IS NULL` while the leaf lives there for delegated charges. The receipt field is
a `bytes32` with no null, so the two candidates were `0x0` and the synthetic
`policy::payer_cap_hash(payer)` that `chain_hashes` records.

`0x0` wins for one reason: D12 requires the row to reproduce the signed body byte-for-byte, and
`capability_hash` is what the row has. Signing the synthetic hash would mean signing a value the
row does not store, so `fetch_receipt` could not rebuild it. `0x0` also reads correctly — this
charge drew on no capability — whereas the payer hash would name a `capabilities` row that does
not exist.

The consequence to know: `routes/proxy.rs`'s `sign_charge_receipt` and `ledger::fetch_receipt`
are two halves of one contract. A field encoded differently in either one produces a receipt
that fails to verify, so they change together or not at all.

**D14. The receipt rides inside the outcome marker, because promotion has two paths.**

Task 7.1 says "sign at promotion time" as though promotion happened once. It happens in two
places (Task 4.4): the request path's own `apply_outcome_update`, and the drain applying the
`tg:outcome:{nonce}` marker for the case where that UPDATE ran before the row existed. A receipt
written only by the first path would be silently lost whenever the second one is the live one —
the caller would hold a receipt in its response header that the ledger never recorded.

So `marker_value`/`from_marker` gained an optional `:issued_at:signature` suffix and both
`mark_outcome` and `apply_outcome_update` take the receipt. One key rather than a second
`tg:receipt:{nonce}` key: the marker already exists to carry exactly this kind of
decided-but-not-yet-writable state, and one key means one write and no new ordering invariant
between two keys that could be observed half-applied. `COALESCE` in the UPDATE means whichever
path runs second cannot blank what the first stored.

**D15. The expense report signature commits to a body hash, and the canonical form is
sorted-key compact JSON.**

Settled 2026-08-12, during Task 7.2.

`prd.md` story 8 wants a *signed* expense report, but a report is a variable-depth tree plus a
variable-length charge list and EIP-712 has no way to hash that directly. So the signed struct is

```solidity
struct ExpenseReport { bytes32 bodyHash; uint64 timestamp; }
```

where `bodyHash = keccak256(the exact JSON body served)`.

The canonical form is **compact JSON with object keys sorted** — `serde_json`'s `Map` is a
`BTreeMap` here, so serialising is already canonical, and
`json.dumps(body, sort_keys=True, separators=(",", ":"))` reproduces it byte-for-byte in Python.
That equivalence is the whole contract, and it is pinned by
`routes::expense::tests::the_signed_body_serialises_canonically` on the Rust side and exercised
against the live endpoint from Python during this task's verification.

`generated_at` and `signature` are **excluded** from the hashed body — neither can be inside its
own digest — and the timestamp is signed in the struct instead. That is why they are added to
the response object after hashing rather than being part of it: a verifier strips exactly those
two keys, re-serialises, and hashes. No field is duplicated between the body and the struct, so
there is nothing for the two to disagree about.

**D16. Report figures come from Postgres, not from the Redis counters.**

`/v1/capabilities/{hash}` reports live spend from `tg:cap:{hash}:spent`, because that is what
the claim script enforces against. The expense report deliberately does not: Redis is a
projection and Postgres is the truth (architecture.md §9.3), and a signed, auditable artifact
should be derived from the ledger rather than from the cache in front of it. Under normal
operation the two agree exactly; where they diverge, the ledger is the one worth signing.

The one exception is a payer-level report's `max_total`, which exists **only** in Redis — a
payer budget is seeded by `POST /v1/budgets` and has no `capabilities` row (D1). Its `spent`
still comes from the ledger like every other node.

Two consequences worth stating:

- `voided` is excluded from both `total_spent` and every node's `spent`, so a node's figure and
  the charges listed beneath it always add up. `failed` charges are **included** in the totals
  and counted separately in `failed_count` — the caller received the upstream's work and only
  the on-chain settlement reverted, so the budget was genuinely consumed. Same reasoning as D8.
- A node's `spent` is not the sum of its children's. It does not need to be: every charge
  decrements every level of its chain (architecture.md §5.2), so a supervisor's counter is
  already the whole subtree's total. Summing children here would double-count.

**D17. The settler records gas, because nothing else can.**

Settled 2026-08-12, before Task 7.3, **by the human** — it was raised as a blocking question
rather than decided unilaterally, because the fix necessarily reaches outside the task's stated
scope.

Task 7.3's `/v1/stats` reports gas per batch and gas per charge, and the Phase 7 Gate checks the
latter against `.gas-snapshot`. No gas figure existed anywhere: `chain::submit` had the receipt
in hand and kept only `tx_hash`, no column stored it, and the gateway is a separate process that
cannot read the settler's memory. Task 7.3's Implementation section names only two gateway
endpoints and never says where gas comes from.

Chosen: `migrations/0005_gas_used.sql` adds `gas_used BIGINT`, `SettlementOutcome` carries
`receipt.gas_used`, and `mark_settled` stamps it across the batch's rows. The alternative —
having the gateway fetch receipts over RPC when `/v1/stats` is called — was rejected: it needs
alloy provider dependencies in the gateway, puts network I/O on a read endpoint, and yields null
whenever the RPC is unreachable.

`gas_used` is NULL for rows settled through the ambiguous-timeout path, where the charge is
confirmed by `authorizationState` and no receipt is ever seen, and for rows settled before this
migration. NULL means "not known", never zero.

`gas_per_charge` divides the transaction's whole gas by the charges that **settled** in it.
Items the contract refused burned gas too and are not in that denominator, so the figure reads
slightly high — the conservative direction for a cost claim.

**D18. `total` is not the gateway's latency, so Task 7.3 needed a `gateway` stage.**

`prd.md` §8 budgets *added gateway latency* at 15 ms p50 and architecture.md §11 says the
upstream hop is "reported separately and never folded into your number". The `total` histogram
from Task 2.5 folds it in by construction — the RAII timer spans the whole handler, upstream
included — so there was no honest `gateway_p50` to report.

Reporting `total` under the name `gateway_p50` would have been precisely the conflation
`prd.md` §8 warns about, and summing the per-stage quantiles instead is not valid either
(quantile-of-sum ≠ sum-of-quantiles). So the proxy handler now records a `gateway` stage:
elapsed request time minus the measured upstream hop, a real per-request value.

Recorded only on the path that actually reached an upstream. A 402 or 409 refusal never pays for
one, and folding those cheap requests in would flatter the number.

**D19. Percentiles are parsed out of the metrics the gateway already exports.**

`PrometheusHandle` exposes no structured snapshot — `render()` is the entire public API — so
`/v1/stats` parses its own exported histogram buckets and interpolates, standard
`histogram_quantile` semantics. This is deliberate rather than merely expedient: `/v1/stats` and
`/metrics` are then the same numbers by construction, with no second copy of the latency data to
keep in step. An unobserved stage returns JSON null, never a fabricated zero.

`GET /v1/feed`'s `since` cursor is an ISO-8601 timestamp and returns strictly newer rows, so the
row that produced the cursor is not redelivered. `created_at` ties are theoretically possible at
microsecond resolution and would drop a row; a monotonic cursor is the fix if that ever matters.
`voided` charges are excluded, as everywhere else, and `status` is included so a reader can tell
a settled charge from a queued one without inferring it from `tx_hash` being null.

---

## Fixed

Items that were deferred and have since been resolved. Kept rather than deleted: the reasoning
is the reason the regression test exists, and a future reader who sees the cursor in
`replay_pending` deserves to know what it is defending against.

### The ledger drain's startup replay wedged on a permanently-unprocessable entry

**Found:** 2026-08-06, while re-verifying Phases 0–4 before starting Phase 5.
**Fixed:** 2026-08-06, after the Phase 5 Gate, as a standalone change.

`ledger::run` (`crates/tollgate-gateway/src/ledger.rs`) replays this consumer's pending list
before reading new entries:

```rust
loop {
    match read_group(&mut redis, "0", None).await {
        Ok(entries) if entries.is_empty() => break,
        Ok(entries) => apply_batch(&mut redis, &pg, entries).await,
        ...
    }
}
```

`apply_batch` deliberately leaves an entry un-acked when it cannot be applied (Task 3.4: "log and
continue; never let one bad entry stall the drain"). That is correct for the steady-state `>` loop,
which always advances. It is **not** correct for this startup loop, which re-reads from `0` — the
start of the pending list — every iteration. An entry that can never be applied is therefore
redelivered forever, `read_group` never returns empty, the loop never breaks, and the drain never
reaches the `>` loop at all. **No new reservation is written to Postgres for the remaining life of
the process.**

**Observed:** with 110 unprocessable entries in the PEL (left by the `policy::claim` integration
tests, whose nonces are not hex), a gateway restart produced 600,700 identical error lines —
the same 100 entries retried 6,007 times each — and six paid requests that returned 200 to the
caller wrote zero rows. `authorisations` stayed at 4. The request path itself is unaffected:
budget is claimed, the upstream is proxied, and the outcome marker is written; only the durable
ledger write is lost.

**Why this is not just test residue:** the test nonces are what filled the PEL here, but nothing
about the wedge is test-specific. Any permanently-failing entry does it — a `provider_slug` whose
row was deleted (FK violation), a payload a future migration cannot parse, a row hitting a new
CHECK constraint. One such entry silently stops all ledger writes from the next restart onward.

**Why deferred, not fixed:** out of scope for the two fixes requested (the x402 timestamp encoding
and the malformed test payout address). The fix is a change to Task 3.4's code with a real design
choice behind it — track the last-read id and page forward with `XREADGROUP ... <last_id>` instead
of re-reading from `0`, or bound the replay to one pass and let the `>` loop own the rest — and it
should be made deliberately rather than folded into an unrelated commit.

**Effect if left as is:** Phase 5 inherits it. The Phase 5 Gate's `FLUSHALL` + restart item
(Task 5.6) will pass, since `FLUSHALL` clears the PEL too, but any restart *without* a flush after
a poison entry lands leaves the gateway silently not persisting charges. Clearing the current
backlog with `XACK`, or a fresh `FLUSHALL`, restores normal operation until the next one.

**How it was fixed.** The startup replay moved out of `ledger::run` into `replay_pending`, which
tracks the last entry id it read and pages forward with `XREADGROUP ... <last_id>` instead of
re-reading from `0`. An entry that can never be applied is now passed over once per boot rather
than redelivered forever; it stays in the PEL for an operator to inspect or `XACK`, and every
entry behind it still lands. The steady-state `>` loop is unchanged, and Task 3.4's "log and
continue, never let one bad entry stall the drain" rule is preserved — it is finally true of the
startup path too, which is the half where it was not.

`read_group`, `ack`, `apply_batch` and `replay_pending` take the stream key as a parameter
instead of hardcoding `RESERVATIONS_KEY`. That exists so the regression test can drive the replay
against a throwaway stream without touching `tg:reservations` or racing the other integration
tests.

**Not scheduled into a plan task.** It was briefly earmarked for Task 5.6, then kept out: 5.6's
Implementation section describes the startup path as "already implemented" and asks for no change
there, and this note itself argued the fix should be made deliberately rather than folded into an
unrelated commit. It was done on its own afterwards instead.

**How the fix is verified.** `ledger::replay::a_poison_entry_does_not_wedge_the_startup_replay`
puts two unappliable entries in a consumer's PEL and asserts the replay returns. It was run
against the old re-read-from-zero loop first, where it failed on the 10s timeout, and against the
fix, where it passes in 0.06s — so the test is known to reproduce the bug rather than merely
passing.

Live: with a poison entry in `tg:reservations` and the gateway restarted, the log showed **one**
error line instead of the unbounded flood, `authorisations` went from 2 rows to 4 as later paid
requests landed, and the poison entry remained pending — one, not retried.

Separately, decision D6 removes the one *new* poison source Phase 5 would otherwise have
introduced (a `capability_hash` FK violation), so the fix is not covering for Phase 5's additions.

### `policy::multilevel` made the integration suite flaky (~1 run in 3)

**Found:** 2026-08-06, running the full `--ignored` suite after the drain-wedge fix.
**Fixed:** 2026-08-06, as a standalone change, before starting Phase 6.

`policy::claim::a_successful_claim_sets_the_nonce_ttl_charges_and_appends_to_the_stream`
asserts that exactly one entry was appended to `tg:reservations`:

```rust
assert_eq!(stream_len(&mut conn).await, before + 1, "one reservation appended");
```

Every test in `mod claim` takes a module-level `STREAM_LOCK` so those length assertions cannot
overlap each other. **`mod multilevel` — added in Task 5.4 — does not take that lock**, and its
five tests all invoke `ClaimScript::submit`, which `XADD`s to the same shared stream. When the
timing lines up, the assertion sees the stream grow by two:

```
assertion `left == right` failed: one reservation appended
  left: 362
 right: 361
```

**Measured:** full gateway `--ignored` suite, 3 failures in 6 runs. With `--skip multilevel`,
0 failures in 6 runs. Reproduced identically against `HEAD`'s `ledger.rs`, so it predates the
drain-wedge fix and is not caused by it — it has been latent since Task 5.4 and earlier "tests
pass" reports were luck.

**Product impact: none.** The claim script is correct and the concurrency test that matters
(`one_hundred_concurrent_claims_stop_exactly_at_max_total`) is unaffected, because it asserts on
spend counters rather than stream length. This is purely two test modules sharing one Redis
stream without sharing its lock.

**How it was fixed — the shared state was removed, not locked harder.**

Two options were on the table: hoist `STREAM_LOCK` so both modules share one lock, or stop the
tests touching `tg:reservations` at all. The second was chosen. A lock leaves the trap in place —
the next test module to claim against the shared stream reintroduces exactly this bug, and
nothing in the code would say so. Removing the shared stream removes the trap.

The cost turned out to be far smaller than this note first estimated. The stream is **already**
`KEYS[n+2]` of `claim.lua`; only the Rust caller hardcoded it. So `ClaimScript` gained a `stream`
field and a `with_stream` constructor, `new()` is `with_stream(RESERVATIONS_KEY)`, and the
invocation reads `self.stream`. No behaviour changes, no threading through `ClaimArgs`, and the
gateway's own call site (`ClaimScript::new()` in `main.rs`) is untouched.

Both test modules now build a throwaway stream per test and `DEL` it at the end.
**`STREAM_LOCK` is deleted** — with no other writer, `mod claim`'s assertion tightened from
`before + 1` to an exact `1`, which is a stronger claim than the locked version ever made.

**Verified:** full `--ignored` suite **0 failures in 15 runs** (was 3 in 6). Root cause confirmed
gone rather than merely quiet: across a full suite run `XLEN tg:reservations` is unchanged
(1728 → 1728), so the tests no longer write to the shared stream at all, and `KEYS tg:test:*`
is 0 before and after, so nothing leaks. The production path was smoke-tested separately because
this touched `policy.rs`: a paid request still returns 200, still `XADD`s to the real
`tg:reservations` (1728 → 1729), and the drain still persists it (4 rows → 5).


---

## Deferred

Things noticed during execution that are out of scope for the task that surfaced them.
Not committed to the diff; recorded here per `CLAUDE.md`'s scope rule.

### Task 6.6 — live Base Sepolia deployment and settlement

**Deferred:** 2026-08-08, after Tasks 6.1–6.5 were complete and committed.

**The Phase 6 Gate does not pass.** Four of its eight items require a real transaction on Base
Sepolia and are unverified: the 10 real paid requests settling in one transaction visible on
Basescan, the payout address balance increasing by exactly the sum of the charges, the measured
per-charge cost recorded in the README, and the Basescan link itself. Nothing after this point
should be read as claiming otherwise, and by `plan.md`'s own rule Phase 7 should not start until
this is closed.

**What is built and does work.** Everything in Tasks 6.1–6.5: the `BatchSettler` contract, its
tests, the deploy script, the anvil fork harness, the settler worker with batch selection and
submission, and per-item retry with bounded attempts. All of it has been exercised end to end
against a local anvil fork of Base Sepolia using **real native USDC** — so the EIP-712
verification, the `authorizationState` replay guard and the balance accounting that ran are the
real contract's, not a mock's. Three paid requests from the gateway settled in one transaction;
a spent nonce requeued alone with `retry_count` reaching 3 and `status='failed'` while the other
two settled untouched.

**What is therefore unproven.** Only the things a fork cannot show: that a real Base Sepolia
transaction lands and is publicly inspectable, and the true all-in gas cost including Base's L1
data-availability fee. The README's `## Settlement cost` figures are fork-measured execution gas
and explicitly exclude that L1 component — they are an estimate of the real number, not the real
number, and Task 6.6 is what replaces them.

**Why deferred:** it needs a funded settler EOA and a funded payer wallet, which only a human with
browser access to the faucets can obtain. It is not blocked on anything in the code.

**How to finish it, exactly.**

1. Fund a settler EOA with Base Sepolia ETH — a few thousandths is ample at ~0.006 gwei; the
   deploy is ~384k gas and a 10-item settle ~450k. Faucet: the Coinbase Developer Platform
   faucet. This wallet pays all gas and needs no USDC.
2. Fund a payer EOA with Base Sepolia USDC — 0.01 covers 10 requests at the seeded 0.001 price.
   Faucet: `faucet.circle.com`. This wallet signs payments off-chain and needs **no** ETH.
3. Both wallets must be plain EOAs with no contract code. USDC's `SignatureChecker` routes any
   `from` that has code to ERC-1271 instead of `ecrecover`, so a smart wallet — or any of anvil's
   ten default accounts, all of which are EIP-7702-delegated on Base Sepolia — cannot make a
   working EIP-3009 payment. Check with `cast code <addr> --rpc-url https://sepolia.base.org`;
   anything but `0x` is unusable. This cost two debugging sessions in Tasks 6.2 and 6.3; do not
   rediscover it.
4. Deploy with `contracts/script/Deploy.s.sol` against `https://sepolia.base.org`. Verify on
   Basescan with an Etherscan V2 API key, or on Blockscout, which needs no key.
5. Write `.env.base-sepolia` pointing at the real RPC, the deployed `BATCH_SETTLER_ADDRESS`, and
   `USDC_ADDRESS=0x036CbD53842c5426634e7929541eC2318f3dCF7e`. That address was confirmed on-chain
   as native USDC rather than bridged USDC.e: `name`/`symbol` "USDC", `decimals` 6, EIP-712
   `version` "2", and `authorizationState` present.
6. Run 10 paid requests through the gateway, then the settler once, and work through the Task 6.6
   verification block. Replace the README's fork-derived cost figures with the measured ones.

### `cargo build --workspace` produces a gateway binary that panics at startup

**Found:** 2026-08-12, during Task 7.3 verification, by building both binaries in one command.

The gateway asks for `hyper-rustls` with `ring`; the settler pulls `alloy`'s
`reqwest-rustls-tls`, which turns on `hyper-rustls`'s `aws-lc-rs`. Cargo unifies features per
dependency across a single invocation, so building both packages together links a gateway whose
rustls has **two** crypto providers and therefore no default. It then panics on the first TLS
setup:

```
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually, or make
sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
```

Confirmed with `cargo tree -e features -i rustls`, which shows `hyper-rustls feature "aws-lc-rs"`
arriving via `reqwest → alloy-transport-http → alloy feature "reqwest-rustls-tls"`.

**Not introduced by Phase 7.** The gateway's `hyper-rustls`/`ring` dates from Task 4.3 and the
settler's `reqwest-rustls-tls` from Task 6.4; the collision has existed since Phase 6 and only
shows when one cargo invocation builds both. `cargo build -p tollgate-gateway` alone produces a
working binary, which is why every previous phase's verification passed — and why this went
unnoticed.

**Effect if left as is:** whichever cargo command last wrote `target/debug/tollgate-gateway`
decides whether it runs. `cargo build --workspace` — the command the README's checks section
names — leaves a binary that dies on its first outbound HTTPS request. Local verification against
the mock upstream is over plain HTTP and unaffected, so this bites first against a real provider.

**Why deferred, not fixed:** out of scope for Task 7.3, whose Implementation section describes
two endpoints. The fix is a deliberate choice — call `CryptoProvider::install_default()` at
gateway startup, or align both crates on one provider — and it belongs in its own commit rather
than folded into a feed endpoint.

### Request path is not tolerant of a Postgres outage

**Found:** Phase 3 Gate, verifying "killing Postgres mid-run loses no reservations once it
returns" (2026-08-06).

`handle_proxy_request` (`crates/tollgate-gateway/src/routes/proxy.rs`) looks up the provider via
`db::get_provider` — a Postgres query — before any Redis-side claim logic runs. If Postgres is
unreachable, this returns `500 internal_error` immediately; the request never reaches the
Redis-only claim path at all.

This is not a Phase 3 regression. Provider lookup has depended on Postgres since Phase 1
(Task 1.2/1.3), and every request handler built since has inherited it unchanged. Verified during
the Phase 3 Gate that the *ledger* itself tolerates a Postgres outage correctly (a claim made
directly against the Lua script while Postgres was stopped still succeeded, stayed in the Redis
stream's pending list un-acked, and landed in `authorisations` once Postgres returned and the
gateway restarted) — so the guarantee `architecture.md` §9.3 actually makes ("Redis is a
projection, Postgres is the truth, the stream bridges them") holds for the ledger. That section is
scoped to reservations/authorisations, not to provider config, and nothing in `architecture.md` or
`prd.md` claims the request path as a whole should survive a Postgres outage.

**Why deferred, not fixed:** no task in `plan.md` proposes caching provider config outside
Postgres. Fixing it would mean adding a cache (Redis or in-memory) for `providers` reads, which is
scope beyond any single task's Implementation section. Every future phase inherits the same
characteristic unchanged — Phase 4's proxy needs `provider.upstream_url`/`timeout_ms` from the same
lookup before it can reach an upstream, so this isn't something Phase 4 introduces or needs to
resolve as a prerequisite either.

**Effect if left as is:** a Postgres blip mid-demo makes in-flight requests 500 instead of degrading
to a Redis-only path. Fail-closed, not a correctness or security issue — no data is lost, no charge
is mis-attributed. Does not block Phase 4.
