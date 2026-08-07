# NOTES

## Decisions

Ambiguities and doc conflicts resolved before executing a phase, so no task has to re-litigate
one mid-build. The same role `plan.md`'s "Assumptions and ambiguities discovered" section plays
for the plan as a whole, for things the plan itself left open.

### Phase 5 — capability delegation

Settled 2026-08-06, before Task 5.1, from a read of `plan.md` §Phase 5, `architecture.md` §5 and
§9.3, and the Phase 0–4 code as built. Ten decisions, D1–D10.

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

---

## Deferred

Things noticed during execution that are out of scope for the task that surfaced them.
Not committed to the diff; recorded here per `CLAUDE.md`'s scope rule.

### `policy::multilevel` makes the integration suite flaky (~1 run in 3)

**Found:** 2026-08-06, running the full `--ignored` suite after the drain-wedge fix.

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

**Why deferred, not fixed:** it surfaced during an unrelated change and folding a test-isolation
fix into the drain-wedge commit is exactly what this file argued against for the wedge itself.
The fix is small but has a design choice in it: hoist `STREAM_LOCK` out of `mod claim` into the
`policy` test scope so both modules share one lock, or give `mod multilevel` its own stream key
so it never touches `tg:reservations` at all. The second is better — tests that do not need the
shared stream should not contend for it — but it means threading a stream key through
`ClaimArgs`, which is production surface changed for a test's benefit.

**Effect if left as is:** `cargo test --workspace -- --ignored` fails intermittently on an
assertion unrelated to whatever is being changed, which will waste time and erode trust in the
suite.

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
