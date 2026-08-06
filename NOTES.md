# NOTES

## Deferred

Things noticed during execution that are out of scope for the task that surfaced them.
Not committed to the diff; recorded here per `CLAUDE.md`'s scope rule.

### The ledger drain's startup replay wedges on a permanently-unprocessable entry

**Found:** 2026-08-06, while re-verifying Phases 0–4 before starting Phase 5.

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
