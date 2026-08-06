# NOTES

## Deferred

Things noticed during execution that are out of scope for the task that surfaced them.
Not committed to the diff; recorded here per `CLAUDE.md`'s scope rule.

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
