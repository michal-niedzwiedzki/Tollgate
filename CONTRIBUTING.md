# Contributing to Tollgate

Thanks for looking. This repository is built in an unusual way, and knowing that up front will
save you time — the conventions below are not style preferences, they are how the project stays
correct.

**Status:** testnet MVP. Base Sepolia only, no real value moves. One item is outstanding and
load-bearing: settlement has never run against the live testnet (`plan.md` Task 6.6). See the
[build status](README.md#build-status) before assuming something works end to end.

---

## The two rules that surprise people

### 1. The build follows `plan.md`, one task at a time

`plan.md` is not a roadmap, it is the build spec: 46 numbered tasks across 11 phases, each with an
**Implementation** section describing exactly what to write and a **Verification** block of
commands that must actually be run. A phase does not start until the previous **Phase Gate**
passes.

If you are executing the plan:

- Implement exactly what the task's Implementation section describes. Nothing else — no drive-by
  refactors, no extra abstractions, no "while I'm here" changes.
- Run every command in the Verification block and paste the real output. Never claim a
  verification passed without running it.
- Anything you notice that is out of scope goes in `NOTES.md` under **Deferred**, not into the
  diff.
- Do not build anything listed under **Post-MVP / Out of Scope**.
- If a task's Implementation section turns out to be wrong or impossible given the actual code,
  **stop and say so before writing anything.** This has happened repeatedly and the plan was
  wrong roughly as often as the code was.

### 2. Automated tools never touch git

This repository is built with Claude Code (see `EXECUTING.md`), under a hard rule: **the agent
never runs `git add`, `git commit`, `git push`, or any other state-changing git command.** It
writes files and reports; a human reviews the diff and commits it.

Every commit here was made by a person after reading the change. The commit messages that appear
in `plan.md` are suggestions *for the human*, not instructions for a tool. Read-only git — `status`,
`diff`, `log`, `show` — is fine.

If you are contributing with AI assistance, please hold the same line. The point is that no change
enters history unread.

---

## Getting set up

The [README quick start](README.md#quick-start) is the authoritative version and is verified to
work from a clean clone. In short:

```bash
./scripts/dev.sh                        # postgres + redis, migrated
cp .env.example .env && set -a && . ./.env && set +a
python3 examples/mock_upstream.py &
TOLLGATE_ALLOW_LOOPBACK_UPSTREAM=true cargo run -p tollgate-gateway
./scripts/seed_providers.sh
```

`.env.example` works as-is — the placeholder zero `USDC_ADDRESS` is fine, because nothing on the
request path touches a chain. You only need real values to run the settler.

---

## Before you open a pull request

```bash
./scripts/check.sh
```

That runs everything across all four languages and must exit 0:

| | Command | Notes |
|---|---|---|
| Rust | `cargo clippy --workspace -- -D warnings` | warnings are errors |
| Rust | `cargo test --workspace` | 111 unit tests, no external services |
| Solidity | `forge test` | forks Base Sepolia, so it needs network and takes ~60s |
| Python | `pytest client/tests/` | live-gateway tests skip themselves when nothing is listening |
| TypeScript | `npm run lint`, `tsc --noEmit`, `npm run build` | in `dashboard/` |

Integration tests are gated behind `--ignored` because they need Postgres and Redis running:

```bash
./scripts/dev.sh
cargo test --workspace -- --ignored      # 19 tests
```

Two known sharp edges, both documented in `NOTES.md`:

- **`cargo build --workspace` produces a gateway that panics on its first HTTPS request.** Feature
  unification gives rustls two crypto providers and no default. Build with
  `cargo build -p tollgate-gateway` until this is fixed.
- **`/v1/stats` percentiles are interpolated from coarse histogram buckets.** Below ~10 ms per
  request they are meaningful; above it they report bucket edges. Read the mean instead.

---

## House style

**Comments explain *why*, and cite the source.** This is the strongest convention in the codebase.
Nearly every non-obvious decision carries a comment naming the document that forced it —
`architecture.md` §9.1, `prd.md` F3, `NOTES.md` D11. If you change such code, update the reasoning
with it. A comment that merely restates the line below it is noise; one that says why the obvious
alternative is wrong is the thing that makes this code reviewable a year later.

**Test names are sentences.** `one_hundred_concurrent_claims_stop_exactly_at_max_total`,
`a_poison_entry_does_not_wedge_the_startup_replay`. The name states the property, so a failure
reads as a claim that stopped being true.

**A test must be able to fail.** When fixing a bug, run the new test against the *unfixed* code
first and confirm it fails. Several tests here are documented as having been verified that way,
and it is the only thing that distinguishes a regression test from decoration.

**Commit messages** are conventional-commit style, lowercase, imperative:

```
feat: decrement every capability level atomically on each charge
fix: page forward through the pending list on startup replay
test: give claim tests their own reservation stream
docs: add readme with quickstart, measured numbers and stated limits
chore: add reset script and fix defects found in demo rehearsal
```

---

## Where decisions live

`NOTES.md` is the project's memory, and it has two halves:

- **Decisions (D1–D22).** When two documents conflict, or a task leaves something open, the
  resolution is recorded with its reasoning and a number. These are not re-litigated later — if you
  think one is wrong, argue with the note, do not silently do something else. Several decisions
  deliberately diverge from `architecture.md`, and each says why.
- **Deferred.** Things noticed while doing something else, kept out of that change's diff. Each
  entry says what it is, why it was not fixed then, and what happens if it stays unfixed.

If your change resolves a Deferred item, move it to **Fixed** with a note on how it was verified,
rather than deleting it. The reasoning is usually the reason a regression test exists.

---

## Reporting a security issue

Tollgate handles payment authorisations, so please **do not open a public issue** for anything
security-relevant. Use GitHub's private vulnerability reporting on this repository.

The areas most worth attacking, and the ones a report will be taken most seriously in:

- **Free shopping** — any path that releases an upstream response before the atomic Redis claim
  returns `ok`.
- **SSRF** — defeating resolve-validate-pin, especially via DNS rebinding between validation and
  connect.
- **Attenuation bypass** — a capability chain that grants a child more than its parent holds, or a
  capability usable by anyone other than its bound subject.
- **Replay** — reusing an EIP-3009 nonce against the gateway inside its validity window.
- **Cap accounting** — any sequence that lets total spend exceed a capability's `maxTotal`.

Known and accepted limits are in [Known boundaries](README.md#known-boundaries); a report that
restates one of those is not a vulnerability, though an argument that a stated boundary is worse
than documented is welcome.

---

## Licence

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same terms that cover the project.
