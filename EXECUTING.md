# Executing plan.md with Claude Code

Four prompts. One at the start of each phase, one per task, and two for when things go wrong.

**Git is yours alone.** The agent never runs `git add`, `git commit`, `git push`, `git reset`,
`git checkout`, `git stash`, or any other command that changes git state. It writes files and
reports; you stage and commit. The commit messages in `plan.md` are suggestions for you to use, not
instructions for the agent.

---

## 0. One-time setup

Before the first session, create `CLAUDE.md` in the repo root so every session picks up the rules
without you restating them:

```markdown
# Tollgate

Build spec: `plan.md`. Requirements: `prd.md`. Design: `architecture.md`.

## Rules

### Git: never touch it

NEVER run `git add`, `git commit`, `git push`, `git reset`, `git revert`, `git checkout`,
`git switch`, `git stash`, `git merge`, `git rebase`, `git tag`, `git branch`, or `git clean`.
Not once, not "to be helpful", not even when a task in `plan.md` shows a commit message.

The commit messages in `plan.md` are for the human to use. You do not commit. The human commits
every change themselves, after reviewing it.

Read-only git is fine: `git status`, `git diff`, `git log`, `git show`.

When a task is finished, stop and say "Task N.M complete, ready for you to review and commit",
then show `git diff --stat` and the suggested commit message as text. Then wait.

### Everything else

- Execute `plan.md` one task at a time. Never start the next task without being asked.
- Never skip a task's Verification block. Run the commands. Paste the real output.
  Do not claim a verification passed without running it.
- Never move to the next phase until the Phase Gate passes.
- Implement exactly the task's scope. Anything you notice but that is not in scope goes in a
  `NOTES.md` "Deferred" list, not into the diff.
- Do not build anything in the "Post-MVP / Out of Scope" section of `plan.md`.
- If the task's Implementation section is wrong or impossible given the actual code, stop and
  say so before writing anything.

## Stack

Rust workspace (gateway + settler + core), Foundry contracts, Python client, Next.js dashboard.
Base Sepolia (84532), native USDC only. `alloy` for all signature work.

## Checks

`cargo clippy --workspace -- -D warnings` and `cargo test --workspace` must pass before any commit.
Later phases add `forge test`, `pytest`, and `npm run build` via `./scripts/check.sh`.
```

---

## 1. Phase start (once per phase, after `/clear`)

```
Read plan.md, architecture.md and prd.md.

We are starting Phase N. Do not write any code yet.

Tell me:
1. Phase N's objective and what will exist when it's done
2. Which previous-phase code each task touches, by file
3. Anything in Phase N that the current repo state contradicts or makes impossible
4. Any task whose Implementation section you think is underspecified

Then stop and wait.
```

Answering 3 and 4 before writing code is where this saves you time. If it flags nothing on a phase
you know is hard, that's a signal to push back rather than proceed.

---

## 2. Per-task prompt (the main one)

```
Execute Task 0.2 from plan.md.

Scope: only what that task's Implementation section describes. Nothing else, no drive-by
refactors, no extra abstractions, no "while I'm here" changes.

DO NOT COMMIT. Do not run git add, git commit, git push, or any git command that changes state.
I commit everything myself. The commit message in the task is for me, not for you.

Then:
1. Run every command in the task's Verification block. Show me the real output.
2. If a verification fails, fix it and re-run. Do not explain a failure away.
3. Run `cargo clippy --workspace -- -D warnings` and `cargo test --workspace`.
4. Show me `git diff --stat` and the suggested commit message as text, then stop.

If anything in the task turns out to be wrong or impossible, stop and tell me before writing code.
```

That's the prompt you'll paste ~46 times. Only the task number changes.

For the four or five tasks where correctness is the point (3.1, 4.1, 4.3, 5.3, 6.5), append:

```
This task is correctness-critical. Before implementing, list the failure modes you're defending
against and how each verification catches one. Then implement.
```

---

## 3. Phase Gate prompt

```
Run the Phase N Gate from plan.md.

Work through the checklist one item at a time. For each: run the actual command or test,
paste the output, and mark it pass or fail. Do not mark an item passed on the grounds that
the code "should" work.

Report failures as a list. Do not fix anything yet.
```

Then, if it fails:

```
Fix gate failures 1 and 3. Keep the two fixes as separate, reviewable changes and tell me a
suggested commit message for each. Do not commit. Re-run the full gate after.
```

---

## 4. When a task fails twice

```
Task N.M's verification has failed twice. Stop implementing.

Diagnose instead:
- What exactly is failing, with the output
- Root cause, not the symptom
- Whether the bug is in your implementation or in plan.md's design for this task

If plan.md is wrong, propose the correction and wait for me before changing it.
```

Two failures usually means the plan under-specified something. Fix `plan.md`, then re-run the task
prompt.

---

## 5. Context hygiene

- `/clear` between phases, not between tasks. A phase is roughly one coherent context.
- Keep `CLAUDE.md` short. It's prepended to every request.
- If a session starts drifting (proposing work outside the task, re-explaining the whole
  architecture), clear and restart from the phase-start prompt.
- Keep a running `NOTES.md` of deferred items so out-of-scope observations have somewhere to go
  other than the diff.

---

## 6. Model and effort

| Tasks | Model | Effort |
|-------|-------|--------|
| 3.1, 4.1, 4.3, 5.1, 5.3, 6.5 | Opus 5 | high |
| Phase 9, Task 10.3 | Sonnet 5 | low |
| Everything else | Sonnet 5 | medium |

If a task fails its verification twice on Sonnet, re-run it on Opus at high effort before assuming
the plan is wrong.
