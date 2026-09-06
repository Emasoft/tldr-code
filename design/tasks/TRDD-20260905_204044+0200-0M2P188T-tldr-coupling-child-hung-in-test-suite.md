---
trdd-id: 0M2P188T
title: tldr coupling child hung 30 CPU-minutes once inside the test suite
column: planned
created: 2026-09-05T20:40:44+0200
updated: 2026-09-06T03:13:22+0200
current-owner: codebase-scan-2026-09-05
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, hang]
---

# tldr coupling child hung 30 CPU-minutes once inside the test suite

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- **IT RECURRED.** The body below says "Not reproducible standalone" and treats the hang as a
  one-off. On 2026-09-06 a per-package `cargo test -p tldr-cli --no-fail-fast -j 2 --
  --test-threads=2` run printed `test coupling_path_preserves_user_supplied has been running
  for over 60 seconds`, and the run was still sitting on it. So this is a SECOND observation,
  under different conditions from the first (per-package, 2 test threads, not the full
  workspace), which removes "it happened once" as a reason to deprioritise it.
- A second test in the same run also passed 60 s: `verify_command::test_verify_default_current_dir`.
  Whether that is the same defect, ordinary slowness, or contention from the constrained thread
  count is NOT established — noted so the next investigator checks rather than assumes.
- What is now worth doing FIRST, ahead of the body's step 1: the body's reproduction attempts
  were standalone runs of the binary, which never reproduced it. Both observations instead came
  from inside a multi-threaded `cargo test`. Reproduce it THERE — the suite context, not the
  binary in isolation, is the only place it has ever appeared.
- Nothing about the cause is settled. No scan hunk is implicated (see the body), and this
  session added no evidence about WHY, only that it happens more than once.

## Why
During the second full `cargo test --workspace` run of the scan landing (2026-09-05, parent
7f50527 plus the scan edits), the test
`path_and_schema_cleanup_v3::coupling_path_preserves_user_supplied`
(`crates/tldr-cli/tests/path_and_schema_cleanup_v3.rs`) never returned. Its child process,
`tldr coupling <tempdir>` with no `--format` flag (so the JSON path), spun from about 19:50 for
more than 45 minutes of wall time and over 30 CPU-minutes on one core. The temp dir still held
the python package fixture the test expects. Only the child was killed (`kill <pid>` at
20:37:28); the test then failed with the usual assert_cmd "Unexpected failure" and the run went
on. A hang inside a shipped command is a live defect even if it happened once, so it gets its
own card instead of a line in the pre-existing-failures list, where it does not belong: it was
never observed at the parent commit.

## What is known
- Not reproducible standalone. The parent-commit binary and the edited binary both finish
  `tldr coupling` on a comparable two-file python fixture in under 1.2 s for `json`, `text`
  and `compact`, with byte-identical output, from the repo root and from a temp cwd.
- The scan's hunks in `crates/tldr-core/src/quality/coupling.rs` add no loop (6 insertions,
  19 deletions, dead-code removal); the `text` formatting hunk is on a path the hung child
  never took. No scan hunk is implicated, but the cause is unknown.
- The sibling tests of that binary run in parallel threads, each with its own temp dir; only
  one child hung.

## What to do
1. Run the binary alone in a loop, 20 iterations each with `--test-threads=1` and with the
   default thread count, and record whether the hang recurs.
2. If it recurs, sample the child while it spins (`/usr/bin/sample <pid> 5` on macOS; the bare
   `sample` name can be shadowed by a Python shim) and attach the stack to this card.
3. Read coupling's directory walk and import resolution for an input that can loop or explode:
   a symlink cycle under the temp dir, or a cwd-relative path that resolves to the repo root
   and walks the whole workspace including `target/`.
4. Give the test's command a wall-clock bound (assert_cmd `.timeout(...)`) so a recurrence
   fails instead of stalling the whole suite.

## Acceptance
- [ ] cause identified with file:line, or 20 clean iterations per thread setting recorded here
- [ ] the test carries a timeout

## Approval log

- 2026-09-05T21:33:13+0200 — APPROVED by the session Claude under the user's 2026-09-05 directive to decide from verified facts and implement what is good. Work is authorized; no push.
