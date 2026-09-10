---
trdd-id: YNXJGRFD
title: clippy with --tests is red at perf_abstract_interp_benchmark.rs 394 unnecessary_sort_by
column: todo
created: 2026-09-10T19:21:55+0200
updated: 2026-09-10T19:21:55+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [clippy, gates]
---

`cargo clippy -p tldr-core --lib --tests -- -D warnings` exits 101 at
`crates/tldr-core/tests/perf_abstract_interp_benchmark.rs:394`
(`clippy::unnecessary_sort_by`), observed by worker-1b on the
2026-09-10 working tree. That file is unchanged since a5bff82, so the
red predates the wave's diff — INFERRED from the file's status, not
re-run at a5bff82; the phrase "pre-existing at a5bff82" in commit
218efb0's body and in the TRDD-2U7D9PNS note carries the same
inference. fmt is TRDD-U5KJ5A8R; the 2U7D9PNS note is a pointer, this
card owns the fix.

## Acceptance

- [ ] `cargo clippy -p tldr-core --lib --tests -- -D warnings` exits 0
  at the closing commit, exit code quoted, no new `allow` attribute.

## Notes and lessons learned
