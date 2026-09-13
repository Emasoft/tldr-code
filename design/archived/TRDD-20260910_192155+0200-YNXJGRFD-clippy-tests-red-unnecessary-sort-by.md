---
trdd-id: YNXJGRFD
title: clippy with --tests is red at perf_abstract_interp_benchmark.rs 394 unnecessary_sort_by
column: complete
created: 2026-09-10T19:21:55+0200
updated: 2026-09-13T16:29:03+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [clippy, gates]
assignee: session-claude
created-by: session-claude
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

- [x] `cargo clippy -p tldr-core --lib --tests -- -D warnings` exits 0
  at the closing commit, exit code quoted, no new `allow` attribute.

## Notes and lessons learned
Scope grew past the title: the title names line 394, but the acceptance names the workspace-scoped `--lib --tests` command, which aborts on other targets before reaching this file. Four sites were fixed, not one — perf_abstract_interp_benchmark.rs:394 (unnecessary_sort_by), analysis_tests.rs:225 and :229 (unnecessary_unwrap), inheritance_tests.rs:739 (for_kv_map). Recorded because the acceptance text, not the title, is what the card promised.
The "pre-existing at a5bff82" claim was NOT measured and will not be. Dating the lint needs a build of an old checkout (multi-GB; disk is the constraint) and the result changes no action — the fix is identical either way. A deliberate drop on 2026-09-13, not an oversight.
What the green gate does NOT prove: the sort at line 394 is exercised by no runnable assertion on this machine. The only test in that file is #[ignore]d and self-skips when an external corpus is absent, then reports ok. Reverse preserves descending order per the type checker and by reading, not by measurement. That self-skipping test reporting success for doing nothing is its own latent defect, same shape as TRDD-Q7VXK3M2. The unwrap rewrites are semantics-unchanged per the compiler (a move-out would not compile), not per the passing tests.
Method note for anyone editing with fastedit --replace: tldr slice returns only the lines on the dataflow path from the criterion — 6 of 28 for one function measured here (test_detect_mixins_by_usage, span 726-753, criterion 745, returned 731/734/735/739/740/745) — so a body reconstructed from it loses the rest. Reported once by a worker and confirmed once directly. Only the mandated fastedit diff review caught it, twice, in this card;s own work. Read real bytes before any --replace.

## Approval log

- 2026-09-13T16:29:03+0200 — COMPLETE by emanuelesabetta. archived → complete.
