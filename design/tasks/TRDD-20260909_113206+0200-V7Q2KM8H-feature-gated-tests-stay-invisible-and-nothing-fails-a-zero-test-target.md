---
trdd-id: V7Q2KM8H
title: Feature-gated tests stay invisible in four files and nothing fails a zero-test target
column: backburner
created: 2026-09-09T11:32:06+0200
updated: 2026-09-09T11:32:06+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-visibility, feature-gates]
parent-trdd: 9788CCBA
---

# Feature-gated tests stay invisible in four files and nothing fails a zero-test target

Split out of TRDD-9788CCBA (archived 2026-09-09), which fixed ONE instance: the crate-level
`#![cfg(feature = "semantic")]` in `crates/tldr-cli/tests/semantic_lang_flag_test.rs`, now a
per-test `#[cfg_attr(not(feature = "semantic"), ignore)]` so the three tests are listed as
`ignored` instead of compiled out. Two things that card's acceptance named are NOT done and
live here so they do not vanish into an archived card.

## What is known

- **Item-level gates, pre-existing at HEAD, in four `tldr-cli` test files:**
  `pdg_bounds_and_stdout_hygiene_v1.rs` (lines 75, 110), `language_command_matrix.rs` (49, 1728,
  1748), `hygiene_and_crash_fixes_v1.rs` (107, 143, 172, 218, 248), `exhaustive_matrix.rs`
  (38, 43, 56, 1368, 1386, 1411, 4060-4382). In `language_command_matrix.rs` the gate covers a
  `gen_lang_tests_serial!` invocation, so `check_semantic`, `check_similar` and `check_embed`
  are reported as never used under default features: same mechanism as the parent card, one
  level down — the tests are invisible, the target is not vacuous. The other three files: gate
  lines found, NOT read.
- **No consumer runs them anyway.** The single workflow contains no `cargo` invocation; the
  Makefile runs only the two `--lib` targets. Nothing in CI or the Makefile executes any
  integration target (parent card, box 1).
- **No guard fails a zero-test target.** The next crate-level `#![cfg(feature = …)]` anyone adds
  will again print `test result: ok. 0 passed` and nobody will see it.

## Next action

Read each of the four files at the gated lines before touching them: a gate on a `use` or a
helper that only resolves under the feature cannot take `ignore` (the attribute still compiles
the body), and a gated macro invocation is not a `#[test]`. Then apply the parent card's
one-line pattern where it fits, and decide whether a zero-test-target guard is worth building
while no CI runs integration targets at all — if yes, it must be demonstrated by a check that
REDS when a target is emptied, not one that passes against the current tree.

## Acceptance

- [ ] Each of the four files read at its gated lines; for each, either the `ignore` pattern
      applied and the target's default-run `test result:` line quoted with the `ignored` count,
      or one sentence why it cannot apply.
- [ ] A decision recorded on the zero-test-target guard: built and red-proofed by emptying a
      target, or explicitly declined with the reason (no consumer).
