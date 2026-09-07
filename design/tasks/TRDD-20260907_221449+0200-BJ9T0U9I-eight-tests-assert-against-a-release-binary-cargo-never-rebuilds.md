---
trdd-id: BJ9T0U9I
title: Eight tests assert against a release binary the test runner never rebuilds
column: todo
created: 2026-09-07T22:14:49+0200
updated: 2026-09-07T22:14:49+0200
current-owner: session-claude
task-type: infra
min-approval-requirement: none
labels: [test-infrastructure, silent-failure, stale-artifact]
---

# Eight tests assert against a release binary the test runner never rebuilds

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-07. **Not started.**

Found while measuring TRDD-K3XQ7M2V's acceptance, first recorded there as a
scope footnote on one acceptance box. **That framing was too small and this card
is the correction:** the hole is project-wide and predates that change.

## What

Eight test files invoke `target/release/tldr` directly:

```
crates/tldr-cli/tests/verification_and_metrics_completeness_v1.rs
crates/tldr-cli/tests/api_check_and_patterns_accuracy_v1.rs
crates/tldr-cli/tests/pdg_bounds_and_stdout_hygiene_v1.rs
crates/tldr-cli/tests/hygiene_and_crash_fixes_v1.rs
crates/tldr-cli/tests/docs_and_elixir_dfg_v1.rs
crates/tldr-cli/tests/context_relative_and_ts_colon_v1.rs
crates/tldr-core/tests/bench_remaining_multilang.rs
crates/tldr-core/tests/bench_quality_multilang.rs
```

The shape (from `api_check_and_patterns_accuracy_v1.rs:35-51`) walks up from
`CARGO_MANIFEST_DIR` to the repo root, appends `target/release/tldr`, asserts
`bin.exists()`, then `Command::new(&bin)`.

**`cargo test` builds DEBUG targets. It never rebuilds `target/release/`.** So
these tests exercise whatever release binary was last built by hand. Measured
2026-09-07: that binary was dated **Sep 5 22:11** while the working tree's
sources were edited **Sep 7 20:33-21:33**. Two days stale, and green.

## Why this is worse than a failing test

Two failure modes, and the quiet one is the problem:

| state of `target/release/tldr` | behaviour |
|---|---|
| ABSENT | `assert!(bin.exists())` panics — loud, unmissable |
| STALE | tests pass, against code that is not the code under test |

The absent case was observed the same day in a detached worktree: four tests in
`api_check_and_patterns_accuracy_v1` failed instantly (`0.00s`) with
`expected release tldr binary at <path> (run cargo build --release --features
semantic)`. The stale case produces `5 passed` in `0.03s` and looks exactly like
success.

**Scope, and this is the part the original footnote got wrong.** This is not
about one change. Any commit since the release binary was last built has been
"tested" by these eight files against pre-change code. That covers the whole
TRDD-O66FM8TN chain (`b64d541`, `e83d2b4`, `9dabab1`, `6d43608`, `b888b2d`,
`804dd75`, `0063e1b`) and anything else landed in that window. A green CI or
local suite in that period does not mean what it appears to mean for these files.

**NOT established, and do not assume either way:** whether CI builds the release
binary before running tests. If it does, the hole is local-only, which changes
the severity but not the fix. Read the workflow before claiming either.

## The fix — prefer the one that cannot go stale

1. **`env!("CARGO_BIN_EXE_<name>")`** — cargo builds the binary as a test
   dependency and hands over its path. Cannot be stale by construction, needs no
   harness step, and the `bin.exists()` assert becomes dead code. This is the
   right answer unless something below rules it out.
2. A build step in the test harness — works, but only where the harness runs;
   a developer invoking `cargo test` directly gets the stale binary again.

**The real question to settle first:** these tests use the RELEASE binary
deliberately — `--features semantic` appears in the panic message, so they may
depend on a feature or on release-mode behaviour that a debug `CARGO_BIN_EXE`
build would not reproduce. `CARGO_BIN_EXE_` gives the profile cargo is currently
building. If the tests genuinely need release+semantic, option 1 needs a feature
declaration, not a blind swap. Read one of the eight and find out what it needs
before rewriting all eight.

## Acceptance

- [ ] The reason these eight use a release binary is established and recorded
      here — feature-gated behaviour, runtime, or historical accident.
- [ ] A mechanism is in place that makes a stale binary impossible, or —
      if that is genuinely not possible — the tests FAIL LOUDLY on a stale
      binary rather than passing. Silent-and-green is the defect.
- [ ] Verified by mutation: change a string the binary prints, run the suite
      WITHOUT a manual release build, and observe the relevant test FAIL.
      A test that still passes after that mutation has not been fixed.
- [ ] Whether CI builds the release binary first is read from the workflow
      and recorded here, so the severity claim rests on the file, not a guess.
