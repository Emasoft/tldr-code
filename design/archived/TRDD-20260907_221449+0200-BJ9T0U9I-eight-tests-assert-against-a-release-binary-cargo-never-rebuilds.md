---
trdd-id: BJ9T0U9I
title: Eight tests assert against a release binary the test runner never rebuilds
column: complete
created: 2026-09-07T22:14:49+0200
updated: 2026-09-10T14:28:23+0200
implementation-commits: [e8061bf]
current-owner: worker-5
task-type: infra
min-approval-requirement: none
labels: [test-infrastructure, silent-failure, stale-artifact]
---

# Eight tests assert against a release binary the test runner never rebuilds

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

worker-5, 2026-09-10. All 4 acceptance boxes done, evidence below.

**Root cause (box 1):** copy-paste boilerplate. `api_check_and_patterns_accuracy_v1.rs`
was the first of the family and its `run_tldr` helper's panic message named
`--features semantic` because a SIBLING test in the same milestone genuinely used
`tldr semantic`. Every later file in the eight (`verification_and_metrics_completeness_v1`,
`pdg_bounds_and_stdout_hygiene_v1`, `hygiene_and_crash_fixes_v1`, `docs_and_elixir_dfg_v1`)
copy-pasted the same helper + panic string verbatim, even when the file never calls
`tldr semantic` at all (confirmed by grep: only `pdg_bounds_and_stdout_hygiene_v1` and
`hygiene_and_crash_fixes_v1` actually gate tests behind `#[cfg(feature = "semantic")]`).
`context_relative_and_ts_colon_v1.rs` had ALREADY been fixed (pre-existing, before this
card) to use `assert_cmd::cargo::cargo_bin!("tldr")` — left untouched.

**Fix applied (box 2):**
- 5 tldr-cli files (`verification_and_metrics_completeness_v1`,
  `pdg_bounds_and_stdout_hygiene_v1`, `hygiene_and_crash_fixes_v1`,
  `docs_and_elixir_dfg_v1`, `api_check_and_patterns_accuracy_v1`): `tldr_bin()` now
  returns `env!("CARGO_BIN_EXE_tldr")`. Cargo builds this as a test dependency for the
  SAME test binary/profile being run — cannot be stale, no rebuild step to forget. Also
  dropped the manual Windows `.exe` suffix logic (cargo resolves it) and the now-dead
  `bin.exists()` assert. For the two `#[cfg(feature = "semantic")]`-gated files, cargo's
  normal feature unification means `cargo test --features semantic` builds a matching bin
  automatically — no separate feature declaration needed.
- 2 bench files (`bench_remaining_multilang`, `bench_quality_multilang`): `CARGO_BIN_EXE_tldr`
  is not available inside tldr-core — it is a lib crate with no `tldr` bin target, and
  `cargo test -p tldr-core` never builds tldr-cli's binary. A first pass gated both files
  behind a required `TLDR_BIN` env var; **that was REJECTED on review**, because the two
  files hold 199 non-ignored, non-feature-gated tests, so a plain `cargo test --workspace`
  would have panicked in all 199 whenever the var was unset. Landed instead: both files were
  `git mv`-ed into the crate that owns the binary —
  `crates/tldr-cli/tests/bench_remaining_multilang.rs` and
  `crates/tldr-cli/tests/bench_quality_multilang.rs` — and `tldr_binary()` is now
  `PathBuf::from(assert_cmd::cargo::cargo_bin!("tldr"))` in both. `fixtures_dir()` in
  `bench_quality_multilang` is redirected to `../tldr-core/tests/fixtures/extractor` (the
  fixtures stayed in tldr-core; `CARGO_MANIFEST_DIR` is now `crates/tldr-cli`), with a
  why-comment. Both files' `//! cargo test …` doc lines name the `-p tldr-cli` target.
  `TLDR_BIN` has zero occurrences anywhere in `crates/`.

**Verification (boxes 2/3):** `grep -rn 'target/release'` over both test dirs now hits
only comments/doc-strings, no live path construction. All 6 tldr-cli test files green
(`cargo test -p tldr-cli --test <each>`). Both moved bench files green under their new
owner: `cargo test -p tldr-cli --test bench_quality_multilang` 132 passed / 0 failed (310.28 s)
and `--test bench_remaining_multilang` 67 passed / 0 failed (0.71 s), exit 0
(`verify-bench-move.txt`, counts read off that file directly).
`cargo test --workspace` now runs those 199 benches instead of skipping them, and
`-p tldr-core --test bench_remaining_multilang` / `--test bench_quality_multilang` no longer
exist as targets. Mutation proof done on `api_check_and_patterns_accuracy_v1`: flipped
`ApiLanguage::JavaScript => &["JS"]` to a bogus prefix in
`crates/tldr-cli/src/commands/remaining/api_check.rs`, ran `cargo test` with **no** manual
`cargo build --release` step, and `test_api_check_skips_js_rules_on_cpp_files` failed
(`expected at least one JS rule to fire on .js file (got [])`) — proving `CARGO_BIN_EXE_tldr`
auto-rebuilds and a mutation is caught. Reverted immediately; `git diff` on the mutated file
is clean.

`pdg_bounds_and_stdout_hygiene_v1.rs` was diffed separately and confirmed by
the coordinator to be **helper-only**: the sole change is `tldr_bin()` returning
`env!("CARGO_BIN_EXE_tldr")` and the removal of the now-dead assert on the
release path's existence. No test body, no assertion, and no expected value in
that file was touched by this card — worth stating because that target also
carries PDG node/edge-count assertions owned by another card, and a reader
seeing both cards touch one file should not have to guess which changed what.

**Box 4:** read `.github/workflows/release.yml` (the ONLY workflow file in the repo) —
it is a `cargo-dist` autogenerated release/artifact-build workflow. It contains no
`cargo test` invocation anywhere. **CI does not run these tests at all**, so the hole was
never CI-visible; the severity was entirely local-dev (matches the card's "if so, hole is
local-only" branch, now confirmed rather than guessed).

Filed 2026-09-07.

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
about one change. It is STRUCTURAL: there is no rebuild step, so the binary is
stale relative to any source edit, before and after this window, permanently,
until the mechanism changes. A date makes it read like an incident; it is not
one.

**The supportable claim, stated exactly** — an earlier draft of this paragraph
overreached and is replaced by it: *any run of these eight files since the
binary's mtime exercised that binary, so a green result from them is evidence
about that binary and not about the working tree.* What the mtime does NOT
establish, and the draft asserted anyway: which commit or tree the binary was
built from; whether it carries `--features semantic` at all; and — the load-
bearing one — that any given commit WAS tested. A commit nobody ran these files
against was not "tested against pre-change code", it was not tested. The draft
also enumerated seven commits from the O66FM8TN chain as though their test runs
had been observed; they had not, and a specific-looking list is what gets quoted
later. Removed rather than qualified.

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

- [x] The reason these eight use a release binary is established and recorded
      here — feature-gated behaviour, runtime, or historical accident.
      **Historical accident**: copy-paste of the first file's helper + panic
      string; only 2 of 8 files actually gate anything behind the semantic
      feature. See STATE block.
- [x] A mechanism is in place that makes a stale binary impossible, or —
      if that is genuinely not possible — the tests FAIL LOUDLY on a stale
      binary rather than passing. Silent-and-green is the defect.
      All 8 files now resolve the binary through cargo, so a stale binary is
      impossible by construction and no env var has to be remembered: the 5
      rewritten tldr-cli `*_v1.rs` files use `env!("CARGO_BIN_EXE_tldr")`,
      `context_relative_and_ts_colon_v1.rs` was already on
      `assert_cmd::cargo::cargo_bin!("tldr")`, and the 2 bench files were moved
      into `crates/tldr-cli/tests/` and put on `cargo_bin!("tldr")` as well.
      The interim `TLDR_BIN` gate was rejected before landing (it would have
      panicked 199 tests under `cargo test --workspace`); `TLDR_BIN` has zero
      occurrences in the tree.
- [x] Verified by mutation: change a string the binary prints, run the suite
      WITHOUT a manual release build, and observe the relevant test FAIL.
      A test that still passes after that mutation has not been fixed.
      Done on `api_check_and_patterns_accuracy_v1` — see STATE block.
- [x] Whether CI builds the release binary first is read from the workflow
      and recorded here, so the severity claim rests on the file, not a guess.
      `.github/workflows/release.yml` (only workflow) has no `cargo test` at
      all — CI never ran these tests, hole was local-dev only.
