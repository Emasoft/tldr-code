---
trdd-id: V7Q2KM8H
title: Feature-gated tests stay invisible in six test files and nothing fails a zero-test target
column: backburner
created: 2026-09-09T11:32:06+0200
updated: 2026-09-09T11:48:57+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-visibility, feature-gates]
parent-trdd: 9788CCBA
---

# Feature-gated tests stay invisible in six test files and nothing fails a zero-test target

Split out of TRDD-9788CCBA (archived 2026-09-09), which fixed ONE instance: the crate-level
`#![cfg(feature = "semantic")]` in `crates/tldr-cli/tests/semantic_lang_flag_test.rs`, now a
per-test `#[cfg_attr(not(feature = "semantic"), ignore)]` so the three tests are listed as
`ignored` instead of compiled out. What that card's acceptance named but did not deliver lives
here, plus the two targets its box 4 wrongly declared absent.

## What is known

- **Two more targets carry the parent's exact defect.** `crates/tldr-core/tests/semantic_tests.rs:1`
  and `crates/tldr-core/tests/semantic_test.rs:1` are `#![cfg(feature = "semantic")]`, found
  2026-09-09 by `grep -rn '^#!\[cfg' crates/*/tests/` after the parent was archived (its box 4
  says "no other crate-level gate"; the correction is in its Approval log). By the parent's
  mechanism both compile to zero tests and report `ok` under default features; unmeasured, no
  `test result:` line taken. Neither file read. Expectation, not
  read: `tldr-core` tests `use` semantic-only items, so the parent's `ignore` pattern would
  not compile there; candidates are `required-features` on a `[[test]]` entry, or a gated
  `mod` plus one always-present ignored test naming the feature.
- **Item-level gates, pre-existing at HEAD, in four `tldr-cli` test files:**
  `pdg_bounds_and_stdout_hygiene_v1.rs` (lines 75, 110), `language_command_matrix.rs` (49, 1728,
  1748), `hygiene_and_crash_fixes_v1.rs` (107, 143, 172, 218, 248), `exhaustive_matrix.rs`
  (60 hits: 38, 43, 56, 1368, 1386, 1411, then 54 between lines 4060 and 4382).
  In `language_command_matrix.rs` the gate covers a `gen_lang_tests_serial!` invocation, so
  `check_semantic`, `check_similar` and `check_embed` are reported as never used under default
  features; that warning is the only proof, no default-run `test result:` line was taken. The
  other three files: gate lines found, NOT read. Under `crates/*/tests/`, with this pattern,
  no other crate has item-level gates; `src/` (what `make test` runs) and `cfg_attr` forms
  were not surveyed.
- **No consumer runs them anyway.** `.github/workflows/release.yml` is cargo-dist generated:
  `dist build` only, no `make`, no `cargo test`. The Makefile (75 lines, every `cargo` line
  read) tests only `-p tldr-core --lib` and `-p tldr-cli --lib`. No justfile or `.cargo/config`
  within three levels of the root. Nothing found runs any integration target; no test at all
  runs in CI (release.yml is the only workflow): a defect bigger than this card, uncarded.
- **The parent's three tests pass without the feature.** `cargo test -p tldr-cli --test
  semantic_lang_flag_test -- --test-threads=1 --include-ignored` on default features,
  2026-09-09: `test result: ok. 3 passed; 0 failed; 0 ignored`, 2.70s, cargo exit 0. Their
  names say "does not panic" (assertion lines not read), which a clean feature-missing error
  satisfies, so the `ignore` gate on them may be unnecessary. Un-gating is a three-line
  deletion plus a rewrite of the parent's doc block, and it trades the `ignored` signal ("run
  me with `--features semantic`", where the tests take 11-48 s) for three default-run greens
  that exercise only the feature-missing path while the names promise the semantic one.
  Decide on pull.
- **No guard fails a zero-test target.** The next crate-level `#![cfg(feature = …)]` anyone adds
  will again print `test result: ok. 0 passed` and nobody will see it.

## Next action

Read each of the six files at the gated lines before touching them: a gate on a `use` or a
helper that only resolves under the feature cannot take `ignore` (the attribute still compiles
the body), and a gated macro invocation is not a `#[test]`. Then apply the parent card's
one-line pattern where it fits, as `#[cfg_attr(not(feature = "semantic"), ignore = "requires
--features semantic")]` so the `ignored` listing explains itself, and decide whether a
zero-test-target guard is worth building while nothing found runs any integration target — if
yes, it must be demonstrated by a check that REDS when a target is emptied, not one that
passes against the current tree.

## Acceptance

- [ ] The two `tldr-core` crate-level targets read; each either made visible under default
      features (its default-run `test result:` line quoted with a non-zero `ignored` count) or
      one sentence why not, with what was done instead.
- [ ] Each of the four `tldr-cli` files read at its gated lines; for each, either the `ignore`
      pattern applied and the target's default-run `test result:` line quoted with the `ignored`
      count, or one sentence why it cannot apply.
- [ ] A decision recorded on the zero-test-target guard: built and red-proofed by emptying a
      target, or explicitly declined with the reason (no consumer).
