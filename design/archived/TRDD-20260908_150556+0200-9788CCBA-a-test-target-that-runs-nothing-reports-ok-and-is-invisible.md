---
trdd-id: 9788CCBA
title: semantic_lang_flag_test compiles to zero tests and reports ok so three tests never run anywhere
column: complete
created: 2026-09-08T15:05:56+0200
updated: 2026-09-09T11:32:06+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

# semantic_lang_flag_test compiles to zero tests and reports ok so three tests never run anywhere

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08 15:05

**CLOSED 2026-09-09 11:32.** The crate-level gate is replaced by a per-test
`#[cfg_attr(not(feature = "semantic"), ignore)]`; evidence in §Acceptance. Box 3's
undelivered half (a guard that FAILS a zero-test target) and the item-level sibling gates
box 4 found are tracked as TRDD-V7Q2KM8H (`backburner`), not here.

**The defect is NOT the feature gate.** Gating semantic tests behind a
non-default feature is a legitimate choice. The defect is that the resulting
signal is `test result: ok` — a target that ran nothing is byte-indistinguishable
from a target that passed, so nothing anywhere reports that these three tests are
not being exercised.

Box 1 answered 2026-09-09: nothing in CI or the Makefile executes ANY integration
target, so the fix changes what a human sees running it by hand. See §Acceptance.

Same defect FAMILY as [[TRDD-A9CD09BA]] (`p99_us` returning 0.0 on empty
samples): in both, an empty measurement is reported as a pass. Different
mechanism, so a separate card — but if a general "vacuous success" guard is ever
built, these are its first two customers.

## Symptom

```
$ cargo test -p tldr-cli --test semantic_lang_flag_test -- --test-threads=1
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
cargo exit = 0.

Surfaced by a 116-target integration sweep at HEAD, which classified it as the
one vacuous target of 116. Report:
`reports/integration-failure-set/20260908_140723+0200-head-integration-failures.md`.

Note the sweep also found `elixir_method_infos_v1` and `surface_gaps_v1` showing
`0 passed` — those are NOT this defect. Both report real failures in the same
run (2 and 6 respectively), so they are failing targets that happen to have a
zero pass count, not silently-passing empty ones.

## Verified — read first-hand, not relayed

- `crates/tldr-cli/tests/semantic_lang_flag_test.rs:1` is
  `#![cfg(feature = "semantic")]` — an inner attribute, so it gates the ENTIRE
  file, not one item.
- The file contains three real tests, `#[test]` at lines 30, 59 and 91:
  `test_semantic_langs_flag_does_not_panic`,
  `test_semantic_global_lang_flag_does_not_panic`,
  `test_embed_langs_flag_does_not_panic`. This is a feature-gating omission, not
  "nobody wrote tests" and not per-test `#[ignore]`.
- `crates/tldr-cli/Cargo.toml` `[features]` reads `default = []` and
  `semantic = ["tldr-core/semantic"]`. `semantic` is **not** in `default`, so a
  plain `cargo test` compiles the whole file out and the harness legitimately
  reports zero tests.
- **It is the only file of its kind in that directory.** `grep -rln
  '^#!\[cfg(feature' crates/tldr-cli/tests/` returns exactly this one path, so
  the blast radius is one target. (`experimental_callgraph` is the other
  non-default feature and gates no test file at crate level.)

## Not established — do not inherit these as facts

- **Whether any CI job enables `--features semantic`.** NOT CHECKED. If one does,
  these three tests do run somewhere and the defect is only the misleading local
  signal. If none does, the tests have never run and the card is a real coverage
  hole. This is box 1 and everything downstream depends on it.
- **Whether the three tests would pass if enabled.** Unknown — they have not been
  observed running. Do not assume enabling the feature turns them green; that is
  box 2's job to find out, and a failure there is a separate finding, not a
  reason to re-disable them.
- **Whether `#![cfg(...)]` was deliberate or copied.** No commit archaeology done.

## Scope

`crates/tldr-cli/tests/semantic_lang_flag_test.rs` and whatever CI configuration
box 1 turns up. Two candidate fixes, and box 1 decides:

- **If CI never enables the feature:** either add a CI job that does, or — if the
  semantic feature is genuinely not meant to be tested — delete the file rather
  than leave three tests that look like coverage and are not. A test nobody runs
  is worse than no test, because it reads as coverage on inspection.
- **If CI does enable it:** the tests are covered and the only fix is to stop the
  default invocation reporting `ok` for an empty run.

Out of scope: the `semantic` feature's own correctness, and any other target's
failures from the sweep.

## Acceptance

- [x] **1. CI answer, from the config.** State whether any workflow/job builds or
      tests `tldr-cli` with `--features semantic`, citing the file and line. A
      negative answer must come from reading every workflow that runs cargo, not
      from one grep for the word `semantic` — a job could enable it via
      `--all-features` or a feature set defined elsewhere, so check for those
      spellings too.
      Answered 2026-09-09: the single workflow `.github/workflows/release.yml` has no
      `cargo` invocation beyond a `command -v cargo` check (line 126). The Makefile's
      `cargo test -p tldr-core --lib` and `cargo test -p tldr-cli --lib` are the only test
      commands found in `.github`, `Makefile`, `scripts`; no `--features` or
      `--all-features` spelling in any of them. So NO CI or Makefile path executes any
      integration target, this one included; the fix changes what a human sees running
      it by hand, nothing else.
- [x] **2. The three tests are observed running, and their real outcome recorded.**
      Not "the file now compiles" — an actual `test result:` line showing
      `3 passed` (or the true failure), quoted verbatim, under whatever
      invocation box 1 establishes as the right one. If any fails, card it
      separately; do not close this box by re-disabling the file.
      Recorded: `cargo test -p tldr-cli --features semantic --test semantic_lang_flag_test
      -- --test-threads=1` → `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured;
      0 filtered out; finished in 47.95s`, cargo exit 0. One feature build; a second
      execution of the same artifacts on 2026-09-09 gave the same counts in 11.31s.
- [x] **3. The three tests are visible in the default run as `ignored`, not compiled out.**
      `cargo test -p tldr-cli --test semantic_lang_flag_test -- --test-threads=1` →
      `test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out`, with
      the three names listed as `ignored`. The original text of this box asked for a check
      that FAILS when a target is made empty again; that guard is NOT delivered here and
      is tracked as TRDD-V7Q2KM8H.
- [x] **4. No sibling left behind.** Re-run the crate-level survey
      (`grep -rln '^#!\[cfg(feature' crates/*/tests/`) across ALL crates, not just
      `tldr-cli` — this card verified only `tldr-cli`. List every hit and state
      for each whether it is the same defect, and `required-features` in every Cargo.toml.
      Result 2026-09-09: no other crate-level `#![cfg(feature` under `crates/*/tests/`;
      no `required-features` in any Cargo.toml. Item-level `#[cfg(feature = "semantic")]`
      lines exist, pre-existing at HEAD, in `pdg_bounds_and_stdout_hygiene_v1.rs`,
      `language_command_matrix.rs`, `hygiene_and_crash_fixes_v1.rs`, `exhaustive_matrix.rs`.
      In `language_command_matrix.rs` they gate the callers of `check_semantic` /
      `check_similar` / `check_embed`, which rustc reports as never used: the same mechanism
      one level down (tests invisible, target not vacuous). The other three: gate lines
      present, not read. Tracked in TRDD-V7Q2KM8H, not fixed here.

## Approval log

- 2026-09-09T11:32:06+0200 — COMPLETE by session tldr-code-7a; todo → complete under the user's delegation of 2026-09-08 ("you are in charge, so decide by yourself"). ai_review = this session's pre-write review fork (its findings applied: box 3 rewritten to what was delivered with the guard split out, box 1 states that no CI or Makefile path runs any integration target, "one build, two executions", unread sibling files marked as unread). testing = the two runs quoted in boxes 2 and 3. human_review not recorded as a column (precedent TRDD-PX8JOJY4). Code and this close are one commit.
