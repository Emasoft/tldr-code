---
trdd-id: 9788CCBA
title: semantic_lang_flag_test compiles to zero tests and reports ok so three tests never run anywhere
column: todo
created: 2026-09-08T15:05:56+0200
updated: 2026-09-08T15:05:56+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

# semantic_lang_flag_test compiles to zero tests and reports ok so three tests never run anywhere

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08 15:05

Nothing implemented. Cause fully established and read first-hand; the open
question is policy, not diagnosis.

**The defect is NOT the feature gate.** Gating semantic tests behind a
non-default feature is a legitimate choice. The defect is that the resulting
signal is `test result: ok` — a target that ran nothing is byte-indistinguishable
from a target that passed, so nothing anywhere reports that these three tests are
not being exercised.

**NEXT ACTION: box 1** — determine whether any CI job builds `tldr-cli` with
`--features semantic`. That answer decides between the two fixes in §Scope, and
it is NOT yet known. Do not assume either way.

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

- [ ] **1. CI answer, from the config.** State whether any workflow/job builds or
      tests `tldr-cli` with `--features semantic`, citing the file and line. A
      negative answer must come from reading every workflow that runs cargo, not
      from one grep for the word `semantic` — a job could enable it via
      `--all-features` or a feature set defined elsewhere, so check for those
      spellings too.
- [ ] **2. The three tests are observed running, and their real outcome recorded.**
      Not "the file now compiles" — an actual `test result:` line showing
      `3 passed` (or the true failure), quoted verbatim, under whatever
      invocation box 1 establishes as the right one. If any fails, card it
      separately; do not close this box by re-disabling the file.
- [ ] **3. A zero-test run is no longer reported as success on the default path.**
      Whatever the box-1 outcome, `cargo test -p tldr-cli` must not leave a target
      silently reporting `ok. 0 passed` with nothing anywhere noting it.
      Demonstrated by a check that FAILS when a target is made empty again — a
      check that merely passes against the current tree does NOT satisfy this box.
- [ ] **4. No sibling left behind.** Re-run the crate-level survey
      (`grep -rln '^#!\[cfg(feature' crates/*/tests/`) across ALL crates, not just
      `tldr-cli` — this card verified only `tldr-cli`. List every hit and state
      for each whether it is the same defect.
