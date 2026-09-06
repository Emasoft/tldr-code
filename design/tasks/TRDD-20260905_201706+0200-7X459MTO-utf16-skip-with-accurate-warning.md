---
trdd-id: 7X459MTO
title: Skip UTF-16 sources without analysing them while keeping the UTF-16 warning
column: planned
created: 2026-09-05T20:17:06+0200
updated: 2026-09-06T04:03:30+0200
current-owner: codebase-scan-2026-09-05
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, encoding]
---

# Skip UTF-16 sources without analysing them while keeping the UTF-16 warning

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- **THIS IS A BREAKING CHANGE to a public API, deliberately taken.** Say so when releasing.
  Two breaks: adding a variant to `pub enum FileReadResult` breaks any downstream exhaustive
  `match`, and `content()` now returns `None` where it returned `Some("")` for UTF-16 — the
  latter IS the fix, and it is invisible to the compiler. Version is `0.4.1-fork.1`, i.e.
  pre-1.0 and a fork, so semver permits it in a minor bump; there is no evidence of external
  dependents either way.
  `#[non_exhaustive]` was added to the enum IN THE SAME CHANGE. That is itself breaking, which
  is exactly why it belongs here: the break is already being taken, so the guard is free now
  and makes every future variant purely additive. In-crate matches stay exhaustive and the
  compiler still catches a missed arm; only downstream crates need a wildcard.
- IMPLEMENTED via shape 1: `FileReadResult::Skipped { warning }`. `content()` returns `None`
  for it (that is the fix — the old `Lossy { content: "", .. }` handed callers an empty string
  as analysable text), `warning()` and `has_warning()` include it, `is_skipped()` added, and
  `EncodingIssues` gained `skipped_files: Vec<EncodingIssue>` with `add_skipped`, counted by
  `has_issues()` and `total()`. `read_source_file_or_skip` records the reason and returns
  `None`. `#[serde(default)]` on the new field so older JSON still deserialises.
- Acceptance line 1 MET: `cargo test -p tldr-core --test encoding_base_tests` => 48 passed,
  0 failed, and both UTF-16 tests now assert BOTH halves — `content()` is `None` AND the
  warning contains "UTF-16". `cargo check -p tldr-core --all-targets` exits 0.
- WIDER CONFIRMATION (2026-09-06 04:00): the whole package was re-run after the change —
  `cargo test -p tldr-core --no-fail-fast -j 2 -- --test-threads=2` => 82 binaries,
  7214 passed, 1 failed. The one failure is `ruby_io_popen_with_user_input_via_compute_taint`,
  which is in the classified baseline, and the totals are byte-identical to the pre-change gate
  run (`cargo_exit=101`, which is the single failing test and NOT a compile or harness error —
  82 `test result:` lines are present and `grep -cE '^error\[E[0-9]+\]'` is 0; a compile error
  would yield far fewer than 82 result lines).
  **Do not read those identical totals as evidence the API change is safe — they are the null
  result this run was guaranteed to produce.** The changed functions have zero non-test callers
  anywhere in the workspace, so the only binary whose behaviour could possibly have moved is
  `encoding_base_tests`, which I edited myself to assert the new outcome. The other 81 binaries
  were never at risk. What this run establishes is narrow and worth exactly that much: the edit
  compiles and broke no unrelated code by accident. It says NOTHING about the safety of the
  breaking change for an external consumer, because a genuine downstream break produces this
  same all-green result.
- **Acceptance line 2 CANNOT BE MET, and the reason is worth more than the line.** It asks for a
  `tldr structure` JSON run to list the file in an issues section. Nothing wires that up:
  `read_source_file`, `read_source_file_or_skip` and `EncodingIssues` have **zero non-test
  callers anywhere in the workspace** (checked across `crates/`, excluding the module's own
  file and tests). No command consumes `EncodingIssues`, so there is no issues section to
  appear in.
- So this fix corrects a real defect in a PUBLIC library API (`pub mod encoding` in
  tldr-core's lib.rs, so external consumers can call it) that no in-repo path currently
  exercises. The bug was real and is fixed; the user-visible symptom the body describes cannot
  occur today because the code is unreached.
- FOLLOW-UP: decide whether the encoding module should be WIRED IN (commands route file reads
  through it and emit `EncodingIssues`) or RETIRED. Do not wire it speculatively just to satisfy
  acceptance line 2 — that is a change across every command's read path and output schema, and it
  needs its own decision.
  **CORRECTION 2026-09-06: this does NOT belong on TRDD-V11BVG55, as this bullet previously
  claimed.** That card's 17 items were read in full and none mentions `encoding`; the routing was
  an assumption. This follow-up currently has NO card.
  Two verified facts now constrain it. (1) `tldr-core` is PUBLISHED on crates.io — 13 versions,
  latest `0.4.0`, upstream `parcadei/tldr-code`; this fork's `0.4.1-fork.1` is not published. So
  `pub mod encoding` (lib.rs:45) is published public API and its zero in-repo callers do NOT make
  it dead — a `pub` export exists for callers you cannot grep. RETIRE is therefore a breaking
  change to a published surface, not the cheap cleanup it appears to be. (2) The workspace reads
  files at ~194 `fs::read_to_string` sites instead, so WIRE IN means touching all of them plus
  every command's output schema. Neither option is small; that is why it needs a card and not a
  drive-by.

## Why

`read_source_file` in `crates/tldr-core/src/encoding.rs` returns
`FileReadResult::Lossy { content: "", warning: "... appears to be UTF-16 encoded (unsupported), skipping" }`
for a file with a UTF-16 BOM. `read_source_file_or_skip` records the warning through
`EncodingIssues::add_lossy` (file plus message) and then hands the empty string to the caller as
analysable text, so the file is counted as analysed with zero symbols while the message says it
was skipped.

The 2026-09-05 scan changed the branch to return `FileReadResult::Binary`, which does skip the
file, but `EncodingIssues::add_binary` stores only the file name: `EncodingIssues` derives
`Serialize`, so the file still appears in `binary_files`, mislabelled as binary, and the
"UTF-16 encoded (unsupported)" message that told the user what actually happened is gone. That
hunk was reverted before the scan commit; upstream behaviour (warn, then analyse an empty
string) stands until this proposal lands.

## What

- Add a skip outcome that carries a message, so a UTF-16 file is neither analysed nor silent.
  Two shapes fit the existing types; pick one at design time:
  1. a new `FileReadResult::Skipped { warning }` variant, handled by `read_source_file_or_skip`
     as `add_lossy`-style recording plus `None` content; or
  2. keep `Binary` and give `EncodingIssues` a `skipped_files: Vec<EncodingIssue>` list that every
     JSON emitter surfaces beside `lossy_files`.
- Update `encoding_base_tests.rs` (`test_read_source_file_utf16_le_bom`/`_be_bom`) to assert the
  new outcome: no content handed to callers, and a warning containing "UTF-16".
- Grep every `FileReadResult` match site (`read_source_file_or_skip`, `content()`, `is_binary()`)
  so the new outcome cannot fall through an exhaustive match.

## Acceptance

- `cargo test -p tldr-core --test encoding_base_tests` passes with the two UTF-16 tests asserting
  "not analysed" and "warning mentions UTF-16" at the same time.
- A JSON run of `tldr structure` over a directory containing one UTF-16 file lists that file with
  a UTF-16 message in its issues section and reports it as not analysed.

## Approval log

- 2026-09-05T21:33:13+0200 — APPROVED by the session Claude under the user's 2026-09-05 directive to decide from verified facts and implement what is good. Work is authorized; no push.
