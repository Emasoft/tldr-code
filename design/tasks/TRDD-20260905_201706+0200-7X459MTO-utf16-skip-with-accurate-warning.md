---
trdd-id: 7X459MTO
title: Skip UTF-16 sources without analysing them while keeping the UTF-16 warning
column: planned
created: 2026-09-05T20:17:06+0200
updated: 2026-09-05T21:33:13+0200
current-owner: codebase-scan-2026-09-05
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, encoding]
---

# Skip UTF-16 sources without analysing them while keeping the UTF-16 warning

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
