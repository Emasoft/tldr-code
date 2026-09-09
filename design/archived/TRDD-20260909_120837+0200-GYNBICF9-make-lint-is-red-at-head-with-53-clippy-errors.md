---
trdd-id: GYNBICF9
title: make lint is red at HEAD with 53 clippy errors so the lint gate gates nothing
column: complete
created: 2026-09-09T12:08:37+0200
updated: 2026-09-09T13:47:32+0200
implementation-commits: [25b583f]
current-owner: main-session
task-type: infra
scope: project
min-approval-requirement: none
labels: [lint, gates]
---

# make lint is red at HEAD with 53 clippy errors so the lint gate gates nothing

## What is known

- Measured 2026-09-09 at HEAD `3ecb2af`: `cargo clippy --workspace -- -D warnings`, which is the
  Makefile's `lint` target and half of `check`, exits 101 with 53 `error` lines. All are style
  lints: 16 "this `if` can be collapsed into the outer `match`", 12 "consider using `sort_by_key`",
  4 "this block may be rewritten with the `?` operator", 4 "deref which would be done by
  auto-deref", and 17 singletons (iterate on a map's values, single-pattern `match`, equality
  `match`, `&PathBuf` for `&Path`, `and_then(|x| Some(y))`, collapsible `if`, manual suffix strip,
  redundant `format!` reference, and others). First locations: `crates/tldr-core/src/types.rs:1900`,
  `ast/extractor.rs:680` and `:1597`, `ast/imports.rs:845`, `:1412`, `:1727`, `ast/parser.rs:326`,
  `analysis/clones/types.rs:1217`, `analysis/clones/extract.rs:160`, `:241`.
- Consequence: any clippy-carried guard is unenforced until this is green. Found while designing
  TRDD-O66FM8TN's box 8, where a `disallowed-methods` entry in the existing `clippy.toml` was the
  obvious guard and had to be replaced by a `--lib` test because of this.
- Not measured: whether these are the same 53 lines an earlier `--all-targets` run reported.
- Pulled to `dev` 2026-09-09 12:24 as step 1 of TRDD-O66FM8TN's box-8 plan: its clippy
  `disallowed-methods` guard enforces nothing while this gate is red.

## Next action

`cargo clippy --fix --workspace --allow-dirty`, then READ the diff hunk by hunk (a collapsed
`match` can move a guard), `make test`, commit. What `--fix` leaves, by hand. Do not add an
`#[allow(clippy::…)]` to reach green.

## Acceptance

- [x] `cargo clippy --workspace -- -D warnings` exits 0 at the closing commit; the exit code and
      the error-line count (0) quoted.
      — `25b583f`, re-run by the coordinator, not taken from the worker: `clippy exit=0
      error-lines=0`.
- [x] `make test` passes on the same commit, both `test result:` lines quoted.
      — `test result: ok. 4830 passed; 0 failed; 293 ignored; 0 measured; 0 filtered out` and
      `test result: ok. 1438 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`,
      `make test exit=0`, coordinator's own run.
- [x] `grep -rc 'allow(clippy' crates/` before and after quoted, no increase.
      — 9 before, 9 after (worker's report; same 8 files).

## Approval log

- 2026-09-09T12:44:49+0200 — COMPLETE by the session Claude under the user's delegation of
  2026-09-08. testing = the runs quoted above. ai_review = the post-write fork on `25b583f`; its
  two open concerns (a `question_mark` rewrite in `context.rs:194,212` possibly turning a loop
  `continue` into a function return; the ten unread `sort_by_key` rewrites possibly dropping a
  secondary key) were settled by reading the hunks: the function returns `Option`, its original
  `None => return None` is what `?` does and the `continue` survived explicitly; every removed
  `sort_by` line is a single-field comparator. Stated deviation: 56 files in one commit against
  the 5-files-per-phase rule, because `clippy -D warnings` exit 0 is undefined on a partial
  application, so no subset could be verified on its own; the user is told here and in the
  session report rather than asked, since the change is mechanical and fully reverted by one
  `git revert`.
- 2026-09-09T13:47:32+0200 — VERIFIED by the coordinator, own runs at `f6a4ce1`, after the
  post-close fork asked: box 3's count re-run, 9 `allow(clippy` in 8 files; the plus side of all
  19 sort rewrites read, the 16 descending ones carry `std::cmp::Reverse`, the 3 ascending ones
  (`entries_by_time`, `all_findings`, the `severity_rank` chain) do not; fmt drift 195 files,
  33 of them among this commit's 56 (the worker reported 31). Box 3's "worker's report" is
  superseded by this line.
