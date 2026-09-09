---
trdd-id: GYNBICF9
title: make lint is red at HEAD with 53 clippy errors so the lint gate gates nothing
column: backburner
created: 2026-09-09T12:08:37+0200
updated: 2026-09-09T12:08:37+0200
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

## Next action

`cargo clippy --fix --workspace --allow-dirty`, then READ the diff hunk by hunk (a collapsed
`match` can move a guard), `make test`, commit. What `--fix` leaves, by hand. Do not add an
`#[allow(clippy::…)]` to reach green.

## Acceptance

- [ ] `cargo clippy --workspace -- -D warnings` exits 0 at the closing commit; the exit code and
      the error-line count (0) quoted.
- [ ] `make test` passes on the same commit, both `test result:` lines quoted.
- [ ] `grep -rc 'allow(clippy' crates/` before and after quoted, no increase.
