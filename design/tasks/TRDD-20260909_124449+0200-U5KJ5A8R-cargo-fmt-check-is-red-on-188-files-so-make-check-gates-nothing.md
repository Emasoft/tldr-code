---
trdd-id: U5KJ5A8R
title: cargo fmt --check is red on 188 files at HEAD so make check gates nothing
column: backburner
created: 2026-09-09T12:44:49+0200
updated: 2026-09-09T12:44:49+0200
current-owner: main-session
task-type: infra
scope: project
min-approval-requirement: none
labels: [fmt, gates]
---

# cargo fmt --check is red on 188 files at HEAD so make check gates nothing

Cited by the TRDD-GYNBICF9 fix commit `25b583f` before this card existed; the id was minted and
reserved in the same session.

## What is known

- Measured 2026-09-09 at `3ecb2af` by the GYNBICF9 worker: `cargo fmt --all -- --check` exits 1
  with 645 `Diff in` lines over 188 files, none of them touched by that card. So the Makefile's
  `fmt` target, and `check` (fmt + lint + test), were red before and independently of the lint
  errors GYNBICF9 fixed.
- After `25b583f`: 195 files. 31 of the 56 files that commit rewrote now carry drift (a collapsed
  `match` changes indentation); some of them already did. That commit deliberately did not run
  `cargo fmt`, because the drift spans files it never touched and mixing the two would hide which
  hunks were the lint fix.
- The third dead gate found in one day: TRDD-GYNBICF9 (lint), TRDD-PS9LN7C5 (no CI runs tests),
  this one (fmt).

## Next action

On a clean tree: `cargo fmt --all`, no hand edits, `make test`, one commit. Read the diff stat,
not the hunks: rustfmt is deterministic and the only thing to check is that no file outside
`crates/` moved and that `rustfmt.toml` (if any) was not changed.

## Acceptance

- [ ] `cargo fmt --all -- --check` exits 0 at the closing commit, exit code quoted.
- [ ] `make test` on the same commit, both `test result:` lines quoted.
- [ ] No rustfmt configuration added or changed; diff stat's last line quoted.
