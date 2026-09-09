---
trdd-id: U5KJ5A8R
title: cargo fmt --check is red on 188 files at HEAD so make check gates nothing
column: backburner
created: 2026-09-09T12:44:49+0200
updated: 2026-09-09T13:47:32+0200
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

- Worker-measured 2026-09-09 at `3ecb2af`, not re-run by the coordinator (it needs a checkout
  of that commit): `cargo fmt --all -- --check` exits 1 with 645 `Diff in` lines over 188 files,
  none of them touched by that card. So the Makefile's `fmt` target, and `check` (fmt + lint +
  test), were red before and independently of the lint errors GYNBICF9 fixed.
- Coordinator's own run at `f6a4ce1` (2026-09-09 13:47): exit 1, 658 `Diff in` hunks, 195 files,
  all under `crates/`; 33 of them are among the 56 files `25b583f` rewrote (the worker reported
  31). So at most 33 of the 195 can be that commit's doing and 162 predate it. That commit
  deliberately did not run `cargo fmt`, because the drift spans files it never touched and
  mixing the two would hide which hunks were the lint fix.
- The third dead gate found in one day: TRDD-GYNBICF9 (lint), TRDD-PS9LN7C5 (no CI runs tests),
  this one (fmt).

## Next action

On a clean tree: `cargo fmt --all`, no hand edits, `make test`, one commit. Read the diff stat,
not the hunks: rustfmt is deterministic and the only thing to check is that no file outside
`crates/` moved and that no rustfmt config appeared (none exists to depth 2 as of `f6a4ce1`).

## Acceptance

- [ ] `cargo fmt --all -- --check` exits 0 at the closing commit, exit code quoted.
- [ ] `make test` on the same commit, both `test result:` lines quoted.
- [ ] No rustfmt configuration added or changed; diff stat's last line quoted.
