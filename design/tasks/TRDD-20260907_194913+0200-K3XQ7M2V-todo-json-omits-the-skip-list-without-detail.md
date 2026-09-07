---
trdd-id: K3XQ7M2V
title: tldr todo JSON omits the skip list unless --detail dead is passed
column: todo
created: 2026-09-07T19:49:13+0200
updated: 2026-09-07T19:49:13+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [robustness, silent-failure, json-output]
parent-trdd: O66FM8TN
---

# tldr todo JSON omits the skip list unless --detail dead is passed

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07 19:49

Not started. Split out of TRDD-O66FM8TN on 2026-09-07 because the parent's
stderr fix landed while this channel stayed broken, and a line in a commit
message is not on the board.

**NEXT ACTION:** read how `TodoCommand::run` assembles its root JSON value
before committing to the shape below — option (c) is *recommended*, not
*verified feasible*. Nobody has read the root serialization yet.

## What

`tldr todo -f json` with no `--detail` emits JSON that does not name the files
the dead-code analysis skipped. The `DeadCodeReport` carrying `files_skipped` /
`warnings` reaches the output only through the `sub_results.insert(..)` in
`TodoCommand::run`, which is gated on `--detail <this analysis>`. A plain run
never takes that branch.

The parent card (TRDD-O66FM8TN) fixed the *stderr* channel on this path and is
guarded by
`crates/tldr-cli/tests/skipped_files_todo_bugbot_test.rs::todo_without_detail_still_names_every_unreadable_file_on_stderr`.
**stderr is not machine-readable**, so for a programmatic consumer of
`-f json` the original defect is intact: a dead-code report computed over a
silently smaller file set, with nothing in the payload saying so.

## Why it is its own card

The parent's subject is "announce the skip, don't drop it silently". This is
the same subject on a different channel, but fixing it requires an output-shape
decision the parent never scoped — and the parent is `min-approval-requirement:
user` for reasons unrelated to that decision. One atomic task per card.

## Options considered

| # | Change | Cost |
|---|---|---|
| a | make `sub_results.insert(..)` unconditional | changes the JSON shape for **every** existing consumer — a breaking public-API change, floor `min-approval-requirement: user` |
| b | surface warnings as `items` | changes summary counts and item semantics; a skip is not a todo item |
| c | **add the skip list as an additive field at the JSON root** | additive only; no existing key changes meaning; no consumer breaks |

**Recommended: (c).** It is the only option that does not make an existing
reader wrong, which is why this card is scoped to (c) alone and carries
`min-approval-requirement: none`. If (c) turns out to be infeasible and the fix
has to be (a), **this card escalates to `user`** before any code lands — do not
silently fall back to it.

## Not yet verified

- Whether `TodoCommand::run` has a root object that can take an additive field
  without disturbing `sub_results` / the summary. **Read this first.** The
  option table above is a design sketch, not a feasibility finding.
- Whether the other sub-analyses have skip lists that should ride the same
  field. `skipped_file_warning`'s doc comment (`tldr-core/src/fs/mod.rs:140`)
  says every directory-walking command MUST adopt the helper, so the field
  should be shaped for more than one producer from the start.

## Acceptance

- [ ] `tldr todo <fixture> -f json` — **no `--detail`** — emits JSON in which
      each of the 5 unreadable files in `design/reproducers/TRDD-BKALIK1B/` is
      named, and none of the 3 readable ones is.
- [ ] The assertion is on the file **names present in the payload**, never on
      absence — absence is what the bug produces too.
- [ ] Red-proofed: with the fix reverted the new test exits non-zero; restored,
      it passes. Record both observations, not just the green one.
- [ ] No existing key in the `-f json` payload changes meaning. Demonstrate by
      running the pre-existing todo JSON tests unmodified.
