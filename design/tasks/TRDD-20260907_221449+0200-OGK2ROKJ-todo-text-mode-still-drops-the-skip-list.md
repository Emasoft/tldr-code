---
trdd-id: OGK2ROKJ
title: tldr todo text output still drops the skip list that JSON now carries
column: todo
created: 2026-09-07T22:14:49+0200
updated: 2026-09-07T22:14:49+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [robustness, silent-failure, text-output]
parent-trdd: O66FM8TN
---

# tldr todo text output still drops the skip list that JSON now carries

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-07 immediately after TRDD-K3XQ7M2V landed in `0063e1b`.
**Not started.**

**This card exists because K3XQ7M2V fixed one of two output formats and the
parent card's condition covers both.** Found by an adversarial review fork, not
by me — I had already written the parent's STATE to say only unit 2 remained.

## What

`0063e1b` gave `TodoReport` a root `warnings: Vec<String>`, so
`tldr todo -f json` now names every skipped file without `--detail`. Serde emits
it; JSON consumers are served.

**`format_todo_text` (`crates/tldr-cli/src/commands/remaining/todo.rs:675`) never
reads `report.warnings`.** So the default, human-facing output of `tldr todo`
still presents a report computed over fewer files than the user believes, with
nothing on screen saying so. The field is populated and then ignored on the path
most users actually see.

## Why it is the parent's business, not a nice-to-have

TRDD-O66FM8TN is titled *"A file the analysis skips must be announced, not
silently dropped from the result"* — **format-agnostic**. K3XQ7M2V's title is
JSON-scoped, so it is complete as written; the parent is not.

**Consequence, and it is the actionable part: O66FM8TN MUST NOT close on unit 2
landing.** Its STATE block was edited on 2026-09-07 to read "ONE unit remains:
unit 2, uncommitted" and, after the commit, would have read as ready to close.
That would have closed a format-agnostic card on a JSON-only fix.

## The precedent to follow — do not invent a format

The sibling commands already solved this and their wording is the spec:

- `crates/tldr-cli/src/commands/dead.rs:571` — `"Files skipped: {} (results exclude them)\n"`
- `crates/tldr-cli/src/commands/calls.rs:354` — `"Files skipped: {} (edges exclude them)\n"`

Match that shape. The parenthetical differs per command because it names what the
exclusion costs *that* command; for `todo` the analogous phrase is about the
items list, not edges.

**Open question the implementer must answer, not assume:** `dead`/`calls` print a
COUNT under the headline numbers. `TodoReport.warnings` is a list of STRINGS that
already name each file. Printing a bare count discards names the struct already
has; printing every name could flood the text output on a large skip set. Decide
deliberately and record the reason — a count plus the names, or a count plus
"run with -f json for the list", are both defensible; picking one silently is not.

## Acceptance

- [ ] `tldr todo <dir>` in TEXT mode names or counts the skipped files when
      `warnings` is non-empty, following the `dead`/`calls` wording.
- [ ] The count-vs-names decision above is recorded here with its reason.
- [ ] A test asserts on the TEXT output with a genuinely unreadable fixture —
      not on `TodoReport.warnings` directly, which `0063e1b` already covers.
      Assert on the file NAME appearing (or the count), never on absence.
- [ ] Red-proofed: the guard is observed FAILING before it is accepted as
      passing. Deleting the fixture is the mutation, not deleting the assertion.
- [ ] Clean-run control: a directory with no unreadable file must NOT print the
      skipped line. Without this the assertion passes on a formatter that always
      prints it.
