---
trdd-id: OGK2ROKJ
title: tldr todo names skipped files only on stderr while dead and calls name them in the report
column: complete
created: 2026-09-07T22:14:49+0200
updated: 2026-09-10T14:28:23+0200
implementation-commits: [a262ce0]
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [robustness, consistency, text-output]
parent-trdd: O66FM8TN
---

# tldr todo names skipped files only on stderr while dead and calls name them in the report

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10

**Fixed. Fork (a) chosen: added the stdout line, matching the `dead`/`calls`
precedent exactly.**

- `crates/tldr-cli/src/commands/remaining/todo.rs:763-780` (`format_todo_text`):
  when `report.warnings` is non-empty, pushes `"Files skipped: {N} (items
  exclude them)"` followed by one indented `"  {warning}"` line per entry,
  then a blank line, right after the Summary block. `N = report.warnings.len()`
  — decided because `TodoReport` has no separate skipped-file counter (only
  `dead`'s `DeadCodeReport` does; `TodoReport.warnings` is the cross-analysis
  aggregate TRDD-K3XQ7M2V built), and `lift_warnings`'s own doc comment
  states each entry already names one file, so the length IS the count.
  Comment at `:458-461` (`run_dead_analysis`, unchanged) still reads true:
  stderr remains load-bearing on the default path for a user watching the
  terminal live; this change adds the third channel the comment's second
  reading (documented in this card's earlier text) anticipated, for a user
  who redirects/pages/pipes stdout instead.
- `crates/tldr-cli/src/commands/remaining/todo.rs:239-250` (`TodoCommand::run`,
  the `Err` arm): also pushes into `warnings` now — sibling fix for
  TRDD-RX6JWVVZ, done in the same session because both cards touch the same
  `warnings` vec and the same formatter. Consequence: the `format_todo_text`
  skip block can legitimately contain a `"<category> analysis failed: ..."`
  entry alongside file-skip entries, under the same "Files skipped" heading.
  Left as-is (not split into two headings) — `TodoReport` still has one
  `warnings: Vec<String>` field, splitting it is a bigger change than either
  card asked for, and the heading wording is arguably still defensible ("this
  analysis is partial") even for a wholly-failed sub-analysis. Flagged here
  rather than silently decided.
- Tests: `crates/tldr-cli/tests/todo_text_skipped_files_test.rs` (2 tests) —
  positive test on the shared `design/reproducers/TRDD-BKALIK1B` fixture
  (`-l python -f text`, asserts `Files skipped: 5` + each of the 5 unreadable
  names on `Skipped ...` lines, negative control that the 3 readable names
  never appear on a `Skipped` line); clean-run control on a fresh tempdir
  with one readable file asserts NO `Files skipped` line at all. Both
  red-proofed 2026-09-10: reverted the `if !report.warnings.is_empty()`
  guard to `if false && ...`, re-ran — the positive test failed exactly as
  expected (stdout had no skip block), reverted, re-ran green.
  `-f text` is explicit in both tests: `tldr todo`'s DEFAULT format is JSON
  (confirmed by running the bare command with no `-f`), so an unqualified
  invocation would have tested the wrong formatter and passed on the unfixed
  code — caught this before committing to the test shape.
- Verify: `cargo build -p tldr-cli` exit 0; `cargo test -p tldr-cli todo`
  — 0 failed across every `todo`-matching target; `cargo clippy -p tldr-cli
  --lib --tests -- -D warnings` clean for `todo.rs` and the new test file
  specifically (the umbrella `--all-targets -D warnings` run currently fails
  on pre-existing/concurrent lint errors in OTHER workers' files —
  `kotlin_extract_and_cpp_extensions_v1.rs`, `schema_cleanup_v2.rs`,
  `format_flag_strictness_v1.rs`, `p19_secondary_fixes_v1.rs`,
  `language_specific_bugs_v1.rs`, `cross_language_extraction_v2`,
  `detection_accuracy_v1`, `deps_and_surface_graceful_degrade_v1`,
  `cross_cutting_and_clear_fix_bugs_v1` — none of which this card's file
  ownership (`todo.rs`, `tests/todo_*.rs`) covers; confirmed via targeted
  `cargo clippy -p tldr-cli --test todo_text_skipped_files_test -- -D
  warnings` exit 0).
- Verified 2026-09-10 by the coordinator, first-hand, not on the worker's
  report: the diff was read (`analysis_failure_warning` at `todo.rs:323`, the
  `warnings.push` in the `Err` arm at `:250-251`, the `Files skipped: {} (items
  exclude them)` block plus one indented line per warning in
  `format_todo_text`), the new 95-line test file was read in full, and
  `todo_text_skipped_files_test` ran 2 passed / 0 failed in the workspace gate.
  All 7 acceptance boxes re-checked against the working tree, none taken on
  trust.

Filed 2026-09-07 immediately after TRDD-K3XQ7M2V landed in `0063e1b`.
RETITLED AND DOWNGRADED the same day — the filed version's central
claim was false. Read the retraction section below before re-reading the rest.

## What

`0063e1b` gave `TodoReport` a root `warnings: Vec<String>`, so
`tldr todo -f json` now names every skipped file without `--detail`. Serde emits
it; JSON consumers are served.

**`format_todo_text` (`crates/tldr-cli/src/commands/remaining/todo.rs:675-741`)
never reads `report.warnings`.** The whole function body has now been read: it
pushes `report.path`, `total_items`, five `report.summary.*` counts, the items
list, a truncation footer and `total_elapsed_ms`. Nothing else. `TodoSummary`
(`types.rs:184-195`) was read from its definition and has exactly those five
`u32` counters — no skipped counter, so no count reaches text by a second route.

So the **report body on stdout** does not mention skipped files, while `dead`
and `calls` print a `Files skipped: N` line in theirs.

## What this card claimed and got WRONG — read this first

**The filed version said the skip list is dropped "silently", with "nothing on
screen saying so". That is FALSE, and the disconfirming evidence was already
inside this card's own parent.**

`crates/tldr-cli/src/commands/remaining/todo.rs:474-476`, inside
`run_dead_analysis` — on the default path, ungated by `--detail` and independent
of output format:

```rust
for warning in &skipped {
    eprintln!("Warning: {warning}");
}
```

The comment immediately above it (`:458-461`) says so in as many words: *"BOTH
channels, deliberately, and the stderr line is the load-bearing one on the
default path."* And TRDD-O66FM8TN carries a whole section — *"Why the complexity
warning is not this one"* — devoted to defending that exact `eprintln!` from
being deleted as duplication.

**`tldr todo` does announce every skipped file to the user today, on stderr.**
Severity drops from silent-failure to a stdout/stderr inconsistency with the
sibling commands; the `silent-failure` label is removed.

**How the error was made, because the shape recurs.** The claim came from a grep
for `warnings` that found no hit inside `format_todo_text`. The grep was
correct; its SCOPE was the wrong one. The announcement is not in the formatter —
it is in the analysis, 200 lines up, in code this same TRDD chain wrote and then
documented twice. **An absence inside a function I chose is not an absence in
the program**, and the re-grounding in `38bfe9f` did not fix that: it checked
the same function three more ways. Two adversarial review forks named the
`eprintln!` before I read it; the fix was to read the code, not to argue the
grep.

## What is actually left, and why it is still worth doing

Not a silent failure — a divergence from the siblings:

| command | where the skip is announced |
|---|---|
| `dead` (`dead.rs:571`) | stdout, in the report — `"Files skipped: {} (results exclude them)"` |
| `calls` (`calls.rs:354`) | stdout, in the report — `"Files skipped: {} (edges exclude them)"` |
| `todo` | **stderr only** — the report body says nothing |

A user who redirects stdout to a file, pipes it, or reads it in a pager gets a
report whose own text does not say it is partial. That is a real gap. It is NOT
a claim that the user was never told.

**`--output <path>` is the sharpest case.** `todo.rs:286-291` writes
`format_todo_text(..)` to a FILE while the warnings still go to the process's
stderr. A user who runs `tldr todo -o report.txt` and reads `report.txt` later
has no way at all to learn the analysis was partial.

**Scope of the claim, closed properly this time.** The retraction above happened
because a grep scoped to `format_todo_text` missed an announcement in its
CALLER. So the same check was then run over the WHOLE FILE:
`grep -n 'println!\|print!\|stdout' todo.rs` returns exactly three lines — a doc
comment at `:155`, the `// Write to stdout` comment at `:297`, and the
`eprintln!` at `:475`. There is no `println!` anywhere in the file. Reading
`:285-303` shows text-mode stdout content is EXACTLY `format_todo_text(..)`'s
return value. So "stdout omits the skip line" is now established over the file,
not over a function chosen in advance.

## The real decision this card forces — and it is NOT count-vs-names

`todo.rs:458-461` does not merely happen to write to stderr. It records an
INTENT: *"BOTH channels, deliberately, and the stderr line is the load-bearing
one on the default path."* Adding a `Files skipped:` line to stdout is a change
**against a stated design decision**, so this card carries the same (a)/(b) fork
TRDD-DPL55YB3 exists to force:

| | Change | What it means |
|---|---|---|
| a | add the stdout line to `todo` | the comment is wrong; the report body should be self-describing, as `dead`/`calls` already assume |
| b | change nothing | stderr is the right channel and `dead`/`calls` are the outliers |

**The comment has a SECOND reading, and it weakens (b).** A review offered it and
it is well supported: the comment sits beside a long *"Why the complexity warning
is not this one"* defence whose evident purpose is stopping someone DELETING the
stderr line. Under that reading, *"BOTH channels, deliberately"* means **do not
remove either**, and *"load-bearing on the default path"* is a statement about
CURRENT coverage — the JSON field is gated behind `--detail` — rather than a
prohibition on a third channel. The phrase "on the default path" even concedes
non-default paths behave differently, which reads as documenting a gap, not
endorsing it. **A comment written to prevent a removal is weak evidence about an
addition.** Weigh both readings against the surrounding code; do not treat the
fork as settled by the quote alone.

(a) is probably right — a report that cannot say it is partial when written to a
file is hard to defend. But it must be ARGUED, not assumed, and whichever way it
goes, the comment at `:458-461` must end up agreeing with the code. Leaving a
comment asserting an intent the code no longer follows is how the next reader
gets misled — which is exactly how this card was filed wrong in the first place.

**Consequence for the parent, CORRECTED.** The filed version said O66FM8TN
"MUST NOT close without it", on the strength of the silence claim. **That reason
is void.** The parent still cannot close — but for reasons already on its own
acceptance list, unticked before this card existed: the 56 silent sites, the
un-surveyed `File::open`/`read_to_end` sites, and centralisation of the skip
path. This card is a consistency improvement against the parent's title, not a
blocker for it.

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

- [x] `tldr todo <dir>` in TEXT mode names or counts the skipped files when
      `warnings` is non-empty, following the `dead`/`calls` wording.
      `todo.rs:763-780`.
- [x] The count-vs-names decision above is recorded here with its reason.
      Both: a `Files skipped: N` count line plus every name indented below it
      — see STATE block; `N = report.warnings.len()`, no separate counter field
      exists on `TodoReport`.
- [x] A test asserts on the TEXT output with a genuinely unreadable fixture —
      not on `TodoReport.warnings` directly, which `0063e1b` already covers.
      Assert on the file NAME appearing (or the count), never on absence.
      `tests/todo_text_skipped_files_test.rs::todo_text_mode_names_every_skipped_file_in_stdout_report`,
      fixture `design/reproducers/TRDD-BKALIK1B` (5 genuinely undecodable files).
- [x] Red-proofed: the guard is observed FAILING before it is accepted as
      passing. Deleting the fixture is the mutation, not deleting the assertion.
      Done by disabling the formatter's `if` guard (not the fixture) — same
      effect (no skip block emitted) with a faster loop; see STATE block for
      the exact before/after run.
- [x] Clean-run control: a directory with no unreadable file must NOT print the
      skipped line. Without this the assertion passes on a formatter that always
      prints it. `todo_text_mode_omits_skipped_line_when_nothing_was_skipped`.
- [x] The test asserts on STDOUT specifically, and does not merge stderr into
      it. `todo.rs:475` already writes the names to stderr, so a harness that
      captures the two together passes without any change to the formatter —
      the assertion would be green on the unfixed binary. `Command::output()`
      keeps `stdout`/`stderr` as separate fields; only `output.stdout` is read.
- [x] Nothing in the final card re-asserts that `todo` drops skips "silently".
      It does not; see the retraction above.
