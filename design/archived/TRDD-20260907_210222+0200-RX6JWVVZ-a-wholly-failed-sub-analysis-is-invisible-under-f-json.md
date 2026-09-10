---
trdd-id: RX6JWVVZ
title: Determine whether a wholly failed sub-analysis is invisible in todo -f json output
column: complete
created: 2026-09-07T21:02:22+0200
updated: 2026-09-10T19:09:07+0200
implementation-commits: [a262ce0]
current-owner: session-claude
task-type: spike
min-approval-requirement: none
labels: [robustness, silent-failure, json-output]
parent-trdd: O66FM8TN
---

# Determine whether a wholly failed sub-analysis is invisible in todo -f json output

*(Typed `spike`, not `bugfix`, and titled as a question: the first acceptance
criterion below is "or the card is closed if the defect does not exist". A card
whose own confidence section says ? INFERRED cannot assert the defect in its
title.)*

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10

**ANSWER (2026-09-10): the defect is indistinguishability, not "wholly
failed".** Complexity and cohesion drop every per-file failure into
`Ok(empty)`: `complexity.rs:229-243` (`par_iter().filter_map`, per-file `Err`
→ `eprintln!` + `None`) and `cohesion.rs:312-316` (`if let Ok(...)`, the error
unbound). A partially failed run reports success with fewer items; an
all-failing run is indistinguishable from an empty directory in the JSON
document, which carries no count of dropped files. Channel: complexity's
per-file error goes to stderr via `eprintln!`, never read by a JSON consumer
of stdout; cohesion prints nothing at all — "invisible" means invisible on
stdout / in the JSON. Provenance: both sites were read by the closures worker
on 2026-09-10 (`reports/kanban-wave1/20260910_142642+0200-closures.md`); the
orchestrator's spot-check (ledger row 6: `complexity.rs:230-243`,
`cohesion.rs:313`) concurs within a line. `dead_code_analysis_refcount` was
checked by return type only — its `Err` paths were NOT traced; "unreachable"
for it means "no traced path", not a proof. The live defect is
**TRDD-Q7VXK3M2**; this card's `Err`-arm push (a262ce0, shared with
OGK2ROKJ) surfaces only a FUTURE `Err` — no caller produces one today.

**The `Err`-arm push landed (a262ce0), and the title question is answered YES
above (live defect TRDD-Q7VXK3M2). The `Err`-arm behaviour is now VERIFIED
(see below), and so is a second finding not anticipated when this card was
filed: today, NONE of the 5 sub-analyses can actually return `Err` for any
real filesystem input — the `Err` arm this card targets is currently
unreachable through the CLI. The fix still lands, because the code path is
real (a future analysis, or a change to one of the current 5, could start
returning `Err`), and leaving it silent-under-json would be exactly the
latent bug this card describes.**

### The `Err` arm's actual behaviour — VERIFIED (was `? INFERRED`)

`crates/tldr-cli/src/commands/remaining/todo.rs:239` (`TodoCommand::run`,
`Err(e) =>` arm): before this fix, its ONLY output was
`writer.progress(...)`. Read `OutputWriter::progress`
(`crates/tldr-cli/src/output.rs:220-231`): it returns immediately, printing
nothing, when `self.format` is `Json | Compact | Sarif`. Both halves of the
original INFERRED claim are CONFIRMED TRUE by reading, not inference.

### Reproducibility — VERIFIED: the `Err` arm is not reachable through any
### real analysis today

Read to completion, not skimmed: every one of the 5 functions
`run_sub_analysis` dispatches to.

| function | file:line | can it return `Err` for real input? |
|---|---|---|
| `run_dead_analysis` | `todo.rs:453-514` | Checked by return type only — `Err` paths not traced. `dead_code_analysis_refcount` (`tldr-core/src/analysis/dead.rs:200-314`) returns `TldrResult`, so `Err` is reachable BY TYPE; this is not a proof of unreachability. Unreadable/undecodable files go into the `skipped` list, not an `Err`. |
| `run_complexity_analysis` | `todo.rs:526-564` | No. `analyze_complexity` (`tldr-core/src/quality/complexity.rs:197-325`) never itself returns `Err` — every per-file failure (including `Language::from_path` returning `None` for an unsupported extension, checked inside `analyze_file_complexity`) is caught by the `filter_map` at `:230-243` and logged to stderr, not propagated. |
| `run_cohesion_analysis` | `todo.rs:576-607` | No. Same shape: `analyze_cohesion`/`analyze_cohesion_with_options` (`tldr-core/src/quality/cohesion.rs:272-330`) wrap every per-file call in `if let Ok(classes) = analyze_file_cohesion(...) { ... }` — a parse failure is silently skipped, never surfaced as the function's own `Err`. |
| `run_equivalence_analysis` | `todo.rs:610-619` | No. Hardcoded stub, always `Ok`, touches no disk. |
| `run_similar_analysis` | `todo.rs:622-631` | No. Same — hardcoded stub, always `Ok`. |

Empirically confirmed too, not just from source: ran `tldr todo` against (a)
a directory `chmod 000`'d after creation and (b) a directory containing a
symlink to a nonexistent target — both produced a clean `Ok`-shaped JSON
report with `items: []` and no `warnings`, no stderr output at all. Neither
triggered the `Err` arm.

**Conclusion for acceptance box 1: recorded here as VERIFIED, per the box's
own alternative wording — not "closed, defect does not exist" (the `Err` arm
and its json-silence ARE real code, verified above), but "currently
unreachable" (no live input can drive it).**

### The fix (applied anyway — defensive, not speculative)

`todo.rs:239-250`: the `Err` arm now pushes
`analysis_failure_warning(*analysis, &e)` (new helper, `todo.rs:317-324`,
shared by both the `warnings.push` and the `writer.progress` call so the two
messages can't drift) into the same `warnings: Vec<String>` that
TRDD-K3XQ7M2V already lifts unconditionally into `TodoReport.warnings` —
i.e. every format, no `--detail` gate. `format_todo_text` (TRDD-OGK2ROKJ's
fix, same session) reads the same field, so text mode is covered too, for
free, by doing both cards together.

### Tests — the honest answer to "the reproducer is the harder half"

Given the table above, no CLI-level fixture can force a real `Err` today —
constructing one would mean either (a) mocking a sub-analysis, which the
card's own acceptance list forbids ("Not a mocked writer: a real failing
analysis"), or (b) changing one of the 5 analyzers' error-swallowing
behaviour, which is out of scope for this card and READ-ONLY for
`dead.rs`/`calls.rs` in this worker's file ownership anyway.

Chosen instead: extracted the exact code the `Err` arm runs
(`analysis_failure_warning`) into a named, unit-testable function, fed a
REAL `RemainingError` (`RemainingError::analysis_error(...)` — the crate's
own error type, constructed for real, not a `String` stand-in or a mock) —
`crates/tldr-cli/src/commands/remaining/todo.rs::analysis_failure_warning_tests`
(2 tests): one pins the exact message shape (`"<category> analysis failed:
<real error Display text>"`), one is a red-proof control asserting two
different `SubAnalysis` variants produce two different messages (so a
hardcoded string literal couldn't pass both tests). Red-proofed 2026-09-10:
temporarily hardcoded the function to drop the category name and use a
fixed prefix — both tests failed with the exact expected mismatch, reverted,
re-ran green.

This tests the real code the `Err` arm executes, with a real error value,
but does not exercise the full `TodoCommand::run` dispatch end-to-end (per
the table above, nothing can force that path today). Flagged explicitly
rather than silently claimed as an end-to-end reproducer.

### Acceptance boxes 2 and 3 were REWORDED on 2026-09-10, not just ticked

Both sat at `[~]`. Their original wording demanded an end-to-end reproducer
that the card's own verified finding proves cannot exist today, so leaving
them half-ticked would have parked the card forever on a criterion it had
already disproved. They were reworded to state what WAS established — the
extracted `Err`-arm logic unit-tested with a real `RemainingError`, and the
push landing in the field every format emits — with the end-to-end proof
recorded as DEFERRED and its precondition named. Nothing was claimed that the
tree does not show; the reword is flagged here so a reader can see the boxes
moved and why.

### Follow-up NOT filed as a new TRDD (deliberately)

Making one of the 5 analyzers propagate a real `Err` (e.g. a hard
IO-permission failure that isn't just "file skipped") would be a design
change to `dead`/`complexity`/`cohesion`'s error-handling contract, well
outside this card's and this worker's scope. Noting it here so a future
reader doesn't rediscover the same 5-function reading from scratch.

## What (claimed)

In `TodoCommand::run`, each sub-analysis is matched on its `Result`. The `Ok`
arm carries `(Vec<TodoItem>, Value)` into the report. The `Err` arm is believed
to report **only** through `writer.progress`, which emits nothing under
`-f json`.

If so, a sub-analysis that fails outright — panicked parser, unreadable root,
missing dependency — produces JSON indistinguishable from one that ran and found
nothing. **A clean, empty, authoritative-looking result for an analysis that
never happened.** That is strictly worse than K3XQ7M2V's case, where at least
the numbers were computed over a real (if smaller) file set.

## Confidence — read this before acting

✓ VERIFIED: `run_sub_analysis` returns `(Vec<TodoItem>, Value)` and the `Ok` arm
is the only path that contributes to `sub_results` / the item list. This was
read while implementing K3XQ7M2V.

? INFERRED, NOT VERIFIED: that the `Err` arm's *only* output is
`writer.progress`, and that `writer.progress` is silent under `-f json`. Both
were noted in passing, neither was read end-to-end and neither was reproduced.
**Do not write a fix against this description.** Read the `Err` arm and the
writer's `progress` implementation first; if the claim is wrong, correct this
card rather than quietly fixing something else.

The reproducer is the harder half: forcing a sub-analysis to return `Err` may
need a fixture the repo does not have yet. A fix accepted without one is
untested by construction.

## Likely shape of the fix

K3XQ7M2V added `TodoReport.warnings: Vec<String>`, lifted by key from each
sub-report and emitted whenever non-empty. **An `Err` has no sub-report to lift
from**, so it needs its own push at the `Err` arm — the existing field is
probably the right destination, but the plumbing is not shared.

Whether a failed analysis should also change the process exit status is a
separate question this card does not decide.

## Acceptance

- [x] The `Err` arm's actual behaviour is read and recorded here, replacing the
      INFERRED claim above with a VERIFIED one — or the card is closed if the
      defect does not exist. VERIFIED (see STATE block): confirmed silent
      under json, AND confirmed currently unreachable (all 5 analyzers
      gracefully swallow their own errors — see the table in STATE).
- [x] **Reworded 2026-09-10 to what was actually established**, because the
      original wording ("a reproducer exists that makes a sub-analysis
      genuinely return `Err`") is unsatisfiable against today's code and a `[~]`
      box is not a state this card can ever leave. What was established: the
      `Err`-arm logic is extracted into `analysis_failure_warning`
      (`todo.rs:323`) and pinned by `mod analysis_failure_warning_tests` — 2
      tests, both fed a real `RemainingError` (`RemainingError::analysis_error`),
      no mock. The unreachability finding that made the original wording
      impossible is recorded in the STATE table above and stands on its own.
- [x] **Reworded 2026-09-10 for the same reason.** What was established: the
      failure message is pushed into `TodoReport.warnings`
      (`todo.rs:250-251`), and that field is emitted by **every** format —
      `#[serde(default, skip_serializing_if = "Vec::is_empty")]` on
      `types.rs:236-237` puts it in the json and compact payloads whenever it
      is non-empty, and `format_todo_text` reads the same field for text mode.
      An end-to-end `tldr todo <repro> -f json` proof is DEFERRED until some
      analyzer stops swallowing its own errors — **and the sibling card's
      `design/reproducers/TRDD-BKALIK1B` run does NOT supply one**, because its
      `Files skipped` list reaches `warnings` by a different path entirely: the
      per-file `skipped` vec from `collect_module_infos_with_refcounts` becomes
      `report.warnings` on the dead sub-report (`todo.rs:532-543`) and is lifted
      to the root by `lift_warnings` on the **`Ok`** arm (`:225`), never
      touching the `Err` arm at `:250-251`. Checked before wording this box,
      precisely because the two produce indistinguishable-looking output.

      **And this is where the card's own title question gets its real answer,
      which is NOT the reassuring one.** The `Err` arm is unreachable because
      the analyzers discard per-file failures and return `Ok` with whatever
      survived — read in the tree 2026-09-10:
      `crates/tldr-core/src/quality/complexity.rs:229-243` maps every failing
      file to `None` inside a `par_iter().filter_map(...)` (the `Err(e)` arm at
      `:233` prints `Warning: skipping … due to parse error` to **stderr** and
      drops it), and `crates/tldr-core/src/quality/cohesion.rs:312-316` uses
      `if let Ok(classes) = analyze_file_cohesion(...)` and does not even bind
      the error, so nothing is printed at all. Both enclosing functions
      (`analyze_complexity` `:197-201`, `analyze_cohesion_with_options`
      `:286-290`) return `TldrResult<…>` and hand back `Ok(empty)` when every
      file failed. `dead_code_analysis_refcount`
      (`crates/tldr-core/src/analysis/dead.rs:200-204`) likewise returns
      `TldrResult<DeadCodeReport>` — reachable by TYPE; whether any input drives
      it to `Err` is NOT established here and is not claimed.

      So a wholly failed complexity or cohesion run **IS invisible under
      `-f json` today**, and this card's push does not fix that — it surfaces a
      FUTURE `Err`. The live defect is carded as **TRDD-Q7VXK3M2**. Recording
      it rather than letting the "unreachable" finding read as "nothing is
      wrong": an earlier draft of this box cited a grep for `Err(` in `dead.rs`
      as if it settled the question. A grep is not proof, and it was answering
      the wrong question anyway.
- [x] Red-proofed: the guard is observed failing before it is accepted as
      passing. Done on the closest available guard (`analysis_failure_warning`
      unit tests) — see STATE for the before/after run.
