---
trdd-id: K3XQ7M2V
title: tldr todo JSON omits the skip list unless --detail dead is passed
column: testing
created: 2026-09-07T19:49:13+0200
updated: 2026-09-07T22:12:00+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [robustness, silent-failure, json-output]
parent-trdd: O66FM8TN
implementation-commits: [0063e1b]
---

# tldr todo JSON omits the skip list unless --detail dead is passed

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07 19:49

Not started. Split out of TRDD-O66FM8TN on 2026-09-07 because the parent's
stderr fix landed while this channel stayed broken, and a line in a commit
message is not on the board.

**IMPLEMENTED 2026-09-07, NOT YET COMMITTED.** Working tree carries the change:
`todo.rs` +40/-0, `types.rs` +16/-0, test +88/-21. Those are LINE COUNTS, and a
line count cannot say what the lines are: the lift itself was read back verbatim
at `todo.rs:243-247`, and the four skipped-files tests pass. Cite that, not the
numstat.

**The recorded blocker did not exist.** This card previously said the plumbing
needed "a third channel out of each sub-analysis (widen the return tuple, or a
collector passed in)". FALSE, and a future reader should not re-derive it:
`run_sub_analysis` returns `(Vec<TodoItem>, Value)` on EVERY run, and only the
`sub_results.insert(..)` is gated on `--detail`. So `result_value` — the whole
serialized sub-report — was already in scope in the existing loop at
`todo.rs:206`, and for the dead-code analysis that is where its `warnings` array
lives. (Only that one sub-report emits a `warnings` key today; established by
reading each sub-report's EMITTED keys, not by grepping struct fields.) No
signature changed; no sub-analysis was touched.

**Implementation:** root `TodoReport.warnings: Vec<String>`
(`skip_serializing_if = "Vec::is_empty"`) + a by-key lift in the existing loop,
placed BEFORE the insert that moves `result_value`.

**NEXT ACTION: commit.** All four acceptance boxes hold; see them below.

**The unfiltered `cargo test -p tldr-cli` returned cargo exit=101** with one
failure, `test_structure_json_output` (`cli_tests.rs:80`). **That failure
PREDATES this change, measured, not argued.** A detached worktree at HEAD
(2d3b87f1ec1cba73699ab3f53577d210f5b17113, `git status --porcelain` empty) ran
that one test and produced the byte-identical failure: `Unexpected stdout, failed
var.contains("functions")`, `test result: FAILED. 0 passed; 1 failed`.

The reading that predicted this — `tldr structure` emits a `definitions` array
of `{kind: "function"}` and no `functions` key, a schema mismatch with no path
to `TodoReport` — turned out right, but it was NOT what settled it. The clean
worktree did. **That is its own defect and its own card:** either the test is
stale against a renamed key, or `structure` regressed. It is not this card's,
and it must not be "fixed" while committing this one.

Read cargo's OWN exit status, never a wrapper's — `b6ldns2e2.output` prints
`cargo exit=101` and, twelve lines below it, `[exited with code 0]`, which is the
enclosing script's. Do NOT substitute `cargo test -p tldr-cli todo`: `todo` is a
test-NAME filter, so most binaries execute nothing, and `test result: ok. 0
passed; ... N filtered out` is a PASS line for a binary that ran nothing. Count
executed tests by SUMMING the `N passed` fields; `grep -c "0 passed"` is invalid
(the substring also matches `10 passed`, `20 passed`).

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
reader wrong, which is why this card is scoped to (c) alone.

### Why this carries `none`, and the floor question it raises

The objective floor for (c) alone is `none` — an additive field triggers nothing
in the tier table. This card was filed at `none`, raised to `user`, and returned
to `none`. The round trip is recorded because the reasoning matters more than the
value:

The raise was made on the observation that the parent TRDD-O66FM8TN carries
`min-approval-requirement: user` while its `## Approval log` records **no trigger
for that floor** — and on the worry that a child scoped to the one option floored
at `none` would read as avoiding review. Neither is a reason. "I cannot name the
parent's trigger" is an absence of evidence, and converting it into the parent's
floor is the same move as asserting a claim without reading its source. Optics
are not a risk to the codebase, and floors raised this way only ever ratchet:
the next agent inherits the same unanswerable question and defaults the same way.

So the floor is the one the tier table gives. **If (c) proves infeasible and the
fix must be (a), that carries `user` on the objective table and this card
escalates** — the escalation clause already covers the case the raise was
hedging.

**Derived finding, belongs to the parent, not here:** O66FM8TN's `user` floor has
no recorded trigger. Someone should document it or lower it. Propagating it
downward was the wrong fix.

## Feasibility of (c) — RESOLVED 2026-09-07, it is feasible

Both blocking assumptions were read and both hold:

- **There is a root struct.** `TodoReport` (`crates/tldr-cli/src/commands/remaining/types.rs:199`)
  is built in `TodoCommand::run` at `todo.rs:260` and serialized whole — via
  `serde_json::to_string_pretty(&report)` at `todo.rs:270` for `--output`, and
  `writer.write(&report)` at `todo.rs:284` for stdout. (The `to_value(&report)`
  calls at 372/422/465 are NOT this: 372 is inside `run_dead_analysis`, which
  begins at 314. They serialize each SUB-analysis's own report. An earlier
  version of this section cited them as evidence for the root — the conclusion
  held, the citation did not.) It already carries a conditionally-emitted
  field — `sub_results` is
  `#[serde(default, skip_serializing_if = "HashMap::is_empty")]` (types.rs:215),
  added by WRAPPER-CROSS-CONSISTENCY-V1/BUG-19 for exactly this reason: an
  always-present empty `{}` was misleading. So an omitted-when-empty additive
  field is this struct's established pattern, not a new convention.
- **Nothing IN THIS WORKSPACE uses `deny_unknown_fields`.** Grep over `crates/`
  returns three hits, all prose: a test comment, a doc comment, and
  `encoding.rs:157`, which notes that `deny_unknown_fields` on a mirror struct
  "would break on output it never asked for".
  **Scope, stated because the search cannot cover the claim's real subject:** a
  consumer of `tldr todo -f json` is by definition OUTSIDE this repo — another
  tool, a script, a downstream crate. No grep here can see one, so this is not
  "no consumer deserializes strictly"; it is "this repo sets no such trap, and
  the one place that considered it rejected it as wrong for this kind of output".
  That is the strongest form available without surveying users, and it is what
  the additive option rests on.

**Remaining design step, not yet done:** the skip list is local to
`run_dead_analysis`, which returns `(Vec<TodoItem>, Value)`. The warnings reach
`result_value` only inside the serialized `DeadCodeReport`. Lifting them to the
root needs a third channel out of each sub-analysis (widen the return tuple, or
a collector passed in) — mechanical, but it touches every sub-analysis, so it is
the part to scope before writing code.

## Not yet verified
- Whether the other sub-analyses have skip lists that should ride the same
  field. `skipped_file_warning`'s doc comment (`tldr-core/src/fs/mod.rs:140`)
  says every directory-walking command MUST adopt the helper, so the field
  should be shaped for more than one producer from the start. Note what that
  doc actually mandates: the **report's `warnings` field**, not a stderr line —
  bugbot adopted the helper and emits a finding with no stderr output.
- Whether any consumer deserializes the todo JSON root with
  `#[serde(deny_unknown_fields)]`. "Additive" is only non-breaking if none does;
  a strict reader breaks on a new key exactly like a renamed one. Check this in
  the same pass as the root-assembly read — it is the assumption option (c)
  rests on.

## Deliberately deferred — provenance inside each warning entry

Review argued for `Vec<{analysis, message}>` over `Vec<String>` — `analysis
.category()` is in scope at the lift and discarded, and adding provenance after
the field ships is breaking. Deferred, because the two sit at **different bars**:

- The FIELD is justified by *the payload must not assert a complete analysis
  when it was incomplete*. That presumes no particular consumer, only that a
  reader not be misled — and it is the one channel that reaches a reader who did
  not know to look, since stderr and `--detail dead` both require already
  suspecting.
- PROVENANCE is justified by *a consumer needs to attribute a warning to an
  analysis*. That does presume a specific need, and with one producer attribution
  is trivial.

A string PREFIX was considered as a cheap middle and **rejected**: with one
producer it is a constant carrying zero information, and it invents a
pseudo-schema (`"dead_code: bad.py: unreadable"`) with no escaping, so a filename
containing `": "` makes the split ambiguous. Worse than either alternative —
opaque is honest, fake-parseable is not, and the separator would become
undocumented public API the first time anyone split on it.

Revisit when a second producer lands; it is a breaking change by then.

## Acceptance

- [x] `tldr todo <fixture> -f json` — **no `--detail`** — emits JSON in which
      each of the 5 unreadable files in `design/reproducers/TRDD-BKALIK1B/` is
      named, and none of the 3 readable ones is. Guarded by
      `todo_without_detail_names_every_unreadable_file_in_root_warnings`, which
      also asserts `sub_results` is absent — so the payload it reads is the
      un-`--detail`ed one, not a richer one that would pass trivially.
- [x] The assertion is on the file **names present in the payload**, never on
      absence. **With one asymmetry, stated because it is a limit of the guard:**
      the `UNREADABLE` loop is a presence check and is the one that can fail; the
      `READABLE` negative loop cannot fail given today's only producer, because
      **no other sub-report emits a `warnings` key at all**, so nothing but the
      dead-code analysis can put a name in this field.
      *That is the whole of what was measured.* The survey established the KEY's
      existence per sub-report; it did NOT enumerate the CONTENTS of dead-code's
      array. So a dead-code warning that named a readable file — a parse failure,
      a truncated analysis — would red the READABLE loop. It guards a future
      producer and that unenumerated case, not the present skip path.
- [x] Red-proofed. **Box text corrected 2026-09-07 — it previously read "with
      the fix reverted", which names an experiment nobody ran.** What was
      actually run, and what each proves:
      - Suppressing the root `warnings` key made the new test panic on its
        `.expect("root warnings array present")` — this is the one that proves
        the test detects the absence of the fix.
      - `.skip(1)` on the `UNREADABLE` loop made it exit 101 at the loop's own
        assert, naming `u32be.py` — proves the per-name assert is reachable and
        reports the missing name, rather than passing vacuously.
      - Deleting the `eprintln!` in `run_dead_analysis` reddened the sibling
        stderr test; restoring it greened it — the parent card's guard.
      - `ws.iter().take(1)` inside `lift_warnings` reddened
        `string_warnings_are_appended_unquoted` and ONLY that test (`MUTANT
        cargo exit=101`, `2 passed; 1 failed`). Run in the clean detached
        worktree, never the committable tree, which `git status --porcelain`
        confirmed unchanged afterwards. This is why that test's input carries
        two entries: with one, `take(1)` passes all three tests, and the card's
        whole subject is that EVERY skipped file is named.
      Both mutations were reverted and the revert confirmed by a full `git diff`
      of the file, not by grepping for the mutation tokens (a token grep cannot
      see a third, accidental edit).
- [x] No existing key in the `-f json` payload changes meaning. The new field is
      `skip_serializing_if = "Vec::is_empty"`, so a run with no warnings emits
      the same key SET as before.

      **SUITE SCOPE — CORRECTED 2026-09-07, this box previously OVERCLAIMED.**
      It read "the whole `tldr-cli` suite was run unmodified ... everything else
      passed". That is FALSE and a future reader must not inherit it.
      `cargo test -p tldr-cli` **fail-fasts**: it halted at `cli_tests`
      (`error: test failed, to rerun pass -p tldr-cli --test cli_tests` is the
      run's last line) after 19 `test result` lines, against **116 integration
      test targets on disk**. So ~97 binaries never executed, and that run says
      nothing whatever about them. What it does establish: among the binaries
      that ran, one failure, `test_structure_json_output`, proven pre-existing
      at HEAD in a clean detached worktree.

      **Two `--no-fail-fast` runs were launched to make this checkable at all:**
      one on the frozen working tree, one at HEAD in the clean detached worktree.
      The gate is a comparison of the FAILED test-NAME SETS, not exit codes —
      identical sets means clean; a name present only in the working tree gets
      re-run ALONE in BOTH trees before any conclusion. Stated in advance because
      improvising it after a red result is how the last investigation started.

      **The HEAD baseline was STOPPED, and why is the useful part.** It produced
      four failures at `api_check_and_patterns_accuracy_v1` (`test_api_check_*`
      x3, `test_patterns_skips_default_ignore_dirs`) that the working tree did
      not — and all four are the SAME panic, at that file's line 51:

          expected release tldr binary at <head-probe>/target/release/tldr
          (run `cargo build --release --features semantic`)

      The probe worktree has no release binary; the main tree does. The same
      fact shows in the timings — that binary is `1 passed; 4 failed` in
      **0.00s** at HEAD versus `5 passed` in **0.03s** on the working tree: the
      four never ran anything. So the earlier "may be worktree artifacts" hedge
      resolves to YES, and narrower than guessed — not missing fixtures, one
      un-built artifact. **The baseline is invalid for every test that shells
      out to `target/release/tldr`, and was never going to be valid without a
      release build there, which was never done.**

      **The first reason recorded for stopping it was a false generalization,
      and is withdrawn.** It read: "a baseline exists only to EXCUSE a failure in
      the working-tree run." A baseline also carries the EXECUTED-TEST INVENTORY
      — which binaries ran and how many tests each held — and that catches a test
      that silently stops running, which no failure ever reports. Worse, the
      argument leapt from ONE binary needing the release artifact to the whole
      run not being worth finishing, without counting the affected class. That is
      the identical narrow-to-broad move this session retracted on TRDD-DPL55YB3,
      made in the same hour as the retraction.

      **Counted afterwards, and it does not support the leap:** exactly EIGHT
      files reference `target/release/tldr` (six under `crates/tldr-cli/tests`,
      two under `crates/tldr-core/tests`). Against 116 tldr-cli integration
      targets, the baseline was invalid for ~6 of them and VALID for the other
      ~110. The five binaries both runs had completed agreed exactly. So the
      measurement argued against stopping, not for it.

      **The honest reason to leave it stopped is CONTENTION, and it is a
      different claim.** The working-tree run is the critical path at roughly one
      binary per two minutes with ~104 to go; a second concurrent cargo (a third
      was already running) halves it. Attribution is needed only if something
      goes red, and deferring it is bounded: the probe's `target/` stays warm, so
      the fallback is compiling ONE test binary there, not a second full suite.
      If the working-tree run comes back green, no attribution is needed at all
      and the baseline would have been pure cost. That is a defensible trade;
      "the baseline was invalid" was not.

      **SCOPE LIMIT on this box, and it is the sharper half of the release-binary
      finding.** The probe worktree had NO `target/release/tldr`, so its tests
      panicked — loudly. The working tree HAS one, dated **Sep 5 22:11**, while
      the sources under test were edited **Sep 7 20:33-21:33**. `cargo test`
      builds DEBUG targets and never rebuilds `target/release/`, so those eight
      files ran a binary compiled two days BEFORE this change. They pass, and
      their passing is not evidence about this change — it is evidence about a
      Sep-5 binary.

      **The kept run is blind in exactly the region where the discarded one was
      declared invalid, and blind more dangerously:** absent-binary fails loudly,
      stale-binary passes silently. Diagnosing the probe as broken and treating
      the main tree as therefore fine was the error; "no binary" and "a binary
      built from different source than the code under test" are both failures to
      measure the change.

      **Bounded — but the FIRST bound published for this was reasoning from the
      wrong artifact, and it shipped in `0063e1b`'s commit message.** It said:
      all eight were grepped for `todo` / `TodoReport`, zero hits, therefore they
      cannot reach the changed code path. The premise is true and the inference
      does not follow. **`crates/tldr-cli/src/commands/remaining/types.rs` is a
      SHARED module — at minimum with `api_check`, verified by its
      `use super::types::{` at `api_check.rs:28`; "the whole `remaining` command
      family" was written before that check and is a generalization from ONE
      confirmed consumer** — it defines
      `APIRule`, `MisuseFinding`, `APICheckSummary`, `MisuseCategory` and
      `MisuseSeverity` alongside `TodoReport`, and
      `api_check_and_patterns_accuracy_v1.rs` (one of the eight) tests exactly
      that command. A test that never utters "todo" can still consume types from
      the file that was edited. The question asked was "does the TEST mention
      todo?"; the question that decides it is "what did the EDIT touch?"

      **The coupling is REAL, not inferred from names.** The first version of
      this paragraph called `types.rs` shared on the strength of type names that
      looked like api-check's (`APIRule`, `MisuseFinding`, …) sitting in the same
      file — which is co-location, and would have been the same inference error
      one layer down. Checked properly: `api_check.rs:28` reads
      `use super::types::{`, and the file names those types 275 times. It really
      does import from the edited module.

      **The sound check, run afterwards, and it does hold — but the first
      statement of it understated the diff.** It said "`todo.rs` gains a private
      helper and one call", asserted from having read the file earlier rather
      than from this commit's diff for that path. Read properly, `todo.rs` is
      **129 insertions, 0 DELETIONS**, in four hunks: a `let mut warnings:
      Vec<String>` local, the `lift_warnings(..)` call, a `warnings,` field in
      the `TodoReport` literal, and the helper plus its `#[cfg(test)] mod
      lift_warnings_tests` (most of the 129). The `types.rs` half was verified
      from the diff at the time and is exactly two hunks: the field inside
      `TodoReport` and `warnings: Vec::new(),` in `TodoReport::new()`.

      **Zero deletions across both files is what actually carries the
      conclusion** — nothing pre-existing was modified or removed, and every
      addition sits inside the todo path or a test module. So the eight are
      unreachable from this diff, by its scope. Stronger evidence than the loose
      phrase it replaces, which is the point: "a helper and one call" was an
      assertion about a diff made without reading it, in a paragraph whose whole
      subject is asserting scope without reading the diff.

      **The argument that beats all three of the above, and that I never made:
      THE PACKAGE COMPILED.** If the `types.rs` edit had broken any other
      `remaining/` consumer structurally, `cargo test -p tldr-cli` would have
      failed to BUILD and zero binaries would have run. Twenty-two ran. That
      excludes structural reachability far more strongly than any grep or
      diff-reading, and unlike the grep it runs in the correct direction — from
      the changed symbol outward, rather than from a test's vocabulary inward.
      What compilation does NOT exclude is a behavioural change in serialized
      output, which is confined to code that serializes a `TodoReport`. Supplied
      by an adversarial review fork; three rounds of evidence were spent
      reconstructing by hand a fact the build had already established.

      **Same conclusion, replaced evidence.** Worth naming plainly: this is the
      identical "right answer, wrong evidence" failure retracted on TRDD-DPL55YB3
      earlier the same day, committed within the hour of writing that retraction,
      and it reached a commit message where it cannot be edited. The correction
      lives here because the card is the durable record; `0063e1b`'s message
      still carries the weaker claim and is not to be cited for it.

      *(An earlier probe used `.arg("...")` and returned empty for all six CLI
      files — a wrong-shape artifact, not a finding.)*

      **Therefore this box's claim EXCLUDES those eight files.** Widening it
      requires `cargo build --release --features semantic` in the working tree
      and a re-run of those targets; that is not done, and the box must not be
      read as covering them.

      The guards for THIS change were then run BY NAME and did execute:
      `--lib lift_warnings` → `cargo exit=0`, `3 passed`, all three named;
      `--test skipped_files_todo_bugbot_test` → `cargo exit=0`, `4 passed;
      0 filtered out`, all four named. A `--no-fail-fast` run over the whole
      package is in flight; until it returns, no claim is made about the rest.
      *Scope of the "same key set" claim:* measured on the empty case by reading
      the emitted keys. The pre-fix key ORDER was never captured (the baseline
      was printed sorted), so this is a claim about the key set, not a
      byte-identical-output claim — an ordinal-index consumer, if one existed,
      would see `total_elapsed_ms` shift when warnings ARE present.
