---
trdd-id: 3TCJKGWM
title: Backward slice includes unrelated statements because the entry node spans the whole straight-line body
column: complete
created: 2026-09-06T03:01:05+0200
updated: 2026-09-10T19:08:05+0200
implementation-commits: [218efb0]
current-owner: kanban-wave1-worker1
task-type: bugfix
min-approval-requirement: none
blocked-by: []
labels: [pdg, slicing, precision, pre-existing]
---

# Backward slice includes unrelated statements because the entry node spans the whole straight-line body

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10

### REGRESSED 2026-09-10 by the workspace gate, then RE-FIXED — the PDG node is the STATEMENT

The one-node-per-SOURCE-LINE builder described further down removed the imprecision this card
was opened for, and introduced an **unsoundness** in exchange: the rows of a single statement
became unconnected nodes, so a backward slice could DROP a statement it depends on. Measured on
`target/debug/tldr` (fixtures in the wave scratchpad, `chop_fixture/`):

- `chop model.py __init__ 3 9` → **0 lines** (`path_exists: false`). The pre-wave binary
  `~/.cargo/bin/tldr` returned 9. The criterion sits on a 6-row `def __init__(` signature
  (lines 3-8) whose rows were six disconnected nodes.
- `slice model.py __init__ 9` → **{5, 9}**, i.e. only the row `a,` happens to sit on — rows
  3,4,6,7,8 of the statement that DEFINES `a` were dropped.
- `slice multiline_call.py f 8` → **{3, 8}**. `x = compute(\n a,\n b,\n)` put the def of `x` on
  row 3 and the uses of `a`/`b` on rows 4/5; the backward walk reached row 3 and stopped, so the
  definitions of `a` and `b` (row 2) never entered the slice.
- Failing test: `cargo test -p tldr-cli --test path_and_schema_cleanup_v3 dunder`.

This is worse than what the card started from: the block-granular builder was imprecise but
**never dropped a relevant statement**; the per-line builder did. Both are wrong about the same
thing — the unit. **A PDG node is now one STATEMENT.**

**The fix as landed** (worker-1b):

- `cfg/extractor.rs` — the builder records statement line spans as
  `StatementSpans = Vec<(block_id, start_line, end_line)>` and returns them beside the `CfgInfo`
  through `get_cfg_context_with_statements` / `extract_cfg_from_tree_with_statements`.
  `get_cfg_context` and `extract_cfg_from_tree` keep their old signatures and drop the `.1`.
  Spans are pushed from: the catch-all `_` arm and `process_expression` (leaf = whole span;
  compound = header only, then recurse into the body), the three leaf processors that create
  their own block (`process_return_statement`, `process_break_statement`,
  `process_continue_statement`), and `record_signature_span` (start row → last row of any child
  except the body, so a Rust `) -> u32 {` and a Python `):` are both covered without naming a
  grammar field; a `decorated_definition` is unwrapped so decorator rows stay separate).
  **No CFG block, edge or `lines` value changed — the `cfg` JSON is byte-identical.**
- `pdg/extractor.rs::build_pdg` — one node per recorded span (deduped by span), then the
  unchanged per-line fallback for every line of a block no span covers, which is what keeps
  Branch/LoopHeader condition lines working. Within a block, lines are claimed widest-span-first
  so the narrowest owner wins; across blocks the first owner wins, which keeps the Return/Exit
  overlap collapsing to one node. Defs/uses are attached BY LINE OWNERSHIP once `node_for_line`
  is final, so a shared row can never count one DFG ref into two nodes;
  `find_defs_uses_in_range` had no caller left and is deleted.
- Spans deliberately live in a `pub(crate)` side channel, NOT on `CfgBlock`. A
  `#[serde(skip)]` field would (a) add invisible state to a public serialized type whose empty
  value silently degrades a deserialized CFG back to the unsound per-line graph, and (b) force
  `statements: Vec::new()` into 77 struct literals across 14 files. Traced before choosing:
  `build_pdg` has exactly ONE caller, `get_pdg_context`, which builds its CFG fresh in-process;
  no `CfgInfo`/`PdgInfo` is deserialized anywhere and fed to the PDG builder.

**Verification after the re-fix** — RED first, on the per-line builder (`build_pdg` fed `&[]`):
`slice_keeps_multiline_signature_together` `left: [5, 9]`,
`slice_is_sound_across_multiline_call` `left: [3, 8]`,
`slice_keeps_multiline_signature_together_rust` and `..._typescript` both `left: [3, 4, 6, 8]`;
`test result: FAILED. 15 passed; 4 failed`. GREEN after:

- `cargo test -p tldr-core --lib` → `ok. 4828 passed; 0 failed; 293 ignored`
- `cargo test -p tldr-core --test pdg_tests --test cfg_tests --test dfg_tests` → `ok. 41` /
  `ok. 24` / `ok. 20`, 0 failed
- `cargo test -p tldr-cli --test path_and_schema_cleanup_v3 dunder` → `ok. 3 passed; 0 failed`
- `cargo test -p tldr-cli --test pdg_bounds_and_stdout_hygiene_v1` → `ok. 4 passed; 0 failed`
- cfg-JSON consumers (`grep -rln '"blocks"' crates/tldr-cli/tests`):
  `reaching_defs_cli_tests` `ok. 28`, `context_file_func_and_cpp_qualified_v1` `ok. 25`,
  `language_command_matrix reaching` `ok. 18` — all 0 failed
- `cargo clippy -p tldr-core --lib -- -D warnings` exit 0;
  `--test pdg_tests --test cfg_tests --test dfg_tests -- -D warnings` exit 0.
  `--lib --tests` is RED only in `tests/perf_abstract_interp_benchmark.rs:394`
  (`unnecessary_sort_by`) — untouched by this card, pre-existing, belongs to TRDD-U5KJ5A8R.
- CLI probes: `chop model.py __init__ 3 9` → `[3,4,5,6,7,8,9]` (7 lines);
  `slice … 9` → `[3,4,5,6,7,8,9]`; `slice … 5` and `slice … 3` both → `[3,4,5,6,7,8]` (the same
  set from either signature row); `slice multiline_call.py f 8` → `[2,3,4,5,6,8]` (7 excluded);
  `branch_sample.py f 9` → `[1,2,3,4,5,8,9]` and `loop_sample.py g 7` → `[1,2,3,4,6,7]`, both
  unchanged and both re-derived by hand from the source first.

**Known limitation — the per-line residue, by node kind so the next regression is a grep.**
A statement is one node only if the CFG builder recorded a span for it. Everything else still
gets one node per source line: a `Branch`/`LoopHeader` **condition** that wraps across rows
(the CFG reports the header block as the condition line only, a pre-existing limit), the
`if`/`for`/`while`/`loop`/`try`/`match` headers themselves, Rust's `?` (`try_expression` without
an `expression` field, via `process_question_mark`), and a nested
`function_definition`/`function_declaration`/`arrow_function`, which gets no span in the
enclosing function at all. Those are the kinds with their own CFG arm; adding a whole-node span
to any of them would make the graph coarser, not finer.

### Original fix (2026-09-06 → 2026-09-10 09:33) — superseded above on the node UNIT only

- **DECIDED (USER go, relayed 2026-09-10): statement-level precision is the GOAL.** The card's
  open question is closed in that direction, so the body's "whether that is a defect or an
  accepted limitation" framing is SUPERSEDED — it is a defect and it is now fixed.
- **FIXED** in `crates/tldr-core/src/pdg/extractor.rs::build_pdg`. A PDG node is now ONE SOURCE
  LINE instead of one CFG basic block:
  - `extractor.rs:49-113` — the node-building loop emits a node per line of each block, keyed
    through a `node_for_line: HashMap<u32, usize>`; a `nodes_for_block: HashMap<usize, Vec<usize>>`
    keeps the block→nodes mapping the control-edge pass needs. Only a block's FIRST line keeps the
    block's own kind (`entry`/`predicate`); the rest are `statement`.
  - `extractor.rs:119-149` — a control CFG edge from a `Branch`/`LoopHeader` now expands to the
    CROSS PRODUCT of the two blocks' line nodes. Keeping the source side whole (not just the
    condition line) preserves exactly the reachability the block-granular graph had, so the split
    cannot DROP a line from a slice — it can only remove lines that were never reachable.
  - `extractor.rs:151-166` — data edges resolve `def_line`/`use_line` through `node_for_line`
    instead of `find_block_for_line`, which is deleted (it had no other caller).
- The card's UNEXPLAINED item is **EXPLAINED and gone**: the two `(6,6)` nodes were the `Return`
  block and the `Exit` block, which the probe below shows both spanning line 6. Not duplicate
  construction — two CFG blocks over one line. The new builder gives one line one node, so the
  duplicate no longer appears.
- Why NOT the slice-side fix, confirmed empirically rather than assumed: clamping
  `nodes_to_lines` would have left `pdg.edges` pointing block-to-block, so the `pdg` JSON,
  `get_slice_rich`'s edge list and every other consumer would still have reported a dependency
  between two unrelated statements. Fixing the graph fixes all of them at once.
- **Regression test**: `crates/tldr-core/tests/pdg_tests.rs:799-832`,
  `slicing_tests::slice_excludes_unrelated_statement_in_straight_line_code`. Pins the exact set,
  not just `!contains(&5)`, so a future coarsening of the graph fails it again.
  - BEFORE (extractor.rs restored to HEAD, test unchanged): FAILED —
    `left: [2, 3, 4, 5, 6]  right: [2, 3, 4, 6]`, exit 101.
  - AFTER: `test result: ok. 36 passed; 0 failed` (exit 0).
- `slicing_tests::slice_empty_function` needed NO change: its bound is `(2..=3)` and the new
  slice for that 3-line body is a subset of it. Its long `// why` comment now over-explains a
  span that no longer exists, but it is accurate about the old behaviour and it is another
  worker's blast radius to re-word; left alone deliberately.
- Verification, all after the fix: `cargo test -p tldr-core --test pdg_tests` exit 0 (36 passed);
  `cargo test -p tldr-core --lib pdg` exit 0 (20 passed); `cargo test -p tldr-core --lib` exit 0
  (4828 passed); `cfg_tests`+`dfg_tests` exit 0; `tldr-cli --test pdg_bounds_and_stdout_hygiene_v1`
  exit 0. `cargo clippy -p tldr-core --lib --test pdg_tests -- -D warnings` exit 0.
  `--all-targets` clippy is RED both before and after this change, in
  `tests/perf_abstract_interp_benchmark.rs` and `tests/analysis_tests.rs` — other workers' files,
  not this card's.
- ~~Known limitation, recorded rather than fixed: a statement spanning several source lines is
  now several nodes, tied together only by the def/use refs the DFG records per line.~~
  **SUPERSEDED 2026-09-10** — it was not a limitation but an unsoundness, and it is fixed; see
  the REGRESSED section at the top. Kept because it is the sentence that predicted the defect.
- Found 2026-09-06 while triaging a test failure, NOT by a scanner.
- PRE-EXISTING — OBSERVED at the fork parent, not argued from diffs. The reproducer below was
  run in a worktree checked out at `7f50527`. Identical slice `[2,3,4,5,6]`, identical node set
  and spans (`id=0 lines=(2,5) type="entry"`, both `(6,6)` statement nodes), identical edge
  MULTISET. The edge PRINT ORDER differs between the two runs (`0->0 b` and `0->1 c` swap
  places), which is not load-bearing and is most likely iteration order over a hash container —
  though that was not verified, so it is stated as an unexplained difference rather than
  dismissed. Nothing in the scan pass caused this.
- Method note, because it cost three rounds: this was first "established" by diffing
  `src/pdg/`, then re-established by diffing `src/cfg/` when that proved insufficient, and the
  next directory in line was `src/ast/` (spans ultimately derive from parsed statement
  ranges). Walking directories terminates only when you happen to guess right and cannot tell
  you when that is. Running the reproducer at the parent answers it in one step. Prefer that.
- ~~Not yet fixed.~~ SUPERSEDED 2026-09-10 — fixed, see the top of this block.
- ~~UNEXPLAINED: the dump below shows TWO distinct nodes, id=1 and id=2, both with
  `lines=(6,6)`.~~ SUPERSEDED 2026-09-10 — explained (Return block + Exit block, both `(6,6)`)
  and removed by the fix.

## Symptom

A backward slice returns statements that have no dependency path to the slicing criterion,
which defeats the purpose of slicing. Observed by printing the PDG and the slice for:

```python
def wide(a):        # line 2
    b = a + 1       # line 3
    c = b + 2       # line 4
    d = 99          # line 5
    return c        # line 6
```

`get_slice(source, "wide", 6, Backward, None, Python)` returns `[2, 3, 4, 5, 6]`.

Line 5 (`d = 99`) has no data or control path to `c`. Under textbook backward-slicing
semantics it must not appear in a slice from `return c`, and the answer would be `{2, 3, 4, 6}`
(`c` ← `b` ← `a`, reaching the parameter on the header line) or `{3, 4, 6}` if the header is
excluded.

What the project documents, in the module docs of `crates/tldr-core/src/pdg/slice.rs`:

> ## Backward Slice
> Given a slicing criterion (line, optional variable), find all statements
> that could affect the computation at that point.
>
> Algorithm:
> 1. Start at the criterion node in PDG
> 2. Follow edges backward (from target to source)
> 3. Collect all visited nodes

Read carefully, that documents SOUNDNESS and not PRECISION. "Find all statements that could
affect" is a lower bound: it forbids MISSING a relevant statement, and says nothing about
INCLUDING an irrelevant one. `[2,3,4,5,6]` satisfies it — as would returning the whole
function body, which is trivially sound and useless. Classical slicing is stated as sound AND
minimal, and minimality is the half that is hard; only the first half is written down here.
Step 3 points the same way: it collects NODES, and never claims a node is one statement, so
node-granular collection is what the algorithm as documented describes.

The `get_slice` rustdoc does not settle it either. Its example says the slice "should include
line 1 (x = 1)" — `include` is again a lower bound, and in a two-statement function the whole
body is the answer under either reading, so the example cannot discriminate.

So the accurate position: the observed slice is SOUND but IMPRECISE, precision is bounded by
basic-block size, and the intended precision is UNDOCUMENTED. Whether that is a defect or an
accepted limitation is exactly the open question this card exists to settle — it should not be
prejudged in either direction.

What the neutrality must NOT bury, because it is measured rather than normative and it is the
fact an implementer actually needs: **precision is bounded by basic-block size, and for
branch-free code the entire function body is one block.** So for any straight-line function,
a backward slice returns the WHOLE body regardless of the criterion. That is not merely
"imprecise" — over that whole input class the result carries no information the reader did not
already have from opening the function. The spec question stays open; this consequence holds
either way, and it is why the card is `todo` and not closed as working-as-intended.

This paragraph has been wrong twice, in opposite directions, and the history is kept because
the failure mode is instructive. First revision asserted "a real defect" without checking for
a spec. Second revision said no spec existed, on a search of `thoughts/` that never looked at
the implementing file. Third revision found the module doc and read its soundness clause as a
precision guarantee, because it was looking for a contract and took the first text that
resembled one.

## Cause (observed, not inferred)

The printed graph for that source:

```
node id=0 lines=(2, 5) type="entry"
node id=1 lines=(6, 6) type="statement"
node id=2 lines=(6, 6) type="statement"
edge 0 -> 0 Data b
edge 0 -> 1 Data c
edge 0 -> 0 Data a
```

Every statement BEFORE the return collapses into ONE `entry` node spanning `(2,5)`; the
`return c` line is separate (and, unexplained, appears as two nodes). Two mechanisms then
combine, both in `pdg/slice.rs`:

1. `find_nodes_for_line` selects every node whose range CONTAINS the line, so an entry node
   with a wide span is selected by any line inside it.
2. `nodes_to_lines` emits every line in a selected node's range `lines.0..=lines.1`.

The full traversal, matching the observed output exactly: `find_nodes_for_line(6)` selects
`{1, 2}` (node 0's `(2,5)` does not contain 6); `edge 0 -> 1` is a data edge meaning node 1
DEPENDS ON node 0, and a backward slice walks dependency edges in reverse, so node 0 is
reached from node 1; `nodes_to_lines` then expands `(2,5)` to `{2,3,4,5}` and unions `{6}`,
giving `[2,3,4,5,6]`.

The two `0 -> 0` self-edges corroborate the wide span rather than contradicting it: `a`
(def line 2, use line 3) and `b` (def line 3, use line 4) are def-use pairs INTERNAL to node
0's span, so both collapse onto the same node.

Precision is therefore bounded by basic-block size, and for branch-free code the body is one
block.

## Reproducer

Drop this in `crates/tldr-core/tests/pdg_tests.rs` inside `mod slicing_tests` (that module has
`use super::*`, which is what puts `get_slice`, `SliceDirection` and `Language` in scope) and
run `cargo test -p tldr-core --test pdg_tests slicing_tests::probe -- --exact --nocapture`.

A snippet identical to this except for the function name and the println label strings has been
compiled and run in that module, both on `main` and in a worktree at the parent `7f50527`.
Every compile-relevant token is the same — the `get_pdg_context` path, `get_slice`,
`SliceDirection`, `Language`, and the `use super::*` scope that supplies them — so "runnable"
is verified, though not by compiling this literal text. It is kept here
rather than committed as an `#[ignore]`d test, because a test that PASSES against today's
behaviour is not the regression test this card's acceptance asks for.

```rust
#[test]
fn probe() {
    let source = "\ndef wide(a):\n    b = a + 1\n    c = b + 2\n    d = 99\n    return c\n";
    let pdg = tldr_core::pdg::extractor::get_pdg_context(source, "wide", Language::Python).unwrap();
    let sl = get_slice(source, "wide", 6, SliceDirection::Backward, None, Language::Python).unwrap();
    let mut v: Vec<_> = sl.into_iter().collect();
    v.sort();
    println!("slice-from-line6 = {v:?}");
    for n in &pdg.nodes {
        println!("node id={} lines={:?} type={:?}", n.id, n.lines, n.node_type);
    }
    for e in &pdg.edges {
        println!("edge {} -> {} {:?} {}", e.source_id, e.target_id, e.dep_type, e.label);
    }
}
```

The same mechanism explains the smaller case pinned by `slicing_tests::slice_empty_function`
in `crates/tldr-core/tests/pdg_tests.rs`: there the entry node is `(2,3)` and overlaps the
`(3,3)` statement node, so slicing from line 3 selects both and yields `{2,3}`.

## What a fix has to decide

The cheap read is "make `nodes_to_lines` emit only the requested line", but that is wrong: it
would silence this symptom while leaving the graph coarse, and would break slices that
legitimately need a whole block. The real question is whether the CFG should split
straight-line statements into separate blocks for PDG purposes, which is a change to
`pdg/extractor.rs` / the CFG builder and affects every PDG consumer.

Recommended order: reproduce with the snippet above, decide block granularity first, and only
then touch the slice-side functions.

## Acceptance

The first line is the decision this card exists to make. The rest are contingent on it, and
must NOT be read as prejudging it — an earlier revision wrote them while the card still claimed
"defect", and they would have made the card unclosable if the decision goes the other way.

- [x] The intended precision is DECIDED and recorded here: is block granularity the intended
      behaviour, or is statement-level precision the goal? The docs state soundness only, so
      this cannot be settled by reading them.
      **DECIDED 2026-09-10 — statement-level precision is the goal** (USER go relayed through
      the kanban-wave orchestrator). Recorded at the top of the STATE block.

- [x] The follow-on work implied by that decision is filed as its own card, and this one closes
      Filed as TRDD-EX9JW9O4 on 2026-09-10 (residue by node kind, incl. reviewer nits N1/N2).

That is the whole acceptance, deliberately. An earlier revision pre-wrote BOTH futures as two
branches of checkboxes; whichever way the decision went, the losing branch's boxes could never
be ticked, so the card became unclosable by construction. One row whose acceptance IS the
decision is the right shape, and the implementation becomes a derived card once there is a
decision to implement.

For whoever files that derived card, the two shapes are: if block granularity is INTENDED,
document the precision bound on `get_slice` (including the branch-free consequence above) and
point `slice_empty_function`'s `(2..=3)` at that doc. If statement-level precision is the GOAL,
make a backward slice from `return c` exclude line 5, pin it with a regression test that fails
against today's behaviour, revisit that same `(2..=3)` bound, and check `cargo test -p
tldr-core` against the classified baseline.

## Approval log

- 2026-09-06T03:01:05+0200 — Filed under the standing directive to decide from verified facts
  and implement what is good. Filed rather than fixed: the fix is a granularity change to the
  CFG/PDG builder affecting every consumer, which is not a change to make inside a test-triage
  turn.
