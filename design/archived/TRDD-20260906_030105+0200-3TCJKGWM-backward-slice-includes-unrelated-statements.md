---
trdd-id: 3TCJKGWM
title: Backward slice includes unrelated statements because the entry node spans the whole straight-line body
column: todo
created: 2026-09-06T03:01:05+0200
updated: 2026-09-06T03:13:22+0200
current-owner: claude-session-2026-09-05
task-type: bugfix
min-approval-requirement: none
blocked-by: []
labels: [pdg, slicing, precision, pre-existing]
---

# Backward slice includes unrelated statements because the entry node spans the whole straight-line body

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

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
- Not yet fixed. Nothing depends on this card; it is filed so the defect is tracked rather
  than living in a test comment.
- UNEXPLAINED, and it should be resolved before designing a fix: the dump below shows TWO
  distinct nodes, id=1 and id=2, both with `lines=(6,6)`. One line yielding two nodes is
  either duplicate node construction (possibly a second defect) or a modeling detail not yet
  understood. It does not change this card's symptom, but it is not accounted for.

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

- [ ] The intended precision is DECIDED and recorded here: is block granularity the intended
      behaviour, or is statement-level precision the goal? The docs state soundness only, so
      this cannot be settled by reading them.

- [ ] The follow-on work implied by that decision is filed as its own card, and this one closes

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
