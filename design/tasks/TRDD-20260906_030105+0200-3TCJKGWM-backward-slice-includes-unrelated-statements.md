---
trdd-id: 3TCJKGWM
title: Backward slice includes unrelated statements because the entry node spans the whole straight-line body
column: todo
created: 2026-09-06T03:01:05+0200
updated: 2026-09-06T03:06:29+0200
current-owner: claude-session-2026-09-05
task-type: bugfix
min-approval-requirement: none
blocked-by: []
labels: [pdg, slicing, precision, pre-existing]
---

# Backward slice includes unrelated statements because the entry node spans the whole straight-line body

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- Found 2026-09-06 while triaging a test failure, NOT by a scanner.
- PRE-EXISTING, checked in BOTH places that can produce a node span, because node spans are
  `block.lines` copied from CFG blocks and the CFG builder is not under `src/pdg/`:
  - `src/pdg/` since the fork parent `7f50527`: only `slice.rs`, in `62bfe3a`, touching
    `get_slice_rich` and `read_source_lines`. `get_slice`, `find_nodes_for_line`,
    `compute_slice` and `nodes_to_lines` are untouched.
  - `src/cfg/` since `7f50527`: only `cfg/extractor.rs`, 8 insertions, confined to `continue`
    handling (pushing `continue_block` onto `loop_exit_blocks`). The reproducer below has no
    `continue` and no loop, so that change cannot affect its block boundaries.
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

This is NOT imported textbook semantics. The project states the contract itself, in the module
docs of the same file that implements it, `crates/tldr-core/src/pdg/slice.rs`:

> ## Backward Slice
> Given a slicing criterion (line, optional variable), find all statements
> that could affect the computation at that point.

`d = 99` cannot affect `return c`, so emitting line 5 violates that stated contract. The
rustdoc on `get_slice` points the same way, its example noting the slice "should include line
1 (x = 1)" — the line the criterion depends on, not every line in the body.

So the intent is documented and the behaviour does not meet it. This is a defect, not an
undocumented design choice. (An earlier revision of this card claimed no spec existed, on a
search of `thoughts/` alone; the contract was in the implementation file's own module docs.)

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

Drop this in `crates/tldr-core/tests/pdg_tests.rs` inside `mod slicing_tests` and run
`cargo test -p tldr-core --test pdg_tests slicing_tests::probe -- --exact --nocapture`. It is
kept here rather than committed as an `#[ignore]`d test, because a test that PASSES against
today's behaviour is not the regression test this card's acceptance asks for.

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

- [ ] A backward slice from `return c` in the snippet above excludes line 5
- [ ] A regression test pins that exclusion, and fails against today's behaviour
- [ ] `slicing_tests::slice_empty_function`'s `(2..=3)` bound is revisited, since it currently
      encodes the coarse-granularity result and would need to tighten if granularity changes
- [ ] `cargo test -p tldr-core` shows no new failures versus the classified baseline

## Approval log

- 2026-09-06T03:01:05+0200 — Filed under the standing directive to decide from verified facts
  and implement what is good. Filed rather than fixed: the fix is a granularity change to the
  CFG/PDG builder affecting every consumer, which is not a change to make inside a test-triage
  turn.
