---
trdd-id: 3TCJKGWM
title: Backward slice includes unrelated statements because the entry node spans the whole straight-line body
column: backburner
created: 2026-09-06T03:01:05+0200
updated: 2026-09-06T03:01:05+0200
current-owner: claude-session-2026-09-05
task-type: bugfix
min-approval-requirement: none
blocked-by: []
labels: [pdg, slicing, precision, pre-existing]
---

# Backward slice includes unrelated statements because the entry node spans the whole straight-line body

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- Found 2026-09-06 while triaging a test failure, NOT by a scanner. Confirmed PRE-EXISTING:
  the only change to `crates/tldr-core/src/pdg/slice.rs` since the fork parent `7f50527` is
  `62bfe3a`, which touches `get_slice_rich` and `read_source_lines` only. `get_slice`,
  `find_nodes_for_line`, `compute_slice` and `nodes_to_lines` are untouched.
- Not yet fixed. Nothing depends on this card; it is filed so the defect is tracked rather
  than living in a test comment.

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

Line 5 (`d = 99`) has no data or control path to `c` and must not appear in a backward slice
from `return c`. The correct answer is `{2, 3, 4, 6}` at worst, `{3, 4, 6}` if the header is
excluded.

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

Every straight-line statement collapses into ONE `entry` node spanning `(2,5)`. Two mechanisms
then combine, both in `pdg/slice.rs`:

1. `find_nodes_for_line` selects every node whose range CONTAINS the line, so an entry node
   with a wide span is selected by any line inside it.
2. `nodes_to_lines` emits every line in a selected node's range `lines.0..=lines.1`.

So as soon as the entry node is reached — here via `edge 0 -> 1` — its whole span is emitted,
unrelated statements included. Precision is therefore bounded by basic-block size, and for
branch-free code the whole body is one block.

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
