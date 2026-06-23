# RC3 — element/subscript writes treated as a full killing redefinition of the container

**Cluster:** reaching-defs (analysis[0]), cross-cluster with dead-stores
**Classification:** design-fork (product-semantics decision on how to model partial / element writes)
**Status:** NOT implemented in fix-R7 (requires a lattice / RefType decision). This doc records the problem, options, trade-offs, and recommendation for the maintainer.

## Problem

An element write `args[length] = ...` (JS lodash `_baseConvert.js::flatSpread`, but the
machinery is language-agnostic) is recorded by the extractor as `RefType::Update` on the
*container* `args` (see `record_subscript_container_and_index_multi`,
`crates/tldr-core/src/dfg/extractor.rs`). `reaching.rs` then folds `Update` into the
definitions set exactly like `Definition`:

```
crates/tldr-core/src/dfg/reaching.rs  (compute_reaching_definitions_counted)
  let defs = refs.iter().filter(|r| matches!(r.ref_type, Definition | Update)) ...
```

and the GEN/KILL builder treats that `Update` as a **kill + gen** of the whole variable —
it manufactures a brand-new `DefId` at the element-write line that KILLS the prior binding.

Consequence (Bug 8): for

```js
function flatSpread(...) {
  var args = ...;        // def @80
  args[length] = ...;    // Update @83  -> treated as a NEW def that kills @80
  ... use args ...       // @85, @86, @92
}
```

the def `args@80` loses its def-use chain (its `uses` become `[]`) because the spurious
`def@83` kills it; the later reads attribute to `@83` instead. The same machinery drives a
parallel **dead-stores** false positive (the @80 store looks dead because its uses were
re-attributed).

This is PRE-EXISTING (baseline 5635a77 already recorded `args[length]=` as `Update` and
already filtered `Definition | Update` into the defs set). It is *not* a regression.

## Why this is a design-fork, not a mechanical fix

`reaching.rs`'s defs/gen/kill is the heart of reaching-defs AND dead-stores, available,
slice/chop, and use-def chains — for ALL languages. Changing how an element write is modeled
is a product-semantics decision (strong-update vs weak-update of aggregates) that ripples to
every consumer and requires a golden re-baseline. It must be made deliberately, not as a
drive-by fix inside a closeout pass.

## Options

### Option A — precise alias model (weak update). RECOMMENDED
Introduce a distinct ref flavor for container element/field writes — either a new
`RefType::ElementUpdate` or a boolean flag on `Update` (e.g. `Update { strong: bool }`). In
`compute_block_gen` / `compute_block_kill`, an element-update:
- is a **Use** of the container (it reads the binding to locate the element), and
- is a **weak update** that does NOT kill the container's existing `DefId` (the binding still
  points at the same object).

Effect: `args@80` keeps its binding and its def-use chain; the element write adds a *use*
(and optionally a same-DefId "may-modify" marker) but no killing def. Fixes Bug 8 and the
parallel dead-store FP, and generalizes to struct-field writes (`p.f = x`) which have the
identical issue.

Trade-offs:
- Most correct; matches standard dataflow treatment of aggregate stores (weak update).
- Touches the core lattice: a new `RefType` variant (or `Update` shape change) forces every
  `match` on `RefType` across `extractor.rs`, `reaching.rs`, `ssa/construct.rs`, `chains.rs`,
  and any consumer pattern-matching `ref_type` to handle the new case (the compiler will list
  them — this is exhaustiveness-checked, so the blast radius is *discoverable* but large).
- Requires re-baselining the DFG golden suites (reaching_tests, fix_cl5_dfg, rust_dataflow,
  solidity_dfg, dead_stores_live_vars).

### Option B — localized chain-merge (keep Update == Definition for kill)
Keep the kill semantics, but in def-use chain attribution, MERGE consecutive defs of the same
var when one is an element-update, so uses attribute to the strong (original) binding.

Trade-offs:
- Localized to chain-building; no lattice change; smaller golden churn.
- Less principled: the IN/OUT sets still contain the spurious kill, so any consumer that reads
  reaching-in directly (not via the merged chains) still sees the wrong picture. It treats the
  symptom (chain attribution) not the cause (the kill).

## Recommendation

**Option A.** Model element/field writes as a weak update (Use + non-killing) via an explicit
ref flavor. It is the correct dataflow semantics, fixes both the reaching-defs and dead-stores
manifestations from one change, and generalizes to struct-field writes. Schedule it as a
dedicated change with a full DFG golden re-baseline, coordinated with the dead-stores owner
(RC3 is the shared root cause of a dead-stores FP).

## Pointers
- Extractor: `record_subscript_container_and_index_multi`, the `subscript`/`member_expression`
  assignment-target arms in `extract_assignment_targets` (`crates/tldr-core/src/dfg/extractor.rs`).
- Lattice: `compute_reaching_definitions_counted`, `compute_block_gen`, `compute_block_kill`
  (`crates/tldr-core/src/dfg/reaching.rs`).
- RefType: `crates/tldr-core/src/types.rs`.
