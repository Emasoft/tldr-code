# Decision: `cohesion` LCOM4 flags fieldless types as `split_candidate`

Cluster: [11] misc-tail. Command: `cohesion`. File:
`crates/tldr-core/src/quality/cohesion.rs` (the `all_fields.is_empty()` branch,
~lines 1413-1446). Classification in `reaudit-rootcause.json` analysis[11]:
**design-fork**.

## Problem (reproduced LIVE)

A fieldless Rust type with method-only `impl`s is reported as a refactor
candidate:

```
$ tldr cohesion /tmp/fieldless.rs   # struct Calculator; impl { add, sub, mul }
class=Calculator field_count=0 method_count=3 lcom4=3 verdict=split_candidate
```

LCOM4 measures cohesion as the number of connected components in the
method-shares-a-field graph. With **zero fields** every method is its own
component, so `lcom4 == method_count` and any type with more than
`low_cohesion_threshold` methods is mechanically flagged "split into N classes".

This is an inapplicable verdict for idiomatic fieldless types:
- Rust unit structs / ZSTs with method `impl`s (`struct Calculator;`).
- Rust trait `impl`s and enums whose variants carry data but the type has no
  named fields the LCOM model sees.
- Utility/static "namespace" types in any language (Java `final class Math`
  with only static methods, Go method sets on empty structs).

The audit measured 105 such zero-field `split_candidate` verdicts when running
`cohesion` over the tldr `crates/` tree itself.

## Root cause

`cohesion.rs` `all_fields.is_empty()` branch sets `lcom4 = method_count` and
then applies the SAME `lcom4 > threshold` verdict rule used for field-bearing
types. LCOM4 is undefined (or trivially maximal) without fields, so the rule is
meaningless here.

## Attribution

PRE-EXISTING / by-design gap. The fieldless-type verdict semantics predate the
campaign; `e0a4791` touched the cohesion path for OCaml/Lua/LCOM4 determinism
but not this verdict rule.

## Options

### Option A — suppress the split verdict for fieldless types (recommended, IMPLEMENTED)
When `field_count == 0`, report `Cohesive` (LCOM4 is not applicable without
fields). `lcom4`/`method_count` are still reported for transparency, and a
`split_suggestion` is omitted. Language-agnostic, simplest, removes the false
"split into N classes" advice for every fieldless method-bearing type.

### Option B — Rust-specific: skip LCOM4 for trait-impl / unit-struct groups
Only compute LCOM4 for `struct`/`enum` declarations that actually declare
fields; skip trait impls and unit structs entirely. More targeted but
Rust-specific and more invasive (needs the declaration kind at the cohesion
layer), and still needs Option A's rule for utility classes in other languages.

### Option C — keep flagging
Rejected: the verdict is actively misleading; a fieldless utility type is not
improved by "splitting into N classes".

## Decision

**Option A**, implemented in `fix-R7-cl11-misctail`: in the
`all_fields.is_empty()` branch, force `verdict = Cohesive` and
`split_suggestion = None` (LCOM4 not applicable). The numeric `lcom4` and
`method_count` are preserved so the report still shows the underlying numbers,
but the actionable verdict no longer fires on zero fields.

Rationale: LCOM4 is genuinely undefined without fields; reporting `Cohesive`
(rather than a new `NotApplicable` variant) avoids changing the
`CohesionVerdict` enum and its many serialization/consumer sites (health
`low_cohesion_count`, smells), keeping the change contained while removing the
false positive. The summary `split_candidates` count drops by exactly the number
of fieldless types previously flagged.

## Blast radius

`cohesion` command for any language with fieldless method-bearing types (Rust
unit structs / trait impls, Go empty-struct method sets, Java/utility static
classes). `health.summary.low_cohesion_count` (derived from cohesion verdicts)
decreases accordingly. Field-bearing types are completely unaffected (the
`all_fields.is_empty()` branch is not taken for them). The `e0a4791` cohesion
determinism tests are unaffected (they assert ordering/counts for field-bearing
fixtures). A new test pins a fieldless Rust type → `Cohesive`.
