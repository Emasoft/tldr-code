# Research note: `slice`/`chop` drop the cross-variable dependency through a Rust `match`-arm RHS

Cluster: [11] misc-tail. Commands: `slice`, `chop` (and transitively
`reaching-defs`, `taint`, `dead-stores`). File:
`crates/tldr-core/src/dfg/extractor.rs` (no Rust `match_expression` modeling) +
`crates/tldr-core/src/pdg/slice.rs` (per-variable line-anchored edge model).
Classification in `reaudit-rootcause.json` analysis[11]: **research-needed**.
Status: **RESEARCHED — DEFERRED (not a closeout fix).**

## Symptom (reproduced LIVE, /tmp/match_chop.rs)

```rust
1  fn parse_human_readable_size(s: &str) -> u64 {
2      let digits = "100";
3      let value: u64 = digits.parse().unwrap();
4      let bytes = match s {
5          "KB" => value.checked_mul(1024).unwrap(),
6          "MB" => value.checked_mul(1024 * 1024).unwrap(),
7          _ => value,
8      };
9      bytes
10 }
```

- `tldr slice … 9` (slice of `bytes`) → `[1, 2, 4, 9]` — **omits line 3**, the
  sole definition of `value`, even though `bytes` is computed FROM `value`.
- `tldr chop … 3 10` (does `value`@3 reach `bytes`@10?) → `path_exists: false`,
  "The source line does not affect the target line." It plainly does.

Matches the audit reproduction on `human.rs::parse_human_readable_size`.

## Root cause (VERIFIED by code read)

Two layers combine:

1. **No Rust `match_expression` modeling in the DFG extractor.** The
   `extract_refs_from_node` dispatch has arms for `let_declaration`,
   `assignment_expression`, loops, closures, etc., but NONE for
   `match_expression`/`match_arm` (the `"match"` strings at extractor.rs:6164+
   are branch-COUNT entries for cyclomatic/cognitive complexity, not DFG edges).
   So a `match` RHS is walked only by the generic fall-through recursion.

2. **The DFG edge model is per-variable and line-anchored.** `process_rust_let`
   (extractor.rs:2987) records the pattern (`bytes`) as a `Definition` at the
   `let` line (4) and recurses the `value` field; the RHS reads of `value` are
   recorded as `Use`s at THEIR lines (5–7). The PDG (pdg/slice.rs) then builds
   data edges between defs and uses OF THE SAME variable. There is no edge that
   says "the def of `bytes`@4 depends on the use of `value`@5–7" — that is a
   CROSS-variable, intra-statement link the model cannot express. So the
   `value → bytes` data dependency is simply absent, and the backward slice of
   `bytes` never reaches `value`'s def.

This is NOT Rust-specific in essence: any multi-line RHS whose def-line differs
from the lines of the variables it reads has the same gap (it just surfaces most
visibly with `match`, which spreads the RHS across several lines).

## Attribution

PRE-EXISTING. No Rust `match_expression` handling existed at baseline `5635a77`
either; the campaign's `abb790b` (B4) added subscript-LHS + Go/C/Lua for-loop
DFG coverage but never touched Rust match modeling or the edge-granularity
contract.

## Options considered

### Option (a) — anchor a multi-line RHS def's reads to the def line
When processing `let bytes = <RHS>`, re-tag every `Use` collected inside `<RHS>`
to the `bytes` def line, so the existing same-line def↔use heuristics chain
`value`(now@4) → `bytes`(@4). Smaller code change, BUT it MOVES the reported line
of every RHS read for every `let`/assignment in the language. That silently
changes `reaching-defs`/`dead-stores`/`taint`/`slice` line attributions for ALL
multi-line RHS in Rust (and, applied consistently, every language), breaking the
many golden line-set tests and — worse — degrading the precision of constructs
that legitimately rely on the read's true line (loop-carried reads, nested
blocks). It trades one false negative for a class of attribution drift.

### Option (b) — statement-level def→use dependence (the principled fix)
Add an explicit intra-statement edge: when a statement DEFINES variable B and
READS variables {A…} within the same RHS subtree, record `def(B) depends_on
use(A)` regardless of line. This is the correct model and also fixes the general
multi-line-RHS class. BUT it changes the core DFG/PDG contract from
per-variable/line-granularity to statement/node-granularity, which ripples into
EVERY consumer (`slice`, `chop`, `reaching-defs`, `taint`, `dead-stores`) for
EVERY language, and requires re-baselining the entire slice/chop golden corpus.

## Why DEFERRED (not done in this closeout)

The constitution mandates PRESERVE-other-langs and ROOT-CAUSE-not-symptom.
- Option (a) is a symptom patch with broad attribution side effects (violates
  "no weakening / no drift" — it would shift line numbers other tests pin).
- Option (b) is the root-cause fix but is, by the audit's own classification, a
  core-contract change with very high blast radius that "needs a design pass on
  whether to keep line-granularity or move to node/statement granularity" and
  should be "investigated behind a flag first."

Neither is a safe v0.5.0 CLOSEOUT change: both require re-baselining the DFG/PDG
golden suites and a deliberate granularity decision that affects all 16
languages. Shipping either hastily risks regressing the slice/chop/taint
behavior the campaign already stabilized for Go/C/Kotlin/etc.

## Recommendation

Schedule Option (b) as a dedicated, flagged work item:
1. Introduce a statement-level def→use edge in the DFG behind a feature flag.
2. Re-baseline slice/chop/reaching-defs/taint/dead-stores golden tests across
   all languages.
3. Validate no precision regression on the existing loop-carried / nested-block
   fixtures (the cases line-granularity currently gets right).
4. Flip the flag once the corpus is green.

The Kotlin for-loop gap (RC4, same cluster) and the slice data/control fixpoint
(also flagged in analysis[11]) are independent and were handled separately; this
note covers ONLY the cross-variable multi-line-RHS / Rust-match dependency.
