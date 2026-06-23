# RC2 META — three divergent extraction paths (interface vs extract vs structure)

**Cluster:** structure-extract (analysis[2]), root_cause #0 (the meta-cause) + the META design-fork entry
**Commands affected:** `structure`, `extract`, `interface`, and every command that consumes them (`health`, `debt`, `smells`, `halstead`, `dead`, `diff`, `impact`, `explain`, `context`)
**Classification:** design-fork (strategic refactor). The per-bug point-fixes for this cluster WERE shipped in fix-R7 (Fork B); Fork A (unification) is the durable direction and is recorded here.

## Problem — the root of the whole cluster

There is NO shared entity model. The same construct is extracted THREE different ways:

1. **`interface`** — its OWN AST walk in `crates/tldr-cli/src/commands/patterns/interface.rs` (`deep_collect` -> `extract_class_info` / `collect_methods_from_body`, with per-language `function_node_kinds` / `method_node_kinds` / `class_node_kinds` tables and its own `get_node_name` / `extract_base_classes` / `extract_function_signature`).
2. **`extract`** — `crates/tldr-core/src/ast/extract.rs` `ModuleInfo` (`extract_<lang>_functions_detailed` / `extract_<lang>_classes_detailed` / `extract_<lang>_params` / per-language base/visibility helpers).
3. **`structure`** — `crates/tldr-core/src/ast/extractor.rs` `CodeStructure` (`extract_<lang>_functions` / `extract_<lang>_classes`, PLUS a generic `extract_definitions` -> `classify_definition_node` / `get_definition_node_name`; `method_infos` is DERIVED from `definitions` filtered by `kind=="method"`).

Each path re-implements per-language node-kind lists and name / param / visibility / base logic, and they have DRIFTED APART. Almost every bug in this cluster is a direct symptom — "command X is right, command Y is wrong" for the same file:

| Bug | Divergence |
|---|---|
| #57 | `interface` lists Elixir macros; `structure`/`extract` dropped them |
| #131/#134 | OCaml: `extract` and `structure` had OPPOSITE errors (too-strict vs too-loose) |
| #207 | `extract` includes Scala abstract defs; `interface` dropped them |
| #247/#254 | `structure` de-conflates TS interfaces/type-aliases; `extract`/`interface` lump them |
| #5/#53 | `extract` param logic diverges from `structure` arity |
| #38/#153 | `interface` base resolver wrong/missing where the `inheritance`/`extract` resolver is correct |

The fix-R7 point-fixes repeatedly had to copy a proven implementation from one path into another (e.g. the Elixir defmacro+guard `get_node_name` logic from `interface.rs` into `extractor.rs`; the C body-check from `extract_c_structs` into both `deep_collect` and `extract_cpp_classes`; sharing the C#/PHP/Kotlin/Swift base extractors from `extract.rs` into `interface.rs`). Every such copy is evidence of the meta-cause and a place the paths can re-drift.

## Options

| Option | Scope | Risk | Notes |
|---|---|---|---|
| **Fork A — unify** | one canonical per-language entity extractor (functions / classes / methods / params / bases / visibility / signature) that all three commands PROJECT from | HIGH | The durable fix. Eliminates the entire "cmd X right, Y wrong" bug class (this cluster alone had ~10). Touches all 3 files + every consumer; needs the FULL corpus regression. Would have prevented #51/#53/#57/#131/#134/#207/#243/#247/#254. |
| **Fork B — per-bug point-fixes** | each divergence fixed individually | LOW per change | SHIPPED in fix-R7 (see commit list). Lower risk per change but leaves the three paths able to re-drift. |
| Hybrid | unify ONE axis at a time (e.g. a shared `BaseResolver`, then a shared `ParamExtractor`) behind the existing call sites | MED | Incremental path toward Fork A; each shared component is independently testable and lands the dedup without a big-bang schema change. The fix-R7 base-resolver sharing (making `extract_{csharp,php,kotlin,swift}_bases` `pub` and calling them from `interface.rs`) is the first hybrid step already taken. |

## Recommendation

**Fork B now (done) + Hybrid next, trending to Fork A.** Ship the per-bug fixes for v0.5.0 (complete). For the next dedicated refactor cycle (NOT a closeout pass), extract ONE shared component at a time — start with the base-resolver (already half-shared) and the param/visibility resolvers — so the three commands converge on a single entity model without a single high-risk big-bang change. Track Fork A as the end state.

Concrete first hybrid steps proven safe in fix-R7:
- Base resolver: `extract.rs::extract_{csharp,php,kotlin,swift}_bases` are now `pub` and reused by `interface.rs::extract_base_classes`. Extend this to ALL languages (Java/Scala/Rust/Python already have correct in-path arms — fold them into the shared resolver).
- OCaml function-shape predicate: `ocaml_binding_has_params` (extract.rs) and `ocaml_value_definition_is_function` (extractor.rs) now encode the SAME rule (params OR `function_expression`/`fun_expression` body). Collapse to one shared predicate.

## Pointers
- `crates/tldr-cli/src/commands/patterns/interface.rs`: `deep_collect`, `function_node_kinds`/`method_node_kinds`/`class_node_kinds`, `get_node_name`, `extract_base_classes`, `extract_function_signature`.
- `crates/tldr-core/src/ast/extract.rs`: `extract_<lang>_*_detailed`, the now-`pub` base extractors, `ocaml_binding_has_params`.
- `crates/tldr-core/src/ast/extractor.rs`: `classify_definition_node`, `get_definition_node_name`, `extract_definitions` (the `method_infos`-from-`definitions` derivation), `ocaml_value_definition_is_function`.
