# RC2 — TypeScript interface / type-alias lumped into `classes[]` (carrier-with-kind design leak)

**Cluster:** structure-extract (analysis[2]), root_cause #9
**Commands affected:** `extract`, `interface` (TS / JS, `.ts` / `.d.ts`); `structure` is already correct (reference)
**Classification:** design-fork (schema vs consumer trade-off). The SIBLING ambient-function drop (root_cause #10, #254's 9 dropped `export function`) WAS implemented in fix-R7 because the reaudit said to do it "EITHER WAY" and it is low-risk — see `fix-R7-cl2-ts-ambient-fn-v1` in `crates/tldr-core/src/ast/extract.rs::extract_ts_functions_detailed`. The class-lumping itself remains a fork.

## Problem

`extract_ts_classes_detailed` (`crates/tldr-core/src/ast/extract.rs`, ~L2818) pushes THREE distinct node kinds into one `classes: Vec<ClassInfo>` carrier:

```
class_declaration       -> ClassInfo { kind: Some("class"), .. }
interface_declaration   -> ClassInfo { kind: Some("interface"), .. }
type_alias_declaration  -> ClassInfo { kind: Some("type"), .. }
```

It is an intentional "polymorphic carrier tagged later via `kind`": the downstream surface/typescript kind-tagging pipeline reads `classes[]` and refines each entry's reported kind. The leak is at the USER-FACING layer:

- `tldr extract` / `tldr interface` report the raw `classes.len()` as the class count, so axios `index.d.ts` shows **73 "classes"** (interfaces + type aliases + classes all summed) where `structure` — which de-conflates by node kind — shows the true class set (#254, #247).
- For the `interface` command specifically, NON-exported file-local interfaces also surface as `all_exports` because there is no export-keyword filter (#243: nest scanner.ts lists 2 non-exported interfaces).

`structure` (extractor.rs `classify_definition_node` + entry-kind switch) already separates `class` / `interface` / `type` into distinct kinds and is the correct reference.

## Why it is a fork (not a clean point-fix)

The `classes[]` carrier is consumed in two incompatible ways:
1. The surface/typescript kind-tagging pipeline RELIES on interfaces + type-aliases being reachable through `classes[]` to tag them. Removing them from `classes[]` (Fork A) changes the `ModuleInfo` schema and breaks that consumer unless it is migrated to read new arrays.
2. User-facing commands want `classes` to mean "classes".

You cannot satisfy both without either a schema change (Fork A) or a presentation-only filter (Fork B).

## Options

| Option | Scope | Risk | Notes |
|---|---|---|---|
| **Fork A — de-conflate the schema** | `extract_ts_classes_detailed` + `ModuleInfo` + every consumer of `classes[]` (surface kind-tagging, `extract`/`interface` projection) | HIGH | Most correct: add `interfaces: Vec<..>` / `type_aliases: Vec<..>` (or a typed `kind` the consumers switch on) so `classes` is classes only. Matches `structure`. Must migrate the surface/typescript pipeline that currently mines `classes[]`. Re-baselines TS goldens. |
| **Fork B — presentation filter** | `extract`/`interface` output projection only | LOW–MED | Keep the carrier; when emitting the user-facing `classes` count/list, filter to `kind == "class"`, and surface interfaces/type-aliases under their own output keys. For `interface`, additionally filter to `export`ed declarations (fixes #243). Leaves the internal carrier inflated but the SCHEMA unchanged. |
| Do nothing | — | — | `extract`/`interface` keep over-counting TS classes; diverges from `structure`. |

## Recommendation

**Fork B now** (low blast radius, fixes the user-visible over-count and the #243 non-exported-export leak without disturbing the surface kind-tagging pipeline), and track **Fork A** as the durable schema fix to be scheduled with a full TS golden re-baseline — ideally folded into the META 3-path unification (see `rc2-meta-three-extraction-paths.md`), since that refactor would give TS a single entity model with proper kind separation and make Fork A fall out for free.

The ambient-function half (#254 functions=0) is ALREADY FIXED (a `function_signature` top-level arm) and is independent of whichever fork is chosen.

## Pointers
- `crates/tldr-core/src/ast/extract.rs`: `extract_ts_classes_detailed` (carrier), `extract_ts_functions_detailed` (the shipped `function_signature` fix).
- `crates/tldr-core/src/ast/extractor.rs`: `classify_definition_node` + entry-kind switch — the correct `structure` de-conflation to mirror.
- surface/typescript kind-tagging pipeline: the consumer that reads `classes[]` and must be migrated for Fork A.
