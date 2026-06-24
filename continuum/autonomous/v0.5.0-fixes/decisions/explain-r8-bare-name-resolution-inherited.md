# R8 — explain bare-name caller/callee FPs (INHERITED from references/impact)

**Cluster:** [8] explain (`reaudit-rootcause.json` analysis[8], root_cause R8).
**Classification:** `research-needed` → researched; **out of the explain cluster's editable scope** (the defect lives in shared `references.rs` / `impact.rs`, not `explain.rs`). Documented with the explain-scoped option and the cross-command home for the real fix. NOT implemented in the explain R7 wave.

## The bug (explain manifestation)

`tldr explain <file> <fn>` lists false-positive callers/callees that come from:
- same-named functions in OTHER files,
- stdlib homonyms (`Mutex.unlock` vs `Lwt_mutex.unlock`),
- local lambda/closure PARAMETERS named like the target (Kotlin `block`, Swift `perform`, Scala `push`),
- stdlib aliases (Lua `string.find` aliased to a local `find`, `mutable.Stack.pop`).

Affected explain bugs: #8, #9, #10, #11 (caller part), #16, #18, #21; #14's `app` is the call-graph variant (a local var promoted to a callee edge). Languages: ocaml, scala, lua, luau, rust, kotlin, swift — i.e. the languages NOT covered by the campaign's TS/JS/C++/Python receiver-keyed precision work.

## Why this is INHERITED, not explain-OWN

`explain` does not resolve these edges itself. It MERGES them from the shared resolvers:
- `enrich_with_project_graph` → `build_project_call_graph` + `impact_analysis_with_ast_fallback`
- `enrich_with_references` → `find_references`

The defect is in those shared functions:
- `crates/tldr-core/src/analysis/references.rs::find_references`
- `crates/tldr-core/src/analysis/impact.rs::impact_analysis_with_ast_fallback` (the "Discovered via references … call graph did not resolve this cross-file edge" fallback, ~L738) — it mints a caller whenever a textual call to the bare name exists, matched via `last_segment_eq_pub` (bare last-segment equality), WITHOUT resolving the call-site receiver's static type or excluding a same-named local binding/param.

**Proof of inheritance (audit, live):** `tldr impact unlock` and `tldr impact perform` independently emit the SAME false positives, with the provenance note "(call graph did not resolve this cross-file edge)". The truly-correct sibling is `tldr calls` (the raw graph), NOT `impact` — the audit's per-bug "impact is correct" note for #11 is mistaken (flagged in analysis[8].notes).

**Confirmed PRE-EXISTING:** `references.rs` was not touched in the campaign at all; `impact_analysis_with_ast_fallback` + the note existed at baseline 5635a77. The campaign's receiver-keyed precision (716bb08 TS/JS, 2670ca9 C++, 79b08e2 Python FuncIndex, CL-2/GH#40 in impact.rs) deliberately did NOT cover these languages.

The partial receiver-discrimination that DOES exist (impact.rs `extract_call_receiver` / `receiver_compatible` / `qualifier_of`, CL-2/GH#40) drops `json.decode` from `rpc.decode`'s callers and `Codec::decode` self-calls from `Parser::decode`, but only for the qualified-receiver shape and the languages whose receiver type it can infer. It has no notion of a caller-local lambda parameter or a closer same-named local definition shadowing the target — which is exactly the OCaml/Scala/Lua/Rust/Kotlin/Swift FP class here.

## Relationship to the already-written calls-graph fork

The **calls-graph half** of R8 (the `calls` resolver picking an arbitrary same-name survivor) is a separate cluster ([5] callgraph-resolution) and is already:
- partially fixed (bounded decline-with-prefer-non-test) in `fix-R7-callgraph-resolution-v1` (6100bcf), and
- documented as a design-fork in `decisions/callgraph-arbitrary-same-name-survivor.md`, whose **Option B (import/module-scope resolution)** is explicitly noted as *shared with the impact references-enrichment half* — i.e. the same infrastructure that would fix this explain manifestation.

That doc also explicitly states the references-enrichment half "live[s] in `crates/tldr-core/src/analysis/impact.rs` and [is] a different implementer's scope." So the explain cluster must not edit it.

## Options (for the cross-command owner)

1. **Scope-aware AST/references fallback (the principled fix, recall-preserving):** before attributing a bare-name call to a target, verify the call-site receiver/binding does NOT resolve to a LOCAL parameter, local `val`/`let`, or a closer same-named definition in the caller's own scope; and distinguish module-qualified homonyms by the qualifier path (`Mutex` vs `Lwt_mutex`), not just the last segment. This is Option B of the callgraph fork, built once in `impact.rs`/`references.rs` and reused by impact/references/whatbreaks/context/explain. Needs per-language scope/import plumbing + re-baselining the cross-lang caller suites.
2. **Extend receiver-type keying to the 6 uncovered languages.** Largest effort; per-language static-type inference for receivers (OCaml/Scala/Lua/Rust/Kotlin/Swift).
3. **explain-LOCAL mitigation (the only thing in THIS cluster's reach):** gate explain's references-enrichment (`enrich_with_references` / the impact-fallback merge) on a confidence/qualifier check so explain is **no LESS precise than `calls`** — e.g. accept an enriched caller/callee edge only when its qualifier matches the target's qualifier (reuse `explain_names_match`'s qualifier awareness, tightened to require qualifier equality when the target is qualified) OR when the raw `calls` graph already contains the edge. This would suppress the explain-surfaced FPs without touching shared code, at the cost of dropping the genuine cross-file C#/Kotlin/Scala callers the enrichment was *added* to recover (ux-and-explain-completeness-v1 P12.AGG12-1; Lua alias recovery P13.AGG13-12). That recall loss is why it is NOT applied as a drive-by: it needs the same FP-vs-recall measurement the cross-command fork demands, and doing it only in explain would make explain inconsistent with impact/references.

## Recommendation

Do NOT patch this inside the explain cluster. The correct fix is **Option 1 / callgraph-fork Option B**, owned by the references/impact implementer and shared with the calls resolver — build the import/module-scope (and local-binding-shadow) resolution once, then explain inherits the precision automatically (the same way explain already inherited the R7-wave-1 callgraph and complexity fixes). The explain-OWN defects (R1 path re-rooting, R2 `<external>` join, R3 Ruby params, R4 Elixir callee pollution) ARE fixed in this wave; R8 is the lone inherited, cross-command item and is tracked here + in `callgraph-arbitrary-same-name-survivor.md` (Option B).

## Blast radius (why explain must not unilaterally tighten)

`find_references` + `impact_analysis_with_ast_fallback` back `impact`, `references`, `whatbreaks`, `context`, AND explain's enrichment. Tightening risks regressing the C#/Kotlin/Scala caller-recovery the enrichment was built for and the Lua alias recovery, measured across `explain_callers_cross_lang_v1`, `sibling_resolver_gaps_v1`, and the `cross_command_consistency` suites. This is the genuinely hard, multi-command problem and the only R8 item not closable from a single cluster's file.
