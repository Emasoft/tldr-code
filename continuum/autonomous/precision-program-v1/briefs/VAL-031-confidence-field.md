# Worker Brief — VAL-031 (m3-honesty-layer): confidence + provenance + staleness on every edge

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype, TDD.
Calls-touching crates/ change → iron rule: **resolution behavior itself unchanged, parity gate 0 flips**.
The gate compares normalized (caller, callee, owner) tuples — NEW ADDITIVE JSON FIELDS do not disturb it,
but any change to WHICH edges exist does. Report `worker_done` to term_240a1ffa-8d57-44d0-a3f7-d48e784e4c48.

## Approved schema (user gate VAL-030, 2026-07-08)
Every resolved edge in `tldr calls --format json` output gains ADDITIVE fields:
- `confidence`: `"T1"` | `"T2"` (string; `"T0"` reserved for m7 harvest — do not emit yet)
- `provenance`: `{"rung": "<rung-id>", "mechanism": "<short-name>"}` — the RAW RUNG ID IS MANDATORY
  regardless of tier (user clause: consumers must see through the tier to the mechanism)
- `staleness`: `{"src_hash": "<sha256 of caller file content>", "generated_at": "<ISO date>"}`
Plus a first-class top-level `unresolved` array: `[{caller_file, caller_func, target, line, reason}]`
(the builder already collects `result.unresolved` + warnings — surface them, do not re-derive).
Schema-version: bump the JSON output's `schema` field (or add one if absent) e.g. `calls.v2`. Existing
field names/positions unchanged.

## Implementation shape (mechanism notes from orchestrator pre-read)
1. **Rung enum**: `ResolutionRung` in `language_policy.rs`-adjacent new module or `callgraph/rung.rs` —
   one variant per cascade mechanism. Derive the variant list by READING the resolver cascade:
   `resolve_call` (resolution.rs:745), `resolve_call_with_receiver`/`_enclosing` (1728/1759), and the
   builder-side paths (super-ctor at builder_v2.rs:301, type-aware resolver). Name variants by MECHANISM
   (e.g. TypeAwareReceiver, SelfReceiver, ModuleImportFull, ModuleImportSuffixAlias, ImportMapExact,
   ImportMapSuffixAlias, ReExportTrace, LocalQualified, CapitalizedReceiverGuess, ClassIndexFuzzyLocal,
   GlobalFuzzy, SuperCtor, CppOutOfLine, ColonReceiver...) — exact set = what the code actually has;
   every `return Some(ResolvedTarget...)` site gets tagged. If a site is genuinely shared by mechanisms,
   prefer the most specific caller-visible one.
2. **Thread it**: add `rung: ResolutionRung` to `ResolvedTarget` (additive struct field; update constructors).
   This touches many construction sites — mechanical, keep each tag honest to its site.
3. **Tier mapping**: ONE pure function `fn tier(rung) -> Confidence` living next to the enum:
   type-aware/scope/exact-import/self/super mechanisms → T1; name-guess mechanisms (capitalized-receiver,
   fuzzy local/global, suffix-alias fallbacks, arity-less bare matches) → T2. PROVISIONAL per user clause —
   put the mapping in ONE match so re-binning is a one-line diff. When genuinely unsure for a rung, choose
   T2 (honesty defaults down, never up).
4. **Emit**: JSON serialization site(s) for calls output (find the emitters in tldr-cli for calls; also the
   graph->JSON path in core if shared). `src_hash`: hash the CALLER file bytes (already read during build —
   reuse, don't re-read if avoidable); `generated_at`: date only is fine.
5. **Unresolved surfacing**: builder's `result.unresolved` + `warnings` → the `unresolved` array with
   `reason` (e.g. "dynamic-import", "no-candidate", "ambiguous-declined").

## OUT OF SCOPE (later assertions)
- NO behavior change to dead/impact/definition (VAL-032). NO --min-confidence flag (VAL-033).
- NO MCP changes (VAL-036). Do NOT re-bin any mechanism's actual resolution order.

## TDD (failing first)
(a) a resolved edge in calls JSON carries confidence+provenance.rung+staleness fields; (b) a T2 mechanism
(e.g. capitalized-receiver guess fixture) emits confidence=="T2" with its rung id; (c) an unresolvable call
appears in `unresolved` with a reason; (d) schema field == calls.v2. Full suites after:
`env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib` and `-p tldr-cli --lib`.

## HARD CONSTRAINTS
- Behavior-preserving on the edge SET: same edges, same owners, same order. The parity gate normalizes
  edges from JSON — if your field additions change its parse, that surfaces as gate noise: do NOT touch the
  fields the gate reads (src/dst names+files). Orchestrator runs canary+full gate.
- NO regex, NO clippy #[allow]. Leave UNCOMMITTED. `git diff --name-only` = intended files only (list them
  in your report; this change legitimately touches resolution.rs, builder_v2.rs, types/emitters + tests).
- If the emitters serve OTHER commands that share the edge JSON (context/impact), keep their output
  backward-compatible (additive fields fine) — note which commands share the path.

## WHEN DONE report worker_done with
(1) the full rung-variant list + its tier mapping table, (2) files changed, (3) test names RED→GREEN,
(4) full suite counts, (5) which other commands share the emit path, (6) confirmation edge SET unchanged
(same counts on a sample corpus run before/after if you can cheaply show it).
