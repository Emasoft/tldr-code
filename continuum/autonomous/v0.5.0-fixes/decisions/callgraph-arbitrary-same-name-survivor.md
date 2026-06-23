# Decision: arbitrary same-name survivor binding in the `calls` resolver (R5 / R8-calls)

Cluster: [5] callgraph-resolution. Fix task: fix-R7. File: `crates/tldr-core/src/callgraph/resolution.rs`.
Root causes in scope: **R5** (`calls` binds an arbitrary same-name survivor via `FuncIndex.get().first()` + `simple_module` fallback) and the **calls-graph half of R8** (name-only resolution of receiver calls). Both are classified `design-fork` in `reaudit-rootcause.json` analysis[5].classification.

The references-enrichment halves (R1, R2) live in `crates/tldr-core/src/analysis/impact.rs` and are a different implementer's scope; they are referenced here only where the calls-graph fix interacts with them.

## Problem

When the `calls` resolver cannot pin a callee to a single definition, it falls back to a name- or simple-module-keyed lookup that silently picks an arbitrary survivor:

- `FuncIndex::get(module, name)` returns `Vec::first()` (types.rs:543). When a single `(module, name)` key holds entries from MORE THAN ONE distinct file, `.first()` is order-dependent garbage.
- The `simple_module` / `bare_module` fallbacks in `resolve_call` (Direct arm, resolution.rs ~L700/L711) and `resolve_module_import_receiver` (~L1550) collapse distinct files that share a final module segment, then call plain `get()` → `.first()`.
- For OCaml, `resolve_ocaml_module_receiver` (~L1686) maps the receiver `Module` to a lowercased file-module key and calls `get()` → `.first()`.

Reproduced LIVE (`tldr calls`, TLDR_NO_DAEMON=1, /tmp/tldr_corpora_b):

| Bug | Repro | Mechanism |
|-----|-------|-----------|
| #132 ocaml-dune | 2317 edges whose `dst_file` is under `test/`; e.g. `bench.ml::go -> .../path_tests.ml::Path.relative` | `Module.func` binds to a nested `module Module` in a test file, OR to one of several `path.ml` files sharing simple-module `path`. |
| #140 ocaml-lwt | 262 `calls` edges into `test/` files | same simple-module collision (`create`, `List.*`). |
| #205 scala-cats-effect | `ArrayStackBenchmark.push -> core/js/.../ArrayStack.scala` (should be jvm-native) | two `ArrayStack.scala` (js, jvm-native) share the FULL module key `cats.effect.ArrayStack`; `.first()` picks js. |
| #195 rust-clap | `complex.rs::<module> -> tests/derive/issues.rs::Args` | `Args` defined in many files; class/name lookup picks a test file. |
| #81 java-retrofit | rxjava `ObservableTest.body -> rxjava3/.../ObservableTest.java` | class name `ObservableTest` defined in many Gradle modules; `ClassIndex` (single-valued) keeps one. |

Two distinct sub-problems hide here:

1. **FuncIndex same-key, multi-file collision** — the `.first()` pick. (OCaml `path.ml` x2, scala `ArrayStack.scala` x2.) Tractable inside resolution.rs.
2. **Class-name collision across packages/modules** — `ClassIndex` is `HashMap<String, ClassEntry>`, single-valued, so two files defining `class Foo` keep one arbitrarily. (java `ObservableTest`, scala/rust class names.) Disambiguating this *correctly* needs per-language import/package/sourceset scope that the resolver does not currently have.

## What is unambiguously fixable (implemented in this task)

The explicit guidance: *"prefer same-file/same-module over a test file; mark genuinely-ambiguous as unresolved rather than picking arbitrarily."*

Implemented (see fix-R7-callgraph-resolution-v1):

- A single disambiguation helper that replaces the bare `.first()` at the cross-file fallback sites. Given the candidate entries under a key, it:
  1. prefers an entry in the **same file as the caller** (a real intra binding),
  2. else, if exactly **one** candidate file is a **non-test** path, picks it (this is the "prefer over a test file" rule),
  3. else **declines** (returns `None`) — genuinely ambiguous, emit no edge rather than an arbitrary one.
- For OCaml, the file-module resolution (`resolve_ocaml_module_receiver`, now disambiguated) runs BEFORE the generic class resolver, because in OCaml `Module.func` canonically denotes the file `module.ml`; a nested `module Module` buried in another (often test) file is the exception, not the rule. This kills the `bench.ml -> path_tests.ml::Path.relative` class binding.

This is AST-agnostic post-processing over already-extracted index entries (no regex/string-structure heuristics; the "test path" classification is a path-segment check, not a structural parse).

Net effect on the reproductions (measured LIVE, before -> after):
- ocaml-dune test-dst edges: 2317 -> 1682 (635 wrong edges removed), total 27136 -> 26930; the `bench.ml -> path_tests.ml::Path.relative` shadowing is fixed.
- ocaml-lwt and the JS/Python/Go/TS corpora lose ZERO legit edges (single-candidate keys unchanged): js-express 332e/260n and python-flask 1249e/1289n are byte-for-byte identical; ocaml-lwt 3253 edges unchanged with 0 lost.
- VERIFIED LIMITATION: scala-cats-effect (`ArrayStackBenchmark.push -> js ArrayStack`, #205) and rust-clap (`complex.rs -> tests/.../Args`, #195) are UNCHANGED (totals 3406 and 6501 identical before/after). These resolve through `ClassIndex` (a single-valued `HashMap<class_name, ClassEntry>` that keeps an arbitrary survivor at INSERT time, before resolution runs), NOT through the FuncIndex fallback sites this fix touches. They are class-name-across-modules collisions deferred to Option B below — the FuncIndex disambiguation cannot reach them.

### What was tried and REVERTED (recorded for the follow-up)

An additional, more aggressive OCaml variant was implemented and then **reverted after LIVE measurement**: making OCaml `Module.func` strictly file-scoped — resolve only (a) caller's-file nested module, (b) sibling file-module, (c) `open`/import, else DECLINE (skip the generic class resolver entirely). It killed more wrong edges (ocaml-dune test-dst 2317 -> 1332, e.g. the `List.fold_left` stdlib captures) BUT it also dropped 9 *legitimate* edges in ocaml-lwt — `test_lwt_direct.ml -> src/direct/lwt_direct.ml::Storage.get/new_key/remove` (a real `open`-reachable cross-file nested module) and 2 `.cppo.ml` file-module-naming-bug edges. That is collateral breakage of edges that previously worked, so it is the wrong trade for a closeout patch. The reason it cannot be done safely without scope: distinguishing a *legit* `open Lwt_direct; Storage.get` (cross-file nested module reachable via `open`) from a *bogus* `module List` in a test file capturing a stdlib `List.fold_left` requires the caller file's resolved `open`/import set — i.e. Option B. The `List.fold_left`-class stdlib captures therefore remain and are deferred to Option B below.

## What is deferred (the design-fork)

The following require infrastructure the resolver lacks and trade recall for precision in ways that need a product call:

### Option A — decline-on-ambiguity everywhere (precision-first)
Route ALL same-name fallbacks (including `ClassIndex` collisions) through the decline gate. Eliminates every wrong edge but drops real edges for any monorepo with same-named functions/classes across modules (Scala cross-build, Java multi-module, Rust `Args`-in-8-files). Highest precision, lowest recall. This task implements a *bounded* form of A (only at the FuncIndex fallback sites, with the prefer-non-test tiebreak) — full A would also gate ClassIndex.

### Option B — import/module-scope resolution (precision + recall)
Use the caller file's resolved imports / open-modules to pick the in-scope definition among same-name candidates:
- OCaml: the `open` list is already parsed; map it + the file's own library to the candidate set.
- Rust: `use` paths.
- Java/Kotlin/Scala: package + Gradle/sbt sourceset/module mapping (NOT currently modeled).
Best quality, but needs per-language module-scope plumbing and a place to store sourceset membership. Shared with R2 Option A (impact references enrichment) — build once, use in both.

### Option C — platform/sourceset dimension for cross-compiled repos
For Scala.js / Scala Native / JVM (and similar), treat `js` / `jvm-native` / `native` variants as a resolution dimension keyed by the caller's sourceset, so `ArrayStackBenchmark` (JVM) binds to the jvm-native `ArrayStack`. A special case of B.

## Recommendation

1. **Now (done):** the bounded decline-with-prefer-non-test fix at the FuncIndex fallback sites + OCaml file-module-before-class ordering. Safe, contained to resolution.rs, matches the "decline on ambiguity / prefer over test" mandate, and leaves single-candidate and single-non-test resolution untouched (so JS/Python/Go/etc. are unaffected — verified: js-express and python-flask edge counts unchanged).
2. **Next (B, fork):** import/module-scope resolution, shared between the calls resolver and the impact references enrichment (R2). This is the principled recall-preserving fix and the right home for the Java/Scala/Rust class-name-across-modules cases (#81, #195) and the platform case (#205, Option C). It needs sourceset/package-scope infrastructure and a re-baseline of `callgraph_resolution_stats` and the cross-lang calls tests, so it is a deliberate follow-up rather than a closeout patch.

## Blast radius

`resolve_call` feeds `impact`, `whatbreaks`, `coupling`, `hubs`, `deps`, `dead`, `context`, `explain` across ALL languages. The bounded fix only changes behavior on a *multi-file collision under one key* — single-candidate and single-non-test lookups are byte-for-byte unchanged, so languages whose module keys are file-unique (TS/JS `./path`, Python dotted paths, Go dir paths, Rust `crate::` paths) see no edge-count change. Verified before/after: js-express 332 edges / 260 nodes and python-flask 1249 edges / 1289 nodes are identical post-fix.
