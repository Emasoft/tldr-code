# RC5 — function-under-test (FUT) attribution has no builtin/source-membership filter; picks the first/outermost call

**Cluster:** invariants-specs (analysis[7]); commands: specs + invariants (the latter reuses `run_specs` via `collect_generic_observations`)
**Classification:** design-fork. NOT implemented in this closeout.
**File/fn:** `crates/tldr-cli/src/commands/contracts/specs.rs` : `generic_extract_call_info` (~L4138) + `first_callable_inside` (~L4290); Python path `crates/.../invariants.rs : extract_observation_from_call`

## Problem

FUT attribution grabs the tail identifier of the first/outermost call inside an
assertion, with the ONLY exclusion being `vocab.is_known_callee`
(assertion-helper names) plus a Rust enum-ctor reject. There is:
- no per-language BUILTIN/stdlib set,
- no "is this symbol defined in the project" gate,
- no dynamic-dispatch unwrap,
- no receiver preservation.

So language builtins, framework DSL methods, dynamic-dispatch wrappers, and
fixtures are reported as functions-under-test.

### Reproduced (LIVE) — representative leaks
- **Elixir** (IDX 60/68 family): `byte_size`/`length`/`is_binary` reported as FUTs.
- **Go** (IDX 68 `go-httprouter`): FUTs = `HasPrefix`/`MatchString`/`Short`/
  `Sprint` (4/5 are stdlib if-guard calls); the real `CleanPath` is absent.
- **PHP** (IDX 152 `php-guzzle`): `\strlen`/`\array_keys` as FUTs.
- **Python**: `Exception`/`frozenset`/`httpbin`/`repr`/`keys`.
- **Ruby**: `__send__` reported instead of resolving `__send__(:snake_case)` to
  `snake_case`.
- **Lua**: `e.A()` -> `A` (receiver `e` lost).
- **Java**: `flashAttr`/`post`/`get` (MockMvc DSL).
- **Scala/Kotlin**: `_2F`/`IO`; range-cast fragments.

## Attribution

PRE-EXISTING. At baseline `5635a77`, `classify_assertion_call`'s
FUT-selection had the identical first/outermost pick and the only filter was
`is_known_assertion_callee` (baseline comment: "the Python-only filter list of
builtins is dropped here"). Campaign `930b831` refactored the two drifted global
lists into per-language `AssertionVocab` (a drift fix) and ADDED narrow
suppression (Go comparison helpers `59ba844`, Rust enum ctors `4a762e1`) but
PRESERVED the no-builtin/no-source-membership behavior. So the campaign improved
vocabulary/drift, not the architectural attribution gap.

## Options

| Option | Scope | Risk | Effect |
|---|---|---|---|
| **A — source-membership gate (strongest)** | Resolve FUT names against the project's defined functions/methods (extractor over the source tree) and DROP names not defined in-project (kills `byte_size`/`strlen`/`Exception`/`frozenset`/`HasPrefix`). | requires passing a project symbol index into the specs walk — changes the `specs` CLI contract (today it takes only a test path) | Most correct. High blast: every spec/invariant attribution across the corpus shifts; broad golden re-baselining. |
| **B — per-language builtin denylist** | Add an `AssertionVocab.builtins` set per language and skip them as FUTs. | cheaper, no project scan | Localized, but incomplete (can't catch user fixtures or unknown stdlib). |
| **C — better SUT selection** | Prefer the call that is NOT a stdlib comparison/length wrapper; PRESERVE receivers (`e.A` -> resolve via receiver); UNWRAP dynamic dispatch (`__send__(:m,...)` -> `m`). | localized | Fixes receiver-loss + dynamic-dispatch + stdlib-wrapper cases without a project index. |

## Blast radius

`generic_extract_call_info` / `first_callable_inside` + the Python
`extract_observation_from_call` feed BOTH `specs` and `invariants` (the latter
through `collect_generic_observations`) for ALL languages. A source index changes
the `specs` CLI contract (needs a source path). HIGH blast radius — every
spec/invariant attribution across the corpus shifts; the
`c3da2dd`/`5faa791` characterization tests pin current behavior and would change.
This is also the architectural ROOT shared with RC4/RC7: the miners have no link
to the project symbol table.

## Recommendation

**Recommend A + C combined behind the existing walk, with B as the fallback when
no index is available.** A delivers correctness (only real project symbols are
FUTs), C handles the cases A can't (receiver/dynamic-dispatch resolution and
stdlib-wrapper avoidance even within in-project calls), and B is a cheap safety
net for invocations where the caller cannot supply a project index.

Filed as a fork (not a closeout fix) because:
1. A changes the `specs` command contract (test-path-only -> needs a project
   symbol index), the single largest API/behavior change in the cluster.
2. It re-baselines essentially every spec/invariant golden across the corpus.
3. The A/B/C combination is a design decision about how `specs`/`invariants`
   couple to the project symbol table — the same architectural gap behind RC4
   and (partly) RC7. It should be designed once, coherently, rather than patched
   per-symptom.

NOTE: RC6 (bare-`assert(x==y)` equality destructuring) is the *fixable* sibling
of this RC — it improves WHICH expression is mined, but the extracted FUT still
passes through this same unfiltered name picker, so RC6 alone does not resolve
RC5.

## Pointers
- `crates/tldr-cli/src/commands/contracts/specs.rs`: `generic_extract_call_info`
  (~L4138), `first_callable_inside` (~L4290), `classify_assertion_call`,
  `AssertionVocab` (per-language tables; Option B target).
- Python path: `crates/tldr-cli/src/commands/contracts/invariants.rs`
  `extract_observation_from_call`, `collect_generic_observations`.
- Project symbol index (Option A): `crates/tldr-core/src/ast/extractor.rs`
  `extract_functions` + `extract_methods`.
