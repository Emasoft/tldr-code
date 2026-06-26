# Grammar Compatibility

This document records non-default tree-sitter grammar arrangements used by tldr,
so future upgrades do not silently regress.

## Pinned grammar versions

Workspace tree-sitter core: `tree-sitter = "=0.25.0"` (`Cargo.toml`). All grammar
parser tables must be ABI-compatible with this core. The supported parse-table
ABI (`LANGUAGE_VERSION`) for 0.25 is 13–15; tldr's grammars target **ABI 14**.

## Vendored fork: tree-sitter-kotlin-ng (assertion B-kotlin-grammar)

**Location:** `vendor/tree-sitter-kotlin-ng/` (in-tree path dependency).
**Upstream:** `tree-sitter-grammars/tree-sitter-kotlin`, crate `tree-sitter-kotlin-ng = 1.1.0`
(author Amaan Qureshi). Vendored copy keeps `version = "1.1.0"` so semver stays satisfied.

### Why vendored

Upstream 1.1.0 (and current master) omit `suspend` and its peer soft/modifier
keywords from the grammar's `_reserved_identifier` rule. As a result a Kotlin
call that uses such a keyword as a **named-argument name** — the real-world case
being coroutines code like:

```kotlin
acquire(
    waiter = waiter,
    suspend = { cont -> addAcquireToQueue(cont as Waiter) },  // `suspend` as arg NAME
)
```

fails to form a `value_argument`, drops the parser into error recovery, and a
downstream string-template (`$`/`${`) scanner then swallows the remainder of the
file into a single root `ERROR` node. Every Kotlin command (`structure`,
`extract`, `interface`, `calls`, `impact`, `slice`, `complexity`, …) walks the
parse tree, so all of them silently drop the classes/methods that fall inside the
`ERROR` (e.g. `SemaphoreImpl`, `SemaphoreSegment` in kotlinx-coroutines
`Semaphore.kt`). This cannot be fixed in tldr extractor logic: the declaration
nodes no longer exist under the `ERROR`. The fix belongs at the grammar layer.

A GitHub fork cannot be pushed from this environment, so the spec's
"fork-and-patch" is realized in-tree by vendoring the pinned crate and patching it
here.

### The patch

`vendor/tree-sitter-kotlin-ng/grammar.js`, rule `_reserved_identifier`: the
following modifier soft-keywords were **added** as identifier alternatives
(Kotlin spec `simpleIdentifier` admits them as identifiers outside modifier
position; the fwcd Kotlin grammar lineage already does this):

```
suspend, tailrec, infix, inline, external, reified, lateinit,
override, abstract, final, open, vararg, noinline, crossinline
```

The pre-existing members (`actual, annotation, constructor, const, data, enum,
expect, inner, get, set, operator, value`) are unchanged. `suspend` remains a
hard token in modifier position (`function_modifier` / `type_modifiers`); the
existing `prec.dynamic(1)` on `_reserved_identifier` plus the dedicated `*_modifier`
rules disambiguate — the same construction the grammar already uses for `data` /
`value` / `inner`.

Adding these spellings to `_reserved_identifier` introduced new LR conflicts that
were resolved by adding the following entries to the `conflicts` array (no
precedence hacks, no rule deletions):

```
[$.function_modifier, $.type_modifiers, $._reserved_identifier]
[$.type_modifiers, $._reserved_identifier]
[$.inheritance_modifier, $._reserved_identifier]
[$.member_modifier, $._reserved_identifier]
[$.parameter_modifier, $._reserved_identifier]
[$.parameter_modifiers]
```

### Regeneration / ABI

`src/parser.c` + `src/grammar.json` + `src/node-types.json` were regenerated with
the **tree-sitter CLI matching the workspace core (0.25.0)** to keep the emitted
`TSLanguage` struct layout binary-compatible with the `tree-sitter = 0.25.0` Rust
core:

```bash
cd vendor/tree-sitter-kotlin-ng
tree-sitter generate --abi 14 grammar.js   # CLI 0.25.0
```

`LANGUAGE_VERSION` stays **14**. Note: generating with a newer CLI (e.g. 0.26.x)
emits a `TSLanguage` struct with added/renamed fields that the 0.25 core
mis-reads, producing spurious recovery (`has_error`) bits at runtime even though
the visible tree is complete — so always regenerate this vendored grammar with a
0.25.x CLI until the workspace tree-sitter core is bumped.

The upstream crate's `[dev-dependencies] tree-sitter = "0.24"` was removed from
the vendored `Cargo.toml`: because this is an in-tree path dependency, Cargo
resolves its dev-dependencies into the workspace graph, which collides with the
pinned `tree-sitter =0.25.0` on the `links = "tree-sitter"` native library.
`tree-sitter` was only used by the crate's own `#[cfg(test)]`/doctest harness
(not run in the tldr pipeline); the library build needs only `tree-sitter-language`.

### Known pre-existing quirk (not introduced by this patch)

Under the 0.25 core, the upstream (registry =1.1.0) grammar already sets a
`has_error` recovery bit on some declaration shapes that nonetheless produce a
complete, correctly-typed tree — e.g. `abstract class C { open fun d() {} }`.
This is upstream behavior, verified identical before and after the patch, so
grammar regression tests assert by **node-kind presence / by-name recovery**,
never by `has_error == false` on such constructs.

### Tests

`crates/tldr-core/tests/grammar_stability_test.rs`:
`test_kotlin_suspend_named_arg_parses_clean`,
`test_kotlin_soft_keyword_named_args_ab_sentinels`,
`test_kotlin_modifier_position_still_parses`,
`test_kotlin_suspend_named_arg_whole_file_cascade_recovery`.

### Upstream

File a PR against `tree-sitter-grammars/tree-sitter-kotlin` adding the soft
keywords to `_reserved_identifier` (cite Kotlin-spec `simpleIdentifier` + fwcd
precedent + the `g(suspend = {})` minimal repro). Once released, this vendored
copy can be dropped and the dependency repointed to the registry.
