# RC2 — Lua/Luau `interface` ignores the module `return {...}` table (uses underscore convention)

**Cluster:** structure-extract (analysis[2]), root_cause #12
**Commands affected:** `interface` (Lua / Luau only)
**Classification:** design-fork (module-system semantics).

## Problem

`crates/tldr-cli/src/commands/patterns/interface.rs::is_node_public` / `is_public_for_lang` decides Lua/Luau visibility purely by the Python/Ruby underscore convention:

```rust
Language::Python | Language::Ruby | Language::Lua | Language::Luau => !name.starts_with('_')
```

But Lua has NO access modifiers and NO underscore convention. A Lua module's PUBLIC API is exactly the set of fields on the table it `return`s at end of file. Consequences (#117, luvit `querystring`):

- **Over-reports**: every non-underscore `local function` is listed as an export even when it is a private helper never placed on the return table (e.g. `charToHex` / `hexToChar`).
- **Under-reports**: real exports that are defined as table fields (`function M.foo() ... end`, or `M.bar = ...`) rather than standalone `local function` decls are missed (luvit `pathjoin` omitted 4 exports).

## Why it is a fork

There is no single canonical Lua module shape; `interface` would have to model the module system:

1. `return { a = a, b = b }` — terminal table-constructor literal. Need to read its fields AND resolve aliases (`a = a` -> the local `a`'s definition).
2. `local M = {}; function M.foo() end; ...; return M` — table built incrementally then returned (luvit MIXES both styles in one file).
3. Re-exports / `setmetatable` / conditional returns — long tail.

A correct implementation must parse the terminal `return` expression, classify it (table literal vs returned-identifier-accumulator), and union the field set. The current heuristic is wrong but cheap; the correct model is non-trivial and Lua-specific.

## Options

| Option | Scope | Risk | Notes |
|---|---|---|---|
| **Fork A — module-accurate** | `interface.rs` Lua visibility path (+ a return-table analyzer) | MED | Parse the terminal `return { ... }` table_constructor; set `all_exports` to exactly its fields (resolve `k = local` aliases to their defs). Handle `local M={}; ...; return M` by collecting `M.x = ...` / `function M.x()` assignments. Fall back to the current heuristic when no clear return-table exists. Lua-gated; no other-language impact. |
| **Fork B — document the heuristic** | docs only | NONE | Declare `interface` for Lua as "public-by-convention (non-`_` locals)" and accept the over/under-report. |
| Do nothing | — | — | Same as Fork B without the disclosure. |

## Recommendation

**Fork A, gated to files with a clear terminal return-table**, falling back to the current underscore heuristic otherwise. This is the only way to get Lua module semantics right and it is fully Lua-scoped (no blast radius to other languages). It needs both the `return {...}` literal path and the `local M = {}; ...; return M` accumulator path because luvit (the corpus repo) uses both. Defer if Lua interface accuracy is not on the v0.5.0 critical path; it is a self-contained follow-up.

## Pointers
- `crates/tldr-cli/src/commands/patterns/interface.rs`: `is_node_public` (L~313), `is_public_for_lang` (L~334) — the underscore-convention gate.
- Corpus: `/tmp/tldr_corpora_b/lua-luvit` (querystring.lua mixes `local function` helpers + a `return {...}`; other luvit modules use `local M={}; return M`).
