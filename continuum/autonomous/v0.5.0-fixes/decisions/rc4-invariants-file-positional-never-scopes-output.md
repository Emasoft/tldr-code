# RC4 — `invariants` FILE positional argument never scopes the reported functions

**Cluster:** invariants-specs (analysis[7]); commands: invariants (and the dead `specs --source` flag)
**Classification:** design-fork. NOT implemented in this closeout.
**File/fn:** `crates/tldr-cli/src/commands/contracts/invariants.rs` : `run_invariants` (~L448)

## Problem

`run_invariants` uses its FILE positional argument ONLY to pick the display
language:

```rust
let source_lang = detect_language(source_path).unwrap_or(Language::Python);
// ... observations come purely from collect_observations(test_path)
```

The `source_path` is never cross-referenced against the symbols actually defined
in that file. Reported functions = whatever function names appear in the test
assertions, grouped by name. As a result the output is IDENTICAL for any FILE
argument pointed at the same test corpus — the positional is decorative.

The CLI help text promises otherwise ("Source file containing functions to
analyze"), so this is a help-vs-behavior mismatch, not just a missing feature.

Separately, `specs` has NO positional FILE and its `--source` flag is declared
but DEAD — never read in `run_specs`.

### Reproduced (LIVE) — IDX 37
`csharp-newtonsoft-bson`: invoking `invariants` with `MathUtils.cs` vs
`BsonDataReader.cs` yields an IDENTICAL function list (`DeepEquals`/`Read`/...).
`MathUtils`' real functions (`IntLength`/`IntToHex`) are absent — proving the
FILE positional is ignored. (Same symptom class: IDX 45/49/59/79/103.)

## Attribution

PRE-EXISTING and *predates* the v0.5.0 campaign. At baseline `5635a77`,
`run_invariants` took `_source_path: &Path` with the comment "currently unused in
this simplified static analysis". Campaign commit `4a762e1` renamed
`_source_path -> source_path` and used it ONLY for `detect_language` (the T2
vocabulary fix). The scoping bug is therefore older than the campaign; the
campaign improved vocabulary, not scoping.

## Options

| Option | Scope | Risk | Effect |
|---|---|---|---|
| **A — make it work** | Parse the FILE with `extract_functions` + `extract_methods` to build the set of symbol names defined in that file, then FILTER `run_invariants`' reported functions to that set (emit empty when none are test-covered). | requires cross-file symbol resolution (reuses `tldr_core::ast::extractor`, already used by verify) | Matches the documented help and fixes IDX 37/45/49/59/79/103 attribution. `specs --source` should be wired with the same filter (or removed). |
| **B — make it honest** | If scoping is intentionally out of scope for the Daikon-lite design, DROP/rename the positional and document that invariants reports over ALL test-observed functions; emit a note. Remove the dead `specs --source`. | cheap | Admits reduced capability but removes the misleading help. |

## Blast radius

`run_invariants` is the core of `invariants` and is reused by verify's
invariants pathway. Filtering changes the function set for EVERY `invariants`
invocation that passes a FILE. `specs` has no positional but its dead `--source`
should be either wired (same symbol-set filter) or removed for consistency.
Symbol-set resolution reuses `tldr_core::ast::extractor` (already a verify
dependency), so no new crate coupling.

## Recommendation

**Recommend A** — the help text already promises file scoping, so A is the
behavior users expect, and the building block (`extractor::{extract_functions,
extract_methods}`) is already in the tree and used by verify. The reason it is
filed as a fork: A changes the reported function set for every FILE-scoped
`invariants` call (broad output churn) and must decide the `specs --source`
question in the same stroke; that re-baselining + cross-command contract
decision is a deliberate change, not a mechanical fix. If A is deferred, B
(honesty) should be applied so the help stops lying.

## Pointers
- `crates/tldr-cli/src/commands/contracts/invariants.rs`: `run_invariants`
  (~L448), `collect_observations`.
- Symbol resolution: `crates/tldr-core/src/ast/extractor.rs`
  `extract_functions` (~L592) + `extract_methods` (already used by verify).
- Dead flag: `specs --source` in the `specs` CLI definition / `run_specs`.
