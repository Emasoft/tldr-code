# Decision: `definition` column input/output index convention (the "off-by-one")

Cluster: [11] misc-tail. Command: `definition`. File:
`crates/tldr-cli/src/commands/remaining/definition.rs`. Classification in
`reaudit-rootcause.json` analysis[11]: listed `fixable-root-cause`, but the
fix_sketch itself flags a **convention conflict** that "needs a convention
decision before fixing to avoid divergence." After investigation this is a
**design-fork**: the safe resolution is to DOCUMENT the convention, not change
it.

## Reported symptom (reproduced LIVE, /tmp/defcol.rs)

```rust
1  fn greet(name: &str) -> String {
2      let msg = name;
3      format!("Hi {}", msg)
4  }
```

`tldr definition defcol.rs 2 14` (query the use of `name` on line 2 at 0-indexed
col 14) resolves the `name` PARAMETER and reports:

```json
"definition": { "file": "defcol.rs", "line": 1, "column": 10 }
```

`name` starts at 0-indexed column 9 in `fn greet(`. The reported column is 10 =
**1-indexed**. The audit framed this as "off-by-one" (reported at N+1).

## Investigation — it is NOT a simple off-by-one bug

Cross-checking the sibling commands:

- `tldr references name defcol.rs` reports `name` at **column 10** as well —
  i.e. `references` is ALSO 1-indexed on output.
- `tldr structure defcol.rs` and `references` were DELIBERATELY set to 1-indexed
  columns by `diff-column-one-indexed-v1` / `scala-column-unification-v1`.

So `definition`'s OUTPUT (1-indexed) is already CONSISTENT with the
`references`/`structure` family. There is no output bug.

The real asymmetry is INPUT vs OUTPUT within `definition`:
- INPUT column is 0-indexed (documented; tree-sitter point lookup is a 0-indexed
  byte offset — `find_symbol_at_position` / `resolve_local_scope` use `column`
  directly as the byte offset).
- OUTPUT column is 1-indexed (matches references/structure).

A user who feeds a resolved column straight back as a query column is therefore
off by one. That is the entire substance of the finding.

## Options

### Option A — make the OUTPUT 0-indexed (match the input)
REJECTED. `references` and `structure` are deliberately 1-indexed
(`diff-column-one-indexed-v1`). Changing `definition`'s output to 0-indexed would
make `definition` the lone 0-indexed-output command — a cross-command
inconsistency worse than the asymmetry it fixes, and it would break
`cross_lang_definition_column_v1` (asserts `column >= 1`).

### Option B — make the INPUT 1-indexed (match the output)
IMPLEMENTED then REVERTED after measuring the blast radius. Subtracting 1 from
the CLI column makes input and output both 1-indexed AND consistent with
references/structure — clean in principle. BUT a body of existing positional
callers/tests assume 0-indexed input, e.g. `sibling_resolver_gaps_v1`:
`tldr definition <lua> 44 1` deliberately queries column 1 to land INSIDE the
`function` keyword and asserts the resolver SKIPS it to the real symbol. Under
1-indexed input, col 1 → byte offset 0 (still inside the keyword, but the whole
test's column arithmetic shifts), silently changing what every positional query
resolves. This would require re-baselining every positional `definition` test
and would break any external script already passing 0-indexed columns. High
churn + external-contract break for a CLI input convention.

### Option C — keep both conventions, DOCUMENT the asymmetry (DECIDED)
Retain input 0-indexed / output 1-indexed (no behavior change), and make the
convention explicit in the `--column` help text so the asymmetry is intentional
and discoverable. This is consistent with the codebase's two existing
conventions (0-indexed positional input that mirrors tree-sitter; 1-indexed
output that mirrors human line/column reporting and the references/structure
family) and incurs zero churn / zero external-contract break.

## Decision

**Option C.** No behavior change. The `DefinitionArgs::column` doc comment now
states explicitly: input is 0-indexed (editor-cursor/byte-offset), reported
column is 1-indexed (matching `references`/`structure`), and the `line` argument
is 1-indexed. Rationale: the OUTPUT is already correct and cross-command
consistent; both ways of "fixing" the asymmetry introduce a worse divergence
(Option A breaks output consistency, Option B breaks input consistency with
existing 0-indexed positional callers/tests). Documenting the intentional
asymmetry is the only change that does not regress an existing contract.

## Blast radius

Doc-only. No code path changes; all `definition` unit tests (44) and the
positional integration tests (`sibling_resolver_gaps_v1`,
`cross_lang_definition_column_v1`) remain valid exactly as written.
