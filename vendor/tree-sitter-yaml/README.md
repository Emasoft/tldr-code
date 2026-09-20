# tree-sitter-yaml (vendored, int32-row patched)

Vendored fork of [`tree-sitter-yaml` 0.7.0]
(https://crates.io/crates/tree-sitter-yaml) from
[tree-sitter-grammars/tree-sitter-yaml](https://github.com/tree-sitter-grammars/tree-sitter-yaml)
(MIT), used by tldr-code as a workspace path dependency.

## Why vendored

Upstream's external scanner (`src/scanner.c`) tracks the current source row in
**`int16_t`** fields (`row`, `cur_row`, …). `cur_row` is incremented on every
newline and the scanner's block-structure decisions hang on
`bool has_nwl = scanner->cur_row > scanner->row`. Once a source reaches
**row 32768 (0-indexed) = 2^15**, the increment overflows negative, `has_nwl`
flips false, and the parser's error recovery swallows the ENTIRE remaining
input into one root `ERROR` node — every `.yaml` past 32,768 lines parsed to
garbage (measured in tldr-code 2026-03: a 241,351-byte / 32,768-line stream
parses clean, 32,769 lines aborts; a single mapping aborts at exactly 32,768
keys — the trigger is the LINE index, not bytes or node count).

- Upstream issue: <https://github.com/tree-sitter-grammars/tree-sitter-yaml/issues/49> (open)
- No fixed fork on crates.io (verified 2026-09: 0.7.2 still declares
  `int16_t row/cur_row`; the `treease-ts-yaml`/`arborium-yaml` forks too)

## The patch (31 lines, all in `src/scanner.c`)

1. The 9 scalar row/col fields of `Scanner` (`row`, `col`, `blk_imp_row`,
   `blk_imp_col`, `blk_imp_tab`, and the temps `end_row`, `end_col`,
   `cur_row`, `cur_col`) widened `int16_t` → `int32_t`.
2. `serialize()` / `deserialize()` widened to match: the 5 persisted scalar
   fields move from 10 to 20 bytes. The 1024-byte
   `TREE_SITTER_SERIALIZATION_BUFFER_SIZE` still leaves slack for ~251
   indent-stack entries (was ~253) — ample. Serialized state never crosses
   crate versions (it exists only inside one parser's incremental reparse).
3. The `bgn_row`/`bgn_col` locals in the scan function widened to follow the
   struct fields they are read from.

The `ind_typ_stk`/`ind_len_stk` stacks stay `int16_t` (upstream shapes: token
kinds and indent columns). `parser.c`, `schema.core.c`, `schema.json.c`,
`node-types.json` and the `tree_sitter/` headers are **verbatim** upstream
0.7.0 (checksum-verified at vendor time), so node kinds and grammar semantics
are unchanged below the old threshold — byte-identical trees (pinned by
tldr-code's `grammar_stability_test` and the element suites).

The patch is documented inline in `src/scanner.c` (file header + every site).

## Layout

```
Cargo.toml            crate manifest (path-dep member of the tldr workspace)
build.rs              upstream's cc build (parser.c + scanner.c, same flags)
lib.rs                LANGUAGE bridge LanguageFn + NODE_TYPES (repo API surface)
src/parser.c          verbatim upstream 0.7.0 (40,548 lines)
src/scanner.c         upstream 0.7.0 + the 31-line int32 patch
src/schema.core.c     verbatim upstream (included by scanner.c, YAML_SCHEMA=core)
src/schema.json.c     verbatim upstream (alternate schema; not compiled)
src/node-types.json   verbatim upstream (exposed as NODE_TYPES)
src/tree_sitter/      verbatim upstream headers (parser.h, array.h, alloc.h)
```

## Re-vendoring (when upstream fixes #49)

1. Copy the fixed upstream crate's `src/` over `src/` in this directory
   (keep this crate's `Cargo.toml`, `build.rs`, `lib.rs`).
2. Delete the patch header and annotations from `src/scanner.c` — nothing
   else in this crate knows about the patch.
3. Re-run `cargo test -p tldr-core --test grammar_stability_test` and the
   `yaml_vendored_grammar_v1` suite, then switch the workspace dep back to
   the registry crate (`tree-sitter-yaml = "=X.Y.Z"`) and delete this vendor.
