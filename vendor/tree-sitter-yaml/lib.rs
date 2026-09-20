//! Vendored YAML grammar for tree-sitter — tldr-code's patched fork of
//! `tree-sitter-yaml` 0.7.0 (tree-sitter-grammars/tree-sitter-yaml, MIT).
//!
//! WHY VENDORED: upstream 0.7.0's external scanner (`src/scanner.c`) tracks
//! the source row in `int16_t` and overflows at row 32768 — any `.yaml` past
//! 32,768 lines parsed into one root `ERROR` node (upstream issue #49, still
//! open; 0.7.2 on crates.io still carries `int16_t`). This vendor applies a
//! 31-line int32 patch (see `src/scanner.c` and README.md) so one whole-file
//! parse works at any size, and tldr-code needs no chunking/native-outline
//! workarounds.
//!
//! Re-vendor when upstream fixes #49: copy the new crate's `src/` over
//! `src/` and drop the patch (see README.md).
//!
//! [issue #49]: https://github.com/tree-sitter-grammars/tree-sitter-yaml/issues/49

use tree_sitter_language::LanguageFn;

extern "C" {
    fn tree_sitter_yaml() -> *const ();
}

/// The tree-sitter [`LanguageFn`][LanguageFn] for this grammar — the same
/// bridge API the registry crate exposes, so consumers (`ast::parser`,
/// `tldr explain`) load it identically against the pinned tree-sitter 0.25
/// runtime (ABI 14 parser, MIN_COMPATIBLE 13 / LANGUAGE_VERSION 15).
///
/// [LanguageFn]: https://docs.rs/tree-sitter-language/*/tree_sitter_language/struct.LanguageFn.html
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_yaml) };

/// The content of the [`node-types.json`][] file for this grammar (verbatim
/// from upstream 0.7.0 — node kinds are unchanged by the scanner patch).
///
/// [`node-types.json`]: https://tree-sitter.github.io/tree-sitter/using-parsers#static-node-types
pub const NODE_TYPES: &str = include_str!("src/node-types.json");
