//! Shared "symbols a file declares" primitive for the `contracts` commands.
//!
//! fix-R3-rc4 (RC4): before this module, every contracts sub-command resolved
//! the set of functions/methods a source file *declares* ad hoc — `verify`
//! re-implemented it inline as `extract_function_names`, `invariants` never
//! computed it at all (so its `<FILE>` positional was decorative and the report
//! echoed every call name observed across the whole test tree), and `specs`
//! advertised a `--source` flag wired to nothing. This module is the single
//! AST-driven definition of "the bare names a file declares", used by every
//! contracts sub-command that needs to scope test-derived results to a
//! particular source file.
//!
//! The set is computed purely from tree-sitter definition node-kinds via
//! [`extract_functions`] / [`extract_methods`] (no regex, no string
//! heuristics): free functions for every language, plus class/contract members
//! for the method-bearing languages (C#, Java, Kotlin, Scala, Swift, Ruby,
//! C++, and — since T9 / audit RB-1 — PHP, Python, TypeScript, JavaScript,
//! Rust) and Solidity contract/interface/library members. `verify`,
//! `invariants`, and `specs --source` all resolve a file's declared symbols
//! through this one definition, so widening the method bridge here is additive
//! across every contracts sub-command (see [`is_method_bearing`]).
//!
//! # Name-matching semantics (known limitation)
//!
//! Scoping matches by *unqualified* function/method name. The canonical
//! association key (per Daikon's program-point grammar) is receiver-type
//! qualified and signature-disambiguated (`Class.method(arg-types)`); a bare
//! name is explicitly its non-identifying sub-component. tldr's tree-sitter
//! layer computes no type binding, so two identically named methods in
//! different classes within the test tree are not distinguished — an
//! observation of `B.read` is *not* excluded when scoping to a file that only
//! declares `A.read`. This residual over-approximation is the same class of
//! imprecision that trace-based likely-invariant inference already tolerates;
//! signature-keyed scoping is deferred future work.

use std::collections::HashSet;
use std::path::Path;

use tldr_core::ast::extractor::{extract_functions, extract_methods};
use tldr_core::ast::ParserPool;
use tldr_core::Language;
use tree_sitter::Tree;

/// Languages whose callable units live (wholly or partly) inside classes /
/// objects, so the free-function extractor must be bridged with the method
/// extractor ([`extract_methods`], `methods_only=true`) to see their declared
/// members. Mirrors the bridge in the `verify` sweep and the `health`
/// command's method-aware function count.
///
/// T9 (audit RB-1): originally this listed only the languages whose *entire*
/// callable surface is method-shaped (C#, or convention-heavy OO like Java /
/// Kotlin / Scala / Swift / Ruby / C++). But every language here that ALSO has
/// free functions — PHP, Python, TypeScript, JavaScript, Rust — still declares
/// class/impl methods that `extract_functions` (methods_only=false) skips.
/// Omitting them left those methods out of a file's declared-symbol set, so
/// `invariants` / `specs --source` scoped genuine, in-file methods OUT of their
/// reports (recording them under `skipped_undefined`). Bridging them in is
/// additive: it can only ADD declared names, never remove any, so the change
/// only surfaces observations that were previously dropped and leaves the
/// already-bridged languages untouched. `extract_methods` already has a
/// working arm for each (see `tldr_core::ast::extractor::extract_methods`).
fn is_method_bearing(language: Language) -> bool {
    matches!(
        language,
        Language::CSharp
            | Language::Java
            | Language::Kotlin
            | Language::Scala
            | Language::Swift
            | Language::Ruby
            | Language::Cpp
            | Language::Php
            | Language::Python
            | Language::TypeScript
            | Language::JavaScript
            | Language::Rust
    )
}

/// Collect the bare names of functions/methods declared in an already-parsed
/// tree: free functions, plus Solidity contract members and class members for
/// the method-bearing languages. De-duplicated, order-preserving.
fn collect_defined_names(tree: &Tree, source: &str, language: Language) -> Vec<String> {
    let mut names = extract_functions(tree, source, language);

    // Solidity wraps every concrete function inside a contract / interface /
    // library, so `extract_functions` (methods_only=false) returns ZERO names
    // for typical `.sol` files; bridge in the contract-member methods.
    if language == Language::Solidity {
        for m in tldr_core::ast::extractor::extract_solidity_methods_for_verify(tree, source) {
            if !names.contains(&m) {
                names.push(m);
            }
        }
    }

    // Method-bearing languages: bridge in class/object members so the declared
    // set isn't limited to free functions (for C# that would be empty).
    if is_method_bearing(language) {
        for m in extract_methods(tree, source, language) {
            if !names.contains(&m) {
                names.push(m);
            }
        }
    }

    names
}

/// Bare names of all functions/methods DECLARED in `source` for `language`,
/// derived from tree-sitter definition nodes.
///
/// Returns the empty vector when `source` is blank or fails to parse — the
/// historical contract of `verify`'s former inline `extract_function_names`,
/// which this hoists so `verify` and `invariants` share ONE definition of a
/// file's declared symbols.
pub fn defined_symbol_names(source: &str, language: Language) -> Vec<String> {
    if source.trim().is_empty() {
        return Vec::new();
    }
    let pool = ParserPool::new();
    let tree = match pool.parse(source, language) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    collect_defined_names(&tree, source, language)
}

/// Defined-symbol SET for a FILE on disk, or `None` when the symbol picture is
/// *unknown* — i.e. the file is unreadable (e.g. invalid UTF-8) or fails to
/// parse. Callers MUST treat `None` as "do not scope" and fall back to
/// unfiltered behaviour, so a parser gap never silently empties a report.
///
/// `Some(set)` means the file parsed successfully; an empty set then means the
/// file genuinely declares nothing — a correct, non-fallback empty scope that
/// is deliberately distinguished from the parse-failure case.
pub fn defined_symbols_for_file(path: &Path, language: Language) -> Option<HashSet<String>> {
    // Unreadable (e.g. non-UTF-8) -> symbols unknown -> fall back (None).
    let source = std::fs::read_to_string(path).ok()?;
    // A readable but blank file genuinely declares nothing (parsed, zero defs).
    if source.trim().is_empty() {
        return Some(HashSet::new());
    }
    let pool = ParserPool::new();
    // Parse failure -> symbols unknown -> fall back (None).
    let tree = pool.parse(&source, language).ok()?;
    Some(
        collect_defined_names(&tree, &source, language)
            .into_iter()
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn defined_symbol_names_python_free_functions() {
        let src = "def alpha(x):\n    return x\n\ndef beta(y):\n    return y\n";
        let names = defined_symbol_names(src, Language::Python);
        assert!(names.contains(&"alpha".to_string()), "{names:?}");
        assert!(names.contains(&"beta".to_string()), "{names:?}");
    }

    #[test]
    fn defined_symbol_names_blank_source_is_empty() {
        assert!(defined_symbol_names("   \n  ", Language::Python).is_empty());
    }

    #[test]
    fn defined_symbols_for_file_parsed_returns_some() {
        let temp = TempDir::new().unwrap();
        let p = temp.path().join("m.py");
        fs::write(&p, "def gamma():\n    return 1\n").unwrap();
        let set = defined_symbols_for_file(&p, Language::Python).expect("parsed -> Some");
        assert!(set.contains("gamma"), "{set:?}");
    }

    #[test]
    fn defined_symbols_for_file_blank_is_some_empty_not_fallback() {
        let temp = TempDir::new().unwrap();
        let p = temp.path().join("empty.py");
        fs::write(&p, "\n\n").unwrap();
        // Parsed, zero defs -> Some(empty), NOT None (fallback).
        let set = defined_symbols_for_file(&p, Language::Python).expect("blank -> Some(empty)");
        assert!(set.is_empty(), "{set:?}");
    }

    #[test]
    fn defined_symbols_for_file_unreadable_is_none_fallback() {
        let temp = TempDir::new().unwrap();
        let p = temp.path().join("bad.py");
        fs::write(&p, [0xff, 0xfe, 0x00, 0x80]).unwrap();
        // Invalid UTF-8 -> unknown symbols -> None so callers fall back.
        assert!(defined_symbols_for_file(&p, Language::Python).is_none());
    }

    // T9 (audit RB-1): class METHODS — not just free/top-level functions —
    // must enter a file's declared-symbol set for the method-scoping
    // languages whose members are extracted via `extract_methods`
    // (methods_only=true). Before this, `is_method_bearing` whitelisted only
    // C#/Java/Kotlin/Scala/Swift/Ruby/C++, so PHP/Python/TS/JS/Rust class
    // methods were dropped from the set — which `invariants`/`specs --source`
    // then scoped OUT of every report (pushed to `skipped_undefined`) even
    // though the method is genuinely declared in the analyzed file.

    #[test]
    fn defined_symbol_names_php_class_methods_are_bridged() {
        // PHP wraps `exponentialDelay` in a class (a `method_declaration`), so
        // `extract_functions` (methods_only=false) alone returns ZERO names;
        // the method must be bridged in via `extract_methods`.
        let src = "<?php\nclass RetryMiddleware {\n    public function exponentialDelay($retries) {\n        return $retries * 2;\n    }\n}\n";
        let names = defined_symbol_names(src, Language::Php);
        assert!(
            names.contains(&"exponentialDelay".to_string()),
            "PHP class method must be in the declared-symbol set: {names:?}"
        );
    }

    #[test]
    fn defined_symbol_names_python_class_methods_are_bridged() {
        // Python free functions are already covered by
        // `defined_symbol_names_python_free_functions`; a class method is only
        // reached via `extract_functions(methods_only=true)`, so it needs the
        // method bridge too.
        let src = "class Calc:\n    def add(self, a, b):\n        return a + b\n";
        let names = defined_symbol_names(src, Language::Python);
        assert!(
            names.contains(&"add".to_string()),
            "Python class method must be in the declared-symbol set: {names:?}"
        );
    }
}
