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
//! C++) and Solidity contract/interface/library members. The bridge set is
//! kept identical to the one `verify` already used so hoisting is
//! behaviour-preserving for the verify sweep.
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
/// extractor to see their declared members. Mirrors the bridge in the
/// `verify` sweep and the `health` command's method-aware function count.
/// Kept identical to the verify list so hoisting is behaviour-preserving.
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
}
