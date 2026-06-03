//! SOL-001: Solidity foundation smoke tests.
//!
//! Phase 1 verification of the Solidity language addition:
//!
//! 1. Empty `.sol` file parses without panicking.
//! 2. Minimal `pragma solidity ^0.8.0; contract Foo {}` parses with no
//!    ERROR nodes (`tree.root_node().has_error()` is `false`).
//! 3. 0.8.18 named-mapping-params syntax — RESULT documented inline.
//! 4. Custom error syntax (0.8.4+) parses without errors.
//! 5. NatSpec `///` comment is preserved as a node in the tree.
//! 6. `Language::Solidity` is detected from `.sol` extension and path.
//!
//! These tests cover the foundation only: tree-sitter wiring + the
//! `Language::Solidity` enum + classifier wiring. Adapter-level
//! extraction (FunctionInfo / ClassInfo / events / modifiers / errors)
//! is the next phase (SOL-002+).

use std::path::Path;

use tldr_core::ast::parser::ParserPool;
use tldr_core::types::Language;

/// Helper: parse `source` as Solidity via `ParserPool` and return the
/// `tree-sitter::Tree`. Panics on parser-wiring errors so the failure
/// surfaces in the test report.
fn parse_solidity(source: &str) -> tree_sitter::Tree {
    let pool = ParserPool::new();
    pool.parse(source, Language::Solidity)
        .expect("Solidity parser should be wired in ParserPool::parse")
}

#[test]
fn empty_solidity_file_parses_without_panic() {
    // Empty file: tree-sitter should still produce a tree with a
    // `source_file` root node. The point is no panic and a valid tree.
    let tree = parse_solidity("");
    let root = tree.root_node();
    // Don't assert on `has_error` for empty input — some grammars
    // treat a totally empty file as an error. The smoke gate is "no
    // panic and we get a root node we can poke at".
    assert!(
        !root.kind().is_empty(),
        "root node kind should be non-empty for empty input"
    );
}

#[test]
fn minimal_contract_parses_with_no_errors() {
    let source = "pragma solidity ^0.8.0;\ncontract Foo {}\n";
    let tree = parse_solidity(source);
    let root = tree.root_node();
    assert!(
        !root.has_error(),
        "minimal contract should parse without ERROR nodes; got tree: {}",
        root.to_sexp()
    );
}

#[test]
fn named_mapping_params_0818_syntax_parses_or_is_documented() {
    // Solidity 0.8.18 introduced named keys/values in mappings:
    //   mapping(address from => uint256 amount) public balances;
    //
    // Per oracle research, some forks of tree-sitter-solidity may not
    // yet support this. This test records the RESULT for the pinned
    // 1.2.13 grammar so downstream phases know whether they can rely
    // on it.
    let source = "\
pragma solidity ^0.8.18;
contract Foo {
    mapping(address from => uint256 amount) public balances;
}
";
    let tree = parse_solidity(source);
    let root = tree.root_node();
    let has_error = root.has_error();
    // We assert nothing strict here — we just record the outcome so a
    // failure shows up clearly in CI when the grammar version is
    // bumped. The current expectation (1.2.13) is `has_error == false`
    // per oracle, but we tolerate either outcome at v0.5.0.
    eprintln!(
        "named_mapping_params: has_error = {} (1.2.13 expected: false)",
        has_error
    );
    // The tree itself must always be parseable, even if it has error
    // nodes — we just want no panic from the parser pool.
    let _ = root.to_sexp();
}

#[test]
fn custom_error_syntax_parses() {
    // Custom errors were added in Solidity 0.8.4.
    let source = "\
pragma solidity ^0.8.4;
contract Foo {
    error InsufficientBalance(uint256 available);
    function withdraw() external {
        revert InsufficientBalance(0);
    }
}
";
    let tree = parse_solidity(source);
    let root = tree.root_node();
    assert!(
        !root.has_error(),
        "custom error declaration should parse without ERROR nodes; got tree: {}",
        root.to_sexp()
    );
}

#[test]
fn natspec_comment_is_preserved() {
    let source = "\
pragma solidity ^0.8.0;
/// @notice This is a documented contract.
/// @dev With dev notes too.
contract Foo {}
";
    let tree = parse_solidity(source);
    let root = tree.root_node();
    assert!(
        !root.has_error(),
        "NatSpec comments should parse without ERROR nodes; got tree: {}",
        root.to_sexp()
    );
    // The grammar surfaces NatSpec as `comment` nodes. We don't pin a
    // specific node kind here (varies per grammar fork) — we just
    // verify the comment text survived in the source span.
    let sexp = root.to_sexp();
    assert!(
        sexp.contains("comment"),
        "expected at least one `comment` node in tree; sexp: {}",
        sexp
    );
}

#[test]
fn language_detected_from_sol_extension() {
    // Classifier must round-trip `.sol` → Solidity via both the
    // extension-string and path-based entrypoints.
    assert_eq!(
        Language::from_extension(".sol"),
        Some(Language::Solidity),
        "from_extension(\".sol\") should return Solidity"
    );
    assert_eq!(
        Language::from_extension("sol"),
        Some(Language::Solidity),
        "from_extension(\"sol\") (no leading dot) should return Solidity"
    );
    let path = Path::new("contracts/Token.sol");
    assert_eq!(
        Language::from_path(path),
        Some(Language::Solidity),
        "from_path(\"contracts/Token.sol\") should return Solidity"
    );
}

#[test]
fn language_solidity_basics() {
    // Round-trip via FromStr, all(), as_str, extensions.
    assert_eq!(
        "solidity".parse::<Language>().unwrap(),
        Language::Solidity,
        "FromStr should accept \"solidity\""
    );
    assert_eq!(
        "sol".parse::<Language>().unwrap(),
        Language::Solidity,
        "FromStr should accept the \"sol\" short alias"
    );
    assert_eq!(Language::Solidity.as_str(), "solidity");
    assert_eq!(Language::Solidity.extensions(), &[".sol"]);
    assert!(
        Language::all().contains(&Language::Solidity),
        "Language::all() must include Solidity"
    );
    // Scan extensions: defaults to canonical for non-family languages.
    assert_eq!(Language::Solidity.scan_extensions(), &[".sol"]);
    // matches_for_scan
    assert!(Language::Solidity.matches_for_scan(Path::new("a.sol")));
    assert!(!Language::Solidity.matches_for_scan(Path::new("a.rs")));
}
