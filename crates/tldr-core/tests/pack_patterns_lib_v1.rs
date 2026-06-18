//! pack-patterns-lib-v1 (v0.5.0 PACK-PATTERNS)
//!
//! Library-level corpus tests for the AST-driven design-pattern +
//! visibility-aware-naming work, exercising `PatternMiner::mine_patterns`
//! directly (the exact pipeline the `tldr patterns` CLI command runs).
//!
//! These complement the CLI integration test
//! `crates/tldr-cli/tests/pack_patterns_v1.rs` and let the pattern miner
//! be validated against the real corpora without the CLI binary.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early
//! (skip) when its `/tmp/repos/<repo>` corpus is absent.

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


use std::path::Path;

use tldr_core::patterns::{PatternConfig, PatternMiner};

const SOLIDITY_CORPUS: &str = "/tmp/repos/solidity-openzeppelin";
const GO_CORPUS: &str = "/tmp/repos/go-httprouter";
const PHP_CORPUS: &str = "/tmp/repos/php-symfony-console";
const OCAML_CORPUS: &str = "/tmp/repos/ocaml-dune";

fn mine(path: &str) -> tldr_core::types::PatternReport {
    // Raise max_files so the whole corpus is scanned (default is 1000;
    // OpenZeppelin alone has ~400 source files but we want headroom).
    let config = PatternConfig {
        max_files: 100_000,
        ..PatternConfig::default()
    };
    let miner = PatternMiner::new(config);
    miner
        .mine_patterns(Path::new(path), None)
        .expect("mine_patterns must succeed on the corpus")
}

// ============================================================================
// Solidity: Ownable + Proxy design patterns detected from the AST.
// ============================================================================
#[test]
fn solidity_design_patterns_ownable_and_proxy() {
    if !corpus_ready(SOLIDITY_CORPUS) {
        eprintln!("[skip] solidity corpus {} absent", SOLIDITY_CORPUS);
        return;
    }
    let report = mine(SOLIDITY_CORPUS);
    assert!(
        !report.design_patterns.is_empty(),
        "design_patterns must be non-empty on the OpenZeppelin corpus"
    );

    let names: Vec<&str> = report
        .design_patterns
        .iter()
        .map(|d| d.pattern.as_str())
        .collect();

    assert!(
        names.contains(&"Ownable"),
        "expected Ownable detected; got {:?}",
        names
    );
    assert!(
        names.contains(&"Proxy"),
        "expected Proxy detected; got {:?}",
        names
    );

    // All Solidity hits must carry AST-grounded file + line.
    for dp in &report.design_patterns {
        if dp.language == "solidity" {
            assert!(!dp.file.is_empty(), "solidity pattern missing file: {:?}", dp);
            assert!(dp.line >= 1, "solidity pattern missing line: {:?}", dp);
            assert!(
                !dp.subject.is_empty(),
                "solidity pattern missing subject: {:?}",
                dp
            );
        }
    }

    // Solidity must now be a supported pattern language (non-zero count).
    let solidity_count = report
        .metadata
        .language_distribution
        .patterns_by_language
        .get("solidity")
        .copied()
        .unwrap_or(0);
    assert!(
        solidity_count >= 1,
        "solidity pattern count must be >= 1; got {}",
        solidity_count
    );
}

// ============================================================================
// Solidity: the full detector set must all fire somewhere in OZ.
// ============================================================================
#[test]
fn solidity_detects_full_pattern_set() {
    if !corpus_ready(SOLIDITY_CORPUS) {
        eprintln!("[skip] solidity corpus {} absent", SOLIDITY_CORPUS);
        return;
    }
    let report = mine(SOLIDITY_CORPUS);
    let names: std::collections::HashSet<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.language == "solidity")
        .map(|d| d.pattern.as_str())
        .collect();

    for expected in ["Ownable", "Pausable", "ReentrancyGuard", "Proxy"] {
        assert!(
            names.contains(expected),
            "expected Solidity pattern `{}` somewhere in OpenZeppelin; detected: {:?}",
            expected,
            names
        );
    }
}

// ============================================================================
// Go: visibility-aware naming — no false violations on unexported funcs.
// ============================================================================
#[test]
fn go_unexported_funcs_not_violations() {
    if !corpus_ready(GO_CORPUS) {
        eprintln!("[skip] go corpus {} absent", GO_CORPUS);
        return;
    }
    let report = mine(GO_CORPUS);
    let naming = report.naming.expect("Go corpus must produce a naming block");

    let unexported_false_positives: Vec<&str> = naming
        .violations
        .iter()
        .map(|v| v.name.as_str())
        .filter(|name| {
            name.chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        unexported_false_positives.is_empty(),
        "unexported (lowercase-first) Go funcs must not be flagged; got {:?}",
        unexported_false_positives
    );

    for known in ["getParams", "addRoute", "longestCommonPrefix", "findWildcard"] {
        assert!(
            !naming.violations.iter().any(|v| v.name == known),
            "correctly-cased unexported Go func `{}` must not be flagged",
            known
        );
    }
    for known in ["ParamsFromContext", "MatchedRoutePath", "New"] {
        assert!(
            !naming.violations.iter().any(|v| v.name == known),
            "correctly-cased exported Go func `{}` must not be flagged",
            known
        );
    }
}

// ============================================================================
// PHP: enriched profile is wired and a supported pattern language.
// ============================================================================
#[test]
fn php_is_supported_and_profile_runs() {
    if !corpus_ready(PHP_CORPUS) {
        eprintln!("[skip] php corpus {} absent", PHP_CORPUS);
        return;
    }
    let report = mine(PHP_CORPUS);
    // PHP must be in files_by_language and (being supported) get a count.
    let files = report
        .metadata
        .language_distribution
        .files_by_language
        .get("php")
        .copied()
        .unwrap_or(0);
    assert!(files >= 1, "expected php files scanned; got {}", files);

    // Any PHP design pattern detected must carry AST-grounded evidence.
    for dp in report.design_patterns.iter().filter(|d| d.language == "php") {
        assert!(!dp.file.is_empty(), "php pattern missing file: {:?}", dp);
        assert!(dp.line >= 1, "php pattern missing line: {:?}", dp);
        assert!(
            ["Singleton", "Factory", "Observer"].contains(&dp.pattern.as_str()),
            "unexpected php pattern name: {:?}",
            dp
        );
    }
}

// ============================================================================
// OCaml: module/functor idioms are detected on a real corpus.
// ============================================================================
#[test]
fn ocaml_module_idioms_detected() {
    if !corpus_ready(OCAML_CORPUS) {
        eprintln!("[skip] ocaml corpus {} absent", OCAML_CORPUS);
        return;
    }
    let report = mine(OCAML_CORPUS);

    let ocaml_patterns: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.language == "ocaml")
        .map(|d| d.pattern.as_str())
        .collect();

    // dune is a large OCaml codebase; it must contain at least one module
    // signature OR functor. (We don't pin an exact count — only that the
    // module-idiom detector fires on real OCaml module code.)
    assert!(
        ocaml_patterns
            .iter()
            .any(|p| matches!(*p, "Functor" | "ModuleSignature" | "FunctorApplication")),
        "expected at least one OCaml module idiom (Functor/ModuleSignature/\
         FunctorApplication) on the dune corpus; got {:?}",
        ocaml_patterns
    );

    for dp in report.design_patterns.iter().filter(|d| d.language == "ocaml") {
        assert!(!dp.file.is_empty(), "ocaml pattern missing file: {:?}", dp);
        assert!(dp.line >= 1, "ocaml pattern missing line: {:?}", dp);
    }
}
