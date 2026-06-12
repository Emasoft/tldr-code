//! pack-patterns-v1 (v0.5.0 PACK-PATTERNS)
//!
//! AST-driven design-pattern detection + language-aware naming.
//!
//! Two real-corpus contracts pinned here:
//!
//! 1. **Solidity design patterns** (`/tmp/repos/solidity-openzeppelin`):
//!    the `patterns` command must surface the OpenZeppelin GoF/Solidity
//!    design patterns it now detects via the Solidity AST profile —
//!    Ownable (contract + `onlyOwner` modifier), Pausable
//!    (`whenNotPaused`/`whenPaused`), ReentrancyGuard (`nonReentrant`),
//!    Proxy (fallback delegate), and Factory (`new` expressions). The
//!    pre-fix baseline returned `Language::Solidity => None` from
//!    `language_profile()`, so 239 Solidity files produced 0 patterns.
//!
//! 2. **Go visibility-aware naming** (`/tmp/repos/go-httprouter`):
//!    correctly-cased *unexported* Go funcs (`getParams`, `addRoute`,
//!    `min`, `recv`, …) must NOT be reported as naming violations.
//!    Pre-fix, the single-majority naming classifier picked
//!    `pascal_case` (from the exported API surface) and flagged all 24
//!    correctly-named unexported camelCase funcs as violations. Go's
//!    convention is visibility-driven: exported (PascalCase) vs
//!    unexported (camelCase), both legitimate in every package.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early (skip) when its `/tmp/repos/<repo>` corpus is absent.

use std::path::Path;
use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

const SOLIDITY_CORPUS: &str = "/tmp/repos/solidity-openzeppelin";
const GO_CORPUS: &str = "/tmp/repos/go-httprouter";

// ============================================================================
// TEST 1: Solidity design-pattern detection on OpenZeppelin.
//
// The `patterns` command must emit a top-level `design_patterns` array
// for the Solidity corpus, and that array must include AT LEAST the
// canonical OpenZeppelin access/control patterns we now detect from the
// contract / modifier / inheritance AST: Ownable and Proxy.
// ============================================================================
#[test]
fn solidity_design_patterns_detect_ownable_and_proxy() {
    if !Path::new(SOLIDITY_CORPUS).exists() {
        eprintln!(
            "[skip] solidity_design_patterns_detect_ownable_and_proxy: corpus {} not present",
            SOLIDITY_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", SOLIDITY_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed on OpenZeppelin; got rc={}", rc);

    let v = parse_json(&out);
    let design = v["design_patterns"].as_array().cloned().unwrap_or_default();
    assert!(
        !design.is_empty(),
        "design_patterns must be a non-empty array on the OpenZeppelin \
         Solidity corpus (239 .sol files). Got: {:?}",
        v.get("design_patterns")
    );

    let names: Vec<String> = design
        .iter()
        .filter_map(|d| d["pattern"].as_str().map(|s| s.to_string()))
        .collect();

    assert!(
        names.iter().any(|n| n == "Ownable"),
        "expected an Ownable design pattern (contract + onlyOwner modifier) \
         detected on OpenZeppelin; got patterns: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n == "Proxy"),
        "expected a Proxy design pattern (fallback delegatecall) detected \
         on OpenZeppelin; got patterns: {:?}",
        names
    );

    // Every detected pattern must carry AST-grounded evidence (file + line).
    for d in &design {
        assert!(
            d["file"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "design pattern must carry a non-empty file: {:?}",
            d
        );
        assert!(
            d["line"].as_u64().map(|l| l >= 1).unwrap_or(false),
            "design pattern must carry a 1-based line: {:?}",
            d
        );
    }
}

// ============================================================================
// TEST 2: Solidity is now a supported pattern language (non-zero count).
// ============================================================================
#[test]
fn solidity_is_supported_pattern_language() {
    if !Path::new(SOLIDITY_CORPUS).exists() {
        eprintln!(
            "[skip] solidity_is_supported_pattern_language: corpus {} not present",
            SOLIDITY_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", SOLIDITY_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed; got rc={}", rc);

    let v = parse_json(&out);
    let by_lang = &v["metadata"]["language_distribution"]["patterns_by_language"];
    let solidity_count = by_lang["solidity"].as_u64().unwrap_or(0);
    assert!(
        solidity_count >= 1,
        "solidity must be a supported pattern language with >= 1 pattern; \
         got {} (pre-fix it was hardcoded to 0). patterns_by_language: {:?}",
        solidity_count,
        by_lang
    );
}

// ============================================================================
// TEST 3: Go visibility-aware naming — no false violations on correctly
//         cased unexported camelCase funcs.
//
// Pre-fix: 24 false-positive violations on httprouter (getParams,
// addRoute, min, recv, …) — all correctly-named unexported Go funcs
// flagged against a pascal_case majority. After the AST-driven
// visibility fix there must be ZERO violations whose `name` begins with
// a lowercase letter (i.e. an unexported func) and whose `actual` is
// camel_case / snake_case. Those are all legitimate Go names.
// ============================================================================
#[test]
fn go_unexported_funcs_are_not_naming_violations() {
    if !Path::new(GO_CORPUS).exists() {
        eprintln!(
            "[skip] go_unexported_funcs_are_not_naming_violations: corpus {} not present",
            GO_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", GO_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed on httprouter; got rc={}", rc);

    let v = parse_json(&out);
    let violations = v["naming"]["violations"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Collect every violation whose name is an unexported Go identifier
    // (first rune lowercase). These are the false positives we are
    // eliminating: an unexported Go func is *correctly* camelCase, so it
    // must never be flagged against a pascal_case expectation.
    let unexported_false_positives: Vec<String> = violations
        .iter()
        .filter_map(|x| x["name"].as_str().map(|s| s.to_string()))
        .filter(|name| {
            name.chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        unexported_false_positives.is_empty(),
        "unexported (lowercase-first) Go funcs must NOT be naming violations \
         — Go convention is visibility-aware (exported PascalCase, unexported \
         camelCase). False positives: {:?}",
        unexported_false_positives
    );

    // Sanity: also assert the specific known-good httprouter names are clean.
    for known in ["getParams", "addRoute", "longestCommonPrefix", "findWildcard"] {
        let flagged = violations
            .iter()
            .any(|x| x["name"].as_str() == Some(known));
        assert!(
            !flagged,
            "correctly-cased unexported Go func `{}` must not be flagged",
            known
        );
    }
}

// ============================================================================
// TEST 4: Go exported funcs that ARE correctly PascalCase are also clean,
//         AND the convention reported for Go is internally consistent
//         (the command still runs end-to-end and emits a naming block).
// ============================================================================
#[test]
fn go_exported_funcs_clean_and_naming_block_present() {
    if !Path::new(GO_CORPUS).exists() {
        eprintln!(
            "[skip] go_exported_funcs_clean_and_naming_block_present: corpus {} not present",
            GO_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", GO_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed; got rc={}", rc);

    let v = parse_json(&out);
    assert!(
        v.get("naming").map(|n| !n.is_null()).unwrap_or(false),
        "naming block must be present for the Go corpus"
    );

    let violations = v["naming"]["violations"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Known exported funcs that are correctly PascalCase must be clean.
    for known in ["ParamsFromContext", "MatchedRoutePath", "New"] {
        let flagged = violations
            .iter()
            .any(|x| x["name"].as_str() == Some(known));
        assert!(
            !flagged,
            "correctly-cased exported Go func `{}` must not be flagged",
            known
        );
    }
}
