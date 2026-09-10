//! verification-and-metrics-completeness-v1 (P12.AGG12-2, AGG12-10, AGG12-11, AGG12-12)
//!
//! Closes four bugs found by the phase-12 deep audit AFTER the
//! verification-pipeline-completeness-v1 milestone landed:
//!
//! 1. **BUG-AGG12-2 (HIGH)** `tldr specs --from-tests` recognised 0 tests for
//!    Rust `#[test]`, C# `[Test]`/`[Fact]`/`[TestMethod]`, and extracted 0
//!    specs for Java/Kotlin (despite the recogniser counting their tests).
//! 2. **BUG-AGG12-10 (MED)** `tldr cognitive` returned 0 for every Ruby
//!    function regardless of branch density. The cognitive calculator only
//!    matched `*_statement` AST node kinds; the Ruby tree-sitter grammar
//!    exposes them as `if`/`unless`/`while`/`for`/`case`/`begin`/`rescue`
//!    plus `*_modifier` variants for trailing conditionals.
//! 3. **BUG-AGG12-11 (MED)** `tldr contracts` on C functions misidentified
//!    the function name as the first parameter. The recursive untyped-param
//!    walker descended into `function_declarator` and matched the function
//!    name `identifier` sibling of the parameter list as a parameter.
//! 4. **BUG-AGG12-12 (MED)** `tldr semantic` indexed minified vendor JS
//!    inside `docs/` directories of non-JS projects (e.g.
//!    `cpp-tinyxml2/docs/jquery.js`), which dominated every search result.
//!    The semantic chunker used a raw `walkdir::WalkDir` with a tiny
//!    `SKIP_DIRECTORIES` list that didn't share the doxygen-sentinel
//!    detection P11 added to the shared walker.
//!
//! Per `thoughts/shared/strategy/no-synthetic-fixtures-v1.md`, every test in
//! this file gates on the existence of a real-codebase repo at
//! `/tmp/repos/<name>`. No `TempDir` synthetic fixtures, no inline
//! Python/Java/Kotlin/etc. files. If the repo is missing, the test returns
//! early so CI without `/tmp/repos/` still passes.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn tldr_bin() -> PathBuf {
    // why: env!("CARGO_BIN_EXE_tldr") is the path cargo builds for THIS
    // test's own profile, as a test dependency -- it cannot go stale the
    // way a hand-resolved `target/release/tldr` guess could, because
    // there is no rebuild step to forget (TRDD-BJ9T0U9I). No test in this
    // file needs `--features semantic`; the old panic message naming it
    // was copy-pasted from a file that does.
    PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
}

fn run_tldr(args: &[&str]) -> (Value, String, bool) {
    let bin = tldr_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let json: Value = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (json, stderr, output.status.success())
}

/// Skip the test if the gating repo path doesn't exist on this machine.
/// Returns `true` if the test should run, `false` if it should bail early.
fn require_repo(p: &str) -> bool {
    if Path::new(p).exists() {
        true
    } else {
        eprintln!("verification-and-metrics-completeness-v1: skipping (missing {})", p);
        false
    }
}

// =============================================================================
// BUG-AGG12-2: specs --from-tests Rust / C# / Kotlin / Java / Python
// =============================================================================

#[test]
fn test_specs_rust_test_attribute() {
    let path = "/tmp/repos/ripgrep/crates/ignore/tests";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert!(ok, "tldr specs failed: {}", stderr);
    let summary = &json["summary"];
    let scanned = summary["test_functions_scanned"].as_u64().unwrap_or(0);
    let files = summary["test_files_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 1,
        "expected ≥ 1 Rust #[test] function in {} (saw {} files / {} fns) — \
         test_recognizer Rust adapter regression",
        path, files, scanned,
    );
}

#[test]
fn test_specs_csharp_test_attribute() {
    let path = "/tmp/repos/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson.Tests";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert!(ok, "tldr specs failed: {}", stderr);
    let summary = &json["summary"];
    let scanned = summary["test_functions_scanned"].as_u64().unwrap_or(0);
    let files = summary["test_files_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 1,
        "expected ≥ 1 C# [Test]/[Fact]/[TestMethod] method in {} (saw {} files / {} fns) — \
         test_recognizer C# adapter regression",
        path, files, scanned,
    );
}

#[test]
fn test_specs_kotlin_extracts_specs() {
    let path = "/tmp/repos/kotlin-datetime/core/common/test";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert!(ok, "tldr specs failed: {}", stderr);
    let summary = &json["summary"];
    let total_specs = summary["total_specs"].as_u64().unwrap_or(0);
    let scanned = summary["test_functions_scanned"].as_u64().unwrap_or(0);
    // Phase-12 baseline: 571 functions scanned but 0 specs extracted.
    // Post-fix the JVM-style assertion extractor MUST harvest at least one
    // assertEquals / assertTrue / assertNotNull from the 571 functions.
    assert!(scanned >= 50, "expected ≥ 50 Kotlin test fns, saw {}", scanned);
    assert!(
        total_specs >= 1,
        "expected ≥ 1 spec extracted from {} Kotlin test fns — JVM assertion \
         walker regression (assertEquals / assertTrue / assertNotNull)",
        scanned,
    );
}

#[test]
fn test_specs_java_unchanged() {
    let path = "/tmp/repos/spring-petclinic/src/test/java";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert!(ok, "tldr specs failed: {}", stderr);
    let summary = &json["summary"];
    let scanned = summary["test_functions_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 1,
        "expected ≥ 1 Java @Test method in {} (regression check)",
        path,
    );
}

#[test]
fn test_specs_python_regression() {
    let path = "/tmp/repos/flask/tests";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert!(ok, "tldr specs failed: {}", stderr);
    let summary = &json["summary"];
    let total_specs = summary["total_specs"].as_u64().unwrap_or(0);
    let scanned = summary["test_functions_scanned"].as_u64().unwrap_or(0);
    // Python pytest extractor must keep extracting specs (regression
    // guard for the previously-Python-only path).
    assert!(scanned >= 1, "expected ≥ 1 Python test fn (regression)");
    assert!(
        total_specs >= 1,
        "expected ≥ 1 spec from Python pytest extractor (regression)",
    );
}

// =============================================================================
// BUG-AGG12-10: Ruby cognitive complexity
// =============================================================================

#[test]
fn test_cognitive_ruby_nonzero() {
    let path = "/tmp/repos/rails-html-sanitizer/lib/rails/html/scrubbers.rb";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["cognitive", path, "--format", "json"]);
    assert!(ok, "tldr cognitive failed: {}", stderr);

    let total = json["summary"]["total_cognitive"].as_u64().unwrap_or(0);
    let max = json["summary"]["max_cognitive"].as_u64().unwrap_or(0);
    let any_nonzero = json["functions"]
        .as_array()
        .map(|arr| arr.iter().any(|f| f["cognitive"].as_u64().unwrap_or(0) > 0))
        .unwrap_or(false);

    assert!(
        any_nonzero,
        "expected at least one Ruby function with cognitive > 0 in {} \
         (total={} max={}) — Ruby AST kinds (`if`/`unless`/`while`/`case`/\
         `*_modifier`) must increment cognitive",
        path, total, max,
    );

    // The `scrub` method on PermitScrubber has if + return-if + unless + nested
    // unless-modifier; a healthy SonarSource cognitive score is ≥ 5.
    let scrub_score = json["functions"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|f| f["name"].as_str() == Some("scrub"))
                .and_then(|f| f["cognitive"].as_u64())
        })
        .unwrap_or(0);
    assert!(
        scrub_score >= 3,
        "expected `scrub` cognitive ≥ 3 (found {}) — multi-branch Ruby \
         method should not score ≤ 2",
        scrub_score,
    );
}

#[test]
fn test_cognitive_python_unchanged() {
    let path = "/tmp/repos/flask/src/flask/app.py";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["cognitive", path, "--format", "json"]);
    assert!(ok, "tldr cognitive failed: {}", stderr);
    let any_nonzero = json["functions"]
        .as_array()
        .map(|arr| arr.iter().any(|f| f["cognitive"].as_u64().unwrap_or(0) > 0))
        .unwrap_or(false);
    assert!(
        any_nonzero,
        "expected ≥ 1 Python function with cognitive > 0 (regression)",
    );
}

// =============================================================================
// BUG-AGG12-11: C / C++ contracts param extraction
// =============================================================================

#[test]
fn test_contracts_c_sdsnew_first_param_is_init() {
    let path = "/tmp/repos/c-sds/sds.c";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&["contracts", path, "sdsnew", "--format", "json"]);
    assert!(ok, "tldr contracts failed: {}", stderr);
    let preconditions = json["preconditions"].as_array().expect("array");
    // The function-name `sdsnew` MUST NOT appear as a precondition variable.
    for pc in preconditions {
        let v = pc["variable"].as_str().unwrap_or("");
        assert_ne!(
            v, "sdsnew",
            "function name `sdsnew` mistakenly emitted as a parameter — \
             extract_untyped_params_recursive function_declarator regression"
        );
    }
    // The actual first parameter `init` (from `const char *init`) MUST appear.
    let has_init = preconditions
        .iter()
        .any(|pc| pc["variable"].as_str() == Some("init"));
    assert!(
        has_init,
        "expected `init` to appear as a precondition variable for `sdsnew` \
         (signature: `sds sdsnew(const char *init)`) — got {:?}",
        preconditions,
    );
}

#[test]
fn test_contracts_cpp_first_param_not_function_name() {
    let path = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if !require_repo(path) {
        return;
    }
    // `XMLDocument::NewElement(const char* name)` — first param is `name`,
    // never the function name (which would be `NewElement`).
    let (json, stderr, ok) =
        run_tldr(&["contracts", path, "NewElement", "--format", "json"]);
    assert!(ok, "tldr contracts failed: {}", stderr);
    let preconditions = json["preconditions"].as_array().expect("array");
    for pc in preconditions {
        let v = pc["variable"].as_str().unwrap_or("");
        assert_ne!(
            v, "NewElement",
            "function name `NewElement` mistakenly emitted as a parameter \
             — function_declarator skip regression for C++"
        );
    }
}

// =============================================================================
// BUG-AGG12-12: semantic walker excludes vendored / generated dirs
// =============================================================================

#[test]
fn test_semantic_excludes_vendored_minified_js() {
    let path = "/tmp/repos/cpp-tinyxml2";
    if !require_repo(path) {
        return;
    }
    let (json, stderr, ok) = run_tldr(&[
        "semantic",
        "parse XML element",
        path,
        "--format",
        "json",
    ]);
    // Semantic search may fail on machines without the embedding model; in
    // that case skip cleanly rather than asserting a hard count.
    if !ok {
        eprintln!("semantic command failed (likely missing ONNX model): {}", stderr);
        return;
    }
    let results = match json["results"].as_array() {
        Some(arr) => arr,
        None => {
            eprintln!("semantic returned no results array; skipping");
            return;
        }
    };
    // Phase-12 baseline: 10/10 hits were inside `docs/jquery.js` /
    // `docs/clipboard.js`. After the fix, ZERO of the results should come
    // from vendor-minified JS in `docs/`.
    let vendor_hits: Vec<&str> = results
        .iter()
        .filter_map(|r| r["file_path"].as_str())
        .filter(|fp| {
            fp.contains("/docs/jquery.js")
                || fp.contains("/docs/clipboard.js")
                || fp.contains("/docs/dynsections.js")
        })
        .collect();
    assert!(
        vendor_hits.is_empty(),
        "semantic walker indexed vendored JS in {}/docs/: {:?} — \
         chunk_directory must use ProjectWalker + dir_has_generated_sentinel",
        path, vendor_hits,
    );
}
