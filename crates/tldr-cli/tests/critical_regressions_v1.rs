//! critical-regressions-v1 — regression tests for the P13.AGG13 milestone.
//!
//! All tests use real repos under `/tmp/repos/<repo>` and gate on existence
//! so they're skipped silently when the corpus isn't checked out (per the
//! no-synthetic-fixtures-v1 strategy).
//!
//! Bugs covered:
//!
//! - **AGG13-1** (P12 regression, HIGH): `tldr specs --from-tests` returned
//!   `total_specs: 0` for go/java/php test files even though
//!   `test_functions_scanned > 0`. Fix:
//!   * Extend the generic assertion-call walker to recognise PHP-specific
//!     call-shaped node kinds (`member_call_expression`,
//!     `function_call_expression`, `scoped_call_expression`,
//!     `nullsafe_member_call_expression`).
//!   * Add a Go-specific harvester for the
//!     `if cond { t.Errorf/Fatal/Fail(...) }` idiom (Go has no
//!     `assertEquals`-shaped helper).
//!
//! - **AGG13-2** (P12 regression, HIGH): Swift `tldr explain` reported
//!   empty callers for methods defined in `extension Heap { ... }` /
//!   nested-type extension bodies because the call-graph builder
//!   attributed the function's `dst_file` to the canonical `Heap.swift`
//!   file rather than the extension's actual source file. The strict
//!   `paths_equivalent` filter then dropped every real caller. Fix:
//!   confirm the function truly exists in the user-supplied file via AST
//!   scan; when so, accept callers from any homonym target.
//!
//! - **AGG13-7** (MED, elevated): `tldr verify` reported
//!   `sub_results.specs.error: "No test directory found"` on Maven /
//!   Gradle / MSBuild projects because `find_test_dirs` only probed
//!   top-level `tests/` and `test/`. Fix: extend discovery to cover
//!   `src/test/{java,kotlin,scala,groovy,resources}` plus `*Tests/`,
//!   `*.Tests/`, `Src/*Tests/` (MSBuild C#).
//!
//! - **AGG13-12** (LOW, partial regression): Lua `tldr explain` missed
//!   cross-module-alias callers for some functions (`m.open` had 0
//!   callers despite real `files.open(...)` call sites in
//!   `provider.lua` and `check_worker.lua`). Fix: in the references
//!   enrichment phase, when the requested function is `<receiver>.<X>`
//!   and the language is Lua/Luau, also query references for the bare
//!   name `X` and accept Call hits whose context contains
//!   `\.<X>(` (i.e. an alias-prefixed invocation).

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip helper: returns true and prints a notice when `path` doesn't
/// exist. Tests gate on real-repo presence per no-synthetic-fixtures-v1.
fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("[skip] {} not present", path);
        return true;
    }
    false
}

fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd().args(args).output().expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON for `tldr {}`: {}\nstdout: {}\nstderr: {}",
            args.join(" "),
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn callers_count(report: &Value) -> usize {
    report
        .get("callers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

fn specs_total(report: &Value) -> u64 {
    report
        .get("summary")
        .and_then(|s| s.get("total_specs"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn specs_scanned(report: &Value) -> u64 {
    report
        .get("summary")
        .and_then(|s| s.get("test_functions_scanned"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

// =============================================================================
// AGG13-1: specs --from-tests for go/java/php
// =============================================================================

#[test]
fn agg13_1_go_specs_from_t_errorf_pattern() {
    // go-httprouter's router_test.go uses `if cond { t.Errorf/Fatal(...) }`
    // 13 times. Pre-fix: 0 specs / 13 scanned. Post-fix: ≥1 spec.
    let test_file = "/tmp/repos/go-httprouter/router_test.go";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_scanned(&report) >= 13,
        "expected ≥13 test functions scanned, got {} (report: {})",
        specs_scanned(&report),
        report
    );
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from Go `if t.Errorf` idiom, got {} (report: {})",
        specs_total(&report),
        report
    );
}

#[test]
fn agg13_1_java_specs_from_junit_assertions() {
    // PetValidatorTests.java uses classic JUnit assertTrue/assertFalse.
    // Both pre- and post-fix should yield ≥1 spec — this guards against
    // a future regression in the Java arm of the generic walker.
    let test_file = "/tmp/repos/spring-petclinic/src/test/java/org/springframework/samples/petclinic/owner/PetValidatorTests.java";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from JUnit assertTrue/assertFalse, got {}",
        specs_total(&report)
    );
}

#[test]
fn agg13_1_php_specs_from_phpunit_assertions() {
    // UnicodeStringTest.php uses `$this->assertSame(...)` — a PHP
    // `member_call_expression` that the generic walker did not include
    // in its is-call match list pre-fix.
    let test_file = "/tmp/repos/php-symfony-string/Tests/UnicodeStringTest.php";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_scanned(&report) >= 2,
        "expected ≥2 test functions scanned, got {}",
        specs_scanned(&report)
    );
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from `\\$this->assertSame(...)`, got {} (report: {})",
        specs_total(&report),
        report
    );
}

#[test]
fn agg13_1_php_specs_from_phpunit_dir() {
    // Whole `Tests/` directory (10 files / 38 functions in phase-13
    // audit). Sanity check that the per-directory walker also benefits
    // from the call-kind extension.
    let test_dir = "/tmp/repos/php-symfony-string/Tests";
    if skip_if_missing(test_dir) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_dir, "--format", "json"]);
    assert!(
        specs_total(&report) >= 5,
        "expected ≥5 specs from full PHP Tests/ directory, got {}",
        specs_total(&report)
    );
}

// =============================================================================
// AGG13-1: cross-language non-regression for kotlin / csharp / ruby / python
// =============================================================================
//
// These are the languages P12-B already fixed. We re-assert ≥1 spec on a
// representative test file from each so the AGG13-1 fix doesn't accidentally
// regress them.

#[test]
fn agg13_1_kotlin_specs_unchanged() {
    let test_file = "/tmp/repos/kotlin-datetime/core/common/test/InstantTest.kt";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from kotlin tests (P12-B fix), got {}",
        specs_total(&report)
    );
}

#[test]
fn agg13_1_csharp_specs_unchanged() {
    let test_file =
        "/tmp/repos/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson.Tests/BsonDataWriterTests.cs";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from csharp tests (P12-B fix), got {}",
        specs_total(&report)
    );
}

#[test]
fn agg13_1_ruby_specs_unchanged() {
    let test_file = "/tmp/repos/rails-html-sanitizer/test/sanitizer_test.rb";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from ruby tests (P12-B fix), got {}",
        specs_total(&report)
    );
}

#[test]
fn agg13_1_python_specs_unchanged() {
    let test_file = "/tmp/repos/flask/tests/test_basic.py";
    if skip_if_missing(test_file) {
        return;
    }

    let report = run_json(&["specs", "--from-tests", test_file, "--format", "json"]);
    assert!(
        specs_total(&report) >= 1,
        "expected ≥1 spec from python tests (pre-existing), got {}",
        specs_total(&report)
    );
}

// =============================================================================
// AGG13-2: Swift explain callers/callees for extension methods
// =============================================================================

#[test]
fn agg13_2_swift_explain_extension_method_has_callers() {
    // `Heap._heapify` lives in `Heap+UnsafeHandle.swift` (an extension
    // body). The Swift call-graph builder attributes the `dst_file` to
    // `Heap.swift` (homonym-extension classifier), so the strict
    // `paths_equivalent` filter in `enrich_with_project_graph` dropped
    // the real `Heap.heapify` caller pre-fix. Post-fix: the AST
    // confirms `_heapify` is defined in `Heap+UnsafeHandle.swift` and
    // we accept callers from the homonym target.
    let file = "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";
    if skip_if_missing(file) {
        return;
    }

    let report = run_json(&["explain", file, "Heap._heapify", "--format", "json"]);
    assert!(
        callers_count(&report) >= 1,
        "expected ≥1 caller for Heap._heapify (Heap.heapify in same file), got {} (report: {})",
        callers_count(&report),
        report
    );
}

#[test]
fn agg13_2_swift_explain_heap_insert_has_callers() {
    // `Heap.insert(_:)` (the public method on the canonical `Heap`
    // type) has many cross-file callers. This is a control: it
    // worked pre-fix and must continue to work post-fix.
    let file = "/tmp/repos/swift-collections/Sources/HeapModule/Heap.swift";
    if skip_if_missing(file) {
        return;
    }

    let report = run_json(&["explain", file, "Heap.insert", "--format", "json"]);
    assert!(
        callers_count(&report) >= 5,
        "expected ≥5 callers for Heap.insert (control), got {}",
        callers_count(&report)
    );
}

// =============================================================================
// AGG13-7: verify discovers Maven/Gradle test directories
// =============================================================================

#[test]
fn agg13_7_verify_finds_maven_src_test_java() {
    // spring-petclinic's tests live under `src/test/java`. Pre-fix:
    // `verify` reported `sub_results.specs.error: "No test directory
    // found"`. Post-fix: discovery includes `src/test/java`, so the
    // specs sub-result must succeed and report ≥1 item.
    let project = "/tmp/repos/spring-petclinic";
    if skip_if_missing(project) {
        return;
    }

    let report = run_json(&["verify", project, "--format", "json"]);
    let specs = report
        .pointer("/sub_results/specs")
        .expect("verify report missing sub_results.specs");

    let error = specs.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        !error.contains("No test directory found"),
        "verify still reports `No test directory found` for Maven layout: {}",
        report
    );
    let items = specs
        .get("items_found")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        items >= 1,
        "expected ≥1 spec item from `verify` on Maven project, got {} (report: {})",
        items,
        report
    );
}

// =============================================================================
// AGG13-12: Lua m.open cross-module-alias callers
// =============================================================================

#[test]
fn agg13_12_lua_explain_m_open_has_cross_module_callers() {
    // `m.open` in `script/files.lua` is invoked as `files.open(...)`
    // from `script/cli/check_worker.lua` and `script/provider/provider.lua`.
    // Pre-fix: the Lua call-graph cross-module-alias resolver missed
    // these (works for `m.reset`, fails for `m.open`). Post-fix: the
    // references-based enrichment queries the bare name `open` and
    // accepts hits whose context contains `\.open(`, surfacing the real
    // callers.
    let file = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(file) {
        return;
    }

    let report = run_json(&["explain", file, "m.open", "--format", "json"]);
    assert!(
        callers_count(&report) >= 2,
        "expected ≥2 callers for m.open (provider.lua, check_worker.lua), got {} (report: {})",
        callers_count(&report),
        report
    );

    // Stronger assertion: the audit-named callers must be present.
    let callers = report
        .get("callers")
        .and_then(|v| v.as_array())
        .expect("callers must be an array");
    let files: Vec<String> = callers
        .iter()
        .filter_map(|c| c.get("file").and_then(|v| v.as_str()).map(String::from))
        .collect();
    assert!(
        files.iter().any(|f| f.contains("provider/provider.lua")),
        "expected provider.lua among m.open callers, got {:?}",
        files
    );
    assert!(
        files.iter().any(|f| f.contains("cli/check_worker.lua")),
        "expected check_worker.lua among m.open callers, got {:?}",
        files
    );
}

#[test]
fn agg13_12_lua_explain_m_reset_still_works() {
    // Control: `m.reset` worked pre-fix (P12.AGG12-1's lua fix). Post-fix
    // must continue to surface ≥1 caller (the previously-passing case).
    let file = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(file) {
        return;
    }

    let report = run_json(&["explain", file, "m.reset", "--format", "json"]);
    assert!(
        callers_count(&report) >= 1,
        "expected ≥1 caller for m.reset (control), got {}",
        callers_count(&report)
    );
}
