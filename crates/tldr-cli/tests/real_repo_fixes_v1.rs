//! real-repo-fixes-v1 — regression tests for five Phase-9 audit bugs
//! (P9.BUG-R1..R8) that the canonical-fixture matrix at
//! `language_command_matrix.rs` missed because synthetic fixtures don't
//! exercise real codebase patterns: macro-prefixed cpp classes, namespace
//! wrapping, qualified-name call graphs, and overload / duplicate-name
//! function detection.
//!
//! Each test is gated on the presence of the upstream sample under
//! `/tmp/repos/<name>` so the suite is a no-op in environments that
//! haven't seeded those fixtures (audit phase only). Where the fixture
//! is missing the test exits early with `return` — it does NOT skip via
//! cfg; we want CI to run them whenever the corpora are present.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn run_tldr_json_strict(args: &[&str]) -> Value {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.args(args).arg("--format").arg("json");
    let output = cmd.output().expect("failed to execute tldr");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "tldr {:?} failed: stdout={} stderr={}",
        args,
        stdout,
        stderr,
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("non-JSON output for {:?}: {} — stdout={}", args, e, stdout))
}

// =============================================================================
// R1: `tldr contracts` cannot locate `static inline` cpp functions
// =============================================================================

#[test]
fn test_r1_contracts_static_inline_cpp() {
    let f = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if !Path::new(f).exists() {
        return;
    }
    let v = run_tldr_json_strict(&["contracts", f, "TIXML_SNPRINTF"]);
    // Schema sanity — contracts report shape.
    assert!(v.get("function").is_some(), "missing `function` field");
    assert!(
        v.get("preconditions").is_some(),
        "missing `preconditions` field"
    );
    assert!(
        v.get("postconditions").is_some(),
        "missing `postconditions` field"
    );
}

// =============================================================================
// R2/R5/R6/R7: `tldr interface` returns 0 classes for cpp/csharp/kotlin/swift
// =============================================================================

fn assert_interface_classes_at_least(file: &str, min: usize) {
    if !Path::new(file).exists() {
        return;
    }
    let v = run_tldr_json_strict(&["interface", file]);
    let classes = v
        .get("classes")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        classes >= min,
        "expected >= {} classes for {}, got {} (output: {})",
        min,
        file,
        classes,
        serde_json::to_string(&v).unwrap_or_default()
    );
}

#[test]
fn test_r2_interface_cpp_classes_populated() {
    assert_interface_classes_at_least("/tmp/repos/cpp-tinyxml2/tinyxml2.h", 6);
}

#[test]
fn test_r5_interface_csharp_classes_populated() {
    assert_interface_classes_at_least(
        "/tmp/repos/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson.Tests/BsonDataWriterTests.cs",
        1,
    );
}

#[test]
fn test_r6_interface_kotlin_classes_populated() {
    assert_interface_classes_at_least("/tmp/repos/kotlin-datetime/core/common/src/UtcOffset.kt", 1);
}

#[test]
fn test_r7_interface_swift_classes_populated() {
    assert_interface_classes_at_least(
        "/tmp/repos/swift-collections/Sources/InternalCollectionsUtilities/Span+Extras.swift",
        1,
    );
}

// =============================================================================
// R3: `tldr context` returns 0 functions for ocaml / elixir
// =============================================================================

fn assert_context_returns_entry(project: &str, entry: &str) {
    if !Path::new(project).exists() {
        return;
    }
    let v = run_tldr_json_strict(&["context", entry, "--project", project]);
    let n = v
        .get("functions")
        .and_then(|f| f.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        n >= 1,
        "expected >= 1 function for `tldr context {} --project {}`, got 0; output={}",
        entry,
        project,
        serde_json::to_string(&v).unwrap_or_default()
    );
}

#[test]
fn test_r3_context_ocaml_returns_entry_function() {
    assert_context_returns_entry("/tmp/repos/ocaml-dune", "to_json");
}

#[test]
fn test_r3_context_elixir_returns_entry_function() {
    assert_context_returns_entry("/tmp/repos/elixir-plug", "init");
}

// =============================================================================
// R4: `tldr inheritance` returns 0 edges for C++ tinyxml2
// =============================================================================

#[test]
fn test_r4_inheritance_cpp_finds_edges() {
    let f = "/tmp/repos/cpp-tinyxml2";
    if !Path::new(f).exists() {
        return;
    }
    let v = run_tldr_json_strict(&["inheritance", f]);
    let edges = v
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        edges >= 6,
        "expected >= 6 inheritance edges for cpp-tinyxml2, got {}",
        edges
    );
}

// =============================================================================
// R8: `tldr diff <file> <file>` (self-diff) reports false positives
// =============================================================================

fn assert_self_diff_identical(file: &str) {
    if !Path::new(file).exists() {
        return;
    }
    let v = run_tldr_json_strict(&["diff", file, file]);
    let identical = v
        .get("identical")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    let total = v
        .get("summary")
        .and_then(|s| s.get("total_changes"))
        .and_then(|n| n.as_u64())
        .unwrap_or(u64::MAX);
    assert!(
        identical && total == 0,
        "self-diff on {} should be identical/0 changes, got identical={} total={}",
        file,
        identical,
        total,
    );
}

#[test]
fn test_r8_self_diff_python_identical() {
    assert_self_diff_identical("/tmp/repos/flask/src/flask/cli.py");
}

#[test]
fn test_r8_self_diff_cpp_identical() {
    assert_self_diff_identical("/tmp/repos/cpp-tinyxml2/tinyxml2.cpp");
}

#[test]
fn test_r8_self_diff_swift_identical() {
    assert_self_diff_identical(
        "/tmp/repos/swift-collections/Sources/InternalCollectionsUtilities/Span+Extras.swift",
    );
}

#[test]
fn test_r8_self_diff_kotlin_identical() {
    assert_self_diff_identical("/tmp/repos/kotlin-datetime/core/common/src/UtcOffset.kt");
}

#[test]
fn test_r8_self_diff_elixir_identical() {
    assert_self_diff_identical("/tmp/repos/elixir-plug/test/plug_test.exs");
}
