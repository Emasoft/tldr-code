//! med-low-schema-cleanup-v1 — regression tests for 6 MED-LOW schema bugs.
//!
//! Covers:
//!   N6  `references` JSON must carry truncation metadata (`truncated`,
//!       `shown_references`, `total_references`) so callers can detect
//!       silent capping at `--limit`.
//!   N7  `tldr structure /empty_dir` must emit `language: null` + a
//!       warning when the directory has zero source files (instead of
//!       silently defaulting to "python").
//!   N9  `tldr definition` must use standardized exit codes:
//!         missing-file path → exit 5
//!         symbol-not-found  → exit 20
//!   N12 `tldr calls` JSON must drop the redundant `edge_count` /
//!       `node_count` keys; canonical pair is
//!       `total_edges` + `shown_edges` + `truncated`.
//!   N13 `tldr dead` JSON must emit `functions_analyzed` (canonical) and
//!       still emit `total_functions` as a deprecated alias.
//!   N15 percentage fields (`dead_percentage`) must be rounded to at
//!       most 2 decimal places at serialization (no 15-digit IEEE-754
//!       noise).

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Build a small Python project so commands have something real to chew on.
fn fixture_project() -> TempDir {
    let temp = TempDir::new().unwrap();
    // A few small files so dead/calls/references all have material.
    let f1 = temp.path().join("svc.py");
    fs::write(
        &f1,
        r#"
def helper(x):
    return x * 2

def used_a():
    return helper(1)

def used_b():
    return helper(2)

def used_c():
    return helper(3)

def dead_one():
    return 0

def main():
    return used_a() + used_b() + used_c()
"#,
    )
    .unwrap();
    let f2 = temp.path().join("driver.py");
    fs::write(
        &f2,
        r#"
from svc import main

if __name__ == "__main__":
    print(main())
"#,
    )
    .unwrap();
    temp
}

// =============================================================================
// N6: references must carry truncation metadata
// =============================================================================

#[test]
fn n6_references_emits_truncation_fields() {
    let project = fixture_project();

    // `helper` has 3 callers in svc.py; ask for limit=1 so truncation
    // genuinely fires.
    let out = tldr_cmd()
        .args([
            "references",
            "helper",
            project.path().to_str().unwrap(),
            "--limit",
            "1",
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run references");
    assert!(out.status.success(), "references should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("references JSON must parse: {e}\n--- stdout ---\n{stdout}"));

    let total = v["total_references"]
        .as_u64()
        .expect("total_references must be a number");
    let shown = v["shown_references"]
        .as_u64()
        .expect("shown_references must be a number (N6)");
    let truncated = v["truncated"]
        .as_bool()
        .expect("truncated must be a bool when truncation fires (N6)");
    let refs_len = v["references"]
        .as_array()
        .expect("references must be an array")
        .len() as u64;

    assert!(
        total >= shown,
        "total_references ({total}) must be >= shown_references ({shown})"
    );
    assert_eq!(
        shown, refs_len,
        "shown_references ({shown}) must equal references[].len() ({refs_len})"
    );
    assert!(
        refs_len <= shown,
        "references[].len() ({refs_len}) must be <= shown_references ({shown})"
    );
    assert!(
        truncated,
        "truncated must be true when --limit 1 hides additional refs"
    );
}

#[test]
fn n6_references_no_truncation_field_when_complete() {
    let project = fixture_project();

    // High limit so truncation does NOT fire — `truncated` should be
    // omitted from the JSON (skip_serializing_if).
    let out = tldr_cmd()
        .args([
            "references",
            "helper",
            project.path().to_str().unwrap(),
            "--limit",
            "1000",
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run references");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");

    let total = v["total_references"].as_u64().unwrap();
    let shown = v["shown_references"].as_u64().unwrap();
    assert_eq!(total, shown, "no truncation: total == shown");
    // `truncated` may be absent (skip_serializing_if=is_false_bool) or
    // explicitly false. Either is fine; what's NOT fine is "true".
    let trunc = v["truncated"].as_bool().unwrap_or(false);
    assert!(!trunc, "truncated must NOT be true when complete");
}

// =============================================================================
// N7: empty directory should emit `language: null` + warning
// =============================================================================

#[test]
fn n7_structure_empty_dir_emits_null_language_and_warning() {
    let temp = TempDir::new().unwrap();
    // Directory exists but contains zero source files.

    let out = tldr_cmd()
        .args([
            "structure",
            temp.path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run structure");
    assert!(
        out.status.success(),
        "structure on empty dir should succeed"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");

    // language must be null (NOT "python") — N7.
    assert!(
        v["language"].is_null(),
        "language must be null on empty dir, got {:?}",
        v["language"]
    );
    let files = v["files"].as_array().expect("files array");
    assert!(files.is_empty(), "files must be empty");
    let warnings = v["warnings"].as_array().expect("warnings array (N7)");
    let joined: String = warnings
        .iter()
        .filter_map(|w| w.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("No source files found"),
        "warnings must mention 'No source files found', got: {joined}"
    );
}

#[test]
fn n7_structure_real_project_keeps_language() {
    // Sanity check: when the directory DOES have source files,
    // `language` is still populated as before.
    let project = fixture_project();
    let out = tldr_cmd()
        .args([
            "structure",
            project.path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run structure");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        !v["language"].is_null(),
        "language must NOT be null when files exist"
    );
}

// =============================================================================
// N9: definition exit codes
// =============================================================================

#[test]
fn n9_definition_missing_file_exits_5() {
    let out = tldr_cmd()
        .args(["definition", "/nonexistent_n9_path.py", "1", "1"])
        .output()
        .expect("run definition");
    assert!(!out.status.success(), "missing file must fail");
    assert_eq!(
        out.status.code(),
        Some(5),
        "missing-file path must return exit 5 (N9), got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn n9_definition_symbol_not_found_exits_20() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("a.py");
    fs::write(&f, "def real_func():\n    return 1\n").unwrap();

    let out = tldr_cmd()
        .args([
            "definition",
            "--symbol",
            "definitely_not_a_real_symbol",
            "--file",
            f.to_str().unwrap(),
        ])
        .output()
        .expect("run definition");
    assert!(!out.status.success(), "missing symbol must fail");
    assert_eq!(
        out.status.code(),
        Some(20),
        "symbol-not-found must return exit 20 (N9), got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

// =============================================================================
// N12: calls JSON must drop redundant edge_count / node_count
// =============================================================================

#[test]
fn n12_calls_json_has_no_redundant_counters() {
    let project = fixture_project();
    let out = tldr_cmd()
        .args([
            "calls",
            project.path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run calls");
    assert!(out.status.success(), "calls should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let obj = v.as_object().expect("calls JSON must be an object");

    assert!(
        !obj.contains_key("edge_count"),
        "calls JSON must NOT contain redundant edge_count (N12)"
    );
    assert!(
        !obj.contains_key("node_count"),
        "calls JSON must NOT contain redundant node_count (N12)"
    );
    assert!(
        obj.contains_key("total_edges"),
        "calls JSON must contain total_edges"
    );
    assert!(
        obj.contains_key("shown_edges"),
        "calls JSON must contain shown_edges"
    );
}

// =============================================================================
// N13: dead must emit functions_analyzed (canonical) + legacy total_functions
// =============================================================================

#[test]
fn n13_dead_emits_functions_analyzed_and_legacy_total_functions() {
    let project = fixture_project();
    let out = tldr_cmd()
        .args([
            "dead",
            project.path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run dead");
    assert!(out.status.success(), "dead should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");

    // The dead command wraps DeadCodeReport in a `report` envelope.
    let report = v.get("report").unwrap_or(&v);
    let canonical = report["functions_analyzed"]
        .as_u64()
        .expect("functions_analyzed must be present (N13 canonical)");
    let legacy = report["total_functions"]
        .as_u64()
        .expect("total_functions must still be emitted as deprecated alias (N13)");
    assert_eq!(
        canonical, legacy,
        "functions_analyzed and total_functions must agree"
    );
    assert!(canonical > 0, "fixture project has functions");
}

// =============================================================================
// N15: percentage fields rounded to <= 2 decimals
// =============================================================================

#[test]
fn n15_dead_percentage_is_at_most_2_decimals() {
    let project = fixture_project();
    let out = tldr_cmd()
        .args([
            "dead",
            project.path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run dead");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let report = v.get("report").unwrap_or(&v);
    let pct_val = &report["dead_percentage"];
    let pct = pct_val.as_f64().expect("dead_percentage is a number");

    // Compare to the same value rounded to 2 decimals; must equal.
    let rounded = (pct * 100.0).round() / 100.0;
    assert!(
        (pct - rounded).abs() < 1e-9,
        "dead_percentage must be pre-rounded to 2 decimals: got {pct}, expected {rounded}"
    );

    // Defensive: textual representation shouldn't have more than ~5
    // chars after the dot. (`12.34` → 2; `100.0` → 1; `0.0` → 1.)
    let s = pct_val.to_string();
    if let Some(dot) = s.find('.') {
        let frac_len = s.len() - dot - 1;
        assert!(
            frac_len <= 6,
            "dead_percentage textual form has too many decimals: {s}"
        );
    }
}
