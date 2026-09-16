//! VULN-MIGRATION-V1 M1 — composite RED test.
//!
//! Single Go fixture with all source+sink names ONLY in strings/comments.
//! Asserts ZERO findings — the closes-#24 root pattern at the file scale.

use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn composite_multi_pattern_string_literal_fp_returns_zero_findings() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vuln_migration_v1")
        .join("composite")
        .join("multi_pattern.go");
    assert!(path.exists(), "fixture missing: {}", path.display());

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("vuln")
        .arg(&path)
        .arg("--lang")
        .arg("go")
        .arg("--format")
        .arg("json")
        .arg("--quiet");

    let output = cmd.output().expect("failed to execute tldr vuln");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON: {}\n--- stdout ---\n{}", e, stdout));

    let findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        findings.is_empty(),
        "composite string-literal fixture should yield ZERO findings; got {} findings: {}",
        findings.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}
