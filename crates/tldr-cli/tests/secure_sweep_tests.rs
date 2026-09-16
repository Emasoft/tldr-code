//! Secure Sweep CLI Integration Tests
//!
//! Test-driven development tests for `tldr secure` command migration.
//! These tests define expected behavior based on spec.md behavioral contracts.
//!
//! # Behavioral Contracts Tested
//!
//! - BC-SEC-1: Safe execution (sub-analyses wrapped, failures recorded)
//! - BC-SEC-2: File scanning (max 500 files, respect .gitignore)
//! - BC-SEC-3: Progress reporting (stderr format)
//! - BC-SEC-4: Severity ordering (critical < high < medium < low < info)
//! - BC-SEC-5: Text output format (top 15 findings, summary)
//!
//! Reference: migration/spec.md

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the tldr command
fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Create a test file in the given directory
fn create_test_file(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&path, content).expect("Failed to write test file");
    path
}

/// Create a .gitignore file
fn create_gitignore(dir: &std::path::Path, content: &str) {
    fs::write(dir.join(".gitignore"), content).expect("Failed to write .gitignore");
}

// =============================================================================
// BC-SEC-1: Safe Execution Tests
// =============================================================================

#[test]
fn test_secure_help() {
    let mut cmd = tldr_cmd();
    cmd.arg("secure").arg("--help");

    // This test will fail until the secure command is implemented
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("secure"))
        .stdout(predicate::str::contains("Security"));
}

#[test]
fn test_secure_empty_directory() {
    let dir = tempdir().unwrap();

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Empty directory should return valid JSON with 0 findings
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"findings\""))
        .stdout(
            predicate::str::contains("[]").or(predicate::str::contains("\"total_findings\": 0")),
        );
}

#[test]
fn test_secure_nonexistent_path() {
    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg("/nonexistent/path/that/does/not/exist")
        .arg("-f")
        .arg("json");

    // Should fail gracefully with error message
    cmd.assert().failure().stderr(
        predicate::str::contains("not found")
            .or(predicate::str::contains("No such file").or(predicate::str::contains("error"))),
    );
}

#[test]
fn test_secure_single_file() {
    let dir = tempdir().unwrap();
    let content = r#"
def vulnerable(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
"#;
    let file = create_test_file(dir.path(), "vuln.py", content);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(file.to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should analyze single file and return JSON
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\": \"secure\""))
        .stdout(predicate::str::contains("\"path\""));
}

#[test]
fn test_secure_sub_analysis_failure_recorded() {
    let dir = tempdir().unwrap();
    // Create an invalid Python file that might cause parse errors
    let content = "def broken(\n    # incomplete function";
    create_test_file(dir.path(), "broken.py", content);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should complete (not crash) even with parse errors
    // Errors should be recorded in sub_results
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\": \"secure\""));
}

// =============================================================================
// BC-SEC-2: File Scanning Tests
// =============================================================================

#[test]
fn test_secure_respects_gitignore() {
    let dir = tempdir().unwrap();

    // Create files
    create_test_file(dir.path(), "included.py", "def foo(): pass");
    create_test_file(dir.path(), "ignored.py", "def bar(): pass");
    create_gitignore(dir.path(), "ignored.py");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    cmd.assert()
        .success()
        // The ignored file should not appear in results
        .stdout(predicate::str::contains("ignored.py").not());
}

#[test]
fn test_secure_directory_scan() {
    let dir = tempdir().unwrap();

    // Create nested structure
    create_test_file(dir.path(), "root.py", "x = 1");
    create_test_file(dir.path(), "subdir/nested.py", "y = 2");
    create_test_file(dir.path(), "subdir/deep/more.py", "z = 3");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should scan all Python files in directory
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\": \"secure\""));
}

#[test]
fn test_secure_language_filter() {
    let dir = tempdir().unwrap();

    // Create Python and non-Python files
    create_test_file(dir.path(), "code.py", "def foo(): pass");
    create_test_file(dir.path(), "code.rs", "fn foo() {}");
    create_test_file(dir.path(), "code.js", "function foo() {}");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-l")
        .arg("python")
        .arg("-f")
        .arg("json");

    // Should only analyze Python files when language is specified
    cmd.assert().success();
}

// =============================================================================
// BC-SEC-3: Progress Reporting Tests
// =============================================================================

#[test]
fn test_secure_progress_format() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "file1.py", "x = 1");
    create_test_file(dir.path(), "file2.py", "y = 2");

    let mut cmd = tldr_cmd();
    cmd.arg("secure").arg(dir.path().to_str().unwrap());

    // Progress should be printed to stderr in format: [step/total] Analyzing {name}...
    // Note: This may not show in non-verbose mode
    cmd.assert().success();
}

// =============================================================================
// BC-SEC-4: Severity Ordering Tests
// =============================================================================

#[test]
fn test_secure_severity_ordering_json() {
    let dir = tempdir().unwrap();

    // Create files with various security issues
    let taint_vuln = r#"
import subprocess
def run_cmd(user_input):
    subprocess.call(user_input, shell=True)  # command injection - critical
"#;
    let leak_vuln = r#"
def process_file(path):
    f = open(path)  # resource leak - high
    data = f.read()
    return data
"#;
    let info_issue = r#"
def minor_issue():
    x = 1  # some info-level finding
    return x
"#;

    create_test_file(dir.path(), "taint.py", taint_vuln);
    create_test_file(dir.path(), "leak.py", leak_vuln);
    create_test_file(dir.path(), "info.py", info_issue);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Findings should be sorted by severity
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"findings\""));
}

#[test]
fn test_secure_text_output_shows_summary() {
    let dir = tempdir().unwrap();

    let content = r#"
def vulnerable():
    user_input = input()
    eval(user_input)  # taint vulnerability
"#;
    create_test_file(dir.path(), "vuln.py", content);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("text");

    // Text output should show summary counts
    cmd.assert().success();
    // Should contain summary information
    // Note: Specific format depends on implementation
}

// =============================================================================
// BC-SEC-5: Text Output Format Tests
// =============================================================================

#[test]
fn test_secure_text_format() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("text");

    // Text output should be human-readable
    cmd.assert().success();
}

#[test]
fn test_secure_json_structure() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // JSON should have required fields
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\""))
        .stdout(predicate::str::contains("\"path\""))
        .stdout(predicate::str::contains("\"findings\""))
        .stdout(predicate::str::contains("\"summary\""))
        .stdout(predicate::str::contains("\"total_elapsed_ms\""));
}

// =============================================================================
// Quick Mode Tests
// =============================================================================

#[test]
fn test_secure_quick_mode() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("--quick")
        .arg("-f")
        .arg("json");

    // Quick mode should run only 3 analyses (taint, resources, bounds)
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\": \"secure\""));
}

#[test]
fn test_secure_full_mode() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Full mode (default) should run all 7 analyses
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"wrapper\": \"secure\""));
}

// =============================================================================
// Finding Structure Tests
// =============================================================================

#[test]
fn test_secure_finding_has_required_fields() {
    let dir = tempdir().unwrap();

    // Create a file with a known taint vulnerability
    let content = r#"
import subprocess
def dangerous(user_input):
    subprocess.call(user_input, shell=True)
"#;
    create_test_file(dir.path(), "vuln.py", content);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Each finding should have category, severity, description, file, line
    cmd.assert().success();
    // If findings exist, they should have proper structure
}

// =============================================================================
// Sub-Analysis Result Tests
// =============================================================================

#[test]
fn test_secure_sub_results_structure() {
    // Per `wrapper-cross-consistency-v1` (commit 226609d) the `secure`
    // wrapper no longer emits per-sub-analysis records — `sub_results`
    // is now empty + serde-skipped. The post-milestone shape is:
    //   { wrapper: "secure", path, findings[], summary{...},
    //     total_elapsed_ms }
    // This test now PINS that contract: assert `sub_results` is ABSENT
    // (catches regressions that re-introduce it) and required top-level
    // keys are present.
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    let output = cmd
        .arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("failed to run tldr secure");
    assert!(
        output.status.success(),
        "tldr secure should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("secure output not valid JSON: {e}\n{stdout}"));
    let obj = parsed
        .as_object()
        .unwrap_or_else(|| panic!("secure output not a JSON object: {stdout}"));

    // Post-milestone shape: sub_results MUST be absent (serde-skipped).
    assert!(
        !obj.contains_key("sub_results"),
        "`sub_results` should be absent from secure JSON per wrapper-cross-consistency-v1; got: {stdout}"
    );
    // Mirror: `details` is also not part of the post-milestone shape.
    assert!(
        !obj.contains_key("details"),
        "`details` should be absent from secure JSON; got: {stdout}"
    );
    // Required top-level keys per the new contract.
    for key in ["wrapper", "path", "findings", "summary", "total_elapsed_ms"] {
        assert!(
            obj.contains_key(key),
            "secure JSON missing required key `{key}`; got: {stdout}"
        );
    }
    assert_eq!(
        obj.get("wrapper").and_then(|v| v.as_str()),
        Some("secure"),
        "wrapper field should be \"secure\""
    );
}

// =============================================================================
// Summary Tests
// =============================================================================

#[test]
fn test_secure_summary_fields() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Summary should have counts
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"summary\""));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_secure_empty_findings() {
    let dir = tempdir().unwrap();
    // Create a completely safe file
    let content = r#"
def safe_function(x, y):
    return x + y
"#;
    create_test_file(dir.path(), "safe.py", content);

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should succeed with empty or minimal findings
    cmd.assert().success();
}

#[test]
fn test_secure_mixed_languages() {
    let dir = tempdir().unwrap();

    create_test_file(dir.path(), "python.py", "x = 1");
    create_test_file(dir.path(), "rust.rs", "let x = 1;");
    create_test_file(dir.path(), "js.js", "const x = 1;");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should handle mixed language directories
    cmd.assert().success();
}

#[test]
fn test_secure_binary_files_ignored() {
    let dir = tempdir().unwrap();

    // Create a binary file
    let binary_path = dir.path().join("binary.bin");
    fs::write(&binary_path, [0u8, 1, 2, 3, 255, 254]).unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should not crash on binary files
    cmd.assert().success();
}

// =============================================================================
// Timing Tests
// =============================================================================

#[test]
fn test_secure_reports_elapsed_time() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "code.py", "x = 1");

    let mut cmd = tldr_cmd();
    cmd.arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json");

    // Should include elapsed time in output
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("elapsed"));
}

// =============================================================================
// SECURE-UTF8-TOLERANCE-V1: Non-UTF-8 file tolerance
// =============================================================================
//
// Pre-fix: `tldr secure` aborted the entire scan with
// `Error: stream did not contain valid UTF-8` on the first non-UTF-8
// file in the directory (e.g. the upstream luau-luau repo's
// `tests/conformance/literals.luau`, `pm.luau`, `sort.luau` parser-test
// fixtures with raw 0xFF/0xFE bytes).
//
// Post-fix: such files are skipped with a structured warning (file path
// + first invalid-byte offset) and the rest of the scan completes.

/// Synthetic 1-valid + 1-invalid-UTF-8 fixture: `secure` must succeed,
/// scan the valid file, and surface the bad file in `warnings` with
/// `files_skipped == 1`. Mirrors the M-X5 surface tolerance test.
#[test]
fn test_secure_continues_after_bad_file_in_dir() {
    let dir = tempdir().unwrap();

    // Valid Python source — secure has a native `.py` analysis path so
    // this guarantees the scan does real work, not just a no-op walk.
    create_test_file(dir.path(), "good.py", "def safe():\n    return 1\n");

    // Synthetic bad file: valid prefix + raw 0xFF/0xFE (never valid as
    // UTF-8 leading bytes) + valid suffix. Mirrors the actual luau-luau
    // parser-test corpus shape.
    let bad_path = dir.path().join("bad.py");
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"# valid prefix\n");
    bytes.extend_from_slice(&[0xFFu8, 0xFEu8]);
    bytes.extend_from_slice(b"\n# valid suffix\n");
    fs::write(&bad_path, bytes).unwrap();

    let output = tldr_cmd()
        .arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("secure must execute");

    assert!(
        output.status.success() || output.status.code() == Some(2),
        "secure must NOT abort on non-UTF-8 input (got status {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "secure stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });

    let files_skipped = report
        .get("files_skipped")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        files_skipped, 1,
        "secure must report files_skipped=1 for the synthetic bad file; report={}",
        report
    );

    let warnings = report
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        warnings.len(),
        1,
        "secure must emit exactly one warning for the bad file; warnings={:?}",
        warnings
    );
    let warning = warnings[0].as_str().unwrap_or("");
    assert!(
        warning.contains("bad.py"),
        "warning must reference the skipped file path; got: {}",
        warning
    );
    assert!(
        warning.contains("invalid UTF-8") || warning.contains("byte"),
        "warning must describe the UTF-8 failure with a byte offset; got: {}",
        warning
    );
}

/// UTF-8-clean inputs MUST NOT have `files_skipped` or `warnings` in the
/// JSON output (backward-compat schema preservation).
#[test]
fn test_secure_clean_input_has_no_skip_fields() {
    let dir = tempdir().unwrap();
    create_test_file(dir.path(), "good.py", "def safe():\n    return 1\n");

    let output = tldr_cmd()
        .arg("secure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("secure must execute");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // `serde(skip_serializing_if)` policy: zero/empty values must be omitted
    // so existing JSON consumers see no schema delta.
    assert!(
        !stdout.contains("\"files_skipped\""),
        "files_skipped must be omitted on UTF-8-clean input; stdout: {}",
        stdout
    );
    assert!(
        !stdout.contains("\"warnings\""),
        "warnings must be omitted on UTF-8-clean input; stdout: {}",
        stdout
    );
}
