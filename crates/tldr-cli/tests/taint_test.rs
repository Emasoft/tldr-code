//! Tests for the taint analysis CLI command
//!
//! Phase 8: CLI integration for taint analysis

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

/// Helper to create a test Python file with taint patterns
fn create_test_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).expect("Failed to write test file");
    path
}

#[test]
fn test_taint_help() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("taint"))
        .stdout(predicate::str::contains("FUNCTION"));
}

#[test]
fn test_taint_missing_args() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_taint_json_output() {
    let dir = tempdir().unwrap();
    let content = r#"
def vulnerable(user_data):
    query = "SELECT * FROM users WHERE id = " + user_data
    cursor.execute(query)
"#;
    let file = create_test_file(dir.path(), "vuln.py", content);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint")
        .arg(file.to_str().unwrap())
        .arg("vulnerable")
        .arg("-f")
        .arg("json");

    // Parse rather than substring-match: `"function"` matches the wire key
    // (TaintInfo: #[serde(rename = "function")]) but equally any string VALUE
    // spelled `function`, so a substring check could pass on a payload missing
    // the key. Keep `out.assert()` rather than `assert!(out.status.success())`:
    // it carries assert_cmd's full failure report — command, status, stdout AND
    // stderr — into the panic, all of which a bare status check throws away.
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    out.assert().success();
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("taint --format json");
    assert_eq!(
        json.get("function").and_then(|v| v.as_str()),
        Some("vulnerable"),
        "taint JSON must carry the wire key `function`; got: {stdout}"
    );
}

#[test]
fn test_taint_text_output() {
    let dir = tempdir().unwrap();
    let content = r#"
def vulnerable():
    user_input = input("Enter ID: ")
    eval(user_input)
"#;
    let file = create_test_file(dir.path(), "eval_vuln.py", content);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint")
        .arg(file.to_str().unwrap())
        .arg("vulnerable")
        .arg("-f")
        .arg("text");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Taint Analysis"))
        .stdout(predicate::str::contains("Sources"));
}

#[test]
fn test_taint_file_not_found() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint")
        .arg("/nonexistent/file.py")
        .arg("test_func");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No such file")));
}

#[test]
fn test_taint_function_not_found() {
    let dir = tempdir().unwrap();
    let content = r#"
def existing_func():
    pass
"#;
    let file = create_test_file(dir.path(), "test.py", content);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint")
        .arg(file.to_str().unwrap())
        .arg("nonexistent_func");

    // why: `let _ = cmd.assert()` discards the `Assert` without checking
    // anything, so this test could never fail. `Command::output()` still
    // proves the process ran to completion (no crash/signal) without
    // asserting a specific exit code, matching the "may vary" intent.
    let output = cmd.output().expect("tldr taint should not fail to spawn");
    assert!(
        output.status.code().is_some(),
        "tldr taint should exit normally, not crash: {:?}",
        output
    );
}

#[test]
fn test_taint_detects_sql_injection() {
    let dir = tempdir().unwrap();
    let content = r#"
def process_user():
    user_id = input("Enter ID: ")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"#;
    let file = create_test_file(dir.path(), "sql_injection.py", content);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("taint")
        .arg(file.to_str().unwrap())
        .arg("process_user")
        .arg("-f")
        .arg("json");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("sources"))
        .stdout(predicate::str::contains("sinks"));
}

#[test]
fn test_taint_alias_works() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("ta").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("taint"));
}
