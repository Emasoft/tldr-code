//! issue-2 (impact-file-arg-v1): `tldr impact <fn> <path>` must accept a
//! FILE path (resolving the enclosing project root), not just a directory.
//!
//! Before: crates/tldr-cli/src/commands/impact.rs:59 called
//! `require_directory` unconditionally, so passing any file failed with
//! "impact requires a directory; got file '...'"
//! (crates/tldr-cli/src/path_validation.rs:28-49) even though the enclosing
//! project root was unambiguous.
//!
//! After: a file argument resolves its project root with the same walk-up
//! `tldr explain` uses (crates/tldr-cli/src/commands/remaining/explain.rs
//! `explain_project_root`), the language comes from the file's extension
//! (crates/tldr-core/src/types.rs:208 `Language::from_path`), and the
//! project graph, AST fallback, and references enrichment all run against
//! the resolved root (commands/impact.rs `ImpactArgs::run`).
//!
//! The fixture mirrors the temp-project style of cli_graph_tests.rs:21-45:
//! a Python project where a.py's `func_a` calls b.py's `func_b`. The
//! file-argument invocation passes the CALLER file (a.py) while querying
//! the CALLEE (`func_b`, defined in b.py) — which also proves the file
//! argument is not misused as a target-side file filter: the core filter
//! (crates/tldr-core/src/analysis/impact.rs:144-149) restricts the target's
//! own file, so scoping targets to a.py would lose the b.py target and
//! report FunctionNotFound.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Temp Python project: a.py defines `func_a` which calls `func_b`;
/// b.py defines `func_b`. Returns the TempDir root.
fn create_caller_callee_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("a.py"),
        "def func_a():\n    return func_b()\n",
    )
    .unwrap();

    fs::write(project_path.join("b.py"), "def func_b():\n    return 1\n").unwrap();

    temp_dir
}

/// Run `tldr impact` with the given args; returns (exit_ok, stdout).
fn run_impact_json(args: &[&str]) -> (bool, String) {
    let output = tldr_cmd()
        .args(args)
        .output()
        .expect("Failed to execute tldr impact");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

/// The JSON must parse, `targets` must contain the queried callee, and the
/// callee's caller_count must be >= 1 (the caller lives in the other file).
fn assert_callee_with_callers(stdout: &str, callee: &str) {
    let v: Value =
        serde_json::from_str(stdout).expect("impact --format json must emit valid JSON");
    let targets = v["targets"]
        .as_object()
        .expect("impact JSON must contain a 'targets' object");
    assert!(
        !targets.is_empty(),
        "targets must not be empty; got:\n{}",
        stdout
    );
    let caller_counts: Vec<u64> = targets
        .values()
        .filter(|t| t["function"] == callee)
        .map(|t| t["caller_count"].as_u64().unwrap_or(0))
        .collect();
    assert!(
        !caller_counts.is_empty(),
        "targets must contain the callee '{}'; got:\n{}",
        callee,
        stdout
    );
    assert!(
        caller_counts.iter().any(|&n| n >= 1),
        "callee '{}' must have caller_count >= 1; got:\n{}",
        callee,
        stdout
    );
}

/// issue-2: a FILE path (the caller file) is accepted; the callee defined
/// in a sibling file is still found with its callers.
#[test]
fn impact_accepts_caller_file_and_finds_callee() {
    let temp = create_caller_callee_project();
    let caller_file = temp.path().join("a.py");
    let caller_file_str = caller_file.to_string_lossy().to_string();

    let (ok, stdout) = run_impact_json(&[
        "impact",
        "func_b",
        &caller_file_str,
        "--format",
        "json",
        "-q",
    ]);
    assert!(
        ok,
        "impact with a FILE path should exit 0; stdout:\n{}",
        stdout
    );
    assert_callee_with_callers(&stdout, "func_b");
}

/// issue-2: a FILE path (the callee's own definition file) is accepted too.
#[test]
fn impact_accepts_callee_file_and_finds_callee() {
    let temp = create_caller_callee_project();
    let callee_file = temp.path().join("b.py");
    let callee_file_str = callee_file.to_string_lossy().to_string();

    let (ok, stdout) = run_impact_json(&[
        "impact",
        "func_b",
        &callee_file_str,
        "--format",
        "json",
        "-q",
    ]);
    assert!(
        ok,
        "impact with the callee's FILE path should exit 0; stdout:\n{}",
        stdout
    );
    assert_callee_with_callers(&stdout, "func_b");
}

/// issue-2: parity — the identical invocation with the project DIR works
/// and reports the same callee with callers.
#[test]
fn impact_file_and_dir_invocations_agree() {
    let temp = create_caller_callee_project();
    let dir_str = temp.path().to_string_lossy().to_string();
    let caller_file_str = temp.path().join("a.py").to_string_lossy().to_string();

    let (ok_dir, stdout_dir) =
        run_impact_json(&["impact", "func_b", &dir_str, "--format", "json", "-q"]);
    assert!(
        ok_dir,
        "impact with the project DIR should exit 0; stdout:\n{}",
        stdout_dir
    );
    assert_callee_with_callers(&stdout_dir, "func_b");

    let (ok_file, stdout_file) = run_impact_json(&[
        "impact",
        "func_b",
        &caller_file_str,
        "--format",
        "json",
        "-q",
    ]);
    assert!(
        ok_file,
        "impact with a FILE path should exit 0 (parity with DIR); stdout:\n{}",
        stdout_file
    );
    assert_callee_with_callers(&stdout_file, "func_b");
}
