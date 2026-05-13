//! cli-error-clarity-v2: close 3 MED bugs sharing the surface
//! "CLI says one thing, runtime does another".
//!
//! - P2.BUG-4 — `tldr hubs|impact|whatbreaks|change-impact <file>` previously
//!   said "Path not found" (false: the file exists) or surfaced the cryptic
//!   git "Not a directory (os error 20)". The four directory-taking commands
//!   now return a clear error mentioning the file path and how to fix it.
//!
//! - P2.BUG-5 — Per-command `--help` advertised every value of the global
//!   `--format` enum (sarif, dot, …) even when the runtime rejects them with
//!   "not supported by <cmd>". The global `--format` flag now hides its
//!   possible values; the long-help text instead enumerates which commands
//!   actually emit each command-specific format. As a result, for any
//!   command that does NOT support sarif, the help text no longer lists
//!   "sarif" as a possible value, eliminating the help/runtime mismatch.
//!
//! - P2.BUG-8 — `tldr context <fn> <project-root>` returned 0 functions when
//!   the same function was found from a deeper directory. Root cause:
//!   `find_function_in_graph` returned the FIRST edge match. If a test
//!   fixture (e.g. `tests/test_config.py`) defined a placeholder class with
//!   the same name as the real implementation, the first edge could land on
//!   the placeholder. The fix iterates ALL candidate locations and prefers
//!   ones whose extracted module actually contains the function definition,
//!   with non-test paths preferred when ties remain.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// P2.BUG-4: directory-taking commands reject files with a clear error
// =============================================================================

/// Build a temp project containing a single .py file. Returns (TempDir, file
/// path) so the caller can reference both. The directory itself is a valid
/// project root; the file is a regular file under it.
fn make_temp_project_with_file() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("foo.py");
    fs::write(&path, "def bar():\n    return 1\n").unwrap();
    (temp, path)
}

/// Helper: assert the command failed with a clear "requires a directory"
/// error mentioning the file path.
fn assert_clear_file_error(cmd_name: &str, args: &[&str]) {
    let assert = tldr_cmd().args(args).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains(&format!("{} requires a directory", cmd_name)),
        "expected '{} requires a directory' in stderr; got:\n{}",
        cmd_name,
        stderr
    );
    // Must mention the file path so the user sees their mistake echoed back.
    let file_arg = args.iter().rev().find(|a| a.contains("foo.py")).unwrap();
    assert!(
        stderr.contains(*file_arg),
        "expected file path '{}' in stderr; got:\n{}",
        file_arg,
        stderr
    );
}

#[test]
fn hubs_on_file_clear_error() {
    let (_temp, file) = make_temp_project_with_file();
    let file_str = file.to_string_lossy().to_string();
    assert_clear_file_error("hubs", &["hubs", &file_str, "-q"]);
}

#[test]
fn impact_on_file_clear_error() {
    let (_temp, file) = make_temp_project_with_file();
    let file_str = file.to_string_lossy().to_string();
    assert_clear_file_error("impact", &["impact", "bar", &file_str, "-q"]);
}

#[test]
fn whatbreaks_on_file_clear_error() {
    let (_temp, file) = make_temp_project_with_file();
    let file_str = file.to_string_lossy().to_string();
    assert_clear_file_error("whatbreaks", &["whatbreaks", "bar", &file_str, "-q"]);
}

// change-impact-file-or-dir-v1 (v0.4.2 bug-D1-D4): change-impact now
// ACCEPTS a regular file path and promotes it to a single-file change
// set. The original P2.BUG-4 contract (reject file with clear error) no
// longer applies to change-impact — the inconsistency with other
// inference commands (dead, smells, …) was the bug. The other three
// commands (hubs, impact, whatbreaks) still reject files because they do
// not have a "scope to one file" semantics.
//
// This test pins the new contract: passing a regular file succeeds and
// emits a valid JSON report.
#[test]
fn change_impact_on_file_now_succeeds() {
    let (_temp, file) = make_temp_project_with_file();
    let file_str = file.to_string_lossy().to_string();
    let assert = tldr_cmd()
        .args(["change-impact", &file_str, "--format", "json", "-q"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("change-impact must emit valid JSON");
    assert!(
        v.get("status").is_some(),
        "expected status field in report; got: {}",
        v
    );
}

// =============================================================================
// P2.BUG-5: per-command --help no longer advertises formats the runtime
// rejects. We test by parsing the `--help` output and confirming that for
// commands which DO NOT support sarif/dot, the help text does not list those
// values under "Possible values".
// =============================================================================

/// Extract the body of the `--format` help block from `tldr <cmd> --help`.
fn format_help_body(cmd: &str) -> String {
    let out = tldr_cmd()
        .args([cmd, "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    // Take everything from `--format` to the next double-newline-section
    // break. We use a generous slice since the body may span multiple lines.
    let start = s
        .find("--format")
        .expect("--format present in help");
    s[start..].to_string()
}

#[test]
fn format_help_matches_runtime_calls() {
    // `calls` does NOT support sarif. Its help must not list sarif as a
    // possible value, and its runtime rejects sarif. The two surfaces are
    // therefore consistent.
    let body = format_help_body("calls");
    assert!(
        !body.contains("Possible values:") || !body.contains("- sarif"),
        "calls --help must not list sarif as a possible value; got:\n{}",
        body
    );

    // Confirm runtime still rejects sarif on calls (this guards against a
    // regression where someone "fixes" the help by silently widening the
    // runtime).
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a.py"), "def x():\n    pass\n").unwrap();
    let assert = tldr_cmd()
        .args([
            "calls",
            temp.path().to_str().unwrap(),
            "--format",
            "sarif",
            "-q",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("not supported by calls"),
        "calls --format sarif should still be rejected by runtime; got:\n{}",
        stderr
    );
}

#[test]
fn format_help_matches_runtime_structure() {
    // `structure` does NOT support sarif or dot. Confirm both sides agree.
    let body = format_help_body("structure");
    assert!(
        !body.contains("Possible values:") || !body.contains("- sarif"),
        "structure --help must not list sarif; got:\n{}",
        body
    );
    assert!(
        !body.contains("Possible values:") || !body.contains("- dot"),
        "structure --help must not list dot; got:\n{}",
        body
    );

    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a.py"), "def x():\n    pass\n").unwrap();
    for fmt in ["sarif", "dot"] {
        let assert = tldr_cmd()
            .args([
                "structure",
                temp.path().to_str().unwrap(),
                "--format",
                fmt,
                "-q",
            ])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
        assert!(
            stderr.contains(&format!("not supported by structure")),
            "structure --format {} should be rejected; got:\n{}",
            fmt,
            stderr
        );
    }
}

// =============================================================================
// P2.BUG-8: `context` works from the project root, not just from inner src/
// =============================================================================

#[test]
fn context_works_from_repo_root() {
    // Build a fixture mini-repo whose layout mimics the bug repro:
    //
    //   <root>/
    //     src/
    //       pkg/
    //         core.py        # defines class Foo with method bar
    //     tests/
    //       test_dummy.py    # placeholder class Foo with NO methods
    //
    // Pre-fix: walking from `<root>` made the call graph see the placeholder
    // first; `tldr context bar <root>` returned 0 functions. Walking from
    // `<root>/src` worked. Post-fix: both should return >= 1 function.
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src/pkg");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("core.py"),
        "class Foo:\n    def bar(self):\n        return helper()\n\ndef helper():\n    return 1\n",
    )
    .unwrap();

    let tests = temp.path().join("tests");
    fs::create_dir_all(&tests).unwrap();
    fs::write(
        tests.join("test_dummy.py"),
        // Placeholder Foo with no body — same name, no methods. This is what
        // makes find_function_in_graph pick the wrong edge pre-fix.
        "class Foo:\n    pass\n",
    )
    .unwrap();

    // From the repo root: must find Foo.bar (>= 1 function in context).
    let out_root = tldr_cmd()
        .args([
            "context",
            "Foo.bar",
            temp.path().to_str().unwrap(),
            "--depth",
            "1",
            "-q",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out_root).expect("context returns JSON");
    let n_root = v["functions"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        n_root >= 1,
        "context Foo.bar from repo root should find >= 1 function, got {}; output: {}",
        n_root,
        String::from_utf8_lossy(&out_root)
    );

    // From the inner src/ directory the count should be at least the same
    // (this is the scope the bug report contrasts against).
    let out_src = tldr_cmd()
        .args([
            "context",
            "Foo.bar",
            temp.path().join("src").to_str().unwrap(),
            "--depth",
            "1",
            "-q",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v_src: Value = serde_json::from_slice(&out_src).unwrap();
    let n_src = v_src["functions"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    assert!(
        n_root >= n_src,
        "context from repo root ({}) should be >= context from src ({})",
        n_root,
        n_src
    );
}
