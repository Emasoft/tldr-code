//! format-flag-strictness-v1
//!
//! Verifies that `tldr <cmd> --format <fmt>` errors out when the requested
//! format is not actually supported by `<cmd>`, instead of silently falling
//! back to plain JSON. Prior to this fix, callers wiring up CI integrations
//! (e.g. SARIF for GitHub code-scanning) believed SARIF was being emitted
//! when it was not — a security false-trust hazard.
//!
//! Universal formats (json, text, compact) are always allowed. SARIF and DOT
//! are gated by the centralized validator in `output::validate_format_for_command`.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Build a tiny Python project so commands have something to scan.
fn fixture() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::write(
        dir.path().join("a.py"),
        "def foo():\n    return 1\n\ndef bar():\n    return foo()\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("b.py"),
        "from a import foo\n\ndef baz():\n    return foo()\n",
    )
    .unwrap();
    dir
}

// =============================================================================
// SARIF: unsupported commands must error
// =============================================================================

/// Each pair is (subcommand_args, expected_format) — running with
/// `--format sarif` against any of these must exit non-zero with a
/// "not supported" error. These are the commands flagged by the v0.2.2
/// audit as silently falling back to plain JSON when given `--format sarif`.
fn unsupported_sarif_cases() -> Vec<&'static [&'static str]> {
    vec![
        &["smells"][..],
        &["dead"][..],
        &["health"][..],
        &["api-check"][..],
        &["secure"][..],
        &["debt"][..],
        &["structure"][..],
        &["tree"][..],
        // taint and reaching-defs previously had no-op SARIF arms that fell
        // back to JSON — they must now error too.
        &["taint", "a.py", "foo"][..],
        &["reaching-defs", "a.py", "foo"][..],
    ]
}

#[test]
fn sarif_errors_on_unsupported_commands() {
    let dir = fixture();
    for case in unsupported_sarif_cases() {
        let mut cmd = tldr_cmd();
        cmd.current_dir(dir.path());
        cmd.args(case);
        cmd.args(["--format", "sarif"]);
        // Most commands that take a path default to "." — append the fixture
        // dir for path-taking subcommands. Subcommands that take explicit
        // file/function args (taint, reaching-defs) already include them.
        let needs_path = !matches!(case[0], "taint" | "reaching-defs");
        if needs_path {
            cmd.arg(".");
        }
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("not supported"))
            .stderr(predicate::str::contains("sarif"));
    }
}

// =============================================================================
// DOT: unsupported commands must error
// =============================================================================

#[test]
fn dot_errors_on_smells() {
    let dir = fixture();
    let mut cmd = tldr_cmd();
    cmd.current_dir(dir.path())
        .args(["smells", ".", "--format", "dot"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not supported"));
}

// =============================================================================
// Supported pairs: no regression
// =============================================================================

#[test]
fn vuln_format_sarif_still_works() {
    // Regression guard: vuln must continue to emit a real SARIF document.
    let dir = fixture();
    let mut cmd = tldr_cmd();
    cmd.current_dir(dir.path()).args([
        "vuln", ".", "--lang", "python", "--format", "sarif", "--quiet",
    ]);
    let output = cmd.output().expect("run tldr vuln");
    // vuln exits non-zero when it finds findings, but we don't care about
    // that here — we only care that the format wasn't rejected pre-dispatch.
    // A pre-dispatch rejection prints "not supported" on stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("not supported"),
        "vuln --format sarif must not be rejected; got stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Real SARIF documents carry a $schema field.
    assert!(
        stdout.contains("$schema") || stdout.contains("\"version\""),
        "vuln --format sarif should emit SARIF; got stdout prefix: {}",
        &stdout.chars().take(200).collect::<String>()
    );
}

#[test]
fn clones_format_sarif_still_works() {
    let dir = fixture();
    let mut cmd = tldr_cmd();
    cmd.current_dir(dir.path())
        .args(["clones", ".", "--format", "sarif", "--quiet"]);
    cmd.assert().success();
}

#[test]
fn deps_format_dot_still_works() {
    let dir = fixture();
    let mut cmd = tldr_cmd();
    cmd.current_dir(dir.path())
        .args(["deps", ".", "--format", "dot", "--quiet"]);
    cmd.assert().success();
}

#[test]
fn json_works_universally() {
    // JSON is the universal format — every command must accept it.
    let dir = fixture();
    for cmd_args in [
        &["smells"][..],
        &["tree"][..],
        &["structure"][..],
        &["calls"][..],
        &["dead"][..],
    ] {
        let mut cmd = tldr_cmd();
        cmd.current_dir(dir.path());
        cmd.args(cmd_args);
        cmd.arg(".");
        cmd.args(["--format", "json", "--quiet"]);
        let output = cmd.output().expect("run tldr");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("not supported"),
            "json must be accepted by {:?}; got stderr: {stderr}",
            cmd_args
        );
    }
}

// =============================================================================
// Unit tests on the validator itself
// =============================================================================

#[test]
fn validator_unit_universal_formats() {
    use tldr_cli::output::{validate_format_for_command, OutputFormat};
    for fmt in [
        OutputFormat::Json,
        OutputFormat::Text,
        OutputFormat::Compact,
    ] {
        for cmd in ["smells", "vuln", "tree", "calls", "structure"] {
            assert!(
                validate_format_for_command(cmd, fmt).is_ok(),
                "{cmd}/{:?} must be accepted",
                fmt
            );
        }
    }
}

#[test]
fn validator_unit_sarif_allowlist() {
    use tldr_cli::output::{validate_format_for_command, OutputFormat};
    assert!(validate_format_for_command("vuln", OutputFormat::Sarif).is_ok());
    assert!(validate_format_for_command("clones", OutputFormat::Sarif).is_ok());
    for cmd in [
        "smells",
        "dead",
        "health",
        "api-check",
        "secure",
        "debt",
        "structure",
        "tree",
        "halstead",
        "complexity",
        "extract",
        "taint",
        "reaching-defs",
    ] {
        let err = validate_format_for_command(cmd, OutputFormat::Sarif)
            .expect_err(&format!("{cmd} must reject sarif"));
        assert!(err.contains("not supported"));
        assert!(err.contains(cmd));
    }
}

#[test]
fn validator_unit_dot_allowlist() {
    use tldr_cli::output::{validate_format_for_command, OutputFormat};
    // Pre-existing DOT emitters.
    assert!(validate_format_for_command("clones", OutputFormat::Dot).is_ok());
    assert!(validate_format_for_command("deps", OutputFormat::Dot).is_ok());
    // surface-gaps-v1 (BUG-19): call-graph and class-hierarchy commands
    // are the canonical DOT use cases and are now allowed.
    assert!(validate_format_for_command("calls", OutputFormat::Dot).is_ok());
    assert!(validate_format_for_command("impact", OutputFormat::Dot).is_ok());
    assert!(validate_format_for_command("hubs", OutputFormat::Dot).is_ok());
    assert!(validate_format_for_command("inheritance", OutputFormat::Dot).is_ok());
    // Commands that don't emit DOT must still reject the flag instead of
    // silently falling back to JSON (the original false-trust hazard).
    for cmd in ["smells", "tree", "structure", "taint", "vuln", "secrets"] {
        let err = validate_format_for_command(cmd, OutputFormat::Dot)
            .expect_err(&format!("{cmd} must reject dot"));
        assert!(err.contains("not supported"));
    }
}
