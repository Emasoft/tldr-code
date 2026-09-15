//! chop-deps-between-v1 (issue #3)
//!
//! Makes `chop` semantics impossible to misuse:
//!
//! 1. `deps-between` is now the visible help alias (semantics-obvious: the
//!    command returns the dependency closure between two lines, NOT a
//!    contiguous line range). `chp` keeps working as a hidden back-compat
//!    alias and `chop` remains the canonical name.
//! 2. `tldr chop --help` carries a loud warning that the output is NOT
//!    bounded by FROM..TO, so nobody uses it as a line-range extractor.
//!
//! Fixture: minimal dataflow copied from tests/fixtures/simple.py — line 2
//! (`x = 1`) flows into line 5 (`return z`), so a dependency path exists.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Temp Python project with a real dataflow dependency between two lines.
fn fixture() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::write(
        dir.path().join("simple.py"),
        "def main():\n    x = 1\n    y = x + 1\n    z = y * 2\n    return z\n",
    )
    .unwrap();
    dir
}

/// Run `tldr <alias> <file> main 2 5 --format json`, return (stdout, success).
fn run_chop_as(alias: &str, dir: &TempDir) -> (String, bool) {
    let file = dir.path().join("simple.py");
    let output = tldr_cmd()
        .args([
            alias,
            file.to_str().unwrap(),
            "main",
            "2",
            "5",
            "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run tldr {alias}: {e}"));
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        output.status.success(),
    )
}

/// (a) `deps-between` and `chop` must behave identically: exit 0 and
/// byte-identical JSON on stdout.
#[test]
fn deps_between_alias_matches_chop_json() {
    let dir = fixture();

    let (deps_out, deps_ok) = run_chop_as("deps-between", &dir);
    let (chop_out, chop_ok) = run_chop_as("chop", &dir);

    assert!(
        deps_ok,
        "tldr deps-between should exit 0; stdout:\n{deps_out}"
    );
    assert!(chop_ok, "tldr chop should exit 0; stdout:\n{chop_out}");

    assert_eq!(
        deps_out, chop_out,
        "deps-between and chop must emit identical JSON"
    );

    // Sanity: the payload is real JSON describing the dependency closure
    // between the two lines (x = 1 at line 2 flows into `return z` at 5).
    let parsed: serde_json::Value =
        serde_json::from_str(&deps_out).expect("stdout should be valid JSON");
    assert_eq!(
        parsed["path_exists"], true,
        "fixture has a real dependency path 2 -> 5"
    );
    let lines = parsed["lines"]
        .as_array()
        .expect("chop JSON should carry a `lines` array");
    assert!(
        !lines.is_empty(),
        "closure between 2 and 5 should contain the path lines"
    );
}

/// (b) `tldr chop --help` must loudly warn that chop is a dependency
/// closure, NOT a contiguous line-range extractor.
#[test]
fn chop_help_warns_not_a_line_range_extractor() {
    let output = tldr_cmd()
        .args(["chop", "--help"])
        .output()
        .expect("failed to run tldr chop --help");
    assert!(output.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        help.contains("not a line-range extractor"),
        "help must say the output is NOT a line-range extract; got:\n{help}"
    );
    assert!(
        help.contains("contiguous"),
        "help must point to contiguous-source alternatives; got:\n{help}"
    );
}

/// (c) The old `chp` spelling keeps working as a hidden back-compat alias
/// and produces the exact same JSON as `chop`.
#[test]
fn chp_hidden_alias_still_works() {
    let dir = fixture();

    let (chp_out, chp_ok) = run_chop_as("chp", &dir);
    let (chop_out, chop_ok) = run_chop_as("chop", &dir);

    assert!(chp_ok, "tldr chp should exit 0; stdout:\n{chp_out}");
    assert!(chop_ok, "tldr chop should exit 0; stdout:\n{chop_out}");
    assert_eq!(chp_out, chop_out, "chp and chop must emit identical JSON");
}

/// The new visible alias must be advertised in the top-level help (that is
/// what makes the closure semantics discoverable from `tldr --help`).
#[test]
fn top_level_help_shows_deps_between_alias() {
    let output = tldr_cmd()
        .args(["--help"])
        .output()
        .expect("failed to run tldr --help");
    assert!(output.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("deps-between"),
        "top-level help should advertise the visible alias deps-between; got:\n{help}"
    );
}
