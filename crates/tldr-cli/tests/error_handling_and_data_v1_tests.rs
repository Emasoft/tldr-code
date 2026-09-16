//! Tests for `error-handling-and-data-v1` milestone.
//!
//! Covers four bugs:
//! - BUG-05: `tldr todo` items had `line=0/1` placeholders for dead-code and
//!   complexity categories.
//! - BUG-11: missing path returned exit 0 with empty output for `smells`.
//! - BUG-13: `tldr complexity` missing-function exit code (already fixed
//!   upstream; this test pins the contract so it does not regress).
//! - BUG-25: `tldr debt` long-method LOC was off-by-one (`end - start`
//!   instead of `end - start + 1`).
//!
//! These tests exec the built binary via `assert_cmd`.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Get the path to the test binary.
fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// ============================================================================
// BUG-05 — todo items must preserve real line numbers
// ============================================================================

/// `tldr todo` previously hardcoded `line=0` for dead-code TodoItems even
/// though `tldr dead` reported the real start line of the dead function.
/// This test pins a fixture with a known dead function and asserts that
/// `todo` carries the real line number through.
#[test]
fn test_todo_item_dead_code_preserves_line() {
    let temp = TempDir::new().unwrap();
    // Write a Python module with one obviously-dead private helper at a
    // known line. The helper is private (`_`-prefix) and has zero call
    // sites, so the refcount-based dead detector will flag it.
    //
    // File layout:
    //   line 1: blank
    //   line 2: def public_entry():
    //   line 3:     return 42
    //   line 4: blank
    //   line 5: blank
    //   line 6: def _orphan_helper():
    //   line 7:     return "never called"
    let src = "\n\
        def public_entry():\n\
            return 42\n\
        \n\
        \n\
        def _orphan_helper():\n\
            return \"never called\"\n";
    let test_file = temp.path().join("mod.py");
    fs::write(&test_file, src).unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["todo", temp.path().to_str().unwrap(), "-q", "--quick"]);
    let out = cmd.output().expect("failed to run tldr todo");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Parse the JSON envelope and locate the dead-code item.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad json: {e}\nstdout={stdout}"));
    let items = v
        .get("items")
        .and_then(|i| i.as_array())
        .expect("items array missing");

    // Find the dead_code item for `_orphan_helper`.
    let item = items
        .iter()
        .find(|it| {
            it.get("category").and_then(|c| c.as_str()) == Some("dead_code")
                && it
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.contains("_orphan_helper"))
                    .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no dead_code item for _orphan_helper in {stdout}"));

    let line = item
        .get("line")
        .and_then(|l| l.as_u64())
        .expect("line field missing");

    // Hard contract: the line must be the real start line (6), NOT the
    // placeholder 0. We assert the exact line — the fixture is pinned.
    assert_eq!(
        line, 6,
        "todo dead_code item should report the real start line (6), got {line}\nfull item: {item}"
    );
}

// ============================================================================
// BUG-11 — missing path must produce a non-zero exit
// ============================================================================

/// `health`, `structure`, `smells`, and `deps` must all exit non-zero when
/// invoked on a path that does not exist. Previously `smells` silently
/// returned exit 0 with empty output, which makes `tldr` unscriptable
/// (downstream tooling cannot tell "no findings" from "did not run").
#[test]
fn test_subcommands_exit_nonzero_on_missing_path() {
    let missing = "/nonexistent/path/should/not/exist/tldr-test";
    for sub in ["health", "structure", "smells", "deps"] {
        let mut cmd = tldr_cmd();
        cmd.args([sub, missing, "-q"]);
        let out = cmd.output().expect("failed to spawn tldr");
        assert!(
            !out.status.success(),
            "tldr {sub} {missing} unexpectedly succeeded (exit 0). stdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

// ============================================================================
// BUG-13 — `tldr complexity` must exit non-zero on unknown function
// ============================================================================

/// `tldr complexity <file> <function>` must exit non-zero when the named
/// function does not exist in the file. This already exits 20 today; the
/// test pins the contract so a future refactor can not silently regress to
/// exit 0.
#[test]
fn test_complexity_exit_nonzero_on_missing_function() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("only_one.py");
    fs::write(&test_file, "def the_only_function(x):\n    return x + 1\n").unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "complexity",
        test_file.to_str().unwrap(),
        "NoSuchFunction",
        "-q",
    ]);
    let out = cmd.output().expect("failed to spawn tldr complexity");
    assert!(
        !out.status.success(),
        "tldr complexity with missing function unexpectedly succeeded. stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("not found") || stderr.to_lowercase().contains("function"),
        "expected 'not found' or 'function' in stderr; got: {stderr}"
    );
}

// ============================================================================
// BUG-25 — debt long-method LOC must be inclusive (end - start + 1)
// ============================================================================

/// Inclusive line ranges: a method spanning lines 10..50 is 41 lines, not
/// 40. Previously `debt` computed `end_line - start_line` and reported one
/// fewer line than `tldr health` / `tldr explain`. We pin a fixture with a
/// 105-line method (above the 100 threshold) and assert debt reports 105.
#[test]
fn test_debt_long_method_loc_inclusive() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("big.py");

    // Build a Python file:
    //   line 1: def big_method(x):
    //   lines 2..105: 104 single-statement filler lines
    //   line 105: x = 104   (last line of the function body)
    // Total: 105 lines, all part of `big_method`.
    let mut src = String::from("def big_method(x):\n");
    for i in 1..=104 {
        src.push_str(&format!("    x = {}\n", i));
    }
    fs::write(&test_file, &src).unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["debt", temp.path().to_str().unwrap(), "-q"]);
    let out = cmd.output().expect("failed to spawn tldr debt");
    let stdout = String::from_utf8_lossy(&out.stdout);

    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad json: {e}\nstdout={stdout}"));
    let issues = v
        .get("issues")
        .and_then(|i| i.as_array())
        .expect("issues array missing");

    let long_method = issues
        .iter()
        .find(|it| {
            it.get("rule").and_then(|r| r.as_str()) == Some("long_method")
                && it
                    .get("element")
                    .and_then(|e| e.as_str())
                    .map(|s| s.contains("big_method"))
                    .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no long_method issue for big_method in {stdout}"));

    let msg = long_method
        .get("message")
        .and_then(|m| m.as_str())
        .expect("message missing");

    // Inclusive count: 105 lines. We assert the exact number to forbid
    // any silent regression to 104.
    assert!(
        msg.contains("105 lines"),
        "expected 'Method has 105 lines' (inclusive end-start+1); got: {msg}"
    );
}
