//! cl16-arg-ergonomics-v1 — context / change-impact reject a bare file-path
//! arg with a misleading error.
//!
//! Surface: `tldr context` expects a function ENTRY; `tldr change-impact`
//! expects a project root or a change set (path-list / git diff). Handing
//! either command a *plain existing file path* used to produce a misleading,
//! useless error:
//!
//!   - `tldr context src/flask/app.py`
//!       → "Function not found: src/flask/app.py\n\nDid you mean:\n  - App\n  - app"
//!         (the "suggestions" are fuzzy function-name matches that have nothing
//!          to do with the file path the user actually typed — pure junk)
//!
//!   - `tldr change-impact src/flask/app.py`   (relative file path)
//!       → "Path not found: " (the inferred project root collapsed to the
//!          empty string when walking up a relative path, so the message names
//!          *no* path at all — junk)
//!
//! Contract pinned here: when the positional arg is an existing file path,
//! each command emits a CLEAR, ACTIONABLE message (or, for change-impact,
//! handles the file sensibly), and NEVER the misleading "Function not found"
//! text nor a junk "Did you mean" suggestion block nor an empty "Path not
//! found: " line.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Build a minimal but real Python project: a project-root marker
/// (`pyproject.toml`) plus a single source file with a couple of functions
/// so the call graph is non-trivial. Returns (TempDir, project_root,
/// source_file).
fn make_temp_project() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    let src = root.join("app.py");
    fs::write(
        &src,
        "def helper():\n    return 1\n\n\ndef main():\n    return helper()\n",
    )
    .unwrap();
    (temp, root, src)
}

// =============================================================================
// context: a file path is not a function entry → clear hint, no junk
// =============================================================================

#[test]
fn context_with_file_path_emits_clear_hint_not_function_not_found() {
    let (_temp, root, src) = make_temp_project();
    let src_str = src.to_string_lossy().to_string();

    let assert = tldr_cmd()
        .current_dir(&root)
        .args(["context", &src_str, "-q"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    // MUST NOT surface the misleading "Function not found" framing for a path.
    assert!(
        !stderr.contains("Function not found"),
        "context on a file path must not say 'Function not found'; got:\n{}",
        stderr
    );
    // MUST NOT emit the junk fuzzy-suggestion block.
    assert!(
        !stderr.contains("Did you mean"),
        "context on a file path must not emit junk 'Did you mean' suggestions; got:\n{}",
        stderr
    );
    // MUST echo the offending path so the user sees their mistake.
    assert!(
        stderr.contains("app.py"),
        "context error must mention the file path the user typed; got:\n{}",
        stderr
    );
    // MUST be actionable: tell them context wants a function name and how to
    // scope to a file (the `<file>:<func>` shorthand / --file flag).
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("function") && (lower.contains("file:") || lower.contains("--file")),
        "context error must explain it expects a function name and how to use a file; got:\n{}",
        stderr
    );
}

#[test]
fn context_with_relative_file_path_emits_clear_hint() {
    // Same as above but the user types the path RELATIVE to cwd (the common
    // case). Must still be clear, never "Function not found".
    let (_temp, root, _src) = make_temp_project();

    let assert = tldr_cmd()
        .current_dir(&root)
        .args(["context", "app.py", "-q"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    assert!(
        !stderr.contains("Function not found"),
        "context on a relative file path must not say 'Function not found'; got:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("Did you mean"),
        "context on a relative file path must not emit junk suggestions; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("app.py"),
        "context error must mention the file path; got:\n{}",
        stderr
    );
}

// =============================================================================
// change-impact: a bare file path must be handled sensibly, never the junk
// empty "Path not found: " message.
// =============================================================================

#[test]
fn change_impact_with_relative_file_path_no_empty_path_error() {
    let (_temp, root, _src) = make_temp_project();

    let assert = tldr_cmd()
        .current_dir(&root)
        .args(["change-impact", "app.py", "--format", "json", "-q"])
        .assert();
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // The misleading empty-path error must be gone entirely.
    assert!(
        !stderr.contains("Path not found: \n") && !stderr.trim_end().ends_with("Path not found:"),
        "change-impact on a relative file must not emit an empty 'Path not found:' line; got:\n{}",
        stderr
    );
    // It should either succeed with a real report, or fail with an actionable
    // message that NAMES the file — never an empty path.
    if output.status.success() {
        let v: Value =
            serde_json::from_str(&stdout).expect("change-impact must emit valid JSON on success");
        assert!(
            v.get("status").is_some(),
            "expected status field; got: {}",
            v
        );
    } else {
        assert!(
            stderr.contains("app.py"),
            "change-impact failure must name the file; got:\n{}",
            stderr
        );
    }
}

#[test]
fn change_impact_with_absolute_file_path_still_succeeds() {
    // Regression guard: absolute single-file mode (already working) must keep
    // working after the relative-path fix.
    let (_temp, _root, src) = make_temp_project();
    let src_str = src.to_string_lossy().to_string();

    let assert = tldr_cmd()
        .args(["change-impact", &src_str, "--format", "json", "-q"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("change-impact must emit valid JSON");
    assert!(
        v.get("status").is_some(),
        "expected status field; got: {}",
        v
    );
}
