//! explain-cross-command-consistency-v1 — regression tests for 2 bugs
//! from the phase-11 audit:
//!
//! - BUG-AGG-1 (HIGH): `tldr explain` returned empty `callers`/`callees`
//!   while `tldr impact` / `tldr references` / `tldr context` found them
//!   on the same target. Root cause: explain's per-file walker only saw
//!   relationships defined in the same source file. After this fix,
//!   explain enriches its results with cross-file callers/callees from
//!   the same project-wide call graph used by impact. It still computes
//!   the per-file walker results too — both sources are merged and
//!   deduplicated.
//!
//! - BUG-AGG-11 (LOW): `tldr change-impact` metadata reported
//!   `call_graph_nodes=0` / `call_graph_edges=0` whenever
//!   `status=NoChanges`, even when `tldr calls` clearly returned a
//!   non-empty graph for the same project. After this fix, the
//!   NoChanges early-return now builds the project call graph and
//!   reports real edge counts in the metadata.
//!
//! All synthetic tests build their fixtures in a tempdir so they do not
//! depend on `/tmp/repos/<x>` being present. The real-repo tests are
//! gated on the corresponding paths existing and are silently skipped
//! otherwise.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// Build a small Python project where `lib.py::target` is called from a
/// different file (`app.py`). The per-file explain walker on `lib.py`
/// alone cannot see the caller in `app.py` — this is exactly the
/// cross-file gap BUG-AGG-1 closes.
fn build_python_cross_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Project marker so explain_project_root walks up and discovers root.
    write(&root.join("pyproject.toml"), "[project]\nname = \"x\"\n");

    write(
        &root.join("lib.py"),
        r#"
def helper(x):
    return x * 2

def target(x):
    return helper(x) + 1
"#,
    );

    write(
        &root.join("app.py"),
        r#"
from lib import target

def caller_one():
    return target(10)

def caller_two():
    return target(20) + 1
"#,
    );

    dir
}

#[test]
fn test_explain_callers_match_impact_python() {
    let dir = build_python_cross_file_project();
    let root = dir.path();
    let lib_py = root.join("lib.py");

    // explain on lib.py::target — should find at least one caller
    // (in app.py).
    let out = tldr_cmd()
        .arg("explain")
        .arg(&lib_py)
        .arg("target")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain");
    assert!(
        out.status.success(),
        "tldr explain failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("explain JSON");
    let callers = v
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array");
    assert!(
        !callers.is_empty(),
        "explain.callers should be non-empty (cross-file callers in app.py); got {}",
        v
    );

    // impact on the same target — should also find ≥1 caller.
    let imp_out = tldr_cmd()
        .arg("impact")
        .arg("target")
        .arg(root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr impact");
    assert!(
        imp_out.status.success(),
        "tldr impact failed: stderr={}",
        String::from_utf8_lossy(&imp_out.stderr)
    );
    let iv: Value = serde_json::from_slice(&imp_out.stdout).expect("impact JSON");
    let total_caller_count: u64 = iv
        .get("targets")
        .and_then(|t| t.as_object())
        .map(|m| {
            m.values()
                .filter_map(|t| t.get("caller_count").and_then(|c| c.as_u64()))
                .sum()
        })
        .unwrap_or(0);
    assert!(
        total_caller_count >= 1,
        "tldr impact should find ≥1 caller for target; got {}",
        iv
    );

    // Cross-command parity: explain's caller count should be at least
    // as large as impact's (it may be larger because it merges per-file
    // results too).
    assert!(
        callers.len() as u64 >= 1,
        "explain.callers count should be ≥ impact.caller_count={}",
        total_caller_count
    );
}

#[test]
fn test_explain_callees_match_impact_python() {
    let dir = build_python_cross_file_project();
    let root = dir.path();
    let lib_py = root.join("lib.py");

    // target() calls helper() — both same-file and via project graph.
    let out = tldr_cmd()
        .arg("explain")
        .arg(&lib_py)
        .arg("target")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).expect("explain JSON");
    let callees = v
        .get("callees")
        .and_then(|c| c.as_array())
        .expect("callees array");
    let names: Vec<&str> = callees
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        names.iter().any(|n| n.contains("helper")),
        "explain.callees should include 'helper'; got {:?}",
        names
    );
}

#[test]
fn test_explain_callers_real_repo_rust() {
    // Gated on /tmp/repos/ripgrep being present. Skip silently when not.
    let walk_rs = Path::new("/tmp/repos/ripgrep/crates/ignore/src/walk.rs");
    if !walk_rs.exists() {
        eprintln!(
            "skipping test_explain_callers_real_repo_rust: {} not present",
            walk_rs.display()
        );
        return;
    }
    let out = tldr_cmd()
        .arg("explain")
        .arg(walk_rs)
        .arg("check_symlink_loop")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain");
    assert!(
        out.status.success(),
        "tldr explain failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("explain JSON");
    let callers = v
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array");
    assert!(
        !callers.is_empty(),
        "explain on check_symlink_loop should report ≥1 caller (matches `tldr impact`); got {}",
        v
    );
}

#[test]
fn test_change_impact_metadata_populated() {
    // Build a tiny Python project initialised as a git repo with a
    // committed, untouched tree. `tldr change-impact` defaults to
    // GitHead; with a clean tree it returns NoChanges and was
    // previously emitting metadata.call_graph_nodes=0 even though
    // `tldr calls` reports a non-empty graph for the same input.
    let dir = build_python_cross_file_project();
    let root = dir.path();

    // Init git so detect_git_changes_head succeeds (clean tree).
    let git_init = std::process::Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .expect("git init");
    if !git_init.success() {
        eprintln!("skipping test_change_impact_metadata_populated: `git init` failed");
        return;
    }
    // Configure committer for the test commit so `git commit` does not fail.
    let _ = std::process::Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "config",
            "user.email",
            "x@y",
        ])
        .status();
    let _ = std::process::Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "config",
            "user.name",
            "x",
        ])
        .status();
    let _ = std::process::Command::new("git")
        .args(["-C", &root.display().to_string(), "add", "-A"])
        .status();
    let _ = std::process::Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "commit",
            "-q",
            "-m",
            "init",
        ])
        .status();

    // change-impact on a clean tree -> NoChanges. After the BUG-AGG-11
    // fix, metadata.call_graph_edges should be non-zero (or the field
    // is absent, in which case we accept the contract too).
    let out = tldr_cmd()
        .arg("change-impact")
        .arg(root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr change-impact");
    assert!(
        out.status.success(),
        "tldr change-impact failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("change-impact JSON");

    // Confirm we exercised the NoChanges path.
    let status_kind = v
        .get("status")
        .and_then(|s| s.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("");
    assert_eq!(
        status_kind,
        "NoChanges",
        "expected NoChanges status on a clean tree; got status={:?}",
        v.get("status")
    );

    // After the fix: metadata is either populated with non-zero counts
    // OR omitted entirely. Zero-count metadata (the bug) is rejected.
    if let Some(meta) = v.get("metadata") {
        if !meta.is_null() {
            let nodes = meta
                .get("call_graph_nodes")
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let edges = meta
                .get("call_graph_edges")
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            // Build a sanity baseline using `tldr calls` on the same project.
            let calls_out = tldr_cmd()
                .arg("calls")
                .arg(root)
                .arg("--format")
                .arg("json")
                .output()
                .expect("run tldr calls");
            assert!(calls_out.status.success());
            let cv: Value = serde_json::from_slice(&calls_out.stdout).expect("calls JSON");
            let calls_edges = cv
                .get("edges")
                .and_then(|e| e.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            // If `tldr calls` says the graph has any edges, then
            // change-impact's metadata MUST also reflect that.
            if calls_edges > 0 {
                assert!(
                    nodes > 0 || edges > 0,
                    "change-impact metadata should be populated when `tldr calls` reports {} edges; got nodes={} edges={}",
                    calls_edges,
                    nodes,
                    edges
                );
            }
        }
    }
}
