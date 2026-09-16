//! schema-cleanup-v2: close 4 LOW bugs sharing the surface
//! "schema/UX polish".
//!
//! - P2.BUG-6 — `tldr clones --format dot` silently emitted JSON (exit 0)
//!   even though `secure --format dot`'s error message and the per-command
//!   DOT validator advertised clones as DOT-supporting. The clones run
//!   loop now wires the canonical `--format dot` route to the existing
//!   `format_clones_dot` emitter.
//!
//! - P2.BUG-7 — Clones JSON `language` field always echoed `"auto"` (or
//!   the user's `--lang` flag verbatim), making it impossible to tell what
//!   the autodetector actually picked. The field is now resolved to the
//!   dominant language string across discovered files.
//!
//! - P2.BUG-9 — `tldr vuln` findings carried no `function` field, blocking
//!   clean piping into `tldr taint <file> <function>` and `tldr slice
//!   <file> <function> <line>`. Findings now carry an `Option<String>`
//!   `function` field populated from the `extract_file` AST extractor.
//!
//! - P2.BUG-10 — Empty-dir handling was inconsistent: `structure`/`calls`/
//!   `vuln` returned exit 0 with empty results while `health` returned
//!   exit 23, `deps` returned exit 11, and `churn` returned exit 1.
//!   `calls` also silently defaulted `language: "python"` for empty dirs.
//!   All commands now treat empty directories as a benign edge case with
//!   exit 0 + empty results + a `warnings` field, and `calls` reports
//!   `language: null` rather than silently defaulting to Python.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// Helpers
// =============================================================================

/// Build a small Python project with two near-duplicate functions so the
/// clones detector has something to find regardless of host environment.
/// Returns the TempDir so the caller can keep it alive for the test.
fn make_clones_project() -> TempDir {
    let temp = TempDir::new().unwrap();
    let dir = temp.path();
    let body = r#"
def alpha(x):
    total = 0
    for i in range(x):
        total += i * i
    return total

def beta(y):
    total = 0
    for i in range(y):
        total += i * i
    return total

def gamma(z):
    total = 0
    for i in range(z):
        total += i * i
    return total
"#;
    fs::write(dir.join("a.py"), body).unwrap();
    fs::write(dir.join("b.py"), body).unwrap();
    temp
}

/// Build a Python project with an obvious vulnerable taint flow inside a
/// named function so the vuln finding can report a non-null `function`
/// field. Uses the canonical Flask `request.args.get` → `cursor.execute`
/// f-string pattern recognised by the canonical taint engine (mirrors
/// the PYTHON_VULN_SQLI fixture in `remaining_test.rs`).
fn make_vuln_project() -> TempDir {
    let temp = TempDir::new().unwrap();
    let body = r#"
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search():
    user_query = request.args.get('q')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{user_query}%'")
    return cursor.fetchall()
"#;
    fs::write(temp.path().join("vuln.py"), body).unwrap();
    temp
}

// =============================================================================
// P2.BUG-6: `tldr clones --format dot` emits valid DOT
// =============================================================================

#[test]
fn clones_dot_output_valid() {
    let project = make_clones_project();
    let out = tldr_cmd()
        .args(["clones", "-q", "--format", "dot"])
        .arg(project.path())
        .output()
        .expect("clones --format dot");

    assert!(
        out.status.success(),
        "clones --format dot must exit 0; got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.starts_with("digraph clones {"),
        "clones --format dot must start with 'digraph clones {{'; got:\n{}",
        stdout
    );
    // The fixture has 3 byte-identical functions across 2 files, so the
    // clone detector must produce at least one pair → at least one DOT
    // edge. (An empty `digraph clones {{}}` would also be a valid empty
    // DOT document, but for THIS fixture we expect non-empty.)
    let edge_count = stdout.matches(" -> ").count();
    assert!(
        edge_count >= 1,
        "fixture has obvious clones; expected >=1 DOT edges, got {} in:\n{}",
        edge_count,
        stdout
    );
}

// =============================================================================
// P2.BUG-7: clones `language` resolves to the actual analyzed language
// =============================================================================

#[test]
fn clones_language_resolved() {
    let project = make_clones_project();

    // No --lang: must autodetect to "python" (not "auto").
    let out = tldr_cmd()
        .args(["clones", "-q"])
        .arg(project.path())
        .output()
        .expect("clones");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).expect("clones JSON");
    let lang = report["language"].as_str().expect("language field present");
    assert_eq!(
        lang, "python",
        "autodetect on .py-only fixture must resolve to 'python', got {:?}",
        lang
    );

    // Explicit --lang python: must still report "python" (not "auto").
    let out = tldr_cmd()
        .args(["clones", "-q", "--language", "python"])
        .arg(project.path())
        .output()
        .expect("clones --language python");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).expect("clones JSON");
    let lang = report["language"].as_str().expect("language field present");
    assert_eq!(lang, "python");
}

// =============================================================================
// P2.BUG-9: vuln findings carry an enclosing `function` field
// =============================================================================

#[test]
fn vuln_finding_has_function_field() {
    let project = make_vuln_project();
    let out = tldr_cmd()
        .args(["vuln", "-q", "--lang", "python"])
        .arg(project.path())
        .output()
        .expect("vuln");
    assert!(
        out.status.success(),
        "vuln must exit 0; got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("vuln JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings array present");
    assert!(
        !findings.is_empty(),
        "fixture has an obvious SQL injection; expected >=1 finding, got 0:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Each finding either reports a non-empty function name OR is at
    // module scope (function field omitted because the value is None
    // and the field is `skip_serializing_if = "Option::is_none"`). For
    // THIS fixture the source line lives inside `search`, so we expect
    // the function to be set.
    let f0 = &findings[0];
    let func = f0
        .get("function")
        .and_then(|v| v.as_str())
        .expect("function field set for an in-function finding");
    assert_eq!(
        func, "search",
        "expected enclosing function 'search', got {:?}",
        func
    );
}

// =============================================================================
// P2.BUG-10: uniform empty-dir exit code (0) across structural commands
// =============================================================================

#[test]
fn empty_dir_uniform_exit_zero() {
    let empty = TempDir::new().unwrap();
    // The 6 commands listed in the bug repro. They cover the structural
    // surface (`structure`), the call-graph surface (`calls`), the
    // health/quality surface (`health`), the dependency surface
    // (`deps`), the git-history surface (`churn`), and the security
    // surface (`vuln`). Each must treat an empty directory as a
    // benign edge case (exit 0).
    for cmd in &["structure", "calls", "health", "deps", "churn", "vuln"] {
        let out = tldr_cmd()
            .args([cmd, "-q"])
            .arg(empty.path())
            .output()
            .unwrap_or_else(|e| panic!("{}: failed to spawn: {}", cmd, e));
        assert!(
            out.status.success(),
            "{} on empty dir must exit 0; got {:?}\nstderr: {}",
            cmd,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// =============================================================================
// P2.BUG-10: `calls` does not silently default `language: "python"` on
// empty input
// =============================================================================

#[test]
fn calls_empty_dir_no_default_language() {
    let empty = TempDir::new().unwrap();
    let out = tldr_cmd()
        .args(["calls", "-q"])
        .arg(empty.path())
        .output()
        .expect("calls");
    assert!(
        out.status.success(),
        "calls on empty dir must exit 0; got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("calls JSON");
    // The `language` field MUST NOT be the literal string "python" — that
    // was the silent fallback the bug reported. Acceptable values are
    // JSON null, the literal string "unknown", or the field's outright
    // omission. A non-null string that equals an actual language is
    // ALSO not acceptable here (the dir is empty, no language was
    // analysed).
    let lang = &report["language"];
    let ok = lang.is_null() || lang.as_str() == Some("unknown") || lang.as_str() == Some("auto");
    assert!(
        ok,
        "calls on empty dir must report language: null|\"unknown\"|\"auto\", \
         not silently default to a real language; got {:?}\nfull report:\n{}",
        lang, report
    );
}
