//! schema-unification-v1: cross-command JSON schema consistency tests.
//!
//! Closes BUG-02 / BUG-17 / BUG-18 / BUG-21 / BUG-23 from the
//! "JSON schema inconsistency" anti-product surface.
//!
//! These tests pin invariants that several historical commands violated:
//!
//! - `vuln.summary.by_type` keys must be snake_case (matching `.vuln_type`).
//! - `extract.functions[]`, `explain`, `vuln.findings[]`, `dead.dead_functions[]`,
//!   and similar should expose a unified `line` field (additive — original
//!   `line_number`/`line_start` are preserved for backward compatibility).
//! - `tldr imports` returns a top-level JSON object envelope (not a bare array)
//!   by default; `--legacy-array` opt-in for the historical shape.
//! - `tldr inheritance` edges always emit a `parent_file` key (`null` when
//!   external) so consumers don't have to use `has("parent_file")`.
//! - `tldr structure` exposes `method_infos` so overloaded methods with the
//!   same name remain distinguishable by `(line, signature)`.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// BUG-02: `vuln.summary.by_type` keys are snake_case (matching `.vuln_type`).
#[test]
fn test_vuln_summary_by_type_snake_case() {
    // Use a small Python file with a clear command-injection sink so vuln
    // produces at least one finding deterministically.
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("sink.py");
    fs::write(
        &test_file,
        r#"
import os
import subprocess

def handler(req):
    user = req.GET["cmd"]
    os.system(user)
    subprocess.call(user, shell=True)
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["vuln", temp.path().to_str().unwrap(), "-q"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&output).expect("vuln output is valid JSON");

    // by_type may be empty if no findings — that's still valid; but if
    // present, every key MUST be snake_case-compatible (lowercase letters,
    // digits, underscores) and MUST contain at least one underscore for
    // multi-word variants like "command_injection". Single-word variants
    // like "xss" / "panic" / "ssrf" / "xxe" are also legal.
    let by_type = v
        .pointer("/summary/by_type")
        .and_then(Value::as_object)
        .expect(".summary.by_type missing or not an object");

    for (key, _) in by_type {
        // No PascalCase: no uppercase characters allowed.
        assert!(
            !key.chars().any(|c| c.is_ascii_uppercase()),
            "by_type key {:?} contains uppercase — must be snake_case",
            key
        );
        // No lowercase-no-separator multi-word collapse: legacy bug emitted
        // "commandinjection". Reject keys that look like a known multi-word
        // variant collapsed without underscores.
        let collapsed_known = [
            "commandinjection",
            "sqlinjection",
            "pathtraversal",
            "openredirect",
            "ldapinjection",
            "xpathinjection",
            "memorysafety",
            "unsafecode",
        ];
        assert!(
            !collapsed_known.contains(&key.as_str()),
            "by_type key {:?} is a collapsed multi-word variant — must be snake_case",
            key
        );
        // Sanity: only ASCII lowercase, digits, underscores.
        assert!(
            key.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "by_type key {:?} has illegal characters",
            key
        );
    }

    // Cross-check: every by_type key SHOULD also appear as a `.vuln_type`
    // value somewhere in the findings array (the two views agree).
    if let Some(findings) = v.pointer("/findings").and_then(Value::as_array) {
        let finding_types: std::collections::HashSet<String> = findings
            .iter()
            .filter_map(|f| f.get("vuln_type").and_then(Value::as_str).map(String::from))
            .collect();
        for key in by_type.keys() {
            assert!(
                finding_types.contains(key),
                "by_type key {:?} not present as a .vuln_type in findings — \
                 schema mismatch (was {:?})",
                key,
                finding_types
            );
        }
    }
}

/// BUG-17: `extract` exposes a unified `line` alongside `line_number`.
#[test]
fn test_extract_emits_line_alias() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("ex.py");
    fs::write(&f, "def hello():\n    return 1\n").unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["extract", f.to_str().unwrap(), "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("extract output is JSON");

    let funcs = v
        .pointer("/functions")
        .and_then(Value::as_array)
        .expect("extract output should have .functions array");
    assert!(!funcs.is_empty(), "expected at least one function");
    let f0 = &funcs[0];
    let line_number = f0
        .get("line_number")
        .and_then(Value::as_u64)
        .expect("functions[0].line_number missing");
    let line = f0
        .get("line")
        .and_then(Value::as_u64)
        .expect("functions[0].line missing — schema-unification-v1 alias");
    assert_eq!(
        line_number, line,
        "line and line_number must agree (alias mapping)"
    );
}

/// BUG-17: `explain` exposes a unified `line` alongside `line_start`.
#[test]
fn test_explain_emits_line_alias() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("ex.py");
    fs::write(&f, "def hello():\n    return 1\n").unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["explain", f.to_str().unwrap(), "hello", "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("explain output is JSON");

    let line_start = v
        .get("line_start")
        .and_then(Value::as_u64)
        .expect("explain.line_start missing");
    let line = v
        .get("line")
        .and_then(Value::as_u64)
        .expect("explain.line missing — schema-unification-v1 alias");
    assert_eq!(line_start, line, "explain.line should mirror .line_start");
}

/// BUG-18: `tldr imports` returns an envelope object by default.
#[test]
fn test_imports_returns_envelope_object() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("imp.py");
    fs::write(&f, "import os\nimport sys\n").unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["imports", f.to_str().unwrap(), "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("imports output is JSON");

    // Top-level shape must be an object.
    assert!(
        v.is_object(),
        "tldr imports default output must be an object envelope, got: {:?}",
        v
    );
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("file"), "envelope missing .file");
    assert!(obj.contains_key("language"), "envelope missing .language");
    assert!(obj.contains_key("imports"), "envelope missing .imports");
    let imps = obj.get("imports").unwrap();
    assert!(imps.is_array(), ".imports must be an array");

    // Legacy flag still produces a top-level array.
    let mut cmd2 = tldr_cmd();
    cmd2.args(["imports", f.to_str().unwrap(), "--legacy-array", "-q"]);
    let out2 = cmd2.assert().success().get_output().stdout.clone();
    let v2: Value = serde_json::from_slice(&out2).expect("imports legacy is JSON");
    assert!(
        v2.is_array(),
        "--legacy-array must produce a top-level array"
    );
}

/// BUG-23: `tldr inheritance` always emits `parent_file` (null for externals).
#[test]
fn test_inheritance_edge_parent_file_always_emitted() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("h.py");
    // Mix of project-internal and stdlib base classes:
    fs::write(
        &f,
        r#"
class Base:
    pass

class Child(Base):
    pass

class CustomError(Exception):
    pass
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args(["inheritance", temp.path().to_str().unwrap(), "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("inheritance output is JSON");

    let edges = v
        .get("edges")
        .and_then(Value::as_array)
        .expect("inheritance.edges missing");
    assert!(!edges.is_empty(), "expected at least one inheritance edge");

    for (i, edge) in edges.iter().enumerate() {
        assert!(
            edge.as_object()
                .map(|o| o.contains_key("parent_file"))
                .unwrap_or(false),
            "edges[{}] missing `parent_file` key (must always be present, \
             even when null) — got: {:?}",
            i,
            edge
        );
    }
}

/// BUG-21: `tldr structure` distinguishes overloaded methods via `method_infos`.
#[test]
fn test_structure_methods_distinguish_overloads() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("Owner.java");
    fs::write(
        &f,
        r#"
package x;
public class Owner {
    public Pet getPet(String name) { return null; }
    public Pet getPet(Integer id) { return null; }
    public Pet getPet(Integer id, boolean ignoreNew) { return null; }
}
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        temp.path().to_str().unwrap(),
        "--lang",
        "java",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is JSON");

    let files = v
        .get("files")
        .and_then(Value::as_array)
        .expect("structure.files missing");
    let owner = files
        .iter()
        .find(|f| {
            f.get("path")
                .and_then(Value::as_str)
                .map(|p| p.ends_with("Owner.java"))
                .unwrap_or(false)
        })
        .expect("Owner.java not found in structure output");

    // Either method_infos or definitions can disambiguate. Prefer method_infos.
    let method_infos = owner
        .get("method_infos")
        .and_then(Value::as_array)
        .expect("Owner.java missing method_infos (schema-unification-v1 BUG-21)");

    // Three getPet entries should be present, with distinct (line, signature).
    let getpet_entries: Vec<&Value> = method_infos
        .iter()
        .filter(|mi| mi.get("name").and_then(Value::as_str) == Some("getPet"))
        .collect();
    assert_eq!(
        getpet_entries.len(),
        3,
        "expected 3 getPet method_infos for overloads, got {}: {:?}",
        getpet_entries.len(),
        method_infos
    );

    // Lines must all differ, OR signatures must all differ — we want at
    // least one disambiguation axis populated.
    let mut lines: Vec<u64> = getpet_entries
        .iter()
        .map(|mi| mi.get("line").and_then(Value::as_u64).unwrap_or(0))
        .collect();
    lines.sort();
    lines.dedup();
    let sigs: std::collections::HashSet<&str> = getpet_entries
        .iter()
        .filter_map(|mi| mi.get("signature").and_then(Value::as_str))
        .collect();
    assert!(
        lines.len() == 3 || sigs.len() == 3,
        "overloads not distinguishable: lines={:?}, sigs={:?}",
        lines,
        sigs
    );
}
