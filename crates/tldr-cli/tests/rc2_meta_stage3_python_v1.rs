//! rc2-meta-stage3-python (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Python slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For Python specifically:
//!
//!   * `structure` already classified every construct correctly via the
//!     `definitions[].kind` family (`class_definition` -> "class",
//!     top-level `def` -> "function", in-class `def`/`async def` -> "method").
//!   * `extract` (`extract_python_class_info`) emitted `kind: None` for every
//!     `class_definition` (`extract.classes[].kind == null`).
//!   * `interface` (`ts_js_entry_kind`) left `kind: None` for every Python
//!     container (no Python arm — fell through to `_ => None`).
//!
//! These tests pin the additive Stage-3 fix that brings `extract` and
//! `interface` into agreement with `structure`: every Python class now carries
//! the canonical `kind` from `classify_node` ("class"). No construct is dropped
//! and no name/line changes — purely additive `kind`.
//!
//! RED before the fix: `Animal` carries no `kind` in extract/interface.
//! GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const PY_SRC: &str = r#"class Animal:
    def __init__(self, name):
        self.name = name

    def speak(self):
        return "..."

    async def fetch(self):
        return 1


class Dog(Animal):
    def speak(self):
        return "woof"


def top_level():
    return 42


async def top_async():
    return 7
"#;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(cmd: &str, path: &Path) -> Value {
    let assert = tldr_cmd()
        .args([cmd, path.to_str().unwrap(), "--format", "json", "-q"])
        .assert()
        .success();
    let out = assert.get_output();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{cmd} must emit valid JSON: {e}\nstdout:\n{stdout}"))
}

fn python_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_py.py");
    fs::write(&file, PY_SRC).unwrap();
    (temp, file)
}

/// `structure.definitions[].{name,kind}` across all files.
fn structure_defs(file: &Path) -> Vec<(String, String)> {
    let v = run_json("structure", file);
    let mut out = Vec::new();
    if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
        for f in files {
            if let Some(defs) = f.get("definitions").and_then(|d| d.as_array()) {
                for d in defs {
                    let name = d.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let kind = d.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
                    out.push((name, kind));
                }
            }
        }
    }
    out
}

/// `extract.classes[].{name,kind}`.
fn extract_class_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("extract", file);
    let mut out = Vec::new();
    if let Some(cs) = v.get("classes").and_then(|c| c.as_array()) {
        for c in cs {
            let name = c.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let kind = c.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
            out.push((name, kind));
        }
    }
    out
}

/// `interface.classes[].{name,kind}`.
fn interface_class_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("interface", file);
    let mut out = Vec::new();
    if let Some(cs) = v.get("classes").and_then(|c| c.as_array()) {
        for c in cs {
            let name = c.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let kind = c.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
            out.push((name, kind));
        }
    }
    out
}

const EXPECTED_CLASSES: &[(&str, &str)] = &[("Animal", "class"), ("Dog", "class")];

// ============================================================================
// EXTRACT — class kind population
// ============================================================================

#[test]
fn extract_populates_python_class_kind() {
    let (_t, file) = python_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXPECTED_CLASSES {
        let g = got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("extract must EMIT python class `{name}`; got: {got:?}")
        });
        assert_eq!(
            g.1, *kind,
            "extract python `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — class kind population
// ============================================================================

#[test]
fn interface_populates_python_class_kind() {
    let (_t, file) = python_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in EXPECTED_CLASSES {
        let g = got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("interface must EMIT python class `{name}`; got: {got:?}")
        });
        assert_eq!(
            g.1, *kind,
            "interface python `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// STRUCTURE — already classifies class / method / function (regression guard)
// ============================================================================

#[test]
fn structure_classifies_python_class_method_function() {
    let (_t, file) = python_fixture();
    let defs = structure_defs(&file);
    let kind_of = |name: &str| -> Option<String> {
        defs.iter().find(|(n, _)| n == name).map(|(_, k)| k.clone())
    };
    assert_eq!(kind_of("Animal").as_deref(), Some("class"), "defs={defs:?}");
    // in-class def / async def -> method
    assert_eq!(kind_of("__init__").as_deref(), Some("method"), "defs={defs:?}");
    assert_eq!(kind_of("fetch").as_deref(), Some("method"), "defs={defs:?}");
    // top-level def / async def -> function
    assert_eq!(kind_of("top_level").as_deref(), Some("function"), "defs={defs:?}");
    assert_eq!(kind_of("top_async").as_deref(), Some("function"), "defs={defs:?}");
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_python_class_kind() {
    let (_t, file) = python_fixture();
    let s = structure_defs(&file);
    let e = extract_class_kinds(&file);
    let i = interface_class_kinds(&file);

    for (name, kind) in EXPECTED_CLASSES {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(sk, Some(*kind), "structure `{name}`; structure={s:?}");
        assert_eq!(ek, Some(*kind), "extract `{name}`; extract={e:?}");
        assert_eq!(ik, Some(*kind), "interface `{name}`; interface={i:?}");
    }
}
