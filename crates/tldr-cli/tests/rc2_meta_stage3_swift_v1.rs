//! rc2-meta-stage3-swift (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Swift slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` / `structure` arm still left the container discriminator
//! unpopulated (extract/interface `ClassInfo.kind == None`; structure reported
//! the class-axis default `"class"`).
//!
//! tree-sitter-swift folds `class` / `struct` / `enum` / `extension` / `actor`
//! into ONE `class_declaration` node (distinguished only by the leading keyword
//! token), and surfaces `protocol_declaration` / `typealias_declaration`
//! separately. The bare node-kind string cannot express this, so the fix routes
//! Swift through the NODE-AWARE canonical `classify_node` (single source of
//! truth — no per-language kind table), which maps:
//!
//!   class X {...}      -> class
//!   struct X {...}     -> struct
//!   enum X {...}       -> enum
//!   protocol X {...}   -> interface
//!   typealias N = T    -> type
//!   extension X {...}  -> class   (extension carriers -> class)
//!
//! RED before the fix: Swift struct/enum/protocol carry no (or a wrong "class")
//! kind across extract/interface/structure, and structure DROPS protocol /
//! typealias entirely. GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const SWIFT_SRC: &str = r#"
class Animal {
    func speak() -> String { return "" }
}

struct Point {
    var x: Int
}

enum Color {
    case red
}

protocol Greet {
    func hi()
}

typealias Meters = Int

func topLevel() -> Int { return 1 }
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

fn swift_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_swift.swift");
    fs::write(&file, SWIFT_SRC).unwrap();
    (temp, file)
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

/// `structure.files[].definitions[].{name,kind}` (class-axis only).
fn structure_def_kinds(file: &Path) -> Vec<(String, String)> {
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

// `extract` surfaces the class / struct / enum carriers it already collected
// (`extract_swift_classes_detailed` matches `class_declaration`). protocol and
// typealias are NOT captured by extract's collector (separate node kinds) — that
// pre-existing collector scope is orthogonal to this additive `kind` slice and
// is intentionally NOT widened here.
const EXTRACT_EXPECTED: &[(&str, &str)] = &[
    ("Animal", "class"),
    ("Point", "struct"),
    ("Color", "enum"),
];

// `interface` collects `class_declaration` + `protocol_declaration`, so it adds
// the protocol carrier (-> interface) on top of class/struct/enum.
const INTERFACE_EXPECTED: &[(&str, &str)] = &[
    ("Animal", "class"),
    ("Point", "struct"),
    ("Color", "enum"),
    ("Greet", "interface"),
];

// `structure` now agrees on the container kinds AND surfaces protocol / typealias
// (formerly dropped) via the Swift `is_class` widening + node-aware override.
const STRUCTURE_EXPECTED: &[(&str, &str)] = &[
    ("Animal", "class"),
    ("Point", "struct"),
    ("Color", "enum"),
    ("Greet", "interface"),
    ("Meters", "type"),
];

#[test]
fn extract_populates_swift_container_kinds() {
    let (_t, file) = swift_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXTRACT_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT swift `{name}`; got: {got:?}"));
        assert_eq!(g.1, *kind, "extract swift `{name}` must be kind:{kind:?}; got: {got:?}");
    }
}

#[test]
fn interface_populates_swift_container_kinds() {
    let (_t, file) = swift_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in INTERFACE_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT swift `{name}`; got: {got:?}"));
        assert_eq!(g.1, *kind, "interface swift `{name}` must be kind:{kind:?}; got: {got:?}");
    }
}

#[test]
fn structure_populates_swift_container_kinds() {
    let (_t, file) = swift_fixture();
    let got = structure_def_kinds(&file);
    for (name, kind) in STRUCTURE_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("structure must EMIT swift `{name}`; got: {got:?}"));
        assert_eq!(g.1, *kind, "structure swift `{name}` must be kind:{kind:?}; got: {got:?}");
    }
}

// CROSS-COMMAND AGREEMENT — extract / interface / structure agree on the kind of
// every container they all surface (class / struct / enum).
#[test]
fn extract_interface_structure_agree_on_swift_kinds() {
    let (_t, file) = swift_fixture();
    let e = extract_class_kinds(&file);
    let i = interface_class_kinds(&file);
    let s = structure_def_kinds(&file);
    for (name, kind) in EXTRACT_EXPECTED {
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(ek, Some(*kind), "extract `{name}`; extract={e:?}");
        assert_eq!(ik, Some(*kind), "interface `{name}`; interface={i:?}");
        assert_eq!(sk, Some(*kind), "structure `{name}`; structure={s:?}");
    }
}
