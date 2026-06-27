//! rc2-meta-stage3-rust (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Rust slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For Rust specifically:
//!
//!   * `extract` (`collect_rust_struct_defs`) emitted `kind: None` for every
//!     `struct_item` / `enum_item` / `trait_item` carrier.
//!   * `interface` (`ts_js_entry_kind`) returned `None` for every Rust container
//!     (no Rust arm), so the `kind` field was omitted entirely.
//!
//! `structure` already classifies all three via the canonical entry-kind switch
//! (`Foo=struct`, `Color=enum`, `Greet=trait`). These tests pin the additive
//! Stage-3 fix that brings `extract` and `interface` into agreement with
//! `structure`: every Rust struct/enum/trait now carries the canonical `kind`
//! from `classify_node` / `classify_node_kind` (the single source of truth — no
//! new per-language kind table).
//!
//! Watch (per plan): a free `fn` is a FunctionInfo (never a class carrier) and
//! an impl-block method is folded into its owner's `methods`, so this
//! class-carrier `kind` population can never confuse `method` with `function`.
//!
//! RED before the fix: `Foo`/`Color`/`Greet` carry no `kind` in extract /
//! interface. GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const RUST_SRC: &str = r#"pub struct Foo { x: i32 }

pub enum Color { Red, Green, Blue }

pub trait Greet {
    fn hi(&self) -> String;
}

impl Foo {
    pub fn new() -> Self { Foo { x: 0 } }
}

pub fn free_fn() -> i32 { 1 }
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

fn rust_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_rust.rs");
    fs::write(&file, RUST_SRC).unwrap();
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

const EXPECTED: &[(&str, &str)] = &[
    ("Foo", "struct"),
    ("Color", "enum"),
    ("Greet", "trait"),
];

// ============================================================================
// EXTRACT — kind population for struct / enum / trait
// ============================================================================

#[test]
fn extract_populates_rust_container_kinds() {
    let (_t, file) = rust_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT rust `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "extract rust `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — kind population for struct / enum / trait
// ============================================================================

#[test]
fn interface_populates_rust_container_kinds() {
    let (_t, file) = rust_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT rust `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "interface rust `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_rust_kinds() {
    let (_t, file) = rust_fixture();
    let s = structure_defs(&file);
    let e = extract_class_kinds(&file);
    let i = interface_class_kinds(&file);

    for (name, kind) in EXPECTED {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(sk, Some(*kind), "structure `{name}`; structure={s:?}");
        assert_eq!(ek, Some(*kind), "extract `{name}`; extract={e:?}");
        assert_eq!(ik, Some(*kind), "interface `{name}`; interface={i:?}");
    }
}
