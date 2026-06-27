//! rc2-meta-stage3-csharp (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, C# slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For C# specifically:
//!
//!   * `extract` (`extract_csharp_class_info`) emitted `kind: None` for every
//!     `class_declaration` / `struct_declaration` / `interface_declaration`
//!     carrier.
//!   * `interface` (`ts_js_entry_kind`) returned `None` for every C# container
//!     (no C# arm), so the `kind` field was omitted entirely.
//!   * `structure` (`classify_definition_node`) had NO C# arm, so its
//!     `definitions[]` DROPPED every C# `struct` / `enum` / `record` entirely
//!     (only `class` / `interface` were class-axis in the shared list).
//!
//! These tests pin the additive Stage-3 fix that brings all three commands into
//! agreement: every C# class/struct/interface now carries the canonical `kind`
//! from `classify_node` / `classify_node_kind` (the single source of truth — no
//! new per-language kind table), and `structure` now surfaces C# struct / enum /
//! record (a C# `record` is a `class` on the canonical class axis,
//! `record_declaration -> Class`).
//!
//! RED before the fix: `Circle`/`Point`/`IShape` carry no `kind` in extract /
//! interface and `structure` drops `Point`(struct)/`Color`(enum)/`Person`(record).
//! GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const CSHARP_SRC: &str = r#"using System;

public interface IShape { double Area(); }

public struct Point { public int X; public int Y; }

public enum Color { Red, Green, Blue }

public class Circle : IShape
{
    public double Radius { get; set; }
    public Circle(double r) { Radius = r; }
    public double Area() { return 3.14 * Radius * Radius; }
}

public record Person(string Name, int Age);
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

fn csharp_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_csharp.cs");
    fs::write(&file, CSHARP_SRC).unwrap();
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

// The three containers `extract` / `interface` / `structure` ALL surface for C#
// (`class_node_kinds(CSharp)` = class/interface/struct). The enum is surfaced by
// `structure`/`extract` (not `interface`'s container set) and the record by
// `structure` (kind:"class"); both asserted separately.
const EXPECTED: &[(&str, &str)] = &[
    ("IShape", "interface"),
    ("Point", "struct"),
    ("Circle", "class"),
];

// ============================================================================
// EXTRACT — kind population for interface / struct / class
// ============================================================================

#[test]
fn extract_populates_csharp_container_kinds() {
    let (_t, file) = csharp_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT csharp `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "extract csharp `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — kind population for interface / struct / class
// ============================================================================

#[test]
fn interface_populates_csharp_container_kinds() {
    let (_t, file) = csharp_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT csharp `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "interface csharp `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_csharp_kinds() {
    let (_t, file) = csharp_fixture();
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

// ============================================================================
// STRUCTURE no longer DROPS the C# struct / enum / record (additive surfacing).
// `enum` and `record` are not part of `interface`'s container set, so these are
// structure-side surfacing assertions (struct also agrees with extract).
// ============================================================================

#[test]
fn structure_surfaces_csharp_struct_enum_record() {
    let (_t, file) = csharp_fixture();
    let s = structure_defs(&file);

    // struct + enum surface with their own canonical kind; record -> class
    // (canonical `record_declaration -> EntityKind::Class`).
    for (name, kind) in [("Point", "struct"), ("Color", "enum"), ("Person", "class")] {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(
            sk,
            Some(kind),
            "structure must surface csharp `{name}`:{kind:?}; structure={s:?}"
        );
    }
}
