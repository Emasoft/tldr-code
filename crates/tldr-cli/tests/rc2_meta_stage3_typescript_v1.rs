//! rc2-meta-stage3-typescript-javascript (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, TS/JS slice.
//!
//! rc2-ts (59cce85) already populated `kind` for TS/JS in the `extract` and
//! `interface` families. The remaining TS divergence (Lane-B active divergence
//! #1/#2) lived in FAMILY 1 (`extractor.rs::classify_definition_node` +
//! `collect_definitions` entry-kind switch): TS `type_alias_declaration` and
//! `enum_declaration` were ABSENT from the shared `is_class` set, so the
//! `structure` command DROPPED every TS type alias and enum from `definitions[]`
//! even though `extract`/`interface` reported the type aliases.
//!
//! These tests pin the additive fix: `structure` now EMITS the previously
//! dropped TS type aliases (`kind:"type"`) and enums (`kind:"enum"`), sourced
//! from the canonical `classify_node_kind` discriminator
//! (`TypeAlias`→"type", `Enum`→"enum"), and agrees with `extract`/`interface`
//! on the type-alias kind. RED before the family-1 fix: Bar/Baz/Color absent
//! from `structure.definitions[]`. GREEN after: present with the correct kind.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Exported variant: `interface` is the PUBLIC-surface projection (rc2-ts gated
/// it to exported declarations via the AST parent-kind visibility gate), so a
/// structure-vs-interface agreement check must use exported constructs.
const TS_SRC_EXPORTED: &str = r#"export interface Foo { b(): void; }
export type Bar = string;
export type Baz = { x: number };
export enum Color { Red, Green, Blue }
export class Qux { m(): void {} }
"#;

const TS_SRC: &str = r#"interface Foo {
  b(): void;
}

type Bar = string;

type Baz = { x: number };

enum Color { Red, Green, Blue }

class Qux {
  m(): void {}
}
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

fn ts_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_ts.ts");
    fs::write(&file, TS_SRC).unwrap();
    (temp, file)
}

fn ts_fixture_exported() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_ts_exp.ts");
    fs::write(&file, TS_SRC_EXPORTED).unwrap();
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

// ============================================================================
// FAMILY 1 (structure) — the un-drop fix
// ============================================================================

/// `structure` must now EMIT the TS type aliases it used to drop, with
/// `kind:"type"` (canonical `EntityKind::TypeAlias`).
#[test]
fn structure_emits_ts_type_aliases_as_kind_type() {
    let (_t, file) = ts_fixture();
    let defs = structure_defs(&file);
    for name in ["Bar", "Baz"] {
        let d = defs.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("structure must EMIT TS type alias `{name}` (was dropped pre-fix); got: {defs:?}")
        });
        assert_eq!(
            d.1, "type",
            "TS `type {name} = ...` must classify as kind:\"type\"; got: {:?}",
            defs
        );
    }
}

/// `structure` must now EMIT the TS enum it used to drop, with `kind:"enum"`.
#[test]
fn structure_emits_ts_enum_as_kind_enum() {
    let (_t, file) = ts_fixture();
    let defs = structure_defs(&file);
    let d = defs
        .iter()
        .find(|(n, _)| n == "Color")
        .unwrap_or_else(|| panic!("structure must EMIT TS `enum Color` (was dropped pre-fix); got: {defs:?}"));
    assert_eq!(d.1, "enum", "TS `enum Color` must classify as kind:\"enum\"; got: {:?}", defs);
}

/// No regression: the TS interface and class still classify correctly in
/// `structure`, and methods remain methods.
#[test]
fn structure_interface_class_method_unchanged() {
    let (_t, file) = ts_fixture();
    let defs = structure_defs(&file);
    assert!(
        defs.iter().any(|(n, k)| n == "Foo" && k == "interface"),
        "TS `interface Foo` must remain kind:\"interface\"; got: {defs:?}"
    );
    assert!(
        defs.iter().any(|(n, k)| n == "Qux" && k == "class"),
        "TS `class Qux` must remain kind:\"class\"; got: {defs:?}"
    );
    assert!(
        defs.iter().any(|(n, k)| n == "m" && k == "method"),
        "TS method `m` must remain kind:\"method\"; got: {defs:?}"
    );
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure now matches extract/interface on aliases
// ============================================================================

/// extract (rc2-ts) already reports the type aliases as `kind:"type"`. Pin that
/// `structure` (this fix) agrees with extract on the type-alias kind so the
/// families no longer diverge.
#[test]
fn structure_agrees_with_extract_on_ts_type_aliases() {
    let (_t, file) = ts_fixture();
    let s = structure_defs(&file);
    let e = extract_class_kinds(&file);
    for name in ["Bar", "Baz"] {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(
            sk,
            Some("type"),
            "structure must report `{name}` as kind:\"type\"; structure={s:?}"
        );
        assert_eq!(
            ek,
            Some("type"),
            "extract must report `{name}` as kind:\"type\" (rc2-ts); extract={e:?}"
        );
    }
}

/// interface (rc2-ts) already reports the type aliases as `kind:"type"`, but
/// only for EXPORTED declarations (the rc2-ts visibility gate). On an exported
/// fixture, `structure` (every definition) and `interface` (public surface)
/// must AGREE on the type-alias and enum kinds — the previously-divergent
/// family-1 path now matches the public-surface path.
#[test]
fn structure_agrees_with_interface_on_exported_ts_types() {
    let (_t, file) = ts_fixture_exported();
    let s = structure_defs(&file);
    let i = interface_class_kinds(&file);
    for (name, kind) in [("Bar", "type"), ("Baz", "type"), ("Color", "enum")] {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(sk, Some(kind), "structure must report `{name}`={kind}; structure={s:?}");
        assert_eq!(ik, Some(kind), "interface must report `{name}`={kind} (rc2-ts); interface={i:?}");
    }
}
