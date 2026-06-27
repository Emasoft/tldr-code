//! rc2-meta-stage3-c (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, C slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `interface`
//! arm still left `ClassInfo.kind == None`. For C specifically:
//!
//!   * `extract` has NO classes by design (`extract_classes_detailed` is a no-op
//!     for C — there is no C `ClassInfo` carrier to populate), so the `extract`
//!     family is intentionally untouched.
//!   * `interface` (`ts_js_entry_kind`) returned `None` for every C container (no
//!     C arm), so the `kind` field was omitted entirely from a C struct.
//!
//! `structure` already classifies C containers via the canonical entry-kind
//! switch (`Point=struct`, `Color=enum`, `add=function`). These tests pin the
//! additive Stage-3 fix that brings `interface` into agreement with `structure`:
//! a C struct now carries the canonical `kind` from `classify_node_kind` (the
//! single source of truth — no new per-language kind table). C has no classes,
//! no methods, and `class_node_kinds(C)` = {`struct_specifier`}, so the
//! population can never confuse `method`/`function` or `struct`/`union`.
//!
//! RED before the fix: `interface` `Point` carries no `kind`. GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const C_SRC: &str = r#"struct Point {
    int x;
    int y;
};

union Value {
    int i;
    float f;
};

enum Color {
    RED,
    GREEN
};

int add(int a, int b) {
    return a + b;
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

fn c_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_c.c");
    fs::write(&file, C_SRC).unwrap();
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
// INTERFACE — kind population for a C struct (the Stage-3 fix)
// ============================================================================

#[test]
fn interface_populates_c_struct_kind() {
    let (_t, file) = c_fixture();
    let got = interface_class_kinds(&file);
    let g = got
        .iter()
        .find(|(n, _)| n == "Point")
        .unwrap_or_else(|| panic!("interface must EMIT c `Point`; got: {got:?}"));
    assert_eq!(
        g.1, "struct",
        "interface c `Point` must be kind:\"struct\"; got: {got:?}"
    );
}

// ============================================================================
// STRUCTURE — regression guard: canonical kinds already correct
// ============================================================================

#[test]
fn structure_reports_c_canonical_kinds() {
    let (_t, file) = c_fixture();
    let s = structure_defs(&file);
    for (name, kind) in [("Point", "struct"), ("Color", "enum"), ("add", "function")] {
        let g = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(g, Some(kind), "structure c `{name}` must be {kind:?}; got: {s:?}");
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == interface on the struct's (name, kind)
// ============================================================================

#[test]
fn structure_interface_agree_on_c_struct_kind() {
    let (_t, file) = c_fixture();
    let s = structure_defs(&file);
    let i = interface_class_kinds(&file);

    let sk = s.iter().find(|(n, _)| n == "Point").map(|(_, k)| k.as_str());
    let ik = i.iter().find(|(n, _)| n == "Point").map(|(_, k)| k.as_str());
    assert_eq!(sk, Some("struct"), "structure `Point`; structure={s:?}");
    assert_eq!(ik, Some("struct"), "interface `Point`; interface={i:?}");
    assert_eq!(sk, ik, "structure and interface must AGREE on c `Point` kind");
}
