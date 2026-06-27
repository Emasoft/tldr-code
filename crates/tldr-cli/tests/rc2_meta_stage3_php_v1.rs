//! rc2-meta-stage3-php (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, PHP slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For PHP specifically:
//!
//!   * `extract` (`extract_php_class_info` / `_interface_info` / `_trait_info`)
//!     emitted `kind: None` for every `class` / `interface` / `trait`.
//!   * `interface` left `kind: None` for every PHP container (`Php` was not an
//!     arm in `ts_js_entry_kind`).
//!
//! `structure` already classified class/interface via the family-1 entry-kind
//! switch. These tests pin the additive Stage-3 fix that brings `extract` and
//! `interface` into agreement with `structure`: every PHP `class` / `interface`
//! / `trait` now carries the canonical `kind` from `classify_node`
//! (`class` / `interface` / `trait`).
//!
//! Scope note (pre-existing, NOT changed here): `structure`'s family-1
//! membership drops PHP `trait_declaration` and `enum_declaration`, and the
//! `interface` command's `class_node_kinds(Php)` covers only
//! {class_declaration, interface_declaration}. This commit is additive-`kind`
//! ONLY — it does not widen any membership table — so the trait `Loggable`
//! appears (with `kind:"trait"`) in `extract` only, and the cross-command
//! agreement is asserted over the constructs each command already emits.
//!
//! RED before the fix: PHP containers carry no `kind` in extract/interface.
//! GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const PHP_SRC: &str = r#"<?php
interface Shape {
    public function area(): float;
}
trait Loggable {
    public function log(string $m): void {}
}
class Circle implements Shape {
    use Loggable;
    public function area(): float { return 3.14; }
}
function helper(int $x): int {
    return $x + 1;
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

fn php_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_php.php");
    fs::write(&file, PHP_SRC).unwrap();
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

// Constructs each command emits. `extract` is the only command that emits the
// trait carrier (`Loggable`); `structure`/`interface` agree on class+interface.
const EXTRACT_EXPECTED: &[(&str, &str)] =
    &[("Shape", "interface"), ("Loggable", "trait"), ("Circle", "class")];
const SHARED_EXPECTED: &[(&str, &str)] = &[("Shape", "interface"), ("Circle", "class")];

// ============================================================================
// EXTRACT — kind population for class / interface / trait
// ============================================================================

#[test]
fn extract_populates_php_container_kinds() {
    let (_t, file) = php_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXTRACT_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT php `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "extract php `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — kind population for class / interface
// ============================================================================

#[test]
fn interface_populates_php_container_kinds() {
    let (_t, file) = php_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in SHARED_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT php `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "interface php `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_php_kinds() {
    let (_t, file) = php_fixture();
    let s = structure_defs(&file);
    let e = extract_class_kinds(&file);
    let i = interface_class_kinds(&file);

    for (name, kind) in SHARED_EXPECTED {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(sk, Some(*kind), "structure `{name}`; structure={s:?}");
        assert_eq!(ek, Some(*kind), "extract `{name}`; extract={e:?}");
        assert_eq!(ik, Some(*kind), "interface `{name}`; interface={i:?}");
    }
}
