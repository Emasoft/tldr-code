//! rc2-meta-stage3-scala (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Scala slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For Scala specifically:
//!
//!   * `extract` (`extract_scala_classes_detailed`) DROPPED `enum_definition`
//!     and `type_definition` (no match arm) and emitted `kind: None` for plain
//!     class/object/trait (only the `case object` / `sealed *` flavor markers
//!     were recorded).
//!   * `interface` left `kind: None` for every Scala container and DROPPED
//!     `enum_definition` / `type_definition` (absent from `class_node_kinds`).
//!
//! `structure` already classified all five via the family-1 fix
//! (b3-structure-polyglot-bound-scala-classify-v1). These tests pin the
//! additive Stage-3 fix that brings `extract` and `interface` into agreement
//! with `structure`: every Scala container/type now carries the canonical
//! `kind` from `classify_node` (`class` / `object` / `trait` / `enum` / `type`),
//! and enums / type aliases are no longer dropped. The `case object` /
//! `sealed *` smells flavor still takes precedence on the `extract` path.
//!
//! RED before the fix: `Color`/`MyInt` absent from `extract`/`interface`;
//! `Plain`/`Companion`/`Greeter` carry no `kind`. GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const SCALA_SRC: &str = r#"class Plain {
  def f(x: Int): Int = x
}

object Companion {}

trait Greeter {
  def hello: String
}

enum Color { case Red, Green, Blue }

type MyInt = Int
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

fn scala_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_scala.scala");
    fs::write(&file, SCALA_SRC).unwrap();
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
    ("Plain", "class"),
    ("Companion", "object"),
    ("Greeter", "trait"),
    ("Color", "enum"),
    ("MyInt", "type"),
];

// ============================================================================
// EXTRACT — kind population + un-dropped enum / type alias
// ============================================================================

#[test]
fn extract_populates_scala_kinds_and_emits_enum_type() {
    let (_t, file) = scala_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("extract must EMIT scala `{name}` (enum/type were dropped pre-fix); got: {got:?}")
        });
        assert_eq!(
            g.1, *kind,
            "extract scala `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — kind population + un-dropped enum / type alias
// ============================================================================

#[test]
fn interface_populates_scala_kinds_and_emits_enum_type() {
    let (_t, file) = scala_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("interface must EMIT scala `{name}` (enum/type were dropped pre-fix); got: {got:?}")
        });
        assert_eq!(
            g.1, *kind,
            "interface scala `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_scala_kinds() {
    let (_t, file) = scala_fixture();
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
