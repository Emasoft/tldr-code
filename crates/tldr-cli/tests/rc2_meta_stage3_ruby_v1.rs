//! rc2-meta-stage3-ruby (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Ruby slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For Ruby specifically:
//!
//!   * `extract` (`extract_ruby_class_info` / `extract_ruby_module_info`)
//!     emitted `kind: None` for every `class` and `module`.
//!   * `interface` left `kind: None` for every Ruby container (`Ruby` was not
//!     an arm in `ts_js_entry_kind`).
//!
//! `structure` already classified both via the family-1 entry-kind switch
//! (`module` -> "module", `class` -> "class"). These tests pin the additive
//! Stage-3 fix that brings `extract` and `interface` into agreement with
//! `structure`: every Ruby `class` / `module` now carries the canonical `kind`
//! from `classify_node` (`class` / `module`).
//!
//! RED before the fix: `Greeter`/`Person` carry no `kind` in extract/interface.
//! GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const RUBY_SRC: &str = r#"module Greeter
  GREETING = "hi"

  class Person
    def initialize(name)
      @name = name
    end

    def greet
      puts GREETING
    end

    def self.create(name)
      new(name)
    end
  end
end

def top_level_func(x)
  x + 1
end
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

fn ruby_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_ruby.rb");
    fs::write(&file, RUBY_SRC).unwrap();
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

const EXPECTED: &[(&str, &str)] = &[("Greeter", "module"), ("Person", "class")];

// ============================================================================
// EXTRACT — kind population for class / module
// ============================================================================

#[test]
fn extract_populates_ruby_class_module_kinds() {
    let (_t, file) = ruby_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT ruby `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "extract ruby `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// INTERFACE — kind population for class / module
// ============================================================================

#[test]
fn interface_populates_ruby_class_module_kinds() {
    let (_t, file) = ruby_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT ruby `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, *kind,
            "interface ruby `{name}` must be kind:{kind:?}; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == extract == interface on (name, kind)
// ============================================================================

#[test]
fn structure_extract_interface_agree_on_ruby_kinds() {
    let (_t, file) = ruby_fixture();
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
