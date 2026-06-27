//! rc2-meta-stage3-go (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Go slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `extract` /
//! `interface` arm still left `ClassInfo.kind == None`. For Go specifically:
//!
//!   * `extract` (`extract_go_types_pass1`) emitted `kind: None` for every
//!     struct / interface carrier.
//!   * `interface` (`extract_class_info` via `ts_js_entry_kind`) returned `None`
//!     for every Go container (no Go arm), so the `kind` field was omitted.
//!
//! Go has no classes: a type is a `type_declaration` wrapping a `type_spec`
//! (whose UNDERLYING type — `struct_type` / `interface_type` / other — decides
//! the kind) or a dedicated `type_alias` node (`type X = Y`). The bare node-kind
//! string cannot express this, so the fix routes Go through the NODE-AWARE
//! canonical `classify_node` (single source of truth — no per-language kind
//! table), which maps:
//!
//!   type X struct {...}     -> struct
//!   type X interface {...}  -> interface
//!   type X = Y              -> type   (alias)
//!   type X <other>          -> class  (defined type, e.g. `type Celsius float64`)
//!
//! RED before the fix: Go struct/interface carry no `kind` in extract /
//! interface. GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const GO_SRC: &str = r#"package main

type Server struct {
	addr string
}

type Handler interface {
	Handle(w int) error
}

type Celsius float64

type Alias = Server

func (s *Server) Start() error {
	return nil
}

func NewServer(addr string) *Server {
	return &Server{addr: addr}
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

fn go_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_go.go");
    fs::write(&file, GO_SRC).unwrap();
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

// `extract` surfaces only struct/interface type carriers (defined types and
// aliases have no body and are not emitted as classes).
const EXTRACT_EXPECTED: &[(&str, &str)] = &[("Server", "struct"), ("Handler", "interface")];

// `interface` surfaces the struct / interface / defined-type carriers it
// already collected pre-Stage-3 (now with the additive `kind`). The Go
// `type X = Y` ALIAS carrier is dropped by interface's pre-existing name
// resolver (it only reads the `type_spec` name, not `type_alias`); that drop is
// orthogonal to this additive `kind` slice and is intentionally NOT changed
// here (adding a new construct is out of Stage-3 scope). `classify_node` still
// classifies `type_alias` -> "type" (see the entity.rs `go_grammar_ground_truth`
// unit test) for the day interface's collector is widened.
const INTERFACE_EXPECTED: &[(&str, &str)] = &[
    ("Server", "struct"),
    ("Handler", "interface"),
    ("Celsius", "class"),
];

// ============================================================================
// EXTRACT — kind population for struct / interface
// ============================================================================

#[test]
fn extract_populates_go_container_kinds() {
    let (_t, file) = go_fixture();
    let got = extract_class_kinds(&file);
    for (name, kind) in EXTRACT_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("extract must EMIT go `{name}`; got: {got:?}"));
        assert_eq!(g.1, *kind, "extract go `{name}` must be kind:{kind:?}; got: {got:?}");
    }
}

// ============================================================================
// INTERFACE — kind population for struct / interface / defined type / alias
// ============================================================================

#[test]
fn interface_populates_go_container_kinds() {
    let (_t, file) = go_fixture();
    let got = interface_class_kinds(&file);
    for (name, kind) in INTERFACE_EXPECTED {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT go `{name}`; got: {got:?}"));
        assert_eq!(g.1, *kind, "interface go `{name}` must be kind:{kind:?}; got: {got:?}");
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — extract == interface on the shared (struct/iface)
// carriers. (NOTE: `structure`'s legacy entry-kind switch reports the class-axis
// default `"class"` for Go type_specs and is intentionally NOT changed by this
// Stage-3 slice, so it is excluded from this agreement assertion.)
// ============================================================================

#[test]
fn extract_interface_agree_on_go_kinds() {
    let (_t, file) = go_fixture();
    let e = extract_class_kinds(&file);
    let i = interface_class_kinds(&file);
    for (name, kind) in EXTRACT_EXPECTED {
        let ek = e.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(ek, Some(*kind), "extract `{name}`; extract={e:?}");
        assert_eq!(ik, Some(*kind), "interface `{name}`; interface={i:?}");
    }
}
