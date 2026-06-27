//! rc2-meta-stage3-lua (v0.5.0 CLOSEOUT)
//!
//! STAGE 3 — universal `kind` population, Lua / Luau slice.
//!
//! rc2-ts (59cce85) populated `kind` for TS/JS only; every non-TS `interface`
//! function arm still left `FunctionInfo.kind == None`. Lua is the minimal
//! Stage-3 case: it has NO native `class` / `method` / `macro` surface, so the
//! ONLY construct the canonical `classify_node` discriminator soundly classifies
//! is a plain function (`function_declaration` / `function_definition_statement`
//! → `EntityKind::Function`). We therefore populate exactly that, additively:
//!
//!   * `interface` now reports `kind:"function"` for every exported Lua/Luau
//!     function (both the walker-collected exports, via `extract_function_info`,
//!     and the branch-nested exports synthesized in `reconcile_lua_exports`).
//!   * `structure.definitions` already emitted `kind:"function"` (plain) /
//!     `kind:"method"` (table-qualified `function T.m` / `function T:m`) via the
//!     Stage-2 family-1 entry-kind switch — UNCHANGED here.
//!   * `extract` keeps the Lua table-convention class as `kind:"table"` (a
//!     heuristic NOT expressible via `classify_node`; deliberately preserved, no
//!     class kind is invented for tables).
//!
//! Scope note: Lua's table-convention "class" has no single AST node that
//! `classify_node` can classify, so its `kind:"table"` tag is NOT routed through
//! the canonical classifier (doing so would regress it). This commit is
//! additive-`kind` for the FUNCTION axis only.
//!
//! RED before the fix: exported Lua functions carry no `kind` in `interface`.
//! GREEN after.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const LUA_SRC: &str = r#"local M = {}
M.__index = M

function M.new(name)
    local self = setmetatable({}, M)
    self.name = name
    return self
end

function M:greet()
    return "hi " .. self.name
end

local function helper(x)
    return x + 1
end

local function compute(a, b)
    return a + b
end

M.VERSION = "1.0"

return {
    new = M.new,
    helper = helper,
    compute = compute,
    VERSION = M.VERSION,
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

fn lua_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("rc2_lua.lua");
    fs::write(&file, LUA_SRC).unwrap();
    (temp, file)
}

/// `interface.functions[].{name,kind}`.
fn interface_function_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("interface", file);
    let mut out = Vec::new();
    if let Some(fs) = v.get("functions").and_then(|f| f.as_array()) {
        for f in fs {
            let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let kind = f.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
            out.push((name, kind));
        }
    }
    out
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

// The exported FUNCTIONS `interface` surfaces. (`new = M.new` aliases a
// table-qualified static method that the module-symbol table does not track as
// a top-level function, so the existing Lua export model routes `new` to
// `values[]`, not `functions[]` — pre-existing behaviour, unrelated to this
// additive-kind change. The genuine top-level functions are `helper`/`compute`.)
const EXPORTED_FUNCS: &[&str] = &["helper", "compute"];

// ============================================================================
// INTERFACE — additive `kind:"function"` for every exported Lua function
// ============================================================================

#[test]
fn interface_populates_lua_function_kinds() {
    let (_t, file) = lua_fixture();
    let got = interface_function_kinds(&file);
    for name in EXPORTED_FUNCS {
        let g = got
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("interface must EMIT lua function `{name}`; got: {got:?}"));
        assert_eq!(
            g.1, "function",
            "interface lua function `{name}` must be kind:\"function\"; got: {got:?}"
        );
    }
}

// ============================================================================
// CROSS-COMMAND AGREEMENT — structure == interface == "function" for the plain
// top-level Lua functions (`helper`, `compute`). (`M.new` is kind="method" in
// structure because it is table-qualified; it surfaces in interface only via
// its export alias `new`, so it is excluded from the per-name agreement.)
// ============================================================================

#[test]
fn structure_interface_agree_on_plain_lua_function_kind() {
    let (_t, file) = lua_fixture();
    let s = structure_defs(&file);
    let i = interface_function_kinds(&file);

    for name in &["helper", "compute"] {
        let sk = s.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        let ik = i.iter().find(|(n, _)| n == name).map(|(_, k)| k.as_str());
        assert_eq!(sk, Some("function"), "structure `{name}`; structure={s:?}");
        assert_eq!(ik, Some("function"), "interface `{name}`; interface={i:?}");
    }
}

// ============================================================================
// REGRESSION GUARD — the Lua table-convention class keeps `kind:"table"`. The
// additive function-axis change must NOT touch the (heuristic) class kind.
// ============================================================================

#[test]
fn extract_lua_table_class_kind_preserved() {
    let (_t, file) = lua_fixture();
    let got = extract_class_kinds(&file);
    let m = got
        .iter()
        .find(|(n, _)| n == "M")
        .unwrap_or_else(|| panic!("extract must EMIT the lua table-class `M`; got: {got:?}"));
    assert_eq!(
        m.1, "table",
        "lua table-class `M` must keep kind:\"table\" (not routed through classify_node); got: {got:?}"
    );
}
