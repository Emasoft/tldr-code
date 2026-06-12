//! fix-cl-9-v1 (gaps IT3-lua-01 / IT3-lua-03 / IT3-lua-04) — Lua
//! bracket-string-indexed function definitions silently dropped.
//!
//! In tree-sitter-lua, a definition of the form
//!
//!     method_handlers["textDocument/completion"] = function(params, id) ... end
//!
//! has a `bracket_index_expression` on the LHS of the `assignment_statement`
//! (as opposed to the `dot_index_expression` used by `M.func = function() ...`).
//! The extractor (`extract_lua_lhs_name`, extract.rs) and the call-graph
//! definition/scope logic (callgraph/languages/lua.rs) only handled
//! `dot_index_expression` / `identifier` / `method_index_expression`, so every
//! bracket-indexed handler resolved to an empty name and was dropped:
//!
//!   * `structure` listed 0 of the 11 `method_handlers["textDocument/..."]`
//!     handlers in `methods.lua`.
//!   * `explain` / `impact` attributed calls made INSIDE those handlers (e.g.
//!     the call to `pick_scope` at methods.lua:551, inside
//!     `method_handlers["textDocument/completion"]` defined at line 534) to the
//!     synthetic `<module>` scope instead of the enclosing handler.
//!
//! These tests assert the bracket-indexed handlers are now extracted and that
//! the caller attribution flows to the real enclosing handler.
//!
//! Tests are skipped (with a loud eprintln) only if the lua corpus is absent,
//! so they never silently pass on a machine without corpora.

use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

fn methods_lua() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/lua-lsp/lua-lsp/methods.lua")
}

fn lua_corpus_dir() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/lua-lsp/lua-lsp")
}

fn corpus_present() -> bool {
    methods_lua().exists()
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Value {
    let output = tldr_cmd()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("invoke tldr {args:?}: {e}"));
    assert!(
        output.status.success(),
        "tldr {args:?} failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr {args:?} stdout not JSON: {e}\n{stdout}"))
}

/// All `bracket_index_expression` handlers that appear on a `t["k"] = function`
/// LHS in methods.lua and MUST now be visible to `structure`.
const EXPECTED_BRACKET_HANDLERS: &[&str] = &[
    "textDocument/didOpen",
    "textDocument/didChange",
    "textDocument/didSave",
    "textDocument/didClose",
    "textDocument/completion",
    "textDocument/definition",
    "textDocument/hover",
    "textDocument/documentSymbol",
    "textDocument/formatting",
    "textDocument/rangeFormatting",
];

#[test]
fn structure_extracts_bracket_indexed_handlers() {
    if !corpus_present() {
        eprintln!("SKIP structure_extracts_bracket_indexed_handlers: lua corpus absent");
        return;
    }

    let v = run_json(&[
        "structure",
        methods_lua().to_str().unwrap(),
        "--format",
        "json",
    ]);

    let funcs = v["files"][0]["functions"]
        .as_array()
        .expect("functions array");
    let names: Vec<String> = funcs
        .iter()
        .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
        .collect();

    // Each expected bracket handler key must appear as a substring of some
    // extracted function name (the name is qualified, e.g.
    // `method_handlers["textDocument/completion"]`).
    for key in EXPECTED_BRACKET_HANDLERS {
        let found = names.iter().any(|n| n.contains(key));
        assert!(
            found,
            "bracket-indexed handler containing {key:?} not extracted by structure.\n\
             extracted names: {names:#?}"
        );
    }
}

/// Walk an impact/explain tree collecting every caller `function` name.
fn collect_caller_funcs(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(tree: &Value, out: &mut Vec<String>) {
        if let Some(callers) = tree.get("callers").and_then(|c| c.as_array()) {
            for c in callers {
                if let Some(f) = c.get("function").and_then(|f| f.as_str()) {
                    out.push(f.to_string());
                }
                walk(c, out);
            }
        }
        if let Some(arr) = tree.as_array() {
            for item in arr {
                walk(item, out);
            }
        }
        if let Some(obj) = tree.as_object() {
            for (k, val) in obj {
                if k != "callers" {
                    walk(val, out);
                }
            }
        }
    }
    walk(v, &mut out);
    out
}

#[test]
fn impact_attributes_pick_scope_caller_to_enclosing_handler() {
    if !corpus_present() {
        eprintln!("SKIP impact_attributes_pick_scope_caller_to_enclosing_handler: lua corpus absent");
        return;
    }

    // pick_scope (methods.lua:82) is called at methods.lua:551, which lives
    // INSIDE method_handlers["textDocument/completion"] (def at line 534).
    let v = run_json(&[
        "impact",
        "pick_scope",
        lua_corpus_dir().to_str().unwrap(),
        "--format",
        "json",
    ]);

    let callers = collect_caller_funcs(&v);

    // The enclosing handler must now be a recognized caller, and the call must
    // NOT be mis-attributed solely to the synthetic <module> scope.
    let attributed_to_handler = callers.iter().any(|c| c.contains("completion"));
    assert!(
        attributed_to_handler,
        "impact pick_scope did not attribute the 551 call to the enclosing \
         bracket-indexed handler (textDocument/completion).\ncallers: {callers:#?}"
    );
}
