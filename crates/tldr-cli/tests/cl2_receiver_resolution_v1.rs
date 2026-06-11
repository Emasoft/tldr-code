//! cl2-receiver-resolution-v1 (GH #40) — receiver-type discrimination in
//! impact's reference-enrichment path.
//!
//! The call graph (and the references-enrichment fallback that augments
//! it) historically resolved callers/callees by BARE IDENTIFIER with no
//! receiver-type discrimination. `enrich_impact_with_references` minted a
//! synthetic caller for *every* textual `Call` reference to the bare
//! method name — so a call to an UNRELATED method that merely shares the
//! name (e.g. the external `json.decode(...)` vs the project-local
//! `rpc.decode()`; or `Codec::decode` vs `Parser::decode`) was reported
//! as a false caller of the target.
//!
//! These tests assert the receiver-aware behavior against real corpora:
//!
//!   1. `/tmp/tldr_corpora/lua-lsp`: `rpc.decode` is defined in `rpc.lua`
//!      and genuinely called from `loop.lua` (`rpc.decode()`). The
//!      `json.decode(...)` sites in `analyze.lua` / `compile_data.lua` /
//!      `rpc.lua` are calls to the EXTERNAL `json` library and must NOT
//!      appear as callers of `rpc.decode`.
//!
//!   2. A synthetic Rust corpus: `Parser::decode` and `Codec::decode` are
//!      same-named methods on DIFFERENT types in DIFFERENT files.
//!      `Parser::run` calls `self.decode` (Parser), `Codec::process`
//!      calls `self.decode` (Codec). Neither must be reported as a caller
//!      of the OTHER type's `decode`.
//!
//! Tests are skipped (with a loud eprintln) only if the lua corpus is
//! absent, so they never silently pass on a machine without corpora.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn lua_corpus() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/lua-lsp")
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr <args...>` and parse stdout as JSON.
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

/// Collect every caller node's `(function, file_basename, note)` across all
/// targets, recursively.
fn collect_callers(v: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    fn basename(p: &str) -> String {
        Path::new(p)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| p.to_string())
    }
    fn walk(tree: &Value, out: &mut Vec<(String, String, String)>) {
        if let Some(callers) = tree.get("callers").and_then(|c| c.as_array()) {
            for c in callers {
                let func = c
                    .get("function")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string();
                let file = basename(c.get("file").and_then(|f| f.as_str()).unwrap_or(""));
                let note = c
                    .get("note")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                out.push((func, file, note));
                walk(c, out);
            }
        }
    }
    if let Some(targets) = v.get("targets").and_then(|t| t.as_object()) {
        for (_k, tree) in targets {
            walk(tree, &mut out);
        }
    }
    out
}

/// Collect callers for a SINGLE target tree.
fn collect_callers_of(tree: &Value) -> Vec<(String, String, String)> {
    let mut wrap = serde_json::Map::new();
    wrap.insert(
        "callers".to_string(),
        tree.get("callers").cloned().unwrap_or(Value::Array(vec![])),
    );
    let mut targets_map = serde_json::Map::new();
    targets_map.insert("t".to_string(), Value::Object(wrap));
    let mut root = serde_json::Map::new();
    root.insert("targets".to_string(), Value::Object(targets_map));
    collect_callers(&Value::Object(root))
}

// ---------------------------------------------------------------------------
// Scenario 1: lua-lsp — json.decode (external) must NOT be a caller of rpc.decode
// ---------------------------------------------------------------------------

#[test]
fn lua_rpc_decode_excludes_json_decode_callers() {
    let corpus = lua_corpus();
    if !corpus.exists() {
        eprintln!(
            "SKIP lua_rpc_decode_excludes_json_decode_callers: corpus missing at {}",
            corpus.display()
        );
        return;
    }

    let v = run_json(&[
        "impact",
        "rpc.decode",
        corpus.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let callers = collect_callers(&v);

    // The `json.decode(...)` call sites live in analyze.lua and
    // compile_data.lua. Those are calls to the EXTERNAL json library —
    // receiver `json`, not `rpc` — and must NOT be minted as callers of
    // the project-local `rpc.decode`.
    let false_callers: Vec<_> = callers
        .iter()
        .filter(|(_f, file, _n)| file == "analyze.lua" || file == "compile_data.lua")
        .collect();
    assert!(
        false_callers.is_empty(),
        "rpc.decode impact wrongly minted callers from json.decode(...) sites \
         (different receiver `json` != `rpc`): {false_callers:?}\nall callers: {callers:?}"
    );

    // The genuine caller (loop.lua: `rpc.decode()`) SHOULD still be present.
    let has_loop = callers.iter().any(|(_f, file, _n)| file == "loop.lua");
    assert!(
        has_loop,
        "rpc.decode impact dropped its genuine caller in loop.lua; callers: {callers:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Rust — Parser::decode vs Codec::decode (same name, different type)
// ---------------------------------------------------------------------------

/// Write a small Rust corpus with two same-named methods on different
/// types in different files into a temp dir, returning that dir.
fn make_rust_corpus() -> PathBuf {
    let base = std::env::temp_dir().join("tldr_cl2_rust_corpus");
    let src = base.join("src");
    std::fs::create_dir_all(&src).expect("create rust corpus dir");

    std::fs::write(
        src.join("parser.rs"),
        r#"//! Parser module with its own `decode` method.

pub struct Parser {
    pub pos: usize,
}

impl Parser {
    pub fn new() -> Self {
        Parser { pos: 0 }
    }

    /// Parser-specific decode.
    pub fn decode(&self, input: &str) -> String {
        input.to_string()
    }

    pub fn run(&self) -> String {
        // Real caller of Parser::decode (receiver is `self`: a Parser).
        self.decode("hello")
    }
}
"#,
    )
    .expect("write parser.rs");

    std::fs::write(
        src.join("codec.rs"),
        r#"//! Codec module with a SAME-NAMED `decode` method on a DIFFERENT type.

pub struct Codec {
    pub mode: u8,
}

impl Codec {
    pub fn new() -> Self {
        Codec { mode: 0 }
    }

    /// Codec-specific decode (DIFFERENT type than Parser::decode).
    pub fn decode(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    pub fn process(&self) -> Vec<u8> {
        // This is a call to Codec::decode, NOT Parser::decode.
        self.decode(&[1, 2, 3])
    }
}
"#,
    )
    .expect("write codec.rs");

    std::fs::write(
        src.join("main.rs"),
        r#"mod parser;
mod codec;

use parser::Parser;
use codec::Codec;

fn main() {
    let p = Parser::new();
    let _ = p.decode("data");

    let c = Codec::new();
    let _ = c.decode(&[9, 9]);
}
"#,
    )
    .expect("write main.rs");

    base
}

#[test]
fn rust_parser_decode_excludes_codec_process_caller() {
    let corpus = make_rust_corpus();

    let v = run_json(&[
        "impact",
        "decode",
        corpus.to_str().unwrap(),
        "--format",
        "json",
    ]);

    let targets = v
        .get("targets")
        .and_then(|t| t.as_object())
        .expect("targets object");

    // Per-target receiver discrimination: `process` from codec.rs must not
    // appear under the Parser.decode target (it calls Codec::decode), and
    // `run` from parser.rs must not appear under the Codec.decode target
    // (it calls Parser::decode).
    for (k, tree) in targets {
        let this_callers = collect_callers_of(tree);

        if k.ends_with("Parser.decode") || k.ends_with("Parser::decode") {
            assert!(
                !this_callers
                    .iter()
                    .any(|(f, file, _n)| f == "process" && file == "codec.rs"),
                "Parser.decode target has false caller process@codec.rs \
                 (that call is to Codec::decode, a different type): {this_callers:?}"
            );
        }
        if k.ends_with("Codec.decode") || k.ends_with("Codec::decode") {
            assert!(
                !this_callers
                    .iter()
                    .any(|(f, file, _n)| f == "run" && file == "parser.rs"),
                "Codec.decode target has false caller run@parser.rs \
                 (that call is to Parser::decode, a different type): {this_callers:?}"
            );
        }
    }
}
