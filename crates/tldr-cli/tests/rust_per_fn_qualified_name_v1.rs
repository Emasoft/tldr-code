//! rust-per-fn-qualified-name-v1 (v0.4.2 cluster M-013):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 cluster M-013):
//! > "Call-graph commands (`impact`, `whatbreaks`) accept Rust `Type::method`
//! >  qualified names, but per-function commands (`reaching-defs`, `available`,
//! >  `dead-stores`, `slice`, `taint`, `resources`, `complexity`, `explain`,
//! >  `references`) reject them with `Function not found: Type::method`."
//!
//! Root cause: `find_function_node` (crates/tldr-core/src/ast/function_finder.rs)
//! has an explicit `::`-qualified-name branch ONLY for C/C++ (L107: `if
//! function_name.contains("::") && matches!(language, Language::C | Language::Cpp)`).
//! For Rust the call-graph layer carries a separate ad-hoc `::`-aware matcher in
//! `crate::analysis::impact::names_match`, but the per-function dispatcher
//! bypasses that and goes straight through `find_function_node` — which
//! falls through to the bare-name search, fails to match, and returns
//! `None`. The dispatcher then surfaces "Function not found".
//!
//! Fix (this v1): extend the `::`-qualified-name branch in
//! `find_function_node` to ALSO accept `Language::Rust`. Resolution
//! strategy for Rust `mod::Type::method`:
//!   1. Try the qualified form verbatim against the AST (no-op for Rust,
//!      kept for cross-language symmetry with C/C++).
//!   2. Take the LAST TWO segments as `Type::method`, descend into the
//!      `impl_item` matching `Type`, and search for `method` inside it.
//!      This handles `mod::Type::method` AND `Type::method`.
//!   3. Fall back to the bare last segment (`method`) for graceful
//!      degradation when the impl block is not found (e.g. trait methods
//!      defined elsewhere).
//!
//! Tests cover the 9 affected per-function commands by exercising the
//! Rust source already in this repo (`crates/tldr-core/src/ast/parser.rs`
//! contains `impl ParserPool { pub fn parse(&self, ...) { ... } }`).

use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

/// Resolve the parser.rs path (same crate, sibling tree-sitter target).
fn parser_rs_path() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("tldr-core")
        .join("src")
        .join("ast")
        .join("parser.rs")
}

fn require_corpus_or_skip() -> Option<String> {
    let p = parser_rs_path();
    if !p.exists() {
        eprintln!("SKIP: corpus parser.rs not present at {}", p.display());
        return None;
    }
    // Confirm the impl + method we anchor the tests on still exists.
    let src = std::fs::read_to_string(&p).expect("read parser.rs");
    if !src.contains("impl ParserPool") {
        eprintln!("SKIP: parser.rs no longer contains `impl ParserPool`");
        return None;
    }
    if !src.contains("pub fn parse(") {
        eprintln!("SKIP: parser.rs no longer contains `pub fn parse(`");
        return None;
    }
    Some(p.to_string_lossy().into_owned())
}

// =============================================================================
// TEST 1: `reaching-defs` accepts Rust Type::method qualified form.
//
// Pre-fix: exit code 20 + stderr "Error: Function not found: ParserPool::parse".
// Post-fix: exit code 0, JSON output with `function: "ParserPool::parse"`
// and a non-empty blocks/chains report.
// =============================================================================
#[test]
fn reaching_defs_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, stdout, stderr) = run_tldr(&[
        "reaching-defs",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "reaching-defs must accept Rust Type::method form. \
         stderr={} stdout={}",
        stderr, stdout
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("reaching-defs json must parse");
    let fname = v["function"].as_str().unwrap_or("");
    assert!(
        fname == "ParserPool::parse" || fname == "parse",
        "function field should be the qualified or bare name, got {:?}",
        fname
    );
}

// =============================================================================
// TEST 2: `available` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn available_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, stdout, stderr) = run_tldr(&[
        "available",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "available must accept Rust Type::method form. stderr={}",
        stderr
    );
    // Parse to confirm JSON-shape (no schema assertion beyond parseability)
    let _v: serde_json::Value =
        serde_json::from_str(&stdout).expect("available json must parse");
}

// =============================================================================
// TEST 3: `dead-stores` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn dead_stores_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, _stdout, stderr) = run_tldr(&[
        "dead-stores",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "dead-stores must accept Rust Type::method form. stderr={}",
        stderr
    );
}

// =============================================================================
// TEST 4: `slice` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn slice_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    // The slice command takes <file> <func> <line>. Pick a line inside
    // ParserPool::parse — line 188 falls in the body in this codebase
    // snapshot. Use the source to look it up dynamically to stay stable
    // across edits.
    let src = std::fs::read_to_string(&file).unwrap();
    let mut target_line: usize = 0;
    let mut in_parse = false;
    for (i, line) in src.lines().enumerate() {
        if !in_parse && line.contains("pub fn parse(") {
            in_parse = true;
            continue;
        }
        if in_parse && line.contains("Tree>") {
            // skip over return-type continuation lines
            continue;
        }
        if in_parse && !line.trim().is_empty() && !line.trim().starts_with("//") {
            // first non-empty, non-comment line inside the function body
            target_line = i + 2; // 1-indexed + one past sig
            break;
        }
    }
    if target_line == 0 {
        eprintln!("SKIP: could not anchor a line inside ParserPool::parse");
        return;
    }
    let line_arg = target_line.to_string();
    let (exit, _stdout, stderr) = run_tldr(&[
        "slice",
        &file,
        "ParserPool::parse",
        &line_arg,
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "slice must accept Rust Type::method form. stderr={}",
        stderr
    );
}

// =============================================================================
// TEST 5: `taint` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn taint_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, _stdout, stderr) = run_tldr(&[
        "taint",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "taint must accept Rust Type::method form. stderr={}",
        stderr
    );
}

// =============================================================================
// TEST 6: `resources` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn resources_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, _stdout, stderr) = run_tldr(&[
        "resources",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "resources must accept Rust Type::method form. stderr={}",
        stderr
    );
}

// =============================================================================
// TEST 7: `complexity` accepts Rust Type::method qualified form.
//
// Sanity check: confirm the metric is the same whether the user types
// `ParserPool::parse` or `ParserPool.parse` (the dot form already works).
// =============================================================================
#[test]
fn complexity_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit_dot, stdout_dot, _) = run_tldr(&[
        "complexity",
        &file,
        "ParserPool.parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(exit_dot, 0, "complexity dot-form must work (pre-fix baseline)");

    let (exit, stdout, stderr) = run_tldr(&[
        "complexity",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "complexity must accept Rust Type::method form. stderr={}",
        stderr
    );

    let v_dot: serde_json::Value = serde_json::from_str(&stdout_dot).unwrap();
    let v_cc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v_dot["cyclomatic"], v_cc["cyclomatic"],
        "cyclomatic must agree across `.` and `::` qualified forms"
    );
    assert_eq!(
        v_dot["lines_of_code"], v_cc["lines_of_code"],
        "lines_of_code must agree across `.` and `::` qualified forms"
    );
}

// =============================================================================
// TEST 8: `explain` accepts Rust Type::method qualified form.
// =============================================================================
#[test]
fn explain_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, _stdout, stderr) = run_tldr(&[
        "explain",
        &file,
        "ParserPool::parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "explain must accept Rust Type::method form. stderr={}",
        stderr
    );
}

// =============================================================================
// TEST 9: `references` accepts Rust Type::method qualified form and
// finds the definition (pre-fix returned 0 definitions silently).
// =============================================================================
#[test]
fn references_accepts_rust_qualified_name() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, stdout, stderr) = run_tldr(&[
        "references",
        "ParserPool::parse",
        &file,
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "references must accept Rust Type::method form. stderr={}",
        stderr
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("references json must parse");
    let defs = v["definitions"]
        .as_array()
        .expect("definitions[] array required");
    assert!(
        !defs.is_empty(),
        "references must surface at least one definition for \
         ParserPool::parse (pre-fix returned empty array silently). \
         got: {}",
        stdout
    );
}

// =============================================================================
// TEST 10: bare-name compatibility — applying the new branch must not
// break the existing bare-name path. (Regression guard.)
// =============================================================================
#[test]
fn complexity_bare_name_still_works() {
    let Some(file) = require_corpus_or_skip() else {
        return;
    };
    let (exit, stdout, stderr) = run_tldr(&[
        "complexity",
        &file,
        "parse",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "bare-name complexity must continue to work. stderr={}",
        stderr
    );
    let _v: serde_json::Value =
        serde_json::from_str(&stdout).expect("complexity json must parse");
}
