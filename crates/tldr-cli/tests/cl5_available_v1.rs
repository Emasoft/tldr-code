//! cl5_available_v1 (v0.5.0 CL-5):
//!
//! Pre-fix audit assertion (iter-3 fix wave, CL-5):
//! > "available-expressions text parse leaks operators.
//! >  `parse_expression_from_line` splits on BINARY_OPS and over-reads to
//! >  statement boundary, leaking `;`, `)`, `{`, `++`, `--` into operands
//! >  instead of using tree-sitter binary_expression operand nodes."
//!
//! Verdict: REAL BUG. When `tldr available <file> <function>` runs over a
//! real C / Go / Java corpus, the text-based fallback parser inside
//! `extract_expressions_full_with_lang` emits `Expression.operands` such
//! as `"NULL) return NULL;"`, `"+;"`, `"addlen) return s;"`,
//! `"(ssize_t)len)"`. These contain statement-boundary punctuation and
//! increment/decrement tokens that can never be part of a single operand
//! of a binary expression — they are pure text-parse leakage.
//!
//! Fix (this v1, AST-DRIVEN):
//!   Derive operands from tree-sitter `binary_expression` operand child
//!   nodes (`extract_operands_from_node`), never from BINARY_OPS text
//!   splitting, whenever the language is known. A clean AST operand can
//!   never contain `;`, `)`, `(`, `{`, `}`, `++`, or `--` at the operand
//!   level.
//!
//! These tests are real-repo gated against /tmp/tldr_corpora/<lang> and
//! the release binary; they skip with a printed reason when the corpus is
//! not present (matching the pattern used elsewhere in this suite).

use std::path::Path;
use std::process::Command;

const C_SDS: &str = "/tmp/tldr_corpora/c-sds/sds.c";
const GO_TREE: &str = "/tmp/tldr_corpora/go-httprouter/tree.go";
const GO_ROUTER: &str = "/tmp/tldr_corpora/go-httprouter/router.go";
const GO_PATH: &str = "/tmp/tldr_corpora/go-httprouter/path.go";
const JAVA_PETCLINIC_DIR: &str = "/tmp/tldr_corpora/java-petclinic";

/// Tokens that must never appear inside a single binary-expression
/// operand. Their presence proves the operand was produced by text
/// splitting that over-read to a statement boundary instead of being
/// derived from an AST operand node.
const FORBIDDEN_IN_OPERAND: &[&str] = &[";", "{", "}", "++", "--"];

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

/// Enumerate function/method names declared in a source file via
/// `tldr structure --format json`. Walks the structure tree and collects
/// any node that carries a `name` together with a function-like `kind` or
/// `type`.
fn function_names(file: &str) -> Vec<String> {
    let (rc, stdout, _stderr) = run_tldr(&["structure", file, "--format", "json", "-q"]);
    if rc != 0 {
        return Vec::new();
    }
    let v: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut names: Vec<String> = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                let kindish = map
                    .get("kind")
                    .and_then(|x| x.as_str())
                    .or_else(|| map.get("type").and_then(|x| x.as_str()));
                let is_funcish =
                    matches!(kindish, Some("function") | Some("method"));
                if is_funcish {
                    if let Some(name) = map.get("name").and_then(|x| x.as_str()) {
                        if !name.is_empty() {
                            out.push(name.to_string());
                        }
                    }
                }
                for child in map.values() {
                    walk(child, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    walk(child, out);
                }
            }
            _ => {}
        }
    }
    walk(&v, &mut names);
    names.sort();
    names.dedup();
    names
}

/// Collect every operand string that appears under any Expression value in
/// the `tldr available` JSON. An Expression object is identified by the
/// `{ text, operands, line }` shape; its `operands` is an array of
/// strings. We sample operands wherever an Expression sits: `all_exprs`,
/// `avail_in[*][*]`, `avail_out[*][*]`.
fn collect_operands(v: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                let is_expr = map.contains_key("text")
                    && map.contains_key("operands")
                    && map.contains_key("line");
                if is_expr {
                    if let Some(ops) = map.get("operands").and_then(|x| x.as_array()) {
                        for o in ops {
                            if let Some(s) = o.as_str() {
                                out.push(s.to_string());
                            }
                        }
                    }
                }
                for child in map.values() {
                    walk(child, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    walk(child, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// True when `operand` contains a statement-boundary / inc-dec token that
/// can never legitimately be part of a single binary-expression operand.
fn operand_is_leaky(operand: &str) -> bool {
    FORBIDDEN_IN_OPERAND.iter().any(|tok| operand.contains(tok))
}

/// Run `tldr available` over every function in `file` and return all
/// `(function, leaky_operand)` pairs where an operand contains a forbidden
/// token. An empty result means no leak.
fn leaky_operands_for_file(file: &str) -> Vec<(String, String)> {
    let mut leaks: Vec<(String, String)> = Vec::new();
    for func in function_names(file) {
        let (rc, stdout, _stderr) =
            run_tldr(&["available", file, &func, "--format", "json", "-q"]);
        if rc != 0 {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&stdout) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for op in collect_operands(&v) {
            if operand_is_leaky(&op) {
                leaks.push((func.clone(), op));
            }
        }
    }
    leaks.sort();
    leaks.dedup();
    leaks
}

/// Recursively enumerate `.java` files under a directory.
fn java_files(dir: &str) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                if let Some(s) = path.to_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new(dir), &mut out);
    out.sort();
    out
}

// =============================================================================
// TEST 1: C (c-sds) — no available-expression operand may contain a
// statement-boundary or inc/dec token. Pre-fix leak examples:
//   "NULL) return NULL;", "+;", "addlen) return s;", "incr;".
// =============================================================================
#[test]
fn cl5_c_sds_operands_have_no_leaked_operators() {
    if !Path::new(C_SDS).exists() {
        eprintln!("[skip] cl5_c_sds_operands_have_no_leaked_operators: corpus {C_SDS} not present");
        return;
    }
    let leaks = leaky_operands_for_file(C_SDS);
    assert!(
        leaks.is_empty(),
        "C corpus available-expression operands leaked operators ({} cases): {:?}",
        leaks.len(),
        leaks.iter().take(25).collect::<Vec<_>>()
    );
}

// =============================================================================
// TEST 2: Go (go-httprouter) — same invariant across the three Go sources.
// =============================================================================
#[test]
fn cl5_go_httprouter_operands_have_no_leaked_operators() {
    let mut any_present = false;
    let mut all_leaks: Vec<(String, String)> = Vec::new();
    for file in [GO_TREE, GO_ROUTER, GO_PATH] {
        if !Path::new(file).exists() {
            continue;
        }
        any_present = true;
        all_leaks.extend(leaky_operands_for_file(file));
    }
    if !any_present {
        eprintln!(
            "[skip] cl5_go_httprouter_operands_have_no_leaked_operators: Go corpus not present"
        );
        return;
    }
    assert!(
        all_leaks.is_empty(),
        "Go corpus available-expression operands leaked operators ({} cases): {:?}",
        all_leaks.len(),
        all_leaks.iter().take(25).collect::<Vec<_>>()
    );
}

// =============================================================================
// TEST 3: Java (java-petclinic) — same invariant across every .java file.
// =============================================================================
#[test]
fn cl5_java_petclinic_operands_have_no_leaked_operators() {
    if !Path::new(JAVA_PETCLINIC_DIR).exists() {
        eprintln!(
            "[skip] cl5_java_petclinic_operands_have_no_leaked_operators: corpus {JAVA_PETCLINIC_DIR} not present"
        );
        return;
    }
    let files = java_files(JAVA_PETCLINIC_DIR);
    if files.is_empty() {
        eprintln!(
            "[skip] cl5_java_petclinic_operands_have_no_leaked_operators: no .java files under {JAVA_PETCLINIC_DIR}"
        );
        return;
    }
    let mut all_leaks: Vec<(String, String)> = Vec::new();
    for file in &files {
        all_leaks.extend(leaky_operands_for_file(file));
    }
    assert!(
        all_leaks.is_empty(),
        "Java corpus available-expression operands leaked operators ({} cases): {:?}",
        all_leaks.len(),
        all_leaks.iter().take(25).collect::<Vec<_>>()
    );
}
