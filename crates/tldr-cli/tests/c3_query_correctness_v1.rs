//! c3-query-correctness-v1 (v0.5.0 AUDIT-FIX, C3) — impact / whatbreaks /
//! context query-correctness characterization tests.
//!
//! Three independent gaps, each guarded against a real corpus under
//! `/tmp/tldr_corpora_b/` (tests skip loudly when the corpus is absent so they
//! never silently pass on a machine without corpora):
//!
//!   (a) impact — C++ method-call caller resolution. `StrPair::GetStr` is
//!       genuinely called via member fields / locals (`_value.GetStr()`,
//!       `endTag.GetStr()`) in tinyxml2. The C++ call graph misses those
//!       method-call edges, so impact reported `caller_count = 0`
//!       ("Entry point"). The references-enrichment fallback dropped the
//!       callers because the CL-2 receiver check compared the receiver
//!       VARIABLE (`endTag`) against the target's TYPE qualifier (`StrPair`).
//!       After the fix the receiver is type-resolved and the callers survive.
//!
//!   (b) whatbreaks — struct/type classification. `whatbreaks GlobSet` on
//!       ripgrep classified a public STRUCT as `target_type=function`. After
//!       the fix the AST/structure resolves it to a type kind.
//!
//!   (c) context — call-graph neighborhood expansion. `context <fn>` for a
//!       Lua nested `local function` (and Swift cross-file `Type.method`)
//!       collapsed to the entry only with `calls: []`. After the fix the
//!       neighborhood is rebuilt from the working call graph.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora_b").join(name)
}

/// True when `p` exists and contains at least one non-`.git` regular file.
fn corpus_ready<P: AsRef<Path>>(p: P) -> bool {
    fn walk(p: &Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}

fn tldr_cmd() -> Command {
    let mut c = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    // Never route through a daemon — characterize the direct-compute path.
    c.env("TLDR_NO_DAEMON", "1");
    c
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

// ---------------------------------------------------------------------------
// (a) impact — C++ method-call caller resolution
// ---------------------------------------------------------------------------

/// Collect every caller node's `(function, file_basename)` across all targets.
fn collect_callers(v: &Value) -> Vec<(String, String)> {
    fn basename(p: &str) -> String {
        Path::new(p)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| p.to_string())
    }
    fn walk(tree: &Value, out: &mut Vec<(String, String)>) {
        if let Some(callers) = tree.get("callers").and_then(|c| c.as_array()) {
            for c in callers {
                let func = c
                    .get("function")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string();
                let file = basename(c.get("file").and_then(|f| f.as_str()).unwrap_or(""));
                out.push((func, file));
                walk(c, out);
            }
        }
    }
    let mut out = Vec::new();
    if let Some(targets) = v.get("targets").and_then(|t| t.as_object()) {
        for (_k, tree) in targets {
            walk(tree, &mut out);
        }
    }
    out
}

/// Max `caller_count` across all target trees.
fn max_caller_count(v: &Value) -> u64 {
    let mut max = 0u64;
    if let Some(targets) = v.get("targets").and_then(|t| t.as_object()) {
        for (_k, tree) in targets {
            if let Some(n) = tree.get("caller_count").and_then(|c| c.as_u64()) {
                max = max.max(n);
            }
        }
    }
    max
}

#[test]
fn cpp_impact_getstr_has_callers() {
    let c = corpus("cpp-tinyxml2");
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP cpp_impact_getstr_has_callers: corpus missing at {}",
            c.display()
        );
        return;
    }

    let v = run_json(&["impact", "GetStr", c.to_str().unwrap(), "--format", "json"]);

    // GAP (a): the C++ method-call call graph misses `x.GetStr()` edges, so the
    // base report is "Entry point" with caller_count 0. The fix recovers the
    // genuine callers (e.g. the local `StrPair endTag; ... endTag.GetStr()`
    // site) via type-resolved references enrichment.
    let max = max_caller_count(&v);
    assert!(
        max > 0,
        "cpp impact GetStr reported caller_count=0 (expected >0); callers={:?}\nreport={v}",
        collect_callers(&v)
    );
}

// ---------------------------------------------------------------------------
// (b) whatbreaks — struct/type classification
// ---------------------------------------------------------------------------

#[test]
fn rust_whatbreaks_globset_is_type() {
    let c = corpus("rust-ripgrep");
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP rust_whatbreaks_globset_is_type: corpus missing at {}",
            c.display()
        );
        return;
    }

    let v = run_json(&[
        "whatbreaks",
        "GlobSet",
        c.to_str().unwrap(),
        "--format",
        "json",
    ]);

    // GAP (b): `GlobSet` is a `pub struct`, not a function. The default
    // detection bucketed it as `function`. The fix relabels it to its
    // AST-resolved type kind.
    let tt = v
        .get("target_type")
        .and_then(|t| t.as_str())
        .unwrap_or("<missing>");
    let type_kinds = [
        "struct",
        "type",
        "enum",
        "trait",
        "class",
        "interface",
        "union",
        "record",
        "object",
    ];
    assert!(
        type_kinds.contains(&tt),
        "whatbreaks GlobSet target_type={tt:?} (expected a struct/type kind); report={v}"
    );
}

// ---------------------------------------------------------------------------
// (c) context — call-graph neighborhood expansion
// ---------------------------------------------------------------------------

/// The entry function's `calls` array within a context result.
fn entry_calls(v: &Value, entry_leaf: &str) -> Option<Vec<String>> {
    let fns = v.get("functions").and_then(|f| f.as_array())?;
    for f in fns {
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let leaf = name.rsplit(['.', ':']).next().unwrap_or(name);
        if name == entry_leaf || leaf == entry_leaf {
            return Some(
                f.get("calls")
                    .and_then(|c| c.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            );
        }
    }
    None
}

#[test]
fn lua_context_nested_local_function_expands_neighborhood() {
    // lua-lsp `visit_statement` is a NESTED `local function` inside `gen_scopes`
    // in analyze.lua. `extract_file` does not surface nested locals, so the
    // core builder's per-node verification dropped it and the result collapsed
    // to an unrelated single function with calls:[]. The call graph DOES carry
    // `visit_statement`'s outgoing edges; the fix rebuilds from it.
    let c = corpus("lua-lsp/lua-lsp");
    let c = if corpus_ready(&c) { c } else { corpus("lua-lsp") };
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP lua_context_nested_local_function_expands_neighborhood: corpus missing at {}",
            c.display()
        );
        return;
    }

    let v = run_json(&[
        "context",
        "visit_statement",
        c.to_str().unwrap(),
        "--depth",
        "3",
        "--format",
        "json",
    ]);

    // The entry must be present AND its call neighborhood must be non-empty.
    let calls = entry_calls(&v, "visit_statement");
    assert!(
        calls.is_some(),
        "context visit_statement did not include the entry function at all; result={v}"
    );
    let calls = calls.unwrap();
    assert!(
        !calls.is_empty(),
        "context visit_statement returned the entry with calls:[] (no neighborhood expansion); result={v}"
    );

    // And the overall context must contain more than the single entry node.
    let n = v
        .get("functions")
        .and_then(|f| f.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        n > 1,
        "context visit_statement returned {n} function(s) (expected a multi-node neighborhood); result={v}"
    );
}

#[test]
fn swift_context_cross_file_method_expands_neighborhood() {
    // swift-collections `Deque.init` has many call-graph callees across files,
    // but the core builder returned 0 functions (cross-file `Type.method`
    // entry resolution failed). The fix rebuilds the neighborhood from the
    // call graph.
    let c = corpus("swift-collections");
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP swift_context_cross_file_method_expands_neighborhood: corpus missing at {}",
            c.display()
        );
        return;
    }

    let v = run_json(&[
        "context",
        "Deque.init",
        c.to_str().unwrap(),
        "--depth",
        "3",
        "--format",
        "json",
    ]);

    let n = v
        .get("functions")
        .and_then(|f| f.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        n > 1,
        "context Deque.init returned {n} function(s) (expected a multi-node neighborhood); result={v}"
    );
}
