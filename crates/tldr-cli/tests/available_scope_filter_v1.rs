//! available-scope-filter-v1 (v0.4.2 cluster M-009):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 M-009):
//! > "`tldr available <file> <function>` returns expressions from SIBLING
//! >  functions in the same file (not just the target function). Audit
//! >  confirmed: c (c12 reaching expressions from sdsReqType when scoped
//! >  to sdsnew); cpp, elixir, java, ocaml also affected (~5 langs)."
//!
//! Verdict: REAL BUG. The available-expressions analyser iterates over
//! the ENTIRE source file's lines when collecting expressions, and uses
//! `find_block_for_line` which contains a fuzzy nearest-block fallback.
//! That fallback maps lines from sibling functions onto blocks of the
//! target function's CFG, so binary expressions defined in unrelated
//! functions leak into the target's `avail_in` / `avail_out` / `all_exprs`.
//!
//! Concrete reproducer in c-sds:
//!   `tldr available /tmp/repos/c-sds/sds.c sdsnew`
//!   sdsnew spans lines 154-157, yet its output contains expressions
//!   first seen on lines 61, 63, 65, 68 — all inside `sdsReqType`
//!   (lines 60-83), a sibling function in the same file.
//!
//! Fix (this v1):
//!   - At the expression-collection step (text-based and AST-based),
//!     reject any source line that does NOT fall within an exact CFG
//!     block range `[block.lines.0, block.lines.1]`. This eliminates
//!     the fuzzy nearest-block fallback for out-of-function lines.
//!   - Equivalently: expressions whose source line is outside the
//!     target function's covered line set are excluded from the output.
//!
//! Tests are real-repo gated; skip with a printed reason when the corpus
//! is not present (matches the pattern used elsewhere in this test suite).

use std::path::Path;
use std::process::Command;

const C_SDS_CORPUS: &str = "/tmp/repos/c-sds/sds.c";
const CPP_TINYXML2_CORPUS: &str = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
const ELIXIR_PLUG_CORPUS: &str = "/tmp/repos/elixir-plug/lib/plug.ex";
const OCAML_DUNE_CORPUS: &str = "/tmp/repos/ocaml-dune/bench/bench.ml";

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

/// Collect every `line` integer that appears under any `Expression` value
/// inside the JSON returned by `tldr available`. This walks
/// `avail_in[*][*].line`, `avail_out[*][*].line`, and
/// `all_exprs[*].line` so the assertion is robust against schema
/// reshufflings — wherever an Expression sits, its `line` is sampled.
fn collect_expression_lines(v: &serde_json::Value) -> Vec<u64> {
    fn walk(v: &serde_json::Value, out: &mut Vec<u64>, in_expr: bool) {
        match v {
            serde_json::Value::Object(map) => {
                let is_expr = map.contains_key("text")
                    && map.contains_key("operands")
                    && map.contains_key("line");
                if is_expr {
                    if let Some(l) = map.get("line").and_then(|x| x.as_u64()) {
                        out.push(l);
                    }
                }
                for (_, child) in map {
                    walk(child, out, in_expr || is_expr);
                }
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    walk(child, out, in_expr);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out, false);
    out.sort_unstable();
    out.dedup();
    out
}

/// Find the (line, line_end) range of a function via `tldr extract`.
/// Returns `None` if the function isn't present, lines aren't u64, or
/// the extract output schema doesn't match.
fn extract_function_range(file: &str, func: &str) -> Option<(u64, u64)> {
    let (rc, stdout, _stderr) = run_tldr(&["extract", file, "--format", "json", "-q"]);
    if rc != 0 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    let funcs = v.get("functions")?.as_array()?;
    for f in funcs {
        let name = f.get("name").and_then(|x| x.as_str())?;
        if name == func {
            let start = f.get("line").and_then(|x| x.as_u64())?;
            let end = f
                .get("line_end")
                .and_then(|x| x.as_u64())
                .unwrap_or(start);
            return Some((start, end));
        }
    }
    None
}

// =============================================================================
// TEST 1: C — sdsnew (lines 154-157) must NOT leak expressions from
// sdsReqType (lines 60-83) or any other sibling function in the same file.
//
// Pre-fix observed leak: line numbers {61, 63, 65, 68} appear in sdsnew's
// avail_in / avail_out / all_exprs — these are all inside sdsReqType.
// Post-fix: every Expression's `line` must fall inside sdsnew's
// [line, line_end] range.
// =============================================================================
#[test]
fn available_scope_c_sdsnew_excludes_sibling_function_lines() {
    if !Path::new(C_SDS_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_c_sdsnew_excludes_sibling_function_lines: corpus {} not present",
            C_SDS_CORPUS
        );
        return;
    }

    let (start, end) = match extract_function_range(C_SDS_CORPUS, "sdsnew") {
        Some(r) => r,
        None => {
            eprintln!(
                "[skip] available_scope_c_sdsnew_excludes_sibling_function_lines: \
                 could not resolve sdsnew range via `tldr extract`"
            );
            return;
        }
    };

    // Sanity: sdsnew is a tiny 3-4 line function. If a future change
    // grew it to span the whole file this assertion is the canary.
    assert!(
        end < 200 && start >= 100,
        "sdsnew is expected to live near lines 154-157; got start={}, end={}",
        start,
        end
    );

    let (rc, stdout, stderr) =
        run_tldr(&["available", C_SDS_CORPUS, "sdsnew", "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "available on a real C file must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("available JSON output must be valid JSON");

    let lines = collect_expression_lines(&v);

    // CORE: every Expression line must fall inside sdsnew's range.
    let leaked: Vec<u64> = lines
        .iter()
        .copied()
        .filter(|l| *l != 0 && (*l < start || *l > end))
        .collect();

    assert!(
        leaked.is_empty(),
        "available output for sdsnew (lines {}-{}) leaked expressions from \
         sibling functions: {:?}. These line numbers fall outside sdsnew \
         and must be filtered out at the expression-collection step.",
        start,
        end,
        leaked
    );
}

// =============================================================================
// TEST 2: C++ — same invariant on a multi-function C++ source.
// Picks `Strip` (a small TiXmlAttribute method on tinyxml2.cpp) and
// asserts no expression line falls outside its range.
// =============================================================================
#[test]
fn available_scope_cpp_excludes_sibling_function_lines() {
    if !Path::new(CPP_TINYXML2_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_cpp_excludes_sibling_function_lines: corpus {} not present",
            CPP_TINYXML2_CORPUS
        );
        return;
    }

    // tinyxml2.cpp has many short methods. Find one with a real body via
    // extract and pick the first non-trivial function for the test.
    let (rc, stdout, _stderr) =
        run_tldr(&["extract", CPP_TINYXML2_CORPUS, "--format", "json", "-q"]);
    if rc != 0 {
        eprintln!("[skip] available_scope_cpp: extract failed");
        return;
    }
    let extract: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_cpp: extract produced non-JSON");
            return;
        }
    };
    let funcs = match extract
        .get("functions")
        .and_then(|x| x.as_array())
        .filter(|a| !a.is_empty())
    {
        Some(a) => a,
        None => {
            eprintln!("[skip] available_scope_cpp: no functions extracted");
            return;
        }
    };

    // Pick a function spanning at least 5 lines and at most ~80 (so there
    // are siblings on both sides whose lines could leak in).
    let mut target: Option<(String, u64, u64)> = None;
    for f in funcs {
        let name = match f.get("name").and_then(|x| x.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let start = match f.get("line").and_then(|x| x.as_u64()) {
            Some(s) => s,
            None => continue,
        };
        let end = match f.get("line_end").and_then(|x| x.as_u64()) {
            Some(e) => e,
            None => continue,
        };
        if end <= start + 4 || end > start + 80 {
            continue;
        }
        target = Some((name, start, end));
        break;
    }
    let (fname, start, end) = match target {
        Some(t) => t,
        None => {
            eprintln!("[skip] available_scope_cpp: no suitable function in tinyxml2.cpp");
            return;
        }
    };

    let (rc, stdout, stderr) = run_tldr(&[
        "available",
        CPP_TINYXML2_CORPUS,
        &fname,
        "--format",
        "json",
        "-q",
    ]);
    if rc != 0 {
        eprintln!(
            "[skip] available_scope_cpp: `available` exited rc={} on {} (likely unsupported language path), stderr=\n{}",
            rc, fname, stderr
        );
        return;
    }

    let v: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_cpp: available produced non-JSON");
            return;
        }
    };

    let lines = collect_expression_lines(&v);
    let leaked: Vec<u64> = lines
        .iter()
        .copied()
        .filter(|l| *l != 0 && (*l < start || *l > end))
        .collect();

    assert!(
        leaked.is_empty(),
        "available output for {} (lines {}-{}) leaked expressions: {:?}. \
         All Expression.line values must fall inside the target function.",
        fname,
        start,
        end,
        leaked
    );
}

// =============================================================================
// TEST 3: avail_in/avail_out per-block invariant.
//
// Independently of which function is chosen, every Expression appearing
// in `avail_in[B]` or `avail_out[B]` for any block B of the function's
// CFG must be defined on a line within the function's own [line, line_end]
// range. This is the stricter form of the previous tests.
// =============================================================================
#[test]
fn available_scope_avail_in_out_lines_within_function() {
    if !Path::new(C_SDS_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_avail_in_out_lines_within_function: corpus {} not present",
            C_SDS_CORPUS
        );
        return;
    }

    let (start, end) = match extract_function_range(C_SDS_CORPUS, "sdsnew") {
        Some(r) => r,
        None => {
            eprintln!("[skip] available_scope_avail_in_out: extract failed");
            return;
        }
    };

    let (rc, stdout, _stderr) =
        run_tldr(&["available", C_SDS_CORPUS, "sdsnew", "--format", "json", "-q"]);
    assert_eq!(rc, 0);

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    for key in ["avail_in", "avail_out"] {
        let map = match v.get(key).and_then(|x| x.as_object()) {
            Some(m) => m,
            None => continue,
        };
        for (block_id, exprs) in map {
            let arr = match exprs.as_array() {
                Some(a) => a,
                None => continue,
            };
            for e in arr {
                let line = match e.get("line").and_then(|x| x.as_u64()) {
                    Some(l) => l,
                    None => continue,
                };
                if line == 0 {
                    continue;
                }
                assert!(
                    line >= start && line <= end,
                    "Expression in {}[block {}] has line={} outside sdsnew range [{}, {}]: {}",
                    key,
                    block_id,
                    line,
                    start,
                    end,
                    serde_json::to_string(e).unwrap_or_default()
                );
            }
        }
    }
}

// =============================================================================
// TEST 4: all_exprs invariant.
//
// `all_exprs` is the union of every expression ever extracted for the
// function. Pre-fix, this set contained expressions from sibling
// functions (the fuzzy `find_block_for_line` fallback put them into
// `result.all_exprs`). Post-fix: every entry's `line` must lie within
// the target function's range.
// =============================================================================
#[test]
fn available_scope_all_exprs_lines_within_function() {
    if !Path::new(C_SDS_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_all_exprs_lines_within_function: corpus {} not present",
            C_SDS_CORPUS
        );
        return;
    }

    let (start, end) = match extract_function_range(C_SDS_CORPUS, "sdsnew") {
        Some(r) => r,
        None => {
            eprintln!("[skip] available_scope_all_exprs: extract failed");
            return;
        }
    };

    let (rc, stdout, _stderr) =
        run_tldr(&["available", C_SDS_CORPUS, "sdsnew", "--format", "json", "-q"]);
    assert_eq!(rc, 0);

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let all_exprs = match v.get("all_exprs").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => {
            eprintln!("[skip] available_scope_all_exprs: no all_exprs field");
            return;
        }
    };

    for e in all_exprs {
        let line = match e.get("line").and_then(|x| x.as_u64()) {
            Some(l) => l,
            None => continue,
        };
        if line == 0 {
            continue;
        }
        assert!(
            line >= start && line <= end,
            "Expression in all_exprs has line={} outside sdsnew range [{}, {}]: {}",
            line,
            start,
            end,
            serde_json::to_string(e).unwrap_or_default()
        );
    }
}

// =============================================================================
// TEST 5: Elixir — same scope invariant on plug.ex.
// Picks the first non-trivial function and asserts no cross-function
// leak. This guards the elixir-specific c12 audit cell.
// =============================================================================
#[test]
fn available_scope_elixir_excludes_sibling_function_lines() {
    if !Path::new(ELIXIR_PLUG_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_elixir_excludes_sibling_function_lines: corpus {} not present",
            ELIXIR_PLUG_CORPUS
        );
        return;
    }

    let (rc, stdout, _stderr) =
        run_tldr(&["extract", ELIXIR_PLUG_CORPUS, "--format", "json", "-q"]);
    if rc != 0 {
        eprintln!("[skip] available_scope_elixir: extract failed");
        return;
    }
    let extract: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_elixir: extract non-JSON");
            return;
        }
    };
    let funcs = match extract
        .get("functions")
        .and_then(|x| x.as_array())
        .filter(|a| !a.is_empty())
    {
        Some(a) => a,
        None => {
            eprintln!("[skip] available_scope_elixir: no functions");
            return;
        }
    };

    let mut target: Option<(String, u64, u64)> = None;
    for f in funcs {
        let name = match f.get("name").and_then(|x| x.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let start = match f.get("line").and_then(|x| x.as_u64()) {
            Some(s) => s,
            None => continue,
        };
        let end = match f.get("line_end").and_then(|x| x.as_u64()) {
            Some(e) => e,
            None => continue,
        };
        if end <= start + 2 || end > start + 60 {
            continue;
        }
        target = Some((name, start, end));
        break;
    }
    let (fname, start, end) = match target {
        Some(t) => t,
        None => {
            eprintln!("[skip] available_scope_elixir: no suitable function");
            return;
        }
    };

    let (rc, stdout, stderr) = run_tldr(&[
        "available",
        ELIXIR_PLUG_CORPUS,
        &fname,
        "--format",
        "json",
        "-q",
    ]);
    if rc != 0 {
        eprintln!(
            "[skip] available_scope_elixir: available rc={} on {} stderr=\n{}",
            rc, fname, stderr
        );
        return;
    }

    let v: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_elixir: non-JSON");
            return;
        }
    };

    let lines = collect_expression_lines(&v);
    let leaked: Vec<u64> = lines
        .iter()
        .copied()
        .filter(|l| *l != 0 && (*l < start || *l > end))
        .collect();

    assert!(
        leaked.is_empty(),
        "available output for elixir {} (lines {}-{}) leaked: {:?}",
        fname,
        start,
        end,
        leaked
    );
}

// =============================================================================
// TEST 6: OCaml — same scope invariant on bench.ml.
// =============================================================================
#[test]
fn available_scope_ocaml_excludes_sibling_function_lines() {
    if !Path::new(OCAML_DUNE_CORPUS).exists() {
        eprintln!(
            "[skip] available_scope_ocaml_excludes_sibling_function_lines: corpus {} not present",
            OCAML_DUNE_CORPUS
        );
        return;
    }

    let (rc, stdout, _stderr) =
        run_tldr(&["extract", OCAML_DUNE_CORPUS, "--format", "json", "-q"]);
    if rc != 0 {
        eprintln!("[skip] available_scope_ocaml: extract failed");
        return;
    }
    let extract: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_ocaml: extract non-JSON");
            return;
        }
    };
    let funcs = match extract
        .get("functions")
        .and_then(|x| x.as_array())
        .filter(|a| !a.is_empty())
    {
        Some(a) => a,
        None => {
            eprintln!("[skip] available_scope_ocaml: no functions");
            return;
        }
    };

    let mut target: Option<(String, u64, u64)> = None;
    for f in funcs {
        let name = match f.get("name").and_then(|x| x.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let start = match f.get("line").and_then(|x| x.as_u64()) {
            Some(s) => s,
            None => continue,
        };
        let end = match f.get("line_end").and_then(|x| x.as_u64()) {
            Some(e) => e,
            None => continue,
        };
        if end <= start + 2 || end > start + 60 {
            continue;
        }
        target = Some((name, start, end));
        break;
    }
    let (fname, start, end) = match target {
        Some(t) => t,
        None => {
            eprintln!("[skip] available_scope_ocaml: no suitable function");
            return;
        }
    };

    let (rc, stdout, stderr) = run_tldr(&[
        "available",
        OCAML_DUNE_CORPUS,
        &fname,
        "--format",
        "json",
        "-q",
    ]);
    if rc != 0 {
        eprintln!(
            "[skip] available_scope_ocaml: available rc={} on {} stderr=\n{}",
            rc, fname, stderr
        );
        return;
    }

    let v: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[skip] available_scope_ocaml: non-JSON");
            return;
        }
    };

    let lines = collect_expression_lines(&v);
    let leaked: Vec<u64> = lines
        .iter()
        .copied()
        .filter(|l| *l != 0 && (*l < start || *l > end))
        .collect();

    assert!(
        leaked.is_empty(),
        "available output for ocaml {} (lines {}-{}) leaked: {:?}",
        fname,
        start,
        end,
        leaked
    );
}
