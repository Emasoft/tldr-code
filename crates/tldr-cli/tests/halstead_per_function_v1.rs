//! halstead-per-function-v1 (v0.4.2 cluster M-026):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 M-026):
//! > "`tldr halstead` emits per-function rows but with IDENTICAL metrics for
//! >  every function in the file — the metric calc uses the same body
//! >  reference repeatedly. Affected: kotlin (Instant.kt 31 funcs all
//! >  identical), elixir (5 multi-clause send_resp rows all identical)."
//!
//! Root cause: `analyze_halstead` extracted per-function `FunctionInfo`
//! entries (correct names + line numbers from the AST extractor), but
//! resolved each entry to a `tree_sitter::Node` via
//! `find_function_node(name, ...)` — which returns the FIRST node matching
//! the name. For files with overloaded methods (kotlin `plus`/`minus`,
//! elixir multi-clause `send_resp`), every function row recomputed
//! Halstead operators/operands over the SAME first-matching subtree.
//!
//! Fix (this v1):
//!   - resolve each `FunctionInfo` to its *own* AST node by matching both
//!     name AND start line, so per-function counters walk the correct
//!     subtree.
//!
//! Tests are real-repo gated; skip with a printed reason when the corpus
//! is not present (matches the pattern used elsewhere in this test suite).

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
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


use std::path::Path;
use std::process::Command;

const KOTLIN_CORPUS: &str = "/tmp/repos/kotlin-datetime";
const ELIXIR_CORPUS: &str = "/tmp/repos/elixir-plug";

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

// =============================================================================
// TEST 1: kotlin — overloaded `plus`/`minus`/`until` methods in Instant.kt
// must NOT broadcast identical Halstead metrics across all rows.
//
// Pre-fix: 31 function rows, only 10 unique `vocabulary` values
// (broadcast: every `plus` got the same metrics as the first `plus`).
// Post-fix: more variety — bodies of overloads differ, so at least
// some `plus`/`minus`/`until` rows must have distinct metrics.
// =============================================================================
#[test]
fn kotlin_overloaded_functions_have_distinct_metrics() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "SKIP: corpus not present at {} — real-repo gated test",
            KOTLIN_CORPUS
        );
        return;
    }

    let file = format!("{}/core/common/src/Instant.kt", KOTLIN_CORPUS);
    let (exit, stdout, stderr) = run_tldr(&["halstead", &file, "--format", "json"]);
    assert_eq!(exit, 0, "halstead exit nonzero. stderr={}", stderr);

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("halstead json must parse");
    let funcs = v["functions"].as_array().expect("functions[] array");
    assert!(
        funcs.len() >= 10,
        "expected at least 10 functions in Instant.kt, got {}",
        funcs.len()
    );

    // Collect (name, line, vocabulary) for all functions named `plus`.
    let plus_rows: Vec<(u64, u64)> = funcs
        .iter()
        .filter(|f| f["name"].as_str() == Some("plus"))
        .map(|f| {
            (
                f["line"].as_u64().unwrap_or(0),
                f["metrics"]["vocabulary"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert!(
        plus_rows.len() >= 3,
        "expected >=3 overloaded `plus` rows, got {}",
        plus_rows.len()
    );

    // Distinct lines (always true since the AST extractor emits per-line).
    let distinct_lines: std::collections::HashSet<u64> =
        plus_rows.iter().map(|(l, _)| *l).collect();
    assert_eq!(
        distinct_lines.len(),
        plus_rows.len(),
        "each overloaded `plus` row must have a distinct line"
    );

    // BROADCAST BUG ASSERTION: pre-fix all `plus` rows have IDENTICAL
    // `vocabulary`. Post-fix at least two `plus` overloads must differ
    // because they have different bodies (e.g. one is a single-arg
    // `DateTimeUnit` overload, another a multi-arg `DateTimePeriod`
    // overload).
    let distinct_vocabs: std::collections::HashSet<u64> =
        plus_rows.iter().map(|(_, v)| *v).collect();
    assert!(
        distinct_vocabs.len() >= 2,
        "BROADCAST BUG: all {} `plus` overloads share vocabulary={:?}. \
         Per-function AST traversal is reusing the SAME first-matching \
         function body for every row. Rows: {:?}",
        plus_rows.len(),
        distinct_vocabs,
        plus_rows
    );
}

// =============================================================================
// TEST 2: kotlin — file-aggregate broadcast detection. With 31 functions,
// we must see significantly more than 10 unique vocabulary values.
// =============================================================================
#[test]
fn kotlin_file_aggregate_broadcast_detection() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "SKIP: corpus not present at {} — real-repo gated test",
            KOTLIN_CORPUS
        );
        return;
    }

    let file = format!("{}/core/common/src/Instant.kt", KOTLIN_CORPUS);
    let (exit, stdout, stderr) = run_tldr(&["halstead", &file, "--format", "json"]);
    assert_eq!(exit, 0, "halstead exit nonzero. stderr={}", stderr);

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("halstead json must parse");
    let funcs = v["functions"].as_array().expect("functions[] array");
    let total = funcs.len();
    assert!(
        total >= 20,
        "expected Instant.kt to surface >=20 functions, got {}",
        total
    );

    // Collect unique (vocabulary, length, volume) tuples — quantized to
    // catch broadcast where every row has identical raw metrics.
    let distinct: std::collections::HashSet<(u64, u64, u64)> = funcs
        .iter()
        .map(|f| {
            let m = &f["metrics"];
            (
                m["vocabulary"].as_u64().unwrap_or(0),
                m["length"].as_u64().unwrap_or(0),
                // volume is f64 — quantize by *1000 truncation for set membership
                (m["volume"].as_f64().unwrap_or(0.0) * 1000.0) as u64,
            )
        })
        .collect();

    // Pre-fix: ~10 unique tuples for 31 functions (broadcast).
    // Post-fix: each function has its own subtree → expect MOST rows
    // to have distinct tuples. Require >= 60% distinctness, which the
    // pre-fix output (10/31 = 32%) fails.
    let distinct_ratio = distinct.len() as f64 / total as f64;
    assert!(
        distinct_ratio >= 0.60,
        "BROADCAST BUG: only {} unique (vocab,length,volume) tuples for {} \
         functions ({:.0}% distinctness, need >= 60%). Per-function AST \
         traversal is broadcasting the same metrics across rows.",
        distinct.len(),
        total,
        distinct_ratio * 100.0
    );
}

// =============================================================================
// TEST 3: elixir — multi-clause `send_resp` in Plug.Conn must NOT all
// emit the same metrics. The 5 clauses (head + 4 body clauses) have
// genuinely different bodies (state checks, IO operations).
// =============================================================================
#[test]
fn elixir_multiclause_send_resp_distinct_metrics() {
    if !corpus_ready(ELIXIR_CORPUS) {
        eprintln!(
            "SKIP: corpus not present at {} — real-repo gated test",
            ELIXIR_CORPUS
        );
        return;
    }

    let file = format!("{}/lib/plug/conn.ex", ELIXIR_CORPUS);
    let (exit, stdout, stderr) = run_tldr(&["halstead", &file, "--format", "json"]);
    assert_eq!(exit, 0, "halstead exit nonzero. stderr={}", stderr);

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("halstead json must parse");
    let funcs = v["functions"].as_array().expect("functions[] array");

    let send_resp_rows: Vec<(u64, u64)> = funcs
        .iter()
        .filter(|f| f["name"].as_str() == Some("send_resp"))
        .map(|f| {
            (
                f["line"].as_u64().unwrap_or(0),
                f["metrics"]["vocabulary"].as_u64().unwrap_or(0),
            )
        })
        .collect();

    // Plug.Conn has multiple `send_resp` clauses — at least 3 rows.
    assert!(
        send_resp_rows.len() >= 3,
        "expected >=3 `send_resp` clause rows in Plug.Conn, got {}: rows={:?}",
        send_resp_rows.len(),
        send_resp_rows
    );

    // BROADCAST BUG ASSERTION: pre-fix all `send_resp` rows share the
    // same vocabulary (the bodyless head's tiny vocabulary, or the
    // first body-bearing clause's vocabulary — depends on the
    // find_function_node fallback logic). Post-fix: distinct clauses
    // with distinct bodies must show distinct vocabularies.
    let distinct_vocabs: std::collections::HashSet<u64> =
        send_resp_rows.iter().map(|(_, v)| *v).collect();
    assert!(
        distinct_vocabs.len() >= 2,
        "BROADCAST BUG: all {} `send_resp` clauses share vocabulary={:?}. \
         Multi-clause Elixir functions must each walk their own clause AST. \
         Rows: {:?}",
        send_resp_rows.len(),
        distinct_vocabs,
        send_resp_rows
    );
}
