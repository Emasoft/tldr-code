//! semantic-chunker-per-lang-v1 (v0.4.2 M-017 + M-018)
//!
//! Phase-22 audit M-017 (10+ langs: c, cpp, elixir, java, javascript,
//! kotlin, lua, luau, ocaml, php, swift, typescript) and M-018 (the
//! downstream `similar` source_chunks=1 fallout) both stem from the
//! same chunker bug: `crates/tldr-core/src/semantic/chunker.rs` only
//! wired Python / TypeScript / JavaScript / Rust / Go / Java into the
//! per-language function-boundary splitter. Every other supported
//! language fell through to the whole-file fallback chunk with
//! `function_name: null`. Worst-case symptom is that the dominant
//! "chunk" for a 1300-line C source file ends up being the license
//! header comment.
//!
//! This file is the regression guard. It asserts, against real
//! corpora, that:
//!
//!   1. For every covered language, `tldr semantic --query "<word>"
//!      <repo-dir>` emits results whose top hits include at least one
//!      result with `function_name != null` (i.e. function-level
//!      chunking actually fires — not the whole-file fallback).
//!   2. Multi-function source files emit > 1 chunk (i.e. the whole-
//!      file fallback no longer wins for files that genuinely have
//!      multiple function definitions).
//!   3. License/copyright headers do NOT dominate the result set:
//!      across the top 20 hits, at least half MUST have a non-null
//!      `function_name`.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

use std::path::Path;
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

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}; stdout was:\n{out}"))
}

/// Extract semantic search "results" array from the JSON output of
/// `tldr semantic --format json`.
fn semantic_results(v: &serde_json::Value) -> &Vec<serde_json::Value> {
    v.get("results")
        .and_then(|r| r.as_array())
        .unwrap_or_else(|| panic!("semantic output missing results[]; got {v}"))
}

/// Run `tldr semantic --query <q> --format json <path>` and assert
/// chunk-level invariants for the given language. The function name
/// invariant is the M-017 core contract.
///
/// `min_hits_with_fn_name`: the minimum number of results in the top
/// 20 that MUST have a non-null `function_name`. Default 1 (any one)
/// is enough to prove the splitter fires; tests that target
/// header-dominated repos raise this to assert headers no longer win.
fn assert_chunker_fires(lang_label: &str, query: &str, path: &str, min_hits_with_fn_name: usize) {
    if !Path::new(path).exists() {
        eprintln!("[skip] {lang_label}: corpus {path} not present");
        return;
    }

    let (rc, out, err) = run_tldr(&[
        "semantic",
        query,
        path,
        "--format",
        "json",
        "--top",
        "20",
        "--threshold",
        "0.0",
        "--quiet",
    ]);
    assert_eq!(
        rc, 0,
        "{lang_label}: semantic must succeed; got rc={rc}\nstderr={err}\nstdout={out}"
    );

    let v = parse_json(&out);
    let results = semantic_results(&v);
    if results.is_empty() {
        // Corpus may be a bare git clone or otherwise have no source
        // files checked out. Real-repo gated tests skip when the
        // corpus is unusable rather than hard-failing.
        eprintln!(
            "[skip] {lang_label}: semantic returned 0 results for {path} \
             (query={query}); corpus likely empty / bare clone"
        );
        return;
    }

    let with_fn = results
        .iter()
        .filter(|r| {
            r.get("function_name")
                .map(|fn_name| !fn_name.is_null())
                .unwrap_or(false)
        })
        .count();

    assert!(
        with_fn >= min_hits_with_fn_name,
        "M-017: {lang_label}: expected at least {min_hits_with_fn_name} of \
         {} results to have non-null function_name, found {with_fn}. \
         Whole-file fallback is still winning. Results sample: {:?}",
        results.len(),
        results
            .iter()
            .take(3)
            .map(|r| {
                (
                    r.get("file_path").cloned(),
                    r.get("function_name").cloned(),
                    r.get("line_start").cloned(),
                    r.get("line_end").cloned(),
                )
            })
            .collect::<Vec<_>>()
    );
}

/// Assert that for a SPECIFIC source file (one path), the chunker
/// produces > 1 chunk. This is the M-018 closure check: the whole-file
/// fallback no longer wins for files that genuinely have multiple
/// function bodies.
///
/// Uses `tldr similar` which reports `source_chunks` in its output,
/// OR we synthesise by running semantic over just the file and
/// counting distinct (line_start, line_end) pairs.
fn assert_file_emits_multiple_chunks(lang_label: &str, file_path: &str, query: &str) {
    if !Path::new(file_path).exists() {
        eprintln!("[skip] {lang_label}: file {file_path} not present");
        return;
    }

    // Semantic over a single file: every result is a chunk from that
    // file, so the result count reflects the chunk count.
    let (rc, out, err) = run_tldr(&[
        "semantic",
        query,
        file_path,
        "--format",
        "json",
        "--top",
        "50",
        "--threshold",
        "0.0",
        "--quiet",
    ]);
    assert_eq!(
        rc, 0,
        "{lang_label}: semantic must succeed for {file_path}; got rc={rc}\nstderr={err}"
    );

    let v = parse_json(&out);
    let results = semantic_results(&v);

    // Distinct (line_start, line_end) pairs = distinct chunks
    let mut distinct: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    for r in results {
        let ls = r.get("line_start").and_then(|x| x.as_u64()).unwrap_or(0);
        let le = r.get("line_end").and_then(|x| x.as_u64()).unwrap_or(0);
        distinct.insert((ls, le));
    }

    assert!(
        distinct.len() > 1,
        "M-017/M-018: {lang_label}: file {file_path} produced only {} \
         distinct chunk(s) (line ranges: {:?}). Expected > 1 — the file \
         has multiple functions but the chunker fell back to whole-file.",
        distinct.len(),
        distinct
    );
}

// =============================================================================
// Per-language tests: C, Cpp, Kotlin, Swift, PHP, Lua, OCaml, Elixir
// =============================================================================

#[test]
fn c_semantic_chunker_emits_function_chunks() {
    // c-sds: ~45 functions in sds.c — definitely > 1 chunk expected.
    assert_chunker_fires(
        "c",
        "dynamic string allocation",
        "/tmp/repos/c-sds",
        2, // at least 2 fn-level hits in top 20
    );
}

#[test]
fn c_sds_file_emits_multiple_chunks() {
    // sds.c is a 1328-line file; pre-fix it produced 1 whole-file
    // chunk. Post-fix it must produce many.
    assert_file_emits_multiple_chunks(
        "c-sds",
        "/tmp/repos/c-sds/sds.c",
        "create string",
    );
}

#[test]
fn cpp_semantic_chunker_emits_function_chunks() {
    assert_chunker_fires(
        "cpp",
        "parse element node",
        "/tmp/repos/cpp-tinyxml2",
        2,
    );
}

#[test]
fn kotlin_semantic_chunker_emits_function_chunks() {
    // Audit evidence: kotlin-datetime — copyright headers dominated.
    // Post-fix MUST produce at least 2 function-level hits in top 20.
    assert_chunker_fires(
        "kotlin",
        "instant from epoch milliseconds",
        "/tmp/repos/kotlin-datetime",
        2,
    );
}

#[test]
fn swift_semantic_chunker_emits_function_chunks() {
    // Audit evidence: swift-collections — license header dominated.
    assert_chunker_fires(
        "swift",
        "heap insert element",
        "/tmp/repos/swift-collections",
        2,
    );
}

#[test]
fn php_semantic_chunker_emits_function_chunks() {
    assert_chunker_fires(
        "php",
        "string to lower case",
        "/tmp/repos/php-symfony-string",
        2,
    );
}

#[test]
fn lua_semantic_chunker_emits_function_chunks() {
    assert_chunker_fires(
        "lua",
        "language server completion",
        "/tmp/repos/lua-lsp",
        2,
    );
}

#[test]
fn ocaml_semantic_chunker_emits_function_chunks() {
    // Target a small subdirectory (bench/) rather than the whole
    // dune corpus. The corpus is ~2700 .ml files which produce
    // thousands of function chunks once the splitter fires — fine
    // for a real audit run but punitive for CI (every chunk needs
    // an embedding). The bench/ subdir has ~17 files and exercises
    // the splitter just as effectively.
    assert_chunker_fires(
        "ocaml",
        "build target file rule",
        "/tmp/repos/ocaml-dune/bench",
        2,
    );
}

#[test]
fn elixir_semantic_chunker_emits_function_chunks() {
    assert_chunker_fires(
        "elixir",
        "connection adapter response",
        "/tmp/repos/elixir-plug",
        2,
    );
}

// =============================================================================
// Header-domination guard: across the top 20 hits in a license-heavy
// repo, at least half MUST be function chunks (not header chunks).
// Targets the worst offenders from the audit (kotlin, swift).
// =============================================================================

#[test]
fn kotlin_headers_do_not_dominate() {
    let path = "/tmp/repos/kotlin-datetime";
    if !Path::new(path).exists() {
        eprintln!("[skip] kotlin_headers_do_not_dominate: corpus {path} not present");
        return;
    }
    let (rc, out, _err) = run_tldr(&[
        "semantic",
        "duration arithmetic",
        path,
        "--format",
        "json",
        "--top",
        "20",
        "--threshold",
        "0.0",
        "--quiet",
    ]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let results = semantic_results(&v);
    if results.len() < 4 {
        eprintln!(
            "[skip] kotlin_headers_do_not_dominate: only {} results, not enough for guard",
            results.len()
        );
        return;
    }
    let with_fn = results
        .iter()
        .filter(|r| {
            r.get("function_name")
                .map(|fn_name| !fn_name.is_null())
                .unwrap_or(false)
        })
        .count();
    let half = results.len() / 2;
    assert!(
        with_fn >= half,
        "M-017: kotlin: copyright headers still dominating — only {with_fn}/{} \
         results have function_name (need >= {half}). Sample non-fn results: {:?}",
        results.len(),
        results
            .iter()
            .filter(|r| r
                .get("function_name")
                .map(|fn_name| fn_name.is_null())
                .unwrap_or(true))
            .take(2)
            .map(|r| (r.get("file_path").cloned(), r.get("line_start").cloned()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn swift_headers_do_not_dominate() {
    let path = "/tmp/repos/swift-collections";
    if !Path::new(path).exists() {
        eprintln!("[skip] swift_headers_do_not_dominate: corpus {path} not present");
        return;
    }
    let (rc, out, _err) = run_tldr(&[
        "semantic",
        "min heap remove root",
        path,
        "--format",
        "json",
        "--top",
        "20",
        "--threshold",
        "0.0",
        "--quiet",
    ]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let results = semantic_results(&v);
    if results.len() < 4 {
        eprintln!(
            "[skip] swift_headers_do_not_dominate: only {} results, not enough for guard",
            results.len()
        );
        return;
    }
    let with_fn = results
        .iter()
        .filter(|r| {
            r.get("function_name")
                .map(|fn_name| !fn_name.is_null())
                .unwrap_or(false)
        })
        .count();
    let half = results.len() / 2;
    assert!(
        with_fn >= half,
        "M-017: swift: license headers still dominating — only {with_fn}/{} \
         results have function_name (need >= {half})",
        results.len()
    );
}
