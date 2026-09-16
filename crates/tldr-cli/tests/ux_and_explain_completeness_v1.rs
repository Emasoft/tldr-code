//! ux-and-explain-completeness-v1 — regression tests for the P12.AGG12 UX
//! milestone. All tests use real repos under `/tmp/repos/<repo>` and gate
//! on existence so they're skipped silently when the corpus isn't checked
//! out (per the no-synthetic-fixtures-v1 strategy).
//!
//! Bugs covered:
//!
//! - **AGG12-1**: `tldr explain` callers were empty / phantom-duplicated /
//!   rejected dotted names across multiple languages. Fix:
//!   * Delegate function lookup to the canonical `function_finder`, which
//!     handles Lua dotted-name (`m.reset`), JS arrow / object-pair, etc.
//!   * Path-aware caller dedup so relative-vs-absolute path mismatches
//!     don't surface phantom duplicates.
//!   * Enrich callers via `find_references` for languages whose project
//!     call graph misses cross-file edges (notably C#).
//!
//! - **AGG12-13**: `tldr search` returned 0 results for queries whose
//!   tokens are all BM25 stopwords (`fn new`, `function`, `def `).
//!   Fix: literal-substring fallback when tokenization yields zero
//!   tokens.
//!
//! - **AGG12-15**: `tldr slice` returned a silent empty result for
//!   out-of-range criterion lines. Fix: emit a `LineOutsideFunction`
//!   diagnostic mirroring `tldr chop`.
//!
//! - **AGG12-16**: `tldr vuln` autodetect rejected 14 of 18 supported
//!   languages with "not yet supported by autodetect". Fix: extend
//!   `is_natively_analyzed` to cover every language the taint engine
//!   already routes.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip helper: returns true and prints a notice when `path` doesn't
/// exist. Tests gate on real-repo presence per no-synthetic-fixtures-v1.
fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("[skip] {} not present", path);
        return true;
    }
    false
}

fn explain_json(file: &str, function: &str) -> Value {
    let out = tldr_cmd()
        .args(["explain", file, function, "--format", "json"])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse explain JSON for {}::{}: {}\nstdout: {}\nstderr: {}",
            file,
            function,
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn callers_count(report: &Value) -> usize {
    report
        .get("callers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

// =============================================================================
// AGG12-1: explain caller completeness across languages
// =============================================================================

#[test]
fn test_explain_typescript_callers_populated() {
    let repo = "/tmp/repos/ts-dom-gen";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/ts-dom-gen/src/build.ts";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "emitFlavor");
    let count = callers_count(&report);
    assert!(
        count >= 1,
        "explain TS emitFlavor should report >= 1 caller (was {}). \
         `tldr references emitFlavor /tmp/repos/ts-dom-gen` finds 5+ \
         call sites; explain must mirror the call-graph view.",
        count
    );
}

#[test]
fn test_explain_java_callers_populated() {
    let repo = "/tmp/repos/spring-petclinic";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "findPaginatedForOwnersLastName");
    let count = callers_count(&report);
    assert!(
        count >= 1,
        "explain Java findPaginatedForOwnersLastName should report >= 1 caller (was {})",
        count
    );
}

#[test]
fn test_explain_csharp_callers_populated() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "WriteToken");
    let count = callers_count(&report);
    assert!(
        count >= 1,
        "explain C# WriteToken should report >= 1 caller (was {}). \
         The references command finds calls in BsonBinaryWriter.Async.cs \
         and BsonDataWriter.cs; explain must surface them too. The C# \
         project call graph misses these edges, so the \
         `enrich_with_references` path is the route that fixes them.",
        count
    );
}

#[test]
fn test_explain_python_no_phantom_line_zero_callers() {
    let repo = "/tmp/repos/flask";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/flask/src/flask/cli.py";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "find_best_app");
    let callers = report
        .get("callers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !callers.is_empty(),
        "explain Python find_best_app should have >= 1 caller, got 0"
    );

    // No phantom line=0 entries — these came from project-graph rows
    // colliding with per-file walker rows due to relative-vs-absolute
    // path mismatch.
    let line_zero_count = callers
        .iter()
        .filter(|c| c.get("line").and_then(|v| v.as_u64()) == Some(0))
        .count();
    assert_eq!(
        line_zero_count, 0,
        "no caller entry should have line=0 — these are phantom \
         duplicates of an entry that already has the real line number. \
         Got: {:#?}",
        callers
    );

    // No duplicate (name, normalized-path) pairs.
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for c in &callers {
        let name = c
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Normalize: strip the canonical /tmp/repos/flask prefix so abs
        // and rel paths to the same file are treated as equivalent for
        // dedup.
        let mut path = c
            .get("file")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(idx) = path.find("flask/") {
            path = path[idx..].to_string();
        }
        assert!(
            seen.insert((name.clone(), path.clone())),
            "duplicate caller entry (name={}, normalized_path={}) — dedup \
             should treat absolute and relative paths to the same file \
             as equivalent.",
            name,
            path
        );
    }
}

#[test]
fn test_explain_lua_dotted_name_resolves() {
    let repo = "/tmp/repos/lua-lsp";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(file) {
        return;
    }

    // Pre-fix: `tldr explain ... m.reset` exited with `Error: symbol
    // 'm.reset' not found`. Fix delegates to the canonical
    // function_finder which understands Lua's dot-indexed
    // `function m.reset()` syntax.
    let out = tldr_cmd()
        .args(["explain", file, "m.reset", "--format", "json"])
        .output()
        .expect("spawn tldr");
    assert!(
        out.status.success(),
        "explain m.reset should succeed, got status {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("explain JSON");
    let function = report
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        function, "m.reset",
        "report should preserve the qualified name 'm.reset' as the function field"
    );
}

#[test]
fn test_explain_rust_callers_unchanged() {
    // Regression guard: rust callers have always worked, ensure the
    // milestone changes don't break that.
    let repo = "/tmp/repos/ripgrep";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/ripgrep/crates/ignore/src/walk.rs";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "check_symlink_loop");
    let count = callers_count(&report);
    // Pre-existing baseline: at least 1 caller present.
    assert!(
        count >= 1,
        "explain rust check_symlink_loop should report >= 1 caller (was {})",
        count
    );
}

#[test]
fn test_explain_go_callers_unchanged() {
    let repo = "/tmp/repos/go-httprouter";
    if skip_if_missing(repo) {
        return;
    }
    let file = "/tmp/repos/go-httprouter/path.go";
    if skip_if_missing(file) {
        return;
    }
    let report = explain_json(file, "CleanPath");
    let count = callers_count(&report);
    assert!(
        count >= 1,
        "explain Go CleanPath should report >= 1 caller (was {})",
        count
    );
}

// =============================================================================
// AGG12-13: BM25 short-token literal fallback
// =============================================================================

#[test]
fn test_search_short_tokens_return_results() {
    let repo = "/tmp/repos/ripgrep";
    if skip_if_missing(repo) {
        return;
    }

    // Pre-fix: BM25 tokenizer dropped both `fn` and `new` as stopwords,
    // leaving zero query tokens, returning zero results.
    let out = tldr_cmd()
        .args(["search", "fn new", repo, "--format", "json"])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).expect("search JSON");
    let total = report
        .get("total_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        total >= 1,
        "`tldr search 'fn new' ripgrep` should return >= 1 result via \
         the literal-fallback path (was {}). The literal substring `fn new` \
         appears in 50+ Rust files in ripgrep.",
        total
    );

    // Mode prefix should reflect the fallback so consumers can see it.
    let mode = report
        .get("search_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        mode.contains("literal-fallback") || mode.contains("regex"),
        "search_mode should reflect literal fallback when query tokens \
         are all stopwords, got '{}'",
        mode
    );
}

// =============================================================================
// AGG12-15: slice OOR diagnostic
// =============================================================================

#[test]
fn test_slice_out_of_range_diagnostic() {
    let file = "/tmp/repos/c-sds/sds.c";
    if skip_if_missing(file) {
        return;
    }

    // sdsnew lives at lines 154-157. Line 100 is OUTSIDE — slice should
    // emit a diagnostic, not silently return lines=[].
    let out = tldr_cmd()
        .args(["slice", file, "sdsnew", "100", "--format", "json"])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).expect("slice JSON");
    let lines = report
        .get("lines")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(lines, 0, "slice should be empty for OOR criterion line");
    let explanation = report
        .get("explanation")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        explanation.contains("outside function") && explanation.contains("sdsnew"),
        "slice should emit a 'line N is outside function ...' diagnostic \
         when the criterion line falls outside the resolved bounds. Got: '{}'",
        explanation
    );
}

// =============================================================================
// AGG12-16: vuln autodetect covers all 18 langs
// =============================================================================

#[test]
fn test_vuln_autodetect_covers_ruby() {
    let repo = "/tmp/repos/rails-html-sanitizer";
    if skip_if_missing(repo) {
        return;
    }
    let out = tldr_cmd()
        .args(["vuln", repo, "--format", "json"])
        .output()
        .expect("spawn tldr");
    assert!(
        out.status.success(),
        "vuln --format json should succeed on a ruby tree without --lang. \
         status={:?}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not yet supported by autodetect"),
        "autodetect should accept ruby; got error: {}",
        stderr
    );
}

#[test]
fn test_vuln_autodetect_covers_csharp() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson";
    if skip_if_missing(repo) {
        return;
    }
    let out = tldr_cmd()
        .args(["vuln", repo, "--format", "json"])
        .output()
        .expect("spawn tldr");
    assert!(
        out.status.success(),
        "vuln on csharp tree should succeed. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not yet supported by autodetect"),
        "autodetect should accept csharp; got error: {}",
        stderr
    );
}

#[test]
fn test_vuln_autodetect_covers_kotlin() {
    let repo = "/tmp/repos/kotlin-datetime";
    if skip_if_missing(repo) {
        return;
    }
    let out = tldr_cmd()
        .args(["vuln", repo, "--format", "json"])
        .output()
        .expect("spawn tldr");
    assert!(
        out.status.success(),
        "vuln on kotlin tree should succeed. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not yet supported by autodetect"),
        "autodetect should accept kotlin; got error: {}",
        stderr
    );
}
