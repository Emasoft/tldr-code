//! docs-and-elixir-dfg-v1 (P11.BUG-AGG-12, AGG-16)
//!
//! Final atomic milestone closing the last 2 LOW bugs from phase 11.
//!
//! 1. **BUG-AGG-12 (LOW)** `tldr search` help text used to claim "regex
//!    search", but the default behavior is BM25 ranking with structure /
//!    callgraph signals. High-frequency tokens are filtered as stopwords,
//!    so users who literally typed `def ` or `function` could see zero
//!    results despite obvious matches. The clap doc is now explicit
//!    about BM25 + IDF stopword filtering, and points users at
//!    `--regex` for literal pattern matching.
//! 2. **BUG-AGG-16 (LOW)** `tldr reaching-defs` / `slice` / `taint`
//!    failed with `Function not found` for guard-clause Elixir
//!    functions (`def assign(conn, key, value) when is_atom(key)`).
//!    The DFG resolver only matched `(call (identifier "def")
//!    (arguments (call ...)))` and missed the binary_operator wrapper
//!    inserted by tree-sitter when a `when` guard is present. The
//!    function finder and DFG parameter extractor now descend through
//!    the binary_operator's left child, matching the AST shape that
//!    the call-graph extractor already supported.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn tldr_bin() -> PathBuf {
    // why: env!("CARGO_BIN_EXE_tldr") is the path cargo builds for THIS
    // test's own profile, as a test dependency -- it cannot go stale the
    // way a hand-resolved `target/release/tldr` guess could, because
    // there is no rebuild step to forget (TRDD-BJ9T0U9I). No test in
    // this file needs `--features semantic`; the old panic message
    // naming it was copy-pasted from a file that does.
    PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
}

fn run_tldr(args: &[&str]) -> (String, String, bool) {
    let bin = tldr_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    fs::write(path, contents).expect("write file");
}

// ---------------------------------------------------------------------------
// BUG-AGG-12: search help text accuracy
// ---------------------------------------------------------------------------

/// The `search --help` output must NOT make a bare claim of "Regex search"
/// because the default behavior is BM25 + structure + callgraph. If a
/// `--regex` flag exists the help should describe BM25 as the default
/// and direct users to `--regex` for literal patterns.
#[test]
fn test_search_help_does_not_falsely_claim_regex() {
    let (stdout, stderr, ok) = run_tldr(&["search", "--help"]);
    assert!(
        ok,
        "`tldr search --help` must succeed (stderr: {})",
        stderr
    );

    let combined = format!("{}{}", stdout, stderr);
    let lower = combined.to_lowercase();

    // The combined help must mention BM25 explicitly so that users
    // know the default ranking model.
    assert!(
        lower.contains("bm25"),
        "`search --help` should describe BM25 ranking explicitly. Got:\n{}",
        combined
    );

    // If the binary supports `--regex`, the help must surface it so
    // that the historical "regex search" expectation has a real answer.
    let mentions_regex_flag = combined.contains("--regex");
    assert!(
        mentions_regex_flag,
        "`search --help` must document the `--regex` flag (the only legitimate \
         way for the docs to describe regex behavior). Got:\n{}",
        combined
    );

    // The first non-empty line of help (the clap "about" string) must
    // not stand alone as "Regex search" — that was the original bug.
    let first_nonempty = combined
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let first_lower = first_nonempty.to_lowercase();
    assert!(
        !(first_lower.starts_with("regex search")
            || first_lower == "regex search"
            || first_lower.contains("regex search across files")),
        "`search --help` first line must not bare-claim 'Regex search'. \
         Got first line: {:?}",
        first_nonempty
    );
}

// ---------------------------------------------------------------------------
// BUG-AGG-16: Elixir guard-clause functions not found by reaching-defs
// ---------------------------------------------------------------------------

/// Repro: a guarded Elixir def (`def my_fn(x) when is_atom(x)`) used to
/// fail with "Function not found" because the DFG resolver did not look
/// through the `binary_operator` wrapper introduced by the `when` guard.
#[test]
fn test_reaching_defs_elixir_guarded_function() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("guarded.ex");
    write(
        &file,
        r#"defmodule Guarded do
  def my_fn(x) when is_atom(x) do
    y = x
    y
  end
end
"#,
    );

    let path_str = file.to_string_lossy().to_string();
    let (stdout, stderr, ok) = run_tldr(&["reaching-defs", &path_str, "my_fn"]);

    // The original bug returned exit=1 with "Function not found: my_fn".
    // The minimum bar: command must NOT report function-not-found.
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("Function not found"),
        "reaching-defs must locate guarded `my_fn`; got:\nstdout={}\nstderr={}",
        stdout,
        stderr
    );
    assert!(
        ok,
        "reaching-defs on a guarded Elixir function must succeed; \
         stdout={}\nstderr={}",
        stdout, stderr
    );
}

/// Regression check: a non-guarded Elixir def must still resolve. This
/// ensures the binary_operator descent we added does not regress the
/// pre-existing simple-call shape.
#[test]
fn test_reaching_defs_elixir_unguarded_function_unchanged() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("plain.ex");
    write(
        &file,
        r#"defmodule Plain do
  def my_fn(x) do
    y = x
    y
  end
end
"#,
    );

    let path_str = file.to_string_lossy().to_string();
    let (stdout, stderr, ok) = run_tldr(&["reaching-defs", &path_str, "my_fn"]);

    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("Function not found"),
        "reaching-defs must still locate the non-guarded `my_fn`; got:\nstdout={}\nstderr={}",
        stdout,
        stderr
    );
    assert!(
        ok,
        "reaching-defs on a plain Elixir function must succeed; \
         stdout={}\nstderr={}",
        stdout, stderr
    );
}
