//! cl15-polyglot-v1 — full polyglot multi-language analysis on mixed-language
//! corpus roots.
//!
//! Surface: at a mixed-language directory root, dir-level commands
//! (`structure`, `calls`, `impact`, `hubs`, `deps`, …) used to auto-detect ONE
//! dominant language via `Language::from_directory` and SILENTLY drop every
//! other language's files. On a corpus root with comparable amounts of Python,
//! Go and TypeScript, that meant two thirds of the source was never analyzed,
//! with no warning.
//!
//! Contract pinned here:
//!
//!   1. Multi-language is the DEFAULT for dir-level commands: `structure`,
//!      `calls` and `impact` each surface entities from ALL detected languages
//!      (Python + Go + TypeScript), not just the dominant one.
//!
//!   2. When a command IS restricted to a single language (via `--lang`), it
//!      emits a CLEAR stderr WARNING naming the dropped languages and their
//!      file counts — never silent.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Build a small but real mixed-language project: one Python file, one Go file
/// and one TypeScript file, each with a uniquely-named function so we can
/// assert presence per-language in the merged output. Balanced file counts
/// (1 each) so `from_directory`'s dominant-language pick is genuinely lossy.
///
/// Returns `(TempDir, project_root)`.
fn make_polyglot_project() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();

    // --- Python -------------------------------------------------------------
    fs::write(
        root.join("alpha.py"),
        "def py_helper():\n    return 1\n\n\ndef py_main():\n    return py_helper()\n",
    )
    .unwrap();

    // --- Go -----------------------------------------------------------------
    fs::write(
        root.join("beta.go"),
        "package main\n\nfunc goHelper() int {\n\treturn 2\n}\n\nfunc goMain() int {\n\treturn goHelper()\n}\n",
    )
    .unwrap();

    // --- TypeScript ---------------------------------------------------------
    fs::write(
        root.join("gamma.ts"),
        "function tsHelper(): number {\n  return 3;\n}\n\nfunction tsMain(): number {\n  return tsHelper();\n}\n",
    )
    .unwrap();

    (temp, root)
}

/// Collect every function/method name that appears anywhere in a JSON value,
/// regardless of the exact schema nesting. We look for the common `"name"`
/// keys under structure `files[].functions[]` and call-graph node strings.
fn collect_names_blob(v: &Value) -> String {
    // The simplest robust approach for a cross-schema test: serialize the
    // whole value and substring-search for the unique function identifiers.
    // The identifiers (py_*, goHelper, tsHelper) are unique enough that a
    // false positive is impossible.
    serde_json::to_string(v).unwrap()
}

// =============================================================================
// structure: analyzes ALL three languages by default
// =============================================================================

#[test]
fn structure_default_analyzes_all_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args(["structure", root.to_str().unwrap(), "--format", "json", "-q"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("structure must emit valid JSON");
    let blob = collect_names_blob(&v);

    assert!(
        blob.contains("py_helper"),
        "structure must include Python entities (py_helper); got:\n{}",
        blob
    );
    assert!(
        blob.contains("goHelper"),
        "structure must include Go entities (goHelper); got:\n{}",
        blob
    );
    assert!(
        blob.contains("tsHelper"),
        "structure must include TypeScript entities (tsHelper); got:\n{}",
        blob
    );
}

// =============================================================================
// calls: builds a call graph across ALL three languages by default
// =============================================================================

#[test]
fn calls_default_analyzes_all_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args(["calls", root.to_str().unwrap(), "--format", "json", "-q"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("calls must emit valid JSON");
    let blob = collect_names_blob(&v);

    assert!(
        blob.contains("py_helper") || blob.contains("py_main"),
        "calls must include Python nodes; got:\n{}",
        blob
    );
    assert!(
        blob.contains("goHelper") || blob.contains("goMain"),
        "calls must include Go nodes; got:\n{}",
        blob
    );
    assert!(
        blob.contains("tsHelper") || blob.contains("tsMain"),
        "calls must include TypeScript nodes; got:\n{}",
        blob
    );
}

// =============================================================================
// impact: resolves callers across ALL three languages by default
// =============================================================================

#[test]
fn impact_default_finds_callers_in_any_language() {
    let (_temp, root) = make_polyglot_project();

    // py_helper is called by py_main. Python is NOT the language that
    // `from_directory` would pick for this balanced tree (the dominant pick
    // is Go), so this target genuinely exercises cross-language analysis:
    // impact must analyze EVERY detected language, not just the dominant one,
    // to resolve the Python caller.
    let assert = tldr_cmd()
        .args([
            "impact",
            "py_helper",
            root.to_str().unwrap(),
            "--format",
            "json",
            "-q",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("impact must emit valid JSON");
    let blob = collect_names_blob(&v);

    assert!(
        blob.contains("py_main"),
        "impact on py_helper must find its Python caller py_main across the polyglot tree; got:\n{}",
        blob
    );
}

// =============================================================================
// single-language restriction: WARN naming dropped languages, never silent
// =============================================================================

#[test]
fn structure_lang_restriction_warns_about_dropped_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args([
            "structure",
            root.to_str().unwrap(),
            "--lang",
            "python",
            "--format",
            "json",
            "-q",
        ])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    // The warning must name the dropped languages so the user knows analysis
    // was narrowed. We assert on the language identifiers AND the word
    // "warning" so this is a genuine, visible alert — never silent.
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("warn"),
        "single-language restriction must emit a WARNING on stderr; got:\n{}",
        stderr
    );
    assert!(
        lower.contains("go") && lower.contains("typescript"),
        "restriction warning must NAME the dropped languages (Go, TypeScript); got:\n{}",
        stderr
    );
    // File counts must appear so the user understands the magnitude of what
    // was dropped (1 .go + 1 .ts).
    assert!(
        stderr.contains('1'),
        "restriction warning must report dropped file counts; got:\n{}",
        stderr
    );
}

// =============================================================================
// hubs: centrality computed across ALL three languages by default
// =============================================================================

#[test]
fn hubs_default_analyzes_all_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args(["hubs", root.to_str().unwrap(), "--format", "json", "-q"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("hubs must emit valid JSON");
    let blob = collect_names_blob(&v);

    // Each language defines a helper that is called by its main — so each
    // language contributes at least one in-degree hub candidate. The merged
    // hub graph must surface functions from every language.
    assert!(
        blob.contains("py_helper") || blob.contains("py_main"),
        "hubs must include Python nodes; got:\n{}",
        blob
    );
    assert!(
        blob.contains("goHelper") || blob.contains("goMain"),
        "hubs must include Go nodes; got:\n{}",
        blob
    );
    assert!(
        blob.contains("tsHelper") || blob.contains("tsMain"),
        "hubs must include TypeScript nodes; got:\n{}",
        blob
    );
}

#[test]
fn hubs_lang_restriction_warns_about_dropped_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args([
            "hubs",
            root.to_str().unwrap(),
            "--lang",
            "typescript",
            "--format",
            "json",
            "-q",
        ])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("warn"),
        "hubs --lang restriction must emit a WARNING on stderr; got:\n{}",
        stderr
    );
    assert!(
        lower.contains("python") && lower.contains("go"),
        "hubs restriction warning must name dropped languages (Python, Go); got:\n{}",
        stderr
    );
}

#[test]
fn calls_lang_restriction_warns_about_dropped_languages() {
    let (_temp, root) = make_polyglot_project();

    let assert = tldr_cmd()
        .args([
            "calls",
            root.to_str().unwrap(),
            "--lang",
            "go",
            "--format",
            "json",
            "-q",
        ])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("warn"),
        "calls --lang restriction must emit a WARNING on stderr; got:\n{}",
        stderr
    );
    assert!(
        lower.contains("python") && lower.contains("typescript"),
        "calls restriction warning must name dropped languages (Python, TypeScript); got:\n{}",
        stderr
    );
}
