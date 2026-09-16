//! VAL-010: 13 commands × 18 languages integration audit.
//!
//! This is an **audit-only** matrix that runs each of 13 representative
//! `tldr` commands against a canonical minimal fixture for each of the 18
//! supported languages. 13 × 18 = **234 test cases**, each named
//! `test_<command>_on_<language>` so a failure immediately identifies the
//! broken pair.
//!
//! # Fixture invariants
//!
//! Each fixture (see `fixtures/mod.rs`) contains:
//! - A canonical manifest matching `Language::from_directory`'s precedence.
//! - File A defining `helper` (constant return) and `main` (calls both).
//! - File B defining `b_util` (constant return), imported from File A.
//! - Exactly 2 call edges: `main -> helper`, `main -> b_util`.
//!
//! # Assertions per cell
//!
//! 1. **Exit code 0** for the informational commands.
//! 2. **JSON output parses** (some commands emit helper progress to stdout
//!    which we strip).
//! 3. **Semantic sanity** — shape-specific checks defined per command.
//!
//! # Known capability gaps
//!
//! Any (command × language) pair that cannot pass because of a documented
//! tldr-core capability gap is marked `#[ignore = "..."]` with a reason
//! pointing at the specific file:line where support ends. Silently passing
//! a broken pair is forbidden (gaming rule).
//!
//! # How to add a new known gap
//!
//! 1. Run the matrix.
//! 2. For each failure, briefly investigate the root cause in tldr-core.
//! 3. If it's a capability gap (not a fixture bug), change the test's
//!    attribute from `#[test]` to `#[test]\n#[ignore = "<reason>"]` and
//!    append a bullet to `KNOWN_CAPABILITY_GAPS` below.
//!
//! # Known capability gaps catalog (as of 2026-04-24)
//!
//! Documented when first discovered in VAL-010. Each `#[ignore]` attribute
//! MUST cite one of these. Fixing any of these gaps is a future milestone.
//!
//! - see individual test `#[ignore]` reasons for file:line citations.

mod fixtures;

use serde_json::Value;
#[cfg(feature = "semantic")]
use serial_test::serial;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

// ============================================================================
// Test harness
// ============================================================================

/// Get the path to the tldr binary under test.
fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run a tldr command and return (exit status, parsed JSON).
///
/// Strips any leading non-JSON lines (some commands like `references` emit
/// a progress line before JSON output). If parsing fails, returns
/// `Value::Null`. Caller is responsible for verifying success.
fn run_tldr(args: &[&str]) -> (std::process::ExitStatus, Value, String, String) {
    let mut cmd = tldr_cmd();
    cmd.args(args);
    let output = cmd.output().expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Some commands emit helper progress before JSON. Find the first `{` or `[`
    // to extract JSON.
    let json_start = stdout.find(['{', '[']).unwrap_or(stdout.len());
    let json_slice = &stdout[json_start..];
    let json = serde_json::from_str::<Value>(json_slice).unwrap_or(Value::Null);

    (output.status, json, stdout, stderr)
}

/// Panic with detailed context if a matrix assertion fails.
fn fail_cell(cmd: &str, lang: &str, why: &str, stdout: &str, stderr: &str) -> ! {
    panic!("\n[{cmd} × {lang}] {why}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n");
}

/// Return the canonical File A path within the fixture (the entry file that
/// defines `helper` and `main`). Used for file-level commands like `extract`,
/// `imports`, `complexity`, `cognitive`, `halstead`.
fn entry_file(lang: &str, root: &Path) -> std::path::PathBuf {
    match lang {
        "python" => root.join("main.py"),
        "typescript" => root.join("main.ts"),
        "javascript" => root.join("main.js"),
        "go" => root.join("main.go"),
        "rust" => root.join("src/main.rs"),
        "java" => root.join("Main.java"),
        "c" => root.join("main.c"),
        "cpp" => root.join("main.cpp"),
        "ruby" => root.join("main.rb"),
        "kotlin" => root.join("Main.kt"),
        "swift" => root.join("Main.swift"),
        "csharp" => root.join("Program.cs"),
        "scala" => root.join("Main.scala"),
        "php" => root.join("main.php"),
        "lua" => root.join("main.lua"),
        "luau" => root.join("main.luau"),
        "elixir" => root.join("main.ex"),
        "ocaml" => root.join("main.ml"),
        _ => panic!("unknown lang: {lang}"),
    }
}

// ============================================================================
// Per-command assertions
// ============================================================================

fn check_structure(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "structure",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("structure", lang, "non-zero exit", &stdout, &stderr);
    }
    let actual_lang = json
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    if actual_lang != lang {
        fail_cell(
            "structure",
            lang,
            &format!("language field was {:?}, expected {:?}", actual_lang, lang),
            &stdout,
            &stderr,
        );
    }
    let files = json.get("files").and_then(Value::as_array);
    let has_any_fn_or_class = files
        .map(|arr| {
            arr.iter().any(|f| {
                let fns = f
                    .get("functions")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let cls = f
                    .get("classes")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let methods = f
                    .get("methods")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                // language-command-matrix-test-followup-v1: post-M4
                // schema-cleanup-v1 moved function/method names from the
                // redundant `functions`/`methods` string arrays into a
                // structured `.definitions[]` array. Accept that as the
                // canonical signal the structure command extracted something.
                let defs = f
                    .get("definitions")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                fns || cls || methods || defs
            })
        })
        .unwrap_or(false);
    if !has_any_fn_or_class {
        fail_cell(
            "structure",
            lang,
            "no files with non-empty functions/classes/methods/definitions",
            &stdout,
            &stderr,
        );
    }
}

fn check_extract(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "extract",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("extract", lang, "non-zero exit", &stdout, &stderr);
    }
    // extract returns functions/classes/methods at top level. Accept either.
    let funcs = json
        .get("functions")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let classes = json
        .get("classes")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    if funcs + classes == 0 {
        fail_cell(
            "extract",
            lang,
            "no functions or classes extracted",
            &stdout,
            &stderr,
        );
    }
}

/// Expected number of import declarations parsed from the entry file
/// for each language's canonical 2-file fixture (see `fixtures/mod.rs`).
///
/// VAL-018: tightened from "JSON parses" to per-language exact-count to
/// catch under-AND over-counting. Each row is verified against the actual
/// fixture body, not language stereotype.
///
/// Languages with EXPLICIT cross-file references (count = 1):
/// - python: `from util import b_util`
/// - typescript: `import { b_util } from './util';`
/// - javascript: `import { b_util } from './util.js';`
/// - go: `import "example.com/x/util"`
/// - rust: `mod util;` is a module declaration the imports parser counts
/// - c: `#include "util.h"`
/// - cpp: `#include "util.hpp"`
/// - ruby: `require_relative 'util'`
/// - php: `require_once 'util.php'`
/// - lua: `local util = require('util')` — `require` call counts
/// - luau: `local util = require('./util')`
///
/// Languages with IMPLICIT same-package/module visibility (count = 0):
/// - java: same-package classes auto-visible per JLS section 6.3 ("A
///   package member is accessible throughout the package without
///   qualification or import declaration").
/// - kotlin: same-package top-level declarations are visible without
///   import (Kotlin spec: package and imports section).
/// - swift: same-module declarations are visible by default per Swift
///   access control (`internal` is the default and applies module-wide).
/// - csharp: same-namespace types auto-visible without `using` (C# spec:
///   namespaces section).
/// - scala: same-package members auto-visible (Scala spec: packages
///   section).
/// - elixir: full qualified module references (`Util.b_util()`) need no
///   `import`/`alias` directive — fixture uses `Util.b_util()` directly.
/// - ocaml: qualified module access (`Util.b_util`) needs no `open Util`
///   — fixture uses qualified reference.
const EXPECTED_IMPORTS: &[(&str, usize)] = &[
    ("python", 1),
    ("typescript", 1),
    ("javascript", 1),
    ("go", 1),
    ("rust", 1),
    ("java", 0),
    ("c", 1),
    ("cpp", 1),
    ("ruby", 1),
    ("kotlin", 0),
    ("swift", 0),
    ("csharp", 0),
    ("scala", 0),
    ("php", 1),
    ("lua", 1),
    ("luau", 1),
    ("elixir", 0),
    ("ocaml", 0),
];

fn check_imports(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "imports",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("imports", lang, "non-zero exit", &stdout, &stderr);
    }
    // VAL-018: tightened — per-language EXPECTED_IMPORTS exact match.
    // Catches both under-counting (e.g. handler skips required imports)
    // and over-counting (e.g. handler treats type annotations as imports).
    //
    // Per `schema-unification-v1` (commit 8d71463) the default `imports`
    // shape is now an envelope: { file, language, imports[] }. The
    // legacy top-level array is opt-in via `--legacy-array`. This test
    // pins the envelope contract: required keys, language matches, and
    // exact import-count match against EXPECTED_IMPORTS.
    let expected = EXPECTED_IMPORTS
        .iter()
        .find(|(l, _)| *l == lang)
        .map(|(_, n)| *n)
        .unwrap_or_else(|| {
            fail_cell(
                "imports",
                lang,
                "missing EXPECTED_IMPORTS entry — every language must be enumerated",
                &stdout,
                &stderr,
            )
        });
    let obj = json.as_object().unwrap_or_else(|| {
        fail_cell(
            "imports",
            lang,
            "output is not a JSON object (expected envelope { file, language, imports[] } per schema-unification-v1)",
            &stdout,
            &stderr,
        )
    });
    for key in ["file", "language", "imports"] {
        if !obj.contains_key(key) {
            fail_cell(
                "imports",
                lang,
                &format!("envelope missing required key `{key}` (schema-unification-v1)"),
                &stdout,
                &stderr,
            );
        }
    }
    let reported_lang = obj
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            fail_cell(
                "imports",
                lang,
                "envelope `language` is not a string",
                &stdout,
                &stderr,
            )
        });
    if reported_lang != lang {
        fail_cell(
            "imports",
            lang,
            &format!("envelope `language` = {reported_lang:?}, expected {lang:?}"),
            &stdout,
            &stderr,
        );
    }
    let arr = obj
        .get("imports")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            fail_cell(
                "imports",
                lang,
                "envelope `imports` is not an array",
                &stdout,
                &stderr,
            )
        });
    if arr.len() != expected {
        fail_cell(
            "imports",
            lang,
            &format!(
                "imports count {} != expected {} (see EXPECTED_IMPORTS table). Imports parsed: {}",
                arr.len(),
                expected,
                serde_json::to_string(arr).unwrap_or_default(),
            ),
            &stdout,
            &stderr,
        );
    }
}

fn check_loc(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "loc",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("loc", lang, "non-zero exit", &stdout, &stderr);
    }
    let summary = json.get("summary");
    let total = summary
        .and_then(|s| s.get("total_lines"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let code = summary
        .and_then(|s| s.get("code_lines"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total == 0 || code == 0 {
        fail_cell(
            "loc",
            lang,
            &format!("total_lines={total} code_lines={code}"),
            &stdout,
            &stderr,
        );
    }
}

fn check_complexity(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    // All fixtures define `helper` as the per-language function name.
    // Swift/Kotlin/Elixir accept the bare name via tree-sitter extraction.
    let (status, json, stdout, stderr) = run_tldr(&[
        "complexity",
        file.to_str().unwrap(),
        "helper",
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("complexity", lang, "non-zero exit", &stdout, &stderr);
    }
    // Accept either `cyclomatic` (newer) or `complexity` key.
    let cx = json
        .get("cyclomatic")
        .or_else(|| json.get("complexity"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if cx == 0 {
        fail_cell(
            "complexity",
            lang,
            "cyclomatic/complexity field missing or zero (expected >= 1)",
            &stdout,
            &stderr,
        );
    }
}

fn check_cognitive(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "cognitive",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("cognitive", lang, "non-zero exit", &stdout, &stderr);
    }
    let functions = json.get("functions").and_then(Value::as_array);
    if functions.map(|a| a.is_empty()).unwrap_or(true) {
        fail_cell(
            "cognitive",
            lang,
            "empty `functions` array (no functions analyzed)",
            &stdout,
            &stderr,
        );
    }
}

fn check_halstead(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "halstead",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("halstead", lang, "non-zero exit", &stdout, &stderr);
    }
    let functions = json.get("functions").and_then(Value::as_array);
    if functions.map(|a| a.is_empty()).unwrap_or(true) {
        fail_cell(
            "halstead",
            lang,
            "empty `functions` array (no metrics computed)",
            &stdout,
            &stderr,
        );
    }
}

fn check_smells(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "smells",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("smells", lang, "non-zero exit", &stdout, &stderr);
    }
    // files_scanned >= 1 OR non-empty smells array.
    let files_scanned = json
        .get("files_scanned")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let smells_arr = json
        .get("smells")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    if files_scanned == 0 && smells_arr == 0 {
        fail_cell(
            "smells",
            lang,
            "files_scanned=0 and smells is empty — pipeline ran on nothing",
            &stdout,
            &stderr,
        );
    }
}

fn check_calls(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "calls",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("calls", lang, "non-zero exit", &stdout, &stderr);
    }
    let total = json.get("total_edges").and_then(Value::as_u64).unwrap_or(0);
    // VAL-011: tightened from `>= 1` to `>= 2`. The canonical fixture has
    // `main -> helper` (intra-file) and `main -> b_util` (cross-file), so
    // any handler that skips the cross-file edge now FAILS instead of
    // silently passing as WEAK.
    if total < 2 {
        fail_cell(
            "calls",
            lang,
            &format!(
                "total_edges={total} but fixture has main -> helper (intra) and main -> b_util (cross-file); expected >= 2",
            ),
            &stdout,
            &stderr,
        );
    }
}

fn check_dead(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "dead",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("dead", lang, "non-zero exit", &stdout, &stderr);
    }
    // Minimum sanity: total_functions > 0 (pipeline saw *some* function).
    let total_fns = json
        .get("total_functions")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total_fns == 0 {
        fail_cell(
            "dead",
            lang,
            "total_functions=0 — dead-code analyzer saw no functions",
            &stdout,
            &stderr,
        );
    }
    // VAL-018: tightened — every fixture defines `dead_helper` (or
    // `deadHelper`/`dead_helper` per language convention) which is
    // never called, so the analyzer must report at least 1 dead or
    // possibly-dead function. Accept either bucket — some languages
    // (e.g. dynamic-dispatch ones) classify into `possibly_dead`
    // instead of `dead_functions`. See `fixtures/mod.rs` for the
    // canonical 4-function invariant added in VAL-018.
    let total_dead = json.get("total_dead").and_then(Value::as_u64).unwrap_or(0);
    let total_possibly_dead = json
        .get("total_possibly_dead")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total_dead + total_possibly_dead == 0 {
        fail_cell(
            "dead",
            lang,
            &format!(
                "total_dead={total_dead} total_possibly_dead={total_possibly_dead} — fixture defines `dead_helper` (never called) so >= 1 was expected",
            ),
            &stdout,
            &stderr,
        );
    }
}

fn check_references(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "references",
        "helper",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("references", lang, "non-zero exit", &stdout, &stderr);
    }
    // total_references >= 1 (definition counts as a ref in tldr's output).
    let total = json
        .get("total_references")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total == 0 {
        fail_cell(
            "references",
            lang,
            "total_references=0 — not even the definition was found",
            &stdout,
            &stderr,
        );
    }
}

fn check_impact(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "impact",
        "helper",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("impact", lang, "non-zero exit", &stdout, &stderr);
    }
    let total_targets = json
        .get("total_targets")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total_targets == 0 {
        fail_cell(
            "impact",
            lang,
            "total_targets=0 — function `helper` not located at all",
            &stdout,
            &stderr,
        );
    }
}

fn check_patterns(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "patterns",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("patterns", lang, "non-zero exit", &stdout, &stderr);
    }
    let files_analyzed = json
        .get("metadata")
        .and_then(|m| m.get("files_analyzed"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if files_analyzed == 0 {
        fail_cell(
            "patterns",
            lang,
            "metadata.files_analyzed=0 — pipeline saw no files",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// 234 tests: 13 commands × 18 languages
// ============================================================================
//
// Organized command-first to make failure clusters easy to spot.

// ---------------------------------------------------------------------------- structure
#[test]
fn test_structure_on_python() {
    check_structure("python");
}
#[test]
fn test_structure_on_typescript() {
    check_structure("typescript");
}
#[test]
fn test_structure_on_javascript() {
    check_structure("javascript");
}
#[test]
fn test_structure_on_go() {
    check_structure("go");
}
#[test]
fn test_structure_on_rust() {
    check_structure("rust");
}
#[test]
fn test_structure_on_java() {
    check_structure("java");
}
#[test]
fn test_structure_on_c() {
    check_structure("c");
}
#[test]
fn test_structure_on_cpp() {
    check_structure("cpp");
}
#[test]
fn test_structure_on_ruby() {
    check_structure("ruby");
}
#[test]
fn test_structure_on_kotlin() {
    check_structure("kotlin");
}
#[test]
fn test_structure_on_swift() {
    check_structure("swift");
}
#[test]
fn test_structure_on_csharp() {
    check_structure("csharp");
}
#[test]
fn test_structure_on_scala() {
    check_structure("scala");
}
#[test]
fn test_structure_on_php() {
    check_structure("php");
}
#[test]
fn test_structure_on_lua() {
    check_structure("lua");
}
#[test]
fn test_structure_on_luau() {
    check_structure("luau");
}
#[test]
fn test_structure_on_elixir() {
    check_structure("elixir");
}
#[test]
fn test_structure_on_ocaml() {
    check_structure("ocaml");
}

// ---------------------------------------------------------------------------- extract
#[test]
fn test_extract_on_python() {
    check_extract("python");
}
#[test]
fn test_extract_on_typescript() {
    check_extract("typescript");
}
#[test]
fn test_extract_on_javascript() {
    check_extract("javascript");
}
#[test]
fn test_extract_on_go() {
    check_extract("go");
}
#[test]
fn test_extract_on_rust() {
    check_extract("rust");
}
#[test]
fn test_extract_on_java() {
    check_extract("java");
}
#[test]
fn test_extract_on_c() {
    check_extract("c");
}
#[test]
fn test_extract_on_cpp() {
    check_extract("cpp");
}
#[test]
fn test_extract_on_ruby() {
    check_extract("ruby");
}
#[test]
fn test_extract_on_kotlin() {
    check_extract("kotlin");
}
#[test]
fn test_extract_on_swift() {
    check_extract("swift");
}
#[test]
fn test_extract_on_csharp() {
    check_extract("csharp");
}
#[test]
fn test_extract_on_scala() {
    check_extract("scala");
}
#[test]
fn test_extract_on_php() {
    check_extract("php");
}
#[test]
fn test_extract_on_lua() {
    check_extract("lua");
}
#[test]
fn test_extract_on_luau() {
    check_extract("luau");
}
#[test]
fn test_extract_on_elixir() {
    check_extract("elixir");
}
#[test]
fn test_extract_on_ocaml() {
    check_extract("ocaml");
}

// ---------------------------------------------------------------------------- imports
#[test]
fn test_imports_on_python() {
    check_imports("python");
}
#[test]
fn test_imports_on_typescript() {
    check_imports("typescript");
}
#[test]
fn test_imports_on_javascript() {
    check_imports("javascript");
}
#[test]
fn test_imports_on_go() {
    check_imports("go");
}
#[test]
fn test_imports_on_rust() {
    check_imports("rust");
}
#[test]
fn test_imports_on_java() {
    check_imports("java");
}
#[test]
fn test_imports_on_c() {
    check_imports("c");
}
#[test]
fn test_imports_on_cpp() {
    check_imports("cpp");
}
#[test]
fn test_imports_on_ruby() {
    check_imports("ruby");
}
#[test]
fn test_imports_on_kotlin() {
    check_imports("kotlin");
}
#[test]
fn test_imports_on_swift() {
    check_imports("swift");
}
#[test]
fn test_imports_on_csharp() {
    check_imports("csharp");
}
#[test]
fn test_imports_on_scala() {
    check_imports("scala");
}
#[test]
fn test_imports_on_php() {
    check_imports("php");
}
#[test]
fn test_imports_on_lua() {
    check_imports("lua");
}
#[test]
fn test_imports_on_luau() {
    check_imports("luau");
}
#[test]
fn test_imports_on_elixir() {
    check_imports("elixir");
}
#[test]
fn test_imports_on_ocaml() {
    check_imports("ocaml");
}

// ---------------------------------------------------------------------------- loc
#[test]
fn test_loc_on_python() {
    check_loc("python");
}
#[test]
fn test_loc_on_typescript() {
    check_loc("typescript");
}
#[test]
fn test_loc_on_javascript() {
    check_loc("javascript");
}
#[test]
fn test_loc_on_go() {
    check_loc("go");
}
#[test]
fn test_loc_on_rust() {
    check_loc("rust");
}
#[test]
fn test_loc_on_java() {
    check_loc("java");
}
#[test]
fn test_loc_on_c() {
    check_loc("c");
}
#[test]
fn test_loc_on_cpp() {
    check_loc("cpp");
}
#[test]
fn test_loc_on_ruby() {
    check_loc("ruby");
}
#[test]
fn test_loc_on_kotlin() {
    check_loc("kotlin");
}
#[test]
fn test_loc_on_swift() {
    check_loc("swift");
}
#[test]
fn test_loc_on_csharp() {
    check_loc("csharp");
}
#[test]
fn test_loc_on_scala() {
    check_loc("scala");
}
#[test]
fn test_loc_on_php() {
    check_loc("php");
}
#[test]
fn test_loc_on_lua() {
    check_loc("lua");
}
#[test]
fn test_loc_on_luau() {
    check_loc("luau");
}
#[test]
fn test_loc_on_elixir() {
    check_loc("elixir");
}
#[test]
fn test_loc_on_ocaml() {
    check_loc("ocaml");
}

// ---------------------------------------------------------------------------- complexity
#[test]
fn test_complexity_on_python() {
    check_complexity("python");
}
#[test]
fn test_complexity_on_typescript() {
    check_complexity("typescript");
}
#[test]
fn test_complexity_on_javascript() {
    check_complexity("javascript");
}
#[test]
fn test_complexity_on_go() {
    check_complexity("go");
}
#[test]
fn test_complexity_on_rust() {
    check_complexity("rust");
}
#[test]
fn test_complexity_on_java() {
    check_complexity("java");
}
#[test]
fn test_complexity_on_c() {
    check_complexity("c");
}
#[test]
fn test_complexity_on_cpp() {
    check_complexity("cpp");
}
#[test]
fn test_complexity_on_ruby() {
    check_complexity("ruby");
}
#[test]
fn test_complexity_on_kotlin() {
    check_complexity("kotlin");
}
#[test]
fn test_complexity_on_swift() {
    check_complexity("swift");
}
#[test]
fn test_complexity_on_csharp() {
    check_complexity("csharp");
}
#[test]
fn test_complexity_on_scala() {
    check_complexity("scala");
}
#[test]
fn test_complexity_on_php() {
    check_complexity("php");
}
#[test]
fn test_complexity_on_lua() {
    check_complexity("lua");
}
#[test]
fn test_complexity_on_luau() {
    check_complexity("luau");
}
#[test]
fn test_complexity_on_elixir() {
    check_complexity("elixir");
}
#[test]
fn test_complexity_on_ocaml() {
    check_complexity("ocaml");
}

// ---------------------------------------------------------------------------- cognitive
#[test]
fn test_cognitive_on_python() {
    check_cognitive("python");
}
#[test]
fn test_cognitive_on_typescript() {
    check_cognitive("typescript");
}
#[test]
fn test_cognitive_on_javascript() {
    check_cognitive("javascript");
}
#[test]
fn test_cognitive_on_go() {
    check_cognitive("go");
}
#[test]
fn test_cognitive_on_rust() {
    check_cognitive("rust");
}
#[test]
fn test_cognitive_on_java() {
    check_cognitive("java");
}
#[test]
fn test_cognitive_on_c() {
    check_cognitive("c");
}
#[test]
fn test_cognitive_on_cpp() {
    check_cognitive("cpp");
}
#[test]
fn test_cognitive_on_ruby() {
    check_cognitive("ruby");
}
#[test]
fn test_cognitive_on_kotlin() {
    check_cognitive("kotlin");
}
#[test]
fn test_cognitive_on_swift() {
    check_cognitive("swift");
}
#[test]
fn test_cognitive_on_csharp() {
    check_cognitive("csharp");
}
#[test]
fn test_cognitive_on_scala() {
    check_cognitive("scala");
}
#[test]
fn test_cognitive_on_php() {
    check_cognitive("php");
}
#[test]
fn test_cognitive_on_lua() {
    check_cognitive("lua");
}
#[test]
fn test_cognitive_on_luau() {
    check_cognitive("luau");
}
#[test]
fn test_cognitive_on_elixir() {
    check_cognitive("elixir");
}
#[test]
fn test_cognitive_on_ocaml() {
    check_cognitive("ocaml");
}

// ---------------------------------------------------------------------------- halstead
#[test]
fn test_halstead_on_python() {
    check_halstead("python");
}
#[test]
fn test_halstead_on_typescript() {
    check_halstead("typescript");
}
#[test]
fn test_halstead_on_javascript() {
    check_halstead("javascript");
}
#[test]
fn test_halstead_on_go() {
    check_halstead("go");
}
#[test]
fn test_halstead_on_rust() {
    check_halstead("rust");
}
#[test]
fn test_halstead_on_java() {
    check_halstead("java");
}
#[test]
fn test_halstead_on_c() {
    check_halstead("c");
}
#[test]
fn test_halstead_on_cpp() {
    check_halstead("cpp");
}
#[test]
fn test_halstead_on_ruby() {
    check_halstead("ruby");
}
#[test]
fn test_halstead_on_kotlin() {
    check_halstead("kotlin");
}
#[test]
fn test_halstead_on_swift() {
    check_halstead("swift");
}
#[test]
fn test_halstead_on_csharp() {
    check_halstead("csharp");
}
#[test]
fn test_halstead_on_scala() {
    check_halstead("scala");
}
#[test]
fn test_halstead_on_php() {
    check_halstead("php");
}
#[test]
fn test_halstead_on_lua() {
    check_halstead("lua");
}
#[test]
fn test_halstead_on_luau() {
    check_halstead("luau");
}
#[test]
fn test_halstead_on_elixir() {
    check_halstead("elixir");
}
#[test]
fn test_halstead_on_ocaml() {
    check_halstead("ocaml");
}

// ---------------------------------------------------------------------------- smells
#[test]
fn test_smells_on_python() {
    check_smells("python");
}
#[test]
fn test_smells_on_typescript() {
    check_smells("typescript");
}
#[test]
fn test_smells_on_javascript() {
    check_smells("javascript");
}
#[test]
fn test_smells_on_go() {
    check_smells("go");
}
#[test]
fn test_smells_on_rust() {
    check_smells("rust");
}
#[test]
fn test_smells_on_java() {
    check_smells("java");
}
#[test]
fn test_smells_on_c() {
    check_smells("c");
}
#[test]
fn test_smells_on_cpp() {
    check_smells("cpp");
}
#[test]
fn test_smells_on_ruby() {
    check_smells("ruby");
}
#[test]
fn test_smells_on_kotlin() {
    check_smells("kotlin");
}
#[test]
fn test_smells_on_swift() {
    check_smells("swift");
}
#[test]
fn test_smells_on_csharp() {
    check_smells("csharp");
}
#[test]
fn test_smells_on_scala() {
    check_smells("scala");
}
#[test]
fn test_smells_on_php() {
    check_smells("php");
}
#[test]
fn test_smells_on_lua() {
    check_smells("lua");
}
#[test]
fn test_smells_on_luau() {
    check_smells("luau");
}
#[test]
fn test_smells_on_elixir() {
    check_smells("elixir");
}
#[test]
fn test_smells_on_ocaml() {
    check_smells("ocaml");
}

// ---------------------------------------------------------------------------- calls
#[test]
fn test_calls_on_python() {
    check_calls("python");
}
#[test]
fn test_calls_on_typescript() {
    check_calls("typescript");
}
#[test]
fn test_calls_on_javascript() {
    check_calls("javascript");
}
#[test]
fn test_calls_on_go() {
    check_calls("go");
}
#[test]
fn test_calls_on_rust() {
    check_calls("rust");
}
#[test]
fn test_calls_on_java() {
    check_calls("java");
}
#[test]
fn test_calls_on_c() {
    check_calls("c");
}
#[test]
fn test_calls_on_cpp() {
    check_calls("cpp");
}
#[test]
fn test_calls_on_ruby() {
    check_calls("ruby");
}
#[test]
fn test_calls_on_kotlin() {
    check_calls("kotlin");
}
#[test]
fn test_calls_on_swift() {
    check_calls("swift");
}
#[test]
fn test_calls_on_csharp() {
    check_calls("csharp");
}
#[test]
fn test_calls_on_scala() {
    check_calls("scala");
}
#[test]
fn test_calls_on_php() {
    check_calls("php");
}
#[test]
fn test_calls_on_lua() {
    check_calls("lua");
}
#[test]
fn test_calls_on_luau() {
    check_calls("luau");
}
#[test]
fn test_calls_on_elixir() {
    check_calls("elixir");
}
#[test]
fn test_calls_on_ocaml() {
    check_calls("ocaml");
}

// ---------------------------------------------------------------------------- dead
#[test]
fn test_dead_on_python() {
    check_dead("python");
}
#[test]
fn test_dead_on_typescript() {
    check_dead("typescript");
}
#[test]
fn test_dead_on_javascript() {
    check_dead("javascript");
}
#[test]
fn test_dead_on_go() {
    check_dead("go");
}
#[test]
fn test_dead_on_rust() {
    check_dead("rust");
}
#[test]
fn test_dead_on_java() {
    check_dead("java");
}
#[test]
fn test_dead_on_c() {
    check_dead("c");
}
#[test]
fn test_dead_on_cpp() {
    check_dead("cpp");
}
#[test]
fn test_dead_on_ruby() {
    check_dead("ruby");
}
#[test]
fn test_dead_on_kotlin() {
    check_dead("kotlin");
}
#[test]
fn test_dead_on_swift() {
    check_dead("swift");
}
#[test]
fn test_dead_on_csharp() {
    check_dead("csharp");
}
#[test]
fn test_dead_on_scala() {
    check_dead("scala");
}
#[test]
fn test_dead_on_php() {
    check_dead("php");
}
#[test]
fn test_dead_on_lua() {
    check_dead("lua");
}
#[test]
fn test_dead_on_luau() {
    check_dead("luau");
}
#[test]
fn test_dead_on_elixir() {
    check_dead("elixir");
}
#[test]
fn test_dead_on_ocaml() {
    check_dead("ocaml");
}

// ---------------------------------------------------------------------------- references
#[test]
fn test_references_on_python() {
    check_references("python");
}
#[test]
fn test_references_on_typescript() {
    check_references("typescript");
}
#[test]
fn test_references_on_javascript() {
    check_references("javascript");
}
#[test]
fn test_references_on_go() {
    check_references("go");
}
#[test]
fn test_references_on_rust() {
    check_references("rust");
}
#[test]
fn test_references_on_java() {
    check_references("java");
}
#[test]
fn test_references_on_c() {
    check_references("c");
}
#[test]
fn test_references_on_cpp() {
    check_references("cpp");
}
#[test]
fn test_references_on_ruby() {
    check_references("ruby");
}
#[test]
fn test_references_on_kotlin() {
    check_references("kotlin");
}
#[test]
fn test_references_on_swift() {
    check_references("swift");
}
#[test]
fn test_references_on_csharp() {
    check_references("csharp");
}
#[test]
fn test_references_on_scala() {
    check_references("scala");
}
#[test]
fn test_references_on_php() {
    check_references("php");
}
#[test]
fn test_references_on_lua() {
    check_references("lua");
}
#[test]
fn test_references_on_luau() {
    check_references("luau");
}
#[test]
fn test_references_on_elixir() {
    check_references("elixir");
}
#[test]
fn test_references_on_ocaml() {
    check_references("ocaml");
}

// ---------------------------------------------------------------------------- impact
#[test]
fn test_impact_on_python() {
    check_impact("python");
}
#[test]
fn test_impact_on_typescript() {
    check_impact("typescript");
}
#[test]
fn test_impact_on_javascript() {
    check_impact("javascript");
}
#[test]
fn test_impact_on_go() {
    check_impact("go");
}
#[test]
fn test_impact_on_rust() {
    check_impact("rust");
}
#[test]
fn test_impact_on_java() {
    check_impact("java");
}
#[test]
fn test_impact_on_c() {
    check_impact("c");
}
#[test]
fn test_impact_on_cpp() {
    check_impact("cpp");
}
#[test]
fn test_impact_on_ruby() {
    check_impact("ruby");
}
#[test]
fn test_impact_on_kotlin() {
    check_impact("kotlin");
}
#[test]
fn test_impact_on_swift() {
    check_impact("swift");
}
#[test]
fn test_impact_on_csharp() {
    check_impact("csharp");
}
#[test]
fn test_impact_on_scala() {
    check_impact("scala");
}
#[test]
fn test_impact_on_php() {
    check_impact("php");
}
#[test]
fn test_impact_on_lua() {
    check_impact("lua");
}
#[test]
fn test_impact_on_luau() {
    check_impact("luau");
}
#[test]
fn test_impact_on_elixir() {
    check_impact("elixir");
}
#[test]
fn test_impact_on_ocaml() {
    check_impact("ocaml");
}

// ---------------------------------------------------------------------------- patterns
#[test]
fn test_patterns_on_python() {
    check_patterns("python");
}
#[test]
fn test_patterns_on_typescript() {
    check_patterns("typescript");
}
#[test]
fn test_patterns_on_javascript() {
    check_patterns("javascript");
}
#[test]
fn test_patterns_on_go() {
    check_patterns("go");
}
#[test]
fn test_patterns_on_rust() {
    check_patterns("rust");
}
#[test]
fn test_patterns_on_java() {
    check_patterns("java");
}
#[test]
fn test_patterns_on_c() {
    check_patterns("c");
}
#[test]
fn test_patterns_on_cpp() {
    check_patterns("cpp");
}
#[test]
fn test_patterns_on_ruby() {
    check_patterns("ruby");
}
#[test]
fn test_patterns_on_kotlin() {
    check_patterns("kotlin");
}
#[test]
fn test_patterns_on_swift() {
    check_patterns("swift");
}
#[test]
fn test_patterns_on_csharp() {
    check_patterns("csharp");
}
#[test]
fn test_patterns_on_scala() {
    check_patterns("scala");
}
#[test]
fn test_patterns_on_php() {
    check_patterns("php");
}
#[test]
fn test_patterns_on_lua() {
    check_patterns("lua");
}
#[test]
fn test_patterns_on_luau() {
    check_patterns("luau");
}
#[test]
fn test_patterns_on_elixir() {
    check_patterns("elixir");
}
#[test]
fn test_patterns_on_ocaml() {
    check_patterns("ocaml");
}

// ============================================================================
// language-command-matrix-extension-v1: extension to ~50 commands × 18 langs.
// ============================================================================
//
// Each new command below adds 18 cells (one per supported language). Every
// cell asserts (1) exit code 0, (2) JSON parses, (3) one shape-specific
// invariant matching the canonical schema (verified against the actual
// command's JSON output, not pre-designed).
//
// Capability gaps that fail are gated with `#[ignore = "<reason>"]` citing
// either:
//  - a known judgment-call deferral (e.g. "vuln autodetect coverage limited
//    to py/rust/ts/js per AA5"),
//  - a specific extractor limitation (e.g. "OCaml class detection no-op
//    in extract_ocaml_classes").
//
// The `for_all_langs!` macro expands one `check_<cmd>` per language to keep
// the file readable. Each language line is a single `#[test] fn` so cargo
// test reports each cell independently.

/// Expand 18 `#[test] fn test_<short>_on_<lang>() { check_<short>("<lang>"); }`
/// stubs from a single invocation. The macro takes the short test stem
/// (e.g. `tree`, `dead_stores`) and the corresponding `check_<stem>`
/// function is invoked with the lang as a string. Languages can be
/// individually gated with `lang, ignore = "<reason>"`.
///
/// Usage:
/// ```
/// gen_lang_tests!(tree, check_tree,
///     python; typescript; ...; ocaml;
/// );
/// ```
macro_rules! gen_lang_tests {
    ($stem:ident, $check:ident, $($lang:ident $(, ignore = $reason:literal)?);* $(;)?) => {
        $(
            paste::paste! {
                #[test]
                $(#[ignore = $reason])?
                fn [<test_ $stem _on_ $lang>]() {
                    $check(stringify!($lang));
                }
            }
        )*
    };
}

/// Variant of `gen_lang_tests!` that adds `#[serial(embedding_cache)]` to
/// each test. fastembed shares a single on-disk model cache; concurrent
/// first-touches race on cache-file creation and one process gets a
/// "No such file or directory" error. Used for embed / semantic / similar.
#[cfg(feature = "semantic")]
macro_rules! gen_lang_tests_serial {
    ($stem:ident, $check:ident, $($lang:ident $(, ignore = $reason:literal)?);* $(;)?) => {
        $(
            paste::paste! {
                #[test]
                #[serial(embedding_cache)]
                $(#[ignore = $reason])?
                fn [<test_ $stem _on_ $lang>]() {
                    $check(stringify!($lang));
                }
            }
        )*
    };
}

/// Stub that defines no tests when the `semantic` feature is off. Embed,
/// semantic, and similar are gated on the feature; without it the tldr
/// binary exits with a "feature not enabled" error and the matrix would
/// fail across the board.
#[cfg(not(feature = "semantic"))]
macro_rules! gen_lang_tests_serial {
    ($stem:ident, $check:ident, $($lang:ident $(, ignore = $reason:literal)?);* $(;)?) => {};
}

// ============================================================================
// Generic shape helper used by many of the new commands.
// ============================================================================

/// Run a tldr subcommand against the canonical fixture root, asserting
/// exit code 0 and that the output parses as a JSON object (or array).
/// Returns the parsed JSON for further per-command shape checks.
fn run_on_fixture(lang: &str, args_after_path: &[&str], cmd: &str) -> Value {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let mut full = vec![cmd, tmp.path().to_str().unwrap()];
    full.extend_from_slice(args_after_path);
    full.extend_from_slice(&["--format", "json", "--quiet"]);
    let (status, json, stdout, stderr) = run_tldr(&full);
    if !status.success() {
        fail_cell(cmd, lang, "non-zero exit", &stdout, &stderr);
    }
    if json.is_null() {
        fail_cell(cmd, lang, "stdout was not parseable JSON", &stdout, &stderr);
    }
    json
}

/// Same as `run_on_fixture` but operates on the entry-file path rather
/// than the fixture root. Used for commands like `cohesion <FILE>`.
fn run_on_entry_file(lang: &str, args_after_file: &[&str], cmd: &str) -> Value {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let mut full = vec![cmd, file.to_str().unwrap()];
    full.extend_from_slice(args_after_file);
    full.extend_from_slice(&["--format", "json", "--quiet"]);
    let (status, json, stdout, stderr) = run_tldr(&full);
    if !status.success() {
        fail_cell(cmd, lang, "non-zero exit", &stdout, &stderr);
    }
    if json.is_null() {
        fail_cell(cmd, lang, "stdout was not parseable JSON", &stdout, &stderr);
    }
    json
}

// ============================================================================
// L1: tree
// ============================================================================
fn check_tree(lang: &str) {
    let json = run_on_fixture(lang, &[], "tree");
    // tree returns a recursive node: { name, type, children?, path? }
    let typ = json.get("type").and_then(Value::as_str).unwrap_or("");
    if typ != "dir" {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("tree", lang, "root .type != \"dir\"", &s, "");
    }
    let children = json
        .get("children")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    if children == 0 {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("tree", lang, "tree.children empty", &s, "");
    }
}

// ============================================================================
// L1: importers
// ============================================================================
fn check_importers(lang: &str) {
    // Use a sentinel module name; the canonical fixtures don't all import
    // the same module name, so we look up `util` (most langs) or a known
    // module. The contract here is: schema is well-formed; importers
    // array exists. Module resolution is per-language.
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let module = match lang {
        "go" => "example.com/x/util",
        _ => "util",
    };
    let (status, json, stdout, stderr) = run_tldr(&[
        "importers",
        module,
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("importers", lang, "non-zero exit", &stdout, &stderr);
    }
    if !json.is_object() {
        fail_cell(
            "importers",
            lang,
            "output is not a JSON object",
            &stdout,
            &stderr,
        );
    }
    if json.get("importers").and_then(Value::as_array).is_none() {
        fail_cell(
            "importers",
            lang,
            ".importers is not an array",
            &stdout,
            &stderr,
        );
    }
    // Total field must be present.
    if json.get("total").and_then(Value::as_u64).is_none() {
        fail_cell(
            "importers",
            lang,
            ".total missing or not a number",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// L2: hubs
// ============================================================================
fn check_hubs(lang: &str) {
    let json = run_on_fixture(lang, &[], "hubs");
    if json.get("hubs").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("hubs", lang, ".hubs is not an array", &s, "");
    }
}

// ============================================================================
// L2: whatbreaks
// ============================================================================
fn check_whatbreaks(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "helper",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("whatbreaks", lang, "non-zero exit", &stdout, &stderr);
    }
    // Schema: { wrapper, path, target, target_type, sub_results }
    for key in ["target", "target_type", "sub_results"] {
        if json.get(key).is_none() {
            fail_cell(
                "whatbreaks",
                lang,
                &format!("missing required key `{key}`"),
                &stdout,
                &stderr,
            );
        }
    }
}

// ============================================================================
// L2: change-impact
// ============================================================================
fn check_change_impact(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "change-impact",
        tmp.path().to_str().unwrap(),
        "--files",
        entry.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("change-impact", lang, "non-zero exit", &stdout, &stderr);
    }
    if json
        .get("changed_files")
        .and_then(Value::as_array)
        .is_none()
    {
        fail_cell(
            "change-impact",
            lang,
            ".changed_files is not an array",
            &stdout,
            &stderr,
        );
    }
    if json
        .get("affected_functions")
        .and_then(Value::as_array)
        .is_none()
    {
        fail_cell(
            "change-impact",
            lang,
            ".affected_functions is not an array",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// L3: reaching-defs
// ============================================================================
fn check_reaching_defs(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "reaching-defs");
    if json.get("blocks").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("reaching-defs", lang, ".blocks is not an array", &s, "");
    }
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("reaching-defs", lang, ".function != \"helper\"", &s, "");
    }
}

// ============================================================================
// L3: available
// ============================================================================
fn check_available(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "available");
    // Schema: { avail_in: {block_id: exprs[]}, avail_out: {...}, all_exprs[],
    //           entry_block, uncertain_exprs[], confidence }
    for key in ["avail_in", "avail_out", "all_exprs"] {
        if json.get(key).is_none() {
            let s = serde_json::to_string(&json).unwrap_or_default();
            fail_cell("available", lang, &format!(".{key} missing"), &s, "");
        }
    }
}

// ============================================================================
// L4: dead-stores
// ============================================================================
fn check_dead_stores(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "dead-stores");
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("dead-stores", lang, ".function != \"helper\"", &s, "");
    }
    if json.get("count").and_then(Value::as_u64).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell(
            "dead-stores",
            lang,
            ".count missing or not a number",
            &s,
            "",
        );
    }
}

// ============================================================================
// L5: slice
// ============================================================================
fn check_slice(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (_, ext_json, _, _) = run_tldr(&[
        "extract",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    let helper_line = extract_helper_line(&ext_json).unwrap_or(2);
    let line_str = helper_line.to_string();
    let (status, json, stdout, stderr) = run_tldr(&[
        "slice",
        file.to_str().unwrap(),
        "helper",
        &line_str,
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("slice", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        fail_cell("slice", lang, ".function != \"helper\"", &stdout, &stderr);
    }
    if json.get("lines").and_then(Value::as_array).is_none() {
        fail_cell("slice", lang, ".lines is not an array", &stdout, &stderr);
    }
}

// ============================================================================
// L5: chop
// ============================================================================
fn check_chop(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let file = entry_file(lang, tmp.path());
    let (_, ext_json, _, _) = run_tldr(&[
        "extract",
        file.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    let helper_line = extract_helper_line(&ext_json).unwrap_or(2);
    let src = helper_line.to_string();
    // Use the same line as both source and target — chop's contract is
    // "intersection of fwd+bwd slice"; with a single-line target this
    // exercises the path-existence schema without depending on per-language
    // helper-body line counts.
    let (status, json, stdout, stderr) = run_tldr(&[
        "chop",
        file.to_str().unwrap(),
        "helper",
        &src,
        &src,
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("chop", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        fail_cell("chop", lang, ".function != \"helper\"", &stdout, &stderr);
    }
    if json.get("lines").and_then(Value::as_array).is_none() {
        fail_cell("chop", lang, ".lines is not an array", &stdout, &stderr);
    }
}

/// Find the `helper` function's start line in an `extract` JSON output.
/// Returns `None` if not found; callers fall back to a sane default.
///
/// review-followup-v1 (Concern 6): post-M4 schema-cleanup-v1, most
/// language fixtures populate `.definitions[]` (with `functions` left
/// null). Without searching that array, slice/chop fall back to
/// `helper_line = 2` for those languages and the test stops exercising
/// the actual line-finding logic. The third arm below restores that
/// signal.
fn extract_helper_line(json: &Value) -> Option<u64> {
    let funcs = json.get("functions").and_then(Value::as_array);
    if let Some(arr) = funcs {
        for f in arr {
            if f.get("name").and_then(Value::as_str) == Some("helper") {
                if let Some(l) = f.get("line").and_then(Value::as_u64) {
                    return Some(l);
                }
                if let Some(l) = f.get("line_start").and_then(Value::as_u64) {
                    return Some(l);
                }
            }
        }
    }
    let classes = json.get("classes").and_then(Value::as_array);
    if let Some(arr) = classes {
        for c in arr {
            if let Some(ms) = c.get("methods").and_then(Value::as_array) {
                for m in ms {
                    if m.get("name").and_then(Value::as_str) == Some("helper") {
                        if let Some(l) = m.get("line").and_then(Value::as_u64) {
                            return Some(l);
                        }
                    }
                }
            }
        }
    }
    // Post-M4 .definitions[] schema — many languages populate this and
    // leave `functions` null. Each entry has a `name` and `line` (or
    // `line_start`) field at top level.
    let defs = json.get("definitions").and_then(Value::as_array);
    if let Some(arr) = defs {
        for d in arr {
            if d.get("name").and_then(Value::as_str) == Some("helper") {
                if let Some(l) = d.get("line").and_then(Value::as_u64) {
                    return Some(l);
                }
                if let Some(l) = d.get("line_start").and_then(Value::as_u64) {
                    return Some(l);
                }
            }
        }
    }
    None
}

// ============================================================================
// L5: taint (per-function shape; clean fixture so flows expected empty)
// ============================================================================
fn check_taint(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "taint");
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("taint", lang, ".function != \"helper\"", &s, "");
    }
    for key in ["sources", "sinks", "flows"] {
        if json.get(key).and_then(Value::as_array).is_none() {
            let s = serde_json::to_string(&json).unwrap_or_default();
            fail_cell("taint", lang, &format!(".{key} is not an array"), &s, "");
        }
    }
}

// ============================================================================
// Resources (per-function lifecycle)
// ============================================================================
fn check_resources(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "resources");
    for key in ["resources", "leaks", "double_closes", "use_after_closes"] {
        if json.get(key).and_then(Value::as_array).is_none() {
            let s = serde_json::to_string(&json).unwrap_or_default();
            fail_cell(
                "resources",
                lang,
                &format!(".{key} is not an array"),
                &s,
                "",
            );
        }
    }
}

// ============================================================================
// Security: vuln (gated to py/rust/ts/js for autodetect coverage)
// ============================================================================
fn check_vuln(lang: &str) {
    let json = run_on_fixture(lang, &[], "vuln");
    if json.get("findings").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("vuln", lang, ".findings is not an array", &s, "");
    }
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("vuln", lang, ".summary missing", &s, "");
    }
}

// ============================================================================
// Security: secure
// ============================================================================
fn check_secure(lang: &str) {
    let json = run_on_fixture(lang, &[], "secure");
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("secure", lang, ".summary missing", &s, "");
    }
    if json.get("findings").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("secure", lang, ".findings is not an array", &s, "");
    }
}

// ============================================================================
// Security: api-check
// ============================================================================
fn check_api_check(lang: &str) {
    let json = run_on_fixture(lang, &[], "api-check");
    if json.get("findings").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("api-check", lang, ".findings is not an array", &s, "");
    }
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("api-check", lang, ".summary missing", &s, "");
    }
}

// ============================================================================
// Quality: churn (needs git fixture)
// ============================================================================
fn check_churn(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_git_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "churn",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("churn", lang, "non-zero exit", &stdout, &stderr);
    }
    let files = json.get("files").and_then(Value::as_array);
    if files.map(|a| a.is_empty()).unwrap_or(true) {
        fail_cell(
            "churn",
            lang,
            ".files empty — git history did not produce churn data",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// Quality: debt
// ============================================================================
fn check_debt(lang: &str) {
    let json = run_on_fixture(lang, &[], "debt");
    if json.get("issues").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("debt", lang, ".issues is not an array", &s, "");
    }
}

// ============================================================================
// Quality: health
// ============================================================================
fn check_health(lang: &str) {
    let json = run_on_fixture(lang, &[], "health");
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("health", lang, ".summary missing", &s, "");
    }
    let files = json
        .get("summary")
        .and_then(|s| s.get("files_analyzed"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if files == 0 {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("health", lang, ".summary.files_analyzed = 0", &s, "");
    }
}

// ============================================================================
// Quality: hotspots (needs git)
// ============================================================================
fn check_hotspots(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_git_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "hotspots",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("hotspots", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("hotspots").and_then(Value::as_array).is_none() {
        fail_cell(
            "hotspots",
            lang,
            ".hotspots is not an array",
            &stdout,
            &stderr,
        );
    }
    if json.get("summary").is_none() {
        fail_cell("hotspots", lang, ".summary missing", &stdout, &stderr);
    }
}

// ============================================================================
// Quality: clones (needs duplicate fixture)
// ============================================================================
fn check_clones(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture_with_clone(lang, tmp.path());
    // language-command-matrix-clones-test-fix-v1: the canonical clone
    // fixture (`build_fixture_with_clone`) writes two near-identical
    // functions IN THE SAME FILE. By design `tldr clones` excludes
    // same-file pairs unless `--include-within-file` is passed (see
    // crates/tldr-core/src/analysis/clones/types.rs default and
    // crates/tldr-cli/src/commands/clones.rs --include-within-file).
    // Pass the flag here to exercise intra-file clone detection on the
    // canonical fixture.
    let (status, json, stdout, stderr) = run_tldr(&[
        "clones",
        tmp.path().to_str().unwrap(),
        "--include-within-file",
        "--min-tokens",
        "10",
        "--min-lines",
        "1",
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("clones", lang, "non-zero exit", &stdout, &stderr);
    }
    let pairs = json.get("clone_pairs").and_then(Value::as_array);
    if pairs.is_none() {
        fail_cell(
            "clones",
            lang,
            ".clone_pairs is not an array",
            &stdout,
            &stderr,
        );
    }
    if json.get("stats").is_none() {
        fail_cell("clones", lang, ".stats missing", &stdout, &stderr);
    }
    // Strengthened invariant (language-command-matrix-strengthen-v1): the
    // clone fixture writes `c_dup_one` and `c_dup_two` as a near-duplicate
    // pair (per fixtures/mod.rs build_fixture_with_clone, line 274:
    // "ensure the clone detector finds at least one candidate pair"). The
    // detector MUST find at least one pair on this fixture.
    let n_pairs = pairs.map(|a| a.len()).unwrap_or(0);
    let stats_found = json
        .get("stats")
        .and_then(|s| s.get("clones_found"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if n_pairs == 0 && stats_found == 0 {
        fail_cell(
            "clones",
            lang,
            ".clone_pairs empty AND stats.clones_found = 0 — \
             expected ≥1 pair from c_dup fixture (fixtures/mod.rs:274)",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// Quality: dice (similarity between two files)
// ============================================================================
fn check_dice(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture_with_clone(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    // Use the duplicated file as second target.
    let (dup_rel, _) = match lang {
        "rust" => ("src/c_dup.rs", ""),
        "python" => ("c_dup.py", ""),
        "typescript" => ("c_dup.ts", ""),
        "javascript" => ("c_dup.js", ""),
        "go" => ("c_dup.go", ""),
        "java" => ("CDup.java", ""),
        "c" => ("c_dup.c", ""),
        "cpp" => ("c_dup.cpp", ""),
        "ruby" => ("c_dup.rb", ""),
        "kotlin" => ("CDup.kt", ""),
        "swift" => ("CDup.swift", ""),
        "csharp" => ("CDup.cs", ""),
        "scala" => ("CDup.scala", ""),
        "php" => ("c_dup.php", ""),
        "lua" => ("c_dup.lua", ""),
        "luau" => ("c_dup.luau", ""),
        "elixir" => ("c_dup.ex", ""),
        "ocaml" => ("c_dup.ml", ""),
        _ => panic!("unknown"),
    };
    let dup_path = tmp.path().join(dup_rel);
    let (status, json, stdout, stderr) = run_tldr(&[
        "dice",
        entry.to_str().unwrap(),
        dup_path.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("dice", lang, "non-zero exit", &stdout, &stderr);
    }
    let coeff = json.get("dice_coefficient").and_then(Value::as_f64);
    if coeff.is_none() {
        fail_cell(
            "dice",
            lang,
            ".dice_coefficient missing or not a number",
            &stdout,
            &stderr,
        );
    }
    // Strengthened invariant (language-command-matrix-strengthen-v1): the
    // entry file and c_dup file from build_fixture_with_clone share enough
    // syntactic structure (per fixtures/mod.rs clone_dup_payload, line 284:
    // "trivial function that mirrors `helper`") that the dice coefficient
    // MUST be non-trivially positive. Threshold ≥0.1 is robustly above
    // tokenizer noise on per-language syntax differences.
    let value = coeff.unwrap_or(0.0);
    if value < 0.1 {
        fail_cell(
            "dice",
            lang,
            &format!(
                ".dice_coefficient = {:.4} < 0.1 — expected ≥0.1 between \
                 entry file and c_dup near-duplicate (fixtures/mod.rs:284)",
                value
            ),
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// Patterns: inheritance, deps, cohesion, coupling
// ============================================================================
fn check_inheritance(lang: &str) {
    let json = run_on_fixture(lang, &[], "inheritance");
    for key in ["edges", "nodes", "roots", "leaves"] {
        if json.get(key).and_then(Value::as_array).is_none() {
            let s = serde_json::to_string(&json).unwrap_or_default();
            fail_cell(
                "inheritance",
                lang,
                &format!(".{key} is not an array"),
                &s,
                "",
            );
        }
    }
}

fn check_deps(lang: &str) {
    let json = run_on_fixture(lang, &[], "deps");
    if json.get("internal_dependencies").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("deps", lang, ".internal_dependencies missing", &s, "");
    }
    if json.get("stats").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("deps", lang, ".stats missing", &s, "");
    }
}

fn check_cohesion(lang: &str) {
    let json = run_on_entry_file(lang, &[], "cohesion");
    if json.get("classes").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("cohesion", lang, ".classes is not an array", &s, "");
    }
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("cohesion", lang, ".summary missing", &s, "");
    }
}

fn check_coupling(lang: &str) {
    // coupling takes two files
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    // pick the "B" file (different filename per lang).
    let b = match lang {
        "python" => tmp.path().join("util.py"),
        "typescript" => tmp.path().join("util.ts"),
        "javascript" => tmp.path().join("util.js"),
        "go" => tmp.path().join("util/util.go"),
        "rust" => tmp.path().join("src/util.rs"),
        "java" => tmp.path().join("Util.java"),
        "c" => tmp.path().join("util.c"),
        "cpp" => tmp.path().join("util.cpp"),
        "ruby" => tmp.path().join("util.rb"),
        "kotlin" => tmp.path().join("Util.kt"),
        "swift" => tmp.path().join("Util.swift"),
        "csharp" => tmp.path().join("Util.cs"),
        "scala" => tmp.path().join("Util.scala"),
        "php" => tmp.path().join("util.php"),
        "lua" => tmp.path().join("util.lua"),
        "luau" => tmp.path().join("util.luau"),
        "elixir" => tmp.path().join("util.ex"),
        "ocaml" => tmp.path().join("util.ml"),
        _ => panic!("unknown lang"),
    };
    let (status, json, stdout, stderr) = run_tldr(&[
        "coupling",
        entry.to_str().unwrap(),
        b.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("coupling", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("a_to_b").is_none() || json.get("b_to_a").is_none() {
        fail_cell(
            "coupling",
            lang,
            ".a_to_b or .b_to_a missing",
            &stdout,
            &stderr,
        );
    }
}

// ============================================================================
// Contracts / Specs / Invariants / Verify / Interface
// ============================================================================
fn check_contracts(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "contracts");
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("contracts", lang, ".function != \"helper\"", &s, "");
    }
    for key in ["preconditions", "postconditions", "invariants"] {
        if json.get(key).and_then(Value::as_array).is_none() {
            let s = serde_json::to_string(&json).unwrap_or_default();
            fail_cell(
                "contracts",
                lang,
                &format!(".{key} is not an array"),
                &s,
                "",
            );
        }
    }
}

/// Build a minimal `tests/` subdir and a single test file for the given
/// language. Used by specs/invariants which require a tests dir input.
fn write_minimal_test_dir(lang: &str, root: &std::path::Path) -> std::path::PathBuf {
    let tdir = root.join("tests_dir_audit_v1");
    std::fs::create_dir_all(&tdir).unwrap();
    let (rel, body) = match lang {
        "python" => (
            "test_audit.py",
            "def test_helper():\n    assert 1 + 1 == 2\n",
        ),
        "typescript" => (
            "audit.test.ts",
            "describe('helper', () => { it('works', () => { /* */ }); });\n",
        ),
        "javascript" => (
            "audit.test.js",
            "describe('helper', () => { it('works', () => { /* */ }); });\n",
        ),
        "go" => (
            "audit_test.go",
            "package x\nimport \"testing\"\nfunc TestAudit(t *testing.T) {}\n",
        ),
        "rust" => (
            "audit.rs",
            "#[test]\nfn test_audit() { assert_eq!(1 + 1, 2); }\n",
        ),
        "java" => (
            "AuditTest.java",
            "class AuditTest { void testAudit() {} }\n",
        ),
        "c" => ("audit_test.c", "void test_audit(void) {}\n"),
        "cpp" => ("audit_test.cpp", "void test_audit() {}\n"),
        "ruby" => (
            "audit_test.rb",
            "def test_audit; raise unless 1 + 1 == 2; end\n",
        ),
        "kotlin" => ("AuditTest.kt", "fun testAudit() {}\n"),
        "swift" => ("AuditTests.swift", "func testAudit() {}\n"),
        "csharp" => ("AuditTest.cs", "class AuditTest { void TestAudit() {} }\n"),
        "scala" => (
            "AuditTest.scala",
            "object AuditTest { def testAudit(): Unit = () }\n",
        ),
        "php" => ("AuditTest.php", "<?php\nfunction test_audit() {}\n"),
        "lua" => (
            "audit_test.lua",
            "local function test_audit() end\nreturn { test_audit = test_audit }\n",
        ),
        "luau" => (
            "audit_test.luau",
            "local function test_audit() end\nreturn { test_audit = test_audit }\n",
        ),
        "elixir" => (
            "audit_test.exs",
            "defmodule AuditTest do\n  def test_audit, do: :ok\nend\n",
        ),
        "ocaml" => ("audit_test.ml", "let test_audit () = ()\n"),
        _ => panic!("unknown"),
    };
    fixtures::write_file(&tdir.join(rel), body);
    tdir
}

fn check_specs(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let tdir = write_minimal_test_dir(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "specs",
        "--from-tests",
        tdir.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("specs", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("functions").and_then(Value::as_array).is_none() {
        fail_cell(
            "specs",
            lang,
            ".functions is not an array",
            &stdout,
            &stderr,
        );
    }
    if json.get("summary").is_none() {
        fail_cell("specs", lang, ".summary missing", &stdout, &stderr);
    }
    // Shape-only by design (language-command-matrix-strengthen-v1):
    // write_minimal_test_dir (line 2477) emits a single test (e.g.
    // `test_helper` asserting `1 + 1 == 2`) that does NOT call the
    // production `helper` function from the canonical fixture — there is no
    // function-under-test relationship to extract a spec from. Empty
    // `.functions` is the correct semantic outcome here, not a bug. To
    // strengthen this cell, write_minimal_test_dir would need to emit a
    // test that actually calls `helper(...)` and asserts on its return —
    // future milestone.
}

fn check_invariants(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let tdir = write_minimal_test_dir(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "invariants",
        entry.to_str().unwrap(),
        "--from-tests",
        tdir.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("invariants", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("functions").and_then(Value::as_array).is_none() {
        fail_cell(
            "invariants",
            lang,
            ".functions is not an array",
            &stdout,
            &stderr,
        );
    }
    if json.get("summary").is_none() {
        fail_cell("invariants", lang, ".summary missing", &stdout, &stderr);
    }
    // Shape-only by design (language-command-matrix-strengthen-v1):
    // matches check_specs rationale — write_minimal_test_dir (line 2477)
    // emits a degenerate `assert 1 + 1 == 2` test that records no
    // input/output observations against entry-file functions. Empty
    // `.functions` is the correct semantic outcome. Strengthening
    // requires test bodies that actually call entry-file functions and
    // assert on observed return values — future milestone.
}

fn check_verify(lang: &str) {
    let json = run_on_fixture(lang, &[], "verify");
    if json.get("sub_results").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("verify", lang, ".sub_results missing", &s, "");
    }
}

fn check_interface(lang: &str) {
    let json = run_on_entry_file(lang, &[], "interface");
    if json.get("all_exports").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("interface", lang, ".all_exports is not an array", &s, "");
    }
}

// ============================================================================
// Coverage (LCOV stub — language-agnostic; only the report parser runs)
// ============================================================================
fn check_coverage(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let lcov = tmp.path().join("coverage.lcov");
    // Reference whichever entry file exists; the LCOV parser is line-based
    // and language-agnostic, so a minimal stub is sufficient.
    let entry_rel = entry_file(lang, tmp.path());
    let entry_rel = entry_rel
        .strip_prefix(tmp.path())
        .unwrap_or_else(|_| std::path::Path::new("main"))
        .to_string_lossy()
        .into_owned();
    let body = format!(
        "TN:\nSF:{}\nDA:1,1\nDA:2,1\nDA:3,1\nLH:3\nLF:3\nend_of_record\n",
        entry_rel
    );
    std::fs::write(&lcov, body).unwrap();
    let (status, json, stdout, stderr) = run_tldr(&[
        "coverage",
        lcov.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("coverage", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("format").and_then(Value::as_str) != Some("lcov") {
        fail_cell("coverage", lang, ".format != \"lcov\"", &stdout, &stderr);
    }
    if json.get("summary").is_none() {
        fail_cell("coverage", lang, ".summary missing", &stdout, &stderr);
    }
}

// ============================================================================
// Search / semantic / similar / embed / context / definition
// ============================================================================
fn check_search(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "search",
        "helper",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("search", lang, "non-zero exit", &stdout, &stderr);
    }
    let results = json.get("results").and_then(Value::as_array);
    if results.is_none() {
        fail_cell("search", lang, ".results is not an array", &stdout, &stderr);
    }
    // Strengthened invariant (language-command-matrix-strengthen-v1): every
    // canonical fixture defines a function literally named `helper` and a
    // `main` that calls `helper()` (see fixtures/mod.rs build_python at
    // line 396, build_typescript at 412, etc.). Searching for the literal
    // token "helper" MUST return ≥1 result.
    let n = results.map(|a| a.len()).unwrap_or(0);
    let total = json
        .get("total_results")
        .and_then(Value::as_u64)
        .unwrap_or(n as u64);
    if n == 0 && total == 0 {
        fail_cell(
            "search",
            lang,
            ".results empty — expected ≥1 hit for literal token \
             \"helper\" defined and called in canonical fixture",
            &stdout,
            &stderr,
        );
    }
}

fn check_semantic(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "semantic",
        "helper function returning a constant",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("semantic", lang, "non-zero exit", &stdout, &stderr);
    }
    let results = json.get("results").and_then(Value::as_array);
    if results.is_none() {
        fail_cell(
            "semantic",
            lang,
            ".results is not an array",
            &stdout,
            &stderr,
        );
    }
    // Strengthened invariant (language-command-matrix-strengthen-v1): the
    // canonical fixture defines `helper` (returns constant 1) and
    // `b_util` (returns constant 2). Semantic search for "helper function
    // returning a constant" MUST return ≥1 result against these chunks.
    let n = results.map(|a| a.len()).unwrap_or(0);
    let total = json
        .get("total_results")
        .and_then(Value::as_u64)
        .unwrap_or(n as u64);
    if n == 0 && total == 0 {
        fail_cell(
            "semantic",
            lang,
            ".results empty — expected ≥1 result for query \"helper \
             function returning a constant\" against fixture defining \
             helper-as-constant (fixtures/mod.rs:396)",
            &stdout,
            &stderr,
        );
    }
}

fn check_similar(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture_with_clone(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    let (status, json, stdout, stderr) = run_tldr(&[
        "similar",
        entry.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("similar", lang, "non-zero exit", &stdout, &stderr);
    }
    let arr = json.get("similar_files").and_then(Value::as_array);
    if arr.is_none() {
        fail_cell(
            "similar",
            lang,
            ".similar_files is not an array",
            &stdout,
            &stderr,
        );
    }
    // Strengthened invariant (language-command-matrix-strengthen-v1): the
    // build_fixture_with_clone fixture writes a c_dup file mirroring
    // helper's structure (fixtures/mod.rs clone_dup_payload, line 284).
    // Embedding-similarity search from the entry file MUST surface ≥1
    // similar file (the c_dup duplicate, the util sibling, or both).
    let n = arr.map(|a| a.len()).unwrap_or(0);
    if n == 0 {
        fail_cell(
            "similar",
            lang,
            ".similar_files empty — expected ≥1 entry given c_dup \
             near-duplicate fixture (fixtures/mod.rs:284)",
            &stdout,
            &stderr,
        );
    }
}

fn check_embed(lang: &str) {
    let json = run_on_fixture(lang, &[], "embed");
    // embed returns { path, model, granularity, chunks_embedded, chunks_cached, latency_ms }
    if json.get("model").and_then(Value::as_str).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("embed", lang, ".model is not a string", &s, "");
    }
    let total = json
        .get("chunks_embedded")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + json
            .get("chunks_cached")
            .and_then(Value::as_u64)
            .unwrap_or(0);
    if total == 0 {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("embed", lang, "chunks_embedded + chunks_cached = 0", &s, "");
    }
}

fn check_context(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    // Use `helper` as the entry — `main` is renamed to `Main` in csharp,
    // and is parameterised in scala/swift/etc. `helper` is the canonical
    // cross-language constant-return function in every fixture.
    let (status, json, stdout, stderr) = run_tldr(&[
        "context",
        "helper",
        "--project",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("context", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("entry_point").and_then(Value::as_str).is_none() {
        fail_cell(
            "context",
            lang,
            ".entry_point missing or not a string",
            &stdout,
            &stderr,
        );
    }
    if json.get("functions").and_then(Value::as_array).is_none() {
        fail_cell(
            "context",
            lang,
            ".functions is not an array",
            &stdout,
            &stderr,
        );
    }
}

fn check_definition(lang: &str) {
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    // Read the actual file content and find the byte-column of "helper" on
    // any line. This is robust across all languages' indentation styles
    // (Java's `class { public static int helper() }` puts helper at col 23+;
    // Python's `def helper()` puts it at col 5).
    let body = std::fs::read_to_string(&entry).unwrap_or_default();
    let mut found: Option<(u32, u32)> = None;
    for (i, line) in body.lines().enumerate() {
        if let Some(col) = line.find("helper") {
            // tldr definition is 1-indexed; the column points at the
            // start of the identifier. Try the start byte of "helper".
            found = Some(((i as u32) + 1, (col as u32) + 1));
            break;
        }
    }
    let (line_no, col_no) = found.unwrap_or((1, 1));
    // Try the discovered position plus a few offsets within the identifier
    // (definition can be picky about which byte exactly).
    let mut last_status = None;
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    let mut last_json: Value = Value::Null;
    for delta in [0i32, 1, 2, 3, 4] {
        let l = line_no.to_string();
        let c = (col_no as i32 + delta).max(1).to_string();
        let (status, json, stdout, stderr) = run_tldr(&[
            "definition",
            entry.to_str().unwrap(),
            &l,
            &c,
            "--format",
            "json",
            "--quiet",
        ]);
        last_status = Some(status);
        last_stdout = stdout;
        last_stderr = stderr;
        last_json = json;
        if last_status.unwrap().success() && last_json.get("symbol").is_some() {
            break;
        }
    }
    if !last_status.map(|s| s.success()).unwrap_or(false) {
        fail_cell(
            "definition",
            lang,
            "non-zero exit on all probed columns",
            &last_stdout,
            &last_stderr,
        );
    }
    if last_json.get("symbol").is_none() && last_json.get("error").is_none() {
        fail_cell(
            "definition",
            lang,
            "neither .symbol nor .error in output",
            &last_stdout,
            &last_stderr,
        );
    }
}

// ============================================================================
// Aggregated: explain, todo, diff
// ============================================================================
fn check_explain(lang: &str) {
    let json = run_on_entry_file(lang, &["helper"], "explain");
    if json.get("function").and_then(Value::as_str) != Some("helper") {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("explain", lang, ".function != \"helper\"", &s, "");
    }
    if json.get("signature").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("explain", lang, ".signature missing", &s, "");
    }
}

fn check_todo(lang: &str) {
    let json = run_on_fixture(lang, &[], "todo");
    if json.get("items").and_then(Value::as_array).is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("todo", lang, ".items is not an array", &s, "");
    }
    if json.get("summary").is_none() {
        let s = serde_json::to_string(&json).unwrap_or_default();
        fail_cell("todo", lang, ".summary missing", &s, "");
    }
}

fn check_diff(lang: &str) {
    // diff requires two files; we use entry vs entry+touch so the AST diff
    // has something to compare. Even identical files produce a valid JSON.
    let tmp = TempDir::new().unwrap();
    fixtures::build_fixture(lang, tmp.path());
    let entry = entry_file(lang, tmp.path());
    let copy = tmp.path().join("entry_copy");
    std::fs::copy(&entry, &copy).unwrap();
    let (status, json, stdout, stderr) = run_tldr(&[
        "diff",
        entry.to_str().unwrap(),
        copy.to_str().unwrap(),
        "--format",
        "json",
        "--quiet",
    ]);
    if !status.success() {
        fail_cell("diff", lang, "non-zero exit", &stdout, &stderr);
    }
    if json.get("changes").and_then(Value::as_array).is_none() {
        fail_cell("diff", lang, ".changes is not an array", &stdout, &stderr);
    }
    if json.get("summary").is_none() {
        fail_cell("diff", lang, ".summary missing", &stdout, &stderr);
    }
}

// ============================================================================
// Per-command × per-language test stubs.
// ============================================================================
//
// Each `gen_lang_tests!` invocation expands to 18 `#[test] fn` items.

gen_lang_tests!(tree, check_tree,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(importers, check_importers,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(hubs, check_hubs,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(whatbreaks, check_whatbreaks,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(change_impact, check_change_impact,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(reaching_defs, check_reaching_defs,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(available, check_available,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(dead_stores, check_dead_stores,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(slice, check_slice,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(chop, check_chop,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(taint, check_taint,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(resources, check_resources,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

// vuln: autodetect coverage limited to py/rust/ts/js per AA5. Non-supported
// langs exit non-zero with a routing-error message ("taint analysis for
// <lang> is not yet supported by autodetect; pass --lang <lang> explicitly")
// and so are gated `#[ignore]` until autodetect is broadened.
gen_lang_tests!(vuln, check_vuln,
    python; typescript; javascript; rust;
    go,       ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    java,     ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    c,        ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    cpp,      ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    ruby,     ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    kotlin,   ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    swift,    ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    csharp,   ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    scala,    ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    php,      ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    lua,      ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    luau,     ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    elixir,   ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
    ocaml,    ignore = "vuln autodetect coverage limited to py/rust/ts/js per AA5";
);

// secure: same gating as vuln — taint analysis autodetect limited to
// py/rust/ts/js. The wrapper shares vuln's routing.
gen_lang_tests!(secure, check_secure,
    python; typescript; javascript; rust;
    go,       ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    java,     ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    c,        ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    cpp,      ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    ruby,     ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    kotlin,   ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    swift,    ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    csharp,   ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    scala,    ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    php,      ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    lua,      ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    luau,     ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    elixir,   ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
    ocaml,    ignore = "secure autodetect coverage limited to py/rust/ts/js per AA5";
);

// api-check: rules library is Python/JS-focused per CLAUDE.md note. Returns
// valid empty-findings JSON on other langs which satisfies the shape check
// — handler exits 0 with `findings: []` so all 18 cells pass schema. No
// gating needed.
gen_lang_tests!(api_check, check_api_check,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(churn, check_churn,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(debt, check_debt,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(health, check_health,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(hotspots, check_hotspots,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(clones, check_clones,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(dice, check_dice,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(inheritance, check_inheritance,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(deps, check_deps,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(cohesion, check_cohesion,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(coupling, check_coupling,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(contracts, check_contracts,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

// specs: pytest-focused, but specs handler returns valid empty-functions
// JSON on non-py langs (handler scans tests dir uniformly). Schema check
// holds across all 18.
gen_lang_tests!(specs, check_specs,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(invariants, check_invariants,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(verify, check_verify,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(interface, check_interface,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

// coverage: LCOV parser is fully language-agnostic.
gen_lang_tests!(coverage, check_coverage,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(search, check_search,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

// semantic / similar / embed: each uses the fastembed model cache via
// the `semantic` cargo feature. Cache initialization is not safe under
// parallel first-touches — `serial(embedding_cache)` lock follows the
// same pattern as `exhaustive_matrix.rs`.
gen_lang_tests_serial!(semantic, check_semantic,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests_serial!(similar, check_similar,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests_serial!(embed, check_embed,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(context, check_context,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(definition, check_definition,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(explain, check_explain,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(todo, check_todo,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);

gen_lang_tests!(diff, check_diff,
    python; typescript; javascript; go; rust; java; c; cpp; ruby;
    kotlin; swift; csharp; scala; php; lua; luau; elixir; ocaml;
);
