//! cluster-misc-v3a: Three mechanical gap fixes.
//!
//! # CLUSTER-M-012 — W-C nested serializer path canonicalization leak (verify)
//!
//! Pre-fix (audit state):
//! - `tldr verify /tmp/repos/flask` emitted `sub_results.contracts.data[].file`
//!   paths as `/private/tmp/repos/flask/...` (macOS firmlink leaked through).
//!
//! Post-fix / current state:
//! - Already closed by M-008 (`PathShapeRewriter`) + M-011 verify-aggregator
//!   path-shape hotfix (`b408ff7`). The `run_verify` call receives the
//!   user-input path (not the canonical form), so `ContractsReport.file` is
//!   always the user-input shape.
//! - This section adds a regression guard asserting zero `/private/tmp/`
//!   occurrences in `sub_results.contracts.data[].file`.
//!
//! # CLUSTER-M-036 — Hubs/centrality `line:0` for cross-file edges
//!
//! Pre-fix:
//! - `tldr hubs <cpp-tinyxml2>` returned `function_ref.line=0` for every
//!   function defined in `tinyxml2.h`. Root cause: `enumerate_function_lines`
//!   used `Language::extensions()` which omits `.h` for C++; the walker never
//!   visited the header file, so the `(file, name) -> line` lookup table had
//!   no entries for header symbols.
//!
//! Post-fix:
//! - `enumerate_function_lines` uses `Language::scan_extensions()` instead of
//!   `Language::extensions()`. For C++, `scan_extensions()` adds `.h` so
//!   header inline functions are indexed by the AST extractor.
//! - `extract_file_with_lang` is called with the known `language` so `.h`
//!   files in a C++ project are parsed as C++ (not C), enabling `class`
//!   declarations to surface as classes.
//!
//! # CLUSTER-M-037 — Halstead/cognitive function counts differ
//!
//! Pre-fix:
//! - C#: `tldr cognitive` reported 50 functions; `tldr halstead` reported 55.
//!   Five overloaded methods (same name, different line) were found by
//!   `extract_file` (and thus halstead) but missed by cognitive's
//!   `augment_cognitive_with_extractor_functions` because it deduped by name
//!   alone — a second overload with a different line was silently skipped.
//! - Java: `tldr halstead` reported 11 functions; `tldr cognitive` reported 12.
//!   Java constructors (`constructor_declaration`) are included in
//!   `get_function_node_kinds(Java)` and thus found by cognitive's AST walk,
//!   but `extract_file` does not surface them in `module.functions` or
//!   `module.classes[].methods`, so halstead missed the constructor.
//!
//! Post-fix:
//! - `augment_cognitive_with_extractor_functions`: `existing` set keyed by
//!   `(name, line)` pairs instead of name only, so overloads at different
//!   lines are each treated as distinct candidates.
//! - `analyze_halstead`: after the `module.functions` + `module.classes[].methods`
//!   loops, a supplementary AST walk using `get_function_node_kinds(lang)`
//!   picks up any function nodes not yet seen by (name, line) — catching Java
//!   constructors and any other node kinds the extractor silently omits.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// =============================================================================
// M-012: verify sub_results.contracts.data[].file never contains /private/tmp/
// =============================================================================

/// Regression guard: `tldr verify` on a Python project must not emit
/// `/private/tmp/` in any `sub_results.contracts.data[].file` value.
/// This was the M-012 bug; closed by M-008 + b408ff7 hotfix.
#[test]
fn test_m012_verify_contracts_no_private_tmp_paths() {
    // Create a minimal Python project so verify has something to analyze.
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("example.py");
    fs::write(
        &src,
        r#"
def add(x: int, y: int) -> int:
    """Add two integers."""
    assert isinstance(x, int), "x must be int"
    assert isinstance(y, int), "y must be int"
    return x + y

def greet(name: str) -> str:
    """Return greeting."""
    assert len(name) > 0, "name must be non-empty"
    return f"Hello, {name}!"
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "verify",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "verify should succeed");

    let v: Value = serde_json::from_str(&stdout).expect("verify should emit valid JSON");

    // Collect all file paths from sub_results.contracts.data[].file
    let contracts_data = &v["sub_results"]["contracts"]["data"];
    if let Some(arr) = contracts_data.as_array() {
        for entry in arr {
            let file = entry["file"].as_str().unwrap_or("");
            assert!(
                !file.contains("/private/tmp/"),
                "M-012 regression: contracts.data[].file must not contain /private/tmp/; got: {file}"
            );
        }
    }
    // Also assert the top-level path field is correct
    let top_path = v["path"].as_str().unwrap_or("");
    assert!(
        !top_path.contains("/private/tmp/"),
        "M-012: top-level path must not contain /private/tmp/; got: {top_path}"
    );
}

// =============================================================================
// M-036: hubs line enrichment for header-file symbols (C++)
// =============================================================================

/// M-036: `tldr hubs` on a C++ project that has inline functions in `.h`
/// headers must return non-zero `function_ref.line` for those header functions.
///
/// Pre-fix: `enumerate_function_lines` used `Language::extensions()` which
/// excludes `.h`, so header symbols always got `line=0`.
/// Post-fix: `scan_extensions()` includes `.h` for C++, and `extract_file_with_lang`
/// uses the C++ grammar for `.h` files.
#[test]
fn test_m036_hubs_cpp_header_functions_have_nonzero_line() {
    let dir = TempDir::new().unwrap();

    // Write a minimal C++ project: a header with inline functions + a .cpp
    // that calls them so the call graph has edges.
    fs::write(
        dir.path().join("utils.h"),
        r#"
#pragma once

inline int add(int a, int b) {
    return a + b;
}

inline int multiply(int a, int b) {
    return a * b;
}

inline int subtract(int a, int b) {
    return a - b;
}
"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("main.cpp"),
        r#"
#include "utils.h"

int compute(int x, int y) {
    return add(x, y) + multiply(x, y) - subtract(x, y);
}

int run_all(int a, int b) {
    return compute(a, b) + add(a, 1) + multiply(b, 2);
}

int main() {
    return run_all(3, 4);
}
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "hubs",
        dir.path().to_str().unwrap(),
        "--lang",
        "cpp",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "hubs should succeed on cpp project");

    let v: Value = serde_json::from_str(&stdout).expect("hubs should emit valid JSON");
    let hubs = v["hubs"].as_array().expect("hubs array present");

    assert!(
        !hubs.is_empty(),
        "M-036: hubs should find at least one hub in the cpp project"
    );

    // Every hub whose file ends with ".h" must have a non-zero line.
    let header_hubs_with_zero: Vec<(&str, u64)> = hubs
        .iter()
        .filter_map(|h| {
            let file = h["function_ref"]["file"].as_str().unwrap_or("");
            let line = h["function_ref"]["line"].as_u64().unwrap_or(0);
            if file.ends_with(".h") && line == 0 {
                Some((file, line))
            } else {
                None
            }
        })
        .collect();

    assert!(
        header_hubs_with_zero.is_empty(),
        "M-036: header functions must not have line=0; offenders: {header_hubs_with_zero:?}"
    );
}

/// M-036: hubs on a pure-Go project (no .h files) must still return
/// non-zero lines. This guards regression for the non-Cpp path.
#[test]
fn test_m036_hubs_go_nonzero_lines() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("router.go"),
        r#"package main

func handle(req string) string {
    return route(req)
}

func route(path string) string {
    return dispatch(path)
}

func dispatch(path string) string {
    return path + "_handled"
}

func main() {
    _ = handle("/foo")
}
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "hubs",
        dir.path().to_str().unwrap(),
        "--lang",
        "go",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "hubs should succeed on go project");

    let v: Value = serde_json::from_str(&stdout).expect("hubs should emit valid JSON");
    let hubs = v["hubs"].as_array().expect("hubs array");

    // All hubs should have non-zero lines (Go functions always have bodies
    // and are found by extract_file).
    let zero_line_hubs: Vec<_> = hubs
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64().unwrap_or(0) == 0)
        .collect();
    assert!(
        zero_line_hubs.is_empty(),
        "M-036: go hubs must not have line=0; offenders: {zero_line_hubs:#?}"
    );
}

// =============================================================================
// M-037: cognitive/halstead function-count parity
// =============================================================================

/// M-037 (C# overload case): `tldr cognitive` must not silently skip a
/// function whose name matches an already-seen function but is defined at a
/// different line (method overload). Both overloads must appear in the
/// cognitive output with their correct lines.
///
/// Pre-fix: `augment_cognitive_with_extractor_functions` deduped by name
/// only; the second overload was silently omitted.
/// Post-fix: dedup by (name, line) so both overloads are included.
#[test]
fn test_m037_cognitive_includes_overloaded_methods() {
    let dir = TempDir::new().unwrap();

    // Two overloads of `Process`: first takes `string`, second takes `int`.
    // Both have bodies so `get_function_body` returns Some for both.
    // Pre-fix: cognitive finds the first via AST walk and skips the second
    // in the augment step because name "Process" is already in `existing`.
    fs::write(
        dir.path().join("Widget.cs"),
        r#"
using System;

public class Widget
{
    public string Process(string input)
    {
        if (input == null)
            return string.Empty;
        return input.Trim();
    }

    public string Process(int value)
    {
        if (value < 0)
            return "negative";
        return value.ToString();
    }

    public void Reset()
    {
        Console.WriteLine("reset");
    }
}
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "cognitive",
        dir.path().join("Widget.cs").to_str().unwrap(),
        "--lang",
        "csharp",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "cognitive should succeed on csharp file");

    let v: Value = serde_json::from_str(&stdout).expect("cognitive should emit valid JSON");
    let functions = v["functions"].as_array().expect("functions array present");

    // We expect both Process overloads + Reset = 3 total.
    // Pre-fix: only 2 (one Process + Reset).
    assert_eq!(
        functions.len(),
        3,
        "M-037: cognitive must report both Process overloads + Reset (expected 3, got {}); functions: {:#?}",
        functions.len(),
        functions
    );

    // Both overloads of Process must be present.
    let process_entries: Vec<_> = functions
        .iter()
        .filter(|f| f["name"].as_str() == Some("Process"))
        .collect();
    assert_eq!(
        process_entries.len(),
        2,
        "M-037: both overloads of Process must appear in cognitive output; got: {process_entries:#?}"
    );

    // The two Process entries must have distinct lines.
    let lines: std::collections::HashSet<u64> = process_entries
        .iter()
        .map(|f| f["line"].as_u64().unwrap_or(0))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "M-037: the two Process overloads must have distinct line numbers; got: {lines:?}"
    );
}

/// M-037 (Java constructor case): `tldr halstead` and `tldr cognitive` must
/// agree on the total function count for a Java file that has a constructor.
///
/// Pre-fix: halstead missed Java constructors (not in `extract_file` output);
/// cognitive found them via the AST walk. Count differed by 1.
/// Post-fix: halstead does a supplementary AST walk for node kinds in
/// `get_function_node_kinds(Java)` to pick up constructors.
#[test]
fn test_m037_halstead_includes_java_constructor() {
    let dir = TempDir::new().unwrap();

    // Java class with a constructor + two regular methods.
    fs::write(
        dir.path().join("Service.java"),
        r#"
public class Service {
    private final String name;

    public Service(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public String greet() {
        return "Hello from " + this.name;
    }
}
"#,
    )
    .unwrap();

    let path = dir.path().join("Service.java");
    let path_str = path.to_str().unwrap();

    let (code_cog, stdout_cog, _) = run_tldr(&["cognitive", path_str, "--format", "json"]);
    assert_eq!(code_cog, 0, "cognitive should succeed");
    let cog: Value = serde_json::from_str(&stdout_cog).expect("cognitive: valid JSON");

    let (code_hal, stdout_hal, _) = run_tldr(&["halstead", path_str, "--format", "json"]);
    assert_eq!(code_hal, 0, "halstead should succeed");
    let hal: Value = serde_json::from_str(&stdout_hal).expect("halstead: valid JSON");

    let cog_count = cog["summary"]["total_functions"]
        .as_u64()
        .expect("cognitive total_functions") as usize;
    let hal_count = hal["summary"]["total_functions"]
        .as_u64()
        .expect("halstead total_functions") as usize;

    // Both must find the constructor + 2 methods = 3.
    assert_eq!(
        cog_count, 3,
        "M-037: cognitive should find constructor + 2 methods = 3; got {cog_count}"
    );
    assert_eq!(
        hal_count,
        cog_count,
        "M-037: halstead must match cognitive function count ({cog_count}); got {hal_count}. \
         Java constructor missing from halstead (fix: supplementary AST walk in analyze_halstead)."
    );

    // Specifically the constructor must appear in halstead output.
    let hal_funcs = hal["functions"].as_array().expect("halstead functions");
    let has_constructor = hal_funcs
        .iter()
        .any(|f| f["name"].as_str() == Some("Service"));
    assert!(
        has_constructor,
        "M-037: halstead must include the Java constructor 'Service'; functions: {hal_funcs:#?}"
    );
}

/// M-037 regression guard: `tldr cognitive` and `tldr halstead` must return
/// the same total function count on a simple Python file (no overloads /
/// constructors). Ensures fixes don't regress Python parity.
#[test]
fn test_m037_cognitive_halstead_parity_python() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("calc.py"),
        r#"
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b
"#,
    )
    .unwrap();

    let path = dir.path().join("calc.py");
    let path_str = path.to_str().unwrap();

    let (_, stdout_cog, _) = run_tldr(&["cognitive", path_str, "--format", "json"]);
    let (_, stdout_hal, _) = run_tldr(&["halstead", path_str, "--format", "json"]);

    let cog: Value = serde_json::from_str(&stdout_cog).expect("cognitive: valid JSON");
    let hal: Value = serde_json::from_str(&stdout_hal).expect("halstead: valid JSON");

    let cog_count = cog["summary"]["total_functions"]
        .as_u64()
        .expect("cognitive total_functions");
    let hal_count = hal["summary"]["total_functions"]
        .as_u64()
        .expect("halstead total_functions");

    assert_eq!(
        cog_count, 3,
        "cognitive should find 3 Python functions; got {cog_count}"
    );
    assert_eq!(
        hal_count, cog_count,
        "M-037 parity regression: halstead ({hal_count}) must match cognitive ({cog_count}) for Python"
    );
}
