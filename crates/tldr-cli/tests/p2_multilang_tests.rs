//! P2: Multi-Language Extension Tests (TDD Red Phase)
//!
//! These tests drive the implementation of 5 commands across all 18 languages.
//! This file covers the resources/contracts subset below; none of the tests
//! here carry `#[ignore]` — they run and assert against the real `tldr` binary.
// why: the doc claimed every test was `#[ignore]`-gated TDD-red-phase, but no
// test in this file carries that attribute — the comment was stale relative
// to the code (contradicted it), which misleads a reader about whether these
// tests actually run in CI.
//!
//! Commands covered:
//! - gvn: 18 languages (redundant expression detection)
//! - bounds: 18 languages (loop bound analysis)
//! - resources: 5 missing languages (Kotlin, Swift, OCaml, Lua, Luau)
//! - contracts: 3 missing languages (Kotlin, Swift, Luau)
//! - behavioral: 1 missing language (Swift)
//!
//! Reference: migration/p2-multilang-spec.md

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Get the test binary
fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Helper to create a test file in a temp directory
fn create_test_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

// =============================================================================
// Resources Multi-Language Tests (5 MISSING languages only)
//
// Each test creates a source file with a resource that is opened but not
// closed, runs `tldr resources`, and asserts that a leak is detected.
// =============================================================================

mod resources_multilang {
    use super::*;

    #[test]
    fn test_resources_kotlin() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.kt",
            r#"
fun leakyFunction(path: String): String {
    val reader = java.io.BufferedReader(java.io.FileReader(path))
    val content = reader.readLine()
    // reader is never closed - resource leak
    return content
}
"#,
        );
        let output = tldr_cmd()
            .args([
                "resources",
                file.to_str().unwrap(),
                "leakyFunction",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        // May exit with code 3 if issues found
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("leak") || json.to_string().contains("resource"),
            "Kotlin resources should detect unclosed BufferedReader leak"
        );
    }

    /// Swift now uses tree-sitter AST (ABI v15 confirmed working in P0)
    #[test]
    fn test_resources_swift() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.swift",
            r#"
func leakyFunction(path: String) -> String {
    let handle = FileHandle(forReadingAtPath: path)!
    let data = handle.readDataToEndOfFile()
    // handle is never closed - resource leak
    return String(data: data, encoding: .utf8)!
}
"#,
        );
        let output = tldr_cmd()
            .args([
                "resources",
                file.to_str().unwrap(),
                "leakyFunction",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("leak") || json.to_string().contains("resource"),
            "Swift resources (regex fallback) should detect unclosed FileHandle leak"
        );
    }

    #[test]
    fn test_resources_ocaml() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.ml",
            r#"
let leaky_function path =
  let ic = open_in path in
  let line = input_line ic in
  (* ic is never closed - resource leak *)
  line
"#,
        );
        let output = tldr_cmd()
            .args([
                "resources",
                file.to_str().unwrap(),
                "leaky_function",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("leak") || json.to_string().contains("resource"),
            "OCaml resources should detect unclosed open_in leak"
        );
    }

    #[test]
    fn test_resources_lua() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.lua",
            r#"
function leaky_function(path)
    local f = io.open(path, "r")
    local content = f:read("*a")
    -- f is never closed - resource leak
    return content
end
"#,
        );
        let output = tldr_cmd()
            .args([
                "resources",
                file.to_str().unwrap(),
                "leaky_function",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("leak") || json.to_string().contains("resource"),
            "Lua resources should detect unclosed io.open leak"
        );
    }

    #[test]
    fn test_resources_luau() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.luau",
            r#"
local function leaky_function(path: string): string
    local f = io.open(path, "r")
    local content = f:read("*a")
    -- f is never closed - resource leak
    return content
end
"#,
        );
        let output = tldr_cmd()
            .args([
                "resources",
                file.to_str().unwrap(),
                "leaky_function",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("leak") || json.to_string().contains("resource"),
            "Luau resources should detect unclosed io.open leak"
        );
    }
}

// =============================================================================
// Contracts Multi-Language Tests (3 MISSING languages only)
//
// Each test creates a source file with a function that has a precondition
// check (guard clause or assertion), runs `tldr contracts`, and asserts
// that a precondition is detected.
// =============================================================================

mod contracts_multilang {
    use super::*;

    #[test]
    fn test_contracts_kotlin() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.kt",
            r#"
fun processData(x: Int, data: List<Int>): Int {
    require(x >= 0) { "x must be non-negative" }
    check(data.isNotEmpty()) { "data cannot be empty" }
    return data.sum() + x
}
"#,
        );
        let output = tldr_cmd()
            .args([
                "contracts",
                file.to_str().unwrap(),
                "processData",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("precondition") || json.to_string().contains("require"),
            "Kotlin contracts should detect require() and check() preconditions"
        );
    }

    /// Swift uses AST-based analysis via tree-sitter-swift 0.7.1
    #[test]
    fn test_contracts_swift() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.swift",
            r#"
func processData(x: Int, data: [Int]) -> Int {
    precondition(x >= 0, "x must be non-negative")
    guard !data.isEmpty else {
        fatalError("data cannot be empty")
    }
    return data.reduce(0, +) + x
}
"#,
        );
        let output = tldr_cmd()
            .args([
                "contracts",
                file.to_str().unwrap(),
                "processData",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("precondition") || json.to_string().contains("guard"),
            "Swift contracts (regex fallback) should detect precondition() and guard clauses"
        );
    }

    #[test]
    fn test_contracts_luau() {
        let temp = TempDir::new().unwrap();
        let file = create_test_file(
            &temp,
            "test.luau",
            r#"
local function processData(x: number, data: {number}): number
    assert(x >= 0, "x must be non-negative")
    if #data == 0 then
        error("data cannot be empty")
    end
    local sum = 0
    for _, v in ipairs(data) do
        sum = sum + v
    end
    return sum + x
end
"#,
        );
        let output = tldr_cmd()
            .args([
                "contracts",
                file.to_str().unwrap(),
                "processData",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(
            json.to_string().contains("precondition") || json.to_string().contains("assert"),
            "Luau contracts should detect assert() and error() guard preconditions"
        );
    }
}

