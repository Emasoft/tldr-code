//! cluster-misc-v2: Three mechanical gap fixes.
//!
//! # CLUSTER-M-029 — Temporal/specs/invariants placeholder fields
//!
//! Pre-fix:
//! - `tldr specs --from-tests <elixir>` emits `test_function:"test"` (macro
//!   keyword) instead of the actual test name extracted from the first string
//!   argument of `test "name" do`.
//! - `test_count` is always 0 on every `FunctionSpecs` entry regardless of
//!   how many distinct test functions exercised the function under test.
//! - Ruby Minitest: `def test_*` methods inside a class inside `test/*.rb`
//!   are not counted when the file stem doesn't start with `test_` or end
//!   with `_test`.
//!
//! Post-fix:
//! - Elixir `test_function` carries the string literal from the first macro
//!   arg (e.g. `"applies mfa"` → `"applies mfa"`).
//! - `test_count` equals the number of distinct test functions that
//!   contributed at least one spec for the function under test.
//! - Ruby Minitest files inside a `test/` directory component are recognised
//!   as test files even when the file stem doesn't match `test_*`/`_test`.
//!
//! # CLUSTER-M-020 — `explain.callers/callees` missing `column` field
//!
//! Pre-fix: callers/callees JSON objects lack a `column` field.
//! Post-fix: each entry carries a `column` field (0-indexed).
//!
//! # CLUSTER-M-043 — Loc misclassifies HTML as JavaScript / silently drops HTML
//!
//! Pre-fix: `.html` files are silently dropped (not counted at all) by `tldr loc`.
//! Post-fix: `.html`/`.htm` files appear under a `"html"` key in `by_language`.

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
// M-029: Elixir specs — test_function carries actual test name
// =============================================================================

/// specs --from-tests on an Elixir ExUnit file must:
/// 1. Scan and count the `test "..." do` blocks correctly (not zero).
/// 2. When specs ARE extracted, the `test_function` field must NOT be the bare
///    macro keyword "test" but the actual test name string.
///
/// Pre-fix: `test_function` was `"test"` (the macro keyword) because
/// `test_function_display_name` found the `identifier` child of the `call`
/// node, which is the macro target `test`, not the test title string argument.
#[test]
fn test_elixir_specs_test_function_name_not_keyword() {
    let dir = TempDir::new().unwrap();

    // Use assert == on a named function call so the generic extractor can
    // produce a property spec and populate test_function.
    fs::write(
        dir.path().join("my_module_test.exs"),
        r#"defmodule MyModuleTest do
  use ExUnit.Case

  test "adds two numbers" do
    assert add(1, 2) == 3
  end

  test "handles zero" do
    assert add(0, 0) == 0
  end
end
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "specs",
        "--from-tests",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(code, 0, "specs command failed");
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");

    // test_functions_scanned must be 2 (two test "..." do blocks).
    let scanned = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(scanned, 2, "expected 2 ExUnit test functions scanned, got {}", scanned);

    // For any specs extracted, test_function must NOT be the bare keyword "test".
    let empty = vec![];
    let functions = v["functions"].as_array().unwrap_or(&empty);
    for func in functions {
        for spec_list_key in &["property_specs", "input_output_specs", "exception_specs"] {
            let empty2 = vec![];
            for spec in func[spec_list_key].as_array().unwrap_or(&empty2) {
                let tf = spec["test_function"].as_str().unwrap_or("");
                assert_ne!(
                    tf, "test",
                    "test_function must not be bare keyword 'test'; got {:?} for function {}",
                    tf,
                    func["function_name"].as_str().unwrap_or("?")
                );
                // After fix: must be the actual test name string, not empty.
                assert!(
                    !tf.is_empty(),
                    "test_function must not be empty"
                );
            }
        }
    }
}

// =============================================================================
// M-029: test_count populated by distinct test functions
// =============================================================================

/// test_count on FunctionSpecs must be >= 1 when at least one test function
/// exercised the function under test.
#[test]
fn test_specs_test_count_nonzero_when_tests_exist() {
    let dir = TempDir::new().unwrap();

    // Write a Python test file exercising `add(...)` from two different
    // test functions.
    fs::write(
        dir.path().join("test_add.py"),
        r#"def test_add_basic():
    assert add(1, 2) == 3

def test_add_zero():
    assert add(0, 0) == 0
"#,
    )
    .unwrap();

    let (code, stdout, _) = run_tldr(&[
        "specs",
        "--from-tests",
        dir.path().join("test_add.py").to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");

    let empty = vec![];
    let functions = v["functions"].as_array().unwrap_or(&empty);
    // If `add` was found as function under test, its test_count must be >= 1.
    let add_entry = functions.iter().find(|f| f["function_name"] == "add");
    if let Some(entry) = add_entry {
        let tc = entry["test_count"].as_u64().unwrap_or(0);
        assert!(tc >= 1, "test_count for 'add' should be >= 1, got {}", tc);
    }
    // Guard: test_functions_scanned must be 2.
    let scanned = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(scanned, 2, "expected 2 test functions scanned");
}

// =============================================================================
// M-029: Ruby Minitest — files inside test/ directory are recognized
// =============================================================================

/// Minitest-style `def test_*` methods inside a `test/` directory component
/// must be counted even when the file stem doesn't start with `test_` or end
/// with `_test`/`_spec`.
///
/// Files named e.g. `helpers.rb` or `sanitizer.rb` inside `test/` should be
/// treated as test files because the directory component marks the entire
/// subtree as a test suite.
#[test]
fn test_ruby_minitest_test_dir_non_test_filename_recognized() {
    let dir = TempDir::new().unwrap();
    let test_dir = dir.path().join("test");
    fs::create_dir_all(&test_dir).unwrap();

    // Deliberately uses a filename that does NOT start with test_ or end with
    // _test/_spec, but IS inside a test/ directory.
    fs::write(
        test_dir.join("sanitizer.rb"),
        r#"require 'minitest/autorun'

class SanitizerTest < Minitest::Test
  def test_sanitize_basic
    assert_equal "hello", sanitize("hello")
  end

  def test_sanitize_strips_html
    assert_equal "bold", sanitize("<b>bold</b>")
  end
end
"#,
    )
    .unwrap();

    let (code, stdout, _) = run_tldr(&[
        "specs",
        "--from-tests",
        test_dir.join("sanitizer.rb").to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");

    // test_functions_scanned must be >= 2 (both def test_* methods counted).
    let scanned = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 2,
        "expected >= 2 test functions scanned from Ruby Minitest file in test/ dir, got {}",
        scanned
    );
}

// =============================================================================
// M-020: explain callers/callees carry column field
// =============================================================================

/// The `callers` and `callees` arrays in `tldr explain` output must contain
/// a `column` field on each entry.
#[test]
fn test_explain_callers_callees_have_column() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("mod.py"),
        r#"def helper(x):
    return x + 1

def caller_a():
    return helper(5)

def caller_b():
    return helper(10) + helper(20)
"#,
    )
    .unwrap();

    let (code, stdout, _) = run_tldr(&[
        "explain",
        dir.path().join("mod.py").to_str().unwrap(),
        "helper",
        "--format",
        "json",
    ]);

    assert_eq!(code, 0, "explain command failed");
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");

    // callers must have column field.
    let empty_callers = vec![];
    let callers = v["callers"].as_array().unwrap_or(&empty_callers);
    for caller in callers {
        assert!(
            caller.get("column").is_some(),
            "caller entry missing 'column' field: {:?}",
            caller
        );
    }

    // callees must have column field.
    let empty_callees = vec![];
    let callees = v["callees"].as_array().unwrap_or(&empty_callees);
    for callee in callees {
        assert!(
            callee.get("column").is_some(),
            "callee entry missing 'column' field: {:?}",
            callee
        );
    }
}

// =============================================================================
// M-043: loc counts .html files under "html" language category
// =============================================================================

/// `tldr loc` on a directory containing `.html` files must report them in a
/// `"html"` key inside `by_language`, not silently drop them.
#[test]
fn test_loc_html_files_counted_as_html() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("index.html"),
        "<!DOCTYPE html>\n<html><body><p>hello</p></body></html>\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("about.html"),
        "<!DOCTYPE html>\n<html><body><p>about</p></body></html>\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("main.py"),
        "def hello():\n    print('hello')\n",
    )
    .unwrap();

    let (code, stdout, _) = run_tldr(&[
        "loc",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(code, 0, "loc command failed");
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");

    let by_lang = &v["by_language"];

    // .html files must appear under "html", not "javascript".
    let html_files = by_lang["html"]["files"].as_u64().unwrap_or(0);
    let js_files_from_html_names = by_lang["javascript"]["files"].as_u64().unwrap_or(0);

    assert!(
        html_files >= 2,
        "expected >= 2 html files counted under 'html' language, got {}",
        html_files
    );

    // There are no actual .js files in this dir, so javascript count must be 0
    // (or absent), confirming html files are not being miscounted as js.
    assert_eq!(
        js_files_from_html_names, 0,
        "html files must not be counted as javascript, got {} js files",
        js_files_from_html_names
    );
}

/// `.htm` extension (alternate HTML extension) must also be counted as "html".
#[test]
fn test_loc_htm_extension_counted_as_html() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("page.htm"),
        "<html><body>page</body></html>\n",
    )
    .unwrap();

    let (code, stdout, _) = run_tldr(&[
        "loc",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");
    let html_files = v["by_language"]["html"]["files"].as_u64().unwrap_or(0);
    assert!(
        html_files >= 1,
        "expected >= 1 htm file counted under 'html' language, got {}",
        html_files
    );
}
