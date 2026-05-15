//! cluster-misc-v3b: Three mechanical gap fixes.
//!
//! # CLUSTER-M-038 — Hotspots disagrees with health.hotspot_count on non-git corpus
//!
//! Pre-fix: `tldr hotspots <non-git-dir>` exits with error "Not a git repository".
//! Post-fix: falls back to complexity-only ranking with a warning; returns exit
//! code 0 and a valid JSON report. `hotspot_count` > 0 when complex functions
//! are present.
//!
//! # CLUSTER-M-041 — Surface/context `kind` mislabel (Class vs Module/function/method)
//!
//! Pre-fix:
//! - Elixir `defmodule` is reported with `kind:"class"` and `example:"Mod/0"`.
//! - OCaml `module M = ...` is reported with `kind:"class"`.
//! - Ruby `module M` is reported with `kind:"class"`.
//!
//! Post-fix:
//! - All three emit `kind:"module"`.
//! - Elixir module example is just `"ModuleName"` (no `/0` arity suffix).
//!
//! # CLUSTER-M-047 — Smells category miscategorized as `long_method` when reason is complexity
//!
//! Pre-fix: both line-count and cyclomatic-threshold violations emit
//! `smell_type:"long_method"`.
//! Post-fix: cyclomatic-threshold violations emit `smell_type:"complex_method"`;
//! line-count violations still emit `smell_type:"long_method"`.

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
// M-038: Hotspots non-git fallback — complexity-only mode
// =============================================================================

/// A non-git directory must not produce an error exit from `tldr hotspots`.
/// It must return exit 0, valid JSON, and a warning about missing git history.
#[test]
fn test_hotspots_non_git_does_not_error() {
    let dir = TempDir::new().unwrap();

    // Write a Python file with a function that has CC > 1 (multiple branches)
    fs::write(
        dir.path().join("example.py"),
        r#"def complex_function(x):
    if x > 0:
        if x > 10:
            return "big"
        elif x > 5:
            return "medium"
        else:
            return "small"
    elif x == 0:
        return "zero"
    else:
        if x < -10:
            return "very negative"
        return "negative"

def simple(x):
    return x + 1
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "hotspots",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(
        code, 0,
        "hotspots on a non-git dir must exit 0; stderr: {}",
        stderr
    );

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from hotspots: {}; stdout: {}", e, stdout));

    // Must carry a warning about absent git history
    let warnings = v["warnings"].as_array().cloned().unwrap_or_default();
    let has_no_git_warning = warnings
        .iter()
        .any(|w| w.as_str().map(|s| s.contains("git")).unwrap_or(false));
    assert!(
        has_no_git_warning,
        "Expected a warning mentioning 'git' in non-git fallback mode; warnings: {:?}",
        warnings
    );

    // Report must contain the `hotspots` array (possibly empty if no files above threshold)
    assert!(
        v["hotspots"].is_array(),
        "Expected hotspots array in JSON output"
    );

    // commit_count must be 0 for every entry in fallback mode
    let empty = vec![];
    for entry in v["hotspots"].as_array().unwrap_or(&empty) {
        let cc = entry["commit_count"].as_u64().unwrap_or(999);
        assert_eq!(
            cc, 0,
            "Non-git hotspot entries must have commit_count=0; got {}",
            cc
        );
    }
}

/// When multiple files have different complexity, the non-git report orders
/// them by complexity (most complex first) and hotspot_score > 0.
#[test]
fn test_hotspots_non_git_sorted_by_complexity() {
    let dir = TempDir::new().unwrap();

    // High-complexity file
    fs::write(
        dir.path().join("high.py"),
        r#"def high(x):
    if x > 0:
        if x > 1:
            if x > 2:
                if x > 3:
                    if x > 4:
                        return 5
                    return 4
                return 3
            return 2
        return 1
    return 0
"#,
    )
    .unwrap();

    // Low-complexity file
    fs::write(dir.path().join("low.py"), "def simple(x):\n    return x\n").unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "hotspots",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "hotspots non-git must exit 0");

    let v: Value = serde_json::from_str(&stdout).expect("invalid JSON");
    let hotspots = v["hotspots"].as_array().cloned().unwrap_or_default();

    // Should have at least 1 entry (the high-complexity file)
    assert!(
        !hotspots.is_empty(),
        "Expected at least one hotspot entry in non-git mode"
    );

    // First entry (highest score) must have hotspot_score > 0
    let top_score = hotspots[0]["hotspot_score"].as_f64().unwrap_or(0.0);
    assert!(
        top_score > 0.0,
        "Top non-git hotspot must have hotspot_score > 0; got {}",
        top_score
    );
}

// =============================================================================
// M-041: Module kind classification — elixir, ocaml, ruby
// =============================================================================

/// Elixir `defmodule` must produce `kind:"module"`, not `kind:"class"`.
/// The example field must NOT contain a `/0` arity suffix.
#[test]
fn test_surface_elixir_defmodule_kind_is_module() {
    let dir = TempDir::new().unwrap();
    let lib_dir = dir.path().join("lib");
    fs::create_dir_all(&lib_dir).unwrap();

    fs::write(
        lib_dir.join("my_plug.ex"),
        r#"defmodule MyPlug do
  @moduledoc "A simple plug module."

  def call(conn, _opts) do
    conn
  end
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "surface",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "surface failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {}; stdout: {}", e, stdout));

    let empty = vec![];
    let apis = v["apis"].as_array().unwrap_or(&empty);

    // Find the module-level entry for MyPlug
    let module_entry = apis.iter().find(|e| {
        e["qualified_name"].as_str() == Some("MyPlug")
    });

    let module_entry = module_entry.unwrap_or_else(|| {
        panic!(
            "No entry with qualified_name 'MyPlug' found; apis: {:?}",
            apis
        )
    });

    let kind = module_entry["kind"].as_str().unwrap_or("");
    assert_eq!(
        kind, "Module",
        "Elixir defmodule must have kind='Module', got '{}'",
        kind
    );

    // Example must not end with "/0"
    let example = module_entry["example"].as_str().unwrap_or("");
    assert!(
        !example.ends_with("/0"),
        "Elixir module example must not have /0 arity suffix; got '{}'",
        example
    );
}

/// Ruby `module M` must produce `kind:"module"`, not `kind:"class"`.
#[test]
fn test_surface_ruby_module_kind_is_module() {
    let dir = TempDir::new().unwrap();
    let lib_dir = dir.path().join("lib");
    fs::create_dir_all(&lib_dir).unwrap();

    fs::write(
        lib_dir.join("my_module.rb"),
        r#"module MyModule
  def self.hello
    "hello"
  end

  class Inner
    def greet
      "hi"
    end
  end
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "surface",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "surface failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {}; stdout: {}", e, stdout));

    let empty = vec![];
    let apis = v["apis"].as_array().unwrap_or(&empty);

    // Find the entry for MyModule (the module-level container). The qualified
    // name may be prefixed with a temp-dir segment, so match on ends_with.
    let module_entry = apis.iter().find(|e| {
        e["qualified_name"]
            .as_str()
            .map(|n| {
                // Ends with .MyModule or IS MyModule, AND not a method (no trailing .hello etc.)
                let after_dot = n.rsplit('.').next().unwrap_or(n);
                after_dot == "MyModule" && e["kind"].as_str() != Some("ClassMethod")
            })
            .unwrap_or(false)
    });

    let module_entry = module_entry.unwrap_or_else(|| {
        panic!(
            "No MyModule container entry found; apis: {:?}",
            apis
        )
    });

    let kind = module_entry["kind"].as_str().unwrap_or("");
    assert_eq!(
        kind, "Module",
        "Ruby module must have kind='Module', got '{}'",
        kind
    );
}

/// OCaml `module M = ...` must produce `kind:"module"`, not `kind:"class"`.
#[test]
fn test_surface_ocaml_module_definition_kind_is_module() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("mylib.ml"),
        r#"let add x y = x + y

module Utils = struct
  let double x = x * 2
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "surface",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "surface failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {}; stdout: {}", e, stdout));

    let empty = vec![];
    let apis = v["apis"].as_array().unwrap_or(&empty);

    // Find the module-level entry for Utils
    let module_entry = apis.iter().find(|e| {
        e["qualified_name"]
            .as_str()
            .map(|n| n.ends_with(".Utils") || n == "Utils")
            .unwrap_or(false)
    });

    let module_entry = module_entry.unwrap_or_else(|| {
        panic!(
            "No 'Utils' module entry found; apis: {:?}",
            apis
        )
    });

    let kind = module_entry["kind"].as_str().unwrap_or("");
    assert_eq!(
        kind, "Module",
        "OCaml module definition must have kind='Module', got '{}'",
        kind
    );
}

// =============================================================================
// M-047: ComplexMethod smell type when cyclomatic threshold fires
// =============================================================================

/// When a function exceeds the *cyclomatic* threshold but NOT the LOC threshold,
/// the smell must be reported as `smell_type:"complex_method"`, not `long_method`.
#[test]
fn test_smells_cyclomatic_threshold_emits_complex_method() {
    let dir = TempDir::new().unwrap();

    // A function with many branches (CC >> 10) but few lines (not a long method).
    // Each `if/elif` adds 1 to cyclomatic complexity.
    fs::write(
        dir.path().join("branchy.py"),
        r#"def very_branchy(x):
    if x == 1: return "one"
    elif x == 2: return "two"
    elif x == 3: return "three"
    elif x == 4: return "four"
    elif x == 5: return "five"
    elif x == 6: return "six"
    elif x == 7: return "seven"
    elif x == 8: return "eight"
    elif x == 9: return "nine"
    elif x == 10: return "ten"
    elif x == 11: return "eleven"
    else: return "other"
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "smells",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "smells failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {}; stdout: {}", e, stdout));

    let empty = vec![];
    let smells = v["smells"].as_array().unwrap_or(&empty);

    // There must be at least one smell for the branchy function
    let branchy_smells: Vec<_> = smells
        .iter()
        .filter(|s| s["name"].as_str() == Some("very_branchy"))
        .collect();

    assert!(
        !branchy_smells.is_empty(),
        "Expected at least one smell for very_branchy; all smells: {:?}",
        smells
    );

    // Among the smells for very_branchy, at least one must be complex_method
    let has_complex_method = branchy_smells
        .iter()
        .any(|s| s["smell_type"].as_str() == Some("complex_method"));

    assert!(
        has_complex_method,
        "Expected a complex_method smell for very_branchy (cyclomatic >10); got: {:?}",
        branchy_smells
    );

    // Must NOT have a long_method smell for very_branchy (it's not long in LOC)
    let has_long_method = branchy_smells
        .iter()
        .any(|s| s["smell_type"].as_str() == Some("long_method"));

    assert!(
        !has_long_method,
        "very_branchy must NOT be reported as long_method (it's short in LOC); got: {:?}",
        branchy_smells
    );
}

/// A function that exceeds the *LOC* threshold must still emit `long_method`.
#[test]
fn test_smells_loc_threshold_still_emits_long_method() {
    let dir = TempDir::new().unwrap();

    // Build a function with > 50 lines but simple logic (CC stays low)
    let mut body = String::from("def long_but_simple():\n");
    for i in 0..55 {
        body.push_str(&format!("    x_{} = {}\n", i, i));
    }
    body.push_str("    return x_0\n");

    fs::write(dir.path().join("long.py"), &body).unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "smells",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "smells failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {}; stdout: {}", e, stdout));

    let empty = vec![];
    let smells = v["smells"].as_array().unwrap_or(&empty);

    let has_long_method = smells
        .iter()
        .any(|s| s["smell_type"].as_str() == Some("long_method"));

    assert!(
        has_long_method,
        "Expected a long_method smell for a 55-line function; smells: {:?}",
        smells
    );
}
