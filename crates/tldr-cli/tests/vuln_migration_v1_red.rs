//! VULN-MIGRATION-V1 M1 — RED tests for 33+ (lang, vuln_type) pairs from plan §4.2.
//!
//! Each pair has 2 tests:
//!   - <lang>_<vuln_type>_positive: assert ≥1 finding of expected vuln_type
//!   - <lang>_<vuln_type>_string_literal_fp: assert ZERO findings
//!     (source/sink patterns appear ONLY inside string literals or comments)
//!
//! At HEAD (pre-M3 substring scanner active):
//!   - positive tests pass (substring scanner matches them)
//!   - string-literal regression tests FAIL on the 14 fall-through langs
//!     (FP class active — the closes-#24 root pattern at the file scale)
//!   - Python path is FP-clean today via tree-sitter analyze_python_file
//!
//! Helper: `run_tldr_vuln(fixture_path, lang_arg) -> serde_json::Value` invokes
//! the binary via assert_cmd cargo_bin.

use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vuln_migration_v1")
        .join(rel)
}

/// Run `tldr vuln <fixture> --lang <lang> --format json --quiet` and parse JSON.
fn run_tldr_vuln(rel_fixture: &str, lang: &str) -> Value {
    let path = fixture_path(rel_fixture);
    assert!(path.exists(), "fixture missing: {}", path.display());

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("vuln")
        .arg(&path)
        .arg("--lang")
        .arg(lang)
        .arg("--format")
        .arg("json")
        .arg("--quiet");

    let output = cmd.output().expect("failed to execute tldr vuln");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse `tldr vuln --lang {} --format json` JSON output: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            lang,
            e,
            stdout,
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn findings_of_type<'a>(report: &'a Value, vt_wire: &str) -> Vec<&'a Value> {
    report
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("vuln_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s == vt_wire)
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn all_findings(report: &Value) -> Vec<Value> {
    report
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

#[test]
fn c_sql_injection_positive() {
    let report = run_tldr_vuln("c/sql_injection_positive.c", "c");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture c/sql_injection_positive.c (lang=c); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn c_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("c/sql_injection_string_literal_fp.c", "c");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture c/sql_injection_string_literal_fp.c (lang=c); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_sql_injection_positive() {
    let report = run_tldr_vuln("cpp/sql_injection_positive.cpp", "cpp");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture cpp/sql_injection_positive.cpp (lang=cpp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("cpp/sql_injection_string_literal_fp.cpp", "cpp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture cpp/sql_injection_string_literal_fp.cpp (lang=cpp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_sql_injection_positive() {
    let report = run_tldr_vuln("csharp/sql_injection_positive.cs", "csharp");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture csharp/sql_injection_positive.cs (lang=csharp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("csharp/sql_injection_string_literal_fp.cs", "csharp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture csharp/sql_injection_string_literal_fp.cs (lang=csharp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_sql_injection_positive() {
    let report = run_tldr_vuln("elixir/sql_injection_positive.ex", "elixir");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture elixir/sql_injection_positive.ex (lang=elixir); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("elixir/sql_injection_string_literal_fp.ex", "elixir");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture elixir/sql_injection_string_literal_fp.ex (lang=elixir); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_sql_injection_positive() {
    let report = run_tldr_vuln("go/sql_injection_positive.go", "go");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture go/sql_injection_positive.go (lang=go); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("go/sql_injection_string_literal_fp.go", "go");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture go/sql_injection_string_literal_fp.go (lang=go); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_sql_injection_positive() {
    let report = run_tldr_vuln("java/sql_injection_positive.java", "java");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture java/sql_injection_positive.java (lang=java); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("java/sql_injection_string_literal_fp.java", "java");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture java/sql_injection_string_literal_fp.java (lang=java); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_sql_injection_positive() {
    let report = run_tldr_vuln("javascript/sql_injection_positive.js", "javascript");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture javascript/sql_injection_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln(
        "javascript/sql_injection_string_literal_fp.js",
        "javascript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/sql_injection_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_sql_injection_positive() {
    let report = run_tldr_vuln("kotlin/sql_injection_positive.kt", "kotlin");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture kotlin/sql_injection_positive.kt (lang=kotlin); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("kotlin/sql_injection_string_literal_fp.kt", "kotlin");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture kotlin/sql_injection_string_literal_fp.kt (lang=kotlin); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_sql_injection_positive() {
    let report = run_tldr_vuln("lua/sql_injection_positive.lua", "lua");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture lua/sql_injection_positive.lua (lang=lua); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("lua/sql_injection_string_literal_fp.lua", "lua");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture lua/sql_injection_string_literal_fp.lua (lang=lua); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_sql_injection_positive() {
    let report = run_tldr_vuln("luau/sql_injection_positive.luau", "luau");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture luau/sql_injection_positive.luau (lang=luau); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("luau/sql_injection_string_literal_fp.luau", "luau");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture luau/sql_injection_string_literal_fp.luau (lang=luau); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_sql_injection_positive() {
    let report = run_tldr_vuln("ocaml/sql_injection_positive.ml", "ocaml");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture ocaml/sql_injection_positive.ml (lang=ocaml); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("ocaml/sql_injection_string_literal_fp.ml", "ocaml");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ocaml/sql_injection_string_literal_fp.ml (lang=ocaml); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_sql_injection_positive() {
    let report = run_tldr_vuln("php/sql_injection_positive.php", "php");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture php/sql_injection_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("php/sql_injection_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/sql_injection_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_sql_injection_positive() {
    let report = run_tldr_vuln("python/sql_injection_positive.py", "python");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture python/sql_injection_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("python/sql_injection_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/sql_injection_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_sql_injection_positive() {
    let report = run_tldr_vuln("ruby/sql_injection_positive.rb", "ruby");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture ruby/sql_injection_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("ruby/sql_injection_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/sql_injection_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_sql_injection_positive() {
    let report = run_tldr_vuln("scala/sql_injection_positive.scala", "scala");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture scala/sql_injection_positive.scala (lang=scala); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("scala/sql_injection_string_literal_fp.scala", "scala");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture scala/sql_injection_string_literal_fp.scala (lang=scala); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_sql_injection_positive() {
    let report = run_tldr_vuln("swift/sql_injection_positive.swift", "swift");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture swift/sql_injection_positive.swift (lang=swift); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln("swift/sql_injection_string_literal_fp.swift", "swift");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture swift/sql_injection_string_literal_fp.swift (lang=swift); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_sql_injection_positive() {
    let report = run_tldr_vuln("typescript/sql_injection_positive.ts", "typescript");
    let f = findings_of_type(&report, "sql_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 sql_injection finding for fixture typescript/sql_injection_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_sql_injection_string_literal_fp() {
    let report = run_tldr_vuln(
        "typescript/sql_injection_string_literal_fp.ts",
        "typescript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/sql_injection_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_xss_positive() {
    let report = run_tldr_vuln("csharp/xss_positive.cs", "csharp");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture csharp/xss_positive.cs (lang=csharp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_xss_string_literal_fp() {
    let report = run_tldr_vuln("csharp/xss_string_literal_fp.cs", "csharp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture csharp/xss_string_literal_fp.cs (lang=csharp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_xss_positive() {
    let report = run_tldr_vuln("elixir/xss_positive.ex", "elixir");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture elixir/xss_positive.ex (lang=elixir); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_xss_string_literal_fp() {
    let report = run_tldr_vuln("elixir/xss_string_literal_fp.ex", "elixir");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture elixir/xss_string_literal_fp.ex (lang=elixir); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_xss_positive() {
    let report = run_tldr_vuln("javascript/xss_positive.js", "javascript");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture javascript/xss_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_xss_string_literal_fp() {
    let report = run_tldr_vuln("javascript/xss_string_literal_fp.js", "javascript");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/xss_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_xss_positive() {
    let report = run_tldr_vuln("lua/xss_positive.lua", "lua");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture lua/xss_positive.lua (lang=lua); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_xss_string_literal_fp() {
    let report = run_tldr_vuln("lua/xss_string_literal_fp.lua", "lua");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture lua/xss_string_literal_fp.lua (lang=lua); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_xss_positive() {
    let report = run_tldr_vuln("luau/xss_positive.luau", "luau");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture luau/xss_positive.luau (lang=luau); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_xss_string_literal_fp() {
    let report = run_tldr_vuln("luau/xss_string_literal_fp.luau", "luau");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture luau/xss_string_literal_fp.luau (lang=luau); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_xss_positive() {
    let report = run_tldr_vuln("php/xss_positive.php", "php");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture php/xss_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_xss_string_literal_fp() {
    let report = run_tldr_vuln("php/xss_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/xss_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_xss_positive() {
    let report = run_tldr_vuln("python/xss_positive.py", "python");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture python/xss_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_xss_string_literal_fp() {
    let report = run_tldr_vuln("python/xss_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/xss_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_xss_positive() {
    let report = run_tldr_vuln("ruby/xss_positive.rb", "ruby");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture ruby/xss_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_xss_string_literal_fp() {
    let report = run_tldr_vuln("ruby/xss_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/xss_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_xss_positive() {
    let report = run_tldr_vuln("typescript/xss_positive.ts", "typescript");
    let f = findings_of_type(&report, "xss");
    assert!(
        !f.is_empty(),
        "expected ≥1 xss finding for fixture typescript/xss_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_xss_string_literal_fp() {
    let report = run_tldr_vuln("typescript/xss_string_literal_fp.ts", "typescript");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/xss_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn c_command_injection_positive() {
    let report = run_tldr_vuln("c/command_injection_positive.c", "c");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture c/command_injection_positive.c (lang=c); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn c_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("c/command_injection_string_literal_fp.c", "c");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture c/command_injection_string_literal_fp.c (lang=c); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_command_injection_positive() {
    let report = run_tldr_vuln("cpp/command_injection_positive.cpp", "cpp");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture cpp/command_injection_positive.cpp (lang=cpp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("cpp/command_injection_string_literal_fp.cpp", "cpp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture cpp/command_injection_string_literal_fp.cpp (lang=cpp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_command_injection_positive() {
    let report = run_tldr_vuln("csharp/command_injection_positive.cs", "csharp");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture csharp/command_injection_positive.cs (lang=csharp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("csharp/command_injection_string_literal_fp.cs", "csharp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture csharp/command_injection_string_literal_fp.cs (lang=csharp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_command_injection_positive() {
    let report = run_tldr_vuln("elixir/command_injection_positive.ex", "elixir");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture elixir/command_injection_positive.ex (lang=elixir); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("elixir/command_injection_string_literal_fp.ex", "elixir");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture elixir/command_injection_string_literal_fp.ex (lang=elixir); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_command_injection_positive() {
    let report = run_tldr_vuln("go/command_injection_positive.go", "go");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture go/command_injection_positive.go (lang=go); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("go/command_injection_string_literal_fp.go", "go");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture go/command_injection_string_literal_fp.go (lang=go); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_command_injection_positive() {
    let report = run_tldr_vuln("java/command_injection_positive.java", "java");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture java/command_injection_positive.java (lang=java); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("java/command_injection_string_literal_fp.java", "java");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture java/command_injection_string_literal_fp.java (lang=java); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_command_injection_positive() {
    let report = run_tldr_vuln("javascript/command_injection_positive.js", "javascript");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture javascript/command_injection_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_command_injection_string_literal_fp() {
    let report = run_tldr_vuln(
        "javascript/command_injection_string_literal_fp.js",
        "javascript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/command_injection_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_command_injection_positive() {
    let report = run_tldr_vuln("kotlin/command_injection_positive.kt", "kotlin");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture kotlin/command_injection_positive.kt (lang=kotlin); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("kotlin/command_injection_string_literal_fp.kt", "kotlin");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture kotlin/command_injection_string_literal_fp.kt (lang=kotlin); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_command_injection_positive() {
    let report = run_tldr_vuln("lua/command_injection_positive.lua", "lua");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture lua/command_injection_positive.lua (lang=lua); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("lua/command_injection_string_literal_fp.lua", "lua");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture lua/command_injection_string_literal_fp.lua (lang=lua); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_command_injection_positive() {
    let report = run_tldr_vuln("luau/command_injection_positive.luau", "luau");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture luau/command_injection_positive.luau (lang=luau); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("luau/command_injection_string_literal_fp.luau", "luau");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture luau/command_injection_string_literal_fp.luau (lang=luau); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_command_injection_positive() {
    let report = run_tldr_vuln("ocaml/command_injection_positive.ml", "ocaml");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture ocaml/command_injection_positive.ml (lang=ocaml); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("ocaml/command_injection_string_literal_fp.ml", "ocaml");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ocaml/command_injection_string_literal_fp.ml (lang=ocaml); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_command_injection_positive() {
    let report = run_tldr_vuln("php/command_injection_positive.php", "php");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture php/command_injection_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("php/command_injection_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/command_injection_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_command_injection_positive() {
    let report = run_tldr_vuln("python/command_injection_positive.py", "python");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture python/command_injection_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("python/command_injection_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/command_injection_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_command_injection_positive() {
    let report = run_tldr_vuln("ruby/command_injection_positive.rb", "ruby");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture ruby/command_injection_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("ruby/command_injection_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/command_injection_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_command_injection_percent_x_positive() {
    let report = run_tldr_vuln("ruby/command_injection_percent_x_positive.rb", "ruby");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture ruby/command_injection_percent_x_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_command_injection_percent_x_string_literal_fp() {
    let report = run_tldr_vuln(
        "ruby/command_injection_percent_x_string_literal_fp.rb",
        "ruby",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/command_injection_percent_x_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_command_injection_positive() {
    let report = run_tldr_vuln("rust/command_injection_positive.rs", "rust");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture rust/command_injection_positive.rs (lang=rust); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("rust/command_injection_string_literal_fp.rs", "rust");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture rust/command_injection_string_literal_fp.rs (lang=rust); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_command_injection_positive() {
    let report = run_tldr_vuln("scala/command_injection_positive.scala", "scala");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture scala/command_injection_positive.scala (lang=scala); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("scala/command_injection_string_literal_fp.scala", "scala");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture scala/command_injection_string_literal_fp.scala (lang=scala); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_command_injection_positive() {
    let report = run_tldr_vuln("swift/command_injection_positive.swift", "swift");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture swift/command_injection_positive.swift (lang=swift); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_command_injection_string_literal_fp() {
    let report = run_tldr_vuln("swift/command_injection_string_literal_fp.swift", "swift");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture swift/command_injection_string_literal_fp.swift (lang=swift); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_command_injection_positive() {
    let report = run_tldr_vuln("typescript/command_injection_positive.ts", "typescript");
    let f = findings_of_type(&report, "command_injection");
    assert!(
        !f.is_empty(),
        "expected ≥1 command_injection finding for fixture typescript/command_injection_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_command_injection_string_literal_fp() {
    let report = run_tldr_vuln(
        "typescript/command_injection_string_literal_fp.ts",
        "typescript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/command_injection_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn c_path_traversal_positive() {
    let report = run_tldr_vuln("c/path_traversal_positive.c", "c");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture c/path_traversal_positive.c (lang=c); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn c_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("c/path_traversal_string_literal_fp.c", "c");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture c/path_traversal_string_literal_fp.c (lang=c); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_path_traversal_positive() {
    let report = run_tldr_vuln("cpp/path_traversal_positive.cpp", "cpp");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture cpp/path_traversal_positive.cpp (lang=cpp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("cpp/path_traversal_string_literal_fp.cpp", "cpp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture cpp/path_traversal_string_literal_fp.cpp (lang=cpp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_path_traversal_positive() {
    let report = run_tldr_vuln("csharp/path_traversal_positive.cs", "csharp");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture csharp/path_traversal_positive.cs (lang=csharp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("csharp/path_traversal_string_literal_fp.cs", "csharp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture csharp/path_traversal_string_literal_fp.cs (lang=csharp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_path_traversal_positive() {
    let report = run_tldr_vuln("elixir/path_traversal_positive.ex", "elixir");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture elixir/path_traversal_positive.ex (lang=elixir); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("elixir/path_traversal_string_literal_fp.ex", "elixir");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture elixir/path_traversal_string_literal_fp.ex (lang=elixir); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_path_traversal_positive() {
    let report = run_tldr_vuln("go/path_traversal_positive.go", "go");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture go/path_traversal_positive.go (lang=go); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("go/path_traversal_string_literal_fp.go", "go");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture go/path_traversal_string_literal_fp.go (lang=go); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_path_traversal_positive() {
    let report = run_tldr_vuln("java/path_traversal_positive.java", "java");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture java/path_traversal_positive.java (lang=java); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("java/path_traversal_string_literal_fp.java", "java");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture java/path_traversal_string_literal_fp.java (lang=java); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_path_traversal_positive() {
    let report = run_tldr_vuln("javascript/path_traversal_positive.js", "javascript");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture javascript/path_traversal_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln(
        "javascript/path_traversal_string_literal_fp.js",
        "javascript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/path_traversal_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_path_traversal_positive() {
    let report = run_tldr_vuln("kotlin/path_traversal_positive.kt", "kotlin");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture kotlin/path_traversal_positive.kt (lang=kotlin); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("kotlin/path_traversal_string_literal_fp.kt", "kotlin");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture kotlin/path_traversal_string_literal_fp.kt (lang=kotlin); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_path_traversal_positive() {
    let report = run_tldr_vuln("lua/path_traversal_positive.lua", "lua");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture lua/path_traversal_positive.lua (lang=lua); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn lua_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("lua/path_traversal_string_literal_fp.lua", "lua");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture lua/path_traversal_string_literal_fp.lua (lang=lua); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_path_traversal_positive() {
    let report = run_tldr_vuln("luau/path_traversal_positive.luau", "luau");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture luau/path_traversal_positive.luau (lang=luau); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn luau_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("luau/path_traversal_string_literal_fp.luau", "luau");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture luau/path_traversal_string_literal_fp.luau (lang=luau); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_path_traversal_positive() {
    let report = run_tldr_vuln("ocaml/path_traversal_positive.ml", "ocaml");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture ocaml/path_traversal_positive.ml (lang=ocaml); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("ocaml/path_traversal_string_literal_fp.ml", "ocaml");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ocaml/path_traversal_string_literal_fp.ml (lang=ocaml); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_path_traversal_positive() {
    let report = run_tldr_vuln("php/path_traversal_positive.php", "php");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture php/path_traversal_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("php/path_traversal_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/path_traversal_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_path_traversal_positive() {
    let report = run_tldr_vuln("python/path_traversal_positive.py", "python");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture python/path_traversal_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("python/path_traversal_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/path_traversal_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_path_traversal_positive() {
    let report = run_tldr_vuln("ruby/path_traversal_positive.rb", "ruby");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture ruby/path_traversal_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("ruby/path_traversal_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/path_traversal_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_path_traversal_positive() {
    let report = run_tldr_vuln("rust/path_traversal_positive.rs", "rust");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture rust/path_traversal_positive.rs (lang=rust); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("rust/path_traversal_string_literal_fp.rs", "rust");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture rust/path_traversal_string_literal_fp.rs (lang=rust); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_path_traversal_positive() {
    let report = run_tldr_vuln("scala/path_traversal_positive.scala", "scala");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture scala/path_traversal_positive.scala (lang=scala); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("scala/path_traversal_string_literal_fp.scala", "scala");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture scala/path_traversal_string_literal_fp.scala (lang=scala); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_path_traversal_positive() {
    let report = run_tldr_vuln("swift/path_traversal_positive.swift", "swift");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture swift/path_traversal_positive.swift (lang=swift); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn swift_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln("swift/path_traversal_string_literal_fp.swift", "swift");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture swift/path_traversal_string_literal_fp.swift (lang=swift); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_path_traversal_positive() {
    let report = run_tldr_vuln("typescript/path_traversal_positive.ts", "typescript");
    let f = findings_of_type(&report, "path_traversal");
    assert!(
        !f.is_empty(),
        "expected ≥1 path_traversal finding for fixture typescript/path_traversal_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_path_traversal_string_literal_fp() {
    let report = run_tldr_vuln(
        "typescript/path_traversal_string_literal_fp.ts",
        "typescript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/path_traversal_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_ssrf_positive() {
    let report = run_tldr_vuln("go/ssrf_positive.go", "go");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture go/ssrf_positive.go (lang=go); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn go_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("go/ssrf_string_literal_fp.go", "go");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture go/ssrf_string_literal_fp.go (lang=go); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_ssrf_positive() {
    let report = run_tldr_vuln("java/ssrf_positive.java", "java");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture java/ssrf_positive.java (lang=java); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("java/ssrf_string_literal_fp.java", "java");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture java/ssrf_string_literal_fp.java (lang=java); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_ssrf_positive() {
    let report = run_tldr_vuln("javascript/ssrf_positive.js", "javascript");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture javascript/ssrf_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("javascript/ssrf_string_literal_fp.js", "javascript");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/ssrf_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_ssrf_positive() {
    let report = run_tldr_vuln("php/ssrf_positive.php", "php");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture php/ssrf_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("php/ssrf_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/ssrf_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_ssrf_positive() {
    let report = run_tldr_vuln("python/ssrf_positive.py", "python");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture python/ssrf_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("python/ssrf_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/ssrf_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_ssrf_positive() {
    let report = run_tldr_vuln("ruby/ssrf_positive.rb", "ruby");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture ruby/ssrf_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("ruby/ssrf_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/ssrf_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_ssrf_positive() {
    let report = run_tldr_vuln("rust/ssrf_positive.rs", "rust");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture rust/ssrf_positive.rs (lang=rust); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("rust/ssrf_string_literal_fp.rs", "rust");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture rust/ssrf_string_literal_fp.rs (lang=rust); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_ssrf_positive() {
    let report = run_tldr_vuln("typescript/ssrf_positive.ts", "typescript");
    let f = findings_of_type(&report, "ssrf");
    assert!(
        !f.is_empty(),
        "expected ≥1 ssrf finding for fixture typescript/ssrf_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_ssrf_string_literal_fp() {
    let report = run_tldr_vuln("typescript/ssrf_string_literal_fp.ts", "typescript");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/ssrf_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_deserialization_positive() {
    let report = run_tldr_vuln("cpp/deserialization_positive.cpp", "cpp");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture cpp/deserialization_positive.cpp (lang=cpp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn cpp_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("cpp/deserialization_string_literal_fp.cpp", "cpp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture cpp/deserialization_string_literal_fp.cpp (lang=cpp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_deserialization_positive() {
    let report = run_tldr_vuln("csharp/deserialization_positive.cs", "csharp");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture csharp/deserialization_positive.cs (lang=csharp); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn csharp_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("csharp/deserialization_string_literal_fp.cs", "csharp");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture csharp/deserialization_string_literal_fp.cs (lang=csharp); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_deserialization_positive() {
    let report = run_tldr_vuln("elixir/deserialization_positive.ex", "elixir");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture elixir/deserialization_positive.ex (lang=elixir); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn elixir_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("elixir/deserialization_string_literal_fp.ex", "elixir");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture elixir/deserialization_string_literal_fp.ex (lang=elixir); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_deserialization_positive() {
    let report = run_tldr_vuln("java/deserialization_positive.java", "java");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture java/deserialization_positive.java (lang=java); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn java_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("java/deserialization_string_literal_fp.java", "java");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture java/deserialization_string_literal_fp.java (lang=java); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_deserialization_positive() {
    let report = run_tldr_vuln("javascript/deserialization_positive.js", "javascript");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture javascript/deserialization_positive.js (lang=javascript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn javascript_deserialization_string_literal_fp() {
    let report = run_tldr_vuln(
        "javascript/deserialization_string_literal_fp.js",
        "javascript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture javascript/deserialization_string_literal_fp.js (lang=javascript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_deserialization_positive() {
    let report = run_tldr_vuln("kotlin/deserialization_positive.kt", "kotlin");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture kotlin/deserialization_positive.kt (lang=kotlin); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn kotlin_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("kotlin/deserialization_string_literal_fp.kt", "kotlin");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture kotlin/deserialization_string_literal_fp.kt (lang=kotlin); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_deserialization_positive() {
    let report = run_tldr_vuln("ocaml/deserialization_positive.ml", "ocaml");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture ocaml/deserialization_positive.ml (lang=ocaml); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ocaml_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("ocaml/deserialization_string_literal_fp.ml", "ocaml");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ocaml/deserialization_string_literal_fp.ml (lang=ocaml); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_deserialization_positive() {
    let report = run_tldr_vuln("php/deserialization_positive.php", "php");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture php/deserialization_positive.php (lang=php); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn php_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("php/deserialization_string_literal_fp.php", "php");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture php/deserialization_string_literal_fp.php (lang=php); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_deserialization_positive() {
    let report = run_tldr_vuln("python/deserialization_positive.py", "python");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture python/deserialization_positive.py (lang=python); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn python_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("python/deserialization_string_literal_fp.py", "python");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture python/deserialization_string_literal_fp.py (lang=python); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_deserialization_positive() {
    let report = run_tldr_vuln("ruby/deserialization_positive.rb", "ruby");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture ruby/deserialization_positive.rb (lang=ruby); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn ruby_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("ruby/deserialization_string_literal_fp.rb", "ruby");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture ruby/deserialization_string_literal_fp.rb (lang=ruby); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_deserialization_positive() {
    let report = run_tldr_vuln("rust/deserialization_positive.rs", "rust");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture rust/deserialization_positive.rs (lang=rust); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn rust_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("rust/deserialization_string_literal_fp.rs", "rust");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture rust/deserialization_string_literal_fp.rs (lang=rust); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_deserialization_positive() {
    let report = run_tldr_vuln("scala/deserialization_positive.scala", "scala");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture scala/deserialization_positive.scala (lang=scala); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn scala_deserialization_string_literal_fp() {
    let report = run_tldr_vuln("scala/deserialization_string_literal_fp.scala", "scala");
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture scala/deserialization_string_literal_fp.scala (lang=scala); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_deserialization_positive() {
    let report = run_tldr_vuln("typescript/deserialization_positive.ts", "typescript");
    let f = findings_of_type(&report, "deserialization");
    assert!(
        !f.is_empty(),
        "expected ≥1 deserialization finding for fixture typescript/deserialization_positive.ts (lang=typescript); got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

#[test]
fn typescript_deserialization_string_literal_fp() {
    let report = run_tldr_vuln(
        "typescript/deserialization_string_literal_fp.ts",
        "typescript",
    );
    let all = all_findings(&report);
    assert!(
        all.is_empty(),
        "expected ZERO findings (string-literal regression-guard) for fixture typescript/deserialization_string_literal_fp.ts (lang=typescript); got {} findings: {}",
        all.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}
