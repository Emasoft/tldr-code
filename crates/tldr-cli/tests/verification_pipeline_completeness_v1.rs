//! verification-pipeline-completeness-v1 (P11.BUG-AGG-2 / AGG-3 / AGG-13)
//!
//! Closes three phase-11 audit findings about the verification pipeline:
//!
//! - **BUG-AGG-2 (MED)**: `tldr invariants --lang <X>` panicked with a
//!   clap type-mismatch downcast because the local `--lang` arg was
//!   typed `Option<String>` while the global `--lang/-l` flag declared
//!   on `Cli` is `Option<Language>`. Fixed by changing the local type
//!   to `Option<Language>`.
//!
//! - **BUG-AGG-3 (HIGH)**: `tldr specs --from-tests` and
//!   `tldr invariants --from-tests` recognised only Python pytest test
//!   files. JavaScript / Java / PHP / Swift / Go / Kotlin / Scala /
//!   Ruby / Elixir / Lua test trees all reported `test_files_scanned = 0`.
//!   Fixed by adding per-language test recognisers in
//!   `crates/tldr-cli/src/commands/contracts/test_recognizer.rs`.
//!
//! - **BUG-AGG-13 (MED)**: `tldr taint` had no Spring annotation source
//!   patterns, so Java web taint was blind. Fixed by adding a
//!   Spring-annotation source pass in `detect_sources_ast` for the Java
//!   language (`@RequestParam` / `@PathVariable` / `@RequestHeader` /
//!   `@ModelAttribute` / `@RequestBody`).

use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr() -> AssertCommand {
    AssertCommand::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, body).unwrap();
    p
}

// -- BUG-AGG-2: invariants --lang must not panic ----------------------------

#[test]
fn test_invariants_lang_flag_no_panic() {
    let tmp = TempDir::new().unwrap();
    let src = write(tmp.path(), "src/m.py", "def add(a, b):\n    return a + b\n");
    let test = write(
        tmp.path(),
        "tests/test_m.py",
        "from src.m import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
    );

    // Pre-fix: process aborted with rc=101 and a clap downcast panic.
    // Post-fix: rc must be 0 (or at minimum not 101 from clap).
    let out = tldr()
        .arg("invariants")
        .arg(src.to_str().unwrap())
        .arg("--from-tests")
        .arg(test.to_str().unwrap())
        .arg("--lang")
        .arg("python")
        .output()
        .expect("failed to run tldr invariants");

    assert!(
        out.status.code() != Some(101),
        "invariants --lang panicked (rc=101). stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// -- BUG-AGG-3: specs recognises test functions in 6 non-Python languages --

fn run_specs_json(test_dir: &Path) -> Value {
    let out = tldr()
        .arg("specs")
        .arg("--from-tests")
        .arg(test_dir.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run tldr specs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse specs JSON: {}\nstdout:\n{}\nstderr:\n{}",
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn assert_files_at_least_one(report: &Value, lang: &str) {
    let n = report["summary"]["test_files_scanned"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing test_files_scanned for {}", lang));
    assert!(
        n >= 1,
        "{}: expected >= 1 test_files_scanned, got {}\nreport: {}",
        lang,
        n,
        report
    );
}

#[test]
fn test_specs_recognizes_javascript_describe_it() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "foo.test.js",
        "describe('group', () => {\n  it('does a thing', () => {});\n  it('does another', () => {});\n});\n",
    );
    let report = run_specs_json(tmp.path());
    assert_files_at_least_one(&report, "javascript");
}

#[test]
fn test_specs_recognizes_java_test_annotation() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "FooTest.java",
        "import org.junit.Test;\nclass FooTest {\n  @Test public void shouldFoo() {}\n}\n",
    );
    let report = run_specs_json(tmp.path());
    assert_files_at_least_one(&report, "java");
}

#[test]
fn test_specs_recognizes_php_phpunit() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "FooTest.php",
        "<?php\nclass FooTest {\n  public function testBar() {}\n}\n",
    );
    let report = run_specs_json(tmp.path());
    assert_files_at_least_one(&report, "php");
}

#[test]
fn test_specs_recognizes_swift_xctest() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "FooTests.swift",
        "import XCTest\nclass FooTests: XCTestCase {\n  func testBar() {}\n}\n",
    );
    let report = run_specs_json(tmp.path());
    assert_files_at_least_one(&report, "swift");
}

#[test]
fn test_specs_recognizes_go_testing() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "foo_test.go",
        "package foo\nimport \"testing\"\nfunc TestFoo(t *testing.T) {}\n",
    );
    let report = run_specs_json(tmp.path());
    assert_files_at_least_one(&report, "go");
}

// -- BUG-AGG-13: taint recognises Spring @RequestParam ----------------------

#[test]
fn test_taint_recognizes_spring_request_param() {
    let tmp = TempDir::new().unwrap();
    let java = write(
        tmp.path(),
        "C.java",
        "import org.springframework.web.bind.annotation.GetMapping;\n\
         import org.springframework.web.bind.annotation.RequestParam;\n\
         import org.springframework.web.bind.annotation.RestController;\n\
         \n\
         @RestController\n\
         class C {\n\
         \n\
         @GetMapping(\"/q\")\n\
         public String f(@RequestParam String x) {\n\
             return query(x);\n\
         }\n\
         \n\
         private String query(String s) { return s; }\n\
         }\n",
    );

    let out = tldr()
        .arg("taint")
        .arg(java.to_str().unwrap())
        .arg("f")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run tldr taint");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse taint JSON: {}\nstdout:\n{}\nstderr:\n{}",
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let sources = report["sources"].as_array().expect("sources missing");
    assert!(
        !sources.is_empty(),
        "expected >= 1 Spring annotation source, got 0.\nreport: {}",
        report
    );
}
