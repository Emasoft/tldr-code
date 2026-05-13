//! test-recognizer-expansion-v1 (v0.4.2 M-005, phase-22 iter-1):
//!
//! Pre-fix audit assertion (cluster M-005, autonomous run):
//! > "`crates/tldr-cli/src/commands/contracts/test_recognizer.rs` has narrow
//! >  per-lang stem patterns that miss real-world test files. Confirmed by
//! >  worker-Q PHP audit at test_recognizer.rs:171 (only `*Test`/`*Tests`
//! >  accepted; misses Symfony AbstractAsciiTestCase, Codeception *Cest) and
//! >  Java JUnit5 (`@ParameterizedTest`, `@RepeatedTest` annotations not
//! >  recognised — only tail `Test` matches at recognise time)."
//!
//! Verdict after AST-level verification:
//!
//! - **PHP**: REAL BUG. File-name gate `stem.ends_with("Test") ||
//!   stem.ends_with("Tests")` rejects `*TestCase` (Symfony pattern) and `*Cest`
//!   (Codeception convention). Repro: `AbstractAsciiTestCase.php`,
//!   `LoginCest.php` → `test_files_scanned: 0`.
//! - **Java**: REAL BUG. Annotation-name tail check only accepts literal
//!   `"Test"`. JUnit5 ships `@ParameterizedTest`, `@RepeatedTest`,
//!   `@TestFactory`, `@TestTemplate` — all silently dropped at AST level.
//!   Repro: `ParamTest.java` (3 test methods) → `test_functions_scanned: 1`.
//!
//! False alarms (verified in code, NOT bugs):
//!   - C# `[Fact]` / `[Theory]` / `[TestMethod]` — already detected
//!     (csharp_attribute_is_test at L381).
//!   - Go `Test*(t *testing.T)` — already detected (L552).
//!   - JS/TS `it()`/`test()`/`describe()` — already detected (L419).
//!   - Ruby `def test_*` — already detected (L529).
//!   - Python pytest fixtures — correctly excluded by predicate (L407).
//!
//! Fix scope (this commit): PHP file-name gate + Java annotation predicate.
//!
//! All tests in this file write to a tempdir and invoke `tldr specs
//! --from-tests` against the fixture directory. They assert that
//! `test_files_scanned` and `test_functions_scanned` reflect the new
//! recognition rules.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tldr_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

/// Run `tldr specs --from-tests <dir>` and return parsed JSON.
fn run_specs(dir: &Path) -> serde_json::Value {
    let out = Command::new(tldr_bin())
        .args(["specs", "--from-tests"])
        .arg(dir)
        .output()
        .expect("invoke tldr");
    assert!(
        out.status.success(),
        "tldr specs failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("could not parse tldr specs JSON: {e}\n--stdout--\n{stdout}")
    })
}

fn write_file(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&p, body).expect("write fixture");
    p
}

// ---------------------------------------------------------------------------
// PHP: extended stem matchers (Symfony TestCase, Codeception Cest)
// ---------------------------------------------------------------------------

#[test]
fn php_symfony_abstract_testcase_recognised() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "AbstractAsciiTestCase.php",
        "<?php\nabstract class AbstractAsciiTestCase extends TestCase {\n  public function testAscii() {}\n  public function testToString() {}\n}\n",
    );
    let v = run_specs(tmp.path());
    let files = v["summary"]["test_files_scanned"].as_u64().unwrap_or(0);
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(files, 1, "Symfony *TestCase.php must be classified as a test file: {v}");
    assert_eq!(fns, 2, "Symfony *TestCase methods named test* must be counted: {v}");
}

#[test]
fn php_codeception_cest_recognised() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "LoginCest.php",
        "<?php\nclass LoginCest {\n  public function testLoginSuccess() {}\n  public function testLoginFailure() {}\n}\n",
    );
    let v = run_specs(tmp.path());
    let files = v["summary"]["test_files_scanned"].as_u64().unwrap_or(0);
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(files, 1, "Codeception *Cest.php must be classified as a test file: {v}");
    assert_eq!(fns, 2, "Codeception Cest methods named test* must be counted: {v}");
}

#[test]
fn php_plain_test_still_recognised() {
    // Regression: the existing `FooTest.php` / `BarTests.php` patterns must
    // still classify after the gate is widened.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "FooTest.php",
        "<?php\nclass FooTest {\n  public function testAlpha() {}\n}\n",
    );
    write_file(
        tmp.path(),
        "BarTests.php",
        "<?php\nclass BarTests {\n  public function testBeta() {}\n}\n",
    );
    let v = run_specs(tmp.path());
    let files = v["summary"]["test_files_scanned"].as_u64().unwrap_or(0);
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(files, 2, "existing *Test/*Tests stems must still be recognised: {v}");
    assert_eq!(fns, 2, "existing PHPUnit test methods must still be counted: {v}");
}

// ---------------------------------------------------------------------------
// Java: JUnit5 annotation variants (@ParameterizedTest, @RepeatedTest, ...)
// ---------------------------------------------------------------------------

#[test]
fn java_parameterized_test_recognised() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "ParamTest.java",
        r#"
package com.example;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.params.ParameterizedTest;
public class ParamTest {
  @Test
  public void plainTest() {}
  @ParameterizedTest
  public void parameterized(int v) {}
  @RepeatedTest(3)
  public void repeated() {}
}
"#,
    );
    let v = run_specs(tmp.path());
    let files = v["summary"]["test_files_scanned"].as_u64().unwrap_or(0);
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(files, 1, "ParamTest.java must be classified as a test file: {v}");
    assert_eq!(
        fns, 3,
        "JUnit5 @Test + @ParameterizedTest + @RepeatedTest must all be counted: {v}"
    );
}

#[test]
fn java_test_factory_and_template_recognised() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "FactoryTest.java",
        r#"
package com.example;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestTemplate;
public class FactoryTest {
  @TestFactory
  public void factory() {}
  @TestTemplate
  public void template() {}
}
"#,
    );
    let v = run_specs(tmp.path());
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(
        fns, 2,
        "JUnit5 @TestFactory + @TestTemplate must be counted: {v}"
    );
}

#[test]
fn java_plain_test_still_recognised() {
    // Regression: vanilla @Test must continue to count after we widen the predicate.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_file(
        tmp.path(),
        "FooTest.java",
        "import org.junit.Test;\nclass FooTest {\n  @Test public void shouldFoo() {}\n  @Test public void shouldBar() {}\n}\n",
    );
    let v = run_specs(tmp.path());
    let fns = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert_eq!(fns, 2, "vanilla JUnit @Test must still be counted: {v}");
}
