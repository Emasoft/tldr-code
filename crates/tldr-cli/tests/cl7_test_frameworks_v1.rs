//! cl7-test-frameworks-v1 (CL-7 — specs/invariants only understood pytest+JUnit):
//!
//! `tldr specs --from-tests` and `tldr invariants --from-tests` returned ~0
//! extractions on Jest/XCTest/RSpec/MUnit/mocha/dune suites because the
//! assertion-call matcher (`classify_assertion_call` / `is_known_assertion_callee`)
//! was pytest/JUnit-shaped: it only recognised flat `assertEquals(a, b)`-style
//! callees, never the per-framework member-call / macro / property shapes:
//!
//!  - Jest/mocha (JS/TS): `expect(x).toBe/toEqual/toStrictEqual(...)`.
//!  - XCTest / swift-testing (Swift): `XCTAssert*`, `expectEqual`.
//!  - RSpec (Ruby): `expect(x).to eq(...)`.
//!  - MUnit/ScalaCheck (Scala): `assertEquals`, `property("..."){...}`, `forAll`.
//!  - dune/OCaml: `let%test`, `let%expect_test`, alcotest `check`, `[%expect]`.
//!
//! Each framework's assertion is now mapped to a precondition/postcondition
//! observation exactly as the pytest path does, recognising the call by its
//! tree-sitter call/method node + callee name (NOT regex over text).
//!
//! These tests are gated on the real corpora under /tmp/tldr_corpora and the
//! release binary at target/release/tldr. They FAIL before the fix because
//! each framework produced `total_specs == 0` (and for OCaml/Scala, the test
//! functions themselves weren't even recognised).

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


use std::path::Path;
use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn skip(reason: &str) {
    eprintln!("[skip] {reason}");
}

/// Run `tldr specs --from-tests <dir>` and return `summary.total_specs`.
fn specs_total(dir: &str) -> u64 {
    let (code, stdout, stderr) =
        run_tldr(&["specs", "--from-tests", dir, "--format", "json"]);
    assert_eq!(code, 0, "specs exited non-zero for {dir}: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("specs JSON parse for {dir}: {e}\n{stdout}"));
    v["summary"]["total_specs"].as_u64().unwrap_or(0)
}

/// Count how many distinct test functions the specs report scanned.
fn specs_test_functions(dir: &str) -> u64 {
    let (code, stdout, _stderr) =
        run_tldr(&["specs", "--from-tests", dir, "--format", "json"]);
    if code != 0 {
        return 0;
    }
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
    v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0)
}

// =============================================================================
// Jest / mocha (JS/TS): `expect(x).toBe/toEqual/toStrictEqual(...)`.
// =============================================================================
#[test]
fn jest_expect_member_assertions_yield_specs() {
    let dir = "/tmp/tldr_corpora/typescript-nest/sample/01-cats-app";
    if !corpus_ready(dir) {
        return skip("jest: typescript-nest corpus missing");
    }
    let total = specs_total(dir);
    assert!(
        total > 0,
        "Jest expect(...).toBe(...) assertions should yield specs, got total_specs={total} for {dir}"
    );
}

// =============================================================================
// XCTest / swift-testing (Swift): `XCTAssertEqual`, `expectEqual`.
// =============================================================================
#[test]
fn xctest_expectequal_assertions_yield_specs() {
    let dir = "/tmp/tldr_corpora/swift-collections/Tests/SortedCollectionsTests/SortedSet";
    if !corpus_ready(dir) {
        return skip("xctest: swift-collections corpus missing");
    }
    let total = specs_total(dir);
    // This dir has 70+ `expectEqual(actual, expected)` calls across many
    // test methods; pre-fix only the rare bare XCTAssertEqual matched.
    assert!(
        total >= 10,
        "Swift expectEqual(...) assertions should yield specs, got total_specs={total} for {dir}"
    );
}

// =============================================================================
// RSpec (Ruby): `expect(x).to eq(...)`.
// =============================================================================
#[test]
fn rspec_expect_to_assertions_yield_specs() {
    let dir = "/tmp/tldr_corpora/ruby-rubocop/spec/tasks";
    if !corpus_ready(dir) {
        return skip("rspec: ruby-rubocop corpus missing");
    }
    let total = specs_total(dir);
    assert!(
        total > 0,
        "RSpec expect(...).to eq(...) assertions should yield specs, got total_specs={total} for {dir}"
    );
}

// =============================================================================
// MUnit / ScalaCheck (Scala): `assertEquals`, `property("..."){...}`, `forAll`.
//
// Pre-fix BOTH the test-function recogniser (which only matched `test(...)`,
// not `property(...)`) and the assertion classifier missed these suites.
// =============================================================================
#[test]
fn scala_munit_property_and_asserts_yield_specs() {
    // ScalaCheck `property("...") { ... assertEquals(fut(x), y) }` suites.
    let dir =
        "/tmp/tldr_corpora/scala-cats-effect/tests/shared/src/test/scala/cats/effect/std/internal";
    if !corpus_ready(dir) {
        return skip("scala: cats-effect corpus missing");
    }
    // The `property(...)` blocks must be recognised as test functions.
    let funcs = specs_test_functions(dir);
    assert!(
        funcs > 0,
        "Scala property(...)/test(...) blocks should be recognised as test functions, got {funcs} for {dir}"
    );
    let total = specs_total(dir);
    assert!(
        total > 0,
        "Scala assertEquals(...) assertions should yield specs, got total_specs={total} for {dir}"
    );
}

// =============================================================================
// dune / OCaml: `let%test`, `let%expect_test`, alcotest `check`, `[%expect]`.
//
// Pre-fix OCaml had NO test-function recogniser at all (matches_test_function
// returned false), so test_functions_scanned and total_specs were both 0.
// =============================================================================
#[test]
fn ocaml_dune_expect_tests_yield_specs() {
    let dir = "/tmp/tldr_corpora/ocaml-dune/test/expect-tests";
    if !corpus_ready(dir) {
        return skip("ocaml: dune corpus missing");
    }
    // `let%expect_test` / `let%test` blocks must be recognised as tests.
    let funcs = specs_test_functions(dir);
    assert!(
        funcs > 0,
        "OCaml let%expect_test/let%test blocks should be recognised as test functions, got {funcs} for {dir}"
    );
    let total = specs_total(dir);
    assert!(
        total > 0,
        "OCaml check(...)/assertion calls should yield specs, got total_specs={total} for {dir}"
    );
}

// =============================================================================
// invariants must also work cross-framework. Observations are now derived
// from the generic spec extraction path, so a Jest suite (a non-Python
// framework) must report > 0 observations.
// =============================================================================
#[test]
fn invariants_cross_framework_observations_nonzero() {
    let test_dir = "/tmp/tldr_corpora/typescript-nest/sample/01-cats-app";
    if !corpus_ready(test_dir) {
        return skip("invariants: typescript-nest corpus missing");
    }
    // invariants needs a source file argument; any source file in the project
    // works since observations are gathered from the --from-tests path.
    let src = "/tmp/tldr_corpora/typescript-nest/sample/01-cats-app/src/cats/cats.service.ts";
    if !corpus_ready(src) {
        return skip("invariants: source file missing");
    }
    let (code, stdout, stderr) = run_tldr(&[
        "invariants",
        src,
        "--from-tests",
        test_dir,
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "invariants exited non-zero: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("invariants JSON parse: {e}\n{stdout}"));
    let obs = v["summary"]["total_observations"].as_u64().unwrap_or(0);
    assert!(
        obs > 0,
        "Jest suite should yield invariant observations, got total_observations={obs}"
    );
}
