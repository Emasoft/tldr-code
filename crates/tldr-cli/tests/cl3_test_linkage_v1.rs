//! cl3-test-linkage-v1 (CL-3 — affected-tests undercount, GH #35):
//!
//! `change-impact` / `whatbreaks` undercounted affected tests for any test
//! file whose path is colocated with source (Go `*_test.go`) or whose test
//! convention is not lower-snake-case (Swift PascalCase `Tests/*Tests.swift`).
//! GH #35 reported the TSX/JSX case but the same defect generalizes across
//! languages. Three mechanisms were broken:
//!
//!  (a) relative-vs-absolute path mismatch in `find_affected_tests`: the
//!      call graph stores project-relative paths while `test_files` /
//!      `changed_files` were absolute, so the set-membership comparisons in
//!      steps 2 & 3 of `find_affected_tests` never matched. Result: test
//!      files that *contained* affected functions (e.g. `tree_test.go`)
//!      were dropped from `affected_tests`.
//!
//!  (b) `is_test_file` had no per-language arm for Swift (PascalCase
//!      `*Tests.swift` under a capital-`Tests/` directory) — the generic
//!      `_ =>` arm only matched lowercase `test` substrings / `/tests/`
//!      dirs, so Swift tests were invisible.
//!
//!  (c) `verify`'s `find_test_dirs` only probed top-level test directories,
//!      so a colocated-test language like Go (`*_test.go` next to source,
//!      no `tests/` dir) reported `spec_count: 0` and "No test directory
//!      found" despite the project clearly containing test files.
//!
//! These tests are gated on the real corpora under /tmp/tldr_corpora and the
//! release binary at target/release/tldr. They FAIL before the fix.

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

const GO_CORPUS: &str = "/tmp/tldr_corpora/go-httprouter";
const SWIFT_CORPUS: &str = "/tmp/tldr_corpora/swift-collections";

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

fn run_tldr_in(dir: &str, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .current_dir(dir)
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

// =============================================================================
// TEST 1 (bug a): Go colocated `*_test.go` — change-impact on a source file
// whose functions are exercised by `tree_test.go` / `router_test.go` must list
// those test files under `affected_tests`.
//
// Pre-fix: `affected_tests` was EMPTY because the affected-function paths
// (relative, from the call graph) never matched the test_files set (absolute).
// =============================================================================
#[test]
fn go_colocated_test_files_are_affected() {
    if !corpus_ready(GO_CORPUS) {
        return skip("go_colocated_test_files_are_affected: go corpus missing");
    }

    let (rc, stdout, stderr) = run_tldr_in(
        GO_CORPUS,
        &["change-impact", "--files", "tree.go", "--lang", "go", "--format", "json", "-q"],
    );
    assert_eq!(rc, 0, "change-impact must succeed; rc={rc}, stderr=\n{stderr}");

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("change-impact output must be valid JSON");

    let affected_tests: Vec<String> = v["affected_tests"]
        .as_array()
        .expect("affected_tests must be an array")
        .iter()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect();

    // tree.go's node.addRoute is exercised by tree_test.go; the change ripples
    // to router_test.go too. At minimum tree_test.go must surface.
    assert!(
        affected_tests.iter().any(|t| t.ends_with("tree_test.go")),
        "tree_test.go must be in affected_tests for a change to tree.go; got: {affected_tests:?}"
    );
    assert!(
        !affected_tests.is_empty(),
        "affected_tests must be non-empty for a Go change with colocated tests; got: {affected_tests:?}"
    );
}

// =============================================================================
// TEST 2 (bug a + bug b): Swift PascalCase `Tests/` — change-impact on a
// source file (`SortedSet.swift`) that is exercised by an XCTest file under
// `Tests/SortedCollectionsTests/SortedSet/SortedSet Tests.swift` must list that
// test file under `affected_tests`.
//
// This exercises BOTH the path-canonicalization fix (the call graph has
// Tests/->Sources/ edges in relative form, but the test_files / changed_files
// sets were absolute) AND the Swift `is_test_file` arm (PascalCase
// `*Tests.swift` inside a capital-`Tests/` directory — invisible to the old
// generic lowercase-`test` heuristic). Pre-fix `affected_tests` was empty.
// =============================================================================
#[test]
fn swift_pascalcase_tests_are_affected() {
    if !corpus_ready(SWIFT_CORPUS) {
        return skip("swift_pascalcase_tests_are_affected: swift corpus missing");
    }

    let changed = "Sources/SortedCollections/SortedSet/SortedSet.swift";
    if !Path::new(SWIFT_CORPUS).join(changed).exists() {
        return skip("swift_pascalcase_tests_are_affected: SortedSet.swift missing");
    }

    let (rc, stdout, stderr) = run_tldr_in(
        SWIFT_CORPUS,
        &["change-impact", "--files", changed, "--lang", "swift", "--format", "json", "-q"],
    );
    assert_eq!(rc, 0, "change-impact must succeed; rc={rc}, stderr=\n{stderr}");

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("change-impact output must be valid JSON");

    let affected_tests: Vec<String> = v["affected_tests"]
        .as_array()
        .expect("affected_tests must be an array")
        .iter()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect();

    assert!(
        affected_tests
            .iter()
            .any(|t| t.ends_with("SortedSet Tests.swift")
                || t.contains("SortedCollectionsTests")),
        "Swift PascalCase test exercising SortedSet.swift must be in affected_tests; got: {affected_tests:?}"
    );
    assert!(
        !affected_tests.is_empty(),
        "affected_tests must be non-empty for a Swift change with linked Tests/; got: {affected_tests:?}"
    );
}

// =============================================================================
// TEST 3 (bug c): Go colocated `*_test.go` — `verify` must discover the
// colocated test files and extract specs even though there is NO top-level
// `tests/` directory.
//
// Pre-fix: `find_test_dirs` only probed top-level test directories, so Go
// projects reported `spec_count: 0` / "No test directory found".
// =============================================================================
#[test]
fn go_colocated_tests_yield_specs_in_verify() {
    if !corpus_ready(GO_CORPUS) {
        return skip("go_colocated_tests_yield_specs_in_verify: go corpus missing");
    }

    let (rc, stdout, stderr) = run_tldr_in(
        GO_CORPUS,
        &["verify", "--lang", "go", "--format", "json", "-q"],
    );
    assert_eq!(rc, 0, "verify must succeed; rc={rc}, stderr=\n{stderr}");

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("verify output must be valid JSON");

    let specs = &v["sub_results"]["specs"];
    let status = specs["status"].as_str().unwrap_or("");
    assert_ne!(
        status, "failed",
        "specs must not be 'failed'/'No test directory found' for Go colocated tests; got: {specs}"
    );
    let items = specs["items_found"].as_u64().unwrap_or(0);
    assert!(
        items > 0,
        "verify must extract specs from Go colocated *_test.go files; got items_found={items}, specs={specs}"
    );
}
