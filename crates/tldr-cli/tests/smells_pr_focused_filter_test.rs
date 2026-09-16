//! M1 VAL-001 — PR-focused smells filter (#1.D)
//!
//! Validates:
//! (a) Default `tldr smells` excludes test-file findings (test noise filter)
//! (b) `--files <FILE>...` flag scopes scan to caller-supplied list
//! (c) `--files` implies `--include-tests` (caller picked them, trust them)
//! (d) `--files` entries are validated via `tldr_core::validation::validate_file_path`;
//!     bad paths produce a clap error (non-zero exit), NOT a silent skip.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// A god-class fixture (>20 methods triggers GodClass smell at default threshold).
fn god_class_py(class_name: &str) -> String {
    let mut s = format!("class {}:\n", class_name);
    for i in 0..25 {
        s.push_str(&format!("    def m{}(self): pass\n", i));
    }
    s
}

fn write(dir: &TempDir, rel: &str, content: &str) -> PathBuf {
    let p = dir.path().join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, content).unwrap();
    p
}

fn tldr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tldr")
}

/// Test 1 — VAL-001 (b): default invocation excludes test-file findings.
/// Pre-fix: report contains BOTH smells (assert fails: "expected 1 smell, got 2").
/// Post-fix: only the production smell + `excluded_test_smells == 1`.
#[test]
fn smells_default_excludes_test_files() {
    let dir = TempDir::new().unwrap();
    write(&dir, "src/prod.py", &god_class_py("Prod"));
    write(&dir, "tests/test_thing.py", &god_class_py("TestThing"));

    let out = Command::new(tldr_bin())
        .args(["smells", dir.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("tldr smells");
    assert!(
        out.status.success(),
        "tldr smells should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The smells JSON includes `smells: [...]` AND a `by_file: { ... }` map,
    // so a raw substring count of "god_class" double-counts each finding.
    // Use the canonical `total_smells` summary field for the kept count.
    assert!(
        stdout.contains("\"total_smells\":1") || stdout.contains("\"total_smells\": 1"),
        "expected total_smells == 1 (test smells must be excluded by default); stdout={}",
        stdout
    );

    // The surviving smell should be from prod.py, not the test file.
    assert!(
        stdout.contains("prod.py"),
        "expected prod.py in output; stdout={}",
        stdout
    );
    assert!(
        !stdout.contains("test_thing.py")
            || stdout.contains("\"excluded_test_smells\":1")
            || stdout.contains("\"excluded_test_smells\": 1"),
        "expected test_thing.py to be excluded or counted in excluded_test_smells; stdout={}",
        stdout
    );

    // The new counter must be present and equal to 1.
    assert!(
        stdout.contains("\"excluded_test_smells\":1")
            || stdout.contains("\"excluded_test_smells\": 1"),
        "expected excluded_test_smells == 1; stdout={}",
        stdout
    );
}

/// Test 2 — VAL-001 (a): --files limits the scan to the explicit list.
/// Pre-fix: clap rejects --files (assert exit non-zero with "unexpected argument").
/// Post-fix: files_scanned == 2.
#[test]
fn smells_files_filter_limits_scan() {
    let dir = TempDir::new().unwrap();
    write(&dir, "src/foo.py", &god_class_py("Foo"));
    write(&dir, "src/bar.py", &god_class_py("Bar"));
    write(&dir, "src/baz.py", &god_class_py("Baz"));
    write(&dir, "src/qux.py", &god_class_py("Qux"));
    write(&dir, "src/quux.py", &god_class_py("Quux"));

    let out = Command::new(tldr_bin())
        .args([
            "smells",
            dir.path().to_str().unwrap(),
            "--files",
            dir.path().join("src/foo.py").to_str().unwrap(),
            "--files",
            dir.path().join("src/bar.py").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("tldr smells --files");
    assert!(
        out.status.success(),
        "tldr smells --files should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"files_scanned\":2") || stdout.contains("\"files_scanned\": 2"),
        "expected files_scanned=2 in output, got: {}",
        stdout
    );
}

/// Test 3 — VAL-001 (d): --files implies --include-tests.
/// Caller explicitly named a test file, so we should trust them.
#[test]
fn smells_files_filter_includes_tests_by_default() {
    let dir = TempDir::new().unwrap();
    write(&dir, "src/foo.py", &god_class_py("Foo"));
    write(&dir, "tests/test_foo.py", &god_class_py("TestFoo"));

    let out = Command::new(tldr_bin())
        .args([
            "smells",
            dir.path().to_str().unwrap(),
            "--files",
            dir.path().join("src/foo.py").to_str().unwrap(),
            "--files",
            dir.path().join("tests/test_foo.py").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("tldr smells --files");
    assert!(
        out.status.success(),
        "tldr smells --files should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // See `smells_default_excludes_test_files` for why we use total_smells:
    // the JSON includes both `smells: [...]` and `by_file: {...}` so a raw
    // substring count of "god_class" double-counts.
    assert!(
        stdout.contains("\"total_smells\":2") || stdout.contains("\"total_smells\": 2"),
        "expected total_smells == 2 (--files implies --include-tests); stdout={}",
        stdout
    );
    // No test exclusion when --files is set.
    assert!(
        stdout.contains("\"excluded_test_smells\":0")
            || stdout.contains("\"excluded_test_smells\": 0"),
        "expected excluded_test_smells == 0 (--files implies --include-tests); stdout={}",
        stdout
    );
}

/// Test 4 — VAL-001 (a): --files entries are validated via validate_file_path.
/// `/etc/passwd` is outside any project — validation must fail with a non-zero exit.
#[test]
fn smells_files_path_validation_blocks_system_dirs() {
    let dir = TempDir::new().unwrap();
    write(&dir, "src/foo.py", &god_class_py("Foo"));

    let out = Command::new(tldr_bin())
        .args([
            "smells",
            dir.path().to_str().unwrap(),
            "--files",
            "/etc/passwd",
            "--files",
            dir.path().join("src/foo.py").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("tldr smells --files");
    assert!(
        !out.status.success(),
        "tldr smells --files /etc/passwd MUST fail; stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.to_lowercase().contains("traversal")
            || combined.to_lowercase().contains("not found")
            || combined.to_lowercase().contains("blocked")
            || combined.to_lowercase().contains("invalid")
            || combined.to_lowercase().contains("path"),
        "expected validation error message; stderr={}",
        stderr
    );
}
