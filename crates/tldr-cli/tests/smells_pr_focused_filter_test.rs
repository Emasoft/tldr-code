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

/// canonical-scan-root-v1 (BATCH-B): `--deep` fans the scan root out to
/// analyzers with different canonicalization habits (the base scan
/// canonicalizes per BUG-12; the deep sub-analyzers copy the walked
/// spelling). Querying through a SYMLINKED root must yield ONE `by_file`
/// key per file, all spelled against the real (canonical) root — never a
/// mixed key set for the same file. Runs the same fixture through BOTH
/// spellings of the root and asserts the key sets agree byte-for-byte.
#[cfg(unix)]
#[test]
fn smells_deep_by_file_keys_are_canonical_across_root_spellings() {
    use std::collections::BTreeSet;
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    fs::create_dir_all(&real_root).unwrap();
    fs::write(real_root.join("god.py"), god_class_py("God")).unwrap();
    // Deep-collector bait: two attribute-disjoint methods → LCOM4 >= 2 →
    // the cohesion sub-analyzer must fire (a deep arm that copies its own
    // walked spelling into the finding).
    fs::write(
        real_root.join("disjoint.py"),
        "class Disjoint:\n    def a(self):\n        self.x = 1\n\n    def b(self):\n        self.y = 2\n",
    )
    .unwrap();

    let link = dir.path().join("linked");
    symlink(&real_root, &link).unwrap();

    let run = |root: &std::path::Path| {
        let out = Command::new(tldr_bin())
            .args([
                "smells",
                root.to_str().unwrap(),
                "--deep",
                "--format",
                "json",
            ])
            .output()
            .expect("tldr smells --deep");
        assert!(
            out.status.success(),
            "tldr smells --deep must succeed; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .expect("smells --deep must emit valid JSON")
    };

    let via_real = run(&real_root);
    let via_link = run(&link);

    let by_file_keys = |report: &serde_json::Value| -> Vec<String> {
        report["by_file"]
            .as_object()
            .expect("smells JSON must carry by_file")
            .keys()
            .cloned()
            .collect()
    };

    assert!(
        !by_file_keys(&via_real).is_empty(),
        "fixture must produce smells (god class + low-cohesion bait)"
    );

    // ONE key per file: every key from the symlinked query is spelled
    // against the REAL root.
    let real_canonical = fs::canonicalize(&real_root).unwrap();
    for key in by_file_keys(&via_link) {
        assert!(
            key.starts_with(real_canonical.to_str().unwrap()),
            "by_file key must use the canonical root spelling: {key}"
        );
    }

    // The two spellings of the same fixture agree byte-for-byte on the key
    // set (one key per file, no second spelling of any file).
    let keys_real: BTreeSet<String> = by_file_keys(&via_real).into_iter().collect();
    let keys_link: BTreeSet<String> = by_file_keys(&via_link).into_iter().collect();
    assert_eq!(
        keys_real, keys_link,
        "the same fixture queried via two root spellings must yield ONE key per file"
    );
}
