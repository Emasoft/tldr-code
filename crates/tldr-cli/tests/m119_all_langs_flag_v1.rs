//! m119-all-langs-flag-v1 (v0.4.2 M-118, D10):
//!
//! Pin the user-facing surface of the `--all-langs` (alias `-A`)
//! escape hatch added to project-path commands. Default behaviour
//! is unchanged: a polyglot project scans only its auto-detected
//! primary language, silently dropping secondary-language files.
//! With `--all-langs`, every detected language is scanned and the
//! results are merged.
//!
//! Anchor command: `structure` (it is the canonical
//! file-walk-and-extract command and the most observable in the
//! test fixture — the JSON `files[]` array gives a direct count).
//!
//! Fixture: a tempdir with TWO languages.
//!   - Python files (dominant by count: 2 files)
//!   - Rust files (secondary: 1 file)
//!
//! Assertions:
//!   1. `structure` default → only Python files appear in `files[]`.
//!   2. `structure --all-langs` → both Python AND Rust appear.
//!   3. `structure -A` → short alias works the same.
//!   4. `--all-langs --help` is documented.

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

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

/// Build a polyglot fixture with Python (dominant) + Rust (secondary).
fn make_polyglot_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");

    // Two Python files — these establish Python as the dominant
    // language under `Language::from_directory`.
    std::fs::write(
        dir.path().join("app.py"),
        "def hello():\n    return 'world'\n\nclass Greeter:\n    def greet(self, name):\n        return f'hi {name}'\n",
    )
    .expect("write app.py");
    std::fs::write(
        dir.path().join("util.py"),
        "def helper(x):\n    return x + 1\n",
    )
    .expect("write util.py");

    // One Rust file — this is the secondary language that the
    // default scan should drop. The fixture is intentionally
    // minimal-but-valid so the Rust grammar parses it cleanly.
    std::fs::write(
        dir.path().join("tool.rs"),
        "pub fn build() -> u32 {\n    let x = 41;\n    x + 1\n}\n",
    )
    .expect("write tool.rs");

    dir
}

/// Count how many JSON `files[]` entries match a given extension.
fn count_files_with_ext(v: &serde_json::Value, ext: &str) -> usize {
    v["files"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f["path"]
                        .as_str()
                        .map(|p| p.ends_with(ext))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

// =============================================================================
// (1) Default scan: Python dominant → Rust files silently dropped.
// =============================================================================

#[test]
fn m119_default_drops_secondary_language() {
    let dir = make_polyglot_dir();
    let path = dir.path().to_str().unwrap();

    let (exit, stdout, stderr) = run(&["structure", path, "--format", "json"]);
    assert_eq!(
        exit, 0,
        "structure (default) must succeed. stderr={}",
        stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("structure json must parse");

    let n_py = count_files_with_ext(&v, ".py");
    let n_rs = count_files_with_ext(&v, ".rs");

    assert!(
        n_py >= 2,
        "default scan should include both Python files. got n_py={}, json={}",
        n_py,
        stdout
    );
    assert_eq!(
        n_rs, 0,
        "default scan should DROP Rust files (dominant=Python). \
         got n_rs={}, json={}",
        n_rs, stdout
    );
}

// =============================================================================
// (2) `--all-langs`: secondary language is included.
// =============================================================================

#[test]
fn m119_all_langs_includes_secondary_language() {
    let dir = make_polyglot_dir();
    let path = dir.path().to_str().unwrap();

    let (exit, stdout, stderr) = run(&["structure", path, "--all-langs", "--format", "json"]);
    assert_eq!(
        exit, 0,
        "structure --all-langs must succeed. stderr={}",
        stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("structure --all-langs json must parse");

    let n_py = count_files_with_ext(&v, ".py");
    let n_rs = count_files_with_ext(&v, ".rs");

    assert!(
        n_py >= 2,
        "--all-langs must still include Python files. got n_py={}, json={}",
        n_py,
        stdout
    );
    assert!(
        n_rs >= 1,
        "--all-langs must INCLUDE the Rust file. got n_rs={}, json={}",
        n_rs,
        stdout
    );
}

// =============================================================================
// (3) `-A` short alias.
// =============================================================================

#[test]
fn m119_short_alias_a_works() {
    let dir = make_polyglot_dir();
    let path = dir.path().to_str().unwrap();

    let (exit, stdout, stderr) = run(&["structure", path, "-A", "--format", "json"]);
    assert_eq!(exit, 0, "structure -A must succeed. stderr={}", stderr);

    let v: serde_json::Value = serde_json::from_str(&stdout).expect("structure -A json must parse");
    let n_rs = count_files_with_ext(&v, ".rs");
    assert!(
        n_rs >= 1,
        "structure -A must include the Rust file. got n_rs={}, json={}",
        n_rs,
        stdout
    );
}

// =============================================================================
// (4) `--all-langs` is mentioned in `structure --help`.
// =============================================================================

#[test]
fn m119_all_langs_documented_in_structure_help() {
    let (exit, stdout, stderr) = run(&["structure", "--help"]);
    assert_eq!(exit, 0, "structure --help must succeed: stderr={}", stderr);
    assert!(
        stdout.contains("--all-langs") || stdout.contains("all-langs"),
        "structure --help must mention --all-langs. stdout={}",
        stdout
    );
}

// =============================================================================
// (5) `--lang` wins over `--all-langs`: explicit pin shrinks scope.
// =============================================================================

#[test]
fn m119_explicit_lang_overrides_all_langs() {
    let dir = make_polyglot_dir();
    let path = dir.path().to_str().unwrap();

    // Explicit --lang rust + --all-langs: the spec says --lang wins.
    // The merged structure should contain ONLY Rust files.
    let (exit, stdout, stderr) = run(&[
        "structure",
        path,
        "--lang",
        "rust",
        "--all-langs",
        "--format",
        "json",
    ]);
    assert_eq!(
        exit, 0,
        "structure --lang rust --all-langs must succeed. stderr={}",
        stderr
    );

    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json must parse");
    let n_py = count_files_with_ext(&v, ".py");
    let n_rs = count_files_with_ext(&v, ".rs");
    assert_eq!(
        n_py, 0,
        "--lang rust must drop Python files even with --all-langs. got n_py={}",
        n_py
    );
    assert!(
        n_rs >= 1,
        "--lang rust must include Rust files. got n_rs={}",
        n_rs
    );
}
