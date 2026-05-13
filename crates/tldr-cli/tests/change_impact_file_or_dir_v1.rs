//! change-impact-file-or-dir-v1 (v0.4.2 bug-D1-D4 / VAL-UX-AGG):
//!
//! Pre-fix audit assertion (W-R, VAL-UX-AGG, audit workers ruby/typescript/java/csharp
//! Phase-20 and rust C-7):
//! > "`tldr change-impact <file>` rejects with 'requires a directory' — UX
//! >  inconsistency since other inference-cmds (dead, smells, debt, health,
//! >  clones, calls, structure, tree) accept either a file or a directory.
//! >  rust C-7 reports the same issue under a different label
//! >  ('error msg contradicts catalog signature'). Fix once, covers both."
//!
//! Verdict: REAL BUG. The `change-impact` CLI command rejects regular files
//! up-front via `require_directory`, which is the right defense against the
//! cryptic "Not a directory (os error 20)" surface from the git diff path
//! BUT is overly strict — change-impact has a perfectly well-defined
//! single-file semantics: "scope the change set to this one file."
//!
//! Fix: when `path` is a regular file, infer the project root by walking up
//! to the nearest ancestor containing a project-root marker (Cargo.toml,
//! package.json, pyproject.toml, .git, setup.py, go.mod) and run the
//! analysis with the file as the explicit change set. When `path` is a
//! genuinely invalid input (e.g. `/no/such/path/xyz`), emit a clean error
//! that names the offending path — not the obsolete "requires a directory"
//! catalog-mismatch wording.

use std::path::Path;
use std::process::Command;

const RG_CORPUS: &str = "/tmp/repos/ripgrep";

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

// =============================================================================
// TEST 1: change-impact accepts a file path (D1 + D4).
//
// Real-repo gated on /tmp/repos/ripgrep. The file
// `crates/globset/src/glob.rs` is a known-good rust source file inside the
// ripgrep workspace. Passing it directly to `change-impact` must:
//   - exit 0
//   - emit a valid JSON report (non-empty stdout, parseable)
//   - identify the file under `changed_files` (since we asked to scope to
//     this single file's change set)
// =============================================================================
#[test]
fn change_impact_accepts_file_path() {
    if !Path::new(RG_CORPUS).exists() {
        eprintln!(
            "[skip] change_impact_accepts_file_path: corpus {} not present",
            RG_CORPUS
        );
        return;
    }
    let file = format!("{}/crates/globset/src/glob.rs", RG_CORPUS);
    if !Path::new(&file).exists() {
        eprintln!(
            "[skip] change_impact_accepts_file_path: target file {} not present",
            file
        );
        return;
    }

    let (rc, stdout, stderr) = run_tldr(&["change-impact", &file, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "change-impact on a file must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );
    assert!(
        !stdout.trim().is_empty(),
        "change-impact on a file must emit non-empty output; stderr=\n{}",
        stderr
    );

    // Must parse as JSON with the expected report shape.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("change-impact output must be valid JSON");
    assert!(
        v.get("changed_files").is_some(),
        "report missing changed_files; got: {}",
        v
    );
    assert!(
        v.get("status").is_some(),
        "report missing status; got: {}",
        v
    );

    // The file path we passed should appear in changed_files (the CLI
    // promotes it to an explicit-files-of-one change set).
    let changed = v["changed_files"]
        .as_array()
        .expect("changed_files must be an array");
    let mentions_target = changed
        .iter()
        .filter_map(|s| s.as_str())
        .any(|s| s.ends_with("glob.rs") || s.contains("glob.rs"));
    assert!(
        mentions_target,
        "changed_files should reference the file we passed; got: {:?}",
        changed
    );
}

// =============================================================================
// TEST 2: change-impact on a directory still works (non-regression).
//
// This guards against any reshaping of the path validator that accidentally
// breaks the original directory contract. We pass the ripgrep repo root and
// require exit 0 with a valid JSON report.
// =============================================================================
#[test]
fn change_impact_directory_still_works() {
    if !Path::new(RG_CORPUS).exists() {
        eprintln!(
            "[skip] change_impact_directory_still_works: corpus {} not present",
            RG_CORPUS
        );
        return;
    }

    let (rc, stdout, stderr) = run_tldr(&["change-impact", RG_CORPUS, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "change-impact on directory must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("change-impact dir output must be valid JSON");
    assert!(
        v.get("changed_files").is_some(),
        "dir report missing changed_files; got: {}",
        v
    );
    assert!(
        v.get("status").is_some(),
        "dir report missing status; got: {}",
        v
    );
}

// =============================================================================
// TEST 3: change-impact on an invalid path returns a clean, actionable error
//         that names the offending path — NOT the obsolete catalog-mismatch
//         "requires a directory" wording (which is now wrong since file
//         paths are accepted).
//
// This does not need a corpus and is unconditional. We pass a clearly
// non-existent path and assert:
//   - non-zero exit
//   - stderr names the path
//   - stderr does NOT claim "requires a directory" (since files are now OK)
// =============================================================================
#[test]
fn change_impact_invalid_path_error_is_clear() {
    let bogus = "/no/such/path/xyz-tldr-change-impact-v1";
    let (rc, _stdout, stderr) = run_tldr(&["change-impact", bogus, "-q"]);
    assert_ne!(
        rc, 0,
        "change-impact on missing path must fail; got rc={}, stderr=\n{}",
        rc, stderr
    );
    assert!(
        stderr.contains(bogus),
        "error must mention the offending path '{}'; got stderr:\n{}",
        bogus,
        stderr
    );
    // The "requires a directory" wording is the old catalog-mismatch error;
    // now that files are accepted, that phrase must NOT appear for a
    // missing path (it would mislead the user into thinking the issue is
    // file vs. dir, when in reality the path doesn't exist at all).
    assert!(
        !stderr.contains("requires a directory"),
        "error must not say 'requires a directory' for an invalid path; got:\n{}",
        stderr
    );
}
