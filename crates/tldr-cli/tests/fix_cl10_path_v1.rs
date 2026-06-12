//! fix-cl-10-v1 (v0.5.0 CL-10) — change-impact path-root join doubling.
//!
//! Gaps: IT3-csharp-01, IT3-kotlin-01.
//!
//! `tldr change-impact <relative-file>` promotes the file to a one-element
//! explicit change set and infers a project root by walking up for a marker.
//! Two interacting defects produced a DOUBLED path and silently-empty results:
//!
//!   - The inferred project root is ABSOLUTE (canonicalised ancestor dir),
//!     but the promoted file path stayed RELATIVE to the CWD. Downstream
//!     `project_root.join(file)` then concatenated an absolute root whose tail
//!     already equals the file's relative head, e.g.
//!       root  = /repo/Src/Newtonsoft.Json.Bson            (has *.csproj)
//!       file  = Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs
//!       join  = /repo/Src/Newtonsoft.Json.Bson/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs  ← DOUBLED
//!     AST extraction fails on the bogus path, the error is swallowed, and
//!     `affected_functions` / `affected_tests` come back empty.
//!
//!   - The `*.kts` (`build.gradle.kts`) marker makes the walk stop at a NESTED
//!     gradle module (`<repo>/core`) instead of the real repo root, so the
//!     join produced `<repo>/core/core/common/...` ← DOUBLED `core/core`.
//!
//! Contract pinned here: with a relative file path, change-impact MUST NOT
//! emit a doubled-path "AST extraction failed" warning and MUST return a
//! non-empty affected-functions set (the function and its caller exist).
//! Absolute-path input must keep working (regression guard).

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Build a C#-style layout: a `.git` repo root, a nested project dir holding a
/// `*.csproj` marker, and a source file with a callee + caller. Mirrors the
/// newtonsoft-bson corpus (IT3-csharp-01). Returns (TempDir, repo_root,
/// relative_file_path).
fn make_csharp_layout() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    fs::create_dir_all(root.join(".git")).unwrap();
    let proj = root.join("Src").join("Demo.Bson");
    fs::create_dir_all(&proj).unwrap();
    fs::write(proj.join("Demo.Bson.csproj"), "<Project></Project>\n").unwrap();
    let src = proj.join("BsonWriter.cs");
    fs::write(
        &src,
        "namespace Demo.Bson {\n  class BsonWriter {\n    void WriteToken() { WriteTokenInternal(); }\n    void WriteTokenInternal() { var x = 1; }\n  }\n}\n",
    )
    .unwrap();
    let rel = PathBuf::from("Src/Demo.Bson/BsonWriter.cs");
    (temp, root, rel)
}

/// Build a Kotlin/gradle multi-module layout: `.git` repo root with a
/// top-level `build.gradle.kts`, a nested `core` module ALSO carrying
/// `build.gradle.kts`, and a deeply nested source file. Mirrors the
/// kotlin-datetime corpus (IT3-kotlin-01) where the walk stops at `core`.
fn make_kotlin_layout() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join("build.gradle.kts"), "// root\n").unwrap();
    let module = root.join("core");
    fs::create_dir_all(&module).unwrap();
    fs::write(module.join("build.gradle.kts"), "// core module\n").unwrap();
    let src_dir = module.join("common").join("src").join("internal");
    fs::create_dir_all(&src_dir).unwrap();
    let src = src_dir.join("math.kt");
    fs::write(
        &src,
        "fun safeMultiplyOrClamp(a: Long, b: Long): Long { return a * b }\n\nfun caller(): Long { return safeMultiplyOrClamp(2, 3) }\n",
    )
    .unwrap();
    let rel = PathBuf::from("core/common/src/internal/math.kt");
    (temp, root, rel)
}

/// Run change-impact on a relative file path from `cwd` and assert: no
/// doubled-path AST-extraction warning, valid JSON, and a non-empty
/// affected-functions set.
fn assert_no_doubling_and_nonempty(cwd: &Path, rel: &Path) {
    let rel_str = rel.to_string_lossy().to_string();
    let assert = tldr_cmd()
        .current_dir(cwd)
        .args(["change-impact", &rel_str, "--format", "json", "-q"])
        .assert()
        .success();
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // No "AST extraction failed" warning at all (it only fires on the bogus
    // doubled path here).
    assert!(
        !stderr.contains("AST extraction failed"),
        "change-impact must not fail AST extraction on a relative file (path doubling); stderr:\n{}",
        stderr
    );

    // Detect a literal doubled segment in any stderr path: a relative
    // component immediately repeated (e.g. `/core/core/` or
    // `/Src/Demo.Bson/Src/Demo.Bson/`). Pin the specific repeats we expect.
    assert!(
        !stderr.contains("/core/core/"),
        "doubled '/core/core/' segment in stderr:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("Demo.Bson/Src/Demo.Bson"),
        "doubled project-dir segment in stderr:\n{}",
        stderr
    );

    let v: Value =
        serde_json::from_str(&stdout).expect("change-impact must emit valid JSON on success");
    let affected = v
        .get("affected_functions")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !affected.is_empty(),
        "affected_functions must be non-empty for a real single-file change set; got JSON:\n{}",
        stdout
    );
}

#[test]
fn change_impact_csharp_nested_csproj_no_path_doubling() {
    let (_temp, root, rel) = make_csharp_layout();
    assert_no_doubling_and_nonempty(&root, &rel);
}

#[test]
fn change_impact_kotlin_nested_gradle_kts_no_path_doubling() {
    let (_temp, root, rel) = make_kotlin_layout();
    assert_no_doubling_and_nonempty(&root, &rel);
}

#[test]
fn change_impact_absolute_file_path_regression_guard() {
    // Absolute single-file mode must keep working after the relative fix.
    let (_temp, root, rel) = make_kotlin_layout();
    let abs = root.join(&rel);
    let abs_str = abs.to_string_lossy().to_string();

    let assert = tldr_cmd()
        .args(["change-impact", &abs_str, "--format", "json", "-q"])
        .assert()
        .success();
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        !stderr.contains("AST extraction failed"),
        "absolute-path change-impact must not fail AST extraction; stderr:\n{}",
        stderr
    );
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(v.get("status").is_some(), "expected status field; got: {}", v);
}
