//! SECURE-UTF8-TOLERANCE-V1 — uniform non-UTF-8 file tolerance
//!
//! The prior `luau-utf8-tolerance-v1` milestone (commit 4c61af8) wired
//! the [`tldr_core::fs::read_to_string_tolerant`] helper into the surface
//! command (`crates/tldr-core/src/surface/{luau,lua}.rs`). But other
//! directory-scanning commands kept their own strict
//! `std::fs::read_to_string` paths, so a single non-UTF-8 file in a
//! scanned tree still aborted the whole command.
//!
//! Concrete repro pre-fix:
//!
//! ```text
//! $ tldr secure --lang luau /tmp/repos/luau-luau
//! Error: IO error: stream did not contain valid UTF-8
//! ```
//!
//! ...because `tests/conformance/literals.luau` (and `pm.luau`,
//! `sort.luau`) intentionally embed raw 0xFF/0xFE bytes as parser-test
//! corpus. `secure` scanned ~3 files, hit the bad one, and bailed.
//!
//! These tests synthesise the same shape (one valid + one invalid-UTF-8
//! file in a tempdir) and assert the dir-scanning commands continue
//! instead of aborting.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Write a "1 valid + 1 non-UTF-8 .py" tempdir. Returns the tempdir
/// guard so the caller controls lifetime.
fn make_mixed_utf8_dir() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("good.py"), b"def safe():\n    return 1\n").unwrap();

    // Synthetic bad file: valid prefix + raw 0xFF/0xFE (never legal as
    // a UTF-8 leading byte) + valid suffix. Same shape as the real
    // luau-luau parser-test fixtures.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"# valid prefix\n");
    bytes.extend_from_slice(&[0xFFu8, 0xFEu8]);
    bytes.extend_from_slice(b"\n# valid suffix\n");
    fs::write(dir.path().join("bad.py"), bytes).unwrap();

    dir
}

/// `tldr smells` MUST complete and emit valid JSON when a directory
/// contains a non-UTF-8 source file alongside valid ones.
///
/// Smells already used `std::fs::read_to_string(path).unwrap_or_default()`
/// which avoided the abort but silently substituted an empty source.
/// This test guards the post-fix behavior: scan completes, JSON is
/// well-formed, total exit code is 0.
#[test]
fn test_smells_continues_after_bad_file_in_dir() {
    let dir = make_mixed_utf8_dir();

    let output = tldr_cmd()
        .arg("smells")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("smells must execute");

    assert!(
        output.status.success(),
        "smells must NOT abort on non-UTF-8 input (status: {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "smells stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });
}

/// `tldr structure` MUST complete and emit valid JSON when a directory
/// contains a non-UTF-8 source file alongside valid ones.
///
/// Structure routes through `tldr_core::ast::parser::parse_file_with_lang`,
/// which already uses `String::from_utf8_lossy` (M2 mitigation). This
/// test pins that behavior so a future refactor can't regress it.
#[test]
fn test_structure_continues_after_bad_file_in_dir() {
    let dir = make_mixed_utf8_dir();

    let output = tldr_cmd()
        .arg("structure")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("structure must execute");

    assert!(
        output.status.success(),
        "structure must NOT abort on non-UTF-8 input (status: {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "structure stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });
}

/// `tldr vuln` MUST complete and surface skipped non-UTF-8 files in
/// `files_skipped` + `warnings`. Pre-fix vuln silently dropped them
/// via an `if let Ok(..)` guard — coverage degraded with no signal.
#[test]
fn test_vuln_continues_after_bad_file_in_dir() {
    let dir = make_mixed_utf8_dir();

    let output = tldr_cmd()
        .arg("vuln")
        .arg(dir.path().to_str().unwrap())
        .arg("--lang")
        .arg("python")
        .arg("-f")
        .arg("json")
        .output()
        .expect("vuln must execute");

    // Exit code 0 (no findings) or 2 (findings detected) are both
    // success cases; only a hard error (exit 1) would indicate the
    // tolerance regressed.
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(2)),
        "vuln must NOT abort on non-UTF-8 input (status: {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "vuln stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });

    let files_skipped = report
        .get("files_skipped")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        files_skipped, 1,
        "vuln must report files_skipped=1 for the synthetic bad file; report={}",
        report
    );

    let warnings = report
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        warnings.len(),
        1,
        "vuln must emit exactly one warning for the bad file; warnings={:?}",
        warnings
    );
    let warning = warnings[0].as_str().unwrap_or("");
    assert!(
        warning.contains("bad.py"),
        "warning must reference the skipped file path; got: {}",
        warning
    );
    assert!(
        warning.contains("invalid UTF-8") || warning.contains("byte"),
        "warning must describe the UTF-8 failure with a byte offset; got: {}",
        warning
    );
}
