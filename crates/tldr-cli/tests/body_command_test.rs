//! body-command-v1 (issue #8) — integration tests for `tldr body`.
//!
//! `tldr body <file> <function>` / `tldr body <file> --from N --to M` is a
//! SAFE contiguous, byte-faithful source reader. These tests pin the two
//! contract halves:
//!
//! 1. **Contiguity**: the emitted span is exactly the function's line bounds
//!    (same bounds path as `chop`) or the requested `--from/--to` window —
//!    never a dependency closure like `slice`/`chop`.
//! 2. **Byte-faithfulness**: the file is read as raw bytes, so CRLF line
//!    endings, a UTF-8 BOM at offset 0, and trailing whitespace survive
//!    verbatim — both in the JSON `body` field and (as raw stdout bytes) in
//!    `--format text` mode.
//!
//! Fixture: tests/fixtures/simple.py is copied into a tempdir (and CRLF/BOM
//! variants are generated) so every assertion is a byte-for-byte comparison
//! against the real file contents. The binary is invoked via
//! `assert_cmd::cargo::cargo_bin!("tldr")`, mirroring cli_graph_tests.rs.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Copy tests/fixtures/simple.py into a tempdir and return its path.
///
/// Fixture content (5 lines, trailing newline):
/// `def main():\n    x = 1\n    y = x + 1\n    z = y * 2\n    return z\n`
fn copy_simple_py(dir: &TempDir) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.py");
    let dst = dir.path().join("simple.py");
    fs::copy(&src, &dst).expect("copy tests/fixtures/simple.py into tempdir");
    dst
}

/// The exact bytes of lines `start..=end` (1-indexed, inclusive).
///
/// Mirrors the documented `body` span semantics: lines joined with their
/// original terminators, including the newline that terminates line `end`
/// (when the file has one — the final line of a file without a trailing
/// newline has none).
fn lines_slice(file: &Path, start: u32, end: u32) -> Vec<u8> {
    let bytes = fs::read(file).expect("read fixture file");
    let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
    lines[start as usize - 1..end as usize].concat()
}

fn body_json(file: &Path, extra_args: &[&str]) -> Value {
    let output = tldr_cmd()
        .args([
            "body",
            file.to_str().expect("utf-8 path"),
            "--format",
            "json",
        ])
        .args(extra_args)
        .output()
        .expect("run tldr body");
    assert!(
        output.status.success(),
        "tldr body failed: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse body JSON from stdout")
}

/// (a) Function mode on the Python fixture: the JSON `body` is byte-for-byte
/// the exact file slice for the function's lines, including the trailing
/// newline of the last line.
#[test]
fn function_mode_body_is_exact_file_slice() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let json = body_json(&file, &["main"]);

    assert_eq!(json["function"], "main");
    assert_eq!(json["language"], "python");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 5);
    assert_eq!(json["line_count"], 5);

    let expected = lines_slice(&file, 1, 5);
    assert_eq!(
        json["body"].as_str().expect("body is a string").as_bytes(),
        expected,
        "body must equal the exact byte slice of lines 1..=5"
    );
    assert_eq!(json["byte_count"], expected.len());

    // Additive-field hygiene: nothing lossy happened, so neither optional
    // field may appear.
    let obj = json.as_object().expect("JSON object");
    assert!(
        !obj.contains_key("encoding_lossy"),
        "no lossy flag on clean UTF-8"
    );
    assert!(
        !obj.contains_key("warnings"),
        "no warnings on a clean extraction"
    );

    // The file has no trailing content, so the body is the entire file.
    assert_eq!(expected, fs::read(&file).expect("read file"));
}

/// (b) THE byte-faithfulness proof: a CRLF file keeps its `\r\n` endings.
#[test]
fn crlf_line_endings_are_preserved() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("crlf.py");
    let crlf_src = "def main():\r\n    x = 1\r\n    return x\r\n";
    fs::write(&file, crlf_src).expect("write CRLF fixture");

    let json = body_json(&file, &["main"]);

    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 3);

    let body = json["body"].as_str().expect("body is a string");
    assert!(body.contains("\r\n"), "CRLF endings must survive verbatim");
    assert_eq!(
        body.as_bytes(),
        crlf_src.as_bytes(),
        "body must be byte-identical to the CRLF source"
    );
    assert_eq!(json["byte_count"], crlf_src.len());
}

/// (c) A UTF-8 BOM at offset 0 is part of line 1 and must survive: a
/// full-range body starts with the BOM bytes and byte_count includes them.
#[test]
fn bom_at_offset_zero_is_preserved() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("bom.py");
    let bom: &[u8] = &[0xEF, 0xBB, 0xBF];
    let src = "def main():\n    x = 1\n    return x\n";
    let mut bytes = bom.to_vec();
    bytes.extend_from_slice(src.as_bytes());
    fs::write(&file, &bytes).expect("write BOM fixture");

    let json = body_json(&file, &["--from", "1", "--to", "3"]);

    let body = json["body"].as_str().expect("body is a string");
    assert!(
        body.starts_with('\u{feff}'),
        "full-range body must start with the BOM (U+FEFF)"
    );
    assert_eq!(
        body.as_bytes(),
        &bytes[..],
        "body must equal the raw file bytes"
    );
    assert_eq!(
        json["byte_count"],
        bytes.len(),
        "byte_count must include the 3 BOM bytes"
    );
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 3);
}

/// (d) Range mode: `--from/--to` yields the exact contiguous slice, and an
/// out-of-range `--to` is clamped to the last line WITH a visible warning
/// (never silently).
#[test]
fn range_mode_exact_slice() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let json = body_json(&file, &["--from", "2", "--to", "4"]);

    assert_eq!(json["line_start"], 2);
    assert_eq!(json["line_end"], 4);
    assert_eq!(json["line_count"], 3);
    let expected = lines_slice(&file, 2, 4);
    assert_eq!(
        json["body"].as_str().expect("body is a string").as_bytes(),
        expected
    );
    assert_eq!(json["byte_count"], expected.len());
}

/// (d, cont.) `--to` beyond the end of file clamps to the last line and adds
/// a warnings entry; the extraction still succeeds.
#[test]
fn range_mode_clamps_out_of_range_to_with_warning() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let json = body_json(&file, &["--from", "2", "--to", "100"]);

    assert_eq!(json["line_start"], 2);
    assert_eq!(json["line_end"], 5, "--to must clamp to the last line");
    assert_eq!(json["line_count"], 4);
    let expected = lines_slice(&file, 2, 5);
    assert_eq!(
        json["body"].as_str().expect("body is a string").as_bytes(),
        expected
    );

    let warnings = json["warnings"].as_array().expect("warnings array present");
    assert!(
        !warnings.is_empty(),
        "clamping must be surfaced as a warning, got: {json}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or_default().contains("clamp")),
        "warning must mention the clamp, got: {warnings:?}"
    );
}

/// (e) A function that does not exist fails with a non-zero exit and an
/// error naming BOTH the function and the file.
#[test]
fn missing_function_fails_naming_function_and_file() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let output = tldr_cmd()
        .args(["body", file.to_str().unwrap(), "does_not_exist"])
        .output()
        .expect("run tldr body");

    assert!(
        !output.status.success(),
        "missing function must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does_not_exist"),
        "error must name the function: {stderr}"
    );
    assert!(
        stderr.contains("simple.py"),
        "error must name the file: {stderr}"
    );
    // Nothing may leak onto stdout on failure.
    assert!(output.stdout.is_empty(), "stdout must stay empty on error");
}

/// (f) Text mode writes the body VERBATIM as raw stdout bytes — no
/// decoration, no added newline. Proven against both an LF fixture and a
/// CRLF fixture (raw bytes only survive if nothing re-encoded the output).
#[test]
fn text_mode_stdout_is_verbatim_bytes() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let output = tldr_cmd()
        .args(["body", file.to_str().unwrap(), "main", "--format", "text"])
        .output()
        .expect("run tldr body");
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        lines_slice(&file, 1, 5),
        "text stdout must be the exact slice bytes"
    );

    // CRLF file through text mode: \r bytes must reach stdout untouched.
    let crlf_file = dir.path().join("crlf_text.py");
    let crlf_src = "def main():\r\n    x = 1\r\n    return x\r\n";
    fs::write(&crlf_file, crlf_src).expect("write CRLF fixture");
    let output = tldr_cmd()
        .args([
            "body",
            crlf_file.to_str().unwrap(),
            "--format",
            "text",
            "--from",
            "1",
            "--to",
            "3",
        ])
        .output()
        .expect("run tldr body");
    assert!(output.status.success());
    assert_eq!(output.stdout, crlf_src.as_bytes());
}

/// (g) `--from` without `--to` (and vice versa) is rejected with a clear
/// error that explains the contiguous-range contract.
#[test]
fn from_without_to_is_a_clear_error() {
    let dir = TempDir::new().expect("tempdir");
    let file = copy_simple_py(&dir);

    let output = tldr_cmd()
        .args(["body", file.to_str().unwrap(), "--from", "2"])
        .output()
        .expect("run tldr body");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--from") && stderr.contains("--to"),
        "error must explain that --from and --to go together: {stderr}"
    );

    let output = tldr_cmd()
        .args(["body", file.to_str().unwrap(), "--to", "4"])
        .output()
        .expect("run tldr body");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--to") && stderr.contains("--from"),
        "error must explain that --to needs --from: {stderr}"
    );
}
