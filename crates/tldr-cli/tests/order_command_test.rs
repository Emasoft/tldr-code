//! order-command-v1 (issue #8b) — integration tests for `tldr order`.
//!
//! `tldr order <file>` is a use-before-define / TDZ report computed from the
//! definition line ranges a single tree-sitter parse already provides. These
//! tests pin the contract end-to-end:
//!
//! 1. **The issue #8 repro**: a JS function referencing `let dataFetchSeq`
//!    declared ~170 lines later — the exact shape where `tldr impact` passed
//!    but eslint failed with `no-use-before-define`. `tldr order` must exit 0
//!    and report the hazard in JSON.
//! 2. **Clean file** → zero issues, exit 0.
//! 3. **Missing file** → clear non-zero CLI error.
//! 4. **Unsupported language** → graceful: exit 0, zero issues, `explanation`
//!    set (cf. #10).
//!
//! The binary is invoked via `assert_cmd::cargo::cargo_bin!("tldr")`,
//! mirroring body_command_test.rs / cli_graph_tests.rs.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Write `content` to a uniquely-named file inside `dir`.
fn write_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).expect("write fixture file");
    path
}

/// The issue #8 shape: `edit()` references `dataFetchSeq` at line 2, the
/// `let` binding lands ~170 lines later (padded with comment lines, like the
/// real file where the definition was far below the edited function).
fn repro_js_source(padding_lines: usize) -> String {
    let mut source = String::from("function edit() {\n  return dataFetchSeq;\n}\n");
    for i in 0..padding_lines {
        source.push_str(&format!("// padding line {}\n", i));
    }
    source.push_str("let dataFetchSeq = 0;\n");
    source
}

fn run_order_json(file: &Path) -> (bool, Value, String) {
    let output = tldr_cmd()
        .args([
            "order",
            file.to_str().expect("utf-8 path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run tldr order");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse order JSON from stdout");
    (output.status.success(), json, stderr)
}

/// (1) THE issue #8 repro: `dataFetchSeq` defined ~170 lines after the
/// function that references it → exit 0 with the `let` hazard present.
#[test]
fn order_flags_issue8_datafetchseq_repro() {
    let dir = TempDir::new().expect("tempdir");
    let padding = 170;
    let file = write_file(&dir, "app.js", &repro_js_source(padding));

    let (success, json, stderr) = run_order_json(&file);
    assert!(success, "tldr order should exit 0; stderr = {}", stderr);
    // stderr must stay clean in json modes (convention: output.rs / N1).
    assert!(
        stderr.trim().is_empty(),
        "stderr should be empty in --format json; got: {}",
        stderr
    );

    assert_eq!(json["language"], "javascript");
    assert_eq!(json["file"], file.display().to_string());
    assert_eq!(json["issues"].as_array().expect("issues array").len(), 1);

    let issue = &json["issues"][0];
    assert_eq!(issue["symbol"], "dataFetchSeq");
    assert_eq!(issue["kind"], "let");
    assert_eq!(issue["use_line"], 2);
    // line 1-3: function, use, }; lines 4..(4+padding-1): padding comments;
    // the `let` lands on line 4 + padding.
    let expected_definition_line = 4 + padding as u64;
    assert_eq!(issue["definition_line"], expected_definition_line);
    assert!(issue["use_line"].as_u64() < issue["definition_line"].as_u64());
    assert_eq!(issue["snippet"], "return dataFetchSeq;");

    // function + let are both module-scope definitions.
    assert!(json["checked_definitions"].as_u64().expect("count") >= 2);
    // explanation is absent (skip_serializing_if) for a supported language.
    assert!(json.get("explanation").is_none());
}

/// (2) A clean file (definitions before uses) → zero issues, exit 0.
#[test]
fn order_clean_file_reports_zero_issues() {
    let dir = TempDir::new().expect("tempdir");
    let source = "\
const config = { name: 'app' };

function render() {
  return config.name;
}

render();
";
    let file = write_file(&dir, "clean.js", source);

    let (success, json, stderr) = run_order_json(&file);
    assert!(success, "tldr order should exit 0; stderr = {}", stderr);
    assert!(
        stderr.trim().is_empty(),
        "stderr should be empty; got {}",
        stderr
    );
    assert_eq!(
        json["issues"].as_array().expect("issues array").len(),
        0,
        "clean file must have zero issues: {}",
        json
    );
    assert!(json["checked_definitions"].as_u64().expect("count") >= 2);
}

/// (2') Python module-level read before its module-level assignment → flagged
/// through the CLI too.
#[test]
fn order_flags_python_module_level_read_before_assignment() {
    let dir = TempDir::new().expect("tempdir");
    let source = "print(config)\nconfig = {}\n";
    let file = write_file(&dir, "app.py", source);

    let (success, json, _) = run_order_json(&file);
    assert!(success, "tldr order should exit 0");
    assert_eq!(json["language"], "python");
    assert_eq!(json["issues"][0]["symbol"], "config");
    assert_eq!(json["issues"][0]["kind"], "assignment");
    assert_eq!(json["issues"][0]["use_line"], 1);
    assert_eq!(json["issues"][0]["definition_line"], 2);
}

/// (3) Missing file → clear non-zero error naming the path.
#[test]
fn order_missing_file_fails_with_clear_error() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("does_not_exist.js");

    let output = tldr_cmd()
        .args(["order", missing.to_str().expect("utf-8 path")])
        .output()
        .expect("run tldr order on missing file");

    assert!(!output.status.success(), "missing file must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Path not found"),
        "error should mention 'Path not found'; got: {}",
        stderr
    );
    assert!(
        stderr.contains("does_not_exist.js"),
        "error should name the missing path; got: {}",
        stderr
    );
}

/// (4) Unsupported language → graceful degradation: exit 0, zero issues,
/// explanation set (cf. issue #10).
#[test]
fn order_unsupported_language_is_graceful() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_file(&dir, "main.go", "func main() {}\n");

    let (success, json, _) = run_order_json(&file);
    assert!(success, "unsupported language must still exit 0");
    assert_eq!(
        json["issues"].as_array().expect("issues array").len(),
        0,
        "zero issues for unsupported language"
    );
    let explanation = json["explanation"]
        .as_str()
        .expect("explanation should be present for unsupported language");
    assert!(
        explanation.contains("not yet supported for go"),
        "explanation should name the language; got: {}",
        explanation
    );
}

/// (5) Text formatter: one `use-before-define:` line per issue + summary.
#[test]
fn order_text_format_lists_hazards() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_file(&dir, "app.js", &repro_js_source(4));

    let output = tldr_cmd()
        .args([
            "order",
            file.to_str().expect("utf-8 path"),
            "--format",
            "text",
        ])
        .output()
        .expect("run tldr order --format text");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Lines 1-3: function + use; lines 4-7: padding; line 8: the `let`.
    assert!(
        stdout.contains("use-before-define: dataFetchSeq (let) used at line 2, defined at line 8"),
        "text output should contain the hazard line; got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("return dataFetchSeq;"),
        "text output should include the use-line snippet"
    );
    assert!(
        stdout.contains("1 use-before-define hazard(s) found"),
        "text output should include the summary; got:\n{}",
        stdout
    );
}

/// (6) Global `--lang/-l` override works for extensionless files.
#[test]
fn order_respects_global_lang_override() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_file(&dir, "myscript", "print(config)\nconfig = {}\n");

    let output = tldr_cmd()
        .args([
            "--lang",
            "python",
            "order",
            file.to_str().expect("utf-8 path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run tldr order --lang python");

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert_eq!(json["language"], "python");
    assert_eq!(json["issues"][0]["symbol"], "config");
}
