//! slice-contiguous-v1 (issue #4) — `tldr slice` must stop being a silent
//! code-deletion hazard.
//!
//! A dataflow slice is a sparse set of lines; before this change the CLI
//! emitted it with no indication that the code between slice lines had been
//! dropped, inviting consumers to read/reconstruct/edit from slice output as
//! if it were contiguous source. Verifies:
//!
//! - default JSON carries the exact non-contiguous warning in `warnings`
//!   (and `elided_count` stays absent);
//! - `--contiguous` JSON covers the full first..=last span, renders every
//!   non-slice span line as a language-appropriate elision marker with
//!   `elided: true`, reports the same count in `elided_count`, keeps
//!   `warnings` empty, and leaves slice-member lines' real code and the
//!   `lines` field untouched;
//! - text mode prints the first-line warning banner in default mode and the
//!   contiguous-view header + markers in `--contiguous` mode.
//!
//! Fixture note: `fixtures/simple.py::main` cannot exercise elision — its
//! backward slices cover every body line, leaving no gap in the span — so
//! the temp project includes a noise line that is dataflow-unrelated to the
//! slicing criterion.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Exact warning text (must match `NON_CONTIGUOUS_WARNING` in
/// `crates/tldr-cli/src/commands/slice.rs`).
const NON_CONTIGUOUS_WARNING: &str =
    "dataflow slice — NOT contiguous source; do not reconstruct or edit from this output";

const CONTIGUOUS_HEADER: &str = "contiguous view — elided lines shown as markers";
const PYTHON_ELISION_MARKER: &str = "# ... elided";

/// Temp Python project: `flow` has a dataflow chain (`x` -> `y` -> `return y`)
/// plus a dataflow-unrelated noise line inside the span, so the backward
/// slice from the return leaves a visible gap.
fn make_python_project() -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("flow.py");
    fs::write(
        &file,
        r#"def helper_noise():
    return 7


def flow():
    x = 1
    noise = helper_noise()
    y = x + 1
    return y
"#,
    )
    .unwrap();
    (temp, file.to_str().unwrap().to_string())
}

/// Run `tldr slice <file> flow 9 --format json [extra...]` and parse stdout.
fn slice_json(file: &str, extra: &[&str]) -> Value {
    let mut args: Vec<&str> = vec!["slice", file, "flow", "9", "--format", "json"];
    args.extend_from_slice(extra);
    let output = tldr_cmd()
        .args(&args)
        .output()
        .expect("failed to execute tldr slice");
    assert!(
        output.status.success(),
        "tldr slice should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("slice stdout must be valid JSON")
}

fn criterion_lines(json: &Value) -> Vec<u32> {
    json["lines"]
        .as_array()
        .expect("`lines` array must be present")
        .iter()
        .map(|v| v.as_u64().unwrap() as u32)
        .collect()
}

// =============================================================================
// (a) default JSON carries the exact non-contiguous warning
// =============================================================================

#[test]
fn test_default_json_warns_not_contiguous() {
    let (_temp, file) = make_python_project();

    let json = slice_json(&file, &[]);

    let warnings = json["warnings"].as_array().expect("warnings field present");
    assert_eq!(
        warnings.len(),
        1,
        "default mode should carry exactly one warning"
    );
    assert_eq!(warnings[0].as_str().unwrap(), NON_CONTIGUOUS_WARNING);

    // `elided_count` only appears in --contiguous mode (skipped when 0).
    assert!(json.get("elided_count").is_none());

    // Default-mode slice_lines are never elided.
    for sl in json["slice_lines"].as_array().unwrap() {
        assert!(
            sl.get("elided").is_none(),
            "default mode must not elide: {sl}"
        );
    }

    // `lines` semantics unchanged: criterion-slice lines only, non-empty.
    let lines = criterion_lines(&json);
    assert!(!lines.is_empty());
    assert_eq!(
        lines.len(),
        json["line_count"].as_u64().unwrap() as usize,
        "line_count must stay the criterion-slice line count"
    );
}

// =============================================================================
// (b) --contiguous JSON: full span, markers, elided_count, real code
// =============================================================================

#[test]
fn test_contiguous_json_full_span_with_markers() {
    let (_temp, file) = make_python_project();

    let json = slice_json(&file, &["--contiguous"]);

    // `warnings` stays empty in contiguous mode (field skipped when empty).
    assert!(
        json.get("warnings").is_none(),
        "--contiguous output must have no warnings, got: {:?}",
        json.get("warnings")
    );

    let lines = criterion_lines(&json);
    assert!(!lines.is_empty(), "fixture must produce a non-empty slice");
    let first = *lines.iter().min().unwrap();
    let last = *lines.iter().max().unwrap();

    let slice_lines = json["slice_lines"].as_array().unwrap();
    let span_lines: Vec<u32> = slice_lines
        .iter()
        .map(|sl| sl["line"].as_u64().unwrap() as u32)
        .collect();
    let expected: Vec<u32> = (first..=last).collect();
    assert_eq!(
        span_lines, expected,
        "slice_lines must cover the full first..=last span in order"
    );

    // Elided markers present, flagged elided:true, and counted.
    let elided: Vec<&Value> = slice_lines
        .iter()
        .filter(|sl| sl["elided"].as_bool() == Some(true))
        .collect();
    assert!(
        !elided.is_empty(),
        "fixture span must contain at least one elided (non-slice) line"
    );
    for sl in &elided {
        assert_eq!(
            sl["code"].as_str().unwrap(),
            PYTHON_ELISION_MARKER,
            "elided line must render the language marker, got: {sl}"
        );
        assert!(
            sl.get("definitions").is_none() && sl.get("uses").is_none(),
            "elided lines carry no dataflow metadata: {sl}"
        );
    }
    assert_eq!(
        elided.len() as u64,
        json["elided_count"].as_u64().unwrap(),
        "elided_count must equal the number of elided:true lines"
    );

    // Slice-member lines still carry their real code — never the marker.
    for &line in &lines {
        let sl = slice_lines
            .iter()
            .find(|sl| sl["line"].as_u64().unwrap() == line as u64)
            .unwrap_or_else(|| panic!("slice_lines missing criterion line {line}"));
        assert_ne!(
            sl["elided"].as_bool(),
            Some(true),
            "slice line {line} must not be elided"
        );
        let code = sl["code"].as_str().unwrap();
        assert!(!code.is_empty(), "slice line {line} must keep real code");
        assert_ne!(code, PYTHON_ELISION_MARKER);
    }

    // Elided lines must never leak into `lines` (criterion lines only).
    for sl in &elided {
        let line = sl["line"].as_u64().unwrap() as u32;
        assert!(
            !lines.contains(&line),
            "elided line {line} must not appear in `lines`"
        );
    }
}

/// `lines` (criterion slice lines) is identical in both modes.
#[test]
fn test_contiguous_keeps_lines_semantics() {
    let (_temp, file) = make_python_project();

    let default_json = slice_json(&file, &[]);
    let contiguous_json = slice_json(&file, &["--contiguous"]);
    assert_eq!(
        criterion_lines(&default_json),
        criterion_lines(&contiguous_json),
        "`lines` semantics must not change under --contiguous"
    );
}

// =============================================================================
// (c) text mode: banner (default) / contiguous header + markers
// =============================================================================

#[test]
fn test_text_mode_warns_banner() {
    let (_temp, file) = make_python_project();

    let output = tldr_cmd()
        .args(["slice", &file, "flow", "9", "--format", "text"])
        .output()
        .expect("failed to execute tldr slice");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let banner = format!("WARNING: {NON_CONTIGUOUS_WARNING}");
    assert!(
        stdout.starts_with(&banner),
        "default text output must open with the warning banner, got:\n{stdout}"
    );
    // Existing rows/behavior preserved.
    assert!(stdout.contains("Program Slice"));
    assert!(stdout.contains("x = 1"));
    assert!(stdout.contains("return y"));
    // No contiguous header in default mode.
    assert!(!stdout.contains(CONTIGUOUS_HEADER));
}

#[test]
fn test_contiguous_text_header_and_markers() {
    let (_temp, file) = make_python_project();

    let output = tldr_cmd()
        .args([
            "slice",
            &file,
            "flow",
            "9",
            "--format",
            "text",
            "--contiguous",
        ])
        .output()
        .expect("failed to execute tldr slice");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(CONTIGUOUS_HEADER),
        "contiguous text output must print the header, got:\n{stdout}"
    );
    assert!(
        stdout.contains(PYTHON_ELISION_MARKER),
        "contiguous text output must show elision markers, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("WARNING:"),
        "contiguous mode must not carry the non-contiguous warning"
    );
    // Real slice code is still shown alongside the markers.
    assert!(stdout.contains("x = 1"));
    assert!(stdout.contains("return y"));
}
