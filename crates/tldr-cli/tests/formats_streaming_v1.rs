//! formats-streaming-v1 (2025-09) — integration tests for the tree-sitter
//! formats extension + limits stretch.
//!
//! Pins four contracts end-to-end:
//!
//! 1. **JSONL streaming** (`tldr structure data.jsonl`): the file is
//!    processed ONE JSON document per row with bounded memory, and the row
//!    health stats ride the additive `jsonl_stream` field on CodeStructure.
//! 2. **First-invalid-row reporting**: an invalid row does not abort the
//!    stream; `rows_invalid` + `first_invalid_row` point at it.
//! 3. **Limits stretch regression** (limits-stretch-v1): a ~5.8 MB JS file
//!    (1.6k functions × ~3.8 KB) — inside the old parse-pool's 5 MB cap vs
//!    the old 10 MB policy gap that used to hard-fail with
//!    `File too large ... (max 5242880)` — now parses cleanly. Policy cap is
//!    2 GiB, pool cap 4 GiB. This one is a release-mode opt-in (`#[ignore]`,
//!    see the test's doc comment): the intra-file call-graph build is
//!    quadratic in function count for a fixed file size, so debug mode
//!    exceeds the sanctioned 600 s suite timeout at any >5 MB fixture.
//! 4. **JSON as a first-class language**: `tldr structure x.json` reports
//!    `language: "json"`. A sibling `.toml` case pins the whole formats
//!    class for single-file structure runs (single-file language resolution
//!    uses `Language::from_path` first — `from_directory` filters formats
//!    via `is_project_language_signal` and would fall back to Python).

use assert_cmd::Command;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write_jsonl(path: &Path, rows: &[&str]) {
    let mut f = fs::File::create(path).expect("create jsonl");
    for r in rows {
        writeln!(f, "{r}").expect("write row");
    }
}

/// (1) Valid JSONL: row stats ride `jsonl_stream`; language is json.
#[test]
fn structure_on_jsonl_streams_rows() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("data.jsonl");
    write_jsonl(
        &path,
        &[
            r#"{"name": "alice", "age": 30}"#,
            r#"{"name": "bob", "tags": [1, 2, 3]}"#,
            r#"{"name": "carol"}"#,
        ],
    );

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on jsonl");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");

    assert_eq!(json["language"], "json");
    assert_eq!(json["jsonl_stream"]["rows_total"], 3);
    assert_eq!(json["jsonl_stream"]["rows_valid"], 3);
    assert_eq!(json["jsonl_stream"]["rows_invalid"], 0);
    assert_eq!(
        json["jsonl_stream"]["bytes_processed"],
        fs::metadata(&path).unwrap().len()
    );
    // additive field absent-keys contract: no failures → no error keys
    assert!(json["jsonl_stream"].get("first_invalid_row").is_none());
    // per-file structure is the one-JSON-document shape (no functions).
    assert_eq!(json["files"].as_array().unwrap().len(), 1);
}

/// (2) An invalid row is reported, not fatal.
#[test]
fn structure_on_jsonl_reports_first_invalid_row() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("mixed.jsonl");
    write_jsonl(&path, &[r#"{"ok": 1}"#, "{broken", r#"{"also_ok": true}"#]);

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on mixed jsonl");

    assert!(
        output.status.success(),
        "invalid rows must not abort the stream"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["jsonl_stream"]["rows_total"], 3);
    assert_eq!(json["jsonl_stream"]["rows_valid"], 2);
    assert_eq!(json["jsonl_stream"]["rows_invalid"], 1);
    assert_eq!(json["jsonl_stream"]["first_invalid_row"], 2);
    assert!(json["jsonl_stream"]["first_error"].is_string());
}

/// (3) limits-stretch-v1 regression: a ~5.8 MB JS file (the old (5 MB, 10 MB]
/// dual-cap gap) parses end-to-end in release instead of hard-failing.
///
/// Fixture shape: [`GAP_FUNCTIONS`] functions × [`GAP_STATEMENTS`] statements
/// (~3.8 KB per function — several statements each, matching real code
/// density rather than one-liners).
///
/// **Why `#[ignore]`:** `get_code_structure`'s intra-file call-graph build
/// walks the whole syntax tree once per function
/// (`extract::build_intra_file_call_graph` → `find_and_extract_calls(root,
/// …)`), so debug-mode cost is quadratic in function count for a fixed file
/// size. Two fixture iterations (2.6k × 50 stmts, 1.5k × 85 stmts, both >5 MB)
/// were each killed by the sanctioned 600 s suite `timeout` in debug. The
/// release-mode run of this 1.6k-function fixture completes in ~4–5 minutes
/// (well inside the 900 s opt-in). Opt-in:
///
/// `timeout 900 cargo test -p tldr-cli --test formats_streaming_v1 --release -- --ignored structure_handles_file_in_old_dual_cap_gap`
const GAP_FUNCTIONS: usize = 1_600;
/// Statements per generated function (~88 × ~42 B ≈ 3.8 KB per body).
const GAP_STATEMENTS: usize = 88;

#[test]
#[ignore = "quadratic intra-file call-graph build makes debug mode exceed the 600 s suite timeout at >5 MB; run in release — see doc comment for the opt-in command"]
fn structure_handles_file_in_old_dual_cap_gap() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("big.js");
    let mut f = fs::File::create(&path).expect("create big.js");
    // 1,600 × ~3.8 KB ≈ 5.8 MB of valid JS: above the OLD 5 MB
    // parse-pool cap, below the OLD 10 MB policy cap — exactly the gap.
    for i in 0..GAP_FUNCTIONS {
        writeln!(f, "function gap{i}(a, b) {{").expect("write fn head");
        writeln!(f, "  const base{i} = a + b + {i};").expect("write base");
        for j in 0..GAP_STATEMENTS {
            writeln!(f, "  const v{i}_{j} = base{i} * {j} + a - b;").expect("write stmt");
        }
        writeln!(f, "  if (base{i} > 0) {{ return v{i}_0; }}").expect("write branch");
        writeln!(f, "  return base{i} + v{i}_{};", GAP_STATEMENTS - 1).expect("write ret");
        writeln!(f, "}}").expect("write fn tail");
    }
    drop(f);
    let size = fs::metadata(&path).unwrap().len();
    assert!(
        size > 5 * 1024 * 1024,
        "fixture must exceed the OLD 5 MB parse cap to exercise the old dual-cap gap; got {size} bytes"
    );
    assert!(
        size < 10 * 1024 * 1024,
        "fixture must stay below the OLD 10 MB policy cap; got {size} bytes"
    );

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "compact"])
        .output()
        .expect("run tldr structure on ~5.8MB js");

    assert!(
        output.status.success(),
        "file in the old (5,10] MB dual-cap gap must parse under the stretched caps \
         (was: hard exit 10); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    // No parse-error/skip indicator: `files_skipped` and `warnings` are
    // additive fields, omitted entirely on a clean end-to-end parse.
    assert!(
        json.get("files_skipped").is_none(),
        "clean parse must not report skipped files: {json}"
    );
    assert!(
        json.get("warnings").is_none(),
        "clean parse must not emit warnings: {json}"
    );
    let files = json["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "single-file input must yield one entry");
    let functions = files[0]["definitions"]
        .as_array()
        .expect("definitions array")
        .len();
    assert_eq!(
        functions, GAP_FUNCTIONS,
        "expected exactly the {GAP_FUNCTIONS} generated functions"
    );
}

/// (4) JSON is a first-class language through the CLI.
#[test]
fn structure_on_json_reports_language() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, r#"{"name": "tldr", "nested": {"ok": true}}"#).expect("write json");

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on json");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["language"], "json");
    // jsonl_stream stays absent for a non-JSONL file (additive-field rule).
    assert!(json.get("jsonl_stream").is_none());
    // element-extraction-v1: JSON surfaces its object properties as element
    // definitions (kind="key") through the same definitions array. The nested
    // key is its own definition; the array-less fixture pins 3 keys total.
    let defs = json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    let kinds: Vec<&str> = defs.iter().filter_map(|d| d["kind"].as_str()).collect();
    assert_eq!(
        kinds,
        vec!["key", "key", "key"],
        "expected key:nested, key:ok, key:name elements, got {defs:?}"
    );
    assert!(
        defs.iter()
            .all(|d| d["byte_start"].is_u64() && d["byte_end"].is_u64()),
        "format elements must carry byte_start/byte_end, got {defs:?}"
    );
}

/// (4b) Sibling pin for the whole formats class: a lone `.toml` file reports
/// `language: "toml"` through the same single-file resolution as the `.json`
/// case above (guards against another `is_project_language_signal` filter
/// leaking into per-file runs).
#[test]
fn structure_on_toml_reports_language() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "[package]\nname = \"tldr\"\nversion = \"0.1.0\"\n").expect("write toml");

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on toml");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["language"], "toml");
    // jsonl_stream stays absent for a non-JSONL file (additive-field rule).
    assert!(json.get("jsonl_stream").is_none());
    // element-extraction-v1: TOML sections + keys ride definitions too.
    let defs = json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    let kinds: Vec<&str> = defs.iter().filter_map(|d| d["kind"].as_str()).collect();
    assert_eq!(
        kinds,
        vec!["section", "key", "key"],
        "expected section:package + key:name + key:version elements, got {defs:?}"
    );
}

/// (4c) YAML sibling: element kinds flow through the CLI for yaml as well
/// (document + top-level keys), completing the json/yaml/toml trio of the
/// element-extraction-v1 batch.
#[test]
fn structure_on_yaml_reports_language() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.yaml");
    fs::write(&path, "name: tldr\nmode: fast\n").expect("write yaml");

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on yaml");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["language"], "yaml");
    assert!(json.get("jsonl_stream").is_none());
    let defs = json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    let kinds: Vec<&str> = defs.iter().filter_map(|d| d["kind"].as_str()).collect();
    assert_eq!(
        kinds,
        vec!["document", "key", "key"],
        "expected document-1 + key:name + key:mode elements, got {defs:?}"
    );
    assert!(
        defs.iter()
            .any(|d| d["name"] == "document-1" && d["kind"] == "document"),
        "the yaml document element must be named document-1, got {defs:?}"
    );
}

/// (4d) Markdown sibling — the mislabel fix (markdown batch, 2026-09). Before
/// `.md` mapped to `Language::Markdown`, `Language::from_path("README.md")`
/// returned `None`, so a single-file `tldr structure README.md` fell back to
/// directory autodetect and mislabeled the file (measured: reported "rust").
/// Now `.md` resolves directly and the report says `language: "markdown"`,
/// with headings/code blocks/tables riding the definitions array.
#[test]
fn structure_on_markdown_reports_language() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(
        &path,
        "# Title\n\nProse paragraph.\n\n```rust\nfn main() {}\n```\n\n| A | B |\n| - | - |\n| 1 | 2 |\n",
    )
    .expect("write markdown");

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on markdown");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        json["language"], "markdown",
        "single-file structure on a .md must report language \"markdown\" \
         (from_path resolves it — the single-file fallback mislabel is fixed)"
    );
    assert!(json.get("jsonl_stream").is_none());
    // element-extraction-v1: markdown elements ride definitions too —
    // heading + code-block (info-string named) + table (header-row named).
    let defs = json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    let kinds: Vec<&str> = defs.iter().filter_map(|d| d["kind"].as_str()).collect();
    assert_eq!(
        kinds,
        vec!["heading", "code-block", "table"],
        "expected heading:Title + code-block:rust + table:A | B elements, got {defs:?}"
    );
    assert!(
        defs.iter()
            .any(|d| d["name"] == "rust" && d["kind"] == "code-block"),
        "the ```rust fenced block must be named after its info-string language, got {defs:?}"
    );
    assert!(
        defs.iter()
            .any(|d| d["name"] == "A | B" && d["kind"] == "table"),
        "the pipe table must be named after its header-row cells, got {defs:?}"
    );
    assert!(
        defs.iter()
            .all(|d| d["byte_start"].is_u64() && d["byte_end"].is_u64()),
        "format elements must carry byte_start/byte_end, got {defs:?}"
    );
}

/// (5) `tldr order` on an out-of-MVP format answers instantly (no full-file
/// read) with the graceful explanation — exit 0, zero issues.
#[test]
fn order_on_jsonl_and_json_answers_gracefully() {
    let dir = TempDir::new().unwrap();
    let jsonl = dir.path().join("data.jsonl");
    write_jsonl(&jsonl, &[r#"{"a": 1}"#]);
    let json = dir.path().join("config.json");
    fs::write(&json, r#"{"a": 1}"#).expect("write json");

    for f in [&jsonl, &json] {
        let output = tldr_cmd()
            .args(["order", f.to_str().unwrap(), "-f", "json"])
            .output()
            .expect("run tldr order");
        assert!(
            output.status.success(),
            "order must exit 0 for {}",
            f.display()
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(json["issues"].as_array().unwrap().len(), 0);
        let explanation = json["explanation"].as_str().expect("explanation present");
        assert!(
            explanation.contains("not yet supported for json"),
            "explanation should name json: {explanation}"
        );
    }
}
