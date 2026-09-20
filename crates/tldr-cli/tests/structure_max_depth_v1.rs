//! structure-max-depth-v1 — `tldr structure --max-depth N` e2e (CLI).
//!
//! CONTRACT UNDER TEST (markup-node-tree-v1):
//!
//! `--max-depth N` narrows the markup element tree to depth `<= N`
//! (root-level elements are depth 0). Depth-less definitions (inner-CSS
//! selectors, code symbols, json keys, …) are NEVER filtered — they carry no
//! markup-nesting semantics. JSON output stays complete and now carries the
//! `depth` field on markup element rows; rows without depth omit the key
//! (additive serde contract).
//!
//! The direct-compute path and the daemon-served path apply the SAME filter
//! (`filter_structure_max_depth`); these tests run the real binary, which
//! falls back to direct compute when no daemon is up — the daemon-side
//! parity pin lives in `daemon_contract_coverage_test.rs`.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

/// The pinned HTML fixture (element depths: html 0, head 1, title 2,
/// style 2, body#main 1, script 2, p 2, br 2 — plus one depth-less
/// inner-CSS `selector` row `body` from the style body).
const PAGE_HTML: &str = "\
<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <title>Page</title>
    <style>body { color: red; }</style>
  </head>
  <body id=\"main\">
    <script src=\"app.js\"></script>
    <p>Hello</p>
    <br/>
  </body>
</html>
";

fn write_page(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("page.html");
    fs::write(&path, PAGE_HTML).expect("write page.html fixture");
    path
}

fn run_structure(path: &Path, extra: &[&str]) -> Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "structure",
            path.to_str().unwrap(),
            "-l",
            "html",
            "-f",
            "json",
            "-q",
        ])
        .args(extra)
        .output()
        .expect("tldr structure must execute");
    assert!(
        output.status.success(),
        "tldr structure {extra:?} must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("structure JSON output must parse")
}

fn element_rows(report: &Value) -> Vec<(String, Option<u32>)> {
    report["files"][0]["definitions"]
        .as_array()
        .expect("definitions array")
        .iter()
        .filter(|d| d["kind"] == "element")
        .map(|d| {
            (
                d["name"].as_str().unwrap_or_default().to_string(),
                d["depth"].as_u64().map(|n| n as u32),
            )
        })
        .collect()
}

/// `--max-depth 1` keeps only the root and first-level elements; the deeper
/// ones (and the style body's element row) are gone, while the depth-less
/// `selector` row survives. Every surviving element carries `depth` in JSON.
#[test]
fn cli_max_depth_1_keeps_root_and_first_level_elements_only() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_page(dir.path());

    let report = run_structure(&path, &["--max-depth", "1"]);
    let elements = element_rows(&report);
    assert_eq!(
        elements,
        vec![
            ("html".to_string(), Some(0)),
            ("head".to_string(), Some(1)),
            ("body#main".to_string(), Some(1)),
        ],
        "--max-depth 1 must keep exactly the depth <= 1 markup elements"
    );

    // The depth-less selector row survived the filter (it has no depth
    // semantics) and omits the additive `depth` key from JSON.
    let defs = report["files"][0]["definitions"].as_array().unwrap();
    assert_eq!(defs.len(), 4, "3 elements + 1 depth-less selector row");
    let selector = defs
        .iter()
        .find(|d| d["kind"] == "selector")
        .expect("the inner-CSS selector row must survive --max-depth");
    assert_eq!(selector["name"], "body");
    assert!(
        selector.get("depth").is_none(),
        "depth-less rows omit the additive depth key: {selector}"
    );
}

/// `--max-depth 0` keeps only root-level elements (plus depth-less rows);
/// the unfiltered default run still returns the full element set, and every
/// element row carries its `depth` in JSON (the additive machine contract).
#[test]
fn cli_max_depth_0_and_the_unfiltered_default_run() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_page(dir.path());

    let report = run_structure(&path, &["--max-depth", "0"]);
    assert_eq!(
        element_rows(&report),
        vec![("html".to_string(), Some(0))],
        "--max-depth 0 keeps only the root element"
    );

    let report = run_structure(&path, &[]);
    let elements = element_rows(&report);
    assert_eq!(
        elements,
        vec![
            ("html".to_string(), Some(0)),
            ("head".to_string(), Some(1)),
            ("title".to_string(), Some(2)),
            ("style".to_string(), Some(2)),
            ("body#main".to_string(), Some(1)),
            ("script".to_string(), Some(2)),
            ("p".to_string(), Some(2)),
            ("br".to_string(), Some(2)),
        ],
        "the default run (no --max-depth) is unfiltered and every element \
         carries its nesting depth"
    );
}
