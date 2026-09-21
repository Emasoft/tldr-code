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

// -----------------------------------------------------------------------------
// xml-navigation-v1 companion: the 100 MiB depth-filtered views (exact
// per-level counts, level-sum invariant, byte-exact depth probes) live in
// `tldr-core/tests/xml_navigation_v1.rs`. This pins the TEXT-MODE navigation
// surface on a MID-SIZE xml file (≈5.8 MB — big enough for the renderer's
// element cap to fire, small enough for a plain CLI run): the Elements
// section indents two spaces per nesting level (a node tree, not a flat
// dump), caps at 200 rendered rows, and fires the "… N more elements"
// summary line that points at the knobs.
// -----------------------------------------------------------------------------

/// Repetitions of the 12-level chain below → 120,000 elements at depths
/// 0..11 (10,000 units × 12).
const SNAPSHOT_UNITS: usize = 10_000;
/// Nesting levels per chain unit.
const SNAPSHOT_LEVELS: usize = 12;
/// One-level payload text (keeps units ~575 bytes ≈ 5.8 MB total).
const SNAPSHOT_PAYLOAD: &str = "mmmmmmmmmmmmmmmmmmmmmmmm";
/// The renderer's element cap (`output::STRUCTURE_TEXT_ELEMENT_CAP`; the
/// constant lives in the binary crate, so the value is pinned here).
const TEXT_ELEMENT_CAP: usize = 200;

/// One 12-level-deep chain unit: `<n0 id="u{i}d0">` … `<n11 id="u{i}d11">`,
/// each element opening on its own line with a payload line, then the 12
/// closing tags — 36 lines, 12 elements, ~575 bytes.
fn snapshot_unit(i: usize) -> String {
    let mut unit = String::new();
    for d in 0..SNAPSHOT_LEVELS {
        unit.push_str(&format!("<n{d} id=\"u{i}d{d}\">\n{SNAPSHOT_PAYLOAD}\n"));
    }
    for d in (0..SNAPSHOT_LEVELS).rev() {
        unit.push_str(&format!("</n{d}>\n"));
    }
    unit
}

fn run_structure_text(path: &Path, extra: &[&str]) -> String {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "structure",
            path.to_str().unwrap(),
            "-l",
            "xml",
            "-q",
            "-f",
            "text",
        ])
        .args(extra)
        .output()
        .expect("tldr structure must execute");
    assert!(
        output.status.success(),
        "tldr structure {extra:?} must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("text output must be UTF-8")
}

/// `--max-depth 2` on the 5 MB xml narrows the 120,000-element tree to the
/// 30,000 rows at depths ≤ 2; the text renderer then shows the first 200
/// rows INDENTED BY DEPTH and fires the cap summary line for the remaining
/// 29,800. Depth-0/1 rows appear (the tree shape is visible); depth-3 rows
/// are gone (the filter, not the renderer, removed them).
#[test]
fn text_mode_5mib_xml_max_depth_2_indented_tree_and_cap_line() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("big5.xml");
    let mut body = String::with_capacity(SNAPSHOT_UNITS * 560);
    for i in 0..SNAPSHOT_UNITS {
        body.push_str(&snapshot_unit(i));
    }
    assert!(
        body.len() >= 5 * 1024 * 1024,
        "the mid-size fixture must be ≥ 5 MB, got {} bytes",
        body.len()
    );
    fs::write(&path, body.as_bytes()).expect("write big5.xml fixture");

    let text = run_structure_text(&path, &["--max-depth", "2"]);

    // The Elements section renders as an indented node tree.
    assert!(text.contains("  Elements:\n"), "Elements section expected");

    // Depth-0 row: base indent + the unit-0 root of the chain.
    assert!(
        text.contains("    - element n0#u0d0 (L1-L36)\n"),
        "depth-0 element row expected in the indented tree"
    );
    // Depth-1 row: two extra spaces per nesting level.
    assert!(
        text.contains("      - element n1#u0d1 (L3-L35)\n"),
        "depth-1 element row expected, indented one level deeper"
    );
    // The filter removed depth ≥ 3 BEFORE rendering — none may appear.
    assert!(
        !text.contains("element n3#"),
        "depth-3 rows must be filtered out by --max-depth 2"
    );

    // The cap line: 30,000 kept rows − 200 rendered = 29,800 hidden.
    let expected_hidden = SNAPSHOT_UNITS * 3 - TEXT_ELEMENT_CAP;
    let expected_cap_line = format!(
        "    … {expected_hidden} more elements (use --max-depth to narrow, \
         --max-results to cap, -f json for all)\n"
    );
    assert!(
        text.contains(&expected_cap_line),
        "the 200-cap summary line must fire on a 120,000-element file; \
         expected {expected_hidden:?} hidden, got:\n{text}"
    );
}

// -----------------------------------------------------------------------------
// max_depth × max_results interplay (FIX-2 3g): BOTH knobs on one invocation
// over a multi-file directory. `--max-results 1` picks the surviving FILE
// (first in walk order), `--max-depth 1` then narrows THAT file's element
// tree, and the renderer's cap message still fires — carrying BOTH hint
// strings — because depth-filtering alone does not clear the 200-row cap.
//
// TIME-BOXED sizing: the knobs are element-count-driven, not byte-driven —
// 250 three-level units per file ≈ 750 elements each (17 KB), fast to parse
// while still 2.5× over the render cap. The byte-scale (5.8 MB) probe lives
// in the test above.
// -----------------------------------------------------------------------------

/// Units per interplay fixture file.
const INTERPLAY_UNITS: usize = 250;
/// One three-level chain unit: `<n0 id="u{i}i0">` → `<n1 id="u{i}i1">` →
/// `<n2 id="u{i}i2">`, 6 lines, 3 elements at depths 0/1/2.
fn interplay_unit(i: usize) -> String {
    format!("<n0 id=\"u{i}i0\">\n<n1 id=\"u{i}i1\">\n<n2 id=\"u{i}i2\">\n</n2>\n</n1>\n</n0>\n")
}

/// `--max-results 1 --max-depth 1` on a two-file directory: exactly one file
/// section survives, its depth-2 elements are gone (the depth filter ran on
/// the SURVIVING file, after the file quota), and the cap message fires with
/// both knob hints intact.
#[test]
fn max_results_1_with_max_depth_1_filters_the_surviving_file_and_keeps_both_hints() {
    let dir = TempDir::new().expect("tempdir");
    for (name, salt) in [("a.xml", 0), ("b.xml", 1_000_000)] {
        let mut body = String::with_capacity(INTERPLAY_UNITS * 48);
        for i in 0..INTERPLAY_UNITS {
            body.push_str(&interplay_unit(i + salt));
        }
        fs::write(dir.path().join(name), body.as_bytes())
            .unwrap_or_else(|e| panic!("write {name} fixture: {e}"));
    }

    let text = run_structure_text(dir.path(), &["--max-results", "1", "--max-depth", "1"]);

    // --max-results 1: the report carries exactly one file, the first in
    // walk order (a.xml); b.xml never appears anywhere in the output.
    assert!(
        text.contains("(1 files)"),
        "the file quota must keep exactly one file, got:\n{text}"
    );
    assert!(
        text.contains("a.xml"),
        "the surviving file section must be a.xml, got:\n{text}"
    );
    assert!(
        !text.contains("b.xml"),
        "the second file must be dropped by --max-results 1, got:\n{text}"
    );

    // --max-depth 1 applied to the SURVIVING file: depth-0/1 rows render
    // (indented by depth), depth-2 rows are filtered out before rendering.
    assert!(
        text.contains("    - element n0#u0i0 (L1-L6)\n"),
        "the surviving file's root-level rows must render, got:\n{text}"
    );
    assert!(
        text.contains("      - element n1#u0i1 (L2-L5)\n"),
        "depth-1 rows must render one level deeper, got:\n{text}"
    );
    assert!(
        !text.contains("element n2#"),
        "depth-2 rows must be filtered out by --max-depth 1 even though \
         --max-results already capped the files, got:\n{text}"
    );

    // The cap message: 2 depth-levels × 250 units = 500 kept rows − 200
    // rendered = 300 hidden — and BOTH knob hints stay in the line: the
    // depth filter did not clear the render cap, and the message still
    // points at both knobs.
    let expected_hidden = INTERPLAY_UNITS * 2 - TEXT_ELEMENT_CAP;
    let expected_cap_line = format!(
        "    … {expected_hidden} more elements (use --max-depth to narrow, \
         --max-results to cap, -f json for all)\n"
    );
    assert!(
        text.contains(&expected_cap_line),
        "the cap message must fire with both hint strings after both knobs \
         ran, expected {expected_hidden} hidden, got:\n{text}"
    );
}
