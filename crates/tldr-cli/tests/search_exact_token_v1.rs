//! search-exact-token-v1 (issue #9): `tldr search` must find exact-token
//! occurrences (recall) and rank them above irrelevant hits.
//!
//! Issue repro (verbatim): `tldr search 'dres' public/app.js` on a ~1180-line
//! JS file returned ONE low-score hit at lines 14-16 (a `rescanClicks` state
//! comment that does NOT contain the token) while the real occurrences at
//! ~979-980 (`const dres = fetch('/api/data');`) were NOT returned.
//!
//! Root cause: the BM25 engine indexes the whole file as one document and
//! picked its single snippet window with first-max *substring* containment,
//! so a line merely containing the query token inside a larger word
//! ("addresses" ⊃ "dres") near the top of the file hijacked the window from
//! the real exact-token occurrences further down.
//!
//! These tests pin the fixed behavior:
//! 1. hits include the real exact-token lines,
//! 2. the top hit is the exact-token occurrence,
//! 3. hits carry `match_type: "exact"` and substring-only noise is absent,
//! 4. disjoint exact clusters are each surfaced,
//! 5. result caps stay explicit via `-k/--top-k`.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// The 1-indexed line holding `const dres = fetch('/api/data');`.
const DRES_LINE_1: usize = 979;
/// The 1-indexed line holding `console.log(dres.status);`.
const DRES_LINE_2: usize = 980;
/// Total fixture length (~1180-line file in the issue; we generate 1200).
const TOTAL_LINES: usize = 1200;

/// Build the issue-shaped fixture as a vector of lines.
///
/// Layout:
/// - line 2: the substring trap from the repro — a `rescanClicks` state
///   comment whose word "addresses" contains `dres` as a substring but
///   never as a whole token;
/// - lines 4..979: filler JS functions;
/// - lines 979-980: the ONLY whole-token `dres` occurrences, at the top
///   level (outside any function) so they map to module-level cards;
/// - padding to 1200 lines.
fn build_fixture_lines() -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push("// App shell bootstrap.".to_string());
    lines.push(
        "// rescanClicks state: addresses stale UI flags after a rescan.".to_string(),
    );
    lines.push("// See the rescan scheduler for details.".to_string());

    // Filler functions until just before the real occurrences.
    let mut i = 0usize;
    while lines.len() + 4 <= DRES_LINE_1 - 1 {
        lines.push(format!("function filler_{}(alpha, beta) {{", i));
        lines.push(format!("  const sum_{} = alpha + beta + {};", i, i));
        lines.push(format!("  return sum_{};", i));
        lines.push("}".to_string());
        i += 1;
    }
    while lines.len() < DRES_LINE_1 - 1 {
        lines.push(String::new());
    }

    // The real occurrences (lines 979-980, 1-indexed).
    lines.push("const dres = fetch('/api/data');".to_string());
    lines.push("console.log(dres.status);".to_string());

    // Blank padding up to the target size (blank lines keep tree-sitter
    // structure entries away from the match windows).
    while lines.len() < TOTAL_LINES {
        lines.push(String::new());
    }
    lines
}

/// Fixture with TWO disjoint exact-token clusters, to pin multi-window
/// recall (the engine must not collapse everything into one snippet).
fn build_two_cluster_fixture() -> String {
    let mut lines: Vec<String> = Vec::new();
    // Cluster 1: lines 1-2.
    lines.push("const dres = fetch('/api/data');".to_string());
    lines.push("console.log(dres.status);".to_string());

    let cluster_2_start = 304usize; // 1-indexed
    let mut i = 0usize;
    while lines.len() + 4 <= cluster_2_start - 2 {
        lines.push(format!("function filler_{}(alpha, beta) {{", i));
        lines.push(format!("  const total_{} = alpha + beta + {};", i, i));
        lines.push(format!("  return total_{};", i));
        lines.push("}".to_string());
        i += 1;
    }
    // Blank separator so the window before cluster 2 touches no function.
    while lines.len() < cluster_2_start - 1 {
        lines.push(String::new());
    }
    // Cluster 2.
    lines.push("const dresRetry = revalidate(dres);".to_string());
    lines.push("console.log(dresRetry.status);".to_string());
    while lines.len() < 400 {
        lines.push(String::new());
    }
    lines.join("\n") + "\n"
}

/// Write the issue-shaped fixture and verify its invariant: `dres` occurs
/// only on the trap comment line (2, via "addresses") and the two real
/// lines (979-980).
fn write_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let lines = build_fixture_lines();
    assert_eq!(lines.len(), TOTAL_LINES, "fixture must have {TOTAL_LINES} lines");
    assert_eq!(
        lines[DRES_LINE_1 - 1],
        "const dres = fetch('/api/data');",
        "fixture line 979 must hold the real occurrence"
    );
    assert_eq!(
        lines[DRES_LINE_2 - 1],
        "console.log(dres.status);",
        "fixture line 980 must hold the real occurrence"
    );
    let containing: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.to_lowercase().contains("dres"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(
        containing,
        vec![2, DRES_LINE_1, DRES_LINE_2],
        "fixture must contain 'dres' only on the trap comment line and the two real lines"
    );

    let path = dir.join("app.js");
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    path
}

/// True when a result card's line_range covers the real occurrence lines.
fn covers_real_lines(result: &serde_json::Value) -> bool {
    let range = result["line_range"].as_array().expect("line_range array");
    let start = range[0].as_u64().expect("line_range start") as usize;
    let end = range[1].as_u64().expect("line_range end") as usize;
    start <= DRES_LINE_1 && end >= DRES_LINE_2
}

/// Run `tldr search 'dres' <file> --format json` with an explicit cap.
fn run_search(file: &std::path::Path, top_k: &str) -> (std::process::Output, serde_json::Value) {
    let output = tldr_cmd()
        .args([
            "search",
            "dres",
            file.to_str().unwrap(),
            "--format",
            "json",
            "-k",
            top_k,
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be a JSON report ({e}): {stdout}"));
    (output, report)
}

#[test]
fn exact_token_hits_are_returned_and_ranked_first() {
    let temp = TempDir::new().unwrap();
    let file = write_fixture(temp.path());

    let (output, report) = run_search(&file, "10");
    assert!(
        output.status.success(),
        "search command should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let results = report["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "searching for 'dres' must return hits; got none. report: {report}"
    );

    // (a) Recall: the real occurrences at lines 979-980 must be returned.
    assert!(
        results.iter().any(covers_real_lines),
        "hits must include lines {DRES_LINE_1}-{DRES_LINE_2}; got: {results:?}"
    );

    // (b) Ranking: the TOP hit is the exact-token occurrence, not the
    // substring-only comment near the top of the file.
    assert!(
        covers_real_lines(&results[0]),
        "top hit must cover lines {DRES_LINE_1}-{DRES_LINE_2}; got: {}",
        results[0]
    );
    let top_text = results[0].to_string();
    assert!(
        top_text.contains("dres"),
        "top hit must reference the searched token; got: {top_text}"
    );

    // (c) Labels: every hit is a whole-token (exact) match.
    for result in results {
        assert_eq!(
            result["match_type"].as_str(),
            Some("exact"),
            "hit must be labeled exact; got: {result}"
        );
    }

    // (d) The old buggy hit — the `rescanClicks` state comment whose only
    // link to the query is the substring "dres" inside "addresses" — must
    // not surface at all.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("rescanClicks"),
        "substring-only comment must not be returned as a hit; stdout: {stdout}"
    );
}

#[test]
fn disjoint_exact_occurrences_are_each_surfaced() {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("two_clusters.js");
    fs::write(&file, build_two_cluster_fixture()).unwrap();

    let (output, report) = run_search(&file, "10");
    assert!(
        output.status.success(),
        "search command should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let results = report["results"].as_array().expect("results array");
    assert!(
        results.len() >= 2,
        "both disjoint exact clusters must be surfaced as separate hits; got: {results:?}"
    );

    // Cluster 1 sits at lines 1-2.
    assert!(
        results
            .iter()
            .any(|r| r["line_range"][0].as_u64().unwrap() <= 1
                && r["line_range"][1].as_u64().unwrap() >= 1),
        "cluster 1 (line 1) must be covered; got: {results:?}"
    );
    // Cluster 2 sits at lines 304-305.
    let retry_line: u64 = 304;
    assert!(
        results
            .iter()
            .any(|r| r["line_range"][0].as_u64().unwrap() <= retry_line
                && r["line_range"][1].as_u64().unwrap() >= retry_line + 1),
        "cluster 2 (lines 304-305) must be covered; got: {results:?}"
    );
    for result in results {
        assert_eq!(
            result["match_type"].as_str(),
            Some("exact"),
            "all hits must be exact whole-token matches; got: {result}"
        );
    }
}

#[test]
fn explicit_top_k_cap_is_respected() {
    // Caps must stay explicit: with `-k 1` exactly one hit is returned and
    // it is the exact-token occurrence (not the substring-only comment).
    let temp = TempDir::new().unwrap();
    let file = write_fixture(temp.path());

    let (output, report) = run_search(&file, "1");
    assert!(
        output.status.success(),
        "search command should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let results = report["results"].as_array().expect("results array");
    assert_eq!(
        results.len(),
        1,
        "-k 1 must cap the output at one hit; got: {results:?}"
    );
    assert!(
        covers_real_lines(&results[0]),
        "the single hit must be the exact-token occurrence; got: {}",
        results[0]
    );
}
