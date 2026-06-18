//! calls-edge-limit-v1 (v0.4.2 cluster M-003):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 M-003):
//! > "`tldr calls` returns at most 200 edges across all langs with
//! >  `truncated:true` flag, but the full edge count can be 207 (csharp),
//! >  676 (elixir), 2570 (kotlin), 2964 (lua), 7110 (swift), 440 (typescript).
//! >  Hardcoded display cap with no override. Affects downstream commands
//! >  consuming the truncated graph."
//!
//! Verdict: REAL BUG. The CLI hardcoded `--max-items` default of 200 was
//! applied unconditionally to ALL output formats including JSON. JSON
//! consumers (downstream tooling, hand-rolled callers, agentic clients)
//! expect the *full* call graph and have no UX motive for the truncation —
//! the cap was a text-pretty-print heuristic that leaked into the data API.
//!
//! Fix (this v1):
//!   - JSON format: emit ALL edges. `truncated:false`,
//!     `shown_edges == total_edges`, regardless of `--max-items`.
//!   - Text / DOT format: keep the user-controllable cap (default 200) and
//!     print a stderr warning when truncation fires.
//!   - `--max-items` (alias `--limit`) remains the override for text/DOT.
//!
//! Tests are real-repo gated; skip with a printed reason when the corpus
//! is not present (matches the pattern used elsewhere in this test suite).

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


use std::path::Path;
use std::process::Command;

const KOTLIN_CORPUS: &str = "/tmp/repos/kotlin-datetime";
const SWIFT_CORPUS: &str = "/tmp/repos/swift-collections";

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
// TEST 1: kotlin — JSON must contain ALL edges, not 200.
//
// Pre-fix: shown_edges=200, total_edges=2570, truncated=true.
// Post-fix: shown_edges=total_edges (>= 207 — kotlin-datetime reported 2570),
//           truncated=false, edges array length matches total.
// =============================================================================
#[test]
fn calls_json_kotlin_emits_all_edges() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "[skip] calls_json_kotlin_emits_all_edges: corpus {} not present",
            KOTLIN_CORPUS
        );
        return;
    }

    let (rc, stdout, stderr) = run_tldr(&["calls", KOTLIN_CORPUS, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "calls on a real repo must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("calls JSON output must be valid JSON");
    let edges = v["edges"]
        .as_array()
        .expect("`edges` must be a JSON array");
    let total_edges = v["total_edges"]
        .as_u64()
        .expect("`total_edges` must be a u64");
    let shown_edges = v["shown_edges"]
        .as_u64()
        .expect("`shown_edges` must be a u64");
    let truncated = v["truncated"]
        .as_bool()
        .expect("`truncated` must be a bool");

    // Sanity: the corpus is known to produce > 200 edges. If a future
    // change shrinks the corpus below 200 this assertion is the canary.
    assert!(
        total_edges > 200,
        "kotlin-datetime is expected to produce > 200 edges; got total={}",
        total_edges
    );

    // CORE: JSON must NOT truncate.
    assert_eq!(
        edges.len() as u64,
        total_edges,
        "JSON `edges` array length ({}) must equal `total_edges` ({}) — \
         the 200-edge cap must not apply to --format json",
        edges.len(),
        total_edges
    );
    assert_eq!(
        shown_edges, total_edges,
        "shown_edges ({}) must equal total_edges ({}) for JSON output",
        shown_edges, total_edges
    );
    assert!(
        !truncated,
        "truncated must be false for JSON output (got true); total={}, shown={}",
        total_edges, shown_edges
    );
}

// =============================================================================
// TEST 2: swift — same invariant on a much larger corpus (7110 edges in
// audit data). Guards against any per-language regression and confirms the
// cap removal scales — JSON must emit thousands of edges.
// =============================================================================
#[test]
fn calls_json_swift_emits_all_edges() {
    if !corpus_ready(SWIFT_CORPUS) {
        eprintln!(
            "[skip] calls_json_swift_emits_all_edges: corpus {} not present",
            SWIFT_CORPUS
        );
        return;
    }

    let (rc, stdout, stderr) = run_tldr(&["calls", SWIFT_CORPUS, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "calls on swift corpus must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("calls JSON output must be valid JSON");
    let edges = v["edges"]
        .as_array()
        .expect("`edges` must be a JSON array");
    let total_edges = v["total_edges"]
        .as_u64()
        .expect("`total_edges` must be a u64");
    let truncated = v["truncated"]
        .as_bool()
        .expect("`truncated` must be a bool");

    assert!(
        total_edges > 1000,
        "swift-collections expected to produce > 1000 edges; got total={}",
        total_edges
    );
    assert_eq!(
        edges.len() as u64,
        total_edges,
        "JSON `edges` array length must equal `total_edges` for swift; \
         edges={}, total={}",
        edges.len(),
        total_edges
    );
    assert!(
        !truncated,
        "truncated must be false for JSON on swift; total={}",
        total_edges
    );
}

// =============================================================================
// TEST 3: text format DOES still honour the cap and reports the truncation
// on stderr — the cap is a UX-only mechanism for pretty-printing and must
// remain (with an audible warning) so terminal sessions don't dump 7k lines.
// =============================================================================
#[test]
fn calls_text_keeps_cap_and_warns() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "[skip] calls_text_keeps_cap_and_warns: corpus {} not present",
            KOTLIN_CORPUS
        );
        return;
    }

    let (rc, stdout, stderr) = run_tldr(&["calls", KOTLIN_CORPUS, "--format", "text", "-q"]);
    assert_eq!(
        rc, 0,
        "calls text on kotlin must succeed; got rc={}, stderr=\n{}",
        rc, stderr
    );

    // Count edge lines (those containing " -> ").
    let edge_lines = stdout.lines().filter(|l| l.contains(" -> ")).count();

    // Cap is 200 by default; text output may still include more than 200
    // for small repos but for kotlin-datetime (2570 edges) it must cap.
    assert!(
        edge_lines <= 200,
        "text format must respect --max-items cap (default 200); \
         saw {} edge lines",
        edge_lines
    );

    // Truncation warning must be on stderr to alert the user.
    assert!(
        stderr.to_lowercase().contains("truncat")
            || stderr.contains("--max-items")
            || stderr.contains("--limit"),
        "text-format truncation must print a stderr warning mentioning \
         truncation or --max-items / --limit; got stderr=\n{}",
        stderr
    );
}

// =============================================================================
// TEST 4: --max-items override on text format must produce MORE rows than
// the default 200 cap, proving the flag works and is wired through.
// =============================================================================
#[test]
fn calls_text_max_items_override() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "[skip] calls_text_max_items_override: corpus {} not present",
            KOTLIN_CORPUS
        );
        return;
    }

    let (rc, stdout, _stderr) = run_tldr(&[
        "calls",
        KOTLIN_CORPUS,
        "--format",
        "text",
        "--max-items",
        "500",
        "-q",
    ]);
    assert_eq!(rc, 0, "calls text with --max-items 500 must succeed");

    let edge_lines = stdout.lines().filter(|l| l.contains(" -> ")).count();
    assert!(
        edge_lines > 200,
        "--max-items 500 must produce more than 200 edge rows; got {}",
        edge_lines
    );
    assert!(
        edge_lines <= 500,
        "--max-items 500 must produce at most 500 edge rows; got {}",
        edge_lines
    );
}
