//! determinism-and-stderr-hygiene-v1 — regression tests for 4 bugs:
//!
//! - BUG-1: `tldr vuln` exited with code 2 and "Error: N findings detected"
//!   on stderr whenever a scan completed with a non-empty findings list,
//!   making every successful-with-findings run look like a tool failure.
//! - BUG-2: `tldr clones` produced non-deterministic `clone_pairs` ordering
//!   (and, when `max_clones` truncated, even DIFFERENT pairs) across runs
//!   because hash-bucket walks used DefaultHasher iteration order.
//! - BUG-3: `tldr hubs` PageRank produced last-digit float drift AND
//!   non-deterministic top-N because the iterative reduction walked a
//!   HashSet of nodes per iteration; equal-score sorts also lacked a
//!   stable tiebreaker.
//! - BUG-18: `tldr inheritance` and `tldr smells` printed progress /
//!   advisory text to stderr in JSON mode, breaking shell pipelines that
//!   gate on stderr-empty.
//!
//! issue #74 (output nondeterminism, remainder): adds repeat-run
//! byte-equality pins for the outputs whose serialization still depended on
//! `HashMap` iteration order or unsorted truncation after PERF-2:
//!
//! - `tldr smells` — `by_file` / `summary.by_type` were `HashMap`s serialized
//!   in hash order (probe: distinct key orders run-to-run). Both are now
//!   `BTreeMap`s (sorted keys).
//! - `tldr impact` — `targets` was a `HashMap<String, CallerTree>` keyed by
//!   `"file:function"`, so a symbol matching in multiple files serialized its
//!   JSON object keys in hash order (probe: 3 distinct orders over 6 runs).
//!   Now a `BTreeMap` (sorted keys).
//! - `tldr references --limit` — verified deterministic WITHOUT code changes:
//!   `find_references` sorts by `(file, line, column)` (PERF-2) BEFORE the
//!   `truncate(limit)`, so the kept subset is the canonically-first N. The
//!   test pins byte-equality AND that the kept prefix equals the first N of
//!   the unlimited run.
//!
//! The tests build a minimal Python project in a tempdir (so they don't
//! depend on `/tmp/repos/<x>` being checked out) with enough surface to
//! produce non-empty smells output, hubs output, and at least one clone
//! pair. Every test invokes the `tldr` binary via `assert_cmd::Command`
//! and reads JSON from stdout, mirroring the style of the milestone's
//! sister regression tests (e.g. `vuln_migration_v1_red.rs`).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Build a minimal multi-file Python project that exercises hubs,
/// clones, inheritance, and smells without needing `/tmp/repos/*`.
fn make_python_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    // Body of a substantial helper (token-rich enough to clear the
    // clones detector default minimum-tokens threshold of ~30). Used
    // twice — once in a.py, once in b.py — so the cross-file clone
    // detector has a guaranteed pair.
    let big_body = r#"def helper_big(items, threshold, factor):
    accumulator = 0
    seen_keys = []
    for index, item in enumerate(items):
        key = item.get("key", index)
        seen_keys.append(key)
        value = item.get("value", 0) * factor
        if value > threshold:
            accumulator += value
            if accumulator > threshold * 10:
                break
        else:
            accumulator -= value
    return accumulator, seen_keys
"#;
    write(
        &dir.path().join("a.py"),
        // a.py: cluster of small helpers calling each other (hubs surface)
        // plus a class hierarchy (inheritance surface).
        &format!(
            r#"class Animal:
    def speak(self):
        return "..."

class Dog(Animal):
    def speak(self):
        return "woof"

class Cat(Animal):
    def speak(self):
        return "meow"

def helper_one(x):
    total = 0
    for i in range(x):
        total += i
        if total > 100:
            break
    return total

def helper_two(x):
    return helper_one(x) + 1

def helper_three(x):
    return helper_two(x) + helper_one(x)

def root(x):
    return helper_three(x)

{big_body}
"#
        ),
    );
    write(
        &dir.path().join("b.py"),
        // b.py: copy of `helper_big` (verbatim Type-1 clone) plus a
        // small caller graph node so hubs has more nodes to rank.
        &format!(
            r#"{big_body}

def caller_b(items):
    return helper_big(items, 5, 2)
"#
        ),
    );
    dir
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vuln_migration_v1")
        .join("python")
        .join("sql_injection_positive.py")
}

// =============================================================================
// BUG-1: vuln exits 0 on completion and stderr is empty
// =============================================================================

#[test]
fn vuln_exits_zero_on_completion() {
    // Use the existing positive SQLi fixture from vuln_migration_v1 so
    // we KNOW findings are present — we want to assert that exit is 0
    // *despite* findings being present (the bug was the `Err` return).
    let fixture = fixture_dir();
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());

    let output = tldr_cmd()
        .arg("vuln")
        .arg(&fixture)
        .arg("--lang")
        .arg("python")
        .arg("--format")
        .arg("json")
        .output()
        .expect("invoke tldr vuln");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // BUG-1 assertion 1: exit 0 on a successful scan, regardless of count.
    assert_eq!(
        output.status.code(),
        Some(0),
        "tldr vuln must exit 0 on successful scan; got {:?}\nstderr:\n{}\nstdout:\n{}",
        output.status.code(),
        stderr,
        stdout,
    );

    // BUG-1 assertion 2: stderr must be byte-empty on success (no "Error:"
    // leak, no progress text in JSON mode).
    assert!(
        stderr.is_empty(),
        "tldr vuln stderr must be empty on success; got:\n{stderr}",
    );

    // Sanity: the JSON should still report findings (regression guard
    // against accidentally suppressing the actual analysis).
    let report: Value = serde_json::from_str(&stdout).expect("vuln stdout must be JSON");
    let total = report
        .pointer("/summary/total_findings")
        .and_then(|v| v.as_u64())
        .expect("summary.total_findings");
    assert!(
        total >= 1,
        "fixture should produce at least one finding; got {total}",
    );
}

// =============================================================================
// BUG-2: clones output is byte-stable across runs (modulo timing field)
// =============================================================================

fn run_clones_strip_timing(dir: &Path) -> Value {
    let output = tldr_cmd()
        .arg("clones")
        .arg(dir)
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr clones");
    assert!(
        output.status.success(),
        "tldr clones failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("clones stdout not JSON: {e}\n{stdout}"));
    // Strip wall-clock timing (inherently variable) so byte-equality
    // captures CONTENT determinism only — that's what the bug was
    // about. The fix made the `clone_pairs[]` order stable; timing
    // was never claimed to be byte-stable.
    // why: `ClonesReport` serializes the timing under BOTH `stats` and the
    // schema-consistency `summary` mirror (P17.AGG17-5). Stripping only
    // `metadata`/`stats` left `summary.detection_time_ms` in the compared
    // string, so any ms of jitter between runs failed this test.
    for key in ["metadata", "stats", "summary"] {
        if let Some(obj) = v.get_mut(key).and_then(|o| o.as_object_mut()) {
            obj.remove("detection_time_ms");
        }
    }
    v
}

#[test]
fn clones_output_is_byte_stable() {
    let dir = make_python_fixture();
    let path = dir.path();

    let r1 = run_clones_strip_timing(path);
    let r2 = run_clones_strip_timing(path);
    let r3 = run_clones_strip_timing(path);

    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();

    assert_eq!(s1, s2, "clones run #1 vs #2 differs");
    assert_eq!(s2, s3, "clones run #2 vs #3 differs");

    // Sanity: the helper duplicate should produce at least one clone pair
    // (ensures we're actually exercising the determinism-affected code
    // path, not just a no-op empty-array comparison).
    let pairs = r1
        .get("clone_pairs")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        pairs >= 1,
        "fixture should produce at least one clone pair; got {pairs}",
    );
}

// =============================================================================
// BUG-3: hubs output is byte-stable across runs
// =============================================================================

fn run_hubs_strip_timing(dir: &Path) -> Value {
    let output = tldr_cmd()
        .arg("hubs")
        .arg(dir)
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr hubs");
    assert!(
        output.status.success(),
        "tldr hubs failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hubs stdout not JSON: {e}\n{stdout}"));
    // Strip timing fields if present (defensive; not all schemas have them).
    if let Some(obj) = v.as_object_mut() {
        obj.remove("scan_time_ms");
        obj.remove("analysis_time_ms");
    }
    v
}

#[test]
fn hubs_output_is_byte_stable() {
    let dir = make_python_fixture();
    let path = dir.path();

    let r1 = run_hubs_strip_timing(path);
    let r2 = run_hubs_strip_timing(path);
    let r3 = run_hubs_strip_timing(path);

    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();

    assert_eq!(
        s1, s2,
        "hubs run #1 vs #2 differs (PageRank non-determinism?)"
    );
    assert_eq!(s2, s3, "hubs run #2 vs #3 differs");

    // Sanity: at least one hub should be produced (chained helpers).
    let hub_count = r1
        .get("hubs")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        hub_count >= 1,
        "fixture should produce at least one hub; got {hub_count}",
    );
}

// =============================================================================
// BUG-18: inheritance stderr is empty in JSON mode
// =============================================================================

#[test]
fn inheritance_stderr_empty_in_json_mode() {
    let dir = make_python_fixture();
    let output = tldr_cmd()
        .arg("inheritance")
        .arg(dir.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("invoke tldr inheritance");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "tldr inheritance failed: stderr=\n{stderr}\nstdout=\n{stdout}",
    );
    assert!(
        stderr.is_empty(),
        "BUG-18: tldr inheritance --format json must produce empty stderr \
         (the 'Found N classes in Mms' summary leaked here pre-fix); got:\n{stderr}",
    );
    // Sanity: JSON should still describe the classes we wrote.
    let report: Value = serde_json::from_str(&stdout).expect("JSON");
    let count = report
        .get("count")
        .and_then(|v| v.as_u64())
        .expect("inheritance count");
    assert!(
        count >= 3,
        "fixture defined Animal/Dog/Cat — expected count>=3; got {count}",
    );
}

// =============================================================================
// BUG-18: smells stderr empty in JSON mode AND warnings[] non-empty
// =============================================================================

#[test]
fn smells_stderr_empty_in_json_mode_but_warning_in_json() {
    let dir = make_python_fixture();
    // No `--deep`, no `--smell-type` => the `--deep` advisory hint is
    // expected. Pre-fix it went to stderr; post-fix it goes into
    // `report.warnings[]`.
    let output = tldr_cmd()
        .arg("smells")
        .arg(dir.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("invoke tldr smells");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "tldr smells failed: stderr=\n{stderr}\nstdout=\n{stdout}",
    );
    assert!(
        stderr.is_empty(),
        "BUG-18: tldr smells --format json must produce empty stderr \
         (the '--deep flag' note leaked here pre-fix); got:\n{stderr}",
    );

    let report: Value = serde_json::from_str(&stdout).expect("smells JSON");
    let warnings = report
        .get("warnings")
        .and_then(|v| v.as_array())
        .expect("smells.warnings array");
    assert!(
        !warnings.is_empty(),
        "BUG-18: smells.warnings[] must contain the relocated --deep hint",
    );
    let joined = warnings
        .iter()
        .filter_map(|w| w.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        joined.contains("--deep"),
        "smells.warnings[] should mention --deep; got: {joined}",
    );
}

// =============================================================================
// issue #74 (a): smells by_file / summary.by_type serialize in sorted order
// =============================================================================

fn run_smells_json(dir: &Path) -> Value {
    let output = tldr_cmd()
        .arg("smells")
        .arg(dir)
        .arg("--deep")
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr smells");
    assert!(
        output.status.success(),
        "tldr smells failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("smells stdout not JSON: {e}\n{stdout}"))
}

/// `SmellsReport.by_file` and `SmellsSummary.by_type` were `HashMap`s whose
/// iteration order leaked into the serialized JSON object key order — the
/// same run on the same input produced different key orders (probed: 4
/// distinct `by_type` orders over 4 runs). Both fields are now `BTreeMap`s,
/// so the full report must be byte-stable across runs AND its keys must be
/// sorted.
#[test]
fn smells_output_is_byte_stable() {
    let dir = make_python_fixture();
    let path = dir.path();

    let r1 = run_smells_json(path);
    let r2 = run_smells_json(path);
    let r3 = run_smells_json(path);

    // No timing field exists in SmellsReport, so this is a FULL byte
    // comparison — nothing is stripped.
    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();
    assert_eq!(s1, s2, "smells run #1 vs #2 differs (issue #74)");
    assert_eq!(s2, s3, "smells run #2 vs #3 differs (issue #74)");

    // Sanity: the fixture must produce enough smells of >= 2 types and >= 2
    // files for the key-order assertions below to be meaningful.
    let by_type = r1
        .pointer("/summary/by_type")
        .and_then(|v| v.as_object())
        .expect("summary.by_type object");
    assert!(
        by_type.len() >= 2,
        "fixture should produce >= 2 smell types; got {by_type:?}"
    );
    let by_file = r1
        .get("by_file")
        .and_then(|v| v.as_object())
        .expect("by_file object");
    assert!(
        by_file.len() >= 2,
        "fixture should produce smells in >= 2 files; got {by_file:?}"
    );

    // The key order must be SORTED (BTreeMap), not merely stable.
    let mut sorted_types: Vec<&String> = by_type.keys().collect();
    sorted_types.sort();
    assert_eq!(
        by_type.keys().collect::<Vec<_>>(),
        sorted_types,
        "summary.by_type keys must be serialized in sorted order (issue #74)"
    );
    let mut sorted_files: Vec<&String> = by_file.keys().collect();
    sorted_files.sort();
    assert_eq!(
        by_file.keys().collect::<Vec<_>>(),
        sorted_files,
        "by_file keys must be serialized in sorted order (issue #74)"
    );
}

// =============================================================================
// issue #74 (c, issue-cited): impact targets map serializes in sorted order
// =============================================================================

fn run_impact_targets_keys(dir: &Path) -> Value {
    let output = tldr_cmd()
        .arg("impact")
        .arg("shared_helper")
        .arg(dir)
        .arg("--lang")
        .arg("python")
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr impact");
    assert!(
        output.status.success(),
        "tldr impact failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("impact stdout not JSON: {e}\n{stdout}"))
}

/// `ImpactReport.targets` was a `HashMap<String, CallerTree>` keyed by
/// `"file:function"`; when a symbol matches in multiple files the JSON
/// object keys came out in hash order (probed: 3 distinct orders over 6
/// runs). It is now a `BTreeMap`, so the key order is sorted and the whole
/// report is byte-stable across runs (ImpactReport has no timing field).
#[test]
fn impact_targets_are_byte_stable_and_sorted() {
    // A symbol defined in three files: `targets` gets one entry per
    // definition site, which is exactly the shape that exposed the
    // HashMap ordering.
    let dir = TempDir::new().expect("tempdir");
    for (name, body) in [
        (
            "alpha.py",
            "def shared_helper(x):\n    total = 0\n    for i in range(x):\n        total += i\n    return total\n\ndef caller_a(x):\n    return shared_helper(x) + 1\n",
        ),
        (
            "beta.py",
            "def shared_helper(x):\n    total = 0\n    for i in range(x):\n        total += i * 2\n    return total\n\ndef caller_b(x):\n    return shared_helper(x) + 2\n",
        ),
        (
            "gamma.py",
            "def shared_helper(x):\n    return x * 3\n\ndef caller_c(x):\n    return shared_helper(x) + 3\n",
        ),
    ] {
        write(&dir.path().join(name), body);
    }

    let r1 = run_impact_targets_keys(dir.path());
    let r2 = run_impact_targets_keys(dir.path());
    let r3 = run_impact_targets_keys(dir.path());

    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();
    assert_eq!(s1, s2, "impact run #1 vs #2 differs (issue #74)");
    assert_eq!(s2, s3, "impact run #2 vs #3 differs (issue #74)");

    // Sanity: all three definition sites must be reported.
    let targets = r1
        .get("targets")
        .and_then(|v| v.as_object())
        .expect("targets object");
    assert_eq!(
        targets.len(),
        3,
        "fixture should produce 3 target entries; got {targets:?}"
    );

    // The key order must be SORTED (BTreeMap), not merely stable.
    let mut sorted_keys: Vec<&String> = targets.keys().collect();
    sorted_keys.sort();
    assert_eq!(
        targets.keys().collect::<Vec<_>>(),
        sorted_keys,
        "impact.targets keys must be serialized in sorted order (issue #74)"
    );
}

// =============================================================================
// issue #74 (b): references --limit truncation is deterministic and keeps
// the canonically-first N
// =============================================================================

fn run_references_json(dir: &Path, limit: usize) -> Value {
    let output = tldr_cmd()
        .arg("references")
        .arg("helper_big")
        .arg(dir)
        .arg("--limit")
        .arg(limit.to_string())
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr references");
    assert!(
        output.status.success(),
        "tldr references failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("references stdout not JSON: {e}\n{stdout}"))
}

/// The issue's "unsorted truncate" citation for `references`: as of PERF-2
/// the references Vec is sorted by `(file, line, column)` BEFORE the
/// `--limit` truncation is applied, so (1) the output is byte-stable across
/// runs (modulo the timing field) and (2) the dropped tail is deterministic
/// — the kept subset is exactly the first N entries of the canonical order.
/// This test pins both properties so a future regression cannot silently
/// reintroduce hash-order data loss under `--limit`.
#[test]
fn references_limit_truncation_is_deterministic_and_keeps_canonical_prefix() {
    let dir = make_python_fixture();
    let path = dir.path();

    // `helper_big` is defined in a.py and b.py and called from b.py —
    // references span multiple files with distinct (file, line) keys.
    let unlimited = run_references_json(path, 1000);
    let total = unlimited
        .get("total_references")
        .and_then(|v| v.as_u64())
        .expect("total_references") as usize;
    assert!(
        total >= 3,
        "fixture should produce >= 3 references to helper_big; got {total}"
    );

    // Truncate below the total and compare two independent runs.
    let limit = 2.min(total - 1);
    let r1 = run_references_json(path, limit);
    let r2 = run_references_json(path, limit);

    // Byte-equality modulo the inherently-variable timing field.
    let strip_timing = |mut v: Value| {
        if let Some(stats) = v.get_mut("stats").and_then(|s| s.as_object_mut()) {
            stats.remove("search_time_ms");
        }
        v
    };
    assert_eq!(
        strip_timing(r1.clone()),
        strip_timing(r2.clone()),
        "references --limit {limit} output differs across runs (issue #74)"
    );

    // Truncation metadata must be honest.
    let shown = r1
        .get("shown_references")
        .and_then(|v| v.as_u64())
        .expect("shown_references") as usize;
    assert_eq!(shown, limit, "shown_references must equal --limit");
    assert_eq!(
        r1.get("truncated").and_then(|v| v.as_bool()),
        Some(true),
        "truncated must be true when total > limit"
    );

    // The kept subset must be the canonically-FIRST N of the unlimited run:
    // sort the unlimited references by (file, line, column) and compare the
    // prefix with the limited run's references.
    let canon = |v: &Value| -> Vec<(String, i64, i64)> {
        v.get("references")
            .and_then(|r| r.as_array())
            .expect("references array")
            .iter()
            .map(|r| {
                (
                    r.get("file")
                        .and_then(|f| f.as_str())
                        .unwrap_or("")
                        .to_string(),
                    r.get("line").and_then(|l| l.as_i64()).unwrap_or(0),
                    r.get("column").and_then(|c| c.as_i64()).unwrap_or(0),
                )
            })
            .collect()
    };
    let mut sorted_unlimited = canon(&unlimited);
    sorted_unlimited.sort();
    let mut kept = canon(&r1);
    kept.sort();
    assert_eq!(
        kept,
        sorted_unlimited[..limit],
        "references --limit must keep the first {limit} entries of the canonical \
         (file, line, column) order — otherwise the dropped tail varies run-to-run \
         (silent data loss, issue #74)"
    );
}

// =============================================================================
// issue #74 (walker determinism ripple): directory walk order is sorted
// =============================================================================

/// Build a multi-file Python project whose CREATION ORDER is the exact
/// reverse of lexical order (`f_09.py` is created before `f_08.py`, `dir_c/`
/// before `dir_a/`). On filesystems where readdir order tracks creation
/// order (or any FS where it is not name-sorted), an unsorted walk yields a
/// non-lexical traversal, so this fixture maximizes the visibility of any
/// future regression away from `sort_by_file_path`. 22 files across 3
/// subdirectories; `helper_big` is defined in two files and called from two
/// more so `references` spans the whole tree.
fn make_reverse_creation_python_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let mut names: Vec<String> = (0..10).map(|i| format!("f_{i:02}.py")).collect();
    for (d, letter) in [("dir_a", "a"), ("dir_b", "b"), ("dir_c", "c")] {
        for i in 0..4 {
            names.push(format!("{d}/{letter}_{i:02}.py"));
        }
    }
    names.sort();
    // Create in REVERSE lexical order — creation order != walk-expectation.
    for rel in names.iter().rev() {
        let mut body = format!(
            "def unique_{}(x):\n    total = 0\n    for i in range(x):\n        total += i\n    return total\n",
            rel.replace(['/', '.'], "__")
        );
        match rel.as_str() {
            "f_00.py" | "dir_a/a_00.py" => body.push_str(
                "\ndef helper_big(items, threshold):\n    acc = 0\n    for it in items:\n        acc += it * threshold\n    return acc\n",
            ),
            "f_05.py" | "dir_c/c_01.py" => {
                body.push_str("\ndef caller_here(x):\n    return helper_big([1, 2, 3], x)\n")
            }
            _ => {}
        }
        write(&dir.path().join(rel), &body);
    }
    dir
}

/// Sorted names of every fixture file — the exact expected `by_file` order
/// after the walker determinism fix. Directory names (`dir_*`) sort before
/// the root-level `f_*` files, and no file name is a prefix of a directory
/// name (or vice versa), so the sorted depth-first walk order equals the
/// globally sorted relative-path order for this fixture.
fn fixture_sorted_names() -> Vec<String> {
    let mut names: Vec<String> = (0..10).map(|i| format!("f_{i:02}.py")).collect();
    for (d, letter) in [("dir_a", "a"), ("dir_b", "b"), ("dir_c", "c")] {
        for i in 0..4 {
            names.push(format!("{d}/{letter}_{i:02}.py"));
        }
    }
    names.sort();
    names
}

/// The issue-#74 walker fix: every directory walk must be a deterministic
/// depth-first traversal over lexically-sorted entries (`ignore`'s
/// `sort_by_file_path`). `tldr loc --by-file` surfaces walk order directly —
/// `by_file` rows keep walk order (PERF-2 merge) and the `max_files` cap
/// truncates mid-walk — so this pins BOTH properties: byte-stability across
/// repeated runs AND exact lexicographic path order (not merely consistency).
/// LocReport has no timing fields, so full stdout bytes are comparable.
#[test]
fn loc_by_file_walk_order_is_sorted_and_byte_stable() {
    let dir = make_reverse_creation_python_fixture();
    let path = dir.path();

    let run = || -> String {
        let output = tldr_cmd()
            .arg("loc")
            .arg(path)
            .arg("--by-file")
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .output()
            .expect("invoke tldr loc");
        assert!(
            output.status.success(),
            "tldr loc failed: stderr=\n{}\nstdout=\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let s1 = run();
    let s2 = run();
    let s3 = run();
    assert_eq!(s1, s2, "loc run #1 vs #2 differs (walk order, issue #74)");
    assert_eq!(s2, s3, "loc run #2 vs #3 differs (walk order, issue #74)");

    let report: Value = serde_json::from_str(&s1).expect("loc stdout must be JSON");
    let by_file = report
        .get("by_file")
        .and_then(|v| v.as_array())
        .expect("loc.by_file array");
    let got: Vec<String> = by_file
        .iter()
        .map(|e| {
            e.get("path")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();

    let expected = fixture_sorted_names();
    assert_eq!(
        got, expected,
        "loc --by_file rows must follow the sorted directory walk (issue #74 \
         walker determinism ripple): the `ignore` walker must be built with \
         sort_by_file_path"
    );
}

/// `tldr structure` and `tldr references` must be byte-stable across repeated
/// runs on the reverse-creation-order fixture. `references` collects its
/// candidate files through `ProjectWalker`; `structure` covers every fixture
/// file, so a walk-order regression (or any run-to-run ordering leak in the
/// walked commands) breaks the byte-equality below.
#[test]
fn references_and_structure_are_byte_stable_on_walked_fixture() {
    let dir = make_reverse_creation_python_fixture();
    let path = dir.path();

    let structure = || -> String {
        let output = tldr_cmd()
            .arg("structure")
            .arg(path)
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .output()
            .expect("invoke tldr structure");
        assert!(
            output.status.success(),
            "tldr structure failed: stderr=\n{}\nstdout=\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let c1 = structure();
    let c2 = structure();
    let c3 = structure();
    assert_eq!(
        c1, c2,
        "structure run #1 vs #2 differs (walk order, issue #74)"
    );
    assert_eq!(
        c2, c3,
        "structure run #2 vs #3 differs (walk order, issue #74)"
    );
    let s: Value = serde_json::from_str(&c1).expect("structure JSON");
    let files = s
        .get("files")
        .and_then(|v| v.as_array())
        .expect("structure.files array");
    assert_eq!(
        files.len(),
        22,
        "structure must cover every fixture file; got {}",
        files.len()
    );

    let references = || -> String {
        let output = tldr_cmd()
            .arg("references")
            .arg("helper_big")
            .arg(path)
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .output()
            .expect("invoke tldr references");
        assert!(
            output.status.success(),
            "tldr references failed: stderr=\n{}\nstdout=\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    // references carries a wall-clock `stats.search_time_ms`; strip it so
    // byte-equality captures content only (same convention as the BUG-2/3
    // pins above).
    let strip_timing = |raw: &str| -> String {
        let mut v: Value = serde_json::from_str(raw).expect("references JSON");
        if let Some(stats) = v.get_mut("stats").and_then(|s| s.as_object_mut()) {
            stats.remove("search_time_ms");
        }
        serde_json::to_string(&v).unwrap()
    };
    let r1 = strip_timing(&references());
    let r2 = strip_timing(&references());
    let r3 = strip_timing(&references());
    assert_eq!(
        r1, r2,
        "references run #1 vs #2 differs (walk order, issue #74)"
    );
    assert_eq!(
        r2, r3,
        "references run #2 vs #3 differs (walk order, issue #74)"
    );
    let r: Value = serde_json::from_str(&r1).unwrap();
    assert_eq!(
        r.get("total_references").and_then(|v| v.as_u64()),
        Some(4),
        "fixture must yield 4 references (2 definitions + 2 call sites); \
         got {:?}",
        r.get("total_references")
    );
}

// =============================================================================
// walk-determinism-v2 (T5 ripple of 1491e826): the ADJACENT walkdir-based
// walkers R1 flagged as follow-ups. `scan_secrets` (security/secrets.rs) and
// `Bm25Index::from_project` (search/bm25.rs) both keep the directory walk's
// visit order in their public results (findings rows / index document order
// under score ties), so an unsorted walkdir made them filesystem-dependent.
// The fix adds `.sort_by(|a, b| a.path().cmp(b.path()))` to those walks;
// these pins hold the contract at the exact fix sites (library level, so the
// masking done by downstream CLI sorts cannot hide a regression).
// =============================================================================

/// Reverse-creation-order fixture with ONE structural secret per file (AWS
/// access key pattern — never placeholder-suppressed). Creation order is the
/// exact reverse of lexical order to maximize visibility of any walk-order
/// regression.
fn make_reverse_creation_secrets_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let mut names: Vec<String> = (0..10).map(|i| format!("f_{i:02}.py")).collect();
    for (d, letter) in [("dir_a", "a"), ("dir_b", "b"), ("dir_c", "c")] {
        for i in 0..4 {
            names.push(format!("{d}/{letter}_{i:02}.py"));
        }
    }
    names.sort();
    for rel in names.iter().rev() {
        write(
            &dir.path().join(rel),
            "# config module\naws_key = \"AKIAIOSFODNN7EXAMPLE\"\nregion = \"us-east-1\"\n",
        );
    }
    dir
}

/// walk-determinism-v2: `scan_secrets` findings must be byte-stable across
/// repeated runs AND their file order must be the sorted directory walk order.
/// The CLI `secrets` surface is archived, but `SecretsReport.findings` is a
/// public library contract (output.rs renders rows in report order with no
/// downstream sort), so a walk-order regression flips user-visible row order.
#[test]
fn secrets_findings_walk_order_is_sorted_and_byte_stable() {
    use tldr_core::security::secrets::scan_secrets;

    let dir = make_reverse_creation_secrets_fixture();
    let path = dir.path();

    let run = || -> Vec<String> {
        let report = scan_secrets(path, 4.5, false, None).expect("scan_secrets");
        assert!(
            !report.findings.is_empty(),
            "fixture must produce findings (AWS access key pattern per file)"
        );
        report
            .findings
            .iter()
            .map(|f| format!("{}:{}:{}", f.file.display(), f.line, f.pattern))
            .collect::<Vec<_>>()
    };

    let r1 = run();
    let r2 = run();
    let r3 = run();
    assert_eq!(
        r1, r2,
        "secrets run #1 vs #2 differs (walk order, walk-determinism-v2)"
    );
    assert_eq!(
        r2, r3,
        "secrets run #2 vs #3 differs (walk order, walk-determinism-v2)"
    );

    // Exact-order pin: one AWS-key finding per file, so first-occurrence file
    // order must equal the lexicographically sorted fixture names.
    let mut got_files: Vec<String> = Vec::new();
    for row in &r1 {
        let file = row.split(':').next().unwrap_or_default().to_string();
        if !got_files.contains(&file) {
            got_files.push(file);
        }
    }
    let expected: Vec<String> = fixture_sorted_names()
        .iter()
        .map(|rel| dir.path().join(rel).display().to_string())
        .collect();
    assert_eq!(
        got_files, expected,
        "secrets findings file order must follow the sorted directory walk \
         (walk-determinism-v2): the walkdir scan must sort by full path"
    );
}

/// Reverse-creation-order fixture where every file has IDENTICAL content, so
/// every document gets an identical BM25 score and `Bm25Index::search` result
/// order collapses to pure index insertion (= walk) order — maximally
/// sensitive to any walk-order regression in `from_project`.
fn make_reverse_creation_bm25_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let mut names: Vec<String> = (0..6).map(|i| format!("f_{i:02}.py")).collect();
    names.push("dir_a/a_00.py".to_string());
    names.push("dir_b/b_00.py".to_string());
    names.sort();
    let body = "def fetch_data(handle):\n    rows = load(handle)\n    return [fetch_data(r) for r in rows]\n\n"
        .repeat(4);
    for rel in names.iter().rev() {
        write(&dir.path().join(rel), &body);
    }
    dir
}

/// Sorted relative names of the BM25 fixture (subset contract of
/// `fixture_sorted_names`).
fn bm25_fixture_sorted_names() -> Vec<String> {
    let mut names: Vec<String> = (0..6).map(|i| format!("f_{i:02}.py")).collect();
    names.push("dir_a/a_00.py".to_string());
    names.push("dir_b/b_00.py".to_string());
    names.sort();
    names
}

/// walk-determinism-v2: `Bm25Index::from_project` inserts documents in walk
/// order and `Bm25Index::search`'s stable score sort keeps insertion order on
/// ties, with `truncate(top_k)` cutting mid-walk — so with identical documents
/// (equal scores) the enumeration order of the index IS the walk order. Pin
/// byte-stability across runs AND lexicographic document order.
#[test]
fn bm25_index_enumeration_order_is_sorted_and_byte_stable() {
    use tldr_core::search::bm25::Bm25Index;
    use tldr_core::Language;

    let dir = make_reverse_creation_bm25_fixture();
    let path = dir.path();

    let run = || -> Vec<String> {
        let index = Bm25Index::from_project(path, Language::Python).expect("from_project");
        let results = index.search("fetch_data", 100);
        assert!(
            !results.is_empty(),
            "fixture must produce BM25 results for 'fetch_data'"
        );
        results
            .iter()
            .map(|r| format!("{}:{}:{}", r.file_path.display(), r.line_start, r.line_end))
            .collect::<Vec<_>>()
    };

    let r1 = run();
    let r2 = run();
    let r3 = run();
    assert_eq!(
        r1, r2,
        "bm25 run #1 vs #2 differs (index insertion order, walk-determinism-v2)"
    );
    assert_eq!(
        r2, r3,
        "bm25 run #2 vs #3 differs (index insertion order, walk-determinism-v2)"
    );

    // Exact-order pin: identical content => identical scores => the stable
    // sort keeps walk order, so first-occurrence document order must be the
    // sorted fixture names.
    let mut got_docs: Vec<String> = Vec::new();
    for row in &r1 {
        let file = row.split(':').next().unwrap_or_default().to_string();
        if !got_docs.contains(&file) {
            got_docs.push(file);
        }
    }
    let expected: Vec<String> = bm25_fixture_sorted_names();
    assert_eq!(
        got_docs, expected,
        "bm25 document enumeration order must follow the sorted directory walk \
         (walk-determinism-v2): from_project's walkdir must sort by full path"
    );
}
