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
    let report: Value =
        serde_json::from_str(&stdout).expect("vuln stdout must be JSON");
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

    assert_eq!(s1, s2, "hubs run #1 vs #2 differs (PageRank non-determinism?)");
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
