//! explain-scoping-v1 (issue #6) — scoping flags for `tldr explain`.
//!
//! Cost regression: `tldr explain <file> <fn>` always enriched its caller /
//! callee data from a whole-project call graph plus a full-project reference
//! scan rooted at the detected project root, so wall-clock scaled with repo
//! size (~0.1s for a single file, seconds for small trees, minutes for large
//! repos) even when the user only cares about a small slice of the tree.
//!
//! This suite pins the new flags:
//!
//! - `--scope <dir>`: bounds caller/callee graph traversal and the reference
//!   search to the given directory instead of the detected project root.
//! - `--no-callers`: skips caller discovery entirely (per-file walker +
//!   project graph + reference scans), leaving `callers == []` and the rest
//!   of the JSON schema unchanged — function-local facts only.
//! - `--depth` is now actually wired into the project-graph caller traversal
//!   (previously declared but ignored — the graph path hard-coded depth 1).
//!
//! Fixture: a temp project with an `app/` dir (a.py defining `scale`,
//! `helper`, and a same-dir caller `run_job`) and a `vendor/` dir padded with
//! many generated filler files to give the whole-project scan real work to
//! do. All tests are self-contained (no real-repo gating).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// How many filler files to generate under `vendor/`. Sized so the default
/// (whole-project) run measurably out-costs the `--no-callers` run without
/// making the suite slow: 40 small Python files is enough work for the
/// project-graph build + reference scan to dominate.
const VENDOR_FILE_COUNT: usize = 40;

/// Build the fixture project:
///
/// ```text
/// <tmp>/
///   pyproject.toml          <- project marker (default root detection)
///   app/a.py                <- scale / helper / run_job (run_job calls helper)
///   vendor/vXX.py  (x40)    <- filler functions, never mention `helper`
/// ```
fn build_scoping_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(&root.join("pyproject.toml"), "[project]\nname = \"x\"\n");

    // The code under test: `helper` has a same-dir caller (`run_job`) and a
    // same-file callee (`scale`), so both relationship fields can be
    // asserted on from a single explain invocation.
    write(
        &root.join("app/a.py"),
        r#"
def scale(x, factor):
    return x * factor

def helper(x):
    return scale(x, 2)

def run_job(values):
    total = 0
    for v in values:
        total = total + helper(v)
    return total
"#,
    );

    // Vendor padding: generated files with filler functions. Deliberately do
    // NOT mention `helper` anywhere — callers must come from app/ only.
    for i in 0..VENDOR_FILE_COUNT {
        let body = format!(
            r#"
def filler_{i}_accumulate(n):
    acc = 0
    for k in range(n):
        acc += k * {i} + 3
    return acc

def filler_{i}_transform(values):
    out = []
    for v in values:
        if v % 2 == 0:
            out.append(v + {i})
        else:
            out.append(v - {i})
    return out

def filler_{i}_combine(a, b):
    return filler_{i}_accumulate(a) + filler_{i}_transform([b])[-1]
"#,
            i = i
        );
        write(&root.join(format!("vendor/v{:02}.py", i)), &body);
    }

    dir
}

/// Parse the explain JSON report from raw stdout.
fn explain_json(out: &[u8]) -> Value {
    serde_json::from_slice(out).expect("explain JSON should parse")
}

fn caller_names(v: &Value) -> Vec<String> {
    v.get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array")
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .map(|s| s.to_string())
        .collect()
}

// ============================================================================
// (a) Default run: callers discovered (whole-project root detection)
// ============================================================================

#[test]
fn default_run_finds_same_dir_caller() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");

    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain");
    assert!(
        out.status.success(),
        "tldr explain failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = explain_json(&out.stdout);
    let names = caller_names(&v);
    assert!(
        !names.is_empty(),
        "default explain should find the caller `run_job` in app/a.py; got {:?}",
        v
    );
    assert!(
        names.iter().any(|n| n.contains("run_job")),
        "callers should include `run_job`; got {:?}",
        names
    );
}

// ============================================================================
// (b) --scope app: correctness preserved when the scope covers the code
// ============================================================================

#[test]
fn scope_run_finds_same_dir_caller() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");
    let app = root.join("app");

    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--scope")
        .arg(&app)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain --scope");
    assert!(
        out.status.success(),
        "tldr explain --scope failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = explain_json(&out.stdout);
    let names = caller_names(&v);
    assert!(
        names.iter().any(|n| n.contains("run_job")),
        "--scope app should still find the same caller `run_job` \
         (scope covers the code); got {:?}",
        names
    );
}

// ============================================================================
// (c) --no-callers: callers == [], schema intact (function/line/callees)
// ============================================================================

#[test]
fn no_callers_leaves_schema_intact_and_empties_callers() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");

    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--no-callers")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain --no-callers");
    assert!(
        out.status.success(),
        "tldr explain --no-callers failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = explain_json(&out.stdout);

    // callers must be empty.
    let callers = v
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array (schema unchanged)");
    assert!(
        callers.is_empty(),
        "--no-callers must leave callers == []; got {:?}",
        callers
    );

    // The rest of the schema stays present: function/line/callees.
    assert_eq!(
        v.get("function").and_then(|f| f.as_str()),
        Some("helper"),
        "function field must still be present and correct"
    );
    let line = v
        .get("line")
        .and_then(|l| l.as_u64())
        .expect("`line` field must still be present (schema-unification-v1 BUG-17)");
    assert!(
        line > 0,
        "line should be a real 1-indexed line; got {}",
        line
    );
    let callees = v
        .get("callees")
        .and_then(|c| c.as_array())
        .expect("callees array (schema unchanged)");
    let callee_names: Vec<&str> = callees
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        callee_names.iter().any(|n| n.contains("scale")),
        "--no-callers keeps function-local callees; expected `scale` in {:?}",
        callee_names
    );
}

/// (c cont.) wall-clock: skipping caller discovery should be faster than the
/// default run. Timing asserts are inherently noisier than behavioral ones,
/// so this lives in its own test — the fixture's vendor padding makes the
/// gap structural (whole-project graph + reference scan vs none), and the
/// margin is generous (plain `<`). If this proves flaky on a given machine,
/// the behavioral guarantees above are the contract; this test only
/// demonstrates the cost win.
#[test]
fn no_callers_is_faster_than_default() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");

    let start = Instant::now();
    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain (default)");
    assert!(out.status.success());
    let default_elapsed = start.elapsed();

    let start = Instant::now();
    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--no-callers")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain --no-callers");
    assert!(out.status.success());
    let no_callers_elapsed = start.elapsed();

    assert!(
        no_callers_elapsed < default_elapsed,
        "--no-callers ({}ms) should be faster than default ({}ms): \
         caller discovery dominates explain's cost",
        no_callers_elapsed.as_millis(),
        default_elapsed.as_millis()
    );
}

// ============================================================================
// (d) --scope /nonexistent: fail fast with a clear message
// ============================================================================

#[test]
fn scope_nonexistent_dir_fails_with_clear_message() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");
    let missing = root.join("does_not_exist");

    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--scope")
        .arg(&missing)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain --scope <missing>");
    assert!(
        !out.status.success(),
        "--scope pointing at a non-existent directory must fail; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist"),
        "error message should clearly mention the missing scope dir; stderr={}",
        stderr
    );
}

// ============================================================================
// (e) --depth is accepted and wired through (previously ignored)
// ============================================================================

#[test]
fn depth_flag_accepted_and_json_parses() {
    let dir = build_scoping_project();
    let root = dir.path();
    let a_py = root.join("app/a.py");

    let out = tldr_cmd()
        .arg("explain")
        .arg(&a_py)
        .arg("helper")
        .arg("--depth")
        .arg("1")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain --depth 1");
    assert!(
        out.status.success(),
        "--depth 1 must be accepted; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = explain_json(&out.stdout);
    let names = caller_names(&v);
    // Same-file caller discovery is depth-independent, so `run_job` must
    // still be present at depth 1.
    assert!(
        names.iter().any(|n| n.contains("run_job")),
        "--depth 1 should not break same-file caller discovery; got {:?}",
        names
    );
}
