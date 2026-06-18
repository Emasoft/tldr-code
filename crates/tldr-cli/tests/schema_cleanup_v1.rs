//! schema-cleanup-v1 — regression tests for 9 schema/dead-UI bugs (M4):
//!
//! - BUG-9:  `health.metrics` sub-row was always "Metrics: no data" for
//!   all the languages whose package model doesn't fit Robert C. Martin's
//!   abstractness/instability framework. Fix: suppress the dead row in
//!   text output (JSON sub-result is unchanged so consumers still see
//!   the failure case).
//! - BUG-10: `patterns.naming.violations[].line` was hard-coded `0`.
//!   Fix: plumb the AST start_position line through the
//!   `NamingSignals` collector tuples so violations carry a real line.
//! - BUG-11: `tldr deps` JSON had `root: ""` and the text header read
//!   `Dependency Analysis: ` with no path. Root cause:
//!   `make_relative_path(&root, &root)` returns an empty PathBuf when
//!   `root.is_self()`. Fix: emit the canonical root path verbatim.
//! - BUG-12: `tldr churn` blanked `summary.most_churned_file` whenever
//!   the repo was a degenerate-shallow clone, even though `files[]`
//!   carried a clean top-N rank by `lines_changed`. Fix: refill
//!   `most_churned_file` from the file with the highest `lines_changed`
//!   so the summary always reflects the data that's available.
//! - BUG-13: `tldr structure` JSON had redundant `functions` (strings)
//!   AND `definitions` (objects), `methods` (strings) AND `method_infos`
//!   (objects). Fix: `#[serde(skip_serializing)]` on the legacy string
//!   arrays — internal callers can still build them, JSON consumers see
//!   only the canonical object arrays. `MethodInfo` also gained
//!   `line_end` for parity with `DefinitionInfo`.
//! - BUG-15: `tldr semantic` and `tldr search` JSON omitted
//!   `total_results` entirely (so `jq '.total_results'` returned
//!   `null`). Fix: add the field to both report structs and populate it
//!   from `results.len()`.
//! - BUG-21: `tldr chop` schema diverged from `tldr slice` (`count` vs
//!   `line_count`, no `file` field, etc.). Fix: add `file` and
//!   `line_count` to `ChopResult` (keeping `count` for back-compat) and
//!   ensure the CLI populates `file` from the canonical path.
//! - BUG-22: `tldr interface.all_exports` was emitted as `null` when no
//!   `__all__` was defined. Fix: change the field to `Vec<String>` and
//!   populate it with the explicit `__all__` (Python only) OR the union
//!   of public function/class names — never `null`.
//! - BUG-23: `tldr extract` method/function objects emitted `line` AND
//!   `line_number` (duplicate values from the BUG-17 alias) but no
//!   `line_end`. Fix: drop `line_number` from JSON serialization, add
//!   `line_end` (populated from `node.end_position()`).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Locate the flask corpus. CI/dev environments check it out under
/// `/tmp/repos/python-flask` (the legacy `/tmp/repos/flask` path is still
/// honored as a fallback). Returns `None` when the corpus is not present
/// (or has no working-tree files) so callers can skip cleanly — see the
/// guarded pattern in `api_check_and_patterns_accuracy_v1.rs`.
fn flask_repo() -> Option<PathBuf> {
    for cand in ["/tmp/repos/python-flask", "/tmp/repos/flask"] {
        let p = PathBuf::from(cand);
        // Require an actual Python source file: the corpus dir can exist
        // as an empty skeleton (git checkout with no working tree), which
        // is useless for these schema assertions.
        if p.join("src/flask/app.py").exists() {
            return Some(p);
        }
    }
    None
}

fn flask_app_py() -> Option<PathBuf> {
    let p = flask_repo()?.join("src/flask/app.py");
    p.exists().then_some(p)
}

/// Skip helper: returns the flask repo path or prints a skip notice and
/// signals the caller to `return`. Mirrors the eprintln+return guard used
/// elsewhere in the CLI test suite for optional corpora.
fn flask_repo_or_skip(test: &str) -> Option<PathBuf> {
    match flask_repo() {
        Some(p) => Some(p),
        None => {
            eprintln!("[skip] {test}: flask corpus not present (looked under /tmp/repos/python-flask and /tmp/repos/flask)");
            None
        }
    }
}

fn flask_app_py_or_skip(test: &str) -> Option<PathBuf> {
    match flask_app_py() {
        Some(p) => Some(p),
        None => {
            eprintln!("[skip] {test}: flask app.py corpus fixture not present");
            None
        }
    }
}

fn run_json(args: &[&str]) -> Value {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON failed: {e}; args were {:?}; stdout was:\n{stdout}",
            args
        )
    })
}

fn run_text(args: &[&str]) -> String {
    let mut argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    argv.extend(["--format".into(), "text".into()]);
    let output = tldr_cmd()
        .args(&argv)
        .output()
        .expect("run tldr (text)");
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

// =============================================================================
// BUG-9: health metrics dead UI
// =============================================================================

#[test]
fn bug9_health_metrics_not_dead_ui() {
    let Some(path) = flask_repo_or_skip("bug9_health_metrics_not_dead_ui") else { return; };
    let text = run_text(&["health", path.to_str().unwrap()]);
    // The "Metrics: no data" row was dead UI on every Python repo.
    // Either the row is suppressed entirely (current behavior) OR it
    // carries actual data — never the literal "no data" string.
    assert!(
        !text.contains("Metrics:     no data"),
        "BUG-9 regression: 'Metrics: no data' is dead UI and should not appear in health text output:\n{text}"
    );
}

// =============================================================================
// BUG-10: patterns naming.violations[].line populated
// =============================================================================

#[test]
fn bug10_patterns_naming_violations_have_line() {
    // BUG-10 contract: when naming violations exist, every violation
    // carries a `line > 0` plumbed through from the AST start_position
    // 4-tuple in `NamingSignals`.
    //
    // Originally this test ran `tldr patterns` against the real flask
    // repo, which had several single-word identifiers (e.g. `print`)
    // that the OLD classifier flagged as `snake_case` violations
    // against `camel_case` expectations. After
    // `language-coverage-fixes-v1` (P4.BUG-N4, commit ef5f6cf),
    // `signals::detect_naming_case` now requires `≥1 underscore` to
    // classify as snake_case / upper_snake_case, and the violation
    // emitter (`patterns::naming::is_compatible`) treats single-word
    // `LowerAlpha` / `UpperAlpha` identifiers as compatible with both
    // adjacent conventions. Flask's previous "violations" were ALL of
    // that single-word shape — post-N4 flask correctly returns zero
    // naming violations (and the `violations` field is even
    // `skip_serializing_if = "Vec::is_empty"`, so it disappears from
    // the JSON entirely).
    //
    // Use a synthetic fixture instead: a Python file with a
    // snake_case majority and ONE camelCase function. Under the
    // corrected classifier, the camelCase function is `NamingCase::
    // CamelCase` (not `LowerAlpha`), and `is_compatible(CamelCase,
    // SnakeCase)` is `false`, so it is reported as a violation.
    // This preserves the original BUG-10 contract: any violation
    // that IS reported must carry `line > 0`.
    let dir = TempDir::new().expect("tempdir");
    let py = dir.path().join("sample.py");
    fs::write(
        &py,
        r#"
def first_function():
    pass

def second_function():
    pass

def third_function():
    pass

def badCamelCase():
    pass

class GoodClass:
    pass

class AnotherClass:
    pass
"#,
    )
    .expect("write sample.py");

    let v = run_json(&["patterns", dir.path().to_str().unwrap()]);
    let violations = v
        .pointer("/naming/violations")
        .and_then(|x| x.as_array())
        .unwrap_or_else(|| {
            panic!("patterns: missing .naming.violations array; got {v}")
        });
    assert!(
        !violations.is_empty(),
        "synthetic fixture (snake_case majority + one camelCase fn) \
         should produce ≥1 naming violation under the corrected \
         classifier; got 0. Full output: {v}"
    );
    // Every violation must carry a non-zero line number from the AST
    // start_position. This is the BUG-10 schema-cleanup contract.
    for viol in violations {
        let line = viol
            .get("line")
            .and_then(|n| n.as_u64())
            .unwrap_or_else(|| panic!("violation missing .line field: {viol}"));
        assert!(
            line > 0,
            "BUG-10 regression: violation reported line=0; expected \
             line>0 from AST start_position. violation: {viol}"
        );
    }
}

// =============================================================================
// BUG-11: deps root populated
// =============================================================================

#[test]
fn bug11_deps_root_populated() {
    let Some(path) = flask_repo_or_skip("bug11_deps_root_populated") else { return; };
    let v = run_json(&["deps", path.to_str().unwrap()]);
    let root = v
        .get("root")
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("deps: missing .root string; got {v}"));
    assert!(
        !root.is_empty(),
        "BUG-11 regression: deps .root is empty string; expected the analyzed path"
    );
    // Text formatter should include the root in the header.
    let text = run_text(&["deps", path.to_str().unwrap()]);
    let first_line = text.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("Dependency Analysis: ") && first_line.len() > "Dependency Analysis: ".len(),
        "BUG-11 regression: text header has empty root: {first_line:?}"
    );
}

// =============================================================================
// BUG-12: churn most_churned_file populated even on shallow clone
// =============================================================================

#[test]
fn bug12_churn_most_churned_file_populated() {
    let Some(path) = flask_repo_or_skip("bug12_churn_most_churned_file_populated") else { return; };
    let v = run_json(&["churn", path.to_str().unwrap()]);
    let mcf = v
        .pointer("/summary/most_churned_file")
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| {
            panic!("churn: missing .summary.most_churned_file string; got {v}")
        });
    // /tmp/repos/flask happens to be a shallow clone (1 commit) — the
    // pre-fix behavior blanked this field; post-fix we refill it from
    // the file with the highest lines_changed.
    let files_len = v
        .pointer("/files")
        .and_then(|x| x.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if files_len > 0 {
        assert!(
            !mcf.is_empty(),
            "BUG-12 regression: most_churned_file is empty even though .files has {files_len} entries"
        );
    }
}

// =============================================================================
// BUG-13: structure no redundant string arrays; method_infos has line_end
// =============================================================================

#[test]
fn bug13_structure_no_redundant_string_arrays() {
    let Some(path) = flask_repo_or_skip("bug13_structure_no_redundant_string_arrays") else { return; };
    let v = run_json(&["structure", path.to_str().unwrap()]);
    let files = v.pointer("/files").and_then(|x| x.as_array()).expect("files");
    assert!(!files.is_empty(), "no files in structure output");
    let f0 = &files[0];
    let keys: Vec<&str> = f0
        .as_object()
        .expect("file is object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    // structure-functions-projection-v1 (v0.4.2 M-006): the `functions`
    // key was re-introduced — but NOT as a redundant string array. It
    // is now a projection of `definitions[].filter(kind=="function")`,
    // i.e. an array of objects with the same shape as `DefinitionInfo`.
    // BUG-13's actual invariant — no `functions: [String]` payload —
    // is enforced below: any entry under `functions[]` must be a
    // JSON object (or the array must be empty), never a bare string.
    if let Some(funcs) = f0.get("functions").and_then(|x| x.as_array()) {
        for fe in funcs {
            assert!(
                fe.is_object(),
                "BUG-13 + M-006 regression: structure JSON 'functions' \
                 entries must be objects (DefinitionInfo shape), not \
                 bare strings. Got: {fe}"
            );
            let inner_keys: Vec<&str> = fe
                .as_object()
                .unwrap()
                .keys()
                .map(|s| s.as_str())
                .collect();
            assert!(
                inner_keys.contains(&"name") && inner_keys.contains(&"kind"),
                "M-006: functions[] entry missing canonical fields; \
                 expected at least name + kind. keys: {inner_keys:?}"
            );
        }
    }
    // BUG-13 invariant that REMAINS in effect: the legacy
    // `methods: [String]` array must not appear; `method_infos` is the
    // canonical method surface.
    assert!(
        !keys.contains(&"methods"),
        "BUG-13 regression: structure JSON still has 'methods' (strings); expected only 'method_infos' (objects). keys: {keys:?}"
    );
    // Canonical object arrays must remain.
    assert!(
        keys.contains(&"definitions") || keys.contains(&"method_infos"),
        "expected 'definitions' or 'method_infos' to be present; keys: {keys:?}"
    );
}

#[test]
fn bug13_method_infos_have_line_end() {
    let Some(path) = flask_repo_or_skip("bug13_method_infos_have_line_end") else { return; };
    let v = run_json(&["structure", path.to_str().unwrap()]);
    // Find any file that has a non-empty method_infos array.
    let files = v.pointer("/files").and_then(|x| x.as_array()).expect("files");
    let mi = files
        .iter()
        .filter_map(|f| f.get("method_infos").and_then(|x| x.as_array()))
        .find(|a| !a.is_empty())
        .unwrap_or_else(|| panic!("no file with non-empty method_infos in flask"));
    let first = &mi[0];
    let keys: Vec<&str> = first
        .as_object()
        .expect("method_info is object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert!(
        keys.contains(&"line"),
        "method_infos[0] missing 'line': {keys:?}"
    );
    assert!(
        keys.contains(&"line_end"),
        "BUG-13 regression: method_infos[0] missing 'line_end' (added for parity with DefinitionInfo): {keys:?}"
    );
}

// =============================================================================
// BUG-15: semantic + search total_results populated
// =============================================================================

#[test]
fn bug15_semantic_total_results_populated() {
    let Some(path) = flask_repo_or_skip("bug15_semantic_total_results_populated") else { return; };
    let v = run_json(&[
        "semantic",
        "create flask app",
        path.to_str().unwrap(),
    ]);
    let total = v.get("total_results").and_then(|x| x.as_u64());
    assert!(
        total.is_some(),
        "BUG-15 regression: semantic JSON .total_results is null/missing; expected integer. got: {v}"
    );
    let results_len = v
        .pointer("/results")
        .and_then(|x| x.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    assert_eq!(
        total.unwrap(),
        results_len,
        "BUG-15: total_results ({}) should equal results.len() ({})",
        total.unwrap(),
        results_len
    );
}

#[test]
fn bug15_search_total_results_populated() {
    let Some(path) = flask_repo_or_skip("bug15_search_total_results_populated") else { return; };
    let v = run_json(&["search", "create", path.to_str().unwrap()]);
    let total = v.get("total_results").and_then(|x| x.as_u64());
    assert!(
        total.is_some(),
        "BUG-15 regression: search JSON .total_results is null/missing; expected integer. got: {v}"
    );
    let results_len = v
        .pointer("/results")
        .and_then(|x| x.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    assert_eq!(
        total.unwrap(),
        results_len,
        "BUG-15: search total_results ({}) should equal results.len() ({})",
        total.unwrap(),
        results_len
    );
}

// =============================================================================
// BUG-21: chop schema parity with slice
// =============================================================================

#[test]
fn bug21_chop_file_and_line_count_populated() {
    let Some(path) = flask_app_py_or_skip("bug21_chop_file_and_line_count_populated") else { return; };
    // Use lines that lie within the same function so the chop has a
    // real result (1230 -> 1235 inside `make_response`).
    let v = run_json(&[
        "chop",
        path.to_str().unwrap(),
        "make_response",
        "1230",
        "1235",
    ]);
    let file = v.get("file").and_then(|x| x.as_str()).unwrap_or("");
    assert!(
        !file.is_empty(),
        "BUG-21 regression: chop .file is null/empty (parity with slice broken). got: {v}"
    );
    let line_count = v.get("line_count").and_then(|x| x.as_u64());
    assert!(
        line_count.is_some(),
        "BUG-21 regression: chop missing 'line_count' (slice-parity field). got: {v}"
    );
    let lines_len = v
        .pointer("/lines")
        .and_then(|x| x.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    assert_eq!(
        line_count.unwrap(),
        lines_len,
        "BUG-21: line_count should equal lines.len(); got {} vs {}",
        line_count.unwrap(),
        lines_len
    );
}

// =============================================================================
// BUG-22: interface all_exports never null
// =============================================================================

#[test]
fn bug22_interface_all_exports_populated() {
    let Some(path) = flask_app_py_or_skip("bug22_interface_all_exports_populated") else { return; };
    let v = run_json(&["interface", path.to_str().unwrap()]);
    let exports = v.get("all_exports");
    assert!(
        exports.is_some(),
        "BUG-22 regression: .all_exports field is missing entirely; got {v}"
    );
    let exports = exports.unwrap();
    assert!(
        !exports.is_null(),
        "BUG-22 regression: .all_exports is null; expected array (use [] for empty modules)"
    );
    assert!(
        exports.is_array(),
        "BUG-22: .all_exports must be an array, got {exports:?}"
    );
    // flask/app.py defines public Flask class etc. — should have entries.
    assert!(
        !exports.as_array().unwrap().is_empty(),
        "BUG-22: flask/app.py has public symbols, expected non-empty all_exports"
    );
}

// =============================================================================
// BUG-23: extract methods carry line_end, not line_number
// =============================================================================

#[test]
fn bug23_extract_methods_have_line_end_not_line_number() {
    let Some(path) = flask_app_py_or_skip("bug23_extract_methods_have_line_end_not_line_number") else { return; };
    let v = run_json(&["extract", path.to_str().unwrap()]);
    // Find any class with a non-empty methods array.
    let classes = v
        .get("classes")
        .and_then(|x| x.as_array())
        .expect("classes array");
    let methods = classes
        .iter()
        .filter_map(|c| c.get("methods").and_then(|x| x.as_array()))
        .find(|a| !a.is_empty())
        .unwrap_or_else(|| panic!("no class with non-empty methods in flask/app.py"));
    let first = &methods[0];
    let keys: Vec<&str> = first
        .as_object()
        .expect("method is object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert!(
        keys.contains(&"line"),
        "extract method missing 'line': {keys:?}"
    );
    assert!(
        keys.contains(&"line_end"),
        "BUG-23 regression: extract method missing 'line_end': {keys:?}"
    );
    assert!(
        !keys.contains(&"line_number"),
        "BUG-23 regression: extract method still emits 'line_number' (duplicate of 'line'); should be dropped from JSON. keys: {keys:?}"
    );
}
