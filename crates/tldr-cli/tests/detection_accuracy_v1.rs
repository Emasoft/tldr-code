//! detection-accuracy-v1 — regression tests for 4 bugs (M3):
//!
//! - BUG-4: Rust `dead` analyzer treated `#[test]` functions and
//!   functions inside `#[cfg(test)] mod tests {}` as live, producing
//!   ~259 false positives on ripgrep. Fix: extract `attribute_item`
//!   siblings + walk `mod_item` ancestors during Rust function
//!   extraction, surfacing `test`/`cfg(test)` as decorators that the
//!   `dead` filter already honours.
//!
//! - BUG-16: Express/NestJS/Fastify/Next.js redirect sinks were wired
//!   as `TaintSinkType::FileWrite`, projecting through
//!   `vuln_type_from_sink` to `path_traversal` (CWE-22) and emitting
//!   findings labelled "FileWrite with unsanitized input" — wrong
//!   ontology for an HTTP redirect with attacker-controllable target.
//!   Fix: introduce `TaintSinkType::OpenRedirect` +
//!   `VulnType::OpenRedirect` (CWE-601), reroute `(res|response|reply|
//!   NextResponse|Response).redirect` and bare `redirect()` patterns.
//!
//! - BUG-17: degenerate taint flows where the source and sink collapse
//!   to the same statement (e.g. `let file = File::open(path)?;` —
//!   path is tainted, File::open is the sink). Pre-fix `taint_flow`
//!   emitted two identical entries with different "Source:" / "Sink:"
//!   labels. Fix: when source.line == sink.line && source.expression ==
//!   sink.expression, collapse `taint_flow` to a single entry and tag
//!   the finding with `direct_sink: true`.
//!
//! - BUG-20: `tldr references` JSON had `definition: <single object>`
//!   even when multiple definitions existed (e.g. flask
//!   `_make_timedelta`); the text formatter hard-coded "Definition:"
//!   (singular) regardless of count. Fix: add `definitions:
//!   Vec<Definition>` populated by a new public `find_definitions`
//!   helper; keep `definition` as a back-compat first-element view;
//!   text formatter prints "Definitions:" plural and lists all entries
//!   when count > 1.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
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

// =============================================================================
// BUG-4: Rust #[test] / mod tests recognition
// =============================================================================

/// Build a minimal Rust project with three test-marked functions and one
/// genuinely unused helper that should remain in the dead-code report.
fn build_rust_test_attribute_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Cargo.toml — minimal so the workspace walker recognises the crate.
    write(
        &root.join("Cargo.toml"),
        r#"[package]
name = "fixture_dead"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
    );

    write(
        &root.join("src/lib.rs"),
        r#"
// A genuinely-unused private helper — should show up in possibly_dead.
fn _truly_unused_helper() -> u32 {
    42
}

// Public entry point that calls another internal fn (so the call graph
// is non-trivial and the dead-code analyzer has something to chew on).
pub fn entry_point() -> u32 {
    nested_used_fn() + 1
}

// Internal function used by `entry_point` — referenced exactly once.
fn nested_used_fn() -> u32 {
    7
}

// Direct #[test] attribute — must be tagged is_test=true and excluded.
#[test]
fn direct_test_attr_function() {
    assert_eq!(1 + 1, 2);
}

// `#[cfg(test)] mod tests { ... }` — every fn inside should be is_test=true.
#[cfg(test)]
mod tests {
    use super::*;

    fn inside_cfg_test_mod() {
        let _ = entry_point();
    }

    #[test]
    fn nested_test_attr() {
        assert!(true);
    }
}

// `mod test_helpers { ... }` — name-based test-module heuristic should
// still classify these as is_test=true (per BUG-4 fix).
mod test_helpers {
    pub fn name_based_test_mod_fn() {}
}
"#,
    );

    dir
}

#[test]
fn rust_test_attribute_excluded_from_dead() {
    let dir = build_rust_test_attribute_project();
    let root = dir.path();

    let output = tldr_cmd()
        .args(["dead", root.to_str().unwrap()])
        .output()
        .expect("run tldr dead");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse JSON failed: {e}; stdout was:\n{stdout}"));

    // Both "high confidence" and "possibly dead" buckets must be inspected:
    // an unused private fn lands in `dead_functions`; a public-but-unused
    // fn lands in `possibly_dead`. The BUG-4 invariant is "no test fn ever
    // ends up in EITHER bucket".
    let dead_functions = v
        .get("dead_functions")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let all_dead: Vec<&Value> = dead_functions.iter().chain(possibly_dead.iter()).collect();
    let names: Vec<&str> = all_dead
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect();

    // The genuinely-unused private helper SHOULD appear in dead_functions
    // (sanity check that the analyzer is actually running over the fixture).
    assert!(
        names.iter().any(|n| *n == "_truly_unused_helper"),
        "expected `_truly_unused_helper` in dead_functions or possibly_dead; got: {names:?}"
    );

    // None of the test-attribute / test-module functions should appear in
    // either bucket — they all have a test-decorator (direct `#[test]`) OR
    // sit inside a `mod tests {}` / `#[cfg(test)] mod ...` block.
    let must_not = [
        "direct_test_attr_function",
        "inside_cfg_test_mod",
        "nested_test_attr",
        "name_based_test_mod_fn",
    ];
    for forbidden in &must_not {
        assert!(
            !names.contains(forbidden),
            "test-marked function `{forbidden}` MUST be excluded from \
             dead_functions and possibly_dead; got: {names:?}"
        );
    }

    // Cross-check: every reported entry must have is_test == false.
    for f in all_dead {
        let is_test = f.get("is_test").and_then(|b| b.as_bool()).unwrap_or(false);
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        assert!(
            !is_test,
            "dead-code report must not contain is_test=true entries; got `{name}`"
        );
    }
}

// =============================================================================
// BUG-16: JS redirect classified as open_redirect (NOT FileWrite/PathTraversal)
// =============================================================================

fn build_js_redirect_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Express-style controller — `exports.handler = function(req, res, next){}`
    // is the canonical detection shape exercised by the v1 RED suite. Arrow-
    // function handlers (`app.get('/x', (req,res) => {...})`) do not currently
    // trigger the JS taint engine's source detection, so use the function-
    // expression form to keep this regression test focused on the
    // open-redirect classification (BUG-16) rather than the orthogonal
    // arrow-fn source-detection gap.
    write(
        &root.join("server.js"),
        r#"
'use strict'

exports.handler = function(req, res, next){
  var dest = req.query.dest;
  res.redirect('/' + dest);
};
"#,
    );

    dir
}

#[test]
fn js_redirect_classified_as_open_redirect() {
    let dir = build_js_redirect_project();
    let root = dir.path();

    let output = tldr_cmd()
        .args(["vuln", root.to_str().unwrap()])
        .output()
        .expect("run tldr vuln");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse JSON failed: {e}; stdout was:\n{stdout}"));

    let findings = v
        .get("findings")
        .and_then(|x| x.as_array())
        .expect("findings array");

    // Locate the open_redirect finding among the report's findings. The JS
    // engine may emit a secondary sql_injection finding on the same line
    // (the `dest` variable name happens to overlap with SQL keywords); we
    // scope the assertion to the redirect-bound entry.
    let redirect_finding = findings
        .iter()
        .find(|f| f.get("vuln_type").and_then(|x| x.as_str()) == Some("open_redirect"));

    let f = redirect_finding.unwrap_or_else(|| {
        panic!("expected an `open_redirect` finding in vuln report; got: {v:#?}")
    });

    // vuln_type must be open_redirect (NOT path_traversal). This is the
    // BUG-16 invariant: pre-fix the JS `res.redirect(...)` sink projected
    // through `vuln_type_from_sink(FileWrite) = PathTraversal`.
    let vt = f.get("vuln_type").and_then(|x| x.as_str()).unwrap_or("");
    assert_eq!(
        vt, "open_redirect",
        "expected vuln_type=open_redirect for redirect sink; got `{vt}` (full finding: {f:#?})"
    );

    // CWE must be 601 (NOT 22).
    let cwe = f.get("cwe_id").and_then(|x| x.as_str()).unwrap_or("");
    assert_eq!(
        cwe, "CWE-601",
        "expected cwe_id=CWE-601; got `{cwe}` (full finding: {f:#?})"
    );

    // The terminal taint_flow entry's description must NOT call this a
    // FileWrite (it must reflect the OpenRedirect sink kind). Works for both
    // the two-step (Source → Sink) and one-step (direct_sink) shapes.
    let flow = f.get("taint_flow").and_then(|x| x.as_array()).unwrap();
    let sink_desc = flow
        .last()
        .and_then(|s| s.get("description"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(
        !sink_desc.contains("FileWrite"),
        "sink description must not contain `FileWrite` for an HTTP redirect; got `{sink_desc}`"
    );
    assert!(
        sink_desc.contains("OpenRedirect"),
        "sink description must mention `OpenRedirect`; got `{sink_desc}`"
    );
}

// =============================================================================
// BUG-17: degenerate source==sink flows are suppressed OR direct_sink-annotated
// =============================================================================

fn build_rust_direct_sink_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(
        &root.join("Cargo.toml"),
        r#"[package]
name = "fixture_direct_sink"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
    );

    // `let file = File::open(path)?;` is the canonical empirical case from
    // ripgrep `crates/cli/src/decompress.rs:362` — the canonical taint engine
    // marks the same statement as BOTH a source (FileRead) AND a sink
    // (FileOpen), which pre-BUG-17 emitted two identical taint_flow entries.
    write(
        &root.join("src/lib.rs"),
        r#"
use std::fs::File;
use std::path::Path;

pub fn open_helper(path: &Path) -> std::io::Result<File> {
    let file = File::open(path)?;
    Ok(file)
}
"#,
    );

    dir
}

#[test]
fn degenerate_source_eq_sink_suppressed_or_annotated() {
    let dir = build_rust_direct_sink_project();
    let root = dir.path();

    let output = tldr_cmd()
        .args(["vuln", root.to_str().unwrap()])
        .output()
        .expect("run tldr vuln");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse JSON failed: {e}; stdout was:\n{stdout}"));

    let findings = v
        .get("findings")
        .and_then(|x| x.as_array())
        .expect("findings array");

    // Walk every finding. For any taint_flow with two entries, those entries
    // MUST NOT be identical (same file + same line + same code_snippet) —
    // either the engine suppresses such entries or the CLI collapses them
    // into a single direct_sink:true step.
    for f in findings {
        let flow = match f.get("taint_flow").and_then(|x| x.as_array()) {
            Some(a) => a,
            None => continue,
        };
        if flow.len() == 2 {
            let a = &flow[0];
            let b = &flow[1];
            let same_file = a.get("file") == b.get("file");
            let same_line = a.get("line") == b.get("line");
            let same_code = a.get("code_snippet") == b.get("code_snippet");
            assert!(
                !(same_file && same_line && same_code),
                "found a degenerate taint_flow with two identical entries — BUG-17 \
                 regressed: {f:#?}"
            );
        }
    }

    // Additionally: when a finding IS a direct-sink (single-element
    // taint_flow), the `direct_sink` field MUST be present and true.
    for f in findings {
        let flow = f.get("taint_flow").and_then(|x| x.as_array());
        if let Some(tf) = flow {
            if tf.len() == 1 {
                let direct = f
                    .get("direct_sink")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                assert!(
                    direct,
                    "single-step taint_flow should be tagged direct_sink:true; got: {f:#?}"
                );
            }
        }
    }
}

// =============================================================================
// BUG-20: references emits `definitions: [..]` array; text says "Definitions:"
// =============================================================================

fn build_python_multi_definition_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Two distinct top-level definitions of `_make_timedelta` across two
    // files — mirrors the flask `sansio/app.py` + `app.py` pattern from
    // BUG-20's empirical repro.
    write(&root.join("pkg/__init__.py"), "");
    write(&root.join("pkg/sansio/__init__.py"), "");
    write(
        &root.join("pkg/sansio/app.py"),
        r#"
def _make_timedelta(value):
    """First definition (sansio layer)."""
    return value
"#,
    );
    write(
        &root.join("pkg/app.py"),
        r#"
def _make_timedelta(value):
    """Second definition (top app layer)."""
    return value

def caller():
    return _make_timedelta(5)
"#,
    );

    dir
}

#[test]
fn references_definitions_array_and_text_header_plural() {
    let dir = build_python_multi_definition_project();
    let root = dir.path();

    // JSON: `definitions` array must have len==2.
    let json_out = tldr_cmd()
        .args(["references", "_make_timedelta", root.to_str().unwrap()])
        .output()
        .expect("run tldr references (json)");

    let stdout = String::from_utf8(json_out.stdout).expect("utf8 stdout");
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse JSON failed: {e}; stdout was:\n{stdout}"));

    let defs = v
        .get("definitions")
        .and_then(|x| x.as_array())
        .unwrap_or_else(|| {
            panic!("expected `definitions` array on references report; got: {v:#?}")
        });

    assert_eq!(
        defs.len(),
        2,
        "expected 2 entries in `definitions` (one per file); got {} (full report: {v:#?})",
        defs.len()
    );

    // Each definition must point to a Python file under the fixture root.
    for def in defs {
        let file = def.get("file").and_then(|x| x.as_str()).unwrap_or("");
        assert!(
            file.ends_with("app.py"),
            "definition file should end with `app.py`; got `{file}`"
        );
    }

    // Backward-compat: `definition` (singular) is still the first entry.
    let single = v.get("definition");
    assert!(
        single.is_some(),
        "back-compat singular `definition` field must still be present"
    );

    // Text format: header must be plural, both entries listed.
    let text_out = tldr_cmd()
        .args([
            "references",
            "_make_timedelta",
            root.to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("run tldr references (text)");

    let text = String::from_utf8(text_out.stdout).expect("utf8 stdout");

    assert!(
        text.contains("Definitions:"),
        "text header must use plural `Definitions:` when count > 1; got:\n{text}"
    );
    // Singular header must NOT appear when plural is used (avoid both-headers).
    let pluralized_lines = text
        .lines()
        .filter(|l| l.trim() == "Definition:" || l.trim() == "Definitions:")
        .collect::<Vec<_>>();
    assert_eq!(
        pluralized_lines.len(),
        1,
        "exactly one `Definition(s):` header expected; got {pluralized_lines:?}"
    );
    assert_eq!(pluralized_lines[0].trim(), "Definitions:");
}
