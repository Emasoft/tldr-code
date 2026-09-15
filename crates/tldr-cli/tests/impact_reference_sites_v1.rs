//! impact-reference-sites-v1 (issue #1) — `tldr impact` must not claim
//! "Entry point - no callers found" when the target function IS referenced
//! through a non-call site.
//!
//! Issue repro (ghbook): a click handler was wired as
//! `$('collect-btn').addEventListener('click', collectBtnClick);` — the
//! `collectBtnClick` identifier is an ARGUMENT of a call, so the TS/JS
//! reference classifier has no `arguments`-parent arm and falls to the
//! catch-all `Read` kind. `impact`'s references enrichment used to request
//! only `kinds=[Call]`, that site was discarded by the kind filter, and the
//! target was reported as an unreferenced entry point even though the whole
//! app pointed at it.
//!
//! After the fix, non-call reference sites become synthetic caller entries
//! labeled "reference (not a call) at line {line}", while a defined-but-
//! never-referenced function (negative control) keeps its honest
//! no-callers note.
//!
//! All fixtures are built in a tempdir; the project ships a `package.json`
//! manifest plus a `.js` source so `Language::from_directory` resolves to
//! JavaScript deterministically. No DOM/runtime is needed — tldr is static.

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

/// Mimic the issue #1 ghbook shape: a plain global `$` helper, a handler
/// (`collectBtnClick`) wired as the SECOND ARGUMENT of an `addEventListener`
/// call (a non-call Read of the identifier), a real call edge
/// (`collectBtnClick` -> `cancelCollect`), and a defined-but-never-
/// referenced function as the negative control. The `addEventListener`
/// wiring line is intentionally the LAST line of the file so it sits outside
/// every function's [start, end] range and resolves to the `<module>`
/// enclosing scope. The negative control CALLS `$` so it is a source of a
/// call-graph edge (it lands on the plain entry-point path, not only the
/// AST-fallback path) while nothing ever references IT.
fn build_js_wiring_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Manifest so language auto-detection is deterministic (JavaScript —
    // no typescript dep declared).
    write(
        &root.join("package.json"),
        "{\n  \"name\": \"impact-reference-sites-fixture\"\n}\n",
    );

    write(
        &root.join("public/app.js"),
        r#"function $(sel) {
  return null;
}

function cancelCollect() {
  return false;
}

function collectBtnClick() {
  cancelCollect();
}

function someNeverReferencedFn() {
  $('nothing');
  return 1;
}

$('collect-btn').addEventListener('click', collectBtnClick);
"#,
    );

    dir
}

fn impact_json(root: &Path, func: &str) -> Value {
    let out = tldr_cmd()
        .arg("impact")
        .arg(func)
        .arg(".")
        .arg("--format")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap_or_else(|e| panic!("run tldr impact {func}: {e}"));
    assert!(
        out.status.success(),
        "tldr impact {func} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "impact {func} JSON parse: {e}; stdout={}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// `ImpactReport.targets` is keyed `"{file}:{function}"` (see
/// `impact_analysis` / `impact_analysis_with_ast_fallback`,
/// tldr-core/src/analysis/impact.rs), so a lookup by bare function name must
/// resolve through the entry's `function` field (or the key's `:`-suffix),
/// never the map key itself.
fn find_target<'a>(v: &'a Value, func: &str) -> &'a Value {
    let targets = v
        .get("targets")
        .and_then(|t| t.as_object())
        .unwrap_or_else(|| panic!("targets object missing: {v}"));
    if let Some(t) = targets.get(func) {
        return t;
    }
    let suffix = format!(":{func}");
    for (key, t) in targets {
        if key.ends_with(&suffix)
            || t.get("function").and_then(|f| f.as_str()) == Some(func)
        {
            return t;
        }
    }
    panic!(
        "no target entry for {func}; keys={:?}",
        targets.keys().collect::<Vec<_>>()
    );
}

/// The issue #1 repro: `collectBtnClick` is referenced (non-call) by the
/// addEventListener wiring line. It must NOT be reported as an unreferenced
/// entry point — the reference site must appear as a caller labeled
/// "reference (not a call)".
#[test]
fn impact_reference_site_labeled_not_a_call() {
    let dir = build_js_wiring_project();
    let root = dir.path();

    let v = impact_json(root, "collectBtnClick");
    let target = find_target(&v, "collectBtnClick");

    let caller_count = target
        .get("caller_count")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!("caller_count missing: {target}"));
    assert!(
        caller_count >= 1,
        "issue #1: referenced function must have caller_count >= 1, got {caller_count}: {target}"
    );

    let note = target
        .get("note")
        .and_then(|n| n.as_str())
        .unwrap_or_default();
    assert!(
        !note.contains("Entry point") && !note.contains("no callers"),
        "issue #1: target must not claim 'Entry point - no callers found' when it is referenced; note={note:?}"
    );

    let callers = target
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array");
    assert!(
        !callers.is_empty(),
        "issue #1: callers array must be non-empty; target={target}"
    );
    let has_reference_site = callers.iter().any(|c| {
        c.get("note")
            .and_then(|n| n.as_str())
            .map(|n| n.contains("reference (not a call)"))
            .unwrap_or(false)
    });
    assert!(
        has_reference_site,
        "expected a caller whose note contains 'reference (not a call)'; callers={callers:?}"
    );
}

/// The real call edge (`collectBtnClick` calls `cancelCollect`) must keep
/// working: `cancelCollect` shows `collectBtnClick` among its callers — and
/// the references enrichment must NOT duplicate it (the addition dedups
/// against the existing call-graph caller by name, so the count stays put).
#[test]
fn impact_call_edge_target_transitively_shows_caller() {
    let dir = build_js_wiring_project();
    let root = dir.path();

    let v = impact_json(root, "cancelCollect");
    let target = find_target(&v, "cancelCollect");

    let caller_count = target
        .get("caller_count")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!("caller_count missing: {target}"));
    assert!(
        caller_count >= 1,
        "cancelCollect must keep its real call-edge caller, got caller_count={caller_count}: {target}"
    );

    let callers = target
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array");
    let names: Vec<&str> = callers
        .iter()
        .filter_map(|c| c.get("function").and_then(|f| f.as_str()))
        .collect();
    assert!(
        names.iter().any(|n| n.contains("collectBtnClick")),
        "cancelCollect should transitively show collectBtnClick as caller; got {names:?}"
    );
    // Dedup: collectBtnClick must appear exactly once even though references
    // also reports the call site inside it.
    let dupes = names.iter().filter(|n| n.contains("collectBtnClick")).count();
    assert_eq!(
        dupes, 1,
        "references enrichment must not duplicate an existing call-graph caller: {names:?}"
    );
}

/// Negative control: a function that is defined but NEVER referenced or
/// called must STILL report its honest no-callers note — the enrichment must
/// not fabricate callers from nothing. Depending on which report path fires
/// (call-graph entry point vs AST fallback), the honest note reads either
/// "Entry point - no callers found" or the VAL-007 AST-fallback wording
/// ("...has no call edges..."); both are no-callers notes and neither may
/// claim the function is referenced.
#[test]
fn impact_unreferenced_function_still_reports_entry_point() {
    let dir = build_js_wiring_project();
    let root = dir.path();

    let v = impact_json(root, "someNeverReferencedFn");
    let target = find_target(&v, "someNeverReferencedFn");

    let caller_count = target
        .get("caller_count")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!("caller_count missing: {target}"));
    assert_eq!(
        caller_count, 0,
        "unreferenced function must have caller_count == 0: {target}"
    );

    let note = target
        .get("note")
        .and_then(|n| n.as_str())
        .unwrap_or_default();
    let honest_no_callers = note.contains("Entry point")
        || note.contains("no callers")
        || note.contains("no call edges");
    assert!(
        honest_no_callers,
        "negative control: defined-but-never-referenced function must keep its no-callers note; note={note:?}"
    );
    assert!(
        !note.contains("reference (not a call)") && !note.contains("Referenced at"),
        "negative control: enrichment must not claim the unreferenced function is referenced; note={note:?}"
    );
    let callers = target
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array");
    assert!(
        callers.is_empty(),
        "negative control: unreferenced function must have no caller entries; callers={callers:?}"
    );
}
