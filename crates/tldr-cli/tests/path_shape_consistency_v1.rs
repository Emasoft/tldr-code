//! path-shape-consistency-v1 (v0.4.2 M-008): every tldr command MUST emit
//! a single path shape per response. Either every path matches the user's
//! input shape (absolute when user passes absolute, project-relative when
//! user passes relative), or every path is project-relative — never both
//! within the same JSON response.
//!
//! On macOS, the firmlink `/tmp -> /private/tmp` MUST be transparently
//! stripped at the emission boundary; a user who passes `/tmp/repos/X`
//! must NEVER see `/private/tmp/repos/X` echoed back.
//!
//! This test is the cluster-M-008 mechanical-consistency probe. The
//! companion design item (D-CROSS-1 — what the canonical path convention
//! should be: absolute / project-relative / paired root+relative) is
//! parked separately; this file only asserts that whatever shape a single
//! response picks, it sticks with it for ALL paths in that response, and
//! that macOS firmlinks never leak.
//!
//! Cross-cmd companion `cross_cmd_path_shape_v1.rs` (already shipped)
//! covers the Scala/explain/smells/deps surface. This file extends the
//! same invariant across the Phase-22 impact/change-impact/calls/structure
//! surface for at least 3 representative languages.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`: every test returns
//! early if the relevant fixture under `/tmp/repos/` is absent.
//!
//! See /tmp/audit_phase22/iteration1/aggregated_clusters.md#CLUSTER-M-008.

use std::path::Path;
use std::process::Command;

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

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

/// Collect every JSON string value whose **key** is in the path-like set.
/// We only check keys we know carry filesystem paths so that JSON values
/// that legitimately contain `/` (e.g. routing constraints, URL patterns
/// like `"path=/foo"`) do not cause spurious failures.
const PATH_LIKE_KEYS: &[&str] = &["file", "file_path", "path", "src_file", "dst_file"];

fn collect_path_values<'a>(
    v: &'a serde_json::Value,
    out: &mut Vec<(String, &'a str)>,
    parent_key: &str,
) {
    match v {
        serde_json::Value::String(s) => {
            if PATH_LIKE_KEYS.contains(&parent_key) {
                out.push((parent_key.to_string(), s.as_str()));
            }
        }
        serde_json::Value::Array(arr) => {
            for x in arr {
                collect_path_values(x, out, parent_key);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, vv) in map {
                collect_path_values(vv, out, k.as_str());
            }
        }
        _ => {}
    }
}

/// Assert no path-like field starts with `/private/tmp/` — that is the
/// macOS firmlink leak that destroys user-input shape on Darwin. The
/// emission-boundary normalizer must strip `/private` whenever the
/// user-input root does NOT itself start with `/private`.
fn assert_no_private_leak(v: &serde_json::Value, cmd: &str) {
    let mut paths: Vec<(String, &str)> = Vec::new();
    collect_path_values(v, &mut paths, "");
    let leak = paths.iter().find(|(_, s)| s.starts_with("/private/tmp/"));
    assert!(
        leak.is_none(),
        "{}: macOS firmlink leak — path-like field starts with /private/tmp/. \
         Got: {:?}",
        cmd,
        leak
    );
}

/// Core invariant: every path-like field in the response must share the
/// SAME shape — all absolute, or all relative. `tldr` may legitimately
/// emit absolute (when user passed absolute) or relative (when user
/// passed relative or when paths are paired with a `root` field) — but
/// MIXING the two within one response is the M-008 bug.
///
/// The `root_field` argument names the top-level absolute-root field
/// (typically `"root"` or `"path"`) which is exempt from the homogeneity
/// check because the root + project-relative pairing pattern is valid by
/// design (see D-CROSS-1 parked design item).
fn assert_homogeneous_path_shape(v: &serde_json::Value, cmd: &str, root_field: &str) {
    let mut paths: Vec<(String, &str)> = Vec::new();
    collect_path_values(v, &mut paths, "");
    // Exempt the top-level root field (paired pattern).
    let nested: Vec<&(String, &str)> = paths
        .iter()
        .filter(|(k, _)| k != root_field)
        .collect();

    if nested.is_empty() {
        return;
    }
    let abs_count = nested.iter().filter(|(_, p)| p.starts_with('/')).count();
    let rel_count = nested.len() - abs_count;
    assert!(
        abs_count == 0 || rel_count == 0,
        "{}: MIXED abs+rel path shapes in same response — {} absolute, {} relative. \
         Sample abs: {:?}. Sample rel: {:?}",
        cmd,
        abs_count,
        rel_count,
        nested.iter().find(|(_, p)| p.starts_with('/')),
        nested.iter().find(|(_, p)| !p.starts_with('/')),
    );
}

const GO_REPO: &str = "/tmp/repos/go-httprouter";
const PY_REPO: &str = "/tmp/repos/flask";
const SCALA_REPO: &str = "/tmp/repos/scala-cats-effect";
const JS_REPO: &str = "/tmp/repos/express";

// =============================================================================
// 1. `tldr impact <fn> <abs-go-repo>` — the go c07 canonical evidence.
//    Pre-fix: `targets["router.go:Router.ServeHTTP"].file` was
//    `"router.go"` (rel) while `targets[".../router_test.go:ServeHTTP"].file`
//    was `/tmp/repos/.../router_test.go` (abs) — same response, two shapes.
//    Post-fix: every `.file` MUST share the shape of the user-passed root.
// =============================================================================
#[test]
fn impact_go_path_shape_homogeneous() {
    if !Path::new(GO_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "ServeHTTP", GO_REPO]);
    assert_eq!(rc, 0, "tldr impact (go) failed: {}", out);
    let v = parse_json(&out);
    assert_no_private_leak(&v, "tldr impact (go)");
    // impact has no top-level `root` field; every `.file` should be abs.
    assert_homogeneous_path_shape(&v, "tldr impact (go)", "__none__");
}

// =============================================================================
// 2. `tldr verify <abs-py-repo>` — the python c39 canonical evidence.
//    Pre-fix: `sub_results.contracts.data[].file` leaked `/private/tmp/...`.
//    Already partially addressed by M-011 hotfix b408ff7, but the
//    centralized normalizer (M-008) must keep it green AND must not
//    regress on a deeper Darwin-only path.
// =============================================================================
#[test]
fn verify_python_no_private_leak() {
    if !Path::new(PY_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["verify", PY_REPO]);
    // verify may exit non-zero (no test dir etc); shape is what matters.
    let _ = rc;
    let v = parse_json(&out);
    assert_no_private_leak(&v, "tldr verify (python)");
    // top-level `path` is the user-input root by design.
    if let Some(p) = v["path"].as_str() {
        assert_eq!(
            p, PY_REPO,
            "verify (python) top-level path must echo user input. Got: {}",
            p
        );
    }
}

// =============================================================================
// 3. `tldr impact <fn> <abs-py-repo>` — cross-lang regression: python
//    impact must not mix abs+rel either. Pre-fix, the
//    `impact_analysis_with_ast_fallback` AST-fallback branch emits
//    absolute paths while the call-graph branch emits relative — same
//    bug shape as the go c07 evidence.
// =============================================================================
#[test]
fn impact_python_path_shape_homogeneous() {
    if !Path::new(PY_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "create_app", PY_REPO]);
    // impact may exit non-zero if function not found across all configs;
    // shape is what matters when JSON IS emitted.
    let _ = rc;
    let v = parse_json(&out);
    if v.is_null() {
        return;
    }
    assert_no_private_leak(&v, "tldr impact (python)");
    assert_homogeneous_path_shape(&v, "tldr impact (python)", "__none__");
}

// =============================================================================
// 4. `tldr impact <fn> <abs-scala-repo>` — scala regression: same
//    invariant. The scala-cats-effect corpus is the same one used by
//    cross_cmd_path_shape_v1.rs so this guarantees the M-008 normalizer
//    plays well with the M3/cross-cmd-path-shape-v1 rewrites already in
//    place.
// =============================================================================
#[test]
fn impact_scala_path_shape_homogeneous() {
    if !Path::new(SCALA_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "interpret", SCALA_REPO]);
    let _ = rc;
    let v = parse_json(&out);
    if v.is_null() {
        return;
    }
    assert_no_private_leak(&v, "tldr impact (scala)");
    assert_homogeneous_path_shape(&v, "tldr impact (scala)", "__none__");
}

// =============================================================================
// 5. `tldr impact <fn> <abs-js-repo>` — javascript regression: same
//    invariant for the express corpus.
// =============================================================================
#[test]
fn impact_javascript_path_shape_homogeneous() {
    if !Path::new(JS_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "Router", JS_REPO]);
    let _ = rc;
    let v = parse_json(&out);
    if v.is_null() {
        return;
    }
    assert_no_private_leak(&v, "tldr impact (javascript)");
    assert_homogeneous_path_shape(&v, "tldr impact (javascript)", "__none__");
}
