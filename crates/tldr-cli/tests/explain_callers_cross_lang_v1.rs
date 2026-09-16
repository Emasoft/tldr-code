//! explain-callers-cross-lang-v1 (P15.AGG15-1): regression where
//! `tldr explain <relative-file> <fn>` returned `callers=[]` when invoked
//! from inside a project root, even though `tldr impact` (using an
//! explicit path argument) returned the correct caller list. The root
//! cause lived in `explain_project_root`: with a relative input like
//! `lib/application.js`, `Path::parent` walks `["lib", ""]`, and the
//! empty-path component's `join("package.json")` falsely "exists"
//! because it resolves against CWD. `explain_project_root` then
//! returned the empty path, `build_project_call_graph` could not
//! discover any source files, and the cross-file caller enrichment
//! short-circuited to nothing.
//!
//! Tests below all run with `current_dir(/tmp/repos/<repo>)` and pass
//! a *relative* file path to `tldr explain` to exercise the exact
//! invocation pattern that regressed. Non-regression tests cover the
//! P13/P14 fixes that share the explain/impact path.
//!
//! Per `no-synthetic-fixtures-v1`: each test gates on real-repo
//! presence (`/tmp/repos/<repo>`) and uses `≥ 1`-style numeric
//! thresholds the canonical real-repo material guarantees.

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

/// Run tldr with explicit working directory so we can pass relative
/// file paths from inside the target repo (the exact invocation
/// pattern that AGG15-1 regressed).
fn run_tldr_in(cwd: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
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

// ============================================================================
// AGG15-1 JS: explain render in express via relative path
// ============================================================================

#[test]
fn js_explain_render_relative_path_callers_present() {
    let repo = "/tmp/repos/express";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "explain",
            "lib/application.js",
            "render",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        callers >= 1,
        "js explain render: callers ({}) should be >= 1; AGG15-1 regression — \
         relative-path explain returned 0 callers because explain_project_root \
         resolved to empty path",
        callers
    );
}

// ============================================================================
// AGG15-1 Ruby: explain sanitize in rails-html-sanitizer via relative path
// ============================================================================

#[test]
fn ruby_explain_sanitize_relative_path_callers_present() {
    let repo = "/tmp/repos/rails-html-sanitizer";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "explain",
            "lib/rails/html/sanitizer.rb",
            "sanitize",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        callers >= 1,
        "ruby explain sanitize: callers ({}) should be >= 1; AGG15-1 regression",
        callers
    );
}

// ============================================================================
// AGG15-1 Swift: explain Heap._heapify via relative path
// AGG14-14 non-regression: callees must still attribute to the canonical
// definition file `Sources/HeapModule/Heap+UnsafeHandle.swift`.
// ============================================================================

#[test]
fn swift_explain_heapify_relative_path_callers_and_callee_files() {
    let repo = "/tmp/repos/swift-collections";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "explain",
            "Sources/HeapModule/Heap+UnsafeHandle.swift",
            "Heap._heapify",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        callers >= 1,
        "swift explain Heap._heapify: callers ({}) should be >= 1; AGG15-1 regression",
        callers
    );
    // P14-B AGG14-14 non-regression: at least one callee must attribute to the
    // canonical Heap+UnsafeHandle.swift definition file (not Tests/HeapTests/...).
    let callees = v["callees"].as_array().cloned().unwrap_or_default();
    let canonical_match = callees.iter().any(|c| {
        c["file"]
            .as_str()
            .map(|s| s.ends_with("Heap+UnsafeHandle.swift"))
            .unwrap_or(false)
    });
    assert!(
        canonical_match,
        "swift Heap._heapify: at least one callee must attribute to \
         Heap+UnsafeHandle.swift (P14-B AGG14-14 non-regression). Callees: {:?}",
        callees
    );
}

// ============================================================================
// Non-regression: csharp impact WriteToken caller_count == 2 (P14-B AGG14-4)
// ============================================================================

#[test]
fn csharp_impact_write_token_callers_two() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson-full";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "WriteToken", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr impact rc != 0; stdout={}", out);
    let v = parse_json(&out);
    // `tldr impact` emits `targets` as an object keyed by `<file>:<func>`,
    // not as an array. Sum caller_count across each target value.
    let total: u64 = v["targets"]
        .as_object()
        .map(|targets| {
            targets
                .values()
                .map(|t| t["caller_count"].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    assert!(
        total >= 2,
        "csharp impact WriteToken: total caller_count ({}) should be >= 2 \
         (P14-B AGG14-4 non-regression)",
        total
    );
}

// ============================================================================
// Non-regression: java impact dedup (P14-B AGG14-1) — caller_count==1, single target
// ============================================================================

#[test]
fn java_impact_dedup_holds() {
    let repo = "/tmp/repos/spring-petclinic";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "impact",
        "findPaginatedForOwnersLastName",
        repo,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr impact rc != 0; stdout={}", out);
    let v = parse_json(&out);
    // `tldr impact` emits `targets` as an object keyed by `<file>:<func>`.
    let targets_map = v["targets"].as_object().cloned().unwrap_or_default();
    let targets = targets_map.len();
    let total: u64 = targets_map
        .values()
        .map(|t| t["caller_count"].as_u64().unwrap_or(0))
        .sum();
    assert!(
        targets >= 1,
        "java impact dedup: at least one target expected, got {}",
        targets
    );
    assert!(
        total >= 1,
        "java impact findPaginatedForOwnersLastName: caller_count ({}) should be >= 1 \
         (P14-B AGG14-1 dedup non-regression)",
        total
    );
    // P14-B dedup: only one target entry (no fan-out per Reflection-discovered file).
    assert_eq!(
        targets, 1,
        "java impact dedup regression: expected exactly 1 target, got {}",
        targets
    );
}

// ============================================================================
// Non-regression: java explain callers + caller.line>0 (P14-C AGG14-16)
// ============================================================================

#[test]
fn java_explain_caller_line_populated() {
    let path = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "explain",
        path,
        "findPaginatedForOwnersLastName",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().cloned().unwrap_or_default();
    assert!(
        !callers.is_empty(),
        "java explain findPaginatedForOwnersLastName: callers should be non-empty"
    );
    let any_line_gt_zero = callers.iter().any(|c| c["line"].as_u64().unwrap_or(0) > 0);
    assert!(
        any_line_gt_zero,
        "java explain: at least one caller must have line > 0 \
         (P14-C AGG14-16 non-regression). Callers: {:?}",
        callers
    );
}

// ============================================================================
// Non-regression: lua m.open cross-module callers >= 18 (P13-A AGG13-12)
// ============================================================================

#[test]
fn lua_explain_m_open_cross_module_callers() {
    let repo = "/tmp/repos/lua-lsp";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &["explain", "script/files.lua", "m.open", "--format", "json"],
    );
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        callers >= 18,
        "lua explain m.open: cross-module callers ({}) should be >= 18 \
         (P13-A AGG13-12 + P14-B AGG14-13 non-regression)",
        callers
    );
}

// ============================================================================
// Non-regression: python explain dedup (P12-A) — flask finalize_request
// returns deduped callers (no duplicate name+file pairs).
// ============================================================================

#[test]
fn python_explain_no_duplicate_callers() {
    let repo = "/tmp/repos/flask";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "explain",
            "src/flask/app.py",
            "finalize_request",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callers = v["callers"].as_array().cloned().unwrap_or_default();
    let total = callers.len();
    let mut keys: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for c in &callers {
        let name = c["name"].as_str().unwrap_or("").to_string();
        let file = c["file"].as_str().unwrap_or("").to_string();
        keys.insert((name, file));
    }
    assert!(
        total >= 1,
        "python explain finalize_request: callers ({}) should be >= 1",
        total
    );
    assert_eq!(
        total,
        keys.len(),
        "python explain dedup regression: {} callers but {} unique (name,file) keys \
         (P12-A AGG12-1 non-regression)",
        total,
        keys.len()
    );
}
