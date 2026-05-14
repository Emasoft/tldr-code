//! explain-callees-in-project-v1 — v0.4.2 M-019 regression tests.
//!
//! Audit cluster M-019 found that `tldr explain` emits `file: "<external>"`
//! for callees that are in fact defined within the same project (and often
//! within the same file). The call-graph builder DOES discover the
//! corresponding edge, but the existing `enrich_with_project_graph` callee
//! merge skips emitting the in-project file when an `<external>` placeholder
//! was already pushed by the per-file walker. This produces the
//! `/tmp/repos/<x>/<external>` shape seen in audit cells:
//!
//!   c     c47 sdsnewlen     — `sdsnewlen` defined in `sds.c` (same file)
//!   cpp   c46 Clear/SetError — same file (tinyxml2.cpp)
//!   go    c47 CleanPath     — same project, different file (path.go)
//!   java  c47 getLastName   — same project, different file (Owner.java)
//!   scala c46 Poll          — wrongly reported under same-file with line 0
//!
//! These tests are language-agnostic: each builds a tiny in-tempdir
//! fixture (so the test does not depend on `/tmp/repos/<x>` being present)
//! and asserts that callees defined IN the project are NEVER emitted with
//! `file: "<external>"`. A callee with a `file` matching `<external>` is
//! the symptom under test.
//!
//! Real-repo tests (gated on `/tmp/repos/<x>` existence, silently skipped
//! otherwise) provide cross-checks against the production fixtures used
//! by the Phase-22 audit.

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

fn run_explain(file: &Path, function: &str) -> Value {
    let out = tldr_cmd()
        .arg("explain")
        .arg(file)
        .arg(function)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tldr explain");
    assert!(
        out.status.success(),
        "tldr explain {} {} failed: stderr={}",
        file.display(),
        function,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("parse explain JSON for {}::{}: {} -- stdout={}", file.display(), function, e, stdout)
    })
}

fn callees(v: &Value) -> Vec<(String, String)> {
    v.get("callees")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .map(|e| {
                    (
                        e.get("name").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                        e.get("file").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Walks every callee[].file and asserts that NONE contains the literal
/// substring `<external>` for any callee whose name appears in `inproject`.
/// `<external>` is permitted only for callees that are truly external
/// (system/library calls like `strlen`, `len`, …).
fn assert_inproject_callees_have_real_files(report: &Value, inproject: &[&str]) {
    let cs = callees(report);
    for name in inproject {
        let matches: Vec<&(String, String)> =
            cs.iter().filter(|(n, _)| n == name || n.ends_with(name)).collect();
        assert!(
            !matches.is_empty(),
            "expected callee {} in report, got: {:?}",
            name,
            cs
        );
        for (n, f) in matches {
            assert!(
                !f.contains("<external>"),
                "callee {} resolved to external file {} (expected an in-project path); full callees={:?}",
                n,
                f,
                cs
            );
        }
    }
}

// =============================================================================
// Same-file in-project callees (c, cpp shape — sdsnewlen, Clear, SetError)
// =============================================================================

/// Build a C project where `caller` calls `same_file_helper` (defined in
/// the same translation unit) and `external_func` (libc-shaped — undefined
/// in this project). The audit cell c47/sds.c::sdsnew shows the symptom:
/// `sdsnewlen` (defined right next to `sdsnew` in `sds.c`) is reported
/// with `file: "<external>"`.
fn build_c_same_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    // Marker so explain_project_root walks up.
    write(&root.join("Makefile"), "all:\n\techo build\n");
    write(
        &root.join("util.c"),
        r#"#include <string.h>

char* same_file_helper(const char* x) {
    return (char*)x;
}

char* caller(const char* init) {
    size_t n = strlen(init);
    return same_file_helper(init);
}
"#,
    );
    dir
}

#[test]
fn c_same_file_callee_resolves_to_real_path() {
    let dir = build_c_same_file_project();
    let root = dir.path();
    let util_c = root.join("util.c");
    let report = run_explain(&util_c, "caller");
    // same_file_helper lives in util.c — must resolve to that file, not
    // "<external>". `strlen` may stay external (libc).
    assert_inproject_callees_have_real_files(&report, &["same_file_helper"]);
}

/// Build a Go project mirroring the audit c47 router.go::ServeHTTP shape:
/// callee defined in a sibling file (`path.go::CleanPath`) — the
/// call-graph DOES discover the edge but the explain merge drops the
/// in-project file because an `<external>` placeholder was emitted first.
fn build_go_cross_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(&root.join("go.mod"), "module example/router\n\ngo 1.21\n");
    write(
        &root.join("path.go"),
        r#"package router

func CleanPath(p string) string {
    return p
}
"#,
    );
    write(
        &root.join("router.go"),
        r#"package router

func ServeHTTP(p string) string {
    return CleanPath(p)
}
"#,
    );
    dir
}

#[test]
fn go_cross_file_callee_resolves_to_real_path() {
    let dir = build_go_cross_file_project();
    let root = dir.path();
    let router_go = root.join("router.go");
    let report = run_explain(&router_go, "ServeHTTP");
    assert_inproject_callees_have_real_files(&report, &["CleanPath"]);
}

/// Build a Java project mirroring the audit c47 OwnerController shape:
/// callee `getLastName` defined in sibling file `Owner.java`.
fn build_java_cross_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(&root.join("pom.xml"), "<project></project>\n");
    let pkg = root.join("src/main/java/com/example");
    write(
        &pkg.join("Owner.java"),
        r#"package com.example;

public class Owner {
    private String lastName;
    public String getLastName() { return lastName; }
}
"#,
    );
    write(
        &pkg.join("OwnerController.java"),
        r#"package com.example;

public class OwnerController {
    public String processFindForm(Owner owner) {
        return owner.getLastName();
    }
}
"#,
    );
    dir
}

#[test]
fn java_cross_file_callee_resolves_to_real_path() {
    let dir = build_java_cross_file_project();
    let oc = dir
        .path()
        .join("src/main/java/com/example/OwnerController.java");
    let report = run_explain(&oc, "processFindForm");
    assert_inproject_callees_have_real_files(&report, &["getLastName"]);
}

/// Build a Kotlin project mirroring the audit c47 Instant.kt shape:
/// callee `offsetIn` defined in sibling file under same project root.
fn build_kotlin_cross_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(&root.join("build.gradle.kts"), "// kt project\n");
    let src = root.join("src/main/kotlin");
    write(
        &src.join("Offset.kt"),
        r#"package datetime

fun offsetIn(x: Long): Long {
    return x + 1
}
"#,
    );
    write(
        &src.join("Instant.kt"),
        r#"package datetime

fun periodUntil(t: Long): Long {
    return offsetIn(t)
}
"#,
    );
    dir
}

#[test]
fn kotlin_cross_file_callee_resolves_to_real_path() {
    let dir = build_kotlin_cross_file_project();
    let instant_kt = dir.path().join("src/main/kotlin/Instant.kt");
    let report = run_explain(&instant_kt, "periodUntil");
    assert_inproject_callees_have_real_files(&report, &["offsetIn"]);
}

/// Build a C++ project where the callee is a method on the same class
/// defined in the SAME file (mirrors the audit c46 tinyxml2 shape:
/// `XMLDocument::Parse` calls `Clear`/`SetError` defined in the same
/// translation unit).
fn build_cpp_same_file_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(&root.join("Makefile"), "all:\n\techo build\n");
    write(
        &root.join("doc.cpp"),
        r#"#include <cstring>

class XMLDocument {
public:
    void Clear() {}
    void SetError(int code) { (void)code; }
    int Parse(const char* p, size_t len) {
        Clear();
        SetError(0);
        return (int)len;
    }
};
"#,
    );
    dir
}

#[test]
fn cpp_same_file_method_callee_resolves_to_real_path() {
    let dir = build_cpp_same_file_project();
    let doc_cpp = dir.path().join("doc.cpp");
    let report = run_explain(&doc_cpp, "Parse");
    // Clear and SetError are defined in doc.cpp itself.
    assert_inproject_callees_have_real_files(&report, &["Clear", "SetError"]);
}

// =============================================================================
// Real-repo cross-checks (gated; skipped silently when fixtures absent)
// =============================================================================

fn fixture_exists(p: &str) -> bool {
    Path::new(p).exists()
}

#[test]
fn real_repo_c_sds_sdsnewlen_not_external() {
    let f = "/tmp/repos/c-sds/sds.c";
    if !fixture_exists(f) {
        eprintln!("skip: {} not present", f);
        return;
    }
    let report = run_explain(Path::new(f), "sdsnew");
    // sdsnewlen is defined in sds.c itself; must NOT be <external>.
    assert_inproject_callees_have_real_files(&report, &["sdsnewlen"]);
}

#[test]
fn real_repo_go_httprouter_servehttp_cleanpath_not_external() {
    let f = "/tmp/repos/go-httprouter/router.go";
    if !fixture_exists(f) {
        eprintln!("skip: {} not present", f);
        return;
    }
    let report = run_explain(Path::new(f), "ServeHTTP");
    // CleanPath, getValue, findCaseInsensitivePath are all in-project
    // (path.go / tree.go). They must NOT be <external>.
    assert_inproject_callees_have_real_files(
        &report,
        &["CleanPath", "getValue", "findCaseInsensitivePath"],
    );
}
