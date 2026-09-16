//! language-specific-bugs-v1 (P14 follow-up): per-language bug fixes
//! surfaced by the phase-14 audit but not addressed by P14-A
//! (cross-language resolver) or P14-B (sibling-resolver gaps).
//!
//! Each test gates on `/tmp/repos/<repo>` existence per the
//! no-synthetic-fixtures-v1 strategy. All assertions are `≥ 1` style
//! with numeric thresholds the canonical real-repo material guarantees.
//!
//! Bugs covered:
//!
//! - AGG14-2  Java MockMvc fluent assertions in `specs --from-tests`
//! - AGG14-7  TypeScript call graph empty on src/build/ source layouts
//! - AGG14-9  Rust `specs --from-tests` recognising `#[test]` items
//! - AGG14-10 Rust `interface` collecting `pub fn` from impl blocks
//! - AGG14-11 Scala `importers` matching dotted FQCN imports
//! - AGG14-12 Java `reaching-defs` not flagging class-level final fields
//! - AGG14-15 Java `api-check` JV001 excluding `== null` idiom
//! - AGG14-16 Java `explain` callees + caller.line populated
//! - AGG14-17 Java `interface` flattening class methods to functions[]

use std::path::Path;
use std::process::Command;

/// Helper: invoke the installed tldr binary via Cargo's release build (the
/// path canonical for milestone tests across this crate's existing
/// `*_v1.rs` files).
fn tldr_bin() -> std::path::PathBuf {
    // Mirrors the convention used by `quality_metrics_and_schema_v1.rs`,
    // `sibling_resolver_gaps_v1.rs`: invoke the in-tree release binary
    // so tests reflect the milestone's actual build artifact.
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

// ============================================================================
// Bug 1 (AGG14-2): Java MockMvc fluent assertions in specs --from-tests
// ============================================================================

#[test]
fn java_mockmvc_specs_from_tests() {
    let path = "/tmp/repos/spring-petclinic/src/test/java/org/springframework/samples/petclinic/owner/OwnerControllerTests.java";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr specs --from-tests exited non-zero");
    let v = parse_json(&out);
    let total = v["summary"]["total_specs"].as_u64().unwrap_or(0);
    let scanned = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert!(
        total >= 10,
        "java MockMvc specs total ({}) should be >= 10 across 13 @Test methods",
        total
    );
    assert!(
        scanned >= 13,
        "java test_functions_scanned ({}) should be >= 13",
        scanned
    );
}

// ============================================================================
// Bug 2 (AGG14-7): TypeScript call graph nodes/edges populated on a repo
// whose source lives under src/build/ (which was previously excluded as a
// build-artifact directory).
// ============================================================================

#[test]
fn typescript_call_graph_under_src_build() {
    let path = "/tmp/repos/ts-dom-gen";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["calls", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr calls exited non-zero");
    let v = parse_json(&out);
    let nodes = v["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let edges = v["edges"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        nodes >= 6,
        "ts-dom-gen call graph nodes ({}) should be >= 6 (emitter.ts has 6 functions)",
        nodes
    );
    assert!(
        edges >= 1,
        "ts-dom-gen call graph edges ({}) should be >= 1 (emitter.ts inter-function calls)",
        edges
    );
}

// ============================================================================
// Bug 3 (AGG14-9): Rust specs --from-tests on lib.rs with inline #[test] mod
// ============================================================================

#[test]
fn rust_specs_inline_test_module() {
    let path = "/tmp/repos/ripgrep/crates/globset/src/lib.rs";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr specs --from-tests exited non-zero");
    let v = parse_json(&out);
    let total = v["summary"]["total_specs"].as_u64().unwrap_or(0);
    let scanned = v["summary"]["test_functions_scanned"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "rust specs total ({}) should be >= 1 from #[test] items",
        total
    );
    assert!(
        scanned >= 1,
        "rust test_functions_scanned ({}) should be >= 1",
        scanned
    );
}

// ============================================================================
// Bug 4 (AGG14-10): Rust interface gathers methods from impl blocks
// ============================================================================

#[test]
fn rust_interface_impl_methods() {
    let path = "/tmp/repos/ripgrep/crates/globset/src/lib.rs";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["interface", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr interface exited non-zero");
    let v = parse_json(&out);
    let classes = v["classes"].as_array().expect("classes array");
    let total_methods: usize = classes
        .iter()
        .map(|c| c["methods"].as_array().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        total_methods >= 10,
        "rust interface total methods across all impl blocks ({}) should be >= 10",
        total_methods
    );
    // Specifically verify GlobSet has at least one method (it has 13 in
    // ripgrep globset/src/lib.rs).
    let glob_set_methods = classes
        .iter()
        .find(|c| c["name"].as_str() == Some("GlobSet"))
        .and_then(|c| c["methods"].as_array().map(|m| m.len()))
        .unwrap_or(0);
    assert!(
        glob_set_methods >= 1,
        "GlobSet methods ({}) should be >= 1",
        glob_set_methods
    );
}

// ============================================================================
// Bug 5a (AGG14-11): Scala importers FQCN match for dotted import paths
// ============================================================================

#[test]
fn scala_importers_fqcn_subpath() {
    let path = "/tmp/repos/scala-cats-effect";
    if !Path::new(path).exists() {
        return;
    }
    // The repo has files importing `cats.effect.kernel.X` — a query for
    // the package prefix `cats.effect` should also match those.
    let (rc, out) = run_tldr(&["importers", "cats.effect", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr importers exited non-zero");
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "scala importers for 'cats.effect' ({}) should be >= 1",
        total
    );
}

// ============================================================================
// Bug 6 (AGG14-12): Java reaching-defs does not flag class-level final
// fields (DI-injected `owners`).
// ============================================================================

#[test]
fn java_reaching_defs_no_class_field_fp() {
    let path = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "reaching-defs",
        path,
        "findPaginatedForOwnersLastName",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr reaching-defs exited non-zero");
    let v = parse_json(&out);
    let uninit = v["uninitialized"].as_array().cloned().unwrap_or_default();
    let owners_flagged = uninit
        .iter()
        .filter(|u| u["var"].as_str() == Some("owners"))
        .count();
    assert_eq!(
        owners_flagged, 0,
        "owners (class-level final field) should NOT be flagged uninitialized"
    );
}

// ============================================================================
// Bug 7 (AGG14-15): Java api-check JV001 excludes `== null` comparisons
// ============================================================================

#[test]
fn java_api_check_no_null_comparison_fp() {
    let path = "/tmp/repos/spring-petclinic/src/main/java";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["api-check", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr api-check exited non-zero");
    let v = parse_json(&out);
    let findings = v["findings"].as_array().cloned().unwrap_or_default();
    let jv001_null_lines: Vec<_> = findings
        .iter()
        .filter(|f| f["rule"]["id"].as_str() == Some("JV001"))
        .filter(|f| {
            let ctx = f["code_context"].as_str().unwrap_or("");
            ctx.contains("== null") || ctx.contains("!= null")
        })
        .collect();
    assert_eq!(
        jv001_null_lines.len(),
        0,
        "JV001 should NOT flag `== null` / `!= null`; got {} findings",
        jv001_null_lines.len()
    );
}

// ============================================================================
// Bug 8 (AGG14-16): Java explain populates callees and non-zero caller.line
// ============================================================================

#[test]
fn java_explain_callees_and_caller_line() {
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
    assert_eq!(rc, 0, "tldr explain exited non-zero");
    let v = parse_json(&out);
    let callees = v["callees"].as_array().cloned().unwrap_or_default();
    assert!(
        callees.len() >= 1,
        "java explain callees ({}) should be >= 1 (function calls findByLastNameStartingWith etc.)",
        callees.len()
    );
    let callers = v["callers"].as_array().cloned().unwrap_or_default();
    assert!(
        callers.len() >= 1,
        "java explain callers ({}) should be >= 1 (called by processFindForm)",
        callers.len()
    );
    for c in &callers {
        let line = c["line"].as_u64().unwrap_or(0);
        assert!(
            line > 0,
            "java explain caller.line ({}) should be > 0 — callsite line of '{:?}'",
            line,
            c["name"].as_str().unwrap_or("?")
        );
    }
}

// ============================================================================
// Bug 9 (AGG14-17): Java interface flattens class methods to top-level
// functions[] for class-only languages.
// ============================================================================

#[test]
fn java_interface_flattens_methods_to_functions() {
    let path = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["interface", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr interface exited non-zero");
    let v = parse_json(&out);
    let classes = v["classes"].as_array().cloned().unwrap_or_default();
    assert!(
        !classes.is_empty(),
        "java interface should find OwnerController class"
    );
    let functions = v["functions"].as_array().cloned().unwrap_or_default();
    assert!(
        functions.len() >= 5,
        "java interface should flatten class methods to functions[] (got {})",
        functions.len()
    );
}

// ============================================================================
// Non-regression checks: P12 / P13 fixes still hold
// ============================================================================

#[test]
fn nonreg_go_specs_still_works() {
    let path = "/tmp/repos/go-httprouter";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let total = v["summary"]["total_specs"].as_u64().unwrap_or(0);
    assert!(total >= 1, "go specs total ({}) should remain >= 1", total);
}

#[test]
fn nonreg_php_specs_still_works() {
    let path = "/tmp/repos/php-symfony-string";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", path, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let total = v["summary"]["total_specs"].as_u64().unwrap_or(0);
    assert!(total >= 1, "php specs total ({}) should remain >= 1", total);
}

#[test]
fn nonreg_python_interface_still_works() {
    let path = "/tmp/repos/flask/src/flask/app.py";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["interface", path, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let classes = v["classes"].as_array().map(|a| a.len()).unwrap_or(0);
    let functions = v["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        classes >= 1,
        "python interface flask app.py should still report >= 1 class (got {})",
        classes
    );
    // python interface puts module-level functions in functions[] but
    // class methods inside class entries — flattening is JV/Kotlin only.
    // Verify we didn't accidentally flatten Python class methods too.
    assert!(
        functions <= 10,
        "python interface should not have flattened class methods (got {} functions)",
        functions
    );
}

#[test]
fn nonreg_lua_smells_kind_populated() {
    let path = "/tmp/repos/lua-lsp/script";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["smells", path, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let smells = v["smells"].as_array().cloned().unwrap_or_default();
    assert!(smells.len() >= 1, "lua smells should yield >= 1 finding");
    // Each smell entry must have a non-null `smell_type` (the
    // categorical kind discriminator emitted by the lua categorizer).
    let null_kinds = smells
        .iter()
        .filter(|s| s["smell_type"].is_null() || s["smell_type"].as_str() == Some(""))
        .count();
    assert_eq!(
        null_kinds,
        0,
        "lua smells should never have null smell_type (got {} null entries of {} total)",
        null_kinds,
        smells.len()
    );
}

#[test]
fn nonreg_ts_interface_free_functions_still_flat() {
    let path = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["interface", path, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    // emitter.ts has top-level functions; the ts interface walker
    // should still expose them as flat entries.
    let functions = v["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        functions >= 1,
        "ts interface emitter.ts top-level functions ({}) should be >= 1",
        functions
    );
}
