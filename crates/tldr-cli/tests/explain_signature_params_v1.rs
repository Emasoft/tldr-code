//! explain-signature-params-v1 (v0.4.2 M-001 / Phase-22 iter-1)
//!
//! Pre-fix: `tldr explain <file> <symbol>` emits `signature.params: []`
//! for 15 languages even when `tldr extract <file>` correctly returns
//! the function's parameter list. Root cause: the explain pipeline's
//! `extract_signature` (in `crates/tldr-cli/src/commands/remaining/explain.rs`)
//! relies on the generic tree-sitter `child_by_field_name("parameters")`
//! plus python-style child-kind inspection (`identifier`, `typed_parameter`,
//! `default_parameter`). Most non-python grammars name their param
//! container or children differently, so the generic walk silently
//! returns zero params even when the function's params are unambiguously
//! present in the AST and successfully extracted by the `tldr extract`
//! pipeline (which uses a language-specific dispatcher in
//! `tldr-core/src/ast/extract.rs`).
//!
//! Affected langs (per Phase-22 iter-1 cluster M-001): c, csharp, java,
//! javascript, kotlin, lua, luau, ocaml, php, python (only for non-trivial
//! signatures), ruby, rust, scala, swift, typescript.
//!
//! Fix — additive + language-agnostic:
//!   - Expose the existing per-language param extractors in
//!     `tldr-core/src/ast/extract.rs` via a new public dispatcher
//!     `extract_function_params(func_node, source, language) -> Vec<String>`.
//!   - In `extract_signature` (explain.rs), when the existing generic
//!     path yields zero params, fall back to the canonical core
//!     dispatcher. Each `String` becomes a `ParamInfo::new(s)`.
//!   - Python path continues to use the rich generic walker first, so
//!     existing `signature.params[].type` / `default` fields are not
//!     regressed.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

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

fn signature_param_names(v: &serde_json::Value) -> Vec<String> {
    v["signature"]["params"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            // Params are emitted as objects {name, type?, default?}; accept
            // bare strings too for forward-compat.
            p["name"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| p.as_str().map(|s| s.to_string()))
        })
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// TEST 1 — RUST: ripgrep glob.rs `parse` method.
//   extract returns params=["&mut self"]; pre-fix explain returns [].
// ============================================================================
#[test]
fn explain_rust_glob_parse_has_params() {
    let target = "/tmp/repos/ripgrep/crates/globset/src/glob.rs";
    if !Path::new(target).exists() {
        eprintln!("[skip] explain_rust_glob_parse_has_params: {} absent", target);
        return;
    }

    let (rc, out) = run_tldr(&["explain", target, "parse"]);
    assert_eq!(rc, 0, "explain must succeed on glob.rs::parse; rc={}", rc);

    let v = parse_json(&out);
    let names = signature_param_names(&v);
    assert!(
        !names.is_empty(),
        "rust explain glob.rs::parse must populate signature.params; got [] \
         (pre-fix: M-001 cluster)"
    );
    // ripgrep's Parser::parse takes `&mut self` only — that single self
    // parameter MUST round-trip through explain.
    let any_self = names.iter().any(|n| n.contains("self"));
    assert!(
        any_self,
        "rust explain glob.rs::parse must include the `self` receiver in \
         signature.params; got {:?}",
        names
    );
}

// ============================================================================
// TEST 2 — JAVA: spring-petclinic OwnerController.processFindForm.
//   extract returns params=["page","owner","result","model"]; pre-fix
//   explain returns [].
// ============================================================================
#[test]
fn explain_java_process_find_form_has_params() {
    let target =
        "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(target).exists() {
        eprintln!(
            "[skip] explain_java_process_find_form_has_params: {} absent",
            target
        );
        return;
    }

    let (rc, out) = run_tldr(&["explain", target, "processFindForm"]);
    assert_eq!(
        rc, 0,
        "explain must succeed on OwnerController.java::processFindForm; rc={}",
        rc
    );

    let v = parse_json(&out);
    let names = signature_param_names(&v);
    assert!(
        names.len() >= 4,
        "java explain processFindForm must report all 4 params (page, owner, \
         result, model); got {:?}",
        names
    );
    for expected in &["page", "owner", "result", "model"] {
        assert!(
            names.iter().any(|n| n == expected),
            "java explain processFindForm params must include `{}`; got {:?}",
            expected,
            names
        );
    }
}

// ============================================================================
// TEST 3 — JAVASCRIPT/TYPESCRIPT: ts-dom-gen file (corpus has TS code).
//   Use express's index.js if ts-dom-gen unavailable.
// ============================================================================
#[test]
fn explain_javascript_has_params() {
    // Pick the first available JS file with a known parameterised function.
    // `handle(req, res, callback)` in express/lib/application.js is verified
    // to return params via `tldr extract` but [] via `tldr explain` pre-fix.
    let candidates: &[(&str, &str)] = &[
        ("/tmp/repos/express/lib/application.js", "handle"),
        ("/tmp/repos/_express_partial/lib/application.js", "handle"),
    ];
    let mut chosen: Option<(&str, &str)> = None;
    for (path, fn_name) in candidates {
        if Path::new(path).exists() {
            chosen = Some((path, fn_name));
            break;
        }
    }
    let (target, fn_name) = match chosen {
        Some(c) => c,
        None => {
            eprintln!("[skip] explain_javascript_has_params: no JS corpus present");
            return;
        }
    };

    // Sanity check extract first — only proceed if extract DOES have params
    // for this function (otherwise the test is checking the wrong thing).
    let (rc_ex, ex) = run_tldr(&["extract", target]);
    assert_eq!(rc_ex, 0);
    let exv = parse_json(&ex);
    let extract_has_params = exv["functions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .any(|f| {
            f["name"].as_str() == Some(fn_name)
                && f["params"]
                    .as_array()
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
        });
    if !extract_has_params {
        eprintln!(
            "[skip] explain_javascript_has_params: extract({}) has no params \
             for {} — test premise not met",
            target, fn_name
        );
        return;
    }

    let (rc, out) = run_tldr(&["explain", target, fn_name]);
    assert_eq!(
        rc, 0,
        "explain must succeed on {}::{}; rc={}",
        target, fn_name, rc
    );
    let v = parse_json(&out);
    let names = signature_param_names(&v);
    assert!(
        !names.is_empty(),
        "JS/TS explain {}::{} must populate signature.params; got [] \
         (pre-fix: M-001 cluster) — extract DID populate params, so explain \
         must propagate them",
        target,
        fn_name
    );
}

// ============================================================================
// TEST 4 — KOTLIN: kotlinx-datetime Instant.kt::plus (line 66).
//   Cross-verified: extract reports `period`, `timeZone`; pre-fix explain
//   returned []. (This overlaps with kotlin_extract_params_v1 but is here
//   to guard the cluster-wide propagation contract.)
// ============================================================================
#[test]
fn explain_kotlin_plus_has_params() {
    let target = "/tmp/repos/kotlin-datetime/core/common/src/Instant.kt";
    if !Path::new(target).exists() {
        eprintln!("[skip] explain_kotlin_plus_has_params: {} absent", target);
        return;
    }

    let (rc, out) = run_tldr(&["explain", target, "plus"]);
    assert_eq!(rc, 0, "explain must succeed on Instant.kt::plus; rc={}", rc);
    let v = parse_json(&out);
    let names = signature_param_names(&v);
    assert!(
        !names.is_empty(),
        "kotlin explain Instant.kt::plus must populate signature.params; \
         got [] (M-001 cluster regression)"
    );
}

// ============================================================================
// TEST 5 — PYTHON NON-REGRESSION: flask helpers.py::url_for.
//   Python is the lang where the generic path already worked. After the
//   fix this MUST continue to emit the richer {name, type} entries (the
//   fix is additive: the python path is kept).
// ============================================================================
#[test]
fn explain_python_url_for_keeps_rich_params() {
    let target = "/tmp/repos/flask/src/flask/helpers.py";
    if !Path::new(target).exists() {
        eprintln!(
            "[skip] explain_python_url_for_keeps_rich_params: {} absent",
            target
        );
        return;
    }

    let (rc, out) = run_tldr(&["explain", target, "url_for"]);
    assert_eq!(rc, 0, "explain must succeed on helpers.py::url_for; rc={}", rc);
    let v = parse_json(&out);
    let params = v["signature"]["params"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        params.len() >= 4,
        "python url_for must keep all params after fix; got {} entries",
        params.len()
    );
    let names = signature_param_names(&v);
    assert!(
        names.iter().any(|n| n == "endpoint"),
        "python url_for must include `endpoint`; got {:?}",
        names
    );

    // Non-regression: at least one param entry retains its `type` (the
    // python generic walker emits typed_parameter `type` fields).
    let any_typed = params.iter().any(|p| p["type"].is_string());
    assert!(
        any_typed,
        "python url_for signature.params must keep type annotations \
         (non-regression); got {:?}",
        params
    );
}

// ============================================================================
// TEST 6 — GO: httprouter has parameterised functions; cross-cluster check
//   that the fix lifts the params:[] reading on a 6th lang.
// ============================================================================
#[test]
fn explain_go_has_params() {
    let target = "/tmp/repos/go-httprouter/router.go";
    if !Path::new(target).exists() {
        eprintln!("[skip] explain_go_has_params: {} absent", target);
        return;
    }

    // Sanity: extract must have params for SOMETHING in this file.
    let (rc_ex, ex) = run_tldr(&["extract", target]);
    assert_eq!(rc_ex, 0);
    let exv = parse_json(&ex);
    let mut fn_with_params: Option<String> = None;
    // Search top-level functions AND class/struct methods.
    for f in exv["functions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
    {
        if f["params"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            if let Some(n) = f["name"].as_str() {
                fn_with_params = Some(n.to_string());
                break;
            }
        }
    }
    if fn_with_params.is_none() {
        for c in exv["classes"].as_array().cloned().unwrap_or_default().iter() {
            for m in c["methods"].as_array().cloned().unwrap_or_default().iter() {
                if m["params"]
                    .as_array()
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
                {
                    if let Some(n) = m["name"].as_str() {
                        fn_with_params = Some(n.to_string());
                        break;
                    }
                }
            }
            if fn_with_params.is_some() {
                break;
            }
        }
    }
    let target_fn = match fn_with_params {
        Some(n) => n,
        None => {
            eprintln!(
                "[skip] explain_go_has_params: no parameterised function found by extract"
            );
            return;
        }
    };

    let (rc, out) = run_tldr(&["explain", target, &target_fn]);
    assert_eq!(rc, 0, "explain must succeed on {}::{}", target, target_fn);
    let v = parse_json(&out);
    let names = signature_param_names(&v);
    assert!(
        !names.is_empty(),
        "go explain {}::{} must populate signature.params after M-001 fix; \
         extract already returned non-empty params for this function",
        target,
        target_fn
    );
}
