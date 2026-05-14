//! verify-aggregator-v1 (v0.4.2 M-011) — regression tests for the
//! `tldr verify` aggregator under-running its sub-analyses across
//! non-Python languages.
//!
//! BUG: Phase-22 iter-1 cluster M-011 found that `tldr verify <dir>`
//! reports `files_analyzed: 0` and `sub_results.contracts.items_found:
//! 0` for ~13 languages (c, cpp, kotlin, ocaml, scala, swift, ...),
//! while invoking `tldr contracts <file> <fn>` directly on those same
//! files returns real pre/post/invariant data. Two root causes:
//!
//!   1. `collect_source_files` had a hardcoded `extension` mapping
//!      covering only py/ts/js/rs/go/java; every other Language variant
//!      fell through to `"py"`, so a `c-sds/` walk asked for `*.py`.
//!
//!   2. `extract_function_names` was Python-regex only (`def NAME(`),
//!      so even when files were enumerated, zero function names came
//!      back for any non-Python language — so `run_contracts` was never
//!      invoked once.
//!
//! After the fix, `verify` must:
//!   - populate `files_analyzed > 0` whenever the target directory
//!     contains source files for the (auto-detected or `--lang`)
//!     language;
//!   - populate `sub_results.contracts.items_found > 0` (or at minimum
//!     non-empty `data`) when at least one of those files has a
//!     function the `run_contracts` sub-runner can analyse.
//!
//! Tests are gated on `/tmp/repos/<name>` so the suite is a no-op when
//! the audit fixtures aren't seeded.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn run_tldr_json(args: &[&str]) -> Option<Value> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.args(args).arg("--format").arg("json");
    let output = cmd.output().expect("failed to execute tldr");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        eprintln!(
            "tldr {:?} failed: stdout={} stderr={}",
            args, stdout, stderr
        );
        return None;
    }
    serde_json::from_str(&stdout).ok()
}

fn files_analyzed(v: &Value) -> u64 {
    v.get("files_analyzed")
        .and_then(|n| n.as_u64())
        .unwrap_or(0)
}

fn contracts_items(v: &Value) -> u64 {
    v.get("sub_results")
        .and_then(|s| s.get("contracts"))
        .and_then(|c| c.get("items_found"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0)
}

fn contracts_data_len(v: &Value) -> usize {
    v.get("sub_results")
        .and_then(|s| s.get("contracts"))
        .and_then(|c| c.get("data"))
        .and_then(|d| d.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

// =============================================================================
// Per-language: files_analyzed must be > 0 when sources exist
// =============================================================================

/// C: c-sds is a 2-file C library with ~40 functions in sds.c.
#[test]
fn test_verify_c_files_analyzed() {
    let repo = "/tmp/repos/c-sds";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "C verify must enumerate source files (got 0 for {})",
        repo
    );
    // Contracts sub-runner must actually be invoked on at least one
    // function — items_found counts pre+post+invariants summed across
    // all functions, so a healthy C corpus should give a non-zero
    // count. Allow `data` non-empty as the looser sufficient
    // condition (a function was analysed even if it had zero pre/post).
    assert!(
        contracts_items(&v) > 0 || contracts_data_len(&v) > 0,
        "C verify must invoke contracts sub-runner on >=1 function \
         (items_found={}, data.len={}) — output: {}",
        contracts_items(&v),
        contracts_data_len(&v),
        serde_json::to_string(&v).unwrap_or_default()
    );
}

/// Kotlin: kotlin-datetime is a multi-module kotlin library.
#[test]
fn test_verify_kotlin_files_analyzed() {
    let repo = "/tmp/repos/kotlin-datetime";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "Kotlin verify must enumerate .kt files (got 0 for {})",
        repo
    );
    assert!(
        contracts_items(&v) > 0 || contracts_data_len(&v) > 0,
        "Kotlin verify must invoke contracts sub-runner on >=1 \
         function (items_found={}, data.len={})",
        contracts_items(&v),
        contracts_data_len(&v),
    );
}

/// Scala: scala-cats-effect — large scala corpus.
#[test]
fn test_verify_scala_files_analyzed() {
    let repo = "/tmp/repos/scala-cats-effect";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "Scala verify must enumerate .scala files (got 0 for {})",
        repo
    );
    assert!(
        contracts_items(&v) > 0 || contracts_data_len(&v) > 0,
        "Scala verify must invoke contracts sub-runner on >=1 \
         function (items_found={}, data.len={})",
        contracts_items(&v),
        contracts_data_len(&v),
    );
}

/// C++: cpp-tinyxml2 — tinyxml2.cpp + tinyxml2.h.
#[test]
fn test_verify_cpp_files_analyzed() {
    let repo = "/tmp/repos/cpp-tinyxml2";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "C++ verify must enumerate .cpp/.h files (got 0 for {})",
        repo
    );
    assert!(
        contracts_items(&v) > 0 || contracts_data_len(&v) > 0,
        "C++ verify must invoke contracts sub-runner on >=1 \
         function (items_found={}, data.len={})",
        contracts_items(&v),
        contracts_data_len(&v),
    );
}

/// Swift: swift-collections.
#[test]
fn test_verify_swift_files_analyzed() {
    let repo = "/tmp/repos/swift-collections";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "Swift verify must enumerate .swift files (got 0 for {})",
        repo
    );
}

/// OCaml: ocaml-dune.
#[test]
fn test_verify_ocaml_files_analyzed() {
    let repo = "/tmp/repos/ocaml-dune";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "OCaml verify must enumerate .ml files (got 0 for {})",
        repo
    );
}

// =============================================================================
// Schema invariants preserved across the fix
// =============================================================================

/// The fix must NOT resurrect the unwired `bounds`/`dead_stores`/
/// `invariants` keys (guarded by `test_verify_drops_unwired_keys` in
/// verify.rs). Re-assert from the CLI surface.
#[test]
fn test_verify_schema_no_unwired_keys_cli() {
    let repo = "/tmp/repos/c-sds";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo]).expect("verify produced JSON");
    let sub = v
        .get("sub_results")
        .and_then(|s| s.as_object())
        .expect("sub_results must be object");
    for forbidden in ["bounds", "dead_stores", "invariants"] {
        assert!(
            !sub.contains_key(forbidden),
            "verify must not emit `{}` key (schema-completeness-v1)",
            forbidden
        );
    }
    // The two wired sub-analyses must always be present.
    assert!(sub.contains_key("contracts"), "missing `contracts` sub_result");
    assert!(sub.contains_key("specs"), "missing `specs` sub_result");
}

/// Explicit `--lang` override must work for any supported language
/// (regression: hardcoded ext-map silently downgraded unknown langs to
/// `.py`).
#[test]
fn test_verify_explicit_lang_kotlin() {
    let repo = "/tmp/repos/kotlin-datetime";
    if !Path::new(repo).exists() {
        return;
    }
    let v = run_tldr_json(&["verify", repo, "--lang", "kotlin"])
        .expect("verify --lang kotlin produced JSON");
    assert!(
        files_analyzed(&v) > 0,
        "explicit `--lang kotlin` must still enumerate .kt files"
    );
}
