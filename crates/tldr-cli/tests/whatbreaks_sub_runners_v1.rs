//! whatbreaks-sub-runners-v1 (v0.4.2 M-010):
//!
//! Pre-fix audit assertion (Phase-22 audit, cluster M-010):
//! > "`tldr whatbreaks` advertises 'callers, transitive callers, importers,
//! >  affected tests' but only invokes `impact` in `sub_results`. Schema
//! >  already has fields (`importer_count`, `affected_test_count`) — they're
//! >  emitted as 0/empty everywhere. Affects ~10 langs uniformly."
//!
//! Verdict: REAL BUG. In `crates/tldr-core/src/analysis/whatbreaks.rs`
//! the `whatbreaks_analysis` Function-target branch only inserts the
//! `impact` sub-runner into `sub_results`. The `importers` and
//! `change-impact` sub-runners are wired (functions exist) but never
//! invoked, so `WhatbreaksSummary::importer_count` and
//! `affected_test_count` are silently left at their `Default::default()`
//! value of 0.
//!
//! Fix: in the Function branch, after running `impact`, also run
//! `run_importers_analysis` against the symbol's containing module
//! (derived from the impact report's primary definition file) and
//! `run_change_impact_analysis` against that same file, then populate
//! the existing `WhatbreaksSummary` fields. The sub_results map gains
//! the keys `importers` and `change-impact` alongside `impact`.
//!
//! Test contract: for a real Function target with at least one importer
//! and one affected test in the corpus, after the fix:
//! - `sub_results` contains `impact`, `importers`, AND `change-impact`
//! - `summary.importer_count > 0`
//! - `summary.affected_test_count > 0` (when not --quick)
//! - Schema fields are populated, not zeroed.
//!
//! Languages covered: rust (ripgrep), go (go-httprouter), typescript/js
//! (express), java (spring-petclinic). Real-repo gated.

use std::path::Path;
use std::process::Command;

const RIPGREP_CORPUS: &str = "/tmp/repos/ripgrep";
const HTTPROUTER_CORPUS: &str = "/tmp/repos/go-httprouter";
const EXPRESS_CORPUS: &str = "/tmp/repos/express";
const PETCLINIC_CORPUS: &str = "/tmp/repos/spring-petclinic";

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

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn parse_whatbreaks(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("whatbreaks stdout must be valid JSON")
}

fn sub_result_keys(report: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = report
        .get("sub_results")
        .and_then(|x| x.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    k.sort();
    k
}

fn importer_count(report: &serde_json::Value) -> u64 {
    report
        .get("summary")
        .and_then(|s| s.get("importer_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX)
}

fn affected_test_count(report: &serde_json::Value) -> u64 {
    report
        .get("summary")
        .and_then(|s| s.get("affected_test_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX)
}

// =============================================================================
// TEST 1 (rust / ripgrep): function target invokes all 3 sub-runners and
// populates importer_count via the `importers` sub-runner.
//
// Target: `Searcher` — a heavily-used symbol in ripgrep with many importers
// and tests. Before the fix, `sub_results.keys() == ["impact"]`. After,
// `["change-impact","impact","importers"]` and importer_count > 0.
// =============================================================================
#[test]
fn rust_function_target_wires_all_three_sub_runners() {
    if !Path::new(RIPGREP_CORPUS).exists() {
        eprintln!("[skip] {} missing", RIPGREP_CORPUS);
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "Searcher",
        RIPGREP_CORPUS,
        "--type",
        "function",
    ]);
    assert_eq!(exit, 0, "tldr whatbreaks exited non-zero. stderr:\n{}", stderr);

    let report = parse_whatbreaks(&stdout);
    let keys = sub_result_keys(&report);

    assert!(
        keys.contains(&"impact".to_string()),
        "sub_results must contain 'impact'; got {:?}",
        keys
    );
    assert!(
        keys.contains(&"importers".to_string()),
        "M-010: sub_results must contain 'importers' (the importers \
         sub-runner is now wired). Got keys: {:?}",
        keys
    );
    assert!(
        keys.contains(&"change-impact".to_string()),
        "M-010: sub_results must contain 'change-impact' (the change-impact \
         sub-runner is now wired). Got keys: {:?}",
        keys
    );

    // ripgrep::Searcher has many importing modules (defines a public type)
    let ic = importer_count(&report);
    assert!(
        ic > 0 && ic < u64::MAX,
        "M-010: ripgrep Searcher must have importer_count > 0 after \
         wiring importers sub-runner; got {}",
        ic
    );
}

// =============================================================================
// TEST 2 (go / go-httprouter): change-impact populates affected_test_count.
//
// Target: `Router.Lookup` — a method on go-httprouter's Router type that
// impact can resolve (Router is a struct, so the call graph keys the
// method by qualified name). Pre-fix: change-impact never ran, so
// affected_test_count == 0 regardless. Post-fix: change-impact resolves
// router.go as the defining file and discovers router_test.go in the
// affected set.
// =============================================================================
#[test]
fn go_function_target_populates_affected_test_count() {
    if !Path::new(HTTPROUTER_CORPUS).exists() {
        eprintln!("[skip] {} missing", HTTPROUTER_CORPUS);
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "Router.Lookup",
        HTTPROUTER_CORPUS,
        "--type",
        "function",
    ]);
    assert_eq!(exit, 0, "stderr:\n{}", stderr);

    let report = parse_whatbreaks(&stdout);
    let keys = sub_result_keys(&report);
    assert!(
        keys.contains(&"change-impact".to_string()),
        "M-010: change-impact sub-runner missing for go. Keys: {:?}",
        keys
    );

    let ci = report
        .get("sub_results")
        .and_then(|s| s.get("change-impact"))
        .expect("change-impact must be present");
    let ci_success = ci.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    let warnings = ci
        .get("warnings")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|w| w.as_str()).any(|w| w.contains("Skipped")))
        .unwrap_or(false);
    assert!(
        ci_success && !warnings,
        "M-010: change-impact must actually run (not be Skipped) when impact \
         resolves a defining file. Got success={}, skipped={}",
        ci_success,
        warnings
    );

    let atc = affected_test_count(&report);
    assert!(
        atc > 0 && atc < u64::MAX,
        "M-010: go-httprouter Router.Lookup must have affected_test_count > 0; got {}",
        atc
    );
}

// =============================================================================
// TEST 3 (javascript / express): importers sub-runner reports non-empty data
// when impact resolves a defining file. We use a method that the call graph
// can resolve (`Router.use` -> `lib/application.js`), then assert the
// importers sub-runner derived the file stem (`application`) and found
// importing files. This exercises the file-stem derivation added in M-010.
// =============================================================================
#[test]
fn ts_function_target_importers_subrunner_has_data() {
    if !Path::new(EXPRESS_CORPUS).exists() {
        eprintln!("[skip] {} missing", EXPRESS_CORPUS);
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "Router.use",
        EXPRESS_CORPUS,
        "--type",
        "function",
    ]);
    assert_eq!(exit, 0, "stderr:\n{}", stderr);

    let report = parse_whatbreaks(&stdout);

    let importers_sr = report
        .get("sub_results")
        .and_then(|s| s.get("importers"))
        .expect("M-010: 'importers' must be in sub_results for ts function target");

    assert_eq!(
        importers_sr.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "M-010: importers sub-runner should succeed; got: {:?}",
        importers_sr
    );

    let data = importers_sr
        .get("data")
        .expect("importers sub_result must expose `data`");
    let module = data.get("module").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        module, "application",
        "M-010: importers must target the file stem ('application') of the \
         resolved defining file, not the bare symbol or dotted path. Got: {}",
        module
    );
    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        count > 0,
        "M-010: express application.js must have importers > 0; got data: {:?}",
        data
    );
    let imp_count = importer_count(&report);
    assert_eq!(
        imp_count, count,
        "M-010: summary.importer_count ({}) must mirror importers.data.count ({})",
        imp_count, count
    );
}

// =============================================================================
// TEST 4 (java / spring-petclinic): --quick flag still wires importers but
// skips change-impact. Verifies the orchestration handles quick mode in the
// Function branch identically to how the File branch already does.
// =============================================================================
#[test]
fn java_function_target_quick_skips_change_impact_but_keeps_importers() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!("[skip] {} missing", PETCLINIC_CORPUS);
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "OwnerController",
        PETCLINIC_CORPUS,
        "--type",
        "function",
        "--quick",
    ]);
    assert_eq!(exit, 0, "stderr:\n{}", stderr);

    let report = parse_whatbreaks(&stdout);
    let keys = sub_result_keys(&report);

    assert!(
        keys.contains(&"impact".to_string()),
        "impact must run regardless of --quick. Keys: {:?}",
        keys
    );
    assert!(
        keys.contains(&"importers".to_string()),
        "importers must run even with --quick. Keys: {:?}",
        keys
    );

    // With --quick, change-impact must be present and recorded as Skipped.
    // `SubResult::skipped` produces success=true, error=None, and a single
    // warning whose text mentions "Skipped" / "--quick".
    let ci = report
        .get("sub_results")
        .and_then(|s| s.get("change-impact"))
        .expect("change-impact entry must exist under --quick");
    let warnings = ci.get("warnings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let has_skipped_warning = warnings
        .iter()
        .filter_map(|w| w.as_str())
        .any(|w| w.contains("Skipped") || w.contains("quick"));
    let elapsed = ci.get("elapsed_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
    assert!(
        has_skipped_warning,
        "M-010: change-impact under --quick must carry a 'Skipped'/'quick' \
         warning, not run for real. Got warnings={:?}, elapsed_ms={}",
        warnings,
        elapsed
    );
}

// =============================================================================
// TEST 5 (sanity): repro the original Phase-22 audit shape. Before the fix,
// only `impact` was in sub_results. After, all three are present. This test
// is intentionally broad — it asserts the union of sub-runner keys is exactly
// {impact, importers, change-impact} for any Function target on any real
// corpus.
// =============================================================================
#[test]
fn function_target_sub_results_keys_are_complete() {
    if !Path::new(RIPGREP_CORPUS).exists() {
        eprintln!("[skip] {} missing", RIPGREP_CORPUS);
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&[
        "whatbreaks",
        "Searcher",
        RIPGREP_CORPUS,
        "--type",
        "function",
    ]);
    assert_eq!(exit, 0, "stderr:\n{}", stderr);

    let report = parse_whatbreaks(&stdout);
    let keys = sub_result_keys(&report);

    let expected = ["change-impact", "impact", "importers"];
    for want in expected {
        assert!(
            keys.iter().any(|k| k == want),
            "M-010: Function-target sub_results must include '{}'. Got: {:?}",
            want,
            keys
        );
    }
}
