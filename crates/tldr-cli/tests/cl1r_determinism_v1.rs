//! cl1r-determinism-v1 (v0.5.0 CL-1R) — residual map-key + deps Vec-order
//! nondeterminism regression tests.
//!
//! The Tier-0 CL-1 fix sorted per-target caller arrays, but two residual
//! nondeterminism sources remained:
//!
//!   1. `ImpactReport.targets` is a `HashMap<String, CallerTree>` in
//!      `crates/tldr-core/src/types.rs`. serde serializes a `HashMap`
//!      in iteration order, which is randomized per-process — so the
//!      *map-key order* of the `targets` object in `impact` JSON differs
//!      run-to-run. The original `cl1_determinism_v1` test side-stepped
//!      this by comparing per-target caller orderings keyed by target name
//!      (see its `impact_caller_orders`). CL-1R fixes the root cause so the
//!      ENTIRE JSON document — including map-key order — is byte-stable.
//!
//!   2. `crates/tldr-core/src/analysis/deps.rs` builds the serialized
//!      `internal_dependencies` adjacency Vec values from collections whose
//!      order is HashMap/HashSet-derived: `collapse_to_packages` converts a
//!      `HashSet<PathBuf>` to a `Vec` (`--collapse-packages`), and the Go
//!      same-package augmentation pushes edges while iterating a
//!      `HashMap<String, Vec<PathBuf>>` of package groups. Without a final
//!      stable sort of each adjacency Vec, the serialized dependency lists
//!      reshuffle run-to-run.
//!
//! These tests run `impact` (a genuine multi-target case on Flask: `run`
//! resolves to both `flask/app.py:run` and `tests/test_config.py:Flask.run`)
//! and `deps` (plain, and `--collapse-packages --include-external`, plus a
//! Go corpus that exercises same-package edges) twice each and assert
//! FULL byte-identical JSON across runs — map-key order included.
//!
//! They are skipped (with a loud eprintln) only if the corpus is not
//! present, so they never silently pass on a machine without corpora.

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn flask_corpus() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/python-flask")
}

fn go_corpus() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/go-httprouter")
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr <args...>` and parse stdout as JSON, stripping wall-clock
/// timing fields (inherently variable, never claimed byte-stable) so the
/// comparison captures CONTENT determinism only.
fn run_json(args: &[&str]) -> Value {
    let output = tldr_cmd()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("invoke tldr {args:?}: {e}"));
    assert!(
        output.status.success(),
        "tldr {args:?} failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr {args:?} stdout not JSON: {e}\n{stdout}"));
    strip_timing(&mut v);
    v
}

/// Recursively remove timing keys anywhere in the JSON tree.
fn strip_timing(v: &mut Value) {
    const TIMING_KEYS: &[&str] = &[
        "search_time_ms",
        "detection_time_ms",
        "scan_time_ms",
        "analysis_time_ms",
        "elapsed_ms",
        "duration_ms",
        "time_ms",
    ];
    match v {
        Value::Object(map) => {
            for k in TIMING_KEYS {
                map.remove(*k);
            }
            for (_, child) in map.iter_mut() {
                strip_timing(child);
            }
        }
        Value::Array(arr) => {
            for child in arr.iter_mut() {
                strip_timing(child);
            }
        }
        _ => {}
    }
}

/// Serialize a `serde_json::Value` to a string that PRESERVES object
/// key-insertion order.
///
/// `serde_json::Value::Object` is a `Map` whose iteration order, by
/// default, is the insertion order recorded when the JSON text was
/// PARSED (serde_json's default `BTreeMap`-free `preserve_order`-off
/// build still records parse order). Re-serializing therefore reproduces
/// the producer's emitted map-key order. This is exactly what we want:
/// it lets a higher-level comparison detect a difference in the
/// PRODUCER's `targets` / `internal_dependencies` map-key order across
/// runs, which is the nondeterminism CL-1R fixes.
fn to_canonical_string(v: &Value) -> String {
    serde_json::to_string(v).unwrap()
}

fn flask_or_skip(name: &str) -> Option<PathBuf> {
    let c = flask_corpus();
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP {name}: corpus {} not present; \
             determinism test requires /tmp/tldr_corpora/python-flask",
            c.display()
        );
        return None;
    }
    Some(c)
}

fn go_or_skip(name: &str) -> Option<PathBuf> {
    let c = go_corpus();
    if !corpus_ready(&c) {
        eprintln!(
            "SKIP {name}: corpus {} not present; \
             determinism test requires /tmp/tldr_corpora/go-httprouter",
            c.display()
        );
        return None;
    }
    Some(c)
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Collect the `targets` object's map-key order as emitted by the producer.
fn impact_target_key_order(v: &Value) -> Vec<String> {
    v.get("targets")
        .and_then(|t| t.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Collect the `internal_dependencies` object's map-key order plus, for each
/// key, the adjacency Vec order — both as emitted by the producer.
fn deps_internal_shape(v: &Value) -> Vec<(String, Vec<String>)> {
    v.get("internal_dependencies")
        .and_then(|t| t.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, deps)| {
                    let list = deps
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .map(|d| d.as_str().unwrap_or_default().to_string())
                                .collect()
                        })
                        .unwrap_or_default();
                    (k.clone(), list)
                })
                .collect()
        })
        .unwrap_or_default()
}

// =============================================================================
// impact: FULL JSON byte-stable across runs (map-key order INCLUDED)
// =============================================================================

#[test]
fn impact_multi_target_full_json_is_byte_stable() {
    let Some(c) = flask_or_skip("impact_multi_target_full_json_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    // `run` resolves to MULTIPLE targets on Flask (flask/app.py:run and
    // tests/test_config.py:Flask.run), so the `targets` MAP must order its
    // keys deterministically — the exact CL-1R concern.
    let args = ["impact", "run", &cs, "--format", "json", "--quiet"];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    // Sanity: this MUST be a multi-target run or the map-key order test is
    // vacuous (a single-key object has only one possible order).
    let key_order = impact_target_key_order(&r1);
    assert!(
        key_order.len() >= 2,
        "expected >= 2 impact targets for `run` on Flask (multi-target needed \
         to exercise map-key order); got {}: {key_order:?}",
        key_order.len()
    );

    // The CL-1R fix: `ImpactReport.targets` is now a BTreeMap, so its map-key
    // order is deterministic AND sorted. Compare the emitted key order first
    // for a precise failure message, then the full JSON.
    assert_eq!(
        impact_target_key_order(&r1),
        impact_target_key_order(&r2),
        "impact `targets` MAP-KEY order differs run #1 vs #2 (HashMap order?)"
    );
    assert_eq!(
        impact_target_key_order(&r2),
        impact_target_key_order(&r3),
        "impact `targets` MAP-KEY order differs run #2 vs #3"
    );

    // Keys must be SORTED (BTreeMap guarantee), not merely stable.
    let mut sorted = key_order.clone();
    sorted.sort();
    assert_eq!(
        key_order, sorted,
        "impact `targets` keys are not emitted in sorted order"
    );

    let s1 = to_canonical_string(&r1);
    let s2 = to_canonical_string(&r2);
    let s3 = to_canonical_string(&r3);
    assert_eq!(s1, s2, "impact FULL JSON differs run #1 vs #2 (map-key order)");
    assert_eq!(s2, s3, "impact FULL JSON differs run #2 vs #3 (map-key order)");
}

// =============================================================================
// deps: FULL JSON byte-stable across runs (adjacency Vec order + map keys)
// =============================================================================

#[test]
fn deps_plain_full_json_is_byte_stable() {
    let Some(c) = flask_or_skip("deps_plain_full_json_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    let args = ["deps", &cs, "--format", "json", "--quiet"];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    let shape = deps_internal_shape(&r1);
    assert!(
        shape.len() >= 10,
        "expected a substantial internal-dependency graph on Flask; got {}",
        shape.len()
    );

    assert_eq!(
        deps_internal_shape(&r1),
        deps_internal_shape(&r2),
        "deps internal_dependencies shape differs run #1 vs #2"
    );

    let s1 = to_canonical_string(&r1);
    let s2 = to_canonical_string(&r2);
    let s3 = to_canonical_string(&r3);
    assert_eq!(s1, s2, "deps FULL JSON differs run #1 vs #2");
    assert_eq!(s2, s3, "deps FULL JSON differs run #2 vs #3");
}

#[test]
fn deps_collapse_external_full_json_is_byte_stable() {
    let Some(c) = flask_or_skip("deps_collapse_external_full_json_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    // `--collapse-packages` routes through `collapse_to_packages`, whose
    // `HashSet<PathBuf>` -> `Vec` conversion is the residual deps
    // nondeterminism source CL-1R fixes. `--include-external` adds the
    // external_dependencies map (BTreeMap already, but exercise it).
    let args = [
        "deps",
        &cs,
        "--collapse-packages",
        "--include-external",
        "--format",
        "json",
        "--quiet",
    ];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    let shape = deps_internal_shape(&r1);
    assert!(
        !shape.is_empty(),
        "expected a non-empty collapsed package graph on Flask"
    );
    // The collapsed adjacency Vec must be SORTED (root-cause fix), not just
    // stable. Verify at least one multi-dep package and that every Vec is
    // sorted.
    for (pkg, deps) in &shape {
        let mut sorted = deps.clone();
        sorted.sort();
        assert_eq!(
            deps, &sorted,
            "collapsed dependency Vec for `{pkg}` is not emitted in sorted order"
        );
    }

    assert_eq!(
        deps_internal_shape(&r1),
        deps_internal_shape(&r2),
        "deps --collapse-packages shape differs run #1 vs #2 (HashSet -> Vec order?)"
    );

    let s1 = to_canonical_string(&r1);
    let s2 = to_canonical_string(&r2);
    let s3 = to_canonical_string(&r3);
    assert_eq!(
        s1, s2,
        "deps --collapse-packages --include-external FULL JSON differs run #1 vs #2"
    );
    assert_eq!(s2, s3, "deps --collapse-packages FULL JSON differs run #2 vs #3");
}

#[test]
fn deps_go_same_package_full_json_is_byte_stable() {
    let Some(c) = go_or_skip("deps_go_same_package_full_json_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    // Go same-package implicit edges are pushed while iterating a
    // `HashMap<String, Vec<PathBuf>>` of package groups — the adjacency Vec
    // order in `internal_dependencies` is HashMap-derived without a final
    // sort. Exercise that path and assert each Vec is sorted + stable.
    let args = ["deps", &cs, "--format", "json", "--quiet"];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    let shape = deps_internal_shape(&r1);
    assert!(
        !shape.is_empty(),
        "expected a non-empty Go internal-dependency graph"
    );
    for (file, deps) in &shape {
        let mut sorted = deps.clone();
        sorted.sort();
        assert_eq!(
            deps, &sorted,
            "Go same-package dependency Vec for `{file}` is not emitted in sorted order"
        );
    }

    assert_eq!(
        deps_internal_shape(&r1),
        deps_internal_shape(&r2),
        "Go deps internal_dependencies shape differs run #1 vs #2 (package HashMap order?)"
    );

    let s1 = to_canonical_string(&r1);
    let s2 = to_canonical_string(&r2);
    let s3 = to_canonical_string(&r3);
    assert_eq!(s1, s2, "Go deps FULL JSON differs run #1 vs #2");
    assert_eq!(s2, s3, "Go deps FULL JSON differs run #2 vs #3");
}
