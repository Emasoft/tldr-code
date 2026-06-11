//! cl1-determinism-v1 (GH #74) — output nondeterminism regression tests.
//!
//! Many commands serialize collections whose order is derived from
//! HashMap/HashSet iteration order or from the *unsorted* `ignore`
//! crate directory walk. Without a final stable sort at each
//! serialization boundary, byte-for-byte output differs run-to-run.
//!
//! The most damaging variant is `references --limit N`: because the
//! reference list is truncated WITHOUT first being sorted, two runs
//! can return entirely DIFFERENT subsets of the same symbol's
//! references — silent data loss, not just cosmetic churn.
//!
//! These tests run affected commands multiple times against the real
//! `/tmp/tldr_corpora/python-flask` corpus and assert byte-identical
//! JSON across runs:
//!   - `references` (full, no limit): byte-stable across 3 runs.
//!   - `references --limit 5`: the SAME 5 (sorted) references each run.
//!   - `impact run`: caller tree byte-stable across 3 runs (reverse
//!     call graph is built from a HashMap → unordered without a sort).
//!
//! They are skipped (with a loud eprintln) only if the corpus is not
//! present, so they never silently pass on a machine without corpora.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The real corpus these determinism tests run against. A Flask checkout
/// has enough references to `run` to overflow a small `--limit` and to
/// produce a multi-caller `impact` tree.
fn corpus() -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora/python-flask")
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr <args...>` and parse stdout as JSON, stripping wall-clock
/// timing fields (which are inherently variable and never claimed to be
/// byte-stable) so the comparison captures CONTENT determinism only.
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

/// Project the `references[]` array down to a stable identity tuple list
/// (file, line, column) for subset comparison.
fn ref_keys(v: &Value) -> Vec<(String, u64, u64)> {
    v.get("references")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .map(|r| {
                    let file = r
                        .get("file")
                        .and_then(|f| f.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let line = r.get("line").and_then(|l| l.as_u64()).unwrap_or(0);
                    let col = r.get("column").and_then(|c| c.as_u64()).unwrap_or(0);
                    (file, line, col)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn corpus_or_skip(name: &str) -> Option<PathBuf> {
    let c = corpus();
    if !c.exists() {
        eprintln!(
            "SKIP {name}: corpus {} not present; \
             determinism test requires /tmp/tldr_corpora/python-flask",
            c.display()
        );
        return None;
    }
    Some(c)
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

// =============================================================================
// references: full output byte-stable across runs
// =============================================================================

#[test]
fn references_full_output_is_byte_stable() {
    let Some(c) = corpus_or_skip("references_full_output_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    let args = ["references", "run", &cs, "--format", "json", "--quiet"];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();

    assert_eq!(s1, s2, "references run #1 vs #2 differs (walk/HashMap order?)");
    assert_eq!(s2, s3, "references run #2 vs #3 differs");

    // Sanity: Flask references `run` many times — guarantees we are
    // exercising the order-sensitive path, not comparing empty arrays.
    let n = ref_keys(&r1).len();
    assert!(
        n >= 10,
        "expected many references to `run` in Flask corpus; got {n}"
    );
}

// =============================================================================
// references --limit: SAME (sorted) subset each run — the data-loss bug
// =============================================================================

#[test]
fn references_truncated_subset_is_stable() {
    let Some(c) = corpus_or_skip("references_truncated_subset_is_stable") else {
        return;
    };
    let cs = path_str(&c);
    let limit = "5";
    let args = [
        "references", "run", &cs, "--limit", limit, "--format", "json", "--quiet",
    ];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    let k1 = ref_keys(&r1);
    let k2 = ref_keys(&r2);
    let k3 = ref_keys(&r3);

    // The cap must actually bite (Flask has > 5 refs to `run`), otherwise
    // this test would be vacuous.
    assert_eq!(k1.len(), 5, "expected exactly 5 references under --limit 5; got {}", k1.len());

    // The DAMAGING bug: truncation before sorting yields different subsets.
    assert_eq!(k1, k2, "references --limit returned a DIFFERENT subset on run #2 (silent data loss)");
    assert_eq!(k2, k3, "references --limit returned a DIFFERENT subset on run #3 (silent data loss)");

    // And full byte-equality (context strings, kinds, ordering) too.
    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(s1, s2, "references --limit full JSON differs across runs");

    // The truncated subset must be a prefix of the full sorted result:
    // truncation should drop the TAIL, never reshuffle the head.
    let full = run_json(&["references", "run", &cs, "--format", "json", "--quiet"]);
    let full_keys = ref_keys(&full);
    assert!(
        full_keys.len() > 5,
        "expected the un-limited reference list to exceed the cap; got {}",
        full_keys.len()
    );
    assert_eq!(
        &full_keys[..5],
        &k1[..],
        "truncated subset is not the sorted prefix of the full result"
    );
}

// =============================================================================
// impact: reverse-call-graph caller tree byte-stable across runs
// =============================================================================

/// For each target in an impact report, project its `callers[]` array down
/// to the ordered list of (file, function) identity tuples. Keyed by the
/// target name so the comparison is independent of the `targets` *map*
/// key-iteration order (which is governed by `ImpactReport.targets`'s
/// `HashMap` in types.rs — out of CL-1's owned scope — see deferred_design)
/// while still pinning the ORDER of each caller list, which is the
/// owned-file concern (impact.rs reverse-graph + enrichment ordering).
fn impact_caller_orders(v: &Value) -> std::collections::BTreeMap<String, Vec<(String, String)>> {
    let mut out = std::collections::BTreeMap::new();
    if let Some(targets) = v.get("targets").and_then(|t| t.as_object()) {
        for (target_key, tree) in targets {
            let callers = tree
                .get("callers")
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|c| {
                            let f = c
                                .get("file")
                                .and_then(|x| x.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let func = c
                                .get("function")
                                .and_then(|x| x.as_str())
                                .unwrap_or_default()
                                .to_string();
                            (f, func)
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.insert(target_key.clone(), callers);
        }
    }
    out
}

#[test]
fn impact_caller_tree_is_byte_stable() {
    let Some(c) = corpus_or_skip("impact_caller_tree_is_byte_stable") else {
        return;
    };
    let cs = path_str(&c);
    let args = ["impact", "run", &cs, "--format", "json", "--quiet"];

    let r1 = run_json(&args);
    let r2 = run_json(&args);
    let r3 = run_json(&args);

    // The owned-file fix (impact.rs): the reverse-graph caller adjacency
    // and the references-enrichment append are now sorted, so the ORDER of
    // every target's `callers[]` array is stable across runs. We compare
    // the per-target caller orderings (keyed by target name) rather than
    // raw JSON, because the `targets` *map* key order is a separate
    // nondeterminism rooted in `ImpactReport.targets: HashMap<..>` in
    // types.rs, which is outside this cluster's owned files.
    let o1 = impact_caller_orders(&r1);
    let o2 = impact_caller_orders(&r2);
    let o3 = impact_caller_orders(&r3);

    assert_eq!(o1, o2, "impact caller ORDER differs run #1 vs #2 (reverse-graph HashMap order?)");
    assert_eq!(o2, o3, "impact caller ORDER differs run #2 vs #3");

    // Sanity: the target should have multiple callers, so the caller
    // array is genuinely order-sensitive (otherwise the assertion above
    // would be vacuously true on single-element / empty lists).
    let max_callers = o1.values().map(|v| v.len()).max().unwrap_or(0);
    assert!(
        max_callers >= 2,
        "expected at least one impact target with >=2 callers; got max {max_callers}"
    );

    // Each caller list must itself be sorted by (file, function) — proves
    // the fix imposes a real total order rather than merely freezing an
    // arbitrary one that happened to repeat.
    for (target, callers) in &o1 {
        let mut sorted = callers.clone();
        sorted.sort();
        assert_eq!(
            callers, &sorted,
            "callers[] for target {target} are not in (file, function) sorted order"
        );
    }
}
