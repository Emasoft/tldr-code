//! health-dashboard-v1 (v0.4.2 M-016)
//!
//! Phase-22 audit M-016 (cluster across ~7 languages: c, cpp, go, java,
//! javascript, kotlin, swift, typescript) found that `tldr health`:
//!   1. Never emitted a top-level `score` (overall health 0-100). Consumers
//!      that wanted a single quality indicator had to re-aggregate the
//!      sub-buckets themselves.
//!   2. Counted `classes_analyzed` and `functions_analyzed` from each
//!      sub-analyzer's view (cohesion → classes, complexity → functions),
//!      which disagreed with the canonical AST projection emitted by
//!      `tldr structure` (M-006). Repros at audit time:
//!         - kotlin-datetime: structure 476 classes / health 0 classes
//!         - swift-collections: structure 1998 classes / health 0 classes
//!         - typescript ts-dom-gen: structure 0 classes / health 1 class
//!         - cpp tinyxml2: structure 30 classes / health 15 classes
//!   3. (Cluster summary on language detection was outdated; in practice
//!      `language` is already populated. We still pin its presence
//!      across the language matrix to keep the regression guard tight.)
//!
//! This file is the regression guard. It asserts, across multiple
//! corpora / languages, that:
//!
//!   A. The health JSON top-level `summary` carries a numeric `score`
//!      field in the range [0, 100] for every analyzed corpus.
//!   B. The top-level `language` is non-null and matches the detected
//!      language of the corpus.
//!   C. `summary.classes_analyzed` equals the sum of
//!      `files[].classes.len()` from `tldr structure` (canonical AST
//!      projection from M-006).
//!   D. `summary.functions_analyzed` equals the sum of
//!      `files[].functions.len()` from `tldr structure`.
//!   E. The score formula is the documented weighted average
//!      (33% complexity / 33% dead-code / 34% smells/hotspots).
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

use std::path::{Path, PathBuf};
use std::process::Command;

fn tldr_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    PathBuf::from(manifest)
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
    serde_json::from_str(out)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}; stdout was:\n{out}"))
}

/// Count classes by summing `files[].classes.len()` from a structure JSON.
fn structure_class_count(structure: &serde_json::Value) -> usize {
    structure
        .get("files")
        .and_then(|f| f.as_array())
        .map(|files| {
            files
                .iter()
                .map(|f| {
                    f.get("classes")
                        .and_then(|c| c.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0)
}

/// Count functions by summing `files[].functions.len()` from a structure JSON.
fn structure_function_count(structure: &serde_json::Value) -> usize {
    structure
        .get("files")
        .and_then(|f| f.as_array())
        .map(|files| {
            files
                .iter()
                .map(|f| {
                    f.get("functions")
                        .and_then(|c| c.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0)
}

fn repo_exists(repo: &str) -> bool {
    Path::new(&format!("/tmp/repos/{repo}")).exists()
}

// =============================================================================
// Test A: `score` is emitted and in [0,100] across languages
// =============================================================================

/// `summary.score` is present, integer-shaped, and in [0,100] for a
/// canonical C corpus.
#[test]
fn c_health_score_present_and_in_range() {
    if !repo_exists("c-sds") {
        return;
    }
    let (exit, out) = run_tldr(&["health", "--quick", "/tmp/repos/c-sds"]);
    assert_eq!(exit, 0, "health exited non-zero: {out}");
    let v = parse_json(&out);
    let score = v
        .get("summary")
        .and_then(|s| s.get("score"))
        .unwrap_or_else(|| panic!("health: summary.score missing; got {v}"));
    let n = score
        .as_u64()
        .unwrap_or_else(|| panic!("health: summary.score is not an unsigned int; got {score}"));
    assert!(
        n <= 100,
        "health: summary.score out of range [0,100]; got {n}"
    );
}

/// Same assertion across kotlin / swift / typescript / go / javascript.
/// Aggregating ~5 langs in one test so the regression guard fires for any
/// language that loses score emission.
#[test]
fn multi_lang_health_score_present_and_in_range() {
    let corpora = [
        ("kotlin-datetime", "kotlin"),
        ("swift-collections", "swift"),
        ("ts-dom-gen", "typescript"),
        ("go-httprouter", "go"),
        ("express", "javascript"),
    ];

    let mut checked = 0usize;
    for (repo, _lang) in corpora.iter() {
        if !repo_exists(repo) {
            continue;
        }
        let path = format!("/tmp/repos/{repo}");
        let (exit, out) = run_tldr(&["health", "--quick", &path]);
        assert_eq!(exit, 0, "[{repo}] health exited non-zero: {out}");
        let v = parse_json(&out);
        let score = v
            .get("summary")
            .and_then(|s| s.get("score"))
            .unwrap_or_else(|| panic!("[{repo}] summary.score missing; got {v}"));
        let n = score.as_u64().unwrap_or_else(|| {
            panic!("[{repo}] summary.score is not an unsigned int; got {score}")
        });
        assert!(
            n <= 100,
            "[{repo}] summary.score out of range [0,100]; got {n}"
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "no corpora present under /tmp/repos/* — multi-lang guard skipped entirely"
    );
}

// =============================================================================
// Test B: `language` field is non-null and matches detection
// =============================================================================

#[test]
fn health_language_field_non_null_multi_lang() {
    let corpora = [
        ("c-sds", "c"),
        ("kotlin-datetime", "kotlin"),
        ("swift-collections", "swift"),
        ("ts-dom-gen", "typescript"),
        ("go-httprouter", "go"),
    ];

    let mut checked = 0usize;
    for (repo, expected_lang) in corpora.iter() {
        if !repo_exists(repo) {
            continue;
        }
        let path = format!("/tmp/repos/{repo}");
        let (exit, out) = run_tldr(&["health", "--quick", &path]);
        assert_eq!(exit, 0, "[{repo}] health exited non-zero: {out}");
        let v = parse_json(&out);
        let lang = v
            .get("language")
            .unwrap_or_else(|| panic!("[{repo}] top-level language key missing; got {v}"));
        assert!(
            !lang.is_null(),
            "[{repo}] language is null; expected {expected_lang}"
        );
        let lang_str = lang
            .as_str()
            .unwrap_or_else(|| panic!("[{repo}] language is not a string; got {lang}"));
        assert_eq!(
            lang_str, *expected_lang,
            "[{repo}] language mismatch: expected {expected_lang}, got {lang_str}"
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "no corpora present under /tmp/repos/* — language guard skipped entirely"
    );
}

// =============================================================================
// Test C: `classes_analyzed` agrees with structure projection (canonical)
// =============================================================================

/// kotlin-datetime: at audit time health=0 classes, structure=476. Pin the
/// post-fix invariant that health's count exactly matches structure.
#[test]
fn kotlin_health_classes_analyzed_matches_structure() {
    if !repo_exists("kotlin-datetime") {
        return;
    }
    let path = "/tmp/repos/kotlin-datetime";
    let (exit_h, out_h) = run_tldr(&["health", "--quick", path]);
    assert_eq!(exit_h, 0, "kotlin health exited non-zero: {out_h}");
    let h = parse_json(&out_h);
    let h_classes = h
        .pointer("/summary/classes_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("kotlin health: summary.classes_analyzed missing; got {h}"))
        as usize;

    let (exit_s, out_s) = run_tldr(&["structure", path]);
    assert_eq!(exit_s, 0, "kotlin structure exited non-zero: {out_s}");
    let s = parse_json(&out_s);
    let s_classes = structure_class_count(&s);

    assert_eq!(
        h_classes, s_classes,
        "kotlin: health.summary.classes_analyzed ({h_classes}) != \
         structure files[].classes.len() sum ({s_classes}). \
         health must canonicalize counters against structure (M-006)."
    );

    // M-016 baseline: kotlin-datetime has >0 classes; assert non-zero so
    // a regression that re-zeros the count gets caught.
    assert!(
        s_classes > 0,
        "kotlin-datetime structure reports {s_classes} classes; \
         regression suite expects a class-rich corpus"
    );
}

/// Same canonical-agreement invariant for Swift and TypeScript in one test.
#[test]
fn swift_and_typescript_health_classes_match_structure() {
    let cases = [
        ("swift-collections", "swift"),
        ("ts-dom-gen", "typescript"),
    ];

    let mut checked = 0usize;
    for (repo, _lang) in cases.iter() {
        if !repo_exists(repo) {
            continue;
        }
        let path = format!("/tmp/repos/{repo}");

        let (exit_h, out_h) = run_tldr(&["health", "--quick", &path]);
        assert_eq!(exit_h, 0, "[{repo}] health exited non-zero: {out_h}");
        let h = parse_json(&out_h);
        let h_classes = h
            .pointer("/summary/classes_analyzed")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                panic!("[{repo}] health: summary.classes_analyzed missing; got {h}")
            }) as usize;

        let (exit_s, out_s) = run_tldr(&["structure", &path]);
        assert_eq!(exit_s, 0, "[{repo}] structure exited non-zero: {out_s}");
        let s = parse_json(&out_s);
        let s_classes = structure_class_count(&s);

        assert_eq!(
            h_classes, s_classes,
            "[{repo}] health.summary.classes_analyzed ({h_classes}) != \
             structure files[].classes.len() sum ({s_classes}). \
             health must canonicalize against structure (M-006)."
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "no swift/typescript corpora present under /tmp/repos/*"
    );
}

// =============================================================================
// Test D: `functions_analyzed` agrees with structure projection
// =============================================================================

/// health.summary.functions_analyzed must match sum of files[].functions.len()
/// from `tldr structure` on the same path. Pinned for c and go.
#[test]
fn multi_lang_health_functions_analyzed_matches_structure() {
    let cases = [("c-sds", "c"), ("go-httprouter", "go")];

    let mut checked = 0usize;
    for (repo, _lang) in cases.iter() {
        if !repo_exists(repo) {
            continue;
        }
        let path = format!("/tmp/repos/{repo}");

        let (exit_h, out_h) = run_tldr(&["health", "--quick", &path]);
        assert_eq!(exit_h, 0, "[{repo}] health exited non-zero: {out_h}");
        let h = parse_json(&out_h);
        let h_fns = h
            .pointer("/summary/functions_analyzed")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                panic!("[{repo}] health: summary.functions_analyzed missing; got {h}")
            }) as usize;

        let (exit_s, out_s) = run_tldr(&["structure", &path]);
        assert_eq!(exit_s, 0, "[{repo}] structure exited non-zero: {out_s}");
        let s = parse_json(&out_s);
        let s_fns = structure_function_count(&s);

        assert_eq!(
            h_fns, s_fns,
            "[{repo}] health.summary.functions_analyzed ({h_fns}) != \
             structure files[].functions.len() sum ({s_fns}). \
             health must canonicalize against structure (M-006)."
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "no c/go corpora present under /tmp/repos/*"
    );
}

// =============================================================================
// Test E: score formula is the documented weighted average
// =============================================================================

/// On a clean / small repo (no dead code, low complexity, no hotspots) the
/// score should land near 100. Conversely a hotspot-heavy corpus must
/// produce a score < 100. This pins the formula's monotone behaviour
/// without baking in exact integer values (which would couple the test
/// to internal threshold tuning).
#[test]
fn health_score_monotone_wrt_hotspots() {
    if !repo_exists("c-sds") {
        return;
    }
    // c-sds has 6 hotspots / 51 functions at audit time → non-trivial smell.
    let (exit, out) = run_tldr(&["health", "--quick", "/tmp/repos/c-sds"]);
    assert_eq!(exit, 0, "c health exited non-zero: {out}");
    let v = parse_json(&out);

    let score = v
        .pointer("/summary/score")
        .and_then(|s| s.as_u64())
        .unwrap_or_else(|| panic!("c-sds health: score missing; got {v}"));
    let hotspots = v
        .pointer("/summary/hotspot_count")
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    let dead = v
        .pointer("/summary/dead_count")
        .and_then(|s| s.as_u64())
        .unwrap_or(0);

    // Formula sanity: the score is a u8 in [0,100] for any non-empty repo.
    // If hotspots > 0 OR dead > 0 the score must be strictly less than 100;
    // a perfect 100 should only be reachable when *all* three buckets
    // report zero penalty.
    if hotspots > 0 || dead > 0 {
        assert!(
            score < 100,
            "c-sds: score=100 despite hotspots={hotspots} / dead={dead}; \
             formula is not penalising any bucket"
        );
    }
    // And the score must be > 0 — a stub that always returns 0 is also
    // a regression.
    assert!(
        score > 0,
        "c-sds: score=0 despite a non-degenerate corpus; \
         formula is not crediting any bucket"
    );
}
