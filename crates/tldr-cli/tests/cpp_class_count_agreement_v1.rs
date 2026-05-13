//! cpp-class-count-agreement-v1 (v0.4.2 bug-B2 / BUG-CPP-P20-01)
//!
//! Pre-fix: on `/tmp/repos/cpp-tinyxml2` (mixed C++ codebase with class
//! declarations in `tinyxml2.h`):
//!
//!   - `tldr health <dir>`     → classes_analyzed = 3
//!   - `tldr structure <dir>`  → ~30 classes (counts forward-decls too)
//!   - `tldr cohesion <file>`  → 14 classes (file-level)
//!   - `tldr cohesion <dir>`   → 15 classes (no language filter)
//!
//! Root cause: `health` invokes
//! `tldr_core::quality::cohesion::analyze_cohesion(path, Some(Cpp), …)`.
//! The directory walker's file filter compares
//! `Language::from_path(e.path())` with the requested language. `.h`
//! files map to `Language::C` (BUG-P19-08 family — already documented
//! in `analyze_file_cohesion`'s `language = C → Cpp` promotion). The
//! filter rejects `.h` before that promotion runs, so the cpp surface
//! over a directory misses every header-resident class.
//!
//! Fix: in `analyze_cohesion_with_options`, when the requested
//! `language = Cpp`, also accept files that `Language::from_path`
//! tagged as `C` whose extension is `.h` / `.hpp`. The inner
//! `analyze_file_cohesion` already re-detects the body as Cpp on the
//! `class`/`namespace` keyword signal.
//!
//! Scope per scope-guardrails: structure's higher number includes
//! forward-decls and is a separate "structure inflates cpp class
//! count via forward-decls" defect (deferred — different heuristic).
//! This change unifies the two surfaces that share the LCOM4 path
//! (health ↔ cohesion).
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

const CORPUS_DIR: &str = "/tmp/repos/cpp-tinyxml2";

// ============================================================================
// TEST 1: health classes_analyzed on directory must agree with
//         cohesion classes_analyzed on the same directory.
// ============================================================================
#[test]
fn cpp_health_cohesion_agree_on_directory() {
    if !Path::new(CORPUS_DIR).exists() {
        eprintln!(
            "[skip] cpp_health_cohesion_agree_on_directory: corpus {} \
             not present",
            CORPUS_DIR
        );
        return;
    }
    let (rc1, h_out) = run_tldr(&["health", CORPUS_DIR, "--format", "json"]);
    assert_eq!(rc1, 0, "health must succeed; got rc={}", rc1);
    let health_classes = parse_json(&h_out)["summary"]["classes_analyzed"]
        .as_u64()
        .unwrap_or(0) as usize;

    let (rc2, c_out) = run_tldr(&["cohesion", CORPUS_DIR, "--format", "json"]);
    assert_eq!(rc2, 0, "cohesion must succeed; got rc={}", rc2);
    let cohesion_classes = parse_json(&c_out)["summary"]["total_classes"]
        .as_u64()
        .or_else(|| parse_json(&c_out)["classes"].as_array().map(|a| a.len() as u64))
        .unwrap_or(0) as usize;

    // Real ground truth: tinyxml2.h has 14 classes with bodies +
    // contrib/html5-printer.cpp has 1 = 15. Anything materially below
    // that means `.h` files were filtered out before the C→Cpp
    // promotion (the documented BUG-CPP-P20-01 / P19-08 root cause).
    assert!(
        health_classes >= 10,
        "health classes_analyzed for {} must be >= 10 once .h files \
         are included; got {} (pre-fix: 3)",
        CORPUS_DIR,
        health_classes
    );
    assert!(
        cohesion_classes >= 10,
        "cohesion total_classes for {} must be >= 10; got {}",
        CORPUS_DIR,
        cohesion_classes
    );
    assert_eq!(
        health_classes, cohesion_classes,
        "health classes_analyzed and cohesion total_classes must \
         agree on the same directory; got health={} cohesion={}",
        health_classes, cohesion_classes
    );
}

// ============================================================================
// TEST 2: cohesion called explicitly with --lang cpp must still find
//         the .h-resident classes (no regression on the explicit
//         language path that already works for the CLI).
// ============================================================================
#[test]
fn cpp_cohesion_lang_cpp_includes_headers() {
    if !Path::new(CORPUS_DIR).exists() {
        eprintln!(
            "[skip] cpp_cohesion_lang_cpp_includes_headers: corpus {} \
             not present",
            CORPUS_DIR
        );
        return;
    }
    let (rc, out) = run_tldr(&[
        "cohesion",
        CORPUS_DIR,
        "--lang",
        "cpp",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "cohesion --lang cpp must succeed; got rc={}", rc);
    let v = parse_json(&out);
    let classes = v["classes"].as_array().cloned().unwrap_or_default();
    let count = classes.len();
    let files: std::collections::BTreeSet<String> = classes
        .iter()
        .filter_map(|c| c["file_path"].as_str().map(|s| s.to_string()))
        .collect();

    assert!(
        count >= 10,
        "cohesion --lang cpp on {} must report >= 10 classes; got {}",
        CORPUS_DIR,
        count
    );
    let has_h_file = files
        .iter()
        .any(|p| p.ends_with(".h") || p.ends_with(".hpp"));
    assert!(
        has_h_file,
        "cohesion --lang cpp must include at least one .h/.hpp file; \
         got files={:?}",
        files
    );
}

// ============================================================================
// TEST 3: file-level invocations are unchanged — `tldr health
//         tinyxml2.h` already worked pre-fix (file path skips the
//         directory walker filter). Regression guard.
// ============================================================================
#[test]
fn cpp_health_cohesion_agree_on_header_file() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
    if !Path::new(file).exists() {
        eprintln!(
            "[skip] cpp_health_cohesion_agree_on_header_file: corpus \
             {} not present",
            file
        );
        return;
    }
    let (rc1, h_out) = run_tldr(&["health", file, "--format", "json"]);
    assert_eq!(rc1, 0, "health on file must succeed; got rc={}", rc1);
    let health_classes = parse_json(&h_out)["summary"]["classes_analyzed"]
        .as_u64()
        .unwrap_or(0) as usize;

    let (rc2, c_out) = run_tldr(&["cohesion", file, "--format", "json"]);
    assert_eq!(rc2, 0, "cohesion on file must succeed; got rc={}", rc2);
    let cohesion_classes = parse_json(&c_out)["classes"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    assert!(
        health_classes >= 10,
        "health on header file must report >= 10 classes; got {}",
        health_classes
    );
    assert_eq!(
        health_classes, cohesion_classes,
        "health and cohesion must agree on the same .h file; got \
         health={} cohesion={}",
        health_classes, cohesion_classes
    );
}

// ============================================================================
// TEST 4: structure is the bigger surface (counts forward decls + bodies).
//         We document that it must be at least as large as the
//         cohesion count (it sees everything cohesion sees, plus more).
//         Strict equality is NOT asserted here — that's a separate
//         deferred issue (structure forward-decl dedup).
// ============================================================================
#[test]
fn cpp_structure_ge_cohesion_on_directory() {
    if !Path::new(CORPUS_DIR).exists() {
        eprintln!(
            "[skip] cpp_structure_ge_cohesion_on_directory: corpus {} \
             not present",
            CORPUS_DIR
        );
        return;
    }
    let (rc1, s_out) = run_tldr(&["structure", CORPUS_DIR, "--format", "json"]);
    assert_eq!(rc1, 0, "structure must succeed; got rc={}", rc1);
    let mut structure_total: usize = 0;
    if let Some(files) = parse_json(&s_out)["files"].as_array() {
        for f in files {
            if let Some(cls) = f["classes"].as_array() {
                structure_total += cls.len();
            }
        }
    }

    let (rc2, c_out) = run_tldr(&["cohesion", CORPUS_DIR, "--format", "json"]);
    assert_eq!(rc2, 0, "cohesion must succeed; got rc={}", rc2);
    let cohesion_count = parse_json(&c_out)["summary"]["total_classes"]
        .as_u64()
        .or_else(|| parse_json(&c_out)["classes"].as_array().map(|a| a.len() as u64))
        .unwrap_or(0) as usize;

    assert!(
        structure_total >= cohesion_count,
        "structure must report at least as many classes as cohesion \
         on the same directory (structure sees forward-decls too); \
         got structure={} cohesion={}",
        structure_total,
        cohesion_count
    );
    // Sanity floor: both surfaces must produce a non-trivial count
    // once .h promotion works.
    assert!(
        structure_total >= 10,
        "structure must report >= 10 classes on {}; got {}",
        CORPUS_DIR,
        structure_total
    );
    assert!(
        cohesion_count >= 10,
        "cohesion must report >= 10 classes on {}; got {}",
        CORPUS_DIR,
        cohesion_count
    );
}
