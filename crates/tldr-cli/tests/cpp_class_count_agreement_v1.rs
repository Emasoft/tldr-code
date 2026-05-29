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
//! Original root cause: `health` invoked
//! `tldr_core::quality::cohesion::analyze_cohesion(path, Some(Cpp), …)`.
//! The directory walker's file filter compared
//! `Language::from_path(e.path())` with the requested language. `.h`
//! files mapped to `Language::C` (BUG-P19-08 family — documented in
//! `analyze_file_cohesion`'s `language = C → Cpp` promotion). The
//! filter rejected `.h` before promotion ran, so the cpp surface over a
//! directory missed every header-resident class.
//!
//! Original fix (`b2`): in `analyze_cohesion_with_options`, when the
//! requested `language = Cpp`, also accept files tagged as `C` whose
//! extension is `.h` / `.hpp`. The inner `analyze_file_cohesion` then
//! re-detects the body as Cpp on the `class`/`namespace` signal.
//!
//! ## M-016 post-canonicalisation (v0.4.2 health-dashboard-v1)
//!
//! Phase-22 audit M-016 promoted `tldr structure`'s AST projection
//! (M-006) to the canonical source-of-truth for `health.summary.
//! classes_analyzed` / `functions_analyzed` across all languages. The
//! old invariant `health.classes == cohesion.classes` (this file's
//! original spec) was a per-cpp-lang patch that only repaired the
//! header-promotion bug; it did NOT extend to other langs where
//! cohesion legitimately reports 0 (kotlin, swift) while structure
//! reports the real class count (476, 1998 respectively).
//!
//! Updated invariants enforced below:
//!
//!   - `health.summary.classes_analyzed == sum(structure.files[].
//!      classes.len())` (cpp + every other lang — the M-016 fix).
//!   - `cohesion.total_classes <= health.classes_analyzed` (cohesion
//!     is a strict-or-equal subset: only classes with extractable
//!     bodies; structure includes forward-decls too).
//!   - Both surfaces continue to clear the `>= 10` floor on
//!     `/tmp/repos/cpp-tinyxml2` (header-promotion regression guard
//!     preserved).
//!
//! The "structure forward-decl dedup" defect is still deferred —
//! M-016 explicitly accepts structure's higher count as canonical
//! because in the broader audit (kotlin, swift, typescript) structure
//! is correct and cohesion is wrong.
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
// TEST 1: health classes_analyzed on directory MUST agree with
//         structure (M-016 canonical), and cohesion remains a
//         strict-or-equal subset (forward-decls vs bodies).
//
// M-016 (v0.4.2 health-dashboard-v1) inverts the original
// "health == cohesion" invariant: structure is the canonical surface.
// The cohesion-vs-structure header-promotion regression is still
// guarded via the `>= 10` floor on both surfaces.
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

    let (rc3, s_out) = run_tldr(&["structure", CORPUS_DIR, "--format", "json"]);
    assert_eq!(rc3, 0, "structure must succeed; got rc={}", rc3);
    let structure_classes: usize = parse_json(&s_out)["files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .map(|f| f["classes"].as_array().map(|a| a.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);

    // Real ground truth: tinyxml2.h has 14 classes with bodies +
    // contrib/html5-printer.cpp has 1 = 15. Anything materially below
    // that means `.h` files were filtered out before the C→Cpp
    // promotion (the documented BUG-CPP-P20-01 / P19-08 root cause).
    // This regression guard is preserved post-M-016.
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

    // M-016: health is canonicalised against structure, not cohesion.
    assert_eq!(
        health_classes, structure_classes,
        "M-016: health.classes_analyzed must equal structure's \
         sum(files[].classes.len()); got health={} structure={}",
        health_classes, structure_classes
    );

    // Cohesion remains a (strict-or-equal) subset of structure —
    // structure includes forward-decls that cohesion's LCOM4 path
    // skips. This documents the deferred "structure forward-decl
    // dedup" defect.
    assert!(
        cohesion_classes <= structure_classes,
        "cohesion total_classes must be <= structure (cohesion is a \
         body-only subset); got cohesion={} structure={}",
        cohesion_classes, structure_classes
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
// TEST 3: file-level invocations: health must equal structure (M-016
//         canonical); cohesion remains a strict-or-equal subset.
//         File path skips the directory walker filter so the original
//         header-promotion bug never triggers here; this test
//         primarily guards the `>= 10` floor + the M-016 canonical
//         invariant on a single-file input.
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

    let (rc3, s_out) = run_tldr(&["structure", file, "--format", "json"]);
    assert_eq!(rc3, 0, "structure on file must succeed; got rc={}", rc3);
    let structure_classes: usize = parse_json(&s_out)["files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .map(|f| f["classes"].as_array().map(|a| a.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);

    // Floor: in single-file mode, `tldr structure tinyxml2.h` reports
    // only top-level classes (~6 in tinyxml2.h's case). The original
    // `>= 10` floor was calibrated against cohesion (which also walks
    // nested classes). Post-M-016 health agrees with structure, so the
    // floor moves down to the top-level-only level. Cohesion still
    // reports the higher nested count and is asserted separately.
    assert!(
        health_classes >= 5,
        "health on header file must report >= 5 top-level classes; \
         got {} (M-016 floor: matches structure's single-file count)",
        health_classes
    );
    assert!(
        cohesion_classes >= 10,
        "cohesion on header file must still report >= 10 classes \
         (nested + top-level); got {}",
        cohesion_classes
    );

    // M-016: health is canonicalised against structure.
    assert_eq!(
        health_classes, structure_classes,
        "M-016: health.classes_analyzed must equal structure's \
         sum(files[].classes.len()); got health={} structure={}",
        health_classes, structure_classes
    );

    // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): after
    // `structure` started recovering macro-decorated classes in single-
    // file mode AND recursing into the recovered bodies for nested
    // classes (e.g. tinyxml2's `class DynArray` nested under `class
    // TINYXML2_LIB StrPair`), `structure` is now the BIGGER surface on
    // `.h` files because it ALSO emits forward declarations and enums
    // alongside the class bodies that cohesion sees. The previously
    // recorded direction (`cohesion >= structure`) documented the
    // deferred "structure single-file nested-class emission" defect —
    // now closed by M-110. Pin the new direction (`structure >=
    // cohesion`) which mirrors TEST 4's directory-mode pin.
    assert!(
        structure_classes >= cohesion_classes,
        "post-M-110: structure on .h must be >= cohesion (structure \
         also emits forward declarations and enums that cohesion's \
         body-only walker skips); got structure={} cohesion={}",
        structure_classes, cohesion_classes
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
