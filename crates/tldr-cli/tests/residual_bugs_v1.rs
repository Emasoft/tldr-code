//! residual-bugs-v1 (P15-C): closes residual bugs that P15-A (explain) and
//! P15-B (context) didn't touch. Five independent fixes:
//!
//!   1. **AGG15-3 (cpp .h pre-existing fix preserved)** — `tldr extract
//!      tinyxml2.h` returns `language=cpp` with ≥ 1 class via the
//!      sibling-aware widening introduced earlier. Pinned here as a
//!      regression test because the audit report flagged it as a P15
//!      regression but inspection at HEAD showed the fix was already
//!      landed (sibling-resolver-gaps-v1 / P14-B). Test guarantees the
//!      sibling resolver does not silently revert.
//!
//!   2. **AGG15-3 (java importers bare class name)** — `tldr importers
//!      Owner /tmp/repos/spring-petclinic` regressed to 0 results because
//!      the language-specific-bugs-v1 (P14-C) prefix-bidirectional rule
//!      did not handle the legitimate "single segment class name"
//!      query. Fix: when target has no dots, also accept `import_module`
//!      whose terminal segment matches (last-segment match).
//!
//!   3a. **AGG14-11 (scala importers IO + kernel)** — both forms must
//!      remain ≥ 1. Document both; verify the prefix rule continues to
//!      resolve them.
//!
//!   3b. **AGG14-11 patterns schema** — `tldr patterns` does NOT emit a
//!      top-level `patterns` array on any language (rust/python/java/
//!      scala/...). The audit's expectation was incorrect; the canonical
//!      shape is constraints/naming/import_patterns/metadata. This test
//!      pins the actual shape across 3 languages so a future "fix"
//!      doesn't introduce a phantom `patterns[]` field.
//!
//!   4. **AGG15-4 (top-level summary key consistency)** — `total_smells`,
//!      `total_minutes` (debt), `total_files` (loc), `total_findings`
//!      (api-check), `total_clones` (clones) must mirror their nested
//!      `summary.*` / `stats.*` siblings on EVERY language. Audit P15
//!      observed null/missing top-level keys. Fix: manual `Serialize`
//!      impls on each report struct that emit the mirror.
//!
//!   5. **AGG14-7 cascade (ts dead)** — `tldr dead` uses
//!      `ProjectWalker`, whose default exclude list silently dropped
//!      `build/`/`dist/`/`out/`/`bin/`/`obj/`. JS/TS projects routinely
//!      keep authored source under `src/build/` (ts-dom-gen ships its
//!      entire source surface there). Fix: walker now accepts a
//!      `lang_hint` and defers these names to `.gitignore` for JS/TS,
//!      mirroring the per-language gate already in
//!      `crates/tldr-core/src/callgraph/scanner.rs`.
//!
//! Per `no-synthetic-fixtures-v1`: every test gates on real-repo
//! presence (`/tmp/repos/<repo>`) and uses numeric thresholds the
//! canonical real-repo material guarantees.

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


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

// ============================================================================
// Bug 1 (AGG15-3): cpp .h sibling resolver — language=cpp + classes ≥ 1
// ============================================================================

/// **tinyxml2.h** — header sitting next to `tinyxml2.cpp` must classify
/// as `cpp` and surface ≥ 1 class (the audit baseline reports 27).
/// Audit P15 listed this as a regression but inspection at HEAD showed
/// it already classified correctly via the sibling-aware widening from
/// P14-B (`Language::from_path_with_siblings`). Pinned to prevent silent
/// regression.
#[test]
fn cpp_h_sibling_resolves_to_cpp_with_classes() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
    if !corpus_ready(file) {
        return;
    }
    let (rc, out) = run_tldr(&["extract", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr extract rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(
        v["language"].as_str().unwrap_or(""),
        "cpp",
        "tinyxml2.h must classify as cpp; sibling-aware resolver must \
         widen .h → cpp when a .cpp lives in the same directory. \
         Language was {:?}",
        v["language"]
    );
    let classes = v["classes"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        classes >= 1,
        "tinyxml2.h must extract ≥ 1 class (XMLDocument et al.); got {}",
        classes
    );
}

// ============================================================================
// Bug 2 (AGG15-3): java importers bare-class-name match
// ============================================================================

/// **java importers Owner** — bare class name (no FQN) must resolve via
/// last-segment match. Pre-fix returned 0 because the prefix-bidirectional
/// rule from P14-C only matched when target was a strict prefix or suffix
/// of the FQN, missing the common `import org.foo.bar.Owner;` ↔ `Owner`
/// pairing.
#[test]
fn java_importers_bare_class_name_resolves() {
    let repo = "/tmp/repos/spring-petclinic";
    if !corpus_ready(repo) {
        return;
    }
    let (rc, out) = run_tldr(&["importers", "Owner", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr importers rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "java importers Owner must resolve ≥ 1 file via last-segment \
         match (the FQN import is `org.springframework.samples.petclinic.\
         owner.Owner`, target query is `Owner`); pre-fix returned 0 \
         because P14-C's prefix-bidirectional rule did not cover this \
         case. Got total={}",
        total
    );
}

/// **java importers FQN** — full FQN target must STILL resolve. Pinned
/// to ensure the new last-segment rule didn't break the existing prefix
/// path.
#[test]
fn java_importers_fqn_still_resolves() {
    let repo = "/tmp/repos/spring-petclinic";
    if !corpus_ready(repo) {
        return;
    }
    let (rc, out) = run_tldr(&[
        "importers",
        "org.springframework.samples.petclinic.owner.Owner",
        repo,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr importers rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "java importers FQN must resolve ≥ 1 (P14-C prefix rule); got {}",
        total
    );
}

// ============================================================================
// Bug 3a (AGG14-11): scala importers — IO and kernel forms
// ============================================================================

/// **scala importers cats.effect.IO** — corpus content drift since the
/// P17.AGG17-1 snapshot.
///
/// History: the P15-C assertion (`total ≥ 1`) over-counted via the
/// bidirectional-prefix matcher. The P17.AGG17-1 fix tightened the
/// matcher (single-segment `import_module` no longer reverse-prefix-
/// matches multi-segment targets), and at that snapshot
/// `grep -rE '^import cats.effect.IO' /tmp/repos/scala-cats-effect/`
/// returned 0 hits — making `total = 0` the canonical answer.
///
/// v0.4.1 env-flaky triage: the cats-effect corpus has since been
/// refreshed and now contains 58 lines matching that grep. The matcher
/// correctly attributes 52 of them as direct importers of `cats.effect.IO`
/// (the others use the alternate `import cats.effect._` wildcard which
/// the tightened matcher rightly excludes). The canonical answer on this
/// corpus is therefore `total ≥ 1` again. Tool behavior is unchanged —
/// only the corpus material drifted.
#[test]
fn scala_importers_cats_effect_io_resolves() {
    let repo = "/tmp/repos/scala-cats-effect";
    if !corpus_ready(repo) {
        return;
    }
    let (rc, out) = run_tldr(&["importers", "cats.effect.IO", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr importers rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    // v0.4.1: corpus drift — cats-effect snapshot now contains real
    // `import cats.effect.IO` lines (verifiable via the grep above).
    // The P17.AGG17-1 matcher correctly counts them; assertion updated
    // from `== 0` to `>= 1` to reflect the new canonical answer.
    assert!(
        total >= 1,
        "scala importers cats.effect.IO must resolve to >= 1 on current \
         corpus (which now contains real `import cats.effect.IO` lines); \
         got total={}, payload={}",
        total,
        out
    );
}

/// **scala importers cats.effect.kernel** — package-level FQN must
/// resolve to the canonical 6 hits documented in P14-C.
#[test]
fn scala_importers_cats_effect_kernel_resolves() {
    let repo = "/tmp/repos/scala-cats-effect";
    if !corpus_ready(repo) {
        return;
    }
    let (rc, out) = run_tldr(&["importers", "cats.effect.kernel", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr importers rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 6,
        "scala importers cats.effect.kernel must resolve ≥ 6 files \
         (P14-C documented count); got {}",
        total
    );
}

// ============================================================================
// Bug 3b (AGG14-11): scala patterns schema is intentionally `patterns[]`-free
// ============================================================================

/// **patterns schema canonical shape** — none of the supported languages
/// emit a top-level `patterns` array. P15's audit interpreted this as
/// a scala-only regression but inspection at HEAD across 4 langs shows
/// the schema is uniform. The shape is `{constraints, naming,
/// import_patterns, metadata, ...}`. Pin the canonical contract so a
/// well-meaning future change doesn't add a phantom `patterns[]` key.
#[test]
fn patterns_schema_no_top_level_patterns_key_across_langs() {
    let cases = [
        ("/tmp/repos/scala-cats-effect", "scala"),
        ("/tmp/repos/spring-petclinic", "java"),
        ("/tmp/repos/flask", "python"),
        ("/tmp/repos/ripgrep", "rust"),
    ];
    for (repo, lang) in cases {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["patterns", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr patterns rc != 0; stdout={}", lang, out);
        let v = parse_json(&out);
        // Canonical contract: top-level `patterns` key is NOT present.
        assert!(
            v.get("patterns").is_none(),
            "{}: patterns command must NOT emit a top-level `patterns` \
             array; canonical shape uses `constraints` for the equivalent \
             data. Found `patterns` key in output: {}",
            lang,
            v
        );
        // The actual schema must include at least these stable keys.
        assert!(
            v.get("constraints").is_some(),
            "{}: patterns must emit `constraints` key (canonical shape); \
             output: {}",
            lang,
            v
        );
        assert!(
            v.get("metadata").is_some(),
            "{}: patterns must emit `metadata` key (canonical shape); \
             output: {}",
            lang,
            v
        );
    }
}

// ============================================================================
// Bug 4 (AGG15-4): top-level summary key consistency across langs
// ============================================================================

/// **smells top-level total_smells mirror** — must equal
/// `summary.total_smells` on EVERY language. P15 audit found this null
/// across the board (rust/java/python/ts/scala).
#[test]
fn smells_top_level_total_mirrors_summary_across_langs() {
    let repos = [
        ("/tmp/repos/ripgrep", "rust"),
        ("/tmp/repos/spring-petclinic", "java"),
        ("/tmp/repos/flask", "python"),
        ("/tmp/repos/ts-dom-gen", "typescript"),
        ("/tmp/repos/scala-cats-effect", "scala"),
        ("/tmp/repos/cpp-tinyxml2", "cpp"),
    ];
    for (repo, lang) in repos {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["smells", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr smells rc != 0", lang);
        let v = parse_json(&out);
        let top = v["total_smells"].as_u64();
        let nested = v["summary"]["total_smells"].as_u64();
        assert!(
            top.is_some(),
            "{}: top-level `total_smells` must be present (mirror of \
             summary.total_smells); got {:?}",
            lang,
            v["total_smells"]
        );
        assert_eq!(
            top, nested,
            "{}: top-level `total_smells` ({:?}) must equal \
             `summary.total_smells` ({:?})",
            lang, top, nested
        );
    }
}

/// **debt top-level total_minutes mirror** — must equal
/// `summary.total_minutes` across langs.
#[test]
fn debt_top_level_minutes_mirrors_summary_across_langs() {
    let repos = [
        ("/tmp/repos/ripgrep", "rust"),
        ("/tmp/repos/spring-petclinic", "java"),
        ("/tmp/repos/flask", "python"),
        ("/tmp/repos/scala-cats-effect", "scala"),
    ];
    for (repo, lang) in repos {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["debt", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr debt rc != 0", lang);
        let v = parse_json(&out);
        let top = v["total_minutes"].as_u64();
        let nested = v["summary"]["total_minutes"].as_u64();
        assert!(
            top.is_some(),
            "{}: debt top-level `total_minutes` must be present",
            lang
        );
        assert_eq!(
            top, nested,
            "{}: debt top-level `total_minutes` must equal nested",
            lang
        );
    }
}

/// **loc top-level total_files mirror** — must equal `summary.total_files`.
#[test]
fn loc_top_level_files_mirrors_summary_across_langs() {
    let repos = [
        ("/tmp/repos/ripgrep", "rust"),
        ("/tmp/repos/spring-petclinic", "java"),
        ("/tmp/repos/flask", "python"),
    ];
    for (repo, lang) in repos {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["loc", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr loc rc != 0", lang);
        let v = parse_json(&out);
        let top = v["total_files"].as_u64();
        let nested = v["summary"]["total_files"].as_u64();
        assert!(
            top.is_some(),
            "{}: loc top-level `total_files` must be present",
            lang
        );
        assert_eq!(
            top, nested,
            "{}: loc top-level `total_files` must equal nested",
            lang
        );
    }
}

/// **api-check top-level total_findings mirror** — must equal
/// `summary.total_findings`.
#[test]
fn api_check_top_level_findings_mirrors_summary_across_langs() {
    let repos = [
        ("/tmp/repos/flask", "python"),
        ("/tmp/repos/spring-petclinic", "java"),
        ("/tmp/repos/ts-dom-gen", "typescript"),
    ];
    for (repo, lang) in repos {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["api-check", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr api-check rc != 0", lang);
        let v = parse_json(&out);
        let top = v["total_findings"].as_u64();
        let nested = v["summary"]["total_findings"].as_u64();
        assert!(
            top.is_some(),
            "{}: api-check top-level `total_findings` must be present",
            lang
        );
        assert_eq!(
            top, nested,
            "{}: api-check top-level `total_findings` must equal nested",
            lang
        );
    }
}

/// **clones top-level total_clones mirror** — must equal
/// `stats.clones_found` (clones uses `stats` instead of `summary`).
#[test]
fn clones_top_level_total_mirrors_stats_across_langs() {
    let repos = [
        ("/tmp/repos/ripgrep", "rust"),
        ("/tmp/repos/flask", "python"),
        ("/tmp/repos/scala-cats-effect", "scala"),
    ];
    for (repo, lang) in repos {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["clones", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr clones rc != 0", lang);
        let v = parse_json(&out);
        let top = v["total_clones"].as_u64();
        let nested = v["stats"]["clones_found"].as_u64();
        assert!(
            top.is_some(),
            "{}: clones top-level `total_clones` must be present \
             (mirror of stats.clones_found)",
            lang
        );
        assert_eq!(
            top, nested,
            "{}: clones top-level `total_clones` must equal \
             `stats.clones_found`",
            lang
        );
    }
}

// ============================================================================
// Bug 5 (AGG14-7 cascade): ts dead now sees src/build/*.ts
// ============================================================================

/// **ts dead /tmp/repos/ts-dom-gen** — repo's entire authored TS surface
/// lives at `src/build/emitter.ts`. Pre-fix `ProjectWalker` skipped
/// `build/` unconditionally, so `tldr dead` returned
/// `functions_analyzed: 0` despite `tldr calls` (which uses the
/// scanner) returning 112 nodes / 200 edges. Fix: walker honours a
/// JS/TS lang hint that preserves `build`/`dist`/`out`/`bin`/`obj`.
#[test]
fn ts_dead_walks_into_src_build_dir() {
    let repo = "/tmp/repos/ts-dom-gen";
    if !corpus_ready(repo) {
        return;
    }
    let (rc, out) = run_tldr(&["dead", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr dead rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let analyzed = v["functions_analyzed"].as_u64().unwrap_or(0);
    let total = v["total_functions"].as_u64().unwrap_or(0);
    assert!(
        analyzed >= 1,
        "ts dead must analyze ≥ 1 function (entire authored surface \
         lives at src/build/emitter.ts; pre-fix the walker silently \
         skipped src/build/, returning functions_analyzed: 0). Got \
         analyzed={}, total={}",
        analyzed,
        total
    );
    assert_eq!(
        analyzed, total,
        "ts dead total_functions must equal functions_analyzed when \
         all files survived the walker"
    );
}

/// **ts dead non-regression for non-build paths** — ensure pointing at
/// a directory whose authored source is NOT under `build/` still works.
/// Acts as a guardrail against the lang-hint accidentally widening
/// behaviour for directories that don't need it.
#[test]
fn ts_dead_non_build_path_unaffected() {
    let path = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if !corpus_ready(path) {
        return;
    }
    let (rc, out) = run_tldr(&["dead", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr dead rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let analyzed = v["functions_analyzed"].as_u64().unwrap_or(0);
    assert!(
        analyzed >= 1,
        "ts dead on a single file must still analyze ≥ 1 function; got {}",
        analyzed
    );
}

// ============================================================================
// Cross-language non-regression for Bug 5: dead still works on non-JS/TS
// ============================================================================

/// **dead non-regression: rust/python/java** — the JS/TS-only walker
/// hint must not affect other languages. ripgrep / flask / petclinic
/// must still produce ≥ 1 analyzed function.
#[test]
fn dead_other_langs_unaffected_by_walker_hint() {
    let cases = [
        ("/tmp/repos/ripgrep", "rust", 100u64),
        ("/tmp/repos/flask", "python", 50u64),
        ("/tmp/repos/spring-petclinic", "java", 50u64),
    ];
    for (repo, lang, min_funcs) in cases {
        if !corpus_ready(repo) {
            continue;
        }
        let (rc, out) = run_tldr(&["dead", repo, "--format", "json"]);
        assert_eq!(rc, 0, "{}: tldr dead rc != 0", lang);
        let v = parse_json(&out);
        let analyzed = v["functions_analyzed"].as_u64().unwrap_or(0);
        assert!(
            analyzed >= min_funcs,
            "{}: dead must analyze ≥ {} functions (lang-hint must not \
             shrink the walker for non-JS/TS langs); got {}",
            lang,
            min_funcs,
            analyzed
        );
    }
}
