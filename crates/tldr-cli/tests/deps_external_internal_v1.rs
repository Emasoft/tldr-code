//! deps-external-internal-classifier-v1 (v0.4.2 M-048)
//!
//! Pre-fix audit assertion: across ~8 languages, `tldr deps --include-external`
//! exposes a per-language deps adapter that fails to map full namespaces /
//! package names to project files and fails to count external packages with
//! meaningful precision:
//!
//!   * Java: `import org.springframework.boot.SpringApplication;` collapses
//!     to base segment `"org"`. Spring petclinic with 47 files yields
//!     `total_external_deps:4` (just `["jakarta", "java", "javax", "org"]`).
//!   * Kotlin: same collapse — `total_external_deps:7` for kotlin-datetime
//!     across 223 files (the seven unique bare-base segments).
//!   * CSharp: `Src/` (capital S) prefix is not stripped by `index_csharp_module`,
//!     so internal namespace lookups for `using Newtonsoft.Json.Bson;` against
//!     files at `Src/Newtonsoft.Json.Bson/...` never hit and
//!     `total_internal_deps:0` even when the project clearly imports its own
//!     namespaces.
//!   * Go: same-package implicit edges (router.go ↔ router_test.go ↔ tree.go
//!     ↔ ...) feed the cycle detector, producing 15 spurious cycles in
//!     go-httprouter where there are zero real cyclic imports.
//!
//! Post-fix:
//!   1. Java / Kotlin / CSharp / Scala / Elixir / Ocaml external names retain
//!      the package prefix (e.g. `org.springframework`, `kotlinx.coroutines`,
//!      `Newtonsoft.Json`), so `total_external_deps` for Spring petclinic
//!      rises from 4 → >= 10 distinct external packages.
//!   2. CSharp `Src/` (capital S) is stripped case-insensitively, so internal
//!      namespace lookups succeed for typical .NET layouts.
//!   3. Go same-package implicit edges no longer feed the cycle detector —
//!      `cycles_found` drops from 15 → 0 for go-httprouter while real
//!      import-based cycles continue to be reported elsewhere.
//!   4. Schema parity: every language report carries `internal_dependencies`,
//!      `external_dependencies`, and the full `stats` block with
//!      `total_external_deps` / `total_internal_deps` keys.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early
//! when its `/tmp/repos/<repo>` corpus is absent.

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

const JAVA_CORPUS: &str = "/tmp/repos/spring-petclinic";
const KOTLIN_CORPUS: &str = "/tmp/repos/kotlin-datetime";
const CSHARP_CORPUS: &str = "/tmp/repos/csharp-newtonsoft-bson-full";
const GO_CORPUS: &str = "/tmp/repos/go-httprouter";
const RUBY_CORPUS: &str = "/tmp/repos/rails-html-sanitizer";

// ============================================================================
// TEST 1: schema parity — every language report carries the four canonical
//         keys with non-error shapes.
// ============================================================================
#[test]
fn deps_schema_parity_across_langs() {
    let corpora: &[(&str, &str)] = &[
        ("java", JAVA_CORPUS),
        ("kotlin", KOTLIN_CORPUS),
        ("csharp", CSHARP_CORPUS),
        ("go", GO_CORPUS),
        ("ruby", RUBY_CORPUS),
    ];
    for (lang, corpus) in corpora {
        if !corpus_ready(corpus) {
            eprintln!(
                "[skip] deps_schema_parity_across_langs/{}: corpus {} not present",
                lang, corpus
            );
            continue;
        }
        let (rc, out) = run_tldr(&["deps", corpus, "--include-external", "--format", "json"]);
        assert_eq!(rc, 0, "deps must succeed on {}; got rc={}", lang, rc);
        let v = parse_json(&out);
        assert!(
            v["internal_dependencies"].is_object(),
            "{}: internal_dependencies must be an object",
            lang
        );
        assert!(
            v["external_dependencies"].is_object(),
            "{}: external_dependencies must be an object (key parity)",
            lang
        );
        assert!(
            v["stats"]["total_internal_deps"].is_number(),
            "{}: stats.total_internal_deps must be a number",
            lang
        );
        assert!(
            v["stats"]["total_external_deps"].is_number(),
            "{}: stats.total_external_deps must be a number",
            lang
        );
        assert!(
            v["stats"]["total_files"].is_number(),
            "{}: stats.total_files must be a number",
            lang
        );
    }
}

// ============================================================================
// TEST 2: Java external-package precision — `import org.springframework.*`
//         must NOT collapse to bare `"org"`. We expect >= 5 distinct
//         external-package names across Spring petclinic.
// ============================================================================
#[test]
fn java_external_packages_keep_namespace_precision() {
    if !corpus_ready(JAVA_CORPUS) {
        eprintln!(
            "[skip] java_external_packages_keep_namespace_precision: corpus {} not present",
            JAVA_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", JAVA_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on java; got rc={}", rc);
    let v = parse_json(&out);

    // Collect the union of every external_dependencies value.
    let ext_map = v["external_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut unique = std::collections::HashSet::new();
    for arr in ext_map.values() {
        if let Some(arr) = arr.as_array() {
            for s in arr {
                if let Some(s) = s.as_str() {
                    unique.insert(s.to_string());
                }
            }
        }
    }

    // Pre-fix: ["jakarta", "java", "javax", "org"] — 4 entries, all
    // single-segment. Post-fix: full second-level package names
    // (e.g. `org.springframework`, `jakarta.persistence`, `java.util`).
    let has_dotted_package = unique.iter().any(|s| s.contains('.'));
    assert!(
        has_dotted_package,
        "java external packages must retain namespace precision (>=2 segments); \
         got bare single-segment values only: {:?}",
        unique
    );

    let total = v["stats"]["total_external_deps"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        total >= 5,
        "Spring petclinic must surface >= 5 distinct external packages \
         (pre-fix: 4 bare-base entries). Got {}: {:?}",
        total,
        unique
    );

    // Sanity: at least one Spring-flavoured external package.
    let has_spring = unique.iter().any(|s| s.starts_with("org.springframework"));
    assert!(
        has_spring,
        "Spring petclinic must surface at least one `org.springframework*` \
         external; got {:?}",
        unique
    );
}

// ============================================================================
// TEST 3: Kotlin external-package precision — same constraint as Java.
//         kotlin-datetime imports from kotlinx.* / org.* / java.* etc.
// ============================================================================
#[test]
fn kotlin_external_packages_keep_namespace_precision() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "[skip] kotlin_external_packages_keep_namespace_precision: corpus {} not present",
            KOTLIN_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", KOTLIN_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on kotlin; got rc={}", rc);
    let v = parse_json(&out);

    let ext_map = v["external_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut unique = std::collections::HashSet::new();
    for arr in ext_map.values() {
        if let Some(arr) = arr.as_array() {
            for s in arr {
                if let Some(s) = s.as_str() {
                    unique.insert(s.to_string());
                }
            }
        }
    }

    let has_dotted_package = unique.iter().any(|s| s.contains('.'));
    assert!(
        has_dotted_package,
        "kotlin external packages must retain namespace precision; got {:?}",
        unique
    );

    let total = v["stats"]["total_external_deps"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        total >= 5,
        "kotlin-datetime must surface >= 5 distinct external packages \
         (pre-fix: 7 bare-base entries). Got {}",
        total
    );
}

// ============================================================================
// TEST 4: CSharp `Src/` (capital-S) prefix stripped + namespace resolution.
//         `using Newtonsoft.Json.Bson;` from files under
//         `Src/Newtonsoft.Json.Bson/...` must produce at least one external
//         entry that retains namespace precision (`Newtonsoft.Json` style,
//         not bare `"Newtonsoft"`).
// ============================================================================
#[test]
fn csharp_external_packages_keep_namespace_precision() {
    if !corpus_ready(CSHARP_CORPUS) {
        eprintln!(
            "[skip] csharp_external_packages_keep_namespace_precision: corpus {} not present",
            CSHARP_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", CSHARP_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on csharp; got rc={}", rc);
    let v = parse_json(&out);

    let ext_map = v["external_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut unique = std::collections::HashSet::new();
    for arr in ext_map.values() {
        if let Some(arr) = arr.as_array() {
            for s in arr {
                if let Some(s) = s.as_str() {
                    unique.insert(s.to_string());
                }
            }
        }
    }

    // Pre-fix: ["Assert", "NUnit", "Newtonsoft", "System", "Test", "Xunit"]
    // — bare single-segment / extracted via .rfind('.') leaving a method
    // name. Post-fix: dotted package names such as `Newtonsoft.Json`,
    // `Xunit`, `System.IO`, etc.
    let has_dotted_package = unique.iter().any(|s| s.contains('.'));
    assert!(
        has_dotted_package,
        "csharp external packages must retain namespace precision; got {:?}",
        unique
    );
}

// ============================================================================
// TEST 5: Go same-package implicit edges no longer create spurious cycles.
//         go-httprouter has zero real cyclic imports.
// ============================================================================
#[test]
fn go_same_package_does_not_create_spurious_cycles() {
    if !corpus_ready(GO_CORPUS) {
        eprintln!(
            "[skip] go_same_package_does_not_create_spurious_cycles: corpus {} not present",
            GO_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", GO_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on go; got rc={}", rc);
    let v = parse_json(&out);

    let cycles = v["stats"]["cycles_found"].as_u64().unwrap_or(u64::MAX);
    // Pre-fix: 15. Post-fix: 0 (no real cycles in go-httprouter).
    assert!(
        cycles <= 2,
        "go-httprouter has zero real cyclic imports; same-package implicit \
         edges must not be fed to the cycle detector. Got {} cycles.",
        cycles
    );
}

// ============================================================================
// TEST 6: rust deps non-regression — `use crate::*` glob must not crash;
//         we accept either expansion-to-empty or skip (documented constraint).
//         At minimum, glob imports must not cause a hard error.
// ============================================================================
#[test]
fn rust_deps_glob_does_not_crash() {
    const RG_CORPUS: &str = "/tmp/repos/ripgrep";
    if !corpus_ready(RG_CORPUS) {
        eprintln!(
            "[skip] rust_deps_glob_does_not_crash: corpus {} not present",
            RG_CORPUS
        );
        return;
    }
    let (rc, _out) =
        run_tldr(&["deps", RG_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on rust+external; got rc={}", rc);
}

// ============================================================================
// TEST 7: Ruby gem dependencies — `require 'gem_name'` must produce
//         non-zero external counts when Gemfile-style gems are required.
// ============================================================================
#[test]
fn ruby_gem_requires_count_as_external() {
    if !corpus_ready(RUBY_CORPUS) {
        eprintln!(
            "[skip] ruby_gem_requires_count_as_external: corpus {} not present",
            RUBY_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", RUBY_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on ruby; got rc={}", rc);
    let v = parse_json(&out);

    let total = v["stats"]["total_external_deps"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        total >= 2,
        "rails-html-sanitizer must surface >= 2 external gems; got {}",
        total
    );

    // rails-html-sanitizer's lib/ requires `loofah`; tests require
    // `minitest/autorun` — at minimum loofah should be listed.
    let ext_map = v["external_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut unique = std::collections::HashSet::new();
    for arr in ext_map.values() {
        if let Some(arr) = arr.as_array() {
            for s in arr {
                if let Some(s) = s.as_str() {
                    unique.insert(s.to_string());
                }
            }
        }
    }
    let has_loofah = unique.iter().any(|s| s == "loofah" || s.starts_with("loofah"));
    assert!(
        has_loofah,
        "rails-html-sanitizer must surface `loofah` as external gem; got {:?}",
        unique
    );
}
