//! fix-deps-schema-v1 (v0.5.0 FIX-DEPS-SCHEMA)
//!
//! Schema-parity contract: a `tldr deps --include-external --format json` report
//! must ALWAYS carry the four canonical map/stat keys, even when a particular
//! language/repo has zero dependencies of a given kind.
//!
//! Pre-fix bug: `DepsReport.internal_dependencies` and
//! `DepsReport.external_dependencies` carried
//! `#[serde(skip_serializing_if = "BTreeMap::is_empty")]`, so a stdlib-only /
//! zero-external repo (e.g. go-httprouter) OMITTED the `external_dependencies`
//! key entirely. Consumers and the schema-parity contract expect the key to be
//! present as an empty object `{}` — not missing and not `null`.
//!
//! Post-fix: empty maps serialize as `{}` (BTreeMap retained for deterministic
//! ordering). Populated maps (java/kotlin/csharp) continue to emit their
//! entries unchanged.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early when
//! its `/tmp/repos/<repo>` corpus is absent.

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

const GO_CORPUS: &str = "/tmp/repos/go-httprouter";
const KOTLIN_CORPUS: &str = "/tmp/repos/kotlin-datetime";

// ============================================================================
// TEST 1: zero-external repo still carries `external_dependencies` as an object.
//         go-httprouter is stdlib-only (no third-party imports), so the
//         external map is empty — it must serialize as `{}`, NOT be omitted
//         and NOT be `null`.
// ============================================================================
#[test]
fn go_zero_external_still_emits_external_dependencies_object() {
    if !corpus_ready(GO_CORPUS) {
        eprintln!(
            "[skip] go_zero_external_still_emits_external_dependencies_object: corpus {} not present",
            GO_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&["deps", GO_CORPUS, "--include-external", "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on go; got rc={}", rc);
    let v = parse_json(&out);

    // Key must be present (not missing).
    assert!(
        v.get("external_dependencies").is_some(),
        "external_dependencies key must be present even when empty (key parity)"
    );
    // Must be an object, not null.
    assert!(
        v["external_dependencies"].is_object(),
        "external_dependencies must be an object (possibly empty {{}}), not null/missing"
    );
    assert!(
        !v["external_dependencies"].is_null(),
        "external_dependencies must not serialize as null"
    );

    // internal_dependencies must likewise always be an object.
    assert!(
        v.get("internal_dependencies").is_some(),
        "internal_dependencies key must be present (key parity)"
    );
    assert!(
        v["internal_dependencies"].is_object(),
        "internal_dependencies must be an object"
    );

    // Stats block parity.
    assert!(
        v["stats"]["total_external_deps"].is_number(),
        "stats.total_external_deps must be a number"
    );
    assert!(
        v["stats"]["total_internal_deps"].is_number(),
        "stats.total_internal_deps must be a number"
    );
}

// ============================================================================
// TEST 2: a language WITH external deps still emits a populated, non-empty
//         external_dependencies map. Guards against the fix accidentally
//         dropping/emptying populated maps.
// ============================================================================
#[test]
fn kotlin_populated_external_dependencies_map_is_non_empty() {
    if !corpus_ready(KOTLIN_CORPUS) {
        eprintln!(
            "[skip] kotlin_populated_external_dependencies_map_is_non_empty: corpus {} not present",
            KOTLIN_CORPUS
        );
        return;
    }
    let (rc, out) = run_tldr(&[
        "deps",
        KOTLIN_CORPUS,
        "--include-external",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "deps must succeed on kotlin; got rc={}", rc);
    let v = parse_json(&out);

    assert!(
        v["external_dependencies"].is_object(),
        "kotlin: external_dependencies must be an object"
    );
    let ext = v["external_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert!(
        !ext.is_empty(),
        "kotlin-datetime imports kotlinx.* packages; external_dependencies must be populated, \
         got an empty map (fix must not blanket-empty populated maps)"
    );
    assert!(
        v["stats"]["total_external_deps"].as_u64().unwrap_or(0) > 0,
        "kotlin: total_external_deps must be > 0 for kotlin-datetime"
    );
}
