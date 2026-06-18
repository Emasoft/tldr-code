//! kotlin-deps-wiring-v1 (v0.4.2 bug-B5 / VAL-KT-DEPS / CF-KT-02)
//!
//! Pre-fix: `tldr deps /tmp/repos/kotlin-datetime` returns every kotlin
//! file with an empty `internal_dependencies` list — 223 files, zero
//! edges, every file is both a leaf and a root. `tldr imports` works on
//! the same files (kotlin import parsing is fine); the bug is in
//! `analysis/deps.rs` — kotlin is missing from the `resolve_import`
//! dispatch, so even though the per-file imports are extracted, none
//! of them are mapped to in-repo files.
//!
//! Post-fix: the resolver:
//!   1. reads each kotlin file's `package <name>` declaration during
//!      indexing and registers the file under `<package>.<simple-name>`
//!      and the package-prefix (for wildcard `*` imports);
//!   2. handles wildcard imports (`com.foo.bar.*`) by returning any
//!      indexed file in that package;
//!   3. skips well-known stdlib namespaces (`kotlin.*`, `kotlinx.coroutines.*`,
//!      `java.*`, `javax.*`).
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

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

const KT_CORPUS: &str = "/tmp/repos/kotlin-datetime";
const PY_CORPUS: &str = "/tmp/repos/flask";

// ============================================================================
// TEST 1: `tldr deps <kotlin-repo>` must produce a non-empty module graph.
//         Pre-fix: every file has 0 deps. Post-fix: aggregate edges > 0.
// ============================================================================
#[test]
fn kotlin_deps_has_non_zero_modules() {
    if !corpus_ready(KT_CORPUS) {
        eprintln!(
            "[skip] kotlin_deps_has_non_zero_modules: corpus {} not present",
            KT_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", KT_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on kotlin-datetime; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert!(
        !internal.is_empty(),
        "deps must list kotlin files in internal_dependencies; got empty map"
    );

    // Total edges across all files. Pre-fix: 0. Post-fix: >> 0.
    let total_edges: usize = internal
        .values()
        .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
        .sum();

    assert!(
        total_edges > 0,
        "kotlin deps must aggregate imports into a graph (total_edges > 0); \
         got {} edges across {} files (pre-fix bug VAL-KT-DEPS: every kotlin \
         file is both leaf and root because resolve_import dispatch is \
         missing the Kotlin arm)",
        total_edges,
        internal.len()
    );
}

// ============================================================================
// TEST 2: at least one kotlin file inside `kotlin-datetime` must resolve
//         to another kotlin file in the same repo. Same-package and/or
//         wildcard resolution covers the kotlinx.datetime → kotlinx.datetime.*
//         topology of the corpus.
// ============================================================================
#[test]
fn kotlin_deps_resolves_internal_imports() {
    if !corpus_ready(KT_CORPUS) {
        eprintln!(
            "[skip] kotlin_deps_resolves_internal_imports: corpus {} not present",
            KT_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", KT_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();

    // Find any kotlin file whose dep list is non-empty AND points to
    // another *.kt path. We don't pin a specific edge because parser
    // grammar variants can label nodes differently — but at least one
    // real internal edge must exist.
    let mut found: Option<(String, String)> = None;
    for (file, deps) in &internal {
        if !file.ends_with(".kt") && !file.ends_with(".kts") {
            continue;
        }
        if let Some(arr) = deps.as_array() {
            for d in arr {
                if let Some(target) = d.as_str() {
                    if target.ends_with(".kt") || target.ends_with(".kts") {
                        found = Some((file.clone(), target.to_string()));
                        break;
                    }
                }
            }
        }
        if found.is_some() {
            break;
        }
    }

    assert!(
        found.is_some(),
        "deps must resolve at least one kotlin import to another in-repo \
         kotlin file. Inspect the imports of `core/common/src/Instant.kt` — \
         `kotlinx.datetime.format.*` should resolve to a file under \
         `core/common/src/format/`. None found."
    );
}

// ============================================================================
// TEST 3 (non-regression): python deps still wires up correctly.
//         Pre-fix flask had > 100 internal edges; the kotlin fix must
//         not regress python resolution.
// ============================================================================
#[test]
fn python_deps_still_works() {
    if !corpus_ready(PY_CORPUS) {
        eprintln!(
            "[skip] python_deps_still_works: corpus {} not present",
            PY_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", PY_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on flask; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();

    let total_edges: usize = internal
        .values()
        .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
        .sum();

    // Baseline at the time of writing: flask reports 183 internal edges
    // across 83 files. Use a conservative floor that catches a regression
    // (e.g. ts/python resolver being broken by an over-broad change).
    assert!(
        total_edges >= 50,
        "python deps non-regression: flask must still produce \
         >= 50 internal edges; got {} (was 183 at fix time)",
        total_edges
    );
}
