//! clones-determinism-v1 (v0.5.0 FIX-CLONES-DET) — clone GROUP / class
//! ordering nondeterminism regression test.
//!
//! BACKGROUND
//! ----------
//! The Tier-0 BUG-2 fix (`determinism_and_stderr_hygiene_v1`) imposed a
//! total order on `clone_pairs[]` before id assignment, so the *pairs*
//! array is byte-stable. But a residual nondeterminism source remained in
//! the clone-CLASS pipeline (`--show-classes`):
//!
//!   `compute_clone_classes_v2` walked `UnionFind::components()`, which
//!   returns a `HashMap<usize, Vec<usize>>`. serde / a plain `for (_root,
//!   members) in components` loop visits that map in DefaultHasher
//!   iteration order (randomized per-process), so:
//!     - the ORDER of `clone_classes[]` shuffled run-to-run,
//!     - the sequential `id` assigned to each class shuffled with it,
//!     - the per-class `fragments[]` member order followed the
//!       component's index list, which — while index-ordered — was keyed
//!       off the same unstable component walk for class membership.
//!
//!   The same set of classes was found every run, but the serialized
//!   `clone_classes[]` (and every class `id`) reshuffled, breaking
//!   byte-diff gates and any downstream tooling that hashes the report.
//!
//! THE FIX
//! -------
//! Impose a deterministic TOTAL ORDER on clone groups and on members
//! within each group at the emission boundary — by file path, then start
//! line, then length (end_line − start_line) — preserving clone-detection
//! semantics (same classes, same membership, just a stable order).
//!
//! THIS TEST
//! ---------
//! Runs `tldr clones --show-classes` THREE times on a corpus that contains
//! duplicated code (`/tmp/repos/typescript-nest`, whose integration test
//! tree has many verbatim `users.service.ts` copies → multi-member clone
//! classes) and asserts FULL byte-identical JSON across runs — class order,
//! class ids, and member order included — after stripping inherently
//! variable wall-clock timing. It also asserts at least one clone pair and
//! at least one multi-member clone class, so the determinism-affected code
//! path is actually exercised (not a no-op empty comparison).
//!
//! The test is skipped (with a loud eprintln) only if the corpus is not
//! present, so it never silently passes on a machine without corpora.

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
use std::path::PathBuf;

fn nest_corpus() -> PathBuf {
    PathBuf::from("/tmp/repos/typescript-nest")
}

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Recursively remove wall-clock timing keys anywhere in the JSON tree.
/// Timing is inherently variable and never claimed byte-stable; stripping
/// it lets the comparison capture CONTENT (ordering) determinism only.
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

/// Run `tldr clones --show-classes <dir>` and parse stdout as JSON with
/// timing stripped. The serde_json build uses `preserve_order`, so
/// re-serializing the parsed `Value` reproduces the producer's exact
/// map-key AND array-element order — exactly what we want to diff.
fn run_clones_classes(dir: &str) -> Value {
    let output = tldr_cmd()
        .arg("clones")
        .arg(dir)
        .arg("--show-classes")
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("invoke tldr clones --show-classes");
    assert!(
        output.status.success(),
        "tldr clones failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("clones stdout not JSON: {e}\n{stdout}"));
    strip_timing(&mut v);
    v
}

#[test]
fn clones_classes_output_is_byte_stable() {
    let corpus = nest_corpus();
    if !corpus_ready(&corpus) {
        eprintln!(
            "SKIP clones_classes_output_is_byte_stable: corpus {} not present; \
             determinism test requires a corpus with duplicate code",
            corpus.display()
        );
        return;
    }
    let dir = corpus.to_string_lossy().into_owned();

    let r1 = run_clones_classes(&dir);
    let r2 = run_clones_classes(&dir);
    let r3 = run_clones_classes(&dir);

    let s1 = serde_json::to_string(&r1).unwrap();
    let s2 = serde_json::to_string(&r2).unwrap();
    let s3 = serde_json::to_string(&r3).unwrap();

    assert_eq!(
        s1, s2,
        "clones --show-classes run #1 vs #2 differs (clone-class ordering non-determinism?)"
    );
    assert_eq!(
        s2, s3,
        "clones --show-classes run #2 vs #3 differs (clone-class ordering non-determinism?)"
    );

    // Sanity: the corpus must produce at least one clone pair so the
    // determinism-affected pairs path is exercised.
    let pairs = r1
        .get("clone_pairs")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        pairs >= 1,
        "corpus should produce at least one clone pair; got {pairs}",
    );

    // Sanity: the corpus must produce at least one MULTI-MEMBER clone class,
    // i.e. the class pipeline (the determinism-affected code path) actually
    // ran with non-trivial grouping.
    let classes = r1
        .get("clone_classes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !classes.is_empty(),
        "corpus should produce at least one clone class; got 0",
    );
    let multi_member = classes.iter().any(|c| {
        c.get("fragments")
            .and_then(|f| f.as_array())
            .map(|a| a.len() >= 2)
            .unwrap_or(false)
    });
    assert!(
        multi_member,
        "corpus should produce at least one clone class with >= 2 members",
    );
}

/// Assert that, within each emitted clone class, the `fragments[]` are in
/// the deterministic total order: (file path, start_line, length). This
/// guards the *member* ordering independently of the class ordering, so a
/// regression that only re-stabilizes class order (but not member order)
/// is still caught.
#[test]
fn clones_class_members_are_totally_ordered() {
    let corpus = nest_corpus();
    if !corpus_ready(&corpus) {
        eprintln!(
            "SKIP clones_class_members_are_totally_ordered: corpus {} not present",
            corpus.display()
        );
        return;
    }
    let dir = corpus.to_string_lossy().into_owned();
    let r = run_clones_classes(&dir);

    let classes = r
        .get("clone_classes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!classes.is_empty(), "expected at least one clone class");

    for (ci, class) in classes.iter().enumerate() {
        let frags = class
            .get("fragments")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default();
        let keys: Vec<(String, u64, u64)> = frags
            .iter()
            .map(|f| {
                let file = f
                    .get("file")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let start = f.get("start_line").and_then(|x| x.as_u64()).unwrap_or(0);
                let end = f.get("end_line").and_then(|x| x.as_u64()).unwrap_or(0);
                let len = end.saturating_sub(start);
                (file, start, len)
            })
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "class #{ci} members are not in (file, start_line, length) order: {keys:?}",
        );
    }
}
