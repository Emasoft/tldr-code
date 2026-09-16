//! review-followup-v1 — regression tests for 6 concerns surfaced by the
//! final review pass on milestones M4 (cross-command-consistency-v3) and
//! M10 (real-repo-fixes-v1):
//!
//! - Concern 1 (CRITICAL): `detect_class_changes` upgraded to multi-value
//!   index + best-of pairing so files with duplicate class names (nested
//!   Python `Config`, Kotlin / C# inner types, etc.) self-diff to identical.
//! - Concern 2: cpp inheritance no longer emits ghost macro-name nodes
//!   (`TINYXML2_LIB`, etc.) when recovering the macro-prefixed misparse.
//! - Concern 3 (rule violation): `#[allow(dead_code)]` on
//!   `_unused_run_tldr_json` removed; function deleted.
//! - Concern 4: `deep_collect` recursion guarded by `MAX_DEEP_WALK_DEPTH`.
//! - Concern 5: 3 M4 tests gained synthetic TempDir fallbacks so they no
//!   longer no-op without `/tmp/repos`.
//! - Concern 6: `extract_helper_line` walks `.definitions[]` so post-M4
//!   schema-cleanup-v1 fixtures get real line numbers (not the line=2
//!   fallback).
//!
//! Concerns 3, 4, and 6 are internal — covered by the existing test
//! suites continuing to pass GREEN. Concerns 1, 2, and 5 have direct
//! `#[test]` entries below.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr <args> --format json -q` and parse stdout as JSON.
fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd()
        .args(args)
        .args(["--format", "json", "-q"])
        .output()
        .unwrap_or_else(|e| panic!("spawn {:?}: {}", args, e));
    assert!(
        out.status.success(),
        "tldr {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} JSON parse failed: {}\nstdout={}",
            args,
            e,
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

// ============================================================================
// Concern 1: detect_class_changes — duplicate class names self-diff identical
// ============================================================================

/// `tldr diff <file> <file>` on a Python file with two classes of the
/// same name (`Config` at module top-level and `Config` nested inside a
/// container class) must report `identical: true, total_changes: 0`.
///
/// Before the upgrade, `detect_class_changes`'s `HashMap<&str, &ClassNode>`
/// kept only the LAST `Config` class per name, so the first `Config` was
/// always reported as missing-from-B and the second as inserted-into-A.
#[test]
fn test_concern1_class_self_diff_with_duplicate_classes() {
    let tmp = TempDir::new().expect("tempdir");
    let py_path = tmp.path().join("dup_classes.py");
    let src = r#"
class Config:
    debug = False
    timeout = 30

    def reset(self):
        self.debug = False


class Outer:
    class Config:
        verbose = True
        retries = 3

        def step(self):
            return self.retries

    def use(self):
        return self.Config()


class Other:
    class Config:
        mode = "fast"

    def show(self):
        return self.Config.mode
"#;
    std::fs::write(&py_path, src).expect("write dup_classes.py");

    let path_str = py_path.to_str().unwrap();
    let v = run_json(&["diff", path_str, path_str]);
    let identical = v.get("identical").and_then(Value::as_bool).unwrap_or(false);
    let total = v
        .get("summary")
        .and_then(|s| s.get("total_changes"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    assert!(
        identical && total == 0,
        "self-diff on duplicate-class python should be identical/0 changes, \
         got identical={} total={}; output={}",
        identical,
        total,
        serde_json::to_string(&v).unwrap_or_default()
    );
}

// ============================================================================
// Concern 2: cpp inheritance — no macro-name ghost nodes
// ============================================================================

/// After recovering `class TINYXML2_LIB Foo : public Bar { ... };` from
/// the tree-sitter-cpp misparse, the walker must NOT also emit the macro
/// token (`TINYXML2_LIB`) as a phantom inheritance node. Asserts that no
/// node with an all-uppercase macro-style name appears in the output.
#[test]
fn test_concern2_no_macro_ghost_nodes_in_cpp_inheritance() {
    let tmp = TempDir::new().expect("tempdir");
    let cpp_path = tmp.path().join("base.cpp");
    let h_path = tmp.path().join("ghost.h");
    // Sibling .cpp triggers cpp autodetect for the .h via from_path_with_siblings.
    std::fs::write(
        &cpp_path,
        "#include \"ghost.h\"\nclass Bar { public: virtual ~Bar() {} };\n",
    )
    .expect("write base.cpp");
    std::fs::write(
        &h_path,
        "class Bar;\nclass TINYXML2_LIB Foo : public Bar {\npublic:\n    void method();\n};\n",
    )
    .expect("write ghost.h");

    // Run inheritance over the tempdir, not just one file, so the
    // module's per-file dispatch path is exercised.
    let v = run_json(&["inheritance", tmp.path().to_str().unwrap()]);
    let nodes = v
        .get("nodes")
        .and_then(Value::as_array)
        .expect("inheritance: missing /nodes");

    let macro_like: Vec<String> = nodes
        .iter()
        .filter_map(|n| n.get("name").and_then(Value::as_str).map(|s| s.to_string()))
        .filter(|name| {
            // All-uppercase / underscore / digit token, len >= 2 — the
            // shape of `TINYXML2_LIB`, `BOOST_API`, `FOLLY_EXPORT`.
            !name.is_empty()
                && name.len() >= 2
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                && name.chars().any(|c| c.is_ascii_uppercase())
        })
        .collect();

    assert!(
        macro_like.is_empty(),
        "expected zero macro-name ghost nodes, found {:?}; full nodes: {:?}",
        macro_like,
        nodes
    );

    // Also assert the real class name `Foo` IS present — the recovery
    // path remains functional.
    let has_foo = nodes
        .iter()
        .any(|n| n.get("name").and_then(Value::as_str) == Some("Foo"));
    assert!(
        has_foo,
        "expected Foo node from macro-prefixed class recovery; got: {:?}",
        nodes
    );
}

// ============================================================================
// Concern 5: 3 M4 tests now have synthetic fallbacks (mirror tests here)
// ============================================================================

/// `tldr extract` on a synthetic foo.h (sibling foo.cpp present) must
/// autodetect cpp via `from_path_with_siblings`. Mirrors the synthetic
/// half of `test_n1_extract_cpp_h_uses_cpp_parser` in
/// `cross_command_consistency_v3.rs`.
#[test]
fn test_concern5_n1_extract_h_synthetic_fallback() {
    let tmp = TempDir::new().expect("tempdir");
    let cpp_path = tmp.path().join("foo.cpp");
    let h_path = tmp.path().join("foo.h");
    std::fs::write(&cpp_path, "class Foo {};\n").expect("write foo.cpp");
    std::fs::write(&h_path, "class Bar {\npublic:\n    void method();\n};\n").expect("write foo.h");

    let v = run_json(&["extract", h_path.to_str().unwrap()]);
    let lang = v
        .get("language")
        .and_then(Value::as_str)
        .expect("extract: missing /language");
    assert_eq!(
        lang, "cpp",
        "synthetic foo.h next to foo.cpp must autodetect cpp, got {:?}",
        lang
    );
    let class_count = v
        .get("classes")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        class_count >= 1,
        "synthetic foo.h: expected >= 1 class, got {}; classes={:?}",
        class_count,
        v.get("classes")
    );
}

/// `tldr extract --lang cpp bar.h` must report language=cpp regardless
/// of extension-based default, even without sibling `.cpp`. Mirrors the
/// synthetic half of `test_n1_extract_lang_flag_honored`.
#[test]
fn test_concern5_n1_extract_lang_flag_synthetic() {
    let tmp = TempDir::new().expect("tempdir");
    let h_path = tmp.path().join("bar.h");
    std::fs::write(&h_path, "class Bar {\npublic:\n    void method();\n};\n").expect("write bar.h");

    let v = run_json(&["extract", "--lang", "cpp", h_path.to_str().unwrap()]);
    let lang = v
        .get("language")
        .and_then(Value::as_str)
        .expect("extract --lang: missing /language");
    assert_eq!(
        lang, "cpp",
        "synthetic bar.h with --lang cpp must report cpp, got {:?}",
        lang
    );
}

/// `tldr complexity` and `tldr explain` must agree on cyclomatic for a
/// Python function with KNOWN branches. Mirrors the synthetic half of
/// `test_n2_cyclomatic_complexity_explain_agree`.
#[test]
fn test_concern5_n2_complexity_explain_agree_synthetic() {
    let tmp = TempDir::new().expect("tempdir");
    let py_path = tmp.path().join("synth_branchy.py");
    let src = r#"
def branchy(x, y):
    if x > 0:
        if y > 0:
            return 1
        elif y < 0:
            return 2
        else:
            return 3
    elif x < 0:
        if y > 0 and x < -1:
            return 4
        return 5
    else:
        return 6
"#;
    std::fs::write(&py_path, src).expect("write synth_branchy.py");

    let path_str = py_path.to_str().unwrap();
    let cmplx = run_json(&["complexity", path_str, "branchy"]);
    let cmplx_cyc = cmplx
        .get("cyclomatic")
        .and_then(Value::as_u64)
        .expect("synthetic complexity: missing cyclomatic");
    let expl = run_json(&["explain", path_str, "branchy"]);
    let expl_cyc = expl
        .pointer("/complexity/cyclomatic")
        .and_then(Value::as_u64)
        .expect("synthetic explain: missing /complexity/cyclomatic");
    assert_eq!(
        cmplx_cyc, expl_cyc,
        "synthetic branchy: cyclomatic mismatch complexity={} explain={}",
        cmplx_cyc, expl_cyc
    );
    // Sanity: a function with this many decision points should have a
    // non-trivial cyclomatic count.
    assert!(
        cmplx_cyc >= 5,
        "synthetic branchy: cyclomatic={} unexpectedly low",
        cmplx_cyc
    );
}
