//! rust-explain-cognitive-v1 (v0.4.2 bug-C6 / VAL-RUST-EXPLAIN)
//!
//! The v0.4.2 audit's C6 finding asserted that
//! `tldr explain /tmp/repos/ripgrep/crates/globset/src/glob.rs parse`
//! reports `complexity.cognitive: null` while `tldr cognitive` on the
//! same file reports `cognitive=19` for the same `parse` function —
//! i.e. the explain aggregator wasn't propagating the cognitive metric
//! into its `complexity` block.
//!
//! Investigation (W-N) found:
//!
//! 1. The original claim is partially a measurement artifact: the
//!    `complexity.cognitive` field never existed in `ComplexityInfo`
//!    at all (neither for rust nor python), so `null` was the
//!    serde-skipped Option's natural appearance under jq probes that
//!    coalesce missing keys to null.
//!
//! 2. BUT the user-facing gap is real: `tldr explain` reports
//!    cyclomatic/num_blocks/num_edges/has_loops with no cognitive
//!    counterpart, despite `tldr cognitive` computing it from the
//!    same AST. The audit's underlying concern — that explain's
//!    complexity block is incomplete vs. the dedicated `tldr
//!    cognitive` command — is valid.
//!
//! W-N's fix wires cognitive into `ComplexityInfo.cognitive`
//! (additive Option<u32>) by calling `analyze_cognitive` filtered to
//! the requested function and joining the result. The field is
//! `#[serde(skip_serializing_if = "Option::is_none")]` so older
//! consumers that don't reference it see no behavior change. The
//! same wiring runs for every language `tldr cognitive` supports —
//! it's not a rust-specific code path — so python/java/etc. all
//! benefit too.
//!
//! Tests are real-repo gated per no-synthetic-fixtures-v1: each test
//! returns early when its `/tmp/repos/<repo>` corpus is absent.

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

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}; stdout was:\n{out}"))
}

const RUST_GLOB: &str = "/tmp/repos/ripgrep/crates/globset/src/glob.rs";
const PY_FLASK_APP: &str = "/tmp/repos/flask/src/flask/app.py";

// ============================================================================
// TEST 1: rust explain emits complexity.cognitive as a non-null number for a
//         function whose standalone `tldr cognitive` value is >0.
// ============================================================================
#[test]
fn rust_explain_complexity_cognitive_not_null() {
    if !Path::new(RUST_GLOB).exists() {
        eprintln!(
            "[skip] rust_explain_complexity_cognitive_not_null: corpus {} not present",
            RUST_GLOB
        );
        return;
    }
    let (rc, out, err) = run_tldr(&["explain", RUST_GLOB, "parse", "--format", "json"]);
    assert_eq!(
        rc, 0,
        "explain must succeed; rc={} stderr={}",
        rc, err
    );
    let v = parse_json(&out);
    let complexity = v
        .get("complexity")
        .unwrap_or_else(|| panic!("explain: missing `complexity`; got {v}"));
    let cog = complexity
        .get("cognitive")
        .unwrap_or_else(|| panic!(
            "VAL-RUST-EXPLAIN: explain.complexity.cognitive key absent for rust. \
             Got complexity={complexity}"
        ));
    assert!(
        !cog.is_null(),
        "VAL-RUST-EXPLAIN: explain.complexity.cognitive is null for rust glob.rs::parse. \
         Got complexity={complexity}"
    );
    let n = cog.as_u64().unwrap_or_else(|| {
        panic!(
            "VAL-RUST-EXPLAIN: explain.complexity.cognitive must be a non-negative integer; got {cog}"
        )
    });
    // The standalone `tldr cognitive` reports 19 for parse on globset/glob.rs.
    // Anchor to >0 rather than exact value: a separate test pins agreement.
    assert!(
        n > 0,
        "VAL-RUST-EXPLAIN: cognitive=0 for a function that `tldr cognitive` flags as a \
         severity violation is suspicious. Got cognitive={n}"
    );
}

// ============================================================================
// TEST 2: rust explain's complexity.cognitive agrees with standalone
//         `tldr cognitive` on the same file/function.
// ============================================================================
#[test]
fn rust_explain_cognitive_matches_standalone() {
    if !Path::new(RUST_GLOB).exists() {
        eprintln!(
            "[skip] rust_explain_cognitive_matches_standalone: corpus {} not present",
            RUST_GLOB
        );
        return;
    }

    // 1. Get the canonical cognitive value from the dedicated command.
    let (rc, cog_out, err) = run_tldr(&["cognitive", RUST_GLOB, "--format", "json"]);
    assert_eq!(rc, 0, "cognitive must succeed; rc={} stderr={}", rc, err);
    let cog_v = parse_json(&cog_out);
    let funcs = cog_v
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("cognitive: missing `functions`; got {cog_v}"));
    let parse_entry = funcs
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("parse"))
        .unwrap_or_else(|| panic!("cognitive: no `parse` entry in functions: {funcs:?}"));
    let standalone_cog = parse_entry
        .get("cognitive")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!("cognitive: parse entry missing cognitive: {parse_entry}"));

    // 2. Get the explain pipeline's value.
    let (rc, ex_out, err) = run_tldr(&["explain", RUST_GLOB, "parse", "--format", "json"]);
    assert_eq!(rc, 0, "explain must succeed; rc={} stderr={}", rc, err);
    let ex_v = parse_json(&ex_out);
    let explain_cog = ex_v
        .pointer("/complexity/cognitive")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!(
            "VAL-RUST-EXPLAIN: explain.complexity.cognitive absent or non-u64; got {ex_v}"
        ));

    assert_eq!(
        explain_cog, standalone_cog,
        "VAL-RUST-EXPLAIN: explain.complexity.cognitive ({}) must equal standalone \
         `tldr cognitive` ({}) for the same function. Both use the same SonarSource \
         algorithm — divergence means explain is not delegating correctly.",
        explain_cog, standalone_cog
    );
}

// ============================================================================
// TEST 3 (non-regression): python explain.complexity.cognitive is also wired
//         and agrees with standalone cognitive. The fix is language-agnostic,
//         so python must not regress.
// ============================================================================
#[test]
fn python_explain_cognitive_still_works() {
    if !Path::new(PY_FLASK_APP).exists() {
        eprintln!(
            "[skip] python_explain_cognitive_still_works: corpus {} not present",
            PY_FLASK_APP
        );
        return;
    }

    let (rc, cog_out, err) = run_tldr(&["cognitive", PY_FLASK_APP, "--format", "json"]);
    assert_eq!(rc, 0, "cognitive must succeed; rc={} stderr={}", rc, err);
    let cog_v = parse_json(&cog_out);
    let funcs = cog_v
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("cognitive: missing functions; got {cog_v}"));
    let target = funcs
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("make_response"))
        .unwrap_or_else(|| panic!("cognitive: no make_response entry: {funcs:?}"));
    let standalone_cog = target
        .get("cognitive")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!("cognitive: make_response missing cognitive: {target}"));

    let (rc, ex_out, err) =
        run_tldr(&["explain", PY_FLASK_APP, "make_response", "--format", "json"]);
    assert_eq!(rc, 0, "explain must succeed; rc={} stderr={}", rc, err);
    let ex_v = parse_json(&ex_out);
    let explain_cog = ex_v
        .pointer("/complexity/cognitive")
        .and_then(|c| c.as_u64())
        .unwrap_or_else(|| panic!(
            "python explain.complexity.cognitive missing — regression of the rust fix. Got {ex_v}"
        ));

    assert_eq!(
        explain_cog, standalone_cog,
        "non-regression: python explain.complexity.cognitive ({}) must equal standalone \
         cognitive ({}) — the wiring is language-agnostic.",
        explain_cog, standalone_cog
    );
}
