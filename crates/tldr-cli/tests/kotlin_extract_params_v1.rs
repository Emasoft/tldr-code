//! kotlin-extract-params-v1 (v0.4.2 bug-B4 / VAL-KT-EXTRACT / CF-KT-01)
//!
//! Pre-fix: `tldr extract` and `tldr explain` on any kotlin file emit
//! `params: []` for every function despite the source clearly declaring
//! parameters. Root cause: `extract_kotlin_params` and the explain-side
//! signature extractor were written against an older grammar where each
//! parameter's child was a `simple_identifier` and the params node hung
//! off a `parameters` field. The tree-sitter-kotlin-ng 1.1.0 grammar in
//! use today represents:
//!   * parameter container as the named child `function_value_parameters`
//!     (NOT a field)
//!   * each `parameter` child contains a plain `identifier`, not a
//!     `simple_identifier`
//!
//! Result: both lookups (`child_by_field_name("parameters")` and the
//! `simple_identifier` walk) silently miss every param.
//!
//! Post-fix:
//!   1. `extract_kotlin_params` also accepts `identifier` (new grammar)
//!      alongside the old `simple_identifier` (back-compat).
//!   2. `explain`'s signature extractor falls back to walking
//!      `function_value_parameters` for kotlin function_declaration
//!      nodes when no `parameters` field is present.
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

const KT_INSTANT: &str = "/tmp/repos/kotlin-datetime/core/common/src/Instant.kt";
const RUST_CORPUS: &str = "/tmp/repos/ripgrep";

// ============================================================================
// TEST 1: `tldr extract <kotlin-file>` must populate the params array for
//         at least one function. Pre-fix: every function has params=[].
// ============================================================================
#[test]
fn kotlin_extract_populates_params_array() {
    if !Path::new(KT_INSTANT).exists() {
        eprintln!(
            "[skip] kotlin_extract_populates_params_array: corpus {} not present",
            KT_INSTANT
        );
        return;
    }

    let (rc, out) = run_tldr(&["extract", KT_INSTANT]);
    assert_eq!(rc, 0, "extract must succeed on Instant.kt; got rc={}", rc);

    let v = parse_json(&out);
    let funcs = v["functions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !funcs.is_empty(),
        "extract must find at least one function in Instant.kt; got 0"
    );

    let with_params = funcs
        .iter()
        .filter(|f| {
            f["params"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .count();

    assert!(
        with_params > 0,
        "at least one function in Instant.kt must have params populated; \
         got {} functions all with params=[] (pre-fix bug VAL-KT-EXTRACT: \
         tree-sitter-kotlin-ng grammar uses `identifier` not `simple_identifier`)",
        funcs.len()
    );
}

// ============================================================================
// TEST 2: extracted param names must match what's in the source signature.
//         Specifically the well-known `Instant.plus(period, timeZone)`.
// ============================================================================
#[test]
fn kotlin_extract_param_names_match_signature() {
    if !Path::new(KT_INSTANT).exists() {
        eprintln!(
            "[skip] kotlin_extract_param_names_match_signature: corpus {} not present",
            KT_INSTANT
        );
        return;
    }

    let (rc, out) = run_tldr(&["extract", KT_INSTANT]);
    assert_eq!(rc, 0, "extract must succeed; got rc={}", rc);

    let v = parse_json(&out);
    let funcs = v["functions"].as_array().cloned().unwrap_or_default();

    // Find the first `plus` overload at line 66 — signature is
    // `(period: DateTimePeriod, timeZone: TimeZone)`
    let plus = funcs
        .iter()
        .find(|f| f["name"].as_str() == Some("plus") && f["line"].as_u64() == Some(66))
        .cloned()
        .expect("Instant.kt must contain `plus` at line 66 with the known signature");

    let params = plus["params"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = params
        .iter()
        .filter_map(|p| p.as_str().map(|s| s.to_string()))
        .collect();

    assert!(
        names.contains(&"period".to_string()),
        "plus(line 66) params must include `period`; got {:?}",
        names
    );
    assert!(
        names.contains(&"timeZone".to_string()),
        "plus(line 66) params must include `timeZone`; got {:?}",
        names
    );
}

// ============================================================================
// TEST 3: `tldr explain <kotlin-file> <func>` must also surface params.
// ============================================================================
#[test]
fn kotlin_explain_passes_params_through() {
    if !Path::new(KT_INSTANT).exists() {
        eprintln!(
            "[skip] kotlin_explain_passes_params_through: corpus {} not present",
            KT_INSTANT
        );
        return;
    }

    let (rc, out) = run_tldr(&["explain", KT_INSTANT, "plus"]);
    assert_eq!(rc, 0, "explain must succeed on Instant.kt::plus; got rc={}", rc);

    let v = parse_json(&out);
    let params = v["signature"]["params"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    assert!(
        !params.is_empty(),
        "explain Instant.kt::plus must populate signature.params; got [] \
         (pre-fix: explain uses child_by_field_name(\"parameters\") which \
         does not exist on kotlin function_declaration nodes)"
    );

    // At least one param has a non-empty name
    let any_named = params.iter().any(|p| {
        p["name"]
            .as_str()
            .map(|n| !n.is_empty())
            .unwrap_or(false)
    });
    assert!(
        any_named,
        "explain signature.params entries must include a name; got {:?}",
        params
    );
}

// ============================================================================
// TEST 4 (non-regression): rust extract must continue to populate params.
// ============================================================================
#[test]
fn rust_extract_params_still_populated() {
    if !Path::new(RUST_CORPUS).exists() {
        eprintln!(
            "[skip] rust_extract_params_still_populated: corpus {} not present",
            RUST_CORPUS
        );
        return;
    }

    // Pick a known rust file with parameterised functions.
    // ripgrep's `crates/core/main.rs` has plenty.
    let candidates = [
        "/tmp/repos/ripgrep/crates/core/main.rs",
        "/tmp/repos/ripgrep/crates/core/flags/parse.rs",
        "/tmp/repos/ripgrep/crates/printer/src/standard.rs",
    ];
    let target = candidates
        .iter()
        .find(|p| Path::new(p).exists())
        .copied()
        .expect("at least one ripgrep rust source file must exist");

    let (rc, out) = run_tldr(&["extract", target]);
    assert_eq!(rc, 0, "extract must succeed on {}; got rc={}", target, rc);

    let v = parse_json(&out);
    let funcs = v["functions"].as_array().cloned().unwrap_or_default();
    assert!(
        !funcs.is_empty(),
        "extract must find functions in {}; got 0",
        target
    );

    let with_params = funcs
        .iter()
        .filter(|f| {
            f["params"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .count();

    assert!(
        with_params > 0,
        "non-regression: rust extract must still populate params for at \
         least one function in {}; got {} functions all with params=[]",
        target,
        funcs.len()
    );
}
