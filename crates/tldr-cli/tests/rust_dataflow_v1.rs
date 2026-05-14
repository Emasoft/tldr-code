//! rust-dataflow-v1 (v0.4.2 bug-C2 / VAL-RUST-DFG)
//!
//! Pre-fix: `tldr reaching-defs <rust-file> <fn>` returns blocks with empty
//! gen/kill/in/out for every block, and `definitions: 0` in stats — even
//! when the function clearly contains many bindings (`let Some(c) = ...`,
//! `while let ... = ...`, `if let ... = ...`, `let Ok(v) = ... else { ... };`).
//! Root cause: the rust DFG extractor (`crates/tldr-core/src/dfg/extractor.rs`
//! `process_rust_let` + the `extract_refs_from_node` dispatch) only recognised
//! three pattern kinds (`identifier`, `mut_pattern`, `tuple_pattern`). Real
//! rust code overwhelmingly uses `tuple_struct_pattern` (`Some(c)`, `Ok(v)`,
//! `Err(e)`, …) as the let binding, and the pattern-with-`else` (let-else
//! 2024) plus the `let_condition` AST node used inside `while let` / `if let`
//! were not dispatched at all. As a result, no rust definitions were emitted,
//! the reaching-defs `gen` set was empty for every block, every variable use
//! came back flagged uninitialized, and `available` (which subtracts the kill
//! set from candidate expressions) lost most of its precision — collapsing
//! both C2 (reaching-defs gen/kill empty) and C3 (`available` confidence
//! always `low`) onto the same root cause.
//!
//! Post-fix: `process_rust_let` recognises `tuple_struct_pattern`,
//! `ref_pattern`, `reference_pattern` (plain `&x` / `&mut x`) and nested
//! tuple-struct / `or_pattern` bindings; `extract_refs_from_node` dispatches
//! `let_condition` to the same handler (so `while let Some(c) = ...` and
//! `if let Some(start) = ...` register `c` and `start` as `Definition`s).
//! Reaching-defs `gen` is non-empty for blocks that contain such bindings,
//! and `definitions > 0` agrees with the bindings the source actually has.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early
//! when its `/tmp/repos/<repo>` corpus is absent.

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

const RUST_GLOB_FILE: &str = "/tmp/repos/ripgrep/crates/globset/src/glob.rs";
const PY_FLASK_FILE: &str = "/tmp/repos/flask/src/flask/app.py";

// ============================================================================
// TEST 1 (primary C2): rust reaching-defs must emit non-empty gen OR kill
//                       for at least one block on a real rust function whose
//                       body uses `while let Some(c) = self.bump()` plus
//                       several `let _ = ...` bindings. Pre-fix: 47 blocks,
//                       all empty. Post-fix: stats.definitions > 0 and at
//                       least one block has |gen| > 0.
// ============================================================================
#[test]
fn rust_reaching_defs_non_empty_gen_kill() {
    if !Path::new(RUST_GLOB_FILE).exists() {
        eprintln!(
            "[skip] rust_reaching_defs_non_empty_gen_kill: corpus {} not present",
            RUST_GLOB_FILE
        );
        return;
    }

    let (rc, out) = run_tldr(&[
        "reaching-defs",
        RUST_GLOB_FILE,
        "parse",
        "--format",
        "json",
    ]);
    assert_eq!(
        rc, 0,
        "reaching-defs must succeed on ripgrep::globset::glob::Parser::parse; got rc={}",
        rc
    );

    let v = parse_json(&out);

    // stats.definitions: pre-fix 0, post-fix > 0
    let defs = v["stats"]["definitions"].as_u64().unwrap_or(0);
    assert!(
        defs > 0,
        "rust reaching-defs must emit at least one Definition for Parser::parse \
         (pre-fix bug-C2: rust DFG extractor ignored tuple_struct_pattern and \
         let_condition, so `while let Some(c) = self.bump()` registered no \
         binding). Got stats.definitions = {}",
        defs
    );

    // At least one block has |gen| > 0 OR |kill| > 0. Pre-fix every block
    // was empty across all four sets.
    let blocks = v["blocks"].as_array().cloned().unwrap_or_default();
    assert!(
        !blocks.is_empty(),
        "rust reaching-defs must emit blocks; got 0"
    );

    let nonzero_gen_or_kill = blocks
        .iter()
        .filter(|b| {
            let g = b["gen"].as_array().map(|a| a.len()).unwrap_or(0);
            let k = b["kill"].as_array().map(|a| a.len()).unwrap_or(0);
            g > 0 || k > 0
        })
        .count();

    assert!(
        nonzero_gen_or_kill > 0,
        "at least one block must have non-empty gen or kill for Parser::parse; \
         got 0 across {} blocks (pre-fix VAL-RUST-DFG / C2: all gen=kill=in=out=[] \
         because rust DFG extractor emitted zero Definition refs).",
        blocks.len()
    );
}

// ============================================================================
// TEST 2 (primary C3 — corrected semantics): rust `available` analysis must
//   produce a result whose `function` metadata field is non-null and matches
//   the function name passed on the CLI, regardless of whether any expressions
//   matched the scope filter.
//
//   The test name reflects the original audit assertion: the `function` field
//   in `tldr available` output must NOT be null when invoked with a valid
//   function name. The metadata about which function was analyzed must NOT
//   depend on whether expression extraction returned any binary expressions.
//
//   Post available-scope-filter-v1 (M-009): the strict per-function CFG-span
//   filter correctly rejects sibling-function leaks. On
//   ripgrep::globset::glob::Parser::parse — whose CFG-mapped body (lines
//   823-837) consists exclusively of `self.<method>()` calls and `match`
//   arms — there are zero clean binary expressions in scope, so
//   `all_exprs` is legitimately empty. The pre-M-009 result of 2 confirmed
//   expressions was the bug: both came from sibling functions
//   (`b <= 0x7F` at line 779 in `parse_class`, `1 + start` at line 488 in
//   another helper) that had been snapped onto the parse function's CFG
//   via the old nearest-block fallback.
//
//   The structural invariant guarded here is the one the test name asserts:
//   the output must always identify the function it analyzed.
// ============================================================================
#[test]
fn rust_available_function_name_not_null() {
    if !Path::new(RUST_GLOB_FILE).exists() {
        eprintln!(
            "[skip] rust_available_function_name_not_null: corpus {} not present",
            RUST_GLOB_FILE
        );
        return;
    }

    let (rc, out) = run_tldr(&["available", RUST_GLOB_FILE, "parse", "--format", "json"]);
    assert_eq!(
        rc, 0,
        "available must succeed on ripgrep::globset::glob::Parser::parse; got rc={}",
        rc
    );

    let v = parse_json(&out);

    // The JSON must be a top-level object (not null), with at least the
    // expected dataflow keys. This is the most literal form of the audit
    // assertion: the result must not be a null analysis.
    assert!(
        v.is_object(),
        "rust available must return an object; got: {:?}",
        v
    );
    assert!(
        v.get("avail_in").is_some(),
        "rust available result must contain avail_in (analysis must run, not bail)"
    );
    assert!(
        v.get("avail_out").is_some(),
        "rust available result must contain avail_out"
    );
    assert!(
        v.get("all_exprs").is_some(),
        "rust available result must contain all_exprs"
    );

    // Primary assertion (matches the test name): the `function` field must
    // be present AND non-null AND equal to the function name we passed on
    // the CLI. This invariant must hold even when expression extraction
    // returns zero binary expressions, because metadata identifying the
    // analyzed function is independent of whether the function happens to
    // contain analyzable expressions.
    let function_field = v.get("function");
    assert!(
        function_field.is_some(),
        "rust available result must contain a `function` field identifying \
         which function was analyzed; got top-level keys: {:?}",
        v.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    let function_field = function_field.unwrap();
    assert!(
        !function_field.is_null(),
        "rust available `function` field must NOT be null when invoked with \
         a valid function name; got null. This is the regression W-K guarded \
         against — the metadata identifying the analyzed function must not \
         depend on whether the scope filter yielded any expressions."
    );
    assert_eq!(
        function_field.as_str(),
        Some("parse"),
        "rust available `function` field must equal the function name passed \
         on the CLI (\"parse\"); got {:?}",
        function_field
    );
}

// ============================================================================
// TEST 3 (non-regression): python reaching-defs must keep emitting >0
//   definitions and >0 gen blocks on flask::app::make_response.
// ============================================================================
#[test]
fn python_reaching_defs_still_works() {
    if !Path::new(PY_FLASK_FILE).exists() {
        eprintln!(
            "[skip] python_reaching_defs_still_works: corpus {} not present",
            PY_FLASK_FILE
        );
        return;
    }

    let (rc, out) = run_tldr(&[
        "reaching-defs",
        PY_FLASK_FILE,
        "make_response",
        "--format",
        "json",
    ]);
    assert_eq!(
        rc, 0,
        "reaching-defs must succeed on flask::app::make_response; got rc={}",
        rc
    );

    let v = parse_json(&out);
    let defs = v["stats"]["definitions"].as_u64().unwrap_or(0);
    assert!(
        defs > 0,
        "python reaching-defs must still emit Definitions (non-reg); got 0"
    );

    let blocks = v["blocks"].as_array().cloned().unwrap_or_default();
    let nonzero_gen = blocks
        .iter()
        .filter(|b| b["gen"].as_array().map(|a| a.len()).unwrap_or(0) > 0)
        .count();
    assert!(
        nonzero_gen > 0,
        "python must keep emitting non-empty gen sets (non-reg); got 0 across {} blocks",
        blocks.len()
    );
}

// ============================================================================
// TEST 4 (non-regression): python `available` must keep returning a valid
//   analysis object with at least one extracted binary expression.
// ============================================================================
#[test]
fn python_available_still_works() {
    if !Path::new(PY_FLASK_FILE).exists() {
        eprintln!(
            "[skip] python_available_still_works: corpus {} not present",
            PY_FLASK_FILE
        );
        return;
    }

    let (rc, out) = run_tldr(&[
        "available",
        PY_FLASK_FILE,
        "make_response",
        "--format",
        "json",
    ]);
    assert_eq!(
        rc, 0,
        "available must succeed on flask::app::make_response; got rc={}",
        rc
    );

    let v = parse_json(&out);
    assert!(v.is_object(), "python available must return an object");
    let all_exprs = v["all_exprs"].as_array().cloned().unwrap_or_default();
    assert!(
        !all_exprs.is_empty(),
        "python available must keep extracting binary expressions (non-reg); got empty"
    );
}
