//! chop-forward-backward-intersect-v1 (v0.4.2 M-034)
//!
//! Tests that `tldr chop` returns the intersection of forward(source) and
//! backward(target) slices **constrained to the user-requested interval**
//! `[min(source, target), max(source, target)]`.
//!
//! # Bug
//!
//! Prior to this fix, `chop` returned essentially the full backward slice
//! from target_line (extending beyond target_line, and including all lines
//! the source line could affect — which for many functions is "every line").
//!
//! Per-cluster audit examples (Phase 22 audit/iteration1/aggregated_clusters.md):
//! - typescript (c15): `chop emitWebIdl 150 250` returned 1832 lines spanning
//!   149..1980 (full backward slice — function is 137..1980)
//! - kotlin (c15): `chop periodUntil 122 138` returned 19 lines (121..139) —
//!   full function interval
//! - ruby (c37): `chop scrub 66 78` returned 14 lines (66..79) — full body
//! - swift (c15): `chop _heapify 379 386` returned 13 lines (377..389) —
//!   extends 2 before source and 3 after target
//! - javascript (c15): `chop render 523 574` returned 50 lines (522..575) —
//!   extends past target
//!
//! # Fix
//!
//! After applying `forward(source) ∩ backward(target)`, also clip the
//! resulting line set to the closed interval
//! `[min(source_line, target_line), max(source_line, target_line)]`. This
//! filters out lines lexically outside the user-requested range, which
//! includes function signature lines and trailing brace/return lines that
//! the PDG attaches to neighbouring nodes.
//!
//! # Invariants
//!
//! For every chop(source, target) with path_exists=true:
//! 1. All `lines[i] >= min(source, target)`
//! 2. All `lines[i] <= max(source, target)`
//! 3. `source_line` is in `lines`
//! 4. `target_line` is in `lines`
//! 5. `count == lines.len()`

use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Helper to run `tldr chop <file> <fn> <src> <tgt>` and parse the JSON output.
fn run_chop(file: &str, function: &str, source_line: u32, target_line: u32) -> serde_json::Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "chop",
            file,
            function,
            &source_line.to_string(),
            &target_line.to_string(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr chop");

    assert!(
        output.status.success(),
        "chop should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "chop output not valid JSON: {}\nstdout: {}",
            e, stdout
        )
    })
}

/// Returns the `lines` array as Vec<u32>.
fn lines_of(v: &serde_json::Value) -> Vec<u32> {
    v["lines"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect()
}

/// Assert that every line in the chop result is within the closed interval
/// `[min(src, tgt), max(src, tgt)]` and that both endpoints are present
/// when path_exists=true.
fn assert_chop_within_interval(
    result: &serde_json::Value,
    source_line: u32,
    target_line: u32,
    lang_label: &str,
) {
    let path_exists = result["path_exists"].as_bool().unwrap_or(false);
    if !path_exists {
        // No path → nothing to assert about bounds, but lines must be empty.
        let lines = lines_of(result);
        assert!(
            lines.is_empty(),
            "{}: path_exists=false but lines is non-empty: {:?}",
            lang_label,
            lines
        );
        return;
    }

    let lines = lines_of(result);
    let lo = source_line.min(target_line);
    let hi = source_line.max(target_line);

    assert!(
        !lines.is_empty(),
        "{}: path_exists=true but lines is empty",
        lang_label
    );

    for &l in &lines {
        assert!(
            l >= lo,
            "{}: chop line {} is BEFORE source/target interval [{}, {}]",
            lang_label,
            l,
            lo,
            hi
        );
        assert!(
            l <= hi,
            "{}: chop line {} is AFTER source/target interval [{}, {}]",
            lang_label,
            l,
            lo,
            hi
        );
    }

    assert!(
        lines.contains(&source_line),
        "{}: chop result must include source_line {}; got {:?}",
        lang_label,
        source_line,
        lines
    );
    assert!(
        lines.contains(&target_line),
        "{}: chop result must include target_line {}; got {:?}",
        lang_label,
        target_line,
        lines
    );

    // count field consistency
    let count = result["count"].as_u64().unwrap_or(0) as usize;
    assert_eq!(
        count,
        lines.len(),
        "{}: count field {} != lines.len() {}",
        lang_label,
        count,
        lines.len()
    );
}

/// Build a TS fixture mirroring the audit ts c15 pattern: long function
/// with one accumulator variable threaded through every statement (so the
/// raw PDG slices are huge), with a small user-requested interval.
fn create_ts_emitter_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    // Function emit() spans many lines. The accumulator `out` is read/written
    // on every line — so forward(source) and backward(target) are both huge
    // and intersect to "everything". Without an interval filter, chop returns
    // far more lines than [source, target].
    let mut body = String::from("function emit(input: string): string {\n");
    body.push_str("  let out = input;\n"); // line 2
    for i in 3..=40 {
        body.push_str(&format!("  out = out + \"{}\";\n", i));
    }
    body.push_str("  return out;\n"); // line 41
    body.push_str("}\n");
    fs::write(dir.path().join("emit.ts"), body).unwrap();
    dir
}

/// Build a Python fixture exercising a small chop interval inside a long
/// linear data-flow chain. Used to assert interval-clipping in a language
/// the slice infrastructure already handles well.
fn create_python_chain_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut body = String::from("def chain(x):\n");
    body.push_str("    a = x + 1\n"); // line 2
    body.push_str("    b = a + 1\n"); // line 3
    body.push_str("    c = b + 1\n"); // line 4
    body.push_str("    d = c + 1\n"); // line 5
    body.push_str("    e = d + 1\n"); // line 6
    body.push_str("    f = e + 1\n"); // line 7
    body.push_str("    g = f + 1\n"); // line 8
    body.push_str("    h = g + 1\n"); // line 9
    body.push_str("    return h\n"); // line 10
    fs::write(dir.path().join("chain.py"), body).unwrap();
    dir
}

/// Build a JavaScript fixture similar to the ts emitter case.
fn create_js_chain_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut body = String::from("function chain(x) {\n");
    body.push_str("  let a = x + 1;\n");
    body.push_str("  let b = a + 1;\n");
    body.push_str("  let c = b + 1;\n");
    body.push_str("  let d = c + 1;\n");
    body.push_str("  let e = d + 1;\n");
    body.push_str("  let f = e + 1;\n");
    body.push_str("  let g = f + 1;\n");
    body.push_str("  let h = g + 1;\n");
    body.push_str("  return h;\n");
    body.push_str("}\n");
    fs::write(dir.path().join("chain.js"), body).unwrap();
    dir
}

/// Build a Ruby fixture.
fn create_ruby_chain_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut body = String::from("def chain(x)\n");
    body.push_str("  a = x + 1\n");
    body.push_str("  b = a + 1\n");
    body.push_str("  c = b + 1\n");
    body.push_str("  d = c + 1\n");
    body.push_str("  e = d + 1\n");
    body.push_str("  f = e + 1\n");
    body.push_str("  g = f + 1\n");
    body.push_str("  h = g + 1\n");
    body.push_str("  return h\n");
    body.push_str("end\n");
    fs::write(dir.path().join("chain.rb"), body).unwrap();
    dir
}

/// Build a Kotlin fixture.
fn create_kotlin_chain_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut body = String::from("fun chain(x: Int): Int {\n");
    body.push_str("    val a = x + 1\n");
    body.push_str("    val b = a + 1\n");
    body.push_str("    val c = b + 1\n");
    body.push_str("    val d = c + 1\n");
    body.push_str("    val e = d + 1\n");
    body.push_str("    val f = e + 1\n");
    body.push_str("    val g = f + 1\n");
    body.push_str("    val h = g + 1\n");
    body.push_str("    return h\n");
    body.push_str("}\n");
    fs::write(dir.path().join("Chain.kt"), body).unwrap();
    dir
}

/// Build a Swift fixture.
fn create_swift_chain_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut body = String::from("func chain(_ x: Int) -> Int {\n");
    body.push_str("    let a = x + 1\n");
    body.push_str("    let b = a + 1\n");
    body.push_str("    let c = b + 1\n");
    body.push_str("    let d = c + 1\n");
    body.push_str("    let e = d + 1\n");
    body.push_str("    let f = e + 1\n");
    body.push_str("    let g = f + 1\n");
    body.push_str("    let h = g + 1\n");
    body.push_str("    return h\n");
    body.push_str("}\n");
    fs::write(dir.path().join("Chain.swift"), body).unwrap();
    dir
}

// =============================================================================
// Tests — chop result MUST be clipped to [min(source,target), max(...)]
// =============================================================================

/// TypeScript emitter pattern (mirrors audit ts c15: emitWebIdl).
/// Function has a `out` accumulator threaded through every statement, so
/// the raw PDG forward/backward slices both span the whole function and
/// intersect to "everything". We assert the chop result lies strictly
/// within the user-requested interval.
#[test]
fn test_chop_typescript_interval_clipped() {
    let dir = create_ts_emitter_fixture();
    let file = dir.path().join("emit.ts");
    let file_str = file.to_str().unwrap();

    let src = 10u32;
    let tgt = 20u32;
    let result = run_chop(file_str, "emit", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "typescript");

    // The chop must be strictly smaller than the full function (function
    // body is ~40 lines; interval is ~11).
    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "typescript: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

#[test]
fn test_chop_python_interval_clipped() {
    let dir = create_python_chain_fixture();
    let file = dir.path().join("chain.py");
    let file_str = file.to_str().unwrap();

    // chain function: lines 1..=10. Pick interval [3..=7] inside the chain.
    let src = 3u32;
    let tgt = 7u32;
    let result = run_chop(file_str, "chain", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "python");

    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "python: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

#[test]
fn test_chop_javascript_interval_clipped() {
    let dir = create_js_chain_fixture();
    let file = dir.path().join("chain.js");
    let file_str = file.to_str().unwrap();

    let src = 3u32;
    let tgt = 7u32;
    let result = run_chop(file_str, "chain", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "javascript");

    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "javascript: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

#[test]
fn test_chop_ruby_interval_clipped() {
    let dir = create_ruby_chain_fixture();
    let file = dir.path().join("chain.rb");
    let file_str = file.to_str().unwrap();

    let src = 3u32;
    let tgt = 7u32;
    let result = run_chop(file_str, "chain", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "ruby");

    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "ruby: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

#[test]
fn test_chop_kotlin_interval_clipped() {
    let dir = create_kotlin_chain_fixture();
    let file = dir.path().join("Chain.kt");
    let file_str = file.to_str().unwrap();

    let src = 3u32;
    let tgt = 7u32;
    let result = run_chop(file_str, "chain", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "kotlin");

    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "kotlin: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

#[test]
fn test_chop_swift_interval_clipped() {
    let dir = create_swift_chain_fixture();
    let file = dir.path().join("Chain.swift");
    let file_str = file.to_str().unwrap();

    let src = 3u32;
    let tgt = 7u32;
    let result = run_chop(file_str, "chain", src, tgt);
    assert_chop_within_interval(&result, src, tgt, "swift");

    let lines = lines_of(&result);
    assert!(
        lines.len() <= (tgt - src + 1) as usize,
        "swift: chop count {} exceeds interval size {}",
        lines.len(),
        tgt - src + 1
    );
}

/// Sanity: when source==target, chop must contain exactly that line and
/// nothing outside it.
#[test]
fn test_chop_same_line_is_single_line() {
    let dir = create_python_chain_fixture();
    let file = dir.path().join("chain.py");
    let file_str = file.to_str().unwrap();

    let result = run_chop(file_str, "chain", 5, 5);
    let lines = lines_of(&result);
    assert_eq!(
        lines,
        vec![5],
        "chop(5,5) must equal exactly [5], got {:?}",
        lines
    );
}

/// Test that reversed source/target (source > target) is handled — the
/// implementation should clip to [target, source] (i.e. the unordered
/// interval). The dependency direction still respects the named source
/// and target lines.
#[test]
fn test_chop_reversed_args_interval_clipped() {
    let dir = create_python_chain_fixture();
    let file = dir.path().join("chain.py");
    let file_str = file.to_str().unwrap();

    // source AFTER target lexically — chop semantics still apply, but the
    // result (if non-empty) must lie within the unordered interval.
    let src = 7u32;
    let tgt = 3u32;
    let result = run_chop(file_str, "chain", src, tgt);
    let path_exists = result["path_exists"].as_bool().unwrap_or(false);
    if path_exists {
        assert_chop_within_interval(&result, src, tgt, "python-reversed");
    }
}
