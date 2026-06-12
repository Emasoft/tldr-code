//! fix-cl-2-v1 (v0.5.0 CL-2, GH #80): PDG backward slice must honor backward
//! reachability *precisely* — not the full basic-block range (over-inclusion)
//! and not an empty set (under-inclusion).
//!
//! # Two failure modes fixed
//!
//! ## (a) Over-inclusion on single/coarse-block CFGs
//!
//! For functions whose criterion line sits inside a coarse CFG basic block,
//! the slice emitter expanded the whole block's `lines.0..=lines.1` range (and
//! the entire directional *half* `bstart..=criterion`). That dragged in every
//! comment, blank line, and unrelated statement sharing the block — and, worse,
//! every statement that runs *after* the criterion. Audited gaps:
//!   IT3-c-02, IT3-cpp-02, IT3-go-03, IT3-luau-06, IT3-rust-04, IT3-rust-05.
//!
//! A backward slice from line `c` must NEVER contain a statement line strictly
//! greater than `c` (a backward slice cannot depend on code that runs later),
//! and must not contain comment/blank lines that carry no data/control
//! dependency to the criterion.
//!
//! ## (b) Under-inclusion (EMPTY) on CFG gaps
//!
//! When the criterion line fell in a block the CFG builder never created — a
//! Swift `if/else` whose then/else bodies are bare `statements` children
//! (no `consequence`/`alternative` field, no `then_clause`/`else_clause` kind),
//! so the else-branch trailing-closure body was dropped entirely — the slice
//! collapsed to EMPTY. `swift _heapify` line 386 (`trickleDownMax(node)`) is the
//! canonical case.
//!
//! Both modes are validated against the real corpora under /tmp/repos.

use std::path::Path;
use std::process::Command;

fn slice_lines(file: &str, function: &str, line: u32, direction: &str) -> Vec<u32> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file,
            function,
            &line.to_string(),
            "-d",
            direction,
            "-q",
        ])
        .output()
        .expect("failed to execute tldr slice");
    assert!(
        output.status.success(),
        "slice should succeed for {file}::{function}:{line} [{direction}]: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("slice output not valid JSON: {e}\nstdout: {stdout}"));
    v["lines"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_u64().unwrap() as u32).collect())
        .unwrap_or_default()
}

/// Statement lines (drop blank lines and pure closing braces) so the
/// "after criterion" assertion targets real over-inclusion of downstream
/// statements, not a trailing `}`.
fn statement_lines(file: &str, function: &str, line: u32, direction: &str) -> Vec<u32> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice", file, function, &line.to_string(), "-d", direction, "-q",
        ])
        .output()
        .expect("failed to execute tldr slice");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let mut lines = Vec::new();
    if let Some(arr) = v["slice_lines"].as_array() {
        for sl in arr {
            let l = sl["line"].as_u64().unwrap() as u32;
            let code = sl["code"].as_str().unwrap_or("").trim();
            if code.is_empty() || code == "}" {
                continue;
            }
            lines.push(l);
        }
    }
    lines
}

// =============================================================================
// (a) Over-inclusion: backward slice must not exceed the criterion and must
//     not return the full coarse-block range.
// =============================================================================

const C_SDS: &str = "/tmp/repos/c-sds/sds.c";
const CPP_TINYXML2: &str = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
const GO_PATH: &str = "/tmp/repos/go-httprouter/path.go";
const LUAU_PARSER: &str = "/tmp/repos/luau/Ast/src/Parser.cpp";
const RUST_DEPS: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../tldr-core/src/analysis/deps.rs");
const SWIFT_HEAP: &str =
    "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";

/// Shared assertion: backward slice contains the criterion, contains no
/// statement line after it, and does NOT span the full contiguous block.
fn assert_backward_precise(file: &str, function: &str, criterion: u32, block_hi: u32, label: &str) {
    if !Path::new(file).exists() {
        eprintln!("skipping {label}: corpus not present at {file}");
        return;
    }
    let lines = slice_lines(file, function, criterion, "backward");
    assert!(
        lines.contains(&criterion),
        "{label}: backward slice from {criterion} must contain the criterion; got {lines:?}"
    );

    // No statement line strictly after the criterion.
    let stmt = statement_lines(file, function, criterion, "backward");
    let after: Vec<u32> = stmt.iter().copied().filter(|&l| l > criterion).collect();
    assert!(
        after.is_empty(),
        "{label}: backward slice from {criterion} must NOT include statement lines AFTER the \
         criterion; offending: {after:?}; full: {lines:?}"
    );

    // Not the full contiguous block range: at least one line between the block
    // start and the criterion must be excluded (a precise slice drops
    // comments/blanks/unrelated statements; the coarse-block bug returned them
    // all).
    let block_lo = lines.iter().copied().min().unwrap_or(criterion);
    let span_len = (block_hi.max(criterion) - block_lo + 1) as usize;
    assert!(
        lines.len() < span_len,
        "{label}: backward slice from {criterion} returned the FULL block range \
         ({block_lo}..={}) — {} lines for a {span_len}-line span; over-inclusion not fixed: {lines:?}",
        block_hi.max(criterion),
        lines.len(),
    );
}

#[test]
fn c_sdsmakeroomfor_backward_not_full_block() {
    // sdsMakeRoomFor body ~204..248; criterion 212 (`if (avail>=addlen) return s`).
    // Pre-fix returned 204..216 (full prefix + post-criterion 213..216).
    assert_backward_precise(C_SDS, "sdsMakeRoomFor", 212, 216, "c/IT3-c-02");
}

#[test]
fn cpp_getcharacterref_backward_not_full_block() {
    // GetCharacterRef body 463..552; criterion 470. Pre-fix returned 463..550
    // (entire remaining function body after the criterion).
    assert_backward_precise(CPP_TINYXML2, "GetCharacterRef", 470, 552, "cpp/IT3-cpp-02");
}

#[test]
fn go_cleanpath_backward_not_full_block() {
    // CleanPath; criterion 40 (`r := 1`, a constant store). Pre-fix returned
    // 21..40 (every statement before the criterion).
    assert_backward_precise(GO_PATH, "CleanPath", 40, 40, "go/IT3-go-03");
}

#[test]
fn luau_parseif_backward_not_full_block() {
    // parseIf 559..617; criterion 570. Pre-fix returned 559..570 contiguous,
    // including 561/562/565 which do not affect the criterion.
    assert_backward_precise(LUAU_PARSER, "parseIf", 570, 570, "luau/IT3-luau-06");
}

#[test]
fn rust_detect_cycles_backward_not_full_block() {
    // detect_cycles 803..849; criterion 813 (`if visited.contains(start_node)`).
    // Pre-fix returned 803..815 contiguous (comments 804..808,810..811 and the
    // unrelated `cycles` def @806 plus post-criterion 814..815).
    assert_backward_precise(RUST_DEPS, "detect_cycles", 813, 830, "rust/IT3-rust-04");
}

#[test]
fn rust_detect_cycles_backward_excludes_unrelated_def() {
    // The `cycles` HashSet is defined on line 806 and is NOT used to compute
    // the criterion `if visited.contains(start_node)` (line 813). A precise
    // backward slice must exclude it.
    if !Path::new(RUST_DEPS).exists() {
        eprintln!("skipping: {RUST_DEPS} not present");
        return;
    }
    let lines = slice_lines(RUST_DEPS, "detect_cycles", 813, "backward");
    assert!(
        !lines.contains(&806),
        "rust/IT3-rust-05: backward slice from 813 must exclude the unrelated `cycles` \
         definition on line 806; got {lines:?}"
    );
    // But the variables that DO feed the criterion must be present: `visited`
    // (def 809) and `start_node` (def 812).
    assert!(
        lines.contains(&809) && lines.contains(&812),
        "rust: backward slice from 813 must include the defs that feed it \
         (visited@809, start_node@812); got {lines:?}"
    );
}

// =============================================================================
// (b) Under-inclusion: swift else-branch trailing-closure body must NOT slice
//     to EMPTY.
// =============================================================================

#[test]
fn swift_heapify_else_branch_backward_not_empty() {
    if !Path::new(SWIFT_HEAP).exists() {
        eprintln!("skipping: {SWIFT_HEAP} not present");
        return;
    }
    // _heapify 378..388. Line 386 (`trickleDownMax(node)`) is inside the ELSE
    // branch's trailing-closure body. The Swift `if_statement` exposes its
    // branches as bare `statements` children, so the CFG builder previously
    // dropped the else body and the slice from 386 returned EMPTY.
    let lines = slice_lines(SWIFT_HEAP, "_heapify", 386, "backward");
    assert!(
        lines.contains(&386),
        "swift/under-inclusion: backward slice from 386 must contain the criterion; got {lines:?}"
    );
    assert!(
        lines.len() >= 2,
        "swift/under-inclusion: backward slice from the else-branch body line 386 must reach \
         beyond the criterion itself (it depends on the closure parameter and the enclosing \
         predicate); got {lines:?}"
    );
    // Backward slice must not reach past the criterion.
    let after: Vec<u32> = lines.iter().copied().filter(|&l| l > 386).collect();
    assert!(
        after.is_empty(),
        "swift: backward slice from 386 must not include lines after the criterion; got {lines:?}"
    );
}
