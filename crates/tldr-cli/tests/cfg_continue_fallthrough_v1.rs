//! cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104)
//!
//! Regression tests for two related CFG defects in `process_continue_statement`
//! and Kotlin `jump_expression` dispatch, surfaced by Phase-22 iter-3 debug-agent
//! investigation at `/tmp/audit_phase22/iter3/investigations/issue-61-actual-cause.md`.
//!
//! # Test A — Issue #61: `continue_block` spurious fallthrough edges (all langs)
//!
//! `process_continue_statement` created a `continue_block`, added the `Continue`
//! edge into it, then left it un-tracked in `loop_exit_blocks`. Every later
//! fallthrough guard of the form
//! `!exit_blocks.contains(&current_block_id) && !loop_exit_blocks.contains(&current_block_id)`
//! treated the continue block as a regular fallthrough source, producing spurious
//! `Unconditional` edges to the post-continue join block and to the function exit.
//!
//! Fix: add `self.loop_exit_blocks.push(continue_block);` immediately after the
//! `add_edge` call in `process_continue_statement` — mirrors the identical fix
//! already present in `process_break_statement` (closes #18).
//!
//! Test A asserts: every block whose only outgoing edge is `Continue` (i.e. the
//! continue_block itself) has **no additional outgoing `Unconditional` edges**.
//! Pre-fix Python/Go/JS/Java all show two spurious `Unconditional` edges from that
//! block (confirmed by `issue61_inspect.rs` example output).
//!
//! # Test B — Kotlin `jump_expression` never dispatched
//!
//! tree-sitter-kotlin-ng emits `jump_expression` / `continue_at` for `continue`.
//! Neither form was dispatched in `process_statement` (extractor.rs:411–473), so
//! Kotlin's `continue` was silently dropped — no `Continue` edge appeared at all.
//!
//! Fix: add a Kotlin-specific dispatch arm that routes `jump_expression` /
//! `continue_at` subtypes to `process_continue_statement` and `break` /
//! `break_at` subtypes to `process_break_statement`.
//!
//! Test B asserts: a Kotlin `for (x in xs) { continue }` function produces at
//! least one `Continue` edge in its CFG.
//!
//! Tests use `tldr_core::cfg::get_cfg_context` directly.

use tldr_core::cfg::get_cfg_context;
use tldr_core::types::{EdgeType, Language};

// ============================================================================
// Test A — Issue #61: no spurious Unconditional edges out of continue block
// ============================================================================
//
// Strategy: any block that has exactly one outgoing edge of type `Continue`
// must not also have any `Unconditional` outgoing edge. Pre-fix there were
// always two spurious Unconditional edges from that block.

fn assert_no_spurious_continue_fallthrough(cfg: &tldr_core::types::CfgInfo, lang: &str) {
    // The `continue_block` is the DESTINATION of each `Continue` edge.
    // After `process_continue_statement` runs:
    //   add_edge(prev_block, continue_block, Continue)
    //   current_block_id = continue_block
    // Without the fix, continue_block is not in loop_exit_blocks, so later
    // fallthrough guards emit spurious Unconditional edges *from* continue_block.
    let continue_dest_blocks: Vec<usize> = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Continue)
        .map(|e| e.to)
        .collect();

    assert!(
        !continue_dest_blocks.is_empty(),
        "[{lang}] expected at least one Continue edge in CFG but found none"
    );

    for block_id in continue_dest_blocks {
        let spurious: Vec<_> = cfg
            .edges
            .iter()
            .filter(|e| e.from == block_id && e.edge_type == EdgeType::Unconditional)
            .collect();
        assert!(
            spurious.is_empty(),
            "[{lang}] continue_block id={block_id} has spurious Unconditional edges: {spurious:?}\n  full edge list: {:?}",
            cfg.edges
        );
    }
}

#[test]
fn test_a_python_for_continue_no_spurious_fallthrough() {
    let src = r#"
def skip_negatives(xs):
    total = 0
    for x in xs:
        if x < 0:
            continue
        total += x
    return total
"#;
    let cfg = get_cfg_context(src, "skip_negatives", Language::Python).expect("cfg ok");
    assert_no_spurious_continue_fallthrough(&cfg, "Python/for");
}

#[test]
fn test_a_python_while_continue_no_spurious_fallthrough() {
    let src = r#"
def count_pos(xs):
    i = 0
    total = 0
    while i < len(xs):
        i += 1
        if xs[i-1] < 0:
            continue
        total += 1
    return total
"#;
    let cfg = get_cfg_context(src, "count_pos", Language::Python).expect("cfg ok");
    assert_no_spurious_continue_fallthrough(&cfg, "Python/while");
}

#[test]
fn test_a_go_for_continue_no_spurious_fallthrough() {
    let src = r#"
func skipNeg(xs []int) int {
    total := 0
    for _, x := range xs {
        if x < 0 {
            continue
        }
        total += x
    }
    return total
}
"#;
    let cfg = get_cfg_context(src, "skipNeg", Language::Go).expect("cfg ok");
    assert_no_spurious_continue_fallthrough(&cfg, "Go/for");
}

#[test]
fn test_a_javascript_for_continue_no_spurious_fallthrough() {
    let src = r#"
function skipNeg(xs) {
    let total = 0;
    for (let i = 0; i < xs.length; i++) {
        if (xs[i] < 0) {
            continue;
        }
        total += xs[i];
    }
    return total;
}
"#;
    let cfg = get_cfg_context(src, "skipNeg", Language::JavaScript).expect("cfg ok");
    assert_no_spurious_continue_fallthrough(&cfg, "JavaScript/for");
}

#[test]
fn test_a_java_for_continue_no_spurious_fallthrough() {
    let src = r#"
class P {
    int skipNeg(int[] xs) {
        int total = 0;
        for (int x : xs) {
            if (x < 0) {
                continue;
            }
            total += x;
        }
        return total;
    }
}
"#;
    let cfg = get_cfg_context(src, "skipNeg", Language::Java).expect("cfg ok");
    assert_no_spurious_continue_fallthrough(&cfg, "Java/enhanced-for");
}

// ============================================================================
// Test B — Kotlin jump_expression dispatched and emits Continue edge
// ============================================================================

#[test]
fn test_b_kotlin_for_continue_emits_continue_edge() {
    let src = r#"
fun skipNeg(xs: List<Int>): Int {
    var total = 0
    for (x in xs) {
        if (x < 0) continue
        total += x
    }
    return total
}
"#;
    let cfg = get_cfg_context(src, "skipNeg", Language::Kotlin).expect("cfg ok");

    let continue_edges: Vec<_> = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Continue)
        .collect();

    assert!(
        !continue_edges.is_empty(),
        "Kotlin for+continue must emit at least one Continue edge; got none. \
         edges={:?}",
        cfg.edges
    );
}
