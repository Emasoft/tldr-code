//! Reproduction tests for VAL-002 (v0.2.2-quality):
//! - Issue #18: CFG `break` creates a back-edge to loop header
//! - Issue  #6: SSA construction drops function parameters
//!
//! These two bugs sit in adjacent pipeline stages
//! (CFG predecessors → SSA phi nodes), so they are bundled.
//!
//! Both tests MUST fail on HEAD a8d077c before the fix is applied.

use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::ssa::construct_minimal_ssa;
use tldr_core::types::{BlockType, EdgeType};
use tldr_core::Language;

// =============================================================================
// (a) Issue #18 — CFG break MUST NOT back-edge to loop header
// =============================================================================

/// Reproduction for parcadei/tldr-code#18.
///
/// In a `for x in items: if cond: break` pattern, the break statement creates
/// its own block (BlockType::Body) and is added to `current_block_id`. After
/// processing the loop body, the back-edge guard (`!exit_blocks.contains(...)`)
/// only excludes return-style exits — break-exit blocks are still treated as
/// candidates for the `current_block_id → header_block` BackEdge insertion.
///
/// Result: the break block gains a spurious BackEdge to the loop header,
/// corrupting downstream predecessor analysis (dominators, SSA phi placement,
/// liveness, etc.).
///
/// This test asserts that NO break block (BlockType::Body emitted from
/// `process_break_statement`) appears as the source of a BackEdge into a
/// LoopHeader block.
#[test]
fn cfg_break_does_not_create_back_edge_to_loop_header() {
    // GIVEN: a for-loop containing a break inside an if
    let source = r#"
def loop_with_break(items):
    for x in items:
        if x == 0:
            break
        print(x)
"#;

    let cfg = get_cfg_context(source, "loop_with_break", Language::Python)
        .expect("CFG extraction must succeed");

    // Identify the loop header block(s)
    let loop_header_ids: Vec<usize> = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::LoopHeader)
        .map(|b| b.id)
        .collect();
    assert!(
        !loop_header_ids.is_empty(),
        "Test pre-condition: at least one LoopHeader must exist; got blocks: {:?}",
        cfg.blocks
            .iter()
            .map(|b| (b.id, b.block_type))
            .collect::<Vec<_>>()
    );

    // Identify all blocks that are the TARGET of a Break edge — these are
    // the `break_block` instances created by `process_break_statement`.
    // (The Break edge is `current_block_id → break_block`, so the block
    // representing the break statement itself is `e.to`.)
    let break_block_ids: Vec<usize> = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Break)
        .map(|e| e.to)
        .collect();
    assert!(
        !break_block_ids.is_empty(),
        "Test pre-condition: at least one Break edge must exist; got edges: {:?}",
        cfg.edges
            .iter()
            .map(|e| (e.from, e.to, e.edge_type))
            .collect::<Vec<_>>()
    );

    // The bug symptom: from a break block, control-flow reaches the loop
    // header via a BackEdge. Concretely: the break block has an outgoing
    // Unconditional edge into a sibling block (e.g. the if-join) which then
    // owns a BackEdge to the loop header. This means the program graph models
    // `break` as "fall through to next iteration", which is wrong.
    //
    // We compute, for each break block, the set of blocks reachable via any
    // forward edge (including the Unconditional edge into the if-join), then
    // check whether any such reachable block is a BackEdge predecessor of the
    // loop header.
    let mut adjacency: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for e in &cfg.edges {
        // Exclude BackEdge from the forward-reachability search itself,
        // because we want to detect `break_block → ... → predecessor → header`.
        if e.edge_type != EdgeType::BackEdge {
            adjacency.entry(e.from).or_default().push(e.to);
        }
    }
    // Predecessors of loop headers via BackEdge.
    let backedge_predecessors_of_headers: std::collections::HashSet<usize> = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::BackEdge)
        .filter(|e| loop_header_ids.contains(&e.to))
        .map(|e| e.from)
        .collect();

    let mut bad_paths: Vec<(usize, usize)> = Vec::new();
    for &break_id in &break_block_ids {
        // BFS from the break block.
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![break_id];
        while let Some(cur) = stack.pop() {
            if !visited.insert(cur) {
                continue;
            }
            if cur != break_id && backedge_predecessors_of_headers.contains(&cur) {
                bad_paths.push((break_id, cur));
            }
            if let Some(next) = adjacency.get(&cur) {
                for &n in next {
                    stack.push(n);
                }
            }
        }
    }

    // Compute the predecessor list of each loop header for diagnostic clarity.
    let predecessors_of_header: Vec<(usize, Vec<usize>)> = loop_header_ids
        .iter()
        .map(|hid| {
            let preds: Vec<usize> = cfg
                .edges
                .iter()
                .filter(|e| e.to == *hid)
                .map(|e| e.from)
                .collect();
            (*hid, preds)
        })
        .collect();

    let edge_dump: Vec<(usize, usize, EdgeType)> = cfg
        .edges
        .iter()
        .map(|e| (e.from, e.to, e.edge_type))
        .collect();

    assert!(
        bad_paths.is_empty(),
        "expected break blocks {:?} to NOT reach a back-edge predecessor of any \
         loop header {:?}; got bad (break_block, intermediate_predecessor) \
         pairs: {:?}; predecessor map: {:?}; edges: {:?}",
        break_block_ids,
        loop_header_ids,
        bad_paths,
        predecessors_of_header,
        edge_dump,
    );
}

// =============================================================================
// (b) Issue #6 — SSA construction MUST NOT drop function parameters
// =============================================================================

/// Reproduction for parcadei/tldr-code#6.
///
/// The DFG records `x` as a Definition on the `def foo(x):` signature line.
/// CFG block ranges are seeded from the function body, so the signature line
/// falls outside every block — `get_block_for_line` returns `None` and the
/// definition is silently dropped from `var_defs`.
///
/// Consequence: the SSA name table never contains an entry for `x`, even
/// though `x` is used at `return x + 1`. A correct fix mirrors the existing
/// pattern in `crates/tldr-core/src/dfg/reaching.rs:131-134`:
/// orphaned definitions fall back to the entry block.
///
/// This test asserts that:
///   1. At least one SsaName exists for the parameter `x`.
///   2. Every phi function has exactly `predecessors.len()` operands
///      (sources). This catches the secondary bug where `fill_phi_sources`
///      omits PhiSource entries when `block_exit_versions` lacks an entry.
#[test]
fn ssa_includes_function_parameters_and_complete_phi_sources() {
    // ---- Sub-assertion 1: parameter SSA name exists --------------------------
    let param_source = r#"
def foo(x):
    return x + 1
"#;
    let cfg = get_cfg_context(param_source, "foo", Language::Python)
        .expect("CFG extraction must succeed for foo");
    let dfg = get_dfg_context(param_source, "foo", Language::Python)
        .expect("DFG extraction must succeed for foo");

    let ssa = construct_minimal_ssa(&cfg, &dfg).expect("SSA construction must succeed");

    let x_names: Vec<&tldr_core::ssa::SsaName> =
        ssa.ssa_names.iter().filter(|n| n.variable == "x").collect();
    assert!(
        !x_names.is_empty(),
        "expected parameter `x` to appear in SSA names; got names: {:?}",
        ssa.ssa_names
            .iter()
            .map(|n| (n.variable.as_str(), n.version))
            .collect::<Vec<_>>()
    );

    // ---- Sub-assertion 2: phi nodes have complete operand counts -------------
    // A loop with a phi-requiring shape: the loop variable `i` is defined in
    // the loop initializer and re-defined inside the body — produces a phi at
    // the loop header whose operand count must equal predecessors.len().
    let phi_source = r#"
def loop_with_phi(items, x):
    total = 0
    for i in items:
        total = total + i + x
    return total
"#;
    let cfg2 = get_cfg_context(phi_source, "loop_with_phi", Language::Python)
        .expect("CFG extraction must succeed for loop_with_phi");
    let dfg2 = get_dfg_context(phi_source, "loop_with_phi", Language::Python)
        .expect("DFG extraction must succeed for loop_with_phi");
    let ssa2 = construct_minimal_ssa(&cfg2, &dfg2).expect("SSA construction must succeed");

    // Sub-assertion 2a: parameter `x` from this larger function also appears.
    let x2_names: Vec<&tldr_core::ssa::SsaName> = ssa2
        .ssa_names
        .iter()
        .filter(|n| n.variable == "x")
        .collect();
    assert!(
        !x2_names.is_empty(),
        "expected parameter `x` of loop_with_phi to appear in SSA names; \
         got names: {:?}",
        ssa2.ssa_names
            .iter()
            .map(|n| (n.variable.as_str(), n.version))
            .collect::<Vec<_>>()
    );

    // Sub-assertion 2b: every phi has operand count == predecessor count.
    let mut mismatches: Vec<(usize, String, usize, usize)> = Vec::new();
    for block in &ssa2.blocks {
        let pred_count = block.predecessors.len();
        for phi in &block.phi_functions {
            if phi.sources.len() != pred_count {
                mismatches.push((
                    block.id,
                    phi.variable.clone(),
                    phi.sources.len(),
                    pred_count,
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "phi operand count mismatch (block_id, var, sources_len, predecessors_len): {:?}",
        mismatches,
    );
}
