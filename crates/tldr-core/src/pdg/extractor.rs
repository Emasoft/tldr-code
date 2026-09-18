//! PDG extraction from source code
//!
//! Builds a Program Dependence Graph by combining CFG and DFG.
//!
//! # PDG Node Types
//! - Entry: Function entry point
//! - Statement: Regular statement
//! - Predicate: Condition in if/while/for
//!
//! # PDG Edge Types
//! - Control: Target is control-dependent on source
//! - Data: Target uses a variable defined by source

use std::collections::{HashMap, HashSet};

use crate::cfg::get_cfg_context_with_statements;
use crate::dfg::get_dfg_context;
use crate::types::{
    CfgInfo, DependenceType, DfgInfo, EdgeType, Language, PdgEdge, PdgInfo, PdgNode,
};
use crate::TldrResult;

/// Extract PDG for a function from source code or file path
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to extract PDG for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(PdgInfo)` - PDG combining CFG and DFG
/// * `Err(FunctionNotFound)` - If function doesn't exist
pub fn get_pdg_context(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<PdgInfo> {
    // Get CFG and DFG
    let (cfg, statements) =
        get_cfg_context_with_statements(source_or_path, function_name, language)?;
    let dfg = get_dfg_context(source_or_path, function_name, language)?;

    // Build PDG from CFG and DFG
    build_pdg(function_name, cfg, dfg, &statements)
}

/// Build PDG from CFG and DFG
///
/// `statements` carries the CFG builder's statement spans as
/// `(block_id, start_line, end_line)`; see `cfg::extractor::StatementSpans`.
fn build_pdg(
    function_name: &str,
    cfg: CfgInfo,
    dfg: DfgInfo,
    statements: &[(usize, u32, u32)],
) -> TldrResult<PdgInfo> {
    let mut nodes: Vec<PdgNode> = Vec::new();
    let mut edges: Vec<PdgEdge> = Vec::new();

    // Create PDG nodes from CFG blocks, ONE NODE PER STATEMENT.
    //
    // why the STATEMENT is the unit (TRDD-3TCJKGWM): the two obvious
    // alternatives are each wrong in a different direction.
    //
    // - One node per BASIC BLOCK makes the whole of a branch-free function
    //   a single node, so a backward slice from `return c` reports every
    //   line in the block, including statements with no dependency path to
    //   the criterion. Imprecise — but never *unsound*: it could not drop a
    //   relevant line, because the one node held them all.
    // - One node per SOURCE LINE fixed that imprecision and introduced an
    //   unsoundness: the rows of a single statement became unconnected
    //   nodes. `x = compute(\n a,\n b,\n)` put the def of `x` on the first
    //   row and the uses of `a`/`b` on the others, so a backward slice from
    //   `return x` reached the row holding `x` and stopped — silently
    //   dropping the definitions of `a` and `b`. Same for a multi-line
    //   `def` signature, where each parameter defines a name on its own row.
    //
    // A statement is one program point, so it is one node. Lines a statement
    // span does not cover (a branch/loop condition line, anything the CFG
    // builder does not classify) still get a node each, exactly as before —
    // that fallback is what keeps predicate blocks working.
    let mut node_for_line: HashMap<u32, usize> = HashMap::new();
    let mut node_for_span: HashMap<(u32, u32), usize> = HashMap::new();
    let mut nodes_for_block: HashMap<usize, Vec<usize>> = HashMap::new();

    for block in &cfg.blocks {
        // Determine node type from block type
        let block_node_type = match block.block_type {
            crate::types::BlockType::Entry => "entry",
            crate::types::BlockType::Branch => "predicate",
            crate::types::BlockType::LoopHeader => "predicate",
            _ => "statement",
        };

        let (start, end) = block.lines;

        // This block's statement spans in source order, deduped. Ties on the
        // start line put the narrowest span first, so a wider one can never
        // claim lines a tighter one already covers.
        let mut spans: Vec<(u32, u32)> = statements
            .iter()
            .filter(|(bid, _, _)| *bid == block.id)
            .map(|&(_, s, e)| (s, e))
            .collect();
        spans.sort_unstable();
        spans.dedup();

        let mut block_nodes: Vec<usize> = Vec::new();
        let mut created: Vec<(u32, u32, usize)> = Vec::new();

        for (s, e) in spans {
            // why: CFG blocks can overlap (a `return` line is both the Return
            // block and the Exit block), and the same statement can be seen
            // twice. One statement is one program point, so an identical span
            // reuses the node instead of orphaning a duplicate.
            if let Some(&existing) = node_for_span.get(&(s, e)) {
                if !block_nodes.contains(&existing) {
                    block_nodes.push(existing);
                }
                continue;
            }

            // Issue #80 (cluster CL-14): a multi-line span that DEFINES
            // something on a row after its first is not one statement — it is
            // the CFG builder's container fallback swallowing several
            // statements (Swift's `statements` node, a Luau whole-function
            // `block`). One node over such a span made every slice touching
            // it return the block's full line range, because the criterion
            // resolved to the span node and `nodes_to_lines` emitted the
            // whole span. Split those spans into one node per row so the
            // DFG's per-line def-use edges carry the slice instead. Genuine
            // multi-line statements define only on their first row (the LHS)
            // and stay whole — that keeps the TRDD-3TCJKGWM soundness (the
            // rows of `x = compute(\n a,\n b,\n)` remain one program point).
            //
            // The multi-line function signature is exempt: its parameters
            // deliberately define on their own rows while the signature stays
            // ONE program point (`record_signature_span`; pinned by
            // `slice_keeps_multiline_signature_together`). A signature-like
            // span is the entry block's leading span that CONTAINS no other
            // statement span and is not overlapped by one starting inside it —
            // a container-swallowing span (Luau's whole-function fallback
            // starts on the `def` row) spans the rows of the statements it
            // swallowed and so does not qualify. Spans starting exactly on the
            // signature's end row (Rust's `) -> u32 {` body-opening row) are
            // boundary rows, not swallowed statements.
            let signature_like = block.id == 0
                && s == start
                && !statements
                    .iter()
                    .any(|&(_, other_s, other_e)| other_s > s && other_e < e)
                && statements.iter().all(|&(other_block, other_s, other_e)| {
                    (other_block == block.id && other_s == s && other_e == e) || other_s >= e
                });
            let hides_statements =
                e > s && !signature_like && span_hides_later_definitions(&dfg, s, e);
            if hides_statements {
                for line in s..=e {
                    let id = match node_for_span.get(&(line, line)) {
                        Some(&existing) => existing,
                        None => {
                            // Only the block's first line carries the block's
                            // own kind; split rows are statements.
                            let node_type = if line == start {
                                block_node_type
                            } else {
                                "statement"
                            };
                            let id = nodes.len();
                            nodes.push(PdgNode {
                                id,
                                node_type: node_type.to_string(),
                                lines: (line, line),
                                definitions: Vec::new(),
                                uses: Vec::new(),
                            });
                            node_for_span.insert((line, line), id);
                            created.push((line, line, id));
                            id
                        }
                    };
                    if !block_nodes.contains(&id) {
                        block_nodes.push(id);
                    }
                }
                continue;
            }

            // Only the block's first line carries the block's own kind; the
            // statements following an entry/predicate line are statements.
            let node_type = if s == start {
                block_node_type
            } else {
                "statement"
            };

            let id = nodes.len();
            nodes.push(PdgNode {
                id,
                node_type: node_type.to_string(),
                lines: (s, e),
                definitions: Vec::new(),
                uses: Vec::new(),
            });
            node_for_span.insert((s, e), id);
            created.push((s, e, id));
            block_nodes.push(id);
        }

        // Claim lines WIDEST span first so the narrowest ends up owning the
        // line — a Python one-liner `if x: y = 1` records both the header and
        // the inner statement on that row, and the inner one is the finer
        // answer. Merged into the global map without clobbering: a line an
        // earlier block already owns keeps its owner, which is what kept the
        // Return/Exit overlap collapsing to one node.
        let mut local: HashMap<u32, usize> = HashMap::new();
        created.sort_by_key(|&(s, e, _)| std::cmp::Reverse(e - s));
        for (s, e, id) in created {
            for line in s..=e {
                local.insert(line, id);
            }
        }
        for (line, id) in local {
            node_for_line.entry(line).or_insert(id);
        }

        // Per-line fallback for every line of the block no span covered. This
        // is what keeps a Branch/LoopHeader condition line — which the CFG
        // reports as the block's whole `lines` range — working as before.
        for line in start..=end {
            if let Some(&existing) = node_for_line.get(&line) {
                if !block_nodes.contains(&existing) {
                    block_nodes.push(existing);
                }
                continue;
            }

            let node_type = if line == start {
                block_node_type
            } else {
                "statement"
            };

            let id = nodes.len();
            nodes.push(PdgNode {
                id,
                node_type: node_type.to_string(),
                lines: (line, line),
                definitions: Vec::new(),
                uses: Vec::new(),
            });
            node_for_line.insert(line, id);
            block_nodes.push(id);
        }

        nodes_for_block.insert(block.id, block_nodes);
    }

    // Attach defs/uses BY LINE OWNERSHIP, once `node_for_line` is final.
    //
    // why ownership and not a per-node range scan (TRDD-3TCJKGWM): spans can
    // share a row — a brace language's `) {`, a one-liner `def f(a): return a`
    // — and a range scan would then count the same DFG ref into two nodes,
    // inflating both `definitions` and the data edges derived from them.
    // `node_for_line` already answers "which node IS this line", exactly once.
    let mut defs_for_node: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut uses_for_node: HashMap<usize, HashSet<String>> = HashMap::new();
    for r in &dfg.refs {
        let Some(&id) = node_for_line.get(&r.line) else {
            continue;
        };
        match r.ref_type {
            crate::types::RefType::Definition | crate::types::RefType::Update => {
                defs_for_node.entry(id).or_default().insert(r.name.clone());
            }
            crate::types::RefType::Use => {
                uses_for_node.entry(id).or_default().insert(r.name.clone());
            }
        }
    }
    for node in &mut nodes {
        if let Some(defs) = defs_for_node.remove(&node.id) {
            let mut defs: Vec<String> = defs.into_iter().collect();
            defs.sort();
            node.definitions = defs;
        }
        if let Some(uses) = uses_for_node.remove(&node.id) {
            let mut uses: Vec<String> = uses.into_iter().collect();
            uses.sort();
            node.uses = uses;
        }
    }

    // Add control dependency edges from CFG.
    //
    // Issue #80 (cluster CL-14): the previous rule marked EVERY CFG edge out
    // of a Branch/LoopHeader block as a control dependence, which over-
    // approximates on two fronts. A block reached only through the branch's
    // false arm (the fall-through join of an `if` without `else`) was marked
    // control-dependent on the condition even though it strictly post-
    // dominates the branch and therefore runs unconditionally; and every
    // statement AFTER a loop was marked dependent on the loop header. Both
    // pulled unrelated lines into backward slices.
    //
    // The standard definition (Ferrante, Ottenstein & Warren) fixes this:
    // B is control-dependent on A iff A has a successor S such that B
    // post-dominates S while B does not strictly post-dominate A. That is
    // exactly "B runs only for some values of A's condition". Blocks that
    // strictly post-dominate the branch (the unconditional join, the code
    // after a loop) are excluded; the branch arms and loop bodies — which do
    // not strictly post-dominate it — are kept, so real control dependence
    // survives (pinned by the loop-body regression test).
    for (pred_block, dep_block) in control_dependence_pairs(&cfg) {
        // why: every statement of the dependent block is control-dependent on
        // the predicate, so the block-level pair expands to the cross product
        // of the two blocks' line nodes. Keeping the source side whole (rather
        // than just the condition line) preserves exactly the reachability the
        // block-granular graph had, so this split cannot drop a line from a
        // slice.
        let (Some(sources), Some(targets)) = (
            nodes_for_block.get(&pred_block),
            nodes_for_block.get(&dep_block),
        ) else {
            continue;
        };
        // Label from the predicate's own out-edge when one exists, purely so
        // the edge keeps carrying which kind of branch produced it.
        let label_edge = cfg
            .edges
            .iter()
            .find(|e| e.from == pred_block)
            .map(|e| e.edge_type)
            .unwrap_or(EdgeType::Unconditional);
        for &source_id in sources {
            for &target_id in targets {
                edges.push(PdgEdge {
                    source_id,
                    target_id,
                    dep_type: DependenceType::Control,
                    label: format!("control_{:?}", label_edge),
                });
            }
        }
    }

    // Add data dependency edges from DFG
    for dfg_edge in &dfg.edges {
        // Find the line nodes holding the def and the use
        let def_node = node_for_line.get(&dfg_edge.def_line);
        let use_node = node_for_line.get(&dfg_edge.use_line);

        if let (Some(&from_id), Some(&to_id)) = (def_node, use_node) {
            edges.push(PdgEdge {
                source_id: from_id,
                target_id: to_id,
                dep_type: DependenceType::Data,
                label: dfg_edge.var.clone(),
            });
        }
    }

    Ok(PdgInfo {
        function: function_name.to_string(),
        cfg,
        dfg,
        nodes,
        edges,
    })
}

/// Does the statement span `[s, e]` hide a DEFINITION on a row after its
/// first? (issue #80 split criterion.)
///
/// One statement defines its targets at its left-hand side — the span's first
/// row. A definition on a LATER row inside the same span means a separate
/// statement begins inside the span, i.e. the span is the CFG builder's
// container fallback that swallowed several statements, and one PDG node over
/// it would make every slice touching it return the whole line range.
fn span_hides_later_definitions(dfg: &DfgInfo, s: u32, e: u32) -> bool {
    dfg.refs.iter().any(|r| {
        r.line > s
            && r.line <= e
            && matches!(
                r.ref_type,
                crate::types::RefType::Definition | crate::types::RefType::Update
            )
    })
}

/// Control-dependence pairs `(predicate_block, dependent_block)` of a CFG,
/// computed with the standard post-dominance definition (Ferrante,
/// Ottenstein & Warren 1987): `B` is control-dependent on `A` iff `A` has a
/// successor `S` such that `B` post-dominates `S` while `B` does not strictly
/// post-dominate `A`.
///
/// A synthetic exit absorbs every sink block so `return` blocks (no outgoing
/// edges) still have post-dominators. Blocks in a cycle that cannot reach any
/// sink keep the initial full universe as their set; that degeneracy is
/// harmless here because such blocks fail the "at least two successors" gate
/// or exclude every candidate via the strict-post-dominance test. A
/// single-block CFG has no block with two successors, so it yields no control
/// pairs at all — within one basic block there is no control dependence, only
/// data dependence (issue #80's single-block case).
fn control_dependence_pairs(cfg: &CfgInfo) -> Vec<(usize, usize)> {
    let block_count = cfg.blocks.len();
    if block_count == 0 {
        return Vec::new();
    }

    let exit = block_count;
    let total = block_count + 1;
    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); block_count];
    for edge in &cfg.edges {
        if edge.from < block_count
            && edge.to < block_count
            && !successors[edge.from].contains(&edge.to)
        {
            successors[edge.from].push(edge.to);
        }
    }

    // Post-dominator sets: `pdom[b]` = every node lying on ALL paths from `b`
    // to the exit (reflexive). Naive iterated intersection — function CFGs
    // are tiny, and the sets only shrink, so this terminates.
    let universe: HashSet<usize> = (0..total).collect();
    let mut pdom: Vec<HashSet<usize>> = vec![universe; total];
    pdom[exit] = HashSet::from([exit]);

    let mut changed = true;
    while changed {
        changed = false;
        for block in 0..block_count {
            let mut next: HashSet<usize> = if successors[block].is_empty() {
                HashSet::from([exit])
            } else {
                successors[block]
                    .iter()
                    .map(|&s| pdom[s].clone())
                    .reduce(|acc, s: HashSet<usize>| acc.intersection(&s).copied().collect())
                    .unwrap_or_default()
            };
            next.insert(block);
            if next != pdom[block] {
                pdom[block] = next;
                changed = true;
            }
        }
    }

    let mut pairs = Vec::new();
    for pred in 0..block_count {
        // A block that does not branch decides nothing: control dependence
        // requires at least two successors.
        if successors[pred].len() < 2 {
            continue;
        }
        for dep in 0..block_count {
            if dep == pred {
                continue;
            }
            let postdominates_a_successor =
                successors[pred].iter().any(|&s| pdom[s].contains(&dep));
            // `dep != pred` is guaranteed above, so containment in
            // `pdom[pred]` IS strict post-dominance.
            let strictly_postdominates_pred = pdom[pred].contains(&dep);
            if postdominates_a_successor && !strictly_postdominates_pred {
                pairs.push((pred, dep));
            }
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_pdg() {
        let source = r#"
def foo(x):
    y = x + 1
    return y
"#;
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();
        assert_eq!(pdg.function, "foo");
        assert!(!pdg.nodes.is_empty());
    }

    #[test]
    fn test_pdg_has_data_dependencies() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // Should have data dependency edges for x
        let data_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Data)
            .collect();

        assert!(!data_edges.is_empty(), "should have data dependency edges");
    }

    #[test]
    fn test_pdg_has_control_dependencies() {
        let source = r#"
def foo(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"#;
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // Should have control dependency edges from the if condition
        let control_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Control)
            .collect();

        assert!(
            !control_edges.is_empty(),
            "should have control dependency edges"
        );
    }

    /// Issue #80: the code after an `if` without `else` strictly post-
    /// dominates the branch, so it must NOT be control-dependent on the
    /// condition. The branch arm must be.
    #[test]
    fn test_control_pairs_if_without_else_excludes_join() {
        let source = r#"
def foo(cond):
    y = 0
    if cond:
        x = 1
    z = y + 2
    return z
"#;
        let (cfg, _) =
            crate::cfg::get_cfg_context_with_statements(source, "foo", Language::Python).unwrap();

        let pairs = control_dependence_pairs(&cfg);
        let branch_block = cfg
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, crate::types::BlockType::Branch))
            .expect("if without else has a branch block");
        let join_block = cfg
            .blocks
            .iter()
            .find(|b| b.lines.0 >= 6 && b.lines.0 <= 7 && b.id != branch_block.id)
            .expect("join block (z = y + 2 / return z)");

        assert!(
            !pairs.contains(&(branch_block.id, join_block.id)),
            "join block must NOT be control-dependent on the branch it \
             strictly post-dominates: pairs={pairs:?} branch={} join={}",
            branch_block.id,
            join_block.id
        );
        // The then-arm itself must remain control-dependent.
        assert!(
            pairs.iter().any(|(pred, _)| *pred == branch_block.id),
            "the branch must keep at least one control-dependent arm: pairs={pairs:?}"
        );
    }

    /// Issue #80: a single-block CFG has no internal control dependence at
    /// all — pairs come only from blocks with two or more successors.
    #[test]
    fn test_control_pairs_single_block_cfg_is_empty() {
        let source = r#"
def foo():
    a = 1
    b = a + 2
    return b
"#;
        let (cfg, _) =
            crate::cfg::get_cfg_context_with_statements(source, "foo", Language::Python).unwrap();

        // Sanity: the fixture really is branch-free (no Branch/LoopHeader).
        assert!(
            !cfg.blocks
                .iter()
                .any(|b| matches!(b.block_type, crate::types::BlockType::Branch)),
            "fixture must be branch-free"
        );
        assert!(
            control_dependence_pairs(&cfg).is_empty(),
            "a branch-free CFG must produce no control-dependence pairs"
        );
    }

    /// Issue #80 split criterion: a span that defines on a later row is a
    /// swallowed container (several statements), not one statement.
    #[test]
    fn test_span_hides_later_definitions() {
        let dfg_with = crate::dfg::get_dfg_context(
            "\ndef f():\n    a = 1\n    b = 2\n    return b\n",
            "f",
            Language::Python,
        )
        .unwrap();
        assert!(
            span_hides_later_definitions(&dfg_with, 2, 4),
            "a span covering two assignments hides the definition of b on row 3"
        );

        let dfg_without = crate::dfg::get_dfg_context(
            "\ndef f(a):\n    x = compute(\n        a,\n    )\n    return x\n",
            "f",
            Language::Python,
        )
        .unwrap();
        assert!(
            !span_hides_later_definitions(&dfg_without, 3, 5),
            "a genuine multi-line call defines only on its first row"
        );
    }
}
