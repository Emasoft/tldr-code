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
use crate::types::{CfgInfo, DependenceType, DfgInfo, Language, PdgEdge, PdgInfo, PdgNode};
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

    // Add control dependency edges from CFG
    // A node B is control-dependent on A if:
    // - There's a path from A to B that B post-dominates
    // - A is a predicate (branch/loop)
    for edge in &cfg.edges {
        let from_block = cfg.blocks.iter().find(|b| b.id == edge.from);
        if let Some(block) = from_block {
            // If the source is a branch, add control dependency
            if matches!(
                block.block_type,
                crate::types::BlockType::Branch | crate::types::BlockType::LoopHeader
            ) {
                // why: every statement of the target block is control-dependent
                // on the predicate, so the block-level CFG edge expands to the
                // cross product of the two blocks' line nodes. Keeping the
                // source side whole (rather than just the condition line)
                // preserves exactly the reachability the block-granular graph
                // had, so this split cannot drop a line from a slice.
                let sources = nodes_for_block.get(&edge.from);
                let targets = nodes_for_block.get(&edge.to);
                if let (Some(sources), Some(targets)) = (sources, targets) {
                    for &source_id in sources {
                        for &target_id in targets {
                            edges.push(PdgEdge {
                                source_id,
                                target_id,
                                dep_type: DependenceType::Control,
                                label: format!("control_{:?}", edge.edge_type),
                            });
                        }
                    }
                }
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
}
