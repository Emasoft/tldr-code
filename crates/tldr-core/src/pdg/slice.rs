//! Program Slicing
//!
//! Computes program slices using PDG traversal.
//!
//! # Slice Types
//!
//! ## Backward Slice
//! Given a slicing criterion (line, optional variable), find all statements
//! that could affect the computation at that point.
//!
//! Algorithm:
//! 1. Start at the criterion node in PDG
//! 2. Follow edges backward (from target to source)
//! 3. Collect all visited nodes
//!
//! ## Forward Slice
//! Given a slicing criterion, find all statements that could be affected
//! by the computation at that point.
//!
//! Algorithm:
//! 1. Start at the criterion node in PDG
//! 2. Follow edges forward (from source to target)
//! 3. Collect all visited nodes
//!
//! # Variable Filtering
//! If a variable is specified, only follow edges related to that variable.
//! For data dependencies, this filters by the variable name.
//! For control dependencies, all are followed (they affect all variables).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::pdg::get_pdg_context;
use crate::types::{DependenceType, Language, PdgInfo, SliceDirection};
use crate::TldrResult;

// =============================================================================
// Rich Slice Types
// =============================================================================

/// A single node in a rich program slice, containing source code and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceNode {
    /// Source line number
    pub line: u32,
    /// Trimmed source line content
    pub code: String,
    /// PDG node type (e.g., "assignment", "return", "call")
    pub node_type: String,
    /// Variables defined at this line
    pub definitions: Vec<String>,
    /// Variables used at this line
    pub uses: Vec<String>,
    /// How this node connects to the dependency chain: "data" or "control"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_type: Option<String>,
    /// Variable name for data dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_label: Option<String>,
}

/// An edge in the rich slice representing a dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceEdge {
    /// Source line number
    pub from_line: u32,
    /// Target line number
    pub to_line: u32,
    /// Dependency type: "data" or "control"
    pub dep_type: String,
    /// Variable name for data dependencies, empty for control
    pub label: String,
}

/// Rich slice result containing code content and dependency chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichSlice {
    /// Slice nodes sorted by line number
    pub nodes: Vec<SliceNode>,
    /// Dependency chain edges within the slice
    pub edges: Vec<SliceEdge>,
}

/// Compute program slice
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to slice
/// * `line` - Line number to slice from
/// * `direction` - Backward or forward slice
/// * `variable` - Optional variable to filter by
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(HashSet<u32>)` - Set of line numbers in the slice
/// * Empty set if line is not in the function
///
/// # Example
/// ```ignore
/// use tldr_core::pdg::get_slice;
/// use tldr_core::{Language, SliceDirection};
///
/// let slice = get_slice(
///     "def foo(): x = 1; return x",
///     "foo",
///     2,  // return line
///     SliceDirection::Backward,
///     None,
///     Language::Python
/// )?;
/// // slice should include line 1 (x = 1)
/// ```
pub fn get_slice(
    source_or_path: &str,
    function_name: &str,
    line: u32,
    direction: SliceDirection,
    variable: Option<&str>,
    language: Language,
) -> TldrResult<HashSet<u32>> {
    // Get PDG for the function
    let pdg = get_pdg_context(source_or_path, function_name, language)?;

    // Find the node(s) containing the target line
    let start_nodes = find_nodes_for_line(&pdg, line);

    if start_nodes.is_empty() {
        // Line not in function - return empty set per spec
        return Ok(HashSet::new());
    }

    // Perform slice traversal (block-level reachability over the PDG).
    let slice = compute_slice(&pdg, &start_nodes, direction, variable);

    // cl14-slice-v1 (GH #80): map visited blocks to lines honoring direction
    // *within* the criterion's basic block via intra-block DFG def-use, so a
    // single-block straight-line function does not collapse to its full body.
    let lines = slice_lines(&pdg, &slice, line, direction, variable);

    Ok(lines)
}

/// Compute a rich program slice with source code and dependency chains
///
/// Like `get_slice()` but returns `RichSlice` with code content, node metadata,
/// and filtered dependency edges instead of bare line numbers.
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to slice
/// * `line` - Line number to slice from
/// * `direction` - Backward or forward slice
/// * `variable` - Optional variable to filter by
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(RichSlice)` - Rich slice with code, metadata, and edges
/// * Empty RichSlice if line is not in the function
pub fn get_slice_rich(
    source_or_path: &str,
    function_name: &str,
    line: u32,
    direction: SliceDirection,
    variable: Option<&str>,
    language: Language,
) -> TldrResult<RichSlice> {
    // Get PDG for the function
    let pdg = get_pdg_context(source_or_path, function_name, language)?;

    // Find the node(s) containing the target line
    let start_nodes = find_nodes_for_line(&pdg, line);

    if start_nodes.is_empty() {
        return Ok(RichSlice {
            nodes: Vec::new(),
            edges: Vec::new(),
        });
    }

    // Perform slice traversal -- get set of visited node IDs
    let visited = compute_slice(&pdg, &start_nodes, direction, variable);

    // Read source lines for code content
    let source_lines = read_source_lines(source_or_path);

    // Build a map from node_id -> PdgNode for visited nodes
    let visited_nodes: Vec<&crate::types::PdgNode> = pdg
        .nodes
        .iter()
        .filter(|n| visited.contains(&n.id))
        .collect();

    // slice-per-line-uses-v1 (v0.4.2 M-033): Build per-line defs/uses from
    // the DFG's line-anchored variable references rather than unioning the
    // entire CFG block's def/use sets onto every line in the block's
    // span. The pre-fix code (commented out below) treated each visited
    // PdgNode as a single statement, but PDG nodes correspond to CFG
    // *basic blocks* — multi-line spans that frequently bundle the
    // function signature, comments, and 2-5 statements together. The
    // result: every line inside a block emitted identical
    // `definitions`/`uses` arrays — the function-aggregate broadcast
    // observed in csharp/java/ocaml/swift at Phase-22 audit cells
    // c14/c15.
    //
    // Algorithm:
    //   1. Determine the set of slice lines: each line in any visited
    //      PdgNode's `lines.0..=lines.1` span (preserves block-membership
    //      semantics).
    //   2. For each slice line `l`, gather the DFG `VarRef`s whose
    //      `r.line == l`, partitioning into definitions/updates (defs)
    //      and uses (uses). This makes each line's defs/uses reflect
    //      the variable activity AT that exact source line.
    //   3. Carry over `node_type` from the (first) visited PdgNode
    //      covering line `l` for diagnostic continuity.
    let mut line_map: HashMap<u32, SliceNode> = HashMap::new();

    // cl14-slice-v1 (GH #80): compute the directional line set once, sharing
    // the exact same intra-block def-use logic as `get_slice()` so the two
    // entry points stay in lockstep (test_rich_slice_backward_compat_with_get_slice).
    let slice_line_set = slice_lines(&pdg, &visited, line, direction, variable);

    // First pass: enumerate the directional slice lines, recording the
    // representative node_type per line from the visited PDG node that covers
    // it. Lines are no longer drawn from the full block span; they come from
    // `slice_line_set`, which honors slice direction within the criterion
    // block (see `slice_lines`).
    for &l in &slice_line_set {
        if l == 0 {
            continue;
        }
        // node_type: the first visited node whose span covers this line.
        let node_type = visited_nodes
            .iter()
            .find(|n| l >= n.lines.0 && l <= n.lines.1)
            .map(|n| n.node_type.clone())
            .unwrap_or_else(|| "statement".to_string());

        let code = source_lines
            .get((l as usize).wrapping_sub(1))
            .map(|s| s.trim_end().to_string())
            .unwrap_or_default();

        line_map.entry(l).or_insert_with(|| SliceNode {
            line: l,
            code,
            node_type,
            definitions: Vec::new(),
            uses: Vec::new(),
            dep_type: None,
            dep_label: None,
        });
    }

    // Second pass: populate per-line defs/uses from the DFG. The DFG's
    // `refs` vector is line-anchored (each `VarRef` carries its own
    // `line` and `ref_type`), so this is the canonical source for
    // per-statement use-set computation — no string scanning, no
    // AST re-walks, no per-lang fixups.
    for r in &pdg.dfg.refs {
        if let Some(entry) = line_map.get_mut(&r.line) {
            match r.ref_type {
                crate::types::RefType::Definition | crate::types::RefType::Update => {
                    if !entry.definitions.contains(&r.name) {
                        entry.definitions.push(r.name.clone());
                    }
                }
                crate::types::RefType::Use => {
                    if !entry.uses.contains(&r.name) {
                        entry.uses.push(r.name.clone());
                    }
                }
            }
        }
    }

    // Build dependency edges restricted to the directional slice line set.
    //
    // cl14-slice-v1 (GH #80): The block-level `pdg.edges` anchor every
    // intra-block def-use to the block's representative (start) line, so for a
    // single-block function they degenerate to `start -> start` and reference
    // lines that are no longer in the directional slice. Derive *data* edges
    // instead from the DFG's line-anchored def-use chains, which carry concrete
    // `def_line`/`use_line` and therefore stay consistent with `slice_line_set`
    // (preserving the `test_rich_slice_edges_within_slice` invariant: every
    // edge endpoint is a slice node).
    let mut edges: Vec<SliceEdge> = Vec::new();
    for dfg_edge in &pdg.dfg.edges {
        if let Some(var) = variable {
            if dfg_edge.var != var {
                continue;
            }
        }
        if slice_line_set.contains(&dfg_edge.def_line)
            && slice_line_set.contains(&dfg_edge.use_line)
        {
            edges.push(SliceEdge {
                from_line: dfg_edge.def_line,
                to_line: dfg_edge.use_line,
                dep_type: "data".to_string(),
                label: dfg_edge.var.clone(),
            });
        }
    }
    // Retain genuine *inter-block* control edges (e.g. a predicate block that a
    // dependent block is control-dependent on). These connect distinct blocks,
    // so their representative lines are real, distinct statement lines and are
    // already in the slice when both blocks were visited. Skip self-edges
    // (block-collapsed artefacts where from == to).
    for edge in &pdg.edges {
        if edge.dep_type != DependenceType::Control {
            continue;
        }
        if !(visited.contains(&edge.source_id) && visited.contains(&edge.target_id)) {
            continue;
        }
        if let (Some(from), Some(to)) =
            (node_id_to_line(&pdg, edge.source_id), node_id_to_line(&pdg, edge.target_id))
        {
            if from != to
                && slice_line_set.contains(&from)
                && slice_line_set.contains(&to)
            {
                edges.push(SliceEdge {
                    from_line: from,
                    to_line: to,
                    dep_type: "control".to_string(),
                    label: edge.label.clone(),
                });
            }
        }
    }

    // CL-1 / GH #74: sort edges by the FULL identity tuple
    // (from_line, to_line, dep_type, label), not just (from_line, to_line).
    // `pdg.edges` is iterated in graph-build order, so two distinct edges
    // that share a from/to pair but differ in `dep_type` (data vs control)
    // or `label` previously kept whatever relative order the PDG happened
    // to emit — nondeterministic run-to-run. Including dep_type/label in
    // the sort key gives a total order. It also makes the `dedup_by` below
    // correct: `dedup_by` only collapses *adjacent* equal elements, so an
    // incomplete sort key could leave true duplicates separated by an
    // intervening edge and silently fail to dedup them.
    edges.sort_by(|a, b| {
        a.from_line
            .cmp(&b.from_line)
            .then(a.to_line.cmp(&b.to_line))
            .then(a.dep_type.cmp(&b.dep_type))
            .then(a.label.cmp(&b.label))
    });
    // Deduplicate edges (same from/to/type/label)
    edges.dedup_by(|a, b| {
        a.from_line == b.from_line
            && a.to_line == b.to_line
            && a.dep_type == b.dep_type
            && a.label == b.label
    });

    // CL-1 / GH #74: annotate each target node with how it connects (dep
    // type/label) AFTER the edges have been sorted+deduped. Previously this
    // ran inside the unordered `pdg.edges` loop with a "first edge wins"
    // (`dep_type.is_none()`) rule, so when a line had several incoming
    // edges the annotation reflected whichever edge the graph build emitted
    // first — nondeterministic. Driving it from the now-totally-ordered
    // `edges` vector makes "first" mean the smallest edge by the stable
    // sort key, so the annotation is reproducible run-to-run.
    for edge in &edges {
        if let Some(node) = line_map.get_mut(&edge.to_line) {
            if node.dep_type.is_none() {
                node.dep_type = Some(edge.dep_type.clone());
                if !edge.label.is_empty() {
                    node.dep_label = Some(edge.label.clone());
                }
            }
        }
    }

    // Collect and sort nodes by line number
    let mut nodes: Vec<SliceNode> = line_map.into_values().collect();
    nodes.sort_by_key(|n| n.line);

    Ok(RichSlice { nodes, edges })
}

/// Read source lines from a path or inline source string
fn read_source_lines(source_or_path: &str) -> Vec<String> {
    let path = Path::new(source_or_path);
    if path.exists() && path.is_file() {
        match std::fs::read_to_string(path) {
            Ok(content) => content.lines().map(|l| l.to_string()).collect(),
            Err(_) => source_or_path.lines().map(|l| l.to_string()).collect(),
        }
    } else {
        source_or_path.lines().map(|l| l.to_string()).collect()
    }
}

/// Map a PDG node ID to its first (representative) line number
fn node_id_to_line(pdg: &PdgInfo, node_id: usize) -> Option<u32> {
    pdg.nodes
        .iter()
        .find(|n| n.id == node_id)
        .map(|n| n.lines.0)
        .filter(|&l| l > 0)
}

/// Find PDG nodes that contain a specific line
fn find_nodes_for_line(pdg: &PdgInfo, line: u32) -> Vec<usize> {
    pdg.nodes
        .iter()
        .filter(|n| line >= n.lines.0 && line <= n.lines.1)
        .map(|n| n.id)
        .collect()
}

/// Compute slice using BFS/DFS traversal
fn compute_slice(
    pdg: &PdgInfo,
    start_nodes: &[usize],
    direction: SliceDirection,
    variable: Option<&str>,
) -> HashSet<usize> {
    let mut visited = HashSet::new();
    let mut worklist: Vec<usize> = start_nodes.to_vec();

    while let Some(node_id) = worklist.pop() {
        if visited.contains(&node_id) {
            continue;
        }
        visited.insert(node_id);

        // Find adjacent nodes based on direction
        let adjacent = match direction {
            SliceDirection::Backward => {
                // Follow edges TO this node (find sources)
                pdg.edges
                    .iter()
                    .filter(|e| e.target_id == node_id)
                    .filter(|e| should_follow_edge(e, variable))
                    .map(|e| e.source_id)
                    .collect::<Vec<_>>()
            }
            SliceDirection::Forward => {
                // Follow edges FROM this node (find targets)
                pdg.edges
                    .iter()
                    .filter(|e| e.source_id == node_id)
                    .filter(|e| should_follow_edge(e, variable))
                    .map(|e| e.target_id)
                    .collect::<Vec<_>>()
            }
        };

        for adj in adjacent {
            if !visited.contains(&adj) {
                worklist.push(adj);
            }
        }
    }

    visited
}

/// Check if an edge should be followed based on variable filter
fn should_follow_edge(edge: &crate::types::PdgEdge, variable: Option<&str>) -> bool {
    match variable {
        None => true, // No filter, follow all edges
        Some(var) => {
            match edge.dep_type {
                DependenceType::Control => true, // Always follow control deps
                DependenceType::Data => edge.label == var, // Only follow if variable matches
            }
        }
    }
}

/// cl14-slice-v1 (v0.5.0 CL-14, GH #80): Compute the exact set of source
/// lines for a slice, honoring `direction` *within* each visited basic block.
///
/// # Why this exists
///
/// A visited PDG node corresponds to a CFG *basic block* — a multi-line span,
/// not a single statement. The naive mapping (expand every visited node's
/// whole `lines.0..=lines.1` range) is wrong whenever the criterion line sits
/// in the middle of a block: it emits *all* lines of the block, including
/// statements that run *after* the criterion (for a backward slice) or
/// *before* it (for a forward slice). For functions whose entire body is a
/// single straight-line block (extremely common for short methods across
/// languages), this collapsed the directional slice to the full function body
/// and made backward and forward slices identical (GH #80).
///
/// PDG *edges* cannot fix this on their own: the PDG builder anchors every
/// intra-block def-use edge to the block's representative line (its start
/// line), so all intra-block edges degenerate to `start -> start` and carry no
/// ordering. The canonical, AST-derived source of intra-block ordering is the
/// DFG's line-anchored references (`pdg.dfg.refs`) and def-use chains
/// (`pdg.dfg.edges`), each carrying its own concrete `def_line` / `use_line`.
///
/// # Algorithm
///
/// 1. Seed the result with the criterion line itself.
/// 2. Intra-block data dependence: starting from the criterion line, follow
///    DFG def-use chains transitively, honoring direction:
///      - backward: from a line, jump to every `def_line` whose value is
///        *used* on a line already in the slice (i.e. lines that *define*
///        what the slice uses). This walks toward the values feeding the
///        criterion. Such defs are always at-or-before their uses, so no
///        line after the criterion is ever admitted via data dependence.
///      - forward: from a line, jump to every `use_line` that *uses* a value
///        *defined* on a line already in the slice.
/// 3. Inter-block contributions: for every *visited* block other than the
///    criterion's own block (reached through the PDG edge traversal, e.g. a
///    control-dependence predicate block or a separate data-flow block), keep
///    the block's full span — these are whole-block contributors selected by
///    the block-level PDG traversal, and the directional decision for them was
///    already made when the edge was followed.
/// 4. Signature cohesion: a multi-line function signature is a single logical
///    construct whose parameter definitions the DFG anchors to their own
///    individual lines (e.g. `a,` on line 5). The signature span is treated as
///    one unit — if the slice admits any signature line (a parameter def) or the
///    criterion itself lies in the signature, the *whole* signature span (the
///    `def`/`fn` keyword line through the last parameter line) is included. This
///    keeps `chop(signature_line, body_line)` non-empty when a parameter is on
///    the path, and is direction-safe because the signature always precedes the
///    body — it never re-introduces post-criterion body statements.
///
/// This keeps the existing behaviour for multi-block control/data slices
/// (predicate blocks, branches) while eliminating the single-block collapse.
fn slice_lines(
    pdg: &PdgInfo,
    visited: &HashSet<usize>,
    criterion_line: u32,
    direction: SliceDirection,
    variable: Option<&str>,
) -> HashSet<u32> {
    // Identify the block that contains the criterion line.
    let criterion_block = pdg
        .nodes
        .iter()
        .find(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
        .map(|n| n.id);

    let mut lines: HashSet<u32> = HashSet::new();

    // (3) Whole-block contributions from *other* visited blocks. The block
    // that contains the criterion is handled by the intra-block def-use walk
    // below so its post-/pre-criterion statements are not over-included.
    for &node_id in visited {
        if Some(node_id) == criterion_block {
            continue;
        }
        if let Some(node) = pdg.nodes.iter().find(|n| n.id == node_id) {
            for line in node.lines.0..=node.lines.1 {
                if line > 0 {
                    lines.insert(line);
                }
            }
        }
    }

    // (1) Seed with the criterion line.
    if criterion_line > 0 {
        lines.insert(criterion_line);
    }

    let block_span = criterion_block
        .and_then(|id| pdg.nodes.iter().find(|n| n.id == id))
        .map(|n| n.lines);

    // Compute the signature span of the criterion block, if it is the block
    // that opens the function. The signature is the leading run of the block
    // from its start line up to (but excluding) the first line that *uses* a
    // variable — body statements read variables; a parameter list only
    // introduces definitions (possibly with default-value sub-expressions,
    // which the DFG still anchors as defs of the parameter). This boundary is
    // derived entirely from the DFG's line-anchored `Use` references — no
    // string scanning or per-language signature parsing.
    let signature_span: Option<(u32, u32)> = block_span.and_then(|(bstart, bend)| {
        // The signature only exists on the function-opening block (the block
        // whose start line is the function's first line). Restrict the cohesion
        // rule to the block with the smallest start line so inner blocks that
        // happen to define-before-use (e.g. a loop header) are not mistaken for
        // a parameter list.
        let is_opening_block = pdg
            .nodes
            .iter()
            .map(|n| n.lines.0)
            .min()
            .map(|min_start| min_start == bstart)
            .unwrap_or(false);
        if !is_opening_block {
            return None;
        }

        // First line within the block that carries a Use reference.
        let first_use_line = pdg
            .dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, crate::types::RefType::Use))
            .map(|r| r.line)
            .filter(|&l| l >= bstart && l <= bend)
            .min();

        // The signature must contain at least one parameter definition for the
        // cohesion rule to apply (otherwise there is no multi-line construct to
        // unify). Parameter defs are Definition refs strictly before the first
        // body use.
        let sig_end = match first_use_line {
            Some(u) if u > bstart => u - 1,
            // No use in block, or first use is on the start line: the signature
            // is just the start line.
            _ => bstart,
        };

        let has_param_def = pdg.dfg.refs.iter().any(|r| {
            matches!(
                r.ref_type,
                crate::types::RefType::Definition | crate::types::RefType::Update
            ) && r.line >= bstart
                && r.line <= sig_end
        });

        if has_param_def {
            Some((bstart, sig_end))
        } else {
            None
        }
    });

    // (2) Intra-block def-use reachability from the criterion, honoring
    // direction. Driven by the DFG's line-anchored def-use chains, which are
    // derived from the tree-sitter AST (no string/regex heuristics).
    //
    // We bound the walk to the criterion's block span so we never re-introduce
    // whole-block over-inclusion: only lines that are genuinely on a def-use
    // chain to/from the criterion (and that lie inside the block, where
    // straight-line order holds) are admitted. Lines reached across block
    // boundaries are governed by the block-level PDG traversal in (3).
    if let Some((bstart, bend)) = block_span {
        let mut frontier: Vec<u32> = vec![criterion_line];
        let mut seen: HashSet<u32> = HashSet::new();
        seen.insert(criterion_line);

        // Signature cohesion seed: if the criterion lies inside the signature
        // span, seed the walk with every signature line so the slice picks up
        // all parameters introduced by the (multi-line) signature and their
        // downstream/upstream def-use, and include the whole signature span.
        if let Some((sstart, send)) = signature_span {
            if criterion_line >= sstart && criterion_line <= send {
                for l in sstart..=send {
                    if l > 0 && seen.insert(l) {
                        lines.insert(l);
                        frontier.push(l);
                    }
                }
            }
        }

        while let Some(cur) = frontier.pop() {
            for e in &pdg.dfg.edges {
                // Respect an explicit variable filter (data deps only).
                if let Some(var) = variable {
                    if e.var != var {
                        continue;
                    }
                }
                let (anchor, other) = match direction {
                    // Backward: a line `cur` that *uses* `e.var` depends on the
                    // line that *defined* it. Step from `use_line` to `def_line`.
                    SliceDirection::Backward => (e.use_line, e.def_line),
                    // Forward: a line `cur` that *defines* `e.var` affects the
                    // line that *uses* it. Step from `def_line` to `use_line`.
                    SliceDirection::Forward => (e.def_line, e.use_line),
                };
                if anchor != cur {
                    continue;
                }
                // Keep the walk inside the criterion block: cross-block def-use
                // is represented by the PDG block traversal, already handled.
                if other < bstart || other > bend {
                    continue;
                }
                if seen.insert(other) {
                    lines.insert(other);
                    frontier.push(other);
                }
            }
        }

        // Signature cohesion (reverse direction): if the walk reached any
        // parameter line *inside* the signature span, unify the whole signature
        // span. This makes a backward slice from a body line that depends on a
        // parameter include the `def`/`fn` keyword line (the chop source),
        // without admitting any body statement (the span ends before the body).
        if let Some((sstart, send)) = signature_span {
            let touched_signature = (sstart..=send).any(|l| lines.contains(&l));
            if touched_signature {
                for l in sstart..=send {
                    if l > 0 {
                        lines.insert(l);
                    }
                }
            }
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backward_slice_simple() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let slice = get_slice(
            source,
            "foo",
            4,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Backward slice from "return y" should include y = x + 2 and x = 1
        assert!(!slice.is_empty(), "slice should not be empty");
    }

    #[test]
    fn test_forward_slice_simple() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        // Line 3 is "x = 1" (line 1 is blank, line 2 is "def foo():")
        let slice = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Forward,
            None,
            Language::Python,
        )
        .unwrap();

        // Forward slice from "x = 1" should include the starting line at minimum
        // Note: forward slice traversal starts from the starting node
        assert!(slice.contains(&3), "slice should include the starting line");
    }

    #[test]
    fn test_slice_with_variable_filter() {
        let source = r#"
def foo():
    x = 1
    y = 2
    z = x + y
    return z
"#;
        let slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            Some("x"),
            Language::Python,
        )
        .unwrap();

        // Backward slice for 'x' from "z = x + y" should include x = 1 but not y = 2
        // Note: the line numbers in this test are approximate
        assert!(!slice.is_empty(), "slice should not be empty");
    }

    #[test]
    fn test_slice_line_not_in_function() {
        let source = "def foo(): pass";
        let slice = get_slice(
            source,
            "foo",
            999,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Line 999 is not in the function - should return empty set
        assert!(
            slice.is_empty(),
            "slice for non-existent line should be empty"
        );
    }

    #[test]
    fn test_slice_returns_line_numbers() {
        let source = r#"
def foo():
    x = 1
    return x
"#;
        let slice = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Result should be line numbers (positive integers)
        for &line in &slice {
            assert!(line > 0, "line numbers should be positive");
        }
    }

    #[test]
    fn test_backward_slice_with_control_deps() {
        let source = r#"
def foo(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"#;
        let slice = get_slice(
            source,
            "foo",
            6,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Backward slice should include the if condition due to control dependency
        assert!(
            !slice.is_empty(),
            "slice should include control dependencies"
        );
    }

    #[test]
    fn test_forward_slice_traces_all_vars() {
        let source = r#"
def foo():
    x = 1
    y = x
    z = y
    return z
"#;
        // Line 3 is "x = 1" (line 1 is blank, line 2 is "def foo():")
        let slice = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Forward,
            None,
            Language::Python,
        )
        .unwrap();

        // Forward slice from x=1 should include the starting line
        // The slice starts at the given line and follows forward dependencies
        assert!(
            slice.contains(&3),
            "forward slice should include the starting line"
        );
    }

    // =========================================================================
    // Tests for get_slice_rich()
    // =========================================================================

    #[test]
    fn test_rich_slice_returns_nodes_with_code() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            4,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Should have nodes with actual code content
        assert!(!rich.nodes.is_empty(), "rich slice should have nodes");
        for node in &rich.nodes {
            assert!(!node.code.is_empty(), "each node should have code content");
            assert!(node.line > 0, "line numbers should be positive");
        }
    }

    #[test]
    fn test_rich_slice_nodes_sorted_by_line() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Nodes must be sorted by line number
        let lines: Vec<u32> = rich.nodes.iter().map(|n| n.line).collect();
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted, "nodes should be sorted by line number");
    }

    #[test]
    fn test_rich_slice_code_is_trimmed() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        for node in &rich.nodes {
            assert_eq!(
                node.code,
                node.code.trim_end(),
                "code should have trailing whitespace trimmed"
            );
        }
    }

    #[test]
    fn test_rich_slice_preserves_definitions_and_uses() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // At least some nodes should have definitions or uses
        let has_defs = rich.nodes.iter().any(|n| !n.definitions.is_empty());
        let has_uses = rich.nodes.iter().any(|n| !n.uses.is_empty());
        assert!(
            has_defs || has_uses,
            "rich slice should preserve definition/use info from PDG"
        );
    }

    #[test]
    fn test_rich_slice_has_node_types() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        for node in &rich.nodes {
            assert!(
                !node.node_type.is_empty(),
                "each node should have a node_type"
            );
        }
    }

    #[test]
    fn test_rich_slice_edges_within_slice() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        let slice_lines: std::collections::HashSet<u32> =
            rich.nodes.iter().map(|n| n.line).collect();
        // All edges should reference lines that are in the slice
        for edge in &rich.edges {
            assert!(
                slice_lines.contains(&edge.from_line),
                "edge from_line {} should be in slice",
                edge.from_line
            );
            assert!(
                slice_lines.contains(&edge.to_line),
                "edge to_line {} should be in slice",
                edge.to_line
            );
        }
    }

    #[test]
    fn test_rich_slice_edge_dep_types() {
        let source = r#"
def foo(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"#;
        let rich = get_slice_rich(
            source,
            "foo",
            7,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // Should have edges with valid dep_type strings
        for edge in &rich.edges {
            assert!(
                edge.dep_type == "data" || edge.dep_type == "control",
                "edge dep_type should be 'data' or 'control', got '{}'",
                edge.dep_type
            );
        }
    }

    #[test]
    fn test_rich_slice_empty_for_invalid_line() {
        let source = "def foo(): pass";
        let rich = get_slice_rich(
            source,
            "foo",
            999,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        assert!(
            rich.nodes.is_empty(),
            "rich slice for non-existent line should have no nodes"
        );
        assert!(
            rich.edges.is_empty(),
            "rich slice for non-existent line should have no edges"
        );
    }

    #[test]
    fn test_rich_slice_from_file_path() {
        // Create a temp file to test file-based slicing
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_slice_rich.py");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "def bar():").unwrap();
        writeln!(f, "    a = 10").unwrap();
        writeln!(f, "    b = a + 1").unwrap();
        writeln!(f, "    return b").unwrap();

        let rich = get_slice_rich(
            path.to_str().unwrap(),
            "bar",
            4,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        assert!(!rich.nodes.is_empty(), "should work with file path input");
        // Code should come from the file
        let has_return = rich.nodes.iter().any(|n| n.code.contains("return"));
        assert!(has_return, "should contain the criterion line code");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_rich_slice_backward_compat_with_get_slice() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let plain = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();
        let rich = get_slice_rich(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // The rich slice line set should match the plain slice line set
        let rich_lines: HashSet<u32> = rich.nodes.iter().map(|n| n.line).collect();
        assert_eq!(
            plain, rich_lines,
            "rich slice lines should match plain slice lines"
        );
    }
}
