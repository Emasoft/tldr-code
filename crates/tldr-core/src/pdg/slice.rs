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

use crate::pdg::get_pdg_context_with_line;
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
    // body-aware-fn-resolution-v1 (B1): pass the criterion line so the PDG
    // is built for the definition whose range contains it (the concrete
    // impl), not the first same-named (possibly body-less) declaration.
    let pdg = get_pdg_context_with_line(source_or_path, function_name, Some(line), language)?;

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
    // body-aware-fn-resolution-v1 (B1): line-aware PDG (see `get_slice`).
    let pdg = get_pdg_context_with_line(source_or_path, function_name, Some(line), language)?;

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
                // rc3: a weak element/field write `xs[i] = …` reads the base
                // (a use); it does NOT rebind `xs`, so it is not a slice def.
                crate::types::RefType::Use | crate::types::RefType::WeakUpdate => {
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

/// cl2-slice-v1 (v0.5.0 CL-2, GH #80): Compute the exact set of source lines
/// for a slice, honoring `direction` with *line-precise* backward/forward
/// reachability — never the full basic-block range.
///
/// # Why this exists
///
/// A visited PDG node corresponds to a CFG *basic block* — a multi-line span,
/// not a single statement. The previous mapping expanded each contributing
/// block's whole `lines.0..=lines.1` range (and, for the criterion's own block,
/// the entire directional *half* `bstart..=criterion`). Both over-include:
/// every comment, blank line, and unrelated statement that merely shares a
/// block with a real dependency was emitted. On single/coarse-block CFGs this
/// degenerated to "the whole block prefix/suffix" (GH #80: c/cpp/go/luau/rust
/// slice + rust chop). Symmetrically, when the criterion line fell in a CFG
/// *gap* (a block the builder never created — e.g. a Swift else-branch
/// trailing-closure body) the slice collapsed to EMPTY (swift `_heapify`).
///
/// # Algorithm (fully line-anchored, AST-derived)
///
/// Every dependency edge in the DFG (`pdg.dfg.edges`) carries its own concrete
/// `def_line` / `use_line`, and every PDG control edge identifies a predicate
/// *block* whose representative line (`lines.0`) is the controlling statement.
/// Both are produced from the tree-sitter AST — no string/regex heuristics.
///
/// 1. Seed the result with the criterion line itself.
/// 2. Data dependence (transitive, line-precise): walk DFG def-use chains.
///      - backward: from a line `cur` that *uses* a value, jump to its
///        `def_line` (the line that produced the value). Defs are at-or-before
///        their uses, so no line after the criterion is ever admitted.
///      - forward: from a line `cur` that *defines* a value, jump to its
///        `use_line`.
///    When a `variable` filter is supplied only edges for that variable are
///    followed (the data-only slice the caller asked for).
/// 3. Control dependence (line-precise): the criterion, and every line admitted
///    above, may be guarded by a predicate. For each slice line, find the PDG
///    block(s) covering it and follow control edges to the controlling
///    predicate block, adding that predicate's line (transitively up the
///    control tree). Control deps are not variable-filtered (a predicate
///    affects every statement it guards). For a forward slice we additionally
///    admit the lines of blocks that the criterion's block *controls* (the code
///    whose execution the criterion decides), clipped to at-or-after the
///    criterion so a forward slice never reaches backwards.
/// 4. Signature cohesion: a multi-line function signature is one logical
///    construct whose parameter defs the DFG anchors to their own lines. If the
///    slice admits any signature line, or the criterion lies in the signature,
///    the whole signature span (decl-keyword line through last parameter line)
///    is unified. This keeps `chop(signature_line, body_line)` non-empty and is
///    direction-safe (the signature always precedes the body).
fn slice_lines(
    pdg: &PdgInfo,
    _visited: &HashSet<usize>,
    criterion_line: u32,
    direction: SliceDirection,
    variable: Option<&str>,
) -> HashSet<u32> {
    let mut lines: HashSet<u32> = HashSet::new();

    // (1) Seed with the criterion line.
    if criterion_line > 0 {
        lines.insert(criterion_line);
    }
    if criterion_line == 0 {
        return lines;
    }

    // (2) Data dependence closure over the DFG's line-anchored def-use edges.
    //
    // fix-R7 (cluster[11] RC5): this closure is now RE-RUNNABLE from an
    // arbitrary seed frontier so the control-dependence pass (step 3) can feed
    // newly-admitted predicate lines back through it, giving a JOINT data+control
    // fixpoint. Previously the data closure ran ONCE from the criterion and the
    // control pass ran afterwards as a one-shot, so a definition used ONLY by a
    // control predicate (sds.c `avail`@206 used by guard@212) was dropped: the
    // guard line was added but its own data dependency was never resolved.
    let mut seen: HashSet<u32> = HashSet::new();
    seen.insert(criterion_line);
    let run_data_closure =
        |lines: &mut HashSet<u32>, seen: &mut HashSet<u32>, seed: Vec<u32>| {
            let mut frontier = seed;
            while let Some(cur) = frontier.pop() {
                for e in &pdg.dfg.edges {
                    if let Some(var) = variable {
                        if e.var != var {
                            continue;
                        }
                    }
                    let (anchor, other) = match direction {
                        // Backward: `cur` uses a value defined at `def_line`.
                        SliceDirection::Backward => (e.use_line, e.def_line),
                        // Forward: `cur` defines a value used at `use_line`.
                        SliceDirection::Forward => (e.def_line, e.use_line),
                    };
                    if anchor != cur || other == 0 {
                        continue;
                    }
                    if seen.insert(other) {
                        lines.insert(other);
                        frontier.push(other);
                    }
                }
            }
        };
    run_data_closure(&mut lines, &mut seen, vec![criterion_line]);

    // (2b) Sparse-DFG directional ref-half. Several backends emit a *sparse*
    // def-use graph: notably OCaml `let .. in` chains (and some C/C++ prologues)
    // materialize no `dfg.edges` at all, so the data closure above admits
    // nothing beyond the criterion and the slice collapses to a single line.
    //
    // The structural, AST-derived recovery that does NOT depend on def-use
    // edges is the criterion's own basic block: within a straight-line block,
    // source line order equals execution order, so the directional slice of the
    // block is the half on the correct side of the criterion. But the *whole*
    // half over-includes comments and blank lines (GH #80 over-inclusion on
    // c/cpp/go/luau/rust). We therefore restrict the half to lines that carry a
    // DFG *reference* (a Definition/Update/Use anchored by tree-sitter to that
    // exact line). Comments, blank lines, and pure-syntax lines carry no ref
    // and are excluded; only real def/use sites survive.
    //
    // The block span is the union of every PDG block covering the criterion
    // (the criterion can lie in both a coarse entry block and a tight statement
    // block); the union keeps OCaml's coarse `let .. in` block reachable while
    // the per-line ref filter prevents over-inclusion.
    //
    // cf1-s13 (anti over-inclusion gate): this block-half recovery is a FALLBACK
    // for a criterion the precise closures cannot reach — it has neither a data
    // dependence (the def-use closure above admitted nothing) nor a control
    // dependence (no guarding predicate). When EITHER exists, steps (2)/(3)
    // already carry the slice precisely and the blunt half-recovery only drags
    // in unrelated block siblings: an OCaml `let res` pulling in the independent
    // `let start` that shares its coarse entry block, or a Solidity bare
    // declaration pulling in a sibling assignment that shares the post-`require`
    // body block. So only run it when the criterion is dependency-isolated.
    //
    // Skipped under an explicit `variable` filter (pure data slice on that var).
    let data_found = lines.len() > 1;
    let control_found = pdg.edges.iter().any(|e| {
        matches!(e.dep_type, DependenceType::Control)
            && pdg.nodes.iter().any(|n| {
                n.id == e.target_id
                    && criterion_line >= n.lines.0
                    && criterion_line <= n.lines.1
            })
            && pdg
                .nodes
                .iter()
                .any(|n| n.id == e.source_id && n.lines.0 <= criterion_line)
    });
    if variable.is_none() && !data_found && !control_found {
        let block_lo = pdg
            .nodes
            .iter()
            .filter(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
            .map(|n| n.lines.0)
            .min();
        let block_hi = pdg
            .nodes
            .iter()
            .filter(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
            .map(|n| n.lines.1)
            .max();
        if let (Some(blo), Some(bhi)) = (block_lo, block_hi) {
            // stmt-edge-v1 (R3-r7-cl11): collect the block's on-side ref lines,
            // then SEED the data closure from them (mirroring the RC5
            // control-predicate re-run below). A criterion that carries no
            // def-use edge of its own — e.g. a function's closing brace, whose
            // tight block also holds the implicit-return use `bytes` — admits
            // that sibling ref line via block recovery but, pre-fix, never
            // explored ITS data dependencies, so `backward(brace)` collapsed to
            // {brace, return-use} and `chop(value-def, brace)` reported no path.
            // Re-seeding the (already re-runnable) closure from these lines pulls
            // in the transitive defs (`bytes`@def -> `value`@def) in the slice
            // direction, leaving forward/backward semantics otherwise unchanged.
            let mut block_seeds: Vec<u32> = Vec::new();
            for r in &pdg.dfg.refs {
                if r.line < blo || r.line > bhi {
                    continue;
                }
                let on_side = match direction {
                    SliceDirection::Backward => r.line <= criterion_line,
                    SliceDirection::Forward => r.line >= criterion_line,
                };
                if on_side && r.line > 0 {
                    lines.insert(r.line);
                    block_seeds.push(r.line);
                }
            }
            run_data_closure(&mut lines, &mut seen, block_seeds);
        }
    }

    // CFr-RW6 (v0.5.0 RC CF-resid): detect a dependency-isolated BARE
    // DECLARATION criterion. A hoisted `uint256 id;` (no initializer) whose
    // name is only assigned in OTHER blocks (e.g. a later loop body) has an
    // empty genuine backward dependence: nothing defines a value it reads, and
    // its own enclosing block computes the name nowhere else. The CFG lowers
    // such a declaration into a coarse continuation block that ALSO holds the
    // preceding `require(...)` guard (the block start IS the guard line); the
    // block's control-dependence on that guard then grafts the guard — and the
    // guard's own data dep, an unrelated parameter — onto the declaration,
    // yielding a disconnected slice ({param, require, decl}). When this holds,
    // the backward control closure below must NOT climb to a guard the
    // declaration does not genuinely depend on.
    //
    // This is strictly NARROWER than S13's inline `uint256 d;`: there the value
    // IS computed in the SAME guarded block (`d = c + 1;`), so the declared
    // name recurs within the block and the require stays a real
    // control-dependence (correctly KEPT). The recurrence test is what
    // separates a genuinely-guarded local from a merely-hoisted declaration —
    // both derived from tree-sitter-anchored DFG refs and CFG block ranges, no
    // string/name heuristics.
    let criterion_is_isolated_bare_decl = matches!(direction, SliceDirection::Backward)
        && variable.is_none()
        && {
            let mut has_def = false;
            let mut has_non_def = false;
            let mut crit_vars: Vec<&str> = Vec::new();
            for r in &pdg.dfg.refs {
                if r.line != criterion_line {
                    continue;
                }
                match r.ref_type {
                    crate::types::RefType::Definition => {
                        has_def = true;
                        crit_vars.push(r.name.as_str());
                    }
                    _ => has_non_def = true,
                }
            }
            let no_incoming_data = !pdg.dfg.edges.iter().any(|e| e.use_line == criterion_line);
            if has_def && !has_non_def && no_incoming_data {
                let block_lo = pdg
                    .nodes
                    .iter()
                    .filter(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
                    .map(|n| n.lines.0)
                    .min();
                let block_hi = pdg
                    .nodes
                    .iter()
                    .filter(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
                    .map(|n| n.lines.1)
                    .max();
                match (block_lo, block_hi) {
                    (Some(blo), Some(bhi)) => {
                        // The declared name must recur nowhere else in the
                        // criterion's enclosing block. A recurrence (S13's
                        // `d = c + 1;`) means the block genuinely computes the
                        // guarded value, keeping the guard a real
                        // control-dependence.
                        let var_recurs_in_block = pdg.dfg.refs.iter().any(|r| {
                            r.line != criterion_line
                                && r.line >= blo
                                && r.line <= bhi
                                && crit_vars.contains(&r.name.as_str())
                        });
                        // The guard must be DEGENERATELY LUMPED: a control
                        // predicate that guards the criterion has its OWN line
                        // inside the criterion's coarse block (the `require`
                        // shares the continuation block). A predicate in a
                        // SEPARATE earlier block is a genuine branch guard
                        // (e.g. a real `if`, RC5's `if avail > 0:`) and stays.
                        let guard_lumped_in_block = pdg.edges.iter().any(|e| {
                            matches!(e.dep_type, DependenceType::Control)
                                && pdg.nodes.iter().any(|n| {
                                    n.id == e.target_id
                                        && criterion_line >= n.lines.0
                                        && criterion_line <= n.lines.1
                                })
                                && pdg.nodes.iter().any(|n| {
                                    n.id == e.source_id
                                        && n.lines.0 >= blo
                                        && n.lines.0 <= bhi
                                })
                        });
                        !var_recurs_in_block && guard_lumped_in_block
                    }
                    _ => false,
                }
            } else {
                false
            }
        };

    // (3) Control dependence closure. Build a quick map: which blocks does each
    // line belong to, and for each block, what is its controlling predicate
    // block (the source of an incoming Control edge). Predicate line = the
    // controlling block's start line.
    //
    // Skipped for an explicit `variable` filter: that requests a pure data
    // slice on the named variable, and control predicates would re-introduce
    // unrelated guard lines.
    if variable.is_none() {
        // For a forward slice, admit the lines of the blocks the criterion's
        // block transitively *controls* (code whose execution it decides),
        // clipped to at-or-after the criterion.
        if matches!(direction, SliceDirection::Forward) {
            // Block id(s) covering the criterion.
            let crit_blocks: Vec<usize> = pdg
                .nodes
                .iter()
                .filter(|n| criterion_line >= n.lines.0 && criterion_line <= n.lines.1)
                .map(|n| n.id)
                .collect();
            let mut ctrl_frontier: Vec<usize> = crit_blocks.clone();
            let mut ctrl_seen: HashSet<usize> = crit_blocks.into_iter().collect();
            while let Some(b) = ctrl_frontier.pop() {
                for edge in &pdg.edges {
                    if !matches!(edge.dep_type, DependenceType::Control) {
                        continue;
                    }
                    if edge.source_id != b {
                        continue;
                    }
                    if ctrl_seen.insert(edge.target_id) {
                        ctrl_frontier.push(edge.target_id);
                        if let Some(node) =
                            pdg.nodes.iter().find(|n| n.id == edge.target_id)
                        {
                            for l in node.lines.0..=node.lines.1 {
                                if l >= criterion_line {
                                    lines.insert(l);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Backward (and, for forward, the predicates guarding the criterion):
        // climb the control tree from every slice line to its controlling
        // predicate(s), adding the predicate lines. A predicate always precedes
        // the statement it guards, so this is direction-safe for backward and
        // adds only at-or-before lines that genuinely gate the criterion.
        let mut ctrl_lines: Vec<u32> = lines.iter().copied().collect();
        let mut ctrl_seen_lines: HashSet<u32> = lines.iter().copied().collect();
        while let Some(cur) = ctrl_lines.pop() {
            // CFr-RW6: a dependency-isolated bare declaration has no genuine
            // control dependence — do not climb to (and graft) the guard that
            // merely shares its coarse continuation block. A bare-decl criterion
            // with no data dependence has no other slice line, so this is the
            // only frontier entry; suppressing it yields the criterion's true
            // (empty) backward closure instead of {param, require, decl}.
            if criterion_is_isolated_bare_decl && cur == criterion_line {
                continue;
            }
            // Blocks covering `cur`.
            let blocks: Vec<usize> = pdg
                .nodes
                .iter()
                .filter(|n| cur >= n.lines.0 && cur <= n.lines.1)
                .map(|n| n.id)
                .collect();
            for b in blocks {
                for edge in &pdg.edges {
                    if !matches!(edge.dep_type, DependenceType::Control) {
                        continue;
                    }
                    if edge.target_id != b {
                        continue;
                    }
                    if let Some(pred) = pdg.nodes.iter().find(|n| n.id == edge.source_id) {
                        let pline = pred.lines.0;
                        // Backward: only guards at-or-before the criterion.
                        if matches!(direction, SliceDirection::Backward)
                            && pline > criterion_line
                        {
                            continue;
                        }
                        if pline > 0 && ctrl_seen_lines.insert(pline) {
                            lines.insert(pline);
                            ctrl_lines.push(pline);
                            // fix-R7 (cluster[11] RC5): a control predicate has
                            // its OWN data dependencies (the guard `if avail > 0`
                            // reads `avail`). Re-run the data closure seeded from
                            // the predicate line so those defs are pulled in
                            // (JOINT fixpoint). Any lines the data closure newly
                            // admits are themselves enqueued for control
                            // resolution so the interleave runs to a fixpoint.
                            let before: HashSet<u32> = lines.clone();
                            run_data_closure(&mut lines, &mut seen, vec![pline]);
                            for &nl in lines.difference(&before) {
                                if ctrl_seen_lines.insert(nl) {
                                    ctrl_lines.push(nl);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // (4) Signature cohesion. The signature lives on the function-opening block
    // (smallest start line). Its span runs from the block start up to (but
    // excluding) the first line that *uses* a variable — body statements read
    // variables; a parameter list only introduces definitions. Derived purely
    // from the DFG's line-anchored refs.
    let opening_block: Option<(u32, u32)> = pdg
        .nodes
        .iter()
        .min_by_key(|n| n.lines.0)
        .map(|n| n.lines);
    // cf1-s13: a genuine signature block is TIGHT — it precedes the body and is
    // followed by separate statement/branch blocks. When the opening block
    // instead spans the WHOLE function (OCaml lowers a `let .. in` chain to a
    // single coarse entry block whose range reaches the function's last line),
    // its "first use" lands deep in the body and the naive `[bstart, first_use-1]`
    // span swallows body `let` bindings as if they were parameters — re-pulling
    // the very `let start` the over-inclusion gate just excluded. For such a
    // coarse block the OCaml signature is exactly its first line (the `let f x =`
    // keyword line carries the parameters), so clamp the span there.
    let function_last_line = pdg.nodes.iter().map(|n| n.lines.1).max().unwrap_or(0);
    let signature_span: Option<(u32, u32)> = opening_block.and_then(|(bstart, bend)| {
        let coarse_whole_function = bend >= function_last_line;
        let first_use_line = pdg
            .dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, crate::types::RefType::Use))
            .map(|r| r.line)
            .filter(|&l| l >= bstart && l <= bend)
            .min();
        let sig_end = if coarse_whole_function {
            bstart
        } else {
            match first_use_line {
                Some(u) if u > bstart => u - 1,
                _ => bstart,
            }
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

    if let Some((sstart, send)) = signature_span {
        let criterion_in_sig = criterion_line >= sstart && criterion_line <= send;
        let touched_signature = (sstart..=send).any(|l| lines.contains(&l));
        if criterion_in_sig || touched_signature {
            for l in sstart..=send {
                if l > 0 {
                    lines.insert(l);
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

    // =====================================================================
    // stmt-edge-v1 (R3-r7-cl11): a backward slice through a MULTI-LINE RHS
    // (`let bytes = match s {..value..}`, `if/else`, block-tail, the
    // C/Go/TS/Python ternary & switch analogues) must reach the def of the
    // cross-variable it is computed FROM. (All fixtures carry a leading
    // newline, so line 1 is blank.)
    // =====================================================================

    #[test]
    fn test_slice_rust_match_arm_reaches_cross_var_def() {
        // 3=`let digits`, 4=`let value`, 5=`let bytes = match s {`,
        // 6/7/8=arms, 9=`};`, 10=`bytes`.
        let source = r#"
fn parse(s: &str) -> u64 {
    let digits = "100";
    let value: u64 = digits.parse().unwrap();
    let bytes = match s {
        "KB" => value.checked_mul(1024).unwrap(),
        "MB" => value.checked_mul(1024 * 1024).unwrap(),
        _ => value,
    };
    bytes
}
"#;
        let slice = get_slice(source, "parse", 10, SliceDirection::Backward, None, Language::Rust)
            .unwrap();
        assert!(
            slice.contains(&4),
            "backward slice of `bytes` must reach the def of `value`@4; got {slice:?}"
        );
        // The scattered match-arm read lines must NOT be pulled in (the edge is
        // anchored on `value`'s DEF, not its reads).
        assert!(
            !slice.contains(&6) && !slice.contains(&7),
            "match-arm read lines must stay out of the slice; got {slice:?}"
        );
    }

    #[test]
    fn test_slice_rust_match_chop_reaches_through_closing_brace() {
        // The proposal's `chop … 3 10` repro: `compute_chop` reports a path iff
        // `backward(target).contains(source)`. Here target = line 11 (the
        // closing brace), source = line 4 (`value`'s def). Pre-fix the backward
        // slice of the brace collapsed to {return-use, brace} and never reached
        // `value`; the cross edge + block-recovery re-seed now connect them.
        let source = r#"
fn parse(s: &str) -> u64 {
    let digits = "100";
    let value: u64 = digits.parse().unwrap();
    let bytes = match s {
        "KB" => value.checked_mul(1024).unwrap(),
        "MB" => value.checked_mul(1024 * 1024).unwrap(),
        _ => value,
    };
    bytes
}
"#;
        let fwd = get_slice(source, "parse", 4, SliceDirection::Forward, None, Language::Rust)
            .unwrap();
        assert!(
            fwd.contains(&5),
            "forward slice of `value`@4 must reach `bytes` def@5; got {fwd:?}"
        );
        // backward slice of the CLOSING BRACE (line 11) must reach `value`@4 —
        // this is exactly `path_exists` for `chop(value-def, brace)`.
        let bwd_brace =
            get_slice(source, "parse", 11, SliceDirection::Backward, None, Language::Rust).unwrap();
        assert!(
            bwd_brace.contains(&4),
            "backward slice of the closing brace must reach `value`@4 (chop path); got {bwd_brace:?}"
        );
    }

    #[test]
    fn test_slice_rust_multiline_if_reaches_cross_var_def() {
        // The non-`match` proof: same bug with an `if/else` RHS, no match node.
        // 3=`let value`, 4=`let bytes = if ..`, 5=`value*1024`, 7=`value`, 9=`bytes`.
        let source = r#"
fn g(s: &str) -> u64 {
    let value: u64 = 1;
    let bytes = if s == "KB" {
        value * 1024
    } else {
        value
    };
    bytes
}
"#;
        let slice =
            get_slice(source, "g", 9, SliceDirection::Backward, None, Language::Rust).unwrap();
        assert!(
            slice.contains(&3),
            "backward slice of `bytes` must reach `value`@3 (multi-line if/else); got {slice:?}"
        );
    }

    #[test]
    fn test_slice_rust_block_tail_reaches_cross_var_def() {
        // block-tail RHS `let bytes = { let t = value; t * 2 }`.
        // 3=`let value`, 4=`let bytes = {`, 5=`let t = value;`, 6=`t * 2`, 8=`bytes`.
        let source = r#"
fn h() -> u64 {
    let value = 1;
    let bytes = {
        let t = value;
        t * 2
    };
    bytes
}
"#;
        let slice =
            get_slice(source, "h", 8, SliceDirection::Backward, None, Language::Rust).unwrap();
        assert!(
            slice.contains(&3),
            "backward slice of `bytes` must reach `value`@3 through the block tail; got {slice:?}"
        );
    }

    #[test]
    fn test_slice_rust_oneline_rhs_no_overinclusion() {
        // Regression guard: a single-line RHS must NOT gain spurious lines.
        // 3=`let value`, 4=`let bytes = value + 1`, 5=`bytes`.
        let source = r#"
fn f(s: &str) -> u64 {
    let value: u64 = 1;
    let bytes = value + 1;
    bytes
}
"#;
        let slice =
            get_slice(source, "f", 5, SliceDirection::Backward, None, Language::Rust).unwrap();
        assert!(
            slice.contains(&3) && slice.contains(&4),
            "single-line slice must still reach value@3 and bytes@4; got {slice:?}"
        );
        // No over-inclusion: only function-body lines 2..=5 may appear.
        assert!(
            slice.iter().all(|&l| (2..=5).contains(&l)),
            "single-line RHS slice over-included lines: {slice:?}"
        );
    }

    #[test]
    fn test_slice_var_filter_label_correct() {
        // The cross edge is labeled with the READ var (`value`); a `--var bytes`
        // filter must NOT follow it, so `value`@4 is not spuriously pulled in.
        let source = r#"
fn parse(s: &str) -> u64 {
    let digits = "100";
    let value: u64 = digits.parse().unwrap();
    let bytes = match s {
        "KB" => value.checked_mul(1024).unwrap(),
        _ => value,
    };
    bytes
}
"#;
        let slice_bytes = get_slice(
            source,
            "parse",
            9,
            SliceDirection::Backward,
            Some("bytes"),
            Language::Rust,
        )
        .unwrap();
        assert!(
            !slice_bytes.contains(&4),
            "`--var bytes` must not follow the value-labeled cross edge; got {slice_bytes:?}"
        );
    }

    // --- Cross-language parity: backward slice of `bytes` reaches `value` ---

    #[test]
    fn test_slice_c_ternary_reaches_cross_var_def() {
        // 3=`int value`, 4=`int other`, 5=`int bytes = c ? value`, 6=`: other;`.
        let source = r#"
int f(int c) {
    int value = 100;
    int other = 5;
    int bytes = c ? value
                  : other;
    return bytes;
}
"#;
        let slice =
            get_slice(source, "f", 7, SliceDirection::Backward, None, Language::C).unwrap();
        assert!(
            slice.contains(&3),
            "C: backward slice of `bytes` must reach `value`@3; got {slice:?}"
        );
    }

    #[test]
    fn test_slice_ts_ternary_reaches_cross_var_def() {
        let source = r#"
function f(c: boolean): number {
    let value = 100;
    let bytes = c ? value * 2
                  : value;
    return bytes;
}
"#;
        let slice = get_slice(
            source,
            "f",
            6,
            SliceDirection::Backward,
            None,
            Language::TypeScript,
        )
        .unwrap();
        assert!(
            slice.contains(&3),
            "TS: backward slice of `bytes` must reach `value`@3; got {slice:?}"
        );
    }

    #[test]
    fn test_slice_python_conditional_reaches_cross_var_def() {
        // `total` (not the `bytes` builtin) avoids the builtin-name suppression.
        let source = r#"
def f(c):
    value = 100
    total = value * 2 if c else value
    return total
"#;
        let slice =
            get_slice(source, "f", 5, SliceDirection::Backward, None, Language::Python).unwrap();
        assert!(
            slice.contains(&3),
            "Python: backward slice of `total` must reach `value`@3; got {slice:?}"
        );
    }

    #[test]
    fn test_slice_go_assignment_reaches_cross_var_def() {
        // 3=`value :=`, 4=`var bytes`, 6=`bytes = value * 1024`, 8=`bytes = value`.
        let source = r#"
func g(s string) uint64 {
	value := uint64(100)
	var bytes uint64
	switch s {
	case "KB":
		bytes = value * 1024
	default:
		bytes = value
	}
	return bytes
}
"#;
        let slice =
            get_slice(source, "g", 11, SliceDirection::Backward, None, Language::Go).unwrap();
        assert!(
            slice.contains(&3),
            "Go: backward slice of `bytes` must reach `value`@3; got {slice:?}"
        );
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

    /// fix-R7 (cluster[11] RC5): a definition used ONLY by a control predicate
    /// that guards the criterion must be pulled into the backward slice. The
    /// slice ran the data closure ONCE from the criterion, THEN added control
    /// predicates as a separate one-shot pass — so a predicate line's OWN data
    /// dependency was never resolved. Here `avail` (line 3) is used only by the
    /// guard `if avail > 0:` (line 4), which controls `result = compute()`
    /// (line 5). Slicing line 5 must include the guard (4) AND `avail`'s def
    /// (3). Reproduces sds.c `avail`@206 used by guard@212. Joint data+control
    /// fixpoint required.
    #[test]
    fn test_backward_slice_data_dep_of_control_predicate_included() {
        let source = r#"
def foo(n):
    avail = n - 1
    if avail > 0:
        result = compute()
    else:
        result = 0
    return result
"#;
        // Line 5 is `result = compute()`.
        let slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // The controlling guard `if avail > 0:` is line 4.
        assert!(
            slice.contains(&4),
            "slice must include the controlling guard line 4, got {:?}",
            slice
        );
        // The guard reads `avail`, whose sole def is line 3 — it must be pulled
        // in transitively (this is the bug: data-dep of a control predicate).
        assert!(
            slice.contains(&3),
            "slice must include `avail` def (line 3), the data dependency of the \
             controlling guard; got {:?}",
            slice
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

    // =========================================================================
    // CF1-S13 (v0.5.0 RC CF-wave): `tldr slice` PDG-correctness across the
    // 'slice' symptom class — JavaScript `switch_case`, OCaml `let .. in`, and
    // Solidity bare declaration + `require` guard. Each sub-case asserts a
    // distinct correctness property that the pre-fix block-derived PDG /
    // block-half recovery violated. One test, every language in the class
    // (anti-treadmill gate).
    // =========================================================================

    #[test]
    fn test_slice_cf1s13_switch_case_and_guards_all_langs() {
        // --- JavaScript: a criterion INSIDE a `switch_case` body. The generic
        // switch lowering only models `switch_entry` arms (Swift), so JS case
        // bodies (`switch_body > switch_case`) were covered by NO CFG block and
        // the slice collapsed to EMPTY. It must be non-empty, contain the
        // criterion, and reach the controlling `switch` predicate.
        let js = r#"
function classify(val) {
  var out;
  switch (val) {
    case 'a':
      out = compute(val);
      break;
    default:
      out = 0;
  }
  return out;
}
"#;
        // Line 6 is `out = compute(val);` (inside `case 'a':`).
        let js_slice =
            get_slice(js, "classify", 6, SliceDirection::Backward, None, Language::JavaScript)
                .unwrap();
        assert!(
            !js_slice.is_empty(),
            "JS: slice of a switch_case-body criterion must NOT be empty; got {js_slice:?}"
        );
        assert!(
            js_slice.contains(&6),
            "JS: slice must contain the criterion line 6; got {js_slice:?}"
        );
        assert!(
            js_slice.contains(&4),
            "JS: slice must reach the controlling `switch (val)` predicate @4; got {js_slice:?}"
        );

        // --- OCaml: a `let .. in` chain compiles to a single coarse entry
        // block. Block-half recovery + signature cohesion then pulled in EVERY
        // preceding ref line, so backward-of `res` wrongly included the
        // independent `let start` binding. `res` has no data/control dependency
        // on `start`; it must be EXCLUDED.
        let ml = r#"
let process fd =
  let start = timer_start () in
  let res = run fd in
  stop_timer start;
  res
"#;
        // Line 6 is `res`; line 3 is `let start = timer_start () in` (no dep).
        let ml_slice =
            get_slice(ml, "process", 6, SliceDirection::Backward, None, Language::Ocaml).unwrap();
        assert!(
            ml_slice.contains(&6),
            "OCaml: slice must contain the criterion `res`@6; got {ml_slice:?}"
        );
        assert!(
            !ml_slice.contains(&3),
            "OCaml: backward slice of `res` must EXCLUDE the independent \
             `let start`@3 (no dependency); got {ml_slice:?}"
        );

        // --- Solidity: a bare declaration after a `require` guard and an
        // unrelated sibling declaration. Block-half recovery pulled in the
        // sibling `uint256 c = b;` (which the bare `uint256 d;` does NOT depend
        // on). The require guard, which genuinely control-dominates the
        // declaration, must be included via control-dependence — consistently —
        // while the unrelated sibling is excluded.
        let sol = r#"
contract C {
    function f(uint256 a, uint256 b) internal pure returns (uint256) {
        require(a > 0, "bad");
        uint256 c = b;
        uint256 d;
        d = c + 1;
        return d;
    }
}
"#;
        // Line 6 is `uint256 d;` (bare decl); 5 is the unrelated `uint256 c = b;`;
        // 4 is the `require` guard.
        let sol_slice =
            get_slice(sol, "f", 6, SliceDirection::Backward, None, Language::Solidity).unwrap();
        assert!(
            sol_slice.contains(&6),
            "Solidity: slice must contain the bare-decl criterion @6; got {sol_slice:?}"
        );
        assert!(
            sol_slice.contains(&4),
            "Solidity: bare-decl slice must include the controlling `require` guard @4; \
             got {sol_slice:?}"
        );
        assert!(
            !sol_slice.contains(&5),
            "Solidity: bare-decl slice must NOT pull in the unrelated sibling \
             `uint256 c = b;`@5; got {sol_slice:?}"
        );
    }

    // =========================================================================
    // CFr-RW6 (v0.5.0 RC CF-resid): RESIDUAL of CF1-S13. The S13 gate stopped
    // *block-half recovery* from grafting siblings, but a sibling-class variant
    // (solidity-solmate `ERC1155.safeBatchTransferFrom`, bare `uint256 id;`@90)
    // still returned the DISCONNECTED set {79,87,90}: the bare declaration's
    // coarse continuation block also holds the preceding `require(...)` guard,
    // and the block's *control-dependence* on that guard grafted the guard (87)
    // plus the guard's own data-dep parameter (`from`@79) onto a declaration
    // that genuinely depends on neither.
    //
    // The distinguishing structural fact: the declared name is HOISTED — it is
    // assigned only in a LATER block (the loop body), never recurring inside its
    // own guarded block — so its true backward closure is just the criterion.
    // The original S13 `uint256 d;` differs precisely because its value IS
    // computed in the same guarded block (`d = c + 1;`), keeping the require a
    // real control-dependence. This one test asserts BOTH the new variant is
    // fixed AND every original S13 sub-case (solidity require KEPT, JS
    // switch-case, OCaml independent-binding) still holds (anti-treadmill gate).
    #[test]
    fn test_slice_cfr_rw6_hoisted_decl_does_not_graft_require_all_langs() {
        // --- NEW VARIANT: a hoisted Solidity bare declaration after a `require`
        // guard, whose value is assigned only inside a later loop (mirrors
        // solmate ERC1155 `safeBatchTransferFrom`'s `uint256 id;`). The backward
        // slice of the declaration must be its TRUE closure (just the criterion)
        // — NOT the grafted {param, require, decl}.
        let sol_hoist = r#"
contract C {
    function g(uint256[] calldata xs, address from) external {
        require(from != address(0), "ZERO");

        uint256 id;
        uint256 amt;

        for (uint256 i = 0; i < xs.length; ) {
            id = xs[i];
            amt = id + 1;
            unchecked { ++i; }
        }
    }
}
"#;
        // Line 6 is the bare decl `uint256 id;`; 4 is the `require` guard; 3 is
        // the signature (defines `from`, used by the guard).
        let hoist_slice =
            get_slice(sol_hoist, "g", 6, SliceDirection::Backward, None, Language::Solidity)
                .unwrap();
        assert!(
            hoist_slice.contains(&6),
            "RW6: slice must contain the hoisted bare-decl criterion @6; got {hoist_slice:?}"
        );
        assert!(
            !hoist_slice.contains(&4),
            "RW6: hoisted bare-decl slice must NOT graft the non-dependent `require` \
             guard @4 (the declaration's value is computed in the loop, not the \
             guarded block); got {hoist_slice:?}"
        );
        assert!(
            !hoist_slice.contains(&3),
            "RW6: hoisted bare-decl slice must NOT graft the guard's parameter \
             `from`@3 pulled via the require's data dependence; got {hoist_slice:?}"
        );
        assert!(
            !hoist_slice.contains(&7),
            "RW6: hoisted bare-decl slice must NOT pull the unrelated sibling \
             declaration `uint256 amt;`@7; got {hoist_slice:?}"
        );

        // --- S13 ORIGINAL solidity: the require GENUINELY control-dominates the
        // declaration whose value is computed in the SAME guarded block, so it
        // is KEPT (must not regress under the RW6 fix).
        let sol = r#"
contract C {
    function f(uint256 a, uint256 b) internal pure returns (uint256) {
        require(a > 0, "bad");
        uint256 c = b;
        uint256 d;
        d = c + 1;
        return d;
    }
}
"#;
        let sol_slice =
            get_slice(sol, "f", 6, SliceDirection::Backward, None, Language::Solidity).unwrap();
        assert!(
            sol_slice.contains(&6) && sol_slice.contains(&4) && !sol_slice.contains(&5),
            "RW6 must not regress S13 solidity: keep crit@6 + require@4, exclude \
             sibling@5; got {sol_slice:?}"
        );

        // --- S13 ORIGINAL JavaScript: a `switch_case`-body criterion must still
        // reach its controlling `switch` predicate (not a bare decl — unaffected).
        let js = r#"
function classify(val) {
  var out;
  switch (val) {
    case 'a':
      out = compute(val);
      break;
    default:
      out = 0;
  }
  return out;
}
"#;
        let js_slice =
            get_slice(js, "classify", 6, SliceDirection::Backward, None, Language::JavaScript)
                .unwrap();
        assert!(
            js_slice.contains(&6) && js_slice.contains(&4),
            "RW6 must not regress S13 js: switch_case criterion@6 must reach \
             `switch (val)`@4; got {js_slice:?}"
        );

        // --- S13 ORIGINAL OCaml: backward slice of `res` must exclude the
        // independent `let start` binding it does not depend on.
        let ml = r#"
let process fd =
  let start = timer_start () in
  let res = run fd in
  stop_timer start;
  res
"#;
        let ml_slice =
            get_slice(ml, "process", 6, SliceDirection::Backward, None, Language::Ocaml).unwrap();
        assert!(
            ml_slice.contains(&6) && !ml_slice.contains(&3),
            "RW6 must not regress S13 ocaml: keep `res`@6, exclude independent \
             `let start`@3; got {ml_slice:?}"
        );
    }
}
