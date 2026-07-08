//! Impact analysis (spec Section 2.2.2)
//!
//! Find all callers of a function via reverse call graph traversal.
//!
//! # Algorithm
//! 1. Build reverse graph (callee -> callers)
//! 2. Find all functions matching target_func
//! 3. BFS traversal up to max_depth
//! 4. Detect cycles (mark as truncated)
//!
//! # Edge Cases
//! - Function not in graph: Fall back to AST search if project root provided
//! - Function in AST but no edges: Return with caller_count: 0 and note
//! - Entry point (no callers): Return with caller_count: 0 and note
//! - Cycle detected: Mark as truncated: true
//! - Ambiguous name: Return all matches

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ast::extractor::{
    extract_functions, extract_methods, extract_rust_impl_methods_qualified,
};
use crate::ast::parser::parse_file;
use crate::callgraph::{confidence_tier, ConfidenceTier, ResolutionRung};
use crate::error::TldrError;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{
    ApproximateCaller, CallerTree, ImpactReport, ProjectCallGraph, WorkspaceConfig,
};
use crate::{Language, TldrResult};

/// Strict last-segment compare for qualified function names.
///
/// Splits on `.` and `::` separators and returns the trailing segment
/// (e.g. `"Class.method"` -> `"method"`, `"a::b::c"` -> `"c"`,
/// `"plain"` -> `"plain"`). This anchors the qualified-name match in
/// `impact_analysis` to a real segment boundary, replacing the
/// historic `ends_with(&format!(".{}", target_func))` form which would
/// match across non-separator boundaries in pathological cases.
fn last_segment(qualified: &str) -> &str {
    // Prefer the deepest separator that actually appears.
    let dot_idx = qualified.rfind('.');
    let coloncolon_idx = qualified.rfind("::").map(|i| i + 1); // position of last ':'
                                                               // FEATURE-1 d.6 (Fix A): the Lua/luau colon-method separator is a SINGLE
                                                               // ':' that is NOT part of a '::'. `Component:setState` must yield the bare
                                                               // `setState` so a bare `setState` query matches (`find_function_in_ast`
                                                               // seeds the Component.lua target). The `::` pairs are already handled by
                                                               // `coloncolon_idx`, so we deliberately exclude them here; C++ `A::b`, `.`,
                                                               // and `->` are therefore unaffected.
    let single_colon_idx = last_standalone_colon(qualified);
    let cut = [dot_idx, coloncolon_idx, single_colon_idx]
        .into_iter()
        .flatten()
        .max();
    match cut {
        Some(i) if i < qualified.len() => &qualified[i + 1..],
        _ => qualified,
    }
}

/// Byte index of the LAST standalone `:` in `qualified` — a `:` whose immediate
/// neighbors are not `:` (so the two colons of a `::` pair are excluded). This
/// is the Lua/luau `Table:method` separator. Returns `None` when every colon is
/// part of a `::` (C++/Rust/Scala) or no colon exists. ASCII-safe: `:` is a
/// single-byte codepoint that never appears inside a UTF-8 continuation byte.
fn last_standalone_colon(qualified: &str) -> Option<usize> {
    let bytes = qualified.as_bytes();
    let mut found = None;
    for i in 0..bytes.len() {
        if bytes[i] != b':' {
            continue;
        }
        let prev_is_colon = i > 0 && bytes[i - 1] == b':';
        let next_is_colon = i + 1 < bytes.len() && bytes[i + 1] == b':';
        if !prev_is_colon && !next_is_colon {
            found = Some(i);
        }
    }
    found
}

/// Full qualifier prefix of a qualified name: everything before the leaf
/// returned by [`last_segment`]. Returns `None` for an unqualified name.
///
/// Examples:
/// - `full_qualifier("Parser.parse")` -> `Some("Parser")`
/// - `full_qualifier("mod::Type::method")` -> `Some("mod::Type")`
/// - `full_qualifier("Type:method")` -> `Some("Type")` (Lua single colon)
/// - `full_qualifier("method")` -> `None`
fn full_qualifier(qualified: &str) -> Option<&str> {
    let leaf = last_segment(qualified);
    if leaf.len() == qualified.len() {
        return None;
    }
    let end = qualified.len() - leaf.len();
    let mut qual = &qualified[..end];
    // Strip the trailing separator that `last_segment` cut on.
    if qual.ends_with("::") {
        qual = &qual[..qual.len() - 2];
    } else if qual.ends_with(['.', ':']) {
        qual = &qual[..qual.len() - 1];
    }
    Some(qual)
}

/// Match `candidate` against `target` allowing both directions of
/// qualification (cross-command-consistency-v3 P5.BUG-N3).
///
/// When the user runs `tldr impact Flask.run`, we don't know in advance
/// whether the call graph emitted edges with the qualified form
/// (`Flask.run`) or the bare method name (`run`). Symmetrically, AST-based
/// fallback may emit either shape depending on language. The previous
/// `impact_analysis` only allowed two directions:
///
/// 1. Exact match: `candidate == target`
/// 2. Strip the qualifier on the candidate: `last_segment(candidate) == target`
///
/// That catches `target="run"` matching `candidate="Flask.run"` but **not**
/// the reverse: a user-typed `Flask.run` against a graph emitting bare `run`.
/// `whatbreaks` accepts the qualified shape because its detection path
/// swallows the resulting `FunctionNotFound` instead of bubbling it up,
/// which masks the same gap.
///
/// This helper closes the asymmetry by also accepting:
///
/// 3. Strip the qualifier on the target: `last_segment(target) == candidate`
/// 4. Last-segment-on-both: `last_segment(target) == last_segment(candidate)`
///
/// Cases (3) and (4) are guarded so `target="run"` does NOT match a candidate
/// like `OtherClass.different_method` that has the same final segment as
/// some unrelated qualified name — the guard requires the target to have
/// a qualifier of its own (so the user explicitly typed `Class.method`).
pub fn names_match(candidate: &str, target: &str) -> bool {
    if candidate == target {
        return true;
    }
    // Direction 1 (legacy): candidate is qualified, target is bare.
    if last_segment(candidate) == target {
        return true;
    }
    // Direction 2 (new): target is qualified, candidate is bare or
    // identically qualified. Only honor when target actually has a
    // qualifier — otherwise we'd accept any bare candidate that ends in
    // `target`, which would re-introduce false matches.
    let target_has_qualifier = target.contains('.') || target.contains("::");
    if target_has_qualifier {
        // rust-impl-qualifier-v1 (VAL-RUST-QUAL): when the target uses
        // the `::` separator (canonically Rust/C++/Scala), we MUST NOT
        // fall back to bare-name or tail-only matching — that turns
        // `Glob::parse` into a sloppy match against every same-named
        // `parse` across the corpus regardless of impl type. Limit the
        // permissive `target_qualified → candidate_bare` directions to
        // the `.`-qualifier shape (Python `Class.method`, Ruby, etc.)
        // where they were originally introduced (P5.BUG-N3).
        if target.contains("::") {
            // W1-4: `::`-qualified queries (Rust/C++/Scala natural syntax)
            // must also match dot-canonicalized graph endpoints like
            // `Parser.parse`, while still preserving the qualifier guard.
            //
            // Concretely we require:
            //   * candidate's leaf matches target's leaf, AND
            //   * candidate's qualifier equals target's qualifier OR ends
            //     with it, after normalizing `::` -> `.` on both sides.
            let cand_leaf = last_segment(candidate);
            let tgt_leaf = last_segment(target);
            if cand_leaf == tgt_leaf {
                if let (Some(cand_qual), Some(tgt_qual)) =
                    (full_qualifier(candidate), full_qualifier(target))
                {
                    let cand_qual_norm = cand_qual.replace("::", ".");
                    let tgt_qual_norm = tgt_qual.replace("::", ".");
                    if cand_qual_norm == tgt_qual_norm
                        || cand_qual_norm.ends_with(&format!(".{tgt_qual_norm}"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        let target_tail = last_segment(target);
        if candidate == target_tail {
            return true;
        }
        // Both qualified: compare tails. Pathological case where the user
        // types `Foo.run` and the graph has `Bar.run` — same simple name,
        // different class. We accept it as a candidate (impact will
        // surface every match; over-inclusion is acceptable for P5.BUG-N3
        // because the alternative is the silent "Function not found"
        // failure the user is actively complaining about, and downstream
        // disambiguation still happens via `target_file` filter).
        if last_segment(candidate) == target_tail {
            return true;
        }
    }
    false
}

/// Analyze impact of changing a function.
///
/// # Arguments
/// * `call_graph` - Project call graph
/// * `target_func` - Name of the function to analyze
/// * `max_depth` - Maximum traversal depth
/// * `target_file` - Optional file filter for disambiguation
///
/// # Returns
/// * `Ok(ImpactReport)` - Impact analysis results
/// * `Err(TldrError::FunctionNotFound)` - Function not found in graph
pub fn impact_analysis(
    call_graph: &ProjectCallGraph,
    target_func: &str,
    max_depth: usize,
    target_file: Option<&Path>,
) -> TldrResult<ImpactReport> {
    impact_analysis_with_options(call_graph, target_func, max_depth, target_file, false)
}

/// Impact analysis with explicit control over approximate T2 caller handling.
pub fn impact_analysis_with_options(
    call_graph: &ProjectCallGraph,
    target_func: &str,
    max_depth: usize,
    target_file: Option<&Path>,
    include_approximate: bool,
) -> TldrResult<ImpactReport> {
    // Build reverse graph (callee -> callers)
    let reverse_graph = build_reverse_graph(call_graph, include_approximate);

    // Find all functions matching the target.
    //
    // cl1r-determinism-v1 (v0.5.0 CL-1R): `ImpactReport.targets` is a
    // `BTreeMap` so the serialized map-key order is deterministic. Build the
    // accumulator as a `BTreeMap` too — the `.entry()` / `.remove()` /
    // `.values()` API is identical and the type flows straight into the
    // report without a conversion.
    let mut targets: BTreeMap<String, CallerTree> = BTreeMap::new();
    let mut found_any = false;

    for edge in call_graph.edges() {
        // v031-issue-7: replace the legacy `dst_func.ends_with(&format!(".{}", target_func))`
        // with a strict last-segment compare anchored on `.` / `::` separators. The
        // legacy form happens to be equivalent for most inputs but the explicit segment
        // compare avoids any future regression where a non-separator suffix sneaks in.
        // cross-command-consistency-v3 (P5.BUG-N3): also match the reverse
        // direction so a user-typed qualified name (`Flask.run`) resolves
        // against bare-name edges (`run`). Centralized in `names_match`.
        if names_match(&edge.dst_func, target_func) {
            // Apply file filter if provided
            if let Some(filter) = target_file {
                if !edge.dst_file.ends_with(filter) && edge.dst_file != filter {
                    continue;
                }
            }
            found_any = true;

            let key = format!("{}:{}", edge.dst_file.display(), edge.dst_func);
            targets.entry(key).or_insert_with(|| {
                // Build caller tree for this target
                build_caller_tree(&edge.dst_file, &edge.dst_func, &reverse_graph, max_depth)
            });
        }
    }

    // Also check if target is a callee (it might have no callers)
    if !found_any {
        // Look for the function as a source in any edge
        for edge in call_graph.edges() {
            if names_match(&edge.src_func, target_func) {
                if let Some(filter) = target_file {
                    if !edge.src_file.ends_with(filter) && edge.src_file != filter {
                        continue;
                    }
                }
                let key = format!("{}:{}", edge.src_file.display(), edge.src_func);
                targets.entry(key).or_insert_with(|| {
                    build_caller_tree(&edge.src_file, &edge.src_func, &reverse_graph, max_depth)
                });
            }
        }
    }

    if targets.is_empty() {
        // Try to find similar function names for suggestions
        let suggestions = find_similar_functions(call_graph, target_func);
        return Err(TldrError::FunctionNotFound {
            name: target_func.to_string(),
            file: target_file.map(|p| p.to_path_buf()),
            suggestions,
        });
    }

    let total_targets = targets.len();
    Ok(ImpactReport {
        targets,
        total_targets,
        type_resolution: None, // Type-aware not enabled in basic analysis
    })
}

/// Impact analysis with AST fallback for isolated functions.
///
/// Tries normal call-graph-based impact analysis first. If the function is not
/// found in the call graph (no edges at all), falls back to AST-based function
/// discovery. This handles the case where a function exists in the codebase but
/// has no callers or callees within the analyzed scope.
///
/// # Arguments
/// * `call_graph` - Project call graph
/// * `target_func` - Name of the function to analyze
/// * `max_depth` - Maximum traversal depth
/// * `target_file` - Optional file filter for disambiguation
/// * `project_root` - Root directory for AST-based fallback search
/// * `language` - Programming language for AST parsing
///
/// # Returns
/// * `Ok(ImpactReport)` - Impact analysis results (possibly with zero callers via AST fallback)
/// * `Err(TldrError::FunctionNotFound)` - Function not found in graph or AST
pub fn impact_analysis_with_ast_fallback(
    call_graph: &ProjectCallGraph,
    target_func: &str,
    max_depth: usize,
    target_file: Option<&Path>,
    project_root: &Path,
    language: Language,
) -> TldrResult<ImpactReport> {
    impact_analysis_with_ast_fallback_options(
        call_graph,
        target_func,
        max_depth,
        target_file,
        project_root,
        language,
        false,
    )
}

/// Impact analysis with AST fallback and explicit approximate caller handling.
pub fn impact_analysis_with_ast_fallback_options(
    call_graph: &ProjectCallGraph,
    target_func: &str,
    max_depth: usize,
    target_file: Option<&Path>,
    project_root: &Path,
    language: Language,
    include_approximate: bool,
) -> TldrResult<ImpactReport> {
    // Try normal call-graph-based analysis first
    match impact_analysis_with_options(
        call_graph,
        target_func,
        max_depth,
        target_file,
        include_approximate,
    ) {
        Ok(mut report) => {
            // v031-issue-7: enrich the call-graph report with AST-discovered
            // definitions whose dst_file is NOT already represented as a
            // target. When two distinct files define the same simple-named
            // function and the FuncIndex simple_module alias collapsed both
            // resolved-edges' dst_file onto a single survivor, the call
            // graph alone reports a single target — the second defining
            // file is invisible. Augment with AST scan so impact analysis
            // surfaces ALL real definitions of `target_func`.
            if let Some(locations) =
                find_function_in_ast(project_root, target_func, target_file, language)
            {
                // Compare via canonicalized paths so AST-discovered absolute
                // paths and call-graph relative paths reconcile correctly.
                fn normalize(p: &Path, root: &Path) -> PathBuf {
                    p.canonicalize()
                        .or_else(|_| root.join(p).canonicalize())
                        .unwrap_or_else(|_| p.to_path_buf())
                }
                let known_files: std::collections::HashSet<PathBuf> = report
                    .targets
                    .values()
                    .map(|t| normalize(&t.file, project_root))
                    .collect();
                let ast_files: std::collections::HashSet<PathBuf> = locations
                    .iter()
                    .map(|(_, f)| normalize(f, project_root))
                    .collect();
                // First add AST-discovered target rows (so they exist as
                // a merge destination for the swift fabrication-fix
                // logic below).
                for (func_name, func_file) in &locations {
                    // Match by canonical file path; AST may emit qualified
                    // names (Class.method) — only enrich for definitions
                    // whose file is not already a target.
                    if known_files.contains(&normalize(func_file, project_root)) {
                        continue;
                    }
                    // fix-PW2-B5-impact-alias: carry the enclosing TYPE
                    // qualifier on each collision-suppressed definition row
                    // (`Type.method`) instead of a bare `method`. A bare method
                    // name makes `enrich_impact_with_references` treat the
                    // target as a free function and blank EVERY `recv.method()`
                    // caller; the qualified form lets enrichment key callers
                    // per-definition and apply receiver discrimination.
                    let qualified = qualify_ast_method_name(func_file, func_name);
                    let key = format!("{}:{}", func_file.display(), qualified);
                    report.targets.entry(key).or_insert_with(|| CallerTree {
                        function: qualified.clone(),
                        file: func_file.clone(),
                        caller_count: 0,
                        callers: vec![],
                        approximate_callers: vec![],
                        truncated: false,
                        note: Some(
                            "Defined in this file but no resolved callers in call graph (FuncIndex alias collision suppressed cross-file resolution)".to_string(),
                        ),
                        confidence: None,
                        receiver_type: None,
                    });
                }
                // cross-cutting-and-clear-fix-bugs-v1 (P18.R2): Swift's
                // call graph mis-attributes class-method dst_files when a
                // class is extended in multiple files (e.g. `extension Heap`
                // in Tests/HeapTests/HeapTests.swift AND in
                // Sources/HeapModule/Heap.swift). The FuncIndex picks one
                // file as the "owner" of `Heap.<method>`, and that file may
                // not actually contain a definition of the queried method.
                // AST has authoritative knowledge of where a function is
                // ACTUALLY defined — for swift, MERGE callers attached to
                // mis-attributed targets into the AST-correct target row,
                // then drop the fabricated rows. This preserves the true
                // caller set (e.g. `Heap.heapify` calling `Heap._heapify`
                // inside `Heap+UnsafeHandle.swift`) while removing the
                // wrong-file fabrication. Swift only, gated to avoid
                // disturbing other languages where the call graph's
                // qualified-name dst_file is correct.
                if matches!(language, Language::Swift) && !ast_files.is_empty() {
                    // Pick the canonical AST file as the merge target.
                    // Prefer the one already present in `report.targets`.
                    let canonical_ast_file = ast_files
                        .iter()
                        .find(|f| {
                            report
                                .targets
                                .values()
                                .any(|t| normalize(&t.file, project_root) == **f)
                        })
                        .cloned()
                        .or_else(|| ast_files.iter().next().cloned());

                    let mut to_merge: Vec<CallerTree> = Vec::new();
                    let drop_keys: Vec<String> = report
                        .targets
                        .iter()
                        .filter_map(|(k, t)| {
                            if !ast_files.contains(&normalize(&t.file, project_root)) {
                                Some(k.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    for k in &drop_keys {
                        if let Some(removed) = report.targets.remove(k) {
                            to_merge.extend(removed.callers);
                        }
                    }
                    if !to_merge.is_empty() {
                        if let Some(canon) = canonical_ast_file {
                            for tree in report.targets.values_mut() {
                                if normalize(&tree.file, project_root) != canon {
                                    continue;
                                }
                                for caller in to_merge.drain(..) {
                                    let already = tree.callers.iter().any(|existing| {
                                        existing.function == caller.function
                                            && existing.file == caller.file
                                    });
                                    if !already {
                                        tree.callers.push(caller);
                                    }
                                }
                                tree.caller_count = tree.callers.len();
                                if tree.caller_count > 0 {
                                    tree.note = None;
                                }
                                break;
                            }
                        }
                    }
                }

                report.total_targets = report.targets.len();
            }

            // REG-SWIFT-IMPACT: cross-language phantom-definition
            // discrimination. Runs UNCONDITIONALLY for every Ok report — i.e.
            // independently of the AST-augmentation block above, which is
            // gated on `find_function_in_ast` finding the function in the
            // scan-pass language and is therefore SKIPPED entirely on a
            // non-swift pass (where no `_heapify` C/Rust/Python definition
            // exists). The swift reconciliation likewise only fires during the
            // swift scan pass. In polyglot mode the impact command runs one
            // pass per detected language against a single MERGED call graph
            // (every language's edges unioned), so a swift class-method target
            // that the FuncIndex mis-attributed to a file which merely
            // `extension`-extends the type (e.g. `extension Heap { ... }` in
            // `Tests/HeapTests/HeapTests.swift` with no actual `_heapify`
            // definition) is emitted DURING the non-swift passes too, where
            // neither gate above runs — and the fabricated row survives the
            // per-pass merge and is unioned into the final report.
            //
            // A scan pass for language L should only mint a definition target
            // whose file is written in L: a target whose FILE language differs
            // from the scan-pass language is the merged graph leaking another
            // language's edge into this pass, and the owning-language pass is
            // the authoritative producer for it. We additionally require
            // (AST-verified, parsing the file in its OWN language) that the
            // off-language file does NOT actually define the function before
            // dropping it, so a genuinely cross-language definition is never
            // discarded. The dropped row's callers are merged onto a surviving
            // same-language definition target when one exists, preserving the
            // true caller set. AST-only — no name/path string heuristics.
            let drop_phantom_keys: Vec<String> = report
                .targets
                .iter()
                .filter(|(_, t)| {
                    let file_lang = Language::from_path(&t.file);
                    // Off-language target leaked in by the merged graph...
                    file_lang.is_some_and(|fl| fl != language)
                        // ...that does not actually define the function.
                        && !file_defines_function(&t.file, &t.function)
                })
                .map(|(k, _)| k.clone())
                .collect();
            if !drop_phantom_keys.is_empty() {
                let mut orphan_callers: Vec<CallerTree> = Vec::new();
                for k in &drop_phantom_keys {
                    if let Some(removed) = report.targets.remove(k) {
                        orphan_callers.extend(removed.callers);
                    }
                }
                // Re-home orphaned callers onto a surviving same-language
                // definition target, if this pass produced one.
                if !orphan_callers.is_empty() {
                    let canon_key = report
                        .targets
                        .iter()
                        .find(|(_, t)| {
                            Language::from_path(&t.file) == Some(language)
                                && file_defines_function(&t.file, &t.function)
                        })
                        .map(|(k, _)| k.clone());
                    if let Some(canon_key) = canon_key {
                        if let Some(tree) = report.targets.get_mut(&canon_key) {
                            for caller in orphan_callers.drain(..) {
                                let already = tree.callers.iter().any(|existing| {
                                    existing.function == caller.function
                                        && existing.file == caller.file
                                });
                                if !already {
                                    tree.callers.push(caller);
                                }
                            }
                            tree.caller_count = tree.callers.len();
                            if tree.caller_count > 0 {
                                tree.note = None;
                            }
                        }
                    }
                }
                report.total_targets = report.targets.len();
            }

            Ok(report)
        }
        Err(TldrError::FunctionNotFound {
            name,
            file,
            suggestions,
        }) => {
            // Call graph lookup failed -- try AST-based discovery
            match find_function_in_ast(project_root, target_func, target_file, language) {
                Some(locations) => {
                    // VAL-007: classify the "no callers" note based on whether
                    // we are operating inside a multi-root workspace (pnpm /
                    // npm / Cargo / go). When we are, AND the function is
                    // syntactically exported/public, the most common cause is
                    // unresolved tsconfig path aliases or an incomplete
                    // module graph — say so, rather than mis-claiming the
                    // function truly has no callers.
                    let ws = WorkspaceConfig::discover(project_root);
                    let multi_root = ws.as_ref().map(|c| c.roots.len() > 1).unwrap_or(false);
                    let workspace_paths: Vec<String> = ws
                        .as_ref()
                        .map(|c| c.roots.iter().map(|p| p.display().to_string()).collect())
                        .unwrap_or_default();

                    // Function exists in AST but has no call edges.
                    // cl1r-determinism-v1 (v0.5.0 CL-1R): BTreeMap for
                    // deterministic serialized map-key order.
                    let mut targets: BTreeMap<String, CallerTree> = BTreeMap::new();
                    for (func_name, func_file) in &locations {
                        // fix-PW2-B5-impact-alias: qualify a bare method name
                        // with its enclosing TYPE (`Type.method`) so the
                        // reference-enrichment pass can apply per-definition
                        // receiver discrimination instead of blanking every
                        // `recv.method()` caller of an isolated method.
                        let qualified = qualify_ast_method_name(func_file, func_name);
                        let key = format!("{}:{}", func_file.display(), qualified);
                        let is_exported = function_is_exported(func_file, target_func, language);

                        let note = build_ast_fallback_note(
                            is_exported,
                            multi_root,
                            &workspace_paths,
                            project_root,
                        );

                        targets.insert(
                            key,
                            CallerTree {
                                function: qualified.clone(),
                                file: func_file.clone(),
                                caller_count: 0,
                                callers: vec![],
                                approximate_callers: vec![],
                                truncated: false,
                                note: Some(note),
                                confidence: None,
                                receiver_type: None,
                            },
                        );
                    }
                    let total_targets = targets.len();
                    Ok(ImpactReport {
                        targets,
                        total_targets,
                        type_resolution: None,
                    })
                }
                None => {
                    // Not in AST either -- propagate original error
                    Err(TldrError::FunctionNotFound {
                        name,
                        file,
                        suggestions,
                    })
                }
            }
        }
        Err(other) => Err(other),
    }
}

/// Remove callers from the main caller tree when the same caller is already
/// represented as a lower-confidence approximate caller on that target node.
pub fn exclude_approximate_callers_from_report(report: &mut ImpactReport) {
    let mut approximate_by_target: Vec<(String, ApproximateCaller)> = Vec::new();
    for tree in report.targets.values() {
        collect_approximate_callers_from_tree(tree, &mut approximate_by_target);
    }

    for tree in report.targets.values_mut() {
        exclude_approximate_callers_from_tree(tree, &approximate_by_target);
    }
}

fn collect_approximate_callers_from_tree(
    tree: &CallerTree,
    out: &mut Vec<(String, ApproximateCaller)>,
) {
    for approx in &tree.approximate_callers {
        out.push((tree.function.clone(), approx.clone()));
    }
    for child in &tree.callers {
        collect_approximate_callers_from_tree(child, out);
    }
}

fn exclude_approximate_callers_from_tree(
    tree: &mut CallerTree,
    approximate_by_target: &[(String, ApproximateCaller)],
) {
    for child in &mut tree.callers {
        exclude_approximate_callers_from_tree(child, approximate_by_target);
    }

    if approximate_by_target.is_empty() {
        tree.caller_count = tree.callers.len();
        return;
    }

    tree.callers.retain(|caller| {
        !approximate_by_target.iter().any(|(target, approx)| {
            names_match(target, &tree.function)
                && paths_match(&approx.file, &caller.file)
                && (approx.function == caller.function
                    || last_segment_eq_pub(&approx.function, &caller.function)
                    || last_segment_eq_pub(&caller.function, &approx.function))
        })
    });
    tree.caller_count = tree.callers.len();
    let should_reset_note = match tree.note.as_deref() {
        Some(note) => note.contains("caller_count"),
        None => true,
    };
    if tree.caller_count == 0 && should_reset_note {
        tree.note = Some("Entry point - no callers found".to_string());
    }
}

fn paths_match(a: &Path, b: &Path) -> bool {
    a == b || a.ends_with(b) || b.ends_with(a)
}

fn reference_enrichment_approximate_caller(name: &str, file: &Path) -> ApproximateCaller {
    let rung = ResolutionRung::ReferenceEnrichment;
    ApproximateCaller {
        function: name.to_string(),
        file: file.to_path_buf(),
        confidence: confidence_tier(rung).as_str().to_string(),
        rung: rung.id().to_string(),
        mechanism: rung.mechanism().to_string(),
    }
}

fn add_approximate_caller_once(tree: &mut CallerTree, caller: ApproximateCaller) {
    if !tree
        .approximate_callers
        .iter()
        .any(|existing| existing == &caller)
    {
        tree.approximate_callers.push(caller);
        tree.approximate_callers.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.function.cmp(&b.function))
                .then_with(|| a.rung.cmp(&b.rung))
        });
    }
}

fn has_matching_approximate_caller(
    approximate_by_target: &[(String, ApproximateCaller)],
    target_function: &str,
    caller_function: &str,
    caller_file: &Path,
) -> bool {
    approximate_by_target.iter().any(|(target, approx)| {
        names_match(target, target_function)
            && paths_match(&approx.file, caller_file)
            && (approx.function == caller_function
                || last_segment_eq_pub(&approx.function, caller_function)
                || last_segment_eq_pub(caller_function, &approx.function))
    })
}

/// Enrich `report.targets` with cross-file callers discovered via
/// `find_references`. Mirrors the original CLI-side helper introduced in
/// `language-adapter-fixes-v1` (P13.AGG13-4); promoted to tldr-core in
/// `sibling-resolver-gaps-v1` (P14.AGG14-4) so `whatbreaks`'s internal
/// impact path benefits from the same enrichment that the user-facing
/// `impact` command does.
///
/// For each call site of `target_func` in the project:
///   1. Locate the enclosing function in the call site's file by parsing
///      with [`crate::extract_file`] and finding the function whose
///      `[line_number, line_end]` range contains the call.
///   2. For each target tree, append a top-level synthetic caller entry
///      per unique (caller_function, caller_file) pair. Dedup against
///      existing direct callers using last-segment-aware name matching
///      (P14.AGG14-1) so the call-graph's qualified `Class.method` form
///      and references' bare `method` form are recognised as the same
///      caller.
///   3. Replace the "Entry point — no callers found" note when callers
///      are added.
/// fix-PW1-B7a-elixir-refcount: returns true if `name` is a synthetic
/// `<Module.Name>` elixir module-atom pseudo-caller — an angle-bracket
/// synthetic-scope sentinel whose inner content is an Elixir module ALIAS
/// (first inner char uppercase, e.g. `<Phoenix.Controller>`, `<Plug.Conn>`).
/// The literal lowercase `<module>` top-level scope is NOT a module atom and is
/// deliberately excluded — it carries genuine module-level call sites.
fn is_elixir_synthetic_module_atom_caller(name: &str) -> bool {
    name.strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|inner| inner.chars().next())
        .is_some_and(|c| c.is_uppercase())
}

/// fix-CF1-S16: AST-driven innermost *named* enclosing function for a call
/// site at 1-indexed `(line, column)` in `file`.
///
/// The references-enrichment path resolves a call site's enclosing function by
/// scanning [`crate::extract_file`]'s `module.functions` list, which for most
/// grammars only carries TOP-LEVEL function declarations (e.g. the Lua
/// extractor pushes `function_declaration` nodes but does not descend into
/// their bodies, so a `local function inner` nested inside a `local function
/// outer` is invisible). The project call graph, by contrast, attributes a
/// nested call to the innermost named local function it actually sits in.
/// That asymmetry makes the references fallback mint a COARSER outer-scope
/// caller (`outer` / `gen_scopes`) for a call site the call graph already
/// resolved to the inner function (`inner` / `visit_expression`) — a phantom
/// duplicate of the same edge.
///
/// This helper walks the AST upward from the call leaf and returns the name of
/// the innermost function-like node that actually carries a name. Anonymous
/// closures (`arrow_function`, Rust `closure_expression`, an unnamed Lua
/// `function_definition` / JS `function_expression`) have no `name` child, so
/// the walk skips them and continues outward to the nearest NAMED enclosing
/// function — matching the call graph's caller attribution. Returns `None` on
/// parse failure, a position miss, or when no named function encloses the site
/// (a genuine module-level call).
pub fn innermost_named_enclosing_function(
    file: &Path,
    line: usize,
    column: usize,
    language: Language,
) -> Option<String> {
    use tree_sitter::Point;

    let (tree, source, _lang) = parse_file(file).ok()?;
    let src = source.as_bytes();

    let row = line.saturating_sub(1);
    let col = column.saturating_sub(1);
    let point = Point::new(row, col);

    let root = tree.root_node();
    let start = root.descendant_for_point_range(point, point)?;

    let mut cur = Some(start);
    while let Some(n) = cur {
        if let Some(name) = function_node_name(&n, src, language) {
            return Some(name);
        }
        // fix-CF2-S18r: a swift subscript's computed accessor (`get` / `set` /
        // `_modify`) is a callable scope the S18 call graph resolves but
        // `function_node_name` does not recognise (it has no `name` field).
        // Surfacing its leaf label here lets the existing `ast_inner` dedup
        // collapse the phantom `<module>` references caller against the
        // already-resolved `<Type>.subscript.<label>` edge. The walk reaches
        // the accessor node only when no NAMED inner function encloses the
        // call first, so a nested named callback is still attributed to itself.
        if let Some(label) = swift_subscript_accessor_label(&n, language) {
            return Some(label.to_string());
        }
        cur = n.parent();
    }
    None
}

/// fix-CF2-S18r: the leaf scope-label of a swift subscript computed accessor.
///
/// Wave-1 S18 made the swift call graph model a subscript's computed accessors
/// (`get` / `set` / `_modify`, plus the implicit single-expression getter whose
/// body sits directly under `computed_property`) as callable scopes named
/// `<Type>.subscript.<label>`. Those scopes are NOT in [`crate::extract_file`]'s
/// function list, so the references-enrichment fallback resolves a call inside
/// one to the coarse `<module>` ancestor and mints a phantom caller for a call
/// site the call graph already resolved to the accessor.
///
/// Given a node on the upward scope walk, return the accessor's leaf label iff
/// `node` is a computed accessor whose enclosing `computed_property` is a direct
/// child of a `subscript_declaration` — exactly (and only) the scopes the call
/// graph mints a caller for. The returned leaf (`_modify`, `get`, `set`) matches
/// the resolved caller's last segment, so the existing last-segment dedup fires.
/// Regular computed *variable* properties (whose `computed_property` is NOT under
/// a `subscript_declaration`) yield `None` and are deliberately not deduped,
/// because the call graph does not mint accessor callers for them. AST node-kind
/// only — no source-text heuristics. Swift-gated since the node-kinds are
/// swift-specific.
fn swift_subscript_accessor_label(
    node: &tree_sitter::Node,
    language: Language,
) -> Option<&'static str> {
    if !matches!(language, Language::Swift) {
        return None;
    }
    // Map the accessor node-kind to the call graph's scope label. An explicit
    // accessor wraps the body in `computed_getter`/`computed_setter`/
    // `computed_modify`; the implicit single-expression getter has no wrapper,
    // so the `computed_property` node itself stands in for an implicit `get`.
    let (label, computed_property) = match node.kind() {
        "computed_getter" => ("get", node.parent()?),
        "computed_setter" => ("set", node.parent()?),
        "computed_modify" => ("_modify", node.parent()?),
        "computed_property" => ("get", *node),
        _ => return None,
    };
    if computed_property.kind() != "computed_property" {
        return None;
    }
    // Only subscript accessors are modelled as callers by the call graph.
    if computed_property.parent()?.kind() == "subscript_declaration" {
        Some(label)
    } else {
        None
    }
}

/// fix-CF1-S16: if `node` is a *named* function-like definition, return its
/// declared name (last `.`/`:`-separated segment for table-/member-qualified
/// Lua `function T.m` and JS `obj.method` forms). Returns `None` for nodes
/// that are not function definitions and for anonymous closures (no `name`
/// field), so [`innermost_named_enclosing_function`]'s scope walk continues
/// outward. AST-only — node-kind + the grammar `name` field, never source
/// text heuristics.
fn function_node_name(node: &tree_sitter::Node, src: &[u8], _language: Language) -> Option<String> {
    let func_like = matches!(
        node.kind(),
        // rust
        "function_item"
            // lua / luau / ts / js / go / swift / kotlin
            | "function_declaration"
            // ts / js named function expressions + generators
            | "function_expression"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
            // java / kotlin / c# / go receivers
            | "method_declaration"
            | "constructor_declaration"
            // python / c / cpp / php named definitions (a Lua anonymous
            // closure is ALSO `function_definition` but carries no `name`
            // child, so it correctly yields `None` below)
            | "function_definition"
    );
    if !func_like {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let text = name_node.utf8_text(src).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    // Last segment for `T.m` / `T:m` (Lua) and member-qualified JS names so the
    // result matches the bare caller name the call graph emits.
    let seg = text
        .rsplit(|c| c == '.' || c == ':')
        .next()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(text);
    Some(seg.to_string())
}

pub fn enrich_impact_with_references(
    report: &mut ImpactReport,
    project_root: &Path,
    target_func: &str,
    language: Language,
) {
    use crate::analysis::references::{find_references, ReferenceKind, ReferencesOptions};
    use crate::extract_file;

    if report.targets.is_empty() {
        return;
    }

    // fix-PW2-B5-impact-alias: snapshot whether the call graph resolved ANY
    // caller for this symbol before enrichment mints synthetic ones. When the
    // FuncIndex declined a genuine multi-file method-name-on-type collision,
    // NO target carries a resolved caller (`any_resolved == false`): the
    // symbol is genuinely unresolvable, so we must NOT blank every method
    // caller. When the graph DID resolve something (`any_resolved == true` —
    // e.g. the f69904c python class-collision, the rust self-call
    // discrimination, a resolved lua module call) we keep strict receiver
    // matching so a resolved edge is never sprayed onto sibling collision
    // targets.
    let any_resolved = report.targets.values().any(|t| !t.callers.is_empty());

    // FEATURE-1 d.3: the number of distinct definitions the impact query
    // resolved to IS the method-definer cardinality (one `report.targets` entry
    // per `(file, Type.method)` definition). `>= 2` is a genuine
    // method-name-on-type collision — the same signal d.2's
    // `method_definer_cardinality` gates on. For such AMBIGUOUS targets a
    // reference-discovered caller must prove receiver-TYPE compatibility to be
    // attributed (the instance-variable relaxation is retired), so a same-named
    // sibling on another type drops out of the caller set. A UNIQUE target
    // (cardinality 1) keeps the never-worse relaxation: its sole owner means an
    // untyped caller name-match would have kept is never dropped.
    let is_ambiguous = report.targets.len() >= 2;
    // FEATURE-1 d.7-1: the set of type qualifiers that appear on >= 2 DISTINCT
    // targets — a genuine same-named-class collision (`Service` defined in two
    // files). Type-based receiver resolution CANNOT disambiguate such a qualifier:
    // the receiver's type name ("Service") matches every same-named sibling, so a
    // caller the call graph already resolved (file-aware) would be SPRAYED onto the
    // siblings (the f69904c guard). Both the Defect-1 var-type upgrade and the
    // Defect-2 SelfRef inheritance relaxation consult this ONE set to stay
    // collision-safe. The qualifier key is `qualifier_of` — the same innermost
    // segment the downstream `receiver_compatible` text compare uses — so the set
    // catches exactly the collisions that compare would conflate.
    let mut qual_counts: HashMap<String, usize> = HashMap::new();
    for t in report.targets.values() {
        if let Some(q) = qualifier_of(&t.function) {
            *qual_counts.entry(q).or_insert(0) += 1;
        }
    }
    let colliding_quals: HashSet<String> = qual_counts
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .map(|(q, _)| q)
        .collect();
    // Resolve receivers to their declared TYPE for a genuine multi-definer
    // collision (`is_ambiguous`). FEATURE-1 d.7-1: the former `!any_resolved` gate
    // suppressed per-type resolution for the remaining unresolved edges the moment
    // ANY edge resolved, collapsing correct callers of the sibling definitions. The
    // upgrade now runs whenever the collision is ambiguous; the collision-safety
    // decision is deferred PER-RESOLVED-TYPE to `extract_call_receiver`, which (via
    // `colliding_quals` + `any_resolved`) DECLINES an upgrade whose resolved type
    // is a colliding qualifier under an already-resolved graph — so a
    // distinct-qualifier target still gains recall while a same-named sibling is
    // never sprayed. Strictly additive: an upgrade only fires on a PROVEN declared
    // type (a miss keeps the variable name), and additions dedup against already-
    // resolved callers (`already_present`), so no already-correct edge is
    // re-pointed. For a unique target it is unnecessary (the
    // `never_worse_unique_keep` relaxation covers it), so it stays gated on
    // `is_ambiguous`.
    let resolve_receiver_types = is_ambiguous;

    let mut options = ReferencesOptions::new();
    options.kinds = Some(vec![ReferenceKind::Call]);
    options.language = Some(language.as_str().to_string());
    options.limit = Some(500);

    let refs_report = match find_references(target_func, project_root, &options) {
        Ok(r) => r,
        Err(_) => {
            recurse_reference_enrichment_for_report(report, project_root, language);
            return;
        }
    };

    let mut file_funcs_cache: HashMap<PathBuf, Vec<(String, u32, u32)>> = HashMap::new();

    // CL-2 / GH #40: derive the *bare* method name the user is asking about
    // so we can extract — per call site — the receiver of THAT call from the
    // AST and reject references whose receiver belongs to a different
    // type/module (e.g. an external `json.decode(...)` when the target is the
    // project-local `rpc.decode`, or `Codec::decode` vs `Parser::decode`).
    let bare_target = target_func.rsplit(['.', ':']).next().unwrap_or(target_func);

    // (enclosing_caller, caller_file, line, call_site_receiver, ast_inner)
    // fix-CF1-S16: `ast_inner` is the AST-resolved innermost NAMED enclosing
    // function for this call site (see `innermost_named_enclosing_function`).
    // It is used purely for dedup: when it matches an already-resolved caller,
    // the coarse `enclosing` (derived from the top-level-only `extract_file`
    // function list) is a phantom duplicate of the same nested edge.
    let mut additions: Vec<(String, PathBuf, u32, CallReceiver, Option<String>)> = Vec::new();
    // cross-cutting-and-clear-fix-bugs-v1 (P18.X3): collect references from
    // both the primary lookup and (for Lua/Luau qualified names like
    // `m.open`) a secondary bare-name lookup with a context filter — same
    // shape as the explain.rs P13.AGG13-12 enrichment. The lua call graph
    // does not always resolve `<alias>.<method>(...)` to `function m.<method>`
    // definitions through references' qualified path, so impact's caller
    // list comes back empty even though explain reports the same callers
    // via this exact mechanism.
    let mut all_refs: Vec<crate::analysis::references::Reference> = refs_report.references.clone();
    if matches!(language, Language::Lua | Language::Luau) {
        if let Some(bare) = target_func.split('.').next_back() {
            if bare != target_func && !bare.is_empty() {
                let mut bare_options = ReferencesOptions::new();
                bare_options.kinds = Some(vec![ReferenceKind::Call]);
                bare_options.language = Some(language.as_str().to_string());
                bare_options.limit = Some(500);
                if let Ok(bare_refs) = find_references(bare, project_root, &bare_options) {
                    let dot_pat = format!(".{}(", bare);
                    let space_pat = format!(".{} (", bare);
                    for r in &bare_refs.references {
                        if !r.context.contains(&dot_pat) && !r.context.contains(&space_pat) {
                            continue;
                        }
                        // Avoid duplicating refs already present in primary
                        // lookup (matched on (file, line) pair).
                        if all_refs
                            .iter()
                            .any(|p| p.file == r.file && p.line == r.line)
                        {
                            continue;
                        }
                        all_refs.push(r.clone());
                    }
                }
            }
        }
    }
    for r in &all_refs {
        let caller_file = r.file.clone();
        let funcs = file_funcs_cache
            .entry(caller_file.clone())
            .or_insert_with(|| {
                let module = match extract_file(&caller_file, None) {
                    Ok(m) => m,
                    Err(_) => return Vec::new(),
                };
                let mut out: Vec<(String, u32, u32)> = Vec::new();
                for f in &module.functions {
                    out.push((f.name.clone(), f.line_number, f.line_end));
                }
                for class in &module.classes {
                    for m in &class.methods {
                        out.push((m.name.clone(), m.line_number, m.line_end));
                        out.push((
                            format!("{}.{}", class.name, m.name),
                            m.line_number,
                            m.line_end,
                        ));
                    }
                }
                out
            });
        let enclosing = funcs
            .iter()
            .find(|(_, start, end)| {
                let line = r.line as u32;
                line >= *start && (*end == 0 || line <= *end)
            })
            .map(|(name, _, _)| name.clone())
            .unwrap_or_else(|| "<module>".to_string());

        // fix-CF1-S16: AST innermost named enclosing function for this exact
        // call site. Differs from `enclosing` only when the call is nested
        // inside a function the coarse `extract_file` list cannot see.
        let ast_inner =
            innermost_named_enclosing_function(&caller_file, r.line, r.column, language);

        let is_self = report.targets.values().any(|tree| {
            paths_equivalent_root(&tree.file, project_root, &caller_file)
                && (enclosing == target_func
                    || last_segment_eq_pub(&enclosing, target_func)
                    || ast_inner.as_deref().is_some_and(|inner| {
                        inner == target_func || last_segment_eq_pub(inner, target_func)
                    }))
        });
        if is_self {
            continue;
        }

        // CL-2 / GH #40: extract the receiver of the call at this exact site
        // from the AST. This is the discriminator that distinguishes
        // `json.decode(...)` (receiver `json`) from `rpc.decode()` (receiver
        // `rpc`) and `self.decode()` inside `impl Codec` (receiver type
        // `Codec`) from the same expression inside `impl Parser`.
        //
        // c3-cpp-method-caller-v1 (v0.5.0 AUDIT-FIX, C3 gap-a): the receiver
        // extractor now type-resolves an instance receiver (`endTag.GetStr()`
        // where `StrPair endTag;` is a local, or a member field of an inline
        // class body in the same file) to its declared TYPE, so the CL-2
        // compatibility check matches the target's type qualifier instead of
        // wrongly rejecting the variable name.
        let receiver = extract_call_receiver(
            &caller_file,
            r.line,
            r.column,
            bare_target,
            language,
            resolve_receiver_types,
            any_resolved,
            &colliding_quals,
        );

        let key_pair = (enclosing.clone(), caller_file.clone());
        if additions
            .iter()
            .any(|(n, f, _, _, _)| n == &key_pair.0 && f == &key_pair.1)
        {
            continue;
        }
        additions.push((enclosing, caller_file, r.line as u32, receiver, ast_inner));
    }

    // fix-PW2-B5-impact-alias: some grammars (notably Swift) classify a member
    // method invocation `recv.method(args)` as a `Read` reference, not a
    // `Call`, so the Call-only lookup above returns NOTHING and impact would
    // blank EVERY caller of a method-name-on-type collision. When the call
    // graph resolved nothing (`!any_resolved`) AND the Call pass produced no
    // caller (`additions.is_empty()`) — i.e. we are about to blank ALL callers
    // — widen the lookup to `Read` references, accepting ONLY the sites the
    // AST confirms are receiver-qualified call expressions (an explicit
    // `recv.` / `self.` receiver). Genuine bare variable reads (no receiver)
    // are excluded, so a truly isolated function is never given phantom
    // callers. The per-target receiver discrimination + relaxation below then
    // decides which definition each call site belongs to.
    if !any_resolved && additions.is_empty() {
        let mut read_opts = ReferencesOptions::new();
        read_opts.kinds = Some(vec![ReferenceKind::Read]);
        read_opts.language = Some(language.as_str().to_string());
        read_opts.limit = Some(500);
        if let Ok(read_refs) = find_references(target_func, project_root, &read_opts) {
            for r in &read_refs.references {
                let caller_file = r.file.clone();
                let receiver = extract_call_receiver(
                    &caller_file,
                    r.line,
                    r.column,
                    bare_target,
                    language,
                    resolve_receiver_types,
                    any_resolved,
                    &colliding_quals,
                );
                // Only accept AST-confirmed receiver-qualified call sites; a
                // bare/unknown/shadowed receiver is not a method invocation we
                // can attribute to a typed definition.
                if !matches!(receiver, CallReceiver::Named(_) | CallReceiver::SelfRef(_)) {
                    continue;
                }
                let funcs = file_funcs_cache
                    .entry(caller_file.clone())
                    .or_insert_with(|| {
                        let module = match extract_file(&caller_file, None) {
                            Ok(m) => m,
                            Err(_) => return Vec::new(),
                        };
                        let mut out: Vec<(String, u32, u32)> = Vec::new();
                        for f in &module.functions {
                            out.push((f.name.clone(), f.line_number, f.line_end));
                        }
                        for class in &module.classes {
                            for m in &class.methods {
                                out.push((m.name.clone(), m.line_number, m.line_end));
                                out.push((
                                    format!("{}.{}", class.name, m.name),
                                    m.line_number,
                                    m.line_end,
                                ));
                            }
                        }
                        out
                    });
                let enclosing = funcs
                    .iter()
                    .find(|(_, start, end)| {
                        let line = r.line as u32;
                        line >= *start && (*end == 0 || line <= *end)
                    })
                    .map(|(name, _, _)| name.clone())
                    .unwrap_or_else(|| "<module>".to_string());

                // fix-CF1-S16: AST innermost named enclosing (see Call path).
                let ast_inner =
                    innermost_named_enclosing_function(&caller_file, r.line, r.column, language);

                let is_self = report.targets.values().any(|tree| {
                    paths_equivalent_root(&tree.file, project_root, &caller_file)
                        && (enclosing == target_func
                            || last_segment_eq_pub(&enclosing, target_func)
                            || ast_inner.as_deref().is_some_and(|inner| {
                                inner == target_func || last_segment_eq_pub(inner, target_func)
                            }))
                });
                if is_self {
                    continue;
                }

                let key_pair = (enclosing.clone(), caller_file.clone());
                if additions
                    .iter()
                    .any(|(n, f, _, _, _)| n == &key_pair.0 && f == &key_pair.1)
                {
                    continue;
                }
                additions.push((enclosing, caller_file, r.line as u32, receiver, ast_inner));
            }
        }
    }

    // fix-PW1-B7a-elixir-refcount (v0.5.0 BACKLOG): suppress synthetic
    // `<Module.Name>` module-atom pseudo-callers (e.g. `<Phoenix.Controller>`,
    // `<Plug.Conn>`) that the elixir call graph mints for module-level /
    // typespec-carrier scopes. A module is not a caller — these are
    // self-referential DSL artifacts, not real call sites. The `<...>` marker
    // is the call graph's internal synthetic-scope sentinel; an UPPERCASE inner
    // name is an Elixir module ALIAS (module atom), which distinguishes it from
    // the legitimate lowercase `<module>` top-level scope that carries genuine
    // module-level call sites. Runs unconditionally (even with no reference
    // additions) so callgraph-resolved pseudo-callers are dropped too.
    if matches!(language, Language::Elixir) {
        for tree in report.targets.values_mut() {
            let before = tree.callers.len();
            tree.callers
                .retain(|c| !is_elixir_synthetic_module_atom_caller(&c.function));
            if tree.callers.len() != before {
                tree.caller_count = tree.callers.len();
            }
        }
    }

    if additions.is_empty() {
        recurse_reference_enrichment_for_report(report, project_root, language);
        return;
    }

    // FEATURE-1 d.7-1: pre-collect each call file's class -> base-class-names map
    // so `receiver_compatible` can recognize a `this->method()` self-call whose
    // ENCLOSING class INHERITS the target's type qualifier (a method defined on a
    // BASE class). Only files carrying a resolved `self`/`this` receiver are
    // parsed (bounded), reusing the canonical `ClassInfo.bases` the AST extractors
    // already produce — no parallel inheritance model.
    let mut class_bases_by_file: HashMap<PathBuf, HashMap<String, Vec<String>>> = HashMap::new();
    for (_, file, _, receiver, _) in &additions {
        if !matches!(receiver, CallReceiver::SelfRef(Some(_))) {
            continue;
        }
        if class_bases_by_file.contains_key(file) {
            continue;
        }
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        if let Ok(module) = extract_file(file, None) {
            for class in &module.classes {
                if !class.name.is_empty() && !class.bases.is_empty() {
                    // Keep-first on a duplicate short name in the same file so a
                    // later same-named class cannot silently overwrite the bases of
                    // an earlier one (never-worse: no spurious widening).
                    map.entry(class.name.clone())
                        .or_insert_with(|| class.bases.clone());
                }
            }
        }
        class_bases_by_file.insert(file.clone(), map);
    }

    let mut approximate_evidence: Vec<(String, ApproximateCaller)> = Vec::new();
    for tree in report.targets.values() {
        collect_approximate_callers_from_tree(tree, &mut approximate_evidence);
    }

    for tree in report.targets.values_mut() {
        // CL-2 / GH #40: derive the receiver-qualifier this target's
        // definition is scoped under, so each candidate caller's call-site
        // receiver can be checked for compatibility. The qualifier comes
        // from the target's own qualified name (`rpc.decode` -> `rpc`,
        // `Parser::decode` -> `Parser`); a bare free function yields `None`.
        let target_qualifier = qualifier_of(&tree.function);

        for (name, file, line, receiver, ast_inner) in &additions {
            // CL-2: receiver-type discrimination. Only mint this caller if
            // the call site's receiver is compatible with the target's
            // defined qualifier. This drops `json.decode(...)` from the
            // callers of `rpc.decode`, and `Codec::decode` self-calls from
            // the callers of `Parser::decode`.
            //
            // FEATURE-1 d.3: strict matching now compares the receiver's
            // resolved declared TYPE against the target's type qualifier (the
            // receiver was upgraded in `extract_call_receiver` via the same
            // SourceTypeIndex machinery the call-graph builder uses). For an
            // AMBIGUOUS (>= 2 definer) collision that type check is REQUIRED — the
            // former blanket instance-variable relaxation that sprayed one call
            // site onto every sibling `Type.method` is retired. Only a
            // CARDINALITY-1 (unique) target keeps the relaxation (`!is_ambiguous`
            // below), so an untyped caller of the sole owner is never dropped
            // (never-worse). Module-qualified targets (lowercase qualifier like
            // lua `rpc`) and type-named receivers (uppercase like `Mutex`) stay
            // strict, preserving the CL-2 / f69904c discriminations.
            let strict_ok = receiver_compatible(
                receiver,
                target_qualifier.as_deref(),
                &tree.file,
                file,
                &class_bases_by_file,
                &colliding_quals,
            );
            // FEATURE-1 d.3: the instance-variable relaxation is retired for
            // AMBIGUOUS (>= 2 definer) collisions — those now require the
            // receiver's declared TYPE to match this target (the receiver was
            // upgraded to its type in `extract_call_receiver`), so a same-named
            // sibling on a DIFFERENT type drops out instead of being sprayed onto
            // every definition. It is kept ONLY for a CARDINALITY-1 (unique)
            // target, where the sole possible owner means an untyped caller that a
            // name-match would have kept must never be dropped (never-worse).
            let keep = strict_ok
                || (!any_resolved
                    && !is_ambiguous
                    && never_worse_unique_keep(receiver, target_qualifier.as_deref()));
            if !keep {
                continue;
            }

            // P14.AGG14-1: last-segment-aware dedup so call-graph
            // qualified-name (`Class.method`) and references bare-name
            // (`method`) collapse to the same caller.
            //
            // fix-CF1-S16: ALSO dedup against the AST innermost named
            // enclosing (`ast_inner`). When this references call site is
            // nested inside a function the call graph already resolved as a
            // caller (`inner` / `visit_expression`), but the coarse
            // `extract_file`-derived `enclosing` is its outer ancestor
            // (`outer` / `gen_scopes`), the outer entry is a phantom
            // duplicate of the same edge — suppress it. The dedup only fires
            // when `ast_inner` matches an ALREADY-PRESENT caller, so a call
            // site the graph attributed to the OUTER scope (a named-callback
            // function expression) is never wrongly collapsed.
            let already_present = tree.callers.iter().any(|c| {
                let names_match = &c.function == name
                    || last_segment_eq_pub(&c.function, name)
                    || last_segment_eq_pub(name, &c.function);
                let inner_match = ast_inner.as_deref().is_some_and(|inner| {
                    &c.function == inner
                        || last_segment_eq_pub(&c.function, inner)
                        || last_segment_eq_pub(inner, &c.function)
                });
                (names_match || inner_match) && paths_equivalent_root(&c.file, project_root, file)
            });
            if already_present {
                continue;
            }

            // CL-2: emit an accurate provenance note. The previous code
            // hardcoded "call graph missing edge" for every minted caller.
            // We now distinguish the genuinely cross-file-unresolved case
            // (target defined in a different file from the call site) from
            // the same-file case the call graph simply failed to link.
            let cross_file = !paths_equivalent_root(&tree.file, project_root, file);
            let note = if cross_file {
                format!(
                    "Discovered via references at line {} (call graph did not resolve this cross-file edge)",
                    line
                )
            } else {
                format!(
                    "Discovered via references at line {} (call graph did not resolve this same-file edge)",
                    line
                )
            };

            tree.callers.push(CallerTree {
                function: name.clone(),
                file: file.clone(),
                caller_count: 0,
                callers: vec![],
                approximate_callers: vec![],
                truncated: false,
                note: Some(note),
                confidence: None,
                receiver_type: receiver.qualifier_label(),
            });
            if !has_matching_approximate_caller(&approximate_evidence, &tree.function, name, file) {
                let approximate = reference_enrichment_approximate_caller(name, file);
                add_approximate_caller_once(tree, approximate.clone());
                approximate_evidence.push((tree.function.clone(), approximate));
            }
            tree.caller_count = tree.callers.len();
            if let Some(n) = &tree.note {
                if n.contains("Entry point") || n.contains("no callers") {
                    tree.note = Some(
                        "caller_count derived from references enrichment (call graph missing cross-file edges)"
                            .to_string(),
                    );
                }
            }
        }

        // CL-1 / GH #74: this is the serialization boundary for the
        // top-level caller list. `tree.callers` is now a mix of
        // call-graph-resolved callers (sorted upstream in
        // `build_reverse_graph`) and reference-discovered callers appended
        // above; the interleaving of those two sources is not itself
        // ordered, so a final stable sort on the caller identity tuple —
        // (file path, function name) — is required for byte-identical
        // output across runs. Sorting by file then function keeps callers
        // from the same file grouped, which also reads better.
        tree.callers.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.function.cmp(&b.function))
        });
    }

    recurse_reference_enrichment_for_report(report, project_root, language);
}

#[derive(Clone)]
struct ReferenceDefinerSignals {
    is_ambiguous: bool,
    colliding_quals: HashSet<String>,
}

fn recurse_reference_enrichment_for_report(
    report: &mut ImpactReport,
    project_root: &Path,
    language: Language,
) {
    let mut file_funcs_cache: HashMap<PathBuf, Vec<(String, u32, u32)>> = HashMap::new();
    let mut definer_cache: HashMap<String, ReferenceDefinerSignals> = HashMap::new();
    for tree in report.targets.values_mut() {
        let mut seen: HashSet<FunctionKey> = HashSet::new();
        seen.insert((tree.file.clone(), tree.function.clone()));
        recurse_reference_enrichment_for_children(
            tree,
            project_root,
            language,
            &mut file_funcs_cache,
            &mut definer_cache,
            &mut seen,
        );
    }
}

fn recurse_reference_enrichment_for_children(
    tree: &mut CallerTree,
    project_root: &Path,
    language: Language,
    file_funcs_cache: &mut HashMap<PathBuf, Vec<(String, u32, u32)>>,
    definer_cache: &mut HashMap<String, ReferenceDefinerSignals>,
    seen: &mut HashSet<FunctionKey>,
) {
    let mut idx = 0;
    while idx < tree.callers.len() {
        recurse_reference_enrichment_for_node(
            &mut tree.callers[idx],
            project_root,
            language,
            file_funcs_cache,
            definer_cache,
            seen,
        );
        idx += 1;
    }
}

fn recurse_reference_enrichment_for_node(
    tree: &mut CallerTree,
    project_root: &Path,
    language: Language,
    file_funcs_cache: &mut HashMap<PathBuf, Vec<(String, u32, u32)>>,
    definer_cache: &mut HashMap<String, ReferenceDefinerSignals>,
    seen: &mut HashSet<FunctionKey>,
) {
    let key = (tree.file.clone(), tree.function.clone());
    if !seen.insert(key.clone()) {
        return;
    }

    enrich_single_caller_tree_node_with_references(
        tree,
        project_root,
        language,
        file_funcs_cache,
        definer_cache,
    );
    recurse_reference_enrichment_for_children(
        tree,
        project_root,
        language,
        file_funcs_cache,
        definer_cache,
        seen,
    );

    seen.remove(&key);
}

fn nested_reference_definer_signals(
    tree: &CallerTree,
    project_root: &Path,
    language: Language,
    bare_target: &str,
    definer_cache: &mut HashMap<String, ReferenceDefinerSignals>,
) -> ReferenceDefinerSignals {
    if let Some(signals) = definer_cache.get(bare_target) {
        return signals.clone();
    }

    let mut definitions: HashSet<(PathBuf, String)> = HashSet::new();
    if let Some(locations) = find_function_in_ast(project_root, bare_target, None, language) {
        for (func_name, func_file) in locations {
            let qualified = qualify_ast_method_name(&func_file, &func_name);
            if last_segment(&qualified) == bare_target {
                definitions.insert((func_file, qualified));
            }
        }
    }
    if definitions.is_empty() {
        definitions.insert((tree.file.clone(), tree.function.clone()));
    }

    let mut qual_counts: HashMap<String, usize> = HashMap::new();
    for (_, func) in &definitions {
        if let Some(q) = qualifier_of(func) {
            *qual_counts.entry(q).or_insert(0) += 1;
        }
    }
    let signals = ReferenceDefinerSignals {
        is_ambiguous: definitions.len() >= 2,
        colliding_quals: qual_counts
            .into_iter()
            .filter(|(_, n)| *n >= 2)
            .map(|(q, _)| q)
            .collect(),
    };
    definer_cache.insert(bare_target.to_string(), signals.clone());
    signals
}

fn enrich_single_caller_tree_node_with_references(
    tree: &mut CallerTree,
    project_root: &Path,
    language: Language,
    file_funcs_cache: &mut HashMap<PathBuf, Vec<(String, u32, u32)>>,
    definer_cache: &mut HashMap<String, ReferenceDefinerSignals>,
) {
    use crate::analysis::references::{find_references, ReferenceKind, ReferencesOptions};
    use crate::extract_file;

    if tree.truncated {
        return;
    }

    let target_func = last_segment(&tree.function).to_string();
    if target_func.is_empty() || target_func.starts_with('<') {
        return;
    }

    let any_resolved = !tree.callers.is_empty();
    let definer_signals =
        nested_reference_definer_signals(tree, project_root, language, &target_func, definer_cache);
    let is_ambiguous = definer_signals.is_ambiguous;
    let colliding_quals = definer_signals.colliding_quals;
    let resolve_receiver_types = is_ambiguous;

    let mut options = ReferencesOptions::new();
    options.kinds = Some(vec![ReferenceKind::Call]);
    options.language = Some(language.as_str().to_string());
    options.limit = Some(500);

    let refs_report = match find_references(&target_func, project_root, &options) {
        Ok(r) => r,
        Err(_) => return,
    };

    let target_file = tree.file.clone();
    let mut additions: Vec<(String, PathBuf, u32, CallReceiver, Option<String>)> = Vec::new();

    for r in &refs_report.references {
        let caller_file = r.file.clone();
        let funcs = file_funcs_cache
            .entry(caller_file.clone())
            .or_insert_with(|| {
                let module = match extract_file(&caller_file, None) {
                    Ok(m) => m,
                    Err(_) => return Vec::new(),
                };
                let mut out: Vec<(String, u32, u32)> = Vec::new();
                for f in &module.functions {
                    out.push((f.name.clone(), f.line_number, f.line_end));
                }
                for class in &module.classes {
                    for m in &class.methods {
                        out.push((m.name.clone(), m.line_number, m.line_end));
                        out.push((
                            format!("{}.{}", class.name, m.name),
                            m.line_number,
                            m.line_end,
                        ));
                    }
                }
                out
            });
        let enclosing = funcs
            .iter()
            .find(|(_, start, end)| {
                let line = r.line as u32;
                line >= *start && (*end == 0 || line <= *end)
            })
            .map(|(name, _, _)| name.clone())
            .unwrap_or_else(|| "<module>".to_string());
        let ast_inner =
            innermost_named_enclosing_function(&caller_file, r.line, r.column, language);

        let is_self = paths_equivalent_root(&target_file, project_root, &caller_file)
            && (enclosing == target_func
                || last_segment_eq_pub(&enclosing, &target_func)
                || ast_inner.as_deref().is_some_and(|inner| {
                    inner == target_func || last_segment_eq_pub(inner, &target_func)
                }));
        if is_self {
            continue;
        }

        let receiver = extract_call_receiver(
            &caller_file,
            r.line,
            r.column,
            &target_func,
            language,
            resolve_receiver_types,
            any_resolved,
            &colliding_quals,
        );

        let key_pair = (enclosing.clone(), caller_file.clone());
        if additions
            .iter()
            .any(|(n, f, _, _, _)| n == &key_pair.0 && f == &key_pair.1)
        {
            continue;
        }
        additions.push((enclosing, caller_file, r.line as u32, receiver, ast_inner));
    }

    if !any_resolved && additions.is_empty() {
        let mut read_opts = ReferencesOptions::new();
        read_opts.kinds = Some(vec![ReferenceKind::Read]);
        read_opts.language = Some(language.as_str().to_string());
        read_opts.limit = Some(500);
        if let Ok(read_refs) = find_references(&target_func, project_root, &read_opts) {
            for r in &read_refs.references {
                let caller_file = r.file.clone();
                let receiver = extract_call_receiver(
                    &caller_file,
                    r.line,
                    r.column,
                    &target_func,
                    language,
                    resolve_receiver_types,
                    any_resolved,
                    &colliding_quals,
                );
                if !matches!(receiver, CallReceiver::Named(_) | CallReceiver::SelfRef(_)) {
                    continue;
                }
                let funcs = file_funcs_cache
                    .entry(caller_file.clone())
                    .or_insert_with(|| {
                        let module = match extract_file(&caller_file, None) {
                            Ok(m) => m,
                            Err(_) => return Vec::new(),
                        };
                        let mut out: Vec<(String, u32, u32)> = Vec::new();
                        for f in &module.functions {
                            out.push((f.name.clone(), f.line_number, f.line_end));
                        }
                        for class in &module.classes {
                            for m in &class.methods {
                                out.push((m.name.clone(), m.line_number, m.line_end));
                                out.push((
                                    format!("{}.{}", class.name, m.name),
                                    m.line_number,
                                    m.line_end,
                                ));
                            }
                        }
                        out
                    });
                let enclosing = funcs
                    .iter()
                    .find(|(_, start, end)| {
                        let line = r.line as u32;
                        line >= *start && (*end == 0 || line <= *end)
                    })
                    .map(|(name, _, _)| name.clone())
                    .unwrap_or_else(|| "<module>".to_string());
                let ast_inner =
                    innermost_named_enclosing_function(&caller_file, r.line, r.column, language);

                let is_self = paths_equivalent_root(&target_file, project_root, &caller_file)
                    && (enclosing == target_func
                        || last_segment_eq_pub(&enclosing, &target_func)
                        || ast_inner.as_deref().is_some_and(|inner| {
                            inner == target_func || last_segment_eq_pub(inner, &target_func)
                        }));
                if is_self {
                    continue;
                }

                let key_pair = (enclosing.clone(), caller_file.clone());
                if additions
                    .iter()
                    .any(|(n, f, _, _, _)| n == &key_pair.0 && f == &key_pair.1)
                {
                    continue;
                }
                additions.push((enclosing, caller_file, r.line as u32, receiver, ast_inner));
            }
        }
    }

    if matches!(language, Language::Elixir) {
        let before = tree.callers.len();
        tree.callers
            .retain(|c| !is_elixir_synthetic_module_atom_caller(&c.function));
        if tree.callers.len() != before {
            tree.caller_count = tree.callers.len();
        }
    }

    if additions.is_empty() {
        return;
    }

    let mut approximate_evidence: Vec<(String, ApproximateCaller)> = Vec::new();
    collect_approximate_callers_from_tree(tree, &mut approximate_evidence);

    let mut class_bases_by_file: HashMap<PathBuf, HashMap<String, Vec<String>>> = HashMap::new();
    for (_, file, _, receiver, _) in &additions {
        if !matches!(receiver, CallReceiver::SelfRef(Some(_))) {
            continue;
        }
        if class_bases_by_file.contains_key(file) {
            continue;
        }
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        if let Ok(module) = extract_file(file, None) {
            for class in &module.classes {
                if !class.name.is_empty() && !class.bases.is_empty() {
                    map.entry(class.name.clone())
                        .or_insert_with(|| class.bases.clone());
                }
            }
        }
        class_bases_by_file.insert(file.clone(), map);
    }

    let target_qualifier = qualifier_of(&tree.function);
    for (name, file, line, receiver, ast_inner) in &additions {
        let strict_ok = receiver_compatible(
            receiver,
            target_qualifier.as_deref(),
            &tree.file,
            file,
            &class_bases_by_file,
            &colliding_quals,
        );
        let keep = strict_ok
            || (!any_resolved
                && !is_ambiguous
                && never_worse_unique_keep(receiver, target_qualifier.as_deref()));
        if !keep {
            continue;
        }

        let already_present = tree.callers.iter().any(|c| {
            let names_match = &c.function == name
                || last_segment_eq_pub(&c.function, name)
                || last_segment_eq_pub(name, &c.function);
            let inner_match = ast_inner.as_deref().is_some_and(|inner| {
                &c.function == inner
                    || last_segment_eq_pub(&c.function, inner)
                    || last_segment_eq_pub(inner, &c.function)
            });
            (names_match || inner_match) && paths_equivalent_root(&c.file, project_root, file)
        });
        if already_present {
            continue;
        }

        let cross_file = !paths_equivalent_root(&tree.file, project_root, file);
        let note = if cross_file {
            format!(
                "Discovered via references at line {} (call graph did not resolve this cross-file edge)",
                line
            )
        } else {
            format!(
                "Discovered via references at line {} (call graph did not resolve this same-file edge)",
                line
            )
        };
        tree.callers.push(CallerTree {
            function: name.clone(),
            file: file.clone(),
            caller_count: 0,
            callers: vec![],
            approximate_callers: vec![],
            truncated: false,
            note: Some(note),
            confidence: None,
            receiver_type: receiver.qualifier_label(),
        });
        if !has_matching_approximate_caller(&approximate_evidence, &tree.function, name, file) {
            let approximate = reference_enrichment_approximate_caller(name, file);
            add_approximate_caller_once(tree, approximate.clone());
            approximate_evidence.push((tree.function.clone(), approximate));
        }
        tree.caller_count = tree.callers.len();
        if let Some(n) = &tree.note {
            if n.contains("Entry point") || n.contains("no callers") {
                tree.note = Some(
                    "caller_count derived from references enrichment (call graph missing cross-file edges)"
                        .to_string(),
                );
            }
        }
    }

    tree.callers.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.function.cmp(&b.function))
    });
}

/// Path equality with project-root anchoring used by the references
/// enrichment helper.
fn paths_equivalent_root(a: &Path, project_root: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let ca = a
        .canonicalize()
        .or_else(|_| project_root.join(a).canonicalize())
        .ok();
    let cb = b
        .canonicalize()
        .or_else(|_| project_root.join(b).canonicalize())
        .ok();
    match (ca, cb) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// Trailing-segment equality after `.` or `::`. Used for last-segment
/// aware caller-dedup in [`enrich_impact_with_references`].
fn last_segment_eq_pub(qualified: &str, target: &str) -> bool {
    let last_dot = qualified.rfind('.');
    let last_cc = qualified.rfind("::").map(|i| i + 1);
    let cut = match (last_dot, last_cc) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    match cut {
        Some(i) if i + 1 < qualified.len() => &qualified[i + 1..] == target,
        _ => qualified == target,
    }
}

// =============================================================================
// CL-2 / GH #40: AST-driven receiver-type discrimination for the references
// enrichment path.
//
// The references engine matches the BARE method name (e.g. `decode`) at every
// textual occurrence and classifies each as a `Call`. Without looking at the
// *receiver* of that call, `enrich_impact_with_references` cannot tell
// `json.decode(...)` (a call to the external `json` library) from
// `rpc.decode()` (a call to the project-local `rpc.decode`), nor
// `self.decode()` inside `impl Codec` from the same expression inside
// `impl Parser`. The helpers below recover the receiver from the AST at the
// exact call site and decide whether it is compatible with the target's
// defined qualifier.
// =============================================================================

/// The receiver of a call site, recovered from the AST.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallReceiver {
    /// A bare call with no receiver: `decode(...)`.
    Bare,
    /// A receiver named by an explicit identifier: `json.decode(...)` ->
    /// `Named("json")`, `Codec::new()` -> `Named("Codec")`.
    Named(String),
    /// A `self` / `this` / `Self` receiver. The optional payload is the
    /// enclosing type the call lexically sits inside (`impl Codec { ... }` ->
    /// `Some("Codec")`), recovered from the AST when available.
    SelfRef(Option<String>),
    /// The receiver could not be determined (parse failure, position miss).
    /// Treated as compatible to avoid dropping a genuine caller.
    Unknown,
    /// explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT): a bare call
    /// whose name resolves to a same-named LOCAL binding (parameter, closure
    /// parameter, local `let`/`val`/`var`, or a closer same-named file-own
    /// definition) that shadows the cross-file target. Decided purely
    /// syntactically by an innermost-binding-wins scope walk (position-filtered,
    /// recursion-guarded). Such a site does NOT call the target -> rejected.
    ShadowedLocal,
}

impl CallReceiver {
    /// A short human-readable label for the resolved receiver, surfaced as
    /// the caller's `receiver_type` so users can see WHY the edge was kept.
    fn qualifier_label(&self) -> Option<String> {
        match self {
            CallReceiver::Named(n) => Some(n.clone()),
            CallReceiver::SelfRef(Some(t)) => Some(t.clone()),
            CallReceiver::SelfRef(None) => Some("self".to_string()),
            CallReceiver::Bare | CallReceiver::Unknown | CallReceiver::ShadowedLocal => None,
        }
    }
}

/// Return the receiver-qualifier a qualified function name is scoped under:
/// `rpc.decode` -> `Some("rpc")`, `Parser::decode` -> `Some("Parser")`,
/// `decode` -> `None`. Mirrors [`last_segment`] but returns the *prefix*.
fn qualifier_of(qualified: &str) -> Option<String> {
    let last_dot = qualified.rfind('.');
    let last_cc = qualified.rfind("::");
    let cut = match (last_dot, last_cc) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }?;
    if cut == 0 {
        return None;
    }
    let prefix = &qualified[..cut];
    // Keep only the *innermost* qualifier segment (e.g. `a.b.decode` -> `b`),
    // since that is the receiver expression at the call site.
    prefix
        .rsplit(['.', ':'])
        .find(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Decide whether a call site's `receiver` is compatible with a target whose
/// definition is scoped under `target_qualifier` and lives in `target_file`.
///
/// Rules (conservative — never drop a genuine caller, only reject a
/// provably-different receiver):
///   - `Unknown` receiver -> compatible (we could not inspect the site).
///   - `Bare` receiver -> compatible (an unqualified call could resolve to
///     the target in scope; the call graph itself handles the resolved
///     cases, this is only the fallback).
///   - `Named(r)`:
///       * if a `target_qualifier` is known, compatible iff `r` equals it
///         (`json` != `rpc` -> reject; `rpc` == `rpc` -> keep);
///       * if the target is a bare free function (no qualifier), a *named*
///         receiver means the call is a method on some object — a different
///         symbol — so reject.
///   - `SelfRef(Some(ty))` -> compatible iff the enclosing type equals the
///     target qualifier (the `impl Parser` vs `impl Codec` split) OR `ty`
///     INHERITS from the target qualifier — a `this->method()` self-call in a
///     DERIVED class binding a method defined on a BASE class (FEATURE-1 d.7-1,
///     inheritance proven from the call file's AST-extracted `ClassInfo.bases`);
///     if the target has no qualifier, a `self`-method call is a different
///     symbol -> reject.
///   - `SelfRef(None)` -> compatible (could not resolve the enclosing type;
///     do not over-reject).
fn receiver_compatible(
    receiver: &CallReceiver,
    target_qualifier: Option<&str>,
    _target_file: &Path,
    call_file: &Path,
    class_bases_by_file: &HashMap<PathBuf, HashMap<String, Vec<String>>>,
    colliding_quals: &HashSet<String>,
) -> bool {
    match (receiver, target_qualifier) {
        // explain-r8-bare-name-resolution-inherited: a bare name proven to bind
        // a same-named local (param/let/val/closer file-own def) is NOT the
        // cross-file target — reject regardless of the target's qualifier.
        (CallReceiver::ShadowedLocal, _) => false,
        (CallReceiver::Unknown, _) => true,
        (CallReceiver::Bare, _) => true,
        (CallReceiver::Named(r), Some(q)) => names_equal_ignore_generics(r, q),
        // Named receiver but the target is a bare free function: the call is
        // a method on an object, a different symbol.
        (CallReceiver::Named(_), None) => false,
        // FEATURE-1 d.7-1: a `self`/`this` call whose enclosing type is `ty` is
        // compatible with the target's type qualifier `q` when `ty == q` (the
        // `impl Parser` vs `impl Codec` split) OR when `ty` INHERITS from `q` — a
        // `this->method()` self-call in a DERIVED class binding a method defined on
        // a BASE class. Inheritance is proven only from the AST-extracted
        // `ClassInfo.bases` of the call file (pre-collected into
        // `class_bases_by_file`); an unproven relationship stays incompatible, so
        // an unrelated same-named sibling type is never wrongly attributed.
        //
        // critic FIX 1: the inheritance relaxation is DISABLED when `q` is a
        // COLLIDING qualifier (same class name on >= 2 targets). Proving `ty`
        // inherits *a* class named `q` cannot prove WHICH file's `q` — so on a
        // collision it would spray the self-call onto every same-named sibling.
        // We then fall back to the exact-match half only, which is BYTE-UNCHANGED
        // baseline behaviour (no wider than pre-existing on collisions).
        (CallReceiver::SelfRef(Some(ty)), Some(q)) => {
            names_equal_ignore_generics(ty, q)
                || (!colliding_quals.contains(q)
                    && class_bases_by_file
                        .get(call_file)
                        .is_some_and(|cb| selfref_type_inherits_qualifier(ty, q, cb)))
        }
        (CallReceiver::SelfRef(Some(_)), None) => false,
        (CallReceiver::SelfRef(None), _) => true,
    }
}

/// FEATURE-1 d.7-1: whether the `self`/`this` enclosing type `ty` inherits —
/// directly or transitively — from the target's type `qualifier`, using only the
/// AST-extracted `ClassInfo.bases` of the call file (`class_bases`, mapping a
/// class name to its declared base names). A `this->method()` self-call in a
/// DERIVED class whose method is defined on a BASE class is thereby recognized as
/// a genuine caller of that base method, instead of being dropped by the
/// exact-name receiver check.
///
/// Additive / never-worse: returns `true` ONLY when inheritance is PROVEN from
/// the extracted base lists (matched on the full base name or its last
/// `::`/`.`-separated segment, generics-tolerant); an unproven or absent
/// relationship returns `false`, so an unrelated same-named sibling type is never
/// wrongly attributed. Traversal is a depth-first walk over a LIFO `stack`
/// (`stack.pop()`), bounded by a visited set against cyclic base declarations.
fn selfref_type_inherits_qualifier(
    ty: &str,
    qualifier: &str,
    class_bases: &HashMap<String, Vec<String>>,
) -> bool {
    let mut stack: Vec<String> = match class_bases.get(ty) {
        Some(bases) => bases.clone(),
        None => return false,
    };
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(ty.to_string());
    while let Some(base) = stack.pop() {
        if !seen.insert(base.clone()) {
            continue;
        }
        let base_leaf = last_segment(&base);
        if names_equal_ignore_generics(&base, qualifier)
            || names_equal_ignore_generics(base_leaf, qualifier)
        {
            return true;
        }
        // Follow transitive bases whose intermediate class is defined in this
        // file too (keyed by full name or last segment).
        if let Some(next) = class_bases
            .get(&base)
            .or_else(|| class_bases.get(base_leaf))
        {
            for b in next {
                if !seen.contains(b) {
                    stack.push(b.clone());
                }
            }
        }
    }
    false
}

/// Compare two type/receiver names, tolerant of a trailing generic argument
/// list (`Parser<'a>` vs `Parser`).
fn names_equal_ignore_generics(a: &str, b: &str) -> bool {
    let strip = |s: &str| s.split(['<', '>']).next().unwrap_or(s).trim().to_string();
    strip(a) == strip(b)
}

/// fix-PW2-B5-impact-alias: case of a symbol name's first alphabetic char.
/// `Some(true)` = uppercase lead (a TYPE / MODULE name like `OrderedSet`,
/// `Mutex`), `Some(false)` = lowercase lead (an instance variable / value like
/// `set`, `_bits`, `rpc`), `None` = no alphabetic character.
fn first_alpha_is_uppercase(name: &str) -> Option<bool> {
    name.chars()
        .find(|c| c.is_alphabetic())
        .map(|c| c.is_uppercase())
}

/// fix-PW2-B5-impact-alias: a TYPE / class / module qualifier is uppercase-led
/// (Swift/Rust/Kotlin/Scala/Python types, OCaml modules). Used to gate the
/// unresolvable-collision relaxation so module-qualified targets (lua `rpc`)
/// keep strict receiver matching.
fn qualifier_is_type_like(qualifier: &str) -> bool {
    matches!(first_alpha_is_uppercase(qualifier), Some(true))
}

/// fix-PW2-B5-impact-alias: an instance-variable / value receiver is
/// lowercase-led (`set`, `_bits`) — provably NOT a type or module reference.
fn receiver_is_instance_like(receiver: &str) -> bool {
    matches!(first_alpha_is_uppercase(receiver), Some(false))
}

/// FEATURE-1 d.3 (was `unresolvable_collision_keeps`): the never-worse guard for
/// a CARDINALITY-1 (unique) target. When the receiver's declared type CANNOT be
/// inferred, a lowercase instance-variable receiver (`set.filter(...)`) against a
/// TYPE qualifier (`OrderedSet.filter`) is KEPT — a unique method name has only
/// one possible owner, so a caller a name-match would have kept must never be
/// dropped just because the receiver stayed untyped.
///
/// The caller now gates this on `!is_ambiguous` (unique target) in ADDITION to
/// the historic `any_resolved == false`. For an AMBIGUOUS (>= 2 definer)
/// collision this relaxation is NO LONGER applied: those callers must instead
/// prove receiver-TYPE compatibility (the retirement of the spray). Module-
/// qualified targets (lowercase qualifier like lua `rpc`) and type-named
/// receivers (uppercase like `Mutex`, `Codec`) return `false` and keep strict
/// matching, preserving the CL-2 `json`≠`rpc` and OCaml stdlib-homonym
/// discriminations.
fn never_worse_unique_keep(receiver: &CallReceiver, target_qualifier: Option<&str>) -> bool {
    match (receiver, target_qualifier) {
        (CallReceiver::Named(r), Some(q)) => {
            qualifier_is_type_like(q) && receiver_is_instance_like(r)
        }
        _ => false,
    }
}

/// Extract the receiver of the call whose method/function name is
/// `bare_target` at 1-indexed `(line, column)` in `file`, by parsing the AST.
///
/// Returns [`CallReceiver::Unknown`] on any failure (parse error, position
/// miss) so the caller treats the site as compatible rather than dropping it.
fn extract_call_receiver(
    file: &Path,
    line: usize,
    column: usize,
    bare_target: &str,
    language: Language,
    resolve_var_types: bool,
    any_resolved: bool,
    colliding_quals: &HashSet<String>,
) -> CallReceiver {
    use tree_sitter::Point;

    let (tree, source, _lang) = match parse_file(file) {
        Ok(t) => t,
        Err(_) => return CallReceiver::Unknown,
    };
    let src = source.as_bytes();

    // tree-sitter points are 0-indexed; references are 1-indexed.
    let row = line.saturating_sub(1);
    let col = column.saturating_sub(1);
    let point = Point::new(row, col);

    let root = tree.root_node();
    let mut node = match root.descendant_for_point_range(point, point) {
        Some(n) => n,
        None => return CallReceiver::Unknown,
    };

    // Land on the identifier node that names the called method. If the
    // position resolved to a wrapper, search for the matching name leaf.
    if node
        .utf8_text(src)
        .map(|t| t != bare_target)
        .unwrap_or(true)
    {
        if let Some(n) = find_named_leaf(&node, bare_target, src) {
            node = n;
        }
    }

    let receiver = receiver_for_call_name(&node, src, language);

    // explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT, Sub-fix B):
    // a genuinely-bare call may still NOT reach the cross-file target if its
    // name is shadowed by a same-named LOCAL binding (parameter / closure param
    // / local `let`/`val`/`var`) or a closer same-named file-own definition in
    // the caller's own scope. A bounded, innermost-binding-wins scope walk
    // (position-filtered, recursion-guarded) decides this purely syntactically.
    if matches!(receiver, CallReceiver::Bare) && shadows_bare_call(&node, src, bare_target) {
        return CallReceiver::ShadowedLocal;
    }

    // c3-cpp-method-caller-v1 (v0.5.0 AUDIT-FIX, C3 gap-a): cross-file member
    // upgrade. `receiver_for_call_name` / `receiver_from_expr` resolved the
    // receiver using only THIS file's AST. A C++ instance method called via a
    // member field inside an OUT-OF-LINE definition (`const char*
    // XMLElement::GetText() { return _value.GetStr(); }` where the inline-bodied
    // class lives in the SAME translation unit) is already handled in-file. When
    // the receiver is still a bare variable name AND the enclosing definition is
    // an out-of-line `Class::method`, look up `Class`'s field of that name
    // within THIS file's class bodies (bounded, no project-wide rescan) and, if
    // found, upgrade the receiver to its declared type so `receiver_compatible`
    // can match the target's type qualifier.
    if let CallReceiver::Named(var) = &receiver {
        if let Some(class_name) = enclosing_out_of_line_class(&node, src) {
            if let Some(ty) = find_class_field_type(&root, src, &class_name, var) {
                return CallReceiver::Named(ty);
            }
        }
        // FEATURE-1 d.3: general receiver->declared-type resolution. The C++
        // block above only covered same-file out-of-line member fields; this
        // generalizes it to every language the resolver understands by delegating
        // to the SAME `SourceTypeIndex` / `resolve_receiver_type_indexed`
        // machinery the call-graph builder (d.2) uses for typed dispatch. When
        // the variable's declared type is recoverable (`AlphaReader ar = ...`,
        // `let c: Codec`, `$a = new Alpha()`, a typed parameter), the receiver is
        // upgraded to that TYPE so `receiver_compatible` becomes a type check and
        // the call is attributed only to the matching definition. A miss keeps
        // the variable name unchanged so the never-worse invariant holds.
        //
        // Gated by `resolve_var_types` (set for a genuine multi-definer collision,
        // `is_ambiguous`). FEATURE-1 d.7-1 (critic FIX 2): the upgrade is DECLINED
        // when the resolved type is a COLLIDING qualifier (same class name on >= 2
        // targets) AND the call graph already resolved some edge (`any_resolved`) —
        // a type-name match then cannot pick WHICH file's `ty.method` owns the call,
        // so keeping it would spray onto every same-named sibling; the call graph's
        // file-aware resolution is authoritative there. For a DISTINCT (non-
        // colliding) qualifier the upgrade proceeds even after some edges resolved,
        // restoring recall; and when nothing resolved (`!any_resolved`) the upgrade
        // always proceeds (the b5 collision-keep behaviour). A miss keeps the
        // variable name unchanged so the never-worse invariant holds.
        //
        // critic v3 FIX: the collision-membership test is GENERICS-TOLERANT
        // (`names_equal_ignore_generics`), symmetric with the downstream
        // `(Named(r), Some(q))` compat compare — otherwise a resolved type carrying
        // a generic suffix (`Service<Foo>`) would miss the bare colliding qualifier
        // (`Service`) here yet still match BOTH targets downstream (which strips
        // generics), re-opening the spray in the very `any_resolved` branch this
        // guard protects.
        if resolve_var_types {
            if let Some(ty) = resolve_receiver_declared_type(&source, language, line as u32, var) {
                let ty_collides = colliding_quals
                    .iter()
                    .any(|q| names_equal_ignore_generics(q, &ty));
                if !(any_resolved && ty_collides) {
                    return CallReceiver::Named(ty);
                }
            }
        }
    }

    receiver
}

/// FEATURE-1 d.3: resolve the bare variable receiver `var` to its DECLARED TYPE
/// using the same `SourceTypeIndex` / `resolve_receiver_type_indexed` machinery
/// the call-graph builder relies on for typed dispatch, with `find_enclosing_class`
/// supplying the enclosing-scope context. Returns the bare type name, or `None`
/// when the type cannot be inferred (untyped / dynamic receiver).
fn resolve_receiver_declared_type(
    source: &str,
    language: Language,
    line: u32,
    var: &str,
) -> Option<String> {
    use crate::callgraph::find_enclosing_class;
    use crate::callgraph::type_resolver::{resolve_receiver_type_indexed, SourceTypeIndex};

    if var.is_empty() || is_self_token(var) {
        return None;
    }
    let index = SourceTypeIndex::build(language, source);
    let enclosing = find_enclosing_class(source, line);
    let (ty, _confidence) =
        resolve_receiver_type_indexed(&index, language, source, line, var, enclosing.as_deref());
    // Reject a degenerate self-mapping (`var` -> `var`) so an unresolved receiver
    // is never presented as its own type.
    match ty {
        Some(t) if t != var => Some(t),
        _ => None,
    }
}

/// c3-cpp-method-caller-v1 (v0.5.0 AUDIT-FIX, C3 gap-a): if the call leaf
/// `node` sits inside an OUT-OF-LINE method definition whose declarator is a
/// qualified `Class::method` (the C++ shape `RetType Class::method(...) {...}`),
/// return `Class`. Returns `None` for free functions and in-class (inline)
/// definitions (those resolve their members in-file already).
fn enclosing_out_of_line_class(node: &tree_sitter::Node, src: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "function_definition" {
            // The declarator carries the (possibly qualified) function name.
            if let Some(decl) = n.child_by_field_name("declarator") {
                if let Some(cls) = qualified_declarator_class(&decl, src) {
                    return Some(cls);
                }
            }
            return None;
        }
        cur = n.parent();
    }
    None
}

/// Walk a C++ declarator subtree looking for a `qualified_identifier` whose
/// `scope` names the owning class (`XMLNode::Value` -> `XMLNode`). Returns the
/// innermost scope segment.
fn qualified_declarator_class(node: &tree_sitter::Node, src: &[u8]) -> Option<String> {
    if node.kind() == "qualified_identifier" {
        if let Some(scope) = node.child_by_field_name("scope") {
            if let Ok(t) = scope.utf8_text(src) {
                let leaf = t.trim().rsplit("::").next().unwrap_or(t).trim();
                if !leaf.is_empty() {
                    return Some(leaf.to_string());
                }
            }
        }
    }
    if let Some(inner) = node.child_by_field_name("declarator") {
        if let Some(found) = qualified_declarator_class(&inner, src) {
            return Some(found);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = qualified_declarator_class(&child, src) {
            return Some(found);
        }
    }
    None
}

/// Recursively locate a `class_specifier`/`struct_specifier` named `class_name`
/// within `node`'s subtree and return the declared type of its `field`.
/// Bounded to the passed tree (the call site's own file), so no project-wide
/// rescan occurs. Handles the tree-sitter-cpp quirk of not always exposing the
/// class `name` field by falling back to the first `type_identifier` child.
fn find_class_field_type(
    node: &tree_sitter::Node,
    src: &[u8],
    class_name: &str,
    field: &str,
) -> Option<String> {
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(src).ok())
            .map(|t| t.trim().to_string())
            .or_else(|| {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "type_identifier" {
                        if let Ok(t) = child.utf8_text(src) {
                            if !t.is_empty() {
                                return Some(t.to_string());
                            }
                        }
                    }
                }
                None
            });
        if name.as_deref() == Some(class_name) {
            if let Some(body) = node.child_by_field_name("body") {
                if let Some(ty) = find_field_decl_type_in_subtree(&body, src, field) {
                    return Some(ty);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_class_field_type(&child, src, class_name, field) {
            return Some(found);
        }
    }
    None
}

/// Find a descendant identifier-ish leaf whose text equals `name`.
fn find_named_leaf<'a>(
    node: &tree_sitter::Node<'a>,
    name: &str,
    src: &[u8],
) -> Option<tree_sitter::Node<'a>> {
    if node.child_count() == 0 {
        return if node.utf8_text(src).map(|t| t == name).unwrap_or(false) {
            Some(*node)
        } else {
            None
        };
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_named_leaf(&child, name, src) {
            return Some(found);
        }
    }
    None
}

/// Given the AST leaf naming the called method, walk up to the enclosing
/// call expression and recover the receiver. Per-language node shapes:
///   - Rust:  `field_expression { value, field }` under `call_expression`
///            (method call), or `scoped_identifier { path, name }` (Type::m).
///   - Lua/Luau: `dot_index_expression` / `method_index_expression` whose
///            first identifier child is the receiver table.
///   - Python/JS/TS/Java/etc.: `attribute` / `member_expression` /
///            `field_access` / `selector_expression` with an object child.
///   - Go: `selector_expression { operand, field }`.
fn receiver_for_call_name(
    node: &tree_sitter::Node,
    src: &[u8],
    _language: Language,
) -> CallReceiver {
    // Walk up to the immediate qualifier node (member/field/dot access).
    let parent = match node.parent() {
        Some(p) => p,
        None => return CallReceiver::Bare,
    };

    match parent.kind() {
        // Rust method call: receiver.method() — `field_expression`.
        "field_expression" => {
            // The `value` field is the receiver; the `field` is the method.
            if let Some(value) = parent.child_by_field_name("value") {
                return receiver_from_expr(&value, src);
            }
            // Fallback: first named child is the receiver expression.
            if let Some(first) = parent.named_child(0) {
                if first.id() != node.id() {
                    return receiver_from_expr(&first, src);
                }
            }
            CallReceiver::Bare
        }

        // Rust associated call: Type::method() — `scoped_identifier`.
        "scoped_identifier" | "scoped_type_identifier" => {
            if let Some(path) = parent.child_by_field_name("path") {
                if let Ok(t) = path.utf8_text(src) {
                    return classify_receiver_text(t);
                }
            }
            CallReceiver::Bare
        }

        // Lua/Luau: json.decode(...) / obj:method(...).
        "dot_index_expression" | "method_index_expression" => {
            // First identifier child is the receiver table/object.
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if child.id() == node.id() {
                    break;
                }
                if matches!(
                    child.kind(),
                    "identifier" | "dot_index_expression" | "method_index_expression"
                ) {
                    return receiver_from_expr(&child, src);
                }
            }
            CallReceiver::Bare
        }

        // Python attribute access: receiver.method.
        "attribute" => {
            if let Some(obj) = parent.child_by_field_name("object") {
                return receiver_from_expr(&obj, src);
            }
            CallReceiver::Bare
        }

        // JS/TS member expression: receiver.method.
        "member_expression" => {
            if let Some(obj) = parent.child_by_field_name("object") {
                return receiver_from_expr(&obj, src);
            }
            CallReceiver::Bare
        }

        // FEATURE-1 d.3: PHP instance method call `$obj->method(...)` /
        // nullsafe `$obj?->method(...)`. The grammar (tree-sitter-php) exposes the
        // receiver on the `object` field and the method on `name`; without this
        // arm the method leaf's parent is unmatched and every PHP member call
        // resolved to `Bare` (compatible with everything -> sprayed onto every
        // sibling `format`/`render` definition). Recovering the receiver lets the
        // type-discrimination below attribute the call to the correct class only.
        "member_call_expression" | "nullsafe_member_call_expression" => {
            if let Some(obj) = parent.child_by_field_name("object") {
                return receiver_from_expr(&obj, src);
            }
            CallReceiver::Bare
        }

        // FEATURE-1 d.3: C# member access `recv.Method(...)`. tree-sitter-c-sharp
        // parses `recv.Read()` as `invocation_expression(function:
        // member_access_expression(expression: recv, name: Read))`, so the method
        // leaf's parent is the `member_access_expression` and the receiver is its
        // `expression` field. Without this arm C# member calls resolved to `Bare`
        // and `impact Read` broadcast one call site across every `Read` definer.
        "member_access_expression" => {
            if let Some(obj) = parent
                .child_by_field_name("expression")
                .or_else(|| parent.child_by_field_name("object"))
            {
                return receiver_from_expr(&obj, src);
            }
            if let Some(first) = parent.named_child(0) {
                if first.id() != node.id() {
                    return receiver_from_expr(&first, src);
                }
            }
            CallReceiver::Bare
        }

        // Java/C#/Kotlin field/member access: receiver.method.
        //
        // fix-PW2-B5-impact-alias: Swift `recv.method` parses as
        // `(navigation_expression target: <recv> suffix: (navigation_suffix
        // suffix: <method>))`, so the method leaf's parent is the
        // `navigation_suffix` and the receiver is the GRANDPARENT
        // `navigation_expression`'s `target` field. Without this the swift
        // member call resolved to `Bare` and `impact` could not discriminate
        // (or recover) method callers at all.
        "field_access" | "navigation_expression" | "navigation_suffix" => {
            if parent.kind() == "navigation_suffix" {
                if let Some(grand) = parent.parent() {
                    if let Some(tgt) = grand.child_by_field_name("target") {
                        return receiver_from_expr(&tgt, src);
                    }
                    // FEATURE-1 d.3: Kotlin `c.doIt()` parses as
                    // `navigation_expression(<subject> navigation_suffix(. doIt))`
                    // with NO `target` field (unlike Swift). The receiver is the
                    // first named child of the navigation_expression that precedes
                    // the suffix. Without this Kotlin member calls resolved to
                    // `Bare` and sprayed across every same-named method definer.
                    if let Some(first) = grand.named_child(0) {
                        if first.id() != parent.id() {
                            return receiver_from_expr(&first, src);
                        }
                    }
                }
            }
            if let Some(obj) = parent.child_by_field_name("object") {
                return receiver_from_expr(&obj, src);
            }
            if let Some(first) = parent.named_child(0) {
                if first.id() != node.id() {
                    return receiver_from_expr(&first, src);
                }
            }
            CallReceiver::Bare
        }

        // Go selector: receiver.Method.
        "selector_expression" => {
            if let Some(op) = parent.child_by_field_name("operand") {
                return receiver_from_expr(&op, src);
            }
            CallReceiver::Bare
        }

        // C++ / PHP / Ruby qualified call shapes.
        "scoped_call_expression" | "qualified_identifier" => {
            if let Some(scope) = parent.child_by_field_name("scope") {
                if let Ok(t) = scope.utf8_text(src) {
                    return classify_receiver_text(t);
                }
            }
            CallReceiver::Bare
        }

        // explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT, Sub-fix A):
        // OCaml qualified value callee. `Mutex.unlock m` parses as
        // `application_expression` whose `function:` field is a `value_path`
        // with named children `module_path` (the qualifier, holding
        // `module_name` leaves) then `value_name` (the called name). A bare
        // `unlock m` is the SAME `value_path` node-kind but with only the
        // `value_name` child. `value_path` has NO fields — the qualifier vs the
        // name differ ONLY by node-kind among the named children (verified
        // against tree-sitter-ocaml v0.24.2 grammar.js / node-types.json and the
        // codebase's own references.rs::classify_ocaml_reference). Recovering the
        // qualifier into `Named(...)` lets `receiver_compatible` reject the
        // stdlib homonym (`Mutex` != the bare project-local `unlock`).
        "value_path" => {
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if !child.is_named() {
                    continue;
                }
                if matches!(child.kind(), "module_path" | "extended_module_path") {
                    // Prefer the trailing `module_name` segment so `A.B.unlock`
                    // -> Named("B") (the immediately-enclosing module).
                    if let Some(q) = last_module_segment_text(&child, src) {
                        return CallReceiver::Named(q);
                    }
                }
            }
            // Only named child is the `value_name` itself -> genuine bare /
            // self-recursive call.
            CallReceiver::Bare
        }

        // No qualifier node above the call name -> a bare call.
        _ => CallReceiver::Bare,
    }
}

/// explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT): walk an OCaml
/// `module_path` / `extended_module_path` subtree to its trailing `module_name`
/// leaf (the innermost / immediately-enclosing module qualifier). For `A.B.f`
/// the path is left-nested `(module_path (module_path (module_name A)) (module_name B))`
/// so the LAST `module_name` by source position is `B`.
fn last_module_segment_text(node: &tree_sitter::Node, src: &[u8]) -> Option<String> {
    let mut best: Option<tree_sitter::Node> = None;
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if n.kind() == "module_name" {
            let take = match &best {
                Some(b) => n.start_byte() > b.start_byte(),
                None => true,
            };
            if take {
                best = Some(n);
            }
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    best.and_then(|b| b.utf8_text(src).ok())
        .map(|s| s.to_string())
}

/// explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT, Sub-fix B):
/// decide whether a bare call to `bare_target` at `call_node` resolves to a
/// same-named LOCAL binding that shadows the cross-file target, rather than to
/// the target itself. Purely syntactic — no type inference.
///
/// Algorithm (innermost-binding-wins, mirroring the canonical lexical-lookup
/// rule from the Scala spec / Crafting Interpreters / SwiftLexicalLookup /
/// OCaml `Env`): walk up the enclosing scopes from the call site. At each
/// scope, inspect ONLY the children that lexically PRECEDE the branch that
/// contains the call (the position filter) for:
///   - a parameter / closure-parameter binder named `bare_target`, or
///   - a local `let`/`val`/`var`/`let_binding` value binding of `bare_target`.
/// The first match wins -> shadowed. Because the branch containing the call is
/// the cut-off, the enclosing *defining* binding of a self-recursive function
/// (whose body contains the call) is never scanned — that is the recursion
/// guard, so a legitimate bare self-call stays `Bare`.
fn shadows_bare_call(call_node: &tree_sitter::Node, src: &[u8], bare_target: &str) -> bool {
    let mut boundary = *call_node;
    let mut scope = call_node.parent();
    while let Some(s) = scope {
        let mut cursor = s.walk();
        for child in s.children(&mut cursor) {
            if child.id() == boundary.id() {
                // Reached the branch that contains the call: everything from
                // here on is at-or-after the use site (position filter) and the
                // recursion guard (the defining binding is exactly this branch).
                break;
            }
            if subtree_binds_parameter(&child, src, bare_target) {
                return true;
            }
            if binding_introduces_name(&child, src, bare_target) {
                return true;
            }
        }
        boundary = s;
        scope = s.parent();
    }
    false
}

/// Parameter binder node-kinds across the 6 uncovered grammars (and the others,
/// harmlessly): a `parameter` / `class_parameter` / `closure_parameter` /
/// `lambda_parameter` whose bound identifier equals `target` shadows the call.
/// A parameter can never be the recursive function itself, so it ALWAYS
/// shadows. Search is bounded — it does not descend into nested function /
/// closure bodies (those introduce their own, sibling scopes).
fn subtree_binds_parameter(node: &tree_sitter::Node, src: &[u8], target: &str) -> bool {
    const PARAM_KINDS: &[&str] = &[
        "parameter",
        "class_parameter",
        "closure_parameter",
        "lambda_parameter",
    ];
    const STOP_KINDS: &[&str] = &[
        // Nested callable / closure scopes: their params belong to a deeper
        // scope, not this one.
        "function_declaration",
        "function_definition",
        "function_item",
        "method_declaration",
        "method_definition",
        "lambda_literal",
        "closure_expression",
        "anonymous_function",
    ];
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if PARAM_KINDS.contains(&n.kind()) && param_binds_name(&n, src, target) {
            return true;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            // Do not descend into a nested callable's body, but DO inspect the
            // top `node` itself even if it is callable-shaped.
            if ch.id() != n.id() && STOP_KINDS.contains(&ch.kind()) {
                continue;
            }
            stack.push(ch);
        }
    }
    false
}

/// Does parameter node `param` bind an identifier equal to `target`? Tries the
/// `name` field first, then the first identifier-ish leaf (Swift/Scala/Kotlin
/// `simple_identifier`/`identifier`; OCaml `value_name`/`value_pattern`).
fn param_binds_name(param: &tree_sitter::Node, src: &[u8], target: &str) -> bool {
    if let Some(name) = param.child_by_field_name("name") {
        if name.utf8_text(src).map(|t| t == target).unwrap_or(false) {
            return true;
        }
    }
    let mut stack = vec![*param];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "simple_identifier" | "identifier" | "value_name" | "value_pattern"
        ) && n.utf8_text(src).map(|t| t == target).unwrap_or(false)
        {
            return true;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    false
}

/// Does the (preceding) sibling/outer node `node` introduce a local value
/// binding of `target` — an OCaml `let_binding`/`value_definition`, a
/// Swift/Kotlin `property_declaration`, or a Scala `val`/`var` definition?
/// This covers the "closer same-named file-own definition" case (lwt_io's own
/// `let unlock`) and sequential local `let`/`val` shadowing.
fn binding_introduces_name(node: &tree_sitter::Node, src: &[u8], target: &str) -> bool {
    match node.kind() {
        // OCaml top-level / let-in value bindings.
        "value_definition" | "let_binding" => {
            // The bound name is a `value_name` leaf that is NOT inside a
            // `parameter` (parameters are separate binders already handled).
            ocaml_binding_name_is(node, src, target)
        }
        // Swift / Kotlin local `let`/`var`.
        "property_declaration" => first_binding_ident_is(node, src, target),
        // Scala local `val`/`var`.
        "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
            first_binding_ident_is(node, src, target)
        }
        _ => false,
    }
}

/// OCaml: is the bound `value_name` of this `value_definition`/`let_binding`
/// equal to `target`? Only the binding's OWN name counts — the name node is a
/// direct `value_name` child of the `let_binding` (not one nested inside a
/// `parameter`).
fn ocaml_binding_name_is(node: &tree_sitter::Node, src: &[u8], target: &str) -> bool {
    let binding = if node.kind() == "let_binding" {
        Some(*node)
    } else {
        let mut found = None;
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if ch.kind() == "let_binding" {
                found = Some(ch);
                break;
            }
        }
        found
    };
    let Some(binding) = binding else {
        return false;
    };
    let mut c = binding.walk();
    for ch in binding.children(&mut c) {
        if ch.kind() == "value_name" {
            return ch.utf8_text(src).map(|t| t == target).unwrap_or(false);
        }
        // Stop before parameters / the `=` body so we only read the bound name.
        if ch.kind() == "parameter" {
            break;
        }
    }
    false
}

/// Swift/Kotlin/Scala value binding: does the LEFTMOST bound identifier
/// (`simple_identifier` / `identifier`, i.e. the binding pattern, which always
/// precedes the `=` initializer) equal `target`? Only the bound name counts —
/// an identifier appearing in the initializer must not be mistaken for the
/// binder (so `let x = push` does NOT shadow a `push` call).
fn first_binding_ident_is(node: &tree_sitter::Node, src: &[u8], target: &str) -> bool {
    let mut leftmost: Option<tree_sitter::Node> = None;
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "simple_identifier" | "identifier") {
            let take = match &leftmost {
                Some(b) => n.start_byte() < b.start_byte(),
                None => true,
            };
            if take {
                leftmost = Some(n);
            }
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    leftmost
        .and_then(|b| b.utf8_text(src).ok())
        .map(|t| t == target)
        .unwrap_or(false)
}

/// Classify a receiver expression node into a [`CallReceiver`]. A leading
/// `self` / `this` / `Self` is reported as a self-reference (with the
/// enclosing type resolved from the AST when possible); anything else with a
/// recoverable leading identifier becomes a `Named` receiver.
///
/// c3-cpp-method-caller-v1 (v0.5.0 AUDIT-FIX, C3 gap-a): for an INSTANCE
/// receiver (`_value.GetStr()`, `endTag.GetStr()`) the leading identifier is a
/// *variable*, not a type. The CL-2 receiver-compatibility check compares the
/// receiver against the target's *type* qualifier (`StrPair`), so a raw
/// `Named("_value")` is wrongly rejected even though `_value`'s declared type
/// IS `StrPair`. Before falling back to the bare variable name, we attempt to
/// resolve that variable's declared type from the AST (a local declaration in
/// the enclosing function or a field declaration in the enclosing class). When
/// resolved, we emit the *type* as the `Named` receiver so the downstream
/// `receiver_compatible(Named(type), Some(qualifier))` check matches. When it
/// cannot be resolved we keep the historic bare-name behaviour, so the
/// json/rpc and Parser/Codec discrimination (cl2-receiver-resolution-v1) is
/// unchanged: an unresolved `json` stays `Named("json")` and is still rejected
/// against the `rpc` qualifier.
fn receiver_from_expr(expr: &tree_sitter::Node, src: &[u8]) -> CallReceiver {
    // For nested qualifiers (`a.b`, `Mod::Sub`), take the *innermost* leading
    // identifier — that is the variable/type whose `.method` is being called.
    if let Ok(text) = expr.utf8_text(src) {
        let base_node = receiver_base_node(expr);
        let base = match base_node {
            Some(n) => n.utf8_text(src).unwrap_or(text),
            None => text,
        };
        if is_self_token(base) {
            return CallReceiver::SelfRef(resolve_enclosing_type(expr, src));
        }
        // c3-cpp-method-caller-v1: try to upgrade the bare variable receiver to
        // its declared TYPE. Only attempt when `base` looks like an instance
        // variable (i.e. not already a Type-cased token that the qualifier
        // match would handle directly). Resolution is AST-driven and bounded
        // to the receiver's own translation unit; a miss returns the variable
        // name unchanged.
        if let Some(resolved_ty) = resolve_receiver_var_type(expr, src, base) {
            return CallReceiver::Named(resolved_ty);
        }
        return classify_receiver_text(base);
    }
    CallReceiver::Unknown
}

/// c3-cpp-method-caller-v1 (v0.5.0 AUDIT-FIX, C3 gap-a): resolve the declared
/// type of the receiver variable `var` named at the call site `node`, walking
/// the AST upward from the call expression.
///
/// Resolution strategy (AST-only, no string/regex heuristics on whole files):
///   1. Walk up to the enclosing function/method body. Inside it, look for a
///      declaration of `var` that carries a type — covering
///        - C/C++ `StrPair endTag;` / `StrPair endTag( ... )`
///          (`declaration` with a `type` field + an identifier declarator), and
///        - the `Type var = ...;` shape across C-family grammars.
///   2. If no local declaration is found, walk up to the enclosing class /
///      struct body and look for a *field* declaration named `var` with a
///      type (covers C++ member fields like `StrPair _value;`).
///
/// Returns the bare type name (generics / pointers / references stripped to the
/// leading type identifier) on success, or `None` when the variable's type
/// cannot be determined — in which case the caller keeps the bare variable
/// name so existing receiver discrimination is preserved.
fn resolve_receiver_var_type(node: &tree_sitter::Node, src: &[u8], var: &str) -> Option<String> {
    if var.is_empty() || is_self_token(var) {
        return None;
    }

    // 1. Search the enclosing function/method body for a local declaration.
    let mut cur = node.parent();
    let mut enclosing_callable: Option<tree_sitter::Node> = None;
    while let Some(n) = cur {
        match n.kind() {
            "function_definition"
            | "function_declaration"
            | "method_definition"
            | "function_item"
            | "method_declaration"
            | "constructor_declaration" => {
                enclosing_callable = Some(n);
                break;
            }
            _ => {}
        }
        cur = n.parent();
    }
    if let Some(body) = enclosing_callable {
        if let Some(ty) = find_var_decl_type_in_subtree(&body, src, var) {
            return Some(ty);
        }
    }

    // 2. Search the enclosing class/struct body for a field declaration.
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            "class_specifier" | "struct_specifier" | "class_declaration" | "class_definition"
            | "struct_item" | "impl_item" => {
                if let Some(ty) = find_field_decl_type_in_subtree(&n, src, var) {
                    return Some(ty);
                }
            }
            _ => {}
        }
        cur = n.parent();
    }

    None
}

/// Strip a C-family type expression down to its leading type *identifier*
/// (`const StrPair&` -> `StrPair`, `std::string` -> keep last segment `string`,
/// `Foo<Bar>` -> `Foo`). Returns `None` for primitive/empty results that could
/// never name a project type.
fn type_leaf_name(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    // Drop a trailing reference/pointer/qualifier cluster.
    t = t.trim_end_matches(['&', '*', ' ']);
    // Take the part before any generic argument list.
    if let Some(idx) = t.find('<') {
        t = &t[..idx];
    }
    // Drop leading qualifiers like `const`, `struct`, `class`, `volatile`.
    let cleaned: Vec<&str> = t
        .split_whitespace()
        .filter(|w| {
            !matches!(
                *w,
                "const" | "struct" | "class" | "volatile" | "mutable" | "static"
            )
        })
        .collect();
    let last = cleaned.last().copied().unwrap_or(t).trim();
    // Keep only the trailing `::` segment so `tinyxml2::StrPair` -> `StrPair`.
    let leaf = last.rsplit("::").next().unwrap_or(last).trim();
    if leaf.is_empty() {
        return None;
    }
    Some(leaf.to_string())
}

/// Recursively search `root` for a *local variable declaration* that introduces
/// a binding named `var` with a recoverable type. Handles the C-family
/// `declaration` node shape (a `type` field plus a declarator that ultimately
/// names `var`).
fn find_var_decl_type_in_subtree(
    root: &tree_sitter::Node,
    src: &[u8],
    var: &str,
) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if matches!(child.kind(), "declaration" | "field_declaration") {
            if let Some(ty_node) = child.child_by_field_name("type") {
                if declarator_binds_name(&child, src, var) {
                    if let Ok(raw) = ty_node.utf8_text(src) {
                        if let Some(leaf) = type_leaf_name(raw) {
                            return Some(leaf);
                        }
                    }
                }
            }
        }
        if let Some(found) = find_var_decl_type_in_subtree(&child, src, var) {
            return Some(found);
        }
    }
    None
}

/// Recursively search a class/struct `root` for a *field* declaration named
/// `var` with a recoverable type. C++ member fields parse as `field_declaration`
/// nodes; the C-family `declaration` shape is accepted too for robustness.
fn find_field_decl_type_in_subtree(
    root: &tree_sitter::Node,
    src: &[u8],
    var: &str,
) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if matches!(child.kind(), "field_declaration" | "declaration") {
            if let Some(ty_node) = child.child_by_field_name("type") {
                if declarator_binds_name(&child, src, var) {
                    if let Ok(raw) = ty_node.utf8_text(src) {
                        if let Some(leaf) = type_leaf_name(raw) {
                            return Some(leaf);
                        }
                    }
                }
            }
        }
        // Recurse into nested scopes (access-specifier groups, nested types).
        if let Some(found) = find_field_decl_type_in_subtree(&child, src, var) {
            return Some(found);
        }
    }
    None
}

/// Whether a C-family `declaration` / `field_declaration` node's declarator
/// ultimately binds an identifier equal to `var`. Walks the declarator subtree
/// (skipping the `type` field) collecting the bound identifier leaves —
/// covering `StrPair endTag;`, `StrPair* p;`, `StrPair endTag(...)` and the
/// `init_declarator` (`StrPair x = ...;`) shape.
fn declarator_binds_name(decl: &tree_sitter::Node, src: &[u8], var: &str) -> bool {
    let type_field = decl.child_by_field_name("type");
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        // Skip the type half so a type identifier that happens to equal `var`
        // is not mistaken for the bound name.
        if let Some(tf) = type_field {
            if child.id() == tf.id() {
                continue;
            }
        }
        if declarator_names_identifier(&child, src, var) {
            return true;
        }
    }
    false
}

/// Recursively check whether a declarator subtree binds the identifier `var`.
/// The bound name is the `declarator`-field identifier (or, lacking field
/// access, the first plain `identifier`/`field_identifier` leaf encountered).
fn declarator_names_identifier(node: &tree_sitter::Node, src: &[u8], var: &str) -> bool {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" => {
            return node.utf8_text(src).map(|t| t == var).unwrap_or(false);
        }
        _ => {}
    }
    // Prefer the canonical `declarator` field when present.
    if let Some(inner) = node.child_by_field_name("declarator") {
        if declarator_names_identifier(&inner, src, var) {
            return true;
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if declarator_names_identifier(&child, src, var) {
            return true;
        }
    }
    false
}

/// Descend a qualifier expression to its leading base identifier (the
/// left-most operand of `a.b.c` / `a::b::c`).
fn receiver_base_node<'a>(expr: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cur = *expr;
    loop {
        match cur.kind() {
            "field_expression" | "attribute" | "member_expression" | "selector_expression" => {
                let next = cur
                    .child_by_field_name("value")
                    .or_else(|| cur.child_by_field_name("object"))
                    .or_else(|| cur.child_by_field_name("operand"))
                    .or_else(|| cur.named_child(0));
                match next {
                    Some(n) if n.id() != cur.id() => cur = n,
                    _ => return Some(cur),
                }
            }
            "dot_index_expression" | "method_index_expression" => match cur.named_child(0) {
                Some(n) if n.id() != cur.id() => cur = n,
                _ => return Some(cur),
            },
            "scoped_identifier" | "scoped_type_identifier" | "qualified_identifier" => {
                match cur
                    .child_by_field_name("path")
                    .or_else(|| cur.child_by_field_name("scope"))
                {
                    Some(n) if n.id() != cur.id() => cur = n,
                    _ => return Some(cur),
                }
            }
            _ => return Some(cur),
        }
    }
}

/// Turn raw receiver text into a [`CallReceiver`]. A self/this token becomes
/// a self-reference with no resolved type; any other non-empty token becomes
/// a named receiver.
fn classify_receiver_text(text: &str) -> CallReceiver {
    let t = text.trim();
    if t.is_empty() {
        return CallReceiver::Bare;
    }
    if is_self_token(t) {
        return CallReceiver::SelfRef(None);
    }
    CallReceiver::Named(t.to_string())
}

/// Whether a receiver token denotes the current instance/type.
fn is_self_token(t: &str) -> bool {
    matches!(t, "self" | "this" | "Self" | "super")
}

/// Resolve the type a `self`/`this` call lexically belongs to by walking up
/// the AST to the enclosing `impl <Type>` (Rust) / class / struct block and
/// reading its type name. Returns `None` when no such enclosing type exists.
fn resolve_enclosing_type(node: &tree_sitter::Node, src: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            // Rust: impl <Type> { ... } — the `type` field names the type.
            "impl_item" => {
                if let Some(ty) = n.child_by_field_name("type") {
                    if let Ok(t) = ty.utf8_text(src) {
                        return Some(t.trim().to_string());
                    }
                }
            }
            // Class/struct definitions across languages — the `name` field.
            "class_declaration"
            | "class_definition"
            | "class_specifier"
            | "struct_specifier"
            | "struct_item"
            | "interface_declaration"
            | "object_declaration"
            | "trait_item" => {
                if let Some(name) = n.child_by_field_name("name") {
                    if let Ok(t) = name.utf8_text(src) {
                        return Some(t.trim().to_string());
                    }
                }
            }
            _ => {}
        }
        cur = n.parent();
    }
    None
}

/// AST-driven check: does `file` actually contain a definition of the
/// function named by `qualified` (compared on its leaf segment)?
///
/// cross-cutting-and-clear-fix-bugs-v1 (P18.R2) / REG-SWIFT-IMPACT: the
/// project call graph can mis-attribute a qualified `Type.method` target's
/// `dst_file` to a file that merely *extends* `Type` (e.g. an `extension
/// Heap { ... }` in a `Tests/` file) without defining the queried method.
/// In polyglot mode the impact command runs one pass per detected language,
/// and the merged call graph emits that phantom swift target during the
/// NON-swift passes — where the swift-gated reconciliation below never runs —
/// so the fabricated `Tests/HeapTests/HeapTests.swift` row survives the
/// per-pass merge.
///
/// This helper parses `file` in its OWN language (recovered from the path,
/// not the scan-pass language) and asks the AST extractors whether a
/// function or method whose leaf name equals `qualified`'s leaf is genuinely
/// declared there. It is the authoritative, AST-only discriminator used to
/// reject a target file that does not define the function. Parse failures or
/// an unknown language return `false` (no claim of a definition).
fn file_defines_function(file: &Path, qualified: &str) -> bool {
    let Some(language) = Language::from_path(file) else {
        return false;
    };
    let (tree, source, _detected) = match parse_file(file) {
        Ok(result) => result,
        Err(_) => return false,
    };
    let leaf = last_segment(qualified);
    let functions = extract_functions(&tree, &source, language);
    let methods = extract_methods(&tree, &source, language);
    functions
        .iter()
        .chain(methods.iter())
        .any(|name| last_segment(name) == leaf)
}

/// fix-PW2-B5-impact-alias: recover the enclosing TYPE qualifier for an
/// AST-discovered definition so a collision-suppressed method row is keyed
/// `Type.method` (per-definition keying) instead of a bare `method`.
///
/// A bare method name makes [`enrich_impact_with_references`] treat the target
/// as a free function and blank EVERY `recv.method(...)` caller. Re-parsing the
/// file via [`crate::extract_file`] (the same AST source the enrichment pass
/// already uses) lets us attach the real class/struct qualifier.
///
/// Already-qualified names (`Class.method`, `Type::method`) and genuine
/// free functions (a name that is itself a top-level function in the file)
/// are returned unchanged so module-level functions are never mis-qualified.
fn qualify_ast_method_name(file: &Path, func_name: &str) -> String {
    if func_name.contains('.') || func_name.contains("::") {
        return func_name.to_string();
    }
    let module = match crate::extract_file(file, None) {
        Ok(m) => m,
        Err(_) => return func_name.to_string(),
    };
    // A name that is ALSO a top-level free function in this file stays bare:
    // qualifying it would invent a spurious receiver.
    if module.functions.iter().any(|f| f.name == func_name) {
        return func_name.to_string();
    }
    for class in &module.classes {
        if class.methods.iter().any(|m| m.name == func_name) {
            return format!("{}.{}", class.name, func_name);
        }
    }
    func_name.to_string()
}

/// Search for a function in the AST of files under `root`.
///
/// Returns a list of (function_name, file_path) pairs if found, or None.
fn find_function_in_ast(
    root: &Path,
    target_func: &str,
    target_file: Option<&Path>,
    language: Language,
) -> Option<Vec<(String, PathBuf)>> {
    let extensions: HashSet<String> = language
        .extensions()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let files = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        match get_file_tree(root, Some(&extensions), true, None) {
            Ok(tree) => collect_files(&tree, root),
            Err(_) => return None,
        }
    };

    let mut found: Vec<(String, PathBuf)> = Vec::new();

    for file_path in &files {
        // Apply target_file filter if provided
        if let Some(filter) = target_file {
            if !file_path.ends_with(filter) && file_path.as_path() != filter {
                continue;
            }
        }

        // Parse the file
        let (tree, source, _detected_lang) = match parse_file(file_path) {
            Ok(result) => result,
            Err(_) => continue,
        };

        // Extract functions and methods
        let functions = extract_functions(&tree, &source, language);
        let methods = extract_methods(&tree, &source, language);

        // rust-impl-qualifier-v1 (VAL-RUST-QUAL): when the user-typed
        // target carries a `Type::method` qualifier AND the file is
        // Rust, augment the candidate set with qualified `Type::method`
        // names extracted from `impl <Type> { ... }` / `trait <Trait>`
        // blocks. The bare-name list still flows through
        // `names_match`, but we then filter to ONLY accept candidates
        // whose impl-type matches the user-typed qualifier — so
        // `Glob::parse` no longer matches a `parse` defined inside an
        // unrelated `impl Config { ... }` or in the top-level
        // `flags/parse.rs` module.
        let rust_target_qualifier: Option<&str> =
            if matches!(language, Language::Rust) && target_func.contains("::") {
                target_func.rsplit_once("::").map(|(ty, _)| ty)
            } else {
                None
            };

        let qualified_methods: Vec<String> = if rust_target_qualifier.is_some() {
            let mut q = Vec::new();
            extract_rust_impl_methods_qualified(&tree, &source, &mut q);
            q
        } else {
            Vec::new()
        };

        if let Some(qualifier) = rust_target_qualifier {
            // Strict qualified path: a candidate is accepted ONLY if its
            // emitted qualified form ends with the user-typed qualifier
            // (handles `some::module::Type::method` too) and the leaf
            // method matches the user-typed leaf.
            let target_leaf = target_func.rsplit("::").next().unwrap_or(target_func);
            for qual in &qualified_methods {
                // Split `Type::method` once from the right.
                let Some((cand_qual, cand_method)) = qual.rsplit_once("::") else {
                    continue;
                };
                if cand_method != target_leaf {
                    continue;
                }
                // Accept when the candidate qualifier equals the user
                // qualifier OR the candidate qualifier ends with
                // `::<user_qualifier>` (so module-scoped impls still
                // resolve when the user typed just the type name).
                let qualifier_matches =
                    cand_qual == qualifier || cand_qual.ends_with(&format!("::{qualifier}"));
                if qualifier_matches {
                    // Emit the qualified form so downstream surfaces
                    // (impact/whatbreaks/context) preserve `Type::method`
                    // in the resolved key + function name.
                    found.push((qual.clone(), file_path.clone()));
                }
            }
            // IMPORTANT: do not fall through to the lenient bare-name
            // matcher when the user explicitly typed a Rust qualifier.
            // The whole point of this fix is that `Glob::parse` must NOT
            // match unrelated bare `parse` definitions.
        } else {
            for func_name in functions.iter().chain(methods.iter()) {
                // cross-command-consistency-v3 (P5.BUG-N3): use the symmetric
                // matcher so AST-extracted bare names (e.g. `run`) reconcile
                // against user-typed qualified names (e.g. `Flask.run`). Bare
                // method names are how `extract_methods` reports class members
                // for most languages, so the previous one-direction match
                // returned `None` for every `Class.method` query and produced
                // the user-visible `Function not found` regression.
                if names_match(func_name, target_func) {
                    found.push((func_name.clone(), file_path.clone()));
                }
            }
        }
    }

    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

/// Build the human-readable note emitted by the AST-fallback path when a
/// function is found in source but has no edges in the call graph (VAL-007).
///
/// The three branches map to user-visible realities:
/// - Exported + multi-root workspace: the most likely cause is unresolved
///   `tsconfig.json` path aliases. Callers exist, we just didn't see them.
/// - Exported + no workspace detected: the user may be running from a
///   single-package subdirectory of a monorepo. Tell them how to widen scope.
/// - Private / not-detectable visibility: retain the conservative wording;
///   a truly isolated private function with zero callers IS a real result.
fn build_ast_fallback_note(
    is_exported: bool,
    multi_root: bool,
    workspace_paths: &[String],
    project_root: &Path,
) -> String {
    if multi_root {
        if is_exported {
            let shown: Vec<&str> = workspace_paths.iter().take(3).map(String::as_str).collect();
            let ellipsis = if workspace_paths.len() > 3 {
                format!(", ... ({} more)", workspace_paths.len() - 3)
            } else {
                String::new()
            };
            format!(
                "Function is exported but no callers found across workspace roots [{}{}]. \
                 If this is unexpected, tsconfig.json path aliases may not be resolving correctly \
                 (per-package configs not yet fully supported).",
                shown.join(", "),
                ellipsis,
            )
        } else {
            format!(
                "Function found via AST but has no call edges across {} workspace roots. \
                 It may be an entry point or truly isolated.",
                workspace_paths.len(),
            )
        }
    } else if is_exported {
        format!(
            "Function is exported but no callers found within the analyzed root '{}'. \
             In monorepo workflows, ensure you run tldr from the directory that contains all callers.",
            project_root.display(),
        )
    } else {
        "Function found via AST but has no call edges in analyzed scope.".to_string()
    }
}

/// Best-effort check for whether `target_func` is declared with export /
/// public visibility in `file`. We look for the declaration site rather
/// than the call site. This is intentionally textual (not AST-based) to
/// keep the cost bounded on the fallback path — the AST has already been
/// consulted to confirm the function exists at all.
///
/// Returns `true` only when evidence is positive; defaults to `false` on
/// read errors or unrecognized languages, which preserves the conservative
/// "unknown visibility" note.
fn function_is_exported(file: &Path, target_func: &str, language: Language) -> bool {
    let source = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Strip a leading `Class.` prefix from method names so we look for the
    // bare identifier in source.
    let name = match target_func.rsplit_once('.') {
        Some((_, tail)) => tail,
        None => target_func,
    };

    // Build language-appropriate export/public markers.
    let patterns: &[&str] = match language {
        Language::TypeScript | Language::JavaScript => &[
            "export function",
            "export async function",
            "export default function",
            "export default async function",
            "export const",
            "export let",
            "export var",
            "export class",
        ],
        Language::Python => &["def "], // Python: any top-level def is importable
        Language::Rust => &["pub fn", "pub async fn", "pub(crate) fn", "pub(super) fn"],
        Language::Go => &[], // Go: case-based, handled below
        Language::Java | Language::CSharp | Language::Kotlin | Language::Scala => &["public "],
        _ => &[],
    };

    // Go: exported iff the first letter is uppercase.
    if language == Language::Go {
        if let Some(ch) = name.chars().next() {
            return ch.is_ascii_uppercase();
        }
        return false;
    }

    for line in source.lines() {
        let trimmed = line.trim_start();
        for marker in patterns {
            if trimmed.starts_with(marker)
                && line.contains(name)
                && looks_like_declaration_of(line, name)
            {
                return true;
            }
        }
    }
    false
}

/// Cheap sanity check that `line` plausibly declares `name` (rather than
/// just mentioning it in a string literal). We require `name` to appear
/// followed by `(`, `=`, `:`, `<`, or whitespace.
fn looks_like_declaration_of(line: &str, name: &str) -> bool {
    let mut haystack = line;
    while let Some(pos) = haystack.find(name) {
        let after = &haystack[pos + name.len()..];
        let before_ok = pos == 0
            || haystack
                .as_bytes()
                .get(pos - 1)
                .map(|b| !b.is_ascii_alphanumeric() && *b != b'_')
                .unwrap_or(true);
        let after_ok = after
            .chars()
            .next()
            .map(|c| matches!(c, '(' | '=' | ':' | '<' | ' ' | '\t' | '\n'))
            .unwrap_or(true);
        if before_ok && after_ok {
            return true;
        }
        haystack = &haystack[pos + name.len()..];
    }
    false
}

/// Key for the reverse graph: (file, function)
type FunctionKey = (std::path::PathBuf, String);

struct ReverseGraph {
    callers: HashMap<FunctionKey, Vec<FunctionKey>>,
    approximate_callers: HashMap<FunctionKey, Vec<ApproximateCaller>>,
}

/// Build reverse graph: (dst_file, dst_func) -> [(src_file, src_func)]
fn build_reverse_graph(call_graph: &ProjectCallGraph, include_approximate: bool) -> ReverseGraph {
    let mut reverse: HashMap<FunctionKey, Vec<FunctionKey>> = HashMap::new();
    let mut approximate: HashMap<FunctionKey, Vec<ApproximateCaller>> = HashMap::new();

    for edge in call_graph.edges() {
        let dst_key = (edge.dst_file.clone(), edge.dst_func.clone());
        let src_key = (edge.src_file.clone(), edge.src_func.clone());

        let is_t2 = call_graph
            .edge_rung(edge)
            .map(|rung| confidence_tier(rung) == ConfidenceTier::T2)
            .unwrap_or(false);
        if is_t2 {
            if let Some(rung) = call_graph.edge_rung(edge) {
                approximate
                    .entry(dst_key.clone())
                    .or_default()
                    .push(ApproximateCaller {
                        function: edge.src_func.clone(),
                        file: edge.src_file.clone(),
                        confidence: ConfidenceTier::T2.as_str().to_string(),
                        rung: rung.id().to_string(),
                        mechanism: rung.mechanism().to_string(),
                    });
            }
            if include_approximate {
                reverse.entry(dst_key).or_default().push(src_key);
            }
        } else {
            reverse.entry(dst_key).or_default().push(src_key);
        }
    }

    // CL-1 / GH #74: the BFS in `build_caller_tree` iterates each callee's
    // adjacency list IN ORDER and emits one `CallerTree` child per caller,
    // so the order of these Vecs is the order of the serialized `callers[]`
    // array. `call_graph.edges()` does not promise a stable iteration order
    // (edges are accumulated across a parallel/HashMap-backed build), so
    // without this sort the caller tree was shuffled run-to-run. Sort every
    // adjacency list on the caller identity tuple — (file path, function
    // name) — which is the same stable key the rest of the impact path
    // uses. Dedup adjacent equal keys so a caller that invokes the target
    // from multiple sites at the same (file, func) doesn't appear twice
    // (its multiplicity is not modelled by the tree).
    for callers in reverse.values_mut() {
        callers.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        callers.dedup();
    }
    for callers in approximate.values_mut() {
        callers.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.function.cmp(&b.function))
                .then_with(|| a.rung.cmp(&b.rung))
        });
        callers.dedup();
    }

    ReverseGraph {
        callers: reverse,
        approximate_callers: approximate,
    }
}

/// Build caller tree via BFS traversal
fn build_caller_tree(
    file: &Path,
    func: &str,
    reverse_graph: &ReverseGraph,
    max_depth: usize,
) -> CallerTree {
    let key = (file.to_path_buf(), func.to_string());

    // Get direct callers
    let callers = reverse_graph.callers.get(&key);
    let caller_count = callers.map(|c| c.len()).unwrap_or(0);
    let approximate_callers = reverse_graph
        .approximate_callers
        .get(&key)
        .cloned()
        .unwrap_or_default();

    // Handle entry point (no callers)
    if caller_count == 0 {
        return CallerTree {
            function: func.to_string(),
            file: file.to_path_buf(),
            caller_count: 0,
            callers: vec![],
            approximate_callers,
            truncated: false,
            note: Some("Entry point - no callers found".to_string()),
            confidence: None,
            receiver_type: None,
        };
    }

    // BFS traversal with depth tracking
    let mut visited: HashSet<FunctionKey> = HashSet::new();
    visited.insert(key.clone());

    let mut child_trees = Vec::new();

    if max_depth > 0 {
        if let Some(callers) = callers {
            for (caller_file, caller_func) in callers {
                let caller_key = (caller_file.clone(), caller_func.clone());

                // Cycle detection
                if visited.contains(&caller_key) {
                    child_trees.push(CallerTree {
                        function: caller_func.clone(),
                        file: caller_file.clone(),
                        caller_count: 0,
                        callers: vec![],
                        approximate_callers: vec![],
                        truncated: true,
                        note: Some("Cycle detected".to_string()),
                        confidence: None,
                        receiver_type: None,
                    });
                    continue;
                }

                visited.insert(caller_key);

                // Recursively build subtree with reduced depth
                let subtree =
                    build_caller_tree(caller_file, caller_func, reverse_graph, max_depth - 1);
                child_trees.push(subtree);
            }
        }
    }

    CallerTree {
        function: func.to_string(),
        file: file.to_path_buf(),
        caller_count,
        callers: child_trees,
        approximate_callers,
        truncated: max_depth == 0 && caller_count > 0,
        note: if max_depth == 0 && caller_count > 0 {
            Some(format!(
                "Truncated at depth limit ({} callers)",
                caller_count
            ))
        } else {
            None
        },
        confidence: None,
        receiver_type: None,
    }
}

/// Find similar function names for error suggestions
fn find_similar_functions(call_graph: &ProjectCallGraph, target: &str) -> Vec<String> {
    let mut all_functions: HashSet<String> = HashSet::new();

    for edge in call_graph.edges() {
        all_functions.insert(edge.src_func.clone());
        all_functions.insert(edge.dst_func.clone());
    }

    // Find functions with similar names (simple substring/prefix matching)
    let target_lower = target.to_lowercase();
    let mut suggestions: Vec<String> = all_functions
        .into_iter()
        .filter(|f| {
            let f_lower = f.to_lowercase();
            f_lower.contains(&target_lower)
                || target_lower.contains(&f_lower)
                || levenshtein_distance(&f_lower, &target_lower) <= 3
        })
        .take(5)
        .collect();

    suggestions.sort();
    suggestions
}

/// Simple Levenshtein distance for fuzzy matching
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix: Vec<Vec<usize>> = vec![vec![0; len2 + 1]; len1 + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate().take(len2 + 1) {
        *val = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(matrix[i][j + 1] + 1, matrix[i + 1][j] + 1),
                matrix[i][j] + cost,
            );
        }
    }

    matrix[len1][len2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CallEdge;

    fn create_test_graph() -> ProjectCallGraph {
        let mut graph = ProjectCallGraph::new();

        // A calls B, B calls C
        graph.add_edge(CallEdge {
            src_file: "a.py".into(),
            src_func: "func_a".to_string(),
            dst_file: "b.py".into(),
            dst_func: "func_b".to_string(),
            call_line: None,
        });
        graph.add_edge(CallEdge {
            src_file: "b.py".into(),
            src_func: "func_b".to_string(),
            dst_file: "c.py".into(),
            dst_func: "func_c".to_string(),
            call_line: None,
        });
        // D also calls C
        graph.add_edge(CallEdge {
            src_file: "d.py".into(),
            src_func: "func_d".to_string(),
            dst_file: "c.py".into(),
            dst_func: "func_c".to_string(),
            call_line: None,
        });

        graph
    }

    // -------------------------------------------------------------------------
    // FEATURE-1 d.6 (Fix A): last_segment must cut at the Lua/luau single-colon
    // method separator so a bare `method` query matches an `X:method` definition.
    // -------------------------------------------------------------------------

    /// FAIL-FIRST: the luau/lua colon-method separator is a single ':' that is
    /// NOT part of a '::'. Before the fix `last_segment` cut only on '.' and
    /// '::', so `Component:setState` returned the whole string.
    #[test]
    fn test_d6_last_segment_cuts_luau_colon_method() {
        assert_eq!(last_segment("Component:setState"), "setState");
        assert_eq!(last_segment("obj:method"), "method");
        // A dotted qualifier followed by a colon method (lua `Mod.Class:m`) cuts
        // at the DEEPEST separator (the colon).
        assert_eq!(last_segment("Mod.Class:render"), "render");
    }

    /// The existing '.'/'::'/'->' behaviors must be UNAFFECTED by the colon fix.
    #[test]
    fn test_d6_last_segment_coloncolon_and_dot_unaffected() {
        // C++/Rust '::' still resolves via the coloncolon index.
        assert_eq!(last_segment("A::b"), "b");
        assert_eq!(last_segment("mod::Type::method"), "method");
        // '.' member access unchanged.
        assert_eq!(last_segment("Class.method"), "method");
        // '->' was never a last_segment separator; still returns whole string.
        assert_eq!(last_segment("a->b"), "a->b");
        // No separator -> whole string.
        assert_eq!(last_segment("plain"), "plain");
    }

    /// FAIL-FIRST: the `find_function_in_ast` seed. A bare `setState` query must
    /// match the AST-extracted luau candidate `Component:setState` (Direction 1
    /// of `names_match`). Before the fix `last_segment("Component:setState")`
    /// returned the whole string, so the match was false and the Component.lua
    /// target was never seeded (`has_target` stuck at 0).
    #[test]
    fn test_d6_names_match_bare_query_finds_luau_colon_method() {
        assert!(names_match("Component:setState", "setState"));
        // C++ '::' candidate still matches a bare query (Direction 1 unchanged).
        assert!(names_match("Glob::parse", "parse"));
        // Does not over-match an unrelated method on the same table.
        assert!(!names_match("Component:setState", "render"));
    }

    /// W1-4: a `::`-qualified query must match a dot-canonicalized call-graph
    /// endpoint (`Parser.parse`) while still rejecting a different qualifier
    /// (`Other.parse`).
    #[test]
    fn test_w1_4_colon_query_matches_dot_canonicalized_endpoint() {
        let mut graph = ProjectCallGraph::new();

        // Parser.parse has three callers.
        for caller in ["caller_a", "caller_b", "caller_c"] {
            graph.add_edge(CallEdge {
                src_file: "src.rs".into(),
                src_func: caller.to_string(),
                dst_file: "parser.rs".into(),
                dst_func: "Parser.parse".to_string(),
                call_line: None,
            });
        }

        // impact Parser::parse must find the three Parser.parse callers.
        let result = impact_analysis(&graph, "Parser::parse", 1, None)
            .expect("Parser::parse should resolve to Parser.parse");
        assert_eq!(result.total_targets, 1, "Expected exactly one target");
        let tree = result.targets.values().next().unwrap();
        assert_eq!(
            tree.caller_count, 3,
            "Parser::parse should match Parser.parse and return 3 callers"
        );

        // Qualifier guard: a different qualifier must not match Parser.parse.
        assert!(
            !names_match("Parser.parse", "Other::parse"),
            "Other::parse should not match Parser.parse"
        );

        // impact Other::parse must NOT resolve to Parser.parse.
        assert!(
            impact_analysis(&graph, "Other::parse", 1, None).is_err(),
            "Other::parse should not resolve when only Parser.parse is in the graph"
        );
    }

    #[test]
    fn test_impact_finds_direct_callers() {
        let graph = create_test_graph();
        let result = impact_analysis(&graph, "func_c", 1, None).unwrap();

        assert_eq!(result.total_targets, 1);
        let tree = result.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 2); // func_b and func_d
    }

    #[test]
    fn test_impact_respects_depth() {
        let graph = create_test_graph();

        // Depth 1 should only show direct callers
        let result = impact_analysis(&graph, "func_c", 1, None).unwrap();
        let tree = result.targets.values().next().unwrap();

        // At depth 1, callers of func_c (func_b, func_d) are shown
        // but their callers should be truncated
        assert_eq!(tree.callers.len(), 2);
    }

    #[test]
    fn test_impact_handles_not_found() {
        let graph = create_test_graph();
        let result = impact_analysis(&graph, "nonexistent", 3, None);

        assert!(result.is_err());
        if let Err(TldrError::FunctionNotFound { name, .. }) = result {
            assert_eq!(name, "nonexistent");
        } else {
            panic!("Expected FunctionNotFound error");
        }
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
    }

    // =========================================================================
    // AST fallback tests
    // =========================================================================

    #[test]
    fn test_impact_ast_fallback_finds_isolated_function() {
        // Function exists in AST but has no call edges
        let graph = ProjectCallGraph::new(); // empty graph
        let dir = std::env::temp_dir().join("tldr_impact_test_isolated");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("isolated.go"),
            "package main\n\nfunc CreateIssue() {\n\tprintln(\"hello\")\n}\n",
        )
        .unwrap();

        let result = impact_analysis_with_ast_fallback(
            &graph,
            "CreateIssue",
            5,
            None,
            &dir,
            crate::Language::Go,
        );

        assert!(
            result.is_ok(),
            "Should succeed via AST fallback, got: {:?}",
            result
        );
        let report = result.unwrap();
        assert_eq!(report.total_targets, 1);
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.function, "CreateIssue");
        assert_eq!(tree.caller_count, 0);
        // VAL-007: the fallback note now adapts based on workspace + export
        // visibility. CreateIssue is exported (Go: uppercase first letter)
        // and the tempdir is not a workspace root, so we expect the
        // "single-root + exported" variant which mentions workspace guidance.
        let note = tree.note.as_ref().unwrap();
        assert!(
            note.contains("no callers") || note.contains("no call edges"),
            "Note should mention missing callers, got: {:?}",
            note
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_impact_ast_fallback_returns_correct_file() {
        // Function exists in a specific file; verify the file path is set
        let graph = ProjectCallGraph::new();
        let dir = std::env::temp_dir().join("tldr_impact_test_file");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("handler.py"), "def create_handler():\n    pass\n").unwrap();

        let result = impact_analysis_with_ast_fallback(
            &graph,
            "create_handler",
            5,
            None,
            &dir,
            crate::Language::Python,
        );

        assert!(result.is_ok());
        let report = result.unwrap();
        let tree = report.targets.values().next().unwrap();
        // File path should reference handler.py
        let file_str = tree.file.to_string_lossy();
        assert!(
            file_str.contains("handler.py"),
            "Expected file path to contain handler.py, got: {}",
            file_str
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_impact_ast_fallback_not_triggered_when_graph_has_function() {
        // If function is in the call graph, don't fall back to AST
        let graph = create_test_graph();

        let dir = std::env::temp_dir().join("tldr_impact_test_no_fallback");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("c.py"), "def func_c():\n    pass\n").unwrap();

        let result = impact_analysis_with_ast_fallback(
            &graph,
            "func_c",
            3,
            None,
            &dir,
            crate::Language::Python,
        );

        assert!(result.is_ok());
        let report = result.unwrap();
        let tree = report.targets.values().next().unwrap();
        // Should have actual callers (func_b and func_d), not a zero-caller fallback
        assert_eq!(tree.caller_count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_impact_ast_fallback_still_errors_when_truly_not_found() {
        // Function doesn't exist in graph OR AST - should still error
        let graph = ProjectCallGraph::new();
        let dir = std::env::temp_dir().join("tldr_impact_test_truly_missing");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("other.py"), "def something_else():\n    pass\n").unwrap();

        let result = impact_analysis_with_ast_fallback(
            &graph,
            "nonexistent_function",
            5,
            None,
            &dir,
            crate::Language::Python,
        );

        assert!(result.is_err());
        if let Err(TldrError::FunctionNotFound { name, .. }) = result {
            assert_eq!(name, "nonexistent_function");
        } else {
            panic!("Expected FunctionNotFound error");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_impact_ast_fallback_finds_method() {
        // Method inside a class should also be found via AST fallback
        let graph = ProjectCallGraph::new();
        let dir = std::env::temp_dir().join("tldr_impact_test_method");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("service.py"),
            "class MyService:\n    def handle_request(self):\n        pass\n",
        )
        .unwrap();

        let result = impact_analysis_with_ast_fallback(
            &graph,
            "handle_request",
            5,
            None,
            &dir,
            crate::Language::Python,
        );

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.total_targets, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // =====================================================================
    // explain-r8-bare-name-resolution-inherited (v0.5.0 CLOSEOUT)
    // Sub-fix A (OCaml module-qualifier homonym) + Sub-fix B (shadowing
    // local-binding) characterization tests for `extract_call_receiver`.
    // =====================================================================

    /// Locate the 1-indexed (line, column) of the `name` token that appears
    /// inside the unique substring `anchor` within `src`.
    fn r8_locate(src: &str, anchor: &str, name: &str) -> (usize, usize) {
        let aidx = src.find(anchor).expect("anchor present in source");
        let rel = anchor.find(name).expect("name present in anchor");
        // Point strictly INSIDE the token (second char when possible) so the
        // zero-width descendant lookup cannot land on a token boundary / the
        // enclosing block.
        let inside = if name.len() > 1 { 1 } else { 0 };
        let byte = aidx + rel + inside;
        let mut line = 1usize;
        let mut col = 1usize;
        for (i, ch) in src.char_indices() {
            if i == byte {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    fn r8_receiver(
        slug: &str,
        fname: &str,
        src: &str,
        anchor: &str,
        name: &str,
        lang: crate::Language,
    ) -> CallReceiver {
        let dir = std::env::temp_dir().join(format!("tldr_r8_{slug}"));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(fname);
        std::fs::write(&path, src).unwrap();
        let (line, col) = r8_locate(src, anchor, name);
        // FEATURE-1 d.3: these tests assert the raw receiver CLASSIFICATION
        // (Named/Bare/SelfRef/ShadowedLocal), independent of the collision
        // cardinality gate, so the declared-type upgrade is enabled to exercise
        // the full extraction path. `any_resolved = false` + an empty collision
        // set leaves the d.7-1 upgrade guard inert (raw classification unchanged).
        let r = extract_call_receiver(&path, line, col, name, lang, true, false, &HashSet::new());
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn r8_ocaml_module_qualifier_is_named_not_bare() {
        // Sub-fix A: `Mutex.unlock a` -> Named("Mutex") (stdlib homonym rejected
        // downstream), while a genuinely bare `unlock` is still Bare.
        let src = "let unlock m = m\n\nlet run () =\n  Mutex.unlock a;\n  ignore b\n";
        let r = r8_receiver(
            "ocaml_qual",
            "lwt_main.ml",
            src,
            "Mutex.unlock",
            "unlock",
            crate::Language::Ocaml,
        );
        assert_eq!(
            r,
            CallReceiver::Named("Mutex".to_string()),
            "qualified `Mutex.unlock` must recover the module qualifier"
        );
    }

    #[test]
    fn r8_ocaml_nested_module_qualifier_takes_innermost() {
        // `A.B.unlock x` -> Named("B"): the immediately-enclosing module.
        let src = "let run () =\n  A.B.unlock x\n";
        let r = r8_receiver(
            "ocaml_nested",
            "m.ml",
            src,
            "A.B.unlock",
            "unlock",
            crate::Language::Ocaml,
        );
        assert_eq!(r, CallReceiver::Named("B".to_string()));
    }

    #[test]
    fn r8_ocaml_file_own_def_shadows_cross_file_target() {
        // Sub-fix B: lwt_io-style — the file's OWN `let unlock` shadows the
        // cross-file `Lwt_mutex.unlock` target for a later bare `unlock` call.
        let src = "let unlock wrapper = wrapper\n\nlet atomic () =\n  unlock w\n";
        let r = r8_receiver(
            "ocaml_fileown",
            "lwt_io.ml",
            src,
            "  unlock w",
            "unlock",
            crate::Language::Ocaml,
        );
        assert_eq!(
            r,
            CallReceiver::ShadowedLocal,
            "bare `unlock` bound by the file's own `let unlock` is not the target"
        );
    }

    #[test]
    fn r8_ocaml_self_recursion_is_kept_bare() {
        // Recursion guard: `let rec drain q = drain q'` — the bare self-call is
        // a legitimate self-edge, NOT a shadow.
        let src = "let rec drain q =\n  drain q\n";
        let r = r8_receiver(
            "ocaml_rec",
            "q.ml",
            src,
            "  drain q",
            "drain",
            crate::Language::Ocaml,
        );
        assert_eq!(
            r,
            CallReceiver::Bare,
            "self-recursive bare call must stay Bare (kept)"
        );
    }

    #[test]
    fn r8_swift_closure_parameter_shadows_toplevel() {
        // Sub-fix B: `func withState(perform:...) { perform(s) }` — `perform`
        // is the closure parameter, not the top-level `Session.perform`.
        let src = "class Session {\n    func perform() {}\n}\n\nfunc withState(perform: (Int) -> Void) {\n    perform(3)\n}\n";
        let r = r8_receiver(
            "swift_param",
            "Protected.swift",
            src,
            "    perform(3)",
            "perform",
            crate::Language::Swift,
        );
        assert_eq!(r, CallReceiver::ShadowedLocal);
    }

    #[test]
    fn r8_kotlin_lambda_parameter_shadows() {
        // Kotlin `block` closure parameter shadows any top-level `block`.
        let src = "fun process(block: () -> Unit) {\n    block()\n}\n";
        let r = r8_receiver(
            "kotlin_block",
            "P.kt",
            src,
            "    block()",
            "block",
            crate::Language::Kotlin,
        );
        assert_eq!(r, CallReceiver::ShadowedLocal);
    }

    #[test]
    fn r8_scala_local_val_shadows_toplevel() {
        // Scala local `val push` (a function value) shadows a top-level `push`.
        let src = "object Stack {\n  def push(x: Int): Unit = ()\n  def run(): Unit = {\n    val push = (y: Int) => y\n    push(3)\n  }\n}\n";
        let r = r8_receiver(
            "scala_push",
            "S.scala",
            src,
            "    push(3)",
            "push",
            crate::Language::Scala,
        );
        assert_eq!(r, CallReceiver::ShadowedLocal);
    }

    #[test]
    fn r8_swift_position_filter_keeps_forward_local() {
        // Position filter: a bare call BEFORE a same-named local `let` must NOT
        // be classified as shadowed (mirrors SwiftLexicalLookup `d`-before-`let d`).
        let src = "func handler() {}\n\nfunc run() {\n    handler()\n    let handler = 3\n}\n";
        let r = r8_receiver(
            "swift_posfilter",
            "F.swift",
            src,
            "    handler()",
            "handler",
            crate::Language::Swift,
        );
        assert_eq!(
            r,
            CallReceiver::Bare,
            "a call textually before its same-named local is not shadowed"
        );
    }

    // =========================================================================
    // fix-PW1-B7a-elixir-refcount (v0.5.0 BACKLOG): impact/explain over-counted
    // elixir callers by crediting (a) `@spec`/`@type`/`@callback` typespec
    // identifier occurrences as if they were calls, and (b) synthetic
    // `<Module.Name>` module-atom pseudo-callers minted by the elixir call
    // graph for module-level / typespec-carrier scopes.
    //
    // This generalization test drives the REAL caller-resolution path used by
    // `impact` and `explain` — build_project_call_graph + impact_analysis +
    // enrich_impact_with_references + find_references — and asserts the resolved
    // elixir caller set EXCLUDES BOTH symptom variants while RETAINING the
    // genuine named caller.
    // =========================================================================
    #[test]
    fn b7a_elixir_typespec_and_module_atom_excluded_from_callers() {
        use crate::analysis::references::{find_references, ReferenceKind, ReferencesOptions};
        use crate::callgraph::builder::build_project_call_graph;
        use crate::Language;

        let root = std::env::temp_dir().join("tldr_b7a_elixir_refcount");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();

        // server.ex: `handle/1` carries a `@spec handle(...)` typespec on the
        // line above its `def`. The def-name occurrence inside the typespec is
        // a TYPE annotation, NOT a call. The module-level @spec also causes the
        // call graph to mint a `<MyApp.Server>` module-atom self-edge.
        let server = "defmodule MyApp.Server do\n  \
            @spec handle(integer) :: integer\n  \
            def handle(x) do\n    \
            x + 1\n  \
            end\nend\n";
        std::fs::write(root.join("lib/server.ex"), server).unwrap();

        // client.ex: a GENUINE caller — `run/1` calls `handle(x)`.
        let client = "defmodule MyApp.Client do\n  \
            def run(x) do\n    \
            handle(x)\n  \
            end\nend\n";
        std::fs::write(root.join("lib/client.ex"), client).unwrap();

        // ---- Variant 1 (typespec): find_references must NOT classify the
        // `handle` identifier inside `@spec handle(...)` as a Call. ----
        let mut opts = ReferencesOptions::new();
        opts.kinds = Some(vec![ReferenceKind::Call]);
        opts.language = Some("elixir".to_string());
        let refs = find_references("handle", &root, &opts).unwrap();
        let server_path_tail = std::path::Path::new("lib/server.ex");
        let spec_ref = refs
            .references
            .iter()
            .find(|r| r.file.ends_with(server_path_tail) && r.line == 2);
        assert!(
            spec_ref.is_none(),
            "@spec typespec line (server.ex:2) must NOT be a Call reference; got: {:?}",
            refs.references
        );
        // The genuine call in client.ex (line 3) must still be a Call ref.
        assert!(
            refs.references
                .iter()
                .any(|r| r.file.ends_with(std::path::Path::new("lib/client.ex"))),
            "genuine call in client.ex must remain a Call reference; got: {:?}",
            refs.references
        );

        // ---- Drive the full impact caller-resolution path. ----
        let graph = build_project_call_graph(&root, Language::Elixir, None, true).unwrap();
        let mut report =
            impact_analysis_with_ast_fallback(&graph, "handle", 3, None, &root, Language::Elixir)
                .expect("impact analysis should succeed");
        enrich_impact_with_references(&mut report, &root, "handle", Language::Elixir);

        // Flatten the resolved caller list across all targets.
        let callers: Vec<(String, String)> = report
            .targets
            .values()
            .flat_map(|t| {
                t.callers
                    .iter()
                    .map(|c| (c.function.clone(), c.file.display().to_string()))
            })
            .collect();

        // Variant 2 (module-atom): NO `<Module.Name>` synthetic pseudo-caller.
        let module_atom = callers.iter().find(|(name, _)| {
            name.strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .and_then(|inner| inner.chars().next())
                .is_some_and(|c| c.is_uppercase())
        });
        assert!(
            module_atom.is_none(),
            "no synthetic <Module.Name> module-atom pseudo-caller may appear; got callers: {:?}",
            callers
        );

        // Variant 1 (typespec): NO caller attributed to the @spec line in
        // server.ex (the def file). `handle`'s only non-def occurrence there is
        // the typespec, so any server.ex caller is the bogus typespec credit.
        let typespec_caller = callers
            .iter()
            .find(|(_, file)| std::path::Path::new(file).ends_with(server_path_tail));
        assert!(
            typespec_caller.is_none(),
            "the @spec typespec occurrence must NOT be credited as a caller; got callers: {:?}",
            callers
        );

        // Retention: the genuine `run` caller survives.
        assert!(
            callers
                .iter()
                .any(|(name, _)| name == "run" || name.ends_with(".run")),
            "genuine named caller `run` must be retained; got callers: {:?}",
            callers
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // =====================================================================
    // fix-PW2-B5-impact-alias (v0.5.0 BACKLOG): a method name defined on N
    // types across N files makes the FuncIndex DECLINE cross-file resolution
    // (genuine multi-file collision), so the call graph emits no resolved
    // edges and the AST-fallback rows are blanked. Before the fix
    // `impact <method>` on such a collision returned caller_count == 0 for
    // EVERY definition even though references show real `recv.method(...)`
    // call sites. The fix (a) keys each collision-suppressed definition row
    // `Type.method` and (b) keeps a lowercase instance-variable receiver as a
    // caller when the collision is genuinely unresolvable — WITHOUT spraying
    // a resolved edge onto sibling targets (preserves the f69904c python
    // class-collision and the CL-2 receiver discrimination).
    //
    // Symptom class: swift (ocaml / php inherit the same fallback + enrich
    // path). These generalization tests drive the REAL resolution path —
    // build_project_call_graph + impact_analysis_with_ast_fallback +
    // enrich_impact_with_references.
    // =====================================================================

    /// Build a graph, run impact + reference enrichment, and return the
    /// per-target `(function, caller_count, [caller_function])` triples.
    fn b5_resolve(
        root: &Path,
        func: &str,
        language: crate::Language,
    ) -> Vec<(String, usize, Vec<String>)> {
        use crate::callgraph::builder::build_project_call_graph;
        let graph = build_project_call_graph(root, language, None, true).unwrap();
        let mut report = impact_analysis_with_ast_fallback(&graph, func, 3, None, root, language)
            .expect("impact analysis should succeed");
        enrich_impact_with_references(&mut report, root, func, language);
        report
            .targets
            .values()
            .map(|t| {
                (
                    t.function.clone(),
                    t.caller_count,
                    t.callers.iter().map(|c| c.function.clone()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn w2_14_cpp_nested_caller_tree_is_reference_enriched_with_local_gates() {
        let root = std::env::temp_dir().join("tldr_w2_14_cpp_nested_enrich");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("app.cpp");
        std::fs::write(
            &file,
            "class A {\npublic:\n    void leaf() {}\n};\n\n\
             class B {\npublic:\n    void leaf() {}\n};\n\n\
             class Worker {\npublic:\n    void step() {\n        A a;\n        a.leaf();\n    }\n};\n\n\
             void entry(DynamicWorker w) {\n    w.step();\n}\n",
        )
        .unwrap();

        let mut targets = BTreeMap::new();
        targets.insert(
            format!("{}:A.leaf", file.display()),
            CallerTree {
                function: "A.leaf".to_string(),
                file: file.clone(),
                caller_count: 1,
                callers: vec![CallerTree {
                    function: "Worker.step".to_string(),
                    file: file.clone(),
                    caller_count: 0,
                    callers: vec![],
                    approximate_callers: vec![],
                    truncated: false,
                    note: Some("Entry point - no callers found".to_string()),
                    confidence: None,
                    receiver_type: None,
                }],
                approximate_callers: vec![],
                truncated: false,
                note: None,
                confidence: None,
                receiver_type: None,
            },
        );
        targets.insert(
            format!("{}:B.leaf", file.display()),
            CallerTree {
                function: "B.leaf".to_string(),
                file: file.clone(),
                caller_count: 0,
                callers: vec![],
                approximate_callers: vec![],
                truncated: false,
                note: Some("Entry point - no callers found".to_string()),
                confidence: None,
                receiver_type: None,
            },
        );
        let mut report = ImpactReport {
            targets,
            total_targets: 2,
            type_resolution: None,
        };

        enrich_impact_with_references(&mut report, &root, "leaf", crate::Language::Cpp);

        fn find_node<'a>(tree: &'a CallerTree, name: &str) -> Option<&'a CallerTree> {
            if tree.function == name {
                return Some(tree);
            }
            tree.callers
                .iter()
                .find_map(|caller| find_node(caller, name))
        }

        let worker = report
            .targets
            .values()
            .find_map(|tree| find_node(tree, "Worker.step"))
            .expect("nested Worker.step caller should remain present");
        assert!(
            worker.callers.iter().any(|caller| caller.function == "entry"),
            "nested Worker.step should be enriched with its statically provable entry caller; report: {:?}",
            report
        );
        let note = worker.note.as_deref().unwrap_or_default();
        assert!(
            !note.contains("Entry point") && !note.contains("no callers"),
            "nested Worker.step must not keep an entry-point/no-callers note after enrichment; node: {:?}",
            worker
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn b5_swift_method_collision_ok_branch_not_all_blanked() {
        // `filter` defined on two structs in two files; each calls a helper so
        // it surfaces as a call-graph src (the Ok-augmentation branch, the
        // line range the slice targets). Callers use INSTANCE variables
        // (`ot`, `bt`) whose names do not equal the type qualifier.
        let root = std::env::temp_dir().join("tldr_b5_swift_ok");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Sources")).unwrap();
        std::fs::write(
            root.join("Sources/Ordered.swift"),
            "public struct OrderedThing {\n    var items: [Int]\n    public func filter(_ p: (Int) -> Bool) -> OrderedThing {\n        let _ = keepIt(items)\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Bitty.swift"),
            "public struct BitThing {\n    var bits: [Int]\n    public func filter(_ p: (Int) -> Bool) -> BitThing {\n        let _ = keepIt(bits)\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Helper.swift"),
            "func keepIt(_ xs: [Int]) -> [Int] { return xs }\nfunc isPositive(_ x: Int) -> Bool { return x > 0 }\n",
        )
        .unwrap();
        // Paren calls (`recv.filter(pred)`) so references classifies them as
        // `Call` (the real-corpus shape `_bits.filter(isIncluded)`).
        std::fs::write(
            root.join("Sources/Use.swift"),
            "func useThem(_ ot: OrderedThing, _ bt: BitThing) {\n    let _ = ot.filter(isPositive)\n    let _ = bt.filter(isPositive)\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "filter", crate::Language::Swift);
        let total_callers: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert!(
            total_callers > 0,
            "B5: swift method-name-on-type collision blanked ALL callers; targets: {:?}",
            targets
        );
        // The genuine cross-file caller `useThem` must be attributed to at
        // least one definition.
        let has_use = targets
            .iter()
            .any(|(_, _, callers)| callers.iter().any(|c| c.contains("useThem")));
        assert!(
            has_use,
            "B5: expected `useThem` to be surfaced as a caller; targets: {:?}",
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn b5_swift_method_collision_err_branch_qualified_not_blanked() {
        // `filter` defined on two structs that call nothing -> impact_analysis
        // returns FunctionNotFound and the AST-fallback (Err) branch builds
        // the targets. Before the fix these rows carried the BARE name
        // `filter` (qualifier lost), so enrichment blanked every caller. The
        // fix qualifies them `Type.filter` and keeps the instance-receiver
        // callers.
        let root = std::env::temp_dir().join("tldr_b5_swift_err");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Sources")).unwrap();
        std::fs::write(
            root.join("Sources/Ordered.swift"),
            "public struct OrderedThing {\n    var items: [Int]\n    public func filter(_ p: (Int) -> Bool) -> OrderedThing {\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Bitty.swift"),
            "public struct BitThing {\n    var bits: [Int]\n    public func filter(_ p: (Int) -> Bool) -> BitThing {\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Helper.swift"),
            "func isPositive(_ x: Int) -> Bool { return x > 0 }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Use.swift"),
            "func useThem(_ ot: OrderedThing, _ bt: BitThing) {\n    let _ = ot.filter(isPositive)\n    let _ = bt.filter(isPositive)\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "filter", crate::Language::Swift);
        // Per-definition keying: every fallback row carries its TYPE qualifier.
        assert!(
            targets
                .iter()
                .all(|(f, _, _)| f.contains('.') && f.ends_with(".filter")),
            "B5: AST-fallback method rows must be keyed `Type.filter`; targets: {:?}",
            targets
        );
        let total_callers: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert!(
            total_callers > 0,
            "B5: swift Err-branch collision blanked ALL callers; targets: {:?}",
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn b5_python_class_collision_preserves_caller_count_one() {
        // f69904c REGRESSION GUARD: two same-named `Service` classes in two
        // files; `Runner.go` constructs `Service()` in a.py and calls
        // `s.handle()`. After VAL-032b, that receiver_type evidence is T2:
        // default impact must NOT report it as a definitive caller, and must
        // not spray it onto the b.py:Service.handle sibling. The genuine
        // a.py target keeps the evidence in approximate_callers.
        let root = std::env::temp_dir().join("tldr_b5_py_classcollision");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("a.py"),
            "class Service:\n    def handle(self):\n        return 1\n\n\nclass Runner:\n    def go(self):\n        s = Service()\n        return s.handle()\n",
        )
        .unwrap();
        std::fs::write(
            root.join("b.py"),
            "class Service:\n    def handle(self):\n        return 2\n",
        )
        .unwrap();

        use crate::callgraph::builder::build_project_call_graph;
        let graph = build_project_call_graph(&root, crate::Language::Python, None, true).unwrap();
        let mut report = impact_analysis_with_ast_fallback(
            &graph,
            "handle",
            3,
            None,
            &root,
            crate::Language::Python,
        )
        .expect("impact analysis should succeed");
        enrich_impact_with_references(&mut report, &root, "handle", crate::Language::Python);
        exclude_approximate_callers_from_report(&mut report);

        let targets: Vec<(String, usize, Vec<String>, Vec<String>, PathBuf)> = report
            .targets
            .values()
            .map(|t| {
                (
                    t.function.clone(),
                    t.caller_count,
                    t.callers.iter().map(|c| c.function.clone()).collect(),
                    t.approximate_callers
                        .iter()
                        .map(|c| format!("{}:{}", c.function, c.rung))
                        .collect(),
                    t.file.clone(),
                )
            })
            .collect();
        assert!(
            targets
                .iter()
                .all(|(_, cc, callers, _, _)| *cc == 0 && callers.is_empty()),
            "B5: python class-collision must not report T2 callers as definitive; targets: {:?}",
            targets
        );
        assert!(
            targets.iter().any(|(_, _, _, approximate, file)| {
                file.ends_with("a.py")
                    && approximate
                        .iter()
                        .any(|caller| caller == "Runner.go:receiver_type")
            }),
            "B5: genuine python class-collision target must keep receiver_type evidence approximate; targets: {:?}",
            targets
        );
        assert!(
            targets
                .iter()
                .filter(|(_, _, _, approximate, _)| !approximate.is_empty())
                .all(|(_, _, _, _, file)| file.ends_with("a.py")),
            "B5: approximate receiver_type evidence must not be sprayed onto sibling target; targets: {:?}",
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d7_cpp_selfref_inheritance_not_sprayed_onto_same_named_sibling() {
        // FEATURE-1 d.7-1 CRITIC FIX-1 GUARD: two UNRELATED same-named `Service`
        // classes in two files each define `run()` (a genuine same-named-class
        // collision -> the qualifier `Service` is COLLIDING). File `a.cpp` also has
        // `class Derived : public Service` whose `trigger()` makes a `this->run()`
        // self-call. `Derived` inherits ONE of the two `Service`s, but the SelfRef
        // inheritance relaxation only proves "Derived inherits a class named
        // Service" — it cannot prove WHICH file's Service. So on a COLLIDING
        // qualifier that relaxation must be DISABLED (fall back to exact match),
        // otherwise `Derived::trigger` sprays onto BOTH `Service.run` defs,
        // including the unrelated `b.cpp` sibling. This asserts the self-call is
        // attributed to AT MOST ONE target (never both same-named siblings).
        let root = std::env::temp_dir().join("tldr_d7_cpp_selfref_collision");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("a.cpp"),
            "class Service {\npublic:\n    void run() {}\n};\n\nclass Derived : public Service {\npublic:\n    void trigger() { this->run(); }\n};\n",
        )
        .unwrap();
        std::fs::write(
            root.join("b.cpp"),
            "class Service {\npublic:\n    void run() {}\n};\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "run", crate::Language::Cpp);
        // Two same-named `Service.run` definitions => a genuine ambiguous collision.
        assert!(
            targets.len() >= 2,
            "d7 FIX-1: expected the two colliding Service.run targets; targets: {:?}",
            targets
        );
        // The `this->run()` self-call in Derived must NOT be sprayed onto BOTH
        // same-named Service.run defs. Before the collision gate it lands on both
        // (the unrelated b.cpp sibling included); after the gate it is attributed
        // to at most one.
        let sprayed = targets
            .iter()
            .filter(|(_, _, callers)| callers.iter().any(|c| c.contains("trigger")))
            .count();
        assert!(
            sprayed <= 1,
            "d7 FIX-1: Derived::trigger self-call (this->run()) sprayed onto {} same-named Service.run defs (must be <= 1); targets: {:?}",
            sprayed,
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn b5_ocaml_module_value_collision_callers_retained() {
        // OCaml inherits the same fallback/enrich path. `parse` defined in two
        // modules; main.ml calls `A.parse` and `B.parse` (module-qualified
        // receivers). The fix must keep these callers (module qualifier ==
        // receiver) and must NOT regress them to blank.
        let root = std::env::temp_dir().join("tldr_b5_ocaml_collision");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.ml"), "let parse x = x + 1\n").unwrap();
        std::fs::write(root.join("b.ml"), "let parse x = x + 2\n").unwrap();
        std::fs::write(
            root.join("main.ml"),
            "let run () =\n  let _ = A.parse 1 in\n  let _ = B.parse 2 in\n  ()\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "parse", crate::Language::Ocaml);
        let total_callers: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert!(
            total_callers > 0,
            "B5: ocaml module-value collision blanked ALL callers; targets: {:?}",
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn b5_php_method_collision_callers_retained() {
        // PHP inherits the same path. `format` defined on three classes;
        // app.php constructs `new Alpha()` / `new Beta()` and calls
        // `->format()`. The fix must retain the resolved callers and must not
        // blank them.
        let root = std::env::temp_dir().join("tldr_b5_php_collision");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("a.php"),
            "<?php\nclass Alpha {\n    public function format($x) { return $x; }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("b.php"),
            "<?php\nclass Beta {\n    public function format($x) { return $x; }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("c.php"),
            "<?php\nclass Gamma {\n    public function format($x) { return $x; }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("app.php"),
            "<?php\nfunction run() {\n    $a = new Alpha();\n    $a->format(1);\n    $b = new Beta();\n    $b->format(2);\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "format", crate::Language::Php);
        let total_callers: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert!(
            total_callers > 0,
            "B5: php method collision blanked ALL callers; targets: {:?}",
            targets
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // =====================================================================
    // FEATURE-1 d.3: retire the impact/references TEXTUAL back-fill spray.
    //
    // On a genuine multi-definer method collision the call graph DECLINES, so
    // impact back-fills callers from a textual `find_references(name, Call)`.
    // The OLD path kept a lowercase instance-variable receiver against EVERY
    // sibling type-qualifier (the `unresolvable_collision_keeps` relaxation),
    // spraying ONE call site onto ALL N definitions (C# `impact Read` -> ~180
    // callers across 19 targets; php `render` cross-attributing Table/TreeHelper;
    // swift `_finalizeKeyingModify` binding to BitArray).
    //
    // d.3 resolves the call-site receiver to its DECLARED TYPE (the same
    // `SourceTypeIndex` machinery the call-graph builder uses) and attributes the
    // caller ONLY to the definition whose owning type matches — the same-named
    // siblings on OTHER types drop out. A CARDINALITY-1 unique target still keeps
    // an untyped caller (never-worse). These generalization tests drive the REAL
    // path (build_project_call_graph + impact_analysis_with_ast_fallback +
    // enrich_impact_with_references) across csharp, php, swift, python, kotlin.
    // =====================================================================

    /// Count how many distinct targets attribute a caller whose function name
    /// contains `caller_frag`. The anti-spray invariant is that a single call
    /// site is attributed to exactly ONE definition, not broadcast to every
    /// same-named sibling.
    fn d3_targets_with_caller(
        targets: &[(String, usize, Vec<String>)],
        caller_frag: &str,
    ) -> usize {
        targets
            .iter()
            .filter(|(_, _, callers)| callers.iter().any(|c| c.contains(caller_frag)))
            .count()
    }

    #[test]
    fn d3_csharp_read_collision_attributes_to_receiver_type_only() {
        // `Read` defined on two C# classes in two files -> genuine collision.
        // `App.Run` calls `ar.Read()` where `ar` is a typed `AlphaReader`.
        // Pre-d.3 the C# member call resolved to `Bare` and the call site was
        // sprayed onto BOTH `Read` definitions; d.3 attributes it to
        // `AlphaReader.Read` ONLY.
        let root = std::env::temp_dir().join("tldr_d3_csharp_read");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("a.cs"),
            "class AlphaReader\n{\n    public int Read()\n    {\n        return 1;\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("b.cs"),
            "class BetaReader\n{\n    public int Read()\n    {\n        return 2;\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("app.cs"),
            "class App\n{\n    public void Run()\n    {\n        AlphaReader ar = new AlphaReader();\n        ar.Read();\n    }\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "Read", crate::Language::CSharp);
        // The call site must be attributed to exactly ONE definition (no spray).
        assert_eq!(
            d3_targets_with_caller(&targets, "Run"),
            1,
            "d3: C# `ar.Read()` sprayed across sibling `Read` definers; targets: {:?}",
            targets
        );
        // And that one definition must be the AlphaReader one (the receiver type),
        // never the BetaReader sibling.
        let beta = targets.iter().find(|(f, _, _)| f.contains("BetaReader"));
        if let Some((_, cc, callers)) = beta {
            assert_eq!(
                *cc, 0,
                "d3: BetaReader.Read must not be credited the AlphaReader call; callers: {:?}",
                callers
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d3_php_render_collision_no_cross_attribution() {
        // php `render` on Table and TreeHelper; `run` calls `$t->render()` with
        // `$t = new Table()`. Pre-d.3 the php member call resolved to `Bare` and
        // cross-attributed the call to TreeHelper; d.3 keeps it on Table only.
        let root = std::env::temp_dir().join("tldr_d3_php_render");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("table.php"),
            "<?php\nclass Table {\n    public function render() { return 1; }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("tree.php"),
            "<?php\nclass TreeHelper {\n    public function render() { return 2; }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("app.php"),
            "<?php\nfunction run() {\n    $t = new Table();\n    $t->render();\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "render", crate::Language::Php);
        assert_eq!(
            d3_targets_with_caller(&targets, "run"),
            1,
            "d3: php `$t->render()` cross-attributed to a sibling class; targets: {:?}",
            targets
        );
        let tree = targets.iter().find(|(f, _, _)| f.contains("TreeHelper"));
        if let Some((_, cc, callers)) = tree {
            assert_eq!(
                *cc, 0,
                "d3: TreeHelper.render must not be credited the Table call; callers: {:?}",
                callers
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d3_swift_filter_collision_discriminates_by_receiver_type() {
        // Two structs each define `filter`; TWO distinct callers each use a
        // differently-typed receiver. d.3 must route each caller to its OWN
        // type's definition with NO cross-attribution.
        let root = std::env::temp_dir().join("tldr_d3_swift_filter");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Sources")).unwrap();
        std::fs::write(
            root.join("Sources/Ordered.swift"),
            "public struct OrderedThing {\n    var items: [Int]\n    public func filter(_ p: (Int) -> Bool) -> OrderedThing {\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Bitty.swift"),
            "public struct BitThing {\n    var bits: [Int]\n    public func filter(_ p: (Int) -> Bool) -> BitThing {\n        return self\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Helper.swift"),
            "func isPositive(_ x: Int) -> Bool { return x > 0 }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Sources/Use.swift"),
            "func useAlpha(_ ot: OrderedThing) {\n    let _ = ot.filter(isPositive)\n}\nfunc useBeta(_ bt: BitThing) {\n    let _ = bt.filter(isPositive)\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "filter", crate::Language::Swift);
        let ordered = targets.iter().find(|(f, _, _)| f.contains("OrderedThing"));
        let bitty = targets.iter().find(|(f, _, _)| f.contains("BitThing"));
        // OrderedThing.filter has useAlpha and NOT useBeta.
        if let Some((_, _, callers)) = ordered {
            assert!(
                callers.iter().any(|c| c.contains("useAlpha")),
                "d3: OrderedThing.filter should be called by useAlpha; callers: {:?}",
                callers
            );
            assert!(
                !callers.iter().any(|c| c.contains("useBeta")),
                "d3: OrderedThing.filter cross-attributed the BitThing caller; callers: {:?}",
                callers
            );
        }
        // BitThing.filter has useBeta and NOT useAlpha.
        if let Some((_, _, callers)) = bitty {
            assert!(
                !callers.iter().any(|c| c.contains("useAlpha")),
                "d3: BitThing.filter cross-attributed the OrderedThing caller; callers: {:?}",
                callers
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d3_python_speak_collision_no_spray() {
        // Positive control (Cat/Dog): `speak` on two classes; `run` constructs a
        // `Cat` and calls `c.speak()`. The resolved call must land on Cat.speak
        // only — Dog.speak stays at zero.
        let root = std::env::temp_dir().join("tldr_d3_py_speak");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("animals.py"),
            "class Cat:\n    def speak(self):\n        return \"meow\"\n\n\nclass Dog:\n    def speak(self):\n        return \"woof\"\n\n\ndef run():\n    c = Cat()\n    return c.speak()\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "speak", crate::Language::Python);
        assert_eq!(
            d3_targets_with_caller(&targets, "run"),
            1,
            "d3: python `c.speak()` sprayed onto the Dog sibling; targets: {:?}",
            targets
        );
        let dog = targets.iter().find(|(f, _, _)| f.contains("Dog"));
        if let Some((_, cc, callers)) = dog {
            assert_eq!(
                *cc, 0,
                "d3: Dog.speak must not be credited the Cat call; callers: {:?}",
                callers
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d3_kotlin_method_collision_no_spray() {
        // Kotlin `doIt` on two classes; `run` uses `val a = Alpha()` then
        // `a.doIt()`. d.3 recovers the Kotlin navigation receiver, resolves its
        // type, and attributes the call to Alpha.doIt only.
        let root = std::env::temp_dir().join("tldr_d3_kotlin");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Alpha.kt"),
            "class Alpha {\n    fun doIt(): Int {\n        return 1\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Beta.kt"),
            "class Beta {\n    fun doIt(): Int {\n        return 2\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("App.kt"),
            "fun run() {\n    val a = Alpha()\n    a.doIt()\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "doIt", crate::Language::Kotlin);
        assert_eq!(
            d3_targets_with_caller(&targets, "run"),
            1,
            "d3: kotlin `a.doIt()` sprayed onto the Beta sibling; targets: {:?}",
            targets
        );
        let beta = targets.iter().find(|(f, _, _)| f.contains("Beta"));
        if let Some((_, cc, callers)) = beta {
            assert_eq!(
                *cc, 0,
                "d3: Beta.doIt must not be credited the Alpha call; callers: {:?}",
                callers
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d3_never_worse_unique_target_keeps_untyped_caller() {
        // NEVER-WORSE INVARIANT: a method uniquely defined on ONE class
        // (cardinality 1) must keep its caller even when the receiver type cannot
        // be inferred. `w`'s type is not statically knowable here, yet
        // `Widget.Frobnicate` has exactly one possible owner, so the caller must
        // NOT be dropped.
        let root = std::env::temp_dir().join("tldr_d3_never_worse");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("widget.cs"),
            "class Widget\n{\n    public void Frobnicate()\n    {\n    }\n}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("user.cs"),
            "class User\n{\n    public void Run(dynamic w)\n    {\n        w.Frobnicate();\n    }\n}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "Frobnicate", crate::Language::CSharp);
        let total_callers: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert!(
            total_callers >= 1,
            "d3 never-worse: unique-target caller dropped when receiver type unknown; targets: {:?}",
            targets
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // =====================================================================
    // fix-CF1-S16 (v0.5.0 RC CF-wave): the references-enrichment fallback
    // resolved a nested call site's enclosing function from `extract_file`'s
    // TOP-LEVEL-only function list. For a call nested inside a `local
    // function inner` (Lua/Luau) / `function inner` (TS) that itself lives
    // inside a `local function outer`, the only containing function the
    // coarse list could see was the OUTER one — so `impact` minted a phantom
    // `outer` caller for an edge the call graph had ALREADY resolved to
    // `inner`, double-counting it (3 callers reported where 2 are real).
    //
    // The fix dedups each references caller against the AST innermost NAMED
    // enclosing function of the exact call site
    // (`innermost_named_enclosing_function`): when that inner name matches an
    // already-resolved caller, the coarse outer entry is suppressed. This
    // generalization test drives the REAL resolution path
    // (build_project_call_graph + impact_analysis_with_ast_fallback +
    // enrich_impact_with_references) across Lua, Luau and TypeScript — every
    // language in this slice's `impact`-dedup symptom class.
    // =====================================================================
    #[test]
    fn cf1_s16_impact_dedups_nested_closure_phantom_caller() {
        // `helper` is called ONCE inside a nested named local function
        // `inner` (which lives inside `outer`) and ONCE directly in the
        // sibling `other`. The truth is exactly two callers — {inner, other};
        // `outer` never calls `helper` itself.
        fn check(label: &str, root: &Path, language: crate::Language) {
            let targets = b5_resolve(root, "helper", language);
            let callers: Vec<String> = targets
                .iter()
                .flat_map(|(_, _, cs)| cs.iter())
                .map(|c| {
                    c.rsplit(['.', ':'])
                        .next()
                        .unwrap_or(c.as_str())
                        .to_string()
                })
                .collect();
            // The inner local function is the TRUE caller and must survive.
            assert!(
                callers.iter().any(|c| c == "inner"),
                "[{label}] inner local-function caller missing: {targets:?}"
            );
            // The sibling direct caller must survive.
            assert!(
                callers.iter().any(|c| c == "other"),
                "[{label}] sibling caller `other` missing: {targets:?}"
            );
            // The coarse OUTER-scope phantom must NOT appear: the nested call
            // belongs to `inner`, and the call graph already resolved it.
            assert!(
                !callers.iter().any(|c| c == "outer"),
                "[{label}] phantom OUTER-scope caller `outer` present \
                 (nested-closure double-count not deduped): {targets:?}"
            );
            // Exactly two callers total across all targets.
            let total: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
            assert_eq!(
                total, 2,
                "[{label}] expected exactly 2 callers (inner, other), got {total}: {targets:?}"
            );
        }

        // ---- Lua ----
        let lua_root = std::env::temp_dir().join("tldr_cf1_s16_lua");
        let _ = std::fs::remove_dir_all(&lua_root);
        std::fs::create_dir_all(&lua_root).unwrap();
        std::fs::write(
            lua_root.join("mod.lua"),
            "local function helper(x)\n  return x + 1\nend\n\n\
             local function outer(items)\n  \
             local function inner(it)\n    return helper(it)\n  end\n  \
             local total = 0\n  for _, v in ipairs(items) do\n    \
             total = total + inner(v)\n  end\n  return total\nend\n\n\
             local function other()\n  return helper(5)\nend\n\n\
             return { outer = outer, other = other }\n",
        )
        .unwrap();
        check("lua", &lua_root, crate::Language::Lua);
        let _ = std::fs::remove_dir_all(&lua_root);

        // ---- Luau (typed) ----
        let luau_root = std::env::temp_dir().join("tldr_cf1_s16_luau");
        let _ = std::fs::remove_dir_all(&luau_root);
        std::fs::create_dir_all(&luau_root).unwrap();
        std::fs::write(
            luau_root.join("mod.luau"),
            "local function helper(x: number): number\n  return x + 1\nend\n\n\
             local function outer(items)\n  \
             local function inner(it)\n    return helper(it)\n  end\n  \
             local total = 0\n  for _, v in items do\n    \
             total = total + inner(v)\n  end\n  return total\nend\n\n\
             local function other()\n  return helper(5)\nend\n\n\
             return { outer = outer, other = other }\n",
        )
        .unwrap();
        check("luau", &luau_root, crate::Language::Luau);
        let _ = std::fs::remove_dir_all(&luau_root);

        // ---- TypeScript ----
        let ts_root = std::env::temp_dir().join("tldr_cf1_s16_ts");
        let _ = std::fs::remove_dir_all(&ts_root);
        std::fs::create_dir_all(&ts_root).unwrap();
        std::fs::write(
            ts_root.join("helper.ts"),
            "export function helper(x: number): number {\n  return x + 1;\n}\n",
        )
        .unwrap();
        std::fs::write(
            ts_root.join("use.ts"),
            "import { helper } from './helper';\n\n\
             export function outer(items: number[]): number {\n  \
             function inner(it: number): number {\n    return helper(it);\n  }\n  \
             let total = 0;\n  for (const v of items) {\n    total += inner(v);\n  }\n  \
             return total;\n}\n\n\
             export function other(): number {\n  return helper(5);\n}\n",
        )
        .unwrap();
        check("ts", &ts_root, crate::Language::TypeScript);
        let _ = std::fs::remove_dir_all(&ts_root);
    }

    // =====================================================================
    // fix-CF2-S18r (v0.5.0 RC CF-wave): Wave-1 S18 taught the swift call graph
    // to model a subscript's computed accessors (`get` / `set` / `_modify`) as
    // callable scopes (`<Type>.subscript.<label>`). Wave-1 S16 added the
    // `innermost_named_enclosing_function` dedup, but it only recognised
    // AST-*named* functions — NOT the synthetic accessor scopes — so the
    // references fallback STILL minted a phantom `<module>` caller for a call
    // site the call graph had already resolved to an accessor.
    //
    // The fix generalises the S16 scope walk to recognise swift subscript
    // accessors, so the accessor's leaf label dedups the phantom against the
    // resolved `<Type>.subscript.<label>` edge. This generalization test drives
    // the REAL resolution path (build_project_call_graph +
    // impact_analysis_with_ast_fallback + enrich_impact_with_references) and
    // asserts BOTH the swift accessor phantom is gone AND that the change does
    // not over-suppress a genuinely distinct caller (the ordinary
    // nested-named-closure case already handled by S16 stays intact).
    // =====================================================================
    #[test]
    fn cf2_s18r_impact_dedups_swift_subscript_accessor_phantom() {
        // ---- Swift subscript accessor (the slice's symptom) ----
        // `finalizeWrite` is called from TWO resolved scopes: the subscript
        // `_modify` accessor (modelled by the S18 call graph as
        // `Box.subscript._modify`) and the ordinary method `directWrite`. The
        // call graph resolves both; the references fallback must NOT also mint
        // a phantom `<module>` caller for the accessor call site (which it does
        // because `extract_file` cannot see the accessor scope).
        let root = std::env::temp_dir().join("tldr_cf2_s18r_swift");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Sources")).unwrap();
        std::fs::write(
            root.join("Sources/Box.swift"),
            "public struct Box {\n  \
               var storage: [Int]\n  \
               public subscript(i: Int) -> Int {\n    \
                 _modify {\n      \
                   prepareWrite()\n      \
                   defer {\n        finalizeWrite()\n      }\n      \
                   yield &storage[i]\n    }\n  }\n  \
               func directWrite() {\n    finalizeWrite()\n  }\n}\n\
             func prepareWrite() {}\n\
             func finalizeWrite() {}\n",
        )
        .unwrap();

        let targets = b5_resolve(&root, "finalizeWrite", crate::Language::Swift);
        let callers: Vec<String> = targets
            .iter()
            .flat_map(|(_, _, cs)| cs.iter().cloned())
            .collect();

        // (1) NO phantom `<module>` caller for the accessor call site.
        assert!(
            !callers
                .iter()
                .any(|c| c == "<module>" || c.ends_with(".<module>")),
            "phantom `<module>` caller for the subscript-accessor call site was \
             not deduped against the resolved `subscript._modify` edge: {targets:?}"
        );
        // (2) The resolved subscript `_modify` accessor caller survives.
        assert!(
            callers
                .iter()
                .any(|c| c.contains("subscript") && c.ends_with("_modify")),
            "resolved subscript `_modify` accessor caller missing: {targets:?}"
        );
        // (3) Anti-over-suppression: the genuinely distinct `directWrite` caller
        // (a different scope sharing only the same callee) is NOT dropped.
        assert!(
            callers.iter().any(|c| c.ends_with("directWrite")),
            "genuinely distinct `directWrite` caller over-suppressed: {targets:?}"
        );
        let total: usize = targets.iter().map(|(_, cc, _)| *cc).sum();
        assert_eq!(
            total, 2,
            "expected exactly 2 resolved callers (subscript._modify, \
             directWrite), got {total}: {targets:?}"
        );
        let _ = std::fs::remove_dir_all(&root);

        // ---- Anti-over-suppression: the ordinary nested-named-closure case
        // (S16) must remain intact under the accessor-aware scope walk. A call
        // nested in `inner` still dedups to `inner`, NOT a phantom `outer`. ----
        let lua_root = std::env::temp_dir().join("tldr_cf2_s18r_lua_nested");
        let _ = std::fs::remove_dir_all(&lua_root);
        std::fs::create_dir_all(&lua_root).unwrap();
        std::fs::write(
            lua_root.join("mod.lua"),
            "local function helper(x)\n  return x + 1\nend\n\n\
             local function outer(items)\n  \
             local function inner(it)\n    return helper(it)\n  end\n  \
             local total = 0\n  for _, v in ipairs(items) do\n    \
             total = total + inner(v)\n  end\n  return total\nend\n\n\
             local function other()\n  return helper(5)\nend\n\n\
             return { outer = outer, other = other }\n",
        )
        .unwrap();
        let lua_targets = b5_resolve(&lua_root, "helper", crate::Language::Lua);
        let lua_callers: Vec<String> = lua_targets
            .iter()
            .flat_map(|(_, _, cs)| cs.iter())
            .map(|c| c.rsplit(['.', ':']).next().unwrap_or(c).to_string())
            .collect();
        assert!(
            lua_callers.iter().any(|c| c == "inner"),
            "[nested-closure] inner caller missing: {lua_targets:?}"
        );
        assert!(
            !lua_callers.iter().any(|c| c == "outer"),
            "[nested-closure] phantom `outer` caller present (accessor change \
             regressed the named-function dedup): {lua_targets:?}"
        );
        let lua_total: usize = lua_targets.iter().map(|(_, cc, _)| *cc).sum();
        assert_eq!(
            lua_total, 2,
            "[nested-closure] expected exactly 2 callers (inner, other): {lua_targets:?}"
        );
        let _ = std::fs::remove_dir_all(&lua_root);
    }
}
