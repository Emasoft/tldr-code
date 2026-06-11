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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ast::extractor::{
    extract_functions, extract_methods, extract_rust_impl_methods_qualified,
};
use crate::ast::parser::parse_file;
use crate::error::TldrError;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{CallerTree, ImpactReport, ProjectCallGraph, WorkspaceConfig};
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
    let cut = match (dot_idx, coloncolon_idx) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    match cut {
        Some(i) if i < qualified.len() => &qualified[i + 1..],
        _ => qualified,
    }
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
            // For `::`-qualified targets, accept ONLY an exact match
            // (handled above) OR a candidate whose qualified form ends
            // with the user-typed qualifier (handles
            // `mod::Type::method` vs user-typed `Type::method`).
            //
            // Concretely we require:
            //   * candidate's leaf matches target's leaf, AND
            //   * candidate's qualifier ends with target's qualifier
            //
            // This is the strict "qualifier preserved" rule the audit
            // (VAL-RUST-QUAL) calls for.
            if let (Some((cand_qual, cand_leaf)), Some((tgt_qual, tgt_leaf))) =
                (candidate.rsplit_once("::"), target.rsplit_once("::"))
            {
                if cand_leaf == tgt_leaf
                    && (cand_qual == tgt_qual
                        || cand_qual.ends_with(&format!("::{tgt_qual}")))
                {
                    return true;
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
    // Build reverse graph (callee -> callers)
    let reverse_graph = build_reverse_graph(call_graph);

    // Find all functions matching the target
    let mut targets: HashMap<String, CallerTree> = HashMap::new();
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
    // Try normal call-graph-based analysis first
    match impact_analysis(call_graph, target_func, max_depth, target_file) {
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
                    let key = format!("{}:{}", func_file.display(), func_name);
                    report.targets.entry(key).or_insert_with(|| CallerTree {
                        function: func_name.clone(),
                        file: func_file.clone(),
                        caller_count: 0,
                        callers: vec![],
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

                    // Function exists in AST but has no call edges
                    let mut targets = HashMap::new();
                    for (func_name, func_file) in &locations {
                        let key = format!("{}:{}", func_file.display(), func_name);
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
                                function: func_name.clone(),
                                file: func_file.clone(),
                                caller_count: 0,
                                callers: vec![],
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

    let mut options = ReferencesOptions::new();
    options.kinds = Some(vec![ReferenceKind::Call]);
    options.language = Some(language.as_str().to_string());
    options.limit = Some(500);

    let refs_report = match find_references(target_func, project_root, &options) {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut file_funcs_cache: HashMap<PathBuf, Vec<(String, u32, u32)>> = HashMap::new();

    let mut additions: Vec<(String, PathBuf, u32)> = Vec::new();
    // cross-cutting-and-clear-fix-bugs-v1 (P18.X3): collect references from
    // both the primary lookup and (for Lua/Luau qualified names like
    // `m.open`) a secondary bare-name lookup with a context filter — same
    // shape as the explain.rs P13.AGG13-12 enrichment. The lua call graph
    // does not always resolve `<alias>.<method>(...)` to `function m.<method>`
    // definitions through references' qualified path, so impact's caller
    // list comes back empty even though explain reports the same callers
    // via this exact mechanism.
    let mut all_refs: Vec<crate::analysis::references::Reference> =
        refs_report.references.clone();
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

        let is_self = report.targets.values().any(|tree| {
            paths_equivalent_root(&tree.file, project_root, &caller_file)
                && (enclosing == target_func
                    || last_segment_eq_pub(&enclosing, target_func))
        });
        if is_self {
            continue;
        }

        let key_pair = (enclosing.clone(), caller_file.clone());
        if additions
            .iter()
            .any(|(n, f, _)| n == &key_pair.0 && f == &key_pair.1)
        {
            continue;
        }
        additions.push((enclosing, caller_file, r.line as u32));
    }

    if additions.is_empty() {
        return;
    }

    for tree in report.targets.values_mut() {
        for (name, file, line) in &additions {
            // P14.AGG14-1: last-segment-aware dedup so call-graph
            // qualified-name (`Class.method`) and references bare-name
            // (`method`) collapse to the same caller.
            let already_present = tree.callers.iter().any(|c| {
                let names_match = &c.function == name
                    || last_segment_eq_pub(&c.function, name)
                    || last_segment_eq_pub(name, &c.function);
                names_match && paths_equivalent_root(&c.file, project_root, file)
            });
            if already_present {
                continue;
            }
            tree.callers.push(CallerTree {
                function: name.clone(),
                file: file.clone(),
                caller_count: 0,
                callers: vec![],
                truncated: false,
                note: Some(format!(
                    "Discovered via references at line {} (call graph missing edge)",
                    line
                )),
                confidence: None,
                receiver_type: None,
            });
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
        let rust_target_qualifier: Option<&str> = if matches!(language, Language::Rust)
            && target_func.contains("::")
        {
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
                let qualifier_matches = cand_qual == qualifier
                    || cand_qual.ends_with(&format!("::{qualifier}"));
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

/// Build reverse graph: (dst_file, dst_func) -> [(src_file, src_func)]
fn build_reverse_graph(call_graph: &ProjectCallGraph) -> HashMap<FunctionKey, Vec<FunctionKey>> {
    let mut reverse: HashMap<FunctionKey, Vec<FunctionKey>> = HashMap::new();

    for edge in call_graph.edges() {
        let dst_key = (edge.dst_file.clone(), edge.dst_func.clone());
        let src_key = (edge.src_file.clone(), edge.src_func.clone());

        reverse.entry(dst_key).or_default().push(src_key);
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

    reverse
}

/// Build caller tree via BFS traversal
fn build_caller_tree(
    file: &Path,
    func: &str,
    reverse_graph: &HashMap<FunctionKey, Vec<FunctionKey>>,
    max_depth: usize,
) -> CallerTree {
    let key = (file.to_path_buf(), func.to_string());

    // Get direct callers
    let callers = reverse_graph.get(&key);
    let caller_count = callers.map(|c| c.len()).unwrap_or(0);

    // Handle entry point (no callers)
    if caller_count == 0 {
        return CallerTree {
            function: func.to_string(),
            file: file.to_path_buf(),
            caller_count: 0,
            callers: vec![],
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
        });
        graph.add_edge(CallEdge {
            src_file: "b.py".into(),
            src_func: "func_b".to_string(),
            dst_file: "c.py".into(),
            dst_func: "func_c".to_string(),
        });
        // D also calls C
        graph.add_edge(CallEdge {
            src_file: "d.py".into(),
            src_func: "func_d".to_string(),
            dst_file: "c.py".into(),
            dst_func: "func_c".to_string(),
        });

        graph
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
}
