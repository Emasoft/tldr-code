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

    // CL-2 / GH #40: derive the *bare* method name the user is asking about
    // so we can extract — per call site — the receiver of THAT call from the
    // AST and reject references whose receiver belongs to a different
    // type/module (e.g. an external `json.decode(...)` when the target is the
    // project-local `rpc.decode`, or `Codec::decode` vs `Parser::decode`).
    let bare_target = target_func.rsplit(['.', ':']).next().unwrap_or(target_func);

    // (enclosing_caller, caller_file, line, call_site_receiver)
    let mut additions: Vec<(String, PathBuf, u32, CallReceiver)> = Vec::new();
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
        let receiver =
            extract_call_receiver(&caller_file, r.line, r.column, bare_target, language);

        let key_pair = (enclosing.clone(), caller_file.clone());
        if additions
            .iter()
            .any(|(n, f, _, _)| n == &key_pair.0 && f == &key_pair.1)
        {
            continue;
        }
        additions.push((enclosing, caller_file, r.line as u32, receiver));
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
        return;
    }

    for tree in report.targets.values_mut() {
        // CL-2 / GH #40: derive the receiver-qualifier this target's
        // definition is scoped under, so each candidate caller's call-site
        // receiver can be checked for compatibility. The qualifier comes
        // from the target's own qualified name (`rpc.decode` -> `rpc`,
        // `Parser::decode` -> `Parser`); a bare free function yields `None`.
        let target_qualifier = qualifier_of(&tree.function);

        for (name, file, line, receiver) in &additions {
            // CL-2: receiver-type discrimination. Only mint this caller if
            // the call site's receiver is compatible with the target's
            // defined qualifier. This drops `json.decode(...)` from the
            // callers of `rpc.decode`, and `Codec::decode` self-calls from
            // the callers of `Parser::decode`.
            if !receiver_compatible(receiver, target_qualifier.as_deref(), &tree.file, file) {
                continue;
            }

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
                truncated: false,
                note: Some(note),
                confidence: None,
                receiver_type: receiver.qualifier_label(),
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
///     target qualifier (this is the `impl Parser` vs `impl Codec` split);
///     if the target has no qualifier, a `self`-method call is a different
///     symbol -> reject.
///   - `SelfRef(None)` -> compatible (could not resolve the enclosing type;
///     do not over-reject).
fn receiver_compatible(
    receiver: &CallReceiver,
    target_qualifier: Option<&str>,
    _target_file: &Path,
    _call_file: &Path,
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
        (CallReceiver::SelfRef(Some(ty)), Some(q)) => names_equal_ignore_generics(ty, q),
        (CallReceiver::SelfRef(Some(_)), None) => false,
        (CallReceiver::SelfRef(None), _) => true,
    }
}

/// Compare two type/receiver names, tolerant of a trailing generic argument
/// list (`Parser<'a>` vs `Parser`).
fn names_equal_ignore_generics(a: &str, b: &str) -> bool {
    let strip = |s: &str| s.split(['<', '>']).next().unwrap_or(s).trim().to_string();
    strip(a) == strip(b)
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
    if node.utf8_text(src).map(|t| t != bare_target).unwrap_or(true) {
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
    }

    receiver
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

        // Java/C#/Kotlin field/member access: receiver.method.
        "field_access" | "navigation_expression" | "navigation_suffix" => {
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
fn resolve_receiver_var_type(
    node: &tree_sitter::Node,
    src: &[u8],
    var: &str,
) -> Option<String> {
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
            "class_specifier"
            | "struct_specifier"
            | "class_declaration"
            | "class_definition"
            | "struct_item"
            | "impl_item" => {
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
        .filter(|w| !matches!(*w, "const" | "struct" | "class" | "volatile" | "mutable" | "static"))
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
            "dot_index_expression" | "method_index_expression" => {
                match cur.named_child(0) {
                    Some(n) if n.id() != cur.id() => cur = n,
                    _ => return Some(cur),
                }
            }
            "scoped_identifier" | "scoped_type_identifier" | "qualified_identifier" => {
                match cur.child_by_field_name("path").or_else(|| cur.child_by_field_name("scope")) {
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
        let r = extract_call_receiver(&path, line, col, name, lang);
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
        let graph =
            build_project_call_graph(&root, Language::Elixir, None, true).unwrap();
        let mut report = impact_analysis_with_ast_fallback(
            &graph,
            "handle",
            3,
            None,
            &root,
            Language::Elixir,
        )
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
}
