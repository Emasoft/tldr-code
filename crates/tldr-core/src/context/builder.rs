//! Context builder (spec Section 2.7.1)
//!
//! Builds LLM-ready context from an entry point via BFS traversal of the call graph.
//!
//! # Algorithm
//! 1. Build cross-file call graph for the project
//! 2. Find the entry point function in the graph
//! 3. BFS traverse callees to specified depth
//! 4. For each function: extract signature, optionally docstring, CFG metrics
//! 5. Format as LLM-consumable text
//!
//! # Token Savings
//! Instead of reading entire files, we extract only:
//! - Function signatures
//! - Docstrings (optional)
//! - Call relationships
//! - CFG metrics (blocks, cyclomatic complexity)
//!
//! This achieves ~95% token savings compared to reading full files.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ast::extract::extract_file;
use crate::callgraph::build_project_call_graph;
use crate::cfg::get_cfg_context;
use crate::error::TldrError;
use crate::types::{FunctionInfo, Language, ProjectCallGraph};
use crate::TldrResult;

/// Context information for a single function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionContext {
    /// Function name
    pub name: String,
    /// File containing the function (relative to project root)
    pub file: PathBuf,
    /// Line number where function is defined
    pub line: u32,
    /// Function signature (e.g., "def foo(x: int, y: str) -> bool")
    pub signature: String,
    /// Optional docstring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring: Option<String>,
    /// Functions called by this function
    pub calls: Vec<String>,
    /// Number of basic blocks in CFG
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<usize>,
    /// Cyclomatic complexity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cyclomatic: Option<u32>,
}

/// Relevant context for LLM consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelevantContext {
    /// Entry point function name
    pub entry_point: String,
    /// Traversal depth used
    pub depth: usize,
    /// All functions in context (entry point + callees)
    pub functions: Vec<FunctionContext>,
}

impl RelevantContext {
    /// Format context for LLM consumption
    ///
    /// Produces a human-readable format suitable for including in LLM prompts.
    pub fn to_llm_string(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "# Code Context: {} (depth={})\n\n",
            self.entry_point, self.depth
        ));

        output.push_str(&format!(
            "## Summary\n- Entry point: `{}`\n- Functions included: {}\n\n",
            self.entry_point,
            self.functions.len()
        ));

        output.push_str("## Functions\n\n");

        for func in &self.functions {
            output.push_str(&format!(
                "### {} ({}:{})\n\n",
                func.name,
                func.file.display(),
                func.line
            ));
            output.push_str(&format!("```\n{}\n```\n\n", func.signature));

            if let Some(ref doc) = func.docstring {
                output.push_str(&format!("**Docstring:** {}\n\n", doc.trim()));
            }

            if !func.calls.is_empty() {
                output.push_str(&format!("**Calls:** {}\n\n", func.calls.join(", ")));
            }

            if let (Some(blocks), Some(cyclomatic)) = (func.blocks, func.cyclomatic) {
                output.push_str(&format!(
                    "**Complexity:** {} blocks, cyclomatic={}\n\n",
                    blocks, cyclomatic
                ));
            }

            output.push_str("---\n\n");
        }

        output
    }
}

/// Get relevant context for LLM starting from an entry point.
///
/// # Arguments
/// * `project` - Project root directory
/// * `entry_point` - Name of the entry point function
/// * `depth` - Maximum traversal depth (0 = entry only, 1 = entry + direct callees, etc.)
/// * `language` - Programming language
/// * `include_docstrings` - Whether to include docstrings in output
/// * `file_filter` - Optional file path to disambiguate common function names.
///   When provided, only matches functions in files whose path ends with this filter.
///   For example, `Some(Path::new("django/shortcuts.py"))` selects `render` from that
///   specific file when multiple files define a function named `render`.
///
/// # Returns
/// * `Ok(RelevantContext)` - Context with functions and their metadata
/// * `Err(TldrError::FunctionNotFound)` - Entry point not found
///
/// # Example
/// ```ignore
/// let ctx = get_relevant_context(
///     Path::new("src"),
///     "main",
///     2,
///     Language::Python,
///     true,
///     None, // no file filter
/// )?;
/// ```
pub fn get_relevant_context(
    project: &Path,
    entry_point: &str,
    depth: usize,
    language: Language,
    include_docstrings: bool,
    file_filter: Option<&Path>,
) -> TldrResult<RelevantContext> {
    // Step 1: Build call graph
    let call_graph = build_project_call_graph(project, language, None, true)?;

    // Step 2: Find entry point in the graph
    let entry_location = find_function_in_graph(&call_graph, entry_point, project, file_filter)?;

    // Step 3: BFS traversal to collect all functions up to depth
    let function_keys = bfs_collect_functions(&call_graph, &entry_location, depth);

    // Step 4: Extract context for each function
    let mut functions = Vec::new();
    let mut seen_files: HashMap<PathBuf, crate::types::ModuleInfo> = HashMap::new();

    for (file, func_name) in function_keys {
        // The call graph stores relative paths (e.g., "main.py", "lib/utils.py").
        // Resolve them against the project root so extract_file() can canonicalize.
        let full_path = if file.is_relative() {
            project.join(&file)
        } else {
            file.clone()
        };

        // Cache file extractions (keyed on original relative path for consistency)
        let module_info = if let Some(info) = seen_files.get(&file) {
            info.clone()
        } else {
            let info = extract_file(&full_path, Some(project)).unwrap_or_else(|_| {
                // Return empty module info on error
                crate::types::ModuleInfo {
                    file_path: file.clone(),
                    language,
                    docstring: None,
                    imports: vec![],
                    functions: vec![],
                    classes: vec![],
                    constants: vec![],
                    call_graph: Default::default(),
                    modifiers: Vec::new(),
                    events: Vec::new(),
                    errors: Vec::new(),
                }
            });
            seen_files.insert(file.clone(), info.clone());
            info
        };

        // Find the function in the module
        if let Some(func_info) = find_function_info(&module_info, &func_name) {
            let func_context = build_function_context(
                &full_path,
                &func_name,
                func_info,
                &module_info,
                project,
                language,
                include_docstrings,
                Some(&call_graph),
                &file,
            );
            functions.push(func_context);
        }
    }

    Ok(RelevantContext {
        entry_point: entry_point.to_string(),
        depth,
        functions,
    })
}

/// Find a function's location (file, name) in the call graph.
///
/// When `file_filter` is `Some`, only matches functions whose file path ends with
/// the filter path. This disambiguates common function names that appear in multiple files.
///
/// cli-error-clarity-v2 (P2.BUG-8): when running from a project root, the call
/// graph may contain edges where the *callee* refers to a method by a name that
/// also happens to be defined as a placeholder (with no methods) in a test
/// file. The previous implementation returned the first edge match, which
/// could land on the placeholder file (e.g. `tests/test_config.py` defining a
/// stub class `Flask`) and then `find_function_info` would fail, producing 0
/// functions. We now collect ALL candidate locations and prefer ones whose
/// extracted module actually contains the function definition. As a tertiary
/// preference (still without verification) we deprioritise files under common
/// test directories so the chosen location is the real implementation.
/// Find the canonical `(file, func)` key in the call graph that
/// corresponds to a `(file_filter, func_name)` pair, so that downstream
/// BFS traversal hits the correct outgoing edges.
///
/// context-relative-and-ts-colon-v1 (P15.AGG15-2): the call graph stores
/// edges with adapter-specific conventions for both file paths
/// (project-relative vs. bare-filename) and function names (bare name
/// vs. `Class.method`). The file_filter early-return path of
/// `find_function_in_graph` previously returned `(rel_path, bare_name)`
/// which often did not match the graph's actual edge key, causing BFS
/// to find zero outgoing edges and collapse the result to the single
/// entry point. This helper probes the graph for an edge whose source
/// matches both the file (after canonicalisation) and the function
/// (exact match or `<Class>.{func}` suffix), returning the graph's own
/// key shape when found.
///
/// Returns `None` when no graph edge matches — callers fall back to
/// the direct-extract key, which preserves correct behaviour for leaf
/// functions and single-file projects where the graph has no outgoing
/// edges to traverse anyway.
fn find_call_graph_key(
    call_graph: &ProjectCallGraph,
    abs_file: &Path,
    func_name: &str,
    project: &Path,
) -> Option<(PathBuf, String)> {
    let canon_filter = abs_file.canonicalize().ok();
    let file_matches = |edge_file: &Path| -> bool {
        // Cheap suffix match first.
        if abs_file.ends_with(edge_file) || edge_file.ends_with(abs_file) {
            return true;
        }
        let abs_edge = if edge_file.is_relative() {
            project.join(edge_file)
        } else {
            edge_file.to_path_buf()
        };
        let canon_edge = abs_edge.canonicalize().ok();
        match (canon_edge, canon_filter.as_ref()) {
            (Some(a), Some(b)) => &a == b,
            _ => false,
        }
    };
    // v0.5.0 SOL-CONV-R1-4 (C20): allow `Class::method` to match the
    // call-graph adapter's canonical `Class.method` form (and vice
    // versa), so that scanner-returned keys typed in the user's
    // preferred separator still resolve to the adapter's canonical key.
    let normalize_separator = |s: &str| s.replace("::", ".");
    let func_target_normalized = normalize_separator(func_name);
    let func_matches = |edge_func: &str| -> bool {
        if edge_func == func_name || edge_func.ends_with(&format!(".{}", func_name)) {
            return true;
        }
        let edge_norm = normalize_separator(edge_func);
        edge_norm == func_target_normalized
            || edge_norm.ends_with(&format!(".{}", func_target_normalized))
    };
    for edge in call_graph.edges() {
        if file_matches(&edge.src_file) && func_matches(&edge.src_func) {
            return Some((edge.src_file.clone(), edge.src_func.clone()));
        }
        if file_matches(&edge.dst_file) && func_matches(&edge.dst_func) {
            return Some((edge.dst_file.clone(), edge.dst_func.clone()));
        }
    }
    None
}

fn find_function_in_graph(
    call_graph: &ProjectCallGraph,
    func_name: &str,
    project: &Path,
    file_filter: Option<&Path>,
) -> TldrResult<(PathBuf, String)> {
    // context-file-func-cross-lang-and-cpp-qualified-v1
    // (P14.AGG13-5 generalization): when the caller supplied an
    // explicit file path (typically via the `<file>:<func>` shorthand
    // or `--file`), we already KNOW which file to inspect. Extract
    // that file directly BEFORE falling back to the call-graph or
    // tree-walking scan. This covers two cross-language failure
    // modes that share a root cause:
    //
    //   - OCaml `path/.../vendor/x.ml:fn`: the project tree-walker
    //     skips `vendor/` (DEFAULT_SKIP_DIRS), so `scan_project_for_function`
    //     never visits the file even though the user pointed us at it.
    //   - TypeScript `src/build/x.ts:fn`: the walker skips `build/`
    //     (build sink), with the same outcome.
    //
    // Direct extraction is bounded (single file), respects the
    // existing `find_function_info` matcher, and only runs when the
    // caller has actually pinned a file — so it has no effect on the
    // unrestricted `tldr context fn` flow.
    if let Some(filter) = file_filter {
        let abs = if filter.is_absolute() {
            filter.to_path_buf()
        } else {
            project.join(filter)
        };
        if abs.is_file() {
            if let Ok(module_info) = extract_file(&abs, Some(project)) {
                // context-relative-and-ts-colon-v1 (P15.AGG15-2): when the
                // file_filter early-return matched, prefer the
                // corresponding key from the call graph over the
                // direct-extract key. The call graph stores edges with
                // adapter-specific conventions (e.g. C# stores
                // `BsonBinaryWriter.WriteToken` not bare `WriteToken`;
                // some adapters store relative paths with leading
                // directory components). Returning the
                // `(rel, func_name)` direct-extract key works for
                // resolution but breaks the downstream BFS callee
                // traversal when the call graph uses a different key
                // shape — BFS finds zero outgoing edges and the result
                // collapses to the single entry point. By probing the
                // call graph first and returning the matching graph key,
                // BFS recovers full callee depth (regression cases:
                // csharp 1→9 functions, js 1→6 functions). Falls back to
                // direct-extract behaviour when no graph edge matches
                // (covers leaf functions and single-file projects).
                if find_function_info(&module_info, func_name).is_some() {
                    if let Some(graph_key) =
                        find_call_graph_key(call_graph, &abs, func_name, project)
                    {
                        return Ok(graph_key);
                    }
                    // Return a project-relative path when possible so
                    // downstream consumers (caching, file-extract) can
                    // canonicalise consistently with the rest of the
                    // graph. Absolute path is fine too — `extract_file`
                    // accepts both.
                    let rel = abs.strip_prefix(project).unwrap_or(&abs).to_path_buf();
                    return Ok((rel, func_name.to_string()));
                }
                // Class-method form: ClassName.method
                if let Some(dot_idx) = func_name.find('.') {
                    let class_name = &func_name[..dot_idx];
                    let method_name = &func_name[dot_idx + 1..];
                    for class in &module_info.classes {
                        if class.name == class_name {
                            for method in &class.methods {
                                if method.name == method_name {
                                    if let Some(graph_key) = find_call_graph_key(
                                        call_graph, &abs, func_name, project,
                                    ) {
                                        return Ok(graph_key);
                                    }
                                    let rel = abs
                                        .strip_prefix(project)
                                        .unwrap_or(&abs)
                                        .to_path_buf();
                                    return Ok((rel, func_name.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // language-adapter-fixes-v1 (P13.AGG13-5): the call graph stores
    // project-relative paths (`lib/application.js`) but `file_filter`
    // arrives as an absolute path (the user typed
    // `/tmp/repos/express/lib/application.js`). The legacy
    // `file.ends_with(filter)` form requires the filter to be a *suffix*
    // of the file's components — which is impossible when the filter is
    // absolute and the file is relative. Compare via canonicalisation
    // (resolving the relative path against `project`) so absolute vs.
    // relative reconciles correctly. Fall back to the legacy
    // suffix-on-components match for cases where canonicalize fails
    // (broken symlinks, missing files).
    let file_matches = |file: &Path| -> bool {
        match file_filter {
            None => true,
            Some(filter) => {
                if file.ends_with(filter) {
                    return true;
                }
                let abs_file = if file.is_relative() {
                    project.join(file)
                } else {
                    file.to_path_buf()
                };
                let canon_file = abs_file.canonicalize().ok();
                let canon_filter = filter.canonicalize().ok();
                match (canon_file, canon_filter) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                }
            }
        }
    };

    // Heuristic: paths that look like test fixtures should be deprioritised
    // unless they actually define the function (verified by extraction below).
    fn is_test_path(p: &Path) -> bool {
        p.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            matches!(
                s.as_ref(),
                "tests" | "test" | "__tests__" | "spec" | "specs" | "testing"
            )
        })
    }

    // Collect ALL edge matches (not just the first) so we can pick the best.
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    let mut seen: HashSet<(PathBuf, String)> = HashSet::new();
    for edge in call_graph.edges() {
        if (edge.src_func == func_name || edge.src_func.ends_with(&format!(".{}", func_name)))
            && file_matches(&edge.src_file)
        {
            let key = (edge.src_file.clone(), edge.src_func.clone());
            if seen.insert(key.clone()) {
                candidates.push(key);
            }
        }
        if (edge.dst_func == func_name || edge.dst_func.ends_with(&format!(".{}", func_name)))
            && file_matches(&edge.dst_file)
        {
            let key = (edge.dst_file.clone(), edge.dst_func.clone());
            if seen.insert(key.clone()) {
                candidates.push(key);
            }
        }
    }

    // Verify each candidate by extracting the module and checking the function
    // actually has a definition there. Prefer non-test candidates first.
    let mut sorted = candidates.clone();
    sorted.sort_by_key(|(f, _)| is_test_path(f));
    for (file, func) in &sorted {
        let full_path = if file.is_relative() {
            project.join(file)
        } else {
            file.clone()
        };
        if let Ok(module_info) = extract_file(&full_path, Some(project)) {
            if find_function_info(&module_info, func).is_some() {
                return Ok((file.clone(), func.clone()));
            }
        }
    }

    // No candidate verified — fall back to the first edge match (preserves
    // previous behaviour for cases where extraction fails for some reason).
    if let Some(first) = candidates.into_iter().next() {
        return Ok(first);
    }

    // If not in call graph, it might be a standalone function
    // Try to find it by scanning project files
    if let Some(location) = scan_project_for_function(project, func_name, file_filter)? {
        // v0.5.0 SOL-CONV-R1-4 (C20): the project scanner returns the
        // function key in whatever shape the caller typed it
        // (`Class::method`, `bare_name`, or `Class.method`). But the
        // language call-graph adapters use one canonical shape per
        // language (Solidity: `Class.method`, C++: `Class::method`,
        // Python: bare name). When the scanner-returned key disagrees
        // with the adapter's canonical key, the downstream BFS
        // forward-graph lookup misses, depth expansion stops at the
        // entry point, and the result collapses to a single function.
        //
        // Probe the call graph for an edge whose source / destination
        // matches the resolved (file, function) under the adapter's
        // shape (suffix-match) and prefer the canonical edge key. Falls
        // back to the scanner's raw key when no edge matches (covers
        // leaf functions that have no outgoing edges).
        let (loc_file, loc_func) = &location;
        let abs_file = if loc_file.is_relative() {
            project.join(loc_file)
        } else {
            loc_file.clone()
        };
        if let Some(canonical) = find_call_graph_key(call_graph, &abs_file, loc_func, project) {
            return Ok(canonical);
        }
        return Ok(location);
    }

    // Not found - collect suggestions
    let suggestions = collect_similar_function_names(call_graph, func_name);

    Err(TldrError::FunctionNotFound {
        name: func_name.to_string(),
        file: None,
        suggestions,
    })
}

/// Scan project files to find a function by name.
///
/// When `file_filter` is `Some`, only scans files whose path ends with the filter,
/// narrowing the search to a specific file for disambiguation.
fn scan_project_for_function(
    project: &Path,
    func_name: &str,
    file_filter: Option<&Path>,
) -> TldrResult<Option<(PathBuf, String)>> {
    use crate::fs::tree::{collect_files, get_file_tree};
    use crate::types::IgnoreSpec;

    // Get all source files
    let tree = get_file_tree(project, None, true, Some(&IgnoreSpec::default()))?;
    let files = collect_files(&tree, project);

    for file_path in files {
        // If file_filter is set, skip files that don't match
        if let Some(filter) = file_filter {
            // Check if the file path (relative to project) ends with the filter
            let relative = file_path.strip_prefix(project).unwrap_or(&file_path);
            // language-adapter-fixes-v1 (P13.AGG13-5): also accept absolute
            // filter paths (the `<file>:<func>` shorthand expands to an
            // absolute file path). Compare canonicalised forms when the
            // legacy suffix-on-components match misses.
            let suffix_ok = relative.ends_with(filter) || file_path.ends_with(filter);
            let abs_ok = if !suffix_ok {
                let canon_file = file_path.canonicalize().ok();
                let canon_filter = filter.canonicalize().ok();
                matches!((canon_file, canon_filter), (Some(a), Some(b)) if a == b)
            } else {
                false
            };
            if !suffix_ok && !abs_ok {
                continue;
            }
        }

        if let Ok(module_info) = extract_file(&file_path, Some(project)) {
            // Check top-level functions
            for func in &module_info.functions {
                if func.name == func_name {
                    return Ok(Some((file_path, func.name.clone())));
                }
            }
            // Check class methods
            for class in &module_info.classes {
                for method in &class.methods {
                    if method.name == func_name {
                        let full_name = format!("{}.{}", class.name, method.name);
                        return Ok(Some((file_path, full_name)));
                    }
                }
            }
            // context-file-func-cross-lang-and-cpp-qualified-v1
            // (P14.AGG14-3): also accept the C++ `Class::method`
            // qualified form when scanning, so that
            // `tldr context Class::method --file foo.cpp` resolves
            // the same way the per-function commands do.
            if func_name.contains("::") {
                let parts: Vec<&str> = func_name.split("::").collect();
                if parts.len() >= 2 {
                    let class_name = parts[0];
                    let method_name = *parts.last().unwrap();
                    for class in &module_info.classes {
                        if class.name == class_name {
                            for method in &class.methods {
                                if method.name == method_name {
                                    return Ok(Some((file_path, func_name.to_string())));
                                }
                            }
                        }
                    }
                    for func in &module_info.functions {
                        if func.name == method_name {
                            return Ok(Some((file_path, func_name.to_string())));
                        }
                    }
                    for class in &module_info.classes {
                        for method in &class.methods {
                            if method.name == method_name {
                                return Ok(Some((file_path, func_name.to_string())));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Collect similar function names for error suggestions
fn collect_similar_function_names(call_graph: &ProjectCallGraph, target: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut suggestions = Vec::new();
    let target_lower = target.to_lowercase();

    for edge in call_graph.edges() {
        for func in [&edge.src_func, &edge.dst_func] {
            if !seen.contains(func) {
                seen.insert(func.clone());
                let func_lower = func.to_lowercase();
                // Simple similarity: contains or edit distance would be better
                if func_lower.contains(&target_lower) || target_lower.contains(&func_lower) {
                    suggestions.push(func.clone());
                }
            }
        }
    }

    suggestions.sort();
    suggestions.truncate(5);
    suggestions
}

/// BFS collect all functions from entry point up to depth
fn bfs_collect_functions(
    call_graph: &ProjectCallGraph,
    entry: &(PathBuf, String),
    max_depth: usize,
) -> Vec<(PathBuf, String)> {
    let mut result = Vec::new();
    let mut visited: HashSet<(PathBuf, String)> = HashSet::new();
    let mut queue: VecDeque<((PathBuf, String), usize)> = VecDeque::new();

    // Build forward graph: caller -> [callees]
    let forward_graph = build_forward_graph(call_graph);

    // Start with entry point
    queue.push_back((entry.clone(), 0));
    visited.insert(entry.clone());

    while let Some(((file, func), current_depth)) = queue.pop_front() {
        result.push((file.clone(), func.clone()));

        // Don't explore further if at max depth
        if current_depth >= max_depth {
            continue;
        }

        // Find all callees of this function
        let key = (file.clone(), func.clone());
        if let Some(callees) = forward_graph.get(&key) {
            for callee in callees {
                if !visited.contains(callee) {
                    visited.insert(callee.clone());
                    queue.push_back((callee.clone(), current_depth + 1));
                }
            }
        }
    }

    result
}

/// Build forward graph: (src_file, src_func) -> [(dst_file, dst_func)]
fn build_forward_graph(
    call_graph: &ProjectCallGraph,
) -> HashMap<(PathBuf, String), Vec<(PathBuf, String)>> {
    let mut forward: HashMap<(PathBuf, String), Vec<(PathBuf, String)>> = HashMap::new();

    for edge in call_graph.edges() {
        let src_key = (edge.src_file.clone(), edge.src_func.clone());
        let dst_key = (edge.dst_file.clone(), edge.dst_func.clone());

        forward.entry(src_key).or_default().push(dst_key);
    }

    forward
}

/// Find function info in a module
fn find_function_info<'a>(
    module_info: &'a crate::types::ModuleInfo,
    func_name: &str,
) -> Option<&'a FunctionInfo> {
    // Check top-level functions (exact match)
    for func in &module_info.functions {
        if func.name == func_name {
            return Some(func);
        }
    }

    // Check class methods (func_name might be "ClassName.method")
    if let Some(dot_idx) = func_name.find('.') {
        let class_name = &func_name[..dot_idx];
        let method_name = &func_name[dot_idx + 1..];

        for class in &module_info.classes {
            if class.name == class_name {
                for method in &class.methods {
                    if method.name == method_name {
                        return Some(method);
                    }
                }
            }
        }

        // real-repo-fixes-v1 (P9.BUG-R3): for languages where the call
        // graph emits qualified names (`Module.func`) but `extract` lists
        // top-level bare functions (notably OCaml `Module.to_json` and
        // Elixir `Module.func`), fall back to a last-segment match against
        // top-level functions. Mirrors `analysis::impact::names_match`'s
        // qualifier-stripping rule (cross-command-consistency-v3 P5.BUG-N3)
        // so `tldr context to_json` and `tldr impact to_json` agree.
        let last = func_name.rsplit('.').next().unwrap_or(func_name);
        if !last.is_empty() && last != func_name {
            for func in &module_info.functions {
                if func.name == last {
                    return Some(func);
                }
            }
            // Also check class methods named with the last segment, in case
            // the qualifier path matches a deeper hierarchy (Foo.Bar.method).
            for class in &module_info.classes {
                for method in &class.methods {
                    if method.name == last {
                        return Some(method);
                    }
                }
            }
        }
    }

    // context-file-func-cross-lang-and-cpp-qualified-v1 (P14.AGG14-3):
    // Accept C++ `Class::method` qualified names. The C++ extractor
    // currently stores the rightmost identifier (`Parse`) for both
    // inline class methods and out-of-class `void XMLDocument::Parse`
    // definitions, so we look for the bare last segment in either
    // top-level functions OR in any class's methods. When the parent
    // class scope IS present (inline definitions), we additionally
    // prefer the matching class scope so disambiguation is preserved.
    if func_name.contains("::") {
        let parts: Vec<&str> = func_name.split("::").collect();
        if parts.len() >= 2 {
            let class_name = parts[0];
            let method_name = *parts.last().unwrap();
            // Prefer the matching class scope when present (inline
            // definitions live in the same translation unit as the
            // class body — typical for header files).
            for class in &module_info.classes {
                if class.name == class_name {
                    for method in &class.methods {
                        if method.name == method_name {
                            return Some(method);
                        }
                    }
                }
            }
            // Fall back to bare last-segment match against top-level
            // functions (covers `void Class::method() {...}`
            // out-of-class definitions in `.cpp` files where the class
            // body lives in a separate `.h`).
            for func in &module_info.functions {
                if func.name == method_name {
                    return Some(func);
                }
            }
            // And bare last-segment match in any class body — handles
            // mixed cases where the class node IS in the file but
            // doesn't match `class_name` exactly (e.g. anonymous
            // namespaces, nested classes).
            for class in &module_info.classes {
                for method in &class.methods {
                    if method.name == method_name {
                        return Some(method);
                    }
                }
            }
        }
    }

    None
}

/// Build function context with all metadata
#[allow(clippy::too_many_arguments)]
fn build_function_context(
    file: &Path,
    func_name: &str,
    func_info: &FunctionInfo,
    module_info: &crate::types::ModuleInfo,
    project: &Path,
    language: Language,
    include_docstrings: bool,
    project_call_graph: Option<&ProjectCallGraph>,
    relative_file: &Path,
) -> FunctionContext {
    // Build signature
    let signature = build_signature(func_info, language);

    // VAL-018: prefer the project call graph (which is populated for ALL
    // 18 languages by the dedicated language handlers in
    // crates/tldr-core/src/callgraph/) over `module_info.call_graph`,
    // which is built by `extract.rs::build_intra_file_call_graph` and
    // historically only populated for Python/TS/JS/Go/Rust/Java.
    //
    // The project call graph keys edges by (file, func), so we need to
    // match the file too when resolving calls.
    let mut calls: Vec<String> = Vec::new();
    if let Some(graph) = project_call_graph {
        for edge in graph.edges() {
            let edge_file_matches = edge.src_file == relative_file
                || edge.src_file == *file
                || file.ends_with(&edge.src_file);
            let edge_func_matches = edge.src_func == func_info.name
                || edge.src_func == func_name
                || edge.src_func.ends_with(&format!(".{}", func_info.name));
            if edge_file_matches && edge_func_matches {
                calls.push(edge.dst_func.clone());
            }
        }
        calls.sort();
        calls.dedup();
    }
    if calls.is_empty() {
        // Fall back to the intra-file call graph for languages where the
        // project call graph might miss intra-file edges.
        calls = module_info
            .call_graph
            .calls
            .get(&func_info.name)
            .cloned()
            .unwrap_or_default();
    }

    // Get CFG metrics (best effort - don't fail if unavailable)
    let (blocks, cyclomatic) = get_cfg_metrics(file, func_name, language);

    // Make file path relative to project
    let relative_file = file
        .strip_prefix(project)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| file.to_path_buf());

    FunctionContext {
        name: func_name.to_string(),
        file: relative_file,
        line: func_info.line_number,
        signature,
        docstring: if include_docstrings {
            func_info.docstring.clone()
        } else {
            None
        },
        calls,
        blocks,
        cyclomatic,
    }
}

/// Build function signature string
fn build_signature(func_info: &FunctionInfo, language: Language) -> String {
    let params = func_info.params.join(", ");

    let return_type = func_info
        .return_type
        .as_ref()
        .map(|t| format!(" -> {}", t))
        .unwrap_or_default();

    let async_prefix = if func_info.is_async { "async " } else { "" };

    match language {
        Language::Python => {
            format!(
                "{}def {}({}){}",
                async_prefix, func_info.name, params, return_type
            )
        }
        Language::TypeScript | Language::JavaScript => {
            format!(
                "{}function {}({}){}",
                async_prefix, func_info.name, params, return_type
            )
        }
        Language::Go => {
            format!("func {}({}){}", func_info.name, params, return_type)
        }
        Language::Rust => {
            format!(
                "{}fn {}({}){}",
                async_prefix, func_info.name, params, return_type
            )
        }
        _ => {
            format!("{}({}){}", func_info.name, params, return_type)
        }
    }
}

/// Get CFG metrics for a function.
///
/// `blocks` is taken from CFG construction.
///
/// p19-secondary-fixes-v1 (BUG-P19-07): the `cyclomatic` value is
/// computed via the canonical
/// `metrics::complexity::analyze_complexity` (the same path
/// `tldr complexity` uses), so the two surfaces agree. Previously the
/// CFG-derived `cyclomatic_complexity` (E-N+2 form) disagreed with the
/// decision-point counter, which caused
/// `tldr complexity tinyxml2.cpp XMLDocument::Parse` (cyclomatic=8) to
/// disagree with
/// `tldr context XMLDocument::Parse /tmp/repos/cpp-tinyxml2` (=4) on the
/// same function.
fn get_cfg_metrics(
    file: &Path,
    func_name: &str,
    language: Language,
) -> (Option<usize>, Option<u32>) {
    // cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #48.
    //
    // Pre-fix:
    //     let lookup_name = func_name.rfind('.').map(strip).unwrap_or(func_name);
    //     get_cfg_context(file, lookup_name, language)
    // Stripping by `.` discarded the class prefix for Python `Class.method`
    // (e.g. `Alpha.process` -> `process`), and the bare lookup then
    // matched the FIRST source-order `process` in the file
    // (`Beta.process`) — yielding the wrong CFG and the wrong `blocks`
    // count. The cyclomatic path correctly used the qualified
    // `Alpha.process` form, so the two metrics on the same record
    // disagreed (cyclomatic=1 Alpha, blocks=14 Beta).
    //
    // Post-fix: pass the qualified name straight through to
    // `get_cfg_context`. Its internal `find_function_node` already
    // understands both `Class.method` (Python/JS/TS/Ruby/...) and
    // `Class::method` (C/C++/Rust) qualified forms via dedicated
    // class-scope resolvers. Fall back to the bare last segment only
    // when the qualified lookup returns an empty CFG, splitting on the
    // LANGUAGE's qualifier separator (`::` for C/C++/Rust, `.` for the
    // rest) so the prefix-strip is consistent with the qualifier form.
    let file_str = file.to_str().unwrap_or("");
    let qualified_cfg = get_cfg_context(file_str, func_name, language).ok();
    let blocks = match qualified_cfg {
        Some(ref cfg) if !cfg.blocks.is_empty() => Some(cfg.blocks.len()),
        _ => {
            let bare = split_qualified_last_segment(func_name, language);
            get_cfg_context(file_str, bare, language)
                .ok()
                .map(|cfg| cfg.blocks.len())
        }
    };

    // Route cyclomatic through the canonical complexity calculator so
    // `tldr context` and `tldr complexity` always agree on the same
    // function. Use the original `func_name` (qualified or bare) — the
    // complexity calculator supports both shapes via
    // `find_function_node`.
    let cyclomatic =
        match crate::metrics::complexity::calculate_complexity(file_str, func_name, language) {
            Ok(metrics) => Some(metrics.cyclomatic),
            Err(_) => {
                // Fallback: try with the bare last segment of the
                // qualified name (lang-aware separator).
                let bare = split_qualified_last_segment(func_name, language);
                crate::metrics::complexity::calculate_complexity(file_str, bare, language)
                    .ok()
                    .map(|m| m.cyclomatic)
            }
        };

    (blocks, cyclomatic)
}

/// cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #48.
///
/// Return the bare last segment of a (possibly) qualified function name,
/// using the language's qualifier separator:
///   - `::` for C, C++, Rust (e.g. `outer::Class::method` -> `method`)
///   - `.` for everything else (e.g. `Module.Class.method` -> `method`)
///
/// When the name carries no qualifier the input is returned unchanged.
fn split_qualified_last_segment<'a>(func_name: &'a str, language: Language) -> &'a str {
    let sep: &str = match language {
        Language::C | Language::Cpp | Language::Rust => "::",
        _ => ".",
    };
    match func_name.rfind(sep) {
        Some(idx) => &func_name[idx + sep.len()..],
        None => func_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that get_relevant_context resolves relative paths from the call graph
    /// correctly against the project root, producing non-empty function context.
    ///
    /// This is a regression test for a bug where BFS returned relative paths
    /// (e.g., "main.py") but extract_file() canonicalized them relative to CWD
    /// instead of the project root, causing silent extraction failures.
    #[test]
    fn test_context_resolves_relative_paths_from_callgraph() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temp project with two files where main.py calls helper.py
        let temp_dir = TempDir::new().unwrap();
        let project = temp_dir.path();

        // main.py: imports and calls helper from helper.py
        let main_py = r#"from helper import do_work

def main():
    """Entry point."""
    result = do_work(42)
    return result
"#;

        // helper.py: defines do_work which calls internal_calc
        let helper_py = r#"def do_work(x):
    """Do some work."""
    return internal_calc(x) + 1

def internal_calc(x):
    """Internal calculation."""
    return x * 2
"#;

        fs::write(project.join("main.py"), main_py).unwrap();
        fs::write(project.join("helper.py"), helper_py).unwrap();

        // Get context starting from "main" with depth=1
        // This should find "main" and its callees (including cross-file "do_work")
        let result = get_relevant_context(project, "main", 1, Language::Python, true, None);

        assert!(
            result.is_ok(),
            "get_relevant_context failed: {:?}",
            result.err()
        );
        let ctx = result.unwrap();

        // The context should include functions (not be empty due to path resolution failure)
        assert!(
            !ctx.functions.is_empty(),
            "Expected non-empty functions in context, got 0. \
             This indicates extract_file() failed to resolve relative paths from the call graph."
        );

        // The entry point "main" should be present
        let func_names: Vec<&str> = ctx.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            func_names.contains(&"main"),
            "Expected 'main' in context functions, got: {:?}",
            func_names
        );

        // With depth=1, callees of main should also appear (e.g., do_work)
        assert!(
            func_names.contains(&"do_work"),
            "Expected callee 'do_work' in context at depth=1, got: {:?}",
            func_names
        );
    }

    /// Test that context works for intra-file calls (same file, different functions).
    /// This is the simpler case that may work even without the path fix if CWD happens
    /// to match the project root, so we test the cross-file case separately above.
    #[test]
    fn test_context_intra_file_calls() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project = temp_dir.path();

        let main_py = r#"def entry():
    """Entry function."""
    return helper(10)

def helper(n):
    """Helper function."""
    return n + 1
"#;

        fs::write(project.join("main.py"), main_py).unwrap();

        let result = get_relevant_context(project, "entry", 1, Language::Python, true, None);

        assert!(
            result.is_ok(),
            "get_relevant_context failed: {:?}",
            result.err()
        );
        let ctx = result.unwrap();

        assert!(
            !ctx.functions.is_empty(),
            "Expected non-empty functions in context"
        );

        let func_names: Vec<&str> = ctx.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            func_names.contains(&"entry"),
            "Expected 'entry' in context, got: {:?}",
            func_names
        );
    }

    #[test]
    fn test_relevant_context_to_llm_string() {
        let ctx = RelevantContext {
            entry_point: "main".to_string(),
            depth: 1,
            functions: vec![
                FunctionContext {
                    name: "main".to_string(),
                    file: PathBuf::from("src/main.py"),
                    line: 10,
                    signature: "def main()".to_string(),
                    docstring: Some("Entry point".to_string()),
                    calls: vec!["helper".to_string()],
                    blocks: Some(3),
                    cyclomatic: Some(2),
                },
                FunctionContext {
                    name: "helper".to_string(),
                    file: PathBuf::from("src/utils.py"),
                    line: 5,
                    signature: "def helper(x: int) -> str".to_string(),
                    docstring: None,
                    calls: vec![],
                    blocks: Some(1),
                    cyclomatic: Some(1),
                },
            ],
        };

        let output = ctx.to_llm_string();
        assert!(output.contains("main"));
        assert!(output.contains("helper"));
        assert!(output.contains("Entry point"));
        assert!(output.contains("depth=1"));
    }

    #[test]
    fn test_build_signature_python() {
        let func = FunctionInfo {
            name: "process".to_string(),
            params: vec!["x: int".to_string(), "y: str".to_string()],
            return_type: Some("bool".to_string()),
            docstring: None,
            is_method: false,
            is_async: false,
            decorators: vec![],
            visibility: None,
            line_number: 1,
            line_end: 1,
            state_mutability: None,
        };

        let sig = build_signature(&func, Language::Python);
        assert_eq!(sig, "def process(x: int, y: str) -> bool");
    }

    #[test]
    fn test_build_signature_async() {
        let func = FunctionInfo {
            name: "fetch".to_string(),
            params: vec!["url: str".to_string()],
            return_type: Some("Response".to_string()),
            docstring: None,
            is_method: false,
            is_async: true,
            decorators: vec![],
            visibility: None,
            line_number: 1,
            line_end: 1,
            state_mutability: None,
        };

        let sig = build_signature(&func, Language::Python);
        assert_eq!(sig, "async def fetch(url: str) -> Response");
    }

    #[test]
    fn test_bfs_collect_empty_graph() {
        let graph = ProjectCallGraph::new();
        let entry = (PathBuf::from("main.py"), "main".to_string());
        let result = bfs_collect_functions(&graph, &entry, 5);
        // Entry point should always be included even if graph is empty
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, "main");
    }

    /// Test that the `file_filter` parameter disambiguates functions with the same name
    /// across different files. When two files both define `render`, passing a file filter
    /// should select only the function from the specified file.
    #[test]
    fn test_file_filter_disambiguates_same_function_name() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project = temp_dir.path();

        // Create two files that each define a function called "render"
        let shortcuts_py = r#"def render(request, template_name):
    """Shortcut render function."""
    return load_template(template_name)

def load_template(name):
    """Load a template by name."""
    return name
"#;

        let backends_py = r#"def render(template, context):
    """Backend render function."""
    return compile_template(template)

def compile_template(template):
    """Compile a template."""
    return template
"#;

        // Place in subdirectories to simulate django-like structure
        fs::create_dir_all(project.join("django")).unwrap();
        fs::write(project.join("django/shortcuts.py"), shortcuts_py).unwrap();
        fs::create_dir_all(project.join("django/template/backends")).unwrap();
        fs::write(
            project.join("django/template/backends/django.py"),
            backends_py,
        )
        .unwrap();

        // Without file_filter: should find *some* render (current behavior)
        let result_any = get_relevant_context(
            project,
            "render",
            1,
            Language::Python,
            false,
            None, // no file filter
        );
        assert!(
            result_any.is_ok(),
            "get_relevant_context without filter failed: {:?}",
            result_any.err()
        );
        let ctx_any = result_any.unwrap();
        assert!(
            !ctx_any.functions.is_empty(),
            "Expected non-empty functions without filter"
        );

        // With file_filter: select the render from django/shortcuts.py specifically
        let result_shortcuts = get_relevant_context(
            project,
            "render",
            1,
            Language::Python,
            false,
            Some(Path::new("django/shortcuts.py")),
        );
        assert!(
            result_shortcuts.is_ok(),
            "get_relevant_context with shortcuts filter failed: {:?}",
            result_shortcuts.err()
        );
        let ctx_shortcuts = result_shortcuts.unwrap();
        assert!(
            !ctx_shortcuts.functions.is_empty(),
            "Expected non-empty functions with shortcuts filter"
        );

        // The entry point should be from django/shortcuts.py
        let entry_func = &ctx_shortcuts.functions[0];
        assert_eq!(entry_func.name, "render");
        assert!(
            entry_func.file.ends_with("django/shortcuts.py"),
            "Expected render from django/shortcuts.py, got: {}",
            entry_func.file.display()
        );

        // With depth=1, should also include load_template (callee of shortcuts.render)
        let callee_names: Vec<&str> = ctx_shortcuts
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            callee_names.contains(&"load_template"),
            "Expected callee 'load_template' from shortcuts, got: {:?}",
            callee_names
        );
        // Should NOT contain compile_template (that's in the backends file)
        assert!(
            !callee_names.contains(&"compile_template"),
            "Should not contain 'compile_template' from backends when filtering to shortcuts"
        );

        // With file_filter: select the render from django/template/backends/django.py
        let result_backends = get_relevant_context(
            project,
            "render",
            1,
            Language::Python,
            false,
            Some(Path::new("django/template/backends/django.py")),
        );
        assert!(
            result_backends.is_ok(),
            "get_relevant_context with backends filter failed: {:?}",
            result_backends.err()
        );
        let ctx_backends = result_backends.unwrap();
        let backend_entry = &ctx_backends.functions[0];
        assert_eq!(backend_entry.name, "render");
        assert!(
            backend_entry
                .file
                .ends_with("django/template/backends/django.py"),
            "Expected render from backends/django.py, got: {}",
            backend_entry.file.display()
        );

        // Should include compile_template but NOT load_template
        let backend_names: Vec<&str> = ctx_backends
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            backend_names.contains(&"compile_template"),
            "Expected callee 'compile_template' from backends, got: {:?}",
            backend_names
        );
        assert!(
            !backend_names.contains(&"load_template"),
            "Should not contain 'load_template' from shortcuts when filtering to backends"
        );
    }

    /// Test that file_filter works with a nonexistent file path and returns FunctionNotFound
    #[test]
    fn test_file_filter_nonexistent_file_returns_error() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project = temp_dir.path();

        let main_py = r#"def render():
    """A render function."""
    pass
"#;
        fs::write(project.join("main.py"), main_py).unwrap();

        // Filter to a file that doesn't contain render
        let result = get_relevant_context(
            project,
            "render",
            0,
            Language::Python,
            false,
            Some(Path::new("nonexistent.py")),
        );

        assert!(
            result.is_err(),
            "Expected FunctionNotFound error when filtering to nonexistent file"
        );
    }

    /// cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #48 (Python).
    ///
    /// `get_cfg_metrics(file, "Alpha.process", Python)` must return the
    /// CFG blocks of `Alpha.process` — not the first source-order bare
    /// `process` (which would be `Beta.process`, complex).
    ///
    /// Pre-fix stripped `Alpha.` and looked up bare `process`, matching
    /// Beta's CFG (~14 blocks). Cyclomatic was unaffected because
    /// `calculate_complexity` already accepted the qualified
    /// `Alpha.process` form (yielding 1) — so the two metrics
    /// disagreed for the same record.
    #[test]
    fn test_48_python_get_cfg_metrics_qualified_method() {
        use std::fs;
        use tempfile::TempDir;

        let src = "\
class Beta:
    def process(self):
        a = 1
        if a > 0:
            if a > 1:
                if a > 2:
                    a += 1
        while a < 100:
            a += 1

class Alpha:
    def process(self):
        x = 1
        return
";
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("ctx48.py");
        fs::write(&file, src).unwrap();

        let (blocks, cyclomatic) = get_cfg_metrics(&file, "Alpha.process", Language::Python);

        let blocks = blocks.expect("expected `blocks` Some for Alpha.process");
        let cyclomatic = cyclomatic.expect("expected `cyclomatic` Some for Alpha.process");

        assert_eq!(
            cyclomatic, 1,
            "expected cyclomatic=1 for Alpha.process; got {}",
            cyclomatic
        );
        assert!(
            blocks < 10,
            "expected `blocks` < 10 for Alpha.process; got {} \
             (bare-name fallback hit Beta.process). cyclomatic={}.",
            blocks,
            cyclomatic
        );
    }

    /// cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #48 (C++ guard).
    #[test]
    fn test_48_cpp_get_cfg_metrics_qualified_method() {
        use std::fs;
        use tempfile::TempDir;

        let src = "class Beta {\n\
            public:\n\
                void process() {\n\
                    int a = 1;\n\
                    if (a > 0) {\n\
                        if (a > 1) {\n\
                            if (a > 2) {\n\
                                a++;\n\
                            }\n\
                        }\n\
                    }\n\
                    while (a < 100) {\n\
                        a++;\n\
                    }\n\
                }\n\
            };\n\
            \n\
            class Alpha {\n\
            public:\n\
                void process() {\n\
                    int x = 1;\n\
                    return;\n\
                }\n\
            };\n";
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("ctx48.cpp");
        fs::write(&file, src).unwrap();

        let (blocks, cyclomatic) = get_cfg_metrics(&file, "Alpha::process", Language::Cpp);

        let blocks = blocks.expect("expected `blocks` Some for Alpha::process");
        let cyclomatic = cyclomatic.expect("expected `cyclomatic` Some for Alpha::process");

        assert_eq!(cyclomatic, 1);
        assert!(blocks < 10, "got blocks={} (regressing cpp `::` path)", blocks);
    }

    /// cpp-python-ast-issues-v1 (v0.4.2 M-106) — `split_qualified_last_segment` helper.
    #[test]
    fn test_split_qualified_last_segment_unit() {
        assert_eq!(
            split_qualified_last_segment("Alpha::process", Language::Cpp),
            "process"
        );
        assert_eq!(
            split_qualified_last_segment("a::b::c", Language::Rust),
            "c"
        );
        assert_eq!(
            split_qualified_last_segment("plain", Language::Cpp),
            "plain"
        );
        assert_eq!(
            split_qualified_last_segment("Alpha.process", Language::Python),
            "process"
        );
        assert_eq!(
            split_qualified_last_segment("Mod.Class.method", Language::Python),
            "method"
        );
        assert_eq!(
            split_qualified_last_segment("bare", Language::Python),
            "bare"
        );
    }
}
