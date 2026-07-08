//! Context command - Build LLM context
//!
//! Generates token-efficient LLM context from an entry point.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;

use tldr_core::callgraph::{confidence_tier, ResolutionRung};
use tldr_core::types::RelevantContext as TypesRelevantContext;
use tldr_core::{
    build_project_call_graph, extract_file, get_relevant_context, ContextCallEdge,
    ContextEdgeProvenance, FunctionContext, Language, RelevantContext,
};

use crate::commands::calls::{parse_min_confidence, MinConfidence};
use crate::commands::daemon_router::{params_with_entry_depth, try_daemon_route};
use crate::output::{OutputFormat, OutputWriter};

/// Build LLM-ready context from entry point
#[derive(Debug, Args)]
pub struct ContextArgs {
    /// Entry point function name
    pub entry: String,

    /// Project root directory as positional argument (mirrors sibling
    /// path-taking commands like `impact`, `whatbreaks`). When set, this
    /// takes precedence over `--project`. (med-cleanup-bundle-v1 / M1)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Project root directory (deprecated alias for the positional path
    /// argument; kept for back-compat). (med-cleanup-bundle-v1 / M1)
    #[arg(long, short = 'p')]
    pub project: Option<PathBuf>,

    /// Programming language
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum traversal depth
    #[arg(long, short = 'd', default_value = "3")]
    pub depth: usize,

    /// Include function docstrings
    #[arg(long)]
    pub include_docstrings: bool,

    /// Filter to functions in this file (for disambiguating common names like "render")
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Minimum confidence tier to traverse: T2 includes all edges, T1 drops T2 guesses, T0 is reserved.
    #[arg(long, default_value = "T2", value_parser = parse_min_confidence)]
    pub(crate) min_confidence: MinConfidence,
}

impl ContextArgs {
    /// Resolve the effective project path. The positional `path` argument
    /// is the canonical input; `--project` is kept as a back-compat alias
    /// and only wins when the positional path is left at its default ".".
    /// (med-cleanup-bundle-v1 / M1)
    fn effective_project(&self) -> PathBuf {
        match &self.project {
            Some(p) if self.path == PathBuf::from(".") => p.clone(),
            _ => self.path.clone(),
        }
    }

    /// Run the context command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        let mut project_path = self.effective_project();

        // language-adapter-fixes-v1 (P13.AGG13-5) /
        // context-file-func-cross-lang-and-cpp-qualified-v1 (P14.AGG13-5,
        // AGG14-8): accept the `<file>:<func>` shorthand so users can
        // disambiguate common function names without typing `--file`
        // separately. The shape mirrors `tldr explain <file> <func>` and
        // `tldr resources <file> <func>`.
        //
        // We walk colons RIGHT-TO-LEFT and pick the leftmost split whose
        // file_part exists on disk. The legacy single-rfind form failed
        // for C++ qualified names because
        // `path/x.cpp:XMLDocument::Parse`'s last `:` lands inside `::`,
        // leaving file_part = `path/x.cpp:XMLDocument:` which is not a
        // file. Walking colons backward fixes this: the second-to-last
        // colon yields file_part = `path/x.cpp` (valid file) and
        // func_part = `XMLDocument::Parse` — the form the per-function
        // lookup now accepts (P14.AGG14-3 in `find_function_node`).
        // Windows drive letters (`C:\foo\bar.js:foo`) keep working
        // because the leftmost split where `C:\foo\bar.js` is a file
        // wins (the earlier `C:` split returns a non-file).
        let (entry, derived_file): (String, Option<PathBuf>) =
            match split_file_func_shorthand(&self.entry) {
                Some((file, func)) => (func, Some(file)),
                None => (self.entry.clone(), None),
            };

        // cl16-arg-ergonomics-v1 (v0.5.0 CL-16): `context` expects a function
        // ENTRY, not a file path. When the user hands us a bare existing file
        // path (no `<file>:<func>` split was found, and no explicit `--file`),
        // the lookup downstream would fail with the misleading
        // "Function not found: <path>" plus a junk block of fuzzy
        // function-name suggestions. Detect the confusion up-front and emit a
        // clear, actionable hint instead: tell the user `context` wants a
        // function name and show the `<file>:<func>` shorthand that scopes to
        // that file. We only trip when the positional arg literally resolves
        // to a regular file on disk, so genuine function names (including
        // qualified `Module::Sub::fn` names) are never affected.
        if derived_file.is_none() && self.file.is_none() {
            let as_path = Path::new(&entry);
            if as_path.is_file() {
                anyhow::bail!(
                    "context expects a function name, but '{}' is a file. \
                     Pass a function name (e.g. `tldr context my_function`), or scope to a \
                     function in that file with the `<file>:<func>` shorthand \
                     (e.g. `tldr context {}:my_function`) or the `--file` flag.",
                    entry,
                    entry
                );
            }
        }

        // The user-supplied --file (if any) wins over the derived form so
        // explicit flags always take precedence over inferred shorthands.
        let effective_file: Option<PathBuf> = self.file.clone().or_else(|| derived_file.clone());

        // Auto-derive project root from file when shorthand was used and
        // the user didn't supply an explicit one. Honour `.git` /
        // `package.json` / `Cargo.toml` markers; otherwise fall back to
        // the file's immediate parent directory. This keeps the
        // shorthand useful from any cwd.
        if derived_file.is_some() && self.path == PathBuf::from(".") && self.project.is_none() {
            if let Some(file) = effective_file.as_ref() {
                if let Some(root) = infer_project_root_from_file(file) {
                    project_path = root;
                }
            }
        }

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&project_path).unwrap_or(Language::Python));

        // Try daemon first for cached result. Only route through the
        // daemon when there is no derived-file disambiguation, since the
        // daemon protocol does not currently propagate the `--file`
        // filter (would silently ignore the disambiguator).
        if effective_file.is_none() && self.min_confidence == MinConfidence::T2 {
            if let Some(context) = try_daemon_route::<TypesRelevantContext>(
                &project_path,
                "context",
                params_with_entry_depth(&entry, Some(self.depth)),
            ) {
                // Output based on format
                if writer.is_text() {
                    // Use the built-in LLM string format
                    let text = context.to_llm_string();
                    writer.write_text(&text)?;
                    return Ok(());
                } else {
                    writer.write(&context)?;
                    return Ok(());
                }
            }
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Building context for {} (depth={})...",
            entry, self.depth
        ));

        // Get relevant context. Strict confidence filters must be applied to
        // graph traversal itself, so those paths rebuild from the call graph.
        let mut context = if self.min_confidence == MinConfidence::T2 {
            get_relevant_context(
                &project_path,
                &entry,
                self.depth,
                language,
                self.include_docstrings,
                effective_file.as_deref(),
            )?
        } else {
            build_context_from_call_graph(
                &project_path,
                &entry,
                self.depth,
                language,
                self.include_docstrings,
                effective_file.as_deref(),
                self.min_confidence,
            )
            .unwrap_or_else(|| RelevantContext {
                entry_point: entry.clone(),
                depth: self.depth,
                functions: vec![],
            })
        };

        // c3-context-neighborhood-v1 (v0.5.0 AUDIT-FIX, C3 gap-c): for some
        // languages (Lua/Luau nested `local function`s; Swift cross-file
        // `Type.method` definitions) the core builder's BFS collapses to a
        // degenerate result — it returns the bare entry only, or even an
        // unrelated function — because its entry resolution / per-node
        // verification goes through `extract_file`, which does NOT surface
        // nested local functions or reconcile the call graph's cross-file
        // `Type.method` keys. The PROJECT call graph (post Wave-2/5) DOES carry
        // those edges. When the standard result is degenerate, rebuild the
        // neighborhood directly from the call graph: locate the entry among the
        // graph's edges, BFS the forward edges to `depth`, and synthesize one
        // `FunctionContext` per reached node with its `calls` populated from the
        // graph. Signatures/line numbers are filled best-effort from
        // `extract_file`; the call-relationship neighborhood is the load-bearing
        // output and always reflects the working call graph.
        if context_is_degenerate(&context, &entry) {
            if let Some(rebuilt) = build_context_from_call_graph(
                &project_path,
                &entry,
                self.depth,
                language,
                self.include_docstrings,
                effective_file.as_deref(),
                self.min_confidence,
            ) {
                if rebuilt.functions.len() > context.functions.len() {
                    context = rebuilt;
                }
            }
        }

        // scala-path-canonical-v1 (v0.4.1 bug-C): preserve the user's
        // input path shape for the entry-point function's `file:` field.
        // `get_relevant_context` -> `build_function_context` strips the
        // project prefix (crates/tldr-core/src/context/builder.rs:823),
        // so a user who typed
        //   `tldr context /tmp/repos/.../X.scala:apply`
        // would see `functions[0].file = "core/.../X.scala"` (drifted
        // shape). Per the P15-B precedent (`6a3288a
        // context-relative-and-ts-colon-v1`), echo the user's input
        // verbatim in output: when the entry-point function's file
        // matches the user-supplied file (by canonical equality or
        // suffix), substitute the user-supplied shape back in.
        if let Some(user_input) = effective_file.as_ref() {
            restore_user_input_shape(&mut context, user_input);
        }
        annotate_context_from_call_graph(
            &mut context,
            &project_path,
            language,
            self.min_confidence,
        );

        // Output based on format
        if writer.is_text() {
            // Use the built-in LLM string format
            let text = context.to_llm_string();
            writer.write_text(&text)?;
        } else {
            writer.write(&context)?;
        }

        Ok(())
    }
}

/// Restore the user's input path shape on every `functions[].file` whose
/// extracted form refers to the same file on disk as `user_input`.
///
/// scala-path-canonical-v1 (v0.4.1 bug-C): we accept either an exact
/// suffix match (so a relative call-graph key like
/// `core/shared/.../X.scala` agrees with a user-supplied absolute
/// `/tmp/repos/.../X.scala`) OR a canonicalised-path equality (to
/// reconcile macOS `/tmp` ↔ `/private/tmp` and any other symlink dance).
/// Canonicalisation is used ONLY for the comparison; the field we write
/// back to is the user's verbatim input.
fn restore_user_input_shape(context: &mut RelevantContext, user_input: &Path) {
    let user_canon = user_input.canonicalize().ok();
    for func in context.functions.iter_mut() {
        let emitted = &func.file;
        let matches = user_input.ends_with(emitted)
            || emitted.ends_with(user_input)
            || match (user_canon.as_ref(), emitted.canonicalize().ok().as_ref()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
        if matches {
            func.file = user_input.to_path_buf();
        }
    }
}

/// Parse the `<file>:<func>` shorthand argument into a `(file_path,
/// func_name)` pair, walking colons right-to-left to find the leftmost
/// split point whose file_part exists on disk.
///
/// context-file-func-cross-lang-and-cpp-qualified-v1
/// (P14.AGG13-5 / AGG14-3): the legacy `rfind(':')` form failed for
/// names that themselves contain `:` (notably C++ `Class::method`).
/// For input `path/x.cpp:XMLDocument::Parse` we now try the rightmost
/// colon first (file_part = `path/x.cpp:XMLDocument:`, not a file →
/// reject), then the next colon (file_part = `path/x.cpp`, valid →
/// accept) and emit func_part = `XMLDocument::Parse`. This keeps
/// Windows drive-letter paths working (`C:\foo\bar.js:foo` returns the
/// `C:\foo\bar.js` split because the earlier `C:` split is not a file).
///
/// Returns `None` when no split is valid; callers fall back to the
/// bare-name interpretation for genuine names containing `:` like
/// `Module::Sub::fn` invoked without a file prefix.
fn split_file_func_shorthand(entry: &str) -> Option<(PathBuf, String)> {
    let mut idx = entry.rfind(':')?;
    loop {
        if idx == 0 || idx + 1 >= entry.len() {
            // Search further-left colons (idx==0 means leading ':').
            match entry[..idx].rfind(':') {
                Some(prev) => {
                    idx = prev;
                    continue;
                }
                None => return None,
            }
        }
        let file_part = &entry[..idx];
        let func_part = &entry[idx + 1..];
        // func_part starts with `:` => we landed inside a `::` group;
        // the next iteration will move further left, but the candidate
        // file_part is also invalid as a file in that case (ends with
        // `:`), so a single `is_file()` check correctly rejects it.
        let candidate = PathBuf::from(file_part);
        if candidate.is_file() && !func_part.is_empty() && !func_part.starts_with(':') {
            return Some((candidate, func_part.to_string()));
        }
        match entry[..idx].rfind(':') {
            Some(prev) => idx = prev,
            None => return None,
        }
    }
}

/// Walk upward from `file`'s parent directory until we hit a directory
/// containing one of the common project-root markers (`.git`,
/// `package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`,
/// `pom.xml`, `build.gradle*`, `*.csproj`, `mix.exs`, `dune-project`).
/// Returns `Some(parent_dir)` as a fallback if no marker is found.
///
/// language-adapter-fixes-v1 (P13.AGG13-5): used by the context command
/// when the user invokes the `<file>:<func>` shorthand without an
/// explicit project path. Lets `tldr context /path/to/repo/src/x.js:foo`
/// resolve from any cwd, mirroring `cd /path/to/repo && tldr context foo`.
fn infer_project_root_from_file(file: &Path) -> Option<PathBuf> {
    let abs = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    let parent = abs.parent()?;
    const MARKERS: &[&str] = &[
        ".git",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "mix.exs",
        "dune-project",
        "Package.swift",
    ];
    let mut cursor: Option<&Path> = Some(parent);
    while let Some(dir) = cursor {
        for m in MARKERS {
            if dir.join(m).exists() {
                return Some(dir.to_path_buf());
            }
        }
        // Also accept any *.csproj sibling (C# projects).
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "csproj" || e == "sln")
                    .unwrap_or(false)
                {
                    return Some(dir.to_path_buf());
                }
            }
        }
        cursor = dir.parent();
    }
    Some(parent.to_path_buf())
}

/// c3-context-neighborhood-v1 (v0.5.0 AUDIT-FIX, C3 gap-c): decide whether the
/// core `get_relevant_context` result is degenerate and warrants a
/// call-graph-driven rebuild.
///
/// A result is degenerate when EITHER:
///   - it contains no function whose name matches `entry` (the BFS landed on an
///     unrelated function because entry resolution failed — observed for Lua
///     nested `local function`s where the result is some other top-level
///     function), OR
///   - it contains the entry but with an EMPTY `calls` list while collapsing to
///     a single function (no neighborhood expanded at all — observed for Swift
///     cross-file `Type.method` entries).
///
/// Name matching is last-segment aware so a graph key `Type.method` / a bare
/// `method` reconcile with the user-typed entry.
fn context_is_degenerate(context: &RelevantContext, entry: &str) -> bool {
    let entry_leaf = last_segment(entry);
    let entry_fn = context
        .functions
        .iter()
        .find(|f| name_matches(&f.name, entry, entry_leaf));
    match entry_fn {
        None => true,
        Some(f) => context.functions.len() <= 1 && f.calls.is_empty(),
    }
}

/// Last `.`/`::`-separated segment of a (possibly qualified) name.
fn last_segment(name: &str) -> &str {
    name.rsplit(['.', ':']).next().unwrap_or(name)
}

/// Whether `candidate` names the same function as the user-typed `entry`,
/// tolerant of qualifier shape on either side (`Type.method` vs bare `method`).
fn name_matches(candidate: &str, entry: &str, entry_leaf: &str) -> bool {
    candidate == entry
        || last_segment(candidate) == entry_leaf
        || candidate == entry_leaf
        || last_segment(candidate) == entry
}

#[derive(Clone)]
struct ContextGraphEdge {
    dst_file: std::path::PathBuf,
    dst_func: String,
    call_line: Option<u32>,
    rung: ResolutionRung,
}

/// c3-context-neighborhood-v1 (v0.5.0 AUDIT-FIX, C3 gap-c): build a
/// [`RelevantContext`] for `entry` directly from the project call graph.
///
/// Locates the entry among the graph's edges (by exact or last-segment name
/// match, honouring an optional `file_filter`), BFS-traverses the forward
/// (caller -> callee) edges to `depth`, and synthesizes a `FunctionContext` per
/// reached `(file, func)` node. Each node's `calls` is the set of its outgoing
/// callee names from the graph. Signature / line / docstring are filled
/// best-effort from `extract_file` (works for top-level functions and class
/// methods; nested locals fall back to a name-only signature). Returns `None`
/// when the graph has no node matching `entry` (the caller then keeps the
/// original — possibly empty — result).
fn build_context_from_call_graph(
    project: &std::path::Path,
    entry: &str,
    depth: usize,
    language: Language,
    include_docstrings: bool,
    file_filter: Option<&Path>,
    min_confidence: MinConfidence,
) -> Option<RelevantContext> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let graph = build_project_call_graph(project, language, None, true).ok()?;
    let entry_leaf = last_segment(entry);

    let file_ok = |f: &std::path::Path| -> bool {
        match file_filter {
            None => true,
            Some(filter) => f.ends_with(filter) || filter.ends_with(f),
        }
    };

    // Forward adjacency keyed by (file, func) -> ordered set of (callee names).
    // Keep a parallel map of node -> outgoing callee NAME list for `calls`.
    let mut forward: BTreeMap<(std::path::PathBuf, String), Vec<ContextGraphEdge>> =
        BTreeMap::new();
    let mut graph_edges: Vec<_> = graph.edges().cloned().collect();
    graph_edges.sort_by(|a, b| {
        a.src_file
            .cmp(&b.src_file)
            .then_with(|| a.src_func.cmp(&b.src_func))
            .then_with(|| a.dst_file.cmp(&b.dst_file))
            .then_with(|| a.dst_func.cmp(&b.dst_func))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
    for edge in &graph_edges {
        let rung = graph
            .edge_rung(edge)
            .unwrap_or(ResolutionRung::LocalFunction);
        if !min_confidence.includes_optional_rung(Some(rung)) {
            continue;
        }
        forward
            .entry((edge.src_file.clone(), edge.src_func.clone()))
            .or_default()
            .push(ContextGraphEdge {
                dst_file: edge.dst_file.clone(),
                dst_func: edge.dst_func.clone(),
                call_line: edge.call_line,
                rung,
            });
    }

    // Find the entry node among the graph's callers (nodes WITH outgoing
    // edges). Prefer an EXACT name match over a last-segment match so a
    // qualified `Deque.init` entry is not captured by some bare `init` node.
    let mut exact_node: Option<(std::path::PathBuf, String)> = None;
    let mut fuzzy_node: Option<(std::path::PathBuf, String)> = None;
    for (key, _callees) in forward.iter() {
        let (file, func) = key;
        if !file_ok(file) {
            continue;
        }
        if func == entry {
            exact_node = Some(key.clone());
            break;
        }
        if fuzzy_node.is_none() && name_matches(func, entry, entry_leaf) {
            fuzzy_node = Some(key.clone());
        }
    }
    // If not found as a caller, accept it as a callee (leaf) so we at least
    // anchor the neighborhood — though with no outgoing edges the result would
    // be a single node, which the caller will reject in favour of the original.
    if exact_node.is_none() && fuzzy_node.is_none() {
        for edge in &graph_edges {
            if !min_confidence.includes_optional_rung(graph.edge_rung(edge)) {
                continue;
            }
            if name_matches(&edge.dst_func, entry, entry_leaf) && file_ok(&edge.dst_file) {
                fuzzy_node = Some((edge.dst_file.clone(), edge.dst_func.clone()));
                break;
            }
        }
    }
    let entry_node = exact_node.or(fuzzy_node)?;

    // BFS forward to `depth`, collecting nodes in discovery order.
    let mut visited: BTreeSet<(std::path::PathBuf, String)> = BTreeSet::new();
    let mut ordered: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut incoming: BTreeMap<(std::path::PathBuf, String), ResolutionRung> = BTreeMap::new();
    let mut queue: VecDeque<((std::path::PathBuf, String), usize)> = VecDeque::new();
    queue.push_back((entry_node.clone(), 0));
    visited.insert(entry_node.clone());
    while let Some((node, d)) = queue.pop_front() {
        ordered.push(node.clone());
        if d >= depth {
            continue;
        }
        if let Some(edges) = forward.get(&node) {
            for edge in edges {
                let callee = (edge.dst_file.clone(), edge.dst_func.clone());
                if visited.insert(callee.clone()) {
                    incoming.entry(callee.clone()).or_insert(edge.rung);
                    queue.push_back((callee, d + 1));
                }
            }
        }
    }

    // Synthesize FunctionContext per node.
    let mut functions: Vec<FunctionContext> = Vec::new();
    let mut module_cache: std::collections::HashMap<
        std::path::PathBuf,
        tldr_core::types::ModuleInfo,
    > = std::collections::HashMap::new();
    for (file, func) in &ordered {
        // Distinct, sorted callee NAMES for this node.
        let mut calls: Vec<String> = forward
            .get(&(file.clone(), func.clone()))
            .map(|v| v.iter().map(|edge| edge.dst_func.clone()).collect())
            .unwrap_or_default();
        calls.sort();
        calls.dedup();

        let (signature, line, docstring) = {
            let module = cached_module(&mut module_cache, project, file, language);
            lookup_signature(module, func, include_docstrings)
        };
        let call_edges: Vec<ContextCallEdge> = forward
            .get(&(file.clone(), func.clone()))
            .map(|edges| {
                edges
                    .iter()
                    .map(|edge| context_call_edge(project, language, &mut module_cache, edge))
                    .collect()
            })
            .unwrap_or_default();
        let (confidence, provenance) = incoming
            .get(&(file.clone(), func.clone()))
            .map(|rung| {
                (
                    Some(confidence_tier(*rung).as_str().to_string()),
                    Some(ContextEdgeProvenance {
                        rung: rung.id().to_string(),
                        mechanism: rung.mechanism().to_string(),
                    }),
                )
            })
            .unwrap_or((None, None));

        functions.push(FunctionContext {
            name: func.clone(),
            file: file.clone(),
            line,
            signature,
            docstring,
            calls,
            call_edges,
            confidence,
            provenance,
            blocks: None,
            cyclomatic: None,
        });
    }

    Some(RelevantContext {
        entry_point: entry.to_string(),
        depth,
        functions,
    })
}

fn empty_module_info(file: &Path, language: Language) -> tldr_core::types::ModuleInfo {
    tldr_core::types::ModuleInfo {
        file_path: file.to_path_buf(),
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
}

fn cached_module<'a>(
    module_cache: &'a mut std::collections::HashMap<
        std::path::PathBuf,
        tldr_core::types::ModuleInfo,
    >,
    project: &Path,
    file: &Path,
    language: Language,
) -> &'a tldr_core::types::ModuleInfo {
    let key = file.to_path_buf();
    let full_path = if file.is_relative() {
        project.join(file)
    } else {
        file.to_path_buf()
    };
    module_cache.entry(key.clone()).or_insert_with(|| {
        extract_file(&full_path, Some(project))
            .unwrap_or_else(|_| empty_module_info(&key, language))
    })
}

fn context_call_edge(
    project: &Path,
    language: Language,
    module_cache: &mut std::collections::HashMap<std::path::PathBuf, tldr_core::types::ModuleInfo>,
    edge: &ContextGraphEdge,
) -> ContextCallEdge {
    let dst_line = {
        let module = cached_module(module_cache, project, &edge.dst_file, language);
        let (_, line, _) = lookup_signature(module, &edge.dst_func, false);
        line
    };
    ContextCallEdge {
        dst_file: edge.dst_file.clone(),
        dst_func: edge.dst_func.clone(),
        dst_line,
        call_line: edge.call_line,
        confidence: confidence_tier(edge.rung).as_str().to_string(),
        provenance: ContextEdgeProvenance {
            rung: edge.rung.id().to_string(),
            mechanism: edge.rung.mechanism().to_string(),
        },
    }
}

fn context_path_matches(a: &Path, b: &Path) -> bool {
    a == b || a.ends_with(b) || b.ends_with(a)
}

fn context_node_matches(
    context_file: &Path,
    context_name: &str,
    edge_file: &Path,
    edge_name: &str,
) -> bool {
    context_path_matches(context_file, edge_file)
        && name_matches(context_name, edge_name, last_segment(edge_name))
}

fn annotate_context_from_call_graph(
    context: &mut RelevantContext,
    project: &Path,
    language: Language,
    min_confidence: MinConfidence,
) {
    let Ok(graph) = build_project_call_graph(project, language, None, true) else {
        return;
    };
    let mut graph_edges: Vec<_> = graph.edges().cloned().collect();
    graph_edges.sort_by(|a, b| {
        a.src_file
            .cmp(&b.src_file)
            .then_with(|| a.src_func.cmp(&b.src_func))
            .then_with(|| a.dst_file.cmp(&b.dst_file))
            .then_with(|| a.dst_func.cmp(&b.dst_func))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
    let mut module_cache: std::collections::HashMap<
        std::path::PathBuf,
        tldr_core::types::ModuleInfo,
    > = std::collections::HashMap::new();

    for func in context.functions.iter_mut() {
        func.call_edges.clear();
        for edge in &graph_edges {
            let rung = graph
                .edge_rung(edge)
                .unwrap_or(ResolutionRung::LocalFunction);
            if !min_confidence.includes_optional_rung(Some(rung)) {
                continue;
            }
            if context_node_matches(&func.file, &func.name, &edge.src_file, &edge.src_func) {
                let detailed = ContextGraphEdge {
                    dst_file: edge.dst_file.clone(),
                    dst_func: edge.dst_func.clone(),
                    call_line: edge.call_line,
                    rung,
                };
                func.call_edges.push(context_call_edge(
                    project,
                    language,
                    &mut module_cache,
                    &detailed,
                ));
            }
            if func.confidence.is_none()
                && func.name != context.entry_point
                && context_node_matches(&func.file, &func.name, &edge.dst_file, &edge.dst_func)
            {
                func.confidence = Some(confidence_tier(rung).as_str().to_string());
                func.provenance = Some(ContextEdgeProvenance {
                    rung: rung.id().to_string(),
                    mechanism: rung.mechanism().to_string(),
                });
            }
        }
        func.call_edges.sort_by(|a, b| {
            a.dst_file
                .cmp(&b.dst_file)
                .then_with(|| a.dst_func.cmp(&b.dst_func))
                .then_with(|| a.call_line.cmp(&b.call_line))
        });
        func.call_edges.dedup_by(|a, b| {
            a.dst_file == b.dst_file
                && a.dst_func == b.dst_func
                && a.call_line == b.call_line
                && a.provenance.rung == b.provenance.rung
        });
    }
}

/// Best-effort signature/line/docstring lookup for `func` within an extracted
/// module. Matches top-level functions and class methods by exact name or last
/// segment (`Type.method`). Falls back to a name-only signature when the symbol
/// is not surfaced by extraction (e.g. a nested local function).
fn lookup_signature(
    module: &tldr_core::types::ModuleInfo,
    func: &str,
    include_docstrings: bool,
) -> (String, u32, Option<String>) {
    let leaf = last_segment(func);
    for f in &module.functions {
        if f.name == func || f.name == leaf {
            let sig = format!(
                "{}({}){}",
                f.name,
                f.params.join(", "),
                f.return_type
                    .as_ref()
                    .map(|t| format!(" -> {}", t))
                    .unwrap_or_default()
            );
            return (
                sig,
                f.line_number,
                if include_docstrings {
                    f.docstring.clone()
                } else {
                    None
                },
            );
        }
    }
    for c in &module.classes {
        for m in &c.methods {
            if m.name == func || m.name == leaf || format!("{}.{}", c.name, m.name) == func {
                let sig = format!(
                    "{}({}){}",
                    m.name,
                    m.params.join(", "),
                    m.return_type
                        .as_ref()
                        .map(|t| format!(" -> {}", t))
                        .unwrap_or_default()
                );
                return (
                    sig,
                    m.line_number,
                    if include_docstrings {
                        m.docstring.clone()
                    } else {
                        None
                    },
                );
            }
        }
    }
    (func.to_string(), 0, None)
}
