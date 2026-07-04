//! Inheritance analysis module for class hierarchy extraction
//!
//! This module provides class hierarchy extraction and analysis for:
//! - Python classes (with ABC, Protocol, metaclass support - A12)
//! - TypeScript classes and interfaces
//! - Go struct embedding (modeled as composition - A14)
//! - Rust trait impl blocks (A16)
//! - Java classes, interfaces, enums, and records
//! - Kotlin classes, interfaces, objects, and data classes
//! - Scala classes, traits, objects, and case classes
//! - Swift classes, protocols, structs, and enums
//! - C# classes, interfaces, and structs
//! - Ruby classes and modules
//! - PHP classes, interfaces, and traits
//!
//! # Architecture
//!
//! 1. Extract classes from source files using tree-sitter
//! 2. Build inheritance graph with edges for extends/implements/embeds
//! 3. Detect patterns: ABC/Protocol, mixins, diamonds
//! 4. Resolve external bases (stdlib vs project vs unresolved)
//!
//! # Mitigations Addressed
//!
//! - A2: Diamond detection using BFS + set intersection (O(|ancestors|) not O(n^3))
//! - A12: Python metaclass extraction via keywords
//! - A14: Go struct embedding as Embeds edges
//! - A16: Rust trait impl blocks as Implements edges
//! - A17: --depth without --class validation
//! - A19: DOT output escaping for special characters
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::inheritance::{extract_inheritance, InheritanceOptions};
//!
//! let options = InheritanceOptions::default();
//! let report = extract_inheritance(Path::new("src"), Some(Language::Python), &options)?;
//! println!("Found {} classes", report.count);
//! ```

pub mod cpp; // real-repo-fixes-v1 (P9.BUG-R4): C/C++ inheritance extraction
pub mod csharp;
pub mod elixir; // inheritance-walker-per-lang-v1 (M-039)
pub mod filter;
pub mod format;
pub mod go;
pub mod java;
pub mod kotlin;
pub mod lua; // inheritance-walker-per-lang-v1 (M-039)
pub mod ocaml; // inheritance-extends-vs-implements-ocaml-v1 (T3): OCaml class hierarchy
pub mod patterns;
pub mod php;
pub mod python;
pub mod resolve;
pub mod ruby;
pub mod rust;
pub mod scala;
pub mod solidity; // v0.5.0 SOL-005c: Solidity contract/interface/library inheritance
pub mod swift;
pub mod typescript;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use walkdir::WalkDir;

use crate::ast::parser::ParserPool;
use crate::error::TldrError;
use crate::types::{
    BaseResolution, InheritanceEdge, InheritanceGraph, InheritanceKind, InheritanceReport,
    Language,
};
use crate::TldrResult;

pub use filter::{filter_by_class, get_fuzzy_suggestions};
pub use format::{escape_dot_string, format_dot, format_text};
pub use patterns::{detect_abc_protocol, detect_diamonds, detect_mixins};
pub use resolve::{is_stdlib_class, resolve_base, PYTHON_STDLIB_CLASSES};

/// Options for inheritance analysis
#[derive(Debug, Clone, Default)]
pub struct InheritanceOptions {
    /// Filter to specific class (show ancestors + descendants)
    pub class_filter: Option<String>,
    /// Limit traversal depth (requires class_filter)
    pub depth: Option<usize>,
    /// Skip external base resolution
    pub no_external: bool,
    /// Skip ABC/mixin/diamond detection
    pub no_patterns: bool,
    /// Maximum nodes for DOT output (A39)
    pub max_nodes: Option<usize>,
    /// Cluster nodes by file in DOT output (A39)
    pub cluster_by_file: bool,
}

impl InheritanceOptions {
    /// Validate options - depth requires class_filter (A17)
    pub fn validate(&self) -> TldrResult<()> {
        if self.depth.is_some() && self.class_filter.is_none() {
            return Err(TldrError::InvalidArgs {
                arg: "--depth".to_string(),
                message: "--depth requires --class. Use --class <NAME> --depth N to limit traversal depth.".to_string(),
                suggestion: Some("To scan entire project without depth limit, omit --depth.".to_string()),
            });
        }
        Ok(())
    }
}

/// Main entry point for inheritance analysis
pub fn extract_inheritance(
    path: &Path,
    lang: Option<Language>,
    options: &InheritanceOptions,
) -> TldrResult<InheritanceReport> {
    // Validate options first (A17)
    options.validate()?;

    let start = Instant::now();
    let parser_pool = ParserPool::new();

    // inheritance-extends-vs-implements-ocaml-v1 (T3) — language selection.
    //
    // When the caller passes no explicit `--lang` and the target is a
    // DIRECTORY, scope the scan to the project's PRIMARY language FAMILY
    // instead of walking every file by per-file extension. Two failure modes
    // motivate this:
    //   * `ocaml-lwt` ships 129 vendored C interop stubs (`src/unix/unix_c/
    //     *.c`) alongside 114 OCaml source files. Per-file dispatch produced a
    //     hierarchy of 197 nodes ALL `language=c` — the OCaml class model was
    //     entirely masked by vendored C.
    //   * A genuinely balanced multi-language tree (1 Python + 1 Java + 1 TS)
    //     must still analyse ALL THREE (the CL-15 polyglot contract that the
    //     `test_multilang_inheritance_in_single_directory` test pins).
    //
    // `select_inheritance_languages` reconciles both — see its docs. An
    // explicit `--lang`, a single-file target, or a tree with no detectable
    // language all fall through to the prior (unfiltered) behaviour.
    let kept_langs: Option<HashSet<Language>> = if lang.is_none() && path.is_dir() {
        select_inheritance_languages(path)
    } else {
        None
    };

    // Collect files matching the explicit `--lang` filter (when given).
    let files = collect_source_files(path, lang);
    if files.is_empty() {
        return Ok(InheritanceReport::new(path.to_path_buf()));
    }

    // Build inheritance graph
    let mut graph = InheritanceGraph::new();
    let mut languages_seen = HashSet::new();

    for file_path in &files {
        // real-repo-fixes-v1 (P9.BUG-R4): use sibling-aware detection so a
        // `.h` header next to `.cpp` translation units is parsed with the
        // C++ grammar. Without this, tinyxml2.h (8 obvious public-inherit
        // relations) was treated as plain C and contributed zero edges.
        let file_lang = Language::from_path_with_siblings(file_path)
            .or_else(|| Language::from_path(file_path))
            .unwrap_or(Language::Python);

        // Skip if an explicit `--lang` filter is set and doesn't match.
        if let Some(filter_lang) = lang {
            if file_lang != filter_lang {
                continue;
            }
        }

        // inheritance-extends-vs-implements-ocaml-v1 (T3): on a no-`--lang`
        // directory scan, drop files outside the autodetected primary language
        // family so vendored interop files (C stubs in an OCaml repo) don't
        // stand in for the project's class model.
        if let Some(ref kept) = kept_langs {
            if !kept.contains(&file_lang) {
                continue;
            }
        }

        languages_seen.insert(file_lang);

        // Extract classes based on language
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue, // Skip unreadable files
        };

        let classes = match file_lang {
            Language::Python => python::extract_classes(&source, file_path, &parser_pool)?,
            Language::TypeScript | Language::JavaScript => {
                typescript::extract_classes(&source, file_path, &parser_pool)?
            }
            Language::Go => go::extract_classes(&source, file_path, &parser_pool)?,
            Language::Rust => rust::extract_classes(&source, file_path, &parser_pool)?,
            Language::Java => java::extract_classes(&source, file_path, &parser_pool)?,
            Language::Kotlin => kotlin::extract_classes(&source, file_path, &parser_pool)?,
            Language::Scala => scala::extract_classes(&source, file_path, &parser_pool)?,
            Language::Swift => swift::extract_classes(&source, file_path, &parser_pool)?,
            Language::CSharp => csharp::extract_classes(&source, file_path, &parser_pool)?,
            Language::Ruby => ruby::extract_classes(&source, file_path, &parser_pool)?,
            Language::Php => php::extract_classes(&source, file_path, &parser_pool)?,
            // real-repo-fixes-v1 (P9.BUG-R4): plug C/C++ inheritance.
            Language::Cpp => cpp::extract_classes(&source, file_path, &parser_pool)?,
            Language::C => cpp::extract_classes_c(&source, file_path, &parser_pool)?,
            // inheritance-walker-per-lang-v1 (M-039)
            Language::Elixir => elixir::extract_classes(&source, file_path, &parser_pool)?,
            // tldr-additive-fixes (T6a): route `.luau` through the shared
            // Lua/Luau walker. `lua::extract_classes` already selects the
            // tree-sitter-luau grammar by extension (see its docs and
            // `lua::tests::test_luau_extend_inheritance`); without this arm
            // `.luau` files fell through to `_ => Vec::new()` and returned an
            // empty hierarchy. Mirrors the `Language::Lua | Language::Luau`
            // pairing used in ast/extract.rs and ast/extractor.rs.
            Language::Lua | Language::Luau => {
                lua::extract_classes(&source, file_path, &parser_pool)?
            }
            // inheritance-extends-vs-implements-ocaml-v1 (T3): OCaml class /
            // class-type hierarchy (`class … inherit …`).
            Language::Ocaml => ocaml::extract_classes(&source, file_path, &parser_pool)?,
            // v0.5.0 SOL-005c (solidity-inheritance-v1): contract /
            // interface / library declarations with flattened
            // `is A, B` bases list. Declared order preserved; no C3
            // linearization in v1.
            Language::Solidity => solidity::extract_classes(&source, file_path, &parser_pool)?,
            _ => Vec::new(), // Unsupported language
        };

        // Add classes to graph
        for class in classes {
            let class_name = class.name.clone();
            let class_file = class.file.clone();
            let class_line = class.line;
            let bases = class.bases.clone();

            // Snapshot per-base kinds before move so each edge gets the
            // right kind from the parallel base_kinds vector.
            let base_kinds: Vec<crate::types::InheritanceKind> = (0..bases.len())
                .map(|i| class.base_kind_at(i))
                .collect();

            graph.add_node(class);

            // Add edges for each base — callgraph-dataflow-issues-v1
            // (#54): use the file/line-preserving variant so cross-file
            // same-named children don't collapse on top of each other.
            for (i, base) in bases.iter().enumerate() {
                graph.add_edge_with_file(
                    &class_name,
                    base,
                    class_file.clone(),
                    class_line,
                    base_kinds[i],
                );
            }
        }
    }

    // Resolve external bases unless disabled
    if !options.no_external {
        resolve::resolve_all_bases(&mut graph, path)?;
    }

    // Detect patterns unless disabled
    let diamonds = if options.no_patterns {
        Vec::new()
    } else {
        // Detect ABC/Protocol/Interface
        patterns::detect_abc_protocol(&mut graph);
        // Detect mixins
        patterns::detect_mixins(&mut graph);
        // Detect diamonds
        patterns::detect_diamonds(&graph)
    };

    // callgraph-dataflow-issues-v1 (#54): pattern detectors mutate the
    // bare-name `nodes` map (legacy API). Sync the pattern marks back
    // into `nodes_per_file` so consumers reading the per-file storage
    // see consistent `is_abstract` / `protocol` / `interface` / `mixin`
    // flags. Properties that depend on the file path (file, line, bases)
    // are preserved from the per-file copy; pattern-derived booleans are
    // overwritten from the bare-name copy.
    let bare_marks: HashMap<String, (Option<bool>, Option<bool>, Option<bool>, Option<bool>)> =
        graph
            .nodes
            .iter()
            .map(|(name, n)| {
                (
                    name.clone(),
                    (n.is_abstract, n.protocol, n.interface, n.mixin),
                )
            })
            .collect();
    for ((_, name), node) in graph.nodes_per_file.iter_mut() {
        if let Some(&(is_abs, proto, iface, mix)) = bare_marks.get(name) {
            node.is_abstract = is_abs;
            node.protocol = proto;
            node.interface = iface;
            node.mixin = mix;
        }
    }

    // Apply class filter if specified
    let filtered_graph = if let Some(ref class_name) = options.class_filter {
        filter::filter_by_class(&graph, class_name, options.depth)?
    } else {
        graph
    };

    // Build report — callgraph-dataflow-issues-v1 (#54): emit nodes from
    // `nodes_per_file` so cross-file same-named classes are preserved.
    // Falls back to the bare-name map when per-file storage is empty
    // (legacy graphs / synthetic tests).
    let mut report = InheritanceReport::new(path.to_path_buf());
    report.nodes = if !filtered_graph.nodes_per_file.is_empty() {
        filtered_graph.nodes_per_file.values().cloned().collect()
    } else {
        filtered_graph.nodes.values().cloned().collect()
    };
    report.count = report.nodes.len();
    report.languages = languages_seen.into_iter().collect();
    report.scan_time_ms = start.elapsed().as_millis() as u64;
    report.diamonds = diamonds;

    report.edges = build_edges(&filtered_graph, path);
    report.roots = filtered_graph.find_roots();
    report.leaves = filtered_graph.find_leaves();

    Ok(report)
}

/// Share denominator for the primary-language-family gate: a detected
/// language joins the family when its file count is at least
/// `dominant_count / PRIMARY_FAMILY_SHARE_DEN` (≥ 20%). Mirrors the constant
/// of the same purpose in `ast::extractor` (B3) so `inheritance` scopes a
/// polyglot tree the same way `structure`/`health` do.
const PRIMARY_FAMILY_SHARE_DEN: usize = 5;

/// inheritance-extends-vs-implements-ocaml-v1 (T3): choose the set of
/// languages to analyse on a no-`--lang` DIRECTORY scan.
///
/// Returns `Some(kept)` with the primary language family, or `None` when no
/// language is detectable (caller then leaves the scan unfiltered).
///
/// # Reconciling two requirements
///
/// 1. **Drop vendored interop.** `ocaml-lwt` carries 129 vendored C stub files
///    vs 114 OCaml source files: C wins a raw file-count vote, but the
///    `dune-project` / `*.opam` manifests make this *authoritatively* an OCaml
///    project. [`Language::from_directory`] (manifest-aware) returns `Ocaml`.
/// 2. **Keep genuine polyglot trees.** A balanced 1-Python/1-Java/1-TS tree
///    has no dominant language and no contradicting manifest; all three must
///    be analysed (the CL-15 contract).
///
/// # Algorithm
///
/// * `dominant_by_count` = the language with the most files (the raw vote).
/// * `manifest_primary` = [`Language::from_directory`] (manifest-aware vote).
/// * When they DIFFER, a manifest has overridden a vendored majority — scope
///   to `manifest_primary` ALONE (drops the vendored interloper). This is the
///   `ocaml-lwt` case: `{Ocaml}`, C excluded.
/// * When they AGREE (or no manifest distinction), use the B3 primary FAMILY:
///   the dominant plus every language whose file count is ≥ 20% of the
///   dominant's. A balanced tree has `dominant_count == 1`, threshold `0`, so
///   every language is kept — full polyglot. A 306-Java/33-JS tree keeps only
///   Java (the JS docs minority is below 20%).
///
/// The tree is walked once for the per-language file inventory (the same
/// `walk_project` + `from_path` inventory the detectors use).
fn select_inheritance_languages(path: &Path) -> Option<HashSet<Language>> {
    let detected = crate::ast::detect_project_languages(path);
    if detected.is_empty() {
        return None;
    }
    if detected.len() == 1 {
        return Some(detected.into_iter().collect());
    }

    // Per-language file counts (same walk the autodetectors use).
    let mut counts: HashMap<Language, usize> = HashMap::new();
    for entry in crate::walker::walk_project(path) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(l) = Language::from_path(p) {
            *counts.entry(l).or_insert(0) += 1;
        }
    }

    let dominant_by_count = counts
        .iter()
        .max_by(|a, b| {
            a.1.cmp(b.1)
                // Deterministic tie-break: lower Debug name wins, matching
                // `from_directory`'s ranking so the two agree on ties.
                .then_with(|| format!("{:?}", b.0).cmp(&format!("{:?}", a.0)))
        })
        .map(|(l, _)| *l);

    let manifest_primary = Language::from_directory(path);

    // Manifest override: the project's manifest names a primary language that
    // is NOT the raw file-count winner -> a vendored majority of another
    // language is masking it. Scope to the manifest language alone.
    if let (Some(mp), Some(dom)) = (manifest_primary, dominant_by_count) {
        if mp != dom && counts.get(&mp).copied().unwrap_or(0) > 0 {
            let mut kept = HashSet::new();
            kept.insert(mp);
            return Some(kept);
        }
    }

    // Otherwise keep the B3 primary family (dominant + >= 20% share).
    let dominant_count = counts.values().copied().max().unwrap_or(0);
    if dominant_count == 0 {
        return Some(detected.into_iter().collect());
    }
    let threshold = dominant_count / PRIMARY_FAMILY_SHARE_DEN;

    let kept: HashSet<Language> = detected
        .into_iter()
        .filter(|l| counts.get(l).copied().unwrap_or(0) >= threshold)
        .collect();

    // Never return empty (would regress to "no source found").
    if kept.is_empty() {
        None
    } else {
        Some(kept)
    }
}

/// Collect source files matching the optional language filter
fn collect_source_files(path: &Path, lang: Option<Language>) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if path.is_file() {
        // Single file
        if let Some(file_lang) = Language::from_path(path) {
            if lang.is_none() || lang == Some(file_lang) {
                files.push(path.to_path_buf());
            }
        }
        return files;
    }

    // Walk directory
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();

        // Skip hidden files and directories
        if entry_path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false)
        {
            continue;
        }

        // Skip non-files
        if !entry_path.is_file() {
            continue;
        }

        // Check language
        if let Some(file_lang) = Language::from_path(entry_path) {
            if lang.is_none() || lang == Some(file_lang) {
                files.push(entry_path.to_path_buf());
            }
        }
    }

    files
}

/// Build InheritanceEdge structs from graph
///
/// inheritance-and-dead-cleanup-v1 (M5): edges are deduplicated at the
/// (child, parent, parent_file) tuple level. The same heritage clause may
/// be emitted multiple times by language extractors (TS overload signatures,
/// TSX re-emission, Go interface satisfaction, etc.). Deduping here keeps
/// downstream consumers (and diamond detection counts) honest.
fn build_edges(graph: &InheritanceGraph, _project_root: &Path) -> Vec<InheritanceEdge> {
    let mut edges = Vec::new();
    // callgraph-dataflow-issues-v1 (#54): edge identity must include the
    // child file so two same-named children in different files produce
    // distinct edges. Pre-fix the dedup key was
    // `(child, parent, parent_file)` and silently collapsed cross-file
    // duplicates.
    let mut seen_edges: HashSet<(String, String, PathBuf, Option<PathBuf>)> = HashSet::new();

    // Fall back to the legacy `parents` map when no per-file edges were
    // recorded (synthetic graphs in tests, etc.) so existing callers that
    // construct graphs via `add_edge` keep working.
    if graph.parent_edges.is_empty() {
        return build_edges_legacy(graph);
    }

    for edge_info in &graph.parent_edges {
        let parent_node = graph.nodes.get(&edge_info.parent);
        // Determine language from per-file node when available, else from
        // bare-name node; needed for stdlib classification.
        let child_node = graph
            .nodes_per_file
            .get(&(edge_info.child_file.clone(), edge_info.child.clone()))
            .or_else(|| graph.nodes.get(&edge_info.child));
        let language = match child_node {
            Some(n) => n.language,
            None => continue,
        };

        let (resolution, external) = if parent_node.is_some() {
            (BaseResolution::Project, false)
        } else if resolve::is_stdlib_class(&edge_info.parent, language) {
            (BaseResolution::Stdlib, true)
        } else {
            (BaseResolution::Unresolved, true)
        };

        let base_edge = if external {
            if resolution == BaseResolution::Stdlib {
                InheritanceEdge::stdlib(
                    &edge_info.child,
                    &edge_info.parent,
                    edge_info.child_file.clone(),
                    edge_info.child_line,
                )
            } else {
                InheritanceEdge::unresolved(
                    &edge_info.child,
                    &edge_info.parent,
                    edge_info.child_file.clone(),
                    edge_info.child_line,
                )
            }
        } else {
            let pn = parent_node.unwrap();
            InheritanceEdge::project(
                &edge_info.child,
                &edge_info.parent,
                edge_info.child_file.clone(),
                edge_info.child_line,
                pn.file.clone(),
                pn.line,
            )
        };

        let edge = base_edge.with_kind(edge_info.kind);

        // Edge identity: (child, parent, child_file, parent_file). The
        // child_file distinguishes cross-file same-named edges; the
        // parent_file preserves the M5 dedup semantics for repeated
        // heritage clauses in the same file (TS overloads etc.).
        let key = (
            edge.child.clone(),
            edge.parent.clone(),
            edge.child_file.clone(),
            edge.parent_file.clone(),
        );
        if seen_edges.insert(key) {
            edges.push(edge);
        }
    }

    edges
}

/// Legacy edge-building path for graphs constructed via the bare
/// `add_edge` API (tests, synthetic graphs). Preserves the pre-fix
/// behaviour for callers that never invoked `add_edge_with_file`.
fn build_edges_legacy(graph: &InheritanceGraph) -> Vec<InheritanceEdge> {
    let mut edges = Vec::new();
    let mut seen_edges: HashSet<(String, String, Option<PathBuf>)> = HashSet::new();

    for (child_name, parents) in &graph.parents {
        let child_node = match graph.nodes.get(child_name) {
            Some(n) => n,
            None => continue,
        };

        let mut kind_for_base: std::collections::HashMap<String, InheritanceKind> =
            std::collections::HashMap::new();
        for (i, b) in child_node.bases.iter().enumerate() {
            kind_for_base
                .entry(b.clone())
                .or_insert_with(|| child_node.base_kind_at(i));
        }

        let mut seen_parents: HashSet<String> = HashSet::new();
        let parents: Vec<&String> = parents
            .iter()
            .filter(|p| seen_parents.insert((*p).clone()))
            .collect();

        for parent_name in parents {
            let parent_node = graph.nodes.get(parent_name);
            let (resolution, external) = if parent_node.is_some() {
                (BaseResolution::Project, false)
            } else if resolve::is_stdlib_class(parent_name, child_node.language) {
                (BaseResolution::Stdlib, true)
            } else {
                (BaseResolution::Unresolved, true)
            };

            let base_edge = if external {
                if resolution == BaseResolution::Stdlib {
                    InheritanceEdge::stdlib(
                        child_name,
                        parent_name,
                        child_node.file.clone(),
                        child_node.line,
                    )
                } else {
                    InheritanceEdge::unresolved(
                        child_name,
                        parent_name,
                        child_node.file.clone(),
                        child_node.line,
                    )
                }
            } else {
                let pn = parent_node.unwrap();
                InheritanceEdge::project(
                    child_name,
                    parent_name,
                    child_node.file.clone(),
                    child_node.line,
                    pn.file.clone(),
                    pn.line,
                )
            };

            let kind = kind_for_base
                .get(parent_name)
                .copied()
                .unwrap_or(InheritanceKind::Extends);
            let edge = base_edge.with_kind(kind);

            let key = (
                edge.child.clone(),
                edge.parent.clone(),
                edge.parent_file.clone(),
            );
            if seen_edges.insert(key) {
                edges.push(edge);
            }
        }
    }

    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_options_validation_depth_without_class() {
        let options = InheritanceOptions {
            depth: Some(3),
            class_filter: None,
            ..Default::default()
        };

        let result = options.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--depth requires --class"));
    }

    #[test]
    fn test_options_validation_depth_with_class() {
        let options = InheritanceOptions {
            depth: Some(3),
            class_filter: Some("MyClass".to_string()),
            ..Default::default()
        };

        assert!(options.validate().is_ok());
    }

    #[test]
    fn test_extract_empty_project() {
        let dir = TempDir::new().unwrap();
        create_test_file(&dir, "empty.py", "# No classes here\npass\n");

        let options = InheritanceOptions::default();
        let report = extract_inheritance(dir.path(), Some(Language::Python), &options).unwrap();

        assert!(report.nodes.is_empty());
        assert!(report.edges.is_empty());
        assert_eq!(report.count, 0);
    }

    /// tldr-additive-fixes (T6a): a `.luau` source using metatable-based OOP
    /// must produce inheritance nodes/edges end-to-end through
    /// `extract_inheritance`. Before the fix the dispatch had a
    /// `Language::Lua` arm but NO `Language::Luau` arm, so every `.luau`
    /// file fell through to `_ => Vec::new()` and returned an empty report
    /// even though `lua::extract_classes` already recognizes the Luau grammar
    /// (see `lua::tests::test_luau_extend_inheritance`). Uses the assigned
    /// `setmetatable({}, { __index = Parent })` idiom so the fixture is
    /// genuinely metatable-OOP (not the separate Luau `class` keyword, which
    /// is a distinct grammar gap).
    #[test]
    fn test_luau_metatable_inheritance_end_to_end() {
        let dir = TempDir::new().unwrap();
        create_test_file(
            &dir,
            "Animal.luau",
            "local Animal = {}\n\
             Animal.__index = Animal\n\
             \n\
             function Animal.new(name: string)\n\
             \treturn setmetatable({ name = name }, Animal)\n\
             end\n\
             \n\
             local Dog = setmetatable({}, { __index = Animal })\n\
             Dog.__index = Dog\n",
        );

        let options = InheritanceOptions::default();
        let report =
            extract_inheritance(dir.path(), Some(Language::Luau), &options).unwrap();

        // Non-empty hierarchy: the `.luau` file must contribute nodes/edges.
        assert!(
            !report.nodes.is_empty(),
            "expected non-empty nodes for .luau metatable OOP, got {:?}",
            report.nodes
        );
        assert!(
            !report.edges.is_empty(),
            "expected non-empty edges for .luau metatable OOP, got {:?}",
            report.edges
        );

        // The `Dog -> Animal` extends edge is present, labelled Luau.
        assert!(
            report.nodes.iter().any(|n| n.name == "Dog"),
            "`Dog` class must be present; got {:?}",
            report.nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        assert!(
            report.nodes.iter().all(|n| n.language == Language::Luau),
            "all nodes should be Luau, got {:?}",
            report.nodes.iter().map(|n| n.language).collect::<Vec<_>>()
        );
        let edge = report
            .edges
            .iter()
            .find(|e| e.child == "Dog" && e.parent == "Animal")
            .expect("Dog should inherit Animal via setmetatable __index");
        assert_eq!(edge.kind, InheritanceKind::Extends);
    }

    /// inheritance-extends-vs-implements-ocaml-v1 (T3): on a no-`--lang`
    /// directory scan of an OCaml project that ALSO carries vendored C interop
    /// stubs (the `ocaml-lwt` shape), the hierarchy must be computed from the
    /// OCaml sources — not from the C files. Before the language-selection fix
    /// every node came out `language=c` and the OCaml classes were missing.
    #[test]
    fn test_ocaml_project_with_vendored_c_respects_target_language() {
        let dir = TempDir::new().unwrap();
        // Manifest marks the project as OCaml (dune/opam honoured by
        // from_directory's close-call manifest tiebreak).
        create_test_file(&dir, "dune-project", "(lang dune 3.0)\n");
        create_test_file(&dir, "lib.opam", "opam-version: \"2.0\"\n");
        // OCaml sources: one class hierarchy + filler modules. Faithful to
        // ocaml-lwt where vendored C strictly OUTNUMBERS OCaml source files
        // (here 5 .c vs 4 .ml, an 80% close call the manifest resolves to
        // OCaml).
        create_test_file(
            &dir,
            "src/engine.ml",
            "class virtual abstract = object\n  method virtual iter : unit\nend\n\nclass libev = object\n  inherit abstract\n  method iter = ()\nend\n",
        );
        for i in 0..3 {
            create_test_file(&dir, &format!("src/mod_{i}.ml"), "let x = 0\n");
        }
        // Vendored C interop stubs with C structs (would dominate by raw count).
        for i in 0..5 {
            create_test_file(
                &dir,
                &format!("src/unix_c/stub_{i}.c"),
                "struct job { int fd; };\nstruct other { struct job j; };\n",
            );
        }

        let options = InheritanceOptions::default();
        // No explicit --lang: the directory scan must pick OCaml.
        let report = extract_inheritance(dir.path(), None, &options).unwrap();

        // OCaml classes present.
        assert!(
            report.nodes.iter().any(|n| n.name == "libev"),
            "OCaml class `libev` must be present; got {:?}",
            report.nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        // Not all nodes are C (the pre-fix symptom).
        assert!(
            report.nodes.iter().all(|n| n.language == Language::Ocaml),
            "all nodes should be OCaml on an OCaml project, got languages {:?}",
            report
                .nodes
                .iter()
                .map(|n| n.language)
                .collect::<Vec<_>>()
        );
        // The `libev` -> `abstract` inherit edge is Extends.
        let edge = report
            .edges
            .iter()
            .find(|e| e.child == "libev" && e.parent == "abstract")
            .expect("libev should inherit abstract");
        assert_eq!(edge.kind, InheritanceKind::Extends);
    }

    /// inheritance-extends-vs-implements (T3): a no-`--lang` directory scan of
    /// a Java project must label `implements` edges `Implements` and `extends`
    /// edges `Extends` end-to-end through `extract_inheritance` (the
    /// petclinic/retrofit live shape).
    #[test]
    fn test_java_implements_vs_extends_end_to_end() {
        let dir = TempDir::new().unwrap();
        create_test_file(&dir, "pom.xml", "<project></project>\n");
        create_test_file(
            &dir,
            "src/Animal.java",
            "public class Animal {}\n",
        );
        create_test_file(
            &dir,
            "src/Serializable.java",
            "public interface Serializable {}\n",
        );
        create_test_file(
            &dir,
            "src/Dog.java",
            "public class Dog extends Animal implements Serializable {}\n",
        );

        let options = InheritanceOptions::default();
        let report = extract_inheritance(dir.path(), None, &options).unwrap();

        let extends_edge = report
            .edges
            .iter()
            .find(|e| e.child == "Dog" && e.parent == "Animal")
            .expect("Dog extends Animal edge");
        assert_eq!(
            extends_edge.kind,
            InheritanceKind::Extends,
            "extends must be Extends"
        );

        let implements_edge = report
            .edges
            .iter()
            .find(|e| e.child == "Dog" && e.parent == "Serializable")
            .expect("Dog implements Serializable edge");
        assert_eq!(
            implements_edge.kind,
            InheritanceKind::Implements,
            "implements must be Implements, not {:?}",
            implements_edge.kind
        );
    }
}
