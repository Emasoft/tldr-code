//! Dependency Analysis Core Types and Functions
//!
//! This module provides dependency analysis for the `deps` CLI command.
//!
//! # Type Overview
//!
//! - [`DepsReport`]: Complete dependency analysis report
//! - [`DepNode`]: A node in the dependency graph (file or package)
//! - [`DepEdge`]: An edge in the dependency graph
//! - [`DepCycle`]: A circular dependency cycle
//! - [`DepKind`]: Classification of a dependency (Internal, Stdlib, External)
//! - [`DepStats`]: Analysis statistics
//! - [`DepsOptions`]: Configuration for dependency analysis
//!
//! # Functions
//!
//! - [`analyze_dependencies`]: Build dependency graph for a directory
//!
//! # Risk Mitigations
//!
//! - S7-R3: Handle relative imports with current file context
//! - S7-R8: Use HashMap index for O(1) resolution (not O(n^2))
//! - S7-R14: Canonicalize paths before indexing, uses `PathBuf` for path handling
//! - S7-R15: `DepNode` derives `Hash` and `Eq` based on path only
//! - S7-R40: Uses `BTreeMap` for deterministic JSON output
//!
//! # References
//!
//! - Spec: session7-spec.md section 1.2 (Type Definitions)
//! - Phased plan: session7-phased-plan.yaml Phase 1, 2

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::ast::imports::get_imports;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{IgnoreSpec, ImportInfo, Language};
use crate::TldrResult;
use std::str::FromStr as _;

// deps-manifest-external-v1 (v0.5.0 T1 AUDIT-FIX): dependency-manifest parser.
// Declared via `#[path]` so the helper lives in its own file without an extra
// `mod` line in `analysis/mod.rs`.
#[path = "deps_manifest.rs"]
mod manifest;
use manifest::{parse_manifest_dependencies, ManifestDeps};

// =============================================================================
// Core Types
// =============================================================================

/// Complete dependency analysis report
///
/// Contains all information about a project's dependency structure including
/// internal dependencies, external dependencies, and circular dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepsReport {
    /// Root path analyzed (relative paths in report are relative to this)
    pub root: PathBuf,

    /// Language detected/specified
    pub language: String,

    /// Internal dependencies (file -> [imported files])
    /// Uses BTreeMap for deterministic JSON output (S7-R40)
    pub internal_dependencies: BTreeMap<PathBuf, Vec<PathBuf>>,

    /// External dependencies (file -> [package names])
    /// Uses BTreeMap for deterministic JSON output (S7-R40).
    ///
    /// Schema-parity contract (FIX-DEPS-SCHEMA): this key is ALWAYS serialized,
    /// emitting an empty object `{}` for stdlib-only / zero-external repos rather
    /// than being omitted. Consumers expect all four canonical keys present.
    #[serde(default)]
    pub external_dependencies: BTreeMap<PathBuf, Vec<String>>,

    /// Circular dependencies found
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circular_dependencies: Vec<DepCycle>,

    /// Analysis statistics
    pub stats: DepStats,

    /// Number of files skipped during analysis (oversize/auto-generated files
    /// that exceed the size policy in `tldr_core::fs::oversize`).
    ///
    /// Soft-skipped files do NOT abort the analysis; they are reported here
    /// alongside a structured warning in [`DepsReport::warnings`].
    #[serde(default)]
    pub files_skipped: usize,

    /// Human-readable warnings collected during analysis.
    ///
    /// Each entry names a file that was skipped and why (e.g. oversize cap
    /// exceeded). Empty for clean scans. (M-Z11: deps-and-surface-graceful-degrade-v1.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Default for DepsReport {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            language: String::new(),
            internal_dependencies: BTreeMap::new(),
            external_dependencies: BTreeMap::new(),
            circular_dependencies: Vec::new(),
            stats: DepStats::default(),
            files_skipped: 0,
            warnings: Vec::new(),
        }
    }
}

/// A node in the dependency graph
///
/// Represents a file or package in the dependency graph.
/// Hash and Eq are implemented based on path only (S7-R15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepNode {
    /// Canonical file path (normalized, relative to project root)
    pub path: PathBuf,

    /// Module name (derived from path, used for display)
    pub name: String,

    /// Whether this is an internal (project) or external (stdlib/third-party) module
    pub kind: DepKind,
}

impl DepNode {
    /// Create a new DepNode with the given path and derive name from it
    pub fn new(path: PathBuf, kind: DepKind) -> Self {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        Self { path, name, kind }
    }

    /// Create a new DepNode with explicit path and name
    pub fn with_name(path: PathBuf, name: String, kind: DepKind) -> Self {
        Self { path, name, kind }
    }
}

// Implement Hash and Eq based on path only (S7-R15)
impl std::hash::Hash for DepNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl PartialEq for DepNode {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for DepNode {}

/// Edge in dependency graph
///
/// Represents an import relationship between two files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEdge {
    /// Source file (importer)
    pub from: PathBuf,

    /// Target file/module (imported)
    pub to: PathBuf,

    /// Import statement line number (1-indexed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,

    /// The actual import statement text
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_text: Option<String>,
}

impl DepEdge {
    /// Create a new edge with minimal information
    pub fn new(from: PathBuf, to: PathBuf) -> Self {
        Self {
            from,
            to,
            line: None,
            import_text: None,
        }
    }

    /// Create a new edge with line number
    pub fn with_line(from: PathBuf, to: PathBuf, line: usize) -> Self {
        Self {
            from,
            to,
            line: Some(line),
            import_text: None,
        }
    }

    /// Create a new edge with full information
    pub fn with_details(from: PathBuf, to: PathBuf, line: usize, import_text: String) -> Self {
        Self {
            from,
            to,
            line: Some(line),
            import_text: Some(import_text),
        }
    }
}

/// A circular dependency cycle
///
/// Represents a cycle in the dependency graph where files form a loop.
/// Example: A -> B -> C -> A is a cycle of length 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepCycle {
    /// Ordered list of files in the cycle
    /// First element is the canonical start (lexicographically smallest after canonicalization)
    pub path: Vec<PathBuf>,

    /// Length of cycle (number of unique nodes)
    pub length: usize,
}

impl DepCycle {
    /// Create a new cycle from a list of paths
    pub fn new(path: Vec<PathBuf>) -> Self {
        let length = path.len();
        Self { path, length }
    }

    /// Return a canonical representation of this cycle for deduplication
    ///
    /// The canonical form:
    /// 1. Rotates the cycle so it starts with the lexicographically smallest path
    /// 2. This ensures the same cycle starting from different nodes compares equal
    ///
    /// Example: [B, C, A] and [A, B, C] both canonicalize to [A, B, C]
    pub fn canonical(&self) -> DepCycle {
        if self.path.is_empty() {
            return self.clone();
        }

        // Find the index of the lexicographically smallest path
        let min_idx = self
            .path
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| *p)
            .map(|(i, _)| i)
            .unwrap_or(0);

        // Rotate the path so it starts with the smallest element
        let mut canonical_path = Vec::with_capacity(self.path.len());
        canonical_path.extend(self.path[min_idx..].iter().cloned());
        canonical_path.extend(self.path[..min_idx].iter().cloned());

        DepCycle {
            path: canonical_path,
            length: self.length,
        }
    }
}

// Implement Hash and Eq for DepCycle based on canonical form
impl std::hash::Hash for DepCycle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the canonical representation
        let canonical = self.canonical();
        canonical.path.hash(state);
    }
}

impl PartialEq for DepCycle {
    fn eq(&self, other: &Self) -> bool {
        // Compare canonical representations
        self.canonical().path == other.canonical().path
    }
}

impl Eq for DepCycle {}

/// Dependency kind
///
/// Classification of where a dependency comes from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum DepKind {
    /// Internal project dependency (files within the project)
    #[default]
    Internal,

    /// External third-party package
    External,

    /// Standard library module
    Stdlib,
}

/// Analysis statistics
///
/// Summary statistics about the dependency analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DepStats {
    /// Total files analyzed
    pub total_files: usize,

    /// Total internal dependency edges
    pub total_internal_deps: usize,

    /// Total external dependencies (unique packages)
    pub total_external_deps: usize,

    /// Maximum dependency depth (longest path from any root)
    pub max_depth: usize,

    /// Number of circular dependencies found
    pub cycles_found: usize,

    /// Files with no outgoing dependencies (leaf nodes)
    pub leaf_files: usize,

    /// Files with no incoming dependencies (root nodes)
    pub root_files: usize,
}

impl DepStats {
    /// Create stats with only the basic counts set
    pub fn new(total_files: usize, total_internal_deps: usize, total_external_deps: usize) -> Self {
        Self {
            total_files,
            total_internal_deps,
            total_external_deps,
            ..Default::default()
        }
    }
}

/// Options for dependency analysis
///
/// Configuration options that control the behavior of dependency analysis.
#[derive(Debug, Clone, Default)]
pub struct DepsOptions {
    /// Include external (third-party) dependencies in the report
    pub include_external: bool,

    /// Collapse files into package-level nodes
    pub collapse_packages: bool,

    /// Maximum depth for transitive dependencies (None = unlimited)
    pub max_depth: Option<usize>,

    /// Only analyze and report circular dependencies
    pub show_cycles_only: bool,

    /// Maximum cycle length to report (cycles longer than this are excluded)
    pub max_cycle_length: Option<usize>,

    /// Language to analyze (None = auto-detect)
    pub language: Option<String>,
}

impl DepsOptions {
    /// Create options with external dependencies included
    pub fn with_external() -> Self {
        Self {
            include_external: true,
            ..Default::default()
        }
    }

    /// Create options focused on cycle detection
    pub fn cycles_only() -> Self {
        Self {
            show_cycles_only: true,
            ..Default::default()
        }
    }

    /// Set maximum cycle length
    pub fn with_max_cycle_length(mut self, max_length: usize) -> Self {
        self.max_cycle_length = Some(max_length);
        self
    }

    /// Set maximum depth for transitive dependencies
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self
    }
}

// =============================================================================
// Analysis Functions (Phase 2)
// =============================================================================

/// Build dependency graph for a directory.
///
/// This function:
/// 1. Walks the directory to find source files for the given language
/// 2. Builds a module_name -> file_path index for O(1) lookup (S7-R8)
/// 3. For each file, parses imports and resolves them to file paths
/// 4. Handles relative imports with current file context (S7-R3)
/// 5. Calculates stats and returns a DepsReport
///
/// # Arguments
///
/// * `path` - Root directory to analyze
/// * `options` - Analysis configuration options
///
/// # Returns
///
/// * `Ok(DepsReport)` - Dependency analysis results
/// * `Err(TldrError)` - If path doesn't exist or other errors
///
/// # Example
///
/// ```ignore
/// use std::path::Path;
/// use tldr_core::analysis::deps::{analyze_dependencies, DepsOptions};
///
/// let report = analyze_dependencies(Path::new("src"), &DepsOptions::default())?;
/// println!("Found {} files with {} internal deps",
///          report.stats.total_files,
///          report.stats.total_internal_deps);
/// ```
pub fn analyze_dependencies(path: &Path, options: &DepsOptions) -> TldrResult<DepsReport> {
    // Validate path exists
    if !path.exists() {
        return Err(crate::error::TldrError::PathNotFound(path.to_path_buf()));
    }

    // Canonicalize root path (S7-R14)
    let root = dunce::canonicalize(path)
        .map_err(|_| crate::error::TldrError::PathNotFound(path.to_path_buf()))?;

    // Detect language from options or auto-detect from files
    let language = if let Some(ref lang_str) = options.language {
        Language::from_str(lang_str).unwrap_or(Language::Python)
    } else {
        detect_dominant_language(&root)?
    };

    // Get extensions for this language.
    //
    // RC1 (v0.5.0 R7 cluster[10]): use `scan_extensions()` (not
    // `extensions()`) for the directory walk so C++ `.h` headers (and the
    // JS/TS sibling spellings) participate. `extensions()` omits `.h` for
    // Cpp, which silently dropped every header from the file set — so
    // `#include "x.h"` never resolved (empty internal graph) and the
    // header was never registered in `build_module_index`. The C++ grammar
    // parses `.h` as a strict superset of C declarations. C is unaffected
    // (its `scan_extensions()` already equals `extensions()`).
    let extensions: HashSet<String> = language
        .scan_extensions()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Get file tree and collect files
    let tree = get_file_tree(&root, Some(&extensions), true, Some(&IgnoreSpec::default()))?;
    let candidate_files = collect_files(&tree, &root);

    // M-Z11 (deps-and-surface-graceful-degrade-v1): apply the central
    // oversize policy BEFORE attempting to parse imports. Without this
    // gate, a single auto-generated `.d.ts` file (e.g.
    // `dom.generated.d.ts` at 2.3 MB) would surface a hard
    // `TldrError::FileTooLarge` from `get_imports` and abort the entire
    // dependency scan with exit code 6, even though the rest of the
    // repo is healthy. Soft-skip oversize files instead, surfacing them
    // as structured warnings and counting them in `files_skipped` so
    // consumers can distinguish a graceful skip from a clean run.
    let (files, mut warnings, files_skipped) = partition_files_by_size(&candidate_files);

    // Handle empty directory case
    if files.is_empty() {
        return Ok(DepsReport {
            root: root.clone(),
            language: language.as_str().to_string(),
            internal_dependencies: BTreeMap::new(),
            external_dependencies: BTreeMap::new(),
            circular_dependencies: Vec::new(),
            stats: DepStats::default(),
            files_skipped: files_skipped as usize,
            warnings,
        });
    }

    // Build module index for O(1) lookup (S7-R8)
    let module_index = build_module_index(&root, &files, language);

    // Build dependency graph
    let mut internal_dependencies: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let mut external_dependencies: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    let mut total_internal_deps = 0;

    for file_path in &files {
        let relative_path = make_relative_path(file_path, &root);

        // Parse imports from file
        let imports = match get_imports(file_path, language) {
            Ok(imports) => imports,
            Err(e) => {
                // Skip files with parse errors (recoverable)
                if is_recoverable_error(&e) {
                    internal_dependencies.insert(relative_path, Vec::new());
                    continue;
                }
                // M-Z11: defensively soft-skip oversize files that slip
                // past the up-front `partition_files_by_size` gate (for
                // example, a file that grew between the stat call and
                // the read). Treat as a recoverable skip with a
                // structured warning rather than aborting the scan.
                if let crate::error::TldrError::FileTooLarge { .. } = &e {
                    warnings.push(format!("Skipped {}: {}", file_path.display(), e));
                    internal_dependencies.insert(relative_path, Vec::new());
                    continue;
                }
                return Err(e);
            }
        };

        let mut file_internal_deps: Vec<PathBuf> = Vec::new();
        let mut file_external_deps: Vec<String> = Vec::new();

        for import in imports {
            // Classify the import (Phase 4)
            let dep_kind = classify_import(&import, &root, file_path, &module_index, language);

            match dep_kind {
                DepKind::Internal => {
                    // Try to resolve to get the actual file path
                    if let Some(target_path) =
                        resolve_import(&import, &root, file_path, &module_index, language)
                    {
                        let target_relative = make_relative_path(&target_path, &root);

                        // Skip self-imports
                        if target_relative != relative_path {
                            // Deduplicate within file
                            if !file_internal_deps.contains(&target_relative) {
                                file_internal_deps.push(target_relative);
                                total_internal_deps += 1;
                            }
                        }
                    }
                }
                DepKind::External => {
                    // Only track external deps if include_external is true
                    if options.include_external {
                        // deps-external-internal-classifier-v1 (M-048):
                        // per-language external-package extractor preserves
                        // namespace precision (e.g. `org.springframework`,
                        // `kotlinx.coroutines`, `Newtonsoft.Json`) instead of
                        // collapsing to the bare first segment (`org`,
                        // `kotlinx`, `Newtonsoft`). For Spring petclinic the
                        // pre-fix collapse yielded 4 unique entries
                        // (`["jakarta","java","javax","org"]`) for ~76 import
                        // sites; post-fix it preserves package-manager-grain
                        // precision (`org.springframework`,
                        // `jakarta.persistence`, etc.).
                        let pkg = external_package_name(&import.module, language);
                        if !pkg.is_empty() && !file_external_deps.contains(&pkg) {
                            file_external_deps.push(pkg);
                        }
                    }
                }
                DepKind::Stdlib => {
                    // m048-deps-stdlib-wiring-v1 (v0.4.2 M-111): stdlib
                    // imports are explicitly NOT added to `file_external_deps`
                    // — they are part of the language toolchain and don't
                    // count as third-party dependencies. Pre-fix this arm
                    // was fused with External (both were pushed into the
                    // same bucket), which silently inflated
                    // `total_external_deps` by the size of every project's
                    // stdlib surface (kotlin reported `kotlin.collections`,
                    // c# reported `System.IO`, ocaml reported `Stdlib.Map`,
                    // etc.).
                }
            }
        }

        internal_dependencies.insert(relative_path.clone(), file_internal_deps);
        if options.include_external && !file_external_deps.is_empty() {
            external_dependencies.insert(relative_path, file_external_deps);
        }
    }

    // Go same-package implicit dependencies:
    // In Go, all files in the same directory share the same package scope.
    // Add edges between files in the same package directory.
    //
    // (deps-external-internal-classifier-v1 / M-048) Track these implicit
    // edges in a separate set so the cycle detector can exclude them.
    // Pre-fix, the implicit n*n same-package edges between (router.go,
    // router_test.go, tree.go, tree_test.go, path.go, path_test.go) in
    // go-httprouter generated 15 spurious cycles even though no real
    // import-based cycle exists. Same-package files are mutually visible
    // by Go's package-scope rules (a compile-time fact about identifier
    // visibility) but that is NOT the same thing as "router.go imports
    // router_test.go imports router.go" — feeding it to the cycle
    // detector is a category error.
    let mut same_package_edges: HashSet<(PathBuf, PathBuf)> = HashSet::new();
    if language == Language::Go {
        let go_packages = group_go_files_by_package(&root, &files);
        for pkg_files in go_packages.values() {
            if pkg_files.len() < 2 {
                continue;
            }
            for file_a in pkg_files {
                let rel_a = make_relative_path(file_a, &root);
                for file_b in pkg_files {
                    let rel_b = make_relative_path(file_b, &root);
                    if rel_a == rel_b {
                        continue;
                    }
                    // Add implicit same-package dependency
                    if let Some(deps) = internal_dependencies.get_mut(&rel_a) {
                        if !deps.contains(&rel_b) {
                            deps.push(rel_b.clone());
                            total_internal_deps += 1;
                            same_package_edges.insert((rel_a.clone(), rel_b.clone()));
                        }
                    }
                }
            }
        }
    }

    // deps-manifest-external-v1 (v0.5.0 T1 AUDIT-FIX): merge the project's
    // DECLARED dependencies from its ecosystem manifest(s)
    // (go.mod / Cargo.toml / package.json / pom.xml|build.gradle /
    // Gemfile+*.gemspec / mix.exs / Package.swift). This is done
    // UNCONDITIONALLY — i.e. independent of `options.include_external`.
    //
    // Rationale: pre-fix, `external_dependencies` was populated solely from
    // per-file import statements AND only when the caller passed
    // `--include-external` (a flag defaulting to `false`). So a plain
    // `tldr deps <dir>` reported `external_dependencies = {}` /
    // `total_external_deps = 0` for every ecosystem even though the manifest
    // unambiguously declares the third-party set. The manifest is the cheap,
    // authoritative source of truth, so we always surface it. The
    // `include_external` flag still governs ONLY the noisier import-derived
    // augmentation above.
    //
    // Manifest entries are keyed by the manifest path (relative to root) so
    // the report attributes each declared dependency to the file declaring
    // it, distinct from the per-file import-site keys.
    for md in parse_manifest_dependencies(&root, language) {
        let ManifestDeps { manifest, packages } = md;
        if packages.is_empty() {
            continue;
        }
        let entry = external_dependencies.entry(manifest).or_default();
        for pkg in packages {
            if !entry.contains(&pkg) {
                entry.push(pkg);
            }
        }
        entry.sort();
    }

    // Calculate stats
    let total_files = files.len();

    // Count unique external packages
    let mut unique_external: HashSet<&String> = HashSet::new();
    for deps in external_dependencies.values() {
        for dep in deps {
            unique_external.insert(dep);
        }
    }
    let total_external_deps = unique_external.len();

    // Calculate leaf and root files
    let mut incoming_count: HashMap<&PathBuf, usize> = HashMap::new();
    for deps in internal_dependencies.values() {
        for dep in deps {
            *incoming_count.entry(dep).or_insert(0) += 1;
        }
    }

    let leaf_files = internal_dependencies
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .count();

    let root_files = internal_dependencies
        .keys()
        .filter(|path| !incoming_count.contains_key(path))
        .count();

    // Collapse to packages if requested (Phase 7)
    let mut final_deps = if options.collapse_packages {
        collapse_to_packages(&internal_dependencies, &root)
    } else {
        internal_dependencies.clone()
    };

    // Detect circular dependencies (Phase 3) - use final_deps
    //
    // (deps-external-internal-classifier-v1 / M-048) Build a cycle-input
    // graph that excludes same-package implicit edges (Go). Without this,
    // every same-package file pair (`router.go` <-> `router_test.go`,
    // etc.) registers as a 2-cycle, manufacturing 15 spurious cycles for
    // go-httprouter where zero real cyclic imports exist.
    let max_cycle_length = options.max_cycle_length.unwrap_or(10);
    let circular_dependencies = if same_package_edges.is_empty() {
        detect_cycles(&final_deps, max_cycle_length)
    } else {
        let mut cycle_input: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
        for (src, deps) in &final_deps {
            let filtered: Vec<PathBuf> = deps
                .iter()
                .filter(|tgt| {
                    !same_package_edges.contains(&(src.clone(), (*tgt).clone()))
                })
                .cloned()
                .collect();
            cycle_input.insert(src.clone(), filtered);
        }
        detect_cycles(&cycle_input, max_cycle_length)
    };
    let cycles_found = circular_dependencies.len();

    // Calculate depth stats (Phase 7)
    let (max_depth, leaf_files_calc, root_files_calc) = calculate_depth_stats(&final_deps);

    // cl1r-determinism-v1 (v0.5.0 CL-1R): sort every serialized adjacency Vec
    // at the emission boundary. The `BTreeMap` keys are already ordered, but
    // each `Vec<PathBuf>` value is assembled from collections whose order is
    // NOT guaranteed across runs:
    //   - `collapse_to_packages` converts a `HashSet<PathBuf>` to a `Vec`
    //     (`--collapse-packages`) in randomized HashSet iteration order;
    //   - the Go same-package augmentation pushes implicit edges while
    //     iterating a `HashMap<String, Vec<PathBuf>>` of package groups.
    // Sorting here (after cycle/depth analysis, which is order-insensitive)
    // makes `internal_dependencies` byte-stable run-to-run without changing
    // its set semantics. Done in place on `final_deps` since it flows
    // straight into the report below.
    for deps in final_deps.values_mut() {
        deps.sort();
    }
    // external_dependencies values are package-name strings assembled in
    // import order; sort them too so the emitted lists are deterministic.
    for pkgs in external_dependencies.values_mut() {
        pkgs.sort();
    }

    let stats = DepStats {
        total_files,
        total_internal_deps,
        total_external_deps,
        max_depth,
        cycles_found,
        leaf_files: if options.collapse_packages {
            leaf_files_calc
        } else {
            leaf_files
        },
        root_files: if options.collapse_packages {
            root_files_calc
        } else {
            root_files
        },
    };

    Ok(DepsReport {
        root: root.clone(),
        language: language.as_str().to_string(),
        internal_dependencies: final_deps,
        external_dependencies,
        circular_dependencies,
        stats,
        files_skipped: files_skipped as usize,
        warnings,
    })
}

/// Partition candidate files under the central oversize policy, soft-skipping
/// files that exceed the configured size cap (M-Z11).
///
/// Returns `(kept, warnings, skipped_count)`. The kept set is the subset of
/// `candidates` that passed the size policy and should be processed normally.
/// `warnings` holds one structured message per skipped file (formatted by
/// [`tldr_core::fs::oversize::format_oversize_warning`]). `skipped_count`
/// counts how many files were dropped under the oversize policy and is
/// surfaced through [`DepsReport::files_skipped`].
///
/// This mirrors the pattern used by `tldr secure` (M-Z8) so behaviour is
/// uniform across commands that walk the file tree.
fn partition_files_by_size(candidates: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>, u32) {
    use crate::fs::oversize::{check_size, format_oversize_warning, SizeCheck};

    let mut kept: Vec<PathBuf> = Vec::with_capacity(candidates.len());
    let mut warnings: Vec<String> = Vec::new();
    let mut skipped: u32 = 0;
    for file in candidates {
        match check_size(file) {
            SizeCheck::Oversize {
                size_bytes,
                max_bytes,
                is_autogen,
            } => {
                skipped += 1;
                warnings.push(format_oversize_warning(
                    file,
                    size_bytes,
                    max_bytes,
                    is_autogen,
                ));
            }
            // WithinLimit | Unknown: keep the file. Unknown means the stat
            // failed (e.g. file vanished); we let the existing read-error
            // path handle that case rather than treating "unknown size" as
            // oversize.
            _ => kept.push(file.clone()),
        }
    }
    (kept, warnings, skipped)
}

// =============================================================================
// Cycle Detection (Phase 3)
// =============================================================================

/// Detect circular dependencies in the import graph using DFS with back-edge detection.
///
/// This function finds all cycles in the dependency graph using depth-first search.
/// When we encounter a back-edge (an edge to a node already in the current recursion stack),
/// we've found a cycle.
///
/// # Risk Mitigations
///
/// - S7-R1: Cycles are canonicalized for deduplication (using DepCycle::canonical())
/// - S7-R2: Uses both visited set AND recursion stack separately
/// - S7-R6: Uses HashSet<DepCycle> to deduplicate identical cycles from different start nodes
///
/// # Arguments
///
/// * `deps` - The internal dependency graph as adjacency list
/// * `max_length` - Maximum cycle length to report (cycles longer than this are excluded)
///
/// # Returns
///
/// A vector of deduplicated cycles, each canonicalized to start from the lexicographically
/// smallest path.
fn detect_cycles(deps: &BTreeMap<PathBuf, Vec<PathBuf>>, max_length: usize) -> Vec<DepCycle> {
    // Use HashSet for deduplication (S7-R6)
    // DepCycle implements Hash and Eq based on canonical form
    let mut cycles: HashSet<DepCycle> = HashSet::new();

    // Track globally visited nodes (optimization: don't re-explore fully processed nodes)
    let mut visited: HashSet<PathBuf> = HashSet::new();

    // Process each node as a potential cycle start
    for start_node in deps.keys() {
        if visited.contains(start_node) {
            continue;
        }

        // Track recursion stack for this DFS tree (S7-R2)
        let mut rec_stack: Vec<PathBuf> = Vec::new();
        let mut rec_set: HashSet<PathBuf> = HashSet::new();

        dfs_find_cycles(
            start_node,
            deps,
            &mut visited,
            &mut rec_stack,
            &mut rec_set,
            &mut cycles,
            max_length,
        );
    }

    // Convert HashSet to Vec (cycles are already deduplicated).
    //
    // cl1r-determinism-v1 (v0.5.0 CL-1R): `HashSet::into_iter` yields the
    // deduplicated cycles in randomized per-process order, so the serialized
    // `circular_dependencies` array reshuffled run-to-run. Sort by each
    // cycle's CANONICAL path (the same rotation-normalized form used for
    // dedup) so the emitted order is deterministic and independent of DFS
    // start-node / HashSet iteration order. The stored `path` is left as its
    // canonical form already (cycles are inserted canonical via DepCycle's
    // Eq/Hash), but we re-derive the key defensively rather than assuming.
    // Normalize each cycle's stored `path` to its canonical rotation so the
    // emitted `path` array is also rotation-stable (the DFS may discover the
    // same cycle starting from any of its nodes; canonicalizing pins a single
    // representation), then sort by that canonical path.
    let mut result: Vec<DepCycle> = cycles.into_iter().map(|c| c.canonical()).collect();
    result.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.length.cmp(&b.length)));
    result
}

/// DFS helper for cycle detection.
///
/// Performs depth-first search from `node`, tracking the recursion stack.
/// When we find a back-edge (edge to a node in rec_set), we extract the cycle.
fn dfs_find_cycles(
    node: &PathBuf,
    deps: &BTreeMap<PathBuf, Vec<PathBuf>>,
    visited: &mut HashSet<PathBuf>,
    rec_stack: &mut Vec<PathBuf>,
    rec_set: &mut HashSet<PathBuf>,
    cycles: &mut HashSet<DepCycle>,
    max_length: usize,
) {
    // Mark as visited and add to recursion stack
    visited.insert(node.clone());
    rec_stack.push(node.clone());
    rec_set.insert(node.clone());

    // Process all neighbors (dependencies)
    if let Some(neighbors) = deps.get(node) {
        for neighbor in neighbors {
            if rec_set.contains(neighbor) {
                // Back-edge found! Extract the cycle from the recursion stack
                if let Some(start_idx) = rec_stack.iter().position(|n| n == neighbor) {
                    let cycle_path: Vec<PathBuf> = rec_stack[start_idx..].to_vec();

                    // Only include cycles within max_length
                    if cycle_path.len() <= max_length {
                        let cycle = DepCycle::new(cycle_path);
                        // HashSet with DepCycle's canonical-based Eq handles deduplication
                        cycles.insert(cycle);
                    }
                }
            } else if !visited.contains(neighbor) {
                // Recurse to unvisited neighbor
                dfs_find_cycles(
                    neighbor, deps, visited, rec_stack, rec_set, cycles, max_length,
                );
            }
            // If visited but not in rec_set, it's a cross-edge or forward-edge, not a back-edge
        }
    }

    // Remove from recursion stack when backtracking
    rec_stack.pop();
    rec_set.remove(node);
}

// =============================================================================
// Advanced Features (Phase 7)
// =============================================================================

/// Compute transitive dependencies up to max_depth using BFS.
///
/// Returns a map from each node to its reachable nodes with their distances.
/// This is useful for computing transitive closure and depth statistics.
///
/// # Arguments
///
/// * `deps` - The dependency graph as adjacency list
/// * `max_depth` - Maximum depth to traverse (None = unlimited)
///
/// # Returns
///
/// Map of node -> {reachable_node -> distance}
pub fn compute_transitive_deps(
    deps: &BTreeMap<PathBuf, Vec<PathBuf>>,
    max_depth: Option<usize>,
) -> BTreeMap<PathBuf, BTreeMap<PathBuf, usize>> {
    let mut result: BTreeMap<PathBuf, BTreeMap<PathBuf, usize>> = BTreeMap::new();
    let effective_max = max_depth.unwrap_or(usize::MAX);

    for start_node in deps.keys() {
        let mut reachable: BTreeMap<PathBuf, usize> = BTreeMap::new();
        let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();

        queue.push_back((start_node.clone(), 0));
        visited.insert(start_node.clone());

        while let Some((node, depth)) = queue.pop_front() {
            // Skip if we've exceeded max depth
            if depth > effective_max {
                continue;
            }

            // Record this node if it's not the start node (depth > 0)
            if depth > 0 {
                reachable.insert(node.clone(), depth);
            }

            // Don't explore beyond max_depth
            if depth >= effective_max {
                continue;
            }

            // Explore neighbors
            if let Some(neighbors) = deps.get(&node) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        result.insert(start_node.clone(), reachable);
    }

    result
}

/// Collapse file-level dependencies to package level.
///
/// This function merges files in the same directory into a single package node.
/// For Python, this means files in the same directory become one package.
///
/// # Arguments
///
/// * `deps` - The file-level dependency graph
/// * `root` - The project root path
///
/// # Returns
///
/// Package-level dependency graph where keys and values are directory paths
pub fn collapse_to_packages(
    deps: &BTreeMap<PathBuf, Vec<PathBuf>>,
    _root: &Path,
) -> BTreeMap<PathBuf, Vec<PathBuf>> {
    let mut package_deps: BTreeMap<PathBuf, HashSet<PathBuf>> = BTreeMap::new();

    for (file, file_deps) in deps {
        // Get the package (parent directory) for this file
        let from_pkg = file.parent().map(|p| p.to_path_buf()).unwrap_or_default();

        for dep in file_deps {
            // Get the package for the dependency
            let to_pkg = dep.parent().map(|p| p.to_path_buf()).unwrap_or_default();

            // Only add if it's a cross-package dependency (not within same package)
            if from_pkg != to_pkg {
                package_deps
                    .entry(from_pkg.clone())
                    .or_default()
                    .insert(to_pkg);
            }
        }

        // Ensure the package exists in the map even if it has no cross-package deps
        package_deps.entry(from_pkg).or_default();
    }

    // Convert HashSet to Vec for the return type.
    //
    // cl1r-determinism-v1 (v0.5.0 CL-1R): `HashSet::into_iter` yields elements
    // in randomized per-process order, so sort each collapsed adjacency Vec
    // before returning. This makes the public `collapse_to_packages` API
    // deterministic for every caller (the `analyze_dependencies` emission
    // boundary applies a belt-and-suspenders sort as well).
    package_deps
        .into_iter()
        .map(|(k, v)| {
            let mut deps: Vec<PathBuf> = v.into_iter().collect();
            deps.sort();
            (k, deps)
        })
        .collect()
}

/// Calculate dependency depth statistics.
///
/// Computes:
/// - max_depth: The longest path from any root to any leaf in the DAG
/// - leaf_files: Count of files with no outgoing dependencies
/// - root_files: Count of files with no incoming dependencies
///
/// # Arguments
///
/// * `deps` - The dependency graph as adjacency list
///
/// # Returns
///
/// Tuple of (max_depth, leaf_files, root_files)
pub fn calculate_depth_stats(deps: &BTreeMap<PathBuf, Vec<PathBuf>>) -> (usize, usize, usize) {
    if deps.is_empty() {
        return (0, 0, 0);
    }

    // Build incoming edges count
    let mut incoming: HashMap<&PathBuf, usize> = HashMap::new();
    for node in deps.keys() {
        incoming.entry(node).or_insert(0);
    }
    for file_deps in deps.values() {
        for dep in file_deps {
            *incoming.entry(dep).or_insert(0) += 1;
        }
    }

    // Calculate leaf files (no outgoing deps)
    let leaf_files = deps.iter().filter(|(_, d)| d.is_empty()).count();

    // Calculate root files (no incoming deps)
    let root_files = deps
        .keys()
        .filter(|k| incoming.get(k).copied().unwrap_or(0) == 0)
        .count();

    // Calculate max depth using BFS from all root nodes
    // This finds the longest path from any root to any node
    let mut max_depth = 0;

    // For each node, compute the maximum depth from any root to this node
    // We'll use dynamic programming with topological order

    // First, compute in-degrees for topological sort
    let mut in_degree: HashMap<&PathBuf, usize> = HashMap::new();
    for node in deps.keys() {
        in_degree.entry(node).or_insert(0);
    }
    for file_deps in deps.values() {
        for dep in file_deps {
            // Only count if the dep is actually in our graph
            if deps.contains_key(dep) {
                *in_degree.entry(dep).or_insert(0) += 1;
            }
        }
    }

    // Initialize distances from roots
    let mut distances: HashMap<&PathBuf, usize> = HashMap::new();
    let mut queue: VecDeque<&PathBuf> = VecDeque::new();

    // Start with root nodes (in-degree 0)
    for (node, &degree) in &in_degree {
        if degree == 0 {
            distances.insert(node, 0);
            queue.push_back(node);
        }
    }

    // Process in topological order
    while let Some(node) = queue.pop_front() {
        let current_dist = *distances.get(node).unwrap_or(&0);

        if let Some(neighbors) = deps.get(node) {
            for neighbor in neighbors {
                // Only process if neighbor is in our graph
                if let Some(in_deg) = in_degree.get_mut(&neighbor) {
                    // Update distance to neighbor (take max of all paths)
                    let new_dist = current_dist + 1;
                    let entry = distances.entry(neighbor).or_insert(0);
                    if new_dist > *entry {
                        *entry = new_dist;
                    }

                    // Update max_depth
                    if new_dist > max_depth {
                        max_depth = new_dist;
                    }

                    // Decrement in-degree and add to queue if ready
                    *in_deg -= 1;
                    if *in_deg == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }
    }

    (max_depth, leaf_files, root_files)
}

/// Build module name -> file path index for O(1) lookup (S7-R8).
///
/// Creates a mapping from module names to file paths to avoid O(n^2) resolution.
/// For Python: "src.utils" -> "src/utils.py", "src.utils" -> "src/utils/__init__.py"
/// For TypeScript: "./utils" -> "src/utils.ts"
/// For Java: "com.google.common.base.Preconditions" -> "com/google/common/base/Preconditions.java"
pub fn build_module_index(
    root: &Path,
    files: &[PathBuf],
    language: Language,
) -> HashMap<String, PathBuf> {
    let mut index: HashMap<String, PathBuf> = HashMap::new();

    // For Go, read the module path from go.mod once before iterating files
    let go_module_path = if language == Language::Go {
        read_go_module_path(root)
    } else {
        None
    };

    // For Rust, pre-discover each file's owning crate root + crate name
    // once so `index_rust_module` and `resolve_rust_import` can wire
    // workspace cross-crate imports. See `find_rust_crate_root`.
    //
    // We cache by crate-root path so a workspace with N files in the
    // same crate only parses one Cargo.toml.
    let mut rust_crate_cache: HashMap<PathBuf, String> = HashMap::new();
    let rust_crate_info: Vec<Option<(PathBuf, String)>> = if language == Language::Rust {
        files
            .iter()
            .map(|f| {
                let info = find_rust_crate_root(f, root)?;
                let cached = rust_crate_cache
                    .entry(info.0.clone())
                    .or_insert_with(|| info.1.clone());
                Some((info.0, cached.clone()))
            })
            .collect()
    } else {
        Vec::new()
    };

    for (idx_file, file_path) in files.iter().enumerate() {
        let relative = match file_path.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let rust_info = if language == Language::Rust {
            rust_crate_info
                .get(idx_file)
                .and_then(|opt| opt.as_ref())
                .map(|(root, name)| (root.as_path(), name.as_str()))
        } else {
            None
        };

        index_module_for_language(
            &mut index,
            file_path,
            relative,
            language,
            go_module_path.as_deref(),
            rust_info,
        );
    }

    index
}

fn index_module_for_language(
    index: &mut HashMap<String, PathBuf>,
    file_path: &Path,
    relative: &Path,
    language: Language,
    go_module_path: Option<&str>,
    rust_crate_info: Option<(&Path, &str)>,
) {
    match language {
        Language::Python => index_python_module(index, file_path, relative),
        Language::TypeScript | Language::JavaScript => {
            index_ts_js_module(index, file_path, relative)
        }
        Language::Go => index_go_module(index, file_path, relative, go_module_path),
        Language::Rust => index_rust_module(index, file_path, relative, rust_crate_info),
        Language::Java => index_java_module(index, file_path, relative),
        Language::Kotlin => {
            let package = read_kotlin_package(file_path);
            index_kotlin_module(index, file_path, relative, package.as_deref());
        }
        Language::C | Language::Cpp => index_c_cpp_module(index, file_path, relative),
        Language::Ruby => index_ruby_module(index, file_path, relative),
        Language::CSharp => index_csharp_module(index, file_path, relative),
        Language::Scala => index_scala_module(index, file_path, relative),
        Language::Elixir => index_elixir_module(index, file_path, relative),
        Language::Ocaml => index_ocaml_module(index, file_path, relative),
        Language::Php => index_php_module(index, file_path, relative),
        Language::Lua | Language::Luau => index_lua_module(index, file_path, relative),
        // solidity-deps-v1 (v0.5.0 SOL-007): Solidity import paths are
        // filesystem-relative. Register each `.sol` under (a) its
        // project-relative path verbatim (matches Foundry remappings
        // like `contracts/MyLib.sol`) and (b) the bare leaf name
        // (matches `import "MyLib.sol"` when the consumer is sloppy).
        Language::Solidity => index_solidity_module(index, file_path, relative),
        // RC2 (v0.5.0 R7 cluster[10], #236): Swift modules are
        // directory-based — a `Sources/<Module>/` dir IS the importable
        // module (`import HeapModule`). Register every Swift file under its
        // owning module name so `import HeapModule` resolves to any file in
        // `Sources/HeapModule/`.
        Language::Swift => index_swift_module(index, file_path, relative),
        _ => {}
    }
}

/// Index a Solidity `.sol` file under every reasonable spelling that
/// an `import "..."` directive may use to reference it.
///
/// solidity-deps-v1 (v0.5.0 SOL-007). Solidity has no Python-style
/// dotted module names; every `import` is a filesystem path string.
/// We register:
///   * `src/foo/Bar.sol`   — project-relative path verbatim (the
///     remapping-target spelling that `import "src/foo/Bar.sol";`
///     yields after Foundry's `remappings.txt` expansion).
///   * `foo/Bar.sol`       — for each ancestor prefix peeled off,
///     so a sibling file's `import "Bar.sol"` from inside `src/foo/`
///     resolves via the relative-path normalisation in
///     `resolve_solidity_import`.
///   * `Bar.sol`           — bare leaf name (sloppy single-segment
///     import).
fn index_solidity_module(
    index: &mut HashMap<String, PathBuf>,
    file_path: &Path,
    relative: &Path,
) {
    let fp = file_path.to_path_buf();
    let rel_str = relative.to_string_lossy().to_string();
    if !rel_str.is_empty() {
        index.insert(rel_str.clone(), fp.clone());
    }

    if let Some(name) = relative.file_name() {
        let name_str = name.to_string_lossy().to_string();
        index.entry(name_str).or_insert_with(|| fp.clone());
    }
}

/// Index a Swift source file under the name of the SwiftPM module it belongs
/// to.
///
/// RC2 (v0.5.0 R7 cluster[10], #236). Swift has no per-file module
/// declaration: a target/module is a *directory* under `Sources/` (or
/// `Tests/`). `import HeapModule` brings in every public symbol of the
/// `Sources/HeapModule/` directory. So we derive the module name from the
/// path — the path segment immediately following the first `Sources` (or
/// `Tests`/`Source`/`src`) component — and register the file under it. The
/// first file seen for a module wins as its representative (`or_insert`), so
/// `import HeapModule` resolves to a stable file in that module. A flat
/// layout (no `Sources/`) falls back to registering each file under its bare
/// stem so single-directory packages still resolve.
fn index_swift_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();

    if let Some(module) = swift_module_name(relative) {
        index.entry(module).or_insert_with(|| fp.clone());
    }

    // Fallback spelling: bare file stem (covers `import` of a flat-layout
    // single-file module and keeps single-dir packages resolvable).
    if let Some(stem) = relative.file_stem() {
        let stem_str = stem.to_string_lossy().to_string();
        if !stem_str.is_empty() {
            index.entry(stem_str).or_insert_with(|| fp.clone());
        }
    }
}

/// Derive the SwiftPM module name for a project-relative path by taking the
/// path segment that immediately follows the source-root component
/// (`Sources` / `Source` / `Tests` / `src`). Returns `None` for a flat
/// layout with no recognised source root.
fn swift_module_name(relative: &Path) -> Option<String> {
    let components: Vec<String> = relative
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    for (i, comp) in components.iter().enumerate() {
        if matches!(comp.as_str(), "Sources" | "Source" | "Tests" | "src") {
            // The module dir is the next component; require at least one
            // further component after it (the file leaf) so we never treat
            // the file itself as the module name.
            if i + 2 < components.len() {
                return components.get(i + 1).cloned();
            }
        }
    }
    None
}

/// Index a Lua/Luau source file under every reasonable spelling that a
/// `require()` call may use to reference it.
///
/// (pdg-bounds-and-stdout-hygiene-v1 P11.BUG-AGG-15) Without this, every
/// Lua project reported zero internal dependencies because the deps
/// resolver had no Lua entry — `tldr deps lua-lsp/script` showed 247
/// files with 0 internal_dependencies despite valid `require("...")`
/// imports throughout. Lua's idiom `require("foo.bar")` maps a dot-
/// separated module path to the filesystem `foo/bar.lua`, so we register
/// the file under:
///   - `foo/bar`           — relative path (filesystem form)
///   - `foo.bar`           — dotted form (require argument)
///   - `bar`               — bare leaf name
///
/// Any of these spellings will match against the `module` field on a
/// captured `ImportInfo` from the require-call extractor.
fn index_lua_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy().to_string();

    // Canonical filesystem-relative form: "src/foo/bar"
    index.insert(stem_str.clone(), fp.clone());

    // Dotted module form: "src.foo.bar" — what require("src.foo.bar") passes
    let dotted = path_to_module_name(&stem);
    if !dotted.is_empty() && dotted != stem_str {
        index
            .entry(dotted)
            .or_insert_with(|| fp.clone());
    }

    // Bare leaf name: "bar" — what require("bar") might pass for a
    // top-level module that happens to live in a subdirectory of
    // package.path. We use `entry().or_insert_with` so that an existing
    // bare-name registration (e.g. from a same-named root module) wins.
    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        if name_str != "init" {
            index
                .entry(name_str.to_string())
                .or_insert_with(|| fp.clone());
        }
    }

    // Lua package convention: foo/init.lua is loaded by `require("foo")`.
    if relative.ends_with("init.lua") || relative.ends_with("init.luau") {
        if let Some(parent) = stem.parent() {
            let parent_dotted = path_to_module_name(parent);
            if !parent_dotted.is_empty() {
                index
                    .entry(parent_dotted)
                    .or_insert_with(|| fp.clone());
            }
            let parent_relative = parent.to_string_lossy().to_string();
            if !parent_relative.is_empty() {
                index
                    .entry(parent_relative)
                    .or_insert_with(|| fp.clone());
            }
            if let Some(parent_name) = parent.file_name() {
                index
                    .entry(parent_name.to_string_lossy().to_string())
                    .or_insert_with(|| fp.clone());
            }
        }
    }
}

fn index_python_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let module_path = path_to_module_name(&stem);
    index.insert(module_path, fp.clone());

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        if name_str != "__init__" {
            index.insert(name_str.to_string(), fp.clone());
        }
    }

    if relative.ends_with("__init__.py") {
        if let Some(parent) = stem.parent() {
            let parent_module = path_to_module_name(parent);
            index.insert(parent_module, fp.clone());
            if let Some(pkg_name) = parent.file_name() {
                index.insert(pkg_name.to_string_lossy().to_string(), fp.clone());
            }
        }
    }
}

fn index_ts_js_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy();
    index.insert(format!("./{}", stem_str), fp.clone());

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        if name_str != "index" {
            index.insert(format!("./{}", name_str), fp.clone());
        }
    }

    if relative.file_stem() == Some(std::ffi::OsStr::new("index")) {
        if let Some(parent) = stem.parent() {
            index.insert(format!("./{}", parent.display()), fp.clone());
        }
    }
}

fn index_go_module(
    index: &mut HashMap<String, PathBuf>,
    file_path: &Path,
    relative: &Path,
    go_module_path: Option<&str>,
) {
    let fp = file_path.to_path_buf();
    let pkg_dir = relative
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    if !pkg_dir.is_empty() {
        index.insert(pkg_dir.clone(), fp.clone());
    }

    if let Some(mod_path) = go_module_path {
        if pkg_dir.is_empty() {
            index.insert(mod_path.to_string(), fp.clone());
        } else {
            index.insert(format!("{}/{}", mod_path, pkg_dir), fp.clone());
        }
    }
}

/// Synthetic key prefix that stashes per-file rust crate metadata into the
/// generic `HashMap<String, PathBuf>` returned by [`build_module_index`].
///
/// The leading `\0` byte makes these keys unreachable from any real rust
/// import string (a NUL byte cannot appear in a `use` path), so they
/// coexist safely with the canonical `crate::foo::bar` entries.
///
/// Schema:
///   - `\0rust_meta::file::<abs_file>` -> the file's owning crate root dir
///   - `\0rust_meta::crate_name::<abs_crate_root>` -> a PathBuf whose
///     single leaf component is the crate's name (e.g. `Path::new("core")`).
///     We store names this way because the side-channel must live in a
///     `HashMap<String, PathBuf>` and we don't want a second map.
///   - `\0rust_meta::src_rel::<abs_file>` -> the file's path relative to
///     `<crate_root>/src/` (or to `<crate_root>` if there is no src/).
///     Used by `crate::`/`self::`/`super::` resolution and by sibling
///     `mod foo;` resolution.
///   - `\0rust_meta::sibling::<abs_dir>::<simple_name>` -> sibling file
///     under `<abs_dir>` matching `<simple_name>.rs` or
///     `<simple_name>/mod.rs`. Used to resolve `mod foo;` declarations
///     to the actual sibling file rather than a global bare-name match.
const RUST_META_PREFIX: &str = "\0rust_meta::";

fn rust_meta_file_key(abs_file: &Path) -> String {
    format!("{}file::{}", RUST_META_PREFIX, abs_file.display())
}

fn rust_meta_crate_name_key(abs_crate_root: &Path) -> String {
    format!("{}crate_name::{}", RUST_META_PREFIX, abs_crate_root.display())
}

fn rust_meta_src_rel_key(abs_file: &Path) -> String {
    format!("{}src_rel::{}", RUST_META_PREFIX, abs_file.display())
}

fn rust_meta_sibling_key(abs_dir: &Path, simple_name: &str) -> String {
    format!(
        "{}sibling::{}::{}",
        RUST_META_PREFIX,
        abs_dir.display(),
        simple_name
    )
}

/// Read the `[package].name` (or `[lib].name`) declaration from a
/// `Cargo.toml`. Returns `None` if the file does not exist, is unparseable,
/// or has no `name` field.
///
/// Hand-rolled parser — we only need the `name = "..."` line inside the
/// first `[package]` or `[lib]` section. This avoids pulling in a full TOML
/// dependency for the deps analyzer.
fn read_cargo_package_name(cargo_toml_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(cargo_toml_path).ok()?;
    let mut in_package = false;
    let mut in_lib = false;
    let mut package_name: Option<String> = None;
    let mut lib_name: Option<String> = None;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_package = section.trim() == "package";
            in_lib = section.trim() == "lib";
            continue;
        }
        if !(in_package || in_lib) {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().map(str::trim).unwrap_or("");
        let val = parts.next().map(str::trim).unwrap_or("");
        if key != "name" {
            continue;
        }
        let raw_val = val.trim_end_matches(|c: char| c == '#' || c.is_whitespace());
        let unquoted = raw_val
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if unquoted.is_empty() {
            continue;
        }
        if in_lib {
            lib_name = Some(unquoted);
        } else {
            package_name = Some(unquoted);
        }
    }
    // `[lib].name` overrides `[package].name` for the crate's import name
    // (and rustc replaces hyphens with underscores in that import name).
    lib_name.or(package_name).map(|s| s.replace('-', "_"))
}

/// Find the nearest ancestor directory of `file_path` that owns a
/// `Cargo.toml` and contains either `src/lib.rs`, `src/main.rs`, or a
/// file under `src/` matching `file_path`. Returns `(crate_root, crate_name)`.
///
/// Walks up at most until `repo_root` (inclusive). Returns `None` when no
/// such ancestor exists — the file is then treated as crate-less and only
/// the path-based fallback applies during resolution.
fn find_rust_crate_root(file_path: &Path, repo_root: &Path) -> Option<(PathBuf, String)> {
    let mut current = file_path.parent()?;
    loop {
        let cargo = current.join("Cargo.toml");
        if cargo.is_file() {
            if let Some(name) = read_cargo_package_name(&cargo) {
                return Some((current.to_path_buf(), name));
            }
        }
        if current == repo_root {
            return None;
        }
        current = match current.parent() {
            Some(p) => p,
            None => return None,
        };
    }
}

/// Compute the file's module path relative to its crate's source root.
///
/// For a typical layout `<crate_root>/src/foo/bar.rs` this returns
/// `Some("foo/bar")`. For `<crate_root>/src/lib.rs` it returns
/// `Some("")` (the crate root module itself). When the file lives
/// outside `<crate_root>/src/` (e.g. `tests/`, `examples/`, `benches/`,
/// or a workspace `build.rs`), returns `None` — such files cannot host
/// canonical `crate::` paths.
fn rust_src_relative(file_path: &Path, crate_root: &Path) -> Option<String> {
    let rel = file_path.strip_prefix(crate_root).ok()?;
    let rel_str = rel.to_string_lossy();
    let body = rel_str
        .strip_prefix("src/")
        .or_else(|| rel_str.strip_prefix("src\\"))?;
    let no_ext = body
        .strip_suffix(".rs")
        .or_else(|| body.strip_suffix(".RS"))
        .unwrap_or(body);
    Some(no_ext.replace('\\', "/"))
}

/// Index a Rust source file for `tldr deps` import resolution.
///
/// (rust-deps-wiring-v1 / VAL-RUST-DEPS) Pre-fix this function inserted
/// every rust file under its bare basename (`tests`, `mod`, ...) into a
/// shared global namespace. In a real workspace (e.g. ripgrep with
/// 9 crates) that caused `mod tests;` declarations at the bottom of
/// `crates/cli/src/escape.rs`, `crates/searcher/src/lines.rs`, and dozens
/// of other unit-test-bearing files to all resolve to the *integration*
/// test file `tests/tests.rs` — 36 spurious incoming edges to a single
/// node. Cross-crate `use ignore::WalkState` from `crates/core/main.rs`
/// fell through entirely because nothing in the index spelled `ignore`.
///
/// Post-fix indexing strategy:
///   1. Discover the file's owning crate via the nearest ancestor
///      `Cargo.toml` (`find_rust_crate_root`). Register the file under
///      `<crate_name>::<src_rel>` — what a workspace cross-crate
///      `use other_crate::foo` resolves against.
///   2. For the crate's `src/lib.rs` or `src/main.rs`, also register the
///      bare crate name so `use ignore` and `extern crate ignore;` both
///      hit the crate root.
///   3. Stash side-channel metadata (crate root, src-relative path,
///      sibling map entries) under reserved `\0rust_meta::` keys so the
///      resolver can do per-file context-sensitive lookups without
///      maintaining a parallel data structure. See [`RUST_META_PREFIX`].
///
/// Notable removal: the unconditional bare-name (`tests`, `walk`, ...)
/// insertion is GONE. `mod foo;` declarations now resolve only against
/// the file's own sibling tree (handled in `resolve_rust_import`), not
/// against any rust file with that basename elsewhere in the repo.
fn index_rust_module(
    index: &mut HashMap<String, PathBuf>,
    file_path: &Path,
    relative: &Path,
    crate_info: Option<(&Path, &str)>,
) {
    let fp = file_path.to_path_buf();

    // ---- Sibling registration ------------------------------------------
    //
    // For `mod foo;` resolution we need to map a (parent_dir, simple_name)
    // pair to the corresponding rust file. There are two shapes that
    // satisfy a `mod foo;` declaration in `<dir>/<host>.rs`:
    //   1. <dir>/foo.rs   — flat sibling file
    //   2. <dir>/foo/mod.rs — directory module via mod.rs
    //
    // Both are siblings of the parent of the `<host>.rs` file. The
    // canonical sibling base directory is `file_path.parent()`. We
    // additionally handle the `mod.rs` self-case: a `mod foo;` inside
    // `<dir>/<sub>/mod.rs` looks for `<dir>/<sub>/foo.rs` or
    // `<dir>/<sub>/foo/mod.rs` (same parent), which is already covered.
    if let Some(parent) = file_path.parent() {
        // file lives directly in `parent` — register it under its file
        // stem (e.g. `crates/.../foo.rs` -> sibling `foo` at `parent`).
        if let Some(stem) = relative.file_stem().and_then(|s| s.to_str()) {
            if stem != "mod" && stem != "lib" && stem != "main" {
                index
                    .entry(rust_meta_sibling_key(parent, stem))
                    .or_insert_with(|| fp.clone());
            }
        }
        // file is a `mod.rs` — register it as the directory module of
        // the *grandparent* directory under the directory's own name.
        // (e.g. `crates/.../foo/mod.rs` -> sibling `foo` at `<...>/`)
        if relative.file_stem() == Some(std::ffi::OsStr::new("mod")) {
            if let (Some(grandparent), Some(dir_name)) =
                (parent.parent(), parent.file_name().and_then(|n| n.to_str()))
            {
                index
                    .entry(rust_meta_sibling_key(grandparent, dir_name))
                    .or_insert_with(|| fp.clone());
            }
        }
    }

    // ---- Crate-aware registration -------------------------------------
    if let Some((crate_root, crate_name)) = crate_info {
        // Stash per-file metadata: which crate, and what is the file's
        // path relative to the crate's src/ root.
        index.insert(rust_meta_file_key(file_path), crate_root.to_path_buf());
        index.insert(
            rust_meta_crate_name_key(crate_root),
            PathBuf::from(crate_name),
        );
        if let Some(src_rel) = rust_src_relative(file_path, crate_root) {
            index.insert(
                rust_meta_src_rel_key(file_path),
                PathBuf::from(src_rel.clone()),
            );

            // The crate's lib.rs / main.rs IS the crate root module —
            // register the bare crate name so cross-crate
            // `use other_crate::foo` resolves to it.
            if src_rel.is_empty() || src_rel == "lib" || src_rel == "main" {
                index
                    .entry(crate_name.to_string())
                    .or_insert_with(|| fp.clone());
            } else {
                // `<crate_name>::<dotted-mod-path>` — what cross-crate
                // imports look up directly.
                let dotted = src_rel.replace('/', "::");
                index
                    .entry(format!("{}::{}", crate_name, dotted))
                    .or_insert_with(|| fp.clone());

                // For directory modules (`<crate_name>/src/foo/mod.rs`),
                // the canonical import path is `<crate_name>::foo`, not
                // `<crate_name>::foo::mod`. Strip a trailing `::mod`.
                if let Some(without_mod) = dotted.strip_suffix("::mod") {
                    index
                        .entry(format!("{}::{}", crate_name, without_mod))
                        .or_insert_with(|| fp.clone());
                }
            }
        }
    }

    // ---- Legacy path-based fallback -----------------------------------
    //
    // Preserve the pre-fix `crate::<path-as-mod>` registration so the
    // existing test corpus (and any project we haven't crate-detected)
    // still gets *some* resolution. Note we keep this BUT we no longer
    // emit the global bare-name basename — that was the source of the
    // 36-incoming-edges bug.
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy();
    let crate_path = stem_str.replace('/', "::");
    if crate_path.starts_with("src::") {
        let without_src = crate_path.strip_prefix("src::").unwrap_or(&crate_path);
        index
            .entry(format!("crate::{}", without_src))
            .or_insert_with(|| fp.clone());
    }
    index
        .entry(format!("crate::{}", crate_path))
        .or_insert_with(|| fp.clone());

    if relative.file_stem() == Some(std::ffi::OsStr::new("mod")) {
        if let Some(parent_path) = stem.parent() {
            if let Some(pkg_name) = parent_path.file_name() {
                index
                    .entry(format!("crate::{}", pkg_name.to_string_lossy()))
                    .or_insert_with(|| fp.clone());
            }
        }
    }
}

/// Strip the longest known source-root prefix from a relative path, matching
/// anywhere on a `/` boundary (handles nested/multi-module projects like
/// `backend/src/main/java/com/example/Foo`).
fn strip_jvm_prefix<'a>(path: &'a str, prefixes: &[&str]) -> &'a str {
    let mut best_end: Option<usize> = None;
    let mut best_prefix_len: usize = 0;
    for prefix in prefixes {
        if let Some(pos) = path.find(prefix) {
            if (pos == 0 || path.as_bytes()[pos - 1] == b'/') && prefix.len() > best_prefix_len {
                best_prefix_len = prefix.len();
                best_end = Some(pos + prefix.len());
            }
        }
    }
    if let Some(end) = best_end {
        &path[end..]
    } else {
        path
    }
}

fn index_java_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let path_str = stem.to_string_lossy();
    let cleaned = strip_jvm_prefix(
        &path_str,
        &["src/main/java/", "src/test/java/", "src/", "lib/", "app/"],
    );
    let qualified_name = cleaned.replace(['/', '\\'], ".");
    if !qualified_name.is_empty() {
        index.insert(qualified_name, fp.clone());
    }
    if let Some(class_name) = stem.file_name() {
        let name_str = class_name.to_string_lossy();
        if !name_str.is_empty() {
            index.insert(name_str.to_string(), fp.clone());
        }
    }
}

/// Index a Kotlin source file for `tldr deps` import resolution.
///
/// (kotlin-deps-wiring-v1 / VAL-KT-DEPS) Kotlin's package declarations
/// are decoupled from the on-disk directory layout — `core/common/src/Instant.kt`
/// can declare `package kotlinx.datetime`. The Java-style "infer the FQN from
/// the path" heuristic therefore registers files under names that no real
/// kotlin import will ever spell. Pre-fix, that meant
/// `tldr deps /tmp/repos/kotlin-datetime` produced zero internal edges
/// across 223 files.
///
/// Post-fix, when the caller can pass in the file's actual
/// `package <qualified.name>` declaration we register the file under:
///   - `<package>.<simple-name>` — what `import com.foo.bar.Simple` looks up
///   - `<package>` — used as the wildcard target (`import com.foo.bar.*`)
///     resolution scan in [`resolve_kotlin_import`]
///   - the bare simple name (last-resort matching for top-level files)
///
/// We still keep the path-derived qualified name as a fallback for the
/// (rare) case where the project actually does follow `src/main/kotlin/foo/Bar.kt`
/// without an overriding `package`.
fn index_kotlin_module(
    index: &mut HashMap<String, PathBuf>,
    file_path: &Path,
    relative: &Path,
    package: Option<&str>,
) {
    let fp = file_path.to_path_buf();
    let stem_path = relative.with_extension("");
    let path_str = stem_path.to_string_lossy();
    // Also strip .kts if with_extension("") didn't catch it (e.g. "build.gradle.kts")
    let path_str_ref: &str = &path_str;
    let stripped = path_str_ref.strip_suffix(".kts").unwrap_or(path_str_ref);
    let cleaned = strip_jvm_prefix(
        stripped,
        &[
            "src/main/kotlin/",
            "src/test/kotlin/",
            "src/",
            "lib/",
            "app/",
        ],
    );
    let qualified_name = cleaned.replace(['/', '\\'], ".");
    if !qualified_name.is_empty() {
        index.insert(qualified_name, fp.clone());
    }

    let simple = relative
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    if !simple.is_empty() {
        // Bare simple name. Use entry/or_insert so the first-seen file wins
        // (avoids overwriting on duplicate basenames across modules).
        index.entry(simple.clone()).or_insert_with(|| fp.clone());
    }

    if let Some(pkg) = package {
        let pkg = pkg.trim();
        if !pkg.is_empty() {
            // Canonical FQN — what `import <pkg>.<simple>` will look up.
            if !simple.is_empty() {
                let fqn = format!("{}.{}", pkg, simple);
                index.insert(fqn, fp.clone());
            }
            // Package itself — used by the wildcard import scan
            // (`import <pkg>.*`) so we don't have to walk every key.
            // First file in a package wins (deterministic).
            index.entry(pkg.to_string()).or_insert_with(|| fp.clone());
        }
    }
}

/// Read the `package <qualified.name>` declaration from a Kotlin source file.
///
/// (kotlin-deps-wiring-v1) Kotlin packages are independent of directory
/// layout, so we have to read the declaration directly. We scan only the
/// first ~64 lines and bail at the first `class`/`fun`/`object` token,
/// which is enough for any well-formed Kotlin file (the `package` line
/// must precede all declarations).
///
/// Returns `None` for files with no package declaration (top-level
/// scripts, `build.gradle.kts`, etc.).
fn read_kotlin_package(file_path: &Path) -> Option<String> {
    // Cap the read at 4KB — package always lives near the top, and we
    // do not want to slurp megabyte generated files (e.g. `zoneInfos.kt`).
    let bytes = match std::fs::read(file_path) {
        Ok(b) => b,
        Err(_) => return None,
    };
    let head = if bytes.len() > 4096 {
        &bytes[..4096]
    } else {
        &bytes[..]
    };
    let text = std::str::from_utf8(head).ok()?;

    // Strip /* ... */ block comments by walking byte-by-byte. Kotlin
    // headers commonly begin with a copyright block comment, so this is
    // the easiest way to skip them without misreading `package` from
    // inside the comment.
    let mut cleaned = String::with_capacity(text.len());
    {
        let bytes = text.as_bytes();
        let mut i = 0;
        let mut in_block = false;
        while i < bytes.len() {
            if in_block {
                if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    in_block = false;
                    i += 2;
                } else {
                    i += 1;
                }
            } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                in_block = true;
                i += 2;
            } else {
                cleaned.push(bytes[i] as char);
                i += 1;
            }
        }
    }

    for raw_line in cleaned.lines() {
        let mut line = raw_line.trim();
        // Strip line comment
        if let Some(pos) = line.find("//") {
            line = line[..pos].trim();
        }
        if line.is_empty() {
            continue;
        }
        // Skip file-level annotations (`@file:JvmName(...)`, etc.)
        if line.starts_with('@') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("package") {
            // Must be followed by whitespace, not e.g. `packageX`.
            let rest = match rest.chars().next() {
                Some(c) if c.is_whitespace() => rest.trim_start(),
                _ => continue,
            };
            // Drop trailing semicolon / inline comment crumbs, then keep
            // only the qualified-id chars to be defensive.
            let pkg: String = rest
                .trim_end_matches(';')
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '_')
                .collect();
            if !pkg.is_empty() {
                return Some(pkg);
            }
            return None;
        }

        // Package can only appear before any import or declaration.
        // If we see one of these without having seen `package`, abort.
        if line.starts_with("import")
            || line.starts_with("class ")
            || line.starts_with("fun ")
            || line.starts_with("object ")
            || line.starts_with("interface ")
            || line.starts_with("typealias ")
            || line.starts_with("enum ")
            || line.starts_with("val ")
            || line.starts_with("var ")
        {
            return None;
        }
    }
    None
}

fn index_c_cpp_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    index.insert(relative.to_string_lossy().to_string(), fp.clone());
    if let Some(name) = relative.file_name() {
        index.insert(name.to_string_lossy().to_string(), fp.clone());
    }

    let components: Vec<_> = relative.components().collect();
    for start in 1..components.len() {
        let sub_path: PathBuf = components[start..].iter().collect();
        let sub_str = sub_path.to_string_lossy().to_string();
        index.entry(sub_str).or_insert_with(|| fp.clone());
    }
}

fn index_ruby_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy().to_string();
    index.insert(stem_str.clone(), fp.clone());

    let stripped = stem_str
        .strip_prefix("lib/")
        .or_else(|| stem_str.strip_prefix("app/"));
    if let Some(s) = stripped {
        index.insert(s.to_string(), fp.clone());
    }

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        index
            .entry(name_str.to_string())
            .or_insert_with(|| fp.clone());
    }
}

fn index_csharp_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let path_str = stem.to_string_lossy();
    // (deps-external-internal-classifier-v1 / M-048) Many .NET solutions
    // use `Src/` (capital S) as the source root (e.g. Newtonsoft.Json.Bson:
    // `Src/Newtonsoft.Json.Bson/BsonDataReader.cs`). The pre-fix
    // `strip_jvm_prefix(&["src/"...])` was case-sensitive and so left
    // `Src.Newtonsoft.Json.Bson.BsonDataReader` in the index — but
    // `using Newtonsoft.Json.Bson;` would never match this `Src.`-prefixed
    // key. Strip both casings.
    let cleaned = strip_jvm_prefix(
        &path_str,
        &["src/", "Src/", "lib/", "Lib/", "app/", "App/"],
    );
    let qualified = cleaned.replace(['/', '\\'], ".");
    if !qualified.is_empty() {
        index.insert(qualified, fp.clone());
    }
    if let Some(parent) = Path::new(cleaned).parent() {
        let ns = parent.to_string_lossy().replace(['/', '\\'], ".");
        if !ns.is_empty() {
            index.entry(ns).or_insert_with(|| fp.clone());
        }
    }
    if let Some(class_name) = stem.file_name() {
        let name_str = class_name.to_string_lossy();
        if !name_str.is_empty() {
            index
                .entry(name_str.to_string())
                .or_insert_with(|| fp.clone());
        }
    }
}

fn index_scala_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let path_str = stem.to_string_lossy();
    let cleaned = strip_jvm_prefix(
        &path_str,
        &["src/main/scala/", "src/test/scala/", "src/", "lib/", "app/"],
    );
    let qualified = cleaned.replace(['/', '\\'], ".");
    if !qualified.is_empty() {
        index.insert(qualified, fp.clone());
    }
    if let Some(parent) = Path::new(cleaned).parent() {
        let pkg = parent.to_string_lossy().replace(['/', '\\'], ".");
        if !pkg.is_empty() {
            index.entry(pkg).or_insert_with(|| fp.clone());
        }
    }
    if let Some(class_name) = stem.file_name() {
        let name_str = class_name.to_string_lossy();
        if !name_str.is_empty() {
            index
                .entry(name_str.to_string())
                .or_insert_with(|| fp.clone());
        }
    }
}

fn index_elixir_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy().to_string();
    index.insert(stem_str.clone(), fp.clone());

    let stripped = stem_str
        .strip_prefix("lib/")
        .or_else(|| stem_str.strip_prefix("test/"));
    if let Some(s) = stripped {
        index.insert(s.to_string(), fp.clone());
        let module_name = s
            .split('/')
            .map(|part| part.split('_').map(capitalize_first).collect::<String>())
            .collect::<Vec<_>>()
            .join(".");
        if !module_name.is_empty() {
            index.insert(module_name, fp.clone());
        }
    }

    // language-adapters-completeness-v1 (BUG-AGG12-8): always derive
    // the canonical Elixir module name from the relative path, not
    // only when the path begins with `lib/` or `test/`. Users
    // commonly run `tldr deps lib` (or another sub-dir of a Mix
    // project) so the relative path strips the `lib/` prefix
    // entirely. Without this fallback, every `alias My.Module` in
    // the corpus failed to resolve and the deps report read
    // `total_internal_deps: 0` despite hundreds of valid aliases.
    let module_name = stem_str
        .split('/')
        .map(|part| part.split('_').map(capitalize_first).collect::<String>())
        .collect::<Vec<_>>()
        .join(".");
    if !module_name.is_empty() {
        index.entry(module_name).or_insert_with(|| fp.clone());
    }

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        index
            .entry(name_str.to_string())
            .or_insert_with(|| fp.clone());
    }
}

fn index_ocaml_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy().to_string();
    index.insert(stem_str.clone(), fp.clone());

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        let module_name = capitalize_first(&name_str);
        if !module_name.is_empty() {
            index.entry(module_name).or_insert_with(|| fp.clone());
        }
    }

    let dot_path = stem_str.replace('/', ".");
    if dot_path.contains('.') {
        let capitalized = dot_path
            .split('.')
            .map(capitalize_first)
            .collect::<Vec<_>>()
            .join(".");
        index.entry(capitalized).or_insert_with(|| fp.clone());
    }
}

fn index_php_module(index: &mut HashMap<String, PathBuf>, file_path: &Path, relative: &Path) {
    let fp = file_path.to_path_buf();
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy().to_string();
    index.insert(stem_str.clone(), fp.clone());

    let stripped = stem_str
        .strip_prefix("src/")
        .or_else(|| stem_str.strip_prefix("app/"))
        .or_else(|| stem_str.strip_prefix("lib/"));
    if let Some(s) = stripped {
        index.insert(s.to_string(), fp.clone());
    }

    let namespace = stem_str.replace('/', "\\");
    if !namespace.is_empty() {
        index.insert(namespace, fp.clone());
    }

    if let Some(name) = stem.file_name() {
        let name_str = name.to_string_lossy();
        index
            .entry(name_str.to_string())
            .or_insert_with(|| fp.clone());
    }
}

/// Resolve an import to a file path.
///
/// Handles relative imports (S7-R3) by using the current file's location
/// as context for resolving relative module paths.
fn resolve_import(
    import: &ImportInfo,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
    language: Language,
) -> Option<PathBuf> {
    let module = &import.module;

    match language {
        Language::Python => resolve_python_import(module, root, current_file, index),
        Language::TypeScript | Language::JavaScript => {
            resolve_ts_import(module, root, current_file, index)
        }
        Language::Go => resolve_go_import(module, index),
        Language::Rust => resolve_rust_import(module, current_file, index),
        Language::Java => resolve_java_import(module, root, current_file, index),
        Language::Kotlin => resolve_kotlin_import(module, index),
        Language::C | Language::Cpp => resolve_c_cpp_import(import, root, current_file, index),
        Language::Ruby => resolve_ruby_import(import, root, current_file, index),
        Language::CSharp => resolve_csharp_import(import, root, current_file, index),
        Language::Scala => resolve_scala_import(import, root, current_file, index),
        Language::Elixir => resolve_elixir_import(import, root, current_file, index),
        Language::Ocaml => resolve_ocaml_import(import, root, current_file, index),
        Language::Php => resolve_php_import(import, root, current_file, index),
        Language::Lua | Language::Luau => resolve_lua_import(import, index),
        Language::Solidity => resolve_solidity_import(import, root, current_file, index),
        // RC2 (v0.5.0 R7 cluster[10], #236): map a bare Swift module
        // identifier (`import HeapModule`) to a representative file in the
        // module's `Sources/<Module>/` directory.
        Language::Swift => resolve_swift_import(import, index),
        _ => None,
    }
}

/// Resolve a Solidity `import "<path>"` directive to a file path.
///
/// solidity-deps-v1 (v0.5.0 SOL-007). Strategy (in order):
///   1. **Relative spellings (`./X`, `../X`)** — normalise against the
///      current file's directory and look up under the project-relative
///      form registered by [`index_solidity_module`].
///   2. **Bare project-rooted spellings (`contracts/X.sol`)** — direct
///      index lookup. This is Foundry's `remappings.txt`-expanded form,
///      where the leading segment is the source-tree root.
///   3. **Bare leaf name (`X.sol`)** — index entry for the file's leaf,
///      tolerates sloppy single-segment imports.
///   4. **External-package prefixes** (`@openzeppelin/contracts/...`,
///      `solmate/...`, …) are *not* resolved here — they fall through
///      to `classify_import`'s External arm. We return `None` for any
///      module starting with `@` (npm-scoped) so we don't accidentally
///      bucket OpenZeppelin as Internal.
fn resolve_solidity_import(
    import: &ImportInfo,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = import.module.trim();
    if module.is_empty() {
        return None;
    }

    // npm-scoped style — never project-local in practice; let the
    // External-package classifier handle it.
    if module.starts_with('@') {
        return None;
    }

    // 1. Relative spellings — resolve against current file's directory.
    if module.starts_with("./") || module.starts_with("../") {
        if let Some(parent) = current_file.parent() {
            let joined = parent.join(module);
            // Manually normalise `..` segments — `Path::canonicalize`
            // requires the target file to exist on disk, which is
            // sometimes the case here but we don't want to depend on
            // it.
            let normalised = normalise_path(&joined);
            if let Ok(relative) = normalised.strip_prefix(root) {
                let key = relative.to_string_lossy().to_string();
                if let Some(path) = index.get(&key) {
                    return Some(path.clone());
                }
            }
            // Final fallback — check whether the joined path itself is
            // a value in the index (some platforms canonicalise tmpdirs
            // through symlinks, so strip_prefix can fail).
            if normalised.exists() {
                return Some(normalised);
            }
        }
        return None;
    }

    // 2. Direct index lookup (Foundry-remapping-expanded form, or a
    // bare leaf name that the indexer registered).
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    None
}

/// Resolve a Swift `import <Module>` directive to a representative file in
/// that module's directory.
///
/// RC2 (v0.5.0 R7 cluster[10], #236). A Swift import names a SwiftPM
/// module (a `Sources/<Module>/` directory), not a file. `index_swift_module`
/// registered each module-directory under its name (first file wins as the
/// representative), so resolution is a direct index lookup of the bare module
/// identifier. Apple-SDK / Swift-runtime umbrellas (`Foundation`, `Swift`,
/// …) are NOT project-local; they are filtered by `is_swift_stdlib` in
/// `classify_import` and will simply miss the project index here (returning
/// `None`, which lets the stdlib/external classifier take over).
fn resolve_swift_import(import: &ImportInfo, index: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    let module = import.module.trim();
    if module.is_empty() {
        return None;
    }
    // Never resolve a stdlib/SDK umbrella to a coincidentally-named project
    // file (e.g. a local `Foundation.swift`). Stdlib imports must fall
    // through to the stdlib classifier, not become a bogus internal edge.
    if is_swift_stdlib(module) {
        return None;
    }
    // A Swift import head can carry a submodule (`os.log`); the importable
    // unit is the umbrella (first segment).
    let head = module.split('.').next().unwrap_or(module);
    index.get(head).or_else(|| index.get(module)).cloned()
}

/// Normalise a path by collapsing `./` and `../` segments without
/// touching the filesystem. Mirrors the logic upstream `path-clean`
/// crate uses; inlined here to avoid the dep.
fn normalise_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// =============================================================================
// Lua / Luau import resolution
// =============================================================================

/// Resolve a Lua `require("module.path")` to a file path within the project.
///
/// (pdg-bounds-and-stdout-hygiene-v1 P11.BUG-AGG-15) Lua's idiom maps the
/// dotted require argument to a filesystem path by replacing `.` with `/`
/// and appending `.lua`. We try a sequence of lookups against the index
/// populated by [`index_lua_module`]:
///   1. The raw module string as-is (covers an exact match in the index).
///   2. The dot-to-slash translation (`foo.bar` -> `foo/bar`) — what the
///      filesystem-relative entry was registered under.
///   3. Progressively shorter prefixes for nested module references that
///      may resolve to a parent `init.lua` (Lua package convention).
///   4. The bare leaf name as a last resort (matches a top-level module).
fn resolve_lua_import(
    import: &ImportInfo,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;
    if module.is_empty() {
        return None;
    }

    // 1. Direct lookup (exact spelling registered in index).
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // 2. Translate dotted form to filesystem-relative form.
    if module.contains('.') {
        let slashed = module.replace('.', "/");
        if let Some(path) = index.get(&slashed) {
            return Some(path.clone());
        }
    }

    // 3. Progressively shorter prefixes — useful when a deeper module is
    //    actually served by a parent `init.lua`.
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        for i in (1..parts.len()).rev() {
            let dotted_prefix = parts[..i].join(".");
            if let Some(path) = index.get(&dotted_prefix) {
                return Some(path.clone());
            }
            let slashed_prefix = parts[..i].join("/");
            if let Some(path) = index.get(&slashed_prefix) {
                return Some(path.clone());
            }
        }
    }

    // 4. Bare leaf name fallback.
    let leaf = parts.last().copied().unwrap_or(module.as_str());
    index.get(leaf).cloned()
}

/// Resolve Python import to file path.
///
/// Handles:
/// - Absolute imports: "from mypackage.utils import x" -> mypackage/utils.py
/// - Relative imports: "from .utils import x" -> current_dir/utils.py
/// - Deep relative: "from ..parent import x" -> parent_dir/parent.py
fn resolve_python_import(
    module: &str,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // Handle relative imports (S7-R3)
    if module.starts_with('.') {
        return resolve_python_relative_import(module, root, current_file, index);
    }

    // python-decoy-resolution-v1 (v0.5.0 T1 AUDIT-FIX): an absolute import
    // (`import flask` / `from flask import X`) is resolvable from a sys.path
    // ROOT — the project root or a recognised source root (`src/`). A file
    // buried at `tests/test_apps/cliapp/inner1/inner2/flask.py` has module
    // path `tests.test_apps.cliapp.inner1.inner2.flask`, NOT `flask`, so it is
    // NOT importable as bare `flask` and must never satisfy that query.
    //
    // Pre-fix `index_python_module` registered the bare leaf name of every
    // file, so the deep test fixture `flask.py` registered a bare `flask` key
    // that the direct lookup below returned — manufacturing 52 phantom
    // internal edges into the decoy across the flask corpus. We now require
    // the candidate's importable module path to actually MATCH the query
    // before accepting it.
    if let Some(path) = index.get(module) {
        if python_candidate_matches(path, module, root) {
            return Some(path.clone());
        }
    }

    // Try first component (from pkg.submodule import X -> pkg/submodule.py)
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        // Try progressively shorter prefixes
        for i in (1..=parts.len()).rev() {
            let prefix = parts[..i].join(".");
            if let Some(path) = index.get(&prefix) {
                if python_candidate_matches(path, &prefix, root) {
                    return Some(path.clone());
                }
            }
        }
    }

    None
}

/// Verify a candidate file is genuinely importable under the absolute module
/// name `module` from a sys.path root.
///
/// python-decoy-resolution-v1. The candidate's importable module path is its
/// path relative to `root`, with a recognised source root (`src/`) stripped,
/// path separators turned into `.`, and a trailing `.__init__` removed
/// (package import). The candidate matches iff that importable path EQUALS
/// `module`.
///
/// Equality (not a suffix rule) is deliberate: a bare `import flask` is
/// importable only as the top-level module `flask` from a sys.path root, so a
/// deeply-nested fixture whose importable path is
/// `tests.test_apps.cliapp.inner1.inner2.flask` (which merely *ends with*
/// `.flask`) is correctly rejected. A `src/`-rooted package
/// (`src/flask/__init__.py`) matches because `src.` is stripped first,
/// yielding the importable name `flask`.
fn python_candidate_matches(path: &Path, module: &str, root: &Path) -> bool {
    let rel = match path.strip_prefix(root) {
        Ok(r) => r,
        // Index entries are absolute project paths; if it isn't under root we
        // cannot reason about its importability — accept conservatively.
        Err(_) => return true,
    };
    let stem = rel.with_extension("");
    let mut importable = path_to_module_name(&stem);
    // Strip a trailing `.__init__` so `flask/__init__.py` -> `flask`.
    if let Some(base) = importable.strip_suffix(".__init__") {
        importable = base.to_string();
    }

    // Exact match against the on-disk path (covers `from src.utils import X`).
    if importable == module {
        return true;
    }
    // Otherwise treat `src/` as a sys.path root and retry (covers the common
    // `from utils import X` against `src/utils.py`). Only strip when the query
    // itself does NOT already carry the `src.` prefix (handled above).
    if let Some(rest) = importable.strip_prefix("src.") {
        return rest == module;
    }
    false
}

/// Resolve Python relative import.
///
/// Counts leading dots and walks up the directory tree accordingly.
fn resolve_python_relative_import(
    module: &str,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // Count leading dots
    let dot_count = module.chars().take_while(|c| *c == '.').count();
    let remainder = &module[dot_count..];

    // Start from current file's directory
    let current_dir = current_file.parent()?;

    // Walk up directories based on dot count
    // . = same directory, .. = parent, ... = grandparent, etc.
    let mut target_dir = current_dir.to_path_buf();
    for _ in 1..dot_count {
        target_dir = target_dir.parent()?.to_path_buf();
    }

    if remainder.is_empty() {
        // "from . import X" - look for __init__.py in current dir
        let init_path = target_dir.join("__init__.py");
        if init_path.exists() {
            return Some(init_path);
        }
        return None;
    }

    // Convert remainder to path components
    let parts: Vec<&str> = remainder.split('.').collect();
    for part in &parts {
        target_dir = target_dir.join(part);
    }

    // Try .py file
    let py_path = target_dir.with_extension("py");
    if py_path.exists() && py_path.starts_with(root) {
        return Some(py_path);
    }

    // Try __init__.py in directory
    let init_path = target_dir.join("__init__.py");
    if init_path.exists() && init_path.starts_with(root) {
        return Some(init_path);
    }

    // Try index lookup with relative path
    let relative_target = target_dir.strip_prefix(root).ok()?;
    let module_name = path_to_module_name(relative_target);
    index.get(&module_name).cloned()
}

/// Resolve TypeScript/JavaScript import to file path.
fn resolve_ts_import(
    module: &str,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // Handle relative imports
    if module.starts_with("./") || module.starts_with("../") {
        let current_dir = current_file.parent()?;
        let resolved = current_dir.join(module);
        let normalized = normalize_path(&resolved);

        // Try with various extensions
        for ext in &[".ts", ".tsx", ".js", ".jsx"] {
            let with_ext = normalized.with_extension(&ext[1..]);
            if with_ext.exists() && with_ext.starts_with(root) {
                return Some(with_ext);
            }
        }

        // Try index file
        for ext in &[".ts", ".tsx", ".js", ".jsx"] {
            let index_path = normalized.join(format!("index{}", ext));
            if index_path.exists() && index_path.starts_with(root) {
                return Some(index_path);
            }
        }
    }

    // Try index lookup
    index.get(module).cloned()
}

/// Resolve Go import to file path.
fn resolve_go_import(module: &str, index: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    // Go imports are package paths
    // Try the full path, then try last component
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Try just the last component
    if let Some(last) = module.rsplit('/').next() {
        if let Some(path) = index.get(last) {
            return Some(path.clone());
        }
    }

    None
}

/// Resolve Rust import to file path.
/// Resolve a rust `use` / `mod` / `extern crate` reference to a file path
/// inside the project.
///
/// (rust-deps-wiring-v1 / VAL-RUST-DEPS) Replaces the prior global-bare-name
/// resolver, which routed every `mod tests;` declaration through whichever
/// rust file happened to be named `tests.rs` first. Resolution now follows
/// rust's real module rules:
///
/// 1. **stdlib filter.** `std::`, `core::`, `alloc::` are external —
///    never internal.
/// 2. **Bare name (no `::`).** Comes from `mod foo;` and from external
///    crate names. First try as a *sibling* file of `current_file`
///    (`<dir>/foo.rs` or `<dir>/foo/mod.rs`) via the per-file sibling
///    index populated by [`index_rust_module`]. If that misses, fall
///    back to a workspace cross-crate match (`use foo;` referring to
///    a workspace member crate's `lib.rs`).
/// 3. **`crate::foo::bar`.** Use the current file's crate (looked up in
///    the stashed `\0rust_meta::` metadata) and query the
///    `<crate_name>::foo::bar` index entry. Falls back to the legacy
///    `crate::foo::bar` path-based key for non-crate-detected projects.
/// 4. **`self::foo`.** Sibling resolution relative to `current_file`'s
///    own module — same lookup as the bare-name case.
/// 5. **`super::foo::bar`.** Treat as `<parent-mod>::foo::bar` within
///    the same crate.
/// 6. **`other_crate::foo`.** Direct `<crate_name>::foo` lookup, with
///    progressive prefix shortening so deep paths fall back to the
///    crate root.
fn resolve_rust_import(
    module: &str,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    if module.is_empty() {
        return None;
    }

    // (1) stdlib filter — stops `std::path::Path` from accidentally
    // matching any indexed `Path` symbol via prefix fallback.
    if is_rust_stdlib(module) {
        return None;
    }

    // (2) Bare name (no `::`) — `mod foo;` or external crate reference.
    if !module.contains("::") {
        // Try sibling resolution first using the current file's parent
        // directory. This is what `mod foo;` is supposed to do.
        if let Some(parent) = current_file.parent() {
            let sibling_key = rust_meta_sibling_key(parent, module);
            if let Some(path) = index.get(&sibling_key) {
                return Some(path.clone());
            }
            // `mod.rs` files declare sub-modules whose siblings live in
            // the same directory, which is already `parent`.
            // For `lib.rs`/`main.rs`, modules live as direct children of
            // `parent`, also already covered. No second lookup needed.
        }
        // Workspace cross-crate fallback: `use ignore;` (rare) or
        // `extern crate ignore;` resolves to the `ignore` crate's
        // lib.rs root. The crate name was registered under its own bare
        // key in `index_rust_module` only for `src/lib.rs`/`src/main.rs`.
        if let Some(path) = index.get(module) {
            // Do NOT match the current file itself (a top-level
            // `mod foo {}` inline module would otherwise resolve to
            // its own host file via the file's `<crate>::foo` entry).
            if path != current_file {
                return Some(path.clone());
            }
        }
        return None;
    }

    // (3-5) Qualified path. Look up the current file's owning crate so
    // `crate::`/`self::`/`super::` can be rewritten to absolute
    // `<crate_name>::...` keys.
    let crate_root: Option<PathBuf> = index
        .get(&rust_meta_file_key(current_file))
        .cloned();
    let crate_name: Option<String> = crate_root.as_ref().and_then(|root| {
        index
            .get(&rust_meta_crate_name_key(root))
            .and_then(|p| p.to_str().map(|s| s.to_string()))
    });
    let src_rel: Option<String> = index
        .get(&rust_meta_src_rel_key(current_file))
        .and_then(|p| p.to_str().map(|s| s.to_string()));

    // (3) `crate::foo::bar` — rewrite to `<crate_name>::foo::bar`.
    if let Some(rest) = module.strip_prefix("crate::") {
        if let Some(ref cname) = crate_name {
            let candidate = format!("{}::{}", cname, rest);
            if let Some(path) = lookup_rust_with_prefix_shrink(&candidate, index) {
                return Some(path);
            }
        }
        // Legacy path-based fallback (kept for non-crate-detected projects).
        return lookup_rust_with_prefix_shrink(module, index);
    }

    // (4) `self::foo::bar` — relative to `current_file`'s own module.
    if let Some(rest) = module.strip_prefix("self::") {
        if let (Some(cname), Some(rel)) = (crate_name.as_ref(), src_rel.as_ref()) {
            // The `self` module is the module declared by current_file.
            // For `<crate>/src/foo/mod.rs`, that's `foo`. For
            // `<crate>/src/foo.rs`, the file's module is `foo` too —
            // but `self::bar` from foo.rs means foo's submodule `bar`,
            // which doesn't exist (foo.rs has no submodules without a
            // mod.rs/dir). For `<crate>/src/foo/bar.rs` declaring inline
            // `mod baz {}`, `self::baz` means inside baz — irrelevant
            // for file-graph deps. We treat `self::X::Y` as
            // `<crate>::<self_mod>::X::Y`.
            let self_mod = rust_self_module_path(rel);
            let candidate = if self_mod.is_empty() {
                format!("{}::{}", cname, rest)
            } else {
                format!("{}::{}::{}", cname, self_mod, rest)
            };
            return lookup_rust_with_prefix_shrink(&candidate, index);
        }
        return None;
    }

    // (5) `super::foo::bar` — walk up one module level (possibly more
    // for nested supers: `super::super::foo`).
    if module.starts_with("super::") {
        if let (Some(cname), Some(rel)) = (crate_name.as_ref(), src_rel.as_ref()) {
            let mut hops = 0usize;
            let mut tail = module;
            while let Some(rest) = tail.strip_prefix("super::") {
                hops += 1;
                tail = rest;
            }
            let self_mod = rust_self_module_path(rel);
            let self_parts: Vec<&str> = if self_mod.is_empty() {
                Vec::new()
            } else {
                self_mod.split("::").collect()
            };
            if hops > self_parts.len() {
                return None;
            }
            let base_parts = &self_parts[..self_parts.len() - hops];
            let candidate = if base_parts.is_empty() {
                format!("{}::{}", cname, tail)
            } else {
                format!("{}::{}::{}", cname, base_parts.join("::"), tail)
            };
            return lookup_rust_with_prefix_shrink(&candidate, index);
        }
        return None;
    }

    // (6) `other_crate::foo::bar` — direct lookup against the
    // crate-name-keyed entries. Stdlib was already filtered.
    if let Some(path) = lookup_rust_with_prefix_shrink(module, index) {
        return Some(path);
    }
    // Some projects pre-dating crate-detection still rely on the legacy
    // `crate::<rest>` shape — try the path-based form once.
    let legacy = format!("crate::{}", module);
    lookup_rust_with_prefix_shrink(&legacy, index)
}

/// Look up `module` in `index`, then progressively shorten it by
/// `::`-segment from the right. Skips synthetic `\0rust_meta::` keys
/// (which can never be a legitimate rust import) and never returns a
/// path stored under such a key.
fn lookup_rust_with_prefix_shrink(
    module: &str,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    if module.starts_with(RUST_META_PREFIX) {
        return None;
    }
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }
    let parts: Vec<&str> = module.split("::").collect();
    for i in (1..parts.len()).rev() {
        let prefix = parts[..i].join("::");
        if let Some(path) = index.get(&prefix) {
            return Some(path.clone());
        }
    }
    None
}

/// Compute the module-path spelling of `current_file` (given as its
/// `src_rel`, e.g. `"foo/bar"` or `"foo/mod"`) — what `<crate>::<X>`
/// the file itself defines.
///
/// Rules:
///   - `""` (the crate root, lib.rs/main.rs) -> `""` (no module path).
///   - `foo/mod`            -> `foo`        (directory module).
///   - `foo/bar/mod`        -> `foo::bar`.
///   - `foo`                -> `foo`        (file module).
///   - `foo/bar`            -> `foo::bar`.
fn rust_self_module_path(src_rel: &str) -> String {
    if src_rel.is_empty() || src_rel == "lib" || src_rel == "main" {
        return String::new();
    }
    let trimmed = src_rel.strip_suffix("/mod").unwrap_or(src_rel);
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.replace('/', "::")
    }
}

/// Resolve Java import to file path.
///
/// Handles:
/// - Qualified imports: "com.google.common.base.Preconditions" -> direct index lookup
/// - Wildcard imports: "com.google.common.base.*" -> resolve to files in that package
/// - Static imports: "com.google.common.base.Preconditions.checkNotNull" -> strip method, resolve class
/// - Fallback: try simple class name (last component after '.')
pub fn resolve_java_import(
    module: &str,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // Skip JDK/standard library imports
    if is_java_stdlib(module) {
        return None;
    }

    // Handle wildcard imports: "com.google.common.base.*"
    if let Some(package_prefix) = module.strip_suffix(".*") {
        // Find any file in the index whose qualified name starts with this package prefix
        for (key, path) in index {
            if key.starts_with(package_prefix)
                && key.len() > package_prefix.len()
                && key.as_bytes()[package_prefix.len()] == b'.'
            {
                // Check that what follows the prefix is a simple name (no more dots)
                let remainder = &key[package_prefix.len() + 1..];
                if !remainder.contains('.') {
                    return Some(path.clone());
                }
            }
        }
        return None;
    }

    // Try direct lookup of the full qualified name
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Handle static imports: the module string might include a method/field name
    // e.g., "com.google.common.base.Preconditions.checkNotNull"
    // Try stripping the last component (method name) and resolving the class
    if let Some(dot_pos) = module.rfind('.') {
        let class_part = &module[..dot_pos];
        if let Some(path) = index.get(class_part) {
            return Some(path.clone());
        }

        // Also try simple name of the class part (for narrow root scenarios where
        // the index only has simple class names, not fully-qualified names)
        // e.g., "com.google.common.base.Preconditions" -> try "Preconditions"
        if let Some(class_dot) = class_part.rfind('.') {
            let class_simple_name = &class_part[class_dot + 1..];
            if let Some(path) = index.get(class_simple_name) {
                return Some(path.clone());
            }
        }
    }

    // Fallback: try simple class name (last component after last '.')
    if let Some(last_dot) = module.rfind('.') {
        let simple_name = &module[last_dot + 1..];
        if let Some(path) = index.get(simple_name) {
            return Some(path.clone());
        }
    }

    None
}

/// Check if Java import is from the JDK standard library.
///
/// JDK packages start with java., javax., sun., com.sun., org.w3c., or org.xml.
pub fn is_java_stdlib(module_name: &str) -> bool {
    module_name.starts_with("java.")
        || module_name.starts_with("javax.")
        || module_name.starts_with("sun.")
        || module_name.starts_with("com.sun.")
        || module_name.starts_with("org.w3c.")
        || module_name.starts_with("org.xml.")
}

// =============================================================================
// Kotlin import resolution
// =============================================================================

/// Resolve a Kotlin `import <qualified.name>` to a file path inside the project.
///
/// (kotlin-deps-wiring-v1 / VAL-KT-DEPS) Kotlin's resolution rules mirror Java's
/// in that imports are qualified package names, but two differences make the
/// Java resolver insufficient out of the box:
///
///   * Kotlin packages are decoupled from directory layout — see
///     [`index_kotlin_module`]. We rely on the package-aware index
///     populated there, plus a wildcard scan for `import foo.bar.*`.
///   * Kotlin stdlib lives under `kotlin.*` and `kotlinx.coroutines.*` —
///     these must be filtered out so they don't pollute the external
///     dependency tally.
fn resolve_kotlin_import(
    module: &str,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // kotlin-internal-self-package-v1 (v0.5.0 T1 AUDIT-FIX): try to resolve
    // the import against the PROJECT's own index with a PRECISE
    // (exact-FQN / exact-package) match BEFORE applying the stdlib filter.
    //
    // `is_kotlin_stdlib` deliberately classifies `kotlinx.coroutines.*` (and
    // `kotlin.*`, `java.*`) as library/stdlib so an ordinary consumer project
    // doesn't tally them as internal. But when the project under analysis IS
    // kotlinx-coroutines itself, `import kotlinx.coroutines.internal.*` refers
    // to its OWN package — those files exist in the index. Pre-fix the
    // unconditional `is_kotlin_stdlib` bail at the top dropped every such
    // self-referential import, so the coroutines repo reported only ~24 of
    // 1000+ files with any internal edge.
    //
    // We only run the PRECISE matcher here (no fuzzy simple-name / parent-
    // strip fallbacks) so an external `kotlinx.coroutines.launch` cannot
    // accidentally bind to an unrelated project file named `launch` — that
    // fuzzy path stays gated behind the stdlib filter below.
    if let Some(found) = resolve_kotlin_precise(module, index) {
        return Some(found);
    }

    if is_kotlin_stdlib(module) {
        return None;
    }

    resolve_kotlin_against_index(module, index)
}

/// Precise Kotlin index resolution: exact-package wildcard or exact-FQN only.
///
/// kotlin-internal-self-package-v1: this runs BEFORE the stdlib filter, so it
/// must NOT use any fuzzy fallback that could bind an external symbol to an
/// unrelated same-named project file. Only an exact package-key (for a
/// `pkg.*` wildcard, registered by `index_kotlin_module`) or an exact
/// fully-qualified-name match counts as project-owned.
fn resolve_kotlin_precise(
    module: &str,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    if let Some(prefix) = module.strip_suffix(".*").or_else(|| module.strip_suffix("*")) {
        let prefix = prefix.trim_end_matches('.');
        if !prefix.is_empty() {
            // Only the exact package key — the project genuinely owns this
            // package iff a file declared `package <prefix>`.
            if let Some(path) = index.get(prefix) {
                return Some(path.clone());
            }
        }
        return None;
    }
    index.get(module).cloned()
}

/// Resolve a Kotlin import against the project file index (no stdlib gate),
/// including the fuzzy simple-name / parent-strip fallbacks.
///
/// Split out of [`resolve_kotlin_import`] so the resolver can consult the
/// index after the stdlib filter (kotlin-internal-self-package-v1).
fn resolve_kotlin_against_index(
    module: &str,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // Wildcard: `import com.foo.bar.*` — return any file whose qualified
    // name starts with `com.foo.bar.`.
    if let Some(prefix) = module.strip_suffix(".*").or_else(|| module.strip_suffix("*")) {
        // Try the bare package key first (registered by index_kotlin_module).
        let prefix = prefix.trim_end_matches('.');
        if !prefix.is_empty() {
            if let Some(path) = index.get(prefix) {
                return Some(path.clone());
            }
            // Scan for any registered FQN inside this package.
            for (key, path) in index {
                if key.starts_with(prefix)
                    && key.len() > prefix.len()
                    && key.as_bytes()[prefix.len()] == b'.'
                {
                    let remainder = &key[prefix.len() + 1..];
                    if !remainder.contains('.') {
                        return Some(path.clone());
                    }
                }
            }
        }
        return None;
    }

    // Direct lookup of the full qualified name.
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Static / nested imports such as `kotlin.time.Duration.Companion.seconds`
    // or `com.foo.bar.Outer.Companion.factory` — strip the trailing component
    // and retry, repeating once more for member-of-companion cases.
    if let Some(dot) = module.rfind('.') {
        let parent = &module[..dot];
        if let Some(path) = index.get(parent) {
            return Some(path.clone());
        }
        if let Some(dot2) = parent.rfind('.') {
            let grandparent = &parent[..dot2];
            if let Some(path) = index.get(grandparent) {
                return Some(path.clone());
            }
        }
    }

    // Last-resort: bare simple name (matches `index_kotlin_module`'s
    // simple-name entry).
    if let Some(dot) = module.rfind('.') {
        let simple = &module[dot + 1..];
        if !simple.is_empty() {
            if let Some(path) = index.get(simple) {
                return Some(path.clone());
            }
        }
    }

    None
}

/// Check if a Kotlin import resolves to the Kotlin/Java standard library.
///
/// Returns `true` for the Kotlin runtime (`kotlin.*`), JetBrains coroutines
/// / serialization / etc. shipped as separate artifacts but which the
/// resolver should still treat as external (`kotlinx.coroutines.*`,
/// `kotlinx.serialization.*`, `kotlinx.io.*`), and the host JVM/JDK packages
/// that kotlin-jvm code routinely imports (`java.*`, `javax.*`). Project
/// code under any other `kotlinx.*` namespace (e.g. `kotlinx.datetime` —
/// which is the corpus we test against in `kotlin_deps_wiring_v1`) is NOT
/// considered stdlib and must be resolved normally.
pub fn is_kotlin_stdlib(module_name: &str) -> bool {
    if is_java_stdlib(module_name) {
        return true;
    }
    if module_name == "kotlin" || module_name.starts_with("kotlin.") {
        return true;
    }
    // Subset of `kotlinx.*` artifacts shipped as separate Kotlin
    // libraries rather than user project code. We intentionally exclude
    // `kotlinx.datetime` and any other namespace that is regularly the
    // ROOT of a project (we'd otherwise resolve nothing for the
    // kotlin-datetime corpus).
    const KOTLINX_STDLIB_BASES: &[&str] = &[
        "kotlinx.coroutines",
        "kotlinx.serialization",
        "kotlinx.io",
        "kotlinx.atomicfu",
        "kotlinx.collections.immutable",
    ];
    for base in KOTLINX_STDLIB_BASES {
        if module_name == *base {
            return true;
        }
        let with_dot = format!("{}.", base);
        if module_name.starts_with(&with_dot) {
            return true;
        }
    }
    false
}

// =============================================================================
// C / C++ import resolution
// =============================================================================

/// Resolve C/C++ `#include` directive to a file path.
///
/// Handles:
/// - `#include "file.h"` (local) -> search index by filename and relative path
/// - `#include <header.h>` (system) -> return None (external/stdlib)
///
/// imports-is-from-schema-v1 (v0.4.2 M-021): C/C++ extractors no longer
/// encode the system-vs-local distinction via the misnamed `is_from` field
/// — the field is now omitted (`None`) for C/C++ imports. The resolver
/// falls through to a plain index lookup; system headers (`stdio.h`,
/// `iostream`) won't exist in the project file index, so they naturally
/// return `None` without an explicit branch.
fn resolve_c_cpp_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Direct index lookup (handles both "utils.h" and "net/socket.h")
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    None
}

// =============================================================================
// Ruby import resolution
// =============================================================================

/// Resolve Ruby `require` / `require_relative` to a file path.
///
/// Handles:
/// - `require "module"` -> index lookup by module name
/// - `require_relative "file"` (`is_from=true`) -> index lookup; filesystem
///   resolution is handled by the index entries already containing relative paths
fn resolve_ruby_import(
    import: &ImportInfo,
    root: &Path,
    current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // ruby-stdlib-shadow-v1 (v0.5.0 T1 AUDIT-FIX): a bare absolute require of a
    // standard-library name (`require 'logger'`, `require 'set'`, `require
    // 'json'`) must resolve to the stdlib, NOT to a same-named project file.
    //
    // Pre-fix this resolver had no stdlib guard (unlike the C# / Scala / Java
    // resolvers, which DO bail on their `is_<lang>_stdlib`). `index_ruby_module`
    // registers the bare leaf name of every file, so a project shipping
    // `lib/sinatra/middleware/logger.rb` registered a bare `logger` key; the
    // direct lookup below then bound the stdlib `require 'logger'` to that
    // project file and counted it as an internal edge.
    //
    // Ruby's `require` searches the load path: a bare stdlib name resolves to
    // the stdlib unless the project places a file of that name at a load-path
    // ROOT (e.g. `lib/logger.rb`, which `index_ruby_module` ALSO registers
    // under the lib-stripped key `logger`). We therefore only decline when the
    // require is a BARE name (no `/`, no relative prefix) that is a known
    // stdlib module AND there is no load-path-root file of that name. A
    // require carrying a path (`sinatra/middleware/logger`) is unaffected and
    // resolves normally below.
    if !module.contains('/')
        && !module.starts_with('.')
        && is_ruby_stdlib(module)
    {
        // The bare stdlib name might still be a genuine load-path-root file
        // (`lib/<name>.rb`), which the indexer registers under the lib-stripped
        // bare key. Distinguish "project owns a root file named <name>" from
        // "the bare key is only a deep-leaf decoy" by checking whether the
        // matched file actually sits at a load-path root.
        match index.get(module) {
            Some(path) if ruby_is_loadpath_root_file(path, module) => {
                return Some(path.clone());
            }
            _ => return None,
        }
    }

    // Direct index lookup
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Try stripping leading "./" for relative requires
    let stripped = module.strip_prefix("./").unwrap_or(module);
    if stripped != module {
        if let Some(path) = index.get(stripped) {
            return Some(path.clone());
        }
    }

    // ruby-require-relative-resolution-v1 (v0.5.0 T1 AUDIT-FIX): a
    // `require_relative '<path>'` resolves the path against the CURRENT
    // file's directory, not the load path. The AST extractor collapses
    // `require` and `require_relative` to the same `module` string, so we
    // cannot tell them apart here — but a path-bearing require (one that
    // carries a `/`, or an explicit `./`/`../`) that did not resolve via the
    // index above is overwhelmingly a `require_relative`. Resolve it against
    // `current_file`'s directory so legitimate intra-project edges like
    // `lib/sinatra/base.rb` -> `require_relative 'middleware/logger'` ->
    // `lib/sinatra/middleware/logger.rb` are counted. This was previously
    // dropped (the resolver ignored `current_file` entirely), undercounting
    // internal edges. Bare stdlib names were already handled above and never
    // reach here.
    let rel_spec = module
        .trim_start_matches("./");
    if let Some(parent) = current_file.parent() {
        let joined = parent.join(rel_spec);
        let normalised = normalise_path(&joined);
        // Try the `.rb` form and the path verbatim, scoped under root.
        for candidate in [normalised.with_extension("rb"), normalised.clone()] {
            if candidate.starts_with(root) && candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Does `path` sit at a Ruby load-path ROOT for the bare module `name`?
///
/// ruby-stdlib-shadow-v1. A bare `require '<name>'` only finds a project file
/// when that file is `<name>.rb` directly under a conventional load-path root
/// (`lib/`, `app/`, or the project root) — i.e. its require-path IS the bare
/// name. A deeply-nested `.../middleware/<name>.rb` is reachable only via its
/// full path (`sinatra/middleware/<name>`), never the bare name, so it must
/// NOT shadow the stdlib. We detect the root case structurally: the file's
/// stem equals `name` AND its parent directory is a load-path root (`lib`,
/// `app`, or empty).
fn ruby_is_loadpath_root_file(path: &Path, name: &str) -> bool {
    let stem_ok = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s == name)
        .unwrap_or(false);
    if !stem_ok {
        return false;
    }
    // The directory component immediately containing the file must be a
    // recognised load-path root (or the path is just `<name>.rb`).
    match path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) {
        Some("lib") | Some("app") => true,
        // File sits at the very top (no meaningful parent dir name).
        None => true,
        Some("") => true,
        _ => {
            // Path of the form `<name>.rb` with no directory at all.
            path.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true)
        }
    }
}

// =============================================================================
// C# import resolution
// =============================================================================

/// Resolve C# `using` directive to a file path.
///
/// Handles:
/// - `using Namespace.SubNamespace;` -> index lookup by dot-separated name
/// - `using static Namespace.Class;` -> same lookup
/// - System namespaces (System.*, Microsoft.*) -> return None (stdlib)
fn resolve_csharp_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Skip well-known .NET standard library namespaces
    if is_csharp_stdlib(module) {
        return None;
    }

    // Direct index lookup
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Try progressively shorter prefixes (like Python/Java)
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        for i in (1..parts.len()).rev() {
            let prefix = parts[..i].join(".");
            if let Some(path) = index.get(&prefix) {
                return Some(path.clone());
            }
        }
    }

    None
}

/// Check if a C# namespace is part of the .NET standard library / framework.
fn is_csharp_stdlib(module_name: &str) -> bool {
    module_name.starts_with("System")
        || module_name.starts_with("Microsoft")
        || module_name.starts_with("Windows")
}

// =============================================================================
// Scala import resolution
// =============================================================================

/// Resolve Scala `import` statement to a file path.
///
/// Handles:
/// - `import package.Class` -> index lookup by qualified name
/// - `import package._` (wildcard, `is_from=true`) -> resolve to package directory
/// - Scala/Java stdlib imports -> return None
fn resolve_scala_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Skip Scala and Java standard library imports
    if is_scala_stdlib(module) {
        return None;
    }

    // Direct index lookup
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // RC14 (v0.5.0 R7 cluster[10], #199): drop AT MOST the trailing segment
    // (the type/object name) to reach the import's OWN package, and resolve
    // only against that. The previous code walked progressively shorter
    // prefixes ALL the way up, so an unresolvable deeper import
    // `cats.effect.tracing.TracingConstants` (file absent) wrongly resolved
    // to an ANCESTOR-package file `cats.effect` (IO.scala) — fabricating a
    // false edge that closed a 2-cycle (LocalQueue <-> IO). A Scala import
    // `a.b.c.D` names the type `D` in package `a.b.c`; if it doesn't resolve
    // to its own file or its own package, it must NOT be force-fit onto an
    // ancestor package. Returning None lets the External/stdlib classifier
    // take over instead of inventing a wrong internal edge.
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        let own_package = parts[..parts.len() - 1].join(".");
        if let Some(path) = index.get(&own_package) {
            return Some(path.clone());
        }
    }

    None
}

/// Check if a Scala import is from the standard library.
fn is_scala_stdlib(module_name: &str) -> bool {
    module_name.starts_with("scala.")
        || module_name.starts_with("java.")
        || module_name.starts_with("javax.")
}

// =============================================================================
// Elixir import resolution
// =============================================================================

/// Resolve Elixir `import`/`alias`/`require`/`use` to a file path.
///
/// Elixir modules use PascalCase dot-separated names (e.g., `Phoenix.Controller`).
/// The index maps these to file paths via path-to-module conversion.
fn resolve_elixir_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Skip Elixir standard library modules
    if is_elixir_stdlib(module) {
        return None;
    }

    // Direct index lookup (module name like "Phoenix.Controller")
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Try progressively shorter prefixes
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        for i in (1..parts.len()).rev() {
            let prefix = parts[..i].join(".");
            if let Some(path) = index.get(&prefix) {
                return Some(path.clone());
            }
        }
    }

    // Try just the last component (e.g., "Controller" from "Phoenix.Controller")
    if let Some(last) = parts.last() {
        if let Some(path) = index.get(*last) {
            return Some(path.clone());
        }
    }

    None
}

/// Check if an Elixir module is from the standard library.
///
/// Sourced from <https://hexdocs.pm/elixir/api-reference.html> (Elixir
/// 1.16 "Modules" index). Bundled tooling applications shipped with the
/// Elixir tarball (`ExUnit`, `EEx`, `Logger`, `Mix`, `IEx`) are also
/// included — they don't require a Mix.exs dep entry, so they aren't
/// third-party.
fn is_elixir_stdlib(module_name: &str) -> bool {
    // Elixir stdlib modules
    let first_part = module_name.split('.').next().unwrap_or(module_name);
    matches!(
        first_part,
        "Kernel"
            | "Enum"
            | "Map"
            | "List"
            | "String"
            | "IO"
            | "File"
            | "Path"
            | "Process"
            | "Agent"
            | "Task"
            | "GenServer"
            | "Supervisor"
            | "Logger"
            | "Macro"
            | "Module"
            | "Access"
            | "Application"
            | "Atom"
            | "Base"
            | "Bitwise"
            | "Code"
            | "Config"
            | "Date"
            | "DateTime"
            | "EEx"
            | "ExUnit"
            | "Exception"
            | "Float"
            | "Function"
            | "IEx"
            | "Integer"
            | "Inspect"
            | "Keyword"
            | "MapSet"
            | "Mix"
            | "NaiveDateTime"
            | "Node"
            | "OptionParser"
            | "Port"
            | "Protocol"
            | "Range"
            | "Record"
            | "Reference"
            | "DynamicSupervisor"
            | "PartitionSupervisor"
            | "GenEvent"
            | "Behaviour"
            | "HashDict"
            | "HashSet"
            | "Regex"
            | "Registry"
            | "Stream"
            | "System"
            | "Time"
            | "Tuple"
            | "URI"
            | "Version"
    )
}

// =============================================================================
// OCaml import resolution
// =============================================================================

/// Resolve OCaml `open`/`include`/`module alias` to a file path.
///
/// OCaml modules are typically PascalCase names that correspond to filenames.
fn resolve_ocaml_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Skip OCaml standard library modules
    if is_ocaml_stdlib(module) {
        return None;
    }

    // Direct index lookup
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // Try the first component for dotted names (e.g., "Stdlib.Map" -> "Stdlib")
    let parts: Vec<&str> = module.split('.').collect();
    if parts.len() > 1 {
        for i in (1..parts.len()).rev() {
            let prefix = parts[..i].join(".");
            if let Some(path) = index.get(&prefix) {
                return Some(path.clone());
            }
        }
    }

    None
}

/// Check if an OCaml module is from the standard library.
fn is_ocaml_stdlib(module_name: &str) -> bool {
    let first_part = module_name.split('.').next().unwrap_or(module_name);
    matches!(
        first_part,
        "Stdlib"
            | "List"
            | "Array"
            | "String"
            | "Bytes"
            | "Buffer"
            | "Char"
            | "Complex"
            | "Digest"
            | "Filename"
            | "Format"
            | "Fun"
            | "Gc"
            | "Hashtbl"
            | "Int32"
            | "Int64"
            | "Lazy"
            | "Lexing"
            | "Map"
            | "Marshal"
            | "Nativeint"
            | "Obj"
            | "Parsing"
            | "Printexc"
            | "Printf"
            | "Queue"
            | "Random"
            | "Scanf"
            | "Seq"
            | "Set"
            | "Stack"
            | "Stream"
            | "Sys"
            | "Uchar"
            | "Unit"
            | "Weak"
    )
}

// =============================================================================
// PHP import resolution
// =============================================================================

/// Resolve PHP `use`/`require`/`include` to a file path.
///
/// Handles:
/// - `use App\Models\User` -> index lookup by namespace
/// - `require 'file.php'` -> direct path lookup
fn resolve_php_import(
    import: &ImportInfo,
    _root: &Path,
    _current_file: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let module = &import.module;

    // Skip PHP standard library / extensions
    if is_php_stdlib(module) {
        return None;
    }

    // Direct index lookup
    if let Some(path) = index.get(module) {
        return Some(path.clone());
    }

    // For namespace imports (backslash-separated), try path-style lookup
    if module.contains('\\') {
        let path_style = module.replace('\\', "/");
        if let Some(path) = index.get(&path_style) {
            return Some(path.clone());
        }

        // Try progressively shorter prefixes
        let parts: Vec<&str> = module.split('\\').collect();
        if parts.len() > 1 {
            // Try just the class name (last component)
            if let Some(last) = parts.last() {
                if let Some(path) = index.get(*last) {
                    return Some(path.clone());
                }
            }
        }
    }

    // For file paths (require/include), try stripping leading "./"
    let stripped = module.strip_prefix("./").unwrap_or(module);
    if stripped != module {
        if let Some(path) = index.get(stripped) {
            return Some(path.clone());
        }
    }

    None
}

/// Check if a PHP namespace/import is from the standard library or extensions.
fn is_php_stdlib(module_name: &str) -> bool {
    // PHP has no true stdlib namespace, but skip common built-in extensions
    let first_part = module_name.split('\\').next().unwrap_or(module_name);
    matches!(
        first_part,
        "PDO"
            | "DateTime"
            | "Exception"
            | "Error"
            | "Throwable"
            | "Iterator"
            | "Closure"
            | "stdClass"
            | "Generator"
            | "SplFixedArray"
            | "SplStack"
            | "SplQueue"
            | "SplHeap"
            | "SplPriorityQueue"
            | "ArrayObject"
            | "ArrayIterator"
    )
}

// =============================================================================
// Ruby / Lua / Swift / JS-builtin stdlib classifiers
// =============================================================================
// (m048-deps-stdlib-wiring-v1 / v0.4.2 M-111) These four helpers fill the
// hole left by the iter-2 audit: `classify_import` had `_ => DepKind::External`
// for every language except python / ts/js / go / rust / java. That meant
// kotlin / c# / scala / elixir / ocaml / php stdlib helpers EXISTED but were
// never called from `classify_import`, and ruby / lua / swift / js-node-builtin
// had no helper at all. Both bugs polluted `total_external_deps`.
//
// The lists are curated from the most authoritative source per language
// (Ruby docs, Lua 5.4 reference, Swift Foundation, Node.js docs). They are
// conservative on purpose — a missing entry under-classifies stdlib as
// External (over-counts external deps slightly) which is a much smaller
// harm than over-classifying real third-party as Stdlib (silently hides a
// dependency from the auditor).

/// Check if a Ruby `require` target is part of the Ruby standard library.
///
/// Source: <https://docs.ruby-lang.org/en/3.3/standard_library_rdoc.html>
/// (Ruby 3.3 "Standard Library" + "Default & Bundled Gems"). Both default
/// gems (`json`, `set`, `securerandom`) and bundled gems shipped with the
/// MRI release (`minitest`, `test-unit`, `rake`) count as stdlib for
/// dependency-graph purposes — they don't need a Gemfile entry on a stock
/// install, so they shouldn't be counted in `total_external_deps`.
///
/// The check matches the gem-grain (leading path segment), so
/// `require 'minitest/autorun'` and `require 'json/add/core'` both
/// classify as stdlib.
pub fn is_ruby_stdlib(module_name: &str) -> bool {
    let head = module_name.split('/').next().unwrap_or(module_name);
    matches!(
        head,
        // Core / built-in (always available; some are autoloaded)
        "English"
        | "abbrev"
        | "base64"
        | "benchmark"
        | "bigdecimal"
        | "cgi"
        | "coverage"
        | "csv"
        | "date"
        | "delegate"
        | "did_you_mean"
        | "digest"
        | "drb"
        | "erb"
        | "etc"
        | "fcntl"
        | "fiddle"
        | "fileutils"
        | "find"
        | "forwardable"
        | "getoptlong"
        | "io"
        | "io/console"
        | "io/nonblock"
        | "io/wait"
        | "ipaddr"
        | "irb"
        | "json"
        | "logger"
        | "monitor"
        | "mutex_m"
        | "net/http"
        | "net/imap"
        | "net/pop"
        | "net/smtp"
        | "nkf"
        | "objspace"
        | "observer"
        | "open-uri"
        | "open3"
        | "openssl"
        | "optparse"
        | "ostruct"
        | "pathname"
        | "pp"
        | "prettyprint"
        | "prime"
        | "pstore"
        | "psych"
        | "racc"
        | "rdoc"
        | "readline"
        | "resolv"
        | "resolv-replace"
        | "ripper"
        | "rss"
        | "scanf"
        | "securerandom"
        | "set"
        | "shellwords"
        | "singleton"
        | "socket"
        | "stringio"
        | "strscan"
        | "syslog"
        | "tempfile"
        | "time"
        | "timeout"
        | "tmpdir"
        | "tracer"
        | "tsort"
        | "un"
        | "uri"
        | "weakref"
        | "yaml"
        | "zlib"
        // Bundled gems (ship with MRI; no Gemfile entry needed)
        | "minitest"
        | "power_assert"
        | "rake"
        | "rbs"
        | "rexml"
        | "rss-maker"
        | "test-unit"
        | "typeprof"
        // Common subforms that come with the Ruby tarball
        | "rubygems"
        | "bundler"
    )
}

/// Check if a Lua `require` target is part of the Lua 5.4 standard library.
///
/// Source: <https://www.lua.org/manual/5.4/manual.html#6> (Standard
/// Libraries). The basic library is identifier-grain; `math`, `string`,
/// `table` etc. are the module-grain names users `require` or address as
/// globals.
pub fn is_lua_stdlib(module_name: &str) -> bool {
    let head = module_name.split('.').next().unwrap_or(module_name);
    matches!(
        head,
        "coroutine"
            | "debug"
            | "io"
            | "math"
            | "os"
            | "package"
            | "string"
            | "table"
            | "utf8"
            // Lua 5.2 bit32 (kept available in some 5.3+ builds and LuaJIT)
            | "bit32"
            // LuaJIT extensions commonly treated as part of the runtime
            | "bit"
            | "ffi"
            | "jit"
    )
}

/// Check if a Swift `import` target is part of the Apple SDK / Swift stdlib.
///
/// Source: Apple's Swift Standard Library + Foundation umbrella
/// (<https://developer.apple.com/documentation/swift>,
/// <https://developer.apple.com/documentation/foundation>) and the Swift
/// concurrency / package-graph modules shipped with the toolchain.
///
/// The list deliberately leaves out community-maintained packages
/// (`swift-collections`, `swift-argument-parser`) — those ARE third-party
/// dependencies on a stock toolchain.
pub fn is_swift_stdlib(module_name: &str) -> bool {
    // The Swift module identifier is a single segment; sub-modules
    // (`os.log`, `Combine.AnyPublisher`) keep the umbrella as head.
    let head = module_name.split('.').next().unwrap_or(module_name);
    matches!(
        head,
        // Core Swift runtime
        "Swift"
            | "SwiftShims"
            | "_Concurrency"
            | "_StringProcessing"
            | "_Differentiation"
            | "RegexBuilder"
            // Apple SDK umbrellas
            | "Foundation"
            | "Dispatch"
            | "Combine"
            | "SwiftUI"
            | "UIKit"
            | "AppKit"
            | "CoreData"
            | "CoreFoundation"
            | "CoreGraphics"
            | "CoreImage"
            | "CoreLocation"
            | "CoreML"
            | "CoreText"
            | "CoreVideo"
            | "QuartzCore"
            | "Metal"
            | "MetalKit"
            | "AVFoundation"
            | "AVKit"
            | "WebKit"
            | "MapKit"
            | "Network"
            | "CryptoKit"
            | "Security"
            | "os"
            | "Darwin"
            | "Glibc"
            | "WinSDK"
            // Toolchain testing modules
            | "XCTest"
            | "Testing"
            // Swift package authoring (ships with swiftc, not third-party)
            | "PackageDescription"
            | "PackagePlugin"
            // Swift toolchain compiler intrinsics
            | "Builtin"
    )
}

/// Check if a Solidity `import "<path>"` target is part of a
/// "standard library".
///
/// Solidity has NO module-system standard library. Builtins such as
/// `msg.sender`, `block.timestamp`, `keccak256`, `abi.encode`, and
/// `selfdestruct` are intrinsics of the language, not import-able
/// modules. The only thing that ever appears inside an `import "..."`
/// directive is either a project-local path (`./Foo.sol`,
/// `../utils/Helpers.sol`, `contracts/MyLib.sol`) or a third-party
/// package path (`@openzeppelin/contracts/...`, `solmate/...`,
/// `forge-std/...`).
///
/// This helper therefore always returns `false`. It exists to keep the
/// per-language stdlib classifier shape uniform — `classify_import`'s
/// Solidity arm calls it for symmetry with every other language, even
/// though the result is constant. The constant return value is part of
/// the API contract: a future "Solidity stdlib" RFC would have to land
/// here, not in a separate code path.
///
/// solidity-deps-v1 (v0.5.0 SOL-007).
pub fn is_solidity_stdlib(_module: &str) -> bool {
    false
}

/// Check if a JavaScript / TypeScript import path is a Node.js built-in module.
///
/// Source: <https://nodejs.org/api/modules.html> (Node.js v22 built-ins).
/// Both the bare form (`require('fs')`) and the `node:` prefixed form
/// (`import fs from 'node:fs'`) are recognised. Sub-paths
/// (`node:fs/promises`, `stream/web`) are matched by leading segment.
pub fn is_js_node_builtin(import_path: &str) -> bool {
    // Strip the `node:` scheme if present, then drop any sub-path.
    let stripped = import_path.strip_prefix("node:").unwrap_or(import_path);
    let head = stripped.split('/').next().unwrap_or(stripped);
    matches!(
        head,
        "assert"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "sys"
            | "timers"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
            // Test runner (Node 18+)
            | "test"
    )
}

// =============================================================================
// External vs Internal Classification (Phase 4)
// =============================================================================

/// Classify an import as internal, stdlib, or external.
///
/// This function determines the category of an import:
/// - Internal: Part of the current project (resolvable to a file)
/// - Stdlib: Part of the language's standard library
/// - External: Third-party package (not in project, not stdlib)
///
/// # Arguments
///
/// * `import` - The import to classify
/// * `root` - Project root directory
/// * `current_file` - File containing the import
/// * `module_index` - Index of module names to file paths
/// * `language` - Programming language
///
/// # Returns
///
/// The classification of the dependency.
pub fn classify_import(
    import: &ImportInfo,
    root: &Path,
    current_file: &Path,
    module_index: &HashMap<String, PathBuf>,
    language: Language,
) -> DepKind {
    // 1. Try to resolve as internal first (using module_index)
    if resolve_import(import, root, current_file, module_index, language).is_some() {
        return DepKind::Internal;
    }

    // 2. If not found, classify as stdlib or external based on language.
    //
    // (m048-deps-stdlib-wiring-v1 / v0.4.2 M-111) Every language with a
    // known `is_<lang>_stdlib` helper now consults it before falling
    // through to External. Prior to this fix the match had an
    // `_ => DepKind::External` catch-all that swallowed kotlin / c# /
    // scala / elixir / ocaml / php — their stdlib helpers existed but
    // were never called, so kotlin.collections / System.IO / scala.io /
    // Logger / Stdlib.Map / PDO all got bucketed as External and
    // inflated `total_external_deps`. Ruby / Lua / Swift / JS node
    // builtins gained dedicated helpers in the same change.
    let module = &import.module;
    match language {
        Language::Python => {
            if is_python_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::TypeScript | Language::JavaScript => {
            // TypeScript: relative imports that weren't resolved are still considered
            // attempts at internal imports (maybe missing files)
            if is_typescript_relative(module) {
                DepKind::Internal
            } else if is_js_node_builtin(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Go => {
            if is_go_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Rust => {
            if is_rust_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Java => {
            if is_java_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Kotlin => {
            if is_kotlin_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::CSharp => {
            if is_csharp_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Scala => {
            if is_scala_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Elixir => {
            if is_elixir_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Ocaml => {
            if is_ocaml_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Php => {
            if is_php_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Ruby => {
            if is_ruby_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Lua | Language::Luau => {
            if is_lua_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::Swift => {
            if is_swift_stdlib(module) {
                DepKind::Stdlib
            } else {
                DepKind::External
            }
        }
        Language::C | Language::Cpp => {
            // rc3-external-deps-c-lua-php-v1 (v0.5.0 CLOSEOUT). C/C++
            // `#include` carries the system-vs-local intent purely in the
            // angle-vs-quote spelling, which the extractor now preserves on
            // `is_from` (Some(true) = `<...>` system, Some(false) = `"..."`
            // local). The grammar gives no other discriminator (ISO C
            // 6.10.2: the written form IS the system-vs-local signal).
            //
            //   * `<...>` system header -> Stdlib. A system-search-path
            //     include is a toolchain header; like every other language's
            //     stdlib it is deliberately kept OFF the third-party External
            //     axis (see the `DepKind::Stdlib` arm in
            //     `analyze_dependencies`). No header-name allow-list is
            //     needed — the angle-bracket form is the canonical signal.
            //   * `"..."` local header -> Internal. A quoted include is, by C
            //     semantics, a project-local file. Resolved local headers
            //     already returned Internal above (step 1); unresolved ones
            //     are still local-intent (a missing/vendored project header),
            //     not a declared third-party package, so they do NOT inflate
            //     `total_external_deps`.
            //   * `None` -> External (defensive; macro-indirection includes
            //     are dropped at extraction, so this should not occur for C).
            match import.is_from {
                Some(true) => DepKind::Stdlib,
                Some(false) => DepKind::Internal,
                None => DepKind::External,
            }
        }
        Language::Solidity => {
            // solidity-deps-v1 (v0.5.0 SOL-007). `is_solidity_stdlib`
            // always returns `false` (Solidity has no module-system
            // stdlib — builtins are intrinsic). The classification
            // bifurcates on the import-path shape instead:
            //   * Relative spellings (`./`, `../`) that didn't resolve
            //     via `resolve_solidity_import` are still treated as
            //     Internal — the target file may be missing or the
            //     resolver may have failed for a reason that doesn't
            //     promote the dep to "third-party package".
            //   * Anything starting with one of the curated external-
            //     ecosystem prefixes (OpenZeppelin / Chainlink /
            //     Uniswap / Aave / solmate / solady / forge-std /
            //     hardhat / ds-test) is External.
            //   * Everything else (bare project-relative spelling like
            //     `contracts/MyLib.sol`) is Internal — these are
            //     Foundry remappings and live inside the project tree.
            //
            // The stdlib helper call is preserved for API symmetry
            // (every other arm calls its `is_<lang>_stdlib`).
            let _ = is_solidity_stdlib(module);
            if module.starts_with("./") || module.starts_with("../") {
                DepKind::Internal
            } else if solidity_external_prefix(module).is_some() {
                DepKind::External
            } else {
                DepKind::Internal
            }
        }
        _ => DepKind::External,
    }
}

/// Return the matching curated external-package prefix for a Solidity
/// import path, or `None` if the path is not in the ecosystem
/// taxonomy.
///
/// solidity-deps-v1 (v0.5.0 SOL-007). The list is curated from common
/// audit corpora (Foundry / Hardhat repos, OpenZeppelin examples) and
/// is **longest-prefix-first** so that `@openzeppelin/contracts-
/// upgradeable/` does not get shadowed by `@openzeppelin/contracts/`
/// — the upgradeable variant is a distinct package coordinate per
/// npm.
///
/// Returns the canonical package coordinate (i.e. the prefix WITHOUT
/// the trailing `/`) so the caller can both classify and emit a
/// deterministic package name from the same lookup.
pub fn solidity_external_prefix(module: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        // Longest first — upgradeable BEFORE the bare contracts entry.
        ("@openzeppelin/contracts-upgradeable/", "@openzeppelin/contracts-upgradeable"),
        ("@openzeppelin/contracts/", "@openzeppelin/contracts"),
        ("@chainlink/contracts/", "@chainlink/contracts"),
        ("@uniswap/v3-periphery/", "@uniswap/v3-periphery"),
        ("@uniswap/v3-core/", "@uniswap/v3-core"),
        ("@uniswap/v2-core/", "@uniswap/v2-core"),
        ("@aave/periphery-v3/", "@aave/periphery-v3"),
        ("@aave/core-v3/", "@aave/core-v3"),
        ("solmate/", "solmate"),
        ("solady/", "solady"),
        ("forge-std/", "forge-std"),
        ("hardhat/", "hardhat"),
        ("ds-test/", "ds-test"),
    ];
    for (prefix, name) in PREFIXES {
        if module.starts_with(prefix) {
            return Some(name);
        }
    }
    None
}

/// Extract the package-manager-grain "external package name" for an import
/// module string, per language conventions.
///
/// (deps-external-internal-classifier-v1 / M-048) The pre-fix
/// `analyze_dependencies` collapsed every external import to the bare first
/// component (`import.module.split('.').next()`), which makes sense for
/// Python (`numpy.linalg` -> `numpy`) but is wrong for languages whose
/// package coordinate spans multiple dotted segments (Java's
/// `org.springframework`, Kotlin's `kotlinx.coroutines`, CSharp's
/// `Newtonsoft.Json`). The pre-fix collapse made `total_external_deps` for
/// Spring petclinic = 4 (`["jakarta","java","javax","org"]`) across 47
/// files — a useless precision-loss.
///
/// Rules:
///   * **Java / Kotlin / Scala / Elixir / Ocaml / Lua / Luau / Php / Python**
///     – dot-separated module. Keep at most two leading segments (the
///     typical `groupId.artifactId` / `package.subpackage` precision).
///     Special-case Java/Kotlin: `org.springframework.boot.*` is best
///     bucketed at `org.springframework` (three-segment vendors like
///     `org.springframework`, `com.fasterxml`, `io.netty` get the
///     `vendor.product` shape).
///   * **CSharp** – same as Java/Kotlin; PascalCase namespaces like
///     `Newtonsoft.Json.Bson` bucket at `Newtonsoft.Json`.
///   * **Rust** – `::`-separated. The first segment is the crate name,
///     which is the package coordinate. `bstr::ByteSlice` -> `bstr`,
///     `tokio::sync::Mutex` -> `tokio`.
///   * **Go** – `/`-separated import path. The full path IS the package
///     coordinate. `github.com/gin-gonic/gin` -> the whole thing.
///   * **TypeScript / JavaScript** – npm packages may be scoped (`@foo/bar`)
///     and may have sub-paths (`lodash/fp`). For scoped packages keep both
///     `@scope` + `name`; for unscoped, keep just the leading name.
///     `node:fs` builtins keep the `node:fs` form.
///   * **Ruby** – `'minitest/autorun'` -> `minitest` (gem name is the
///     leading segment).
///   * **C / C++** – `#include "path/to/header.h"` is path-shaped; keep
///     the verbatim form (already coarse).
fn external_package_name(module: &str, language: Language) -> String {
    let module = module
        .trim_start_matches("./")
        .trim_start_matches("../")
        .trim();
    if module.is_empty() {
        return String::new();
    }

    fn first_n_dotted(s: &str, n: usize) -> String {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() <= n {
            s.to_string()
        } else {
            parts[..n].join(".")
        }
    }

    match language {
        Language::Java | Language::Kotlin | Language::Scala | Language::CSharp => {
            // Java/Kotlin/CSharp/Scala — typical 2-segment Maven/NuGet
            // group:artifact coordinate. For `org.*` / `com.*` / `io.*`
            // there's usually a vendor.product convention; 2 segments
            // captures e.g. `org.springframework`, `Newtonsoft.Json`,
            // `kotlinx.coroutines`, `jakarta.persistence`.
            first_n_dotted(module, 2)
        }
        Language::Python | Language::Lua | Language::Luau | Language::Elixir | Language::Ocaml
        | Language::Php => {
            // Python / Lua / Elixir / OCaml / PHP — typically one
            // top-level package per pip/luarocks/hex/opam entry.
            module
                .split('.')
                .next()
                .unwrap_or(module)
                .to_string()
        }
        Language::Rust => {
            // Rust crate name == first `::` segment.
            module
                .split("::")
                .next()
                .unwrap_or(module)
                .to_string()
        }
        Language::Go => {
            // Go module path is the full import path (e.g.
            // `github.com/gin-gonic/gin`). Internal stdlib was already
            // filtered by `is_go_stdlib`; keep the full path here.
            module.to_string()
        }
        Language::TypeScript | Language::JavaScript => {
            // npm convention: scoped (`@foo/bar/sub`) -> `@foo/bar`;
            // unscoped (`lodash/fp`) -> `lodash`; builtins (`node:fs`)
            // keep verbatim.
            if let Some(rest) = module.strip_prefix('@') {
                let parts: Vec<&str> = rest.splitn(3, '/').collect();
                if parts.len() >= 2 {
                    format!("@{}/{}", parts[0], parts[1])
                } else {
                    format!("@{}", rest)
                }
            } else if module.starts_with("node:") {
                module.to_string()
            } else {
                module.split('/').next().unwrap_or(module).to_string()
            }
        }
        Language::Ruby => {
            // `require 'minitest/autorun'` -> `minitest` (the gem).
            module.split('/').next().unwrap_or(module).to_string()
        }
        Language::C | Language::Cpp => {
            // `#include` is path-shaped; keep verbatim.
            module.to_string()
        }
        Language::Solidity => {
            // solidity-deps-v1 (v0.5.0 SOL-007). Solidity import paths
            // are package-path strings. Use the longest-prefix match
            // against the curated taxonomy in
            // `solidity_external_prefix` so we always collapse to the
            // canonical package coordinate (e.g.
            // `@openzeppelin/contracts/token/ERC20/ERC20.sol` ->
            // `@openzeppelin/contracts`, and the upgradeable variant
            // stays distinct as `@openzeppelin/contracts-upgradeable`).
            //
            // Defensive fallback: if no prefix matches (e.g. a path
            // that slipped through `classify_import` without being
            // External), keep just the first path segment — this is
            // the npm-style coordinate shape (`somepkg/sub/path.sol`
            // -> `somepkg`).
            if let Some(name) = solidity_external_prefix(module) {
                name.to_string()
            } else if let Some(rest) = module.strip_prefix('@') {
                // Scoped npm-style fallback for an unrecognised
                // `@scope/pkg/...` import.
                let parts: Vec<&str> = rest.splitn(3, '/').collect();
                if parts.len() >= 2 {
                    format!("@{}/{}", parts[0], parts[1])
                } else {
                    format!("@{}", rest)
                }
            } else {
                module.split('/').next().unwrap_or(module).to_string()
            }
        }
        _ => module.to_string(),
    }
}

/// Check if Python import is stdlib.
///
/// Uses a comprehensive list of Python 3.11+ stdlib modules.
/// Handles dotted imports by checking the base module.
pub fn is_python_stdlib(module_name: &str) -> bool {
    // Comprehensive Python stdlib modules list (3.11+)
    const PYTHON_STDLIB: &[&str] = &[
        // Core
        "abc",
        "aifc",
        "argparse",
        "array",
        "ast",
        "asyncio",
        "atexit",
        "base64",
        "bdb",
        "binascii",
        "bisect",
        "builtins",
        "bz2",
        "calendar",
        "cgi",
        "cgitb",
        "chunk",
        "cmath",
        "cmd",
        "code",
        "codecs",
        "codeop",
        "collections",
        "colorsys",
        "compileall",
        "concurrent",
        "configparser",
        "contextlib",
        "contextvars",
        "copy",
        "copyreg",
        "cProfile",
        "csv",
        "ctypes",
        "curses",
        "dataclasses",
        "datetime",
        "dbm",
        "decimal",
        "difflib",
        "dis",
        "distutils",
        "doctest",
        "email",
        "encodings",
        "enum",
        "errno",
        "faulthandler",
        "fcntl",
        "filecmp",
        "fileinput",
        "fnmatch",
        "fractions",
        "ftplib",
        "functools",
        "gc",
        "getopt",
        "getpass",
        "gettext",
        "glob",
        "graphlib",
        "grp",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "http",
        "idlelib",
        "imaplib",
        "imghdr",
        "importlib",
        "inspect",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "keyword",
        "lib2to3",
        "linecache",
        "locale",
        "logging",
        "lzma",
        "mailbox",
        "mailcap",
        "marshal",
        "math",
        "mimetypes",
        "mmap",
        "modulefinder",
        "multiprocessing",
        "netrc",
        "nis",
        "nntplib",
        "numbers",
        "operator",
        "optparse",
        "os",
        "pathlib",
        "pdb",
        "pickle",
        "pickletools",
        "pipes",
        "pkgutil",
        "platform",
        "plistlib",
        "poplib",
        "posix",
        "posixpath",
        "pprint",
        "profile",
        "pstats",
        "pty",
        "pwd",
        "py_compile",
        "pyclbr",
        "pydoc",
        "queue",
        "quopri",
        "random",
        "re",
        "readline",
        "reprlib",
        "resource",
        "rlcompleter",
        "runpy",
        "sched",
        "secrets",
        "select",
        "selectors",
        "shelve",
        "shlex",
        "shutil",
        "signal",
        "site",
        "smtpd",
        "smtplib",
        "sndhdr",
        "socket",
        "socketserver",
        "sqlite3",
        "ssl",
        "stat",
        "statistics",
        "string",
        "stringprep",
        "struct",
        "subprocess",
        "sunau",
        "symtable",
        "sys",
        "sysconfig",
        "syslog",
        "tabnanny",
        "tarfile",
        "telnetlib",
        "tempfile",
        "termios",
        "test",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "tkinter",
        "token",
        "tokenize",
        "tomllib",
        "trace",
        "traceback",
        "tracemalloc",
        "tty",
        "turtle",
        "turtledemo",
        "types",
        "typing",
        "unicodedata",
        "unittest",
        "urllib",
        "uu",
        "uuid",
        "venv",
        "warnings",
        "wave",
        "weakref",
        "webbrowser",
        "winreg",
        "winsound",
        "wsgiref",
        "xdrlib",
        "xml",
        "xmlrpc",
        "zipapp",
        "zipfile",
        "zipimport",
        "zlib",
        "zoneinfo",
        // Common typing modules
        "_typeshed",
        "typing_extensions",
        // Private/internal modules commonly seen
        "_thread",
        "_collections",
        "_abc",
        "_io",
        "_weakref",
        "__future__",
    ];

    // Get the base module name (first component before any dots)
    let base = module_name.split('.').next().unwrap_or(module_name);
    PYTHON_STDLIB.contains(&base)
}

/// Check if TypeScript/JavaScript import is a relative import.
///
/// Relative imports start with "./" or "../" and are internal.
/// Non-relative imports (like "express", "@types/node") are external.
pub fn is_typescript_relative(import_path: &str) -> bool {
    import_path.starts_with("./") || import_path.starts_with("../")
}

/// Check if TypeScript/JavaScript import is external (node_modules).
///
/// External imports don't start with . or / (relative paths).
/// Examples: "lodash", "@types/node", "express"
pub fn is_typescript_external(import_path: &str) -> bool {
    !import_path.starts_with('.') && !import_path.starts_with('/')
}

/// Check if Go import is stdlib.
///
/// Go stdlib packages don't contain dots in the base segment.
/// Examples: "fmt", "net/http", "encoding/json" are stdlib.
/// Examples: "github.com/gin-gonic/gin" is external.
pub fn is_go_stdlib(import_path: &str) -> bool {
    // Go stdlib: single-segment or known prefixes without dots
    // External packages always have dots (domain names)
    const GO_STDLIB_PREFIXES: &[&str] = &[
        "archive",
        "bufio",
        "builtin",
        "bytes",
        "cmp",
        "compress",
        "container",
        "context",
        "crypto",
        "database",
        "debug",
        "embed",
        "encoding",
        "errors",
        "expvar",
        "flag",
        "fmt",
        "go",
        "hash",
        "html",
        "image",
        "index",
        "internal",
        "io",
        "iter",
        "log",
        "maps",
        "math",
        "mime",
        "net",
        "os",
        "path",
        "plugin",
        "reflect",
        "regexp",
        "runtime",
        "slices",
        "sort",
        "strconv",
        "strings",
        "structs",
        "sync",
        "syscall",
        "testing",
        "text",
        "time",
        "unicode",
        "unsafe",
    ];

    let base = import_path.split('/').next().unwrap_or(import_path);

    // If the base contains a dot, it's likely a domain (external)
    if base.contains('.') {
        return false;
    }

    GO_STDLIB_PREFIXES.contains(&base)
}

/// Check if Rust import is stdlib.
///
/// Rust stdlib includes std::, core::, and alloc:: prefixes.
pub fn is_rust_stdlib(import_path: &str) -> bool {
    import_path.starts_with("std::")
        || import_path.starts_with("core::")
        || import_path.starts_with("alloc::")
        || import_path == "std"
        || import_path == "core"
        || import_path == "alloc"
}

/// Check if Rust import is internal (crate::, self::, super::).
pub fn is_rust_internal(import_path: &str) -> bool {
    import_path.starts_with("crate::")
        || import_path.starts_with("self::")
        || import_path.starts_with("super::")
}

/// Read the Go module path from a go.mod file in the given root directory.
///
/// Parses the `module` directive from go.mod. For example, given:
/// ```text
/// module github.com/spf13/cobra
///
/// go 1.15
/// ```
/// Returns `Some("github.com/spf13/cobra")`.
///
/// Returns `None` if go.mod doesn't exist or doesn't contain a module directive.
fn read_go_module_path(root: &Path) -> Option<String> {
    let go_mod_path = root.join("go.mod");
    let content = std::fs::read_to_string(go_mod_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let module_path = rest.trim();
            if !module_path.is_empty() {
                return Some(module_path.to_string());
            }
        }
    }
    None
}

/// Collect Go files grouped by their package directory (relative to root).
///
/// Returns a map from relative directory path to list of files in that directory.
/// Files at the root level use an empty string key.
fn group_go_files_by_package(root: &Path, files: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    let mut groups: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for file_path in files {
        if let Ok(relative) = file_path.strip_prefix(root) {
            let pkg_dir = relative
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            groups.entry(pkg_dir).or_default().push(file_path.clone());
        }
    }
    groups
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a path to a Python module name (e.g., "src/utils" -> "src.utils")
fn path_to_module_name(path: &Path) -> String {
    path.to_string_lossy()
        .replace(['/', '\\'], ".")
        .trim_start_matches('.')
        .to_string()
}

/// Make a path relative to root, or return the path as-is if not under root
fn make_relative_path(path: &Path, root: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Normalize a path (resolve . and ..)
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            c => result.push(c),
        }
    }
    result
}

/// Detect the dominant language in a directory.
///
/// Delegates to [`Language::from_directory`], which uses the same
/// manifest-priority + extension-majority detection used by every other
/// subcommand (`structure`, `calls`, `extract`, etc.). This ensures `deps`
/// autodetects the same set of languages those commands do — including
/// Java (pom.xml/build.gradle) and Scala (build.sbt) sources buried multiple
/// directory levels deep, which the previous shallow 1-level walk missed.
fn detect_dominant_language(root: &Path) -> TldrResult<Language> {
    Language::from_directory(root)
        .ok_or_else(|| crate::error::TldrError::UnsupportedLanguage("unknown".to_string()))
}

/// Check if an error is recoverable (e.g., parse error in one file)
fn is_recoverable_error(err: &crate::error::TldrError) -> bool {
    matches!(err, crate::error::TldrError::ParseError { .. })
}

// =============================================================================
// Output Formatting (Phase 6)
// =============================================================================

/// Large graph warning threshold (S7-R43)
const LARGE_GRAPH_THRESHOLD: usize = 500;

/// Format dependency report as human-readable text.
///
/// Output format follows spec section 1.6:
/// ```text
/// Dependency Analysis: src/
/// Language: Python
///
/// Internal Dependencies (24 edges, 12 files):
///   src/auth.py
///     -> src/utils.py
///     -> src/db.py
///
/// External Packages (8):
///   jwt (1 import)
///   ...
///
/// Circular Dependencies Found: 1
///   [CYCLE] src/a.py -> src/b.py -> src/c.py -> src/a.py
///
/// Stats:
///   Max depth: 4
///   Leaf files: 3 (no outgoing deps)
///   Root files: 2 (no incoming deps)
/// ```
pub fn format_deps_text(report: &DepsReport) -> String {
    let mut output = String::new();

    output.push_str(&format!("Dependency Analysis: {}\n", report.root.display()));
    output.push_str(&format!(
        "Language: {}\n\n",
        capitalize_first(&report.language)
    ));

    // Internal dependencies
    if !report.internal_dependencies.is_empty() {
        output.push_str(&format!(
            "Internal Dependencies ({} edges, {} files):\n",
            report.stats.total_internal_deps, report.stats.total_files
        ));
        for (file, deps) in &report.internal_dependencies {
            if !deps.is_empty() {
                output.push_str(&format!("  {}\n", file.display()));
                for dep in deps {
                    output.push_str(&format!("    -> {}\n", dep.display()));
                }
            }
        }
        output.push('\n');
    }

    // External packages
    if !report.external_dependencies.is_empty() {
        // Count imports per package
        let mut package_counts: std::collections::HashMap<&String, usize> =
            std::collections::HashMap::new();
        for deps in report.external_dependencies.values() {
            for dep in deps {
                *package_counts.entry(dep).or_insert(0) += 1;
            }
        }

        output.push_str(&format!("External Packages ({}):\n", package_counts.len()));
        // Sort by count descending, then alphabetically
        let mut packages: Vec<_> = package_counts.iter().collect();
        packages.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (pkg, count) in packages {
            let plural = if *count == 1 { "import" } else { "imports" };
            output.push_str(&format!("  {} ({} {})\n", pkg, count, plural));
        }
        output.push('\n');
    }

    // Circular dependencies
    if !report.circular_dependencies.is_empty() {
        output.push_str(&format!(
            "Circular Dependencies Found: {}\n",
            report.circular_dependencies.len()
        ));
        for cycle in &report.circular_dependencies {
            let cycle_str: Vec<String> =
                cycle.path.iter().map(|p| p.display().to_string()).collect();
            // Show cycle with closing loop
            let first = cycle
                .path
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            output.push_str(&format!(
                "  [CYCLE] {} -> {}\n",
                cycle_str.join(" -> "),
                first
            ));
        }
        output.push('\n');
    } else {
        output.push_str("No circular dependencies found.\n\n");
    }

    // Stats
    output.push_str("Stats:\n");
    output.push_str(&format!("  Max depth: {}\n", report.stats.max_depth));
    output.push_str(&format!(
        "  Leaf files: {} (no outgoing deps)\n",
        report.stats.leaf_files
    ));
    output.push_str(&format!(
        "  Root files: {} (no incoming deps)\n",
        report.stats.root_files
    ));

    output
}

/// Format dependency report as DOT graph for graphviz.
///
/// Risk mitigations:
/// - S7-R42: All node identifiers are quoted (paths may have special chars)
/// - S7-R43: Warns on large graphs (>500 nodes) via stderr
///
/// Output format follows spec section 1.6:
/// ```dot
/// digraph deps {
///   rankdir=LR;
///   node [shape=box];
///
///   // Nodes
///   "src/auth.py" [label="auth.py"];
///   "src/utils.py" [label="utils.py"];
///
///   // Edges
///   "src/auth.py" -> "src/utils.py";
///
///   // Cycles highlighted in red
///   "src/a.py" -> "src/b.py" [color=red];
/// }
/// ```
pub fn format_deps_dot(report: &DepsReport) -> String {
    let mut output = String::with_capacity(1024);

    // Count nodes for large graph warning (S7-R43)
    let mut nodes: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (file, deps) in &report.internal_dependencies {
        nodes.insert(file.display().to_string());
        for dep in deps {
            nodes.insert(dep.display().to_string());
        }
    }

    if nodes.len() > LARGE_GRAPH_THRESHOLD {
        eprintln!(
            "Warning: Large graph with {} nodes. Consider using --collapse-packages or filtering.",
            nodes.len()
        );
    }

    output.push_str("digraph deps {\n");
    output.push_str("  rankdir=LR;\n");
    output.push_str("  node [shape=box, fontname=\"Helvetica\"];\n");
    output.push_str("  edge [fontname=\"Helvetica\", fontsize=10];\n\n");

    // Output nodes with labels (S7-R42: quote all identifiers)
    output.push_str("  // Nodes\n");
    for node in &nodes {
        let label = std::path::Path::new(node)
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_else(|| node.into());
        // Escape quotes in node identifier and label
        let escaped_node = escape_dot_string(node);
        let escaped_label = escape_dot_string(&label);
        output.push_str(&format!(
            "  \"{}\" [label=\"{}\"];\n",
            escaped_node, escaped_label
        ));
    }
    output.push('\n');

    // Collect cycle edges for highlighting
    let mut cycle_edges: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for cycle in &report.circular_dependencies {
        for i in 0..cycle.path.len() {
            let from = cycle.path[i].display().to_string();
            let to = cycle.path[(i + 1) % cycle.path.len()].display().to_string();
            cycle_edges.insert((from, to));
        }
    }

    // Output edges (S7-R42: quote all identifiers)
    output.push_str("  // Edges\n");
    for (file, deps) in &report.internal_dependencies {
        let from = file.display().to_string();
        let escaped_from = escape_dot_string(&from);
        for dep in deps {
            let to = dep.display().to_string();
            let escaped_to = escape_dot_string(&to);
            if cycle_edges.contains(&(from.clone(), to.clone())) {
                // Highlight cycle edges in red (spec)
                output.push_str(&format!(
                    "  \"{}\" -> \"{}\" [color=red, penwidth=2];\n",
                    escaped_from, escaped_to
                ));
            } else {
                output.push_str(&format!("  \"{}\" -> \"{}\";\n", escaped_from, escaped_to));
            }
        }
    }

    output.push_str("}\n");
    output
}

/// Escape special characters in DOT strings.
fn escape_dot_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Capitalize the first letter of a string.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deps_report_default() {
        let report = DepsReport::default();
        assert!(report.root.as_os_str().is_empty());
        assert!(report.language.is_empty());
        assert!(report.internal_dependencies.is_empty());
        assert!(report.external_dependencies.is_empty());
        assert!(report.circular_dependencies.is_empty());
        assert_eq!(report.stats.total_files, 0);
    }

    #[test]
    fn test_dep_node_hash_eq_by_path() {
        let node1 = DepNode::with_name(
            PathBuf::from("src/auth.py"),
            "auth".to_string(),
            DepKind::Internal,
        );
        let node2 = DepNode::with_name(
            PathBuf::from("src/auth.py"),
            "different_name".to_string(), // Different name, same path
            DepKind::External,            // Different kind, same path
        );
        let node3 = DepNode::with_name(
            PathBuf::from("src/utils.py"),
            "auth".to_string(), // Same name, different path
            DepKind::Internal,
        );

        // node1 and node2 should be equal (same path)
        assert_eq!(node1, node2);

        // node1 and node3 should not be equal (different path)
        assert_ne!(node1, node3);

        // Test hash consistency with equality
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(node1.clone());
        assert!(set.contains(&node2)); // Should find node2 via node1's path
        assert!(!set.contains(&node3)); // Should not find node3
    }

    #[test]
    fn test_dep_cycle_canonical() {
        // Cycle: A -> B -> C -> A
        let cycle1 = DepCycle::new(vec![
            PathBuf::from("a.py"),
            PathBuf::from("b.py"),
            PathBuf::from("c.py"),
        ]);

        // Same cycle starting from B: B -> C -> A -> B
        let cycle2 = DepCycle::new(vec![
            PathBuf::from("b.py"),
            PathBuf::from("c.py"),
            PathBuf::from("a.py"),
        ]);

        // Same cycle starting from C: C -> A -> B -> C
        let cycle3 = DepCycle::new(vec![
            PathBuf::from("c.py"),
            PathBuf::from("a.py"),
            PathBuf::from("b.py"),
        ]);

        // All should have the same canonical form
        let c1 = cycle1.canonical();
        let c2 = cycle2.canonical();
        let c3 = cycle3.canonical();

        assert_eq!(c1.path, c2.path);
        assert_eq!(c2.path, c3.path);

        // Canonical form should start with 'a.py' (lexicographically smallest)
        assert_eq!(c1.path[0], PathBuf::from("a.py"));
    }

    #[test]
    fn test_dep_cycle_eq_hash() {
        let cycle1 = DepCycle::new(vec![
            PathBuf::from("a.py"),
            PathBuf::from("b.py"),
            PathBuf::from("c.py"),
        ]);

        let cycle2 = DepCycle::new(vec![
            PathBuf::from("b.py"),
            PathBuf::from("c.py"),
            PathBuf::from("a.py"),
        ]);

        // Same cycle, different starting points - should be equal
        assert_eq!(cycle1, cycle2);

        // Should work in HashSet
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(cycle1);
        assert!(set.contains(&cycle2));
        assert_eq!(set.len(), 1); // Only one unique cycle
    }

    #[test]
    fn test_dep_kind_default() {
        assert_eq!(DepKind::default(), DepKind::Internal);
    }

    #[test]
    fn test_dep_stats_default() {
        let stats = DepStats::default();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_internal_deps, 0);
        assert_eq!(stats.total_external_deps, 0);
        assert_eq!(stats.max_depth, 0);
        assert_eq!(stats.cycles_found, 0);
        assert_eq!(stats.leaf_files, 0);
        assert_eq!(stats.root_files, 0);
    }

    #[test]
    fn test_deps_options_builders() {
        let opts = DepsOptions::with_external();
        assert!(opts.include_external);

        let opts = DepsOptions::cycles_only();
        assert!(opts.show_cycles_only);

        let opts = DepsOptions::default()
            .with_max_cycle_length(5)
            .with_max_depth(3);
        assert_eq!(opts.max_cycle_length, Some(5));
        assert_eq!(opts.max_depth, Some(3));
    }

    #[test]
    fn test_dep_edge_constructors() {
        let edge = DepEdge::new(PathBuf::from("a.py"), PathBuf::from("b.py"));
        assert_eq!(edge.from, PathBuf::from("a.py"));
        assert_eq!(edge.to, PathBuf::from("b.py"));
        assert!(edge.line.is_none());
        assert!(edge.import_text.is_none());

        let edge = DepEdge::with_line(PathBuf::from("a.py"), PathBuf::from("b.py"), 10);
        assert_eq!(edge.line, Some(10));
        assert!(edge.import_text.is_none());

        let edge = DepEdge::with_details(
            PathBuf::from("a.py"),
            PathBuf::from("b.py"),
            10,
            "from b import func".to_string(),
        );
        assert_eq!(edge.line, Some(10));
        assert_eq!(edge.import_text, Some("from b import func".to_string()));
    }

    #[test]
    fn test_deps_report_serialization() {
        let mut report = DepsReport {
            root: PathBuf::from("src"),
            language: "python".to_string(),
            stats: DepStats {
                total_files: 2,
                total_internal_deps: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        report
            .internal_dependencies
            .insert(PathBuf::from("a.py"), vec![PathBuf::from("b.py")]);

        // Should serialize without errors
        let json = serde_json::to_string(&report).expect("serialization failed");
        assert!(json.contains("\"root\":\"src\""));
        assert!(json.contains("\"language\":\"python\""));

        // Should deserialize back
        let parsed: DepsReport = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(parsed.root, PathBuf::from("src"));
        assert_eq!(parsed.language, "python");
    }

    #[test]
    fn test_btreemap_deterministic_order() {
        // Verify BTreeMap produces deterministic JSON output
        let mut deps1 = BTreeMap::new();
        deps1.insert(PathBuf::from("z.py"), vec![PathBuf::from("a.py")]);
        deps1.insert(PathBuf::from("a.py"), vec![PathBuf::from("b.py")]);
        deps1.insert(PathBuf::from("m.py"), vec![PathBuf::from("c.py")]);

        let mut deps2 = BTreeMap::new();
        // Insert in different order
        deps2.insert(PathBuf::from("m.py"), vec![PathBuf::from("c.py")]);
        deps2.insert(PathBuf::from("a.py"), vec![PathBuf::from("b.py")]);
        deps2.insert(PathBuf::from("z.py"), vec![PathBuf::from("a.py")]);

        let json1 = serde_json::to_string(&deps1).unwrap();
        let json2 = serde_json::to_string(&deps2).unwrap();

        // BTreeMap ensures same JSON regardless of insertion order
        assert_eq!(json1, json2);

        // Verify alphabetical order in JSON
        let a_pos = json1.find("a.py").unwrap();
        let m_pos = json1.find("m.py").unwrap();
        let z_pos = json1.find("z.py").unwrap();
        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    // =========================================================================
    // C / C++ import resolver tests
    // =========================================================================

    #[test]
    fn test_build_module_index_c_header_files() {
        let root = PathBuf::from("/project");
        let files = vec![
            PathBuf::from("/project/src/utils.h"),
            PathBuf::from("/project/src/utils.c"),
            PathBuf::from("/project/include/config.h"),
            PathBuf::from("/project/src/net/socket.h"),
        ];
        let index = build_module_index(&root, &files, Language::C);

        // Header files should be indexed by their relative path
        assert!(index.contains_key("src/utils.h"));
        assert_eq!(index["src/utils.h"], PathBuf::from("/project/src/utils.h"));

        // Also indexed by filename only
        assert!(index.contains_key("utils.h"));

        // Nested headers
        assert!(index.contains_key("include/config.h"));
        assert!(index.contains_key("config.h"));
        assert!(index.contains_key("src/net/socket.h"));
        assert!(index.contains_key("net/socket.h"));
        assert!(index.contains_key("socket.h"));
    }

    #[test]
    fn test_build_module_index_cpp_header_files() {
        let root = PathBuf::from("/project");
        let files = vec![
            PathBuf::from("/project/include/widget.hpp"),
            PathBuf::from("/project/src/widget.cpp"),
        ];
        let index = build_module_index(&root, &files, Language::Cpp);

        assert!(index.contains_key("include/widget.hpp"));
        assert!(index.contains_key("widget.hpp"));
    }

    #[test]
    fn test_resolve_c_local_include() {
        let mut index = HashMap::new();
        index.insert(
            "src/utils.h".to_string(),
            PathBuf::from("/project/src/utils.h"),
        );
        index.insert("utils.h".to_string(), PathBuf::from("/project/src/utils.h"));

        let import = ImportInfo {
            module: "utils.h".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 0,
        };
        let result = resolve_c_cpp_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/project/src/utils.h"));
    }

    #[test]
    fn test_resolve_c_system_include_returns_none() {
        let index = HashMap::new();
        let import = ImportInfo {
            module: "stdio.h".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 0,
        };
        let result = resolve_c_cpp_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_classify_c_system_header_is_stdlib() {
        // rc3-external-deps-c-lua-php-v1: `<...>` system header (is_from
        // Some(true)) classifies as Stdlib so it stays OFF the third-party
        // External axis (and out of total_external_deps).
        let index = HashMap::new();
        let import = ImportInfo {
            module: "stdio.h".to_string(),
            names: Vec::new(),
            is_from: Some(true),
            alias: None,
            line: 0,
        };
        let kind = classify_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
            Language::C,
        );
        assert_eq!(kind, DepKind::Stdlib);

        // A `<arpa/inet.h>`-style nested system header (NOT in any allow-list)
        // is still Stdlib purely on the angle-bracket signal.
        let import2 = ImportInfo {
            module: "arpa/inet.h".to_string(),
            names: Vec::new(),
            is_from: Some(true),
            alias: None,
            line: 0,
        };
        assert_eq!(
            classify_import(
                &import2,
                Path::new("/project"),
                Path::new("/project/src/main.c"),
                &index,
                Language::C,
            ),
            DepKind::Stdlib
        );
    }

    #[test]
    fn test_classify_c_local_quoted_header_is_internal() {
        // rc3-external-deps-c-lua-php-v1: an unresolved `"local.h"` quoted
        // include (is_from Some(false)) is a project-local file by C
        // semantics -> Internal, never inflating total_external_deps.
        let index = HashMap::new();
        let import = ImportInfo {
            module: "local.h".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let kind = classify_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
            Language::C,
        );
        assert_eq!(kind, DepKind::Internal);
    }

    #[test]
    fn test_resolve_c_relative_path_include() {
        let mut index = HashMap::new();
        index.insert(
            "net/socket.h".to_string(),
            PathBuf::from("/project/src/net/socket.h"),
        );
        index.insert(
            "src/net/socket.h".to_string(),
            PathBuf::from("/project/src/net/socket.h"),
        );

        let import = ImportInfo {
            module: "net/socket.h".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 0,
        };
        let result = resolve_c_cpp_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/project/src/net/socket.h"));
    }

    // =========================================================================
    // Ruby import resolver tests
    // =========================================================================

    #[test]
    fn test_build_module_index_ruby() {
        let root = PathBuf::from("/project");
        let files = vec![
            PathBuf::from("/project/lib/devise/models.rb"),
            PathBuf::from("/project/lib/utils.rb"),
            PathBuf::from("/project/app/models/user.rb"),
        ];
        let index = build_module_index(&root, &files, Language::Ruby);

        assert!(index.contains_key("devise/models"));
        assert_eq!(
            index["devise/models"],
            PathBuf::from("/project/lib/devise/models.rb")
        );
        assert!(index.contains_key("lib/devise/models"));
        assert!(index.contains_key("utils"));
    }

    #[test]
    fn test_resolve_ruby_require() {
        let mut index = HashMap::new();
        index.insert(
            "devise/models".to_string(),
            PathBuf::from("/project/lib/devise/models.rb"),
        );

        let import = ImportInfo {
            module: "devise/models".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 0,
        };
        let result = resolve_ruby_import(
            &import,
            Path::new("/project"),
            Path::new("/project/app/main.rb"),
            &index,
        );
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/project/lib/devise/models.rb")
        );
    }

    #[test]
    fn test_resolve_ruby_require_relative() {
        let mut index = HashMap::new();
        index.insert("utils".to_string(), PathBuf::from("/project/lib/utils.rb"));

        let import = ImportInfo {
            module: "utils".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 0,
        };
        let result = resolve_ruby_import(
            &import,
            Path::new("/project"),
            Path::new("/project/lib/main.rb"),
            &index,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/project/lib/utils.rb"));
    }

    // =========================================================================
    // C# import resolver tests
    // =========================================================================

    #[test]
    fn test_build_module_index_csharp() {
        let root = PathBuf::from("/project");
        let files = vec![
            PathBuf::from("/project/Newtonsoft/Json/JsonConvert.cs"),
            PathBuf::from("/project/MyApp/Models/User.cs"),
            PathBuf::from("/project/MyApp/Services/AuthService.cs"),
        ];
        let index = build_module_index(&root, &files, Language::CSharp);

        assert!(index.contains_key("Newtonsoft.Json.JsonConvert"));
        assert!(index.contains_key("MyApp.Models.User"));
        assert!(index.contains_key("MyApp.Services.AuthService"));
        assert!(index.contains_key("Newtonsoft.Json"));
        assert!(index.contains_key("MyApp.Models"));
    }

    #[test]
    fn test_resolve_csharp_using() {
        let mut index = HashMap::new();
        index.insert(
            "MyApp.Models".to_string(),
            PathBuf::from("/project/MyApp/Models/User.cs"),
        );

        let import = ImportInfo {
            module: "MyApp.Models".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_csharp_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Program.cs"),
            &index,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_csharp_system_namespace_returns_none() {
        let index = HashMap::new();
        let import = ImportInfo {
            module: "System.Collections.Generic".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_csharp_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Program.cs"),
            &index,
        );
        assert!(result.is_none());
    }

    // =========================================================================
    // Scala import resolver tests
    // =========================================================================

    #[test]
    fn test_build_module_index_scala() {
        let root = PathBuf::from("/project");
        let files = vec![
            PathBuf::from("/project/cats/Functor.scala"),
            PathBuf::from("/project/myapp/models/User.scala"),
            PathBuf::from("/project/myapp/services/Auth.scala"),
        ];
        let index = build_module_index(&root, &files, Language::Scala);

        assert!(index.contains_key("cats.Functor"));
        assert!(index.contains_key("myapp.models.User"));
        assert!(index.contains_key("myapp.services.Auth"));
        assert!(index.contains_key("myapp.models"));
        assert!(index.contains_key("myapp.services"));
    }

    #[test]
    fn test_resolve_scala_simple_import() {
        let mut index = HashMap::new();
        index.insert(
            "cats.Functor".to_string(),
            PathBuf::from("/project/cats/Functor.scala"),
        );

        let import = ImportInfo {
            module: "cats.Functor".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_scala_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Main.scala"),
            &index,
        );
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/project/cats/Functor.scala")
        );
    }

    #[test]
    fn test_resolve_scala_wildcard_import() {
        let mut index = HashMap::new();
        index.insert(
            "myapp.models".to_string(),
            PathBuf::from("/project/myapp/models/User.scala"),
        );

        let import = ImportInfo {
            module: "myapp.models".to_string(),
            names: vec!["*".to_string()],
            is_from: Some(true),
            alias: None,
            line: 0,
        };
        let result = resolve_scala_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Main.scala"),
            &index,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_scala_stdlib_returns_none() {
        let index = HashMap::new();
        let import = ImportInfo {
            module: "scala.util.Try".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_scala_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Main.scala"),
            &index,
        );
        assert!(result.is_none());
    }

    // =========================================================================
    // resolve_import integration tests for new languages
    // =========================================================================

    #[test]
    fn test_resolve_import_dispatches_c() {
        let mut index = HashMap::new();
        index.insert("utils.h".to_string(), PathBuf::from("/project/src/utils.h"));

        let import = ImportInfo {
            module: "utils.h".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.c"),
            &index,
            Language::C,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_import_dispatches_cpp() {
        let mut index = HashMap::new();
        index.insert(
            "widget.hpp".to_string(),
            PathBuf::from("/project/include/widget.hpp"),
        );

        let import = ImportInfo {
            module: "widget.hpp".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_import(
            &import,
            Path::new("/project"),
            Path::new("/project/src/main.cpp"),
            &index,
            Language::Cpp,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_import_dispatches_ruby() {
        let mut index = HashMap::new();
        index.insert("utils".to_string(), PathBuf::from("/project/lib/utils.rb"));

        let import = ImportInfo {
            module: "utils".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_import(
            &import,
            Path::new("/project"),
            Path::new("/project/app/main.rb"),
            &index,
            Language::Ruby,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_import_dispatches_csharp() {
        let mut index = HashMap::new();
        index.insert(
            "MyApp.Models".to_string(),
            PathBuf::from("/project/MyApp/Models/User.cs"),
        );

        let import = ImportInfo {
            module: "MyApp.Models".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Program.cs"),
            &index,
            Language::CSharp,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_import_dispatches_scala() {
        let mut index = HashMap::new();
        index.insert(
            "cats.Functor".to_string(),
            PathBuf::from("/project/cats/Functor.scala"),
        );

        let import = ImportInfo {
            module: "cats.Functor".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_import(
            &import,
            Path::new("/project"),
            Path::new("/project/Main.scala"),
            &index,
            Language::Scala,
        );
        assert!(result.is_some());
    }

    // =========================================================================
    // deps-manifest-external-v1 (v0.5.0 T1 AUDIT-FIX) — manifest parsing +
    // unconditional external-dependency population. RED before fix: every
    // ecosystem reported `external_dependencies = {}` / `total_external_deps
    // = 0` for a plain `analyze_dependencies` (no `--include-external`).
    // =========================================================================

    use tempfile::TempDir;

    /// Write `content` to `root/rel`, creating parent dirs.
    fn write_at(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    /// Run `analyze_dependencies` with default options (i.e. WITHOUT
    /// `include_external`) to prove the manifest path populates externals
    /// regardless of the flag.
    fn analyze_default(root: &Path) -> DepsReport {
        analyze_dependencies(root, &DepsOptions::default()).unwrap()
    }

    /// Flatten every external package across all manifest/import entries.
    fn all_external(report: &DepsReport) -> std::collections::BTreeSet<String> {
        report
            .external_dependencies
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    #[test]
    fn test_manifest_go_mod_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "go.mod",
            "module github.com/me/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/net v0.1.0\n\tgithub.com/transitive/dep v0.0.1 // indirect\n)\n",
        );
        write_at(
            root,
            "main.go",
            "package main\n\nimport \"github.com/gin-gonic/gin\"\n\nfunc main() {}\n",
        );

        let report = analyze_default(root);
        let ext = all_external(&report);
        // Declared direct deps present; the `// indirect` one is excluded.
        assert!(
            ext.contains("github.com/gin-gonic/gin"),
            "go.mod direct dep missing: {ext:?}"
        );
        assert!(
            ext.contains("golang.org/x/net"),
            "go.mod direct dep missing: {ext:?}"
        );
        assert!(
            !ext.contains("github.com/transitive/dep"),
            "indirect dep must be excluded: {ext:?}"
        );
        assert!(
            report.stats.total_external_deps >= 2,
            "external count not populated: {}",
            report.stats.total_external_deps
        );
    }

    #[test]
    fn test_manifest_cargo_toml_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"  #:version\n\n[dependencies]\nanyhow = \"1.0\"\nserde = { version = \"1.0\", features = [\"derive\"] }\n\n[dev-dependencies]\ntempfile = \"3\"\n\n[dependencies.tokio]\nversion = \"1\"\nfeatures = [\"full\"]\n",
        );
        write_at(root, "src/main.rs", "fn main() {}\n");

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(ext.contains("anyhow"), "missing anyhow: {ext:?}");
        assert!(ext.contains("serde"), "missing serde: {ext:?}");
        assert!(ext.contains("tempfile"), "missing dev-dep tempfile: {ext:?}");
        assert!(
            ext.contains("tokio"),
            "missing detail-table dep tokio: {ext:?}"
        );
        // The detail table's inner keys must NOT leak as deps.
        assert!(!ext.contains("version"), "inner key leaked: {ext:?}");
        assert!(!ext.contains("features"), "inner key leaked: {ext:?}");
    }

    #[test]
    fn test_manifest_package_json_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "package.json",
            "{\n  \"name\": \"app\",\n  \"dependencies\": { \"axios\": \"^1.0.0\", \"@scope/pkg\": \"1.2.3\" },\n  \"devDependencies\": { \"typescript\": \"^5.0.0\" }\n}\n",
        );
        write_at(root, "index.ts", "export const x = 1;\n");

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(ext.contains("axios"), "missing axios: {ext:?}");
        assert!(ext.contains("@scope/pkg"), "missing scoped dep: {ext:?}");
        assert!(ext.contains("typescript"), "missing devDep: {ext:?}");
    }

    #[test]
    fn test_manifest_gradle_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "build.gradle",
            "dependencies {\n  api libs.okhttp.client\n  implementation \"com.squareup.retrofit2:retrofit:2.9.0\"\n  compileOnly libs.kotlinx.coroutines\n}\n",
        );
        // A Java source so the language detector picks Java.
        write_at(
            root,
            "src/main/java/com/app/Main.java",
            "package com.app;\npublic class Main {}\n",
        );

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(
            ext.contains("com.squareup.retrofit2:retrofit"),
            "missing maven-style gradle coord: {ext:?}"
        );
        assert!(
            ext.contains("okhttp.client"),
            "missing version-catalog accessor: {ext:?}"
        );
        assert!(
            ext.contains("kotlinx.coroutines"),
            "missing compileOnly accessor: {ext:?}"
        );
    }

    #[test]
    fn test_manifest_pom_xml_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "pom.xml",
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.squareup.okhttp3</groupId>\n      <artifactId>okhttp</artifactId>\n      <version>4.0.0</version>\n    </dependency>\n    <dependency>\n      <groupId>io.reactivex.rxjava3</groupId>\n      <artifactId>rxjava</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n",
        );
        write_at(
            root,
            "src/main/java/com/app/Main.java",
            "package com.app;\npublic class Main {}\n",
        );

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(
            ext.contains("com.squareup.okhttp3:okhttp"),
            "missing pom coord: {ext:?}"
        );
        assert!(
            ext.contains("io.reactivex.rxjava3:rxjava"),
            "missing pom coord: {ext:?}"
        );
    }

    #[test]
    fn test_manifest_gemfile_gemspec_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "Gemfile",
            "source 'https://rubygems.org'\ngemspec\ngem 'rake', '~> 13.0'\ngroup :test do\n  gem 'rspec', require: false\nend\n",
        );
        write_at(
            root,
            "app.gemspec",
            "Gem::Specification.new do |s|\n  s.name = 'app'\n  s.add_dependency 'activesupport', '~> 7.0'\n  s.add_development_dependency 'minitest'\nend\n",
        );
        write_at(root, "lib/app.rb", "module App; end\n");

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(ext.contains("rake"), "missing Gemfile gem: {ext:?}");
        assert!(ext.contains("rspec"), "missing grouped gem: {ext:?}");
        assert!(
            ext.contains("activesupport"),
            "missing gemspec add_dependency: {ext:?}"
        );
        assert!(
            ext.contains("minitest"),
            "missing gemspec add_development_dependency: {ext:?}"
        );
    }

    #[test]
    fn test_manifest_mix_exs_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "mix.exs",
            "defmodule App.MixProject do\n  use Mix.Project\n\n  def project do\n    [app: :app, deps: deps()]\n  end\n\n  defp deps do\n    [\n      {:plug, \"~> 1.14\"},\n      {:jason, \"~> 1.0\", optional: true},\n      {:ex_doc, \"~> 0.38\", only: :docs}\n    ]\n  end\nend\n",
        );
        write_at(root, "lib/app.ex", "defmodule App do\nend\n");

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(ext.contains("plug"), "missing hex dep plug: {ext:?}");
        assert!(ext.contains("jason"), "missing hex dep jason: {ext:?}");
        assert!(ext.contains("ex_doc"), "missing hex dep ex_doc: {ext:?}");
        // The keyword-list option atoms must NOT be harvested as deps.
        assert!(!ext.contains("docs"), "option atom leaked: {ext:?}");
        assert!(!ext.contains("test"), "option atom leaked: {ext:?}");
    }

    #[test]
    fn test_manifest_package_swift_external_deps() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "Package.swift",
            "// swift-tools-version:5.7\nimport PackageDescription\nlet package = Package(\n    name: \"App\",\n    dependencies: [\n        .package(url: \"https://github.com/apple/swift-numerics\", from: \"1.0.0\"),\n        .package(url: \"https://github.com/apple/swift-argument-parser.git\", from: \"1.2.0\"),\n    ]\n)\n",
        );
        write_at(root, "Sources/App/main.swift", "print(\"hi\")\n");

        let report = analyze_default(root);
        let ext = all_external(&report);
        assert!(
            ext.contains("swift-numerics"),
            "missing swift pkg (url leaf): {ext:?}"
        );
        assert!(
            ext.contains("swift-argument-parser"),
            "missing swift pkg (.git stripped): {ext:?}"
        );
    }

    #[test]
    fn test_manifest_parse_unit_go_mod_single_line() {
        // Single-line `require` form + block form mixed.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "go.mod",
            "module x\nrequire github.com/a/b v1.0.0\nrequire (\n\tgithub.com/c/d v2.0.0\n)\n",
        );
        let mds = parse_manifest_dependencies(root, Language::Go);
        let pkgs: std::collections::BTreeSet<String> =
            mds.iter().flat_map(|m| m.packages.clone()).collect();
        assert!(pkgs.contains("github.com/a/b"));
        assert!(pkgs.contains("github.com/c/d"));
    }

    // =========================================================================
    // kotlin-internal-self-package-v1 (v0.5.0 T1 AUDIT-FIX): a project that
    // OWNS the `kotlinx.coroutines.*` namespace must resolve its own imports
    // as INTERNAL, not have them swallowed by the kotlinx-as-stdlib filter.
    // RED before fix: resolve_kotlin_import bailed on is_kotlin_stdlib first.
    // =========================================================================

    #[test]
    fn test_kotlin_self_owned_kotlinx_package_is_internal() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // The project itself lives under kotlinx.coroutines.* (like the real
        // kotlinx-coroutines repo).
        write_at(
            root,
            "src/Builders.kt",
            "package kotlinx.coroutines\n\nimport kotlinx.coroutines.internal.Foo\n\nfun bar() {}\n",
        );
        write_at(
            root,
            "src/internal/Foo.kt",
            "package kotlinx.coroutines.internal\n\nclass Foo\n",
        );

        let report = analyze_dependencies(root, &DepsOptions::with_external()).unwrap();
        // The import of the project's OWN kotlinx.coroutines.internal must
        // resolve to the internal file, NOT be dropped as stdlib/external.
        let builders = PathBuf::from("src/Builders.kt");
        let internal = report
            .internal_dependencies
            .get(&builders)
            .cloned()
            .unwrap_or_default();
        assert!(
            internal.contains(&PathBuf::from("src/internal/Foo.kt")),
            "self-owned kotlinx package import not resolved internal: {internal:?}"
        );
        // And it must NOT have been counted as an external dep.
        let ext = all_external(&report);
        assert!(
            !ext.iter().any(|e| e.starts_with("kotlinx.coroutines")),
            "self-owned package wrongly classified external: {ext:?}"
        );
    }

    #[test]
    fn test_kotlin_real_external_kotlinx_still_external() {
        // Control: a project that does NOT own kotlinx.coroutines must still
        // treat it as external/stdlib (no regression of the stdlib filter).
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "src/App.kt",
            "package com.example.app\n\nimport kotlinx.coroutines.launch\n\nfun run() {}\n",
        );
        let report = analyze_dependencies(root, &DepsOptions::with_external()).unwrap();
        let app = PathBuf::from("src/App.kt");
        let internal = report
            .internal_dependencies
            .get(&app)
            .cloned()
            .unwrap_or_default();
        assert!(
            internal.is_empty(),
            "external kotlinx wrongly resolved internal: {internal:?}"
        );
    }

    // =========================================================================
    // ruby-stdlib-shadow-v1 (v0.5.0 T1 AUDIT-FIX): a bare `require 'logger'`
    // must classify as stdlib even when the project ships a file named
    // `logger.rb` at a NON-loadpath-root location. RED before fix:
    // resolve_ruby_import had no stdlib guard, so the project file shadowed
    // the stdlib and the dep was counted internal.
    // =========================================================================

    #[test]
    fn test_ruby_bare_stdlib_require_not_shadowed_by_project_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Project ships its OWN logger at a nested path (not loadpath root).
        write_at(
            root,
            "lib/app/middleware/logger.rb",
            "module App\n  class Logger\n  end\nend\n",
        );
        // A consumer does `require 'logger'` (the stdlib) AND a project file.
        write_at(
            root,
            "lib/app/base.rb",
            "require 'logger'\nrequire 'app/middleware/logger'\n\nmodule App\n  class Base\n  end\nend\n",
        );

        let report = analyze_dependencies(root, &DepsOptions::with_external()).unwrap();
        let base = PathBuf::from("lib/app/base.rb");
        let internal = report
            .internal_dependencies
            .get(&base)
            .cloned()
            .unwrap_or_default();
        // The bare stdlib `logger` require must NOT resolve to the project's
        // nested logger.rb. (The `app/middleware/logger` require may resolve.)
        assert!(
            internal.contains(&PathBuf::from("lib/app/middleware/logger.rb")),
            "project-path require should resolve: {internal:?}"
        );
        // Stdlib `require 'logger'` must not be counted as external either.
        let ext = all_external(&report);
        assert!(
            !ext.contains("logger"),
            "stdlib logger wrongly counted external: {ext:?}"
        );
    }

    #[test]
    fn test_resolve_ruby_bare_stdlib_returns_none() {
        // Direct unit on the resolver: a bare stdlib name with a colliding
        // project index entry must return None (stdlib wins).
        let mut index = HashMap::new();
        index.insert(
            "logger".to_string(),
            PathBuf::from("/proj/lib/app/middleware/logger.rb"),
        );
        let import = ImportInfo {
            module: "logger".to_string(),
            names: Vec::new(),
            is_from: None,
            alias: None,
            line: 1,
        };
        let resolved = resolve_ruby_import(
            &import,
            Path::new("/proj"),
            Path::new("/proj/lib/app/base.rb"),
            &index,
        );
        assert!(
            resolved.is_none(),
            "bare stdlib require must not resolve to a project file"
        );
    }

    /// ruby-require-relative-resolution-v1: `require_relative 'middleware/logger'`
    /// from `lib/app/base.rb` must resolve to `lib/app/middleware/logger.rb`
    /// (current-file-relative), an internal edge the pre-fix resolver dropped.
    #[test]
    fn test_ruby_require_relative_resolves_against_current_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "lib/app/middleware/logger.rb",
            "module App\n  class Logger; end\nend\n",
        );
        write_at(
            root,
            "lib/app/base.rb",
            "require_relative 'middleware/logger'\nmodule App\n  class Base; end\nend\n",
        );

        let report = analyze_dependencies(root, &DepsOptions::default()).unwrap();
        let base = PathBuf::from("lib/app/base.rb");
        let internal = report
            .internal_dependencies
            .get(&base)
            .cloned()
            .unwrap_or_default();
        assert!(
            internal.contains(&PathBuf::from("lib/app/middleware/logger.rb")),
            "require_relative path not resolved against current file: {internal:?}"
        );
    }

    // =========================================================================
    // python-decoy-resolution-v1 (v0.5.0 T1 AUDIT-FIX): `from flask import X`
    // must NOT resolve to a deeply-nested test fixture `flask.py`; a top-level
    // package/module of that name (or external) takes priority. RED before
    // fix: the bare-leaf index entry of a nested fixture shadowed the real one.
    // =========================================================================

    #[test]
    fn test_python_import_not_resolved_to_nested_test_decoy() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // A real top-level package `mypkg`.
        write_at(root, "src/mypkg/__init__.py", "value = 1\n");
        write_at(root, "src/mypkg/app.py", "from mypkg import value\n");
        // A nested test fixture that happens to be named `mypkg.py`.
        write_at(
            root,
            "tests/fixtures/inner/deep/mypkg.py",
            "# decoy module named like the package\n",
        );
        // A consumer importing the package.
        write_at(root, "src/consumer.py", "from mypkg import value\n");

        let report = analyze_dependencies(root, &DepsOptions::with_external()).unwrap();
        let consumer = PathBuf::from("src/consumer.py");
        let internal = report
            .internal_dependencies
            .get(&consumer)
            .cloned()
            .unwrap_or_default();
        // It must resolve to the real package __init__, NOT the nested decoy.
        assert!(
            !internal.contains(&PathBuf::from("tests/fixtures/inner/deep/mypkg.py")),
            "import resolved to nested test decoy: {internal:?}"
        );
    }

    // =========================================================================
    // R7 cluster[10] deps-graph fixes (v0.5.0 CLOSEOUT)
    // =========================================================================

    /// RC1 (#120,#121,#28): C++ `.h` headers must be walked so `#include "x.h"`
    /// resolves to an internal dependency. RED before fix: `analyze_dependencies`
    /// used `language.extensions()` (no `.h` for Cpp), so a `.cpp` that includes
    /// a project `.h` produced ZERO internal deps and the `.h` was never indexed.
    #[test]
    fn test_cpp_deps_resolves_header_includes() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "src/format.h",
            "#pragma once\nint fmt();\n",
        );
        write_at(
            root,
            "src/format.cpp",
            "#include \"format.h\"\nint fmt() { return 1; }\n",
        );
        // Header-to-header include too.
        write_at(
            root,
            "src/core.h",
            "#pragma once\n#include \"format.h\"\nstruct Core {};\n",
        );

        let opts = DepsOptions {
            language: Some("cpp".to_string()),
            ..Default::default()
        };
        let report = analyze_dependencies(root, &opts).unwrap();
        // The .h files must be counted in the walk.
        assert!(
            report.stats.total_files >= 3,
            "headers excluded from walk: total_files={}",
            report.stats.total_files
        );
        // format.cpp -> format.h must be an internal edge.
        let cpp = PathBuf::from("src/format.cpp");
        let cpp_deps = report
            .internal_dependencies
            .get(&cpp)
            .cloned()
            .unwrap_or_default();
        assert!(
            cpp_deps.contains(&PathBuf::from("src/format.h")),
            "format.cpp -> format.h internal edge missing: {cpp_deps:?}"
        );
        assert!(
            report.stats.total_internal_deps >= 2,
            "expected >=2 internal deps (format.cpp->format.h, core.h->format.h), got {}",
            report.stats.total_internal_deps
        );
    }

    /// RC14 (#199): Scala package-prefix over-resolution -> false cycle. An
    /// UNRESOLVABLE deeper import `cats.effect.tracing.TracingConstants`
    /// (whose file is absent) must NOT resolve to a shorter ANCESTOR-package
    /// file (`cats.effect` -> IO.scala). RED before fix: the prefix-shortening
    /// fallback walked all the way up to `cats.effect`, fabricating a false
    /// edge that closed a 2-cycle.
    #[test]
    fn test_resolve_scala_import_no_ancestor_package_overmatch() {
        let mut index = HashMap::new();
        // IO.scala lives in package `cats.effect`; index registers the
        // parent-package key `cats.effect` -> IO.scala (first file wins).
        index.insert(
            "cats.effect".to_string(),
            PathBuf::from("/p/cats/effect/IO.scala"),
        );
        index.insert(
            "cats.effect.IO".to_string(),
            PathBuf::from("/p/cats/effect/IO.scala"),
        );

        // An import of a type in a DEEPER package whose file is absent.
        let import = ImportInfo {
            module: "cats.effect.tracing.TracingConstants".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_scala_import(
            &import,
            Path::new("/p"),
            Path::new("/p/cats/effect/unsafe/LocalQueue.scala"),
            &index,
        );
        assert!(
            result.is_none(),
            "deeper import must NOT resolve to an ancestor-package file (got {result:?})"
        );
    }

    /// RC14 regression guard: dropping the TYPE segment to reach the import's
    /// OWN package still resolves. `import a.b.C` where only the package
    /// `a.b` is indexed must resolve to the `a.b` file.
    #[test]
    fn test_resolve_scala_import_own_package_still_resolves() {
        let mut index = HashMap::new();
        index.insert(
            "myapp.models".to_string(),
            PathBuf::from("/p/myapp/models/User.scala"),
        );
        let import = ImportInfo {
            module: "myapp.models.User".to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line: 0,
        };
        let result = resolve_scala_import(
            &import,
            Path::new("/p"),
            Path::new("/p/Main.scala"),
            &index,
        );
        assert_eq!(
            result,
            Some(PathBuf::from("/p/myapp/models/User.scala")),
            "import of a type in package a.b must resolve to the a.b package file"
        );
    }

    /// RC2 (#236): Swift internal module dependencies. `import HeapModule`
    /// where `Sources/HeapModule/` exists in the project must resolve to an
    /// internal edge. RED before fix: `index_module_for_language` and
    /// `resolve_import` had no `Language::Swift` arm (`_ => {}` / `_ => None`),
    /// so every Swift import fell through to External and internal stayed 0.
    #[test]
    fn test_swift_deps_resolves_module_directory_imports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Swift Package layout: each Sources/<Module>/ dir is an importable
        // module.
        write_at(
            root,
            "Sources/HeapModule/Heap.swift",
            "public struct Heap<T> { public init() {} public func popMax() -> T? { nil } }\n",
        );
        write_at(
            root,
            "Sources/Collections/Deque.swift",
            "import HeapModule\npublic struct Deque {}\n",
        );

        let opts = DepsOptions {
            language: Some("swift".to_string()),
            ..Default::default()
        };
        let report = analyze_dependencies(root, &opts).unwrap();
        // Deque.swift imports HeapModule -> must resolve to a file in
        // Sources/HeapModule.
        let consumer = PathBuf::from("Sources/Collections/Deque.swift");
        let internal = report
            .internal_dependencies
            .get(&consumer)
            .cloned()
            .unwrap_or_default();
        assert!(
            internal
                .iter()
                .any(|p| p.starts_with("Sources/HeapModule")),
            "Swift `import HeapModule` did not resolve to Sources/HeapModule: {internal:?}"
        );
        assert!(
            report.stats.total_internal_deps >= 1,
            "Swift internal deps still zero: {}",
            report.stats.total_internal_deps
        );
    }
}
