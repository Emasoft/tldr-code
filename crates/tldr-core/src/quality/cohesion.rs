//! Cohesion Analyzer for Health Command
//!
//! This module provides class cohesion analysis using the LCOM4 metric.
//! It creates a NEW implementation (not reusing debt.rs LCOM4 which returns f64).
//!
//! # LCOM4 Algorithm
//!
//! LCOM4 (Lack of Cohesion of Methods 4) measures class cohesion by counting
//! connected components in the method-field graph:
//!
//! 1. For each class, build a graph where nodes = methods
//! 2. Add edges between methods that share at least one field access
//! 3. Count connected components using Union-Find
//! 4. LCOM4 = component count (usize, NOT normalized!)
//!
//! # Interpretation
//!
//! - LCOM4 = 1: Fully cohesive (all methods share fields, single responsibility)
//! - LCOM4 > 1: Multiple responsibilities, candidate for splitting
//! - LCOM4 = 0: Degenerate case (no methods)
//!
//! # Multi-Language Support
//!
//! - Python: class with def methods
//! - TypeScript/JavaScript: class with methods
//! - Java: class/interface/enum with methods
//! - Go: struct with receiver methods
//! - Rust: struct with impl block methods
//! - Ruby: class with def methods, @instance_variable field access
//! - C#: class/struct/interface with methods, this.field access
//! - Scala: class/object/trait with def methods, this.field access
//! - PHP: class/interface/trait with function methods, $this->field access
//!
//! # References
//!
//! - Chidamber & Kemerer, "A Metrics Suite for Object Oriented Design"
//! - Health spec section 4.2

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::walker::walk_project;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ast::parser::parse;
use crate::error::TldrError;
use crate::types::Language;
use crate::TldrResult;

// =============================================================================
// Types
// =============================================================================

/// Information about a connected component in the method-field graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Methods in this component
    pub methods: Vec<String>,
    /// Fields accessed by methods in this component
    pub fields: Vec<String>,
}

/// Verdict for class cohesion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionVerdict {
    /// Class is cohesive (LCOM4 <= threshold)
    Cohesive,
    /// Class should be considered for splitting (LCOM4 > threshold)
    SplitCandidate,
}

/// Cohesion analysis for a single class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassCohesion {
    /// Class/struct name
    pub name: String,
    /// File path containing the class
    pub file: PathBuf,
    /// Line number where the class starts
    pub line: usize,
    /// Number of methods (excluding dunders)
    pub method_count: usize,
    /// Number of unique fields accessed
    pub field_count: usize,
    /// LCOM4 value: raw connected component count (NOT normalized!)
    /// - 0: no methods (degenerate)
    /// - 1: fully cohesive
    /// - >1: multiple responsibilities
    pub lcom4: usize,
    /// Connected components with their methods and fields
    pub components: Vec<ComponentInfo>,
    /// Cohesion verdict based on threshold
    pub verdict: CohesionVerdict,
    /// Optional suggestion for splitting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_suggestion: Option<String>,
}

/// Summary statistics for cohesion analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CohesionSummary {
    /// Total number of classes analyzed
    pub total_classes: usize,
    /// Number of cohesive classes (LCOM4 <= threshold)
    pub cohesive: usize,
    /// Number of split candidates (LCOM4 > threshold)
    pub split_candidates: usize,
    /// Average LCOM4 across all classes (None if no classes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_lcom4: Option<f64>,
}

/// Complete cohesion analysis report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CohesionReport {
    /// Number of classes analyzed
    pub classes_analyzed: usize,
    /// Average LCOM4 across all classes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_lcom4: Option<f64>,
    /// Number of classes with low cohesion (LCOM4 > threshold)
    pub low_cohesion_count: usize,
    /// All classes with cohesion data (sorted by LCOM4 descending)
    pub classes: Vec<ClassCohesion>,
    /// Summary statistics
    pub summary: CohesionSummary,
}

/// Options for cohesion analysis
#[derive(Debug, Clone)]
pub struct CohesionOptions {
    /// Include dunder methods in analysis (default: false)
    pub include_dunder: bool,
    /// Threshold for low cohesion detection (default: 2)
    /// Classes with LCOM4 > threshold are flagged as SplitCandidate
    pub low_cohesion_threshold: usize,
}

impl Default for CohesionOptions {
    fn default() -> Self {
        Self {
            include_dunder: false,
            low_cohesion_threshold: 2,
        }
    }
}

// =============================================================================
// Union-Find Data Structure
// =============================================================================

/// Union-Find data structure for LCOM4 connected component calculation.
/// Uses iterative path compression to avoid stack overflow.
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    /// Find root with iterative path compression
    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        // Find root
        while self.parent[root] != root {
            root = self.parent[root];
        }
        // Path compression
        let mut node = x;
        while self.parent[node] != root {
            let next = self.parent[node];
            self.parent[node] = root;
            node = next;
        }
        root
    }

    /// Union by rank
    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx != ry {
            if self.rank[rx] < self.rank[ry] {
                self.parent[rx] = ry;
            } else if self.rank[rx] > self.rank[ry] {
                self.parent[ry] = rx;
            } else {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
    }

    /// Count connected components
    fn count_components(&mut self) -> usize {
        let n = self.parent.len();
        if n == 0 {
            return 0;
        }
        (0..n).map(|i| self.find(i)).collect::<HashSet<_>>().len()
    }

    /// Get component ID for each node (after all unions)
    fn get_components(&mut self) -> Vec<usize> {
        let n = self.parent.len();
        (0..n).map(|i| self.find(i)).collect()
    }
}

// =============================================================================
// Internal Types for Class Extraction
// =============================================================================

/// Method information for LCOM4 calculation
struct MethodInfo {
    name: String,
    start_byte: usize,
    end_byte: usize,
}

/// Class information for LCOM4 calculation
#[derive(Default)]
struct ClassInfo {
    name: String,
    line: usize,
    methods: Vec<MethodInfo>,
    /// cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): marks a class
    /// declaration as `partial` (currently emitted only for the C#
    /// `partial class Foo {}` form). When `true`, the directory walker
    /// merges all `ClassInfo` entries with the same name across files
    /// before computing LCOM4, so that fields/methods declared in
    /// sibling source files are counted toward the same cohesion entry.
    /// Default `false` for every other class extractor.
    is_partial: bool,
    /// fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet B1'): the enclosing namespace
    /// chain (outermost first) for languages with namespace semantics
    /// (C++ `namespace_definition`, C# `namespace_declaration` /
    /// `file_scoped_namespace_declaration`). Empty for the global namespace
    /// and for languages without namespaces. Combined with `name` it forms
    /// the normalized qualified key used by the shared partial-class
    /// aggregator, so two same-named classes in different namespaces are not
    /// merged.
    namespace_path: Vec<String>,
}

// =============================================================================
// Main API
// =============================================================================

/// Analyze class cohesion using LCOM4 metric
///
/// Scans all supported files in the given path, extracts classes, and computes
/// LCOM4 (connected component count) for each class.
///
/// # Arguments
/// * `path` - Directory or file to analyze
/// * `language` - Optional language filter (auto-detect if None)
/// * `threshold` - LCOM4 threshold for low cohesion (default: 2)
///
/// # Returns
/// * `Ok(CohesionReport)` - Report with cohesion metrics per class
/// * `Err(TldrError)` - On file system errors
///
/// # Behavior
/// - LCOM4 = 1 means cohesive (all methods share fields)
/// - LCOM4 > 1 indicates potential for splitting
/// - Dunder methods (__init__, __str__, etc.) excluded by default
/// - Empty classes return LCOM4 = 0 (degenerate case)
///
/// # Example
/// ```ignore
/// use tldr_core::quality::cohesion::analyze_cohesion;
/// use std::path::Path;
///
/// let report = analyze_cohesion(Path::new("src/"), None, 2)?;
/// for class in &report.classes {
///     if class.lcom4 > 2 {
///         println!("{}: LCOM4={} - consider splitting", class.name, class.lcom4);
///     }
/// }
/// ```
pub fn analyze_cohesion(
    path: &Path,
    language: Option<Language>,
    threshold: usize,
) -> TldrResult<CohesionReport> {
    let options = CohesionOptions {
        include_dunder: false,
        low_cohesion_threshold: threshold,
    };

    analyze_cohesion_with_options(path, language, options)
}

/// Analyze class cohesion with full options
pub fn analyze_cohesion_with_options(
    path: &Path,
    language: Option<Language>,
    options: CohesionOptions,
) -> TldrResult<CohesionReport> {
    // Collect files to analyze
    let file_paths: Vec<PathBuf> = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        walk_project(path)
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter(|e| {
                let p = e.path();
                let detected = Language::from_path(p);
                match (detected, language) {
                    (Some(d), Some(l)) => {
                        if d == l {
                            return true;
                        }
                        // cpp-class-count-agreement-v1 (BUG-CPP-P20-01):
                        // `.h`/`.hpp` headers in a mixed C++ codebase map
                        // to `Language::C` via `Language::from_path`, so
                        // the directory walker rejected them when the
                        // caller requested `Cpp` (e.g. `health` invokes
                        // `analyze_cohesion(path, Some(Cpp), …)`).
                        // `analyze_file_cohesion` already promotes such
                        // headers back to `Cpp` on the `class`/
                        // `namespace` keyword signal. Let the file
                        // through here so that promotion can run; this
                        // re-unifies the `health` ↔ `cohesion`
                        // directory-walk surfaces (extends the v0.4.1
                        // P19-08 file-level fix to the directory walker).
                        if l == Language::Cpp && d == Language::C {
                            if let Some(ext) = p
                                .extension()
                                .and_then(|e| e.to_str())
                            {
                                if ext.eq_ignore_ascii_case("h")
                                    || ext.eq_ignore_ascii_case("hpp")
                                {
                                    return true;
                                }
                            }
                        }
                        false
                    }
                    (Some(_), None) => true,
                    _ => false,
                }
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    };

    // Analyze each file and collect class cohesion data.
    //
    // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): for languages
    // with partial-class semantics (currently C# `partial class Foo`),
    // we first extract per-method field-access sets at file scope and
    // then *merge* entries with the same name across files before
    // computing LCOM4. Languages with no partial-class semantics flow
    // through the legacy per-file `analyze_file_cohesion` path.
    let mut all_classes: Vec<ClassCohesion> = Vec::new();
    // fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet B1'): the partial-class
    // aggregator is keyed on a normalized qualified key
    // `(namespace_path, name)` rather than the bare `name`. This is the SHARED
    // aggregator for C# `partial class` AND (now) C++ in-body classes, so the
    // qualified key simultaneously fixes:
    //   - the C++ `.h`/`.cpp` double-count (both flow through here and merge),
    //   - the C++ `a::Widget` vs `b::Widget` mis-merge, and
    //   - the C# `A.Widget` vs `B.Widget` namespace collision.
    // `name` is still kept as the bare DISPLAY string so output shows the
    // unqualified class name (no cross-language display drift).
    let mut partial_buckets: HashMap<PartialKey, PartialClassBucket> = HashMap::new();

    // fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): partial extractions are
    // buffered first, then bucketed in a SECOND pass so the namespace-
    // compatibility merge (below) can see the full set of qualified keys before
    // deciding where an empty-namespace extraction belongs.
    let mut partial_exts: Vec<MethodFieldsExtraction> = Vec::new();

    // fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): C++ resolves a
    // class's *bare* member accesses against its declared-field set, but for the
    // dominant `.h`/`.cpp` split the data members are declared in the HEADER
    // while the out-of-line method bodies that touch them live in the SOURCE
    // file. Resolving each file in isolation therefore leaves every `.cpp`
    // method's field set empty, so a header-declared class (e.g. tinyxml2's
    // `XMLElement`) looks fully disconnected (`lcom4 == method_count`). Build a
    // PROJECT-WIDE declared-field map keyed on `(namespace_path, class)` up
    // front so the per-file extraction can resolve cross-translation-unit bare
    // members. Empty for non-C++ analyses (the helper only walks C++ files).
    let global_declared = cpp_project_declared_fields(&file_paths);

    for file_path in &file_paths {
        match extract_file_method_fields(file_path, &options, &global_declared) {
            Ok(extractions) => {
                for ext in extractions {
                    if ext.is_partial {
                        partial_exts.push(ext);
                    } else {
                        // Non-partial: compute cohesion immediately as
                        // before (within-file granularity).
                        all_classes.push(cohesion_from_method_fields(
                            &ext.name,
                            &ext.file_path,
                            ext.line,
                            ext.methods,
                            &options,
                        ));
                    }
                }
            }
            Err(_) => {
                // Graceful degradation: ignore parse failures, just
                // like the legacy `analyze_file_cohesion` path.
            }
        }
    }

    // fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): namespace-compatibility merge.
    //
    // B1' keys partial classes on the qualified `(namespace_path, name)` so
    // `a::Widget` and `b::Widget` (and C# `A.Widget` / `B.Widget`) stay
    // distinct. But C++ tree-sitter error recovery can PREMATURELY CLOSE an
    // enclosing `namespace_definition` when a header contains a construct it
    // cannot parse (e.g. tinyxml2's macro-prefixed `class TINYXML2_LIB
    // XMLElement : public XMLNode` recovers as a sibling of the `preproc_ifdef`
    // rather than of the namespace body). The `.h` declaration then carries an
    // EMPTY namespace_path while its cleanly-parsed `.cpp` out-of-line
    // definitions carry the real `["tinyxml2"]`. A pure equality key would NOT
    // merge them → double-count.
    //
    // Resolution (purely structural, no source-text heuristic): an extraction
    // whose namespace_path is EMPTY merges into the qualified bucket of the
    // same bare name IFF EXACTLY ONE such qualified bucket exists. When zero
    // exist it forms its own `([], name)` bucket (a genuine global-scope
    // class); when MORE than one exists the namespace is truly ambiguous, so it
    // is kept separate (never guess which qualified class it belongs to). This
    // collapses the parse-recovery double-count without ever mis-merging two
    // genuinely distinct namespaced classes.
    let mut qualified_names: HashMap<String, HashSet<Vec<String>>> = HashMap::new();
    for ext in &partial_exts {
        if !ext.namespace_path.is_empty() {
            qualified_names
                .entry(ext.name.clone())
                .or_default()
                .insert(ext.namespace_path.clone());
        }
    }

    for ext in partial_exts {
        let resolved_ns: Vec<String> = if ext.namespace_path.is_empty() {
            match qualified_names.get(&ext.name) {
                // Exactly one qualified namespace for this name: adopt it so the
                // parse-recovery-truncated `.h` entry merges with the `.cpp`.
                Some(ns_set) if ns_set.len() == 1 => {
                    ns_set.iter().next().cloned().unwrap_or_default()
                }
                // Zero or ambiguous (>1): keep the empty namespace.
                _ => Vec::new(),
            }
        } else {
            ext.namespace_path.clone()
        };

        let key = PartialKey {
            namespace_path: resolved_ns,
            name: ext.name.clone(),
        };
        let bucket = partial_buckets
            .entry(key)
            .or_insert_with(|| PartialClassBucket {
                name: ext.name.clone(),
                first_file: ext.file_path.clone(),
                first_line: ext.line,
                methods: Vec::new(),
            });
        if ext.line < bucket.first_line
            || (ext.line == bucket.first_line && ext.file_path < bucket.first_file)
        {
            bucket.first_file = ext.file_path.clone();
            bucket.first_line = ext.line;
        }
        bucket.methods.extend(ext.methods);
    }

    // Now compute LCOM4 for merged partial-class buckets.
    for (_, bucket) in partial_buckets {
        // fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): a single logical class can
        // contribute the SAME method twice across the merged sources — e.g. the
        // `.h` carries `Accept` as a declared-only signature (empty field set)
        // while the `.cpp` carries the out-of-line `XMLElement::Accept`
        // definition (the real field accesses). Counting both would inflate
        // `method_count`/LCOM4. Collapse by method name, UNIONING the field sets
        // so the richest signal (from whichever source defined the body) wins.
        let methods = dedup_methods_by_name(bucket.methods);
        all_classes.push(cohesion_from_method_fields(
            &bucket.name,
            &bucket.first_file,
            bucket.first_line,
            methods,
            &options,
        ));
    }

    // Sort by LCOM4 descending (worst cohesion first)
    all_classes.sort_by(|a, b| b.lcom4.cmp(&a.lcom4));

    // Calculate summary statistics
    let total_classes = all_classes.len();
    let total_lcom4: usize = all_classes.iter().map(|c| c.lcom4).sum();
    let avg_lcom4 = if total_classes > 0 {
        Some(total_lcom4 as f64 / total_classes as f64)
    } else {
        None
    };
    let low_cohesion_count = all_classes
        .iter()
        .filter(|c| c.lcom4 > options.low_cohesion_threshold)
        .count();
    let cohesive_count = all_classes
        .iter()
        .filter(|c| c.verdict == CohesionVerdict::Cohesive)
        .count();

    let summary = CohesionSummary {
        total_classes,
        cohesive: cohesive_count,
        split_candidates: low_cohesion_count,
        avg_lcom4,
    };

    Ok(CohesionReport {
        classes_analyzed: total_classes,
        avg_lcom4,
        low_cohesion_count,
        classes: all_classes,
        summary,
    })
}

/// Analyze cohesion for all classes in a single file
///
/// cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): the directory
/// walk now goes through `extract_file_method_fields` +
/// `cohesion_from_method_fields` so partial-class entries can be
/// merged across files. This per-file helper remains live solely for
/// the in-tree unit tests under `mod tests` that exercise the legacy
/// data path directly.
#[cfg(test)]
fn analyze_file_cohesion(
    file_path: &Path,
    options: &CohesionOptions,
) -> TldrResult<Vec<ClassCohesion>> {
    let source = std::fs::read_to_string(file_path)?;
    let mut language = Language::from_path(file_path).ok_or_else(|| {
        TldrError::UnsupportedLanguage(
            file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_string(),
        )
    })?;
    // p19-secondary-fixes-v1 (BUG-P19-08): `Language::from_path` maps
    // `.h` → C. Headers in mixed C++ codebases (tinyxml2.h, Boost,
    // Folly, …) carry the C++ class declarations; cohesion run with
    // `language = C` then dispatches to a `_ => vec![]` arm and emits
    // `classes_analyzed = 0`. When the source contains a `class` /
    // `namespace` keyword, promote to C++ so the new cpp class
    // extractor runs and the count agrees with the
    // `structure --lang cpp` / `interface` surfaces.
    if matches!(language, Language::C)
        && file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("h") || e.eq_ignore_ascii_case("hpp"))
            .unwrap_or(false)
        && (source.contains("\nclass ")
            || source.contains(" class ")
            || source.contains("namespace "))
    {
        language = Language::Cpp;
    }

    // Parse the file using the global parser pool
    let tree = parse(&source, language)?;
    let root = tree.root_node();

    // Extract classes based on language
    let class_infos = extract_classes(root, &source, language);

    // Compute LCOM4 for each class.
    //
    // cpp-class-count-agreement-v1 (BUG-CPP-P20-01): for C++ only,
    // skip classes with zero extracted methods. LCOM4 has no signal
    // on a method-less C++ class — those are typically forward decls
    // (`class Foo;`), pure-virtual interfaces, or class bodies whose
    // methods are all declared inline but defined out-of-line in a
    // `.cpp`. The CLI `cohesion` surface already discards these via
    // the default `min_methods=1` filter; aligning the C++ core path
    // keeps `health`'s `classes_analyzed` summary in step with the
    // standalone CLI surface (tinyxml2.h: 14 instead of 26 noisy
    // entries).
    //
    // Other languages keep the 0-method classes (Rust data-only
    // structs with `impl Default`, etc.) per their existing semantics
    // — see `test_rust_analyze_file_cohesion_on_coupling_rs`.
    let cpp_drop_methodless = matches!(language, Language::Cpp);
    let mut results = Vec::new();
    for class_info in class_infos {
        if cpp_drop_methodless && class_info.methods.is_empty() {
            continue;
        }
        let cohesion = compute_class_cohesion(&class_info, &source, file_path, options);
        results.push(cohesion);
    }

    Ok(results)
}

// =============================================================================
// Cross-file aggregation (v0.4.2 M-030)
// =============================================================================

/// A method paired with the set of fields it accesses, extracted at
/// file scope so it can be transported across the cross-file
/// partial-class aggregator without needing to keep the file's source
/// string alive.
#[derive(Debug, Clone)]
struct MethodFields {
    name: String,
    fields: HashSet<String>,
}

/// A single class extraction from a single file, with field-access
/// sets precomputed per method. The `is_partial` flag selects between
/// per-file cohesion (the legacy path) and cross-file aggregation
/// (M-030).
#[derive(Debug, Clone)]
struct MethodFieldsExtraction {
    name: String,
    file_path: PathBuf,
    line: usize,
    is_partial: bool,
    methods: Vec<MethodFields>,
    /// fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet B1'): enclosing namespace chain
    /// (outermost first). Empty for the global namespace / languages without
    /// namespaces. Forms the qualified partial-class aggregation key together
    /// with `name`.
    namespace_path: Vec<String>,
}

/// fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet B1'): normalized qualified key for
/// the shared partial-class aggregator. Keying on `(namespace_path, name)`
/// instead of the bare `name` prevents two same-named classes that live in
/// different namespaces (C++ `a::Widget` vs `b::Widget`; C# `A.Widget` vs
/// `B.Widget`) from being merged. The bare `name` is still carried separately
/// for DISPLAY so no cross-language output drift is introduced.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartialKey {
    namespace_path: Vec<String>,
    name: String,
}

/// Accumulator for one logical partial class across the dir walk.
#[derive(Debug, Clone)]
struct PartialClassBucket {
    /// Bare class name, used for DISPLAY (the qualified identity lives in the
    /// `PartialKey` used as the map key).
    name: String,
    first_file: PathBuf,
    first_line: usize,
    methods: Vec<MethodFields>,
}

/// Read+parse a file and extract per-method `(name, fields)` pairs for
/// `.h`/`.hpp` headers map to `Language::C` by extension, but a C++ header is
/// the dominant declaration site for C++ classes. Promote such a header to
/// `Language::Cpp` when it carries a `class`/`namespace` keyword (the
/// `analyze_file_cohesion` P19-08 promotion). Factored into one place so every
/// cohesion entry point (per-file extraction AND the project-wide declared-field
/// prepass) shares a single promotion rule.
fn cpp_promote_header_to_cpp(language: Language, file_path: &Path, source: &str) -> Language {
    if matches!(language, Language::C)
        && file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("h") || e.eq_ignore_ascii_case("hpp"))
            .unwrap_or(false)
        && (source.contains("\nclass ")
            || source.contains(" class ")
            || source.contains("namespace "))
    {
        Language::Cpp
    } else {
        language
    }
}

/// every class detected. This is the "data" form used by the M-030
/// cross-file aggregator — it factors out the per-method field-access
/// extraction so the union step at the bucket level is trivial.
fn extract_file_method_fields(
    file_path: &Path,
    options: &CohesionOptions,
    global_declared: &HashMap<(Vec<String>, String), HashSet<String>>,
) -> TldrResult<Vec<MethodFieldsExtraction>> {
    let source = std::fs::read_to_string(file_path)?;
    let mut language = Language::from_path(file_path).ok_or_else(|| {
        TldrError::UnsupportedLanguage(
            file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_string(),
        )
    })?;
    // Mirror the `analyze_file_cohesion` `.h → Cpp` promotion (P19-08).
    language = cpp_promote_header_to_cpp(language, file_path, &source);

    let tree = parse(&source, language)?;
    let root = tree.root_node();

    // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M12):
    // Solidity needs cross-method state-var awareness — the LCOM4
    // "fields" are bare identifiers (no `this`/`self`), so the per-method
    // `extract_field_accesses(method_source, …)` helper cannot determine
    // what is a state-var reference vs. a local variable. We re-walk the
    // file here, collecting per-class state-var names, and look for
    // matching identifiers inside each method's body. The result feeds
    // the existing `cohesion_from_method_fields` aggregator unchanged.
    if matches!(language, Language::Solidity) {
        return Ok(extract_file_method_fields_solidity(&root, &source, file_path));
    }

    // fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet A1+B1'): C++ needs a dedicated
    // path. The generic `extract_field_accesses(method_source, …)` re-parses
    // each method body in isolation, so it only sees `this->member` access and
    // misses the dominant C++ idiom of *bare* member access (`width`, not
    // `this->width`). We re-walk the file, collect each class's `.h`-declared
    // field names, and classify a bare `identifier` as a field access iff it is
    // a declared field and is not shadowed by a parameter / local. This also
    // threads the enclosing-namespace chain so the shared partial aggregator
    // can use a namespace-qualified key.
    if matches!(language, Language::Cpp) {
        return Ok(extract_file_method_fields_cpp(
            &root, &source, file_path, options, global_declared,
        ));
    }

    let class_infos = extract_classes(root, &source, language);

    let mut out: Vec<MethodFieldsExtraction> = Vec::new();

    for class_info in class_infos {
        let methods: Vec<MethodFields> = class_info
            .methods
            .iter()
            .filter(|m| options.include_dunder || !is_dunder_method(&m.name))
            .map(|m| {
                let method_source = &source[m.start_byte..m.end_byte];
                let fields = extract_field_accesses(method_source, file_path);
                MethodFields {
                    name: m.name.clone(),
                    fields,
                }
            })
            .collect();
        out.push(MethodFieldsExtraction {
            name: class_info.name,
            file_path: file_path.to_path_buf(),
            line: class_info.line,
            is_partial: class_info.is_partial,
            methods,
            namespace_path: class_info.namespace_path,
        });
    }
    Ok(out)
}

/// Solidity-specific `MethodFieldsExtraction` walker. Mirrors the generic
/// `extract_file_method_fields` flow, but threads each class's state-var
/// name set through to the per-method field-access scan so that bare
/// state-var references (the Solidity "field access" idiom) are correctly
/// classified.
fn extract_file_method_fields_solidity(
    root: &tree_sitter::Node,
    source: &str,
    file_path: &Path,
) -> Vec<MethodFieldsExtraction> {
    let mut out = Vec::new();
    collect_solidity_method_fields(root, source, file_path, &mut out);
    out
}

fn collect_solidity_method_fields(
    node: &tree_sitter::Node,
    source: &str,
    file_path: &Path,
    out: &mut Vec<MethodFieldsExtraction>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration" => {
                if let Some(info) = build_solidity_cohesion_class_info(&child, source) {
                    let state_var_names = solidity_state_var_names(&child, source);
                    let mut methods: Vec<MethodFields> =
                        Vec::with_capacity(info.methods.len());
                    if let Some(body) = child.child_by_field_name("body") {
                        let mut bc = body.walk();
                        for member in body.children(&mut bc) {
                            let mname = match member.kind() {
                                "function_definition" | "modifier_definition" => {
                                    member
                                        .child_by_field_name("name")
                                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                                        .map(|s| s.to_string())
                                }
                                "constructor_definition" => {
                                    Some("constructor".to_string())
                                }
                                "fallback_receive_definition" => {
                                    Some(solidity_fallback_or_receive_keyword(
                                        &member, source,
                                    ))
                                }
                                _ => None,
                            };
                            if let Some(name) = mname {
                                let fields = solidity_field_accesses_in_method(
                                    &member,
                                    source,
                                    &state_var_names,
                                );
                                methods.push(MethodFields { name, fields });
                            }
                        }
                    }
                    out.push(MethodFieldsExtraction {
                        name: info.name,
                        file_path: file_path.to_path_buf(),
                        line: info.line,
                        is_partial: info.is_partial,
                        methods,
                        namespace_path: Vec::new(),
                    });
                }
            }
            _ => collect_solidity_method_fields(&child, source, file_path, out),
        }
    }
}

/// fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): collapse a method list so each
/// method name appears once, UNIONING the field-access sets of all entries that
/// share a name. Used when a merged partial-class bucket received the same
/// method from more than one source (e.g. a `.h` declared-only signature plus
/// its `.cpp` out-of-line definition). Insertion order of first appearance is
/// preserved so output stays deterministic.
fn dedup_methods_by_name(methods: Vec<MethodFields>) -> Vec<MethodFields> {
    let mut order: Vec<String> = Vec::new();
    let mut by_name: HashMap<String, HashSet<String>> = HashMap::new();
    for m in methods {
        let entry = by_name.entry(m.name.clone()).or_insert_with(|| {
            order.push(m.name.clone());
            HashSet::new()
        });
        entry.extend(m.fields);
    }
    order
        .into_iter()
        .map(|name| {
            let fields = by_name.remove(&name).unwrap_or_default();
            MethodFields { name, fields }
        })
        .collect()
}

/// Compute the LCOM4 result for a class given its precomputed method
/// `(name, fields)` set. Mirrors the algorithm in
/// `compute_class_cohesion` but operates on data that has already been
/// unioned across files (partial-class case) or that came from a
/// single file (the non-partial path).
fn cohesion_from_method_fields(
    name: &str,
    file_path: &Path,
    line: usize,
    methods: Vec<MethodFields>,
    options: &CohesionOptions,
) -> ClassCohesion {
    let method_count = methods.len();

    // Degenerate / singleton method handling identical to
    // `compute_class_cohesion`.
    if method_count == 0 {
        return ClassCohesion {
            name: name.to_string(),
            file: file_path.to_path_buf(),
            line,
            method_count: 0,
            field_count: 0,
            lcom4: 0,
            components: vec![],
            verdict: CohesionVerdict::Cohesive,
            split_suggestion: None,
        };
    }

    if method_count == 1 {
        let m = &methods[0];
        let field_vec: Vec<String> = m.fields.iter().cloned().collect();
        return ClassCohesion {
            name: name.to_string(),
            file: file_path.to_path_buf(),
            line,
            method_count: 1,
            field_count: field_vec.len(),
            lcom4: 1,
            components: vec![ComponentInfo {
                methods: vec![m.name.clone()],
                fields: field_vec,
            }],
            verdict: CohesionVerdict::Cohesive,
            split_suggestion: None,
        };
    }

    let method_fields: Vec<&HashSet<String>> =
        methods.iter().map(|m| &m.fields).collect();
    let all_fields: HashSet<String> =
        method_fields.iter().flat_map(|s| s.iter().cloned()).collect();
    let field_count = all_fields.len();

    if all_fields.is_empty() {
        let lcom4 = method_count;
        let components: Vec<ComponentInfo> = methods
            .iter()
            .map(|m| ComponentInfo {
                methods: vec![m.name.clone()],
                fields: vec![],
            })
            .collect();
        let verdict = if lcom4 > options.low_cohesion_threshold {
            CohesionVerdict::SplitCandidate
        } else {
            CohesionVerdict::Cohesive
        };
        let split_suggestion = if verdict == CohesionVerdict::SplitCandidate {
            Some(format!(
                "Class has {} disconnected methods with no shared state",
                method_count
            ))
        } else {
            None
        };
        return ClassCohesion {
            name: name.to_string(),
            file: file_path.to_path_buf(),
            line,
            method_count,
            field_count: 0,
            lcom4,
            components,
            verdict,
            split_suggestion,
        };
    }

    let mut uf = UnionFind::new(method_count);
    for i in 0..method_count {
        for j in (i + 1)..method_count {
            if !method_fields[i].is_disjoint(method_fields[j]) {
                uf.union(i, j);
            }
        }
    }
    let lcom4 = uf.count_components();
    let component_ids = uf.get_components();
    let mut component_map: HashMap<usize, (Vec<String>, HashSet<String>)> = HashMap::new();
    for (i, &comp_id) in component_ids.iter().enumerate() {
        let entry = component_map
            .entry(comp_id)
            .or_insert_with(|| (Vec::new(), HashSet::new()));
        entry.0.push(methods[i].name.clone());
        entry.1.extend(method_fields[i].iter().cloned());
    }
    let components: Vec<ComponentInfo> = component_map
        .into_values()
        .map(|(methods, fields)| ComponentInfo {
            methods,
            fields: fields.into_iter().collect(),
        })
        .collect();

    let verdict = if lcom4 > options.low_cohesion_threshold {
        CohesionVerdict::SplitCandidate
    } else {
        CohesionVerdict::Cohesive
    };
    let split_suggestion = if verdict == CohesionVerdict::SplitCandidate {
        Some(format!(
            "Consider splitting into {} classes based on {} disconnected method groups",
            lcom4, lcom4
        ))
    } else {
        None
    };

    ClassCohesion {
        name: name.to_string(),
        file: file_path.to_path_buf(),
        line,
        method_count,
        field_count,
        lcom4,
        components,
        verdict,
        split_suggestion,
    }
}

/// Extract classes from the AST based on language
fn extract_classes(root: tree_sitter::Node, source: &str, language: Language) -> Vec<ClassInfo> {
    match language {
        Language::Python => extract_python_classes(root, source),
        Language::TypeScript | Language::JavaScript => extract_typescript_classes(root, source),
        Language::Go => extract_go_structs(root, source),
        Language::Rust => extract_rust_structs(root, source),
        Language::Java => extract_java_classes(root, source),
        Language::Ruby => extract_ruby_classes(root, source),
        Language::CSharp => extract_csharp_classes(root, source),
        Language::Scala => extract_scala_classes(root, source),
        Language::Php => extract_php_classes(root, source),
        // p19-secondary-fixes-v1 (BUG-P19-08): cpp `health` previously
        // reported `classes_analyzed=0` while `structure` (after the
        // BUG-P19-05 fix) and `interface` report ~26 for the same
        // header. Add cpp class extraction so the three pipelines agree
        // on the class count surface.
        Language::Cpp => extract_cpp_classes_cohesion(root, source),
        // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): Phase-21
        // regression — swift extension-only / class+extension files
        // reported `classes:0`. Aggregate `class_declaration`
        // (tree-sitter-swift uses the same node kind for `class`,
        // `struct`, `enum`, `actor`, and `extension`) by extended-type
        // name within the file.
        Language::Swift => extract_swift_classes_cohesion(root, source),
        // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): the kotlin
        // class extractor was entirely absent, so every kotlin file
        // reported `classes:0`. Use the same `class_declaration` /
        // `object_declaration` shape as the structure/interface
        // surfaces (M-022).
        Language::Kotlin => extract_kotlin_classes_cohesion(root, source),
        // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): detect
        // setmetatable-style prototype OO (`local Point = {}; function
        // Point:m()`) for lua/luau, which are the dominant idiomatic
        // class forms in the language. No tree-sitter class node
        // exists; we synthesise one per `local X = {}` whose name is
        // referenced by `function X.m()` / `function X:m()` bindings.
        Language::Lua | Language::Luau => extract_lua_classes_cohesion(root, source),
        // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M12):
        // walk `contract_declaration` / `interface_declaration` /
        // `library_declaration` and emit a `ClassInfo` per declaration.
        // Each class's methods are the `function_definition` /
        // `modifier_definition` / `constructor_definition` /
        // `fallback_receive_definition` children of its body. State
        // variables — the LCOM4 "fields" for Solidity — are NOT carried
        // through `ClassInfo` (which has no `fields` slot for the
        // cohesion path); instead `extract_file_method_fields` /
        // `analyze_file_cohesion` route Solidity through a dedicated
        // branch that knows how to identify bare state-var references
        // inside method bodies (state vars are accessed without any
        // `self`/`this` prefix in Solidity, unlike every other supported
        // language).
        Language::Solidity => extract_solidity_classes_cohesion(root, source),
        // IT3-elixir-02 (v0.5.0 CL-6): the cohesion `extract_classes` dispatch
        // had no Elixir arm, so every `defmodule` reported `classes:0`. Treat
        // an Elixir module as a class whose methods are its `def`/`defp`
        // clauses and whose LCOM4 "fields" are the `@attr` module attributes
        // referenced in each method body (matched by
        // `extract_elixir_module_attribute`).
        Language::Elixir => extract_elixir_classes_cohesion(root, source),
        _ => vec![], // Unsupported language
    }
}

// =============================================================================
// Solidity Class Extraction (v0.5.0 SOL-015c M12)
// =============================================================================

/// Extract Solidity contract / library / interface declarations as
/// `ClassInfo` entries for the cohesion pipeline.
///
/// Grammar reference (tree-sitter-solidity):
///   - `contract_declaration` / `interface_declaration` / `library_declaration`
///     each carry a `name` field (identifier) and a `body` field
///     (`contract_body`).
///   - Method-like members inside the body: `function_definition`,
///     `modifier_definition`, `constructor_definition`,
///     `fallback_receive_definition` — each has a `name` field
///     (except constructor/fallback/receive, which we synthesize as
///     "constructor" / "fallback" / "receive").
///
/// State variables are intentionally NOT collected here. The companion
/// Solidity branch in `extract_file_method_fields` walks `contract_body`
/// children to collect state-variable names and uses them to drive the
/// per-method field-access detection.
fn extract_solidity_classes_cohesion(
    root: tree_sitter::Node,
    source: &str,
) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    walk_solidity_decls(&root, source, &mut classes);
    classes
}

fn walk_solidity_decls(
    node: &tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration" => {
                if let Some(info) = build_solidity_cohesion_class_info(&child, source) {
                    classes.push(info);
                }
            }
            _ => walk_solidity_decls(&child, source, classes),
        }
    }
}

fn build_solidity_cohesion_class_info(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node
        .utf8_text(source.as_bytes())
        .ok()?
        .to_string();
    if name.is_empty() {
        return None;
    }
    let line = node.start_position().row + 1;

    let mut methods: Vec<MethodInfo> = Vec::new();

    if let Some(body) = node.child_by_field_name("body") {
        let mut bc = body.walk();
        for member in body.children(&mut bc) {
            match member.kind() {
                "function_definition" | "modifier_definition" => {
                    if let Some(name_node) = member.child_by_field_name("name") {
                        if let Ok(mname) = name_node.utf8_text(source.as_bytes()) {
                            methods.push(MethodInfo {
                                name: mname.to_string(),
                                start_byte: member.start_byte(),
                                end_byte: member.end_byte(),
                            });
                        }
                    }
                }
                "constructor_definition" => {
                    methods.push(MethodInfo {
                        name: "constructor".to_string(),
                        start_byte: member.start_byte(),
                        end_byte: member.end_byte(),
                    });
                }
                "fallback_receive_definition" => {
                    // tree-sitter-solidity collapses fallback() and
                    // receive() into a single node kind; the discriminator
                    // is the leading keyword child. We synthesise a
                    // stable name for each so the LCOM4 component list
                    // can refer to them.
                    let kw = solidity_fallback_or_receive_keyword(&member, source);
                    methods.push(MethodInfo {
                        name: kw,
                        start_byte: member.start_byte(),
                        end_byte: member.end_byte(),
                    });
                }
                _ => {}
            }
        }
    }

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

/// Distinguish `fallback() external` from `receive() external payable` —
/// both share the `fallback_receive_definition` node kind in the
/// upstream grammar. We scan the children for the leading keyword.
fn solidity_fallback_or_receive_keyword(
    node: &tree_sitter::Node,
    source: &str,
) -> String {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "fallback" {
            return "fallback".to_string();
        }
        if kind == "receive" {
            return "receive".to_string();
        }
        // Some grammar versions emit the keyword as raw text inside a
        // sibling anonymous node; fall back to the source-text scan.
        if let Ok(text) = child.utf8_text(source.as_bytes()) {
            let t = text.trim();
            if t == "fallback" {
                return "fallback".to_string();
            }
            if t == "receive" {
                return "receive".to_string();
            }
        }
    }
    // Defensive default — should never trigger in practice.
    "fallback".to_string()
}

/// Collect bare state-variable names declared at the body scope of a
/// Solidity `contract_declaration` / `library_declaration` /
/// `interface_declaration`. Both `state_variable_declaration` and
/// `constant_variable_declaration` carry a `name` field.
fn solidity_state_var_names(node: &tree_sitter::Node, source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(body) = node.child_by_field_name("body") {
        let mut bc = body.walk();
        for member in body.children(&mut bc) {
            match member.kind() {
                "state_variable_declaration" | "constant_variable_declaration" => {
                    if let Some(name_node) = member.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            out.insert(name.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Walk a Solidity method/function body and return the set of identifier
/// references whose text matches a declared state-variable name.
///
/// Solidity does NOT use `this.`/`self.` for state-variable access — the
/// names appear bare. We collect every `identifier` leaf in the body and
/// intersect with `state_var_names`. This is robust under aliasing
/// (`uint256 x = balances[msg.sender]`), assignment (`balances[to] += amount`),
/// and conditional access. Local variables and parameters that happen to
/// shadow a state-var name are not filtered out — that's a degenerate
/// case that's both rare in real Solidity AND captured deterministically
/// from the AST. (Per the project's AST-only-fixes rule, we accept this
/// classification rather than reach for a regex bodge.)
fn solidity_field_accesses_in_method(
    method_node: &tree_sitter::Node,
    source: &str,
    state_var_names: &HashSet<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    if state_var_names.is_empty() {
        return out;
    }
    let body = method_node
        .child_by_field_name("body")
        .unwrap_or(*method_node);
    solidity_collect_identifier_hits(&body, source, state_var_names, &mut out);
    out
}

fn solidity_collect_identifier_hits(
    node: &tree_sitter::Node,
    source: &str,
    state_var_names: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            if state_var_names.contains(text) {
                out.insert(text.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        solidity_collect_identifier_hits(&child, source, state_var_names, out);
    }
}

// =============================================================================
// Swift Class Extraction (v0.4.2 M-030)
// =============================================================================

/// Extract swift classes/structs/enums/actors AND aggregate extension
/// blocks by extended-type name (within-file).
///
/// `tree-sitter-swift` models `class Foo {}`, `struct Foo {}`,
/// `enum Foo {}`, `actor Foo {}`, and `extension Foo {}` ALL as a
/// `class_declaration` node — the discriminator lives in the leading
/// declaration keyword (the first child). `.child_by_field_name("name")`
/// returns:
///   - for `class Foo {}` -> `type_identifier("Foo")`
///   - for `extension Foo {}` -> `user_type/type_identifier("Foo")`
/// so we read the name field directly. Method bodies live in a
/// `class_body` child (whose children contain `function_declaration`
/// nodes — the same shape the interface command uses post-M-022).
///
/// Aggregation policy: multiple `class_declaration` nodes that resolve
/// to the same name (e.g. `class Shape {...}` + `extension Shape {...}`
/// + `extension Shape {...}`) merge into a single `ClassInfo` whose
/// `methods` list is the union of all of them. The reported `line`
/// is the smallest start-line across the contributing nodes (the
/// canonical declaration site).
fn extract_swift_classes_cohesion(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut by_name: std::collections::BTreeMap<String, ClassInfo> =
        std::collections::BTreeMap::new();
    extract_swift_classes_cohesion_recursive(root, source, &mut by_name);
    by_name.into_values().collect()
}

fn extract_swift_classes_cohesion_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut std::collections::BTreeMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration" || child.kind() == "protocol_declaration" {
            if let Some(info) = extract_swift_class_info(&child, source) {
                let entry = classes
                    .entry(info.name.clone())
                    .or_insert_with(|| ClassInfo {
                        name: info.name.clone(),
                        line: info.line,
                        methods: Vec::new(),
                        is_partial: false,
                        namespace_path: Vec::new(),
                    });
                if info.line < entry.line {
                    entry.line = info.line;
                }
                entry.methods.extend(info.methods);
            }
        }
        // Recurse into children — swift classes/protocols/extensions
        // may be nested inside namespace-like contexts.
        extract_swift_classes_cohesion_recursive(child, source, classes);
    }
}

fn extract_swift_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    // Pull the name via the tree-sitter `name` field. For
    // `extension Foo`, the field still points to the extended type.
    // Fallback: scan direct named children for the first
    // `type_identifier` / `user_type` / `simple_identifier`.
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
        .or_else(|| swift_first_type_identifier(node, source))?;

    if name.is_empty() {
        return None;
    }

    let line = node.start_position().row + 1;
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_body" || child.kind() == "protocol_body" {
            collect_swift_methods(&child, source, &mut methods);
        }
    }
    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn swift_first_type_identifier(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "type_identifier" | "simple_identifier" => {
                if let Ok(t) = child.utf8_text(source.as_bytes()) {
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                }
            }
            "user_type" => {
                if let Some(found) = swift_first_type_identifier(&child, source) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

fn collect_swift_methods(
    body: &tree_sitter::Node,
    source: &str,
    methods: &mut Vec<MethodInfo>,
) {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        // tree-sitter-swift emits `function_declaration` for both
        // class methods and protocol method requirements. `init` is
        // an `init_declaration`; intentionally excluded from LCOM4
        // (constructor-exclusion policy is shared with TS/Java/CSharp).
        if child.kind() == "function_declaration" {
            let name = child
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
                .or_else(|| swift_first_simple_identifier(&child, source));
            if let Some(n) = name {
                if !n.is_empty() {
                    methods.push(MethodInfo {
                        name: n,
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }
}

fn swift_first_simple_identifier(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "simple_identifier" {
            if let Ok(t) = child.utf8_text(source.as_bytes()) {
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

// =============================================================================
// Kotlin Class Extraction (v0.4.2 M-030)
// =============================================================================

/// Extract kotlin classes/objects with their methods.
///
/// Mirrors the shape used by the structure/interface surfaces (M-022):
///   - `class_declaration` -> `class`, `interface`, `enum class`,
///     `data class`, `sealed class`, …
///   - `object_declaration` -> singleton `object Foo {}`
/// Method bodies live in a `class_body` child; methods are
/// `function_declaration` nodes (post-M-022).
fn extract_kotlin_classes_cohesion(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_kotlin_classes_cohesion_recursive(root, source, &mut classes);
    classes
}

fn extract_kotlin_classes_cohesion_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration"
            || child.kind() == "object_declaration"
            || child.kind() == "companion_object"
        {
            if let Some(info) = extract_kotlin_class_info(&child, source) {
                classes.push(info);
            }
        }
        // Recurse into children to discover nested classes.
        extract_kotlin_classes_cohesion_recursive(child, source, classes);
    }
}

fn extract_kotlin_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    // Tree-sitter-kotlin uses `type_identifier` for class names.
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
        .or_else(|| swift_first_type_identifier(node, source))?;

    if name.is_empty() {
        return None;
    }

    let line = node.start_position().row + 1;
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_body" {
            collect_kotlin_methods(&child, source, &mut methods);
        }
    }
    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn collect_kotlin_methods(
    body: &tree_sitter::Node,
    source: &str,
    methods: &mut Vec<MethodInfo>,
) {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "function_declaration" {
            let name = child
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
                .or_else(|| swift_first_simple_identifier(&child, source));
            if let Some(n) = name {
                if !n.is_empty() {
                    methods.push(MethodInfo {
                        name: n,
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }
}

// =============================================================================
// Elixir Module Extraction (v0.5.0 CL-6, IT3-elixir-02)
// =============================================================================

/// Extract Elixir modules (`defmodule`) as cohesion classes.
///
/// IT3-elixir-02 (v0.5.0 CL-6): cohesion had no Elixir arm. An Elixir module is
/// modelled as a class whose methods are its `def`/`defp` function clauses; the
/// LCOM4 "fields" are the module attributes (`@attr`) each method references
/// (recognised downstream by `extract_elixir_module_attribute`).
///
/// Grammar (tree-sitter-elixir): both `defmodule` and `def`/`defp` are `call`
/// nodes — `call(identifier "<keyword>", arguments(...), do_block(...))`. The
/// module name is the `alias` in the `defmodule` arguments; the method name is
/// the leading identifier of the `def`/`defp` clause. Multiple clauses of the
/// same function name (Elixir multi-clause functions) collapse to a single
/// method whose byte span covers all clauses, so a shared `@attr` correctly
/// links them.
fn extract_elixir_classes_cohesion(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_elixir_classes_cohesion_recursive(&root, source, &mut classes);
    classes
}

fn extract_elixir_classes_cohesion_recursive(
    node: &tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some(first) = child.child(0) {
                if first.utf8_text(source.as_bytes()).ok() == Some("defmodule") {
                    if let Some(info) = extract_elixir_module_cohesion_info(&child, source) {
                        classes.push(info);
                    }
                    // Recurse into the module body to capture nested modules.
                    extract_elixir_classes_cohesion_recursive(&child, source, classes);
                    continue;
                }
            }
        }
        extract_elixir_classes_cohesion_recursive(&child, source, classes);
    }
}

fn extract_elixir_module_cohesion_info(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<ClassInfo> {
    // Module name: the `alias` inside the `defmodule` arguments.
    let args = node.child(1)?;
    let name = if args.kind() == "arguments" {
        let mut ac = args.walk();
        let found = args
            .children(&mut ac)
            .find(|c| c.kind() == "alias")
            .and_then(|c| c.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()));
        found
    } else if args.kind() == "alias" {
        args.utf8_text(source.as_bytes()).ok().map(|s| s.to_string())
    } else {
        None
    }?;
    if name.is_empty() {
        return None;
    }

    let line = node.start_position().row + 1;

    // Methods live in the module's `do_block`. Collapse multi-clause
    // functions (`def foo(0)`, `def foo(n)`) into one `MethodInfo` spanning
    // all clauses so a shared `@attr` connects them.
    let mut methods: Vec<MethodInfo> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut bc = node.walk();
    for child in node.children(&mut bc) {
        if child.kind() == "do_block" {
            collect_elixir_methods(&child, source, &mut methods, &mut by_name);
        }
    }

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn collect_elixir_methods(
    body: &tree_sitter::Node,
    source: &str,
    methods: &mut Vec<MethodInfo>,
    by_name: &mut HashMap<String, usize>,
) {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() != "call" {
            continue;
        }
        let Some(first) = child.child(0) else { continue };
        let kw = first.utf8_text(source.as_bytes()).ok();
        if kw != Some("def") && kw != Some("defp") {
            continue;
        }
        if let Some(name) = elixir_method_name(&child, source) {
            if let Some(&idx) = by_name.get(&name) {
                // Extend the existing clause's span to cover this clause too.
                let existing: &mut MethodInfo = &mut methods[idx];
                existing.start_byte = existing.start_byte.min(child.start_byte());
                existing.end_byte = existing.end_byte.max(child.end_byte());
            } else {
                by_name.insert(name.clone(), methods.len());
                methods.push(MethodInfo {
                    name,
                    start_byte: child.start_byte(),
                    end_byte: child.end_byte(),
                });
            }
        }
    }
}

/// Extract the function name from a `def`/`defp` `call` node.
///
/// Shapes handled (tree-sitter-elixir):
///   `def foo(a, b) do ... end`  -> arguments( call( identifier "foo", ...) )
///   `def foo do ... end`        -> arguments( identifier "foo" )
///   `def foo(a) when g do ...`  -> arguments( binary_operator( call(...), guard) )
fn elixir_method_name(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let args = node.child(1)?;
    let clause = if args.kind() == "arguments" {
        args.child(0)?
    } else {
        args
    };
    match clause.kind() {
        "identifier" => clause
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string()),
        "call" => clause
            .child(0)
            .filter(|c| c.kind() == "identifier")
            .and_then(|c| c.utf8_text(source.as_bytes()).ok().map(|s| s.to_string())),
        "binary_operator" => {
            // `def foo(args) when guard` — the function clause is the
            // left-hand `call`/`identifier`.
            let mut bc = clause.walk();
            for c in clause.children(&mut bc) {
                if c.kind() == "call" {
                    if let Some(fname) = c.child(0).filter(|n| n.kind() == "identifier") {
                        return fname
                            .utf8_text(source.as_bytes())
                            .ok()
                            .map(|s| s.to_string());
                    }
                }
                if c.kind() == "identifier" {
                    return c.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

// =============================================================================
// Lua Class Extraction (v0.4.2 M-030)
// =============================================================================

/// Detect setmetatable-style prototype classes in lua/luau source.
///
/// The dominant lua OO idiom is:
/// ```lua
/// local Point = {}
/// function Point.new(x, y) ... end
/// function Point:distance(other) ... end
/// function Point:translate(dx, dy) ... end
/// ```
/// The `Point` identifier is bound by a `local Point = {}` (an
/// empty-table assignment) and then receives methods via dotted
/// (`Point.new`) or colon-prefixed (`Point:distance`) `function`
/// statements.
///
/// Heuristic:
///   1. Collect all `local X = {}` bindings (variable_declaration
///      whose RHS is an empty `table_constructor`).
///   2. Walk `function_declaration` statements and look for nodes
///      whose name is `Foo.bar` or `Foo:bar` (a dot_index_expression
///      / method_index_expression). The bare identifier `Foo` is the
///      class name; the trailing identifier is the method name.
///   3. Emit a `ClassInfo` per `X` that owns >=1 method.
///
/// Body for cohesion field-extraction is the function's full byte
/// span (`self.X` accesses are recognised by `extract_lua_self_field_access`).
fn extract_lua_classes_cohesion(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    // 1. Find candidate class names from `local X = {}` bindings.
    let mut candidates: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    collect_lua_empty_table_locals(root, source, &mut candidates);

    if candidates.is_empty() {
        return Vec::new();
    }

    // 2. Walk function statements and bucket by class name.
    let mut by_name: std::collections::BTreeMap<String, ClassInfo> =
        std::collections::BTreeMap::new();
    collect_lua_table_methods(root, source, &candidates, &mut by_name);

    // 3. Only emit entries that actually own methods.
    by_name
        .into_values()
        .filter(|c| !c.methods.is_empty())
        .collect()
}

fn collect_lua_empty_table_locals(
    node: tree_sitter::Node,
    source: &str,
    names: &mut std::collections::BTreeSet<String>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // tree-sitter-lua: `variable_declaration` wraps both `local
        // X = ...` and bare `X = ...` statements; the LHS appears as
        // `assignment_statement` -> `variable_list` and RHS as
        // `expression_list`.
        let kind = child.kind();
        if kind == "variable_declaration"
            || kind == "assignment_statement"
            || kind == "local_declaration"
        {
            // Scan for an `expression_list` whose only entry is a
            // `table_constructor`. Pair it with the identifier name
            // on the LHS.
            let mut name: Option<String> = None;
            let mut has_empty_table = false;
            let mut inner = child.walk();
            for sub in child.children(&mut inner) {
                match sub.kind() {
                    "variable_list" | "identifier" | "name" => {
                        if let Some(n) = lua_first_identifier(&sub, source) {
                            name = Some(n);
                        }
                    }
                    "expression_list" | "table_constructor" => {
                        if lua_is_table_constructor(&sub) {
                            has_empty_table = true;
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(n), true) = (name, has_empty_table) {
                names.insert(n);
            }
        }
        collect_lua_empty_table_locals(child, source, names);
    }
}

fn lua_first_identifier(node: &tree_sitter::Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" || node.kind() == "name" {
        if let Ok(t) = node.utf8_text(source.as_bytes()) {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(n) = lua_first_identifier(&child, source) {
            return Some(n);
        }
    }
    None
}

fn lua_is_table_constructor(node: &tree_sitter::Node) -> bool {
    if node.kind() == "table_constructor" {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "table_constructor" {
            return true;
        }
    }
    false
}

fn collect_lua_table_methods(
    node: tree_sitter::Node,
    source: &str,
    candidates: &std::collections::BTreeSet<String>,
    classes: &mut std::collections::BTreeMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        // tree-sitter-lua: `function_declaration` for `function X.m()
        // ... end` AND `function X:m() ... end`. The function name
        // is exposed via a child node which may be a
        // `dot_index_expression`, `method_index_expression`, or plain
        // `identifier`.
        if kind == "function_declaration" || kind == "function_definition_statement" {
            if let Some((class_name, method_name)) =
                lua_extract_dotted_function_name(&child, source)
            {
                if candidates.contains(&class_name) {
                    let entry = classes
                        .entry(class_name.clone())
                        .or_insert_with(|| ClassInfo {
                            name: class_name.clone(),
                            line: child.start_position().row + 1,
                            methods: Vec::new(),
                            is_partial: false,
                            namespace_path: Vec::new(),
                        });
                    if child.start_position().row + 1 < entry.line {
                        entry.line = child.start_position().row + 1;
                    }
                    entry.methods.push(MethodInfo {
                        name: method_name,
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
        collect_lua_table_methods(child, source, candidates, classes);
    }
}

fn lua_extract_dotted_function_name(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<(String, String)> {
    // Search direct children for a name node carrying the
    // dotted/colon form. Tree-sitter-lua exposes either
    // `dot_index_expression` (`X.m`), `method_index_expression`
    // (`X:m`), or a `variable` containing one of these.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "dot_index_expression" | "method_index_expression" => {
                return lua_split_dotted_name(&child, source);
            }
            "variable" | "name" | "function_name" | "field_expression" => {
                if let Some(pair) = lua_split_dotted_name(&child, source) {
                    return Some(pair);
                }
            }
            _ => {}
        }
    }
    None
}

fn lua_split_dotted_name(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<(String, String)> {
    // Two identifier children separated by `.` or `:`. Pull them in
    // order: the first is the class, the second is the method.
    let mut identifiers: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" | "name" => {
                if let Ok(t) = child.utf8_text(source.as_bytes()) {
                    if !t.is_empty() {
                        identifiers.push(t.to_string());
                    }
                }
            }
            "dot_index_expression" | "method_index_expression" => {
                if let Some(pair) = lua_split_dotted_name(&child, source) {
                    return Some(pair);
                }
            }
            _ => {}
        }
    }
    if identifiers.len() >= 2 {
        Some((identifiers[0].clone(), identifiers[1].clone()))
    } else {
        None
    }
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): build a PROJECT-WIDE
/// declared-field map keyed on `(namespace_path, class)` by walking every C++
/// file's in-body class declarations (including the macro-prefixed misparse and
/// its spilled members). This is consumed by `extract_file_method_fields_cpp`
/// so a `.cpp` out-of-line method body can resolve the bare data members that
/// were declared in a SEPARATE `.h` — the dominant C++ split that a per-file
/// walk cannot see. Non-C++ files are skipped (returns only C++ class keys).
/// Field sets for the same key are UNIONED across files so a class declared
/// across multiple headers still resolves the full member set.
fn cpp_project_declared_fields(
    file_paths: &[PathBuf],
) -> HashMap<(Vec<String>, String), HashSet<String>> {
    let mut global: HashMap<(Vec<String>, String), HashSet<String>> = HashMap::new();
    // Default options suffice: declared-field collection does not depend on the
    // dunder/threshold knobs (those only filter emitted methods, not fields).
    let options = CohesionOptions {
        include_dunder: false,
        low_cohesion_threshold: 0,
    };
    for file_path in file_paths {
        // Apply the same `.h → Cpp` promotion the per-file walk uses so headers
        // (which map to `Language::C` by extension) are still scanned for C++
        // class declarations.
        let language = match Language::from_path(file_path) {
            Some(l) => l,
            None => continue,
        };
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let language = cpp_promote_header_to_cpp(language, file_path, &source);
        if !matches!(language, Language::Cpp) {
            continue;
        }
        let tree = match parse(&source, language) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Reuse the in-body walk purely for its declared-field side effect; the
        // emitted extractions are discarded here.
        let mut throwaway: Vec<MethodFieldsExtraction> = Vec::new();
        let mut per_file: HashMap<(Vec<String>, String), HashSet<String>> =
            HashMap::new();
        collect_cpp_inbody_class_fields(
            &tree.root_node(),
            &source,
            file_path,
            &[],
            &options,
            &mut throwaway,
            &mut per_file,
        );
        for (key, fields) in per_file {
            global.entry(key).or_default().extend(fields);
        }
    }
    global
}

/// fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet A1+B1'): dedicated C++
/// `MethodFieldsExtraction` builder. Mirrors the Solidity dedicated flow:
/// it threads each class's `.h`-declared field-name set into a bare-identifier
/// scan so that the dominant C++ idiom of *bare* member access (`width`, not
/// `this->width`) is classified as a field access, and it threads the enclosing
/// namespace chain so the shared partial aggregator can use a namespace-
/// qualified key.
///
/// Two class shapes are handled in one pass:
///   - in-body classes (`class_specifier` / `struct_specifier`, including the
///     `TINYXML2_LIB`-style macro-prefixed misparse): own declared fields are
///     known, so inline method bodies get full bare-member resolution. These
///     are marked `is_partial` so the `.h` declaration and any out-of-line
///     `.cpp` definitions merge into one logical class via the aggregator.
///   - out-of-line definitions (`Ret ns::Class::method(){…}` in a `.cpp` with
///     no class body): grouped by `(namespace_path, class)` and emitted as a
///     partial extraction. Bare-member resolution uses `global_declared` — the
///     PROJECT-WIDE declared-field map keyed on `(namespace_path, class)`
///     harvested from every C++ file's in-body declarations — so a `.cpp`
///     out-of-line body resolves the bare members declared in its `.h`
///     (fix-T5-cohesion-wiring-repair3-v1). `this->member` is always resolved.
///     The residual under-count boundary is now only INHERITED (base-class)
///     fields, whose declarations belong to a different class key.
///
/// Boundary — parse-recovery namespace truncation: per the QA-corrected B1'
/// design, the `.h` declaration and `.cpp` out-of-line definitions merge IFF
/// their qualified `(namespace_path, name)` keys are EQUAL. When a header
/// contains a construct tree-sitter-cpp cannot parse (e.g. a private copy
/// constructor `Foo( const Foo& );` in tinyxml2's `StrPair`), error recovery
/// can prematurely close the enclosing `namespace_definition`, leaving the
/// classes that follow as siblings with an EMPTY namespace_path while their
/// `.cpp` counterparts (parsed cleanly) carry the real namespace. Those keys
/// then differ, so the two do not merge — they remain two entries. This is an
/// inherent AST limitation (the namespace structure is genuinely lost in the
/// recovered tree); we do NOT paper over it with a non-structural heuristic.
fn extract_file_method_fields_cpp(
    root: &tree_sitter::Node,
    source: &str,
    file_path: &Path,
    options: &CohesionOptions,
    global_declared: &HashMap<(Vec<String>, String), HashSet<String>>,
) -> Vec<MethodFieldsExtraction> {
    let mut out: Vec<MethodFieldsExtraction> = Vec::new();

    // fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): declared-field set
    // per `(namespace_path, class)` harvested from the in-body (`.h`) pass, so
    // the out-of-line (`.cpp`) merge below can resolve the SAME bare members
    // (`_rootAttribute`, …) instead of resolving against an empty set. Without
    // this the out-of-line definitions of a header-declared class look fully
    // disconnected (XMLElement: `lcom4 == method_count`).
    let mut declared_by_class: HashMap<(Vec<String>, String), HashSet<String>> =
        HashMap::new();

    // In-body classes (with declared-field-aware bare-member resolution).
    collect_cpp_inbody_class_fields(
        root, source, file_path, &[], options, &mut out, &mut declared_by_class,
    );

    // Out-of-line `ns::Class::method` definitions, keyed by (namespace, class).
    let mut out_of_line: HashMap<(Vec<String>, String), Vec<(String, usize, usize)>> =
        HashMap::new();
    collect_cpp_out_of_line_extractions(root, source, &[], &mut out_of_line);

    for ((namespace_path, class_name), defs) in out_of_line {
        // Skip out-of-line methods already represented inline in an in-body
        // class extraction from THIS file (same span) so a single-TU header
        // does not double-count.
        let inbody = out.iter_mut().find(|e| {
            e.name == class_name && e.namespace_path == namespace_path
        });
        // fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): resolve the
        // out-of-line method bodies against the class's declared-field set,
        // unioning the set harvested from THIS file (single-TU `.h`+`.cpp`)
        // with the PROJECT-WIDE set (the dominant case: members declared in a
        // separate header, defined out-of-line in this `.cpp`). The union lets
        // a `.cpp` method like `XMLElement::FindAttribute` resolve the bare
        // `_rootAttribute` declared in `tinyxml2.h`.
        //
        // Empty-namespace compatibility: tree-sitter-cpp error recovery can
        // PREMATURELY CLOSE the enclosing `namespace tinyxml2` in the HEADER
        // (the class declarations float up with an EMPTY namespace_path) while
        // the cleanly-parsed `.cpp` out-of-line definitions carry the real
        // `["tinyxml2"]`. So an exact `(namespace, name)` lookup would MISS the
        // header-declared fields. Mirror the B1' partial-merge tolerance by
        // also folding in the `([], name)` variant when this class has a
        // non-empty namespace — exactly the parse-recovery case — so the bare
        // members still resolve. (This only adds fields; the cohesion ENTRIES
        // stay separate via the namespace-qualified partial key.)
        let key = (namespace_path.clone(), class_name.clone());
        let mut declared = declared_by_class.get(&key).cloned().unwrap_or_default();
        if let Some(g) = global_declared.get(&key) {
            declared.extend(g.iter().cloned());
        }
        if !namespace_path.is_empty() {
            if let Some(g) = global_declared.get(&(Vec::new(), class_name.clone())) {
                declared.extend(g.iter().cloned());
            }
        }
        let methods: Vec<MethodFields> = defs
            .iter()
            .filter(|(name, _, _)| options.include_dunder || !is_dunder_method(name))
            .map(|(name, start, end)| {
                let fields = cpp_method_field_accesses(
                    &source[*start..*end],
                    &declared,
                );
                MethodFields {
                    name: name.clone(),
                    fields,
                }
            })
            .collect();

        match inbody {
            Some(entry) => {
                // Merge out-of-line methods into the in-body class entry,
                // skipping any whose name is already present inline.
                for m in methods {
                    if !entry.methods.iter().any(|e| e.name == m.name) {
                        entry.methods.push(m);
                    }
                }
            }
            None => {
                let line = defs
                    .iter()
                    .map(|(_, s, _)| *s)
                    .min()
                    .map(|b| source[..b].bytes().filter(|&c| c == b'\n').count() + 1)
                    .unwrap_or(1);
                out.push(MethodFieldsExtraction {
                    name: class_name,
                    file_path: file_path.to_path_buf(),
                    line,
                    is_partial: true,
                    methods,
                    namespace_path,
                });
            }
        }
    }

    out
}

/// Recursively walk for in-body C++ classes, tracking the enclosing namespace
/// chain. Emits one `MethodFieldsExtraction` per class with bare-member +
/// `this->` field resolution against the class's own declared fields.
///
/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): `declared_by_class`
/// records the resolved declared-field set per `(namespace_path, name)` so the
/// caller's out-of-line (`Class::method`) merge can resolve the SAME bare
/// members in the `.cpp` definitions (otherwise those `.cpp` methods resolve
/// against an empty set and the class looks fully disconnected — the XMLElement
/// `lcom4 == method_count` symptom). The walk is index-based (not a bare
/// cursor `for`) so the macro-prefixed misparse — whose members for a LARGE
/// class SPILL OUT as siblings of the misparsed `function_definition` rather
/// than nesting inside its truncated `compound_statement` body — can absorb
/// those spilled siblings into the same class before they are revisited.
fn collect_cpp_inbody_class_fields(
    node: &tree_sitter::Node,
    source: &str,
    file_path: &Path,
    namespace_path: &[String],
    options: &CohesionOptions,
    out: &mut Vec<MethodFieldsExtraction>,
    declared_by_class: &mut HashMap<(Vec<String>, String), HashSet<String>>,
) {
    let mut cursor = node.walk();
    let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
    let mut i = 0usize;
    while i < children.len() {
        let child = children[i];
        match child.kind() {
            "namespace_definition" => {
                let mut nested = namespace_path.to_vec();
                if let Some(name) = child.child_by_field_name("name") {
                    if let Some(seg) = node_text_of(&name, source) {
                        if !seg.is_empty() {
                            nested.push(seg);
                        }
                    }
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_cpp_inbody_class_fields(
                        &body, source, file_path, &nested, options, out,
                        declared_by_class,
                    );
                } else {
                    collect_cpp_inbody_class_fields(
                        &child, source, file_path, &nested, options, out,
                        declared_by_class,
                    );
                }
                i += 1;
                continue;
            }
            "class_specifier" | "struct_specifier" => {
                if let Some((name, body)) = cpp_class_name_and_body(&child, source) {
                    let declared = cpp_declared_field_names(&body, source);
                    let methods = cpp_inbody_methods_fields(
                        &body, source, &declared, options,
                    );
                    record_declared_fields(
                        declared_by_class, namespace_path, &name, &declared,
                    );
                    // Skip method-less classes (forward decls / pure-virtual
                    // interfaces) — they carry no LCOM4 signal, matching the
                    // prior `cpp_drop_methodless` behaviour.
                    if !methods.is_empty() {
                        out.push(MethodFieldsExtraction {
                            name,
                            file_path: file_path.to_path_buf(),
                            line: child.start_position().row + 1,
                            is_partial: true,
                            methods,
                            namespace_path: namespace_path.to_vec(),
                        });
                    }
                    // Recurse into the body for nested classes.
                    collect_cpp_inbody_class_fields(
                        &body, source, file_path, namespace_path, options, out,
                        declared_by_class,
                    );
                }
                i += 1;
                continue;
            }
            "function_definition" | "declaration" => {
                // Macro-prefixed misparse: `class TINYXML2_LIB XMLElement {…}`.
                if let Some((name, body)) =
                    cpp_macro_prefixed_class_name_and_body(&child, source)
                {
                    // fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL):
                    // for a LARGE macro-prefixed class tree-sitter error
                    // recovery truncates the captured `compound_statement` body
                    // and SPILLS the remaining members (`_rootAttribute`, the
                    // inline accessors, the out-of-line method declarations, …)
                    // out as siblings of THIS `function_definition`, terminated
                    // by a floated brace-only `ERROR }` node. Gather those
                    // spilled siblings so the declared-field scan and inline
                    // method scan see the WHOLE class, not just the truncated
                    // head. `spill_end` is exclusive; it equals `i + 1` when
                    // there is no spill (small class, e.g. StrPair).
                    let spill_end =
                        cpp_macro_spilled_region_end(&children, i);
                    // The captured `compound_statement` body is a CONTAINER —
                    // its members are CHILDREN, so it is scanned with the
                    // child-iterating collectors. Each spilled SIBLING is itself
                    // a member node, so it is scanned with the single-node
                    // visitors (calling the child-iterating form on it would
                    // only descend into a method body / declarator and miss the
                    // member, which is exactly why XMLElement's inline
                    // accessors and `_rootAttribute`/`_closingType` were lost).
                    let spilled = &children[i + 1..spill_end];

                    let mut declared = HashSet::new();
                    cpp_collect_declared_fields(&body, source, &mut declared);
                    for n in spilled {
                        cpp_visit_declared_node(n, source, &mut declared);
                    }
                    let mut methods = Vec::new();
                    let mut seen: HashSet<String> = HashSet::new();
                    cpp_collect_inbody_methods(
                        &body, source, &declared, options, &mut methods,
                        &mut seen,
                    );
                    for n in spilled {
                        cpp_visit_inbody_method_node(
                            n, source, &declared, options, &mut methods,
                            &mut seen,
                        );
                    }
                    record_declared_fields(
                        declared_by_class, namespace_path, &name, &declared,
                    );
                    if !methods.is_empty() {
                        out.push(MethodFieldsExtraction {
                            name,
                            file_path: file_path.to_path_buf(),
                            line: child.start_position().row + 1,
                            is_partial: true,
                            methods,
                            namespace_path: namespace_path.to_vec(),
                        });
                    }
                    // Recurse into the captured body and each spilled sibling
                    // for genuinely nested classes (the inline/declared scans
                    // above already pruned nested-class members).
                    collect_cpp_inbody_class_fields(
                        &body, source, file_path, namespace_path, options, out,
                        declared_by_class,
                    );
                    for n in spilled {
                        collect_cpp_inbody_class_fields(
                            n, source, file_path, namespace_path, options, out,
                            declared_by_class,
                        );
                    }
                    // Consume the whole spilled region so the absorbed sibling
                    // members are not revisited as standalone constructs.
                    i = spill_end;
                    continue;
                }
            }
            _ => {}
        }
        collect_cpp_inbody_class_fields(
            &child, source, file_path, namespace_path, options, out,
            declared_by_class,
        );
        i += 1;
    }
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): record a class's
/// resolved declared-field set, UNIONING with any prior set for the same
/// `(namespace_path, name)` (a class may be seen more than once across the file
/// walk — e.g. a forward-declared shell and the full definition). Empty sets
/// never erase a previously recorded non-empty set.
fn record_declared_fields(
    declared_by_class: &mut HashMap<(Vec<String>, String), HashSet<String>>,
    namespace_path: &[String],
    name: &str,
    declared: &HashSet<String>,
) {
    if declared.is_empty() {
        declared_by_class
            .entry((namespace_path.to_vec(), name.to_string()))
            .or_default();
        return;
    }
    declared_by_class
        .entry((namespace_path.to_vec(), name.to_string()))
        .or_default()
        .extend(declared.iter().cloned());
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): find the exclusive
/// end index of the SPILLED-member region that follows a macro-prefixed class
/// misparse at `children[start]`.
///
/// Background (verified by debug-parse on tinyxml2 `XMLElement` and synthetic
/// reductions): for a SMALL macro-prefixed class the misparsed
/// `function_definition` keeps the whole `compound_statement` body and the
/// trailing `};` produces a stray-semicolon `expression_statement` as its
/// immediate next sibling — there is NO spill. For a LARGE class tree-sitter
/// truncates the captured body and the remaining members appear as siblings;
/// the immediate next sibling is then member-shaped (a `declaration` /
/// `function_definition` / `comment`), NOT a stray semicolon.
///
/// Detection therefore keys on the IMMEDIATE sibling:
///   - stray-semicolon `expression_statement`, a scope-closing `}` token, a new
///     `namespace_definition` / `class_specifier` / `struct_specifier`, or
///     end-of-children  ->  NO spill, return `start + 1`.
///   - anything else  ->  the class spilled; greedily absorb siblings until the
///     spill terminates.
///
/// Spill termination (once spilling is confirmed):
///   - a brace-only `ERROR` (the class's floated closing `}`, seen at
///     translation-unit scope) — CONSUMED (return its index + 1);
///   - a `}` token (the enclosing scope's own brace, seen when the class
///     spilled inside a `namespace` body) — NOT consumed (return its index);
///   - a new `namespace_definition` / `class_specifier` / `struct_specifier` —
///     NOT consumed.
/// Every other sibling (`declaration`, `function_definition`, `comment`,
/// `labeled_statement`, mid-body `expression_statement`, `enum_specifier`,
/// non-brace recovery `ERROR`, stray `;` token, …) is part of the spilled class
/// body and is absorbed; the recursive field/method collectors prune nested
/// classes and method bodies, so absorbing them is safe.
fn cpp_macro_spilled_region_end(
    children: &[tree_sitter::Node],
    start: usize,
) -> usize {
    let first = match children.get(start + 1) {
        Some(n) => *n,
        None => return start + 1,
    };
    // Immediate-sibling disambiguation: a complete (non-spilling) macro class is
    // followed by the stray `;` of its `};`, or by a scope boundary.
    if cpp_is_stray_semicolon(&first) {
        return start + 1;
    }
    match first.kind() {
        "}" | "namespace_definition" | "class_specifier" | "struct_specifier" => {
            return start + 1;
        }
        _ => {}
    }

    // Confirmed spill: absorb the spilled body up to its terminator.
    let mut j = start + 1;
    while j < children.len() {
        let n = children[j];
        if cpp_is_brace_only_error(&n) {
            return j + 1;
        }
        match n.kind() {
            "}" | "namespace_definition" | "class_specifier"
            | "struct_specifier" => return j,
            _ => j += 1,
        }
    }
    j
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): `true` for an
/// `expression_statement` that is just a lone `;` — the residue of a complete
/// class's `};`. Used to recognize that a macro-prefixed class did NOT spill.
fn cpp_is_stray_semicolon(node: &tree_sitter::Node) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    let mut cursor = node.walk();
    let mut saw_semi = false;
    for c in node.children(&mut cursor) {
        if c.kind() == ";" {
            saw_semi = true;
        } else {
            return false;
        }
    }
    saw_semi
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): `true` for the
/// floated class-closing brace produced by macro-misparse recovery — an
/// `ERROR` node with zero NAMED children whose only child is the `}` token.
/// Verified by debug-parse: the in-class recovery `ERROR` (e.g.
/// `virtual ~XMLElement(); …`) carries named children, and the post-class
/// `enum` recovery `ERROR` carries an `enum`/`type_identifier`; only the
/// class-closing brace is a pure `}` token, so this never mistakes a recovery
/// node that still holds members for the terminator.
fn cpp_is_brace_only_error(node: &tree_sitter::Node) -> bool {
    if node.kind() != "ERROR" || node.named_child_count() != 0 {
        return false;
    }
    let mut cursor = node.walk();
    let mut saw_close_brace = false;
    for c in node.children(&mut cursor) {
        if c.kind() == "}" {
            saw_close_brace = true;
        } else {
            return false;
        }
    }
    saw_close_brace
}

/// Return `(class_name, body_node)` for a `class_specifier`/`struct_specifier`
/// that has a body. `None` for forward declarations (`class Foo;`).
fn cpp_class_name_and_body<'a>(
    node: &tree_sitter::Node<'a>,
    source: &str,
) -> Option<(String, tree_sitter::Node<'a>)> {
    let info = extract_cpp_class_info(node, source)?;
    let body = node.child_by_field_name("body")?;
    Some((info.name, body))
}

/// Return `(class_name, body_node)` for the macro-prefixed misparse
/// (`class MACRO Name {…}` parsed as a `declaration`/`function_definition`).
fn cpp_macro_prefixed_class_name_and_body<'a>(
    node: &tree_sitter::Node<'a>,
    source: &str,
) -> Option<(String, tree_sitter::Node<'a>)> {
    let type_node = node.child_by_field_name("type")?;
    if type_node.kind() != "class_specifier" && type_node.kind() != "struct_specifier" {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "identifier" {
        return None;
    }
    let name = node_text_of(&declarator, source)?;
    if name.is_empty() {
        return None;
    }
    // The misparsed body lives in a sibling `field_declaration_list` /
    // `compound_statement` direct child.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "field_declaration_list" || child.kind() == "compound_statement" {
            return Some((name, child));
        }
    }
    None
}

/// Collect the bare field names declared at the body scope of a C++ class:
/// `field_declaration -> field_identifier` (and pointer/array/reference
/// declarators that wrap a `field_identifier`). Member functions are NOT
/// fields; only data members are collected.
///
/// fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): the body is walked *recursively*
/// rather than via a flat direct-child scan. A well-formed
/// `field_declaration_list` body lists members as direct children, but the
/// macro-prefixed misparse (`class TINYXML2_LIB XMLElement : public XMLNode`)
/// yields a `compound_statement` body in which error recovery nests ALL
/// members under a single `labeled_statement` (the first `public:` access
/// specifier). A flat scan therefore saw zero data members, so bare-member
/// resolution silently degraded to `field_count = 0` for every macro-prefixed
/// class (XMLElement, XMLPrinter, …). Recursing through `labeled_statement`
/// (and any other recovery wrapper) restores the declared-field set, while we
/// still STOP at nested `class_specifier`/`struct_specifier` bodies (their
/// members belong to the nested class) and at `function_definition` bodies (a
/// method body's locals are not data members).
fn cpp_declared_field_names(body: &tree_sitter::Node, source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    cpp_collect_declared_fields(body, source, &mut out);
    out
}

/// Recursive worker for `cpp_declared_field_names`. See that function for the
/// rationale behind recursing past `labeled_statement` wrappers while pruning
/// nested class and method-body subtrees. Iterates `node`'s CHILDREN and
/// classifies each via [`cpp_visit_declared_node`].
fn cpp_collect_declared_fields(
    node: &tree_sitter::Node,
    source: &str,
    out: &mut HashSet<String>,
) {
    let mut cursor = node.walk();
    for member in node.children(&mut cursor) {
        cpp_visit_declared_node(&member, source, out);
    }
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): classify a SINGLE
/// node as (or recurse to find) a declared data member. Factored out of the
/// child loop so the macro-spill path can apply the SAME classification to a
/// spilled SIBLING node directly (a spilled `_rootAttribute;` arrives as a
/// `declaration` node that is itself the member, not a child of the node it is
/// passed as).
fn cpp_visit_declared_node(
    member: &tree_sitter::Node,
    source: &str,
    out: &mut HashSet<String>,
) {
    match member.kind() {
        // Nested class/struct: its data members belong to the nested class,
        // not this one. Do not descend.
        "class_specifier" | "struct_specifier" => {}
        // A method's body lives here; its locals/params are not data members
        // of the class. Do not descend.
        "function_definition" => {}
        // Data members appear as `field_declaration` in a well-formed
        // `field_declaration_list` body, but as plain `declaration` nodes when
        // the class is the macro-prefixed misparse whose body is a
        // `compound_statement` (e.g. `class TINYXML2_LIB StrPair { … }`, where
        // `int _flags;` parses as a `declaration` with an `identifier`
        // declarator rather than a `field_declaration` with a
        // `field_identifier`). Handle both shapes.
        "field_declaration" | "declaration" => {
            // Skip member functions: a `field_declaration`/`declaration` whose
            // declarator is (or wraps) a `function_declarator` is a method
            // declaration, not a data member.
            //
            // Only the `declarator` field is consulted (never a positional
            // scan): a `declaration` with no `declarator` field is a type-only
            // construct such as `enum Mode { … };` or a nested type, whose
            // inner identifiers (enum constants, etc.) must NOT be mistaken for
            // data members.
            if let Some(decl) = member.child_by_field_name("declarator") {
                if cpp_declarator_is_function(&decl) {
                    return;
                }
                collect_cpp_field_identifier(&decl, source, out);
            }
        }
        // Everything else (access-specifier `labeled_statement` wrappers,
        // `comment`, ERROR recovery nodes, …): recurse to reach the members
        // nested beneath it.
        _ => cpp_collect_declared_fields(member, source, out),
    }
}

/// Return `true` if a (possibly wrapped) declarator is/contains a
/// `function_declarator`, i.e. the declaration is a member function rather
/// than a data member.
fn cpp_declarator_is_function(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "function_declarator" => true,
        "pointer_declarator" | "reference_declarator" | "array_declarator"
        | "parenthesized_declarator" | "init_declarator" => node
            .child_by_field_name("declarator")
            .map(|inner| cpp_declarator_is_function(&inner))
            .unwrap_or(false),
        _ => false,
    }
}

/// Walk a member declarator to record the declared data-member name. Handles
/// both `field_identifier` (normal `field_declaration`) and `identifier`
/// (macro-prefixed `declaration`), descending through pointer/array/reference/
/// init declarator wrappers.
fn collect_cpp_field_identifier(
    node: &tree_sitter::Node,
    source: &str,
    out: &mut HashSet<String>,
) {
    match node.kind() {
        "field_identifier" | "identifier" => {
            if let Some(t) = node_text_of(node, source) {
                if !t.is_empty() {
                    out.insert(t);
                }
            }
        }
        "pointer_declarator" | "array_declarator" | "reference_declarator"
        | "init_declarator" | "parenthesized_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                collect_cpp_field_identifier(&inner, source, out);
            }
        }
        _ => {}
    }
}

/// Build per-method `MethodFields` for an in-body C++ class, resolving bare
/// member accesses against `declared` (plus `this->member`), with shadowing.
///
/// fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): walks the body *recursively* so
/// that the macro-prefixed misparse — whose `compound_statement` body nests
/// every member under a single `labeled_statement` access-specifier wrapper —
/// still surfaces its methods (a flat direct-child scan saw zero, which is why
/// `cohesion` previously dropped the `.h` `XMLElement`/`XMLPrinter` entries and
/// double-counted against the `.cpp` out-of-line definitions). Two member
/// shapes are recognized:
///   - `function_definition` — an inline method (has a body); bare-member field
///     resolution runs against `declared`.
///   - `field_declaration`/`declaration` whose declarator is a function
///     declarator — a declared-only method (signature in the `.h`, defined
///     out-of-line). It carries no inline field signal but is still a method,
///     so emitting it lets the in-body `(namespace, class)` entry MERGE with
///     the matching out-of-line `.cpp` definitions instead of forming a second
///     entry (the double-count root cause).
/// Nested `class_specifier`/`struct_specifier` bodies and method bodies are
/// pruned so a nested class's methods are not attributed to the parent.
fn cpp_inbody_methods_fields(
    body: &tree_sitter::Node,
    source: &str,
    declared: &HashSet<String>,
    options: &CohesionOptions,
) -> Vec<MethodFields> {
    let mut methods = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    cpp_collect_inbody_methods(body, source, declared, options, &mut methods, &mut seen);
    methods
}

/// Recursive worker for `cpp_inbody_methods_fields`. `seen` de-duplicates
/// methods by name so a declared-only signature does not produce a phantom
/// second entry when the inline definition is also present in the same body.
fn cpp_collect_inbody_methods(
    node: &tree_sitter::Node,
    source: &str,
    declared: &HashSet<String>,
    options: &CohesionOptions,
    methods: &mut Vec<MethodFields>,
    seen: &mut HashSet<String>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cpp_visit_inbody_method_node(&child, source, declared, options, methods, seen);
    }
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): classify a SINGLE
/// node as an inline / declared-only method (or recurse to find members).
/// Factored out of the child loop so the macro-spill path can apply the SAME
/// classification to a spilled SIBLING node directly — a spilled inline method
/// arrives as a `function_definition` node that is itself the method, not a
/// child of the node it is passed as, so calling the child-loop form on it
/// would only inspect the method body (yielding nothing, the XMLElement
/// `FirstAttribute`/`ClosingType`-missing symptom).
fn cpp_visit_inbody_method_node(
    child: &tree_sitter::Node,
    source: &str,
    declared: &HashSet<String>,
    options: &CohesionOptions,
    methods: &mut Vec<MethodFields>,
    seen: &mut HashSet<String>,
) {
    match child.kind() {
        // Nested class/struct methods belong to the nested class.
        "class_specifier" | "struct_specifier" => {}
        // Inline method: extract name, resolve bare-member field accesses
        // against the class's declared-field set. Do NOT recurse into it (its
        // body is the method body, not more class members).
        "function_definition" => {
            let declarator = match child.child_by_field_name("declarator") {
                Some(d) => d,
                None => return,
            };
            let name = match extract_cpp_method_name(&declarator, source) {
                Some(n) => n,
                None => return,
            };
            if !options.include_dunder && is_dunder_method(&name) {
                return;
            }
            let method_text = &source[child.start_byte()..child.end_byte()];
            let fields = cpp_method_field_accesses(method_text, declared);
            if seen.insert(name.clone()) {
                methods.push(MethodFields { name, fields });
            } else if let Some(existing) = methods.iter_mut().find(|m| m.name == name) {
                // An inline definition supersedes a prior declared-only
                // signature: union its (richer) field set in.
                existing.fields.extend(fields);
            }
        }
        // `field_declaration` / `declaration` whose declarator is a function
        // declarator. Two sub-cases:
        //   - declared-only signature (`void Resize(int,int);`): emit with an
        //     EMPTY field set so the in-body class merges with its out-of-line
        //     definitions.
        //   - fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL):
        //     MISPARSED INLINE method. In the macro-prefixed misparse an inline
        //     method `int Area() const { return _w * _h; }` is NOT a
        //     `function_definition`; it parses as a `declaration` whose
        //     declarator is an `init_declarator` (function_declarator + an
        //     `initializer_list` "value" holding the body). Detect the body via
        //     `cpp_declaration_has_inline_body` and resolve its bare-member
        //     field accesses from the declaration text (otherwise the inline
        //     `Area`/`FirstAttribute`/`ClosingType` accessors are mis-emitted as
        //     field-less, leaving them disconnected from `_w`/`_h`).
        "field_declaration" | "declaration" => {
            if let Some(decl) = child.child_by_field_name("declarator") {
                if cpp_declarator_is_function(&decl) {
                    if let Some(name) = extract_cpp_method_name(&decl, source) {
                        if !options.include_dunder && is_dunder_method(&name) {
                            return;
                        }
                        let fields = if cpp_declaration_has_inline_body(child) {
                            let method_text =
                                &source[child.start_byte()..child.end_byte()];
                            cpp_method_field_accesses(method_text, declared)
                        } else {
                            HashSet::new()
                        };
                        if seen.insert(name.clone()) {
                            methods.push(MethodFields { name, fields });
                        } else if !fields.is_empty() {
                            if let Some(existing) =
                                methods.iter_mut().find(|m| m.name == name)
                            {
                                // A misparsed-inline body supersedes a prior
                                // declared-only signature: union the richer set.
                                existing.fields.extend(fields);
                            }
                        }
                    }
                }
            }
        }
        // Access-specifier `labeled_statement` wrappers, `comment`, ERROR
        // recovery nodes, …: recurse to reach the nested members.
        _ => cpp_collect_inbody_methods(child, source, declared, options, methods, seen),
    }
}

/// fix-T5-cohesion-wiring-repair3-v1 (v0.5.0 DESIGN-TAIL): `true` when a
/// `declaration` / `field_declaration` node actually carries an INLINE method
/// body that tree-sitter recovery folded into an `init_declarator` value (the
/// macro-prefixed misparse turns `T m() { … }` into a `declaration` whose
/// `init_declarator` has a `function_declarator` declarator and an
/// `initializer_list`/`compound_statement` value). Distinguishes a real inline
/// body from a pure signature (`void m();` — no value) and from a defaulted /
/// deleted / pure-virtual declarator (`= 0` / `= default`, whose value is a
/// `number_literal` / `default_method_clause` and yields no field hits anyway).
/// Checked structurally on node kinds only.
fn cpp_declaration_has_inline_body(node: &tree_sitter::Node) -> bool {
    let decl = match node.child_by_field_name("declarator") {
        Some(d) => d,
        None => return false,
    };
    if decl.kind() != "init_declarator" {
        return false;
    }
    // The inner declarator must be (or wrap) a function declarator …
    let inner = match decl.child_by_field_name("declarator") {
        Some(d) => d,
        None => return false,
    };
    if !cpp_declarator_is_function(&inner) {
        return false;
    }
    // … and there must be a brace-delimited body in the value slot.
    match decl.child_by_field_name("value") {
        Some(v) => matches!(
            v.kind(),
            "initializer_list" | "compound_statement" | "field_initializer_list"
        ),
        None => false,
    }
}

/// Resolve the set of field accesses inside a single C++ method body.
///
/// Counts two forms as a field access:
///   1. `this->member` — a `field_expression` whose `argument` is `this`
///      (always a genuine field read; threaded through the SAME set so callers
///      need only one path).
///   2. a *bare* `identifier` whose text is in `declared` AND is not shadowed
///      by a parameter or a local declaration in scope.
///
/// The shadowing scan covers block scopes and `for` / range-`for` init
/// declarators (C++ has richer scoping than Solidity), so a loop variable or
/// local that happens to share a field's name is not mis-counted.
///
/// AST-driven: parses the method text and inspects node kinds/fields only.
fn cpp_method_field_accesses(
    method_source: &str,
    declared: &HashSet<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let tree = match parse(method_source, Language::Cpp) {
        Ok(t) => t,
        Err(_) => return out,
    };
    let root = tree.root_node();

    // Names shadowed by parameters or local declarations anywhere in the
    // method (conservative: a name declared as a local in any scope is treated
    // as shadowed for the whole method, so a local never masquerades as a
    // field). This errs toward UNDER-counting, never inventing field accesses.
    let mut shadowed: HashSet<String> = HashSet::new();
    cpp_collect_shadowed_names(&root, method_source, &mut shadowed);

    cpp_collect_field_hits(&root, method_source, declared, &shadowed, &mut out);
    out
}

/// Collect names that are shadowed within a C++ method body: parameter names
/// (`parameter_declaration -> declarator -> identifier`) and local variable
/// names (`init_declarator`/`declaration -> declarator -> identifier`),
/// including `for`-loop and range-`for` initializers.
fn cpp_collect_shadowed_names(
    node: &tree_sitter::Node,
    source: &str,
    out: &mut HashSet<String>,
) {
    match node.kind() {
        "parameter_declaration" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                cpp_record_declared_identifier(&decl, source, out);
            }
        }
        "init_declarator" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                cpp_record_declared_identifier(&decl, source, out);
            }
        }
        // `declaration` may hold a bare `identifier` declarator (no init):
        // `int x;`. The `init_declarator` arm covers `int x = …;`.
        "declaration" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                cpp_record_declared_identifier(&decl, source, out);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cpp_collect_shadowed_names(&child, source, out);
    }
}

/// Record the bare identifier name of a (possibly wrapped) declarator into
/// `out`. Descends through pointer/reference/array/init declarator wrappers.
fn cpp_record_declared_identifier(
    node: &tree_sitter::Node,
    source: &str,
    out: &mut HashSet<String>,
) {
    match node.kind() {
        "identifier" => {
            if let Some(t) = node_text_of(node, source) {
                if !t.is_empty() {
                    out.insert(t);
                }
            }
        }
        "pointer_declarator" | "reference_declarator" | "array_declarator"
        | "init_declarator" | "parenthesized_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                cpp_record_declared_identifier(&inner, source, out);
            }
        }
        _ => {}
    }
}

/// Walk a C++ method body collecting field accesses (`this->member` and bare
/// declared-field identifiers not shadowed by a local/param). Skips the
/// `field`/member side of any non-`this` member access (`obj.x`, `obj->x`) so
/// foreign-object members are never counted, and skips call targets.
fn cpp_collect_field_hits(
    node: &tree_sitter::Node,
    source: &str,
    declared: &HashSet<String>,
    shadowed: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    match node.kind() {
        "field_expression" => {
            // `this->member` / `this.member` -> genuine field read.
            if let Some(arg) = node.child_by_field_name("argument") {
                if arg.kind() == "this" {
                    if let Some(field) = node.child_by_field_name("field") {
                        if let Some(t) = node_text_of(&field, source) {
                            if !t.is_empty() {
                                out.insert(t);
                            }
                        }
                    }
                }
            }
            // Recurse only into the `argument` side; the `field` side is a
            // member name that must not be treated as a bare identifier.
            if let Some(arg) = node.child_by_field_name("argument") {
                cpp_collect_field_hits(&arg, source, declared, shadowed, out);
            }
            return;
        }
        "identifier" => {
            if let Some(t) = node_text_of(node, source) {
                if declared.contains(&t) && !shadowed.contains(&t) {
                    out.insert(t);
                }
            }
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cpp_collect_field_hits(&child, source, declared, shadowed, out);
    }
}

/// Collect out-of-line C++ method definitions keyed by
/// `(namespace_path, class_name)`, tracking the enclosing namespace chain.
fn collect_cpp_out_of_line_extractions(
    node: &tree_sitter::Node,
    source: &str,
    namespace_path: &[String],
    out: &mut HashMap<(Vec<String>, String), Vec<(String, usize, usize)>>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "namespace_definition" {
            let mut nested = namespace_path.to_vec();
            if let Some(name) = child.child_by_field_name("name") {
                if let Some(seg) = node_text_of(&name, source) {
                    if !seg.is_empty() {
                        nested.push(seg);
                    }
                }
            }
            if let Some(body) = child.child_by_field_name("body") {
                collect_cpp_out_of_line_extractions(&body, source, &nested, out);
            } else {
                collect_cpp_out_of_line_extractions(&child, source, &nested, out);
            }
            continue;
        }
        if child.kind() == "function_definition" {
            if let Some((scope_ns, class_name, method_name)) =
                cpp_out_of_line_qualified_name_ns(&child, source)
            {
                // The qualified scope segments (e.g. `a::Widget::m` ->
                // scope `a::Widget`) combine the enclosing namespace with any
                // explicit namespace prefix in the qualifier. The trailing
                // scope segment is the class; the rest are namespace.
                let mut full_ns = namespace_path.to_vec();
                full_ns.extend(scope_ns);
                out.entry((full_ns, class_name)).or_default().push((
                    method_name,
                    child.start_byte(),
                    child.end_byte(),
                ));
                continue;
            }
        }
        // Do not descend into class bodies — their inline methods are handled
        // by the in-body pass.
        if child.kind() != "class_specifier" && child.kind() != "struct_specifier" {
            collect_cpp_out_of_line_extractions(&child, source, namespace_path, out);
        }
    }
}

/// Like `cpp_out_of_line_qualified_name`, but additionally returns the
/// namespace segments that appear BEFORE the class segment in the qualifier
/// (e.g. `a::Widget::area` -> namespace `["a"]`, class `"Widget"`,
/// method `"area"`).
fn cpp_out_of_line_qualified_name_ns(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<(Vec<String>, String, String)> {
    let declarator = cpp_unwrap_to_function_declarator(node.child_by_field_name("declarator")?)?;
    let inner = declarator.child_by_field_name("declarator")?;
    if inner.kind() != "qualified_identifier" {
        return None;
    }
    // Flatten the full `a::Widget::area` path into ordered segments.
    let mut segs: Vec<String> = Vec::new();
    cpp_flatten_qualified_segments(inner, source, &mut segs);
    if segs.len() < 2 {
        return None;
    }
    let method_name = segs.pop()?;
    let class_name = segs.pop()?;
    if class_name.is_empty() || method_name.is_empty() {
        return None;
    }
    Some((segs, class_name, method_name))
}

/// Flatten a (possibly nested) `qualified_identifier` into ordered leaf
/// segments: `a::Widget::area` -> ["a","Widget","area"].
fn cpp_flatten_qualified_segments(
    node: tree_sitter::Node,
    source: &str,
    out: &mut Vec<String>,
) {
    match node.kind() {
        "qualified_identifier" => {
            if let Some(scope) = node.child_by_field_name("scope") {
                cpp_flatten_qualified_segments(scope, source, out);
            }
            if let Some(name) = node.child_by_field_name("name") {
                cpp_flatten_qualified_segments(name, source, out);
            }
        }
        _ => {
            if let Some(t) = node_text_of(&node, source) {
                if !t.is_empty() {
                    out.push(t);
                }
            }
        }
    }
}

/// Extract C++ classes for cohesion analysis (BUG-P19-08).
/// Mirrors the (class_specifier | struct_specifier) handling in
/// `ast::extractor::extract_cpp_classes` including the macro-prefixed
/// misparse recovery (e.g. `class TINYXML2_LIB XMLDocument`).
fn extract_cpp_classes_cohesion(
    root: tree_sitter::Node,
    source: &str,
) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_cpp_classes_cohesion_recursive(root, source, &mut classes);

    // IT3-cpp-03 (v0.5.0 CL-6): the recursive pass above only sees methods
    // *defined inline* inside a `class_specifier` body. The dominant C++ idiom
    // declares the class (with only method signatures) in a `.h` and defines
    // the methods out-of-line in a `.cpp`:
    //
    //     int  Widget::area()              { return this->w * this->h; }
    //     void Widget::resize(int w,int h) { this->w = w; this->h = h; }
    //
    // On the `.cpp` there is no `class_specifier` at all, so cohesion reported
    // `classes:0`. Collect these out-of-line `function_definition` nodes whose
    // declarator name is a `qualified_identifier` (`Widget::area`), group them
    // by the class qualifier, and either merge into a matching in-body class
    // (header+source in one TU) or synthesize a fresh class for the qualifier.
    let mut out_of_line: HashMap<String, Vec<MethodInfo>> = HashMap::new();
    collect_cpp_out_of_line_methods(&root, source, &mut out_of_line);

    for (class_name, methods) in out_of_line {
        if let Some(existing) = classes.iter_mut().find(|c| c.name == class_name) {
            // Merge, skipping methods already captured inline (same span).
            for m in methods {
                if !existing
                    .methods
                    .iter()
                    .any(|e| e.start_byte == m.start_byte && e.end_byte == m.end_byte)
                {
                    existing.methods.push(m);
                }
            }
        } else {
            let line = methods
                .iter()
                .map(|m| m.start_byte)
                .min()
                .map(|b| source[..b].bytes().filter(|&c| c == b'\n').count() + 1)
                .unwrap_or(1);
            classes.push(ClassInfo {
                name: class_name,
                line,
                methods,
                is_partial: true,
                namespace_path: Vec::new(),
            });
        }
    }

    classes
}

/// Collect out-of-line C++ method definitions (`Ret Class::method(){...}`),
/// keyed by the class qualifier.
///
/// AST (tree-sitter-cpp): a top-level `function_definition` whose `declarator`
/// is a `function_declarator` whose own `declarator` field is a
/// `qualified_identifier`. The `qualified_identifier` exposes a `scope`
/// (the class / namespace path, e.g. `Widget` or `Outer::Inner`) and a `name`
/// (the bare method identifier). We use the *immediate* scope segment as the
/// owning class name.
fn collect_cpp_out_of_line_methods(
    node: &tree_sitter::Node,
    source: &str,
    out: &mut HashMap<String, Vec<MethodInfo>>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_definition" {
            if let Some((class_name, method_name)) =
                cpp_out_of_line_qualified_name(&child, source)
            {
                out.entry(class_name).or_default().push(MethodInfo {
                    name: method_name,
                    start_byte: child.start_byte(),
                    end_byte: child.end_byte(),
                });
                // Don't recurse into the function body.
                continue;
            }
        }
        // Recurse (covers `namespace_definition` -> `declaration_list`, etc.),
        // but do not descend into `class_specifier` bodies — those inline
        // methods are already handled by the recursive in-body pass.
        if child.kind() != "class_specifier" && child.kind() != "struct_specifier" {
            collect_cpp_out_of_line_methods(&child, source, out);
        }
    }
}

/// If `node` is an out-of-line method definition (`Ret Class::method(...)`),
/// return `(class_qualifier, method_name)`.
fn cpp_out_of_line_qualified_name(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<(String, String)> {
    // Walk through declarator wrappers (pointer/reference) to the
    // `function_declarator`.
    let declarator = cpp_unwrap_to_function_declarator(node.child_by_field_name("declarator")?)?;
    let inner = declarator.child_by_field_name("declarator")?;
    if inner.kind() != "qualified_identifier" {
        return None;
    }
    let scope = inner.child_by_field_name("scope")?;
    let name_node = inner.child_by_field_name("name")?;
    // For nested qualifiers (`Outer::Inner::m`) the `scope` is itself a
    // `qualified_identifier`; take its trailing `name` segment as the
    // immediate owning class.
    let class_name = cpp_qualified_tail(&scope, source)?;
    let method_name = node_text_of(&name_node, source)?;
    if class_name.is_empty() || method_name.is_empty() {
        return None;
    }
    Some((class_name, method_name))
}

fn cpp_unwrap_to_function_declarator<'a>(
    node: tree_sitter::Node<'a>,
) -> Option<tree_sitter::Node<'a>> {
    match node.kind() {
        "function_declarator" => Some(node),
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => {
            cpp_unwrap_to_function_declarator(node.child_by_field_name("declarator")?)
        }
        _ => None,
    }
}

/// Return the trailing identifier segment of a (possibly nested) C++ scope.
fn cpp_qualified_tail(node: &tree_sitter::Node, source: &str) -> Option<String> {
    match node.kind() {
        "qualified_identifier" => {
            let name = node.child_by_field_name("name")?;
            cpp_qualified_tail(&name, source)
        }
        _ => node_text_of(node, source),
    }
}

fn node_text_of(node: &tree_sitter::Node, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes())
        .ok()
        .map(|s| s.to_string())
}

fn extract_cpp_classes_cohesion_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_specifier" | "struct_specifier" => {
                if let Some(info) = extract_cpp_class_info(&child, source) {
                    classes.push(info);
                }
                if let Some(body) = child.child_by_field_name("body") {
                    extract_cpp_classes_cohesion_recursive(body, source, classes);
                }
                continue;
            }
            "function_definition" | "declaration" => {
                if let Some(info) = extract_cpp_macro_prefixed_class(&child, source) {
                    classes.push(info);
                    continue;
                }
            }
            _ => {}
        }
        extract_cpp_classes_cohesion_recursive(child, source, classes);
    }
}

fn extract_cpp_class_info(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<ClassInfo> {
    let mut name: Option<String> = None;
    if let Some(name_node) = node.child_by_field_name("name") {
        let n = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
        if !n.is_empty() {
            name = Some(n);
        }
    }
    if name.is_none() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "type_identifier" {
                let n = child.utf8_text(source.as_bytes()).ok()?.to_string();
                if !n.is_empty() {
                    name = Some(n);
                    break;
                }
            }
        }
    }
    let name = name?;
    let line = node.start_position().row + 1;
    // cpp-class-count-agreement-v1 (BUG-CPP-P20-01): a `class_specifier`
    // node without a `body` is a forward declaration (`class Foo;`).
    // Forward decls have no methods, no fields, no LCOM4 signal, and
    // were inflating cohesion's `classes_analyzed` (e.g. tinyxml2.h
    // reported 26 = 14 real bodies + 12 forward-decls). The CLI
    // `cohesion` surface already discards them via the `min_methods=1`
    // default; filtering them here re-aligns the `health` and
    // `cohesion` surfaces at the source.
    let body = node.child_by_field_name("body")?;
    let methods = extract_cpp_methods(&body, source);
    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn extract_cpp_macro_prefixed_class(
    node: &tree_sitter::Node,
    source: &str,
) -> Option<ClassInfo> {
    let type_node = node.child_by_field_name("type")?;
    if type_node.kind() != "class_specifier" && type_node.kind() != "struct_specifier" {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "identifier" {
        return None;
    }
    let name = declarator.utf8_text(source.as_bytes()).ok()?.to_string();
    if name.is_empty() {
        return None;
    }
    let line = node.start_position().row + 1;
    // The body of a misparsed macro-class lives in a sibling
    // `compound_statement` rather than a tree-sitter `body` field; pick
    // the first such direct child if present.
    let mut body_methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "compound_statement" || child.kind() == "field_declaration_list" {
            body_methods = extract_cpp_methods(&child, source);
            break;
        }
    }
    Some(ClassInfo {
        name,
        line,
        methods: body_methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn extract_cpp_methods(
    body: &tree_sitter::Node,
    source: &str,
) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        // Inline method definitions appear as `function_definition`
        // inside `field_declaration_list`.
        if child.kind() == "function_definition" {
            if let Some(declarator) = child.child_by_field_name("declarator") {
                if let Some(name) = extract_cpp_method_name(&declarator, source) {
                    methods.push(MethodInfo {
                        name,
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }
    methods
}

fn extract_cpp_method_name(node: &tree_sitter::Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "destructor_name" => {
            Some(node.utf8_text(source.as_bytes()).ok()?.to_string())
        }
        "function_declarator" | "pointer_declarator" | "reference_declarator"
        | "parenthesized_declarator" | "init_declarator" | "array_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            extract_cpp_method_name(&inner, source)
        }
        _ => None,
    }
}

// =============================================================================
// Python Class Extraction
// =============================================================================

/// Extract Python classes with their methods
fn extract_python_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_python_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_python_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_definition" => {
                if let Some(class_info) = extract_python_class_info(&child, source) {
                    classes.push(class_info);
                }
                // Recurse into class body for nested classes (T16 mitigation)
                if let Some(body) = child.child_by_field_name("body") {
                    extract_python_classes_recursive(body, source, classes);
                }
            }
            "decorated_definition" => {
                // Handle decorated classes
                if let Some(def) = child.child_by_field_name("definition") {
                    if def.kind() == "class_definition" {
                        if let Some(class_info) = extract_python_class_info(&def, source) {
                            classes.push(class_info);
                        }
                        // Recurse into class body for nested classes
                        if let Some(body) = def.child_by_field_name("body") {
                            extract_python_classes_recursive(body, source, classes);
                        }
                    }
                }
            }
            _ => {
                // Recurse into other nodes (module level)
                extract_python_classes_recursive(child, source, classes);
            }
        }
    }
}

fn extract_python_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_python_methods(&body, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn extract_python_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(method) = extract_python_method(&child, source) {
                    methods.push(method);
                }
            }
            "decorated_definition" => {
                if let Some(def) = child.child_by_field_name("definition") {
                    if def.kind() == "function_definition" {
                        if let Some(method) = extract_python_method(&def, source) {
                            methods.push(method);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    methods
}

fn extract_python_method(node: &tree_sitter::Node, source: &str) -> Option<MethodInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    Some(MethodInfo {
        name,
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    })
}

// =============================================================================
// TypeScript/JavaScript Class Extraction
// =============================================================================

/// Extract TypeScript/JavaScript classes with their methods
fn extract_typescript_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_typescript_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_typescript_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration" || child.kind() == "class" {
            if let Some(class_info) = extract_typescript_class_info(&child, source) {
                classes.push(class_info);
            }
        }
        // Recurse into children
        extract_typescript_classes_recursive(child, source, classes);
    }
}

fn extract_typescript_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_typescript_methods(&body, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn extract_typescript_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        // TypeScript method_definition
        if child.kind() == "method_definition" || child.kind() == "public_field_definition" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    // Skip constructor for cohesion analysis (similar to __init__)
                    if name != "constructor" {
                        methods.push(MethodInfo {
                            name: name.to_string(),
                            start_byte: child.start_byte(),
                            end_byte: child.end_byte(),
                        });
                    }
                }
            }
        }
    }

    methods
}

// =============================================================================
// Java Class Extraction
// =============================================================================

/// Extract Java classes, interfaces, and enums with their methods
fn extract_java_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_java_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_java_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "interface_declaration" | "enum_declaration" => {
                if let Some(class_info) = extract_java_class_info(&child, source) {
                    classes.push(class_info);
                }
                // Recurse into class body for nested classes
                if let Some(body) = child.child_by_field_name("body") {
                    extract_java_classes_recursive(body, source, classes);
                }
            }
            _ => {
                // Recurse into other nodes (program level, etc.)
                extract_java_classes_recursive(child, source, classes);
            }
        }
    }
}

fn extract_java_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_java_methods(&body, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

fn extract_java_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        // method_declaration is a regular method; constructor_declaration is excluded
        // (similar to how TypeScript excludes "constructor")
        if child.kind() == "method_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    methods.push(MethodInfo {
                        name: name.to_string(),
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }

    methods
}

// =============================================================================
// Go Struct Extraction
// =============================================================================

/// Extract Go structs with their receiver methods
fn extract_go_structs(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut structs: HashMap<String, ClassInfo> = HashMap::new();

    // First pass: collect all struct declarations
    collect_go_structs(root, source, &mut structs);

    // Second pass: collect receiver methods and associate with structs
    collect_go_methods(root, source, &mut structs);

    structs.into_values().collect()
}

fn collect_go_structs(
    node: tree_sitter::Node,
    source: &str,
    structs: &mut HashMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "type_declaration" {
            // Look for struct type specs
            let mut type_cursor = child.walk();
            for type_child in child.children(&mut type_cursor) {
                if type_child.kind() == "type_spec" {
                    if let Some(name_node) = type_child.child_by_field_name("name") {
                        if let Some(type_node) = type_child.child_by_field_name("type") {
                            if type_node.kind() == "struct_type" {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let line = type_child.start_position().row + 1;
                                    structs.insert(
                                        name.to_string(),
                                        ClassInfo {
                                            name: name.to_string(),
                                            line,
                                            methods: Vec::new(),
                                            is_partial: false,
                                            namespace_path: Vec::new(),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        // Recurse
        collect_go_structs(child, source, structs);
    }
}

fn collect_go_methods(
    node: tree_sitter::Node,
    source: &str,
    structs: &mut HashMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            // Extract receiver type
            if let Some(receiver) = child.child_by_field_name("receiver") {
                if let Some(struct_name) = extract_go_receiver_type(&receiver, source) {
                    // Extract method name
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(method_name) = name_node.utf8_text(source.as_bytes()) {
                            if let Some(class_info) = structs.get_mut(&struct_name) {
                                class_info.methods.push(MethodInfo {
                                    name: method_name.to_string(),
                                    start_byte: child.start_byte(),
                                    end_byte: child.end_byte(),
                                });
                            }
                        }
                    }
                }
            }
        }
        // Recurse
        collect_go_methods(child, source, structs);
    }
}

fn extract_go_receiver_type(receiver: &tree_sitter::Node, source: &str) -> Option<String> {
    // receiver is parameter_list, find the type inside
    let mut cursor = receiver.walk();
    for child in receiver.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            if let Some(type_node) = child.child_by_field_name("type") {
                // Handle pointer receiver (*Type)
                if type_node.kind() == "pointer_type" {
                    if let Some(elem) = type_node.named_child(0) {
                        return elem
                            .utf8_text(source.as_bytes())
                            .ok()
                            .map(|s| s.to_string());
                    }
                } else {
                    return type_node
                        .utf8_text(source.as_bytes())
                        .ok()
                        .map(|s| s.to_string());
                }
            }
        }
    }
    None
}

// =============================================================================
// Rust Struct Extraction
// =============================================================================

/// Extract Rust structs with their impl block methods
fn extract_rust_structs(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut structs: HashMap<String, ClassInfo> = HashMap::new();

    // First pass: collect all struct declarations
    collect_rust_structs(root, source, &mut structs);

    // Second pass: collect impl block methods and associate with structs
    collect_rust_impl_methods(root, source, &mut structs);

    structs.into_values().collect()
}

fn collect_rust_structs(
    node: tree_sitter::Node,
    source: &str,
    structs: &mut HashMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "struct_item" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    let line = child.start_position().row + 1;
                    structs.insert(
                        name.to_string(),
                        ClassInfo {
                            name: name.to_string(),
                            line,
                            methods: Vec::new(),
                            is_partial: false,
                            namespace_path: Vec::new(),
                        },
                    );
                }
            }
        }
        // Recurse
        collect_rust_structs(child, source, structs);
    }
}

fn collect_rust_impl_methods(
    node: tree_sitter::Node,
    source: &str,
    structs: &mut HashMap<String, ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "impl_item" {
            // Get the type being implemented
            if let Some(type_node) = child.child_by_field_name("type") {
                if let Ok(type_name) = type_node.utf8_text(source.as_bytes()) {
                    let type_name = type_name.to_string();

                    // Get the body of the impl block
                    if let Some(body) = child.child_by_field_name("body") {
                        let mut body_cursor = body.walk();
                        for body_child in body.children(&mut body_cursor) {
                            if body_child.kind() == "function_item" {
                                // Skip associated functions (no self parameter).
                                // Only include instance methods (&self, &mut self, self)
                                // for LCOM4 analysis, since associated functions like
                                // new() and default() don't access self.field and would
                                // inflate LCOM4 by forming disconnected components.
                                if !rust_function_has_self(&body_child) {
                                    continue;
                                }
                                if let Some(name_node) = body_child.child_by_field_name("name") {
                                    if let Ok(method_name) = name_node.utf8_text(source.as_bytes())
                                    {
                                        if let Some(class_info) = structs.get_mut(&type_name) {
                                            class_info.methods.push(MethodInfo {
                                                name: method_name.to_string(),
                                                start_byte: body_child.start_byte(),
                                                end_byte: body_child.end_byte(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Recurse
        collect_rust_impl_methods(child, source, structs);
    }
}

/// Check if a Rust function_item has a self parameter (&self, &mut self, or self).
///
/// In tree-sitter-rust, instance methods have a `self_parameter` node inside
/// the `parameters` field. Associated functions (like `fn new() -> Self`)
/// have no `self_parameter`.
fn rust_function_has_self(function_node: &tree_sitter::Node) -> bool {
    if let Some(params) = function_node.child_by_field_name("parameters") {
        let mut cursor = params.walk();
        for param_child in params.children(&mut cursor) {
            if param_child.kind() == "self_parameter" {
                return true;
            }
        }
    }
    false
}

// =============================================================================
// Ruby Class Extraction
// =============================================================================

/// Extract Ruby classes with their methods
fn extract_ruby_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_ruby_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_ruby_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class" => {
                if let Some(class_info) = extract_ruby_class_info(&child, source) {
                    classes.push(class_info);
                }
                // Recurse into class body for nested classes
                if let Some(body) = child.child_by_field_name("body") {
                    extract_ruby_classes_recursive(body, source, classes);
                }
            }
            _ => {
                extract_ruby_classes_recursive(child, source, classes);
            }
        }
    }
}

fn extract_ruby_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_ruby_methods(&body, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

/// Extract methods from a Ruby class body (body_statement node).
///
/// Ruby methods are `method` nodes (instance methods) and `singleton_method`
/// nodes (class methods like `self.foo`). For LCOM4 we include both since
/// singleton methods can also access class-level instance variables.
fn extract_ruby_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        if child.kind() == "method" || child.kind() == "singleton_method" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    methods.push(MethodInfo {
                        name: name.to_string(),
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }

    methods
}

// =============================================================================
// C# Class Extraction
// =============================================================================

/// Extract C# classes, structs, and interfaces with their methods
fn extract_csharp_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_csharp_classes_recursive(root, source, &[], &mut classes);
    classes
}

/// fix-cl-7-v1 (v0.5.0 DESIGN-TAIL, Facet B1'): walk C# declarations while
/// tracking the enclosing namespace chain so each `ClassInfo` carries its
/// `namespace_path`. Two namespace forms exist:
///   - `namespace_declaration` nests its members in a `body`
///     (`declaration_list`); the namespace applies to that subtree.
///   - `file_scoped_namespace_declaration` (`namespace A;`) is a *sibling*;
///     every declaration that follows it in the same scope belongs to it.
/// We therefore process children left-to-right, extending the active
/// namespace once a file-scoped declaration is seen.
fn extract_csharp_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    current_ns: &[String],
    classes: &mut Vec<ClassInfo>,
) {
    let mut active_ns: Vec<String> = current_ns.to_vec();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "struct_declaration" | "interface_declaration" => {
                if let Some(mut class_info) = extract_csharp_class_info(&child, source) {
                    class_info.namespace_path = active_ns.clone();
                    classes.push(class_info);
                }
                // Recurse into class body for nested classes (they keep the
                // same namespace path; nested-class qualification is out of
                // scope for the merge key).
                if let Some(body) = child.child_by_field_name("body") {
                    extract_csharp_classes_recursive(body, source, &active_ns, classes);
                }
            }
            "namespace_declaration" => {
                let mut nested = active_ns.clone();
                nested.extend(csharp_namespace_segments(&child, source));
                if let Some(body) = child.child_by_field_name("body") {
                    extract_csharp_classes_recursive(body, source, &nested, classes);
                } else {
                    extract_csharp_classes_recursive(child, source, &nested, classes);
                }
            }
            "file_scoped_namespace_declaration" => {
                // Applies to all subsequent siblings in this scope.
                active_ns = current_ns.to_vec();
                active_ns.extend(csharp_namespace_segments(&child, source));
            }
            _ => {
                extract_csharp_classes_recursive(child, source, &active_ns, classes);
            }
        }
    }
}

/// Extract the namespace name segments from a C# namespace node's `name`
/// field. `namespace A` -> `["A"]`; `namespace A.B.C` (a `qualified_name`)
/// -> `["A","B","C"]`.
fn csharp_namespace_segments(ns_node: &tree_sitter::Node, source: &str) -> Vec<String> {
    match ns_node.child_by_field_name("name") {
        Some(name) => csharp_name_segments(&name, source),
        None => Vec::new(),
    }
}

fn csharp_name_segments(node: &tree_sitter::Node, source: &str) -> Vec<String> {
    match node.kind() {
        "qualified_name" => {
            let mut out = Vec::new();
            if let Some(q) = node.child_by_field_name("qualifier") {
                out.extend(csharp_name_segments(&q, source));
            }
            if let Some(n) = node.child_by_field_name("name") {
                out.extend(csharp_name_segments(&n, source));
            }
            out
        }
        _ => node_text_of(node, source)
            .filter(|s| !s.is_empty())
            .into_iter()
            .collect(),
    }
}

fn extract_csharp_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_csharp_methods(&body, source);

    // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): detect the
    // `partial` modifier on a `class_declaration` / `struct_declaration`
    // / `interface_declaration`. Tree-sitter-c-sharp surfaces
    // modifiers either as `modifier` direct children (current grammar)
    // or via a `modifiers` field (older grammars / robustness path).
    // When `partial` is present, downstream aggregation (in
    // `analyze_cohesion_with_options`) merges entries with the same
    // name across files into a single LCOM4 computation.
    let is_partial = csharp_class_is_partial(node, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial,
        // Populated by the caller (`extract_csharp_classes_recursive`) which
        // tracks the enclosing `namespace_declaration` /
        // `file_scoped_namespace_declaration` chain. fix-cl-7-v1 Facet B1'.
        namespace_path: Vec::new(),
    })
}

fn csharp_class_is_partial(node: &tree_sitter::Node, source: &str) -> bool {
    // Scan direct children for a `modifier` text == "partial".
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifier" {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "partial" {
                    return true;
                }
            }
        }
    }
    // Defense-in-depth: older grammars expose a `modifiers` aggregate.
    if let Some(mods) = node.child_by_field_name("modifiers") {
        if let Ok(text) = mods.utf8_text(source.as_bytes()) {
            if text.split_whitespace().any(|w| w == "partial") {
                return true;
            }
        }
    }
    false
}

/// Extract methods from a C# class body (declaration_list node).
///
/// Only includes `method_declaration` nodes. Constructors
/// (`constructor_declaration`) are excluded from LCOM4 analysis,
/// consistent with how Java excludes constructors.
fn extract_csharp_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    methods.push(MethodInfo {
                        name: name.to_string(),
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }

    methods
}

// =============================================================================
// Scala Class Extraction
// =============================================================================

/// Extract Scala classes, objects, and traits with their methods
fn extract_scala_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_scala_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_scala_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_definition" | "object_definition" | "trait_definition" => {
                if let Some(class_info) = extract_scala_class_info(&child, source) {
                    classes.push(class_info);
                }
                // Recurse into body for nested classes
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "template_body" || inner_child.kind() == "body" {
                        extract_scala_classes_recursive(inner_child, source, classes);
                    }
                }
            }
            _ => {
                extract_scala_classes_recursive(child, source, classes);
            }
        }
    }
}

fn extract_scala_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    // Scala tree-sitter may use "name" field or have identifier as a direct child
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
        .or_else(|| {
            // Fallback: find first identifier child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return child
                        .utf8_text(source.as_bytes())
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            None
        })?;

    let line = node.start_position().row + 1;
    let methods = extract_scala_methods(node, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

/// Extract methods from a Scala class/object/trait.
///
/// Scala methods (`function_definition` / `function_declaration`) live inside
/// a `template_body` or `body` child of the class node.
fn extract_scala_methods(node: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "template_body" || child.kind() == "body" {
            let mut body_cursor = child.walk();
            for body_child in child.children(&mut body_cursor) {
                if body_child.kind() == "function_definition"
                    || body_child.kind() == "function_declaration"
                {
                    if let Some(name_node) = body_child.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            methods.push(MethodInfo {
                                name: name.to_string(),
                                start_byte: body_child.start_byte(),
                                end_byte: body_child.end_byte(),
                            });
                        }
                    }
                }
            }
        }
    }

    methods
}

// =============================================================================
// PHP Class Extraction
// =============================================================================

/// Extract PHP classes, interfaces, and traits with their methods
fn extract_php_classes(root: tree_sitter::Node, source: &str) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    extract_php_classes_recursive(root, source, &mut classes);
    classes
}

fn extract_php_classes_recursive(
    node: tree_sitter::Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                if let Some(class_info) = extract_php_class_info(&child, source) {
                    classes.push(class_info);
                }
                // Recurse into class body for nested classes
                if let Some(body) = child.child_by_field_name("body") {
                    extract_php_classes_recursive(body, source, classes);
                }
            }
            _ => {
                extract_php_classes_recursive(child, source, classes);
            }
        }
    }
}

fn extract_php_class_info(node: &tree_sitter::Node, source: &str) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();
    let line = node.start_position().row + 1;

    let body = node.child_by_field_name("body")?;
    let methods = extract_php_methods(&body, source);

    Some(ClassInfo {
        name,
        line,
        methods,
        is_partial: false,
        namespace_path: Vec::new(),
    })
}

/// Extract methods from a PHP class body (declaration_list node).
///
/// Only includes `method_declaration` nodes. Constructors (`__construct`)
/// are included as regular methods since PHP doesn't use a separate AST
/// node type for constructors.
fn extract_php_methods(body: &tree_sitter::Node, source: &str) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    methods.push(MethodInfo {
                        name: name.to_string(),
                        start_byte: child.start_byte(),
                        end_byte: child.end_byte(),
                    });
                }
            }
        }
    }

    methods
}

// =============================================================================
// LCOM4 Computation
// =============================================================================

/// Check if a method name is a dunder method (__name__)
fn is_dunder_method(name: &str) -> bool {
    name.starts_with("__") && name.ends_with("__")
}

/// Extract self.field accesses from a method's source text (Python)
pub(crate) fn extract_self_accesses(method_source: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Regex to match self.field_name patterns
    // Handles: self.field, self.field_name, self._private_field
    let pattern = Regex::new(r"self\.([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

    for cap in pattern.captures_iter(method_source) {
        if let Some(field) = cap.get(1) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Extract this.field accesses from a method's source text (TypeScript/JavaScript)
fn extract_this_accesses(method_source: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Regex to match this.field_name patterns
    let pattern = Regex::new(r"this\.([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

    for cap in pattern.captures_iter(method_source) {
        if let Some(field) = cap.get(1) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Extract field accesses from Go method (receiver.field)
fn extract_go_receiver_accesses(method_source: &str, receiver_name: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Match receiver.field patterns
    let pattern_str = format!(
        r"{}\.([a-zA-Z_][a-zA-Z0-9_]*)",
        regex::escape(receiver_name)
    );
    if let Ok(pattern) = Regex::new(&pattern_str) {
        for cap in pattern.captures_iter(method_source) {
            if let Some(field) = cap.get(1) {
                fields.insert(field.as_str().to_string());
            }
        }
    }

    // Also match common Go receiver patterns like s.field, t.field
    let short_pattern = Regex::new(r"\b([a-z])\.([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();
    for cap in short_pattern.captures_iter(method_source) {
        if let Some(field) = cap.get(2) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Extract field accesses from Rust method (self.field)
fn extract_rust_self_accesses(method_source: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Regex to match self.field_name patterns
    let pattern = Regex::new(r"self\.([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

    for cap in pattern.captures_iter(method_source) {
        if let Some(field) = cap.get(1) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Extract field accesses from Ruby method (@field instance variables)
fn extract_ruby_instance_var_accesses(method_source: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Match all @-prefixed identifiers (including @@class_vars), then filter.
    // The regex crate does not support lookbehinds, so we capture an optional
    // second '@' and skip matches where it is present (@@class_var).
    let pattern = Regex::new(r"(@?)@([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

    for cap in pattern.captures_iter(method_source) {
        // If group 1 captured an '@', this is a @@class_var -- skip it.
        if cap.get(1).is_some_and(|m| !m.as_str().is_empty()) {
            continue;
        }
        if let Some(field) = cap.get(2) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Extract field accesses from PHP method ($this->field)
fn extract_php_this_accesses(method_source: &str) -> HashSet<String> {
    let mut fields = HashSet::new();

    // Regex to match $this->field_name patterns
    let pattern = Regex::new(r"\$this->([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

    for cap in pattern.captures_iter(method_source) {
        if let Some(field) = cap.get(1) {
            fields.insert(field.as_str().to_string());
        }
    }

    fields
}

/// Compute cohesion for a single class
///
/// cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): superseded by
/// `cohesion_from_method_fields` in the directory-walk pipeline so
/// partial-class entries can be merged across files. Retained for
/// the in-tree unit tests that drive the legacy data shape directly.
#[cfg(test)]
fn compute_class_cohesion(
    class_info: &ClassInfo,
    source: &str,
    file_path: &Path,
    options: &CohesionOptions,
) -> ClassCohesion {
    // Filter out dunder methods if not including them
    let methods: Vec<&MethodInfo> = class_info
        .methods
        .iter()
        .filter(|m| options.include_dunder || !is_dunder_method(&m.name))
        .collect();

    let method_count = methods.len();

    // Special cases (T9 mitigation):
    // - 0 methods: LCOM4 = 0 (degenerate case, can't measure)
    // - 1 method: LCOM4 = 1 (single method is trivially cohesive)
    if method_count == 0 {
        return ClassCohesion {
            name: class_info.name.clone(),
            file: file_path.to_path_buf(),
            line: class_info.line,
            method_count: 0,
            field_count: 0,
            lcom4: 0,
            components: vec![],
            verdict: CohesionVerdict::Cohesive,
            split_suggestion: None,
        };
    }

    if method_count == 1 {
        let method = methods[0];
        let method_source = &source[method.start_byte..method.end_byte];
        let fields = extract_field_accesses(method_source, file_path);
        let field_vec: Vec<String> = fields.into_iter().collect();

        return ClassCohesion {
            name: class_info.name.clone(),
            file: file_path.to_path_buf(),
            line: class_info.line,
            method_count: 1,
            field_count: field_vec.len(),
            lcom4: 1,
            components: vec![ComponentInfo {
                methods: vec![method.name.clone()],
                fields: field_vec,
            }],
            verdict: CohesionVerdict::Cohesive,
            split_suggestion: None,
        };
    }

    // Extract field accesses for each method
    let method_fields: Vec<HashSet<String>> = methods
        .iter()
        .map(|m| {
            let method_source = &source[m.start_byte..m.end_byte];
            extract_field_accesses(method_source, file_path)
        })
        .collect();

    // Collect all unique fields
    let all_fields: HashSet<String> = method_fields.iter().flatten().cloned().collect();
    let field_count = all_fields.len();

    // If no methods access any fields, each method is its own component
    if all_fields.is_empty() {
        let lcom4 = method_count;
        let components: Vec<ComponentInfo> = methods
            .iter()
            .map(|m| ComponentInfo {
                methods: vec![m.name.clone()],
                fields: vec![],
            })
            .collect();

        let verdict = if lcom4 > options.low_cohesion_threshold {
            CohesionVerdict::SplitCandidate
        } else {
            CohesionVerdict::Cohesive
        };

        let split_suggestion = if verdict == CohesionVerdict::SplitCandidate {
            Some(format!(
                "Class has {} disconnected methods with no shared state",
                method_count
            ))
        } else {
            None
        };

        return ClassCohesion {
            name: class_info.name.clone(),
            file: file_path.to_path_buf(),
            line: class_info.line,
            method_count,
            field_count: 0,
            lcom4,
            components,
            verdict,
            split_suggestion,
        };
    }

    // Build Union-Find and connect methods that share fields
    let mut uf = UnionFind::new(method_count);

    for i in 0..method_count {
        for j in (i + 1)..method_count {
            // Check if methods i and j share any fields
            if !method_fields[i].is_disjoint(&method_fields[j]) {
                uf.union(i, j);
            }
        }
    }

    // Count connected components
    let lcom4 = uf.count_components();

    // Build component info
    let component_ids = uf.get_components();
    let mut component_map: HashMap<usize, (Vec<String>, HashSet<String>)> = HashMap::new();

    for (i, &comp_id) in component_ids.iter().enumerate() {
        let entry = component_map
            .entry(comp_id)
            .or_insert_with(|| (Vec::new(), HashSet::new()));
        entry.0.push(methods[i].name.clone());
        entry.1.extend(method_fields[i].iter().cloned());
    }

    let components: Vec<ComponentInfo> = component_map
        .into_values()
        .map(|(methods, fields)| ComponentInfo {
            methods,
            fields: fields.into_iter().collect(),
        })
        .collect();

    let verdict = if lcom4 > options.low_cohesion_threshold {
        CohesionVerdict::SplitCandidate
    } else {
        CohesionVerdict::Cohesive
    };

    let split_suggestion = if verdict == CohesionVerdict::SplitCandidate {
        Some(format!(
            "Consider splitting into {} classes based on {} disconnected method groups",
            lcom4, lcom4
        ))
    } else {
        None
    };

    ClassCohesion {
        name: class_info.name.clone(),
        file: file_path.to_path_buf(),
        line: class_info.line,
        method_count,
        field_count,
        lcom4,
        components,
        verdict,
        split_suggestion,
    }
}

/// Extract field accesses based on file extension/language.
///
/// Uses AST-based extraction when possible, falling back to regex for
/// languages where tree-sitter parsing fails or returns no results.
fn extract_field_accesses(method_source: &str, file_path: &Path) -> HashSet<String> {
    let lang = Language::from_path(file_path);

    match lang {
        Some(language) => extract_field_accesses_ast(method_source, language, None),
        None => {
            // Unknown language: try regex fallback based on extension
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            match ext {
                "py" => extract_self_accesses(method_source),
                "ts" | "tsx" | "js" | "jsx" => extract_this_accesses(method_source),
                "go" => extract_go_receiver_accesses(method_source, ""),
                "rs" => extract_rust_self_accesses(method_source),
                "rb" => extract_ruby_instance_var_accesses(method_source),
                "cs" => extract_this_accesses(method_source),
                "scala" | "sc" => extract_this_accesses(method_source),
                "php" => extract_php_this_accesses(method_source),
                _ => HashSet::new(),
            }
        }
    }
}

/// AST-based field access extraction for all 18 supported languages.
///
/// Parses the method source text with tree-sitter and walks the AST looking
/// for field/member access nodes where the object is self/this/receiver.
///
/// Falls back to regex if AST parsing fails.
///
/// # Arguments
/// * `method_source` - Source code of the method body
/// * `language` - The programming language
/// * `receiver_name` - Optional receiver name for Go (e.g., "s" in `func (s *Server)`)
pub fn extract_field_accesses_ast(
    method_source: &str,
    language: Language,
    receiver_name: Option<&str>,
) -> HashSet<String> {
    use crate::security::ast_utils::field_access_info;

    let tree = match parse(method_source, language) {
        Ok(t) => t,
        Err(_) => {
            // Fallback to regex if AST parsing fails
            return extract_field_accesses_regex(method_source, language, receiver_name);
        }
    };

    let mut fields = HashSet::new();
    let source = method_source.as_bytes();
    let patterns = field_access_info(language);

    walk_and_extract_fields(
        &tree.root_node(),
        source,
        language,
        receiver_name,
        patterns,
        &mut fields,
    );

    // If AST found nothing but regex would have found something, fallback
    if fields.is_empty() {
        let regex_fields = extract_field_accesses_regex(method_source, language, receiver_name);
        if !regex_fields.is_empty() {
            return regex_fields;
        }
    }

    fields
}

/// Walk AST nodes recursively and extract field names from field access expressions.
fn walk_and_extract_fields(
    node: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    receiver_name: Option<&str>,
    patterns: &[crate::security::ast_utils::FieldAccessPattern],
    fields: &mut HashSet<String>,
) {
    use crate::security::ast_utils::{is_in_comment, is_in_string};

    let node_kind = node.kind();

    for pattern in patterns {
        if node_kind == pattern.node_kind {
            // Skip if inside a comment or string
            if is_in_comment(node, language) || is_in_string(node, language) {
                continue;
            }

            if let Some(field_name) =
                extract_field_from_pattern(node, source, language, receiver_name, pattern)
            {
                fields.insert(field_name);
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_and_extract_fields(&child, source, language, receiver_name, patterns, fields);
    }
}

/// Extract a field name from a node matching a FieldAccessPattern.
///
/// Returns Some(field_name) if the node is a self/this/receiver field access,
/// None otherwise.
fn extract_field_from_pattern(
    node: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    receiver_name: Option<&str>,
    _pattern: &crate::security::ast_utils::FieldAccessPattern,
) -> Option<String> {
    match language {
        Language::Python => extract_field_with_named_receiver(
            node,
            source,
            "object",
            "attribute",
            "self",
            "call",
            "function",
        ),
        Language::TypeScript | Language::JavaScript => extract_field_with_named_receiver(
            node,
            source,
            "object",
            "property",
            "this",
            "call_expression",
            "function",
        ),
        Language::Go => extract_go_field_access(node, source, receiver_name),
        Language::Rust => extract_field_with_named_receiver(
            node,
            source,
            "value",
            "field",
            "self",
            "call_expression",
            "function",
        ),
        Language::Java => extract_java_this_field_access(node, source),
        Language::CSharp => extract_field_with_positional_receiver(
            node,
            source,
            0,
            "name",
            "this",
            "invocation_expression",
            0,
        ),
        Language::Cpp => extract_field_with_named_receiver(
            node,
            source,
            "argument",
            "field",
            "this",
            "call_expression",
            "function",
        ),
        Language::C => extract_c_field_access(node, source),
        Language::Ruby => extract_ruby_instance_field(node, source),
        Language::Kotlin => extract_navigation_field_access(
            node,
            source,
            "this_expression",
            "this",
            "call_expression",
        ),
        Language::Swift => extract_swift_navigation_field_access(node, source),
        Language::Scala => extract_scala_this_field_access(node, source),
        Language::Php => extract_php_this_field_access(node, source),
        Language::Lua | Language::Luau => extract_lua_self_field_access(node, source),
        Language::Elixir => extract_elixir_module_attribute(node, source),
        Language::Ocaml => None,
        // v0.5.0 SOL-001 Solidity foundation. Cohesion analysis
        // (state-variable access tracking) lands with the adapter in
        // SOL-002+.
        Language::Solidity => None,
    }
}

fn extract_field_with_named_receiver(
    node: &tree_sitter::Node,
    source: &[u8],
    receiver_field: &str,
    field_name: &str,
    expected_receiver: &str,
    call_parent_kind: &str,
    call_target_field: &str,
) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let receiver = node.child_by_field_name(receiver_field)?;
    if node_text(&receiver, source) != expected_receiver {
        return None;
    }
    if parent_field_matches_node(node, call_parent_kind, call_target_field) {
        return None;
    }
    Some(node_text(&node.child_by_field_name(field_name)?, source).to_string())
}

/// Java `this.field` access extraction.
///
/// IT3-java-04 (v0.5.0 CL-6): the previous implementation routed Java through
/// `extract_field_with_named_receiver(..., "method_invocation", "object")`,
/// which dropped any `field_access` that was the `object` (receiver) of a
/// `method_invocation` — e.g. `this.field.doSomething()`. That guard exists to
/// avoid double-counting a `this.method()` *call* as a field, but in the Java
/// grammar `this.method()` is a `method_invocation` (with `object = this`,
/// `name = method`), **never** a `field_access`. A `field_access` node whose
/// `object` is `this` is therefore *always* a genuine field read — even when it
/// is itself the receiver of a subsequent method call. We drop the spurious
/// parent guard entirely and simply require `object == this`.
///
/// Grammar (tree-sitter-java):
///   `field_access` has `object` and `field` fields. `object` may be a
///   `this` node (kind `"this"`) for the `this.field` idiom this metric tracks.
fn extract_java_this_field_access(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let receiver = node.child_by_field_name("object")?;
    if node_text(&receiver, source) != "this" {
        return None;
    }
    Some(node_text(&node.child_by_field_name("field")?, source).to_string())
}

fn extract_field_with_positional_receiver(
    node: &tree_sitter::Node,
    source: &[u8],
    receiver_index: usize,
    field_name: &str,
    expected_receiver: &str,
    call_parent_kind: &str,
    call_target_index: usize,
) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let receiver = node.child(receiver_index)?;
    if node_text(&receiver, source) != expected_receiver {
        return None;
    }
    if parent_child_matches_node(node, call_parent_kind, call_target_index) {
        return None;
    }
    Some(node_text(&node.child_by_field_name(field_name)?, source).to_string())
}

fn extract_go_field_access(
    node: &tree_sitter::Node,
    source: &[u8],
    receiver_name: Option<&str>,
) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let operand = node.child_by_field_name("operand")?;
    let operand_text = node_text(&operand, source);
    if !is_go_receiver_match(operand_text, receiver_name) {
        return None;
    }
    if parent_field_matches_node(node, "call_expression", "function") {
        return None;
    }
    Some(node_text(&node.child_by_field_name("field")?, source).to_string())
}

fn is_go_receiver_match(operand_text: &str, receiver_name: Option<&str>) -> bool {
    match receiver_name {
        Some("") | None => is_single_lowercase_identifier(operand_text),
        Some(recv) => operand_text == recv,
    }
}

fn is_single_lowercase_identifier(text: &str) -> bool {
    text.len() == 1 && text.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

fn extract_c_field_access(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    node.child_by_field_name("argument")?;
    Some(node_text(&node.child_by_field_name("field")?, source).to_string())
}

fn extract_ruby_instance_field(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let text = node_text(node, source);
    if text.starts_with('@') && !text.starts_with("@@") {
        return Some(text[1..].to_string());
    }
    None
}

fn extract_navigation_field_access(
    node: &tree_sitter::Node,
    source: &[u8],
    self_kind: &str,
    self_text: &str,
    call_parent_kind: &str,
) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let target = node.child(0)?;
    if target.kind() != self_kind && node_text(&target, source) != self_text {
        return None;
    }

    for i in 1..node.child_count() {
        let child = node.child(i)?;
        if child.kind() == "identifier" || child.kind() == "simple_identifier" {
            if parent_child_matches_node(node, call_parent_kind, 0) {
                return None;
            }
            return Some(node_text(&child, source).to_string());
        }
        if child.kind() == "navigation_suffix" {
            if let Some(identifier) = extract_suffix_identifier(&child, source) {
                if parent_child_matches_node(node, call_parent_kind, 0) {
                    return None;
                }
                return Some(identifier);
            }
        }
    }

    None
}

fn extract_suffix_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if child.kind() == "simple_identifier" || child.kind() == "identifier" {
            return Some(node_text(&child, source).to_string());
        }
    }
    None
}

/// Swift-specific field extraction that tolerates tree-sitter-swift's
/// left-associative misparse of mixed-arithmetic + member-access
/// expressions.
///
/// Background: for `self.a + self.b`, tree-sitter-swift produces
///
/// ```text
/// navigation_expression "self.a + self.b"
///   additive_expression "self.a + self"
///     navigation_expression "self.a"
///       self_expression
///       navigation_suffix .a
///     +
///     self_expression "self"      <-- orphan self
///   navigation_suffix .b          <-- attached to outer node
/// ```
///
/// The trailing `.b` is parented by the *outer* `navigation_expression`
/// whose `child(0)` is the additive_expression, NOT a `self_expression`.
/// The legacy `extract_navigation_field_access(self_kind="self_expression",
/// self_text="self")` filter then rejected the outer node, dropping
/// `b` from the field set. This was observable as e.g. `Shape.area`
/// reporting only `width` from `self.width * self.height`
/// (cohesion-cross-file-aggregation-v1 / v0.4.2 M-030).
///
/// Recovery: if the outer `navigation_expression` carries a trailing
/// `navigation_suffix` AND the subtree (excluding sub-
/// navigation_expressions which already booked their own field) holds
/// at least one orphan `self_expression`, treat the suffix's
/// identifier as a self.field access too.
fn extract_swift_navigation_field_access(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    // Fast path: the conventional `self.x` shape.
    if let Some(s) = extract_navigation_field_access(
        node,
        source,
        "self_expression",
        "self",
        "call_expression",
    ) {
        return Some(s);
    }

    // Misparse recovery (see doc comment).
    // We only run the rescue for the OUTER navigation_expression — i.e.
    // when its trailing child is a `navigation_suffix` AND there's an
    // orphan `self_expression` reachable in the subtree that is NOT
    // already consumed by an inner navigation_expression. We avoid
    // double-counting by requiring the orphan self to sit directly
    // inside an `additive_expression` / `multiplicative_expression` /
    // similar arithmetic parent rather than under a nested
    // navigation_expression.
    if node.kind() != "navigation_expression" {
        return None;
    }
    let last_idx = node.child_count().checked_sub(1)?;
    let last = node.child(last_idx)?;
    if last.kind() != "navigation_suffix" {
        return None;
    }
    if !swift_subtree_has_orphan_self(node) {
        return None;
    }
    // Don't emit if the navigation_expression itself is the function
    // target of a call_expression (consistent with the legacy filter).
    if parent_child_matches_node(node, "call_expression", 0) {
        return None;
    }
    extract_suffix_identifier(&last, source)
}

/// True iff `root`'s descendants contain a `self_expression` whose
/// nearest navigation_expression ancestor is `root` itself — i.e. a
/// `self` reference that has NOT already been paired with a
/// navigation_suffix by a sub-navigation_expression. Used by the
/// swift misparse recovery in
/// `extract_swift_navigation_field_access`.
fn swift_subtree_has_orphan_self(root: &tree_sitter::Node) -> bool {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            // Skip sub-navigation_expressions: their `self_expression`
            // descendants are already consumed.
            "navigation_expression" => continue,
            "self_expression" => return true,
            _ => {
                if swift_subtree_has_orphan_self(&child) {
                    return true;
                }
            }
        }
    }
    false
}

fn extract_scala_this_field_access(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let mut identifiers = Vec::new();
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        match child.kind() {
            "identifier" | "type_identifier" => {
                identifiers.push(node_text(&child, source).to_string());
            }
            "this" => identifiers.push("this".to_string()),
            _ => {}
        }
    }
    if identifiers.len() >= 2 && identifiers[0] == "this" {
        return Some(identifiers[1].clone());
    }
    None
}

fn extract_php_this_field_access(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let object = node.child_by_field_name("object")?;
    if node_text(&object, source) != "$this" {
        return None;
    }
    Some(node_text(&node.child_by_field_name("name")?, source).to_string())
}

fn extract_lua_self_field_access(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let first = node.child(0)?;
    if node_text(&first, source) != "self" {
        return None;
    }

    for i in (0..node.child_count()).rev() {
        let child = node.child(i)?;
        if child.kind() == "identifier" {
            if parent_child_matches_node(node, "function_call", 0) {
                return None;
            }
            return Some(node_text(&child, source).to_string());
        }
    }
    None
}

fn extract_elixir_module_attribute(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    use crate::security::ast_utils::node_text;

    let operator = node.child(0)?;
    if node_text(&operator, source) != "@" {
        return None;
    }
    let name_node = node.child(1)?;
    if name_node.kind() == "call" {
        return Some(node_text(&name_node.child(0)?, source).to_string());
    }
    Some(node_text(&name_node, source).to_string())
}

fn parent_field_matches_node(
    node: &tree_sitter::Node,
    parent_kind: &str,
    field_name: &str,
) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != parent_kind {
        return false;
    }
    parent
        .child_by_field_name(field_name)
        .is_some_and(|child| child.id() == node.id())
}

fn parent_child_matches_node(
    node: &tree_sitter::Node,
    parent_kind: &str,
    child_index: usize,
) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != parent_kind {
        return false;
    }
    parent
        .child(child_index)
        .is_some_and(|child| child.id() == node.id())
}

/// Regex-based field access extraction (fallback when AST parsing fails).
fn extract_field_accesses_regex(
    method_source: &str,
    language: Language,
    receiver_name: Option<&str>,
) -> HashSet<String> {
    match language {
        Language::Python => extract_self_accesses(method_source),
        Language::TypeScript | Language::JavaScript => extract_this_accesses(method_source),
        Language::Go => {
            let recv = receiver_name.unwrap_or("");
            extract_go_receiver_accesses(method_source, recv)
        }
        Language::Rust => extract_rust_self_accesses(method_source),
        Language::Ruby => extract_ruby_instance_var_accesses(method_source),
        Language::CSharp => extract_this_accesses(method_source),
        Language::Scala => extract_this_accesses(method_source),
        Language::Php => extract_php_this_accesses(method_source),
        _ => HashSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_find_single_component() {
        let mut uf = UnionFind::new(3);
        uf.union(0, 1);
        uf.union(1, 2);
        assert_eq!(uf.count_components(), 1);
    }

    #[test]
    fn test_union_find_multiple_components() {
        let mut uf = UnionFind::new(4);
        uf.union(0, 1); // Component 1: {0, 1}
        uf.union(2, 3); // Component 2: {2, 3}
        assert_eq!(uf.count_components(), 2);
    }

    #[test]
    fn test_union_find_all_separate() {
        let mut uf = UnionFind::new(4);
        // No unions
        assert_eq!(uf.count_components(), 4);
    }

    #[test]
    fn test_union_find_empty() {
        let mut uf = UnionFind::new(0);
        assert_eq!(uf.count_components(), 0);
    }

    #[test]
    fn test_is_dunder_method() {
        assert!(is_dunder_method("__init__"));
        assert!(is_dunder_method("__str__"));
        assert!(is_dunder_method("__repr__"));
        assert!(!is_dunder_method("__private"));
        assert!(!is_dunder_method("public__"));
        assert!(!is_dunder_method("regular_method"));
    }

    #[test]
    fn test_extract_self_accesses() {
        let source = r#"
def method(self):
    self.value = 1
    self._private = 2
    x = self.other
    return self.value + self.other
"#;
        let fields = extract_self_accesses(source);
        assert!(fields.contains("value"));
        assert!(fields.contains("_private"));
        assert!(fields.contains("other"));
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn test_extract_this_accesses() {
        let source = r#"
getValue() {
    return this.value + this.other;
}
"#;
        let fields = extract_this_accesses(source);
        assert!(fields.contains("value"));
        assert!(fields.contains("other"));
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn test_cohesion_verdict_serialization() {
        let cohesive = CohesionVerdict::Cohesive;
        let split = CohesionVerdict::SplitCandidate;

        assert_eq!(serde_json::to_string(&cohesive).unwrap(), "\"cohesive\"");
        assert_eq!(
            serde_json::to_string(&split).unwrap(),
            "\"split_candidate\""
        );
    }

    // =========================================================================
    // AST-based field access extraction tests (all 18 languages)
    // =========================================================================

    #[test]
    fn test_ast_python_field_access() {
        let source = "def method(self):\n    x = self.name\n    y = self.age\n    z = self.name";
        let fields = extract_field_accesses_ast(source, Language::Python, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
        assert_eq!(
            fields.len(),
            2,
            "Expected 2 unique fields, got {:?}",
            fields
        );
    }

    #[test]
    fn test_ast_python_excludes_method_calls() {
        let source = "def method(self):\n    self.do_thing()\n    x = self.name";
        let fields = extract_field_accesses_ast(source, Language::Python, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        // do_thing is a method call, not a field access
        assert!(
            !fields.contains("do_thing"),
            "Should not contain method call 'do_thing': {:?}",
            fields
        );
    }

    #[test]
    fn test_ast_python_string_not_detected() {
        let source = r#"def method(self):
    x = "self.fake_field"
    y = self.real_field"#;
        let fields = extract_field_accesses_ast(source, Language::Python, None);
        assert!(
            fields.contains("real_field"),
            "Expected 'real_field' in {:?}",
            fields
        );
        assert!(
            !fields.contains("fake_field"),
            "Should not detect field in string literal: {:?}",
            fields
        );
    }

    #[test]
    fn test_ast_python_comment_not_detected() {
        let source = "def method(self):\n    # self.commented_field\n    x = self.real_field";
        let fields = extract_field_accesses_ast(source, Language::Python, None);
        assert!(
            fields.contains("real_field"),
            "Expected 'real_field' in {:?}",
            fields
        );
        assert!(
            !fields.contains("commented_field"),
            "Should not detect field in comment: {:?}",
            fields
        );
    }

    #[test]
    fn test_ast_typescript_field_access() {
        let source = "method() {\n    const x = this.name;\n    const y = this.age;\n}";
        let fields = extract_field_accesses_ast(source, Language::TypeScript, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
        assert_eq!(fields.len(), 2, "Expected 2 fields, got {:?}", fields);
    }

    #[test]
    fn test_ast_javascript_field_access() {
        let source = "function method() {\n    const x = this.value;\n    this.count = 0;\n}";
        let fields = extract_field_accesses_ast(source, Language::JavaScript, None);
        assert!(fields.contains("value"), "Expected 'value' in {:?}", fields);
        assert!(fields.contains("count"), "Expected 'count' in {:?}", fields);
    }

    #[test]
    fn test_ast_go_field_access() {
        let source = "func (s *Server) method() {\n    x := s.host\n    y := s.port\n}";
        let fields = extract_field_accesses_ast(source, Language::Go, Some("s"));
        assert!(fields.contains("host"), "Expected 'host' in {:?}", fields);
        assert!(fields.contains("port"), "Expected 'port' in {:?}", fields);
    }

    #[test]
    fn test_ast_go_single_letter_receiver_heuristic() {
        // When no explicit receiver name, match single-letter lowercase identifiers
        let source = "func method() {\n    x := s.host\n    y := s.port\n}";
        let fields = extract_field_accesses_ast(source, Language::Go, None);
        assert!(fields.contains("host"), "Expected 'host' in {:?}", fields);
        assert!(fields.contains("port"), "Expected 'port' in {:?}", fields);
    }

    #[test]
    fn test_ast_rust_field_access() {
        let source = "fn method(&self) {\n    let x = self.name;\n    let y = self.age;\n}";
        let fields = extract_field_accesses_ast(source, Language::Rust, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
        assert_eq!(fields.len(), 2, "Expected 2 fields, got {:?}", fields);
    }

    #[test]
    fn test_ast_java_field_access() {
        let source = "void method() {\n    int x = this.value;\n    this.count = 0;\n}";
        let fields = extract_field_accesses_ast(source, Language::Java, None);
        assert!(fields.contains("value"), "Expected 'value' in {:?}", fields);
        assert!(fields.contains("count"), "Expected 'count' in {:?}", fields);
    }

    #[test]
    fn test_ast_kotlin_field_access() {
        let source = "fun method() {\n    val x = this.name\n    this.age = 25\n}";
        let fields = extract_field_accesses_ast(source, Language::Kotlin, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_swift_field_access() {
        // Swift tree-sitter now works with tree-sitter 0.25.0 (ABI v15 support)
        let source = "func method() {\n    let x = self.name\n    self.age = 25\n}";
        let fields = extract_field_accesses_ast(source, Language::Swift, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_csharp_field_access() {
        let source = "void Method() {\n    var x = this.Name;\n    this.Count = 0;\n}";
        let fields = extract_field_accesses_ast(source, Language::CSharp, None);
        assert!(fields.contains("Name"), "Expected 'Name' in {:?}", fields);
        assert!(fields.contains("Count"), "Expected 'Count' in {:?}", fields);
    }

    #[test]
    fn test_ast_cpp_field_access() {
        let source = "void method() {\n    int x = this->name;\n    this->age = 25;\n}";
        let fields = extract_field_accesses_ast(source, Language::Cpp, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_c_field_access() {
        let source = "void method(struct Server* s) {\n    int x = s->host;\n    s->port = 80;\n}";
        let fields = extract_field_accesses_ast(source, Language::C, None);
        assert!(fields.contains("host"), "Expected 'host' in {:?}", fields);
        assert!(fields.contains("port"), "Expected 'port' in {:?}", fields);
    }

    #[test]
    fn test_ast_ruby_instance_variable() {
        let source = "def method\n    x = @name\n    @age = 25\nend";
        let fields = extract_field_accesses_ast(source, Language::Ruby, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_scala_field_access() {
        let source = "def method(): Unit = {\n    val x = this.name\n    this.age = 25\n}";
        let fields = extract_field_accesses_ast(source, Language::Scala, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_php_field_access() {
        let source = "<?php\nfunction method() {\n    $x = $this->name;\n    $this->age = 25;\n}";
        let fields = extract_field_accesses_ast(source, Language::Php, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_lua_field_access() {
        let source = "function MyClass:method()\n    local x = self.name\n    self.age = 25\nend";
        let fields = extract_field_accesses_ast(source, Language::Lua, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_luau_field_access() {
        let source = "function MyClass:method()\n    local x = self.name\n    self.age = 25\nend";
        let fields = extract_field_accesses_ast(source, Language::Luau, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_elixir_module_attribute() {
        let source = "defmodule MyModule do\n  @name \"test\"\n  @age 25\nend";
        let fields = extract_field_accesses_ast(source, Language::Elixir, None);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
    }

    #[test]
    fn test_ast_ocaml_no_self() {
        // OCaml is functional - no self concept, should return empty
        let source = "let method x = x.name + x.age";
        let fields = extract_field_accesses_ast(source, Language::Ocaml, None);
        // OCaml has no self/this - should return empty or record field accesses
        // For LCOM4 purposes, OCaml classes are rare, so empty is fine
        assert!(
            fields.is_empty(),
            "OCaml should return empty set for LCOM4: {:?}",
            fields
        );
    }

    #[test]
    fn test_ast_regex_fallback_on_parse_failure() {
        // Test that regex fallback works when AST parsing would fail
        // Python regex should still work even with invalid syntax wrapping
        let source = "self.name = 1\nself.age = 2";
        let fields = extract_field_accesses_regex(source, Language::Python, None);
        assert!(
            fields.contains("name"),
            "Regex fallback should find 'name': {:?}",
            fields
        );
        assert!(
            fields.contains("age"),
            "Regex fallback should find 'age': {:?}",
            fields
        );
    }

    // =========================================================================
    // Java class extraction tests
    // =========================================================================

    #[test]
    fn test_extract_java_classes_basic() {
        let source = r#"
public class MyService {
    private String name;

    public MyService(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Java);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(classes[0].name, "MyService");
        // constructor should be excluded, leaving getName and setName
        let non_ctor_methods: Vec<_> = classes[0]
            .methods
            .iter()
            .filter(|m| m.name != "MyService")
            .collect();
        assert_eq!(
            non_ctor_methods.len(),
            2,
            "Expected 2 non-constructor methods, got {:?}",
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_java_classes_multiple() {
        let source = r#"
public class First {
    public void doA() {}
}

class Second {
    public void doB() {}
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Java);
        assert_eq!(
            classes.len(),
            2,
            "Expected 2 classes, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"First"), "Expected 'First' in {:?}", names);
        assert!(
            names.contains(&"Second"),
            "Expected 'Second' in {:?}",
            names
        );
    }

    #[test]
    fn test_extract_java_interface_and_enum() {
        let source = r#"
interface Describable {
    String describe();
}

enum Color {
    RED, GREEN, BLUE;

    public String label() {
        return this.name();
    }
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Java);
        // Should find at least Color enum (has a method), and possibly Describable interface
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Color"),
            "Expected 'Color' enum in {:?}",
            names
        );
    }

    #[test]
    fn test_extract_java_methods_exclude_constructors() {
        let source = r#"
public class Widget {
    private int size;

    public Widget() {
        this.size = 0;
    }

    public Widget(int size) {
        this.size = size;
    }

    public int getSize() {
        return this.size;
    }
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Java);
        assert_eq!(classes.len(), 1);
        let widget = &classes[0];
        // Constructors should be included as MethodInfo (LCOM4 filters dunders, not constructors per se,
        // but for Java we should include method_declaration only, not constructor_declaration)
        // method_declaration: getSize; constructor_declaration: Widget(), Widget(int)
        // We expect only getSize from method_declaration
        let method_names: Vec<&str> = widget.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            method_names.contains(&"getSize"),
            "Expected 'getSize' in {:?}",
            method_names
        );
        // Constructors are separate AST nodes (constructor_declaration) -- we don't extract them
        assert!(
            !method_names.contains(&"Widget"),
            "Constructors should not be extracted: {:?}",
            method_names
        );
    }

    // =========================================================================
    // Rust struct extraction and LCOM4 tests
    // =========================================================================

    #[test]
    fn test_extract_rust_structs_basic() {
        let source = r#"
pub struct Foo {
    bar: String,
    baz: i32,
}

impl Foo {
    pub fn get_bar(&self) -> &str {
        &self.bar
    }
    pub fn get_baz(&self) -> i32 {
        self.baz
    }
    pub fn set_bar(&mut self, val: String) {
        self.bar = val;
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Rust);
        assert_eq!(classes.len(), 1, "Expected 1 struct, got {}", classes.len());
        assert_eq!(classes[0].name, "Foo");
        assert_eq!(
            classes[0].methods.len(),
            3,
            "Expected 3 methods, got {}: {:?}",
            classes[0].methods.len(),
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_lcom4_cohesive_struct() {
        // All methods access overlapping fields => LCOM4 = 1
        let source = r#"
pub struct Foo {
    bar: String,
    baz: i32,
}

impl Foo {
    pub fn get_bar(&self) -> &str {
        &self.bar
    }
    pub fn get_baz(&self) -> i32 {
        self.baz
    }
    pub fn set_bar(&mut self, val: String) {
        self.bar = val;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("foo.rs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let foo = results.iter().find(|c| c.name == "Foo").unwrap();
        assert_eq!(
            foo.method_count, 3,
            "Expected 3 methods, got {}",
            foo.method_count
        );
        assert!(
            foo.field_count > 0,
            "Expected fields to be detected, got {}",
            foo.field_count
        );
        // get_bar accesses bar, get_baz accesses baz, set_bar accesses bar
        // bar connects get_bar and set_bar; they're in one component
        // baz is only in get_baz => separate component
        // So LCOM4 should be 2 (two components: {get_bar, set_bar} and {get_baz})
        assert_eq!(
            foo.lcom4, 2,
            "Expected LCOM4=2 (two components), got {}",
            foo.lcom4
        );
    }

    #[test]
    fn test_rust_lcom4_fully_cohesive() {
        // All methods share the same field => LCOM4 = 1
        let source = r#"
pub struct Counter {
    count: i32,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }
    pub fn decrement(&mut self) {
        self.count -= 1;
    }
    pub fn get(&self) -> i32 {
        self.count
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("counter.rs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let counter = results.iter().find(|c| c.name == "Counter").unwrap();
        assert_eq!(counter.method_count, 3);
        assert_eq!(
            counter.field_count, 1,
            "Expected 1 field (count), got {}",
            counter.field_count
        );
        assert_eq!(
            counter.lcom4, 1,
            "Fully cohesive class should have LCOM4=1, got {}",
            counter.lcom4
        );
    }

    #[test]
    fn test_rust_multiple_structs() {
        let source = r#"
pub struct Alpha {
    x: i32,
}

impl Alpha {
    pub fn get_x(&self) -> i32 {
        self.x
    }
}

pub struct Beta {
    y: String,
}

impl Beta {
    pub fn get_y(&self) -> &str {
        &self.y
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Rust);
        assert_eq!(
            classes.len(),
            2,
            "Expected 2 structs, got {}",
            classes.len()
        );
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Alpha"), "Expected 'Alpha' in {:?}", names);
        assert!(names.contains(&"Beta"), "Expected 'Beta' in {:?}", names);
    }

    #[test]
    fn test_rust_struct_with_multiple_impl_blocks() {
        let source = r#"
pub struct MyType {
    a: i32,
    b: String,
}

impl MyType {
    pub fn get_a(&self) -> i32 {
        self.a
    }
}

impl MyType {
    pub fn get_b(&self) -> &str {
        &self.b
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Rust);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 struct (merged impl blocks), got {}",
            classes.len()
        );
        let my_type = &classes[0];
        assert_eq!(
            my_type.methods.len(),
            2,
            "Expected 2 methods from merged impl blocks, got {}: {:?}",
            my_type.methods.len(),
            my_type.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_trait_impl_methods_included() {
        // impl Default for X should count as methods of X
        let source = r#"
pub struct Config {
    name: String,
    count: i32,
}

impl Config {
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: String::new(),
            count: 0,
        }
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Rust);
        assert_eq!(classes.len(), 1, "Expected 1 struct");
        let config = &classes[0];
        let method_names: Vec<&str> = config.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            method_names.contains(&"get_name"),
            "Expected 'get_name' in methods: {:?}",
            method_names
        );
        // default() from impl Default is a static/associated function (no self parameter),
        // so it should NOT be included in instance methods for LCOM4 analysis.
        assert!(
            !method_names.contains(&"default"),
            "Static 'default()' should be excluded from instance methods: {:?}",
            method_names
        );
        assert_eq!(
            config.methods.len(),
            1,
            "Expected 1 instance method (get_name only, default() excluded), got {}: {:?}",
            config.methods.len(),
            method_names
        );
    }

    #[test]
    fn test_rust_static_method_not_inflating_lcom4() {
        // Static methods (no self parameter) shouldn't inflate LCOM4
        // because they don't participate in field sharing
        let source = r#"
pub struct Builder {
    name: String,
    count: i32,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            count: 0,
        }
    }
    pub fn get_name(&self) -> &str {
        &self.name
    }
    pub fn get_count(&self) -> i32 {
        self.count
    }
    pub fn inc(&mut self) {
        self.count += 1;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("builder.rs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        let builder = results.iter().find(|c| c.name == "Builder").unwrap();
        // new() is a static method (no self parameter), it should be excluded from LCOM4.
        // Only instance methods (with &self or &mut self) participate in field sharing.
        // After fix: method_count should be 3 (get_name, get_count, inc)
        // LCOM4 should be 2: {get_name} accesses name, {get_count, inc} access count
        assert_eq!(
            builder.method_count, 3,
            "Expected 3 instance methods (excluding static new()), got {}",
            builder.method_count
        );
        assert_eq!(
            builder.lcom4, 2,
            "Expected LCOM4=2 (two components: {{get_name}} and {{get_count, inc}}), got {}",
            builder.lcom4
        );
    }

    #[test]
    fn test_rust_field_accesses_detected_in_methods() {
        // Verify that field accesses are detected when extracting from a Rust method
        let method_source = r#"pub fn process(&mut self) {
    let x = self.name;
    self.count += 1;
    self.data.push(x);
}"#;
        let fields = extract_rust_self_accesses(method_source);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("count"), "Expected 'count' in {:?}", fields);
        assert!(fields.contains("data"), "Expected 'data' in {:?}", fields);
        assert_eq!(fields.len(), 3, "Expected 3 fields, got {:?}", fields);
    }

    #[test]
    fn test_rust_analyze_file_cohesion_on_coupling_rs() {
        // coupling.rs has many structs (CouplingReport, ModuleCoupling, etc.)
        // but they are data-only structs with impl Default (a static method).
        // After the self-filtering fix, these structs have 0 instance methods,
        // which is correct since they have no self-accessing methods.
        let coupling_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/quality/coupling.rs");
        if coupling_path.exists() {
            let options = CohesionOptions::default();
            let results = analyze_file_cohesion(&coupling_path, &options).unwrap();
            // The structs should be found, even though they have 0 instance methods
            let names: Vec<&str> = results.iter().map(|c| c.name.as_str()).collect();
            assert!(
                results.len() >= 3,
                "Expected at least 3 structs in coupling.rs, got {}: {:?}",
                results.len(),
                names
            );
            // All should have 0 instance methods (only default() which is static)
            for r in &results {
                assert_eq!(
                    r.method_count, 0,
                    "Struct {} should have 0 instance methods (default() is static), got {}",
                    r.name, r.method_count
                );
            }
        }
    }

    #[test]
    fn test_rust_analyze_file_cohesion_on_real_file() {
        // Test with a more realistic Rust file that has pub visibility, derives, etc.
        let source = r#"
use std::collections::HashMap;

/// A report structure
#[derive(Debug, Clone)]
pub struct Report {
    pub title: String,
    pub items: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl Report {
    pub fn new(title: String) -> Self {
        Self {
            title,
            items: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_item(&mut self, item: String) {
        self.items.push(item);
    }

    pub fn get_title(&self) -> &str {
        &self.title
    }

    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("report.rs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(
            !results.is_empty(),
            "Expected structs to be found in realistic Rust file"
        );
        let report = results
            .iter()
            .find(|c| c.name == "Report")
            .expect("Expected 'Report' struct to be found");
        // new() is a static method (no self), add_item uses self.items,
        // get_title uses self.title, item_count uses self.items,
        // set_metadata uses self.metadata
        assert!(
            report.method_count >= 4,
            "Expected at least 4 methods, got {}",
            report.method_count
        );
        assert!(
            report.field_count >= 2,
            "Expected at least 2 fields, got {}",
            report.field_count
        );
    }

    // =========================================================================
    // Ruby class extraction tests
    // =========================================================================

    #[test]
    fn test_extract_ruby_classes_basic() {
        let source = r#"
class Dog
  def initialize(name, age)
    @name = name
    @age = age
  end

  def bark
    @name
  end

  def age
    @age
  end
end
"#;
        let tree = parse(source, Language::Ruby).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Ruby);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(classes[0].name, "Dog");
        // initialize, bark, age = 3 methods
        assert_eq!(
            classes[0].methods.len(),
            3,
            "Expected 3 methods, got {:?}",
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_ruby_classes_with_inheritance() {
        let source = r#"
class Animal
  def speak
    @sound
  end
end

class Cat < Animal
  def purr
    @purr_volume
  end
end
"#;
        let tree = parse(source, Language::Ruby).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Ruby);
        assert_eq!(
            classes.len(),
            2,
            "Expected 2 classes, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Animal"),
            "Expected 'Animal' in {:?}",
            names
        );
        assert!(names.contains(&"Cat"), "Expected 'Cat' in {:?}", names);
    }

    #[test]
    fn test_ruby_lcom4_cohesive_class() {
        // All methods access the same field => LCOM4 = 1
        let source = r#"
class Counter
  def initialize
    @count = 0
  end

  def increment
    @count += 1
  end

  def decrement
    @count -= 1
  end

  def value
    @count
  end
end
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("counter.rb");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let counter = results.iter().find(|c| c.name == "Counter").unwrap();
        assert_eq!(
            counter.method_count, 4,
            "Expected 4 methods, got {}",
            counter.method_count
        );
        assert_eq!(
            counter.lcom4, 1,
            "Fully cohesive class should have LCOM4=1, got {}",
            counter.lcom4
        );
    }

    #[test]
    fn test_ruby_lcom4_split_candidate() {
        // Two groups of methods accessing different fields => LCOM4 = 2
        let source = r#"
class Mixed
  def get_name
    @name
  end

  def set_name(n)
    @name = n
  end

  def get_age
    @age
  end

  def set_age(a)
    @age = a
  end
end
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("mixed.rb");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let mixed = results.iter().find(|c| c.name == "Mixed").unwrap();
        assert_eq!(
            mixed.method_count, 4,
            "Expected 4 methods, got {}",
            mixed.method_count
        );
        // name group: {get_name, set_name}, age group: {get_age, set_age}
        assert_eq!(
            mixed.lcom4, 2,
            "Expected LCOM4=2 (two components), got {}",
            mixed.lcom4
        );
    }

    // =========================================================================
    // C# class extraction tests
    // =========================================================================

    #[test]
    fn test_extract_csharp_classes_basic() {
        let source = r#"
class UserService {
    private string name;

    public string GetName() {
        return this.name;
    }

    public void SetName(string n) {
        this.name = n;
    }
}
"#;
        let tree = parse(source, Language::CSharp).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::CSharp);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(classes[0].name, "UserService");
        assert_eq!(
            classes[0].methods.len(),
            2,
            "Expected 2 methods, got {:?}",
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_csharp_classes_multiple() {
        let source = r#"
class First {
    public void DoA() {}
}

class Second {
    public void DoB() {}
}
"#;
        let tree = parse(source, Language::CSharp).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::CSharp);
        assert_eq!(
            classes.len(),
            2,
            "Expected 2 classes, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"First"), "Expected 'First' in {:?}", names);
        assert!(
            names.contains(&"Second"),
            "Expected 'Second' in {:?}",
            names
        );
    }

    #[test]
    fn test_csharp_lcom4_cohesive_class() {
        let source = r#"
class Counter {
    private int count;

    public void Increment() {
        this.count += 1;
    }

    public void Decrement() {
        this.count -= 1;
    }

    public int GetValue() {
        return this.count;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("counter.cs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let counter = results.iter().find(|c| c.name == "Counter").unwrap();
        assert_eq!(
            counter.method_count, 3,
            "Expected 3 methods, got {}",
            counter.method_count
        );
        assert_eq!(
            counter.lcom4, 1,
            "Fully cohesive class should have LCOM4=1, got {}",
            counter.lcom4
        );
    }

    #[test]
    fn test_csharp_lcom4_split_candidate() {
        let source = r#"
class Mixed {
    private string name;
    private int age;

    public string GetName() {
        return this.name;
    }

    public void SetName(string n) {
        this.name = n;
    }

    public int GetAge() {
        return this.age;
    }

    public void SetAge(int a) {
        this.age = a;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("mixed.cs");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let mixed = results.iter().find(|c| c.name == "Mixed").unwrap();
        assert_eq!(
            mixed.method_count, 4,
            "Expected 4 methods, got {}",
            mixed.method_count
        );
        assert_eq!(
            mixed.lcom4, 2,
            "Expected LCOM4=2 (two components), got {}",
            mixed.lcom4
        );
    }

    // =========================================================================
    // Scala class extraction tests
    // =========================================================================

    #[test]
    fn test_extract_scala_classes_basic() {
        let source = r#"
class UserService {
  def getName(): String = {
    this.name
  }

  def setName(n: String): Unit = {
    this.name = n
  }
}
"#;
        let tree = parse(source, Language::Scala).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Scala);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(classes[0].name, "UserService");
        assert_eq!(
            classes[0].methods.len(),
            2,
            "Expected 2 methods, got {:?}",
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_scala_object_and_trait() {
        let source = r#"
object Config {
  def getValue(): String = {
    this.value
  }
}

trait Describable {
  def describe(): String
}
"#;
        let tree = parse(source, Language::Scala).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Scala);
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Config"),
            "Expected 'Config' object in {:?}",
            names
        );
        assert!(
            names.contains(&"Describable"),
            "Expected 'Describable' trait in {:?}",
            names
        );
    }

    #[test]
    fn test_scala_lcom4_cohesive_class() {
        let source = r#"
class Counter {
  def increment(): Unit = {
    this.count += 1
  }

  def decrement(): Unit = {
    this.count -= 1
  }

  def getValue(): Int = {
    this.count
  }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("counter.scala");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let counter = results.iter().find(|c| c.name == "Counter").unwrap();
        assert_eq!(
            counter.method_count, 3,
            "Expected 3 methods, got {}",
            counter.method_count
        );
        assert_eq!(
            counter.lcom4, 1,
            "Fully cohesive class should have LCOM4=1, got {}",
            counter.lcom4
        );
    }

    #[test]
    fn test_scala_lcom4_split_candidate() {
        let source = r#"
class Mixed {
  def getName(): String = {
    this.name
  }

  def setName(n: String): Unit = {
    this.name = n
  }

  def getAge(): Int = {
    this.age
  }

  def setAge(a: Int): Unit = {
    this.age = a
  }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("mixed.scala");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let mixed = results.iter().find(|c| c.name == "Mixed").unwrap();
        assert_eq!(
            mixed.method_count, 4,
            "Expected 4 methods, got {}",
            mixed.method_count
        );
        assert_eq!(
            mixed.lcom4, 2,
            "Expected LCOM4=2 (two components), got {}",
            mixed.lcom4
        );
    }

    // =========================================================================
    // PHP class extraction tests
    // =========================================================================

    #[test]
    fn test_extract_php_classes_basic() {
        let source = r#"<?php
class UserService {
    private $name;

    public function getName() {
        return $this->name;
    }

    public function setName($n) {
        $this->name = $n;
    }
}
"#;
        let tree = parse(source, Language::Php).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Php);
        assert_eq!(
            classes.len(),
            1,
            "Expected 1 class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(classes[0].name, "UserService");
        assert_eq!(
            classes[0].methods.len(),
            2,
            "Expected 2 methods, got {:?}",
            classes[0]
                .methods
                .iter()
                .map(|m| &m.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_php_classes_multiple() {
        let source = r#"<?php
class First {
    public function doA() {}
}

class Second {
    public function doB() {}
}
"#;
        let tree = parse(source, Language::Php).unwrap();
        let classes = extract_classes(tree.root_node(), source, Language::Php);
        assert_eq!(
            classes.len(),
            2,
            "Expected 2 classes, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"First"), "Expected 'First' in {:?}", names);
        assert!(
            names.contains(&"Second"),
            "Expected 'Second' in {:?}",
            names
        );
    }

    #[test]
    fn test_php_lcom4_cohesive_class() {
        let source = r#"<?php
class Counter {
    private $count;

    public function increment() {
        $this->count += 1;
    }

    public function decrement() {
        $this->count -= 1;
    }

    public function getValue() {
        return $this->count;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("counter.php");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let counter = results.iter().find(|c| c.name == "Counter").unwrap();
        assert_eq!(
            counter.method_count, 3,
            "Expected 3 methods, got {}",
            counter.method_count
        );
        assert_eq!(
            counter.lcom4, 1,
            "Fully cohesive class should have LCOM4=1, got {}",
            counter.lcom4
        );
    }

    #[test]
    fn test_php_lcom4_split_candidate() {
        let source = r#"<?php
class Mixed {
    private $name;
    private $age;

    public function getName() {
        return $this->name;
    }

    public function setName($n) {
        $this->name = $n;
    }

    public function getAge() {
        return $this->age;
    }

    public function setAge($a) {
        $this->age = $a;
    }
}
"#;
        let test_dir = tempfile::tempdir().unwrap();
        let file_path = test_dir.path().join("mixed.php");
        std::fs::write(&file_path, source).unwrap();

        let options = CohesionOptions::default();
        let results = analyze_file_cohesion(&file_path, &options).unwrap();
        assert!(!results.is_empty(), "Expected at least 1 class in results");
        let mixed = results.iter().find(|c| c.name == "Mixed").unwrap();
        assert_eq!(
            mixed.method_count, 4,
            "Expected 4 methods, got {}",
            mixed.method_count
        );
        assert_eq!(
            mixed.lcom4, 2,
            "Expected LCOM4=2 (two components), got {}",
            mixed.lcom4
        );
    }

    #[test]
    fn test_extract_ruby_instance_var_no_panic() {
        // The regex must not panic (lookbehinds are unsupported in the regex crate).
        let source = "@name = 'Alice'\n@@class_var = 1\n@age = 30";
        let fields = extract_ruby_instance_var_accesses(source);
        assert!(fields.contains("name"), "Expected 'name' in {:?}", fields);
        assert!(fields.contains("age"), "Expected 'age' in {:?}", fields);
        // @@class_var should NOT produce a match for "class_var" as an instance var
        assert!(
            !fields.contains("class_var"),
            "@@class_var should not be matched as instance var, got {:?}",
            fields
        );
    }

    #[test]
    fn test_extract_ruby_instance_var_inline() {
        // Instance variable in expressions
        let source = "puts @value + @@counter";
        let fields = extract_ruby_instance_var_accesses(source);
        assert!(fields.contains("value"), "Expected 'value' in {:?}", fields);
        assert!(
            !fields.contains("counter"),
            "@@counter should not match as instance var, got {:?}",
            fields
        );
    }
}
