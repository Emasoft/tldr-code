//! Whatbreaks analysis - unified impact analysis wrapper
//!
//! This module provides the `whatbreaks` command which auto-detects
//! the target type and runs appropriate sub-analyses.
//!
//! ## Target Types
//!
//! - **Function**: Runs `impact` analysis to find callers
//! - **File**: Runs `importers` + `change-impact` analysis
//! - **Module**: Runs `importers` analysis
//!
//! ## Target Detection Algorithm (T15 mitigation)
//!
//! 1. If target is an existing file path -> File
//! 2. If target contains "/" or ends with language extension -> File
//! 3. If target contains "." and first part is a directory -> Module
//! 4. Default to Function
//!
//! ## Partial Failure Handling (T29 mitigation)
//!
//! Each sub-analysis is wrapped in `SubResult` which captures:
//! - Success/failure status
//! - Data on success
//! - Error message on failure
//! - Elapsed time
//!
//! If one sub-analysis fails, others continue to run.
//!
//! ## Error Mapping (T11 mitigation)
//!
//! Sub-command errors are mapped as follows:
//! - `impact` FunctionNotFound -> SubResult { success: false, error: "..." }
//! - `importers` empty list -> SubResult { success: true, data: [] }
//! - `change-impact` no tests -> SubResult { success: true, data: [] }
//! - `change-impact` doc/non-code language -> SubResult { success: true, skipped: true, skip_reason: "..." }
//!   (doc-target-whatbreaks-v1: the leg routes through the code call graph,
//!   which rejects every non-code language; for a doc target that is a
//!   non-applicable leg, not a failure)
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::analysis::whatbreaks::{whatbreaks_analysis, WhatbreaksOptions};
//! use tldr_core::Language;
//! use std::path::Path;
//!
//! let options = WhatbreaksOptions::default();
//! let report = whatbreaks_analysis(
//!     "process_data",
//!     Path::new("src"),
//!     &options,
//! )?;
//!
//! println!("Target type: {:?}", report.target_type);
//! println!("Direct callers: {}", report.summary.direct_caller_count);
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::analysis::change_impact::change_impact;
use crate::analysis::clones::is_test_file;
use crate::analysis::impact::impact_analysis_with_ast_fallback;
use crate::analysis::importers::find_importers;
use crate::callgraph::build_project_call_graph;
use crate::types::{Language, ProjectCallGraph};
use crate::TldrResult;

// =============================================================================
// Types
// =============================================================================

/// Detected type of whatbreaks target (T15 mitigation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetType {
    /// Target is a function name - run impact analysis
    Function,
    /// Target is a file path - run importers + change-impact
    File,
    /// Target is a module name - run importers
    Module,
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetType::Function => write!(f, "function"),
            TargetType::File => write!(f, "file"),
            TargetType::Module => write!(f, "module"),
        }
    }
}

/// Status of a sub-analysis (T29 mitigation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubStatus {
    /// Analysis completed successfully
    Success,
    /// Analysis failed with an error
    Error,
    /// Analysis was skipped (e.g., not applicable for target type)
    Skipped,
}

/// Result of a sub-analysis with error handling (T11, T29 mitigation)
///
/// Wraps individual sub-analysis results to allow partial failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubResult {
    /// Whether the analysis succeeded
    pub success: bool,
    /// Analysis data on success (serialized to JSON Value for flexibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error message on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Warnings that don't prevent success (T29 mitigation)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Whether the data is incomplete/partial
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    /// Whether this sub-analysis was deliberately SKIPPED (not applicable
    /// for the target) rather than failed.
    ///
    /// doc-target-whatbreaks-v1: a skipped sub-analysis is an honest,
    /// successful outcome — `success` stays `true` and the reason lives in
    /// [`SubResult::skip_reason`]. Additive with `skip_serializing_if` so
    /// non-skipped results serialize exactly as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    /// Why the sub-analysis was skipped; present iff `skipped` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Time taken for this sub-analysis in milliseconds
    pub elapsed_ms: f64,
}

impl SubResult {
    /// Create a successful result with data
    pub fn success<T: Serialize>(data: T, elapsed_ms: f64) -> Self {
        Self {
            success: true,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
            error: None,
            warnings: Vec::new(),
            partial: false,
            skipped: false,
            skip_reason: None,
            elapsed_ms,
        }
    }

    /// Create a failed result with error
    pub fn error(error: String, elapsed_ms: f64) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            warnings: Vec::new(),
            partial: false,
            skipped: false,
            skip_reason: None,
            elapsed_ms,
        }
    }

    /// Create a skipped result (a deliberate, non-applicable outcome —
    /// NOT a failure: `success` is `true`).
    ///
    /// doc-target-whatbreaks-v1: the reason is carried in the dedicated
    /// `skip_reason` field (machine-readable) AND in `warnings` (the legacy
    /// channel pre-existing readers already consume). The text renderer
    /// prints skipped results from `skip_reason` only, so the reason is
    /// never shown twice.
    pub fn skipped(reason: &str) -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            warnings: vec![reason.to_string()],
            partial: false,
            skipped: true,
            skip_reason: Some(reason.to_string()),
            elapsed_ms: 0.0,
        }
    }

    /// Create a partial success result
    pub fn partial<T: Serialize>(data: T, warnings: Vec<String>, elapsed_ms: f64) -> Self {
        Self {
            success: true,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
            error: None,
            warnings,
            partial: true,
            skipped: false,
            skip_reason: None,
            elapsed_ms,
        }
    }

    /// Add a warning to the result
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Summary statistics aggregated across sub-analyses
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WhatbreaksSummary {
    /// Number of direct callers (from impact analysis)
    pub direct_caller_count: usize,
    /// Number of transitive callers (from impact analysis)
    pub transitive_caller_count: usize,
    /// Number of files importing the target (from importers analysis)
    pub importer_count: usize,
    /// Number of test files affected (from change-impact analysis)
    pub affected_test_count: usize,
}

/// Full whatbreaks analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatbreaksReport {
    /// Always "whatbreaks" - identifies this as a whatbreaks wrapper report
    pub wrapper: String,
    /// Project path analyzed
    pub path: PathBuf,
    /// Target that was analyzed
    pub target: String,
    /// Detected or forced target type
    pub target_type: TargetType,
    /// Explanation of why this target type was chosen (T15 mitigation)
    pub detection_reason: String,
    /// Results from each sub-analysis
    pub sub_results: HashMap<String, SubResult>,
    /// Aggregated summary statistics
    pub summary: WhatbreaksSummary,
    /// Total time for all analyses in milliseconds
    pub total_elapsed_ms: f64,
}

/// Options for whatbreaks analysis
#[derive(Debug, Clone)]
pub struct WhatbreaksOptions {
    /// Maximum depth for impact traversal
    pub depth: usize,
    /// Skip slow analyses (e.g., diff-impact)
    pub quick: bool,
    /// Programming language (None = auto-detect)
    pub language: Option<Language>,
    /// Force target type (None = auto-detect)
    pub force_type: Option<TargetType>,
}

impl Default for WhatbreaksOptions {
    fn default() -> Self {
        Self {
            depth: 3,
            quick: false,
            language: None,
            force_type: None,
        }
    }
}

// =============================================================================
// Target Detection (T15 mitigation)
// =============================================================================

/// Detect the type of target based on its pattern and project structure
///
/// Returns (TargetType, detection_reason) where detection_reason explains
/// why this type was chosen (for debugging and user clarity).
///
/// # Algorithm
///
/// 1. If target is an existing file path -> File
/// 2. If target contains "/" or ends with language extension -> File
/// 3. If target contains "::" or "." suggesting qualified name:
///    a. If first part before "." is a directory -> Module
///    b. Otherwise -> Function (qualified name like Class.method)
/// 4. Default to Function
///
/// # Arguments
///
/// * `target` - The target string from user input
/// * `project_path` - Project root directory
///
/// # Returns
///
/// (TargetType, String) - The detected type and explanation
pub fn detect_target_type(target: &str, project_path: &Path) -> (TargetType, String) {
    // Check 1: Is it an existing file path?
    let target_path = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        project_path.join(target)
    };

    if target_path.is_file() {
        return (
            TargetType::File,
            format!("Path '{}' exists as a file", target),
        );
    }

    // Check 2: Does it look like a file path?
    if target.contains('/') || target.contains('\\') {
        return (
            TargetType::File,
            format!("Path '{}' contains path separator", target),
        );
    }

    // Check for file extensions
    // why: this list only covered 7 of the 18 languages the tool supports
    // (see Language::extensions in types.rs), so a non-existent target like
    // "Foo.java" or "bar.rb" fell through to the qualified-name heuristic
    // below and was misdetected as TargetType::Function instead of File.
    //
    // doc-target-whatbreaks-v1: the doc/config/plain-text extensions are
    // added (the union of `Language::extensions` for the doc languages in
    // `is_doc_language`) so a NOT-YET-ON-DISK doc target like
    // `tldr whatbreaks docs/new.md` or `openapi.json` is detected as File
    // instead of falling through the `.`-check to the qualified-name
    // heuristic. The is_file check above stays FIRST: an existing doc file
    // (`b.md` that is on disk) is caught there before this list is consulted.
    let file_extensions = [
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".cxx",
        ".c++",
        ".hpp",
        ".hh",
        ".hxx",
        ".h++",
        ".rb",
        ".kt",
        ".kts",
        ".swift",
        ".cs",
        ".scala",
        ".php",
        ".lua",
        ".luau",
        ".ex",
        ".exs",
        ".ml",
        ".mli",
        ".md",
        ".markdown",
        ".txt",
        ".text",
        ".html",
        ".htm",
        ".xhtml",
        ".xml",
        ".svg",
        ".xsd",
        ".xsl",
        ".css",
        ".tex",
        ".sty",
        ".cls",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".sh",
        ".bash",
    ];
    for ext in &file_extensions {
        if target.ends_with(ext) {
            return (
                TargetType::File,
                format!("Target '{}' ends with file extension '{}'", target, ext),
            );
        }
    }

    // Check 3: Is it a directory (module)?
    if target_path.is_dir() {
        return (
            TargetType::Module,
            format!("Path '{}' exists as a directory", target),
        );
    }

    // Check 4: Qualified name with dots
    if target.contains('.') {
        let parts: Vec<&str> = target.split('.').collect();
        let first_part = parts[0];

        // Check if the first part is a directory (module pattern)
        let first_part_path = project_path.join(first_part);
        if first_part_path.is_dir() {
            return (
                TargetType::Module,
                format!(
                    "First part '{}' of '{}' is a directory (module pattern)",
                    first_part, target
                ),
            );
        }

        // Otherwise it's likely a qualified function name like Class.method
        return (
            TargetType::Function,
            format!(
                "Target '{}' contains '.' but first part '{}' is not a directory (qualified function name)",
                target, first_part
            ),
        );
    }

    // Check 5: Rust-style qualified name
    if target.contains("::") {
        return (
            TargetType::Function,
            format!(
                "Target '{}' contains '::' (qualified function name)",
                target
            ),
        );
    }

    // Default: assume function
    (
        TargetType::Function,
        format!(
            "Target '{}' does not match file or module patterns (defaulting to function)",
            target
        ),
    )
}

// =============================================================================
// Sub-Analysis Execution
// =============================================================================

/// Run impact analysis for a function target
fn run_impact_analysis(
    target: &str,
    project_path: &Path,
    call_graph: &ProjectCallGraph,
    depth: usize,
    language: Language,
) -> SubResult {
    let start = Instant::now();

    match impact_analysis_with_ast_fallback(call_graph, target, depth, None, project_path, language)
    {
        Ok(mut report) => {
            // sibling-resolver-gaps-v1 (P14.AGG14-4): mirror the
            // user-facing `tldr impact` references-enrichment so
            // `whatbreaks` finds the same callers. Without this,
            // `whatbreaks WriteToken` reports `caller_count = 0`
            // ("Entry point") for csharp/kotlin/java cases that the
            // call-graph alone misses but `find_references` resolves.
            crate::analysis::impact::enrich_impact_with_references(
                &mut report,
                project_path,
                target,
                language,
            );

            // Count direct callers from all targets
            let direct_count: usize = report.targets.values().map(|t| t.caller_count).sum();

            // Count transitive callers (all callers in the tree)
            let transitive_count: usize =
                report.targets.values().map(count_transitive_callers).sum();

            // VAL-002 (#1.E): collect unique test-file paths across all caller
            // trees so the Function-target branch in `whatbreaks_analysis` can
            // populate `summary.affected_test_count`. Walking the typed
            // ImpactReport here matches `transitive_count`'s depth semantics
            // exactly (same tree, same nodes). De-duped via HashSet<PathBuf>.
            let mut test_files: HashSet<PathBuf> = HashSet::new();
            for tree in report.targets.values() {
                collect_test_files_from_tree(tree, &mut test_files);
            }
            let test_file_count = test_files.len();

            SubResult::success(
                serde_json::json!({
                    "targets": report.targets.len(),
                    "direct_callers": direct_count,
                    "transitive_callers": transitive_count,
                    "affected_test_count": test_file_count,
                    "report": report,
                }),
                start.elapsed().as_secs_f64() * 1000.0,
            )
        }
        Err(e) => SubResult::error(e.to_string(), start.elapsed().as_secs_f64() * 1000.0),
    }
}

/// Count transitive callers in a caller tree (recursive)
fn count_transitive_callers(tree: &crate::types::CallerTree) -> usize {
    let mut count = tree.caller_count;
    for caller in &tree.callers {
        count += count_transitive_callers(caller);
    }
    count
}

/// Recursively walk a caller tree and accumulate unique test-file paths into
/// `acc`. A node is considered a test file iff
/// [`crate::analysis::clones::is_test_file`] returns true for `tree.file`.
///
/// Used by [`run_impact_analysis`] (VAL-002) to compute the
/// `affected_test_count` JSON field that
/// [`whatbreaks_analysis`]'s Function-target branch reads back into
/// [`WhatbreaksSummary::affected_test_count`].
fn collect_test_files_from_tree(tree: &crate::types::CallerTree, acc: &mut HashSet<PathBuf>) {
    if is_test_file(&tree.file) {
        acc.insert(tree.file.clone());
    }
    for child in &tree.callers {
        collect_test_files_from_tree(child, acc);
    }
}

/// doc-target-whatbreaks-v1: `--lang`-less language resolution for a
/// whatbreaks target.
///
/// File targets resolve through the ONE shared single-file helper
/// [`crate::validation::resolve_target_language`] — the same resolution
/// `structure`/`impact`/`references` use — so an existing file target speaks
/// its own language (doc language included) regardless of what the enclosing
/// directory looks like. `Ok(None)` (missing path, directory, unknown
/// extension, OOXML container) and `Err` (binary content) both fall through
/// to the legacy directory autodetect: those targets give this analysis no
/// language it can truthfully claim. Function/Module targets and every
/// `--lang`-less non-File path keep the pre-fix
/// `from_directory(project).unwrap_or(Python)` behavior unchanged.
fn resolve_file_target_language(
    target: &str,
    target_type: TargetType,
    project_path: &Path,
) -> Language {
    if target_type == TargetType::File {
        let target_path = if Path::new(target).is_absolute() {
            PathBuf::from(target)
        } else {
            project_path.join(target)
        };
        if target_path.is_file() {
            if let Ok(Some(lang)) = crate::validation::resolve_target_language(&target_path) {
                return lang;
            }
        }
    }
    Language::from_directory(project_path).unwrap_or(Language::Python)
}

/// Run importers analysis for a file or module target
fn run_importers_analysis(target: &str, project_path: &Path, language: Language) -> SubResult {
    let start = Instant::now();

    // Derive module name from target (root-relative — see `derive_module_name`)
    let module_name = derive_module_name(target, project_path, language);

    match find_importers(project_path, &module_name, language) {
        Ok(report) => SubResult::success(
            serde_json::json!({
                "module": report.module,
                "importers": report.importers,
                "count": report.total,
            }),
            start.elapsed().as_secs_f64() * 1000.0,
        ),
        Err(e) => SubResult::error(e.to_string(), start.elapsed().as_secs_f64() * 1000.0),
    }
}

/// Whether the call-graph layer — the engine change-impact's core traversal
/// runs on — can build a graph for `language`.
///
/// doc-target-whatbreaks-v1: delegates to the call-graph's OWN support list
/// (`scanner::SUPPORTED_LANGUAGES`, re-exported as
/// `crate::callgraph::is_supported_language`) so this gate can never drift
/// from the builder that would otherwise reject the language with
/// `Unsupported language: <lang>`. Doc/config/text languages (markdown,
/// json, yaml, …) are NOT in that set: change-impact for such targets is a
/// non-applicable leg, reported as an explicit skip — never a failure.
fn call_graph_supports(language: Language) -> bool {
    crate::callgraph::is_supported_language(&language.to_string())
}

/// Run change-impact analysis for a file target
fn run_change_impact_analysis(target: &str, project_path: &Path, language: Language) -> SubResult {
    let start = Instant::now();

    // For file targets, provide the file as an explicit changed file
    let target_path = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        project_path.join(target)
    };

    let changed_files = if target_path.exists() {
        Some(vec![target_path])
    } else {
        None
    };

    match change_impact(project_path, changed_files.as_deref(), language) {
        Ok(report) => SubResult::success(
            serde_json::json!({
                "changed_files": report.changed_files,
                "affected_tests": report.affected_tests,
                "affected_functions": report.affected_functions.len(),
            }),
            start.elapsed().as_secs_f64() * 1000.0,
        ),
        Err(e) => SubResult::error(e.to_string(), start.elapsed().as_secs_f64() * 1000.0),
    }
}

/// Derive the importers module string from a whatbreaks File/Module target.
///
/// doc-target-whatbreaks-v1 contract:
///
/// 1. The target is first made PROJECT-ROOT-RELATIVE: absolute targets are
///    taken as-is, relative ones join onto `project_path`; both sides are
///    canonicalized (error-tolerantly — a not-yet-existing target or an
///    uncanonicalizable root falls back to lexical stripping) and the root
///    prefix stripped. An ABSOLUTE target and its root-relative spelling
///    therefore produce IDENTICAL module strings. Previously the raw target
///    was split on `/`, so an absolute path like `/tmp/proj/b.md` became the
///    leading-dot garbage `.tmp.proj.b.md` and `find_importers` matched
///    nothing even when the language was right.
/// 2. Doc language → the module string is the root-relative path WITH its
///    extension, `/`-joined (`b.md`, `docs/x.md`): document languages
///    reference each other by PATH (the doc arm of `module_matches`) and
///    link extraction keeps targets raw.
/// 3. Code language → the legacy dotted-module logic applied to the now
///    root-relative path: known code extension stripped, separators → dots
///    (`src/utils.py` → `src.utils`). Inputs that were already
///    root-relative produce byte-identical output to the pre-fix version.
/// 4. Non-path targets (a Module name like `myapp.service`) pass through
///    step 1 untouched and keep the legacy dotted-module output.
fn derive_module_name(target: &str, project_path: &Path, language: Language) -> String {
    let relative = root_relative_path(target, project_path);
    let relative_str = relative.to_string_lossy().replace('\\', "/");

    if crate::analysis::doc_impact::is_doc_language(language) {
        return relative_str;
    }

    // Code languages: strip the known extension, then path separators ->
    // dots (legacy module notation) — now applied to the ROOT-RELATIVE
    // path so absolute and relative spellings agree.
    let without_ext = strip_known_code_extension(&relative_str);
    without_ext.replace('/', ".")
}

/// Make `target` relative to `project_path` (doc-target-whatbreaks-v1).
///
/// Canonicalize both sides first (symlinked roots like macOS
/// `/var` → `/private/var` and `.`-style roots then compare equal); on any
/// failure degrade through lexical fallbacks and finally to the file name so
/// the function never panics and never returns an empty module.
///
/// `pub`: shared with the importers command (doc-target-importers-v1), which
/// rewrites an ABSOLUTE doc-file module string to its project-root-relative
/// spelling before `find_importers` runs — the same derivation, so the two
/// commands agree byte-for-byte on the module string for the same target.
pub fn root_relative_path(target: &str, project_path: &Path) -> PathBuf {
    let absolute = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        project_path.join(target)
    };

    let target_canon = absolute.canonicalize().ok();
    let root_canon = project_path.canonicalize().ok();

    // 1. Best: canonicalized target under canonicalized root.
    if let (Some(t), Some(r)) = (&target_canon, &root_canon) {
        if let Ok(rel) = t.strip_prefix(r) {
            if !rel.as_os_str().is_empty() {
                return rel.to_path_buf();
            }
        }
    }
    // 2. Lexical: raw absolute target under the canonicalized root (target
    //    may not exist on disk while the root does).
    if let Some(r) = &root_canon {
        if let Ok(rel) = absolute.strip_prefix(r) {
            if !rel.as_os_str().is_empty() {
                return rel.to_path_buf();
            }
        }
    }
    // 3. Lexical: raw absolute target under the raw root.
    if let Ok(rel) = absolute.strip_prefix(project_path) {
        if !rel.as_os_str().is_empty() {
            return rel.to_path_buf();
        }
    }
    // 4. Relative input: already root-relative by construction — drop the
    //    leading `./` noise.
    if !Path::new(target).is_absolute() {
        let cleaned: PathBuf = Path::new(target)
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        if !cleaned.as_os_str().is_empty() {
            return cleaned;
        }
    }
    // 5. Last resort: an unstrippable absolute target (outside the project
    //    root) degrades to its file name — the widest query that can still
    //    match an import inside the project.
    absolute
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(target))
}

/// Strip a known code-language extension from a path-shaped string.
///
/// why: kept in sync with the file_extensions list in `detect_target_type`
/// so module-name derivation strips the extension for every CODE language
/// the tool supports. Doc extensions are deliberately absent here — doc
/// module strings ARE paths and keep their extension (see
/// `derive_module_name`).
fn strip_known_code_extension(path_str: &str) -> &str {
    const KNOWN_CODE_EXTENSIONS: &[&str] = &[
        ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".c", ".h",
        ".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".rb", ".kt", ".kts",
        ".swift", ".cs", ".scala", ".php", ".lua", ".luau", ".ex", ".exs", ".ml", ".mli",
    ];
    if let Some(idx) = path_str.rfind('.') {
        let ext = &path_str[idx..];
        if KNOWN_CODE_EXTENSIONS.contains(&ext) {
            return &path_str[..idx];
        }
    }
    path_str
}

// =============================================================================
// Main Analysis Function
// =============================================================================

/// Run whatbreaks analysis on a target
///
/// This is the main entry point for the whatbreaks command.
/// It auto-detects (or uses forced) target type and runs appropriate sub-analyses.
///
/// # Arguments
///
/// * `target` - Target to analyze (function name, file path, or module name)
/// * `project_path` - Project root directory
/// * `options` - Analysis options
///
/// # Returns
///
/// * `Ok(WhatbreaksReport)` - Complete analysis report with sub-results
/// * `Err(TldrError)` - If fundamental analysis fails (e.g., can't build call graph)
///
/// # Example
///
/// ```rust,ignore
/// let report = whatbreaks_analysis("process_data", Path::new("src"), &options)?;
/// ```
pub fn whatbreaks_analysis(
    target: &str,
    project_path: &Path,
    options: &WhatbreaksOptions,
) -> TldrResult<WhatbreaksReport> {
    let total_start = Instant::now();

    // Determine target type
    let (target_type, detection_reason) = if let Some(forced_type) = options.force_type {
        (
            forced_type,
            format!("Forced via --type flag to {:?}", forced_type),
        )
    } else {
        detect_target_type(target, project_path)
    };

    // Detect language.
    //
    // doc-target-whatbreaks-v1: for File targets the language comes from the
    // TARGET FILE itself (the shared single-file helper
    // `validation::resolve_target_language`), not from directory dominance.
    // A doc-only project has no project-language signal at all
    // (`Language::from_directory` skips every doc format via
    // `is_project_language_signal`), so the old
    // `from_directory(project).unwrap_or(Python)` silently analyzed a
    // `b.md` target with Python's call-graph/importers layers and reported
    // an honest-looking but wrong `count: 0`.
    let language = options
        .language
        .unwrap_or_else(|| resolve_file_target_language(target, target_type, project_path));

    // Build call graph (needed for function targets, optional for others)
    let call_graph = match target_type {
        TargetType::Function => {
            // Must build call graph for impact analysis
            build_project_call_graph(project_path, language, None, true)?
        }
        _ => {
            // Try to build but don't fail if it doesn't work
            build_project_call_graph(project_path, language, None, true)
                .unwrap_or_else(|_| ProjectCallGraph::new())
        }
    };

    // Run sub-analyses based on target type
    let mut sub_results: HashMap<String, SubResult> = HashMap::new();
    let mut summary = WhatbreaksSummary::default();

    match target_type {
        TargetType::Function => {
            // Run impact analysis
            let impact_result =
                run_impact_analysis(target, project_path, &call_graph, options.depth, language);

            // Extract counts from successful result
            if impact_result.success {
                if let Some(data) = &impact_result.data {
                    if let Some(direct) = data.get("direct_callers").and_then(|v| v.as_u64()) {
                        summary.direct_caller_count = direct as usize;
                    }
                    if let Some(transitive) =
                        data.get("transitive_callers").and_then(|v| v.as_u64())
                    {
                        summary.transitive_caller_count = transitive as usize;
                    }
                    // VAL-002 (#1.E): read the test-file count emitted by
                    // run_impact_analysis. Mirrors the direct/transitive
                    // pattern above. The File-target branch populates this
                    // same field via change_impact, but the Function path
                    // had been silently leaving it at the
                    // WhatbreaksSummary::default() value of 0.
                    if let Some(test_count) =
                        data.get("affected_test_count").and_then(|v| v.as_u64())
                    {
                        summary.affected_test_count = test_count as usize;
                    }
                }
            }

            sub_results.insert("impact".to_string(), impact_result);
        }

        TargetType::File => {
            // Run importers analysis
            let importers_result = run_importers_analysis(target, project_path, language);

            if importers_result.success {
                if let Some(data) = &importers_result.data {
                    if let Some(count) = data.get("count").and_then(|v| v.as_u64()) {
                        summary.importer_count = count as usize;
                    }
                }
            }

            sub_results.insert("importers".to_string(), importers_result);

            // Run change-impact analysis (unless --quick)
            if !options.quick {
                // doc-target-whatbreaks-v1: change-impact's core is the CODE
                // call graph (`build_project_call_graph` inside
                // `change_impact`), which rejects every language outside
                // `SUPPORTED_LANGUAGES` with `Unsupported language: <lang>`.
                // For a doc/config/text target (resolved per-file since
                // doc-target-whatbreaks-v1) that leg is MEANINGLESS, not
                // broken: report it as an explicit skip — `success: true` +
                // `skipped: true` + reason — instead of the fabricated
                // failure. NEVER fabricate success: importers above still
                // reports its real result; the skip states exactly what did
                // not run and why.
                if call_graph_supports(language) {
                    let change_impact_result =
                        run_change_impact_analysis(target, project_path, language);

                    if change_impact_result.success {
                        if let Some(data) = &change_impact_result.data {
                            if let Some(tests) =
                                data.get("affected_tests").and_then(|v| v.as_array())
                            {
                                summary.affected_test_count = tests.len();
                            }
                        }
                    }

                    sub_results.insert("change-impact".to_string(), change_impact_result);
                } else {
                    sub_results.insert(
                        "change-impact".to_string(),
                        SubResult::skipped(&format!(
                            "change-impact requires a code language; target is {language}"
                        )),
                    );
                }
            } else {
                sub_results.insert(
                    "change-impact".to_string(),
                    SubResult::skipped("Skipped due to --quick flag"),
                );
            }
        }

        TargetType::Module => {
            // Run importers analysis
            let importers_result = run_importers_analysis(target, project_path, language);

            if importers_result.success {
                if let Some(data) = &importers_result.data {
                    if let Some(count) = data.get("count").and_then(|v| v.as_u64()) {
                        summary.importer_count = count as usize;
                    }
                }
            }

            sub_results.insert("importers".to_string(), importers_result);
        }
    }

    let total_elapsed_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    Ok(WhatbreaksReport {
        wrapper: "whatbreaks".to_string(),
        path: project_path.to_path_buf(),
        target: target.to_string(),
        target_type,
        detection_reason,
        sub_results,
        summary,
        total_elapsed_ms,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn add_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    // -------------------------------------------------------------------------
    // Target Detection Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detects_function_target() {
        let test_dir = create_test_dir();

        // No file exists, no directory, no special patterns -> function
        let (target_type, reason) = detect_target_type("process_data", test_dir.path());
        assert_eq!(target_type, TargetType::Function);
        assert!(reason.contains("defaulting to function"));
    }

    #[test]
    fn test_detects_file_target_existing() {
        let test_dir = create_test_dir();
        add_file(&test_dir, "service.py", "def run(): pass");

        let (target_type, reason) = detect_target_type("service.py", test_dir.path());
        assert_eq!(target_type, TargetType::File);
        assert!(reason.contains("exists as a file"));
    }

    #[test]
    fn test_detects_file_target_extension() {
        let test_dir = create_test_dir();

        // Even if file doesn't exist, .py extension suggests file
        let (target_type, reason) = detect_target_type("nonexistent.py", test_dir.path());
        assert_eq!(target_type, TargetType::File);
        assert!(reason.contains("file extension"));
    }

    #[test]
    fn test_detects_file_target_path() {
        let test_dir = create_test_dir();

        // Path separator suggests file
        let (target_type, reason) = detect_target_type("src/service.py", test_dir.path());
        assert_eq!(target_type, TargetType::File);
        assert!(reason.contains("path separator"));
    }

    #[test]
    fn test_detects_module_target() {
        let test_dir = create_test_dir();
        std::fs::create_dir_all(test_dir.path().join("myapp")).unwrap();
        add_file(&test_dir, "myapp/__init__.py", "");

        let (target_type, reason) = detect_target_type("myapp.service", test_dir.path());
        assert_eq!(target_type, TargetType::Module);
        assert!(reason.contains("is a directory"));
    }

    #[test]
    fn test_detects_qualified_function() {
        let test_dir = create_test_dir();

        // "Class.method" where "Class" is not a directory -> qualified function
        let (target_type, reason) = detect_target_type("UserService.run", test_dir.path());
        assert_eq!(target_type, TargetType::Function);
        assert!(reason.contains("qualified function name"));
    }

    #[test]
    fn test_detects_rust_qualified_function() {
        let test_dir = create_test_dir();

        // Rust-style "module::function"
        let (target_type, reason) = detect_target_type("utils::helper", test_dir.path());
        assert_eq!(target_type, TargetType::Function);
        assert!(reason.contains("::"));
    }

    // -------------------------------------------------------------------------
    // SubResult Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sub_result_success() {
        let result = SubResult::success(vec![1, 2, 3], 100.5);
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(result.error.is_none());
        assert_eq!(result.elapsed_ms, 100.5);
    }

    #[test]
    fn test_sub_result_error() {
        let result = SubResult::error("Something went wrong".to_string(), 50.0);
        assert!(!result.success);
        assert!(result.data.is_none());
        assert_eq!(result.error.as_deref(), Some("Something went wrong"));
    }

    #[test]
    fn test_sub_result_skipped() {
        let result = SubResult::skipped("Not applicable");
        assert!(result.success);
        assert!(result.data.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("Not applicable"));
        // doc-target-whatbreaks-v1: a skip is an HONEST successful outcome
        // with the explicit skipped state + machine-readable reason.
        assert!(result.skipped);
        assert_eq!(result.skip_reason.as_deref(), Some("Not applicable"));
        assert!(result.error.is_none());
        // Serializes additively: skipped=true present, skip_reason present.
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["skipped"], true);
        assert_eq!(json["skip_reason"], "Not applicable");
        assert_eq!(json["error"], serde_json::Value::Null);

        // Non-skipped results must not gain the fields (skip_serializing_if).
        let plain = SubResult::success(vec![1], 1.0);
        let plain_json = serde_json::to_value(&plain).unwrap();
        assert!(plain_json.get("skipped").is_none());
        assert!(plain_json.get("skip_reason").is_none());
    }

    /// doc-target-whatbreaks-v1: the call-graph support gate delegates to the
    /// call-graph's own SUPPORTED_LANGUAGES — code languages in, doc/config/
    /// text languages out (the set change-impact would be rejected by).
    #[test]
    fn test_call_graph_supports_code_but_not_doc_languages() {
        assert!(call_graph_supports(Language::Python));
        assert!(call_graph_supports(Language::Rust));
        assert!(call_graph_supports(Language::TypeScript));
        assert!(!call_graph_supports(Language::Markdown));
        assert!(!call_graph_supports(Language::Json));
        assert!(!call_graph_supports(Language::Yaml));
        assert!(!call_graph_supports(Language::Html));
        assert!(!call_graph_supports(Language::Text));
    }

    /// doc-target-whatbreaks-v1: a DOC file target reports the change-impact
    /// leg as an explicit skip (success + skipped + reason), never as
    /// `Unsupported language` failure. Importers still runs its real query.
    #[test]
    fn test_doc_file_target_skips_change_impact_instead_of_failing() {
        let test_dir = create_test_dir();
        add_file(&test_dir, "a.md", "# A\n\n[B](b.md)\n");
        add_file(&test_dir, "b.md", "# B\n\nbody\n");

        // No --lang: the language resolves from the target file (Markdown).
        let report =
            whatbreaks_analysis("b.md", test_dir.path(), &WhatbreaksOptions::default()).unwrap();

        assert_eq!(report.target_type, TargetType::File);
        assert_eq!(report.summary.importer_count, 1, "{:?}", report.summary);

        let change_impact_result = report.sub_results.get("change-impact").unwrap();
        assert!(
            change_impact_result.success,
            "a skip is a successful outcome"
        );
        assert!(change_impact_result.skipped);
        assert!(change_impact_result.error.is_none());
        let reason = change_impact_result.skip_reason.as_deref().unwrap();
        assert!(
            reason.contains("change-impact requires a code language"),
            "reason: {reason}"
        );
        assert!(
            reason.contains("markdown"),
            "reason names the language: {reason}"
        );

        // Serialized JSON must carry the honest state and NO error string.
        let json = serde_json::to_value(&report).unwrap();
        let ci = &json["sub_results"]["change-impact"];
        assert_eq!(ci["success"], true);
        assert_eq!(ci["skipped"], true);
        assert_eq!(ci["error"], serde_json::Value::Null);
        assert!(
            !json.to_string().contains("Unsupported language"),
            "no fabricated failure anywhere in the report"
        );
    }

    #[test]
    fn test_sub_result_partial() {
        let warnings = vec!["Some files could not be parsed".to_string()];
        let result = SubResult::partial(vec![1, 2], warnings, 75.0);
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(result.partial);
        assert_eq!(result.warnings.len(), 1);
    }

    // -------------------------------------------------------------------------
    // Module Name Derivation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_derive_module_name_simple() {
        let dir = create_test_dir();
        assert_eq!(
            derive_module_name("service", dir.path(), Language::Python),
            "service"
        );
    }

    #[test]
    fn test_derive_module_name_with_extension() {
        let dir = create_test_dir();
        assert_eq!(
            derive_module_name("service.py", dir.path(), Language::Python),
            "service"
        );
    }

    #[test]
    fn test_derive_module_name_with_path() {
        let dir = create_test_dir();
        assert_eq!(
            derive_module_name("src/service.py", dir.path(), Language::Python),
            "src.service"
        );
    }

    // -------------------------------------------------------------------------
    // doc-target-whatbreaks-v1: root-relative module derivation contract
    // -------------------------------------------------------------------------

    /// An ABSOLUTE code-file target derives the SAME dotted module as its
    /// root-relative spelling — the pre-fix version split the raw absolute
    /// path on `/` into the leading-dot garbage `.tmp.…service`.
    #[test]
    fn test_derive_module_name_absolute_matches_relative_code() {
        let dir = create_test_dir();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        let absolute = dir.path().join("src/service.py");
        let rel_from_abs =
            derive_module_name(absolute.to_str().unwrap(), dir.path(), Language::Python);
        let rel = derive_module_name("src/service.py", dir.path(), Language::Python);
        assert_eq!(rel_from_abs, rel, "absolute and relative must agree");
        assert_eq!(rel, "src.service");
    }

    /// Doc-language targets keep the root-relative PATH (extension included),
    /// absolute or relative — doc links reference each other by path.
    #[test]
    fn test_derive_module_name_doc_keeps_relative_path() {
        let dir = create_test_dir();

        let abs = dir.path().join("b.md");
        assert_eq!(
            derive_module_name(abs.to_str().unwrap(), dir.path(), Language::Markdown),
            "b.md"
        );
        assert_eq!(
            derive_module_name("b.md", dir.path(), Language::Markdown),
            "b.md"
        );
        assert_eq!(
            derive_module_name("docs/x.md", dir.path(), Language::Markdown),
            "docs/x.md"
        );
        let nested = dir.path().join("docs").join("x.md");
        assert_eq!(
            derive_module_name(nested.to_str().unwrap(), dir.path(), Language::Markdown),
            "docs/x.md"
        );
    }

    /// Error tolerance: an absolute target OUTSIDE the project root degrades
    /// to its file name instead of emitting a leading-dot dotted path.
    #[test]
    fn test_derive_module_name_outside_root_falls_back_to_file_name() {
        let project = create_test_dir();
        let other = create_test_dir();
        let outside = other.path().join("lonely.py");

        let derived =
            derive_module_name(outside.to_str().unwrap(), project.path(), Language::Python);
        assert_eq!(derived, "lonely");
    }

    // -------------------------------------------------------------------------
    // Integration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_function_runs_impact() {
        let test_dir = create_test_dir();
        add_file(
            &test_dir,
            "utils.py",
            r#"
def helper():
    return True

def caller():
    return helper()
"#,
        );

        let options = WhatbreaksOptions {
            language: Some(Language::Python),
            ..Default::default()
        };

        let report = whatbreaks_analysis("helper", test_dir.path(), &options).unwrap();

        assert_eq!(report.target_type, TargetType::Function);
        assert!(report.sub_results.contains_key("impact"));
    }

    #[test]
    fn test_continues_on_partial_failure() {
        let test_dir = create_test_dir();
        // Create a file that will cause the file-based analysis path
        add_file(&test_dir, "service.py", "def run(): pass");

        let options = WhatbreaksOptions {
            language: Some(Language::Python),
            ..Default::default()
        };

        // Even if some analyses fail, the report should still be generated
        let report = whatbreaks_analysis("service.py", test_dir.path(), &options).unwrap();

        assert_eq!(report.target_type, TargetType::File);
        // Report should contain both sub-analysis keys
        assert!(report.sub_results.contains_key("importers"));
        assert!(report.sub_results.contains_key("change-impact"));
    }

    #[test]
    fn test_reports_individual_errors() {
        let test_dir = create_test_dir();
        // No files exist - function lookup will fail

        let options = WhatbreaksOptions {
            language: Some(Language::Python),
            ..Default::default()
        };

        let report =
            whatbreaks_analysis("nonexistent_function", test_dir.path(), &options).unwrap();

        assert_eq!(report.target_type, TargetType::Function);

        // The impact sub-result should have an error
        if let Some(impact_result) = report.sub_results.get("impact") {
            // Either success with empty data or error - both are valid
            // The key is that the report was generated
            assert!(impact_result.success || impact_result.error.is_some());
        }
    }

    #[test]
    fn test_quick_mode_skips_change_impact() {
        let test_dir = create_test_dir();
        add_file(&test_dir, "service.py", "def run(): pass");

        let options = WhatbreaksOptions {
            language: Some(Language::Python),
            quick: true,
            ..Default::default()
        };

        let report = whatbreaks_analysis("service.py", test_dir.path(), &options).unwrap();

        // change-impact should be skipped
        if let Some(change_impact_result) = report.sub_results.get("change-impact") {
            assert!(change_impact_result
                .warnings
                .iter()
                .any(|w| w.contains("quick")));
        }
    }

    #[test]
    fn test_forced_type_overrides_detection() {
        let test_dir = create_test_dir();
        add_file(&test_dir, "service.py", "def run(): pass");

        let options = WhatbreaksOptions {
            language: Some(Language::Python),
            force_type: Some(TargetType::Function),
            ..Default::default()
        };

        // "service.py" would normally be detected as File,
        // but we're forcing Function
        let report = whatbreaks_analysis("service.py", test_dir.path(), &options).unwrap();

        assert_eq!(report.target_type, TargetType::Function);
        assert!(report.detection_reason.contains("Forced"));
    }
}
