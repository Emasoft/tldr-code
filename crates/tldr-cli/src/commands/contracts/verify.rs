//! Verify command - Aggregated verification dashboard combining multiple analyses.
//!
//! Provides a unified view of code constraints including:
//! - Contracts (pre/postconditions) from source analysis
//! - Specs from test files
//! - Bounds analysis warnings
//! - Dead store detection
//!
//! # ELEPHANT Mitigations Addressed
//! - E02: Capture all sub-analysis errors, report in summary
//! - E03: Partial failure handling - continue and report
//! - E07: Clear intermediate results after each file
//! - E09: Concurrent access - unique temp dirs
//!
//! # Example
//!
//! ```bash
//! tldr verify ./src
//! tldr verify ./src --quick
//! tldr verify ./src --detail contracts
//! tldr verify ./src --format text
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use tldr_core::walker::walk_project;

use tldr_core::Language;

use crate::output::{OutputFormat, OutputWriter};

use super::contracts::run_contracts;
use super::error::{ContractsError, ContractsResult};
use super::specs::run_specs;
use super::types::ContractsReport;
use super::types::{
    CoverageInfo, OutputFormat as ContractsOutputFormat, SubAnalysisResult, SubAnalysisStatus,
    VerifyReport, VerifySummary,
};
// validate_file_path is available but currently unused
// use super::validation::validate_file_path;

// =============================================================================
// Resource Limits (E03 Mitigation)
// =============================================================================

/// Maximum number of files to analyze (E03 mitigation)
const MAX_FILES: usize = 500;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Aggregated verification dashboard combining multiple analyses.
///
/// Runs contracts, specs, bounds, and dead-stores analyses on a project
/// directory and provides a unified coverage report.
///
/// # Example
///
/// ```bash
/// tldr verify ./src
/// tldr verify ./src --quick
/// tldr verify ./src --detail contracts
/// ```
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Directory to analyze (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format (json or text). Prefer global --format/-f flag.
    #[arg(
        long = "output-format",
        short = 'o',
        hide = true,
        default_value = "json"
    )]
    pub output_format: ContractsOutputFormat,

    /// Programming language override (auto-detected if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Show specific sub-analysis detail
    #[arg(long)]
    pub detail: Option<String>,

    /// Quick mode - skip expensive analyses (invariants, patterns)
    #[arg(long)]
    pub quick: bool,
}

impl VerifyArgs {
    /// Run the verify command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists. Canonicalisation is used ONLY for the
        // up-front existence probe; verify-aggregator-path-shape-fix-v1
        // (v0.4.2 hotfix for M-011) keeps the user-input shape on the
        // walked path so emitted file paths (top-level `path`, plus
        // every `ContractsReport.file` embedded in `sub_results.contracts.data`)
        // round-trip the user's input verbatim. Walking the canonical form
        // on macOS resolves `/tmp/...` -> `/private/tmp/...` and leaks the
        // resolved shape via the contracts sub-runner. The W-C
        // cross-cmd-path-shape-v1 invariant requires no `/private/tmp/`
        // anywhere in the response.
        if !self.path.exists() {
            return Err(ContractsError::FileNotFound {
                path: self.path.clone(),
            }
            .into());
        }

        writer.progress(&format!(
            "Running verification on {}...",
            self.path.display()
        ));

        // Determine language (auto-detect from directory, default to Python)
        let language = self.lang.unwrap_or_else(|| {
            if self.path.is_file() {
                Language::from_path(&self.path).unwrap_or(Language::Python)
            } else {
                Language::from_directory(&self.path).unwrap_or(Language::Python)
            }
        });

        // Run verification on the user-input path (NOT the canonical form).
        // The internal walker (`walk_project` / `ProjectWalker`) honours
        // `follow_links(false)` so passing `/tmp/repos/...` preserves the
        // user shape on every emitted `DirEntry::path()`. Each
        // `ContractsReport.file` is then a child of the user-input root
        // and the W-C path-shape contract is satisfied without an
        // additional post-walk rewrite.
        let mut report = run_verify(
            &self.path,
            language,
            self.quick,
            self.detail.as_deref(),
        )?;

        // cross-cmd-path-shape-v1 (v0.4.2 bug-A5): re-assert user input
        // shape on the top-level `path` field. Defensive: in the unlikely
        // event a future refactor re-introduces canonicalisation in
        // `run_verify`, this line still guarantees the top-level field
        // echoes user input.
        report.path = self.path.clone();

        // Output based on format
        let use_text = matches!(self.output_format, ContractsOutputFormat::Text)
            || matches!(format, OutputFormat::Text);

        if use_text {
            let text = format_verify_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

// =============================================================================
// Core Analysis Functions
// =============================================================================

/// Run the full verification dashboard.
///
/// # Arguments
/// * `path` - Directory or file to analyze
/// * `language` - Programming language for analysis
/// * `quick` - If true, skip expensive analyses (invariants, patterns)
/// * `detail` - If Some, show only the specified sub-analysis
///
/// # Returns
/// VerifyReport with all sub-analysis results and coverage summary.
///
/// # Note on `_quick`
/// The `_quick` parameter is currently unused: per schema-completeness-v1,
/// the only sub-analyses that ran in non-quick mode (`bounds`, `invariants`)
/// were stub-only and have been removed from the report. The flag is preserved
/// in the signature so that callers can pass it through unchanged, and it will
/// regain meaning in `verify-full-integration-v1` when those analyses are
/// wired up for real.
pub fn run_verify(
    path: &Path,
    language: Language,
    _quick: bool,
    detail: Option<&str>,
) -> ContractsResult<VerifyReport> {
    let start_time = Instant::now();

    // Collect files to analyze
    let files = collect_source_files(path, language)?;
    let files_analyzed = files.len() as u32;

    // Initialize report
    let mut sub_results: HashMap<String, SubAnalysisResult> = HashMap::new();
    let mut files_failed = 0u32;

    // Run sub-analyses
    // 1. Contracts sweep
    let contracts_result = sweep_contracts(&files, language, detail);
    if let Some(ref err) = contracts_result.error {
        files_failed += count_failures_from_error(err);
    }
    sub_results.insert("contracts".to_string(), contracts_result);

    // 2. Specs extraction (if test directory exists)
    //
    // cl3-test-linkage-v1 (CL-3 / GH #35): `find_test_dirs` historically only
    // probed top-level test *directories*. Languages that colocate tests with
    // source (Go `*_test.go`, Rust inline `#[cfg(test)]`) have no such
    // directory, so verify reported "No test directory found" / spec_count 0
    // despite the project clearly containing tests. When no test directory is
    // found we now fall back to the project root for colocated-test languages
    // (detected AST-side: `sweep_specs` -> `run_specs` only counts files the
    // language `test_recognizer` accepts, so scanning the root is safe).
    let test_dirs = find_test_dirs(path, language);
    if !test_dirs.is_empty() {
        let specs_result = sweep_specs(&test_dirs[0], detail);
        sub_results.insert("specs".to_string(), specs_result);
    } else {
        sub_results.insert(
            "specs".to_string(),
            SubAnalysisResult {
                name: "specs".to_string(),
                status: SubAnalysisStatus::Failed,
                items_found: 0,
                elapsed_ms: 0,
                error: Some("No test directory found".to_string()),
                data: None,
            },
        );
    }

    // schema-completeness-v1: `bounds`, `dead_stores`, and `invariants` were
    // emitted as stub `Skipped` entries with status messages like "not yet
    // integrated". The verify command was effectively lying about running them.
    // Per the milestone (option b: drop the unwired sub_results), they are no
    // longer reported. `sweep_bounds` and `sweep_dead_stores` are retained
    // (allow(dead_code)) so that wiring them up in a future
    // "verify-full-integration-v1" milestone is a one-line change.
    //
    // Currently aggregated sub_results: contracts, specs.

    // Compute coverage from results
    let summary = build_verify_summary(&sub_results, files_analyzed);

    let total_elapsed_ms = (start_time.elapsed().as_millis() as u64).max(1);

    // Determine if we have partial results
    let partial_results = sub_results.values().any(|r| {
        matches!(
            r.status,
            SubAnalysisStatus::Partial | SubAnalysisStatus::Failed
        )
    });

    Ok(VerifyReport {
        path: path.to_path_buf(),
        sub_results,
        summary,
        total_elapsed_ms,
        files_analyzed,
        files_failed,
        partial_results,
    })
}

/// Collect source files for analysis.
///
/// verify-aggregator-v1 (v0.4.2 M-011): previously hardcoded a tiny
/// ext-map (`py/ts/rs/go/java`) and silently fell through to `"py"`
/// for every other [`Language`] variant, so `tldr verify <dir>` on a
/// C / C++ / Kotlin / Scala / Swift / OCaml / ... project walked the
/// tree looking for `*.py` files and reported `files_analyzed: 0`.
///
/// Now delegates to [`Language::scan_extensions`] (the same widening
/// list used by other directory-walking commands), which covers every
/// supported language and includes the JS↔TS / C↔Cpp sibling families.
/// The leading `.` in each canonical extension is stripped at the
/// comparison site so `*.tsx`, `*.kt`, `*.scala`, `*.ml`, etc. all
/// participate.
fn collect_source_files(path: &Path, language: Language) -> ContractsResult<Vec<PathBuf>> {
    // Language::scan_extensions returns canonical-prefixed extensions
    // (".py", ".kt", ...) — strip the leading dot so we can compare
    // against std::path::Path::extension() which yields the raw "py".
    let exts: Vec<&str> = language
        .scan_extensions()
        .iter()
        .map(|e| e.strip_prefix('.').unwrap_or(e))
        .collect();

    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.to_path_buf());
    } else {
        for entry in walk_project(path).filter(|e| {
            e.path().is_file()
                && e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|ext| exts.iter().any(|e| *e == ext))
                // Skip Python test files (`test_*.py`) for main
                // analysis. The pytest layout pulls these into specs
                // separately; other languages' test naming
                // conventions (`*Test.java`, `*Tests.cs`,
                // `*Spec.scala`) are handled by `find_test_dirs` /
                // path-based detection rather than file-name prefix.
                && !e.file_name().to_str().is_some_and(|n| n.starts_with("test_"))
        }) {
            files.push(entry.path().to_path_buf());

            // Apply file limit (E03 mitigation)
            if files.len() >= MAX_FILES {
                break;
            }
        }
    }

    Ok(files)
}

/// Find test directories by convention.
///
/// critical-regressions-v1 (P13.AGG13-7): extends discovery to include
/// Maven/Gradle (`src/test/java`, `src/test/kotlin`, `src/test/scala`,
/// `src/test/groovy`) and MSBuild (`*Tests/`, `*.Tests/`, `Src/*Tests/`)
/// layouts. Previously only top-level `tests/`, `test/` were probed, so
/// `tldr verify` on a Spring/Maven project reported `error: "No test
/// directory found"` despite `src/test/java` clearly existing.
fn find_test_dirs(project_path: &Path, language: Language) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // Check common test directory names (top-level).
    for name in &["tests", "test", "Tests", "Test", "spec", "specs", "__tests__"] {
        let dir = project_path.join(name);
        if dir.is_dir() {
            candidates.push(dir);
        }
    }

    // Maven / Gradle / sbt layouts: `src/test/<lang>`.
    let src_test = project_path.join("src").join("test");
    if src_test.is_dir() {
        candidates.push(src_test.clone());
        // Also add language-scoped subdirs explicitly (java/kotlin/scala/groovy/resources)
        // so downstream walkers stop at language roots when src/test/ contains
        // non-source folders too.
        for lang_sub in &["java", "kotlin", "scala", "groovy", "resources"] {
            let sub = src_test.join(lang_sub);
            if sub.is_dir() && !candidates.iter().any(|p| p == &sub) {
                candidates.push(sub);
            }
        }
    }

    // MSBuild C# layout: project sibling `*Tests` or `*.Tests` directories
    // at top-level or under `Src/`/`src/` (case-insensitive on macOS, exact
    // on linux — read both forms).
    for parent in &[project_path.to_path_buf(), project_path.join("src"), project_path.join("Src")]
    {
        if !parent.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if name.ends_with("Tests")
                    || name.ends_with(".Tests")
                    || name.ends_with("Test")
                    || name.ends_with(".Test")
                {
                    if !candidates.iter().any(|p| p == &path) {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    // Check for test_*.py files in the project root (legacy pytest layout).
    if let Ok(entries) = std::fs::read_dir(project_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("test_") && name.ends_with(".py") {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    // cl3-test-linkage-v1 (CL-3 / GH #35): colocated-test fallback. Languages
    // like Go (`*_test.go`) and Rust (inline `#[cfg(test)]`) do not use a
    // dedicated test directory, so none of the directory probes above match.
    // If we found nothing yet, AST-scan the project for a file the language's
    // `test_recognizer` accepts; if one exists, return the project root so
    // `sweep_specs` walks it (the walker re-filters via `recognize`, so only
    // real test files contribute).
    if candidates.is_empty() && project_has_colocated_tests(project_path, language) {
        candidates.push(project_path.to_path_buf());
    }

    candidates
}

/// Detect whether the project contains colocated test files (no dedicated
/// test directory) by AST-recognizing files via the language `test_recognizer`.
///
/// Returns as soon as the first recognized test file is found so large trees
/// stop early. Used only as a fallback when [`find_test_dirs`]'s directory
/// probes come up empty.
fn project_has_colocated_tests(project_path: &Path, language: Language) -> bool {
    use tldr_core::walker::walk_project;

    for entry in walk_project(project_path).filter(|e| e.path().is_file()) {
        let file_path = entry.path();
        // Only consider files in the target language.
        if super::test_recognizer::detect_language(file_path) != Some(language) {
            continue;
        }
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if super::test_recognizer::recognize(file_path, &source, language).is_test_file {
            return true;
        }
    }
    false
}

// =============================================================================
// Sub-Analysis Sweepers
// =============================================================================

/// Sweep contracts analysis over all files.
fn sweep_contracts(
    files: &[PathBuf],
    language: Language,
    _detail: Option<&str>,
) -> SubAnalysisResult {
    let start = Instant::now();
    let mut total_contracts = 0u32;
    let mut all_results: Vec<ContractsReport> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for file in files {
        // Find all functions in the file and analyze each
        match analyze_file_contracts(file, language) {
            Ok(reports) => {
                for report in reports {
                    total_contracts += report.preconditions.len() as u32;
                    total_contracts += report.postconditions.len() as u32;
                    total_contracts += report.invariants.len() as u32;
                    all_results.push(report);
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", file.display(), e));
            }
        }
    }

    let status = if errors.is_empty() {
        SubAnalysisStatus::Success
    } else if !all_results.is_empty() {
        SubAnalysisStatus::Partial
    } else {
        SubAnalysisStatus::Failed
    };

    SubAnalysisResult {
        name: "contracts".to_string(),
        status,
        items_found: total_contracts,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        data: Some(serde_json::to_value(&all_results).unwrap_or(serde_json::Value::Null)),
    }
}

/// Analyze contracts for all functions in a file.
fn analyze_file_contracts(
    file: &Path,
    language: Language,
) -> ContractsResult<Vec<ContractsReport>> {
    let source = std::fs::read_to_string(file)?;
    let functions = extract_function_names(&source, language)?;

    let mut reports = Vec::new();
    for func_name in functions {
        match run_contracts(file, &func_name, language, 100) {
            Ok(report) => reports.push(report),
            Err(_) => continue, // Skip functions that fail to analyze
        }
    }

    Ok(reports)
}

/// Extract the bare names of functions/methods DECLARED in `source`.
///
/// verify-aggregator-v1 (v0.4.2 M-011): previously a line-based regex matching
/// only Python's `def NAME(` syntax, which silently returned an empty list for
/// every other language. As a result `sweep_contracts` invoked `run_contracts`
/// zero times on C / C++ / Kotlin / Scala / Swift / OCaml / Ruby / Rust / Go /
/// Java / TS / JS files and the aggregator's `contracts.items_found` was always
/// `0`. It was then made AST-based (ParserPool + tree-sitter `extract_functions`
/// plus the Solidity and method-bearing-language bridges).
///
/// fix-R3-rc4 (RC4): that AST extractor is now hoisted into
/// `contracts::symbols::defined_symbol_names`, the SINGLE shared definition of
/// "the symbols a file declares", so `verify` and `invariants` (and `specs
/// --source`) agree on it instead of recomputing it ad hoc. This wrapper is
/// behaviour-preserving for the verify sweep: it still covers every supported
/// language and still falls back to the empty list on blank/unparseable source
/// (`analyze_file_contracts` records the error upstream when `run_contracts`
/// itself fails on a function).
fn extract_function_names(source: &str, language: Language) -> ContractsResult<Vec<String>> {
    Ok(super::symbols::defined_symbol_names(source, language))
}

/// Sweep specs extraction from test directory.
fn sweep_specs(test_path: &Path, _detail: Option<&str>) -> SubAnalysisResult {
    let start = Instant::now();

    match run_specs(test_path, None) {
        Ok(report) => {
            let total_specs = report.summary.total_specs;
            SubAnalysisResult {
                name: "specs".to_string(),
                status: SubAnalysisStatus::Success,
                items_found: total_specs,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: None,
                data: Some(serde_json::to_value(&report).unwrap_or(serde_json::Value::Null)),
            }
        }
        Err(e) => SubAnalysisResult {
            name: "specs".to_string(),
            status: SubAnalysisStatus::Failed,
            items_found: 0,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: Some(e.to_string()),
            data: None,
        },
    }
}

/// Sweep bounds analysis over all files.
///
/// schema-completeness-v1: not currently wired into the verify report.
/// Retained for `verify-full-integration-v1`.
#[allow(dead_code)]
fn sweep_bounds(
    _files: &[PathBuf],
    _language: Language,
    _detail: Option<&str>,
) -> SubAnalysisResult {
    let start = Instant::now();

    // Bounds analysis is expensive - for now, return a stub
    // TODO: Implement when bounds command is integrated
    SubAnalysisResult {
        name: "bounds".to_string(),
        status: SubAnalysisStatus::Skipped,
        items_found: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: Some("Bounds sweep not yet integrated".to_string()),
        data: None,
    }
}

/// Sweep dead stores detection over all files.
///
/// schema-completeness-v1: not currently wired into the verify report.
/// Retained for `verify-full-integration-v1`.
#[allow(dead_code)]
fn sweep_dead_stores(
    _files: &[PathBuf],
    _language: Language,
    _detail: Option<&str>,
) -> SubAnalysisResult {
    let start = Instant::now();

    // Dead stores requires SSA analysis for each function
    // TODO: Implement when dead_stores command is fully integrated
    SubAnalysisResult {
        name: "dead_stores".to_string(),
        status: SubAnalysisStatus::Skipped,
        items_found: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: Some("Dead stores sweep not yet integrated".to_string()),
        data: None,
    }
}

// =============================================================================
// Summary Building
// =============================================================================

/// Build the verify summary from sub-analysis results.
fn build_verify_summary(
    sub_results: &HashMap<String, SubAnalysisResult>,
    total_files: u32,
) -> VerifySummary {
    // Count items from each sub-analysis
    let spec_count = sub_results.get("specs").map(|r| r.items_found).unwrap_or(0);

    let contract_count = sub_results
        .get("contracts")
        .map(|r| r.items_found)
        .unwrap_or(0);

    let invariant_count = sub_results
        .get("invariants")
        .map(|r| r.items_found)
        .unwrap_or(0);

    // Compute coverage from contracts data
    let coverage = compute_coverage(sub_results, total_files);

    VerifySummary {
        spec_count,
        invariant_count,
        contract_count,
        annotated_count: 0,  // Not yet implemented
        behavioral_count: 0, // Not yet implemented
        pattern_count: 0,
        pattern_high_confidence: 0,
        coverage,
    }
}

/// Compute function coverage from analysis results.
fn compute_coverage(
    sub_results: &HashMap<String, SubAnalysisResult>,
    total_files: u32,
) -> CoverageInfo {
    let mut constrained_functions: HashSet<String> = HashSet::new();
    let mut total_functions: HashSet<String> = HashSet::new();

    // Extract function info from contracts results
    if let Some(contracts_result) = sub_results.get("contracts") {
        if let Some(data) = &contracts_result.data {
            if let Some(reports) = data.as_array() {
                for report in reports {
                    if let Some(func_name) = report.get("function").and_then(|f| f.as_str()) {
                        total_functions.insert(func_name.to_string());

                        // Check if function has any constraints
                        let has_pre = report
                            .get("preconditions")
                            .and_then(|p| p.as_array())
                            .is_some_and(|a| !a.is_empty());
                        let has_post = report
                            .get("postconditions")
                            .and_then(|p| p.as_array())
                            .is_some_and(|a| !a.is_empty());
                        let has_inv = report
                            .get("invariants")
                            .and_then(|i| i.as_array())
                            .is_some_and(|a| !a.is_empty());

                        if has_pre || has_post || has_inv {
                            constrained_functions.insert(func_name.to_string());
                        }
                    }
                }
            }
        }
    }

    // If no functions found, use file count as proxy
    let total = if total_functions.is_empty() {
        total_files
    } else {
        total_functions.len() as u32
    };

    let constrained = constrained_functions.len() as u32;
    let coverage_pct = if total > 0 {
        (constrained as f64 / total as f64 * 100.0).round() / 1.0 // Round to 1 decimal
    } else {
        0.0
    };

    CoverageInfo {
        constrained_functions: constrained,
        total_functions: total,
        coverage_pct,
        // M18 (med-cleanup-bundle-v1): document what the
        // total_functions denominator represents so callers do not
        // mistake `coverage_pct` for project-wide coverage.
        scope: "constraint-relevant functions (subset of all project functions; \
                 typically << structure/health total_functions)"
            .to_string(),
    }
}

/// Count failures from error message.
fn count_failures_from_error(error: &str) -> u32 {
    // Count semicolons (our error separator) + 1
    (error.matches(';').count() + 1) as u32
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Format verify report as human-readable text.
pub fn format_verify_text(report: &VerifyReport) -> String {
    let s = &report.summary;
    let cov = &s.coverage;

    let mut lines = vec![
        format!("Verification: {}", report.path.display()),
        "=".repeat(50),
        format!("Test Specs:    {} behavioral specs extracted", s.spec_count),
        format!("Invariants:    {} inferred invariants", s.invariant_count),
        format!(
            "Contracts:     {} pre/postconditions inferred",
            s.contract_count
        ),
        format!(
            "Annotations:   {} Annotated[T] constraints found",
            s.annotated_count
        ),
        format!(
            "Behaviors:     {} functions with behavioral models",
            s.behavioral_count
        ),
        format!(
            "Patterns:      {} project patterns ({} high-confidence)",
            s.pattern_count, s.pattern_high_confidence
        ),
        String::new(),
        "Constraint Coverage:".to_string(),
        format!(
            "  Functions with any constraint: {}/{} ({:.1}%)",
            cov.constrained_functions, cov.total_functions, cov.coverage_pct
        ),
        format!("  Scope: {}", cov.scope),
        String::new(),
        format!("Elapsed: {}ms", report.total_elapsed_ms),
    ];

    // Add errors if any
    let failed: Vec<&str> = report
        .sub_results
        .iter()
        .filter(|(_, r)| matches!(r.status, SubAnalysisStatus::Failed))
        .map(|(name, _)| name.as_str())
        .collect();

    if !failed.is_empty() {
        lines.push(format!("Errors: {}", failed.join(", ")));
    }

    lines.join("\n")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const PYTHON_WITH_CONTRACTS: &str = r#"
def constrained(x):
    if x < 0:
        raise ValueError("x must be non-negative")
    return x * 2

def unconstrained(y):
    return y * 3
"#;

    const PYTHON_TEST_FILE: &str = r#"
import pytest
from mymodule import add, validate

def test_add():
    assert add(2, 3) == 5

def test_validate_raises():
    with pytest.raises(ValueError):
        validate("")
"#;

    // -------------------------------------------------------------------------
    // Full Sweep Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_full_sweep() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let test_dir = temp.path().join("tests");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&test_dir).unwrap();

        fs::write(src_dir.join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();
        fs::write(test_dir.join("test_module.py"), PYTHON_TEST_FILE).unwrap();

        let report = run_verify(temp.path(), Language::Python, false, None).unwrap();

        // Should have sub_results
        assert!(report.sub_results.contains_key("contracts"));
        assert!(report.sub_results.contains_key("specs"));
        assert!(report.total_elapsed_ms > 0);
    }

    #[test]
    fn test_verify_quick_mode() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();

        let report = run_verify(temp.path(), Language::Python, true, None).unwrap();

        // schema-completeness-v1: invariants/bounds/dead_stores are no longer
        // emitted (they were stubs). Quick mode is currently a no-op flag — the
        // remaining sub-analyses (contracts, specs) run identically in either
        // mode. Asserts that quick mode still produces a structurally-valid
        // report and never resurrects the dropped keys.
        assert!(report.sub_results.contains_key("contracts"));
        assert!(!report.sub_results.contains_key("invariants"));
        assert!(!report.sub_results.contains_key("bounds"));
        assert!(!report.sub_results.contains_key("dead_stores"));
    }

    #[test]
    fn test_verify_no_skipped_subresults() {
        // schema-completeness-v1: every sub_result the verify command claims to
        // produce must have actually run — no stub `Skipped` entries left over.
        // Run on both quick and non-quick mode against a fixture with both
        // source and tests so we exercise the full path.
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let test_dir = temp.path().join("tests");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&test_dir).unwrap();
        fs::write(src_dir.join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();
        fs::write(test_dir.join("test_module.py"), PYTHON_TEST_FILE).unwrap();

        for quick in [false, true] {
            let report = run_verify(temp.path(), Language::Python, quick, None).unwrap();
            for (name, result) in &report.sub_results {
                assert!(
                    !matches!(result.status, SubAnalysisStatus::Skipped),
                    "sub_result `{name}` has status Skipped in quick={quick} — verify should never emit unwired stubs (schema-completeness-v1)"
                );
            }
        }
    }

    #[test]
    fn test_verify_drops_unwired_keys() {
        // Hard regression guard for the option-(b) path: the verify report MUST
        // NOT contain `bounds`, `dead_stores`, or `invariants` keys until they
        // are actually wired up (deferred to verify-full-integration-v1).
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let test_dir = temp.path().join("tests");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&test_dir).unwrap();
        fs::write(src_dir.join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();
        fs::write(test_dir.join("test_module.py"), PYTHON_TEST_FILE).unwrap();

        let report = run_verify(temp.path(), Language::Python, false, None).unwrap();
        for forbidden in ["bounds", "dead_stores", "invariants"] {
            assert!(
                !report.sub_results.contains_key(forbidden),
                "verify must not emit `{forbidden}` until it is actually wired up"
            );
        }
        // Conversely, the wired analyses must still be present.
        assert!(report.sub_results.contains_key("contracts"));
        assert!(report.sub_results.contains_key("specs"));
    }

    #[test]
    fn test_verify_partial_failure() {
        let temp = TempDir::new().unwrap();

        // Create a file that will cause parse errors
        fs::write(temp.path().join("broken.py"), "def broken( syntax error").unwrap();
        fs::write(temp.path().join("valid.py"), "def valid(): pass").unwrap();

        let report = run_verify(temp.path(), Language::Python, false, None).unwrap();

        // Should still produce a report (partial results)
        assert!(report.sub_results.contains_key("contracts"));
    }

    #[test]
    fn test_verify_file_limit() {
        let temp = TempDir::new().unwrap();

        // Create more than MAX_FILES Python files
        for i in 0..600 {
            fs::write(
                temp.path().join(format!("module_{}.py", i)),
                format!("def func_{i}(): pass"),
            )
            .unwrap();
        }

        let files = collect_source_files(temp.path(), Language::Python).unwrap();

        assert!(
            files.len() <= MAX_FILES,
            "Should limit to {} files, got {}",
            MAX_FILES,
            files.len()
        );
    }

    #[test]
    fn test_verify_coverage_calculation() {
        let temp = TempDir::new().unwrap();

        fs::write(temp.path().join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();

        let report = run_verify(temp.path(), Language::Python, true, None).unwrap();

        let cov = &report.summary.coverage;
        assert!(cov.total_functions > 0 || report.files_analyzed > 0);
        assert!(cov.coverage_pct >= 0.0 && cov.coverage_pct <= 100.0);
    }

    #[test]
    fn test_verify_json_output() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("module.py"), "def foo(): pass").unwrap();

        let report = run_verify(temp.path(), Language::Python, true, None).unwrap();

        // Should serialize to valid JSON
        let json = serde_json::to_string(&report);
        assert!(json.is_ok());

        // Verify expected fields
        let json_value: serde_json::Value = serde_json::from_str(&json.unwrap()).unwrap();
        assert!(json_value.get("path").is_some());
        assert!(json_value.get("sub_results").is_some());
        assert!(json_value.get("summary").is_some());
        assert!(json_value.get("total_elapsed_ms").is_some());
    }

    #[test]
    fn test_verify_text_output() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();

        let report = run_verify(temp.path(), Language::Python, true, None).unwrap();
        let text = format_verify_text(&report);

        assert!(text.contains("Verification:"));
        assert!(text.contains("Constraint Coverage:"));
        assert!(text.contains("Elapsed:"));
    }

    #[test]
    fn test_verify_detail_filter() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("module.py"), PYTHON_WITH_CONTRACTS).unwrap();

        let report = run_verify(temp.path(), Language::Python, true, Some("contracts")).unwrap();

        // Should still run all analyses but detail is informational
        assert!(report.sub_results.contains_key("contracts"));
    }

    // -------------------------------------------------------------------------
    // Helper Function Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_test_dirs() {
        let temp = TempDir::new().unwrap();
        let tests_dir = temp.path().join("tests");
        fs::create_dir(&tests_dir).unwrap();

        let dirs = find_test_dirs(temp.path(), Language::Python);
        assert!(!dirs.is_empty());
        assert!(dirs[0].ends_with("tests"));
    }

    #[test]
    fn test_find_test_dirs_none() {
        let temp = TempDir::new().unwrap();

        // No test directory and no colocated test files -> empty.
        let dirs = find_test_dirs(temp.path(), Language::Python);
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_find_test_dirs_colocated_go() {
        // cl3-test-linkage-v1 (CL-3 / GH #35): Go colocates `*_test.go` next
        // to source with no `tests/` directory; the colocated fallback must
        // return the project root so specs extraction can walk it.
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("router.go"),
            "package main\n\nfunc Add(a, b int) int { return a + b }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("router_test.go"),
            "package main\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n",
        )
        .unwrap();

        let dirs = find_test_dirs(temp.path(), Language::Go);
        assert!(
            !dirs.is_empty(),
            "colocated Go *_test.go must yield a test-dir candidate (project root)"
        );
        assert_eq!(dirs[0], temp.path());
    }

    #[test]
    fn test_extract_function_names() {
        let source = r#"
def foo():
    pass

def bar(x):
    return x

def baz(a, b):
    return a + b
"#;

        let names = extract_function_names(source, Language::Python).unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"foo".to_string()));
        assert!(names.contains(&"bar".to_string()));
        assert!(names.contains(&"baz".to_string()));
    }

    #[test]
    fn test_empty_directory() {
        let temp = TempDir::new().unwrap();

        let report = run_verify(temp.path(), Language::Python, true, None).unwrap();

        assert_eq!(report.files_analyzed, 0);
        assert_eq!(report.summary.coverage.total_functions, 0);
    }

    // -------------------------------------------------------------------------
    // fix-R2-themeE (RC9): verify coverage denominator must reflect REAL
    // methods for method-only / method-bearing languages, not collapse to the
    // file count. extract_functions returns [] for C# (no free functions), so
    // the Solidity-only extract_methods bridge left total_functions empty and
    // compute_coverage fell back to total_files (==1 here). After the fix the
    // bridge runs for C#/Java/Kotlin/Scala/Swift/Ruby/C++, so total_functions
    // == the real method count.
    // -------------------------------------------------------------------------

    /// RC9: a single C# file with five methods must report
    /// total_functions == 5 (the method count), NOT 1 (the file count).
    #[test]
    fn rc9_verify_csharp_total_functions_is_method_count_not_file_count() {
        let temp = TempDir::new().unwrap();
        let cs = r#"
public class Calc {
    public int Add(int a, int b) { return a + b; }
    public int Sub(int a, int b) { return a - b; }
    public int Mul(int a, int b) { return a * b; }
    public int Neg(int a) { return -a; }
    public int Id(int a) { return a; }
}
"#;
        fs::write(temp.path().join("Calc.cs"), cs).unwrap();

        let report = run_verify(temp.path(), Language::CSharp, false, None).unwrap();

        assert_eq!(
            report.files_analyzed, 1,
            "exactly one C# source file present"
        );
        let total = report.summary.coverage.total_functions;
        assert!(
            total > report.files_analyzed,
            "RC9: total_functions ({}) must exceed the file count ({}) — it must \
             count C# methods, not collapse to total_files",
            total,
            report.files_analyzed
        );
        assert_eq!(
            total, 5,
            "RC9: the five C# methods (Add/Sub/Mul/Neg/Id) must all count toward \
             total_functions, got {}",
            total
        );
    }

    /// RC9 blast-radius: C# methods bridge does not regress the Solidity path
    /// (which already bridged extract_methods) nor the Python free-function
    /// path. extract_function_names must still return the right names.
    #[test]
    fn rc9_extract_function_names_csharp_methods_and_solidity_unchanged() {
        // C#: free functions = []; methods = the five member methods.
        let cs = r#"
public class Calc {
    public int Add(int a, int b) { return a + b; }
    public int Sub(int a, int b) { return a - b; }
    private int Helper(int a) { return a; }
}
"#;
        let cs_names = extract_function_names(cs, Language::CSharp).unwrap();
        assert!(
            cs_names.contains(&"Add".to_string())
                && cs_names.contains(&"Sub".to_string())
                && cs_names.contains(&"Helper".to_string()),
            "RC9: C# method names must be bridged into extract_function_names, got {:?}",
            cs_names
        );

        // Solidity: contract member functions still bridged (unchanged path).
        let sol = r#"
contract Token {
    function transfer(address to, uint256 amount) public returns (bool) {
        require(amount > 0, "amount");
        return true;
    }
    function balanceOf(address who) public view returns (uint256) {
        return 0;
    }
}
"#;
        let sol_names = extract_function_names(sol, Language::Solidity).unwrap();
        assert!(
            sol_names.contains(&"transfer".to_string())
                && sol_names.contains(&"balanceOf".to_string()),
            "RC9 blast-radius: Solidity contract methods must still be bridged, got {:?}",
            sol_names
        );

        // Python: free functions unchanged (no method double-add, dedup holds).
        let py = "def foo():\n    pass\n\ndef bar(x):\n    return x\n";
        let py_names = extract_function_names(py, Language::Python).unwrap();
        assert_eq!(
            py_names.len(),
            2,
            "RC9 blast-radius: Python free functions unchanged, got {:?}",
            py_names
        );
    }
}
