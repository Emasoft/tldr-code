//! Health Analysis Module
//!
//! This module provides comprehensive code health analysis, aggregating multiple
//! sub-analyzers into a unified report. It implements the health command which
//! wraps complexity, cohesion, dead code, Martin metrics, coupling, and similarity
//! analyses.
//!
//! # Overview
//!
//! The health command provides a code health dashboard with:
//! - Cyclomatic/cognitive complexity analysis
//! - Class cohesion (LCOM4) analysis
//! - Dead code detection
//! - Martin package coupling metrics
//! - Pairwise module coupling (full mode only)
//! - Function similarity detection (full mode only)
//!
//! # Example
//!
//! ```ignore
//! use tldr_core::quality::health::{run_health, HealthOptions};
//!
//! let options = HealthOptions::default();
//! let report = run_health(Path::new("src/"), None, false)?;
//! println!("Hotspots: {}", report.summary.hotspot_count);
//! ```

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::walker::ProjectWalker;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::ast::extract::extract_file;
use crate::ast::extractor::get_code_structure;
use crate::callgraph::build_project_call_graph;
use crate::error::TldrError;
use crate::types::{IgnoreSpec, Language, ModuleInfo};
use crate::TldrResult;

use super::cohesion::{analyze_cohesion, CohesionReport};
use super::complexity::{analyze_complexity, ComplexityOptions, ComplexityReport};
use super::coupling::{analyze_coupling_with_graph, CouplingOptions, CouplingReport};
use super::dead_code::{analyze_dead_code_with_refcount, DeadCodeReport};
use super::martin::{compute_martin_metrics, MartinReport};
use crate::analysis::clones::{detect_clones, ClonesOptions};

// Re-export ThresholdPreset from smells module to avoid duplication
pub use super::smells::ThresholdPreset;

// =============================================================================
// Severity Enum (T6: Explicit discriminants with Ord derive)
// =============================================================================

/// Severity level for health findings.
///
/// Ordered from least to most severe: Info < Low < Medium < High < Critical.
/// Uses explicit discriminants to ensure stable ordering (T6 mitigation).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Severity {
    /// Informational - no action needed
    #[default]
    Info = 0,
    /// Low - minor improvement possible
    Low = 1,
    /// Medium - should address in next sprint
    Medium = 2,
    /// High - address soon
    High = 3,
    /// Critical - address immediately
    Critical = 4,
}

impl Severity {
    /// Get the numeric value of the severity level
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this severity is at or above a threshold
    pub fn is_at_least(&self, threshold: Severity) -> bool {
        *self >= threshold
    }
}

// ThresholdPreset is re-exported from smells module (avoid duplication)

// =============================================================================
// HealthOptions Struct
// =============================================================================

/// Configuration options for health analysis.
///
/// These options control thresholds, analysis mode, and output preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthOptions {
    /// Skip expensive analyses (coupling, similar)
    pub quick: bool,
    /// Threshold preset (overrides individual settings if not None)
    pub preset: ThresholdPreset,
    /// Complexity hotspot threshold (default: 10)
    pub complexity_threshold: usize,
    /// LCOM4 low cohesion threshold (default: 2)
    pub cohesion_threshold: usize,
    /// Similarity match threshold (default: 0.7)
    pub similarity_threshold: f64,
    /// Maximum items to return for coupling and similarity analyses (default: 50)
    pub max_items: usize,
    /// Summary mode - omit detail arrays, only include summary metrics
    #[serde(skip)]
    pub summary: bool,
}

impl Default for HealthOptions {
    fn default() -> Self {
        Self {
            quick: false,
            preset: ThresholdPreset::Default,
            complexity_threshold: 10,
            cohesion_threshold: 2,
            similarity_threshold: 0.7,
            max_items: 50,
            summary: false,
        }
    }
}

/// Get complexity hotspot threshold for a preset
fn complexity_threshold_for(preset: ThresholdPreset) -> usize {
    match preset {
        ThresholdPreset::Strict => 8,
        ThresholdPreset::Default => 10,
        ThresholdPreset::Relaxed => 15,
    }
}

/// Get LCOM4 low cohesion threshold for a preset
fn cohesion_threshold_for(preset: ThresholdPreset) -> usize {
    match preset {
        ThresholdPreset::Strict => 1,
        ThresholdPreset::Default => 2,
        ThresholdPreset::Relaxed => 3,
    }
}

/// Get similarity match threshold for a preset
fn similarity_threshold_for(preset: ThresholdPreset) -> f64 {
    match preset {
        ThresholdPreset::Strict => 0.6,
        ThresholdPreset::Default => 0.7,
        ThresholdPreset::Relaxed => 0.8,
    }
}

impl HealthOptions {
    /// Create options with a specific preset
    pub fn with_preset(preset: ThresholdPreset) -> Self {
        Self {
            quick: false,
            preset,
            complexity_threshold: complexity_threshold_for(preset),
            cohesion_threshold: cohesion_threshold_for(preset),
            similarity_threshold: similarity_threshold_for(preset),
            max_items: 50,
            summary: false,
        }
    }

    /// Create quick mode options (skips coupling and similarity)
    pub fn quick() -> Self {
        Self {
            quick: true,
            ..Default::default()
        }
    }

    /// Set summary mode
    pub fn with_summary(mut self, summary: bool) -> Self {
        self.summary = summary;
        self
    }

    /// Set max items limit
    pub fn with_max_items(mut self, max_items: usize) -> Self {
        self.max_items = max_items;
        self
    }
}

// =============================================================================
// SubAnalysisResult Struct
// =============================================================================

/// Result from one sub-analysis.
///
/// Each sub-analyzer (complexity, cohesion, etc.) produces a SubAnalysisResult
/// that captures success/failure, timing, and the analysis data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubAnalysisResult {
    /// Name of the sub-analysis (e.g., "complexity", "cohesion")
    pub name: String,
    /// Whether the analysis completed successfully
    pub success: bool,
    /// Elapsed time in milliseconds
    pub elapsed_ms: f64,
    /// Error message if analysis failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Number of findings from this analysis
    pub findings_count: usize,
    /// Heterogeneous sub-analyzer results (analysis-specific data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SubAnalysisResult {
    /// Create a successful sub-analysis result
    pub fn success(
        name: impl Into<String>,
        elapsed_ms: f64,
        findings_count: usize,
        details: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            success: true,
            elapsed_ms,
            error: None,
            findings_count,
            details: Some(details),
        }
    }

    /// Create a failed sub-analysis result
    pub fn failure(name: impl Into<String>, elapsed_ms: f64, error: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success: false,
            elapsed_ms,
            error: Some(error.into()),
            findings_count: 0,
            details: None,
        }
    }

    /// Create a skipped sub-analysis result (for quick mode)
    pub fn skipped(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success: false,
            elapsed_ms: 0.0,
            error: Some("skipped (quick mode)".to_string()),
            findings_count: 0,
            details: None,
        }
    }
}

// =============================================================================
// HealthSummary Struct
// =============================================================================

/// Aggregated summary metrics from all sub-analyzers.
///
/// This struct collects key metrics from each sub-analysis into a single
/// summary view. Fields are Option to handle cases where sub-analyzers
/// fail or are skipped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthSummary {
    // Analysis scope
    /// Number of files successfully analyzed
    pub files_analyzed: usize,
    /// Number of functions analyzed
    pub functions_analyzed: usize,
    /// Number of classes analyzed
    pub classes_analyzed: usize,

    // Complexity metrics
    /// Average cyclomatic complexity across all functions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_cyclomatic: Option<f64>,
    /// Number of functions with complexity above threshold
    pub hotspot_count: usize,

    // Cohesion metrics
    /// Average LCOM4 across all classes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_lcom4: Option<f64>,
    /// Number of classes with low cohesion (LCOM4 > threshold)
    pub low_cohesion_count: usize,

    // Dead code metrics
    /// Number of unreachable functions detected
    pub dead_count: usize,
    /// Percentage of functions that are dead (0.0-100.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_percentage: Option<f64>,

    // Martin metrics
    /// Average distance from main sequence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_distance: Option<f64>,
    /// Number of packages in the zone of pain
    pub packages_in_pain_zone: usize,

    // Coupling metrics (full mode only)
    /// Number of tightly coupled module pairs
    pub tight_coupling_pairs: usize,

    // Similarity metrics (full mode only)
    /// Number of similar function pairs detected
    pub similar_pairs: usize,

    /// Overall health score 0-100 (higher = better).
    ///
    /// health-dashboard-v1 (v0.4.2 M-016): aggregated quality indicator
    /// derived from a weighted average of three normalised buckets:
    ///   * 33% complexity (penalised by `avg_cyclomatic` vs preset
    ///     threshold). avg_cc <= threshold/2 ⇒ 100; avg_cc >= 2*threshold ⇒ 0.
    ///   * 33% dead-code (penalised by `dead_percentage`).
    ///     dead% == 0 ⇒ 100; dead% >= 25 ⇒ 0.
    ///   * 34% smells/hotspots (penalised by `hotspot_count /
    ///     functions_analyzed`). ratio == 0 ⇒ 100; ratio >= 0.25 ⇒ 0.
    /// Each bucket gracefully degrades to a neutral 50 when its
    /// underlying sub-analyzer didn't produce data (skipped or failed).
    ///
    /// Skipped if `functions_analyzed == 0` and no other signal is
    /// available (`None`) — we don't synthesise a score on empty input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
}

impl HealthSummary {
    /// Create a new empty summary
    pub fn new() -> Self {
        Self::default()
    }

    /// Update summary with complexity metrics
    pub fn with_complexity(mut self, avg: Option<f64>, hotspots: usize) -> Self {
        self.avg_cyclomatic = avg;
        self.hotspot_count = hotspots;
        self
    }

    /// Update summary with cohesion metrics
    pub fn with_cohesion(
        mut self,
        avg_lcom4: Option<f64>,
        low_cohesion: usize,
        classes: usize,
    ) -> Self {
        self.avg_lcom4 = avg_lcom4;
        self.low_cohesion_count = low_cohesion;
        self.classes_analyzed = classes;
        self
    }

    /// Update summary with dead code metrics
    pub fn with_dead_code(mut self, dead: usize, total: usize) -> Self {
        self.dead_count = dead;
        if total > 0 {
            self.dead_percentage = Some((dead as f64 / total as f64) * 100.0);
        }
        self.functions_analyzed = total;
        self
    }

    /// Update summary with Martin metrics
    pub fn with_martin(mut self, avg_distance: Option<f64>, pain_zone: usize) -> Self {
        self.avg_distance = avg_distance;
        self.packages_in_pain_zone = pain_zone;
        self
    }

    /// Update summary with coupling metrics
    pub fn with_coupling(mut self, tight_pairs: usize) -> Self {
        self.tight_coupling_pairs = tight_pairs;
        self
    }

    /// Update summary with similarity metrics
    pub fn with_similarity(mut self, similar: usize) -> Self {
        self.similar_pairs = similar;
        self
    }
}

// =============================================================================
// Path Serialization (T30: Custom path serializer for consistent JSON output)
// =============================================================================

/// Serialize PathBuf to a consistent string representation
fn serialize_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&path.display().to_string())
}

// =============================================================================
// HealthReport Struct
// =============================================================================

/// Complete health analysis report.
///
/// This is the top-level output from the health command, containing:
/// - The analyzed path
/// - Aggregated summary metrics
/// - Individual sub-analyzer results
/// - Total elapsed time
///
/// The sub_results field uses IndexMap (T24) to preserve insertion order
/// in JSON output for deterministic results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthReport {
    /// Wrapper identifier (always "health")
    pub wrapper: String,
    /// Analyzed path.
    ///
    /// cross-command-consistency-v1 (BUG-14): renamed in JSON to `root` so
    /// project-root field naming is identical across commands
    /// (`structure`, `deps`, `clones`, `health`, `secure`, `inheritance`,
    /// ...).  The Rust field is still `path` for compatibility, but JSON
    /// callers see `root`. The `alias` keeps deserialisation of older bodies
    /// working.
    #[serde(rename = "root", alias = "path", serialize_with = "serialize_path")]
    pub path: PathBuf,
    /// Detected or specified language
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Whether quick mode was used
    pub quick_mode: bool,
    /// Total elapsed time in milliseconds
    pub total_elapsed_ms: f64,
    /// Aggregated summary metrics
    pub summary: HealthSummary,
    /// Individual sub-analysis results (T24: IndexMap for deterministic ordering)
    #[serde(rename = "details")]
    pub sub_results: IndexMap<String, SubAnalysisResult>,
    /// Global errors that affected the entire analysis
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl HealthReport {
    /// Create a new health report
    pub fn new(path: PathBuf, language: Option<Language>, quick: bool) -> Self {
        Self {
            wrapper: "health".to_string(),
            path,
            language,
            quick_mode: quick,
            total_elapsed_ms: 0.0,
            summary: HealthSummary::new(),
            sub_results: IndexMap::new(),
            errors: Vec::new(),
        }
    }

    /// Add a sub-analysis result to the report
    pub fn add_sub_result(&mut self, result: SubAnalysisResult) {
        self.sub_results.insert(result.name.clone(), result);
    }

    /// Add a global error to the report
    pub fn with_error(mut self, error: String) -> Self {
        self.errors.push(error);
        self
    }

    /// Set the total elapsed time
    pub fn with_elapsed(mut self, elapsed_ms: f64) -> Self {
        self.total_elapsed_ms = elapsed_ms;
        self
    }

    /// Set the summary
    pub fn with_summary(mut self, summary: HealthSummary) -> Self {
        self.summary = summary;
        self
    }

    /// Convert to JSON-serializable value
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Get detailed data for a specific sub-analysis
    ///
    /// Valid sub_names: complexity, cohesion, dead, metrics, coupling, similar
    pub fn detail(&self, sub_name: &str) -> Option<&serde_json::Value> {
        self.sub_results
            .get(sub_name)
            .and_then(|r| r.details.as_ref())
    }

    /// Generate human-readable text output
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        // Header
        let path_str = self.path.display().to_string();
        let truncated_path = if path_str.len() > 60 {
            format!("...{}", &path_str[path_str.len() - 57..])
        } else {
            path_str
        };
        output.push_str(&format!("Health Report: {}\n", truncated_path));
        output.push_str(&"=".repeat(50));
        output.push('\n');

        // Complexity
        let cc_line = if let Some(avg) = self.summary.avg_cyclomatic {
            format!(
                "Complexity:  avg CC={:.1}, hotspots={} (CC>10)\n",
                avg, self.summary.hotspot_count
            )
        } else if let Some(result) = self.sub_results.get("complexity") {
            if !result.success {
                format!(
                    "Complexity:  {}\n",
                    result.error.as_deref().unwrap_or("failed")
                )
            } else {
                "Complexity:  no data\n".to_string()
            }
        } else {
            "Complexity:  not analyzed\n".to_string()
        };
        output.push_str(&cc_line);

        // Cohesion
        let coh_line = if let Some(avg) = self.summary.avg_lcom4 {
            format!(
                "Cohesion:    {} classes, avg LCOM4={:.1}, {} low-cohesion\n",
                self.summary.classes_analyzed, avg, self.summary.low_cohesion_count
            )
        } else if let Some(result) = self.sub_results.get("cohesion") {
            if !result.success {
                format!(
                    "Cohesion:    {}\n",
                    result.error.as_deref().unwrap_or("failed")
                )
            } else {
                "Cohesion:    no data\n".to_string()
            }
        } else {
            "Cohesion:    not analyzed\n".to_string()
        };
        output.push_str(&coh_line);

        // Coupling (full mode only)
        if !self.quick_mode {
            if self.summary.tight_coupling_pairs > 0 {
                output.push_str(&format!(
                    "Coupling:    {} tightly coupled pairs\n",
                    self.summary.tight_coupling_pairs
                ));
            } else if let Some(result) = self.sub_results.get("coupling") {
                if !result.success {
                    output.push_str(&format!(
                        "Coupling:    {}\n",
                        result.error.as_deref().unwrap_or("failed")
                    ));
                } else {
                    output.push_str("Coupling:    no tight coupling detected\n");
                }
            }
        }

        // Dead code
        let dead_line = if self.summary.dead_count > 0 {
            format!(
                "Dead Code:   {} unreachable functions\n",
                self.summary.dead_count
            )
        } else if let Some(result) = self.sub_results.get("dead") {
            if !result.success {
                format!(
                    "Dead Code:   {}\n",
                    result.error.as_deref().unwrap_or("failed")
                )
            } else {
                "Dead Code:   none detected\n".to_string()
            }
        } else {
            "Dead Code:   not analyzed\n".to_string()
        };
        output.push_str(&dead_line);

        // Similarity (full mode only)
        if !self.quick_mode {
            if self.summary.similar_pairs > 0 {
                output.push_str(&format!(
                    "Duplication: {} clone pairs detected\n",
                    self.summary.similar_pairs
                ));
            } else if let Some(result) = self.sub_results.get("similar") {
                if !result.success {
                    output.push_str(&format!(
                        "Duplication: {}\n",
                        result.error.as_deref().unwrap_or("failed")
                    ));
                } else {
                    output.push_str("Duplication: no clones detected\n");
                }
            }
        }

        // Martin metrics
        //
        // schema-cleanup-v1 BUG-9: the Martin (Robert C. Martin)
        // package-level abstractness/instability metric is computed only
        // for languages that surface a clear notion of a "package" with
        // a complete set of internal-vs-external dependencies (Java,
        // .NET assemblies, etc.). For Python / TypeScript / Go / Rust /
        // most others the analyzer always emits zero packages, which
        // historically rendered as "Metrics:     no data" (and the JSON
        // showed `packages_analyzed: 0` for every repo).
        //
        // To stop printing dead UI we now only emit the Metrics row
        // when there's actual data (avg_distance is Some) OR the sub-
        // analysis produced an explicit failure that the user should
        // see. The "no data" case is silently suppressed in text
        // output. JSON consumers can still inspect
        // `details.metrics.details.packages_analyzed` directly.
        if let Some(avg_d) = self.summary.avg_distance {
            output.push_str(&format!(
                "Metrics:     avg D={:.2} (distance from main sequence)\n",
                avg_d
            ));
        } else if let Some(result) = self.sub_results.get("metrics") {
            if !result.success {
                output.push_str(&format!(
                    "Metrics:     {}\n",
                    result.error.as_deref().unwrap_or("failed")
                ));
            }
            // success && no avg_distance: silently skip ("no data" is
            // dead UI for languages without true package boundaries).
        }
        // missing sub-result entirely: silently skip ("not analyzed").

        // Footer
        output.push('\n');
        output.push_str(&format!("Elapsed: {:.0}ms\n", self.total_elapsed_ms));

        // Errors
        if !self.errors.is_empty() {
            output.push_str(&format!("\nErrors: {}\n", self.errors.join(", ")));
        }

        output
    }
}

// =============================================================================
// Health Orchestrator - run_health() (Phase 6)
// =============================================================================

/// Run comprehensive health analysis on a codebase.
///
/// Aggregates 6 sub-analyzers (4 in quick mode, 6 in full mode):
/// - complexity (always)
/// - cohesion (always)
/// - dead_code (always)
/// - martin (always)
/// - coupling (full mode only)
/// - similarity (full mode only)
///
/// # Arguments
/// * `path` - Directory or file to analyze
/// * `language` - Optional language override (auto-detect if None)
/// * `options` - Health analysis options (thresholds, quick mode)
///
/// # Returns
/// * `Ok(HealthReport)` - Complete health report with all sub-analyses
/// * `Err(TldrError)` - If path doesn't exist or has no supported files
///
/// # T8 Mitigation: Graceful Error Handling
/// If one analyzer fails, others continue. Failed analyzers have success=false.
///
/// # T13 Mitigation: Shared Call Graph
/// Call graph is built once and shared across dead_code, coupling, similarity.
///
/// # Example
/// ```ignore
/// use tldr_core::quality::health::{run_health, HealthOptions};
/// use std::path::Path;
///
/// let options = HealthOptions::default();
/// let report = run_health(Path::new("src/"), None, options)?;
/// println!("Hotspots: {}", report.summary.hotspot_count);
/// ```
pub fn run_health(
    path: &Path,
    language: Option<Language>,
    options: HealthOptions,
) -> TldrResult<HealthReport> {
    let start = Instant::now();

    // Step 1: Validate path
    if !path.exists() {
        return Err(TldrError::PathNotFound(path.to_path_buf()));
    }

    // Step 2: Detect language if not specified (T3 mitigation; delegates to
    // the canonical `Language::from_path` / `Language::from_directory`
    // detectors — VAL-002).
    //
    // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): for a single
    // file, use `from_path_with_siblings` so a `.h` next to a `.cpp` is
    // routed through the cpp grammar. The plain `from_path` mapping
    // `.h → C` causes `structure` (which uses the sibling widening) and
    // `health` to disagree on cpp header files — breaking the M-016
    // invariant pinned by `cpp_health_cohesion_agree_on_header_file`.
    let detected_language = match language {
        Some(l) => l,
        None => {
            if path.is_file() {
                Language::from_path_with_siblings(path).ok_or_else(|| {
                    TldrError::UnsupportedLanguage(
                        path.extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                    )
                })?
            } else {
                Language::from_directory(path)
                    .ok_or_else(|| TldrError::NoSupportedFiles(path.to_path_buf()))?
            }
        }
    };

    // Create the report
    let mut report = HealthReport::new(path.to_path_buf(), Some(detected_language), options.quick);

    // Step 3: Build call graph ONCE (T13 mitigation)
    // This is shared across dead_code, coupling, and similarity
    let call_graph_result = build_project_call_graph(path, detected_language, None, true);
    let (call_graph, call_graph_error) = match call_graph_result {
        Ok(g) => (Some(g), None),
        Err(e) => (None, Some(e.to_string())),
    };

    // Collect module infos for dead code analysis (needed alongside call graph)
    let module_infos = collect_module_infos(path, detected_language);

    // Step 4: Run sub-analyzers with timing and graceful error handling (T8)

    // ----- COMPLEXITY (always) -----
    let complexity_result = run_with_timing("complexity", || {
        let opts = ComplexityOptions {
            hotspot_threshold: options.complexity_threshold,
            ..Default::default()
        };
        analyze_complexity(path, Some(detected_language), Some(opts))
    });
    report.add_sub_result(complexity_result);

    // ----- COHESION (always) -----
    let cohesion_result = run_with_timing("cohesion", || {
        analyze_cohesion(path, Some(detected_language), options.cohesion_threshold)
    });
    report.add_sub_result(cohesion_result);

    // ----- DEAD CODE (always, uses refcount-based analysis) -----
    let dead_result = if !module_infos.is_empty() {
        run_with_timing("dead", || {
            analyze_dead_code_with_refcount(
                path,
                detected_language,
                &module_infos,
                &["main", "test_"],
            )
        })
    } else {
        SubAnalysisResult::failure("dead", 0.0, "No module infos collected")
    };
    report.add_sub_result(dead_result);

    // ----- MARTIN METRICS (always) -----
    let martin_result = run_with_timing("metrics", || {
        compute_martin_metrics(path, Some(detected_language))
    });
    report.add_sub_result(martin_result);

    // ----- COUPLING (full mode only) -----
    if options.quick {
        report.add_sub_result(SubAnalysisResult::skipped("coupling"));
    } else {
        let coupling_result = if let Some(ref cg) = call_graph {
            run_with_timing("coupling", || {
                let opts = CouplingOptions {
                    max_pairs: options.max_items,
                    ..Default::default()
                };
                analyze_coupling_with_graph(path, detected_language, cg, &opts)
            })
        } else {
            let error_msg = call_graph_error
                .clone()
                .unwrap_or_else(|| "Call graph not available".to_string());
            SubAnalysisResult::failure("coupling", 0.0, error_msg)
        };
        report.add_sub_result(coupling_result);
    }

    // ----- CLONES (full mode only) -----
    // Uses tree-sitter AST-based clone detection (T1/T2/T3) instead of the old
    // similarity analysis which compared all function pairs and produced misleading
    // counts (e.g. 104K "similar" pairs on a 265K-line codebase).
    if options.quick {
        report.add_sub_result(SubAnalysisResult::skipped("similar"));
    } else {
        let clones_start = Instant::now();
        let clones_result = {
            let opts = ClonesOptions {
                max_clones: options.max_items,
                exclude_tests: true,
                ..Default::default()
            };
            match detect_clones(path, &opts) {
                Ok(report) => {
                    let elapsed_ms = clones_start.elapsed().as_secs_f64() * 1000.0;
                    let count = report.clone_pairs.len();
                    let details = serde_json::to_value(&report).ok();
                    SubAnalysisResult {
                        name: "similar".to_string(),
                        success: true,
                        elapsed_ms,
                        error: None,
                        findings_count: count,
                        details,
                    }
                }
                Err(e) => SubAnalysisResult {
                    name: "similar".to_string(),
                    success: false,
                    elapsed_ms: clones_start.elapsed().as_secs_f64() * 1000.0,
                    error: Some(e.to_string()),
                    findings_count: 0,
                    details: None,
                },
            }
        };
        report.add_sub_result(clones_result);
    }

    // Step 5: Aggregate summary from sub-results
    let mut summary = aggregate_summary(&report.sub_results);

    // HEALTH-FILES-ANALYZED-COUNTER-V1: `files_analyzed` is not produced
    // by any individual sub-analyzer's `details` payload (complexity →
    // `functions_analyzed`, cohesion → `classes_analyzed`, etc.), so
    // `aggregate_summary` always left it at 0. Populate it here from a
    // direct extension-filtered walk of the input path against
    // `detected_language.extensions()` — same source-of-truth used by
    // `collect_module_infos` / `vuln`'s `files_scanned`.
    summary.files_analyzed = count_source_files(path, detected_language);

    // health-dashboard-v1 (v0.4.2 M-016): canonicalize class/function
    // counters against `tldr structure` (the AST projection from M-006).
    // The cohesion sub-analyzer reports only classes that participate
    // in cohesion analysis (0 for many languages); the complexity
    // sub-analyzer counts only functions whose CFG was built. Both
    // disagreed with structure in the Phase-22 audit.
    canonicalize_counters_from_structure(&mut summary, path, detected_language);

    // health-dashboard-v1 (v0.4.2 M-016): compute the aggregated
    // 0-100 health score. Done AFTER canonicalisation so the smells
    // ratio uses the corrected `functions_analyzed`.
    summary.score = compute_health_score(&summary, options.complexity_threshold);

    report.summary = summary;

    // Step 6: Record total elapsed time (T28: use as_secs_f64)
    report.total_elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(report)
}

/// Run a sub-analyzer with timing and error capture (T8 mitigation).
///
/// This helper wraps analyzer calls to:
/// 1. Time the execution
/// 2. Catch errors gracefully
/// 3. Return a consistent SubAnalysisResult
fn run_with_timing<T, F>(name: &str, f: F) -> SubAnalysisResult
where
    F: FnOnce() -> TldrResult<T>,
    T: Serialize + AnalysisMetrics,
{
    let start = Instant::now();
    match f() {
        Ok(result) => {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let findings_count = result.findings_count();
            let details = serde_json::to_value(&result).ok();
            SubAnalysisResult {
                name: name.to_string(),
                success: true,
                elapsed_ms,
                error: None,
                findings_count,
                details,
            }
        }
        Err(e) => SubAnalysisResult {
            name: name.to_string(),
            success: false,
            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: Some(e.to_string()),
            findings_count: 0,
            details: None,
        },
    }
}

/// Trait for extracting metrics counts from analyzer results.
trait AnalysisMetrics {
    fn findings_count(&self) -> usize;
}

impl AnalysisMetrics for ComplexityReport {
    fn findings_count(&self) -> usize {
        self.hotspot_count
    }
}

impl AnalysisMetrics for CohesionReport {
    fn findings_count(&self) -> usize {
        self.low_cohesion_count
    }
}

impl AnalysisMetrics for DeadCodeReport {
    fn findings_count(&self) -> usize {
        self.dead_count
    }
}

impl AnalysisMetrics for MartinReport {
    fn findings_count(&self) -> usize {
        self.packages_in_pain_zone + self.packages_in_uselessness_zone
    }
}

impl AnalysisMetrics for CouplingReport {
    fn findings_count(&self) -> usize {
        self.tight_coupling_count
    }
}

/// Count source files at `path` matching `language`'s extensions.
///
/// HEALTH-FILES-ANALYZED-COUNTER-V1: this is the authoritative source
/// for `HealthSummary::files_analyzed`. It mirrors the extension filter
/// used by `collect_module_infos` (and by sub-analyzers like complexity)
/// but counts unconditionally — a file that fails to parse / extract
/// still counts as "analyzed" because it was visited by the pipeline.
/// This matches the semantics of `vuln`'s `files_scanned` counter.
fn count_source_files(path: &Path, language: Language) -> usize {
    let extensions = language.extensions();

    if path.is_file() {
        return match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => {
                let ext_with_dot = format!(".{}", ext);
                if extensions.contains(&ext_with_dot.as_str()) {
                    1
                } else {
                    0
                }
            }
            None => 0,
        };
    }

    let mut count = 0usize;
    // cross-cutting-and-clear-fix-bugs-v1 (P18.X4): pass the language hint
    // so JS/TS projects with sources under `src/build/` are not silently
    // skipped before extension filtering.
    for entry in ProjectWalker::new(path).lang_hint(language).iter() {
        let file_path = entry.path();
        if file_path.is_file() {
            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                let ext_with_dot = format!(".{}", ext);
                if extensions.contains(&ext_with_dot.as_str()) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Collect module infos for dead code analysis.
fn collect_module_infos(path: &Path, language: Language) -> Vec<(PathBuf, ModuleInfo)> {
    let mut module_infos: Vec<(PathBuf, ModuleInfo)> = Vec::new();
    let extensions = language.extensions();

    if path.is_file() {
        if let Ok(info) = extract_file(path, path.parent()) {
            module_infos.push((path.to_path_buf(), info));
        }
    } else {
        // cross-cutting-and-clear-fix-bugs-v1 (P18.X4): JS/TS hint so
        // `src/build/*.ts` is included.
        for entry in ProjectWalker::new(path).lang_hint(language).iter() {
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    let ext_with_dot = format!(".{}", ext);
                    if extensions.contains(&ext_with_dot.as_str()) {
                        if let Ok(info) = extract_file(file_path, Some(path)) {
                            module_infos.push((file_path.to_path_buf(), info));
                        }
                    }
                }
            }
        }
    }

    module_infos
}

/// Aggregate summary metrics from sub-analysis results.
fn aggregate_summary(sub_results: &IndexMap<String, SubAnalysisResult>) -> HealthSummary {
    let mut summary = HealthSummary::new();

    // Extract complexity metrics
    if let Some(result) = sub_results.get("complexity") {
        if result.success {
            if let Some(ref details) = result.details {
                if let Some(avg) = details.get("avg_cyclomatic").and_then(|v| v.as_f64()) {
                    summary.avg_cyclomatic = Some(avg);
                }
                if let Some(count) = details.get("hotspot_count").and_then(|v| v.as_u64()) {
                    summary.hotspot_count = count as usize;
                }
                if let Some(count) = details.get("functions_analyzed").and_then(|v| v.as_u64()) {
                    summary.functions_analyzed = count as usize;
                }
            }
        }
    }

    // Extract cohesion metrics
    if let Some(result) = sub_results.get("cohesion") {
        if result.success {
            if let Some(ref details) = result.details {
                if let Some(avg) = details.get("avg_lcom4").and_then(|v| v.as_f64()) {
                    summary.avg_lcom4 = Some(avg);
                }
                if let Some(count) = details.get("low_cohesion_count").and_then(|v| v.as_u64()) {
                    summary.low_cohesion_count = count as usize;
                }
                if let Some(count) = details.get("classes_analyzed").and_then(|v| v.as_u64()) {
                    summary.classes_analyzed = count as usize;
                }
            }
        }
    }

    // Extract dead code metrics
    if let Some(result) = sub_results.get("dead") {
        if result.success {
            if let Some(ref details) = result.details {
                if let Some(count) = details.get("dead_count").and_then(|v| v.as_u64()) {
                    summary.dead_count = count as usize;
                }
                if let Some(pct) = details.get("dead_percentage").and_then(|v| v.as_f64()) {
                    summary.dead_percentage = Some(pct);
                }
            }
        }
    }

    // Extract martin metrics
    if let Some(result) = sub_results.get("metrics") {
        if result.success {
            if let Some(ref details) = result.details {
                if let Some(avg) = details.get("avg_distance").and_then(|v| v.as_f64()) {
                    summary.avg_distance = Some(avg);
                }
                if let Some(count) = details
                    .get("packages_in_pain_zone")
                    .and_then(|v| v.as_u64())
                {
                    summary.packages_in_pain_zone = count as usize;
                }
            }
        }
    }

    // Extract coupling metrics (full mode only)
    if let Some(result) = sub_results.get("coupling") {
        if result.success {
            if let Some(ref details) = result.details {
                if let Some(count) = details.get("tight_coupling_count").and_then(|v| v.as_u64()) {
                    summary.tight_coupling_pairs = count as usize;
                }
            }
        }
    }

    // Extract clone detection metrics (full mode only)
    if let Some(result) = sub_results.get("similar") {
        if result.success {
            // Use findings_count directly (set by run_with_timing from ClonesReport)
            summary.similar_pairs = result.findings_count;
        }
    }

    summary
}

/// Canonicalize `classes_analyzed` and `functions_analyzed` against the
/// `tldr structure` AST projection (M-006).
///
/// health-dashboard-v1 (v0.4.2 M-016): the cohesion sub-analyzer reports
/// only classes that participate in cohesion analysis (typically zero
/// for languages where it isn't implemented or for codebases without
/// detectable class-internal coupling). The complexity sub-analyzer
/// counts only functions whose CFG was successfully built. Both
/// counters disagreed wildly with `tldr structure`:
///   - kotlin-datetime: structure 476 classes, health-via-cohesion 0
///   - swift-collections: structure 1998 classes, health-via-cohesion 0
///   - ts-dom-gen: structure 0 classes, health-via-cohesion 1
///
/// Canonicalise both counters against the AST projection that
/// downstream tooling (and M-006's `files[].functions` schema) treats
/// as the source of truth: sum of `files[].classes.len()` and sum of
/// `files[].definitions[kind=="function"].len()` across the corpus.
///
/// On failure (e.g. unsupported language for `get_code_structure`),
/// leaves the existing counters in place rather than panicking.
fn canonicalize_counters_from_structure(
    summary: &mut HealthSummary,
    path: &Path,
    language: Language,
) {
    let structure = match get_code_structure(path, language, 0, Some(&IgnoreSpec::default())) {
        Ok(s) => s,
        Err(_) => return,
    };

    let classes_total: usize = structure.files.iter().map(|f| f.classes.len()).sum();

    // v0.5.0 SOL-015b M9 (solidity-sol015b-health-clones-smells-v1):
    // Solidity emits contract/interface/library member functions as
    // `kind="method"` (see `collect_definitions` in
    // `ast/extractor.rs`) AND `extract_solidity_functions` routes
    // contract members through `extract_methods` rather than
    // `extract_functions`. Counting only `kind=="function"` here
    // caused `health.summary.functions_analyzed` to report 0 for
    // every Solidity file whose functions all live inside a contract
    // — even though the underlying complexity sub-analyzer happily
    // computed cyclomatic / cognitive metrics for each one. Walk
    // ClassInfo.methods (surfaced as kind="method" definitions) so
    // contract members count toward the corpus-wide function total.
    //
    // For non-Solidity languages the previous (function-only) count
    // is preserved verbatim — the Phase-22 health-dashboard-v1
    // invariant `summary.functions_analyzed == sum(files[].functions.len())`
    // continues to hold across the kotlin / swift / typescript / cpp /
    // java / go / javascript corpora pinned by `health_dashboard_v1.rs`.
    let functions_total: usize = structure
        .files
        .iter()
        .map(|f| {
            f.definitions
                .iter()
                .filter(|d| {
                    if matches!(language, Language::Solidity) {
                        // Contract members appear as `method` and free
                        // functions as `function`. Both contribute to
                        // the function-axis count.
                        d.kind == "function" || d.kind == "method"
                    } else {
                        d.kind == "function"
                    }
                })
                .count()
        })
        .sum();

    summary.classes_analyzed = classes_total;
    summary.functions_analyzed = functions_total;
}

/// Compute the overall health score (0-100).
///
/// health-dashboard-v1 (v0.4.2 M-016): weighted average of three
/// normalised buckets:
///   * 33% complexity
///   * 33% dead-code
///   * 34% smells/hotspots
///
/// Each bucket reports a 0-100 sub-score (100 = best, 0 = worst).
/// When the underlying signal is missing (sub-analyzer failed/skipped
/// or no functions in the corpus), the bucket degrades to a neutral
/// 50 so it doesn't dominate the final result.
///
/// Returns `None` when `functions_analyzed == 0` AND `classes_analyzed
/// == 0` (genuinely empty corpus — no signal to score).
fn compute_health_score(
    summary: &HealthSummary,
    complexity_threshold: usize,
) -> Option<u8> {
    if summary.functions_analyzed == 0 && summary.classes_analyzed == 0 {
        return None;
    }

    // ----- Complexity bucket -----
    // avg_cyclomatic at/below threshold/2 ⇒ 100; at/above 2*threshold ⇒ 0.
    let complexity_score = match summary.avg_cyclomatic {
        Some(avg) => {
            let t = complexity_threshold.max(1) as f64;
            let low = t / 2.0;
            let high = t * 2.0;
            if avg <= low {
                100.0
            } else if avg >= high {
                0.0
            } else {
                // Linear interpolation: at low ⇒ 100, at high ⇒ 0.
                100.0 * (1.0 - (avg - low) / (high - low))
            }
        }
        None => 50.0,
    };

    // ----- Dead-code bucket -----
    // dead% == 0 ⇒ 100; dead% >= 25 ⇒ 0.
    let dead_score = match summary.dead_percentage {
        Some(pct) => {
            if pct <= 0.0 {
                100.0
            } else if pct >= 25.0 {
                0.0
            } else {
                100.0 * (1.0 - pct / 25.0)
            }
        }
        None => 50.0,
    };

    // ----- Smells/hotspots bucket -----
    // ratio = hotspot_count / functions_analyzed.
    // ratio == 0 ⇒ 100; ratio >= 0.25 ⇒ 0.
    let smells_score = if summary.functions_analyzed > 0 {
        let ratio =
            summary.hotspot_count as f64 / summary.functions_analyzed as f64;
        if ratio <= 0.0 {
            100.0
        } else if ratio >= 0.25 {
            0.0
        } else {
            100.0 * (1.0 - ratio / 0.25)
        }
    } else {
        50.0
    };

    // Weighted average: 33 / 33 / 34 (sums to 100).
    let weighted = (complexity_score * 33.0 + dead_score * 33.0 + smells_score * 34.0) / 100.0;

    // Clamp + round to u8.
    let clamped = weighted.clamp(0.0, 100.0);
    Some(clamped.round() as u8)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        // T6: Verify severity ordering Critical > High > Medium > Low > Info
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);

        // Test is_at_least
        assert!(Severity::Critical.is_at_least(Severity::High));
        assert!(Severity::High.is_at_least(Severity::High));
        assert!(!Severity::Medium.is_at_least(Severity::High));
    }

    #[test]
    fn test_severity_comparison() {
        let severities = vec![
            Severity::Medium,
            Severity::Critical,
            Severity::Low,
            Severity::High,
            Severity::Info,
        ];
        let mut sorted = severities.clone();
        sorted.sort();

        assert_eq!(
            sorted,
            vec![
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
    }

    #[test]
    fn test_threshold_preset_defaults() {
        // Test Default preset thresholds via helper functions
        assert_eq!(complexity_threshold_for(ThresholdPreset::Default), 10);
        assert_eq!(cohesion_threshold_for(ThresholdPreset::Default), 2);
        assert!((similarity_threshold_for(ThresholdPreset::Default) - 0.7).abs() < 0.001);

        // Test Strict preset thresholds
        assert_eq!(complexity_threshold_for(ThresholdPreset::Strict), 8);
        assert_eq!(cohesion_threshold_for(ThresholdPreset::Strict), 1);

        // Test Relaxed (lenient) preset thresholds
        assert_eq!(complexity_threshold_for(ThresholdPreset::Relaxed), 15);
        assert_eq!(cohesion_threshold_for(ThresholdPreset::Relaxed), 3);
    }

    #[test]
    fn test_health_report_structure() {
        let report = HealthReport::new(PathBuf::from("src/"), Some(Language::Python), false);

        assert_eq!(report.wrapper, "health");
        assert_eq!(report.path, PathBuf::from("src/"));
        assert_eq!(report.language, Some(Language::Python));
        assert!(!report.quick_mode);
        assert!(report.sub_results.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_health_summary_aggregation() {
        let summary = HealthSummary::new()
            .with_complexity(Some(5.5), 3)
            .with_cohesion(Some(1.5), 2, 10)
            .with_dead_code(5, 100)
            .with_martin(Some(0.25), 1)
            .with_coupling(2)
            .with_similarity(4);

        assert_eq!(summary.avg_cyclomatic, Some(5.5));
        assert_eq!(summary.hotspot_count, 3);
        assert_eq!(summary.avg_lcom4, Some(1.5));
        assert_eq!(summary.low_cohesion_count, 2);
        assert_eq!(summary.classes_analyzed, 10);
        assert_eq!(summary.dead_count, 5);
        assert!((summary.dead_percentage.unwrap() - 5.0).abs() < 0.001);
        assert_eq!(summary.functions_analyzed, 100);
        assert_eq!(summary.avg_distance, Some(0.25));
        assert_eq!(summary.packages_in_pain_zone, 1);
        assert_eq!(summary.tight_coupling_pairs, 2);
        assert_eq!(summary.similar_pairs, 4);
    }

    #[test]
    fn test_sub_analysis_result_structure() {
        let success =
            SubAnalysisResult::success("complexity", 150.5, 10, serde_json::json!({"avg": 5.5}));
        assert!(success.success);
        assert_eq!(success.name, "complexity");
        assert!((success.elapsed_ms - 150.5).abs() < 0.001);
        assert!(success.error.is_none());
        assert_eq!(success.findings_count, 10);
        assert!(success.details.is_some());

        let failure = SubAnalysisResult::failure("cohesion", 50.0, "parse error");
        assert!(!failure.success);
        assert_eq!(failure.error, Some("parse error".to_string()));
        assert!(failure.details.is_none());

        let skipped = SubAnalysisResult::skipped("coupling");
        assert!(!skipped.success);
        assert!(skipped.error.as_ref().unwrap().contains("quick mode"));
        assert_eq!(skipped.elapsed_ms, 0.0);
    }

    #[test]
    fn test_health_report_add_sub_result() {
        let mut report = HealthReport::new(PathBuf::from("src/"), None, false);

        let complexity =
            SubAnalysisResult::success("complexity", 100.0, 5, serde_json::json!({"hotspots": 2}));
        report.add_sub_result(complexity);

        assert_eq!(report.sub_results.len(), 1);
        assert!(report.sub_results.contains_key("complexity"));
    }

    #[test]
    fn test_health_report_to_text() {
        let mut report = HealthReport::new(PathBuf::from("src/"), Some(Language::Python), false);
        report.total_elapsed_ms = 1234.0;
        report.summary = HealthSummary::new()
            .with_complexity(Some(5.2), 3)
            .with_cohesion(Some(1.5), 2, 12)
            .with_dead_code(5, 50);

        let text = report.to_text();

        assert!(text.contains("Health Report: src/"));
        assert!(text.contains("avg CC=5.2"));
        assert!(text.contains("hotspots=3"));
        assert!(text.contains("12 classes"));
        assert!(text.contains("LCOM4=1.5"));
        assert!(text.contains("5 unreachable"));
        assert!(text.contains("1234ms"));
    }

    #[test]
    fn test_health_report_detail_method() {
        let mut report = HealthReport::new(PathBuf::from("src/"), None, false);

        let complexity = SubAnalysisResult::success(
            "complexity",
            100.0,
            5,
            serde_json::json!({"hotspots": [{"name": "func1", "cc": 15}]}),
        );
        report.add_sub_result(complexity);

        // Should find complexity details
        let detail = report.detail("complexity");
        assert!(detail.is_some());
        assert!(detail.unwrap()["hotspots"].is_array());

        // Should return None for non-existent
        assert!(report.detail("nonexistent").is_none());
    }

    #[test]
    fn test_health_options_default() {
        let opts = HealthOptions::default();

        assert!(!opts.quick);
        assert_eq!(opts.preset, ThresholdPreset::Default);
        assert_eq!(opts.complexity_threshold, 10);
        assert_eq!(opts.cohesion_threshold, 2);
        assert!((opts.similarity_threshold - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_health_options_with_preset() {
        let strict = HealthOptions::with_preset(ThresholdPreset::Strict);
        assert_eq!(strict.complexity_threshold, 8);
        assert_eq!(strict.cohesion_threshold, 1);
        assert!((strict.similarity_threshold - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_health_options_quick() {
        let quick = HealthOptions::quick();
        assert!(quick.quick);
    }

    #[test]
    fn test_health_report_json_serialization() {
        let mut report = HealthReport::new(PathBuf::from("test/"), Some(Language::Python), true);
        report.summary = HealthSummary::new().with_complexity(Some(5.0), 2);

        let json = report.to_dict();

        assert_eq!(json["wrapper"], "health");
        // cross-command-consistency-v1 (BUG-14): canonical key is `root`.
        assert_eq!(json["root"], "test/");
        assert_eq!(json["quick_mode"], true);
        assert_eq!(json["summary"]["avg_cyclomatic"], 5.0);
        assert_eq!(json["summary"]["hotspot_count"], 2);
        // T4: sub_results should be serialized as "details"
        assert!(json.get("details").is_some());
    }

    /// HEALTH-FILES-ANALYZED-COUNTER-V1: ensure `count_source_files`
    /// returns the right count for a directory of mixed extensions.
    #[test]
    fn test_count_source_files_directory() {
        use std::fs;
        let temp = tempfile::TempDir::new().unwrap();
        let p = temp.path();
        fs::write(p.join("a.py"), "def f(): pass\n").unwrap();
        fs::write(p.join("b.py"), "def g(): pass\n").unwrap();
        fs::write(p.join("c.py"), "def h(): pass\n").unwrap();
        fs::write(p.join("notes.txt"), "ignored\n").unwrap();
        fs::write(p.join("setup.cfg"), "ignored\n").unwrap();

        let count = count_source_files(p, Language::Python);
        assert_eq!(count, 3, "expected 3 .py files, got {}", count);
    }

    /// HEALTH-FILES-ANALYZED-COUNTER-V1: full `run_health` pass on a
    /// multi-file Python directory must report `files_analyzed > 0`.
    /// Pre-fix this assertion failed with `files_analyzed: 0` while
    /// `functions_analyzed` and `classes_analyzed` were populated
    /// correctly.
    #[test]
    fn test_run_health_files_analyzed_populated() {
        use std::fs;
        let temp = tempfile::TempDir::new().unwrap();
        let p = temp.path();
        fs::write(
            p.join("a.py"),
            "class A:\n    def m(self):\n        return 1\n",
        )
        .unwrap();
        fs::write(
            p.join("b.py"),
            "class B:\n    def n(self):\n        return 2\n",
        )
        .unwrap();
        fs::write(p.join("c.py"), "def free():\n    return 3\n").unwrap();

        let opts = HealthOptions {
            quick: true, // skip coupling/similarity for test speed
            ..HealthOptions::default()
        };
        let report = run_health(p, Some(Language::Python), opts).unwrap();
        assert_eq!(
            report.summary.files_analyzed, 3,
            "expected 3 files_analyzed, got {} (functions={}, classes={})",
            report.summary.files_analyzed,
            report.summary.functions_analyzed,
            report.summary.classes_analyzed,
        );
    }

    /// schema-naming-and-units-v1: text and JSON outputs must agree on
    /// `tight_coupling_pairs` for a given report instance. Both formats
    /// must read from the same source of truth (`HealthSummary`), not
    /// from divergent helper paths. A regression where text reads
    /// `findings_count` while JSON reads the summary field would produce
    /// off-by-one disagreements between formats.
    #[test]
    fn test_health_format_consistency() {
        let summary = HealthSummary::new()
            .with_complexity(Some(5.5), 3)
            .with_cohesion(Some(1.5), 2, 10)
            .with_dead_code(5, 100)
            .with_martin(Some(0.25), 1)
            .with_coupling(7) // <-- the value under test
            .with_similarity(4);

        let report = HealthReport::new(PathBuf::from("test/"), None, false)
            .with_summary(summary)
            .with_elapsed(123.0);

        // JSON view: `summary.tight_coupling_pairs` is the canonical field.
        let json = report.to_dict();
        let json_pairs = json
            .get("summary")
            .and_then(|s| s.get("tight_coupling_pairs"))
            .and_then(|v| v.as_u64())
            .expect("summary.tight_coupling_pairs missing in JSON");
        assert_eq!(json_pairs, 7, "JSON must reflect the configured count");

        // Text view: must extract the same number, formatted as the
        // user-visible "N tightly coupled pairs" line.
        let text = report.to_text();
        let line = text
            .lines()
            .find(|l| l.contains("tightly coupled pairs"))
            .expect(
                "text output must include a 'tightly coupled pairs' line when count > 0",
            );

        // Parse the leading integer out of "Coupling:    N tightly coupled pairs".
        let text_pairs: u64 = line
            .split_whitespace()
            .find_map(|tok| tok.parse::<u64>().ok())
            .expect("text line must contain an integer count");

        assert_eq!(
            text_pairs, json_pairs,
            "text format and JSON must agree on tight_coupling_pairs (same source of truth)\n\
             text line: {line:?}\n\
             json:      {json_pairs}"
        );
    }

    /// schema-naming-and-units-v1: text and JSON must agree on every
    /// `HealthSummary` numeric the text formatter prints. This generalises
    /// `test_health_format_consistency` beyond the coupling pair count to
    /// guard against future bugs where text reads from a different field.
    #[test]
    fn test_health_format_consistency_all_summary_fields() {
        let summary = HealthSummary::new()
            .with_complexity(Some(7.25), 4)
            .with_cohesion(Some(2.0), 3, 12)
            .with_dead_code(6, 100)
            .with_martin(Some(0.40), 2)
            .with_coupling(11)
            .with_similarity(5);

        let report = HealthReport::new(PathBuf::from("proj/"), None, false)
            .with_summary(summary.clone())
            .with_elapsed(99.0);

        let text = report.to_text();
        let json = report.to_dict();
        let json_summary = json.get("summary").expect("summary present");

        // Coupling
        let json_coupling = json_summary
            .get("tight_coupling_pairs")
            .and_then(|v| v.as_u64())
            .unwrap();
        let text_coupling: u64 = text
            .lines()
            .find(|l| l.contains("tightly coupled pairs"))
            .and_then(|l| l.split_whitespace().find_map(|t| t.parse::<u64>().ok()))
            .expect("coupling line missing");
        assert_eq!(text_coupling, json_coupling);

        // Similarity (clone pairs)
        let json_similar = json_summary
            .get("similar_pairs")
            .and_then(|v| v.as_u64())
            .unwrap();
        let text_similar: u64 = text
            .lines()
            .find(|l| l.contains("clone pairs detected"))
            .and_then(|l| l.split_whitespace().find_map(|t| t.parse::<u64>().ok()))
            .expect("duplication line missing");
        assert_eq!(text_similar, json_similar);

        // Dead code
        let json_dead = json_summary
            .get("dead_count")
            .and_then(|v| v.as_u64())
            .unwrap();
        let text_dead: u64 = text
            .lines()
            .find(|l| l.contains("unreachable functions"))
            .and_then(|l| l.split_whitespace().find_map(|t| t.parse::<u64>().ok()))
            .expect("dead code line missing");
        assert_eq!(text_dead, json_dead);
    }

    #[test]
    fn test_indexmap_preserves_order() {
        let mut report = HealthReport::new(PathBuf::from("test/"), None, false);

        // Add in specific order
        report.add_sub_result(SubAnalysisResult::skipped("complexity"));
        report.add_sub_result(SubAnalysisResult::skipped("cohesion"));
        report.add_sub_result(SubAnalysisResult::skipped("dead"));
        report.add_sub_result(SubAnalysisResult::skipped("metrics"));
        report.add_sub_result(SubAnalysisResult::skipped("coupling"));
        report.add_sub_result(SubAnalysisResult::skipped("similar"));

        // T24: IndexMap should preserve insertion order
        let keys: Vec<_> = report.sub_results.keys().collect();
        assert_eq!(
            keys,
            vec![
                "complexity",
                "cohesion",
                "dead",
                "metrics",
                "coupling",
                "similar"
            ]
        );
    }
}
