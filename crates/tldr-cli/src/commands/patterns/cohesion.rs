//! Cohesion command - LCOM4 (Lack of Cohesion of Methods) analysis for Python classes.
//!
//! LCOM4 measures class cohesion by counting connected components in the method-field graph:
//! - LCOM4 = 1: All methods are connected (cohesive class)
//! - LCOM4 > 1: Methods form disconnected groups (split candidate)
//!
//! # Algorithm
//!
//! 1. Parse class, extract methods and field accesses (`self.x`)
//! 2. Build bipartite graph: methods <-> fields they access
//! 3. Add edges for intra-class method calls (`self.method()`)
//! 4. Count connected components via union-find with path compression
//!
//! # TIGER Mitigations
//!
//! - **T06**: Union-find with path compression AND union by rank
//! - **E01**: `--timeout` flag (default 30s)
//! - **E04**: `MAX_METHODS_PER_CLASS` and `MAX_FIELDS_PER_CLASS` limits
//! - **E05**: `MAX_ITERATIONS` for union-find operations
//!
//! # Example
//!
//! ```bash
//! tldr cohesion src/models.py
//! tldr cohesion src/models.py --min-methods 3 --include-dunder
//! tldr cohesion src/ --format text
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Args, ValueEnum};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tldr_core::walker::walk_project;

use tldr_core::quality::cohesion as core_cohesion;
use tldr_core::types::Language;

use crate::output::{common_path_prefix, strip_prefix_display, OutputFormat as GlobalOutputFormat};

use super::error::{PatternsError, PatternsResult};
use super::types::{
    ClassCohesion, CohesionReport, CohesionSummary, CohesionVerdict, ComponentInfo,
};
use super::validation::{
    validate_directory_path, validate_file_path, validate_file_path_in_project, MAX_DIRECTORY_FILES,
};

// =============================================================================
// Constants (TIGER/ELEPHANT Mitigations)
// =============================================================================

/// Default timeout in seconds (E01)
const DEFAULT_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// Output Format
// =============================================================================

/// Output format for cohesion command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON output (default)
    #[default]
    Json,
    /// Human-readable text output
    Text,
}

// =============================================================================
// CLI Arguments
// =============================================================================

/// Compute LCOM4 (Lack of Cohesion of Methods) metric for Python classes.
///
/// LCOM4 measures class cohesion by counting connected components in the
/// method-field bipartite graph. A cohesive class has LCOM4 = 1, while
/// a class with LCOM4 > 1 is a candidate for splitting.
///
/// # Example
///
/// ```bash
/// tldr cohesion src/models.py
/// tldr cohesion src/models.py --min-methods 3
/// tldr cohesion src/ --format text
/// ```
#[derive(Debug, Args)]
pub struct CohesionArgs {
    /// File or directory to analyze
    pub path: PathBuf,

    /// Minimum number of instance methods for a class to be included in analysis.
    /// Classes with fewer methods are filtered from results. For Rust and Go,
    /// only instance methods (with self/receiver) are counted, not associated
    /// functions like new() or default().
    #[arg(long, default_value = "1")]
    pub min_methods: u32,

    /// Include dunder methods (__init__, __str__, etc.) in analysis
    #[arg(long)]
    pub include_dunder: bool,

    /// Output format (json or text). Prefer global --format/-f flag.
    #[arg(
        long = "output-format",
        alias = "output",
        short = 'o',
        hide = true,
        value_enum,
        default_value = "json"
    )]
    pub output_format: OutputFormat,

    /// Analysis timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,

    /// Project root for path validation (optional)
    #[arg(long)]
    pub project_root: Option<PathBuf>,

    /// Language filter (auto-detected if omitted)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,
}

impl CohesionArgs {
    /// Run the cohesion analysis command
    pub fn run(&self, global_format: GlobalOutputFormat) -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(self.timeout);

        // Validate path
        let canonical_path = if let Some(ref root) = self.project_root {
            validate_file_path_in_project(&self.path, root)?
        } else {
            validate_file_path(&self.path)?
        };

        // Analyze based on path type
        let mut report = if canonical_path.is_dir() {
            analyze_directory(&canonical_path, self, start, timeout, MAX_DIRECTORY_FILES)?
        } else {
            analyze_single_file(&canonical_path, self)?
        };

        // (path-and-schema-cleanup-v3 P3.BUG-N2) When the user supplied
        // a single file path, echo it verbatim in each class's
        // `file_path`. The canonical path was used for the read above,
        // but downstream consumers expect the JSON to mirror the input
        // (no `/tmp/...` -> `/private/tmp/...` rewrite on macOS).
        // Directory mode skips this — each file there is the resolved
        // path of a walker entry, not user-supplied.
        if !canonical_path.is_dir() {
            let user_path_str = self.path.display().to_string();
            for class in &mut report.classes {
                class.file_path = user_path_str.clone();
            }
        }

        // Emit an explicit truncation warning to stderr when the Python
        // per-file walk was bounded by the file cap (graceful degradation —
        // results on stdout stay valid, exit code stays 0). Mirrors the
        // `dead`-command scan-cap warning.
        if report.truncated == Some(true) {
            eprintln!(
                "Warning: cohesion scan truncated at {} Python files (limit {}) in {} — \
                 results are partial; non-Python files are unaffected",
                report.files_scanned.unwrap_or(0),
                report.files_limit.unwrap_or(0),
                self.path.display(),
            );
        }

        // Resolve format: global -f flag takes priority over hidden --output-format
        let use_text = matches!(global_format, GlobalOutputFormat::Text)
            || matches!(self.output_format, OutputFormat::Text);

        // Output based on format
        if use_text {
            let text = format_cohesion_text(&report);
            println!("{}", text);
        } else {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }

        Ok(())
    }
}

// =============================================================================
// Core Analysis Functions
// =============================================================================

/// Analyze a single file for class cohesion.
///
/// fix-PW4-D-flask-lcom4-unify (v0.5.0 BACKLOG): ALL supported languages —
/// Python included — are routed through the canonical core engine
/// (`tldr_core::quality::cohesion`). This is the SAME engine consumed by
/// `health` (`run_health` -> `analyze_cohesion`) and `todo`
/// (`run_cohesion_analysis` -> `analyze_cohesion`), so the `cohesion`, `health`,
/// and `todo` surfaces now report identical LCOM4 values for the same class.
/// Previously the Python path ran a divergent CLI-local extraction
/// (`analyze_class`/`compute_lcom4`) that disagreed with the canonical engine
/// (flask `Flask`: 6 vs 16). The `include_dunder` and `min_methods` knobs are
/// honored against the canonical extraction.
fn analyze_single_file(path: &Path, args: &CohesionArgs) -> PatternsResult<CohesionReport> {
    let options = core_cohesion::CohesionOptions {
        include_dunder: args.include_dunder,
        low_cohesion_threshold: 2,
    };
    let core_report =
        core_cohesion::analyze_cohesion_with_options(path, None, options).map_err(|e| {
            PatternsError::ParseError {
                file: path.to_path_buf(),
                message: format!("Core cohesion analysis failed: {}", e),
            }
        })?;

    // Convert core types to CLI types.
    let classes: Vec<ClassCohesion> = core_report
        .classes
        .into_iter()
        .filter(|c| c.method_count >= args.min_methods as usize)
        .map(|c| ClassCohesion {
            class_name: c.name,
            file_path: c.file.display().to_string(),
            line: c.line as u32,
            lcom4: c.lcom4 as u32,
            method_count: c.method_count as u32,
            field_count: c.field_count as u32,
            verdict: match c.verdict {
                core_cohesion::CohesionVerdict::Cohesive => CohesionVerdict::Cohesive,
                core_cohesion::CohesionVerdict::SplitCandidate => CohesionVerdict::SplitCandidate,
                core_cohesion::CohesionVerdict::NotApplicable => CohesionVerdict::NotApplicable,
            },
            split_suggestion: c.split_suggestion,
            components: c
                .components
                .into_iter()
                .map(|comp| ComponentInfo {
                    methods: comp.methods,
                    fields: comp.fields,
                })
                .collect(),
        })
        .collect();

    let summary = compute_summary(&classes);
    Ok(CohesionReport {
        classes,
        summary,
        ..Default::default()
    })
}

/// Analyze a directory of source files for class cohesion.
///
/// Supports Python, Java, TypeScript, JavaScript, Go, Rust, and other
/// languages supported by the core library.
fn analyze_directory(
    dir: &Path,
    args: &CohesionArgs,
    start: Instant,
    timeout: Duration,
    max_files: u32,
) -> PatternsResult<CohesionReport> {
    validate_directory_path(dir)?;

    let mut all_classes = Vec::new();
    let mut file_count = 0u32;
    // cohesion-degrade-on-cap-v1 (W1): track whether the python per-file
    // walk reached `max_files` so we can report partial results with an
    // explicit truncation flag instead of erroring out. Mirrors the
    // `truncated` degradation contract on `CouplingReport` (see
    // `tldr_core::quality::coupling`) and the `dead`-command scan-cap
    // warning, rather than the legacy hard-fail that refused to run on
    // medium-to-large repos (the same defect VAL-006 fixed for `vuln`).
    let mut truncated = false;
    // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): non-python
    // files are routed through the core analyzer at the *directory*
    // granularity (rather than per-file) so the core's partial-class
    // merge step — required for `partial class Foo` declarations that
    // span multiple `.cs` files — actually runs. Python files keep
    // the per-file walk so the CLI-specific `test_*.py` exclusion
    // continues to apply.
    let mut has_non_python = false;

    for entry in walk_project(dir) {
        // Check timeout
        if start.elapsed() > timeout {
            return Err(PatternsError::Timeout {
                timeout_secs: args.timeout,
            });
        }

        let path = entry.path();

        // Analyze files with recognized language extensions
        if path.is_file() && Language::from_path(path).is_some() {
            // Skip test files unless explicitly included
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.starts_with("test_") || filename.ends_with("_test.py") {
                continue;
            }

            let lang = Language::from_path(path);
            if lang == Some(Language::Python) {
                // Per-file cap applies ONLY to the Python per-file walk — the
                // only work bounded by this loop. Non-Python files are handled
                // by the core analyzer below, which does its own (uncapped)
                // directory walk, so counting them here would error before the
                // core even ran and would mis-flag complete results as
                // truncated. Degrade gracefully instead of erroring: stop the
                // Python walk at the cap and report partial results flagged via
                // `truncated` (the same hard-fail VAL-006 removed for `vuln`,
                // and that `coupling`/`dead` already avoid by truncating with a
                // warning rather than aborting).
                if file_count >= max_files {
                    truncated = true;
                    break;
                }
                file_count += 1;

                // Analyze file, collecting errors but continuing
                match analyze_single_file(path, args) {
                    Ok(report) => {
                        all_classes.extend(report.classes);
                    }
                    Err(_) => {
                        // Skip files with parse errors
                        continue;
                    }
                }
            } else if lang.is_some() {
                has_non_python = true;
            }
        }
    }

    if has_non_python {
        // cohesion-cross-file-aggregation-v1 (v0.4.2 M-030): walk the
        // *directory* through the core analyzer so cross-file partial-
        // class merging runs. The core re-walks the directory itself
        // and applies its own language detection per file; the python-
        // specific test-file filter above does not need to reach here
        // because the core path simply emits whatever it finds (and the
        // duplicate-python work is benign — python entries come from
        // the per-file walk above, and the core's per-language extractor
        // dispatch for python re-runs the same algorithm).
        match core_cohesion::analyze_cohesion(dir, None, 2) {
            Ok(core_report) => {
                let core_classes: Vec<ClassCohesion> = core_report
                    .classes
                    .into_iter()
                    .filter(|c| {
                        // Filter out python — the per-file walk above
                        // already handled python with the CLI's
                        // test-file exclusion. Re-including them here
                        // would double-count.
                        let p = Path::new(&c.file);
                        Language::from_path(p) != Some(Language::Python)
                    })
                    .filter(|c| c.method_count >= args.min_methods as usize)
                    .map(|c| ClassCohesion {
                        class_name: c.name,
                        file_path: c.file.display().to_string(),
                        line: c.line as u32,
                        lcom4: c.lcom4 as u32,
                        method_count: c.method_count as u32,
                        field_count: c.field_count as u32,
                        verdict: match c.verdict {
                            core_cohesion::CohesionVerdict::Cohesive => CohesionVerdict::Cohesive,
                            core_cohesion::CohesionVerdict::SplitCandidate => {
                                CohesionVerdict::SplitCandidate
                            }
                            core_cohesion::CohesionVerdict::NotApplicable => {
                                CohesionVerdict::NotApplicable
                            }
                        },
                        split_suggestion: c.split_suggestion,
                        components: c
                            .components
                            .into_iter()
                            .map(|comp| ComponentInfo {
                                methods: comp.methods,
                                fields: comp.fields,
                            })
                            .collect(),
                    })
                    .collect();
                all_classes.extend(core_classes);
            }
            Err(_) => {
                // Graceful degradation: leave non-python results empty
                // if the core walker fails wholesale (typically a
                // permissions or fs error — `analyze_cohesion_with_
                // options` already swallows per-file parse failures).
            }
        }
    }

    let summary = compute_summary(&all_classes);

    Ok(CohesionReport {
        classes: all_classes,
        summary,
        truncated: if truncated { Some(true) } else { None },
        files_scanned: if truncated { Some(file_count) } else { None },
        files_limit: if truncated { Some(max_files) } else { None },
    })
}

/// Compute summary statistics for a set of class cohesion results.
fn compute_summary(classes: &[ClassCohesion]) -> CohesionSummary {
    let total = classes.len() as u32;
    if total == 0 {
        return CohesionSummary::default();
    }

    let cohesive = classes
        .iter()
        .filter(|c| c.verdict == CohesionVerdict::Cohesive)
        .count() as u32;

    // fix-R3-r7-cl11 (Fix 4): a `NotApplicable` class (genuinely fieldless type)
    // is counted as NEITHER cohesive nor a split candidate, and is excluded from
    // the LCOM4 average — never as `total - cohesive`, which would wrongly fold
    // it into `split_candidates`. `split_candidates` is now exactly the
    // `SplitCandidate` population (mirrors the core summary), and the average is
    // taken over applicable classes only.
    let split_candidates = classes
        .iter()
        .filter(|c| c.verdict == CohesionVerdict::SplitCandidate)
        .count() as u32;

    let applicable: Vec<f64> = classes
        .iter()
        .filter(|c| c.verdict != CohesionVerdict::NotApplicable)
        .map(|c| c.lcom4 as f64)
        .collect();
    let avg_lcom4 = if applicable.is_empty() {
        0.0
    } else {
        applicable.iter().sum::<f64>() / applicable.len() as f64
    };

    CohesionSummary {
        total_classes: total,
        cohesive,
        split_candidates,
        avg_lcom4: (avg_lcom4 * 100.0).round() / 100.0, // Round to 2 decimal places
    }
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format a cohesion report as human-readable text.
///
/// Shows split candidate classes sorted worst-first (highest LCOM4), with
/// color-coded severity, path stripping, component details, and split suggestions.
/// Top 30 entries shown by default with overflow message.
///
/// ```text
/// Cohesion Analysis (LCOM4)
///
/// LCOM4  Methods  Fields  Class                         File
///     4        8       6  UserManager                   models/user.py:42
///     |-- Component 1: create, update [db, cache]
///     |-- Component 2: send_email [mailer]
///     `-- Suggestion: Split into 4 focused classes
///     3        6       4  OrderProcessor                services/order.py:15
///     |-- Component 1: process, submit [queue]
///     `-- Suggestion: Split into 3 focused classes
///
/// Summary: 47 classes, 12 split candidates (25.5%), avg LCOM4: 1.82
/// ```
pub fn format_cohesion_text(report: &CohesionReport) -> String {
    let mut output = String::new();

    let s = &report.summary;
    output.push_str(&format!(
        "Cohesion Analysis (LCOM4) ({} classes, {} split candidates)\n\n",
        s.total_classes, s.split_candidates
    ));

    // Truncation note (graceful-degradation contract, mirrors coupling's
    // `(showing top N of M pairs)` line). Appended before every return path.
    let truncation_note = if report.truncated == Some(true) {
        format!(
            "  (partial: scanned {} of the Python files, truncated at limit {})\n",
            report.files_scanned.unwrap_or(0),
            report.files_limit.unwrap_or(0),
        )
    } else {
        String::new()
    };

    // Filter to split candidates only (LCOM4 > 1) and sort worst-first
    let mut candidates: Vec<&ClassCohesion> = report
        .classes
        .iter()
        .filter(|c| c.verdict == CohesionVerdict::SplitCandidate)
        .collect();
    candidates.sort_by(|a, b| b.lcom4.cmp(&a.lcom4));

    if candidates.is_empty() {
        output.push_str("  No split candidates found.\n\n");
        output.push_str(&format_cohesion_summary(s));
        output.push_str(&truncation_note);
        return output;
    }

    // Compute common path prefix for relative display
    let paths: Vec<&Path> = candidates
        .iter()
        .filter_map(|c| Path::new(c.file_path.as_str()).parent())
        .collect();
    let prefix = if paths.is_empty() {
        std::path::PathBuf::new()
    } else {
        common_path_prefix(&paths)
    };

    // Header
    output.push_str(&format!(
        " {:>5}  {:>7}  {:>6}  {:<28}  {}\n",
        "LCOM4", "Methods", "Fields", "Class", "File"
    ));

    // Show top 30
    let limit = candidates.len().min(30);
    for class in candidates.iter().take(limit) {
        let rel = strip_prefix_display(Path::new(&class.file_path), &prefix);
        let lcom4_str = format_lcom4_colored(class.lcom4);

        // Truncate class name to 28 chars
        let name = if class.class_name.len() > 28 {
            format!("{}...", &class.class_name[..25])
        } else {
            class.class_name.clone()
        };

        output.push_str(&format!(
            " {:>5}  {:>7}  {:>6}  {:<28}  {}:{}\n",
            lcom4_str, class.method_count, class.field_count, name, rel, class.line
        ));

        // Show component details for split candidates
        if !class.components.is_empty() {
            let comp_count = class.components.len();
            for (i, comp) in class.components.iter().enumerate() {
                let is_last = i == comp_count - 1 && class.split_suggestion.is_none();
                let connector = if is_last { "`--" } else { "|--" };
                let methods_str = comp.methods.join(", ");
                let fields_str = if comp.fields.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", comp.fields.join(", "))
                };
                output.push_str(&format!(
                    "     {}  Component {}: {}{}\n",
                    connector,
                    i + 1,
                    methods_str,
                    fields_str
                ));
            }
        }

        // Show split suggestion
        if let Some(ref suggestion) = class.split_suggestion {
            output.push_str(&format!("     `--  Suggestion: {}\n", suggestion));
        }
    }

    if candidates.len() > limit {
        output.push_str(&format!(
            "\n  ... and {} more split candidates\n",
            candidates.len() - limit
        ));
    }

    output.push('\n');
    output.push_str(&format_cohesion_summary(s));
    output.push_str(&truncation_note);

    output
}

/// Format LCOM4 value with color coding based on severity.
fn format_lcom4_colored(lcom4: u32) -> String {
    if lcom4 >= 4 {
        format!("{}", lcom4).red().bold().to_string()
    } else if lcom4 >= 2 {
        format!("{}", lcom4).yellow().to_string()
    } else {
        format!("{}", lcom4).green().to_string()
    }
}

/// Format the cohesion summary line.
fn format_cohesion_summary(s: &CohesionSummary) -> String {
    let pct = if s.total_classes > 0 {
        (s.split_candidates as f64 / s.total_classes as f64) * 100.0
    } else {
        0.0
    };
    format!(
        "Summary: {} classes, {} split candidates ({:.1}%), avg LCOM4: {:.2}\n",
        s.total_classes, s.split_candidates, pct, s.avg_lcom4
    )
}

// =============================================================================
// Public Entry Point
// =============================================================================

/// Run cohesion analysis (for programmatic use).
pub fn run(args: CohesionArgs) -> Result<CohesionReport> {
    let start = Instant::now();
    let timeout = Duration::from_secs(args.timeout);

    // Validate path
    let canonical_path = if let Some(ref root) = args.project_root {
        validate_file_path_in_project(&args.path, root)?
    } else {
        validate_file_path(&args.path)?
    };

    // Analyze based on path type
    let report = if canonical_path.is_dir() {
        analyze_directory(&canonical_path, &args, start, timeout, MAX_DIRECTORY_FILES)?
    } else {
        analyze_single_file(&canonical_path, &args)?
    };

    Ok(report)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_compute_summary() {
        let classes = vec![
            ClassCohesion {
                class_name: "A".to_string(),
                file_path: "test.py".to_string(),
                line: 1,
                lcom4: 1,
                method_count: 3,
                field_count: 2,
                verdict: CohesionVerdict::Cohesive,
                split_suggestion: None,
                components: vec![],
            },
            ClassCohesion {
                class_name: "B".to_string(),
                file_path: "test.py".to_string(),
                line: 10,
                lcom4: 2,
                method_count: 4,
                field_count: 3,
                verdict: CohesionVerdict::SplitCandidate,
                split_suggestion: Some("Split B".to_string()),
                components: vec![],
            },
        ];

        let summary = compute_summary(&classes);
        assert_eq!(summary.total_classes, 2);
        assert_eq!(summary.cohesive, 1);
        assert_eq!(summary.split_candidates, 1);
        assert!((summary.avg_lcom4 - 1.5).abs() < 0.01);
    }

    // =========================================================================
    // format_cohesion_text tests
    // =========================================================================

    /// Helper to build a ClassCohesion for tests.
    fn make_class(
        name: &str,
        location: (&str, u32),
        lcom4: u32,
        methods: u32,
        fields: u32,
        components: Vec<ComponentInfo>,
        suggestion: Option<&str>,
    ) -> ClassCohesion {
        let (file, line) = location;
        ClassCohesion {
            class_name: name.to_string(),
            file_path: file.to_string(),
            line,
            lcom4,
            method_count: methods,
            field_count: fields,
            verdict: CohesionVerdict::from_lcom4(lcom4),
            split_suggestion: suggestion.map(|s| s.to_string()),
            components,
        }
    }

    #[test]
    fn test_format_cohesion_text_sorts_worst_first() {
        let report = CohesionReport {
            classes: vec![
                make_class("Low", ("src/a.py", 1), 2, 3, 2, vec![], None),
                make_class("High", ("src/b.py", 5), 5, 8, 6, vec![], None),
                make_class("Mid", ("src/c.py", 10), 3, 5, 4, vec![], None),
            ],
            summary: CohesionSummary {
                total_classes: 3,
                cohesive: 0,
                split_candidates: 3,
                avg_lcom4: 3.33,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        // "High" (LCOM4=5) should appear before "Mid" (3) before "Low" (2)
        let high_pos = text.find("High").expect("High not found");
        let mid_pos = text.find("Mid").expect("Mid not found");
        let low_pos = text.find("Low").expect("Low not found");
        assert!(
            high_pos < mid_pos,
            "High (LCOM4=5) should appear before Mid (LCOM4=3)"
        );
        assert!(
            mid_pos < low_pos,
            "Mid (LCOM4=3) should appear before Low (LCOM4=2)"
        );
    }

    #[test]
    fn test_format_cohesion_text_filters_cohesive_classes() {
        let report = CohesionReport {
            classes: vec![
                make_class("Cohesive", ("src/a.py", 1), 1, 3, 2, vec![], None),
                make_class("NeedsSplit", ("src/b.py", 5), 3, 6, 4, vec![], None),
            ],
            summary: CohesionSummary {
                total_classes: 2,
                cohesive: 1,
                split_candidates: 1,
                avg_lcom4: 2.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        // Cohesive class (LCOM4=1) should NOT appear in the table rows
        // but NeedsSplit (LCOM4=3) should appear
        assert!(
            !text.contains("Cohesive"),
            "Cohesive classes should be filtered out"
        );
        assert!(
            text.contains("NeedsSplit"),
            "Split candidates should appear"
        );
    }

    #[test]
    fn test_format_cohesion_text_limits_to_30() {
        // Create 35 split candidates
        let classes: Vec<ClassCohesion> = (0..35)
            .map(|i| {
                make_class(
                    &format!("Class{}", i),
                    (&format!("src/mod{}.py", i), i + 1),
                    2,
                    4,
                    3,
                    vec![],
                    None,
                )
            })
            .collect();
        let report = CohesionReport {
            classes,
            summary: CohesionSummary {
                total_classes: 35,
                cohesive: 0,
                split_candidates: 35,
                avg_lcom4: 2.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        assert!(
            text.contains("and 5 more"),
            "Should show overflow message for remaining 5 classes"
        );
    }

    #[test]
    fn test_format_cohesion_text_strips_common_path_prefix() {
        let report = CohesionReport {
            classes: vec![
                make_class("A", ("src/models/user.py", 1), 3, 5, 4, vec![], None),
                make_class("B", ("src/models/order.py", 10), 2, 4, 3, vec![], None),
            ],
            summary: CohesionSummary {
                total_classes: 2,
                cohesive: 0,
                split_candidates: 2,
                avg_lcom4: 2.5,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        // The common prefix "src/models/" should be stripped, showing just filenames
        assert!(
            text.contains("user.py"),
            "Should display stripped path: user.py"
        );
        assert!(
            text.contains("order.py"),
            "Should display stripped path: order.py"
        );
        // Full path should not appear
        assert!(
            !text.contains("src/models/user.py"),
            "Full path should be stripped"
        );
    }

    #[test]
    fn test_format_cohesion_text_has_header() {
        let report = CohesionReport {
            classes: vec![make_class("A", ("src/a.py", 1), 2, 3, 2, vec![], None)],
            summary: CohesionSummary {
                total_classes: 1,
                cohesive: 0,
                split_candidates: 1,
                avg_lcom4: 2.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        assert!(
            text.contains("Cohesion Analysis"),
            "Should have title header"
        );
        assert!(
            text.contains("LCOM4") && text.contains("Methods") && text.contains("Fields"),
            "Should have column headers"
        );
        assert!(
            text.contains("Class") && text.contains("File"),
            "Should have Class and File columns"
        );
    }

    #[test]
    fn test_format_cohesion_text_summary_line() {
        let report = CohesionReport {
            classes: vec![],
            summary: CohesionSummary {
                total_classes: 47,
                cohesive: 35,
                split_candidates: 12,
                avg_lcom4: 1.82,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        assert!(
            text.contains("47 classes"),
            "Summary should show total classes"
        );
        assert!(
            text.contains("12 split candidates"),
            "Summary should show split candidate count"
        );
        assert!(text.contains("1.82"), "Summary should show avg LCOM4");
    }

    #[test]
    fn test_format_cohesion_text_shows_components() {
        let components = vec![
            ComponentInfo {
                methods: vec!["create".to_string(), "update".to_string()],
                fields: vec!["db".to_string(), "cache".to_string()],
            },
            ComponentInfo {
                methods: vec!["send_email".to_string()],
                fields: vec!["mailer".to_string()],
            },
        ];
        let report = CohesionReport {
            classes: vec![make_class(
                "UserManager",
                ("src/user.py", 1),
                2,
                3,
                3,
                components,
                Some("Split into 2 focused classes"),
            )],
            summary: CohesionSummary {
                total_classes: 1,
                cohesive: 0,
                split_candidates: 1,
                avg_lcom4: 2.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        // Should show component info
        assert!(text.contains("Component 1"), "Should show Component 1");
        assert!(
            text.contains("create") && text.contains("update"),
            "Should show methods in component"
        );
        assert!(
            text.contains("db") && text.contains("cache"),
            "Should show fields in component"
        );
        assert!(text.contains("Component 2"), "Should show Component 2");
        assert!(
            text.contains("send_email"),
            "Should show methods in component 2"
        );
        // Should show suggestion
        assert!(
            text.contains("Split into 2 focused classes"),
            "Should show split suggestion"
        );
    }

    #[test]
    fn test_format_cohesion_text_empty_report() {
        let report = CohesionReport {
            classes: vec![],
            summary: CohesionSummary {
                total_classes: 0,
                cohesive: 0,
                split_candidates: 0,
                avg_lcom4: 0.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        assert!(
            text.contains("No split candidates"),
            "Empty report should show 'No split candidates' message"
        );
    }

    #[test]
    fn test_format_cohesion_text_all_cohesive() {
        let report = CohesionReport {
            classes: vec![
                make_class("Good1", ("src/a.py", 1), 1, 5, 3, vec![], None),
                make_class("Good2", ("src/b.py", 10), 1, 4, 2, vec![], None),
            ],
            summary: CohesionSummary {
                total_classes: 2,
                cohesive: 2,
                split_candidates: 0,
                avg_lcom4: 1.0,
            },
            ..Default::default()
        };
        let text = format_cohesion_text(&report);
        // All classes are cohesive, so no table rows should appear
        assert!(
            text.contains("No split candidates"),
            "All-cohesive report should show 'No split candidates'"
        );
    }

    #[test]
    fn test_cohesion_args_lang_flag() {
        // Verify CohesionArgs has a lang field of type Option<Language>
        let args = CohesionArgs {
            path: PathBuf::from("src/"),
            min_methods: 2,
            include_dunder: false,
            output_format: OutputFormat::Json,
            timeout: 30,
            project_root: None,
            lang: Some(Language::Rust),
        };
        assert_eq!(args.lang, Some(Language::Rust));

        // Also test None case (auto-detect)
        let args_auto = CohesionArgs {
            path: PathBuf::from("src/"),
            min_methods: 2,
            include_dunder: false,
            output_format: OutputFormat::Json,
            timeout: 30,
            project_root: None,
            lang: None,
        };
        assert_eq!(args_auto.lang, None);
    }

    // =========================================================================
    // Directory scan-cap degradation tests (cohesion-degrade-on-cap-v1, W1)
    //
    // Regression guard: `tldr cohesion <large-dir>` previously HARD-FAILED with
    // `TooManyFiles` once the per-file walk reached MAX_DIRECTORY_FILES, refusing
    // to run on medium-to-large repos (kotlin-coroutines 1062, ruby-rubocop 1708,
    // typescript-nest 1683) while structure/loc/patterns processed them fine.
    // The fix degrades gracefully (partial results + `truncated` flag, exit 0),
    // mirroring the `truncated` contract on `CouplingReport`. The cap is injected
    // via the `max_files` parameter so the production scan path is exercised with
    // a small cap rather than writing 1001 real files.
    // =========================================================================

    /// Write a Python file containing a single cohesive class (LCOM4 == 1):
    /// two methods that both touch the same field, so the class is connected.
    fn write_cohesive_py(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            "class Widget:\n    def __init__(self):\n        self.value = 0\n\n    def get(self):\n        return self.value\n\n    def set(self, v):\n        self.value = v\n",
        )
        .expect("write python file");
        path
    }

    fn dir_args() -> CohesionArgs {
        CohesionArgs {
            path: PathBuf::from("."),
            min_methods: 1,
            include_dunder: false,
            output_format: OutputFormat::Json,
            timeout: 30,
            project_root: None,
            lang: None,
        }
    }

    /// RED→GREEN guard: with more files than the cap, the scan must DEGRADE
    /// (return Ok with partial results + truncation markers), NOT error.
    #[test]
    fn test_directory_scan_degrades_gracefully_past_cap() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Create 5 analyzable Python files; cap the scan at 2.
        for i in 0..5 {
            write_cohesive_py(tmp.path(), &format!("mod_{i}.py"));
        }

        let args = dir_args();
        let result = analyze_directory(
            tmp.path(),
            &args,
            Instant::now(),
            Duration::from_secs(30),
            /* max_files = */ 2,
        );

        // Must NOT hard-fail with TooManyFiles — this is the core regression.
        let report = result.expect(
            "cohesion directory scan must degrade gracefully past the file cap, not return Err",
        );

        // Partial results: the bounded subset that WAS scanned still yields classes.
        assert!(
            !report.classes.is_empty(),
            "truncated scan should still return cohesion results for the files it did process"
        );

        // Explicit truncation contract (mirrors CouplingReport.truncated).
        assert_eq!(
            report.truncated,
            Some(true),
            "report must flag that the scan was truncated at the file cap"
        );
        assert_eq!(
            report.files_limit,
            Some(2),
            "report must record the limit that triggered truncation"
        );
        let scanned = report
            .files_scanned
            .expect("truncated report must record how many files were scanned");
        assert!(
            scanned <= 5,
            "files_scanned ({scanned}) cannot exceed the number of files present"
        );
        assert!(
            scanned >= 2,
            "files_scanned ({scanned}) should reach the cap before truncating"
        );
    }

    /// Characterization guard: when the directory fits under the cap, results are
    /// complete and NO truncation markers are set (no false-positive truncation).
    #[test]
    fn test_directory_scan_under_cap_is_not_truncated() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        for i in 0..3 {
            write_cohesive_py(tmp.path(), &format!("mod_{i}.py"));
        }

        let args = dir_args();
        let report = analyze_directory(
            tmp.path(),
            &args,
            Instant::now(),
            Duration::from_secs(30),
            /* max_files = */ 1000,
        )
        .expect("under-cap directory scan should succeed");

        assert_eq!(
            report.classes.len(),
            3,
            "all 3 files should be analyzed when under the cap"
        );
        assert_eq!(
            report.truncated, None,
            "an un-truncated scan must not set the truncated flag"
        );
        assert_eq!(report.files_scanned, None);
        assert_eq!(report.files_limit, None);
    }

    /// Characterization guard: the JSON schema is unchanged for the common
    /// (un-truncated) case — the truncation fields are omitted entirely, so
    /// existing consumers see no new keys. They appear only when truncated.
    #[test]
    fn test_truncation_fields_omitted_in_json_when_not_truncated() {
        let untruncated = CohesionReport {
            classes: vec![],
            summary: CohesionSummary::default(),
            ..Default::default()
        };
        let json = serde_json::to_string(&untruncated).unwrap();
        assert!(
            !json.contains("truncated"),
            "truncated key must be omitted when None: {json}"
        );
        assert!(!json.contains("files_scanned"), "files_scanned must be omitted when None");
        assert!(!json.contains("files_limit"), "files_limit must be omitted when None");

        let truncated = CohesionReport {
            classes: vec![],
            summary: CohesionSummary::default(),
            truncated: Some(true),
            files_scanned: Some(1000),
            files_limit: Some(1000),
        };
        let json = serde_json::to_string(&truncated).unwrap();
        assert!(json.contains("\"truncated\":true"), "truncated must appear when set: {json}");
        assert!(json.contains("\"files_scanned\":1000"));
        assert!(json.contains("\"files_limit\":1000"));
    }

    /// Guard the text-formatter wiring of the truncation note (mirrors
    /// coupling's `(showing top N of M)` line) so a revert is caught.
    #[test]
    fn test_format_cohesion_text_shows_truncation_note() {
        let report = CohesionReport {
            classes: vec![],
            summary: CohesionSummary::default(),
            truncated: Some(true),
            files_scanned: Some(1000),
            files_limit: Some(1000),
        };
        let text = format_cohesion_text(&report);
        assert!(
            text.contains("partial") && text.contains("truncated"),
            "truncated text report must carry a partial/truncated note: {text}"
        );

        // And NOT present when complete.
        let complete = CohesionReport {
            classes: vec![],
            summary: CohesionSummary::default(),
            ..Default::default()
        };
        let text = format_cohesion_text(&complete);
        assert!(
            !text.contains("partial"),
            "complete report must not claim partial results: {text}"
        );
    }

    // =========================================================================
    // fix-PW4-D-flask-lcom4-unify (v0.5.0 BACKLOG): LCOM4 engine unification.
    //
    // The `cohesion` command's Python path MUST agree with the canonical
    // `tldr_core::quality::cohesion::analyze_cohesion` engine that BOTH `health`
    // (`run_health` -> `analyze_cohesion`) and `todo` (`run_cohesion_analysis`
    // -> `analyze_cohesion`) already consume. Before this fix the command ran a
    // *parallel* local LCOM4 extraction (`analyze_class`/`compute_lcom4`) that
    // diverged from the canonical engine (flask `Flask`: cohesion=6 vs
    // health/todo=16; minimal `Sample`: cohesion=4 vs health/todo=5).
    //
    // Generalization (single-variant = FAIL): agreement is asserted across
    // several Python class shapes (the known-divergent one, a cohesive one, a
    // two-component one, a self-call-bridged one) AND a non-Python class, which
    // already delegated to the core engine and must stay unchanged.
    // =========================================================================

    /// The minimal known-divergent class (pre-fix cohesion=4, canonical=5),
    /// reused below so the regression is pinned by name.
    const DIVERGENT_PY: &str = "\
class Sample:
    def __init__(self):
        self.a = 1
        self.b = 2
        self.c = 3
    def m1(self):
        return self.a
    def m2(self):
        return self.b
    def m3(self):
        self.c = self.helper()
    def helper(self):
        return 5
    def m4(self, x):
        local = x + 1
        return local
    def m5(self):
        for i in range(self.a):
            print(i)
";

    fn gen_args(path: &Path) -> CohesionArgs {
        CohesionArgs {
            path: path.to_path_buf(),
            min_methods: 1,
            include_dunder: false,
            output_format: OutputFormat::Json,
            timeout: 30,
            project_root: None,
            lang: None,
        }
    }

    #[test]
    fn test_cohesion_command_agrees_with_canonical_engine_python() {
        let tmp = tempfile::TempDir::new().expect("tempdir");

        let fixtures: &[(&str, &str)] = &[
            ("divergent.py", DIVERGENT_PY),
            (
                "cohesive.py",
                "class Widget:\n    def __init__(self):\n        self.value = 0\n\n    def get(self):\n        return self.value\n\n    def inc(self):\n        self.value += 1\n",
            ),
            (
                "two_comp.py",
                "class Split:\n    def __init__(self):\n        self.x = 0\n        self.y = 0\n    def gx(self):\n        return self.x\n    def sx(self, v):\n        self.x = v\n    def gy(self):\n        return self.y\n    def sy(self, v):\n        self.y = v\n",
            ),
            (
                "with_calls.py",
                "class Bridge:\n    def __init__(self):\n        self.a = 1\n        self.b = 2\n    def ra(self):\n        return self.a\n    def rb(self):\n        return self.b\n    def both(self):\n        return self.ra() + self.rb()\n",
            ),
        ];

        for (name, src) in fixtures {
            let path = tmp.path().join(name);
            std::fs::write(&path, src).expect("write fixture");

            let cmd = analyze_single_file(&path, &gen_args(&path)).expect("command analysis");
            // The exact engine `health` and `todo` call.
            let canon = core_cohesion::analyze_cohesion(&path, Some(Language::Python), 2)
                .expect("canonical analysis");

            let canon_by: HashMap<String, &core_cohesion::ClassCohesion> =
                canon.classes.iter().map(|c| (c.name.clone(), c)).collect();

            assert!(
                !cmd.classes.is_empty(),
                "command produced no classes for {name}"
            );

            for cls in &cmd.classes {
                let cc = canon_by.get(&cls.class_name).unwrap_or_else(|| {
                    panic!("canonical engine missing class {} in {name}", cls.class_name)
                });
                assert_eq!(
                    cls.lcom4, cc.lcom4 as u32,
                    "LCOM4 disagreement on {} in {name}: cohesion={} but canonical (health/todo)={}",
                    cls.class_name, cls.lcom4, cc.lcom4
                );
                assert_eq!(
                    cls.field_count, cc.field_count as u32,
                    "field_count disagreement on {} in {name}",
                    cls.class_name
                );
                assert_eq!(
                    cls.method_count, cc.method_count as u32,
                    "method_count disagreement on {} in {name}",
                    cls.class_name
                );
            }
        }
    }

    #[test]
    fn test_cohesion_command_divergent_class_matches_canonical_value() {
        // Pin the headline regression: the historically-divergent `Sample`
        // class now reports the canonical value (== health == todo), not the
        // old local-engine value.
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("sample.py");
        std::fs::write(&path, DIVERGENT_PY).expect("write");

        let cmd = analyze_single_file(&path, &gen_args(&path)).expect("command");
        let canon = core_cohesion::analyze_cohesion(&path, Some(Language::Python), 2)
            .expect("canonical");

        let cmd_sample = cmd
            .classes
            .iter()
            .find(|c| c.class_name == "Sample")
            .expect("command Sample");
        let canon_sample = canon
            .classes
            .iter()
            .find(|c| c.name == "Sample")
            .expect("canonical Sample");

        assert_eq!(
            cmd_sample.lcom4, canon_sample.lcom4 as u32,
            "Sample LCOM4 must equal the canonical engine value"
        );
        assert!(
            cmd_sample.lcom4 > 1,
            "Sample is a multi-component class; LCOM4 must exceed 1"
        );
    }

    #[test]
    fn test_cohesion_command_non_python_unchanged() {
        // Non-Python already delegated to the core engine; the unification must
        // not perturb it.
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "struct Counter { n: i32, label: String }\nimpl Counter {\n    fn inc(&mut self) { self.n += 1; }\n    fn val(&self) -> i32 { self.n }\n    fn name(&self) -> &str { &self.label }\n}\n",
        )
        .expect("write rust");

        let cmd = analyze_single_file(&path, &gen_args(&path)).expect("command");
        let canon = core_cohesion::analyze_cohesion(&path, Some(Language::Rust), 2)
            .expect("canonical");

        let canon_by: HashMap<String, &core_cohesion::ClassCohesion> =
            canon.classes.iter().map(|c| (c.name.clone(), c)).collect();
        for cls in &cmd.classes {
            let cc = canon_by
                .get(&cls.class_name)
                .unwrap_or_else(|| panic!("canonical missing rust type {}", cls.class_name));
            assert_eq!(cls.lcom4, cc.lcom4 as u32, "rust LCOM4 changed for {}", cls.class_name);
        }
    }
}
