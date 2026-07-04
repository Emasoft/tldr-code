//! Diagnostics command - Unified type checking and linting across languages
//!
//! Session 6 Phase 10: CLI command for running diagnostic tools.
//!
//! # Features
//! - Auto-detect available tools (pyright, ruff, tsc, eslint, etc.)
//! - Run type checkers and linters in parallel
//! - Unified diagnostic output format
//! - Severity filtering (error, warning, info, hint)
//! - Multiple output formats (JSON, text, SARIF, GitHub Actions)
//!
//! # Exit Codes (documented in --help, S6-R52 mitigation)
//! - 0: Success (no errors, or only warnings without --strict). Also used
//!      when tldr has NO diagnostic integration for the language at all
//!      (e.g. Luau): there is simply nothing to run — an "N/A" state, not
//!      an analysis failure — so a `set -e` CI harness does not treat an
//!      unsupported language as a hard error (T6c / VAL-T6c).
//! - 1: Errors found (or warnings with --strict)
//! - 60: Diagnostic tools exist for the language but none are installed
//!       (or none survived --tools / --no-typecheck / --no-lint filtering)
//! - 61: All tools failed to run

use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;

use tldr_core::diagnostics::{
    compute_exit_code, compute_summary, dedupe_diagnostics, detect_available_tools,
    filter_diagnostics_by_severity, run_tools_parallel, tools_for_language, DiagnosticsReport,
    Severity, ToolConfig,
};
use tldr_core::Language;

use crate::output::{format_diagnostics_text, OutputFormat, OutputWriter};

/// Run type checking and linting
///
/// Runs diagnostic tools (type checkers and linters) and produces unified output.
/// Tools are detected automatically based on language and availability.
///
/// # Exit Codes
///
/// - 0: Success (no errors, or only warnings without --strict); also the
///      "N/A" code when tldr has no integration for the language (T6c)
/// - 1: Errors found (or warnings with --strict)
/// - 60: Diagnostic tools exist for the language but none are installed/selected
/// - 61: All tools failed to run
#[derive(Debug, Args)]
pub struct DiagnosticsArgs {
    /// File or directory to analyze
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    // === Tool Selection ===
    /// Specific tools to run (comma-separated, e.g., "pyright,ruff")
    #[arg(long, value_delimiter = ',')]
    pub tools: Vec<String>,

    /// Skip type checking (linters only)
    #[arg(long)]
    pub no_typecheck: bool,

    /// Skip linting (type checkers only)
    #[arg(long)]
    pub no_lint: bool,

    // === Filtering ===
    /// Minimum severity to report (error, warning, info, hint)
    #[arg(long, short = 's', value_enum, default_value = "hint")]
    pub severity: SeverityFilter,

    /// Ignore specific error codes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub ignore: Vec<String>,

    // === Output Options ===
    /// Additional output format (sarif, github-actions)
    #[arg(long, value_enum)]
    pub output: Option<DiagnosticOutput>,

    /// Analyze entire project (not just specified path)
    #[arg(long)]
    pub project: bool,

    /// Maximum number of annotations for GitHub Actions output
    #[arg(long, default_value = "50")]
    pub max_annotations: usize,

    // === Execution ===
    /// Overall timeout budget per tool in seconds.
    ///
    /// T10 (VAL-T10): the external tool itself is given a slightly SHORTER
    /// budget (this value minus a small margin — see `tool_timeout_budget`
    /// in the runner) so that a slow tool degrades to a timed-out ToolResult
    /// and tldr can still parse, emit its report, and exit BEFORE an outer
    /// wall (e.g. a CI `timeout 60 tldr ...` wrapper) SIGKILLs the whole
    /// process with exit 124.
    #[arg(long, default_value = "60")]
    pub timeout: u64,

    /// Fail on warnings (not just errors)
    #[arg(long)]
    pub strict: bool,

    // === Baseline Comparison (Phase 12) ===
    /// Compare against baseline file (show only new issues)
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Save current results as baseline
    #[arg(long)]
    pub save_baseline: Option<PathBuf>,
}

/// Severity filter for CLI (maps to core Severity)
#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum SeverityFilter {
    /// Show only errors
    Error,
    /// Show errors and warnings
    Warning,
    /// Show errors, warnings, and info
    Info,
    /// Show all diagnostics including hints
    #[default]
    Hint,
}

impl From<SeverityFilter> for Severity {
    fn from(filter: SeverityFilter) -> Self {
        match filter {
            SeverityFilter::Error => Severity::Error,
            SeverityFilter::Warning => Severity::Warning,
            SeverityFilter::Info => Severity::Information,
            SeverityFilter::Hint => Severity::Hint,
        }
    }
}

/// Additional output formats for diagnostics
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DiagnosticOutput {
    /// SARIF 2.1.0 format for GitHub/GitLab Code Scanning
    Sarif,
    /// GitHub Actions workflow commands (::error::, ::warning::)
    GithubActions,
}

impl DiagnosticsArgs {
    /// Run the diagnostics command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // 1. Detect language (default to Python if not specified and can't detect)
        let language = self.lang.unwrap_or_else(|| {
            if self.path.is_file() {
                Language::from_path(&self.path).unwrap_or(Language::Python)
            } else {
                Language::from_directory(&self.path).unwrap_or(Language::Python)
            }
        });

        writer.progress(&format!("Detecting tools for {:?}...", language));

        // 2. Get available tools
        let mut tools: Vec<ToolConfig> = if self.tools.is_empty() {
            detect_available_tools(language)
        } else {
            // Filter to requested tools
            tools_for_language(language)
                .into_iter()
                .filter(|t| {
                    self.tools
                        .iter()
                        .any(|name| t.name.eq_ignore_ascii_case(name))
                })
                .collect()
        };

        // 3. Apply type/lint filtering
        if self.no_typecheck {
            tools.retain(|t| !t.is_type_checker);
        }
        if self.no_lint {
            tools.retain(|t| !t.is_linter);
        }

        // 4. Check if we have tools to run
        if tools.is_empty() {
            // hygiene-and-crash-fixes-v1 (BUG-AGG12-6): emit a valid empty
            // JSON/SARIF document on stdout BEFORE the stderr message so JSON
            // consumers don't choke on a 0-byte stdout. The advisory message
            // remains on stderr (so humans see it), and we exit 0 because
            // "no diagnostic tools installed" is an absence-of-tooling
            // condition, not a runtime failure of the analysis itself.
            let empty_report = DiagnosticsReport::default();
            match self.output {
                Some(DiagnosticOutput::Sarif) => {
                    let sarif = to_sarif(&empty_report);
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                Some(DiagnosticOutput::GithubActions) => {
                    // GitHub Actions output is an annotation stream; an empty
                    // stream is the correct representation of "no findings".
                    output_github_actions(&empty_report, self.max_annotations);
                }
                None => {
                    if writer.is_text() {
                        writer.write_text(&format!(
                            "No diagnostic tools available for {:?}.\n",
                            language
                        ))?;
                    } else {
                        // Emit the empty DiagnosticsReport via the writer so
                        // downstream JSON consumers get a well-formed object
                        // that matches the schema of a real diagnostics run.
                        writer.write(&empty_report)?;
                    }
                }
            }

            // Advisory on stderr (S6-R36 mitigation kept). The leading
            // "No diagnostic tools available for {lang}" phrase is a contract
            // pinned by hygiene_and_crash_fixes_v1 (agg12_6) — keep it.
            //
            // fix-C5-5 (v0.5.0 AUDIT-FIX): emit a complete, non-dangling
            // advisory (see `build_no_tools_advisory`).
            eprint!("{}", build_no_tools_advisory(language));
            // T6c (VAL-T6c): the empty `tools` list conflates two distinct
            // states that a `set -e` CI harness could not previously tell
            // apart (both exited 60):
            //
            //   (A) tldr HAS diagnostic integration for this language but no
            //       tool is installed (or none survived --tools/--no-*):
            //       actionable — exit 60 so callers can prompt an install.
            //       This preserves the S6-R36 contract and keeps existing
            //       skip-on-no-tools gates (e.g.
            //       high_bundle_progress_determinism_coverage_v1) working.
            //
            //   (B) tldr has NO integration for this language at all (e.g.
            //       Luau): there is nothing to run — an "N/A" state, not an
            //       analysis failure. Exit 0 so `set -e` harnesses do not
            //       fail on an unsupported language. The empty (but
            //       well-formed) report on stdout plus the stderr advisory
            //       already describe the state in-band, and `tools_run`
            //       being empty distinguishes it from a clean run that DID
            //       execute tools.
            //
            // Emitting valid JSON on stdout remains additive in both cases.
            match no_tools_exit_code(language) {
                0 => return Ok(()),
                code => std::process::exit(code),
            }
        }

        writer.progress(&format!(
            "Running diagnostics: {}",
            tools.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
        ));

        // 5. Run tools in parallel
        let mut report = run_tools_parallel(&tools, &self.path, self.timeout)?;

        // Check if all tools failed (exit code 61)
        //
        // hygiene-and-crash-fixes-v1 (BUG-AGG12-6, exhaustive iteration per
        // no-synthetic-fixtures-v1 §5): the same 0-byte-stdout class affects
        // the all-tools-failed path too. Emit the partial report (with the
        // tools_run errors populated) on stdout so JSON consumers can still
        // parse it, then surface the advisory on stderr. Exit 0 because the
        // tool-execution failures are described in-band in the JSON.
        if !report.tools_run.is_empty() && report.tools_run.iter().all(|t| !t.success) {
            // Recompute summary so the empty-diagnostics array is internally
            // consistent with summary.total == 0.
            report.summary = compute_summary(&report.diagnostics);
            match self.output {
                Some(DiagnosticOutput::Sarif) => {
                    let sarif = to_sarif(&report);
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                Some(DiagnosticOutput::GithubActions) => {
                    output_github_actions(&report, self.max_annotations);
                }
                None => {
                    if writer.is_text() {
                        let text = format_diagnostics_text(&report, 0);
                        writer.write_text(&text)?;
                    } else {
                        writer.write(&report)?;
                    }
                }
            }
            eprintln!("Note: All diagnostic tools failed to run.");
            for result in &report.tools_run {
                if let Some(err) = &result.error {
                    eprintln!("  - {}: {}", result.name, err);
                }
            }
            // Preserve exit code 61 (S6-R36) so callers can still discriminate
            // tool-failure from clean/dirty runs. Stdout now carries the JSON.
            std::process::exit(61);
        }

        // 6. Deduplicate diagnostics
        report.diagnostics = dedupe_diagnostics(report.diagnostics);

        // 7. Filter by severity
        let min_severity: Severity = self.severity.into();
        let unfiltered_count = report.diagnostics.len();
        report.diagnostics = filter_diagnostics_by_severity(&report.diagnostics, min_severity);

        // 8. Filter by ignored codes
        if !self.ignore.is_empty() {
            report.diagnostics.retain(|d| {
                if let Some(code) = &d.code {
                    !self.ignore.iter().any(|ignored| code == ignored)
                } else {
                    true
                }
            });
        }

        // 9. Apply baseline comparison (Phase 12)
        if let Some(baseline_path) = &self.baseline {
            report = apply_baseline(report, baseline_path)?;
        }

        // 10. Recompute summary after filtering (S6-R28 mitigation)
        report.summary = compute_summary(&report.diagnostics);

        // 11. Save baseline if requested
        if let Some(save_path) = &self.save_baseline {
            save_baseline(&report, save_path)?;
            writer.progress(&format!("Baseline saved to: {}", save_path.display()));
        }

        // 12. Calculate filtered count for display (S6-R47 mitigation)
        let filtered_count = unfiltered_count - report.diagnostics.len();

        // 13. Output based on format
        match self.output {
            Some(DiagnosticOutput::Sarif) => {
                let sarif = to_sarif(&report);
                // Warn if SARIF exceeds 10MB estimate (S6-R56 mitigation)
                let estimated_size = serde_json::to_string(&sarif).map(|s| s.len()).unwrap_or(0);
                if estimated_size > 10 * 1024 * 1024 {
                    eprintln!(
                        "Warning: SARIF output is large (~{}MB). GitHub may reject files over 10MB.",
                        estimated_size / (1024 * 1024)
                    );
                }
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
            Some(DiagnosticOutput::GithubActions) => {
                output_github_actions(&report, self.max_annotations);
            }
            None => {
                if writer.is_text() {
                    let text = format_diagnostics_text(&report, filtered_count);
                    writer.write_text(&text)?;
                } else {
                    writer.write(&report)?;
                }
            }
        }

        // 14. Compute exit code (S6-R36 mitigation: distinct codes)
        let exit_code = compute_exit_code(&report.summary, self.strict);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }

        Ok(())
    }
}

/// fix-C5-5 (v0.5.0 AUDIT-FIX): build the stderr advisory shown when no
/// diagnostic tool is available for `language`.
///
/// Two cases:
///
///   1. tldr knows of tools for the language but none are installed
///      (`tools_for_language` non-empty): the message ends with
///      `Install one of:` followed by one `  - <tool> (<hint>)` line per
///      known tool. This is the actionable path.
///
///   2. tldr has NO tool integration for the language at all
///      (`tools_for_language` empty — OCaml, Solidity, Luau, …): the old
///      code still printed the dangling `Install one of:` with an empty
///      list, which reads as a broken/error message. Instead emit a single,
///      self-contained sentence making clear there is simply nothing to run
///      (not an analysis failure).
///
/// Both cases keep the leading `No diagnostic tools available for {lang}`
/// phrase that `hygiene_and_crash_fixes_v1` pins as a contract. The returned
/// string is newline-terminated and printed verbatim with `eprint!`.
fn build_no_tools_advisory(language: Language) -> String {
    let installable = tools_for_language(language);
    if installable.is_empty() {
        format!(
            "Note: No diagnostic tools available for {language:?}. \
             tldr has no type-checker or linter integration for {language:?} yet, \
             so there is nothing to run — this is not an analysis error.\n"
        )
    } else {
        let mut msg = format!(
            "Note: No diagnostic tools available for {language:?}. Install one of:\n"
        );
        for tool in installable {
            msg.push_str(&format!(
                "  - {} ({})\n",
                tool.name,
                tldr_core::diagnostics::get_install_suggestion(tool.name)
            ));
        }
        msg
    }
}

/// T6c (VAL-T6c): classify the terminal exit code for the "no tools to run"
/// branch, splitting the two states that were previously conflated under a
/// single `exit(60)`.
///
/// - Returns `0` when tldr has NO diagnostic integration for `language`
///   (`tools_for_language` is empty — e.g. Luau): nothing can run, so this
///   is an "N/A" state, not an analysis failure. Exit 0 keeps `set -e` CI
///   harnesses from failing on an unsupported language.
/// - Returns `60` when tldr DOES know tools for the language but none are
///   installed (or none survived `--tools` / `--no-typecheck` / `--no-lint`
///   filtering): actionable, so callers/CI can prompt an install. This is
///   the state the S6-R36 exit-60 contract was designed for.
fn no_tools_exit_code(language: Language) -> i32 {
    if tools_for_language(language).is_empty() {
        // Case B — tldr has NO integration for this language: nothing can
        // run, so this is an "N/A" state, not an analysis failure. Exit 0
        // keeps `set -e` CI harnesses from failing on an unsupported
        // language; the empty (but well-formed) report on stdout and the
        // stderr advisory describe the state in-band, and an empty
        // `tools_run` distinguishes it from a clean run that DID execute.
        0
    } else {
        // Case A — tldr knows tools for the language but none are installed
        // (or none survived `--tools` / `--no-typecheck` / `--no-lint`
        // filtering): actionable, so preserve the S6-R36 exit-60 contract.
        60
    }
}

// =============================================================================
// Phase 11: SARIF Output Format
// =============================================================================

/// SARIF 2.1.0 output structure
#[derive(Debug, serde::Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, serde::Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, serde::Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    start_column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
}

/// Convert DiagnosticsReport to SARIF 2.1.0 format
fn to_sarif(report: &DiagnosticsReport) -> SarifReport {
    let results: Vec<SarifResult> = report
        .diagnostics
        .iter()
        .map(|d| {
            // Map severity to SARIF level (S6-R35 mitigation)
            let level = match d.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Information => "note",
                Severity::Hint => "note",
            };

            // Use relative path for URI (S6-R23 mitigation)
            let uri = d.file.display().to_string();
            let relative_uri = if uri.starts_with('/') {
                // Strip absolute path prefix - try common prefixes
                uri.trim_start_matches('/')
                    .split_once('/')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or(uri)
            } else {
                uri
            };

            SarifResult {
                rule_id: d.code.clone().unwrap_or_else(|| d.source.clone()),
                level: level.to_string(),
                message: SarifMessage {
                    text: d.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: relative_uri },
                        region: SarifRegion {
                            start_line: d.line,
                            start_column: d.column,
                            end_line: d.end_line,
                            end_column: d.end_column,
                        },
                    },
                }],
                help_uri: d.url.clone(),
            }
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "tldr-diagnostics".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/user/tldr".to_string(),
                },
            },
            results,
        }],
    }
}

// =============================================================================
// Phase 11: GitHub Actions Output Format
// =============================================================================

/// Output diagnostics as GitHub Actions workflow commands
fn output_github_actions(report: &DiagnosticsReport, max_annotations: usize) {
    // Warn if exceeding annotation limit (S6-R55 mitigation)
    if report.diagnostics.len() > max_annotations {
        eprintln!(
            "Warning: {} diagnostics found, but GitHub Actions limits annotations to {}. \
             Only first {} will be shown. Use --max-annotations to adjust.",
            report.diagnostics.len(),
            max_annotations,
            max_annotations
        );
    }

    for diag in report.diagnostics.iter().take(max_annotations) {
        let severity = match diag.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Information => "notice",
            Severity::Hint => "notice",
        };

        // GitHub Actions format: ::severity file=path,line=N,col=M::message
        // Escape message for GH Actions (newlines become %0A)
        let escaped_message = diag
            .message
            .replace('\n', "%0A")
            .replace('\r', "%0D")
            .replace('%', "%25");

        println!(
            "::{} file={},line={},col={}::{}",
            severity,
            diag.file.display(),
            diag.line,
            diag.column,
            escaped_message
        );
    }

    // Output summary as a group
    println!("::group::Diagnostics Summary");
    println!(
        "Errors: {}, Warnings: {}, Info: {}, Hints: {}",
        report.summary.errors, report.summary.warnings, report.summary.info, report.summary.hints
    );
    println!("::endgroup::");
}

// =============================================================================
// Phase 12: Baseline Comparison
// =============================================================================

/// Baseline file structure for JSON serialization
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BaselineFile {
    version: u32,
    created_at: String,
    diagnostics: Vec<BaselineDiagnostic>,
}

/// Simplified diagnostic for baseline storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
struct BaselineDiagnostic {
    /// Relative file path
    file: String,
    /// Start line
    line: u32,
    /// Start column
    column: u32,
    /// Hash of message for comparison
    message_hash: u64,
    /// Original message (for resolved diagnostics)
    message: String,
    /// Error code
    code: Option<String>,
}

impl From<&tldr_core::diagnostics::Diagnostic> for BaselineDiagnostic {
    fn from(d: &tldr_core::diagnostics::Diagnostic) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        d.message.hash(&mut hasher);
        let message_hash = hasher.finish();

        BaselineDiagnostic {
            file: d.file.display().to_string(),
            line: d.line,
            column: d.column,
            message_hash,
            message: d.message.clone(),
            code: d.code.clone(),
        }
    }
}

/// Apply baseline comparison to filter out known issues
fn apply_baseline(
    mut report: DiagnosticsReport,
    baseline_path: &PathBuf,
) -> Result<DiagnosticsReport> {
    // Read baseline file
    let baseline_content = std::fs::read_to_string(baseline_path).map_err(|e| {
        anyhow!(
            "Failed to read baseline file '{}': {}",
            baseline_path.display(),
            e
        )
    })?;

    // Parse baseline (S6-R25 mitigation: validate on load)
    let baseline: BaselineFile = serde_json::from_str(&baseline_content).map_err(|e| {
        anyhow!(
            "Invalid baseline JSON in '{}': {}",
            baseline_path.display(),
            e
        )
    })?;

    // Check version compatibility
    if baseline.version != 1 {
        return Err(anyhow!(
            "Unsupported baseline version: {}. Expected version 1.",
            baseline.version
        ));
    }

    // Convert current diagnostics to baseline format for comparison
    let current_set: std::collections::HashSet<BaselineDiagnostic> =
        report.diagnostics.iter().map(|d| d.into()).collect();

    let baseline_set: std::collections::HashSet<BaselineDiagnostic> =
        baseline.diagnostics.into_iter().collect();

    // Find new diagnostics (in current but not in baseline)
    let new_diagnostics: std::collections::HashSet<_> =
        current_set.difference(&baseline_set).cloned().collect();

    // Find resolved diagnostics (in baseline but not in current)
    let resolved: Vec<_> = baseline_set.difference(&current_set).collect();

    if !resolved.is_empty() {
        eprintln!(
            "Info: {} issues from baseline have been resolved.",
            resolved.len()
        );
    }

    // Filter report to only new diagnostics
    report.diagnostics.retain(|d| {
        let bd: BaselineDiagnostic = d.into();
        new_diagnostics.contains(&bd)
    });

    Ok(report)
}

/// Save current diagnostics as baseline file
fn save_baseline(report: &DiagnosticsReport, path: &PathBuf) -> Result<()> {
    let baseline = BaselineFile {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        diagnostics: report.diagnostics.iter().map(|d| d.into()).collect(),
    };

    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(path, json)
        .map_err(|e| anyhow!("Failed to write baseline file '{}': {}", path.display(), e))?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_filter_conversion() {
        assert_eq!(Severity::from(SeverityFilter::Error), Severity::Error);
        assert_eq!(Severity::from(SeverityFilter::Warning), Severity::Warning);
        assert_eq!(Severity::from(SeverityFilter::Info), Severity::Information);
        assert_eq!(Severity::from(SeverityFilter::Hint), Severity::Hint);
    }

    #[test]
    fn test_args_default_values() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct TestCli {
            #[command(flatten)]
            args: DiagnosticsArgs,
        }

        let cli = TestCli::try_parse_from(["test"]).unwrap();
        assert_eq!(cli.args.path, PathBuf::from("."));
        assert!(!cli.args.no_typecheck);
        assert!(!cli.args.no_lint);
        assert!(!cli.args.strict);
        assert_eq!(cli.args.timeout, 60);
        assert!(matches!(cli.args.severity, SeverityFilter::Hint));
    }

    #[test]
    fn test_sarif_severity_mapping() {
        use tldr_core::diagnostics::Diagnostic;

        let diag = Diagnostic {
            file: PathBuf::from("test.py"),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            severity: Severity::Error,
            message: "test error".to_string(),
            code: Some("E001".to_string()),
            source: "test".to_string(),
            url: None,
        };

        let report = DiagnosticsReport {
            diagnostics: vec![diag],
            summary: tldr_core::diagnostics::DiagnosticsSummary {
                errors: 1,
                warnings: 0,
                info: 0,
                hints: 0,
                total: 1,
            },
            tools_run: vec![],
            files_analyzed: 1,
        };

        let sarif = to_sarif(&report);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].level, "error");
    }

    #[test]
    fn test_baseline_diagnostic_hash() {
        use tldr_core::diagnostics::Diagnostic;

        let diag1 = Diagnostic {
            file: PathBuf::from("test.py"),
            line: 10,
            column: 5,
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            message: "test warning".to_string(),
            code: Some("W001".to_string()),
            source: "test".to_string(),
            url: None,
        };

        let diag2 = Diagnostic {
            file: PathBuf::from("test.py"),
            line: 10,
            column: 5,
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            message: "test warning".to_string(), // Same message
            code: Some("W001".to_string()),
            source: "test".to_string(),
            url: None,
        };

        let bd1: BaselineDiagnostic = (&diag1).into();
        let bd2: BaselineDiagnostic = (&diag2).into();

        assert_eq!(bd1, bd2);
        assert_eq!(bd1.message_hash, bd2.message_hash);
    }

    // =====================================================================
    // fix-C5-5 (v0.5.0 AUDIT-FIX): the no-tools advisory must not dangle.
    // =====================================================================

    /// RED→GREEN: for a language with NO tool integration (Luau), the
    /// advisory must be a complete sentence — it must NOT end with the
    /// dangling "Install one of:" promise followed by nothing.
    ///
    /// NOTE (T6b): this test used to target OCaml, but T6b adds an OCaml
    /// diagnostics integration (`dune build @check`), so OCaml is no longer
    /// a "no integration" language. Luau still has none, so it is the
    /// correct fixture for the genuinely-unsupported path.
    #[test]
    fn test_no_tools_advisory_not_dangling_for_unsupported_language() {
        // Precondition: Luau genuinely has no tool config.
        assert!(
            tools_for_language(Language::Luau).is_empty(),
            "test precondition: Luau must have no diagnostic tool config"
        );

        let msg = build_no_tools_advisory(Language::Luau);

        // Contract pinned by hygiene_and_crash_fixes_v1: the leading phrase
        // must be present.
        assert!(
            msg.contains("No diagnostic tools available"),
            "advisory must keep the pinned 'No diagnostic tools available' phrase: {msg:?}"
        );
        // The defect: a trailing "Install one of:" with no list.
        assert!(
            !msg.contains("Install one of:"),
            "advisory for a language with no tools must NOT dangle an empty 'Install one of:' list: {msg:?}"
        );
        // It must read as informative, not an error.
        assert!(
            msg.contains("not an analysis error"),
            "advisory should clarify this is not an error: {msg:?}"
        );
        // No line should be an empty bullet.
        assert!(
            !msg.lines().any(|l| l.trim() == "-" || l.trim() == "- ()"),
            "advisory must not contain an empty tool bullet: {msg:?}"
        );
    }

    /// Guard: for a language that HAS tool integrations (Python), the
    /// advisory still lists installable tools after "Install one of:".
    #[test]
    fn test_no_tools_advisory_lists_tools_for_supported_language() {
        assert!(
            !tools_for_language(Language::Python).is_empty(),
            "test precondition: Python must have diagnostic tool configs"
        );
        let msg = build_no_tools_advisory(Language::Python);
        assert!(
            msg.contains("No diagnostic tools available"),
            "must keep the pinned phrase: {msg:?}"
        );
        assert!(
            msg.contains("Install one of:"),
            "Python advisory must offer an install list: {msg:?}"
        );
        // At least one concrete tool bullet (e.g. pyright / ruff).
        assert!(
            msg.lines().filter(|l| l.trim_start().starts_with("- ")).count() >= 1,
            "Python advisory must list at least one tool: {msg:?}"
        );
    }

    // =====================================================================
    // T6c (VAL-T6c): the "no tools to run" branch must return DISTINCT exit
    // codes for "no integration exists" vs "known but uninstalled".
    // =====================================================================

    /// RED→GREEN: a language with NO integration (Luau) yields the "N/A"
    /// code 0 (not an analysis error), while a language that HAS integration
    /// but no installed tool still yields the actionable code 60.
    #[test]
    fn test_no_tools_exit_code_splits_states() {
        // Case B — no integration at all: N/A, exit 0 so `set -e` CI does
        // not fail on an unsupported language.
        assert!(
            tools_for_language(Language::Luau).is_empty(),
            "precondition: Luau must have no diagnostic tool config"
        );
        assert_eq!(
            no_tools_exit_code(Language::Luau),
            0,
            "a language with no diagnostic integration must exit 0 (N/A)"
        );

        // Case A — integration exists (Python), tool merely absent: exit 60,
        // reserved for the actionable install-a-tool state (S6-R36).
        assert!(
            !tools_for_language(Language::Python).is_empty(),
            "precondition: Python must have diagnostic tool configs"
        );
        assert_eq!(
            no_tools_exit_code(Language::Python),
            60,
            "a language with known-but-uninstalled tools must stay at exit 60"
        );
    }
}
