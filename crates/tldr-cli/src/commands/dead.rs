//! Dead command - Find dead code
//!
//! Identifies functions that are never called (unreachable code).
//! Auto-routes through daemon when available for ~35x speedup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use tldr_core::walker::ProjectWalker;

/// Maximum number of files to scan in WalkDir traversals.
///
/// Prevents runaway scans in massive monorepos or symlink-heavy layouts.
/// Projects with fewer files are unaffected.
const MAX_FILES: usize = 10_000;

use tldr_core::analysis::dead::dead_code_analysis_refcount;
use tldr_core::analysis::refcount::count_identifiers_in_tree;
use tldr_core::ast::parser::parse_file;
use tldr_core::ast::{extract_file, extract_from_tree};
use tldr_core::types::{DeadCodeReport, ModuleInfo};
use tldr_core::{
    build_project_call_graph, collect_all_functions, dead_code_analysis, FunctionRef, Language,
};

use crate::commands::daemon_router::{params_for_dead, try_daemon_route};
use crate::output::{OutputFormat, OutputWriter};

/// Find dead (unreachable) code
#[derive(Debug, Args)]
pub struct DeadArgs {
    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Custom entry point patterns (comma-separated)
    #[arg(long, short = 'e', value_delimiter = ',')]
    pub entry_points: Vec<String>,

    /// Maximum number of dead functions to display
    #[arg(long, default_value = "100")]
    pub max_items: usize,

    /// Use call-graph-based analysis instead of the default reference counting
    #[arg(long)]
    pub call_graph: bool,

    /// Walk vendored/build dirs (node_modules, target, dist, etc.) that would normally be skipped.
    #[arg(long)]
    pub no_default_ignore: bool,
}

impl DeadArgs {
    /// Run the dead command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists BEFORE language detection / progress banner
        // (lang-detect-default-v1)
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&self.path).unwrap_or(Language::Python));

        // Try daemon first for cached result
        let entry_points: Option<Vec<String>> = if self.entry_points.is_empty() {
            None
        } else {
            Some(self.entry_points.clone())
        };

        if let Some(report) = try_daemon_route::<DeadCodeReport>(
            &self.path,
            "dead",
            params_for_dead(Some(&self.path), entry_points.as_deref()),
        ) {
            // Apply truncation if needed
            let (truncated_report, truncated, total_count, shown_count) =
                apply_truncation(report, self.max_items);

            // Output based on format
            if writer.is_text() {
                let text = format_dead_code_text_truncated(
                    &truncated_report,
                    truncated,
                    total_count,
                    shown_count,
                );
                writer.write_text(&text)?;
                return Ok(());
            } else {
                let _ = (total_count, shown_count); // text path only
                let output = DeadCodeOutput {
                    report: truncated_report,
                    truncated,
                };
                writer.write(&output)?;
                return Ok(());
            }
        }

        // Fallback to direct compute
        let entry_points_for_analysis: Option<Vec<String>> = if self.entry_points.is_empty() {
            None
        } else {
            Some(self.entry_points.clone())
        };

        // TRDD-O66FM8TN: every file the walk could not read is a hole in a
        // whole-program analysis — a function whose only caller lives in a
        // skipped file comes out as dead. The collectors hand back one
        // warning per dropped file; it goes into the report, not to /dev/null.
        let (mut report, skipped) = if self.call_graph {
            // Old path: build call graph, then analyze
            writer.progress(&format!(
                "Building call graph for {} ({:?})...",
                self.path.display(),
                language
            ));

            let graph = build_project_call_graph(&self.path, language, None, true)?;

            writer.progress("Extracting all functions...");
            let (module_infos, skipped) =
                collect_module_infos(&self.path, language, self.no_default_ignore);
            let all_functions: Vec<FunctionRef> = collect_all_functions(&module_infos);

            writer.progress("Analyzing dead code (call graph)...");
            (
                dead_code_analysis(&graph, &all_functions, entry_points_for_analysis.as_deref())?,
                skipped,
            )
        } else {
            // New default path: reference counting (single-pass)
            writer.progress(&format!(
                "Scanning {} ({:?}) with reference counting...",
                self.path.display(),
                language
            ));

            let (module_infos, merged_ref_counts, skipped) =
                collect_module_infos_with_refcounts(&self.path, language, self.no_default_ignore);
            let all_functions: Vec<FunctionRef> = collect_all_functions(&module_infos);

            writer.progress("Analyzing dead code (refcount)...");
            (
                dead_code_analysis_refcount(
                    &all_functions,
                    &merged_ref_counts,
                    entry_points_for_analysis.as_deref(),
                )?,
                skipped,
            )
        };
        report.files_skipped = skipped.len();
        report.warnings = skipped;

        // Apply truncation if needed
        let (truncated_report, truncated, total_count, shown_count) =
            apply_truncation(report, self.max_items);

        // Output based on format
        if writer.is_text() {
            let text = format_dead_code_text_truncated(
                &truncated_report,
                truncated,
                total_count,
                shown_count,
            );
            writer.write_text(&text)?;
        } else {
            let _ = (total_count, shown_count); // text path only
            let output = DeadCodeOutput {
                report: truncated_report,
                truncated,
            };
            writer.write(&output)?;
        }

        Ok(())
    }
}

/// Check if JS/TS source has a file-level 'use server' or 'use client' directive.
/// This is checked on the source string directly (no file I/O) to avoid path resolution issues.
fn source_has_framework_directive(source: &str, ext: &str) -> bool {
    if !matches!(ext, "ts" | "tsx" | "js" | "jsx" | "mjs") {
        return false;
    }
    for line in source.lines().take(5) {
        let trimmed = line.trim();
        if trimmed == r#""use server""#
            || trimmed == r#"'use server'"#
            || trimmed == r#""use server";"#
            || trimmed == r#"'use server';"#
            || trimmed == r#""use client""#
            || trimmed == r#"'use client'"#
            || trimmed == r#""use client";"#
            || trimmed == r#"'use client';"#
        {
            return true;
        }
        // Skip empty lines and comments
        if !trimmed.is_empty()
            && !trimmed.starts_with("//")
            && !trimmed.starts_with("/*")
            && !trimmed.starts_with('*')
            && !trimmed.starts_with('"')
            && !trimmed.starts_with('\'')
        {
            break;
        }
    }
    false
}

/// Tag all functions and class methods in a ModuleInfo with a synthetic decorator
/// if the source contains a framework directive ('use server'/'use client').
fn tag_directive_functions(info: &mut ModuleInfo, source: &str, path: &Path) {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if source_has_framework_directive(source, ext) {
        for func in &mut info.functions {
            if !func
                .decorators
                .contains(&"use_server_directive".to_string())
            {
                func.decorators.push("use_server_directive".to_string());
            }
        }
        for class in &mut info.classes {
            for method in &mut class.methods {
                if !method
                    .decorators
                    .contains(&"use_server_directive".to_string())
                {
                    method.decorators.push("use_server_directive".to_string());
                }
            }
        }
    }
}

/// inheritance-and-dead-cleanup-v1 (M6): TypeScript declaration files
/// (`.d.ts`) contain only `interface` / `type` / ambient declarations — no
/// executable code. Including them in dead-code analysis produces false
/// "possibly_dead" findings for every declared symbol. Mirrors the
/// oversize-skip pattern used elsewhere in the codebase.
fn is_typescript_declaration_file(path: &Path) -> bool {
    path.to_string_lossy().to_ascii_lowercase().ends_with(".d.ts")
}

/// Collect ModuleInfo from all files in a directory using detailed AST extraction.
///
/// This provides the enriched function metadata (decorators, visibility, etc.)
/// needed for accurate dead code analysis with low false-positive rates.
///
/// Returns the module infos plus one warning per file that was dropped because
/// it could not be read or parsed (TRDD-O66FM8TN) — callers must surface them.
fn collect_module_infos(
    path: &Path,
    language: Language,
    no_default_ignore: bool,
) -> (Vec<(PathBuf, ModuleInfo)>, Vec<String>) {
    let mut module_infos = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    if path.is_file() {
        // M6: skip .d.ts declaration-only files
        if is_typescript_declaration_file(path) {
            return (module_infos, skipped);
        }
        match extract_file(path, path.parent()) {
            Ok(mut info) => {
                if let Ok(source) = std::fs::read_to_string(path) {
                    tag_directive_functions(&mut info, &source, path);
                }
                // Use filename only for single files (matches call graph convention)
                let rel_path = path
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| path.to_path_buf());
                module_infos.push((rel_path, info));
            }
            Err(e) => skipped.push(tldr_core::fs::skipped_file_warning(path, e)),
        }
    } else {
        // language-coverage-fixes-v1 (P4.BUG-N1, P4.BUG-N5): use
        // `scan_extensions()` so C++ dir scans include `.h` and JS/TS
        // sibling extensions (`.tsx` ↔ `.jsx`) participate together.
        let extensions: &[&str] = language.scan_extensions();
        let mut file_count: usize = 0;
        // residual-bugs-v1 (P15.AGG14-7-cascade): pass the resolved
        // language to the walker so JS/TS source under `src/build/` or
        // `packages/x/dist/` is preserved (mirrors the per-language gate
        // in `crates/tldr-core/src/callgraph/scanner.rs`). Without this
        // hint, `tldr dead /tmp/repos/ts-dom-gen` returned
        // `functions_analyzed: 0` because the walker silently skipped
        // `src/build/`, where the entire authored TypeScript surface
        // lives.
        let mut walker = ProjectWalker::new(path).lang_hint(language);
        if no_default_ignore {
            walker = walker.no_default_ignore();
        }
        for entry in walker.iter() {
            let file_path = entry.path();
            if file_path.is_file() {
                // M6: skip .d.ts declaration-only files
                if is_typescript_declaration_file(file_path) {
                    continue;
                }
                if let Some(ext_str) = file_path.extension().and_then(|e| e.to_str()) {
                    let dotted = format!(".{}", ext_str);
                    if extensions.contains(&dotted.as_str()) {
                        file_count += 1;
                        if file_count > MAX_FILES {
                            eprintln!(
                                "Warning: dead code scan truncated at {} files in {}",
                                MAX_FILES,
                                path.display()
                            );
                            break;
                        }
                        match extract_file(file_path, Some(path)) {
                            Ok(mut info) => {
                                // Tag functions with framework directive from source
                                if let Ok(source) = std::fs::read_to_string(file_path) {
                                    tag_directive_functions(&mut info, &source, file_path);
                                }
                                // Use relative path to match call graph edge convention
                                let rel_path = file_path
                                    .strip_prefix(path)
                                    .unwrap_or(file_path)
                                    .to_path_buf();
                                module_infos.push((rel_path, info));
                            }
                            // TRDD-O66FM8TN: was `if let Ok(..)` — an unreadable
                            // file vanished from the analysis with no trace.
                            Err(e) => {
                                skipped.push(tldr_core::fs::skipped_file_warning(file_path, e))
                            }
                        }
                    }
                }
            }
        }
    }

    (module_infos, skipped)
}

/// Collect ModuleInfo AND identifier reference counts in a single pass.
///
/// For each file, we parse once with tree-sitter and then run both:
/// - `extract_from_tree()` to get ModuleInfo (functions, classes, imports)
/// - `count_identifiers_in_tree()` to get identifier occurrence counts
///
/// The identifier counts are merged into a single project-wide HashMap.
///
/// The third element is one warning per file that was dropped because it could
/// not be read or parsed (TRDD-O66FM8TN). Reference counting is whole-program:
/// a dropped file takes its references with it, so every caller must surface
/// these rather than bind them to `_`.
pub(crate) fn collect_module_infos_with_refcounts(
    path: &Path,
    language: Language,
    no_default_ignore: bool,
) -> (
    Vec<(PathBuf, ModuleInfo)>,
    HashMap<String, usize>,
    Vec<String>,
) {
    let mut module_infos = Vec::new();
    let mut merged_counts: HashMap<String, usize> = HashMap::new();
    let mut skipped: Vec<String> = Vec::new();

    if path.is_file() {
        // M6: skip .d.ts declaration-only files (still produce empty
        // module_infos / counts so callers behave gracefully).
        if is_typescript_declaration_file(path) {
            return (module_infos, merged_counts, skipped);
        }
        match parse_file(path) {
            Ok((tree, source, lang)) => {
                // Extract ModuleInfo from the parsed tree
                if let Ok(mut info) = extract_from_tree(&tree, &source, lang, path, path.parent())
                {
                    tag_directive_functions(&mut info, &source, path);
                    let rel_path = path
                        .file_name()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| path.to_path_buf());
                    module_infos.push((rel_path, info));
                }
                // Count identifiers from the same parsed tree
                let file_counts = count_identifiers_in_tree(&tree, source.as_bytes(), lang);
                for (name, count) in file_counts {
                    *merged_counts.entry(name).or_insert(0) += count;
                }
            }
            Err(e) => skipped.push(tldr_core::fs::skipped_file_warning(path, e)),
        }
    } else {
        // language-coverage-fixes-v1 (P4.BUG-N1, P4.BUG-N5): use
        // `scan_extensions()` so C++ dir scans include `.h` and JS/TS
        // sibling extensions (`.tsx` ↔ `.jsx`) participate together.
        let extensions: &[&str] = language.scan_extensions();
        let mut file_count: usize = 0;
        // residual-bugs-v1 (P15.AGG14-7-cascade): pass the resolved
        // language to the walker so JS/TS source under `src/build/` or
        // `packages/x/dist/` is preserved (mirrors the per-language gate
        // in `crates/tldr-core/src/callgraph/scanner.rs`). Without this
        // hint, `tldr dead /tmp/repos/ts-dom-gen` returned
        // `functions_analyzed: 0` because the walker silently skipped
        // `src/build/`, where the entire authored TypeScript surface
        // lives.
        let mut walker = ProjectWalker::new(path).lang_hint(language);
        if no_default_ignore {
            walker = walker.no_default_ignore();
        }
        for entry in walker.iter() {
            let file_path = entry.path();
            if file_path.is_file() {
                // M6: skip .d.ts declaration-only files
                if is_typescript_declaration_file(file_path) {
                    continue;
                }
                if let Some(ext_str) = file_path.extension().and_then(|e| e.to_str()) {
                    let dotted = format!(".{}", ext_str);
                    if extensions.contains(&dotted.as_str()) {
                        file_count += 1;
                        if file_count > MAX_FILES {
                            eprintln!(
                                "Warning: born-dead scan truncated at {} files in {}",
                                MAX_FILES,
                                path.display()
                            );
                            break;
                        }
                        match parse_file(file_path) {
                            Ok((tree, source, lang)) => {
                                // Extract ModuleInfo from the parsed tree
                                if let Ok(mut info) =
                                    extract_from_tree(&tree, &source, lang, file_path, Some(path))
                                {
                                    // Tag functions with framework directive while we have the source
                                    tag_directive_functions(&mut info, &source, file_path);
                                    let rel_path = file_path
                                        .strip_prefix(path)
                                        .unwrap_or(file_path)
                                        .to_path_buf();
                                    module_infos.push((rel_path, info));
                                }
                                // Count identifiers from the same parsed tree
                                let file_counts =
                                    count_identifiers_in_tree(&tree, source.as_bytes(), lang);
                                for (name, count) in file_counts {
                                    *merged_counts.entry(name).or_insert(0) += count;
                                }
                            }
                            // TRDD-O66FM8TN: was `if let Ok(..)`. This is the
                            // default `tldr dead` path, and a UTF-16 caller
                            // file silently dropped here turned every function
                            // it called into a "possibly dead" false positive.
                            Err(e) => {
                                skipped.push(tldr_core::fs::skipped_file_warning(file_path, e))
                            }
                        }
                    }
                }
            }
        }
    }

    (module_infos, merged_counts, skipped)
}

/// Wrapper struct for JSON output with truncation metadata.
///
/// low-cleanup-bundle-v1 (L5): the previous shape redundantly carried three
/// near-identical counters (`total_dead == total_count == shown_count` on
/// the un-truncated case). We dropped `total_count` (duplicate of the
/// canonical `total_dead` in `DeadCodeReport`) and `shown_count` (always
/// derivable from `dead_functions.len()`), keeping only the boolean
/// `truncated` flag for the rare case the list was clipped by --max-items.
#[derive(Serialize)]
struct DeadCodeOutput {
    #[serde(flatten)]
    report: DeadCodeReport,
    #[serde(skip_serializing_if = "is_false", default)]
    truncated: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Apply truncation to the report based on max_items.
fn apply_truncation(
    mut report: DeadCodeReport,
    max_items: usize,
) -> (DeadCodeReport, bool, usize, usize) {
    let total_count = report.dead_functions.len();

    if total_count > max_items {
        report.dead_functions.truncate(max_items);
        // Also truncate by_file to match
        let mut count = 0;
        let mut new_by_file = std::collections::HashMap::new();
        // why: `by_file` is a HashMap, so its iteration order is
        // nondeterministic; sort by path first so which files get
        // truncated (and their order) is stable across runs.
        let mut entries: Vec<_> = report.by_file.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (path, funcs) in entries {
            let remaining = max_items - count;
            if remaining == 0 {
                break;
            }
            let to_take = funcs.len().min(remaining);
            let truncated_funcs: Vec<String> = funcs.into_iter().take(to_take).collect();
            count += truncated_funcs.len();
            new_by_file.insert(path, truncated_funcs);
        }
        report.by_file = new_by_file;
        (report, true, total_count, max_items)
    } else {
        (report, false, total_count, total_count)
    }
}

/// Format dead code report with optional truncation notice.
fn format_dead_code_text_truncated(
    report: &DeadCodeReport,
    truncated: bool,
    total_count: usize,
    shown_count: usize,
) -> String {
    use colored::Colorize;

    let mut output = String::new();

    output.push_str(&format!(
        "Dead Code Analysis\n\nDefinitely dead: {} / {} functions ({:.1}% dead)\n",
        report.total_dead.to_string().red(),
        report.total_functions,
        report.dead_percentage
    ));

    if report.total_possibly_dead > 0 {
        output.push_str(&format!(
            "Possibly dead (public but uncalled): {}\n",
            report.total_possibly_dead.to_string().yellow()
        ));
    }

    // TRDD-O66FM8TN: name every dropped file right under the headline
    // numbers, because those numbers were computed without it.
    if !report.warnings.is_empty() {
        output.push_str(&format!(
            "Files skipped: {} (results exclude them)\n",
            report.files_skipped.to_string().yellow()
        ));
        for warning in &report.warnings {
            output.push_str(&format!("  {}\n", warning.yellow()));
        }
    }

    output.push('\n');

    if !report.by_file.is_empty() {
        output.push_str("Definitely dead:\n");
        // why: `by_file` is a HashMap, so iterating it directly makes text
        // output nondeterministic (files list in a different order each
        // run), which breaks reproducibility and snapshot testing.
        let mut files: Vec<_> = report.by_file.iter().collect();
        files.sort_by(|a, b| a.0.cmp(b.0));
        for (file, funcs) in files {
            output.push_str(&format!("{}\n", file.display().to_string().green()));
            for func in funcs {
                output.push_str(&format!("  - {}\n", func.red()));
            }
            output.push('\n');
        }
    }

    if truncated {
        output.push_str(&format!(
            "\n[{}: showing {} of {} dead functions]\n",
            "TRUNCATED".yellow(),
            shown_count,
            total_count
        ));
    }

    output
}
