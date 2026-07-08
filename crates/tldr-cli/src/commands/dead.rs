//! Dead command - Find dead code
//!
//! Identifies functions that are never called (unreachable code).
//! Auto-routes through daemon when available for ~35x speedup.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use tldr_core::callgraph::{
    build_project_call_graph_v2, confidence_tier, BuildConfig, ConfidenceTier,
};
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

    /// Treat weak liveness evidence as dead instead of possibly_dead
    #[arg(long)]
    pub approximate: bool,
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

        // Fallback to direct compute
        let entry_points_for_analysis: Option<Vec<String>> = if self.entry_points.is_empty() {
            None
        } else {
            Some(self.entry_points.clone())
        };

        let mut report = if self.call_graph {
            // Old path: build call graph, then analyze
            writer.progress(&format!(
                "Building call graph for {} ({:?})...",
                self.path.display(),
                language
            ));

            let graph = build_project_call_graph(&self.path, language, None, true)?;

            writer.progress("Extracting all functions...");
            let module_infos = collect_module_infos(&self.path, language, self.no_default_ignore);
            let all_functions: Vec<FunctionRef> = collect_all_functions(&module_infos);

            writer.progress("Analyzing dead code (call graph)...");
            dead_code_analysis(&graph, &all_functions, entry_points_for_analysis.as_deref())?
        } else {
            // New default path: reference counting (single-pass)
            writer.progress(&format!(
                "Scanning {} ({:?}) with reference counting...",
                self.path.display(),
                language
            ));

            let (module_infos, merged_ref_counts) =
                collect_module_infos_with_refcounts(&self.path, language, self.no_default_ignore);
            let all_functions: Vec<FunctionRef> = collect_all_functions(&module_infos);

            writer.progress("Analyzing dead code (refcount)...");
            dead_code_analysis_refcount(
                &all_functions,
                &merged_ref_counts,
                entry_points_for_analysis.as_deref(),
            )?
        };

        let module_infos = collect_module_infos(&self.path, language, self.no_default_ignore);
        let all_functions: Vec<FunctionRef> = collect_all_functions(&module_infos);
        apply_weak_liveness_policy(
            &mut report,
            &all_functions,
            &self.path,
            language,
            self.approximate,
        );

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
                schema: "dead.v2",
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
    path.to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(".d.ts")
}

/// Collect ModuleInfo from all files in a directory using detailed AST extraction.
///
/// This provides the enriched function metadata (decorators, visibility, etc.)
/// needed for accurate dead code analysis with low false-positive rates.
fn collect_module_infos(
    path: &Path,
    language: Language,
    no_default_ignore: bool,
) -> Vec<(PathBuf, ModuleInfo)> {
    let mut module_infos = Vec::new();

    if path.is_file() {
        // M6: skip .d.ts declaration-only files
        if is_typescript_declaration_file(path) {
            return module_infos;
        }
        if let Ok(mut info) = extract_file(path, path.parent()) {
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
                        if let Ok(mut info) = extract_file(file_path, Some(path)) {
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
                    }
                }
            }
        }
    }

    module_infos
}

/// Collect ModuleInfo AND identifier reference counts in a single pass.
///
/// For each file, we parse once with tree-sitter and then run both:
/// - `extract_from_tree()` to get ModuleInfo (functions, classes, imports)
/// - `count_identifiers_in_tree()` to get identifier occurrence counts
///
/// The identifier counts are merged into a single project-wide HashMap.
pub(crate) fn collect_module_infos_with_refcounts(
    path: &Path,
    language: Language,
    no_default_ignore: bool,
) -> (Vec<(PathBuf, ModuleInfo)>, HashMap<String, usize>) {
    let mut module_infos = Vec::new();
    let mut merged_counts: HashMap<String, usize> = HashMap::new();

    if path.is_file() {
        // M6: skip .d.ts declaration-only files (still produce empty
        // module_infos / counts so callers behave gracefully).
        if is_typescript_declaration_file(path) {
            return (module_infos, merged_counts);
        }
        if let Ok((tree, source, lang)) = parse_file(path) {
            // Extract ModuleInfo from the parsed tree
            if let Ok(mut info) = extract_from_tree(&tree, &source, lang, path, path.parent()) {
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
                        if let Ok((tree, source, lang)) = parse_file(file_path) {
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
                    }
                }
            }
        }
    }

    (module_infos, merged_counts)
}

fn apply_weak_liveness_policy(
    report: &mut DeadCodeReport,
    all_functions: &[FunctionRef],
    root: &Path,
    language: Language,
    approximate: bool,
) {
    let mut config = BuildConfig {
        language: format!("{:?}", language).to_lowercase(),
        ..Default::default()
    };
    if let Some(workspace) = tldr_core::types::WorkspaceConfig::discover(root) {
        config.workspace_roots = workspace.roots;
    }
    let Ok(ir) = build_project_call_graph_v2(root, config) else {
        return;
    };

    let mut strong_called: HashSet<(String, String)> = HashSet::new();
    let mut weak_evidence: HashMap<(String, String), Vec<String>> = HashMap::new();

    for edge in &ir.edges {
        let key = function_key(&edge.dst_file, &edge.dst_func);
        match confidence_tier(edge.rung) {
            ConfidenceTier::T1 => {
                strong_called.insert(key);
            }
            ConfidenceTier::T2 => {
                weak_evidence
                    .entry(key)
                    .or_default()
                    .push(format!("t2-edge-only:{}", edge.rung.id()));
            }
        }
    }

    for unresolved in &ir.unresolved {
        add_unresolved_name_match_evidence(&mut weak_evidence, &unresolved.target, all_functions);
    }

    for evidence in weak_evidence.values_mut() {
        evidence.sort();
        evidence.dedup();
    }

    let all_by_key: HashMap<(String, String), FunctionRef> = all_functions
        .iter()
        .map(|func| (function_key(&func.file, &func.name), func.clone()))
        .collect();

    report
        .dead_functions
        .retain(|func| !strong_called.contains(&function_key(&func.file, &func.name)));
    report
        .possibly_dead
        .retain(|func| !strong_called.contains(&function_key(&func.file, &func.name)));

    for (key, evidence) in weak_evidence {
        if strong_called.contains(&key) {
            continue;
        }
        report
            .dead_functions
            .retain(|func| function_key(&func.file, &func.name) != key);
        if let Some(existing) = report
            .possibly_dead
            .iter_mut()
            .find(|func| function_key(&func.file, &func.name) == key)
        {
            existing.dead_evidence = evidence;
        } else if let Some(func) = all_by_key.get(&key) {
            let mut weak_func = func.clone();
            weak_func.dead_evidence = evidence;
            report.possibly_dead.push(weak_func);
        }
    }

    if approximate {
        let promoted = std::mem::take(&mut report.possibly_dead);
        for func in promoted {
            if !report
                .dead_functions
                .iter()
                .any(|existing| existing.file == func.file && existing.name == func.name)
            {
                report.dead_functions.push(func);
            }
        }
    }

    sort_and_dedup_functions(&mut report.dead_functions);
    sort_and_dedup_functions(&mut report.possibly_dead);
    recompute_dead_report_summary(report);
}

fn function_key(file: &Path, name: &str) -> (String, String) {
    (normalize_path_for_key(file), name.to_string())
}

fn add_unresolved_name_match_evidence(
    weak_evidence: &mut HashMap<(String, String), Vec<String>>,
    unresolved_target: &str,
    all_functions: &[FunctionRef],
) {
    let unresolved_leaf = last_name_segment(unresolved_target);
    if unresolved_leaf.is_empty() {
        return;
    }
    for func in all_functions {
        if last_name_segment(&func.name) == unresolved_leaf {
            weak_evidence
                .entry(function_key(&func.file, &func.name))
                .or_default()
                .push(format!("unresolved-name-match:{unresolved_leaf}"));
        }
    }
}

fn normalize_path_for_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn last_name_segment(name: &str) -> &str {
    let after_colons = name.rsplit("::").next().unwrap_or(name);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

fn sort_and_dedup_functions(functions: &mut Vec<FunctionRef>) {
    functions.sort_by(|a, b| a.file.cmp(&b.file).then_with(|| a.name.cmp(&b.name)));
    functions.dedup_by(|a, b| a.file == b.file && a.name == b.name);
}

fn recompute_dead_report_summary(report: &mut DeadCodeReport) {
    report.total_dead = report.dead_functions.len();
    report.total_possibly_dead = report.possibly_dead.len();
    report.dead_percentage = if report.total_functions > 0 {
        (report.total_dead as f64 / report.total_functions as f64) * 100.0
    } else {
        0.0
    };

    let mut by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for func in &report.dead_functions {
        by_file
            .entry(func.file.clone())
            .or_default()
            .push(func.name.clone());
    }
    for funcs in by_file.values_mut() {
        funcs.sort();
        funcs.dedup();
    }
    report.by_file = by_file;
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
    schema: &'static str,
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
        for (path, funcs) in report.by_file {
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

    output.push('\n');

    if !report.by_file.is_empty() {
        output.push_str("Definitely dead:\n");
        for (file, funcs) in &report.by_file {
            output.push_str(&format!("{}\n", file.display().to_string().green()));
            for func in funcs {
                let line = report
                    .dead_functions
                    .iter()
                    .find(|f| &f.file == file && &f.name == func)
                    .map(|f| f.line)
                    .unwrap_or(0);
                output.push_str(&format!("  - {}:{}\n", line, func.red()));
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

#[cfg(test)]
mod val032_tests {
    use super::*;

    #[test]
    fn unresolved_name_match_records_weak_liveness_evidence() {
        let all_functions = vec![
            FunctionRef {
                file: PathBuf::from("helpers.py"),
                name: "globals".to_string(),
                line: 1,
                signature: "globals()".to_string(),
                ref_count: 1,
                is_public: true,
                is_test: false,
                is_trait_method: false,
                is_method: false,
                has_decorator: false,
                decorator_names: Vec::new(),
                dead_evidence: Vec::new(),
            },
            FunctionRef {
                file: PathBuf::from("helpers.py"),
                name: "_truly_dead".to_string(),
                line: 4,
                signature: "_truly_dead()".to_string(),
                ref_count: 1,
                is_public: false,
                is_test: false,
                is_trait_method: false,
                is_method: false,
                has_decorator: false,
                decorator_names: Vec::new(),
                dead_evidence: Vec::new(),
            },
        ];
        let mut weak_evidence = HashMap::new();

        add_unresolved_name_match_evidence(&mut weak_evidence, "builtins.globals", &all_functions);

        assert_eq!(
            weak_evidence
                .get(&("helpers.py".to_string(), "globals".to_string()))
                .cloned(),
            Some(vec!["unresolved-name-match:globals".to_string()])
        );
        assert!(
            !weak_evidence.contains_key(&("helpers.py".to_string(), "_truly_dead".to_string())),
            "unresolved-name-match must not keep unrelated functions alive"
        );
    }
}
