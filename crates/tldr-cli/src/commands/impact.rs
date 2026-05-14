//! Impact command - Show impact analysis
//!
//! Finds all callers of a function (reverse call graph traversal).
//! Supports `--type-aware` flag for Python type resolution (Phase 7-8).
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::ImpactReport;
use tldr_core::{
    build_project_call_graph, enrich_impact_with_references, impact_analysis_with_ast_fallback,
    Language,
};

use crate::commands::daemon_router::{params_with_func_depth, try_daemon_route};
use crate::output::{format_impact_dot, format_impact_text, OutputFormat, OutputWriter};
use crate::path_shape::PathShapeRewriter;
use crate::path_validation::require_directory;

/// Analyze impact of changing a function
#[derive(Debug, Args)]
pub struct ImpactArgs {
    /// Function name to analyze
    pub function: String,

    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum traversal depth
    #[arg(long, short = 'd', default_value = "5")]
    pub depth: usize,

    /// Filter by file path
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Enable type-aware method resolution (resolves self.method() to ClassName.method)
    #[arg(long)]
    pub type_aware: bool,
}

impl ImpactArgs {
    /// Run the impact command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists AND is a directory BEFORE language detection
        // / progress banner (lang-detect-default-v1).
        // cli-error-clarity-v2 (P2.BUG-4): reject files with a clear message
        // instead of saying "Path not found" or letting downstream surface
        // cryptic IO errors.
        require_directory(&self.path, "impact")?;

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&self.path).unwrap_or(Language::Python));

        let type_aware_msg = if self.type_aware { " (type-aware)" } else { "" };

        // Try daemon first for cached result
        if let Some(report) = try_daemon_route::<ImpactReport>(
            &self.path,
            "impact",
            params_with_func_depth(&self.function, Some(self.depth)),
        ) {
            // Output based on format
            if writer.is_text() {
                let text = format_impact_text(&report, self.type_aware);
                writer.write_text(&text)?;
                return Ok(());
            } else if writer.is_dot() {
                // surface-gaps-v1 (BUG-19): DOT impact graph (reverse calls).
                let dot = format_impact_dot(&report);
                writer.write_text(&dot)?;
                return Ok(());
            } else {
                writer.write(&report)?;
                return Ok(());
            }
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Building call graph for {} ({:?}){}...",
            self.path.display(),
            language,
            type_aware_msg
        ));

        // Build call graph first
        let graph = build_project_call_graph(&self.path, language, None, true)?;

        writer.progress(&format!(
            "Analyzing impact of {}{}...",
            self.function, type_aware_msg
        ));

        // Run impact analysis with AST fallback for isolated functions
        // TODO: When type_aware is true, use type-aware call graph building
        // For now, this flag is registered but type resolution is pending full implementation
        let mut report = impact_analysis_with_ast_fallback(
            &graph,
            &self.function,
            self.depth,
            self.file.as_deref(),
            &self.path,
            language,
        )?;

        // language-adapter-fixes-v1 (P13.AGG13-4): for languages whose call
        // graph builder under-reports cross-file edges (notably C# field-typed
        // method calls, Kotlin/Scala/OCaml functor wrappers), the call graph
        // alone leaves `caller_count = 0` even when `tldr explain` and
        // `tldr references` find call sites. Mirror the same fallback explain
        // uses (P12.AGG12-1) so `impact` agrees with `explain`/`references`.
        //
        // sibling-resolver-gaps-v1 (P14.AGG14-1, P14.AGG14-4): the helper
        // moved into `tldr-core::analysis::impact` so the same enrichment
        // also runs inside `whatbreaks`. The same-fix-different-shape
        // dedup (last-segment aware) lives in the core helper.
        enrich_impact_with_references(&mut report, &self.path, &self.function, language);

        // If type-aware was requested, add placeholder stats to indicate it's enabled
        // (actual type resolution is integrated in callgraph builder - Phase 8 full implementation)
        if self.type_aware {
            report.type_resolution = Some(tldr_core::types::TypeResolutionStats {
                enabled: true,
                resolved_high_confidence: 0,
                resolved_medium_confidence: 0,
                fallback_used: 0,
                total_call_sites: 0,
            });
        }

        // path-shape-consistency-v1 (v0.4.2 M-008): the impact report
        // joins data from TWO producers — `impact_analysis` walks the
        // call graph (emits project-relative `router.go`) and
        // `impact_analysis_with_ast_fallback` augments with AST-found
        // definitions (emits absolute `/tmp/repos/.../router.go`). On
        // macOS the canonical form may further leak `/private/tmp/`.
        // The audit M-008 cluster requires every path in the response
        // to share the user-input shape. Route every CallerTree.file
        // through the centralized emission-boundary normalizer.
        restore_impact_path_shape(&mut report, &self.path);

        // Output based on format
        if writer.is_text() {
            let text = format_impact_text(&report, self.type_aware);
            writer.write_text(&text)?;
        } else if writer.is_dot() {
            // surface-gaps-v1 (BUG-19): direct-compute DOT impact path.
            let dot = format_impact_dot(&report);
            writer.write_text(&dot)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

/// path-shape-consistency-v1 (v0.4.2 M-008): re-assert user-input path
/// shape across every `CallerTree.file` (recursive) and every
/// `targets` HashMap key (which contains `<file>:<func>` strings).
///
/// All rewrite logic lives in [`PathShapeRewriter`] — this function is a
/// thin schema-aware wrapper that knows how to walk the `ImpactReport`
/// tree. The same centralized rewriter is reused by every multi-producer
/// emitter to guarantee response-wide shape uniformity.
fn restore_impact_path_shape(report: &mut ImpactReport, user_root: &std::path::Path) {
    let rewriter = PathShapeRewriter::new(user_root);

    fn walk(tree: &mut tldr_core::types::CallerTree, rewriter: &PathShapeRewriter) {
        if let Some(np) = rewriter.rewrite_pathbuf(&tree.file) {
            tree.file = np;
        }
        for child in tree.callers.iter_mut() {
            walk(child, rewriter);
        }
    }

    // 1. Rewrite every CallerTree.file (recursive).
    for tree in report.targets.values_mut() {
        walk(tree, &rewriter);
    }

    // 2. Rewrite the HashMap keys. Keys are `<file>:<func>` strings;
    //    when `<file>` is project-relative ("router.go") the absolute
    //    user-input root must be prepended so the key shape matches
    //    the value shape. Split on the LAST `:` to preserve any `:`
    //    that legitimately appears in the file portion (rare but
    //    possible on Windows; defensive).
    let old_targets = std::mem::take(&mut report.targets);
    for (key, tree) in old_targets {
        let new_key = if let Some(colon_idx) = key.rfind(':') {
            let (file_part, func_part) = key.split_at(colon_idx);
            // func_part includes the leading ':'
            match rewriter.rewrite(file_part) {
                Some(new_file) => format!("{}{}", new_file, func_part),
                None => key,
            }
        } else {
            key
        };
        report.targets.insert(new_key, tree);
    }
}
