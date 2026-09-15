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
use crate::commands::remaining::explain::explain_project_root;
use crate::output::{format_impact_dot, format_impact_text, OutputFormat, OutputWriter};
use crate::path_validation::require_directory;

/// Analyze impact of changing a function
#[derive(Debug, Args)]
pub struct ImpactArgs {
    /// Function name to analyze
    pub function: String,

    /// Project directory or a single file (project root is resolved from it)
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

        // issue-2 (impact-file-arg-v1): `<path>` now accepts a single FILE as
        // well as a directory. A file argument resolves its enclosing project
        // root with the same walk-up `tldr explain` uses
        // (remaining/explain.rs `explain_project_root`), and the language is
        // picked from the file's extension (`Language::from_path`,
        // tldr-core/src/types.rs:208). Directory arguments keep the previous
        // semantics untouched: `require_directory` still rejects a missing
        // path with the clear "Path not found" error (cli-error-clarity-v2
        // P2.BUG-4), and hubs/whatbreaks/change-impact are unaffected.
        //
        // The file argument's ONLY extra role is root resolution — it does
        // NOT double as a target-side file filter. The core filter
        // (`impact_analysis`, tldr-core/src/analysis/impact.rs:144-149)
        // restricts the TARGET's own file, and the queried function is
        // routinely defined in a different file than the one passed
        // (`tldr impact callee caller.py` — the callee lives in callee.py);
        // scoping targets to the passed file would report FunctionNotFound.
        // The explicit `--file` flag keeps that disambiguation role in both
        // modes.
        let (analysis_root, language) = if self.path.is_file() {
            let project_root = explain_project_root(&self.path);
            let language = self
                .lang
                .unwrap_or_else(|| Language::from_path(&self.path).unwrap_or(Language::Python));
            (project_root, language)
        } else {
            // Validate path exists AND is a directory BEFORE language
            // detection / progress banner (lang-detect-default-v1).
            // cli-error-clarity-v2 (P2.BUG-4): reject non-directory paths
            // with a clear message instead of saying "Path not found" or
            // letting downstream surface cryptic IO errors. (Files are
            // handled above; a MISSING path lands here and still gets the
            // clear "Path not found" error.)
            require_directory(&self.path, "impact")?;

            // Determine language (auto-detect from directory, default to Python)
            let language = self.lang.unwrap_or_else(|| {
                Language::from_directory(&self.path).unwrap_or(Language::Python)
            });
            (self.path.clone(), language)
        };

        let type_aware_msg = if self.type_aware { " (type-aware)" } else { "" };

        // Try daemon first for cached result
        if let Some(report) = try_daemon_route::<ImpactReport>(
            &analysis_root,
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
            analysis_root.display(),
            language,
            type_aware_msg
        ));

        // Build call graph first
        let graph = build_project_call_graph(&analysis_root, language, None, true)?;

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
            &analysis_root,
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
        enrich_impact_with_references(&mut report, &analysis_root, &self.function, language);

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
