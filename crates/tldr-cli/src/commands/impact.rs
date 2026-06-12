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

        // cl15-polyglot-v1 (v0.5.0 CL-15): determine the set of languages to
        // analyze. When the user did NOT pin `--lang`, build a MERGED call
        // graph across EVERY detected language and run the impact analysis
        // (plus per-language AST fallback) against it — so callers in any
        // language are resolved, not just those in the dominant one. When the
        // user DID pin `--lang`, restrict to that language but emit a clear
        // stderr WARNING naming the dropped languages + file counts.
        let scan_languages: Vec<Language> = if self.lang.is_some() {
            crate::commands::polyglot::warn_if_languages_dropped(&self.path, language);
            vec![language]
        } else {
            let mut langs = crate::commands::polyglot::detected_language_list(&self.path);
            if langs.is_empty() {
                langs.push(language);
            }
            langs
        };

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

        // cl15-polyglot-v1 (v0.5.0 CL-15): build ONE merged call graph that
        // unions every detected language's edges. The per-language V2 builder
        // filters to that language's `scan_extensions()` family, so a polyglot
        // tree needs one build pass per language; we fold every edge into a
        // single `ProjectCallGraph`. Impact's graph walk is language-agnostic
        // (it just traverses edges), so the merged graph resolves callers in
        // any language.
        let mut graph = tldr_core::types::ProjectCallGraph::new();
        for scan_lang in &scan_languages {
            let g = build_project_call_graph(&self.path, *scan_lang, None, true)?;
            for edge in g.edges() {
                graph.add_edge(edge.clone());
            }
        }

        writer.progress(&format!(
            "Analyzing impact of {}{}...",
            self.function, type_aware_msg
        ));

        // Run impact analysis with AST fallback for isolated functions, once
        // per detected language. The call-graph walk inside is identical
        // across passes (same merged graph), but the AST fallback +
        // language-specific reconciliation (`find_function_in_ast`,
        // Swift/C#/Kotlin enrichment) is language-specific — so each language
        // contributes its own AST-discovered definitions. Targets keyed by
        // `<file>:<func>` dedup naturally across passes via the BTreeMap.
        //
        // TODO: When type_aware is true, use type-aware call graph building.
        // For now, this flag is registered but type resolution is pending.
        let mut report: Option<ImpactReport> = None;
        // fix-cl-3b-v1 (v0.5.0 CL-3b, IT3-ocaml-02 / #74): the per-language
        // pass must NOT fast-fail the whole command when ONE scanned
        // language doesn't contain the symbol. `impact_analysis_with_ast_fallback`
        // returns `FunctionNotFound` when neither the call graph nor that
        // language's AST scan locate `target` — which is the expected
        // outcome for every language EXCEPT the one that actually defines
        // it. The previous `?` propagated the first such error (e.g. the C
        // stubs in a dune tree) and aborted before the OCaml pass ever ran,
        // so a top-level OCaml `let` that `whatbreaks`' single-language
        // internal impact resolves fine reported "Function not found".
        // We now tolerate per-language `FunctionNotFound`, retaining it only
        // as the fallback error to surface if EVERY language misses.
        let mut last_not_found: Option<anyhow::Error> = None;
        for scan_lang in &scan_languages {
            let mut r = match impact_analysis_with_ast_fallback(
                &graph,
                &self.function,
                self.depth,
                self.file.as_deref(),
                &self.path,
                *scan_lang,
            ) {
                Ok(r) => r,
                Err(tldr_core::TldrError::FunctionNotFound {
                    name,
                    file,
                    suggestions,
                }) => {
                    // Remember it; another language may still resolve the symbol.
                    last_not_found = Some(
                        tldr_core::TldrError::FunctionNotFound {
                            name,
                            file,
                            suggestions,
                        }
                        .into(),
                    );
                    continue;
                }
                Err(other) => return Err(other.into()),
            };

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
            enrich_impact_with_references(&mut r, &self.path, &self.function, *scan_lang);

            match report.as_mut() {
                None => report = Some(r),
                Some(acc) => merge_impact_reports(acc, r),
            }
        }
        // Only error when NO scanned language resolved the symbol.
        let mut report = match report {
            Some(r) => r,
            None => {
                return Err(last_not_found.unwrap_or_else(|| {
                    anyhow::anyhow!("Function not found: {}", self.function)
                }));
            }
        };

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

/// cl15-polyglot-v1 (v0.5.0 CL-15): merge a per-language `ImpactReport`
/// (`incoming`) into the accumulator (`acc`).
///
/// Each polyglot pass runs against the SAME merged call graph, so the
/// graph-walk targets are identical across passes; the only per-pass
/// difference is the language-specific AST fallback, which can add targets
/// (definitions in files the call graph missed) or attach more callers to an
/// existing target. The merge therefore:
///
///  - unions `targets` by their `<file>:<func>` key;
///  - on a key collision keeps whichever `CallerTree` reports MORE callers
///    (the richer of the two — a language pass that resolved real callers
///    beats one that found a bare zero-caller definition row);
///  - recomputes `total_targets` from the merged map.
fn merge_impact_reports(acc: &mut ImpactReport, incoming: ImpactReport) {
    let incoming_type_resolution = incoming.type_resolution;
    for (key, tree) in incoming.targets {
        match acc.targets.get(&key) {
            Some(existing) if existing.caller_count >= tree.caller_count => {
                // Keep the richer existing entry.
            }
            _ => {
                acc.targets.insert(key, tree);
            }
        }
    }
    acc.total_targets = acc.targets.len();
    // Preserve any type-resolution stats already present; the per-pass
    // placeholder is re-applied by the caller after the merge if requested.
    if acc.type_resolution.is_none() {
        acc.type_resolution = incoming_type_resolution;
    }
}

/// path-shape-consistency-v1 (v0.4.2 M-008): re-assert user-input path
/// shape across every `CallerTree.file` (recursive) and every
/// `targets` map key (which contains `<file>:<func>` strings).
///
/// cl1r-determinism-v1 (v0.5.0 CL-1R): `targets` is now a `BTreeMap`, so the
/// take-and-rebuild below re-sorts keys after the path-shape rewrite — the
/// serialized map-key order stays deterministic even though some keys change
/// shape (project-relative -> absolute) during the rewrite.
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

    // 2. Rewrite the map keys. Keys are `<file>:<func>` strings;
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
