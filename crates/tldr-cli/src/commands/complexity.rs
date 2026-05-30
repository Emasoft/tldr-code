//! Complexity command - Calculate function complexity metrics
//!
//! Returns ComplexityMetrics with cyclomatic, cognitive, max_nesting, and lines_of_code.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::ComplexityMetrics;
use tldr_core::{calculate_complexity, detect_or_parse_language, validate_file_path, Language};

use crate::commands::daemon_router::{params_with_file_function, try_daemon_route};
use crate::commands::elixir_per_clause;
use crate::output::{format_complexity_text, OutputFormat, OutputWriter};

/// Calculate complexity metrics for a function
#[derive(Debug, Args)]
pub struct ComplexityArgs {
    /// file containing the function
    pub file: PathBuf,

    /// Function name to analyze
    pub function: String,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt in to the
    /// bare-name fallback for Rust / C / C++ `Class::method` inputs.
    /// Default behaviour is strict-qualified (the canonical
    /// `find_function_node` C/C++/Rust `::` branch already handles
    /// the qualified form). With `--qualified` set, the CLI also
    /// pre-canonicalises the input via
    /// `tldr_core::ast::function_finder::resolve_qualified_function_name`
    /// so the lookup short-circuits to the rightmost bare segment.
    #[arg(long)]
    pub qualified: bool,
}

impl ComplexityArgs {
    /// Run the complexity command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate file path exists (M28: shared validator - returns PathNotFound error)
        let validated_path = validate_file_path(self.file.to_str().unwrap_or_default(), None)?;

        // Detect language up front so we can apply the m117 D8
        // `--qualified` pre-canonicaliser before we hit either the
        // daemon route or the direct-compute path.
        let language =
            detect_or_parse_language(self.lang.as_ref().map(|l| l.as_str()), &validated_path)?;

        // m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt-in bare-name
        // canonicalisation. Default is strict-qualified (no-op).
        let function = tldr_core::ast::function_finder::resolve_qualified_function_name(
            &self.function,
            language,
            self.qualified,
        );

        // Try daemon first for cached result (use file's parent as project root)
        let project = validated_path.parent().unwrap_or(&validated_path);
        if let Some(result) = try_daemon_route::<ComplexityMetrics>(
            project,
            "complexity",
            params_with_file_function(&validated_path, &function),
        ) {
            if writer.is_text() {
                writer.write_text(&format_complexity_text(&result))?;
            } else {
                writer.write(&result)?;
            }
            return Ok(());
        }

        // Fallback to direct compute

        writer.progress(&format!(
            "Calculating complexity for {} in {} ({:?})...",
            function,
            validated_path.display(),
            language
        ));

        // Calculate complexity - the function takes file path as string
        let result = calculate_complexity(
            validated_path.to_str().unwrap_or_default(),
            &function,
            language,
        )?;

        // elixir-per-clause-dfg-cfg-v1 (v0.4.2 M-031): for Elixir
        // multi-clause `def NAME`, iterate every body-bearing clause and
        // emit a `per_clauses: [...]` array. The legacy top-level
        // metrics stay populated with the first-body-bearing-clause's
        // result (M-E1 selector) for backwards compatibility.
        let per_clauses = elixir_per_clause::for_each_body_bearing_clause(
            &validated_path,
            &function,
            language,
            |tmp_path, _clause, _offset| -> anyhow::Result<ComplexityMetrics> {
                Ok(calculate_complexity(
                    tmp_path.to_str().unwrap_or_default(),
                    &function,
                    language,
                )?)
            },
        )?;

        // Output based on format
        if writer.is_text() {
            writer.write_text(&format_complexity_text(&result))?;
            return Ok(());
        }
        if let Some(per_clauses) = per_clauses {
            let clauses = elixir_per_clause::list_body_bearing_clauses(
                &validated_path,
                &function,
                language,
            )
            .unwrap_or_default();
            #[derive(serde::Serialize)]
            struct PerClauseEntry {
                start_line: u32,
                end_line: u32,
                arity: usize,
                has_body: bool,
                cyclomatic: u32,
                cognitive: u32,
                max_nesting: u32,
                lines_of_code: u32,
            }
            let entries: Vec<PerClauseEntry> = clauses
                .iter()
                .zip(per_clauses.iter())
                .map(|(c, m)| PerClauseEntry {
                    start_line: c.start_line,
                    end_line: c.end_line,
                    arity: c.arity,
                    has_body: c.has_body,
                    cyclomatic: m.cyclomatic,
                    cognitive: m.cognitive,
                    max_nesting: m.max_nesting,
                    lines_of_code: m.lines_of_code,
                })
                .collect();
            #[derive(serde::Serialize)]
            struct ComplexityWithPerClauses<'a> {
                #[serde(flatten)]
                inner: &'a ComplexityMetrics,
                per_clauses: Vec<PerClauseEntry>,
            }
            writer.write(&ComplexityWithPerClauses {
                inner: &result,
                per_clauses: entries,
            })?;
        } else {
            writer.write(&result)?;
        }

        Ok(())
    }
}
