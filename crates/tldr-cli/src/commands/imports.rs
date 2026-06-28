//! Imports command - Parse import statements from a file
//!
//! Returns an array of ImportInfo objects with module, names, is_from, and alias.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use tldr_core::ast::imports::filter_display_imports;
use tldr_core::types::ImportInfo;
use tldr_core::{detect_or_parse_language, get_imports, Language};

use crate::commands::daemon_router::{params_with_file_lang, try_daemon_route};
use crate::output::{format_imports_text, OutputFormat, OutputWriter};

/// Envelope shape for `tldr imports` JSON output (schema-unification-v1).
///
/// Wraps the previously bare `Vec<ImportInfo>` array in an object so the
/// command's JSON shape matches every other top-level command (`structure`,
/// `vuln`, `dead`, etc., all of which return objects). Closes BUG-18.
///
/// Use `--legacy-array` to emit the old bare-array shape for backward
/// compatibility with tools that hard-coded `jq '.[]'` over the top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportsEnvelope {
    /// Path of the file that was parsed.
    pub file: String,
    /// Detected (or user-specified) language.
    pub language: String,
    /// Parsed import statements. Always present; empty array if none.
    pub imports: Vec<ImportInfo>,
}

/// Parse import statements from a file
#[derive(Debug, Args)]
pub struct ImportsArgs {
    /// File to parse
    pub file: PathBuf,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Emit the legacy bare-array JSON shape (`[ImportInfo, ...]`) instead of
    /// the canonical envelope object `{file, language, imports}`. Provided for
    /// backward compatibility with consumers that hard-coded `jq '.[]'` over
    /// the top level. New code should consume the envelope shape.
    #[arg(long = "legacy-array")]
    pub legacy_array: bool,
}

impl ImportsArgs {
    /// Run the imports command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // bug10/RC6: the OCaml extractor harvests every implicit qualified ref
        // (e.g. `Dune_lang.parse`) into the raw import set so `deps`/`importers`
        // can mint edges — but the `imports` COMMAND must surface only genuine
        // `open`/`include`/`module =` directives (else `pkg_rules.ml` reports
        // ~1100 "imports" instead of ~17). Detect the language up-front
        // (best-effort) so both the daemon and direct paths filter identically;
        // a detection failure simply skips filtering. See
        // `tldr_core::ast::imports::filter_display_imports`.
        let display_lang =
            detect_or_parse_language(self.lang.as_ref().map(|l| l.as_str()), &self.file).ok();

        // Try daemon first for cached result (use file's parent as project root)
        let project = self.file.parent().unwrap_or(&self.file);
        if let Some(result) = try_daemon_route::<Vec<ImportInfo>>(
            project,
            "imports",
            params_with_file_lang(&self.file, self.lang.as_ref().map(|l| l.as_str())),
        ) {
            let result = match display_lang {
                Some(lang) => filter_display_imports(result, lang),
                None => result,
            };
            if writer.is_text() {
                writer.write_text(&format!(
                    "{} ({} imports)\n\n{}",
                    self.file.display().to_string().bold(),
                    result.len(),
                    format_imports_text(&result),
                ))?;
            } else if self.legacy_array {
                writer.write(&result)?;
            } else {
                // schema-unification-v1 BUG-18: wrap in envelope so the
                // top-level JSON is an object (consistent with structure,
                // vuln, dead, etc.) instead of a bare array.
                let envelope = ImportsEnvelope {
                    file: self.file.display().to_string(),
                    language: self.lang.as_ref().map(|l| l.as_str().to_string()).unwrap_or_else(|| {
                        // Daemon path: language not directly known; best-effort
                        // detect from extension. If detection fails, fall back
                        // to "unknown" rather than failing — the imports still
                        // got parsed.
                        detect_or_parse_language(None, &self.file)
                            .map(|l| l.as_str().to_string())
                            .unwrap_or_else(|_| "unknown".to_string())
                    }),
                    imports: result,
                };
                writer.write(&envelope)?;
            }
            return Ok(());
        }

        // Fallback to direct compute

        // Detect or parse language (uses shared validator M28)
        let language =
            detect_or_parse_language(self.lang.as_ref().map(|l| l.as_str()), &self.file)?;

        writer.progress(&format!(
            "Parsing imports from {} ({:?})...",
            self.file.display(),
            language
        ));

        // Get imports
        let result = get_imports(&self.file, language)?;
        // bug10/RC6: drop OCaml implicit qualified refs at the presentation
        // boundary (identity for every other language).
        let result = filter_display_imports(result, language);

        // Output based on format
        if writer.is_text() {
            writer.write_text(&format!(
                "{} ({} imports)\n\n{}",
                self.file.display().to_string().bold(),
                result.len(),
                format_imports_text(&result),
            ))?;
        } else if self.legacy_array {
            writer.write(&result)?;
        } else {
            // schema-unification-v1 BUG-18: envelope shape, see daemon branch.
            let envelope = ImportsEnvelope {
                file: self.file.display().to_string(),
                language: language.as_str().to_string(),
                imports: result,
            };
            writer.write(&envelope)?;
        }

        Ok(())
    }
}
