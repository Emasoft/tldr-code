//! Importers command - Find all files that import a given module
//!
//! Returns an ImportersReport with module name, list of importing files, and total count.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use colored::Colorize;

use tldr_core::types::ImportersReport;
use tldr_core::{find_importers, resolve_target_language, Language};

use crate::commands::daemon_router::{params_with_module, try_daemon_route};
use crate::output::{format_importers_text, OutputFormat, OutputWriter};

/// Find all files that import a given module
#[derive(Debug, Args)]
pub struct ImportersArgs {
    /// Module name to search for
    pub module: String,

    /// Directory to search (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detected from directory if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum number of importing files to show (0 = unlimited)
    #[arg(long, short = 'm', default_value = "50")]
    pub limit: usize,
}

impl ImportersArgs {
    /// Run the importers command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists BEFORE daemon route / language detection / progress banner
        // (lang-detect-default-v1)
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // Try daemon first for cached result
        if let Some(mut result) = try_daemon_route::<ImportersReport>(
            &self.path,
            "importers",
            params_with_module(&self.module, Some(&self.path)),
        ) {
            self.apply_limit(&mut result);
            self.output_result(&writer, &result)?;
            return Ok(());
        }

        // Determine language.
        //
        // doc-target-importers-v1: the module string can itself name an
        // EXISTING FILE — documents do (`tldr importers b.md <root>` queries
        // the file `b.md` by its root-relative path; the doc arm of
        // `module_matches`, tldr-core/src/analysis/importers.rs, path-matches
        // link targets only when the language is a doc language). The old
        // resolution (`--lang` else `Language::from_directory(path)` else
        // Python) could never produce a doc language on such a query:
        // `from_directory` skips every doc format via
        // `is_project_language_signal` (types.rs), so a doc-only project fell
        // through to Python, `find_importers` walked only `.py` files, and
        // the command silently reported `total: 0`.
        //
        // Resolution order (documented decision):
        // 1. `--lang` — the unchanged override, first.
        // 2. The module string LOOKS like a path (contains a path separator
        //    or a dot) AND names an existing file (resolved relative to the
        //    path arg, else as given, i.e. CWD-relative) → the shared
        //    `resolve_target_language` decides: doc language → use it, code
        //    language → use it. Per-file truth beats directory dominance, so
        //    `tldr importers lib.py <ts-project>` still resolves Python.
        // 3. Everything else — module strings that are not files
        //    (`std::collections::HashMap`, `myapp.service`, `utils`), targets
        //    that resolve to `Ok(None)` (missing path, directory, unknown
        //    extension, OOXML container) or `Err` (binary content) — keeps
        //    the LEGACY fallback byte-identical to the pre-fix behavior:
        //    directory autodetect from the path arg, Python as last resort.
        let language = self
            .lang
            .unwrap_or_else(|| self.language_from_module_file_or_directory());

        // Fallback to direct compute
        writer.progress(&format!(
            "Finding files that import '{}' in {} ({:?})...",
            self.module,
            self.path.display(),
            language
        ));

        // Find importers
        let mut result = find_importers(&self.path, &self.module, language)?;
        self.apply_limit(&mut result);
        self.output_result(&writer, &result)?;

        Ok(())
    }

    fn apply_limit(&self, report: &mut ImportersReport) {
        if self.limit > 0 && report.importers.len() > self.limit {
            report.importers.truncate(self.limit);
        }
    }

    /// doc-target-importers-v1: `--lang`-less language resolution — see the
    /// documented order at the call site. The module string names an existing
    /// file (path-shaped AND present relative to the path arg, else as given)
    /// → per-file `resolve_target_language`; anything else keeps the legacy
    /// directory autodetect with the Python last resort.
    fn language_from_module_file_or_directory(&self) -> Language {
        let looks_like_path =
            self.module.contains('.') || self.module.contains('/') || self.module.contains('\\');
        if looks_like_path {
            let via_root = self.path.join(&self.module);
            let candidate = if via_root.exists() {
                Some(via_root)
            } else {
                let direct = PathBuf::from(&self.module);
                direct.exists().then_some(direct)
            };
            if let Some(file) = candidate {
                // `Ok(None)` (missing path, directory, unknown extension,
                // OOXML container) and `Err` (binary content) both fall
                // through: no language this command can truthfully claim
                // from such a target.
                if let Ok(Some(lang)) = resolve_target_language(&file) {
                    return lang;
                }
            }
        }
        Language::from_directory(&self.path).unwrap_or(Language::Python)
    }

    fn output_result(&self, writer: &OutputWriter, report: &ImportersReport) -> Result<()> {
        if writer.is_text() {
            let shown = report.importers.len();
            let total = report.total;
            let truncated = shown < total;

            let header = if truncated {
                format!(
                    "{} imported by {} files (showing {})\n",
                    format!("\"{}\"", report.module).bold(),
                    total,
                    shown,
                )
            } else {
                format!(
                    "{} imported by {} {}\n",
                    format!("\"{}\"", report.module).bold(),
                    total,
                    if total == 1 { "file" } else { "files" },
                )
            };

            writer.write_text(&format!("{}\n{}", header, format_importers_text(report)))?;
        } else {
            writer.write(report)?;
        }
        Ok(())
    }
}
