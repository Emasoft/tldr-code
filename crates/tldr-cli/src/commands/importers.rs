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
use tldr_core::analysis::doc_impact::is_doc_language;

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

        // Try daemon first for cached result. NB the module string reaches
        // the daemon VERBATIM — the daemon handler owns its own language
        // resolution and has no doc-target arm, so the doc rewrite below
        // (and the A2 per-file language resolution) applies to the
        // direct-compute path, which is what the doc_target_commands_v1
        // pins exercise.
        if let Some(mut result) = try_daemon_route::<ImportersReport>(
            &self.path,
            "importers",
            params_with_module(&self.module, Some(&self.path)),
        ) {
            self.apply_limit(&mut result);
            self.output_result(&writer, &result)?;
            return Ok(());
        }

        // doc-target-importers-v1 + the follow-up (absolute-path ergonomics):
        // when the module string names an EXISTING FILE and resolves to a DOC
        // language, the module string is rewritten to the file's
        // PROJECT-ROOT-RELATIVE spelling WITH its extension (the same
        // `root_relative_path` derivation whatbreaks uses, so the two
        // commands agree byte-for-byte) before `find_importers` runs. Links
        // inside the project are written relative to their file
        // (`b.md`, `docs/b.md` — the suffix semantics of `doc_module_matches`
        // match the root-relative form), while a user-supplied ABSOLUTE path
        // (`/repo/docs/b.md`) can never match one verbatim. Code-language
        // module strings are NEVER rewritten (dotted-module queries like
        // `lib.py` → `lib` stay queries for the dotted name).
        let (module, language) = match self.lang {
            Some(lang) => (self.module.clone(), lang),
            None => match self.resolve_module_file_language() {
                Some(resolved) => resolved,
                None => (self.module.clone(), self.legacy_language_fallback()),
            },
        };

        // Fallback to direct compute
        writer.progress(&format!(
            "Finding files that import '{}' in {} ({:?})...",
            module,
            self.path.display(),
            language
        ));

        // Find importers
        let mut result = find_importers(&self.path, &module, language)?;
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
    /// documented order at the call site.
    ///
    /// Returns `Some((module, language))` when the module string names an
    /// existing file: `language` is the per-file `resolve_target_language`
    /// verdict and `module` is the module string to query with — for a DOC
    /// language the PROJECT-ROOT-RELATIVE path WITH extension (absolute
    /// inputs are rewritten so they can match root-relative links;
    /// `root_relative_path` keeps `b.md` → `b.md` and
    /// `/repo/docs/b.md` → `docs/b.md` when the query path arg is the
    /// project root), for a CODE language the module string VERBATIM
    /// (dotted-module queries must not be rewritten). `None` keeps the
    /// legacy directory autodetect with the Python last resort: module
    /// strings that are not files (`std::collections::HashMap`,
    /// `myapp.service`, `utils`), targets resolving to `Ok(None)`
    /// (directory, OOXML container) and binary content (`Err`).
    fn resolve_module_file_language(&self) -> Option<(String, Language)> {
        let looks_like_path =
            self.module.contains('.') || self.module.contains('/') || self.module.contains('\\');
        if !looks_like_path {
            return None;
        }
        let via_root = self.path.join(&self.module);
        let candidate = if via_root.exists() {
            Some(via_root)
        } else {
            let direct = PathBuf::from(&self.module);
            direct.exists().then_some(direct)
        };
        let file = candidate?;
        // `Ok(None)` (directory, OOXML container) and `Err` (binary content)
        // both fall through: no language this command can truthfully claim
        // from such a target.
        let language = resolve_target_language(&file).ok()??;
        let module = if is_doc_language(language) {
            // Doc languages reference each other by PATH: rewrite the module
            // string to the file's project-root-relative spelling (with
            // extension). A root-relative input round-trips unchanged; an
            // absolute one is stripped against the query path arg.
            tldr_core::analysis::whatbreaks::root_relative_path(&self.module, &self.path)
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            self.module.clone()
        };
        Some((module, language))
    }

    /// The pre-fix legacy fallback, byte-identical: directory autodetect from
    /// the path arg, Python as last resort.
    fn legacy_language_fallback(&self) -> Language {
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
