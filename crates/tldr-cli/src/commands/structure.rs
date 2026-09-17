//! Structure command - Show code structure
//!
//! Extracts and displays functions, classes, and imports from source files.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::CodeStructure;
use tldr_core::{get_code_structure, resolve_target_language, IgnoreSpec, Language};

use crate::commands::daemon_router::{params_with_path_lang, try_daemon_route};
use crate::output::{format_structure_text, OutputFormat, OutputWriter};

/// Extract code structure (functions, classes, imports)
#[derive(Debug, Args)]
pub struct StructureArgs {
    /// Directory to scan (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detected if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum number of files to process (0 = unlimited)
    #[arg(long, short = 'm', default_value = "0")]
    pub max_results: usize,
}

impl StructureArgs {
    /// Run the structure command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists BEFORE language detection / progress banner
        // (lang-detect-default-v1: avoid printing misleading "(Python)" banner
        // when the path doesn't exist and from_directory silently returns None.)
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // Determine language (auto-detect from directory, default to Python)
        //
        // Resolution order:
        // - Single FILE input: `resolve_target_language` (extensionless-
        //   targets-v1) — the ONE single-file helper: known extension →
        //   `from_path` (formats-extension-v1, byte-identical), extensionless
        //   existing file → content sniff (shebang → `<?xml` → Text; a
        //   binary file is a structured error, NOT a Python mislabel),
        //   missing/directory/unrecognized-extension → `Ok(None)`. OOXML
        //   containers (`.docx`/`.xlsx`/`.pptx`, ooxml-structure-v1) also
        //   resolve to `Ok(None)` — the sniff must never see their ZIP
        //   bytes — so we fall through to the directory/Python fallback and
        //   `get_code_structure`'s `is_ooxml_path` early-return owns the
        //   container (its output reports `language: null`).
        //   `from_directory` deliberately filters the 7 formats languages
        //   (Json/Yaml/Toml/Xml/Html/Css/Bash) via
        //   `is_project_language_signal`, so a lone `config.json` /
        //   `config.toml` would otherwise fall through to the Python
        //   default instead of reporting its own format. For an
        //   unrecognized single file, fall back to the parent directory's
        //   dominant language (mirroring `get_code_structure`, which
        //   anchors single-file runs on the parent), then to the
        //   historical Python default.
        // - DIRECTORY input: `from_directory` dominant-language detection.
        let language = match self.lang {
            Some(lang) => lang,
            None => {
                if self.path.is_file() {
                    match resolve_target_language(&self.path)? {
                        Some(lang) => lang,
                        None => self
                            .path
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .and_then(Language::from_directory)
                            .unwrap_or(Language::Python),
                    }
                } else {
                    Language::from_directory(&self.path).unwrap_or(Language::Python)
                }
            }
        };

        // Try daemon first for cached result
        if let Some(structure) = try_daemon_route::<CodeStructure>(
            &self.path,
            "structure",
            params_with_path_lang(&self.path, Some(language.as_str())),
        ) {
            // Output based on format
            if writer.is_text() {
                let text = format_structure_text(&structure);
                writer.write_text(&text)?;
                return Ok(());
            } else {
                writer.write(&structure)?;
                return Ok(());
            }
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Extracting structure from {} ({:?})...",
            self.path.display(),
            language
        ));

        // Get code structure
        let structure = get_code_structure(
            &self.path,
            language,
            self.max_results,
            Some(&IgnoreSpec::default()),
        )?;

        // Output based on format
        if writer.is_text() {
            let text = format_structure_text(&structure);
            writer.write_text(&text)?;
        } else {
            writer.write(&structure)?;
        }

        Ok(())
    }
}
