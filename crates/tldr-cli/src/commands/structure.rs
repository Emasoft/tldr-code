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

    /// markup-node-tree-v1: keep only markup element definitions at nesting
    /// depth <= N (root-level elements are depth 0). Formats only —
    /// XML/SVG/HTML/XHTML and OOXML parts carry element depths; definitions
    /// without depth semantics (code symbols, inner-CSS/inner-JS rows, json/
    /// yaml/toml keys, log/text/csv/sql rows) are never filtered. Unset = no
    /// filtering (the full flat element list, JSON-complete).
    #[arg(long)]
    pub max_depth: Option<u32>,
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
        //   targets-v1 + unknown-ext-text-v1) — the ONE single-file helper:
        //   known extension → `from_path` (formats-extension-v1,
        //   byte-identical), extensionless existing file → content sniff
        //   (shebang → `<?xml` → Text; a binary file is a structured error,
        //   NOT a Python mislabel), unknown-extension existing file →
        //   `Some(Text)`. `Ok(None)` — and therefore the parent-directory
        //   fallback below — is reached by DIRECTORIES, MISSING paths and
        //   OOXML containers only. OOXML containers (`.docx`/`.xlsx`/
        //   `.pptx`, ooxml-structure-v1) resolve to `Ok(None)` — the sniff
        //   must never see their ZIP bytes — so we fall through to the
        //   directory/Python fallback and `get_code_structure`'s
        //   `is_ooxml_path` early-return owns the container (its output
        //   reports `language: null`).
        //   `from_directory` deliberately filters the 7 formats languages
        //   (Json/Yaml/Toml/Xml/Html/Css/Bash) via
        //   `is_project_language_signal`, so a lone `config.json` /
        //   `config.toml` would otherwise fall through to the Python
        //   default instead of reporting its own format. For a
        //   non-resolving single file, fall back to the parent directory's
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

        // Try daemon first for cached result.
        //
        // markup-node-tree-v1: thread `--max-depth` so the daemon applies the
        // SAME element-tree narrowing the direct-compute path does (the
        // daemon filters post-extraction per request, so the shared
        // per-project memoization stays untouched). A request without the
        // key means "no filtering" on both routes.
        let mut params = params_with_path_lang(&self.path, Some(language.as_str()));
        if let Some(depth) = self.max_depth {
            if let serde_json::Value::Object(ref mut map) = params {
                map.insert("max_depth".to_string(), serde_json::json!(depth));
            }
        }
        if let Some(structure) = try_daemon_route::<CodeStructure>(&self.path, "structure", params)
        {
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
        let mut structure = get_code_structure(
            &self.path,
            language,
            self.max_results,
            Some(&IgnoreSpec::default()),
        )?;

        // markup-node-tree-v1: `--max-depth` narrows the markup element tree
        // AFTER extraction (direct-compute parity with the daemon route).
        if let Some(depth) = self.max_depth {
            tldr_core::filter_structure_max_depth(&mut structure, depth);
        }

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
