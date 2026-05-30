//! Structure command - Show code structure
//!
//! Extracts and displays functions, classes, and imports from source files.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::CodeStructure;
use tldr_core::{get_code_structure, IgnoreSpec, Language};

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

    /// m117-deferred-decisions-v1 (v0.4.2 M-118, D10): on polyglot
    /// repos, scan EVERY detected language rather than just the
    /// auto-detected primary. Default off preserves the legacy
    /// "dominant language only" behaviour. Mutually exclusive with
    /// `--lang`: passing `--lang` forces a single language and
    /// short-circuits multi-language enumeration.
    #[arg(long = "all-langs", short = 'A')]
    pub all_langs: bool,
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

        // m117-deferred-decisions-v1 (v0.4.2 M-118, D10): `--all-langs`
        // escape hatch. Iterate every detected language on a polyglot
        // tree and merge `files` from each per-language scan into one
        // CodeStructure. The flag is no-op when:
        //   - `--lang` is set (user pinned a specific language)
        //   - The target is a single file (only one language applies)
        // The merged structure echoes the FIRST scanned language in
        // its `language` field to preserve the existing single-language
        // schema; downstream consumers that want the per-language
        // breakdown can call `--lang` repeatedly.
        if self.all_langs && self.lang.is_none() && self.path.is_dir() {
            return self.run_all_langs(format, quiet);
        }

        // Determine language. User-supplied `--lang` wins. Otherwise:
        //   - For a single-file path, prefer the sibling-aware
        //     `from_path_with_siblings` widening so a `.h` next to a
        //     `.cpp` parses as C++ (otherwise the C grammar returns
        //     macro-decorated classes as silent garbage — see
        //     m040-cpp-macro-class-cross-pipeline-v1 / v0.4.2 M-110).
        //   - For a directory path, defer to the existing
        //     `from_directory` autodetector.
        // Python remains the historic last-resort fallback for empty /
        // unrecognised inputs.
        let language = self.lang.unwrap_or_else(|| {
            if self.path.is_file() {
                Language::from_path_with_siblings(&self.path)
                    .or_else(|| Language::from_directory(&self.path))
                    .unwrap_or(Language::Python)
            } else {
                Language::from_directory(&self.path).unwrap_or(Language::Python)
            }
        });

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

    /// m117-deferred-decisions-v1 (v0.4.2 M-118, D10): polyglot
    /// scanning helper. Walks the directory once with the project
    /// walker, groups files by `Language::from_path`, runs
    /// `get_code_structure` per detected language, and merges the
    /// `files` vectors. Warnings and `files_skipped` are summed
    /// across the per-language scans.
    fn run_all_langs(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        use std::collections::HashSet;

        let writer = OutputWriter::new(format, quiet);

        // Stage 1: enumerate every language that has at least one
        // file under `self.path`. We deliberately reuse `from_path`
        // (not `from_path_with_siblings`) here because each per-lang
        // scan handles its own extension widening downstream.
        let mut seen: HashSet<Language> = HashSet::new();
        let mut langs: Vec<Language> = Vec::new();
        for entry in tldr_core::walker::walk_project(&self.path) {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if let Some(lang) = Language::from_path(p) {
                if seen.insert(lang) {
                    langs.push(lang);
                }
            }
        }
        // Stable order across runs: sort by the Debug-rendered enum
        // variant name. `Language` doesn't derive `Ord`, but the
        // Debug repr is stable per-build.
        langs.sort_by_key(|l| format!("{:?}", l));

        // Empty tree → fall back to Python so the output schema is
        // still well-formed (mirrors the single-language path's
        // historical fallback).
        if langs.is_empty() {
            langs.push(Language::Python);
        }

        writer.progress(&format!(
            "Extracting structure from {} (--all-langs: {} languages)...",
            self.path.display(),
            langs.len()
        ));

        // Stage 2: run get_code_structure once per language and
        // merge. Preserve the first language as the top-level
        // `language` field (legacy schema) but emit per-language
        // tallies via a `languages_scanned` warning suffix so users
        // see what was covered.
        let mut merged_files: Vec<tldr_core::types::FileStructure> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut files_skipped: u32 = 0;
        let mut primary: Option<Language> = None;

        for lang in &langs {
            let s = get_code_structure(
                &self.path,
                *lang,
                self.max_results,
                Some(&IgnoreSpec::default()),
            )?;
            if primary.is_none() {
                primary = Some(*lang);
            }
            merged_files.extend(s.files);
            files_skipped = files_skipped.saturating_add(s.files_skipped);
            for w in s.warnings {
                warnings.push(w);
            }
        }

        warnings.push(format!(
            "--all-langs: scanned {} language(s): {}",
            langs.len(),
            langs
                .iter()
                .map(|l| format!("{:?}", l))
                .collect::<Vec<_>>()
                .join(", ")
        ));

        let merged = CodeStructure {
            root: self.path.clone(),
            language: primary,
            files: merged_files,
            files_skipped,
            warnings,
        };

        if writer.is_text() {
            writer.write_text(&format_structure_text(&merged))?;
        } else {
            writer.write(&merged)?;
        }
        Ok(())
    }
}
