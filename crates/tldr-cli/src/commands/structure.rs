//! Structure command - Show code structure
//!
//! Extracts and displays functions, classes, and imports from source files.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::CodeStructure;
use tldr_core::{get_code_structure, get_polyglot_code_structure, IgnoreSpec, Language};

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

        // cl15-polyglot-v1 (v0.5.0 CL-15): multi-language is now the DEFAULT
        // for directory scans. When the user did NOT pin a language with
        // `--lang`, iterate EVERY detected language on the tree and merge
        // their `files` into one CodeStructure — never silently drop the
        // non-dominant languages. The legacy `--all-langs` flag is now
        // redundant in this default path but kept for compatibility (it
        // selects the same multi-language behaviour). The polyglot path is a
        // no-op when:
        //   - `--lang` is set (user pinned a specific language — see the
        //     dropped-language warning emitted further below)
        //   - The target is a single file (only one language applies)
        // The merged structure echoes the FIRST scanned language in its
        // `language` field to preserve the existing single-language schema.
        if self.lang.is_none() && self.path.is_dir() {
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

        // cl15-polyglot-v1 (v0.5.0 CL-15): if the user pinned `--lang` on a
        // polyglot directory, the non-matching languages are dropped from
        // this scan. Emit a clear stderr WARNING naming them + file counts so
        // the restriction is never silent. (The single-file path can only
        // ever be one language, so this only fires for directories.)
        if self.lang.is_some() && self.path.is_dir() {
            crate::commands::polyglot::warn_if_languages_dropped(&self.path, language);
        }

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

    /// cl15-polyglot-v1 (v0.5.0 CL-15) / reg-health-regression-v1 (v0.5.0
    /// REG-HEALTH): polyglot scanning helper — the DEFAULT directory path
    /// (no longer gated behind `--all-langs`).
    ///
    /// Delegates to the shared
    /// [`tldr_core::get_polyglot_code_structure`] so `structure` and
    /// `health` count classes/functions identically (the M-016 invariant).
    /// That core helper:
    ///   - detects every language present and runs `get_code_structure` per
    ///     language,
    ///   - deduplicates files by path (a `.h` scanned by both the C and C++
    ///     grammars is kept once, under its sibling-aware owner), so the
    ///     class total is not inflated by double-counted headers, and
    ///   - emits `language: null` + `"No source files found in directory"`
    ///     for an empty tree (the N7 contract) instead of a Python fallback.
    fn run_all_langs(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        let lang_count = crate::commands::polyglot::detected_language_list(&self.path).len();
        writer.progress(&format!(
            "Extracting structure from {} ({} language(s))...",
            self.path.display(),
            lang_count
        ));

        let merged = get_polyglot_code_structure(
            &self.path,
            self.max_results,
            Some(&IgnoreSpec::default()),
        )?;

        // b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3):
        // the default polyglot scan now scopes to the primary language family to
        // avoid pathological output on repos whose minority languages are
        // generated/vendored docs (e.g. a 211 MB dump from a single committed
        // minified dokka `main.js` in an otherwise-Java repo). Scoping must NOT
        // be silent (the CL-15 contract): `get_polyglot_code_structure` records
        // a "scoped to the primary language family — dropped …" warning in the
        // result's `warnings`; mirror it to STDERR here (like the `--lang`
        // dropped-language warning) so it survives `--quiet` and JSON output and
        // lands where correctness alerts belong. The warning stays in the JSON
        // `warnings` array too, so machine consumers see it without parsing
        // stderr.
        for w in &merged.warnings {
            if w.starts_with("polyglot scan: scoped to the primary language family") {
                eprintln!("Warning: {w}");
            }
        }

        if writer.is_text() {
            writer.write_text(&format_structure_text(&merged))?;
        } else {
            writer.write(&merged)?;
        }
        Ok(())
    }
}
