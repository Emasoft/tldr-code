//! Smart Search command - Enriched BM25 search with structure + call graph context.
//!
//! Returns enriched "search result cards" containing function-level context
//! (signature, callers, callees) for each BM25 match, minimizing round-trips
//! for LLM agents exploring a codebase.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::{
    enriched_search, EnrichedSearchOptions, EnrichedSearchReport, Language, SearchMode,
};

use crate::commands::daemon_router::{params_for_enriched_search, try_daemon_route};
use crate::output::{format_enriched_search_text, OutputFormat, OutputWriter};

/// Enriched search: BM25 search with function-level context cards.
///
/// By default this command performs token-based ranking using BM25 with
/// structure and call-graph signals. Common high-frequency tokens
/// (stopwords like `fn`, `def`, `function`, `class`) are filtered out
/// of the BM25 query because they would otherwise dominate scoring
/// without adding signal.
///
/// ux-and-explain-completeness-v1 (P12.AGG12-13): when EVERY query
/// token is filtered (e.g. `fn new`, `function`, `def `), the command
/// transparently falls back to literal substring search so the query
/// still returns useful results. The report's `search_mode` field is
/// then `literal-fallback+structure` (or `+callgraph`).
///
/// Pass `--regex` to interpret the query as a regex pattern, or
/// `--hybrid <PATTERN>` to combine BM25 ranking with a regex filter.
#[derive(Debug, Args)]
pub struct SmartSearchArgs {
    /// Search query (natural language or code terms; BM25 by default,
    /// regex when `--regex` is set)
    ///
    /// Issue #13: flag-like queries (`tldr search '--port' <dir>`) used to be
    /// rejected by clap with a misleading "tip: a similar argument exists:
    /// '--format'". `allow_hyphen_values` lets the first positional swallow
    /// hyphen-prefixed tokens, so they are treated as the query. The explicit
    /// escape form (`tldr search -f json -- '--port' <dir>`) keeps working,
    /// and registered flags (`-f`, `-k`, `-l`, `--regex`, ...) are still
    /// parsed as flags, not values.
    #[arg(allow_hyphen_values = true)]
    pub query: String,

    /// Directory to search in (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum number of result cards to return
    #[arg(long, short = 'k', default_value = "10")]
    pub top_k: usize,

    /// Skip call graph enrichment (much faster, no callers/callees)
    #[arg(long)]
    pub no_callgraph: bool,

    /// Use regex pattern matching instead of BM25 ranking.
    /// The query is interpreted as a regex pattern.
    #[arg(long, conflicts_with = "hybrid")]
    pub regex: bool,

    /// Hybrid mode: combine BM25 relevance with regex filtering.
    /// The positional query is used for BM25 ranking, this pattern for regex filtering.
    #[arg(long, conflicts_with = "regex")]
    pub hybrid: Option<String>,
}

impl SmartSearchArgs {
    /// Run the search command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists BEFORE language detection / progress banner
        // (lang-detect-default-v1)
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // Determine language (auto-detect from directory, default to Python).
        //
        // Single FILE input: `from_path` first. The search root may be a
        // single file (see tldr-core `search::enriched::resolve_indexed_path`:
        // "when the search root IS a file, e.g. `tldr search 'dres'
        // public/app.js`"), and `from_directory` deliberately filters the 7
        // formats languages via `is_project_language_signal`, so a lone
        // `data.json` would otherwise fall through to Python and the BM25
        // index (which filters by `language.extensions()`) would silently
        // skip the file. For an unrecognized single file, fall back to the
        // parent directory's dominant language, then to the historical
        // Python default — mirroring `structure`'s single-file resolution.
        let language = self.lang.unwrap_or_else(|| {
            if self.path.is_file() {
                Language::from_path(&self.path)
                    .or_else(|| {
                        self.path
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .and_then(Language::from_directory)
                    })
                    .unwrap_or(Language::Python)
            } else {
                Language::from_directory(&self.path).unwrap_or(Language::Python)
            }
        });

        writer.progress(&format!(
            "Smart searching for '{}' in {} ({})...",
            self.query,
            self.path.display(),
            language.as_str()
        ));

        let search_mode = if self.regex {
            SearchMode::Regex(self.query.clone())
        } else if let Some(ref pattern) = self.hybrid {
            SearchMode::Hybrid {
                query: self.query.clone(),
                pattern: pattern.clone(),
            }
        } else {
            SearchMode::Bm25
        };

        let options = EnrichedSearchOptions {
            top_k: self.top_k,
            include_callgraph: !self.no_callgraph,
            search_mode,
        };

        // Issue #65: route through the daemon FIRST (same pattern as
        // imports/context). The daemon computes the SAME core
        // `enriched_search` this binary would run (one code path — no drift)
        // and memoizes the report keyed by every query-affecting parameter
        // with project-root input hashes, so the expensive per-invocation
        // BM25/call-graph work is paid once per project state instead of
        // once per query. Any failure — daemon not running, IPC error,
        // unparseable/deserializing response — yields `None` and the router
        // appends the issue-#67 `fallback` line; we then compute directly,
        // exactly as before this route existed (a project with no daemon
        // ever sees zero behavior change beyond the failed route attempt).
        //
        // Socket discovery follows the established convention: the search
        // root when it is a directory (the common case — the served project
        // root), the file's parent when the user searched a single file.
        // A subdirectory root simply finds no daemon and falls back, which
        // is the same conservative behavior every other routed command has.
        let canonical_root = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());
        let project_for_daemon = if canonical_root.is_file() {
            canonical_root
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf()
        } else {
            canonical_root.clone()
        };
        if let Some(report) = try_daemon_route::<EnrichedSearchReport>(
            &project_for_daemon,
            "enriched_search",
            params_for_enriched_search(
                &canonical_root,
                &self.query,
                Some(language.as_str()),
                self.top_k,
                !self.no_callgraph,
                &options.search_mode,
            ),
        ) {
            return write_enriched_report(&writer, &report);
        }

        // Fallback to direct compute (client-local, as before issue #65).
        let report = enriched_search(&self.query, &self.path, language, options)?;

        // Output based on format
        write_enriched_report(&writer, &report)?;

        Ok(())
    }
}

/// Emit an enriched-search report through the CLI writer.
///
/// Shared by the daemon route and the direct-compute fallback so both paths
/// produce byte-identical output (same formatter for text, same serde
/// serialization for JSON).
fn write_enriched_report(
    writer: &OutputWriter,
    report: &EnrichedSearchReport,
) -> anyhow::Result<()> {
    if writer.is_text() {
        let text = format_enriched_search_text(report);
        writer.write_text(&text)?;
    } else {
        writer.write(report)?;
    }
    Ok(())
}
