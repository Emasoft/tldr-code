//! Similar command - Find similar code fragments
//!
//! Finds code that is semantically similar to a given file or function.
//! Uses dense embeddings to compute similarity scores.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::semantic::{
    BuildOptions, CacheConfig, ChunkGranularity, EmbeddingModel, IndexSearchOptions, SemanticIndex,
};

use crate::output::{OutputFormat, OutputWriter};

/// Find similar code fragments
#[derive(Debug, Args)]
pub struct SimilarArgs {
    /// Source file to find similar code for
    pub file: PathBuf,

    /// Specific function name (optional, searches whole file if not specified)
    #[arg(short = 'F', long)]
    pub function: Option<String>,

    /// Maximum number of results
    #[arg(short = 'n', long, default_value = "5")]
    pub top: usize,

    /// Minimum similarity threshold
    #[arg(short = 't', long, default_value = "0.7")]
    pub threshold: f64,

    /// Path to search for similar code (default: current directory)
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Embedding model: arctic-xs, arctic-s, arctic-m, arctic-m-long, arctic-l
    #[arg(short, long, default_value = "arctic-m")]
    pub model: String,

    /// Include self in results (by default, the query is excluded)
    #[arg(long)]
    pub include_self: bool,

    /// Disable embedding cache
    #[arg(long)]
    pub no_cache: bool,

    /// M16 (med-cleanup-bundle-v1): emit one row per matching chunk
    /// (legacy behavior). The default — when no `--function` is given
    /// and the target is a whole file — aggregates chunk matches per
    /// destination file and ranks by total similarity, since per-chunk
    /// scoring on a 600-LOC file made the user wade through 5 unrelated
    /// 4-9 line helpers.
    #[arg(long)]
    pub by_chunk: bool,
}

impl SimilarArgs {
    /// Run the similar command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Parse model
        let model = parse_model(&self.model)?;

        // Canonicalize file path for matching
        let canonical_file = self
            .file
            .canonicalize()
            .unwrap_or_else(|_| self.file.clone());
        let file_str = canonical_file.display().to_string();

        // Smart search path: if --path is the default "." and the input file is
        // an absolute path, use the file's parent directory to avoid indexing the
        // entire cwd (which may be an enormous repo).
        let effective_path =
            if self.path == std::path::Path::new(".") && canonical_file.is_absolute() {
                canonical_file
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| self.path.clone())
            } else {
                self.path.clone()
            };

        writer.progress(&format!(
            "Finding code similar to {}{}...",
            self.file.display(),
            self.function
                .as_ref()
                .map(|f| format!("::{}", f))
                .unwrap_or_default()
        ));

        // Build options
        let build_opts = BuildOptions {
            model,
            granularity: ChunkGranularity::Function,
            languages: None,
            show_progress: !quiet,
            use_cache: !self.no_cache,
        };

        // Cache config
        let cache_config = if self.no_cache {
            None
        } else {
            Some(CacheConfig::default())
        };

        // Build index using effective path
        let index = SemanticIndex::build(&effective_path, build_opts, cache_config)?;

        writer.progress(&format!(
            "Searching {} chunks for similar code...",
            index.len()
        ));

        // Search options
        let search_opts = IndexSearchOptions {
            top_k: self.top,
            threshold: self.threshold,
            include_snippet: true,
            snippet_lines: 5,
        };

        // cross-cmd-path-shape-v1 (v0.4.2 bug-A5): the index stores
        // every chunk under its canonical (`dunce::canonicalize`d) file
        // path because `effective_path` is canonicalised above and the
        // index walker honours that. On macOS this means `tldr similar
        // /tmp/repos/.../IO.scala` emits `source_file` and
        // `similar_files[].file_path` as `/private/tmp/.../...`,
        // leaking the symlink resolution into output. We rewrite the
        // canonical prefix back to the user-input prefix on output —
        // the M3 pattern. The canonical root for the rewrite is the
        // PARENT directory's canonicalisation (because `effective_path`
        // is parent-based), and the user-input root is the user's
        // input file's parent directory verbatim.
        let user_input_root = self
            .file
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let canon_user_root = dunce::canonicalize(&user_input_root).ok();
        let rewrite_path = |p: &std::path::Path| -> Option<std::path::PathBuf> {
            // 1. Whole-file equality: `p` is exactly the canonical
            //    form of `self.file` -> swap to verbatim user input.
            if let Ok(c) = dunce::canonicalize(&self.file) {
                if p == c.as_path() {
                    return Some(self.file.clone());
                }
            }
            if p.starts_with(&user_input_root) {
                return None;
            }
            if let Some(canon) = canon_user_root.as_ref() {
                if let Ok(suffix) = p.strip_prefix(canon) {
                    if user_input_root.as_os_str().is_empty() {
                        return Some(suffix.to_path_buf());
                    }
                    return Some(user_input_root.join(suffix));
                }
            }
            None
        };

        // M16 (med-cleanup-bundle-v1): when the user passed a whole
        // file (no `--function`) and did not opt into the legacy
        // per-chunk view via `--by-chunk`, aggregate matches per
        // destination FILE and rank by total similarity. The chunk
        // granularity made `tldr similar lib/application.js` (~600
        // LOC) return five unrelated 4-9 line helpers — useless.
        if self.function.is_none() && !self.by_chunk {
            let mut report = aggregate_similar_by_file(
                &index,
                &file_str,
                self.top,
                self.threshold,
            )?;
            // Restore user-input shape on every emitted path.
            if let Some(np) = rewrite_path(&report.source_file) {
                report.source_file = np;
            }
            for f in report.similar_files.iter_mut() {
                if let Some(np) = rewrite_path(&f.file_path) {
                    f.file_path = np;
                }
            }
            if writer.is_text() {
                let text = format_aggregated_similar_text(&report);
                writer.write_text(&text)?;
            } else {
                writer.write(&report)?;
            }
            return Ok(());
        }

        // Find similar (legacy per-chunk path: explicit --function or
        // explicit --by-chunk).
        let mut report = index.find_similar(&file_str, self.function.as_deref(), &search_opts)?;

        // Restore user-input shape on every emitted path
        // (`source.file_path` + per-result `file_path`).
        if let Some(np) = rewrite_path(&report.source.file_path) {
            report.source.file_path = np;
        }
        for s in report.similar.iter_mut() {
            if let Some(np) = rewrite_path(&s.file_path) {
                s.file_path = np;
            }
        }

        // Output based on format
        if writer.is_text() {
            let text = format_similar_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

// =============================================================================
// M16 — File-level aggregation
// =============================================================================

/// File-level similarity result. One row per destination file, with
/// total similarity (sum of per-chunk best scores) and chunk count.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSimilarityResult {
    pub file_path: std::path::PathBuf,
    /// Sum of per-chunk best similarity scores against the source's chunks.
    pub total_score: f64,
    /// Number of source-chunk to dest-chunk pairs that contributed.
    pub matched_chunks: usize,
    /// Average score across matched_chunks (total_score / matched_chunks).
    pub avg_score: f64,
}

/// Aggregated similarity report keyed by destination file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatedSimilarityReport {
    pub source_file: std::path::PathBuf,
    pub source_chunks: usize,
    pub model: tldr_core::semantic::EmbeddingModel,
    pub similar_files: Vec<FileSimilarityResult>,
    pub total_compared_chunks: usize,
}

/// Build a file-level aggregation: for every chunk in the source file,
/// find each candidate chunk's similarity, group by destination file,
/// keep only the best contribution per (source_chunk, dest_file) pair,
/// then sum.
fn aggregate_similar_by_file(
    index: &SemanticIndex,
    file_str: &str,
    top: usize,
    threshold: f64,
) -> Result<AggregatedSimilarityReport> {
    use std::collections::HashMap;

    // Source chunks (every chunk whose file_path matches `file_str`).
    let source_chunks: Vec<&tldr_core::semantic::EmbeddedChunk> = index
        .chunks()
        .iter()
        .filter(|c| c.chunk.file_path.to_string_lossy() == file_str)
        .collect();

    if source_chunks.is_empty() {
        return Err(anyhow::anyhow!(
            "no indexed chunks found for source file: {}",
            file_str
        ));
    }

    // (dest_file -> (score, count)) accumulator. For each source chunk
    // and each dest chunk we keep the per-(src_chunk, dest_file) best.
    let mut per_src_dest_best: HashMap<(usize, std::path::PathBuf), f64> = HashMap::new();
    let mut total_compared: usize = 0;

    for (src_idx, src) in source_chunks.iter().enumerate() {
        for dest in index.chunks().iter() {
            // Skip self-file: do not recommend the source's own chunks.
            if dest.chunk.file_path == src.chunk.file_path {
                continue;
            }
            total_compared += 1;
            // Use core's similarity helper to stay consistent with the
            // rest of the semantic stack.
            let score =
                tldr_core::semantic::cosine_similarity(&src.embedding, &dest.embedding);
            if score < threshold {
                continue;
            }
            let key = (src_idx, dest.chunk.file_path.clone());
            let entry = per_src_dest_best.entry(key).or_insert(0.0);
            if score > *entry {
                *entry = score;
            }
        }
    }

    // Now sum per dest_file across source chunks, also count contributors.
    let mut per_file: HashMap<std::path::PathBuf, (f64, usize)> = HashMap::new();
    for ((_src_idx, dest_file), score) in per_src_dest_best {
        let entry = per_file.entry(dest_file).or_insert((0.0, 0));
        entry.0 += score;
        entry.1 += 1;
    }

    let mut similar_files: Vec<FileSimilarityResult> = per_file
        .into_iter()
        .map(|(file_path, (total_score, matched_chunks))| {
            let avg_score = if matched_chunks > 0 {
                total_score / matched_chunks as f64
            } else {
                0.0
            };
            FileSimilarityResult {
                file_path,
                total_score,
                matched_chunks,
                avg_score,
            }
        })
        .collect();

    similar_files.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    similar_files.truncate(top);

    Ok(AggregatedSimilarityReport {
        source_file: std::path::PathBuf::from(file_str),
        source_chunks: source_chunks.len(),
        model: index.model(),
        similar_files,
        total_compared_chunks: total_compared,
    })
}

/// Format an aggregated (file-level) similarity report.
fn format_aggregated_similar_text(report: &AggregatedSimilarityReport) -> String {
    use colored::Colorize;
    let mut output = String::new();
    output.push_str(&format!(
        "{}: {} ({} source chunks)\n",
        "Finding files similar to".bold(),
        report.source_file.display().to_string().green(),
        report.source_chunks,
    ));
    output.push_str(&format!(
        "Model: {} | Compared: {} chunks\n\n",
        format!("{:?}", report.model).yellow(),
        report.total_compared_chunks,
    ));

    if report.similar_files.is_empty() {
        output.push_str("No similar files found above threshold.\n");
    } else {
        output.push_str(&format!(
            "{} ({} found):\n\n",
            "Similar files".bold(),
            report.similar_files.len()
        ));
        for (i, f) in report.similar_files.iter().enumerate() {
            output.push_str(&format!(
                "{}. {} (total: {:.2}, avg: {:.2}, chunks: {})\n",
                i + 1,
                f.file_path.display().to_string().green(),
                f.total_score,
                f.avg_score,
                f.matched_chunks,
            ));
        }
    }
    output
}

/// Parse model string into EmbeddingModel
fn parse_model(model_str: &str) -> Result<EmbeddingModel> {
    match model_str {
        "arctic-xs" | "xs" => Ok(EmbeddingModel::ArcticXS),
        "arctic-s" | "s" => Ok(EmbeddingModel::ArcticS),
        "arctic-m" | "m" => Ok(EmbeddingModel::ArcticM),
        "arctic-m-long" | "m-long" => Ok(EmbeddingModel::ArcticMLong),
        "arctic-l" | "l" => Ok(EmbeddingModel::ArcticL),
        _ => Err(anyhow::anyhow!(
            "Invalid model '{}'. Options: arctic-xs, arctic-s, arctic-m, arctic-m-long, arctic-l",
            model_str
        )),
    }
}

/// Format similarity report for text output
fn format_similar_text(report: &tldr_core::semantic::SimilarityReport) -> String {
    use colored::Colorize;

    let mut output = String::new();

    // Source info
    let source_name = report.source.function_name.as_deref().unwrap_or("<file>");
    let source_class = report
        .source
        .class_name
        .as_ref()
        .map(|c| format!("{}::", c))
        .unwrap_or_default();

    output.push_str(&format!(
        "{}: {}:{}{}\n",
        "Finding similar to".bold(),
        report.source.file_path.display().to_string().green(),
        source_class,
        source_name.blue()
    ));
    output.push_str(&format!(
        "Model: {} | Compared: {} chunks | Exclude self: {}\n\n",
        format!("{:?}", report.model).yellow(),
        report.total_compared,
        report.exclude_self
    ));

    if report.similar.is_empty() {
        output.push_str("No similar code found above threshold.\n");
    } else {
        output.push_str(&format!(
            "{} ({} found):\n\n",
            "Similar code".bold(),
            report.similar.len()
        ));

        for (i, result) in report.similar.iter().enumerate() {
            let func_name = result.function_name.as_deref().unwrap_or("<file>");
            let class_prefix = result
                .class_name
                .as_ref()
                .map(|c| format!("{}::", c))
                .unwrap_or_default();

            output.push_str(&format!(
                "{}. {}:{}{} (score: {:.2})\n",
                i + 1,
                result.file_path.display().to_string().green(),
                class_prefix,
                func_name.blue(),
                result.score
            ));
            output.push_str(&format!(
                "   Lines {}-{}\n",
                result.line_start, result.line_end
            ));

            if !result.snippet.is_empty() {
                output.push_str(&format!("   {}\n", result.snippet.dimmed()));
            }
            output.push('\n');
        }
    }

    output
}
