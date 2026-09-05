//! Churn command - Git-based file churn analysis
//!
//! Analyzes git history to identify high-churn files (frequently changed code).
//! Combined with complexity analysis, creates a "hotspot matrix" for prioritizing
//! refactoring efforts.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;

use tldr_core::quality::churn::{
    build_summary, check_shallow_clone, count_unique_commits, get_author_stats, get_file_churn,
    is_degenerate_shallow, is_git_repository, ChurnError, ChurnReport,
};

/// M15 (med-cleanup-bundle-v1): the JSON warning string used to flag a
/// degenerate-shallow repo. Formatting code uses this prefix to keep
/// text and JSON in sync — when the warning is present, per-file ranks
/// MUST be suppressed in text output too.
const DEGENERATE_SHALLOW_WARN_PREFIX: &str = "Shallow clone with";

use crate::output::{OutputFormat, OutputWriter};

/// Analyze git-based code churn
#[derive(Debug, Args)]
pub struct ChurnArgs {
    /// Directory to analyze (default: current dir)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Days of history to analyze
    #[arg(long, default_value = "365")]
    pub days: u32,

    /// Maximum files to show
    #[arg(long, default_value = "20")]
    pub top: usize,

    /// Exclude files matching pattern (glob syntax, can be repeated)
    #[arg(long, short = 'e')]
    pub exclude: Vec<String>,

    /// Include author statistics
    #[arg(long)]
    pub authors: bool,

    /// Deprecated: use `tldr hotspots` instead. This flag is ignored.
    #[arg(long, hide = true)]
    pub hotspots: bool,
}

impl ChurnArgs {
    /// Run the churn command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // schema-cleanup-v2 (P2.BUG-10): an empty directory is not a real
        // error — it's a benign edge case (e.g. fresh `mktemp -d`). Pre-fix
        // `analyze_churn` raised `Not a git repository` (exit 1) for an
        // empty mktemp tree, breaking parity with `structure` (exit 0 +
        // warnings). Short-circuit only when the directory is *empty*
        // (no entries at all). Non-empty non-git directories still get
        // the original error — that case is genuinely actionable user
        // input ("did you mean to git init?").
        if self.path.is_dir() && is_directory_empty(&self.path) {
            let stub = serde_json::json!({
                "root": self.path.display().to_string(),
                "files": [],
                "authors": [],
                "hotspots": [],
                "summary": serde_json::Value::Null,
                "warnings": ["Empty directory: no files to analyze"],
            });
            if writer.is_text() {
                writer.write_text(&format!(
                    "Churn Analysis: {} (no files found)",
                    self.path.display()
                ))?;
            } else {
                writer.write(&stub)?;
            }
            return Ok(());
        }

        writer.progress(&format!(
            "Analyzing churn in {} (last {} days)...",
            self.path.display(),
            self.days
        ));

        // Run the analysis
        let report = analyze_churn(
            &self.path,
            self.days,
            self.top,
            &self.exclude,
            self.authors,
            self.hotspots,
        )?;

        // Output based on format
        if writer.is_text() {
            let text = format_churn_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

/// schema-cleanup-v2 (P2.BUG-10): does the directory contain ZERO
/// entries? Used to short-circuit the empty-dir edge case before the
/// `Not a git repository` error path triggers. Returns `false` on any
/// I/O failure — the caller falls through to the existing error path,
/// which is the right behavior for a path that exists but cannot be
/// read.
fn is_directory_empty(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => false,
    }
}

/// Orchestrate churn analysis combining all phases.
///
/// # Arguments
/// * `path` - Directory to analyze (must be in a git repository)
/// * `days` - Time window in days
/// * `top_k` - Maximum files to return
/// * `exclude_patterns` - Glob patterns to exclude
/// * `include_authors` - Whether to include author statistics
/// * `include_hotspots` - Whether to calculate hotspot matrix
///
/// # Returns
/// Complete ChurnReport with files, optional authors, optional hotspots, and summary
pub fn analyze_churn(
    path: &Path,
    days: u32,
    top_k: usize,
    exclude_patterns: &[String],
    include_authors: bool,
    include_hotspots: bool,
) -> Result<ChurnReport, ChurnError> {
    // Check if path is a git repository
    if !is_git_repository(path)? {
        return Err(ChurnError::NotGitRepository {
            path: path.to_path_buf(),
        });
    }

    // Check for shallow clone
    let (is_shallow, shallow_depth) = check_shallow_clone(path)?;

    let mut warnings = Vec::new();
    if is_shallow {
        let depth_info = shallow_depth
            .map(|d| format!(" (~{} commits)", d))
            .unwrap_or_default();
        warnings.push(format!(
            "Repository is a shallow clone{}. Churn analysis may be incomplete.",
            depth_info
        ));
    }

    // Get file churn data
    let file_stats = get_file_churn(path, days, exclude_patterns)?;

    // BUG-03 fix: ask git directly for the unique-SHA count rather
    // than summing per-file commit_count (which would double-count
    // multi-file commits).
    let total_unique_commits = count_unique_commits(path, days)?;

    // Sort files by commit_count descending and take top_k
    // why: file_stats is a HashMap, so its iteration order is
    // nondeterministic across runs. Sorting by commit_count alone left
    // tied files (equal commit_count, common for small repos) in
    // whatever arbitrary order the HashMap produced, making `top`
    // output non-reproducible. Break ties by file path for a stable,
    // deterministic ordering.
    let mut files: Vec<_> = file_stats.values().cloned().collect();
    files.sort_by(|a, b| {
        b.commit_count
            .cmp(&a.commit_count)
            .then_with(|| a.file.cmp(&b.file))
    });
    files.truncate(top_k);

    // Get author stats if requested
    let authors = if include_authors {
        get_author_stats(path, days, &file_stats)?
    } else {
        Vec::new()
    };

    // Hotspot analysis removed — use `tldr hotspots` instead
    if include_hotspots {
        eprintln!("Warning: `churn --hotspots` is removed. Use `tldr hotspots` instead.");
    }
    let hotspots = Vec::new();

    // Build summary
    let mut summary = build_summary(&file_stats, days, total_unique_commits);

    // BUG-06 fix: when the repo is a shallow clone with at most one
    // commit, the per-file rank and average are mathematically
    // meaningless (every file is tied for "most churned" with
    // commit_count == 1, and avg_commits_per_file collapses to 1.0
    // by construction). Emit a warning and zero the average.
    //
    // schema-cleanup-v1 BUG-12: previously this also blanked
    // `most_churned_file`, which left consumers with an empty string
    // even when `files[0]` carried a clear top-N rank by
    // `lines_changed`. Now we keep `most_churned_file` populated by
    // picking the file with the highest `lines_changed` regardless
    // of the degenerate-commit-count case — the summary should
    // always reflect the data that's available.
    let degenerate = is_degenerate_shallow(is_shallow, total_unique_commits);
    if degenerate {
        warnings.push(format!(
            "Shallow clone with {} commit in window — per-file churn ranks and averages are degenerate and have been suppressed. Re-run on a full clone (`git fetch --unshallow`) for meaningful churn analysis.",
            total_unique_commits
        ));
        summary.avg_commits_per_file = 0.0;
        // Repick most_churned_file by lines_changed (descending),
        // since commit_count is degenerate (all == 1).
        // why: max_by_key over a HashMap's values() picks the *last*
        // maximal element in iteration order, which is nondeterministic
        // for a HashMap. Tie-break by file path so the degenerate-shallow
        // fallback is reproducible across runs.
        if let Some(top) = file_stats
            .values()
            .max_by_key(|f| (f.lines_changed, std::cmp::Reverse(&f.file)))
        {
            summary.most_churned_file = top.file.clone();
        }
    }

    Ok(ChurnReport {
        files,
        hotspots,
        authors,
        summary,
        is_shallow,
        shallow_depth,
        warnings,
    })
}

/// Format churn report for text output (plain text, no box-drawing)
fn format_churn_text(report: &ChurnReport) -> String {
    use colored::Colorize;

    let mut output = String::new();

    // Header with summary
    output.push_str(&format!(
        "Churn Analysis ({} files, {} days)\n",
        report.summary.total_files.to_string().yellow(),
        report.summary.time_window_days
    ));
    output.push_str(&format!(
        "Total commits: {}, Lines changed: {}\n",
        report.summary.total_commits.to_string().cyan(),
        report.summary.total_lines_changed.to_string().cyan()
    ));
    output.push_str(&format!(
        "Most churned: {}\n\n",
        report.summary.most_churned_file.green()
    ));

    // Warnings
    for warning in &report.warnings {
        output.push_str(&format!("{} {}\n", "Warning:".yellow(), warning));
    }
    if !report.warnings.is_empty() {
        output.push('\n');
    }

    // M15 (med-cleanup-bundle-v1): if the JSON layer flagged this as a
    // degenerate-shallow scenario (every file tied at 1 commit), the
    // ranked list is mathematically meaningless — the JSON output already
    // suppresses `most_churned_file` and zeros `avg_commits_per_file`,
    // and emits a stronger warning. The text formatter MUST mirror that
    // suppression instead of printing a misleading ordered list.
    let suppress_per_file = report
        .warnings
        .iter()
        .any(|w| w.starts_with(DEGENERATE_SHALLOW_WARN_PREFIX));

    // Files list
    if !report.files.is_empty() && !suppress_per_file {
        output.push_str(&"High-Churn Files:\n".bold().to_string());
        output.push_str(&format!(
            " {:>3}  {:>7}  {:>7}  {:>7}  {:>4}  {:>10}  {}\n",
            "#", "Commits", "+Lines", "-Lines", "Auth", "Last", "File"
        ));

        for (i, file) in report.files.iter().enumerate() {
            output.push_str(&format!(
                " {:>3}  {:>7}  {:>7}  {:>7}  {:>4}  {:>10}  {}\n",
                i + 1,
                file.commit_count,
                format!("+{}", file.lines_added),
                format!("-{}", file.lines_deleted),
                file.author_count,
                file.last_commit.as_deref().unwrap_or("-"),
                file.file
            ));
        }
        output.push('\n');
    } else if suppress_per_file && !report.files.is_empty() {
        // Acknowledge presence of file data but explain why we are not
        // printing ranks.
        output.push_str(
            "High-Churn Files: (suppressed — degenerate shallow clone, see warning above)\n\n",
        );
    }

    // Hotspots list
    if !report.hotspots.is_empty() {
        output.push_str(&"Hotspots (churn x complexity):\n".bold().to_string());
        output.push_str(&format!(
            " {:>3}  {:>5}  {:>7}  {:>4}  {}\n",
            "#", "Score", "Commits", "CC", "File"
        ));

        for (i, hotspot) in report.hotspots.iter().enumerate() {
            let score_str = format!("{:.2}", hotspot.combined_score);
            let score_display = if hotspot.combined_score > 0.6 {
                score_str.red().to_string()
            } else if hotspot.combined_score > 0.3 {
                score_str.yellow().to_string()
            } else {
                score_str.green().to_string()
            };

            output.push_str(&format!(
                " {:>3}  {:>5}  {:>7}  {:>4}  {}\n",
                i + 1,
                score_display,
                hotspot.commit_count,
                hotspot.cyclomatic_complexity,
                hotspot.file
            ));
        }
        output.push('\n');
    }

    // Authors list
    if !report.authors.is_empty() {
        output.push_str(&"Author Statistics:\n".bold().to_string());
        output.push_str(&format!(
            " {:>3}  {:>7}  {:>7}  {:>7}  {:>5}  {}\n",
            "#", "Commits", "+Lines", "-Lines", "Files", "Author"
        ));

        for (i, author) in report.authors.iter().enumerate() {
            output.push_str(&format!(
                " {:>3}  {:>7}  {:>7}  {:>7}  {:>5}  {}\n",
                i + 1,
                author.commits,
                format!("+{}", author.lines_added),
                format!("-{}", author.lines_deleted),
                author.files_touched,
                author.name
            ));
        }
    }

    output
}
