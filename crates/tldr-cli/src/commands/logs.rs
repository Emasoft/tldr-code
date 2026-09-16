//! Logs command — filter and list log entries from a `.log` file (log batch).
//!
//! `tldr logs <file> [--from TS] [--to TS] [--level LEVEL] [--grep PAT]` runs
//! the native, streaming entry scanner ([`tldr_core::ast::logs`]) over the
//! file and emits the entries that pass every active filter:
//!
//! - `--from` / `--to`: INCLUSIVE bounds on the entry's parsed timestamp,
//!   compared as UTC-normalized `(epoch_secs, nanos)` tuples. Bounds accept
//!   every timestamp shape the scanner recognizes plus a bare date
//!   (`--from 2026-09-14` = midnight UTC of that day). Entries whose
//!   timestamp is missing or year-less (syslog `Sep 14 08:34:49` — no year,
//!   so any inference would be a guess) are EXCLUDED and counted in the
//!   `unfilterable` field rather than silently matched or guessed.
//! - `--level`: case-insensitive exact match against the NORMALIZED level
//!   (`warning` and `warn` are the same filter; `ERROR` matches `error`).
//! - `--grep`: case-sensitive substring on the entry's raw source text.
//!
//! # Streaming
//!
//! Filters are applied INSIDE the scan callback, so a GiB log with a narrow
//! window never materialises unmatched entries — memory stays proportional
//! to the MATCHED entries only (plus one line + one entry in the scanner).
//!
//! # Output
//!
//! - `--format json` / `--format compact`: a [`LogsReport`] document (schema
//!   `logs-command-v1` — all-new fields, so the command is additive-safe for
//!   every existing consumer).
//! - `--format text`: matched entries printed as their raw source lines with
//!   a `--` separator between entries (line terminators are stripped by the
//!   scanner, including the `\r` of CRLF pairs — see `ast::logs`).

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use tldr_core::ast::logs::{
    normalize_level_token, parse_interval_bound, stream_log_entries, LogEntry, TimestampInstant,
};

use crate::output::{OutputFormat, OutputWriter};

/// Result document for `tldr logs` — schema `logs-command-v1`.
///
/// All fields are new (the command is new), so the schema is additive-safe
/// by construction; `entries` rows serialize [`LogEntry`] directly.
#[derive(Debug, Serialize)]
pub struct LogsReport {
    /// File path exactly as the user supplied it.
    pub file: String,
    /// Total entries the scanner grouped the file into (before filtering).
    pub total_entries: u64,
    /// Entries that passed every active filter.
    pub matched: u64,
    /// Entries EXCLUDED only because their timestamp could not be compared
    /// under an active `--from`/`--to` window (missing or year-less
    /// timestamps). Always `0` when no interval filter is set.
    pub unfilterable: u64,
    /// The matched entries, in source order.
    pub entries: Vec<LogEntry>,
}

/// Filter and list log entries from a log file.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Path to the log file
    #[arg(value_name = "file")]
    pub file: PathBuf,

    /// Inclusive lower bound on the entry timestamp (e.g. `2026-09-14`,
    /// `2026-09-14T08:00:00Z`, `2026-09-14 08:00:00`). Entries whose
    /// timestamp is missing or year-less are excluded and counted as
    /// unfilterable.
    #[arg(long, value_name = "TS")]
    pub from: Option<String>,

    /// Inclusive upper bound on the entry timestamp (same forms as --from).
    #[arg(long, value_name = "TS")]
    pub to: Option<String>,

    /// Exact normalized level filter (fatal/critical/emerg/alert/panic/
    /// error/err → error; warn/warning → warn; info/notice/information →
    /// info; debug/trace/fine/finer/finest → debug). Case-insensitive.
    #[arg(long, value_name = "LEVEL")]
    pub level: Option<String>,

    /// Case-sensitive substring filter on the entry's raw source text.
    #[arg(long, value_name = "PAT")]
    pub grep: Option<String>,
}

impl LogsArgs {
    /// Run the logs command
    pub fn run(&self, cli_format: OutputFormat, quiet: bool) -> Result<()> {
        // Validate the path BEFORE anything else (same convention as
        // `structure`/`body`), and require a regular file.
        if !self.file.exists() {
            anyhow::bail!("Path not found: {}", self.file.display());
        }
        if !self.file.is_file() {
            anyhow::bail!("Not a file: {}", self.file.display());
        }

        // Parse the interval bounds up front: an unparseable user bound is a
        // hard error, not a silent empty result.
        let from_bound: Option<TimestampInstant> = match &self.from {
            Some(s) => Some(parse_interval_bound(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not parse --from '{}'. Supported forms: RFC3339 \
                     (2026-09-14T08:34:49Z), space-separated datetime \
                     (2026-09-14 08:34:49,123), bracketed common-log \
                     (14/Sep/2026:08:34:49 +0200), epoch (10 or 13 digits), \
                     or a bare date (2026-09-14).",
                    s
                )
            })?),
            None => None,
        };
        let to_bound: Option<TimestampInstant> = match &self.to {
            Some(s) => Some(parse_interval_bound(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not parse --to '{}'. Supported forms: RFC3339 \
                     (2026-09-14T08:34:49Z), space-separated datetime \
                     (2026-09-14 08:34:49,123), bracketed common-log \
                     (14/Sep/2026:08:34:49 +0200), epoch (10 or 13 digits), \
                     or a bare date (2026-09-14).",
                    s
                )
            })?),
            None => None,
        };
        let interval_active = from_bound.is_some() || to_bound.is_some();

        // Normalize the level filter once (`warning` → `warn`); an
        // unrecognized word filters on its lowercased form verbatim, which
        // matches no entry's normalized level (a predictable empty result).
        let level_filter: Option<String> = self.level.as_ref().map(|l| {
            normalize_level_token(l)
                .map(str::to_string)
                .unwrap_or_else(|| l.to_lowercase())
        });
        let grep_filter: Option<&str> = self.grep.as_deref();

        let writer = OutputWriter::new(cli_format, quiet);
        writer.progress(&format!("Scanning {}...", self.file.display()));

        let text_mode = writer.is_text();
        let mut report = LogsReport {
            file: self.file.display().to_string(),
            total_entries: 0,
            matched: 0,
            unfilterable: 0,
            entries: Vec::new(),
        };

        // Streaming stdout handle for text mode: matched entries are printed
        // as they are scanned, so nothing proportional to the file (or the
        // entry count) is buffered.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        let mut first_printed = true;

        let total = stream_log_entries(&self.file, |entry: LogEntry, text: &str| {
            // The closure mutates `report` below; `total_entries` is set from
            // the scanner's return value afterwards.
            // 1. Level filter (exact normalized match).
            if let Some(filter) = &level_filter {
                if entry.level.as_deref() != Some(filter.as_str()) {
                    return;
                }
            }
            // 2. Grep filter (case-sensitive substring on the raw text).
            if let Some(pat) = grep_filter {
                if !text.contains(pat) {
                    return;
                }
            }
            // 3. Interval filter — inclusive bounds on the normalized
            //    timestamp. Entries with a missing or year-less (syslog)
            //    timestamp cannot be compared: exclude + count as
            //    unfilterable rather than guessing a year.
            if interval_active {
                let inst = match entry
                    .timestamp
                    .as_deref()
                    .and_then(tldr_core::ast::logs::normalize_timestamp)
                {
                    Some(i) => i,
                    None => {
                        report.unfilterable += 1;
                        return;
                    }
                };
                if let Some(from) = from_bound {
                    if inst < from {
                        return;
                    }
                }
                if let Some(to) = to_bound {
                    if inst > to {
                        return;
                    }
                }
            }

            report.matched += 1;
            if text_mode {
                if !first_printed {
                    let _ = writeln!(handle, "--");
                }
                first_printed = false;
                let _ = writeln!(handle, "{}", text);
            } else {
                report.entries.push(entry);
            }
        })?;
        report.total_entries = total;

        if text_mode {
            handle.flush()?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}
