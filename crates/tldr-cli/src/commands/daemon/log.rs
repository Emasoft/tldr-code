//! `tldr daemon log` — filterable reader for the daemon's persistent JSONL
//! request log (closes the issue-#67 residual "no log-reading command").
//!
//! Reads `<project>/.tldr/cache/daemon.log` through the SAME typed entry
//! ([`super::logging::DaemonLogEntry`]) the writer serializes, so the
//! reader and the writer cannot drift. Nothing here talks to the daemon —
//! every log line is flushed on write, so a running daemon can be read
//! safely while it works.
//!
//! # Semantics
//!
//! - Project resolution mirrors `daemon status`: the shared
//!   `resolve_default_project` (registry discovery for the `.` default,
//!   explicit `--project` always honoured).
//! - Default prints the last [`super::logging::DEFAULT_LOG_TAIL`] entries;
//!   `--tail N` the last N (0 = all). N applies AFTER the
//!   `--event`/`--command` filters, so `--event error --tail 50` shows the
//!   last 50 errors, not "errors among the last 50 lines".
//! - The read is capped at `MAX_LOG_BYTES` from the END of the file (the
//!   writer's rotation bound): an oversized file contributes only its last
//!   window, and the window's cut-off head fragment is dropped uncounted.
//! - Lines that are not valid log entries (e.g. a line truncated by a
//!   crash mid-write, or JSON that does not match the schema) are skipped
//!   silently but counted; the count is reported in text output.
//! - A project without a log gets a clean "No daemon log" message with
//!   exit 0 (graceful, like the #34 not-running precedent).
//!
//! # Output
//!
//! - JSON mode (the default `--format json|compact`, or the explicit
//!   `--json` override which forces JSON even under `--format text`): a
//!   bare JSON array of log entries, schema = the log schema.
//! - Text mode: one human line per entry,
//!   `[ts] event command path? duration? status detail?` — the design's
//!   `[ts] event command status detail?` spine with the two optional
//!   schema fields (`path`, `duration_ms`) slotted between command and
//!   status so every schema field stays visible; full fidelity is one
//!   `--json` away.

use std::path::PathBuf;

use clap::Args;

use super::daemon_registry::resolve_default_project;
use super::logging::{
    daemon_log_path, read_daemon_log, DaemonLogEntry, LogQuery, DEFAULT_LOG_TAIL,
};
use crate::output::OutputFormat;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Arguments for the `daemon log` command.
#[derive(Debug, Clone, Args)]
pub struct DaemonLogArgs {
    /// Project root directory (default: current directory, or the running
    /// daemon's project when exactly one daemon is live).
    #[arg(long, short = 'p', default_value = ".")]
    pub project: PathBuf,

    /// Print only the last N entries (after filtering); 0 = all entries.
    #[arg(long, default_value_t = DEFAULT_LOG_TAIL, value_name = "N")]
    pub tail: usize,

    /// Only entries whose `event` field equals this value
    /// (case-insensitive): request|response|lifecycle|slow|fallback|error.
    #[arg(long, value_name = "EVENT")]
    pub event: Option<String>,

    /// Only entries whose `command` field equals this value
    /// (case-insensitive), e.g. `extract` or `ping`.
    #[arg(long, value_name = "NAME")]
    pub command: Option<String>,

    /// Emit a JSON array of entries even under `--format text`
    /// (`--format json`/`compact` already emit JSON).
    #[arg(long)]
    pub json: bool,
}

// =============================================================================
// Command Implementation
// =============================================================================

impl DaemonLogArgs {
    /// Run the daemon log command.
    pub fn run(&self, format: OutputFormat, quiet: bool) -> anyhow::Result<()> {
        if quiet {
            return Ok(());
        }

        // Same resolution contract as `daemon status`/`daemon stop`: an
        // explicit `--project` always wins; the `.` default discovers the
        // running daemon through the shared registry helper.
        let project = resolve_default_project(&self.project)?;
        let log_path = daemon_log_path(&project);
        let query = LogQuery {
            tail: self.tail,
            event: self.event.clone(),
            command: self.command.clone(),
        };
        let use_json = self.json || matches!(format, OutputFormat::Json | OutputFormat::Compact);

        if !log_path.exists() {
            // Graceful (the #34 precedent): a project that never ran a
            // daemon has no log, and that is not an error.
            if use_json {
                println!("[]");
            } else {
                println!(
                    "No daemon log for {} (the daemon has not run for this project yet)",
                    project.display()
                );
            }
            return Ok(());
        }

        let read = read_daemon_log(&log_path, &query);
        if use_json {
            println!("{}", serde_json::to_string_pretty(&read.entries)?);
            return Ok(());
        }

        for entry in &read.entries {
            println!("{}", format_log_line(entry));
        }
        if read.skipped > 0 {
            println!(
                "({} unparseable line{} skipped)",
                read.skipped,
                if read.skipped == 1 { "" } else { "s" }
            );
        }
        Ok(())
    }
}

/// Format one entry as its human line:
/// `[ts] event command path? duration? status detail?`
fn format_log_line(entry: &DaemonLogEntry) -> String {
    let mut line = format!("[{}] {} {}", entry.ts, entry.event, entry.command);
    if let Some(path) = &entry.path {
        line.push(' ');
        line.push_str(path);
    }
    if let Some(duration_ms) = entry.duration_ms {
        line.push_str(&format!(" {duration_ms:.3}ms"));
    }
    line.push(' ');
    line.push_str(&entry.status);
    if let Some(detail) = &entry.detail {
        line.push(' ');
        line.push_str(detail);
    }
    line
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        event: &str,
        command: &str,
        path: Option<&str>,
        duration_ms: Option<f64>,
        status: &str,
        detail: Option<&str>,
    ) -> DaemonLogEntry {
        DaemonLogEntry::now(
            event,
            command,
            path.map(str::to_string),
            duration_ms,
            status,
            detail.map(str::to_string),
        )
    }

    #[test]
    fn log_args_default_to_tail_100_no_filters() {
        let args = DaemonLogArgs {
            project: PathBuf::from("."),
            tail: DEFAULT_LOG_TAIL,
            event: None,
            command: None,
            json: false,
        };
        assert_eq!(args.project, PathBuf::from("."));
        assert_eq!(args.tail, 100);
        assert!(args.event.is_none() && args.command.is_none());
        assert!(!args.json);
    }

    #[test]
    fn format_log_line_matches_the_documented_spine() {
        // Full record: [ts] event command path duration status detail.
        let full = entry(
            "response",
            "extract",
            Some("/abs/file.py"),
            Some(12.3456),
            "ok",
            Some("done"),
        );
        assert_eq!(
            format_log_line(&full),
            format!(
                "[{}] response extract /abs/file.py 12.346ms ok done",
                full.ts
            )
        );

        // Bare lifecycle line: [ts] event command status.
        let bare = entry("lifecycle", "daemon", None, None, "ok", Some("started"));
        assert_eq!(
            format_log_line(&bare),
            format!("[{}] lifecycle daemon ok started", bare.ts)
        );

        // No detail, no path, no duration: no trailing junk.
        let minimal = entry("request", "ping", None, None, "accepted", None);
        assert_eq!(
            format_log_line(&minimal),
            format!("[{}] request ping accepted", minimal.ts)
        );
        assert!(!format_log_line(&minimal).ends_with(' '));
    }

    #[test]
    fn log_query_filters_are_exact_and_case_insensitive() {
        let query = LogQuery {
            tail: 0,
            event: Some("RESPONSE".to_string()),
            command: Some("Extract".to_string()),
        };
        assert!(query.matches(&entry("response", "extract", None, None, "ok", None)));
        assert!(!query.matches(&entry("request", "extract", None, None, "ok", None)));
        assert!(!query.matches(&entry("response", "ping", None, None, "ok", None)));
        // Exact, not substring.
        assert!(!query.matches(&entry("response", "extract_all", None, None, "ok", None)));
    }
}
