//! Daemon persistent JSONL request log (issue #67).
//!
//! The daemon writes an append-only, one-JSON-object-per-line log at
//! `<project>/.tldr/cache/daemon.log` — the same directory
//! `persist_stats` already uses for `query_cache.bin` and
//! `salsa_stats.json` (write-path conventions reused: the directory is
//! created on demand, but there the similarity ends — the log is
//! deliberately NOT temp+rename atomic, because its contract is
//! append-only streaming, not crash-atomic replacement).
//!
//! # Line schema (stable field names — tests assert these, not timestamps)
//!
//! ```text
//! {"ts":"2026-07-18T12:00:00.123456+00:00","pid":4242,"version":"0.4.1-fork.1",
//!  "event":"request|response|lifecycle|slow|fallback|error","command":"extract",
//!  "path":"/abs/file.py","duration_ms":12.345,"status":"ok|error|accepted","detail":"..."}
//! ```
//!
//! - `ts` — RFC 3339 (chrono `Utc::now().to_rfc3339()`).
//! - `pid` — writing process id (daemon process, or CLI process for
//!   client-side `fallback` lines).
//! - `version` — the crate version, i.e. exactly what `tldr --version`
//!   prints (`env!("CARGO_PKG_VERSION")`).
//! - `event` — closed set above. `request` (accepted, before handling),
//!   `response` (after handling, with `duration_ms` + `status`),
//!   `slow` (companion marker when a request exceeded
//!   [`SLOW_REQUEST_MS`]), `error` (companion marker carrying the error
//!   context of a failed request or a daemon-side failure), `lifecycle`
//!   (start / shutdown_command / idle_timeout / stopped / project_missing),
//!   `fallback` (CLIENT-side: a `try_daemon_route` failure fell back to
//!   direct compute — written from the CLI process).
//! - `command` — canonical snake_case command name (`ping`, `extract`,
//!   `calls`, …) or `daemon` for lifecycle lines.
//! - `path` — request target path, when the command has one.
//! - `duration_ms` — request wall time in milliseconds (f64, sub-ms
//!   precision) — present on `response` and `slow` lines.
//! - `status` — `accepted` for `request`, `ok`/`error` for
//!   `response`/`slow`/`error`, `ok`/`error` for `lifecycle` and
//!   `fallback`.
//! - `detail` — free-form context (error text, shutdown reason, …).
//!
//! # Why a bespoke logger instead of `tracing`
//!
//! `tracing`/`tracing-subscriber` are already in the dependency tree (the
//! legacy `tldr-daemon` crate uses them), but the contract here is a
//! specific on-disk JSONL schema in a per-project file with size-cap
//! rotation and a process-shared append helper for CLI-side fallback
//! lines. Wiring a custom `tracing` Layer for that (plus keeping the
//! existing stderr output untouched) is more machinery than the ~150-line
//! file logger below, so the "prefer tracing only if trivially
//! integrable" clause does not apply.
//!
//! # Bounds (documented contract)
//!
//! - **Rotation**: truncate-and-restart. Before every append the file
//!   size is checked; when it exceeds [`MAX_LOG_BYTES`] the file is
//!   recreated empty (previous content dropped) and the new line is
//!   appended. No last-N-lines archival — the newest session always wins.
//! - **Append + flush**: every line is a single `write_all` on a file
//!   opened `append+create`; no buffering, so a line is on disk (or the
//!   write failed) when `emit` returns.
//! - **Best-effort**: a write failure (missing permissions, disk full,
//!   project vanished) NEVER breaks request handling. Failures are
//!   counted in [`DaemonLogger::dropped_writes`] and otherwise silent.
//! - **Deleted-project safety**: if the project root no longer exists the
//!   write is skipped WITHOUT recreating directories — the log must never
//!   resurrect a project the run loop's self-terminate check relies on
//!   being gone.
//!
//! # Out of scope (documented)
//!
//! - The log-reading command EXISTS as of the #67 residual close-out:
//!   `tldr daemon log` (`super::log`) reads this file through the SAME
//!   [`DaemonLogEntry`] type the writer serializes, so the two sides cannot
//!   drift. `tldr daemon status` still exposes `log_path` and
//!   `log_size_bytes` for pointing humans at the file.
//! - Per-request cache hit/miss markers (see the coverage matrix in
//!   `daemon_contract_coverage_test.rs`) stay observable through
//!   `FullStatus.salsa_stats`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Log file name, stored next to `query_cache.bin` / `salsa_stats.json`.
pub const DAEMON_LOG_FILENAME: &str = "daemon.log";

/// Requests slower than this many milliseconds get an explicit `slow` line.
///
/// Overridable per daemon via [`super::daemon_impl::TLDRDaemon::with_slow_request_ms`]
/// so tests can force the marker without injecting sleeps.
pub const SLOW_REQUEST_MS: u64 = 1000;

/// Size cap: when the log exceeds this many bytes it is truncated on the
/// next append (truncate-and-restart rotation).
pub const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Closed set of log event names (schema contract).
pub const EVENT_REQUEST: &str = "request";
pub const EVENT_RESPONSE: &str = "response";
pub const EVENT_LIFECYCLE: &str = "lifecycle";
pub const EVENT_SLOW: &str = "slow";
pub const EVENT_FALLBACK: &str = "fallback";
pub const EVENT_ERROR: &str = "error";

/// The crate version — exactly the value `tldr --version` prints.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The daemon log path for `project`:
/// `<project>/.tldr/cache/daemon.log`.
pub fn daemon_log_path(project: &Path) -> PathBuf {
    project
        .join(".tldr")
        .join("cache")
        .join(DAEMON_LOG_FILENAME)
}

// =============================================================================
// Log entry type — the single schema source shared by writer AND reader
// =============================================================================

/// One daemon-log line, typed.
///
/// This is the SINGLE source of truth for the on-disk JSONL schema: the
/// writer ([`DaemonLogger::emit`] and [`log_client_fallback`]) serializes
/// this struct, and the reader (`tldr daemon log`, [`read_daemon_log`])
/// deserializes into it — the two sides cannot drift.
///
/// Field declaration order IS the documented wire order (`ts, pid, version,
/// event, command, path?, duration_ms?, status, detail?`): serde_json
/// serializes struct fields in declaration order.
///
/// Deserialization is tolerant in exactly one direction: unknown fields
/// (a newer writer adding to the schema) are ignored, and the optional
/// fields become `None` when absent. A line that lacks a required field or
/// carries it with the wrong type is not a log line — the reader counts it
/// as skipped instead of failing the whole read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonLogEntry {
    /// RFC 3339 instant of the write (`Utc::now().to_rfc3339()`).
    pub ts: String,
    /// Writing process id (daemon process, or CLI process for client-side
    /// `fallback` lines).
    pub pid: u32,
    /// Crate version — exactly the value `tldr --version` prints.
    pub version: String,
    /// Closed-set event name (`request|response|lifecycle|slow|fallback|error`).
    pub event: String,
    /// Canonical snake_case command name (`ping`, `extract`, …) or `daemon`
    /// for lifecycle lines.
    pub command: String,
    /// Request target path, when the command has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Request wall time in milliseconds, sub-ms precision (present on
    /// `response` and `slow` lines).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// `accepted` for `request`; `ok`/`error` otherwise.
    pub status: String,
    /// Free-form context (error text, shutdown reason, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl DaemonLogEntry {
    /// Build an entry stamped with the current time, process id and crate
    /// version — the three fields every writer path shares.
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        event: impl Into<String>,
        command: impl Into<String>,
        path: Option<String>,
        duration_ms: Option<f64>,
        status: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            ts: Utc::now().to_rfc3339(),
            pid: std::process::id(),
            version: crate_version().to_string(),
            event: event.into(),
            command: command.into(),
            path,
            duration_ms,
            status: status.into(),
            detail,
        }
    }
}

/// Serialize one entry as a JSONL line (compact, with the trailing newline).
///
/// Best-effort like every write here: serialization of this struct is
/// JSON-native (strings, `u32`, finite `f64` durations), so the `Err` arm
/// is effectively unreachable — but a failure degrades to a dropped write,
/// never a panic.
pub fn serialize_entry_line(entry: &DaemonLogEntry) -> Option<String> {
    let mut line = serde_json::to_string(entry).ok()?;
    line.push('\n');
    Some(line)
}

// =============================================================================
// Log reader — the engine behind `tldr daemon log` (super::log)
// =============================================================================

/// Byte cap for one log read.
///
/// The writer rotates at [`MAX_LOG_BYTES`], so a conforming log never
/// exceeds the cap by more than one trailing line. The reader still refuses
/// to load more than the cap from disk: for an oversized (non-conforming or
/// mid-rotation) file it seeks to `size - cap` and parses only the tail
/// window. [`LOG_READ_CAP_BYTES`] is exactly the rotation cap — the whole
/// file fits in memory whenever the writer's contract holds.
pub const LOG_READ_CAP_BYTES: u64 = MAX_LOG_BYTES;

/// Number of entries `tldr daemon log` prints when `--tail` is not given.
pub const DEFAULT_LOG_TAIL: usize = 100;

/// What to read out of the daemon log: a tail bound plus field filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogQuery {
    /// Print only the last N entries AFTER filtering; 0 = every entry.
    pub tail: usize,
    /// Exact, case-insensitive match on the `event` field.
    pub event: Option<String>,
    /// Exact, case-insensitive match on the `command` field.
    pub command: Option<String>,
}

impl LogQuery {
    /// Does `entry` pass both filters? (Exact match, ASCII
    /// case-insensitive — `--event RESPONSE` selects `response` lines.)
    pub fn matches(&self, entry: &DaemonLogEntry) -> bool {
        if let Some(event) = &self.event {
            if !entry.event.eq_ignore_ascii_case(event) {
                return false;
            }
        }
        if let Some(command) = &self.command {
            if !entry.command.eq_ignore_ascii_case(command) {
                return false;
            }
        }
        true
    }
}

/// The result of reading a daemon log.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DaemonLogRead {
    /// Parsed entries (filtered + tail-bounded), oldest first.
    pub entries: Vec<DaemonLogEntry>,
    /// Non-empty fragments inside the read window that were not valid log
    /// entries — garbage, or lines truncated by a crash mid-write — skipped
    /// silently but counted. The window's cut-off HEAD fragment (only ever
    /// present on a file larger than [`LOG_READ_CAP_BYTES`]) is NOT counted:
    /// it is the unparseable tail of a line whose head lies before the
    /// window, a boundary artifact rather than a corrupt line.
    pub skipped: u64,
}

/// Read the daemon log at `path` according to `query`.
///
/// Total and graceful: a missing, unreadable or empty file yields zero
/// entries and zero skipped lines — the CLI layer turns that into the clean
/// "no daemon log" message (exit 0). At most [`LOG_READ_CAP_BYTES`] are
/// loaded from the END of the file; everything newer wins, mirroring the
/// writer's truncate-and-restart rotation.
///
/// The `skipped` counter covers the whole window, independent of the tail
/// bound — it is a file-health signal, not an output-shape one.
pub fn read_daemon_log(path: &Path, query: &LogQuery) -> DaemonLogRead {
    let mut read = DaemonLogRead::default();

    let Ok(meta) = std::fs::metadata(path) else {
        return read;
    };
    let total = meta.len();
    if total == 0 {
        return read;
    }

    let window_start = total.saturating_sub(LOG_READ_CAP_BYTES);
    let Ok(mut file) = File::open(path) else {
        return read;
    };

    // Does the window open at a line boundary? Peek the byte before it: a
    // newline (or window_start == 0) means the first fragment in the window
    // is a complete line; anything else means it is the tail of a line
    // whose head the cap cut off.
    let mut at_line_boundary = window_start == 0;
    if window_start > 0 {
        let mut peek = [0u8; 1];
        if file
            .seek(SeekFrom::Start(window_start - 1))
            .and_then(|_| file.read(&mut peek))
            .map(|n| n == 1)
            .unwrap_or(false)
        {
            at_line_boundary = peek[0] == b'\n';
        }
    }

    if file.seek(SeekFrom::Start(window_start)).is_err() {
        return read;
    }
    let window_len = usize::try_from(total - window_start).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(window_len.min(8 * 1024 * 1024));
    if file.take(window_len as u64).read_to_end(&mut buf).is_err() {
        return read;
    }

    let raw = String::from_utf8_lossy(&buf);
    let mut first = true;
    for fragment in raw.split('\n') {
        if first {
            first = false;
            if !at_line_boundary {
                continue;
            }
        }
        let line = fragment.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<DaemonLogEntry>(line) {
            Ok(entry) => read.entries.push(entry),
            Err(_) => read.skipped += 1,
        }
    }

    if query.event.is_some() || query.command.is_some() {
        read.entries.retain(|entry| query.matches(entry));
    }
    if query.tail > 0 && read.entries.len() > query.tail {
        let excess = read.entries.len() - query.tail;
        read.entries.drain(..excess);
    }
    read
}

// =============================================================================
// DaemonLogger
// =============================================================================

/// Append-only JSONL logger for one project's daemon.
///
/// Held by [`super::daemon_impl::TLDRDaemon`]; interior-mutable (the file
/// handle is opened lazily on first write), `Send + Sync` via the internal
/// `Mutex`, and infallible from the caller's perspective.
pub struct DaemonLogger {
    project: PathBuf,
    path: PathBuf,
    file: Mutex<Option<File>>,
    dropped_writes: AtomicU64,
    /// Rotation cap in bytes. Production loggers carry [`MAX_LOG_BYTES`]
    /// (see [`DaemonLogger::new`]); the test-only
    /// [`DaemonLogger::with_max_bytes`] injects a tiny value so the
    /// rotation decisions are exercisable without multi-megabyte fixtures —
    /// injected and default caps route through the SAME decision code.
    max_bytes: u64,
}

impl DaemonLogger {
    /// Create a logger for `project`'s `<project>/.tldr/cache/daemon.log`.
    ///
    /// No filesystem access happens here — the file is opened lazily on
    /// the first [`DaemonLogger::emit`], so constructing a daemon never
    /// touches disk (and never resurrects a deleted project directory).
    pub fn new(project: PathBuf) -> Self {
        let path = daemon_log_path(&project);
        Self {
            project,
            path,
            file: Mutex::new(None),
            dropped_writes: AtomicU64::new(0),
            max_bytes: MAX_LOG_BYTES,
        }
    }

    /// Test-only rotation-cap override (injectable [`MAX_LOG_BYTES`]): the
    /// SAME logger with a tiny cap, so lib pins can drive the rotation
    /// decisions with small fixtures. Not part of the public surface —
    /// production loggers always carry [`MAX_LOG_BYTES`].
    #[cfg(test)]
    fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The log file path (exposed through `tldr daemon status` as
    /// `log_path`).
    pub fn log_path(&self) -> &Path {
        &self.path
    }

    /// Current log size in bytes, `None` when the file does not exist
    /// (exposed through `tldr daemon status` as `log_size_bytes`).
    pub fn log_size_bytes(&self) -> Option<u64> {
        std::fs::metadata(&self.path).ok().map(|m| m.len())
    }

    /// Number of writes dropped because the filesystem said no
    /// (best-effort contract observability).
    pub fn dropped_writes(&self) -> u64 {
        self.dropped_writes.load(Ordering::Relaxed)
    }

    /// Append one structured line. Best-effort: never panics, never
    /// propagates IO errors.
    ///
    /// `path`, `duration_ms` and `detail` are omitted from the line when
    /// `None`. Field order follows the documented schema — the line is
    /// serialized from the shared [`DaemonLogEntry`] type (declaration
    /// order = wire order).
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        event: &str,
        command: &str,
        path: Option<&Path>,
        duration_ms: Option<f64>,
        status: &str,
        detail: Option<&str>,
    ) {
        let entry = DaemonLogEntry::now(
            event,
            command,
            path.map(|p| p.to_string_lossy().into_owned()),
            duration_ms,
            status,
            detail.map(str::to_string),
        );
        self.write_line(&entry);
    }

    /// Open (or reopen after rotation) the log file in append mode.
    ///
    /// Returns `None` on any failure — counted as a dropped write by the
    /// caller.
    fn open_file(&self) -> Option<File> {
        let cache_dir = self.path.parent()?;
        std::fs::create_dir_all(cache_dir).ok()?;
        // Rotation: if the previous session (or a long-running session,
        // checked again before every append below) pushed the file past
        // the cap, truncate-and-restart. `File::create` truncates.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > self.max_bytes {
                std::fs::remove_file(&self.path).ok()?;
            }
        }
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .ok()
    }

    /// Serialize `entry` through the shared type, then lock the (lazily
    /// opened) file handle, re-check the size cap, append, and let the
    /// `File` drop-flush the small write. Any error increments
    /// [`Self::dropped_writes`].
    fn write_line(&self, entry: &DaemonLogEntry) {
        let Some(serialized) = serialize_entry_line(entry) else {
            // Not a panic risk in practice (JSON-native fields only); a
            // serialization failure degrades to a dropped write.
            self.dropped_writes.fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Deleted-project guard, checked on EVERY emit: once the project
        // root is gone the logger must neither write nor recreate any
        // directory (the daemon's self-terminate check relies on the
        // project staying gone; a POSIX handle would happily keep writing
        // to the unlinked inode otherwise).
        if !self.project.exists() {
            self.dropped_writes.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(_) => {
                self.dropped_writes.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Open lazily; after a rotation/poisoned-handle the handle is
        // reopened on the next write.
        if guard.is_none() {
            match self.open_file() {
                Some(f) => *guard = Some(f),
                None => {
                    self.dropped_writes.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }

        // Rotation for a long-running session: the cap is re-checked
        // against the LIVE file before every append, so a daemon that
        // never restarts still honors the bound.
        let file = guard.as_mut().expect("handle opened above");
        if let Ok(meta) = file.metadata() {
            if meta.len() + serialized.len() as u64 > self.max_bytes {
                match self.open_file() {
                    Some(f) => {
                        *guard = Some(f);
                    }
                    None => {
                        // Keep the old handle: a failed rotation still
                        // lets the line land if the old file is writable.
                    }
                }
            }
        }
        let file = guard.as_mut().expect("handle present");
        match file
            .write_all(serialized.as_bytes())
            .and_then(|_| file.flush())
        {
            Ok(()) => {}
            Err(_) => {
                // Force a reopen on the next write — the current handle
                // may be stale (rotated away, device gone, …).
                *guard = None;
                self.dropped_writes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl std::fmt::Debug for DaemonLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonLogger")
            .field("project", &self.project)
            .field("path", &self.path)
            .field(
                "dropped_writes",
                &self.dropped_writes.load(Ordering::Relaxed),
            )
            .finish()
    }
}

// =============================================================================
// Client-side fallback logging (shared helper)
// =============================================================================

/// Append a `fallback` line for a CLI command whose `try_daemon_route`
/// attempt failed and which is falling back to direct compute.
///
/// This is the shared helper the daemon and the CLI router both use (the
/// router lives in the same crate), so client-side fallbacks land in the
/// SAME file the daemon writes — one observability stream per project.
///
/// Deliberately conservative: the line is appended ONLY when the log file
/// already exists, i.e. a daemon has run for this project at least once.
/// The CLI fallback path never creates the file (nor `.tldr/cache/`), so
/// running plain direct-compute commands in a project that never opted
/// into the daemon leaves no new state behind.
pub fn log_client_fallback(project: &Path, endpoint: &str, reason: &str) {
    let path = daemon_log_path(project);
    if !path.exists() {
        return;
    }
    let entry = DaemonLogEntry::now(
        EVENT_FALLBACK,
        endpoint,
        None,
        None,
        "ok",
        Some(reason.to_string()),
    );
    let Some(serialized) = serialize_entry_line(&entry) else {
        return;
    };

    // One-shot open/append/drop: O_APPEND keeps concurrent writes from the
    // daemon process and this CLI process line-atomic for small writes.
    if let Ok(mut file) = OpenOptions::new().append(true).open(&path) {
        let _ = file.write_all(serialized.as_bytes());
        let _ = file.flush();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Parse every line of the log file into a JSON object.
    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        let raw = std::fs::read_to_string(path).expect("log file readable");
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("every line is valid JSON"))
            .collect()
    }

    #[test]
    fn emit_writes_schema_lines_with_required_fields() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());

        logger.emit(
            EVENT_REQUEST,
            "extract",
            Some(&project),
            None,
            "accepted",
            None,
        );
        logger.emit(
            EVENT_RESPONSE,
            "extract",
            Some(&project),
            Some(12.5),
            "ok",
            None,
        );

        let path = daemon_log_path(&project);
        assert!(path.exists(), "first emit must create the log file");
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 2, "one JSON object per line");

        let request = &lines[0];
        assert_eq!(request["event"], "request");
        assert_eq!(request["command"], "extract");
        assert_eq!(request["status"], "accepted");
        assert_eq!(request["pid"], std::process::id());
        assert_eq!(request["version"], crate_version());
        assert_eq!(request["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            request["path"],
            project.to_string_lossy().as_ref(),
            "path is recorded as a string"
        );
        assert!(
            request.get("ts").and_then(|v| v.as_str()).is_some(),
            "ts must be present (RFC 3339 string, not asserted for value)"
        );
        assert!(
            request.get("duration_ms").is_none(),
            "duration_ms must be omitted when not applicable"
        );
        assert!(request.get("detail").is_none(), "detail omitted when None");

        let response = &lines[1];
        assert_eq!(response["event"], "response");
        assert_eq!(response["status"], "ok");
        assert_eq!(response["duration_ms"], 12.5);
        // Schema field order (serde_json preserve_order): ts, pid, version,
        // event, command, path, duration_ms, status, detail — the optional
        // fields stay out, the required ones keep their relative order.
        let raw = std::fs::read_to_string(&path).unwrap();
        let first_line = raw.lines().next().unwrap();
        let schema_order = ["ts", "pid", "version", "event", "command", "path", "status"];
        let positions: Vec<usize> = schema_order
            .iter()
            .map(|k| {
                first_line
                    .find(&format!("\"{k}\""))
                    .unwrap_or_else(|| panic!("required key {k} missing from line: {first_line}"))
            })
            .collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(
            positions, sorted,
            "required schema fields must appear in documented order in: {first_line}"
        );
    }

    #[test]
    fn ts_is_rfc3339_shaped() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());
        logger.emit(EVENT_LIFECYCLE, "daemon", None, None, "ok", Some("started"));

        let line = &read_lines(&daemon_log_path(&project))[0];
        let ts = line["ts"].as_str().expect("ts is a string");
        // Stable-shape assertion only (issue #67: never assert timestamps):
        // an RFC 3339 instant always carries the year prefix and the offset.
        assert!(
            ts.len() > 20,
            "ts must be a full RFC 3339 instant, got {ts}"
        );
        assert!(ts.starts_with("20"), "got {ts}");
        assert!(ts.contains('T') || ts.contains('t'), "got {ts}");
    }

    #[test]
    fn rotation_truncates_when_cap_exceeded() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());

        // Pre-fill past the cap (MAX_LOG_BYTES + one filler line).
        let log_path = daemon_log_path(&project);
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        let filler = format!("{}\n", "x".repeat(256)).repeat(1 + MAX_LOG_BYTES as usize / 257);
        std::fs::write(&log_path, &filler).unwrap();
        assert!(std::fs::metadata(&log_path).unwrap().len() > MAX_LOG_BYTES);

        logger.emit(EVENT_REQUEST, "ping", None, None, "accepted", None);

        let size = std::fs::metadata(&log_path).unwrap().len();
        assert!(
            size <= MAX_LOG_BYTES,
            "the log must be truncated at the cap after rotation, got {size} bytes"
        );
        let lines = read_lines(&log_path);
        assert_eq!(lines.len(), 1, "previous (over-cap) content is dropped");
        assert_eq!(lines[0]["event"], "request");
        assert_eq!(lines[0]["command"], "ping");
    }

    #[test]
    fn long_lived_session_rotates_without_reopen_by_caller() {
        // The cap is re-checked before every append, so a single logger
        // instance truncates mid-session too.
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());

        // First emit opens the handle.
        logger.emit(EVENT_REQUEST, "warm", None, None, "accepted", None);
        // Grow the file far past the cap behind the logger's back (simulates
        // a very long session).
        let log_path = daemon_log_path(&project);
        let filler = "y".repeat(MAX_LOG_BYTES as usize + 1024);
        {
            let mut f = OpenOptions::new().append(true).open(&log_path).unwrap();
            f.write_all(filler.as_bytes()).unwrap();
        }

        logger.emit(EVENT_RESPONSE, "warm", None, Some(1.0), "ok", None);

        let size = std::fs::metadata(&log_path).unwrap().len();
        assert!(
            size <= MAX_LOG_BYTES,
            "mid-session append must rotate: {size}"
        );
        let lines = read_lines(&log_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["event"], "response");
    }

    /// Rotation MID-REQUEST (injectable tiny cap — same decision code as the
    /// production `MAX_LOG_BYTES`, never a megabyte fixture): the file starts
    /// under the cap, the `request` line's append pushes it OVER (rotation is
    /// DEFERRED — the pre-append size was still under, so the line is written
    /// anyway), and the following `response` append performs the actual
    /// truncate-and-restart: the newest line wins, the now-orphaned request
    /// line is gone, and the reader parses the aftermath as a clean, conforming
    /// log (1 entry, 0 skipped).
    #[test]
    fn mid_request_rotation_drops_the_orphaned_request_and_keeps_the_response_readable() {
        const CAP: u64 = 512;
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone()).with_max_bytes(CAP);

        let log_path = daemon_log_path(&project);
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        // Filler: one non-JSON line, strictly under the cap.
        std::fs::write(&log_path, format!("{}\n", "x".repeat(300))).unwrap();

        // A request line padded (via the path field) far past CAP − filler:
        // its append overflows the cap while the pre-append size stays under.
        let big_file = format!("{}.py", "p".repeat(400));
        let big_path = project.join(&big_file);
        logger.emit(
            EVENT_REQUEST,
            "extract",
            Some(&big_path),
            None,
            "accepted",
            None,
        );

        let size_after_request = std::fs::metadata(&log_path).unwrap().len();
        assert!(
            size_after_request > CAP,
            "fixture assumption: the request line must push the file over the \
             cap (deferred rotation), got {size_after_request} bytes"
        );
        let raw_after_request = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            raw_after_request.contains(&big_file),
            "the over-cap request line itself must still be appended — \
             rotation is deferred to the NEXT append, not skipped"
        );

        // The response's append performs the truncate-and-restart.
        logger.emit(EVENT_RESPONSE, "extract", None, Some(1.5), "ok", None);

        let raw = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !raw.contains(&big_file),
            "the orphaned request line must not survive the mid-request rotation"
        );
        let lines = read_lines(&log_path);
        assert_eq!(
            lines.len(),
            1,
            "truncate-and-restart keeps exactly the newest line: {raw}"
        );
        assert_eq!(lines[0]["event"], "response");
        assert_eq!(lines[0]["status"], "ok");
        assert!(
            std::fs::metadata(&log_path).unwrap().len() <= CAP,
            "the file is back under the cap after the rotation"
        );

        // The reader sees a clean, conforming log — no garbage fragments, no
        // skipped lines, the surviving response parsed through the shared type.
        let read = read_daemon_log(&log_path, &LogQuery::default());
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.entries[0].event, EVENT_RESPONSE);
        assert_eq!(read.entries[0].command, "extract");
        assert_eq!(read.skipped, 0, "no unparseable fragments after rotation");
    }

    #[test]
    fn write_failure_never_panics_and_is_counted() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        // `.tldr` exists as a REGULAR FILE: create_dir_all(".tldr/cache")
        // must fail, and the failure must be swallowed.
        std::fs::write(project.join(".tldr"), b"not a directory").unwrap();

        let logger = DaemonLogger::new(project.clone());
        logger.emit(EVENT_REQUEST, "ping", None, None, "accepted", None);

        assert_eq!(logger.dropped_writes(), 1, "the failed write is counted");
        assert!(
            !daemon_log_path(&project).exists(),
            "no log file may appear when the cache dir cannot be created"
        );
    }

    #[test]
    fn deleted_project_never_gets_directories_recreated() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());

        // Emit once with the project present...
        logger.emit(EVENT_REQUEST, "ping", None, None, "accepted", None);
        assert!(daemon_log_path(&project).exists());
        // ...then delete the whole project and emit again.
        std::fs::remove_dir_all(&project).unwrap();
        logger.emit(EVENT_REQUEST, "ping", None, None, "accepted", None);

        assert!(
            !project.exists(),
            "the logger must not resurrect a deleted project directory"
        );
        assert_eq!(logger.dropped_writes(), 1);
    }

    #[test]
    fn client_fallback_appends_when_log_exists_and_never_creates_it() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();

        // No daemon ever ran for this project: the fallback helper must not
        // create state.
        log_client_fallback(&project, "calls", "daemon not running");
        assert!(
            !daemon_log_path(&project).exists(),
            "the CLI fallback path must not create the log file"
        );

        // A daemon ran (the log exists): the fallback line is appended.
        let logger = DaemonLogger::new(project.clone());
        logger.emit(EVENT_LIFECYCLE, "daemon", None, None, "ok", Some("started"));
        log_client_fallback(&project, "calls", "daemon not running");

        let lines = read_lines(&daemon_log_path(&project));
        assert_eq!(lines.len(), 2);
        let fallback = &lines[1];
        assert_eq!(fallback["event"], "fallback");
        assert_eq!(fallback["command"], "calls");
        assert_eq!(fallback["detail"], "daemon not running");
        assert_eq!(fallback["status"], "ok");
        assert_eq!(fallback["pid"], std::process::id());
    }

    #[test]
    fn log_size_bytes_reports_none_for_missing_file() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let logger = DaemonLogger::new(project.clone());
        assert_eq!(logger.log_size_bytes(), None);
        logger.emit(EVENT_REQUEST, "ping", None, None, "accepted", None);
        assert!(logger.log_size_bytes().unwrap_or(0) > 0);
        assert_eq!(logger.log_path(), daemon_log_path(&project));
    }

    // =========================================================================
    // Reader (`read_daemon_log`) — lib-level pins. End-to-end CLI coverage
    // (text formatting, --json shape, real-daemon smoke, window cap on an
    // oversized fabricated file) lives in tests/daemon_log_v1.rs.
    // =========================================================================

    /// Write a hand-built entry straight into a log file (bypasses the
    /// logger so the schema round-trip is exact).
    fn write_entries(path: &Path, entries: &[DaemonLogEntry]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut raw = String::new();
        for e in entries {
            raw.push_str(&serialize_entry_line(e).expect("entry serializes"));
        }
        std::fs::write(path, raw).unwrap();
    }

    fn entry_at(event: &str, command: &str, status: &str, detail: Option<&str>) -> DaemonLogEntry {
        DaemonLogEntry::now(
            event,
            command,
            None,
            None,
            status,
            detail.map(str::to_string),
        )
    }

    fn all_query() -> LogQuery {
        LogQuery {
            tail: 0,
            event: None,
            command: None,
        }
    }

    #[test]
    fn shared_type_round_trips_the_documented_schema() {
        // The exact struct the writer builds is what the reader gets back —
        // the drift-proofing pin for the shared type.
        let temp = TempDir::new().unwrap();
        let path = daemon_log_path(temp.path());
        let written = DaemonLogEntry {
            ts: "2026-07-18T12:00:00.123456+00:00".to_string(),
            pid: 4242,
            version: "0.4.1-fork.1".to_string(),
            event: EVENT_RESPONSE.to_string(),
            command: "extract".to_string(),
            path: Some("/abs/file.py".to_string()),
            duration_ms: Some(12.345),
            status: "ok".to_string(),
            detail: None,
        };
        write_entries(&path, &[written.clone()]);

        let read = read_daemon_log(&path, &all_query());
        assert_eq!(read.entries, vec![written]);
        assert_eq!(read.skipped, 0);
    }

    #[test]
    fn reader_missing_and_empty_files_are_graceful() {
        let temp = TempDir::new().unwrap();
        let missing = daemon_log_path(temp.path());
        let read = read_daemon_log(&missing, &all_query());
        assert!(read.entries.is_empty());
        assert_eq!(read.skipped, 0);

        std::fs::create_dir_all(missing.parent().unwrap()).unwrap();
        std::fs::write(&missing, b"").unwrap();
        let read = read_daemon_log(&missing, &all_query());
        assert!(read.entries.is_empty());
        assert_eq!(read.skipped, 0);
    }

    #[test]
    fn reader_keeps_log_order_and_skips_garbage_counting_it() {
        let temp = TempDir::new().unwrap();
        let path = daemon_log_path(temp.path());
        let entries = [
            entry_at(EVENT_REQUEST, "extract", "accepted", Some("a")),
            entry_at(EVENT_RESPONSE, "extract", "ok", Some("b")),
            entry_at(EVENT_LIFECYCLE, "daemon", "ok", Some("c")),
        ];
        write_entries(&path, &entries);
        // Crash-mid-write artifacts: a garbage line and a truncated tail.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"not json at all\n{\"ts\": \"2026-").unwrap();
        }

        let read = read_daemon_log(&path, &all_query());
        let details: Vec<Option<&str>> = read.entries.iter().map(|e| e.detail.as_deref()).collect();
        assert_eq!(details, vec![Some("a"), Some("b"), Some("c")]);
        assert_eq!(read.skipped, 2, "garbage + truncated tail are counted");
    }

    #[test]
    fn reader_valid_json_that_is_not_a_log_line_is_skipped() {
        let temp = TempDir::new().unwrap();
        let path = daemon_log_path(temp.path());
        write_entries(&path, &[entry_at(EVENT_REQUEST, "ping", "accepted", None)]);
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            // Valid JSON, wrong schema: not a log line.
            f.write_all(b"{\"unrelated\": true}\n").unwrap();
        }
        let read = read_daemon_log(&path, &all_query());
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.skipped, 1);
    }

    #[test]
    fn reader_tail_applies_after_filters() {
        let temp = TempDir::new().unwrap();
        let path = daemon_log_path(temp.path());
        // 4 pings interleaved with 2 extracts; tail must pick the LAST N
        // MATCHING entries, not matching entries among the last N.
        let entries = [
            entry_at(EVENT_REQUEST, "ping", "accepted", Some("p1")),
            entry_at(EVENT_REQUEST, "extract", "accepted", Some("e1")),
            entry_at(EVENT_REQUEST, "ping", "accepted", Some("p2")),
            entry_at(EVENT_REQUEST, "ping", "accepted", Some("p3")),
            entry_at(EVENT_REQUEST, "extract", "accepted", Some("e2")),
            entry_at(EVENT_REQUEST, "ping", "accepted", Some("p4")),
        ];
        write_entries(&path, &entries);

        let query = LogQuery {
            tail: 2,
            event: None,
            command: Some("ping".to_string()),
        };
        let read = read_daemon_log(&path, &query);
        let details: Vec<Option<&str>> = read.entries.iter().map(|e| e.detail.as_deref()).collect();
        assert_eq!(details, vec![Some("p3"), Some("p4")]);

        let query = LogQuery {
            tail: 100,
            event: None,
            command: Some("EXTRACT".to_string()),
        };
        let read = read_daemon_log(&path, &query);
        assert_eq!(read.entries.len(), 2, "case-insensitive exact match");
        assert_eq!(read.entries[0].detail.as_deref(), Some("e1"));
    }

    #[test]
    fn reader_tail_zero_means_everything_and_tail_bounds_match_exactly() {
        let temp = TempDir::new().unwrap();
        let path = daemon_log_path(temp.path());
        let entries: Vec<DaemonLogEntry> = (0..5)
            .map(|i| entry_at(EVENT_REQUEST, "ping", "accepted", Some(&i.to_string())))
            .collect();
        write_entries(&path, &entries);

        assert_eq!(read_daemon_log(&path, &all_query()).entries.len(), 5);
        let read = read_daemon_log(
            &path,
            &LogQuery {
                tail: 3,
                event: None,
                command: None,
            },
        );
        let details: Vec<Option<&str>> = read.entries.iter().map(|e| e.detail.as_deref()).collect();
        assert_eq!(details, vec![Some("2"), Some("3"), Some("4")]);
    }
}
