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
//! - No log-reading command: `tldr daemon status` exposes `log_path` and
//!   `log_size_bytes`; reading/filtering the log is future work.
//! - Client-side fallbacks in commands that do NOT route through
//!   `try_daemon_route_async` (e.g. the client-local enriched search) are
//!   not logged here — there is no shared choke point for them.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;

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
        }
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
    /// `None`. Field order follows the documented schema (serde_json is
    /// built with `preserve_order`).
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
        let mut line = serde_json::Map::new();
        line.insert("ts".into(), serde_json::json!(Utc::now().to_rfc3339()));
        line.insert("pid".into(), serde_json::json!(std::process::id()));
        line.insert("version".into(), serde_json::json!(crate_version()));
        line.insert("event".into(), serde_json::json!(event));
        line.insert("command".into(), serde_json::json!(command));
        if let Some(p) = path {
            line.insert("path".into(), serde_json::json!(p.to_string_lossy()));
        }
        if let Some(d) = duration_ms {
            line.insert("duration_ms".into(), serde_json::json!(d));
        }
        line.insert("status".into(), serde_json::json!(status));
        if let Some(d) = detail {
            line.insert("detail".into(), serde_json::json!(d));
        }

        let mut serialized = serde_json::Value::Object(line).to_string();
        serialized.push('\n');
        self.write_line(&serialized);
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
            if meta.len() > MAX_LOG_BYTES {
                std::fs::remove_file(&self.path).ok()?;
            }
        }
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .ok()
    }

    /// Serialize one line to disk. Locks the (lazily opened) file handle,
    /// re-checks the size cap, appends, and lets the `File` drop-flush the
    /// small write. Any error increments [`Self::dropped_writes`].
    fn write_line(&self, line: &str) {
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
            if meta.len() + line.len() as u64 > MAX_LOG_BYTES {
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
        match file.write_all(line.as_bytes()).and_then(|_| file.flush()) {
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
    let mut line = serde_json::Map::new();
    line.insert("ts".into(), serde_json::json!(Utc::now().to_rfc3339()));
    line.insert("pid".into(), serde_json::json!(std::process::id()));
    line.insert("version".into(), serde_json::json!(crate_version()));
    line.insert("event".into(), serde_json::json!(EVENT_FALLBACK));
    line.insert("command".into(), serde_json::json!(endpoint));
    line.insert("status".into(), serde_json::json!("ok"));
    line.insert("detail".into(), serde_json::json!(reason));
    let mut serialized = serde_json::Value::Object(line).to_string();
    serialized.push('\n');

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
}
