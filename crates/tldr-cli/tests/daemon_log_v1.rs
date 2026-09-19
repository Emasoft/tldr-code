//! `daemon_log_v1` — contract suite for `tldr daemon log`, the filterable
//! reader for the daemon's persistent JSONL request log (closes the #67
//! residual "no log-reading command").
//!
//! # Coverage matrix
//!
//! - Default tail = last 100 entries; `--tail N` bounds; `--tail 0` = all.
//! - `--event` / `--command` filters: exact, case-insensitive; applied
//!   BEFORE the tail bound (last N matching, not matching among last N).
//! - Invalid lines (garbage, valid-JSON-wrong-schema, crash-truncated
//!   mid-write) are skipped silently but counted in text output.
//! - `--json` shape: a bare array of entries whose keys follow the log
//!   schema order (the SAME typed struct the writer serializes —
//!   `DaemonLogEntry` — so writer and reader cannot drift).
//! - Text mode: one line per entry
//!   `[ts] event command path? duration? status detail?`.
//! - Missing log → clean "No daemon log" message, exit 0; empty file →
//!   empty output.
//! - Rotation boundary: the reader never loads more than `MAX_LOG_BYTES`
//!   from the END of the file (unit-tested against a fabricated oversized
//!   file — writing 5 MB of real entries would be too slow; a plain
//!   filler blob exercises the same seek-based window).
//! - One real-daemon smoke test: an in-process daemon session (same
//!   no-OS-process pattern as `daemon_contract_coverage_test.rs`) writes
//!   through the actual serve loop, and the real `tldr` binary reads it.
//!
//! # Isolation
//!
//! Every CLI run passes an explicit `--project <tempdir>`, so
//! `resolve_default_project` honours the path untouched — no registry, no
//! `~/.tldr` state, no env coupling. The daemon session runs in-process
//! and is shut down explicitly; nothing lingers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

use tldr_cli::commands::daemon::{
    check_socket_alive, daemon_log_path, read_daemon_log, send_command, DaemonCommand,
    DaemonConfig, DaemonLogEntry, DaemonLogger, IpcListener, LogQuery, TLDRDaemon, MAX_LOG_BYTES,
};

// =============================================================================
// Helpers
// =============================================================================

fn tldr() -> AssertCommand {
    assert_cmd::cargo::cargo_bin_cmd!("tldr")
}

/// Canonicalized project tempdir (macOS resolves `/var` → `/private/var`;
/// `resolve_default_project` canonicalizes too, so both spellings meet in
/// the same directory).
fn project_dir(prefix: &str) -> (TempDir, PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("project tempdir");
    let canonical = temp.path().canonicalize().expect("canonicalize project");
    (temp, canonical)
}

/// A `daemon log` invocation against `project` with extra CLI args.
fn daemon_log(project: &Path, extra: &[&str]) -> AssertCommand {
    let mut cmd = tldr();
    cmd.args(["daemon", "log", "--project"]).arg(project);
    cmd.args(extra);
    cmd
}

fn stdout_of(assertion: assert_cmd::assert::Assert) -> String {
    String::from_utf8(assertion.get_output().stdout.clone()).expect("stdout is utf-8")
}

/// Write `count` identifiable entries through the SHARED writer type
/// (direct-write: deterministic, no daemon needed).
fn write_numbered_entries(project: &Path, event: &str, command: &str, count: usize) {
    let logger = DaemonLogger::new(project.to_path_buf());
    for i in 0..count {
        logger.emit(
            event,
            command,
            None,
            None,
            "accepted",
            Some(&format!("entry-{i}")),
        );
    }
}

fn parsed_json_array(stdout: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(stdout).expect("default output must be a JSON array");
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected a JSON array, got: {stdout}"))
        .clone()
}

// =============================================================================
// Tail semantics
// =============================================================================

/// Default (no `--tail`): the last 100 entries, oldest first.
#[test]
fn default_tail_prints_the_last_100_entries() {
    let (_temp, project) = project_dir("dlog-tail100-");
    write_numbered_entries(&project, "request", "extract", 150);

    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    let entries = parsed_json_array(&stdout);
    assert_eq!(entries.len(), 100, "default tail is 100");
    let first = entries.first().unwrap()["detail"].as_str().unwrap();
    let last = entries.last().unwrap()["detail"].as_str().unwrap();
    assert_eq!(first, "entry-50", "the oldest 50 are tail-cut: {first}");
    assert_eq!(last, "entry-149");
}

/// `--tail 0` = everything; `--tail N` = the last N; an over-large N
/// returns what exists.
#[test]
fn tail_zero_returns_everything_and_tail_n_bounds() {
    let (_temp, project) = project_dir("dlog-tailn-");
    write_numbered_entries(&project, "request", "extract", 7);

    let stdout = stdout_of(daemon_log(&project, &["--tail", "0"]).assert().success());
    let entries = parsed_json_array(&stdout);
    assert_eq!(entries.len(), 7, "--tail 0 must not mean 'none'");
    assert_eq!(entries[0]["detail"].as_str().unwrap(), "entry-0");

    let stdout = stdout_of(daemon_log(&project, &["--tail", "3"]).assert().success());
    let entries = parsed_json_array(&stdout);
    let details: Vec<&str> = entries
        .iter()
        .map(|e| e["detail"].as_str().unwrap())
        .collect();
    assert_eq!(details, vec!["entry-4", "entry-5", "entry-6"]);

    let stdout = stdout_of(daemon_log(&project, &["--tail", "999"]).assert().success());
    assert_eq!(parsed_json_array(&stdout).len(), 7);
}

// =============================================================================
// Filters
// =============================================================================

#[test]
fn event_filter_is_exact_and_case_insensitive() {
    let (_temp, project) = project_dir("dlog-event-");
    let logger = DaemonLogger::new(project.clone());
    logger.emit("request", "extract", None, None, "accepted", Some("r1"));
    logger.emit("response", "extract", None, Some(1.0), "ok", Some("p1"));
    logger.emit("request", "ping", None, None, "accepted", Some("r2"));

    // Uppercase needle, lowercase haystack.
    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text", "--event", "RESPONSE"])
            .assert()
            .success(),
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "exactly the response line: {lines:?}");
    assert!(lines[0].contains("response extract"));
    assert!(lines[0].ends_with("ok p1"));

    // Lowercase needle on both remaining request lines.
    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text", "--event", "request"])
            .assert()
            .success(),
    );
    assert_eq!(stdout.lines().count(), 2);
}

#[test]
fn command_filter_is_exact_and_case_insensitive() {
    let (_temp, project) = project_dir("dlog-command-");
    let logger = DaemonLogger::new(project.clone());
    logger.emit("request", "extract", None, None, "accepted", Some("e1"));
    logger.emit("request", "ping", None, None, "accepted", Some("p1"));
    logger.emit("response", "extract", None, Some(2.0), "ok", Some("e2"));

    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text", "--command", "EXTRACT"])
            .assert()
            .success(),
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "both extract lines, nothing else: {lines:?}"
    );
    assert!(lines.iter().all(|l| l.contains("extract")));

    // Exact, not substring.
    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text", "--command", "ping"])
            .assert()
            .success(),
    );
    assert_eq!(stdout.lines().count(), 1);
}

/// `--tail N` applies AFTER filtering: the last N MATCHING entries.
#[test]
fn filters_apply_before_the_tail_bound() {
    let (_temp, project) = project_dir("dlog-filter-tail-");
    let logger = DaemonLogger::new(project.clone());
    for (command, tag) in [
        ("ping", "p1"),
        ("extract", "e1"),
        ("ping", "p2"),
        ("ping", "p3"),
        ("extract", "e2"),
        ("ping", "p4"),
    ] {
        logger.emit("request", command, None, None, "accepted", Some(tag));
    }

    let stdout = stdout_of(
        daemon_log(&project, &["--command", "ping", "--tail", "2"])
            .assert()
            .success(),
    );
    let entries = parsed_json_array(&stdout);
    let tags: Vec<&str> = entries
        .iter()
        .map(|e| e["detail"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        vec!["p3", "p4"],
        "last 2 pings, not 'pings among the last 2 lines'"
    );
}

// =============================================================================
// Invalid-line handling
// =============================================================================

#[test]
fn invalid_lines_are_skipped_silently_but_counted() {
    let (_temp, project) = project_dir("dlog-invalid-");
    write_numbered_entries(&project, "request", "extract", 2);

    // Corrupt the log behind the writer's back: garbage, valid JSON with
    // the wrong schema, and a crash-style truncated tail (no newline).
    let log_path = daemon_log_path(&project);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        f.write_all(b"not json at all\n{\"unrelated\": true}\n{\"ts\": \"2026-")
            .unwrap();
    }

    // Text mode: the two good entries, then the skip count.
    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text"])
            .assert()
            .success(),
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "2 entries + the skip note: {lines:?}");
    assert!(lines[0].contains("request extract"));
    assert!(lines[1].contains("request extract"));
    assert_eq!(lines[2], "(3 unparseable lines skipped)");

    // JSON mode: a bare array with only the parseable entries (the count
    // never pollutes the machine contract).
    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    let entries = parsed_json_array(&stdout);
    assert_eq!(entries.len(), 2);
}

/// The mid-write edge specifically: a truncated LAST line (no closing
/// brace, no newline) is not an entry, and the singular note reads right.
#[test]
fn truncated_last_line_mid_write_is_not_an_entry() {
    let (_temp, project) = project_dir("dlog-truncated-");
    write_numbered_entries(&project, "response", "ping", 2);
    let log_path = daemon_log_path(&project);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        f.write_all(b"{\"ts\":\"2026-07-18T12:00:00+00:00\",\"pid\":1,\"ver")
            .unwrap();
    }

    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text"])
            .assert()
            .success(),
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2], "(1 unparseable line skipped)", "singular note");

    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    assert_eq!(parsed_json_array(&stdout).len(), 2);
}

// =============================================================================
// Output shapes
// =============================================================================

/// `--json` (and the json default): a bare array whose objects follow the
/// log schema — the same `DaemonLogEntry` the writer serializes, so the
/// key order and the optional-field omission are pinned here.
#[test]
fn json_output_shape_is_the_log_schema() {
    let (_temp, project) = project_dir("dlog-jsonshape-");
    let logger = DaemonLogger::new(project.clone());
    logger.emit("request", "extract", Some(&project), None, "accepted", None);
    logger.emit(
        "response",
        "extract",
        Some(&project),
        Some(12.5),
        "ok",
        Some("done"),
    );

    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    let entries = parsed_json_array(&stdout);
    assert_eq!(entries.len(), 2);

    // serde_json is built with preserve_order: struct field declaration
    // order IS the wire order, so the reader's array must show the exact
    // documented schema (optional fields out when absent).
    let request = entries[0].as_object().unwrap();
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["ts", "pid", "version", "event", "command", "path", "status"],
        "request entry keys in schema order: {keys:?}"
    );
    assert_eq!(
        request["pid"],
        std::process::id(),
        "the writer ran in-process"
    );
    assert_eq!(request["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(request["path"], project.to_string_lossy().as_ref());
    assert!(request.get("duration_ms").is_none());
    assert!(request.get("detail").is_none());

    let response = entries[1].as_object().unwrap();
    let keys: Vec<&str> = response.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec![
            "ts",
            "pid",
            "version",
            "event",
            "command",
            "path",
            "duration_ms",
            "status",
            "detail"
        ],
        "response entry keys in schema order: {keys:?}"
    );
    assert_eq!(response["duration_ms"], 12.5);

    // `--json` forces the array even under `--format text`.
    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text", "--json"])
            .assert()
            .success(),
    );
    assert_eq!(parsed_json_array(&stdout).len(), 2);
}

/// Text mode: one human line per entry,
/// `[ts] event command path? duration? status detail?`.
#[test]
fn text_mode_formats_the_documented_line_shape() {
    let (_temp, project) = project_dir("dlog-textfmt-");
    let log_path = daemon_log_path(&project);
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

    // Hand-written fixed-ts entries: the exact human line becomes
    // assertable (the repo rule "never assert timestamps" applies to
    // writer-generated values; these are fixtures).
    let fixture = [
        r#"{"ts":"2026-07-18T12:00:00.123456+00:00","pid":4242,"version":"0.4.1-fork.1","event":"request","command":"extract","path":"/abs/file.py","status":"accepted"}"#,
        r#"{"ts":"2026-07-18T12:00:00.200000+00:00","pid":4242,"version":"0.4.1-fork.1","event":"response","command":"extract","path":"/abs/file.py","duration_ms":12.5,"status":"ok","detail":"done"}"#,
        r#"{"ts":"2026-07-18T12:00:05.000000+00:00","pid":4242,"version":"0.4.1-fork.1","event":"lifecycle","command":"daemon","status":"ok","detail":"started"}"#,
    ];
    std::fs::write(&log_path, fixture.join("\n") + "\n").unwrap();

    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text"])
            .assert()
            .success(),
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "no skip note when nothing was skipped");
    assert_eq!(
        lines,
        vec![
            "[2026-07-18T12:00:00.123456+00:00] request extract /abs/file.py accepted",
            "[2026-07-18T12:00:00.200000+00:00] response extract /abs/file.py 12.500ms ok done",
            "[2026-07-18T12:00:05.000000+00:00] lifecycle daemon ok started",
        ]
    );
}

// =============================================================================
// Graceful edges
// =============================================================================

#[test]
fn missing_log_file_is_graceful_with_exit_zero() {
    let (_temp, project) = project_dir("dlog-missing-");

    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text"])
            .assert()
            .success(),
    );
    assert!(
        stdout.contains("No daemon log"),
        "clean human message, got: {stdout}"
    );
    assert!(stdout.contains(&project.to_string_lossy().as_ref()));

    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    assert_eq!(parsed_json_array(&stdout), Vec::<serde_json::Value>::new());
}

#[test]
fn empty_log_file_prints_empty_output() {
    let (_temp, project) = project_dir("dlog-empty-");
    let log_path = daemon_log_path(&project);
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
    std::fs::write(&log_path, b"").unwrap();

    let stdout = stdout_of(
        daemon_log(&project, &["--format", "text"])
            .assert()
            .success(),
    );
    assert!(
        stdout.trim().is_empty(),
        "empty file → empty text output, got: {stdout:?}"
    );

    let stdout = stdout_of(daemon_log(&project, &[]).assert().success());
    assert_eq!(parsed_json_array(&stdout), Vec::<serde_json::Value>::new());
}

#[test]
fn quiet_suppresses_all_output() {
    let (_temp, project) = project_dir("dlog-quiet-");
    write_numbered_entries(&project, "request", "extract", 3);
    let stdout = stdout_of(
        tldr()
            .args(["daemon", "log", "--project"])
            .arg(&project)
            .args(["--quiet"])
            .assert()
            .success(),
    );
    assert!(stdout.is_empty(), "--quiet must print nothing: {stdout:?}");
}

// =============================================================================
// Rotation boundary: the reader's read cap (unit-tested against a
// fabricated oversized file — a full 5 MB of real entries would be slow)
// =============================================================================

#[test]
fn read_cap_parses_only_the_last_window_of_an_oversized_file() {
    let (_temp, project) = project_dir("dlog-cap-");
    let log_path = daemon_log_path(&project);
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

    // Filler WITHOUT a trailing newline: the window (last MAX_LOG_BYTES)
    // must open strictly inside the blob, so its first fragment is the
    // unparseable tail of the cut line — dropped WITHOUT being counted.
    let blob = "x".repeat(MAX_LOG_BYTES as usize + 1024);
    let entry = |tag: &str| {
        let e = DaemonLogEntry::now(
            "request",
            "extract",
            None,
            None,
            "accepted",
            Some(tag.to_string()),
        );
        serde_json::to_string(&e).expect("entry serializes")
    };
    let mut raw = blob;
    raw.push('\n');
    raw.push_str(&entry("e1"));
    raw.push('\n');
    raw.push_str("garbage line\n");
    raw.push_str(&entry("e2"));
    raw.push('\n');
    raw.push_str(&entry("e3"));
    raw.push('\n');
    std::fs::write(&log_path, raw).unwrap();
    assert!(
        std::fs::metadata(&log_path).unwrap().len() > MAX_LOG_BYTES,
        "fixture must exceed the cap"
    );

    // Reader, unfiltered and untailed.
    let read = read_daemon_log(&log_path, &LogQuery::default());
    let tags: Vec<Option<&str>> = read.entries.iter().map(|e| e.detail.as_deref()).collect();
    assert_eq!(
        tags,
        vec![Some("e1"), Some("e2"), Some("e3")],
        "only the last window is read, in order"
    );
    assert_eq!(
        read.skipped, 1,
        "the in-window garbage line counts; the cut head fragment does not"
    );

    // Same file through the real binary: --tail 2 serves the last two
    // entries of the window.
    let stdout = stdout_of(daemon_log(&project, &["--tail", "2"]).assert().success());
    let entries = parsed_json_array(&stdout);
    let tags: Vec<&str> = entries
        .iter()
        .map(|e| e["detail"].as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["e2", "e3"]);
}

// =============================================================================
// Real-daemon smoke test (in-process serve loop, real reader binary)
// =============================================================================

#[cfg(unix)]
mod smoke {
    use super::*;

    /// Spawn `TLDRDaemon::run` over a freshly bound IPC listener (same
    /// no-OS-process pattern as `daemon_contract_coverage_test.rs`).
    async fn start_in_process_daemon(
        project: &Path,
        config: DaemonConfig,
    ) -> tokio::task::JoinHandle<tldr_cli::commands::daemon::DaemonResult<()>> {
        let daemon = TLDRDaemon::new(project.to_path_buf(), config);
        let listener = IpcListener::bind(project)
            .await
            .expect("IPC listener bind on a fresh tempdir must succeed");
        let handle = tokio::spawn(async move { std::sync::Arc::new(daemon).run(listener).await });

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !check_socket_alive(project).await {
            assert!(
                std::time::Instant::now() < deadline,
                "in-process daemon socket never became connectable"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle
    }

    #[tokio::test]
    async fn real_daemon_session_log_is_readable_over_the_cli() {
        let (_temp, project) = project_dir("dlog-smoke-");
        std::fs::write(
            project.join("utils.py"),
            "def helper():\n    return 'help'\n",
        )
        .expect("write utils.py");

        let handle = start_in_process_daemon(&project, DaemonConfig::default()).await;

        send_command(&project, &DaemonCommand::Ping)
            .await
            .expect("ping round-trip");
        send_command(
            &project,
            &DaemonCommand::Extract {
                file: project.join("utils.py"),
                session: None,
            },
        )
        .await
        .expect("extract round-trip");

        send_command(&project, &DaemonCommand::Shutdown)
            .await
            .expect("shutdown acknowledged");
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("daemon exits after shutdown")
            .expect("run task must not panic")
            .expect("graceful shutdown returns Ok");

        // The real binary reads the real session log.
        let stdout = stdout_of(daemon_log(&project, &["--tail", "0"]).assert().success());
        let entries = parsed_json_array(&stdout);
        assert!(!entries.is_empty(), "a served session must leave entries");

        for entry in &entries {
            let obj = entry.as_object().unwrap();
            for key in ["ts", "pid", "version", "event", "command", "status"] {
                assert!(obj.contains_key(key), "every entry carries {key}: {entry}");
            }
            assert_eq!(obj["version"], env!("CARGO_PKG_VERSION"));
        }

        let is = |e: &serde_json::Value, event: &str, detail: &str| {
            e["event"] == event && e["detail"] == detail
        };
        assert!(
            is(&entries[0], "lifecycle", "started"),
            "the session must open with the started line: {:?}",
            entries[0]
        );
        assert!(
            is(entries.last().unwrap(), "lifecycle", "stopped"),
            "the session must close with the stopped line: {:?}",
            entries.last().unwrap()
        );
        assert!(
            entries
                .iter()
                .any(|e| e["event"] == "request" && e["command"] == "ping"),
            "the ping request line must be in the log"
        );
        assert!(
            entries.iter().any(|e| e["event"] == "response"
                && e["command"] == "extract"
                && e["duration_ms"].is_number()
                && e["status"] == "ok"),
            "the extract response line must carry a duration: {entries:?}"
        );

        // Event filter through the real binary, case-insensitive.
        let stdout = stdout_of(
            daemon_log(&project, &["--tail", "0", "--event", "LIFECYCLE"])
                .assert()
                .success(),
        );
        let lifecycle = parsed_json_array(&stdout);
        assert!(!lifecycle.is_empty());
        assert!(
            lifecycle.iter().all(|e| e["event"] == "lifecycle"),
            "only lifecycle entries survive the filter"
        );

        // Tail through the real binary: the last entry is the closing stop.
        let stdout = stdout_of(daemon_log(&project, &["--tail", "1"]).assert().success());
        let last = parsed_json_array(&stdout);
        assert_eq!(last.len(), 1);
        assert!(
            is(&last[0], "lifecycle", "stopped"),
            "with --tail 1 the newest entry is the stopped line: {:?}",
            last[0]
        );
    }
}
