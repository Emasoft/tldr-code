//! broken-pipe-and-flag-like-queries-v1 (issues #12 and #13)
//!
//! Two CLI-ergonomics regressions pinned as executable contracts against
//! the real `tldr` binary (spawned via `CARGO_BIN_EXE_tldr`, no synthetic
//! fixtures beyond a temp source tree the search command needs to index).
//!
//! 1. **Issue #12 — broken pipe exited 1.** `tldr search fn <dir> -f json |
//!    head -c 1` printed `Error: Broken pipe (os error 32)` on stderr and
//!    exited 1. Unix convention: EPIPE on stdout means the READER went
//!    away (head, grep -m, less … all do this on purpose) — the writer
//!    must exit 0, silently, never with an error diagnostic. Fix shape:
//!    `main.rs`'s single top-level error boundary maps
//!    `std::io::ErrorKind::BrokenPipe` (anywhere in the anyhow chain) to a
//!    silent `ExitCode::SUCCESS`, so every command is covered. The harness
//!    mirrors `| head -c 1`: spawn the binary with `Stdio::piped()` stdout
//!    and drop the parent's read end immediately.
//!
//! 2. **Issue #13 — flag-like search queries rejected.** `tldr search
//!    '--port' <dir>` died with a clap usage error and a misleading
//!    `tip: a similar argument exists: '--format'`. Fix shape:
//!    `SmartSearchArgs`' query positional sets
//!    `#[arg(allow_hyphen_values = true)]`, so hyphen-prefixed queries are
//!    accepted verbatim. The `--` escape form keeps working, registered
//!    flags (`-f`, `-k`, `-l`, `--regex`) are still parsed as flags, and
//!    other commands' positionals are untouched.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn tldr_bin() -> PathBuf {
    // why: env!("CARGO_BIN_EXE_tldr") is the path cargo builds for THIS
    // test's own profile, as a test dependency — it cannot go stale the way
    // a hand-resolved `target/debug/tldr` guess could (TRDD-BJ9T0U9I).
    PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
}

/// Fixture: a small Rust "service" project. `server.rs` contains the
/// literal `--port` string plus the `port` token several times so a
/// flag-like query (`--port`) and a plain query (`port`) both have a real
/// match; the remaining files widen the JSON report so the broken-pipe
/// harness exercises real (multi-write) output volume.
///
/// Returns the project root (the directory handed to `tldr search`).
fn write_service_fixture(dir: &TempDir) -> PathBuf {
    let root = dir.path().join("service");
    std::fs::create_dir_all(&root).expect("create fixture root");

    std::fs::write(
        root.join("server.rs"),
        r#"use std::net::TcpListener;

/// The CLI exposes the socket address through the `--port` flag.
pub const CLI_FLAG: &str = "--port";

pub fn serve(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    for stream in listener.incoming() {
        let _ = stream;
    }
    Ok(())
}
"#,
    )
    .expect("write server.rs");

    for i in 0..5 {
        std::fs::write(
            root.join(format!("worker_{i}.rs")),
            format!(
                r#"pub fn worker_{i}_run(batch: usize) -> usize {{
    let mut total = 0;
    for step in 0..batch {{
        total += step * {i};
    }}
    total
}}

pub fn worker_{i}_report(total: usize) -> String {{
    format!("worker {i}: {{total}}")
}}
"#
            ),
        )
        .expect("write worker file");
    }

    root
}

fn run(args: &[&str]) -> (Vec<u8>, Vec<u8>, Option<i32>) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    (out.stdout, out.stderr, out.status.code())
}

/// Parse stdout as an enriched-search JSON report and collect the `file`
/// value of every result card.
fn result_files(stdout: &[u8], context: &str) -> Vec<String> {
    let report: serde_json::Value = serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "{context}: stdout must parse as an enriched-search JSON report: {e} | head: {:?}",
            String::from_utf8_lossy(stdout)
                .chars()
                .take(300)
                .collect::<String>()
        )
    });
    report
        .get("results")
        .and_then(|r| r.as_array())
        .unwrap_or_else(|| panic!("{context}: report must carry a 'results' array"))
        .iter()
        .filter_map(|card| {
            card.get("file")
                .and_then(|f| f.as_str())
                .map(|f| f.to_string())
        })
        .collect()
}

// =============================================================================
// Issue #12: broken pipe on stdout must exit 0, silently
// =============================================================================

/// `tldr search fn <dir> -f json | head -c 1` used to print
/// `Error: Broken pipe (os error 32)` and exit 1. The harness reproduces
/// the pipe geometry exactly: the binary's stdout is a pipe whose read end
/// the parent drops immediately (the `head -c 1` equivalent), so every
/// stdout write in the child fails with EPIPE. The CLI must exit 0 with an
/// empty stderr — the reader's early exit is not an error.
#[test]
fn issue12_broken_pipe_from_closed_reader_exits_zero_silently() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    let mut child = Command::new(tldr_bin())
        .args(["search", "fn", root.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tldr");

    // The `| head -c 1` equivalent: close the read end before the child
    // has produced output. (Dropping the handle closes the pipe; the child
    // then gets EPIPE on its next stdout write because Rust ignores
    // SIGPIPE by default and surfaces the failure as an io::Error.)
    drop(child.stdout.take());

    let output = child.wait_with_output().expect("failed to wait for tldr");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_eq!(
        output.status.code(),
        Some(0),
        "a closed stdout reader means the READER went away — tldr must exit 0, \
         never 'Error: Broken pipe (os error 32)' with exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "broken pipe must be silent (no 'Error:' diagnostic on stderr); got: {stderr}"
    );
}

/// The fix lives at the top-level error boundary, so it is command-agnostic:
/// a different command (`structure`) hitting the same closed-reader pipe
/// must also exit 0 silently, not just `search`.
#[test]
fn issue12_broken_pipe_applies_across_commands_structure_too() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    let mut child = Command::new(tldr_bin())
        .args(["structure", root.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tldr");

    drop(child.stdout.take());

    let output = child.wait_with_output().expect("failed to wait for tldr");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_eq!(
        output.status.code(),
        Some(0),
        "broken pipe handling must apply to every command (top-level boundary); \
         structure exited {:?}; stderr: {stderr}",
        output.status.code()
    );
    assert!(
        stderr.is_empty(),
        "broken pipe must be silent for structure too; got: {stderr}"
    );
}

// =============================================================================
// Issue #13: flag-like search queries
// =============================================================================

/// `tldr search --port <dir>` used to be rejected by clap with
/// `error: unexpected argument '--port' found` plus the misleading
/// `tip: a similar argument exists: '--format'` (exit 2). With
/// `allow_hyphen_values` on the query positional it must run like any other
/// search — and actually find the file containing `--port`.
#[test]
fn issue13_flag_like_query_accepted_and_finds_the_flag_file() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    let (stdout, stderr, code) = run(&["search", "--port", root.to_str().unwrap(), "-f", "json"]);

    assert_eq!(
        code,
        Some(0),
        "flag-like query must be accepted as the search query (was clap exit 2); \
         stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must parse as JSON: {e} | stderr: {} | head: {:?}",
            String::from_utf8_lossy(&stderr),
            String::from_utf8_lossy(&stdout)
                .chars()
                .take(300)
                .collect::<String>()
        )
    });
    // The query positional must have received the literal flag-like value.
    assert_eq!(
        report.get("query").and_then(|q| q.as_str()),
        Some("--port"),
        "the hyphen-prefixed positional must arrive verbatim as the query"
    );

    let files = result_files(&stdout, "flag-like query");
    assert!(
        files.iter().any(|f| f.ends_with("server.rs")),
        "search '--port' must find the fixture file containing --port; got files: {files:?}"
    );
}

/// The explicit escape form `tldr search -f json -- '--port' <dir>` must
/// keep working unchanged.
#[test]
fn issue13_double_dash_escape_form_still_works() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    let (stdout, stderr, code) = run(&[
        "search",
        "-f",
        "json",
        "--",
        "--port",
        root.to_str().unwrap(),
    ]);

    assert_eq!(
        code,
        Some(0),
        "the `--` escape form must keep working; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|e| panic!("stdout must parse as JSON: {e}"));
    assert_eq!(
        report.get("query").and_then(|q| q.as_str()),
        Some("--port"),
        "the escaped query must arrive verbatim"
    );
    let files = result_files(&stdout, "escaped flag-like query");
    assert!(
        files.iter().any(|f| f.ends_with("server.rs")),
        "escaped query must find the fixture file containing --port; got: {files:?}"
    );
}

/// Registered flags keep parsing as flags (not query values) even next to a
/// flag-like query, plain queries still work, and commands that did NOT opt
/// into `allow_hyphen_values` still reject flag-like positionals with the
/// clap usage error.
#[test]
fn issue13_registered_flags_and_other_commands_are_unaffected() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    // `-k 1` must still be consumed as the top_k flag; `--port` stays the
    // query. The report must therefore carry at most one result card.
    let (stdout, stderr, code) = run(&[
        "search",
        "-k",
        "1",
        "--port",
        root.to_str().unwrap(),
        "-f",
        "json",
    ]);
    assert_eq!(
        code,
        Some(0),
        "-k must still parse as a flag next to a flag-like query; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|e| panic!("stdout must parse as JSON: {e}"));
    let total = report
        .get("total_results")
        .and_then(|t| t.as_u64())
        .expect("report must carry total_results");
    assert!(
        total <= 1,
        "-k 1 must cap the report at one card; got total_results={total}"
    );

    // Plain (non-hyphen) queries keep taking the same positional path.
    let (stdout, stderr, code) = run(&["search", "port", root.to_str().unwrap(), "-f", "json"]);
    assert_eq!(
        code,
        Some(0),
        "plain query must keep working after the allow_hyphen_values change; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let files = result_files(&stdout, "plain query");
    assert!(
        files.iter().any(|f| f.ends_with("server.rs")),
        "plain 'port' query must find server.rs; got: {files:?}"
    );

    // Only `search`'s query positional allows hyphen values: another
    // command's flag-like positional argument is still a clap usage error.
    let (stdout, stderr, code) = run(&["structure", "--port", root.to_str().unwrap()]);
    assert_ne!(
        code,
        Some(0),
        "structure must keep rejecting a flag-like positional (only search opted in)"
    );
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert!(
        stderr_str.contains("unexpected argument"),
        "structure must fail with the clap usage error; got: {stderr_str}"
    );
    assert!(
        stdout.iter().all(|b| b.is_ascii_whitespace()),
        "clap usage errors must not leak onto stdout; got: {}",
        String::from_utf8_lossy(&stdout)
    );
}

/// `--help` / `--version` are still intercepted by clap even though the
/// query positional now allows hyphen values.
#[test]
fn issue13_help_still_intercepted_for_search() {
    let (stdout, stderr, code) = run(&["search", "--help"]);
    assert_eq!(
        code,
        Some(0),
        "search --help must still print help; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let help = String::from_utf8_lossy(&stdout);
    assert!(
        help.contains("Usage"),
        "search --help must render usage text; got: {}",
        help.chars().take(200).collect::<String>()
    );
}

/// Sanity: the fixture used above is a real, analyzable Rust tree (guards
/// against the suite silently degenerating into empty-report vacuity).
#[test]
fn fixture_is_indexed_by_search() {
    let tmp = TempDir::new().unwrap();
    let root = write_service_fixture(&tmp);

    let (stdout, stderr, code) = run(&["search", "serve", root.to_str().unwrap(), "-f", "json"]);
    assert_eq!(
        code,
        Some(0),
        "search over the fixture must succeed; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|e| panic!("stdout must parse as JSON: {e}"));
    let searched = report
        .get("total_files_searched")
        .and_then(|t| t.as_u64())
        .expect("report must carry total_files_searched");
    assert!(
        searched >= 6,
        "fixture must index all 6 rust files; got total_files_searched={searched}"
    );
}
