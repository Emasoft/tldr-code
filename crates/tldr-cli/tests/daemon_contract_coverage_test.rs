//! Daemon contract-coverage suite for issues #65–#68 (test-only ask W5b).
//!
//! Everything in this file is an in-process contract test: it binds a real
//! `IpcListener` on a per-test tempdir and drives `TLDRDaemon::run` on a
//! spawned task (the issue-#62 `cache clear` precedent). No OS daemon is
//! spawned, no fixed ports are used, no network is touched, and the task dies
//! with the test process — daemon hygiene is structural, not best-effort.
//!
//! # Coverage matrix (issue → requested contract → test)
//!
//! Legend: `[existing]` = test that already covered the contract when this
//! ask was audited (base `5d7c27c4`); `[new]` = test added here; `[gap]` =
//! documented feature gap (NOT testable without writing the feature or
//! pinning a bug as a contract).
//!
//! ## Issue #65 — search enrichment cache
//!
//! | Requested contract | Where it lives |
//! |---|---|
//! | Baseline daemon health (`status` reports running) | [existing] `issue83_daemon_language_test.rs::daemon_serves_rust_language_for_all_five_commands_without_explicit_lang`; [new] `daemon_test.rs::daemon_end_to_end_start_status_query_stop` |
//! | Repeated search avoids recomputing (daemon `Search` path) | [existing] `daemon_impl::tests::test_daemon_search_caches_result` (hits ≥ 1); [new] `repeat_search_hits_cache_and_different_patterns_do_not_cross_contaminate` (exact miss→hit→fresh-miss deltas + payload identity, via real IPC) |
//! | Search hit/miss externally observable (not timing) | [new] `search_stats_are_visible_through_the_status_response` (`FullStatus.salsa_stats` over IPC) |
//! | `tldr search` (enriched/callgraph) uses the daemon | [IMPLEMENTED — was a gap] `SmartSearchArgs::run` now routes through `try_daemon_route("enriched_search")` first; the daemon computes the SAME core `enriched_search` the CLI fallback calls (one code path — no drift) and memoizes the report keyed by every query-affecting parameter (root, query, mode, top_k, callgraph toggle, language) with project-root input hashes — enrichment is **daemon-backed** for the same result shape, **client-local** on any route failure. Tests: [new] `enriched_search_daemon_payload_matches_direct_compute_on_the_same_fixture` (parity pin), `repeat_enriched_search_hits_cache_and_query_params_do_not_cross_contaminate` (counters, not timing), `enriched_search_invalidation_cycle_reflects_file_edits_over_ipc` (edit → Notify → fresh), `enriched_search_cli_command_uses_the_running_daemon_cache` (the real CLI command, daemon up) |
//! | Search fallback visible when daemon is down | [IMPLEMENTED] `SmartSearchArgs::run` falls back to direct compute through the shared router choke point (issue #67 helper) — [new] `enriched_search_cli_command_falls_back_to_direct_compute_and_logs_when_daemon_is_down` (`fallback` line with `command: "enriched_search"` in daemon.log); the daemon-adjacent `daemon_test.rs::test_daemon_query_without_running_daemon_reports_clear_error` still covers the explicit-error surface |
//! | Search cache invalidation on file change (#51 root-hash) | FIXED by the #51 follow-up: the `Search` handler now registers the project-root input hashes like every other project-wide arm — [new] `search_invalidation_cycle_reflects_file_edits_over_ipc` (real-IPC search → edit → Notify → re-query cycle, plus the in-process pins `test_daemon_search_cache_invalidated_on_notify` and its Tree/Context/Structure/warmed-file-structure siblings in `daemon_impl::tests`) |
//!
//! ## Issue #66 — CLI command routing / daemon reuse
//!
//! | Requested contract | Where it lives |
//! |---|---|
//! | CLI commands route through a running daemon | [existing] `issue83_daemon_language_test.rs` (five commands against a REAL daemon); [existing] `daemon_payload_round_trip_test.rs` (the daemon payloads `calls`/`dead` decode — the precondition for reuse) |
//! | Same-file repeat request hits the cache | [new] `repeat_same_file_extract_hits_cache_while_a_different_file_misses` (exact deltas) |
//! | Different-file requests don't cross-contaminate | [same new test] file B is a fresh miss and its payload differs from A's |
//! | Repeated routed commands hit cache | [existing] `daemon_impl::tests::test_daemon_warm_wires_caches` (7 file-scoped commands all hits after warm); [new] the two repeat tests above |
//! | Source change → cached result invalidated, not stale | [existing] `test_daemon_calls_cache_invalidated_on_notify`, `test_daemon_impact_cache_invalidated_on_notify`, `test_daemon_warmed_call_graph_slot_invalidated_on_notify` (#51) and the four #59 spelling tests (`test_daemon_extract_notify_symlink_path_mismatch`, `test_daemon_extract_notify_relative_path_mismatch`, `test_daemon_notify_deleted_file_invalidates_via_raw_spelling`, `test_daemon_notify_canonical_path_control_and_no_over_invalidation`) |
//! | Daemon-unavailable fallback is explicit, not silent | [new] `daemon_test.rs::test_daemon_query_without_running_daemon_reports_clear_error`, `test_daemon_status_not_running`, `test_daemon_stop_not_running`, `test_daemon_notify_silent_when_not_running` |
//! | Daemon hit vs miss distinguishable | [new] `search_stats_are_visible_through_the_status_response` + `repeat_same_file_extract_hits_cache_while_a_different_file_misses` (counters, not timing) |
//!
//! ## Issue #67 — logging / observability contract
//!
//! | Requested contract | Where it lives |
//! |---|---|
//! | Cache hit/miss externally observable for daemon-cached commands | [new] `search_stats_are_visible_through_the_status_response`, `repeat_same_file_extract_hits_cache_while_a_different_file_misses`; [existing] CLI `cache stats` JSON (`test_cache_stats_json_output`) |
//! | Invalidation externally observable | [existing] `test_daemon_calls_cache_invalidated_on_notify` (asserts `stats().invalidations ≥ 1`); [new] same counter observed through the `Status` wire response |
//! | Errors are delivered with context, not swallowed; daemon stays live | [new] `error_responses_carry_context_over_ipc_and_daemon_stays_live`; [existing] `test_daemon_extract_nonexistent_file`, `test_daemon_diagnostics_returns_error_with_guidance` |
//! | Shutdown state observable (explicit stop) | [new] `graceful_shutdown_persists_observability_state_and_releases_the_socket` (converts the ignored `daemon_test.rs::test_daemon_graceful_shutdown_persists_stats` placeholder); [log] `daemon_log_records_request_response_lifecycle_and_shutdown_shape_over_ipc` (log distinguishes `shutdown_command` from `idle_timeout` and error exits) |
//! | Idle shutdown observable in a testable config | [new] `idle_timeout_self_terminates_the_daemon` (converts the ignored `test_daemon_idle_timeout` placeholder); [log] same test suite asserts the `idle_timeout` lifecycle line shape via the lib pins in `daemon_impl::tests` |
//! | Startup metadata: project/pid/socket persisted | [existing] registry + discovery records (`val003_daemon_registry_test.rs`, `daemon_active.rs` lib tests); [new] e2e start output carries `pid` + `socket` |
//! | Persistent `.tldr/cache/daemon.log` with per-request traces, slow/error markers, version metadata | [IMPLEMENTED — was a gap] `commands/daemon/logging.rs` writes append-only JSONL `{ts, pid, version, event, command, path?, duration_ms?, status, detail?}` next to `salsa_stats.json`, capped at `MAX_LOG_BYTES` (truncate-and-restart), best-effort (write failures counted, never fatal). Tests: `daemon_log_records_request_response_lifecycle_and_shutdown_shape_over_ipc`, `slow_marker_fires_when_the_threshold_is_injected`, `error_events_carry_request_context_in_the_log_over_ipc`, `log_is_truncated_when_it_exceeds_the_cap`, `status_response_exposes_log_path_and_log_size_bytes`, plus lib pins in `logging.rs` and `daemon_impl::tests` |
//! | Local fallback visibility | [IMPLEMENTED at the shared choke point] `try_daemon_route_async` appends a `fallback` line through the SAME shared helper (`logging::log_client_fallback`) — `client_fallback_is_logged_by_the_shared_router_helper`. Since issue #65 the enriched search routes through the same choke point, so its fallbacks land in the log too: `enriched_search_cli_command_falls_back_to_direct_compute_and_logs_when_daemon_is_down` |
//! | Cache hit/miss per line | [documented, out of scope] the log records per-request command/status/duration; hit/miss stays observable through `FullStatus.salsa_stats` (counters) — a `cache: hit|miss` log field would require threading per-request cache outcomes out of every handler arm (future work) |
//!
//! ## Issue #68 — ignored placeholder cleanup (lifecycle)
//!
//! Converted to active tests in `daemon_test.rs`: start/stop/status/query/notify/warm/stats
//! `--help` probes; `status`/`stop` not-running; `notify` without daemon;
//! query-without-daemon clear error; the five `warm` foreground tests; and one
//! real-binary end-to-end lifecycle test (`daemon_end_to_end_start_status_query_stop`)
//! covering start→status→double-start→ping→unknown-cmd→track→stop→status with
//! `TLDR_DAEMON_REGISTRY_DIR`/`TLDR_DAEMON_ACTIVE_DIR` env isolation and a drop
//! stop-guard (issue-#83 pattern).
//!
//! Converted to in-process tests here: graceful-shutdown persistence (was
//! `test_daemon_graceful_shutdown_persists_stats`), idle timeout (was
//! `test_daemon_idle_timeout`), track flush threshold (was
//! `test_track_flush_at_threshold`, whose old assertion was vacuous), and the
//! start/stop/query lifecycle core (`ipc_lifecycle_serves_ping_and_shuts_down`).
//!
//! Deleted placeholders (stale designs superseded by the above; full mapping in
//! `daemon_test.rs`): start-creates-socket, start-creates-pid-file,
//! start-already-running, status-returns-uptime, status-json-output,
//! query-roundtrip, notify-tracks-dirty-files, notify-reindex-threshold,
//! cache-stats-after-queries, cache-invalidation-on-file-change, stale-PID,
//! stale-socket, concurrent-start, permission-denied, unknown-command, track.
//!
//! Remaining `#[ignore]`s carry accurate current reasons: the semantic test
//! needs the feature-gated build, and the three `stats` file tests mutate the
//! real `~/.tldr/stats.jsonl` (needs a stats-path isolation hook).

#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use tldr_cli::commands::daemon::{
    check_socket_alive, send_command, DaemonCommand, DaemonConfig, DaemonResponse, DaemonResult,
    IpcListener, TLDRDaemon,
};
use tldr_cli::commands::SmartSearchArgs;
use tldr_cli::output::OutputFormat;
use tldr_core::{
    enriched_search as direct_enriched_search, EnrichedSearchOptions, EnrichedSearchReport,
    Language, SearchMode,
};

/// A deterministic two-file Python project with one call edge (main → helper).
fn write_python_project(dir: &Path) {
    std::fs::write(
        dir.join("main.py"),
        "from utils import helper\n\n\ndef main():\n    helper()\n",
    )
    .expect("write main.py");
    std::fs::write(dir.join("utils.py"), "def helper():\n    return 'help'\n")
        .expect("write utils.py");
}

/// Canonicalized project tempdir: the socket path hashes the canonical
/// spelling (macOS resolves `/var` → `/private/var`), so daemon and clients
/// must agree on the same one.
fn project_dir(prefix: &str) -> TempDir {
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("project tempdir");
    // canonicalize() materializes the same directory at its resolved path;
    // TempDir keeps ownership of the original, which IS the resolved path on
    // macOS after canonicalization of a symlink-free /tmp entry.
    let canonical = temp.path().canonicalize().expect("canonicalize project");
    // Write a marker through the canonical spelling so it definitely exists.
    std::fs::write(canonical.join(".project-root"), "daemon-contract-suite").expect("marker");
    temp
}

/// Spawn `TLDRDaemon::run` over a freshly bound IPC listener for `project`
/// and wait (bounded) until the socket is connectable. Mirrors the
/// issue-#62 in-process precedent: no OS process, nothing to clean up.
async fn start_in_process_daemon(
    project: &Path,
    config: DaemonConfig,
) -> tokio::task::JoinHandle<DaemonResult<()>> {
    start_prebuilt_daemon(project, TLDRDaemon::new(project.to_path_buf(), config)).await
}

/// Variant of [`start_in_process_daemon`] that takes an already-constructed
/// (possibly customized) daemon — the hook the #67 slow-threshold test uses
/// to inject `with_slow_request_ms(0)` without sleeps.
async fn start_prebuilt_daemon(
    project: &Path,
    daemon: TLDRDaemon,
) -> tokio::task::JoinHandle<DaemonResult<()>> {
    let listener = IpcListener::bind(project)
        .await
        .expect("IPC listener bind on a fresh tempdir must succeed");
    let handle = tokio::spawn(async move { Arc::new(daemon).run(listener).await });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !check_socket_alive(project).await {
        assert!(
            Instant::now() < deadline,
            "in-process daemon socket never became connectable"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    handle
}

fn default_config() -> DaemonConfig {
    DaemonConfig::default()
}

// =============================================================================
// Issue #68 — lifecycle core, in-process (start = bind+run, stop = Shutdown,
// query = Ping over the real IPC transport)
// =============================================================================

/// The daemon serve loop answers a real IPC `Ping`, and after a `Shutdown`
/// command it exits, releases the socket (no longer connectable) and the
/// join handle resolves. This is the start/query/stop lifecycle exercised
/// through the exact `TLDRDaemon::run` path the `tldr-daemon` runner uses.
#[tokio::test]
async fn ipc_lifecycle_serves_ping_and_shuts_down() {
    let temp = project_dir("dc-lifecycle-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    // Query: ping round-trip over the real socket.
    let pong = send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("ping must round-trip while the daemon is running");
    match pong {
        DaemonResponse::Status { status, message } => {
            assert_eq!(status, "ok");
            assert_eq!(message.as_deref(), Some("pong"));
        }
        other => panic!("expected Status response for ping, got {:?}", other),
    }

    // Stop: the explicit Shutdown command must terminate the loop.
    let ack = send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown must be acknowledged");
    match ack {
        DaemonResponse::Status { status, .. } => assert_eq!(status, "shutting_down"),
        other => panic!("expected Status response for shutdown, got {:?}", other),
    }

    let joined = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon must exit after an explicit Shutdown command");
    joined
        .expect("run task must not panic")
        .expect("run must return Ok on a graceful shutdown");

    assert!(
        !check_socket_alive(&project).await,
        "socket must no longer be connectable after shutdown"
    );
}

/// Issue #67 / #68: an explicit-stop shutdown persists the observability
/// state (`salsa_stats.json` with hit/miss/invalidation counters, plus the
/// full `query_cache.bin`) so the session's cache behaviour survives for
/// later inspection. Converts the ignored `test_daemon_graceful_shutdown_
/// persists_stats` placeholder, whose "not yet implemented" reason expired.
#[tokio::test]
async fn graceful_shutdown_persists_observability_state_and_releases_the_socket() {
    let temp = project_dir("dc-shutdown-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    // Generate exactly one observable miss+hit pair before shutting down.
    for _ in 0..2 {
        let response = send_command(
            &project,
            &DaemonCommand::Search {
                pattern: "def main".to_string(),
                max_results: Some(10),
            },
        )
        .await
        .expect("search round-trip");
        assert!(
            matches!(response, DaemonResponse::Result(_)),
            "search must succeed, got {:?}",
            response
        );
    }

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");

    let stats_path = project.join(".tldr").join("cache").join("salsa_stats.json");
    let raw = std::fs::read_to_string(&stats_path).expect(
        "graceful shutdown must persist salsa_stats.json (the daemon's external \
         hit/miss/invalidation record)",
    );
    let stats: serde_json::Value = serde_json::from_str(&raw).expect("valid stats JSON");
    assert_eq!(
        stats["hits"], 1,
        "second identical search must be a hit: {raw}"
    );
    assert_eq!(stats["misses"], 1, "first search must be a miss: {raw}");
    assert_eq!(
        stats["invalidations"], 0,
        "no invalidation happened in this session: {raw}"
    );
    assert!(
        project
            .join(".tldr")
            .join("cache")
            .join("query_cache.bin")
            .exists(),
        "the full query cache must also be persisted on shutdown"
    );
}

/// Issue #68: the idle-timeout contract, in a testable configuration. With
/// `idle_timeout_secs: 1` and NO client activity the daemon self-terminates
/// (no Shutdown command is ever sent). Converts the ignored
/// `test_daemon_idle_timeout` placeholder, which only documented the
/// behaviour in comments.
///
/// Issue #67 extension: the idle exit must also be visible in the
/// persistent log as an `idle_timeout` lifecycle line, distinguishable
/// from the explicit-stop `shutdown_command` line.
#[tokio::test]
async fn idle_timeout_self_terminates_the_daemon() {
    let temp = project_dir("dc-idle-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let config = DaemonConfig {
        idle_timeout_secs: 1,
        ..DaemonConfig::default()
    };
    let handle = start_in_process_daemon(&project, config).await;

    // No client sends anything after readiness. The run loop polls idle
    // state every ~100ms, so 10s is a generous, non-timing-sensitive bound.
    let joined = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon must self-terminate after the idle timeout");
    joined
        .expect("run task must not panic")
        .expect("run must return Ok on an idle self-termination");

    assert!(
        !check_socket_alive(&project).await,
        "an idle-shut-down daemon must not accept connections"
    );

    // The log reconstructs the session: started → idle_timeout → stopped,
    // with NO shutdown_command line (no explicit stop ever happened).
    let raw = std::fs::read_to_string(tldr_cli::commands::daemon::daemon_log_path(&project))
        .expect("an idle self-termination must still leave the persistent log");
    let log: Vec<serde_json::Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect();
    let lifecycle_details: Vec<&str> = log
        .iter()
        .filter(|l| l["event"] == "lifecycle")
        .filter_map(|l| l["detail"].as_str())
        .collect();
    assert!(
        lifecycle_details
            .iter()
            .any(|d| d.starts_with("idle_timeout")),
        "the idle exit must be logged as an idle_timeout lifecycle line: {lifecycle_details:?}"
    );
    assert!(
        lifecycle_details.contains(&"started") && lifecycle_details.contains(&"stopped"),
        "the session must open and close in the log: {lifecycle_details:?}"
    );
    assert!(
        !lifecycle_details
            .iter()
            .any(|d| d.starts_with("shutdown_command")),
        "an idle exit must not be recorded as an explicit stop: {lifecycle_details:?}"
    );
}

// =============================================================================
// Issue #67 — counters are externally observable (stable fields, no timing)
// =============================================================================

/// The `Status` wire response must expose the salsa hit/miss/invalidation
/// counters (`FullStatus.salsa_stats`) — the external, timing-free signal
/// issues #65/#66/#67 all rely on to distinguish daemon hit vs miss. Exact
/// counts pin that each handler performs exactly one cache lookup.
#[tokio::test]
async fn search_stats_are_visible_through_the_status_response() {
    let temp = project_dir("dc-stats-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    // One miss (fresh pattern), one hit (identical repeat), one fresh miss
    // (different pattern). Exactly three cache lookups, no notify.
    let run_search = |pattern: &'static str| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Search {
                    pattern: pattern.to_string(),
                    max_results: Some(10),
                },
            )
            .await
        }
    };

    let first = run_search("def main").await.expect("first search");
    assert!(matches!(first, DaemonResponse::Result(_)), "got {first:?}");
    let second = run_search("def main").await.expect("repeat search");
    assert!(
        matches!(second, DaemonResponse::Result(_)),
        "got {second:?}"
    );
    let third = run_search("class Nowhere").await.expect("other search");
    assert!(matches!(third, DaemonResponse::Result(_)), "got {third:?}");

    let status = send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip");
    let salsa = match status {
        DaemonResponse::FullStatus { salsa_stats, .. } => salsa_stats,
        other => panic!("expected FullStatus response, got {:?}", other),
    };
    assert_eq!(
        (salsa.misses, salsa.hits, salsa.invalidations),
        (2, 1, 0),
        "exactly one miss, one repeat hit, one fresh-pattern miss, zero \
         invalidations — observed through the Status wire response"
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// Issue #67: invalidations are visible through the same external counter.
/// A Notify for a file whose hashes back real cache entries must move
/// `invalidations` on the `Status` response — the external counterpart of
/// the in-process #51/#59 invalidation tests.
#[tokio::test]
async fn notify_invalidation_is_visible_through_the_status_response() {
    let temp = project_dir("dc-invalidate-");
    let project = temp.path().canonicalize().unwrap();
    let utils = project.join("utils.py");
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    // Populate a file-scoped slot (extract registers this file's input
    // hashes — the dependency edge invalidation walks).
    let extract = |file: std::path::PathBuf| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Extract {
                    file,
                    session: None,
                },
            )
            .await
        }
    };
    let populated = extract(utils.clone()).await.expect("extract round-trip");
    assert!(
        matches!(populated, DaemonResponse::Result(_)),
        "extract must succeed, got {populated:?}"
    );
    let salsa_before = match send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip")
    {
        DaemonResponse::FullStatus { salsa_stats, .. } => salsa_stats,
        other => panic!("expected FullStatus, got {other:?}"),
    };

    // File change event for the same file.
    let notify = send_command(
        &project,
        &DaemonCommand::Notify {
            file: utils.clone(),
        },
    )
    .await
    .expect("notify round-trip");
    match notify {
        DaemonResponse::NotifyResponse {
            status,
            dirty_count,
            ..
        } => {
            assert_eq!(status, "ok");
            assert_eq!(dirty_count, 1);
        }
        other => panic!("expected NotifyResponse, got {other:?}"),
    }

    let salsa_after = match send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip")
    {
        DaemonResponse::FullStatus { salsa_stats, .. } => salsa_stats,
        other => panic!("expected FullStatus, got {other:?}"),
    };
    assert!(
        salsa_after.invalidations > salsa_before.invalidations,
        "a notify for a file backing real cache entries must move the \
         externally visible invalidation counter (before: {}, after: {})",
        salsa_before.invalidations,
        salsa_after.invalidations
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

// =============================================================================
// Issue #65 — daemon `Search` cache contract (miss → hit, slot separation)
// =============================================================================

/// A repeat search is served from the cache (hit counter moves, payload is
/// byte-identical) while a different pattern is a fresh miss producing a
/// different payload — the daemon `Search` reuse contract without any
/// timing assertion. (This pins the daemon's plain `Search` command; the
/// CLI enriched-search command has its OWN daemon route and contract tests
/// since issue #65 — see the enriched-search section below.)
#[tokio::test]
async fn repeat_search_hits_cache_and_different_patterns_do_not_cross_contaminate() {
    let temp = project_dir("dc-search-");
    let project = temp.path().canonicalize().unwrap();
    // Two files whose contents share no tokens, so a match for one pattern
    // cannot legitimately appear in the other's result set.
    std::fs::write(
        project.join("search_a.py"),
        "def alphafn():\n    return 1\n",
    )
    .expect("write search_a.py");
    std::fs::write(project.join("search_b.py"), "def betafn():\n    return 2\n")
        .expect("write search_b.py");

    let handle = start_in_process_daemon(&project, default_config()).await;

    let search = |pattern: &'static str| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Search {
                    pattern: pattern.to_string(),
                    max_results: Some(10),
                },
            )
            .await
        }
    };

    let first = match search("alphafn").await.expect("first search") {
        DaemonResponse::Result(v) => v,
        other => panic!("first search must return a Result, got {other:?}"),
    };
    let repeat = match search("alphafn").await.expect("repeat search") {
        DaemonResponse::Result(v) => v,
        other => panic!("repeat search must return a Result, got {other:?}"),
    };
    let other = match search("betafn").await.expect("other search") {
        DaemonResponse::Result(v) => v,
        other => panic!("other search must return a Result, got {other:?}"),
    };

    // Repeat is served from the slot: identical payload.
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&repeat).unwrap(),
        "the repeat search must be served the cached payload unchanged"
    );
    // Different pattern is a genuinely different result — no slot bleeding.
    assert_ne!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&other).unwrap(),
        "a different pattern must not be served the first pattern's cached \
         payload"
    );
    let first_str = serde_json::to_string(&first).unwrap();
    let other_str = serde_json::to_string(&other).unwrap();
    assert!(
        first_str.contains("alphafn") && !first_str.contains("betafn"),
        "the alphafn query must only surface alphafn, got {first_str}"
    );
    assert!(
        other_str.contains("betafn") && !other_str.contains("alphafn"),
        "the betafn query must only surface betafn — a cached slot for a \
         different pattern must never leak in, got {other_str}"
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// Issue #51 follow-up (W5b coverage audit): the full search invalidation
/// cycle over the real IPC transport — search → edit the file → Notify →
/// re-query. The pre-fix `Search` handler cached with an EMPTY dependency
/// list, so Notify could never reach the slot and the stale result survived
/// the edit forever (the [gap] row in the coverage matrix above documented
/// exactly this before the fix). Mirrors the #51 test shape
/// (`test_daemon_calls_cache_invalidated_on_notify`) at the wire level.
///
/// CONTROL (documented, not pinned): search registers the PROJECT ROOT's
/// input hashes — a search scans every file, so no single-file dependency
/// can describe it. At that granularity ANY file edit drops ALL project-wide
/// slots for the project (including search slots for unrelated patterns);
/// the cache cannot distinguish an "unrelated" edit, by design — the same
/// conservative-never-stale tradeoff every #51 project-wide arm made. The
/// file-scoped no-over-invalidation control stays pinned by
/// `test_daemon_notify_canonical_path_control_and_no_over_invalidation`.
#[tokio::test]
async fn search_invalidation_cycle_reflects_file_edits_over_ipc() {
    let temp = project_dir("dc-search-inval-");
    let project = temp.path().canonicalize().unwrap();
    // Two files whose contents share no tokens, so a removed token cannot
    // legitimately appear in any fresh result set.
    let search_a = project.join("search_a.py");
    std::fs::write(&search_a, "def alphafn():\n    return 1\n").expect("write search_a.py");
    std::fs::write(project.join("search_b.py"), "def betafn():\n    return 2\n")
        .expect("write search_b.py");

    let handle = start_in_process_daemon(&project, default_config()).await;

    let search = |pattern: &'static str| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Search {
                    pattern: pattern.to_string(),
                    max_results: Some(10),
                },
            )
            .await
        }
    };

    // 1. Populate the slot (miss) and prove it is served from cache (hit,
    //    identical payload) BEFORE the edit.
    let first = match search("alphafn").await.expect("first search") {
        DaemonResponse::Result(v) => v,
        other => panic!("first search must return a Result, got {other:?}"),
    };
    let repeat = match search("alphafn").await.expect("repeat search") {
        DaemonResponse::Result(v) => v,
        other => panic!("repeat search must return a Result, got {other:?}"),
    };
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&repeat).unwrap(),
        "precondition: the repeat search must be a cache hit"
    );

    // 2. Edit the file: the token disappears from the project entirely.
    std::fs::write(&search_a, "def gammafn():\n    return 1\n").expect("edit search_a.py");

    // 3. Notify over IPC.
    let notify = send_command(
        &project,
        &DaemonCommand::Notify {
            file: search_a.clone(),
        },
    )
    .await
    .expect("notify round-trip");
    match notify {
        DaemonResponse::NotifyResponse { status, .. } => assert_eq!(status, "ok"),
        other => panic!("expected NotifyResponse, got {other:?}"),
    }

    // 4. Re-query the SAME pattern — must be recomputed and must not
    //    surface the removed token (pre-fix: stale cached HIT).
    let after = match search("alphafn").await.expect("post-notify search") {
        DaemonResponse::Result(v) => v,
        other => panic!("post-notify search must return a Result, got {other:?}"),
    };
    let after_str = serde_json::to_string(&after).unwrap();
    assert!(
        !after_str.contains("alphafn"),
        "after Notify the re-queried search must not surface the removed \
         token — a stale cached result was served (issue #51 follow-up): \
         {after_str}"
    );

    // 5. The renamed token must be findable (fresh-compute sanity).
    let renamed = match search("gammafn").await.expect("renamed-token search") {
        DaemonResponse::Result(v) => v,
        other => panic!("renamed-token search must return a Result, got {other:?}"),
    };
    let renamed_str = serde_json::to_string(&renamed).unwrap();
    assert!(
        renamed_str.contains("gammafn") && !renamed_str.contains("alphafn"),
        "the renamed token must be findable after the edit + Notify, got \
         {renamed_str}"
    );

    // 6. The cycle must be externally observable: at least one invalidation
    //    moved the counter.
    let status = send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip");
    match status {
        DaemonResponse::FullStatus { salsa_stats, .. } => assert!(
            salsa_stats.invalidations >= 1,
            "the Notify must have invalidated at least one cache entry \
             (observed through the Status wire response), got {}",
            salsa_stats.invalidations
        ),
        other => panic!("expected FullStatus response, got {:?}", other),
    }

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

// =============================================================================
// Issue #65 — enriched search daemon route (CLI `tldr search`)
// =============================================================================
//
// The CLI enriched search (`SmartSearchArgs::run`) used to compute strictly
// client-local: the BM25 index was rebuilt over the project on EVERY
// invocation. Since the route landed, the daemon computes the SAME core
// `enriched_search` (one code path — no drift) and memoizes the report keyed
// by every query-affecting parameter with project-root input hashes.
// These tests pin that contract over the real IPC transport.

/// A deterministic two-file Python project with one call edge
/// (alpha_caller → alpha_search_fn) so call-graph enrichment has content.
fn write_enriched_fixture(dir: &Path) {
    std::fs::write(
        dir.join("alpha.py"),
        "def alpha_search_fn():\n    return 1\n\n\ndef alpha_caller():\n    alpha_search_fn()\n",
    )
    .expect("write alpha.py");
    std::fs::write(dir.join("beta.py"), "def beta_other_fn():\n    return 2\n")
        .expect("write beta.py");
}

/// Deterministic view of an enriched report for parity comparison:
///
/// 1. Cards are sorted by (file, name, line_start) — the pipeline's dedup
///    map does not guarantee card ORDER across two identical
///    recomputations.
/// 2. Scores are quantized to 10 decimal places — BM25 accumulates
///    per-term scores in HashMap iteration order (randomly seeded per index
///    build), so two fresh computations of the SAME query can differ by one
///    ulp (~1e-15 relative). This is pre-existing core behavior, not route
///    drift: a direct-vs-direct comparison differs the same way. The
///    daemon-side cache makes repeat queries byte-identical (pinned by
///    `repeat_enriched_search_hits_cache_...`); parity here pins identical
///    cards/fields/enrichment with fp-reassembly tolerance on scores.
fn normalized_report(report: &EnrichedSearchReport) -> EnrichedSearchReport {
    let mut r = report.clone();
    r.results.sort_by(|a, b| {
        (&a.file, &a.name, a.line_range.0).cmp(&(&b.file, &b.name, b.line_range.0))
    });
    for card in &mut r.results {
        card.score = (card.score * 1e10).round() / 1e10;
    }
    r
}

/// Wire params for one enriched-search request against `project`.
fn enriched_request(
    project: &Path,
    query: &str,
    top_k: usize,
    include_callgraph: bool,
) -> DaemonCommand {
    DaemonCommand::EnrichedSearch {
        query: query.to_string(),
        root: Some(project.to_path_buf()),
        language: Some(Language::Python),
        top_k: Some(top_k),
        include_callgraph: Some(include_callgraph),
        search_mode: SearchMode::default(),
    }
}

/// (a) PARITY PIN: the daemon's enriched-search payload and a direct
/// `enriched_search` call on the same fixture are the same report — same
/// shape (`query`/`results`/`total_results`/`total_files_searched`/
/// `search_mode`), same cards, same enrichment (the callgraph card carries
/// its caller). The daemon handler calls the exact core function the CLI
/// fallback calls, so any drift between daemon-mode and direct-mode output
/// is a regression this test catches. (Scores compare at fp-reassembly
/// tolerance — see `normalized_report`; card order is normalized too.)
#[tokio::test]
async fn enriched_search_daemon_payload_matches_direct_compute_on_the_same_fixture() {
    let temp = project_dir("dc-enrich-parity-");
    let project = temp.path().canonicalize().unwrap();
    write_enriched_fixture(&project);

    // Direct compute — the EXACT call the CLI's direct-compute path makes.
    let direct = direct_enriched_search(
        "alpha_search_fn",
        &project,
        Language::Python,
        EnrichedSearchOptions {
            top_k: 10,
            include_callgraph: true,
            search_mode: SearchMode::default(),
        },
    )
    .expect("direct enriched search");
    assert!(
        !direct.results.is_empty(),
        "fixture sanity: the query must match the fixture"
    );

    let handle = start_in_process_daemon(&project, default_config()).await;

    let response = send_command(
        &project,
        &enriched_request(&project, "alpha_search_fn", 10, true),
    )
    .await
    .expect("enriched_search round-trip");

    let value = match response {
        DaemonResponse::Result(value) => value,
        DaemonResponse::Error { error, .. } => {
            panic!("EnrichedSearch handler errored on a valid project: {error}")
        }
        other => panic!("expected a Result response, got {other:?}"),
    };

    // Wire shape pin: the report fields a client (the CLI writer included)
    // depends on must all be present.
    for key in [
        "query",
        "results",
        "total_results",
        "total_files_searched",
        "search_mode",
    ] {
        assert!(
            value.get(key).is_some(),
            "enriched payload must carry `{key}`; got {value}"
        );
    }
    assert_eq!(
        value["total_results"],
        value["results"].as_array().expect("results array").len()
    );

    // THE parity pin: the wire payload decodes into the report type and is
    // the same report direct compute produced.
    let wire: EnrichedSearchReport = serde_json::from_value(value).expect(
        "the daemon's enriched payload must deserialize into EnrichedSearchReport — \
         a failure here means `tldr search` can never use the daemon cache",
    );
    assert_eq!(
        serde_json::to_string(&normalized_report(&wire)).unwrap(),
        serde_json::to_string(&normalized_report(&direct)).unwrap(),
        "daemon-mode enriched search must equal direct compute on the same fixture"
    );

    // Enrichment sanity: the matched card is callgraph-enriched (its caller
    // from the fixture's call edge is attached), proving the daemon path
    // runs the FULL enriched pipeline, not a bare match list.
    let card = wire
        .results
        .iter()
        .find(|c| c.name == "alpha_search_fn")
        .expect("the matched function card must be present");
    assert!(
        card.callers.iter().any(|c| c == "alpha_caller"),
        "the alpha_search_fn card must carry its fixture caller via callgraph \
         enrichment, got callers={:?}",
        card.callers
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// (b) CACHE-HIT PIN + cache-key separation: an identical repeat is served
/// from the slot (hit counter moves, payload byte-identical), while a
/// request differing ONLY in `top_k` or in the callgraph toggle is a fresh
/// miss — every query-affecting parameter is part of the cache key, so no
/// param-shape can be served another param-shape's slot. Counters (exact
/// deltas through the Status response) make this a state assertion, not a
/// timing one.
#[tokio::test]
async fn repeat_enriched_search_hits_cache_and_query_params_do_not_cross_contaminate() {
    let temp = project_dir("dc-enrich-hit-");
    let project = temp.path().canonicalize().unwrap();
    write_enriched_fixture(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let run = |query: &'static str, top_k: usize, cg: bool| {
        let project = project.clone();
        async move { send_command(&project, &enriched_request(&project, query, top_k, cg)).await }
    };

    // 1st: miss. "alpha" matches both alpha.py functions → ≥ 2 cards, so a
    // top_k=1 request below has genuinely different content to serve.
    let first = match run("alpha", 10, true).await.expect("first query") {
        DaemonResponse::Result(v) => v,
        other => panic!("first query must return a Result, got {other:?}"),
    };
    assert!(
        first["results"].as_array().expect("results").len() >= 2,
        "fixture sanity: 'alpha' must match at least two cards, got {first}"
    );
    // 2nd: identical repeat → hit.
    let repeat = match run("alpha", 10, true).await.expect("repeat query") {
        DaemonResponse::Result(v) => v,
        other => panic!("repeat query must return a Result, got {other:?}"),
    };
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&repeat).unwrap(),
        "the identical repeat must be served the cached payload unchanged"
    );
    // 3rd: same query, top_k=1 → FRESH slot (truncated payload).
    let top1 = match run("alpha", 1, true).await.expect("top_k=1 query") {
        DaemonResponse::Result(v) => v,
        other => panic!("top_k=1 query must return a Result, got {other:?}"),
    };
    assert_eq!(
        top1["results"].as_array().expect("results").len(),
        1,
        "top_k must be honored: got {top1}"
    );
    // 4th: same query/limit, callgraph OFF → FRESH slot (no callers).
    let nocg = match run("alpha", 10, false).await.expect("no-callgraph query") {
        DaemonResponse::Result(v) => v,
        other => panic!("no-callgraph query must return a Result, got {other:?}"),
    };
    let cards = nocg["results"].as_array().expect("results");
    assert!(
        cards.iter().all(|c| c["callers"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true)),
        "a no-callgraph request must not be served the callgraph-enriched slot: {nocg}"
    );

    // Counter pin: exactly misses=3 (fresh query, top_k, no-cg) + hits=1
    // (identical repeat), zero invalidations.
    let status = send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip");
    match status {
        DaemonResponse::FullStatus { salsa_stats, .. } => assert_eq!(
            (
                salsa_stats.misses,
                salsa_stats.hits,
                salsa_stats.invalidations
            ),
            (3, 1, 0),
            "cache-key separation must show up as exact counter deltas"
        ),
        other => panic!("expected FullStatus response, got {:?}", other),
    }

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// (c) CACHE CORRECTNESS: enriched results must reflect file edits — the
/// query → edit → Notify → re-query cycle over the real IPC transport.
/// The handler registers the project ROOT's input hashes (conservative
/// never-stale: ANY file edit drops ALL project-wide slots, the same
/// tradeoff every #51 project-wide arm made), so the renamed token must
/// appear and the removed token must vanish.
#[tokio::test]
async fn enriched_search_invalidation_cycle_reflects_file_edits_over_ipc() {
    let temp = project_dir("dc-enrich-inval-");
    let project = temp.path().canonicalize().unwrap();
    let alpha = project.join("alpha.py");
    write_enriched_fixture(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let run = |query: &'static str| {
        let project = project.clone();
        async move { send_command(&project, &enriched_request(&project, query, 10, true)).await }
    };

    // 1. Populate: the original token is found, and the repeat is a HIT.
    let first = match run("alpha_search_fn").await.expect("first query") {
        DaemonResponse::Result(v) => v,
        other => panic!("first query must return a Result, got {other:?}"),
    };
    let first_str = serde_json::to_string(&first).unwrap();
    assert!(
        first_str.contains("alpha_search_fn"),
        "precondition: the original token must be found, got {first_str}"
    );
    let repeat = match run("alpha_search_fn").await.expect("repeat query") {
        DaemonResponse::Result(v) => v,
        other => panic!("repeat query must return a Result, got {other:?}"),
    };
    assert_eq!(
        first_str,
        serde_json::to_string(&repeat).unwrap(),
        "precondition: the repeat must be a cache hit"
    );

    // 2. Edit: the token is renamed project-wide.
    std::fs::write(
        &alpha,
        "def gammafn():\n    return 1\n\n\ndef gamma_caller():\n    gammafn()\n",
    )
    .expect("edit alpha.py");

    // 3. Notify over IPC.
    let notify = send_command(
        &project,
        &DaemonCommand::Notify {
            file: alpha.clone(),
        },
    )
    .await
    .expect("notify round-trip");
    match notify {
        DaemonResponse::NotifyResponse { status, .. } => assert_eq!(status, "ok"),
        other => panic!("expected NotifyResponse, got {other:?}"),
    }

    // 4. Re-query the OLD token: the slot must have been dropped. A stale
    //    hit would still surface the pre-edit card; a fresh compute finds
    //    nothing (the token is gone from the project).
    let stale_check = match run("alpha_search_fn").await.expect("stale check") {
        DaemonResponse::Result(v) => v,
        other => panic!("stale check must return a Result, got {other:?}"),
    };
    let stale_cards = serde_json::to_string(&stale_check["results"]).unwrap();
    assert_eq!(
        stale_cards, "[]",
        "after Notify the re-queried search must not surface the removed \
         token — a stale cached result was served: {stale_cards}"
    );

    // 5. The renamed token must be findable (fresh-compute sanity).
    let renamed = match run("gammafn").await.expect("renamed query") {
        DaemonResponse::Result(v) => v,
        other => panic!("renamed query must return a Result, got {other:?}"),
    };
    let renamed_str = serde_json::to_string(&renamed).unwrap();
    assert!(
        renamed_str.contains("gammafn") && !renamed_str.contains("alpha_search_fn"),
        "the renamed token must be found after the edit + Notify, got {renamed_str}"
    );

    // 6. Externally observable: at least one invalidation moved the counter.
    let status = send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip");
    match status {
        DaemonResponse::FullStatus { salsa_stats, .. } => assert!(
            salsa_stats.invalidations >= 1,
            "the Notify must have invalidated at least one enriched-search \
             entry (observed through the Status wire response), got {}",
            salsa_stats.invalidations
        ),
        other => panic!("expected FullStatus response, got {:?}", other),
    }

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// (d) FALLBACK, at the CLI-command level: with the daemon DOWN, the REAL
/// `SmartSearchArgs::run` must still succeed (direct compute — behavior
/// unchanged from before the route existed) AND the failed route must leave
/// the issue-#67 `fallback` line in the project's daemon.log (the fallback
/// is never silent).
///
/// Plain `#[test]` (not `#[tokio::test]`): the CLI command builds its own
/// blocking runtime for the route attempt, which must not run inside another
/// runtime's worker context. Daemon lifecycle phases are block_on'd on this
/// test-owned runtime; the CLI runs happen between them, outside it.
#[test]
fn enriched_search_cli_command_falls_back_to_direct_compute_and_logs_when_daemon_is_down() {
    let temp = project_dir("dc-enrich-fb-");
    let project = temp.path().canonicalize().unwrap();
    write_enriched_fixture(&project);

    let rt = tokio::runtime::Runtime::new().expect("test runtime");

    // Phase 1: a daemon ran once (so the persistent log exists), then stopped.
    rt.block_on(async {
        let handle = start_in_process_daemon(&project, default_config()).await;
        send_command(&project, &DaemonCommand::Shutdown)
            .await
            .expect("shutdown acknowledged");
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("daemon exits after shutdown")
            .expect("run task must not panic")
            .expect("graceful shutdown returns Ok");
        assert!(
            !check_socket_alive(&project).await,
            "precondition: the daemon is down"
        );
    });

    // Phase 2: the REAL CLI command with the daemon down — direct compute.
    let args = SmartSearchArgs {
        query: "alpha_search_fn".to_string(),
        path: project.clone(),
        lang: Some(Language::Python),
        top_k: 10,
        no_callgraph: true,
        regex: false,
        hybrid: None,
    };
    args.run(OutputFormat::Json, true)
        .expect("fallback direct compute must succeed with the daemon down");

    // Phase 3: the fallback is visible in the shared project log.
    let log = read_log(&project);
    let fallbacks: Vec<&serde_json::Value> = log
        .iter()
        .filter(|l| l["event"] == "fallback" && l["command"] == "enriched_search")
        .collect();
    assert_eq!(
        fallbacks.len(),
        1,
        "the failed enriched-search route must leave exactly one fallback line: {log:?}"
    );
    let detail = fallbacks[0]["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("daemon"),
        "the fallback line says WHY the daemon route failed: {detail}"
    );
}

/// (d, cont.) ROUTE PROOF at the CLI-command level: with a daemon RUNNING
/// for the project, two identical `SmartSearchArgs::run` invocations move
/// the daemon's salsa counters (1 miss + 1 hit) — the only way those
/// counters move is through the daemon's query cache, so this pins that the
/// CLI command actually routes (and that the route caches), not merely that
/// some payload shape decodes.
#[test]
fn enriched_search_cli_command_uses_the_running_daemon_cache() {
    let temp = project_dir("dc-enrich-cli-");
    let project = temp.path().canonicalize().unwrap();
    write_enriched_fixture(&project);

    let rt = tokio::runtime::Runtime::new().expect("test runtime");
    rt.block_on(async {
        start_in_process_daemon(&project, default_config()).await;
    });

    let args = SmartSearchArgs {
        query: "alpha_search_fn".to_string(),
        path: project.clone(),
        lang: Some(Language::Python),
        top_k: 10,
        no_callgraph: false,
        regex: false,
        hybrid: None,
    };
    args.run(OutputFormat::Json, true)
        .expect("first CLI search must succeed through the daemon route");
    args.run(OutputFormat::Json, true)
        .expect("second CLI search must succeed through the daemon route");

    rt.block_on(async {
        let status = send_command(&project, &DaemonCommand::Status { session: None })
            .await
            .expect("status round-trip");
        match status {
            DaemonResponse::FullStatus { salsa_stats, .. } => assert_eq!(
                (salsa_stats.misses, salsa_stats.hits),
                (1, 1),
                "two identical CLI searches against a running daemon must be \
                 exactly one miss (compute) + one hit (cache) — anything else \
                 means the CLI command is not routing through the daemon"
            ),
            other => panic!("expected FullStatus response, got {:?}", other),
        }

        send_command(&project, &DaemonCommand::Shutdown)
            .await
            .expect("shutdown acknowledged");
        // (The socket-release and join-handle contract is pinned by
        // `ipc_lifecycle_serves_ping_and_shuts_down`; not re-asserted here.)
    });

    // Dropping the runtime ends the in-process daemon task — structural
    // hygiene: no lingering process or socket outside the test.
    drop(rt);
}

// =============================================================================
// Issue #66 — same-file reuse vs different-file isolation, via real IPC
// =============================================================================

/// The file-scoped reuse contract: a repeat request for the SAME file is a
/// cache hit, while a request for a DIFFERENT file is a fresh miss whose
/// payload reflects its own content — two files never cross-contaminate.
/// Counters (exact deltas through the Status response) make this a state
/// assertion, not a timing one.
#[tokio::test]
async fn repeat_same_file_extract_hits_cache_while_a_different_file_misses() {
    let temp = project_dir("dc-extract-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);
    let file_a = project.join("main.py"); // defines main
    let file_b = project.join("utils.py"); // defines helper

    let handle = start_in_process_daemon(&project, default_config()).await;

    let extract = |file: std::path::PathBuf| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Extract {
                    file,
                    session: None,
                },
            )
            .await
        }
    };

    // 1st request for A: miss. 2nd request for A: hit. 1st request for B:
    // fresh miss. Exactly three lookups.
    let a1 = extract(file_a.clone()).await.expect("extract A");
    let a1 = match a1 {
        DaemonResponse::Result(v) => v,
        other => panic!("extract A must succeed, got {other:?}"),
    };
    let a2 = extract(file_a.clone()).await.expect("extract A repeat");
    let a2 = match a2 {
        DaemonResponse::Result(v) => v,
        other => panic!("extract A repeat must succeed, got {other:?}"),
    };
    let b1 = extract(file_b.clone()).await.expect("extract B");
    let b1 = match b1 {
        DaemonResponse::Result(v) => v,
        other => panic!("extract B must succeed, got {other:?}"),
    };

    let salsa = match send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip")
    {
        DaemonResponse::FullStatus { salsa_stats, .. } => salsa_stats,
        other => panic!("expected FullStatus, got {other:?}"),
    };
    assert_eq!(
        (salsa.misses, salsa.hits),
        (2, 1),
        "A(miss) + A-repeat(hit) + B(fresh miss) — the same-file repeat must \
         hit the cache and the different-file request must not"
    );

    // Payload identity/isolation: the repeat is identical, B differs and
    // carries B's function, not A's.
    assert_eq!(
        serde_json::to_string(&a1).unwrap(),
        serde_json::to_string(&a2).unwrap(),
        "the repeated same-file extract must be served the cached payload"
    );
    let b_str = serde_json::to_string(&b1).unwrap();
    assert_ne!(
        serde_json::to_string(&a1).unwrap(),
        b_str,
        "different files must produce different payloads"
    );
    assert!(
        b_str.contains("helper") && !b_str.contains("def main"),
        "file B's payload must reflect B's content only, got {b_str}"
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

// =============================================================================
// Issue #67 — errors are delivered with context, not swallowed
// =============================================================================

/// A request that fails (extract of a nonexistent file) must come back over
/// the IPC wire as a structured error carrying context (non-empty message,
/// `status: "error"`), and the daemon must remain live and serving
/// afterwards — an error is reported, never swallowed into a hung or dead
/// daemon.
#[tokio::test]
async fn error_responses_carry_context_over_ipc_and_daemon_stays_live() {
    let temp = project_dir("dc-errors-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let failing = send_command(
        &project,
        &DaemonCommand::Extract {
            file: project.join("does_not_exist.py"),
            session: None,
        },
    )
    .await
    .expect("the failing request must still get a response over the wire");

    let error_text = match &failing {
        DaemonResponse::Error { status, error } => {
            assert_eq!(status, "error");
            assert!(
                !error.is_empty(),
                "the error response must carry a non-empty context message"
            );
            error.clone()
        }
        other => panic!("expected a structured Error response, got {other:?}"),
    };
    assert!(
        error_text.contains("does_not_exist"),
        "the error context must identify the failing request target, got: \
         {error_text}"
    );

    // The daemon survived the failure and still serves healthy requests.
    let alive = send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("the daemon must still be serving after a failed request");
    match alive {
        DaemonResponse::Status { status, message } => {
            assert_eq!(status, "ok");
            assert_eq!(message.as_deref(), Some("pong"));
        }
        other => panic!("expected a pong after the error, got {other:?}"),
    }

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

// =============================================================================
// Issue #68 — hook-stats flush threshold (converts the vacuous
// `test_track_flush_at_threshold` placeholder into a real state assertion)
// =============================================================================

/// The 5th tracked hook invocation (`HOOK_FLUSH_THRESHOLD`) must actually
/// persist the stats files and report `flushed: true`; the 4th must report
/// `flushed: false`. The old placeholder asserted a string that matched
/// either way (it also checked the wrong invocation index), so the flush
/// contract it claimed to cover was unasserted until now.
#[tokio::test]
async fn track_flush_persists_stats_exactly_at_the_threshold() {
    let temp = project_dir("dc-track-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let track = |n: u64| {
        let project = project.clone();
        async move {
            send_command(
                &project,
                &DaemonCommand::Track {
                    hook: "contract-hook".to_string(),
                    success: true,
                    metrics: std::collections::HashMap::from([(
                        "files_checked".to_string(),
                        n as f64,
                    )]),
                },
            )
            .await
        }
    };

    let stats_file = project.join(".tldr").join("cache").join("salsa_stats.json");
    assert!(
        !stats_file.exists(),
        "precondition: nothing persisted before the threshold is reached"
    );

    let mut flushed_flags = Vec::new();
    for i in 1..=5u64 {
        let response = track(i).await.expect("track round-trip");
        match response {
            DaemonResponse::TrackResponse {
                hook,
                total_invocations,
                flushed,
                ..
            } => {
                assert_eq!(hook, "contract-hook");
                assert_eq!(total_invocations, i);
                flushed_flags.push(flushed);
            }
            other => panic!("expected TrackResponse, got {other:?}"),
        }
    }

    assert_eq!(
        flushed_flags,
        vec![false, false, false, false, true],
        "flush must happen exactly at the 5-invocation threshold"
    );
    let raw = std::fs::read_to_string(&stats_file)
        .expect("the threshold flush must persist salsa_stats.json");
    let stats: serde_json::Value = serde_json::from_str(&raw).expect("valid stats JSON");
    assert!(
        stats.get("hits").is_some() && stats.get("misses").is_some(),
        "persisted stats must expose the hit/miss counters, got {raw}"
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

// =============================================================================
// Issue #67 — persistent JSONL request log (the implemented contract)
// =============================================================================

/// The daemon log path for a project: `<project>/.tldr/cache/daemon.log`,
/// next to `query_cache.bin` / `salsa_stats.json`.
fn log_file(project: &Path) -> std::path::PathBuf {
    tldr_cli::commands::daemon::daemon_log_path(project)
}

/// Parse every non-empty line of the log into a JSON object (every line
/// must be valid JSON — the JSONL contract).
fn read_log(project: &Path) -> Vec<serde_json::Value> {
    let raw = std::fs::read_to_string(log_file(project)).expect("daemon.log must exist");
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("line {l:?} not JSON: {e}")))
        .collect()
}

/// Events of the parsed log as `("event", "command")` pairs.
fn event_pairs(log: &[serde_json::Value]) -> Vec<(String, String)> {
    log.iter()
        .map(|l| {
            (
                l["event"].as_str().expect("event is a string").to_string(),
                l["command"]
                    .as_str()
                    .expect("command is a string")
                    .to_string(),
            )
        })
        .collect()
}

/// Start the daemon, serve a Ping and a real Extract, stop it, and verify
/// the persistent log: a `started` lifecycle line, request/response pairs
/// naming the same command (response with `duration_ms`), an explicit-stop
/// `shutdown_command` line, a closing `stopped` line, and pid/version
/// metadata on every line. Timestamps are never asserted by value
/// (issue #67: stable names/fields only).
#[tokio::test]
async fn daemon_log_records_request_response_lifecycle_and_shutdown_shape_over_ipc() {
    let temp = project_dir("dc-log-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let pong = send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("ping round-trip");
    assert!(matches!(pong, DaemonResponse::Status { .. }));

    let utils = project.join("utils.py");
    let extract = send_command(
        &project,
        &DaemonCommand::Extract {
            file: utils.clone(),
            session: None,
        },
    )
    .await
    .expect("extract round-trip");
    assert!(matches!(extract, DaemonResponse::Result(_)));

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");

    let log = read_log(&project);
    assert!(!log.is_empty(), "a served session must leave log lines");

    // Every line carries the process metadata and the required fields.
    for line in &log {
        assert_eq!(line["pid"], std::process::id(), "line: {line}");
        assert_eq!(
            line["version"],
            env!("CARGO_PKG_VERSION"),
            "the version metadata matches `tldr --version`: {line}"
        );
        assert!(line.get("ts").and_then(|v| v.as_str()).is_some(), "{line}");
        assert!(line.get("status").is_some(), "{line}");
    }

    // Session shape: started → request/response pairs → shutdown_command → stopped.
    let pairs = event_pairs(&log);
    assert_eq!(
        pairs.first().map(|(e, c)| (e.as_str(), c.as_str())),
        Some(("lifecycle", "daemon")),
        "the session must open with a lifecycle line"
    );
    assert_eq!(
        log[0]["detail"], "started",
        "the opening lifecycle line marks the start: {:?}",
        log[0]
    );
    assert_eq!(
        pairs.last().map(|(e, c)| (e.as_str(), c.as_str())),
        Some(("lifecycle", "daemon")),
        "the session must close with a lifecycle line"
    );
    assert_eq!(
        log.last().unwrap()["detail"],
        "stopped",
        "the closing lifecycle line marks the stop: {:?}",
        log.last().unwrap()
    );
    assert!(
        log.iter().any(|l| l["event"] == "lifecycle"
            && l["detail"] == "shutdown_command: explicit stop requested"),
        "an explicit stop is distinguishable from an idle timeout or an \
         error exit in the log: {pairs:?}"
    );

    // Per-request traces: request + response lines naming the same command.
    // The Shutdown arm emits its `shutdown_command` lifecycle line BETWEEN
    // the request and response brackets (documented shape), so adjacency is
    // asserted per-command.
    for (command, expected_status, adjacent) in [
        ("ping", "ok", true),
        ("extract", "ok", true),
        ("shutdown", "ok", false),
    ] {
        let i = pairs
            .iter()
            .position(|(e, c)| e == "request" && c == command)
            .unwrap_or_else(|| {
                panic!("exactly the served {command} request must be logged: {pairs:?}")
            });
        if adjacent {
            assert_eq!(
                pairs[i + 1],
                ("response".to_string(), command.to_string()),
                "the {command} request must be immediately followed by its response line: {pairs:?}"
            );
        } else {
            // shutdown: the explicit-stop lifecycle line sits between the
            // brackets (distinguishing it from idle/error exits).
            assert_eq!(
                pairs[i + 1],
                ("lifecycle".to_string(), "daemon".to_string()),
                "the shutdown request must carry its explicit-stop lifecycle line: {pairs:?}"
            );
            assert_eq!(
                log[i + 1]["detail"],
                "shutdown_command: explicit stop requested",
                "{:?}",
                log[i + 1]
            );
            assert_eq!(
                pairs[i + 2],
                ("response".to_string(), command.to_string()),
                "the shutdown response must close the brackets: {pairs:?}"
            );
        }
        let response = &log[i + 1 + usize::from(!adjacent)];
        assert_eq!(response["event"], "response");
        assert_eq!(response["status"], expected_status, "{response}");
        assert!(
            response
                .get("duration_ms")
                .and_then(|v| v.as_f64())
                .is_some(),
            "response lines carry the duration: {response}"
        );
    }

    // The extract request line names the file it served.
    let extract_request = &log[pairs
        .iter()
        .position(|(e, c)| e == "request" && c == "extract")
        .unwrap()];
    assert_eq!(
        extract_request["path"],
        utils.to_string_lossy().as_ref(),
        "request lines carry the command's target path: {extract_request}"
    );
}

/// The slow-request marker: with the threshold injected to 0 (the
/// test-visible `with_slow_request_ms` hook — no sleeps needed), every
/// served request gets a `slow` companion line carrying the duration.
#[tokio::test]
async fn slow_marker_fires_when_the_threshold_is_injected() {
    let temp = project_dir("dc-slow-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let daemon = TLDRDaemon::new(project.to_path_buf(), default_config()).with_slow_request_ms(0);
    let handle = start_prebuilt_daemon(&project, daemon).await;

    send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("ping round-trip");

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");

    let log = read_log(&project);
    let pairs = event_pairs(&log);
    let slow: Vec<&serde_json::Value> = log.iter().filter(|l| l["event"] == "slow").collect();
    assert!(
        !slow.is_empty(),
        "with threshold 0 at least one request must be marked slow: {pairs:?}"
    );
    assert!(
        slow.iter().any(|l| l["command"] == "ping"),
        "the ping request must be among the slow-marked: {pairs:?}"
    );
    for line in &slow {
        assert!(
            line.get("duration_ms").and_then(|v| v.as_f64()).is_some(),
            "slow lines carry the measured duration: {line}"
        );
    }
}

/// A failing request over IPC produces the `error` companion line carrying
/// the request's context — the #85-family silent-swallowing gap closed in
/// the persistent log.
#[tokio::test]
async fn error_events_carry_request_context_in_the_log_over_ipc() {
    let temp = project_dir("dc-logerr-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    let failing = send_command(
        &project,
        &DaemonCommand::Extract {
            file: project.join("does_not_exist.py"),
            session: None,
        },
    )
    .await
    .expect("the failing request still gets a wire response");
    assert!(matches!(failing, DaemonResponse::Error { .. }));

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");

    let log = read_log(&project);
    let extract_errors: Vec<&serde_json::Value> = log
        .iter()
        .filter(|l| l["event"] == "error" && l["command"] == "extract")
        .collect();
    assert_eq!(
        extract_errors.len(),
        1,
        "one failed extract request = one error line carrying its context: {log:?}"
    );
    let error = extract_errors[0];
    assert_eq!(error["command"], "extract");
    assert_eq!(error["status"], "error");
    let detail = error["detail"]
        .as_str()
        .expect("error line carries context");
    assert!(
        detail.contains("does_not_exist"),
        "the error context must identify the failing target: {detail}"
    );
}

/// Bounds contract: a log pushed past `MAX_LOG_BYTES` is truncated on the
/// next daemon start (truncate-and-restart), and the new session appends
/// fresh lines.
#[tokio::test]
async fn log_is_truncated_when_it_exceeds_the_cap() {
    let temp = project_dir("dc-rotate-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let max_bytes = tldr_cli::commands::daemon::MAX_LOG_BYTES;
    let log_path = log_file(&project);
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
    let filler = "x".repeat(max_bytes as usize + 1024);
    std::fs::write(&log_path, &filler).unwrap();

    let handle = start_in_process_daemon(&project, default_config()).await;
    send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("ping round-trip");
    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");

    let size = std::fs::metadata(&log_path).unwrap().len();
    assert!(
        size <= max_bytes,
        "the log must be truncated at the cap, got {size} bytes"
    );
    let log = read_log(&project);
    assert!(
        !log.is_empty(),
        "after rotation the fresh session's lines remain"
    );
    assert_eq!(
        log[0]["detail"], "started",
        "the surviving content is the NEW session's, not the filler"
    );
}

/// The observability surface: `Status` over IPC exposes the additive
/// `log_path` + `log_size_bytes` fields pointing at the live log.
#[tokio::test]
async fn status_response_exposes_log_path_and_log_size_bytes() {
    let temp = project_dir("dc-logstatus-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    let handle = start_in_process_daemon(&project, default_config()).await;

    send_command(&project, &DaemonCommand::Ping)
        .await
        .expect("ping round-trip");

    let status = send_command(&project, &DaemonCommand::Status { session: None })
        .await
        .expect("status round-trip");
    let (log_path, log_size_bytes) = match status {
        DaemonResponse::FullStatus {
            log_path,
            log_size_bytes,
            ..
        } => (log_path, log_size_bytes),
        other => panic!("expected FullStatus, got {other:?}"),
    };
    assert_eq!(
        log_path.as_deref(),
        Some(log_file(&project).as_path()),
        "log_path must point at the project's daemon.log"
    );
    let reported = log_size_bytes.expect("log_size_bytes must be present");
    assert!(reported > 0, "the served session already logged lines");
    let actual = std::fs::metadata(log_file(&project)).unwrap().len();
    assert!(
        reported <= actual,
        "the reported size cannot exceed the real file (only grows): {reported} > {actual}"
    );

    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
}

/// Local-fallback visibility: after the daemon is gone, a CLI command
/// routed through `try_daemon_route_async` falls back to direct compute and
/// appends a `fallback` line to the SAME project log via the shared helper
/// (the fallback is never silent). Client-side fallbacks in commands with
/// NO daemon route stay out of the log's scope (documented).
#[tokio::test]
async fn client_fallback_is_logged_by_the_shared_router_helper() {
    use tldr_cli::commands::daemon_router::try_daemon_route_async;

    let temp = project_dir("dc-fallback-");
    let project = temp.path().canonicalize().unwrap();
    write_python_project(&project);

    // A daemon ran once (the log exists), then stopped.
    let handle = start_in_process_daemon(&project, default_config()).await;
    send_command(&project, &DaemonCommand::Shutdown)
        .await
        .expect("shutdown acknowledged");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon exits after shutdown")
        .expect("run task must not panic")
        .expect("graceful shutdown returns Ok");
    assert!(
        !check_socket_alive(&project).await,
        "precondition: the daemon is down"
    );

    // CLI-side routing attempt → no daemon → fallback logged.
    let routed: Option<serde_json::Value> = try_daemon_route_async(
        &project,
        "calls",
        serde_json::json!({ "language": "python" }),
    )
    .await;
    assert!(routed.is_none(), "a dead daemon route must yield None");

    let log = read_log(&project);
    let fallbacks: Vec<&serde_json::Value> = log
        .iter()
        .filter(|l| l["event"] == "fallback" && l["command"] == "calls")
        .collect();
    assert_eq!(
        fallbacks.len(),
        1,
        "the failed daemon route must leave exactly one fallback line: {log:?}"
    );
    let detail = fallbacks[0]["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("daemon"),
        "the fallback line says WHY the daemon route failed: {detail}"
    );
    assert_eq!(fallbacks[0]["pid"], std::process::id());
}
