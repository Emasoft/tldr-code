//! Daemon payload round-trip tests (daemon-calls-payload-v1 / dead round-trip).
//!
//! Two defects, one observable symptom: `tldr dead` and `tldr calls` NEVER
//! used the daemon cache because the CLI could not decode the daemon's
//! payload, and `try_daemon_route` silently returns `None` on a decode
//! failure — so every invocation fell back to direct compute.
//!
//! 1. `Dead`: the daemon serializes `DeadCodeReport` with BOTH the canonical
//!    `functions_analyzed` key and the deprecated `total_functions` alias
//!    (hand-rolled `Serialize` in tldr-core/src/types.rs), while the CLI's
//!    derived `Deserialize` declared the alias on the same field — serde
//!    rejects a payload carrying a field AND its alias ("duplicate field
//!    `total_functions`"). Every cached payload therefore failed to decode.
//! 2. `Calls`: the daemon serialized the raw compat `ProjectCallGraph`
//!    (`{"edges": [...]}`) — a shape structurally incompatible with the
//!    CLI's `CallGraphOutput`, so deserialization failed on the missing
//!    required fields before any duplicate-field question even arose.
//!
//! Both tests drive the REAL daemon handler (`handle_command`) and assert on
//! the serialized wire value, which is exactly what crosses the IPC socket.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use tldr_cli::commands::daemon::types::{DaemonCommand, DaemonConfig, DaemonResponse};
use tldr_cli::commands::daemon::TLDRDaemon;
use tldr_core::DeadCodeReport;

fn write_python_project(dir: &std::path::Path) {
    std::fs::write(
        dir.join("main.py"),
        "from utils import helper\n\n\ndef main():\n    helper()\n",
    )
    .expect("write main.py");
    std::fs::write(dir.join("utils.py"), "def helper():\n    return 'help'\n")
        .expect("write utils.py");
}

fn make_daemon(project: &std::path::Path) -> Arc<TLDRDaemon> {
    Arc::new(TLDRDaemon::new(
        project.to_path_buf(),
        DaemonConfig {
            idle_timeout_secs: 60,
            ..DaemonConfig::default()
        },
    ))
}

#[tokio::test]
async fn dead_payload_deserializes_into_dead_code_report() {
    let temp = TempDir::new().expect("temp project");
    write_python_project(temp.path());
    let daemon = make_daemon(temp.path());

    let response = daemon
        .handle_command(DaemonCommand::Dead {
            path: None,
            entry: None,
            language: Some(tldr_core::Language::Python),
        })
        .await;

    let value = match response {
        DaemonResponse::Result(value) => value,
        DaemonResponse::Error { error, .. } => {
            panic!("Dead handler errored on a valid project: {error}")
        }
        other => panic!("expected a Result response, got {other:?}"),
    };

    // Pin the wire contract first: BOTH spellings are on the wire (canonical
    // + deprecated alias). If one disappears the back-compat contract broke;
    // if the deserializer is derived-with-alias again, the assertion below
    // (from_value) is the one that fails.
    assert!(
        value.get("functions_analyzed").is_some(),
        "canonical `functions_analyzed` key must be emitted (N13): {value}"
    );
    assert!(
        value.get("total_functions").is_some(),
        "deprecated `total_functions` alias must still be emitted (N13): {value}"
    );
    assert_eq!(
        value["functions_analyzed"], value["total_functions"],
        "canonical and alias must agree"
    );
    assert!(
        value["functions_analyzed"].as_u64().unwrap_or(0) >= 2,
        "fixture has two functions; got {value}"
    );

    // THE regression: deserializing the daemon's own payload must succeed.
    // Pre-fix this failed with `duplicate field total_functions`, which
    // pushed `tldr dead` to its direct-compute fallback on every call.
    let report: DeadCodeReport = serde_json::from_value(value).expect(
        "the daemon's Dead payload must deserialize into DeadCodeReport — \
         a duplicate-field failure here means `tldr dead` can never use the \
         daemon cache",
    );
    assert!(
        report.total_functions >= 2,
        "functions_analyzed must survive the round-trip, got {}",
        report.total_functions
    );
    assert_eq!(report.total_dead, report.dead_functions.len());
}

#[tokio::test]
async fn dead_cache_hit_serves_a_payload_that_still_deserializes() {
    let temp = TempDir::new().expect("temp project");
    write_python_project(temp.path());
    let daemon = make_daemon(temp.path());

    let first = daemon
        .handle_command(DaemonCommand::Dead {
            path: None,
            entry: None,
            language: Some(tldr_core::Language::Python),
        })
        .await;
    let first_value = match first {
        DaemonResponse::Result(value) => value,
        other => panic!("first Dead request must succeed, got {other:?}"),
    };
    let hits_after_first = daemon.cache_stats().hits;

    // Small sleep so the second request's arrival time differs from the
    // first's (not required for correctness, but keeps the two responses
    // obviously independent).
    std::thread::sleep(Duration::from_millis(5));

    let second = daemon
        .handle_command(DaemonCommand::Dead {
            path: None,
            entry: None,
            language: Some(tldr_core::Language::Python),
        })
        .await;
    let second_value = match second {
        DaemonResponse::Result(value) => value,
        other => panic!("second Dead request must succeed, got {other:?}"),
    };

    assert!(
        daemon.cache_stats().hits > hits_after_first,
        "the second identical Dead query must be a CACHE HIT — pre-fix the \
         CLI could never decode the payload, so the cache was useless for \
         dead"
    );

    let first_report: DeadCodeReport = serde_json::from_value(first_value).expect("first decodes");
    let second_report: DeadCodeReport =
        serde_json::from_value(second_value).expect("cache-hit payload decodes");
    assert_eq!(
        first_report.total_functions, second_report.total_functions,
        "cache hit must serve the same analysis"
    );
    assert_eq!(
        first_report.total_dead, second_report.total_dead,
        "cache hit must serve the same dead set"
    );
}

#[tokio::test]
async fn calls_payload_matches_the_cli_output_shape() {
    let temp = TempDir::new().expect("temp project");
    write_python_project(temp.path());
    let daemon = make_daemon(temp.path());

    let response = daemon
        .handle_command(DaemonCommand::Calls {
            path: None,
            language: Some(tldr_core::Language::Python),
            max_items: None,
        })
        .await;

    let value = match response {
        DaemonResponse::Result(value) => value,
        DaemonResponse::Error { error, .. } => {
            panic!("Calls handler errored on a valid project: {error}")
        }
        other => panic!("expected a Result response, got {other:?}"),
    };

    // The CallGraphOutput shape the CLI deserializes into: every required
    // field present, with the canonical N12 counter pair. Pre-fix the
    // payload was the raw ProjectCallGraph (`{"edges": [...]}`) and NONE of
    // root/language/nodes/truncated/total_edges/shown_edges existed.
    for key in [
        "root",
        "language",
        "nodes",
        "edges",
        "truncated",
        "total_edges",
        "shown_edges",
    ] {
        assert!(
            value.get(key).is_some(),
            "calls payload must carry `{key}` (CallGraphOutput shape); got {value}"
        );
    }
    assert_eq!(
        value["total_edges"], value["shown_edges"],
        "an untruncated graph reports total == shown"
    );

    let edges = value["edges"].as_array().expect("edges is an array");
    assert!(
        !edges.is_empty(),
        "fixture main.py -> utils.py must produce at least one edge; got {value}"
    );
    let first_edge = &edges[0];
    for key in ["src_file", "src_func", "dst_file", "dst_func", "call_type"] {
        assert!(
            first_edge.get(key).is_some(),
            "edge objects must be EdgeOutput-shaped (`{key}` present); got {first_edge}"
        );
    }

    // Paths are relative to the project root, matching direct compute.
    let src = first_edge["src_file"]
        .as_str()
        .expect("src_file is a string");
    assert!(
        !src.starts_with('/'),
        "edge files must be project-relative like direct compute emits, got {src}"
    );
    let _root: PathBuf = serde_json::from_value(value["root"].clone()).expect("root is a path");
}
