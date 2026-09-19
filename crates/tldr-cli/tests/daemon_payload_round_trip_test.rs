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
use tldr_core::{DeadCodeReport, EnrichedSearchReport, SearchMode};

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

/// daemon-enriched-search-v1 (issue #65): the new `EnrichedSearch` command's
/// REQUEST and RESPONSE payloads both round-trip.
///
/// Request side: the command serializes with the `enriched_search` wire tag
/// and reconstructs with every field intact — including a `SearchMode` that
/// carries data (hybrid's query/pattern pair) — and an older client that
/// omits `search_mode` entirely deserializes to the BM25 default (wire
/// back-compat).
///
/// Response side: the daemon handler drives the REAL core `enriched_search`
/// (the exact function the CLI's direct-compute path calls), and its wire
/// payload must deserialize into `EnrichedSearchReport` — the precondition
/// for `tldr search`'s `try_daemon_route` to ever accept a daemon answer —
/// and the cache-hit payload must decode identically.
#[tokio::test]
async fn enriched_search_payload_round_trips_into_enriched_search_report() {
    let temp = TempDir::new().expect("temp project");
    write_python_project(temp.path());
    let daemon = make_daemon(temp.path());

    // ---- REQUEST round-trip (wire shape, defaults, data-carrying mode) ----
    let cmd = DaemonCommand::EnrichedSearch {
        query: "helper".to_string(),
        root: None,
        language: Some(tldr_core::Language::Python),
        top_k: Some(5),
        include_callgraph: Some(false),
        search_mode: SearchMode::Hybrid {
            query: "helper".to_string(),
            pattern: "def helper".to_string(),
        },
    };
    let json = serde_json::to_string(&cmd).expect("request serializes");
    assert!(
        json.contains(r#""cmd":"enriched_search""#),
        "the wire tag must be the snake_case command name, got {json}"
    );
    let back: DaemonCommand = serde_json::from_str(&json).expect("request deserializes");
    match back {
        DaemonCommand::EnrichedSearch {
            query,
            root,
            language,
            top_k,
            include_callgraph,
            search_mode,
        } => {
            assert_eq!(query, "helper");
            assert_eq!(root, None, "no root means the served project");
            assert_eq!(language, Some(tldr_core::Language::Python));
            assert_eq!(top_k, Some(5));
            assert_eq!(include_callgraph, Some(false));
            match search_mode {
                SearchMode::Hybrid { query, pattern } => {
                    assert_eq!(query, "helper");
                    assert_eq!(pattern, "def helper");
                }
                other => panic!("hybrid mode must round-trip, got {other:?}"),
            }
        }
        other => panic!("expected EnrichedSearch, got {other:?}"),
    }

    // Back-compat: a request WITHOUT `search_mode` (and without the optional
    // knobs) deserializes to the BM25 default — old clients keep today's
    // behavior byte-for-byte.
    let legacy: DaemonCommand =
        serde_json::from_str(r#"{"cmd":"enriched_search","query":"helper"}"#)
            .expect("a bare request must deserialize");
    match legacy {
        DaemonCommand::EnrichedSearch {
            root,
            language,
            top_k,
            include_callgraph,
            search_mode,
            ..
        } => {
            assert!(matches!(search_mode, SearchMode::Bm25), "default is BM25");
            assert_eq!(
                (root, language, top_k, include_callgraph),
                (None, None, None, None)
            );
        }
        other => panic!("expected EnrichedSearch, got {other:?}"),
    }

    // ---- RESPONSE round-trip through the REAL handler ----
    let response = daemon
        .handle_command(DaemonCommand::EnrichedSearch {
            query: "helper".to_string(),
            root: None,
            language: Some(tldr_core::Language::Python),
            top_k: Some(10),
            include_callgraph: Some(true),
            search_mode: SearchMode::Bm25,
        })
        .await;

    let value = match response {
        DaemonResponse::Result(value) => value,
        DaemonResponse::Error { error, .. } => {
            panic!("EnrichedSearch handler errored on a valid project: {error}")
        }
        other => panic!("expected a Result response, got {other:?}"),
    };

    for key in [
        "query",
        "results",
        "total_results",
        "total_files_searched",
        "search_mode",
    ] {
        assert!(
            value.get(key).is_some(),
            "enriched payload must carry `{key}` (EnrichedSearchReport shape); got {value}"
        );
    }

    // THE regression guard: the daemon's payload decodes into the CLI's
    // report type. Pre-route, nothing guaranteed this; if it breaks,
    // `try_daemon_route::<EnrichedSearchReport>` returns None on EVERY call
    // and `tldr search` silently degrades to client-local compute forever.
    let report: EnrichedSearchReport = serde_json::from_value(value).expect(
        "the daemon's EnrichedSearch payload must deserialize into \
         EnrichedSearchReport",
    );
    assert_eq!(report.query, "helper");
    assert!(
        !report.results.is_empty(),
        "fixture sanity: 'helper' must match the two-file project"
    );
    assert_eq!(report.total_results, report.results.len());
    let card = report
        .results
        .iter()
        .find(|c| c.name == "helper")
        .expect("the `helper` function card must be present");
    assert_eq!(card.kind, "function");
    assert!(
        card.signature.contains("def helper"),
        "the card signature must survive the round-trip, got {:?}",
        card.signature
    );

    // Cache-hit payload still decodes (mirrors the Dead test above).
    let hits_after_first = daemon.cache_stats().hits;
    let second = daemon
        .handle_command(DaemonCommand::EnrichedSearch {
            query: "helper".to_string(),
            root: None,
            language: Some(tldr_core::Language::Python),
            top_k: Some(10),
            include_callgraph: Some(true),
            search_mode: SearchMode::Bm25,
        })
        .await;
    let second_value = match second {
        DaemonResponse::Result(value) => value,
        other => panic!("second EnrichedSearch request must succeed, got {other:?}"),
    };
    assert!(
        daemon.cache_stats().hits > hits_after_first,
        "the second identical EnrichedSearch query must be a CACHE HIT — \
         pre-route the CLI could never decode the payload, so the cache was \
         useless for search"
    );
    let second_report: EnrichedSearchReport =
        serde_json::from_value(second_value).expect("cache-hit payload decodes");
    assert_eq!(
        second_report.total_results, report.total_results,
        "cache hit must serve the same analysis"
    );
    assert_eq!(
        second_report.results.len(),
        report.results.len(),
        "cache hit must serve the same result set"
    );
}
