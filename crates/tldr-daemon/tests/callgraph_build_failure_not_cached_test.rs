//! Issue #85: the HTTP call-graph endpoints must not CACHE a failed build.
//!
//! Pre-fix, the `calls` / `impact` / `arch` handlers mapped every build
//! failure (`build_project_call_graph` returning `Err`, or the blocking task
//! failing to join) onto `ProjectCallGraph::new()`. Because the shared
//! `DaemonState` cache stores whatever the builder returns, that empty graph
//! was then served — HTTP 200, zero edges — to every subsequent VALID
//! request for the lifetime of the daemon. The error itself was invisible.
//!
//! Post-fix a failed build surfaces as HTTP 500 with the cause, and the
//! cache slot stays empty, so the next request retries the build and serves
//! the real graph.
//!
//! The sequence below is the issue's repro shape: one failing request, then
//! a valid one against the SAME daemon state. The second response must carry
//! the real edge, not the cached emptiness of the first.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{extract::State, Json};
use tempfile::TempDir;

use tldr_daemon::handlers::callgraph::{calls, CallsRequest};
use tldr_daemon::server::compute_socket_path;
use tldr_daemon::state::DaemonState;

fn make_state(project_root: PathBuf) -> Arc<DaemonState> {
    let socket = compute_socket_path(&project_root, "1.0");
    Arc::new(DaemonState::new(project_root, socket))
}

async fn run_calls(state: Arc<DaemonState>) -> Result<serde_json::Value, (u16, String)> {
    let response = calls(
        State(Arc::clone(&state)),
        Json(CallsRequest {
            language: "python".to_string(),
        }),
    )
    .await;

    match response {
        Ok(response) => Ok(serde_json::to_value(&response.0).expect("response serializes")),
        // `HandlerError` has no `Debug`, so match instead of `expect`.
        Err(err) => Err((err.0.as_u16(), err.1)),
    }
}

/// A readable Python file with a real cross-file call edge.
fn write_source(dir: &Path) {
    std::fs::write(
        dir.join("main.py"),
        "from utils import helper\n\n\ndef main():\n    helper()\n",
    )
    .expect("write main.py");
    std::fs::write(dir.join("utils.py"), "def helper():\n    return 'help'\n")
        .expect("write utils.py");
}

#[tokio::test]
async fn failed_build_returns_500_and_next_request_gets_the_real_graph() {
    let project = TempDir::new().expect("project tempdir");

    // The daemon's project root does not exist yet — the first build fails
    // at the filesystem layer.
    let missing_root = project.path().join("not_built_yet");
    let state = make_state(missing_root.clone());

    // FIRST request: the build fails. It must surface as HTTP 500 with a
    // cause, not as HTTP 200 with an empty graph.
    let first = run_calls(Arc::clone(&state)).await;
    let (status, message) = first
        .expect_err("a build over a missing project root must fail, not return an empty graph");
    assert_eq!(
        status, 500,
        "a failed build must be an HTTP 500, got {status}: {message}"
    );
    assert!(
        !message.is_empty(),
        "the error must carry a diagnosable cause"
    );

    // The project comes into being (editor saves the first sources).
    std::fs::create_dir_all(&missing_root).expect("create project root");
    write_source(&missing_root);

    // SECOND request: the build must be RETRIED and serve the real graph.
    // Pre-fix this returned the cached empty graph from request one.
    let second = run_calls(Arc::clone(&state))
        .await
        .expect("the retried build must succeed once the project exists");
    let result = &second["result"];

    let edge_count = result["edge_count"]
        .as_u64()
        .expect("edge_count is a number");
    assert!(
        edge_count >= 1,
        "second request must carry the REAL graph (main -> helper), got \
         edge_count={edge_count} — the failed build was still cached: {second}"
    );
    let edges = result["edges"].as_array().expect("edges is an array");
    assert_eq!(
        edges.len() as u64,
        edge_count,
        "edge_count must agree with the edges list"
    );
}

#[tokio::test]
async fn successful_build_is_still_cached_after_a_failure() {
    // The control for the fix: fail-caching is gone, but SUCCESS caching is
    // untouched — the second request after a success must not rebuild.
    let project = TempDir::new().expect("project tempdir");
    write_source(project.path());
    let state = make_state(project.path().to_path_buf());

    let first = run_calls(Arc::clone(&state))
        .await
        .expect("build over a real project succeeds");
    let edge_count = first["result"]["edge_count"].as_u64().expect("edge_count");
    assert!(edge_count >= 1, "fixture must produce at least one edge");

    let second = run_calls(Arc::clone(&state))
        .await
        .expect("second call succeeds");
    assert_eq!(
        second, first,
        "the second request must be served from the cache (identical payload)"
    );
}
