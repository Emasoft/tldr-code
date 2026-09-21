//! markup-node-tree-v1 (FIX-2 3a) — the axum HTTP daemon's `max_depth`
//! handling, pinned at the wire boundary.
//!
//! CONTRACT UNDER TEST (`handlers::ast::structure`):
//!
//! `POST /structure` accepts an OPTIONAL `max_depth: u32` (absent or `null`
//! = no filtering) and applies `filter_structure_max_depth` PER REQUEST,
//! AFTER the extraction. Every element row with `Some(depth) <= max_depth`
//! survives (depth-less rows — inner-CSS selectors, code symbols — are never
//! filtered), and a follow-up request WITHOUT `max_depth` on the SAME daemon
//! state still returns the FULL set: the filter must never be baked into any
//! shared/memoized extraction slot.
//!
//! Test design: `tower::ServiceExt::oneshot` against `build_router` — the
//! real axum stack (JSON extraction, serde binding, `DaemonResponse`
//! wrapper) without a socket, a spawned process, or an idle-timeout ticker.
//! The CLI-IPC-surface pin for the same knob lives in
//! `tldr-cli/tests/daemon_contract_coverage_test.rs`
//! (`structure_max_depth_filters_per_request_and_keeps_the_cached_slot_full`);
//! this file pins the HTTP surface the MCP/HTTP clients exercise.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tempfile::TempDir;
use tldr_daemon::server::build_router;
use tldr_daemon::state::DaemonState;
use tower::ServiceExt; // `.oneshot`

/// The pinned HTML page (element depths: html 0, head 1, title 2, style 2,
/// body#main 1, script 2, p 2, br 2 — plus one depth-less inner-CSS
/// `selector` row from the style body).
const PAGE_HTML: &str = "\
<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <title>Page</title>
    <style>body { color: red; }</style>
  </head>
  <body id=\"main\">
    <script src=\"app.js\"></script>
    <p>Hello</p>
    <br/>
  </body>
</html>
";

/// Project with one page; the socket path is never bound (oneshot).
fn project_with_page() -> (TempDir, Arc<DaemonState>) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("page.html"), PAGE_HTML).expect("write page.html fixture");
    let state = Arc::new(DaemonState::new(
        dir.path().to_path_buf(),
        dir.path().join("unused-test.sock"),
    ));
    (dir, state)
}

/// POST one structure request body and unwrap the `DaemonResponse` envelope.
async fn post_structure(state: Arc<DaemonState>, body: Value) -> Value {
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/structure")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await
        .expect("oneshot serves the request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "structure must answer 200: {:?}",
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map(|b| String::from_utf8_lossy(&b).to_string())
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    let envelope: Value = serde_json::from_slice(&bytes).expect("DaemonResponse JSON parses");
    assert_eq!(envelope["status"], "ok", "envelope: {envelope}");
    let result = envelope
        .get("result")
        .cloned()
        .expect("successful envelope carries the structure result");
    assert!(result.is_object(), "the structure result is an object");
    result
}

/// The (name, depth-as-JSON) rows of every `element` definition.
fn element_rows(report: &Value) -> Vec<(String, Option<u32>)> {
    report["files"][0]["definitions"]
        .as_array()
        .expect("definitions array")
        .iter()
        .filter(|d| d["kind"] == "element")
        .map(|d| {
            (
                d["name"].as_str().unwrap_or_default().to_string(),
                d["depth"].as_u64().map(|n| n as u32),
            )
        })
        .collect()
}

/// `{"language":"html","max_depth":1}` narrows the element tree to depth <= 1
/// over HTTP; the depth-less `selector` row survives unfiltered.
#[tokio::test]
async fn structure_with_max_depth_1_returns_only_shallow_element_rows() {
    let (_dir, state) = project_with_page();

    let report = post_structure(state.clone(), json!({"language": "html", "max_depth": 1})).await;

    assert_eq!(
        element_rows(&report),
        vec![
            ("html".to_string(), Some(0)),
            ("head".to_string(), Some(1)),
            ("body#main".to_string(), Some(1)),
        ],
        "max_depth 1 must keep exactly the depth <= 1 markup elements"
    );

    // The depth-less selector row survived (no markup-nesting semantics) and
    // omits the additive `depth` key from JSON.
    let defs = report["files"][0]["definitions"].as_array().unwrap();
    assert_eq!(defs.len(), 4, "3 elements + 1 depth-less selector row");
    let selector = defs
        .iter()
        .find(|d| d["kind"] == "selector")
        .expect("the inner-CSS selector row must survive max_depth filtering");
    assert_eq!(selector["name"], "body");
    assert!(
        selector.get("depth").is_none(),
        "depth-less rows omit the additive depth key: {selector}"
    );
}

/// The filter is PER REQUEST: on the SAME daemon state, a request without
/// `max_depth` — before, between, and after filtered ones — always returns
/// the full set. A memoized-filtered slot would make these fail.
#[tokio::test]
async fn structure_without_max_depth_returns_the_full_set_around_filtered_requests() {
    let (_dir, state) = project_with_page();

    let unfiltered = |state: Arc<DaemonState>| {
        let state = state.clone();
        async move { element_rows(&post_structure(state, json!({"language": "html"})).await) }
    };

    // 1. Unfiltered first: the full element set.
    assert_eq!(
        unfiltered(state.clone()).await.len(),
        8,
        "no max_depth key means no filtering"
    );

    // 2. Filtered in between.
    let report = post_structure(state.clone(), json!({"language": "html", "max_depth": 0})).await;
    assert_eq!(
        element_rows(&report),
        vec![("html".to_string(), Some(0))],
        "max_depth 0 keeps only root-level elements"
    );

    // 3. Unfiltered again: still the full set — the per-request filter never
    //    poisoned the shared extraction result.
    let full = unfiltered(state.clone()).await;
    assert_eq!(
        full,
        vec![
            ("html".to_string(), Some(0)),
            ("head".to_string(), Some(1)),
            ("title".to_string(), Some(2)),
            ("style".to_string(), Some(2)),
            ("body#main".to_string(), Some(1)),
            ("script".to_string(), Some(2)),
            ("p".to_string(), Some(2)),
            ("br".to_string(), Some(2)),
        ],
        "every element carries its nesting depth on the unfiltered route"
    );

    // 4. `max_depth: null` binds like the key being absent (serde default).
    let report = post_structure(state, json!({"language": "html", "max_depth": null})).await;
    assert_eq!(
        element_rows(&report).len(),
        8,
        "null max_depth means no filtering"
    );
}
