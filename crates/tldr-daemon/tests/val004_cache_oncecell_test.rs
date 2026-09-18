//! VAL-004 regression test: daemon caches actually populate.
//!
//! Bug: `get_or_build_call_graph` / `get_or_build_bm25` previously called
//! `.or_insert_with(OnceCell::new).clone()` on the HashMap entry. `OnceCell::clone`
//! produces an INDEPENDENT, uninitialized cell, so `get_or_init` initialized the
//! cloned cell (which was then returned and discarded), not the cell stored in the
//! HashMap. Every subsequent request observed the still-empty HashMap entry and
//! rebuilt from scratch.
//!
//! This test invokes each cache twice with the same key. The builder closure
//! increments an `AtomicU64`; we assert the counter == 1 after both calls
//! (cache hit on second call).
//!
//! RED on HEAD `88ddac6` before the fix: counter == 2 (every call rebuilds).
//! GREEN after the fix: counter == 1.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tldr_core::{Bm25Index, Language, ProjectCallGraph};
use tldr_daemon::state::DaemonState;

#[tokio::test]
async fn call_graph_cache_serves_cached_result_on_second_request() {
    let state = DaemonState::new(
        PathBuf::from("/tmp/val004-cg-project"),
        PathBuf::from("/tmp/val004-cg.sock"),
    );

    let build_count = Arc::new(AtomicU64::new(0));

    // First call: builder MUST run exactly once.
    {
        let counter = Arc::clone(&build_count);
        let _g = state
            .get_or_build_call_graph(Language::Python, move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(ProjectCallGraph::new())
                }
            })
            .await
            .unwrap();
    }

    // Second call: cache MUST hit; builder MUST NOT run again.
    {
        let counter = Arc::clone(&build_count);
        let _g = state
            .get_or_build_call_graph(Language::Python, move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(ProjectCallGraph::new())
                }
            })
            .await
            .unwrap();
    }

    let n = build_count.load(Ordering::SeqCst);
    assert_eq!(
        n, 1,
        "call_graph builder ran {} times across 2 requests; expected 1 (cache miss + cache hit). \
         counter == 2 indicates the OnceCell-clone bug: every request rebuilds.",
        n
    );
}

#[tokio::test]
async fn bm25_cache_serves_cached_result_on_second_request() {
    let state = DaemonState::new(
        PathBuf::from("/tmp/val004-bm25-project"),
        PathBuf::from("/tmp/val004-bm25.sock"),
    );

    let build_count = Arc::new(AtomicU64::new(0));

    {
        let counter = Arc::clone(&build_count);
        let _i = state
            .get_or_build_bm25(Language::Python, move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Bm25Index::default()
                }
            })
            .await;
    }

    {
        let counter = Arc::clone(&build_count);
        let _i = state
            .get_or_build_bm25(Language::Python, move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Bm25Index::default()
                }
            })
            .await;
    }

    let n = build_count.load(Ordering::SeqCst);
    assert_eq!(
        n, 1,
        "bm25 builder ran {} times across 2 requests; expected 1 (cache miss + cache hit). \
         counter == 2 indicates the OnceCell-clone bug: every request rebuilds.",
        n
    );
}

#[tokio::test]
async fn call_graph_cache_returns_same_arc_instance_on_second_request() {
    // Deeper invariant: the second request MUST return the SAME `Arc` (pointer
    // equality), proving the HashMap entry actually retained the initialized cell.
    let state = DaemonState::new(
        PathBuf::from("/tmp/val004-arc-project"),
        PathBuf::from("/tmp/val004-arc.sock"),
    );

    let g1 = state
        .get_or_build_call_graph(Language::Python, || async { Ok(ProjectCallGraph::new()) })
        .await
        .unwrap();
    let g2 = state
        .get_or_build_call_graph(Language::Python, || async { Ok(ProjectCallGraph::new()) })
        .await
        .unwrap();

    assert!(
        Arc::ptr_eq(&g1, &g2),
        "Second request returned a different Arc — cache did NOT persist the built graph"
    );
}
