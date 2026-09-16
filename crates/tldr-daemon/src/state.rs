//! Daemon shared state management
//!
//! This module provides the `DaemonState` struct which holds all shared state
//! for the daemon including caches for call graphs and BM25 indexes.
//!
//! # Mitigations Addressed
//!
//! - **M11**: Daemon Deadlock - Use `RwLock` for caches, `AtomicU64` for timestamps
//! - **M12**: Cache Race Condition - Use `tokio::sync::OnceCell` for lazy init
//! - **M13**: Tree-Sitter Memory - Reuse parsers via LRU cache

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{OnceCell, RwLock};

use tldr_core::{Bm25Index, Language, ProjectCallGraph};

/// Default idle timeout in seconds (5 minutes)
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Default LRU cache size for parsed trees
pub const DEFAULT_TREE_CACHE_SIZE: usize = 1000;

/// Shared daemon state
///
/// All fields are designed for concurrent access:
/// - Immutable after construction: `project`, `socket_path`, `version`
/// - Atomic: `last_activity`
/// - RwLock: mutable caches
/// - OnceCell: lazy initialization
pub struct DaemonState {
    /// Project root directory (immutable after init)
    project: PathBuf,

    /// Socket path (immutable after init)
    socket_path: PathBuf,

    /// Protocol version for handshake (M21)
    version: &'static str,

    /// Last activity timestamp (epoch millis, lock-free via AtomicU64)
    /// M11: Use atomic for timestamps to avoid lock contention
    last_activity: AtomicU64,

    /// Idle timeout duration
    idle_timeout: Duration,

    /// Call graph cache (lazy, built on first request)
    ///
    /// M12: OnceCell ensures single build even with concurrent requests.
    /// VAL-004 (#10): the value MUST be `Arc<OnceCell<...>>` rather than
    /// `OnceCell<...>` directly — `OnceCell::clone` produces an INDEPENDENT
    /// uninitialized cell, so cloning the bare cell out of the map and then
    /// `get_or_init`-ing the clone leaves the map's cell empty and rebuilds on
    /// every request. Wrapping in `Arc` makes `clone()` share the same cell.
    call_graph_cache: RwLock<HashMap<Language, Arc<OnceCell<Arc<ProjectCallGraph>>>>>,

    /// BM25 index cache (lazy, built on first search)
    ///
    /// VAL-004 (#10): see `call_graph_cache` rationale for the `Arc<OnceCell<...>>` shape.
    bm25_cache: RwLock<HashMap<Language, Arc<OnceCell<Arc<Bm25Index>>>>>,

    /// Request counter for metrics
    request_count: AtomicU64,

    /// Error counter for metrics
    error_count: AtomicU64,
}

impl DaemonState {
    /// Create new daemon state for a project
    pub fn new(project: PathBuf, socket_path: PathBuf) -> Self {
        Self {
            project,
            socket_path,
            version: "1.0",
            last_activity: AtomicU64::new(Self::current_epoch_millis()),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            call_graph_cache: RwLock::new(HashMap::new()),
            bm25_cache: RwLock::new(HashMap::new()),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Create with custom idle timeout
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Get the project root
    pub fn project(&self) -> &PathBuf {
        &self.project
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Get the protocol version
    pub fn version(&self) -> &str {
        self.version
    }

    /// Get the idle timeout duration
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Update last activity timestamp (lock-free)
    pub fn touch(&self) {
        self.last_activity
            .store(Self::current_epoch_millis(), Ordering::Relaxed);
    }

    /// Get last activity timestamp
    pub fn last_activity(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Check if daemon has been idle longer than timeout
    pub fn is_idle(&self) -> bool {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = Self::current_epoch_millis();
        let idle_ms = now.saturating_sub(last);
        idle_ms > self.idle_timeout.as_millis() as u64
    }

    /// Increment request counter
    pub fn record_request(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment error counter
    pub fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total request count
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Get total error count
    pub fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Get or build call graph for a language
    ///
    /// M12: Uses OnceCell to ensure only one build happens even with concurrent requests
    pub async fn get_or_build_call_graph<F, Fut>(
        &self,
        language: Language,
        builder: F,
    ) -> Arc<ProjectCallGraph>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ProjectCallGraph>,
    {
        // First, get or insert the shared OnceCell for this language.
        // The cell is wrapped in Arc so cloning it shares the underlying cell
        // (a bare `OnceCell::clone` would produce an independent uninitialized
        // copy — the VAL-004 / #10 bug).
        let cell: Arc<OnceCell<Arc<ProjectCallGraph>>> = {
            let read_guard = self.call_graph_cache.read().await;
            if let Some(cell) = read_guard.get(&language) {
                if let Some(graph) = cell.get() {
                    return Arc::clone(graph);
                }
                Arc::clone(cell)
            } else {
                drop(read_guard);

                let mut write_guard = self.call_graph_cache.write().await;
                Arc::clone(
                    write_guard
                        .entry(language)
                        .or_insert_with(|| Arc::new(OnceCell::new())),
                )
            }
        };

        // Now initialize the OnceCell (only one caller will actually build).
        // Because `cell` shares the cell stored in the HashMap, this initialization
        // is observable by every subsequent reader.
        Arc::clone(
            cell.get_or_init(|| async { Arc::new(builder().await) })
                .await,
        )
    }

    /// Get or build BM25 index for a language
    pub async fn get_or_build_bm25<F, Fut>(&self, language: Language, builder: F) -> Arc<Bm25Index>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Bm25Index>,
    {
        // See `get_or_build_call_graph` for the Arc<OnceCell<...>> rationale (VAL-004 / #10).
        let cell: Arc<OnceCell<Arc<Bm25Index>>> = {
            let read_guard = self.bm25_cache.read().await;
            if let Some(cell) = read_guard.get(&language) {
                if let Some(index) = cell.get() {
                    return Arc::clone(index);
                }
                Arc::clone(cell)
            } else {
                drop(read_guard);

                let mut write_guard = self.bm25_cache.write().await;
                Arc::clone(
                    write_guard
                        .entry(language)
                        .or_insert_with(|| Arc::new(OnceCell::new())),
                )
            }
        };

        Arc::clone(
            cell.get_or_init(|| async { Arc::new(builder().await) })
                .await,
        )
    }

    /// Invalidate all caches (e.g., when files change)
    pub async fn invalidate_caches(&self) {
        let mut cg_guard = self.call_graph_cache.write().await;
        cg_guard.clear();
        drop(cg_guard);

        let mut bm25_guard = self.bm25_cache.write().await;
        bm25_guard.clear();
    }

    /// Get daemon status for monitoring (M22)
    pub async fn status(&self) -> DaemonStatus {
        let now = Self::current_epoch_millis();
        let uptime_ms = now.saturating_sub(self.last_activity.load(Ordering::Relaxed));

        let cg_cache_size = self.call_graph_cache.read().await.len();
        let bm25_cache_size = self.bm25_cache.read().await.len();

        DaemonStatus {
            version: self.version.to_string(),
            project: self.project.clone(),
            socket_path: self.socket_path.clone(),
            uptime_seconds: uptime_ms / 1000,
            last_activity_epoch_ms: self.last_activity.load(Ordering::Relaxed),
            requests_served: self.request_count.load(Ordering::Relaxed),
            errors: self.error_count.load(Ordering::Relaxed),
            call_graph_cache_entries: cg_cache_size,
            bm25_cache_entries: bm25_cache_size,
            idle_timeout_seconds: self.idle_timeout.as_secs(),
        }
    }

    /// Get current epoch milliseconds
    fn current_epoch_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Daemon status for monitoring endpoint
#[derive(Debug, Clone, serde::Serialize)]
pub struct DaemonStatus {
    pub version: String,
    pub project: PathBuf,
    pub socket_path: PathBuf,
    pub uptime_seconds: u64,
    pub last_activity_epoch_ms: u64,
    pub requests_served: u64,
    pub errors: u64,
    pub call_graph_cache_entries: usize,
    pub bm25_cache_entries: usize,
    pub idle_timeout_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_daemon_state_creation() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        assert_eq!(state.project(), &PathBuf::from("/tmp/project"));
        assert_eq!(state.socket_path(), &PathBuf::from("/tmp/tldr.sock"));
        assert_eq!(state.version(), "1.0");
        assert_eq!(state.request_count(), 0);
        assert_eq!(state.error_count(), 0);
    }

    #[tokio::test]
    async fn test_touch_updates_activity() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        let before = state.last_activity();
        tokio::time::sleep(Duration::from_millis(10)).await;
        state.touch();
        let after = state.last_activity();

        assert!(after >= before);
    }

    #[tokio::test]
    async fn test_request_counting() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        state.record_request();
        state.record_request();
        state.record_error();

        assert_eq!(state.request_count(), 2);
        assert_eq!(state.error_count(), 1);
    }

    #[tokio::test]
    async fn test_idle_detection() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        )
        .with_idle_timeout(Duration::from_millis(50));

        assert!(!state.is_idle());

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(state.is_idle());

        state.touch();
        assert!(!state.is_idle());
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        // Build a call graph
        let _graph = state
            .get_or_build_call_graph(Language::Python, || async { ProjectCallGraph::new() })
            .await;

        // Verify it's cached
        {
            let cache = state.call_graph_cache.read().await;
            assert_eq!(cache.len(), 1);
        }

        // Invalidate
        state.invalidate_caches().await;

        // Verify cache is cleared
        {
            let cache = state.call_graph_cache.read().await;
            assert_eq!(cache.len(), 0);
        }
    }

    #[tokio::test]
    async fn test_status() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        state.record_request();
        state.record_request();

        let status = state.status().await;
        assert_eq!(status.version, "1.0");
        assert_eq!(status.project, PathBuf::from("/tmp/project"));
        assert_eq!(status.requests_served, 2);
    }

    /// v031-cluster-M2 regression: `get_or_build_call_graph` must key its
    /// cache by `Language`. Building once with `Python` and once with
    /// `TypeScript` must produce TWO independent cache entries, not one.
    ///
    /// This locks the contract that callers in daemon.rs which thread the
    /// language through (rather than hardcoding `Language::Python`) get
    /// cache hits scoped to the correct language. A future regression that
    /// collapses both languages into a single Python bucket would re-surface
    /// the original 10-hardcode bug class.
    #[tokio::test]
    async fn test_get_or_build_call_graph_caches_per_language() {
        let state = DaemonState::new(
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/tldr.sock"),
        );

        // Build for Python.
        let _py = state
            .get_or_build_call_graph(Language::Python, || async { ProjectCallGraph::new() })
            .await;

        // Build for TypeScript — must take a fresh slot in the cache map.
        let _ts = state
            .get_or_build_call_graph(Language::TypeScript, || async { ProjectCallGraph::new() })
            .await;

        let cache = state.call_graph_cache.read().await;
        assert_eq!(
            cache.len(),
            2,
            "cache must hold one entry per language — got {} entries, \
             indicating cross-language cache collapse",
            cache.len()
        );
        assert!(
            cache.contains_key(&Language::Python),
            "Python entry missing from cache"
        );
        assert!(
            cache.contains_key(&Language::TypeScript),
            "TypeScript entry missing from cache — indicates the threaded \
             language was discarded somewhere in the cache lookup path"
        );
    }
}
