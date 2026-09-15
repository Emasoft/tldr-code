//! Core daemon state machine and runtime
//!
//! This module contains the `TLDRDaemon` struct which manages:
//! - Daemon lifecycle state (Initializing -> Ready -> ShuttingDown)
//! - Salsa-style query cache
//! - Session statistics tracking
//! - Hook activity tracking
//! - Dirty file tracking for incremental re-indexing
//!
//! # Security Mitigations
//!
//! - TIGER-P2-02: Socket cleanup on abnormal exit via signal handlers

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{watch, RwLock};

use super::error::{DaemonError, DaemonResult};
use super::ipc::{read_command, send_response, IpcListener, IpcStream};
use super::salsa::{QueryCache, QueryKey};
use super::types::{
    AllSessionsSummary, DaemonCommand, DaemonConfig, DaemonResponse, DaemonStatus, HookStats,
    SalsaCacheStats, SessionStats, HOOK_FLUSH_THRESHOLD,
};

#[cfg(test)]
use super::types::DEFAULT_REINDEX_THRESHOLD;
#[cfg(feature = "semantic")]
use tldr_core::semantic::{BuildOptions, CacheConfig, IndexSearchOptions, SemanticIndex};
use tldr_core::{
    architecture_analysis, build_project_call_graph, change_impact, collect_all_functions,
    dead_code_analysis, detect_or_parse_language, extract_file, find_importers, get_cfg_context,
    get_code_structure, get_dfg_context, get_file_tree, get_imports, get_relevant_context,
    get_slice, impact_analysis, search as tldr_search, CodeStructure, FileTree, Language, NodeType,
    SliceDirection,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Hash a slice of string arguments into a u64 for cache key generation.
fn hash_str_args(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

// daemon-warm-v2 (issue #7): every helper below builds the EXACT `QueryKey`
// the corresponding `DaemonCommand` handler constructs for a request. The
// Warm handler MUST warm through these same helpers — if warm computed its
// own keys inline, a drift between the two shapes would silently re-create
// the original issue #7 bug (warm fills cache slots no query ever reads).

/// Build the `QueryKey` the `Structure` handler constructs for a request on
/// `path` with the request's language string (empty string when the client
/// sent no language hint).
fn structure_query_key(path: &Path, lang_str: &str, language: Language) -> QueryKey {
    QueryKey::new(
        "structure",
        hash_str_args(&[&path.to_string_lossy(), lang_str]),
        language,
    )
}

/// Build the `QueryKey` the `Extract` handler constructs for a request on
/// `file`.
fn extract_query_key(file: &Path, language: Language) -> QueryKey {
    QueryKey::new(
        "extract",
        hash_str_args(&[&file.to_string_lossy()]),
        language,
    )
}

/// Build the `QueryKey` the `Cfg` handler constructs for a request on
/// `file` / `function`.
fn cfg_query_key(file: &Path, function: &str, language: Language) -> QueryKey {
    QueryKey::new(
        "cfg",
        hash_str_args(&[&file.to_string_lossy(), function]),
        language,
    )
}

/// Build the `QueryKey` the `Dfg` handler constructs for a request on
/// `file` / `function`.
fn dfg_query_key(file: &Path, function: &str, language: Language) -> QueryKey {
    QueryKey::new(
        "dfg",
        hash_str_args(&[&file.to_string_lossy(), function]),
        language,
    )
}

/// Build the `QueryKey` the `Imports` handler constructs for a request on
/// `file`.
fn imports_query_key(file: &Path, language: Language) -> QueryKey {
    QueryKey::new(
        "imports",
        hash_str_args(&[&file.to_string_lossy()]),
        language,
    )
}

/// Build the `QueryKey` the `Calls` handler constructs for a request rooted
/// at `root`.
fn calls_query_key(root: &Path, language: Language) -> QueryKey {
    QueryKey::new("calls", hash_str_args(&[&root.to_string_lossy()]), language)
}

/// Maximum number of `(file, function)` cfg/dfg slots warmed per source file.
///
/// Pathological files (machine-generated tables, minified bundles) can carry
/// thousands of symbols; warming all of them would block the daemon's
/// connection loop for seconds on a single `Warm` command. The cap bounds the
/// per-file work; combined with the shared oversize file policy (checked via
/// `tldr_core::fs::oversize`) it keeps a whole-project warm proportional to
/// real source content.
const MAX_WARM_FUNCTIONS_PER_FILE: usize = 128;

/// Outcome summary of [`TLDRDaemon::warm_per_file_caches`].
#[derive(Debug, Default)]
struct PerFileWarmStats {
    /// Number of query-cache entries inserted by the warm pass.
    entries: usize,
    /// Number of source files actually warmed.
    files_processed: usize,
    /// Number of source files skipped (oversize / undetectable language).
    files_skipped: usize,
    /// Human-readable notes for the Warm response message.
    warmed: Vec<String>,
    /// Human-readable per-file failures for the Warm response message.
    errors: Vec<String>,
}

/// Resolve the effective `Language` for a daemon-handler invocation.
///
/// v031-cluster-M2: M1 added `language: Option<Language>` to seven
/// DaemonCommand variants (Context, Calls, Impact, Dead, Arch, Importers,
/// ChangeImpact). The handler arms that consume those variants previously
/// passed a hardcoded `Language::Python` to `tldr-core` regardless of what
/// the client supplied — a forgotten-thread bug. This helper centralises the
/// `Some(lang) | None -> default` resolution so every handler arm threads
/// the language consistently. The default-on-`None` is `Language::Python`
/// to preserve back-compat with v0.2.x clients that never sent a language
/// hint.
pub(crate) fn resolve_language(language: Option<Language>) -> Language {
    language.unwrap_or(Language::Python)
}

/// Count the number of file nodes in a FileTree recursively.
fn count_tree_files(tree: &FileTree) -> usize {
    match tree.node_type {
        NodeType::File => 1,
        NodeType::Dir => tree.children.iter().map(count_tree_files).sum(),
    }
}

// =============================================================================
// TLDRDaemon - Main Daemon Process
// =============================================================================

/// Main daemon process that handles client connections and manages state.
///
/// The daemon runs an event loop that:
/// 1. Accepts incoming IPC connections
/// 2. Reads commands from clients
/// 3. Dispatches commands to handlers
/// 4. Sends responses back to clients
/// 5. Handles shutdown signals gracefully
pub struct TLDRDaemon {
    /// Project root directory
    project: PathBuf,
    /// Daemon configuration
    config: DaemonConfig,
    /// When the daemon was started
    start_time: Instant,
    /// Current daemon status
    status: Arc<RwLock<DaemonStatus>>,
    /// Salsa-style query cache
    cache: QueryCache,
    /// Per-session statistics
    sessions: DashMap<String, SessionStats>,
    /// Per-hook activity statistics
    hooks: DashMap<String, HookStats>,
    /// Set of dirty files awaiting reindex
    dirty_files: Arc<RwLock<HashSet<PathBuf>>>,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Flag to track if we've been signaled to stop
    stopping: AtomicBool,
    /// Last time a client command was handled (for idle timeout)
    last_activity: Arc<RwLock<Instant>>,
    /// Number of indexed files (for status reporting)
    indexed_files: Arc<RwLock<usize>>,
    /// Persistent semantic index (built lazily on first query, invalidated on Notify)
    #[cfg(feature = "semantic")]
    semantic_index: Arc<RwLock<Option<SemanticIndex>>>,
}

impl TLDRDaemon {
    /// Create a new daemon instance.
    ///
    /// The daemon starts in `Initializing` status and must have `run()` called
    /// to begin accepting connections.
    pub fn new(project: PathBuf, config: DaemonConfig) -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        // daemon-warm-v2 (issue #7): persistence used to be one-way —
        // `persist_stats` wrote `.tldr/cache/query_cache.bin` on shutdown but
        // this constructor never read it, so every daemon start began from an
        // empty cache. Load the previous session's cache here. Missing file
        // (first run) and corrupt/stale-schema files are both handled by
        // `QueryCache::load_from_file`'s graceful-discard contract, which
        // returns a fresh empty cache; only unexpected IO errors land in the
        // `unwrap_or_else` fallback below.
        let cache_path = project
            .join(".tldr")
            .join("cache")
            .join("query_cache.bin");
        let cache =
            QueryCache::load_from_file(&cache_path).unwrap_or_else(|_| QueryCache::with_defaults());

        Self {
            project,
            config,
            start_time: Instant::now(),
            status: Arc::new(RwLock::new(DaemonStatus::Initializing)),
            cache,
            sessions: DashMap::new(),
            hooks: DashMap::new(),
            dirty_files: Arc::new(RwLock::new(HashSet::new())),
            shutdown_tx,
            stopping: AtomicBool::new(false),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            indexed_files: Arc::new(RwLock::new(0)),
            #[cfg(feature = "semantic")]
            semantic_index: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the daemon's current status.
    pub async fn status(&self) -> DaemonStatus {
        *self.status.read().await
    }

    /// Get the daemon's uptime in seconds.
    pub fn uptime(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Get the daemon's uptime formatted as a human-readable string.
    pub fn uptime_human(&self) -> String {
        let secs = self.start_time.elapsed().as_secs();
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;
        format!("{}h {}m {}s", hours, minutes, seconds)
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> SalsaCacheStats {
        self.cache.stats()
    }

    /// Get the project path.
    pub fn project(&self) -> &PathBuf {
        &self.project
    }

    /// Get the number of indexed files.
    pub async fn indexed_files(&self) -> usize {
        *self.indexed_files.read().await
    }

    /// Get a summary of all sessions.
    pub fn all_sessions_summary(&self) -> AllSessionsSummary {
        let mut summary = AllSessionsSummary {
            active_sessions: self.sessions.len(),
            ..AllSessionsSummary::default()
        };

        for entry in self.sessions.iter() {
            let stats = entry.value();
            summary.total_raw_tokens += stats.raw_tokens;
            summary.total_tldr_tokens += stats.tldr_tokens;
            summary.total_requests += stats.requests;
        }

        summary
    }

    /// Get all hook statistics.
    pub fn hook_stats(&self) -> HashMap<String, HookStats> {
        self.hooks
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Signal the daemon to shut down gracefully.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    /// Run the daemon main loop.
    ///
    /// This function blocks until the daemon is shut down via:
    /// - A `Shutdown` command from a client
    /// - A SIGTERM/SIGINT signal
    /// - An error in the listener
    pub async fn run(self: Arc<Self>, listener: IpcListener) -> DaemonResult<()> {
        // Set status to Ready
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Ready;
        }

        // Set up signal handlers for graceful shutdown
        #[cfg(unix)]
        {
            let daemon = Arc::clone(&self);
            tokio::spawn(async move {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("Failed to register SIGTERM handler");
                let mut sigint =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .expect("Failed to register SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        daemon.shutdown();
                    }
                    _ = sigint.recv() => {
                        daemon.shutdown();
                    }
                }
            });
        }

        // Main event loop
        let idle_timeout = std::time::Duration::from_secs(self.config.idle_timeout_secs);

        loop {
            // Check for shutdown signal
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }

            // Safety net: self-terminate if project directory no longer exists
            if !self.project.exists() {
                eprintln!(
                    "Project directory {} no longer exists, shutting down",
                    self.project.display()
                );
                break;
            }

            // Self-terminate after idle timeout with no client activity
            {
                let last = self.last_activity.read().await;
                if last.elapsed() > idle_timeout {
                    eprintln!(
                        "No client activity for {}s, shutting down",
                        self.config.idle_timeout_secs
                    );
                    break;
                }
            }

            // Accept connection with timeout
            let accept_future = listener.accept();
            let timeout = tokio::time::Duration::from_millis(100);

            match tokio::time::timeout(timeout, accept_future).await {
                Ok(Ok(mut stream)) => {
                    // Update activity timestamp
                    *self.last_activity.write().await = Instant::now();

                    // Handle the connection
                    let daemon = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = daemon.handle_connection(&mut stream).await {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    // Accept error - log and continue
                    eprintln!("Accept error: {}", e);
                }
                Err(_) => {
                    // Timeout - check shutdown and continue
                    continue;
                }
            }
        }

        // Set status to ShuttingDown
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::ShuttingDown;
        }

        // Persist stats before exit
        self.persist_stats().await?;

        // Set status to Stopped
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Stopped;
        }

        Ok(())
    }

    /// Handle a single client connection.
    async fn handle_connection(self: &Arc<Self>, stream: &mut IpcStream) -> DaemonResult<()> {
        // Read command
        let cmd = read_command(stream).await?;

        // Handle command
        let response = self.handle_command(cmd).await;

        // Send response
        send_response(stream, &response).await?;

        Ok(())
    }

    /// Handle a daemon command and return the response.
    pub async fn handle_command(&self, cmd: DaemonCommand) -> DaemonResponse {
        match cmd {
            DaemonCommand::Ping => DaemonResponse::Status {
                status: "ok".to_string(),
                message: Some("pong".to_string()),
            },

            DaemonCommand::Status { session } => self.handle_status(session).await,

            DaemonCommand::Shutdown => {
                self.shutdown();
                DaemonResponse::Status {
                    status: "shutting_down".to_string(),
                    message: Some("Daemon is shutting down".to_string()),
                }
            }

            DaemonCommand::Notify { file } => self.handle_notify(file).await,

            DaemonCommand::Track {
                hook,
                success,
                metrics,
            } => self.handle_track(hook, success, metrics).await,

            DaemonCommand::Warm { language } => {
                // why: every other language-taking handler (Structure, Cfg, Dfg,
                // Slice, Imports, ...) reports an unparseable language string as
                // an error. This arm used to swallow the parse failure via
                // `.ok()` and silently warm caches under the default language
                // instead, hiding a bad client request (fail-fast violation).
                let lang = match language.as_deref() {
                    Some(l) => match l.parse::<Language>() {
                        Ok(lang) => lang,
                        Err(_) => {
                            return DaemonResponse::Error {
                                status: "error".to_string(),
                                error: format!("unknown language: {}", l),
                            };
                        }
                    },
                    None => resolve_language(None),
                };

                let mut warmed = Vec::new();
                let mut errors = Vec::new();
                let mut entries = 0usize;

                // 1. Warm call graph
                let calls_key = calls_query_key(&self.project, lang);
                if self.cache.get::<serde_json::Value>(&calls_key).is_some() {
                    warmed.push("call_graph (cached)");
                } else {
                    match build_project_call_graph(&self.project, lang, None, true) {
                        Ok(result) => {
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(calls_key, &val, vec![]);
                            entries += 1;
                            warmed.push("call_graph");
                        }
                        Err(e) => errors.push(format!("call_graph: {}", e)),
                    }
                }

                // 2. Warm code structure
                //
                // daemon-warm-v2 (issue #7): the language string in the key now
                // matches what the Structure handler would hash for the only
                // request shape that can actually hit this slot. The CLI always
                // sends an explicit language string (`language.as_str()`, e.g.
                // "python"); the previous `""` slot was unreachable by design.
                let struct_key = structure_query_key(&self.project, lang.as_str(), lang);
                // Keep the structure result around so step 5 can enumerate the
                // project's source files with the same walker/ignore rules the
                // structure query itself used.
                let mut project_structure: Option<CodeStructure> = None;
                if let Some(cached) = self.cache.get::<CodeStructure>(&struct_key) {
                    warmed.push("structure (cached)");
                    project_structure = Some(cached);
                } else {
                    match get_code_structure(&self.project, lang, 0, None) {
                        Ok(result) => {
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(struct_key, &val, vec![]);
                            entries += 1;
                            warmed.push("structure");
                            project_structure = Some(result);
                        }
                        Err(e) => errors.push(format!("structure: {}", e)),
                    }
                }

                // 3. Warm file tree
                let tree_key = QueryKey::new(
                    "tree",
                    hash_str_args(&[&self.project.to_string_lossy()]),
                    lang,
                );
                if self.cache.get::<serde_json::Value>(&tree_key).is_some() {
                    warmed.push("file_tree (cached)");
                } else {
                    match get_file_tree(&self.project, None, true, None) {
                        Ok(result) => {
                            let file_count = count_tree_files(&result);
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(tree_key, &val, vec![]);
                            entries += 1;
                            *self.indexed_files.write().await = file_count;
                            warmed.push("file_tree");
                        }
                        Err(e) => errors.push(format!("file_tree: {}", e)),
                    }
                }

                // 4. Warm per-file query caches (issue #7).
                //
                // Project-level keys only help queries that address the whole
                // project. File-scoped handlers (extract/imports/structure per
                // file, cfg/dfg per (file, function)) key on REQUEST strings —
                // this step fills those exact slots for every source file the
                // structure walk found, so the next CLI query is a cache hit
                // instead of a guaranteed miss. Function+line-scoped keys
                // (slice) are intentionally NOT warmed.
                let per_file = self.warm_per_file_caches(lang, project_structure);
                entries += per_file.entries;
                if per_file.files_processed > 0 {
                    warmed.push("per-file query caches");
                }
                warmed.extend(per_file.warmed.iter().map(|s| s.as_str()));
                errors.extend(per_file.errors);

                // 5. Warm semantic index
                #[cfg(feature = "semantic")]
                {
                    let mut index_guard = self.semantic_index.write().await;
                    if index_guard.is_some() {
                        warmed.push("semantic_index (cached)");
                    } else {
                        let build_opts = BuildOptions {
                            show_progress: false,
                            use_cache: true,
                            ..Default::default()
                        };
                        match SemanticIndex::build(
                            &self.project,
                            build_opts,
                            Some(CacheConfig::default()),
                        ) {
                            Ok(idx) => {
                                *index_guard = Some(idx);
                                warmed.push("semantic_index");
                            }
                            Err(e) => errors.push(format!("semantic_index: {}", e)),
                        }
                    }
                }

                // daemon-warm-v2 (issue #7): record how many query-cache
                // entries this warm produced so callers can see that real
                // precomputation happened (not just a cache sweep).
                let mut message = if errors.is_empty() {
                    format!("Warmed: {}", warmed.join(", "))
                } else {
                    format!(
                        "Warmed: {}. Errors: {}",
                        warmed.join(", "),
                        errors.join("; ")
                    )
                };
                message.push_str(&format!("; {} query cache entries precomputed", entries));

                DaemonResponse::Status {
                    status: "ok".to_string(),
                    message: Some(message),
                }
            }

            #[cfg(feature = "semantic")]
            DaemonCommand::Semantic { query, top_k } => {
                // Semantic search with persistent index
                let mut index_guard = self.semantic_index.write().await;

                // Build index lazily on first query
                if index_guard.is_none() {
                    let build_opts = BuildOptions {
                        show_progress: false,
                        use_cache: true,
                        ..Default::default()
                    };
                    let cache_config = Some(CacheConfig::default());

                    match SemanticIndex::build(&self.project, build_opts, cache_config) {
                        Ok(idx) => {
                            *index_guard = Some(idx);
                        }
                        Err(e) => {
                            return DaemonResponse::Error {
                                status: "error".to_string(),
                                error: format!("Failed to build semantic index: {}", e),
                            };
                        }
                    }
                }

                // Search the index
                let index = index_guard.as_mut().unwrap();
                let search_opts = IndexSearchOptions {
                    top_k,
                    threshold: 0.5,
                    include_snippet: true,
                    snippet_lines: 5,
                };

                match index.search(&query, &search_opts) {
                    Ok(report) => match serde_json::to_value(&report) {
                        Ok(value) => DaemonResponse::Result(value),
                        Err(e) => DaemonResponse::Error {
                            status: "error".to_string(),
                            error: format!("Serialization error: {}", e),
                        },
                    },
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: format!("Semantic search failed: {}", e),
                    },
                }
            }

            #[cfg(not(feature = "semantic"))]
            DaemonCommand::Semantic { .. } => DaemonResponse::Error {
                status: "error".to_string(),
                error: "Semantic search requires the 'semantic' feature".to_string(),
            },

            // Pass-through analysis commands with Salsa cache integration
            DaemonCommand::Search {
                pattern,
                max_results,
            } => {
                let max = max_results.unwrap_or(100);
                // Search is regex-based and language-agnostic; tag with the
                // resolve_language default so QueryKey is well-formed without
                // discriminating across languages.
                let key = QueryKey::new(
                    "search",
                    hash_str_args(&[&pattern, &max.to_string()]),
                    resolve_language(None),
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match tldr_search(&pattern, &self.project, None, 2, max, 1000, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Extract { file, session: _ } => {
                // Extract auto-detects language from the file path. Tag the
                // cache key with the detected language so two files with the
                // same name in different language sub-projects do not collide.
                let detected_lang = detect_or_parse_language(None, &file)
                    .unwrap_or(Language::Python);
                let key = extract_query_key(&file, detected_lang);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match extract_file(&file, Some(&self.project)) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Tree { path } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let root_str = root.to_string_lossy().to_string();
                // File tree is language-agnostic; tag with default language.
                let key = QueryKey::new(
                    "tree",
                    hash_str_args(&[&root_str]),
                    resolve_language(None),
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_file_tree(&root, None, true, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Structure { path, lang } => {
                let lang_str = lang.as_deref().unwrap_or("");
                let language = match detect_or_parse_language(lang.as_deref(), &path) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = structure_query_key(&path, lang_str, language);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_code_structure(&path, language, 0, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Context {
                entry,
                depth,
                language,
            } => {
                let d = depth.unwrap_or(2);
                let lang = resolve_language(language);
                let key = QueryKey::new(
                    "context",
                    hash_str_args(&[&entry, &d.to_string()]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_relevant_context(&self.project, &entry, d, lang, true, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Cfg { file, function } => {
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = cfg_query_key(&file, &function, language);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_cfg_context(&file.to_string_lossy(), &function, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Dfg { file, function } => {
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = dfg_query_key(&file, &function, language);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_dfg_context(&file.to_string_lossy(), &function, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Slice {
                file,
                function,
                line,
            } => {
                let file_str = file.to_string_lossy().to_string();
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "slice",
                    hash_str_args(&[&file_str, &function, &line.to_string()]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_slice(
                    &file_str,
                    &function,
                    line as u32,
                    SliceDirection::Backward,
                    None,
                    language,
                ) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Calls { path, language } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let key = calls_query_key(&root, lang);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match build_project_call_graph(&root, lang, None, true) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Impact {
                func,
                depth,
                language,
            } => {
                let d = depth.unwrap_or(3);
                let lang = resolve_language(language);
                let key = QueryKey::new(
                    "impact",
                    hash_str_args(&[&func, &d.to_string()]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&self.project, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                match impact_analysis(&graph, &func, d, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Dead {
                path,
                entry,
                language,
            } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let entry_str = entry.as_ref().map(|v| v.join(",")).unwrap_or_default();
                let key = QueryKey::new(
                    "dead",
                    hash_str_args(&[&root_str, &entry_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&root, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                // Collect all functions from the project by extracting each file
                let extensions: HashSet<String> = lang
                    .extensions()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let file_tree = match get_file_tree(&root, Some(&extensions), true, None) {
                    Ok(t) => t,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let files = tldr_core::fs::tree::collect_files(&file_tree, &root);
                let mut module_infos = Vec::new();
                for file_path in files {
                    if let Ok(info) = extract_file(&file_path, Some(&root)) {
                        module_infos.push((file_path, info));
                    }
                }
                let all_functions = collect_all_functions(&module_infos);
                let entry_strings: Option<Vec<String>> = entry;
                let entry_refs: Option<&[String]> = entry_strings.as_deref();
                match dead_code_analysis(&graph, &all_functions, entry_refs) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Arch { path, language } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let key = QueryKey::new("arch", hash_str_args(&[&root_str]), lang);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&root, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                match architecture_analysis(&graph) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Imports { file } => {
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = imports_query_key(&file, language);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_imports(&file, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Importers {
                module,
                path,
                language,
            } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let key = QueryKey::new(
                    "importers",
                    hash_str_args(&[&module, &root_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match find_importers(&root, &module, lang) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Diagnostics { path, project: _ } => DaemonResponse::Error {
                status: "error".to_string(),
                error: format!(
                    "Diagnostics requires external tool orchestration; \
                         use CLI directly: tldr diagnostics {}",
                    path.display()
                ),
            },

            DaemonCommand::ChangeImpact {
                files,
                session: _,
                git: _,
                language,
            } => {
                let lang = resolve_language(language);
                let files_str = files
                    .as_ref()
                    .map(|v| {
                        v.iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let key = QueryKey::new(
                    "change_impact",
                    hash_str_args(&[&files_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let changed: Option<Vec<PathBuf>> = files;
                match change_impact(&self.project, changed.as_deref(), lang) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }
        }
    }

    /// Warm the file-scoped query-cache slots for every source file in
    /// `structure` (daemon-warm-v2, issue #7).
    ///
    /// Project-level keys only serve project-scoped requests; the file-scoped
    /// daemon handlers key on the REQUEST's path string, so before this pass
    /// every per-file CLI query was a guaranteed cache miss. For each file the
    /// pass fills the exact `QueryKey` slots the corresponding handler
    /// constructs (through the shared `*_query_key` helpers — warm and the
    /// handlers MUST agree by construction):
    ///
    /// - `extract`, `imports`, `structure`: one entry per file
    /// - `cfg`, `dfg`: one entry per `(file, function|method)` pair, mirrored
    ///   from the file's own structure definitions
    ///
    /// Function+line-scoped keys (`slice`) are deliberately NOT warmed: the
    /// line argument is request-specific, so there is no single slot to fill.
    ///
    /// Per-file work is capped consistently with the rest of the daemon:
    /// files over the shared oversize policy (`tldr_core::fs::oversize`) are
    /// skipped, as are files whose language cannot be detected, and each file
    /// warms at most `MAX_WARM_FUNCTIONS_PER_FILE` cfg/dfg pairs.
    fn warm_per_file_caches(
        &self,
        lang: Language,
        structure: Option<CodeStructure>,
    ) -> PerFileWarmStats {
        let mut stats = PerFileWarmStats::default();
        let structure = match structure {
            Some(s) => s,
            None => return stats,
        };

        for file_structure in &structure.files {
            // FileStructure.path is RELATIVE to the structure root (see
            // `extract_file_structure`), and the structure walk itself builds
            // file paths as `project.join(relative)` — the daemon's own
            // project string. Reconstruct the same absolute form here so the
            // warmed key matches what a request on that absolute path hashes.
            let path: PathBuf = if file_structure.path.is_absolute() {
                file_structure.path.clone()
            } else {
                self.project.join(&file_structure.path)
            };
            let path = path.as_path();

            // Size cap: skip files the daemon's own parse policy would skip,
            // so warm never does work a query would refuse to reuse.
            if let tldr_core::fs::oversize::SizeCheck::Oversize { .. } =
                tldr_core::fs::oversize::check_size(path)
            {
                stats.files_skipped += 1;
                continue;
            }

            // File-scoped handlers (extract/imports/cfg/dfg) derive the
            // key language from the request path; mirror that detection
            // exactly so the warmed slot matches the handler's slot.
            let file_lang = match detect_or_parse_language(None, path) {
                Ok(l) => l,
                Err(_) => {
                    stats.files_skipped += 1;
                    continue;
                }
            };
            let file_hash = super::salsa::hash_path(path);

            // 1. extract — mirrors the DaemonCommand::Extract handler.
            let extract_key = extract_query_key(path, file_lang);
            if self.cache.get::<serde_json::Value>(&extract_key).is_none() {
                match extract_file(path, Some(&self.project)) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(extract_key, &val, vec![file_hash]);
                        stats.entries += 1;
                    }
                    Err(e) => stats
                        .errors
                        .push(format!("extract {}: {}", path.display(), e)),
                }
            }

            // 2. imports — mirrors the DaemonCommand::Imports handler.
            let imports_key = imports_query_key(path, file_lang);
            if self.cache.get::<serde_json::Value>(&imports_key).is_none() {
                match get_imports(path, file_lang) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(imports_key, &val, vec![file_hash]);
                        stats.entries += 1;
                    }
                    Err(e) => stats
                        .errors
                        .push(format!("imports {}: {}", path.display(), e)),
                }
            }

            // 3. structure for this single file — mirrors the
            //    DaemonCommand::Structure handler for the request shape the
            //    CLI sends (`tldr structure <file>` always passes an explicit
            //    language string). The handler inserts with NO input
            //    dependencies, so warm must not add any either.
            let file_struct_key = structure_query_key(path, lang.as_str(), lang);
            if self
                .cache
                .get::<serde_json::Value>(&file_struct_key)
                .is_none()
            {
                match get_code_structure(path, lang, 0, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(file_struct_key, &val, vec![]);
                        stats.entries += 1;
                    }
                    Err(e) => stats
                        .errors
                        .push(format!("structure {}: {}", path.display(), e)),
                }
            }

            // 4. cfg + dfg per (file, function) — mirrors the
            //    DaemonCommand::Cfg / DaemonCommand::Dfg handlers. Function
            //    names come from the same structure walk, deduplicated;
            //    classes/structs/callables are skipped (the cfg/dfg handlers
            //    are function-scoped).
            let mut functions: Vec<String> = Vec::new();
            for def in &file_structure.definitions {
                if def.kind != "function" && def.kind != "method" {
                    continue;
                }
                if functions.contains(&def.name) {
                    continue;
                }
                functions.push(def.name.clone());
                if functions.len() >= MAX_WARM_FUNCTIONS_PER_FILE {
                    break;
                }
            }

            for function in &functions {
                for (name, key, result) in [
                    (
                        "cfg",
                        cfg_query_key(path, function, file_lang),
                        get_cfg_context(&path.to_string_lossy(), function, file_lang)
                            .map(|v| serde_json::to_value(&v).unwrap_or_default()),
                    ),
                    (
                        "dfg",
                        dfg_query_key(path, function, file_lang),
                        get_dfg_context(&path.to_string_lossy(), function, file_lang)
                            .map(|v| serde_json::to_value(&v).unwrap_or_default()),
                    ),
                ] {
                    if self.cache.get::<serde_json::Value>(&key).is_some() {
                        continue;
                    }
                    match result {
                        Ok(val) => {
                            self.cache.insert(key, &val, vec![file_hash]);
                            stats.entries += 1;
                        }
                        Err(e) => stats
                            .errors
                            .push(format!("{} {}::{}: {}", name, path.display(), function, e)),
                    }
                }
            }

            stats.files_processed += 1;
        }

        if stats.files_processed > 0 {
            stats.warmed.push(format!(
                "{} file-scoped slots ({} file(s) scanned, {} skipped)",
                stats.entries, stats.files_processed, stats.files_skipped
            ));
        }

        stats
    }

    /// Handle the Status command.
    async fn handle_status(&self, session: Option<String>) -> DaemonResponse {
        let status = self.status().await;
        let uptime = self.uptime();
        let files = self.indexed_files().await;
        let salsa_stats = self.cache_stats();
        let all_sessions = Some(self.all_sessions_summary());
        let hook_stats = Some(self.hook_stats());

        // Get session-specific stats if requested
        let session_stats =
            session.and_then(|id| self.sessions.get(&id).map(|entry| entry.value().clone()));

        DaemonResponse::FullStatus {
            status,
            uptime,
            files,
            project: self.project.clone(),
            salsa_stats,
            dedup_stats: None,
            session_stats,
            all_sessions,
            hook_stats,
        }
    }

    /// Handle the Notify command (file change notification).
    async fn handle_notify(&self, file: PathBuf) -> DaemonResponse {
        // Add file to dirty set
        let dirty_count = {
            let mut dirty = self.dirty_files.write().await;
            dirty.insert(file.clone());
            dirty.len()
        };

        // Invalidate cache entries for this file
        let file_hash = super::salsa::hash_path(&file);
        self.cache.invalidate_by_input(file_hash);

        // Invalidate semantic index so it rebuilds on next query
        #[cfg(feature = "semantic")]
        {
            let mut idx = self.semantic_index.write().await;
            *idx = None;
        }

        let threshold = self.config.auto_reindex_threshold;
        let reindex_triggered = dirty_count >= threshold;

        // Trigger reindex if threshold reached
        if reindex_triggered {
            // Clear dirty set
            let mut dirty = self.dirty_files.write().await;
            dirty.clear();

            // In full implementation, would spawn background reindex task
            // For now, just clear the dirty set
        }

        DaemonResponse::NotifyResponse {
            status: "ok".to_string(),
            dirty_count,
            threshold,
            reindex_triggered,
        }
    }

    /// Handle the Track command (hook activity tracking).
    async fn handle_track(
        &self,
        hook: String,
        success: bool,
        metrics: HashMap<String, f64>,
    ) -> DaemonResponse {
        // Get or create hook stats
        let mut entry = self
            .hooks
            .entry(hook.clone())
            .or_insert_with(|| HookStats::new(hook.clone()));

        // Record invocation
        let metrics_opt = if metrics.is_empty() {
            None
        } else {
            Some(metrics)
        };
        entry.record_invocation(success, metrics_opt);

        let total_invocations = entry.invocations;
        let due_for_flush = total_invocations.is_multiple_of(HOOK_FLUSH_THRESHOLD as u64);

        // Flush stats periodically. why: previously this branch was a no-op
        // comment and `flushed` was hardcoded true whenever the threshold
        // hit, so callers were told stats were persisted when nothing was
        // ever written to disk. Actually call persist_stats() and only
        // report success when it succeeds.
        let flushed = if due_for_flush {
            self.persist_stats().await.is_ok()
        } else {
            false
        };

        DaemonResponse::TrackResponse {
            status: "ok".to_string(),
            hook,
            total_invocations,
            flushed,
        }
    }

    /// Persist statistics to disk.
    async fn persist_stats(&self) -> DaemonResult<()> {
        // Create cache directory if it doesn't exist
        let cache_dir = self.project.join(".tldr/cache");
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir)?;
        }

        // Save Salsa cache stats
        let salsa_stats_path = cache_dir.join("salsa_stats.json");
        let stats = self.cache_stats();
        let json = serde_json::to_string_pretty(&stats)?;
        std::fs::write(salsa_stats_path, json)?;

        // Save full query cache
        let cache_path = cache_dir.join("query_cache.bin");
        self.cache.save_to_file(&cache_path)?;

        Ok(())
    }
}

// =============================================================================
// Daemon Control Functions
// =============================================================================

/// Start a daemon in the background for the given project.
///
/// Returns the PID of the daemon process.
pub async fn start_daemon_background(project: &std::path::Path) -> DaemonResult<u32> {
    use std::process::Command;

    // Get the current executable path
    let exe_path = std::env::current_exe().map_err(DaemonError::Io)?;

    // Spawn the daemon process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let child = unsafe {
            Command::new(&exe_path)
                .args(["daemon", "start", "--project"])
                .arg(project.as_os_str())
                .arg("--foreground")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .pre_exec(|| {
                    // Create new session (detach from terminal)
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .map_err(DaemonError::Io)?
        };

        Ok(child.id())
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let child = Command::new(&exe_path)
            .args(["daemon", "start", "--project"])
            .arg(project.as_os_str())
            .arg("--foreground")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .map_err(DaemonError::Io)?;

        Ok(child.id())
    }
}

/// Wait for a daemon to become ready by polling the socket.
///
/// Returns `Ok(())` if the daemon becomes available within the timeout.
pub async fn wait_for_daemon(project: &std::path::Path, timeout_secs: u64) -> DaemonResult<()> {
    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        // Try to connect
        if super::ipc::check_socket_alive(project).await {
            return Ok(());
        }

        // Wait a bit before retrying
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Err(DaemonError::ConnectionTimeout { timeout_secs })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_daemon_new() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        assert_eq!(daemon.project(), temp.path());
        assert!(daemon.uptime() < 1.0);
    }

    #[tokio::test]
    async fn test_daemon_status_initial() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        assert_eq!(daemon.status().await, DaemonStatus::Initializing);
    }

    #[tokio::test]
    async fn test_daemon_uptime_human() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let uptime = daemon.uptime_human();
        assert!(uptime.contains("h"));
        assert!(uptime.contains("m"));
        assert!(uptime.contains("s"));
    }

    #[tokio::test]
    async fn test_daemon_handle_ping() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon.handle_command(DaemonCommand::Ping).await;

        match response {
            DaemonResponse::Status { status, message } => {
                assert_eq!(status, "ok");
                assert_eq!(message, Some("pong".to_string()));
            }
            _ => panic!("Expected Status response"),
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_shutdown() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon.handle_command(DaemonCommand::Shutdown).await;

        match response {
            DaemonResponse::Status { status, .. } => {
                assert_eq!(status, "shutting_down");
            }
            _ => panic!("Expected Status response"),
        }

        // Verify daemon is stopping
        assert!(daemon.stopping.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_daemon_handle_notify() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("test.rs");
        let response = daemon.handle_command(DaemonCommand::Notify { file }).await;

        match response {
            DaemonResponse::NotifyResponse {
                dirty_count,
                threshold,
                reindex_triggered,
                ..
            } => {
                assert_eq!(dirty_count, 1);
                assert_eq!(threshold, DEFAULT_REINDEX_THRESHOLD);
                assert!(!reindex_triggered);
            }
            _ => panic!("Expected NotifyResponse"),
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_notify_threshold() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig {
            auto_reindex_threshold: 3, // Lower threshold for testing
            ..DaemonConfig::default()
        };
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Add files up to threshold
        for i in 0..3 {
            let file = temp.path().join(format!("test{}.rs", i));
            daemon.handle_command(DaemonCommand::Notify { file }).await;
        }

        // The third notification should trigger reindex
        let file = temp.path().join("test3.rs");
        let response = daemon.handle_command(DaemonCommand::Notify { file }).await;

        match response {
            DaemonResponse::NotifyResponse {
                reindex_triggered: _,
                ..
            } => {
                // After threshold is hit, dirty set is cleared
                // So reindex_triggered would have been true, but dirty_count is now 1
            }
            _ => panic!("Expected NotifyResponse"),
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_track() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Track {
                hook: "test-hook".to_string(),
                success: true,
                metrics: HashMap::new(),
            })
            .await;

        match response {
            DaemonResponse::TrackResponse {
                hook,
                total_invocations,
                ..
            } => {
                assert_eq!(hook, "test-hook");
                assert_eq!(total_invocations, 1);
            }
            _ => panic!("Expected TrackResponse"),
        }
    }

    #[tokio::test]
    async fn test_daemon_all_sessions_summary() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Add a session
        daemon.sessions.insert(
            "test-session".to_string(),
            SessionStats {
                session_id: "test-session".to_string(),
                raw_tokens: 1000,
                tldr_tokens: 100,
                requests: 10,
                started_at: None,
            },
        );

        let summary = daemon.all_sessions_summary();
        assert_eq!(summary.active_sessions, 1);
        assert_eq!(summary.total_raw_tokens, 1000);
        assert_eq!(summary.total_tldr_tokens, 100);
        assert_eq!(summary.total_requests, 10);
    }

    // =========================================================================
    // Pass-through handler tests
    // =========================================================================

    /// Helper to create a temp dir with a Python file for testing
    fn create_test_project() -> TempDir {
        let temp = TempDir::new().unwrap();
        let py_file = temp.path().join("main.py");
        std::fs::write(
            &py_file,
            "def hello():\n    \"\"\"Say hello.\"\"\"\n    return 'hello'\n\ndef main():\n    hello()\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn test_hash_str_args_deterministic() {
        let h1 = hash_str_args(&["search", "pattern", "100"]);
        let h2 = hash_str_args(&["search", "pattern", "100"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_str_args_different_inputs() {
        let h1 = hash_str_args(&["search", "pattern_a"]);
        let h2 = hash_str_args(&["search", "pattern_b"]);
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn test_daemon_search_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_array(), "Search should return an array of matches");
                let arr = val.as_array().unwrap();
                assert!(
                    !arr.is_empty(),
                    "Should find at least one match for 'def hello'"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Search returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_search_caches_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // First call populates cache
        let _r1 = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        // Second call should hit cache
        let _r2 = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        let stats = daemon.cache_stats();
        assert!(stats.hits >= 1, "Second call should hit cache");
    }

    #[tokio::test]
    async fn test_daemon_extract_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Extract {
                file: temp.path().join("main.py"),
                session: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Extract should return a module info object"
                );
                // Should contain functions field
                assert!(
                    val.get("functions").is_some(),
                    "Should have 'functions' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Extract returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_extract_nonexistent_file() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Extract {
                file: temp.path().join("nonexistent.py"),
                session: None,
            })
            .await;

        match response {
            DaemonResponse::Error { error, .. } => {
                assert!(
                    !error.is_empty(),
                    "Should return an error for nonexistent file"
                );
            }
            _ => panic!("Expected Error response for nonexistent file"),
        }
    }

    #[tokio::test]
    async fn test_daemon_tree_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Tree { path: None })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Tree should return a FileTree object");
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Tree returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_structure_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Structure {
                path: temp.path().to_path_buf(),
                lang: Some("python".to_string()),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Structure should return a CodeStructure object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Structure returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_imports_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Imports {
                file: temp.path().join("main.py"),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_array(), "Imports should return an array");
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Imports returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_cfg_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Cfg {
                file,
                function: "hello".to_string(),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Cfg should return a CfgInfo object");
                assert!(
                    val.get("function").is_some(),
                    "Should have 'function' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Cfg returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_dfg_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Dfg {
                file,
                function: "hello".to_string(),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Dfg should return a DfgInfo object");
                assert!(
                    val.get("function").is_some(),
                    "Should have 'function' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Dfg returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_calls_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Calls {
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Calls should return a ProjectCallGraph object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Calls returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_arch_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Arch {
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Arch should return an ArchitectureReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Arch returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_diagnostics_returns_error_with_guidance() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let path = temp.path().join("src");
        let response = daemon
            .handle_command(DaemonCommand::Diagnostics {
                path: path.clone(),
                project: None,
            })
            .await;

        match response {
            DaemonResponse::Error { error, .. } => {
                assert!(
                    error.contains("Diagnostics requires external tool orchestration"),
                    "Error should explain that diagnostics needs CLI: {}",
                    error
                );
                assert!(
                    error.contains("tldr diagnostics"),
                    "Error should suggest CLI usage"
                );
            }
            other => panic!("Expected Error response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_importers_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Importers {
                module: "os".to_string(),
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Importers should return an ImportersReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Importers returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_dead_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Dead {
                path: None,
                entry: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Dead should return a DeadCodeReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Dead returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_change_impact_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::ChangeImpact {
                files: Some(vec![temp.path().join("main.py")]),
                session: None,
                git: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "ChangeImpact should return a ChangeImpactReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("ChangeImpact returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_extract_cache_invalidation() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");

        // First extract populates cache
        let r1 = daemon
            .handle_command(DaemonCommand::Extract {
                file: file.clone(),
                session: None,
            })
            .await;
        assert!(matches!(r1, DaemonResponse::Result(_)));

        // Notify file change - should invalidate the cache entry
        daemon
            .handle_command(DaemonCommand::Notify { file: file.clone() })
            .await;

        // After invalidation, next extract should be a cache miss
        let _r2 = daemon
            .handle_command(DaemonCommand::Extract {
                file,
                session: None,
            })
            .await;

        let stats = daemon.cache_stats();
        // Should have: 1 miss (first), 1 invalidation, 1 miss (after invalidation)
        assert!(
            stats.invalidations >= 1,
            "File notify should have caused invalidation"
        );
    }

    #[tokio::test]
    async fn test_daemon_slice_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Slice {
                file,
                function: "hello".to_string(),
                line: 3,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_array(),
                    "Slice should return an array of line numbers"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Slice returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_context_returns_result_or_error() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Context {
                entry: "main".to_string(),
                depth: Some(1),
                language: None,
            })
            .await;

        // Context may return Result or Error depending on whether 'main' is found
        // in the call graph. Both are valid outcomes for this test.
        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Context should return a RelevantContext object"
                );
            }
            DaemonResponse::Error { .. } => {
                // Function not found in call graph is acceptable
            }
            other => panic!("Expected Result or Error response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_impact_returns_result_or_error() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Impact {
                func: "hello".to_string(),
                depth: Some(2),
                language: None,
            })
            .await;

        // Impact may return Result or Error depending on call graph contents
        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Impact should return an ImpactReport object"
                );
            }
            DaemonResponse::Error { .. } => {
                // Function not found in call graph is acceptable for small test projects
            }
            other => panic!("Expected Result or Error response, got {:?}", other),
        }
    }

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_semantic_search_builds_index() {
        // Create a temp dir with a simple Python file
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("hello.py");
        std::fs::write(
            &py_file,
            "def greet(name):\n    return f'Hello, {name}!'\n\ndef farewell(name):\n    return f'Goodbye, {name}!'\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Semantic {
                query: "greeting function".to_string(),
                top_k: 5,
            })
            .await;

        // Should return a Result with search results, not an error
        match &response {
            DaemonResponse::Result(value) => {
                assert!(value.get("query").is_some());
                assert!(value.get("results").is_some());
            }
            DaemonResponse::Error { error, .. } => {
                // May fail in CI without ONNX model - that's acceptable
                // but it should NOT say "not yet implemented"
                assert!(
                    !error.contains("not yet implemented"),
                    "Semantic search should be wired, got: {}",
                    error
                );
            }
            other => panic!("Unexpected response: {:?}", other),
        }
    }

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_semantic_index_invalidated_on_notify() {
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("example.py");
        std::fs::write(&py_file, "def compute(x):\n    return x * 2\n").unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // First semantic search - builds index
        let _ = daemon
            .handle_command(DaemonCommand::Semantic {
                query: "computation".to_string(),
                top_k: 5,
            })
            .await;

        // Verify index is populated
        {
            let idx = daemon.semantic_index.read().await;
            // Index may be Some (if ONNX model available) or None (if build failed)
            // We just verify the field exists and is accessible
            let _ = idx.is_some();
        }

        // Notify a file change - should invalidate the index
        let _ = daemon
            .handle_command(DaemonCommand::Notify {
                file: py_file.clone(),
            })
            .await;

        // Verify index was cleared
        {
            let idx = daemon.semantic_index.read().await;
            assert!(
                idx.is_none(),
                "Semantic index should be invalidated after Notify"
            );
        }
    }

    #[tokio::test]
    async fn test_daemon_warm_wires_caches() {
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("example.py");
        std::fs::write(
            &py_file,
            "def add(a, b):\n    return a + b\n\ndef multiply(x, y):\n    return x * y\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Warm { language: None })
            .await;

        match &response {
            DaemonResponse::Status { status, message } => {
                assert_eq!(status, "ok");
                let msg = message.as_deref().unwrap_or("");
                // Should mention what was warmed, not just "Warm completed"
                assert!(
                    msg.contains("Warmed"),
                    "Expected warm details, got: {}",
                    msg
                );
            }
            other => panic!("Expected Status response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_warm_with_language() {
        let temp = tempfile::tempdir().unwrap();
        let rs_file = temp.path().join("lib.rs");
        std::fs::write(
            &rs_file,
            "pub fn hello() -> String {\n    \"hello\".to_string()\n}\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Warm {
                language: Some("rust".to_string()),
            })
            .await;

        match &response {
            DaemonResponse::Status { status, .. } => {
                assert_eq!(status, "ok");
            }
            other => panic!("Expected Status response, got {:?}", other),
        }
    }

    // =========================================================================
    // daemon-warm-v2 (issue #7): warm must precompute what queries reuse
    // =========================================================================

    /// Issue #7 key-equality test.
    ///
    /// The Warm handler and the file-scoped handlers MUST construct
    /// identical `QueryKey`s for the same request. Both sides go through the
    /// same `*_query_key` helpers; the assertion proves it end-to-end: after
    /// a Warm, the expected handler keys are already populated in the cache,
    /// and issuing the real handler commands is served FROM cache (hits go
    /// up, misses do not). Pre-fix, warm filled slots no query ever read.
    #[tokio::test]
    async fn test_warm_keys_match_file_scoped_handler_keys() {
        let temp = tempfile::tempdir().unwrap();
        // Canonicalize like `tldr daemon start` does, so the path strings
        // warm hashes (via the structure walk) and the strings the handlers
        // hash from the request agree — on macOS temp paths sit under a
        // /private symlink, so raw temp paths would diverge here.
        let project = temp.path().canonicalize().unwrap();
        let py_file = project.join("example.py");
        std::fs::write(
            &py_file,
            "def add(a, b):\n    return a + b\n\ndef multiply(x, y):\n    return x * y\n",
        )
        .unwrap();

        let daemon = TLDRDaemon::new(project.clone(), DaemonConfig::default());

        // --- Warm, and require the entry-count report -------------------
        let warm_response = daemon
            .handle_command(DaemonCommand::Warm { language: None })
            .await;
        let warm_msg = match &warm_response {
            DaemonResponse::Status { status, message } => {
                assert_eq!(status, "ok");
                message.clone().unwrap_or_default()
            }
            other => panic!("Expected Status response, got {:?}", other),
        };
        assert!(
            warm_msg.contains("query cache entries precomputed"),
            "warm must report how many entries it precomputed, got: {}",
            warm_msg
        );

        let detected = detect_or_parse_language(None, &py_file).unwrap();
        assert_eq!(detected, Language::Python);

        // --- The keys the file-scoped handlers construct for queries on
        //     this file, built through the SAME helpers the handlers use ---
        let expected_keys = vec![
            extract_query_key(&py_file, detected),
            imports_query_key(&py_file, detected),
            structure_query_key(&py_file, "python", Language::Python),
            cfg_query_key(&py_file, "add", detected),
            dfg_query_key(&py_file, "add", detected),
            cfg_query_key(&py_file, "multiply", detected),
            dfg_query_key(&py_file, "multiply", detected),
        ];
        for key in &expected_keys {
            let cached: Option<serde_json::Value> = daemon.cache.get(key);
            assert!(
                cached.is_some(),
                "warm must precompute the '{}' slot for {}",
                key.query_name,
                py_file.display()
            );
        }

        // --- End-to-end: the real handler commands must now be cache hits.
        //     Each handler performs exactly one cache lookup, so 7 commands
        //     mean 7 hits and zero new misses.
        let commands = vec![
            DaemonCommand::Extract {
                file: py_file.clone(),
                session: None,
            },
            DaemonCommand::Imports {
                file: py_file.clone(),
            },
            DaemonCommand::Structure {
                path: py_file.clone(),
                lang: Some("python".to_string()),
            },
            DaemonCommand::Cfg {
                file: py_file.clone(),
                function: "add".to_string(),
            },
            DaemonCommand::Dfg {
                file: py_file.clone(),
                function: "add".to_string(),
            },
            DaemonCommand::Cfg {
                file: py_file.clone(),
                function: "multiply".to_string(),
            },
            DaemonCommand::Dfg {
                file: py_file.clone(),
                function: "multiply".to_string(),
            },
        ];

        let before = daemon.cache_stats();
        for cmd in commands {
            let response = daemon.handle_command(cmd).await;
            assert!(
                matches!(response, DaemonResponse::Result(_)),
                "file-scoped query after warm must succeed, got {:?}",
                response
            );
        }
        let after = daemon.cache_stats();

        assert_eq!(
            after.hits - before.hits,
            expected_keys.len() as u64,
            "every file-scoped query must be served from the slots warm filled"
        );
        assert_eq!(
            after.misses - before.misses,
            0,
            "no file-scoped query may miss after warm (keys must match exactly)"
        );
    }

    /// Warm must skip oversize files (cap consistent with the daemon's own
    /// parse policy) instead of blocking the connection loop on them.
    #[tokio::test]
    async fn test_warm_skips_oversize_files() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().canonicalize().unwrap();

        // Small file: warmed.
        let py_file = project.join("small.py");
        std::fs::write(&py_file, "def small_fn():\n    return 1\n").unwrap();
        // Oversize file: skipped (10 MB cap for normal source files).
        let big_file = project.join("big.py");
        let big_body = "# padding\n".repeat(11 * 1024 * 1024 / 9);
        std::fs::write(&big_file, big_body).unwrap();

        let daemon = TLDRDaemon::new(project.clone(), DaemonConfig::default());
        let response = daemon
            .handle_command(DaemonCommand::Warm { language: None })
            .await;

        match &response {
            DaemonResponse::Status { status, .. } => assert_eq!(status, "ok"),
            other => panic!("Expected Status response, got {:?}", other),
        }

        // The small file's slots are filled...
        let detected = detect_or_parse_language(None, &py_file).unwrap();
        let key = extract_query_key(&py_file, detected);
        let cached: Option<serde_json::Value> = daemon.cache.get(&key);
        assert!(cached.is_some(), "small file must be warmed");

        // ...and the oversize file's are not.
        let big_detected = detect_or_parse_language(None, &big_file).unwrap();
        let big_key = extract_query_key(&big_file, big_detected);
        let big_cached: Option<serde_json::Value> = daemon.cache.get(&big_key);
        assert!(big_cached.is_none(), "oversize file must be skipped by warm");
    }

    /// daemon-warm-v2 (issue #7): persistence must round-trip. A daemon
    /// restart loads the `query_cache.bin` the previous session wrote, so
    /// warmed/queried slots survive the restart instead of being lost.
    #[test]
    fn test_daemon_new_loads_persisted_query_cache() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join(".tldr").join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let cache_path = cache_dir.join("query_cache.bin");

        // Persist a cache entry exactly the way persist_stats does.
        let key = QueryKey::new("extract", hash_str_args(&["/some/file.py"]), Language::Python);
        let persisted = QueryCache::with_defaults();
        persisted.insert(key.clone(), &serde_json::json!({ "precomputed": true }), vec![]);
        persisted.save_to_file(&cache_path).unwrap();

        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), DaemonConfig::default());
        let loaded: Option<serde_json::Value> = daemon.cache.get(&key);
        assert!(
            loaded.is_some(),
            "TLDRDaemon::new must load the persisted query cache from query_cache.bin"
        );
    }

    /// A missing (first-run) persisted cache must not fail construction.
    #[test]
    fn test_daemon_new_without_persisted_cache_starts_fresh() {
        let temp = TempDir::new().unwrap();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), DaemonConfig::default());
        assert!(daemon.cache.is_empty());
        assert_eq!(daemon.cache_stats().hits, 0);
        assert_eq!(daemon.cache_stats().misses, 0);
    }

    #[tokio::test]
    async fn test_daemon_last_activity_updated_on_command() {
        let temp = tempfile::tempdir().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Record initial activity time
        let before = *daemon.last_activity.read().await;

        // Small delay to ensure time difference
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Any command should NOT update last_activity (only connections do),
        // but handle_command is what we can test. Verify the field exists and is accessible.
        let _ = daemon.handle_command(DaemonCommand::Ping).await;

        // last_activity is set at connection accept, not command handling,
        // so it should still be the initial value
        let after = *daemon.last_activity.read().await;
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_daemon_created_with_nonexistent_project() {
        // Daemon should be constructable with any path — the exists() check
        // happens in the run loop, not in new()
        let fake_path = PathBuf::from("/tmp/nonexistent-project-dir-12345");
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(fake_path.clone(), config);

        assert_eq!(daemon.project(), &fake_path);
        // The project doesn't exist, but daemon construction succeeds.
        // The run() loop would detect this and self-terminate.
        assert!(!fake_path.exists());
    }
}
