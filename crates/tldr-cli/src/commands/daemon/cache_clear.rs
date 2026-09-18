//! Cache clear command implementation
//!
//! CLI command: `tldr cache clear [--project PATH]`
//!
//! Clears the cache for a TLDR project:
//! 1. If daemon is running, gracefully stops it and waits for it to exit
//!    (issue #62). The daemon is LEFT STOPPED — restart it with
//!    `tldr daemon start`.
//! 2. Deletes cache files in `.tldr/cache/`
//! 3. Reports cleared size
//!
//! The wait-for-exit matters: the daemon's shutdown path persists
//! `.tldr/cache/salsa_stats.json` + `query_cache.bin`, so deleting before the
//! daemon is gone lets its shutdown persist recreate the files right after
//! the clear (the cache appeared "magically restored").
//!
//! Files removed:
//! - salsa_cache.bin (Salsa query cache)
//! - salsa_stats.json (legacy stats file)
//! - call_graph.json (call graph cache)
//! - *.pkl files (pickle files, if any)
//! - Any other files in the cache directory

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use serde::Serialize;

use crate::output::OutputFormat;

use super::daemon_active::remove_active_for_project;
use super::daemon_registry::remove_entry;
use super::error::DaemonResult;
use super::ipc::{check_socket_alive, cleanup_socket, send_command};
use super::pid::{cleanup_stale_pid, compute_pid_path};
use super::types::DaemonCommand;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Arguments for the `cache clear` command.
#[derive(Debug, Clone, Args)]
pub struct CacheClearArgs {
    /// Project root directory (default: current directory)
    #[arg(long, short = 'p', default_value = ".")]
    pub project: PathBuf,
}

// =============================================================================
// Output Types
// =============================================================================

/// Output structure for cache clear command.
#[derive(Debug, Clone, Serialize)]
pub struct CacheClearOutput {
    /// Status of the operation
    pub status: String,
    /// Number of files removed
    pub files_removed: usize,
    /// Bytes freed
    pub bytes_freed: u64,
    /// Human-readable size freed
    pub size_freed_human: String,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// =============================================================================
// Command Implementation
// =============================================================================

impl CacheClearArgs {
    /// Run the cache clear command.
    pub fn run(&self, format: OutputFormat, quiet: bool) -> anyhow::Result<()> {
        // Create a new tokio runtime for the async operations
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(self.run_async(format, quiet))
    }

    /// Async implementation of the cache clear command.
    async fn run_async(&self, format: OutputFormat, quiet: bool) -> anyhow::Result<()> {
        // Resolve project path to absolute
        let project = self.project.canonicalize().unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(&self.project)
        });

        // Gracefully stop the daemon first if it's running — and WAIT for it
        // to actually exit before deleting anything (issue #62). The daemon
        // is left stopped; restart it with `tldr daemon start`.
        self.stop_daemon_and_wait(&project).await;

        // Clear cache files
        let (files_removed, bytes_freed) = self.clear_cache_files(&project)?;

        let output = if files_removed == 0 {
            CacheClearOutput {
                status: "ok".to_string(),
                files_removed: 0,
                bytes_freed: 0,
                size_freed_human: "0 B".to_string(),
                message: Some("No cache directory found".to_string()),
            }
        } else {
            CacheClearOutput {
                status: "ok".to_string(),
                files_removed,
                bytes_freed,
                size_freed_human: format_bytes(bytes_freed),
                message: Some(format!("Cache cleared: {} file(s) removed", files_removed)),
            }
        };

        self.print_output(&output, format, quiet)
    }

    /// Gracefully stop the daemon for `project` and wait for it to actually
    /// exit before returning (issue #62).
    ///
    /// Semantics: if a daemon is running for this project, `cache clear`
    /// stops it first and LEAVES IT STOPPED — restart with
    /// `tldr daemon start --project <path>`.
    ///
    /// why: the daemon's shutdown path calls `persist_stats()`, which writes
    /// `.tldr/cache/salsa_stats.json` + `query_cache.bin` (recreating the
    /// directory if needed). The previous fire-and-forget `Shutdown` returned
    /// as soon as the daemon ACKed — but the daemon ACKs BEFORE its event
    /// loop breaks and the persist runs — so the immediately-following
    /// `clear_cache_files()` deleted the files and the daemon's late persist
    /// recreated them: the cache appeared "magically restored" (issue #62).
    ///
    /// This mirrors the proven `daemon stop` pattern: send `Shutdown`, then
    /// poll `check_socket_alive()` with a bounded 5s budget and only proceed
    /// once the daemon is actually gone. The wait happens ONLY when the
    /// shutdown command was really delivered, so the common no-daemon path
    /// stays zero-latency. If the daemon ignores the shutdown within the
    /// budget, clear proceeds best-effort (same residual behaviour as
    /// `daemon stop`).
    async fn stop_daemon_and_wait(&self, project: &Path) {
        let cmd = DaemonCommand::Shutdown;
        // Ignore connection errors - daemon might not be running.
        if send_command(project, &cmd).await.is_ok() {
            // Wait for the daemon to actually stop (5 seconds max).
            let mut retries = 0;
            while retries < 50 {
                if !check_socket_alive(project).await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                retries += 1;
            }

            // Clean up the stopped daemon's records (socket file, PID file,
            // legacy discovery record + v0.3.0 registry entry) — the same
            // project-guarded removal `daemon stop` performs, so `daemon
            // status`/`list` don't report a daemon that is no longer there.
            let _ = cleanup_socket(project);
            let pid_path = compute_pid_path(project);
            let _ = cleanup_stale_pid(&pid_path);
            let _ = remove_active_for_project(project);
            let _ = remove_entry(project);
        }
    }

    /// Clear all cache files in the project's .tldr/cache/ directory.
    fn clear_cache_files(&self, project: &Path) -> DaemonResult<(usize, u64)> {
        let cache_dir = project.join(".tldr").join("cache");

        if !cache_dir.exists() {
            return Ok((0, 0));
        }

        let mut files_removed = 0;
        let mut bytes_freed = 0u64;

        // Collect files to remove
        let entries: Vec<_> = fs::read_dir(&cache_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.metadata().map(|m| m.is_file()).unwrap_or(false))
            .collect();

        // Remove each file
        for entry in entries {
            let path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                bytes_freed += metadata.len();
            }
            if fs::remove_file(&path).is_ok() {
                files_removed += 1;
            }
        }

        Ok((files_removed, bytes_freed))
    }

    /// Print output in the requested format.
    fn print_output(
        &self,
        output: &CacheClearOutput,
        format: OutputFormat,
        quiet: bool,
    ) -> anyhow::Result<()> {
        if quiet {
            return Ok(());
        }

        match format {
            OutputFormat::Json | OutputFormat::Compact => {
                println!("{}", serde_json::to_string_pretty(output)?);
            }
            OutputFormat::Text | OutputFormat::Sarif | OutputFormat::Dot => {
                if output.files_removed == 0 {
                    println!("No cache directory found");
                } else {
                    println!(
                        "Cache cleared: {} file(s) removed ({})",
                        output.files_removed, output.size_freed_human
                    );
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Start an in-process daemon for `project` on a freshly bound IPC
    /// listener and wait until its socket is connectable (Ready).
    ///
    /// Returns the daemon's `run()` join handle; the daemon exits after a
    /// `Shutdown` command. This exercises the exact same `TLDRDaemon::run`
    /// code path the `tldr-daemon` foreground runner uses, without spawning
    /// an OS process (no daemon left behind if the test fails — the task dies
    /// with the test process).
    async fn start_in_process_daemon(project: &Path) -> tokio::task::JoinHandle<DaemonResult<()>> {
        use crate::commands::daemon::daemon_impl::TLDRDaemon;
        use crate::commands::daemon::ipc::{check_socket_alive, IpcListener};
        use crate::commands::daemon::types::DaemonConfig;
        use std::sync::Arc;
        use std::time::Instant;

        let listener = IpcListener::bind(project).await.unwrap();
        let daemon = TLDRDaemon::new(project.to_path_buf(), DaemonConfig::default());
        let handle = tokio::spawn(async move { Arc::new(daemon).run(listener).await });

        // The socket is connectable as soon as the listener is bound; wait
        // for the daemon to observe it (bounded) so the shutdown round-trip
        // below is deterministic.
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

    /// Issue #62: `cache clear` with a RUNNING daemon must leave the cache
    /// directory empty. The daemon's shutdown path calls `persist_stats()`,
    /// which writes `.tldr/cache/salsa_stats.json` + `query_cache.bin` and
    /// recreates the directory; if clear deletes the files before that
    /// persist runs, the daemon recreates them and the cache appears
    /// "magically restored". The fix: clear performs a graceful daemon
    /// shutdown (waiting for exit) BEFORE deleting.
    #[tokio::test]
    async fn test_cache_clear_with_running_daemon_leaves_cache_empty() {
        let temp = TempDir::new().unwrap();
        // Canonicalize exactly like run_async does so the socket path hash
        // matches between daemon and client (macOS /var → /private/var).
        let project = temp.path().canonicalize().unwrap();
        let cache_dir = project.join(".tldr").join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("salsa_stats.json"), "{}").unwrap();

        let daemon_task = start_in_process_daemon(&project).await;

        let args = CacheClearArgs {
            project: project.clone(),
        };
        args.run_async(OutputFormat::Json, true).await.unwrap();

        // The daemon must have exited (shutdown was requested by clear).
        let joined = tokio::time::timeout(Duration::from_secs(10), daemon_task).await;
        assert!(joined.is_ok(), "daemon did not shut down after cache clear");

        // THE REGRESSION: no file may exist in the cache directory after the
        // clear. A daemon-side late `persist_stats()` re-creating
        // salsa_stats.json / query_cache.bin fails this assertion.
        let leftovers: Vec<std::path::PathBuf> = fs::read_dir(&cache_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "cache files were recreated after clear: {:?}",
            leftovers
        );
    }

    /// Issue #62 (control): `cache clear` WITHOUT a daemon must keep its
    /// existing behaviour — files are deleted and never reappear.
    #[tokio::test]
    async fn test_cache_clear_without_daemon_files_removed_and_not_recreated() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let cache_dir = project.join(".tldr").join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("salsa_stats.json"), "{}").unwrap();
        fs::write(cache_dir.join("query_cache.bin"), "payload").unwrap();

        let args = CacheClearArgs {
            project: project.clone(),
        };
        args.run_async(OutputFormat::Json, true).await.unwrap();

        // Give any hypothetical late writer time to interfere.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let leftovers: Vec<std::path::PathBuf> = fs::read_dir(&cache_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "cache files survived clear with no daemon: {:?}",
            leftovers
        );
    }

    #[test]
    fn test_cache_clear_args_default() {
        let args = CacheClearArgs {
            project: PathBuf::from("."),
        };
        assert_eq!(args.project, PathBuf::from("."));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_cache_clear_output_serialization() {
        let output = CacheClearOutput {
            status: "ok".to_string(),
            files_removed: 26,
            bytes_freed: 1048576,
            size_freed_human: "1.0 MB".to_string(),
            message: Some("Cache cleared: 26 file(s) removed".to_string()),
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("ok"));
        assert!(json.contains("26"));
        assert!(json.contains("1048576"));
        assert!(json.contains("1.0 MB"));
    }

    #[test]
    fn test_cache_clear_output_empty() {
        let output = CacheClearOutput {
            status: "ok".to_string(),
            files_removed: 0,
            bytes_freed: 0,
            size_freed_human: "0 B".to_string(),
            message: Some("No cache directory found".to_string()),
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("No cache directory found"));
    }

    #[test]
    fn test_clear_cache_files_no_cache_dir() {
        let temp = TempDir::new().unwrap();
        let args = CacheClearArgs {
            project: temp.path().to_path_buf(),
        };

        let result = args.clear_cache_files(temp.path());
        assert!(result.is_ok());
        let (files, bytes) = result.unwrap();
        assert_eq!(files, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_clear_cache_files_with_files() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join(".tldr").join("cache");
        fs::create_dir_all(&cache_dir).unwrap();

        // Create some test files
        fs::write(cache_dir.join("salsa_cache.bin"), "test data 1").unwrap();
        fs::write(cache_dir.join("call_graph.json"), r#"{"edges":[]}"#).unwrap();
        fs::write(cache_dir.join("test.pkl"), "pickle data").unwrap();

        let args = CacheClearArgs {
            project: temp.path().to_path_buf(),
        };

        let result = args.clear_cache_files(temp.path());
        assert!(result.is_ok());
        let (files, bytes) = result.unwrap();
        assert_eq!(files, 3);
        assert!(bytes > 0);

        // Verify files are gone
        assert!(!cache_dir.join("salsa_cache.bin").exists());
        assert!(!cache_dir.join("call_graph.json").exists());
        assert!(!cache_dir.join("test.pkl").exists());
    }

    #[test]
    fn test_clear_cache_files_preserves_directory() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join(".tldr").join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("test.bin"), "data").unwrap();

        let args = CacheClearArgs {
            project: temp.path().to_path_buf(),
        };

        args.clear_cache_files(temp.path()).unwrap();

        // Cache directory should still exist (only files removed)
        assert!(cache_dir.exists());
    }

    #[tokio::test]
    async fn test_cache_clear_no_cache() {
        let temp = TempDir::new().unwrap();
        let args = CacheClearArgs {
            project: temp.path().to_path_buf(),
        };

        // Should succeed even with no cache
        let result = args.run_async(OutputFormat::Json, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_clear_with_files() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join(".tldr").join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("test.bin"), "test data").unwrap();

        let args = CacheClearArgs {
            project: temp.path().to_path_buf(),
        };

        let result = args.run_async(OutputFormat::Json, true).await;
        assert!(result.is_ok());

        // File should be removed
        assert!(!cache_dir.join("test.bin").exists());
    }
}
