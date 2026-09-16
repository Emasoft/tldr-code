//! Multi-daemon registry (v0.3.0 VAL-003).
//!
//! Replaces v0.2.2's single-slot `daemon-active.json` with a multi-entry
//! `daemon-registry.json` file. Each entry records one running daemon; the
//! file always contains the union of all live daemons known to the user.
//!
//! # Concurrency (option c — bounded compare-and-swap retry)
//!
//! The per-project flock at [`super::pid::try_acquire_lock`] (pid.rs:261,
//! `libc::flock(LOCK_EX | LOCK_NB)`) protects the SOCKET file, NOT the
//! registry. Two `daemon start` calls from DIFFERENT projects bypass that
//! flock and race read-modify-write the shared registry.
//!
//! Rather than introducing a new advisory-lock dependency, this module uses
//! a bounded compare-and-swap retry loop:
//!
//! 1. Read the registry file's mtime (pre-mtime).
//! 2. Read the registry, modify in-memory.
//! 3. Re-read the mtime (post-mtime).
//! 4. If pre == post (no concurrent writer landed): atomically write
//!    (tmp + rename) and return.
//! 5. Otherwise: retry, up to 3 attempts. On exhaustion return
//!    [`std::io::ErrorKind::WouldBlock`].
//!
//! In practice, a 3-attempt cap is sufficient because each attempt's window
//! is microseconds and the contender pool is bounded by the number of
//! projects on disk.
//!
//! # Migration from v0.2.x
//!
//! On first registry access, [`migrate_from_active_if_needed`] looks for the
//! legacy `daemon-active.json`; if present and its PID is alive, it is
//! converted into a registry entry and the legacy file is deleted. If the
//! PID is dead, the legacy file is also removed (stale record cleanup).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One live-daemon record in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRegistryEntry {
    /// Canonicalized project path the daemon was started with.
    pub project: PathBuf,
    /// PID of the daemon process. Validated via `kill(pid, 0)` on Unix.
    pub pid: u32,
    /// Path to the daemon's IPC socket (informational).
    pub socket: PathBuf,
    /// RFC3339 timestamp recorded at registration time.
    pub started_at: String,
}

/// On-disk registry shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonRegistry {
    /// All live daemons known at the time of read.
    pub daemons: Vec<DaemonRegistryEntry>,
}

const CAS_RETRY_ATTEMPTS: usize = 3;

/// Path to the daemon registry file.
///
/// Resolution order:
/// 1. `TLDR_DAEMON_REGISTRY_DIR` env override (used by tests for isolation).
/// 2. `<dirs::cache_dir()>/tldr/daemon-registry.json`.
/// 3. `./.cache/tldr/daemon-registry.json` fallback (mirrors `daemon_active`).
pub fn registry_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("TLDR_DAEMON_REGISTRY_DIR") {
        return PathBuf::from(dir).join("daemon-registry.json");
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("tldr")
        .join("daemon-registry.json")
}

/// Atomically write `registry` to [`registry_file_path`] via tmp + rename.
fn write_registry_atomic(registry: &DaemonRegistry) -> std::io::Result<()> {
    let path = registry_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(registry).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Read the registry from disk, run one-shot v0.2.x migration if needed,
/// and prune dead-PID entries. The pruned-and-migrated registry is also
/// written back so subsequent reads observe a clean state.
///
/// Auxiliary state — a missing/corrupt file simply yields an empty registry.
pub fn read_registry() -> DaemonRegistry {
    migrate_from_active_if_needed();
    let path = registry_file_path();
    let mut registry = match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => DaemonRegistry::default(),
    };
    let original_len = registry.daemons.len();
    registry.daemons.retain(|d| is_pid_alive(d.pid));
    if registry.daemons.len() != original_len {
        // Pruned at least one stale entry — flush back. Best-effort.
        let _ = write_registry_atomic(&registry);
    }
    registry
}

/// Convenience: list of live entries (after pruning + migration).
pub fn live_entries() -> Vec<DaemonRegistryEntry> {
    read_registry().daemons
}

/// Look up a registry entry by canonicalized project path.
pub fn find_entry(project: &Path) -> Option<DaemonRegistryEntry> {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    read_registry()
        .daemons
        .into_iter()
        .find(|d| d.project == canon)
}

/// Add (or replace) the registry entry for `project` via bounded
/// compare-and-swap.
///
/// Returns `Err(io::ErrorKind::WouldBlock)` if [`CAS_RETRY_ATTEMPTS`] are
/// exhausted under contention.
pub fn add_entry(project: &Path, pid: u32, socket: &Path) -> std::io::Result<()> {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let path = registry_file_path();

    for _attempt in 0..CAS_RETRY_ATTEMPTS {
        let pre_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        let mut registry = read_registry();
        registry.daemons.retain(|d| d.project != canon);
        registry.daemons.push(DaemonRegistryEntry {
            project: canon.clone(),
            pid,
            socket: socket.to_path_buf(),
            started_at: chrono::Utc::now().to_rfc3339(),
        });
        let post_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if pre_mtime == post_mtime {
            return write_registry_atomic(&registry);
        }
        // Contention: another writer landed between our read and our
        // intended write. Retry.
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "daemon registry contended after 3 CAS attempts",
    ))
}

/// Remove the registry entry for `project` via bounded compare-and-swap.
pub fn remove_entry(project: &Path) -> std::io::Result<()> {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let path = registry_file_path();

    for _attempt in 0..CAS_RETRY_ATTEMPTS {
        let pre_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        let mut registry = read_registry();
        let before = registry.daemons.len();
        registry.daemons.retain(|d| d.project != canon);
        if registry.daemons.len() == before {
            // Nothing to remove — caller's invariant satisfied.
            return Ok(());
        }
        let post_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if pre_mtime == post_mtime {
            return write_registry_atomic(&registry);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "daemon registry contended after 3 CAS attempts",
    ))
}

/// One-shot migration from v0.2.x `daemon-active.json`.
///
/// Triggered on first registry access. If a legacy daemon-active.json exists
/// and its PID is alive, append it as a registry entry. Either way, delete
/// the legacy file so subsequent registry reads do not re-trigger migration.
fn migrate_from_active_if_needed() {
    let registry_path = registry_file_path();
    if registry_path.exists() {
        return;
    }

    // Use the same parent dir as the registry for the legacy file lookup.
    // This matches the production layout (both files share `<cache>/tldr/`)
    // AND the test layout (both share the env-overridden directory).
    let active_path = match registry_path.parent() {
        Some(p) => p.join("daemon-active.json"),
        None => return,
    };
    if !active_path.exists() {
        return;
    }

    // Best-effort: read + validate + migrate. Failures collapse to "delete
    // the legacy file and move on" so the user is not stuck with the
    // legacy file blocking new registry creation.
    let migrated = match std::fs::read_to_string(&active_path) {
        Ok(content) => match serde_json::from_str::<super::daemon_active::DaemonActive>(&content) {
            Ok(active) if is_pid_alive(active.pid) => Some(DaemonRegistryEntry {
                project: active.project,
                pid: active.pid,
                socket: active.socket,
                started_at: chrono::Utc::now().to_rfc3339(),
            }),
            _ => None,
        },
        Err(_) => None,
    };

    if let Some(entry) = migrated {
        let registry = DaemonRegistry {
            daemons: vec![entry],
        };
        let _ = write_registry_atomic(&registry);
    }
    // Always delete the legacy file once migration has been attempted —
    // a dead-PID record is stale and should not block future registry
    // creation.
    let _ = std::fs::remove_file(&active_path);
}

/// Best-effort PID liveness check. Mirrors `daemon_active::is_pid_alive`.
#[cfg(unix)]
fn is_pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    )
}

#[cfg(not(unix))]
fn is_pid_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serialize tests that mutate the process-global TLDR_DAEMON_REGISTRY_DIR
    /// env var. Without this, parallel tests stomp on each other's overrides
    /// and `add_entry` sees a NotFound when another thread has already
    /// removed the env var (registry dir resolves to a non-existent default).
    static REGISTRY_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: scope an env var override for the duration of a closure.
    fn with_registry_dir<F: FnOnce(&Path)>(prefix: &str, f: F) {
        // Hold the lock for the entire body so set_var / f / remove_var
        // run atomically with respect to other tests in this module.
        let _guard = REGISTRY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().expect("tempdir");
        std::env::set_var("TLDR_DAEMON_REGISTRY_DIR", tmp.path());
        let _prefix = prefix;
        f(tmp.path());
        std::env::remove_var("TLDR_DAEMON_REGISTRY_DIR");
    }

    #[test]
    fn registry_path_honors_env_override() {
        with_registry_dir("env-override", |dir| {
            let path = registry_file_path();
            assert_eq!(path, dir.join("daemon-registry.json"));
        });
    }

    #[test]
    fn read_registry_on_missing_file_returns_empty() {
        with_registry_dir("missing-file", |_dir| {
            let r = read_registry();
            assert!(r.daemons.is_empty());
        });
    }

    #[test]
    fn add_then_find_round_trips() {
        with_registry_dir("round-trip", |dir| {
            let project = dir.join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let socket = dir.join("proj.sock");
            add_entry(&project, std::process::id(), &socket).expect("add");
            let found = find_entry(&project).expect("entry should exist");
            assert_eq!(found.pid, std::process::id());
            assert_eq!(found.socket, socket);
        });
    }

    #[test]
    fn remove_entry_drops_record() {
        with_registry_dir("remove", |dir| {
            let project = dir.join("proj-r");
            std::fs::create_dir_all(&project).unwrap();
            let socket = dir.join("proj-r.sock");
            add_entry(&project, std::process::id(), &socket).expect("add");
            remove_entry(&project).expect("remove");
            assert!(find_entry(&project).is_none());
        });
    }

    #[test]
    fn dead_pid_entries_are_pruned_on_read() {
        with_registry_dir("prune", |dir| {
            let project = dir.join("proj-dead");
            std::fs::create_dir_all(&project).unwrap();
            // Spawn `true` and reap → PID is now definitely dead.
            let mut child = std::process::Command::new("true")
                .spawn()
                .expect("spawn true");
            let dead_pid = child.id();
            let _ = child.wait();
            // Inject a dead-pid entry directly via add_entry (which writes
            // the PID we hand it; the prune happens on subsequent reads).
            let socket = dir.join("proj-dead.sock");
            add_entry(&project, dead_pid, &socket).expect("add");
            let live = live_entries();
            assert!(
                live.iter().all(|d| d.pid != dead_pid),
                "dead PID entry should have been pruned on read"
            );
        });
    }
}
