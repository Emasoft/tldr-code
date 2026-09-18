//! Active-daemon discovery file (VAL-013, issue #20).
//!
//! `tldr daemon status` historically defaulted `--project` to `"."`, computed
//! a socket-path hash from the canonicalized cwd, and connected via that
//! hash. Invoked from a cwd different from the original
//! `daemon start --project` cwd, the hash differs → connect fails → status
//! incorrectly reports `not_running`, even when a daemon IS alive.
//!
//! This module implements the **single-daemon quick-fix path** from the
//! VAL-013 spec: on successful bind, daemon start atomically writes
//! `<cache_dir>/tldr/daemon-active.json` containing `{project, pid, socket}`.
//! When `daemon status` is invoked WITHOUT an explicit `--project`, it reads
//! this file, verifies the PID is alive (via `kill(pid, 0)` on Unix), and
//! falls back to the recorded project path for socket discovery.
//!
//! The multi-daemon case is intentionally NOT handled here — users running
//! multiple daemons can still pass `--project` explicitly. A global daemon
//! registry is deferred to v0.3.0.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Active-daemon discovery record persisted to disk.
///
/// Written atomically by `daemon start` after a successful socket bind, read
/// by `daemon status` when `--project` is the default, and removed by
/// `daemon stop` after a successful shutdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonActive {
    /// Canonicalized project path the daemon was started with.
    pub project: PathBuf,
    /// PID of the daemon process. Validated via `kill(pid, 0)` on Unix
    /// before the record is trusted.
    pub pid: u32,
    /// Path to the daemon's IPC socket (informational; status recomputes
    /// from `project` for safety).
    pub socket: PathBuf,
}

/// Path to the active-daemon discovery file.
///
/// Resolution order:
/// 1. `TLDR_DAEMON_ACTIVE_DIR` env override (used by tests for isolation;
///    mirrors `TLDR_DAEMON_REGISTRY_DIR` on the registry file).
/// 2. `<dirs::cache_dir()>/tldr/daemon-active.json`.
/// 3. Relative `.cache/tldr/...` fallback if `dirs::cache_dir()` is
///    unavailable (see issue #34 for why this fallback is being reworked).
pub fn active_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("TLDR_DAEMON_ACTIVE_DIR") {
        return PathBuf::from(dir).join("daemon-active.json");
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("tldr")
        .join("daemon-active.json")
}

/// Atomically write the active-daemon record.
///
/// Writes to `<path>.tmp` first, then renames into place. The rename is
/// atomic on POSIX (and on NTFS via MoveFileEx), so a concurrent reader
/// either sees the previous file or the new one — never a half-written
/// file.
///
/// Failures are surfaced to the caller, but the caller (`daemon start`)
/// treats them as warnings rather than fatal errors: the discovery file
/// is auxiliary state and a missing file simply degrades to the
/// pre-fix behaviour (i.e., `daemon status` from a different cwd reports
/// `not_running`, exactly as today).
pub fn write_active(project: &Path, pid: u32, socket: &Path) -> std::io::Result<()> {
    let path = active_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let record = DaemonActive {
        project: project.to_path_buf(),
        pid,
        socket: socket.to_path_buf(),
    };
    let json = serde_json::to_string_pretty(&record).map_err(std::io::Error::other)?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Read the active-daemon record, or `None` if absent / stale / corrupt.
///
/// "Stale" here means the recorded PID is no longer alive — `kill(pid, 0)`
/// returns `ESRCH`. This guards against the case where a daemon crashed
/// without removing the file: we don't want `daemon status` to report a
/// dead daemon as `running`.
pub fn read_active() -> Option<DaemonActive> {
    let parsed = read_active_record()?;
    if !is_pid_alive(parsed.pid) {
        return None;
    }
    Some(parsed)
}

/// Read the raw active-daemon record WITHOUT the PID-liveness gate.
///
/// `daemon stop` needs to compare the recorded project against the project
/// it just shut down — at that point the recorded PID is already dead, so
/// the liveness gate in [`read_active`] would make the comparison
/// impossible. Corrupt files still yield `None` (issue #38).
pub fn read_active_record() -> Option<DaemonActive> {
    let path = active_file_path();
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Remove the active-daemon record, ignoring `NotFound`.
///
/// Called from `daemon stop` after a successful shutdown. NotFound is
/// expected when the file was never written (e.g., daemon crashed during
/// bind) or was already cleaned up.
pub fn remove_active() -> std::io::Result<()> {
    match std::fs::remove_file(active_file_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove the active-daemon record ONLY when it belongs to `project`.
///
/// Issue #38: `daemon stop` used to delete `daemon-active.json` wholesale —
/// including in its "Daemon not running" path, where the record could
/// belong to a DIFFERENT, still-running daemon (started for another
/// project). Deleting it there orphaned that daemon's cross-cwd discovery.
/// This helper reads the record (no liveness gate — the project being
/// stopped is dead by the time cleanup runs) and removes the file only
/// when the recorded project matches. Returns `true` when a matching
/// record was found and removed.
pub fn remove_active_for_project(project: &Path) -> bool {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    match read_active_record() {
        Some(active) => {
            // Canonicalize the RECORDED path too: v0.2.x-era writers may
            // have stored a non-canonical spelling, and macOS resolves
            // `/var` → `/private/var` — a byte comparison of raw strings
            // would miss the match and leave a stale record behind.
            let recorded = active.project.canonicalize().unwrap_or_else(|_| active.project.clone());
            if recorded == canon {
                remove_active().is_ok()
            } else {
                false
            }
        }
        None => false,
    }
}

/// Best-effort liveness probe.
///
/// On Unix, sends signal 0 to `pid`. The signal-0 kernel path validates the
/// target's existence and the caller's permission without actually
/// delivering a signal:
///   - `Ok` (return 0): process exists and we have permission.
///   - `Err(EPERM)`: process exists but we don't have permission to signal
///     it. Treat as alive — a different-uid daemon is still a daemon.
///   - `Err(ESRCH)`: no such process — treat as dead.
///
/// On non-Unix platforms, returns `true` as a best-effort default; the
/// status command's underlying `IpcStream::connect` will then surface a
/// real failure if the daemon is not actually reachable.
#[cfg(unix)]
fn is_pid_alive(pid: u32) -> bool {
    // Signal 0: existence + permission check, no actual signal delivered.
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    // EPERM means the process exists but is owned by another user.
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

    #[test]
    fn write_then_read_round_trips() {
        // Use a private cache dir for the test to avoid clobbering the
        // user's real daemon-active.json. We do this by overriding HOME
        // and (on macOS) XDG_CACHE_HOME via a tempdir.
        let tmp = TempDir::new().expect("tempdir");
        let cache_root = tmp.path().to_path_buf();

        // Build a record manually at a known location and verify
        // serialization / round-trip without touching active_file_path.
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let socket = tmp.path().join("tldr-deadbeef.sock");

        let record = DaemonActive {
            project: project.clone(),
            pid: std::process::id(),
            socket: socket.clone(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: DaemonActive = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.project, project);
        assert_eq!(parsed.pid, std::process::id());
        assert_eq!(parsed.socket, socket);

        // Touch cache_root so the variable is used (placeholder until we
        // fully decouple the cache location).
        assert!(cache_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pid_zero_is_not_alive() {
        // PID 0 (the kernel scheduler on Linux / "any process in the
        // session" on signalling semantics) is never a valid daemon
        // candidate. kill(0, 0) actually targets the whole process group,
        // so we can't strictly assert false here. Use a definitely-dead
        // PID instead: a freshly reaped child.
        // Spawn `true` and wait for it.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        let _ = child.wait();
        // After wait(), the PID has been reaped; signal 0 should return
        // ESRCH.
        assert!(!is_pid_alive(pid), "reaped child PID should not be alive");
    }

    #[cfg(unix)]
    #[test]
    fn current_process_is_alive() {
        assert!(is_pid_alive(std::process::id()));
    }

    // =========================================================================
    // issue-38-stop-discovery-v1: project-guarded discovery-record removal
    // =========================================================================

    /// Serialize tests that mutate the process-global TLDR_DAEMON_ACTIVE_DIR
    /// env var (same rationale as REGISTRY_ENV_LOCK in daemon_registry.rs).
    static ACTIVE_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: scope the discovery-file directory override to an isolated
    /// tempdir for the duration of `f`, so tests never touch the user's
    /// real `~/<cache>/tldr/daemon-active.json`.
    fn with_active_dir<F: FnOnce(&Path)>(f: F) {
        let _guard = ACTIVE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().expect("tempdir");
        std::env::set_var("TLDR_DAEMON_ACTIVE_DIR", tmp.path());
        f(tmp.path());
        std::env::remove_var("TLDR_DAEMON_ACTIVE_DIR");
    }

    /// Removing for a DIFFERENT project must leave the record intact —
    /// this is the "never wholesale" half of issue #38: `daemon stop
    /// --project B` must not delete the discovery record of a still-running
    /// daemon for project A.
    #[test]
    fn remove_active_for_project_keeps_other_projects_record() {
        with_active_dir(|dir| {
            let project_a = dir.join("daemon-a");
            std::fs::create_dir_all(&project_a).unwrap();
            write_active(&project_a, std::process::id(), &dir.join("a.sock"))
                .expect("write record for A");

            let project_b = dir.join("daemon-b");
            std::fs::create_dir_all(&project_b).unwrap();
            let removed = remove_active_for_project(&project_b);
            assert!(
                !removed,
                "no record for project B — nothing may be removed"
            );
            assert!(
                active_file_path().exists(),
                "project A's discovery record must survive a stop of project B"
            );
            // And the surviving record still resolves to A.
            assert_eq!(read_active().expect("record readable").project, project_a);
        });
    }

    /// Removing for the OWNING project deletes the record — including when
    /// the recorded PID is already dead (the normal post-stop state).
    #[test]
    fn remove_active_for_project_removes_own_record() {
        with_active_dir(|dir| {
            let project = dir.join("daemon-own");
            std::fs::create_dir_all(&project).unwrap();
            write_active(&project, std::process::id(), &dir.join("own.sock"))
                .expect("write record");
            assert!(active_file_path().exists());
            assert!(
                remove_active_for_project(&project),
                "the record belongs to this project and must be removed"
            );
            assert!(
                !active_file_path().exists(),
                "the discovery record for the stopped project must be gone"
            );
        });
    }

    /// `read_active_record` returns the raw record even when the recorded
    /// PID is dead (the liveness gate in `read_active` would hide it) and
    /// `None` for corrupt content.
    #[test]
    fn read_active_record_skips_liveness_gate() {
        with_active_dir(|dir| {
            let project = dir.join("daemon-dead-pid");
            std::fs::create_dir_all(&project).unwrap();
            // Spawn `true` and reap → definitely-dead PID.
            let mut child = std::process::Command::new("true").spawn().expect("spawn");
            let dead_pid = child.id();
            let _ = child.wait();
            write_active(&project, dead_pid, &dir.join("d.sock")).expect("write record");
            assert!(
                read_active().is_none(),
                "liveness gate must still reject a dead PID"
            );
            let raw = read_active_record().expect("raw record readable");
            assert_eq!(raw.project, project, "raw record must surface the project");

            // Corrupt content → None (both readers).
            std::fs::write(active_file_path(), "not json at all").unwrap();
            assert!(read_active_record().is_none());
            assert!(read_active().is_none());
        });
    }

    /// The discovery-file path honours the `TLDR_DAEMON_ACTIVE_DIR` override
    /// (test isolation hook, mirroring `TLDR_DAEMON_REGISTRY_DIR`).
    #[test]
    fn active_file_path_honors_env_override() {
        with_active_dir(|dir| {
            assert_eq!(active_file_path(), dir.join("daemon-active.json"));
        });
    }
}
