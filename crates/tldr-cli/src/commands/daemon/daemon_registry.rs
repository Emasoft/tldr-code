//! Multi-daemon registry (v0.3.0 VAL-003).
//!
//! Replaces v0.2.2's single-slot `daemon-active.json` with a multi-entry
//! `daemon-registry.json` file. Each entry records one running daemon; the
//! file always contains the union of all live daemons known to the user.
//!
//! # Concurrency (option d — exclusive lock file, issue #64)
//!
//! The per-project flock at [`super::pid::try_acquire_lock`] (pid.rs:261,
//! `libc::flock(LOCK_EX | LOCK_NB)`) protects the SOCKET file, NOT the
//! registry. Two `daemon start` calls from DIFFERENT projects bypass that
//! flock and race read-modify-write the shared registry.
//!
//! v0.2.2 → v0.3.0 used a bounded mtime compare-and-swap retry here
//! (option c). It had no mutual exclusion between the mtime check and the
//! write: concurrent writers for different projects all passed the check
//! and the last full-registry write silently dropped every earlier
//! writer's entry (issue #64). The shared fixed temp filename also made
//! concurrent `write_registry_atomic` calls steal each other's tmp file
//! mid-rename, surfacing as spurious ENOENT errors.
//!
//! The registry is now guarded by a dedicated lock file,
//! `daemon-registry.lock` (sibling of the registry file), held for the
//! whole read-modify-write cycle:
//!
//! 1. `flock(LOCK_EX)` on the lock file (blocking). The kernel releases
//!    the lock when the owning process exits, so a crashed writer can
//!    never wedge the registry — no stale-lock recovery is needed.
//! 2. Read the registry, modify in memory, write atomically (tmp + rename)
//!    while still holding the lock.
//! 3. Release on drop (RAII guard).
//!
//! Writers outside this module do not exist: every registry mutation goes
//! through [`add_entry`], [`remove_entry`], or the prune/migration
//! write-back in [`read_registry`], all of which hold the lock.
//!
//! # Migration from v0.2.x
//!
//! On first registry access, [`migrate_from_active_if_needed`] looks for the
//! legacy `daemon-active.json`; if present and its PID is alive, it is
//! converted into a registry entry and the legacy file is deleted. If the
//! PID is dead, the legacy file is also removed (stale record cleanup).

use std::fs::{File, OpenOptions};
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

// =============================================================================
// Registry lock (issue #64)
// =============================================================================

/// Sibling lock file guarding every read-modify-write cycle on the
/// registry. A dedicated file (not the registry JSON itself) because the
/// registry is REPLACED by `tmp + rename` on every write — a lock held on
/// the renamed-away inode would protect nothing.
fn registry_lock_path() -> PathBuf {
    registry_file_path().with_extension("lock")
}

/// An exclusive advisory lock over the daemon registry (issue #64).
///
/// RAII: the OS drops the lock when the guard — and its file handle — is
/// dropped, including on panic and on process exit, so a crashed daemon or
/// CLI can never leave a stale lock behind.
struct RegistryLock {
    _file: File,
}

impl RegistryLock {
    /// Block until the exclusive registry lock is acquired.
    ///
    /// Blocking (rather than the removed CAS loop's bounded non-blocking
    /// retry) is the correct shape here: the lock protects a
    /// read-modify-write cycle lasting microseconds, and the kernel
    /// releases `flock`/`LockFileEx` when the owning process dies, so a
    /// crashed writer cannot wedge the registry. Under contention callers
    /// wait their turn instead of failing with `WouldBlock` — a `daemon
    /// start` must not lose its registration because another project
    /// registered at the same moment.
    fn acquire() -> std::io::Result<Self> {
        let path = registry_lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        lock_exclusive(&file)?;
        Ok(RegistryLock { _file: file })
    }
}

/// Acquire a blocking exclusive lock on `file`.
///
/// Unix: `flock(LOCK_EX)` — the same primitive `pid.rs::try_lock_file`
/// uses for socket singleton enforcement (there non-blocking, here
/// blocking), via the already-vendored `libc`. `flock` locks are owned by
/// the open file description, so two `open()`s in the same process (the
/// multi-threaded test case) exclude each other just like two processes.
#[cfg(unix)]
fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Windows equivalent: a blocking exclusive byte-range lock via
/// `LockFileEx` (no `LOCKFILE_FAIL_IMMEDIATELY`), mirroring `pid.rs`.
#[cfg(windows)]
fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = file.as_raw_handle() as HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe { LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &mut overlapped) };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Directory used when the platform cache dir is unavailable.
///
/// Absolute, TMPDIR-honoring; see `daemon_active::fallback_cache_root` for
/// the issue #34 rationale (a relative `.cache` fallback made the registry's
/// location cwd-dependent, breaking cross-cwd discovery — and `daemon
/// status` consults the registry BEFORE the legacy active record, so the
/// registry path must be stable too).
fn fallback_cache_root() -> PathBuf {
    std::env::temp_dir()
}

/// Compose the registry-file path from a resolved cache root.
///
/// Exposed for tests: the `None` branch is the issue #34 bug — the fallback
/// root must compose to an ABSOLUTE path.
pub fn registry_file_path_in(cache_dir: Option<PathBuf>) -> PathBuf {
    cache_dir
        .unwrap_or_else(fallback_cache_root)
        .join("tldr")
        .join("daemon-registry.json")
}

/// Path to the daemon registry file.
///
/// Resolution order:
/// 1. `TLDR_DAEMON_REGISTRY_DIR` env override (used by tests for isolation).
/// 2. `<dirs::cache_dir()>/tldr/daemon-registry.json`.
/// 3. `<temp_dir>/tldr/daemon-registry.json` fallback if
///    `dirs::cache_dir()` is unavailable — ABSOLUTE, mirroring
///    `daemon_active::active_file_path` (issue #34).
pub fn registry_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("TLDR_DAEMON_REGISTRY_DIR") {
        return PathBuf::from(dir).join("daemon-registry.json");
    }
    registry_file_path_in(dirs::cache_dir())
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
/// Issue #64: the prune write-back is a WRITE to the shared registry file,
/// so it runs under the registry lock like every other mutation — without
/// it, a reader pruning a stale entry could overwrite a concurrent
/// registration with a snapshot that predates it.
///
/// Auxiliary state — a missing/corrupt file simply yields an empty registry.
/// If the lock file itself cannot be created (e.g. read-only cache dir),
/// the read degrades to unlocked: callers lose only the prune write-back,
/// which is best-effort.
pub fn read_registry() -> DaemonRegistry {
    // Hold the lock for the whole read + prune write-back. If the lock
    // file itself cannot be created/opened, degrade to unlocked: the
    // caller loses only the prune write-back, which is best-effort.
    let _guard = RegistryLock::acquire().ok();
    read_registry_unlocked()
}

/// Read the registry WITHOUT acquiring the lock. Callers must already hold
/// the registry lock ([`RegistryLock::acquire`]).
fn read_registry_unlocked() -> DaemonRegistry {
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

/// Resolve the project path for a daemon command invoked with the DEFAULT
/// `--project .` (VAL-013 cross-cwd discovery, shared by `status` and
/// `stop`; issue #38).
///
/// Resolution order — an EXPLICIT `--project` (anything other than the
/// literal "." default) is always honoured untouched:
///
/// 1. Registry has exactly one live daemon → use its project path. This is
///    what makes cross-cwd discovery work: the daemon registered itself at
///    start time with a canonicalized absolute path, independent of the
///    caller's cwd.
/// 2. Registry empty → fall back to the v0.2.x single-slot
///    `daemon-active.json` record (migration window) when its PID is alive.
/// 3. Still nothing → the caller's path (canonicalized; cwd for ".").
/// 4. Two or more live daemons → error asking for an explicit `--project`
///    or `tldr daemon list` (same contract as `daemon status`).
///
/// Issue #38: `daemon stop` did NOT use this discovery — it hashed the
/// caller's cwd-derived path, computed the wrong socket path, reported
/// "Daemon not running" for a live daemon, and then deleted the
/// `daemon-active.json` discovery record wholesale.
pub fn resolve_default_project(project_arg: &Path) -> anyhow::Result<PathBuf> {
    let fallback = || {
        project_arg.canonicalize().unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(project_arg)
        })
    };
    if project_arg != Path::new(".") {
        return Ok(fallback());
    }
    let entries = live_entries();
    match entries.len() {
        0 => Ok(match super::daemon_active::read_active() {
            Some(active) => active.project,
            None => fallback(),
        }),
        1 => Ok(entries.into_iter().next().unwrap().project),
        n => Err(anyhow::anyhow!(
            "multiple daemons running ({}); use --project <abs-path> or run 'tldr daemon list'",
            n
        )),
    }
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

/// Add (or replace) the registry entry for `project`.
///
/// Issue #64: the whole read-modify-write cycle runs while holding the
/// exclusive registry lock, so a concurrent registration can neither
/// interleave between this call's read and its write (the old mtime CAS
/// had no mutual exclusion there — every writer passed the check and the
/// last full-file write dropped the others' entries) nor steal the shared
/// `daemon-registry.json.tmp` file out from under the atomic rename.
pub fn add_entry(project: &Path, pid: u32, socket: &Path) -> std::io::Result<()> {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let _lock = RegistryLock::acquire()?;

    let mut registry = read_registry_unlocked();
    registry.daemons.retain(|d| d.project != canon);
    registry.daemons.push(DaemonRegistryEntry {
        project: canon,
        pid,
        socket: socket.to_path_buf(),
        started_at: chrono::Utc::now().to_rfc3339(),
    });
    write_registry_atomic(&registry)
}

/// Remove the registry entry for `project`.
///
/// Serialized against [`add_entry`] and the prune write-back by the same
/// registry lock (issue #64); removing an absent entry is a no-op.
pub fn remove_entry(project: &Path) -> std::io::Result<()> {
    let canon = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let _lock = RegistryLock::acquire()?;

    let mut registry = read_registry_unlocked();
    let before = registry.daemons.len();
    registry.daemons.retain(|d| d.project != canon);
    if registry.daemons.len() == before {
        // Nothing to remove — caller's invariant satisfied.
        return Ok(());
    }
    write_registry_atomic(&registry)
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

    // =========================================================================
    // issue-64-concurrent-registration-v1: concurrent add_entry must not
    // silently lose entries
    // =========================================================================

    /// Issue #64: concurrent `add_entry` calls for DIFFERENT projects must
    /// all survive. The mtime-based compare-and-swap has no mutual exclusion
    /// between its check and its write: when several writers are inside the
    /// read-modify-write window at the same time (released by a barrier —
    /// the exact interleaving the issue describes), every one of them passes
    /// the `pre_mtime == post_mtime` check and the last full-registry write
    /// silently drops all earlier writers' entries.
    ///
    /// Contract: every `add_entry` that returns `Ok(())` must leave its
    /// entry in the registry, so all THREADS × PROJECTS_PER_THREAD × CYCLES
    /// distinct projects must be present at the end.
    #[test]
    fn concurrent_add_entry_preserves_all_entries() {
        use std::sync::Arc;

        const THREADS: usize = 8;
        const PROJECTS_PER_THREAD: usize = 8;
        const CYCLES: usize = 3;

        with_registry_dir("concurrent-add", |dir| {
            // Pre-create every project directory so add_entry can
            // canonicalize it (macOS: /var → /private/var).
            let mut all_projects = Vec::new();
            for cycle in 0..CYCLES {
                for t in 0..THREADS {
                    for p in 0..PROJECTS_PER_THREAD {
                        let project = dir.join(format!("c{cycle}-t{t}-p{p}"));
                        std::fs::create_dir_all(&project).unwrap();
                        all_projects.push(project);
                    }
                }
            }

            let barrier = Arc::new(std::sync::Barrier::new(THREADS));
            let mut handles = Vec::new();
            for t in 0..THREADS {
                let projects: Vec<_> = all_projects
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % THREADS == t)
                    .map(|(_, p)| p.clone())
                    .collect();
                let barrier = barrier.clone();
                handles.push(std::thread::spawn(move || {
                    let mut oks = 0usize;
                    let mut errs = Vec::new();
                    barrier.wait();
                    for project in &projects {
                        let socket = project.with_file_name(format!(
                            "{}.sock",
                            project.file_name().unwrap().to_string_lossy()
                        ));
                        match add_entry(project, std::process::id(), &socket) {
                            Ok(()) => oks += 1,
                            Err(e) => errs.push(e.to_string()),
                        }
                    }
                    (oks, errs)
                }));
            }

            let mut total_ok = 0usize;
            let mut errors = Vec::new();
            for h in handles {
                let (oks, errs) = h.join().expect("worker thread must not panic");
                total_ok += oks;
                errors.extend(errs);
            }

            assert!(
                errors.is_empty(),
                "issue #64: add_entry must not fail under concurrent \
                 registration, got {} errors: {:?}",
                errors.len(),
                errors.first()
            );
            assert_eq!(
                total_ok,
                THREADS * PROJECTS_PER_THREAD * CYCLES,
                "issue #64: every concurrent registration must report success"
            );

            let entries = live_entries();
            assert_eq!(
                entries.len(),
                THREADS * PROJECTS_PER_THREAD * CYCLES,
                "issue #64: entries were silently lost by concurrent \
                 add_entry (last-writer-wins over the shared registry file)"
            );
            for project in &all_projects {
                assert!(
                    find_entry(project).is_some(),
                    "issue #64: entry for {} was lost by a concurrent writer",
                    project.display()
                );
            }
        });
    }

    // =========================================================================
    // issue-38-stop-discovery-v1: shared default-project resolution
    // =========================================================================

    /// Helper: scope BOTH env overrides (registry + legacy active-file dir)
    /// to the same isolated directory for the duration of `f`.
    fn with_isolated_discovery<F: FnOnce(&Path)>(f: F) {
        let _guard = REGISTRY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().expect("tempdir");
        std::env::set_var("TLDR_DAEMON_REGISTRY_DIR", tmp.path());
        std::env::set_var("TLDR_DAEMON_ACTIVE_DIR", tmp.path());
        f(tmp.path());
        std::env::remove_var("TLDR_DAEMON_REGISTRY_DIR");
        std::env::remove_var("TLDR_DAEMON_ACTIVE_DIR");
    }

    /// An explicit `--project` (anything but ".") is honoured untouched:
    /// the registry is not consulted.
    #[test]
    fn resolve_default_project_explicit_path_wins() {
        with_isolated_discovery(|dir| {
            let daemon_project = dir.join("daemon-a");
            std::fs::create_dir_all(&daemon_project).unwrap();
            add_entry(&daemon_project, std::process::id(), &dir.join("a.sock")).expect("add");
            // Explicit path for a DIFFERENT project — even with a live
            // registry entry, the explicit path must be returned as-is
            // (canonicalized).
            let explicit = dir.join("explicit");
            std::fs::create_dir_all(&explicit).unwrap();
            let resolved = resolve_default_project(&explicit).expect("resolve");
            assert_eq!(resolved, explicit.canonicalize().unwrap());
        });
    }

    /// Exactly one live registry entry → its project path (the cross-cwd
    /// discovery `daemon stop` was missing; issue #38). `add_entry`
    /// canonicalizes the project it stores, so the expectation is the
    /// canonicalized path (macOS: `/var` → `/private/var`).
    #[test]
    fn resolve_default_project_single_registry_entry() {
        with_isolated_discovery(|dir| {
            let daemon_project = dir.join("daemon-single");
            std::fs::create_dir_all(&daemon_project).unwrap();
            add_entry(&daemon_project, std::process::id(), &dir.join("s.sock")).expect("add");
            let resolved = resolve_default_project(Path::new(".")).expect("resolve with one entry");
            assert_eq!(
                resolved,
                daemon_project.canonicalize().unwrap(),
                "the single live daemon's project must be resolved from any cwd"
            );
        });
    }

    /// No registry entries + no legacy record → the caller's cwd.
    #[test]
    fn resolve_default_project_falls_back_to_cwd() {
        with_isolated_discovery(|_dir| {
            let cwd = std::env::current_dir().unwrap();
            let resolved = resolve_default_project(Path::new(".")).expect("resolve fallback");
            assert_eq!(
                resolved, cwd,
                "with no discovery state, the caller's cwd is the project"
            );
        });
    }

    /// No registry entries + a live legacy `daemon-active.json` record →
    /// the recorded project (v0.2.x migration window).
    #[test]
    fn resolve_default_project_falls_back_to_legacy_active_record() {
        with_isolated_discovery(|dir| {
            let legacy_project = dir.join("legacy-daemon");
            std::fs::create_dir_all(&legacy_project).unwrap();
            super::super::daemon_active::write_active(
                &legacy_project,
                std::process::id(),
                &dir.join("legacy.sock"),
            )
            .expect("write legacy record");
            let resolved =
                resolve_default_project(Path::new(".")).expect("resolve legacy fallback");
            assert_eq!(
                resolved, legacy_project,
                "a live legacy discovery record must be honoured when the registry is empty"
            );
        });
    }

    /// Two or more live daemons → error asking for an explicit `--project`
    /// (same contract as `daemon status`).
    #[test]
    fn resolve_default_project_multiple_entries_is_an_error() {
        with_isolated_discovery(|dir| {
            for name in ["m-daemon-a", "m-daemon-b"] {
                let project = dir.join(name);
                std::fs::create_dir_all(&project).unwrap();
                add_entry(
                    &project,
                    std::process::id(),
                    &dir.join(format!("{name}.sock")),
                )
                .expect("add");
            }
            let result = resolve_default_project(Path::new("."));
            let err = result.expect_err("multiple daemons must be ambiguous");
            assert!(
                err.to_string().contains("multiple daemons running"),
                "error must explain the ambiguity, got: {err}"
            );
        });
    }

    // =========================================================================
    // issue-34-no-cache-dir-discovery-v1: ABSOLUTE registry fallback
    // =========================================================================

    /// THE issue #34 bug, registry side: `daemon status` consults the
    /// registry BEFORE the legacy active record, so with no platform cache
    /// dir the registry's relative `.cache` fallback made cross-cwd
    /// discovery fail the same way. The composed fallback path must be
    /// ABSOLUTE.
    #[test]
    fn registry_file_path_fallback_is_absolute() {
        let composed = registry_file_path_in(None);
        assert!(
            composed.is_absolute(),
            "issue #34: the no-cache-dir fallback for the registry file must be \
             absolute (was the relative `.cache`), got {}",
            composed.display()
        );
        assert_eq!(
            composed.file_name().and_then(|n| n.to_str()),
            Some("daemon-registry.json"),
            "fallback must keep the registry-file name"
        );
    }

    /// A resolved cache dir composes unchanged (the fallback only applies
    /// when `dirs::cache_dir()` is `None`).
    #[test]
    fn registry_file_path_uses_resolved_cache_dir_when_available() {
        let composed = registry_file_path_in(Some(PathBuf::from("/cache-root")));
        assert_eq!(
            composed,
            PathBuf::from("/cache-root/tldr/daemon-registry.json")
        );
        assert!(composed.is_absolute());
    }
}
