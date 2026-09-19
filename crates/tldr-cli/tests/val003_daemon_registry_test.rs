//! VAL-003 — multi-daemon registry (v0.3.0).
//!
//! Replaces v0.2.2 single-slot daemon-active.json with a multi-entry
//! daemon-registry.json. Two simultaneously-running daemons must both be
//! discoverable via `tldr daemon list`; `daemon status` (no flag) errors
//! when multiple daemons are live; migration from v0.2.x daemon-active.json
//! is one-shot.
//!
//! Concurrency story: issue #64 replaced the original option (c) bounded
//! mtime compare-and-swap (no mutual exclusion between check and write —
//! concurrent registrations silently overwrote each other) with an
//! exclusive `flock` on a dedicated `daemon-registry.lock` file held for
//! the whole read-modify-write cycle. Per-project flock at
//! `pid.rs::try_acquire_lock` still protects the SOCKET file, NOT the
//! registry.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tldr")
}

/// A scope guard that issues `daemon stop --all` (using the test's
/// TLDR_DAEMON_REGISTRY_DIR override) on drop. Best-effort.
struct StopAllGuard {
    registry_dir: std::path::PathBuf,
}

impl Drop for StopAllGuard {
    fn drop(&mut self) {
        let _ = Command::new(bin())
            .env("TLDR_DAEMON_REGISTRY_DIR", &self.registry_dir)
            .args(["daemon", "stop", "--all"])
            .output();
    }
}

/// Wait until the daemon for `project` answers `status --project <project>`
/// with `"running"`. Caps at `timeout`.
fn wait_for_daemon_running(registry_dir: &Path, project: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new(bin())
            .env("TLDR_DAEMON_REGISTRY_DIR", registry_dir)
            .args(["daemon", "status", "--project"])
            .arg(project)
            .output();
        if let Ok(out) = out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("\"status\": \"running\"")
                || stdout.contains("\"status\":\"running\"")
            {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Two daemons in distinct projects must both appear in `daemon list`;
/// no-arg `daemon status` must error with multi-daemon message; `stop --all`
/// must drain the registry.
#[test]
fn daemon_list_shows_two_daemons_in_distinct_projects() {
    let cache_root = tempfile::Builder::new()
        .prefix("val003-cache-")
        .tempdir()
        .expect("tempdir");
    let project_a = tempfile::Builder::new()
        .prefix("val003-proj-a-")
        .tempdir()
        .expect("tempdir a");
    let project_b = tempfile::Builder::new()
        .prefix("val003-proj-b-")
        .tempdir()
        .expect("tempdir b");

    let cache_path = cache_root.path().to_path_buf();
    let path_a = project_a.path().canonicalize().expect("canon a");
    let path_b = project_b.path().canonicalize().expect("canon b");

    // Best-effort cleanup even if any assertion fails.
    let _guard = StopAllGuard {
        registry_dir: cache_path.clone(),
    };

    // Start two daemons (default mode = background).
    let start_a = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "start", "--project"])
        .arg(&path_a)
        .output()
        .expect("start a spawn");
    assert!(
        start_a.status.success(),
        "daemon start A failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start_a.stdout),
        String::from_utf8_lossy(&start_a.stderr)
    );

    let start_b = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "start", "--project"])
        .arg(&path_b)
        .output()
        .expect("start b spawn");
    assert!(
        start_b.status.success(),
        "daemon start B failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start_b.stdout),
        String::from_utf8_lossy(&start_b.stderr)
    );

    // Wait for both to become reachable.
    assert!(
        wait_for_daemon_running(&cache_path, &path_a, Duration::from_secs(10)),
        "daemon A never became reachable"
    );
    assert!(
        wait_for_daemon_running(&cache_path, &path_b, Duration::from_secs(10)),
        "daemon B never became reachable"
    );

    // `daemon list` shows 2 entries.
    let list_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list spawn");
    assert!(
        list_out.status.success(),
        "daemon list failed: stderr={}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse list json: err={} stdout={}", e, stdout));
    let daemons = parsed["daemons"]
        .as_array()
        .expect("daemons array missing in list output");
    assert_eq!(
        daemons.len(),
        2,
        "expected 2 daemons in registry, got {}; payload={}",
        daemons.len(),
        stdout
    );

    // No-arg `daemon status` must error when multiple daemons live.
    let status_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "status"])
        .current_dir("/tmp")
        .output()
        .expect("status spawn");
    assert!(
        !status_out.status.success(),
        "daemon status (no flag) must fail when multiple daemons are live; stdout={} stderr={}",
        String::from_utf8_lossy(&status_out.stdout),
        String::from_utf8_lossy(&status_out.stderr)
    );
    let err = String::from_utf8_lossy(&status_out.stderr);
    assert!(
        err.contains("multiple") && err.contains("--project"),
        "expected 'multiple' and '--project' hints in stderr, got: {}",
        err
    );

    // `daemon status --project <A>` succeeds.
    let status_a = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "status", "--project"])
        .arg(&path_a)
        .output()
        .expect("status a spawn");
    assert!(
        status_a.status.success(),
        "status --project A must succeed: stderr={}",
        String::from_utf8_lossy(&status_a.stderr)
    );

    // `daemon stop --all` reduces registry to 0 entries.
    let stop_all = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "stop", "--all"])
        .output()
        .expect("stop all spawn");
    assert!(
        stop_all.status.success(),
        "stop --all failed: stderr={}",
        String::from_utf8_lossy(&stop_all.stderr)
    );

    let list_after = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list-after spawn");
    let stdout_after = String::from_utf8_lossy(&list_after.stdout);
    let parsed_after: serde_json::Value =
        serde_json::from_str(&stdout_after).expect("parse list-after");
    assert_eq!(
        parsed_after["daemons"].as_array().unwrap().len(),
        0,
        "expected empty registry after stop --all, payload={}",
        stdout_after
    );
}

/// One-shot migration: pre-create a v0.2.x-shaped daemon-active.json with the
/// current process's PID (alive); the first registry access (e.g., `daemon
/// list`) must build daemon-registry.json from it and delete the legacy
/// daemon-active.json.
#[test]
fn migration_from_v022_daemon_active_is_one_shot() {
    let cache_root = tempfile::Builder::new()
        .prefix("val003-migrate-")
        .tempdir()
        .expect("tempdir");
    let cache_path = cache_root.path().to_path_buf();

    // Pre-create daemon-active.json with the current process PID (alive
    // for the duration of the test). The test process itself is the
    // "daemon" PID — sufficient for migration's PID-liveness check.
    let active_path = cache_path.join("daemon-active.json");
    let socket_path = cache_path.join("v022-leftover.sock");
    let project_dir = tempfile::Builder::new()
        .prefix("val003-v022-leftover-")
        .tempdir()
        .expect("tempdir leftover");
    let project_canon = project_dir.path().canonicalize().expect("canon proj");

    let record = serde_json::json!({
        "project": project_canon.to_string_lossy(),
        "pid": std::process::id(),
        "socket": socket_path.to_string_lossy(),
    });
    std::fs::write(&active_path, record.to_string()).expect("write active");
    assert!(active_path.exists(), "preconditions: active file written");

    // Trigger migration via any registry-touching command.
    let list_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list spawn (triggers migration)");
    assert!(
        list_out.status.success(),
        "daemon list failed during migration: stderr={}",
        String::from_utf8_lossy(&list_out.stderr)
    );

    let registry_path = cache_path.join("daemon-registry.json");
    assert!(
        registry_path.exists(),
        "daemon-registry.json must be created by migration shim"
    );
    assert!(
        !active_path.exists(),
        "legacy daemon-active.json must be removed after migration"
    );

    // The migrated entry should appear in the list output.
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("parse migrated list");
    let daemons = parsed["daemons"].as_array().expect("daemons array");
    assert_eq!(
        daemons.len(),
        1,
        "expected 1 migrated entry in registry, got {}; payload={}",
        daemons.len(),
        stdout
    );
}

/// Concurrent `daemon start` from 3 distinct projects: ALL 3 must succeed
/// in registering (issue #64). Pre-fix, the mtime-based CAS let concurrent
/// writers pass the check simultaneously and the last full-registry write
/// silently dropped the earlier registrations — the test accepted "≥2 of 3"
/// to tolerate that loss. With the registry lock, no registration may be
/// lost, so the assertion is exact.
#[test]
fn concurrent_daemon_starts_all_register() {
    use std::thread;

    let cache_root = tempfile::Builder::new()
        .prefix("val003-concurrent-")
        .tempdir()
        .expect("tempdir");
    let cache_path = cache_root.path().to_path_buf();

    let _guard = StopAllGuard {
        registry_dir: cache_path.clone(),
    };

    // Each thread starts a daemon for a distinct, real (canonicalizable)
    // project directory.
    let projects: Vec<_> = (0..3)
        .map(|i| {
            tempfile::Builder::new()
                .prefix(&format!("val003-conc-{}-", i))
                .tempdir()
                .expect("tempdir conc")
        })
        .collect();
    let project_paths: Vec<_> = projects
        .iter()
        .map(|p| p.path().canonicalize().expect("canon"))
        .collect();

    let handles: Vec<_> = project_paths
        .iter()
        .map(|p| {
            let cache = cache_path.clone();
            let project = p.clone();
            thread::spawn(move || {
                Command::new(bin())
                    .env("TLDR_DAEMON_REGISTRY_DIR", &cache)
                    .args(["daemon", "start", "--project"])
                    .arg(&project)
                    .output()
                    .expect("start spawn")
            })
        })
        .collect();
    let mut ok_count = 0;
    for h in handles {
        let out = h.join().expect("thread join");
        if out.status.success() {
            ok_count += 1;
        }
    }
    assert_eq!(
        ok_count, 3,
        "issue #64: all 3 concurrent daemon starts must succeed, got {} \
         (a lost start means a registration was dropped)",
        ok_count
    );

    // Wait briefly for entries to settle, then check the registry.
    std::thread::sleep(Duration::from_millis(500));
    let list_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list spawn");
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("parse concurrent list");
    let n = parsed["daemons"].as_array().unwrap().len();
    assert_eq!(
        n, 3,
        "issue #64: all 3 concurrently started daemons must appear in the \
         registry, got {}; payload={}",
        n, stdout
    );
}

// =============================================================================
// val003 self-heal: stale records after a SIGKILLed daemon
// =============================================================================

/// Read the RAW registry file (no CLI read — a registry read prunes
/// dead-PID entries on the spot, which would pre-heal the state under
/// test).
fn read_raw_registry(registry_dir: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(registry_dir.join("daemon-registry.json"))
        .expect("daemon-registry.json must exist");
    serde_json::from_str(&raw).expect("parse daemon-registry.json")
}

/// Spawn `kill -9 <pid>` — the exact artifact the test harness leaves
/// behind when it SIGKILLs a long bash call whose setsid-detached daemon
/// can never run its exit cleanup.
fn kill_9(pid: u32) {
    let out = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()
        .expect("spawn kill");
    assert!(
        out.status.success(),
        "kill -9 {} failed: {}",
        pid,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Poll until `pid` is provably dead (`kill -0` fails), capped at `timeout`.
/// The SIGKILLed daemon is an orphan (its parent CLI already exited), so it
/// is reaped by init/launchd and no zombie holds the PID.
fn wait_pid_dead(pid: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let alive = Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !alive {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Start a real daemon for `project`, wait until reachable, then SIGKILL it
/// and wait until the PID is dead. Returns the daemon's PID and socket path
/// — the stale artifacts the restart must self-heal.
fn start_then_sigkill_daemon(registry_dir: &Path, project: &Path) -> (u32, std::path::PathBuf) {
    let start = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", registry_dir)
        .args(["daemon", "start", "--project"])
        .arg(project)
        .output()
        .expect("start spawn");
    assert!(
        start.status.success(),
        "daemon start failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );
    assert!(
        wait_for_daemon_running(registry_dir, project, Duration::from_secs(10)),
        "daemon never became reachable"
    );

    // Read the entry from the RAW registry (pre-kill state) — the entry
    // carries the daemon PID and its socket path.
    let parsed = read_raw_registry(registry_dir);
    let entry = parsed["daemons"]
        .as_array()
        .expect("daemons array")
        .iter()
        .find(|e| e["project"].as_str() == Some(project.to_str().unwrap()))
        .expect("registry entry for the started daemon")
        .clone();
    let pid = entry["pid"].as_u64().expect("entry.pid") as u32;
    let socket = std::path::PathBuf::from(entry["socket"].as_str().expect("entry.socket"));

    kill_9(pid);
    assert!(
        wait_pid_dead(pid, Duration::from_secs(10)),
        "daemon pid {} did not die after SIGKILL",
        pid
    );
    (pid, socket)
}

/// The val003 flake scenario, end to end: a daemon SIGKILLed mid-flight
/// (harness kill of a long bash call — the setsid-detached daemon survives
/// its process group and cannot run exit cleanup) leaves the socket file and
/// ghost records behind. A subsequent `daemon start` for the same project
/// must SELF-HEAL: succeed cleanly and re-register a live daemon, instead
/// of surfacing `Address already in use` / ghost entries.
#[test]
fn stale_daemon_records_self_heal_on_restart() {
    let cache_root = tempfile::Builder::new()
        .prefix("val003-selfheal-restart-")
        .tempdir()
        .expect("tempdir cache");
    let cache_path = cache_root.path().to_path_buf();
    let project = tempfile::Builder::new()
        .prefix("val003-selfheal-restart-proj-")
        .tempdir()
        .expect("tempdir project");
    let path = project.path().canonicalize().expect("canon project");

    let _guard = StopAllGuard {
        registry_dir: cache_path.clone(),
    };

    let (dead_pid, socket_path) = start_then_sigkill_daemon(&cache_path, &path);

    // Precondition: the SIGKILL left the stale socket file behind (no
    // cleanup ran) and the registry still holds the dead daemon's record.
    assert!(
        socket_path.exists(),
        "precondition: the SIGKILLed daemon must leave its socket file at {}",
        socket_path.display()
    );
    let raw = read_raw_registry(&cache_path);
    assert!(
        raw["daemons"]
            .as_array()
            .expect("daemons array")
            .iter()
            .any(|e| e["pid"].as_u64() == Some(u64::from(dead_pid))),
        "precondition: the dead daemon's registry entry must still be present"
    );

    // The restart must succeed — pre-hardening this is where a stale socket
    // surfaced as a bind failure and ghost records lingered.
    let restart = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "start", "--project"])
        .arg(&path)
        .output()
        .expect("restart spawn");
    assert!(
        restart.status.success(),
        "daemon start must self-heal stale records and succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&restart.stdout),
        String::from_utf8_lossy(&restart.stderr)
    );

    // The new daemon is live and registered.
    assert!(
        wait_for_daemon_running(&cache_path, &path, Duration::from_secs(10)),
        "restarted daemon never became reachable"
    );
    let list_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list spawn");
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("parse list json");
    let daemons = parsed["daemons"].as_array().expect("daemons array");
    assert_eq!(
        daemons.len(),
        1,
        "the registry must hold exactly the restarted daemon (the dead \
         daemon's ghost entry must be gone); payload={}",
        stdout
    );
    assert_ne!(
        daemons[0]["pid"].as_u64(),
        Some(u64::from(dead_pid)),
        "the surviving entry must be the NEW daemon, not the SIGKILLed ghost"
    );
}

/// Status-side self-heal: with a SIGKILLed daemon's ghost state on disk,
/// `daemon status` must report `not_running` AND purge the provably-stale
/// artifacts (dead socket file, dead-PID records) instead of leaving them
/// to surface as connect errors on the next start.
#[test]
fn stale_daemon_records_self_heal_on_status_discovery() {
    let cache_root = tempfile::Builder::new()
        .prefix("val003-selfheal-status-")
        .tempdir()
        .expect("tempdir cache");
    let cache_path = cache_root.path().to_path_buf();
    let project = tempfile::Builder::new()
        .prefix("val003-selfheal-status-proj-")
        .tempdir()
        .expect("tempdir project");
    let path = project.path().canonicalize().expect("canon project");

    let _guard = StopAllGuard {
        registry_dir: cache_path.clone(),
    };

    let (_dead_pid, socket_path) = start_then_sigkill_daemon(&cache_path, &path);
    assert!(
        socket_path.exists(),
        "precondition: the SIGKILLed daemon must leave its socket file at {}",
        socket_path.display()
    );

    let status_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["daemon", "status", "--project"])
        .arg(&path)
        .output()
        .expect("status spawn");
    assert!(
        status_out.status.success(),
        "status must succeed on a stale daemon: stderr={}",
        String::from_utf8_lossy(&status_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        stdout.contains("not_running"),
        "status must report not_running for a dead daemon, got: {}",
        stdout
    );

    // Self-heal: the dead socket file is gone, and a registry read now
    // yields no entries for the dead daemon.
    assert!(
        !socket_path.exists(),
        "status discovery must purge the dead socket file at {}",
        socket_path.display()
    );
    let list_out = Command::new(bin())
        .env("TLDR_DAEMON_REGISTRY_DIR", &cache_path)
        .args(["--format", "json", "daemon", "list"])
        .output()
        .expect("list spawn");
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("parse list json");
    assert_eq!(
        parsed["daemons"].as_array().unwrap().len(),
        0,
        "the dead daemon's ghost entry must be gone after the purge; payload={}",
        stdout
    );
}
