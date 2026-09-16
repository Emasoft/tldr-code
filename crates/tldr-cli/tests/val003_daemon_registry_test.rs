//! VAL-003 — multi-daemon registry (v0.3.0).
//!
//! Replaces v0.2.2 single-slot daemon-active.json with a multi-entry
//! daemon-registry.json. Two simultaneously-running daemons must both be
//! discoverable via `tldr daemon list`; `daemon status` (no flag) errors
//! when multiple daemons are live; migration from v0.2.x daemon-active.json
//! is one-shot.
//!
//! Concurrency story: option (c) bounded compare-and-swap retry. Per-project
//! flock at `pid.rs::try_acquire_lock` protects the SOCKET file, NOT the
//! registry. Cross-project starts can race read-modify-write the shared
//! registry; CAS retry (3 attempts) handles this without a new dep.

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

/// Concurrent `daemon start` from 3 distinct projects: at least 2 of 3 must
/// succeed in registering. (Option (c) bounded CAS retry — under ordinary
/// load all 3 succeed; under heavy contention the 3rd may exhaust retries,
/// which is acceptable per spec.)
#[test]
fn concurrent_add_entry_is_bounded_cas_safe() {
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
    assert!(
        ok_count >= 2,
        "expected >=2 of 3 concurrent daemon starts to succeed (option c CAS bound), got {}",
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
    assert!(
        n >= 2,
        "expected >=2 daemons registered after concurrent CAS, got {}; payload={}",
        n,
        stdout
    );
}
