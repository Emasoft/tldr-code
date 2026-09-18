//! Issue #38: `tldr daemon stop` fails cross-cwd and deletes the discovery
//! file.
//!
//! Pre-fix, `daemon stop` hashed the CALLER's cwd-derived project path
//! instead of resolving the running daemon through the discovery state that
//! `daemon status` already used (multi-daemon registry / legacy
//! `daemon-active.json`). Started from a directory different from the
//! `daemon start` cwd, stop computed the wrong socket path, reported
//! "Daemon not running" for a LIVE daemon — and then called
//! `remove_active()` unconditionally, deleting the discovery record
//! wholesale and breaking that daemon's cross-cwd discovery.
//!
//! Repro verdict on base 074aeeea (daemon started for /tmp fixture from the
//! repo cwd, then `tldr daemon stop` with no `--project`):
//!   - `{"status": "ok", "message": "Daemon not running"}` ← BUG
//!   - `daemon status --project <fixture>` → still `"running"`
//!
//! Fix (issue-38-stop-discovery-v1): `daemon stop` resolves its project
//! through the shared `resolve_default_project` helper (registry → legacy
//! record → cwd, explicit `--project` always wins), and the legacy
//! discovery record is removed ONLY when it belongs to the project that was
//! actually stopped (`remove_active_for_project`), never wholesale.
//!
//! These tests spawn a REAL daemon (30-minute idle timeout — the stop guard
//! is mandatory hygiene).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Scope guard: `daemon stop --project <fixture>` on drop, so the spawned
/// daemon never outlives the test (AGENTS.md daemon hygiene).
struct DaemonStopGuard {
    project: PathBuf,
    registry_dir: PathBuf,
    active_dir: PathBuf,
}

impl Drop for DaemonStopGuard {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_tldr"))
            .args(["daemon", "stop", "--project"])
            .arg(&self.project)
            .env("TLDR_DAEMON_REGISTRY_DIR", &self.registry_dir)
            .env("TLDR_DAEMON_ACTIVE_DIR", &self.active_dir)
            .output();
    }
}

/// Minimal fixture (one rust file) + canonicalized path.
fn create_fixture(prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let fixture = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("fixture tempdir");
    std::fs::write(fixture.path().join("main.rs"), "fn main() {}\n").expect("write fixture");
    let path = fixture.path().canonicalize().expect("canonicalize fixture");
    (fixture, path)
}

fn wait_for_daemon_running(project: &Path, timeout: Duration, registry_dir: &Path) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new(env!("CARGO_BIN_EXE_tldr"))
            .args(["daemon", "status", "--project"])
            .arg(project)
            .env("TLDR_DAEMON_REGISTRY_DIR", registry_dir)
            .output();
        if let Ok(out) = out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("\"status\": \"running\"") || stdout.contains("\"status\":\"running\"")
            {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_daemon_gone(project: &Path, timeout: Duration, registry_dir: &Path) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new(env!("CARGO_BIN_EXE_tldr"))
            .args(["daemon", "status", "--project"])
            .arg(project)
            .env("TLDR_DAEMON_REGISTRY_DIR", registry_dir)
            .output();
        if let Ok(out) = out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("not_running") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// RED on base, GREEN after the fix: `daemon stop` with NO `--project` from
/// a cwd different from the `daemon start` cwd must actually stop the
/// daemon (pre-fix: "Daemon not running" while the daemon stayed alive).
#[test]
fn daemon_stop_from_other_cwd_stops_the_daemon() {
    let registry = tempfile::Builder::new()
        .prefix("issue38-registry-")
        .tempdir()
        .expect("registry tempdir");
    let registry_dir = registry.path().to_path_buf();
    let active = tempfile::Builder::new()
        .prefix("issue38-active-")
        .tempdir()
        .expect("active tempdir");
    let active_dir = active.path().to_path_buf();

    let (_fixture, fixture_path) = create_fixture("issue38-fixture-");

    let start = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "start", "--project"])
        .arg(&fixture_path)
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
        .env("TLDR_DAEMON_ACTIVE_DIR", &active_dir)
        .output()
        .expect("daemon start spawn");
    assert!(
        start.status.success(),
        "daemon start failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );

    let _stop_guard = DaemonStopGuard {
        project: fixture_path.clone(),
        registry_dir: registry_dir.clone(),
        active_dir: active_dir.clone(),
    };

    assert!(
        wait_for_daemon_running(&fixture_path, Duration::from_secs(10), &registry_dir),
        "daemon never became reachable within 10 s"
    );

    // CORE REPRODUCTION: stop with no --project from a DIFFERENT cwd. The
    // daemon's project is the fixture; the caller's cwd (/tmp) is not.
    let stop = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "stop"])
        .current_dir("/tmp")
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
        .env("TLDR_DAEMON_ACTIVE_DIR", &active_dir)
        .output()
        .expect("daemon stop spawn (from /tmp)");

    let stdout = String::from_utf8_lossy(&stop.stdout).into_owned();
    assert!(
        stdout.contains("Daemon stopped"),
        "issue #38: cross-cwd `daemon stop` must stop the daemon, got: {stdout} \
         (RED proof keyword: \"Daemon not running\")"
    );

    // The daemon must actually be gone.
    assert!(
        wait_for_daemon_gone(&fixture_path, Duration::from_secs(5), &registry_dir),
        "issue #38: daemon still reachable after cross-cwd stop"
    );
}

/// The "never wholesale" half of issue #38: stopping project B (explicit
/// `--project`) must NOT delete the discovery record belonging to a
/// different project A.
#[test]
fn stop_of_one_project_keeps_another_projects_discovery_record() {
    // NOTE: registry dir and active dir are deliberately SEPARATE — with a
    // shared dir the registry migration would absorb (and delete) the
    // legacy record, which is not the scenario under test.
    let registry = tempfile::Builder::new()
        .prefix("issue38-registry2-")
        .tempdir()
        .expect("registry tempdir");
    let registry_dir = registry.path().to_path_buf();
    let active = tempfile::Builder::new()
        .prefix("issue38-active2-")
        .tempdir()
        .expect("active tempdir");
    let active_dir = active.path().to_path_buf();

    // Seed a legacy discovery record for a DIFFERENT project (pid = this
    // test process, which is alive for the whole test).
    let other_project = active.path().join("daemon-other");
    std::fs::create_dir_all(&other_project).unwrap();
    let record = serde_json::json!({
        "project": other_project,
        "pid": std::process::id(),
        "socket": other_project.join("daemon-other.sock"),
    });
    let record_path = active_dir.join("daemon-active.json");
    std::fs::write(
        &record_path,
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .expect("seed discovery record");

    let (_fixture, fixture_path) = create_fixture("issue38-fixture2-");

    let start = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "start", "--project"])
        .arg(&fixture_path)
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
        .env("TLDR_DAEMON_ACTIVE_DIR", &active_dir)
        .output()
        .expect("daemon start spawn");
    assert!(start.status.success(), "daemon start failed");

    let _stop_guard = DaemonStopGuard {
        project: fixture_path.clone(),
        registry_dir: registry_dir.clone(),
        active_dir: active_dir.clone(),
    };

    assert!(
        wait_for_daemon_running(&fixture_path, Duration::from_secs(10), &registry_dir),
        "daemon never became reachable within 10 s"
    );

    let stop = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "stop", "--project"])
        .arg(&fixture_path)
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
        .env("TLDR_DAEMON_ACTIVE_DIR", &active_dir)
        .output()
        .expect("daemon stop spawn");
    let stdout = String::from_utf8_lossy(&stop.stdout).into_owned();
    assert!(
        stdout.contains("Daemon stopped"),
        "fixture daemon must stop cleanly, got: {stdout}"
    );

    // The discovery record for the OTHER project must survive.
    let content = std::fs::read_to_string(&record_path)
        .unwrap_or_else(|e| panic!("issue #38: discovery record was deleted: {e}"));
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("record JSON");
    assert_eq!(
        parsed.get("project").and_then(|v| v.as_str()),
        Some(other_project.to_str().unwrap()),
        "issue #38: stop of one project must not delete another project's discovery record"
    );
}
