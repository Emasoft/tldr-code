//! Issue #34: daemon discovery failed without a cache directory.
//!
//! `active_file_path()` (and, for the registry, `registry_file_path()`)
//! fell back to the RELATIVE `.cache` path when `dirs::cache_dir()`
//! returned `None` (e.g. `$HOME` unset with no passwd entry). The
//! discovery file's location then depended on the cwd of whichever process
//! touched it: `daemon start` wrote `<start-cwd>/.cache/tldr/
//! daemon-active.json` while `daemon status` from another cwd read
//! `<other-cwd>/.cache/tldr/daemon-active.json` and never found the
//! record — VAL-013 cross-cwd discovery completely failed in such
//! environments, and `daemon status` reported `not_running` for a live
//! daemon (a cwd-dependent, cwd-inconsistent degradation rather than the
//! clean "no daemon here" answer).
//!
//! Fix (issue-34-no-cache-dir-discovery-v1): the fallback root is
//! `std::env::temp_dir()` — absolute on all platforms, honoring `TMPDIR`,
//! the same directory family the daemon already uses for sockets/PIDs —
//! so both discovery files resolve identically from any cwd. With no
//! discovery state at all, `daemon status` keeps reporting a clean
//! `not_running` (exit 0), never an error.
//!
//! Repro note: `dirs::cache_dir()` cannot be forced to `None` in-process
//! on macOS (dirs falls back to getpwuid), so the red proof is the
//! lib-level assertion that the `None`-cache-dir branch composes an
//! ABSOLUTE path — on base it composed the relative `.cache/tldr/...`,
//! which fails `is_absolute()`.

#![cfg(unix)]

use std::process::Command;
use std::time::{Duration, Instant};

/// THE issue #34 invariant, asserted against the real lib code: when the
/// platform cache dir is unavailable, both discovery-file paths must be
/// absolute so they are cwd-independent. RED on base (`PathBuf::from(
/// ".cache")` composes to the relative `.cache/tldr/...`).
#[test]
fn discovery_paths_without_cache_dir_are_absolute() {
    let active = tldr_cli::commands::daemon::daemon_active::active_file_path_in(None);
    assert!(
        active.is_absolute(),
        "issue #34: no-cache-dir fallback for daemon-active.json must be absolute, \
         got {}",
        active.display()
    );

    let registry = tldr_cli::commands::daemon::daemon_registry::registry_file_path_in(None);
    assert!(
        registry.is_absolute(),
        "issue #34: no-cache-dir fallback for daemon-registry.json must be absolute, \
         got {}",
        registry.display()
    );

    // Same file NAME in both roots — the registry migration looks up the
    // legacy record as a sibling of the registry file, so both fallbacks
    // must land in the same `<root>/tldr/` layout.
    assert_eq!(
        active.file_name().and_then(|n| n.to_str()),
        Some("daemon-active.json")
    );
    assert_eq!(
        registry.file_name().and_then(|n| n.to_str()),
        Some("daemon-registry.json")
    );
}

/// Graceful degradation: with NO discovery state anywhere (isolated empty
/// registry dir, no legacy record reachable), `daemon status` from a
/// different cwd must exit 0 and report a clean `not_running` — never an
/// error, never a panic (the "no daemon" answer must not depend on the
/// cache dir being present or readable).
#[test]
fn daemon_status_without_discovery_state_reports_not_running_cleanly() {
    let registry = tempfile::Builder::new()
        .prefix("issue34-registry-")
        .tempdir()
        .expect("registry tempdir");

    let start = Instant::now();
    let _ = start; // silence unused warnings on non-timing builds

    // Poll a couple of times so a transient failure would surface, then
    // assert the clean contract.
    for _ in 0..2 {
        let out = Command::new(env!("CARGO_BIN_EXE_tldr"))
            .args(["daemon", "status"])
            .current_dir("/tmp")
            .env("TLDR_DAEMON_REGISTRY_DIR", registry.path())
            // Point the legacy active record at the same empty dir so no
            // real user cache state can leak into the assertion.
            .env("TLDR_DAEMON_ACTIVE_DIR", registry.path())
            .output()
            .expect("daemon status spawn");
        assert!(
            out.status.success(),
            "issue #34: `daemon status` without a cache dir / discovery state must \
             degrade cleanly (exit 0), got exit={:?} stdout={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("not_running"),
            "issue #34: expected a clean not_running report, got: {stdout}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
