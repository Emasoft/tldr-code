//! Issue #83: daemon mode defaulted to Python for 5 analysis commands.
//!
//! `context`, `impact`, `calls`, `dead` and `importers` detect the project
//! language CLI-side but (pre-fix) did not pass it to the daemon. The daemon
//! resolved the missing `language` field to `Language::Python`
//! (`resolve_language(None)` in commands/daemon/daemon.rs), so a rust-only
//! project got Python-typed analysis — e.g. `tldr context main` printed
//! `"signature": "def main()"` — served as a SUCCESSFUL response, so the CLI
//! had no reason to fall back to direct compute.
//!
//! Repro verdict on base 074aeeea (binary `target/debug/tldr`, daemon for a
//! rust-only fixture, raw `daemon query` with no language field):
//!   - context  → `"signature": "def main()"`  (wrong, user-visible)
//!   - calls    → `{"edges": []}`              (wrong; CLI silently fell back
//!     only because the payload failed `CallGraphOutput` deserialization)
//!   - impact   → `"Function not found: helper"` (wrong)
//!   - dead     → `functions_analyzed: 0`      (wrong)
//!   - importers→ `total: 0`                   (wrong)
//!
//! Fix: (a) CLI threads the detected language into the daemon request params
//! for all five commands; (b) the daemon's project-rooted handlers
//! auto-detect from the project root when the hint is absent
//! (`resolve_language_from_root`), so older clients benefit too. Explicit
//! `--lang` hints still win.
//!
//! These tests spawn a REAL daemon (30-minute idle timeout — the stop guard
//! below is mandatory) and assert the five commands produce Rust-shaped
//! results while the daemon is serving.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Scope guard: `daemon stop --project <fixture>` on drop, so the spawned
/// daemon never outlives the test (AGENTS.md daemon hygiene).
struct DaemonStopGuard {
    project: std::path::PathBuf,
    registry_dir: std::path::PathBuf,
}

impl Drop for DaemonStopGuard {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_tldr"))
            .args(["daemon", "stop", "--project"])
            .arg(&self.project)
            .env("TLDR_DAEMON_REGISTRY_DIR", &self.registry_dir)
            .output();
    }
}

/// A rust-ONLY fixture (no Python files, so a wrong-language analysis cannot
/// accidentally succeed): `main.rs` calls a local fn and imports the sibling
/// module; `utils.rs` defines the imported fn.
fn create_rust_fixture(prefix: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let fixture = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("fixture tempdir");
    std::fs::write(
        fixture.path().join("main.rs"),
        "mod utils;\n\nuse crate::utils::greet;\n\nfn main() {\n    helper();\n    greet();\n}\n\nfn helper() {\n    println!(\"hello\");\n}\n",
    )
    .expect("write main.rs");
    std::fs::write(
        fixture.path().join("utils.rs"),
        "pub fn greet() {\n    println!(\"greet\");\n}\n",
    )
    .expect("write utils.rs");
    let path = fixture.path().canonicalize().expect("canonicalize fixture");
    (fixture, path)
}

/// Wait until `daemon status --project <fixture>` reports "running".
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

/// Run one CLI analysis command with the daemon up and return stdout.
fn run_cli(args: &[&str], registry_dir: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(args)
        .env("TLDR_DAEMON_REGISTRY_DIR", registry_dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {:?}: {}", args, e));
    assert!(
        out.status.success(),
        "command {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Start one daemon over the rust fixture and run the FIVE affected commands
/// in daemon mode; each must produce Rust-shaped analysis (issue #83).
#[test]
fn daemon_serves_rust_language_for_all_five_commands_without_explicit_lang() {
    let registry = tempfile::Builder::new()
        .prefix("issue83-registry-")
        .tempdir()
        .expect("registry tempdir");
    let registry_dir = registry.path().to_path_buf();

    let (_fixture, fixture_path) = create_rust_fixture("issue83-rust-");

    let start = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "start", "--project"])
        .arg(&fixture_path)
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
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
    };

    assert!(
        wait_for_daemon_running(&fixture_path, Duration::from_secs(10), &registry_dir),
        "daemon never became reachable within 10 s"
    );

    // --- 1. context: Rust-styled signature (pre-fix: "def main()") ---------
    let stdout = run_cli(
        &[
            "context",
            "main",
            "--project",
            fixture_path.to_str().unwrap(),
        ],
        &registry_dir,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("context did not emit JSON: {} stdout={}", e, stdout));
    let functions = parsed
        .get("functions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !functions.is_empty(),
        "issue #83: daemon-served context found no functions; stdout={}",
        stdout
    );
    let signature = functions[0]
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        signature.contains("fn main") && !signature.contains("def "),
        "issue #83: daemon-served context must be Rust-styled, got {:?}",
        signature
    );

    // --- 2. calls: real edges (pre-fix daemon payload had none) ------------
    let stdout = run_cli(&["calls", fixture_path.to_str().unwrap()], &registry_dir);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("calls did not emit JSON: {} stdout={}", e, stdout));
    let edges = parsed
        .get("edges")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        edges.len() >= 2,
        "issue #83: calls must report the main→helper and main→greet edges, got {} \
         edges; stdout={}",
        edges.len(),
        stdout
    );
    let language = parsed
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        language, "rust",
        "issue #83: calls must report the detected language, got {:?}",
        language
    );

    // --- 3. impact: function resolvable in the Rust graph ------------------
    let stdout = run_cli(
        &["impact", "helper", fixture_path.to_str().unwrap()],
        &registry_dir,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("impact did not emit JSON: {} stdout={}", e, stdout));
    let targets = parsed
        .get("targets")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    assert!(
        !targets.is_empty(),
        "issue #83: daemon-served impact must resolve `helper` (pre-fix: \
         Function not found); stdout={}",
        stdout
    );
    let caller_count = targets
        .values()
        .next()
        .and_then(|t| t.get("caller_count"))
        .and_then(|v| v.as_u64());
    assert_eq!(
        caller_count,
        Some(1),
        "issue #83: `helper` is called by `main`; stdout={}",
        stdout
    );

    // --- 4. dead: functions actually analyzed (pre-fix: 0) ------------------
    let stdout = run_cli(&["dead", fixture_path.to_str().unwrap()], &registry_dir);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dead did not emit JSON: {} stdout={}", e, stdout));
    let analyzed = parsed
        .get("functions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        analyzed >= 3,
        "issue #83: dead must analyze main/helper/greet, got functions_analyzed={}; \
         stdout={}",
        analyzed,
        stdout
    );

    // --- 5. importers: Rust `use` scan (pre-fix: Python-only scan → 0) -----
    let stdout = run_cli(
        &["importers", "crate::utils", fixture_path.to_str().unwrap()],
        &registry_dir,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("importers did not emit JSON: {} stdout={}", e, stdout));
    let total = parsed.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        total >= 1,
        "issue #83: importers of `crate::utils` must find main.rs (it has \
         `use crate::utils;`), got total={}; stdout={}",
        total,
        stdout
    );
}

/// Explicit `--lang` must still win over auto-detection (back-compat gate).
#[test]
fn explicit_lang_flag_still_wins_in_daemon_mode() {
    let registry = tempfile::Builder::new()
        .prefix("issue83-registry-")
        .tempdir()
        .expect("registry tempdir");
    let registry_dir = registry.path().to_path_buf();

    let (_fixture, fixture_path) = create_rust_fixture("issue83-lang-");

    let start = Command::new(env!("CARGO_BIN_EXE_tldr"))
        .args(["daemon", "start", "--project"])
        .arg(&fixture_path)
        .env("TLDR_DAEMON_REGISTRY_DIR", &registry_dir)
        .output()
        .expect("daemon start spawn");
    assert!(start.status.success(), "daemon start failed");

    let _stop_guard = DaemonStopGuard {
        project: fixture_path.clone(),
        registry_dir: registry_dir.clone(),
    };

    assert!(
        wait_for_daemon_running(&fixture_path, Duration::from_secs(10), &registry_dir),
        "daemon never became reachable within 10 s"
    );

    // Ask for PYTHON explicitly on the rust fixture: the hint must win, so
    // the Python scan finds no functions and the report stays empty (this
    // pins "explicit hint wins" — auto-detect must NOT override it).
    let stdout = run_cli(
        &[
            "dead",
            fixture_path.to_str().unwrap(),
            "--lang",
            "python",
            "-f",
            "json",
        ],
        &registry_dir,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dead did not emit JSON: {} stdout={}", e, stdout));
    let analyzed = parsed
        .get("functions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        analyzed, 0,
        "explicit --lang python must win over auto-detection (rust fixture has no \
         .py sources); stdout={}",
        stdout
    );
}
