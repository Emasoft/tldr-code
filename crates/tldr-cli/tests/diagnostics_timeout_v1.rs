//! diagnostics-subprocess-timeout-v1 (v0.4.2 cluster M-028):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 M-028):
//! > "`tldr diagnostics` hangs or times out without progress for several
//! >  langs (cpp/kotlin/lua/python/swift). Subprocess management lacks
//! >  per-tool timeout, partial-output streaming, and fast-fail when
//! >  default config absent."
//!
//! Root cause: `run_tool` in `crates/tldr-core/src/diagnostics/runner.rs`
//! spawned children with `stdout(Stdio::piped())` + `stderr(Stdio::piped())`
//! and waited for the child to exit (`try_wait` polling loop) BEFORE
//! reading the pipes. When tools emit large output (e.g. kotlinc on a
//! 223-file repo emits ~22k lines to stderr; luacheck on lua-lsp emits
//! ~10k lines to stdout), the OS pipe buffer (~64KB) fills up and the
//! child blocks writing — but `try_wait` never sees an exit, so the
//! parent times out at 60s with `error: "Timeout"` even though the
//! tool would have finished in ~3-13 seconds if drained concurrently.
//!
//! Fix (this v1):
//!   1. Spawn background threads to drain stdout & stderr concurrently
//!      with the child process (eliminates pipe deadlock).
//!   2. Close stdin (`Stdio::null()`) so tools never block waiting for
//!      input.
//!   3. On timeout, kill the child AND join drainer threads with a
//!      bounded wait so we still get partial output.
//!   4. Emit progress events to stderr (start / done / timeout) when
//!      `TLDR_DIAGNOSTICS_PROGRESS=1` is set, so users see something
//!      during long-running tool invocations.
//!
//! Tests are real-repo gated; skipped with a printed reason when a
//! corpus or required tool is missing.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

const LUA_LSP_CORPUS: &str = "/tmp/repos/lua-lsp";
const KOTLIN_DATETIME_CORPUS: &str = "/tmp/repos/kotlin-datetime";

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn tool_available(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_tldr_with_env(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String, u128) {
    let mut cmd = Command::new(tldr_bin());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let start = Instant::now();
    let out = cmd.output().expect("failed to run tldr binary");
    let elapsed = start.elapsed().as_millis();
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr, elapsed)
}

/// Test 1 — pipe-deadlock regression on luacheck (lua-lsp, ~10k diagnostics).
///
/// Before the fix, `tldr diagnostics --lang lua /tmp/repos/lua-lsp` would
/// time out at 60s ("error": "Timeout") even though luacheck completes
/// in ~3.5s standalone, because the parent waited on `try_wait` while
/// the child blocked on a full stdout pipe.
///
/// After the fix, the command should complete well under a generous
/// 45s ceiling AND report `success: true` for luacheck.
#[test]
fn luacheck_large_output_does_not_deadlock_on_pipes() {
    if !Path::new(LUA_LSP_CORPUS).exists() {
        eprintln!("SKIP: {} not present", LUA_LSP_CORPUS);
        return;
    }
    if !tool_available("luacheck") {
        eprintln!("SKIP: luacheck not on PATH");
        return;
    }

    let (exit, stdout, _stderr, elapsed) = run_tldr_with_env(
        &[
            "diagnostics",
            "--lang",
            "lua",
            "--timeout",
            "45",
            LUA_LSP_CORPUS,
        ],
        &[],
    );

    // Must complete in well under 30s (luacheck itself takes ~3.5s — the
    // remaining budget accounts for parsing 10k diagnostic lines).
    assert!(
        elapsed < 30_000,
        "luacheck hang regression: elapsed={}ms (expected < 30000ms)",
        elapsed
    );

    // tldr should exit 0 or 1 (not a panic / crash exit). Code 60/61
    // indicate "no tools available" / "all tools failed" and would
    // mean the pipe deadlock is back.
    assert!(
        exit == 0 || exit == 1,
        "unexpected exit code {} for luacheck run (would be 61 on deadlock)",
        exit
    );

    // Verify the luacheck tool ran successfully (not timed out).
    assert!(
        stdout.contains("\"name\": \"luacheck\""),
        "luacheck tool result missing from output"
    );
    assert!(
        !stdout.contains("\"error\": \"Timeout\""),
        "luacheck timed out — pipe-deadlock regression. stdout (head): {}",
        &stdout.chars().take(500).collect::<String>()
    );
}

/// Test 2 — pipe-deadlock regression on kotlinc (kotlin-datetime, ~22k lines stderr).
///
/// kotlinc emits its compiler diagnostics to STDERR (not stdout). Pre-fix
/// the parent did not drain stderr concurrently, so the child blocked
/// writing once stderr filled (~64KB on macOS).
#[test]
fn kotlinc_large_stderr_does_not_deadlock_on_pipes() {
    if !Path::new(KOTLIN_DATETIME_CORPUS).exists() {
        eprintln!("SKIP: {} not present", KOTLIN_DATETIME_CORPUS);
        return;
    }
    if !tool_available("kotlinc") {
        eprintln!("SKIP: kotlinc not on PATH");
        return;
    }

    // kotlinc on this corpus takes ~13s wall-clock standalone. Give a
    // generous ceiling of 60s and require completion well before that.
    let (exit, stdout, _stderr, elapsed) = run_tldr_with_env(
        &[
            "diagnostics",
            "--lang",
            "kotlin",
            "--tools",
            "kotlinc",
            "--timeout",
            "90",
            KOTLIN_DATETIME_CORPUS,
        ],
        &[],
    );

    assert!(
        elapsed < 60_000,
        "kotlinc hang regression: elapsed={}ms (expected < 60000ms)",
        elapsed
    );
    assert!(
        exit == 0 || exit == 1,
        "unexpected exit code {} for kotlinc run",
        exit
    );

    // Either kotlinc ran successfully (no Timeout) OR it produced
    // diagnostics. The bad state is `error: "Timeout"` after 90s.
    let timed_out = stdout.contains("\"error\": \"Timeout\"");
    assert!(
        !timed_out,
        "kotlinc timed out — pipe-deadlock regression. elapsed={}ms",
        elapsed
    );
}

/// Test 3 — timeout actually fires and is bounded (no runaway).
///
/// We invoke kotlinc with a very short --timeout (2s). The tool would
/// take ~13s on this corpus, so it MUST be killed. The parent should
/// return within a small grace window (we allow up to 8s to cover
/// process kill + drain join). Pre-fix, the parent would just wait
/// the full 2s and report Timeout BUT the broader complaint is that
/// when output was large, even Timeout would be delayed indefinitely
/// because the polling loop only checked the elapsed time once per
/// 100ms cycle AND because the read-stdout step at the end could
/// block forever on a still-buffered pipe.
#[test]
fn short_timeout_is_enforced_with_bounded_grace() {
    if !Path::new(KOTLIN_DATETIME_CORPUS).exists() {
        eprintln!("SKIP: {} not present", KOTLIN_DATETIME_CORPUS);
        return;
    }
    if !tool_available("kotlinc") {
        eprintln!("SKIP: kotlinc not on PATH");
        return;
    }

    let (exit, stdout, _stderr, elapsed) = run_tldr_with_env(
        &[
            "diagnostics",
            "--lang",
            "kotlin",
            "--tools",
            "kotlinc",
            "--timeout",
            "2",
            KOTLIN_DATETIME_CORPUS,
        ],
        &[],
    );

    // Must return within a bounded grace window after the 2s timeout.
    // Grace = pipe-drain join (1s cap) + process kill propagation +
    // tldr post-processing. 10s ceiling is very generous.
    assert!(
        elapsed < 10_000,
        "short --timeout=2 did not bound runtime: elapsed={}ms (expected < 10000ms)",
        elapsed
    );

    // tldr exits 0/1 (success/errors-found) or 61 (all-tools-failed:
    // legitimate when the only tool times out). The bad state is a
    // panic exit (-1) or a hang past the 10s ceiling above.
    assert!(
        exit == 0 || exit == 1 || exit == 61,
        "unexpected exit code {} for short-timeout run",
        exit
    );

    // The tool result MUST be marked as Timeout.
    assert!(
        stdout.contains("\"error\": \"Timeout\""),
        "expected Timeout marker in tool result. stdout head: {}",
        &stdout.chars().take(400).collect::<String>()
    );
}

/// Test 4 — TLDR_DIAGNOSTICS_PROGRESS=1 emits progress messages on stderr.
///
/// Pre-fix there was zero feedback during long-running tool runs.
/// With the env opt-in, each tool emits a "starting" line at spawn and
/// a "done"/"timeout" line at finish, so users see progress.
#[test]
fn progress_env_var_emits_stderr_events() {
    if !Path::new(LUA_LSP_CORPUS).exists() {
        eprintln!("SKIP: {} not present", LUA_LSP_CORPUS);
        return;
    }
    if !tool_available("luacheck") {
        eprintln!("SKIP: luacheck not on PATH");
        return;
    }

    let (_exit, _stdout, stderr, _elapsed) = run_tldr_with_env(
        &[
            "diagnostics",
            "--lang",
            "lua",
            "--timeout",
            "45",
            LUA_LSP_CORPUS,
        ],
        &[("TLDR_DIAGNOSTICS_PROGRESS", "1")],
    );

    // Look for the structured progress prefix used by the runner. We
    // require both a start AND a finish event for luacheck.
    assert!(
        stderr.contains("[diagnostics] starting luacheck"),
        "expected start progress event in stderr; got: {}",
        &stderr.chars().take(400).collect::<String>()
    );
    assert!(
        stderr.contains("[diagnostics] luacheck"),
        "expected luacheck progress event(s) in stderr; got: {}",
        &stderr.chars().take(400).collect::<String>()
    );
}

/// Test 5 — progress env var OFF is the default (no spam).
///
/// We must NOT spam stderr by default. This guards against an
/// accidental always-on regression.
#[test]
fn progress_silent_by_default() {
    if !Path::new(LUA_LSP_CORPUS).exists() {
        eprintln!("SKIP: {} not present", LUA_LSP_CORPUS);
        return;
    }
    if !tool_available("luacheck") {
        eprintln!("SKIP: luacheck not on PATH");
        return;
    }

    let (_exit, _stdout, stderr, _elapsed) = run_tldr_with_env(
        &[
            "diagnostics",
            "--lang",
            "lua",
            "--timeout",
            "45",
            LUA_LSP_CORPUS,
        ],
        &[],
    );

    assert!(
        !stderr.contains("[diagnostics] starting"),
        "progress event leaked with no opt-in: {}",
        &stderr.chars().take(400).collect::<String>()
    );
}
