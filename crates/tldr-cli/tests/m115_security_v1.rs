//! m115-security-v1 (v0.4.2 M-115)
//!
//! Wave 17g: close three security issues surfaced by the iter-3 audit.
//!
//! 1. **#52 Daemon PID file symlink-following (HIGH)** — the daemon's
//!    PID code path opened the PID file with `std::fs::File::open` /
//!    `std::fs::read_to_string`, which silently follows symlinks. An
//!    attacker who could plant a symlink at the PID path (e.g. under
//!    `$TMPDIR` shared between users) could redirect the victim's
//!    `daemon stop` / `daemon start` write to an arbitrary file.
//!    Fix: open the PID file with `O_NOFOLLOW` so the call returns
//!    `ELOOP` (`io::ErrorKind::FilesystemLoop` on stable, mapped to
//!    `DaemonError::PidSymlink`) instead of dereferencing the link.
//!
//! 2. **#56 Secrets scanner misses alphanumeric high-entropy strings** —
//!    `is_likely_false_positive` in `tldr-core/src/security/secrets.rs`
//!    treated any string matching `^[A-Za-z0-9+/]+=*$` as a base64
//!    look-alike and discarded it. A 40-char alphanumeric API-key-shaped
//!    token (entropy > 4.5 bits/char) was suppressed despite being
//!    exactly the high-entropy signal the scanner was supposed to flag.
//!    Fix: drop the pure-character-class base64 suppression — entropy
//!    is the signal — and keep the structural patterns (UUID, hex
//!    hashes, repeated chars, dotted version strings) that genuinely
//!    indicate non-secrets.
//!
//! 3. **#37 Daemon `smells` endpoint path traversal** — documentation
//!    only this wave. The mitigation ("do not expose the daemon outside
//!    localhost") IS the current default. `SECURITY.md` at the repo
//!    root documents the threat model, the known issue, and the
//!    reporting channel.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// #52 — Daemon PID file symlink rejected
// =============================================================================

#[cfg(unix)]
#[test]
fn issue_52_pid_symlink_rejected() {
    use std::os::unix::fs::symlink;
    use tldr_cli::commands::daemon::pid::{check_stale_pid, try_acquire_lock};

    let tmp = tempfile::tempdir().unwrap();
    let pid_path = tmp.path().join("tldr-fake.pid");
    let evil_target = tmp.path().join("evil-target.txt");

    // Pre-create the symlink target with sentinel content. After the
    // exploit attempt, this file must remain UNTOUCHED — that's how we
    // detect the daemon would have followed the symlink and truncated
    // / overwritten an arbitrary file owned by the victim.
    fs::write(&evil_target, b"SENTINEL_CONTENT_DO_NOT_OVERWRITE\n").unwrap();

    // Plant the symlink at the PID path.
    symlink(&evil_target, &pid_path).expect("symlink failed");
    assert!(
        fs::symlink_metadata(&pid_path).unwrap().file_type().is_symlink(),
        "pid_path must be a symlink for this test to be meaningful",
    );

    // 1) `try_acquire_lock` must refuse to open through the symlink.
    let acquire_result = try_acquire_lock(&pid_path);
    assert!(
        acquire_result.is_err(),
        "try_acquire_lock must refuse to follow a symlinked PID file",
    );

    // 2) `check_stale_pid` must also refuse — it's called on the
    //    `daemon stop` path before any read.
    let stale_result = check_stale_pid(&pid_path);
    assert!(
        stale_result.is_err(),
        "check_stale_pid must refuse to follow a symlinked PID file",
    );

    // 3) The sentinel target must NOT have been truncated or modified.
    let target_after = fs::read(&evil_target).unwrap();
    assert_eq!(
        target_after, b"SENTINEL_CONTENT_DO_NOT_OVERWRITE\n",
        "symlink target was modified — daemon followed the symlink",
    );
}

// =============================================================================
// #56 — Alphanumeric high-entropy strings are detected
// =============================================================================

#[test]
fn issue_56_alphanumeric_high_entropy_detected() {
    // Use the `tldr_core::security::secrets` API directly so we don't
    // depend on the `tldr secrets` subcommand being wired (the M-115
    // fix is in the library; the CLI is just a thin caller).
    use tldr_core::security::secrets::scan_secrets;

    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("config.py");

    // A 40-char alphanumeric API-key-shaped token. Entropy of this
    // specific string is > 4.5 bits/char (verified offline). It is
    // pure [A-Za-z0-9], which is exactly the character class the old
    // `is_likely_false_positive` regex `^[A-Za-z0-9+/]+=*$` suppressed.
    //
    // Pre-fix: scanner reports 0 high-entropy findings.
    // Post-fix: scanner reports >= 1 high-entropy finding for this string.
    let api_key = "aZ7Qm3Lp9Xr2Yt5Bn8Wj4Vk6Hs1Cf0Du8Eg3MoNi";
    assert_eq!(api_key.len(), 40);

    let contents = format!("config_token = \"{}\"\n", api_key);
    fs::write(&target, contents).unwrap();

    let report = scan_secrets(&target, 4.5, false, None).expect("scan_secrets");

    let high_entropy_hits: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "High Entropy")
        .collect();

    assert!(
        !high_entropy_hits.is_empty(),
        "expected at least one High Entropy finding for a 40-char \
         alphanumeric token with entropy > 4.5 bits/char; got findings: {:?}",
        report.findings.iter().map(|f| &f.pattern).collect::<Vec<_>>(),
    );
}

// =============================================================================
// #37 — SECURITY.md exists at the repo root
// =============================================================================

#[test]
fn issue_37_security_md_documented() {
    // CARGO_MANIFEST_DIR for tldr-cli = crates/tldr-cli/. The repo root
    // is two parents up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let security_md = repo_root.join("SECURITY.md");

    assert!(
        security_md.exists(),
        "SECURITY.md must exist at repo root: {}",
        security_md.display(),
    );

    let body = fs::read_to_string(&security_md).expect("read SECURITY.md");

    // Must reference issue #37 explicitly so the audit trail is intact.
    assert!(
        body.contains("#37"),
        "SECURITY.md must reference issue #37 by number",
    );

    // Must contain a "Reporting" section (some form of disclosure channel).
    let lower = body.to_lowercase();
    assert!(
        lower.contains("reporting") || lower.contains("report a"),
        "SECURITY.md must describe a reporting process",
    );

    // Must contain a threat model section.
    assert!(
        lower.contains("threat model"),
        "SECURITY.md must contain a threat model section",
    );

    // Must mention localhost-only / single-user posture.
    assert!(
        lower.contains("localhost") || lower.contains("local-only"),
        "SECURITY.md must document the localhost-only posture",
    );
}

// Silence the unused-import warning on platforms where we don't run
// the symlink test.
#[cfg(not(unix))]
#[allow(dead_code)]
fn _unused() {
    let _ = Value::Null;
    let _ = tldr_cmd();
}
