//! VAL-010 (M11): change-impact git PATH resolution + origin/<branch> hint.
//!
//! Issue: GitHub parcadei/tldr-code#1 sub-issue #1.B.
//!
//! Two reproductions:
//!
//!  Test A (PATH fallback): `Command::new("git")` in change_impact.rs
//!    inherits the calling process's PATH. When PATH is empty (cargo-built
//!    CLI invoked with `env -i`), `git` cannot be located and the spawn
//!    fails with "No such file or directory (os error 2)". Change-impact
//!    must fall back to a known git binary (which::which lookup, then
//!    common Unix paths) so the analysis succeeds without PATH.
//!
//!  Test B (origin/<branch> hint): when the user passes `--base feature-x`
//!    and only `refs/remotes/origin/feature-x` exists locally (no local
//!    branch `feature-x`), the previous error reason was just "Branch
//!    'feature-x' not found" with no remediation hint. After the fix,
//!    the reason MUST contain the substring `origin/feature-x` so the
//!    user can correct their invocation.

use std::path::Path;
use std::sync::Mutex;

use tldr_core::analysis::{change_impact_extended, ChangeImpactStatus, DetectionMethod};
use tldr_core::types::Language;

/// Serialize tests that mutate process-global PATH so they don't trample
/// each other when cargo runs them in parallel.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn init_git_repo_with_one_commit(dir: &Path) {
    let run = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git should be available in the test environment");
        assert!(
            out.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };

    run(&["init", "-q"]);
    run(&["config", "user.email", "test@test.com"]);
    run(&["config", "user.name", "Test"]);
    run(&["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("README.md"), "# seed\n").unwrap();
    run(&["add", "README.md"]);
    run(&["commit", "-q", "-m", "seed"]);
}

/// Test A: change-impact must succeed when PATH is empty.
///
/// We strip PATH from the test process for the duration of the call,
/// then restore it. With the fix in place, change_impact_extended uses
/// `which::which` (which itself only consults PATH) PLUS an absolute-path
/// fallback list, so an empty PATH still resolves to /usr/bin/git or
/// /opt/homebrew/bin/git etc.
#[test]
fn change_impact_succeeds_when_path_is_empty() {
    use tempfile::TempDir;

    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    init_git_repo_with_one_commit(project);

    // Save original PATH and set it to a non-existent dir so git cannot
    // be located via PATH. NOTE: simply unsetting PATH is NOT enough on
    // macOS / glibc because execvp falls back to a built-in default
    // (`_PATH_DEFPATH` = "/usr/bin:/bin") and /usr/bin/git exists.
    let saved_path = std::env::var_os("PATH");
    let bogus_path = tmp.path().join("__no_such_dir_for_path__");
    // SAFETY: serialized via ENV_LOCK; restored before drop.
    unsafe {
        std::env::set_var("PATH", &bogus_path);
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        change_impact_extended(
            project,
            DetectionMethod::GitHead,
            Language::Python,
            10,
            true,
            &[],
            None,
        )
    }));

    // Restore PATH no matter what.
    // SAFETY: serialized via ENV_LOCK.
    unsafe {
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
    }

    let report = result
        .expect("call should not panic")
        .expect("change_impact_extended should return Ok even with empty PATH");

    // The clean tempdir tree should report NoChanges (baseline established
    // successfully). Pre-fix it returned NoBaseline because git could not
    // be spawned without PATH.
    match &report.status {
        ChangeImpactStatus::NoChanges => {
            // Expected post-fix.
        }
        ChangeImpactStatus::Completed => {
            // Also acceptable (zero changed files but Completed).
        }
        ChangeImpactStatus::NoBaseline { reason } => {
            panic!(
                "PATH fallback failed: change-impact returned NoBaseline with reason: {}\n\
                 Expected NoChanges (clean tree, baseline OK).",
                reason
            );
        }
        ChangeImpactStatus::DetectionFailed { reason } => {
            panic!(
                "PATH fallback failed: change-impact returned DetectionFailed: {}",
                reason
            );
        }
    }
}

/// Test B: when only `origin/<branch>` exists, the NoBaseline reason
/// MUST contain the hint substring `origin/<branch>` so the user knows
/// to retry with the qualified ref.
#[test]
fn detection_error_hints_at_origin_branch_when_only_remote_exists() {
    use tempfile::TempDir;

    // Acquire the ENV_LOCK so we don't race with `change_impact_succeeds_when
    // _path_is_empty` which transiently clears PATH process-wide. Without
    // this, our `git update-ref` invocation can fail with ENOENT when run
    // in parallel.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = TempDir::new().unwrap();
    let project = tmp.path();
    init_git_repo_with_one_commit(project);

    // Create only the remote-tracking ref `origin/feature-x` pointing at HEAD.
    // No local branch `feature-x` exists.
    let head_sha = {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(project)
            .output()
            .expect("git rev-parse HEAD should work in test env");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };

    let out = std::process::Command::new("git")
        .args(["update-ref", "refs/remotes/origin/feature-x", &head_sha])
        .current_dir(project)
        .output()
        .expect("git update-ref should work");
    assert!(
        out.status.success(),
        "update-ref failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Now invoke change-impact with --base feature-x (unqualified -> only
    // origin/feature-x exists). Pre-fix: error reason mentions "Branch
    // 'feature-x' not found" without any pointer to origin/feature-x.
    // Post-fix: reason MUST contain the substring `origin/feature-x`.
    let report = change_impact_extended(
        project,
        DetectionMethod::GitBase {
            base: "feature-x".to_string(),
        },
        Language::Python,
        10,
        true,
        &[],
        None,
    )
    .expect("change_impact_extended should return Ok (errors are surfaced via status)");

    let reason = match &report.status {
        ChangeImpactStatus::NoBaseline { reason } => reason.clone(),
        ChangeImpactStatus::DetectionFailed { reason } => reason.clone(),
        other => panic!(
            "expected NoBaseline or DetectionFailed status when --base resolves \
             only via origin/, got {:?}",
            other
        ),
    };

    assert!(
        reason.contains("origin/feature-x"),
        "expected detection-failure reason to suggest `origin/feature-x` \
         (since refs/remotes/origin/feature-x exists locally), got reason: {:?}",
        reason
    );
}
