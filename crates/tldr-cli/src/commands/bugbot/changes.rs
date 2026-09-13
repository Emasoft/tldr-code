//! Git change detection for bugbot
//!
//! Detects files changed via git, filtered to the target language.
//! Uses direct `git` commands to list changed files -- no call graph needed.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use tldr_core::Language;

/// Result of detecting changed files in the project.
#[derive(Debug, Clone)]
pub struct ChangeDetectionResult {
    /// Files that changed and match the target language.
    pub changed_files: Vec<PathBuf>,
    /// How changes were detected (e.g. "git:staged", "git:uncommitted").
    pub detection_method: String,
}

/// Resolve and canonicalize the git repository root for `project`.
///
/// The git invocations in this module are all made to print paths relative to
/// the repository top-level directory -- `diff --name-only` does so inherently
/// (verified: `git -C <subdir> diff --name-only` still emits `<subdir>/file`),
/// and `ls-files` only when its caller passes `--full-name`. This is the single place
/// that resolves and canonicalizes that root, so every `git_changed_files`
/// call made from the same `detect_changes` invocation joins against the
/// exact same value -- a subdirectory `project` (e.g. a crate dir under the
/// repo) never gets its segment doubled (TRDD-M2MUQ7QH), and the result
/// compares equal to any other canonicalized path even when the OS reports
/// the same location under two different spellings (e.g. macOS `/var/...`
/// vs `/private/var/...`). Callers must not canonicalize `project`
/// themselves and expect it to matter here -- this function is the only
/// source of truth for the repo root, by construction, not by convention.
fn resolve_canonical_repo_root(project: &Path) -> Result<PathBuf> {
    let root_output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(project)
        .output()
        .context("Failed to resolve git repository root")?;
    if !root_output.status.success() {
        let stderr = String::from_utf8_lossy(&root_output.stderr);
        anyhow::bail!("git rev-parse --show-toplevel failed: {}", stderr);
    }
    let raw_root = String::from_utf8_lossy(&root_output.stdout)
        .trim()
        .to_string();
    if raw_root.is_empty() {
        anyhow::bail!(
            "git rev-parse --show-toplevel returned an empty path for '{}' \
             (expected a work-tree root; this happens for a bare repo, or \
             when GIT_DIR is set without a work tree)",
            project.display()
        );
    }
    PathBuf::from(&raw_root)
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize git repository root '{raw_root}'"))
}

/// Run a git command in `project`, then join each non-empty stdout line onto `repo_root`.
///
/// `repo_root` (never `project`) is the correct join base even when `project` is a
/// subdirectory -- but only if `args` make git print root-relative paths, which
/// CALLERS MUST ENSURE. It is inherent for `diff --name-only`; `ls-files` requires
/// `--full-name` (it is CWD-relative otherwise). A caller that omits it produces
/// paths under `repo_root` that point nowhere -- which the escape guard below
/// cannot detect, because such a path is still under the root. The `ls-files`
/// case is therefore enforced below rather than merely documented.
fn git_changed_files(project: &Path, repo_root: &Path, args: &[&str]) -> Result<Vec<PathBuf>> {
    // `ls-files` is CWD-relative unless `--full-name` is passed, so joining its
    // output onto `repo_root` from a subdirectory `project` yields paths that are
    // under the root yet point nowhere -- a wrongness the `starts_with` guard
    // below is structurally unable to see. Fail fast on the caller's mistake
    // rather than returning plausible-looking garbage. This is a contract check,
    // not error handling: a correct caller can never trip it.
    if args.contains(&"ls-files") && !args.contains(&"--full-name") {
        anyhow::bail!(
            "git_changed_files called with `ls-files` but without `--full-name`: {:?}. \
             `ls-files` reports paths relative to the current directory, so its output \
             cannot be joined onto the repo root without it.",
            args
        );
    }

    let output = Command::new("git")
        .args(args)
        .current_dir(project)
        .output()
        .context("Failed to run git")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let joined = repo_root.join(l);
            // `Path::join` silently DISCARDS `repo_root` when `l` is absolute
            // (or drops back out of it via `..`), so a malformed/adversarial
            // line in git's stdout can produce a path outside `repo_root` --
            // and the next consumer of this list, `filter_tldrignored`,
            // panics on exactly that ("path is expected to be under the
            // root"), with no indication of which line caused it. Fail fast
            // here instead, with the offending line named, rather than
            // silently dropping it (that would hide malformed git output)
            // or letting the panic surface downstream with no context.
            if !joined.starts_with(repo_root) {
                anyhow::bail!(
                    "git reported a path outside the repo root: line {:?} joined onto \
                     {:?} produced {:?}, which escapes the root",
                    l,
                    repo_root,
                    joined
                );
            }
            Ok(joined)
        })
        .collect()
}

/// Detect changed files in `project`, filtered to the given `language`.
///
/// # Arguments
/// * `project` - Project root directory (must be inside a git repo)
/// * `base_ref` - Git base reference (e.g. "HEAD", "main", "origin/main")
/// * `staged` - If true, only consider staged changes; otherwise all uncommitted
/// * `language` - Only return files matching this language's extensions
///
/// # Detection Method
/// - `staged == true`  => `"git:staged"`
/// - `staged == false` and `base_ref == "HEAD"` => `"git:uncommitted"`
/// - `staged == false` and `base_ref != "HEAD"` => `"git:{base_ref}...HEAD"`
///
/// # Returns
/// A `ChangeDetectionResult` with the filtered file list and the detection method string.
pub fn detect_changes(
    project: &Path,
    base_ref: &str,
    staged: bool,
    language: &Language,
) -> Result<ChangeDetectionResult> {
    // Resolve the canonical repo root exactly once, here, and pass it down
    // to every `git_changed_files` call below -- see `resolve_canonical_repo_root`
    // for why a single shared resolution point (rather than each call
    // re-resolving and re-canonicalizing on its own) is what prevents the
    // root used for one call from silently drifting from the root used for
    // another within the same `detect_changes` invocation.
    let repo_root = resolve_canonical_repo_root(project)?;

    let (raw_files, detection_method) = if staged {
        let files = git_changed_files(project, &repo_root, &["diff", "--name-only", "--staged"])
            .context("Failed to list staged changes")?;
        (files, "git:staged".to_string())
    } else if base_ref == "HEAD" {
        // Uncommitted = modified tracked + staged + untracked
        let mut files = git_changed_files(project, &repo_root, &["diff", "--name-only", "HEAD"])
            .context("Failed to list uncommitted changes")?;
        let staged_files =
            git_changed_files(project, &repo_root, &["diff", "--name-only", "--staged"])
                .context("Failed to list staged changes")?;

        // `--full-name` is load-bearing: unlike `diff --name-only`, `ls-files`
        // defaults to printing paths relative to the CURRENT DIRECTORY, not the
        // repo top level (verified: `git -C crates/tldr-cli ls-files` prints
        // `Cargo.toml`; with `--full-name` it prints `crates/tldr-cli/Cargo.toml`).
        // Without it, a `project` below the repo root yields lines that join onto
        // `repo_root` into paths that do not exist -- and the escape guard in
        // `git_changed_files` does NOT catch that, because such a path is still
        // under the root, just wrong.
        let untracked = git_changed_files(
            project,
            &repo_root,
            &["ls-files", "--others", "--exclude-standard", "--full-name"],
        )
        .context("Failed to list untracked files")?;
        files.extend(staged_files);
        files.extend(untracked);
        files.sort();
        files.dedup();
        (files, "git:uncommitted".to_string())
    } else {
        let range = format!("{}...HEAD", base_ref);
        let files = git_changed_files(project, &repo_root, &["diff", "--name-only", &range])
            .context("Failed to list base-ref changes")?;
        (files, format!("git:{}...HEAD", base_ref))
    };

    // Filter files to only those matching the target language's extensions.
    let valid_extensions = language.extensions();
    let changed_files: Vec<PathBuf> = raw_files
        .into_iter()
        .filter(|f| {
            f.extension()
                .and_then(|e| e.to_str())
                .map(|ext| {
                    let dotted = format!(".{}", ext);
                    valid_extensions.contains(&dotted.as_str())
                })
                .unwrap_or(false)
        })
        .collect();

    // Filter out paths matching .tldrignore patterns (e.g. corpus/, vendor/).
    // `changed_files` entries were joined against `repo_root` (see
    // `git_changed_files`), so the ignore matcher must be rooted at the SAME
    // base -- `repo_root` is canonical and git reports paths relative to the
    // repo top level anyway. Passing the non-canonical `project` here panics
    // when it differs from `repo_root` only by symlink resolution (e.g.
    // macOS /var/folders vs /private/var/folders).
    let changed_files = tldr_core::callgraph::filter_tldrignored(&repo_root, changed_files);

    Ok(ChangeDetectionResult {
        changed_files,
        detection_method,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: initialize a git repo with an initial commit in a temp directory.
    fn init_git_repo() -> TempDir {
        let tmp = TempDir::new().expect("create temp dir");
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .expect("git init");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .expect("git config email");

        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .expect("git config name");

        // Create an initial commit so HEAD exists
        std::fs::write(dir.join("README.md"), "# test\n").expect("write readme");
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .expect("git commit");

        tmp
    }

    #[test]
    fn test_detect_changes_no_changes_returns_empty() {
        let tmp = init_git_repo();
        let result =
            detect_changes(tmp.path(), "HEAD", false, &Language::Rust).expect("detect_changes");

        assert!(
            result.changed_files.is_empty(),
            "Expected no changed files in a clean repo, got: {:?}",
            result.changed_files
        );
        assert_eq!(result.detection_method, "git:uncommitted");
    }

    #[test]
    fn test_detect_changes_staged_method() {
        let tmp = init_git_repo();
        let result =
            detect_changes(tmp.path(), "HEAD", true, &Language::Rust).expect("detect_changes");

        assert_eq!(result.detection_method, "git:staged");
    }

    #[test]
    fn test_detect_changes_base_ref_method() {
        let tmp = init_git_repo();
        // Create a branch named "main" so the base ref is valid
        Command::new("git")
            .args(["branch", "main"])
            .current_dir(tmp.path())
            .output()
            .expect("git branch main");

        let result =
            detect_changes(tmp.path(), "main", false, &Language::Python).expect("detect_changes");

        assert_eq!(result.detection_method, "git:main...HEAD");
    }

    #[test]
    fn test_detect_changes_filters_by_language() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // Create uncommitted files of different languages
        std::fs::write(dir.join("hello.rs"), "fn main() {}\n").expect("write rs");
        std::fs::write(dir.join("hello.py"), "print('hi')\n").expect("write py");
        std::fs::write(dir.join("hello.js"), "console.log('hi')\n").expect("write js");

        // Stage them all (so git sees them as changes)
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");

        // Detect only Rust changes
        let result =
            detect_changes(dir, "HEAD", true, &Language::Rust).expect("detect_changes rust");

        // Only .rs files should appear
        for f in &result.changed_files {
            assert_eq!(
                f.extension().and_then(|e| e.to_str()),
                Some("rs"),
                "Expected only .rs files, got: {}",
                f.display()
            );
        }
        assert!(
            !result.changed_files.is_empty(),
            "Expected at least one .rs file in changed_files"
        );

        // Detect only Python changes
        let result =
            detect_changes(dir, "HEAD", true, &Language::Python).expect("detect_changes python");

        for f in &result.changed_files {
            assert_eq!(
                f.extension().and_then(|e| e.to_str()),
                Some("py"),
                "Expected only .py files, got: {}",
                f.display()
            );
        }
        assert!(
            !result.changed_files.is_empty(),
            "Expected at least one .py file in changed_files"
        );
    }

    #[test]
    fn test_detect_changes_uncommitted_finds_unstaged() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // Modify a tracked file (create it first, commit, then modify)
        let rs_file = dir.join("lib.rs");
        std::fs::write(&rs_file, "pub fn old() {}\n").expect("write rs");
        Command::new("git")
            .args(["add", "lib.rs"])
            .current_dir(dir)
            .output()
            .expect("git add");
        Command::new("git")
            .args(["commit", "-m", "add lib"])
            .current_dir(dir)
            .output()
            .expect("git commit");

        // Now modify it without staging
        std::fs::write(&rs_file, "pub fn new_version() {}\n").expect("overwrite rs");

        let result = detect_changes(dir, "HEAD", false, &Language::Rust).expect("detect_changes");

        assert_eq!(result.detection_method, "git:uncommitted");
        assert!(
            result.changed_files.iter().any(|f| {
                f.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "lib.rs")
                    .unwrap_or(false)
            }),
            "Expected lib.rs in changed files, got: {:?}",
            result.changed_files
        );
    }

    #[test]
    fn test_detect_changes_ignores_non_matching_extensions() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // Create only non-Rust files
        std::fs::write(dir.join("app.py"), "x = 1\n").expect("write py");
        std::fs::write(dir.join("app.js"), "var x = 1;\n").expect("write js");
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");

        let result = detect_changes(dir, "HEAD", true, &Language::Rust).expect("detect_changes");

        assert!(
            result.changed_files.is_empty(),
            "Expected no Rust files when only .py and .js were changed, got: {:?}",
            result.changed_files
        );
    }

    #[test]
    fn test_change_detection_result_fields() {
        let result = ChangeDetectionResult {
            changed_files: vec![PathBuf::from("src/main.rs")],
            detection_method: "git:staged".to_string(),
        };
        assert_eq!(result.changed_files.len(), 1);
        assert_eq!(result.detection_method, "git:staged");
    }

    #[test]
    fn test_detect_changes_respects_tldrignore() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // Create files in corpus/ (should be ignored) and src/ (should survive)
        std::fs::create_dir_all(dir.join("corpus")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("corpus/vendored.py"), "x = 1\n").unwrap();
        std::fs::write(dir.join("src/main.py"), "y = 2\n").unwrap();

        // Create .tldrignore excluding corpus/
        std::fs::write(dir.join(".tldrignore"), "corpus/\n").unwrap();

        // Stage all files
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");

        let result = detect_changes(dir, "HEAD", true, &Language::Python).expect("detect_changes");

        // corpus/vendored.py should be excluded, only src/main.py remains
        assert!(
            !result
                .changed_files
                .iter()
                .any(|f| { f.to_string_lossy().contains("corpus") }),
            "corpus/ files should be excluded by .tldrignore, got: {:?}",
            result.changed_files
        );
        assert!(
            result.changed_files.iter().any(|f| {
                f.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "main.py")
                    .unwrap_or(false)
            }),
            "src/main.py should be present, got: {:?}",
            result.changed_files
        );
    }

    #[test]
    fn test_detect_changes_project_is_subdirectory_of_repo_root() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // `project` will be `<dir>/crate`, a SUBDIRECTORY of the repo root
        // `<dir>` itself. This is the only shape where rooting the
        // `.tldrignore` matcher at `project` (the old, buggy behavior) and
        // rooting it at `repo_root` (the fix) can actually disagree -- every
        // other test in this file uses `project == repo_root`.
        std::fs::create_dir_all(dir.join("crate/src")).unwrap();
        std::fs::write(dir.join("crate/src/main.py"), "y = 2\n").unwrap();
        std::fs::create_dir_all(dir.join("other")).unwrap();
        std::fs::write(dir.join("other/skip.py"), "x = 1\n").unwrap();

        // `.tldrignore` lives at the REPO ROOT, not under `project`.
        std::fs::write(dir.join(".tldrignore"), "other/\n").unwrap();

        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");

        let project = dir.join("crate");
        let result =
            detect_changes(&project, "HEAD", true, &Language::Python).expect("detect_changes");

        let repo_root = dir.canonicalize().expect("canonicalize repo root");
        let expected = vec![repo_root.join("crate/src/main.py")];
        assert_eq!(
            result.changed_files, expected,
            "expected exactly crate/src/main.py, got: {:?}",
            result.changed_files
        );
    }

    #[test]
    fn test_detect_changes_untracked_in_subdirectory_project_resolves_to_real_path() {
        let tmp = init_git_repo();
        let dir = tmp.path();

        // An UNTRACKED file under a crate subdirectory. Untracked files are the
        // only ones reached via `ls-files`, which -- unlike `diff --name-only` --
        // reports CWD-relative paths unless `--full-name` is passed. Without that
        // flag this returns `<repo_root>/src/new.py`, a path that does not exist,
        // instead of `<repo_root>/crate/src/new.py`.
        std::fs::create_dir_all(dir.join("crate/src")).unwrap();
        std::fs::write(dir.join("crate/src/new.py"), "z = 3\n").unwrap();

        // An untracked file the repo-root `.tldrignore` excludes BY ITS
        // ROOT-RELATIVE path. It only matches once the path is spelled
        // `crate/vendor/skip.py`; the buggy spelling `vendor/skip.py` slips
        // past the matcher. So this also pins the ignore interaction, which
        // path-validity alone would not cover.
        std::fs::create_dir_all(dir.join("crate/vendor")).unwrap();
        std::fs::write(dir.join("crate/vendor/skip.py"), "w = 4\n").unwrap();
        std::fs::write(dir.join(".tldrignore"), "crate/vendor/\n").unwrap();

        let project = dir.join("crate");
        let result =
            detect_changes(&project, "HEAD", false, &Language::Python).expect("detect_changes");

        let repo_root = dir.canonicalize().expect("canonicalize repo root");
        assert!(
            result
                .changed_files
                .contains(&repo_root.join("crate/src/new.py")),
            "expected the real path crate/src/new.py, got: {:?}",
            result.changed_files
        );
        // The wrong path is named explicitly so a reader sees exactly which
        // regression this guards; it can never pass vacuously.
        assert!(
            !result.changed_files.contains(&repo_root.join("src/new.py")),
            "got the CWD-relative spelling src/new.py -- `--full-name` is missing: {:?}",
            result.changed_files
        );
        assert!(
            !result
                .changed_files
                .iter()
                .any(|f| f.to_string_lossy().contains("skip.py")),
            "crate/vendor/ is .tldrignore'd and must not survive, got: {:?}",
            result.changed_files
        );
    }

    #[test]
    fn test_git_changed_files_rejects_ls_files_without_full_name() {
        let tmp = init_git_repo();
        let dir = tmp.path();
        let repo_root = dir.canonicalize().expect("canonicalize repo root");

        let err = git_changed_files(dir, &repo_root, &["ls-files", "--others"])
            .expect_err("ls-files without --full-name must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("--full-name"),
            "error must name the missing flag, got: {msg}"
        );

        // The positive control must produce a real path, not merely avoid
        // erroring -- otherwise it cannot tell a correct guard from one that
        // never fires at all.
        std::fs::write(dir.join("x.py"), "").unwrap();
        let ok = git_changed_files(dir, &repo_root, &["ls-files", "--others", "--full-name"])
            .expect("ls-files with --full-name must be accepted");
        assert!(
            ok.contains(&repo_root.join("x.py")),
            "expected x.py in {ok:?}"
        );
    }
}
