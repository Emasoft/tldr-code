//! Path validation helpers for CLI commands.
//!
//! cli-error-clarity-v2 (P2.BUG-4): commands that operate on a project
//! directory (hubs, impact, whatbreaks, change-impact, …) historically
//! produced confusing errors when given a regular file:
//!
//! - `tldr hubs <file>` → `Error: Path not found: <file>` (false: it exists)
//! - `tldr change-impact <file>` → `Git: Not a directory (os error 20)`
//!   (cryptic; the user has no idea what to do)
//!
//! These helpers normalise the validation so every directory-taking command
//! returns the same clear, actionable error mentioning the file path and
//! suggesting the project root.
//!
//! All helpers return `anyhow::Error` so they can be used directly with the
//! `?` operator inside `run()` methods that already return
//! `anyhow::Result<()>`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Project-root marker filenames used by [`infer_project_root_for_file`].
///
/// These are the canonical "this directory is the root of a project" markers
/// across the languages tldr supports. The list is ordered so the most
/// language-specific markers come before the generic VCS marker — when a
/// monorepo has both `Cargo.toml` and `.git` at different levels, we want
/// the nearest crate root, not the repo root.
const PROJECT_ROOT_MARKERS: &[&str] = &[
    // Rust
    "Cargo.toml",
    // JavaScript / TypeScript
    "package.json",
    "tsconfig.json",
    // Python
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    // Go
    "go.mod",
    // Java / Kotlin / Scala
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    // Ruby
    "Gemfile",
    // PHP
    "composer.json",
    // C# / F#
    "*.csproj",
    "*.fsproj",
    // Elixir
    "mix.exs",
    // Generic VCS (last-resort fallback)
    ".git",
];

/// Walk up from `file_path` looking for the nearest ancestor directory
/// containing a project-root marker. Returns the ancestor directory when
/// found, or the file's immediate parent as a last-resort fallback.
///
/// Used by commands that accept either a directory (project root) or a
/// regular file (single-file scope) — when given a file, the project root
/// must be inferred so directory-walking analyses (call graph, test
/// discovery) still have a sensible base.
///
/// The traversal uses a small set of canonical markers covering all
/// languages tldr supports (Cargo.toml, package.json, pyproject.toml,
/// go.mod, …) plus `.git` as a generic last-resort marker. When no marker
/// is found anywhere up the chain, the file's immediate parent directory
/// is returned — analyses will still run, just scoped to that directory.
pub fn infer_project_root_for_file(file_path: &Path) -> PathBuf {
    let mut current = match file_path.parent() {
        Some(p) => p.to_path_buf(),
        None => return PathBuf::from("."),
    };
    let fallback = current.clone();

    loop {
        for marker in PROJECT_ROOT_MARKERS {
            if let Some(stripped) = marker.strip_prefix("*.") {
                // Glob-style: any file in this dir ending with `.<stripped>`
                if let Ok(entries) = std::fs::read_dir(&current) {
                    for entry in entries.flatten() {
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .ends_with(&format!(".{}", stripped))
                        {
                            return current;
                        }
                    }
                }
            } else if current.join(marker).exists() {
                return current;
            }
        }
        match current.parent() {
            Some(p) if p != current => current = p.to_path_buf(),
            _ => return fallback,
        }
    }
}

/// Validate that `path` exists and is a directory, producing clear error
/// messages on failure.
///
/// `command` is the CLI subcommand name (e.g. `"hubs"`) used to make the
/// error message specific.
pub fn require_directory(path: &Path, command: &str) -> Result<()> {
    if !path.exists() {
        bail!("Path not found: {}", path.display());
    }
    if path.is_file() {
        bail!(
            "{} requires a directory; got file '{}'. Pass the project root \
             or omit the argument to use the current directory.",
            command,
            path.display()
        );
    }
    if !path.is_dir() {
        bail!(
            "{} requires a directory; got non-directory path '{}'. Pass the \
             project root or omit the argument to use the current directory.",
            command,
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn directory_passes() {
        let dir = tempdir().unwrap();
        require_directory(dir.path(), "hubs").unwrap();
    }

    #[test]
    fn file_fails_with_clear_message() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.py");
        fs::write(&file, "x = 1\n").unwrap();
        let err = require_directory(&file, "hubs").unwrap_err().to_string();
        assert!(err.contains("hubs requires a directory"), "{}", err);
        assert!(err.contains(file.to_string_lossy().as_ref()), "{}", err);
    }

    #[test]
    fn missing_path_fails() {
        let err = require_directory(Path::new("/no/such/path/xyz"), "hubs")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Path not found"), "{}", err);
    }

    #[test]
    fn infer_project_root_finds_cargo_toml() {
        let dir = tempdir().unwrap();
        // <root>/Cargo.toml + <root>/src/foo.rs
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        let file = dir.path().join("src").join("foo.rs");
        fs::write(&file, "fn main() {}\n").unwrap();

        let root = infer_project_root_for_file(&file);
        // Both should resolve to the same directory after canonicalising.
        let want = std::fs::canonicalize(dir.path()).unwrap();
        let got = std::fs::canonicalize(&root).unwrap();
        assert_eq!(got, want, "expected {:?}, got {:?}", want, got);
    }

    #[test]
    fn infer_project_root_finds_package_json() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        let file = dir.path().join("src").join("foo.ts");
        fs::write(&file, "export const x = 1;\n").unwrap();

        let root = infer_project_root_for_file(&file);
        let want = std::fs::canonicalize(dir.path()).unwrap();
        let got = std::fs::canonicalize(&root).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn infer_project_root_falls_back_to_parent_when_no_marker() {
        // No Cargo.toml / package.json / .git anywhere — must still return
        // *some* directory (the file's parent) rather than panic or recurse
        // forever.
        let dir = tempdir().unwrap();
        let file = dir.path().join("alone.py");
        fs::write(&file, "x = 1\n").unwrap();
        let root = infer_project_root_for_file(&file);
        // The fallback is the file's parent, which is the temp dir itself.
        // After canonicalising both, they should match.
        let want = std::fs::canonicalize(dir.path()).unwrap();
        let got = std::fs::canonicalize(&root).unwrap();
        assert_eq!(got, want);
    }
}
