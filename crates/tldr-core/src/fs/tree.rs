//! File tree traversal with ignore support
//!
//! Implements the `tree` command functionality (spec Section 2.1.1).
//!
//! # Mitigations Addressed
//! - M6: Large file memory (skip files > MAX_FILE_SIZE)
//! - M9: Path handling platform (use PathBuf, dunce for normalization)
//! - M12: Gitignore pattern edge cases (use ignore crate)
//! - M13: Symlink cycle detection (walkdir with inode tracking)

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ignore::gitignore::GitignoreBuilder;
use walkdir::{DirEntry, WalkDir};

use crate::error::TldrError;
use crate::types::{FileTree, IgnoreSpec, NodeType};
use crate::TldrResult;

/// Maximum file size to process (5MB) - M6 mitigation
pub const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Default directories to skip during traversal.
///
/// **api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-7)**: extended this
/// list to include common generated artifact dirs (e.g. `out`, `bin`,
/// `obj`, `.gradle`, `dox` for doxygen, `.pytest_cache`, `.mypy_cache`,
/// `.ruff_cache`) so `tldr patterns` and other tree-driven commands
/// don't mis-classify projects whose generated docs/build output happens
/// to outnumber authored sources.
pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    // Vendored / package-manager output
    "node_modules",
    "vendor",
    // Build sinks (general)
    "target",
    "dist",
    "build",
    "out",
    "bin",
    "obj",
    // JavaScript framework caches
    ".next",
    ".nuxt",
    // Doxygen output (typical custom-config dir; see GENERATED_DIR_SENTINELS
    // below for the `docs/` doxygen-output detection).
    "dox",
    // Python tooling
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".env",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    // Coverage artefacts
    "coverage",
    ".coverage",
    // JVM tooling
    ".gradle",
    // Version control
    ".git",
    ".svn",
    ".hg",
    // Editor caches
    ".idea",
    ".vscode",
    ".cache",
];

/// Files whose presence at the top level of a directory mark it as
/// generator output rather than authored source. Used by the file-tree
/// walker to skip directories whose name is ambiguous (e.g. `docs/`
/// containing doxygen html output vs `docs/` with authored markdown).
///
/// (api-check-and-patterns-accuracy-v1, P11.BUG-AGG-7)
const GENERATED_DIR_SENTINELS: &[&str] = &["doxygen.css", "doxygen.svg"];

/// Whether a directory contains any [`GENERATED_DIR_SENTINELS`] at its
/// top level. Cheap top-level read; nested matches are not considered.
pub(crate) fn dir_has_generated_sentinel(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if GENERATED_DIR_SENTINELS.contains(&name) {
                return true;
            }
        }
    }
    false
}

/// Get file tree structure with optional extension filtering.
///
/// # Arguments
/// * `root` - Root directory to scan
/// * `extensions` - Optional set of extensions to include (e.g., `{".py", ".ts"}`)
/// * `exclude_hidden` - Skip hidden files/directories (default: true)
/// * `ignore_spec` - Optional gitignore-style patterns
///
/// # Returns
/// * `Ok(FileTree)` - Tree structure with files and directories
/// * `Err(TldrError::PathNotFound)` - Root directory doesn't exist
/// * `Err(TldrError::PathTraversal)` - Path contains directory traversal
///
/// # Example
/// ```ignore
/// use std::collections::HashSet;
/// use tldr_core::fs::tree::get_file_tree;
///
/// let extensions: HashSet<String> = [".py".to_string()].into_iter().collect();
/// let tree = get_file_tree(Path::new("src"), Some(&extensions), true, None)?;
/// ```
pub fn get_file_tree(
    root: &Path,
    extensions: Option<&HashSet<String>>,
    exclude_hidden: bool,
    ignore_spec: Option<&IgnoreSpec>,
) -> TldrResult<FileTree> {
    // Validate root path exists
    if !root.exists() {
        return Err(TldrError::PathNotFound(root.to_path_buf()));
    }

    // Check for path traversal attempts - M9 mitigation
    let canonical =
        dunce::canonicalize(root).map_err(|_| TldrError::PathNotFound(root.to_path_buf()))?;

    // Detect path traversal by checking if the path contains ".."
    let path_str = root.to_string_lossy();
    if path_str.contains("..") {
        // Verify it actually escapes by comparing canonical with expected
        if let Ok(parent) = std::env::current_dir() {
            let joined = parent.join(root);
            if let Ok(joined_canonical) = dunce::canonicalize(&joined) {
                // If the canonical path doesn't start with parent, it's traversal
                if !joined_canonical.starts_with(&parent)
                    && !joined_canonical.starts_with(&canonical)
                {
                    return Err(TldrError::PathTraversal(root.to_path_buf()));
                }
            }
        }
    }

    // Build gitignore matcher if patterns provided
    let gitignore = build_gitignore(&canonical, ignore_spec);

    // Get root directory name
    let root_name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());

    // Build tree recursively
    let children = build_tree_children(
        &canonical,
        &canonical,
        extensions,
        exclude_hidden,
        gitignore.as_ref(),
    )?;

    Ok(FileTree::dir(root_name, children))
}

/// Build gitignore matcher from IgnoreSpec patterns
fn build_gitignore(
    root: &Path,
    ignore_spec: Option<&IgnoreSpec>,
) -> Option<ignore::gitignore::Gitignore> {
    let patterns = ignore_spec?.patterns.as_slice();
    if patterns.is_empty() {
        return None;
    }

    let mut builder = GitignoreBuilder::new(root);
    for pattern in patterns {
        // Add pattern - ignore errors for invalid patterns
        let _ = builder.add_line(None, pattern);
    }

    builder.build().ok()
}

/// Recursively build tree children
fn build_tree_children(
    dir: &Path,
    root: &Path,
    extensions: Option<&HashSet<String>>,
    exclude_hidden: bool,
    gitignore: Option<&ignore::gitignore::Gitignore>,
) -> TldrResult<Vec<FileTree>> {
    let mut children = Vec::new();

    // Use WalkDir with follow_links disabled for M13 (symlink cycle detection).
    // Because follow_links is false, walkdir physically cannot traverse a
    // symlink-induced cycle, so no in-walk inode tracking is required.
    // Issue #15: a previous inode-tracking heuristic incorrectly flagged
    // hardlinked files as cycles; that heuristic has been removed.
    // Note: We don't use filter_entry on the root, as filter_entry would skip
    // the entire directory if the root has a hidden name (like .tmp...)
    let walker = WalkDir::new(dir)
        .max_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Don't filter the root directory itself (depth 0)
            if e.depth() == 0 {
                return true;
            }
            should_include_entry(e, exclude_hidden, gitignore)
        });

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Skip the directory itself
        if path == dir {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        if entry.file_type().is_dir() {
            // Skip default skip directories
            if DEFAULT_SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }

            // api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-7):
            // skip directories that look like generator output (e.g.
            // doxygen-emitted `docs/`). The name-based ignore list above
            // can't catch these because `docs/` is also a legitimate
            // authored-content directory; the sentinel-file check
            // disambiguates by reading the dir's top level for
            // unambiguous generator artefacts.
            if dir_has_generated_sentinel(path) {
                continue;
            }

            // Recurse into directory
            let sub_children =
                build_tree_children(path, root, extensions, exclude_hidden, gitignore)?;

            // Only include directory if it has children (or no extension filter)
            if !sub_children.is_empty() || extensions.is_none() {
                children.push(FileTree::dir(name, sub_children));
            }
        } else if entry.file_type().is_file() {
            // Check extension filter
            if let Some(exts) = extensions {
                let ext = path
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                if !exts.contains(&ext) {
                    continue;
                }
            }

            // Get relative path from root
            let relative_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

            children.push(FileTree::file(name, relative_path));
        }
    }

    // Sort children: directories first, then files, alphabetically within each group
    children.sort_by(|a, b| match (&a.node_type, &b.node_type) {
        (NodeType::Dir, NodeType::File) => std::cmp::Ordering::Less,
        (NodeType::File, NodeType::Dir) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    Ok(children)
}

/// Check if a directory entry should be included
fn should_include_entry(
    entry: &DirEntry,
    exclude_hidden: bool,
    gitignore: Option<&ignore::gitignore::Gitignore>,
) -> bool {
    let name = entry.file_name().to_string_lossy();

    // Exclude hidden files if requested
    if exclude_hidden && name.starts_with('.') && name != "." && name != ".." {
        return false;
    }

    // Check gitignore patterns
    if let Some(gi) = gitignore {
        let is_dir = entry.file_type().is_dir();
        if gi.matched(entry.path(), is_dir).is_ignore() {
            return false;
        }
    }

    true
}

/// Collect all files from tree as flat list
pub fn collect_files(tree: &FileTree, root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_recursive(tree, root, &mut files);
    files
}

fn collect_files_recursive(tree: &FileTree, root: &Path, files: &mut Vec<PathBuf>) {
    match tree.node_type {
        NodeType::File => {
            if let Some(ref path) = tree.path {
                files.push(root.join(path));
            }
        }
        NodeType::Dir => {
            for child in &tree.children {
                collect_files_recursive(child, root, files);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create some test files
        fs::write(dir.path().join("main.py"), "# Python file").unwrap();
        fs::write(dir.path().join("utils.py"), "# Utils").unwrap();
        fs::write(dir.path().join("config.json"), "{}").unwrap();

        // Create subdirectory
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/module.py"), "# Module").unwrap();

        // Create hidden file
        fs::write(dir.path().join(".hidden"), "hidden").unwrap();

        dir
    }

    #[test]
    fn test_get_file_tree_basic() {
        let dir = create_test_dir();
        let tree = get_file_tree(dir.path(), None, true, None).unwrap();

        assert_eq!(tree.node_type, NodeType::Dir);
        assert!(!tree.children.is_empty());
    }

    #[test]
    fn test_get_file_tree_extension_filter() {
        let dir = create_test_dir();
        let extensions: HashSet<String> = [".py".to_string()].into_iter().collect();
        let tree = get_file_tree(dir.path(), Some(&extensions), true, None).unwrap();

        // All files should be .py
        fn check_extensions(node: &FileTree) {
            if node.node_type == NodeType::File {
                assert!(
                    node.name.ends_with(".py"),
                    "Found non-py file: {}",
                    node.name
                );
            }
            for child in &node.children {
                check_extensions(child);
            }
        }
        check_extensions(&tree);
    }

    #[test]
    fn test_get_file_tree_excludes_hidden() {
        let dir = create_test_dir();
        let tree = get_file_tree(dir.path(), None, true, None).unwrap();

        // No hidden files in children (root can be hidden like .tmp...)
        fn check_no_hidden(node: &FileTree) {
            assert!(
                !node.name.starts_with('.') || node.name == ".",
                "Hidden file found: {}",
                node.name
            );
            for child in &node.children {
                check_no_hidden(child);
            }
        }
        // Check only children, not the root (which can have .tmp prefix from tempfile)
        for child in &tree.children {
            check_no_hidden(child);
        }
    }

    #[test]
    fn test_get_file_tree_includes_hidden() {
        let dir = create_test_dir();
        let tree = get_file_tree(dir.path(), None, false, None).unwrap();

        // Should have hidden file
        fn has_hidden(node: &FileTree) -> bool {
            if node.name.starts_with('.') && node.name != "." {
                return true;
            }
            node.children.iter().any(has_hidden)
        }
        assert!(has_hidden(&tree), "No hidden files found");
    }

    #[test]
    fn test_get_file_tree_nonexistent() {
        let result = get_file_tree(Path::new("/nonexistent/path"), None, true, None);
        assert!(matches!(result, Err(TldrError::PathNotFound(_))));
    }

    #[test]
    fn test_get_file_tree_ignore_patterns() {
        let dir = create_test_dir();
        let ignore = IgnoreSpec::new(vec!["*.json".to_string()]);
        let tree = get_file_tree(dir.path(), None, true, Some(&ignore)).unwrap();

        // No .json files
        fn check_no_json(node: &FileTree) {
            assert!(
                !node.name.ends_with(".json"),
                "JSON file found: {}",
                node.name
            );
            for child in &node.children {
                check_no_json(child);
            }
        }
        check_no_json(&tree);
    }

    #[test]
    fn test_collect_files() {
        let dir = create_test_dir();
        let tree = get_file_tree(dir.path(), None, true, None).unwrap();
        let files = collect_files(&tree, dir.path());

        assert!(!files.is_empty());
        assert!(files.iter().any(|f| f.ends_with("main.py")));
    }

    /// Regression test for issue #15 — tree builder must NOT report
    /// SymlinkCycle when traversing a directory containing hardlinked files.
    /// WalkDir is configured with follow_links(false), so no real symlink
    /// cycle can occur; the previous inode-tracking heuristic incorrectly
    /// flagged hardlinks as cycles.
    #[test]
    fn test_get_file_tree_hardlinks_no_symlink_cycle() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.txt");
        let hard = dir.path().join("hardlink.txt");

        fs::write(&original, "shared content").unwrap();
        fs::hard_link(&original, &hard).expect("hardlink creation failed");

        // Sanity: both paths exist and reference the same inode on Unix.
        assert!(original.exists());
        assert!(hard.exists());

        let result = get_file_tree(dir.path(), None, true, None);

        // Pre-fix: returns Err(TldrError::SymlinkCycle(...)).
        // Post-fix: returns Ok with both files listed.
        assert!(
            result.is_ok(),
            "tree builder must not report SymlinkCycle on hardlinks; got: {:?}",
            result.err()
        );
        let tree = result.unwrap();
        let names: Vec<&str> = tree.children.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"original.txt") && names.contains(&"hardlink.txt"),
            "expected both hardlinked files in tree; got: {:?}",
            names
        );
    }
}
