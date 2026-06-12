//! Shared project walker built on `ignore::WalkBuilder`.
//!
//! Honors `.gitignore`, skips hidden dirs, skips vendor/build dirs by default,
//! does not follow symlinks. Every project-wide filesystem walk in tldr
//! should go through this module instead of using `walkdir::WalkDir` directly.
//!
//! # Why this exists
//!
//! Raw `walkdir::WalkDir` doesn't honor `.gitignore`, doesn't skip vendor dirs
//! (like `node_modules`, `target`, `dist`), and by default follows symlinks.
//! In pnpm monorepos `node_modules/.pnpm/` is a symlink forest that causes
//! infinite loops (`tldr smells` on a 2GB pnpm repo ran for 10+ minutes
//! before being killed) and produces false findings inside vendored code.
//!
//! # Typical usage
//!
//! ```rust,ignore
//! use tldr_core::walker::walk_project;
//!
//! for entry in walk_project("src") {
//!     // `entry` is an `ignore::DirEntry` yielded only for non-ignored files.
//! }
//! ```
//!
//! Or with more control:
//!
//! ```rust,ignore
//! use tldr_core::walker::ProjectWalker;
//!
//! let files: Vec<_> = ProjectWalker::new("src")
//!     .max_depth(10)
//!     .extensions(&["rs"])
//!     .iter()
//!     .collect();
//! ```

use std::path::{Path, PathBuf};

use ignore::{DirEntry, WalkBuilder};

/// Directories skipped by default regardless of `.gitignore` presence.
///
/// Commands that explicitly need to scan vendored code (e.g. auditing
/// dependencies) can disable this list via
/// [`ProjectWalker::no_default_ignore`].
///
/// **api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-7)**: extended this
/// list to include common generated/vendored artifact dirs that previously
/// polluted language autodetection (e.g. doxygen `dox/` output, sphinx
/// `_build/`, gradle/maven build sinks, Python venvs and caches). These
/// directories ship in many third-party repositories — without skipping
/// them, `tldr patterns /tmp/repos/cpp-tinyxml2` mis-classified the project
/// as JavaScript-majority because the `docs/` doxygen output contained 63
/// generated `.js` files vs 3 actual `.cpp` source files.
pub const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    // Vendored / package-manager output
    "node_modules",
    "vendor",
    // Build sinks (general)
    "target",
    "dist",
    "build",
    "out",
    // fix-cl-3b-v1 (v0.5.0 CL-3b, IT3-ocaml-03 / #74): `bin` removed from
    // the unconditional skip list. It is a build sink for some toolchains
    // but is *authored source* for many layouts the analyzer must read —
    // dune (`bin/main.ml`, `bin/common.ml`), Rust (`src/bin/`), Go
    // (`bin/`/`cmd/` entry points). Skipping it made `references` /
    // `impact` report `definitions: []` / `total_references: 0` for
    // top-level functions defined under `bin/` even though `structure`,
    // `extract`, `definition`, and `interface` resolved them (those use
    // `get_file_tree`, whose `DEFAULT_SKIP_DIRS` had already dropped
    // `bin`). Compiled artifacts under `bin/` carry no source extension,
    // so the per-command extension filter / `is_source_file` gate drops
    // them anyway — removing the name from the skip list only recovers the
    // authored `.ml` / `.rs` / `.go` sources. JS/TS `bin/` source was
    // already preserved via `JS_TS_PRESERVED_DIRS` + `lang_hint`; this
    // makes the behavior uniform across languages.
    "obj",
    // JavaScript framework caches
    ".next",
    ".nuxt",
    // Doxygen output (typical custom-config dir; the more common `docs/`
    // is detected via the `doxygen.css` sentinel below since `docs/` may
    // legitimately hold authored markdown).
    "dox",
    // Python tooling
    "__pycache__",
    ".pytest_cache",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    // Coverage artefacts
    "coverage",
    ".coverage",
    // JVM tooling
    ".gradle",
    // Version control
    ".git",
];

/// Files whose presence in a directory indicates it is generator output
/// rather than authored source. When a directory contains any of these
/// sentinels at its top level, the walker skips it (subject to
/// [`ProjectWalker::no_default_ignore`]).
///
/// This is the secondary mechanism used to detect generated docs whose
/// directory name is itself ambiguous (e.g. `docs/` may be authored
/// markdown OR doxygen html output). A name-only ignore list cannot
/// distinguish those without reading inside the dir.
///
/// Sentinels chosen here are unambiguous markers of *generated* output:
/// - `doxygen.css` / `doxygen.svg`: doxygen-emitted style/asset files
///   (placed alongside generated HTML+JS by `doxygen` in its target dir).
/// - `.doctrees/` is sphinx's internal cache, typically inside `_build/`.
const GENERATED_DIR_SENTINELS: &[&str] = &["doxygen.css", "doxygen.svg"];

/// JS/TS-friendly subset of [`DEFAULT_EXCLUDE_DIRS`]: directories that are
/// build sinks for some languages (Rust `build/`, Java `dist/`) but commonly
/// hold authored source for JS/TS (`src/build/emitter.ts` in ts-dom-gen,
/// monorepo `packages/x/dist/index.ts`). When a [`ProjectWalker`] is
/// configured with [`ProjectWalker::lang_hint`] set to JS or TS, these
/// names are NOT auto-excluded — the walker defers to `.gitignore` instead.
///
/// residual-bugs-v1 (P15.AGG14-7-cascade): mirrors the per-language gate
/// already in `crates/tldr-core/src/callgraph/scanner.rs`
/// (`should_skip_build_or_dist_for_lang`). Without this gate `tldr dead`
/// (which uses `ProjectWalker`) returned `functions_analyzed: 0` on
/// ts-dom-gen even though `tldr calls` (which uses the scanner) returned
/// 112 nodes / 200 edges from the same file (`src/build/emitter.ts`).
const JS_TS_PRESERVED_DIRS: &[&str] = &["build", "dist", "out", "bin", "obj"];

/// Builder for project walks.
///
/// Produces an iterator of [`ignore::DirEntry`]s after applying:
/// - `.gitignore` / global gitignore / `.git/info/exclude` (default on)
/// - hidden-file filtering (always on)
/// - the [`DEFAULT_EXCLUDE_DIRS`] list (default on, disable via
///   [`ProjectWalker::no_default_ignore`])
/// - `follow_links(false)` (always — critical for pnpm symlink forests)
/// - optional max depth
/// - optional extension allow-list
/// - optional language hint that relaxes the JS/TS-friendly subset
///   ([`JS_TS_PRESERVED_DIRS`]) when set to `Language::JavaScript` or
///   `Language::TypeScript`
pub struct ProjectWalker {
    root: PathBuf,
    respect_gitignore: bool,
    default_ignore: bool,
    max_depth: Option<usize>,
    extensions: Option<Vec<&'static str>>,
    lang_hint: Option<crate::types::Language>,
}

impl ProjectWalker {
    /// Create a walker rooted at `root` with all default filters on.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            respect_gitignore: true,
            default_ignore: true,
            max_depth: None,
            extensions: None,
            lang_hint: None,
        }
    }

    /// Tell the walker which language it is being run for. When set to
    /// `Language::JavaScript` or `Language::TypeScript`, the walker stops
    /// auto-excluding [`JS_TS_PRESERVED_DIRS`] (`build`, `dist`, `out`,
    /// `bin`, `obj`) — JS/TS projects routinely keep authored source under
    /// these names. For all other languages the hint is a no-op (the
    /// default exclusion list applies).
    ///
    /// residual-bugs-v1 (P15.AGG14-7-cascade): without this hook, callers
    /// that already know the language (e.g. `tldr dead --lang typescript`)
    /// could not opt into the same per-language gate the call-graph
    /// scanner already implements, leading to 0-result outputs on repos
    /// like ts-dom-gen whose entire source surface lives at
    /// `src/build/emitter.ts`.
    pub fn lang_hint(mut self, lang: crate::types::Language) -> Self {
        self.lang_hint = Some(lang);
        self
    }

    /// Disable the [`DEFAULT_EXCLUDE_DIRS`] list.
    ///
    /// Use when a command explicitly needs to scan vendored code
    /// (e.g. `node_modules`, `target`). `.gitignore` is still honored
    /// unless [`ProjectWalker::respect_gitignore(false)`] is also set.
    pub fn no_default_ignore(mut self) -> Self {
        self.default_ignore = false;
        self
    }

    /// Control whether `.gitignore` rules are honored. Default: `true`.
    pub fn respect_gitignore(mut self, yes: bool) -> Self {
        self.respect_gitignore = yes;
        self
    }

    /// Limit recursion depth.
    pub fn max_depth(mut self, n: usize) -> Self {
        self.max_depth = Some(n);
        self
    }

    /// Only yield files with these extensions (e.g. `&["rs", "ts", "tsx"]`).
    ///
    /// Extensions should NOT include the leading dot. Matching is
    /// case-sensitive. Callers that want language-aware filtering should
    /// prefer `Language::from_path` after the walk.
    pub fn extensions(mut self, exts: &[&'static str]) -> Self {
        self.extensions = Some(exts.to_vec());
        self
    }

    /// Iterate yielded entries.
    ///
    /// Errors during traversal (permission denied, broken symlinks, etc.)
    /// are silently skipped — the caller gets only successful `DirEntry`s.
    pub fn iter(self) -> impl Iterator<Item = DirEntry> {
        let default_ignore = self.default_ignore;
        let extensions = self.extensions.clone();
        // residual-bugs-v1 (P15.AGG14-7-cascade): when the caller passes
        // a JS/TS language hint, the JS/TS-preserved subset of the
        // default exclude list is treated as opt-in (deferred to
        // `.gitignore`). Captured into a single bool so the closure
        // below stays cheap.
        //
        // cross-cutting-and-clear-fix-bugs-v1 (P18.X4): when no lang_hint
        // was supplied AND the root dir is dominated by JS/TS extensions
        // (counted permissively, ignoring the default skip list so the
        // count reflects actual content), opt into the same preservation
        // automatically. This fixes commands that don't explicitly set
        // `lang_hint` (patterns, deps, search, etc.) on JS/TS layouts
        // like `src/build/emitter.ts` where the only source is under a
        // name that's normally a build sink.
        let auto_js_ts = self.lang_hint.is_none() && root_is_js_ts_dominated(&self.root);
        let preserve_js_ts_dirs = auto_js_ts
            || matches!(
                self.lang_hint,
                Some(crate::types::Language::JavaScript) | Some(crate::types::Language::TypeScript)
            );

        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(true) // skip .hidden files/dirs
            .git_ignore(self.respect_gitignore)
            .git_global(self.respect_gitignore)
            .git_exclude(self.respect_gitignore)
            .parents(self.respect_gitignore)
            // CL-1 / GH #74: the `ignore` crate's single-threaded walk does
            // NOT yield entries in any defined order — it surfaces them in
            // filesystem readdir order, which varies by platform and even
            // between runs on the same machine. Every downstream consumer
            // (references, hubs, cohesion, complexity, health, …) that
            // collects walk results into a Vec and later truncates or
            // serializes therefore produced run-to-run-different output.
            // Pinning a total order on the FULL path makes the walk a
            // deterministic foundation so callers don't each have to
            // re-sort. We compare on the whole path (not just the file
            // name) so sibling files across different directories also
            // have a stable total order.
            .sort_by_file_path(|a, b| a.cmp(b))
            .follow_links(false); // CRITICAL: avoid pnpm symlink loops

        if let Some(depth) = self.max_depth {
            builder.max_depth(Some(depth));
        }

        if default_ignore {
            builder.filter_entry(move |entry| {
                // Only filter directory entries by the exclude list; files
                // named "node_modules" are fine to yield (edge case).
                let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                if !is_dir {
                    return true;
                }
                let name_excluded = match entry.file_name().to_str() {
                    Some(name) => {
                        if preserve_js_ts_dirs && JS_TS_PRESERVED_DIRS.contains(&name) {
                            // JS/TS hint active and the directory name is
                            // one of the names JS/TS callers commonly use
                            // for authored source — defer to .gitignore.
                            false
                        } else {
                            DEFAULT_EXCLUDE_DIRS.contains(&name)
                        }
                    }
                    None => false,
                };
                if name_excluded {
                    return false;
                }
                // api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-7):
                // sentinel-file detection for generator output whose
                // directory name is ambiguous (e.g. `docs/` containing
                // doxygen output). When a directory contains any of the
                // sentinel files at its top level, treat it as generated
                // and skip descent. This is a cheap top-level dir read,
                // performed only on directories not already excluded by
                // name above.
                if dir_has_generated_sentinel(entry.path()) {
                    return false;
                }
                true
            });
        }

        builder.build().filter_map(move |res| {
            let entry = res.ok()?;
            if let Some(ref allowed) = extensions {
                // Only apply extension filter to files; directories must
                // still pass through so we can descend into them.
                let is_file = entry.file_type().map(|ft| ft.is_file()).unwrap_or(false);
                if is_file {
                    let ext = entry.path().extension().and_then(|s| s.to_str());
                    match ext {
                        Some(e) if allowed.contains(&e) => Some(entry),
                        _ => None,
                    }
                } else {
                    Some(entry)
                }
            } else {
                Some(entry)
            }
        })
    }
}

/// Whether a directory contains any [`GENERATED_DIR_SENTINELS`] at its
/// top level. Used by [`ProjectWalker::iter`]'s `filter_entry` to skip
/// generator output dirs whose name is ambiguous.
///
/// The check reads only the top-level entries of `dir`; nested matches
/// are not considered (a project that authors a `doxygen.css` deep inside
/// its source tree is legitimate). Errors during read (permission denied,
/// non-directory) are treated as "no sentinel found" — the walker then
/// falls through to the normal name-based exclusion logic.
fn dir_has_generated_sentinel(dir: &Path) -> bool {
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

/// cross-cutting-and-clear-fix-bugs-v1 (P18.X4): permissive JS/TS
/// dominance check. Walks `dir` ignoring the default skip list (so the
/// count reflects what's REALLY there, not what's left after stripping
/// `build/`, `dist/`, etc.) and reports whether `.ts`/`.tsx`/`.js`/`.jsx`/
/// `.mjs`/`.cjs` files outnumber any other recognised language. Used to
/// opt ProjectWalker into JS/TS-preservation when the caller did not set
/// an explicit `lang_hint`.
///
/// To keep the cost bounded, the walk caps at 256 inspected files —
/// enough to disambiguate even small libraries without scanning a giant
/// monorepo every time.
fn root_is_js_ts_dominated(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let mut js_ts_count = 0usize;
    let mut other_count = 0usize;
    let mut inspected = 0usize;
    const CAP: usize = 256;
    let mut walker = WalkBuilder::new(dir);
    walker
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .follow_links(false);
    for entry in walker.build().flatten() {
        if inspected >= CAP {
            break;
        }
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let p = entry.path();
        let Some(ext) = p.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        match ext {
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => {
                js_ts_count += 1;
                inspected += 1;
            }
            "py" | "rs" | "go" | "java" | "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "kt"
            | "swift" | "rb" | "php" | "scala" | "lua" | "luau" | "ex" | "exs" | "ml" | "mli"
            | "cs" => {
                other_count += 1;
                inspected += 1;
            }
            _ => {}
        }
    }
    js_ts_count > other_count && js_ts_count > 0
}

/// Convenience free function: walk project with all defaults on.
///
/// Equivalent to `ProjectWalker::new(root).iter()`. Use [`ProjectWalker`]
/// directly for finer control (extension filters, max depth, opt-outs).
pub fn walk_project(root: impl AsRef<Path>) -> impl Iterator<Item = DirEntry> {
    ProjectWalker::new(root).iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn collect_rel_files(root: &Path, walker: impl Iterator<Item = DirEntry>) -> Vec<String> {
        let mut out: Vec<String> = walker
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(|e| {
                e.path()
                    .strip_prefix(root)
                    .unwrap_or(e.path())
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_string()
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn test_skips_node_modules_by_default() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("foo.rs"), "fn main() {}");
        write_file(&root.join("node_modules/bad.py"), "import os");

        let files = collect_rel_files(root, walk_project(root));
        assert_eq!(files, vec!["foo.rs".to_string()]);
    }

    #[test]
    fn test_skips_target_dist_build_cache() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("src/lib.rs"), "fn main() {}");
        write_file(&root.join("target/debug/x.rs"), "fn x() {}");
        write_file(&root.join("dist/bundle.js"), "// bundled");
        write_file(&root.join("build/out.o"), "binary");
        write_file(&root.join("__pycache__/cached.pyc"), "binary");
        write_file(&root.join(".next/cache.js"), "// cached");
        write_file(&root.join("vendor/dep.go"), "package v");

        let files = collect_rel_files(root, walk_project(root));
        assert_eq!(files, vec!["src/lib.rs".to_string()]);
    }

    #[test]
    fn test_respects_gitignore() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        // Gotcha: ignore crate only activates gitignore under a git repo or
        // if we register a custom ignore. Create a .git dir so it's treated
        // as a repo root.
        fs::create_dir_all(root.join(".git")).unwrap();
        write_file(&root.join(".gitignore"), "secret/\n");
        write_file(&root.join("foo.rs"), "fn main() {}");
        write_file(&root.join("secret/x.rs"), "fn x() {}");

        let files = collect_rel_files(root, walk_project(root));
        assert_eq!(files, vec!["foo.rs".to_string()]);
    }

    #[test]
    fn test_hidden_dirs_skipped() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("visible.rs"), "fn main() {}");
        write_file(&root.join(".hidden/secret.rs"), "fn secret() {}");

        let files = collect_rel_files(root, walk_project(root));
        assert_eq!(files, vec!["visible.rs".to_string()]);
    }

    #[test]
    fn test_does_not_follow_symlinks_into_loop() {
        // Build root/a.rs plus root/loop -> root to exercise the symlink
        // guard. On systems where symlinks aren't supported the call errors
        // out; just skip those.
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("a.rs"), "fn a() {}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            // Point a child dir back to root -> would loop if followed.
            let loop_path = root.join("loop");
            symlink(root, &loop_path).unwrap();
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            let loop_path = root.join("loop");
            // May fail without dev-mode; swallow the error so the rest of
            // the test still exercises normal traversal.
            let _ = symlink_dir(root, &loop_path);
        }

        // Traversal must terminate. Collect with a reasonable cap to
        // prevent a runaway test from hanging CI for infinity.
        let files: Vec<_> = walk_project(root).take(10_000).collect();
        // Must find a.rs exactly once; symlink target must not be
        // descended into.
        let count_a = files.iter().filter(|e| e.file_name() == "a.rs").count();
        assert_eq!(count_a, 1, "expected exactly one a.rs, got {}", count_a);
    }

    #[test]
    fn test_no_default_ignore_walks_node_modules() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("foo.rs"), "fn main() {}");
        write_file(&root.join("node_modules/bad.py"), "import os");

        let files = collect_rel_files(root, ProjectWalker::new(root).no_default_ignore().iter());
        assert!(
            files.contains(&"foo.rs".to_string()),
            "missing foo.rs: {files:?}"
        );
        assert!(
            files.contains(&"node_modules/bad.py".to_string()),
            "expected node_modules/bad.py to be walked with no_default_ignore: {files:?}"
        );
    }

    #[test]
    fn test_extensions_filter() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("a.rs"), "fn a() {}");
        write_file(&root.join("b.py"), "def b(): pass");
        write_file(&root.join("c.ts"), "function c() {}");

        let files = collect_rel_files(root, ProjectWalker::new(root).extensions(&["rs"]).iter());
        assert_eq!(files, vec!["a.rs".to_string()]);
    }

    #[test]
    fn test_max_depth_limits_recursion() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(&root.join("top.rs"), "fn top() {}");
        write_file(&root.join("a/b/deep.rs"), "fn deep() {}");

        // max_depth(1) should include entries exactly one level deep, i.e.
        // files immediately under root (top.rs and the `a` directory) but
        // not a/b/deep.rs.
        let files = collect_rel_files(root, ProjectWalker::new(root).max_depth(1).iter());
        assert!(files.contains(&"top.rs".to_string()), "{files:?}");
        assert!(
            !files.contains(&"a/b/deep.rs".to_string()),
            "max_depth=1 should have excluded deep file: {files:?}"
        );
    }
}
