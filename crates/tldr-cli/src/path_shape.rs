//! path-shape-consistency-v1 (v0.4.2 M-008): centralized emission-boundary
//! path normalizer.
//!
//! The Phase-22 audit cluster M-008 found that ~12 languages exhibit the
//! same mechanical bug: within a single tldr response, paths are emitted
//! in MIXED shapes — some absolute, some relative — and on macOS the
//! `/private/tmp/` firmlink form sometimes leaks through.
//!
//! Root cause: each emitter site (impact, change-impact, verify, search,
//! structure, interface, …) hand-rolls its own `PathBuf::strip_prefix` +
//! `dunce::canonicalize` logic. Some sites canonicalize, some don't; some
//! handle the `/private` firmlink, some don't. The result is per-call-site
//! drift.
//!
//! This module is the single source-of-truth for "rewrite this path so it
//! matches the user-input shape". Every CLI command that joins data from
//! multiple producers (call-graph + AST + references + …) MUST route its
//! emitted paths through [`PathShapeRewriter::rewrite`] before serializing
//! the response.
//!
//! ## Invariants
//!
//! 1. **Shape echo**: if user passes absolute, every emitted path is
//!    absolute under the user-input prefix. If user passes relative,
//!    every emitted path is project-relative under the inferred root.
//!    Paired `root` + project-relative entries are allowed by the
//!    response schema (e.g. `tldr structure` emits root + relative
//!    `files[].path`); the rewriter leaves the paired form alone.
//!
//! 2. **macOS firmlink strip**: on Darwin, `/private/tmp/...` →
//!    `/tmp/...` whenever the user did NOT type `/private/` themselves.
//!    The same applies to `/private/var/...` for tempdirs created via
//!    `TempDir` which canonicalize through the firmlink.
//!
//! 3. **No-op safety**: paths that already match the user-input shape
//!    are returned unchanged (`None` from [`PathShapeRewriter::rewrite`])
//!    so the caller can avoid pointless allocations.
//!
//! ## Companion design item
//!
//! The policy question — what the canonical convention SHOULD be
//! (absolute / project-relative / paired) — is parked at design item
//! D-CROSS-1. This module enforces *mechanical* consistency only: shape
//! follows user input.

use std::path::{Path, PathBuf};

/// Centralized emission-boundary path rewriter.
///
/// Construct once per command invocation using the user-input root path,
/// then call [`PathShapeRewriter::rewrite`] (or one of the typed
/// convenience methods) on every emitted path before serializing the
/// response.
///
/// # Example
///
/// ```ignore
/// let rewriter = PathShapeRewriter::new(&user_input_root);
/// for entry in report.targets.values_mut() {
///     if let Some(np) = rewriter.rewrite(&entry.file) {
///         entry.file = np;
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PathShapeRewriter {
    /// User-input root, verbatim (no canonicalisation). This is the
    /// "ground truth" shape that every emitted path is rewritten to.
    user_root: PathBuf,
    /// Canonical form of `user_root` for prefix matching. `None` if
    /// canonicalisation failed (e.g. the path doesn't exist yet).
    canon_root: Option<PathBuf>,
    /// Whether the user-input root is itself absolute. When false, the
    /// rewriter prefers relative output (matches user shape).
    user_root_is_absolute: bool,
}

impl PathShapeRewriter {
    /// Build a rewriter for `user_root` (the path the user typed on the
    /// command line).
    pub fn new(user_root: &Path) -> Self {
        let canon_root = dunce::canonicalize(user_root).ok();
        let user_root_is_absolute = user_root.is_absolute();
        Self {
            user_root: user_root.to_path_buf(),
            canon_root,
            user_root_is_absolute,
        }
    }

    /// Rewrite a path-string to match the user-input shape, or return
    /// `None` if the input already matches.
    ///
    /// The rewrite rules apply in this order:
    ///
    /// 1. **Already user-shaped**: if `s` starts with `user_root`
    ///    verbatim, no rewrite needed.
    /// 2. **Canonical-prefix rewrite**: if `s` starts with the
    ///    canonical form of `user_root` (macOS `/private/tmp/...` when
    ///    user typed `/tmp/...`), rewrite the prefix back to
    ///    `user_root`.
    /// 3. **Darwin firmlink strip**: if `s` starts with `/private/`
    ///    AND the user did not type `/private/` themselves, strip the
    ///    `/private` segment unconditionally — this catches paths that
    ///    are absolute but rooted somewhere outside `user_root` (e.g.
    ///    external library references that still went through
    ///    `canonicalize`).
    /// 4. **Project-relative absolutise**: if `s` is project-relative
    ///    and the user-input root IS absolute, join `s` with
    ///    `user_root` so the response is uniformly absolute.
    /// 5. **Absolute → relative**: if `s` is absolute and starts with
    ///    `user_root` AND the user-input root is itself relative, strip
    ///    the prefix so the response is uniformly relative.
    pub fn rewrite(&self, s: &str) -> Option<String> {
        let p = Path::new(s);

        // 1. Already user-shaped: leave alone.
        if !self.user_root.as_os_str().is_empty() && p.starts_with(&self.user_root) {
            return None;
        }

        // 2. Canonical-prefix rewrite (macOS `/private/tmp/...`).
        if let Some(canon) = self.canon_root.as_ref() {
            if let Ok(suffix) = p.strip_prefix(canon) {
                let joined = if self.user_root.as_os_str().is_empty() {
                    suffix.to_path_buf()
                } else {
                    self.user_root.join(suffix)
                };
                return Some(joined.display().to_string());
            }
        }

        // 3. Darwin firmlink strip: `/private/tmp/...` → `/tmp/...`
        //    when user did NOT type `/private/` themselves. This
        //    catches paths that came from `canonicalize` but don't
        //    share the user-input prefix.
        //
        //    Rust spells macOS as `target_os = "macos"`, not "darwin".
        //    We run the strip-rule unconditionally across hosts: the
        //    audit evidence (python c39) was Darwin-only, but emitted
        //    JSON may be archived and replayed on Linux — keep the
        //    strip deterministic across hosts so replay assertions
        //    match production behaviour.
        if s.starts_with("/private/")
            && !self.user_root_starts_with_private()
        {
            // Strip the `/private` prefix (8 chars including the
            // trailing slash boundary). E.g. `/private/tmp/foo` →
            // `/tmp/foo`. After stripping, re-run rule 1/4 in case the
            // stripped form now matches user-input shape.
            let stripped = format!("/{}", &s[9..]);
            // Re-apply rule 1 on the stripped form: if user_root is
            // absolute and stripped now starts with user_root, accept.
            // Otherwise emit the stripped absolute form.
            let stripped_path = Path::new(&stripped);
            if !self.user_root.as_os_str().is_empty()
                && stripped_path.starts_with(&self.user_root)
            {
                return Some(stripped);
            }
            return Some(stripped);
        }

        // 4. Project-relative → absolutise against user_root (only
        //    when user_root is absolute — otherwise leave the relative
        //    form alone for the paired-root pattern).
        if p.is_relative() && self.user_root_is_absolute {
            return Some(self.user_root.join(p).display().to_string());
        }

        // 5. Absolute → relative (only when user_root is itself
        //    relative AND p sits under canon_root). This case is rare
        //    in practice — most CLI invocations pass absolute roots —
        //    but covered for completeness.
        if !self.user_root_is_absolute {
            if let Some(canon) = self.canon_root.as_ref() {
                if let Ok(suffix) = p.strip_prefix(canon) {
                    return Some(suffix.display().to_string());
                }
            }
        }

        None
    }

    /// Convenience for `PathBuf`-valued fields. Returns `Some(new_path)`
    /// when a rewrite is needed, `None` to keep the original.
    pub fn rewrite_pathbuf(&self, p: &Path) -> Option<PathBuf> {
        self.rewrite(&p.display().to_string())
            .map(PathBuf::from)
    }

    /// Walk a `serde_json::Value` tree in-place and rewrite every string
    /// value found under a key in `PATH_LIKE_KEYS`. Use this as a
    /// last-resort post-serialization pass for commands whose Rust
    /// types are too varied to walk structurally.
    ///
    /// **Prefer typed rewrites** ([`PathShapeRewriter::rewrite_pathbuf`])
    /// at the source where possible — JSON-walking has no schema
    /// awareness and may rewrite fields that happen to share a name
    /// with a path field but aren't actually paths. The
    /// `PATH_LIKE_KEYS` allow-list is conservative to avoid false
    /// positives.
    pub fn rewrite_json_in_place(&self, v: &mut serde_json::Value) {
        self.rewrite_json_inner(v, "");
    }

    fn rewrite_json_inner(&self, v: &mut serde_json::Value, parent_key: &str) {
        match v {
            serde_json::Value::String(s) => {
                if PATH_LIKE_KEYS.contains(&parent_key) {
                    if let Some(np) = self.rewrite(s.as_str()) {
                        *s = np;
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for x in arr.iter_mut() {
                    self.rewrite_json_inner(x, parent_key);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, vv) in map.iter_mut() {
                    let k_str = k.clone();
                    self.rewrite_json_inner(vv, k_str.as_str());
                }
            }
            _ => {}
        }
    }

    fn user_root_starts_with_private(&self) -> bool {
        self.user_root
            .components()
            .next()
            .map(|c| c.as_os_str() == "/" || c.as_os_str().is_empty())
            .unwrap_or(false)
            && self
                .user_root
                .to_string_lossy()
                .starts_with("/private/")
    }
}

/// Path-like JSON keys recognised by [`PathShapeRewriter::rewrite_json_in_place`].
/// Conservative allow-list: only string values found under one of these
/// keys are eligible for the rewrite. Adding a new key here is the
/// correct way to extend coverage when a new emitter ships.
pub const PATH_LIKE_KEYS: &[&str] = &[
    "file",
    "file_path",
    "path",
    "src_file",
    "dst_file",
    "source_file",
    "target_file",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_strips_private_firmlink_on_absolute_input() {
        // User typed /tmp/repos/foo; analyser leaked /private/tmp/repos/foo/x.go.
        // Expected: rewrite to /tmp/repos/foo/x.go.
        let r = PathShapeRewriter::new(Path::new("/tmp/repos/foo"));
        let got = r.rewrite("/private/tmp/repos/foo/x.go");
        // On a host where /tmp -> /private/tmp the canonical-prefix
        // rule fires; on a host where it does not, the firmlink-strip
        // rule fires. Either way the result is the user-shape.
        assert_eq!(got.as_deref(), Some("/tmp/repos/foo/x.go"));
    }

    #[test]
    fn rewrite_absolutises_relative_when_user_input_absolute() {
        let r = PathShapeRewriter::new(Path::new("/tmp/repos/foo"));
        let got = r.rewrite("router.go");
        assert_eq!(got.as_deref(), Some("/tmp/repos/foo/router.go"));
    }

    #[test]
    fn rewrite_leaves_user_shaped_paths_alone() {
        let r = PathShapeRewriter::new(Path::new("/tmp/repos/foo"));
        assert!(r.rewrite("/tmp/repos/foo/router.go").is_none());
    }

    #[test]
    fn rewrite_does_not_touch_private_when_user_typed_private() {
        let r = PathShapeRewriter::new(Path::new("/private/var/tmp/x"));
        // User explicitly wants /private/...; rewriter must NOT strip.
        let got = r.rewrite("/private/var/tmp/x/inner.go");
        assert!(got.is_none(), "no rewrite expected, got {:?}", got);
    }

    #[test]
    fn rewrite_json_in_place_walks_typed_keys_only() {
        let r = PathShapeRewriter::new(Path::new("/tmp/repos/foo"));
        let mut v: serde_json::Value = serde_json::json!({
            "file": "/private/tmp/repos/foo/a.rs",
            "irrelevant": "/private/tmp/elsewhere",
            "nested": [
                {"file_path": "b.rs"},
                {"path": "/tmp/repos/foo/c.rs"}
            ]
        });
        r.rewrite_json_in_place(&mut v);
        assert_eq!(v["file"], "/tmp/repos/foo/a.rs");
        // unrelated key: untouched
        assert_eq!(v["irrelevant"], "/private/tmp/elsewhere");
        assert_eq!(v["nested"][0]["file_path"], "/tmp/repos/foo/b.rs");
        // already user-shaped: untouched
        assert_eq!(v["nested"][1]["path"], "/tmp/repos/foo/c.rs");
    }
}
