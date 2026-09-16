//! Document blast radius (doclinks-v1)
//!
//! File-level impact analysis for **documents**: given a doc file, find every
//! document that (transitively) links to it. This is the document analogue of
//! `impact_analysis`'s reverse call-graph BFS — "who breaks if I change this
//! file" for markdown/html/xml and the CSS/LaTeX loaded elements (`@import`,
//! `url()`, `\input`, `\includegraphics`, …).
//!
//! # Why the impact BFS is reused verbatim
//!
//! `build_caller_tree_visited` (analysis/impact.rs) traverses a reverse map
//! keyed by `(file, function)` pairs. Nothing in it cares that the function
//! slot holds a real function — a file-level link graph only needs the file
//! half of the key. This module therefore builds:
//!
//! ```text
//! reverse: (linked-to file, "<doc>") -> [(linking file, "<doc>")]
//! ```
//!
//! and runs the SAME traversal with `FunctionKey(file, "<doc>")`. Cycle
//! detection, same-level dedup, depth truncation and the entry-point note
//! semantics are inherited unchanged (`build_caller_tree_visited` was made
//! `pub(crate)` for exactly this — no callgraph/scanner changes).
//!
//! # Link graph construction
//!
//! Every doc-language file in the project (extension union of Markdown, Html,
//! Xml, Css, Latex, Json, Yaml, Toml, Bash via `get_file_tree`/`collect_files`)
//! contributes edges:
//! `get_imports` yields one `ImportInfo` per document link (see
//! `ast::doclinks`), and each raw target is resolved to a project file:
//!
//! 1. strip `#fragment` / `?query`, collapse leading `./`, trim trailing `/`;
//! 2. **skip** empty targets and external URLs (`://`, `mailto:`) — they are
//!    kept in the imports output but can never resolve to a project file;
//! 3. resolve `linking_file.parent().join(target)` first (markdown/HTML
//!    relative-URL semantics: a link is read against the document that
//!    contains it), then fall back to `root.join(target)` for links written
//!    from the project root's perspective (generated indexes and the
//!    "exact" project-relative spelling);
//! 4. skip anything that does not exist or lands outside the project root.
//!
//! # Output shape
//!
//! A single-target [`ImpactReport`]: the targets key is `"<file>:<doc>"` and
//! the root node carries `note: Some("discovered via document link")` so
//! consumers can tell document blast radius apart from code impact. Child
//! notes (entry point / cycle detected / truncated at depth limit) come from
//! the BFS itself.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::analysis::impact::build_caller_tree_visited;
use crate::ast::imports::get_imports;
use crate::error::TldrError;
use crate::fs::sniff::sniff_extensionless_files;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{IgnoreSpec, ImpactReport, Language};
use crate::TldrResult;

/// Synthetic function-name slot for the file-level link graph. The impact
/// BFS keys nodes by `(file, function)`; documents occupy the function slot
/// with this marker so the same traversal code runs untouched.
pub(crate) const DOC_NODE: &str = "<doc>";

/// Root note stamped on the document impact target node — provenance for
/// consumers distinguishing doc-link closure from code call-graph impact.
const DOC_NOTE: &str = "discovered via document link";

/// The document languages participating in the document link graph:
/// markdown/html/xml hyperlinks, the CSS/LaTeX loaded elements (`@import`,
/// `url()`, `\input`, `\includegraphics`, `\bibliography`, …), the
/// config-batch reference surfaces — JSON/YAML `$ref`/`extends` mapping
/// keys, TOML path-shaped string values, bash `source`/`.` script loads —
/// and (plain-text batch) the `.txt` whole-document URL/path scan (see
/// `ast::doclinks` for each language's extraction policy).
pub fn is_doc_language(language: Language) -> bool {
    matches!(
        language,
        Language::Markdown
            | Language::Html
            | Language::Xml
            | Language::Css
            | Language::Latex
            | Language::Json
            | Language::Yaml
            | Language::Toml
            | Language::Bash
            | Language::Text
    )
}

/// Extension union of the document languages, for the file walk.
fn doc_language_extensions() -> HashSet<String> {
    [
        Language::Markdown,
        Language::Html,
        Language::Xml,
        Language::Css,
        Language::Latex,
        Language::Json,
        Language::Yaml,
        Language::Toml,
        Language::Bash,
        Language::Text,
    ]
    .iter()
    .flat_map(|l| l.extensions().iter().map(|s| s.to_string()))
    .collect()
}

/// Compute the document blast radius of `target` inside the project `root`:
/// the transitive reverse-link closure (every file that links to it, every
/// file that links to those, up to `depth` levels).
///
/// # Arguments
/// * `root` - Project root directory (walked for doc-language files)
/// * `target` - The document file whose blast radius is queried
/// * `language` - Language hint for the target (used only as a per-file
///   detection fallback; the walk classifies each file by its own extension)
/// * `depth` - Maximum traversal depth (same semantics as `impact_analysis`)
///
/// # Returns
/// * `Ok(ImpactReport)` - Single-target report keyed `"<file>:<doc>"`
/// * `Err(TldrError::PathNotFound)` - Target or root does not exist
pub fn document_impact(
    root: &Path,
    target: &Path,
    language: Language,
    depth: usize,
) -> TldrResult<ImpactReport> {
    if !root.exists() {
        return Err(TldrError::PathNotFound(root.to_path_buf()));
    }
    if !target.exists() {
        return Err(TldrError::PathNotFound(target.to_path_buf()));
    }

    // Canonical forms up front: every reverse-map key and the BFS query key
    // must agree byte-for-byte regardless of how the caller spelled the
    // paths (relative root, `./` segments, symlinked tempdirs on macOS).
    let canonical_root = dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let canonical_target = dunce::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());

    let extensions = doc_language_extensions();
    let tree = get_file_tree(
        &canonical_root,
        Some(&extensions),
        true,
        Some(&IgnoreSpec::default()),
    )?;
    let mut files = collect_files(&tree, &canonical_root);

    // extensionless-targets-v1: the extension walk above cannot see
    // extensionless files at all (the walker's extension filter drops them),
    // so `LICENSE` / `Makefile` / `.bashrc` were invisible to the document
    // link graph. Probe them now: `sniff_extensionless_files` re-walks for
    // exactly that population (hidden files INCLUDED — dotfiles are the
    // flagship extensionless population and are otherwise unreachable) and
    // sniffs each with one bounded ≤4 KiB read; binary content and
    // unsupported shebangs drop out and contribute no node. Sniffed Text and
    // Bash targets both carry reference surfaces (`get_imports`), so they
    // join the graph like any doc-language file. Code-language walks are
    // untouched.
    let sniffed = sniff_extensionless_files(&canonical_root, Some(&IgnoreSpec::default()));
    let sniffed_langs: HashMap<PathBuf, Language> = sniffed.iter().cloned().collect();
    for (path, _) in &sniffed {
        files.push(path.clone());
    }

    // Reverse link graph: (linked-to file, DOC) -> [(linking file, DOC)].
    type FunctionKey = (PathBuf, String);
    let mut reverse: HashMap<FunctionKey, Vec<FunctionKey>> = HashMap::new();

    for file in &files {
        let Ok(canonical_file) = dunce::canonicalize(file) else {
            continue;
        };
        if !canonical_file.starts_with(&canonical_root) {
            continue;
        }
        // extensionless-targets-v1: a sniffed extensionless file must be
        // parsed as its SNIFFED language — the `language` fallback below is
        // the TARGET's hint and would misread a sniffed `.bashrc` as, say,
        // the markdown target's language.
        let file_lang = sniffed_langs
            .get(&canonical_file)
            .copied()
            .or_else(|| Language::from_path(&canonical_file))
            .unwrap_or(language);
        let imports = match get_imports(&canonical_file, file_lang) {
            Ok(imports) => imports,
            // why: same recovery contract as `find_importers` — parse
            // failures on individual files are skipped, everything else
            // propagates (fail-fast).
            Err(e) if e.is_recoverable() => continue,
            Err(e) => return Err(e),
        };

        let from_dir = canonical_file
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| canonical_root.clone());

        for import in &imports {
            let Some(resolved) = resolve_doc_target(&canonical_root, &from_dir, &import.module)
            else {
                // Unresolved and external targets contribute no edge; they
                // stay visible in `tldr imports` output.
                continue;
            };
            reverse
                .entry((resolved, DOC_NODE.to_string()))
                .or_default()
                .push((canonical_file.clone(), DOC_NODE.to_string()));
        }
    }

    // Deterministic output: sort + dedup caller lists (the same file linking
    // the same target twice — e.g. two links to one page — must not produce
    // duplicate caller nodes).
    for callers in reverse.values_mut() {
        callers.sort();
        callers.dedup();
    }

    let visited: HashSet<FunctionKey> = [(canonical_target.clone(), DOC_NODE.to_string())]
        .into_iter()
        .collect();
    let mut root_tree =
        build_caller_tree_visited(&canonical_target, DOC_NODE, &reverse, depth, visited);
    // Stamp the provenance note on the ROOT node; child notes (entry point /
    // cycle / truncation) are inherited from the BFS.
    root_tree.note = Some(DOC_NOTE.to_string());

    let mut targets = HashMap::new();
    targets.insert(
        format!("{}:{}", canonical_target.display(), DOC_NODE),
        root_tree,
    );
    Ok(ImpactReport {
        targets,
        total_targets: 1,
        type_resolution: None,
    })
}

/// Resolve a raw link target string to a project file, if it points at one.
///
/// Resolution rules (in order):
/// 1. normalize: strip `#fragment` / `?query`, collapse leading `./`,
///    trim trailing `/`;
/// 2. skip empty targets and external URLs (`://`, `mailto:`);
/// 3. **spelling candidates:** the LITERAL normalized target first, then —
///    when it differs — the percent-DECODED form (`%20` → space, …). The
///    plain-text extraction keeps percent-encoded tokens raw
///    (`ast::doclinks::scan_paths_and_urls`), so a link written
///    `guide%20with%20spaces.md` only resolves when the decoded spelling is
///    tried here; the reverse — a raw-space target like
///    `<./docs/guide with spaces.md>` — needs no decoding (spaces are legal
///    path characters and `Path::join` carries them verbatim). Decoding is
///    a std-only `%XX` byte pass; malformed escapes stay verbatim.
/// 4. absolute targets are taken as-is when they exist;
/// 5. otherwise try `from_dir.join(candidate)` first — markdown/HTML resolve
///    a relative URL against the document that contains it — and fall back
///    to `root.join(candidate)` (the "exact" project-relative spelling, e.g.
///    links written from the project root's perspective);
/// 6. the winner is canonicalized so it matches the BFS query key space;
///    callers drop anything outside the project root. A spelling is only
///    retried when the previous spelling found nothing, so a file literally
///    named `a%20b.md` wins over its decoded reading `a b.md`.
fn resolve_doc_target(root: &Path, from_dir: &Path, raw: &str) -> Option<PathBuf> {
    let mut module = raw;
    if let Some(pos) = module.find(['#', '?']) {
        module = &module[..pos];
    }
    while let Some(stripped) = module.strip_prefix("./") {
        module = stripped;
    }
    let module = module.trim_end_matches('/');

    if module.is_empty() {
        return None;
    }
    if module.contains("://") || module.starts_with("mailto:") {
        return None;
    }

    // Spelling candidates: literal first, then the decoded form when it
    // differs (rule 3).
    let mut spellings = vec![module.to_string()];
    let decoded = percent_decode(module);
    if decoded != module {
        spellings.push(decoded);
    }

    for spelling in &spellings {
        let candidate = if spelling.starts_with('/') {
            PathBuf::from(spelling)
        } else {
            let from_file = from_dir.join(spelling);
            if from_file.exists() {
                from_file
            } else {
                let from_root = root.join(spelling);
                if from_root.exists() {
                    from_root
                } else {
                    continue; // this spelling found nothing — try the next
                }
            }
        };
        return Some(dunce::canonicalize(&candidate).unwrap_or(candidate));
    }
    None
}

/// Minimal std-only percent-decoding: every `%XX` hex pair becomes its byte,
/// everything else passes through verbatim (malformed escapes included).
/// Invalid UTF-8 after decoding is lossy-repaired — link targets that decode
/// to non-UTF-8 bytes are pathological and unresolvable anyway.
fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0);
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0);
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// index.md -> a.md -> b.md chain plus an external link from a.md.
    fn build_doc_project() -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("index.md"), "# Index\n\n[A](a.md)\n").unwrap();
        fs::write(
            dir.path().join("a.md"),
            "# A\n\n[B](b.md) [ext](https://example.com/x)\n",
        )
        .unwrap();
        fs::write(dir.path().join("b.md"), "# B\n\n[C](c.md#frag)\n").unwrap();
        dir
    }

    #[test]
    fn is_doc_language_covers_the_ten_doc_languages() {
        assert!(is_doc_language(Language::Markdown));
        assert!(is_doc_language(Language::Html));
        assert!(is_doc_language(Language::Xml));
        assert!(is_doc_language(Language::Css));
        assert!(is_doc_language(Language::Latex));
        // doclinks-v1 config batch: config files join the reference graph.
        assert!(is_doc_language(Language::Json));
        assert!(is_doc_language(Language::Yaml));
        assert!(is_doc_language(Language::Toml));
        assert!(is_doc_language(Language::Bash));
        // plain-text batch: `.txt` joins with the URL/path prose scan.
        assert!(is_doc_language(Language::Text));
        assert!(!is_doc_language(Language::Python));
        assert!(!is_doc_language(Language::Log));
    }

    #[test]
    fn resolve_doc_target_tries_literal_then_percent_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("docs")).unwrap();
        // A file whose name contains a raw space — the angle-wrapped
        // raw-space target needs NO decoding (spaces are legal path chars).
        fs::write(root.join("docs/guide with spaces.md"), "# Guide\n").unwrap();

        let from = root.to_path_buf();

        // Raw-space target resolves literally.
        let got = resolve_doc_target(root, &from, "./docs/guide with spaces.md").expect("literal");
        assert!(got.ends_with("docs/guide with spaces.md"));

        // Percent-encoded target resolves through the decoded fallback: only
        // the DECODED file exists here.
        let encoded_dir = tempfile::tempdir().unwrap();
        fs::write(encoded_dir.path().join("a b.md"), "decoded form\n").unwrap();
        let got = resolve_doc_target(encoded_dir.path(), encoded_dir.path(), "./a%20b.md")
            .expect("decoded fallback");
        assert!(
            got.ends_with("a b.md"),
            "decoded spelling must resolve: {got:?}"
        );

        // A file literally named `a%20b.md` wins over its decoded reading
        // (the literal spelling is tried first).
        let both_dir = tempfile::tempdir().unwrap();
        fs::write(both_dir.path().join("a%20b.md"), "literal-name wins\n").unwrap();
        fs::write(both_dir.path().join("a b.md"), "decoded form\n").unwrap();
        let got = resolve_doc_target(both_dir.path(), both_dir.path(), "./a%20b.md").unwrap();
        assert!(
            got.to_string_lossy().ends_with("a%20b.md"),
            "literal spelling must win over the decoded fallback: {got:?}"
        );
    }

    #[test]
    fn document_impact_transitive_closure() {
        let dir = build_doc_project();
        let root = dir.path();

        let report = document_impact(root, &root.join("b.md"), Language::Markdown, 5)
            .expect("document_impact");

        assert_eq!(report.total_targets, 1);
        let (key, tree) = report.targets.iter().next().expect("single target");
        assert!(key.ends_with("b.md:<doc>"), "key = {key}");
        assert_eq!(tree.function, "<doc>");
        assert_eq!(tree.note.as_deref(), Some("discovered via document link"));

        // depth-1 caller: a.md; depth-2: index.md.
        assert_eq!(tree.callers.len(), 1);
        let a_tree = &tree.callers[0];
        assert!(a_tree.file.ends_with("a.md"));
        assert_eq!(a_tree.callers.len(), 1);
        assert!(a_tree.callers[0].file.ends_with("index.md"));

        // The external URL is a real import but must never enter the graph.
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("example.com"), "external URL leaked: {json}");
    }

    #[test]
    fn document_impact_depth_limits_truncate() {
        let dir = build_doc_project();
        let root = dir.path();

        let report = document_impact(root, &root.join("b.md"), Language::Markdown, 1)
            .expect("document_impact");
        let tree = report.targets.values().next().unwrap();
        // Depth 1: direct caller (a.md) present, ITS callers truncated.
        assert_eq!(tree.callers.len(), 1);
        let a_tree = &tree.callers[0];
        assert!(a_tree.file.ends_with("a.md"));
        assert!(a_tree.truncated, "depth-1 must truncate a.md's subtree");
        assert!(a_tree.callers.is_empty());
    }

    #[test]
    fn document_impact_zero_linkers_is_entry_point() {
        let dir = build_doc_project();
        let root = dir.path();

        let report = document_impact(root, &root.join("index.md"), Language::Markdown, 5)
            .expect("document_impact");
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 0);
        assert!(tree.callers.is_empty());
        assert_eq!(tree.note.as_deref(), Some("discovered via document link"));
    }

    #[test]
    fn document_impact_resolves_fragments_and_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("docs")).unwrap();
        // root-relative link from a nested file
        fs::write(dir.path().join("docs/page.md"), "[t](target.md)\n").unwrap();
        fs::write(dir.path().join("target.md"), "target\n").unwrap();
        // file-relative link
        fs::write(dir.path().join("docs/other.md"), "[t](./target.md)\n").unwrap();

        let report = document_impact(
            dir.path(),
            &dir.path().join("target.md"),
            Language::Markdown,
            5,
        )
        .unwrap();
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 2, "both doc files link target.md");
        let mut linked_by: Vec<String> = tree
            .callers
            .iter()
            .map(|c| c.file.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        linked_by.sort();
        assert_eq!(linked_by, vec!["other.md", "page.md"]);
    }

    #[test]
    fn document_impact_duplicate_links_dedup() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.md"), "[1](b.md) [2](b.md)\n").unwrap();
        fs::write(dir.path().join("b.md"), "b\n").unwrap();

        let report =
            document_impact(dir.path(), &dir.path().join("b.md"), Language::Markdown, 5).unwrap();
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 1, "two links from one file = one caller");
    }

    #[test]
    fn document_impact_html_linkers_join_the_graph() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("page.html"), r#"<a href="doc.md">d</a>"#).unwrap();
        fs::write(dir.path().join("doc.md"), "doc\n").unwrap();

        let report = document_impact(
            dir.path(),
            &dir.path().join("doc.md"),
            Language::Markdown,
            5,
        )
        .unwrap();
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 1);
        assert!(tree.callers[0].file.ends_with("page.html"));
    }

    // extensionless-targets-v1: a sniffed extensionless shell script joins
    // the doc graph — a `.bashrc` (hidden file, shebang-sniffed to Bash)
    // sourcing an extensionless `env.sh` is the only way this closure can
    // have a caller, and before the probe BOTH files were invisible.
    #[test]
    fn document_impact_sniffed_extensionless_files_join_the_graph() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A project marker so the impact doc-root resolves to the tempdir
        // (the same pattern the doclinks config fixture uses).
        fs::write(root.join("package.json"), "{\"name\": \"probe\"}\n").unwrap();
        // Hidden extensionless file with a shebang → Bash.
        fs::write(root.join(".bashrc"), "#!/bin/bash\nsource ./lib/env.sh\n").unwrap();
        // Extensionless prose target (no shebang) → Text.
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("lib/env.sh"), "export TLDR_EDITOR=vim\n").unwrap();

        let report = document_impact(root, &root.join("lib/env.sh"), Language::Text, 5)
            .expect("document_impact");
        let tree = report.targets.values().next().unwrap();
        assert_eq!(tree.caller_count, 1, "the sniffed .bashrc must be a caller");
        assert!(
            tree.callers[0].file.ends_with(".bashrc"),
            "caller = {:?}",
            tree.callers[0].file
        );
    }

    #[test]
    fn document_impact_missing_target_errors() {
        let dir = build_doc_project();
        let err = document_impact(
            dir.path(),
            &dir.path().join("missing.md"),
            Language::Markdown,
            5,
        )
        .unwrap_err();
        assert!(matches!(err, TldrError::PathNotFound(_)));
    }
}
