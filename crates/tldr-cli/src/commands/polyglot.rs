//! cl15-polyglot-v1 (v0.5.0 CL-15): shared multi-language project scan.
//!
//! At a mixed-language corpus root, the dir-level commands (`structure`,
//! `calls`, `impact`, `hubs`, `deps`, …) historically auto-detected ONE
//! dominant language via [`Language::from_directory`] and SILENTLY dropped
//! every other language's files. On a corpus with comparable amounts of
//! Python, Go and TypeScript that meant two thirds of the source was never
//! analyzed, with no warning.
//!
//! This module centralizes the two pieces every dir-level command needs to
//! become polyglot-correct:
//!
//!  1. [`detect_languages`] — walk the project once, group files by
//!     [`Language::from_path`], and return every detected language with its
//!     file count, in a deterministic order. This is the building block for
//!     "analyze EACH detected language, merge results" — the generalization
//!     of the `structure.rs::run_all_langs` pattern from an earlier wave.
//!
//!  2. [`warn_if_languages_dropped`] — when a command DOES restrict to a
//!     single language (the user passed `--lang`, or a command cannot yet
//!     merge multi-language results), emit a CLEAR stderr WARNING naming the
//!     dropped languages and their file counts. Never silent.
//!
//! # Determinism
//!
//! [`detect_languages`] sorts its result by the `Debug`-rendered enum variant
//! name. `Language` does not derive `Ord`, but its `Debug` repr is stable
//! per-build, so the language order (and thus any merged output that echoes a
//! "first" language) is reproducible across runs.

use std::collections::HashMap;
use std::path::Path;

use tldr_core::Language;

/// One detected language plus how many files of it live under the scanned
/// root. `files` is always ≥ 1 (a language with zero files is never reported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedLanguage {
    /// The detected language.
    pub language: Language,
    /// Number of source files of this language found under the scan root.
    pub files: usize,
}

/// Walk `path` once and group files by [`Language::from_path`], returning every
/// detected language with its file count.
///
/// The walk goes through [`tldr_core::walker::walk_project`], which already
/// skips `node_modules`/`target`/`build`/`dist`/`.git` and other vendored
/// trees, hidden dirs, and `.gitignored` paths, without following symlinks —
/// the same walk [`Language::from_directory`] uses, so the file inventory is
/// consistent with the dominant-language autodetector.
///
/// The result is sorted deterministically (by the `Debug`-rendered variant
/// name). An empty / source-free tree yields an empty `Vec`.
pub fn detect_languages(path: &Path) -> Vec<DetectedLanguage> {
    let mut counts: HashMap<Language, usize> = HashMap::new();
    for entry in tldr_core::walker::walk_project(path) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(lang) = Language::from_path(p) {
            *counts.entry(lang).or_insert(0) += 1;
        }
    }

    let mut detected: Vec<DetectedLanguage> = counts
        .into_iter()
        .map(|(language, files)| DetectedLanguage { language, files })
        .collect();
    // Stable order across runs: sort by the Debug-rendered enum variant name.
    detected.sort_by_key(|d| format!("{:?}", d.language));
    detected
}

/// Just the [`Language`] values detected under `path`, in the same
/// deterministic order as [`detect_languages`]. Convenience for callers that
/// want to iterate per-language scans without the counts.
pub fn detected_language_list(path: &Path) -> Vec<Language> {
    detect_languages(path)
        .into_iter()
        .map(|d| d.language)
        .collect()
}

/// cl15-polyglot-v1: emit a CLEAR stderr WARNING when a command restricts its
/// analysis to `kept` and thereby drops the other languages present under
/// `path`.
///
/// `path` is re-walked via [`detect_languages`] so the warning reports
/// accurate per-language file counts. When `kept` is the only language present
/// (or the tree has no other source), nothing is emitted.
///
/// The warning is intentionally written with a bare `eprintln!` rather than the
/// `OutputWriter` progress channel: this is a correctness alert about dropped
/// source, NOT a cosmetic progress banner, so it must survive `--quiet` and
/// machine-readable formats. Tools that merge stderr+stdout still get clean
/// JSON on stdout; the warning lands on stderr where alerts belong.
pub fn warn_if_languages_dropped(path: &Path, kept: Language) {
    let detected = detect_languages(path);
    warn_if_languages_dropped_from(&detected, kept);
}

/// Variant of [`warn_if_languages_dropped`] that takes a pre-computed
/// detection list, so callers that already walked the tree don't pay for a
/// second walk.
pub fn warn_if_languages_dropped_from(detected: &[DetectedLanguage], kept: Language) {
    let dropped: Vec<&DetectedLanguage> = detected
        .iter()
        .filter(|d| d.language != kept)
        .collect();
    if dropped.is_empty() {
        return;
    }

    let dropped_total: usize = dropped.iter().map(|d| d.files).sum();
    let detail = dropped
        .iter()
        .map(|d| {
            format!(
                "{} ({} file{})",
                d.language.as_str(),
                d.files,
                if d.files == 1 { "" } else { "s" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    eprintln!(
        "Warning: analyzing only {} — dropped {} file{} from {} other language{}: {}. \
         Pass a different --lang to analyze them, or omit --lang for full polyglot analysis.",
        kept.as_str(),
        dropped_total,
        if dropped_total == 1 { "" } else { "s" },
        dropped.len(),
        if dropped.len() == 1 { "" } else { "s" },
        detail,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn polyglot_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::write(root.join("a.py"), "def f():\n    return 1\n").unwrap();
        fs::write(root.join("b.go"), "package main\nfunc g() int { return 2 }\n").unwrap();
        fs::write(root.join("c.ts"), "function h(): number { return 3; }\n").unwrap();
        fs::write(root.join("d.ts"), "function i(): number { return 4; }\n").unwrap();
        temp
    }

    #[test]
    fn detect_languages_groups_and_counts_all() {
        let temp = polyglot_dir();
        let detected = detect_languages(temp.path());

        // Three distinct languages.
        assert_eq!(detected.len(), 3, "got: {:?}", detected);

        let by_lang: HashMap<Language, usize> = detected
            .iter()
            .map(|d| (d.language, d.files))
            .collect();
        assert_eq!(by_lang.get(&Language::Python), Some(&1));
        assert_eq!(by_lang.get(&Language::Go), Some(&1));
        assert_eq!(by_lang.get(&Language::TypeScript), Some(&2));
    }

    #[test]
    fn detect_languages_is_deterministic() {
        let temp = polyglot_dir();
        let a = detect_languages(temp.path());
        let b = detect_languages(temp.path());
        assert_eq!(a, b, "detection order must be reproducible");
    }

    #[test]
    fn detect_languages_empty_dir_is_empty() {
        let temp = TempDir::new().unwrap();
        assert!(detect_languages(temp.path()).is_empty());
    }
}
