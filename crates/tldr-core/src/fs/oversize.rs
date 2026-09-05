//! File-size policy for skipping oversize and auto-generated files.
//!
//! `tldr` analyses scale roughly with file size, but some downstream
//! passes (per-line scanners, per-symbol cross products, dead-code
//! reachability) are super-linear and time out on a few-MB single
//! file. The 2.3 MB `dom.generated.d.ts` from the TypeScript DOM-gen
//! repo is the canonical example: under the previous (per-command,
//! inconsistent) cap policy `tldr structure / smells / dead / secure`
//! all timed out at 30 s on that single file, even though the rest of
//! the repo finished in ~20 ms.
//!
//! This module centralises the size policy:
//!
//! - **Normal source files**: 10 MB cap (matches the historical
//!   per-command cap in `patterns/contracts/vuln`).
//! - **Auto-generated / minified files** (`.d.ts`, `.min.js`,
//!   `.min.css`, `.bundle.js`, `.bundle.css`): 512 KB cap. These are
//!   rarely valuable to analyse deeply (tens of thousands of
//!   generated declarations or minified IIFEs) and are the most
//!   common cause of pathological slowdowns. The 512 KB cap is
//!   empirically chosen against the `ts-dom-gen` baselines tree
//!   (60+ `*.generated.d.ts` artefacts in the 100 KB – 2.3 MB
//!   range): a 1 MB cap left ~12 baselines admitted and the
//!   whole-repo run took 58 s; 512 KB drops the run under 30 s
//!   while admitting every hand-authored `.d.ts` shim observed in
//!   `tldr-rs-canonical` (the largest is 75 KB).
//!
//! The cap is enforced at file-read time (in
//! `ast::parser::parse_file_with_lang`) so every command that goes
//! through the central parser inherits the policy uniformly. Callers
//! receive a recoverable [`TldrError::FileTooLarge`] which they convert
//! into a structured warning (`Skipped <path>: <size>MB exceeds <cap>MB
//! cap for <category>`) and a `files_skipped` counter on the result.
//!
//! [`TldrError::FileTooLarge`]: crate::error::TldrError::FileTooLarge

use std::path::Path;

/// Maximum file size for normal source files, in bytes (10 MB).
///
/// Files at or below this size are read and analysed normally.
pub const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum file size for auto-generated or minified files, in bytes
/// (512 KB).
///
/// Applies to extensions reported as auto-gen by [`is_autogen_file`].
/// Empirically chosen: the `ts-dom-gen` baselines directory holds
/// dozens of `*.generated.d.ts` files in the 100 KB – 2.3 MB range;
/// `tldr structure /tmp/repos/ts-dom-gen` took 58 s with a 1 MB cap
/// because all of the 600 KB – 950 KB baselines were still admitted
/// and each ran ~1 s of per-method-info AST work. Dropping the cap
/// to 512 KB keeps the whole-repo run under 30 s while admitting
/// every hand-authored `.d.ts` shim observed in `tldr-rs-canonical`
/// (the largest is 75 KB).
pub const MAX_AUTOGEN_FILE_SIZE_BYTES: u64 = 512 * 1024;

/// Suffixes that mark a file as auto-generated or minified.
///
/// We match on the **full path string** suffix (lowercased) rather
/// than just the final extension so that multi-dot suffixes like
/// `.d.ts` and `.min.js` are recognised correctly. (`Path::extension`
/// would return only `ts` / `js` and miss the `d.` / `min.` prefix
/// signal.)
const AUTOGEN_SUFFIXES: &[&str] = &[
    ".d.ts",
    ".d.mts",
    ".d.cts",
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".min.css",
    ".bundle.js",
    ".bundle.mjs",
    ".bundle.css",
];

/// Returns `true` when `path` looks like an auto-generated or
/// minified source artefact (`.d.ts`, `.min.js`, `.bundle.css`, …).
///
/// Comparison is case-insensitive on the path's UTF-8-lossy
/// representation so paths with non-UTF-8 bytes (rare on disk but
/// possible) still match.
pub fn is_autogen_file(path: &Path) -> bool {
    let lossy = path.to_string_lossy().to_lowercase();
    AUTOGEN_SUFFIXES.iter().any(|s| lossy.ends_with(s))
}

/// Maximum allowed size in bytes for `path` under the current
/// policy.
///
/// - [`MAX_AUTOGEN_FILE_SIZE_BYTES`] when [`is_autogen_file`] is true.
/// - [`MAX_FILE_SIZE_BYTES`] otherwise.
pub fn max_size_for(path: &Path) -> u64 {
    if is_autogen_file(path) {
        MAX_AUTOGEN_FILE_SIZE_BYTES
    } else {
        MAX_FILE_SIZE_BYTES
    }
}

/// Outcome of an oversize check on a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeCheck {
    /// The file is within policy and can be processed.
    WithinLimit {
        /// Observed file size in bytes.
        size_bytes: u64,
    },
    /// The file exceeds the policy and should be skipped.
    Oversize {
        /// Observed file size in bytes.
        size_bytes: u64,
        /// Configured maximum for this file (in bytes).
        max_bytes: u64,
        /// `true` when the cap that applied is the auto-gen cap
        /// (caller can use this to format the warning).
        is_autogen: bool,
    },
    /// Could not stat the file (caller should fall back to its
    /// existing I/O error handling).
    Unknown,
}

/// Stat `path` and classify it under the current size policy.
///
/// Returns [`SizeCheck::Unknown`] if the path cannot be stat-ed (for
/// example, `path` does not exist yet) — callers should fall back to
/// their existing read-error path in that case rather than treat
/// "unknown size" as oversize.
pub fn check_size(path: &Path) -> SizeCheck {
    match std::fs::metadata(path) {
        Ok(md) => {
            let size_bytes = md.len();
            let max_bytes = max_size_for(path);
            if size_bytes > max_bytes {
                SizeCheck::Oversize {
                    size_bytes,
                    max_bytes,
                    is_autogen: is_autogen_file(path),
                }
            } else {
                SizeCheck::WithinLimit { size_bytes }
            }
        }
        Err(_) => SizeCheck::Unknown,
    }
}

/// Format a human-readable warning for an oversize-skipped file.
///
/// The format is stable and is asserted by integration tests:
///
/// ```text
/// Skipped <path>: 3MB exceeds 512KB cap for auto-generated/minified files
/// Skipped <path>: 12MB exceeds 10MB cap for source files
/// ```
///
/// Sizes use KB when the value is below 1 MiB and MB otherwise, so
/// the auto-gen 512 KB cap displays as "512KB" rather than the
/// confusing "1MB". Both size and cap use the same unit per
/// formatted line for direct comparison.
pub fn format_oversize_warning(
    path: &Path,
    size_bytes: u64,
    max_bytes: u64,
    is_autogen: bool,
) -> String {
    let category = if is_autogen {
        "auto-generated/minified files"
    } else {
        "source files"
    };
    format!(
        "Skipped {}: {} exceeds {} cap for {}",
        path.display(),
        format_size(size_bytes),
        format_size(max_bytes),
        category
    )
}

/// Render `bytes` as a short human-readable size string.
///
/// Below 1 MiB: rounded up to the nearest KB (e.g. `512KB`,
/// `768KB`). At or above 1 MiB: rounded up to the nearest MB
/// (e.g. `3MB`, `10MB`). The choice of "ceil" preserves the
/// "exceeds X cap" semantics — a file just one byte over the cap
/// renders as "MB exceeds MB" with the exceedance being the +1
/// rather than rounding artefacts.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        let kb = bytes.div_ceil(1024);
        format!("{}KB", kb)
    } else {
        let mb = bytes.div_ceil(1024 * 1024);
        format!("{}MB", mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn is_autogen_file_recognises_dts_min_bundle() {
        assert!(is_autogen_file(&PathBuf::from("dom.generated.d.ts")));
        assert!(is_autogen_file(&PathBuf::from("/abs/path/lib.d.ts")));
        assert!(is_autogen_file(&PathBuf::from("foo.min.js")));
        assert!(is_autogen_file(&PathBuf::from("vendor.bundle.js")));
        assert!(is_autogen_file(&PathBuf::from("style.min.css")));
        // Case-insensitive
        assert!(is_autogen_file(&PathBuf::from("Foo.D.TS")));
    }

    #[test]
    fn is_autogen_file_rejects_normal_source() {
        assert!(!is_autogen_file(&PathBuf::from("foo.ts")));
        assert!(!is_autogen_file(&PathBuf::from("bar.js")));
        assert!(!is_autogen_file(&PathBuf::from("lib.rs")));
        assert!(!is_autogen_file(&PathBuf::from("index.tsx")));
    }

    #[test]
    fn max_size_picks_5mb_for_autogen_10mb_for_source() {
        assert_eq!(
            max_size_for(&PathBuf::from("dom.d.ts")),
            MAX_AUTOGEN_FILE_SIZE_BYTES
        );
        assert_eq!(
            max_size_for(&PathBuf::from("dom.ts")),
            MAX_FILE_SIZE_BYTES
        );
    }

    #[test]
    fn check_size_within_limit_for_small_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("small.ts");
        std::fs::write(&path, b"hello").unwrap();
        match check_size(&path) {
            SizeCheck::WithinLimit { size_bytes } => assert_eq!(size_bytes, 5),
            other => panic!("expected WithinLimit, got {:?}", other),
        }
    }

    #[test]
    fn check_size_oversize_for_dts_above_autogen_cap() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("huge.d.ts");
        // autogen cap + 1 byte: just over the auto-gen cap.
        let bytes = vec![b'a'; (MAX_AUTOGEN_FILE_SIZE_BYTES as usize) + 1];
        std::fs::write(&path, &bytes).unwrap();
        match check_size(&path) {
            SizeCheck::Oversize {
                size_bytes,
                max_bytes,
                is_autogen,
            } => {
                assert_eq!(size_bytes, MAX_AUTOGEN_FILE_SIZE_BYTES + 1);
                assert_eq!(max_bytes, MAX_AUTOGEN_FILE_SIZE_BYTES);
                assert!(is_autogen);
            }
            other => panic!("expected Oversize, got {:?}", other),
        }
    }

    #[test]
    fn check_size_within_limit_for_dts_just_under_cap() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("borderline.d.ts");
        // Exactly the cap is allowed (the policy is "exceeds", not
        // ">=").
        let bytes = vec![b'a'; MAX_AUTOGEN_FILE_SIZE_BYTES as usize];
        std::fs::write(&path, &bytes).unwrap();
        match check_size(&path) {
            SizeCheck::WithinLimit { size_bytes } => {
                assert_eq!(size_bytes, MAX_AUTOGEN_FILE_SIZE_BYTES)
            }
            other => panic!("expected WithinLimit, got {:?}", other),
        }
    }

    #[test]
    fn check_size_within_limit_for_source_between_caps() {
        // A non-autogen file between the auto-gen cap (512 KB) and
        // the source cap (10 MB) must NOT be flagged as oversize:
        // the auto-gen cap doesn't apply to it.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("medium.ts");
        let bytes = vec![b'a'; (MAX_AUTOGEN_FILE_SIZE_BYTES as usize) + 1024];
        std::fs::write(&path, &bytes).unwrap();
        match check_size(&path) {
            SizeCheck::WithinLimit { .. } => {}
            other => panic!("expected WithinLimit, got {:?}", other),
        }
    }

    #[test]
    fn check_size_unknown_for_missing_file() {
        let outcome = check_size(Path::new("/nonexistent/path/abc.ts"));
        assert_eq!(outcome, SizeCheck::Unknown);
    }

    #[test]
    fn format_oversize_warning_matches_documented_shape() {
        // Sub-MB cap: rendered as "KB".
        let msg = format_oversize_warning(
            Path::new("/tmp/dom.d.ts"),
            3 * 1024 * 1024,
            512 * 1024,
            true,
        );
        assert!(msg.contains("/tmp/dom.d.ts"));
        assert!(msg.contains("3MB"));
        assert!(msg.contains("512KB"));
        assert!(msg.contains("auto-generated/minified files"));

        // Multi-MB cap: rendered as "MB" on both sides.
        let msg2 = format_oversize_warning(
            Path::new("/tmp/big.ts"),
            12 * 1024 * 1024,
            10 * 1024 * 1024,
            false,
        );
        assert!(msg2.contains("12MB"));
        assert!(msg2.contains("10MB"));
        assert!(msg2.contains("source files"));
    }

    #[test]
    fn format_size_uses_kb_below_one_mib() {
        assert_eq!(format_size(0), "0KB");
        assert_eq!(format_size(1), "1KB"); // div_ceil
        assert_eq!(format_size(512 * 1024), "512KB");
        assert_eq!(format_size(1023 * 1024), "1023KB");
    }

    #[test]
    fn format_size_uses_mb_at_or_above_one_mib() {
        assert_eq!(format_size(1024 * 1024), "1MB");
        assert_eq!(format_size(2 * 1024 * 1024 + 1), "3MB");
        assert_eq!(format_size(10 * 1024 * 1024), "10MB");
    }
}
