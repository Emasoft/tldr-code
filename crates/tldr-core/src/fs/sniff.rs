//! Content sniffing for extensionless files (extensionless-targets-v1)
//!
//! Before this module, a file without a recognized extension was invisible to
//! tldr: [`crate::types::Language::from_path`] returned `None` (there is no
//! arm for "no extension at all"), single-file target resolution fell through
//! to a parent-directory/Python guess (`tldr structure Makefile` reported
//! Python), `detect_or_parse_language` errored, and every directory walk
//! filtered by extension lists — so `LICENSE`, `Makefile`, `.bashrc` never
//! joined structure, imports, importers or the document link graph.
//!
//! This module adds the missing input: **what does the content say?** Two
//! layers, both deterministic and both bounded:
//!
//! 1. [`is_probably_binary`] — a content-sniff over a bounded sample that
//!    decides binary vs text. There was NO content sniffing anywhere in the
//!    codebase before this (only `metrics/file_utils.rs`' extension-based
//!    heuristic); this is the single home for it.
//! 2. [`sniff_language`] — a language ladder for extensionless files only:
//!    shebang → `<?xml` → Text. Callers must check the extension FIRST (see
//!    [`crate::validation::resolve_target_language`] for the canonical
//!    resolution order); a file with an extension keeps its extension
//!    semantics, sniffed or not.
//!
//! # Binary rule table (`is_probably_binary`, sample = first min(64 KiB, len) bytes)
//!
//! | # | Rule | Rationale |
//! |---|------|-----------|
//! | B0 | UTF-16/UTF-32 BOM prefix (`FF FE`, `FE FF`) | **NOT binary** — the parser pool's wide-encoding path (`fs::wide_encoding_marker` → `ReadOutcome::WideEncoded`) owns these; a BOM'd UTF-16 file is text in a wide encoding, and calling it binary would misreport a decodable document. BOM-LESS UTF-16 (every ASCII byte interleaved with NUL) falls through to B1 and IS binary — it is undecodable without a hint. |
//! | B1 | any NUL byte in the first 8 KiB of the sample | A NUL is a byte no text format carries (the same signal `wide_encoding_marker` uses for BOM-less wide encodings, bounded the same way: 8 KiB, not the whole file). |
//! | B2 | >10% non-text control bytes (all bytes `0x01..=0x1F` except `\t` `\n` `\v` `\f` `\r` `\b` `\033`, plus `0x7F`) in the sample | Executables, images and compressed blobs are dominated by control bytes; text (even ANSI-colored logs, which carry `\033` escapes, and tab-formatted configs) stays far below 10%. |
//! | B3 | the sample is not valid UTF-8 (`std::str::from_utf8` on the sample, byte-wise) | Latin-1 fixtures, image headers and random bytes fail UTF-8 validation; every supported text format is UTF-8 (wide encodings were excluded by B0). |
//!
//! The sample bound is what makes the sniff safe on huge inputs: at most 64
//! KiB is inspected regardless of file size, and each rule short-circuits.
//!
//! # Language ladder (`sniff_language`, extensionless files ONLY)
//!
//! Reads at most the first 4 KiB, applies the binary rules, then tries:
//!
//! | # | Rule | Result |
//! |---|------|--------|
//! | L0 | read error / binary content | `None` — the caller decides rejection (`resolve_target_language` maps this to a structured "binary file" error; a missing file must be handled by the caller BEFORE calling). |
//! | L1 | content starts `#!` (first line) | map the interpreter token: `bash`/`sh`/`zsh`/`ash`/`dash` → [`Language::Bash`]; `python`/`pythonN`/`pypy` → [`Language::Python`]; `node`/`deno` → [`Language::JavaScript`]; `ruby` → [`Language::Ruby`]; anything else → `None` (a file that declares itself as an interpreter we do not support is NOT prose — do not guess Text). NOTE: the design brief listed `perl → Perl`, but the 29-variant `Language` enum has no Perl variant; `perl` therefore lands in the unsupported bucket (`None`) until a variant exists. |
//! | L2 | content starts `<?xml` after BOM/whitespace | [`Language::Xml`] (case-sensitive — the XML declaration is lowercase by spec). |
//! | L3 | anything else, including the EMPTY file | [`Language::Text`] — prose with no declared syntax. An empty file is deliberately Text: a zero-byte LICENSE/placeholder is a text target whose TOC scan and reference scan legitimately yield nothing. |
//!
//! # Doc-graph walks
//!
//! [`sniff_extensionless_files`] is the walk-side helper: it collects the
//! extensionless files under a root (hidden files INCLUDED — dotfiles like
//! `.bashrc`/`.npmrc` are the flagship extensionless population, and the
//! directory walks that run before it already exclude hidden files, so the
//! probe is the only way a `.bashrc` can ever join a graph) and sniffs each
//! one. The cost bound is explicit: the walk reads directory entries only,
//! and each file contributes at most one ≤4 KiB read; binary files drop out
//! at B2/B3/B4 without ever being parsed.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::fs::tree::collect_extensionless_files;
use crate::types::{IgnoreSpec, Language};

/// How far into a file [`is_probably_binary`] looks. Bounded on purpose —
/// see the module-level rule table.
pub const BINARY_SAMPLE_MAX: usize = 64 * 1024;

/// The NUL scan (rule B2) is bounded tighter than the general sample: a wide
/// or binary format shows its first NUL immediately, while a legitimate
/// source file that embeds a NUL later (generated C tables, protobuf output)
/// must not be misflagged. Mirrors `fs::wide_encoding_marker`'s reasoning.
pub const NUL_SCAN_PREFIX: usize = 8 * 1024;

/// How far into a file [`sniff_language`] reads. The language ladder only
/// needs the shebang line or the first bytes of an XML declaration — 4 KiB is
/// generous for both and bounds the per-file cost of the doc-graph probe.
pub const LANGUAGE_SAMPLE_MAX: usize = 4 * 1024;

/// Non-text control bytes for rule B3, as the complement of the text-legal
/// set: TAB LF VT FF CR BS ESC are all carried by real text files (Makefiles
/// are tab-indented; ANSI-colored logs carry ESC sequences), everything else
/// below 0x20 plus DEL is binary noise.
fn is_non_text_control(b: u8) -> bool {
    const TEXT_LEGAL: [u8; 7] = [0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B];
    (b < 0x20 && !TEXT_LEGAL.contains(&b)) || b == 0x7F
}

/// Content-sniff `bytes` for binary vs text. See the module-level rule table
/// (B0–B4) — the rules ARE the spec. The sample is the first
/// [`BINARY_SAMPLE_MAX`] bytes; callers pass a whole-file read or a bounded
/// prefix, whichever they already hold.
#[must_use]
pub fn is_probably_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(BINARY_SAMPLE_MAX)];

    // B0: UTF-16/UTF-32 BOM — NOT binary. Both UTF-16 BOMs (FF FE / FE FF)
    // subsume the UTF-32 ones (FF FE 00 00 / 00 00 FE FF), so the 2-byte
    // prefixes suffice. The parser's wide-encoding path handles these.
    if sample.starts_with(&[0xFF, 0xFE]) || sample.starts_with(&[0xFE, 0xFF]) {
        return false;
    }

    // B1: any NUL in the bounded prefix.
    let nul_prefix = &sample[..sample.len().min(NUL_SCAN_PREFIX)];
    if nul_prefix.contains(&0x00) {
        return true;
    }

    // B2: >10% non-text control bytes in the sample.
    let controls = sample.iter().filter(|b| is_non_text_control(**b)).count();
    if !sample.is_empty() && controls * 10 > sample.len() {
        return true;
    }

    // B3: invalid UTF-8 in the sample.
    std::str::from_utf8(sample).is_err()
}

/// The language ladder over an already-read sample (rule table L1–L3).
/// `None` means "no confident language": binary content (L0) or a shebang
/// naming an unsupported interpreter. Extensionless files ONLY — callers
/// must resolve extensions first. Public so `resolve_target_language` can
/// run the ladder over the one 64 KiB sample it already read (no second
/// file read), and for in-memory callers.
#[must_use]
pub fn sniff_language_from_sample(sample: &[u8]) -> Option<Language> {
    if is_probably_binary(sample) {
        return None; // L0
    }

    // Skip a UTF-8 BOM and ASCII whitespace before matching L1/L2 — the
    // design pins both: a BOM'd document and a leading blank line must not
    // hide the shebang / XML declaration.
    let body = sample
        .strip_prefix(&[0xEF, 0xBB, 0xBF][..])
        .unwrap_or(sample);
    let body = {
        let mut i = 0usize;
        while i < body.len()
            && (body[i] == b' ' || body[i] == b'\t' || body[i] == b'\n' || body[i] == b'\r')
        {
            i += 1;
        }
        &body[i..]
    };

    // L2 (checked before L1's line-splitting only for clarity; the two
    // prefixes are disjoint so order is unobservable): XML declaration.
    if body.starts_with(b"<?xml") {
        return Some(Language::Xml);
    }

    // L1: shebang. Map the interpreter token from the first line.
    if body.starts_with(b"#!") {
        return sniff_shebang(body);
    }

    // L3: everything else — including the empty sample — is prose.
    Some(Language::Text)
}

/// L1 helper: map a `#!` line to a language. Tokenization handles the three
/// real-world spellings: direct (`/bin/bash`), env-forwarded
/// (`/usr/bin/env python3`) and env-with-flags (`/usr/bin/env -S bash -e`).
/// The FIRST token that maps wins; an unrecognized interpreter returns `None`
/// (a `#!/usr/bin/make` file must not be mislabeled as prose).
fn sniff_shebang(body: &[u8]) -> Option<Language> {
    let line_end = body.iter().position(|b| *b == b'\n').unwrap_or(body.len());
    let line = &body[2..line_end]; // skip "#!"
    let line = std::str::from_utf8(line).ok()?;

    line.split_whitespace()
        // strip path components: "/usr/bin/env" → "env"
        .map(|tok| tok.rsplit('/').next().unwrap_or(tok))
        .find_map(|tok| match tok {
            "bash" | "sh" | "zsh" | "ash" | "dash" => Some(Language::Bash),
            "node" | "deno" => Some(Language::JavaScript),
            "ruby" => Some(Language::Ruby),
            // NOTE: `perl` intentionally lands in the unsupported bucket —
            // the `Language` enum has no Perl variant (see module docs L1).
            t => {
                // python / python3 / python3.12 / pypy3
                let stem = t.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
                if stem == "python" || stem == "pypy" {
                    Some(Language::Python)
                } else {
                    None
                }
            }
        })
}

/// Sniff an extensionless file's language (rule table L0–L3). Returns `None`
/// for: unreadable files, binary content, and shebangs naming an unsupported
/// interpreter. Callers must check the extension FIRST — this function never
/// consults the path.
#[must_use]
pub fn sniff_language(path: &Path) -> Option<Language> {
    let sample = read_prefix(path, LANGUAGE_SAMPLE_MAX)?;
    sniff_language_from_sample(&sample)
}

/// Read up to `max` bytes from `path`. `None` on any read failure — the
/// caller (which has usually already established the file exists) decides
/// how to surface it.
fn read_prefix(path: &Path, max: usize) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(max.min(4096));
    let mut chunk = [0u8; 4096];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 || buf.len() >= max {
            break;
        }
        let take = n.min(max - buf.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < n {
            break;
        }
    }
    Some(buf)
}

/// Probe a directory tree for extensionless files that sniff to a language.
///
/// This is the doc-graph walk helper (used by `analysis::doc_impact` and
/// `analysis::importers`): the extension walks those callers run first cannot
/// see extensionless files at all (the walker's extension filter drops them),
/// so this probe re-walks for exactly that population and sniffs each file
/// (≤[`LANGUAGE_SAMPLE_MAX`] per file). Walk parity with `get_file_tree`
/// except for one deliberate widening, both documented at
/// [`collect_extensionless_files`]: hidden files are INCLUDED (dotfiles are
/// the flagship extensionless population and are otherwise unreachable),
/// while generated/vendor directories, doxygen-output sentinels and
/// gitignore patterns are skipped exactly like the extension walk. Files that
/// sniff binary or to an unsupported shebang are dropped — they contribute no
/// node.
#[must_use]
pub fn sniff_extensionless_files(
    root: &Path,
    ignore_spec: Option<&IgnoreSpec>,
) -> Vec<(PathBuf, Language)> {
    let Ok(files) = collect_extensionless_files(root, ignore_spec) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, Language)> = files
        .into_iter()
        .filter_map(|p| sniff_language(&p).map(|l| (p, l)))
        .collect();
    // The walk sorts paths; a re-sort keyed on the path keeps the
    // (path, language) pairs deterministic even if the collector's ordering
    // contract changes. (Path key only — `Language` derives no Ord.)
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ---------------------------------------------------------------------
    // is_probably_binary — rule table B0–B3
    // ---------------------------------------------------------------------

    #[test]
    fn nul_byte_means_binary() {
        assert!(is_probably_binary(b"hello\x00world"));
        // NUL far into the sample, still inside the 8 KiB scan window.
        let mut bytes = vec![b'a'; 5000];
        bytes[4000] = 0;
        assert!(is_probably_binary(&bytes));
    }

    #[test]
    fn utf8_text_is_not_binary() {
        assert!(!is_probably_binary(
            b"# Title\n\nsome prose, a URL https://x.y/z\n"
        ));
        // Tab-indented Makefile content: TAB is text-legal.
        assert!(!is_probably_binary(b"build:\n\tgcc -o app main.o\n"));
        // ANSI escape (0x1B) is text-legal (colored logs).
        assert!(!is_probably_binary(b"\x1b[31mERROR\x1b[0m boom\n"));
    }

    #[test]
    fn utf16_bom_is_not_binary_but_bomless_utf16_is() {
        // UTF-16 LE BOM: FF FE — rule B0 says NOT binary (wide-encoding path).
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend_from_slice(b"h\x00i\x00\n\x00");
        assert!(
            !is_probably_binary(&utf16),
            "BOM'd UTF-16 must not be binary"
        );
        // UTF-16 BE BOM.
        assert!(!is_probably_binary(&[0xFE, 0xFF, b'h', 0x00]));
        // UTF-32 BOMs share the leading bytes and are covered.
        assert!(!is_probably_binary(&[0xFF, 0xFE, 0x00, 0x00, 0x41, 0x00]));
        // BOM-LESS UTF-16: interleaved NULs → rule B1 fires.
        assert!(is_probably_binary(b"h\x00i\x00\n\x00"));
    }

    #[test]
    fn control_byte_ratio_rule() {
        // 12% non-text control bytes → binary (just over the 10% line).
        let mut bytes = vec![b'a'; 100];
        for b in bytes.iter_mut().take(12) {
            *b = 0x01;
        }
        assert!(is_probably_binary(&bytes));
        // 8% → text.
        let mut bytes = vec![b'a'; 100];
        for b in bytes.iter_mut().take(8) {
            *b = 0x01;
        }
        assert!(!is_probably_binary(&bytes));
    }

    #[test]
    fn invalid_utf8_means_binary() {
        // 0xFF is never valid as a leading UTF-8 byte.
        assert!(is_probably_binary(b"valid prefix \xFF\xFE invalid"));
    }

    #[test]
    fn empty_and_small_samples() {
        // Empty content: no NUL, 0% controls, valid UTF-8 → NOT binary (the
        // language ladder then falls through to Text — see L3).
        assert!(!is_probably_binary(b""));
    }

    // ---------------------------------------------------------------------
    // sniff_language — rule table L0–L3
    // ---------------------------------------------------------------------

    fn sniff_bytes(bytes: &[u8]) -> Option<Language> {
        sniff_language_from_sample(bytes)
    }

    #[test]
    fn shebang_maps_known_interpreters() {
        assert_eq!(sniff_bytes(b"#!/bin/bash\nset -e\n"), Some(Language::Bash));
        assert_eq!(sniff_bytes(b"#!/bin/sh\n"), Some(Language::Bash));
        assert_eq!(sniff_bytes(b"#!/usr/bin/zsh\n"), Some(Language::Bash));
        assert_eq!(sniff_bytes(b"#!/bin/ash\n"), Some(Language::Bash));
        assert_eq!(sniff_bytes(b"#!/bin/dash\n"), Some(Language::Bash));
        assert_eq!(
            sniff_bytes(b"#!/usr/bin/env python3\nimport os\n"),
            Some(Language::Python)
        );
        assert_eq!(
            sniff_bytes(b"#!/usr/bin/python3.12\n"),
            Some(Language::Python)
        );
        assert_eq!(
            sniff_bytes(b"#!/usr/bin/env node\n"),
            Some(Language::JavaScript)
        );
        assert_eq!(
            sniff_bytes(b"#!/usr/bin/env deno run\n"),
            Some(Language::JavaScript)
        );
        assert_eq!(sniff_bytes(b"#!/usr/bin/ruby\n"), Some(Language::Ruby));
        // perl: no Language variant exists → unsupported bucket (None).
        assert_eq!(sniff_bytes(b"#!/usr/bin/perl -w\n"), None);
        // env with flags: the interpreter is not the first token.
        assert_eq!(
            sniff_bytes(b"#!/usr/bin/env -S bash -e\n"),
            Some(Language::Bash)
        );
    }

    #[test]
    fn shebang_unknown_interpreter_is_none() {
        // A file that declares itself as something unsupported is NOT prose.
        assert_eq!(sniff_bytes(b"#!/usr/bin/make -f\n"), None);
        assert_eq!(sniff_bytes(b"#!/usr/bin/awk -f\n"), None);
    }

    #[test]
    fn xml_declaration_maps_to_xml() {
        assert_eq!(
            sniff_bytes(b"<?xml version=\"1.0\"?>\n<a/>\n"),
            Some(Language::Xml)
        );
        // After a BOM...
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"<?xml version=\"1.0\"?>\n");
        assert_eq!(sniff_bytes(&bom), Some(Language::Xml));
        // ...and after leading whitespace.
        assert_eq!(
            sniff_bytes(b"\n\n  <?xml version=\"1.0\"?>\n"),
            Some(Language::Xml)
        );
        // Case-sensitive: the XML declaration is lowercase by spec.
        assert_eq!(
            sniff_bytes(b"<?XML version=\"1.0\"?>\n"),
            Some(Language::Text)
        );
    }

    #[test]
    fn plain_prose_and_empty_files_are_text() {
        assert_eq!(
            sniff_bytes(b"# Title\n\nsee ./docs/x.md\n"),
            Some(Language::Text)
        );
        // Decided: an EMPTY file is Text (documented L3).
        assert_eq!(sniff_bytes(b""), Some(Language::Text));
        // Makefile-ish content: no shebang, no XML declaration.
        assert_eq!(
            sniff_bytes(b"build: main.o\n\tgcc -o app main.o\n"),
            Some(Language::Text)
        );
    }

    #[test]
    fn binary_content_is_none() {
        assert_eq!(sniff_bytes(b"PK\x03\x04\x00\x00\x00"), None);
        assert_eq!(sniff_bytes(&[0x00, 0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn sniff_language_reads_real_files() {
        // Extensionless on-disk checks through the public entry point.
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"#!/bin/bash\nsource ./lib/env.sh\n").unwrap();
        assert_eq!(sniff_language(f.path()), Some(Language::Bash));

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"PROJECT LICENSE\n\nsee https://x.y/z\n")
            .unwrap();
        assert_eq!(sniff_language(f.path()), Some(Language::Text));

        // Missing file → None.
        assert_eq!(
            sniff_language(Path::new("/nonexistent/extless-target")),
            None
        );
    }

    #[test]
    fn sniff_language_bounded_to_4kib_sample() {
        // A shebang beyond the 4 KiB window is NOT seen — the ladder only
        // reads the head of the file (documented cost bound).
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[b'a'; LANGUAGE_SAMPLE_MAX + 16]).unwrap();
        f.write_all(b"#!/bin/bash\n").unwrap();
        assert_eq!(sniff_language(f.path()), Some(Language::Text));
    }
}
