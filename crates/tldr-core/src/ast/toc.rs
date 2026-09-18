//! Heuristic table-of-contents scanning for plain text (plain-text batch —
//! `Language::Text`).
//!
//! Plain text has no syntax: no maintained (or even unmaintained) tree-sitter
//! grammar can parse "arbitrary prose", so `.txt`/`.text` files NEVER go
//! through tree-sitter — the same no-grammar precedent as `Language::Log`
//! (commit d1992302). This module is the only consumer of text content on the
//! structure path: a deterministic, single-pass **TOC scanner** that walks the
//! source line-by-line and classifies heading-shaped lines into
//! [`DefinitionInfo`] entries (`kind: "heading"`), which is what `tldr
//! structure <file>.txt` reports.
//!
//! Reference EXTRACTION (URLs / paths) for plain text lives in
//! `ast::doclinks::scan_paths_and_urls` — the two scanners share the same
//! "no grammar, heuristics only" philosophy but serve different pipelines
//! (structure vs. the document link graph).
//!
//! # The heuristic table (the format contract, documented because it IS the
//! spec)
//!
//! A line becomes a heading when the FIRST matching rule fires (rules are
//! tried in this order; one line yields at most one heading):
//!
//! | # | Rule | Shape | Region | Notes |
//! |---|------|-------|--------|-------|
//! | 1 | **Setext underline** | a non-blank line whose NEXT line is `===…` (level 1) or `---…` (level 2) | both lines | underline (trimmed) must be ≥ 2 chars AND ≥ the text line's trimmed length; the text line may not itself be underline-shaped (`===…`/`---…` runs are horizontal rules, not heading text) |
//! | 2 | **ATX heading** | line starts with a run of 1..=6 `#` followed by whitespace | the heading line | rare in `.txt` but free to support (CommonMark-shaped); the `#` markers never enter the name; a bare `#` run without trailing whitespace (`#!/usr/bin/env`, `#hashtag`) is NOT a heading |
//! | 3 | **ALL-CAPS line** | trimmed length 3..=80, ≥ 2 alphabetic chars, EVERY alphabetic char uppercase, and the line does not end with `.`/`,`/`;`/`:` | the heading line | the classic plain-text title convention (`CHAPTER ONE`, `OVERVIEW`); digits and punctuation inside are fine (`2. OVERVIEW`) |
//! | 4 | **Numbered outline** | trimmed starts `\d+(\.\d+)*` then optional `.`/`)` then whitespace then a non-space char (`1. Setup`, `2) Limits`, `3.2.1 Details`, `12 Top`) | the heading line | the name KEEPS the numbering prefix (it is the outline identity); leading whitespace allowed so indented sub-outlines (`  1.1.1`) surface too |
//! | 5 | **Section word** | trimmed starts `Chapter`/`Part`/`Section`/`Appendix` (case-insensitive) followed by whitespace and a run of 1+ roman-numeral/digit chars (`[IVXLCivxlc0-9]`) | the heading line | `Chapter 1`, `PART IV`, `Appendix 2`, `Section 3: Method` match; `Appendix B` does NOT (`B` is not a numeral/digit — documented limitation) |
//!
//! # False-positive classes (accepted — Text is heuristic BY DESIGN)
//!
//! Plain text has no markup to disambiguate, so every rule has a known
//! false-positive class. They are accepted because `.txt` heading detection
//! is best-effort by definition (unresolved/mis-detected lines are inert
//! downstream — a wrong heading is a cosmetic miss, not a wrong analysis):
//!
//! - **Rule 1 (setext):** a text line followed by a full-width `---`/`===`
//!   run that was meant as a rule or table divider becomes a heading. The
//!   underline length bound (≥ the text length) keeps most ASCII-art rules
//!   out but not all of them.
//! - **Rule 3 (ALL-CAPS):** SHOUTED PROSE and shouted log lines
//!   (`ERROR: DATABASE EXPLODED`, `FATAL` / `PANIC` banners) become
//!   headings. The trailing-punctuation exclusion (`.`/`,`/`;`/`:`) removes
//!   the `ERROR:` / `WARNING:` label lines that END with their colon; a
//!   shouty line that only STARTS with the label and continues with words
//!   still matches — acceptable, Text is heuristic.
//! - **Rule 4 (numbered outline):** decimal numbers read like outline items
//!   (`3.14 is a constant` matches as `3.14` + ` is a constant`), and
//!   ordered-list items (`1. do this`) are indistinguishable from outline
//!   headings in plain text. Both stay false positives.
//! - **Rule 5 (section word):** a sentence that happens to open with the
//!   word (`Part of the problem is…`) does NOT match (the word must be
//!   followed by whitespace + a numeral/roman run), but a line like
//!   `Section 5 covers deployment` does.
//!
//! # Region / span semantics
//!
//! `line_start`/`line_end` are 1-indexed and inclusive (both lines for a
//! setext heading, the single line otherwise). `byte_start` is the offset of
//! the heading's FIRST physical line start (0-indexed, leading indentation
//! included — the same convention the `ast::logs` scanner uses);
//! `byte_end` is one past the heading's LAST content byte, exclusive of the
//! trailing `\n`/`\r\n` terminator (CRLF handled: the `\r` never enters the
//! span). `source[byte_start..byte_end]` is therefore the exact byte region
//! of the heading. `signature` is always empty (prose has no signatures) and
//! `definition_line` is the heading's first line — the declaration-line
//! analogue.

use std::path::Path;

use crate::types::DefinitionInfo;
use crate::TldrResult;

/// Check whether `path` looks like a plain-text file (`.txt`/`.text`
/// extension, case-insensitive).
#[must_use]
pub fn is_text_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("text"))
        .unwrap_or(false)
}

/// Read a plain-text file into a `String` for the two Text scanners.
///
/// Wide encodings (BOM'd or BOM-less UTF-16/UTF-32) are REJECTED with the
/// shared `TldrError::EncodingError` — the same policy every tree-sitter
/// file read applies (see `fs::wide_encoding_marker`): lossy-decoding
/// UTF-16 prose yields `h\0e\0a\0d\0…` garbage that would scan to zero
/// headings, so a loud structured error beats a silently empty result.
/// Everything else (valid UTF-8, latin-1/cp1252 leftovers, mixed-encoding
/// output) lossy-decodes, mirroring the `ast::logs` streaming scanner —
/// plain-text files routinely carry bytes from mixed-encoding writers and
/// the heuristics only need the ASCII shapes.
pub fn parse_text_file(path: &Path) -> TldrResult<String> {
    let bytes = std::fs::read(path).map_err(crate::error::TldrError::IoError)?;
    if let Some(detail) = crate::fs::wide_encoding_marker(&bytes) {
        return Err(crate::error::TldrError::EncodingError {
            path: path.to_path_buf(),
            detail: detail.to_string(),
        });
    }
    Ok(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

/// One physical line: 1-indexed number, byte offset of the line's first
/// byte, and the content span (physical line minus the trailing `\n` and a
/// CRLF `\r`) as `(start, end)`.
#[derive(Debug, Clone, Copy)]
struct Line {
    no: u32,
    byte_start: usize,
    content: (usize, usize),
}

/// Scan plain-text `source` for heading-shaped lines (heuristic TOC) and
/// return them as [`DefinitionInfo`] entries (`kind: "heading"`) in source
/// order. See the module docs for the rule table and its false-positive
/// classes — the rules ARE the spec.
#[must_use]
pub fn scan_toc(source: &str) -> Vec<DefinitionInfo> {
    // Precompute the line table once: split_inclusive keeps every physical
    // line WITH its terminator so byte offsets stay exact under CRLF (the
    // `\r` is dropped from the content span but the cursor still covered it).
    let mut lines: Vec<Line> = Vec::new();
    let mut offset = 0usize;
    for (idx, physical) in source.split_inclusive('\n').enumerate() {
        let mut content_len = physical.len();
        if physical.ends_with('\n') {
            content_len -= 1;
        }
        if content_len > 0 && physical.as_bytes()[content_len - 1] == b'\r' {
            content_len -= 1;
        }
        lines.push(Line {
            no: (idx + 1) as u32,
            byte_start: offset,
            content: (offset, offset + content_len),
        });
        offset += physical.len();
    }

    let mut defs = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let text = &source[line.content.0..line.content.1];
        let trimmed = text.trim();
        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Rule 1 — setext underline (consumes the underline line too).
        if i + 1 < lines.len() {
            if let Some((name, byte_end)) = setext_heading(source, &lines[i], &lines[i + 1]) {
                defs.push(heading(
                    name,
                    line.no,
                    lines[i + 1].no,
                    line.byte_start,
                    byte_end,
                ));
                i += 2;
                continue;
            }
        }

        // Rule 2 — ATX heading (`#`…`######` + whitespace).
        if let Some(name) = atx_heading(trimmed) {
            defs.push(heading(
                name,
                line.no,
                line.no,
                line.byte_start,
                line.content.1,
            ));
            i += 1;
            continue;
        }

        // Rule 3 — ALL-CAPS line.
        if let Some(name) = all_caps_heading(trimmed) {
            defs.push(heading(
                name,
                line.no,
                line.no,
                line.byte_start,
                line.content.1,
            ));
            i += 1;
            continue;
        }

        // Rule 4 — numbered outline.
        if numbered_outline(trimmed) || word_outline(trimmed) {
            defs.push(heading(
                collapse(trimmed),
                line.no,
                line.no,
                line.byte_start,
                line.content.1,
            ));
        }
        i += 1;
    }
    defs
}

/// Build one `heading` definition. `signature` is always empty (prose has no
/// signatures) and `definition_line` is the heading's first line.
fn heading(
    name: String,
    line_start: u32,
    line_end: u32,
    byte_start: usize,
    byte_end: usize,
) -> DefinitionInfo {
    DefinitionInfo {
        name,
        kind: "heading".to_string(),
        line_start,
        line_end,
        definition_line: Some(line_start),
        byte_start: Some(byte_start as u64),
        byte_end: Some(byte_end as u64),
        signature: String::new(),
        container: None,
    }
}

/// Collapse internal whitespace runs and trim (every heading's name goes
/// through this, so indented or double-spaced headings keep a clean name).
fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Rule 1 — is `next` a setext underline for `cur`? Returns the collapsed
/// heading name (from the text line) and the region end (one past the
/// underline line's last content byte) when it is.
///
/// Level 1 = `===…`, level 2 = `---…` (the level itself is not reported —
/// `DefinitionInfo` has no level field — but the two shapes are kept
/// distinct for documentation parity with markdown setext headings).
/// Constraints: the underline (trimmed) must be ≥ 2 chars AND at least as
/// long as the text line's trimmed length (an underline shorter than its
/// text is almost certainly a divider under an unrelated paragraph), and the
/// text line must not itself be underline-shaped (a run of `=`/`-` is a
/// horizontal rule, never heading text — this also stops two adjacent
/// `-----` lines from pairing up).
fn setext_heading(source: &str, cur: &Line, next: &Line) -> Option<(String, usize)> {
    let underline = source[next.content.0..next.content.1].trim();
    if !setext_underline(underline) {
        return None;
    }
    let text = source[cur.content.0..cur.content.1].trim();
    // The text line must not itself be an underline run (see doc comment).
    if setext_underline(text) {
        return None;
    }
    if underline.len() < 2 || underline.len() < text.len() {
        return None;
    }
    Some((collapse(text), next.content.1))
}

/// Is this trimmed line a setext underline: a run of ≥ 2 IDENTICAL `=` or
/// `-` characters and nothing else?
fn setext_underline(line: &str) -> bool {
    let b = line.as_bytes();
    if b.len() < 2 || (b[0] != b'=' && b[0] != b'-') {
        return false;
    }
    b.iter().all(|&c| c == b[0])
}

/// Rule 2 — ATX heading: a trimmed line starting with a run of 1..=6 `#`
/// characters followed by whitespace. Returns the collapsed heading text
/// (markers stripped). A bare `#` run without trailing whitespace
/// (`#!/usr/bin/env`, `#hashtag`) is not a heading; a `#######` (7+) run is
/// not either (CommonMark caps ATX at 6).
fn atx_heading(trimmed: &str) -> Option<String> {
    let b = trimmed.as_bytes();
    let mut i = 0usize;
    while i < b.len() && b[i] == b'#' {
        i += 1;
    }
    if i == 0 || i > 6 {
        return None;
    }
    // Whitespace (or nothing at all — a bare `#` run) must follow the run;
    // require whitespace AND content after it, otherwise the heading has no
    // name and would emit an empty definition.
    if i >= b.len() || !(b[i] == b' ' || b[i] == b'\t') {
        return None;
    }
    let name = collapse(&trimmed[i + 1..]);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Rule 3 — ALL-CAPS line: trimmed length 3..=80, ≥ 2 alphabetic chars,
/// every alphabetic char uppercase, and the line does not end with
/// `.`/`,`/`;`/`:` (the colon rule removes the `ERROR:`/`WARNING:` label
/// lines; the other punctuation removes trailing-sentence shout lines).
/// Returns the collapsed text.
fn all_caps_heading(trimmed: &str) -> Option<String> {
    let len = trimmed.chars().count();
    if !(3..=80).contains(&len) {
        return None;
    }
    if trimmed.ends_with(['.', ',', ';', ':']) {
        return None;
    }
    let mut alpha = 0usize;
    for c in trimmed.chars() {
        if c.is_alphabetic() {
            alpha += 1;
            if !c.is_uppercase() {
                return None;
            }
        }
    }
    if alpha < 2 {
        return None;
    }
    Some(collapse(trimmed))
}

/// Rule 4 — numbered outline: trimmed starts with `\d+(\.\d+)*`, an
/// optional `.`/`)`, then whitespace and a non-space character. The numbering
/// prefix stays part of the name (it IS the outline identity). Documented
/// false positives: decimal numbers in prose (`3.14 is a constant`) and
/// ordered-list items (`1. do this`).
fn numbered_outline(trimmed: &str) -> bool {
    let b = trimmed.as_bytes();
    let mut i = 0usize;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return false;
    }
    // Dotted sub-levels: (`.` + digits)*  — `1.1`, `3.2.1`, …
    while i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    // Optional `.` / `)` delimiter.
    if i < b.len() && (b[i] == b'.' || b[i] == b')') {
        i += 1;
    }
    // Whitespace, then at least one non-space character of heading text.
    if i >= b.len() || !b[i].is_ascii_whitespace() {
        return false;
    }
    let rest = trimmed[i..].trim_start();
    !rest.is_empty()
}

/// Rule 5 — section word: trimmed starts (case-insensitively) with
/// `Chapter`/`Part`/`Section`/`Appendix`, followed by whitespace and a run
/// of 1+ roman-numeral/digit characters (`[IVXLCivxlc0-9]`). `Appendix B`
/// deliberately does not match (`B` is not a numeral — documented
/// limitation).
fn word_outline(trimmed: &str) -> bool {
    const WORDS: [&str; 4] = ["chapter", "part", "section", "appendix"];
    let lower = trimmed.to_ascii_lowercase();
    let Some(word) = WORDS.iter().find(|w| {
        lower.len() > w.len()
            && lower.starts_with(*w)
            && lower.as_bytes()[w.len()].is_ascii_whitespace()
    }) else {
        return false;
    };
    let rest = trimmed[word.len()..].trim_start();
    let b = rest.as_bytes();
    // `[IVXLCivxlc0-9]+` — at least one numeral/digit char leading the token
    // (the rest of the line may continue: `Section 3: Method`).
    !b.is_empty() && (b[0].is_ascii_digit() || matches!(b[0], b'I' | b'V' | b'X' | b'L' | b'C'))
}

// =============================================================================
// Tests — each rule's positives and its documented negatives
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.kind.clone()).collect()
    }

    fn names(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.name.clone()).collect()
    }

    // -------------------------------------------------------------------------
    // Rule 1 — setext
    // -------------------------------------------------------------------------

    #[test]
    fn setext_underline_equal_and_dash() {
        let src = "Introduction\n============\n\nBody\n\nDetails\n--------\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["Introduction", "Details"],
            "setext = and - underlines are both headings"
        );
        // The region covers BOTH lines; the level difference is documented
        // but not reported (DefinitionInfo has no level field).
        assert_eq!(defs[0].line_start, 1);
        assert_eq!(defs[0].line_end, 2);
        assert_eq!(defs[1].line_start, 6);
        assert_eq!(defs[1].line_end, 7);
        assert_eq!(defs[1].definition_line, Some(6));
    }

    #[test]
    fn setext_underline_shorter_than_text_is_not_a_heading() {
        // 8-char text under a 4-char underline → the underline reads as a
        // divider under an unrelated paragraph, not a heading.
        let src = "A Long Heading\n----\n\nbody\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "underline shorter than the text must not emit: {defs:?}"
        );
    }

    #[test]
    fn setext_underline_needs_two_chars() {
        let src = "Title\n=\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "a single-char underline is not setext: {defs:?}"
        );
    }

    #[test]
    fn setext_text_line_that_is_an_underline_does_not_pair() {
        // Two adjacent `-----` runs are horizontal rules, not a heading.
        let src = "-----\n-----\nbody\n";
        let defs = scan_toc(src);
        assert!(defs.is_empty(), "adjacent rules must not pair up: {defs:?}");
    }

    // -------------------------------------------------------------------------
    // Rule 2 — ATX
    // -------------------------------------------------------------------------

    #[test]
    fn atx_heading_markers_stripped_from_name() {
        let src = "# Top\n\n## Sub heading\nbody\n";
        let defs = scan_toc(src);
        assert_eq!(names(&defs), vec!["Top", "Sub heading"]);
        // Region = the full heading line (markers included in the bytes,
        // excluded from the name).
        let start = src.find("## Sub heading").unwrap();
        let def = &defs[1];
        assert_eq!(def.byte_start, Some(start as u64));
        let slice = &src[def.byte_start.unwrap() as usize..def.byte_end.unwrap() as usize];
        assert_eq!(slice, "## Sub heading");
    }

    #[test]
    fn atx_hash_without_space_is_not_a_heading() {
        let src = "#!/usr/bin/env bash\n#hashtag\n####### seven\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "shebang / hashtag / 7-run stay inert: {defs:?}"
        );
    }

    #[test]
    fn atx_bare_hash_run_with_no_text_is_inert() {
        let src = "# \n##\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "a `#` run with no text has no name: {defs:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Rule 3 — ALL-CAPS
    // -------------------------------------------------------------------------

    #[test]
    fn all_caps_line_is_a_heading_and_collapses_whitespace() {
        let src = "  USER    GUIDE  \nprose follows\n";
        let defs = scan_toc(src);
        assert_eq!(names(&defs), vec!["USER GUIDE"], "name collapsed");
        // byte region = the physical line, leading indentation included.
        let def = &defs[0];
        assert_eq!(def.byte_start, Some(0));
        let slice = &src[def.byte_start.unwrap() as usize..def.byte_end.unwrap() as usize];
        assert_eq!(slice, "  USER    GUIDE  ");
    }

    #[test]
    fn all_caps_lowercase_line_is_not_a_heading() {
        let src = "this is just prose\nanother line\n";
        let defs = scan_toc(src);
        assert!(defs.is_empty(), "lowercase prose is inert: {defs:?}");
    }

    #[test]
    fn all_caps_colon_ending_line_is_not_a_heading() {
        // `ERROR:`-style label lines end with the colon and never emit.
        let src = "SEE ALSO:\nERROR:\nbody\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "colon-terminated caps lines stay inert: {defs:?}"
        );
    }

    #[test]
    fn all_caps_shouty_log_line_is_a_documented_false_positive() {
        // The accepted FP class: a shouty line that does not END with the
        // colon still matches. Text is heuristic; this pin documents it.
        let src = "ERROR: DATABASE EXPLODED\n";
        let defs = scan_toc(src);
        assert_eq!(names(&defs), vec!["ERROR: DATABASE EXPLODED"]);
    }

    #[test]
    fn all_caps_needs_two_alphabetic_chars() {
        // "A 1" — 3 chars but a single alphabetic char → inert.
        let src = "A 1\nbody\n";
        let defs = scan_toc(src);
        assert!(defs.is_empty(), "one alpha char is not enough: {defs:?}");
        // "USA" — 3 chars, 3 alphabetic (≥ 2) → heading.
        let src = "USA\nbody\n";
        let defs = scan_toc(src);
        assert_eq!(names(&defs), vec!["USA"], "3 alpha chars ≥ 2 → heading");
        // "IT" — 2 chars is below the 3-char length floor → inert.
        let src = "IT\nbody\n";
        let defs = scan_toc(src);
        assert!(defs.is_empty(), "below the 3-char floor: {defs:?}");
    }

    #[test]
    fn all_caps_trailing_sentence_punctuation_is_not_a_heading() {
        let src = "THE END.\nNEXT, THIS;\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "sentence-punctuated caps stay inert: {defs:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Rule 4 — numbered outline (incl. indented sub-outline depth)
    // -------------------------------------------------------------------------

    #[test]
    fn numbered_outline_forms_and_prefix_kept() {
        let src = "1. Setup\n2) Limits\n3.2.1 Details\n12 Top\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["1. Setup", "2) Limits", "3.2.1 Details", "12 Top"],
            "numbering prefixes stay in the name"
        );
        assert_eq!(kinds(&defs), vec!["heading"; 4]);
    }

    #[test]
    fn numbered_outline_indented_sub_levels_emit() {
        let src = "1. Setup\n  1.1. Requirements\n    1.1.1 Compilers\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["1. Setup", "1.1. Requirements", "1.1.1 Compilers"],
            "indented sub-outlines surface with their depth"
        );
        // Deeper indentation stays inside the byte region.
        let deep = &defs[2];
        let slice = &src[deep.byte_start.unwrap() as usize..deep.byte_end.unwrap() as usize];
        assert_eq!(slice, "    1.1.1 Compilers");
    }

    #[test]
    fn numbered_outline_needs_trailing_text() {
        let src = "1.\n2)\n3\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "bare numbers are not outline items: {defs:?}"
        );
    }

    #[test]
    fn numbered_outline_decimal_prose_is_a_documented_false_positive() {
        let src = "3.14 is a constant\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["3.14 is a constant"],
            "accepted FP: decimal numbers read like outlines"
        );
    }

    // -------------------------------------------------------------------------
    // Rule 5 — section words
    // -------------------------------------------------------------------------

    #[test]
    fn section_words_match_case_insensitively() {
        let src = "Chapter 1\nPART IV\nSection 3: Method\nappendix 2\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["Chapter 1", "PART IV", "Section 3: Method", "appendix 2"]
        );
    }

    #[test]
    fn section_word_without_numeral_stays_inert() {
        // `Appendix B` — B is not a roman numeral/digit (documented
        // limitation); `Chapterish 5` fails the whitespace-after-word rule;
        // `Part of the problem` has no numeral after the word.
        let src = "Appendix B\nChapterish 5\nPart of the problem\n";
        let defs = scan_toc(src);
        assert!(
            defs.is_empty(),
            "non-numeral section words stay inert: {defs:?}"
        );
    }

    // -------------------------------------------------------------------------
    // General invariants
    // -------------------------------------------------------------------------

    #[test]
    fn blank_lines_and_prose_emit_nothing() {
        let src = "\n\nplain prose line\n   \nanother prose line\n\n";
        assert!(scan_toc(src).is_empty());
    }

    #[test]
    fn headings_carry_exact_spans_and_slice_back() {
        let src = "OVERVIEW\n\nIntroduction\n============\n\nprose\n";
        let defs = scan_toc(src);
        assert_eq!(defs.len(), 2);
        for d in &defs {
            assert_eq!(d.kind, "heading");
            assert!(d.signature.is_empty(), "prose has no signatures");
            assert_eq!(d.definition_line, Some(d.line_start));
            assert!(d.byte_start.is_some() && d.byte_end.is_some());
            let (s, e) = (d.byte_start.unwrap() as usize, d.byte_end.unwrap() as usize);
            assert!(e > s);
            // Every byte span is an exact slice of the source.
            let _ = &src[s..e];
        }
        // The setext heading's region covers text + underline exactly.
        let setext = &defs[1];
        let slice = &src[setext.byte_start.unwrap() as usize..setext.byte_end.unwrap() as usize];
        assert_eq!(slice, "Introduction\n============");
        // byte_end excludes the trailing newline.
        assert_eq!(
            setext.byte_end,
            Some((src.find("============").unwrap() + "============".len()) as u64)
        );
    }

    #[test]
    fn source_order_is_deterministic() {
        let src = "ZULU TITLE\n\n# alpha\n\n2. beta\n\nChapter 9\n";
        let defs = scan_toc(src);
        assert_eq!(
            names(&defs),
            vec!["ZULU TITLE", "alpha", "2. beta", "Chapter 9"]
        );
    }

    #[test]
    fn is_text_path_covers_both_extensions_case_insensitively() {
        assert!(is_text_path(std::path::Path::new("notes.txt")));
        assert!(is_text_path(std::path::Path::new("notes.text")));
        assert!(is_text_path(std::path::Path::new("NOTES.TXT")));
        assert!(is_text_path(std::path::Path::new("a/b/readme.Text")));
        assert!(!is_text_path(std::path::Path::new("notes.md")));
        assert!(!is_text_path(std::path::Path::new("notes")));
        assert!(!is_text_path(std::path::Path::new("notes.txt.bak")));
    }

    #[test]
    fn crlf_byte_spans_exclude_the_carriage_return() {
        let src = "OVERVIEW\r\n\r\nIntroduction\r\n============\r\n";
        let defs = scan_toc(src);
        assert_eq!(defs.len(), 2);
        let setext = &defs[1];
        let slice = &src[setext.byte_start.unwrap() as usize..setext.byte_end.unwrap() as usize];
        // The `\r` never enters the region (the newline separator between
        // the two lines is part of the file bytes and stays).
        assert_eq!(slice, "Introduction\r\n============");
    }
}
