//! Dot-file semantics for `.env` and ignore files (dotfiles-v1).
//!
//! `.env`-family files (`KEY=value` assignments) and ignore files
//! (`.gitignore`-family glob patterns) are plain text with NO tree-sitter
//! grammar worth running — their structure IS the line, not a parse tree — so
//! they join the Log/Text no-grammar precedent: the extractor's
//! `Language::Text` early-return routes them to the line scanners in this
//! module (see `ast::extractor`, the Text branch) instead of the TOC
//! heuristic, whose heading rules are meaningless for `KEY=value` and
//! `*.log` lines.
//!
//! # The env grammar (the decision, documented because it IS the spec)
//!
//! `is_env_path` accepts (by FILE NAME, not extension):
//!
//! - `.env` exactly;
//! - the `.env.` PREFIX family (`.env.local`, `.env.production`, …);
//! - the `*.env` SUFFIX family (`dev.env`, `test.env`, …) — the common
//!   per-environment spelling that keeps the extension visible to `ls`.
//!
//! `parse_env_file` emits one `DefinitionInfo` (`kind: "env"`) per
//! non-empty, non-comment line with a `KEY=` shape:
//!
//! - comment = a line whose trimmed text starts with `#`;
//! - an optional `export ` prefix is accepted (shell-export style) and
//!   stripped — the name is the KEY either way;
//! - the KEY is everything before the FIRST `=`; it must be non-empty and
//!   contain no whitespace (a prose line with an `=` in it is not an
//!   assignment);
//! - the value (everything after the first `=`) is NOT stored as data —
//!   `DefinitionInfo` has no value field — it surfaces as the SIGNATURE,
//!   truncated to 80 chars (a secret is equally secret at 80 chars, and the
//!   signature's job is one-line orientation, not transport).
//!
//! # The ignore grammar
//!
//! `is_ignore_path` accepts exactly (by FILE NAME): `.gitignore`,
//! `.dockerignore`, `.npmignore`, `.eslintignore`, `.prettierignore`,
//! `.ignore`. The set is deliberately closed — every member is a
//! tool-consumed ignore list; arbitrary `.something-ignore` files are not.
//!
//! `parse_ignore_file` emits one `DefinitionInfo` (`kind: "pattern"`) per
//! non-empty, non-comment line (comment = trimmed text starts with `#`); the
//! name IS the pattern text (trimmed, truncated to 80 chars — glob patterns
//! are identities, not prose) and the signature is empty (a pattern has no
//! one-line summary beyond itself).
//!
//! # Region / span semantics (identical to the `ast::toc` convention)
//!
//! `line_start`/`line_end` are 1-indexed and inclusive (the single line).
//! `byte_start` is the offset of the line's first byte (leading indentation
//! included), `byte_end` is one past the line's last content byte — the
//! trailing `\n`/`\r\n` terminator never enters the span, so
//! `source[byte_start..byte_end]` is the exact line text. `definition_line`
//! is the line itself (the declaration-line analogue).
//!
//! # Imports / references (left as-is, documented)
//!
//! The Text-path reference scanner (`ast::doclinks::scan_paths_and_urls`)
//! already catches path-shaped VALUES in env files and path-shaped PATTERNS
//! in ignore files — this module owns STRUCTURE only and deliberately does
//! not duplicate it.

use crate::types::DefinitionInfo;

/// Files whose name marks them as env-assignment files (dotfiles-v1):
/// `.env`, the `.env.` prefix family, and the `*.env` suffix family —
/// matched on the FILE NAME (case-sensitively: `.ENV` is a different file
/// convention and not part of the accepted set).
#[must_use]
pub fn is_env_path(file_name: &str) -> bool {
    file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env")
}

/// Files whose name marks them as ignore-pattern files (dotfiles-v1): the
/// closed set `.gitignore`, `.dockerignore`, `.npmignore`, `.eslintignore`,
/// `.prettierignore`, `.ignore` — matched on the FILE NAME exactly.
#[must_use]
pub fn is_ignore_path(file_name: &str) -> bool {
    matches!(
        file_name,
        ".gitignore"
            | ".dockerignore"
            | ".npmignore"
            | ".eslintignore"
            | ".prettierignore"
            | ".ignore"
    )
}

/// One physical line: 1-indexed number, byte offsets of the content span
/// (the physical line minus the trailing `\n` and a CRLF `\r`).
#[derive(Debug, Clone, Copy)]
struct Line {
    no: u32,
    content: (usize, usize),
}

/// Walk `source` into a line table (the `ast::toc` convention:
/// `split_inclusive('\n')` keeps byte offsets exact under CRLF — the `\r`
/// is dropped from the content span).
fn line_table(source: &str) -> Vec<Line> {
    let mut lines = Vec::new();
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
            content: (offset, offset + content_len),
        });
        offset += physical.len();
    }
    lines
}

/// Scan env-file `source` into `kind: "env"` definitions — one per
/// non-empty, non-comment `KEY=` line (see the module docs for the full
/// grammar).
#[must_use]
pub fn parse_env_file(source: &str) -> Vec<DefinitionInfo> {
    let mut defs = Vec::new();
    for line in line_table(source) {
        let text = &source[line.content.0..line.content.1];
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Optional shell-export prefix: `export KEY=value` names KEY.
        let assignment = trimmed
            .strip_prefix("export ")
            .map(|rest| rest.trim_start())
            .unwrap_or(trimmed);
        let Some(eq) = assignment.find('=') else {
            continue;
        };
        let key = assignment[..eq].trim();
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            continue;
        }
        let value = assignment[eq + 1..].trim();
        defs.push(DefinitionInfo {
            name: key.to_string(),
            kind: "env".to_string(),
            line_start: line.no,
            line_end: line.no,
            definition_line: Some(line.no),
            byte_start: Some(line.content.0 as u64),
            byte_end: Some(line.content.1 as u64),
            signature: truncate(value),
        });
    }
    defs
}

/// Scan ignore-file `source` into `kind: "pattern"` definitions — one per
/// non-empty, non-comment line; the name is the pattern text (see the module
/// docs).
#[must_use]
pub fn parse_ignore_file(source: &str) -> Vec<DefinitionInfo> {
    let mut defs = Vec::new();
    for line in line_table(source) {
        let text = &source[line.content.0..line.content.1];
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        defs.push(DefinitionInfo {
            name: truncate(trimmed),
            kind: "pattern".to_string(),
            line_start: line.no,
            line_end: line.no,
            definition_line: Some(line.no),
            byte_start: Some(line.content.0 as u64),
            byte_end: Some(line.content.1 as u64),
            signature: String::new(),
        });
    }
    defs
}

/// One-line signature bound: values/patterns longer than 80 chars are cut —
/// the signature orients, it does not transport.
fn truncate(text: &str) -> String {
    if text.chars().count() <= 80 {
        text.to_string()
    } else {
        let cut: String = text.chars().take(80).collect();
        cut + "…"
    }
}

// =============================================================================
// Tests — the grammar decisions pinned
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn names(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.name.clone()).collect()
    }

    fn kinds(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.kind.clone()).collect()
    }

    // -------------------------------------------------------------------------
    // is_env_path / is_ignore_path predicates
    // -------------------------------------------------------------------------

    #[test]
    fn env_predicate_covers_the_three_families() {
        assert!(is_env_path(".env"));
        assert!(is_env_path(".env.local"));
        assert!(is_env_path(".env.production"));
        assert!(is_env_path("dev.env"));
        assert!(is_env_path("test.env"));
        assert!(!is_env_path("env"));
        assert!(!is_env_path(".environment"));
        assert!(!is_env_path("config.env.bak"));
        assert!(!is_env_path("notes.txt"));
        assert!(!is_env_path(".gitignore"));
    }

    #[test]
    fn ignore_predicate_is_the_closed_set() {
        assert!(is_ignore_path(".gitignore"));
        assert!(is_ignore_path(".dockerignore"));
        assert!(is_ignore_path(".npmignore"));
        assert!(is_ignore_path(".eslintignore"));
        assert!(is_ignore_path(".prettierignore"));
        assert!(is_ignore_path(".ignore"));
        assert!(!is_ignore_path(".gitignore.bak"));
        assert!(!is_ignore_path("gitignore"));
        assert!(!is_ignore_path(".env"));
        // A plausible-looking but non-member file stays out (closed set).
        assert!(!is_ignore_path(".cargoignore"));
    }

    // -------------------------------------------------------------------------
    // parse_env_file
    // -------------------------------------------------------------------------

    #[test]
    fn env_lines_emit_kind_env_with_key_names() {
        let src = "DATABASE_URL=postgres://localhost/app\nPORT=8080\n";
        let defs = parse_env_file(src);
        assert_eq!(kinds(&defs), vec!["env", "env"]);
        assert_eq!(names(&defs), vec!["DATABASE_URL", "PORT"]);
    }

    #[test]
    fn env_export_prefix_is_stripped() {
        let src = "export EDITOR=vim\nEDITOR=nano\n";
        let defs = parse_env_file(src);
        assert_eq!(names(&defs), vec!["EDITOR", "EDITOR"]);
        // The export line's signature holds its own value only.
        assert_eq!(defs[0].signature, "vim");
        assert_eq!(defs[1].signature, "nano");
    }

    #[test]
    fn env_comments_blank_and_non_assignment_lines_stay_inert() {
        let src = "# a comment\n\n   \nNO_EQUALS_HERE\nanother plain line\n";
        assert!(parse_env_file(src).is_empty());
    }

    #[test]
    fn env_prose_with_equals_is_not_an_assignment() {
        // Whitespace inside the KEY disqualifies the line (prose, not env).
        let src = "SOME TEXT=value\nGOOD_KEY=1\n";
        let defs = parse_env_file(src);
        assert_eq!(names(&defs), vec!["GOOD_KEY"]);
    }

    #[test]
    fn env_key_must_be_non_empty() {
        let src = "=value\nKEY=1\n";
        let defs = parse_env_file(src);
        assert_eq!(names(&defs), vec!["KEY"]);
    }

    #[test]
    fn env_regions_are_the_lines_and_values_live_in_signatures() {
        let src = "A=1\nB=two words\n";
        let defs = parse_env_file(src);
        for d in &defs {
            assert_eq!(d.line_start, d.line_end);
            assert_eq!(d.definition_line, Some(d.line_start));
        }
        // Byte slice-back: each region is the exact line text (no newline).
        let a = &src[defs[0].byte_start.unwrap() as usize..defs[0].byte_end.unwrap() as usize];
        assert_eq!(a, "A=1");
        let b = &src[defs[1].byte_start.unwrap() as usize..defs[1].byte_end.unwrap() as usize];
        assert_eq!(b, "B=two words");
        assert_eq!(defs[1].signature, "two words");
    }

    #[test]
    fn env_crlf_terminators_never_enter_the_region() {
        let src = "A=1\r\nB=2\r\n";
        let defs = parse_env_file(src);
        assert_eq!(defs.len(), 2);
        let a = &src[defs[0].byte_start.unwrap() as usize..defs[0].byte_end.unwrap() as usize];
        assert_eq!(a, "A=1");
    }

    #[test]
    fn env_long_values_truncate_at_80_chars() {
        let long = "x".repeat(200);
        let src = format!("KEY={long}\n");
        let defs = parse_env_file(&src);
        assert_eq!(defs[0].signature.chars().count(), 81); // 80 + the ellipsis
        assert!(defs[0].signature.ends_with('…'));
    }

    #[test]
    fn env_leading_whitespace_is_tolerated() {
        let src = "  INDENTED=1\n";
        let defs = parse_env_file(src);
        assert_eq!(names(&defs), vec!["INDENTED"]);
    }

    // -------------------------------------------------------------------------
    // parse_ignore_file
    // -------------------------------------------------------------------------

    #[test]
    fn ignore_lines_emit_kind_pattern_with_pattern_names() {
        let src = "target/\n*.log\nnode_modules/\n";
        let defs = parse_ignore_file(src);
        assert_eq!(kinds(&defs), vec!["pattern"; 3]);
        assert_eq!(names(&defs), vec!["target/", "*.log", "node_modules/"]);
        assert!(defs.iter().all(|d| d.signature.is_empty()));
    }

    #[test]
    fn ignore_comments_and_blanks_stay_inert() {
        let src = "# build output\n\ntarget/\n  \n";
        let defs = parse_ignore_file(src);
        assert_eq!(names(&defs), vec!["target/"]);
    }

    #[test]
    fn ignore_regions_are_the_lines() {
        let src = "target/\n!keep/\n";
        let defs = parse_ignore_file(src);
        let first = &src[defs[0].byte_start.unwrap() as usize..defs[0].byte_end.unwrap() as usize];
        assert_eq!(first, "target/");
        assert_eq!(defs[1].name, "!keep/");
        assert_eq!(defs[1].line_start, 2);
    }

    #[test]
    fn ignore_long_patterns_truncate_at_80_chars() {
        let long = format!("dir/{}", "a".repeat(120));
        let defs = parse_ignore_file(&long);
        assert_eq!(defs[0].name.chars().count(), 81);
        assert!(defs[0].name.ends_with('…'));
    }
}
