//! JSONL / NDJSON row streaming (formats-extension, 2025-09).
//!
//! `stream_jsonl` is the concrete "chunk streaming" behavior requested for
//! tree-sitter-supported formats: a `.jsonl` / `.ndjson` file is **one JSON
//! document per row**, so it is processed with **bounded memory** — a
//! `BufReader` holds one row at a time, each row is parsed independently with
//! the `tree-sitter-json` grammar, and nothing larger than a single row ever
//! lives in RAM. A 2 GB `.jsonl` costs the same peak memory as a 2 KB one.
//!
//! This is also why the size policy (`fs::oversize::max_size_for`) exempts
//! `.jsonl`/`.ndjson` files: their size is not a memory risk.
//!
//! # Row semantics
//!
//! - Each non-blank row is one independent JSON document ("equivalent of
//!   loading one JSON file per row").
//! - Blank/whitespace-only rows are counted (`rows_blank`) and skipped —
//!   common at EOF.
//! - A row that fails to parse is counted (`rows_invalid`); the first
//!   failure's row number (1-indexed) and message are reported so callers can
//!   point at the offending line. Streaming does NOT abort on the first bad
//!   row — a report of "499_999 valid / 1 invalid at row 12345" is more
//!   actionable than a hard error.
//!
//! # Consumers
//!
//! - `tldr structure <file>.jsonl` returns the standard structure shape with
//!   the additive `jsonl_stream` summary attached.
//! - `parse_file_with_lang` treats a `.jsonl` path as "the first valid row's
//!   tree" so every other parse-based command stays bounded-memory on JSONL.

use std::io::BufRead;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::types::Language;
use crate::TldrResult;

use super::parser::PARSER_POOL;

/// Check whether `path` is a newline-delimited JSON file (`.jsonl`/`.ndjson`).
#[must_use]
pub fn is_jsonl_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("jsonl") || e.eq_ignore_ascii_case("ndjson"))
        .unwrap_or(false)
}

/// Summary of a JSONL row-streaming pass (attached to `CodeStructure` as the
/// additive `jsonl_stream` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonlStreamSummary {
    /// Total non-blank rows seen.
    pub rows_total: u64,
    /// Rows that parsed as valid JSON documents.
    pub rows_valid: u64,
    /// Rows that failed to parse.
    pub rows_invalid: u64,
    /// Blank / whitespace-only rows skipped.
    pub rows_blank: u64,
    /// 1-indexed row number of the first parse failure, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_invalid_row: Option<u64>,
    /// Parser message for the first parse failure, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
    /// Total bytes streamed from the file.
    pub bytes_processed: u64,
    /// Wall-clock streaming + parsing time in milliseconds.
    pub parse_ms: u128,
}

/// Full streaming report for a `.jsonl` / `.ndjson` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonlStreamReport {
    /// Analyzed file path.
    pub file: String,
    /// Always `"json"` — the per-row grammar.
    pub language: String,
    /// Streaming summary (also embedded additively in `CodeStructure`).
    #[serde(flatten)]
    pub summary: JsonlStreamSummary,
}

/// Stream `path` row by row, parsing each row as an independent JSON
/// document with the tree-sitter JSON grammar.
///
/// Memory is bounded by the longest row, never by the file size.
pub fn stream_jsonl(path: &Path) -> TldrResult<JsonlStreamReport> {
    let file =
        std::fs::File::open(path).map_err(crate::error::TldrError::IoError)?;
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);

    let started = Instant::now();
    let mut rows_total: u64 = 0;
    let mut rows_valid: u64 = 0;
    let mut rows_invalid: u64 = 0;
    let mut rows_blank: u64 = 0;
    let mut bytes_processed: u64 = 0;
    let mut first_invalid_row: Option<u64> = None;
    let mut first_error: Option<String> = None;

    // One row in RAM at a time — this is the bounded-memory guarantee.
    let mut row = String::new();
    loop {
        row.clear();
        let read = reader
            .read_line(&mut row)
            .map_err(crate::error::TldrError::IoError)?;
        if read == 0 {
            break;
        }
        bytes_processed += read as u64;

        let trimmed = row.trim();
        if trimmed.is_empty() {
            rows_blank += 1;
            continue;
        }
        rows_total += 1;

        match PARSER_POOL.parse(trimmed, Language::Json) {
            Ok(tree) => {
                if tree.root_node().has_error() {
                    rows_invalid += 1;
                    if first_invalid_row.is_none() {
                        first_invalid_row = Some(rows_total);
                        first_error =
                            Some("row is not a valid JSON document".to_string());
                    }
                } else {
                    rows_valid += 1;
                }
            }
            Err(_) => {
                rows_invalid += 1;
                if first_invalid_row.is_none() {
                    first_invalid_row = Some(rows_total);
                    first_error = Some("row failed to parse as JSON".to_string());
                }
            }
        }
    }

    Ok(JsonlStreamReport {
        file: path.display().to_string(),
        language: Language::Json.as_str().to_string(),
        summary: JsonlStreamSummary {
            rows_total,
            rows_valid,
            rows_invalid,
            rows_blank,
            first_invalid_row,
            first_error,
            bytes_processed,
            parse_ms: started.elapsed().as_millis(),
        },
    })
}

/// Parse and return the FIRST non-blank row of a `.jsonl` file together with
/// its source text, keeping memory bounded by one row.
///
/// Used by the parser chokepoint (`parse_file_with_lang`) so commands that
/// consume a single `Tree` stay bounded on JSONL: the row's structure IS the
/// structure of "one JSON file", per the one-document-per-row equivalence.
pub fn first_row_tree(path: &Path) -> TldrResult<Option<(tree_sitter::Tree, String)>> {
    let file = std::fs::File::open(path).map_err(crate::error::TldrError::IoError)?;
    let mut reader = std::io::BufReader::new(file);
    let mut row = String::new();
    loop {
        row.clear();
        let read = reader
            .read_line(&mut row)
            .map_err(crate::error::TldrError::IoError)?;
        if read == 0 {
            return Ok(None);
        }
        let trimmed = row.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tree = PARSER_POOL.parse(trimmed, Language::Json)?;
        return Ok(Some((tree, trimmed.to_string())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_jsonl(dir: &tempfile::TempDir, name: &str, rows: &[&str]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, rows.join("\n")).expect("write jsonl fixture");
        path
    }

    #[test]
    fn is_jsonl_path_matches_extensions() {
        assert!(is_jsonl_path(Path::new("a.jsonl")));
        assert!(is_jsonl_path(Path::new("a.ndjson")));
        assert!(is_jsonl_path(Path::new("A.JSONL")));
        assert!(!is_jsonl_path(Path::new("a.json")));
        assert!(!is_jsonl_path(Path::new("a.txt")));
    }

    #[test]
    fn streams_valid_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(
            &dir,
            "valid.jsonl",
            &[r#"{"a": 1}"#, r#"[1, 2, 3]"#, r#""plain string""#],
        );
        let report = stream_jsonl(&path).unwrap();
        assert_eq!(report.summary.rows_total, 3);
        assert_eq!(report.summary.rows_valid, 3);
        assert_eq!(report.summary.rows_invalid, 0);
        assert_eq!(report.summary.rows_blank, 0);
        assert_eq!(report.summary.bytes_processed, path.metadata().unwrap().len());
        assert!(report.summary.first_invalid_row.is_none());
        assert!(report.summary.parse_ms < 10_000);
    }

    #[test]
    fn reports_first_invalid_row_without_aborting() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(
            &dir,
            "mixed.jsonl",
            &[
                r#"{"ok": 1}"#,
                "{not json",           // row 2 — invalid
                r#"{"also_ok": [1]}"#, // row 3 — still counted (no abort)
            ],
        );
        let report = stream_jsonl(&path).unwrap();
        assert_eq!(report.summary.rows_total, 3);
        assert_eq!(report.summary.rows_valid, 2);
        assert_eq!(report.summary.rows_invalid, 1);
        assert_eq!(report.summary.first_invalid_row, Some(2));
        assert!(report.summary.first_error.is_some());
    }

    #[test]
    fn blank_rows_are_counted_and_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(
            &dir,
            "blanks.jsonl",
            &["", r#"{"a": 1}"#, "   ", ""],
        );
        // join("\n") => "\n{\"a\": 1}\n   \n": one blank row, one data row,
        // one whitespace row (the trailing "" element is EOF, not a row).
        let report = stream_jsonl(&path).unwrap();
        assert_eq!(report.summary.rows_total, 1);
        assert_eq!(report.summary.rows_valid, 1);
        assert_eq!(report.summary.rows_blank, 2);
    }

    #[test]
    fn streams_many_rows_with_bounded_behavior() {
        // 200k rows — proves streaming handles far-beyond-old-cap row counts
        // quickly (the old 10 MB policy would have skipped a file this size;
        // per-row streaming keeps peak memory at one row).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("many.jsonl");
        use std::io::Write as _;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for i in 0..200_000 {
            writeln!(f, r#"{{"id": {i}, "name": "row-{i}"}}"#).unwrap();
        }
        drop(f);

        let report = stream_jsonl(&path).unwrap();
        assert_eq!(report.summary.rows_total, 200_000);
        assert_eq!(report.summary.rows_valid, 200_000);
        assert_eq!(report.summary.rows_invalid, 0);
    }

    #[test]
    fn first_row_tree_returns_first_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(&dir, "first.jsonl", &["", r#"{"first": true}"#, r#"{"second": 2}"#]);
        let (tree, text) = first_row_tree(&path).unwrap().expect("row exists");
        assert!(!tree.root_node().has_error());
        assert_eq!(text, r#"{"first": true}"#);
    }

    #[test]
    fn first_row_tree_empty_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(&dir, "empty.jsonl", &["", ""]);
        assert!(first_row_tree(&path).unwrap().is_none());
    }

    #[test]
    fn report_serializes_additively() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(&dir, "s.jsonl", &[r#"{"a": 1}"#]);
        let report = stream_jsonl(&path).unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["language"], "json");
        assert_eq!(json["rows_total"], 1);
        // first_invalid_row / first_error are skipped when absent.
        assert!(json.get("first_invalid_row").is_none());
        assert!(json.get("first_error").is_none());
    }
}
