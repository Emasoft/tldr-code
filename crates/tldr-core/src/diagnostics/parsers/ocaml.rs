//! OCaml compiler diagnostic parser (`dune build @check` / `ocamlc`).
//!
//! The OCaml toolchain (and `dune`, which forwards the compiler's output)
//! emits diagnostics in a stable multi-line block format:
//!
//! ```text
//! File "src/foo.ml", line 5, characters 10-15:
//! 5 | let x = bar ()
//!              ^^^
//! Error: Unbound value bar
//! ```
//!
//! Multi-line spans use the plural `lines N1-N2` header, and warnings carry a
//! number/name label:
//!
//! ```text
//! File "src/foo.ml", lines 5-7, characters 2-10:
//! Warning 26 [unused-var]: unused variable y.
//! ```
//!
//! Parsing is done with plain string operations (no regex): each `File "…"`
//! header is decoded for its path/line/column, then the following lines are
//! scanned — skipping the echoed source and `^^^` caret lines — until the
//! `Error`/`Warning` payload line is reached. Character offsets are 0-indexed
//! in OCaml output and are converted to tldr's 1-indexed columns.

use crate::diagnostics::{Diagnostic, Severity};
use crate::error::TldrError;
use std::path::PathBuf;

/// Read the leading run of ASCII digits from `s`, returning the parsed value
/// and the remainder after the digits. Returns `None` when `s` does not start
/// with a digit.
fn take_u32(s: &str) -> Option<(u32, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    let value: u32 = s[..end].parse().ok()?;
    Some((value, &s[end..]))
}

/// Decoded location from a `File "…"` header line.
struct OcamlHeader {
    file: String,
    line: u32,
    end_line: Option<u32>,
    column: u32,
    end_column: Option<u32>,
}

/// Parse a single `File "path", line N, characters C1-C2:` header (also the
/// plural `lines N1-N2` form). Returns `None` if the line is not a header.
fn parse_header(line: &str) -> Option<OcamlHeader> {
    let rest = line.strip_prefix("File \"")?;
    let close = rest.find('"')?;
    let file = rest[..close].to_string();
    // Remainder after the closing quote, e.g. `, line 5, characters 10-15:`.
    let mut rest = &rest[close + 1..];

    // Line(s): prefer the plural `lines A-B` form, else singular `line A`.
    let (line_start, end_line) = if let Some(idx) = rest.find(", lines ") {
        let after = &rest[idx + ", lines ".len()..];
        let (start, after) = take_u32(after)?;
        let after = after.strip_prefix('-').unwrap_or(after);
        let end = take_u32(after).map(|(v, _)| v);
        rest = after;
        (start, end)
    } else {
        let idx = rest.find(", line ")?;
        let after = &rest[idx + ", line ".len()..];
        let (start, after) = take_u32(after)?;
        rest = after;
        (start, None)
    };

    // Characters `C1-C2` are optional (some file-level diagnostics omit them).
    let (column, end_column) = if let Some(idx) = rest.find("characters ") {
        let after = &rest[idx + "characters ".len()..];
        match take_u32(after) {
            Some((c1, after)) => {
                let after = after.strip_prefix('-').unwrap_or(after);
                let c2 = take_u32(after).map(|(v, _)| v);
                // OCaml character offsets are 0-indexed; tldr columns are
                // 1-indexed.
                (c1 + 1, c2.map(|c| c + 1))
            }
            None => (1, None),
        }
    } else {
        (1, None)
    };

    Some(OcamlHeader {
        file,
        line: line_start,
        end_line,
        column,
        end_column,
    })
}

/// Split an `Error`/`Warning` payload line into `(Severity, message)`.
///
/// Handles the label variants OCaml uses: `Error:`, `Error (alert …):`,
/// `Warning NN [name]:`, and bare `Warning NN:`. The message is the text
/// after the first `": "`; when there is none the whole line is kept.
fn parse_payload(line: &str) -> Option<(Severity, String)> {
    let severity = if line.starts_with("Error") {
        Severity::Error
    } else if line.starts_with("Warning") {
        Severity::Warning
    } else {
        return None;
    };

    let message = match line.split_once(": ") {
        Some((_label, rest)) => rest.trim().to_string(),
        None => line.trim().to_string(),
    };

    Some((severity, message))
}

/// Parse OCaml/dune compiler output into unified `Diagnostic` structs.
///
/// Malformed or non-diagnostic lines are skipped. A `File "…"` block that is
/// not followed by an `Error`/`Warning` payload before the next header (or
/// EOF) is ignored rather than emitted with a placeholder.
pub fn parse_ocaml_output(output: &str) -> Result<Vec<Diagnostic>, TldrError> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    let lines: Vec<&str> = output.lines().collect();
    let mut diagnostics = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let Some(header) = parse_header(lines[i].trim_start()) else {
            i += 1;
            continue;
        };

        // Scan forward for the payload line, skipping echoed source / caret
        // lines. Stop at the next header so an unterminated block does not
        // consume the following diagnostic.
        let mut j = i + 1;
        let mut payload = None;
        while j < lines.len() {
            let candidate = lines[j].trim_start();
            if parse_header(candidate).is_some() {
                break;
            }
            if let Some(p) = parse_payload(candidate) {
                payload = Some(p);
                break;
            }
            j += 1;
        }

        if let Some((severity, message)) = payload {
            diagnostics.push(Diagnostic {
                file: PathBuf::from(&header.file),
                line: header.line,
                column: header.column,
                end_line: header.end_line,
                end_column: header.end_column,
                severity,
                message,
                code: None,
                source: "ocaml".to_string(),
                url: None,
            });
            // Continue after the payload line.
            i = j + 1;
        } else {
            // No payload before the next header/EOF — resume from where the
            // scan stopped so we do not re-parse the same header.
            i = j;
        }
    }

    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_single_line() {
        let output = "File \"src/foo.ml\", line 5, characters 10-15:\n\
                      5 | let x = bar ()\n\
                      \x20            ^^^\n\
                      Error: Unbound value bar";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 1);

        let d = &result[0];
        assert_eq!(d.file, PathBuf::from("src/foo.ml"));
        assert_eq!(d.line, 5);
        // OCaml `characters 10-15` → 1-indexed column 11.
        assert_eq!(d.column, 11);
        assert_eq!(d.end_column, Some(16));
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(d.message, "Unbound value bar");
        assert_eq!(d.source, "ocaml");
    }

    #[test]
    fn test_parse_warning_with_label() {
        let output = "File \"src/foo.ml\", line 3, characters 6-7:\n\
                      Warning 26 [unused-var]: unused variable y.";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert_eq!(result[0].line, 3);
        assert_eq!(result[0].message, "unused variable y.");
    }

    #[test]
    fn test_parse_multiline_span() {
        let output = "File \"src/foo.ml\", lines 5-7, characters 2-10:\n\
                      Error: This expression has type int but was expected of type string";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 1);
        let d = &result[0];
        assert_eq!(d.line, 5);
        assert_eq!(d.end_line, Some(7));
        assert_eq!(d.column, 3);
        assert_eq!(d.end_column, Some(11));
        assert_eq!(d.severity, Severity::Error);
    }

    #[test]
    fn test_parse_alert_error_form() {
        let output = "File \"src/foo.ml\", line 1, characters 0-3:\n\
                      Error (alert deprecated): Stdlib.foo is deprecated";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Error);
        assert_eq!(result[0].message, "Stdlib.foo is deprecated");
    }

    #[test]
    fn test_parse_multiple_blocks() {
        let output = "File \"a.ml\", line 1, characters 0-3:\n\
                      Error: first\n\
                      File \"b.ml\", line 2, characters 4-5:\n\
                      Warning 20 [ignored]: second";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file, PathBuf::from("a.ml"));
        assert_eq!(result[0].severity, Severity::Error);
        assert_eq!(result[1].file, PathBuf::from("b.ml"));
        assert_eq!(result[1].severity, Severity::Warning);
    }

    #[test]
    fn test_header_without_characters() {
        let output = "File \"dune\", line 4:\n\
                      Error: Dune project files require a version field";

        let result = parse_ocaml_output(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].line, 4);
        assert_eq!(result[0].column, 1);
        assert_eq!(result[0].end_column, None);
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_ocaml_output("").unwrap().is_empty());
    }

    #[test]
    fn test_parse_no_payload_block_ignored() {
        // A dangling header with no Error/Warning must not emit a diagnostic.
        let output = "File \"src/foo.ml\", line 5, characters 10-15:\n\
                      5 | let x = bar ()";
        assert!(parse_ocaml_output(output).unwrap().is_empty());
    }
}
