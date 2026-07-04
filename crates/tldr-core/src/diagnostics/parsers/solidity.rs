//! Solidity linter (solhint) JSON output parser.
//!
//! solhint emits JSON via `solhint -f json`. Unlike ESLint's per-file
//! nesting, solhint's `json` formatter flattens every message into a single
//! top-level array and stamps each one with its originating `filePath`. It
//! also rewrites the numeric `severity` (2 = error, otherwise warning) to the
//! human-readable strings `"Error"` / `"Warning"`, and appends a trailing
//! summary object of the shape `{ "conclusion": "…" }` when there is at least
//! one problem. That summary object carries no `filePath`, so it is skipped.
//!
//! ```json
//! [
//!   {
//!     "line": 5,
//!     "column": 1,
//!     "severity": "Error",
//!     "message": "Code contains empty blocks",
//!     "ruleId": "no-empty-blocks",
//!     "filePath": "contracts/Foo.sol"
//!   },
//!   { "conclusion": "1 problem/s (1 error/s)" }
//! ]
//! ```

use crate::diagnostics::{Diagnostic, Severity};
use crate::error::TldrError;
use serde::Deserialize;
use std::path::PathBuf;

/// One element of solhint's flattened `-f json` array.
///
/// Every field is optional so the trailing `{ "conclusion": … }` summary
/// object (which has none of the location fields) deserializes cleanly and
/// is filtered out afterwards by the missing `filePath`.
#[derive(Debug, Deserialize)]
struct SolhintMessage {
    #[serde(rename = "filePath")]
    file_path: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    severity: Option<String>,
    message: Option<String>,
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
}

/// Parse solhint JSON output into unified `Diagnostic` structs.
///
/// # Arguments
/// * `output` - The raw JSON output from `solhint -f json`
///
/// # Returns
/// A vector of `Diagnostic` structs, or an error if the JSON is malformed.
///
/// # Severity Mapping
/// solhint's `json` formatter emits `"Error"` / `"Warning"` strings; anything
/// else (or a missing severity) is treated as a warning, matching solhint's
/// own `severity === 2 ? Error : Warning` fallback.
pub fn parse_solhint_output(output: &str) -> Result<Vec<Diagnostic>, TldrError> {
    // Handle empty output (clean run — solhint prints nothing).
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    // Handle the empty array a clean run can also produce.
    if output.trim() == "[]" {
        return Ok(Vec::new());
    }

    let parsed: Vec<SolhintMessage> =
        serde_json::from_str(output).map_err(|e| TldrError::ParseError {
            file: std::path::PathBuf::from("<solhint-output>"),
            line: None,
            message: format!("Failed to parse solhint JSON: {}", e),
        })?;

    let mut diagnostics = Vec::new();

    for msg in parsed {
        // The trailing `{ "conclusion": … }` summary object has no filePath —
        // it is not a diagnostic, so skip it.
        let Some(file) = msg.file_path else {
            continue;
        };

        let severity = match msg.severity.as_deref() {
            Some("Error") | Some("error") => Severity::Error,
            _ => Severity::Warning,
        };

        diagnostics.push(Diagnostic {
            file: PathBuf::from(file),
            // solhint uses 1-indexed positions; fall back to 1 when a rule
            // reports a file-level problem with no precise location.
            line: msg.line.unwrap_or(1),
            column: msg.column.unwrap_or(1),
            end_line: None,
            end_column: None,
            severity,
            message: msg.message.unwrap_or_default(),
            code: msg.rule_id,
            source: "solhint".to_string(),
            url: None,
        });
    }

    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_and_warning() {
        // Faithful to solhint's `-f json` formatter: a flat array of message
        // objects (string severity + filePath) plus the trailing conclusion.
        let json = r#"[
            {
                "line": 5,
                "column": 1,
                "severity": "Error",
                "message": "Code contains empty blocks",
                "ruleId": "no-empty-blocks",
                "filePath": "contracts/Foo.sol"
            },
            {
                "line": 12,
                "column": 3,
                "severity": "Warning",
                "message": "Explicitly mark visibility of state",
                "ruleId": "state-visibility",
                "filePath": "contracts/Foo.sol"
            },
            { "conclusion": "2 problem/s (1 error/s, 1 warning/s)" }
        ]"#;

        let result = parse_solhint_output(json).unwrap();
        // The conclusion object must NOT become a diagnostic.
        assert_eq!(result.len(), 2);

        let e = &result[0];
        assert_eq!(e.file, PathBuf::from("contracts/Foo.sol"));
        assert_eq!(e.line, 5);
        assert_eq!(e.column, 1);
        assert_eq!(e.severity, Severity::Error);
        assert_eq!(e.code, Some("no-empty-blocks".to_string()));
        assert_eq!(e.source, "solhint");

        let w = &result[1];
        assert_eq!(w.line, 12);
        assert_eq!(w.severity, Severity::Warning);
        assert_eq!(w.code, Some("state-visibility".to_string()));
    }

    #[test]
    fn test_missing_location_defaults_to_one() {
        // File-level rule with no line/column reported.
        let json = r#"[
            {
                "severity": "Warning",
                "message": "Compiler version must be fixed",
                "ruleId": "compiler-version",
                "filePath": "contracts/Bar.sol"
            }
        ]"#;

        let result = parse_solhint_output(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].line, 1);
        assert_eq!(result[0].column, 1);
        assert_eq!(result[0].severity, Severity::Warning);
    }

    #[test]
    fn test_empty_output() {
        assert!(parse_solhint_output("").unwrap().is_empty());
    }

    #[test]
    fn test_empty_array() {
        assert!(parse_solhint_output("[]").unwrap().is_empty());
    }

    #[test]
    fn test_conclusion_only() {
        // A run that only emits the summary object yields no diagnostics.
        let json = r#"[{ "conclusion": "0 problem/s" }]"#;
        assert!(parse_solhint_output(json).unwrap().is_empty());
    }

    #[test]
    fn test_invalid_json() {
        assert!(parse_solhint_output("not json").is_err());
    }
}
