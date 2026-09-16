//! Order command - use-before-define / TDZ report (issue #8b)
//!
//! Wires `tldr_core::analysis::order::analyze_definition_order` to the CLI.
//!
//! Motivating repro (issue #8): an edit referenced `let dataFetchSeq = 0;`
//! declared ~170 lines AFTER the edited function; `tldr impact` passed but
//! eslint failed with 4x `no-use-before-define`. `tldr order` catches exactly
//! this shape from the definition line ranges a single parse already provides.
//!
//! # Conventions
//! - Single positional `<file>` argument (not a byte-faithful command, so a
//!   plain `read_to_string` is fine).
//! - Language resolution: global `--lang/-l` override first, then
//!   `Language::from_path` on the file extension.
//! - Output via [`OutputWriter`]: JSON default, text formatter below.
//! - Graceful degradation for languages outside MVP scope (JS/TS/Python):
//!   exit 0 with `explanation` set and zero issues.
//! - Hard CLI-misuse errors (missing file, undeterminable language) via
//!   `anyhow::bail!` like `structure.rs`.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::analysis::order::{analyze_definition_order, OrderReport};
use tldr_core::Language;

use crate::output::{OutputFormat, OutputWriter};

/// Report use-before-define / TDZ hazards for a single file.
#[derive(Debug, Args)]
pub struct OrderArgs {
    /// Source file to analyze (MVP: JavaScript, TypeScript, Python)
    pub file: PathBuf,
}

impl OrderArgs {
    /// Run the order command.
    ///
    /// Threads `(format, quiet, cli.lang)` exactly like `References`.
    pub fn run(&self, format: OutputFormat, quiet: bool, cli_lang: Option<Language>) -> Result<()> {
        // Validate the path BEFORE any output so errors stay on stderr with a
        // non-zero exit (cli-error-clarity-v2 style).
        if !self.file.exists() {
            anyhow::bail!(
                "Path not found: '{}'. Please provide a valid file.",
                self.file.display()
            );
        }
        if self.file.is_dir() {
            anyhow::bail!(
                "'{}' is a directory. tldr order analyzes a single file.",
                self.file.display()
            );
        }

        let writer = OutputWriter::new(format, quiet);

        // Language: explicit global --lang wins, else path extension.
        let language = match cli_lang {
            Some(l) => l,
            None => Language::from_path(&self.file).ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot determine language for '{}'. Pass --lang <language> \
                     (e.g. --lang javascript, --lang python).",
                    self.file.display()
                )
            })?,
        };

        // Formats-extension hardening (2025-09): for languages outside the
        // definition-order MVP scope (JS/TS/Python), return the explanation
        // WITHOUT reading the file — a 2 GB .jsonl/.xml/.parquet answers
        // instantly instead of being read into RAM for a guaranteed
        // "not supported" outcome.
        if !matches!(
            language,
            Language::JavaScript | Language::TypeScript | Language::Python
        ) {
            let mut report = analyze_definition_order("", language);
            report.file = self.file.display().to_string();
            if writer.is_text() {
                let text = format_order_text(&report);
                writer.write_text(&text)?;
            } else {
                writer.write(&report)?;
            }
            return Ok(());
        }

        // Not a byte-faithfulness command: plain read is fine here.
        let source = std::fs::read_to_string(&self.file)
            .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", self.file.display(), e))?;

        writer.progress(&format!(
            "Analyzing definition order in {} ({})...",
            self.file.display(),
            language.as_str()
        ));

        let mut report = analyze_definition_order(&source, language);
        // The core entry point takes only the source text; the file label is
        // the caller's concern.
        report.file = self.file.display().to_string();

        if writer.is_text() {
            let text = format_order_text(&report);
            writer.write_text(&text)?;
        } else {
            // JSON output (default) — stderr stays clean in json modes.
            writer.write(&report)?;
        }

        Ok(())
    }
}

/// Format the definition-order report as human-readable text.
///
/// One line per issue: `use-before-define: <symbol> (<kind>) used at line N,
/// defined at line M`, followed by the use-line snippet and a summary.
/// The `explanation` (unsupported language / parse failure) is printed when
/// present so consumers can tell "clean" from "not analyzed".
fn format_order_text(report: &OrderReport) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "Use-before-define (TDZ) report: {} ({})\n",
        report.file, report.language
    ));

    if let Some(explanation) = &report.explanation {
        output.push('\n');
        output.push_str(&format!("Note: {}\n", explanation));
    }

    if !report.issues.is_empty() {
        output.push('\n');
        for issue in &report.issues {
            output.push_str(&format!(
                "use-before-define: {} ({}) used at line {}, defined at line {}\n",
                issue.symbol, issue.kind, issue.use_line, issue.definition_line
            ));
            if !issue.snippet.is_empty() {
                output.push_str(&format!("    {}\n", issue.snippet));
            }
        }
    }

    output.push('\n');
    if report.issues.is_empty() {
        output.push_str(&format!(
            "No use-before-define hazards found ({} module-scope definitions checked).\n",
            report.checked_definitions
        ));
    } else {
        output.push_str(&format!(
            "{} use-before-define hazard(s) found ({} module-scope definitions checked).\n",
            report.issues.len(),
            report.checked_definitions
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tldr_core::analysis::order::OrderIssue;

    #[test]
    fn test_format_order_text_with_issues() {
        let report = OrderReport {
            file: "src/app.js".to_string(),
            language: "javascript".to_string(),
            issues: vec![OrderIssue {
                symbol: "dataFetchSeq".to_string(),
                kind: "let".to_string(),
                use_line: 2,
                definition_line: 171,
                snippet: "return dataFetchSeq;".to_string(),
            }],
            checked_definitions: 4,
            explanation: None,
        };

        let text = format_order_text(&report);
        assert!(text.contains("Use-before-define (TDZ) report: src/app.js (javascript)"));
        assert!(text
            .contains("use-before-define: dataFetchSeq (let) used at line 2, defined at line 171"));
        assert!(text.contains("    return dataFetchSeq;"));
        assert!(text
            .contains("1 use-before-define hazard(s) found (4 module-scope definitions checked)."));
    }

    #[test]
    fn test_format_order_text_clean() {
        let report = OrderReport {
            file: "a.py".to_string(),
            language: "python".to_string(),
            issues: Vec::new(),
            checked_definitions: 3,
            explanation: None,
        };

        let text = format_order_text(&report);
        assert!(text
            .contains("No use-before-define hazards found (3 module-scope definitions checked)."));
    }

    #[test]
    fn test_format_order_text_with_explanation() {
        let report = OrderReport {
            file: "main.go".to_string(),
            language: "go".to_string(),
            issues: Vec::new(),
            checked_definitions: 0,
            explanation: Some("definition-order analysis not yet supported for go".to_string()),
        };

        let text = format_order_text(&report);
        assert!(text.contains("Note: definition-order analysis not yet supported for go"));
        assert!(text.contains("No use-before-define hazards found"));
    }
}
