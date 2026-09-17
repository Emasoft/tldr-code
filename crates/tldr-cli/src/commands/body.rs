//! Body command — SAFE contiguous, byte-faithful source reader (issue #8).
//!
//! `tldr body <file> <function>` prints the exact contiguous source lines of
//! a function body; `tldr body <file> --from N --to M` prints an exact
//! contiguous line range. Both modes are:
//!
//! - **Contiguous**: the output is exactly the requested span — no dependency
//!   closure, no reordering, nothing added or removed. This is what
//!   distinguishes `body` from `slice` (a PDG statement closure) and `chop`
//!   (forward ∩ backward slice between two lines), neither of which is
//!   bounded by the requested line window.
//! - **Byte-faithful**: the file is read with [`std::fs::read`] (raw bytes,
//!   never `read_to_string`), and line boundaries are computed by scanning
//!   for `\n` once. CRLF line endings, a UTF-8 BOM at offset 0, and trailing
//!   whitespace are preserved exactly. The JSON `body` field is decoded with
//!   `String::from_utf8_lossy` and an additive `encoding_lossy` flag (plus a
//!   `warnings` entry) is set when the span is not valid UTF-8; text format
//!   writes the raw bytes verbatim so nothing is ever lost on that path.
//!
//! Function line bounds reuse the exact path `chop` uses —
//! [`tldr_core::ast::function_finder::find_function_bounds_from_path_or_source`]
//! — so `tldr body f.py main` and `tldr structure f.py` agree on where
//! `main` starts and ends.
//!
//! # Element-name resolution (body-elements-v1)
//!
//! When the function-kind search finds no node named `<name>`, the command
//! falls back to the structure extractor's DEFINITION table (the same
//! `files[].definitions` array `tldr structure` reports) before failing:
//! markdown headings, CSS selectors, JSON/YAML/TOML keys, TOML sections, CSV
//! records/cells, log entries, text headings, LaTeX sections, OOXML parts,
//! classes, constants and fields are all real, region-bearing definitions
//! that are not function-kind AST nodes. Definitions that carry exact byte
//! offsets are sliced byte-faithfully (`source[byte_start..byte_end]` IS the
//! element); the rest use the definition's 1-indexed line span minus its
//! trailing newline. The name matches exactly (case-sensitive); the FIRST
//! same-name definition in source order wins. `--from/--to` behavior is
//! untouched.
//!
//! # Output
//!
//! - `--format json` / `--format compact`: a [`BodyResult`] document
//!   (schema `body-command-v1 (issue #8)`).
//! - `--format text`: the body bytes verbatim on stdout, with no decoration
//!   and no added trailing newline beyond what the source itself contains.
//!
//! # Examples
//!
//! ```bash
//! # Exact source of a function
//! tldr body src/lib.rs parse_config
//!
//! # Exact contiguous line range (1-indexed, inclusive)
//! tldr body src/lib.rs --from 10 --to 24
//!
//! # Raw bytes for reconstruction (piping-safe)
//! tldr body f.py handler --format text > extracted.py
//! ```

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use tldr_core::ast::extractor::get_code_structure;
use tldr_core::ast::function_finder::find_function_bounds_from_path_or_source;
use tldr_core::Language;

use crate::output::{OutputFormat, OutputWriter};

/// Result document for `tldr body` — the exact contiguous source span.
///
/// Schema: `body-command-v1 (issue #8)`. Additive-field conventions apply:
/// `encoding_lossy` and `warnings` are skipped when empty/false, and any
/// future fields must be additive (new optional/flagged fields only) so
/// consumers never see a breaking change.
#[derive(Debug, Serialize)]
pub struct BodyResult {
    /// File path exactly as the user supplied it.
    pub file: String,
    /// Function name, when the function-lookup mode was used.
    pub function: Option<String>,
    /// Language used for function lookup (or `"unknown"` when a pure line
    /// range was requested and detection failed — detection is not needed
    /// for ranges).
    pub language: String,
    /// First line of the span (1-indexed, inclusive).
    pub line_start: u32,
    /// Last line of the span (1-indexed, inclusive).
    pub line_end: u32,
    /// Number of lines in the span (`line_end - line_start + 1`).
    pub line_count: u32,
    /// Exact byte length of `body` as it appears in the file.
    pub byte_count: usize,
    /// The source span. Valid UTF-8 unless `encoding_lossy` is true, in
    /// which case invalid sequences were replaced with U+FFFD (text format
    /// still emits the raw bytes).
    pub body: String,
    /// True when the span contained invalid UTF-8 and was lossily decoded
    /// for the JSON `body` field. Skipped when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub encoding_lossy: bool,
    /// Non-fatal advisories (e.g. `--to` clamped to the last line). Skipped
    /// when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Print the exact contiguous source of a function body or line range.
#[derive(Debug, Args)]
pub struct BodyArgs {
    /// Path to the source file
    #[arg(value_name = "file")]
    pub file: PathBuf,

    /// Function whose exact body lines should be printed
    #[arg(value_name = "function")]
    pub function: Option<String>,

    /// First line of the contiguous range (1-indexed, inclusive). Requires --to.
    #[arg(long, value_name = "N")]
    pub from: Option<u32>,

    /// Last line of the contiguous range (1-indexed, inclusive; the newline
    /// terminating this line is included in the output). Requires --from.
    #[arg(long, value_name = "M")]
    pub to: Option<u32>,
}

/// Compute the byte offset at which each line starts, by scanning for `\n`
/// exactly once over the raw file bytes.
///
/// `starts[0] == 0` always. When the file ends with `\n`, the final entry
/// equals `bytes.len()` and is a phantom start for a zero-length line that
/// does not exist; [`count_lines`] accounts for that.
fn line_starts(bytes: &[u8]) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Number of real (1-indexed) lines in the file.
fn count_lines(bytes: &[u8], starts: &[usize]) -> usize {
    if bytes.is_empty() {
        0
    } else if bytes[bytes.len() - 1] == b'\n' {
        // The trailing newline opened a phantom zero-length "line" that has
        // no content — do not count it.
        starts.len() - 1
    } else {
        starts.len()
    }
}

/// A resolved source span to slice out of the file.
///
/// body-elements-v1: `body <file> <name>` can resolve a name two ways —
/// through the function-kind AST search (a 1-indexed line range, sliced with
/// the line-offset machinery) or, as a fallback, through the structure
/// extractor's definition table where the producer populated exact byte
/// offsets (format elements, log entries, CSV records/cells, text headings —
/// sliced byte-faithfully).
#[derive(Debug, Clone, Copy)]
enum ResolvedSpan {
    /// 1-indexed inclusive line range: the span runs from the start of
    /// `line_start` to the end of line `line_end`. `include_trailing_newline`
    /// decides whether the newline terminating `line_end` is part of the
    /// span: the function path and `--from/--to` ranges INCLUDE it (so the
    /// body re-concatenates into the file losslessly), while the
    /// element-definition line fallback EXCLUDES it — an element region is
    /// the element itself, the same convention every byte-span producer
    /// follows.
    Lines {
        line_start: u32,
        line_end: u32,
        include_trailing_newline: bool,
    },
    /// Exact byte range of an element definition — `source[start..end]` IS
    /// the element (the region, not the surrounding lines: a nested JSON
    /// key's bytes start mid-line at the quote). `line_start`/`line_end`
    /// are the definition's line numbers and describe the range's lines.
    Bytes {
        start: usize,
        end: usize,
        line_start: u32,
        line_end: u32,
    },
}

/// Resolve `name` against the file's DEFINITION table — the same
/// `files[].definitions` array `tldr structure` reports — after the
/// function-kind search failed to find it.
///
/// This is the second half of body-elements-v1: headings, CSS selectors,
/// JSON/YAML/TOML keys, TOML sections, CSV records/cells, log entries, text
/// headings, LaTeX sections, OOXML parts, classes, constants and fields are
/// all real, region-bearing definitions that are NOT function-kind AST
/// nodes, so `tldr body <file> <name>` used to dead-end with "Function
/// '<name>' not found" for every one of them.
///
/// Extraction, per definition:
/// 1. **Byte-first.** Producers that populate `DefinitionInfo::byte_start`
///    /`byte_end` (format elements, log entries, CSV records/cells, text
///    headings, OOXML parts) give `source[byte_start..byte_end]` as the
///    element's exact region — slice those bytes verbatim.
/// 2. **Line fallback.** Code-language definitions keep byte spans `None`
///    (element-extraction-v1); use the definition's 1-indexed
///    `line_start`/`line_end` through the same line-offset machinery as the
///    function path, MINUS the trailing newline — an element region is the
///    element itself (the same convention every byte producer follows).
///
/// `name` matches exactly (case-sensitive). If several definitions share
/// the name (same-named JSON keys at different depths, a CSV header cell vs
/// a record, overloads), the FIRST match in source order wins: every
/// definition producer emits pre-order (documented in `ast::elements`), so
/// vec order IS source order. The body envelope has no notes field, so the
/// first-match rule lives here and in the CHANGELOG rather than in the JSON.
///
/// `file_len` bounds-checks byte spans so a stale producer can never panic
/// the slice downstream; an out-of-range or degenerate definition is
/// skipped exactly like a non-match.
fn find_element_span(
    file: &Path,
    name: &str,
    language: Language,
    file_len: usize,
) -> Option<ResolvedSpan> {
    // Single-file extraction: `max_results = 0` (unlimited), no ignore
    // spec. A failed extraction (oversize file, unreadable, unsupported)
    // degrades to "not found" — the caller's error shape stays unchanged.
    let structure = get_code_structure(file, language, 0, None).ok()?;
    for file_structure in &structure.files {
        for def in &file_structure.definitions {
            if def.name != name {
                continue;
            }
            if let (Some(byte_start), Some(byte_end)) = (def.byte_start, def.byte_end) {
                let start = byte_start as usize;
                let end = byte_end as usize;
                if end > start && end <= file_len && def.line_start >= 1 {
                    return Some(ResolvedSpan::Bytes {
                        start,
                        end,
                        line_start: def.line_start,
                        line_end: def.line_end,
                    });
                }
            } else if def.line_start >= 1 && def.line_end >= def.line_start {
                return Some(ResolvedSpan::Lines {
                    line_start: def.line_start,
                    line_end: def.line_end,
                    include_trailing_newline: false,
                });
            }
            // Degenerate span on a name match: keep scanning — a later
            // same-name definition may still be usable.
        }
    }
    None
}

impl BodyArgs {
    /// Run the body command
    pub fn run(
        &self,
        cli_format: OutputFormat,
        quiet: bool,
        cli_lang: Option<Language>,
    ) -> Result<()> {
        // -- Mode selection ------------------------------------------------
        let wants_function = self.function.is_some();
        let wants_range = self.from.is_some() || self.to.is_some();
        if wants_function && wants_range {
            anyhow::bail!(
                "Pass either a function name or --from/--to, not both: \
                 'tldr body <file> <function>' or 'tldr body <file> --from N --to M'."
            );
        }
        if wants_range && (self.from.is_none() || self.to.is_none()) {
            anyhow::bail!(
                "--from and --to must be given together as a contiguous range: \
                 'tldr body {} --from N --to M'.",
                self.file.display()
            );
        }
        if !wants_function && !wants_range {
            anyhow::bail!(
                "Nothing to extract: pass a function name ('tldr body {} <function>') \
                 or a contiguous line range ('tldr body {} --from N --to M').",
                self.file.display(),
                self.file.display()
            );
        }

        // Validate the path exists BEFORE any detection / progress banner
        // (same convention as `structure`).
        if !self.file.exists() {
            anyhow::bail!("Path not found: {}", self.file.display());
        }

        let writer = OutputWriter::new(cli_format, quiet);
        writer.progress(&format!("Reading {}...", self.file.display()));

        // -- Byte-faithful read --------------------------------------------
        // Raw bytes only: `read_to_string` would normalize nothing but would
        // make the BOM/CRLF story lossy-adjacent, and we slice by byte
        // offset regardless of encoding.
        let bytes = std::fs::read(&self.file)?;
        let starts = line_starts(&bytes);
        let total_lines = count_lines(&bytes, &starts);

        let mut warnings: Vec<String> = Vec::new();
        let (function, span) = if let Some(function) = &self.function {
            // Function mode: same bounds resolution path as `chop`, so
            // `body`, `structure`, and `chop` always agree on a function's
            // line span.
            let language = match cli_lang.or_else(|| Language::from_path(&self.file)) {
                Some(l) => l,
                None => anyhow::bail!(
                    "Could not detect a language for '{}' (needed to locate function '{}'). \
                     Pass --lang <lang> or use --from/--to for a plain line range.",
                    self.file.display(),
                    function
                ),
            };
            let resolved = match find_function_bounds_from_path_or_source(
                &self.file.to_string_lossy(),
                function,
                language,
            ) {
                Some((start, end)) => ResolvedSpan::Lines {
                    line_start: start,
                    line_end: end,
                    include_trailing_newline: true,
                },
                // body-elements-v1: the function-kind search found nothing,
                // but the name may still be a definition that is NOT a
                // function-kind node — a markdown heading, CSS selector,
                // JSON key, CSV record, log entry, a class, a constant…
                // Fall back to the definition table before giving up (the
                // not-found error shape is unchanged when that fails too).
                None => match find_element_span(&self.file, function, language, bytes.len()) {
                    Some(span) => span,
                    None => anyhow::bail!(
                        "Function '{}' not found in '{}'.",
                        function,
                        self.file.display()
                    ),
                },
            };
            (Some(function.clone()), resolved)
        } else {
            // Range mode: validate, then clamp an over-long `--to` to the
            // last line with an advisory (never silently).
            let from = self.from.expect("from/to validated above");
            let mut to = self.to.expect("from/to validated above");
            if from < 1 {
                anyhow::bail!("--from must be >= 1 (lines are 1-indexed), got {}.", from);
            }
            if to < from {
                anyhow::bail!(
                    "--from must be <= --to for a contiguous range, got {}..{}.",
                    from,
                    to
                );
            }
            if (to as usize) > total_lines {
                warnings.push(format!(
                    "--to {} clamped to {} ('{}' has {} lines).",
                    to,
                    total_lines,
                    self.file.display(),
                    total_lines
                ));
                to = total_lines as u32;
            }
            if (from as usize) > total_lines {
                anyhow::bail!(
                    "--from {} is past the end of '{}' ({} lines).",
                    from,
                    self.file.display(),
                    total_lines
                );
            }
            (
                None,
                ResolvedSpan::Lines {
                    line_start: from,
                    line_end: to,
                    include_trailing_newline: true,
                },
            )
        };

        // -- Slice the exact byte span --------------------------------------
        // Line spans run from the start of `line_start`; the newline
        // terminating `line_end` is included or not per
        // `include_trailing_newline` (see `ResolvedSpan::Lines`). Byte spans
        // are the element definition's exact region.
        let (line_start, line_end, start_offset, end_offset) = match span {
            ResolvedSpan::Lines {
                line_start,
                line_end,
                include_trailing_newline,
            } => {
                let start_offset = starts[line_start as usize - 1];
                let end_offset = if (line_end as usize) < total_lines {
                    starts[line_end as usize] // start of line `line_end + 1`
                } else {
                    bytes.len() // last line: include everything up to EOF
                };
                // Element line spans end at the last CONTENT byte of
                // `line_end` — strip the terminating newline (never strip
                // past the span start: an empty line contributes nothing).
                let end_offset = if !include_trailing_newline
                    && end_offset > start_offset
                    && bytes[end_offset - 1] == b'\n'
                {
                    end_offset - 1
                } else {
                    end_offset
                };
                (line_start, line_end, start_offset, end_offset)
            }
            ResolvedSpan::Bytes {
                start,
                end,
                line_start,
                line_end,
            } => (line_start, line_end, start, end),
        };
        let body_bytes = &bytes[start_offset..end_offset];

        let encoding_lossy = std::str::from_utf8(body_bytes).is_err();
        if encoding_lossy {
            warnings.push(
                "body contains invalid UTF-8; the JSON `body` field replaced invalid \
                 sequences with U+FFFD (`--format text` preserves the raw bytes)."
                    .to_string(),
            );
        }

        let language_str = cli_lang
            .or_else(|| Language::from_path(&self.file))
            .map(|l| l.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let result = BodyResult {
            file: self.file.display().to_string(),
            function,
            language: language_str,
            line_start,
            line_end,
            line_count: line_end - line_start + 1,
            byte_count: body_bytes.len(),
            body: String::from_utf8_lossy(body_bytes).into_owned(),
            encoding_lossy,
            warnings,
        };

        match cli_format {
            OutputFormat::Text => {
                // Verbatim raw bytes, no decoration, no added newline.
                let stdout = std::io::stdout();
                let mut handle = stdout.lock();
                handle.write_all(body_bytes)?;
                handle.flush()?;
            }
            _ => {
                // JSON / compact: full BodyResult document.
                writer.write(&result)?;
            }
        }

        Ok(())
    }
}
