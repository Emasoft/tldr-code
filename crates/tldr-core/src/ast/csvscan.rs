//! Native RFC 4180 CSV/TSV record scanning (`Language::Csv` / `Language::Tsv`).
//!
//! No usable tree-sitter grammar exists for CSV. The ONLY CSV grammar crate
//! published on crates.io — `tree-sitter-csv` 1.2.0, last publish 2024-01-24 —
//! is UNBUILDABLE and UNLINKABLE in this workspace, verified by a build probe
//! (2026-09, recorded in the root `Cargo.toml` audit note next to the
//! tree-sitter-sql comment):
//!
//! 1. it declares build-dependency `cc ~1.0.82`, which semver-conflicts with
//!    the `cc ^1.2.10` the pinned tree-sitter 0.25 stack already requires —
//!    cargo refuses the duplicate `cc` requirement outright;
//! 2. even built, it exports raw tree-sitter **0.20-era** `language_csv()`
//!    functions with NO `tree-sitter-language` bridge `LANGUAGE` LanguageFn,
//!    so it cannot load against the pinned ts 0.25 runtime the way every
//!    format grammar here does (the latex/markdown bridge precedent).
//!
//! So `.csv`/`.tsv` files NEVER parse through tree-sitter — the same
//! no-grammar precedent as `Language::Log` (`ast::logs`) and `Language::Text`
//! (`ast::toc`). This module is the only consumer of CSV/TSV content: a
//! deterministic, streaming **record scanner** implementing the RFC 4180
//! dialect (with the two documented leniencies below).
//!
//! # Streaming / memory model
//!
//! A `BufReader` holds **one physical line at a time** (1 MB buffer, the
//! `ast::jsonl`/`ast::logs` precedent — a data export may be GiB-scale), plus
//! the field/record currently being assembled. Nothing proportional to the
//! file size is ever held in RAM while scanning. Byte offsets are tracked
//! manually as the running position over the physical lines, so
//! `byte_start`/`byte_end` stay exact. [`parse_csv_file`] is the
//! collect-everything convenience wrapper used by `tldr structure`; the
//! honest memory bound on that path is the materialised `Vec<CsvRecord>`
//! (one struct per record — like `ast::logs::parse_log_file`), NOT the byte
//! size, and the size policy exempts `.csv`/`.tsv` the same way it exempts
//! `.jsonl`/`.log` (see `fs::oversize::max_size_for`).
//!
//! # The state machine (the format contract, documented because it IS the spec)
//!
//! Records are separated by `\n` or `\r\n`; fields by the delimiter (`,` for
//! CSV, `\t` for TSV — callers pass the byte). A field may be quoted with `"`
//! and then may contain delimiters, `"` (doubled = one literal quote) and
//! line breaks. States, per input byte:
//!
//! | State           | byte                        | effect |
//! |-----------------|-----------------------------|--------|
//! | FieldStart      | `"`                         | open a QUOTED field (the quote is its first raw byte) |
//! | FieldStart      | delimiter                   | close an EMPTY field, open the next |
//! | FieldStart      | `\n` (or `\r\n`)            | record end |
//! | FieldStart      | anything else               | open an UNQUOTED field |
//! | Unquoted        | delimiter                   | close field, open next |
//! | Unquoted        | `\r` before `\n`            | close field, record end (both bytes consumed, `\r` excluded from content) |
//! | Unquoted        | `\n`                        | close field, record end |
//! | Unquoted        | `"`                         | ordinary CONTENT (leniency 1 below) |
//! | Quoted          | `"`                         | pending: escaped quote or field close |
//! | Quoted          | anything else (incl. `\n`)  | content — embedded line breaks stay inside the field |
//! | QuoteInQuoted   | `"`                         | escaped quote: one literal `"` enters the text, stay Quoted |
//! | QuoteInQuoted   | delimiter                   | close field (the closing quote was its last raw byte) |
//! | QuoteInQuoted   | `\n` (or `\r\n`)            | close field, record end |
//! | QuoteInQuoted   | anything else               | the earlier `"` was CONTENT after all: push it and re-read this byte as Unquoted (leniency 2 below) |
//!
//! **Leniency 1** — a `"` inside an unquoted field is an ordinary content
//! byte (`a"b` stays `a"b`). RFC 4180 calls this malformed; real exports
//! contain it, and refusing the file would trade one cosmetic defect for a
//! zero-structure report.
//!
//! **Leniency 2** — garbage after a closing quote (`"a"x,b`) folds the stray
//! quote into the field text and re-enters UNQUOTED scanning, so a following
//! delimiter still terminates the field (the Python-csv lenient reading:
//! `"a"x,b` → fields `a"x` + `b`). Ending the field AT the quote would
//! instead silently split one logical field in two. An unterminated quote at
//! EOF simply closes its record at EOF.
//!
//! # Span / text semantics
//!
//! - A field's RAW byte span covers exactly its source bytes: an unquoted
//!   field's bytes, or a quoted field INCLUDING both quote tokens (so `""`
//!   escapes and embedded newlines are inside the span).
//! - A record's span = its first field's first byte through its last field's
//!   last byte — `source[byte_start..byte_end]` reproduces the record exactly
//!   (delimiters, quotes and embedded line breaks included). A trailing empty
//!   field is a zero-width span, so a record ending in a delimiter ends at
//!   that delimiter (`a,b,` spans the three bytes `a,b,`).
//! - The field TEXT is the unescaped content: quotes stripped, `""` → `"`,
//!   and embedded `\r\n` normalized to `\n` (the `\r` never enters text; the
//!   SPAN keeps the raw bytes — the same text-vs-region split `ast::logs`
//!   documents for entry text). Bytes are accumulated raw and lossy-decoded
//!   once at field close, so multi-byte UTF-8 field text survives intact.
//! - Record/field terminating `\r\n` is EXCLUDED from the span and text but
//!   the byte cursor advances over both, so subsequent spans stay exact. A
//!   lone `\r` NOT followed by `\n` is ordinary content (RFC 4180 knows only
//!   CRLF; bare-CR files are out of scope).
//! - A UTF-8 BOM at file offset 0 is skipped (neither content nor span), so
//!   the first header cell of an Excel-exported file is named `id`, not
//!   `\u{feff}id`.
//! - Blank lines (nothing but the terminator) are skipped — they emit no
//!   record. The trailing newline at EOF therefore never fabricates a
//!   phantom trailing record, and `a\n\nb\n` yields exactly records `a`, `b`.

use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::TldrResult;

/// Streaming buffer size (1 MB — the `ast::jsonl`/`ast::logs` precedent).
const STREAM_BUFFER: usize = 1024 * 1024;

/// Record-name budget: the first field text is truncated to this many
/// **characters** (char-boundary safe) when it becomes a `record` name.
pub const MAX_RECORD_NAME_CHARS: usize = 60;

/// One scanned CSV field: its unescaped TEXT plus the exact RAW byte span
/// (quotes included for quoted fields) and line range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsvField {
    /// Unescaped field text (quotes stripped, `""` → `"`, embedded `\r\n`
    /// normalized to `\n`).
    pub text: String,
    /// Byte offset of the field's FIRST raw byte (0-indexed; the opening
    /// quote for a quoted field).
    pub byte_start: u64,
    /// Byte offset ONE PAST the field's last raw byte (exclusive; the closing
    /// quote is inside the span for quoted fields).
    pub byte_end: u64,
    /// First line of the field (1-indexed).
    pub line_start: u32,
    /// Last line of the field (1-indexed, inclusive) — differs from
    /// `line_start` only for fields with embedded line breaks.
    pub line_end: u32,
    /// Whether the field was quoted in the source.
    pub quoted: bool,
}

/// One scanned CSV/TSV record: a field row with its exact byte span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsvRecord {
    /// First line of the record (1-indexed).
    pub line_start: u32,
    /// Last line of the record (1-indexed, inclusive) — differs from
    /// `line_start` when any field embeds a line break.
    pub line_end: u32,
    /// Byte offset of the record's FIRST byte (0-indexed — the first field's
    /// first byte).
    pub byte_start: u64,
    /// Byte offset ONE PAST the record's last byte (exclusive). Line
    /// terminators INTERIOR to the record (embedded in quoted fields) are
    /// part of the span; the record-terminating `\n`/`\r\n` is excluded.
    /// `source[byte_start..byte_end]` is the record's exact source region.
    pub byte_end: u64,
    /// Fields in source order (an empty source field yields an empty-text
    /// field with a zero-width span).
    pub fields: Vec<CsvField>,
}

// =============================================================================
// Public API
// =============================================================================

/// Check whether `path` looks like a CSV file (`.csv` extension,
/// case-insensitive).
#[must_use]
pub fn is_csv_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("csv"))
        .unwrap_or(false)
}

/// Check whether `path` looks like a TSV file (`.tsv` extension,
/// case-insensitive).
#[must_use]
pub fn is_tsv_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("tsv"))
        .unwrap_or(false)
}

/// The field delimiter byte for a `.csv` (`,`) or `.tsv` (`\t`) path;
/// `None` for anything else. The single place the extension→delimiter
/// mapping lives, so the structure hook and any future consumer agree.
#[must_use]
pub fn delimiter_for(path: &Path) -> Option<u8> {
    if is_csv_path(path) {
        Some(b',')
    } else if is_tsv_path(path) {
        Some(b'\t')
    } else {
        None
    }
}

/// Stream `path` record-by-record, handing each completed [`CsvRecord`] to
/// `emit`.
///
/// Returns the TOTAL number of records scanned. Memory is bounded by the
/// longest physical line plus the record being assembled — never by the file
/// size (a quoted field may span many lines; only that field's text is held).
pub fn stream_csv_records<F>(path: &Path, delimiter: u8, mut emit: F) -> TldrResult<u64>
where
    F: FnMut(CsvRecord),
{
    let file = std::fs::File::open(path).map_err(crate::error::TldrError::IoError)?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER, file);

    let mut total: u64 = 0;
    // Running byte offset of the NEXT byte to process = sum of physical line
    // lengths (including terminators). Offsets stay exact because the cursor
    // advances over the FULL physical line, terminators included.
    let mut offset: u64 = 0;
    let mut line_no: u64 = 0;
    // State machine (see the module docs for the transition table).
    let mut st = St::FieldStart;
    let mut rec = Rec::default();
    let mut cur: Option<Cur> = None;
    // The file may START with a UTF-8 BOM; those three bytes are skipped.
    let mut bom_pending = true;

    // Reusable read buffer (one physical line at a time — the bounded-memory
    // guarantee; a pathological single 100 MB line costs 100 MB here, the
    // same trade-off as the jsonl row reader).
    let mut buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(crate::error::TldrError::IoError)?;
        if n == 0 {
            break; // EOF
        }
        line_no += 1;

        let mut i = 0usize;
        // BOM skip: only at the very start of the file.
        if bom_pending && offset == 0 && buf.len() >= 3 && buf[0..3] == [0xEF, 0xBB, 0xBF] {
            i = 3;
        }
        bom_pending = false;

        while i < buf.len() {
            let b = buf[i];
            let pos = offset + i as u64;
            // One-byte lookahead within the physical line — needed to tell
            // the `\r` of a `\r\n` pair (terminator, excluded) from a lone
            // `\r` (content). A `\r\n` pair never straddles buffers because
            // `read_until` stops right after the `\n`.
            let next = buf.get(i + 1).copied();

            match st {
                St::FieldStart => match b {
                    b'"' => {
                        rec.open(pos, line_no);
                        cur = Some(Cur::new(pos, line_no, true));
                        st = St::Quoted;
                        i += 1;
                    }
                    _ if b == delimiter => {
                        rec.open(pos, line_no);
                        // Empty field: zero-width span at the position the
                        // field would have occupied.
                        rec.push_field(Cur::new(pos, line_no, false).close(pos), pos);
                        st = St::FieldStart;
                        i += 1;
                    }
                    b'\n' => {
                        i += 1;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    }
                    b'\r' if next == Some(b'\n') => {
                        i += 2;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    }
                    _ => {
                        rec.open(pos, line_no);
                        let mut c = Cur::new(pos, line_no, false);
                        c.push(b);
                        c.byte_end = pos + 1;
                        cur = Some(c);
                        st = St::Unquoted;
                        i += 1;
                    }
                },
                St::Unquoted => {
                    if b == delimiter {
                        if let Some(c) = cur.take() {
                            rec.push_field(c.close(pos), pos);
                        }
                        st = St::FieldStart;
                        i += 1;
                    } else if b == b'\r' && next == Some(b'\n') {
                        // CRLF record terminator: `\r` excluded from content
                        // AND from the span; cursor advances over both.
                        if let Some(c) = cur.take() {
                            rec.push_field(c.close(pos), pos);
                        }
                        i += 2;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    } else if b == b'\n' {
                        if let Some(c) = cur.take() {
                            rec.push_field(c.close(pos), pos);
                        }
                        i += 1;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    } else {
                        // Leniency 1: a `"` here is ordinary content.
                        if let Some(c) = cur.as_mut() {
                            c.push(b);
                            c.byte_end = pos + 1;
                            c.line_end = line_no;
                        }
                        i += 1;
                    }
                }
                St::Quoted => {
                    if b == b'"' {
                        // Potential closing quote — it is part of the field's
                        // RAW span whether it closes the field or (lenient)
                        // turns out to be content.
                        if let Some(c) = cur.as_mut() {
                            c.byte_end = pos + 1;
                            c.line_end = line_no;
                        }
                        st = St::QuoteInQuoted;
                        i += 1;
                    } else if b == b'\r' && next == Some(b'\n') {
                        // Embedded CRLF inside quotes: BOTH bytes are raw
                        // span bytes; the text keeps only `\n` (normalized).
                        if let Some(c) = cur.as_mut() {
                            c.push(b'\n');
                            c.byte_end = pos + 2;
                            c.line_end = line_no;
                        }
                        i += 2;
                    } else {
                        // Content — including a lone `\n` (embedded line
                        // break) and a lone `\r` (raw content byte).
                        if let Some(c) = cur.as_mut() {
                            c.push(b);
                            c.byte_end = pos + 1;
                            c.line_end = line_no;
                        }
                        i += 1;
                    }
                }
                St::QuoteInQuoted => match b {
                    b'"' => {
                        // Escaped quote: one literal `"` enters the text.
                        if let Some(c) = cur.as_mut() {
                            c.push(b'"');
                            c.byte_end = pos + 1;
                            c.line_end = line_no;
                        }
                        st = St::Quoted;
                        i += 1;
                    }
                    _ if b == delimiter => {
                        // Field close: the closing quote was this field's
                        // last raw byte (byte_end already covers it).
                        if let Some(c) = cur.take() {
                            let end = c.byte_end;
                            rec.push_field(c.close(end), end);
                        }
                        st = St::FieldStart;
                        i += 1;
                    }
                    b'\n' => {
                        if let Some(c) = cur.take() {
                            let end = c.byte_end;
                            rec.push_field(c.close(end), end);
                        }
                        i += 1;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    }
                    b'\r' if next == Some(b'\n') => {
                        if let Some(c) = cur.take() {
                            let end = c.byte_end;
                            rec.push_field(c.close(end), end);
                        }
                        i += 2;
                        finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);
                    }
                    _ => {
                        // Leniency 2: the earlier `"` was content after all.
                        // Push it and re-read THIS byte under UNQUOTED rules
                        // (a following delimiter or line break still
                        // terminates the field — the Python-csv lenient
                        // reading of `"a"x,b` → fields `a"x` + `b`).
                        if let Some(c) = cur.as_mut() {
                            c.push(b'"');
                        }
                        st = St::Unquoted;
                        continue; // re-process this byte (no i += 1)
                    }
                },
            }
        }
        // Advance over the FULL physical line (terminator included).
        offset += n as u64;
    }

    // EOF: close any open field and flush the final record (an unterminated
    // quote simply ends its record here).
    if let Some(c) = cur.take() {
        let end = c.byte_end;
        rec.push_field(c.close(end), end);
    }
    finish(&mut rec, &mut cur, &mut st, &mut emit, &mut total);

    Ok(total)
}

/// Parse a CSV/TSV file into all of its records (source order —
/// deterministic).
///
/// Convenience wrapper over [`stream_csv_records`]; the structure path uses
/// this. Note the honest memory bound: unlike a filtered streaming pass, this
/// materialises EVERY record — the `Vec<CsvRecord>` (not the file size) is
/// the memory ceiling.
pub fn parse_csv_file(path: &Path, delimiter: u8) -> TldrResult<Vec<CsvRecord>> {
    let mut records = Vec::new();
    stream_csv_records(path, delimiter, |record| records.push(record))?;
    Ok(records)
}

// =============================================================================
// State machine internals
// =============================================================================

/// Scanner states — see the module-doc transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    /// At the boundary before a field's first byte.
    FieldStart,
    /// Accumulating an unquoted field.
    Unquoted,
    /// Inside a quoted field.
    Quoted,
    /// Saw a `"` inside a quoted field: escaped quote, field close, or
    /// (lenient) content quote — the next byte decides.
    QuoteInQuoted,
}

/// Field accumulator (the field currently being assembled). Bytes are
/// accumulated RAW and decoded once at close, so multi-byte UTF-8 text
/// survives byte-level scanning.
struct Cur {
    byte_start: u64,
    line_start: u64,
    bytes: Vec<u8>,
    /// Exclusive end: one past the last byte belonging to the field.
    byte_end: u64,
    line_end: u64,
    quoted: bool,
}

impl Cur {
    fn new(byte_start: u64, line_start: u64, quoted: bool) -> Self {
        Self {
            byte_start,
            line_start,
            bytes: Vec::new(),
            byte_end: byte_start,
            line_end: line_start,
            quoted,
        }
    }

    /// Push one content byte (escape normalization happens at the call site).
    fn push(&mut self, b: u8) {
        self.bytes.push(b);
    }

    /// Freeze the accumulator into a [`CsvField`] with the given span end.
    fn close(self, byte_end: u64) -> CsvField {
        CsvField {
            text: String::from_utf8_lossy(&self.bytes).into_owned(),
            byte_start: self.byte_start,
            byte_end,
            line_start: self.line_start as u32,
            line_end: self.line_end as u32,
            quoted: self.quoted,
        }
    }
}

/// Record accumulator.
#[derive(Default)]
struct Rec {
    byte_start: Option<u64>,
    line_start: Option<u64>,
    byte_end: u64,
    line_end: u64,
    fields: Vec<CsvField>,
    has_content: bool,
}

impl Rec {
    /// Stamp the record's start on its first consumed byte (a delimiter
    /// counts — `,a` is a record whose region starts at the comma).
    fn open(&mut self, pos: u64, line_no: u64) {
        if self.byte_start.is_none() {
            self.byte_start = Some(pos);
            self.line_start = Some(line_no);
        }
        self.has_content = true;
    }

    /// Add a closed field and extend the record's span to it.
    fn push_field(&mut self, field: CsvField, end: u64) {
        self.byte_end = self.byte_end.max(end);
        self.line_end = self.line_end.max(u64::from(field.line_end));
        self.fields.push(field);
    }

    /// Consume the accumulator into a [`CsvRecord`].
    fn finish(self) -> CsvRecord {
        let line_start = self.line_start.unwrap_or(1);
        CsvRecord {
            line_start: line_start as u32,
            line_end: self.line_end.max(line_start) as u32,
            byte_start: self.byte_start.unwrap_or(0),
            byte_end: self.byte_end,
            fields: self.fields,
        }
    }
}

/// Close the current record: fold any open field in, and — when the record
/// consumed at least one content byte — emit it and count it. Blank records
/// (nothing but the terminator: empty lines and the phantom record after a
/// trailing newline) are dropped silently. Resets the state to
/// [`St::FieldStart`].
fn finish<F>(rec: &mut Rec, cur: &mut Option<Cur>, st: &mut St, emit: &mut F, total: &mut u64)
where
    F: FnMut(CsvRecord),
{
    if let Some(c) = cur.take() {
        let end = c.byte_end;
        rec.push_field(c.close(end), end);
    }
    if rec.has_content {
        let done = std::mem::take(rec);
        emit(done.finish());
        *total += 1;
    } else {
        *rec = Rec::default();
    }
    *st = St::FieldStart;
}

// =============================================================================
// Name helper (used by the structure mapping in ast::extractor)
// =============================================================================

/// The `record` definition name for a record: the first field's text
/// truncated to [`MAX_RECORD_NAME_CHARS`] characters (char-boundary safe,
/// an ellipsis appended when truncation happened), or `row-N` (1-indexed
/// source order) when that text is empty/whitespace.
///
/// The raw field text is used verbatim (a first field that itself embeds a
/// line break keeps that break in the name — the byte span stays the exact
/// addressable region regardless of how the name reads).
#[must_use]
pub fn record_name(record: &CsvRecord, row_number: u64) -> String {
    let first = record.fields.first().map(|f| f.text.as_str()).unwrap_or("");
    if first.trim().is_empty() {
        return format!("row-{row_number}");
    }
    let mut name: String = first.chars().take(MAX_RECORD_NAME_CHARS).collect();
    if name.chars().count() < first.chars().count() {
        name.push('…');
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scan an in-memory fixture through the real streaming path.
    fn scan(source: &str, delimiter: u8) -> Vec<CsvRecord> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.csv");
        std::fs::write(&path, source).unwrap();
        parse_csv_file(&path, delimiter).unwrap()
    }

    fn texts(record: &CsvRecord) -> Vec<&str> {
        record.fields.iter().map(|f| f.text.as_str()).collect()
    }

    /// The record's span must slice back to its exact source region.
    fn slice<'a>(source: &'a str, r: &CsvRecord) -> &'a str {
        &source[r.byte_start as usize..r.byte_end as usize]
    }

    #[test]
    fn is_csv_and_tsv_paths() {
        assert!(is_csv_path(Path::new("a.csv")));
        assert!(is_csv_path(Path::new("A.CSV")));
        assert!(!is_csv_path(Path::new("a.tsv")));
        assert!(is_tsv_path(Path::new("a.tsv")));
        assert!(is_tsv_path(Path::new("A.TSV")));
        assert!(!is_tsv_path(Path::new("a.csv")));
        assert!(!is_csv_path(Path::new("a.json")));
        assert_eq!(delimiter_for(Path::new("a.csv")), Some(b','));
        assert_eq!(delimiter_for(Path::new("a.tsv")), Some(b'\t'));
        assert_eq!(delimiter_for(Path::new("a.json")), None);
    }

    #[test]
    fn header_and_records_basic() {
        let src = "id,name\n1,ada\n2,grace\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 3);
        assert_eq!(texts(&recs[0]), vec!["id", "name"]);
        assert_eq!(texts(&recs[1]), vec!["1", "ada"]);
        assert_eq!(texts(&recs[2]), vec!["2", "grace"]);

        // Exact spans: one line per record, byte region = line minus its
        // terminator.
        assert_eq!((recs[0].line_start, recs[0].line_end), (1, 1));
        assert_eq!((recs[1].line_start, recs[1].line_end), (2, 2));
        assert_eq!((recs[2].line_start, recs[2].line_end), (3, 3));
        assert_eq!(slice(src, &recs[0]), "id,name");
        assert_eq!(slice(src, &recs[1]), "1,ada");
        assert_eq!(slice(src, &recs[2]), "2,grace");

        // Field-level span: field 0 of record 1 is exactly "1".
        let f = &recs[1].fields[0];
        assert_eq!(&src[f.byte_start as usize..f.byte_end as usize], "1");
        assert!(!f.quoted);
    }

    #[test]
    fn quoted_fields_may_contain_delimiters() {
        let src = "a,\"x,y\",z\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 1);
        assert_eq!(texts(&recs[0]), vec!["a", "x,y", "z"]);
        // The middle field's RAW span includes both quotes.
        let f = &recs[0].fields[1];
        assert!(f.quoted);
        assert_eq!(&src[f.byte_start as usize..f.byte_end as usize], "\"x,y\"");
        assert_eq!(slice(src, &recs[0]), "a,\"x,y\",z");
    }

    #[test]
    fn embedded_newline_record_spans_three_lines() {
        let src = "name,desc\na,\"line1\nline2\nline3\"\nb,c\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 3);
        // Record 2 spans lines 2..=4 (the quoted field embeds two breaks).
        assert_eq!((recs[1].line_start, recs[1].line_end), (2, 4));
        assert_eq!(texts(&recs[1]), vec!["a", "line1\nline2\nline3"]);
        // The record region covers all three lines exactly.
        assert_eq!(slice(src, &recs[1]), "a,\"line1\nline2\nline3\"");
        // Neighbours are unaffected.
        assert_eq!((recs[0].line_start, recs[0].line_end), (1, 1));
        assert_eq!((recs[2].line_start, recs[2].line_end), (5, 5));
        assert_eq!(texts(&recs[2]), vec!["b", "c"]);
    }

    #[test]
    fn doubled_quotes_are_escapes() {
        let src = "\"a\"\"b\",c\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 1);
        // Text: the escape collapses to one literal quote.
        assert_eq!(texts(&recs[0]), vec!["a\"b", "c"]);
        // Raw span keeps every source byte, escapes included.
        let f = &recs[0].fields[0];
        assert_eq!(
            &src[f.byte_start as usize..f.byte_end as usize],
            "\"a\"\"b\""
        );
        assert_eq!(slice(src, &recs[0]), "\"a\"\"b\",c");
    }

    #[test]
    fn crlf_terminators_are_excluded_from_spans_and_text() {
        let src = "a,b\r\nc,\"d\r\ne\"\r\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 2);
        // Record 1: plain CRLF record — span excludes the `\r\n`.
        assert_eq!(slice(src, &recs[0]), "a,b");
        assert_eq!(texts(&recs[0]), vec!["a", "b"]);
        // Record 2 embeds a CRLF inside the quoted field: the RAW span keeps
        // the `\r\n` bytes, the TEXT normalizes to `\n`.
        assert_eq!(slice(src, &recs[1]), "c,\"d\r\ne\"");
        assert_eq!(texts(&recs[1]), vec!["c", "d\ne"]);
        assert_eq!((recs[1].line_start, recs[1].line_end), (2, 3));
    }

    #[test]
    fn empty_fields_and_blank_lines() {
        // Trailing delimiter = trailing empty field; a blank line between
        // records emits nothing.
        let src = "a,,c\n\n,;\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 2);
        assert_eq!(texts(&recs[0]), vec!["a", "", "c"]);
        // The empty middle field is a zero-width span at the second comma.
        let empty = &recs[0].fields[1];
        assert_eq!(empty.byte_start, empty.byte_end);
        assert_eq!(slice(src, &recs[0]), "a,,c");
        // The second record starts at its leading delimiter.
        assert_eq!(slice(src, &recs[1]), ",;");
    }

    #[test]
    fn trailing_newline_makes_no_phantom_record() {
        assert_eq!(scan("a,b\n", b',').len(), 1);
        assert_eq!(scan("a,b", b',').len(), 1); // no trailing newline
        assert_eq!(scan("a,b\n\n\n", b',').len(), 1); // blank tail lines
        assert!(scan("", b',').is_empty());
        assert!(scan("\n\n", b',').is_empty());
    }

    #[test]
    fn tsv_uses_tab_delimiter() {
        let src = "id\tname\n1\tada\n";
        let recs = scan(src, b'\t');
        assert_eq!(recs.len(), 2);
        assert_eq!(texts(&recs[0]), vec!["id", "name"]);
        assert_eq!(texts(&recs[1]), vec!["1", "ada"]);
        // A comma is ordinary content under the TSV delimiter.
        assert_eq!(texts(&scan("a,b\tc\n", b'\t')[0]), vec!["a,b", "c"]);
    }

    #[test]
    fn lenient_quote_shapes() {
        // Leniency 1: quote inside an unquoted field is content.
        assert_eq!(texts(&scan("a\"b,c\n", b',')[0]), vec!["a\"b", "c"]);
        // Leniency 2: garbage after a closing quote folds into the text.
        assert_eq!(texts(&scan("\"a\"x,b\n", b',')[0]), vec!["a\"x", "b"]);
        // Unterminated quote: the record closes at EOF — and because the
        // never-closed field is quoted, the line break at EOF is embedded
        // CONTENT inside it (both in text and in the record's region).
        let src = "a,\"open\n";
        let recs = scan(src, b',');
        assert_eq!(recs.len(), 1);
        assert_eq!(texts(&recs[0]), vec!["a", "open\n"]);
        assert_eq!(slice(src, &recs[0]), "a,\"open\n");
    }

    #[test]
    fn utf8_bom_is_skipped() {
        let src = "\u{feff}id,name\n1,ada\n";
        let recs = scan(src, b',');
        // The BOM never enters the first field's text...
        assert_eq!(texts(&recs[0]), vec!["id", "name"]);
        // ...and the record span starts at the first real byte (BOM bytes
        // belong to no field), so slices stay content-clean.
        assert_eq!(&src[3..recs[0].byte_end as usize], "id,name");
    }

    #[test]
    fn multibyte_utf8_field_text_survives() {
        let src = "id,ville\n1,Montréal\n2,København\n";
        let recs = scan(src, b',');
        assert_eq!(texts(&recs[1]), vec!["1", "Montréal"]);
        assert_eq!(texts(&recs[2]), vec!["2", "København"]);
        assert_eq!(slice(src, &recs[1]), "1,Montréal");
    }

    #[test]
    fn thousand_row_determinism_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.csv");
        std::fs::write(&path, {
            let mut s = String::from("id,name\n");
            for i in 0..1000 {
                s.push_str(&format!("{i},\"row, {i}\"\n"));
            }
            s
        })
        .unwrap();
        let a = parse_csv_file(&path, b',').unwrap();
        let b = parse_csv_file(&path, b',').unwrap();
        assert_eq!(a.len(), 1001); // header + 1000 rows
        assert_eq!(a, b, "two scans of the same file must agree exactly");
        assert_eq!(texts(&a[0]), vec!["id", "name"]);
        assert_eq!(texts(&a[500]), vec!["499", "row, 499"]);
        assert_eq!(texts(&a[1000]), vec!["999", "row, 999"]);
        // Every record is a single line whose slice starts with its text.
        let src = std::fs::read_to_string(&path).unwrap();
        for (n, r) in a.iter().enumerate() {
            assert_eq!(r.line_start, r.line_end, "record {n} must be one line");
            assert!(
                slice(&src, r).starts_with(&a[n].fields[0].text),
                "record {n} slice must open with its first field"
            );
        }
    }

    #[test]
    fn record_name_truncates_and_falls_back() {
        let field = |text: &str| CsvField {
            text: text.to_string(),
            byte_start: 0,
            byte_end: 1,
            line_start: 1,
            line_end: 1,
            quoted: false,
        };
        let rec = |f: CsvField| CsvRecord {
            line_start: 1,
            line_end: 1,
            byte_start: 0,
            byte_end: 1,
            fields: vec![f],
        };

        let long = "x".repeat(100);
        let name = record_name(&rec(field(&long)), 7);
        assert_eq!(name.chars().count(), MAX_RECORD_NAME_CHARS + 1); // 60 + ellipsis
        assert!(name.ends_with('…'));

        assert_eq!(record_name(&rec(field("   ")), 7), "row-7");
        assert_eq!(record_name(&rec(field("")), 12), "row-12");
        assert_eq!(record_name(&rec(field("héllo")), 1), "héllo");
    }
}
