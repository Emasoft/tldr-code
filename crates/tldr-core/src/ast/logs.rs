//! Native log-entry extraction (log batch — `Language::Log`).
//!
//! No maintained tree-sitter grammar for logs is published on crates.io
//! (audited: nothing suitable exists — the same crates.io-audit precedent
//! that killed tree-sitter-sql), so `.log` files are NEVER parsed through
//! tree-sitter. This module is the only consumer of log content: a
//! deterministic, streaming **entry scanner** that walks the file
//! line-by-line and groups lines into entries.
//!
//! # Streaming / memory model
//!
//! A `BufReader` holds **one physical line at a time** (1 MB buffer, the
//! `ast::jsonl` streaming precedent — a `.log` may be GiB-scale), plus the
//! text of the entry currently being assembled. Nothing proportional to the
//! file size is ever held in RAM while scanning. Byte offsets are tracked
//! manually as the running sum of physical line lengths (including the
//! terminating `\n`), so `byte_start`/`byte_end` stay exact even with CRLF
//! line endings: the trailing `\r` of a `\r\n` pair is EXCLUDED from the
//! entry's content span (and from its text) but the cursor still advances
//! over it. `source[byte_start..byte_end]` is the entry's exact byte region —
//! its first content byte through the last content byte of its last line; a
//! line terminator INTERIOR to the region (between the entry's own lines)
//! is part of the file bytes and remains in the span, while the trailing
//! terminator of the last line is excluded. The text handed to the callback
//! is that region with every line terminator (and CRLF `\r`) removed.
//!
//! Because streaming is the point, the primary API is
//! [`stream_log_entries`], which hands each completed entry (with its text)
//! to a callback; [`parse_log_file`] is the collect-everything convenience
//! wrapper used by `tldr structure`. The CLI `tldr logs` command filters
//! inside the callback, so a GiB log with a narrow `--from/--to` window
//! never materialises the unmatched entries.
//!
//! # Entry heuristics (the format contract, documented because it IS the spec)
//!
//! A line **starts a new entry** when (after trimming leading whitespace) it
//! begins with a recognized timestamp or a recognized level token:
//!
//! | Shape                    | Example                        | Notes |
//! |--------------------------|--------------------------------|-------|
//! | ISO-8601 / RFC3339       | `2026-09-14T08:34:49Z`         | `T`/`t` separator; optional fractional secs (`.`/`,`) and zone (`Z`, `±HH:MM`, `±HHMM`, `±HH`) |
//! | space-separated datetime | `2026-09-14 08:34:49,123`      | one-or-more spaces after the date; seconds optional; fraction/zone optional |
//! | syslog                   | `Sep 14 08:34:49`              | 3-letter English month abbreviation (case-insensitive); day may be space-padded; NO year → interval-unfilterable |
//! | bracketed common-log     | `[14/Sep/2026:08:34:49 +0200]` | Apache/CLF; timestamp text captured WITHOUT the brackets; includes the year |
//! | epoch                    | `1726298089` / `1726298089123` | exactly 10 (seconds) or 13 (millis) digits followed by whitespace or end-of-line |
//! | level token              | `ERROR:` / `WARN - msg` / `[error]` | a level word at line start followed by `:` or ` -`, or `[level]`; a bare level word followed by only a space is deliberately NOT an entry start ("Error handling request…" prose must not split) |
//!
//! Timestamp detection is tried FIRST, so a timestamp-led line always wins
//! even when the rest of the line also contains level words.
//!
//! **Levels** (word-boundary, case-insensitive) normalize to:
//!
//! | Words                                                    | Normalized |
//! |----------------------------------------------------------|------------|
//! | `fatal` `critical` `emerg` `alert` `panic` `error` `err` | `"error"`  |
//! | `warn` `warning`                                          | `"warn"`   |
//! | `info` `notice` `information`                             | `"info"`   |
//! | `debug` `trace` `fine` `finer` `finest`                   | `"debug"`  |
//!
//! On a timestamp-led entry the level is looked up in the remainder of the
//! start line (first word-boundary match wins); on a level-led entry the
//! leading token IS the level. The entry's `name` downstream (`tldr
//! structure`) is the normalized level, or `"entry"` when no level was
//! found (level-less timestamped lines and leading garbage alike).
//!
//! **Continuation lines** (no new-entry marker — stack traces, indented
//! dumps, wrapped messages) attach to the current entry: the entry's
//! `line_end`/`byte_end` extend to the continuation's last content byte.
//! Leading garbage before the first timestamp forms ONE `"entry"` (all its
//! lines are continuations of the first garbage line). Blank lines are
//! neutral: they neither split nor extend an entry (trailing blank lines at
//! EOF therefore don't inflate the last entry's span).

use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::TldrResult;

/// Streaming buffer size (1 MB — the `ast::jsonl` precedent).
const STREAM_BUFFER: usize = 1024 * 1024;

/// One parsed log entry: a contiguous run of source lines that belongs
/// together (one event plus its stack trace / continuation lines).
///
/// This struct is deliberately NOT [`crate::types::DefinitionInfo`] — log
/// entries are not code definitions; the mapping to `DefinitionInfo`
/// (kind `"entry"`) lives in the `get_code_structure` hook. Field order
/// matches the `tldr logs` JSON row schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// First line of the entry (1-indexed).
    pub line_start: u32,
    /// Last line of the entry (1-indexed, inclusive).
    pub line_end: u32,
    /// Byte offset of the entry's FIRST byte in the file (0-indexed).
    pub byte_start: u64,
    /// Byte offset ONE PAST the entry's last content byte (exclusive end,
    /// 0-indexed). The trailing line terminator (`\r\n` / `\n`) of the
    /// entry's last line is excluded; line terminators INTERIOR to the
    /// entry (between its own lines) are part of the file bytes inside the
    /// span — see the module docs for the CRLF handling.
    pub byte_end: u64,
    /// Normalized severity level (`error`/`warn`/`info`/`debug`), when a
    /// level token was recognized on the entry's start line.
    pub level: Option<String>,
    /// The raw timestamp text as it appeared on the start line (e.g.
    /// `2026-09-14T08:34:49Z`, `Sep 14 08:34:49`, `14/Sep/2026:08:34:49
    /// +0200` without the brackets), when a timestamp was recognized.
    pub timestamp: Option<String>,
}

/// Why a line starts a new entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryStart {
    /// Line began with a recognized timestamp (raw text captured).
    Timestamp(String),
    /// Line began with a bare level token (already normalized).
    Level(&'static str),
}

/// Accumulator for the entry currently being assembled.
struct CurrentEntry {
    start_line: u64,
    end_line: u64,
    byte_start: u64,
    byte_end: u64,
    level: Option<&'static str>,
    timestamp: Option<String>,
    text: String,
}

impl CurrentEntry {
    fn new(
        line_no: u64,
        byte_start: u64,
        byte_end: u64,
        level: Option<&'static str>,
        timestamp: Option<String>,
        text: &str,
    ) -> Self {
        Self {
            start_line: line_no,
            end_line: line_no,
            byte_start,
            byte_end,
            level,
            timestamp,
            text: text.to_string(),
        }
    }

    /// Continuation: extend the entry's region to another content line.
    fn extend(&mut self, line_no: u64, content_byte_end: u64, content: &str) {
        self.end_line = line_no;
        self.byte_end = content_byte_end;
        self.text.push('\n');
        self.text.push_str(content);
    }

    /// Consume the accumulator into `(entry, entry_text)`.
    fn finish(self) -> (LogEntry, String) {
        let CurrentEntry {
            start_line,
            end_line,
            byte_start,
            byte_end,
            level,
            timestamp,
            text,
        } = self;
        (
            LogEntry {
                line_start: start_line as u32,
                line_end: end_line as u32,
                byte_start,
                byte_end,
                level: level.map(str::to_string),
                timestamp,
            },
            text,
        )
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Check whether `path` looks like a log file (`.log` extension,
/// case-insensitive).
#[must_use]
pub fn is_log_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

/// Stream `path` line-by-line, grouping lines into log entries, and hand
/// each completed entry to `emit` together with its source text (line
/// terminators stripped — see the module docs).
///
/// Returns the TOTAL number of entries scanned (not the number `emit`
/// accepted) — the CLI uses this as `total_entries` while filtering inside
/// the callback, so a filtered pass never holds all entries in memory.
///
/// Memory is bounded by the longest single line plus the longest entry (one
/// entry's text in RAM at a time), never by the file size.
pub fn stream_log_entries<F>(path: &Path, mut emit: F) -> TldrResult<u64>
where
    F: FnMut(LogEntry, &str),
{
    let file = std::fs::File::open(path).map_err(crate::error::TldrError::IoError)?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER, file);

    let mut total: u64 = 0;
    // Running byte offset = sum of physical line lengths incl. `\n`.
    let mut offset: u64 = 0;
    let mut line_no: u64 = 0;
    let mut current: Option<CurrentEntry> = None;

    // Reusable read buffer (one physical line at a time — the
    // bounded-memory guarantee; a pathological single 100 MB line costs
    // 100 MB here, the same trade-off as the jsonl row reader).
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

        // Content = physical line minus `\n`, minus a trailing `\r` (CRLF).
        // The `\r` is excluded from content AND from byte_end, but the
        // cursor below advances over the full physical line, so offsets
        // stay exact either way.
        let mut content_len = buf.len();
        if content_len > 0 && buf[content_len - 1] == b'\n' {
            content_len -= 1;
        }
        if content_len > 0 && buf[content_len - 1] == b'\r' {
            content_len -= 1;
        }
        // Lossy decode: logs routinely carry non-UTF-8 bytes from
        // mixed-encoding writers; the heuristics only need ASCII shapes.
        let view = String::from_utf8_lossy(&buf[..content_len]);

        let line_byte_start = offset;
        let content_byte_end = line_byte_start + content_len as u64;
        // Advance over the FULL physical line (terminators included).
        offset += n as u64;

        let trimmed = view.trim();
        if trimmed.is_empty() {
            // Blank lines are neutral: no split, no extension.
            continue;
        }

        match classify_line_start(trimmed) {
            Some(EntryStart::Timestamp(ts)) => {
                if let Some(done) = current.take() {
                    let (entry, text) = done.finish();
                    emit(entry, &text);
                    total += 1;
                }
                // Level lookup in the remainder of the start line.
                let level = find_level_word(trimmed).map(|(l, _, _)| l);
                current = Some(CurrentEntry::new(
                    line_no,
                    line_byte_start,
                    content_byte_end,
                    level,
                    Some(ts),
                    &view,
                ));
            }
            Some(EntryStart::Level(level)) => {
                if let Some(done) = current.take() {
                    let (entry, text) = done.finish();
                    emit(entry, &text);
                    total += 1;
                }
                current = Some(CurrentEntry::new(
                    line_no,
                    line_byte_start,
                    content_byte_end,
                    Some(level),
                    None,
                    &view,
                ));
            }
            None => {
                if let Some(cur) = current.as_mut() {
                    // Continuation: extend the current entry's region.
                    cur.extend(line_no, content_byte_end, &view);
                } else {
                    // Leading garbage before the first timestamp: becomes
                    // ONE "entry" (subsequent non-marker lines attach).
                    current = Some(CurrentEntry::new(
                        line_no,
                        line_byte_start,
                        content_byte_end,
                        None,
                        None,
                        &view,
                    ));
                }
            }
        }
    }
    // EOF: flush the final entry.
    if let Some(done) = current.take() {
        let (entry, text) = done.finish();
        emit(entry, &text);
        total += 1;
    }

    Ok(total)
}

/// Parse a log file into all of its entries (source order — deterministic).
///
/// Convenience wrapper over [`stream_log_entries`]; `tldr structure` uses
/// this path. Note the honest memory bound: unlike the streaming CLI
/// command, this materialises EVERY entry — the `Vec<LogEntry>` (not the
/// file size) is the memory ceiling on the structure path.
pub fn parse_log_file(path: &Path) -> TldrResult<Vec<LogEntry>> {
    let mut entries = Vec::new();
    stream_log_entries(path, |entry, _| entries.push(entry))?;
    Ok(entries)
}

// =============================================================================
// Line-start classification
// =============================================================================

/// Classify a trimmed line: does it START a new log entry?
///
/// Timestamps are tried first (a timestamp-led line always wins), then the
/// level-token shapes. See the module docs for the full heuristic table.
fn classify_line_start(line: &str) -> Option<EntryStart> {
    if let Some(ts) = match_timestamp_prefix(line) {
        return Some(EntryStart::Timestamp(ts));
    }
    if let Some(level) = match_leading_level_token(line) {
        return Some(EntryStart::Level(level));
    }
    None
}

/// Try the four timestamp shapes at the start of `line`; returns the raw
/// timestamp text (bracketed common-log captured WITHOUT the brackets).
fn match_timestamp_prefix(line: &str) -> Option<String> {
    let b = line.as_bytes();

    // 1. ISO-8601 / RFC3339 / space-separated datetime: `YYYY-MM-DD`.
    if b.len() >= 10
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        let mut end = 10usize;
        // Separator: 'T'/'t' or 1+ spaces, then at least `HH:MM`.
        if end < b.len() && (b[end] == b'T' || b[end] == b't') {
            end += 1;
        } else {
            let spaces = count_spaces(b, end);
            if spaces == 0 {
                return None; // bare date, no time → not an entry start
            }
            end += spaces;
        }
        // HH:MM (seconds optional).
        if b.len() < end + 5
            || !b[end..end + 2].iter().all(u8::is_ascii_digit)
            || b[end + 2] != b':'
            || !b[end + 3..end + 5].iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        end += 5;
        // Optional `:SS` — needs exactly 3 more bytes (`:` + 2 digits), so
        // a line ending right at the seconds must still match (>=, not >).
        if b.len() >= end + 3
            && b[end] == b':'
            && b[end + 1..end + 3].iter().all(u8::is_ascii_digit)
        {
            end += 3;
            // Optional fraction: `.`/`,` + digits.
            if end < b.len() && (b[end] == b'.' || b[end] == b',') {
                let frac = count_digits(b, end + 1);
                if frac > 0 {
                    end += 1 + frac;
                }
            }
        }
        // Optional zone: Z | ±HH:MM | ±HHMM | ±HH
        end += skip_zone(b, end);
        return Some(line[..end].to_string());
    }

    // 2. Bracketed common-log: `[DD/Mon/YYYY:HH:MM:SS( ±HHMM)?]`.
    if b.first() == Some(&b'[') {
        let mut i = 1usize;
        let day = count_digits(b, i);
        if (1..=2).contains(&day) {
            i += day;
            if i < b.len() && b[i] == b'/' {
                i += 1;
                let mon = count_alpha(b, i);
                if mon == 3 {
                    i += 3;
                    if i < b.len() && b[i] == b'/' {
                        i += 1;
                        let year = count_digits(b, i);
                        if year == 4 {
                            i += 4;
                            // `:HH:MM:SS` — needs exactly 9 more bytes, so
                            // a line ending right at the seconds matches.
                            if b.len() >= i + 9
                                && b[i] == b':'
                                && b[i + 1..i + 3].iter().all(u8::is_ascii_digit)
                                && b[i + 3] == b':'
                                && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
                                && b[i + 6] == b':'
                                && b[i + 7..i + 9].iter().all(u8::is_ascii_digit)
                            {
                                i += 9;
                                // Optional ` ±HHMM`.
                                if i < b.len()
                                    && b[i] == b' '
                                    && b.len() > i + 6
                                    && (b[i + 1] == b'+' || b[i + 1] == b'-')
                                    && b[i + 2..i + 4].iter().all(u8::is_ascii_digit)
                                    && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
                                {
                                    i += 6;
                                }
                                return Some(line[1..i].to_string());
                            }
                        }
                    }
                }
            }
        }
        // Not a common-log timestamp: fall through (may be `[error]` etc.).
    }

    // 3. Syslog: `Mon DD HH:MM:SS` (case-insensitive month, space-padded day).
    let mon = count_alpha(b, 0);
    if mon == 3 {
        let month = &line[..3];
        if month_index(month).is_some() {
            let mut i = 3usize;
            let spaces = count_spaces(b, i);
            if spaces > 0 {
                i += spaces;
                let day = count_digits(b, i);
                if (1..=2).contains(&day) {
                    i += day;
                    let spaces2 = count_spaces(b, i);
                    if spaces2 > 0 {
                        i += spaces2;
                        // `HH:MM:SS` — needs exactly 8 more bytes, so a
                        // line ending right at the seconds matches.
                        if b.len() >= i + 8
                            && b[i..i + 2].iter().all(u8::is_ascii_digit)
                            && b[i + 2] == b':'
                            && b[i + 3..i + 5].iter().all(u8::is_ascii_digit)
                            && b[i + 5] == b':'
                            && b[i + 6..i + 8].iter().all(u8::is_ascii_digit)
                        {
                            return Some(line[..i + 8].to_string());
                        }
                    }
                }
            }
        }
    }

    // 4. Epoch: exactly 10 (seconds) or 13 (millis) digits, then a
    // non-digit (whitespace or end-of-line).
    let digits = count_digits(b, 0);
    if digits == 10 || digits == 13 {
        let next = b.get(digits);
        match next {
            None => return Some(line[..digits].to_string()),
            Some(c) if c.is_ascii_whitespace() => return Some(line[..digits].to_string()),
            _ => {}
        }
    }

    None
}

/// Try the level-token shapes at the start of `line`:
/// `[level]`, or a level word followed by `:` or ` -`.
/// Returns the NORMALIZED level.
fn match_leading_level_token(line: &str) -> Option<&'static str> {
    let b = line.as_bytes();

    // `[level]` — bracketed common-log timestamps were already matched by
    // `match_timestamp_prefix` (it runs first), so a `[` here can only be
    // a level tag or something unrecognized.
    if b.first() == Some(&b'[') {
        if let Some((level, wlen)) = match_level_at(&b[1..]) {
            if b.get(1 + wlen) == Some(&b']') {
                return Some(level);
            }
        }
        return None;
    }

    // Bare level word at position 0 + separator (`:` or whitespace + `-`).
    if let Some((level, wlen)) = match_level_at(b) {
        match b.get(wlen) {
            Some(b':') => return Some(level),
            Some(c) if c.is_ascii_whitespace() => {
                let mut j = wlen;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if b.get(j) == Some(&b'-') {
                    return Some(level);
                }
                // Space-only separator: deliberately NOT an entry start
                // ("Error handling request…" prose must not split).
            }
            _ => {}
        }
    }
    None
}

/// Scan `line` left-to-right for the first level word at a word boundary.
/// Returns `(normalized_level, position, word_len)`.
fn find_level_word(line: &str) -> Option<(&'static str, usize, usize)> {
    let b = line.as_bytes();
    for i in 0..b.len() {
        // Word start: beginning of line or previous char not alphanumeric.
        if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] >= 0x80) {
            continue;
        }
        if let Some((level, len)) = match_level_at(&b[i..]) {
            // Word end: next char must not continue the word.
            let after = i + len;
            let boundary = match b.get(after) {
                None => true,
                Some(c) => !(c.is_ascii_alphanumeric() || *c >= 0x80),
            };
            if boundary {
                return Some((level, i, len));
            }
        }
    }
    None
}

/// Case-insensitively match a level word at the START of `bytes`.
/// Returns `(normalized, word_len)`. Ordered longest-first so overlapping
/// prefixes resolve deterministically (`warning` before `warn`).
fn match_level_at(bytes: &[u8]) -> Option<(&'static str, usize)> {
    const WORDS: &[(&str, &str)] = &[
        // (word, normalized) — longest first so overlapping prefixes pick
        // the longest candidate at the same position.
        ("information", "info"),
        ("critical", "error"),
        ("warning", "warn"),
        ("notice", "info"),
        ("finest", "debug"),
        ("debug", "debug"),
        ("trace", "debug"),
        ("alert", "error"),
        ("panic", "error"),
        ("emerg", "error"),
        ("error", "error"),
        ("fatal", "error"),
        ("finer", "debug"),
        ("warn", "warn"),
        ("info", "info"),
        ("fine", "debug"),
        ("err", "error"),
    ];
    for (word, norm) in WORDS {
        let wb = word.as_bytes();
        if bytes.len() >= wb.len()
            && bytes[..wb.len()]
                .iter()
                .zip(wb.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some((norm, wb.len()));
        }
    }
    None
}

/// Normalize a level token (case-insensitive) to its canonical form.
/// `None` when the token is not a recognized level word (whole-token
/// match only: `"warning"` matches, `"warningly"` does not).
#[must_use]
pub fn normalize_level_token(word: &str) -> Option<&'static str> {
    match_level_at(word.as_bytes())
        .filter(|(_, len)| word.len() == *len)
        .map(|(norm, _)| norm)
}

// =============================================================================
// Timestamp normalization (interval filtering)
// =============================================================================

/// A comparable instant: `(epoch_seconds, nanoseconds)` — UTC-normalized.
/// Compared lexicographically; inclusive `--from`/`--to` bounds compare
/// against this tuple.
pub type TimestampInstant = (i64, u32);

/// Month-abbreviation index (0-based, `Jan` = 0).
fn month_index(m: &str) -> Option<usize> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    MONTHS.iter().position(|name| name.eq_ignore_ascii_case(m))
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's
/// `days_from_civil` — std-free; no new dependency is pulled for this).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Normalize a recognized timestamp string to a comparable UTC instant.
///
/// - ISO-8601 / RFC3339 and space-separated datetimes: full support
///   (fraction, `Z`, `±HH:MM`/`±HHMM`/`±HH` offsets; a missing zone is
///   treated as UTC — documented judgment call for naive timestamps).
/// - Bracketed common-log (`DD/Mon/YYYY:HH:MM:SS ±HHMM`, brackets
///   optional): full support — it carries the year.
/// - Epoch digits: 10 = seconds, 13 = milliseconds.
/// - **Syslog (`Mon DD HH:MM:SS`): `None`** — there is no year, so any
///   inferred year would be a guess. Callers doing interval filtering must
///   count these entries as `unfilterable` instead of guessing.
pub fn normalize_timestamp(ts: &str) -> Option<TimestampInstant> {
    let s = ts.trim();
    let s = s.strip_prefix('[').unwrap_or(s);
    let s = s.strip_suffix(']').unwrap_or(s);
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }

    // Pure digits → epoch (10 = seconds, 13 = millis).
    if b.iter().all(u8::is_ascii_digit) {
        return match b.len() {
            10 => Some((s.parse::<i64>().ok()?, 0)),
            13 => {
                let ms = s.parse::<i64>().ok()?;
                Some((ms / 1000, (ms % 1000) as u32 * 1_000_000))
            }
            _ => None,
        };
    }

    // `YYYY-MM-DD...` → ISO / space-separated datetime.
    if b.len() >= 10
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        let year: i64 = s[..4].parse().ok()?;
        let month: u32 = s[5..7].parse().ok()?;
        let day: u32 = s[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        let mut i = 10usize;
        if i >= b.len() {
            return None;
        }
        // Separator (T/t/space) must be present.
        if b[i] == b'T' || b[i] == b't' || b[i].is_ascii_whitespace() {
            i += 1;
        } else {
            return None;
        }
        let (hour, minute, second, frac_nanos, next) = parse_hms_frac(s, i)?;
        let offset_secs = parse_zone(s, next);
        let days = days_from_civil(year, month, day);
        let secs =
            days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64 - offset_secs;
        return Some((secs, frac_nanos));
    }

    // `DD/Mon/YYYY:HH:MM:SS( ±HHMM)?` — bracketed common-log (has a year).
    let slash = b.iter().position(|c| *c == b'/')?;
    let day = s[..slash].parse::<u32>().ok()?;
    if day == 0 || day > 31 {
        return None;
    }
    let rest = &s[slash + 1..];
    if rest.len() < 4 {
        return None;
    }
    let month = month_index(&rest[..3])? as u32 + 1;
    let rest = rest[3..].strip_prefix('/')?;
    if rest.len() < 4 {
        return None;
    }
    let year: i64 = rest[..4].parse().ok()?;
    let rest = rest[4..].strip_prefix(':')?;
    let (hour, minute, second, frac_nanos, next) = parse_hms_frac(rest, 0)?;
    let offset_secs = parse_zone(rest, next);
    let days = days_from_civil(year, month, day);
    let secs =
        days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64 - offset_secs;
    Some((secs, frac_nanos))
    // NOTE: the syslog shape (`Mon DD HH:MM:SS`) intentionally falls
    // through to `None` — no year, no guesswork.
}

/// Interval-bound parser for the CLI's `--from`/`--to`: everything
/// [`normalize_timestamp`] accepts PLUS a bare date (`YYYY-MM-DD`), which
/// is interpreted as midnight UTC — `--from 2026-09-14` means "from the
/// start of that day".
#[must_use]
pub fn parse_interval_bound(s: &str) -> Option<TimestampInstant> {
    if let Some(inst) = normalize_timestamp(s) {
        return Some(inst);
    }
    // Bare-date fallback.
    let b = s.trim().as_bytes();
    if b.len() == 10
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        let year: i64 = s[..4].parse().ok()?;
        let month: u32 = s[5..7].parse().ok()?;
        let day: u32 = s[8..10].parse().ok()?;
        if (1..=12).contains(&month) && (1..=31).contains(&day) {
            let days = days_from_civil(year, month, day);
            return Some((days * 86_400, 0));
        }
    }
    None
}

/// Parse `HH:MM(:SS(.frac)?)?` starting at byte `i` of `s`.
/// Returns `(hour, minute, second, frac_nanos, next_index)`.
#[allow(clippy::type_complexity)]
fn parse_hms_frac(s: &str, i: usize) -> Option<(u32, u32, u32, u32, usize)> {
    let b = s.as_bytes();
    if b.len() < i + 5
        || !b[i..i + 2].iter().all(u8::is_ascii_digit)
        || b[i + 2] != b':'
        || !b[i + 3..i + 5].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let hour: u32 = s[i..i + 2].parse().ok()?;
    let minute: u32 = s[i + 3..i + 5].parse().ok()?;
    let mut next = i + 5;
    let mut second: u32 = 0;
    let mut frac_nanos: u32 = 0;
    // `:SS` needs exactly 3 more bytes — a timestamp ending right at the
    // seconds must still match (>=, not >).
    if b.len() >= next + 3
        && b[next] == b':'
        && b[next + 1..next + 3].iter().all(u8::is_ascii_digit)
    {
        second = s[next + 1..next + 3].parse().ok()?;
        next += 3;
        if second > 60 {
            return None;
        }
        if next < b.len() && (b[next] == b'.' || b[next] == b',') {
            let digits = count_digits(b, next + 1);
            if digits > 0 {
                let frac_end = (next + 1 + digits).min(s.len());
                // First 9 fraction digits → nanoseconds (pad right, drop
                // anything finer).
                let mut nanos = String::with_capacity(9);
                for c in s[next + 1..frac_end].chars().take(9) {
                    nanos.push(c);
                }
                while nanos.len() < 9 {
                    nanos.push('0');
                }
                frac_nanos = nanos.parse().unwrap_or(0);
                next += 1 + digits;
            }
        }
    }
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute, second, frac_nanos, next))
}

/// Parse an optional UTC-offset suffix starting at byte `i`:
/// `Z`/`z`, `±HH:MM`, `±HHMM`, or `±HH`. Returns the offset in seconds
/// EAST of UTC (0 when absent — naive timestamps are treated as UTC).
fn parse_zone(s: &str, i: usize) -> i64 {
    let b = s.as_bytes();
    if i >= b.len() {
        return 0;
    }
    match b[i] {
        b'Z' | b'z' => 0,
        b'+' | b'-' => {
            let sign = if b[i] == b'-' { -1 } else { 1 };
            let rest = &s[i + 1..];
            let rb = rest.as_bytes();
            let digits = count_digits(rb, 0);
            let (h, m) = match digits {
                4 => (&rest[..2], Some(&rest[2..4])),
                2 => {
                    // `HH` or `HH:MM`
                    if rb.len() > 3 && rb[2] == b':' && count_digits(rb, 3) == 2 {
                        (&rest[..2], Some(&rest[3..5]))
                    } else {
                        (&rest[..2], None)
                    }
                }
                _ => return 0,
            };
            let hours: i64 = h.parse().unwrap_or(0);
            let minutes: i64 = m.and_then(|x| x.parse().ok()).unwrap_or(0);
            sign * (hours * 3600 + minutes * 60)
        }
        _ => 0,
    }
}

// =============================================================================
// Small byte-scan helpers
// =============================================================================

fn count_digits(b: &[u8], from: usize) -> usize {
    let mut n = 0;
    while from + n < b.len() && b[from + n].is_ascii_digit() {
        n += 1;
    }
    n
}

fn count_alpha(b: &[u8], from: usize) -> usize {
    let mut n = 0;
    while from + n < b.len() && b[from + n].is_ascii_alphabetic() {
        n += 1;
    }
    n
}

fn count_spaces(b: &[u8], from: usize) -> usize {
    let mut n = 0;
    while from + n < b.len() && (b[from + n] == b' ' || b[from + n] == b'\t') {
        n += 1;
    }
    n
}

/// Skip an optional zone suffix at `i`; returns how many bytes it occupied.
fn skip_zone(b: &[u8], i: usize) -> usize {
    if i >= b.len() {
        return 0;
    }
    match b[i] {
        b'Z' | b'z' => 1,
        b'+' | b'-' => {
            let digits = count_digits(b, i + 1);
            match digits {
                4 => 5,
                2 => {
                    // `HH` or `HH:MM`
                    if b.len() > i + 3 && b[i + 3] == b':' && count_digits(b, i + 4) == 2 {
                        6
                    } else {
                        3
                    }
                }
                _ => 0,
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(content: &str) -> Vec<LogEntry> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.log");
        std::fs::write(&path, content).expect("write fixture");
        parse_log_file(&path).expect("scan")
    }

    fn scan_text(content: &str) -> Vec<(LogEntry, String)> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.log");
        std::fs::write(&path, content).expect("write fixture");
        let mut out: Vec<(LogEntry, String)> = Vec::new();
        stream_log_entries(&path, |e, t| out.push((e, t.to_string()))).expect("stream");
        out
    }

    // -------------------------------------------------------------------
    // Timestamp formats
    // -------------------------------------------------------------------

    #[test]
    fn iso_rfc3339_zulu_starts_entry() {
        let entries = scan("2026-09-14T08:34:49Z ERROR boot failed\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("2026-09-14T08:34:49Z")
        );
        assert_eq!(entries[0].level.as_deref(), Some("error"));
        assert_eq!(entries[0].line_start, 1);
        assert_eq!(entries[0].line_end, 1);
    }

    #[test]
    fn iso_with_offset_and_fraction() {
        let entries = scan("2026-09-14T08:34:49.123+02:00 WARN slow query\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("2026-09-14T08:34:49.123+02:00")
        );
        assert_eq!(entries[0].level.as_deref(), Some("warn"));
    }

    #[test]
    fn space_separated_datetime_with_comma_millis() {
        let entries = scan("2026-09-14 08:34:49,123 [main] INFO starting\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("2026-09-14 08:34:49,123")
        );
        assert_eq!(entries[0].level.as_deref(), Some("info"));
    }

    #[test]
    fn syslog_without_year_starts_entry() {
        let entries = scan("Sep 14 08:34:49 myhost sshd[4242]: Accepted publickey\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp.as_deref(), Some("Sep 14 08:34:49"));
        // No level word on the line.
        assert_eq!(entries[0].level, None);
        // Year-less → interval-unfilterable.
        assert_eq!(normalize_timestamp("Sep 14 08:34:49"), None);
    }

    #[test]
    fn syslog_space_padded_day() {
        let entries = scan("Sep  9 03:00:01 host cron[1]: job ran\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp.as_deref(), Some("Sep  9 03:00:01"));
    }

    #[test]
    fn timestamps_ending_exactly_at_seconds_are_captured() {
        // Regression: the `:SS` length checks were off-by-one, so a line
        // ending right at the seconds lost them ("08:34" instead of
        // "08:34:49") in both detection and normalization.
        let entries = scan("2026-09-14 08:34:49\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp.as_deref(), Some("2026-09-14 08:34:49"));
        assert!(normalize_timestamp("2026-09-14 08:34:49").is_some());

        let entries = scan("[14/Sep/2026:08:34:49]\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("14/Sep/2026:08:34:49")
        );

        let entries = scan("Sep 14 08:34:49\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp.as_deref(), Some("Sep 14 08:34:49"));
    }

    #[test]
    fn bracketed_common_log_starts_entry_without_brackets_in_ts() {
        let line = r#"[14/Sep/2026:08:34:49 +0200] "GET / HTTP/1.1" 200 512"#;
        let entries = scan(&format!("{line}\n"));
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("14/Sep/2026:08:34:49 +0200")
        );
        // Bracketed lines have a year → normalizable.
        assert!(normalize_timestamp("14/Sep/2026:08:34:49 +0200").is_some());
    }

    #[test]
    fn epoch_seconds_and_millis_start_entries() {
        let entries = scan("1726298089 first\n1726298089123 second\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].timestamp.as_deref(), Some("1726298089"));
        assert_eq!(entries[1].timestamp.as_deref(), Some("1726298089123"));
        assert!(normalize_timestamp("1726298089").is_some());
        assert!(normalize_timestamp("1726298089123").is_some());
        // 11 digits is NOT an epoch entry start.
        let entries = scan("17262980891 middle\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp, None);
    }

    // -------------------------------------------------------------------
    // Level map
    // -------------------------------------------------------------------

    #[test]
    fn level_words_normalize_to_four_levels() {
        for (word, expected) in [
            ("fatal", "error"),
            ("critical", "error"),
            ("emerg", "error"),
            ("alert", "error"),
            ("panic", "error"),
            ("error", "error"),
            ("err", "error"),
            ("warn", "warn"),
            ("warning", "warn"),
            ("info", "info"),
            ("notice", "info"),
            ("information", "info"),
            ("debug", "debug"),
            ("trace", "debug"),
            ("fine", "debug"),
            ("finer", "debug"),
            ("finest", "debug"),
        ] {
            assert_eq!(
                normalize_level_token(word),
                Some(expected),
                "level word {word}"
            );
            // Case-insensitive.
            assert_eq!(
                normalize_level_token(&word.to_uppercase()),
                Some(expected),
                "level word UPPER {word}"
            );
        }
        assert_eq!(normalize_level_token("verbose"), None);
        // Whole-token match only.
        assert_eq!(normalize_level_token("warningly"), None);
        assert_eq!(normalize_level_token("errors"), None);
    }

    #[test]
    fn level_led_entries_via_colon_dash_and_bracket() {
        let entries = scan("ERROR: disk full\nWARN - retrying\n[debug] entering loop\n");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].level.as_deref(), Some("error"));
        assert_eq!(entries[0].timestamp, None);
        assert_eq!(entries[1].level.as_deref(), Some("warn"));
        assert_eq!(entries[2].level.as_deref(), Some("debug"));
    }

    #[test]
    fn bare_level_word_without_strict_separator_is_not_an_entry_start() {
        // "Error handling request…" is prose, not a level-led log entry: it
        // does NOT start a level entry (level None) — but being non-blank
        // garbage it still forms one "entry" per the leading-garbage rule.
        let entries = scan("Error handling request took 5ms\nERROR: real entry\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].level, None);
        assert_eq!(entries[0].timestamp, None);
        assert_eq!(entries[0].line_start, 1);
        // The strict-separator line starts a LEVEL entry.
        assert_eq!(entries[1].level.as_deref(), Some("error"));
        assert_eq!(entries[1].line_start, 2);
    }

    // -------------------------------------------------------------------
    // Continuations, garbage, blanks
    // -------------------------------------------------------------------

    #[test]
    fn stack_trace_lines_attach_to_entry() {
        let content = "\
2026-09-14T08:34:49Z ERROR query failed
Traceback (most recent call last):
  File \"db.py\", line 42, in query
    return conn.execute(sql)
ConnectionError: timeout
2026-09-14T08:35:00Z INFO recovered
";
        let entries = scan(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line_start, 1);
        assert_eq!(entries[0].line_end, 5);
        assert_eq!(entries[1].line_start, 6);
        assert_eq!(entries[1].line_end, 6);
    }

    #[test]
    fn leading_garbage_forms_single_entry() {
        let content = "\
random preamble line one
random preamble line two
2026-09-14T08:34:49Z INFO first real entry
";
        let entries = scan(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line_start, 1);
        assert_eq!(entries[0].line_end, 2);
        assert_eq!(entries[0].level, None);
        assert_eq!(entries[0].timestamp, None);
        assert_eq!(entries[1].line_start, 3);
    }

    #[test]
    fn blank_lines_are_neutral() {
        let content = "\
2026-09-14T08:34:49Z INFO one

2026-09-14T08:35:00Z INFO two

";
        let entries = scan(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line_end, 1); // blank line does not extend
        assert_eq!(entries[1].line_end, 3); // trailing blank does not extend
    }

    #[test]
    fn empty_and_blank_files_produce_no_entries() {
        assert!(scan("").is_empty());
        assert!(scan("\n\n  \n").is_empty());
    }

    #[test]
    fn byte_offsets_are_exact_for_crlf() {
        let content =
            "2026-09-14T08:34:49Z INFO one\r\ncontinuation\r\n2026-09-14T08:35:00Z INFO two\r\n";
        let out = scan_text(content);
        assert_eq!(out.len(), 2);

        let (e0, t0) = &out[0];
        assert_eq!(e0.line_start, 1);
        assert_eq!(e0.line_end, 2);
        // The span is the EXACT byte region: first content byte through the
        // last content byte of line 2. The trailing \r\n of line 2 is
        // excluded, but the INTERIOR \r\n between the entry's own lines is
        // part of the file bytes inside the span; the emitted text strips it.
        assert_eq!(
            &content[e0.byte_start as usize..e0.byte_end as usize],
            "2026-09-14T08:34:49Z INFO one\r\ncontinuation"
        );
        assert_eq!(t0, "2026-09-14T08:34:49Z INFO one\ncontinuation");

        let (e1, t1) = &out[1];
        // byte_start sits at the start of line 3 (after the two CRLFs).
        assert_eq!(e1.byte_start, e0.byte_end + 2); // + \r\n
        assert_eq!(&content[e1.byte_start as usize..e1.byte_end as usize], t1);
        assert_eq!(t1, "2026-09-14T08:35:00Z INFO two");
    }

    #[test]
    fn file_without_trailing_newline_is_scanned() {
        let entries = scan("2026-09-14T08:34:49Z INFO last line has no newline");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line_end, 1);
    }

    #[test]
    fn source_order_is_deterministic_and_spans_cover_the_file() {
        let content = "\
1726298089 epoch entry
[error] bracket entry
2026-09-14T08:34:49,123 INFO iso entry
Sep 14 08:34:49 syslog entry
";
        let entries = scan(content);
        assert_eq!(entries.len(), 4);
        let mut prev_end_line = 0;
        for e in &entries {
            assert!(e.line_start > prev_end_line, "entries must be ordered");
            prev_end_line = e.line_end;
        }
    }

    // -------------------------------------------------------------------
    // Timestamp normalization (interval semantics)
    // -------------------------------------------------------------------

    #[test]
    fn normalization_orders_instants_monotonically() {
        let a = normalize_timestamp("2026-09-14T08:34:49Z").unwrap();
        let b = normalize_timestamp("2026-09-14T08:34:50Z").unwrap();
        let c = normalize_timestamp("2026-09-14T09:34:49Z").unwrap();
        let d = normalize_timestamp("2026-09-15T08:34:49Z").unwrap();
        assert!(a < b && b < c && c < d);
    }

    #[test]
    fn normalization_applies_utc_offsets() {
        // 08:34:49 +02:00 (east of UTC) == 06:34:49Z
        let offset = normalize_timestamp("2026-09-14T08:34:49+02:00").unwrap();
        let zulu = normalize_timestamp("2026-09-14T06:34:49Z").unwrap();
        assert_eq!(offset, zulu);
        // 08:34:49 -0100 (west of UTC — local = UTC − 1h) == 09:34:49Z
        let neg = normalize_timestamp("2026-09-14T08:34:49-0100").unwrap();
        let zulu2 = normalize_timestamp("2026-09-14T09:34:49Z").unwrap();
        assert_eq!(neg, zulu2);
    }

    #[test]
    fn normalization_handles_fraction_and_naive_timestamps() {
        let (secs, nanos) = normalize_timestamp("2026-09-14 08:34:49,123").unwrap();
        let (base, _) = normalize_timestamp("2026-09-14T08:34:49Z").unwrap();
        assert_eq!(secs, base);
        assert_eq!(nanos, 123_000_000);
        // Naive (no zone) is treated as UTC — documented judgment call.
        let naive = normalize_timestamp("2026-09-14 08:34:49").unwrap();
        assert_eq!(naive, (base, 0));
    }

    #[test]
    fn normalization_bracketed_has_year_syslog_does_not() {
        assert!(normalize_timestamp("14/Sep/2026:08:34:49 +0200").is_some());
        assert!(normalize_timestamp("[14/Sep/2026:08:34:49]").is_some());
        // Year-less syslog → unfilterable.
        assert_eq!(normalize_timestamp("Sep 14 08:34:49"), None);
        assert_eq!(normalize_timestamp("not a timestamp"), None);
    }

    #[test]
    fn interval_bounds_accept_bare_dates() {
        let midnight = parse_interval_bound("2026-09-14").unwrap();
        let with_time = parse_interval_bound("2026-09-14T00:00:00Z").unwrap();
        assert_eq!(midnight, with_time);
        assert!(parse_interval_bound("junk").is_none());
    }

    #[test]
    fn is_log_path_matches_extension_case_insensitively() {
        assert!(is_log_path(Path::new("server.log")));
        assert!(is_log_path(Path::new("SERVER.LOG")));
        assert!(is_log_path(Path::new("/var/log/sys.log")));
        assert!(!is_log_path(Path::new("server.txt")));
        assert!(!is_log_path(Path::new("log")));
    }

    #[test]
    fn streaming_reports_total_even_when_callback_filters() {
        let content = "2026-09-14T08:34:49Z ERROR a\n2026-09-14T08:34:50Z INFO b\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.log");
        std::fs::write(&path, content).unwrap();
        let mut seen = 0usize;
        let total = stream_log_entries(&path, |e, _| {
            if e.level.as_deref() == Some("error") {
                seen += 1;
            }
        })
        .unwrap();
        assert_eq!(total, 2, "total counts every scanned entry");
        assert_eq!(seen, 1, "the callback filtered one out");
    }
}
