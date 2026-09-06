//! File system operations for TLDR
//!
//! This module provides file tree traversal and ignore pattern handling.

pub mod oversize;
pub mod tree;

use std::io;
use std::path::Path;

pub use oversize::{
    check_size, format_oversize_warning, is_autogen_file, max_size_for, SizeCheck,
    MAX_AUTOGEN_FILE_SIZE_BYTES, MAX_FILE_SIZE_BYTES,
};
pub use tree::get_file_tree;

/// How far into a file to look for the NUL byte that marks a wide encoding.
///
/// Bounded rather than whole-file on purpose. A wide-encoded file (BOM-less
/// UTF-16, UTF-32) carries a NUL by byte 1, because the high byte of its first
/// ASCII character is zero. A legitimate source file that embeds a raw NUL —
/// generated C tables, protobuf/flatbuffers output, binary-protocol fixtures
/// written as `.py`/`.js`/`.rs` — carries it far later. Scanning the whole file
/// would skip those too, trading one silent-loss bug for another.
pub const NUL_SCAN_PREFIX: usize = 1024;

/// Returns a human-readable marker when `bytes` look wide-encoded (UTF-16 or
/// UTF-32), which `String::from_utf8`/`from_utf8_lossy` cannot detect: a
/// BOM-less UTF-16 encoding of ASCII text is every ASCII byte interleaved
/// with NUL, and NUL is a *valid* 1-byte UTF-8 sequence — so UTF-8 validation
/// accepts it outright.
///
/// UTF-32 BOMs are checked first: `FF FE 00 00` (LE) and `00 00 FE FF` (BE)
/// share their leading 2 bytes with the UTF-16 BOMs, so checking UTF-16
/// first would mislabel a UTF-32 LE file as "UTF-16 LE BOM".
///
/// The NUL scan is bounded to the first [`NUL_SCAN_PREFIX`] bytes rather than
/// the whole file: a wide-encoded file has a NUL by byte 1, while a
/// legitimate source file that embeds a raw NUL (generated C tables,
/// protobuf output, binary-protocol fixtures) has it much later, so scanning
/// the whole file would skip those too.
///
/// **1024 is a judgment, not a derived value**, and the two failure directions
/// are not symmetric:
/// - TOO LARGE: a real source file with a NUL inside the first KiB is skipped
///   and the warning miscalls it wide-encoded. A generated C blob table
///   starting near the top of the file would do it. This is the live risk.
/// - TOO SMALL: a wide-encoded file whose first N bytes are all non-Latin (a
///   BOM-less UTF-16 file opening with a CJK docstring, where U+4E2D is
///   `2D 4E` and carries no NUL) slips through. Detection needs only the
///   first ASCII character — a space, a newline, `#`, `//` — so a handful of
///   bytes suffices for anything with ASCII structure near the top, which
///   source code has.
///
/// The bound is therefore generous on purpose: it costs nothing against the
/// second failure and would only need shrinking if the first is ever observed.
pub fn wide_encoding_marker(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) || bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
    {
        Some("UTF-32 BOM")
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some("UTF-16 LE BOM")
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some("UTF-16 BE BOM")
    } else if bytes[..NUL_SCAN_PREFIX.min(bytes.len())].contains(&0x00) {
        Some("NUL byte in the first 1024 bytes")
    } else {
        None
    }
}

/// Outcome of a tolerant UTF-8 file read.
///
/// Distinguishes cases that surface scanners need to handle differently:
///
/// - [`ReadOutcome::Ok`] - the file was readable and decoded as valid UTF-8.
/// - [`ReadOutcome::NonUtf8`] - the file exists and is readable, but contains
///   bytes that are not valid UTF-8 (e.g. a Lua/Luau parser-test fixture
///   with raw `0xFF` bytes). Callers should skip the file and emit a warning,
///   not abort the whole scan. The first invalid byte offset is included so
///   the warning can pinpoint the exact location.
/// - [`ReadOutcome::WideEncoded`] - the bytes are valid UTF-8 by the letter,
///   but look like a wide encoding (BOM-less UTF-16, UTF-32) that
///   `String::from_utf8` cannot detect — analysing it would produce
///   confidently wrong results, not a decode error.
/// - The error case (`Err(io::Error)`) is reserved for genuine I/O failures
///   (permission denied, file vanished, etc.) which still propagate.
#[derive(Debug)]
pub enum ReadOutcome {
    /// Successful read with valid UTF-8 content.
    Ok(String),
    /// File exists but is not valid UTF-8. `byte_offset` is the index of the
    /// first invalid byte sequence (matches `std::str::Utf8Error::valid_up_to`).
    NonUtf8 {
        /// Byte offset of the first invalid UTF-8 sequence.
        byte_offset: usize,
    },
    /// File is valid UTF-8 but looks wide-encoded (see [`wide_encoding_marker`]).
    WideEncoded {
        /// Human-readable description of the marker that fired.
        detail: &'static str,
    },
}

/// Read a source file as UTF-8 text, tolerantly classifying non-UTF-8 content
/// as a skippable condition rather than a hard error.
///
/// Many parser-test corpora (notably the Luau `tests/conformance/literals.luau`
/// and `pm.luau` files) intentionally contain raw non-UTF-8 bytes. When such a
/// file appears under a directory being scanned (e.g. `tldr surface /repo`),
/// we want to skip it with a warning and continue, not abort the scan.
///
/// # Returns
///
/// - `Ok(ReadOutcome::Ok(source))` for valid UTF-8 files.
/// - `Ok(ReadOutcome::NonUtf8 { byte_offset })` for files whose bytes are not
///   valid UTF-8.
/// - `Err(io::Error)` for genuine I/O failures (file missing, permission
///   denied, etc.).
///
/// # Why not `from_utf8_lossy`?
///
/// Replacing invalid bytes with U+FFFD would produce gibberish strings that
/// parsers can choke on, surface garbage symbols, or yield misleading taint
/// analysis. Skipping with a warning is the safer policy.
pub fn read_to_string_tolerant(path: &Path) -> io::Result<ReadOutcome> {
    let bytes = std::fs::read(path)?;
    if let Some(detail) = wide_encoding_marker(&bytes) {
        return Ok(ReadOutcome::WideEncoded { detail });
    }
    match String::from_utf8(bytes) {
        Ok(source) => Ok(ReadOutcome::Ok(source)),
        Err(err) => {
            let byte_offset = err.utf8_error().valid_up_to();
            Ok(ReadOutcome::NonUtf8 { byte_offset })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn read_to_string_tolerant_returns_ok_for_valid_utf8() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world\n").unwrap();
        let outcome = read_to_string_tolerant(f.path()).unwrap();
        match outcome {
            ReadOutcome::Ok(s) => assert_eq!(s, "hello world\n"),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn read_to_string_tolerant_returns_nonutf8_for_invalid_bytes() {
        let mut f = NamedTempFile::new().unwrap();
        // 0xFF is never valid as a leading byte in UTF-8.
        f.write_all(b"valid prefix \xFF\xFE invalid").unwrap();
        let outcome = read_to_string_tolerant(f.path()).unwrap();
        match outcome {
            ReadOutcome::NonUtf8 { byte_offset } => {
                assert_eq!(byte_offset, "valid prefix ".len());
            }
            other => panic!("expected NonUtf8, got {:?}", other),
        }
    }

    #[test]
    fn read_to_string_tolerant_returns_err_for_missing_file() {
        let outcome = read_to_string_tolerant(Path::new("/nonexistent/path/xyz.txt"));
        assert!(outcome.is_err());
    }
}
