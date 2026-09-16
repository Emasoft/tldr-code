//! Chunked YAML parsing for files the tree-sitter-yaml grammar cannot parse.
//!
//! # Root cause (measured + traced, 2026-03)
//!
//! `tree-sitter-yaml` 0.7.0's external scanner (`src/scanner.c`) tracks the
//! current source row in **`int16_t`** fields:
//!
//! ```c
//! typedef struct {
//!     int16_t row;          // scanner.c:136 — the token-start row
//!     ...
//!     int16_t end_row;      // scanner.c:145 — temp
//!     int16_t cur_row;      // scanner.c:147 — temp, ++ per newline
//! } Scanner;
//! ```
//!
//! `cur_row` is incremented on every newline (`adv_nwl` / `skp_nwl`,
//! scanner.c:217/230) and the scanner's block-structure decisions hang on
//! `bool has_nwl = scanner->cur_row > scanner->row` (scanner.c:889). Once a
//! source reaches **row 32768 (0-indexed) = 2^15**, the increment overflows
//! into negative territory: `cur_row` wraps to -32768 while `row` still holds
//! 32767, `has_nwl` flips to false, every subsequent indentation/newline
//! decision is wrong, the scanner stops producing valid tokens and the
//! parser's error recovery swallows the ENTIRE remaining input into one root
//! `ERROR` node. The serialized scanner state stores the row as `int16_t`
//! too (scanner.c:156/190), so the wrapped (negative) row persists across
//! tokens — the parse never recovers.
//!
//! Empirical shape of the defect (all measured through `PARSER_POOL.parse`):
//!
//! - a `---`-document stream parses clean through 6553 documents (32 768
//!   lines, 241 351 bytes, ~190k tree nodes) and ABORTS at 6554 documents —
//!   the returned tree's root is `ERROR` (`has_error == true`), its last
//!   sane node ends at row 32767, and the aborted tree is byte-identical
//!   for every larger input (parse time plateaus);
//! - a single-document block mapping parses clean through 32 767 keys
//!   (32 768 lines, 731 425 bytes) and aborts at exactly 32 768 keys —
//!   so the trigger is the LINE index, not the byte size and not the tree
//!   shape;
//! - long single lines parse fine (50 000-char values on 5 000 lines are
//!   clean), confirming rows — not bytes — are the counter that overflows;
//! - the old defect pin's "~65k nodes" was a numeric coincidence: the ERROR
//!   tree at the break happened to hold ~65.5k *named* nodes (6557
//!   documents × ~10 named nodes each). The real limit is 2^15 LINES.
//!
//! No upstream fix exists: crates.io's newest `tree-sitter-yaml` (0.7.2,
//! published 2025-10-07) still declares `int16_t row/cur_row` in its
//! scanner (verified against the published crate source), and the abort is
//! invisible to callers beyond `root.has_error()` — the engine silently
//! extracted ZERO definitions from every large `.yaml`.
//!
//! # Fix: document-aligned chunked parsing
//!
//! YAML is a stream of documents, and a document boundary is a grammar-level
//! parse boundary — so a large `.yaml` is split at top-level document starts
//! and each segment is parsed INDEPENDENTLY, well under the 32 768-line
//! abort threshold. Every segment starts at a column-0 `---` line, which per
//! the YAML spec can only BE a document start: `---` inside a quoted scalar
//! or flow collection cannot sit at column 0 (multi-line flow scalars and
//! flow collections must indent their continuation lines), and inside a
//! block scalar (`|`/`>`) content lines are always indented past the parent
//! node — a column-0 `---` would terminate that scalar per spec. The one
//! residual risk is malformed yaml that tolerates a column-0 `---` mid-
//! scalar; a segment cut there fails to parse and degrades to the
//! best-effort path (its partial tree is kept and the caller warns — see
//! [`parse_yaml_chunks`] and the merge in `extractor.rs`).
//!
//! Segments are COALESCED up to [`YAML_CHUNK_MAX_LINES`] lines per chunk
//! (each chunk still begins at a document marker and parses independently):
//! one tree per document would mean millions of separate parse calls and
//! tree allocations for a 100 MiB file. Offsets stay exact because each
//! chunk carries its `byte_base` (segment start) and `line_base` (newlines
//! before the segment) — see [`translate_definition`].
//!
//! Files at or below [`YAML_CHUNK_THRESHOLD_BYTES`] are NOT chunked: the
//! caller keeps the single whole-file parse (byte-identical behaviour, no
//! renumbering, no new code paths). A `---`-less single document above the
//! threshold cannot be split — it returns as ONE chunk whose parse aborts
//! exactly as before, and the caller MUST surface that through `warnings`
//! (the structure path does; the imports path has no warning channel and
//! documents the silence in `ast::imports`).

use tree_sitter::Tree;

use crate::ast::parser::PARSER_POOL;
use crate::types::{DefinitionInfo, Language};

/// Files larger than this are parsed in document-aligned chunks.
///
/// Below it the caller parses the whole file once — small files (the
/// overwhelming majority) keep byte-identical behaviour with the pre-chunking
/// engine. 512 KiB is ~14x the 36 KiB the abort needs on stream-shaped files
/// and comfortably below the smallest file where chunk overhead could matter.
pub const YAML_CHUNK_THRESHOLD_BYTES: usize = 512 * 1024;

/// The measured grammar abort threshold: the first token on 0-indexed row
/// 32 768 overflows the yaml scanner's `int16_t` row counter (see the module
/// docs). Row 32 767 — the last row an `int16_t` can represent — parses clean.
pub const YAML_LINE_LIMIT: u32 = 32_768;

/// Line budget per chunk (4x margin under [`YAML_CHUNK_LIMIT`]-adjacent
/// territory): documents are coalesced into chunks up to this many lines so a
/// 100 MiB stream parses in ~1.8k independent chunks instead of millions.
/// A single document longer than this still gets its own (possibly aborting)
/// chunk — documents are never split.
pub const YAML_CHUNK_MAX_LINES: u32 = 8_192;

/// One independently-parsed segment of a larger YAML file.
///
/// `tree` parses `&source[byte_base..]` — the chunk's text starts at
/// `byte_base` in the FULL file, and the chunk's row 0 is full-file row
/// `line_base`. All chunk-relative spans translate with
/// [`translate_definition`].
pub struct YamlChunk {
    /// The segment's own syntax tree (root `stream`, one document per chunk
    /// unless a document was too long to split further).
    pub tree: Tree,
    /// Byte offset of the segment's first byte in the full file.
    pub byte_base: usize,
    /// Byte offset one past the chunk's last PARSED byte. For every chunk
    /// except the last this is the next document boundary minus its trailing
    /// newline run (see [`parse_yaml_chunks_with`] — those newline bytes
    /// belong to no document and are parsed by nobody); for the last chunk it
    /// is the full source length. `&source[byte_base..byte_end]` is the exact
    /// parsed text.
    pub byte_end: usize,
    /// Number of newlines in the full file BEFORE the segment — the chunk's
    /// row 0 is full-file row `line_base`.
    pub line_base: u32,
}

impl YamlChunk {
    /// `true` when the segment's parse produced error nodes — for a segment
    /// at or under [`YAML_LINE_LIMIT`] this is a malformed-yaml signal, for a
    /// longer un-splittable segment it is the int16-row abort itself.
    pub fn has_error(&self) -> bool {
        self.tree.root_node().has_error()
    }
}

/// Should `source` be parsed in chunks rather than as one file?
pub fn should_chunk(source: &str) -> bool {
    source.len() > YAML_CHUNK_THRESHOLD_BYTES
}

/// Parse `source` as document-aligned chunks (see the module docs).
///
/// Returns exactly one chunk for sources at or under
/// [`YAML_CHUNK_THRESHOLD_BYTES`] (the plain single parse, offsets 0) and for
/// sources with no column-0 `---` document starts (nothing to split on — a
/// single document; if it is over [`YAML_LINE_LIMIT`] lines the parse aborts
/// and the CALLER must warn). Never returns an empty vec.
pub fn parse_yaml_chunks(source: &str) -> Vec<YamlChunk> {
    if !should_chunk(source) {
        return vec![whole_source_chunk(source)];
    }
    parse_yaml_chunks_with(source, YAML_CHUNK_MAX_LINES)
}

/// Chunk with an explicit line budget (the test seam — production code goes
/// through [`parse_yaml_chunks`]).
///
/// Boundary placement, and why the LAST document of a chunk must not end at
/// the next chunk's `---`: a single whole-file parse ends every mid-stream
/// document at its last CONTENT byte — the newline that terminates its last
/// line belongs to NO document (measured: `document 0..8 = "---\na: 1"` for
/// source `"---\na: 1\n---\nb: 2\n"`), while a document at EOF swallows the
/// trailing newline run. A chunk parsed up to the next `---` would make its
/// last document a chunk-EOF document and swallow that newline, drifting its
/// byte span +1 (or +N with blank lines) from the single-parse convention.
/// So every non-final chunk ends at its last content byte (the trailing
/// newline run before the next `---` is trimmed — it is pure newline bytes,
/// parsed by nobody, and still counted in the next chunk's `line_base`). The
/// FINAL chunk ends at the file's true EOF, where the single-parse convention
/// also swallows the trailing run — identical bytes, identical tree.
fn parse_yaml_chunks_with(source: &str, max_chunk_lines: u32) -> Vec<YamlChunk> {
    let starts = chunk_starts(source);
    let mut chunks = Vec::new();
    let mut chunk_start = starts[0]; // always 0
    let mut chunk_lines = 0u32;
    let mut line_base = 0u32;

    for k in 0..starts.len() {
        let doc_start = starts[k];
        // A document spans to the next document's start (or EOF for the last).
        let doc_end = starts.get(k + 1).copied().unwrap_or(source.len());
        let seg_lines = count_newlines(&source[doc_start..doc_end]);
        if chunk_lines > 0 && chunk_lines + seg_lines > max_chunk_lines {
            // Close the current chunk BEFORE this document — every document
            // counted so far stays whole inside it. The closing chunk's text
            // ends at its last content byte (trailing newline run trimmed —
            // see the boundary-placement note above).
            let end = trim_trailing_newlines(source, doc_start);
            chunks.push(make_chunk(source, chunk_start, end, line_base));
            // The next chunk's row 0 is full-file row (newlines before it) —
            // the trimmed gap bytes are counted here, in the FULL source.
            line_base += count_newlines(&source[chunk_start..doc_start]);
            chunk_start = doc_start;
            chunk_lines = 0;
        }
        chunk_lines += seg_lines;
    }

    // The tail (or the whole file when there are no boundaries) is the last
    // chunk — untrimmed to the file's EOF. For a `---`-less oversized single
    // document this chunk aborts exactly like the pre-chunking single parse,
    // and the caller warns.
    chunks.push(make_chunk(source, chunk_start, source.len(), line_base));
    chunks
}

/// One chunk over the whole source: the single-parse path, offsets zero.
fn whole_source_chunk(source: &str) -> YamlChunk {
    make_chunk(source, 0, source.len(), 0)
}

/// Byte offset one past the last non-newline byte at or before `end` — the
/// parseable text of a non-final chunk (see [`parse_yaml_chunks_with`]).
fn trim_trailing_newlines(source: &str, mut end: usize) -> usize {
    let bytes = source.as_bytes();
    while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    end
}

/// Parse `&source[start..end]` as one chunk.
///
/// `PARSER_POOL.parse` for Yaml can only fail on sources above `u32::MAX`
/// bytes; every chunk is a slice of a source that already passed the
/// oversize policy (`fs::oversize`), so the expect is unreachable.
fn make_chunk(source: &str, start: usize, end: usize, line_base: u32) -> YamlChunk {
    let tree = PARSER_POOL
        .parse(&source[start..end], Language::Yaml)
        .expect("yaml chunk within the u32::MAX parse ceiling must parse");
    YamlChunk {
        tree,
        byte_base: start,
        byte_end: end,
        line_base,
    }
}

/// Byte offsets where a CHUNK may begin: 0 (the implicit first document,
/// which may be empty or marker-less) plus every top-level `---` document
/// start. Sorted, deduped, first element always 0.
fn chunk_starts(source: &str) -> Vec<usize> {
    let mut starts = document_starts(source);
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    starts.dedup();
    starts
}

/// Byte offsets of every line that OPENS a YAML document: a line that is
/// exactly `---`, or starts with `--- ` / `---\t` (an inline first node or
/// comment), at COLUMN 0. See the module docs for why column 0 is the
/// spec-guaranteed safe split point.
fn document_starts(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut starts = Vec::new();
    let mut line_begin = 0usize;
    for i in 0..=bytes.len() {
        if i == bytes.len() || bytes[i] == b'\n' {
            if is_document_start_line(&bytes[line_begin..i]) {
                starts.push(line_begin);
            }
            line_begin = i + 1;
        }
    }
    starts
}

/// `line` (one line's bytes, newline excluded) opens a document iff it is
/// `---`, or `---` followed by a space/tab (content or comment). CRLF is
/// tolerated (`---\r` == `---`). `---key` (no separator) is NOT a document
/// start — the marker must end the line or be followed by whitespace.
fn is_document_start_line(line: &[u8]) -> bool {
    let line = if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    };
    if !line.starts_with(b"---") {
        return false;
    }
    match line.len() {
        3 => true,
        _ => matches!(line[3], b' ' | b'\t'),
    }
}

/// Newlines in `s` — the incremental line counter that keeps chunk
/// `line_base`s O(total source) instead of O(chunks × source).
fn count_newlines(s: &str) -> u32 {
    s.bytes().filter(|&b| b == b'\n').count() as u32
}

/// Translate one chunk-relative [`DefinitionInfo`] into FULL-FILE
/// coordinates: byte spans shift by the chunk's `byte_base`, line spans by
/// its `line_base` (the chunk's row 0 is full-file row `line_base`). The
/// signature text needs no translation — callers extract it from the chunk
/// slice, whose bytes are the element's real bytes.
pub fn translate_definition(def: &mut DefinitionInfo, byte_base: usize, line_base: u32) {
    def.line_start = def.line_start.saturating_add(line_base);
    def.line_end = def.line_end.saturating_add(line_base);
    if let Some(d) = def.definition_line {
        def.definition_line = Some(d.saturating_add(line_base));
    }
    if let Some(b) = def.byte_start {
        def.byte_start = Some(b.saturating_add(byte_base as u64));
    }
    if let Some(b) = def.byte_end {
        def.byte_end = Some(b.saturating_add(byte_base as u64));
    }
}

/// Renumber chunk-local `document` elements into full-file numbering, in
/// place, in slice order. Each chunk's element walker names its documents
/// `document-1..k` (per-stream indices); a chunked file's documents must
/// number continuously across chunks. Returns the NEXT document number to
/// use (feed it into the following chunk's call).
pub(crate) fn renumber_documents(definitions: &mut [DefinitionInfo], next_doc_no: usize) -> usize {
    let mut doc_no = next_doc_no;
    for def in definitions.iter_mut() {
        if def.kind == "document" {
            def.name = format!("document-{doc_no}");
            doc_no += 1;
        }
    }
    doc_no
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(i: usize) -> String {
        format!("---\nid: unit-{i}\nitems:\n  - x\n  - y\n")
    }

    fn doc_stream(n: usize) -> String {
        (0..n).map(doc).collect()
    }

    // ------------------------------------------------------------------
    // boundary detection
    // ------------------------------------------------------------------

    #[test]
    fn document_starts_only_at_column_zero() {
        // Column-0 markers split; everything else must not.
        let src = "---\na: 1\n  ---\nb: 2\nkey: |\n  ---\n  text\nnext: \"---\"\n---\nc: 3\n";
        let starts = document_starts(src);
        assert_eq!(starts, vec![0, src.find("\n---\nc: 3").unwrap() + 1]);

        // `--- content` on the marker line is a document start.
        assert_eq!(document_starts("--- key: v\n"), vec![0]);
        // `---# comment` (no separator) is NOT a marker.
        assert!(document_starts("---comment\n").is_empty());
        // `--- \t` (tab separator) IS.
        assert_eq!(document_starts("---\tx: 1\n"), vec![0]);
        // CRLF: `---\r\n` is a marker line ("---\r\n" = 5 bytes).
        assert_eq!(
            document_starts("---\r\na: 1\r\n---\r\nb: 2\r\n"),
            vec![0, 11]
        );
        // `...` (document END) is not a start.
        assert!(document_starts("a: 1\n...\n").is_empty());
        // `---` inside a quoted scalar is on an INDENTED continuation line
        // (column-0 continuation is invalid yaml per spec) — no split.
        assert!(document_starts("a: \"x\n  --- y\"\n").is_empty());
        // Empty source, no final newline.
        assert!(document_starts("").is_empty());
        assert!(document_starts("a: 1").is_empty());
    }

    #[test]
    fn chunk_starts_always_begin_at_zero() {
        // Leading marker: 0 IS a document start, no insertion
        // ("---\na: 1\n" = 9 bytes, so the second `---` sits at 9).
        assert_eq!(chunk_starts("---\na: 1\n---\nb: 2\n"), vec![0, 9]);
        // No leading marker: 0 is INSERTED (the implicit first document);
        // "a: 1\n" = 5 bytes, so the `---` sits at 5.
        assert_eq!(chunk_starts("a: 1\n---\nb: 2\n"), vec![0, 5]);
        assert_eq!(chunk_starts(""), vec![0]);
    }

    // ------------------------------------------------------------------
    // chunk geometry
    // ------------------------------------------------------------------

    #[test]
    fn chunks_are_document_aligned_and_within_budget() {
        // 400 docs × 5 lines = 2000 lines; budget 64 lines (≈12 docs) ⇒
        // every chunk ≤ 64 lines and every chunk after the first begins at
        // a column-0 `---`.
        let source = doc_stream(400);
        let chunks = parse_yaml_chunks_with(&source, 64);
        assert!(chunks.len() > 10);
        for (idx, chunk) in chunks.iter().enumerate() {
            if idx > 0 {
                assert!(
                    source[chunk.byte_base..].starts_with("---\n"),
                    "chunk {idx} must begin at a document marker"
                );
            }
            assert!(!chunk.has_error(), "chunk {idx} must parse clean");
        }
        // Chunk geometry: chunk i's parsed text ends at its last content
        // byte; only a run of newline bytes separates it from chunk i+1's
        // `---` (the run belongs to no document — see the boundary note).
        for w in chunks.windows(2) {
            let text = &source[w[0].byte_base..w[0].byte_end];
            assert!(text.starts_with("---\n"));
            assert!(text.ends_with("  - y"), "chunk text must end at content");
            let gap = &source[w[0].byte_end..w[1].byte_base];
            assert!(!gap.is_empty(), "a newline run must separate chunks");
            assert!(
                gap.bytes().all(|b| b == b'\n' || b == b'\r'),
                "chunk gap must be pure newlines: {gap:?}"
            );
            assert!(
                count_newlines(text) <= 64,
                "chunk exceeded the line budget: {} lines",
                count_newlines(text)
            );
        }
        // The last chunk runs untrimmed to EOF.
        let last = chunks.last().unwrap();
        assert_eq!(last.byte_end, source.len());
        assert!(source[last.byte_base..].ends_with("  - y\n"));
    }

    #[test]
    fn line_bases_accumulate_exactly() {
        let source = doc_stream(300);
        let chunks = parse_yaml_chunks_with(&source, 50);
        for chunk in &chunks {
            let expected: u32 = source[..chunk.byte_base]
                .bytes()
                .filter(|&b| b == b'\n')
                .count() as u32;
            assert_eq!(chunk.line_base, expected);
        }
    }

    #[test]
    fn single_oversized_document_stays_one_chunk() {
        // One document, 40k lines, no further markers ⇒ exactly one chunk
        // over the budget (documents are never split), and — at 40k lines,
        // far past the grammar's 32 768-line row ceiling — its parse aborts.
        let mut source = String::from("---\n");
        for i in 0..40_000 {
            source.push_str(&format!("key-{i}: value-{i}\n"));
        }
        let chunks = parse_yaml_chunks_with(&source, 100);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].byte_base, 0);
        assert_eq!(chunks[0].line_base, 0);
        assert!(chunks[0].has_error(), "40k-line document must abort");
    }

    #[test]
    fn small_source_is_one_clean_chunk() {
        let source = doc_stream(10);
        let chunks = parse_yaml_chunks(&source);
        assert_eq!(chunks.len(), 1);
        assert!(!chunks[0].has_error());
        assert_eq!(chunks[0].byte_base, 0);
        assert_eq!(chunks[0].line_base, 0);
    }

    // ------------------------------------------------------------------
    // the abort itself (pinned small so it stays in `make test`)
    // ------------------------------------------------------------------

    #[test]
    fn grammar_aborts_at_row_32768() {
        // 32 767 keys + the leading `---` = 32 768 lines: clean (the last
        // token sits on row 32 767, the largest an int16 scanner row can
        // hold). One more key puts a token on row 32768 ⇒ abort.
        let build = |n: usize| {
            let mut s = String::from("---\n");
            for i in 0..n {
                s.push_str(&format!("k{i}: v\n"));
            }
            s
        };
        let clean = PARSER_POOL.parse(&build(32_767), Language::Yaml).unwrap();
        assert!(!clean.root_node().has_error());
        let aborted = PARSER_POOL.parse(&build(32_768), Language::Yaml).unwrap();
        assert!(aborted.root_node().has_error());
        // The aborted tree's exact shape varies with the content around the
        // overflow (root `ERROR`, or a `stream` holding an `ERROR` child) —
        // `has_error` is the stable signature, the kind is not.
    }

    // ------------------------------------------------------------------
    // offset translation + renumbering
    // ------------------------------------------------------------------

    #[test]
    fn translate_definition_shifts_all_spans() {
        let mut def = DefinitionInfo {
            name: "k".into(),
            kind: "key".into(),
            line_start: 1,
            line_end: 3,
            definition_line: Some(1),
            byte_start: Some(0),
            byte_end: Some(9),
            signature: "k: v".into(),
        };
        translate_definition(&mut def, 1000, 500);
        assert_eq!(def.line_start, 501);
        assert_eq!(def.line_end, 503);
        assert_eq!(def.definition_line, Some(501));
        assert_eq!(def.byte_start, Some(1000));
        assert_eq!(def.byte_end, Some(1009));
        // The signature is chunk-slice text — untouched by translation.
        assert_eq!(def.signature, "k: v");
    }

    #[test]
    fn renumber_documents_continues_across_slices() {
        let mk = |kind: &str, name: &str| DefinitionInfo {
            name: name.into(),
            kind: kind.into(),
            line_start: 1,
            line_end: 1,
            definition_line: None,
            byte_start: None,
            byte_end: None,
            signature: String::new(),
        };
        let mut defs = vec![
            mk("document", "document-1"),
            mk("key", "a"),
            mk("document", "document-1"),
        ];
        let next = renumber_documents(&mut defs, 7);
        assert_eq!(defs[0].name, "document-7");
        assert_eq!(defs[1].name, "a"); // non-documents untouched
        assert_eq!(defs[2].name, "document-8");
        assert_eq!(next, 9);
    }
}

// ===========================================================================
// Large-file end-to-end (via the public entry points, temp files on disk).
// Kept under the 1 MiB scale so they run in `make test` (debug, seconds);
// the 100 MiB byte-exact proof lives in large_file_accuracy_v1 (release,
// opt-in) and reuses these invariants.
// ===========================================================================

#[cfg(test)]
mod large_file {
    use super::*;
    use crate::types::CodeStructure;
    use std::path::Path;

    /// The suite unit shape (5 lines, ~37 bytes per document).
    fn doc(i: usize) -> String {
        format!("---\nid: unit-{i}\nitems:\n  - x\n  - y\n")
    }

    fn doc_stream(n: usize) -> String {
        (0..n).map(doc).collect()
    }

    fn write_temp(source: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("large.yaml");
        std::fs::write(&path, source).expect("write fixture");
        (dir, path)
    }

    /// Field-by-field equality (DefinitionInfo carries no PartialEq).
    fn assert_defs_equal(a: &[DefinitionInfo], b: &[DefinitionInfo]) {
        assert_eq!(
            a.len(),
            b.len(),
            "definition count mismatch (chunked vs single parse)"
        );
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(x.name, y.name, "defs[{i}] name");
            assert_eq!(x.kind, y.kind, "defs[{i}] kind");
            assert_eq!(
                x.line_start, y.line_start,
                "defs[{i}] ({}) line_start",
                x.name
            );
            assert_eq!(x.line_end, y.line_end, "defs[{i}] ({}) line_end", x.name);
            assert_eq!(
                x.definition_line, y.definition_line,
                "defs[{i}] definition_line"
            );
            assert_eq!(
                x.byte_start, y.byte_start,
                "defs[{i}] ({}) byte_start",
                x.name
            );
            assert_eq!(x.byte_end, y.byte_end, "defs[{i}] ({}) byte_end", x.name);
            assert_eq!(x.signature, y.signature, "defs[{i}] ({}) signature", x.name);
        }
    }

    /// THE equivalence pin: merging document-aligned chunk parses must
    /// produce EXACTLY what one whole-file parse produces — same order,
    /// same names, same line and byte spans. Runs the merge with a tiny
    /// line budget so the source genuinely splits into many chunks.
    #[test]
    fn chunked_merge_equals_single_parse() {
        // 600 docs × 5 lines = 3000 lines (~110 KB — small, so a whole-file
        // parse is clean and the direct extraction is the ground truth).
        let source = doc_stream(600);
        let chunks = parse_yaml_chunks_with(&source, 64);
        assert!(chunks.len() > 20, "the source must actually split");

        let (structure, warnings) = crate::ast::extractor::merge_yaml_chunk_structure(
            Path::new("large.yaml"),
            std::path::PathBuf::from("large.yaml"),
            &source,
            chunks,
        )
        .expect("merge");

        // The direct (single-parse) ground truth — for yaml this is exactly
        // what extract_file_structure assembles below the chunk threshold
        // (legacy definitions are empty; functions/classes/methods too).
        let tree = PARSER_POOL.parse(&source, Language::Yaml).expect("parse");
        let direct = crate::ast::elements::extract_elements(Language::Yaml, &tree, &source);

        assert!(warnings.is_empty(), "all chunks parse clean: {warnings:?}");
        assert_defs_equal(&structure.definitions, &direct);
        assert_eq!(structure.definitions.len(), 600 * 3);
    }

    /// Small files keep the exact pre-chunking behaviour: no chunking, no
    /// warnings, correct document numbering.
    #[test]
    fn structure_small_yaml_unchanged() {
        let source = doc_stream(100);
        let (_dir, path) = write_temp(&source);
        let CodeStructure {
            files, warnings, ..
        } = crate::get_code_structure(&path, Language::Yaml, 0, None).expect("structure");
        assert!(!should_chunk(&source));
        assert!(warnings.is_empty());
        assert_eq!(files.len(), 1);
        let defs = &files[0].definitions;
        assert_eq!(defs.len(), 300);
        assert_eq!(defs[6].kind, "document");
        assert_eq!(defs[6].name, "document-3");
        assert_eq!(defs[6].line_start, 11);
        assert_eq!(defs[6].line_end, 15);
        // Single-parse convention: a mid-stream document's byte span ends at
        // its last content byte — the line's newline belongs to no document.
        assert_eq!(
            &source[defs[6].byte_start.unwrap() as usize..defs[6].byte_end.unwrap() as usize],
            "---\nid: unit-2\nitems:\n  - x\n  - y"
        );
        // `_dir` keeps owning the tempdir to the end of the test.
    }

    /// Over the threshold, multi-document: EVERY document extracts, spans
    /// map to full-file coordinates, numbering is continuous, no warnings.
    #[test]
    fn structure_over_threshold_multi_doc_extracts_everything() {
        let n = 20_000; // 20k docs × ~37 B ≈ 740 KB > 512 KiB; 100k lines
        let source = doc_stream(n);
        assert!(should_chunk(&source));
        let (_dir, path) = write_temp(&source);
        let CodeStructure {
            files,
            warnings,
            files_skipped,
            ..
        } = crate::get_code_structure(&path, Language::Yaml, 0, None).expect("structure");
        assert_eq!(files_skipped, 0);
        assert!(
            warnings.is_empty(),
            "clean chunks must not warn: {warnings:?}"
        );
        assert_eq!(files.len(), 1);
        let defs = &files[0].definitions;
        assert_eq!(defs.len(), n * 3, "document + id + items per unit");

        // Strict interleaving: [document-i, id-i, items-i] per unit, in
        // source order across the whole file. Document byte spans follow the
        // single-parse convention (end at last content byte) EXCEPT the
        // file's last document, which swallows the file's trailing newline
        // at EOF — the same in both worlds.
        for i in [0usize, 1, 7_777, 13_531, n - 1] {
            let (d, k, it) = (&defs[3 * i], &defs[3 * i + 1], &defs[3 * i + 2]);
            let unit = doc(i);
            let unit_trimmed = unit.trim_end_matches('\n');

            assert_eq!(d.kind, "document");
            assert_eq!(
                d.name,
                format!("document-{}", i + 1),
                "continuous numbering"
            );
            assert_eq!(d.line_start, (5 * i + 1) as u32);
            assert_eq!(d.line_end, (5 * i + 5) as u32);
            assert_eq!(
                &source[d.byte_start.unwrap() as usize..d.byte_end.unwrap() as usize],
                if i == n - 1 {
                    unit.as_str()
                } else {
                    unit_trimmed
                },
                "document byte span (EOF convention applies to the file's last document only)"
            );

            assert_eq!(k.kind, "key");
            assert_eq!(k.name, "id");
            assert_eq!(k.line_start, (5 * i + 2) as u32);
            assert_eq!(k.line_end, (5 * i + 2) as u32);
            assert_eq!(
                &source[k.byte_start.unwrap() as usize..k.byte_end.unwrap() as usize],
                format!("id: unit-{i}")
            );
            assert_eq!(k.signature, format!("id: unit-{i}"));

            assert_eq!(it.kind, "key");
            assert_eq!(it.name, "items");
            assert_eq!(it.line_start, (5 * i + 3) as u32);
            assert_eq!(it.line_end, (5 * i + 5) as u32);
            assert_eq!(
                &source[it.byte_start.unwrap() as usize..it.byte_end.unwrap() as usize],
                if i == n - 1 {
                    // The file's last document swallows the EOF newline INSIDE
                    // its last pair — the same convention a single parse has
                    // (and why the suite probes `items` on the line path).
                    "items:\n  - x\n  - y\n"
                } else {
                    "items:\n  - x\n  - y"
                },
                "items key + its sequence value"
            );
        }
    }

    /// THE honesty pin (STEP 3): a `---`-less single document too long for
    /// the grammar's int16 row counter cannot be chunked — its parse aborts
    /// exactly as before, and the structure path must SAY SO instead of
    /// silently extracting zero definitions.
    #[test]
    fn structure_over_threshold_single_doc_warns() {
        // 40k lines / ~700 KB: over BOTH the chunk threshold and the 32768
        // line limit, with no document marker to split on.
        let mut source = String::from("---\n");
        for i in 0..40_000 {
            source.push_str(&format!("key-{i}: value-{i}\n"));
        }
        assert!(should_chunk(&source));
        let (_dir, path) = write_temp(&source);
        let CodeStructure {
            files,
            warnings,
            files_skipped,
            ..
        } = crate::get_code_structure(&path, Language::Yaml, 0, None).expect("structure");
        assert_eq!(files_skipped, 0, "the file is analysed, not skipped");
        assert_eq!(warnings.len(), 1, "exactly one honesty warning");
        assert!(warnings[0].contains(&path.display().to_string()));
        assert!(
            warnings[0].contains("line limit"),
            "warning must name the mechanism: {}",
            warnings[0]
        );
        assert!(warnings[0].contains("int16"));
        // Best effort: the aborted tree still holds the parseable PREFIX
        // (everything before source row 32768), so the extraction is
        // truncated — not empty, and far short of the 40k keys on disk.
        // The point of the warning is that the truncation is NAMED.
        let defs = &files[0].definitions;
        assert!(!defs.is_empty(), "the parseable prefix must still extract");
        assert!(
            defs.len() < 40_000,
            "the abort must truncate: got {} definitions",
            defs.len()
        );
    }
    /// The imports path merges per-chunk doclinks — no spans, plain
    /// concatenation in source order, nothing lost at chunk boundaries.
    #[test]
    fn imports_over_threshold_concatenate_doclinks() {
        // 16k docs × 3 lines ≈ 580 KB > 512 KiB, one `$ref` per document.
        let n = 16_000;
        let mut source = String::new();
        for i in 0..n {
            source.push_str(&format!("---\nid: unit-{i}\n$ref: shared-{i}.yaml\n"));
        }
        assert!(should_chunk(&source));
        let (_dir, path) = write_temp(&source);

        let links = crate::ast::imports::get_imports(&path, Language::Yaml).expect("imports");
        assert_eq!(links.len(), n, "one link per document — none lost");
        assert_eq!(links[0].module, "shared-0.yaml");
        assert_eq!(links[n - 1].module, format!("shared-{}.yaml", n - 1));
        assert_eq!(links[0].alias.as_deref(), Some("$ref"));
        assert!(links[0].is_from);
        // Source order across chunks: modules must be strictly increasing.
        for (i, link) in links.iter().enumerate() {
            assert_eq!(
                link.module,
                format!("shared-{i}.yaml"),
                "source order at {i}"
            );
        }
    }
}
