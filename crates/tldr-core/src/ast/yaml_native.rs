//! Native top-level outline for single YAML documents the grammar cannot
//! parse (yaml-native-outline-v1).
//!
//! # Why this exists
//!
//! `tree-sitter-yaml` 0.7.0 aborts on any source that reaches row 32 768:
//! its external scanner tracks the current row in `int16_t` fields, which
//! overflow negative (root cause, measurements, and the document-aligned
//! chunking fix — see the [`crate::ast::yaml_chunk`] module docs). Chunking
//! fully extracts every MULTI-document file, but a SINGLE document longer
//! than the limit cannot be split — its chunk's parse is guaranteed to
//! abort, and the tree-sitter path recovers only the truncated prefix
//! before row 32 768.
//!
//! On exactly that path (a chunk whose parse `has_error` AND which spans
//! more than [`crate::ast::yaml_chunk::YAML_LINE_LIMIT`] lines) the chunk
//! merger (`ast::extractor::merge_yaml_chunk_structure`) REPLACES the
//! aborted tree's truncated extraction with [`scan_yaml_outline_native`]: a
//! deterministic, dependency-free line scan that recovers the document's
//! TOP-LEVEL mapping keys — the outline needed to navigate a 100k-line
//! config the grammar cannot read. Ordinary parse failures (a chunk at or
//! under the line limit: small malformed files, the pathological column-0
//! `---` mid-scalar cut) NEVER engage this scanner — their best-effort
//! prefix extraction and plain warning stay unchanged.
//!
//! # What is emitted
//!
//! One [`DefinitionInfo`] with `kind = "key"` per TOP-LEVEL mapping key:
//!
//! - a top-level key line is a COLUMN-0 line matching
//!   `^[A-Za-z_][\w.\- ]*:` — refined two ways that keep every valid
//!   top-level key and drop the obvious junk: an optional matching quote
//!   pair around the key is accepted (and stripped from the name), and the
//!   colon must be followed by a space, a tab, or end-of-line (the YAML
//!   mapping form — which also rejects bare URLs such as
//!   `http://example.com`, whose colon is followed by `/`, and `a:b`, which
//!   YAML itself reads as a plain scalar, not a mapping).
//! - comments (`#…`), document markers (`---`, `…`), sequence entries
//!   (`- item`) and INDENTED lines (every nested key, every block-scalar
//!   body, every quoted continuation) all fail the first-character test
//!   and are skipped — no recursion, by design. Nested extraction is
//!   documented future work; a 100k-line single document is overwhelmingly
//!   a flat/flat-ish config.
//! - REGION semantics — the standard indentation trick: a top-level key
//!   owns everything up to the NEXT column-0 key line. `line_end` is the
//!   next key's line minus 1 (the file's last key runs to the slice's last
//!   line); `byte_end` stops at the region's last content byte (trailing
//!   newline run trimmed — the codebase-wide content-byte convention), and
//!   the FINAL key of an uncapped scan swallows the trailing newline at
//!   EOF, byte-identical to what a single whole-file parse produces.
//! - byte spans are exact slice-backs in FULL-FILE coordinates (the caller
//!   passes the chunk's `byte_base`/`line_base` and no post-translation is
//!   needed); `definition_line` is the key line; `signature` is the key
//!   line's text (trimmed); `container` is `None` — these are the host
//!   file's own keys, living in the host structure only.
//! - BUDGET: the scan stops at [`YAML_NATIVE_MAX_KEYS`] emitted keys
//!   (paranoia — a pathologically huge flat file must not balloon the
//!   structure output); the informational warning says so when the cap
//!   bites, and the capped-out key line bounds the last emitted region.
//!
//! Why the column-0 test is also the block-scalar guard: a block scalar
//! (`|`/`>`) or a quoted multi-line scalar under a column-0 key must indent
//! its continuation lines per the YAML spec (the same argument that makes
//! a column-0 `---` a safe split point in `ast::yaml_chunk`), so a column-0
//! key-shaped line cannot be interior content of one. The known residual is
//! FLOW context — a multi-line flow collection is free to place
//! `key: value` at column 0 — accepted here: the scanner is a fallback for
//! documents the grammar rejects wholesale, and the target shape is the
//! flat config.
//!
//! # Honesty
//!
//! The scan ALWAYS returns exactly one informational warning — "single
//! document exceeds the grammar's 32768-line limit; native top-level
//! outline used (N keys)" — which the merger prefixes with the file path.
//! It replaces the old abort warning ("structure truncated/empty for that
//! document"): nothing is skipped silently, and an outline that found ZERO
//! keys (e.g. one giant top-level sequence) says so. Imports/doclinks are
//! NOT covered: the merger still takes them from the aborted tree's
//! parseable prefix (`ast::imports` documents the no-warning channel on
//! that path).

use crate::types::DefinitionInfo;

/// Paranoia budget: the outline never emits more than this many top-level
/// keys per chunk. A flat config can plausibly hold tens of thousands of
/// keys; 100 000 bounds the structure output while staying far above
/// anything a real config needs, and a scan that hits the cap says so in
/// its warning instead of failing silently.
pub const YAML_NATIVE_MAX_KEYS: usize = 100_000;

/// One candidate top-level key line found by the scan.
struct TopKey {
    /// Byte offset of the key line's first byte within `source_slice` —
    /// a column-0 line, so this is also the region's first byte.
    start: usize,
    /// 0-based row of the key line within `source_slice`.
    row: u32,
    /// The key text (quotes stripped, trailing blanks trimmed).
    name: String,
}

/// Scan `source_slice` (a chunk of a larger file, or a whole file) for its
/// top-level mapping keys — see the module docs.
///
/// `byte_base`/`line_base` are the slice's origin in the FULL file: emitted
/// byte spans are shifted by `byte_base`, 1-based line spans by
/// `line_base`, so `full_source[def.byte_start..def.byte_end]` slices back
/// to the key's exact region with no post-translation.
///
/// Returns the definitions in source order plus exactly ONE informational
/// warning (the abort-path replacement message; the caller prefixes the
/// file path).
pub fn scan_yaml_outline_native(
    source_slice: &str,
    byte_base: usize,
    line_base: u32,
) -> (Vec<DefinitionInfo>, Vec<String>) {
    let bytes = source_slice.as_bytes();

    // Pass 1 — find the top-level key lines. The cap stops the WHOLE scan:
    // the capped-out key line becomes the last emitted region's boundary,
    // keeping both passes O(emitted).
    let mut keys: Vec<TopKey> = Vec::new();
    // `Some((line-start byte, row))` of the key line that exceeded the cap.
    let mut capped_at: Option<(usize, u32)> = None;
    let mut line_begin = 0usize;
    let mut row = 0u32;
    while line_begin <= bytes.len() {
        let line_end = match bytes[line_begin..].iter().position(|&b| b == b'\n') {
            Some(p) => line_begin + p,
            None => bytes.len(),
        };
        if let Some(name) = top_level_key(&bytes[line_begin..line_end]) {
            if keys.len() >= YAML_NATIVE_MAX_KEYS {
                capped_at = Some((line_begin, row));
                break;
            }
            keys.push(TopKey {
                start: line_begin,
                row,
                // The key matcher only accepts ASCII, so lossy == exact.
                name: String::from_utf8_lossy(name).into_owned(),
            });
        }
        // Step past the line REGARDLESS of whether it was a key: blank
        // lines carry rows too (a key's region is line-continuous).
        row += 1;
        line_begin = line_end + 1;
    }

    // Pass 2 — emit one definition per key. Region end:
    //  - the next key's line, content bytes only (newline run trimmed),
    //  - the capped-out key line for the last key of a capped scan,
    //  - the slice's true end for the last key of an uncapped scan (the
    //    EOF convention — a single whole-file parse swallows the trailing
    //    newline into its last node too).
    let total_lines = source_slice.lines().count() as u32;
    let mut defs: Vec<DefinitionInfo> = Vec::with_capacity(keys.len());
    for (k, key) in keys.iter().enumerate() {
        let (region_end_byte, region_end_line) = match keys.get(k + 1) {
            Some(next) => (
                crate::ast::yaml_chunk::trim_trailing_newlines(source_slice, next.start),
                next.row,
            ),
            None => match capped_at {
                Some((end, end_row)) => (
                    crate::ast::yaml_chunk::trim_trailing_newlines(source_slice, end),
                    end_row,
                ),
                None => (bytes.len(), total_lines),
            },
        };

        // Signature: the key line's text (trimmed) — the element
        // convention (`ast::elements::element_def`).
        let key_line_end = source_slice[key.start..]
            .find('\n')
            .map(|p| key.start + p)
            .unwrap_or(bytes.len());
        let signature = source_slice[key.start..key_line_end].trim().to_string();

        defs.push(DefinitionInfo {
            name: key.name.clone(),
            kind: "key".to_string(),
            line_start: line_base + key.row + 1,
            line_end: line_base + region_end_line,
            definition_line: Some(line_base + key.row + 1),
            byte_start: Some((byte_base + key.start) as u64),
            byte_end: Some((byte_base + region_end_byte) as u64),
            signature,
            container: None,
        });
    }

    // The informational message that replaces the parse-abort warning —
    // still loud, now accurate: nothing is truncated, an outline was used.
    let mut warning = format!(
        "single document exceeds the grammar's {}-line limit; native \
         top-level outline used ({} keys)",
        crate::ast::yaml_chunk::YAML_LINE_LIMIT,
        defs.len(),
    );
    if capped_at.is_some() {
        warning.push_str(&format!("; outline capped at {YAML_NATIVE_MAX_KEYS} keys"));
    }
    (defs, vec![warning])
}

/// Key text of `line` (one line's bytes, newline excluded) iff the line is
/// a column-0 top-level mapping key — see the module docs for the exact
/// shape and the rationale. Returns the key text with an optional quote
/// pair stripped and trailing blanks trimmed.
fn top_level_key(line: &[u8]) -> Option<&[u8]> {
    // Tolerate CRLF: `key:\r` is `key:`.
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    // Optional opening quote — a quoted top-level key is rare but legal.
    let quoted = matches!(line.first(), Some(b'"') | Some(b'\''));
    let quote = if quoted { line[0] } else { b'\0' };
    let rest = if quoted { &line[1..] } else { line };

    // First key character: ASCII letter or underscore. This single test
    // enforces column 0 (leading whitespace fails it) and rejects comments
    // (`#`), document markers (`---`, `...`) and sequence entries (`-`).
    let first = *rest.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = 1usize;
    while end < rest.len()
        && (rest[end].is_ascii_alphanumeric() || matches!(rest[end], b'_' | b'.' | b'-' | b' '))
    {
        end += 1;
    }

    // Optional matching closing quote directly before the colon; an
    // unclosed quote means a plain scalar (or garbage), not a key.
    if quoted {
        if rest.get(end) == Some(&quote) {
            end += 1;
        } else {
            return None;
        }
    }

    // The mapping colon, then the YAML-mandated separator: space, tab, or
    // end-of-line. This is what rejects bare URLs (`http://…` — colon
    // followed by `/`) and `a:b` (a plain scalar per YAML).
    if rest.get(end) != Some(&b':') {
        return None;
    }
    match rest.get(end + 1) {
        None => {}
        Some(b' ' | b'\t') => {}
        _ => return None,
    }

    let mut key = if quoted {
        &rest[..end - 1]
    } else {
        &rest[..end]
    };
    // Trailing blanks (`key :` forms) are not part of the name; interior
    // spaces are (`some key:` is one key). The first character is
    // alphanumeric/underscore, so this can never empty the name — the
    // check is belt and braces.
    while key.last() == Some(&b' ') {
        key = &key[..key.len() - 1];
    }
    if key.is_empty() {
        return None;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slice-back through the FULL file: definitions are emitted in
    /// full-file coordinates (bases applied), so a slice must start at
    /// `byte_base + def.byte_start`.
    fn slice_back<'a>(full: &'a str, byte_base: usize, def: &DefinitionInfo) -> &'a str {
        &full[byte_base + def.byte_start.unwrap() as usize
            ..byte_base + def.byte_end.unwrap() as usize]
    }

    #[test]
    fn flat_mapping_every_key_with_exact_regions() {
        let src = "alpha: 1\nbeta: 2\ngamma: 3\n";
        let (defs, warnings) = scan_yaml_outline_native(src, 0, 0);
        assert_eq!(defs.len(), 3);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
        for d in &defs {
            assert_eq!(d.kind, "key");
            assert_eq!(d.container, None);
            assert_eq!(d.definition_line, Some(d.line_start));
        }
        // `alpha` owns line 1 only (the next key's line minus 1); the byte
        // region ends at its last content byte (newline run trimmed).
        assert_eq!(defs[0].line_start, 1);
        assert_eq!(defs[0].line_end, 1);
        assert_eq!(slice_back(src, 0, &defs[0]), "alpha: 1");
        assert_eq!(defs[0].signature, "alpha: 1");
        // The LAST key runs to the slice end — the EOF newline is
        // swallowed, the single whole-file parse convention.
        assert_eq!(defs[2].line_start, 3);
        assert_eq!(defs[2].line_end, 3);
        assert_eq!(slice_back(src, 0, &defs[2]), "gamma: 3\n");
        // Exactly one informational (abort-replacement) warning with the
        // key count.
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("single document exceeds the grammar's 32768-line limit"),
            "warning must name the mechanism: {}",
            warnings[0]
        );
        assert!(
            warnings[0].contains("native top-level outline used (3 keys)"),
            "warning must carry the count: {}",
            warnings[0]
        );
    }

    #[test]
    fn nested_value_region_belongs_to_the_top_level_key() {
        let src = "outer:\n  a: 1\n  b: 2\n  c: 3\nnext: v\n";
        let (defs, _) = scan_yaml_outline_native(src, 0, 0);
        assert_eq!(defs.len(), 2, "nested keys must not emit");
        // `outer` spans its whole nested block (lines 1-4)...
        assert_eq!(defs[0].name, "outer");
        assert_eq!(defs[0].line_start, 1);
        assert_eq!(defs[0].line_end, 4);
        assert_eq!(
            slice_back(src, 0, &defs[0]),
            "outer:\n  a: 1\n  b: 2\n  c: 3"
        );
        // ...and the next COLUMN-0 key opens the next region.
        assert_eq!(defs[1].name, "next");
        assert_eq!(defs[1].line_start, 5);
        assert_eq!(defs[1].line_end, 5);
        assert_eq!(slice_back(src, 0, &defs[1]), "next: v\n");
    }

    #[test]
    fn non_key_lines_are_ignored() {
        let src = concat!(
            "# leading comment\n",
            "---\n",
            "real: 1\n",
            "  nested: not-top\n",
            "\ttabbed: not-top\n",
            "- seq entry\n",
            "...\n",
            "# comment between keys\n",
            "url: http://example.com/x\n",
            "plain:scalar-no-space\n",
            "'quoted key': yes\n",
            "\"dquoted\": no\n",
            "spaced key : trailing-blanks-trimmed\n",
            "last: |\n",
            "  looks: like-a-key-but-indented\n",
        );
        let (defs, _) = scan_yaml_outline_native(src, 0, 0);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["real", "url", "quoted key", "dquoted", "spaced key", "last"]
        );
        // `real` owns everything up to the next column-0 key (`url`): the
        // indented lines, the sequence entry, the `...` and the comments.
        assert_eq!(defs[0].line_start, 3);
        assert_eq!(defs[0].line_end, 8);
        // `url` IS a key (`url: ` — colon followed by space); its VALUE's
        // `//` colon is irrelevant. `plain:scalar-no-space` is not a
        // mapping at all (no separator after the colon) and is skipped —
        // but it still lands inside `url`'s region (line 10).
        assert_eq!(defs[1].name, "url");
        assert_eq!(defs[1].line_start, 9);
        assert_eq!(defs[1].line_end, 10);
        // Quoted keys are recognized and unquoted; interior spaces survive.
        assert_eq!(defs[2].name, "quoted key");
        assert_eq!(defs[3].name, "dquoted");
        assert_eq!(defs[4].name, "spaced key");
        // The block scalar's indented body (a key-shaped line!) is inside
        // `last`'s region, never emitted, and the EOF convention keeps the
        // trailing newline in the last region's bytes.
        let last = defs.last().unwrap();
        assert_eq!(last.name, "last");
        assert_eq!(last.line_start, 14);
        assert_eq!(last.line_end, 15);
        assert_eq!(
            slice_back(src, 0, last),
            "last: |\n  looks: like-a-key-but-indented\n"
        );
    }

    #[test]
    fn bases_rebase_spans_into_full_file_coordinates() {
        // Chunk geometry: the slice sits at byte offset 1000 in the full
        // file; its row 0 is full-file row 50 (line_base). Both bases are
        // pure arithmetic — no post-translation may be needed.
        let chunk = "alpha: 1\nbeta: 2\n";
        let mut full = vec![b'x'; 1000];
        full.extend_from_slice(chunk.as_bytes());
        let full = String::from_utf8(full).expect("ascii");
        let (defs, _) = scan_yaml_outline_native(chunk, 1000, 50);
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].line_start, 51); // 50 + row 0 + 1
        assert_eq!(defs[0].line_end, 51); // next key's line minus 1
        assert_eq!(defs[0].definition_line, Some(51));
        assert_eq!(defs[0].byte_start, Some(1000));
        assert_eq!(defs[0].byte_end, Some(1000 + 8)); // "alpha: 1"
        assert_eq!(&full[1000..1008], slice_back(&full, 0, &defs[0]));
        assert_eq!(defs[1].line_start, 52);
        assert_eq!(defs[1].byte_start, Some(1000 + 9));
        assert_eq!(defs[1].byte_end, Some((1000 + chunk.len()) as u64)); // EOF convention
    }

    #[test]
    fn crlf_lines_are_keys_too() {
        let src = "alpha: 1\r\nbeta: 2\r\n";
        let (defs, _) = scan_yaml_outline_native(src, 0, 0);
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].name, "alpha");
        assert_eq!(defs[0].line_end, 1);
        // The region ends at the last content byte — the \r\n run is
        // trimmed; the LAST key swallows the whole trailing run.
        assert_eq!(slice_back(src, 0, &defs[0]), "alpha: 1");
        assert_eq!(slice_back(src, 0, &defs[1]), "beta: 2\r\n");
        assert_eq!(defs[1].line_end, 2);
    }

    #[test]
    fn zero_keys_is_loud_not_silent() {
        // One top-level SEQUENCE: no mapping keys exist, so the outline is
        // empty — and the informational warning says exactly that instead
        // of silently emitting nothing.
        let src = "- a\n- b\n- c\n";
        let (defs, warnings) = scan_yaml_outline_native(src, 0, 0);
        assert!(defs.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("native top-level outline used (0 keys)"),
            "zero-key outline must say so: {}",
            warnings[0]
        );
    }

    #[test]
    fn budget_caps_emitted_keys_and_the_warning_says_so() {
        // MAX + 5 flat keys: the scan stops at the cap; the last emitted
        // key's region ends at the first capped-out key line (content
        // bytes), and the warning names the cap.
        let n = YAML_NATIVE_MAX_KEYS + 5;
        let mut src = String::with_capacity(n * 8);
        for i in 0..n {
            src.push_str(&format!("k{i}: v\n"));
        }
        let (defs, warnings) = scan_yaml_outline_native(&src, 0, 0);
        assert_eq!(defs.len(), YAML_NATIVE_MAX_KEYS, "the cap bounds emission");
        assert_eq!(
            warnings.len(),
            1,
            "still exactly one warning: {:?}",
            warnings
        );
        assert!(
            warnings[0].contains(&format!("used ({YAML_NATIVE_MAX_KEYS} keys)")),
            "{}",
            warnings[0]
        );
        assert!(
            warnings[0].contains(&format!("capped at {YAML_NATIVE_MAX_KEYS} keys")),
            "the cap must be named: {}",
            warnings[0]
        );
        // The last emitted key's region stops at the first un-emitted key
        // line, content bytes only.
        let last = defs.last().unwrap();
        assert_eq!(
            slice_back(&src, 0, last),
            format!("k{}: v", YAML_NATIVE_MAX_KEYS - 1)
        );
        assert_eq!(last.line_start, YAML_NATIVE_MAX_KEYS as u32);
        assert_eq!(last.line_end, YAML_NATIVE_MAX_KEYS as u32);
    }
}
