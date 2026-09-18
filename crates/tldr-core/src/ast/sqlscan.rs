//! Native SQL schema-structure scanning (sql-schema-scan-v1 — `sqlscan`).
//!
//! `.sql`/`.ddl` files NEVER go through tree-sitter: crates.io publishes only
//! `tree-sitter-sql` **0.0.2** (the DerekStride grammar, source-only, dead
//! since 2021 — audit note in the root `Cargo.toml`), so there is no buildable
//! grammar to wire and no `Language::Sql` variant. The Log (`ast::logs`, no
//! grammar exists), Text (`ast::toc`, no syntax can have a grammar) and
//! CSV/TSV (`ast::csvscan`, the only published crate is unbuildable) scanners
//! are the no-grammar precedents this module follows. `.sql` keeps resolving
//! through the unknown-extension ladder (`validation::resolve_target_language`
//! → `Language::Text`, unknown-ext-text-v1 — that ladder's own doc comment
//! names `schema.sql`), and this module is reached ONLY from the
//! `Language::Text` early-return in `ast::extractor` (path predicate
//! [`is_sql_path`], checked before the env/ignore/TOC dispatch) and from
//! `ast::imports::get_imports` (same path predicate, before the language-arm
//! dispatch — the language arm cannot tell a `.sql` Text file from a `.txt`
//! one).
//!
//! # Scope — a schema OUTLINE, not a SQL parser (the honest bound)
//!
//! This is a **schema-outline scanner**: it recognizes the DDL statements
//! that describe a database's shape, across the dialect soup real dumps ship
//! (PostgreSQL / MySQL / SQLite / T-SQL / Oracle). It is NOT a SQL parser:
//! there is no expression grammar, no dialect switch, and **column-level
//! extraction is deliberately NOT implemented** (a table's columns are future
//! work — the region pins them in the source for a reader, and `signature`
//! shows the statement's first line).
//!
//! # The statement splitter (tokenizer-aware — the rules, because they ARE
//! the spec)
//!
//! A schema file is split into statements at `;` characters that are TOP-LEVEL
//! — i.e. not inside any of the masked regions below. The splitter is a single
//! left-to-right byte pass (SQL quote/delimiter syntax is ASCII; multi-byte
//! UTF-8 sequences can never match an ASCII delimiter, so byte offsets stay
//! exact and UTF-8 content survives untouched):
//!
//! | Mask | Opens | Closes | Notes |
//! |------|-------|--------|-------|
//! | line comment | `--` | end of line | the `\n` itself stays unmasked (it is structure, not content) |
//! | block comment | `/*` | `*/` | non-nesting (the SQL standard, and every mainstream engine) |
//! | single-quoted string | `'` | `'` | `''` is an escaped quote (standard SQL doubling), NOT a closer |
//! | double-quoted identifier | `"` | `"` | `""` doubling (standard SQL delimited identifier) |
//! | backtick identifier | `` ` `` | `` ` `` | MySQL; ``` `` ``` doubling |
//! | bracket identifier | `[` | `]` | T-SQL; `]]` doubling |
//! | dollar-quoted body | `$tag$` | the same `$tag$` | PostgreSQL; the tag is the identifier-shaped run between two `$`s (empty tag = `$$`), it cannot contain `$`, and it must not START with a digit (that would collide with positional params, per the PostgreSQL lexer) |
//!
//! An unterminated quote/dollar-body consumes to end of source (a stray `$$`
//! cannot silently split every following statement in half). Comments are the
//! only masks the splitter ALLOWS inside a statement region — they are part of
//! the file's SQL text; a `;` inside any quoted/dollar mask never splits.
//!
//! Known splitter limitation (bounded, accepted): procedural `BEGIN … END`
//! bodies (SQLite triggers, T-SQL/MySQL stored routines) have no body mask —
//! the `;` separating their inner statements DOES split, so such a definition
//! reports a region truncated at its first inner `;` (the definition itself
//! still emits: its keyword head is intact). Only PostgreSQL dollar-quoting is
//! body-aware. MySQL dump-view conditionals (`/*!50001 CREATE … VIEW … */`)
//! sit entirely inside a comment and therefore emit nothing either.
//!
//! # The kind table (the format contract, documented because it IS the spec)
//!
//! Each statement is classified by a case-insensitive, statement-anchored
//! keyword match (the regexes run on a comment-masked copy of the statement —
//! `CREATE /* x */ TABLE` still matches — anchored at the statement's first
//! keyword). FIRST matching rule wins; anything else (DML, `GRANT`, `DROP`,
//! `SET`, `CREATE SEQUENCE`, `CREATE DATABASE`, …) emits nothing — the set is
//! deliberately closed; new kinds are additive future work:
//!
//! | Statement shape | kind | name |
//! |-----------------|------|------|
//! | `CREATE [OR REPLACE] [GLOBAL\|LOCAL] [TEMP\|TEMPORARY\|UNLOGGED] TABLE [IF NOT EXISTS] <name>` | `"table"` | schema-qualified name as written |
//! | `CREATE [OR REPLACE] [MATERIALIZED] VIEW [IF NOT EXISTS] <name>` | `"view"` | idem |
//! | `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] <name>` | `"index"` | idem (a nameless `CREATE INDEX ON t …` emits nothing — an unnamed index has no name to report) |
//! | `CREATE [OR REPLACE] FUNCTION [IF NOT EXISTS] <name>` | `"function"` | idem (postgres `…(args)` and oracle `… RETURN` forms both key on the name token; the paren list is not required) |
//! | `CREATE [OR REPLACE] PROCEDURE [IF NOT EXISTS] <name>` | `"procedure"` | idem |
//! | `CREATE [OR REPLACE] [CONSTRAINT] TRIGGER [IF NOT EXISTS] <name>` | `"trigger"` | idem |
//! | `CREATE SCHEMA [IF NOT EXISTS] <name>` | `"schema"` | idem (the `AUTHORIZATION role` form emits nothing — its name slot is the keyword `AUTHORIZATION`, not a schema name) |
//! | `CREATE [OR REPLACE] TYPE [IF NOT EXISTS] [BODY] <name>` | `"type"` | idem (`TYPE BODY` is Oracle's second half of the same definition) |
//! | `ALTER TABLE [ONLY] <tbl> [IF EXISTS] ADD CONSTRAINT <name>` | `"constraint"` | the CONSTRAINT's name (the table is the statement's target, not the definition; unnamed `ADD CHECK`/`ADD PRIMARY KEY` emit nothing) |
//!
//! The name is a dotted chain of identifiers — each part bare
//! (`[A-Za-z_][A-Za-z0-9_$#]*`, non-ASCII letters allowed), double-quoted,
//! backtick-quoted or bracket-quoted — joined by `.` (whitespace around the
//! dot collapses). Quotes/backticks/brackets are STRIPPED from every part
//! (`public."User Table"` → `public.User Table`); the qualified spelling is
//! otherwise kept exactly as written. A statement whose name slot is missing,
//! keyword-shadowed, or unparseable emits nothing.
//!
//! # Region / span semantics (the `ast::toc`/`ast::dotfiles` convention)
//!
//! `byte_start` is the statement chunk's first non-whitespace byte — a comment
//! block opening the chunk is attached trivia and stays inside the region (the
//! `line_start`/`line_end` span includes it) — and `byte_end` is ONE PAST the
//! terminating `;` (or one past the last content byte for an unterminated
//! final statement), so `source[byte_start..byte_end]` is the exact statement
//! region, terminator included, trailing whitespace excluded.
//! `definition_line` is the line of the statement's first KEYWORD (the
//! declaration-line analogue — comments never move it, mirroring
//! `DefinitionInfo::definition_line`'s contract). `signature` is the first
//! physical line of the statement PROPER (comments skipped), trimmed and
//! truncated to 120 chars with `…` (the `ast::dotfiles` one-line-bound
//! convention: the signature orients, it does not transport).
//!
//! Known false-positive class (accepted, bounded): `COPY … FROM stdin` data
//! blocks in pg_dump output are not COPY-aware, so a data row whose text
//! happens to open with a DDL keyword shape would emit a phantom row. Data
//! rows almost never start with one (the row starts with its first column
//! value) and a phantom row is a cosmetic miss, not a wrong analysis.
//!
//! # Outbound references (`extract_sql_refs`) — the blast-radius edge
//!
//! `REFERENCES <name>` (inline column constraint and table-level
//! `FOREIGN KEY (…) REFERENCES <name>` alike) is the one reference surface a
//! schema file has: a table that references another table. One
//! [`ImportInfo`] per occurrence in source order — `module` = the referenced
//! name (same dotted/quoted/strip rules as the kind table), `is_from` =
//! `true` (referenced by name at a point of use — the doclink convention),
//! `alias` = `"references"`, `via` = `None`. No dedup: extraction stays a
//! faithful index (two occurrences are two edges); resolution is downstream.
//! **The scan runs through the same tokenizer masks**, so a `REFERENCES`
//! inside a string literal, comment or dollar-quoted body never emits.
//!
//! By DESIGN the targets do not resolve to project files: a REFERENCES target
//! is a TABLE NAME, not a path, and the document graph
//! (`analysis::doc_impact::resolve_doc_target`) resolves path strings — the
//! rows stay visible in `tldr imports` and are inert in `tldr impact` unless a
//! file happens to be named like the table. That is the honest contract: the
//! edge documents the schema relationship; it does not fabricate a file
//! mapping that does not exist.

use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;

use crate::types::{DefinitionInfo, ImportInfo};

/// Files whose EXTENSION marks them as SQL schema files (sql-schema-scan-v1):
/// `.sql` and the DDL dump spelling `.ddl` — matched on the extension
/// (case-insensitively) because the LANGUAGE ladder has no Sql variant to key
/// on: `.sql` resolves to Text via the unknown-extension rule and both
/// dispatch points key on the PATH.
#[must_use]
pub fn is_sql_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("sql") || e.eq_ignore_ascii_case("ddl"))
        .unwrap_or(false)
}

/// One raw statement chunk: the bytes between the previous top-level `;` and
/// the next one (or end of source). `semi` is the index of the terminating
/// `;`, or `source.len()` for the unterminated final chunk.
#[derive(Debug, Clone, Copy)]
struct RawStatement {
    start: usize,
    semi: usize,
}

/// Is this byte an identifier continuation char for a bare SQL identifier or
/// a dollar-quote tag? ASCII alnum + `_` + `$` + `#` + any non-ASCII byte
/// (non-ASCII letters are legal in SQL identifiers).
#[inline]
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'#' || b >= 0x80
}

/// Dollar-quote TAG char: identifier-shaped but NEVER `$` (the tag is
/// delimited by the dollars — PostgreSQL's `$tag$` cannot contain one).
#[inline]
fn is_tag_byte(b: u8) -> bool {
    is_ident_byte(b) && b != b'$'
}

/// Skip a `'…'` / `"…"` / `` `…` `` region opened at `open`. Doubled quotes
/// (`''`, `""`, ``` `` ```) are escapes, not closers. Returns the index one
/// past the closing quote, or `bytes.len()` when unterminated.
fn skip_doubled(bytes: &[u8], open: usize, quote: u8) -> usize {
    let mut j = open + 1;
    while j < bytes.len() {
        if bytes[j] == quote {
            if bytes.get(j + 1) == Some(&quote) {
                j += 2; // escaped quote
                continue;
            }
            return j + 1;
        }
        j += 1;
    }
    bytes.len()
}

/// Skip a `[…]` bracket-quoted identifier opened at `open`. `]]` is an
/// escaped bracket (T-SQL doubling). Returns the index one past `]`, or
/// `bytes.len()` when unterminated.
fn skip_bracket(bytes: &[u8], open: usize) -> usize {
    let mut j = open + 1;
    while j < bytes.len() {
        if bytes[j] == b']' {
            if bytes.get(j + 1) == Some(&b']') {
                j += 2;
                continue;
            }
            return j + 1;
        }
        j += 1;
    }
    bytes.len()
}

/// Skip a PostgreSQL dollar-quoted body `$tag$…$tag$` opened at `open`.
/// Returns `Some(index one past the CLOSING tag)` — `Some(bytes.len())` when
/// the quote never closes (consume to EOF: a stray `$$` must not split every
/// following statement) — or `None` when the `$` does not open a dollar quote
/// at all (no tag, or a tag starting with a digit, the positional-param
/// collision the PostgreSQL lexer refuses).
fn skip_dollar_quote(bytes: &[u8], open: usize) -> Option<usize> {
    let mut j = open + 1;
    if bytes.get(j).is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    while j < bytes.len() && is_tag_byte(bytes[j]) {
        j += 1;
    }
    if bytes.get(j) != Some(&b'$') {
        return None; // no closing `$` right after the tag → not a dollar quote
    }
    let tag = &bytes[open..=j]; // `$tag$` including both delimiting dollars
    let mut k = j + 1;
    while k + tag.len() <= bytes.len() {
        if &bytes[k..k + tag.len()] == tag {
            return Some(k + tag.len());
        }
        k += 1;
    }
    Some(bytes.len())
}

/// Split `source` into raw statement chunks at top-level `;` — the
/// tokenizer-aware pass described in the module docs. The FINAL chunk is
/// always returned (callers filter chunks that hold no content), so a
/// `;`-terminated source yields one empty trailing chunk.
fn split_statements(source: &str) -> Vec<RawStatement> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut chunk_start = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i = skip_doubled(bytes, i, b'\'');
            }
            b'"' => {
                i = skip_doubled(bytes, i, b'"');
            }
            b'`' => {
                i = skip_doubled(bytes, i, b'`');
            }
            b'[' => {
                i = skip_bracket(bytes, i);
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                // Line comment: mask to end of line; the `\n` stays unmasked.
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                // Block comment: non-nesting, standard SQL.
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'$' => {
                i = skip_dollar_quote(bytes, i).unwrap_or(i + 1);
            }
            b';' => {
                out.push(RawStatement {
                    start: chunk_start,
                    semi: i,
                });
                chunk_start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    out.push(RawStatement {
        start: chunk_start,
        semi: bytes.len(),
    });
    out
}

/// First non-whitespace byte at or after `from` (the chunk's content start),
/// or `None` when the chunk holds nothing but whitespace.
fn first_content_byte(bytes: &[u8], from: usize) -> Option<usize> {
    (from..bytes.len()).find(|&i| !bytes[i].is_ascii_whitespace())
}

/// Skip whitespace AND comments (`--` to end of line, `/* … */`) from `from` —
/// lands on the statement-proper start: the first byte of the first SQL token.
/// Callers bound the result to the statement region (the scan may run past a
/// chunk that ends in a comment).
fn skip_ws_and_comments(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        return i;
    }
}

/// UTF-8 sequence length for a leading byte (1 for ASCII, 2/3/4 per the lead
/// bits). Only called on bytes inside quoted regions of lossy-decoded (hence
/// well-formed) input, so a continuation byte never leads.
fn utf8_len(lead: u8) -> usize {
    match lead {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        _ => 4,
    }
}

/// Read a `"`/`` ` ``-quoted part starting at `open`; a doubled quote is an
/// escaped quote (SQL doubling). Returns `(unescaped content, index one past
/// the closing quote)`.
fn read_quoted(raw: &str, open: usize, quote: u8) -> (Option<String>, usize) {
    let bytes = raw.as_bytes();
    let mut part = String::new();
    let mut j = open + 1;
    while j < bytes.len() {
        if bytes[j] == quote {
            if bytes.get(j + 1) == Some(&quote) {
                part.push(quote as char);
                j += 2;
                continue;
            }
            return (Some(part), j + 1);
        }
        let ch_len = utf8_len(bytes[j]);
        part.push_str(&raw[j..j + ch_len]);
        j += ch_len;
    }
    (None, bytes.len())
}

/// Read a `[…]`-quoted part starting at `open`; `]]` is an escaped bracket.
fn read_bracket(raw: &str, open: usize) -> (Option<String>, usize) {
    let bytes = raw.as_bytes();
    let mut part = String::new();
    let mut j = open + 1;
    while j < bytes.len() {
        if bytes[j] == b']' {
            if bytes.get(j + 1) == Some(&b']') {
                part.push(']');
                j += 2;
                continue;
            }
            return (Some(part), j + 1);
        }
        let ch_len = utf8_len(bytes[j]);
        part.push_str(&raw[j..j + ch_len]);
        j += ch_len;
    }
    (None, bytes.len())
}

/// Parse a dotted-name region (starting exactly at `at` within `raw`) into its
/// clean spelling: one part per identifier — quoted parts unquoted and
/// unescaped — joined with `.`, whitespace around dots collapsed. Returns
/// `None` for a zero-part or empty-part parse (a nameless slot emits nothing).
fn parse_dotted_name(raw: &str, at: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut i = at;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match bytes.get(i) {
            Some(b'"') => {
                let (part, next) = read_quoted(raw, i, b'"');
                parts.push(part?);
                i = next;
            }
            Some(b'`') => {
                let (part, next) = read_quoted(raw, i, b'`');
                parts.push(part?);
                i = next;
            }
            Some(b'[') => {
                let (part, next) = read_bracket(raw, i);
                parts.push(part?);
                i = next;
            }
            Some(&b) if b.is_ascii_alphabetic() || b == b'_' || b >= 0x80 => {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                parts.push(raw[start..i].to_string());
            }
            _ => return None,
        }
        // Optional `.` separator; whitespace around it collapses away. The
        // chain ends at the first non-dot follower (`(`, `,`, whitespace+kw).
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if bytes.get(j) == Some(&b'.') {
            i = j + 1;
            continue;
        }
        break;
    }
    if parts.is_empty() || parts.iter().any(String::is_empty) {
        return None;
    }
    Some(parts.join("."))
}

/// The keyword table's shared fragments. One bare / double-quoted / backtick /
/// bracket identifier part, and a dotted chain of them captured as a named
/// group (`?P<table>` for ALTER's target table, `?P<name>` for the definition
/// name — every regex names the reported name exactly `name`).
fn dotted_ident(group: &str) -> String {
    // Doubled quotes inside a quoted part are the SQL escape (`""` / `` `` ``
    // / `]]`), so the part alternation must try the DOUBLED form at a quote —
    // a plain `[^"…]` class would end the part at the first quote of a pair
    // and truncate the name (`"we""ird"` would capture `"we"`).
    let part =
        r#"(?:"(?:[^"\n]|"")*"|`(?:[^`\n]|``)*`|\[(?:[^\]\n]|\]\])*\]|[A-Za-z_][A-Za-z0-9_$#]*)"#;
    format!(r#"(?P<{group}>{part}(?:\s*\.\s*{part})*)"#)
}

fn keyword_regex(body: &str) -> Regex {
    Regex::new(&format!(r"(?is)^\s*{body}")).expect("sqlscan keyword regex")
}

lazy_static! {
    static ref TABLE_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?(?:global\s+|local\s+)?(?:temp\s+|temporary\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref VIEW_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref INDEX_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref FUNCTION_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?function\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref PROCEDURE_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?procedure\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref TRIGGER_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref SCHEMA_RE: Regex = keyword_regex(&format!(
        r#"create\s+schema\s+(?:if\s+not\s+exists\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref TYPE_RE: Regex = keyword_regex(&format!(
        r#"create\s+(?:or\s+replace\s+)?type\s+(?:if\s+not\s+exists\s+)?(?:body\s+)?{}"#,
        dotted_ident("name")
    ));
    static ref ALTER_CONSTRAINT_RE: Regex = keyword_regex(&format!(
        r#"alter\s+table\s+(?:only\s+)?{}\s+(?:if\s+exists\s+)?add\s+constraint\s+{}"#,
        dotted_ident("table"),
        dotted_ident("name")
    ));
}

/// A captured name slot that swallowed a KEYWORD instead of a name — the
/// nameless forms the kind table refuses (`CREATE INDEX ON t …` has no index
/// name; `CREATE SCHEMA AUTHORIZATION role` names the schema by side effect).
/// A QUOTED `"on"` keeps its quotes in the raw capture and never matches, so
/// genuinely-quoted spellings survive the guard.
fn keyword_shadowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.eq_ignore_ascii_case("on") || trimmed.eq_ignore_ascii_case("authorization")
}

/// Classify a comment-masked statement text. Returns `(kind, cleaned name)`
/// for the FIRST matching keyword rule, or `None` when the statement is
/// outside the closed kind table or its name slot is unusable.
fn classify(masked: &str) -> Option<(&'static str, String)> {
    // The shapes anchor distinct keyword sequences, so the order below is
    // documentation of the table rather than disambiguation.
    let table: [(&Regex, &'static str); 9] = [
        (&TABLE_RE, "table"),
        (&VIEW_RE, "view"),
        (&INDEX_RE, "index"),
        (&FUNCTION_RE, "function"),
        (&PROCEDURE_RE, "procedure"),
        (&TRIGGER_RE, "trigger"),
        (&SCHEMA_RE, "schema"),
        (&TYPE_RE, "type"),
        (&ALTER_CONSTRAINT_RE, "constraint"),
    ];
    for (re, kind) in table {
        if let Some(caps) = re.captures(masked) {
            let raw = caps.name("name")?.as_str();
            if keyword_shadowed(raw) {
                return None;
            }
            let name = parse_dotted_name(raw, 0)?;
            return Some((kind, name));
        }
    }
    None
}

/// One-line signature bound: a first line longer than 120 chars is cut — the
/// signature orients, it does not transport (the `ast::dotfiles` convention,
/// at SQL's wider bound).
fn truncate_signature(line: &str) -> String {
    if line.chars().count() <= 120 {
        line.to_string()
    } else {
        let cut: String = line.chars().take(120).collect();
        cut + "…"
    }
}

/// Byte-length-preserving comment mask over `text` (comment bytes → spaces)
/// so the keyword regexes see a clean statement head even when comments
/// decorate it (`CREATE /* x */ TABLE`). Quoted/dollar regions are NOT masked
/// — the name capture needs them intact — and they cannot hide a comment
/// opener from this mask because they are consumed by the same skip rules the
/// splitter uses. Only the statement head matters: the mask runs over the
/// statement text, whose quotes were validated by the splitter already.
fn mask_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i = skip_doubled(bytes, i, b'\'');
            }
            b'"' => {
                i = skip_doubled(bytes, i, b'"');
            }
            b'`' => {
                i = skip_doubled(bytes, i, b'`');
            }
            b'[' => {
                i = skip_bracket(bytes, i);
            }
            b'$' => {
                i = skip_dollar_quote(bytes, i).unwrap_or(i + 1);
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let open = i;
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                let close = (i + 2).min(bytes.len());
                for slot in out[open..close].iter_mut() {
                    *slot = b' ';
                }
                i = close;
            }
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Newlines in `s` (the running-line-count helper for the monotone scan).
fn count_newlines(s: &str) -> u32 {
    s.bytes().filter(|&b| b == b'\n').count() as u32
}

/// Scan SQL `source` for the schema outline and return the definitions in
/// source order (deterministic by construction — the splitter is a single
/// forward pass). See the module docs for the kind table and span semantics.
#[must_use]
pub fn parse_sql_schema(source: &str) -> Vec<DefinitionInfo> {
    let bytes = source.as_bytes();
    let mut defs = Vec::new();
    // Running line counter, advanced chunk-by-chunk (monotone scan → O(n):
    // every source byte is newline-counted exactly once, in [cursor, next
    // content start) spans).
    let mut line = 1u32;
    let mut cursor = 0usize;
    for raw in split_statements(source) {
        let terminated = raw.semi < bytes.len();
        // Region: first content byte .. one past the terminator (or past the
        // last content byte when the final statement is unterminated).
        let Some(content_start) = first_content_byte(bytes, raw.start) else {
            continue; // whitespace-only chunk (e.g. the trailing empty one) —
                      // its bytes are re-counted by the next chunk's span
        };
        let content_end = if terminated {
            raw.semi + 1 // the `;` is part of the region
        } else {
            let mut end = raw.semi;
            while end > raw.start && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            end
        };

        // Advance the bookkeeping for EVERY content-bearing chunk, emitted or
        // not, so the counter never double-counts or skips a span: the
        // between-chunk bytes first, then the region's OWN newlines carry the
        // counter to the region's last line for the next chunk.
        line += count_newlines(&source[cursor..content_start]);
        let line_start = line;
        let line_end = line_start + count_newlines(&source[content_start..content_end]);
        line = line_end;
        cursor = content_end;

        // Statement proper: past the attached comment block (bounded to the
        // region — a chunk that ends in a comment has no statement left).
        let stmt_start = skip_ws_and_comments(bytes, content_start).min(content_end);
        if stmt_start >= content_end {
            continue; // comments/whitespace only — no statement, no emit
        }
        let stmt_line = line_start + count_newlines(&source[content_start..stmt_start]);
        let stmt_text = &source[stmt_start..content_end];

        let Some((kind, name)) = classify(&mask_comments(stmt_text)) else {
            continue;
        };

        // First physical line of the statement proper → signature.
        let head = stmt_text.split('\n').next().unwrap_or(stmt_text);
        defs.push(DefinitionInfo {
            name,
            kind: kind.to_string(),
            line_start,
            line_end,
            definition_line: Some(stmt_line),
            byte_start: Some(content_start as u64),
            byte_end: Some(content_end as u64),
            signature: truncate_signature(head.trim()),
            container: None,
        });
    }
    defs
}

/// Scan SQL `source` for `REFERENCES <name>` foreign-key targets and return
/// them as [`ImportInfo`] rows in source order (see the module docs — the
/// name-targets-don't-resolve-to-files contract lives there).
#[must_use]
pub fn extract_sql_refs(source: &str) -> Vec<ImportInfo> {
    const KEYWORD: &[u8] = b"references";
    let bytes = source.as_bytes();
    let mut refs = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i = skip_doubled(bytes, i, b'\'');
            }
            b'"' => {
                i = skip_doubled(bytes, i, b'"');
            }
            b'`' => {
                i = skip_doubled(bytes, i, b'`');
            }
            b'[' => {
                i = skip_bracket(bytes, i);
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'$' => {
                i = skip_dollar_quote(bytes, i).unwrap_or(i + 1);
            }
            b'r' | b'R' => {
                // Whole-word `references` (case-insensitive): the bytes
                // before/after must not be identifier chars, so
                // `my_references` and `references2` never trigger.
                let word_end = i + KEYWORD.len();
                if word_end <= bytes.len()
                    && bytes[i..word_end].eq_ignore_ascii_case(KEYWORD)
                    && (i == 0 || !is_ident_byte(bytes[i - 1]))
                    && !bytes.get(word_end).is_some_and(|&b| is_ident_byte(b))
                {
                    // Whitespace, then the dotted target name. A failed parse
                    // (`REFERENCES (…)` oddities) emits nothing and scanning
                    // resumes one byte past the keyword — the name region is
                    // re-walked by the masks above, so nothing can
                    // double-emit (a bare identifier cannot re-open the
                    // whole-word keyword without a separator in between, and
                    // quoted/bracketed names are consumed whole).
                    let mut j = word_end;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if let Some(name) = parse_dotted_name(source, j) {
                        refs.push(ImportInfo {
                            module: name,
                            names: Vec::new(),
                            is_from: true,
                            alias: Some("references".to_string()),
                            via: None,
                        });
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    refs
}

// =============================================================================
// Tests — the splitter rules, the kind table, the ref edges pinned
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.kind.clone()).collect()
    }

    fn names(defs: &[DefinitionInfo]) -> Vec<String> {
        defs.iter().map(|d| d.name.clone()).collect()
    }

    fn slice<'a>(source: &'a str, def: &DefinitionInfo) -> &'a str {
        &source[def.byte_start.unwrap() as usize..def.byte_end.unwrap() as usize]
    }

    // -------------------------------------------------------------------------
    // is_sql_path
    // -------------------------------------------------------------------------

    #[test]
    fn sql_predicate_covers_both_extensions_case_insensitively() {
        assert!(is_sql_path(std::path::Path::new("db/schema.sql")));
        assert!(is_sql_path(std::path::Path::new("dump.DDL")));
        assert!(is_sql_path(std::path::Path::new("migrations/001_init.Sql")));
        assert!(!is_sql_path(std::path::Path::new("notes.txt")));
        assert!(!is_sql_path(std::path::Path::new("sql")));
        assert!(!is_sql_path(std::path::Path::new("schema.sql.bak")));
        assert!(!is_sql_path(std::path::Path::new("mysqldump")));
    }

    // -------------------------------------------------------------------------
    // Kind table — one positive per row
    // -------------------------------------------------------------------------

    #[test]
    fn every_kind_in_the_table_emits() {
        let src = "\
CREATE TABLE users (id int);
create view v_users as select * from users;
CREATE UNIQUE INDEX ix_users ON users (id);
CREATE INDEX CONCURRENTLY ix_email ON users (email);
CREATE OR REPLACE FUNCTION add_one(x int) RETURNS int AS $$ BEGIN RETURN x + 1; END; $$ LANGUAGE plpgsql;
CREATE PROCEDURE purge_old() LANGUAGE SQL AS $$ DELETE FROM users; $$;
CREATE TRIGGER t_touch BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION add_one(1);
CREATE SCHEMA analytics;
CREATE TYPE mood AS ENUM ('sad', 'happy');
ALTER TABLE users ADD CONSTRAINT fk_users_team FOREIGN KEY (team_id) REFERENCES teams (id);
";
        let defs = parse_sql_schema(src);
        assert_eq!(
            kinds(&defs),
            vec![
                "table",
                "view",
                "index",
                "index",
                "function",
                "procedure",
                "trigger",
                "schema",
                "type",
                "constraint"
            ]
        );
        assert_eq!(
            names(&defs),
            vec![
                "users",
                "v_users",
                "ix_users",
                "ix_email",
                "add_one",
                "purge_old",
                "t_touch",
                "analytics",
                "mood",
                "fk_users_team"
            ]
        );
    }

    #[test]
    fn materialized_view_unique_index_and_or_replace_forms() {
        let src = "\
CREATE MATERIALIZED VIEW mv_sales AS SELECT * FROM sales;
CREATE OR REPLACE VIEW v2 AS SELECT 1;
create or replace function zero() returns int language sql as $$ select 0 $$;
CREATE OR REPLACE PROCEDURE p2() LANGUAGE plpgsql AS $$ BEGIN END $$;
";
        let defs = parse_sql_schema(src);
        assert_eq!(kinds(&defs), vec!["view", "view", "function", "procedure"]);
        assert_eq!(names(&defs), vec!["mv_sales", "v2", "zero", "p2"]);
    }

    #[test]
    fn if_not_exists_is_accepted_everywhere_it_exists() {
        let src = "\
CREATE TABLE IF NOT EXISTS t1 (id int);
CREATE VIEW IF NOT EXISTS v1 AS SELECT 1;
CREATE INDEX IF NOT EXISTS i1 ON t1 (id);
CREATE SCHEMA IF NOT EXISTS s1;
CREATE TRIGGER IF NOT EXISTS tr1 AFTER INSERT ON t1 BEGIN SELECT 1; END;
";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["t1", "v1", "i1", "s1", "tr1"]);
        assert_eq!(
            kinds(&defs),
            vec!["table", "view", "index", "schema", "trigger"]
        );
    }

    #[test]
    fn temp_and_unlogged_and_or_replace_table_forms() {
        let src = "\
CREATE TEMP TABLE scratch (id int);
CREATE GLOBAL TEMPORARY TABLE stage (id int);
CREATE UNLOGGED TABLE fast (id int);
CREATE OR REPLACE TABLE upsertable (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(kinds(&defs), vec!["table"; 4]);
        assert_eq!(names(&defs), vec!["scratch", "stage", "fast", "upsertable"]);
    }

    #[test]
    fn pg_dump_alter_only_form_names_the_constraint() {
        let src = "ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);\n";
        let defs = parse_sql_schema(src);
        assert_eq!(kinds(&defs), vec!["constraint"]);
        assert_eq!(names(&defs), vec!["users_pkey"]);
    }

    #[test]
    fn oracle_function_without_parens_and_type_body() {
        let src = "\
CREATE FUNCTION get_sal RETURN NUMBER IS BEGIN RETURN 1; END;
CREATE OR REPLACE TYPE body_t AS OBJECT (x int);
CREATE OR REPLACE TYPE BODY body_t AS MEMBER FUNCTION f RETURN int IS BEGIN RETURN 1; END;
";
        let defs = parse_sql_schema(src);
        assert_eq!(kinds(&defs), vec!["function", "type", "type"]);
        assert_eq!(names(&defs), vec!["get_sal", "body_t", "body_t"]);
    }

    #[test]
    fn unnamed_index_schema_authorization_and_unnamed_constraint_emit_nothing() {
        // `CREATE INDEX ON t` has no index name; `CREATE SCHEMA AUTHORIZATION
        // role` names the schema by side effect; `ADD CHECK`/`ADD PRIMARY
        // KEY` are unnamed constraints — all four emit nothing.
        let src = "\
CREATE INDEX ON users (id);
CREATE SCHEMA AUTHORIZATION jones;
ALTER TABLE users ADD CHECK (id > 0);
ALTER TABLE users ADD PRIMARY KEY (id);
CREATE TABLE real_table (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["real_table"]);
    }

    #[test]
    fn dml_and_out_of_scope_ddl_emit_nothing() {
        let src = "\
INSERT INTO users VALUES (1);
UPDATE users SET id = 2;
GRANT SELECT ON users TO role;
DROP TABLE users;
CREATE SEQUENCE seq_users;
CREATE DATABASE app;
CREATE EXTENSION pg_trgm;
SET search_path = public;
SELECT 1;
";
        assert!(parse_sql_schema(src).is_empty());
    }

    // -------------------------------------------------------------------------
    // Names — quoting, qualification
    // -------------------------------------------------------------------------

    #[test]
    fn quoted_identifiers_strip_their_wrappers() {
        let src = "\
CREATE TABLE \"user table\" (id int);
CREATE TABLE `order` (id int);
CREATE TABLE [select] (id int);
CREATE TABLE \"we\"\"ird\" (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(
            names(&defs),
            vec!["user table", "order", "select", "we\"ird"]
        );
    }

    #[test]
    fn schema_qualified_names_are_kept_as_written() {
        let src = "\
CREATE TABLE public.users (id int);
CREATE TABLE \"app\".\"User Table\" (id int);
CREATE TABLE db . main . events (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(
            names(&defs),
            vec!["public.users", "app.User Table", "db.main.events"]
        );
    }

    // -------------------------------------------------------------------------
    // Splitter — masks (the statement-splitting rules pinned)
    // -------------------------------------------------------------------------

    #[test]
    fn semicolon_inside_single_quoted_string_does_not_split() {
        let src = "CREATE TABLE t (c text DEFAULT 'a;b');\nCREATE TABLE t2 (id int);\n";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["t", "t2"]);
        // The first statement's region runs to its OWN terminator.
        assert_eq!(defs[0].line_end, 1);
    }

    #[test]
    fn semicolon_inside_comments_and_quoted_identifiers_does_not_split() {
        let src = "\
-- a comment; with a semicolon
CREATE /* inline; comment */ TABLE t (id int);
CREATE TABLE \"quoted;name\" (id int);
CREATE TABLE `back;tick` (id int);
CREATE TABLE [brack;et] (id int);
CREATE TABLE last (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(
            names(&defs),
            vec!["t", "quoted;name", "back;tick", "brack;et", "last"]
        );
    }

    #[test]
    fn dollar_quoted_body_with_embedded_semicolons_stays_one_statement() {
        let src = "\
CREATE FUNCTION multi() RETURNS void AS $$
BEGIN
  INSERT INTO a VALUES (1);
  INSERT INTO b VALUES (2);
END;
$$ LANGUAGE plpgsql;
CREATE TABLE after (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["multi", "after"]);
        // The function's region spans its whole dollar-quoted body (lines
        // 1..=6 — line 7 is the next statement) and the `;`-laden body never
        // splits it.
        assert_eq!((defs[0].line_start, defs[0].line_end), (1, 6));
    }

    #[test]
    fn tagged_dollar_quotes_match_only_their_own_tag() {
        let src = "\
CREATE FUNCTION f1() RETURNS int AS $body$ SELECT 1; $$ $body$ LANGUAGE sql;
CREATE FUNCTION f2() RETURNS int AS $fn$ SELECT $$; $fn$ LANGUAGE sql;
CREATE TABLE t (id int);
";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["f1", "f2", "t"]);
    }

    #[test]
    fn unterminated_dollar_quote_consumes_to_eof_instead_of_splitting() {
        let src = "CREATE TABLE t (id int);\nCREATE FUNCTION broken() AS $$ never closed;\n";
        let defs = parse_sql_schema(src);
        // The broken function never terminates, but the split stays bounded:
        // the unterminated body is ONE trailing chunk and nothing after it is
        // fabricated.
        assert_eq!(names(&defs), vec!["t", "broken"]);
        assert_eq!(defs[1].line_end, 2);
    }

    #[test]
    fn dollar_tag_starting_with_a_digit_is_not_a_quote() {
        // `$1$` shape: the positional-param collision — the `$` is a plain
        // character, so the statements' real `;`s still split normally.
        let src = "CREATE TABLE t (id int);\nCREATE TABLE t2 (id int);\n";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["t", "t2"]);
    }

    #[test]
    fn trailing_comment_chunk_is_inert_and_keeps_line_numbers_exact() {
        let src = "CREATE TABLE a (id int);\n-- trailing note; with a semi\n";
        let defs = parse_sql_schema(src);
        assert_eq!(names(&defs), vec!["a"]);
        assert_eq!(defs[0].line_start, 1);
        assert_eq!(defs[0].line_end, 1);
    }

    // -------------------------------------------------------------------------
    // Regions, spans, signature
    // -------------------------------------------------------------------------

    #[test]
    fn regions_are_exact_byte_slices_with_the_terminator_included() {
        let src = "CREATE TABLE users (id int);\n\nCREATE TABLE teams (\n  id int\n);\n";
        let defs = parse_sql_schema(src);
        assert_eq!(slice(src, &defs[0]), "CREATE TABLE users (id int);");
        assert_eq!(defs[0].line_start, 1);
        assert_eq!(defs[0].line_end, 1);
        assert_eq!(slice(src, &defs[1]), "CREATE TABLE teams (\n  id int\n);");
        assert_eq!((defs[1].line_start, defs[1].line_end), (3, 5));
    }

    #[test]
    fn unterminated_final_statement_region_ends_at_last_content_byte() {
        let src = "CREATE TABLE t (id int);\nCREATE TABLE tail (id int)"; // no `;`
        let defs = parse_sql_schema(src);
        assert_eq!(slice(src, &defs[1]), "CREATE TABLE tail (id int)");
        assert_eq!(defs[1].line_end, 2);
    }

    #[test]
    fn leading_comments_join_the_region_but_never_move_the_declaration_line() {
        let src = "-- billing tables\n-- owned by finance\nCREATE TABLE invoices (\n  id int\n);\n";
        let defs = parse_sql_schema(src);
        assert_eq!(
            slice(src, &defs[0]),
            "-- billing tables\n-- owned by finance\nCREATE TABLE invoices (\n  id int\n);"
        );
        assert_eq!(defs[0].line_start, 1, "region starts at the comment block");
        assert_eq!(
            defs[0].definition_line,
            Some(3),
            "definition_line = the CREATE TABLE keyword line"
        );
        assert_eq!(defs[0].signature, "CREATE TABLE invoices (");
    }

    #[test]
    fn signature_is_the_first_statement_line_trimmed() {
        let src = "\n  CREATE TABLE spaces (\n    id int\n  );\n";
        let defs = parse_sql_schema(src);
        assert_eq!(defs[0].signature, "CREATE TABLE spaces (");
        assert_eq!(defs[0].definition_line, Some(2));
    }

    #[test]
    fn signature_truncates_at_120_chars_with_an_ellipsis() {
        let long_cols = "c".repeat(300);
        let src = format!("CREATE TABLE wide ({long_cols});\n");
        let defs = parse_sql_schema(&src);
        assert_eq!(defs[0].signature.chars().count(), 121); // 120 + the ellipsis
        assert!(defs[0].signature.ends_with('…'));
    }

    #[test]
    fn source_order_is_deterministic_and_whitespace_only_chunks_emit_nothing() {
        let src = ";\n;;\n   \nCREATE TABLE zeta (id int);\n\n\nCREATE TABLE alpha (id int);\n;\n";
        let defs = parse_sql_schema(src);
        assert_eq!(
            names(&defs),
            vec!["zeta", "alpha"],
            "source order, not sorted"
        );
    }

    #[test]
    fn crlf_files_slice_back_exactly() {
        let src = "CREATE TABLE a (id int);\r\nCREATE TABLE b (id int);\r\n";
        let defs = parse_sql_schema(src);
        assert_eq!(slice(src, &defs[0]), "CREATE TABLE a (id int);");
        assert_eq!(defs[0].line_end, 1);
    }

    #[test]
    fn empty_source_is_no_definitions() {
        assert!(parse_sql_schema("").is_empty());
        assert!(parse_sql_schema("\n\n  \n").is_empty());
    }

    // -------------------------------------------------------------------------
    // extract_sql_refs — the blast-radius edges
    // -------------------------------------------------------------------------

    #[test]
    fn inline_and_table_level_references_emit_rows() {
        let src = "\
CREATE TABLE a (id int, b_id int REFERENCES b_table (id));
CREATE TABLE c (
  id int,
  FOREIGN KEY (a_id) REFERENCES public.a (id)
);
";
        let refs = extract_sql_refs(src);
        assert_eq!(
            refs.iter().map(|r| r.module.clone()).collect::<Vec<_>>(),
            vec!["b_table", "public.a"]
        );
        for r in &refs {
            assert!(r.is_from, "referenced by name at a point of use");
            assert_eq!(r.alias.as_deref(), Some("references"));
            assert!(r.names.is_empty());
            assert!(r.via.is_none());
        }
    }

    #[test]
    fn references_inside_strings_comments_and_dollar_bodies_never_emit() {
        let src = "\
CREATE TABLE t (
  note text DEFAULT 'REFERENCES fake_string',
  -- REFERENCES fake_comment
  /* REFERENCES fake_block */
  body text
);
CREATE FUNCTION f() RETURNS void AS $$ INSERT INTO logs VALUES ('REFERENCES fake_dollar'); $$ LANGUAGE sql;
CREATE TABLE real_ref (t_id int REFERENCES t (id));
";
        let refs = extract_sql_refs(src);
        assert_eq!(
            refs.iter().map(|r| r.module.clone()).collect::<Vec<_>>(),
            vec!["t"],
            "only the real constraint emits"
        );
    }

    #[test]
    fn every_occurrence_emits_no_dedup() {
        let src = "CREATE TABLE a (x int REFERENCES b, y int REFERENCES b);\n";
        let refs = extract_sql_refs(src);
        assert_eq!(refs.len(), 2, "extraction stays a faithful index");
        assert!(refs.iter().all(|r| r.module == "b"));
    }

    #[test]
    fn create_target_is_not_a_reference_edge() {
        let src = "CREATE TABLE a (id int);\nCREATE TABLE b (a_id int REFERENCES a (id));\n";
        let refs = extract_sql_refs(src);
        let modules: Vec<&str> = refs.iter().map(|r| r.module.as_str()).collect();
        assert_eq!(modules, vec!["a"], "the CREATE target never emits");
    }

    #[test]
    fn quoted_and_qualified_reference_targets_keep_their_spelling() {
        let src = "CREATE TABLE a (x int REFERENCES \"quoted table\"(id), y int REFERENCES `bt`.`col`);\n";
        let refs = extract_sql_refs(src);
        assert_eq!(
            refs.iter().map(|r| r.module.clone()).collect::<Vec<_>>(),
            vec!["quoted table", "bt.col"]
        );
    }

    #[test]
    fn identifier_containing_references_is_not_a_keyword() {
        let src = "CREATE TABLE preferences (id int);\nCREATE TABLE t (p_id int REFERENCES preferences (id));\n";
        let refs = extract_sql_refs(src);
        assert_eq!(
            refs.iter().map(|r| r.module.clone()).collect::<Vec<_>>(),
            vec!["preferences"],
            "whole-word matching only"
        );
    }

    #[test]
    fn empty_source_has_no_refs() {
        assert!(extract_sql_refs("").is_empty());
        assert!(extract_sql_refs("CREATE TABLE a (id int);\n").is_empty());
    }
}
