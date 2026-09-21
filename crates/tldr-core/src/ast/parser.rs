//! Tree-sitter parser pool for efficient parsing
//!
//! Provides reusable parsers for each supported language to avoid
//! repeated initialization overhead.
//!
//! # Mitigations Addressed
//! - M1: Tree-sitter version matching (use pinned versions)
//! - M2: Unicode/encoding handling (validate UTF-8 first — zero-copy move —
//!   then fall back to lossy conversion only for invalid bytes; wide
//!   encodings are rejected up front)
//! - M13: Reuse parsers to reduce memory (parser pool)

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tree_sitter::{Language, Parser, Tree};

use crate::error::TldrError;
use crate::types::Language as TldrLanguage;
use crate::TldrResult;

/// Maximum in-memory source size the parser pool will parse
/// (`u32::MAX` bytes = 4 GiB − 1 — the exact tree-sitter ceiling).
///
/// Why not a round "4 GiB": tree-sitter stores node byte offsets in `u32`,
/// so the largest parseable source is `u32::MAX` = 2^32 − 1 bytes. The old
/// literal `4 * 1024 * 1024 * 1024` = 2^32 was one byte PAST that ceiling —
/// a source that size could never have parsed anyway. The cap now equals the
/// ceiling exactly and is aligned with the read-side policy cap
/// (`fs::oversize::MAX_FILE_SIZE_BYTES`, also `u32::MAX as u64`), so a file
/// that passes the policy check can never be rejected here for size: source
/// strings enter this pool only after the caller-side policy check, and
/// `String::from_utf8` on valid UTF-8 preserves the byte length.
///
/// History: the historical 5 MB M6 cap fought the centralized 10 MB size
/// policy in `fs::oversize` — files in (5 MB, 10 MB] passed the policy check
/// and then hard-failed here with a confusing "File too large: ... (max
/// 5242880)". limits-stretch-v1 lifted it above the policy cap of the time;
/// limits-stretch-v2 pins both to the same u32 ceiling.
pub const MAX_PARSE_SIZE: u64 = u32::MAX as u64;

/// TypeScript / JavaScript grammar dialect.
///
/// `tree-sitter-typescript` ships two distinct grammars:
/// - `LANGUAGE_TYPESCRIPT`: pure TS, faster, rejects JSX.
/// - `LANGUAGE_TSX`: TSX grammar, understands JSX expressions.
///
/// `TldrLanguage::TypeScript` and `TldrLanguage::JavaScript` both map onto
/// these two dialects depending on the file extension. `.tsx` and `.jsx`
/// route to TSX; everything else gets the non-TSX default. Languages that
/// are not TS/JS use `TsDialect::None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsDialect {
    /// Non-TS/JS language — dialect is not applicable.
    None,
    /// Plain TypeScript / JavaScript grammar (no JSX).
    Ts,
    /// TSX grammar — accepts both TSX and JSX syntax.
    Tsx,
}

impl TsDialect {
    /// Derive a dialect from an optional file path and a language.
    ///
    /// Returns `TsDialect::Tsx` for `.tsx` / `.jsx` paths on TS/JS,
    /// `TsDialect::Ts` for plain TS/JS files, and `TsDialect::None` for
    /// every other language.
    pub fn from_path_and_lang(path: Option<&Path>, lang: TldrLanguage) -> Self {
        match lang {
            TldrLanguage::TypeScript | TldrLanguage::JavaScript => {
                match path
                    .and_then(|p| p.extension())
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_ascii_lowercase())
                {
                    Some(ref e) if e == "tsx" || e == "jsx" => TsDialect::Tsx,
                    _ => TsDialect::Ts,
                }
            }
            _ => TsDialect::None,
        }
    }
}

/// Composite cache key for the parser pool.
///
/// The old pool keyed parsers by `TldrLanguage` alone, which collapsed the
/// TS and TSX grammars into one slot. A TS-grammar parser and a TSX-grammar
/// parser are different tree-sitter objects and must not share a slot —
/// otherwise calling `set_language` on every borrow would either thrash the
/// cache or (worse) silently reuse the wrong grammar on a cache miss.
///
/// The new key is `(TldrLanguage, TsDialect)`. Non-TS/JS languages use
/// `TsDialect::None`, preserving their old single-slot behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParserKey {
    /// Logical TLDR language (Python, TypeScript, ...).
    pub lang: TldrLanguage,
    /// Grammar dialect — only meaningful for TS/JS, `None` otherwise.
    pub dialect: TsDialect,
}

impl ParserKey {
    /// Build a cache key from a language and dialect.
    pub fn new(lang: TldrLanguage, dialect: TsDialect) -> Self {
        Self { lang, dialect }
    }
}

/// Thread-safe parser pool that reuses parsers per `(language, dialect)`.
pub struct ParserPool {
    parsers: Mutex<HashMap<ParserKey, Parser>>,
}

impl ParserPool {
    /// Create a new parser pool
    pub fn new() -> Self {
        Self {
            parsers: Mutex::new(HashMap::new()),
        }
    }

    /// Get tree-sitter Language for a TLDR language.
    ///
    /// For TS and JS this returns the non-TSX default. Callers that have a
    /// path and need JSX-aware parsing (i.e. `.tsx` / `.jsx`) should use
    /// [`Self::parse_file`] or [`Self::parse_with_path`] instead; those
    /// route through [`Self::select_ts_grammar`] and pick up
    /// `LANGUAGE_TSX` from the path extension.
    pub fn get_ts_language(lang: TldrLanguage) -> Option<Language> {
        match lang {
            TldrLanguage::Python => Some(tree_sitter_python::LANGUAGE.into()),
            TldrLanguage::TypeScript | TldrLanguage::JavaScript => {
                Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            }
            TldrLanguage::Go => Some(tree_sitter_go::LANGUAGE.into()),
            TldrLanguage::Rust => Some(tree_sitter_rust::LANGUAGE.into()),
            TldrLanguage::Java => Some(tree_sitter_java::LANGUAGE.into()),
            // P2 languages - Phase 2: C and C++
            TldrLanguage::C => Some(tree_sitter_c::LANGUAGE.into()),
            TldrLanguage::Cpp => Some(tree_sitter_cpp::LANGUAGE.into()),
            // P2 languages - Phase 3: Ruby
            TldrLanguage::Ruby => Some(tree_sitter_ruby::LANGUAGE.into()),
            // P2 languages - Phase 4: C#, Scala, PHP
            TldrLanguage::CSharp => Some(tree_sitter_c_sharp::LANGUAGE.into()),
            TldrLanguage::Scala => Some(tree_sitter_scala::LANGUAGE.into()),
            // Note: PHP uses LANGUAGE_PHP (not LANGUAGE) - includes PHP opening tag support
            TldrLanguage::Php => Some(tree_sitter_php::LANGUAGE_PHP.into()),
            // P2 languages - Phase 5: Lua, Luau, Elixir
            TldrLanguage::Lua => Some(tree_sitter_lua::LANGUAGE.into()),
            TldrLanguage::Luau => Some(tree_sitter_luau::LANGUAGE.into()),
            TldrLanguage::Elixir => Some(tree_sitter_elixir::LANGUAGE.into()),
            TldrLanguage::Ocaml => Some(tree_sitter_ocaml::LANGUAGE_OCAML.into()),
            TldrLanguage::Kotlin => Some(tree_sitter_kotlin_ng::LANGUAGE.into()),
            TldrLanguage::Swift => Some(tree_sitter_swift::LANGUAGE.into()),
            // Formats extension (2025-09): data/config/markup/web/shell.
            // XML family routes through LANGUAGE_XML (SVG/XSD/XSL are XML
            // documents; the DTD grammar is intentionally not wired).
            TldrLanguage::Json => Some(tree_sitter_json::LANGUAGE.into()),
            TldrLanguage::Yaml => Some(tree_sitter_yaml::LANGUAGE.into()),
            TldrLanguage::Toml => Some(tree_sitter_toml_ng::LANGUAGE.into()),
            TldrLanguage::Xml => Some(tree_sitter_xml::LANGUAGE_XML.into()),
            TldrLanguage::Html => Some(tree_sitter_html::LANGUAGE.into()),
            TldrLanguage::Css => Some(tree_sitter_css::LANGUAGE.into()),
            TldrLanguage::Bash => Some(tree_sitter_bash::LANGUAGE.into()),
            // LaTeX batch (2025-11): document markup flows through the same
            // format-tier grammar wiring. tree-sitter-latex exports its
            // `LANGUAGE` LanguageFn through the tree-sitter-language bridge
            // (like the formats above), so it loads against the pinned
            // tree-sitter 0.25 runtime.
            TldrLanguage::Latex => Some(codebook_tree_sitter_latex::LANGUAGE.into()),
            // Markdown batch (2026-09): document markup joins the format
            // tier. tree-sitter-md 0.5.3 exports TWO LanguageFns — `LANGUAGE`
            // (the BLOCK grammar) and `INLINE_LANGUAGE` (inline content) —
            // with no combined language. We wire the BLOCK grammar only:
            // headings, code fences and pipe tables are block nodes, which is
            // everything the element walker (`ast::elements::walk_markdown`)
            // consumes. The inline grammar would require injection parsing
            // (parse every `inline` node a second time under INLINE_LANGUAGE
            // and splice the trees); until that exists, inline spans remain
            // opaque text inside `inline` nodes — the documented trade-off.
            // The crate's `tree-sitter ^0.26` dep is optional and only
            // activated by its `parser` feature, which we do NOT enable, so
            // the LanguageFn rides the tree-sitter-language bridge and loads
            // against the pinned ts 0.25 runtime (verified by
            // grammar_stability_test).
            TldrLanguage::Markdown => Some(tree_sitter_md::LANGUAGE.into()),
            // Log batch: NO grammar. No maintained log grammar exists on
            // crates.io (404 audit), so `Language::Log` deliberately has no
            // tree-sitter mapping — a direct `parse(source, Log)` call is
            // UnsupportedLanguage. Log content is consumed exclusively by
            // the native scanner in `ast::logs`; `parse_file_with_lang`
            // short-circuits before this would ever matter.
            TldrLanguage::Log => None,
            // Plain-text batch: NO grammar, for a stronger reason than
            // logs — plain text has NO SYNTAX to parse. There is nothing a
            // tree-sitter grammar could be written against, so
            // `Language::Text` deliberately has no tree-sitter mapping (a
            // direct `parse(source, Text)` call is UnsupportedLanguage).
            // Text content is consumed by the heuristic TOC scanner in
            // `ast::toc` (structure) and the reference scanner in
            // `ast::doclinks` (imports) — both regex-free-of-grammars,
            // text-only passes.
            TldrLanguage::Text => None,
            // CSV/TSV batch: NO grammar, and not for lack of trying — the
            // only CSV grammar crate on crates.io (`tree-sitter-csv` 1.2.0,
            // last publish 2024-01-24) is UNBUILDABLE here: its build-dep
            // `cc ~1.0.82` semver-conflicts with the `cc ^1.2.10` the pinned
            // tree-sitter 0.25 stack requires (cargo refuses the duplicate),
            // and its exports are raw ts-0.20-era `language_csv()` functions
            // with NO tree-sitter-language bridge LanguageFn (verified by
            // build probe; audit note in the root Cargo.toml next to the
            // tree-sitter-sql comment). So `Language::Csv`/`Language::Tsv`
            // deliberately have no tree-sitter mapping — a direct
            // `parse(source, Csv)` call is UnsupportedLanguage. CSV/TSV
            // content is consumed exclusively by the native RFC 4180 record
            // scanner in `ast::csvscan`; `parse_file_with_lang` short-
            // circuits before this would ever matter.
            TldrLanguage::Csv | TldrLanguage::Tsv => None,
        }
    }

    /// Pick the right TS/JS grammar from a path extension.
    ///
    /// - `.tsx` / `.jsx` -> `LANGUAGE_TSX` (JSX-aware).
    /// - Everything else -> `LANGUAGE_TYPESCRIPT` (the conservative default).
    ///
    /// `tree-sitter-typescript` does not ship a dedicated JSX grammar, so
    /// `.jsx` files are routed through the TSX grammar as well — it
    /// understands JSX syntax without the TS type annotations we'd have
    /// otherwise hit error-recovery on.
    fn select_ts_grammar(path: Option<&Path>) -> Language {
        match path
            .and_then(|p| p.extension())
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
        {
            Some(ref e) if e == "tsx" || e == "jsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
            _ => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        }
    }

    /// Resolve `(language, path)` to a concrete tree-sitter grammar.
    fn resolve_grammar(lang: TldrLanguage, path: Option<&Path>) -> Option<Language> {
        match lang {
            TldrLanguage::TypeScript | TldrLanguage::JavaScript => {
                Some(Self::select_ts_grammar(path))
            }
            _ => Self::get_ts_language(lang),
        }
    }

    /// Parse source code using the path-less default grammar.
    ///
    /// For TS/JS this returns `LANGUAGE_TYPESCRIPT` (non-TSX). Callers
    /// that know the original file path should prefer
    /// [`Self::parse_with_path`] or [`Self::parse_file`] so that `.tsx`
    /// and `.jsx` files get routed to the TSX grammar.
    ///
    /// # Arguments
    /// * `source` - Source code to parse (UTF-8)
    /// * `lang` - Programming language
    ///
    /// # Returns
    /// * `Ok(Tree)` - Parsed syntax tree
    /// * `Err(TldrError::UnsupportedLanguage)` - Language not supported
    /// * `Err(TldrError::ParseError)` - Parsing failed
    pub fn parse(&self, source: &str, lang: TldrLanguage) -> TldrResult<Tree> {
        self.parse_with_path(source, lang, None)
    }

    /// Parse source code, using the file path (if known) to pick the
    /// right dialect of the tree-sitter grammar.
    ///
    /// When `path` is `Some`, this inspects the extension and routes
    /// `.tsx` / `.jsx` files through `LANGUAGE_TSX`. All other paths (and
    /// `None`) use the language's default grammar.
    ///
    /// The parser cache is keyed on `(language, dialect)`, so a TS-grammar
    /// parser and a TSX-grammar parser coexist in distinct slots and are
    /// reused across calls with the same dialect.
    pub fn parse_with_path(
        &self,
        source: &str,
        lang: TldrLanguage,
        path: Option<&Path>,
    ) -> TldrResult<Tree> {
        // Check file size - M6 mitigation
        if (source.len() as u64) > MAX_PARSE_SIZE {
            return Err(TldrError::ParseError {
                file: path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
                line: None,
                message: format!(
                    "File too large: {} bytes (max {})",
                    source.len(),
                    MAX_PARSE_SIZE
                ),
            });
        }

        let ts_lang = Self::resolve_grammar(lang, path)
            .ok_or_else(|| TldrError::UnsupportedLanguage(lang.to_string()))?;
        let dialect = TsDialect::from_path_and_lang(path, lang);
        let key = ParserKey::new(lang, dialect);

        // Get or create parser for this (lang, dialect) pair, load its
        // grammar, and parse. Slot creation is `Parser::new()` ONLY: the
        // grammar load below is the fallible `set_language`, so a first-use
        // failure maps onto `TldrError::ParseError` like every other
        // grammar failure (FIX-1a: the old `.expect` inside the
        // slot-creation closure panicked on first use — on a rayon worker
        // that aborts the whole process — while the very next statement
        // mapped the SAME failure into a typed error).
        let mut parsers = self.parsers.lock().unwrap();
        let parser = acquire_pooled_parser(&mut parsers, key, &ts_lang, path)?;

        parser
            .parse(source, None)
            .ok_or_else(|| TldrError::ParseError {
                file: path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
                line: None,
                message: "Parsing returned None".to_string(),
            })
    }

    /// Parse a file from disk.
    ///
    /// Dispatches to the grammar dialect appropriate for the file
    /// extension (`.tsx` / `.jsx` route to TSX). Handles encoding with
    /// UTF-8 lossy fallback (M2 mitigation).
    pub fn parse_file(&self, path: &std::path::Path) -> TldrResult<(Tree, String, TldrLanguage)> {
        self.parse_file_with_lang(path, None)
    }

    /// Parse a file from disk, optionally honoring a caller-supplied
    /// language hint over path-extension detection.
    ///
    /// When `lang_hint` is `Some(_)`, that language is used directly and
    /// the file extension is ignored for language selection. This lets
    /// callers (e.g. `tldr imports myscript --lang python`) parse files
    /// with non-standard or missing extensions correctly.
    ///
    /// When `lang_hint` is `None`, behavior matches [`Self::parse_file`]:
    /// the language is inferred from the path extension and an
    /// [`TldrError::UnsupportedLanguage`] is returned if no language can
    /// be determined.
    ///
    /// The path is still threaded into [`Self::parse_with_path`] so the
    /// TSX/JSX dialect is picked up for `.tsx` / `.jsx` files when the
    /// caller hint resolves to TypeScript or JavaScript.
    ///
    /// # Arguments
    /// * `path` - Path to the file on disk
    /// * `lang_hint` - Optional language override that takes precedence
    ///   over path-extension detection
    ///
    /// # Returns
    /// * `Ok((tree, source, lang))` - Parsed tree plus the language that
    ///   was actually used (the hint when supplied, else the detected
    ///   language)
    /// * `Err(TldrError::UnsupportedLanguage)` - No hint and the
    ///   extension does not map to a supported language
    /// * `Err(TldrError::PathNotFound | PermissionDenied | IoError)` -
    ///   Filesystem errors reading the file
    /// * `Err(TldrError::ParseError)` - Parsing failed
    pub fn parse_file_with_lang(
        &self,
        path: &std::path::Path,
        lang_hint: Option<TldrLanguage>,
    ) -> TldrResult<(Tree, String, TldrLanguage)> {
        parse_file_pipeline(path, lang_hint, &ParseStrategy::Pool(self))
    }
}

/// Get or create the pooled parser for `key` and put it on `ts_lang`.
///
/// FIX-1a (grammar-load panic): the slot is created as a bare
/// `Parser::new()` — no `set_language` inside the `or_insert_with` closure —
/// and the grammar load below is the SAME fallible call the pool already ran
/// defensively on every borrow. A grammar that fails to load therefore maps
/// onto `TldrError::ParseError` on first use exactly like on reuse, instead
/// of `.expect`-panicking inside a slot-creation closure (a panic in a rayon
/// worker aborts the whole process). On success the behavior is unchanged:
/// the slot's grammar is (re-)set once per parse, as before.
fn acquire_pooled_parser<'m>(
    parsers: &'m mut HashMap<ParserKey, Parser>,
    key: ParserKey,
    ts_lang: &Language,
    path: Option<&Path>,
) -> TldrResult<&'m mut Parser> {
    // `Parser: Default` and `Parser::default()` IS `Parser::new()` — the
    // slot is a bare parser, the grammar load below is the fallible step.
    let parser = parsers.entry(key).or_default();
    // Defensive re-set: if a previous borrow left the cached parser on a
    // different grammar (shouldn't happen with the new key, but cheap
    // insurance) this snaps it back before parsing — and on a FRESH slot it
    // IS the first grammar load.
    parser
        .set_language(ts_lang)
        .map_err(|e| TldrError::ParseError {
            file: path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
            line: None,
            message: format!("Failed to set language: {}", e),
        })?;
    Ok(parser)
}

/// Where the file-parse pipeline acquires its `tree_sitter::Parser`
/// (PERF-2): the global [`PARSER_POOL`] for single-file/small-corpus
/// callers, or the per-thread parser cache for the parallel hot paths.
///
/// The global pool is one mutex-guarded map whose guard is held across
/// the whole `parse`, so under rayon it serializes every worker;
/// `tree_sitter::Parser` is also `!Send`, which is why the parallel arm
/// keeps one parser per thread instead.
enum ParseStrategy<'a> {
    Pool(&'a ParserPool),
    ThreadLocal,
}

impl ParseStrategy<'_> {
    fn parse(&self, source: &str, lang: TldrLanguage, path: Option<&Path>) -> TldrResult<Tree> {
        match self {
            ParseStrategy::Pool(pool) => pool.parse_with_path(source, lang, path),
            ParseStrategy::ThreadLocal => parse_with_path_threadlocal(source, lang, path),
        }
    }
}

/// Shared file-parse pipeline behind [`ParserPool::parse_file_with_lang`]
/// and its PERF-2 thread-local twin [`parse_file_with_lang_threadlocal`]:
/// resolve the language (hint over extension), enforce the size policy,
/// handle the native-scanner arms (JSONL/Log/Text/CSV), read + decode the
/// source, then parse it with the caller's parse strategy.
///
/// The strategy indirection is the whole point: parallel hot paths parse
/// through the per-thread parser cache (pool access would serialize every
/// rayon worker on one mutex), while single-file callers keep the global
/// pool — every arm below stays shared, not duplicated.
fn parse_file_pipeline(
    path: &std::path::Path,
    lang_hint: Option<TldrLanguage>,
    strategy: &ParseStrategy<'_>,
) -> TldrResult<(Tree, String, TldrLanguage)> {
    // Resolve language: hint wins over extension detection so that
    // extensionless files (e.g. `myscript --lang python`) parse
    // correctly. Falls back to extension detection when no hint.
    let lang = match lang_hint {
        Some(l) => l,
        None => TldrLanguage::from_path(path).ok_or_else(|| {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            TldrError::UnsupportedLanguage(ext)
        })?,
    };

    // typescript-large-file-perf-v1: enforce the file-size policy
    // BEFORE reading the file into memory. `parse_file_with_lang`
    // is the single chokepoint every parse-based command goes
    // through (structure, calls, smells, dead, secure, …), so
    // applying the cap here gives uniform skip behaviour across
    // commands. Auto-generated / minified files (`.d.ts`,
    // `.min.js`, `.bundle.css`, …) get a stricter 512 MiB cap;
    // normal source files keep the u32::MAX (4 GiB − 1) cap — the
    // tree-sitter node-offset ceiling (limits-stretch-v2).
    // See `crate::fs::oversize` for the full policy.
    // WithinLimit / Unknown: fall through to the existing read path.
    // `Unknown` (stat failed) lets the existing I/O error handling
    // produce the right error variant.
    if let crate::fs::oversize::SizeCheck::Oversize {
        size_bytes,
        max_bytes,
        ..
    } = crate::fs::oversize::check_size(path)
    {
        return Err(TldrError::FileTooLarge {
            path: path.to_path_buf(),
            size_mb: (size_bytes as usize).div_ceil(1024 * 1024),
            max_mb: (max_bytes as usize).div_ceil(1024 * 1024),
        });
    }

    // formats-extension-v1 (2025-09): `.jsonl`/`.ndjson` files are one
    // JSON document per row and are NEVER read whole — parse the first
    // non-blank row's tree instead (bounded memory, see `ast::jsonl`).
    // Structure output for a JSON document is empty, which is exactly
    // the "one JSON file per row" equivalence; `tldr structure` attaches
    // full row-health stats via `jsonl_stream` (see `get_code_structure`).
    if lang == TldrLanguage::Json && crate::ast::jsonl::is_jsonl_path(path) {
        return match crate::ast::jsonl::first_row_tree(path)? {
            Some((tree, row_text)) => Ok((tree, row_text, lang)),
            // Empty (all-blank) JSONL: a valid empty parse, no content.
            None => Ok((strategy.parse("", lang, None)?, String::new(), lang)),
        };
    }

    // Log batch: `.log` files NEVER go through tree-sitter — no
    // maintained log grammar exists on crates.io (404 audit), and the
    // native, streaming scanner in `ast::logs` is the ONLY consumer of
    // log content. `parse_file_with_lang` still has to honor its
    // `(Tree, String, Language)` contract, so — mirroring the
    // all-blank-JSONL arm above — it returns an EMPTY tree with empty
    // source without reading the file (a GiB log costs nothing here).
    // The tree is a structural placeholder that Log consumers never
    // inspect: the `get_code_structure` hook early-returns to
    // `ast::logs` before any tree walk happens.
    //
    // The placeholder tree is produced by parsing `""` under the Bash
    // grammar (an empty shell `program` — the least-surprising clean
    // empty parse); asserting `!has_error()` is pinned by the unit test
    // below. Direct `parse(source, Log)` calls (no file) still fail
    // with UnsupportedLanguage, which is the honest answer.
    if lang == TldrLanguage::Log {
        let tree = strategy.parse("", TldrLanguage::Bash, None)?;
        return Ok((tree, String::new(), lang));
    }

    // Plain-text batch: `.txt`/`.text` files NEVER go through
    // tree-sitter — plain text has no syntax, so no grammar can exist
    // (the Log no-grammar precedent, d1992302). The TREE is the same
    // structural placeholder as Log's (an empty shell `program`) that
    // Text consumers never inspect: the `get_code_structure` hook
    // early-returns to the heuristic TOC scanner in `ast::toc` before
    // any tree walk happens, and the reference extraction in
    // `ast::doclinks` is regex-only.
    //
    // UNLIKE Log — whose entries are re-derived from the file by the
    // streaming scanner and whose placeholder source is empty — Text
    // consumers NEED THE CONTENT: both the TOC scan and the URL/path
    // reference scan work on the text itself. So this arm READS the
    // file and returns the real source beside the placeholder tree.
    // Wide encodings (UTF-16/32) are rejected with the shared
    // `EncodingError` (the same policy as every tree-sitter read —
    // see `ast::toc::parse_text_file`); everything else lossy-decodes.
    if lang == TldrLanguage::Text {
        let source = crate::ast::toc::parse_text_file(path)?;
        let tree = strategy.parse("", TldrLanguage::Bash, None)?;
        return Ok((tree, source, lang));
    }

    // CSV/TSV batch: `.csv`/`.tsv` files NEVER go through tree-sitter —
    // the only CSV grammar crate on crates.io is unbuildable (`cc
    // ~1.0.82` build-dep semver-conflicts with ts 0.25's `cc ^1.2.10`;
    // ts-0.20-era exports with no bridge LanguageFns — audit note in the
    // root Cargo.toml). The native RFC 4180 record scanner in
    // `ast::csvscan` owns CSV/TSV content. Mirroring the Log arm above,
    // this returns the EMPTY structural placeholder tree (an empty shell
    // `program`) WITHOUT reading the file (a GiB export costs nothing
    // here — the scanner streams it): the `get_code_structure` hook
    // early-returns to `ast::csvscan` before any tree walk happens, and
    // the scanner re-derives everything from the file, so the placeholder
    // source stays empty. Direct `parse(source, Csv)` calls (no file)
    // still fail with UnsupportedLanguage, which is the honest answer.
    if lang == TldrLanguage::Csv || lang == TldrLanguage::Tsv {
        let tree = strategy.parse("", TldrLanguage::Bash, None)?;
        return Ok((tree, String::new(), lang));
    }

    // Read file content with UTF-8 lossy fallback - M2 mitigation
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            TldrError::PathNotFound(path.to_path_buf())
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            TldrError::PermissionDenied(path.to_path_buf())
        } else {
            TldrError::IoError(e)
        }
    })?;

    // Reject wide encodings (BOM'd or BOM-less UTF-16/UTF-32) before the
    // lossy UTF-8 conversion below. `from_utf8_lossy` never fails - on
    // wide-encoded bytes it silently produces replacement-character
    // garbage that parses to zero symbols, so the file is reported as
    // successfully analysed with no functions/classes instead of being
    // skipped. BOM-less UTF-16 is the COMMON form (a BOM is often absent
    // on Unix-authored files, and pipes/editors strip it) and is caught
    // by NEITHER a plain BOM check NOR `str::from_utf8`: a UTF-16
    // encoding of ASCII text is every ASCII byte interleaved with NUL,
    // and NUL is a *valid* 1-byte UTF-8 sequence. Measured — validating
    // UTF-8 ACCEPTS BOM-less UTF-16LE and UTF-16BE outright, while
    // REJECTING latin-1/cp1252, so it fails in both directions at once.
    // See `crate::fs::wide_encoding_marker` for the full detection
    // rationale (shared with `read_to_string_tolerant` so the two file
    // read paths cannot drift).
    //
    // ASSUMPTION, stated because it is not proven: NUL-in-the-first-KiB
    // of a real source file is rare enough that a WARNED skip beats a
    // silent mis-parse. Evidence is 0 of 919 files in THIS repo, which
    // is a homogeneous sample of the tool's own codebase, not of the
    // arbitrary user code tldr runs on. The failure mode is at least
    // visible now: the file is named in `warnings`, not dropped in
    // silence.
    if let Some(detail) = crate::fs::wide_encoding_marker(&bytes) {
        return Err(TldrError::EncodingError {
            path: path.to_path_buf(),
            detail: detail.to_string(),
        });
    }

    // Convert to string, avoiding a copy for valid UTF-8. The old
    // `String::from_utf8_lossy(&bytes).to_string()` always copied —
    // even when the bytes were already valid UTF-8 (the common case),
    // doubling peak memory on every file: the raw `Vec<u8>` AND its
    // `String` clone were both live. `String::from_utf8` instead MOVES
    // the buffer when the bytes are valid UTF-8 (zero-copy; the
    // `Vec<u8>` is consumed), and only the invalid-UTF-8 fallback pays
    // for one lossy copy (`FromUtf8Error::as_bytes` hands back the
    // original bytes, so the lossy result is byte-identical to what
    // `from_utf8_lossy(&bytes)` produced before). Wide encodings
    // (UTF-16/32) were already rejected above, so this is purely a
    // memory win with no behaviour change.
    let source = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };

    // Parse the source, passing the path so the TSX dialect is picked
    // up for `.tsx` / `.jsx` files.
    let tree = strategy.parse(&source, lang, Some(path)).map_err(|e| {
        if let TldrError::ParseError { line, message, .. } = e {
            TldrError::ParseError {
                file: path.to_path_buf(),
                line,
                message,
            }
        } else {
            e
        }
    })?;

    Ok((tree, source, lang))
}

impl Default for ParserPool {
    fn default() -> Self {
        Self::new()
    }
}

// Global parser pool for convenience
lazy_static::lazy_static! {
    /// Global parser pool instance
    pub static ref PARSER_POOL: Arc<ParserPool> = Arc::new(ParserPool::new());
}

/// Parse source code using the global parser pool (path-less).
pub fn parse(source: &str, lang: TldrLanguage) -> TldrResult<Tree> {
    PARSER_POOL.parse(source, lang)
}

/// Parse source code using the global parser pool, with an optional
/// path used to pick the right TS/JS grammar dialect.
pub fn parse_with_path(source: &str, lang: TldrLanguage, path: Option<&Path>) -> TldrResult<Tree> {
    PARSER_POOL.parse_with_path(source, lang, path)
}

/// Parse a file using the global parser pool.
pub fn parse_file(path: &std::path::Path) -> TldrResult<(Tree, String, TldrLanguage)> {
    PARSER_POOL.parse_file(path)
}

/// Parse a file using the global parser pool with an optional language hint.
///
/// See [`ParserPool::parse_file_with_lang`] for the semantics: when
/// `lang_hint` is `Some(_)` it overrides path-extension detection, which
/// is required for extensionless files (e.g. `tldr imports myscript
/// --lang python`).
pub fn parse_file_with_lang(
    path: &std::path::Path,
    lang_hint: Option<TldrLanguage>,
) -> TldrResult<(Tree, String, TldrLanguage)> {
    PARSER_POOL.parse_file_with_lang(path, lang_hint)
}

// =============================================================================
// PERF-2: per-thread parser cache for the parallel hot paths
// =============================================================================

thread_local! {
    /// Per-thread parser cache, keyed by `(language, dialect)`.
    ///
    /// Rationale: the global [`PARSER_POOL`] is one `Mutex<HashMap<..>>`
    /// whose guard is held across `set_language` AND the entire `parse()`
    /// call, so a naive `par_iter` over files stays mutex-bound — every
    /// worker queues on the same lock and the fan-out degenerates to the
    /// sequential speed. Sharing parsers across threads is not an option
    /// either: `tree_sitter::Parser` is `!Send`. A thread-local map gives
    /// every rayon worker its own parser per `(language, dialect)` slot:
    /// zero contention, and one grammar setup per thread instead of one
    /// per file.
    ///
    /// Memory shape (documented, accepted): the cache is bounded by
    /// `threads × (language, dialect)` slots and entries are NEVER evicted
    /// — each `Parser` holds one grammar (static, process-lifetime data),
    /// so the worst case is one parser per grammar per worker thread for
    /// the thread's lifetime. Acceptable by design; revisit only if the
    /// grammar count or the worker pool size ever grows unboundedly.
    ///
    /// Used ONLY by the parallel hot paths (structure fan-out, references
    /// AST verification, deps/import-graph import extraction, callgraph
    /// `parse_source`). Single-file callers keep using the global pool.
    static THREAD_LOCAL_PARSERS: RefCell<HashMap<ParserKey, Parser>> =
        RefCell::new(HashMap::new());
}

/// Run `f` with this thread's cached parser for `key`, creating the parser
/// on first use. Mirrors the pool's slot semantics, including the defensive
/// `set_language` re-set before every parse (cheap insurance that a cached
/// parser is always on the grammar the caller just resolved).
///
/// FIX-1a (grammar-load panic): as in the pool, slot creation is a bare
/// `Parser::new()` and the fallible `set_language` runs OUTSIDE the
/// `or_insert_with` closure, so a first-use grammar-load failure returns
/// `TldrError::ParseError` instead of `.expect`-panicking on a rayon worker
/// (which would abort the process). On success the behavior is unchanged.
fn with_thread_local_parser<R>(
    key: ParserKey,
    ts_lang: Language,
    path: Option<&Path>,
    f: impl FnOnce(&mut Parser) -> R,
) -> TldrResult<R> {
    THREAD_LOCAL_PARSERS.with(|cache| {
        let mut cache = cache.borrow_mut();
        let parser = cache.entry(key).or_default();
        parser
            .set_language(&ts_lang)
            .map_err(|e| TldrError::ParseError {
                file: path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
                line: None,
                message: format!("Failed to set language: {}", e),
            })?;
        Ok(f(parser))
    })
}

/// Map a `(language, dialect)` key to its tree-sitter grammar.
///
/// `TsDialect::Tsx` on a TS/JS language selects `LANGUAGE_TSX`, `Ts`
/// selects the plain TypeScript grammar; every other language falls back
/// to its default grammar.
fn grammar_for_key(lang: TldrLanguage, dialect: TsDialect) -> Option<Language> {
    match (lang, dialect) {
        (TldrLanguage::TypeScript | TldrLanguage::JavaScript, TsDialect::Tsx) => {
            Some(tree_sitter_typescript::LANGUAGE_TSX.into())
        }
        (TldrLanguage::TypeScript | TldrLanguage::JavaScript, TsDialect::Ts) => {
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        _ => ParserPool::get_ts_language(lang),
    }
}

/// Parse source code through the per-thread parser cache (PERF-2), with an
/// optional path selecting the TS/JS grammar dialect — the thread-local
/// twin of [`parse_with_path`]. Same grammar routing, same size cap, same
/// error shapes; only the parser storage differs (per-thread map instead
/// of the global mutex-guarded pool).
pub fn parse_with_path_threadlocal(
    source: &str,
    lang: TldrLanguage,
    path: Option<&Path>,
) -> TldrResult<Tree> {
    if (source.len() as u64) > MAX_PARSE_SIZE {
        return Err(TldrError::ParseError {
            file: path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
            line: None,
            message: format!(
                "File too large: {} bytes (max {})",
                source.len(),
                MAX_PARSE_SIZE
            ),
        });
    }

    let dialect = TsDialect::from_path_and_lang(path, lang);
    let ts_lang = grammar_for_key(lang, dialect)
        .ok_or_else(|| TldrError::UnsupportedLanguage(lang.to_string()))?;
    let key = ParserKey::new(lang, dialect);

    with_thread_local_parser(key, ts_lang, path, |parser| parser.parse(source, None))?.ok_or_else(
        || TldrError::ParseError {
            file: path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("<source>")),
            line: None,
            message: "Parsing returned None".to_string(),
        },
    )
}

/// Parse a file from disk through the per-thread parser cache (PERF-2).
/// Thread-local twin of [`parse_file`].
pub fn parse_file_threadlocal(path: &std::path::Path) -> TldrResult<(Tree, String, TldrLanguage)> {
    parse_file_with_lang_threadlocal(path, None)
}

/// Parse a file from disk through the per-thread parser cache (PERF-2),
/// optionally honoring a caller-supplied language hint. Thread-local twin
/// of [`ParserPool::parse_file_with_lang`]: identical pipeline (size
/// policy, JSONL/Log/Text/CSV arms, UTF-8 lossy fallback, TSX dialect
/// routing), but the underlying `tree_sitter::Parser` lives in this
/// thread's cache instead of the global mutex-guarded pool — required for
/// callers running under rayon, where pool access would serialize all
/// workers on one lock (the pool guard is held across the whole `parse`).
pub fn parse_file_with_lang_threadlocal(
    path: &std::path::Path,
    lang_hint: Option<TldrLanguage>,
) -> TldrResult<(Tree, String, TldrLanguage)> {
    parse_file_pipeline(path, lang_hint, &ParseStrategy::ThreadLocal)
}

/// Parse source with an EXPLICIT grammar dialect through the per-thread
/// parser cache. Crate-visible for the callgraph builder, whose language
/// strings map `"typescript"`/`"javascript"` to the TSX grammar — a
/// different routing than the path-based [`parse_with_path`] — while
/// sharing the per-thread cache. The dialect is part of the cache key, so
/// the callgraph `(TypeScript, Tsx)` slot cannot collide with the
/// path-based `(TypeScript, Ts)` slot.
pub(crate) fn parse_with_dialect_threadlocal(
    source: &str,
    lang: TldrLanguage,
    dialect: TsDialect,
) -> TldrResult<Tree> {
    let ts_lang = grammar_for_key(lang, dialect)
        .ok_or_else(|| TldrError::UnsupportedLanguage(lang.to_string()))?;
    let key = ParserKey::new(lang, dialect);

    with_thread_local_parser(key, ts_lang, None, |parser| parser.parse(source, None))?.ok_or_else(
        || TldrError::ParseError {
            file: std::path::PathBuf::from("<source>"),
            line: None,
            message: "Parsing returned None".to_string(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_python() {
        let source = "def foo(): pass";
        let tree = parse(source, TldrLanguage::Python).unwrap();
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn test_parse_typescript() {
        let source = "function foo() {}";
        let tree = parse(source, TldrLanguage::TypeScript).unwrap();
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn test_parse_go() {
        let source = "package main\nfunc foo() {}";
        let tree = parse(source, TldrLanguage::Go).unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn test_parse_rust() {
        let source = "fn foo() {}";
        let tree = parse(source, TldrLanguage::Rust).unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn test_swift_now_supported() {
        // Swift was previously disabled due to ABI v15 incompatibility with tree-sitter 0.24.7.
        // tree-sitter 0.25.0 supports ABI v15 via the tree-sitter-language bridging crate.
        let result = parse("let x = 1", TldrLanguage::Swift);
        assert!(
            result.is_ok(),
            "Swift should now parse successfully: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().root_node().kind(), "source_file");
    }

    #[test]
    fn test_parser_reuse() {
        let pool = ParserPool::new();

        // Parse multiple times with same language
        for _ in 0..5 {
            let _ = pool.parse("def foo(): pass", TldrLanguage::Python).unwrap();
        }

        // Only one parser should be created
        let parsers = pool.parsers.lock().unwrap();
        assert_eq!(parsers.len(), 1);
    }

    // ---------------------------------------------------------------------
    // VAL-004: TSX/JSX grammar dialect selection
    // ---------------------------------------------------------------------
    //
    // Regression tests for the bug where ParserPool::parse_file chose
    // LANGUAGE_TYPESCRIPT for .tsx / .jsx paths. That grammar does not
    // understand JSX syntax, so JSX-heavy files entered tree-sitter
    // error-recovery and produced pathological ASTs. Downstream, the
    // message-chain smell detector went exponential on these broken trees,
    // timing out on real-world files such as dub's
    // `apps/web/.../screenshot.tsx` (1584 LOC).
    //
    // Fix: ParserPool::parse_file must select tree_sitter_typescript::
    // LANGUAGE_TSX when the path extension is `.tsx` or `.jsx`, and the
    // parser cache must distinguish dialects so a TS-grammar parser and a
    // TSX-grammar parser do not share a cache slot.

    /// Recursively count the number of `ERROR` nodes in a tree.
    fn count_error_nodes(node: tree_sitter::Node) -> usize {
        let mut count = if node.is_error() { 1 } else { 0 };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            count += count_error_nodes(child);
        }
        count
    }

    #[test]
    fn test_parse_file_tsx_uses_tsx_grammar() {
        // A tempdir .tsx file with JSX must parse cleanly (zero ERROR
        // nodes) when routed through parse_file, which has the path and
        // can dispatch to LANGUAGE_TSX.
        let dir = tempfile::tempdir().unwrap();
        let tsx_path = dir.path().join("App.tsx");
        std::fs::write(
            &tsx_path,
            r#"export const App = ({ name }: { name: string }) => <div className="a">{name}</div>;
"#,
        )
        .unwrap();

        let pool = ParserPool::new();
        let (tree, _src, lang) = pool.parse_file(&tsx_path).unwrap();
        assert_eq!(lang, TldrLanguage::TypeScript);
        let errors = count_error_nodes(tree.root_node());
        assert_eq!(
            errors, 0,
            "expected zero ERROR nodes for .tsx via TSX grammar, got {}",
            errors
        );

        // Plain .ts also parses cleanly via the non-TSX default.
        let ts_path = dir.path().join("plain.ts");
        std::fs::write(&ts_path, "export const x: number = 1;\n").unwrap();
        let (tree, _src, lang) = pool.parse_file(&ts_path).unwrap();
        assert_eq!(lang, TldrLanguage::TypeScript);
        assert_eq!(
            count_error_nodes(tree.root_node()),
            0,
            "plain .ts should parse cleanly"
        );
    }

    #[test]
    fn test_parse_file_jsx_uses_tsx_grammar() {
        // tree-sitter-typescript does not ship a dedicated JSX grammar;
        // LANGUAGE_TSX handles both TSX and JSX. Selecting it for .jsx
        // files keeps JSX syntax out of error-recovery.
        let dir = tempfile::tempdir().unwrap();
        let jsx_path = dir.path().join("App.jsx");
        std::fs::write(
            &jsx_path,
            "export const App = ({ name }) => <div className=\"a\">{name}</div>;\n",
        )
        .unwrap();

        let pool = ParserPool::new();
        let (tree, _src, lang) = pool.parse_file(&jsx_path).unwrap();
        assert_eq!(lang, TldrLanguage::JavaScript);
        let errors = count_error_nodes(tree.root_node());
        assert_eq!(
            errors, 0,
            "expected zero ERROR nodes for .jsx via TSX grammar, got {}",
            errors
        );
    }

    #[test]
    fn test_parse_cache_distinguishes_dialects() {
        // The parser cache must key on (language, dialect) so that a TS
        // parser and a TSX parser are not clobbered into the same slot
        // across repeated calls. If they shared a slot, the second call
        // would silently reuse the wrong grammar and the third call (back
        // to .ts) would then see JSX-flavoured error recovery again.
        let dir = tempfile::tempdir().unwrap();
        let ts_path = dir.path().join("a.ts");
        let tsx_path = dir.path().join("b.tsx");
        std::fs::write(&ts_path, "export const n: number = 1;\n").unwrap();
        std::fs::write(&tsx_path, "export const App = () => <div>{1}</div>;\n").unwrap();

        let pool = ParserPool::new();
        // .ts -> .tsx -> .ts, each must parse cleanly.
        let (t1, _, _) = pool.parse_file(&ts_path).unwrap();
        assert_eq!(count_error_nodes(t1.root_node()), 0, "first .ts failed");
        let (t2, _, _) = pool.parse_file(&tsx_path).unwrap();
        assert_eq!(count_error_nodes(t2.root_node()), 0, ".tsx failed");
        let (t3, _, _) = pool.parse_file(&ts_path).unwrap();
        assert_eq!(
            count_error_nodes(t3.root_node()),
            0,
            "second .ts failed (cache collision between TS and TSX parsers)"
        );
    }

    #[test]
    fn test_legacy_parse_without_path_uses_ts_default() {
        // The legacy `parse(source, lang)` API has no path and therefore
        // cannot disambiguate TS vs TSX. Contract: it keeps working for
        // plain TypeScript (returns LANGUAGE_TYPESCRIPT, the conservative
        // default) and produces ERROR nodes when given JSX. Callers that
        // need JSX-aware parsing must use parse_file or pass a path.
        let pool = ParserPool::new();

        // Plain TS parses cleanly via the path-less default.
        let tree = pool
            .parse("export const x: number = 1;", TldrLanguage::TypeScript)
            .unwrap();
        assert_eq!(
            count_error_nodes(tree.root_node()),
            0,
            "plain TS should parse cleanly via path-less API"
        );

        // JSX via path-less API produces error nodes — that is the
        // documented contract; it is not a regression.
        let jsx_src = "const App = () => <div className=\"a\">hi</div>;";
        let tree = pool.parse(jsx_src, TldrLanguage::TypeScript).unwrap();
        assert!(
            count_error_nodes(tree.root_node()) > 0,
            "path-less TS parse of JSX is expected to produce ERROR nodes; \
             if it parses cleanly, the default grammar changed and callers \
             must be audited"
        );
    }

    // ---------------------------------------------------------------------
    // Log batch: Language::Log never parses through tree-sitter.
    // ---------------------------------------------------------------------
    #[test]
    fn test_parse_file_log_returns_clean_empty_tree() {
        // `parse_file_with_lang` on a `.log` path must return an EMPTY tree
        // + empty source WITHOUT reading the file (the native scanner in
        // `ast::logs` is the only consumer of log content). The placeholder
        // tree (empty Bash program) must still be a clean parse so no
        // generic has_error() validation anywhere trips on it.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("server.log");
        std::fs::write(&log_path, "2026-09-14T08:34:49Z ERROR big log content\n").unwrap();

        let pool = ParserPool::new();
        let (tree, source, lang) = pool.parse_file(&log_path).unwrap();
        assert_eq!(lang, TldrLanguage::Log);
        assert_eq!(source, "");
        assert_eq!(tree.root_node().child_count(), 0, "empty program");
        assert_eq!(
            count_error_nodes(tree.root_node()),
            0,
            "placeholder empty tree must be a clean parse"
        );

        // Direct path-less parse of log SOURCE stays UnsupportedLanguage —
        // logs have no grammar, by design.
        let err = pool.parse("some log line", TldrLanguage::Log);
        assert!(
            matches!(err, Err(TldrError::UnsupportedLanguage(_))),
            "parse(source, Log) must be UnsupportedLanguage, got {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------
    // Plain-text batch: Language::Text never parses through tree-sitter.
    // ---------------------------------------------------------------------
    #[test]
    fn test_parse_file_text_returns_placeholder_tree_with_real_source() {
        // `parse_file_with_lang` on a `.txt` path must return the structural
        // PLACEHOLDER tree (empty Bash program — Text consumers never walk
        // it) but WITH the real source: unlike Log, whose entries are
        // re-derived from the file by the streaming scanner, Text consumers
        // (the `ast::toc` TOC scan and the `ast::doclinks` reference scan)
        // work on the text itself.
        let dir = tempfile::tempdir().unwrap();
        let txt_path = dir.path().join("notes.txt");
        std::fs::write(&txt_path, "OVERVIEW\n\nsee docs/guide.md\n").unwrap();

        let pool = ParserPool::new();
        let (tree, source, lang) = pool.parse_file(&txt_path).unwrap();
        assert_eq!(lang, TldrLanguage::Text);
        assert_eq!(source, "OVERVIEW\n\nsee docs/guide.md\n", "real source");
        assert_eq!(tree.root_node().child_count(), 0, "empty program");
        assert_eq!(
            count_error_nodes(tree.root_node()),
            0,
            "placeholder empty tree must be a clean parse"
        );

        // Direct path-less parse of prose SOURCE stays UnsupportedLanguage —
        // plain text has no grammar (nothing to parse it WITH), by design.
        let err = pool.parse("some prose line", TldrLanguage::Text);
        assert!(
            matches!(err, Err(TldrError::UnsupportedLanguage(_))),
            "parse(source, Text) must be UnsupportedLanguage, got {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------
    // VAL-008: parser health audit for all 18 supported languages.
    //
    // Each of tldr's 18 supported languages must have a tree-sitter grammar
    // capable of parsing a minimal valid source file with zero ERROR and
    // zero MISSING nodes. This test codifies the baseline so that grammar
    // regressions (e.g. an incompatible ABI bump) get caught immediately.
    // ---------------------------------------------------------------------
    #[test]
    fn test_all_18_parsers_accept_minimal_valid_snippet() {
        let snippets: &[(TldrLanguage, &str)] = &[
            (TldrLanguage::Python, "def x(): pass"),
            (TldrLanguage::TypeScript, "export const x: number = 1;"),
            (TldrLanguage::JavaScript, "export const x = 1;"),
            (TldrLanguage::Go, "package main\nfunc main() {}"),
            (TldrLanguage::Rust, "pub fn x() {}"),
            (
                TldrLanguage::Java,
                "class X { public static void main(String[] a){} }",
            ),
            (TldrLanguage::C, "int main(){return 0;}"),
            (TldrLanguage::Cpp, "int main(){return 0;}"),
            (TldrLanguage::Ruby, "def x; end"),
            (TldrLanguage::Kotlin, "fun x(){}"),
            (TldrLanguage::Swift, "func x(){}"),
            (TldrLanguage::CSharp, "class X { static void Main(){} }"),
            (
                TldrLanguage::Scala,
                "object X { def main(args: Array[String]): Unit = {} }",
            ),
            (TldrLanguage::Php, "<?php function x(){}"),
            (TldrLanguage::Lua, "function x() end"),
            (TldrLanguage::Luau, "function x() end"),
            (
                TldrLanguage::Elixir,
                "defmodule X do\ndef y(), do: :ok\nend",
            ),
            (TldrLanguage::Ocaml, "let x () = ()"),
        ];

        let pool = ParserPool::new();
        let mut failures: Vec<String> = Vec::new();
        for (lang, src) in snippets {
            match pool.parse(src, *lang) {
                Ok(tree) => {
                    let errs = count_error_nodes(tree.root_node());
                    if errs != 0 {
                        failures.push(format!(
                            "{:?}: {} ERROR node(s) on valid snippet: {:?}",
                            lang, errs, src
                        ));
                    }
                }
                Err(e) => {
                    failures.push(format!("{:?}: parse failed: {:?} on {:?}", lang, e, src));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "Parser audit failures (VAL-008): {}",
            failures.join(" | ")
        );
    }

    // ---------------------------------------------------------------------
    // FIX-1a (F2): a first-use grammar-load failure must map onto
    // `TldrError::ParseError`, not `.expect`-panic. The panic lived inside
    // the slot-creation closures (pool + thread-local); on a rayon worker a
    // panic aborts the whole process, so the very first use of a slot whose
    // grammar fails to load used to be a process kill while the SECOND use
    // of the same broken grammar returned a typed error.
    //
    // The tests drive both first-use paths with a SYNTHETIC `Language` whose
    // `TSLanguage.abi_version` is far below tree-sitter's minimum supported
    // ABI — the only field `Parser::set_language` reads before rejecting
    // (`ts_language_abi_version`), so the zeroed remainder of the static is
    // never dereferenced on the error path. `ts_language_copy`/`_delete` are
    // no-ops for non-WASM languages, so dropping the wrapper is safe.
    // ---------------------------------------------------------------------

    /// A `TSLanguage`-shaped static whose ABI version is out of range.
    #[repr(C)]
    struct BadAbiLanguage {
        abi_version: u32,
        /// Zeroed remainder: keeps any speculative later-field read inside
        /// our own static at NULL (nothing reads past `abi_version` on the
        /// rejection path today, but the padding makes the layout honest).
        _rest: [u32; 64],
    }

    static BAD_ABI_LANGUAGE: BadAbiLanguage = BadAbiLanguage {
        // Far below tree-sitter 0.25's MIN_COMPATIBLE_LANGUAGE_VERSION (13).
        abi_version: 1,
        _rest: [0; 64],
    };

    /// The grammar-factory shape the `tree-sitter-language` bridge wraps: a C
    /// function returning the `TSLanguage` static. `Language::new` calls it
    /// once and wraps the pointer.
    unsafe extern "C" fn bad_abi_language_fn() -> *const () {
        &BAD_ABI_LANGUAGE as *const BadAbiLanguage as *const ()
    }

    /// A `Language` whose grammar fails to load (`set_language` → Err).
    fn bad_grammar() -> Language {
        // SAFETY: the pointer targets our own `'static` struct, laid out
        // with `abi_version` first exactly like the C `TSLanguage`; the
        // rejection path reads that one field and nothing else.
        unsafe {
            Language::new(tree_sitter_language::LanguageFn::from_raw(
                bad_abi_language_fn,
            ))
        }
    }

    #[test]
    fn first_use_grammar_load_failure_maps_to_typed_error_pool() {
        let mut parsers: HashMap<ParserKey, Parser> = HashMap::new();
        let key = ParserKey::new(TldrLanguage::Python, TsDialect::None);
        let bad = bad_grammar();

        // Sanity: the synthetic language really is rejected by set_language.
        let mut probe = Parser::new();
        let err = probe.set_language(&bad).unwrap_err();
        assert!(err.to_string().contains("Incompatible language version"));

        // FIRST use of the slot: typed error, NOT a panic (this test passing
        // is the pin — the pre-fix code `.expect`-aborted right here).
        // (`.err()`, not `unwrap_err()`: the Ok side is `&mut Parser`, which
        // is not `Debug`.)
        let err = acquire_pooled_parser(&mut parsers, key, &bad, None)
            .err()
            .expect("the bad-grammar first use must fail");
        match &err {
            TldrError::ParseError {
                file,
                line,
                message,
            } => {
                assert_eq!(file, &std::path::PathBuf::from("<source>"));
                assert!(line.is_none());
                assert!(
                    message.contains("Failed to set language"),
                    "the pool must map the grammar-load failure onto its typed message: {message}"
                );
            }
            other => panic!("expected TldrError::ParseError, got {other:?}"),
        }

        // The slot is created but UNSET — a later call with a REAL grammar
        // on the same slot must succeed (a failed first use does not poison
        // the cache).
        let good = ParserPool::get_ts_language(TldrLanguage::Python).unwrap();
        let parser = acquire_pooled_parser(&mut parsers, key, &good, None).unwrap();
        assert!(parser.parse("def foo(): pass", None).is_some());
    }

    #[test]
    fn first_use_grammar_load_failure_maps_to_typed_error_thread_local() {
        let key = ParserKey::new(TldrLanguage::Python, TsDialect::None);
        let bad = bad_grammar();

        // FIRST use of this thread's slot: typed error, NOT a panic (the
        // pre-fix code `.expect`-aborted right here, on the rayon-worker
        // stack this cache exists for).
        let err = with_thread_local_parser(key, bad, None, |_| 42).unwrap_err();
        match &err {
            TldrError::ParseError { message, .. } => {
                assert!(
                    message.contains("Failed to set language"),
                    "the thread-local cache must map the grammar-load failure onto its \
                     typed message: {message}"
                );
            }
            other => panic!("expected TldrError::ParseError, got {other:?}"),
        }

        // The unset slot stays usable: the same key with a REAL grammar
        // loads and parses (no poisoned cache).
        let good = ParserPool::get_ts_language(TldrLanguage::Python).unwrap();
        let trees = with_thread_local_parser(key, good, None, |parser| {
            parser.parse("def foo(): pass", None)
        })
        .unwrap();
        assert!(trees.is_some());
    }
}
