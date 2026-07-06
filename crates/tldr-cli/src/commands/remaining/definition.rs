//! Definition command - Go-to-definition functionality
//!
//! Finds where a symbol is defined in the codebase.
//! Supports both position-based and name-based lookup.
//!
//! # Example
//!
//! ```bash
//! # Position-based: find definition of symbol at line 10, column 5
//! tldr definition src/main.py 10 5
//!
//! # Name-based: find definition by symbol name
//! tldr definition --symbol MyClass --file src/main.py
//!
//! # Cross-file resolution with project context
//! tldr definition --symbol helper --file src/main.py --project .
//! ```

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use tree_sitter::Node;

use super::error::{RemainingError, RemainingResult};
use super::types::{DefinitionResult, Location, SymbolInfo, SymbolKind};
use crate::output::OutputWriter;

use tldr_core::ast::parser::PARSER_POOL;
use tldr_core::callgraph::cross_file_types::{ClassDef, FuncDef};
use tldr_core::callgraph::languages::LanguageRegistry;
use tldr_core::Language;

// =============================================================================
// Column position normalization (r7-cl11-definition-column-convention)
//
// tree-sitter natively reports a column as a 0-based UTF-8 *byte* offset
// within its line; LSP editors default to UTF-16 code units. Historically
// every `definition` call site re-derived an ad-hoc column with a
// hand-written `±1` and an *implicit* (byte) encoding, so the index-base
// and the encoding were both undeclared and inconsistent. This module
// introduces ONE canonical `(index-base, encoding)` mapper at the CLI <->
// tree-sitter boundary — the rust-analyzer `LineIndex` / gopls
// `ColumnMapper` pattern — so the conversion lives in exactly one place
// instead of being re-derived (or omitted) per call site.
//
// Default encoding is `Utf8Byte`, which makes every conversion the
// identity: the existing 0-indexed-byte INPUT and 1-indexed-byte OUTPUT
// contracts are preserved byte-for-byte (zero regression). `utf16`/`utf32`
// are explicit opt-in via `--position-encoding` and only diverge from the
// default on lines containing non-ASCII before the column.
// =============================================================================

/// Declared column encoding for the `definition` command's INPUT and
/// REPORTED columns. Making the encoding an explicit, negotiable property
/// removes the implicit byte-offset assumption that silently disagreed
/// with every stock LSP editor on any non-ASCII line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PositionEncoding {
    /// 0-based UTF-8 byte offset (tree-sitter native; LSP `utf-8`). Default.
    #[default]
    Utf8Byte,
    /// 0-based UTF-16 code-unit offset (the LSP default, `utf-16`).
    Utf16,
    /// 0-based Unicode code-point / char offset (LSP `utf-32`).
    Utf32Char,
}

impl PositionEncoding {
    /// Parse a CLI `--position-encoding` value. Accepts the LSP spellings
    /// plus common aliases; returns `None` for unknown input.
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "utf8" | "utf-8" | "byte" | "bytes" => Some(Self::Utf8Byte),
            "utf16" | "utf-16" => Some(Self::Utf16),
            "utf32" | "utf-32" | "char" | "chars" | "codepoint" | "codepoints" => {
                Some(Self::Utf32Char)
            }
            _ => None,
        }
    }
}

/// Per-file line index used to convert a tree-sitter UTF-8 byte column to
/// or from a declared [`PositionEncoding`]. Built once from the source
/// string. Because the byte<->code-unit delta is content-dependent (a
/// non-BMP char is 4 UTF-8 bytes but 2 UTF-16 units), the conversion is
/// derived from the line's actual bytes — never a constant offset or a
/// `÷2` heuristic.
pub struct LineIndex<'a> {
    lines: Vec<&'a str>,
}

impl<'a> LineIndex<'a> {
    /// Build the index from raw source. Lines are split on `\n` with an
    /// optional trailing `\r` stripped, matching `str::lines` semantics so
    /// the row indices agree with tree-sitter's `Point::row`.
    pub fn new(src: &'a str) -> Self {
        let lines = src
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect();
        Self { lines }
    }

    fn line(&self, row: usize) -> &'a str {
        self.lines.get(row).copied().unwrap_or("")
    }

    /// Clamp a byte offset down to the nearest char boundary `<= byte` so
    /// slicing a multi-byte char never panics.
    fn floor_char_boundary(line: &str, byte: usize) -> usize {
        let mut b = byte.min(line.len());
        while b > 0 && !line.is_char_boundary(b) {
            b -= 1;
        }
        b
    }

    /// Convert a 0-based tree-sitter UTF-8 byte column to the 0-based
    /// column in `enc`. For [`PositionEncoding::Utf8Byte`] this is the
    /// identity, so today's byte-column output is preserved exactly.
    pub fn byte_col_to(&self, row: usize, byte_col: usize, enc: PositionEncoding) -> usize {
        match enc {
            PositionEncoding::Utf8Byte => byte_col,
            PositionEncoding::Utf16 => {
                let line = self.line(row);
                let end = Self::floor_char_boundary(line, byte_col);
                line[..end].chars().map(char::len_utf16).sum()
            }
            PositionEncoding::Utf32Char => {
                let line = self.line(row);
                let end = Self::floor_char_boundary(line, byte_col);
                line[..end].chars().count()
            }
        }
    }

    /// Convert a 0-based column in `enc` to a 0-based UTF-8 byte column
    /// suitable for `tree_sitter::Point::new`. Inverse of [`byte_col_to`];
    /// for [`PositionEncoding::Utf8Byte`] it is the identity. A column past
    /// end-of-line clamps to the line length.
    pub fn enc_col_to_byte(&self, row: usize, col: usize, enc: PositionEncoding) -> usize {
        match enc {
            PositionEncoding::Utf8Byte => col,
            PositionEncoding::Utf16 => {
                let line = self.line(row);
                let mut units = 0usize;
                for (byte_idx, ch) in line.char_indices() {
                    if units >= col {
                        return byte_idx;
                    }
                    units += ch.len_utf16();
                }
                line.len()
            }
            PositionEncoding::Utf32Char => {
                let line = self.line(row);
                for (chars, (byte_idx, _ch)) in line.char_indices().enumerate() {
                    if chars >= col {
                        return byte_idx;
                    }
                }
                line.len()
            }
        }
    }
}

/// Re-encode every column carried by a [`DefinitionResult`] from the
/// internal 1-indexed UTF-8 byte representation to the declared output
/// encoding. A no-op for [`PositionEncoding::Utf8Byte`] (the default), so
/// the existing `col >= 1` byte-column contract is untouched unless the
/// caller explicitly opts into `utf16`/`utf32`.
fn reencode_result_columns(result: &mut DefinitionResult, enc: PositionEncoding) {
    if enc == PositionEncoding::Utf8Byte {
        return;
    }
    reencode_location(&mut result.symbol.location, enc);
    reencode_location(&mut result.definition, enc);
    reencode_location(&mut result.type_definition, enc);
}

/// Re-encode the column (and `end_column`, if present) of one optional
/// [`Location`] in place, reading the located file to build its
/// [`LineIndex`]. Columns are 1-indexed byte on input and 1-indexed `enc`
/// on output; a `0` column (the "no column" sentinel) is left untouched.
fn reencode_location(loc: &mut Option<Location>, enc: PositionEncoding) {
    let Some(l) = loc.as_mut() else { return };
    let Ok(src) = fs::read_to_string(&l.file) else {
        return;
    };
    let li = LineIndex::new(&src);
    if l.column >= 1 {
        let row0 = l.line.saturating_sub(1) as usize;
        let byte0 = (l.column - 1) as usize;
        l.column = li.byte_col_to(row0, byte0, enc) as u32 + 1;
    }
    if let Some(ec) = l.end_column {
        if ec >= 1 {
            let erow0 = l.end_line.unwrap_or(l.line).saturating_sub(1) as usize;
            let ebyte0 = (ec - 1) as usize;
            l.end_column = Some(li.byte_col_to(erow0, ebyte0, enc) as u32 + 1);
        }
    }
}

// =============================================================================
// Constants
// =============================================================================

/// Maximum depth for import resolution to prevent cycles
const MAX_IMPORT_DEPTH: usize = 10;

/// Python built-in functions
const PYTHON_BUILTINS: &[&str] = &[
    "abs",
    "aiter",
    "all",
    "any",
    "anext",
    "ascii",
    "bin",
    "bool",
    "breakpoint",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "__import__",
];

// =============================================================================
// Graph Utils (TIGER-02 Mitigation)
// =============================================================================

/// Tracks visited nodes to detect cycles during import resolution
pub struct DefinitionCycleDetector {
    visited: HashSet<(PathBuf, String)>,
}

impl DefinitionCycleDetector {
    /// Create a new cycle detector
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
        }
    }

    /// Visit a (file, symbol) pair. Returns true if already visited (cycle detected).
    pub fn visit(&mut self, file: &Path, symbol: &str) -> bool {
        let key = (file.to_path_buf(), symbol.to_string());
        !self.visited.insert(key)
    }
}

impl Default for DefinitionCycleDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// CLI Arguments
// =============================================================================

/// Find symbol definition (go-to-definition)
///
/// Supports two modes:
/// 1. Position-based: Find symbol at file:line:column and jump to its definition
/// 2. Name-based: Find definition of a named symbol using --symbol and --file
///
/// # Example
///
/// ```bash
/// # Position mode
/// tldr definition src/main.py 10 5
///
/// # Name mode
/// tldr definition --symbol MyClass --file src/main.py
/// ```
#[derive(Debug, Args)]
pub struct DefinitionArgs {
    /// Source file (positional, for position-based lookup)
    pub file: Option<PathBuf>,

    /// line number (1-indexed, for position-based lookup)
    pub line: Option<u32>,

    /// column number (0-indexed, for position-based lookup).
    ///
    /// CONVENTION (fix-R7 cluster[11] RC9 — decided, see
    /// `decisions/r7-cl11-definition-column-convention.md`): the INPUT column is
    /// 0-indexed (editor-cursor / tree-sitter byte-offset style), while the
    /// REPORTED column in the result is 1-indexed, matching `references` and
    /// `structure` (`diff-column-one-indexed-v1`). This input/output asymmetry
    /// is the declared *index-base* axis of [`PositionEncoding`]; it is retained
    /// as the default to avoid a silent CLI-contract break (making the input
    /// 1-indexed would shift every existing 0-indexed positional caller/test by
    /// one). The *encoding* axis — orthogonal to the base — is now explicit via
    /// `--position-encoding`. The `line` argument is 1-indexed (human line
    /// numbers).
    pub column: Option<u32>,

    /// Column encoding for the INPUT column and the REPORTED columns
    /// (r7-cl11-definition-column-convention).
    ///
    /// `utf8` (default) = 0-based UTF-8 byte offset, tree-sitter native —
    /// byte-for-byte identical to the historical behavior. `utf16` = LSP's
    /// default UTF-16 code units (what stock editors send/expect). `utf32` =
    /// Unicode code points (char count). The three coincide on pure-ASCII
    /// lines and only diverge where a line contains non-ASCII before the
    /// column, so enabling `utf16`/`utf32` never moves an ASCII result.
    #[arg(long = "position-encoding", value_name = "ENC", default_value = "utf8")]
    pub position_encoding: String,

    /// Find symbol by name instead of position
    #[arg(long)]
    pub symbol: Option<String>,

    /// File to search in (used with --symbol)
    #[arg(long = "file", name = "target_file")]
    pub target_file: Option<PathBuf>,

    /// Project root for cross-file resolution
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Enable workspace-wide cross-file resolution.
    ///
    /// When enabled (default), if `--project` is not provided the project
    /// root is auto-detected from the source file by walking up looking for
    /// repository / package markers (`.git`, `Cargo.toml`, `pyproject.toml`,
    /// `package.json`, `go.mod`, `pom.xml`, `build.gradle`). Set to `false`
    /// (`--workspace=false`) to disable auto-detection and keep resolution
    /// strictly within the source file unless an explicit `--project` is
    /// provided.
    ///
    /// `definition-workspace-cross-file-v1`.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub workspace: bool,

    /// Output file (optional, stdout if not specified)
    #[arg(long, short = 'O')]
    pub output: Option<PathBuf>,
}

impl DefinitionArgs {
    /// Run the definition command
    pub fn run(
        &self,
        format: crate::output::OutputFormat,
        quiet: bool,
        lang: Option<Language>,
    ) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Convert language option to string hint
        let lang_hint = match lang {
            Some(l) => format!("{:?}", l).to_lowercase(),
            None => "auto".to_string(),
        };

        // r7-cl11: resolve the declared column encoding once. Default `utf8`
        // makes every column conversion below the identity, preserving the
        // historical byte-column INPUT/OUTPUT contract exactly.
        let encoding = PositionEncoding::parse_cli(&self.position_encoding).ok_or_else(|| {
            RemainingError::invalid_argument(format!(
                "invalid --position-encoding '{}': expected one of utf8, utf16, utf32",
                self.position_encoding
            ))
        })?;

        // Determine which mode we're in
        let result = if let Some(ref symbol_name) = self.symbol {
            // Name-based mode - require --file
            let file = self.target_file.as_ref().ok_or_else(|| {
                RemainingError::invalid_argument("--file is required with --symbol")
            })?;

            writer.progress(&format!(
                "Finding definition of '{}' in {}...",
                symbol_name,
                file.display()
            ));

            // Workspace cross-file resolution (definition-workspace-cross-file-v1
            // + F4b-definition-py-import): resolve the effective cross-file
            // root, honouring an explicit --project, --workspace=false opt-out,
            // and the Python package-dir fallback for marker-less trees.
            let root_lang = detect_language(file, &lang_hint).ok();
            let effective_project_buf = resolve_definition_root(
                self.project.as_deref(),
                self.workspace,
                file,
                root_lang,
            );
            let effective_project = effective_project_buf.as_deref();

            find_definition_by_name(symbol_name, file, effective_project, &lang_hint)?
        } else {
            // Position-based mode
            let file = self
                .file
                .as_ref()
                .ok_or_else(|| RemainingError::invalid_argument("file argument is required"))?;
            let line = self
                .line
                .ok_or_else(|| RemainingError::invalid_argument("line argument is required"))?;
            let column = self
                .column
                .ok_or_else(|| RemainingError::invalid_argument("column argument is required"))?;

            writer.progress(&format!(
                "Finding definition at {}:{}:{}...",
                file.display(),
                line,
                column
            ));

            // Workspace cross-file resolution (definition-workspace-cross-file-v1
            // + F4b-definition-py-import): resolve the effective cross-file
            // root, honouring an explicit --project, --workspace=false opt-out,
            // and the Python package-dir fallback for marker-less trees.
            let root_lang = detect_language(file, &lang_hint).ok();
            let effective_project_buf = resolve_definition_root(
                self.project.as_deref(),
                self.workspace,
                file,
                root_lang,
            );
            let effective_project = effective_project_buf.as_deref();

            // r7-cl11: normalize the declared-encoding INPUT column to the
            // 0-indexed UTF-8 byte column the resolver consumes internally.
            // The index-base stays 0-indexed (default contract); only the
            // *encoding* is converted. For `utf8` this is the identity, so
            // every existing 0-indexed positional query is unchanged.
            let byte_column = if encoding == PositionEncoding::Utf8Byte {
                column
            } else {
                match fs::read_to_string(file) {
                    Ok(src) => {
                        let li = LineIndex::new(&src);
                        let row0 = line.saturating_sub(1) as usize;
                        li.enc_col_to_byte(row0, column as usize, encoding) as u32
                    }
                    // File unreadable: let the resolver surface FileNotFound.
                    Err(_) => column,
                }
            };

            match find_definition_by_position(
                file,
                line,
                byte_column,
                effective_project,
                &lang_hint,
            ) {
                Ok(result) => result,
                Err(e) => {
                    // M2 (med-cleanup-bundle-v1): when the resolver returns
                    // an "unresolved at ..." sentinel (or any genuine
                    // resolution failure), exit non-zero with a clear stderr
                    // error. Previously we silently returned a fake-success
                    // JSON payload with `name: "<unknown at ...>"` — the
                    // CLI exited 0 and downstream tooling could not detect
                    // the failure.
                    //
                    // med-low-schema-cleanup-v1 (N9): preserve the
                    // typed `RemainingError` so `main` can downcast it
                    // and emit the standardized exit code (5 for
                    // missing-file, 20 for symbol-not-found).
                    // Previously we wrapped every failure into a plain
                    // `anyhow::anyhow!` string which discarded the
                    // type and collapsed every definition failure
                    // onto exit 1.
                    match e {
                        RemainingError::FileNotFound { .. }
                        | RemainingError::SymbolNotFound { .. } => return Err(e.into()),
                        _ => {
                            let msg = e.to_string();
                            let detail = if msg.contains("unresolved at") {
                                // The InvalidArgument sentinel already
                                // contains the file:line:col anchor —
                                // propagate verbatim.
                                msg
                            } else {
                                format!(
                                    "definition not found for {}:{}:{}: {}",
                                    file.display(),
                                    line,
                                    column,
                                    msg
                                )
                            };
                            return Err(anyhow::anyhow!(detail));
                        }
                    }
                }
            }
        };

        // r7-cl11: re-encode the REPORTED columns into the declared output
        // encoding. No-op for the default `utf8` (the 1-indexed byte-column
        // contract is preserved exactly); under `utf16`/`utf32` the columns
        // become LSP-correct on non-ASCII lines.
        let mut result = result;
        reencode_result_columns(&mut result, encoding);

        // Determine output format
        let use_text = format == crate::output::OutputFormat::Text;

        // Write output
        if let Some(ref output_path) = self.output {
            if use_text {
                let text = format_definition_text(&result);
                fs::write(output_path, text)?;
            } else {
                let json = serde_json::to_string_pretty(&result)?;
                fs::write(output_path, json)?;
            }
        } else if use_text {
            let text = format_definition_text(&result);
            writer.write_text(&text)?;
        } else {
            writer.write(&result)?;
        }

        Ok(())
    }
}

// =============================================================================
// Core Functions
// =============================================================================

/// Find definition by symbol name
pub fn find_definition_by_name(
    symbol: &str,
    file: &Path,
    project: Option<&Path>,
    lang_hint: &str,
) -> RemainingResult<DefinitionResult> {
    // Validate file exists
    if !file.exists() {
        return Err(RemainingError::file_not_found(file));
    }

    // Detect language. Returns UnsupportedLanguage for genuinely unknown
    // extensions; the supported set covers all 18 TLDR languages (VAL-015).
    let language = detect_language(file, lang_hint)?;

    // Python builtins still surface as a builtin definition with no
    // location — every other language goes straight to source resolution.
    if is_builtin(symbol, &language) {
        return Ok(DefinitionResult {
            symbol: SymbolInfo {
                name: symbol.to_string(),
                kind: SymbolKind::Function,
                location: None,
                type_annotation: None,
                docstring: None,
                is_builtin: true,
                module: Some("builtins".to_string()),
            },
            definition: None,
            type_definition: None,
        });
    }

    // Read and parse file
    let source = fs::read_to_string(file).map_err(RemainingError::Io)?;

    // Try to find the symbol in this file first
    if let Some(result) = find_symbol_in_file(symbol, file, &source, language)? {
        return Ok(result);
    }

    // If not found and we have a project context, try cross-file resolution.
    // `project` is the caller-supplied resolution root; `None` means the
    // caller opted out of cross-file resolution (e.g. `--workspace=false`),
    // so we stay single-file. The CLI computes this root via
    // [`resolve_definition_root`], which supplies a Python package-dir
    // fallback for marker-less trees (see F4b-definition-py-import).
    if let Some(project_root) = project {
        let mut detector = DefinitionCycleDetector::new();
        if let Some(result) =
            resolve_cross_file(symbol, file, project_root, language, &mut detector, 0)?
        {
            return Ok(result);
        }
    }

    Err(RemainingError::symbol_not_found(symbol, file))
}

/// Find definition by position (line, column)
///
/// Implements a three-pass resolver (`definition-name-resolution-v1`) so
/// that cursors on USAGE sites resolve, not just on declaration sites:
///
/// 1. **Local scope**: walk up tree-sitter ancestors from the cursor and
///    look at parameter lists / let-bindings / var declarations of each
///    enclosing function/method/block. If a binding name matches the
///    symbol text, return that binding's location.
/// 2. **File scope**: scan the file for top-level definitions
///    (functions, classes, Python module-level assignments). Reuses the
///    existing [`find_symbol_in_file`] helper.
/// 3. **Import scope**: if the symbol matches an `import` / `use`
///    alias, return the import line (so `click` in `click.echo(...)`
///    resolves to `import click`).
///
/// If none match the result is a clear `<unresolved at FILE:LINE:COL —
/// symbol 'X' not found in scope>` payload, not the legacy
/// `<unknown ...>` opaque.
pub fn find_definition_by_position(
    file: &Path,
    line: u32,
    column: u32,
    project: Option<&Path>,
    lang_hint: &str,
) -> RemainingResult<DefinitionResult> {
    // Validate file exists
    if !file.exists() {
        return Err(RemainingError::file_not_found(file));
    }

    // Detect language. Supports all 18 TLDR languages (VAL-015).
    let language = detect_language(file, lang_hint)?;

    // Read and parse file
    let source = fs::read_to_string(file).map_err(RemainingError::Io)?;

    // Find symbol at position
    let symbol_name = find_symbol_at_position(&source, line, column, language, file)?;

    // Pass 1: try local-scope resolution from the cursor position.
    // This catches usages of parameters and locally-declared variables
    // before we fall through to the file/import scopes.
    if let Some(result) =
        resolve_local_scope(&source, line, column, &symbol_name, language, file)?
    {
        return Ok(result);
    }

    // C2 (v0.5.0 AUDIT-FIX): Lua/Luau standard-library member access
    // (`string.find`, `table.insert`, …). A local binding that shadows
    // the stdlib name would already have resolved in Pass 1 above, so by
    // the time we get here a `lib.member` whose base is a stdlib table is
    // genuinely a builtin call. Return a clean builtin result rather than
    // letting the trailing-segment cross-file fallback latch onto an
    // unrelated user symbol named after the member (the live
    // `string.find` -> `tables.luau:182` regression).
    if let Some(lib) = lua_stdlib_member(&symbol_name, language) {
        let member = trailing_segment(&symbol_name);
        return Ok(builtin_definition_result(&member, lib));
    }

    // Pass 2 (+ optional cross-file): existing name-based search. This
    // covers top-level functions, classes, and Python module-level
    // assignments.
    match find_definition_by_name(&symbol_name, file, project, lang_hint) {
        Ok(result) => Ok(result),
        Err(RemainingError::SymbolNotFound { .. }) => {
            // sibling-resolver-gaps-v1 (P14.AGG14-6): when the
            // resolver returned a qualified name (e.g. `m.reset` from
            // a lua `function m.reset()` line, or `Class::method` for
            // C++), the per-file definition lookup may not match the
            // dotted form. Retry once with the trailing segment so the
            // user gets a useful answer rather than "not found".
            let trailing = trailing_segment(&symbol_name);
            if trailing != symbol_name && !trailing.is_empty() {
                if let Ok(result) =
                    find_definition_by_name(&trailing, file, project, lang_hint)
                {
                    return Ok(result);
                }
            }
            // Pass 3: import-scope resolution. If the cursor sits on an
            // imported alias (`click` in `click.echo(...)`), resolve to
            // the `import` line.
            if let Some(result) = resolve_import_scope(&source, &symbol_name, language, file)? {
                return Ok(result);
            }
            // Total miss — surface a clearer message than the legacy
            // `<unknown>` shape.
            Err(RemainingError::invalid_argument(format!(
                "unresolved at {}:{}:{} — symbol '{}' not found in scope",
                file.display(),
                line,
                column,
                symbol_name
            )))
        }
        Err(e) => Err(e),
    }
}

/// Last `.` / `::`-separated segment (e.g. `m.reset` -> `reset`,
/// `XMLDocument::Parse` -> `Parse`, `plain` -> `plain`). Used by the
/// keyword-skip fallback in the position-based definition lookup.
fn trailing_segment(s: &str) -> String {
    let mut tail = s;
    if let Some(idx) = s.rfind("::") {
        tail = &s[idx + 2..];
    }
    if let Some(idx) = tail.rfind('.') {
        tail = &tail[idx + 1..];
    }
    tail.to_string()
}

/// Pass 1: local-scope resolution.
///
/// Walks up tree-sitter ancestors from the cursor node. For each
/// function/method/closure/block ancestor, scans its parameters and
/// variable bindings. The first matching binding wins (innermost
/// scope).
///
/// Currently covers Python (parameters, simple `=` assignments), the
/// JS/TS family (parameters, `let`/`const`/`var`), and Rust
/// (parameters, `let` bindings). Other languages fall through to the
/// next pass without resolving locally — this is the documented
/// carry-forward.
fn resolve_local_scope(
    source: &str,
    line: u32,
    column: u32,
    symbol: &str,
    language: Language,
    file: &Path,
) -> RemainingResult<Option<DefinitionResult>> {
    // Only the languages with implemented binding scrapers participate.
    // Other languages return None, falling through to file/import passes.
    if !matches!(
        language,
        Language::Python
            | Language::JavaScript
            | Language::TypeScript
            | Language::Rust
            | Language::Go
            | Language::Java
            | Language::C
            | Language::Cpp
            | Language::Ruby
            | Language::Kotlin
            | Language::Swift
            | Language::Scala
            | Language::Php
            | Language::Lua
            | Language::Luau
            | Language::Elixir
            | Language::Ocaml
            | Language::CSharp
            // C2 (v0.5.0 AUDIT-FIX): Solidity participates so contract
            // state variables and function parameters resolve via
            // `scan_solidity_scope`.
            | Language::Solidity
    ) {
        return Ok(None);
    }

    let tree = PARSER_POOL
        .parse_with_path(source, language, Some(file))
        .map_err(|e| RemainingError::parse_error(file.to_path_buf(), e.to_string()))?;
    let root = tree.root_node();
    let target_line = line.saturating_sub(1) as usize;
    let target_col = column as usize;
    let point = tree_sitter::Point::new(target_line, target_col);
    let Some(start_node) = root.descendant_for_point_range(point, point) else {
        return Ok(None);
    };

    // Walk up ancestors, scanning each scope-introducing ancestor for
    // bindings.
    let mut current = Some(start_node);
    let mut scanned_root = false;
    while let Some(node) = current {
        if is_scope_node(node.kind(), language) {
            // T7 (AUDIT-FIX): if the cursor is ON this scope owner's own
            // name/declarator, it is a DECLARATION site, not a usage — e.g.
            // `def handler():` queried at `handler`, or
            // `func (r *Router) allowed(...)` queried at `allowed`. Decline
            // local resolution so control falls through to Pass 2, which
            // returns the self-referential declaration location. Without
            // this guard `scan_scope_for_binding` would walk the body below
            // and return the FIRST same-named descendant — a local shadow of
            // the same name — as the "definition". The check is byte-range
            // (node identity), so it fires only at the declarator and leaves
            // every usage query (cursor on a use) to hit Pass 1 unchanged.
            if cursor_on_scope_declarator(node, start_node, language) {
                return Ok(None);
            }
            if node.parent().is_none() {
                scanned_root = true;
            }
            if let Some(loc) =
                scan_scope_for_binding(node, source, symbol, language, file, start_node)
            {
                return Ok(Some(make_local_result(symbol, loc)));
            }
        }
        current = node.parent();
    }

    // C2 (v0.5.0 AUDIT-FIX): class fields / properties declared at the
    // class-body level are SIBLINGS of the method that uses them, so the
    // ancestor walk above only reaches them when the enclosing class
    // container is itself a scope node (kotlin `class_body`, scala
    // `template_body`, solidity `contract_declaration`, …). Two cases
    // slip through:
    //
    //   1. A class container kind that is not (yet) listed in
    //      `is_scope_node` for the language.
    //   2. A file that failed to fully parse, leaving the tree-sitter
    //      ROOT as an `ERROR` node rather than the normal
    //      `source_file` / `compilation_unit`. The real Semaphore.kt
    //      audit case parses to an `ERROR` root with the `private val`
    //      property and the consuming function as direct children of
    //      that ERROR node.
    //
    // For languages whose scope scanner is class-field-aware (it matches
    // property / field / val-var declarations and stops at nested
    // class/function boundaries), do a final scan of the ROOT node when
    // it was not already scanned. This is safe and idempotent: the
    // scanner only returns property/field bindings, never re-derives an
    // inner-scope local that the ancestor walk already rejected.
    if !scanned_root && language_has_class_fields(language) {
        if let Some(loc) =
            scan_scope_for_binding(root, source, symbol, language, file, start_node)
        {
            return Ok(Some(make_local_result(symbol, loc)));
        }
    }

    Ok(None)
}

/// T7 declaration-site guard. Returns true when `cursor` sits on
/// `scope`'s own name/declarator — i.e. the cursor is a *declaration*
/// site (`def handler`, `func (r *Router) allowed`), not a *usage*. In
/// that case [`resolve_local_scope`] must decline so the file-scope pass
/// returns the self-referential declaration rather than a same-named
/// local shadow scanned out of the body. The match is by byte-range
/// containment (node identity), never by text, so it fires only when the
/// cursor is literally on the declarator.
fn cursor_on_scope_declarator(scope: Node, cursor: Node, language: Language) -> bool {
    match scope_name_node(scope, language) {
        Some(name) => {
            cursor.start_byte() >= name.start_byte() && cursor.end_byte() <= name.end_byte()
        }
        None => false,
    }
}

/// The identifier node that NAMES a scope-owning declaration, used by the
/// T7 declaration-site guard. For the vast majority of languages
/// tree-sitter exposes this as the `name` field (Python
/// `function_definition`; Go `function_declaration` / `method_declaration`
/// — the Go receiver lives in a separate `receiver` field, so `name` is
/// just the method name; Rust; the JS/TS family; Java; etc.). C / C++
/// instead nest the name inside a `declarator` chain whose range also
/// spans the parameter list, so we drill through the declarator to the
/// innermost name identifier; that keeps the guard from misfiring on a
/// parameter cursor.
fn scope_name_node(scope: Node, language: Language) -> Option<Node> {
    if matches!(language, Language::C | Language::Cpp) && scope.kind() == "function_definition" {
        return c_declarator_name_node(scope.child_by_field_name("declarator")?);
    }
    scope.child_by_field_name("name")
}

/// Drill a C / C++ `declarator` chain (`pointer_declarator`,
/// `reference_declarator`, `function_declarator`,
/// `parenthesized_declarator`, …) down to the innermost identifier-like
/// node that spells the function name. Returns `None` if no name
/// identifier is reachable.
fn c_declarator_name_node(mut decl: Node) -> Option<Node> {
    loop {
        match decl.kind() {
            "identifier" | "field_identifier" | "qualified_identifier" | "destructor_name"
            | "operator_name" | "operator_cast" => return Some(decl),
            _ => {
                decl = decl.child_by_field_name("declarator")?;
            }
        }
    }
}

/// Build a [`DefinitionResult`] for a local-scope binding hit.
fn make_local_result(symbol: &str, loc: (SymbolKind, Location)) -> DefinitionResult {
    DefinitionResult {
        symbol: SymbolInfo {
            name: symbol.to_string(),
            kind: loc.0,
            location: Some(loc.1.clone()),
            type_annotation: None,
            docstring: None,
            is_builtin: false,
            module: None,
        },
        definition: Some(loc.1),
        type_definition: None,
    }
}

/// Languages whose local-scope scanner can resolve a class-body-level
/// field / property declaration (and therefore benefit from the
/// root-node fallback scan in [`resolve_local_scope`]). These scanners
/// match `val`/`var`/property/state-variable forms and stop at nested
/// class/function boundaries, so scanning the outermost node never
/// leaks an unrelated inner binding.
fn language_has_class_fields(language: Language) -> bool {
    matches!(
        language,
        Language::Kotlin
            | Language::Scala
            | Language::Swift
            | Language::Java
            | Language::CSharp
            | Language::Solidity
    )
}

/// Returns true for tree-sitter node kinds that introduce a new
/// lexical scope in the given language. Used by
/// [`resolve_local_scope`] to bound the per-scope binding scan.
fn is_scope_node(kind: &str, language: Language) -> bool {
    match language {
        Language::Python => matches!(
            kind,
            "function_definition" | "lambda" | "module"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            kind,
            "function_declaration"
                | "function"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "method_signature"
                | "statement_block"
                | "program"
        ),
        Language::Rust => matches!(
            kind,
            "function_item"
                | "closure_expression"
                | "block"
                | "source_file"
        ),
        Language::Go => matches!(
            kind,
            "function_declaration" | "method_declaration" | "block" | "source_file"
        ),
        Language::Java => matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "block"
                | "program"
        ),
        Language::C => matches!(
            kind,
            "function_definition" | "compound_statement" | "translation_unit"
        ),
        Language::Cpp => matches!(
            kind,
            "function_definition"
                | "lambda_expression"
                | "compound_statement"
                | "translation_unit"
        ),
        Language::Ruby => matches!(
            kind,
            "method"
                | "singleton_method"
                | "do_block"
                | "block"
                | "lambda"
                | "program"
        ),
        Language::Kotlin => matches!(
            kind,
            "function_declaration"
                | "anonymous_function"
                | "lambda_literal"
                | "function_body"
                | "statements"
                // C2 (v0.5.0 AUDIT-FIX): the class body is a scope so a
                // method can see its enclosing class's `val`/`var`
                // properties. `kotlin_walk_for_binding` still stops at a
                // *nested* `class_declaration`, so this does not leak
                // inner-class fields into an outer scope.
                | "class_body"
                | "class_declaration"
                | "object_declaration"
                | "enum_class_body"
                | "source_file"
        ),
        Language::Swift => matches!(
            kind,
            "function_declaration"
                | "init_declaration"
                | "deinit_declaration"
                | "lambda_literal"
                | "function_body"
                | "statements"
                // C2 (v0.5.0 AUDIT-FIX): class/struct/enum/protocol body
                // scope so a method can resolve sibling `let`/`var`
                // properties. `swift_walk_for_binding` stops at nested
                // type declarations.
                | "class_body"
                | "class_declaration"
                | "protocol_body"
                | "enum_class_body"
                | "source_file"
        ),
        Language::Scala => matches!(
            kind,
            "function_definition"
                | "function_declaration"
                | "lambda_expression"
                | "block"
                // C2 (v0.5.0 AUDIT-FIX): scan the class/trait/object
                // body so a method can resolve sibling `val`/`var`
                // fields. `scala_walk_for_binding` stops at a nested
                // class/object/trait definition.
                | "class_definition"
                | "object_definition"
                | "trait_definition"
                | "template_body"
                | "compilation_unit"
        ),
        Language::Php => matches!(
            kind,
            "function_definition"
                | "method_declaration"
                | "anonymous_function_creation_expression"
                | "arrow_function"
                | "compound_statement"
                | "program"
        ),
        Language::Lua | Language::Luau => matches!(
            kind,
            "function_declaration"
                | "function_definition"
                | "function_definition_statement"
                | "function_statement"
                | "local_function"
                | "local_function_statement"
                | "function"
                | "function_body"
                | "do_statement"
                | "block"
                | "chunk"
        ),
        Language::Elixir => matches!(
            kind,
            "call" | "do_block" | "anonymous_function" | "stab_clause" | "source"
        ),
        Language::Ocaml => matches!(
            kind,
            "let_binding"
                | "value_definition"
                | "fun_expression"
                | "function_expression"
                | "compilation_unit"
        ),
        Language::CSharp => matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
                | "block"
                | "compilation_unit"
        ),
        // v0.5.0 SOL-001: Solidity introduces scopes at every
        // function-shape, contract/interface/library body, and any
        // `block`. SOL-002 may refine this.
        Language::Solidity => matches!(
            kind,
            "function_definition"
                | "constructor_definition"
                | "fallback_function_definition"
                | "receive_function_definition"
                | "modifier_definition"
                | "contract_declaration"
                | "interface_declaration"
                | "library_declaration"
                | "function_body"
                | "block"
                | "source_file"
        ),
    }
}

/// Scan the given scope `node` for a binding with name `symbol`.
/// Returns the kind + location of the first match found (intra-scope
/// order, recursive into bindings only).
fn scan_scope_for_binding(
    node: Node,
    source: &str,
    symbol: &str,
    language: Language,
    file: &Path,
    cursor: Node,
) -> Option<(SymbolKind, Location)> {
    // Search only the scope's immediate body, but recurse into binding
    // forms. We delegate to a language-specific recursive helper.
    let bytes = source.as_bytes();
    match language {
        Language::Python => scan_python_scope(node, bytes, symbol, file),
        Language::JavaScript | Language::TypeScript => scan_jslike_scope(node, bytes, symbol, file),
        Language::Rust => scan_rust_scope(node, bytes, symbol, file),
        Language::Go => scan_go_scope(node, bytes, symbol, file),
        Language::Java => scan_java_scope(node, bytes, symbol, file),
        Language::C | Language::Cpp => scan_clike_scope(node, bytes, symbol, file),
        Language::Ruby => scan_ruby_scope(node, bytes, symbol, file),
        Language::Kotlin => scan_kotlin_scope(node, bytes, symbol, file),
        Language::Swift => scan_swift_scope(node, bytes, symbol, file),
        Language::Scala => scan_scala_scope(node, bytes, symbol, file),
        Language::Php => scan_php_scope(node, bytes, symbol, file),
        Language::Lua | Language::Luau => scan_lua_scope(node, bytes, symbol, file),
        Language::Elixir => scan_elixir_scope(node, bytes, symbol, file),
        Language::Ocaml => scan_ocaml_scope(node, bytes, symbol, file, cursor),
        Language::CSharp => scan_csharp_scope(node, bytes, symbol, file),
        // v0.5.0 C2 AUDIT-FIX: Solidity scope-binding scanner resolves
        // contract state variables and function/constructor parameters.
        Language::Solidity => scan_solidity_scope(node, bytes, symbol, file),
    }
}

/// Python-specific scope binding scanner.
///
/// Looks at the scope node's parameter list (when it is a function or
/// lambda) and recursively at `assignment` and `for` statements within
/// the body. Stops at nested function/class/lambda boundaries to
/// preserve lexical scoping.
fn scan_python_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // Parameters first (only meaningful on function_definition / lambda).
    if matches!(node.kind(), "function_definition" | "lambda") {
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(loc) = python_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    // Walk body looking for assignments / for-targets, but don't descend
    // into nested function/class/lambda scopes.
    let body = node
        .child_by_field_name("body")
        .or_else(|| Some(node));
    if let Some(body) = body {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if let Some(loc) = python_walk_for_binding(child, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    None
}

fn python_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                if child.utf8_text(src).ok()? == symbol {
                    return Some(make_param_location(child, file));
                }
            }
            // Default-argument and typed-parameter shapes wrap the name.
            "default_parameter"
            | "typed_parameter"
            | "typed_default_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => {
                let name_node = match child.child_by_field_name("name") {
                    Some(n) => Some(n),
                    None => {
                        // Fallback: first identifier child.
                        let mut c = child.walk();
                        let found = child
                            .children(&mut c)
                            .find(|n| n.kind() == "identifier");
                        found
                    }
                };
                if let Some(name) = name_node {
                    if name.utf8_text(src).ok()? == symbol {
                        return Some(make_param_location(name, file));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn python_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        // Don't descend into nested scopes — they have their own bindings.
        "function_definition" | "class_definition" | "lambda" => None,
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(loc) = python_match_target(left, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
        "for_statement" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(loc) = python_match_target(left, src, symbol, file) {
                    return Some(loc);
                }
            }
            // Continue into body.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = python_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = python_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

fn python_match_target(
    target: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match target.kind() {
        "identifier" => {
            if target.utf8_text(src).ok()? == symbol {
                Some((
                    SymbolKind::Variable,
                    Location::with_column(
                        file.display().to_string(),
                        target.start_position().row as u32 + 1,
                        // scala-column-unification-v1 (v0.4.1 bug-B):
                        // tree-sitter `Point::column` is 0-indexed.
                        // Emit 1-indexed columns to agree with the
                        // 18 sites in `analysis/references.rs` that
                        // already do `+ 1`.
                        target.start_position().column as u32 + 1,
                    ),
                ))
            } else {
                None
            }
        }
        // Tuple / list patterns: `a, b = ...`
        "pattern_list" | "tuple_pattern" | "list_pattern" => {
            let mut cursor = target.walk();
            for child in target.children(&mut cursor) {
                if let Some(loc) = python_match_target(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
        _ => None,
    }
}

fn make_param_location(name: Node, file: &Path) -> (SymbolKind, Location) {
    (
        SymbolKind::Parameter,
        Location::with_column(
            file.display().to_string(),
            name.start_position().row as u32 + 1,
            // scala-column-unification-v1 (v0.4.1 bug-B): 1-indexed
            // column. Used by every language's parameter scanner
            // (rust/go/scala/java/c/cpp/ruby/kotlin/swift/php/csharp/
            // python/elixir).
            name.start_position().column as u32 + 1,
        ),
    )
}

/// JS/TS scope binding scanner. Handles formal parameters and
/// `let`/`const`/`var` declarations.
fn scan_jslike_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if let Some(params) = node.child_by_field_name("parameters") {
        if let Some(loc) = jslike_scan_params(params, src, symbol, file) {
            return Some(loc);
        }
    }
    // Walk body for variable_declarations.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = jslike_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn jslike_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                if child.utf8_text(src).ok()? == symbol {
                    return Some(make_param_location(child, file));
                }
            }
            "required_parameter" | "optional_parameter" | "rest_pattern"
            | "assignment_pattern" => {
                let pat_node = match child.child_by_field_name("pattern") {
                    Some(n) => Some(n),
                    None => {
                        let mut c = child.walk();
                        let found = child
                            .children(&mut c)
                            .find(|n| n.kind() == "identifier");
                        found
                    }
                };
                if let Some(pat) = pat_node {
                    if pat.kind() == "identifier" && pat.utf8_text(src).ok()? == symbol {
                        return Some(make_param_location(pat, file));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn jslike_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        // Don't descend into nested scopes.
        "function_declaration" | "function" | "function_expression" | "arrow_function"
        | "method_definition" | "method_signature" | "class_declaration" => None,
        "lexical_declaration" | "variable_declaration" => {
            // children are variable_declarators
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if name.kind() == "identifier"
                            && name.utf8_text(src).ok()? == symbol
                        {
                            return Some((
                                SymbolKind::Variable,
                                Location::with_column(
                                    file.display().to_string(),
                                    name.start_position().row as u32 + 1,
                                    // scala-column-unification-v1
                                    // (v0.4.1 bug-B): 1-indexed.
                                    name.start_position().column as u32 + 1,
                                ),
                            ));
                        }
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = jslike_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Rust scope binding scanner. Handles function parameters and
/// `let` bindings.
fn scan_rust_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(node.kind(), "function_item" | "closure_expression") {
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(loc) = rust_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = rust_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn rust_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() == "parameter" {
            if let Some(pat) = child.child_by_field_name("pattern") {
                if pat.kind() == "identifier" && pat.utf8_text(src).ok()? == symbol {
                    return Some(make_param_location(pat, file));
                }
            }
        }
    }
    None
}

fn rust_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        // Don't descend into nested scopes.
        "function_item" | "closure_expression" | "impl_item" => None,
        "let_declaration" => {
            if let Some(pat) = node.child_by_field_name("pattern") {
                if pat.kind() == "identifier" && pat.utf8_text(src).ok()? == symbol {
                    return Some((
                        SymbolKind::Variable,
                        Location::with_column(
                            file.display().to_string(),
                            pat.start_position().row as u32 + 1,
                            // scala-column-unification-v1
                            // (v0.4.1 bug-B): 1-indexed.
                            pat.start_position().column as u32 + 1,
                        ),
                    ));
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = rust_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Go scope binding scanner. Handles function parameters and
/// short variable declarations (`x := ...`).
fn scan_go_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(node.kind(), "function_declaration" | "method_declaration") {
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                if child.kind() == "parameter_declaration" {
                    let mut c = child.walk();
                    for n in child.children(&mut c) {
                        if n.kind() == "identifier" && n.utf8_text(src).ok()? == symbol {
                            return Some(make_param_location(n, file));
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = go_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn go_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_declaration" | "method_declaration" | "func_literal" => None,
        "short_var_declaration" | "var_declaration" => {
            if let Some(left) = node.child_by_field_name("left") {
                let mut c = left.walk();
                for n in left.children(&mut c) {
                    if n.kind() == "identifier" && n.utf8_text(src).ok()? == symbol {
                        return Some((
                            SymbolKind::Variable,
                            Location::with_column(
                                file.display().to_string(),
                                n.start_position().row as u32 + 1,
                                // scala-column-unification-v1
                                // (v0.4.1 bug-B): 1-indexed.
                                n.start_position().column as u32 + 1,
                            ),
                        ));
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = go_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

// =============================================================================
// Local-scope scanners for the 13 additional languages
// (definition-additional-langs-v1)
// =============================================================================

/// Build a (Variable, Location) pair from a name node.
fn make_var_location(name: Node, file: &Path) -> (SymbolKind, Location) {
    (
        SymbolKind::Variable,
        Location::with_column(
            file.display().to_string(),
            name.start_position().row as u32 + 1,
            // scala-column-unification-v1 (v0.4.1 bug-B): 1-indexed
            // column. Shared by every language's local-variable
            // scanner (scala val/var, java/csharp/kotlin/swift/ruby/
            // php/c/cpp locals).
            name.start_position().column as u32 + 1,
        ),
    )
}

/// Walk all descendants of `node` looking for the FIRST identifier-typed
/// child whose text matches `symbol`. Stops descent at scope-introducing
/// boundaries provided by `is_scope_boundary`. Used by language scanners
/// that share a common AST shape.
fn name_node_matches(n: Node, src: &[u8], symbol: &str) -> bool {
    if let Ok(t) = n.utf8_text(src) {
        t == symbol
    } else {
        false
    }
}

/// Java scope binding scanner. Handles formal parameters, local variable
/// declarations, and enhanced-for loop parameters.
fn scan_java_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "method_declaration" | "constructor_declaration" | "lambda_expression"
    ) {
        if let Some(params) = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("formal_parameters"))
        {
            if let Some(loc) = java_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = java_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn java_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if matches!(child.kind(), "formal_parameter" | "spread_parameter") {
            if let Some(name) = child.child_by_field_name("name") {
                if name_node_matches(name, src, symbol) {
                    return Some(make_param_location(name, file));
                }
            }
        } else if child.kind() == "identifier" && name_node_matches(child, src, symbol) {
            // Lambda-style `(x, y) -> ...`
            return Some(make_param_location(child, file));
        } else if child.kind() == "inferred_parameters" {
            let mut c = child.walk();
            for n in child.children(&mut c) {
                if n.kind() == "identifier" && name_node_matches(n, src, symbol) {
                    return Some(make_param_location(n, file));
                }
            }
        }
    }
    None
}

fn java_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "method_declaration"
        | "constructor_declaration"
        | "class_declaration"
        | "interface_declaration"
        | "lambda_expression" => None,
        "local_variable_declaration" => {
            // children include variable_declarator nodes
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if name_node_matches(name, src, symbol) {
                            return Some(make_var_location(name, file));
                        }
                    }
                }
            }
            None
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                if name_node_matches(name, src, symbol) {
                    return Some(make_var_location(name, file));
                }
            }
            // Continue into body
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = java_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = java_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// C / C++ scope binding scanner. Handles function parameters and local
/// variable declarations (declarator with init_declarator).
fn scan_clike_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if node.kind() == "function_definition" {
        // Parameters live under `declarator` -> `function_declarator` -> `parameters`
        if let Some(decl) = node.child_by_field_name("declarator") {
            if let Some(loc) = clike_scan_declarator_params(decl, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    if node.kind() == "lambda_expression" {
        // C++ lambdas: `[capture](params) { body }`
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "abstract_function_declarator" || child.kind() == "parameter_list" {
                if let Some(loc) = clike_scan_param_list(child, src, symbol, file) {
                    return Some(loc);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = clike_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn clike_scan_declarator_params(
    declarator: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // Walk to find a `parameter_list`.
    let mut cursor = declarator.walk();
    for child in declarator.children(&mut cursor) {
        if child.kind() == "parameter_list" {
            if let Some(loc) = clike_scan_param_list(child, src, symbol, file) {
                return Some(loc);
            }
        } else if matches!(
            child.kind(),
            "function_declarator" | "parenthesized_declarator"
        ) {
            if let Some(loc) = clike_scan_declarator_params(child, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    None
}

fn clike_scan_param_list(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            // Walk descendants for a `identifier` (the parameter name).
            if let Some(name) = clike_find_param_identifier(child, src, symbol) {
                return Some(make_param_location(name, file));
            }
        }
    }
    None
}

fn clike_find_param_identifier<'a>(
    node: Node<'a>,
    src: &[u8],
    symbol: &str,
) -> Option<Node<'a>> {
    if matches!(node.kind(), "identifier" | "field_identifier") && name_node_matches(node, src, symbol)
    {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(n) = clike_find_param_identifier(child, src, symbol) {
            return Some(n);
        }
    }
    None
}

fn clike_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_definition" | "lambda_expression" => None,
        "declaration" | "init_declarator" => {
            // Find the declarator name(s).
            if let Some(name) = clike_extract_decl_name(node, src, symbol) {
                return Some(make_var_location(name, file));
            }
            // Continue into siblings.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = clike_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = clike_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

fn clike_extract_decl_name<'a>(node: Node<'a>, src: &[u8], symbol: &str) -> Option<Node<'a>> {
    // For `declaration`, look for `init_declarator` or `declarator` -> identifier.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "init_declarator" => {
                if let Some(decl) = child.child_by_field_name("declarator") {
                    if let Some(n) = clike_extract_decl_name(decl, src, symbol) {
                        return Some(n);
                    }
                }
            }
            "identifier" | "field_identifier" => {
                if name_node_matches(child, src, symbol) {
                    return Some(child);
                }
            }
            "pointer_declarator" | "array_declarator" | "parenthesized_declarator"
            | "reference_declarator" => {
                if let Some(n) = clike_extract_decl_name(child, src, symbol) {
                    return Some(n);
                }
                // Or deeper: declarator field
                if let Some(inner) = child.child_by_field_name("declarator") {
                    if let Some(n) = clike_extract_decl_name(inner, src, symbol) {
                        return Some(n);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Ruby scope binding scanner. Handles method parameters and simple
/// local-variable assignments (`name = expr`). Recurses into block forms.
fn scan_ruby_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(node.kind(), "method" | "singleton_method" | "lambda" | "do_block" | "block") {
        // Parameters: method_parameters / block_parameters / lambda_parameters
        if let Some(params) = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("method_parameters"))
            .or_else(|| node.child_by_field_name("block_parameters"))
        {
            if let Some(loc) = ruby_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = ruby_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn ruby_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                if name_node_matches(child, src, symbol) {
                    return Some(make_param_location(child, file));
                }
            }
            "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "block_parameter" => {
                if let Some(name) = child.child_by_field_name("name") {
                    if name_node_matches(name, src, symbol) {
                        return Some(make_param_location(name, file));
                    }
                } else {
                    // fallback first identifier child
                    let mut c = child.walk();
                    for n in child.children(&mut c) {
                        if n.kind() == "identifier" && name_node_matches(n, src, symbol) {
                            return Some(make_param_location(n, file));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn ruby_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "method" | "singleton_method" | "class" | "module" | "lambda" => None,
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "identifier" && name_node_matches(left, src, symbol) {
                    return Some(make_var_location(left, file));
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = ruby_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Kotlin scope binding scanner. Handles function value parameters and
/// `val`/`var` property declarations.
fn scan_kotlin_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "function_declaration" | "anonymous_function" | "lambda_literal"
    ) {
        // `function_value_parameters` field "parameters", or direct child
        let params = node
            .child_by_field_name("parameters")
            .or_else(|| {
                let mut c = node.walk();
                let found = node.children(&mut c).find(|n| {
                    matches!(
                        n.kind(),
                        "function_value_parameters" | "lambda_parameters"
                    )
                });
                found
            });
        if let Some(params) = params {
            if let Some(loc) = kotlin_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = kotlin_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn kotlin_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if matches!(
            child.kind(),
            "parameter" | "function_value_parameter" | "value_parameter"
        ) {
            // first descendant identifier — but prefer field "name" / "simple_identifier"
            let name = child
                .child_by_field_name("name")
                .or_else(|| {
                    let mut c = child.walk();
                    let found = child
                        .children(&mut c)
                        .find(|n| matches!(n.kind(), "identifier" | "simple_identifier"));
                    found
                });
            if let Some(name) = name {
                if name_node_matches(name, src, symbol) {
                    return Some(make_param_location(name, file));
                }
            }
        } else if matches!(child.kind(), "identifier" | "simple_identifier")
            && name_node_matches(child, src, symbol)
        {
            return Some(make_param_location(child, file));
        }
    }
    None
}

fn kotlin_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_declaration"
        | "anonymous_function"
        | "lambda_literal"
        | "class_declaration"
        | "object_declaration" => None,
        "property_declaration" => {
            // variable_declaration child has the name
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declaration" {
                    let mut c = child.walk();
                    for n in child.children(&mut c) {
                        if matches!(n.kind(), "identifier" | "simple_identifier")
                            && name_node_matches(n, src, symbol)
                        {
                            return Some(make_var_location(n, file));
                        }
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = kotlin_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Swift scope binding scanner. Handles function parameters and
/// `let`/`var` property bindings.
fn scan_swift_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "function_declaration" | "init_declaration" | "lambda_literal"
    ) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(
                child.kind(),
                "parameter" | "value_parameter" | "lambda_function_type_parameters"
            ) {
                let name = child
                    .child_by_field_name("name")
                    .or_else(|| {
                        let mut c = child.walk();
                        let found = child
                            .children(&mut c)
                            .find(|n| matches!(n.kind(), "identifier" | "simple_identifier"));
                        found
                    });
                if let Some(name) = name {
                    if name_node_matches(name, src, symbol) {
                        return Some(make_param_location(name, file));
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = swift_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn swift_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_declaration" | "init_declaration" | "class_declaration"
        | "struct_declaration" | "enum_declaration" | "lambda_literal" => None,
        "property_declaration" => {
            // pattern: `let name = expr` or `var name = expr`
            // The `name` field or first `pattern` child holds the binding.
            let name = node.child_by_field_name("name").or_else(|| {
                let mut c = node.walk();
                let found = node.children(&mut c)
                    .find(|n| matches!(n.kind(), "identifier" | "simple_identifier" | "pattern"));
                found
            });
            if let Some(name) = name {
                // If it's a pattern, drill down to first identifier
                if name.kind() == "pattern" {
                    let mut c = name.walk();
                    for n in name.children(&mut c) {
                        if matches!(n.kind(), "identifier" | "simple_identifier")
                            && name_node_matches(n, src, symbol)
                        {
                            return Some(make_var_location(n, file));
                        }
                    }
                } else if name_node_matches(name, src, symbol) {
                    return Some(make_var_location(name, file));
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = swift_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Scala scope binding scanner. Handles function parameters and
/// `val`/`var`/`def` bindings within a block.
fn scan_scala_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "function_definition" | "function_declaration" | "lambda_expression"
    ) {
        // Parameters live under `parameters` field (a `parameters` node containing `parameter` items).
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(loc) = scala_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = scala_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn scala_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if matches!(child.kind(), "parameter" | "class_parameter" | "binding") {
            let name = child.child_by_field_name("name").or_else(|| {
                let mut c = child.walk();
                let found = child
                    .children(&mut c)
                    .find(|n| n.kind() == "identifier");
                found
            });
            if let Some(name) = name {
                if name_node_matches(name, src, symbol) {
                    return Some(make_param_location(name, file));
                }
            }
        } else if matches!(child.kind(), "identifier") && name_node_matches(child, src, symbol) {
            return Some(make_param_location(child, file));
        } else if matches!(child.kind(), "parameters" | "bindings") {
            // Nested parameter group (currying)
            if let Some(loc) = scala_scan_params(child, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    None
}

fn scala_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_definition" | "function_declaration" | "class_definition"
        | "object_definition" | "trait_definition" | "lambda_expression" => None,
        "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
            // pattern field or identifier
            let name = node.child_by_field_name("pattern").or_else(|| {
                let mut c = node.walk();
                let found = node.children(&mut c).find(|n| n.kind() == "identifier");
                found
            });
            if let Some(name) = name {
                if name.kind() == "identifier" && name_node_matches(name, src, symbol) {
                    return Some(make_var_location(name, file));
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = scala_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// PHP scope binding scanner. Handles function parameters and simple
/// variable assignments (`$x = ...`).
fn scan_php_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "function_definition"
            | "method_declaration"
            | "anonymous_function_creation_expression"
            | "arrow_function"
    ) {
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(loc) = php_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = php_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn php_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // PHP variable names always include the `$`. Accept both forms.
    let target_with_dollar = if symbol.starts_with('$') {
        symbol.to_string()
    } else {
        format!("${}", symbol)
    };
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if matches!(
            child.kind(),
            "simple_parameter"
                | "variadic_parameter"
                | "property_promotion_parameter"
        ) {
            // The name child is `variable_name` containing `$identifier`.
            if let Some(name) = child
                .child_by_field_name("name")
                .or_else(|| {
                    let mut c = child.walk();
                    let found = child
                        .children(&mut c)
                        .find(|n| n.kind() == "variable_name");
                    found
                })
            {
                if let Ok(t) = name.utf8_text(src) {
                    if t == target_with_dollar || t.trim_start_matches('$') == symbol.trim_start_matches('$') {
                        return Some(make_param_location(name, file));
                    }
                }
            }
        }
    }
    None
}

fn php_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_definition"
        | "method_declaration"
        | "anonymous_function_creation_expression"
        | "arrow_function"
        | "class_declaration" => None,
        "assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "variable_name" {
                    if let Ok(t) = left.utf8_text(src) {
                        let bare = t.trim_start_matches('$');
                        if bare == symbol.trim_start_matches('$') {
                            return Some(make_var_location(left, file));
                        }
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = php_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Lua / Luau scope binding scanner. Handles function parameters and
/// `local x = ...` declarations.
fn scan_lua_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // Function parameters
    if matches!(
        node.kind(),
        "function_declaration"
            | "function_definition"
            | "function_definition_statement"
            | "function_statement"
            | "local_function"
            | "local_function_statement"
            | "function"
    ) {
        // parameters under field "parameters" or as a direct child of kind "parameters"
        let params = node.child_by_field_name("parameters").or_else(|| {
            let mut c = node.walk();
            let found = node.children(&mut c).find(|n| n.kind() == "parameters");
            found
        });
        if let Some(params) = params {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                match child.kind() {
                    "identifier" | "name" => {
                        if name_node_matches(child, src, symbol) {
                            return Some(make_param_location(child, file));
                        }
                    }
                    // Luau wraps params in `parameter` nodes containing
                    // an `identifier` child (and optional type annotation).
                    "parameter" => {
                        let mut c = child.walk();
                        for n in child.children(&mut c) {
                            if matches!(n.kind(), "identifier" | "name")
                                && name_node_matches(n, src, symbol)
                            {
                                return Some(make_param_location(n, file));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = lua_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn lua_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_declaration"
        | "function_definition"
        | "function_definition_statement"
        | "function_statement"
        | "local_function"
        | "local_function_statement"
        | "function" => None,
        "local_variable_declaration"
        | "local_declaration"
        | "local_variable_declaration_statement"
        | "variable_declaration" => {
            // Walk children for name(s)
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "identifier" | "name" => {
                        if name_node_matches(child, src, symbol) {
                            return Some(make_var_location(child, file));
                        }
                    }
                    "variable_list" | "name_list" | "attnamelist" => {
                        let mut c = child.walk();
                        for n in child.children(&mut c) {
                            if matches!(n.kind(), "identifier" | "name")
                                && name_node_matches(n, src, symbol)
                            {
                                return Some(make_var_location(n, file));
                            }
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = lua_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Elixir scope binding scanner. Handles `def`/`defp` parameters via
/// AST surface scan. Note: Elixir's tree-sitter grammar models function
/// definitions as `call` nodes (call to `def`/`defp`/`defmacro`) so we
/// must check the call target name.
fn scan_elixir_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // For a `call` whose first identifier child is one of
    // def/defp/defmacro/defmacrop, walk its argument list to find the first
    // call (the function head) and scan its arguments for identifier params.
    if node.kind() == "call" {
        if let Some(name) = elixir_call_head_name(node, src) {
            if matches!(
                name.as_str(),
                "def" | "defp" | "defmacro" | "defmacrop"
            ) {
                // Find the `arguments` child and scan
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "arguments" {
                        if let Some(loc) = elixir_scan_def_args(child, src, symbol, file) {
                            return Some(loc);
                        }
                    }
                }
            }
        }
    }
    if node.kind() == "stab_clause" {
        // `fn x -> ... end` style anonymous functions
        if let Some(left) = node.child_by_field_name("left") {
            if let Some(loc) = elixir_scan_stab_left(left, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = elixir_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

/// For an Elixir `call` node, return the name of the call head — the first
/// `identifier` child (e.g. "def", "defp", "alias", "import").
fn elixir_call_head_name(node: Node, src: &[u8]) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return child.utf8_text(src).ok().map(|s| s.to_string());
            }
        }
    }
    None
}

fn elixir_scan_def_args(
    args: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // The first argument is typically a `call` (the function head).
    // For `def f(x) when guard(x)` the first argument is a `binary_operator`
    // whose left child is the head call.
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        let head_call = match child.kind() {
            "call" => Some(child),
            "binary_operator" => {
                // `when` guard form — the function head is the left child.
                let mut found: Option<Node> = None;
                let mut bc = child.walk();
                for bch in child.children(&mut bc) {
                    if bch.kind() == "call" {
                        found = Some(bch);
                        break;
                    }
                }
                found
            }
            _ => None,
        };
        if let Some(head) = head_call {
            // The head's arguments are an `arguments` child of the inner call.
            let mut cc = head.walk();
            for inner in head.children(&mut cc) {
                if inner.kind() == "arguments" {
                    let mut c = inner.walk();
                    for arg in inner.children(&mut c) {
                        if let Some(loc) = elixir_match_param(arg, src, symbol, file) {
                            return Some(loc);
                        }
                    }
                }
            }
            return None;
        } else if child.kind() == "identifier" && name_node_matches(child, src, symbol) {
            // Zero-arity def: `def foo, do: ...` — no params to match
            return None;
        }
    }
    None
}

fn elixir_scan_stab_left(
    left: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = left.walk();
    for child in left.children(&mut cursor) {
        if let Some(loc) = elixir_match_param(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn elixir_match_param(
    arg: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match arg.kind() {
        "identifier" => {
            if name_node_matches(arg, src, symbol) {
                Some(make_param_location(arg, file))
            } else {
                None
            }
        }
        // Default args: `x \\ 0` are represented as `binary_operator`
        "binary_operator" => {
            if let Some(left) = arg.child_by_field_name("left") {
                if left.kind() == "identifier" && name_node_matches(left, src, symbol) {
                    return Some(make_param_location(left, file));
                }
            }
            None
        }
        _ => None,
    }
}

fn elixir_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // Don't descend into nested defs.
    if node.kind() == "call" {
        if let Some(name) = elixir_call_head_name(node, src) {
            if matches!(
                name.as_str(),
                "def" | "defp" | "defmacro" | "defmacrop" | "defmodule"
            ) {
                return None;
            }
        }
    }
    // Match-pattern bindings: `x = expr`
    if node.kind() == "binary_operator" {
        if let Some(op) = node.child_by_field_name("operator") {
            if let Ok(o) = op.utf8_text(src) {
                if o == "=" {
                    if let Some(left) = node.child_by_field_name("left") {
                        if left.kind() == "identifier" && name_node_matches(left, src, symbol) {
                            return Some(make_var_location(left, file));
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = elixir_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

/// OCaml scope binding scanner. Handles `let f x = ...` parameters and
/// `let x = ...` value bindings.
fn scan_ocaml_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
    cursor_node: Node,
) -> Option<(SymbolKind, Location)> {
    // `value_definition` wraps one or more `let_binding` children — recurse
    // into them.
    if node.kind() == "value_definition" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                if let Some(loc) = ocaml_scan_let_binding_params(child, src, symbol, file) {
                    return Some(loc);
                }
            }
        }
    }
    if node.kind() == "let_binding" {
        if let Some(loc) = ocaml_scan_let_binding_params(node, src, symbol, file) {
            return Some(loc);
        }
    }
    if matches!(node.kind(), "fun_expression" | "function_expression") {
        // anon `fun x -> ...`
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(child.kind(), "parameter" | "value_pattern") {
                if let Some(name) = ocaml_find_first_ident(child, src, symbol) {
                    return Some(make_param_location(name, file));
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = ocaml_walk_for_binding(child, src, symbol, file, cursor_node) {
            return Some(loc);
        }
    }
    None
}

/// Scan a `let_binding` node's parameters (skipping the bound name).
fn ocaml_scan_let_binding_params(
    binding: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if child.kind() == "parameter" {
            if let Some(name) = ocaml_find_first_ident(child, src, symbol) {
                return Some(make_param_location(name, file));
            }
        }
    }
    None
}

fn ocaml_find_first_ident<'a>(node: Node<'a>, src: &[u8], symbol: &str) -> Option<Node<'a>> {
    if matches!(
        node.kind(),
        "value_name" | "value_pattern" | "lowercase_identifier" | "identifier"
    ) && name_node_matches(node, src, symbol)
    {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(n) = ocaml_find_first_ident(child, src, symbol) {
            return Some(n);
        }
    }
    None
}

fn ocaml_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
    cursor_node: Node,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "fun_expression" | "function_expression" => None,
        "let_binding" | "value_definition" => {
            // Match the bound name (first value_name / value_pattern that is a plain identifier).
            if ocaml_decline_nonrec_rhs_self_match(node, src, symbol, cursor_node) {
                return None;
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(child.kind(), "value_name" | "value_pattern") {
                    if let Some(name) = ocaml_find_first_ident(child, src, symbol) {
                        if name.start_byte() > cursor_node.start_byte() {
                            return None;
                        }
                        return Some(make_var_location(name, file));
                    }
                    // Stop after first — subsequent names are parameters.
                    break;
                }
            }
            if node.kind() == "value_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(loc) =
                        ocaml_walk_for_binding(child, src, symbol, file, cursor_node)
                    {
                        return Some(loc);
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) =
                    ocaml_walk_for_binding(child, src, symbol, file, cursor_node)
                {
                    return Some(loc);
                }
            }
            None
        }
    }
}

fn ocaml_decline_nonrec_rhs_self_match(
    node: Node,
    src: &[u8],
    symbol: &str,
    cursor_node: Node,
) -> bool {
    let Some(binding) = ocaml_binding_containing_cursor(node, cursor_node) else {
        return false;
    };
    if ocaml_binding_has_rec_token(binding, src) {
        return false;
    }
    let Some(bound_name) = ocaml_bound_name_node(binding, src, symbol) else {
        return false;
    };
    !node_contains(bound_name, cursor_node)
        && ocaml_binding_rhs_contains_cursor(binding, src, cursor_node)
}

fn ocaml_binding_containing_cursor<'a>(
    node: Node<'a>,
    cursor_node: Node<'a>,
) -> Option<Node<'a>> {
    if node.kind() == "let_binding" && node_contains(node, cursor_node) {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "let_binding" && node_contains(child, cursor_node) {
            return Some(child);
        }
    }
    if node.kind() == "value_definition" && node_contains(node, cursor_node) {
        return Some(node);
    }
    None
}

fn ocaml_binding_has_rec_token(binding: Node, src: &[u8]) -> bool {
    if ocaml_node_has_rec_token(binding, src) {
        return true;
    }
    match binding.parent() {
        Some(parent) => {
            parent.kind() == "value_definition" && ocaml_node_has_rec_token(parent, src)
        }
        None => false,
    }
}

fn ocaml_node_has_rec_token(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "rec" || matches!(child.utf8_text(src), Ok("rec")) {
            return true;
        }
    }
    false
}

fn ocaml_bound_name_node<'a>(binding: Node<'a>, src: &[u8], symbol: &str) -> Option<Node<'a>> {
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if matches!(child.kind(), "value_name" | "value_pattern") {
            return ocaml_find_first_ident(child, src, symbol);
        }
    }
    None
}

fn ocaml_binding_rhs_contains_cursor(binding: Node, src: &[u8], cursor_node: Node) -> bool {
    let mut seen_equals = false;
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if child.kind() == "=" || matches!(child.utf8_text(src), Ok("=")) {
            seen_equals = true;
            continue;
        }
        if seen_equals && node_contains(child, cursor_node) {
            return true;
        }
    }
    false
}

fn node_contains(outer: Node, inner: Node) -> bool {
    inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// C# scope binding scanner. Handles parameters and local variable
/// declarations (`int x = ...`, `var x = ...`).
fn scan_csharp_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    if matches!(
        node.kind(),
        "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
    ) {
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(loc) = csharp_scan_params(params, src, symbol, file) {
                return Some(loc);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = csharp_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

fn csharp_scan_params(
    params: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if matches!(child.kind(), "parameter") {
            if let Some(name) = child.child_by_field_name("name") {
                if name_node_matches(name, src, symbol) {
                    return Some(make_param_location(name, file));
                }
            }
        } else if child.kind() == "identifier" && name_node_matches(child, src, symbol) {
            // Lambda implicit-typed: `(x, y) => ...`
            return Some(make_param_location(child, file));
        } else if child.kind() == "implicit_parameter_list" {
            let mut c = child.walk();
            for n in child.children(&mut c) {
                if n.kind() == "identifier" && name_node_matches(n, src, symbol) {
                    return Some(make_param_location(n, file));
                }
            }
        }
    }
    None
}

fn csharp_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "method_declaration"
        | "constructor_declaration"
        | "local_function_statement"
        | "class_declaration"
        | "struct_declaration"
        | "interface_declaration"
        | "lambda_expression"
        | "anonymous_method_expression" => None,
        "variable_declaration" => {
            // children include `variable_declarator` nodes
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if name_node_matches(name, src, symbol) {
                            return Some(make_var_location(name, file));
                        }
                    } else {
                        // fallback: first identifier child
                        let mut c = child.walk();
                        for n in child.children(&mut c) {
                            if n.kind() == "identifier" && name_node_matches(n, src, symbol) {
                                return Some(make_var_location(n, file));
                            }
                        }
                    }
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = csharp_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Solidity scope binding scanner (v0.5.0 C2 AUDIT-FIX).
///
/// Handles two binding forms that previously left the resolver returning
/// `None` (and therefore falling through to a wrong cross-file hit):
///
/// 1. **Contract state variables** — `mapping(...) public balanceOf;`,
///    `uint256 public totalSupply;`, `address owner;`. These are
///    `state_variable_declaration` nodes whose name is the last
///    `identifier` child (after the `type_name` and any `visibility` /
///    modifier children). They live directly under the `contract_body`
///    (and interface/library bodies), so when the cursor's enclosing
///    `contract_declaration` scope is scanned we descend through the
///    `contract_body` to reach them.
/// 2. **Function / constructor / modifier parameters** — the `parameter`
///    nodes inside the parameter list.
///
/// AST kinds verified via debug-parse against
/// `solidity-solmate/src/tokens/ERC20.sol` (the live audit corpus):
/// `state_variable_declaration` → [`type_name`, `visibility`,
/// `identifier`, `;`].
fn scan_solidity_scope(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // Function-shaped scopes: scan their parameter list first so a
    // parameter shadows an outer state variable of the same name.
    if matches!(
        node.kind(),
        "function_definition"
            | "constructor_definition"
            | "fallback_function_definition"
            | "receive_function_definition"
            | "modifier_definition"
    ) {
        if let Some(loc) = solidity_scan_params(node, src, symbol, file) {
            return Some(loc);
        }
    }
    // Walk children for state-variable declarations (and nested params),
    // stopping at nested contract/function boundaries.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = solidity_walk_for_binding(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

/// Scan a Solidity function/constructor/modifier node for a parameter
/// named `symbol`. Parameters are `parameter` nodes; the name is the
/// `identifier` child (a `parameter` may also be name-less, e.g.
/// `uint256` in an interface, which we skip).
fn solidity_scan_params(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    fn find_param<'a>(
        n: Node<'a>,
        src: &[u8],
        symbol: &str,
        file: &Path,
    ) -> Option<(SymbolKind, Location)> {
        if n.kind() == "parameter" {
            // Name is the identifier child (after the type_name).
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                if ch.kind() == "identifier" && name_node_matches(ch, src, symbol) {
                    return Some(make_param_location(ch, file));
                }
            }
            return None;
        }
        // Do not descend into the function body when scanning params.
        if matches!(n.kind(), "function_body" | "block") {
            return None;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if let Some(loc) = find_param(ch, src, symbol, file) {
                return Some(loc);
            }
        }
        None
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(loc) = find_param(child, src, symbol, file) {
            return Some(loc);
        }
    }
    None
}

/// Recursive walk for Solidity bindings. Resolves `state_variable_declaration`
/// (and `constant_variable_declaration`) names. Stops at nested
/// contract/function boundaries so an inner scope's bindings are scanned
/// by their own scope node rather than leaking across boundaries.
fn solidity_walk_for_binding(
    node: Node,
    src: &[u8],
    symbol: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        // Do not descend into nested definitions — their bindings belong
        // to a different scope.
        "function_definition"
        | "constructor_definition"
        | "fallback_function_definition"
        | "receive_function_definition"
        | "modifier_definition"
        | "contract_declaration"
        | "interface_declaration"
        | "library_declaration"
        | "struct_declaration" => None,
        "state_variable_declaration" | "constant_variable_declaration" => {
            // The variable name is the last `identifier` child (the
            // `type_name`'s own identifiers are nested under `type_name`,
            // not direct children, so a direct-child identifier is the
            // declared name).
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" && name_node_matches(child, src, symbol) {
                    return Some((
                        SymbolKind::Property,
                        Location::with_column(
                            file.display().to_string(),
                            child.start_position().row as u32 + 1,
                            child.start_position().column as u32 + 1,
                        ),
                    ));
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = solidity_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
}

/// Pass 3: import-scope resolution.
///
/// Scans the source for `import` / `from ... import` (Python),
/// `import { ... } from ...` / `import X from ...` (JS/TS), and
/// `use ::path::X;` (Rust) statements, returning the line of the
/// matching alias. This handles the canonical case from the bug
/// report (`click` in `click.echo(...)` resolves to `import click`
/// on line 1).
fn resolve_import_scope(
    source: &str,
    symbol: &str,
    language: Language,
    file: &Path,
) -> RemainingResult<Option<DefinitionResult>> {
    let line_idx = match language {
        Language::Python => python_import_line(source, symbol),
        Language::JavaScript | Language::TypeScript => jslike_import_line(source, symbol),
        Language::Rust => rust_use_line(source, symbol),
        Language::Java => java_import_line(source, symbol),
        Language::Kotlin | Language::Scala => jvm_import_line(source, symbol),
        Language::Swift => swift_import_line(source, symbol),
        Language::Php => php_use_line(source, symbol),
        Language::CSharp => csharp_using_line(source, symbol),
        Language::Lua | Language::Luau => lua_require_line(source, symbol),
        Language::Elixir => elixir_alias_line(source, symbol),
        Language::Ocaml => ocaml_open_line(source, symbol),
        // C / C++ have only `#include` (preprocessor), which doesn't bind
        // symbols at the language level. Ruby's `require` doesn't bind a
        // symbol either. They fall through to the file-scope pass.
        Language::C | Language::Cpp | Language::Ruby | Language::Go => None,
        // v0.5.0 SOL-001 Solidity foundation. Import-scope resolution
        // (5 import forms — bare, `as`, `* as`, `{ X, Y }`,
        // `{ X as A }`) lands in SOL-002 with import extraction.
        Language::Solidity => None,
    };

    let Some((line_no, col)) = line_idx else {
        return Ok(None);
    };

    let location = Location::with_column(file.display().to_string(), line_no, col);
    Ok(Some(DefinitionResult {
        symbol: SymbolInfo {
            name: symbol.to_string(),
            kind: SymbolKind::Module,
            location: Some(location.clone()),
            type_annotation: None,
            docstring: None,
            is_builtin: false,
            module: None,
        },
        definition: Some(location),
        type_definition: None,
    }))
}

/// Find the (1-indexed line, column) of a Python import that exposes
/// `symbol`. Supports `import X`, `import X as Y`, `import a.b.c`,
/// `from M import X, Y`, `from M import X as Z`.
fn python_import_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        if let Some(rest) = line.strip_prefix("import ") {
            for piece in rest.split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                // `X as Y` — alias is what's bound.
                let bound = if let Some((_, alias)) = piece.split_once(" as ") {
                    alias.trim()
                } else {
                    // `a.b.c` binds top-level `a`.
                    piece.split('.').next().unwrap_or(piece).trim()
                };
                if bound == symbol {
                    return Some((idx as u32 + 1, leading as u32));
                }
            }
        } else if line.starts_with("from ") {
            if let Some(import_idx) = line.find(" import ") {
                let names_str = &line[import_idx + 8..];
                for piece in names_str.split(',') {
                    let piece = piece.trim().trim_start_matches('(').trim_end_matches(')');
                    if piece.is_empty() || piece == "*" {
                        continue;
                    }
                    let bound = if let Some((_, alias)) = piece.split_once(" as ") {
                        alias.trim()
                    } else {
                        piece.trim()
                    };
                    if bound == symbol {
                        return Some((idx as u32 + 1, leading as u32));
                    }
                }
            }
        }
    }
    None
}

/// Find the (1-indexed line, column) of a JS/TS `import` that
/// exposes `symbol`. Handles default, namespace, and named imports
/// (with `as` aliases). Best-effort, line-based — does not handle
/// multi-line `import { ... }` blocks.
fn jslike_import_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let body = match line.strip_prefix("import ") {
            Some(b) => b,
            None => continue,
        };
        // Strip trailing `from "..."` clause (and quoted source).
        let body = body
            .split(" from ")
            .next()
            .unwrap_or(body)
            .trim()
            .trim_end_matches(';')
            .trim();

        // Cases:
        //   X                    — default import
        //   X, { a, b as c }     — default + named
        //   { a, b as c }        — named
        //   * as X               — namespace
        //   "side-effect"        — no bindings
        if body.starts_with('"') || body.starts_with('\'') {
            continue;
        }

        // Split off namespace `* as X`.
        if let Some(rest) = body.strip_prefix("* as ") {
            let bound = rest.trim().trim_end_matches(',').trim();
            if bound == symbol {
                return Some((idx as u32 + 1, leading as u32));
            }
            continue;
        }

        // Default import: first token before `,` or `{`.
        let mut remainder = body;
        let mut pieces: Vec<&str> = Vec::new();
        if !remainder.starts_with('{') {
            // there's a default before `,` or `{`
            if let Some(idx_brace) = remainder.find('{') {
                let (default_part, rest) = remainder.split_at(idx_brace);
                let default_name = default_part.trim().trim_end_matches(',').trim();
                if !default_name.is_empty() {
                    pieces.push(default_name);
                }
                remainder = rest;
            } else {
                let default_name = remainder.trim();
                if !default_name.is_empty() {
                    pieces.push(default_name);
                }
                remainder = "";
            }
        }
        // Named import block.
        if remainder.starts_with('{') {
            let inside = remainder
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim();
            for p in inside.split(',') {
                let p = p.trim();
                if !p.is_empty() {
                    pieces.push(p);
                }
            }
        }
        for piece in pieces {
            let bound = if let Some((_, alias)) = piece.split_once(" as ") {
                alias.trim()
            } else {
                piece.trim()
            };
            if bound == symbol {
                return Some((idx as u32 + 1, leading as u32));
            }
        }
    }
    None
}

/// Find the (1-indexed line, column) of a Rust `use` that exposes
/// `symbol`. Best-effort: handles `use a::b::Symbol;` and
/// `use a::b::Symbol as Alias;` but not nested grouped (`use a::{b, c}`)
/// — those are documented as carry-forwards.
fn rust_use_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        // Skip grouped imports (e.g. `use a::{b, c}`).
        if rest.contains('{') {
            continue;
        }
        // Last segment is the bound name (modulo `as`).
        let bound = if let Some((_, alias)) = rest.split_once(" as ") {
            alias.trim()
        } else {
            rest.rsplit("::").next().unwrap_or(rest).trim()
        };
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

// =============================================================================
// Import-line finders for the additional languages
// (definition-additional-langs-v1)
// =============================================================================

/// Bound name for a dotted import path: `a.b.c` → `c` (the last segment).
fn last_dotted_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path).trim()
}

/// Java: `import com.foo.Bar;` binds `Bar`. `import static com.foo.X.Y;`
/// binds `Y`. Wildcards (`import com.foo.*;`) don't bind a specific name.
fn java_import_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        let rest = rest.strip_prefix("static ").map(|r| r.trim()).unwrap_or(rest);
        if rest.ends_with('*') {
            continue;
        }
        if last_dotted_segment(rest) == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// Kotlin/Scala: `import x.y.Z` binds `Z`; `import x.y.{ A, B => C }` (Scala)
/// binds `A` and `C`; `import x.y.*` (Kotlin) is a wildcard. `import x.y.Z as W`
/// (Kotlin) binds `W`.
fn jvm_import_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        // Scala selector group `pkg.{a, b => c}`
        if let Some(brace_idx) = rest.find('{') {
            let inside = rest[brace_idx..]
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim();
            for sel in inside.split(',') {
                let sel = sel.trim();
                if sel.is_empty() {
                    continue;
                }
                // `a => b` → bound is `b`; `a => _` → not bound; plain `a` → `a`
                let bound = if let Some((_, alias)) = sel.split_once("=>") {
                    let a = alias.trim();
                    if a == "_" {
                        continue;
                    }
                    a
                } else {
                    sel
                };
                if bound == symbol {
                    return Some((idx as u32 + 1, leading as u32));
                }
            }
            continue;
        }
        if rest.ends_with('*') || rest.ends_with('_') {
            continue;
        }
        // Kotlin alias: `import a.b.C as D`
        let bound = if let Some((_, alias)) = rest.split_once(" as ") {
            alias.trim()
        } else {
            last_dotted_segment(rest)
        };
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// Swift: `import Foundation` binds the module name `Foundation`.
/// `import class Foo.Bar` binds `Bar`. `import struct/enum/protocol/typealias/var/func`
/// follow the same pattern.
fn swift_import_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let rest = rest.trim();
        // Strip the optional kind keyword.
        let rest = ["class ", "struct ", "enum ", "protocol ", "typealias ", "var ", "func "]
            .iter()
            .find_map(|prefix| rest.strip_prefix(prefix))
            .unwrap_or(rest)
            .trim();
        let bound = last_dotted_segment(rest);
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// PHP: `use Foo\Bar\Baz;` binds `Baz`. `use Foo\Bar\Baz as Qux;` binds `Qux`.
/// `use function Foo\bar;` binds `bar`. `use Foo\{A, B as C};` binds `A` and `C`.
fn php_use_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        let rest = ["function ", "const "]
            .iter()
            .find_map(|p| rest.strip_prefix(p))
            .unwrap_or(rest)
            .trim();
        // Group `Foo\{A, B as C}`
        if let Some(brace_idx) = rest.find('{') {
            let inside = rest[brace_idx..]
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim();
            for sel in inside.split(',') {
                let sel = sel.trim();
                if sel.is_empty() {
                    continue;
                }
                let bound = if let Some((_, alias)) = sel.split_once(" as ") {
                    alias.trim()
                } else {
                    sel.rsplit('\\').next().unwrap_or(sel).trim()
                };
                if bound == symbol {
                    return Some((idx as u32 + 1, leading as u32));
                }
            }
            continue;
        }
        let bound = if let Some((_, alias)) = rest.split_once(" as ") {
            alias.trim()
        } else {
            rest.rsplit('\\').next().unwrap_or(rest).trim()
        };
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// C#: `using System;` binds `System` (top namespace). `using X = Foo.Bar;`
/// binds `X`. `using static Foo.Bar;` doesn't bind a symbol-name.
fn csharp_using_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("using ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        if rest.starts_with("static ") {
            continue;
        }
        // Alias: `X = Foo.Bar`
        let bound = if let Some((alias, _)) = rest.split_once('=') {
            alias.trim()
        } else {
            // `using System` binds top-level segment.
            rest.split('.').next().unwrap_or(rest).trim()
        };
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// Lua / Luau: `local foo = require("path.to.foo")` — the `local`
/// declaration is the binding. Plain `require(...)` without `local`
/// doesn't bind a name.
fn lua_require_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        let Some(rest) = line.strip_prefix("local ") else {
            continue;
        };
        // Form: `<name> = require(...)` (with optional type annotation `<name>: T = require(...)`)
        let Some(eq_idx) = rest.find('=') else {
            continue;
        };
        let lhs = rest[..eq_idx].trim();
        let rhs = rest[eq_idx + 1..].trim();
        if !rhs.starts_with("require") {
            continue;
        }
        // Strip type annotation if present: `name : Type`
        let bound = lhs.split(':').next().unwrap_or(lhs).trim();
        if bound == symbol {
            return Some((idx as u32 + 1, leading as u32));
        }
    }
    None
}

/// Elixir: `alias Foo.Bar` binds `Bar`; `alias Foo.Bar, as: Qux` binds `Qux`;
/// `import Foo.Bar` brings functions into scope (we treat the module name as bound);
/// `use Foo.Bar` similar.
fn elixir_alias_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        for kw in &["alias ", "import ", "use ", "require "] {
            if let Some(rest) = line.strip_prefix(kw) {
                let rest = rest.trim().trim_end_matches(',');
                // `alias Foo.Bar, as: Qux`
                let bound = if let Some(as_idx) = rest.find(", as:") {
                    let after = rest[as_idx + 5..].trim();
                    after.trim_end_matches(',').trim()
                } else {
                    // Path with possible parameters/options after a comma
                    let path = rest.split(',').next().unwrap_or(rest).trim();
                    // Brace-grouped: `alias Foo.{A, B}`
                    if let Some(brace_idx) = path.find('{') {
                        let prefix = &path[..brace_idx];
                        let inside = path[brace_idx..]
                            .trim_start_matches('{')
                            .trim_end_matches('}')
                            .trim();
                        for sel in inside.split(',') {
                            let sel = sel.trim();
                            if !sel.is_empty() && sel == symbol {
                                return Some((idx as u32 + 1, leading as u32));
                            }
                        }
                        let _ = prefix;
                        return None;
                    }
                    path.rsplit('.').next().unwrap_or(path).trim()
                };
                if bound == symbol {
                    return Some((idx as u32 + 1, leading as u32));
                }
            }
        }
    }
    None
}

/// OCaml: `open Foo` brings module `Foo`'s contents into scope (we treat
/// `Foo` as bound). `module M = Foo.Bar` binds `M`.
fn ocaml_open_line(source: &str, symbol: &str) -> Option<(u32, u32)> {
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        let leading = raw.len() - line.len();
        if let Some(rest) = line.strip_prefix("open ") {
            let rest = rest.trim_end_matches(";;").trim_end_matches(';').trim();
            // `open Foo.Bar` binds `Bar`'s contents but the canonical bound name is `Bar`.
            let bound = rest.rsplit('.').next().unwrap_or(rest).trim();
            if bound == symbol {
                return Some((idx as u32 + 1, leading as u32));
            }
        } else if let Some(rest) = line.strip_prefix("module ") {
            // `module M = Foo.Bar`
            if let Some((alias, _)) = rest.split_once('=') {
                let alias = alias.trim();
                if alias == symbol {
                    return Some((idx as u32 + 1, leading as u32));
                }
            }
        }
    }
    None
}

/// Find symbol name at a given position.
///
/// Parses with the given language via `ParserPool` (route TS/JS through the
/// right grammar dialect using the file path), then walks up the AST from
/// the deepest node at `(line, column)` looking for an identifier-like node.
/// Identifier kinds vary across languages — we accept any kind whose name
/// ends in `"identifier"` to cover language-specific variants
/// (`identifier`, `property_identifier`, `field_identifier`,
/// `type_identifier`, `shorthand_property_identifier`, etc.).
/// Maximum length of a symbol name accepted by [`find_symbol_at_position`].
///
/// language-coverage-fixes-v1 (P4.BUG-N3): the previous implementation
/// echoed `node.utf8_text(...)` with no upper bound. When the caller
/// passed a `(line, col)` past EOF, tree-sitter returned the entire
/// file as the "node text", and that text was then formatted into the
/// error message — producing a 65 KB stderr blast for `flask/app.py`
/// at line 9999. Symbols are identifiers; clamping at 256 bytes is far
/// more than any real source identifier and keeps error messages
/// bounded even if the cursor lands on a wrapper node.
const MAX_SYMBOL_LEN: usize = 256;

fn find_symbol_at_position(
    source: &str,
    line: u32,
    column: u32,
    language: Language,
    file: &Path,
) -> RemainingResult<String> {
    // language-coverage-fixes-v1 (P4.BUG-N3): validate `(line, col)`
    // against the file BEFORE parsing. Out-of-range positions previously
    // walked into tree-sitter's root node and echoed the entire source
    // file back through the error message; bounded checks here produce
    // a typed, short error instead.
    let line_count = source.lines().count();
    let target_line_0 = line.saturating_sub(1) as usize;
    if line as usize == 0 || target_line_0 >= line_count {
        return Err(RemainingError::invalid_argument(format!(
            "line {} out of range (file has {} lines)",
            line, line_count
        )));
    }
    let line_text = source.lines().nth(target_line_0).unwrap_or("");
    // tree-sitter columns are byte offsets within the line; allow
    // `column == line.len()` (end-of-line cursor) but reject anything
    // beyond.
    if (column as usize) > line_text.len() {
        return Err(RemainingError::invalid_argument(format!(
            "column {} out of range on line {} (line has {} bytes)",
            column,
            line,
            line_text.len()
        )));
    }

    // sibling-resolver-gaps-v1 (P14.AGG14-6): if the user passed a
    // column that lands on a language keyword (`function`/`func`/`fn`
    // /`def`/`export`/...), advance past the keyword to the next
    // identifier on the line. Reproduced across 8 languages: e.g.
    // `tldr definition foo.lua 44 1` for the line `function m.reset()`
    // previously errored with "symbol 'function' not found in scope".
    // Walking past the keyword resolves to `m.reset` (or `reset`)
    // matching the surrounding tokens. Repeat once more if the next
    // identifier is also a keyword (e.g. `pub fn` for rust, where col=1
    // is `pub` and the function lives at col=8). For Go, also skip a
    // balanced `(receiver Type)` parameter group between `func` and the
    // method name.
    let mut effective_column = column as usize;
    for _ in 0..6 {
        let candidate =
            extract_identifier_at_column(line_text, effective_column.min(line_text.len()));
        if !candidate.is_empty() && is_language_keyword(&candidate, language) {
            // Skip the keyword: walk to the end of the identifier run,
            // then over any non-identifier bytes (whitespace, `(`, etc.)
            // until the next identifier-byte starts. If the first
            // non-identifier byte we hit is `(`, walk over the whole
            // balanced group first (Go-style method receivers).
            let bytes = line_text.as_bytes();
            let is_ident =
                |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            let mut i = effective_column.min(bytes.len());
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            // Skip whitespace.
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            // Skip a balanced (...) group (e.g. go method receiver).
            if i < bytes.len() && bytes[i] == b'(' {
                let mut depth = 0i32;
                while i < bytes.len() {
                    match bytes[i] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            i += 1;
                            if depth == 0 {
                                break;
                            }
                            continue;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && !is_ident(bytes[i]) {
                    i += 1;
                }
            }
            if i < bytes.len() {
                effective_column = i;
                continue;
            }
        }
        break;
    }

    let tree = PARSER_POOL
        .parse_with_path(source, language, Some(file))
        .map_err(|e| RemainingError::parse_error(file.to_path_buf(), e.to_string()))?;

    // Convert 1-indexed line to 0-indexed
    let target_line = target_line_0;
    let target_col = effective_column;

    // Find the node at the position
    let root = tree.root_node();
    let point = tree_sitter::Point::new(target_line, target_col);

    let node = root
        .descendant_for_point_range(point, point)
        .ok_or_else(|| {
            RemainingError::invalid_argument(format!(
                "No symbol found at line {}, column {}",
                line, column
            ))
        })?;

    let text = node.utf8_text(source.as_bytes()).map_err(|_| {
        RemainingError::parse_error(file.to_path_buf(), "Invalid UTF-8".to_string())
    })?;

    if is_identifier_kind(node.kind()) {
        // sibling-resolver-gaps-v1 (P14.AGG14-6): when the keyword-skip
        // landed us on the head of a dotted/qualified name (e.g.
        // `m.reset` in lua, `ps.ByName` in go, `Class::method` in c++),
        // return the full qualified expression rather than just the
        // first identifier — that's what the user means by "what is
        // defined on this line".
        if let Some(parent) = node.parent() {
            let pkind = parent.kind();
            if matches!(
                pkind,
                "dot_index_expression"
                    | "member_expression"
                    | "field_expression"
                    | "selector_expression"
                    | "qualified_identifier"
                    | "scoped_identifier"
                    | "field_access"
                    | "name_qualified"
                    | "field_identifier"
            ) {
                if let Ok(full) = parent.utf8_text(source.as_bytes()) {
                    if !full.is_empty() && full.contains(text) {
                        return Ok(clamp_symbol(full));
                    }
                }
            }
        }
        return Ok(clamp_symbol(text));
    }

    // Walk up looking for an identifier-like node (covers cases where the
    // tree-sitter cursor lands on a wrapper node such as `call_expression`).
    let mut current = node.parent();
    while let Some(n) = current {
        if is_identifier_kind(n.kind()) {
            let text = n.utf8_text(source.as_bytes()).map_err(|_| {
                RemainingError::parse_error(file.to_path_buf(), "Invalid UTF-8".to_string())
            })?;
            return Ok(clamp_symbol(text));
        }
        current = n.parent();
    }

    // Fall back: extract a word-boundary identifier slice from the
    // line text rather than echoing the entire wrapper node — a
    // wrapper like `call_expression` can span hundreds of lines.
    Ok(extract_identifier_at_column(line_text, target_col))
}

/// Clamp a candidate symbol name to [`MAX_SYMBOL_LEN`] bytes (truncating
/// at a UTF-8 boundary) so error messages stay bounded.
fn clamp_symbol(s: &str) -> String {
    if s.len() <= MAX_SYMBOL_LEN {
        return s.to_string();
    }
    // Find the largest valid UTF-8 prefix ≤ MAX_SYMBOL_LEN.
    let mut end = MAX_SYMBOL_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Extract a contiguous identifier-character run around `col` from
/// `line`. ASCII identifier characters: `[A-Za-z0-9_]`. Returns an
/// empty string if no identifier touches `col`.
///
/// Used as the bounded fallback when the cursor lands on a wrapper
/// node and no enclosing identifier-kind ancestor was found.
fn extract_identifier_at_column(line: &str, col: usize) -> String {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return String::new();
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // Start from min(col, line.len()-1).
    let landing = col.min(bytes.len().saturating_sub(1));

    // If we landed inside an identifier run, walk back to the start
    // and forward to the end and return that whole identifier.
    if is_ident(bytes[landing]) {
        let mut start = landing;
        while start > 0 && is_ident(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = landing;
        while end < bytes.len() && is_ident(bytes[end]) {
            end += 1;
        }
        return clamp_symbol(&line[start..end]);
    }

    // definition-resolver-ranking-v1 (v0.4.2 M-040, scala arm): the
    // cursor sits on a non-identifier byte (punctuation, whitespace).
    // The legacy implementation only inspected the byte immediately to
    // the left, so a cursor on `:` (or on whitespace AFTER `:`)
    // adjacent to a single-character identifier was returned as an
    // empty symbol. ExitCode.scala:35:14 (the colon after the `i`
    // parameter declaration) is the canonical scala c44 case — the
    // resolver previously errored with `symbol '' not found in scope`.
    //
    // Post-fix: walk LEFT through non-identifier bytes until we either
    // (a) find an identifier byte and return the identifier ending
    // there, or (b) reach the line start without seeing one. If the
    // left scan finds nothing, do the symmetric scan to the RIGHT so
    // a cursor placed before a token (e.g. on the opening `(` of a
    // call) still resolves to the call name.
    //
    // The scan is bounded to a small window per side (32 bytes) to
    // avoid pathological behavior on long lines — beyond that, a
    // failure to resolve is a more honest answer than an arbitrary
    // identifier from the other end of the line.
    const SCAN_WINDOW: usize = 32;

    // Scan LEFT for an adjacent identifier run.
    let mut left = landing;
    let left_lo = landing.saturating_sub(SCAN_WINDOW);
    while left > left_lo && !is_ident(bytes[left]) {
        left -= 1;
    }
    if is_ident(bytes[left]) {
        let mut start = left;
        while start > 0 && is_ident(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = left + 1;
        while end < bytes.len() && is_ident(bytes[end]) {
            end += 1;
        }
        return clamp_symbol(&line[start..end]);
    }

    // No identifier found to the left within the window. Scan RIGHT.
    let right_hi = (landing + SCAN_WINDOW).min(bytes.len());
    let mut right = landing;
    while right < right_hi && !is_ident(bytes[right]) {
        right += 1;
    }
    if right < right_hi && is_ident(bytes[right]) {
        let start = right;
        let mut end = right;
        while end < bytes.len() && is_ident(bytes[end]) {
            end += 1;
        }
        return clamp_symbol(&line[start..end]);
    }

    String::new()
}

/// Returns true for tokens that are language keywords (and therefore
/// not legal symbol names). Used by [`find_symbol_at_position`] to
/// skip the keyword when the user passes `col=1` on a definition line
/// like `function foo()` or `func (r *Receiver) Bar()`.
///
/// sibling-resolver-gaps-v1 (P14.AGG14-6): the keyword set covers the
/// 8 languages where the bug was directly reproduced
/// (lua/luau/go/rust/python/typescript/scala/swift/ruby/php/c/cpp/java/csharp)
/// plus a small superset so the same skip logic also helps adjacent
/// langs without harm. Definition lookup over any of these tokens is
/// not a meaningful operation; the resolver should advance to the next
/// identifier rather than report "symbol 'fn' not found".
fn is_language_keyword(word: &str, language: Language) -> bool {
    // Conservative shared set used regardless of language — these are
    // never legal identifier names anywhere in the supported corpus.
    const SHARED: &[&str] = &[
        "fn", "func", "function", "def", "defp", "defmodule", "defmacro",
        "defmacrop", "defstruct", "let", "var", "const", "class", "struct",
        "trait", "interface", "module", "namespace", "package", "import",
        "from", "use", "using", "export", "pub", "public", "private",
        "protected", "static", "final", "abstract", "override", "async",
        "await", "return", "if", "else", "elif", "while", "for", "do",
        "match", "switch", "case", "break", "continue", "type", "typedef",
        "enum", "implements", "extends", "self", "this", "super", "void",
        "new", "delete", "object", "trait",
    ];
    if SHARED.contains(&word) {
        return true;
    }
    // Per-language extras for variants that are legal identifiers in
    // *some* langs but keywords in others (e.g. ocaml `let`, rust `mod`).
    match language {
        Language::Rust => matches!(
            word,
            "fn" | "mod"
                | "impl"
                | "trait"
                | "where"
                | "ref"
                | "mut"
                | "dyn"
                | "as"
                | "in"
                | "loop"
                | "move"
                | "unsafe"
                | "extern"
                | "crate"
                | "Self"
        ),
        Language::Ocaml => matches!(
            word,
            "let" | "rec"
                | "and"
                | "in"
                | "fun"
                | "function"
                | "module"
                | "open"
                | "type"
                | "of"
                | "match"
                | "with"
                | "begin"
                | "end"
                | "val"
        ),
        Language::Java | Language::CSharp | Language::Kotlin => {
            matches!(word, "synchronized" | "throws" | "throw" | "try" | "catch" | "finally")
        }
        _ => false,
    }
}

/// Returns true for any tree-sitter node kind that represents an identifier
/// in one of the supported languages.
fn is_identifier_kind(kind: &str) -> bool {
    // Most languages use "identifier"; OO languages add "property_identifier",
    // "field_identifier", "type_identifier"; Ruby uses "constant" for class
    // names; Elixir/Erlang use "atom" sometimes; Lua uses "name".
    kind == "identifier"
        || kind == "property_identifier"
        || kind == "field_identifier"
        || kind == "type_identifier"
        || kind == "shorthand_property_identifier"
        || kind == "constant"
        || kind == "name"
        || kind.ends_with("_identifier")
}

/// Find a symbol definition within a single file.
///
/// Dispatches based on language:
/// - Python keeps its bespoke recursive walker so module-level
///   `assignment` definitions (variables, constants) are still found —
///   that detail is missing from the shared `extract_definitions` API.
/// - Every other language uses
///   `CallGraphLanguageSupport::extract_definitions`, which already knows
///   the per-language tree-sitter kinds for functions, methods, and
///   classes.
fn find_symbol_in_file(
    symbol: &str,
    file: &Path,
    source: &str,
    language: Language,
) -> RemainingResult<Option<DefinitionResult>> {
    if language == Language::Python {
        return find_symbol_in_file_python(symbol, file, source);
    }
    find_symbol_in_file_generic(symbol, file, source, language)
}

/// Python-specific in-file search (legacy path: handles module-level
/// `assignment` definitions in addition to functions and classes).
fn find_symbol_in_file_python(
    symbol: &str,
    file: &Path,
    source: &str,
) -> RemainingResult<Option<DefinitionResult>> {
    let tree = PARSER_POOL
        .parse_with_path(source, Language::Python, Some(file))
        .map_err(|e| RemainingError::parse_error(file.to_path_buf(), e.to_string()))?;

    let root = tree.root_node();

    if let Some((kind, location)) = find_definition_recursive(root, source, symbol, file) {
        return Ok(Some(DefinitionResult {
            symbol: SymbolInfo {
                name: symbol.to_string(),
                kind,
                location: Some(location.clone()),
                type_annotation: None,
                docstring: None,
                is_builtin: false,
                module: None,
            },
            definition: Some(location),
            type_definition: None,
        }));
    }

    Ok(None)
}

/// Generic in-file search backed by `CallGraphLanguageSupport::extract_definitions`.
///
/// The handler returns `(Vec<FuncDef>, Vec<ClassDef>)`. We match the
/// requested symbol against both vectors and translate the result into
/// the CLI's `DefinitionResult` shape.
fn find_symbol_in_file_generic(
    symbol: &str,
    file: &Path,
    source: &str,
    language: Language,
) -> RemainingResult<Option<DefinitionResult>> {
    let tree = PARSER_POOL
        .parse_with_path(source, language, Some(file))
        .map_err(|e| RemainingError::parse_error(file.to_path_buf(), e.to_string()))?;

    let registry = LanguageRegistry::with_defaults();
    let handler = registry
        .get(language.as_str())
        .ok_or_else(|| RemainingError::unsupported_language(format!("{:?}", language)))?;

    let (funcs, classes) = handler
        .extract_definitions(source, file, &tree)
        .map_err(|e| RemainingError::parse_error(file.to_path_buf(), e.to_string()))?;

    if let Some((kind, location)) = match_definition(symbol, &funcs, &classes, file) {
        return Ok(Some(DefinitionResult {
            symbol: SymbolInfo {
                name: symbol.to_string(),
                kind,
                location: Some(location.clone()),
                type_annotation: None,
                docstring: None,
                is_builtin: false,
                module: None,
            },
            definition: Some(location),
            type_definition: None,
        }));
    }

    Ok(None)
}

/// Match `symbol` against extracted FuncDefs / ClassDefs and produce a
/// `(SymbolKind, Location)` pair for the first match. Functions inside a
/// class become `Method`; standalone functions are `Function`; classes
/// (including Rust struct/enum/trait, which the handlers report as
/// classes) become `Class`.
fn match_definition(
    symbol: &str,
    funcs: &[FuncDef],
    classes: &[ClassDef],
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    // definition-resolver-ranking-v1 (v0.4.2 M-040): rank candidates
    // instead of picking the first textual match. The legacy behaviour
    // (first-match-wins) caused the cpp arm of M-040 — a forward
    // declaration `class XMLDocument;` at line 116 was returned in
    // preference to the real class body at line 1718. The same
    // pattern bites any language whose extractor emits both a
    // bodyless declaration and a real body for the same name (e.g.
    // C/C++ prototypes vs definitions).
    //
    // Ranking key (lower = better):
    //
    //   - `end_line > line` (multi-line body present): preferred over
    //     `end_line == line` (single-line declaration). Forward
    //     declarations and bodyless prototypes always satisfy
    //     `end_line == line`. Bodied definitions span multiple lines
    //     when the declaration includes a `{ ... }` block, which is
    //     the universal C/C++/Rust/Scala/etc. shape.
    //   - For functions, additionally prefer matches that are
    //     themselves inside a class (`is_method`) when the caller
    //     asked for a method-shaped name — but since we cannot
    //     distinguish caller intent here, we fall back to the
    //     `end_line > line` tie-breaker first, then preserve source
    //     order for ties.
    //
    // The ranking is stable: the FIRST best-ranked match wins, so
    // tie-breakers fall back to legacy first-match order — keeping
    // existing tests green.
    fn rank_score(line: u32, end_line: u32) -> u32 {
        // Bodied entries (multi-line span) get score 0; bodyless
        // entries (single-line) get score 1. Lower is better.
        if end_line > line {
            0
        } else {
            1
        }
    }

    let best_func = funcs
        .iter()
        .filter(|f| definition_function_name_matches(&f.name, symbol))
        .enumerate()
        .min_by_key(|(idx, f)| (rank_score(f.line, f.end_line), *idx))
        .map(|(_, f)| f);

    if let Some(f) = best_func {
        let kind = if f.is_method {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        };
        // p19-secondary-fixes-v1 (BUG-P19-06): `FuncDef`/`ClassDef`
        // carry only the line number; locating the column of the
        // symbol name on that source line gives `definition` a
        // 1-indexed column instead of the default 0. Without this
        // every cpp/rust/scala/swift definition reported column=0.
        //
        // cross-lang-definition-column-v1 (v0.4.2 bug-A1-A2-A4):
        // `locate_symbol_line_column` additionally scans a small
        // forward window when the symbol is not present on the
        // `FuncDef`-reported line. tree-sitter-java's
        // `method_declaration` and tree-sitter-kotlin's
        // `function_declaration` start at the leading annotation
        // line; same for Scala `@deprecated`-decorated methods. The
        // scan recovers the actual header line and 1-indexed column.
        let (line_out, col_out) = locate_symbol_line_column(file, f.line, symbol);
        let loc = match col_out {
            Some(c) => Location::with_column(file.display().to_string(), line_out, c),
            None => Location::new(file.display().to_string(), line_out),
        };
        return Some((kind, loc));
    }

    let best_class = classes
        .iter()
        .filter(|c| c.name == symbol)
        .enumerate()
        .min_by_key(|(idx, c)| (rank_score(c.line, c.end_line), *idx))
        .map(|(_, c)| c);

    if let Some(c) = best_class {
        // cross-lang-definition-column-v1 (v0.4.2 bug-A1-A2-A4):
        // mirror the FuncDef path — annotation-decorated class
        // declarations would otherwise emit column=0.
        let (line_out, col_out) = locate_symbol_line_column(file, c.line, symbol);
        let loc = match col_out {
            Some(col_v) => Location::with_column(file.display().to_string(), line_out, col_v),
            None => Location::new(file.display().to_string(), line_out),
        };
        return Some((SymbolKind::Class, loc));
    }

    None
}

fn definition_function_name_matches(name: &str, symbol: &str) -> bool {
    name == symbol || name.rsplit_once("::").is_some_and(|(_, tail)| tail == symbol)
}

/// Locate the 1-indexed column of `symbol` on line `line` (1-indexed) of
/// `file`. Returns `None` if the file cannot be read or the symbol does
/// not appear on that line. Used to populate the `column` field of
/// `definition` results when the underlying `FuncDef`/`ClassDef` only
/// carries the line.
#[cfg(test)]
fn locate_symbol_column(file: &Path, line: u32, symbol: &str) -> Option<u32> {
    let (out_line, col) = locate_symbol_line_column(file, line, symbol);
    if out_line == line {
        col
    } else {
        // Backward-compatible: legacy helper only returned a column when
        // the symbol was on the reported line. Forward-scan matches go
        // through `locate_symbol_line_column` directly.
        None
    }
}

/// Locate the 1-indexed `(line, column)` of `symbol` near
/// `start_line` (1-indexed) of `file`. When the symbol is present on
/// `start_line`, returns `(start_line, Some(col))` exactly like the
/// previous `locate_symbol_column` behavior. When it is not (e.g. the
/// `FuncDef` line points at a leading annotation in
/// java/kotlin/scala), scans up to `MAX_FORWARD` lines ahead and
/// returns the first line that contains the symbol as a whole word
/// (bordered by non-identifier characters). Returns
/// `(start_line, None)` if the file cannot be read or no occurrence is
/// found within the window.
///
/// The forward scan is intentionally narrow: real annotation-decorated
/// declarations almost always have the header within 1–3 lines of the
/// first annotation, even for multi-line `@Foo(\n  ...,\n)` modifiers.
/// `MAX_FORWARD = 16` accommodates very verbose annotations while
/// staying tight enough to avoid spuriously matching the symbol in a
/// later unrelated declaration.
///
/// The word-boundary check (`is_identifier_continuation` on the bytes
/// immediately before and after the match) prevents a substring match
/// such as `parse` inside `parseFully` from being mistaken for the
/// real declaration.
fn locate_symbol_line_column(file: &Path, start_line: u32, symbol: &str) -> (u32, Option<u32>) {
    const MAX_FORWARD: usize = 16;
    let Ok(content) = std::fs::read_to_string(file) else {
        return (start_line, None);
    };
    let target_idx = start_line.saturating_sub(1) as usize;
    let lines: Vec<&str> = content.lines().collect();
    if target_idx >= lines.len() {
        return (start_line, None);
    }

    // m116-easy-mechanical-v1 (#45): the textual-find paths below
    // return the FIRST whole-word occurrence of `symbol` on a line,
    // which is wrong when the call site appears before the
    // definition on the same line —
    //   `let x = bar(); fn bar() -> i32 { 42 }`
    // would emit column 13 (the call site) instead of column 23 (the
    // `fn bar` definition's name node). Prefer an AST-derived
    // (line, column) anchored at the actual definition's name child.
    if let Some((line_out, col_out)) =
        ast_locate_symbol_definition(file, &content, start_line, symbol, MAX_FORWARD as u32)
    {
        return (line_out, Some(col_out));
    }

    // First try the reported line. Use a word-bounded match so a
    // substring (e.g. `parse` inside `parseFully`) is not selected.
    if let Some(col) = find_word_bounded(lines[target_idx], symbol) {
        return (start_line, Some(col));
    }

    // Forward scan for annotation-decorated declarations
    // (java `@GetMapping`, kotlin `@Deprecated`, scala `@deprecated`).
    let end_idx = std::cmp::min(target_idx + 1 + MAX_FORWARD, lines.len());
    for idx in (target_idx + 1)..end_idx {
        if let Some(col) = find_word_bounded(lines[idx], symbol) {
            let line_out = (idx as u32).saturating_add(1);
            return (line_out, Some(col));
        }
    }

    (start_line, None)
}

/// m116-easy-mechanical-v1 (#45): AST-based column lookup for a
/// definition's name child. Parses the file, walks the entire AST, and
/// returns the (1-indexed line, 1-indexed column) of the FIRST
/// definition-shaped node whose `name` field text equals `symbol` AND
/// whose start row lies within `[start_line - 0, start_line + max_forward]`.
/// Returns `None` if the file is unparseable, no language is detected,
/// or no matching declaration name node exists in the window.
///
/// Definition-shaped node kinds covered (cross-language):
/// `function_item`, `function_declaration`, `function_definition`,
/// `method_declaration`, `method_definition`, `class_declaration`,
/// `class_definition`, `struct_declaration`, `struct_item`,
/// `interface_declaration`, `trait_item`, `enum_item`,
/// `enum_declaration`, `type_alias`, `type_item`, `const_item`,
/// `static_item`, `impl_item`, `mod_item`.
fn ast_locate_symbol_definition(
    file: &Path,
    source: &str,
    start_line: u32,
    symbol: &str,
    max_forward: u32,
) -> Option<(u32, u32)> {
    let language = tldr_core::Language::from_path(file)?;
    let tree = PARSER_POOL.parse(source, language).ok()?;
    let root = tree.root_node();
    let bytes = source.as_bytes();
    let window_end = start_line.saturating_add(max_forward);

    let mut best: Option<(u32, u32)> = None;
    walk_ast_for_definition_name(
        root, bytes, symbol, start_line, window_end, &mut best,
    );
    best
}

fn walk_ast_for_definition_name(
    node: Node,
    source: &[u8],
    symbol: &str,
    start_line: u32,
    window_end: u32,
    best: &mut Option<(u32, u32)>,
) {
    let kind = node.kind();
    let is_def = matches!(
        kind,
        "function_item"
            | "function_declaration"
            | "function_definition"
            | "method_declaration"
            | "method_definition"
            | "class_declaration"
            | "class_definition"
            | "struct_declaration"
            | "struct_item"
            | "interface_declaration"
            | "trait_item"
            | "enum_item"
            | "enum_declaration"
            | "type_alias"
            | "type_item"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "object_declaration"
    );
    if is_def {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name_text) = name_node.utf8_text(source) {
                if name_text == symbol {
                    let row = name_node.start_position().row as u32 + 1;
                    let col = name_node.start_position().column as u32 + 1;
                    if row >= start_line.saturating_sub(0) && row <= window_end {
                        // Prefer earliest (line, then column).
                        match best {
                            None => *best = Some((row, col)),
                            Some((br, bc)) if (row, col) < (*br, *bc) => {
                                *best = Some((row, col))
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ast_for_definition_name(
            child, source, symbol, start_line, window_end, best,
        );
    }
}

/// Find the first whole-word occurrence of `symbol` in `line_text` and
/// return its 1-indexed character column. Whole-word means the bytes
/// immediately before and after the match are not identifier
/// continuation characters (ASCII alphanumerics or `_`). Returns
/// `None` if no whole-word match exists.
fn find_word_bounded(line_text: &str, symbol: &str) -> Option<u32> {
    if symbol.is_empty() {
        return None;
    }
    let bytes = line_text.as_bytes();
    let sym_bytes = symbol.as_bytes();
    let mut search_start = 0usize;
    while search_start <= bytes.len().saturating_sub(sym_bytes.len()) {
        let remainder = &line_text[search_start..];
        let Some(rel_offset) = remainder.find(symbol) else {
            return None;
        };
        let byte_offset = search_start + rel_offset;
        let before_ok = byte_offset == 0
            || !is_identifier_continuation(bytes[byte_offset.saturating_sub(1)]);
        let after_idx = byte_offset + sym_bytes.len();
        let after_ok =
            after_idx >= bytes.len() || !is_identifier_continuation(bytes[after_idx]);
        if before_ok && after_ok {
            // 1-indexed character column (UTF-8 aware).
            let col_chars = line_text[..byte_offset].chars().count();
            return Some(col_chars as u32 + 1);
        }
        // Skip past this occurrence and keep searching.
        search_start = byte_offset + 1;
    }
    None
}

/// ASCII identifier continuation: `[A-Za-z0-9_]`. Conservative for the
/// 18 TLDR-supported languages — every one of them uses ASCII
/// identifier characters in their lexers (Unicode identifiers are
/// permitted in some languages but the boundary check still holds
/// because a non-ASCII byte is never `[A-Za-z0-9_]`).
fn is_identifier_continuation(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Recursively search the AST for a definition
fn find_definition_recursive(
    node: Node,
    source: &str,
    target_name: &str,
    file: &Path,
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "function_definition" => {
            // Get the name child
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    if name == target_name {
                        // Check if inside a class by looking at parents
                        let in_class = is_inside_class(node);
                        let kind = if in_class {
                            SymbolKind::Method
                        } else {
                            SymbolKind::Function
                        };
                        let location = Location::with_column(
                            file.display().to_string(),
                            name_node.start_position().row as u32 + 1,
                            // scala-column-unification-v1
                            // (v0.4.1 bug-B): 1-indexed column.
                            name_node.start_position().column as u32 + 1,
                        );
                        return Some((kind, location));
                    }
                }
            }
        }
        "class_definition" => {
            // Get the name child
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    if name == target_name {
                        let location = Location::with_column(
                            file.display().to_string(),
                            name_node.start_position().row as u32 + 1,
                            // scala-column-unification-v1
                            // (v0.4.1 bug-B): 1-indexed column.
                            name_node.start_position().column as u32 + 1,
                        );
                        return Some((SymbolKind::Class, location));
                    }
                }
            }
        }
        "assignment" => {
            // Check for variable assignments at module level
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    if let Ok(name) = left.utf8_text(source.as_bytes()) {
                        if name == target_name {
                            let location = Location::with_column(
                                file.display().to_string(),
                                left.start_position().row as u32 + 1,
                                // scala-column-unification-v1
                                // (v0.4.1 bug-B): 1-indexed column.
                                left.start_position().column as u32 + 1,
                            );
                            return Some((SymbolKind::Variable, location));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    // Search children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(result) = find_definition_recursive(child, source, target_name, file) {
                return Some(result);
            }
        }
    }

    None
}

/// Check if a node is inside a class definition
fn is_inside_class(node: Node) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "class_definition" {
            return true;
        }
        current = n.parent();
    }
    false
}

/// Resolve `symbol` across files in the project.
///
/// Python uses an import-based resolver (parses `from X import Y` /
/// `import X` and follows them); other languages do a project-wide walk
/// of files matching the language's extensions and run
/// [`find_symbol_in_file`] on each. The walk-based approach is correct
/// for the canonical small fixture and large enough to be useful in
/// practice. For projects whose import topology is essential (large TS
/// monorepos, etc.), the daemon-backed `ModuleIndex` already handles
/// resolution and can be plugged in here as a follow-up.
fn resolve_cross_file(
    symbol: &str,
    current_file: &Path,
    project_root: &Path,
    language: Language,
    detector: &mut DefinitionCycleDetector,
    depth: usize,
) -> RemainingResult<Option<DefinitionResult>> {
    // Prevent infinite recursion
    if depth >= MAX_IMPORT_DEPTH {
        return Ok(None);
    }

    // Check for cycle
    if detector.visit(current_file, symbol) {
        return Ok(None);
    }

    if language == Language::Python {
        return resolve_cross_file_python(symbol, current_file, project_root, detector, depth);
    }

    // Generic project walk for the other 17 languages.
    resolve_cross_file_walk(symbol, current_file, project_root, language)
}

/// Python-specific cross-file resolution via parsed import statements
/// (preserves the pre-VAL-015 behaviour for Python).
fn resolve_cross_file_python(
    symbol: &str,
    current_file: &Path,
    project_root: &Path,
    detector: &mut DefinitionCycleDetector,
    depth: usize,
) -> RemainingResult<Option<DefinitionResult>> {
    let source = fs::read_to_string(current_file).map_err(RemainingError::Io)?;
    let imports = extract_imports(&source);

    for (module_path, imported_names) in imports {
        let is_imported = imported_names.is_empty() || imported_names.contains(&symbol.to_string());

        if is_imported {
            if let Some(resolved_path) =
                resolve_module_path(&module_path, current_file, project_root)
            {
                if resolved_path.exists() {
                    let module_source =
                        fs::read_to_string(&resolved_path).map_err(RemainingError::Io)?;

                    if let Some(result) = find_symbol_in_file(
                        symbol,
                        &resolved_path,
                        &module_source,
                        Language::Python,
                    )? {
                        return Ok(Some(result));
                    }

                    if let Some(result) = resolve_cross_file(
                        symbol,
                        &resolved_path,
                        project_root,
                        Language::Python,
                        detector,
                        depth + 1,
                    )? {
                        return Ok(Some(result));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Generic cross-file resolution: walk the project for files whose
/// extension belongs to `language` and probe each for the symbol.
///
/// Skips the file we already searched (`current_file`) and common
/// non-source directories (`.git`, `target`, `node_modules`, etc.) to
/// avoid pathological scans on real projects.
fn resolve_cross_file_walk(
    symbol: &str,
    current_file: &Path,
    project_root: &Path,
    language: Language,
) -> RemainingResult<Option<DefinitionResult>> {
    // W1-5: defend against an empty or non-existent project root. WalkDir on
    // an empty path returns ENOENT, and `.flatten()` silently swallows it so
    // zero files are visited. Bail out cleanly instead.
    if project_root.as_os_str().is_empty() || !project_root.exists() {
        return Ok(None);
    }

    let extensions = language.scan_extensions();
    let current_canonical = fs::canonicalize(current_file).ok();

    let walker = walkdir::WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_skipped_dir(e.path()));

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip non-matching extensions.
        let matches_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                extensions
                    .iter()
                    .any(|ext| ext.trim_start_matches('.').eq_ignore_ascii_case(e))
            })
            .unwrap_or(false);
        if !matches_ext {
            continue;
        }
        // Skip the file we already searched.
        if let Some(ref c) = current_canonical {
            if let Ok(p) = fs::canonicalize(path) {
                if &p == c {
                    continue;
                }
            }
        }

        let Ok(source) = fs::read_to_string(path) else {
            continue;
        };
        if let Some(result) = find_symbol_in_file(symbol, path, &source, language)? {
            return Ok(Some(result));
        }
    }

    Ok(None)
}

/// Walk up ancestors of `file` looking for the closest directory that
/// contains a repository or package marker. Used by the
/// `definition-workspace-cross-file-v1` workspace flag to auto-detect a
/// project root when `--project` is not explicitly supplied.
///
/// Markers (in priority order): `.git`, `Cargo.toml`, `pyproject.toml`,
/// `package.json`, `go.mod`, `pom.xml`, `build.gradle`,
/// `build.gradle.kts`, `composer.json`. The first ancestor that
/// contains any of these wins.
///
/// Returns `None` if no marker is found before reaching the filesystem
/// root, in which case the caller falls back to in-file resolution.
/// Resolve the effective cross-file resolution root for the `definition`
/// command, given the user's `--project` / `--workspace` choices.
///
/// Precedence:
/// 1. An explicit `--project` always wins (returned verbatim).
/// 2. With `--workspace=false` and no `--project`, return `None` — the user
///    explicitly opted out of cross-file resolution, so the resolver stays
///    single-file (and position queries fall back to the import-line
///    `module` result). This preserves the documented legacy behaviour.
/// 3. With workspace resolution enabled (the default), walk up for a project
///    marker via [`find_workspace_root`].
/// 4. F4b-definition-py-import: when no marker is found *and* the file is
///    Python, fall back to the file's own package directory. Python
///    *relative* from-imports (`from .mod import f`) resolve relative to the
///    current file and need no project marker, so without this fallback a
///    `from .mod import f; f()` query in a marker-less tree skipped
///    cross-file resolution entirely and dead-ended at the import line as
///    `kind=module` instead of following `f` to its real definition. The
///    fallback is Python-only: the other languages resolve cross-file via a
///    project-wide directory walk that genuinely needs a real root, so their
///    behaviour is unchanged.
fn resolve_definition_root(
    explicit_project: Option<&Path>,
    workspace: bool,
    file: &Path,
    language: Option<Language>,
) -> Option<PathBuf> {
    if let Some(p) = explicit_project {
        return Some(p.to_path_buf());
    }
    if !workspace {
        return None;
    }
    if let Some(root) = find_workspace_root(file) {
        return Some(root);
    }
    if language == Some(Language::Python) {
        return file.parent().map(Path::to_path_buf);
    }
    None
}

pub(crate) fn find_workspace_root(file: &Path) -> Option<PathBuf> {
    const MARKERS: &[&str] = &[
        ".git",
        "Cargo.toml",
        "pyproject.toml",
        "setup.py",
        "package.json",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "Gemfile",
        "mix.exs",
    ];

    // Start from the file's directory (or the file itself if it's a dir).
    // W1-5: a bare/relative file like `main.js` has an empty parent (`""`),
    // which makes the marker walk and subsequent WalkDir fail. Normalize the
    // empty parent to the current working directory (`.`).
    let start = if file.is_dir() {
        file.to_path_buf()
    } else {
        let parent = file.parent()?.to_path_buf();
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent
        }
    };

    let mut current: Option<&Path> = Some(start.as_path());
    while let Some(dir) = current {
        for marker in MARKERS {
            if dir.join(marker).exists() {
                return Some(dir.to_path_buf());
            }
        }
        current = dir.parent();
    }
    None
}

/// Skip well-known non-source directories during the project walk.
///
/// Returning `true` here prunes the directory and its descendants from
/// the walk, which keeps the cross-file resolver from descending into
/// `node_modules`, `target`, build outputs, and version control caches.
fn is_skipped_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".tox"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".idea"
            | ".vscode"
    )
}

/// Extract import statements from source code
fn extract_imports(source: &str) -> Vec<(String, Vec<String>)> {
    let mut imports = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("from ") {
            if let Some(import_idx) = line.find(" import ") {
                let module = &line[5..import_idx];
                let names_str = &line[import_idx + 8..];
                let names: Vec<String> = names_str
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .split(" as ")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .filter(|s| !s.is_empty() && s != "*")
                    .collect();
                imports.push((module.trim().to_string(), names));
            }
        } else if let Some(module) = line.strip_prefix("import ") {
            let module = module.split(" as ").next().unwrap_or(module).trim();
            imports.push((module.to_string(), Vec::new()));
        }
    }

    imports
}

/// Resolve a module path to a file path
///
/// Handles both absolute imports (`os.path`) and relative imports (`.utils`, `..pkg.mod`).
/// For relative imports, leading dots indicate the number of parent directories to traverse
/// from the current file's location (1 dot = same package, 2 dots = parent, etc.).
fn resolve_module_path(module: &str, current_file: &Path, project_root: &Path) -> Option<PathBuf> {
    let current_dir = current_file.parent()?;

    // Count leading dots for relative imports
    let dot_count = module.chars().take_while(|&c| c == '.').count();

    if dot_count > 0 {
        // Relative import: strip the leading dots and resolve relative to current package
        let remainder = &module[dot_count..];

        // Navigate up (dot_count - 1) directories from the current file's directory.
        // 1 dot  = same directory as current file
        // 2 dots = parent directory
        // 3 dots = grandparent directory, etc.
        let mut base = current_dir.to_path_buf();
        for _ in 1..dot_count {
            base = base.parent()?.to_path_buf();
        }

        if remainder.is_empty() {
            // "from . import X" - resolve to __init__.py in current package
            let pkg_candidate = base.join("__init__.py");
            if pkg_candidate.exists() {
                return Some(pkg_candidate);
            }
            return None;
        }

        // Convert remaining dotted path to filesystem path
        let rel_path = remainder.replace('.', "/");

        // Try as a module file
        let candidate = base.join(&rel_path).with_extension("py");
        if candidate.exists() {
            return Some(candidate);
        }

        // Try as a package directory
        let pkg_candidate = base.join(&rel_path).join("__init__.py");
        if pkg_candidate.exists() {
            return Some(pkg_candidate);
        }

        return None;
    }

    // Absolute import: try relative to current directory first, then project root
    let rel_path = module.replace('.', "/");

    // Try relative to current file's directory
    let candidate = current_dir.join(&rel_path).with_extension("py");
    if candidate.exists() {
        return Some(candidate);
    }

    // Try as package
    let pkg_candidate = current_dir.join(&rel_path).join("__init__.py");
    if pkg_candidate.exists() {
        return Some(pkg_candidate);
    }

    // Try relative to project root
    let candidate = project_root.join(&rel_path).with_extension("py");
    if candidate.exists() {
        return Some(candidate);
    }

    let pkg_candidate = project_root.join(&rel_path).join("__init__.py");
    if pkg_candidate.exists() {
        return Some(pkg_candidate);
    }

    None
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a symbol is a language builtin
pub fn is_builtin(name: &str, language: &Language) -> bool {
    match language {
        Language::Python => PYTHON_BUILTINS.contains(&name),
        _ => false,
    }
}

/// Lua / Luau standard-library global tables.
///
/// A member access whose base is one of these (e.g. `string.find`,
/// `table.insert`, `math.max`) is a call into the standard library, not
/// a reference to a user-defined symbol. C2 (v0.5.0 AUDIT-FIX): without
/// this check the resolver fell through to a trailing-segment cross-file
/// search and produced a *wrong* hit on an unrelated user `find` in
/// another file (the live `string.find` -> `tables.luau` regression).
///
/// Covers Lua 5.x and Luau standard libraries. These names are reserved
/// stdlib globals in the supported corpus; treating their members as
/// builtins is the correct go-to-definition answer (an external/builtin
/// symbol with no user source location).
const LUA_STDLIB_TABLES: &[&str] = &[
    "string", "table", "math", "os", "io", "coroutine", "debug", "utf8",
    "package", "bit32", "buffer", "vector", "task",
];

/// If `symbol` is a dotted member access `lib.member` whose base `lib` is
/// a Lua/Luau standard-library table, return `Some(lib)`. Used to short
/// circuit go-to-definition with a clean builtin result instead of a
/// bogus user-symbol cross-file hit.
///
/// Only the FIRST segment is inspected: `string.find` -> `Some("string")`,
/// `mytable.find` -> `None`, `find` -> `None`. A user variable that
/// happens to be named after a stdlib table (e.g. a local `string`) is a
/// rare shadowing case; if a local binding exists it is resolved by the
/// earlier local-scope pass before this check runs, so the stdlib answer
/// only applies when no user binding shadows the name.
fn lua_stdlib_member(symbol: &str, language: Language) -> Option<&'static str> {
    if !matches!(language, Language::Lua | Language::Luau) {
        return None;
    }
    // Must be a dotted/colon member access with a single base segment.
    let base = symbol.split(['.', ':']).next()?;
    if base.is_empty() || base == symbol {
        return None;
    }
    LUA_STDLIB_TABLES
        .iter()
        .copied()
        .find(|&lib| lib == base)
}

/// Build a builtin [`DefinitionResult`] for a standard-library / external
/// symbol that has no user source location.
fn builtin_definition_result(name: &str, module: &str) -> DefinitionResult {
    DefinitionResult {
        symbol: SymbolInfo {
            name: name.to_string(),
            kind: SymbolKind::Function,
            location: None,
            type_annotation: None,
            docstring: None,
            is_builtin: true,
            module: Some(module.to_string()),
        },
        definition: None,
        type_definition: None,
    }
}

/// Detect language from a file extension or an explicit hint.
///
/// Supports all 18 TLDR languages (VAL-015). The hint is the lower-case
/// language name (`"python"`, `"typescript"`, ..., `"ocaml"`); a hint of
/// `"auto"` falls through to extension-based detection via
/// [`Language::from_path`].
fn detect_language(file: &Path, hint: &str) -> RemainingResult<Language> {
    if hint != "auto" {
        let normalized = hint.to_lowercase();
        // Common short aliases.
        let alias = match normalized.as_str() {
            "py" => Some(Language::Python),
            "ts" => Some(Language::TypeScript),
            "tsx" => Some(Language::TypeScript),
            "js" => Some(Language::JavaScript),
            "jsx" => Some(Language::JavaScript),
            "rs" => Some(Language::Rust),
            "golang" => Some(Language::Go),
            "c++" => Some(Language::Cpp),
            "c#" => Some(Language::CSharp),
            "cs" => Some(Language::CSharp),
            "kt" => Some(Language::Kotlin),
            "rb" => Some(Language::Ruby),
            "ex" | "exs" => Some(Language::Elixir),
            "ml" | "mli" => Some(Language::Ocaml),
            _ => None,
        };
        if let Some(lang) = alias {
            return Ok(lang);
        }
        // Match against the canonical lowercase name (matches Language::as_str).
        for lang in Language::all() {
            if lang.as_str() == normalized {
                return Ok(*lang);
            }
        }
        return Err(RemainingError::unsupported_language(hint));
    }

    Language::from_path(file).ok_or_else(|| {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        RemainingError::unsupported_language(ext)
    })
}

/// Format definition result as text
fn format_definition_text(result: &DefinitionResult) -> String {
    let mut output = String::new();

    output.push_str("=== Definition Result ===\n\n");
    output.push_str(&format!("Symbol: {}\n", result.symbol.name));
    output.push_str(&format!("Kind: {:?}\n", result.symbol.kind));

    if result.symbol.is_builtin {
        output.push_str("Type: Built-in\n");
        if let Some(ref module) = result.symbol.module {
            output.push_str(&format!("Module: {}\n", module));
        }
    } else if let Some(ref location) = result.definition {
        output.push_str("\nDefinition Location:\n");
        output.push_str(&format!("  File: {}\n", location.file));
        output.push_str(&format!("  Line: {}\n", location.line));
        if location.column > 0 {
            output.push_str(&format!("  Column: {}\n", location.column));
        }
    } else {
        output.push_str("\nDefinition: Not found\n");
    }

    if let Some(ref type_def) = result.type_definition {
        output.push_str("\nType Definition:\n");
        output.push_str(&format!("  File: {}\n", type_def.file));
        output.push_str(&format!("  Line: {}\n", type_def.line));
    }

    if let Some(ref docstring) = result.symbol.docstring {
        output.push_str(&format!("\nDocstring:\n  {}\n", docstring));
    }

    output
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_builtin_python() {
        assert!(is_builtin("len", &Language::Python));
        assert!(is_builtin("print", &Language::Python));
        assert!(is_builtin("range", &Language::Python));
        assert!(!is_builtin("my_func", &Language::Python));
    }

    #[test]
    fn test_cycle_detector() {
        let mut detector = DefinitionCycleDetector::new();

        // First visit should return false (not a cycle)
        assert!(!detector.visit(Path::new("file.py"), "symbol"));

        // Second visit to same location should return true (cycle)
        assert!(detector.visit(Path::new("file.py"), "symbol"));

        // Different location should return false
        assert!(!detector.visit(Path::new("other.py"), "symbol"));
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(
            detect_language(Path::new("test.py"), "auto").unwrap(),
            Language::Python
        );
    }

    #[test]
    fn test_detect_language_with_hint() {
        assert_eq!(
            detect_language(Path::new("test.txt"), "python").unwrap(),
            Language::Python
        );
    }

    #[test]
    fn test_extract_imports() {
        let source = r#"
from os import path, getcwd
from sys import argv
import json
import re as regex
"#;
        let imports = extract_imports(source);

        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].0, "os");
        assert!(imports[0].1.contains(&"path".to_string()));
        assert!(imports[0].1.contains(&"getcwd".to_string()));
        assert_eq!(imports[1].0, "sys");
        assert!(imports[1].1.contains(&"argv".to_string()));
        assert_eq!(imports[2].0, "json");
        assert_eq!(imports[3].0, "re");
    }

    #[test]
    fn test_extract_imports_relative() {
        let source = r#"
from .utils import echo, make_str
from .exceptions import Abort
from ._utils import FLAG_NEEDS_VALUE
from . import types
"#;
        let imports = extract_imports(source);

        assert_eq!(imports.len(), 4);
        // Relative imports should preserve the dot prefix
        assert_eq!(imports[0].0, ".utils");
        assert!(imports[0].1.contains(&"echo".to_string()));
        assert!(imports[0].1.contains(&"make_str".to_string()));
        assert_eq!(imports[1].0, ".exceptions");
        assert!(imports[1].1.contains(&"Abort".to_string()));
        assert_eq!(imports[2].0, "._utils");
        assert!(imports[2].1.contains(&"FLAG_NEEDS_VALUE".to_string()));
        assert_eq!(imports[3].0, ".");
        assert!(imports[3].1.contains(&"types".to_string()));
    }

    #[test]
    fn test_resolve_module_path_relative_import() {
        // Create a temp directory structure simulating a Python package
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("mypkg");
        fs::create_dir_all(&pkg).unwrap();

        // Create files
        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(pkg.join("core.py"), "from .utils import helper\n").unwrap();
        fs::write(pkg.join("utils.py"), "def helper(): pass\n").unwrap();

        let current_file = pkg.join("core.py");
        let project_root = dir.path();

        // Relative import ".utils" from core.py should resolve to utils.py in the same directory
        let resolved = resolve_module_path(".utils", &current_file, project_root);
        assert!(
            resolved.is_some(),
            "resolve_module_path should find .utils relative to core.py"
        );
        assert_eq!(
            resolved.unwrap(),
            pkg.join("utils.py"),
            "Should resolve to sibling utils.py"
        );
    }

    #[test]
    fn test_resolve_module_path_relative_import_subpackage() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("mypkg");
        let sub = pkg.join("sub");
        fs::create_dir_all(&sub).unwrap();

        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(sub.join("__init__.py"), "").unwrap();
        fs::write(pkg.join("core.py"), "").unwrap();
        fs::write(sub.join("helpers.py"), "def helper(): pass\n").unwrap();

        let current_file = pkg.join("core.py");
        let project_root = dir.path();

        // ".sub.helpers" from core.py should resolve to sub/helpers.py
        let resolved = resolve_module_path(".sub.helpers", &current_file, project_root);
        assert!(
            resolved.is_some(),
            "resolve_module_path should find .sub.helpers relative to core.py"
        );
        assert_eq!(
            resolved.unwrap(),
            sub.join("helpers.py"),
            "Should resolve to sub/helpers.py"
        );
    }

    #[test]
    fn test_cross_file_definition_via_relative_import() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("mypkg");
        fs::create_dir_all(&pkg).unwrap();

        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(
            pkg.join("core.py"),
            "from .utils import echo\n\ndef main():\n    echo('hello')\n",
        )
        .unwrap();
        fs::write(pkg.join("utils.py"), "def echo(msg):\n    print(msg)\n").unwrap();

        // Look for 'echo' starting from core.py with project context
        let result =
            find_definition_by_name("echo", &pkg.join("core.py"), Some(dir.path()), "python");

        assert!(
            result.is_ok(),
            "Should find echo via cross-file resolution: {:?}",
            result.err()
        );
        let result = result.unwrap();
        assert_eq!(result.symbol.name, "echo");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        assert!(
            result.definition.is_some(),
            "Should have a definition location"
        );
        let def_loc = result.definition.unwrap();
        assert!(
            def_loc.file.contains("utils.py"),
            "Definition should be in utils.py, got: {}",
            def_loc.file
        );
        assert_eq!(def_loc.line, 1, "echo is defined on line 1 of utils.py");
    }

    #[test]
    fn test_w2_15_cpp_header_out_of_line_method_resolves_cross_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let main_cpp = root.join("main.cpp");
        let api_h = root.join("api.h");

        fs::write(
            &main_cpp,
            "#include \"api.h\"\n\nint main() {\n    Api api;\n    return api.target();\n}\n",
        )
        .unwrap();
        fs::write(
            &api_h,
            "class Api {\npublic:\n    int target();\n};\n\nint Api::target() {\n    return 7;\n}\n",
        )
        .unwrap();

        let result = find_definition_by_name("target", &main_cpp, Some(root), "cpp")
            .expect("C++ header definition should resolve cross-file");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.expect("definition location must be Some");
        assert!(
            def.file.ends_with("api.h"),
            "definition should resolve to api.h, got {}",
            def.file
        );
        assert_eq!(
            def.line, 6,
            "definition should point at the out-of-line Api::target body"
        );
    }

    // -------------------------------------------------------------------------
    // F4b-definition-py-import: a Python `from .mod import f` followed by a
    // usage `f()` must resolve to f's REAL definition (Function/Class/
    // Variable in the imported module), NOT to `kind=module` at the import
    // line. The regression appeared whenever no explicit `--project` /
    // workspace root was detected: cross-file resolution was skipped and the
    // query dead-ended at the Pass-3 import-scope fallback. The fix derives a
    // Python fallback root (file's package dir) so relative from-imports
    // always fall through to `resolve_cross_file`.
    //
    // GENERALIZATION: every variant in the symptom class is exercised below
    // using the real CLI-derived fallback root (`resolve_definition_root`
    // with workspace on and no `--project`, asserted via `f4b_root` to be the
    // file's package dir) — function, class and module-level variable
    // from-imports, a sub-package (`from .sub.deep import …`) relative
    // import, both the name-based and position-based entry points, the
    // root-resolution policy itself (explicit-project / workspace-off /
    // Python-vs-non-Python / marker-present branches), AND the two regression
    // guards that must stay green (a same-file definition still wins over the
    // import, and a genuinely-unresolvable third-party `import json` still
    // falls back to the import-line `module` result). A single-variant test
    // would not have caught a partial fix.
    // -------------------------------------------------------------------------

    /// Build a marker-less package (no `.git`/`pyproject.toml`/… so
    /// `find_workspace_root` returns None and the Python fallback root is
    /// exercised) and return the tempdir + `app.py` path.
    fn f4b_make_pkg() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        let sub = pkg.join("sub");
        fs::create_dir_all(&sub).unwrap();

        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(sub.join("__init__.py"), "").unwrap();
        // mod.py: a function (line 1), a class (line 5), a module-level
        // variable (line 9).
        fs::write(
            pkg.join("mod.py"),
            "def helper():\n    return 42\n\n\nclass Widget:\n    pass\n\n\nCONST = 99\n",
        )
        .unwrap();
        // sub/deep.py: a function (line 1) reached via a sub-package import.
        fs::write(sub.join("deep.py"), "def deep_fn():\n    return 7\n").unwrap();
        // app.py: imports each symbol and uses it. A locally-defined
        // `local_fn` (line 8) guards same-file precedence; `import json`
        // (line 5) guards the plain-import fallback.
        let app = pkg.join("app.py");
        fs::write(
            &app,
            "from .mod import helper\n\
             from .mod import Widget\n\
             from .mod import CONST\n\
             from .sub.deep import deep_fn\n\
             import json\n\
             \n\
             \n\
             def local_fn():\n\
            \x20   return 1\n\
             \n\
             \n\
             def main():\n\
            \x20   helper()\n\
            \x20   Widget()\n\
            \x20   x = CONST\n\
            \x20   deep_fn()\n\
            \x20   json.loads(\"{}\")\n\
            \x20   return local_fn()\n",
        )
        .unwrap();
        (dir, app)
    }

    /// The cross-file root the CLI now derives for a marker-less Python tree
    /// (`resolve_definition_root` with workspace on, no `--project`). Asserts
    /// the fallback is exactly the file's package directory so the tests
    /// exercise the *real* policy the binary runs, not a hand-picked root.
    fn f4b_root(app: &Path) -> PathBuf {
        let root = resolve_definition_root(None, true, app, Some(Language::Python))
            .expect("marker-less Python tree must yield a package-dir fallback root");
        assert_eq!(
            root,
            app.parent().unwrap(),
            "fallback root must be the file's own package directory"
        );
        root
    }

    #[test]
    fn test_f4b_from_import_function_resolves_to_real_def_no_project() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        // Name-based: must follow the from-import to the real Function def in
        // mod.py — NOT report kind=module at the import line.
        let result = find_definition_by_name("helper", &app, Some(&root), "python")
            .expect("from-import of a function must resolve cross-file");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.expect("definition location must be Some");
        assert!(
            def.file.ends_with("mod.py"),
            "helper must resolve into mod.py, got {}",
            def.file
        );
        assert_eq!(def.line, 1, "helper is defined on line 1 of mod.py");
    }

    #[test]
    fn test_f4b_from_import_class_resolves_to_real_def_no_project() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        let result = find_definition_by_name("Widget", &app, Some(&root), "python")
            .expect("from-import of a class must resolve cross-file");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Class,
            "imported class must be kind=class, not module"
        );
        let def = result.definition.unwrap();
        assert!(def.file.ends_with("mod.py"));
        assert_eq!(def.line, 5);
    }

    #[test]
    fn test_f4b_from_import_variable_resolves_to_real_def_no_project() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        let result = find_definition_by_name("CONST", &app, Some(&root), "python")
            .expect("from-import of a module-level variable must resolve cross-file");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Variable,
            "imported variable must be kind=variable, not module"
        );
        let def = result.definition.unwrap();
        assert!(def.file.ends_with("mod.py"));
        assert_eq!(def.line, 9);
    }

    #[test]
    fn test_f4b_subpackage_from_import_resolves_no_project() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        let result = find_definition_by_name("deep_fn", &app, Some(&root), "python")
            .expect("sub-package from-import must resolve cross-file");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.unwrap();
        assert!(
            def.file.ends_with("deep.py"),
            "deep_fn must resolve into sub/deep.py, got {}",
            def.file
        );
        assert_eq!(def.line, 1);
    }

    #[test]
    fn test_f4b_position_based_from_import_resolves_no_project() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        // Cursor on `helper` in the `helper()` call on line 13 (col 4,
        // 0-indexed). End-to-end position path must reach the real def.
        let result = find_definition_by_position(&app, 13, 4, Some(&root), "python")
            .expect("position-based from-import usage must resolve cross-file");
        assert_eq!(result.symbol.name, "helper");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Function,
            "position-based usage of an imported function must be kind=function, not module"
        );
        assert_eq!(result.definition.unwrap().line, 1);
    }

    #[test]
    fn test_f4b_same_file_definition_still_wins_over_cross_file() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        // `local_fn` is defined in app.py itself — must resolve to the local
        // def, never wander cross-file.
        let result = find_definition_by_name("local_fn", &app, Some(&root), "python")
            .expect("same-file definition must still resolve");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.unwrap();
        assert!(
            def.file.ends_with("app.py"),
            "local_fn must resolve in app.py, got {}",
            def.file
        );
        assert_eq!(def.line, 8);
    }

    #[test]
    fn test_f4b_plain_unresolvable_import_still_falls_back_to_module() {
        let (_dir, app) = f4b_make_pkg();
        let root = f4b_root(&app);
        // `import json` cannot be followed to a project file (third-party):
        // the Python package-dir fallback root must find nothing and leave the
        // Pass-3 import-line `module` result intact. Cursor on `json` in the
        // `json.loads(...)` call on line 17 (col 4, 0-indexed).
        let result = find_definition_by_position(&app, 17, 4, Some(&root), "python")
            .expect("plain-import usage must still resolve to the import line");
        assert_eq!(result.symbol.name, "json");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Module,
            "an unresolvable third-party import must stay kind=module"
        );
        assert_eq!(
            result.definition.unwrap().line,
            5,
            "json import is on line 5"
        );
    }

    #[test]
    fn test_f4b_resolve_definition_root_policy() {
        // The root-resolution policy that decides whether (and from where)
        // cross-file resolution runs. Covers every branch so the workspace
        // opt-out contract and the Python fallback cannot silently drift.
        let (_dir, app) = f4b_make_pkg();
        let pkg_dir = app.parent().unwrap();
        let explicit = app.parent().unwrap().parent().unwrap(); // tmp root

        // 1. Explicit --project always wins (regardless of workspace flag).
        assert_eq!(
            resolve_definition_root(Some(explicit), false, &app, Some(Language::Python)),
            Some(explicit.to_path_buf()),
            "explicit --project must win even with --workspace=false"
        );

        // 2. --workspace=false, no --project -> None (legacy opt-out). This is
        //    the contract guarded by test_definition_workspace_false_keeps_legacy_behaviour.
        assert_eq!(
            resolve_definition_root(None, false, &app, Some(Language::Python)),
            None,
            "--workspace=false must disable cross-file resolution"
        );

        // 3. Workspace on, marker-less Python tree -> file's package dir
        //    (the F4b fix: relative from-imports resolve without a marker).
        assert_eq!(
            resolve_definition_root(None, true, &app, Some(Language::Python)),
            Some(pkg_dir.to_path_buf()),
            "marker-less Python tree must fall back to the package directory"
        );

        // 4. Workspace on, marker-less, NON-Python -> None (the package-dir
        //    fallback is Python-only; walk-languages need a real root).
        assert_eq!(
            resolve_definition_root(None, true, &app, Some(Language::Rust)),
            None,
            "non-Python marker-less tree must not get the package-dir fallback"
        );

        // 5. Workspace on, marker PRESENT -> the detected workspace root wins
        //    over the package-dir fallback.
        let marked = tempfile::tempdir().unwrap();
        let pkg = marked.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(marked.path().join("pyproject.toml"), "").unwrap();
        let marked_app = pkg.join("app.py");
        fs::write(&marked_app, "x = 1\n").unwrap();
        assert_eq!(
            resolve_definition_root(None, true, &marked_app, Some(Language::Python)),
            Some(marked.path().to_path_buf()),
            "a detected workspace marker must win over the package-dir fallback"
        );
    }

    /// W1-5: a bare/relative `--file` path must still resolve cross-file
    /// definitions. Without the fix `find_workspace_root("main.js")` derives an
    /// empty parent, the marker walk returns `Some("")`, and the subsequent
    /// WalkDir on an empty root visits zero files -> "symbol not found".
    #[test]
    fn test_w1_5_bare_relative_file_resolves_cross_file() {
        // Guard that restores the original working directory even on panic.
        struct ChdirGuard(PathBuf);
        impl Drop for ChdirGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // A marker so workspace detection has something to find.
        fs::create_dir_all(root.join(".git")).unwrap();

        // helper.js defines the symbol.
        fs::write(
            root.join("helper.js"),
            "function helper() {\n    return 42;\n}\n",
        )
        .unwrap();

        // main.js uses it.
        fs::write(
            root.join("main.js"),
            "function main() {\n    return helper();\n}\n",
        )
        .unwrap();

        // Exercise the resolver exactly as the CLI does: from inside the project
        // root, with a bare relative file path.
        let guard = ChdirGuard(std::env::current_dir().unwrap());
        std::env::set_current_dir(root).unwrap();

        let resolved_root =
            resolve_definition_root(None, true, Path::new("main.js"), Some(Language::JavaScript))
                .expect("workspace root must resolve for a bare relative file");
        assert!(
            !resolved_root.as_os_str().is_empty(),
            "resolved workspace root must not be empty"
        );

        let result = find_definition_by_name("helper", Path::new("main.js"), Some(&resolved_root), "javascript")
            .expect("helper must resolve cross-file from a bare relative --file");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.expect("definition location must be Some");
        assert!(
            def.file.ends_with("helper.js"),
            "helper must resolve into helper.js, got {}",
            def.file
        );
        assert_eq!(def.line, 1, "helper is defined on line 1 of helper.js");

        drop(guard);
    }

    // -------------------------------------------------------------------------
    // VAL-015: multi-language go-to-definition
    //
    // Until VAL-015, find_definition_by_name and find_definition_by_position
    // returned UnsupportedLanguage for any non-Python file. These tests
    // verify the generalisation: the dispatch reuses each language handler's
    // CallGraphLanguageSupport::extract_definitions API to locate the
    // definition site of a top-level function in a single file.
    //
    // Coverage: Python (regression), TypeScript (brace-language family),
    // Rust (strict-types), Go (semicolon-free), Java (OOP).
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_definition_typescript_function() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("main.ts");
        fs::write(
            &file,
            "export function target_fn(): number { return 42; }\n\
             export function caller(): void { target_fn(); }\n",
        )
        .unwrap();

        let result = find_definition_by_name("target_fn", &file, None, "typescript")
            .expect("definition lookup should succeed for TypeScript");
        assert_eq!(result.symbol.name, "target_fn");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 1, "target_fn is on line 1, got {}", loc.line);
    }

    #[test]
    fn test_find_definition_rust_function() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lib.rs");
        fs::write(
            &file,
            "fn helper() -> i32 { 1 }\n\nfn target_fn() -> i32 { helper() }\n",
        )
        .unwrap();

        let result = find_definition_by_name("target_fn", &file, None, "rust")
            .expect("definition lookup should succeed for Rust");
        assert_eq!(result.symbol.name, "target_fn");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 3, "target_fn is on line 3, got {}", loc.line);
    }

    #[test]
    fn test_find_definition_go_function() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("main.go");
        fs::write(
            &file,
            "package main\n\nfunc target_fn() int { return 1 }\n\nfunc main() { target_fn() }\n",
        )
        .unwrap();

        let result = find_definition_by_name("target_fn", &file, None, "go")
            .expect("definition lookup should succeed for Go");
        assert_eq!(result.symbol.name, "target_fn");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 3, "target_fn is on line 3, got {}", loc.line);
    }

    #[test]
    fn test_find_definition_java_method() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Main.java");
        // Java requires methods inside a class; the matrix fixture follows
        // the same pattern.
        fs::write(
            &file,
            "class Main {\n    public static int target_fn() { return 1; }\n    public static void main(String[] args) { target_fn(); }\n}\n",
        )
        .unwrap();

        let result = find_definition_by_name("target_fn", &file, None, "java")
            .expect("definition lookup should succeed for Java");
        assert_eq!(result.symbol.name, "target_fn");
        // Methods inside a class must report Method, not Function.
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Method,
            "Java method inside class should be Method, got {:?}",
            result.symbol.kind
        );
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 2, "target_fn is on line 2, got {}", loc.line);
    }

    #[test]
    fn test_find_definition_class_typescript() {
        // Classes must surface as SymbolKind::Class regardless of language.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("widget.ts");
        fs::write(&file, "export class Widget {\n    render(): void {}\n}\n").unwrap();

        let result = find_definition_by_name("Widget", &file, None, "typescript")
            .expect("definition lookup should succeed for TS class");
        assert_eq!(result.symbol.name, "Widget");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Class,
            "Widget should be Class kind, got {:?}",
            result.symbol.kind
        );
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 1);
    }

    #[test]
    fn test_find_definition_position_rust() {
        // Position-based lookup: jump from a call site to the definition.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lib.rs");
        let source = "fn target_fn() -> i32 { 1 }\n\nfn caller() -> i32 { target_fn() }\n";
        fs::write(&file, source).unwrap();

        // Position of the `target_fn` reference inside caller.
        // Line 3, column 22 (0-indexed) — points at `target_fn` in the call.
        // "fn caller() -> i32 { target_fn() }"
        //  0123456789012345678901
        //                       ^ col 21 = 't'
        let result = find_definition_by_position(&file, 3, 22, None, "rust")
            .expect("position-based lookup should succeed for Rust");
        assert_eq!(result.symbol.name, "target_fn");
        let loc = result.definition.expect("definition location must be Some");
        assert_eq!(loc.line, 1, "definition is on line 1");
    }

    #[test]
    fn test_detect_language_all_18() {
        // All 18 languages must be detectable from extension or hint.
        // This catches missing entries in detect_language as we add support.
        let cases: &[(&str, &str, Language)] = &[
            ("a.py", "auto", Language::Python),
            ("a.ts", "auto", Language::TypeScript),
            ("a.tsx", "auto", Language::TypeScript),
            ("a.js", "auto", Language::JavaScript),
            ("a.jsx", "auto", Language::JavaScript),
            ("a.rs", "auto", Language::Rust),
            ("a.go", "auto", Language::Go),
            ("a.java", "auto", Language::Java),
            ("a.c", "auto", Language::C),
            ("a.h", "auto", Language::C),
            ("a.cpp", "auto", Language::Cpp),
            ("a.cc", "auto", Language::Cpp),
            ("a.hpp", "auto", Language::Cpp),
            ("a.rb", "auto", Language::Ruby),
            ("a.kt", "auto", Language::Kotlin),
            ("a.swift", "auto", Language::Swift),
            ("a.cs", "auto", Language::CSharp),
            ("a.scala", "auto", Language::Scala),
            ("a.php", "auto", Language::Php),
            ("a.lua", "auto", Language::Lua),
            ("a.luau", "auto", Language::Luau),
            ("a.ex", "auto", Language::Elixir),
            ("a.exs", "auto", Language::Elixir),
            ("a.ml", "auto", Language::Ocaml),
        ];
        for (path, hint, expected) in cases {
            let got = detect_language(Path::new(path), hint)
                .unwrap_or_else(|e| panic!("detect_language failed for {}: {:?}", path, e));
            assert_eq!(got, *expected, "wrong language for {}", path);
        }
    }

    // -------------------------------------------------------------------------
    // definition-name-resolution-v1 — three-pass resolver tests
    //
    // Before this milestone, `tldr definition <file> <line> <col>` only
    // resolved when the cursor sat ON a function/class declaration. Cursors
    // on USAGE sites returned `<unknown at FILE:LINE:COL>`. The three-pass
    // resolver fixes that:
    //   Pass 1 — local scope (params, let/var bindings)
    //   Pass 2 — file scope (existing handler)
    //   Pass 3 — import scope (`import X` aliases)
    // -------------------------------------------------------------------------

    #[test]
    fn test_definition_resolves_local_param() {
        // Cursor on the usage of a parameter `x` in `def foo(x): return x + 1`
        // should resolve to the parameter, not return <unknown>.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("local.py");
        // Line 1: def foo(x):
        // Line 2:     return x + 1
        fs::write(&file, "def foo(x):\n    return x + 1\n").unwrap();

        // Cursor on `x` in `return x + 1` — column 11 of line 2.
        let result = find_definition_by_position(&file, 2, 11, None, "python")
            .expect("local-scope resolution should succeed");
        assert_eq!(result.symbol.name, "x");
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Parameter,
            "should resolve local `x` as Parameter, got {:?}",
            result.symbol.kind
        );
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(def.line, 1, "param `x` is declared on line 1, got {}", def.line);
    }

    #[test]
    fn test_definition_resolves_file_scope_function() {
        // Cursor on a usage of `helper` should resolve to its top-level
        // declaration line.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("filescope.py");
        // Line 1: def helper():
        // Line 2:     return 1
        // Line 3:
        // Line 4: def main():
        // Line 5:     return helper()
        fs::write(
            &file,
            "def helper():\n    return 1\n\ndef main():\n    return helper()\n",
        )
        .unwrap();

        // Cursor on `helper` in `return helper()` — column 11 of line 5.
        let result = find_definition_by_position(&file, 5, 11, None, "python")
            .expect("file-scope resolution should succeed");
        assert_eq!(result.symbol.name, "helper");
        assert_eq!(result.symbol.kind, SymbolKind::Function);
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(
            def.line, 1,
            "helper is declared on line 1, got {}",
            def.line
        );
    }

    #[test]
    fn test_definition_resolves_import_alias() {
        // Cursor on `click` in `click.echo(...)` should resolve to the
        // `import click` line — this is the canonical BUG-24 repro.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("imports.py");
        // Line 1: import click
        // Line 2:
        // Line 3: def main():
        // Line 4:     click.echo("hi")
        fs::write(
            &file,
            "import click\n\ndef main():\n    click.echo(\"hi\")\n",
        )
        .unwrap();

        // Cursor on `click` at column 4 of line 4.
        let result = find_definition_by_position(&file, 4, 4, None, "python")
            .expect("import-scope resolution should succeed");
        assert_eq!(result.symbol.name, "click");
        let def = result
            .definition
            .expect("import-scope resolution must produce a definition location");
        assert_eq!(
            def.line, 1,
            "import click is on line 1, got {}",
            def.line
        );
    }

    #[test]
    fn test_definition_unresolved_message() {
        // Cursor on a name that doesn't exist in any scope should produce a
        // payload whose symbol.name contains `unresolved at`.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("unresolved.py");
        // Line 1: x = 1
        // Line 2: print(nonexistent_name)
        fs::write(&file, "x = 1\nprint(nonexistent_name)\n").unwrap();

        // Cursor on `nonexistent_name` — column 6 of line 2.
        let err = find_definition_by_position(&file, 2, 6, None, "python")
            .expect_err("unresolved name must produce an error");
        let msg = err.to_string();
        assert!(
            msg.contains("unresolved at"),
            "error should mention 'unresolved at', got: {}",
            msg
        );
        assert!(
            msg.contains("nonexistent_name"),
            "error should mention the symbol, got: {}",
            msg
        );
    }

    #[test]
    fn test_definition_resolves_js_import_alias() {
        // JS namespace import: `import express from "express"` and a usage
        // `express()` — cursor on `express` should resolve to the import.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.js");
        // Line 1: const express = require("express");
        // ... we use ES-module style for the parser:
        // Line 1: import express from "express";
        // Line 2: const app = express();
        fs::write(
            &file,
            "import express from \"express\";\nconst app = express();\n",
        )
        .unwrap();

        // Cursor on `express` in `express()` — column 12 of line 2.
        let result = find_definition_by_position(&file, 2, 12, None, "javascript")
            .expect("JS import resolution should succeed");
        assert_eq!(result.symbol.name, "express");
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(def.line, 1, "import is on line 1, got {}", def.line);
    }

    #[test]
    fn test_definition_resolves_rust_let_binding() {
        // Cursor on a usage of a `let`-bound local should resolve to the
        // let-binding.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lib.rs");
        // Line 1: fn main() {
        // Line 2:     let counter = 42;
        // Line 3:     println!("{}", counter);
        // Line 4: }
        fs::write(
            &file,
            "fn main() {\n    let counter = 42;\n    println!(\"{}\", counter);\n}\n",
        )
        .unwrap();

        // Cursor on `counter` in `println!` — column 19 of line 3.
        let result = find_definition_by_position(&file, 3, 19, None, "rust")
            .expect("Rust let-binding resolution should succeed");
        assert_eq!(result.symbol.name, "counter");
        assert_eq!(result.symbol.kind, SymbolKind::Variable);
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(
            def.line, 2,
            "let counter is on line 2, got {}",
            def.line
        );
    }

    // =========================================================================
    // T7 (audit fix): `definition` invoked ON a declaration's own name (a
    // binding site) must resolve to that declaration, NOT to a shadowing
    // local variable of the same name declared inside its body.
    //
    // Repro: Pass 1 (local scope) walked up to the declaration itself as the
    // first scope-owning ancestor, then scanned its body and returned the
    // FIRST descendant identifier matching by text — the inner shadow. The
    // declaration-site guard bails out of Pass 1 when the cursor sits on the
    // scope owner's own name field, letting Pass 2 (file scope) return the
    // self-referential declaration location.
    // =========================================================================

    #[test]
    fn test_definition_on_decl_name_ignores_body_shadow_python() {
        // A function whose body declares a local shadowing its own name.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("shadow.py");
        // Line 1: def handler():
        // Line 2:     handler = 1
        // Line 3:     return handler
        fs::write(&file, "def handler():\n    handler = 1\n    return handler\n").unwrap();

        // Cursor ON the declaration name `handler` — column 4 of line 1.
        let result = find_definition_by_position(&file, 1, 4, None, "python")
            .expect("declaration-site lookup should succeed");
        assert_eq!(result.symbol.name, "handler");
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(
            def.line, 1,
            "cursor on the `def handler` name must resolve to the declaration \
             (line 1), not the body-local shadow (line 2); got line {}",
            def.line
        );
    }

    #[test]
    fn test_definition_on_decl_name_ignores_body_shadow_go_method() {
        // Audit repro shape (router.go:409:17): a method whose body declares a
        // local shadowing the method's own name.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("router.go");
        // Line 5: func (r *Router) allowed() bool {
        // Line 6: \tallowed := false
        // Line 7: \treturn allowed
        let source = "package main\n\ntype Router struct{}\n\nfunc (r *Router) allowed() bool {\n\tallowed := false\n\treturn allowed\n}\n";
        fs::write(&file, source).unwrap();

        // Cursor ON the method name `allowed` — column 17 of line 5.
        let result = find_definition_by_position(&file, 5, 17, None, "go")
            .expect("declaration-site lookup should succeed for Go method");
        assert_eq!(result.symbol.name, "allowed");
        let def = result.definition.expect("definition location must be Some");
        assert_eq!(
            def.line, 5,
            "cursor on the method name must resolve to the declaration \
             (line 5), not the body-local shadow (line 6); got line {}",
            def.line
        );
    }

    // =========================================================================
    // definition-additional-langs-v1: local-scope + import-scope tests for
    // the 13 additional languages (java, c, cpp, ruby, kotlin, swift, scala,
    // php, lua, luau, elixir, ocaml, csharp).
    // =========================================================================


    fn assert_resolves_param(
        file: &Path,
        line: u32,
        column: u32,
        lang: &str,
        expected_name: &str,
        expected_def_line: u32,
    ) {
        let result = find_definition_by_position(file, line, column, None, lang)
            .unwrap_or_else(|e| panic!("{} resolution should succeed: {}", lang, e));
        assert_eq!(result.symbol.name, expected_name);
        assert_eq!(
            result.symbol.kind,
            SymbolKind::Parameter,
            "{}: expected Parameter, got {:?}",
            lang,
            result.symbol.kind
        );
        let def = result.definition.expect("definition must be Some");
        assert_eq!(
            def.line, expected_def_line,
            "{}: param declared on line {}, got {}",
            lang, expected_def_line, def.line
        );
    }

    // =========================================================================
    // r7-cl11-definition-column-convention: char-aware column tests.
    //
    // Pin the canonical `(index-base, encoding)` mapper introduced to replace
    // the per-call-site ad-hoc `±1`/implicit-byte column math. These exercise
    // the `LineIndex` directly (the single conversion choke point) plus the
    // INPUT/OUTPUT wiring, so the coverage is self-contained and does not
    // depend on the external `/tmp/repos` corpus.
    // =========================================================================

    // Axis-2 discriminator (the gap a byte-only column hides): the three
    // encodings must DIVERGE on a non-ASCII line and COINCIDE on pure ASCII.
    // `néme` = 4 chars, 5 UTF-8 bytes (n=1, é=2, m=1, e=1), 4 UTF-16 units.
    #[test]
    fn r7_cl11_byte_col_diverges_on_non_ascii() {
        let src = "fn greet(néme: &str) -> String {\n    néme.to_string()\n}\n";
        let li = LineIndex::new(src);
        // Byte column just past `néme` on line 0: `fn greet(` is 9 bytes, plus
        // 5 bytes for `néme` => byte 14.
        let byte_col = 9 + "néme".len(); // 9 + 5 = 14
        assert_eq!(byte_col, 14);
        // utf8 keeps the raw byte width (today's value).
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf8Byte), 14);
        // utf16 and utf32 collapse the 2-byte `é` to one unit => 9 + 4 = 13.
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf16), 13);
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf32Char), 13);

        // The *width* of `néme` alone (offset 9 -> 14): utf8=5, utf16=4, utf32=4.
        let start = li.byte_col_to(0, 9, PositionEncoding::Utf8Byte);
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf8Byte) - start, 5);
        let start16 = li.byte_col_to(0, 9, PositionEncoding::Utf16);
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf16) - start16, 4);
        let start32 = li.byte_col_to(0, 9, PositionEncoding::Utf32Char);
        assert_eq!(li.byte_col_to(0, byte_col, PositionEncoding::Utf32Char) - start32, 4);
    }

    // Non-BMP: a 🦀 (U+1F980) is 4 UTF-8 bytes but TWO UTF-16 code units and
    // ONE code point — proving the byte<->utf16 delta is content-dependent
    // (not a constant, not `÷2`), the exact bug helix#5711 documents.
    #[test]
    fn r7_cl11_non_bmp_utf16_is_two_units() {
        let src = "let x = \"🦀\";\n"; // crab then closing quote
        let li = LineIndex::new(src);
        let quote_open = src.find('"').unwrap(); // byte 8
        let after_crab = quote_open + 1 + "🦀".len(); // 9 + 4 = 13
        // From just-after the opening quote to just-after the crab:
        let b0 = quote_open + 1; // byte 9
        assert_eq!(
            li.byte_col_to(0, after_crab, PositionEncoding::Utf16)
                - li.byte_col_to(0, b0, PositionEncoding::Utf16),
            2,
            "🦀 is two UTF-16 code units"
        );
        assert_eq!(
            li.byte_col_to(0, after_crab, PositionEncoding::Utf32Char)
                - li.byte_col_to(0, b0, PositionEncoding::Utf32Char),
            1,
            "🦀 is one code point"
        );
        assert_eq!(
            li.byte_col_to(0, after_crab, PositionEncoding::Utf8Byte)
                - li.byte_col_to(0, b0, PositionEncoding::Utf8Byte),
            4,
            "🦀 is four UTF-8 bytes"
        );
    }

    // Pure ASCII: all three encodings coincide (no result ever moves).
    #[test]
    fn r7_cl11_ascii_encodings_coincide() {
        let src = "fn greet(name: &str) {}\n";
        let li = LineIndex::new(src);
        for col in [0usize, 5, 9, 13, 20] {
            let b = li.byte_col_to(0, col, PositionEncoding::Utf8Byte);
            let u16 = li.byte_col_to(0, col, PositionEncoding::Utf16);
            let u32 = li.byte_col_to(0, col, PositionEncoding::Utf32Char);
            assert_eq!(b, u16, "ascii utf8/utf16 must coincide at {}", col);
            assert_eq!(b, u32, "ascii utf8/utf32 must coincide at {}", col);
        }
    }

    // Axis-1 round-trip invariant: encoding conversion is a bijection on the
    // line's columns. enc_col_to_byte ∘ byte_col_to == identity at every char
    // boundary — the property the ad-hoc per-site math could not guarantee.
    #[test]
    fn r7_cl11_encoding_round_trip_is_identity() {
        let src = "fn f(néme: i32, 🦀x: i32) {}\n";
        let li = LineIndex::new(src);
        let line0 = src.split('\n').next().unwrap();
        for enc in [
            PositionEncoding::Utf8Byte,
            PositionEncoding::Utf16,
            PositionEncoding::Utf32Char,
        ] {
            // Walk every char-boundary byte column and round-trip it.
            for (byte_idx, _) in line0.char_indices() {
                let enc_col = li.byte_col_to(0, byte_idx, enc);
                let back = li.enc_col_to_byte(0, enc_col, enc);
                assert_eq!(
                    back, byte_idx,
                    "round-trip failed for {:?} at byte {}",
                    enc, byte_idx
                );
            }
        }
    }

    // Encoding parser accepts the LSP spellings + aliases, rejects garbage.
    #[test]
    fn r7_cl11_position_encoding_parse() {
        assert_eq!(PositionEncoding::parse_cli("utf8"), Some(PositionEncoding::Utf8Byte));
        assert_eq!(PositionEncoding::parse_cli("UTF-8"), Some(PositionEncoding::Utf8Byte));
        assert_eq!(PositionEncoding::parse_cli("byte"), Some(PositionEncoding::Utf8Byte));
        assert_eq!(PositionEncoding::parse_cli("utf16"), Some(PositionEncoding::Utf16));
        assert_eq!(PositionEncoding::parse_cli("utf-16"), Some(PositionEncoding::Utf16));
        assert_eq!(PositionEncoding::parse_cli("utf32"), Some(PositionEncoding::Utf32Char));
        assert_eq!(PositionEncoding::parse_cli("char"), Some(PositionEncoding::Utf32Char));
        assert_eq!(PositionEncoding::parse_cli(""), None);
        assert_eq!(PositionEncoding::parse_cli("latin1"), None);
        assert_eq!(PositionEncoding::default(), PositionEncoding::Utf8Byte);
    }

    // OUTPUT re-encoding is a no-op under the default `utf8` (byte contract
    // preserved) and rewrites the column under `utf16` for a non-ASCII line.
    //
    // Fixture line bytes: `fn f(néme: i32)...`
    //   0:f 1:n 2:' ' 3:f 4:( 5:n 6,7:é 8:m 9:e 10:: ...
    // So `néme` starts at byte 5 => 1-indexed byte column 6 (start, BEFORE the
    // multi-byte `é`), and byte 8 (`m`, AFTER `é`) => 1-indexed column 9.
    #[test]
    fn r7_cl11_reencode_output_columns() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("u.rs");
        fs::write(&file, "fn f(néme: i32) -> i32 { néme }\n").unwrap();
        let fstr = file.display().to_string();

        let mk = |col: u32, name: &str| DefinitionResult {
            symbol: SymbolInfo {
                name: name.to_string(),
                kind: SymbolKind::Parameter,
                location: Some(Location::with_column(fstr.clone(), 1, col)),
                type_annotation: None,
                docstring: None,
                is_builtin: false,
                module: None,
            },
            definition: Some(Location::with_column(fstr.clone(), 1, col)),
            type_definition: None,
        };

        // Default utf8: byte column unchanged (the existing contract).
        let mut r8 = mk(6, "néme");
        reencode_result_columns(&mut r8, PositionEncoding::Utf8Byte);
        assert_eq!(r8.definition.unwrap().column, 6);

        // utf16, column 6 = start of `néme` (precedes the multi-byte `é`) =>
        // unchanged, proving the conversion is line-content-aware.
        let mut r16_start = mk(6, "néme");
        reencode_result_columns(&mut r16_start, PositionEncoding::Utf16);
        assert_eq!(
            r16_start.definition.unwrap().column,
            6,
            "col at the start of `néme` precedes `é` => unchanged"
        );

        // utf16, column 9 = byte 8 (`m`, AFTER the 2-byte `é`) => the saved
        // byte collapses the column to 8.
        let mut r16_after = mk(9, "néme");
        reencode_result_columns(&mut r16_after, PositionEncoding::Utf16);
        assert_eq!(
            r16_after.definition.unwrap().column,
            8,
            "1-indexed byte col 9 (after the 2-byte `é`) -> utf16 col 8"
        );
    }

    #[test]
    fn test_definition_resolves_local_param_java() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Foo.java");
        // Line 1: class Foo {
        // Line 2:   int add(int a, int b) {
        // Line 3:     return a + b;
        // Line 4:   }
        // Line 5: }
        fs::write(
            &file,
            "class Foo {\n  int add(int a, int b) {\n    return a + b;\n  }\n}\n",
        )
        .unwrap();
        // Cursor on `a` in `return a + b` — column 11 of line 3.
        assert_resolves_param(&file, 3, 11, "java", "a", 2);
    }

    #[test]
    fn test_definition_resolves_local_param_c() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.c");
        // Line 1: int add(int a, int b) {
        // Line 2:   return a + b;
        // Line 3: }
        fs::write(&file, "int add(int a, int b) {\n  return a + b;\n}\n").unwrap();
        // Cursor on `a` in line 2.
        assert_resolves_param(&file, 2, 9, "c", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_cpp() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.cpp");
        fs::write(&file, "int add(int a, int b) {\n  return a + b;\n}\n").unwrap();
        assert_resolves_param(&file, 2, 9, "cpp", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_ruby() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.rb");
        // Line 1: def add(a, b)
        // Line 2:   a + b
        // Line 3: end
        fs::write(&file, "def add(a, b)\n  a + b\nend\n").unwrap();
        assert_resolves_param(&file, 2, 2, "ruby", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_kotlin() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.kt");
        // Line 1: fun add(a: Int, b: Int): Int {
        // Line 2:   return a + b
        // Line 3: }
        fs::write(
            &file,
            "fun add(a: Int, b: Int): Int {\n  return a + b\n}\n",
        )
        .unwrap();
        // Cursor on `a` in line 2.
        assert_resolves_param(&file, 2, 9, "kotlin", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_swift() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.swift");
        // Line 1: func add(a: Int, b: Int) -> Int {
        // Line 2:   return a + b
        // Line 3: }
        fs::write(
            &file,
            "func add(a: Int, b: Int) -> Int {\n  return a + b\n}\n",
        )
        .unwrap();
        // Cursor on `a` in line 2.
        assert_resolves_param(&file, 2, 9, "swift", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_scala() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.scala");
        // Line 1: def add(a: Int, b: Int): Int = {
        // Line 2:   a + b
        // Line 3: }
        fs::write(
            &file,
            "def add(a: Int, b: Int): Int = {\n  a + b\n}\n",
        )
        .unwrap();
        assert_resolves_param(&file, 2, 2, "scala", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_php() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.php");
        // Line 1: <?php
        // Line 2: function add($a, $b) {
        // Line 3:   return $a + $b;
        // Line 4: }
        fs::write(
            &file,
            "<?php\nfunction add($a, $b) {\n  return $a + $b;\n}\n",
        )
        .unwrap();
        // Cursor on `$a` (or `a` portion) in line 3.
        let result = find_definition_by_position(&file, 3, 10, None, "php")
            .expect("php resolution should succeed");
        // The symbol may resolve as `$a` or `a` depending on tokenization.
        let name = result.symbol.name.trim_start_matches('$');
        assert_eq!(name, "a");
        assert_eq!(result.symbol.kind, SymbolKind::Parameter);
        let def = result.definition.expect("definition must be Some");
        assert_eq!(def.line, 2);
    }

    #[test]
    fn test_definition_resolves_local_param_lua() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.lua");
        // Line 1: local function add(a, b)
        // Line 2:   return a + b
        // Line 3: end
        fs::write(&file, "local function add(a, b)\n  return a + b\nend\n").unwrap();
        assert_resolves_param(&file, 2, 9, "lua", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_luau() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.luau");
        fs::write(&file, "local function add(a, b)\n  return a + b\nend\n").unwrap();
        assert_resolves_param(&file, 2, 9, "luau", "a", 1);
    }

    #[test]
    fn test_definition_resolves_local_param_elixir() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.ex");
        // Line 1: defmodule Foo do
        // Line 2:   def add(a, b) do
        // Line 3:     a + b
        // Line 4:   end
        // Line 5: end
        fs::write(
            &file,
            "defmodule Foo do\n  def add(a, b) do\n    a + b\n  end\nend\n",
        )
        .unwrap();
        // Cursor on `a` in line 3.
        assert_resolves_param(&file, 3, 4, "elixir", "a", 2);
    }

    #[test]
    fn test_definition_resolves_local_param_ocaml() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.ml");
        // Line 1: let add a b = a + b
        fs::write(&file, "let add a b = a + b\n").unwrap();
        // Cursor on `a` in `a + b` — column 14 of line 1.
        assert_resolves_param(&file, 1, 14, "ocaml", "a", 1);
    }

    #[test]
    fn test_definition_ocaml_nonrec_let_rhs_uses_prior_binding_but_rec_self_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("shadow.ml");
        fs::write(
            &file,
            "let x = 1\n\nlet x =\n  x + 1\n\nlet rec y =\n  y + 1\n",
        )
        .unwrap();

        let nonrec = find_definition_by_position(&file, 4, 2, None, "ocaml")
            .expect("non-recursive rhs use should resolve");
        assert_eq!(nonrec.symbol.name, "x");
        let nonrec_def = nonrec.definition.expect("non-recursive definition");
        assert_eq!(
            nonrec_def.line, 1,
            "non-recursive let RHS should resolve to prior x, not line {}",
            nonrec_def.line
        );

        let recursive = find_definition_by_position(&file, 7, 2, None, "ocaml")
            .expect("recursive rhs use should resolve");
        assert_eq!(recursive.symbol.name, "y");
        let recursive_def = recursive.definition.expect("recursive definition");
        assert_eq!(
            recursive_def.line, 6,
            "let rec RHS should keep resolving to the recursive binding"
        );
    }

    #[test]
    fn test_definition_resolves_local_param_csharp() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Foo.cs");
        // Line 1: class Foo {
        // Line 2:   int Add(int a, int b) {
        // Line 3:     return a + b;
        // Line 4:   }
        // Line 5: }
        fs::write(
            &file,
            "class Foo {\n  int Add(int a, int b) {\n    return a + b;\n  }\n}\n",
        )
        .unwrap();
        assert_resolves_param(&file, 3, 11, "csharp", "a", 2);
    }

    // ----- Broader tests: import-scope and var-decl forms -----

    #[test]
    fn test_definition_resolves_import_alias_java() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Foo.java");
        // Line 1: import java.util.List;
        // Line 2: class Foo {
        // Line 3:   List<String> xs;
        // Line 4: }
        fs::write(
            &file,
            "import java.util.List;\nclass Foo {\n  List<String> xs;\n}\n",
        )
        .unwrap();
        // Cursor on `List` in line 3.
        let result = find_definition_by_position(&file, 3, 2, None, "java")
            .expect("java import resolution should succeed");
        assert_eq!(result.symbol.name, "List");
        let def = result.definition.expect("definition must be Some");
        assert_eq!(def.line, 1, "import is on line 1, got {}", def.line);
    }

    #[test]
    fn test_definition_resolves_local_var_kotlin() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.kt");
        // Line 1: fun main() {
        // Line 2:   val counter = 42
        // Line 3:   println(counter)
        // Line 4: }
        fs::write(
            &file,
            "fun main() {\n  val counter = 42\n  println(counter)\n}\n",
        )
        .unwrap();
        // Cursor on `counter` in line 3.
        let result = find_definition_by_position(&file, 3, 10, None, "kotlin")
            .expect("kotlin val resolution should succeed");
        assert_eq!(result.symbol.name, "counter");
        assert_eq!(result.symbol.kind, SymbolKind::Variable);
        let def = result.definition.expect("definition must be Some");
        assert_eq!(def.line, 2);
    }

    #[test]
    fn test_definition_resolves_param_swift() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.swift");
        // Line 1: func greet(name: String) -> String {
        // Line 2:   return "Hello, " + name
        // Line 3: }
        fs::write(
            &file,
            "func greet(name: String) -> String {\n  return \"Hello, \" + name\n}\n",
        )
        .unwrap();
        // Cursor on `name` at end of line 2.
        assert_resolves_param(&file, 2, 21, "swift", "name", 1);
    }

    #[test]
    fn test_definition_resolves_use_statement_php() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("foo.php");
        // Line 1: <?php
        // Line 2: use App\Models\User;
        // Line 3: function get(): User {
        // Line 4:   return new User();
        // Line 5: }
        fs::write(
            &file,
            "<?php\nuse App\\Models\\User;\nfunction get(): User {\n  return new User();\n}\n",
        )
        .unwrap();
        // Cursor on `User` in line 4.
        let result = find_definition_by_position(&file, 4, 14, None, "php")
            .expect("php use resolution should succeed");
        assert_eq!(result.symbol.name, "User");
        let def = result.definition.expect("definition must be Some");
        assert_eq!(def.line, 2, "use statement on line 2, got {}", def.line);
    }

    #[test]
    fn test_definition_resolves_local_var_csharp() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Foo.cs");
        // Line 1: class Foo {
        // Line 2:   void M() {
        // Line 3:     var counter = 42;
        // Line 4:     System.Console.WriteLine(counter);
        // Line 5:   }
        // Line 6: }
        fs::write(
            &file,
            "class Foo {\n  void M() {\n    var counter = 42;\n    System.Console.WriteLine(counter);\n  }\n}\n",
        )
        .unwrap();
        // Cursor on `counter` in line 4.
        let result = find_definition_by_position(&file, 4, 29, None, "csharp")
            .expect("csharp var resolution should succeed");
        assert_eq!(result.symbol.name, "counter");
        assert_eq!(result.symbol.kind, SymbolKind::Variable);
        let def = result.definition.expect("definition must be Some");
        assert_eq!(def.line, 3);
    }

    // =========================================================================
    // C2 (v0.5.0 AUDIT-FIX): go-to-definition for class fields/properties
    // (kotlin val/var, scala), Solidity contract state variables, and
    // correct handling of stdlib/builtin member access (luau string.find
    // must NOT resolve to a bogus user symbol).
    // =========================================================================

    /// Kotlin: a usage of a class-level `private val` property must resolve
    /// to that property's declaration — not error "not found in scope".
    /// Mirrors the live Semaphore.kt `_availablePermits` gap.
    #[test]
    fn test_definition_resolves_class_property_kotlin() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Sem.kt");
        // Line 1: class Sem {
        // Line 2:   private val _permits = atomic(0)
        // Line 3:   fun acquire(): Boolean {
        // Line 4:     val p = _permits.value
        // Line 5:     return p > 0
        // Line 6:   }
        // Line 7: }
        fs::write(
            &file,
            "class Sem {\n  private val _permits = atomic(0)\n  fun acquire(): Boolean {\n    val p = _permits.value\n    return p > 0\n  }\n}\n",
        )
        .unwrap();
        // Cursor on `_permits` in line 4 (the usage). Column 12 lands on `_`.
        let result = find_definition_by_position(&file, 4, 12, None, "kotlin")
            .expect("kotlin private property usage should resolve to its declaration");
        assert_eq!(result.symbol.name, "_permits");
        let def = result.definition.expect("definition must be Some");
        assert_eq!(
            def.line, 2,
            "private val _permits declared on line 2, got {}",
            def.line
        );
    }

    /// Scala: a usage of a class-level `private[this] val` field must
    /// resolve to that field's declaration.
    #[test]
    fn test_definition_resolves_class_field_scala() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Fiber.scala");
        // Line 1: class Fiber {
        // Line 2:   private[this] val objectState = newStack()
        // Line 3:   def run(): Int = {
        // Line 4:     val x = objectState
        // Line 5:     0
        // Line 6:   }
        // Line 7: }
        fs::write(
            &file,
            "class Fiber {\n  private[this] val objectState = newStack()\n  def run(): Int = {\n    val x = objectState\n    0\n  }\n}\n",
        )
        .unwrap();
        // Cursor on `objectState` in line 4 (usage). `    val x = ` is 12
        // bytes, so column 12 lands on `o`.
        let result = find_definition_by_position(&file, 4, 12, None, "scala")
            .expect("scala class field usage should resolve to its declaration");
        assert_eq!(result.symbol.name, "objectState");
        let def = result.definition.expect("definition must be Some");
        assert_eq!(
            def.line, 2,
            "val objectState declared on line 2, got {}",
            def.line
        );
    }

    /// Solidity: a usage of a contract STATE VARIABLE (a `mapping`) must
    /// resolve to the state-variable declaration in the SAME file — not a
    /// same-named declaration in another file. Mirrors the live solmate
    /// ERC20.sol `balanceOf` gap (was wrongly resolving to ERC721.sol).
    #[test]
    fn test_definition_resolves_state_variable_solidity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Token.sol");
        // Line 1: contract Token {
        // Line 2:   mapping(address => uint256) public balanceOf;
        // Line 3:
        // Line 4:   function burn(address from, uint256 amount) public {
        // Line 5:     balanceOf[from] -= amount;
        // Line 6:   }
        // Line 7: }
        fs::write(
            &file,
            "contract Token {\n  mapping(address => uint256) public balanceOf;\n\n  function burn(address from, uint256 amount) public {\n    balanceOf[from] -= amount;\n  }\n}\n",
        )
        .unwrap();
        // Cursor on `balanceOf` in line 5 (the usage). Column 4 lands on `b`.
        let result = find_definition_by_position(&file, 5, 4, None, "solidity")
            .expect("solidity state variable usage should resolve to its declaration");
        assert_eq!(result.symbol.name, "balanceOf");
        let def = result.definition.expect("definition must be Some");
        assert_eq!(
            def.line, 2,
            "state variable balanceOf declared on line 2, got {}",
            def.line
        );
        // And it must point back to THIS file, not leak to another.
        assert!(
            def.file.ends_with("Token.sol"),
            "state var must resolve in the same file, got {}",
            def.file
        );
    }

    /// Luau: a member access on a standard-library table (`string.find`)
    /// must NOT be resolved to an unrelated user-defined `find` symbol in
    /// some other file. It should be reported as a builtin / external
    /// symbol (no bogus source location). Mirrors the live classes.luau
    /// `string.find` gap (was wrongly resolving to tables.luau:182).
    #[test]
    fn test_definition_stdlib_member_not_bogus_user_symbol_luau() {
        let dir = tempfile::tempdir().unwrap();
        // A decoy user file defining `find` so cross-file resolution has
        // something wrong to latch onto if the stdlib guard is missing.
        let decoy = dir.path().join("decoy.luau");
        fs::write(&decoy, "local function find(a, b)\n  return a\nend\nreturn find\n").unwrap();
        let file = dir.path().join("main.luau");
        // Line 1: local function check(actual, expected)
        // Line 2:   assert(string.find(actual, expected))
        // Line 3: end
        fs::write(
            &file,
            "local function check(actual, expected)\n  assert(string.find(actual, expected))\nend\n",
        )
        .unwrap();
        // Cursor on `string` (base of the stdlib member access) in line 2.
        // `  assert(` is 9 bytes, so column 9 is `s` of `string`.
        let result =
            find_definition_by_position(&file, 2, 9, Some(dir.path()), "luau");
        match result {
            Ok(def) => {
                // Must be flagged as a builtin and carry NO bogus source
                // location pointing at the decoy file.
                assert!(
                    def.symbol.is_builtin,
                    "string.find must be reported as a builtin, got {:?}",
                    def.symbol
                );
                if let Some(loc) = def.definition {
                    assert!(
                        !loc.file.ends_with("decoy.luau"),
                        "stdlib member must NOT resolve to the decoy user symbol, got {}",
                        loc.file
                    );
                }
            }
            Err(_) => {
                // A clean "external/builtin" miss is also acceptable — what
                // is NOT acceptable is a bogus hit on decoy.luau, which the
                // Ok branch guards against.
            }
        }
    }
}
