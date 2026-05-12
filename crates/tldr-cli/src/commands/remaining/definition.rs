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

    /// column number (0-indexed, for position-based lookup)
    pub column: Option<u32>,

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

            // Workspace cross-file resolution (definition-workspace-cross-file-v1):
            // when no explicit --project is supplied AND --workspace is on
            // (the default), auto-detect the project root by walking up
            // ancestors looking for repository / package markers.
            let auto_project: Option<PathBuf> = if self.project.is_none() && self.workspace {
                find_workspace_root(file)
            } else {
                None
            };
            let effective_project = self.project.as_deref().or(auto_project.as_deref());

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

            // Workspace cross-file resolution (definition-workspace-cross-file-v1):
            // auto-detect project root if not explicitly provided.
            let auto_project: Option<PathBuf> = if self.project.is_none() && self.workspace {
                find_workspace_root(file)
            } else {
                None
            };
            let effective_project = self.project.as_deref().or(auto_project.as_deref());

            match find_definition_by_position(
                file,
                line,
                column,
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
    while let Some(node) = current {
        if is_scope_node(node.kind(), language) {
            if let Some(loc) = scan_scope_for_binding(node, source, symbol, language, file) {
                return Ok(Some(DefinitionResult {
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
                }));
            }
        }
        current = node.parent();
    }

    Ok(None)
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
                | "source_file"
        ),
        Language::Scala => matches!(
            kind,
            "function_definition"
                | "function_declaration"
                | "lambda_expression"
                | "block"
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
        Language::Ocaml => scan_ocaml_scope(node, bytes, symbol, file),
        Language::CSharp => scan_csharp_scope(node, bytes, symbol, file),
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
        if let Some(loc) = ocaml_walk_for_binding(child, src, symbol, file) {
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
) -> Option<(SymbolKind, Location)> {
    match node.kind() {
        "fun_expression" | "function_expression" => None,
        "let_binding" | "value_definition" => {
            // Match the bound name (first value_name / value_pattern that is a plain identifier).
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(child.kind(), "value_name" | "value_pattern") {
                    if let Some(name) = ocaml_find_first_ident(child, src, symbol) {
                        return Some(make_var_location(name, file));
                    }
                    // Stop after first — subsequent names are parameters.
                    break;
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(loc) = ocaml_walk_for_binding(child, src, symbol, file) {
                    return Some(loc);
                }
            }
            None
        }
    }
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
    // Start from min(col, line.len()-1); walk back to identifier start.
    let mut start = col.min(bytes.len().saturating_sub(1));
    // If we landed on a non-ident byte, scan one to the left first.
    if !is_ident(bytes[start]) && start > 0 && is_ident(bytes[start - 1]) {
        start -= 1;
    }
    if !is_ident(bytes[start]) {
        return String::new();
    }
    while start > 0 && is_ident(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = start;
    while end < bytes.len() && is_ident(bytes[end]) {
        end += 1;
    }
    let slice = &line[start..end];
    clamp_symbol(slice)
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
    for f in funcs {
        if f.name == symbol {
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
            let col = locate_symbol_column(file, f.line, symbol);
            let loc = match col {
                Some(c) => Location::with_column(file.display().to_string(), f.line, c),
                None => Location::new(file.display().to_string(), f.line),
            };
            return Some((kind, loc));
        }
    }
    for c in classes {
        if c.name == symbol {
            let col = locate_symbol_column(file, c.line, symbol);
            let loc = match col {
                Some(col_v) => {
                    Location::with_column(file.display().to_string(), c.line, col_v)
                }
                None => Location::new(file.display().to_string(), c.line),
            };
            return Some((SymbolKind::Class, loc));
        }
    }
    None
}

/// Locate the 1-indexed column of `symbol` on line `line` (1-indexed) of
/// `file`. Returns `None` if the file cannot be read or the symbol does
/// not appear on that line. Used to populate the `column` field of
/// `definition` results when the underlying `FuncDef`/`ClassDef` only
/// carries the line.
fn locate_symbol_column(file: &Path, line: u32, symbol: &str) -> Option<u32> {
    let content = std::fs::read_to_string(file).ok()?;
    let target_line = line.saturating_sub(1) as usize;
    let line_text = content.lines().nth(target_line)?;
    let byte_offset = line_text.find(symbol)?;
    // Convert byte offset to 1-indexed column (UTF-8 aware: count chars
    // up to byte_offset).
    let col_chars = line_text[..byte_offset].chars().count();
    Some(col_chars as u32 + 1)
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
    let extensions = language.extensions();
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
    let start = if file.is_dir() {
        file.to_path_buf()
    } else {
        file.parent()?.to_path_buf()
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
}
