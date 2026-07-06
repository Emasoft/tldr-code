//! Reference Finding Core Types and Functions
//!
//! This module provides reference finding for the `references` CLI command.
//!
//! # Type Overview
//!
//! - [`ReferencesReport`]: Complete reference finding report
//! - [`Reference`]: A single reference to a symbol
//! - [`Definition`]: Location where symbol is defined
//! - [`DefinitionKind`]: Kind of definition (function, class, variable, etc.)
//! - [`ReferenceKind`]: Kind of reference (call, read, write, import, type)
//! - [`SearchScope`]: Search scope for reference finding
//! - [`ReferenceStats`]: Search statistics
//! - [`ReferencesOptions`]: Configuration for reference finding
//! - [`TextCandidate`]: Candidate match from text search (Phase 9)
//!
//! # Risk Mitigations
//!
//! - S7-R17: Reference context truncation - limit context to 200 chars
//! - S7-R38: Line numbers - ensure 1-indexed throughout
//! - S7-R9: Memory usage - read one file at a time, don't load all (Phase 9)
//! - S7-R10: Regex compilation per file - compile once, reuse (Phase 9)
//! - S7-R4: Unicode position mapping - use byte offsets consistently (Phase 9, 10)
//! - S7-R5: Method call classification - check grandparent for call expression (Phase 10)
//! - S7-R6: Multi-match same line - verify each match independently (Phase 10)
//! - S7-R12: Re-parsing files - group candidates by file, parse once per file (Phase 10)
//! - S7-R22: f-string interpolation - handle formatted_string AST node (Phase 10)
//! - S7-R48: String matches - check AST node type is identifier, not string_literal (Phase 10)
//!
//! # References
//!
//! - Spec: session7-spec.md section 2.2 (Type Definitions)
//! - Phased plan: session7-phased-plan.yaml Phase 8, 9, 10

use crate::walker::walk_project;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tree_sitter::Node;

use crate::ast::parser::parse_file;
use crate::security::ast_utils;
use crate::types::Language;
use crate::TldrResult;

// =============================================================================
// Core Types
// =============================================================================

/// Maximum context line length before truncation (S7-R17)
const MAX_CONTEXT_LENGTH: usize = 200;

/// Complete reference finding report
///
/// Contains all information about references to a symbol including
/// the definition location, all references found, and search statistics.
///
/// med-low-schema-cleanup-v1 (N6): mirrors the `calls` schema's
/// truncation triplet — `total_references` (full pre-truncation count),
/// `shown_references` (length of `references` after limiting), and
/// `truncated` (whether limiting actually dropped any). Pre-fix the
/// `references` Vec was silently capped at `--limit` and there was no
/// way for downstream tooling to detect that more references existed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferencesReport {
    /// Symbol that was searched for
    pub symbol: String,

    /// Definition location (legacy/back-compat: first definition only).
    ///
    /// M3 detection-accuracy-v1 BUG-20: this field is retained for backward
    /// compatibility but is now a derived view of the first entry in
    /// `definitions`. Prefer `definitions` for new consumers — see the
    /// `definitions_array_and_text_header_plural` test in
    /// `crates/tldr-cli/tests/detection_accuracy_v1.rs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<Definition>,

    /// All definitions found for the symbol (canonical multi-definition shape).
    ///
    /// Always serialized (even when empty) so downstream tools can reliably
    /// iterate. Pre-M3 only `definition` (singular `Option<Definition>`) was
    /// emitted, which silently truncated cases where a symbol had multiple
    /// definitions across files (e.g. flask `_make_timedelta`). When this Vec
    /// has more than one entry the text formatter prints "Definitions:" in the
    /// plural and lists all entries. See M3 detection-accuracy-v1 BUG-20.
    #[serde(default)]
    pub definitions: Vec<Definition>,

    /// All references found (post-truncation; may be a prefix of the
    /// full set if `truncated == true`).
    pub references: Vec<Reference>,

    /// Total number of references found before any limit was applied.
    pub total_references: usize,

    /// Number of references actually returned in `references` after
    /// applying the caller's limit. Equals `references.len()`.
    #[serde(default)]
    pub shown_references: usize,

    /// Whether the `references` Vec was truncated by the caller's
    /// `--limit`. When `true`, `total_references > shown_references`.
    /// Omitted from JSON when `false` to keep the default-shape
    /// existing snapshot tests stable.
    #[serde(default, skip_serializing_if = "is_false_bool")]
    pub truncated: bool,

    /// Search scope used
    pub search_scope: SearchScope,

    /// Search statistics
    pub stats: ReferenceStats,
}

/// Helper for `skip_serializing_if` on the boolean `truncated` field.
fn is_false_bool(v: &bool) -> bool {
    !*v
}

impl ReferencesReport {
    /// Create a new empty report for a symbol
    pub fn new(symbol: String) -> Self {
        Self {
            symbol,
            ..Default::default()
        }
    }

    /// Create a report with no matches found
    pub fn no_matches(symbol: String, scope: SearchScope, stats: ReferenceStats) -> Self {
        Self {
            symbol,
            definition: None,
            definitions: Vec::new(),
            references: Vec::new(),
            total_references: 0,
            shown_references: 0,
            truncated: false,
            search_scope: scope,
            stats,
        }
    }
}

/// Location where symbol is defined
///
/// Contains file path, position (1-indexed), kind, and optional signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Definition {
    /// File containing the definition
    pub file: PathBuf,

    /// Line number (1-indexed, S7-R38)
    pub line: usize,

    /// Column number (1-indexed, S7-R38)
    pub column: usize,

    /// Kind of definition
    pub kind: DefinitionKind,

    /// Function/class signature if applicable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Definition {
    /// Create a new definition with minimal information
    pub fn new(file: PathBuf, line: usize, column: usize, kind: DefinitionKind) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            signature: None,
        }
    }

    /// Create a definition with signature
    pub fn with_signature(
        file: PathBuf,
        line: usize,
        column: usize,
        kind: DefinitionKind,
        signature: String,
    ) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            signature: Some(signature),
        }
    }
}

/// Kind of definition
///
/// Categorizes what type of construct the definition is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefinitionKind {
    /// Function definition
    Function,

    /// Class definition
    Class,

    /// Struct definition (a value-type aggregate, e.g. Swift / Rust `struct`).
    ///
    /// CF2-S19: Swift folds `struct`/`enum`/`actor`/`class` into one
    /// `class_declaration` node distinguished only by the leading keyword
    /// token. `references` must classify a `struct X {}` definition as
    /// `"struct"` (not the conservative `"class"`), mirroring the keyword the
    /// `structure`/`extract` producers already read in `entity::classify_node`.
    Struct,

    /// Enum definition (e.g. Swift / Rust `enum`).
    ///
    /// CF2-S19: see [`DefinitionKind::Struct`].
    Enum,

    /// Actor definition (Swift concurrency `actor`).
    ///
    /// CF2-S19: see [`DefinitionKind::Struct`].
    Actor,

    /// Variable definition
    Variable,

    /// Constant definition
    Constant,

    /// Type alias or type definition
    Type,

    /// Module definition
    Module,

    /// Method definition (function in a class)
    Method,

    /// Property or field definition
    Property,

    /// Unknown or other kind
    #[default]
    Other,
}

impl DefinitionKind {
    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            DefinitionKind::Function => "function",
            DefinitionKind::Class => "class",
            DefinitionKind::Struct => "struct",
            DefinitionKind::Enum => "enum",
            DefinitionKind::Actor => "actor",
            DefinitionKind::Variable => "variable",
            DefinitionKind::Constant => "constant",
            DefinitionKind::Type => "type",
            DefinitionKind::Module => "module",
            DefinitionKind::Method => "method",
            DefinitionKind::Property => "property",
            DefinitionKind::Other => "other",
        }
    }
}

impl std::fmt::Display for DefinitionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single reference to the symbol
///
/// Contains file path, position (1-indexed), kind, and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// File containing the reference
    pub file: PathBuf,

    /// Line number (1-indexed, S7-R38)
    pub line: usize,

    /// Column number (1-indexed, S7-R38)
    pub column: usize,

    /// Kind of reference
    pub kind: ReferenceKind,

    /// Line of code containing the reference (context)
    /// Truncated to MAX_CONTEXT_LENGTH (S7-R17)
    pub context: String,

    /// Confidence of this being a true reference (0.0 - 1.0)
    /// 1.0 = verified by AST, lower = text match only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// End column for highlighting (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
}

impl Reference {
    /// Create a new reference with minimal information
    pub fn new(
        file: PathBuf,
        line: usize,
        column: usize,
        kind: ReferenceKind,
        context: String,
    ) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            context: truncate_context(context),
            confidence: None,
            end_column: None,
        }
    }

    /// Create a reference with full information
    pub fn with_details(
        file: PathBuf,
        line: usize,
        column: usize,
        end_column: usize,
        kind: ReferenceKind,
        context: String,
        confidence: f64,
    ) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            context: truncate_context(context),
            confidence: Some(confidence),
            end_column: Some(end_column),
        }
    }

    /// Create a reference verified by AST (confidence = 1.0)
    pub fn verified(
        file: PathBuf,
        line: usize,
        column: usize,
        kind: ReferenceKind,
        context: String,
    ) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            context: truncate_context(context),
            confidence: Some(1.0),
            end_column: None,
        }
    }
}

/// Truncate context to MAX_CONTEXT_LENGTH (S7-R17)
fn truncate_context(context: String) -> String {
    if context.len() > MAX_CONTEXT_LENGTH {
        let truncated: String = context.chars().take(MAX_CONTEXT_LENGTH - 3).collect();
        format!("{}...", truncated)
    } else {
        context
    }
}

/// Kind of reference
///
/// Categorizes how the symbol is being used at this reference site.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceKind {
    /// Function/method invocation
    Call,

    /// Variable read
    Read,

    /// Variable assignment/write
    Write,

    /// Import statement
    Import,

    /// Type annotation
    Type,

    /// Definition site itself
    Definition,

    /// Unknown or other kind
    #[default]
    Other,
}

impl ReferenceKind {
    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ReferenceKind::Call => "call",
            ReferenceKind::Read => "read",
            ReferenceKind::Write => "write",
            ReferenceKind::Import => "import",
            ReferenceKind::Type => "type",
            ReferenceKind::Definition => "definition",
            ReferenceKind::Other => "other",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "call" => Some(ReferenceKind::Call),
            "read" => Some(ReferenceKind::Read),
            "write" => Some(ReferenceKind::Write),
            "import" => Some(ReferenceKind::Import),
            "type" => Some(ReferenceKind::Type),
            "definition" => Some(ReferenceKind::Definition),
            "other" => Some(ReferenceKind::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReferenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Search scope for reference finding
///
/// Controls how much of the workspace is searched for references.
/// Used for optimization based on symbol visibility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum SearchScope {
    /// Search only within the current function (local variables)
    Local,

    /// Search only within the current file (private items)
    File,

    /// Search entire workspace (public items)
    #[default]
    Workspace,
}

impl SearchScope {
    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SearchScope::Local => "local",
            SearchScope::File => "file",
            SearchScope::Workspace => "workspace",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "local" => Some(SearchScope::Local),
            "file" => Some(SearchScope::File),
            "workspace" => Some(SearchScope::Workspace),
            _ => None,
        }
    }
}

impl std::fmt::Display for SearchScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Search statistics
///
/// Provides information about the search process for debugging
/// and performance analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReferenceStats {
    /// Number of files searched
    pub files_searched: usize,

    /// Number of text match candidates found (before AST verification)
    pub candidates_found: usize,

    /// Number of verified references (after AST pruning)
    pub verified_references: usize,

    /// Search time in milliseconds
    pub search_time_ms: u64,
}

impl ReferenceStats {
    /// Create stats with counts
    pub fn new(files_searched: usize, candidates_found: usize, verified_references: usize) -> Self {
        Self {
            files_searched,
            candidates_found,
            verified_references,
            search_time_ms: 0,
        }
    }

    /// Set search time
    pub fn with_time(mut self, time_ms: u64) -> Self {
        self.search_time_ms = time_ms;
        self
    }
}

/// Options for reference finding
///
/// Configuration options that control the behavior of reference finding.
#[derive(Debug, Clone, Default)]
pub struct ReferencesOptions {
    /// Include the definition in results
    pub include_definition: bool,

    /// Filter by reference kinds (None = all kinds)
    pub kinds: Option<Vec<ReferenceKind>>,

    /// Search scope (None = infer from symbol)
    pub scope: SearchScope,

    /// Language to analyze (None = auto-detect)
    pub language: Option<String>,

    /// Maximum results to return
    pub limit: Option<usize>,

    /// File containing the symbol definition (helps scope optimization)
    pub definition_file: Option<PathBuf>,

    /// Number of context lines to include
    pub context_lines: usize,
}

impl ReferencesOptions {
    /// Create new default options
    pub fn new() -> Self {
        Self::default()
    }

    /// Include definition in results
    pub fn with_definition(mut self) -> Self {
        self.include_definition = true;
        self
    }

    /// Filter by specific reference kinds
    pub fn with_kinds(mut self, kinds: Vec<ReferenceKind>) -> Self {
        self.kinds = Some(kinds);
        self
    }

    /// Set search scope
    pub fn with_scope(mut self, scope: SearchScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set language
    pub fn with_language(mut self, language: String) -> Self {
        self.language = Some(language);
        self
    }

    /// Set maximum results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set definition file for scope optimization
    pub fn with_definition_file(mut self, file: PathBuf) -> Self {
        self.definition_file = Some(file);
        self
    }

    /// Set context lines
    pub fn with_context_lines(mut self, lines: usize) -> Self {
        self.context_lines = lines;
        self
    }
}

// =============================================================================
// Phase 9: Text Search for Reference Candidates
// =============================================================================

/// Candidate match from text search (before AST verification)
///
/// These are potential references found by text search that need
/// to be verified using AST parsing in Phase 10.
#[derive(Debug, Clone)]
pub struct TextCandidate {
    /// File containing the candidate match
    pub file: PathBuf,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// End column (1-indexed)
    pub end_column: usize,
    /// The full line text containing the match
    pub line_text: String,
}

impl TextCandidate {
    /// Create a new text candidate
    pub fn new(
        file: PathBuf,
        line: usize,
        column: usize,
        end_column: usize,
        line_text: String,
    ) -> Self {
        Self {
            file,
            line,
            column,
            end_column,
            line_text,
        }
    }
}

/// Find all text occurrences of a symbol (fast, overapproximating)
///
/// This is the first step in the rust-analyzer pattern:
/// "text search to find superset, then prune with semantic resolve"
///
/// # Arguments
///
/// * `symbol` - The symbol name to search for
/// * `root` - The root directory to search in
/// * `language` - Optional language filter (e.g., "python", "typescript")
///
/// # Returns
///
/// A vector of TextCandidate structs representing potential matches.
/// These need to be verified using AST parsing in Phase 10.
///
/// # Risk Mitigations
///
/// - S7-R9: Memory usage - read one file at a time, don't load all
/// - S7-R10: Regex compilation per file - compile once, reuse
pub fn find_text_candidates(
    symbol: &str,
    root: &Path,
    language: Option<&str>,
) -> TldrResult<Vec<TextCandidate>> {
    let mut candidates = Vec::new();

    // Build regex with word boundaries to avoid partial matches
    // e.g., searching for "get" shouldn't match "forget"
    // S7-R10: Compile regex once, reuse for all files
    let pattern = format!(r"\b{}\b", regex::escape(symbol));
    let re = Regex::new(&pattern)?;

    // Walk directory, filter by language extension
    // S7-R9: Files are read one at a time to bound memory usage
    // Skips node_modules, target, dist, hidden dirs via the shared walker
    for entry in walk_project(root)
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| is_source_file(e.path(), language))
    {
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue, // Skip files we can't read
        };

        for (line_num, line) in content.lines().enumerate() {
            // Skip comment lines (basic heuristic for common cases)
            if is_comment_line(line, language) {
                continue;
            }

            for mat in re.find_iter(line) {
                candidates.push(TextCandidate {
                    file: entry.path().to_path_buf(),
                    line: line_num + 1,        // 1-indexed (S7-R38)
                    column: mat.start() + 1,   // 1-indexed (S7-R38)
                    end_column: mat.end() + 1, // 1-indexed
                    line_text: line.to_string(),
                });
            }
        }
    }

    Ok(candidates)
}

/// Check if file is a source file for the given language.
///
/// Uses `Language::from_path` to support all 18 languages (Python, TypeScript,
/// JavaScript, Go, Rust, Java, C, C++, Ruby, Kotlin, Swift, C#, Scala, PHP,
/// Lua, Luau, Elixir, OCaml).
fn is_source_file(path: &Path, language: Option<&str>) -> bool {
    match Language::from_path(path) {
        Some(detected) => {
            match language {
                None => true, // No filter — accept any supported language
                Some(lang) => {
                    // Check if detected language matches the requested filter
                    let normalized = lang.to_lowercase();
                    match normalized.as_str() {
                        "python" => matches!(detected, Language::Python),
                        "typescript" => matches!(detected, Language::TypeScript),
                        "javascript" => {
                            matches!(detected, Language::JavaScript | Language::TypeScript)
                        }
                        "go" => matches!(detected, Language::Go),
                        "rust" => matches!(detected, Language::Rust),
                        "java" => matches!(detected, Language::Java),
                        "c" => matches!(detected, Language::C),
                        "cpp" => matches!(detected, Language::Cpp),
                        "csharp" => matches!(detected, Language::CSharp),
                        "kotlin" => matches!(detected, Language::Kotlin),
                        "scala" => matches!(detected, Language::Scala),
                        "swift" => matches!(detected, Language::Swift),
                        "php" => matches!(detected, Language::Php),
                        "ruby" => matches!(detected, Language::Ruby),
                        "lua" => matches!(detected, Language::Lua),
                        "luau" => matches!(detected, Language::Luau),
                        "elixir" => matches!(detected, Language::Elixir),
                        "ocaml" => matches!(detected, Language::Ocaml),
                        // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M13).
                        "solidity" => matches!(detected, Language::Solidity),
                        _ => false,
                    }
                }
            }
        }
        None => false, // Not a recognized source file
    }
}

/// Basic check if line is a comment (for filtering obvious false positives)
///
/// This is a heuristic to reduce noise from text search. Full comment
/// detection is done in AST verification (Phase 10).
fn is_comment_line(line: &str, language: Option<&str>) -> bool {
    let trimmed = line.trim();

    match language {
        // Hash-style comments: Python, Ruby, PHP, Elixir
        Some("python") | Some("ruby") | Some("elixir") => trimmed.starts_with('#'),
        // PHP also supports // and /* */
        Some("php") => {
            trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
        }
        // C-style comments: TypeScript, JavaScript, Go, Rust, Java, C, C++, C#, Kotlin, Scala, Swift, Solidity.
        // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M13).
        Some("typescript") | Some("javascript") | Some("go") | Some("rust") | Some("java")
        | Some("c") | Some("cpp") | Some("csharp") | Some("kotlin") | Some("scala")
        | Some("swift") | Some("solidity") => {
            trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
        }
        // Lua / Luau: -- comments
        Some("lua") | Some("luau") => trimmed.starts_with("--"),
        // OCaml: (* comments *)
        Some("ocaml") => trimmed.starts_with("(*"),
        // Default: handle all common comment patterns
        None => {
            trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.starts_with("--")
                || trimmed.starts_with("(*")
        }
        _ => false,
    }
}

/// Count source files in a directory for statistics
fn count_source_files(root: &Path, language: Option<&str>) -> usize {
    walk_project(root)
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| is_source_file(e.path(), language))
        .count()
}

// =============================================================================
// Phase 10: AST Verification and Reference Kind Classification
// =============================================================================

/// Verified reference from AST analysis
///
/// Contains the reference kind determined by AST context and confidence score.
#[derive(Debug, Clone)]
pub struct VerifiedReference {
    /// The determined reference kind
    pub kind: ReferenceKind,
    /// Confidence score (1.0 = fully verified by AST)
    pub confidence: f64,
    /// Whether this is a valid reference (not in string/comment)
    pub is_valid: bool,
}

/// Verify text candidates using AST parsing
///
/// Groups candidates by file, parses each file once, and verifies each
/// candidate against the AST. Returns only valid references with
/// correct kind classification.
///
/// # Risk Mitigations
///
/// - S7-R12: Re-parsing files - group candidates by file, parse once per file
/// - S7-R4: Unicode position mapping - use byte offsets consistently
/// - S7-R48: String matches - check AST node type is identifier, not string_literal
pub fn verify_candidates_with_ast(
    candidates: &[TextCandidate],
    symbol: &str,
    _language_str: Option<&str>,
) -> Vec<(TextCandidate, VerifiedReference)> {
    let mut verified = Vec::new();

    // S7-R12: Group candidates by file to parse each file only once
    let mut by_file: HashMap<PathBuf, Vec<&TextCandidate>> = HashMap::new();
    for candidate in candidates {
        by_file
            .entry(candidate.file.clone())
            .or_default()
            .push(candidate);
    }

    // Process each file
    for (file_path, file_candidates) in by_file {
        // Try to parse the file
        let parsed = match parse_file(&file_path) {
            Ok(p) => p,
            Err(_) => {
                // Parse failed, include candidates as unverified
                for candidate in file_candidates {
                    verified.push((
                        candidate.clone(),
                        VerifiedReference {
                            kind: ReferenceKind::Other,
                            confidence: 0.5, // Text match only
                            is_valid: true,  // Assume valid if we can't verify
                        },
                    ));
                }
                continue;
            }
        };

        let (tree, source, lang) = parsed;
        let source_bytes = source.as_bytes();

        // Verify each candidate in this file
        for candidate in file_candidates {
            if let Some(verified_ref) =
                verify_single_candidate(candidate, symbol, &tree, source_bytes, lang)
            {
                if verified_ref.is_valid {
                    verified.push((candidate.clone(), verified_ref));
                }
                // If not valid (e.g., in string), skip this candidate
            }
        }
    }

    verified
}

/// Verify a single candidate against the AST
///
/// Returns Some(VerifiedReference) if the candidate can be verified,
/// None if verification fails (should not happen normally).
fn verify_single_candidate(
    candidate: &TextCandidate,
    symbol: &str,
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> Option<VerifiedReference> {
    // Convert 1-indexed line/column to tree-sitter Point (0-indexed)
    let point = tree_sitter::Point::new(candidate.line - 1, candidate.column - 1);

    // Find the smallest node containing this position
    let node = tree.root_node().descendant_for_point_range(point, point)?;

    // Get the text of this node
    let node_text = node.utf8_text(source).ok()?;

    // S7-R48: Check if the node text matches the symbol exactly
    // This filters out partial matches
    if node_text != symbol {
        // The node text doesn't match - might be part of a larger identifier
        // or the position is off. Try to find exact match nearby.
        return find_exact_match_node(&node, symbol, source, language);
    }

    // Check if this node is in an invalid context (string, comment)
    if is_in_invalid_context(&node, language) {
        return Some(VerifiedReference {
            kind: ReferenceKind::Other,
            confidence: 1.0,
            is_valid: false, // In string/comment, not a real reference
        });
    }

    // RC7 (v0.5.0 R7 cluster[10], #146): a bare-name `references` query
    // targets the function/method/const namespace, not a PHP `$variable`
    // (which lives in a distinct sigil-prefixed namespace). A `$width`
    // occurrence must NOT be reported as a reference to the method `width`.
    if php_node_is_variable_occurrence(&node, language) {
        return Some(VerifiedReference {
            kind: ReferenceKind::Other,
            confidence: 1.0,
            is_valid: false,
        });
    }

    // Classify the reference kind based on AST context
    let kind = classify_reference_kind(&node, source, language);

    Some(VerifiedReference {
        kind,
        confidence: 1.0, // Fully verified by AST
        is_valid: true,
    })
}

/// RC7 (v0.5.0 R7 cluster[10], #146): true when `node` is the identifier of a
/// PHP `$variable` occurrence (its immediate parent is `variable_name`).
///
/// In tree-sitter-php a `$width` reads as `variable_name($ , name "width")`,
/// whereas a method `width()` reads as a `name` whose parent is a
/// call/declaration node — never `variable_name`. PHP variables and
/// functions/methods/constants occupy separate namespaces (the `$` sigil is
/// load-bearing), so a bare-name reference query (which has no sigil) must
/// exclude variable occurrences. Returns false for every non-PHP language.
fn php_node_is_variable_occurrence(node: &Node, language: Language) -> bool {
    if language != Language::Php {
        return false;
    }
    node.parent()
        .map(|p| p.kind() == "variable_name")
        .unwrap_or(false)
}

/// Try to find the exact match node when position lookup returns a parent node
fn find_exact_match_node(
    node: &Node,
    symbol: &str,
    source: &[u8],
    language: Language,
) -> Option<VerifiedReference> {
    // Check this node and its descendants for exact match
    let mut cursor = node.walk();

    // Check children
    for child in node.children(&mut cursor) {
        if let Ok(text) = child.utf8_text(source) {
            if text == symbol {
                if is_in_invalid_context(&child, language) {
                    return Some(VerifiedReference {
                        kind: ReferenceKind::Other,
                        confidence: 1.0,
                        is_valid: false,
                    });
                }
                // RC7 (#146): exclude PHP `$variable` occurrences from a
                // bare-name (function/method/const) reference query.
                if php_node_is_variable_occurrence(&child, language) {
                    return Some(VerifiedReference {
                        kind: ReferenceKind::Other,
                        confidence: 1.0,
                        is_valid: false,
                    });
                }
                let kind = classify_reference_kind(&child, source, language);
                return Some(VerifiedReference {
                    kind,
                    confidence: 1.0,
                    is_valid: true,
                });
            }
        }
    }

    // fix-PW1-B7-refs-stringFP: no exact identifier child matched, which means
    // the candidate position resolved to a node spanning non-code text — almost
    // always the symbol word appearing inside a string literal / docstring /
    // comment (e.g. `string_content`, `encapsed_string`). Such occurrences are
    // NOT references; emitting them as `confidence: 0.5, is_valid: true` inflated
    // counts by 31-49% on real corpora. Gate the textual fallback on the node
    // not being in an invalid (string/comment) context.
    if is_in_invalid_context(node, language) {
        return Some(VerifiedReference {
            kind: ReferenceKind::Other,
            confidence: 1.0,
            is_valid: false,
        });
    }

    // If no exact match found, return unverified
    Some(VerifiedReference {
        kind: ReferenceKind::Other,
        confidence: 0.5,
        is_valid: true,
    })
}

/// Check if a node is in an invalid context (string literal, comment)
///
/// # Risk Mitigations
///
/// - S7-R48: String matches - check AST node type is identifier, not string_literal
/// - S7-R22: f-string interpolation - handle formatted_string AST node
fn is_in_invalid_context(node: &Node, language: Language) -> bool {
    // Check the node type itself
    let node_kind = node.kind();

    // Common string/comment node types across languages
    let invalid_self_kinds = [
        "string",
        "string_literal",
        "string_content",
        "template_string",
        "raw_string_literal",
        "comment",
        "line_comment",
        "block_comment",
        "heredoc_content",
    ];

    if invalid_self_kinds.contains(&node_kind) {
        return true;
    }

    // fix-PW1-B7-refs-stringFP: the fixed list above misses grammar-specific
    // string/comment leaf kinds (PHP `encapsed_string`, Ruby/PHP heredoc bodies,
    // `*_string_content`, doc-comment variants, …). When a candidate position
    // resolves directly to such a node the symbol is plain string/comment text,
    // not a reference. This mirrors the AST-node-kind classification already
    // used for ancestors in the generic branch below — it inspects tree-sitter
    // node *kinds*, never the source text.
    if node_kind.contains("string") || node_kind.contains("comment") || node_kind.contains("heredoc")
    {
        return true;
    }

    // Walk up the tree to check ancestors
    let mut current = node.parent();
    while let Some(ancestor) = current {
        let kind = ancestor.kind();

        match language {
            Language::Python => {
                // Python string types
                if matches!(
                    kind,
                    "string" | "string_content" | "concatenated_string" | "comment"
                ) {
                    return true;
                }
                // S7-R22: f-string interpolation is OK - the code inside is real
                // formatted_string contains format_expression which should be verified
                if kind == "string" {
                    // Check if we're NOT inside a format_expression
                    if !is_inside_format_expression(node) {
                        return true;
                    }
                }
            }
            Language::TypeScript | Language::JavaScript => {
                if matches!(
                    kind,
                    "string" | "template_string" | "string_fragment" | "comment"
                ) {
                    // Template literals with ${} expressions are OK
                    if kind == "template_string" && has_template_substitution(&ancestor) {
                        // Check if we're inside the substitution
                        if is_inside_template_substitution(node) {
                            return false;
                        }
                    }
                    return true;
                }
            }
            Language::Go => {
                if matches!(
                    kind,
                    "raw_string_literal" | "interpreted_string_literal" | "comment"
                ) {
                    return true;
                }
            }
            Language::Rust => {
                if matches!(
                    kind,
                    "string_literal" | "raw_string_literal" | "line_comment" | "block_comment"
                ) {
                    return true;
                }
            }
            _ => {
                // Generic check for other languages
                if kind.contains("string") || kind.contains("comment") {
                    return true;
                }
            }
        }

        current = ancestor.parent();
    }

    false
}

/// Check if node is inside a Python f-string format expression
fn is_inside_format_expression(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "interpolation" || ancestor.kind() == "format_expression" {
            return true;
        }
        if ancestor.kind() == "string" || ancestor.kind() == "concatenated_string" {
            return false; // Hit string boundary without finding format_expression
        }
        current = ancestor.parent();
    }
    false
}

/// Check if a template string has substitutions
fn has_template_substitution(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "template_substitution" {
            return true;
        }
    }
    false
}

/// Check if node is inside a template substitution (${...})
fn is_inside_template_substitution(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "template_substitution" {
            return true;
        }
        if ancestor.kind() == "template_string" {
            return false;
        }
        current = ancestor.parent();
    }
    false
}

/// Classify reference kind based on AST context
///
/// Examines the parent and grandparent nodes to determine how the symbol
/// is being used.
///
/// # Risk Mitigations
///
/// - S7-R5: Method call classification - check grandparent for call expression
pub fn classify_reference_kind(node: &Node, source: &[u8], language: Language) -> ReferenceKind {
    let parent = match node.parent() {
        Some(p) => p,
        None => return ReferenceKind::Other,
    };

    match language {
        Language::Python => classify_python_reference(node, &parent, source),
        Language::TypeScript | Language::JavaScript => {
            classify_typescript_reference(node, &parent, source)
        }
        Language::Go => classify_go_reference(node, &parent, source),
        Language::Rust => classify_rust_reference(node, &parent, source),
        Language::Java => classify_java_reference(node, &parent, source),
        Language::C => classify_c_reference(node, &parent, source),
        Language::Cpp => classify_cpp_reference(node, &parent, source),
        Language::CSharp => classify_csharp_reference(node, &parent, source),
        Language::Kotlin => classify_kotlin_reference(node, &parent, source),
        Language::Scala => classify_scala_reference(node, &parent, source),
        Language::Swift => classify_swift_reference(node, &parent, source),
        Language::Php => classify_php_reference(node, &parent, source),
        Language::Ruby => classify_ruby_reference(node, &parent, source),
        Language::Lua => classify_lua_reference(node, &parent, source),
        Language::Luau => classify_luau_reference(node, &parent, source),
        Language::Elixir => classify_elixir_reference(node, &parent, source),
        Language::Ocaml => classify_ocaml_reference(node, &parent, source),
        // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M13):
        // classify Solidity references. The grammar uses `call_expression`
        // with a `function` field whose subtree is either a bare
        // identifier (direct call), a `member_expression` (qualified
        // call like `this.foo()` / `super.foo()` / `receiver.foo()`),
        // or a more complex form. Definition / assignment / type /
        // import shapes are handled below.
        Language::Solidity => classify_solidity_reference(node, &parent, source),
    }
}

/// Classify a Solidity reference's [`ReferenceKind`].
///
/// Grammar reference (tree-sitter-solidity 1.2.x):
///   - Expressions are wrapped in an `expression` super-node (a union
///     node whose single named child is the actual operand). The
///     `function` field of a `call_expression` is of type `expression`
///     and wraps either an `identifier`, a `member_expression`, etc.
///     This means the immediate AST parent of `foo` in `foo(args)` is
///     an `expression`, NOT the `call_expression` — we therefore walk
///     UP through `expression` wrappers when deciding the semantic
///     parent of the identifier.
///   - `call_expression` → Call (when we are the function expression).
///   - `member_expression`'s `property` segment is a Call iff the
///     enclosing `call_expression`'s `function` is the member_expression
///     itself; otherwise it is a Read.
///   - `assignment_expression` / `augmented_assignment_expression` left
///     side → Write.
///   - `function_definition` / `modifier_definition` /
///     `contract_declaration` / etc. `name` slot → Definition.
///   - `user_defined_type` / `type_name` → Type.
///   - `import_directive` / `import_clause` → Import.
fn classify_solidity_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    // Step 1: walk up through `expression` wrappers — the union node
    // shape means the *semantic* parent of `foo` in `foo(args)` is the
    // `call_expression`, not the wrapper `expression`.
    let (effective_parent, child_through_wrappers) =
        solidity_skip_expression_wrappers(node, parent);

    let parent_kind = effective_parent.kind();

    match parent_kind {
        // Direct call: foo(args). The `function` field is an
        // `expression` wrapping our identifier (or wrapping a
        // member_expression). Check by id.
        "call_expression" => {
            if let Some(func) = effective_parent.child_by_field_name("function") {
                if func.id() == child_through_wrappers.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Qualified call: receiver.method(args).
        "member_expression" => {
            // We are either the `object` (receiver — Read) or the
            // `property` (the method/field name).
            let property = effective_parent.child_by_field_name("property");
            let is_property = property.map(|p| p.id() == node.id()).unwrap_or(false);
            if is_property {
                // Walk past the wrapping expression(s) above the
                // member_expression to see if its container is a
                // call_expression whose `function` is this member.
                let mut anc = effective_parent.parent();
                let mut last = effective_parent;
                while let Some(a) = anc {
                    if a.kind() == "expression" {
                        last = a;
                        anc = a.parent();
                        continue;
                    }
                    if a.kind() == "call_expression" {
                        if let Some(func) = a.child_by_field_name("function") {
                            if func.id() == last.id() {
                                return ReferenceKind::Call;
                            }
                        }
                    }
                    break;
                }
            }
            ReferenceKind::Read
        }

        // Assignment: target = value
        "assignment_expression" => {
            if let Some(left) = effective_parent.child_by_field_name("left") {
                if left.id() == child_through_wrappers.id()
                    || node_contains(node, &left)
                {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Augmented update: x += 1 / x -= 1
        "augmented_assignment_expression" => {
            if let Some(left) = effective_parent.child_by_field_name("left") {
                if left.id() == child_through_wrappers.id()
                    || node_contains(node, &left)
                {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Definitions — names being introduced.
        "function_definition"
        | "modifier_definition"
        | "constructor_definition"
        | "fallback_receive_definition"
        | "contract_declaration"
        | "interface_declaration"
        | "library_declaration"
        | "event_definition"
        | "error_declaration"
        | "struct_declaration"
        | "enum_declaration" => {
            if let Some(name) = effective_parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Parameters / variables — the `name` slot is a Definition.
        "parameter" | "variable_declaration" | "state_variable_declaration"
        | "constant_variable_declaration" => {
            if let Some(name) = effective_parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Type slot. tree-sitter-solidity wraps named types in
        // `user_defined_type` / `type_name`.
        "user_defined_type" | "type_name" => ReferenceKind::Type,

        // Import statements.
        "import_directive" | "import_clause" | "source_import"
        | "named_imports" | "import_alias" => ReferenceKind::Import,

        // Default: treat as a value read.
        _ => ReferenceKind::Read,
    }
}

/// Walk up through the tree-sitter-solidity `expression` union wrappers
/// to find the first ancestor whose kind is NOT `expression`.
///
/// Returns `(effective_parent, immediate_child_below_effective_parent)`:
///   - The first element is the first non-`expression` ancestor (the
///     semantic parent of the identifier).
///   - The second is the descendant *just below* that effective parent —
///     equivalent to the value that would be returned by
///     `effective_parent.child_by_field_name("function")` /
///     `child_by_field_name("left")` when the identifier sits inside a
///     stack of `expression` wrappers. Comparing by `Node::id()` against
///     that child lets us positively identify which slot we occupy.
fn solidity_skip_expression_wrappers<'a>(
    node: &Node<'a>,
    parent: &Node<'a>,
) -> (Node<'a>, Node<'a>) {
    let mut effective = *parent;
    let mut child_under_effective = *node;
    while effective.kind() == "expression" {
        match effective.parent() {
            Some(next) => {
                child_under_effective = effective;
                effective = next;
            }
            None => break,
        }
    }
    (effective, child_under_effective)
}

/// Classify Python reference kind
fn classify_python_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Function/method call: func() or obj.method()
        "call" => ReferenceKind::Call,

        // S7-R5: Check if we're the function being called (not an argument)
        "argument_list" => {
            // We're an argument to a call, likely a Read
            ReferenceKind::Read
        }

        // Assignment: x = value
        "assignment" => {
            // Check if node is on LHS (target) or RHS (value)
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Augmented assignment: x += 1 (both read and write, report as Write)
        "augmented_assignment" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Import statements
        "import_statement" | "import_from_statement" | "dotted_name" | "aliased_import" => {
            // Check if we're actually in an import context
            let mut current = Some(*parent);
            while let Some(ancestor) = current {
                if ancestor.kind() == "import_statement"
                    || ancestor.kind() == "import_from_statement"
                {
                    return ReferenceKind::Import;
                }
                current = ancestor.parent();
            }
            ReferenceKind::Read
        }

        // Type annotations
        "type" | "annotation" | "subscript" => {
            // Check if this is in a type annotation context
            if is_type_context(parent) {
                return ReferenceKind::Type;
            }
            ReferenceKind::Read
        }

        // Function/class definition
        "function_definition" | "class_definition" => {
            // Check if this is the name being defined
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Parameter definition
        "parameter" | "typed_parameter" | "default_parameter" | "typed_default_parameter" => {
            // The parameter name itself is a Definition
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            // Type annotation in parameter
            if let Some(type_node) = parent.child_by_field_name("type") {
                if node_contains(node, &type_node) {
                    return ReferenceKind::Type;
                }
            }
            ReferenceKind::Read
        }

        // For loop variable
        "for_statement" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Comprehension
        "for_in_clause" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Attribute access: obj.attr - we need to check grandparent for call
        "attribute" => {
            // S7-R5: Check grandparent for call expression
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call" {
                    // Check if the call's function is this attribute
                    if let Some(func) = grandparent.child_by_field_name("function") {
                        if func.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        // Default: assume it's a read
        _ => ReferenceKind::Read,
    }
}

/// Classify TypeScript/JavaScript reference kind
fn classify_typescript_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Function call
        "call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Assignment
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Variable declarator: let x = ...
        "variable_declarator" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Import statements
        "import_specifier" | "import_clause" | "namespace_import" => ReferenceKind::Import,

        // Type annotations
        "type_annotation" | "type_identifier" | "generic_type" | "type_arguments" => {
            ReferenceKind::Type
        }

        // Function/class declaration
        "function_declaration" | "class_declaration" | "method_definition" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Member expression: obj.prop - check grandparent for call
        "member_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(func) = grandparent.child_by_field_name("function") {
                        if func.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        _ => ReferenceKind::Read,
    }
}

/// Classify Go reference kind
fn classify_go_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Function call
        "call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Assignment
        "assignment_statement" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Short variable declaration: x := value
        "short_var_declaration" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Import
        "import_spec" => ReferenceKind::Import,

        // Type reference
        "type_identifier" | "qualified_type" | "pointer_type" | "slice_type" | "array_type" => {
            ReferenceKind::Type
        }

        // Function declaration
        "function_declaration" | "method_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Selector expression: pkg.Func or obj.Method
        "selector_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(func) = grandparent.child_by_field_name("function") {
                        if func.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        _ => ReferenceKind::Read,
    }
}

/// Classify Rust reference kind
fn classify_rust_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Function call
        "call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Assignment (let with value or reassignment)
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Let binding
        "let_declaration" => {
            if let Some(pattern) = parent.child_by_field_name("pattern") {
                if node_contains(node, &pattern) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Use declaration (imports)
        "use_declaration" | "use_clause" | "scoped_identifier" => {
            // Check if we're in a use context
            let mut current = Some(*parent);
            while let Some(ancestor) = current {
                if ancestor.kind() == "use_declaration" {
                    return ReferenceKind::Import;
                }
                current = ancestor.parent();
            }
            ReferenceKind::Read
        }

        // Type references
        "type_identifier" | "generic_type" | "scoped_type_identifier" | "reference_type" => {
            ReferenceKind::Type
        }

        // Function definition
        "function_item" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Method call: obj.method()
        "field_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(func) = grandparent.child_by_field_name("function") {
                        if func.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        _ => ReferenceKind::Read,
    }
}

/// Return the first named child of `node` whose kind is in `kinds`.
fn first_named_child_of_kind<'a>(node: &Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if kinds.contains(&child.kind()) {
                return Some(child);
            }
        }
    }
    None
}

/// Classify Java reference kind.
///
/// Grammar reference: tree-sitter-java. `method_declaration` /
/// `constructor_declaration` hold the method name as their first `identifier`
/// child (return types are `type_identifier` / `void_type`, so not confused).
/// Call sites use `method_invocation` whose callee identifier is a direct
/// `identifier` child (for `obj.method()` the callee is under a `field_access`
/// parent — we classify on the direct identifier attached to the invocation).
fn classify_java_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Direct call site: greet()
        "method_invocation" => {
            // The callee identifier appears as the "name" field or the first
            // identifier child of the invocation. Arguments are in argument_list,
            // so an identifier that is NOT inside argument_list is the callee.
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Call;
                }
            }
            // Fallback: if no "name" field, the first identifier child is the callee.
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Method / constructor definition: first identifier child is the name.
        "method_declaration" | "constructor_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Class / interface / enum declarations: name field
        "class_declaration" | "interface_declaration" | "enum_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Assignment: lhs is Write
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Imports
        "import_declaration" => ReferenceKind::Import,

        // Field access / scoped access: if grandparent is method_invocation
        // and this field_access is the callee, it's a Call.
        "field_access" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "method_invocation" {
                    if let Some(name) = grandparent.child_by_field_name("name") {
                        if node_contains(node, &name) {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        // Type references
        "type_identifier" | "generic_type" | "array_type" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Classify C reference kind.
///
/// Grammar reference: tree-sitter-c. `function_definition` contains a
/// `function_declarator` whose first `identifier` child is the function name.
/// `call_expression` has the callee as its first child (an `identifier` for
/// direct calls).
fn classify_c_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        // Direct call: greet()
        "call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            // Fallback: first child of call_expression is the callee
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // Function name inside function_declarator: definition
        "function_declarator" => {
            // The first identifier child is the function name.
            if let Some(decl) = parent.child_by_field_name("declarator") {
                if node.id() == decl.id() {
                    return classify_c_declarator_as_definition(parent);
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    // Check whether this declarator is inside a function_definition
                    // — if so, this is a Definition. Otherwise it's still the name
                    // of a declared function (forward declaration), also Definition.
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Parameter declaration name
        "parameter_declaration" => {
            if let Some(decl) = parent.child_by_field_name("declarator") {
                if node_contains(node, &decl) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Initializers / assignments: lhs of assignment_expression is a Write.
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // Preprocessor includes
        "preproc_include" => ReferenceKind::Import,

        // Field access used as callee
        "field_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        // Type references
        "type_identifier" | "sized_type_specifier" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Helper: a function_declarator within a function_definition/declaration
/// always names a function-kind entity (not a variable), so its identifier
/// is a Definition. Kept as a tiny helper to match the established pattern.
fn classify_c_declarator_as_definition(_declarator: &Node) -> ReferenceKind {
    ReferenceKind::Definition
}

/// Classify C++ reference kind.
///
/// Grammar reference: tree-sitter-cpp. Structure mirrors C for the
/// must-have cases (`function_definition` → `function_declarator` →
/// `identifier` for the name; `call_expression` with direct `identifier`
/// callee). Adds handling for qualified identifiers (ns::func()) and
/// field expressions for method calls.
fn classify_cpp_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_declarator" => {
            if let Some(first_id) = first_named_child_of_kind(
                parent,
                &[
                    "identifier",
                    "field_identifier",
                    "qualified_identifier",
                    "destructor_name",
                ],
            ) {
                if node.id() == first_id.id() || node_contains(node, &first_id) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        // Qualified identifier: ns::func — if part of a call, it's a Call
        "qualified_identifier" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
                // Qualified identifier inside a declarator is part of a Definition.
                if grandparent.kind() == "function_declarator" {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "field_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "parameter_declaration" => {
            if let Some(decl) = parent.child_by_field_name("declarator") {
                if node_contains(node, &decl) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "preproc_include" => ReferenceKind::Import,

        "type_identifier" | "template_type" | "sized_type_specifier" => ReferenceKind::Type,

        "class_specifier" | "struct_specifier" | "namespace_definition" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node_contains(node, &name) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        _ => ReferenceKind::Read,
    }
}

/// Classify C# reference kind.
///
/// Grammar reference: tree-sitter-c-sharp. `method_declaration`,
/// `constructor_declaration`, and `class_declaration` expose a "name" field
/// (and also have the name as a direct identifier child). Call sites are
/// `invocation_expression` — the callee is a direct `identifier` child or
/// a `member_access_expression`.
fn classify_csharp_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "invocation_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "method_declaration" | "constructor_declaration" | "local_function_statement" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            // Fallback: for method_declaration the name is the second identifier
            // (first is return type when type_identifier isn't emitted). Safely
            // take the first identifier — this is the established fallback in
            // the C# callgraph handler.
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "class_declaration"
        | "interface_declaration"
        | "struct_declaration"
        | "enum_declaration"
        | "record_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "member_access_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "invocation_expression" {
                    if let Some(func) = grandparent.child_by_field_name("function") {
                        if func.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "using_directive" | "namespace_declaration" => ReferenceKind::Import,

        "type_parameter" | "type_argument_list" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Classify Kotlin reference kind.
///
/// Grammar reference: tree-sitter-kotlin. `function_declaration` /
/// `class_declaration` have the name as a direct `identifier` child.
/// `call_expression` has the callee as a direct `identifier` or a
/// `navigation_expression` child.
fn classify_kotlin_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "call_expression" => {
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() || node_contains(node, &first) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_declaration"
        | "class_declaration"
        | "object_declaration"
        | "property_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "navigation_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "assignment" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "import_header" | "import_list" => ReferenceKind::Import,

        "user_type" | "type_reference" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Classify Scala reference kind.
///
/// Grammar reference: tree-sitter-scala. `function_definition` /
/// `function_declaration` / `class_definition` / `object_definition` have the
/// name as a direct `identifier` or `type_identifier` child. Call sites are
/// `call_expression` with the callee as the first non-arguments child.
fn classify_scala_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "call_expression" => {
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() || node_contains(node, &first) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_definition" | "function_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) =
                first_named_child_of_kind(parent, &["identifier", "type_identifier"])
            {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "class_definition" | "object_definition" | "trait_definition" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) =
                first_named_child_of_kind(parent, &["identifier", "type_identifier"])
            {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "field_expression" | "select_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "import_declaration" | "import_expression" | "import_selectors" => ReferenceKind::Import,

        "type_identifier" | "generic_type" | "compound_type" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Classify Swift reference kind.
///
/// Grammar reference: tree-sitter-swift. `function_declaration` /
/// `protocol_function_declaration` expose a "name" field (a
/// `simple_identifier`). `init_declaration` doesn't have a simple name but
/// its identifier site is still a Definition. `call_expression` has the
/// callable as its first child (usually `simple_identifier` or
/// `navigation_expression`).
fn classify_swift_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "call_expression" => {
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() || node_contains(node, &first) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_declaration" | "protocol_function_declaration" | "init_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["simple_identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "class_declaration" | "protocol_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node_contains(node, &name) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "property_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node_contains(node, &name) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "navigation_expression" => {
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call_expression" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "assignment" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "import_declaration" => ReferenceKind::Import,

        "user_type" | "type_identifier" => ReferenceKind::Type,

        // CFr-RW2: tree-sitter-swift error-recovers a modifier/attribute-
        // decorated type declaration whose body holds unparseable syntax
        // (e.g. `open class Session: @unchecked Sendable { … #if … #endif }`)
        // by burying the type name inside an `ERROR` node that trails the
        // recovered `class`/`struct`/`enum`/`actor` keyword token. The buried
        // name is still the definition site, so classify it as a Definition
        // (it is otherwise dropped to `Read` and never reaches `definitions[]`).
        "ERROR" if swift_recovered_type_def_kind(node).is_some() => ReferenceKind::Definition,

        _ => ReferenceKind::Read,
    }
}

/// Classify PHP reference kind.
///
/// Grammar reference: tree-sitter-php. `function_definition` and
/// `method_declaration` expose a "name" field (a `name` node). Call sites are
/// `function_call_expression` / `member_call_expression` /
/// `scoped_call_expression` — all with a "function"/"name" field.
fn classify_php_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "function_call_expression" => {
            if let Some(func) = parent.child_by_field_name("function") {
                if node_contains(node, &func) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "member_call_expression" | "scoped_call_expression" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node_contains(node, &name) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_definition" | "method_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "class_declaration" | "trait_declaration" | "interface_declaration" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        "namespace_use_declaration" | "namespace_use_clause" | "namespace_name" => {
            ReferenceKind::Import
        }

        "named_type" | "primitive_type" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Classify Ruby reference kind.
///
/// Grammar reference: tree-sitter-ruby. `method` / `singleton_method` have
/// the name as a direct `identifier` child. Call sites are `call` nodes
/// where the callee identifier is also a direct `identifier` child (with
/// `argument_list` containing arguments).
fn classify_ruby_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "call" => {
            // The callee is the identifier that is NOT inside argument_list and
            // NOT a receiver. Ruby's `call` can look like:
            //   call { identifier(callee), argument_list }
            //   call { identifier(receiver), ".", identifier(callee), argument_list }
            // The callee is the LAST identifier child before the argument_list
            // (or at the end if no arguments).
            if let Some(name) = parent.child_by_field_name("method") {
                if node_contains(node, &name) {
                    return ReferenceKind::Call;
                }
            }
            // Fallback: find the last identifier child before argument_list.
            let mut last_id: Option<Node> = None;
            for i in 0..parent.child_count() {
                if let Some(child) = parent.child(i) {
                    if child.kind() == "argument_list" {
                        break;
                    }
                    if child.kind() == "identifier" {
                        last_id = Some(child);
                    }
                }
            }
            if let Some(id) = last_id {
                if node.id() == id.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "method" | "singleton_method" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "class" | "module" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node_contains(node, &name) {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "assignment" | "operator_assignment" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            ReferenceKind::Read
        }

        // CF2-S19: a bareword self-send — a method invoked with NO receiver and
        // NO parentheses, e.g. `cleanup` / `do_thing` on its own line inside a
        // method body. tree-sitter-ruby parses such a no-argument bareword call
        // as a lone `identifier` sitting directly in a statement-sequence
        // container (the method/block/begin body, or an `if`/`unless` branch),
        // NOT as a `call` node. The `call` arm above therefore never fires and
        // the occurrence fell through to `_ => Read`, mislabelling every
        // bareword self-send. An `identifier` that IS a whole statement in one
        // of these containers is in call position (a local-variable read is
        // virtually never written as a standalone no-op statement), so classify
        // it as a `Call`. Receivers, call callees (handled by `call`),
        // assignment targets (handled above) and definition names (handled by
        // `method`/`class`) all have other parents and are unaffected.
        "body_statement" | "then" | "else" | "ensure" | "begin"
            if node.kind() == "identifier" =>
        {
            ReferenceKind::Call
        }

        _ => ReferenceKind::Read,
    }
}

/// Classify Lua reference kind.
///
/// Grammar reference: tree-sitter-lua (nvim-treesitter). `function_declaration`
/// has the name as a direct `identifier` child (or `dot_index_expression` /
/// `method_index_expression`). Call sites are `function_call` with the callee
/// as the first child.
fn classify_lua_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    classify_lua_family_reference(node, parent)
}

/// Classify Luau reference kind.
///
/// Luau's grammar mirrors Lua's for the core call/definition nodes
/// (`function_call`, `function_declaration`, `identifier`). Share the impl.
fn classify_luau_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    classify_lua_family_reference(node, parent)
}

fn classify_lua_family_reference(node: &Node, parent: &Node) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "function_call" => {
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() || node_contains(node, &first) {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "function_declaration" | "local_function" | "function_definition_statement" => {
            if let Some(name) = parent.child_by_field_name("name") {
                if node.id() == name.id() {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "dot_index_expression" | "method_index_expression" => {
            // If we're the function name (last identifier) and grandparent is
            // function_call, it's a Call. If grandparent is function_declaration,
            // it's a Definition.
            if let Some(grandparent) = parent.parent() {
                match grandparent.kind() {
                    "function_call" => {
                        if let Some(first) = grandparent.child(0) {
                            if first.id() == parent.id() {
                                return ReferenceKind::Call;
                            }
                        }
                    }
                    "function_declaration" => {
                        return ReferenceKind::Definition;
                    }
                    _ => {}
                }
            }
            ReferenceKind::Read
        }

        "assignment_statement" => {
            if let Some(left) = parent.child_by_field_name("variables") {
                if node_contains(node, &left) {
                    return ReferenceKind::Write;
                }
            }
            // Fallback: check if the node is in the "variable_list" (first
            // named child) — that's the LHS in the nvim grammar.
            for i in 0..parent.child_count() {
                if let Some(child) = parent.child(i) {
                    if child.kind() == "variable_list" {
                        if node_contains(node, &child) {
                            return ReferenceKind::Write;
                        }
                        break;
                    }
                }
            }
            ReferenceKind::Read
        }

        "variable_declaration" => {
            // Local declarations: `local foo = ...` — the name is a Definition.
            ReferenceKind::Definition
        }

        _ => ReferenceKind::Read,
    }
}

/// Classify Elixir reference kind.
///
/// Elixir's grammar uses `call` nodes for nearly everything. The pattern for a
/// function definition is `call { identifier("def"|"defp"), arguments { call {
/// identifier(funcname), ... } } }`. So to detect Definition, we check: our
/// identifier is the first identifier child of a `call`, that call's parent is
/// `arguments`, and the argument's parent `call` has first identifier "def" /
/// "defp" / "defmacro" / "defmacrop".
///
/// Direct call sites: our identifier is the first identifier child of a `call`
/// node (not inside the def-pattern above). Dotted calls (`Mod.func`) have
/// parent `dot`.
fn classify_elixir_reference(node: &Node, parent: &Node, source: &[u8]) -> ReferenceKind {
    // fix-PW1-B7a-elixir-refcount (v0.5.0 BACKLOG): a def-name occurrence
    // inside a `@spec`/`@type`/`@typep`/`@opaque`/`@callback`/`@macrocallback`
    // typespec is a TYPE annotation, not a function call. `@spec handle(...)`
    // parses as `unary_operator(@) -> call(spec) -> arguments -> ... -> call(handle)`,
    // so the inner `handle` identifier would otherwise classify as a `Call` and
    // be wrongly credited as a caller by impact/explain. Demote any occurrence
    // living under a typespec attribute to a `Read` (a genuine textual usage,
    // but never a call). AST/structural — no source-text heuristic.
    if elixir_occurrence_in_typespec(node, source) {
        return ReferenceKind::Read;
    }

    let parent_kind = parent.kind();

    match parent_kind {
        "call" => {
            // Is this the first identifier child of the call?
            if let Some(first_id) = first_named_child_of_kind(parent, &["identifier"]) {
                if node.id() == first_id.id() {
                    // Check if this call is inside `arguments` of a def-style call.
                    if is_elixir_def_call(parent, source) {
                        return ReferenceKind::Definition;
                    }
                    // Otherwise it's a plain function call.
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        // RC8 (v0.5.0 R7 cluster[10], #56): a ZERO-ARITY `def name do` parses
        // as `call(target=def, arguments(identifier name), do_block)` — the
        // name's immediate parent is `arguments`, NOT a nested `call`. The
        // existing `"call"` arm above only catches the with-args shape (where
        // the name lives inside a nested `call`). Detect the zero-arity def
        // here: if this identifier is the FIRST child of an `arguments` node
        // whose parent `call` has target `def`/`defp`/`defmacro`/`defmacrop`,
        // it is a Definition. Without this the def line was classified `read`.
        "arguments" => {
            if let Some(outer_call) = parent.parent() {
                if outer_call.kind() == "call" {
                    let target_is_def = outer_call
                        .child_by_field_name("target")
                        .and_then(|t| t.utf8_text(source).ok())
                        .map(|t| matches!(t, "def" | "defp" | "defmacro" | "defmacrop"))
                        .unwrap_or(false);
                    if target_is_def {
                        // Must be the first (name) argument.
                        if let Some(first_arg) =
                            first_named_child_of_kind(parent, &["identifier"])
                        {
                            if first_arg.id() == node.id() {
                                return ReferenceKind::Definition;
                            }
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "dot" => {
            // Dotted call: App.greet — if the dot's parent is a call whose first
            // child is this dot, it's a Call.
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "call" {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            // Check we're the name side (usually the LAST identifier child of dot).
                            let mut last_id: Option<Node> = None;
                            for i in 0..parent.child_count() {
                                if let Some(child) = parent.child(i) {
                                    if child.kind() == "identifier" {
                                        last_id = Some(child);
                                    }
                                }
                            }
                            if let Some(id) = last_id {
                                if node.id() == id.id() {
                                    return ReferenceKind::Call;
                                }
                            }
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        _ => ReferenceKind::Read,
    }
}

/// fix-PW1-B7a-elixir-refcount: returns true if `node` lives anywhere inside a
/// typespec module-attribute subtree — `@spec` / `@type` / `@typep` /
/// `@opaque` / `@callback` / `@macrocallback`. Such an attribute parses as a
/// `unary_operator` whose `operator` is `@` and whose `operand` is a `call`
/// with one of those typespec target identifiers. The function-name occurrences
/// inside the signature (e.g. `handle` in `@spec handle(...) :: ...`) are TYPE
/// annotations, not calls, and must not be counted as references-as-calls.
///
/// Walks the ancestor chain (bounded — a real call inside a function body never
/// has a typespec `unary_operator` ancestor, since module attributes are
/// siblings of `def`, not enclosing nodes).
fn elixir_occurrence_in_typespec(node: &Node, source: &[u8]) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "unary_operator" && elixir_unary_is_typespec(&ancestor, source) {
            return true;
        }
        current = ancestor.parent();
    }
    false
}

/// Returns true if `unary_node` is a typespec module-attribute (`@spec`,
/// `@type`, `@typep`, `@opaque`, `@callback`, `@macrocallback`).
fn elixir_unary_is_typespec(unary_node: &Node, source: &[u8]) -> bool {
    if unary_node.kind() != "unary_operator" {
        return false;
    }
    // operator must be `@`.
    let has_at = unary_node
        .child_by_field_name("operator")
        .map(|op| op.kind() == "@")
        .unwrap_or(false);
    if !has_at {
        return false;
    }
    // operand is the attribute call; its target identifier names the attribute.
    let operand = match unary_node.child_by_field_name("operand") {
        Some(o) if o.kind() == "call" => o,
        _ => return false,
    };
    let target = match operand.child_by_field_name("target") {
        Some(t) if t.kind() == "identifier" => t,
        _ => return false,
    };
    matches!(
        target.utf8_text(source).unwrap_or(""),
        "spec" | "type" | "typep" | "opaque" | "callback" | "macrocallback"
    )
}

/// Returns true if `call_node` is the inner `call` inside
/// `outer_call(def|defp|defmacro|defmacrop, arguments { call_node, ... })`.
fn is_elixir_def_call(call_node: &Node, source: &[u8]) -> bool {
    // call_node.parent() should be `arguments`.
    let args = match call_node.parent() {
        Some(p) if p.kind() == "arguments" => p,
        _ => return false,
    };
    let outer_call = match args.parent() {
        Some(p) if p.kind() == "call" => p,
        _ => return false,
    };
    // Find the first identifier child of outer_call.
    for i in 0..outer_call.child_count() {
        if let Some(child) = outer_call.child(i) {
            if child.kind() == "identifier" {
                let start = child.start_byte();
                let end = child.end_byte();
                if end <= source.len() {
                    let text = &source[start..end];
                    return matches!(text, b"def" | b"defp" | b"defmacro" | b"defmacrop");
                }
                return false;
            }
        }
    }
    false
}

/// Classify OCaml reference kind.
///
/// Grammar reference: tree-sitter-ocaml. The identifier-like node is a
/// `value_name`. At definition sites its parent is `let_binding` (or
/// `value_definition`). At call sites its parent is `value_path`, whose
/// parent is `application_expression` with this `value_path` as the first
/// child. Shadowing rebinding is another Definition (per OCaml semantics —
/// `let x = ... let x = ...` is two separate bindings, not a Write).
/// RC7 (v0.5.0 R3): return the HEAD module name of the qualifier of an OCaml
/// reference occurrence, if any.
///
/// Given the matched leaf node (a `value_name`/`constructor_name`/… inside a
/// `value_path`/`constructor_path`/`type_constructor_path`/`field_path`), this
/// reads the OPTIONAL leading `module_path` qualifier (per tree-sitter-ocaml
/// `value_path = path(module_path, value_name)`) and descends its
/// left-recursive `module_path` chain to the LEFTMOST `module_name` — the head
/// segment that disambiguates stdlib `Mutex.lock` from a project
/// `Lwt_mutex.lock`. Returns `None` for a bare/local reference (no qualifier).
///
/// This is the discriminating AST node the legacy classifier ignored: it keyed
/// references purely on the leaf text (`lock`), so a stdlib `Mutex.lock` call
/// was indistinguishable from the project def.
fn ocaml_reference_qualifier_head(leaf_node: &Node, source: &[u8]) -> Option<String> {
    let parent = leaf_node.parent()?;
    if !matches!(
        parent.kind(),
        "value_path" | "constructor_path" | "type_constructor_path" | "field_path"
    ) {
        return None;
    }
    // The qualifier is the first NAMED child iff it is a `module_path`.
    let first = parent.named_child(0)?;
    if first.kind() != "module_path" {
        return None;
    }
    // Descend the left-recursive `module_path` chain to the leftmost
    // `module_name` head. `module_path = path(module_path, module_name)` so the
    // nested `module_path` (when present) is the prefix; recurse into it.
    let mut current = first;
    loop {
        let mut next: Option<Node> = None;
        let mut cursor = current.walk();
        for ch in current.named_children(&mut cursor) {
            if ch.kind() == "module_path" {
                next = Some(ch);
                break;
            }
        }
        match next {
            Some(inner) => current = inner,
            None => break,
        }
    }
    // `current` is now the leftmost `module_path`; its `module_name` child is
    // the head segment.
    let mut cursor = current.walk();
    for ch in current.named_children(&mut cursor) {
        if ch.kind() == "module_name" {
            return ch.utf8_text(source).ok().map(|s| s.to_string());
        }
    }
    None
}

fn classify_ocaml_reference(node: &Node, parent: &Node, _source: &[u8]) -> ReferenceKind {
    let parent_kind = parent.kind();

    match parent_kind {
        "let_binding" | "value_definition" => {
            // The bound name is the first `value_name` child.
            if let Some(name) = parent.child_by_field_name("pattern") {
                if node.id() == name.id() || node_contains(node, &name) {
                    return ReferenceKind::Definition;
                }
            }
            if let Some(first_name) = first_named_child_of_kind(parent, &["value_name"]) {
                if node.id() == first_name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "value_path" => {
            // If this path is the callee of an application_expression, it's a Call.
            // Otherwise it's a Read.
            if let Some(grandparent) = parent.parent() {
                if matches!(grandparent.kind(), "application_expression" | "application") {
                    if let Some(first) = grandparent.child(0) {
                        if first.id() == parent.id() {
                            return ReferenceKind::Call;
                        }
                    }
                }
            }
            ReferenceKind::Read
        }

        "application_expression" | "application" => {
            // Bare value_name used as callee (no module qualifier).
            if let Some(first) = parent.child(0) {
                if node.id() == first.id() {
                    return ReferenceKind::Call;
                }
            }
            ReferenceKind::Read
        }

        "module_binding" | "module_definition" => {
            if let Some(first_name) = first_named_child_of_kind(parent, &["module_name"]) {
                if node.id() == first_name.id() {
                    return ReferenceKind::Definition;
                }
            }
            ReferenceKind::Read
        }

        "open_module" | "include_module" => ReferenceKind::Import,

        "type_constructor" | "type_constructor_path" => ReferenceKind::Type,

        _ => ReferenceKind::Read,
    }
}

/// Check if a node is contained within another node (by position)
fn node_contains(inner: &Node, outer: &Node) -> bool {
    inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// Check if parent is in a type annotation context
fn is_type_context(node: &Node) -> bool {
    let mut current = Some(*node);
    while let Some(n) = current {
        let kind = n.kind();
        if matches!(
            kind,
            "type"
                | "annotation"
                | "type_annotation"
                | "return_type"
                | "parameter"
                | "typed_parameter"
                | "generic_type"
                | "type_arguments"
        ) {
            return true;
        }
        // Stop at statement boundaries
        if kind.ends_with("_statement") || kind.ends_with("_definition") {
            return false;
        }
        current = n.parent();
    }
    false
}

// =============================================================================
// Phase 11: Definition Finding and Cross-File Tracking
// =============================================================================

/// Predicate: a path looks like a test file across the language ecosystems
/// supported by `tldr`.
///
/// Recognises (in priority order):
///
/// 1. **Java/Kotlin/Scala** — Maven/Gradle convention `src/test/`
///    (e.g. `src/test/java/...`, `src/test/kotlin/...`).
/// 2. **JS/TS** — `__tests__/`, `.test.<ext>`, `.spec.<ext>`, `.e2e.<ext>`,
///    plus `test/`, `tests/`. Mirrors `vuln::is_js_test_file` minus the
///    extension gate (the gate is JS-only; here we want a generic predicate).
/// 3. **Python** — `tests/`, `test/`, `test_*.py`, `*_test.py`,
///    `conftest.py`.
/// 4. **Rust** — `tests/`, `_test.rs`, `tests.rs`. Mirrors
///    `vuln::is_rust_test_file`.
/// 5. **Ruby** — `spec/`, `_spec.rb`, `_test.rb`.
/// 6. **Go** — `_test.go`.
///
/// Used by `find_definition` (the references-canonical-def-v1 milestone)
/// to PREFER non-test files when picking a canonical definition. When a
/// symbol like `Flask` is defined in both `src/flask/app.py` (canonical
/// class) AND `tests/test_config.py` (test subclass `class Flask(flask.Flask)`),
/// the canonical-def picker uses this predicate to filter out the test
/// match and return the real source location.
///
/// Conservative — when in doubt, returns `false` (i.e. treats the file
/// as non-test). This avoids false-suppressing legitimate source code.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use tldr_core::analysis::references::is_test_file_path;
///
/// // Test files
/// assert!(is_test_file_path(Path::new("tests/test_config.py")));
/// assert!(is_test_file_path(Path::new("src/test/java/com/Foo.java")));
/// assert!(is_test_file_path(Path::new("foo/__tests__/bar.js")));
/// assert!(is_test_file_path(Path::new("foo_test.go")));
/// assert!(is_test_file_path(Path::new("spec/foo_spec.rb")));
/// assert!(is_test_file_path(Path::new("crates/x/tests/it.rs")));
/// assert!(is_test_file_path(Path::new("foo.spec.ts")));
///
/// // Source files
/// assert!(!is_test_file_path(Path::new("src/flask/app.py")));
/// assert!(!is_test_file_path(Path::new("lib/router/index.js")));
/// assert!(!is_test_file_path(Path::new("src/main.rs")));
/// ```
pub fn is_test_file_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Normalise Windows path separators to forward slashes for matching.
    let normalised: String = path_str.replace('\\', "/");
    let n = normalised.as_str();

    // 1. Java/Kotlin/Scala Maven/Gradle convention.
    //    Match the SEGMENT `src/test/` — a `srcXtest` substring would not.
    if n.contains("/src/test/") || n.starts_with("src/test/") {
        return true;
    }

    // 2. Generic test-directory components (matches at any depth, including
    //    leading position for relative paths).
    //    Note: we deliberately match `test/` AND `tests/` — both are common.
    let has_test_dir = n.contains("/tests/")
        || n.contains("/test/")
        || n.contains("/__tests__/")
        || n.contains("/spec/")
        || n.contains("/specs/")
        || n.starts_with("tests/")
        || n.starts_with("test/")
        || n.starts_with("__tests__/")
        || n.starts_with("spec/")
        || n.starts_with("specs/");
    if has_test_dir {
        return true;
    }

    // 3. Filename-suffix patterns by extension.
    let filename = match path.file_name().and_then(|f| f.to_str()) {
        Some(f) => f,
        None => return false,
    };

    // Python: test_*.py / *_test.py / conftest.py
    if filename.ends_with(".py")
        && (filename.starts_with("test_")
            || filename.ends_with("_test.py")
            || filename == "conftest.py")
    {
        return true;
    }

    // Rust: *_test.rs / tests.rs
    if filename.ends_with("_test.rs") || filename == "tests.rs" {
        return true;
    }

    // Go: *_test.go
    if filename.ends_with("_test.go") {
        return true;
    }

    // Ruby: *_spec.rb / *_test.rb
    if filename.ends_with("_spec.rb") || filename.ends_with("_test.rb") {
        return true;
    }

    // JS/TS: foo.test.ext / foo.spec.ext / foo.e2e.ext
    let js_exts = [
        ".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs", ".cts", ".mts",
    ];
    for ext in &js_exts {
        if filename.ends_with(ext) {
            let stem = &filename[..filename.len() - ext.len()];
            if stem.ends_with(".test")
                || stem.ends_with(".spec")
                || stem.ends_with(".e2e")
            {
                return true;
            }
        }
    }

    false
}

/// Predicate: a path lives under a "real source" directory (`src/`,
/// `lib/`, `main/`).
///
/// Used as a SECONDARY ranking signal in `find_definition` — among
/// non-test definition candidates, prefer one that lives in `src/` /
/// `lib/` / `main/` over one in (say) `examples/` or `scripts/`.
fn is_src_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let n: String = path_str.replace('\\', "/");

    // Order matters: check `src/main/` BEFORE `src/test/` would have been
    // checked (`is_test_file_path` already excluded it earlier).
    n.contains("/src/main/")
        || n.contains("/src/")
        || n.starts_with("src/")
        || n.contains("/lib/")
        || n.starts_with("lib/")
        || n.contains("/main/")
        || n.starts_with("main/")
}

/// Find the canonical definition location for a symbol.
///
/// Scans all source files in the workspace, collects every AST node
/// whose name matches `symbol`, and ranks the candidates so the
/// **canonical** (non-test, source-tree) definition wins:
///
/// 1. **Tier 1 (preferred):** non-test file that lives under `src/` /
///    `lib/` / `main/`.
/// 2. **Tier 2:** non-test file anywhere else.
/// 3. **Tier 3 (last resort):** test file (only picked if every match
///    is in a test file — e.g. when the symbol is genuinely test-only).
///
/// Within a tier, candidates are ordered by file path lexicographically
/// (stable, deterministic) and the lowest line number wins on tie.
///
/// # Why
///
/// Pre-`references-canonical-def-v1` this function returned the FIRST
/// match emitted by `walk_project`, which on real codebases (`flask`,
/// `express`) was a test subclass like
/// `class Flask(flask.Flask)` at `tests/test_config.py:202` — a
/// confusing UX failure that hid the canonical
/// `class Flask` at `src/flask/app.py:109`.
///
/// # Supported languages for AST-level definition matching
///
/// - Python: `function_definition`, `class_definition`, module-level
///   `assignment`
/// - TypeScript / JavaScript: `function_declaration`, `class_declaration`,
///   `variable_declaration`
/// - Go: `function_declaration`, `type_declaration`
/// - Rust: `function_item`, `struct_item`, `enum_item`, `const_item`,
///   `static_item`, `type_item`
///
/// Languages not in this list yield `Ok(None)` — the references
/// command still works (text-search + AST verification of references),
/// just without a `definition` field in the report.
///
/// # Arguments
///
/// * `symbol` - The symbol name to find the definition for
/// * `root` - The root directory to search in
/// * `language` - Optional language filter
///
/// # Returns
///
/// `Some(Definition)` for the highest-tier match, or `None` if no
/// AST-level match was found in any file.
pub fn find_definition(
    symbol: &str,
    root: &Path,
    language: Option<&str>,
) -> TldrResult<Option<Definition>> {
    // Back-compat singular: returns the first (highest-tier) definition only.
    // M3 detection-accuracy-v1 BUG-20 introduced `find_definitions` (plural)
    // to return ALL of them; this helper now delegates to that and picks the
    // first to preserve every existing caller's contract.
    Ok(find_definitions(symbol, root, language)?.into_iter().next())
}

/// Find every definition of `symbol` reachable under `root`.
///
/// Pre-M3 the references engine only ever surfaced ONE definition (the
/// highest-tier match). Languages with overload-style multi-definition
/// patterns — flask's `_make_timedelta` having two distinct top-level
/// definitions in `sansio/app.py` and `app.py`, Python `@overload`d
/// signatures, TypeScript declaration-merging, Rust trait impls — were
/// silently collapsed. M3 detection-accuracy-v1 BUG-20 introduces this
/// plural API; the singular [`find_definition`] is now a thin first-element
/// view over it for back-compat.
///
/// Result is sorted by canonical-def tier (src > non-test > test), then
/// path, then line — matching the ordering [`find_definition`] previously
/// used to choose its single winner.
pub fn find_definitions(
    symbol: &str,
    root: &Path,
    language: Option<&str>,
) -> TldrResult<Vec<Definition>> {
    let mut candidates: Vec<Definition> = Vec::new();

    for entry in walk_project(root)
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| is_source_file(e.path(), language))
    {
        if let Ok(Some(def)) = find_definition_in_file(symbol, entry.path(), language) {
            candidates.push(def);
        }
    }

    // Rank: tier 1 (non-test + src) > tier 2 (non-test) > tier 3 (test).
    // Sort key: (tier, path_str, line). Lower tier = higher priority.
    candidates.sort_by(|a, b| {
        let tier_a = canonical_def_tier(&a.file);
        let tier_b = canonical_def_tier(&b.file);
        tier_a
            .cmp(&tier_b)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok(candidates)
}

/// Compute the canonical-def ranking tier for a path.
///
/// Lower number = higher priority. See [`find_definition`] docs for the
/// full ranking rationale.
fn canonical_def_tier(path: &Path) -> u8 {
    if is_test_file_path(path) {
        // Tier 3: test file. Only picked when every match is in a test file.
        3
    } else if is_src_path(path) {
        // Tier 1: non-test file in a real source directory.
        1
    } else {
        // Tier 2: non-test file outside src/lib/main (examples/, scripts/, etc.)
        2
    }
}

/// Find definition of a symbol in a specific file
fn find_definition_in_file(
    symbol: &str,
    file_path: &Path,
    _language_str: Option<&str>,
) -> TldrResult<Option<Definition>> {
    // CF2-S19: a C++ header kept as `.h` (the common `tinyxml2.h` / `tinyxml2.cpp`
    // layout, and every header-only library such as fmt) is mapped to
    // `Language::C` by the bare-extension classifier `parse_file` uses. The C
    // grammar has no `class`/`struct`/`namespace`, so `class Foo : public Bar {…}`
    // error-recovers into a `function_definition` whose declarator is the bare
    // class name — and `check_cpp_definition` then reports the class as
    // `kind:function` carrying a MEMBER (e.g. the destructor) signature, since
    // the real `class_specifier` node never forms. Resolve the header's true
    // language via the shared AST-content-sniffing resolver
    // (`Language::resolve_header_language`, used by structure/extract/interface)
    // and parse with that grammar, so a C++ class/struct definition forms a
    // proper `class_specifier`/`struct_specifier` and carries its OWN kind +
    // signature. Non-`.h` paths and genuine pure-C headers are unaffected (the
    // resolver returns the same language as `from_path`).
    let lang_hint = Language::from_path_with_siblings(file_path);
    let parsed = crate::ast::parser::parse_file_with_lang(file_path, lang_hint)?;
    let (tree, source, language) = parsed;
    let source_bytes = source.as_bytes();

    // Search recursively through the AST for definition nodes
    let root = tree.root_node();
    find_definition_in_node(&root, symbol, source_bytes, language, file_path)
}

/// Recursively search for a definition in an AST node
fn find_definition_in_node(
    node: &Node,
    symbol: &str,
    source: &[u8],
    language: Language,
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    // Check if this node is a definition matching our symbol
    if let Some(def) = check_definition_node(node, symbol, source, language, file_path)? {
        return Ok(Some(def));
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(def) = find_definition_in_node(&child, symbol, source, language, file_path)? {
            return Ok(Some(def));
        }
    }

    Ok(None)
}

/// Check if a node is a definition of the target symbol
fn check_definition_node(
    node: &Node,
    symbol: &str,
    source: &[u8],
    language: Language,
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    match language {
        Language::Python => check_python_definition(node, symbol, source, file_path),
        Language::TypeScript | Language::JavaScript => {
            check_ts_definition(node, symbol, source, file_path)
        }
        Language::Go => check_go_definition(node, symbol, source, file_path),
        Language::Rust => check_rust_definition(node, symbol, source, file_path),
        // cpp-explain-refs-cleanup-v1 (BUG-CPP-P20-03): C/C++ qualified
        // function names (`XMLDocument::Parse`) were silently dropped
        // because no language arm was wired. The result was an empty
        // `definitions[]` even when a textually verified `function_definition`
        // for the symbol existed in the project. Route C++ and C to the
        // dedicated cpp definition matcher; the text-search + AST verifier
        // already enumerate references, so this only fills the
        // `definitions[]` array.
        Language::Cpp | Language::C => check_cpp_definition(node, symbol, source, file_path),
        // solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c M13):
        // Solidity definition detection. Symbols of interest:
        //   - `function_definition`        (with `name` field)
        //   - `modifier_definition`        (with `name` field)
        //   - `event_definition`           (with `name` field)
        //   - `error_declaration`          (with `name` field)
        //   - `contract_declaration`       (with `name` field)
        //   - `interface_declaration`      (with `name` field)
        //   - `library_declaration`        (with `name` field)
        //   - `struct_declaration`         (with `name` field)
        //   - `enum_declaration`           (with `name` field)
        //   - `state_variable_declaration` / `constant_variable_declaration`
        //
        // Without this arm, Solidity references previously returned
        // empty `definitions[]` because the symbol resolver fell
        // through to the `_ => Ok(None)` branch.
        Language::Solidity => check_solidity_definition(node, symbol, source, file_path),
        // RC8 (v0.5.0 R7 cluster[10], #56): Elixir definitions were never
        // harvested (the `_ => Ok(None)` arm), so `definitions[]` was always
        // empty for Elixir symbols — including zero-arity `def name do`,
        // whose def line was then classified as `read`. Wire the dedicated
        // Elixir definition matcher.
        Language::Elixir => check_elixir_definition(node, symbol, source, file_path),
        _ => Ok(None),
    }
}

/// Check if an Elixir node is a `def`/`defp`/`defmacro`/`defmacrop`
/// definition of the target symbol.
///
/// RC8 (v0.5.0 R7 cluster[10], #56). tree-sitter-elixir parses a definition
/// as a `call` node whose `target` field is the identifier `def`/`defp`/…
/// and whose `arguments` child holds the function name. There are two
/// shapes (verified by debug-parse):
///   * with-args: `arguments` contains a nested `call` whose `target` is the
///     function-name identifier (`def add(a, b) do` → `call(add, args)`).
///   * zero-arity: `arguments` contains the function-name `identifier`
///     DIRECTLY (`def get_csrf_token do` → bare `identifier`).
/// Both must be recognised. The matched name's position is recorded.
fn check_elixir_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    if node.kind() != "call" {
        return Ok(None);
    }
    // The `def`/… keyword is the `target` field.
    let target_text = node
        .child_by_field_name("target")
        .and_then(|t| t.utf8_text(source).ok())
        .unwrap_or("");
    let def_kind = match target_text {
        "def" | "defp" => DefinitionKind::Function,
        "defmacro" | "defmacrop" => DefinitionKind::Function,
        // fix-PW2-B-refs-elixir-defmodule (v0.5.0 BACKLOG): `defmodule Foo do`
        // is the same `call(target=defmodule, arguments=…)` shape, but its name
        // argument is an `alias` node (single leaf carrying the full dotted name,
        // e.g. `Plug.Conn` or a single-segment `NotSentError`). Without this arm
        // module-symbol queries fell through to `_ => Ok(None)`, leaving
        // `definitions[]` empty and `--include-definition` a no-op for modules.
        "defmodule" => DefinitionKind::Module,
        _ => return Ok(None),
    };

    // Locate the `arguments` child by KIND (it is not a named field).
    let mut cursor = node.walk();
    let args = node
        .children(&mut cursor)
        .find(|c| c.kind() == "arguments");
    let Some(args) = args else {
        return Ok(None);
    };

    // Inspect the first argument: a nested `call` (with-args) or a bare
    // `identifier` (zero-arity).
    let mut acursor = args.walk();
    for child in args.children(&mut acursor) {
        let name_node = match child.kind() {
            // with-args: def add(a, b) -> call(target=add, ...)
            "call" => child.child_by_field_name("target"),
            // zero-arity: def get_csrf_token -> bare identifier
            "identifier" => Some(child),
            // defmodule Plug.Conn -> the name is an `alias` leaf whose text is
            // the full (possibly dotted) module name. Matching the full alias
            // text mirrors the reference verifier's `node_text == symbol` exact
            // match, so `--include-definition` and `references[]` stay consistent.
            "alias" => Some(child),
            _ => None,
        };
        if let Some(name_node) = name_node {
            if name_node.utf8_text(source).unwrap_or("") == symbol {
                let signature = extract_signature(node, source, Language::Elixir);
                return Ok(Some(Definition {
                    file: file_path.to_path_buf(),
                    line: node.start_position().row + 1,
                    column: name_node.start_position().column + 1,
                    kind: def_kind,
                    signature,
                }));
            }
        }
        // Only the FIRST argument carries the name; stop after it.
        break;
    }
    Ok(None)
}

/// Check if a Solidity node is a definition of the target symbol.
fn check_solidity_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let kind = node.kind();
    let (def_kind, name_field) = match kind {
        "function_definition" | "modifier_definition" => {
            (DefinitionKind::Function, Some("name"))
        }
        "constructor_definition" => (DefinitionKind::Function, None),
        "event_definition" | "error_declaration" => {
            (DefinitionKind::Other, Some("name"))
        }
        "contract_declaration" => (DefinitionKind::Class, Some("name")),
        "interface_declaration" => (DefinitionKind::Class, Some("name")),
        "library_declaration" => (DefinitionKind::Class, Some("name")),
        "struct_declaration" => (DefinitionKind::Type, Some("name")),
        "enum_declaration" => (DefinitionKind::Type, Some("name")),
        "state_variable_declaration" => (DefinitionKind::Property, Some("name")),
        "constant_variable_declaration" => (DefinitionKind::Constant, Some("name")),
        _ => return Ok(None),
    };

    let Some(field) = name_field else { return Ok(None) };
    let Some(name_node) = node.child_by_field_name(field) else {
        return Ok(None);
    };
    if name_node.utf8_text(source).unwrap_or("") != symbol {
        return Ok(None);
    }
    let signature = extract_signature(node, source, Language::Solidity);
    Ok(Some(Definition {
        file: file_path.to_path_buf(),
        line: node.start_position().row + 1,
        column: name_node.start_position().column + 1,
        kind: def_kind,
        signature,
    }))
}

/// Check if a Python node is a definition of the target symbol
fn check_python_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let node_kind = node.kind();

    match node_kind {
        "function_definition" => {
            // def symbol(...):
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Python);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Function,
                        signature,
                    }));
                }
            }
        }
        "class_definition" => {
            // class Symbol:
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Python);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Class,
                        signature,
                    }));
                }
            }
        }
        "assignment" | "expression_statement" => {
            // symbol = value (module-level assignment)
            // Check if parent is module (top-level)
            if let Some(parent) = node.parent() {
                if parent.kind() == "module" || parent.kind() == "expression_statement" {
                    // Look for identifier on left side
                    let target_node = if node_kind == "assignment" {
                        node.child_by_field_name("left")
                    } else {
                        // expression_statement wraps assignment
                        node.child(0).and_then(|c| c.child_by_field_name("left"))
                    };

                    if let Some(left) = target_node {
                        if left.kind() == "identifier"
                            && left.utf8_text(source).unwrap_or("") == symbol
                        {
                            return Ok(Some(Definition {
                                file: file_path.to_path_buf(),
                                line: left.start_position().row + 1,
                                column: left.start_position().column + 1,
                                kind: DefinitionKind::Variable,
                                signature: None,
                            }));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Check if a TypeScript/JavaScript node is a definition of the target symbol
fn check_ts_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let node_kind = node.kind();

    match node_kind {
        "function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::TypeScript);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Function,
                        signature,
                    }));
                }
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::TypeScript);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Class,
                        signature,
                    }));
                }
            }
        }
        "variable_declarator" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    // Determine if const (constant) or let/var (variable)
                    let kind = if let Some(parent) = node.parent() {
                        if let Some(gp) = parent.parent() {
                            let decl_text = gp.utf8_text(source).unwrap_or("");
                            if decl_text.starts_with("const") {
                                DefinitionKind::Constant
                            } else {
                                DefinitionKind::Variable
                            }
                        } else {
                            DefinitionKind::Variable
                        }
                    } else {
                        DefinitionKind::Variable
                    };

                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: name_node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind,
                        signature: None,
                    }));
                }
            }
        }
        "type_alias_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::TypeScript);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::TypeScript);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        // cl4-interface-v1 (IT3-javascript-03, GH #78): member-assignment of
        // a function — `app.defaultConfiguration = function () { ... }` /
        // `Foo.prototype.bar = function bar() { ... }`. This is how pre-ES6
        // modules (Express, much of node core) declare their public API. The
        // canonical-definition resolver had no arm for `assignment_expression`
        // whose left side is a `member_expression` and whose right side is a
        // function value, so `references` returned `definitions: []` for every
        // such symbol even though `structure` / `extract` / `interface` all
        // report it. Match AST-driven: left = `member_expression` (or
        // `subscript_expression`), right = `function_expression` /
        // `arrow_function` / `function`, and the assigned member name (the
        // `property` field, or the named function's own `name`) equals the
        // target symbol. The definition site is anchored at the member name.
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(left), Some(right)) = (left, right) {
                let right_is_function = matches!(
                    right.kind(),
                    "function_expression" | "arrow_function" | "function" | "generator_function"
                );
                if right_is_function {
                    // The assigned member name comes from the `property`
                    // field of a `member_expression` left-hand side
                    // (`app.NAME = ...` / `Foo.prototype.NAME = ...`).
                    let member_name_node = match left.kind() {
                        "member_expression" => left.child_by_field_name("property"),
                        _ => None,
                    };
                    if let Some(name_node) = member_name_node {
                        if name_node.utf8_text(source).unwrap_or("") == symbol {
                            let signature =
                                extract_signature(&right, source, Language::TypeScript);
                            return Ok(Some(Definition {
                                file: file_path.to_path_buf(),
                                line: name_node.start_position().row + 1,
                                column: name_node.start_position().column + 1,
                                kind: DefinitionKind::Function,
                                signature,
                            }));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Check if a Go node is a definition of the target symbol
fn check_go_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let node_kind = node.kind();

    match node_kind {
        "function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Go);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Function,
                        signature,
                    }));
                }
            }
        }
        "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Go);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Method,
                        signature,
                    }));
                }
            }
        }
        "type_declaration" | "type_spec" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Go);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Check if a Rust node is a definition of the target symbol
fn check_rust_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let node_kind = node.kind();

    match node_kind {
        "function_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Function,
                        signature,
                    }));
                }
            }
        }
        "struct_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        "enum_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        "const_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Constant,
                        signature,
                    }));
                }
            }
        }
        "static_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Variable,
                        signature,
                    }));
                }
            }
        }
        "type_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Rust);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Check if a C/C++ node is a definition of the target symbol.
///
/// cpp-explain-refs-cleanup-v1 (BUG-CPP-P20-03): C++ definitions appear
/// under several AST shapes that differ from Python/Go/Rust:
///
/// * Out-of-class definitions: `function_definition` whose declarator
///   chain (`function_declarator` → optional `pointer_declarator`/
///   `reference_declarator` → `qualified_identifier`) names
///   `XMLDocument::Parse`.
/// * In-class inline methods: `function_definition` whose declarator
///   chain ends at a bare `field_identifier` / `identifier` named
///   `Parse`. We accept both the qualified form and the bare leaf name
///   here so callers can search by either spelling.
/// * Pure declarations in headers / class bodies:
///   `declaration` -> `function_declarator` … (used when the .cpp pairs
///   with a forward declaration). The same matcher handles them.
/// * Type definitions: `class_specifier`, `struct_specifier`,
///   `union_specifier`, `enum_specifier`, `namespace_definition` —
///   their `name` field carries a `type_identifier`/`identifier`.
fn check_cpp_definition(
    node: &Node,
    symbol: &str,
    source: &[u8],
    file_path: &Path,
) -> TldrResult<Option<Definition>> {
    let node_kind = node.kind();

    match node_kind {
        "function_definition" => {
            // CFr-RW2: a macro/attribute-decorated class declaration such as
            // `class TINYXML2_LIB XMLNode { … };` error-recovers in
            // tree-sitter-cpp into a `function_definition` whose `type` is the
            // (macro-named) `class_specifier` and whose `declarator` is the
            // BARE class-name identifier — the export/visibility macro is
            // absorbed as the class_specifier's `name`, and the real class
            // name lands in the declarator. A genuine function always carries a
            // `function_declarator` (parameter list); a plain `identifier`
            // declarator under a class/struct/union specifier type is therefore
            // this misparse. Classify it by the class keyword (kind:class)
            // instead of the catch-all `function`.
            if let Some(type_node) = node.child_by_field_name("type") {
                if matches!(
                    type_node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                ) {
                    if let Some(decl) = node.child_by_field_name("declarator") {
                        if decl.kind() == "identifier"
                            && decl.utf8_text(source).unwrap_or("") == symbol
                        {
                            let signature = extract_signature(node, source, Language::Cpp);
                            return Ok(Some(Definition {
                                file: file_path.to_path_buf(),
                                line: node.start_position().row + 1,
                                column: decl.start_position().column + 1,
                                kind: DefinitionKind::Class,
                                signature,
                            }));
                        }
                    }
                }
            }
            if let Some(decl) = node.child_by_field_name("declarator") {
                if let Some((line, column)) =
                    find_cpp_declarator_match(&decl, symbol, source)
                {
                    let signature = extract_signature(node, source, Language::Cpp);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line,
                        column,
                        kind: DefinitionKind::Function,
                        signature,
                    }));
                }
            }
        }
        "declaration" => {
            // Pure declaration (no body) — e.g. forward declaration in a
            // header. tree-sitter-cpp wraps the function_declarator in a
            // top-level `declaration` here, so the field-based walk above
            // does not find it on this node directly.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "function_declarator" {
                    if let Some((line, column)) =
                        find_cpp_declarator_match(&child, symbol, source)
                    {
                        let signature = extract_signature(node, source, Language::Cpp);
                        return Ok(Some(Definition {
                            file: file_path.to_path_buf(),
                            line,
                            column,
                            kind: DefinitionKind::Function,
                            signature,
                        }));
                    }
                }
            }
        }
        "class_specifier" | "struct_specifier" | "union_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Cpp);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Class,
                        signature,
                    }));
                }
            }
        }
        "enum_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Cpp);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Type,
                        signature,
                    }));
                }
            }
        }
        "namespace_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.utf8_text(source).unwrap_or("") == symbol {
                    let signature = extract_signature(node, source, Language::Cpp);
                    return Ok(Some(Definition {
                        file: file_path.to_path_buf(),
                        line: node.start_position().row + 1,
                        column: name_node.start_position().column + 1,
                        kind: DefinitionKind::Other,
                        signature,
                    }));
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Walk a C++ declarator chain looking for the leaf name that equals
/// `symbol`. Accepts both the qualified form (`XMLDocument::Parse`) and
/// the bare leaf form (`Parse`); the qualified form is the canonical
/// spelling consumers ask for. Returns `(line, column)` of the leaf name
/// node so the resulting `Definition` carries 1-indexed positions
/// identical to the other language arms.
fn find_cpp_declarator_match(
    decl: &Node,
    symbol: &str,
    source: &[u8],
) -> Option<(usize, usize)> {
    let kind = decl.kind();
    match kind {
        "function_declarator" => {
            // The function_declarator wraps the actual name in its
            // `declarator` field — recurse so qualified / pointer /
            // reference wrappers all funnel into the leaf handlers.
            if let Some(inner) = decl.child_by_field_name("declarator") {
                return find_cpp_declarator_match(&inner, symbol, source);
            }
        }
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => {
            if let Some(inner) = decl.child_by_field_name("declarator") {
                return find_cpp_declarator_match(&inner, symbol, source);
            }
        }
        "qualified_identifier" | "scoped_identifier" => {
            // Compare both the full qualified text (`XMLDocument::Parse`)
            // and the trailing name segment (`Parse`) so callers can use
            // either spelling.
            let full = decl.utf8_text(source).unwrap_or("");
            if full == symbol {
                return Some((
                    decl.start_position().row + 1,
                    decl.start_position().column + 1,
                ));
            }
            if let Some(name) = decl.child_by_field_name("name") {
                let name_text = name.utf8_text(source).unwrap_or("");
                if name_text == symbol {
                    return Some((
                        name.start_position().row + 1,
                        name.start_position().column + 1,
                    ));
                }
                // The trailing name field may itself be another
                // qualified_identifier (template-nested names); recurse.
                if name.kind() == "qualified_identifier" {
                    if let Some(pos) = find_cpp_declarator_match(&name, symbol, source) {
                        return Some(pos);
                    }
                }
            }
        }
        "identifier" | "field_identifier" | "destructor_name" | "operator_name" => {
            let text = decl.utf8_text(source).unwrap_or("");
            if text == symbol {
                return Some((
                    decl.start_position().row + 1,
                    decl.start_position().column + 1,
                ));
            }
        }
        _ => {}
    }
    None
}

/// Extract function/class signature from AST node
///
/// Returns the first line of the definition as the signature:
/// - Python: "def login(username, password):" or "class User:"
/// - TypeScript: "function login(username: string): boolean"
/// - Go: "func Login(username string) bool"
/// - Rust: "pub fn login(username: &str) -> bool"
fn extract_signature(node: &Node, source: &[u8], _language: Language) -> Option<String> {
    let node_text = node.utf8_text(source).ok()?;

    // Get the first line of the definition
    let first_line = node_text.lines().next()?;

    // Truncate if too long
    let signature = if first_line.len() > MAX_CONTEXT_LENGTH {
        format!("{}...", &first_line[..MAX_CONTEXT_LENGTH - 3])
    } else {
        first_line.to_string()
    };

    Some(signature.trim().to_string())
}

/// Main entry point for reference finding (text search + AST verification)
///
/// # Arguments
///
/// * `symbol` - The symbol name to search for
/// * `root` - The root directory to search in
/// * `options` - Configuration options for the search
///
/// # Returns
///
/// A ReferencesReport containing all found references with statistics.
///
/// # Phases
///
/// - Phase 9: Text search for candidates
/// - Phase 10: AST verification and kind classification
/// - Phase 11: Definition tracking and cross-file references
pub fn find_references(
    symbol: &str,
    root: &Path,
    options: &ReferencesOptions,
) -> TldrResult<ReferencesReport> {
    let start = std::time::Instant::now();

    let language = options.language.as_deref();

    // Phase 13: Determine search scope based on symbol visibility
    // If scope is explicitly set in options, use it; otherwise auto-detect
    let effective_scope = if options.scope != SearchScope::Workspace {
        // User explicitly set a non-default scope
        options.scope
    } else if let Some(lang) = language {
        // Auto-detect scope based on symbol naming conventions
        determine_search_scope(symbol, options.definition_file.as_deref(), lang)
    } else {
        SearchScope::Workspace
    };

    // Step 1: Text search for candidates (Phase 9)
    let candidates = find_text_candidates(symbol, root, language)?;
    let candidates_found = candidates.len();

    // Phase 13: Apply scope filter before AST verification (for performance)
    let scoped_candidates = apply_scope_filter(
        candidates,
        effective_scope,
        options.definition_file.as_deref(),
    );

    // Step 2: AST verification and kind classification (Phase 10)
    let verified = verify_candidates_with_ast(&scoped_candidates, symbol, language);

    // Step 3: Convert verified references to Reference structs
    let mut references: Vec<Reference> = verified
        .into_iter()
        .map(|(candidate, verified_ref)| Reference {
            file: candidate.file,
            line: candidate.line,
            column: candidate.column,
            kind: verified_ref.kind,
            context: truncate_context(candidate.line_text),
            confidence: Some(verified_ref.confidence),
            end_column: Some(candidate.end_column),
        })
        .collect();

    // Step 4: Find definitions (Phase 11)
    // M3 detection-accuracy-v1 BUG-20: collect ALL definitions, not just the
    // first one. `definition` (singular) is preserved for back-compat as the
    // first entry; `definitions` (plural) carries the full set.
    let mut definitions = find_definitions(symbol, root, language)?;

    // AGG13-14 (quality-metrics-and-schema-v1): `find_definitions` only
    // implements per-language definition detection for python/ts/js/go/rust.
    // For java, csharp, ocaml (and other unimplemented languages),
    // `definitions[]` was always empty even when the AST verifier already
    // classified one of the verified references as `kind=Definition`.
    // The schema invariant "every definition appears in `definitions[]`"
    // was therefore violated for those languages. Promote any
    // `kind=Definition` reference into `definitions[]` when
    // `find_definitions` did not already report it (matched by file+line).
    // We deliberately keep the original `references[]` entry intact for
    // back-compat with downstream consumers that already iterated the
    // unified list.
    // m116-easy-mechanical-v1 (#41): the fallback below hardcoded
    // `DefinitionKind::Function`, which mislabelled class / struct /
    // interface / enum / trait declarations as "function" for every
    // unsupported language (java, csharp, kotlin, scala, swift, …).
    // Classify each promoted definition by re-parsing the file and
    // walking the AST up from the (line, column) byte position to the
    // enclosing declaration node, then mapping the node kind to a
    // `DefinitionKind`.
    let mut file_parse_cache: HashMap<PathBuf, (tree_sitter::Tree, String, Language)> = HashMap::new();
    for r in &references {
        if r.kind != ReferenceKind::Definition {
            continue;
        }
        let already = definitions
            .iter()
            .any(|d| d.file == r.file && d.line == r.line);
        if already {
            continue;
        }
        let kind = classify_promoted_definition_kind(&r.file, r.line, r.column, &mut file_parse_cache)
            .unwrap_or(DefinitionKind::Other);
        definitions.push(Definition::new(r.file.clone(), r.line, r.column, kind));
    }

    // W2-16: exclude Elixir references whose MODULE QUALIFIER names a different
    // module than the queried definition. A bare `references underscore` query
    // for `Phoenix.Naming.underscore/1` previously reported unrelated
    // `Macro.underscore(...)` call sites as confidence=1.0 references because
    // the Elixir `dot` arm matched only the leaf identifier.
    filter_elixir_foreign_qualified_refs(&mut references, &definitions, &mut file_parse_cache);

    // RC7 (v0.5.0 R3): exclude OCaml references whose MODULE QUALIFIER names a
    // DIFFERENT module than the queried definition. A bare-name `references
    // lock` query over `ocaml-lwt` previously reported six stdlib `Mutex.lock`
    // call sites (and any other `Foo.lock`) as confident references to the
    // project def `Lwt_mutex.lock`, because the verifier matched purely on the
    // `value_name` leaf (`lock`) and never read the `module_path` qualifier.
    //
    // Discriminator (root-cause, AST): the leftmost `module_name` head of the
    // qualifier must equal the owning module of one of the queried
    // definitions (the file-stem-derived OCaml module name). A bare/local ref
    // (no qualifier — opened or same-module) is always kept; a qualifier
    // naming the def's own module (`Lwt_mutex.lock`) is kept; a qualifier
    // naming stdlib/another module (`Mutex.lock`) is dropped.
    filter_ocaml_foreign_qualified_refs(&mut references, &definitions, &mut file_parse_cache);

    let definition = definitions.first().cloned();

    // Apply kind filter if specified (Phase 13)
    if let Some(ref kinds) = options.kinds {
        references.retain(|r| kinds.contains(&r.kind));
    }

    // CL-1 / GH #74: sort references into a stable total order BEFORE the
    // truncation below. The reference list is assembled from a directory
    // walk and per-file line scan; even with the walker now yielding files
    // in path order, an explicit sort on the reference identity tuple is
    // the contract that guarantees:
    //   1. byte-identical output run-to-run, and
    //   2. `--limit N` drops the TAIL of a fixed ordering rather than
    //      returning a different SUBSET each run (the silent-data-loss
    //      bug — two runs previously surfaced disjoint references for the
    //      same symbol under the same cap).
    // A reference is uniquely located by (file, line, column); we add
    // `end_column` purely as a final deterministic tiebreaker for the
    // pathological case of two zero-width matches at the same position.
    references.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.end_column.cmp(&b.end_column))
    });

    // Capture the full verified count BEFORE truncation so callers/UI can
    // report "showing 20 of 337" honestly. Pre-`references-canonical-def-v1`
    // `total_references` was set to the truncated length, which made the
    // default `--limit 20` look like the symbol only had 20 references on
    // the planet. (See changelog: investigation step "why is ref count
    // 20 (low)?".)
    let total_verified = references.len();

    // Apply limit if specified.
    // med-low-schema-cleanup-v1 (N6): record whether truncation actually
    // dropped any references and how many we ended up returning so the
    // CLI/JSON output can carry honest truncation metadata. Mirrors
    // the `calls` schema (truncated / total_edges / shown_edges).
    let truncated = options.limit.is_some_and(|l| total_verified > l);
    if let Some(limit) = options.limit {
        references.truncate(limit);
    }
    let shown_references = references.len();

    let files_searched = count_source_files(root, language);

    let stats = ReferenceStats {
        files_searched,
        candidates_found,
        verified_references: total_verified,
        search_time_ms: start.elapsed().as_millis() as u64,
    };

    Ok(ReferencesReport {
        symbol: symbol.to_string(),
        definition,
        definitions,
        references,
        total_references: total_verified,
        shown_references,
        truncated,
        search_scope: effective_scope, // Use the effective scope (auto-detected or explicit)
        stats,
    })
}

// =============================================================================
// Phase 13: Advanced Features - Search Scope Optimization & Kind Filtering
// =============================================================================

/// Determine optimal search scope based on symbol visibility
///
/// This function infers the appropriate search scope based on:
/// - Python: `_prefix` = File scope, `__dunder__` = Workspace, normal = Workspace
/// - TypeScript: non-exported = File scope, exported = Workspace
/// - Go: lowercase = File (package-private), uppercase = Workspace
/// - Rust: pub = Workspace, pub(crate) = Workspace, private = File
///
/// # Arguments
///
/// * `symbol` - The symbol name to analyze
/// * `definition_file` - Optional path to the file containing the definition
/// * `language` - The programming language (e.g., "python", "typescript", "go", "rust")
///
/// # Returns
///
/// The inferred `SearchScope` for the symbol.
///
/// # Phase 13 Risks Addressed
///
/// - S7-R19: SearchScope Go package - handles Go visibility
/// - S7-R29: Private class methods - conservative: if unsure, use Workspace
/// - S7-R30: Rust pub(crate)/pub(super) - maps to appropriate scope
pub fn determine_search_scope(
    symbol: &str,
    definition_file: Option<&Path>,
    language: &str,
) -> SearchScope {
    match language.to_lowercase().as_str() {
        "python" => determine_python_scope(symbol, definition_file),
        "typescript" | "javascript" => determine_ts_scope(symbol, definition_file),
        "go" => determine_go_scope(symbol, definition_file),
        "rust" => determine_rust_scope(symbol, definition_file),
        _ => SearchScope::Workspace, // Conservative default
    }
}

/// Determine Python scope based on naming conventions
///
/// - `_single_underscore` = private by convention = File scope
/// - `__dunder__` = special methods = Workspace scope (implicit calls)
/// - `__name_mangled` (double underscore, no trailing) = File scope
/// - Other = Workspace scope
fn determine_python_scope(symbol: &str, _definition_file: Option<&Path>) -> SearchScope {
    // __dunder__ methods are special - they're called implicitly
    if symbol.starts_with("__") && symbol.ends_with("__") {
        return SearchScope::Workspace;
    }

    // __name_mangled (double underscore without trailing) = private
    if symbol.starts_with("__") && !symbol.ends_with("__") {
        return SearchScope::File;
    }

    // _single_underscore = private by convention
    if symbol.starts_with('_') && !symbol.starts_with("__") {
        return SearchScope::File;
    }

    // Default: public symbol
    SearchScope::Workspace
}

/// Determine TypeScript/JavaScript scope
///
/// Without parsing the file, we can't know if a symbol is exported.
/// Conservative approach: assume Workspace scope.
fn determine_ts_scope(_symbol: &str, _definition_file: Option<&Path>) -> SearchScope {
    // TODO: Parse definition_file to check for export keyword
    // For now, be conservative and search workspace
    SearchScope::Workspace
}

/// Determine Go scope based on capitalization
///
/// - Uppercase first letter = exported = Workspace
/// - Lowercase first letter = package-private = File (approximation)
fn determine_go_scope(symbol: &str, _definition_file: Option<&Path>) -> SearchScope {
    if let Some(first_char) = symbol.chars().next() {
        if first_char.is_uppercase() {
            return SearchScope::Workspace;
        }
        // Lowercase = package-private, approximate as File scope
        return SearchScope::File;
    }
    SearchScope::Workspace
}

/// Determine Rust scope based on naming (conservative)
///
/// Without parsing the file, we can't know visibility modifiers.
/// Conservative approach: assume Workspace scope.
fn determine_rust_scope(_symbol: &str, _definition_file: Option<&Path>) -> SearchScope {
    // TODO: Parse definition_file to check pub/pub(crate)/private
    // For now, be conservative and search workspace
    SearchScope::Workspace
}

/// Apply scope filtering to text search candidates
///
/// Filters candidates based on the search scope:
/// - `Local`: Only candidates in the same file (TODO: same function)
/// - `File`: Only candidates in the definition file
/// - `Workspace`: No filtering, return all candidates
///
/// # Arguments
///
/// * `candidates` - Vector of text search candidates
/// * `scope` - The search scope to apply
/// * `definition_file` - The file containing the symbol definition
///
/// # Returns
///
/// Filtered vector of candidates matching the scope.
pub fn apply_scope_filter(
    candidates: Vec<TextCandidate>,
    scope: SearchScope,
    definition_file: Option<&Path>,
) -> Vec<TextCandidate> {
    match scope {
        SearchScope::Workspace => candidates, // No filter
        SearchScope::File => {
            if let Some(def_file) = definition_file {
                candidates
                    .into_iter()
                    .filter(|c| c.file == def_file)
                    .collect()
            } else {
                candidates // Can't filter without definition file
            }
        }
        SearchScope::Local => {
            // Local scope: restrict to same file
            // TODO: Further restrict to same function/block
            if let Some(def_file) = definition_file {
                candidates
                    .into_iter()
                    .filter(|c| c.file == def_file)
                    .collect()
            } else {
                candidates
            }
        }
    }
}

/// Filter references by allowed kinds
///
/// Returns only references whose kind is in the allowed_kinds list.
///
/// # Arguments
///
/// * `references` - Vector of references to filter
/// * `allowed_kinds` - Slice of allowed ReferenceKind values
///
/// # Returns
///
/// Filtered vector containing only references with allowed kinds.
///
/// # Example
///
/// ```ignore
/// let filtered = filter_by_kinds(refs, &[ReferenceKind::Call, ReferenceKind::Import]);
/// ```
pub fn filter_by_kinds(
    references: Vec<Reference>,
    allowed_kinds: &[ReferenceKind],
) -> Vec<Reference> {
    references
        .into_iter()
        .filter(|r| allowed_kinds.contains(&r.kind))
        .collect()
}

/// Get incoming calls (who calls this function)
///
/// This is a basic call hierarchy feature that finds all locations
/// where the specified symbol is called.
///
/// # Arguments
///
/// * `symbol` - The function/method name to find callers for
/// * `root` - The root directory to search in
/// * `options` - Reference finding options
///
/// # Returns
///
/// Vector of References with kind == Call
pub fn get_incoming_calls(
    symbol: &str,
    root: &Path,
    options: &ReferencesOptions,
) -> TldrResult<Vec<Reference>> {
    let report = find_references(symbol, root, options)?;
    Ok(report
        .references
        .into_iter()
        .filter(|r| r.kind == ReferenceKind::Call)
        .collect())
}

/// Get outgoing calls (what this function calls)
///
/// This finds all function calls made within a specific function.
/// Uses the AST to find all call expressions within the function body.
///
/// # Arguments
///
/// * `file` - Path to the file containing the function
/// * `function` - Name of the function to analyze
///
/// # Returns
///
/// Vector of function names that are called by the specified function.
///
/// # Note
///
/// This is a simplified implementation. For full call graph analysis,
/// use the `tldr calls` command infrastructure.
pub fn get_outgoing_calls(file: &Path, function: &str) -> TldrResult<Vec<String>> {
    use crate::ast::parser::parse_file;

    let (tree, source, language) = parse_file(file)?;
    let source_bytes = source.as_bytes();

    // Find the function node and extract calls in one pass
    let root = tree.root_node();
    let calls = find_and_extract_calls(&root, function, source_bytes, language);
    Ok(calls)
}

/// Find a function by name and extract all calls from it
///
/// Combines function finding and call extraction to avoid lifetime issues.
fn find_and_extract_calls(
    node: &tree_sitter::Node,
    function_name: &str,
    source: &[u8],
    language: Language,
) -> Vec<String> {
    let node_kind = node.kind();

    // Check if this is a function definition with matching name
    let is_function = ast_utils::function_node_kinds(language).contains(&node_kind);

    if is_function {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.utf8_text(source).unwrap_or("") == function_name {
                // Found the function, extract all calls from it
                let mut calls = Vec::new();
                extract_calls_recursive(node, source, language, &mut calls);
                return calls;
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let calls = find_and_extract_calls(&child, function_name, source, language);
        if !calls.is_empty() {
            return calls;
        }
    }

    Vec::new()
}

/// Recursively extract call expressions from a node
fn extract_calls_recursive(
    node: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    calls: &mut Vec<String>,
) {
    let node_kind = node.kind();

    // Check if this is a call expression
    let is_call = ast_utils::call_node_kinds(language).contains(&node_kind);

    if is_call {
        // Extract the function name being called
        if let Some(func_node) = node.child_by_field_name("function") {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            // For simple identifiers, use as-is; for member access, extract the method name
            let call_name = if func_text.contains('.') {
                func_text.rsplit('.').next().unwrap_or(func_text)
            } else {
                func_text
            };
            if !call_name.is_empty() {
                calls.push(call_name.to_string());
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_calls_recursive(&child, source, language, calls);
    }
}

// =============================================================================
// m116-easy-mechanical-v1 (#41): AST-based classifier for definitions
// promoted from `kind=Definition` references.
//
// `find_definitions` only has per-language arms for python / ts / js /
// go / rust / c / cpp. For java / csharp / kotlin / scala / swift the
// AST verifier already classifies one of the matched references as
// `kind=Definition`, but the promotion path previously hardcoded
// `DefinitionKind::Function`. That mis-labelled every class / struct /
// interface / enum / trait definition. Re-parse the file once
// (cached) and map the enclosing declaration node's kind to a
// `DefinitionKind`.
// =============================================================================

/// Re-parse `file` (cached across the loop) and classify the
/// declaration node that contains the byte position at
/// (`line`, `column`). Returns `None` if the file is unparseable, the
/// language is unsupported, or no enclosing declaration node exists.
/// RC7 (v0.5.0 R3): derive the OCaml module name that a file defines.
///
/// OCaml's compilation-unit convention maps `foo_bar.ml` to module `Foo_bar`
/// (capitalize the FIRST character of the stem only). This is the owning
/// module against which a reference's `module_path` qualifier head is compared.
fn ocaml_module_name_from_path(file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_string_lossy();
    let mut chars = stem.chars();
    let first = chars.next()?;
    Some(first.to_uppercase().collect::<String>() + chars.as_str())
}

fn elixir_alias_text(node: &Node, source: &[u8]) -> Option<String> {
    if node.kind() != "alias" {
        return None;
    }
    let text = node.utf8_text(source).ok()?.trim();
    if text.chars().next().is_some_and(|c| c.is_uppercase()) {
        Some(text.to_string())
    } else {
        None
    }
}

fn elixir_reference_qualifier_head(leaf_node: &Node, source: &[u8]) -> Option<String> {
    let dot = leaf_node.parent()?;
    if dot.kind() != "dot" {
        return None;
    }
    let mut cursor = dot.walk();
    let mut named = dot.named_children(&mut cursor);
    let left = named.next()?;
    let right = named.next()?;
    if right.id() != leaf_node.id() {
        return None;
    }
    elixir_alias_text(&left, source)
}

fn elixir_defmodule_name_from_call(call: &Node, source: &[u8]) -> Option<String> {
    if call.kind() != "call" {
        return None;
    }
    let target = call
        .child_by_field_name("target")
        .and_then(|t| t.utf8_text(source).ok())?;
    if target != "defmodule" {
        return None;
    }
    let mut cursor = call.walk();
    let args = call.children(&mut cursor).find(|c| c.kind() == "arguments")?;
    let mut acursor = args.walk();
    for child in args.named_children(&mut acursor) {
        return elixir_alias_text(&child, source);
    }
    None
}

fn elixir_definition_enclosing_module(
    definition: &Definition,
    cache: &mut HashMap<PathBuf, (tree_sitter::Tree, String, Language)>,
) -> Option<String> {
    if !cache.contains_key(&definition.file) {
        let parsed = parse_file(&definition.file).ok()?;
        cache.insert(definition.file.clone(), parsed);
    }
    let (tree, source, language) = cache.get(&definition.file)?;
    if *language != Language::Elixir {
        return None;
    }
    let row = definition.line.saturating_sub(1);
    let col = definition.column.saturating_sub(1);
    let pt = tree_sitter::Point { row, column: col };
    let mut current = tree
        .root_node()
        .named_descendant_for_point_range(pt, pt);
    while let Some(node) = current {
        if let Some(module) = elixir_defmodule_name_from_call(&node, source.as_bytes()) {
            return Some(module);
        }
        current = node.parent();
    }
    None
}

fn filter_elixir_foreign_qualified_refs(
    references: &mut Vec<Reference>,
    definitions: &[Definition],
    cache: &mut HashMap<PathBuf, (tree_sitter::Tree, String, Language)>,
) {
    let def_modules: std::collections::HashSet<String> = definitions
        .iter()
        .filter_map(|d| elixir_definition_enclosing_module(d, cache))
        .collect();
    if def_modules.is_empty() {
        return;
    }

    references.retain(|r| {
        if r.kind == ReferenceKind::Definition {
            return true;
        }
        if !cache.contains_key(&r.file) {
            match parse_file(&r.file) {
                Ok(parsed) => {
                    cache.insert(r.file.clone(), parsed);
                }
                Err(_) => return true,
            }
        }
        let (tree, source, language) = match cache.get(&r.file) {
            Some(p) => p,
            None => return true,
        };
        if *language != Language::Elixir {
            return true;
        }
        let row = r.line.saturating_sub(1);
        let col = r.column.saturating_sub(1);
        let pt = tree_sitter::Point { row, column: col };
        let leaf = match tree
            .root_node()
            .named_descendant_for_point_range(pt, pt)
        {
            Some(n) => n,
            None => return true,
        };
        match elixir_reference_qualifier_head(&leaf, source.as_bytes()) {
            Some(head) => def_modules.contains(&head),
            None => true,
        }
    });
}

/// RC7 (v0.5.0 R3): drop OCaml references whose qualifier names a module other
/// than the queried definition's owning module.
///
/// See the call site in [`find_references`]. Bare/local references (no
/// qualifier) and references qualified by the def's own module are retained;
/// references qualified by stdlib/another module are removed. Non-OCaml files
/// and references without a qualifier are never affected, so this is fully
/// language-gated.
fn filter_ocaml_foreign_qualified_refs(
    references: &mut Vec<Reference>,
    definitions: &[Definition],
    cache: &mut HashMap<PathBuf, (tree_sitter::Tree, String, Language)>,
) {
    // Owning modules of the queried definition(s).
    let def_modules: std::collections::HashSet<String> = definitions
        .iter()
        .filter_map(|d| ocaml_module_name_from_path(&d.file))
        .collect();
    if def_modules.is_empty() {
        return;
    }

    references.retain(|r| {
        // Only OCaml definitions are ever harvested into `def_modules`; gate on
        // the file actually parsing as OCaml below. Keep every Definition.
        if r.kind == ReferenceKind::Definition {
            return true;
        }
        if !cache.contains_key(&r.file) {
            match parse_file(&r.file) {
                Ok(parsed) => {
                    cache.insert(r.file.clone(), parsed);
                }
                Err(_) => return true, // unparseable — keep conservatively
            }
        }
        let (tree, source, language) = match cache.get(&r.file) {
            Some(p) => p,
            None => return true,
        };
        if *language != Language::Ocaml {
            return true;
        }
        let row = r.line.saturating_sub(1);
        let col = r.column.saturating_sub(1);
        let pt = tree_sitter::Point { row, column: col };
        let leaf = match tree
            .root_node()
            .named_descendant_for_point_range(pt, pt)
        {
            Some(n) => n,
            None => return true,
        };
        match ocaml_reference_qualifier_head(&leaf, source.as_bytes()) {
            // Qualified by a foreign module (stdlib `Mutex`, another project
            // module, an external opam package) — not a reference to THIS def.
            Some(head) => def_modules.contains(&head),
            // Bare/local reference — always kept.
            None => true,
        }
    });
}

fn classify_promoted_definition_kind(
    file: &Path,
    line: usize,
    column: usize,
    cache: &mut HashMap<PathBuf, (tree_sitter::Tree, String, Language)>,
) -> Option<DefinitionKind> {
    if !cache.contains_key(file) {
        let parsed = parse_file(file).ok()?;
        cache.insert(file.to_path_buf(), parsed);
    }
    let (tree, source, language) = cache.get(file)?;

    let row = line.saturating_sub(1);
    let col = column.saturating_sub(1);
    let pt = tree_sitter::Point {
        row,
        column: col,
    };
    let root = tree.root_node();
    let smallest = root.named_descendant_for_point_range(pt, pt)?;

    // CFr-RW2: a Swift type declaration the grammar error-recovered (its name
    // buried in an `ERROR` trailing the recovered `class`/`struct`/`enum`/
    // `actor` keyword) never forms a `class_declaration`, so the generic
    // ancestor walk below would classify it by the wrapping
    // `function_declaration` (→ `function`). Classify by the recovered keyword
    // instead.
    if *language == Language::Swift {
        if let Some(k) = swift_recovered_type_def_kind(&smallest) {
            return Some(k);
        }
    }

    // Walk up to the first declaration-shaped ancestor.
    let mut current = Some(smallest);
    while let Some(node) = current {
        if let Some(k) = decl_node_to_definition_kind(&node, *language) {
            return Some(k);
        }
        // Also accept a name-field match: an enclosing decl whose
        // `name` child contains the position should be classified by
        // the decl's kind.
        current = node.parent();
    }
    // Fallback: walk the AST top-down looking for a declaration node
    // whose start_position equals our (line, column) — covers cases
    // where the verified-reference column points at the IDENTIFIER
    // child (not the decl node itself).
    walk_for_decl_containing(&root, row, col, *language, source.as_bytes())
}

fn walk_for_decl_containing(
    node: &Node,
    row: usize,
    col: usize,
    language: Language,
    _source: &[u8],
) -> Option<DefinitionKind> {
    let start = node.start_position();
    let end = node.end_position();
    let in_range = (start.row < row || (start.row == row && start.column <= col))
        && (end.row > row || (end.row == row && end.column >= col));
    if !in_range {
        return None;
    }

    let mut best: Option<DefinitionKind> = decl_node_to_definition_kind(node, language);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(child_kind) = walk_for_decl_containing(&child, row, col, language, _source) {
            best = Some(child_kind);
        }
    }
    best
}

/// Map a tree-sitter declaration node kind to a `DefinitionKind`.
///
/// Covers the broad set of declaration kinds emitted by the grammars
/// of the 18 TLDR-supported languages. Returns `None` for non-decl
/// node kinds — callers walk up to the next ancestor.
fn node_kind_to_definition_kind(kind: &str, _language: Language) -> Option<DefinitionKind> {
    let dk = match kind {
        // Functions
        "function_item"
        | "function_definition"
        | "function_declaration"
        | "function_declarator"
        | "function" => DefinitionKind::Function,
        // Methods
        "method_declaration"
        | "method_definition"
        | "method_spec"
        | "constructor_declaration"
        | "destructor_declaration"
        | "method"
        | "secondary_constructor" => DefinitionKind::Method,
        // Classes / structs / interfaces / traits / enums
        "class_declaration"
        | "class_definition"
        | "class_specifier"
        | "class"
        | "object_declaration"
        | "object_definition"
        | "record_declaration" => DefinitionKind::Class,
        "struct_declaration"
        | "struct_item"
        | "struct_specifier" => DefinitionKind::Class,
        "interface_declaration"
        | "interface_definition"
        | "trait_item"
        | "trait_definition"
        | "protocol_declaration" => DefinitionKind::Class,
        "enum_item"
        | "enum_declaration"
        | "enum_definition"
        | "enum_specifier" => DefinitionKind::Class,
        // Types / type aliases
        "type_alias"
        | "type_alias_declaration"
        | "type_item"
        | "type_definition" => DefinitionKind::Type,
        // Constants
        "const_item" | "const_declaration" => DefinitionKind::Constant,
        // Variables (static / let / val / var bindings)
        "static_item" | "let_declaration" | "variable_declaration"
        | "lexical_declaration" | "property_declaration"
        | "field_declaration" | "field_definition" => DefinitionKind::Variable,
        // Modules / namespaces
        "mod_item" | "module_declaration" | "namespace_declaration" => {
            DefinitionKind::Module
        }
        _ => return None,
    };
    Some(dk)
}

/// Node-aware refinement of [`node_kind_to_definition_kind`].
///
/// Most declaration node kinds are fully decided by their bare kind string,
/// but a few grammars fold several declaration axes into a single node kind
/// disambiguated only by a child keyword token. CF2-S19: tree-sitter-swift
/// folds `struct` / `enum` / `actor` / `class` / `extension` into ONE
/// `class_declaration` node, so the string-keyed mapping conservatively
/// returns `Class`. Consult the leading keyword child here (mirroring
/// `entity::classify_node`) so a Swift struct/enum/actor definition reports
/// its own kind instead of the catch-all `"class"`.
fn decl_node_to_definition_kind(node: &Node, language: Language) -> Option<DefinitionKind> {
    if language == Language::Swift && node.kind() == "class_declaration" {
        return Some(swift_class_declaration_definition_kind(node));
    }
    node_kind_to_definition_kind(node.kind(), language)
}

/// Map a Swift `class_declaration` to the precise [`DefinitionKind`] implied
/// by its leading declaration keyword.
///
/// CF2-S19. tree-sitter-swift emits the keyword as a dedicated token child
/// (`struct` / `enum` / `actor` / `class`); `extension` carriers stay on the
/// class axis. Defaults to `Class` when no keyword child is found (defensive —
/// every well-formed `class_declaration` has one).
fn swift_class_declaration_definition_kind(node: &Node) -> DefinitionKind {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "struct" => return DefinitionKind::Struct,
            "enum" => return DefinitionKind::Enum,
            "actor" => return DefinitionKind::Actor,
            "class" | "extension" => return DefinitionKind::Class,
            _ => {}
        }
    }
    DefinitionKind::Class
}

/// CFr-RW2. Detect a tree-sitter-swift error-recovery of a
/// modifier/attribute-decorated type declaration and return the
/// [`DefinitionKind`] implied by its leading keyword.
///
/// When a declaration such as `open class Session: @unchecked Sendable { … }`
/// contains body syntax the grammar cannot model (e.g. a `#if canImport(…)`
/// conditional-compilation directive), tree-sitter does not form a
/// `class_declaration`. Instead the enclosing declaration keeps the bare
/// `class` / `struct` / `enum` / `actor` keyword token, and the type NAME is
/// buried as the FIRST named child of an `ERROR` node whose immediately
/// preceding sibling is that keyword token:
///
/// ```text
/// function_declaration
///   modifiers `open`
///   class                     <- keyword token (ERROR.prev_sibling)
///   ERROR
///     simple_identifier `Session`   <- buried type name (named_child 0)
///     …
/// ```
///
/// `name_node` is the candidate identifier (the verified-reference leaf). The
/// match is purely structural — the keyword's AST node-kind drives the result,
/// no name allow-list is consulted. Returns `None` for every shape that is not
/// this error-recovery (so a well-formed declaration is unaffected).
fn swift_recovered_type_def_kind(name_node: &Node) -> Option<DefinitionKind> {
    let err = name_node.parent()?;
    if err.kind() != "ERROR" {
        return None;
    }
    // The identifier must be the buried type name — the ERROR's first named
    // child — not some other identifier salvaged into the same error region.
    if err.named_child(0)?.id() != name_node.id() {
        return None;
    }
    // The token immediately preceding the ERROR must be the type-declaration
    // keyword the parser recovered before bailing out.
    let keyword = err.prev_sibling()?;
    match keyword.kind() {
        "class" | "extension" => Some(DefinitionKind::Class),
        "struct" => Some(DefinitionKind::Struct),
        "enum" => Some(DefinitionKind::Enum),
        "actor" => Some(DefinitionKind::Actor),
        _ => None,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_references_report_default() {
        let report = ReferencesReport::default();
        assert!(report.symbol.is_empty());
        assert!(report.definition.is_none());
        assert!(report.references.is_empty());
        assert_eq!(report.total_references, 0);
        assert_eq!(report.search_scope, SearchScope::Workspace);
    }

    #[test]
    fn test_references_report_new() {
        let report = ReferencesReport::new("test_symbol".to_string());
        assert_eq!(report.symbol, "test_symbol");
        assert!(report.definition.is_none());
        assert!(report.references.is_empty());
    }

    #[test]
    fn test_definition_kind_serialization() {
        let kinds = vec![
            DefinitionKind::Function,
            DefinitionKind::Class,
            DefinitionKind::Variable,
            DefinitionKind::Constant,
            DefinitionKind::Type,
            DefinitionKind::Module,
            DefinitionKind::Method,
            DefinitionKind::Property,
            DefinitionKind::Other,
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: DefinitionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn test_reference_kind_serialization() {
        let kinds = vec![
            ReferenceKind::Call,
            ReferenceKind::Read,
            ReferenceKind::Write,
            ReferenceKind::Import,
            ReferenceKind::Type,
            ReferenceKind::Definition,
            ReferenceKind::Other,
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: ReferenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn test_search_scope_serialization() {
        let scopes = vec![
            SearchScope::Local,
            SearchScope::File,
            SearchScope::Workspace,
        ];

        for scope in scopes {
            let json = serde_json::to_string(&scope).unwrap();
            let parsed: SearchScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, parsed);
        }
    }

    #[test]
    fn test_reference_kind_parse() {
        assert_eq!(ReferenceKind::parse("call"), Some(ReferenceKind::Call));
        assert_eq!(ReferenceKind::parse("CALL"), Some(ReferenceKind::Call));
        assert_eq!(ReferenceKind::parse("read"), Some(ReferenceKind::Read));
        assert_eq!(ReferenceKind::parse("invalid"), None);
    }

    #[test]
    fn test_search_scope_parse() {
        assert_eq!(SearchScope::parse("local"), Some(SearchScope::Local));
        assert_eq!(SearchScope::parse("FILE"), Some(SearchScope::File));
        assert_eq!(
            SearchScope::parse("workspace"),
            Some(SearchScope::Workspace)
        );
        assert_eq!(SearchScope::parse("invalid"), None);
    }

    #[test]
    fn test_truncate_context_short() {
        let short = "def login(): pass".to_string();
        let result = truncate_context(short.clone());
        assert_eq!(result, short);
    }

    #[test]
    fn test_truncate_context_long() {
        let long: String = "x".repeat(300);
        let result = truncate_context(long);
        assert!(result.len() <= MAX_CONTEXT_LENGTH);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_definition_new() {
        let def = Definition::new(
            PathBuf::from("src/auth.py"),
            42,
            5,
            DefinitionKind::Function,
        );
        assert_eq!(def.file, PathBuf::from("src/auth.py"));
        assert_eq!(def.line, 42);
        assert_eq!(def.column, 5);
        assert_eq!(def.kind, DefinitionKind::Function);
        assert!(def.signature.is_none());
    }

    #[test]
    fn test_definition_with_signature() {
        let def = Definition::with_signature(
            PathBuf::from("src/auth.py"),
            42,
            5,
            DefinitionKind::Function,
            "def login(username: str, password: str) -> bool:".to_string(),
        );
        assert!(def.signature.is_some());
        assert!(def.signature.as_ref().unwrap().contains("login"));
    }

    #[test]
    fn test_reference_new() {
        let ref_ = Reference::new(
            PathBuf::from("src/routes.py"),
            15,
            12,
            ReferenceKind::Call,
            "result = auth.login(username, password)".to_string(),
        );
        assert_eq!(ref_.file, PathBuf::from("src/routes.py"));
        assert_eq!(ref_.line, 15);
        assert_eq!(ref_.column, 12);
        assert_eq!(ref_.kind, ReferenceKind::Call);
        assert!(ref_.confidence.is_none());
    }

    #[test]
    fn test_reference_verified() {
        let ref_ = Reference::verified(
            PathBuf::from("src/routes.py"),
            15,
            12,
            ReferenceKind::Call,
            "login()".to_string(),
        );
        assert_eq!(ref_.confidence, Some(1.0));
    }

    #[test]
    fn test_reference_stats_default() {
        let stats = ReferenceStats::default();
        assert_eq!(stats.files_searched, 0);
        assert_eq!(stats.candidates_found, 0);
        assert_eq!(stats.verified_references, 0);
        assert_eq!(stats.search_time_ms, 0);
    }

    #[test]
    fn test_reference_stats_with_time() {
        let stats = ReferenceStats::new(10, 50, 25).with_time(127);
        assert_eq!(stats.files_searched, 10);
        assert_eq!(stats.candidates_found, 50);
        assert_eq!(stats.verified_references, 25);
        assert_eq!(stats.search_time_ms, 127);
    }

    #[test]
    fn test_references_options_builder() {
        let opts = ReferencesOptions::new()
            .with_definition()
            .with_kinds(vec![ReferenceKind::Call, ReferenceKind::Import])
            .with_scope(SearchScope::File)
            .with_limit(100)
            .with_context_lines(2);

        assert!(opts.include_definition);
        assert_eq!(opts.kinds.as_ref().unwrap().len(), 2);
        assert_eq!(opts.scope, SearchScope::File);
        assert_eq!(opts.limit, Some(100));
        assert_eq!(opts.context_lines, 2);
    }

    #[test]
    fn test_report_serialization() {
        let report = ReferencesReport {
            symbol: "login".to_string(),
            definition: Some(Definition::new(
                PathBuf::from("src/auth.py"),
                42,
                5,
                DefinitionKind::Function,
            )),
            definitions: vec![Definition::new(
                PathBuf::from("src/auth.py"),
                42,
                5,
                DefinitionKind::Function,
            )],
            references: vec![Reference::new(
                PathBuf::from("src/routes.py"),
                15,
                12,
                ReferenceKind::Call,
                "login()".to_string(),
            )],
            total_references: 1,
            shown_references: 1,
            truncated: false,
            search_scope: SearchScope::Workspace,
            stats: ReferenceStats::new(10, 5, 1).with_time(50),
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: ReferencesReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.symbol, "login");
        assert!(parsed.definition.is_some());
        assert_eq!(parsed.references.len(), 1);
        assert_eq!(parsed.total_references, 1);
        assert_eq!(parsed.search_scope, SearchScope::Workspace);
    }

    #[test]
    fn test_no_matches_report() {
        let report = ReferencesReport::no_matches(
            "nonexistent".to_string(),
            SearchScope::Workspace,
            ReferenceStats::new(50, 0, 0),
        );

        assert_eq!(report.symbol, "nonexistent");
        assert!(report.definition.is_none());
        assert!(report.references.is_empty());
        assert_eq!(report.total_references, 0);
        assert_eq!(report.stats.files_searched, 50);
    }

    // =========================================================================
    // Tier-2 classifier tests (VAL-Java..VAL-Ocaml)
    //
    // Each test parses a minimal fixture with one definition of `greet`
    // and two call sites. It walks the tree, classifies every identifier
    // whose text is `greet`, and asserts:
    //   1. at least one Definition
    //   2. at least two Calls
    //   3. NO Other for any occurrence of `greet`
    // =========================================================================

    /// Collect (kind, line) for every identifier-like node whose text equals `needle`.
    fn collect_reference_kinds_for(
        source: &str,
        lang: Language,
        needle: &str,
        identifier_kinds: &[&str],
    ) -> Vec<(ReferenceKind, usize)> {
        use crate::ast::parser;
        let tree = parser::parse(source, lang).expect("parse should succeed");
        let src_bytes = source.as_bytes();
        let mut results = Vec::new();

        fn walk<'a>(
            node: tree_sitter::Node<'a>,
            source: &'a [u8],
            src_str: &'a str,
            needle: &str,
            identifier_kinds: &[&str],
            language: Language,
            out: &mut Vec<(ReferenceKind, usize)>,
        ) {
            if identifier_kinds.contains(&node.kind()) {
                let start = node.start_byte();
                let end = node.end_byte();
                if end <= src_str.len() {
                    let text = &src_str[start..end];
                    if text == needle {
                        let kind = classify_reference_kind(&node, source, language);
                        let line = node.start_position().row + 1;
                        out.push((kind, line));
                    }
                }
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    walk(
                        child,
                        source,
                        src_str,
                        needle,
                        identifier_kinds,
                        language,
                        out,
                    );
                }
            }
        }

        walk(
            tree.root_node(),
            src_bytes,
            source,
            needle,
            identifier_kinds,
            lang,
            &mut results,
        );
        results
    }

    /// Assert the classifier found at least one Definition and at least two Calls,
    /// and never returned Other for the needle identifier.
    fn assert_def_and_calls(results: &[(ReferenceKind, usize)], language_name: &str) {
        assert!(
            !results.is_empty(),
            "{}: no occurrences of `greet` matched by walker",
            language_name
        );
        let def_count = results
            .iter()
            .filter(|(k, _)| *k == ReferenceKind::Definition)
            .count();
        let call_count = results
            .iter()
            .filter(|(k, _)| *k == ReferenceKind::Call)
            .count();
        let other_count = results
            .iter()
            .filter(|(k, _)| *k == ReferenceKind::Other)
            .count();
        assert!(
            def_count >= 1,
            "{}: expected >=1 Definition, got {} (results={:?})",
            language_name,
            def_count,
            results
        );
        assert!(
            call_count >= 2,
            "{}: expected >=2 Calls, got {} (results={:?})",
            language_name,
            call_count,
            results
        );
        assert_eq!(
            other_count, 0,
            "{}: expected 0 Other, got {} (results={:?})",
            language_name, other_count, results
        );
    }

    #[test]
    fn test_java_classifier_emits_call_and_definition() {
        let src = r#"
class App {
    static String greet(String name) { return "Hello " + name; }
    public static void main(String[] args) {
        System.out.println(greet("World"));
        System.out.println(greet("Alice"));
    }
}
"#;
        let results = collect_reference_kinds_for(src, Language::Java, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Java");
    }

    #[test]
    fn test_c_classifier_emits_call_and_definition() {
        let src = r#"
#include <stdio.h>
void greet(const char *name) { printf("Hello %s\n", name); }
int main(void) {
    greet("World");
    greet("Alice");
    return 0;
}
"#;
        let results = collect_reference_kinds_for(src, Language::C, "greet", &["identifier"]);
        assert_def_and_calls(&results, "C");
    }

    #[test]
    fn test_cpp_classifier_emits_call_and_definition() {
        let src = r#"
#include <iostream>
void greet(const std::string &name) { std::cout << "Hello " << name; }
int main() {
    greet("World");
    greet("Alice");
    return 0;
}
"#;
        let results = collect_reference_kinds_for(src, Language::Cpp, "greet", &["identifier"]);
        assert_def_and_calls(&results, "C++");
    }

    #[test]
    fn test_csharp_classifier_emits_call_and_definition() {
        let src = r#"
class App {
    static string greet(string name) { return "Hello " + name; }
    static void Main() {
        System.Console.WriteLine(greet("World"));
        System.Console.WriteLine(greet("Alice"));
    }
}
"#;
        let results = collect_reference_kinds_for(src, Language::CSharp, "greet", &["identifier"]);
        assert_def_and_calls(&results, "C#");
    }

    #[test]
    fn test_kotlin_classifier_emits_call_and_definition() {
        let src = r#"
fun greet(name: String): String { return "Hello " + name }
fun main() {
    println(greet("World"))
    println(greet("Alice"))
}
"#;
        let results = collect_reference_kinds_for(src, Language::Kotlin, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Kotlin");
    }

    #[test]
    fn test_scala_classifier_emits_call_and_definition() {
        let src = r#"
object App {
  def greet(name: String): String = "Hello " + name
  def main(args: Array[String]): Unit = {
    println(greet("World"))
    println(greet("Alice"))
  }
}
"#;
        let results = collect_reference_kinds_for(
            src,
            Language::Scala,
            "greet",
            &["identifier", "type_identifier"],
        );
        assert_def_and_calls(&results, "Scala");
    }

    #[test]
    fn test_swift_classifier_emits_call_and_definition() {
        let src = r#"
func greet(name: String) -> String { return "Hello " + name }
func main() {
    print(greet(name: "World"))
    print(greet(name: "Alice"))
}
"#;
        let results =
            collect_reference_kinds_for(src, Language::Swift, "greet", &["simple_identifier"]);
        assert_def_and_calls(&results, "Swift");
    }

    #[test]
    fn test_php_classifier_emits_call_and_definition() {
        let src = r#"<?php
function greet($name) { return "Hello " . $name; }
echo greet("World");
echo greet("Alice");
"#;
        let results = collect_reference_kinds_for(src, Language::Php, "greet", &["name"]);
        assert_def_and_calls(&results, "PHP");
    }

    #[test]
    fn test_ruby_classifier_emits_call_and_definition() {
        let src = r#"
def greet(name)
  "Hello " + name
end
puts greet("World")
puts greet("Alice")
"#;
        let results = collect_reference_kinds_for(src, Language::Ruby, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Ruby");
    }

    #[test]
    fn test_lua_classifier_emits_call_and_definition() {
        let src = r#"
function greet(name)
  return "Hello " .. name
end
print(greet("World"))
print(greet("Alice"))
"#;
        let results = collect_reference_kinds_for(src, Language::Lua, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Lua");
    }

    #[test]
    fn test_luau_classifier_emits_call_and_definition() {
        let src = r#"
function greet(name: string): string
  return "Hello " .. name
end
print(greet("World"))
print(greet("Alice"))
"#;
        let results = collect_reference_kinds_for(src, Language::Luau, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Luau");
    }

    #[test]
    fn test_elixir_classifier_emits_call_and_definition() {
        let src = r#"
defmodule App do
  def greet(name) do
    "Hello " <> name
  end
end

IO.puts(App.greet("World"))
IO.puts(App.greet("Alice"))
"#;
        let results = collect_reference_kinds_for(src, Language::Elixir, "greet", &["identifier"]);
        assert_def_and_calls(&results, "Elixir");
    }

    #[test]
    fn test_ocaml_classifier_emits_call_and_definition() {
        let src = r#"
let greet name = "Hello " ^ name
let _ = print_string (greet "World")
let _ = print_string (greet "Alice")
"#;
        let results = collect_reference_kinds_for(src, Language::Ocaml, "greet", &["value_name"]);
        assert_def_and_calls(&results, "OCaml");
    }

    // RC7 (v0.5.0 R3): the discriminating AST node — the `module_path`
    // qualifier — must be read so a stdlib `Mutex.lock` is not reported as a
    // reference to a project `Lwt_mutex.lock`.
    #[test]
    fn test_ocaml_reference_qualifier_head_reads_module_path() {
        use crate::ast::parser::parse_file;
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.ml");
        // `Mutex.lock m` (qualified, stdlib head), `Lwt_mutex.lock m`
        // (qualified, project head) and bare `lock m` (no qualifier).
        let src = "let _ = Mutex.lock m\nlet _ = Lwt_mutex.lock m\nlet _ = lock m\n";
        std::fs::File::create(&path)
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();
        let (tree, source, _lang) = parse_file(&path).unwrap();
        // Collect every `value_name` leaf whose text is `lock`.
        let mut heads = Vec::new();
        let root = tree.root_node();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "value_name" && n.utf8_text(source.as_bytes()).unwrap() == "lock" {
                heads.push(ocaml_reference_qualifier_head(&n, source.as_bytes()));
            }
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                stack.push(ch);
            }
        }
        assert!(
            heads.contains(&Some("Mutex".to_string())),
            "expected a `Mutex`-qualified lock, got {heads:?}"
        );
        assert!(
            heads.contains(&Some("Lwt_mutex".to_string())),
            "expected a `Lwt_mutex`-qualified lock, got {heads:?}"
        );
        assert!(
            heads.contains(&None),
            "expected a bare (unqualified) lock, got {heads:?}"
        );
    }

    // RC7 end-to-end: `references lock` must exclude the stdlib `Mutex.lock`
    // call sites while keeping the project `Lwt_mutex.lock` and the bare
    // `lock` reference.
    #[test]
    fn test_ocaml_references_excludes_stdlib_qualified_call() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Project module Lwt_mutex defining `lock`.
        let mut f1 = std::fs::File::create(root.join("lwt_mutex.ml")).unwrap();
        f1.write_all(b"let lock m = m\n").unwrap();
        // A user site mixing stdlib `Mutex.lock`, project `Lwt_mutex.lock`,
        // and a bare `lock`.
        let mut f2 = std::fs::File::create(root.join("user.ml")).unwrap();
        f2.write_all(
            b"let _ = Mutex.lock guard\nlet _ = Lwt_mutex.lock m\nlet _ = lock m\n",
        )
        .unwrap();

        let opts = ReferencesOptions::new()
            .with_language("ocaml".to_string())
            .with_scope(SearchScope::Workspace);
        let report = find_references("lock", root, &opts).unwrap();

        let contexts: Vec<&str> = report
            .references
            .iter()
            .map(|r| r.context.as_str())
            .collect();
        // Stdlib `Mutex.lock` must be excluded.
        assert!(
            !contexts.iter().any(|c| c.contains("Mutex.lock")),
            "stdlib Mutex.lock should be excluded, got refs: {contexts:?}"
        );
        // Project `Lwt_mutex.lock` and bare `lock` must be kept.
        assert!(
            contexts.iter().any(|c| c.contains("Lwt_mutex.lock")),
            "project Lwt_mutex.lock should be kept, got refs: {contexts:?}"
        );
        assert!(
            contexts.iter().any(|c| c.trim_start().starts_with("let _ = lock")),
            "bare `lock` should be kept, got refs: {contexts:?}"
        );
    }

    #[test]
    fn test_elixir_references_excludes_foreign_qualified_module_call() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::write(
            root.join("naming.ex"),
            "defmodule Phoenix.Naming do\n  def underscore(value) do\n    value\n  end\n\n  def same_module(value) do\n    Phoenix.Naming.underscore(value)\n  end\nend\n",
        )
        .unwrap();
        std::fs::write(
            root.join("other.ex"),
            "defmodule MyApp.Other do\n  def run(value) do\n    Macro.underscore(value)\n  end\nend\n",
        )
        .unwrap();

        let opts = ReferencesOptions::new()
            .with_language("elixir".to_string())
            .with_scope(SearchScope::Workspace);
        let report = find_references("underscore", root, &opts).unwrap();
        let contexts: Vec<&str> = report
            .references
            .iter()
            .map(|r| r.context.as_str())
            .collect();

        assert!(
            !contexts.iter().any(|c| c.contains("Macro.underscore")),
            "foreign Macro.underscore must not be reported for Phoenix.Naming.underscore: {contexts:?}"
        );
        assert!(
            contexts.iter().any(|c| c.contains("Phoenix.Naming.underscore")),
            "same-module Phoenix.Naming.underscore must be kept: {contexts:?}"
        );
        assert!(
            report
                .definitions
                .iter()
                .any(|d| d.file.ends_with("naming.ex") && d.line == 2),
            "Phoenix.Naming.underscore definition should still be found: {:?}",
            report.definitions
        );
    }

    /// fix-PW1-B7-refs-stringFP (v0.5.0 BACKLOG): a symbol word that occurs
    /// only as plain text inside a string literal / docstring must NOT be
    /// reported as a reference. Pre-fix, when `descendant_for_point_range`
    /// resolved a candidate to a string-content (or comment) node whose text
    /// did not equal the symbol, `find_exact_match_node` fell through to a
    /// `confidence: 0.5, is_valid: true` fallback, inflating reference counts
    /// by 31-49% on real corpora (flask `Flask`, symfony-console `Command`).
    ///
    /// Generalization (anti-treadmill gate): the exclusion is AST-node-kind
    /// driven in `is_in_invalid_context`, so it must hold for EVERY language in
    /// the symptom class. This test asserts it for PHP and Python (the named
    /// class) plus Rust (representing "+all").
    #[test]
    fn test_references_excludes_string_literal_matches_all_langs() {
        use std::io::Write;

        struct Case {
            lang: &'static str,
            file: &'static str,
            src: &'static [u8],
            symbol: &'static str,
            /// Context fragments that are string-literal occurrences — excluded.
            banned: &'static [&'static str],
            /// A real code occurrence that must be kept.
            required: &'static str,
        }

        let cases = [
            Case {
                lang: "python",
                file: "w.py",
                src: b"class Widget:\n    \"\"\"Docstring naming Widget here.\"\"\"\n\n    def build(self):\n        label = \"a Widget label string\"\n        return Widget()\n",
                symbol: "Widget",
                banned: &["Docstring naming Widget", "a Widget label string"],
                required: "return Widget()",
            },
            Case {
                lang: "php",
                file: "c.php",
                src: b"<?php\nclass Command {\n    public function run(): void {\n        $msg = 'run the Command now';\n        throw new LogicException(\"Command failed badly\");\n        new Command();\n    }\n}\n",
                symbol: "Command",
                banned: &["run the Command now", "Command failed badly"],
                required: "new Command()",
            },
            Case {
                lang: "rust",
                file: "w.rs",
                src: b"struct Widget;\nfn build() -> Widget {\n    let _m = \"make a Widget string\";\n    Widget\n}\n",
                symbol: "Widget",
                banned: &["make a Widget string"],
                required: "-> Widget",
            },
        ];

        for c in &cases {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let mut f = std::fs::File::create(root.join(c.file)).unwrap();
            f.write_all(c.src).unwrap();

            let opts = ReferencesOptions::new()
                .with_language(c.lang.to_string())
                .with_scope(SearchScope::Workspace);
            let report = find_references(c.symbol, root, &opts).unwrap();

            let contexts: Vec<&str> =
                report.references.iter().map(|r| r.context.as_str()).collect();

            for bad in c.banned {
                assert!(
                    !contexts.iter().any(|ctx| ctx.contains(bad)),
                    "[{}] string-literal occurrence {bad:?} must be excluded, got refs: {contexts:?}",
                    c.lang
                );
            }
            assert!(
                contexts.iter().any(|ctx| ctx.contains(c.required)),
                "[{}] real code occurrence {:?} must be kept, got refs: {contexts:?}",
                c.lang,
                c.required
            );
        }
    }

    // =========================================================================
    // references-canonical-def-v1 tests
    //
    // Pre-milestone behaviour: `find_definition` returned the FIRST AST match
    // from `walk_project`'s walker order, which on `flask` returned a test
    // subclass at `tests/test_config.py:202`, hiding the canonical
    // `class Flask` at `src/flask/app.py:109`.
    //
    // Post-milestone: non-test files in `src/` / `lib/` / `main/` win,
    // falling back to non-test files anywhere, falling back to test files
    // only when every match is in a test file.
    // =========================================================================

    #[test]
    fn test_is_test_file_path_python() {
        // Positive: Python test conventions
        assert!(is_test_file_path(Path::new("tests/test_config.py")));
        assert!(is_test_file_path(Path::new("tests/test_app.py")));
        assert!(is_test_file_path(Path::new("foo/tests/x.py")));
        assert!(is_test_file_path(Path::new("test_module.py")));
        assert!(is_test_file_path(Path::new("module_test.py")));
        assert!(is_test_file_path(Path::new("conftest.py")));
        assert!(is_test_file_path(Path::new("foo/conftest.py")));

        // Negative: Python source
        assert!(!is_test_file_path(Path::new("src/flask/app.py")));
        assert!(!is_test_file_path(Path::new("flask/app.py")));
        assert!(!is_test_file_path(Path::new("module.py")));
        assert!(!is_test_file_path(Path::new("testify.py"))); // not test_ prefix
    }

    #[test]
    fn test_is_test_file_path_js_ts() {
        // Positive: JS/TS test conventions
        assert!(is_test_file_path(Path::new("test/foo.js")));
        assert!(is_test_file_path(Path::new("tests/foo.ts")));
        assert!(is_test_file_path(Path::new("foo/__tests__/bar.tsx")));
        assert!(is_test_file_path(Path::new("foo.test.js")));
        assert!(is_test_file_path(Path::new("foo.test.tsx")));
        assert!(is_test_file_path(Path::new("foo.spec.ts")));
        assert!(is_test_file_path(Path::new("foo.e2e.js")));

        // Negative: JS/TS source
        assert!(!is_test_file_path(Path::new("lib/router/index.js")));
        assert!(!is_test_file_path(Path::new("src/index.ts")));
        assert!(!is_test_file_path(Path::new("dist/foo.js")));
    }

    #[test]
    fn test_is_test_file_path_rust() {
        // Positive: Rust test conventions
        assert!(is_test_file_path(Path::new("crates/x/tests/it.rs")));
        assert!(is_test_file_path(Path::new("tests/integration.rs")));
        assert!(is_test_file_path(Path::new("crates/x/src/foo_test.rs")));
        assert!(is_test_file_path(Path::new("crates/x/src/tests.rs")));

        // Negative: Rust source
        assert!(!is_test_file_path(Path::new("crates/x/src/main.rs")));
        assert!(!is_test_file_path(Path::new("src/lib.rs")));
        assert!(!is_test_file_path(Path::new("crates/x/src/tester.rs")));
    }

    #[test]
    fn test_is_test_file_path_java() {
        // Positive: Maven/Gradle src/test/ convention
        assert!(is_test_file_path(Path::new("src/test/java/com/Foo.java")));
        assert!(is_test_file_path(Path::new("foo/src/test/kotlin/Bar.kt")));
        assert!(is_test_file_path(Path::new(
            "module/src/test/scala/Spec.scala"
        )));

        // Negative: src/main/ is source
        assert!(!is_test_file_path(Path::new(
            "src/main/java/com/Foo.java"
        )));
        assert!(!is_test_file_path(Path::new(
            "module/src/main/kotlin/Bar.kt"
        )));
    }

    #[test]
    fn test_is_test_file_path_ruby_go() {
        // Ruby
        assert!(is_test_file_path(Path::new("spec/foo_spec.rb")));
        assert!(is_test_file_path(Path::new("test/foo_test.rb")));
        // Go
        assert!(is_test_file_path(Path::new("foo_test.go")));
        assert!(is_test_file_path(Path::new("pkg/x/handler_test.go")));
        // Negative
        assert!(!is_test_file_path(Path::new("lib/foo.rb")));
        assert!(!is_test_file_path(Path::new("pkg/x/handler.go")));
    }

    #[test]
    fn test_canonical_def_tier_ranking() {
        // Tier 1: non-test in src/lib/main
        assert_eq!(canonical_def_tier(Path::new("src/flask/app.py")), 1);
        assert_eq!(canonical_def_tier(Path::new("lib/router/index.js")), 1);
        assert_eq!(
            canonical_def_tier(Path::new("module/src/main/java/com/Foo.java")),
            1
        );

        // Tier 2: non-test outside src/lib/main
        assert_eq!(canonical_def_tier(Path::new("examples/demo.py")), 2);
        assert_eq!(canonical_def_tier(Path::new("scripts/build.py")), 2);

        // Tier 3: test files
        assert_eq!(
            canonical_def_tier(Path::new("tests/test_config.py")),
            3
        );
        assert_eq!(
            canonical_def_tier(Path::new("src/test/java/com/Foo.java")),
            3
        );
        assert_eq!(canonical_def_tier(Path::new("foo.test.js")), 3);
    }

    /// Python: `src/foo.py::Foo` + `tests/test_foo.py::Foo` subclass
    /// → canonical = src.
    ///
    /// Mirrors the real-world flask case (`src/flask/app.py:109` vs
    /// `tests/test_config.py:202`).
    #[test]
    fn test_references_skips_test_subclass_picks_canonical_python() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("foo.py"),
            "class Foo:\n    def __init__(self):\n        pass\n",
        )
        .unwrap();

        let tests_dir = root.join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        std::fs::write(
            tests_dir.join("test_foo.py"),
            "from src.foo import Foo as _Foo\n\nclass Foo(_Foo):\n    pass\n",
        )
        .unwrap();

        let def = find_definition("Foo", root, Some("python"))
            .unwrap()
            .expect("definition should be found");
        assert!(
            def.file.to_string_lossy().contains("src/foo.py"),
            "expected src/foo.py, got {}",
            def.file.display()
        );
        assert!(
            !def.file.to_string_lossy().contains("tests/"),
            "should NOT pick tests/ file"
        );
    }

    /// JS: `lib/router.js::Router` + `test/router.test.js::Router`
    /// → canonical = lib.
    #[test]
    fn test_references_skips_test_subclass_picks_canonical_js() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let lib_dir = root.join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(
            lib_dir.join("router.js"),
            "function Router() { return {}; }\nmodule.exports = Router;\n",
        )
        .unwrap();

        let test_dir = root.join("test");
        std::fs::create_dir_all(&test_dir).unwrap();
        std::fs::write(
            test_dir.join("router.test.js"),
            "function Router() { return 'test-stub'; }\n",
        )
        .unwrap();

        let def = find_definition("Router", root, Some("javascript"))
            .unwrap()
            .expect("definition should be found");
        let file_str = def.file.to_string_lossy().to_string();
        assert!(
            file_str.contains("lib/router.js"),
            "expected lib/router.js, got {file_str}"
        );
        assert!(!file_str.contains("test/"), "should NOT pick test/ file");
    }

    /// Rust: `src/foo.rs::Foo` (struct) + `tests/foo_test.rs::Foo`
    /// → canonical = src.
    #[test]
    fn test_references_skips_test_subclass_picks_canonical_rust() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("foo.rs"), "pub struct Foo { x: u32 }\n").unwrap();

        let tests_dir = root.join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        std::fs::write(
            tests_dir.join("foo_test.rs"),
            "struct Foo { dummy: () }\n#[test]\nfn t() { let _ = Foo { dummy: () }; }\n",
        )
        .unwrap();

        let def = find_definition("Foo", root, Some("rust"))
            .unwrap()
            .expect("definition should be found");
        let file_str = def.file.to_string_lossy().to_string();
        assert!(
            file_str.contains("src/foo.rs"),
            "expected src/foo.rs, got {file_str}"
        );
        assert!(!file_str.contains("tests/"), "should NOT pick tests/ file");
    }

    /// Go: `pkg/foo.go::Foo` + `pkg/foo_test.go::Foo`
    /// → canonical = pkg/foo.go.
    ///
    /// Note: Go uses `_test.go` filename suffix, no `src/` convention.
    /// `pkg/foo.go` is tier 2 (non-test, non-src) and `pkg/foo_test.go`
    /// is tier 3 (test) — tier 2 wins.
    #[test]
    fn test_references_skips_test_subclass_picks_canonical_go() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let pkg = root.join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("foo.go"),
            "package pkg\n\ntype Foo struct { X int }\n",
        )
        .unwrap();
        std::fs::write(
            pkg.join("foo_test.go"),
            "package pkg\n\ntype Foo struct { Dummy bool }\n",
        )
        .unwrap();

        let def = find_definition("Foo", root, Some("go"))
            .unwrap()
            .expect("definition should be found");
        let file_str = def.file.to_string_lossy().to_string();
        assert!(
            file_str.ends_with("pkg/foo.go") || file_str.ends_with("pkg\\foo.go"),
            "expected pkg/foo.go, got {file_str}"
        );
        assert!(
            !file_str.contains("_test.go"),
            "should NOT pick _test.go file"
        );
    }

    /// Edge case: when EVERY match is in a test file, fall back to the
    /// earliest test match rather than returning None — the symbol is
    /// genuinely test-only.
    #[test]
    fn test_references_canonical_def_test_only_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let tests_dir = root.join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        std::fs::write(
            tests_dir.join("test_helpers.py"),
            "def test_only_helper():\n    pass\n",
        )
        .unwrap();

        let def = find_definition("test_only_helper", root, Some("python"))
            .unwrap()
            .expect("definition should be found in test file as fallback");
        assert!(def.file.to_string_lossy().contains("tests/"));
    }

    /// Verify `total_references` reflects the FULL pre-truncation count,
    /// not the truncated `references` Vec length. Pre-fix, default
    /// `--limit 20` made `total_references` always = 20 for popular
    /// symbols, hiding the true scale (337 for Flask).
    #[test]
    fn test_total_references_reflects_pre_truncation_count() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        // Definition + 5 calls
        std::fs::write(
            src_dir.join("foo.py"),
            "def my_func():\n    pass\n\nmy_func()\nmy_func()\nmy_func()\nmy_func()\nmy_func()\n",
        )
        .unwrap();

        let opts = ReferencesOptions {
            limit: Some(2),
            language: Some("python".to_string()),
            ..Default::default()
        };
        let report = find_references("my_func", root, &opts).unwrap();

        // The Vec is truncated to 2...
        assert!(report.references.len() <= 2);
        // ...but total_references reflects the real count (>2).
        assert!(
            report.total_references > 2,
            "expected total_references > 2, got {}",
            report.total_references
        );
        assert_eq!(
            report.total_references, report.stats.verified_references,
            "stats.verified_references should mirror total_references"
        );
    }

    // =========================================================================
    // R7 cluster[10] deps-graph: references RC8 (Elixir zero-arity def) + RC7
    // (PHP variable_name exclusion)
    // =========================================================================

    /// RC8 (#56): a zero-arity Elixir `def name do` must be recognised as a
    /// DEFINITION and lifted into `definitions[]`. RED before fix: the name
    /// node's parent is `arguments` (not `call`), so `is_elixir_def_call`
    /// never fired and the def line was classified as `read`, leaving
    /// `definitions[]` empty.
    #[test]
    fn test_elixir_zero_arity_def_is_definition() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let lib = root.join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(
            lib.join("csrf.ex"),
            "defmodule CSRF do\n  def get_csrf_token do\n    :token\n  end\n\n  def use_it do\n    get_csrf_token()\n  end\nend\n",
        )
        .unwrap();

        // find_definitions must surface the zero-arity def.
        let defs = find_definitions("get_csrf_token", root, Some("elixir")).unwrap();
        assert!(
            !defs.is_empty(),
            "zero-arity Elixir def must be found as a definition"
        );
        assert!(
            defs.iter().any(|d| d.line == 2),
            "definition should be at line 2 (def get_csrf_token do): {:?}",
            defs.iter().map(|d| d.line).collect::<Vec<_>>()
        );

        // The references report must classify line 2 as a Definition, not Read.
        let opts = ReferencesOptions {
            include_definition: true,
            language: Some("elixir".to_string()),
            ..Default::default()
        };
        let report = find_references("get_csrf_token", root, &opts).unwrap();
        assert!(
            !report.definitions.is_empty(),
            "ReferencesReport.definitions[] must be populated for zero-arity def"
        );
        let def_line_kind = report
            .references
            .iter()
            .find(|r| r.line == 2)
            .map(|r| r.kind);
        assert!(
            def_line_kind != Some(ReferenceKind::Read),
            "def line must not be classified Read; got {def_line_kind:?}"
        );
    }

    /// RC8 regression guard: with-args defs still resolve (the existing
    /// nested-`call` path must keep working).
    #[test]
    fn test_elixir_with_args_def_still_definition() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let lib = root.join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(
            lib.join("math.ex"),
            "defmodule Math do\n  def add(a, b) do\n    a + b\n  end\nend\n",
        )
        .unwrap();

        let defs = find_definitions("add", root, Some("elixir")).unwrap();
        assert!(
            defs.iter().any(|d| d.line == 2),
            "with-args Elixir def must still be a definition at line 2: {:?}",
            defs.iter().map(|d| d.line).collect::<Vec<_>>()
        );
    }

    /// fix-PW2-B-refs-elixir-defmodule (v0.5.0 BACKLOG): `check_elixir_definition`
    /// handled `def`/`defp`/`defmacro`/`defmacrop` but had NO `defmodule` arm, so
    /// a module-symbol query returned `definitions[]: []` and `--include-definition`
    /// was a no-op for module names. Generalization across the elixir defmodule
    /// symptom class: single-segment, dotted (`Foo.Bar`), and nested defmodule must
    /// ALL surface a `Module`-kind definition; the existing `def` path must keep
    /// working in the same file.
    #[test]
    fn test_elixir_defmodule_is_definition() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let lib = root.join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        // Top-level dotted module + nested single-segment module + a plain def.
        std::fs::write(
            lib.join("conn.ex"),
            "defmodule Plug.Conn do\n  def assign(conn, key, value) do\n    conn\n  end\n\n  defmodule NotSentError do\n    defexception message: \"a response was neither set nor sent\"\n  end\nend\n",
        )
        .unwrap();

        // Variant 1: dotted top-level module name.
        let dotted = find_definitions("Plug.Conn", root, Some("elixir")).unwrap();
        assert!(
            dotted.iter().any(|d| d.line == 1 && d.kind == DefinitionKind::Module),
            "dotted defmodule `Plug.Conn` must be a Module definition at line 1: {:?}",
            dotted.iter().map(|d| (d.line, d.kind)).collect::<Vec<_>>()
        );

        // Variant 2: nested single-segment module name.
        let nested = find_definitions("NotSentError", root, Some("elixir")).unwrap();
        assert!(
            nested.iter().any(|d| d.line == 6 && d.kind == DefinitionKind::Module),
            "nested defmodule `NotSentError` must be a Module definition at line 6: {:?}",
            nested.iter().map(|d| (d.line, d.kind)).collect::<Vec<_>>()
        );

        // Regression: the plain `def` in the same file still resolves as a def.
        let func = find_definitions("assign", root, Some("elixir")).unwrap();
        assert!(
            func.iter().any(|d| d.line == 2),
            "plain Elixir def must still resolve alongside defmodule: {:?}",
            func.iter().map(|d| d.line).collect::<Vec<_>>()
        );

        // End-to-end: references --include-definition must populate definitions[].
        let opts = ReferencesOptions {
            include_definition: true,
            language: Some("elixir".to_string()),
            ..Default::default()
        };
        let report = find_references("NotSentError", root, &opts).unwrap();
        assert!(
            !report.definitions.is_empty(),
            "ReferencesReport.definitions[] must be populated for a defmodule symbol"
        );
        assert!(
            report.definitions.iter().any(|d| d.kind == DefinitionKind::Module),
            "defmodule definition must carry DefinitionKind::Module: {:?}",
            report.definitions.iter().map(|d| d.kind).collect::<Vec<_>>()
        );
    }

    /// RC7 (#146): a PHP bare-name query for a method `width` must NOT match
    /// occurrences of the local variable `$width`. PHP variables live in a
    /// distinct sigil-prefixed namespace; `$width` is a different entity from
    /// the method `width()`. RED before fix: the `name` token inside
    /// `variable_name` (text == "width") was collected and classified Read at
    /// confidence 1.0.
    #[test]
    fn test_php_references_method_query_excludes_variable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("Box.php"),
            "<?php\nclass Box {\n    public function width() { return 10; }\n    public function area() {\n        $width = 5;\n        $w = $width;\n        return $width * $this->width();\n    }\n}\n",
        )
        .unwrap();

        let opts = ReferencesOptions {
            language: Some("php".to_string()),
            ..Default::default()
        };
        let report = find_references("width", root, &opts).unwrap();

        // No reference may point at a `$width` variable occurrence (lines 5,6,7
        // contain `$width`). The only legitimate references are the method
        // definition (line 3) and the `$this->width()` call (line 7).
        for r in &report.references {
            let is_var_line = matches!(r.line, 5 | 6);
            assert!(
                !is_var_line,
                "PHP $width variable occurrence wrongly matched as method ref at line {} kind {:?}",
                r.line, r.kind
            );
        }
        // The genuine method call `$this->width()` (line 7) must still be a Call.
        assert!(
            report
                .references
                .iter()
                .any(|r| r.line == 7 && r.kind == ReferenceKind::Call),
            "the real $this->width() call must still be found: {:?}",
            report
                .references
                .iter()
                .map(|r| (r.line, r.kind))
                .collect::<Vec<_>>()
        );
    }

    /// CF2-S19 generalization gate (anti-treadmill): the `references`
    /// definition-kind and reference-kind classifier must be correct for
    /// EVERY language in this slice's symptom class — cpp, ruby AND swift.
    ///
    /// Each sub-case fails on the pre-fix source and passes after the fix:
    ///
    /// * **cpp** — a `class` kept in a `.h` header. The bare-extension
    ///   classifier maps `.h` → C, whose grammar has no `class`, so
    ///   `class Shape {…}` error-recovers into a `function_definition` and the
    ///   definition was reported as `kind:function` carrying a MEMBER
    ///   signature (the destructor). The header-aware parse forms a real
    ///   `class_specifier`, so the def is `kind:class` with its OWN signature.
    /// * **ruby** — a bareword self-send (`cleanup` on its own line, no
    ///   receiver, no parens) parses as a lone `identifier` in a statement
    ///   container, which fell through to `Read`; it must be a `Call`.
    /// * **swift** — `struct`/`enum`/`actor` fold into one `class_declaration`
    ///   node and were promoted as the catch-all `kind:class`; each must
    ///   report its own keyword (`struct`/`enum`/`actor`), while a real
    ///   `class` stays `class`.
    #[test]
    fn test_references_definition_and_reference_kind_cpp_ruby_swift() {
        use std::io::Write;

        // ---- cpp: a `class` in a `.h` header reports kind:class (not
        // kind:function with a member's signature). -----------------------
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            // Header kept as `.h`; C++-exclusive `namespace`/`class` make the
            // content sniffer resolve it to C++. The class carries members
            // (ctor + destructor + method) whose signatures the pre-fix code
            // wrongly attributed to the class definition.
            let src = b"namespace demo {\nclass Shape {\npublic:\n    Shape();\n    virtual ~Shape();\n    void draw();\n};\n}\n";
            let mut f = std::fs::File::create(root.join("shape.h")).unwrap();
            f.write_all(src).unwrap();

            // language=None: `is_source_file` accepts the `.h` (it maps to C),
            // while `find_definition_in_file` resolves the true C++ language
            // per-file and parses with the C++ grammar.
            let opts = ReferencesOptions::new().with_scope(SearchScope::Workspace);
            let report = find_references("Shape", root, &opts).unwrap();

            let class_def = report.definitions.iter().find(|d| d.kind == DefinitionKind::Class);
            assert!(
                class_def.is_some(),
                "[cpp] `class Shape` must be reported with kind:class (not function); got {:?}",
                report
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line, d.signature.clone()))
                    .collect::<Vec<_>>()
            );
            let class_def = class_def.unwrap();
            // The signature must be the class's OWN declaration line, never a
            // member (e.g. the `~Shape()` destructor) carried by the off-by-one.
            if let Some(sig) = &class_def.signature {
                assert!(
                    sig.starts_with("class"),
                    "[cpp] class def must carry its OWN signature `class Shape …`, got {sig:?}"
                );
                assert!(
                    !sig.contains("~Shape") && !sig.contains("draw"),
                    "[cpp] class def signature must not be a member's, got {sig:?}"
                );
            }
        }

        // ---- ruby: a bareword self-send is a Call, not a Read. -----------
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            // `cleanup` on line 4 is a no-receiver, no-paren bareword call.
            let src = b"class Worker\n  def run\n    prepare\n    cleanup\n  end\n\n  def cleanup\n    @done = true\n  end\nend\n";
            let mut f = std::fs::File::create(root.join("worker.rb")).unwrap();
            f.write_all(src).unwrap();

            let opts = ReferencesOptions::new()
                .with_language("ruby".to_string())
                .with_scope(SearchScope::Workspace);
            let report = find_references("cleanup", root, &opts).unwrap();

            // The bareword self-send on line 4 must be classified Call.
            let bareword = report.references.iter().find(|r| r.line == 4);
            assert!(
                bareword.is_some(),
                "[ruby] expected the bareword `cleanup` reference on line 4; got {:?}",
                report.references.iter().map(|r| (r.line, r.kind)).collect::<Vec<_>>()
            );
            assert_eq!(
                bareword.unwrap().kind,
                ReferenceKind::Call,
                "[ruby] bareword self-send `cleanup` (line 4) must be a Call, not {:?}; all refs: {:?}",
                bareword.unwrap().kind,
                report.references.iter().map(|r| (r.line, r.kind)).collect::<Vec<_>>()
            );
            // The definition itself must still be a Definition, not a Call.
            assert!(
                report.references.iter().any(|r| r.line == 7 && r.kind == ReferenceKind::Definition),
                "[ruby] `def cleanup` (line 7) must still be a Definition; got {:?}",
                report.references.iter().map(|r| (r.line, r.kind)).collect::<Vec<_>>()
            );
        }

        // ---- swift: struct/enum/actor/class each report their own kind. ---
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let src = b"public struct OrderedDictionary {\n    var count = 0\n}\nenum Direction {\n    case north\n}\nactor Counter {\n    var n = 0\n}\nclass Base {\n    var x = 0\n}\n";
            let mut f = std::fs::File::create(root.join("collections.swift")).unwrap();
            f.write_all(src).unwrap();

            let expected = [
                ("OrderedDictionary", DefinitionKind::Struct, "struct"),
                ("Direction", DefinitionKind::Enum, "enum"),
                ("Counter", DefinitionKind::Actor, "actor"),
                ("Base", DefinitionKind::Class, "class"),
            ];
            for (symbol, want_kind, want_str) in expected {
                let opts = ReferencesOptions::new()
                    .with_language("swift".to_string())
                    .with_scope(SearchScope::Workspace);
                let report = find_references(symbol, root, &opts).unwrap();
                assert!(
                    report.definitions.iter().any(|d| d.kind == want_kind),
                    "[swift] `{symbol}` must be reported with kind:{want_str}; got {:?}",
                    report
                        .definitions
                        .iter()
                        .map(|d| (d.kind.as_str(), d.line))
                        .collect::<Vec<_>>()
                );
                // The serialized JSON `kind` string must be the keyword.
                let first = report.definitions.iter().find(|d| d.kind == want_kind).unwrap();
                assert_eq!(
                    first.kind.as_str(),
                    want_str,
                    "[swift] `{symbol}` kind string mismatch"
                );
            }
        }
    }

    /// CFr-RW2 (residual of CF2-S19). `references` mis-classified the
    /// DEFINITION KIND for two sibling declaration shapes the plain-keyword
    /// reader missed:
    ///
    /// * **cpp** — a macro/attribute-decorated class such as
    ///   `class TINYXML2_LIB XMLNode { … };`. tree-sitter-cpp absorbs the
    ///   export/visibility macro as the `class_specifier`'s name and error-
    ///   recovers the whole thing into a `function_definition` whose
    ///   declarator is the BARE class name — so the def was reported as
    ///   `kind:function`. It must report `kind:class`, while a PLAIN
    ///   `class …` (the S19 original) still reports `kind:class`.
    /// * **swift** — a modifier/attribute-decorated declaration whose body
    ///   carries syntax the grammar cannot model (a `#if canImport(…)`
    ///   conditional-compilation directive) never forms a `class_declaration`;
    ///   the type name is buried in an `ERROR` trailing the recovered
    ///   `class`/`struct`/`enum`/`actor` keyword. The def-site was dropped to
    ///   `Read` (so `definitions[]` was empty). An `open class` /
    ///   `public final class` must be recovered as `kind:class` WITH the def
    ///   present, while a plain `struct` (the S19 original) still reports
    ///   `kind:struct`.
    ///
    /// This test asserts BOTH the new sibling cases AND the S19 originals so it
    /// guards against a regression in either direction.
    #[test]
    fn test_references_kind_macro_and_recovered_modifier_class_cfr_rw2() {
        use std::io::Write;

        // ---- cpp: macro-decorated class -> kind:class (NEW); plain class
        //      still kind:class (S19 original). --------------------------------
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            // `MYLIB_API` is an unknown export/visibility macro token; it sits
            // between the `class` keyword and the real class name `Gizmo`.
            let src = b"class MYLIB_API Gizmo {\npublic:\n    Gizmo();\n    int value;\n};\n\nclass PlainGadget {\npublic:\n    int n;\n};\n";
            let mut f = std::fs::File::create(root.join("widget.cpp")).unwrap();
            f.write_all(src).unwrap();

            let opts = ReferencesOptions::new()
                .with_language("cpp".to_string())
                .with_scope(SearchScope::Workspace);

            // NEW sibling: the macro-decorated class must be kind:class, never
            // the catch-all `function` the misparse produced.
            let gizmo = find_references("Gizmo", root, &opts).unwrap();
            assert!(
                gizmo.definitions.iter().any(|d| d.kind == DefinitionKind::Class),
                "[cpp macro-class] `class MYLIB_API Gizmo` must be kind:class; got {:?}",
                gizmo
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>()
            );
            assert!(
                !gizmo
                    .definitions
                    .iter()
                    .any(|d| d.kind == DefinitionKind::Function && d.line == 1),
                "[cpp macro-class] the line-1 class def must NOT be reported as function; got {:?}",
                gizmo
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>()
            );

            // S19 original: a plain `class` is unaffected and stays kind:class.
            let plain = find_references("PlainGadget", root, &opts).unwrap();
            assert!(
                plain.definitions.iter().any(|d| d.kind == DefinitionKind::Class),
                "[cpp plain-class S19] `class PlainGadget` must stay kind:class; got {:?}",
                plain
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>()
            );
        }

        // ---- swift: modifier-prefixed class that error-recovers (a `#if`
        //      directive in the body) -> kind:class WITH the def present (NEW);
        //      plain `struct` still kind:struct (S19 original). ----------------
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            // The `#if canImport(Darwin)` directive makes tree-sitter-swift
            // error-recover the `open class` / `public final class`
            // declarations: the type name lands inside an ERROR trailing the
            // `class` keyword. Without the fix `definitions[]` is empty and the
            // def line is classified `read`.
            let src = b"import Foundation\n\nopen class Gadget: @unchecked Sendable {\n    public static let shared = Gadget()\n    #if canImport(Darwin)\n    @_spi(WebSocket) open func socket() {}\n    #endif\n}\n\npublic final class Widget: @unchecked Sendable {\n    static let d = Widget()\n    #if canImport(Darwin)\n    @_spi(X) open func go() {}\n    #endif\n}\n\nstruct Plain {\n    var n = 0\n}\n";
            let mut f = std::fs::File::create(root.join("gadget.swift")).unwrap();
            f.write_all(src).unwrap();

            let opts = ReferencesOptions::new()
                .with_language("swift".to_string())
                .with_scope(SearchScope::Workspace);

            // NEW sibling 1: `open class` (modifier-prefixed, error-recovered).
            let gadget = find_references("Gadget", root, &opts).unwrap();
            assert!(
                gadget.definitions.iter().any(|d| d.kind == DefinitionKind::Class),
                "[swift open class] `Gadget` def must be present with kind:class; got defs={:?}, l3 refs={:?}",
                gadget
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>(),
                gadget
                    .references
                    .iter()
                    .filter(|r| r.line == 3)
                    .map(|r| r.kind)
                    .collect::<Vec<_>>()
            );
            // The recovered def-site line must itself be a Definition, not Read.
            assert!(
                gadget
                    .references
                    .iter()
                    .any(|r| r.line == 3 && r.kind == ReferenceKind::Definition),
                "[swift open class] the `open class Gadget` line (3) must be a Definition; got {:?}",
                gadget
                    .references
                    .iter()
                    .map(|r| (r.line, r.kind))
                    .collect::<Vec<_>>()
            );

            // NEW sibling 2: `public final class` (two leading modifiers).
            let widget = find_references("Widget", root, &opts).unwrap();
            assert!(
                widget.definitions.iter().any(|d| d.kind == DefinitionKind::Class),
                "[swift public final class] `Widget` def must be present with kind:class; got {:?}",
                widget
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>()
            );

            // S19 original: a plain `struct` still reports kind:struct (the
            // error-recovery path must not hijack well-formed declarations).
            let plain = find_references("Plain", root, &opts).unwrap();
            assert!(
                plain.definitions.iter().any(|d| d.kind == DefinitionKind::Struct),
                "[swift struct S19] `struct Plain` must stay kind:struct; got {:?}",
                plain
                    .definitions
                    .iter()
                    .map(|d| (d.kind.as_str(), d.line))
                    .collect::<Vec<_>>()
            );
        }

        // ---- ruby: a bareword self-send stays a Call (S19 original — guards
        //      the cross-language classifier against collateral regressions). -
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let src = b"class Worker\n  def run\n    cleanup\n  end\n\n  def cleanup\n    @done = true\n  end\nend\n";
            let mut f = std::fs::File::create(root.join("worker.rb")).unwrap();
            f.write_all(src).unwrap();

            let opts = ReferencesOptions::new()
                .with_language("ruby".to_string())
                .with_scope(SearchScope::Workspace);
            let report = find_references("cleanup", root, &opts).unwrap();
            assert!(
                report
                    .references
                    .iter()
                    .any(|r| r.line == 3 && r.kind == ReferenceKind::Call),
                "[ruby bareword S19] `cleanup` self-send (line 3) must stay a Call; got {:?}",
                report
                    .references
                    .iter()
                    .map(|r| (r.line, r.kind))
                    .collect::<Vec<_>>()
            );
        }
    }
}
