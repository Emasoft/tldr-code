//! Taint Analysis Types
//!
//! This module provides the core types for CFG-based taint analysis.
//! Taint analysis tracks how untrusted data flows through a program
//! to detect potential security vulnerabilities like SQL injection,
//! command injection, and code injection.
//!
//! # Types
//!
//! - `TaintSourceType` - Categorizes sources of untrusted input
//! - `TaintSinkType` - Categorizes dangerous operations (sinks)
//! - `SanitizerType` - Categorizes sanitization operations
//! - `TaintSource` - A detected source of tainted data
//! - `TaintSink` - A detected dangerous sink
//! - `TaintFlow` - A flow from source to sink (potential vulnerability)
//! - `TaintInfo` - Complete taint analysis result for a function
//!
//! # References
//! - session11-taint-spec.md

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::ssa::types::{SsaFunction, SsaNameId};
use crate::types::{CfgInfo, RefType, VarRef};
use crate::Language;
use crate::TldrError;

thread_local! {
    /// Test-only thread-local switch that, when set to `true`, makes
    /// `detect_sources` and `detect_sinks` return empty vectors regardless of
    /// the regex bank's `.sources` / `.sinks` contents. Sanitizer banks are
    /// untouched (they are consulted via `detect_sanitizer` /
    /// `detect_sanitizer_ast`, not the source/sink code paths gated here).
    ///
    /// Used by `field_access_info-extension-v1` M1 to provide a transient
    /// bank-empty harness for the `analyze_ast_only` integration-test helper
    /// — mirrors the W2-pre "AST-only mode simulation" pattern proven in
    /// `regex-removal-v1` (W2-pre-report.json:45). The flag is process-local
    /// to a single thread; a guard struct (`AstOnlyTestModeGuard`) restores
    /// the previous value on Drop so concurrent tests on different threads
    /// do not see each other's overrides, and mid-test panics still restore
    /// the flag.
    ///
    /// This is **not a production switch** — production code never sets it,
    /// so the only runtime cost is one `Cell::get()` on each `detect_sources`
    /// / `detect_sinks` entry, which is negligible.
    static AST_ONLY_TEST_MODE: Cell<bool> = const { Cell::new(false) };
}

/// Test-only RAII guard that sets `AST_ONLY_TEST_MODE` to `true` on
/// construction and restores the previous value on Drop. Used by
/// `analyze_ast_only` in M1 integration tests to gate `detect_sources` /
/// `detect_sinks` to AST-only behavior for the duration of one
/// `compute_taint_with_tree` call.
///
/// Public so integration-test crates (which see `tldr-core` as a regular
/// dependency, not under `cfg(test)`) can construct it. Not part of the
/// stable public API; documented as test-only.
pub struct AstOnlyTestModeGuard {
    previous: bool,
}

impl AstOnlyTestModeGuard {
    /// Set `AST_ONLY_TEST_MODE` to `true` for the current thread; the
    /// previous value is captured for restoration on Drop.
    pub fn enter() -> Self {
        let previous = AST_ONLY_TEST_MODE.with(|m| {
            let prev = m.get();
            m.set(true);
            prev
        });
        Self { previous }
    }
}

impl Drop for AstOnlyTestModeGuard {
    fn drop(&mut self) {
        let prev = self.previous;
        AST_ONLY_TEST_MODE.with(|m| m.set(prev));
    }
}

/// Internal taint-set key for the SSA-aware propagation path (M1b VAL-001b).
///
/// When `compute_taint_with_tree` is called with `Some(&SsaFunction)` the
/// engine keys its taint set by `Versioned(SsaNameId)` so that re-assignment
/// through a sanitiser (`x = sanitize(x)`) correctly clears taint on the
/// post-sanitiser SSA version.
///
/// `Raw(String)` is used in the SAME SSA-aware path as a robustness fallback
/// for variables that have no SSA name entry — this can happen in real
/// SsaFunction outputs when the DFG emits a Use for a free variable (function
/// parameter, builtin) that has no defining SSA instruction in the function.
/// Mixed `Versioned`/`Raw` keys allow the SSA propagation to remain sound under
/// the per-language SSA-coverage gap rather than silently dropping taint.
///
/// When `compute_taint_with_tree` is called with `None`, the engine bypasses
/// `TaintKey` entirely and runs the M1a `HashSet<String>` path unchanged.
///
/// This enum is private to the taint module: callers see only the `Option<&
/// SsaFunction>` parameter on `compute_taint_with_tree` and the `TaintInfo`
/// shape, both of which are unchanged at the API boundary.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum TaintKey {
    /// SSA-versioned taint key. Set when an SsaNameId is available for the var.
    Versioned(SsaNameId),
    /// Raw variable-name fallback. Set when the SSA function has no entry for
    /// the variable (free vars, parameters in some languages, partial SSA).
    Raw(String),
}

/// Hard cap on worklist iterations to prevent infinite loops in taint analysis.
///
/// The computed max_iterations (blocks * vars) can be enormous for real-world
/// files with many blocks and variables. When the taint set oscillates (e.g.,
/// due to substring matching in stmt.contains()), the worklist never converges.
/// This cap ensures the analysis always terminates in bounded time.
const MAX_TAINT_ITERATIONS: usize = 1000;

// =============================================================================
// Enums - Taint Categories
// =============================================================================

/// Source of tainted (untrusted) data.
///
/// These represent entry points where external data enters the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceType {
    /// User input: `input()`, `raw_input()`
    UserInput,
    /// Standard input: `sys.stdin.read()`, `sys.stdin.readline()`
    Stdin,
    /// HTTP query/form parameters: `request.args`, `request.form`, `request.values`
    HttpParam,
    /// HTTP body data: `request.json`, `request.data`, `request.body`
    HttpBody,
    /// Environment variables: `os.environ`, `os.getenv()`
    EnvVar,
    /// File reads: `open().read()`, `pathlib.read_text()`
    FileRead,
}

/// Dangerous sink types where tainted data should not flow unsanitized.
///
/// These represent operations that can be exploited if fed untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSinkType {
    /// SQL queries: `cursor.execute()`, raw SQL execution
    SqlQuery,
    /// Code evaluation: `eval()`
    CodeEval,
    /// Code execution: `exec()`
    CodeExec,
    /// Code compilation: `compile()`
    CodeCompile,
    /// Shell command execution: `os.system()`, `subprocess.run()`
    ShellExec,
    /// File writes: `open(..., 'w')`, `.write_text()`
    FileWrite,
    /// HTML/template raw output (XSS sink).
    HtmlOutput,
    /// File system path access (path-traversal sink). Distinct from FileWrite which is write-only.
    FileOpen,
    /// Outbound HTTP/URL request (SSRF sink).
    HttpRequest,
    /// Untrusted-data deserialization (RCE-via-deser sink).
    Deserialize,
    /// HTTP redirect with attacker-controllable target (CWE-601 open-redirect).
    /// Examples: Express `res.redirect(target)`, Fastify `reply.redirect(target)`,
    /// Flask/Werkzeug `redirect(url)`, Next.js `NextResponse.redirect(...)`,
    /// browser `window.location.href = ...` / `window.open(...)`.
    /// (M3 detection-accuracy-v1 BUG-16)
    OpenRedirect,
}

/// Sanitizer types that neutralize taint.
///
/// These represent operations that make tainted data safe for specific sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerType {
    /// Numeric conversion: `int()`, `float()`, `bool()` - safe for SQL
    Numeric,
    /// Shell escaping: `shlex.quote()` - safe for shell commands
    Shell,
    /// HTML escaping: `html.escape()`, `markupsafe.escape()` - safe for HTML output
    Html,
}

// =============================================================================
// Structs - Taint Data
// =============================================================================

/// A detected taint source - where untrusted data enters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Variable name that receives tainted data
    pub var: String,
    /// Line number of the source
    pub line: u32,
    /// Type of source
    pub source_type: TaintSourceType,
    /// Optional statement text for context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
}

/// A detected taint sink - dangerous operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Variable used in the sink
    pub var: String,
    /// Line number of the sink
    pub line: u32,
    /// Type of sink
    pub sink_type: TaintSinkType,
    /// Whether the variable is tainted at this sink (true = vulnerability)
    pub tainted: bool,
    /// Optional statement text for context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
}

/// A taint flow from source to sink (represents a potential vulnerability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// The source of tainted data
    pub source: TaintSource,
    /// The sink where tainted data flows
    pub sink: TaintSink,
    /// Block IDs along the flow path from source to sink
    pub path: Vec<usize>,
}

/// Complete taint analysis result for a function.
///
/// Contains all detected sources, sinks, and flows, plus the taint state
/// at each CFG block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintInfo {
    /// Function name.
    ///
    /// cross-command-consistency-v1 (BUG-14): renamed in JSON to `function`
    /// so the function-name field is identical across commands
    /// (`slice`, `dead-stores`, `resources`, `reaching-defs`, `taint`,
    /// `explain`, ...). The Rust field is still `function_name` for
    /// backwards compatibility; JSON callers see `function`. The `alias`
    /// keeps deserialisation of older bodies working.
    #[serde(rename = "function", alias = "function_name")]
    pub function_name: String,
    /// Tainted variables at each block: block_id -> set of tainted variable names
    pub tainted_vars: HashMap<usize, HashSet<String>>,
    /// All detected taint sources
    pub sources: Vec<TaintSource>,
    /// All detected sinks (both tainted and untainted)
    pub sinks: Vec<TaintSink>,
    /// Flows from source to sink (vulnerabilities)
    pub flows: Vec<TaintFlow>,
    /// Variables that have been sanitized
    pub sanitized_vars: HashSet<String>,
    /// Convergence status: "converged" if the worklist reached a fixed point,
    /// "iteration_limit_reached" if analysis was capped at MAX_TAINT_ITERATIONS.
    #[serde(default = "default_convergence")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<String>,
}

fn default_convergence() -> Option<String> {
    None
}

// =============================================================================
// Implementations
// =============================================================================

impl TaintInfo {
    /// Create a new TaintInfo for a function with empty collections.
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            function_name: function_name.into(),
            tainted_vars: HashMap::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            flows: Vec::new(),
            sanitized_vars: HashSet::new(),
            convergence: None,
        }
    }

    /// Check if a variable is tainted at a given block.
    ///
    /// Returns `false` if the block doesn't exist or the variable isn't tainted.
    pub fn is_tainted(&self, block_id: usize, var: &str) -> bool {
        self.tainted_vars
            .get(&block_id)
            .map(|vars| vars.contains(var))
            .unwrap_or(false)
    }

    /// Get all sinks where the variable is tainted (vulnerabilities).
    pub fn get_vulnerabilities(&self) -> Vec<&TaintSink> {
        self.sinks.iter().filter(|s| s.tainted).collect()
    }
}

// =============================================================================
// Helper Functions - Phase 2
// =============================================================================

/// Build predecessor map from CFG edges.
///
/// Returns a mapping from each block ID to its list of predecessor block IDs.
/// Every block is guaranteed to have an entry (even if empty).
pub fn build_predecessors(cfg: &CfgInfo) -> HashMap<usize, Vec<usize>> {
    let mut preds: HashMap<usize, Vec<usize>> = HashMap::new();

    // Initialize all blocks with empty predecessor lists
    for block in &cfg.blocks {
        preds.entry(block.id).or_default();
    }

    // Add predecessors from edges
    for edge in &cfg.edges {
        preds.entry(edge.to).or_default().push(edge.from);
    }

    preds
}

/// Build successor map from CFG edges.
///
/// Returns a mapping from each block ID to its list of successor block IDs.
/// Every block is guaranteed to have an entry (even if empty).
pub fn build_successors(cfg: &CfgInfo) -> HashMap<usize, Vec<usize>> {
    let mut succs: HashMap<usize, Vec<usize>> = HashMap::new();

    // Initialize all blocks with empty successor lists
    for block in &cfg.blocks {
        succs.entry(block.id).or_default();
    }

    // Add successors from edges
    for edge in &cfg.edges {
        succs.entry(edge.from).or_default().push(edge.to);
    }

    succs
}

/// Build line-to-block mapping from CFG.
///
/// Maps each line number to the block that contains it.
/// When blocks overlap (e.g., merge points within code blocks),
/// prefers LARGER blocks (actual code blocks over merge points).
/// For same-size blocks, prefers HIGHER block ID (branch bodies come after merge points).
///
/// This pattern is copied from reaching.rs:102-125 to handle overlapping blocks correctly.
pub fn build_line_to_block(cfg: &CfgInfo) -> HashMap<u32, usize> {
    let mut mapping: HashMap<u32, usize> = HashMap::new();

    // For each line, find the best block that contains it
    // We need to collect all lines first, then find the best block for each
    let mut all_lines: HashSet<u32> = HashSet::new();
    for block in &cfg.blocks {
        for line in block.lines.0..=block.lines.1 {
            all_lines.insert(line);
        }
    }

    for line in all_lines {
        let mut best_block: Option<(usize, u32)> = None; // (block_id, size)

        for block in &cfg.blocks {
            let (start, end) = block.lines;
            if line >= start && line <= end {
                let size = end - start + 1;
                // Prefer LARGER blocks (more likely to be actual code blocks)
                // For same size, prefer HIGHER block ID (branch bodies come after merge points)
                if best_block.is_none()
                    || size > best_block.unwrap().1
                    || (size == best_block.unwrap().1 && block.id > best_block.unwrap().0)
                {
                    best_block = Some((block.id, size));
                }
            }
        }

        if let Some((block_id, _)) = best_block {
            mapping.insert(line, block_id);
        }
    }

    mapping
}

/// Group VarRefs by their containing block.
///
/// Uses the line_to_block mapping to assign each VarRef to its block.
/// Refs within each block are sorted by line number.
/// VarRefs that don't map to any block are excluded.
pub fn build_refs_by_block<'a>(
    refs: &'a [VarRef],
    line_to_block: &HashMap<u32, usize>,
) -> HashMap<usize, Vec<&'a VarRef>> {
    let mut by_block: HashMap<usize, Vec<&VarRef>> = HashMap::new();

    for var_ref in refs {
        if let Some(&block_id) = line_to_block.get(&var_ref.line) {
            by_block.entry(block_id).or_default().push(var_ref);
        }
    }

    // Sort refs within each block by line number
    for refs in by_block.values_mut() {
        refs.sort_by_key(|r| r.line);
    }

    by_block
}

/// Validate CFG structure for taint analysis.
///
/// Checks:
/// - CFG has at least one block
/// - Entry block exists in the block list
/// - All edge endpoints reference valid block IDs
///
/// # Errors
///
/// Returns `TldrError::InvalidArgs` if validation fails.
pub fn validate_cfg(cfg: &CfgInfo) -> Result<(), TldrError> {
    // Check for empty CFG
    if cfg.blocks.is_empty() {
        return Err(TldrError::InvalidArgs {
            arg: "cfg".to_string(),
            message: "Empty CFG".to_string(),
            suggestion: None,
        });
    }

    // Collect all valid block IDs
    let block_ids: HashSet<usize> = cfg.blocks.iter().map(|b| b.id).collect();

    // Check entry block exists
    if !block_ids.contains(&cfg.entry_block) {
        return Err(TldrError::InvalidArgs {
            arg: "cfg".to_string(),
            message: format!("Entry block {} not in blocks", cfg.entry_block),
            suggestion: Some(format!(
                "Valid block IDs are: {:?}",
                block_ids.iter().collect::<Vec<_>>()
            )),
        });
    }

    // Check all edges reference valid blocks
    for edge in &cfg.edges {
        if !block_ids.contains(&edge.from) {
            return Err(TldrError::InvalidArgs {
                arg: "cfg".to_string(),
                message: format!(
                    "Edge references invalid source block: {} -> {}",
                    edge.from, edge.to
                ),
                suggestion: Some(format!(
                    "Valid block IDs are: {:?}",
                    block_ids.iter().collect::<Vec<_>>()
                )),
            });
        }
        if !block_ids.contains(&edge.to) {
            return Err(TldrError::InvalidArgs {
                arg: "cfg".to_string(),
                message: format!(
                    "Edge references invalid target block: {} -> {}",
                    edge.from, edge.to
                ),
                suggestion: Some(format!(
                    "Valid block IDs are: {:?}",
                    block_ids.iter().collect::<Vec<_>>()
                )),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Pattern Matching - Phase 3
// =============================================================================

/// Language-specific taint analysis patterns.
///
/// Each language has its own set of source, sink, and sanitizer patterns.
/// Currently only Python patterns are defined; other languages fall back to Python.
///
/// `Clone` is derived so multiple framework-specific banks can be merged into
/// a single unified bank via [`merge_patterns`] (see TypeScript: Express +
/// Next.js + Fastify + NestJS).
#[derive(Clone)]
pub struct LanguagePatterns {
    /// Regex patterns that identify taint sources and their source type.
    pub sources: Vec<(Regex, TaintSourceType)>,
    /// Regex patterns that identify taint sinks and their sink type.
    pub sinks: Vec<(Regex, TaintSinkType)>,
    /// Regex patterns that identify sanitizer calls and their sanitizer type.
    pub sanitizers: Vec<(Regex, SanitizerType)>,
}

lazy_static! {
    /// Python-specific taint patterns.
    static ref PYTHON_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M8): sources + sinks regex banks
        // deleted; AST-based detection in detect_sources_ast/detect_sinks_ast
        // is canonical.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST-based
        // detection via PYTHON_AST_SANITIZERS is canonical, dispatched via
        // `build_sanitizer_ast_index` in `compute_taint_with_tree`. The
        // regex bank's `int|float|bool`, `(shlex|pipes).quote`, and
        // `(html|markupsafe|cgi).escape` patterns are all covered by the
        // AST bank's structured (call_names, member_patterns) tuples.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Unified TypeScript / JavaScript taint patterns.
    ///
    /// Wave-2-atomic (regex-removal-v1 M7): the four framework sub-banks
    /// (TYPESCRIPT_EXPRESS_PATTERNS, NEXTJS_PATTERNS, FASTIFY_PATTERNS,
    /// NESTJS_PATTERNS) and the `merge_patterns` helper that previously
    /// composed them have been deleted along with their source+sink regex
    /// entries. Source/sink detection is now exclusively AST-based via
    /// `detect_sources_ast` / `detect_sinks_ast` in
    /// `compute_taint_with_tree`. The sanitizer Vec is RETAINED across all
    /// 4 sub-banks (sanitizer-removal is a future milestone).
    static ref TYPESCRIPT_PATTERNS: LanguagePatterns = LanguagePatterns {
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied.
        // AST bank TYPESCRIPT_AST_SANITIZERS covers parseInt/Number/parseFloat,
        // encodeURIComponent/DOMPurify.sanitize, and Zod .parse/.safeParse.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Go taint patterns.
    static ref GO_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // GO_AST_SANITIZERS covers strconv.{Atoi,ParseInt,ParseFloat} and
        // html.EscapeString / url.QueryEscape.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Java taint patterns.
    static ref JAVA_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // JAVA_AST_SANITIZERS covers Integer.parseInt / Long.parseLong /
        // Double.parseDouble and ESAPI.encoder / StringEscapeUtils.escapeHtml.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Rust taint patterns.
    static ref RUST_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // RUST_AST_SANITIZERS covers `.parse::<NUM>()` via raw-substring
        // entries on the numeric type names.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// C taint patterns.
    static ref C_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // C_AST_SANITIZERS covers atoi/atol/atof/strtol/strtoul/strtod plus
        // snprintf.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// C++ taint patterns.
    static ref CPP_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // CPP_AST_SANITIZERS covers std::stoi/stol/stoul/stoll/stof/stod
        // plus static_cast<numeric>.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Ruby taint patterns.
    static ref RUBY_PATTERNS: LanguagePatterns = LanguagePatterns {
        // field_access_info-extension-v1 M5 (ATOMIC): sources + sinks regex banks
        // deleted; AST detection canonical via structured (receiver, field) tuples
        // in RUBY_AST_SOURCES / RUBY_AST_SINKS. Sanitizers RETAINED (sanitizer-
        // removal-v1 future milestone). EXCEPTION: `\bgets\b` UserInput entry
        // RETAINED — tree-sitter-ruby parses bare `gets` as an identifier, not a
        // `call` node, so AST `call_names: ['gets']` does not cover the bare-call
        // form. This regex catches `input = gets.chomp` and `cmd = gets` shapes.
        // Documented in M1-report.json finding #2 (carry-forward exception).
        sources: vec![
            // UserInput: bare `gets` (tree-sitter-ruby parses this as identifier,
            // not call → AST call_names entry does not fire on bare form).
            (Regex::new(r"\bgets\b").unwrap(), TaintSourceType::UserInput),
        ],
        sinks: vec![],
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // RUBY_AST_SANITIZERS covers .to_i / .to_f via member_patterns and
        // CGI.escapeHTML / Rack::Utils.escape_html via raw-substring entries.
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Kotlin taint patterns.
    static ref KOTLIN_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // KOTLIN_AST_SANITIZERS covers .toInt/.toLong/.toDouble/.toFloat.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Swift taint patterns.
    static ref SWIFT_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // SWIFT_AST_SANITIZERS covers Int/Double/Float and
        // addingPercentEncoding.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// C# taint patterns.
    static ref CSHARP_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // CSHARP_AST_SANITIZERS covers int.Parse / Convert.ToInt32 /
        // double.Parse and HttpUtility.HtmlEncode.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Scala taint patterns.
    static ref SCALA_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // SCALA_AST_SANITIZERS covers .toInt/.toLong/.toDouble and
        // StringEscapeUtils.escapeHtml.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// PHP taint patterns.
    static ref PHP_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // PHP_AST_SANITIZERS covers intval/floatval and (int)/(float) casts,
        // htmlspecialchars/htmlentities, and mysqli_real_escape_string.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Lua/Luau taint patterns.
    static ref LUA_PATTERNS: LanguagePatterns = LanguagePatterns {
        // Wave-2-atomic (regex-removal-v1 M9): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // LUA_AST_SANITIZERS (shared by Lua/Luau) covers tonumber.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// Elixir taint patterns.
    static ref ELIXIR_PATTERNS: LanguagePatterns = LanguagePatterns {
        // field_access_info-extension-v1 M5 (ATOMIC): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // ELIXIR_AST_SANITIZERS covers String.to_integer / String.to_float
        // and Phoenix.HTML.html_escape.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

lazy_static! {
    /// OCaml taint patterns.
    static ref OCAML_PATTERNS: LanguagePatterns = LanguagePatterns {
        // field_access_info-extension-v1 M5 (ATOMIC): sources + sinks regex banks
        // deleted.
        // sanitizer-removal-v1 M4 (ATOMIC): sanitizer Vec emptied; AST bank
        // OCAML_AST_SANITIZERS covers int_of_string / float_of_string.
        sources: vec![],
        sinks: vec![],
        sanitizers: vec![],
    };
}

/// Get taint analysis patterns for a given language.
///
/// Each language has its own set of source, sink, and sanitizer patterns.
/// TypeScript/JavaScript share patterns, as do Lua/Luau.
pub fn get_patterns(language: Language) -> &'static LanguagePatterns {
    match language {
        Language::Python => &PYTHON_PATTERNS,
        Language::TypeScript | Language::JavaScript => &TYPESCRIPT_PATTERNS,
        Language::Go => &GO_PATTERNS,
        Language::Java => &JAVA_PATTERNS,
        Language::Rust => &RUST_PATTERNS,
        Language::C => &C_PATTERNS,
        Language::Cpp => &CPP_PATTERNS,
        Language::Ruby => &RUBY_PATTERNS,
        Language::Kotlin => &KOTLIN_PATTERNS,
        Language::Swift => &SWIFT_PATTERNS,
        Language::CSharp => &CSHARP_PATTERNS,
        Language::Scala => &SCALA_PATTERNS,
        Language::Php => &PHP_PATTERNS,
        Language::Lua | Language::Luau => &LUA_PATTERNS,
        Language::Elixir => &ELIXIR_PATTERNS,
        Language::Ocaml => &OCAML_PATTERNS,
    }
}

/// Detect taint sources in a statement.
///
/// Scans the statement for patterns matching known taint sources (e.g., `input()`,
/// `request.args`, `os.environ`). If a source is found and the statement is an
/// assignment, returns a `TaintSource` with the assigned variable name.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `line` - The line number of the statement
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// A vector of detected `TaintSource`s. Usually 0 or 1, but could be more if
/// multiple sources appear in the same statement.
pub fn detect_sources(statement: &str, line: u32, language: Language) -> Vec<TaintSource> {
    // Test-only AST-only-mode override: when set by an integration-test
    // `AstOnlyTestModeGuard`, skip the entire regex source bank so the
    // returned vector reflects pure-AST detection. See `AST_ONLY_TEST_MODE`
    // doc comment.
    if AST_ONLY_TEST_MODE.with(|m| m.get()) {
        return Vec::new();
    }

    let mut sources = Vec::new();
    let patterns = get_patterns(language);

    for (pattern, source_type) in patterns.sources.iter() {
        if pattern.is_match(statement) {
            // Try to extract variable name from assignment (left side of =)
            if let Some(var) = extract_assigned_var(statement) {
                sources.push(TaintSource {
                    var,
                    line,
                    source_type: *source_type,
                    statement: Some(statement.to_string()),
                });
            } else {
                // For non-assignment sources (e.g., C's scanf(buf), fgets(buf, ...)),
                // extract the first variable argument from the call
                if let Some(var) = extract_call_arg(statement, pattern) {
                    sources.push(TaintSource {
                        var,
                        line,
                        source_type: *source_type,
                        statement: Some(statement.to_string()),
                    });
                } else {
                    // Last resort: use a synthetic variable name from the source type
                    // This handles patterns like "std::cin >> input" or "STDIN.read"
                    // where neither assignment nor call extraction works
                    let var = extract_source_var_from_statement(statement);
                    if let Some(var) = var {
                        sources.push(TaintSource {
                            var,
                            line,
                            source_type: *source_type,
                            statement: Some(statement.to_string()),
                        });
                    }
                }
            }
        }
    }

    sources
}

/// Extract a variable name from a source statement when there's no assignment or call arg.
///
/// Handles patterns like:
/// - "std::cin >> input" -> "input"
/// - "fmt.Scan(&input)" -> "input"
/// - "std::ifstream file(path)" -> "file"
/// - "scanf(\"%s\", buf)" -> "buf" (already handled by extract_call_arg)
fn extract_source_var_from_statement(statement: &str) -> Option<String> {
    // Handle C++ "cin >> var" pattern
    if let Some(pos) = statement.find(">>") {
        let after = statement[pos + 2..].trim();
        let var = after.split_whitespace().next().unwrap_or("");
        let var = var.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
        if is_valid_identifier(var) {
            return Some(var.to_string());
        }
    }

    // Handle "&var" references (Go's fmt.Scan(&input))
    if let Some(pos) = statement.find('&') {
        let after = &statement[pos + 1..];
        let var = after
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        if is_valid_identifier(var) {
            return Some(var.to_string());
        }
    }

    // Handle C++ constructor-style declarations: "Type var(args)" or "Type var"
    // e.g., "std::ifstream file(path)" -> "file"
    let tokens: Vec<&str> = statement.split_whitespace().collect();
    if tokens.len() >= 2 {
        // Find a token that looks like a variable (followed by '(' or end)
        for tok in tokens.iter().skip(1) {
            // Strip trailing '(' and everything after for constructor calls
            let var = tok.split('(').next().unwrap_or(tok);
            let var = var.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if is_valid_identifier(var) && var.len() > 1 {
                return Some(var.to_string());
            }
        }
    }

    None
}

/// Detect taint sinks in a statement.
///
/// Scans the statement for patterns matching known taint sinks (e.g., `execute()`,
/// `eval()`, `os.system()`). If a sink is found, extracts the variable being
/// passed as an argument.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `line` - The line number of the statement
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// A vector of detected `TaintSink`s. The `tainted` field is set to `false`
/// initially; it will be updated by the taint propagation analysis.
pub fn detect_sinks(statement: &str, line: u32, language: Language) -> Vec<TaintSink> {
    // Test-only AST-only-mode override: when set by an integration-test
    // `AstOnlyTestModeGuard`, skip the entire regex sink bank so the
    // returned vector reflects pure-AST detection. See `AST_ONLY_TEST_MODE`
    // doc comment.
    if AST_ONLY_TEST_MODE.with(|m| m.get()) {
        return Vec::new();
    }

    let mut sinks = Vec::new();
    let patterns = get_patterns(language);
    for (pattern, sink_type) in patterns.sinks.iter() {
        if pattern.is_match(statement) {
            // Extract variable name from call argument
            if let Some(var) = extract_call_arg(statement, pattern) {
                sinks.push(TaintSink {
                    var,
                    line,
                    sink_type: *sink_type,
                    tainted: false,
                    statement: Some(statement.to_string()),
                });
            } else {
                // Handle assignment-style sinks (e.g., "element.innerHTML = userContent")
                // and patterns where the dangerous argument is on the RHS of an assignment
                if let Some(var) = extract_sink_var_from_statement(statement, pattern) {
                    sinks.push(TaintSink {
                        var,
                        line,
                        sink_type: *sink_type,
                        tainted: false,
                        statement: Some(statement.to_string()),
                    });
                } else {
                    // Fallback: extract interpolated variables from format strings.
                    // This catches f"SELECT {query}", `SELECT ${query}`, etc.
                    // where the sink argument is a string literal with embedded variables.
                    let interp_vars = extract_interpolated_vars(statement);
                    for var in interp_vars {
                        sinks.push(TaintSink {
                            var,
                            line,
                            sink_type: *sink_type,
                            tainted: false,
                            statement: Some(statement.to_string()),
                        });
                    }
                }
            }
        }
    }
    sinks
}

/// Extract a variable from a sink statement when extract_call_arg fails.
///
/// Handles:
/// - Assignment-style sinks: "element.innerHTML = userContent" -> "userContent"
/// - Non-call sinks: "unsafe { std::ptr::write(ptr, val) }" -> "ptr"
/// - Process constructors: "new ProcessBuilder(cmd).start()" -> "cmd"
/// - Space-separated args (OCaml): "Unix.execvp cmd args" -> "cmd"
/// - Scala: "import sys.process._; cmd.!" -> "cmd"
fn extract_sink_var_from_statement(statement: &str, pattern: &Regex) -> Option<String> {
    if let Some(m) = pattern.find(statement) {
        let after = &statement[m.end()..];
        let after = after.trim();

        // If the pattern matched an assignment (innerHTML =), RHS is the var
        if after.is_empty() || !after.starts_with('(') {
            // Get what's after the "=" in the full statement
            if let Some(eq_pos) = statement.rfind('=') {
                // Make sure it's not == or other compound operators
                let before_eq = if eq_pos > 0 {
                    statement.as_bytes()[eq_pos - 1]
                } else {
                    b' '
                };
                let after_eq = if eq_pos + 1 < statement.len() {
                    statement.as_bytes()[eq_pos + 1]
                } else {
                    b' '
                };
                if before_eq != b'='
                    && before_eq != b'!'
                    && before_eq != b'<'
                    && before_eq != b'>'
                    && after_eq != b'='
                {
                    let rhs = statement[eq_pos + 1..].trim();
                    let var = rhs
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    if is_valid_identifier(var) {
                        return Some(var.to_string());
                    }
                }
            }
        }

        // Try to find a parenthesized argument after the pattern
        // Handle "new ProcessBuilder(cmd).start()" or "ProcessBuilder(cmd)"
        let search_area = &statement[m.start()..];
        if let Some(open) = search_area.find('(') {
            let rest = &search_area[open + 1..];
            let end = rest.find([',', ')']).unwrap_or(rest.len());
            let arg = rest[..end].trim();
            if !arg.starts_with('"') && !arg.starts_with('\'') && !arg.is_empty() {
                let var_name = arg.split('.').next().unwrap_or(arg);
                let var_name = var_name.trim_start_matches('$');
                if is_valid_identifier(var_name) {
                    return Some(var_name.to_string());
                }
            }
        }

        // Handle space-separated arguments (OCaml, Haskell, etc.)
        // e.g., "Unix.execvp cmd args" -> "cmd"
        // e.g., "Sys.command cmd" -> "cmd"
        if !after.is_empty() && !after.starts_with('(') {
            // Take the first space-separated token after the pattern
            let token = after
                .split(|c: char| c.is_whitespace() || c == ';')
                .next()
                .unwrap_or("");
            let token = token.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if is_valid_identifier(token) {
                return Some(token.to_string());
            }
        }

        // Handle semicolon-separated statements
        // e.g., "import sys.process._; cmd.!" -> look before semicolon for var
        if statement.contains(';') {
            // Look for identifiers in the other parts of the statement
            for part in statement.split(';') {
                let part = part.trim();
                // Skip the part that contains the pattern match
                if pattern.is_match(part) {
                    continue;
                }
                // Find first identifier in this part
                let var = part
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .find(|t| is_valid_identifier(t));
                if let Some(var) = var {
                    return Some(var.to_string());
                }
            }
        }
    }

    None
}

/// Check if a statement contains a sanitizer and return its type.
///
/// Scans for patterns like `int()`, `shlex.quote()`, `html.escape()` that
/// neutralize taint for specific sink types.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// `Some(SanitizerType)` if a sanitizer is detected, `None` otherwise.
pub fn detect_sanitizer(statement: &str, language: Language) -> Option<SanitizerType> {
    // Test-only AST-only-mode override: when set by an integration-test
    // `AstOnlyTestModeGuard`, skip the entire regex sanitizer bank so the
    // returned value reflects pure-AST detection. See `AST_ONLY_TEST_MODE`
    // doc comment.
    if AST_ONLY_TEST_MODE.with(|m| m.get()) {
        return None;
    }

    let patterns = get_patterns(language);
    for (pattern, sanitizer_type) in patterns.sanitizers.iter() {
        if pattern.is_match(statement) {
            return Some(*sanitizer_type);
        }
    }
    None
}

/// Convenience wrapper to check if a statement contains any sanitizer.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// `true` if the statement contains a sanitizer, `false` otherwise.
pub fn is_sanitizer(statement: &str, language: Language) -> bool {
    detect_sanitizer(statement, language).is_some()
}

/// Find sanitizers in a statement and return the sanitized variable with its type.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `line` - The line number of the statement
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// A vector of (variable_name, SanitizerType) pairs for each sanitizer found.
pub fn find_sanitizers_in_statement(
    statement: &str,
    _line: u32,
    language: Language,
) -> Vec<(String, SanitizerType)> {
    let mut result = Vec::new();
    let patterns = get_patterns(language);

    for (pattern, sanitizer_type) in patterns.sanitizers.iter() {
        if pattern.is_match(statement) {
            // The sanitized variable is the one being assigned to
            if let Some(var) = extract_assigned_var(statement) {
                result.push((var, *sanitizer_type));
            }
        }
    }

    result
}

/// Extract variable name from assignment (LHS of =).
///
/// Handles various Python assignment patterns:
/// - Simple assignment: `var = ...`
/// - Type-annotated assignment: `var: Type = ...`
/// - Walrus operator: `(var := ...)`
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
///
/// # Returns
///
/// `Some(variable_name)` if an assignment is detected, `None` otherwise.
fn extract_assigned_var(statement: &str) -> Option<String> {
    let trimmed = statement.trim();

    // Walrus operator / Go short declaration: (var := ...) or var := ...
    if let Some(pos) = trimmed.find(":=") {
        let before = &trimmed[..pos];
        let var = before.trim().trim_start_matches('(').trim();
        if is_valid_identifier(var) {
            return Some(var.to_string());
        }
        // Handle "rows, err := ..." -> take first variable
        if let Some(first) = var.split(',').next() {
            let first = first.trim();
            if is_valid_identifier(first) {
                return Some(first.to_string());
            }
        }
    }

    // Standard assignment: var = ...
    if let Some(pos) = trimmed.find('=') {
        // Skip == comparison
        if pos > 0 && trimmed.chars().nth(pos.saturating_sub(1)) == Some('=') {
            return None;
        }
        if pos + 1 < trimmed.len() && trimmed.chars().nth(pos + 1) == Some('=') {
            return None;
        }
        // Skip !=, <=, >=
        if pos > 0 {
            let prev_char = trimmed.chars().nth(pos.saturating_sub(1));
            if prev_char == Some('!') || prev_char == Some('<') || prev_char == Some('>') {
                return None;
            }
        }

        let before = &trimmed[..pos];
        // Handle type annotation: var: Type = ...
        let var_part = if let Some(colon_pos) = before.find(':') {
            &before[..colon_pos]
        } else {
            before
        };
        let var = var_part.trim();
        if is_valid_identifier(var) {
            return Some(var.to_string());
        }

        // Handle multi-language patterns where there are keywords/types before the var:
        // JavaScript/TypeScript: const/let/var name = ...
        // Rust: let/let mut name = ...
        // Java/C#: TypeName name = ...
        // C/C++: type *name = ..., type name = ...
        // Kotlin: val/var name = ...
        // Swift: let/var name = ...
        // Lua: local name = ...
        // Scala: val/var name = ...
        // OCaml: let name = ...
        // PHP: $name = ...
        let tokens: Vec<&str> = var.split_whitespace().collect();
        if tokens.len() >= 2 {
            // Take the last token as the variable name
            let last = tokens[tokens.len() - 1];
            // Strip pointer/reference markers for C/C++
            let clean = last.trim_start_matches('*').trim_start_matches('&');
            // Strip PHP $ prefix for validation but keep it
            let check = clean.trim_start_matches('$');
            if !check.is_empty() && is_valid_identifier(check) {
                return Some(clean.to_string());
            }
        }

        // Handle Elixir pattern match: {:ok, content} = ...
        // Extract last identifier from destructuring
        if var.contains('{') || var.contains('(') || var.contains('[') {
            // Find identifiers in the pattern
            let cleaned = var.replace(['{', '}', '(', ')', '[', ']', ':'], " ");
            let idents: Vec<&str> = cleaned
                .split_whitespace()
                .filter(|t| is_valid_identifier(t) && *t != "ok" && *t != "err")
                .collect();
            if let Some(last_ident) = idents.last() {
                return Some(last_ident.to_string());
            }
        }

        // Handle PHP $var = ... (single token starting with $)
        if let Some(name) = var.strip_prefix('$') {
            if is_valid_identifier(name) {
                return Some(var.to_string());
            }
        }
    }

    // No assignment found - check for function-call-as-source patterns
    // like scanf("%s", buf) or fgets(buf, ...) where the target variable
    // is an argument rather than the LHS of an assignment.
    // These are handled by detect_sources_from_call_args (separate path).
    None
}

/// Extract the first argument from a function call that matches the pattern.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
/// * `pattern` - The regex pattern that matched (to find the right call)
///
/// # Returns
///
/// `Some(argument_name)` if a variable argument is found, `None` if the argument
/// is a string literal or not a valid identifier.
fn extract_call_arg(statement: &str, pattern: &Regex) -> Option<String> {
    // Find where the pattern matches, then find the opening paren
    if let Some(m) = pattern.find(statement) {
        let after_match = &statement[m.end()..];
        // The pattern includes the `(`, so we're already past it
        // But some patterns end with `\(`, so we need to handle that
        let rest = after_match.strip_prefix('(').unwrap_or(after_match);
        // Try each argument until we find a valid variable
        let mut remaining = rest;
        loop {
            // Find end of current argument (comma or close paren)
            let end = remaining.find([',', ')']).unwrap_or(remaining.len());
            let arg = remaining[..end].trim();
            // Check if it's a variable (not a string literal)
            if !arg.is_empty()
                && !arg.starts_with('"')
                && !arg.starts_with('\'')
                && !arg.starts_with("f\"")
                && !arg.starts_with("f'")
                && !arg.starts_with("r\"")
                && !arg.starts_with("r'")
            {
                // Handle attribute access like obj.attr - just get the first part
                let var_name = arg.split('.').next().unwrap_or(arg);
                // Strip PHP $ prefix for validation
                let check_name = var_name.trim_start_matches('$');
                if is_valid_identifier(check_name) {
                    return Some(var_name.to_string());
                }
            }
            // String concatenation: "..." + var — extract var from RHS of +
            if arg.contains('+') {
                for part in arg.split('+') {
                    let part = part.trim();
                    if !part.is_empty()
                        && !part.starts_with('"')
                        && !part.starts_with('\'')
                        && !part.starts_with("f\"")
                        && !part.starts_with("f'")
                    {
                        let var_name = part.split('.').next().unwrap_or(part);
                        let check_name = var_name.trim_start_matches('$');
                        if is_valid_identifier(check_name) {
                            return Some(var_name.to_string());
                        }
                    }
                }
            }
            // Move to next argument
            if end >= remaining.len() {
                break;
            }
            let next_char = remaining.as_bytes()[end];
            if next_char == b')' {
                break;
            }
            // Skip comma and move to next arg
            remaining = &remaining[end + 1..];
        }
    }
    None
}

/// Extract interpolated variables from format strings (f-strings, template literals).
///
/// Handles:
/// - Python f-strings: `f"SELECT {query}"` -> ["query"]
/// - Python .format(): `"SELECT {}".format(query)` -> ["query"]
/// - Python % formatting: `"SELECT %s" % query` -> ["query"]
/// - JS/TS template literals: `` `SELECT ${query}` `` -> ["query"]
/// - Ruby interpolation: `"SELECT #{query}"` -> ["query"]
/// - Rust format!: `format!("SELECT {}", query)` -> ["query"]
///
/// Returns all valid identifier names found inside interpolation braces.
fn extract_interpolated_vars(statement: &str) -> Vec<String> {
    let mut vars = Vec::new();

    // Python f-string / JS template literal / Ruby: {var} or ${var} or #{var}
    // Match {identifier}, ${identifier}, #{identifier} patterns
    let _chars = statement.chars().peekable();
    let mut i = 0;
    let bytes = statement.as_bytes();

    while i < bytes.len() {
        // Detect interpolation start: { or ${ or #{
        let is_interp = match bytes[i] {
            b'{' => {
                // Could be f-string {var} or standalone — check it's not {{
                i + 1 < bytes.len() && bytes[i + 1] != b'{'
            }
            b'$' | b'#' => {
                // ${var} or #{var}
                i + 1 < bytes.len() && bytes[i + 1] == b'{'
            }
            _ => false,
        };

        if is_interp {
            // Skip to the opening brace
            let brace_start = if bytes[i] == b'{' { i } else { i + 1 };
            if brace_start + 1 < bytes.len() {
                // Find closing brace
                if let Some(close) = statement[brace_start + 1..].find('}') {
                    let inner = &statement[brace_start + 1..brace_start + 1 + close];
                    let inner = inner.trim();
                    // Could be an expression like `query` or `user.name` — take first identifier
                    let var_name = inner
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    if is_valid_identifier(var_name) {
                        vars.push(var_name.to_string());
                    }
                    i = brace_start + 1 + close + 1;
                    continue;
                }
            }
        }

        // Python .format() args: "...".format(var1, var2)
        if i + 8 < bytes.len() && &statement[i..i + 8] == ".format(" {
            let args_start = i + 8;
            if let Some(close) = statement[args_start..].find(')') {
                let args_str = &statement[args_start..args_start + close];
                for arg in args_str.split(',') {
                    let arg = arg.trim();
                    // Skip keyword args like key=val, take val
                    let val = if let Some(eq_pos) = arg.find('=') {
                        arg[eq_pos + 1..].trim()
                    } else {
                        arg
                    };
                    let var_name = val
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    if is_valid_identifier(var_name) {
                        vars.push(var_name.to_string());
                    }
                }
                i = args_start + close + 1;
                continue;
            }
        }

        // Python % formatting: "..." % (var,) or "..." % var
        if bytes[i] == b'%' && i > 0 {
            let before = statement[..i].trim_end();
            let after = statement[i + 1..].trim_start();
            if (before.ends_with('"') || before.ends_with('\'')) && !after.starts_with('%') {
                // Single var: "..." % var
                // Tuple: "..." % (var1, var2)
                let args_str = if after.starts_with('(') {
                    if let Some(close) = after.find(')') {
                        &after[1..close]
                    } else {
                        ""
                    }
                } else {
                    // Single variable
                    after
                        .split(|c: char| c.is_whitespace() || c == ')' || c == ',')
                        .next()
                        .unwrap_or("")
                };
                for arg in args_str.split(',') {
                    let arg = arg.trim();
                    let var_name = arg
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    if is_valid_identifier(var_name) {
                        vars.push(var_name.to_string());
                    }
                }
            }
        }

        i += 1;
    }

    // Deduplicate
    vars.sort();
    vars.dedup();
    vars
}

/// Check if a string is a valid Python identifier.
///
/// A valid identifier starts with a letter or underscore, and contains
/// only letters, digits, and underscores.
fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_')
            .unwrap_or(false)
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Check if an identifier appears as a standalone word in text.
/// Uses word-boundary logic: the identifier must be surrounded by
/// non-alphanumeric, non-underscore characters (or be at string edges).
/// Prevents substring matches (e.g., "user" won't match inside "user_name").
fn identifier_in_text(text: &str, ident: &str) -> bool {
    let bytes = text.as_bytes();
    let ident_len = ident.len();
    if ident_len == 0 || ident_len > bytes.len() {
        return false;
    }
    let mut pos = 0;
    while pos + ident_len <= bytes.len() {
        match text[pos..].find(ident) {
            Some(offset) => {
                let abs = pos + offset;
                let before_ok = abs == 0 || {
                    let c = bytes[abs - 1];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                let after_pos = abs + ident_len;
                let after_ok = after_pos >= bytes.len() || {
                    let c = bytes[after_pos];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                if before_ok && after_ok {
                    return true;
                }
                pos = abs + 1;
            }
            None => break,
        }
    }
    false
}

/// Check if a statement contains only a constant string (no taint).
///
/// Used to reduce false positives - string literals are not tainted.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
///
/// # Returns
///
/// `true` if the statement is a constant string assignment, `false` otherwise.
#[allow(dead_code)]
pub fn is_constant_string(statement: &str) -> bool {
    // Match patterns like: var = "string" or var = 'string'
    lazy_static! {
        static ref CONST_STRING: Regex = Regex::new(r#"^\s*\w+\s*=\s*["'][^"']*["']\s*$"#).unwrap();
    }
    CONST_STRING.is_match(statement)
}

/// Check if a statement uses ORM-safe patterns (parameterized queries).
///
/// SQLAlchemy and similar ORMs use operator overloading for safe queries.
/// These should not be flagged as SQL injection sinks.
///
/// # Arguments
///
/// * `statement` - The source code statement to analyze
///
/// # Returns
///
/// `true` if the statement uses ORM-safe patterns, `false` otherwise.
#[allow(dead_code)]
pub fn is_orm_safe_pattern(statement: &str) -> bool {
    lazy_static! {
        // SQLAlchemy patterns: session.query(...).filter(...), select(...).where(...)
        static ref ORM_SAFE: Regex =
            Regex::new(r"(\.filter\s*\(|\.where\s*\(|\.filter_by\s*\()").unwrap();
    }
    ORM_SAFE.is_match(statement)
}

// =============================================================================
// AST-Based Detection - Phase 9
// =============================================================================
//
// These functions use tree-sitter AST nodes to detect sources, sinks, and
// sanitizers. They complement the regex-based detection by:
// 1. Filtering out false positives from comments and string literals
// 2. Using structural matching instead of text patterns
// 3. Working with the full parsed tree for context
//
// The AST-based functions are used by `compute_taint_with_tree` and fall back
// to regex-based detection when the AST yields no results.

use super::ast_utils::{
    call_node_kinds, extract_call_name, extract_member_access_receiver_and_field,
    find_parent_assignment_var, is_in_comment, is_in_string, node_text, string_node_kinds,
    walk_descendants,
};

/// AST-based source pattern: matches call names and member access patterns.
///
/// **FORMAT NOTE (v0.3.0 M2):** `member_patterns` is now `(receiver, field)`
/// tuples, matched structurally via
/// [`extract_member_access_receiver_and_field`]. The v0.2.x
/// `text.contains(member_pattern)` substring path was removed at the 3
/// `detect_*_ast` predicates because it produced false positives whenever an
/// arbitrary AST node's text happened to include the pattern as a substring
/// (e.g., a string literal containing `"req.body"`). Ruby/Elixir/OCaml module
/// calls stay as `call_names` or substring fallback — see
/// `m2-ground-truth.md` §field_access_info.
struct AstSourcePattern {
    /// Simple function names that indicate a source (e.g., "input", "readLine")
    call_names: &'static [&'static str],
    /// Member-access patterns as `(receiver, field)` tuples
    /// (e.g., `("request", "args")` matches `request.args`).
    member_patterns: &'static [(&'static str, &'static str)],
    /// The source type to assign when matched
    source_type: TaintSourceType,
}

/// AST-based sink pattern. See [`AstSourcePattern`] for the v0.3.0 format note.
struct AstSinkPattern {
    call_names: &'static [&'static str],
    member_patterns: &'static [(&'static str, &'static str)],
    sink_type: TaintSinkType,
}

/// AST-based sanitizer pattern. See [`AstSourcePattern`] for the v0.3.0 format note.
struct AstSanitizerPattern {
    call_names: &'static [&'static str],
    member_patterns: &'static [(&'static str, &'static str)],
    sanitizer_type: SanitizerType,
}

/// Complete AST pattern set for a language.
struct AstLanguagePatterns {
    sources: &'static [AstSourcePattern],
    sinks: &'static [AstSinkPattern],
    sanitizers: &'static [AstSanitizerPattern],
}

// ---------------------------------------------------------------------------
// AST Pattern Definitions for All 18 Languages
// ---------------------------------------------------------------------------

static PYTHON_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["input"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("request", "args"),
            ("request", "form"),
            ("request", "values"),
            ("request", "cookies"),
            ("request", "headers"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("request", "json"), ("request", "data")],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("request", "get_json")],
        source_type: TaintSourceType::HttpBody,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("sys", "stdin")],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("os", "environ"), ("os", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        // Wildcard receiver: any `obj.read()` / `.readlines()` / `.readline()`.
        member_patterns: &[("*", "read"), ("*", "readlines"), ("*", "readline")],
        source_type: TaintSourceType::FileRead,
    },
];

static PYTHON_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        // Wildcard receiver: matches `cursor.execute(...)`, `db.executemany(...)`.
        member_patterns: &[("*", "execute"), ("*", "executemany")],
        sink_type: TaintSinkType::SqlQuery,
    },
    AstSinkPattern {
        call_names: &["eval"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &["exec"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeExec,
    },
    AstSinkPattern {
        call_names: &["compile"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeCompile,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("subprocess", "run"),
            ("subprocess", "call"),
            ("subprocess", "Popen"),
            ("subprocess", "check_output"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("os", "system"), ("os", "popen")],
        sink_type: TaintSinkType::ShellExec,
    },
    // W1-M4: Python `os.spawn*` family sinks (parity-add for Wave 2 regex
    // deletion). The legacy regex bank entry `os\.(system|popen|spawn\w*)\(`
    // wildcards across 8 spawn variants; we wire them as explicit
    // member_patterns so the AST path (call.member shape) recognizes them
    // independently. Contract names 8 entries (covering every spawn variant
    // listed in CPython `os` docs), but only 6 have direct named tests in
    // `rr_stdlib_integ_test.rs`; the remaining two (`spawnle`, `spawnlpe`)
    // are added for completeness/parity with the `\w*` regex glob.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("os", "spawnl"),
            ("os", "spawnle"),
            ("os", "spawnlp"),
            ("os", "spawnlpe"),
            ("os", "spawnv"),
            ("os", "spawnve"),
            ("os", "spawnvp"),
            ("os", "spawnvpe"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("*", "write")],
        sink_type: TaintSinkType::FileWrite,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L382-L386.
    // `Markup(`, `mark_safe(` are bare calls; `|safe` is a Jinja filter
    // (substring inside template strings) — raw fallback.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with two structured
    // entries — `("response", "write")` (Pyramid/WSGI lowercase response object)
    // and `("Response", "set_data")` (Flask Response builder). The existing
    // PYTHON_AST_SINKS FileWrite entry `("*", "write")` continues to fire on
    // generic `.write(` calls; the new HtmlOutput entry fires alongside it on
    // the specific lowercase-`response` receiver, emitting an additional Xss-
    // classified finding. ADDITIVE — does not modify the broad FileWrite entry.
    // infra-tail-issues-v1 (#57, v0.4.2 M-108): added the four canonical
    // Flask reflected-XSS sinks — `render_template_string`,
    // `render_template`, `make_response`, and bare `Response(...)` — to
    // close the gap observed in iter-2 python.md c21/c23. Pre-fix only
    // `Markup` / `mark_safe` / `|safe` / `response.write` /
    // `Response.set_data` matched, so a view returning
    // `render_template_string(f"<h1>{user}</h1>")` produced ZERO sinks
    // and therefore zero findings, even though the taint source
    // (`request.args.get`) and propagation worked. These four calls all
    // emit the HTTP response body as HTML (or trigger the Jinja
    // sandbox), exactly the CWE-79 shape that HtmlOutput projects to.
    AstSinkPattern {
        call_names: &[
            "Markup",
            "mark_safe",
            "render_template_string",
            "render_template",
            "make_response",
            "Response",
        ],
        member_patterns: &[
            ("", "|safe"),
            ("response", "write"),
            ("Response", "set_data"),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L514-L520.
    // `open(` is a bare builtin; `Path(` is a constructor call. shutil/os.path
    // are member-access shapes.
    AstSinkPattern {
        call_names: &["open", "Path"],
        member_patterns: &[
            ("os.path", "join"),
            ("shutil", "copy"),
            ("shutil", "move"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L616-L630.
    AstSinkPattern {
        call_names: &["urlopen"],
        member_patterns: &[
            ("requests", "get"),
            ("requests", "post"),
            ("requests", "put"),
            ("requests", "delete"),
            ("requests", "head"),
            ("requests", "patch"),
            ("requests", "request"),
            ("urllib.request", "urlopen"),
            ("httpx", "get"),
            ("httpx", "post"),
            ("httpx", "request"),
            ("aiohttp", "ClientSession"),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L713-L718.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("pickle", "load"),
            ("pickle", "loads"),
            ("yaml", "load"),
            ("yaml", "unsafe_load"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static PYTHON_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &["int", "float", "bool"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("shlex", "quote"), ("pipes", "quote")],
        sanitizer_type: SanitizerType::Shell,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("html", "escape"),
            ("markupsafe", "escape"),
            ("cgi", "escape"),
        ],
        sanitizer_type: SanitizerType::Html,
    },
];

static TYPESCRIPT_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("req", "body")],
        source_type: TaintSourceType::HttpBody,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("req", "params"),
            ("req", "query"),
            ("req", "cookies"),
            ("req", "headers"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("process", "env")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("process", "stdin")],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &["readline"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        // Wildcard: `fs.read()`, `obj.readFile()` etc.
        member_patterns: &[("*", "read"), ("*", "readFile")],
        source_type: TaintSourceType::FileRead,
    },
    // W1-M5: NextJS App Router + Fastify + NestJS HTTP source parity-add.
    //
    // The existing AST bank only covered `req.*` (Express convention). The
    // regex banks `TYPESCRIPT_NEXTJS_PATTERNS`, `TYPESCRIPT_FASTIFY_PATTERNS`,
    // and `TYPESCRIPT_NESTJS_PATTERNS` recognize the `request.*` receiver and
    // the `searchParams.*` chain too. This block wires the structural
    // equivalents into `TYPESCRIPT_AST_SOURCES` so Wave 2's atomic deletion
    // of the regex banks does not regress source detection.
    //
    // HttpBody — App Router request reader methods + Fastify/NestJS body unwrap.
    // `('request', 'body')` covers App Router, Fastify (`request.body`), and
    // the NestJS `@Req()` manual unwrap idiom (`const body = request.body`).
    // `('request', 'raw')` is Fastify's underlying Node-style request handle.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("request", "json"),
            ("request", "text"),
            ("request", "formData"),
            ("request", "body"),
            ("request", "raw"),
        ],
        source_type: TaintSourceType::HttpBody,
    },
    // HttpParam — request property accessors and Web-spec `URLSearchParams`
    // methods. `searchParams.{get,getAll,has}` is the Web platform shape used
    // by NextJS's `request.nextUrl.searchParams.get(...)` chain. Fastify uses
    // `request.params` / `.query`; both frameworks expose `.headers` /
    // `.cookies`.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("request", "headers"),
            ("request", "cookies"),
            ("request", "params"),
            ("request", "query"),
            ("searchParams", "get"),
            ("searchParams", "getAll"),
            ("searchParams", "has"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    // Raw-fallback HttpParam entries — non-member-access shapes.
    //  * `request.nextUrl.searchParams` is a chained property access whose
    //    structural shape varies; the substring fallback catches lines where
    //    the chain appears verbatim.
    //  * `headers().get(` / `cookies().get(` are NextJS server-component
    //    helpers (call_expression on a bare identifier, not a member-access
    //    on a fixed receiver).
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "request.nextUrl.searchParams"),
            ("", "headers().get("),
            ("", "cookies().get("),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    // NestJS decorator raw-fallbacks. Decorators (`@Body(...)`, `@Query(...)`,
    // ...) are `decorator` AST nodes, not member-access; the empty-receiver
    // raw-fallback path matches them by substring on the descendant text.
    // The decorators bind a parameter to the corresponding HTTP source:
    //  * `@Body`, `@Req`, `@Request`, `@UploadedFile(s)` -> HttpBody
    //  * `@Query`, `@Param`, `@Headers`, `@Cookies` -> HttpParam
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "@Body("),
            ("", "@Req("),
            ("", "@Request("),
            ("", "@UploadedFile("),
            ("", "@UploadedFiles("),
        ],
        source_type: TaintSourceType::HttpBody,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "@Query("),
            ("", "@Param("),
            ("", "@Headers("),
            ("", "@Cookies("),
        ],
        source_type: TaintSourceType::HttpParam,
    },
];

static TYPESCRIPT_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &["eval"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &[],
        // `new Function(...)` is a `new_expression`, not member-access — raw fallback.
        member_patterns: &[("", "new Function")],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("child_process", "exec"),
            ("child_process", "spawn"),
            ("child_process", "execSync"),
            ("child_process", "execFile"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["execSync"],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("*", "innerHTML")],
        sink_type: TaintSinkType::FileWrite,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("document", "write")],
        sink_type: TaintSinkType::FileWrite,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("*", "query"), ("*", "execute")],
        sink_type: TaintSinkType::SqlQuery,
    },
    // W1-M1: NextJS framework sinks (parity-add for Wave 2 regex deletion).
    // NextResponse.redirect — App Router response helper.
    //
    // js-res-json-fp-narrowing-v1 DROPPED `("NextResponse", "json")` from
    // this bank: NextResponse.json writes a JSON HTTP response body with
    // `Content-Type: application/json`. There is no file open, no path
    // traversal, and no XSS vector when the browser respects the content
    // type. Pre-fix it was wired here as FileWrite which projected to
    // PathTraversal via `vuln_type_from_sink`, producing a high-severity
    // FP class on every Next.js App Router handler that emitted tainted
    // input back as JSON.
    // M3 detection-accuracy-v1 BUG-16: redirect entries reclassified from
    // FileWrite -> OpenRedirect (CWE-601). Pre-fix `NextResponse.redirect(t)`
    // / `Response.redirect(t)` / bare `redirect(t)` projected through
    // `vuln_type_from_sink(FileWrite) = PathTraversal` and emitted findings
    // labelled "FileWrite with unsanitized input" / cwe_id=CWE-22 — wrong
    // ontology for an HTTP redirect with attacker-controllable target.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("NextResponse", "redirect"),
            ("Response", "redirect"),
        ],
        sink_type: TaintSinkType::OpenRedirect,
    },
    // Bare `redirect(...)` server-action helper from `next/navigation` —
    // call_expression with no receiver. Raw-fallback (empty receiver) entry
    // matches via the substring path on the call_expression's text.
    // (M3 BUG-16 reclassified to OpenRedirect.)
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", "redirect")],
        sink_type: TaintSinkType::OpenRedirect,
    },
    // JSX `dangerouslySetInnerHTML={{ __html: tainted }}` — attribute
    // identifier is a jsx_attribute, not a member-access. Raw-fallback entry
    // catches the attribute name on the line via substring path.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", "dangerouslySetInnerHTML")],
        sink_type: TaintSinkType::FileWrite,
    },
    // W1-M2: Fastify framework sinks (parity-add for Wave 2 regex deletion).
    // `reply.redirect(...)` / `.header(...)` are caught here as FileWrite
    // (semantically navigation/header-emit). `reply.send(...)` was previously
    // wired here as FileWrite but VULN-MIGRATION-V1 M3 reclassified it to
    // HtmlOutput (Xss) — see the HtmlOutput AstSinkPattern below for the
    // M3-reclassified `*.send` entries.
    // M3 detection-accuracy-v1 BUG-16: `reply.redirect` reclassified to
    // OpenRedirect (CWE-601). `reply.header` stays under FileWrite — header
    // emission still maps to PathTraversal in the legacy ontology (no
    // dedicated "header injection" sink yet).
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("reply", "redirect"),
        ],
        sink_type: TaintSinkType::OpenRedirect,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("reply", "header"),
        ],
        sink_type: TaintSinkType::FileWrite,
    },
    // W1-M3: NestJS framework sinks (parity-add for Wave 2 regex deletion).
    // NestJS controllers expose two response shapes:
    //   * Express-style `res.redirect|json(...)` — historically caught
    //     ONLY by the NESTJS_PATTERNS regex; not present in the AST bank
    //     until this milestone.
    //   * `Response`-builder form (the NestJS docs `@Res() response: Response`
    //     pattern). Real-world usage capitalizes the type but conventionally
    //     uses lowercase `response` as the parameter name; we wire BOTH
    //     receiver casings since member_patterns matches structurally on the
    //     identifier text. `('Response','redirect')` was already added in
    //     W1-M1's NextJS block (it doubles as the bare-`Response` App Router
    //     alias); the remaining redirect/json methods are added here for
    //     completeness as FileWrite (navigation/JSON-emit, not Xss).
    //
    // VULN-MIGRATION-V1 M3 RECLASSIFIED the `*.send` entries
    // (`('res','send')`, `('Response','send')`, `('response','send')`) from
    // FileWrite to HtmlOutput — those entries now live in the dedicated
    // HtmlOutput AstSinkPattern below. Reflected `.send(tainted)` is
    // semantically Xss (the response body is interpreted as HTML by the
    // browser), not PathTraversal/FileWrite.
    //
    // js-res-json-fp-narrowing-v1 DROPPED the `.json` entries
    // (`('res','json')`, `('Response','json')`, `('response','json')`)
    // from this bank for the same reason as the parallel NextJS
    // `('NextResponse','json')` removal above. `res.json(tainted)` /
    // `Response.json(tainted)` / `response.json(tainted)` write a JSON
    // HTTP response body with `Content-Type: application/json` — no
    // file open, no path traversal, no XSS (browser respects the
    // content type). Pre-fix these were wired as FileWrite which
    // projected to PathTraversal via `vuln_type_from_sink`, emitting
    // a high-severity FP on every Express/NestJS handler that echoed
    // tainted input back as JSON. Empirical repro:
    //   /tmp/repos/express/test/express.raw.js:506
    //   res.json({ buf: req.body.toString('hex') })
    // (the file-suppression mask in js-test-file-suppression-v1 hides
    // this specific case at test scope, but the underlying pattern
    // bank would still re-fire on PRODUCTION code anywhere `res.json`
    // appeared with tainted input — this fix closes the class.)
    //
    // Only the redirect entries remain wired here as FileWrite:
    // navigation responses CAN be path-traversal-equivalent when the
    // tainted target is a server-side path / route resolution. The
    // `*.send` entries live in the HtmlOutput bank below (M3
    // reclassification).
    // M3 detection-accuracy-v1 BUG-16: Express/NestJS `res.redirect` and
    // `response.redirect` are HTTP-redirect sinks (CWE-601 open-redirect),
    // not file writes. Pre-fix the FileWrite -> PathTraversal projection
    // emitted findings labelled "FileWrite with unsanitized input" with
    // CWE-22, which is incorrect for a redirect operation.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("res", "redirect"),
            ("response", "redirect"),
        ],
        sink_type: TaintSinkType::OpenRedirect,
    },
    // VULN-MIGRATION-V1 M3 — `*.send(tainted)` reclassification.
    // Express/Fastify/NestJS reply.send / res.send / response.send /
    // Response.send all emit the argument as the response body (typically
    // text/html), making reflected unsanitized input an XSS vector. Pre-M3
    // these were wired as FileWrite (the closest pre-HtmlOutput variant);
    // M3 promotes them to HtmlOutput now that the variant exists, fixing
    // the (javascript|typescript)_xss_positive vuln_type-projection mismatch.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("reply", "send"),
            ("res", "send"),
            ("Response", "send"),
            ("response", "send"),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // detection-gap-fixes-v1 — `(NextResponse, json)` + `(NextResponse, redirect)`
    // ADDITIVE HtmlOutput entries for reflected-XSS detection on the Next.js
    // App Router response helpers.
    //
    // Background: `js-res-json-fp-narrowing-v1` removed the `(NextResponse, json)`
    // entry from the FileWrite bank to kill the `path_traversal` FP class on
    // every Next.js handler that echoed user input as JSON. That removal was
    // correct: `NextResponse.json(tainted)` is NOT a path-traversal sink (no
    // file I/O, no path resolution). However, when the SERVER reflects
    // unsanitized user input as a JSON response body, downstream consumers
    // that interpret the payload as HTML (template insertion, jQuery `$.html`
    // on `response.text()`, manual `dangerouslySetInnerHTML` on a fetched
    // string) DO produce a real reflected-XSS vector — exactly the
    // CWE-79 shape this entry catches.
    //
    // This entry is wired ONLY to HtmlOutput (Xss). The FileWrite/PathTraversal
    // entry remains REMOVED — `js-res-json-fp-narrowing-v1`'s FP regression
    // guard (`vuln_js_res_json_fp_narrowing_v1_test::*_path_traversal_*_zero_findings`)
    // continues to assert ZERO `path_traversal` findings on the FP fixture
    // (which exercises ALL FOUR receivers: res / response / Response /
    // NextResponse). Adding NextResponse.json HERE (HtmlOutput, not FileWrite)
    // does NOT re-introduce the path_traversal FP — it adds an `xss` finding
    // class that is semantically correct for reflected-input JSON responses.
    //
    // SCOPE: ONLY `NextResponse.{json,redirect}` is added. Express
    // `(res|response|Response).json` is NOT added — the Express convention
    // strictly enforces `Content-Type: application/json` and there is no
    // ecosystem-wide pattern of downstream HTML-interpretation of Express
    // JSON responses that would justify the FP cost. NextResponse is added
    // because the Next.js App Router is overwhelmingly used in shapes where
    // server response bodies are rendered into client components that DO
    // interpret strings as HTML (e.g., `dangerouslySetInnerHTML` reading from
    // `await fetch(...).then(r => r.json())`).
    //
    // `NextResponse.redirect` is also added here as HtmlOutput in addition to
    // its existing FileWrite entry above (open-redirect detection). The
    // ADDITIVE wiring (no break in the for-pattern loop, per VULN-MIGRATION-V1
    // M3 convention) means `NextResponse.redirect(tainted)` now emits BOTH a
    // FileWrite sink (open-redirect / PathTraversal-equivalent) AND an
    // HtmlOutput sink (reflected-URL XSS when the redirect target is rendered
    // by a downstream component before navigation completes). The downstream
    // dedup_by `discriminant(sink_type)` filters same-type duplicates so this
    // does not produce duplicate findings within a single sink_type bucket.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("NextResponse", "json"),
            ("NextResponse", "redirect"),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L387-L394.
    // `outerHTML` is a property name (member shape with wildcard receiver).
    // `document.writeln` is member-access. `.html(` is jQuery method.
    //
    // PARITY NOTE — pattern subset deliberately avoids double-coverage with
    // existing FileWrite entries: `("*", "innerHTML")`, `("document", "write")`,
    // `("", "dangerouslySetInnerHTML")` already fire as FileWrite (pre-M2,
    // regex-removal-v1 W1-M1 wired them as the closest available enum variant
    // before HtmlOutput existed). Per dispatch-contract M2 line 156 (no
    // double-coverage), they are NOT re-added here. vuln_type_from_sink
    // projects FileWrite -> Xss/PathTraversal/etc. via context-aware mapping.
    // (M3 has separately reclassified the `*.send(...)` entries above from
    // FileWrite to HtmlOutput; the innerHTML/document.write/dangerouslySet-
    // InnerHTML entries remain FileWrite-projected via context-aware mapping
    // pending a future reclassification.)
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "outerHTML"),
            ("document", "writeln"),
            ("*", "html"),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L521-L527.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("fs", "readFile"),
            ("fs", "writeFile"),
            ("fs", "readFileSync"),
            ("fs", "writeFileSync"),
            ("path", "join"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L631-L646.
    // `fetch(`, `got(`, `node-fetch(` are bare calls. `axios(` is also bare.
    // `node-fetch` is a hyphenated identifier — raw fallback.
    AstSinkPattern {
        call_names: &["fetch", "got", "axios"],
        member_patterns: &[
            ("axios", "get"),
            ("axios", "post"),
            ("axios", "put"),
            ("axios", "delete"),
            ("axios", "request"),
            ("http", "get"),
            ("http", "request"),
            ("https", "get"),
            ("https", "request"),
            ("superagent", "get"),
            ("", "node-fetch("),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M4: Deserialize sinks for JS/TS.
    // `node-serialize`'s `unserialize(...)` is the canonical RCE-prone deserializer
    // in the JS ecosystem (CVE-2017-5941). Two-pronged structural match:
    //  * `member_patterns: [("serialize", "unserialize")]` — the idiomatic
    //    `const serialize = require('node-serialize'); serialize.unserialize(d);`
    //    shape; matched via the call-shape path in `member_patterns_match`
    //    (taint.rs:3866-3886) which splits the dotted call name on `rfind('.')`.
    //  * `("", "node-serialize")` — raw substring fallback catches lines that
    //    inline the require, e.g. `require('node-serialize').unserialize(d)`.
    // The string-literal regression-guard FP fixture (`deserialization_string_
    // literal_fp.{js,ts}`) does not mention either pattern, so adding this entry
    // does not introduce new FPs (verified via dispatch contract M4 stop_threshold).
    AstSinkPattern {
        call_names: &["unserialize"],
        member_patterns: &[
            ("serialize", "unserialize"),
            ("", "node-serialize"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static TYPESCRIPT_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &["parseInt", "Number", "parseFloat"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
    // sanitizer-removal-v1 M3 (Gap 2): Zod-style validator parity-add.
    //
    // The TYPESCRIPT_PATTERNS regex bank includes `\.(parse|safeParse)\s*\(`
    // (Numeric) to capture `schema.parse(input)` / `schema.safeParse(input)`
    // sanitizer flows; the AST bank lacked an equivalent, so M4's atomic
    // deletion of the regex bank would lose detection. Wildcard receiver
    // `"*"` matches any object via the call-shape path in
    // `member_patterns_match` (taint.rs:3077-3079), giving the same coverage
    // (and same over-broad surface — also matching `JSON.parse`, `Date.parse`)
    // as the regex it replaces. Parity-preserving.
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("*", "parse"), ("*", "safeParse")],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &["encodeURIComponent"],
        member_patterns: &[("DOMPurify", "sanitize")],
        sanitizer_type: SanitizerType::Html,
    },
];

static GO_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("fmt", "Scan"),
            ("bufio", "NewReader"),
            ("bufio", "NewScanner"),
        ],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("r", "FormValue"),
            ("r", "PostFormValue"),
            // r.URL.Query is a nested selector_expression; outer object_text is "r.URL".
            ("r.URL", "Query"),
            // Wildcard `.Query()` for non-`r` receivers (e.g., `req.Query()`).
            ("*", "Query"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        // r.Body is a member-access; ".ReadAll(r.Body)" is a substring fallback
        // for the call form (call_expression containing the whole text).
        member_patterns: &[("r", "Body"), ("", ".ReadAll(r.Body)")],
        source_type: TaintSourceType::HttpBody,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("os", "Getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("os", "Stdin")],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("os", "Open"), ("ioutil", "ReadFile")],
        source_type: TaintSourceType::FileRead,
    },
];

static GO_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("exec", "Command")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("db", "Exec"), ("db", "Query"), ("db", "QueryRow")],
        sink_type: TaintSinkType::SqlQuery,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("template", "HTML"), ("fmt", "Fprintf")],
        sink_type: TaintSinkType::FileWrite,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L528-L534.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("os", "Open"),
            ("os", "Create"),
            ("ioutil", "ReadFile"),
            ("ioutil", "WriteFile"),
            ("filepath", "Join"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L647-L654.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("http", "Get"),
            ("http", "Post"),
            ("http", "PostForm"),
            ("http", "Head"),
            ("http", "NewRequest"),
            ("http", "NewRequestWithContext"),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
];

static GO_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("strconv", "Atoi"),
            ("strconv", "ParseInt"),
            ("strconv", "ParseFloat"),
        ],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("html", "EscapeString"), ("url", "QueryEscape")],
        sanitizer_type: SanitizerType::Html,
    },
];

static JAVA_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        // `new Scanner(System.in)` is an object_creation_expression; raw fallback.
        member_patterns: &[("", "new Scanner(System.in)")],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &["readLine"],
        member_patterns: &[("", "new BufferedReader")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("request", "getParameter"), ("*", "getQueryString")],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("System", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "new FileReader"), ("Files", "readAllLines")],
        source_type: TaintSourceType::FileRead,
    },
];

static JAVA_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        // Runtime.getRuntime().exec is a chained call; raw fallback. ProcessBuilder
        // is an object_creation; raw fallback.
        member_patterns: &[
            ("", "Runtime.getRuntime().exec"),
            ("", "ProcessBuilder"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "execute"),
            ("*", "executeQuery"),
            ("*", "executeUpdate"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Class", "forName")],
        sink_type: TaintSinkType::CodeEval,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L541-L546.
    // `new File(` is an object_creation_expression — raw fallback.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended raw-fallback `member_patterns` with
    // FQN form `("", "new java.io.File(")`. The bare `("", "new File(")`
    // entry above does NOT substring-match the FQN form (the package prefix
    // interrupts the substring `"new File("`); a separate FQN entry is needed.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Files", "readString"),
            ("Files", "writeString"),
            ("Paths", "get"),
            ("", "new File("),
            ("", "new java.io.File("),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L655-L666.
    // `URL(` matches `new URL(...)` constructor; `RestTemplate` is a class
    // identifier — raw fallback. `URI.create` and `HttpRequest.newBuilder`
    // are structural. The wildcard `.send(`, `.openConnection(`, etc. use
    // `*` receiver.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("URI", "create"),
            ("HttpRequest", "newBuilder"),
            ("HttpClient", "newHttpClient"),
            ("*", "openConnection"),
            ("*", "openStream"),
            ("*", "send"),
            ("*", "getForObject"),
            ("*", "postForObject"),
            ("", "URL("),
            ("", "RestTemplate"),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L719-L723.
    // `ObjectInputStream` and `XMLDecoder` are class identifiers — raw fallback.
    // `readObject(` is a method call (wildcard receiver).
    //
    // VULN-SOURCE-PARITY-V1 M2: extended raw-fallback `member_patterns` with
    // FQN constructor form `("", "new java.io.ObjectInputStream(")` so the
    // `new java.io.ObjectInputStream(...).readObject()` chain matches
    // deterministically at the constructor-call text. The bare `("", "ObjectInputStream")`
    // entry above does substring-match `new java.io.ObjectInputStream(...)` but
    // the empirical evidence in M1-investigation.json line 159 showed sinks=[]
    // for the FQN chain shape — adding the explicit FQN raw-fallback entry
    // ensures deterministic firing across tree-sitter-java AST shapes.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "readObject"),
            ("", "ObjectInputStream"),
            ("", "XMLDecoder"),
            ("", "new java.io.ObjectInputStream("),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static JAVA_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("Integer", "parseInt"),
            ("Long", "parseLong"),
            ("Double", "parseDouble"),
        ],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("ESAPI", "encoder"),
            ("StringEscapeUtils", "escapeHtml"),
        ],
        sanitizer_type: SanitizerType::Html,
    },
];

static RUST_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        // `io::stdin`, `std::io::stdin` are scoped_identifier nodes (`::`),
        // not field_expression — raw substring fallback.
        member_patterns: &[("", "io::stdin"), ("", "std::io::stdin")],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "env::var"), ("", "std::env::var")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "env::args"), ("", "std::env::args")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "fs::read_to_string"),
            ("", "std::fs::read_to_string"),
            ("", "File::open"),
        ],
        source_type: TaintSourceType::FileRead,
    },
];

static RUST_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", "Command::new"), ("", "std::process::Command")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        // `unsafe` is a keyword inside an unsafe_block; raw fallback.
        member_patterns: &[("", "unsafe")],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", "std::ptr::write"), ("", "std::ptr::read")],
        sink_type: TaintSinkType::FileWrite,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L535-L540.
    // All four shapes are scoped_identifier paths — raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "std::fs::read_to_string"),
            ("", "std::fs::write"),
            ("", "File::open"),
            ("", "PathBuf::from"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L667-L676.
    // `reqwest::get`, `reqwest::Client`, `ureq::get`, `ureq::post`,
    // `hyper::Client`, `Url::parse` are scoped_identifier paths — raw fallback.
    //
    // RUST-VULN-TAINT-PIPELINE-V1 M2: extended with `reqwest::blocking::get`
    // and `reqwest::blocking::Client` to close the SSRF bank gap surfaced in
    // `vuln-source-parity-v1` M1 investigation. Required to close
    // `rust_ssrf_positive` whose handler calls `reqwest::blocking::get(&u)`.
    // `extract_call_name_rust` returns the full scoped_identifier text
    // ("reqwest::blocking::get") — same shape as the existing reqwest::get /
    // hyper::Client entries, matched via the raw-fallback path in
    // `member_patterns_match` (pat_rcv == "" → descendant_text.contains).
    //
    // RUST-WILDCARD-GET-NARROWING-V1 M2: the previously over-broad wildcard
    // entries `("*", "get")` and `("*", "post")` (which fired on ANY
    // `<receiver>.get(<tainted>)` / `.post(<tainted>)` member-access shape —
    // including HashMap/Vec/BTreeMap/Option) have been retired. Replaced with
    // an explicit receiver-NAME allowlist of HTTP-client conventions —
    // `client`, `agent`, `http`, `request_builder`, `req` — paired with
    // `get`/`post` fields. `member_patterns_match` matches receiver NAME-text,
    // not type, so this allowlist preserves the load-bearing
    // `let client = reqwest::Client::new(); client.get(&url)` real-world idiom
    // while eliminating the 100% FP rate on collection `.get(<tainted>)`
    // callers (closes premortem `dab0766` R8). Residual gaps for short
    // receiver names (`c`, `r`) and composed access (`self.client.get`) are
    // documented in CHANGELOG and may be addressed by a future type-aware
    // receiver-walk milestone.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("client", "get"),
            ("client", "post"),
            ("agent", "get"),
            ("agent", "post"),
            ("http", "get"),
            ("http", "post"),
            ("request_builder", "get"),
            ("request_builder", "post"),
            ("req", "get"),
            ("req", "post"),
            ("", "reqwest::get"),
            ("", "reqwest::Client"),
            ("", "reqwest::blocking::get"),
            ("", "reqwest::blocking::Client"),
            ("", "ureq::get"),
            ("", "ureq::post"),
            ("", "hyper::Client"),
            ("", "Url::parse"),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L724-L728.
    // All scoped_identifier paths — raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "serde_json::from_str"),
            ("", "serde_yaml::from_str"),
            ("", "bincode::deserialize"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static RUST_AST_SANITIZERS: &[AstSanitizerPattern] = &[AstSanitizerPattern {
    call_names: &[],
    // Turbofish `.parse::<i32>` — generic_function call, not field_expression
    // in the simple sense. Keep as raw substring fallback.
    member_patterns: &[
        ("", ".parse::<i32>"),
        ("", ".parse::<i64>"),
        ("", ".parse::<u32>"),
        ("", ".parse::<u64>"),
        ("", ".parse::<f32>"),
        ("", ".parse::<f64>"),
        ("", ".parse::<usize>"),
        ("", ".parse::<isize>"),
    ],
    sanitizer_type: SanitizerType::Numeric,
}];

// C banks: zero member_patterns (pure call_names) — type-annotation flip only.
static C_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["scanf", "fscanf", "sscanf", "fgets", "gets", "getchar"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &["getenv"],
        member_patterns: &[],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &["fread", "fopen"],
        member_patterns: &[],
        source_type: TaintSourceType::FileRead,
    },
    AstSourcePattern {
        call_names: &["recv", "recvfrom"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    // VULN-MIGRATION-V1 M3: command-line argument access — `argv[N]` is a
    // subscript_expression on the `argv` parameter. Mirrors vuln.rs
    // get_sources entry `("argv[", "Command line arguments")`.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "argv[")],
        source_type: TaintSourceType::UserInput,
    },
];

static C_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &["system", "popen", "execl", "execv", "execvp"],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["sprintf", "vsprintf"],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["strcpy", "strcat", "strncpy"],
        member_patterns: &[],
        sink_type: TaintSinkType::FileWrite,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L547-L551.
    // Note: `open` is NOT C's typical `fopen` — it's the POSIX `open(fd, ...)`
    // syscall. Both `open` and `fopen` are bare calls.
    AstSinkPattern {
        call_names: &["fopen", "open", "freopen"],
        member_patterns: &[],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-SOURCE-PARITY-V1 M2: SqlQuery sinks for C — bare DB-driver calls.
    // Restores pre-M3 vuln.rs get_sinks coverage for (SqlInjection, C) which was
    // lost in M2 audit. `mysql_query`, `PQexec`, `sqlite3_exec` are all bare
    // call_expression names with no receiver.
    AstSinkPattern {
        call_names: &["mysql_query", "PQexec", "sqlite3_exec"],
        member_patterns: &[],
        sink_type: TaintSinkType::SqlQuery,
    },
];

static C_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &["atoi", "atol", "atof", "strtol", "strtoul", "strtod"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &["snprintf"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Shell,
    },
];

static CPP_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["getline"],
        // `std::cin`, `std::getline` are qualified_identifier nodes (`::`),
        // not field_expression — raw fallback.
        member_patterns: &[("", "std::cin"), ("", "std::getline")],
        source_type: TaintSourceType::UserInput,
    },
    // VULN-SOURCE-PARITY-V1 M2: extended `call_names` to include `std::getenv`
    // FQN form alongside bare `getenv`. `std::getenv` parses as a
    // qualified_identifier whose extracted call_name is exactly the literal
    // `std::getenv` — call_names exact-match suffices (no member_pattern needed).
    AstSourcePattern {
        call_names: &["getenv", "std::getenv"],
        member_patterns: &[],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "std::ifstream"), ("", "std::fstream")],
        source_type: TaintSourceType::FileRead,
    },
    // VULN-MIGRATION-V1 M3: command-line argument access. Mirrors C.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "argv[")],
        source_type: TaintSourceType::UserInput,
    },
];

static CPP_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &["system", "popen"],
        member_patterns: &[("", "std::system")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["sprintf"],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L552-L556.
    // `std::ifstream(` / `std::ofstream(` are constructor calls (qualified
    // identifier) — raw fallback. `fopen(` is the C function (bare call).
    //
    // VULN-SOURCE-PARITY-V1 M2: extended call_names with `std::fopen` /
    // `std::freopen` (qualified-identifier exact-match — `extract_call_name_c`
    // for C++ returns the full qualified name) so the FQN forms are recognized
    // alongside the bare C variants.
    AstSinkPattern {
        call_names: &["fopen", "std::fopen", "std::freopen"],
        member_patterns: &[("", "std::ifstream"), ("", "std::ofstream")],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L729-L738.
    // Both are qualified-identifier shapes — raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "boost::archive::text_iarchive"),
            ("", "cereal::BinaryInputArchive"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
    // VULN-SOURCE-PARITY-V1 M2: SqlQuery sinks for C++ — same as C bare-call
    // shapes (no `std::` prefix on these C-API DB drivers).
    AstSinkPattern {
        call_names: &["mysql_query", "PQexec", "sqlite3_exec"],
        member_patterns: &[],
        sink_type: TaintSinkType::SqlQuery,
    },
];

static CPP_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    // sanitizer-removal-v1 M3 (Gap 1, M2-FIND-01): moved from raw-substring
    // member_patterns to call_names to fix the string-literal regression
    // surfaced post-M2 wiring (`cpp_std_stoi_in_string_literal_does_not_sanitize`).
    //
    // Prior shape `member_patterns: &[("", "std::stoi"), ...]` relied on the raw-
    // substring fallback in `member_patterns_match` (taint.rs:3094-3098), which
    // matches the descendant's full text. When the descendant is an assignment
    // whose RHS is a string literal containing the substring (e.g.
    // `std::string msg = "use std::stoi to convert";`), the assignment node
    // itself is NOT in_string, so the per-descendant `is_in_string` filter at
    // the caller (L3508/L3564) does not exclude it, and the fallback fired.
    //
    // The call_names path filters by descendant.kind() ∈ call_node_kinds (L3520-
    // 3528 in detect_sanitizer_ast and L3572-3580 in build_sanitizer_ast_index),
    // so only `call_expression` descendants are tested. tree-sitter-cpp parses
    // `std::stoi(x)` as a call_expression whose `function` field is a
    // qualified_identifier with text `std::stoi`; `extract_call_name_c` returns
    // exactly that string. String literals are not call_expression descendants,
    // so the substring-match-in-string-literal regression cannot fire.
    AstSanitizerPattern {
        call_names: &[
            "std::stoi",
            "std::stol",
            "std::stoul",
            "std::stoll",
            "std::stof",
            "std::stod",
        ],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
    // `static_cast<T>(...)` parses as a call_expression whose `function` field is
    // a template_function node; its text is `static_cast<T>`. `extract_call_name_c`
    // returns that full text, matching the call_names entry below. Same string-
    // literal-safety rationale as above.
    AstSanitizerPattern {
        call_names: &[
            "static_cast<int>",
            "static_cast<long>",
            "static_cast<float>",
            "static_cast<double>",
        ],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
];

// Ruby PARTIAL coverage (per m2-ground-truth): field_access_info covers ONLY
// `instance_variable` (the `@name` pattern). Module method calls like
// `STDIN.read`, `IO.popen`, `File.read` are structurally matched via
// `(receiver, field)` tuples — Ruby's call grammar produces `call` and
// `method_call` node kinds carrying `receiver` + `method` children, so the
// structured-shape entries fire on the AST without regex. The raw-substring
// `("", "X.y")` duplicates were deleted in M5 (field_access_info-extension-v1)
// atomically with the regex banks; structured (receiver, field) tuples are now
// the sole match path for Module.function calls. Subscripts (`params[`, `ENV[`)
// remain non-member-access raw-substring fallbacks (no call shape).
static RUBY_AST_SOURCES: &[AstSourcePattern] = &[
    // ORDER MATTERS: Stdin patterns BEFORE the bare-`gets` UserInput so the
    // structured `("STDIN", "gets")` entry wins on `STDIN.gets` calls. The
    // UserInput `call_names: ["gets"]` entry uses the `ends_with(".gets")`
    // heuristic which would otherwise shadow `STDIN.gets` and lose the more-
    // specific Stdin source type. (M5 carry-forward — pre-M5 the regex bank
    // produced both UserInput and Stdin from the same line; post-M5 only the
    // most-specific structured AST entry should fire per descendant.)
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("STDIN", "read"),
            ("STDIN", "gets"),
            ("STDIN", "readline"),
        ],
        source_type: TaintSourceType::Stdin,
    },
    AstSourcePattern {
        call_names: &["gets"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "params[")],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "ENV[")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("File", "read"), ("File", "open")],
        source_type: TaintSourceType::FileRead,
    },
];

static RUBY_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &["eval"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &["system", "exec"],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("IO", "popen")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("*", "send")],
        sink_type: TaintSinkType::CodeEval,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L395-L399.
    // `html_safe` is a bare method on a string receiver (wildcard). `raw(` is
    // a Rails view helper (bare call). `render html:` is a method call with
    // a keyword argument — raw substring fallback.
    AstSinkPattern {
        call_names: &["raw"],
        member_patterns: &[("*", "html_safe"), ("", "render html:")],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L557-L562.
    // `Pathname.new(` is a constructor — raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("File", "open"),
            ("File", "read"),
            ("File", "write"),
            ("", "Pathname.new("),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L677-L687.
    // `Net::HTTP.*`, `URI.*`, `RestClient.*`, `HTTParty.*` are scoped paths —
    // raw fallback. Bare `open(` is Kernel#open (allows http:// URLs).
    AstSinkPattern {
        call_names: &["open"],
        member_patterns: &[
            ("", "Net::HTTP.get"),
            ("", "Net::HTTP.post"),
            ("", "Net::HTTP.start"),
            ("", "URI.open"),
            ("", "URI.parse"),
            ("", "RestClient.get"),
            ("", "RestClient.post"),
            ("", "HTTParty.get"),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L739-L743.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Marshal", "load"),
            ("YAML", "load"),
            ("Psych", "load"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
    // VULN-SOURCE-PARITY-V1 M2: SqlQuery sinks for Ruby — NEW BANK. Pre-M3
    // vuln.rs get_sinks for (SqlInjection, Ruby) was entirely absent from the
    // canonical bank. `ActiveRecord::Base.connection.execute` is a multi-segment
    // call chain — raw fallback substring. `raw_sql(` is a bare ActiveRecord
    // helper. `("connection", "execute")` is the structured shape for the
    // shorter `connection.execute(...)` form when a `connection` accessor is in
    // scope.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "ActiveRecord::Base.connection.execute"),
            ("", "raw_sql("),
            ("connection", "execute"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
];

static RUBY_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("*", "to_i"), ("*", "to_f")],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("", "CGI.escapeHTML"),
            ("", "Rack::Utils.escape_html"),
        ],
        sanitizer_type: SanitizerType::Html,
    },
];

static KOTLIN_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["readLine", "readln"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("System", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        // Bare identifier — raw fallback.
        member_patterns: &[("", "BufferedReader")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("request", "getParameter")],
        source_type: TaintSourceType::HttpParam,
    },
    // VULN-MIGRATION-V1 M3: Ktor query parameter access — raw-fallback for
    // `call.request.queryParameters["..."]` subscript shape and the typed
    // `call.parameters[`. Mirrors vuln.rs get_sources for Kotlin.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "call.request.queryParameters"),
            ("", "call.parameters["),
            ("", "call.receive<"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
];

static KOTLIN_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "Runtime.getRuntime().exec"),
            ("", "ProcessBuilder"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "execute"),
            ("*", "executeQuery"),
            ("", "prepareStatement"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L563-L568.
    // `File(` is a constructor call — raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Files", "readString"),
            ("Files", "writeString"),
            ("Paths", "get"),
            ("", "File("),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L744-L747.
    // `ObjectInputStream(` is a constructor — raw fallback.
    // `readObject(` is a method call (wildcard receiver).
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "readObject"),
            ("", "ObjectInputStream("),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static KOTLIN_AST_SANITIZERS: &[AstSanitizerPattern] = &[AstSanitizerPattern {
    call_names: &[],
    member_patterns: &[
        ("*", "toInt"),
        ("*", "toLong"),
        ("*", "toDouble"),
        ("*", "toFloat"),
    ],
    sanitizer_type: SanitizerType::Numeric,
}];

static SWIFT_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["readLine"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        // Three-segment chain — match outer (object_text="ProcessInfo.processInfo", field="environment").
        member_patterns: &[("ProcessInfo.processInfo", "environment")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        // FileManager.default is structural; URLSession is a bare identifier (raw).
        member_patterns: &[
            ("FileManager", "default"),
            ("", "URLSession"),
        ],
        source_type: TaintSourceType::FileRead,
    },
    // VULN-MIGRATION-V1 M3: command-line argument access — Swift's
    // `CommandLine.arguments[N]` is a subscript on a static member chain.
    // Mirrors vuln.rs get_sources for Swift.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "CommandLine.arguments")],
        source_type: TaintSourceType::UserInput,
    },
    // VULN-SOURCE-PARITY-V1 M2: Vapor `request.query[...]` HTTP query subscript
    // is a multi-segment subscript shape (request.query[String.self]). Raw-
    // fallback substring match on the access prefix catches the variants.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "request.query[")],
        source_type: TaintSourceType::HttpParam,
    },
];

static SWIFT_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        // VULN-MIGRATION-V1 M3: bare `system(` is the C-bridged shell call;
        // mirrors vuln.rs's substring entry for Swift.
        call_names: &["system"],
        // `Process()` is a constructor call; `NSTask` is a bare identifier — raw.
        //
        // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with structured
        // entries `("Process", "launchedProcess")` and `("Process", "run")` for
        // Foundation Process static-method shapes that distinct from the
        // `Process()` constructor form.
        member_patterns: &[
            ("", "Process()"),
            ("", "NSTask"),
            ("Process", "launchedProcess"),
            ("Process", "run"),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    // VULN-SOURCE-PARITY-V1 M2: extended SqlQuery bank with wildcard-receiver
    // method shapes for Swift database libraries (GRDB / SQLite.swift).
    // `executeQuery` and `prepareStatement` are common methods on a `db` /
    // `connection` receiver of varying type — wildcard receiver matches.
    AstSinkPattern {
        call_names: &["sqlite3_exec"],
        member_patterns: &[("*", "executeQuery"), ("*", "prepareStatement")],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L569-L573.
    // Swift labelled-argument constructor calls (`String(contentsOfFile:`,
    // `Data(contentsOf:`) are unique syntax shapes — raw substring fallback.
    // `FileManager.default.contents(atPath:` is a chained-call labelled
    // argument — raw fallback.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with two additional
    // FileHandle labelled-argument constructor forms.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "String(contentsOfFile:"),
            ("", "Data(contentsOf:"),
            ("", "FileManager.default.contents(atPath:"),
            ("", "FileHandle(forReadingAtPath:"),
            ("", "FileHandle(forWritingAtPath:"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
];

static SWIFT_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &["Int", "Double", "Float"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        // `addingPercentEncoding` is a method-call name.
        member_patterns: &[("*", "addingPercentEncoding")],
        sanitizer_type: SanitizerType::Html,
    },
];

static CSHARP_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("Console", "ReadLine")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("Request", "QueryString"), ("Request", "Form")],
        source_type: TaintSourceType::HttpParam,
    },
    // VULN-MIGRATION-V1 M3: ASP.NET Core / .NET request access — `Request.Query[
    // "..."]` is a subscript shape; raw-fallback for the access prefix.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "Request.Query["), ("", "Request.Form[")],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("Environment", "GetEnvironmentVariable")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("File", "ReadAllText"),
            ("File", "ReadAllLines"),
            ("File", "OpenRead"),
            // Bare identifier — raw fallback.
            ("", "StreamReader"),
        ],
        source_type: TaintSourceType::FileRead,
    },
];

static CSHARP_AST_SINKS: &[AstSinkPattern] = &[
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with raw-fallback
    // (`""`, `"Process.Start"`) so qualified `System.Diagnostics.Process.Start`
    // FQN call shape is matched via the substring path. Mirrors Java's
    // `("", "Runtime.getRuntime().exec")` convention.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Process", "Start"), ("", "Process.Start")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            // `SqlCommand` is a bare identifier (constructor call) — raw fallback.
            ("", "SqlCommand"),
            ("*", "ExecuteNonQuery"),
            ("*", "ExecuteReader"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Activator", "CreateInstance")],
        sink_type: TaintSinkType::CodeEval,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L405-L409.
    // `Html.Raw(` and `AppendHtml(` are method calls. `@Html.Raw(` is a Razor
    // operator-prefix template syntax — raw fallback (carry-forward documented
    // per validator mandate razor_java_constructor_carry_forward_documented).
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with
    // (`Response`, `Write`) restoring pre-M3 vuln.rs (Xss, CSharp) coverage that
    // was lost in M2 audit.
    AstSinkPattern {
        call_names: &["AppendHtml"],
        member_patterns: &[
            ("Html", "Raw"),
            ("", "@Html.Raw("),
            ("Response", "Write"),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L574-L579.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with raw-fallback
    // (`""`, `"System.IO.File.Open"`) for the qualified FQN form. Bare
    // `File.Open` is already covered by the structured `("File", "Open")`
    // entry above.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("File", "Open"),
            ("File", "ReadAllText"),
            ("File", "WriteAllText"),
            ("Path", "Combine"),
            ("", "System.IO.File.Open"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L748-L757.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with three
    // raw-fallback FQN/constructor shapes for legacy .NET deserializers.
    // `JavaScriptSerializer(` is a constructor call (followed by `.Deserialize`);
    // `new XmlSerializer` and `new SoapFormatter` are object_creation
    // expressions. Restores pre-M3 vuln.rs (Deserialize, CSharp) coverage.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("BinaryFormatter", "Deserialize"),
            ("NetDataContractSerializer", "Deserialize"),
            ("", "JavaScriptSerializer("),
            ("", "new XmlSerializer"),
            ("", "new SoapFormatter"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static CSHARP_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[
            ("int", "Parse"),
            ("Convert", "ToInt32"),
            ("double", "Parse"),
        ],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("HttpUtility", "HtmlEncode")],
        sanitizer_type: SanitizerType::Html,
    },
];

static SCALA_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        // `StdIn.readLine` is structural; `scala.io.StdIn` is a multi-segment qualified
        // path — raw fallback.
        member_patterns: &[
            ("StdIn", "readLine"),
            ("", "scala.io.StdIn"),
        ],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("System", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("Source", "fromFile")],
        source_type: TaintSourceType::FileRead,
    },
    // VULN-MIGRATION-V1 M3: Play / generic Scala HTTP request access.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("request", "getQueryString"),
            ("request", "queryString"),
            ("request", "body"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
];

static SCALA_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        // `Runtime.getRuntime.exec` is multi-segment chain (raw); `sys.process` is
        // structural; `Process(` is a constructor call (raw).
        member_patterns: &[
            ("", "Runtime.getRuntime.exec"),
            ("sys", "process"),
            ("", "Process("),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("*", "execute"), ("*", "executeQuery")],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L580-L585.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with raw-fallback
    // FQN form `("", "scala.io.Source.fromFile")`. The bare `("Source", "fromFile")`
    // structured entry only matches when the receiver text equals exactly
    // "Source" — a fully-qualified `scala.io.Source.fromFile(...)` call has
    // receiver text "scala.io.Source" which `rfind('.')` does not split into
    // "Source"; the raw-fallback substring entry catches the FQN form.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Source", "fromFile"),
            ("Files", "readString"),
            ("Files", "writeString"),
            ("Paths", "get"),
            ("", "scala.io.Source.fromFile"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L758-L761.
    // `ObjectInputStream(` is a constructor — raw fallback.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with explicit FQN
    // raw-fallback `("", "new java.io.ObjectInputStream(")` so the qualified
    // constructor form matches deterministically (the bare
    // `("", "ObjectInputStream(")` should substring-match per the comment, but
    // M1 empirical evidence showed the FQN shape did not fire — the explicit
    // FQN entry resolves the gap).
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("*", "readObject"),
            ("", "ObjectInputStream("),
            ("", "new java.io.ObjectInputStream("),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

static SCALA_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("*", "toInt"), ("*", "toLong"), ("*", "toDouble")],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("StringEscapeUtils", "escapeHtml")],
        sanitizer_type: SanitizerType::Html,
    },
];

// PHP: superglobal subscripts (`$_GET[`, `$_POST[`, etc.) are subscript_expression
// nodes, not member-access — raw fallback. `->query(` is PHP's member-access
// arrow operator, distinct from `.` field access; raw fallback preserves shape.
static PHP_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "$_GET["),
            ("", "$_REQUEST["),
            ("", "$_COOKIE["),
            ("", "$_SERVER["),
        ],
        source_type: TaintSourceType::HttpParam,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("", "$_POST[")],
        source_type: TaintSourceType::HttpBody,
    },
    AstSourcePattern {
        call_names: &["fgets"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &["file_get_contents"],
        member_patterns: &[],
        source_type: TaintSourceType::FileRead,
    },
    AstSourcePattern {
        call_names: &["getenv"],
        member_patterns: &[("", "$_ENV[")],
        source_type: TaintSourceType::EnvVar,
    },
];

static PHP_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &["eval"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeEval,
    },
    AstSinkPattern {
        call_names: &[
            "exec",
            "system",
            "passthru",
            "shell_exec",
            "popen",
            "proc_open",
        ],
        member_patterns: &[],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["mysqli_query"],
        member_patterns: &[("", "->query(")],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L400-L404.
    // `echo` and `print` are PHP statement-keywords (echo_statement / print_intrinsic);
    // `<?= ` is the short-tag template raw output — all raw substring fallbacks.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("", "echo "),
            ("", "print "),
            ("", "<?= "),
        ],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L586-L592.
    // `include(` and `require(` are language constructs — raw substring
    // fallback. Bare `fopen`, `file_get_contents`, `file_put_contents` are
    // function calls (call_names path).
    AstSinkPattern {
        call_names: &["fopen", "file_get_contents", "file_put_contents"],
        member_patterns: &[
            ("", "include("),
            ("", "require("),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: HttpRequest (Ssrf) sinks per vuln.rs L688-L697.
    // `Guzzle\Client` is a namespaced class identifier — raw fallback.
    // `->request(` is PHP arrow-method-call — raw fallback (mirrors the
    // existing PHP `->query(` SqlQuery convention).
    // NOTE: `fopen` and `file_get_contents` deliberately appear in BOTH the
    // FileOpen and HttpRequest sink banks — vuln.rs lists them under both
    // VulnTypes because PHP's `fopen` / `file_get_contents` accept http://
    // URLs (SSRF) AND filesystem paths (PathTraversal). The taint engine
    // emits one TaintFlow per matching (pattern, descendant) pair, so the
    // pattern is correctly mirrored from vuln.rs.
    AstSinkPattern {
        call_names: &[
            "fopen",
            "file_get_contents",
            "curl_exec",
            "curl_setopt",
            "get_headers",
            "readfile",
        ],
        member_patterns: &[
            ("", "Guzzle\\Client"),
            ("", "->request("),
        ],
        sink_type: TaintSinkType::HttpRequest,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L762-L765.
    AstSinkPattern {
        call_names: &["unserialize", "yaml_parse"],
        member_patterns: &[],
        sink_type: TaintSinkType::Deserialize,
    },
];

static PHP_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &["intval", "floatval"],
        // `(int)`, `(float)` are cast expressions — raw fallback.
        member_patterns: &[("", "(int)"), ("", "(float)")],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &["htmlspecialchars", "htmlentities"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Html,
    },
    AstSanitizerPattern {
        call_names: &["mysqli_real_escape_string"],
        member_patterns: &[],
        sanitizer_type: SanitizerType::Shell,
    },
];

static LUA_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("io", "read")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("os", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("io", "open")],
        source_type: TaintSourceType::FileRead,
    },
    // VULN-MIGRATION-V1 M3: OpenResty ngx HTTP request access — multi-segment
    // chain (`ngx.req.get_uri_args(`, `ngx.req.get_post_args(`); raw fallback.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "ngx.req.get_uri_args"),
            ("", "ngx.req.get_post_args"),
            ("", "ngx.req.get_headers"),
        ],
        source_type: TaintSourceType::HttpParam,
    },
];

static LUA_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("os", "execute")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("io", "popen")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &["loadstring", "load", "dofile", "loadfile"],
        member_patterns: &[],
        sink_type: TaintSinkType::CodeEval,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L414-L417.
    // OpenResty `ngx.say(` / `ngx.print(` — member-access shape.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("ngx", "say"), ("ngx", "print")],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L593-L597.
    // `io.open` is member-access; `dofile` and `loadfile` are bare calls but
    // already wired as CodeEval above. Adding them here as FileOpen too
    // mirrors vuln.rs's dual classification (file-load vector).
    AstSinkPattern {
        call_names: &["dofile", "loadfile"],
        member_patterns: &[("io", "open")],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-SOURCE-PARITY-V1 M2: SqlQuery sinks for Lua/Luau — colon-method
    // call form `db:query(...)` / `conn:execute(...)`. Lua's `:method` syntax
    // parses distinctly from member access (`.`); raw-substring fallback on
    // the call_expression text catches `:query(` / `:execute(` reliably.
    // Restores pre-M3 vuln.rs (SqlInjection, Lua) coverage that was entirely
    // absent in the canonical bank. Luau dispatches to LUA_AST_* via
    // get_ast_patterns so the same entries cover both.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", ":query("), ("", ":execute(")],
        sink_type: TaintSinkType::SqlQuery,
    },
];

// Lua sanitizers: zero member_patterns — type-annotation flip only.
static LUA_AST_SANITIZERS: &[AstSanitizerPattern] = &[AstSanitizerPattern {
    call_names: &["tonumber"],
    member_patterns: &[],
    sanitizer_type: SanitizerType::Numeric,
}];

// Elixir PARTIAL coverage (per m2-ground-truth): field_access_info covers ONLY
// `unary_operator` (the `@module_attribute` pattern). `Module.function` calls
// like `IO.gets`, `System.cmd` are structurally matched via `(receiver, field)`
// tuples — the W2-pre call-shape path uses `extract_call_name_elixir` + `rfind('.')`
// to split into a `(receiver, field)` pair, so the structured-shape entries fire
// on the AST without regex. Multi-segment receivers (e.g. `Ecto.Adapters.SQL.query`)
// are supported because `rfind('.')` keeps the full dotted prefix as the receiver.
// The raw-substring `("", "X.y")` duplicates were deleted in M5 (field_access_info-
// extension-v1) atomically with the regex banks; structured tuples are now the
// sole match path.
static ELIXIR_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("IO", "gets")],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("System", "get_env")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("File", "read"), ("File", "read!")],
        source_type: TaintSourceType::FileRead,
    },
    // VULN-MIGRATION-V1 M3: Phoenix conn.params subscript access — raw fallback
    // for the multi-segment subscript shape `conn.params["..."]`.
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("", "conn.params["),
            ("", "conn.body_params["),
            ("", "conn.query_params["),
        ],
        source_type: TaintSourceType::HttpParam,
    },
];

static ELIXIR_AST_SINKS: &[AstSinkPattern] = &[
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with three
    // additional ShellExec shapes:
    //   * `("System","shell")` — mirrors System.cmd structural shape.
    //   * `("Port","open")` — Port.open/2 spawns OS processes.
    //   * `("","" :os.cmd("")` raw-fallback for atom-prefixed Erlang call
    //     `:os.cmd(...)` (parses distinctly from Elixir Module.fn calls).
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("System", "cmd"),
            ("System", "shell"),
            ("Port", "open"),
            ("", ":os.cmd("),
        ],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Code", "eval_string")],
        sink_type: TaintSinkType::CodeEval,
    },
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with bang-suffix
    // variant `("Ecto.Adapters.SQL","query!")` and `Repo.query`/`query!`
    // shorthand. Elixir's `!` suffix produces a distinct atom — tree-sitter-
    // elixir parses `query!` as a separate identifier from `query`.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Ecto.Adapters.SQL", "query"),
            ("Ecto.Adapters.SQL", "query!"),
            ("Repo", "query"),
            ("Repo", "query!"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: HtmlOutput (Xss) sinks per vuln.rs L410-L413.
    // `Phoenix.HTML.raw(` is a multi-segment Module.function call —
    // structural via (Phoenix.HTML, raw) tuple per Elixir `rfind('.')` shape.
    // Bare `raw(` is a Phoenix view helper — call_names path.
    AstSinkPattern {
        call_names: &["raw"],
        member_patterns: &[("Phoenix.HTML", "raw")],
        sink_type: TaintSinkType::HtmlOutput,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L598-L602.
    //
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with bang-suffix
    // variants — `read!`, `write!`, `open!`, `stream!` — Elixir's bang-
    // convention raises on error and parses as a distinct atom in tree-sitter-
    // elixir. The non-bang forms remain for soft-error-tuple shapes.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("File", "read"),
            ("File", "read!"),
            ("File", "write"),
            ("File", "write!"),
            ("File", "open!"),
            ("File", "stream!"),
            ("Path", "join"),
        ],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L766.
    // `:erlang.binary_to_term(` is an Erlang-call shape (atom-prefixed) —
    // raw fallback.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("", ":erlang.binary_to_term(")],
        sink_type: TaintSinkType::Deserialize,
    },
];

static ELIXIR_AST_SANITIZERS: &[AstSanitizerPattern] = &[
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("", "String.to_integer"), ("", "String.to_float")],
        sanitizer_type: SanitizerType::Numeric,
    },
    AstSanitizerPattern {
        call_names: &[],
        member_patterns: &[("", "Phoenix.HTML.html_escape")],
        sanitizer_type: SanitizerType::Html,
    },
];

// OCaml PARTIAL coverage (per m2-ground-truth): field_access_info covers ONLY
// `field_get_expression` (the `record.field` pattern). `Module.function` calls
// like `Sys.command`, `Unix.execvp`, `Sqlite3.exec` are application_expression
// nodes — extract_call_name_ocaml returns the value-path (e.g. "Sys.command") by
// walking application_expression's child(0). The W2-pre call-shape path uses
// rfind('.') to split into a `(receiver, field)` pair, so the structured-shape
// entries fire on the AST without regex. Bare-call forms (`read_line`,
// `input_line`) remain in `call_names`. Parenthesised application form
// `(Sys.command) cmd` is a known limitation per plan §9 risk #3 — not covered.
// The raw-substring `("", "X.y")` duplicates were deleted in M5 (field_access_info-
// extension-v1) atomically with the regex banks; structured tuples are now the
// sole match path for Module.function calls.
static OCAML_AST_SOURCES: &[AstSourcePattern] = &[
    AstSourcePattern {
        call_names: &["read_line"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &["input_line"],
        member_patterns: &[],
        source_type: TaintSourceType::UserInput,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[("Sys", "getenv")],
        source_type: TaintSourceType::EnvVar,
    },
    AstSourcePattern {
        call_names: &[],
        member_patterns: &[
            ("In_channel", "read_all"),
            ("In_channel", "input_all"),
        ],
        source_type: TaintSourceType::FileRead,
    },
];

static OCAML_AST_SINKS: &[AstSinkPattern] = &[
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Sys", "command")],
        sink_type: TaintSinkType::ShellExec,
    },
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[("Unix", "execvp")],
        sink_type: TaintSinkType::ShellExec,
    },
    // VULN-SOURCE-PARITY-V1 M2: extended `member_patterns` with three additional
    // OCaml DB-driver shapes — `Mariadb.Stmt.execute`, `Postgresql.exec`,
    // `Mysql.exec`, plus `Sqlite3.prepare` (parameterized-query precursor that
    // taints when the query string is concatenated). Multi-segment receivers
    // like `Mariadb.Stmt` are supported because OCaml's `extract_call_name_ocaml`
    // returns the full dotted prefix and `rfind('.')` keeps it as the receiver.
    // Restores pre-M3 vuln.rs (SqlInjection, OCaml) coverage that was reduced
    // to a single entry in M2 audit.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Sqlite3", "exec"),
            ("Sqlite3", "prepare"),
            ("Mariadb.Stmt", "execute"),
            ("Postgresql", "exec"),
            ("Mysql", "exec"),
        ],
        sink_type: TaintSinkType::SqlQuery,
    },
    // VULN-MIGRATION-V1 M2: FileOpen (PathTraversal) sinks per vuln.rs L603-L607.
    // `open_in` and `open_out` are bare OCaml functions; `Filename.concat`
    // is a Module.function call (structural via Elixir/OCaml rfind('.') path).
    AstSinkPattern {
        call_names: &["open_in", "open_out"],
        member_patterns: &[("Filename", "concat")],
        sink_type: TaintSinkType::FileOpen,
    },
    // VULN-MIGRATION-V1 M2: Deserialize sinks per vuln.rs L767-L770.
    AstSinkPattern {
        call_names: &[],
        member_patterns: &[
            ("Marshal", "from_channel"),
            ("Marshal", "from_string"),
        ],
        sink_type: TaintSinkType::Deserialize,
    },
];

// OCaml sanitizers: zero member_patterns — type-annotation flip only.
static OCAML_AST_SANITIZERS: &[AstSanitizerPattern] = &[AstSanitizerPattern {
    call_names: &["int_of_string", "float_of_string"],
    member_patterns: &[],
    sanitizer_type: SanitizerType::Numeric,
}];

/// Get AST-based taint patterns for a given language.
fn get_ast_patterns(language: Language) -> AstLanguagePatterns {
    match language {
        Language::Python => AstLanguagePatterns {
            sources: PYTHON_AST_SOURCES,
            sinks: PYTHON_AST_SINKS,
            sanitizers: PYTHON_AST_SANITIZERS,
        },
        Language::TypeScript | Language::JavaScript => AstLanguagePatterns {
            sources: TYPESCRIPT_AST_SOURCES,
            sinks: TYPESCRIPT_AST_SINKS,
            sanitizers: TYPESCRIPT_AST_SANITIZERS,
        },
        Language::Go => AstLanguagePatterns {
            sources: GO_AST_SOURCES,
            sinks: GO_AST_SINKS,
            sanitizers: GO_AST_SANITIZERS,
        },
        Language::Java => AstLanguagePatterns {
            sources: JAVA_AST_SOURCES,
            sinks: JAVA_AST_SINKS,
            sanitizers: JAVA_AST_SANITIZERS,
        },
        Language::Rust => AstLanguagePatterns {
            sources: RUST_AST_SOURCES,
            sinks: RUST_AST_SINKS,
            sanitizers: RUST_AST_SANITIZERS,
        },
        Language::C => AstLanguagePatterns {
            sources: C_AST_SOURCES,
            sinks: C_AST_SINKS,
            sanitizers: C_AST_SANITIZERS,
        },
        Language::Cpp => AstLanguagePatterns {
            sources: CPP_AST_SOURCES,
            sinks: CPP_AST_SINKS,
            sanitizers: CPP_AST_SANITIZERS,
        },
        Language::Ruby => AstLanguagePatterns {
            sources: RUBY_AST_SOURCES,
            sinks: RUBY_AST_SINKS,
            sanitizers: RUBY_AST_SANITIZERS,
        },
        Language::Kotlin => AstLanguagePatterns {
            sources: KOTLIN_AST_SOURCES,
            sinks: KOTLIN_AST_SINKS,
            sanitizers: KOTLIN_AST_SANITIZERS,
        },
        Language::Swift => AstLanguagePatterns {
            sources: SWIFT_AST_SOURCES,
            sinks: SWIFT_AST_SINKS,
            sanitizers: SWIFT_AST_SANITIZERS,
        },
        Language::CSharp => AstLanguagePatterns {
            sources: CSHARP_AST_SOURCES,
            sinks: CSHARP_AST_SINKS,
            sanitizers: CSHARP_AST_SANITIZERS,
        },
        Language::Scala => AstLanguagePatterns {
            sources: SCALA_AST_SOURCES,
            sinks: SCALA_AST_SINKS,
            sanitizers: SCALA_AST_SANITIZERS,
        },
        Language::Php => AstLanguagePatterns {
            sources: PHP_AST_SOURCES,
            sinks: PHP_AST_SINKS,
            sanitizers: PHP_AST_SANITIZERS,
        },
        Language::Lua | Language::Luau => AstLanguagePatterns {
            sources: LUA_AST_SOURCES,
            sinks: LUA_AST_SINKS,
            sanitizers: LUA_AST_SANITIZERS,
        },
        Language::Elixir => AstLanguagePatterns {
            sources: ELIXIR_AST_SOURCES,
            sinks: ELIXIR_AST_SINKS,
            sanitizers: ELIXIR_AST_SANITIZERS,
        },
        Language::Ocaml => AstLanguagePatterns {
            sources: OCAML_AST_SOURCES,
            sinks: OCAML_AST_SINKS,
            sanitizers: OCAML_AST_SANITIZERS,
        },
    }
}

// ---------------------------------------------------------------------------
// Fast-path substring prefilter (vuln-fastpath-substring-prefilter-v1)
// ---------------------------------------------------------------------------

/// Cached per-language source+sink substring needles for the
/// `scan_file_vulns` per-function fast-path skip.
///
/// **Correctness contract.** A `TaintFlow` requires BOTH a source AND a sink
/// in the same function body. If NEITHER any source nor sink call-name
/// appears anywhere in the function body's source text, no `TaintFlow` is
/// possible and the expensive CFG/DFG/taint construction can be safely
/// skipped. The substring check is a SUPERSET of the AST detector — a hit
/// inside a string literal or comment still runs the full analysis (the
/// canonical AST sanitizer / `is_in_string` filters resolve those FPs at
/// the detector layer); a clean miss is a true negative.
///
/// **Needle construction.**
/// - `call_names: [N]` → needle `N` (e.g. `eval`, `exec`, `raw`).
/// - `member_patterns: [(R, F)]` with `R` non-empty and `R != "*"` →
///   needle `R.F` (e.g. `request.args`, `os.system`).
/// - `member_patterns: [(R, F)]` with `R == ""` or `R == "*"` →
///   needle `.F` (e.g. `.execute`, `.read`). The leading `.` keeps the
///   needle length ≥ 2 even for short fields like `("*", "get")` and
///   prevents the prefilter from matching identifier substrings (e.g.
///   `getter` would not match `.get`).
///
/// No length filter is applied to call_names: dropping short bare-call
/// names like `raw` (Phoenix HTML helper, Ruby ERB helper) would risk
/// false-negative skips when a function uses ONLY the bare-call form. The
/// safe default is to include them; the cost is just less skipping when
/// such names happen to appear in non-vulnerable code.
pub fn fastpath_pattern_strings(language: Language) -> &'static [&'static str] {
    use std::sync::OnceLock;

    macro_rules! fastpath_static {
        ($name:ident, $lang:expr) => {{
            static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
            CELL.get_or_init(|| build_fastpath_needles($lang))
                .as_slice()
        }};
    }

    match language {
        Language::Python => fastpath_static!(PY, Language::Python),
        Language::TypeScript => fastpath_static!(TS, Language::TypeScript),
        Language::JavaScript => fastpath_static!(JS, Language::JavaScript),
        Language::Go => fastpath_static!(GO, Language::Go),
        Language::Java => fastpath_static!(JAVA, Language::Java),
        Language::Rust => fastpath_static!(RUST, Language::Rust),
        Language::C => fastpath_static!(C, Language::C),
        Language::Cpp => fastpath_static!(CPP, Language::Cpp),
        Language::Ruby => fastpath_static!(RB, Language::Ruby),
        Language::Kotlin => fastpath_static!(KT, Language::Kotlin),
        Language::Swift => fastpath_static!(SW, Language::Swift),
        Language::CSharp => fastpath_static!(CS, Language::CSharp),
        Language::Scala => fastpath_static!(SC, Language::Scala),
        Language::Php => fastpath_static!(PHP, Language::Php),
        Language::Lua => fastpath_static!(LUA, Language::Lua),
        Language::Luau => fastpath_static!(LUAU, Language::Luau),
        Language::Elixir => fastpath_static!(EX, Language::Elixir),
        Language::Ocaml => fastpath_static!(OCAML, Language::Ocaml),
    }
}

/// Build the deduplicated needle list for one language. Called once per
/// language by the `OnceLock` cells in `fastpath_pattern_strings`.
fn build_fastpath_needles(language: Language) -> Vec<&'static str> {
    let patterns = get_ast_patterns(language);
    // Use a HashSet keyed by &'static str to dedupe before flattening to a
    // Vec. Both `call_names` and `member_patterns` arrays contain `&'static
    // str` references, so the resulting needles inherit that lifetime when
    // they originate from `call_names` directly. For composed needles
    // (`R.F`, `.F`) we must allocate a `String`, then leak it to obtain a
    // `&'static str` — leak is bounded (one call per language per process,
    // bounded by the static pattern table size).
    use std::collections::HashSet;
    let mut set: HashSet<&'static str> = HashSet::new();

    fn intern_needle(s: String) -> &'static str {
        // Box::leak is the canonical way to obtain &'static str from a
        // dynamically built String. Bounded leak: this function is called
        // O(patterns) times per language, once per process.
        Box::leak(s.into_boxed_str())
    }

    for src in patterns.sources {
        for &name in src.call_names {
            if !name.is_empty() {
                set.insert(name);
            }
        }
        for &(receiver, field) in src.member_patterns {
            if field.is_empty() {
                continue;
            }
            if receiver.is_empty() {
                // Empty receiver = scoped_identifier path / bare-name
                // raw-fallback shape (e.g. Rust `("", "env::var")`,
                // PHP `("", "$_GET")`, Elixir `("", "Code.eval_string")`).
                // The path appears as-is in source text; use it directly.
                set.insert(field);
            } else if receiver == "*" {
                // Wildcard receiver = member access with arbitrary
                // receiver name (e.g. Python `("*", "execute")`). The
                // source text always contains a leading `.` for member
                // access — `.execute` won't match the keyword in
                // identifiers like `executor`.
                set.insert(intern_needle(format!(".{}", field)));
            } else {
                // Specific receiver (e.g. Python `("os", "system")` →
                // `os.system`).
                set.insert(intern_needle(format!("{}.{}", receiver, field)));
            }
        }
    }
    for sink in patterns.sinks {
        for &name in sink.call_names {
            if !name.is_empty() {
                set.insert(name);
            }
        }
        for &(receiver, field) in sink.member_patterns {
            if field.is_empty() {
                continue;
            }
            if receiver.is_empty() {
                // See source-loop comment for the empty / "*" / specific
                // receiver convention.
                set.insert(field);
            } else if receiver == "*" {
                set.insert(intern_needle(format!(".{}", field)));
            } else {
                set.insert(intern_needle(format!("{}.{}", receiver, field)));
            }
        }
    }
    set.into_iter().collect()
}

/// Returns `true` iff the given function body text contains AT LEAST one
/// substring from the language's source-or-sink needle set. When `false`,
/// the caller may safely skip the CFG/DFG/taint analysis for that function
/// (no `TaintFlow` is possible — see `fastpath_pattern_strings`).
///
/// O(N · M) worst case where N = body length, M = pattern count. M ≤ ~80
/// per language; for typical function bodies the inner loop short-circuits
/// on the first hit. Profiled simple-loop is fast enough; Aho-Corasick was
/// considered (see plan) but the linear scan dominates the savings from
/// avoiding CFG/DFG construction.
pub fn function_body_has_taint_pattern(body_text: &str, language: Language) -> bool {
    let needles = fastpath_pattern_strings(language);
    needles.iter().any(|n| body_text.contains(n))
}

// ---------------------------------------------------------------------------
// AST-Based Detection Functions
// ---------------------------------------------------------------------------

/// Match a list of `(receiver, field)` tuple patterns against an AST descendant.
///
/// **v0.3.0 M2 — structural rewrite of v0.2.x `text.contains(member_pattern)`.**
///
/// The legacy substring path produced false positives whenever an arbitrary AST
/// node's text happened to include the pattern as a substring (e.g., a string
/// literal containing `"req.body"`). After this rewrite, three matching modes
/// are supported via the tuple convention:
///
/// 1. **Structural exact** — `(receiver, field)` with both non-empty and
///    `receiver != "*"`: matches a member-access node whose `object_text == receiver`
///    AND `member_text == field`. Uses [`extract_member_access_receiver_and_field`]
///    to dispatch via [`field_access_info`].
/// 2. **Structural wildcard** — `("*", field)`: matches a member-access node
///    whose `member_text == field`, with any receiver. Used for `".read(`,
///    `".write(`, `".execute(` shapes that previously matched by substring.
/// 3. **Raw substring fallback** — `("", raw_text)`: matches against
///    `node_text(descendant)` only when the descendant is in a code-bearing
///    context (already filtered by `is_in_string` / `is_in_comment` upstream).
///    Used for shapes that aren't member-access in the tree-sitter sense:
///    subscript access (`$_GET[`, `params[`, `ENV[`), `new` expressions
///    (`new Function`, `new BufferedReader`), C++ template-call (`static_cast<int>`),
///    bare identifiers (`unsafe`, `BufferedReader`, `NSTask`), and Ruby/Elixir/OCaml
///    qualified module calls (`IO.popen`, `System.cmd`, `Sys.command`) where
///    `field_access_info` only covers `@ivar` / `@attr` / `record.field` (per
///    `m2-ground-truth.md` partial-coverage note).
///
/// The string/comment context filter is applied by callers BEFORE entering
/// this function — see `is_in_string` and `is_in_comment` checks in each
/// `detect_*_ast` predicate. The fallback substring mode therefore can never
/// fire inside a string literal.
fn member_patterns_match(
    descendant: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    member_patterns: &[(&str, &str)],
    descendant_text: &str,
) -> bool {
    // First check structural matches against member-access nodes.
    if let Some((rcv, field)) =
        extract_member_access_receiver_and_field(descendant, source, language)
    {
        for (pat_rcv, pat_field) in member_patterns {
            if pat_rcv.is_empty() {
                continue; // raw-substring entries are handled in the fallback below
            }
            if *pat_rcv == "*" {
                if field == *pat_field {
                    return true;
                }
            } else if rcv == *pat_rcv && field == *pat_field {
                return true;
            }
        }
        // Structural match attempted; no entries matched.
        // Fall through to the call-shape and substring-fallback paths.
    }

    // W2-pre: structural match for call-shaped nodes whose dotted call name
    // encodes a (receiver, field) pair. In several languages
    // (Java `method_invocation`, TypeScript/JavaScript/Go/Rust/C# `call_expression`)
    // a method call like `request.getParameter(...)` is a single call node whose
    // `extract_call_name` yields the dotted form `"request.getParameter"`.
    // It is NOT a `field_access` / `member_expression` node, so the structural
    // path above (which dispatches via `field_access_info`) does not see it.
    //
    // Pre-W2-pre, member_patterns like `("request", "getParameter")` only
    // matched when the same expression appeared as a field-access in some other
    // descendant — which fails for direct method calls. The regex bank caught
    // these cases via substring; under AST-only dispatch (Wave-2-atomic), they
    // were lost. Splitting the dotted call name on the last `.` reconstructs
    // the (receiver, field) pair structurally, with no regex coupling.
    let call_kinds = call_node_kinds(language);
    if call_kinds.contains(&descendant.kind()) {
        if let Some(call_name) = extract_call_name(descendant, source, language) {
            if let Some(dot_pos) = call_name.rfind('.') {
                let rcv = &call_name[..dot_pos];
                let field = &call_name[dot_pos + 1..];
                for (pat_rcv, pat_field) in member_patterns {
                    if pat_rcv.is_empty() {
                        continue;
                    }
                    if *pat_rcv == "*" {
                        if field == *pat_field {
                            return true;
                        }
                    } else if rcv == *pat_rcv && field == *pat_field {
                        return true;
                    }
                }
            }
        }
    }

    // Raw-substring fallback for non-member-access shapes (subscripts, new
    // expressions, qualified module calls in Ruby/Elixir/OCaml, etc.). The
    // caller has already filtered out string-literal and comment contexts via
    // `is_in_string` / `is_in_comment`, so this fallback is safe with respect
    // to the github#24 substring-in-string-literal regression.
    for (pat_rcv, pat_field) in member_patterns {
        if pat_rcv.is_empty() && descendant_text.contains(pat_field) {
            return true;
        }
    }

    false
}

/// W2-pre: Regex-free first-argument extraction for AST-detected calls.
///
/// Walks the matched call node's children to find its `arguments` list (or the
/// first `(`-bracketed group if no `arguments` field is exposed by the grammar)
/// and returns the first child argument that is a plain identifier. Skips
/// string-literal arguments.
///
/// This replaces the regex-coupled `extract_call_arg(stmt_text, regex)` for the
/// AST detection path so that var extraction does not depend on the regex bank
/// being populated. Wave-2-atomic deletes the regex bank; without this helper
/// every AST hit that would have relied on `extract_call_arg` returns
/// `var = None` and the source/sink is silently dropped.
fn extract_first_identifier_arg_ast(
    descendant: &tree_sitter::Node,
    source: &[u8],
    language: Language,
) -> Option<String> {
    let string_kinds = string_node_kinds(language);

    // VULN-MIGRATION-V1 M3 (PHP echo carry-forward from M2-carry-forward.json):
    // PHP `echo $x;`, `print $x;`, and `<?= $x ?>` are language statement-keywords
    // (echo_statement / print_intrinsic / unary_expression) — not call_expression.
    // They have no `arguments` field and no `argument`-kind children. Walk the
    // named children of the statement node and recursively scan for the first
    // variable_name / name identifier descendant. Skips string-literal subtrees
    // already filtered by is_in_string upstream of detect_sinks_ast.
    if language == Language::Php
        && matches!(
            descendant.kind(),
            "echo_statement" | "print_intrinsic"
        )
    {
        // BFS over named descendants seeking the first variable_name / name node.
        let mut stack: Vec<tree_sitter::Node> = vec![*descendant];
        while let Some(node) = stack.pop() {
            // Skip string-literal subtrees (defensive — caller also filters).
            if string_kinds.contains(&node.kind()) {
                continue;
            }
            // PHP variable references: `variable_name` (with `$` prefix in text).
            // Member accesses (`$obj->name`) appear as `member_access_expression`
            // with a `variable_name` first child.
            if matches!(node.kind(), "variable_name" | "name") && node.id() != descendant.id() {
                let text = node_text(&node, source);
                let head = text.trim_start_matches('$');
                let head = head.split('.').next().unwrap_or(head);
                let head = head.split("->").next().unwrap_or(head);
                if is_valid_identifier(head) {
                    return Some(head.to_string());
                }
            }
            // Push named children for further walk.
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.is_named() {
                        stack.push(child);
                    }
                }
            }
        }
        return None;
    }

    // RUBY-BACKTICK-EXTRACTION-V1: Ruby subshell var-extraction.
    //
    // tree-sitter-ruby 0.23.1 parses both `cmd` (backtick) and %x{cmd}/%x[cmd]/
    // %x(cmd) as a single `subshell` named-node whose children are
    // `interpolation` / `string_content` / `escape_sequence`. The generic
    // args-list path below (post all language-specific arms) requires either
    // `child_by_field_name("arguments")` OR a child whose kind contains
    // "argument" or equals "call_suffix". `subshell` has NEITHER, so the
    // generic path returns None for subshell. Without this arm, the new
    // Ruby subshell dispatch arm in detect_sinks_ast would extract var=None
    // and emit zero sinks → ruby_command_injection_positive stays RED.
    //
    // BFS over named descendants of the subshell, recursing into
    // `interpolation` (and any other named children). Skip `string_kinds`
    // subtrees so identifiers inside `string_content` are not picked up.
    // Return the first non-self `identifier`'s text. Mirrors the PHP echo
    // BFS at L3954-3982 stylistically.
    if language == Language::Ruby && descendant.kind() == "subshell" {
        let mut stack: Vec<tree_sitter::Node> = vec![*descendant];
        while let Some(node) = stack.pop() {
            // Skip string-literal subtrees (defensive).
            if string_kinds.contains(&node.kind()) {
                continue;
            }
            if node.kind() == "identifier" && node.id() != descendant.id() {
                let text = node_text(&node, source);
                let head = text.split('.').next().unwrap_or(text);
                if is_valid_identifier(head) {
                    return Some(head.to_string());
                }
            }
            // Push named children for further walk.
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.is_named() {
                        stack.push(child);
                    }
                }
            }
        }
        return None;
    }

    // CPP-DESER-DECLARATION-V1: Cpp typed-local-declaration sink shape.
    //
    // tree-sitter-cpp 0.23.4 parses
    // `boost::archive::text_iarchive ia(std::stringstream(d) >> obj);` as
    // `declaration → init_declarator { value: argument_list { binary_expression
    // { left: call_expression(std::stringstream → identifier(d)) ... } } }`.
    // The descendant matched by detect_sinks_ast for the
    // `boost::archive::text_iarchive` Deserialize sink is the `declaration`
    // node itself. `declaration` has neither an `arguments` field nor any
    // child whose kind contains "argument" (the `init_declarator` does not
    // match `kind.contains("argument")`), so the generic args-list lookup at
    // L4076 returns None and var-extraction silently drops the source/sink
    // pair → cpp_deserialization_positive RED.
    //
    // Walk: descendant(declaration) → child of kind init_declarator
    // → child_by_field_name("value") = argument_list. Then delegate to
    // extract_first_identifier_arg_ast_descent (added by
    // var-extract-nested-constructor-v1) which BFS-traverses the
    // argument_list's named descendants in source order, with the
    // string-kind filter applied at every level — so closes-#24
    // string-literal regression-guard is preserved by construction.
    //
    // Mirrors the BFS-style language-specific arms at L3959-3994 (PHP echo)
    // and L4013-4036 (Ruby subshell): early-arm short-circuits before the
    // generic args-list lookup.
    if language == Language::Cpp && descendant.kind() == "declaration" {
        for i in 0..descendant.child_count() {
            let Some(init_decl) = descendant.child(i) else {
                continue;
            };
            if !init_decl.is_named() || init_decl.kind() != "init_declarator" {
                continue;
            }
            if let Some(value) = init_decl.child_by_field_name("value") {
                if let Some(found) =
                    extract_first_identifier_arg_ast_descent(&value, source, language, 0)
                {
                    return Some(found);
                }
            }
        }
        return None;
    }

    // OCaml application_expression has no "arguments" field — child(0) is the
    // function expression and child(1..) are the arguments. Scan from child(1).
    // (M5 carry-forward: pre-M5 the regex bank's `extract_call_arg` text-scanned
    // past the function name; post-M5 we need an AST equivalent.)
    if language == Language::Ocaml && descendant.kind() == "application_expression" {
        for i in 1..descendant.child_count() {
            let Some(child) = descendant.child(i) else {
                continue;
            };
            if !child.is_named() {
                continue;
            }
            if string_kinds.contains(&child.kind()) {
                continue;
            }
            let text = node_text(&child, source).trim();
            if text.is_empty() {
                continue;
            }
            // OCaml-specific: strip parens around `(expr)` parenthesised args.
            let stripped = text
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            let head = stripped.split('.').next().unwrap_or(stripped);
            let head = head.trim_start_matches('&');
            if is_valid_identifier(head) {
                return Some(head.to_string());
            }
        }
        return None;
    }

    // Find an arguments-like child. Common field names across grammars:
    //   * tree-sitter-{python,go,c,cpp,rust,java,javascript,typescript}: "arguments"
    //   * tree-sitter-{kotlin,swift,csharp}: positional — the call_expression's
    //     last child is typically the value_arguments / arguments node.
    let args = descendant
        .child_by_field_name("arguments")
        .or_else(|| {
            // Positional fallback: scan children for a node whose kind looks like
            // an arg list.
            for i in 0..descendant.child_count() {
                if let Some(child) = descendant.child(i) {
                    let kind = child.kind();
                    if kind.contains("argument") || kind == "call_suffix" {
                        return Some(child);
                    }
                }
            }
            None
        })?;

    // VAR-EXTRACT-NESTED-CONSTRUCTOR-V1: when the first NAMED non-string-literal
    // arg-list child is itself a constructor / call / instance-shaped node and
    // the direct-identifier path fails for it, descend into that child via BFS
    // seeking the first identifier-shaped leaf. Mirrors the BFS-over-named-
    // descendants pattern previously used for PHP echo_statement at L3954-3982.
    // (NOT OCaml application_expression at L3989-4016 — that is a flat 1-level
    // scan, not a BFS.) Bounded recursion (depth 5) with `string_kinds` filter
    // applied at every level (closes-#24 string-literal regression-guard
    // preserved at every level).
    //
    // Per-language descend-through set:
    //   * Java   : { object_creation_expression, method_invocation,
    //                parenthesized_expression }
    //   * Scala  : { call_expression, instance_expression, infix_expression }
    //   * Cpp    : { binary_expression, call_expression,
    //                parenthesized_expression, argument_list }
    //
    // CPP-DESER-DECLARATION-V1: the Cpp descend-through set is FORWARD-COVERAGE
    // for future Cpp call_expression sinks whose first argument is a nested
    // constructor / parenthesised / binary expression. The cpp_deserialization_
    // positive fixture (matched on `declaration` node) does NOT consult this
    // path — it short-circuits via the new entry arm above the generic
    // args-list lookup at L4076 and delegates straight to the descent helper.
    // The extension here is a separate forward-coverage hook reachable only
    // when extract_first_identifier_arg_ast is invoked on a Cpp
    // call_expression-shaped descendant (e.g., a future
    // cpp/path_traversal_positive style fixture wrapping a nested constructor
    // in the argument list).
    let descend_kinds: &[&str] = match language {
        Language::Java => &[
            "object_creation_expression",
            "method_invocation",
            "parenthesized_expression",
        ],
        Language::Scala => &[
            "call_expression",
            "instance_expression",
            "infix_expression",
        ],
        Language::Cpp => &[
            "binary_expression",
            "call_expression",
            "parenthesized_expression",
            "argument_list",
        ],
        _ => &[],
    };

    // Walk arg list children and return the first identifier-like text.
    for i in 0..args.child_count() {
        let Some(child) = args.child(i) else {
            continue;
        };
        // Skip punctuation tokens like '(', ',', ')'.
        if !child.is_named() {
            continue;
        }
        // Skip string-literal arguments.
        if string_kinds.contains(&child.kind()) {
            continue;
        }
        let text = node_text(&child, source).trim();
        if !text.is_empty() {
            // For dotted identifiers (e.g., `obj.attr`), take the leading identifier.
            let head = text.split('.').next().unwrap_or(text);
            // Strip Rust reference operator and PHP `$` sigil.
            let head = head.trim_start_matches('&').trim_start_matches('$');
            if is_valid_identifier(head) {
                return Some(head.to_string());
            }
        }

        // VAR-EXTRACT-NESTED-CONSTRUCTOR-V1: direct path failed for this child.
        // If its kind is in the per-language descend-through set, recurse via
        // BFS to find the leftmost identifier-shaped leaf inside it.
        if descend_kinds.contains(&child.kind()) {
            if let Some(found) =
                extract_first_identifier_arg_ast_descent(&child, source, language, 0)
            {
                return Some(found);
            }
        }
    }

    None
}

/// VAR-EXTRACT-NESTED-CONSTRUCTOR-V1: BFS-over-named-descendants helper that
/// descends through nested constructor / call / instance / infix nodes seeking
/// the first identifier-shaped leaf. Bounded recursion (depth 5) with explicit
/// `string_node_kinds(language)` filter at every level so closes-#24
/// string-literal regression-guard is preserved at every recursion step.
///
/// Closes vuln-source-parity-v1 M5 Bucket B Java + Scala subset
/// (java_deserialization_positive, scala_deserialization_positive).
/// cpp_deserialization_positive is closed by `cpp-deser-declaration-v1`
/// via a Cpp `declaration` entry arm in the OUTER helper that delegates
/// to this descent helper on the init_declarator's `value` argument_list.
fn extract_first_identifier_arg_ast_descent(
    node: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    depth: u32,
) -> Option<String> {
    const MAX_DEPTH: u32 = 5;
    if depth >= MAX_DEPTH {
        return None;
    }
    let string_kinds = string_node_kinds(language);

    // BFS over named descendants in source order. Push children in REVERSE so
    // pop yields leftmost first.
    let mut stack: Vec<(tree_sitter::Node, u32)> = Vec::new();
    for i in (0..node.child_count()).rev() {
        if let Some(c) = node.child(i) {
            if c.is_named() {
                stack.push((c, depth + 1));
            }
        }
    }

    while let Some((cur, d)) = stack.pop() {
        if d >= MAX_DEPTH {
            continue;
        }
        // Skip string-literal subtrees at every level (closes-#24 guard).
        if string_kinds.contains(&cur.kind()) {
            continue;
        }

        // Try as identifier-leaf via the same head-extraction rules as the
        // outer helper.
        let text = node_text(&cur, source).trim();
        if !text.is_empty() {
            let head = text.split('.').next().unwrap_or(text);
            let head = head.trim_start_matches('&').trim_start_matches('$');
            if is_valid_identifier(head) {
                return Some(head.to_string());
            }
        }

        // Push named children in reverse so leftmost child pops first.
        for i in (0..cur.child_count()).rev() {
            if let Some(c) = cur.child(i) {
                if c.is_named() {
                    stack.push((c, d + 1));
                }
            }
        }
    }

    None
}

/// W2-pre: Regex-free RHS-of-assignment extraction for sink-shaped descendants.
///
/// For sinks expressed as assignments (e.g.,
/// `element.innerHTML = userContent`, JSX
/// `dangerouslySetInnerHTML={{ __html: html }}`), the dangerous data flows from
/// the RHS into the matched LHS expression. This walks the descendant's
/// ancestor chain looking for an assignment-like parent and returns the first
/// identifier appearing on the RHS.
///
/// Falls back to a simple text-based scan of the line when the AST shape is
/// not a standard assignment node (handles JSX `{...}` expression containers
/// where the descendant text already includes the `=`).
fn extract_assignment_rhs_ident(
    descendant: &tree_sitter::Node,
    source: &[u8],
    line_text: &str,
) -> Option<String> {
    // Pure text-based scan: find the LAST `=` that is not part of `==`, `!=`,
    // `<=`, `>=`, and walk forward to the first valid identifier.
    let bytes = line_text.as_bytes();
    let mut idx = line_text.len();
    while idx > 0 {
        if let Some(pos) = line_text[..idx].rfind('=') {
            let before = if pos > 0 { bytes[pos - 1] } else { b' ' };
            let after = if pos + 1 < bytes.len() {
                bytes[pos + 1]
            } else {
                b' '
            };
            if before != b'=' && before != b'!' && before != b'<' && before != b'>'
                && after != b'='
            {
                let rhs = &line_text[pos + 1..];
                // Skip JSX expression-container braces `{{` / `{`.
                let rhs = rhs.trim_start_matches(['{', ' ', '\t']);
                // Skip object-literal property keys like `__html:` so that
                // `dangerouslySetInnerHTML={{ __html: html }}` returns `html`.
                if let Some(colon_pos) = rhs.find(':') {
                    // Only treat as object literal if the segment before `:`
                    // is a bare identifier (no parens / commas).
                    let key = rhs[..colon_pos].trim();
                    if is_valid_identifier(key) {
                        let rest = rhs[colon_pos + 1..].trim();
                        let var = rest
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .next()
                            .unwrap_or("");
                        if is_valid_identifier(var) {
                            return Some(var.to_string());
                        }
                    }
                }
                let var = rhs
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                if is_valid_identifier(var) {
                    return Some(var.to_string());
                }
            }
            idx = pos;
        } else {
            break;
        }
    }
    let _ = (descendant, source); // reserved for future structural fallback
    None
}

/// Detect taint sources using AST nodes from a parsed tree.
///
/// Walks the tree looking for call nodes that match known source patterns.
/// Unlike regex-based detection, this correctly skips matches inside
/// comments and string literals.
///
/// # Arguments
/// * `root` - Root node of the function/file to analyze
/// * `source` - Source code bytes
/// * `language` - Programming language
/// * `line_filter` - If Some, only detect sources on this specific line
///
/// # Returns
/// Vector of detected taint sources
pub fn detect_sources_ast(
    root: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    line_filter: Option<u32>,
) -> Vec<TaintSource> {
    let patterns = get_ast_patterns(language);
    let mut sources = Vec::new();
    let descendants = walk_descendants(*root);

    for descendant in &descendants {
        // Skip comments and strings
        if is_in_comment(descendant, language) || is_in_string(descendant, language) {
            continue;
        }

        let line = descendant.start_position().row as u32 + 1;
        if let Some(filter) = line_filter {
            if line != filter {
                continue;
            }
        }

        let text = node_text(descendant, source);

        for pattern in patterns.sources {
            let matched = pattern.call_names.iter().any(|name| {
                // Check if this is a call node with matching name
                let call_kinds = call_node_kinds(language);
                if call_kinds.contains(&descendant.kind()) {
                    if let Some(call_name) = extract_call_name(descendant, source, language) {
                        return call_name == *name || call_name.ends_with(&format!(".{}", name));
                    }
                }
                false
            }) || member_patterns_match(descendant, source, language, pattern.member_patterns, text);

            if matched {
                let line_text = std::str::from_utf8(source)
                    .unwrap_or("")
                    .lines()
                    .nth((line - 1) as usize)
                    .unwrap_or("");
                // Try to get variable from parent assignment
                let var = find_parent_assignment_var(descendant, source, language)
                    .or_else(|| extract_assigned_var(line_text))
                    // W2-pre: regex-free fallback for sources whose tainted
                    // data is delivered by-pointer in the first call argument
                    // (e.g., C `fgets(buf, ..., stdin)`, `scanf("%s", buf)`,
                    // `fread(buf, ...)`). Walks the descendant's `arguments`
                    // list and returns the first identifier-shaped child.
                    .or_else(|| extract_first_identifier_arg_ast(descendant, source, language))
                    // M5 carry-forward (field_access_info-extension-v1): for
                    // call-shaped sources whose only arguments are string
                    // literals (e.g., Elixir `IO.gets("> ")` in a pipe chain,
                    // OCaml `Sys.getenv "VAR"`), neither parent-assignment nor
                    // first-arg extraction yields a var. Fall back to the same
                    // text-based heuristic the regex bank used pre-M5
                    // (`extract_source_var_from_statement`) so the AST hit is
                    // not silently dropped.
                    .or_else(|| extract_source_var_from_statement(line_text))
                    // Final fallback: derive a synthetic var from the call's
                    // leading identifier (`IO.gets` -> `IO`). This preserves
                    // the parity with the M4 regex-bank behavior where these
                    // shapes still produced a TaintSource (with a synthetic
                    // var) so that source-type assertions in integration tests
                    // succeed. Without this, AST-detected sources whose args
                    // are entirely string literals would be silently dropped
                    // post-regex-deletion.
                    .or_else(|| {
                        let call_kinds = call_node_kinds(language);
                        if call_kinds.contains(&descendant.kind()) {
                            extract_call_name(descendant, source, language)
                                .and_then(|name| {
                                    name.split('.').next().map(|s| s.to_string())
                                })
                                .filter(|s| is_valid_identifier(s))
                        } else {
                            None
                        }
                    });

                if let Some(var) = var {
                    sources.push(TaintSource {
                        var,
                        line,
                        source_type: pattern.source_type,
                        statement: Some(line_text.to_string()),
                    });
                    break; // Only one source per node
                }
            }
        }
    }

    // verification-pipeline-completeness-v1 (P11.BUG-AGG-13): Java Spring
    // annotation source pass. Method parameters annotated with
    // `@RequestParam` / `@PathVariable` / `@ModelAttribute` /
    // `@RequestBody` / `@RequestHeader` are HTTP-bound entry points; they
    // weren't covered by the existing `member_patterns` machinery (which
    // matches `request.getParameter` style member access — the legacy
    // servlet API). Spring controllers don't reference `request.*`
    // explicitly, so without this pass `tldr taint` was blind to every
    // Spring-MVC controller.
    if language == Language::Java {
        sources.extend(detect_spring_annotation_sources(root, source, line_filter));
    }

    sources
}

/// Detect Spring web annotation taint sources on Java method parameters.
///
/// Walks `formal_parameter` nodes in the AST, inspects their `modifiers`
/// child for any of the recognised Spring annotations, and emits one
/// `TaintSource` per matching parameter (binding the parameter's
/// identifier as the tainted variable name and its source line).
///
/// Recognised annotations and their `TaintSourceType` mapping:
///
/// | Annotation         | TaintSourceType |
/// |--------------------|-----------------|
/// | `@RequestParam`    | HttpParam       |
/// | `@PathVariable`    | HttpParam       |
/// | `@RequestHeader`   | HttpParam       |
/// | `@ModelAttribute`  | HttpParam       |
/// | `@RequestBody`     | HttpBody        |
///
/// FQN forms (`@org.springframework.web.bind.annotation.RequestParam`)
/// are matched by tail-identifier comparison so any import shape works.
fn detect_spring_annotation_sources(
    root: &tree_sitter::Node,
    source: &[u8],
    line_filter: Option<u32>,
) -> Vec<TaintSource> {
    let mut out = Vec::new();
    let descendants = walk_descendants(*root);
    for node in &descendants {
        if node.kind() != "formal_parameter" {
            continue;
        }
        let line = node.start_position().row as u32 + 1;
        if let Some(filter) = line_filter {
            if line != filter {
                continue;
            }
        }

        // Find the annotation tail-name and the parameter identifier.
        let annot = match find_first_spring_annotation(node, source) {
            Some(a) => a,
            None => continue,
        };
        let var_name = match formal_parameter_identifier(node, source) {
            Some(v) => v,
            None => continue,
        };

        let source_type = match annot.as_str() {
            "RequestBody" => TaintSourceType::HttpBody,
            "RequestParam" | "PathVariable" | "RequestHeader" | "ModelAttribute" => {
                TaintSourceType::HttpParam
            }
            _ => continue,
        };

        let statement = std::str::from_utf8(source)
            .unwrap_or("")
            .lines()
            .nth((line - 1) as usize)
            .map(|s| s.to_string());

        out.push(TaintSource {
            var: var_name,
            line,
            source_type,
            statement,
        });
    }
    out
}

/// Spring annotations recognised as Java taint sources by
/// `detect_spring_annotation_sources`. FQN forms are matched by
/// tail-identifier comparison so `@RequestParam`,
/// `@org.springframework.web.bind.annotation.RequestParam`, and any
/// other intermediate qualifier shape all hit the same entry.
const SPRING_ANNOT_NAMES: &[&str] = &[
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "ModelAttribute",
    "RequestBody",
];

/// Walk a `formal_parameter` node looking for a Spring web annotation
/// in its `modifiers` subtree. Returns the tail identifier of the
/// matching annotation (e.g. `RequestParam` for `@RequestParam` or
/// `@org.springframework.web.bind.annotation.RequestParam`).
fn find_first_spring_annotation(param: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    fn descend(node: &tree_sitter::Node, source: &[u8], out: &mut Option<String>) {
        if out.is_some() {
            return;
        }
        let kind = node.kind();
        if kind == "marker_annotation" || kind == "annotation" {
            let text = node_text(node, source);
            let trimmed = text.trim_start_matches('@');
            let head = trimmed
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or("");
            let last = head.rsplit('.').next().unwrap_or("").to_string();
            if SPRING_ANNOT_NAMES.contains(&last.as_str()) {
                *out = Some(last);
                return;
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            descend(&child, source, out);
            if out.is_some() {
                return;
            }
        }
    }

    let mut found: Option<String> = None;
    descend(param, source, &mut found);
    found
}

/// Extract the parameter identifier (variable name) from a Java
/// `formal_parameter` node. Tree-sitter-java places the identifier as
/// the last `identifier` child of the parameter.
fn formal_parameter_identifier(param: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = param.walk();
    let mut last_ident: Option<String> = None;
    for child in param.children(&mut cursor) {
        if child.kind() == "identifier" {
            last_ident = Some(node_text(&child, source).to_string());
        }
    }
    last_ident
}

/// Detect taint sinks using AST nodes from a parsed tree.
///
/// Similar to `detect_sources_ast` but for dangerous operations (sinks).
pub fn detect_sinks_ast(
    root: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    line_filter: Option<u32>,
) -> Vec<TaintSink> {
    let patterns = get_ast_patterns(language);
    let mut sinks = Vec::new();
    let descendants = walk_descendants(*root);

    for descendant in &descendants {
        if is_in_comment(descendant, language) || is_in_string(descendant, language) {
            continue;
        }

        let line = descendant.start_position().row as u32 + 1;
        if let Some(filter) = line_filter {
            if line != filter {
                continue;
            }
        }

        let text = node_text(descendant, source);

        for pattern in patterns.sinks {
            let matched = pattern.call_names.iter().any(|name| {
                let call_kinds = call_node_kinds(language);
                if call_kinds.contains(&descendant.kind()) {
                    if let Some(call_name) = extract_call_name(descendant, source, language) {
                        return call_name == *name || call_name.ends_with(&format!(".{}", name));
                    }
                }
                false
            }) || member_patterns_match(descendant, source, language, pattern.member_patterns, text);

            if matched {
                let stmt_text = std::str::from_utf8(source)
                    .unwrap_or("")
                    .lines()
                    .nth((line - 1) as usize)
                    .unwrap_or("");

                // Extract variable argument. Prefer the regex-bank path
                // (existing additive behavior) but fall back to AST-only
                // helpers so the AST hit is not silently dropped when the
                // regex bank is empty (Wave-2-atomic).
                let regex_patterns = get_patterns(language);
                let var = regex_patterns
                    .sinks
                    .iter()
                    .find(|(p, _)| p.is_match(stmt_text))
                    .and_then(|(p, _)| extract_call_arg(stmt_text, p))
                    .or_else(|| {
                        regex_patterns
                            .sinks
                            .iter()
                            .find(|(p, _)| p.is_match(stmt_text))
                            .and_then(|(p, _)| extract_sink_var_from_statement(stmt_text, p))
                    })
                    // W2-pre: regex-free fallbacks. (1) call-shaped sinks —
                    // walk the descendant's `arguments` list. (2) JSX
                    // `dangerouslySetInnerHTML={{ __html: tainted }}` and
                    // `obj.prop = tainted` shapes — scan for `=`-RHS
                    // identifiers. These keep AST detection self-contained
                    // when the regex bank is removed.
                    .or_else(|| extract_first_identifier_arg_ast(descendant, source, language))
                    .or_else(|| extract_assignment_rhs_ident(descendant, source, stmt_text))
                    // M5 carry-forward (field_access_info-extension-v1): for
                    // call-shaped sinks whose arguments are entirely
                    // non-identifier (e.g., Elixir `System.cmd([])` with a
                    // list literal arg, OCaml `Sqlite3.exec db cmd` with
                    // multiple receivers), derive a synthetic var from the
                    // call's leading identifier (`System.cmd` -> `System`).
                    // Preserves M4 regex-bank parity: the regex path produced
                    // a TaintSink (sometimes with synthetic var) so that
                    // sink-type assertions in integration tests succeed.
                    .or_else(|| {
                        let call_kinds = call_node_kinds(language);
                        if call_kinds.contains(&descendant.kind()) {
                            extract_call_name(descendant, source, language)
                                .and_then(|name| {
                                    name.split('.').next().map(|s| s.to_string())
                                })
                                .filter(|s| is_valid_identifier(s))
                        } else {
                            None
                        }
                    });

                if let Some(var) = var {
                    sinks.push(TaintSink {
                        var,
                        line,
                        sink_type: pattern.sink_type,
                        tainted: false,
                        statement: Some(stmt_text.to_string()),
                    });
                    // VULN-MIGRATION-V1 M3: do NOT break — a single descendant
                    // can match multiple AstSinkPattern entries with different
                    // sink_types (e.g., PHP `file_get_contents` is registered
                    // under BOTH FileOpen and HttpRequest per the M2 dual-
                    // classification convention; pre-M3 the `break` here
                    // emitted only the FIRST matching pattern, silently
                    // dropping the SSRF classification). The downstream
                    // dedup_by `discriminant(sink_type)` filters same-type
                    // duplicates so removing the break does not produce extra
                    // findings for single-classification sinks.
                }
            }
        }

        // RUBY-BACKTICK-EXTRACTION-V1: Ruby backtick / %x{} subshell dispatch.
        //
        // Closes carry-forward from vuln-source-parity-v1 M5 Bucket A Ruby
        // (ruby_command_injection_positive). Predecessor precedent:
        // field_access_info-extension-v1 retained `\bgets\b` for a bare-call
        // AST shape gap — same shape of carry-forward (raw-substring/AST
        // node-kind mismatch), different localized resolution.
        //
        // tree-sitter-ruby 0.23.1 parses BOTH `…` (backtick) and
        // %x{…}/%x[…]/%x(…) as a single `subshell` named-node containing
        // `interpolation` / `string_content` / `escape_sequence` children.
        // subshell is NOT call-shaped — it has no `method` / `receiver`
        // field and `extract_call_name_ruby` returns None for it. The
        // for-pattern-in-patterns.sinks loop above cannot match it via
        // `call_names` (gated on call_node_kinds + extract_call_name) or
        // `member_patterns` (gated on member_access_expression OR call-shape
        // OR raw-substring with high FP risk on the backtick character).
        // Therefore this dispatch arm IS the entire matcher for subshell.
        //
        // Adding `subshell` to call_node_kinds(Ruby) (Option A) would require
        // extending extract_call_name_ruby with a synthetic name AND would
        // affect every consumer of call_node_kinds (sources, sanitizers,
        // references.rs is_call gate). Localized arm here (Option B) is
        // surgically scoped to ShellExec sink detection only.
        //
        // Var-extraction reuses extract_first_identifier_arg_ast (extended in
        // this milestone with a Ruby-specific subshell BFS arm — see helper
        // body above). For `\`#{cmd}\``, the BFS yields subshell →
        // interpolation → identifier(cmd). Pure-static subshells without
        // interpolation (e.g., `\`ls\``) yield None and emit no sink —
        // correct (no taint flow possible).
        //
        // No new RUBY_AST_SINKS entry is added: subshell is not call-shaped
        // so any AstSinkPattern entry would be silently dead under the
        // existing for-pattern-in-patterns.sinks loop. The dispatch arm IS
        // the wire.
        if language == Language::Ruby && descendant.kind() == "subshell" {
            let stmt_text = std::str::from_utf8(source)
                .unwrap_or("")
                .lines()
                .nth((line - 1) as usize)
                .unwrap_or("");
            let var = extract_first_identifier_arg_ast(descendant, source, language)
                .or_else(|| extract_assignment_rhs_ident(descendant, source, stmt_text))
                .or_else(|| extract_source_var_from_statement(stmt_text));
            if let Some(var) = var {
                sinks.push(TaintSink {
                    var,
                    line,
                    sink_type: TaintSinkType::ShellExec,
                    tainted: false,
                    statement: Some(stmt_text.to_string()),
                });
                // Only one sink per node — same convention as the loop above.
                continue;
            }
        }

        // detection-gap-fixes-v1 — Python f-string XSS via view-function return.
        //
        // tree-sitter-python 0.23.6 parses
        //   `return f"<h1>Hello, {name}!</h1>"`
        // as
        //   return_statement
        //     return
        //     string
        //       string_start "f\""
        //       string_content "<h1>Hello, "
        //       interpolation
        //         { "{"
        //         identifier "name"
        //         } "}"
        //       string_content "!</h1>"
        //       string_end "\""
        //
        // The `string` descendant is filtered out by the `is_in_string` guard at
        // the top of the descendant loop (a string IS in a string), so it never
        // reaches the AstSinkPattern matcher. The PYTHON_AST_SINKS HtmlOutput
        // bank only fires on `Markup(...)` / `mark_safe(...)` / `|safe` /
        // `(response, write)` / `(Response, set_data)` shapes — none match a
        // bare f-string return. Result: pre-fix the taint pipeline saw the
        // tainted source (`request.args.get`) flow into `name` and then
        // disappear into a `return` with no sink — producing zero XSS findings
        // on the canonical Flask f-string-return shape.
        //
        // Fix: localized dispatch arm — when a `return_statement` directly
        // returns a `string` containing one or more `interpolation` children
        // (i.e., a Python f-string with at least one `{var}`), classify the
        // return as an HtmlOutput sink. Var-extraction walks the first
        // interpolation's named children seeking the first plain `identifier`,
        // mirroring the Ruby subshell BFS arm above.
        //
        // Why ONLY f-strings (not plain string returns):
        //  - Plain string literal returns (`return "<h1>static</h1>"`) carry no
        //    runtime variable, so no taint can flow through them — emitting a
        //    sink would be pure-noise (the taint engine would gate firing on a
        //    tainted var, but there's no var to gate on).
        //  - F-strings with at least one interpolation child carry a runtime
        //    variable. If that variable is tainted, the response body reflects
        //    user input as HTML — exactly the CWE-79 reflected-XSS shape.
        //  - This narrow predicate (string-with-interpolation, NOT every
        //    return) keeps the FP surface minimal while closing the gap on
        //    the canonical Flask/Bottle/Pyramid view shape:
        //      `@app.route('/x') def view(): return f"...{user}..."`
        //
        // Why dispatch arm (not AstSinkPattern entry): AstSinkPattern matches
        // descendants by call-shape (`call_names`) or member-shape
        // (`member_patterns`). A `return_statement` has neither shape — it's a
        // statement keyword. There is no SinkPattern slot that fires on
        // `return_statement` kind alone. (Compare the Ruby subshell arm above:
        // same shape of localization for a non-call/non-member statement.)
        //
        // Sink-type rationale: HtmlOutput projects to VulnType::Xss / CWE-79
        // via `vuln_type_from_sink` — the canonical reflected-XSS finding
        // class. Matches the JS/TS `(reply|res|response|Response).send`
        // HtmlOutput entries from VULN-MIGRATION-V1 M3 (same semantic: HTTP
        // response body emitted with default text/html Content-Type).
        if language == Language::Python && descendant.kind() == "return_statement" {
            let mut returned_string: Option<tree_sitter::Node> = None;
            for i in 0..descendant.child_count() {
                if let Some(child) = descendant.child(i) {
                    if child.is_named() && child.kind() == "string" {
                        returned_string = Some(child);
                        break;
                    }
                }
            }
            if let Some(string_node) = returned_string {
                // infra-tail-issues-v1 (#57b, v0.4.2 M-108): walk ALL
                // interpolation children of the f-string, not just the
                // first. Pre-fix the arm `break`-d after the first
                // interpolation, so a return like
                //   return f"v{version} hello {user}"
                // (where `version` is a constant and `user` is the
                // tainted source) only emitted a sink gated on
                // `version`, and downstream taint reconciliation missed
                // the `user` flow entirely. Emit one HtmlOutput sink
                // per interpolation that yields a valid identifier so
                // any tainted var in any slot triggers the finding.
                let mut emitted_any = false;
                let stmt_text = std::str::from_utf8(source)
                    .unwrap_or("")
                    .lines()
                    .nth((line - 1) as usize)
                    .unwrap_or("");
                for i in 0..string_node.child_count() {
                    let interp = match string_node.child(i) {
                        Some(c) if c.is_named() && c.kind() == "interpolation" => c,
                        _ => continue,
                    };
                    // Walk this interpolation's named descendants
                    // seeking the first identifier — yields the var
                    // name to gate taint on.
                    let mut stack: Vec<tree_sitter::Node> = vec![interp];
                    let mut var_name: Option<String> = None;
                    while let Some(node) = stack.pop() {
                        if node.kind() == "identifier" {
                            let text = node_text(&node, source);
                            let head = text.split('.').next().unwrap_or(text);
                            if is_valid_identifier(head) {
                                var_name = Some(head.to_string());
                                break;
                            }
                        }
                        for j in 0..node.child_count() {
                            if let Some(child) = node.child(j) {
                                if child.is_named() {
                                    stack.push(child);
                                }
                            }
                        }
                    }
                    if let Some(var) = var_name {
                        sinks.push(TaintSink {
                            var,
                            line,
                            sink_type: TaintSinkType::HtmlOutput,
                            tainted: false,
                            statement: Some(stmt_text.to_string()),
                        });
                        emitted_any = true;
                    }
                }
                if emitted_any {
                    continue;
                }
            }
        }
    }

    sinks
}

/// Detect sanitizers using AST nodes.
///
/// Returns the sanitizer type if found, checking that the match
/// is in actual code (not in a comment or string).
pub fn detect_sanitizer_ast(
    root: &tree_sitter::Node,
    source: &[u8],
    language: Language,
    line: u32,
) -> Option<SanitizerType> {
    let patterns = get_ast_patterns(language);
    let descendants = walk_descendants(*root);

    for descendant in &descendants {
        if is_in_comment(descendant, language) || is_in_string(descendant, language) {
            continue;
        }

        let node_line = descendant.start_position().row as u32 + 1;
        if node_line != line {
            continue;
        }

        let text = node_text(descendant, source);

        for pattern in patterns.sanitizers {
            let matched = pattern.call_names.iter().any(|name| {
                let call_kinds = call_node_kinds(language);
                if call_kinds.contains(&descendant.kind()) {
                    if let Some(call_name) = extract_call_name(descendant, source, language) {
                        return call_name == *name;
                    }
                }
                false
            }) || member_patterns_match(descendant, source, language, pattern.member_patterns, text);

            if matched {
                return Some(pattern.sanitizer_type);
            }
        }
    }

    None
}

/// Build a per-line index of AST sanitizer hits by walking the tree ONCE.
///
/// Mirrors the source/sink WALK-ONCE pattern at the top of
/// `compute_taint_with_tree` (see L3573-3590). Avoids the historical
/// O(L*N) infinite-loop hang that motivated the no-line-filter pass for
/// sources and sinks.
///
/// The public per-line API `detect_sanitizer_ast` (L3498) is preserved for
/// external callers but is NOT invoked from the worklist — this helper is
/// the worklist's single AST entry point. Lines are 1-indexed to match
/// `VarRef.line` and `SsaInstruction.line`.
///
/// When multiple sanitizer hits land on the same line, the latest write
/// wins (matches the source/sink helper's `insert` semantics).
fn build_sanitizer_ast_index(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> HashMap<u32, SanitizerType> {
    let mut index: HashMap<u32, SanitizerType> = HashMap::new();
    let patterns = get_ast_patterns(language);
    let root = tree.root_node();
    let descendants = walk_descendants(root);

    for descendant in &descendants {
        if is_in_comment(descendant, language) || is_in_string(descendant, language) {
            continue;
        }

        let line = descendant.start_position().row as u32 + 1;

        // M3-FIND-01 (sanitizer-removal-v1 M4): string-literal range-overlap
        // filter for the raw-substring fallback in `member_patterns_match`.
        // The fallback (`pat_rcv.is_empty() && descendant_text.contains(pat_field)`)
        // matches against the descendant's full text, which can include the
        // text of any string-literal child. For a statement like
        // `msg = "use int(x) to convert"`, the descendant is the assignment
        // node (NOT inside a string itself, so the outer `is_in_string` skip
        // does not fire), but its text contains the substring `int(`. Pre-M4
        // the regex bank exhibited the same false positive; post-M4 (regex
        // deleted) the AST raw-fallback would inherit it without this filter.
        //
        // We mask string-literal descendant byte ranges with ASCII spaces in
        // a copy of the descendant's text, then pass the masked text to
        // `member_patterns_match`. The structural paths inside that helper
        // (member-access via `extract_member_access_receiver_and_field` and
        // call-shape via `extract_call_name`) re-extract from real AST
        // nodes, so masking only affects the raw-substring fallback path.
        let masked_text = mask_string_literal_descendants(descendant, source, language);

        for pattern in patterns.sanitizers {
            let matched = pattern.call_names.iter().any(|name| {
                let call_kinds = call_node_kinds(language);
                if call_kinds.contains(&descendant.kind()) {
                    if let Some(call_name) = extract_call_name(descendant, source, language) {
                        return call_name == *name;
                    }
                }
                false
            }) || member_patterns_match(
                descendant,
                source,
                language,
                pattern.member_patterns,
                &masked_text,
            );

            if matched {
                index.insert(line, pattern.sanitizer_type);
                break;
            }
        }
    }

    index
}

/// M3-FIND-01 mitigation: build a copy of `descendant`'s text with all
/// string-literal descendant byte ranges replaced by ASCII spaces.
///
/// Used by `build_sanitizer_ast_index` to neutralize the raw-substring
/// fallback in `member_patterns_match` against text that lives inside
/// string-literal children. ASCII spaces are chosen because:
/// - they preserve the byte length and offsets of the source text
///   (important for any caller that later inspects byte positions),
/// - they cannot accidentally satisfy any sanitizer pattern's `pat_field`
///   (no real sanitizer is a single space character).
///
/// The caller has already filtered the descendant itself via `is_in_string`,
/// so any string-literal nodes encountered here are STRICT descendants of
/// `descendant`. The string-literal node kinds are language-specific and
/// come from `string_node_kinds(language)`.
fn mask_string_literal_descendants(
    descendant: &tree_sitter::Node,
    source: &[u8],
    language: Language,
) -> String {
    let start = descendant.start_byte();
    let end = descendant.end_byte();
    if end <= start || end > source.len() {
        return node_text(descendant, source).to_string();
    }
    let mut buf: Vec<u8> = source[start..end].to_vec();
    let string_kinds = string_node_kinds(language);

    for d in walk_descendants(*descendant) {
        if !string_kinds.contains(&d.kind()) {
            continue;
        }
        let s = d.start_byte();
        let e = d.end_byte();
        if e <= start || s >= end {
            continue;
        }
        // Clip to [start, end) and translate to local offsets.
        let local_s = s.saturating_sub(start);
        let local_e = e.saturating_sub(start).min(buf.len());
        for byte in &mut buf[local_s..local_e] {
            *byte = b' ';
        }
    }

    String::from_utf8(buf).unwrap_or_else(|_| node_text(descendant, source).to_string())
}

/// Compute taint analysis with optional AST tree for improved detection.
///
/// When a parsed tree is provided, uses AST-based detection to filter out
/// false positives from comments and string literals. Falls back to regex
/// when AST detection yields no results.
///
/// This is the preferred entry point for CLI commands that have access to
/// the full parsed tree.
pub fn compute_taint_with_tree(
    cfg: &CfgInfo,
    refs: &[VarRef],
    statements: &HashMap<u32, String>,
    tree: Option<&tree_sitter::Tree>,
    source: Option<&[u8]>,
    language: Language,
    ssa: Option<&SsaFunction>,
) -> Result<TaintInfo, TldrError> {
    // If we have tree + source, use AST-enhanced detection within compute_taint
    // For now, delegate to the existing compute_taint which uses regex patterns.
    // The AST detection functions are available for direct use, and we integrate
    // them here as an enhancement layer.

    // Validate CFG
    validate_cfg(cfg)?;

    let mut result = TaintInfo::new(&cfg.function);

    // Build helper maps
    let predecessors = build_predecessors(cfg);
    let successors = build_successors(cfg);
    let line_to_block = build_line_to_block(cfg);
    let refs_by_block = build_refs_by_block(refs, &line_to_block);

    // sanitizer-removal-v1 M4 (ATOMIC): build per-line AST sanitizer
    // index ONCE; mirrors the source/sink WALK-ONCE pattern below. The
    // worklist (`process_block`, `ssa_propagate`) consults this index
    // AST-only (regex bank deleted; M2 fallback removed).
    //
    // M3-FIND-01: `build_sanitizer_ast_index` masks string-literal
    // descendant byte ranges before invoking the raw-substring fallback
    // in `member_patterns_match`, so a sanitizer-name substring inside
    // a string literal cannot trigger sanitization.
    let sanitizer_ast_index: HashMap<u32, SanitizerType> =
        if let (Some(t), Some(s)) = (tree, source) {
            build_sanitizer_ast_index(t, s, language)
        } else {
            HashMap::new()
        };

    // Detect sources and sinks
    if let (Some(tree), Some(src)) = (tree, source) {
        // AST-based detection: walk the tree ONCE (no line filter) to avoid
        // O(lines * nodes) quadratic slowdown that caused infinite-loop-like hangs
        // on large files.
        let root = tree.root_node();

        let all_ast_sources = detect_sources_ast(&root, src, language, None);
        let all_ast_sinks = detect_sinks_ast(&root, src, language, None);

        // Index AST results by line for fast lookup
        let mut ast_sources_by_line: HashMap<u32, Vec<TaintSource>> = HashMap::new();
        for s in all_ast_sources {
            ast_sources_by_line.entry(s.line).or_default().push(s);
        }
        let mut ast_sinks_by_line: HashMap<u32, Vec<TaintSink>> = HashMap::new();
        for s in all_ast_sinks {
            ast_sinks_by_line.entry(s.line).or_default().push(s);
        }

        for (&line, stmt) in statements {
            // Sources: prefer AST results, fall back to regex
            if let Some(sources) = ast_sources_by_line.remove(&line) {
                result.sources.extend(sources);
            } else {
                result.sources.extend(detect_sources(stmt, line, language));
            }

            // Sinks: merge AST and regex results to avoid missing detections
            // when AST finds something on a line but misses certain sink patterns.
            // Dedup below handles any duplicates from the merge.
            if let Some(sinks) = ast_sinks_by_line.remove(&line) {
                result.sinks.extend(sinks);
            }
            result.sinks.extend(detect_sinks(stmt, line, language));
        }
    } else {
        // No tree available - use regex only (backward compatible)
        for (&line, stmt) in statements {
            result.sources.extend(detect_sources(stmt, line, language));
            result.sinks.extend(detect_sinks(stmt, line, language));
        }
    }

    // Deduplicate sources by (line, source_type, var)
    result.sources.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| format!("{:?}", a.source_type).cmp(&format!("{:?}", b.source_type)))
            .then_with(|| a.var.cmp(&b.var))
    });
    result.sources.dedup_by(|a, b| {
        a.line == b.line
            && a.var == b.var
            && std::mem::discriminant(&a.source_type) == std::mem::discriminant(&b.source_type)
    });

    // Deduplicate sinks by (line, sink_type, var)
    result.sinks.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| format!("{:?}", a.sink_type).cmp(&format!("{:?}", b.sink_type)))
            .then_with(|| a.var.cmp(&b.var))
    });
    result.sinks.dedup_by(|a, b| {
        a.line == b.line
            && a.var == b.var
            && std::mem::discriminant(&a.sink_type) == std::mem::discriminant(&b.sink_type)
    });

    // The rest of the algorithm is the same as compute_taint

    // Initialize taint sets per block
    let block_ids: Vec<usize> = cfg.blocks.iter().map(|b| b.id).collect();
    let mut tainted: HashMap<usize, HashSet<String>> = HashMap::new();
    for &bid in &block_ids {
        tainted.insert(bid, HashSet::new());
    }

    for source in &result.sources {
        if let Some(&block_id) = line_to_block.get(&source.line) {
            tainted
                .entry(block_id)
                .or_default()
                .insert(source.var.clone());
        }
    }

    // Worklist iteration
    // Cap iterations to prevent infinite loops on large real-world files
    let unique_vars: HashSet<&str> = refs.iter().map(|r| r.name.as_str()).collect();
    let computed_max = block_ids.len() * unique_vars.len().max(1) + 10;
    let max_iterations = computed_max.min(MAX_TAINT_ITERATIONS);
    let mut worklist: VecDeque<usize> = block_ids.iter().cloned().collect();
    let mut iterations = 0;
    let mut iteration_limit_reached = false;

    let mut source_vars_by_block: HashMap<usize, HashSet<String>> = HashMap::new();
    for source in &result.sources {
        if let Some(&block_id) = line_to_block.get(&source.line) {
            source_vars_by_block
                .entry(block_id)
                .or_default()
                .insert(source.var.clone());
        }
    }

    // Per-line source-var index used by process_block to preserve taint at
    // source-defining lines (e.g., `x = input()` where `x` is freshly tainted
    // by the source call). Under v0.2.x substring semantics this case was
    // covered accidentally by `stmt.contains("x")` matching the LHS; under
    // VarRef semantics (v0.3.0 M1a VAL-001a) we must check sources explicitly.
    let mut sources_by_line: HashMap<u32, HashSet<String>> = HashMap::new();
    for source in &result.sources {
        sources_by_line
            .entry(source.line)
            .or_default()
            .insert(source.var.clone());
    }

    // M1b VAL-001b: SSA-versioned propagation when an `SsaFunction` is supplied
    // and non-empty. When SSA is unavailable (None, Err, or an empty function
    // per the per-language SSA-coverage gap documented in the v0.3.0 contract),
    // this branch is bypassed entirely and the M1a String-keyed worklist below
    // runs unchanged — the engine never panics on missing SSA.
    let ssa_active = ssa.is_some_and(|s| !s.blocks.is_empty());
    let ssa_tainted_per_block: Option<HashMap<usize, HashSet<TaintKey>>> = if ssa_active {
        let ssa_ref = ssa.expect("ssa_active implies Some");
        let ctx = SsaPropagateCtx {
            ssa: ssa_ref,
            sources: &result.sources,
            predecessors: &predecessors,
            successors: &successors,
            line_to_block: &line_to_block,
            max_iterations,
            sanitizer_ast_index: &sanitizer_ast_index,
        };
        let tainted_ssa = ssa_propagate(&ctx, &mut result.sanitized_vars);
        // Translate SSA-versioned tainted set into the String-keyed `tainted`
        // map for backward compatibility with the rest of the pipeline (e.g.,
        // `result.tainted_vars` debug surface). This is an over-approximation:
        // a variable name appears in `tainted[block]` if any of its SSA versions
        // is tainted at block exit. The precise sink check below uses the
        // SsaNameId-keyed set instead, so the over-approximation here does not
        // produce false-positive flows.
        for (block_id, taint_keys) in &tainted_ssa {
            let str_set: HashSet<String> = taint_keys
                .iter()
                .filter_map(|k| match k {
                    TaintKey::Versioned(id) => {
                        ssa_name_by_id(ssa_ref, *id).map(|n| n.variable.clone())
                    }
                    TaintKey::Raw(s) => Some(s.clone()),
                })
                .collect();
            tainted.insert(*block_id, str_set);
        }
        Some(tainted_ssa)
    } else {
        None
    };

    if !ssa_active {
        while let Some(block_id) = worklist.pop_front() {
            if iterations >= max_iterations {
                iteration_limit_reached = true;
                break;
            }
            iterations += 1;

            let mut taint_in: HashSet<String> = predecessors
                .get(&block_id)
                .map(|preds| {
                    preds
                        .iter()
                        .flat_map(|p| tainted.get(p).cloned().unwrap_or_default())
                        .collect()
                })
                .unwrap_or_default();

            if let Some(source_vars) = source_vars_by_block.get(&block_id) {
                taint_in.extend(source_vars.clone());
            }

            let taint_out = process_block(
                block_id,
                taint_in,
                &refs_by_block,
                &sources_by_line,
                &mut result.sanitized_vars,
                &sanitizer_ast_index,
            );

            let old_taint = tainted.get(&block_id).cloned().unwrap_or_default();
            if taint_out != old_taint {
                tainted.insert(block_id, taint_out);
                if let Some(succs) = successors.get(&block_id) {
                    for &s in succs {
                        if !worklist.contains(&s) {
                            worklist.push_back(s);
                        }
                    }
                }
            }
        }
    }

    if iteration_limit_reached {
        result.convergence = Some("iteration_limit_reached".to_string());
    }

    result.tainted_vars = tainted.clone();

    // Phase 5: Detect vulnerabilities
    for sink in &mut result.sinks {
        if let Some(&sink_block) = line_to_block.get(&sink.line) {
            if let (Some(tainted_ssa), Some(ssa_ref)) = (ssa_tainted_per_block.as_ref(), ssa) {
                // M1b SSA-precise sink check: at the sink line, identify the
                // SsaNameIds *used* (or defined) for the sink's variable; if
                // any of those specific versioned ids are in the tainted set
                // at this block, the sink is tainted. This catches the
                // sanitiser-reassignment case where the over-approximated
                // String-keyed `tainted` map would say "x is tainted" but the
                // latest SSA version of x at the sink line is actually clean.
                if ssa_sink_is_tainted(ssa_ref, sink, sink_block, tainted_ssa) {
                    sink.tainted = true;
                }
                // VULN-MIGRATION-V1 M3 indirect-match fallback (parity with M1a):
                // When the SSA-precise check fails because the sink's `var` is a
                // free variable (e.g., a method receiver like `cursor` in
                // `cursor.execute(f"... {tainted}")`), the precise check sees no
                // SSA match for `cursor` because it's never assigned in-function.
                // Mirrors the M1a `else if !tainted_at_block.is_empty()` block
                // below. Sanitised variables (in `result.sanitized_vars`) are
                // excluded from the indirect match so SSA's sanitiser-precision
                // is preserved (val001b regression guard:
                // `let x = req.body; x = sanitize(x); eval(x)` MUST stay 0
                // flows under SSA-versioned propagation).
                //
                // Additional gate: ONLY trigger the indirect match when the
                // sink's `var` is NOT itself an SSA-tracked variable in this
                // function — i.e., the sink's `var` is a free variable
                // (method receiver / module identifier) where the SSA-precise
                // check is structurally inapplicable. This preserves SSA's
                // sanitiser-reassignment precision: when `var` IS SSA-tracked
                // (like `x` in `let x = ...; x = sanitize(x); eval(x)`), the
                // SSA path's verdict is authoritative.
                if !sink.tainted {
                    let sink_var_is_ssa_tracked = ssa_ref
                        .ssa_names
                        .iter()
                        .any(|n| n.variable == sink.var);
                    if !sink_var_is_ssa_tracked
                        && !result.sanitized_vars.contains(&sink.var)
                    {
                        if let Some(tainted_at_block) = tainted.get(&sink_block) {
                            if let Some(block) =
                                cfg.blocks.iter().find(|b| b.id == sink_block)
                            {
                                let block_text: String = (block.lines.0..=block.lines.1)
                                    .filter_map(|l| statements.get(&l))
                                    .map(|s| s.as_str())
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                for tvar in tainted_at_block {
                                    if result.sanitized_vars.contains(tvar) {
                                        continue;
                                    }
                                    if identifier_in_text(&block_text, tvar) {
                                        sink.tainted = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            } else if let Some(tainted_at_block) = tainted.get(&sink_block) {
                // M1a String-keyed sink check (unchanged when SSA is inactive).
                if tainted_at_block.contains(&sink.var) {
                    sink.tainted = true;
                } else if !tainted_at_block.is_empty() {
                    // Indirect match: check if any tainted variable appears
                    // in the block's statements. Handles multi-line calls where
                    // the tainted argument is on a different line than the sink
                    // function name (e.g., conn.execute(\n "..." + username))
                    if let Some(block) = cfg.blocks.iter().find(|b| b.id == sink_block) {
                        let block_text: String = (block.lines.0..=block.lines.1)
                            .filter_map(|l| statements.get(&l))
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(" ");
                        for tvar in tainted_at_block {
                            if identifier_in_text(&block_text, tvar) {
                                sink.tainted = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let sources_clone = result.sources.clone();
    let sinks_snapshot: Vec<(String, u32, TaintSinkType, bool, Option<String>)> = result
        .sinks
        .iter()
        .map(|s| {
            (
                s.var.clone(),
                s.line,
                s.sink_type,
                s.tainted,
                s.statement.clone(),
            )
        })
        .collect();

    for (sink_var, sink_line, sink_type, sink_tainted, sink_statement) in sinks_snapshot {
        if !sink_tainted {
            continue;
        }

        if let Some(&sink_block) = line_to_block.get(&sink_line) {
            for source in &sources_clone {
                if let Some(&source_block) = line_to_block.get(&source.line) {
                    // Direct flow: sink's `var` matches a tainted variable that
                    // reaches sink_block.
                    let direct =
                        flows_to(&source.var, &sink_var, &tainted, &predecessors, sink_block);

                    // VULN-MIGRATION-V1 M3: Indirect flow — when the sink's
                    // structural `var` is the call receiver (e.g.,
                    // `cursor.execute(f"...{name}")` extracts `cursor`) but the
                    // tainted variable (`name`) flows through the f-string /
                    // interpolation / concat argument, accept the flow if the
                    // source's variable is tainted at the sink block AND its
                    // identifier appears in the sink statement text. Mirrors
                    // the indirect-match logic used to set `sink.tainted` above.
                    let indirect = if direct {
                        false
                    } else if !result.sanitized_vars.contains(&source.var)
                        && tainted
                            .get(&sink_block)
                            .map(|t| t.contains(&source.var))
                            .unwrap_or(false)
                    {
                        match &sink_statement {
                            Some(stmt) => identifier_in_text(stmt, &source.var),
                            None => false,
                        }
                    } else {
                        false
                    };

                    if direct || indirect {
                        let is_sanitized = result.sanitized_vars.contains(&sink_var)
                            || result.sanitized_vars.contains(&source.var);
                        // TAINT-FLOW-CAUSAL-ORDERING-V1: drop causally impossible
                        // flows where the source line is AFTER the sink line.
                        // In dataflow analysis the source must execute before the
                        // sink that consumes its value; a `source.line > sink.line`
                        // pair is a label collision (e.g. `with open(f)` on line N
                        // is paired with `f.read()` on line N+1: the engine
                        // correctly classifies `read()` as a source and `open()`
                        // as a `FileOpen` sink, but on the call-chain timeline the
                        // open precedes the read so the read CANNOT taint the
                        // open). We drop rather than swap-and-relabel because the
                        // source/sink TYPES are correct — only the pairing is
                        // spurious. See `taint-flow-causal-ordering-v1` rationale
                        // in CHANGELOG.md.
                        let causally_ordered = source.line <= sink_line;
                        if !is_sanitized && causally_ordered {
                            let path = compute_flow_path(source_block, sink_block, &successors);
                            let flow = TaintFlow {
                                source: source.clone(),
                                sink: TaintSink {
                                    var: sink_var.clone(),
                                    line: sink_line,
                                    sink_type,
                                    tainted: true,
                                    statement: sink_statement.clone(),
                                },
                                path,
                            };
                            result.flows.push(flow);
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

// =============================================================================
// Vulnerability Detection Helpers - Phase 5
// =============================================================================

/// Check if source variable flows to target variable via taint propagation.
///
/// This is a conservative check that assumes any source could cause taint
/// if the target variable is tainted at the target block. A more precise
/// implementation would track per-variable taint provenance.
///
/// # Arguments
///
/// * `_source_var` - The source variable (unused in conservative check)
/// * `target_var` - The variable to check at the sink
/// * `tainted_vars` - Taint state at each block
/// * `_predecessors` - Block predecessor map (unused in conservative check)
/// * `target_block` - The block containing the sink
///
/// # Returns
///
/// `true` if the target variable is tainted at the target block.
fn flows_to(
    _source_var: &str,
    target_var: &str,
    tainted_vars: &HashMap<usize, HashSet<String>>,
    _predecessors: &HashMap<usize, Vec<usize>>,
    target_block: usize,
) -> bool {
    // Conservative approximation: if target_var is tainted at target_block,
    // assume any source could cause it. More precise tracking would require
    // per-variable taint provenance.
    tainted_vars
        .get(&target_block)
        .map(|t| t.contains(target_var))
        .unwrap_or(false)
}

/// Compute block IDs along the flow path from source to sink.
///
/// Uses BFS to find the shortest path through the CFG from the block
/// containing the source to the block containing the sink.
///
/// # Arguments
///
/// * `source_block` - Block ID containing the taint source
/// * `sink_block` - Block ID containing the taint sink
/// * `successors` - Block successor map
///
/// # Returns
///
/// Vector of block IDs from source to sink (inclusive).
fn compute_flow_path(
    source_block: usize,
    sink_block: usize,
    successors: &HashMap<usize, Vec<usize>>,
) -> Vec<usize> {
    if source_block == sink_block {
        return vec![source_block];
    }

    // BFS to find shortest path
    let mut visited: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<Vec<usize>> = VecDeque::new();

    queue.push_back(vec![source_block]);
    visited.insert(source_block);

    while let Some(path) = queue.pop_front() {
        let current = *path.last().unwrap();

        if let Some(succs) = successors.get(&current) {
            for &next in succs {
                if next == sink_block {
                    let mut result = path.clone();
                    result.push(next);
                    return result;
                }

                if !visited.contains(&next) {
                    visited.insert(next);
                    let mut new_path = path.clone();
                    new_path.push(next);
                    queue.push_back(new_path);
                }
            }
        }
    }

    // No path found - return just source and sink
    vec![source_block, sink_block]
}

// =============================================================================
// Worklist Algorithm - Phase 4
// =============================================================================

/// Compute taint analysis for a function using worklist-based forward dataflow.
///
/// # Algorithm
///
/// Forward worklist-based dataflow analysis:
/// 1. Initialize: entry block tainted_vars = sources
/// 2. Worklist iteration until fixed point:
///    - taint_in[B] = union(taint_out[P] for P in predecessors[B])
///    - Process block: propagate taint through assignments
///    - taint_out[B] = process_block(taint_in[B])
///    - If changed, add successors to worklist
///
/// # Arguments
///
/// * `cfg` - Control flow graph for the function
/// * `refs` - Variable references (definitions and uses)
/// * `statements` - Map of line number to statement text (for pattern matching)
/// * `language` - The programming language (determines which taint patterns to use)
///
/// # Returns
///
/// `TaintInfo` containing all taint analysis results.
///
/// # Errors
///
/// Returns `TldrError::InvalidArgs` if the CFG is invalid.
pub fn compute_taint(
    cfg: &CfgInfo,
    refs: &[VarRef],
    statements: &HashMap<u32, String>,
    language: Language,
) -> Result<TaintInfo, TldrError> {
    // Wave-2-atomic (regex-removal-v1 M11): legacy entry refactored to
    // internal-parse-and-delegate. Public signature is preserved; internally,
    // we reconstruct the source text from the line-keyed `statements` map,
    // parse it via `tldr_core::ast::parser::parse`, and delegate to
    // `compute_taint_with_tree` which performs AST-based detection. On parse
    // failure, we degrade gracefully to an empty `TaintInfo::default()` so
    // callers that previously got a successful regex-only response receive a
    // benign empty result instead of an error.
    //
    // Rationale: detect_sources / detect_sinks regex banks are deleted for
    // 13 GO languages in regex-removal-v1 (Wave-2-atomic). Ruby / Elixir / OCaml
    // source+sink regex banks were deleted in field_access_info-extension-v1 M5
    // once their `(receiver, field)` structured AST entries landed (M2/M3/M4).
    // The AST detection path (detect_sources_ast / detect_sinks_ast inside
    // compute_taint_with_tree) is the canonical pattern source. The Ruby
    // `\bgets\b` source regex is RETAINED — tree-sitter-ruby parses bare `gets`
    // as identifier (not call), so AST `call_names: ['gets']` does not fire on
    // the bare form. All sanitizer regex banks are retained pending sanitizer-
    // removal-v1.
    let max_line = statements.keys().copied().max().unwrap_or(0) as usize;
    let mut lines: Vec<String> = vec![String::new(); max_line];
    for (&line, stmt) in statements {
        if line >= 1 && (line as usize) <= lines.len() {
            lines[(line - 1) as usize] = stmt.clone();
        }
    }
    let src = lines.join("\n");

    match crate::ast::parser::parse(&src, language) {
        Ok(tree) => compute_taint_with_tree(
            cfg,
            refs,
            statements,
            Some(&tree),
            Some(src.as_bytes()),
            language,
            None,
        ),
        Err(_) => Ok(TaintInfo::default()),
    }
}

/// Process a single block for taint propagation.
///
/// Propagates taint through assignments in the block:
/// - If RHS uses a tainted variable, LHS becomes tainted
/// - If a sanitizer is applied, the result is NOT tainted
/// - Definitions without taint remove taint from the variable
///
/// # Arguments
///
/// * `block_id` - The block being processed
/// * `current_taint` - Set of tainted variables at block entry
/// * `refs_by_block` - VarRefs grouped by block
/// * `statements` - Statement text by line number
/// * `line_to_block` - Mapping from line to block ID
/// * `sanitized_vars` - Set of variables that have been sanitized (mutated)
/// * `language` - The programming language (determines which patterns to use)
///
/// # Returns
///
/// Set of tainted variables at block exit.
fn process_block(
    block_id: usize,
    mut current_taint: HashSet<String>,
    refs_by_block: &HashMap<usize, Vec<&VarRef>>,
    sources_by_line: &HashMap<u32, HashSet<String>>,
    sanitized_vars: &mut HashSet<String>,
    sanitizer_ast_index: &HashMap<u32, SanitizerType>,
) -> HashSet<String> {
    // sanitizer-removal-v1 M4 (ATOMIC): post-dispatch-flip the per-line
    // `stmt` text and `language` are no longer needed in this function —
    // the regex `detect_sanitizer(stmt, language)` fallback was the only
    // consumer. Sanitizer dispatch now reads exclusively from
    // `sanitizer_ast_index`. The `statements` and `language` parameters
    // were removed to satisfy `-D warnings`.
    let empty_refs = vec![];
    let block_refs = refs_by_block.get(&block_id).unwrap_or(&empty_refs);

    for var_ref in block_refs {
        match var_ref.ref_type {
            RefType::Definition => {
                // Check if RHS uses a tainted variable.
                // VarRef-based per-line use lookup (v0.3.0 M1a VAL-001a) replaces
                // the v0.2.x `stmt.contains(tv.as_str())` substring check, which
                // produced false positives whenever a tainted variable's name
                // appeared as a substring of an unrelated token (method names,
                // class names, comments).
                let rhs_tainted = rhs_uses_tainted(var_ref.line, &current_taint, block_refs);

                // Check if this Definition is itself the source line for this
                // variable (e.g., `x = input()` with `x` registered as a source).
                // The substring engine preserved this case accidentally because
                // `stmt.contains("x")` matched the LHS identifier; under VarRef
                // semantics, the LHS Def is not a Use, so we must check the
                // sources map explicitly to avoid stripping freshly-seeded taint.
                let is_source_def = sources_by_line
                    .get(&var_ref.line)
                    .is_some_and(|vars| vars.contains(&var_ref.name));

                // Check if sanitized.
                // sanitizer-removal-v1 M4 (ATOMIC): AST-only (regex bank
                // deleted; M2 fallback removed). The per-line AST sanitizer
                // index is the sole dispatch source.
                let ast_sanitizer_hit = sanitizer_ast_index.contains_key(&var_ref.line);
                if ast_sanitizer_hit {
                    sanitized_vars.insert(var_ref.name.clone());
                    current_taint.remove(&var_ref.name);
                } else if rhs_tainted || is_source_def {
                    current_taint.insert(var_ref.name.clone());
                } else {
                    // Definition without taint removes taint
                    current_taint.remove(&var_ref.name);
                }
            }
            RefType::Use => {
                // Uses don't change taint state directly
            }
            RefType::Update => {
                // Update is use-then-def (e.g., x += y).
                // If RHS uses a tainted variable, the result is tainted.
                // VarRef-based per-line use lookup (v0.3.0 M1a VAL-001a).
                let rhs_tainted = rhs_uses_tainted(var_ref.line, &current_taint, block_refs);
                if rhs_tainted {
                    current_taint.insert(var_ref.name.clone());
                }
            }
        }
    }

    current_taint
}

/// Check whether any tainted variable appears as a `RefType::Use` VarRef on
/// the given line within `block_refs`.
///
/// Replaces the v0.2.x substring check `stmt.contains(tv.as_str())` which
/// produced false positives whenever a tainted variable's name appeared as a
/// substring of an unrelated token (method names, class names, comments).
/// Uses the DFG's per-line use-reference granularity instead — the DFG already
/// emits Use refs at correct token boundaries.
fn rhs_uses_tainted(
    line: u32,
    current_taint: &HashSet<String>,
    block_refs: &[&VarRef],
) -> bool {
    block_refs.iter().any(|r| {
        r.line == line
            && matches!(r.ref_type, RefType::Use)
            && current_taint.contains(&r.name)
    })
}

// =============================================================================
// SSA-aware Propagation (M1b VAL-001b v0.3.0)
// =============================================================================

/// SSA-versioned forward dataflow propagation.
///
/// Layered on top of M1a's VarRef path (still the fallback when SSA is
/// unavailable per the per-language SSA-coverage gap), this function keys the
/// taint set by `SsaNameId` (versioned) so that re-assignment through a
/// sanitiser correctly clears taint on the post-sanitiser SSA version
/// (`x = sanitize(x)` produces a distinct `x_v2` that is not propagated).
///
/// # Returns
///
/// A `HashMap<usize, HashSet<TaintKey>>` mapping each CFG block id to the set
/// of `TaintKey` values tainted at block exit. `Versioned(SsaNameId)` keys are
/// used when an instruction's target id is known; `Raw(String)` keys are used
/// for free variables that have no SSA defining instruction (function
/// parameters in some language frontends, builtins) — this preserves soundness
/// under partial SSA coverage rather than silently dropping taint.
/// Read-only context for the SSA-aware propagation worklist.
///
/// Bundles the helper maps and CFG-derived structures that
/// `ssa_propagate` needs but does not mutate. The `sanitized_vars`
/// out-parameter is passed separately because it is mutated.
struct SsaPropagateCtx<'a> {
    ssa: &'a SsaFunction,
    sources: &'a [TaintSource],
    predecessors: &'a HashMap<usize, Vec<usize>>,
    successors: &'a HashMap<usize, Vec<usize>>,
    line_to_block: &'a HashMap<u32, usize>,
    max_iterations: usize,
    /// sanitizer-removal-v1 M4 (ATOMIC): per-line AST sanitizer index built
    /// once at the top of `compute_taint_with_tree`. Sole sanitizer dispatch
    /// source — the regex `detect_sanitizer` fallback was removed.
    ///
    /// Pre-M4 this struct also held `statements: &HashMap<u32, String>` and
    /// `language: Language`; they fed `detect_sanitizer(stmt, language)`
    /// and are not needed under AST-only dispatch.
    sanitizer_ast_index: &'a HashMap<u32, SanitizerType>,
}

/// Look up an SSA name by id.
///
/// callgraph-dataflow-issues-v1 (#50): SsaNameIds are 1-indexed (the
/// renaming state's `next_id` starts at 1, with `0` reserved for the
/// "undefined" marker), but `ssa.ssa_names` is a 0-indexed `Vec` sorted
/// by id. Direct indexing via `ssa_names.get(id.0 as usize)` produces
/// an off-by-one error that silently returned the wrong SsaName and
/// broke source-seeding / use-checking throughout the SSA-aware taint
/// propagation. This helper performs a correct id-based lookup.
///
/// The Vec is sorted by id (per `RenamingState::into_ssa_names`) so we
/// binary-search; the common case where the id-to-position offset is
/// exactly 1 hits in O(1) via direct indexing first.
fn ssa_name_by_id(
    ssa: &SsaFunction,
    id: crate::ssa::types::SsaNameId,
) -> Option<&crate::ssa::types::SsaName> {
    // Fast path: `id.0 - 1` is the expected position when ids are dense
    // and 1-indexed starting at 1 (the canonical construction layout).
    let target = id.0;
    let expected_idx = (target.saturating_sub(1)) as usize;
    if let Some(n) = ssa.ssa_names.get(expected_idx) {
        if n.id == id {
            return Some(n);
        }
    }
    // Fallback: binary search over the sorted Vec.
    ssa.ssa_names
        .binary_search_by_key(&target, |n| n.id.0)
        .ok()
        .and_then(|i| ssa.ssa_names.get(i))
}

fn ssa_propagate(
    ctx: &SsaPropagateCtx<'_>,
    sanitized_vars: &mut HashSet<String>,
) -> HashMap<usize, HashSet<TaintKey>> {
    let SsaPropagateCtx {
        ssa,
        sources,
        predecessors,
        successors,
        line_to_block,
        max_iterations,
        sanitizer_ast_index,
    } = *ctx;
    // Build per-block instruction list keyed by block id (SsaBlock.id matches
    // CFG block id per ssa::types). Sort instructions by line to guarantee
    // deterministic processing order within a block (Q-M1-C).
    let mut block_insts: HashMap<usize, Vec<&crate::ssa::types::SsaInstruction>> = HashMap::new();
    for sblock in &ssa.blocks {
        let mut insts: Vec<&crate::ssa::types::SsaInstruction> = sblock.instructions.iter().collect();
        insts.sort_by_key(|i| i.line);
        block_insts.insert(sblock.id, insts);
    }

    // Phi functions per block (entry-of-block taint merging).
    let mut block_phis: HashMap<usize, &Vec<crate::ssa::types::PhiFunction>> = HashMap::new();
    for sblock in &ssa.blocks {
        block_phis.insert(sblock.id, &sblock.phi_functions);
    }

    // Initial source seeding: for each TaintSource, find an SsaNameId defined
    // on `source.line` whose variable name matches `source.var`. If found,
    // seed `Versioned(id)`. If no SSA instruction defines that var on that
    // line (free var / partial SSA), seed `Raw(var)` so taint is not lost.
    let mut tainted: HashMap<usize, HashSet<TaintKey>> = HashMap::new();
    for source in sources {
        if let Some(&block_id) = line_to_block.get(&source.line) {
            let block = tainted.entry(block_id).or_default();
            let mut seeded_versioned = false;
            if let Some(insts) = block_insts.get(&block_id) {
                for inst in insts {
                    if inst.line != source.line {
                        continue;
                    }
                    if let Some(target) = inst.target {
                        if let Some(name) = ssa_name_by_id(ssa, target) {
                            if name.variable == source.var {
                                block.insert(TaintKey::Versioned(target));
                                seeded_versioned = true;
                            }
                        }
                    }
                }
            }
            if !seeded_versioned {
                block.insert(TaintKey::Raw(source.var.clone()));
            }
        }
    }

    // Worklist: CFG block ids visited in BFS order until fixed point.
    let block_ids: Vec<usize> = ssa.blocks.iter().map(|b| b.id).collect();
    let mut worklist: VecDeque<usize> = block_ids.iter().cloned().collect();
    let mut iterations: usize = 0;

    while let Some(block_id) = worklist.pop_front() {
        if iterations >= max_iterations {
            break;
        }
        iterations += 1;

        // taint_in = union of predecessor taint_out, then phi-merge: for each
        // phi target whose phi-source set intersects predecessor taint_out,
        // mark the phi target as tainted.
        let mut taint_in: HashSet<TaintKey> = HashSet::new();
        if let Some(preds) = predecessors.get(&block_id) {
            for p in preds {
                if let Some(t) = tainted.get(p) {
                    for k in t {
                        taint_in.insert(k.clone());
                    }
                }
            }
        }

        if let Some(phis) = block_phis.get(&block_id) {
            for phi in phis.iter() {
                let any_tainted = phi
                    .sources
                    .iter()
                    .any(|s| taint_in.contains(&TaintKey::Versioned(s.name)));
                if any_tainted {
                    taint_in.insert(TaintKey::Versioned(phi.target));
                }
            }
        }

        // Re-seed sources that originate inside this block (matches the M1a
        // path which extends taint_in with source_vars_by_block).
        for source in sources {
            if line_to_block.get(&source.line) == Some(&block_id) {
                if let Some(insts) = block_insts.get(&block_id) {
                    let mut found = false;
                    for inst in insts {
                        if inst.line != source.line {
                            continue;
                        }
                        if let Some(target) = inst.target {
                            if let Some(name) = ssa_name_by_id(ssa, target) {
                                if name.variable == source.var {
                                    taint_in.insert(TaintKey::Versioned(target));
                                    found = true;
                                }
                            }
                        }
                    }
                    if !found {
                        taint_in.insert(TaintKey::Raw(source.var.clone()));
                    }
                }
            }
        }

        // Process instructions in line order. For each instruction:
        //   uses_tainted = any inst.uses[i] is in current_taint as Versioned;
        //                  OR variable name of inst.uses[i] is in current_taint
        //                  as Raw (covers partial SSA / free vars).
        //   if a sanitiser is recognised on this line via the M1a regex
        //     `detect_sanitizer` helper:
        //       - record the original variable name in `sanitized_vars` (so
        //         the downstream flow construction's `is_sanitized` guard
        //         still fires).
        //       - DO NOT mark the target as tainted (the post-sanitiser SSA
        //         version is clean).
        //   else if uses_tainted:
        //       - mark target as Versioned(target) tainted.
        //   else:
        //       - target stays clean (its previous SSA version, if any, is
        //         unaffected — SSA names are immutable single-assignment).
        let mut current_taint = taint_in.clone();
        if let Some(insts) = block_insts.get(&block_id) {
            for inst in insts {
                // sanitizer-removal-v1 M4 (ATOMIC): the per-line `line_stmt`
                // text is no longer needed; pre-M4 it fed
                // `detect_sanitizer(line_stmt, language)`. AST-only dispatch
                // reads from `sanitizer_ast_index` directly.
                let uses_tainted = inst.uses.iter().any(|use_id| {
                    if current_taint.contains(&TaintKey::Versioned(*use_id)) {
                        return true;
                    }
                    if let Some(name) = ssa_name_by_id(ssa, *use_id) {
                        if current_taint.contains(&TaintKey::Raw(name.variable.clone())) {
                            return true;
                        }
                    }
                    false
                });

                if let Some(target) = inst.target {
                    let target_var = ssa_name_by_id(ssa, target).map(|n| n.variable.clone());

                    // sanitizer-removal-v1 M4 (ATOMIC): AST-only (regex
                    // bank deleted; M2 fallback removed). Mirrors
                    // process_block sibling site.
                    let ast_sanitizer_hit = sanitizer_ast_index.contains_key(&inst.line);
                    if ast_sanitizer_hit {
                        if let Some(v) = target_var.clone() {
                            sanitized_vars.insert(v);
                        }
                        // Sanitiser: post-sanitiser SSA version is clean.
                        // The pre-sanitiser version, if it was tainted, stays
                        // tainted in the set (it is a separate SsaNameId).
                        // Downstream sink check uses inst.uses at the sink
                        // line to resolve which version is referenced.
                    } else if uses_tainted {
                        current_taint.insert(TaintKey::Versioned(target));
                        // If the prior version of this variable was tainted
                        // via a Raw key (partial-SSA fallback), preserve that
                        // shadow until the variable is unambiguously rebound.
                    } else if let Some(ref v) = target_var {
                        // A clean re-definition removes the Raw shadow for
                        // this variable name (the new SSA version is clean
                        // and downstream `Versioned` lookups will miss it).
                        current_taint.remove(&TaintKey::Raw(v.clone()));
                    }
                }
            }
        }

        let old_taint = tainted.get(&block_id).cloned().unwrap_or_default();
        if current_taint != old_taint {
            tainted.insert(block_id, current_taint);
            if let Some(succs) = successors.get(&block_id) {
                for &s in succs {
                    if !worklist.contains(&s) {
                        worklist.push_back(s);
                    }
                }
            }
        }
    }

    tainted
}

/// Precise SSA-mode sink-taint check.
///
/// Walks every SSA instruction at `sink.line` and checks whether any of the
/// `inst.uses` for the sink's variable resolve to an SsaNameId tainted at
/// `sink_block` (or whose name is tainted via a `Raw` fallback key). This is
/// strictly more precise than the over-approximating String-keyed `tainted`
/// map produced for backward compatibility — it correctly leaves the sink
/// untainted in the `let x = req.body; x = DOMPurify.sanitize(x); eval(x)`
/// fixture because the SSA name used at `eval(x)` is `x_v2` (clean) rather
/// than `x_v1` (tainted).
fn ssa_sink_is_tainted(
    ssa: &SsaFunction,
    sink: &TaintSink,
    sink_block: usize,
    tainted_ssa: &HashMap<usize, HashSet<TaintKey>>,
) -> bool {
    let block_taint = match tainted_ssa.get(&sink_block) {
        Some(t) => t,
        None => return false,
    };

    // Find the SSA block matching the CFG sink_block.
    let sblock = match ssa.blocks.iter().find(|b| b.id == sink_block) {
        Some(b) => b,
        None => return false,
    };

    // Inspect every instruction on the sink line; any matching use that
    // resolves to a tainted Versioned key — or whose name matches a Raw key —
    // marks the sink as tainted.
    for inst in &sblock.instructions {
        if inst.line != sink.line {
            continue;
        }
        for use_id in &inst.uses {
            if block_taint.contains(&TaintKey::Versioned(*use_id)) {
                if let Some(name) = ssa_name_by_id(ssa, *use_id) {
                    if name.variable == sink.var {
                        return true;
                    }
                }
            }
            if let Some(name) = ssa_name_by_id(ssa, *use_id) {
                if name.variable == sink.var
                    && block_taint.contains(&TaintKey::Raw(name.variable.clone()))
                {
                    return true;
                }
            }
        }
        // Also handle the rare case where the sink's variable appears as the
        // instruction *target* (e.g., `eval(x)` modelled as a Call with
        // target = result; here we keep the conservative check on uses only,
        // which matches the M1a model for sink detection).
    }

    // Final fallback: the sink line might not have an SSA instruction at all
    // (e.g., a multi-line call where the sink token sits on a continuation
    // line). Fall back to the Raw-key check on the variable name.
    if block_taint.contains(&TaintKey::Raw(sink.var.clone())) {
        return true;
    }

    // callgraph-dataflow-issues-v1 (#50): bare expression-statement sinks
    // such as `eval(x)` produce NO SSA instruction at the sink line
    // (only definitions create instructions). The Raw-key fallback above
    // only catches free-variable sources that never received a versioned
    // seed. Walk the SSA names to find the most recent version of the
    // sink variable defined at or before the sink line, then check
    // whether that version is tainted at the sink block. This handles
    // the `x = user_input; eval(x)` chain where the SSA propagation
    // correctly marked `x_v_latest` as Versioned-tainted but the sink
    // check could not locate it without a colocated instruction.
    let mut latest_def: Option<&crate::ssa::types::SsaName> = None;
    for name in &ssa.ssa_names {
        if name.variable != sink.var {
            continue;
        }
        if name.def_line > sink.line {
            continue;
        }
        match latest_def {
            None => latest_def = Some(name),
            Some(cur) if name.def_line > cur.def_line => latest_def = Some(name),
            _ => {}
        }
    }
    if let Some(name) = latest_def {
        if block_taint.contains(&TaintKey::Versioned(name.id)) {
            return true;
        }
    }

    // Also check the union of taint across THIS block's predecessors:
    // some flows reach the sink block via `taint_in` but the local
    // worklist did not re-record the version-keyed entry under our
    // block's exit set if the sink block has no defining instruction
    // for the variable. (Defensive guard for the `x = src; eval(x)`
    // pattern when the sink lives in a successor of the definition.)
    // The taint_in is materialised via `tainted_ssa` predecessors
    // implicitly — `block_taint` is exit-of-block — so the Versioned
    // lookup above already handles same-block. No-op here serves as
    // documentation of intent.

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_source_type_serde() {
        let source = TaintSourceType::UserInput;
        let json = serde_json::to_string(&source).unwrap();
        assert_eq!(json, "\"user_input\"");

        let parsed: TaintSourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, source);
    }

    #[test]
    fn test_taint_sink_type_serde() {
        let sink = TaintSinkType::SqlQuery;
        let json = serde_json::to_string(&sink).unwrap();
        assert_eq!(json, "\"sql_query\"");

        let parsed: TaintSinkType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sink);
    }

    #[test]
    fn test_sanitizer_type_serde() {
        let sanitizer = SanitizerType::Numeric;
        let json = serde_json::to_string(&sanitizer).unwrap();
        assert_eq!(json, "\"numeric\"");

        let parsed: SanitizerType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sanitizer);
    }

    #[test]
    fn test_taint_info_new() {
        let info = TaintInfo::new("my_function");
        assert_eq!(info.function_name, "my_function");
        assert!(info.tainted_vars.is_empty());
        assert!(info.sources.is_empty());
        assert!(info.sinks.is_empty());
        assert!(info.flows.is_empty());
        assert!(info.sanitized_vars.is_empty());
    }

    #[test]
    fn test_taint_info_default() {
        let info = TaintInfo::default();
        assert!(info.function_name.is_empty());
        assert!(info.tainted_vars.is_empty());
    }

    #[test]
    fn test_taint_info_is_tainted() {
        let mut info = TaintInfo::new("test");
        let mut block_taint = HashSet::new();
        block_taint.insert("user_input".to_string());
        info.tainted_vars.insert(0, block_taint);

        assert!(info.is_tainted(0, "user_input"));
        assert!(!info.is_tainted(0, "other_var"));
        assert!(!info.is_tainted(1, "user_input")); // block 1 doesn't exist
    }

    #[test]
    fn test_taint_info_get_vulnerabilities() {
        let mut info = TaintInfo::new("test");

        // Add a tainted sink (vulnerability)
        info.sinks.push(TaintSink {
            var: "query".to_string(),
            line: 5,
            sink_type: TaintSinkType::SqlQuery,
            tainted: true,
            statement: Some("cursor.execute(query)".to_string()),
        });

        // Add a non-tainted sink (safe)
        info.sinks.push(TaintSink {
            var: "safe_query".to_string(),
            line: 10,
            sink_type: TaintSinkType::SqlQuery,
            tainted: false,
            statement: Some("cursor.execute(safe_query)".to_string()),
        });

        let vulns = info.get_vulnerabilities();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].var, "query");
    }

    /// Test that compute_taint terminates on a large CFG with many variables
    /// and back-edges that could cause oscillation in the worklist algorithm.
    /// This test would hang forever without the MAX_TAINT_ITERATIONS cap.
    #[test]
    fn test_taint_terminates_on_large_cfg_with_backedges() {
        use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};

        // Create a CFG with 50 blocks in a chain, plus back-edges
        let num_blocks = 50;
        let mut blocks = Vec::new();
        let mut edges = Vec::new();

        for i in 0..num_blocks {
            let start_line = (i * 10 + 1) as u32;
            let end_line = (i * 10 + 10) as u32;
            blocks.push(CfgBlock {
                id: i,
                block_type: BlockType::Body,
                lines: (start_line, end_line),
                calls: Vec::new(),
            });
        }

        // Linear chain edges
        for i in 0..num_blocks - 1 {
            edges.push(CfgEdge {
                from: i,
                to: i + 1,
                edge_type: EdgeType::Unconditional,
                condition: None,
            });
        }

        // Add back-edges to create loops that could cause oscillation
        for i in (5..num_blocks).step_by(5) {
            edges.push(CfgEdge {
                from: i,
                to: i - 3,
                edge_type: EdgeType::BackEdge,
                condition: None,
            });
        }

        let cfg = CfgInfo {
            function: "large_func".to_string(),
            blocks,
            edges,
            entry_block: 0,
            exit_blocks: vec![num_blocks - 1],
            cyclomatic_complexity: 10,
            nested_functions: HashMap::new(),
        };

        // Create many variable refs across blocks
        let mut refs = Vec::new();
        let mut statements = HashMap::new();

        for i in 0..num_blocks {
            let line = (i * 10 + 1) as u32;
            let var_name = format!("var_{}", i);
            refs.push(VarRef {
                name: var_name.clone(),
                ref_type: RefType::Definition,
                line,
                column: 0,
                context: None,
                group_id: None,
            });
            // Create statements that reference previous variables to create taint chains
            if i > 0 {
                statements.insert(line, format!("var_{} = var_{}", i, i - 1));
            } else {
                statements.insert(line, "var_0 = input()".to_string());
            }
        }

        // This MUST terminate within a reasonable time (< 1 second)
        let start = std::time::Instant::now();
        let result = compute_taint(&cfg, &refs, &statements, Language::Python);
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "compute_taint should succeed");
        assert!(
            elapsed.as_secs() < 5,
            "compute_taint took too long: {:?} (possible infinite loop)",
            elapsed
        );

        // Should have found the input() source
        let info = result.unwrap();
        assert!(!info.sources.is_empty(), "Should detect input() source");
    }

    /// Test that the hard iteration cap MAX_TAINT_ITERATIONS is respected
    /// even when the computed max_iterations would be very large.
    #[test]
    fn test_taint_iteration_cap_prevents_runaway() {
        use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};

        // Create a small CFG but with MANY variable references to inflate max_iterations
        let blocks = vec![
            CfgBlock {
                id: 0,
                block_type: BlockType::Body,
                lines: (1, 100),
                calls: Vec::new(),
            },
            CfgBlock {
                id: 1,
                block_type: BlockType::Body,
                lines: (101, 200),
                calls: Vec::new(),
            },
        ];
        let edges = vec![
            CfgEdge {
                from: 0,
                to: 1,
                edge_type: EdgeType::Unconditional,
                condition: None,
            },
            CfgEdge {
                from: 1,
                to: 0,
                edge_type: EdgeType::BackEdge,
                condition: None,
            },
        ];

        let cfg = CfgInfo {
            function: "runaway".to_string(),
            blocks,
            edges,
            entry_block: 0,
            exit_blocks: vec![1],
            cyclomatic_complexity: 2,
            nested_functions: HashMap::new(),
        };

        // Create 500 unique variable refs - this would make max_iterations = 2 * 500 + 10 = 1010
        // which is above our MAX_TAINT_ITERATIONS cap of 1000
        let mut refs = Vec::new();
        let mut statements = HashMap::new();

        for i in 0..500 {
            let line = (i + 1) as u32;
            refs.push(VarRef {
                name: format!("v{}", i),
                ref_type: RefType::Definition,
                line,
                column: 0,
                context: None,
                group_id: None,
            });
            statements.insert(line, format!("v{} = input()", i));
        }

        let start = std::time::Instant::now();
        let result = compute_taint(&cfg, &refs, &statements, Language::Python);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_secs() < 5,
            "Should terminate quickly with iteration cap, took {:?}",
            elapsed
        );
    }

    /// Test that compute_taint_with_tree deduplicates sources that are detected
    /// by both AST-based and regex-based detection on the same line.
    #[test]
    fn test_sources_are_deduplicated() {
        use crate::ast::ParserPool;
        use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};

        let python_code = r#"import os

def vulnerable_func(user_input):
    data = input("Enter: ")
    query = "SELECT * FROM users WHERE id = " + data
    os.system(user_input)
    eval(data)
"#;

        let cfg = CfgInfo {
            function: "vulnerable_func".to_string(),
            blocks: vec![
                CfgBlock {
                    id: 0,
                    block_type: BlockType::Entry,
                    lines: (3, 3),
                    calls: Vec::new(),
                },
                CfgBlock {
                    id: 1,
                    block_type: BlockType::Body,
                    lines: (4, 7),
                    calls: vec![
                        "input".to_string(),
                        "os.system".to_string(),
                        "eval".to_string(),
                    ],
                },
            ],
            edges: vec![CfgEdge {
                from: 0,
                to: 1,
                edge_type: EdgeType::Unconditional,
                condition: None,
            }],
            entry_block: 0,
            exit_blocks: vec![1],
            cyclomatic_complexity: 1,
            nested_functions: HashMap::new(),
        };

        let refs = vec![
            VarRef {
                name: "user_input".to_string(),
                ref_type: RefType::Definition,
                line: 3,
                column: 0,
                context: None,
                group_id: None,
            },
            VarRef {
                name: "data".to_string(),
                ref_type: RefType::Definition,
                line: 4,
                column: 0,
                context: None,
                group_id: None,
            },
            VarRef {
                name: "query".to_string(),
                ref_type: RefType::Definition,
                line: 5,
                column: 0,
                context: None,
                group_id: None,
            },
        ];

        let mut statements: HashMap<u32, String> = HashMap::new();
        for (i, line) in python_code.lines().enumerate() {
            statements.insert((i + 1) as u32, line.to_string());
        }

        let pool = ParserPool::new();
        let tree = pool.parse(python_code, Language::Python).ok();

        let result = compute_taint_with_tree(
            &cfg,
            &refs,
            &statements,
            tree.as_ref(),
            Some(python_code.as_bytes()),
            Language::Python,
            None,
        )
        .unwrap();

        // Each unique (line, source_type, var) should appear exactly once
        let mut seen = std::collections::HashSet::new();
        for source in &result.sources {
            let key = (
                source.line,
                std::mem::discriminant(&source.source_type),
                source.var.clone(),
            );
            assert!(
                seen.insert(key.clone()),
                "Duplicate source found: line={}, var={}, type={:?}",
                source.line,
                source.var,
                source.source_type
            );
        }

        // Same for sinks
        let mut seen_sinks = std::collections::HashSet::new();
        for sink in &result.sinks {
            let key = (
                sink.line,
                std::mem::discriminant(&sink.sink_type),
                sink.var.clone(),
            );
            assert!(
                seen_sinks.insert(key.clone()),
                "Duplicate sink found: line={}, var={}, type={:?}",
                sink.line,
                sink.var,
                sink.sink_type
            );
        }
    }

    /// Test that sinks are detected even when AST detection misses them
    /// but regex detection would catch them. Both sources should be merged.
    #[test]
    fn test_sinks_detected_via_merge() {
        use crate::ast::ParserPool;
        use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};

        let python_code = r#"import os

def vuln(user_input):
    os.system(user_input)
    eval(user_input)
"#;

        let cfg = CfgInfo {
            function: "vuln".to_string(),
            blocks: vec![
                CfgBlock {
                    id: 0,
                    block_type: BlockType::Entry,
                    lines: (3, 3),
                    calls: Vec::new(),
                },
                CfgBlock {
                    id: 1,
                    block_type: BlockType::Body,
                    lines: (4, 5),
                    calls: vec!["os.system".to_string(), "eval".to_string()],
                },
            ],
            edges: vec![CfgEdge {
                from: 0,
                to: 1,
                edge_type: EdgeType::Unconditional,
                condition: None,
            }],
            entry_block: 0,
            exit_blocks: vec![1],
            cyclomatic_complexity: 1,
            nested_functions: HashMap::new(),
        };

        let refs = vec![VarRef {
            name: "user_input".to_string(),
            ref_type: RefType::Definition,
            line: 3,
            column: 0,
            context: None,
            group_id: None,
        }];

        let mut statements: HashMap<u32, String> = HashMap::new();
        for (i, line) in python_code.lines().enumerate() {
            statements.insert((i + 1) as u32, line.to_string());
        }

        let pool = ParserPool::new();
        let tree = pool.parse(python_code, Language::Python).ok();

        let result = compute_taint_with_tree(
            &cfg,
            &refs,
            &statements,
            tree.as_ref(),
            Some(python_code.as_bytes()),
            Language::Python,
            None,
        )
        .unwrap();

        // Should detect at least 2 sinks: os.system and eval
        let sink_types: Vec<_> = result.sinks.iter().map(|s| s.sink_type).collect();
        assert!(
            sink_types.contains(&TaintSinkType::ShellExec),
            "Should detect os.system as ShellExec sink, got: {:?}",
            sink_types
        );
        assert!(
            sink_types.contains(&TaintSinkType::CodeEval),
            "Should detect eval as CodeEval sink, got: {:?}",
            sink_types
        );
    }
}
