//! Vulnerability detection via taint analysis
//!
//! Implements detection of security vulnerabilities as per spec Section 2.9.2:
//! - SQL Injection (user input -> cursor.execute)
//! - XSS (user input -> innerHTML)
//! - Command Injection (user input -> os.system)
//! - Path Traversal (user input -> open/Path)
//! - SSRF (user input -> http.Get / requests.get)
//! - Deserialization (user input -> pickle.load / unserialize)
//!
//! # Architecture (post vuln-migration-v1 M3)
//!
//! `scan_file_vulns` is a thin per-function wrapper over the canonical
//! `tldr_core::security::taint::compute_taint_with_tree` — for every function
//! returned by `extract_functions_detailed` we build a CFG/DFG, run the
//! AST-based taint engine, and project each `TaintFlow` to a `VulnFinding`
//! via the `From` adapters on the (RETAINED) `vuln::TaintSource` /
//! `vuln::TaintSink` output records. The pre-M3 substring two-pass scanner
//! (`get_sources` / `get_sinks` per-language Vec tables, `extract_propagation`,
//! `is_type_coerced`, `is_sanitized_*`) has been deleted; sanitizer awareness
//! and string-literal filtering now flow through the canonical AST sanitizer
//! / `is_in_string` / `is_in_comment` infrastructure (see
//! `sanitizer-removal-v1` and `regex-removal-v1`).
//!
//! # Example
//! ```ignore
//! use tldr_core::security::vuln::{scan_vulnerabilities, VulnType};
//!
//! let report = scan_vulnerabilities(Path::new("src/"), None, None)?;
//! for finding in &report.findings {
//!     println!("{}: {} -> {}", finding.vuln_type, finding.source, finding.sink);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::ast::extract::{extract_classes_detailed, extract_functions_detailed};
use crate::ast::parser::parse;
use crate::cfg::extractor::extract_cfg_from_tree;
use crate::dfg::extractor::extract_dfg_from_tree_with_cfg;
use crate::error::TldrError;
use crate::security::taint::{
    compute_taint_with_tree, TaintSink as CanonicalTaintSink, TaintSinkType,
    TaintSource as CanonicalTaintSource, TaintSourceType,
};
use crate::types::Language;
use crate::TldrResult;

// =============================================================================
// Types
// =============================================================================

/// Types of vulnerabilities detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnType {
    /// SQL Injection - unsanitized input to SQL queries
    SqlInjection,
    /// Cross-Site Scripting - unsanitized input to HTML output
    Xss,
    /// Command Injection - unsanitized input to shell commands
    CommandInjection,
    /// Path Traversal - unsanitized input to file operations
    PathTraversal,
    /// Server-Side Request Forgery
    Ssrf,
    /// Unsafe Deserialization
    Deserialization,
    /// Open Redirect (CWE-601) — HTTP redirect target controllable by user input.
    /// (M3 detection-accuracy-v1 BUG-16)
    OpenRedirect,
}

impl std::fmt::Display for VulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnType::SqlInjection => write!(f, "SQL Injection"),
            VulnType::Xss => write!(f, "Cross-Site Scripting (XSS)"),
            VulnType::CommandInjection => write!(f, "Command Injection"),
            VulnType::PathTraversal => write!(f, "Path Traversal"),
            VulnType::Ssrf => write!(f, "Server-Side Request Forgery"),
            VulnType::Deserialization => write!(f, "Unsafe Deserialization"),
            VulnType::OpenRedirect => write!(f, "Open Redirect"),
        }
    }
}

/// A taint source (user input entry point) — output adapter record
///
/// (vuln-migration-v1 M3, premortem T2/DR2) RETAINED as an output adapter
/// struct populated via `From<crate::security::TaintSource>`. The CLI consumer
/// at `crates/tldr-cli/src/commands/remaining/vuln.rs:679-688` reads
/// `f.source.line / .expression / .source_type` unchanged; preserving this
/// shape avoids a JSON/SARIF schema break.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Variable name containing tainted data
    pub variable: String,
    /// Source description
    pub source_type: String,
    /// Line number
    pub line: u32,
    /// Original expression
    pub expression: String,
}

/// A taint sink (dangerous operation) — output adapter record
///
/// (vuln-migration-v1 M3, premortem T2/DR2) RETAINED as an output adapter
/// struct populated via `From<crate::security::TaintSink>`. The CLI consumer
/// at `crates/tldr-cli/src/commands/remaining/vuln.rs:679-688` reads
/// `f.sink.line / .expression / .sink_type` unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Function/method being called
    pub function: String,
    /// Sink type description
    pub sink_type: String,
    /// Line number
    pub line: u32,
    /// Full call expression
    pub expression: String,
}

/// A single vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    /// Type of vulnerability
    pub vuln_type: VulnType,
    /// File containing the vulnerability
    pub file: PathBuf,
    /// Source of tainted data
    pub source: TaintSource,
    /// Sink where tainted data flows
    pub sink: TaintSink,
    /// Taint flow path (variable assignments)
    pub flow_path: Vec<String>,
    /// Severity (based on vuln type and certainty)
    pub severity: String,
    /// Remediation advice
    pub remediation: String,
    /// CWE ID
    pub cwe_id: Option<String>,
}

/// Summary of vulnerability scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSummary {
    /// Total vulnerabilities found
    pub total_findings: usize,
    /// Count by vulnerability type
    pub by_type: HashMap<String, usize>,
    /// Files with vulnerabilities
    pub affected_files: usize,
}

/// Report from vulnerability scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    /// All vulnerability findings
    pub findings: Vec<VulnFinding>,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Summary statistics
    pub summary: VulnSummary,
}

// =============================================================================
// Adapters: canonical taint structs → vuln output records
// =============================================================================

impl From<CanonicalTaintSource> for TaintSource {
    fn from(canonical: CanonicalTaintSource) -> Self {
        Self {
            variable: canonical.var,
            source_type: format!("{:?}", canonical.source_type),
            line: canonical.line,
            expression: canonical
                .statement
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
        }
    }
}

impl From<CanonicalTaintSink> for TaintSink {
    fn from(canonical: CanonicalTaintSink) -> Self {
        // The canonical sink has `var` (the tainted argument); the vuln record
        // wants `function` (the call/sink-pattern name). The cleanest synthesis
        // is the `var` itself when the canonical layer didn't preserve a call
        // name — downstream display text uses both `function` and `expression`,
        // and the expression always carries the full statement.
        Self {
            function: canonical.var.clone(),
            sink_type: format!("{:?}", canonical.sink_type),
            line: canonical.line,
            expression: canonical
                .statement
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
        }
    }
}

// =============================================================================
// Helpers: TaintSinkType → VulnType + severity + descriptions
// =============================================================================

/// Project a canonical `TaintSinkType` to the user-facing `VulnType` ontology.
///
/// Exhaustive — adding a `TaintSinkType` variant in M1 forces a compile-time
/// update here (no wildcard arm, by design).
fn vuln_type_from_sink(sink_type: TaintSinkType) -> VulnType {
    match sink_type {
        TaintSinkType::SqlQuery => VulnType::SqlInjection,
        TaintSinkType::ShellExec
        | TaintSinkType::CodeEval
        | TaintSinkType::CodeExec
        | TaintSinkType::CodeCompile => VulnType::CommandInjection,
        TaintSinkType::HtmlOutput => VulnType::Xss,
        TaintSinkType::FileOpen | TaintSinkType::FileWrite => VulnType::PathTraversal,
        TaintSinkType::HttpRequest => VulnType::Ssrf,
        TaintSinkType::Deserialize => VulnType::Deserialization,
        TaintSinkType::OpenRedirect => VulnType::OpenRedirect,
    }
}

/// Get severity string for a vulnerability type.
///
/// Pre-M3 every finding hard-coded "HIGH"; preserved exactly for output
/// stability.
fn severity_for(_vuln_type: VulnType) -> &'static str {
    "HIGH"
}

/// TAINT-FINDING-DEDUPE-V1: rank a `TaintSinkType` by specificity for the
/// per-call-site dedupe in `scan_file_vulns`.
///
/// When two findings collide on `(file, sink.line, source.line,
/// source.variable)` — i.e. the SAME taint flow matched multiple sink
/// patterns at the same call site — we keep the entry with the HIGHEST
/// rank. The ordering reflects "most actionable diagnostic":
///
/// 1. **`SqlQuery`** (rank 110) — the only SQL sink, dedup against itself
///    only; rank kept distinct from the code-execution family for clarity.
/// 2. **`ShellExec`** (rank 100) — directly invokes a shell; an exploit
///    is a one-step OS-level compromise.
/// 3. **`CodeEval`** (rank 95) — `eval()` family: arbitrary in-process
///    code execution, generally more severe than `exec()` because `eval`
///    return values may be exfiltrated.
/// 4. **`CodeExec`** (rank 90) — `exec()` family: runs a code object but
///    does not return the value.
/// 5. **`CodeCompile`** (rank 85) — `compile()` produces a code object
///    that is only dangerous when later executed; least specific of the
///    Code* triple.
/// 6. **`Deserialize`** (rank 80) — RCE-via-deserialization, ranks below
///    the code-execution family because the exploit pathway is gadget-
///    chain-dependent.
/// 7. **`HtmlOutput`** (rank 70) — XSS sink.
/// 8. **`FileOpen`** (rank 60) — read-side path-traversal, more frequent
///    in real corpora than `FileWrite`; preferred when both match.
/// 9. **`FileWrite`** (rank 50).
/// 10. **`HttpRequest`** (rank 40) — SSRF.
///
/// The numeric rank itself is internal; only the relative ordering is
/// observable. The CodeEval > CodeExec > CodeCompile sub-ordering is the
/// load-bearing one for the flask `cli.py:1023`/`config.py:209` case
/// where `eval(compile(...))` triggers all three sink patterns at the
/// same call site.
fn sink_type_precedence(sink_type: TaintSinkType) -> u32 {
    match sink_type {
        TaintSinkType::SqlQuery => 110,
        TaintSinkType::ShellExec => 100,
        TaintSinkType::CodeEval => 95,
        TaintSinkType::CodeExec => 90,
        TaintSinkType::CodeCompile => 85,
        TaintSinkType::Deserialize => 80,
        TaintSinkType::HtmlOutput => 70,
        TaintSinkType::FileOpen => 60,
        TaintSinkType::FileWrite => 50,
        TaintSinkType::HttpRequest => 40,
        // Open-redirect ranks below SSRF; both involve URL flow but
        // the open-redirect surface is generally lower-impact than full SSRF.
        TaintSinkType::OpenRedirect => 35,
    }
}

/// Get a human-readable description for a `TaintSourceType`, partitioned by
/// language.
///
/// Pre-M3 these strings came from `get_sources` per-language Vec tables (e.g.,
/// `"Flask GET parameter"`, `"Express query parameter"`). After the substring
/// scanner is deleted, the canonical taint engine emits enum-typed
/// `TaintSourceType` instead. This helper preserves the descriptive
/// per-language mapping so the JSON `source.source_type` field continues to
/// carry actionable output (R6 mitigation).
fn descriptions_for(source_type: TaintSourceType, language: Language) -> &'static str {
    match (source_type, language) {
        // HTTP parameters / body / cookies / headers
        (TaintSourceType::HttpParam, Language::Python) => "Flask GET/POST parameter",
        (TaintSourceType::HttpParam, Language::JavaScript)
        | (TaintSourceType::HttpParam, Language::TypeScript) => "Express query/route parameter",
        (TaintSourceType::HttpParam, Language::Go) => "HTTP query parameter",
        (TaintSourceType::HttpParam, Language::Java) => "Servlet parameter",
        (TaintSourceType::HttpParam, Language::Ruby) => "Rails parameter",
        (TaintSourceType::HttpParam, Language::Kotlin) => "Ktor query parameter",
        (TaintSourceType::HttpParam, Language::Scala) => "Play query parameter",
        (TaintSourceType::HttpParam, Language::CSharp) => "ASP.NET request parameter",
        (TaintSourceType::HttpParam, Language::Php) => "PHP $_GET / $_POST / $_REQUEST",
        (TaintSourceType::HttpParam, Language::Elixir) => "Phoenix conn.params",
        (TaintSourceType::HttpParam, Language::Lua) | (TaintSourceType::HttpParam, Language::Luau) => {
            "OpenResty/ngx request args"
        }
        (TaintSourceType::HttpParam, _) => "HTTP request parameter",

        (TaintSourceType::HttpBody, Language::Python) => "Flask JSON/raw request body",
        (TaintSourceType::HttpBody, Language::JavaScript)
        | (TaintSourceType::HttpBody, Language::TypeScript) => "Express request body",
        (TaintSourceType::HttpBody, _) => "HTTP request body",

        // User input
        (TaintSourceType::UserInput, Language::Python) => "User input from stdin",
        (TaintSourceType::UserInput, Language::Java) => "User input (Scanner / readLine)",
        (TaintSourceType::UserInput, Language::Kotlin) => "User input (readLine)",
        (TaintSourceType::UserInput, Language::Scala) => "User input (StdIn / readLine)",
        (TaintSourceType::UserInput, Language::CSharp) => "User input (Console.ReadLine)",
        (TaintSourceType::UserInput, Language::Swift) => "User input (CommandLine.arguments / readLine)",
        (TaintSourceType::UserInput, Language::Lua)
        | (TaintSourceType::UserInput, Language::Luau) => "User input (io.read)",
        (TaintSourceType::UserInput, _) => "User input from stdin",

        (TaintSourceType::Stdin, Language::C) | (TaintSourceType::Stdin, Language::Cpp) => {
            "Standard input (scanf / fgets / cin)"
        }
        (TaintSourceType::Stdin, _) => "Standard input",

        // Environment / args
        (TaintSourceType::EnvVar, Language::Python) => "Environment variable (os.environ / os.getenv)",
        (TaintSourceType::EnvVar, Language::JavaScript)
        | (TaintSourceType::EnvVar, Language::TypeScript) => "Environment variable (process.env)",
        (TaintSourceType::EnvVar, Language::Go) => "Environment variable (os.Getenv)",
        (TaintSourceType::EnvVar, Language::Rust) => "Environment variable (std::env::var)",
        (TaintSourceType::EnvVar, Language::Java) => "Environment variable (System.getenv)",
        (TaintSourceType::EnvVar, Language::Kotlin) => "Environment variable (System.getenv)",
        (TaintSourceType::EnvVar, Language::Scala) => "Environment variable (sys.env)",
        (TaintSourceType::EnvVar, Language::CSharp) => "Environment variable (Environment.GetEnvironmentVariable)",
        (TaintSourceType::EnvVar, Language::Php) => "Environment variable ($_ENV / getenv)",
        (TaintSourceType::EnvVar, Language::Ruby) => "Environment variable (ENV)",
        (TaintSourceType::EnvVar, Language::C) | (TaintSourceType::EnvVar, Language::Cpp) => "Environment variable (getenv)",
        (TaintSourceType::EnvVar, Language::Lua) | (TaintSourceType::EnvVar, Language::Luau) => "Environment variable (os.getenv)",
        (TaintSourceType::EnvVar, Language::Swift) => "Environment variable (ProcessInfo.environment)",
        (TaintSourceType::EnvVar, Language::Elixir) => "Environment variable (System.get_env)",
        (TaintSourceType::EnvVar, Language::Ocaml) => "Environment variable (Sys.getenv)",
        // v0.5.0 SOL-001 Solidity foundation. Solidity has no
        // environment-variable concept (no OS-level env access from
        // the EVM), but tx.origin / msg.sender are the analogous
        // untrusted inputs — SOL-005 will introduce a new
        // TaintSourceType variant for those rather than abusing
        // EnvVar. Until then, return a neutral description.
        (TaintSourceType::EnvVar, Language::Solidity) => "Untrusted blockchain input",

        // File reads
        (TaintSourceType::FileRead, _) => "Untrusted file read",
    }
}

/// Get remediation advice for a vulnerability type
fn get_remediation(vuln_type: VulnType) -> &'static str {
    match vuln_type {
        VulnType::SqlInjection =>
            "Use parameterized queries or prepared statements instead of string concatenation",
        VulnType::Xss =>
            "Sanitize output using context-appropriate encoding (HTML, JavaScript, URL, etc.)",
        VulnType::CommandInjection =>
            "Use subprocess with shell=False and pass arguments as a list, or use shlex.quote()",
        VulnType::PathTraversal =>
            "Validate paths against a whitelist or use realpath() and verify the result is within allowed directories",
        VulnType::Ssrf =>
            "Validate URLs against an allowlist of domains and protocols",
        VulnType::Deserialization =>
            "Avoid deserializing untrusted data, or use safer formats like JSON",
        VulnType::OpenRedirect =>
            "Validate redirect targets against an allowlist of trusted URLs/origins; do not concatenate user input into the redirect target",
    }
}

/// Get CWE ID for a vulnerability type
fn get_cwe_id(vuln_type: VulnType) -> &'static str {
    match vuln_type {
        VulnType::SqlInjection => "CWE-89",
        VulnType::Xss => "CWE-79",
        VulnType::CommandInjection => "CWE-78",
        VulnType::PathTraversal => "CWE-22",
        VulnType::Ssrf => "CWE-918",
        VulnType::Deserialization => "CWE-502",
        VulnType::OpenRedirect => "CWE-601",
    }
}

// =============================================================================
// Main API
// =============================================================================

/// Scan for security vulnerabilities using taint analysis
///
/// # Arguments
/// * `path` - File or directory to scan
/// * `language` - Optional language filter (auto-detect if None)
/// * `vuln_type` - Optional filter for specific vulnerability type
///
/// # Returns
/// * `Ok(VulnReport)` - Report with all findings
/// * `Err(TldrError)` - On file system or parse errors
///
/// # Example
/// ```ignore
/// use tldr_core::security::vuln::{scan_vulnerabilities, VulnType};
///
/// // Scan for all vulnerabilities
/// let report = scan_vulnerabilities(Path::new("src/"), None, None)?;
///
/// // Scan for SQL injection only
/// let report = scan_vulnerabilities(
///     Path::new("src/"),
///     Some(Language::Python),
///     Some(VulnType::SqlInjection),
/// )?;
/// ```
pub fn scan_vulnerabilities(
    path: &Path,
    language: Option<Language>,
    vuln_type: Option<VulnType>,
) -> TldrResult<VulnReport> {
    let mut findings = Vec::new();

    // Collect files to scan
    let files: Vec<PathBuf> = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                let detected = Language::from_path(e.path());
                match (detected, language) {
                    (Some(d), Some(l)) => d == l,
                    (Some(_), None) => true,
                    _ => false,
                }
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    };

    // VULN-MIGRATION-V1 M3 perf: parallelize per-file scan with rayon (per
    // dispatch-contract M3 stop-threshold "If either axis fails, parallelize
    // per-file with rayon BEFORE declaring GREEN"). Per-function CFG/DFG/taint
    // construction is the hot loop — distributing across cores keeps the
    // dir-level wall-clock under the 2x M1 baseline.
    use rayon::prelude::*;
    let scan_results: Vec<Vec<VulnFinding>> = files
        .par_iter()
        .map(|file_path| scan_file_vulns(file_path, vuln_type).unwrap_or_default())
        .collect();
    for file_findings in scan_results {
        if !file_findings.is_empty() {
            findings.extend(file_findings);
        }
    }
    // files_scanned counts every file we attempted, mirroring pre-M3 semantics
    // (the pre-M3 loop incremented on Ok regardless of finding count; we keep
    // the same liberal counting since rayon's `unwrap_or_default()` collapses
    // Err paths to empty Vecs).
    let files_scanned = files.len();

    // Calculate summary
    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut affected_files: HashSet<PathBuf> = HashSet::new();
    for finding in &findings {
        *by_type.entry(finding.vuln_type.to_string()).or_insert(0) += 1;
        affected_files.insert(finding.file.clone());
    }

    let summary = VulnSummary {
        total_findings: findings.len(),
        by_type,
        affected_files: affected_files.len(),
    };

    Ok(VulnReport {
        findings,
        files_scanned,
        summary,
    })
}

// =============================================================================
// Sanitization post-filters (VULN-MIGRATION-V1 M3 carry-forward)
// =============================================================================
// These two argument-shape sanitization patterns aren't expressible as AST
// sanitizer call-wrappers in the canonical sanitizer dispatch (they depend on
// the SHAPE of the call's arguments, not on whether a sanitizer call wraps the
// tainted variable). They were detected pre-M3 by `is_sanitized_sql` /
// `is_sanitized_command` line-text inspection in `is_sanitized_sink`. Mirrored
// here as scan_file_vulns post-filters to preserve the test_e2e_*
// regression-guard semantics. A future canonical-engine extension can promote
// these to first-class AST sanitizers and delete this code.

/// Detect parameterized SQL: placeholder (`?` / `%s` / `:name`) + tuple/list/dict
/// argument syntax on the same statement.
fn is_parameterized_sql(line: &str) -> bool {
    let has_placeholder =
        line.contains('?') || line.contains("%s") || has_named_param(line);
    let has_args_collection =
        line.contains(", (") || line.contains(", [") || line.contains(", {");
    has_placeholder && has_args_collection
}

/// Detect parameter-named placeholder `:user_id`. Avoids URL false positives
/// (`http://`) by requiring the preceding char to be space / `=` / quote.
fn has_named_param(line: &str) -> bool {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphabetic() {
            if i == 0 {
                return true;
            }
            let prev = bytes[i - 1];
            if prev == b' ' || prev == b'=' || prev == b'\'' || prev == b'"' {
                return true;
            }
        }
    }
    false
}

/// Detect safe subprocess invocation: list-form arguments
/// (`subprocess.{run,call,Popen}([`) or explicit `shell=False`.
/// `shell=True` overrides — always unsafe.
fn is_safe_subprocess_call(line: &str) -> bool {
    if line.contains("shell=True") {
        return false;
    }
    if line.contains("shell=False") {
        return true;
    }
    for prefix in &["subprocess.run(", "subprocess.call(", "subprocess.Popen("] {
        if let Some(pos) = line.find(prefix) {
            let after = &line[pos + prefix.len()..];
            if after.trim_start().starts_with('[') {
                return true;
            }
        }
    }
    false
}

// =============================================================================
// Internal Implementation — per-function compute_taint_with_tree dispatch
// =============================================================================

/// Scan a single file for vulnerabilities.
///
/// (vuln-migration-v1 M3) Per-function loop over the canonical
/// `compute_taint_with_tree`:
///   1. Parse the file ONCE with tree-sitter (tree reused across functions).
///   2. Enumerate functions via `extract_functions_detailed`.
///   3. For each function: build CFG + DFG (which scope to that function via
///      `find_function_node`), construct minimal SSA where possible, scope the
///      `statements` map to the function's CFG block range, and run
///      `compute_taint_with_tree`.
///   4. Project each `TaintFlow` to a `VulnFinding` via the adapter `From`
///      impls + `vuln_type_from_sink` classification.
///
/// String-literal and comment FP suppression: the canonical engine filters
/// those upstream via `is_in_string` / `is_in_comment` (regex-removal-v1 +
/// sanitizer-removal-v1). The pre-M3 substring scanner had no such filtering,
/// which is why string-literal regression-guard fixtures FAILED on the 14
/// fall-through languages — that class of FP is closed at M3.
fn scan_file_vulns(path: &Path, vuln_filter: Option<VulnType>) -> TldrResult<Vec<VulnFinding>> {
    let content = std::fs::read_to_string(path)?;
    let language = Language::from_path(path).ok_or_else(|| {
        TldrError::UnsupportedLanguage(
            path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_string(),
        )
    })?;

    // Parse ONCE — reused across per-function CFG/DFG/taint passes.
    let tree = match parse(&content, language) {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()), // graceful degradation on parse failure
    };

    // Enumerate function definitions (name + start line) using the canonical
    // ast::extract helper (visibility extended to pub(crate) in M3 per
    // premortem T3/DR3). Top-level functions ONLY — methods inside classes,
    // structs, traits, objects are returned via `extract_classes_detailed`
    // (Scala `object M { def f ... }`, Java `class C { void f() {} }`, etc.).
    let mut fn_infos: Vec<crate::types::FunctionInfo> =
        extract_functions_detailed(&tree, &content, language);
    let class_infos = extract_classes_detailed(&tree, &content, language);
    for class_info in class_infos {
        fn_infos.extend(class_info.methods);
    }
    // Dedup by (name, line_number) — some extractors may double-emit a function
    // under both the top-level and class-method paths.
    fn_infos.sort_by(|a, b| a.line_number.cmp(&b.line_number).then(a.name.cmp(&b.name)));
    fn_infos.dedup_by(|a, b| a.name == b.name && a.line_number == b.line_number);

    let path_str = path.to_str().unwrap_or_default();
    let path_buf = path.to_path_buf();
    let source_bytes = content.as_bytes();
    let mut findings: Vec<VulnFinding> = Vec::new();

    // FALLBACK: empty function list (e.g., top-level Go statements with no
    // user-defined functions, or extractor missed all). Run a single
    // whole-file taint pass using a synthetic CFG-empty path. We do this by
    // skipping the loop and emitting nothing — preserving existing behavior
    // where files with no functions had no findings.
    if fn_infos.is_empty() {
        return Ok(findings);
    }

    // VULN-MIGRATION-V1 M3 perf: parallelize the per-function CFG/DFG/taint
    // construction with rayon. Each function's analysis is independent (the
    // shared inputs — `tree`, `content`, `language` — are read-only). Tree-
    // sitter's `Tree` is `Send + Sync` so it can be shared across threads.
    // This is the inner-loop parallelism complement to the outer per-file
    // par_iter in `scan_vulnerabilities`; for single-file CLI dispatch
    // (where the outer loop has only 1 element), this inner par_iter is the
    // primary parallelism source.
    use rayon::prelude::*;

    // VULN-FASTPATH-SUBSTRING-PREFILTER-V1 (BUG-26 perf):
    // Pre-compute the (start_line, end_line) body range for each function
    // BEFORE the par_iter so the cheap substring prefilter can run without
    // touching CFG. `fn_infos` is already sorted by `line_number` ascending;
    // the body of fn[i] runs from `fn_infos[i].line_number` to either
    // `fn_infos[i+1].line_number - 1` or EOF. This is a coarse over-
    // approximation (it includes any trailing top-level code between
    // functions in the file), which is correctness-preserving for the
    // prefilter — over-approximating the body text only causes the
    // prefilter to RUN the full analysis more often, never to skip it
    // incorrectly.
    let total_lines = content.lines().count() as u32;
    let mut fn_body_ranges: Vec<(u32, u32)> = Vec::with_capacity(fn_infos.len());
    for (i, fi) in fn_infos.iter().enumerate() {
        let start = fi.line_number.max(1);
        let end = if i + 1 < fn_infos.len() {
            fn_infos[i + 1].line_number.saturating_sub(1).max(start)
        } else {
            total_lines.max(start)
        };
        fn_body_ranges.push((start, end));
    }
    // Slice each function's body text once, lazily-shared via Vec<&str>.
    // `String::lines` allocates iterators not slices; use byte-offset slicing
    // for O(N) total instead of O(N²) for line-walking each function.
    let line_offsets: Vec<usize> = {
        let mut v: Vec<usize> = Vec::with_capacity(total_lines as usize + 1);
        v.push(0);
        for (i, b) in content.bytes().enumerate() {
            if b == b'\n' {
                v.push(i + 1);
            }
        }
        // Push end-of-content sentinel so range slicing always has an upper
        // bound for the last line.
        if *v.last().unwrap_or(&0) != content.len() {
            v.push(content.len());
        }
        v
    };
    let body_slice = |start_line: u32, end_line: u32| -> &str {
        let s = (start_line.saturating_sub(1) as usize).min(line_offsets.len() - 1);
        let e_idx = (end_line as usize).min(line_offsets.len() - 1);
        let start_byte = line_offsets[s];
        let end_byte = line_offsets[e_idx];
        &content[start_byte..end_byte]
    };

    // TAINT-FINDING-DEDUPE-V1: tag each candidate finding with its canonical
    // `TaintSinkType` so the merge phase can rank colliding entries by sink
    // specificity (most-specific wins; see `sink_type_precedence`).
    let per_fn_findings: Vec<Vec<(VulnFinding, TaintSinkType)>> = fn_infos
        .par_iter()
        .enumerate()
        .map(|(idx, fn_info)| {
            // VULN-FASTPATH-SUBSTRING-PREFILTER-V1: cheap substring check
            // before any CFG/DFG/taint construction. A `TaintFlow` requires
            // BOTH a source AND a sink in the same function; if neither
            // call-name appears anywhere in the body's source text, no
            // flow is possible. Substring match is a SUPERSET of the AST
            // detector — hits inside string literals or comments still
            // run the full analysis (canonical AST `is_in_string` /
            // sanitizer dispatch resolves those FPs at the detector
            // layer). A clean miss is a true negative and safe to skip.
            // See `crate::security::taint::fastpath_pattern_strings` for
            // the needle-set construction and correctness contract.
            let (start_line, end_line) = fn_body_ranges[idx];
            let body_text = body_slice(start_line, end_line);
            if !crate::security::taint::function_body_has_taint_pattern(body_text, language) {
                return Vec::new();
            }
            let cfg = match extract_cfg_from_tree(&tree, &content, &fn_info.name, language) {
                Ok(c) if !c.blocks.is_empty() => c,
                _ => return Vec::new(),
            };
            let dfg = match extract_dfg_from_tree_with_cfg(
                &tree,
                &content,
                &fn_info.name,
                language,
                &cfg,
            ) {
                Ok(d) => d,
                Err(_) => return Vec::new(),
            };
            // Pass `ssa = None` to force the M1a String-keyed worklist path
            // (handles indirect taint matches like
            // `cursor.execute(f"...{tainted}")`).
            let ssa: Option<&crate::ssa::types::SsaFunction> = None;
            let (fn_start, fn_end) = {
                let start = cfg.blocks.iter().map(|b| b.lines.0).min().unwrap_or(1);
                let end = cfg
                    .blocks
                    .iter()
                    .map(|b| b.lines.1)
                    .max()
                    .unwrap_or(content.lines().count() as u32);
                (start, end)
            };
            let statements: HashMap<u32, String> = content
                .lines()
                .enumerate()
                .filter(|(i, _)| {
                    let line_num = (i + 1) as u32;
                    line_num >= fn_start && line_num <= fn_end
                })
                .map(|(i, line)| ((i + 1) as u32, line.to_string()))
                .collect();
            let info = match compute_taint_with_tree(
                &cfg,
                &dfg.refs,
                &statements,
                Some(&tree),
                Some(source_bytes),
                language,
                ssa,
            ) {
                Ok(i) => i,
                Err(_) => return Vec::new(),
            };
            // Build candidate findings; dedup happens in the merge phase below.
            let mut local: Vec<(VulnFinding, TaintSinkType)> = Vec::new();
            for flow in info.flows {
                let canonical_sink_type = flow.sink.sink_type;
                let vuln_type = vuln_type_from_sink(canonical_sink_type);
                if let Some(filter) = vuln_filter {
                    if vuln_type != filter {
                        continue;
                    }
                }
                let stmt_text = flow.sink.statement.as_deref().unwrap_or("");
                if vuln_type == VulnType::SqlInjection && is_parameterized_sql(stmt_text) {
                    continue;
                }
                if vuln_type == VulnType::CommandInjection
                    && is_safe_subprocess_call(stmt_text)
                {
                    continue;
                }
                // M3 detection-accuracy-v1 BUG-17: degenerate flow suppression.
                //
                // When the canonical engine emits a flow whose source and sink
                // collapse to the same file + line + expression text AND the
                // source/sink variables are identical, the JSON `taint_flow`
                // would emit two identical entries — there is literally no
                // propagation to describe (the engine's source-pattern and
                // sink-pattern matched the SAME identifier on the SAME line).
                //
                // The `source.var == sink.var` guard is load-bearing: a single
                // statement can legitimately host BOTH a source (`id =
                // params[:id]`) AND a sink that USES that tainted `id` later
                // on the same line (`db.execute("... " + id)` — the Ruby/Lua
                // single-line pattern from the v1 RED suite). Those legit
                // flows have distinct sink semantics from the source variable
                // and MUST NOT be suppressed. Empirically Ruby/Lua emit
                // sink.var = the call expression text or a different
                // identifier, so the equality check leaves them alone.
                //
                // The narrower var-mismatch class (e.g. Rust `let f =
                // File::open(path)`) is NOT suppressed here — it survives
                // and is annotated downstream by the CLI emit layer with
                // `direct_sink: true` (see `analyze_file` in
                // crates/tldr-cli/src/commands/remaining/vuln.rs and the
                // `degenerate_source_eq_sink_suppressed_or_annotated` test
                // in crates/tldr-cli/tests/detection_accuracy_v1.rs).
                if flow.source.line == flow.sink.line
                    && flow.source.var == flow.sink.var
                    && flow
                        .source
                        .statement
                        .as_deref()
                        .unwrap_or("")
                        == flow.sink.statement.as_deref().unwrap_or("")
                {
                    continue;
                }
                let description =
                    descriptions_for(flow.source.source_type, language).to_string();
                let source_record: TaintSource = flow.source.clone().into();
                let sink_record: TaintSink = flow.sink.clone().into();
                let flow_path: Vec<String> = if flow.path.is_empty() {
                    vec![
                        format!(
                            "{}:{} - taint source",
                            source_record.line, source_record.variable
                        ),
                        format!("{}:{} - sink", sink_record.line, sink_record.function),
                    ]
                } else {
                    flow.path
                        .iter()
                        .map(|bid| format!("block-{}", bid))
                        .collect()
                };
                local.push((
                    VulnFinding {
                        vuln_type,
                        file: path_buf.clone(),
                        source: TaintSource {
                            variable: source_record.variable,
                            source_type: description,
                            line: source_record.line,
                            expression: source_record.expression,
                        },
                        sink: sink_record,
                        flow_path,
                        severity: severity_for(vuln_type).to_string(),
                        remediation: get_remediation(vuln_type).to_string(),
                        cwe_id: Some(get_cwe_id(vuln_type).to_string()),
                    },
                    canonical_sink_type,
                ));
            }
            local
        })
        .collect();

    // TAINT-FINDING-DEDUPE-V1: collapse findings that share
    // `(file, sink.line, source.line, source.variable, vuln_type)`. The
    // same call site commonly matches multiple sink patterns within ONE
    // vuln_type — e.g. `eval(compile(f.read(), startup, "exec"))` triggers
    // CodeEval + CodeExec + CodeCompile in the canonical engine, all
    // mapping to `CommandInjection`, all with the same sink line and the
    // same `(source.line, source.variable)`. Most consumers want a single
    // highest-precedence finding per `(call site, vuln_type)` pair.
    //
    // Tuple INCLUDES `source.variable` — distinct tainted variables on
    // the same line are legitimately distinct findings (e.g.
    // `os.system(env_var + " " + user_input)` has two source vars on one
    // line; both must be retained).
    //
    // Tuple INCLUDES `vuln_type` — a single sink (e.g. PHP
    // `file_get_contents($u)`) can simultaneously be a `PathTraversal`
    // (FileOpen) AND an `Ssrf` (HttpRequest) for the same source variable
    // and source line. These are ORTHOGONAL findings (different remediation,
    // different CWE) and the RED suite asserts ≥1 of each type — collapsing
    // across vuln_type would corrupt that signal. Within-vuln_type dedupe
    // still solves the CodeEval/CodeExec/CodeCompile case (all
    // `CommandInjection`) and the FileOpen/FileWrite case (both
    // `PathTraversal`).
    //
    // Tuple EXCLUDES `sink.function` (the canonical sink var) because the
    // sink var is derived from the sink-pattern detector and varies
    // between overlapping detectors at the same call site (e.g. `f` for
    // FileOpen vs the wrapped expression for Code* sinks); including it
    // would defeat the dedupe.
    //
    // Precedence: pick the entry with highest `sink_type_precedence`
    // rank — see that helper for the ordering rationale (CodeEval >
    // CodeExec > CodeCompile, FileOpen > FileWrite, etc.). On ties the
    // first-encountered entry wins (deterministic via parallel map order
    // collected in `fn_infos` ordering).
    use std::collections::hash_map::Entry;
    let mut best: HashMap<(String, u32, u32, String, VulnType), (VulnFinding, TaintSinkType)> =
        HashMap::new();
    for fn_findings in per_fn_findings {
        for (finding, sink_type) in fn_findings {
            let key = (
                finding.file.display().to_string(),
                finding.sink.line,
                finding.source.line,
                finding.source.variable.clone(),
                finding.vuln_type,
            );
            match best.entry(key) {
                Entry::Vacant(v) => {
                    v.insert((finding, sink_type));
                }
                Entry::Occupied(mut o) => {
                    let cur_rank = sink_type_precedence(o.get().1);
                    let new_rank = sink_type_precedence(sink_type);
                    if new_rank > cur_rank {
                        o.insert((finding, sink_type));
                    }
                }
            }
        }
    }
    findings.extend(best.into_values().map(|(f, _)| f));

    let _ = path_str; // path_str retained for future use; suppress unused warn
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::TempDir;

    #[test]
    fn test_vuln_type_display() {
        assert_eq!(VulnType::SqlInjection.to_string(), "SQL Injection");
        assert_eq!(VulnType::Xss.to_string(), "Cross-Site Scripting (XSS)");
    }

    #[test]
    fn test_cwe_ids() {
        assert_eq!(get_cwe_id(VulnType::SqlInjection), "CWE-89");
        assert_eq!(get_cwe_id(VulnType::Xss), "CWE-79");
        assert_eq!(get_cwe_id(VulnType::CommandInjection), "CWE-78");
    }

    #[test]
    fn test_vuln_type_from_sink_exhaustive() {
        // Exhaustive — adding a TaintSinkType variant in M1 forces an update.
        assert_eq!(vuln_type_from_sink(TaintSinkType::SqlQuery), VulnType::SqlInjection);
        assert_eq!(vuln_type_from_sink(TaintSinkType::ShellExec), VulnType::CommandInjection);
        assert_eq!(vuln_type_from_sink(TaintSinkType::CodeEval), VulnType::CommandInjection);
        assert_eq!(vuln_type_from_sink(TaintSinkType::CodeExec), VulnType::CommandInjection);
        assert_eq!(vuln_type_from_sink(TaintSinkType::CodeCompile), VulnType::CommandInjection);
        assert_eq!(vuln_type_from_sink(TaintSinkType::HtmlOutput), VulnType::Xss);
        assert_eq!(vuln_type_from_sink(TaintSinkType::FileOpen), VulnType::PathTraversal);
        assert_eq!(vuln_type_from_sink(TaintSinkType::FileWrite), VulnType::PathTraversal);
        assert_eq!(vuln_type_from_sink(TaintSinkType::HttpRequest), VulnType::Ssrf);
        assert_eq!(vuln_type_from_sink(TaintSinkType::Deserialize), VulnType::Deserialization);
    }

    #[test]
    fn test_go_vuln_e2e() {
        let go_code = r#"package main

import (
    "database/sql"
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    db, _ := sql.Open("mysql", "dsn")
    db.Query("SELECT * FROM users WHERE id = " + id)

    cmd := r.URL.Query().Get("cmd")
    out, _ := exec.Command(cmd).Output()
}
"#;
        let tmp = std::env::temp_dir().join("test_go_vuln_e2e.go");
        std::fs::write(&tmp, go_code).unwrap();
        let result = scan_vulnerabilities(&tmp, None, None).unwrap();
        eprintln!("Go findings: {}", result.findings.len());
        for f in &result.findings {
            eprintln!(
                "  {:?} line {}: {} -> {}",
                f.vuln_type, f.sink.line, f.source.variable, f.sink.function
            );
        }
        assert!(
            !result.findings.is_empty(),
            "Expected Go SQL injection finding, got {}",
            result.findings.len()
        );
        std::fs::remove_file(&tmp).ok();
    }

    // =========================================================================
    // E2E regression guard — preserved per validator mandate
    // e2e_test_preservation_mandatory. These tests pin scan_file_vulns /
    // scan_vulnerabilities behavior at the public-API boundary; the M3
    // collapse must keep them GREEN.
    // =========================================================================

    #[test]
    fn test_e2e_parameterized_query_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("safe_sql.py");
        std::fs::write(
            &file,
            r#"
from flask import request
import sqlite3
def handler():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"#,
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            findings.is_empty(),
            "Parameterized query must produce 0 findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_e2e_subprocess_list_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("safe_cmd.py");
        std::fs::write(
            &file,
            r#"
from flask import request
def handler():
    filename = request.args.get("file")
    subprocess.run(["cat", filename])
"#,
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            findings.is_empty(),
            "subprocess.run with list args must produce 0 findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_e2e_type_coercion_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("safe_int.py");
        std::fs::write(
            &file,
            r#"
from flask import request
def handler():
    user_id = int(request.args.get("id"))
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"#,
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            findings.is_empty(),
            "int() type coercion must break taint, producing 0 findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_e2e_real_sqli_still_detected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vuln_sql.py");
        std::fs::write(
            &file,
            r#"
from flask import request
def handler():
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
"#,
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            !findings.is_empty(),
            "Real SQL injection must still be detected"
        );
    }

    #[test]
    fn test_e2e_real_command_injection_still_detected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vuln_cmd.py");
        std::fs::write(
            &file,
            r#"
from flask import request
def handler():
    filename = request.args.get("file")
    os.system("cat " + filename)
"#,
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            !findings.is_empty(),
            "Real command injection must still be detected"
        );
    }

    /// TAINT-FINDING-DEDUPE-V1 regression guard.
    ///
    /// Reproduces the flask `cli.py:1023` triple-sink pattern:
    /// `eval(compile(f.read(), startup, "exec"))` simultaneously matches the
    /// `eval()` (CodeEval), `exec` argument (CodeExec), and `compile()`
    /// (CodeCompile) sink patterns. With M3.1 causal-ordering applied, ONE
    /// source variable on the same line emitting against a SINGLE call site
    /// must collapse to ONE finding post-dedupe — keeping CodeEval as the
    /// most-specific sink type.
    ///
    /// Acceptance: exactly 1 CommandInjection finding for the synthetic
    /// `eval(compile(f.read(), ...))` shape, with `sink.sink_type == "CodeEval"`.
    #[test]
    fn test_taint_finding_dedupe_eval_compile_collapses_to_one() {
        // Single call site `eval(compile(config_file.read(), filename, "exec"))`
        // — with `config_file = ...read()` declared on the SAME line as the
        // sink, source.line == sink.line, source.var == "config_file". The
        // canonical engine emits one flow per matched sink pattern (CodeEval +
        // CodeExec + CodeCompile) — dedupe must collapse to a single
        // CodeEval-flagged finding.
        let py = r#"
def from_pyfile(filename, d):
    config_file = open(filename, "rb").read()
    eval(compile(config_file, filename, "exec"), d.__dict__)
    return True
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("dedupe_repro.py");
        std::fs::write(&file, py).unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        // Only inspect CommandInjection findings — the FileOpen on the
        // `open(...)` line is a separate (legitimate) PathTraversal finding
        // and must not be dedupe-folded across vuln_type.
        let cmd_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::CommandInjection)
            .collect();
        assert_eq!(
            cmd_findings.len(),
            1,
            "Expected exactly 1 CommandInjection finding post-dedupe, got {}: {:?}",
            cmd_findings.len(),
            cmd_findings
                .iter()
                .map(|f| f.sink.sink_type.clone())
                .collect::<Vec<_>>()
        );
        // Precedence: CodeEval beats CodeExec beats CodeCompile.
        assert_eq!(
            cmd_findings[0].sink.sink_type, "CodeEval",
            "Dedupe must keep CodeEval (highest sink_type_precedence) over \
             CodeExec/CodeCompile, got {}",
            cmd_findings[0].sink.sink_type
        );
    }

    /// TAINT-FINDING-DEDUPE-V1 boundary test: distinct source variables on
    /// the same sink line must NOT be deduped against each other.
    ///
    /// Two source variables (`env_var` from `os.environ` and `name` from
    /// `request.args.get`) flowing into a single sink line are legitimately
    /// distinct findings — the dedupe key includes `source.variable` for
    /// exactly this case.
    #[test]
    fn test_taint_finding_dedupe_distinct_source_vars_kept() {
        let py = r#"
import os
from flask import request
def handler():
    env_var = os.environ.get("HOME")
    name = request.args.get("name")
    os.system("echo " + env_var + " " + name)
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("distinct_vars.py");
        std::fs::write(&file, py).unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        let cmd_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::CommandInjection)
            .collect();
        // Two distinct source variables flow into the same `os.system` sink
        // line; both must be retained.
        assert_eq!(
            cmd_findings.len(),
            2,
            "Expected 2 distinct CommandInjection findings (one per source \
             variable), got {}",
            cmd_findings.len()
        );
        let mut src_vars: Vec<&str> = cmd_findings
            .iter()
            .map(|f| f.source.variable.as_str())
            .collect();
        src_vars.sort();
        assert_eq!(src_vars, vec!["env_var", "name"]);
    }

    /// TAINT-FLOW-CAUSAL-ORDERING-V1 regression guard.
    ///
    /// Reproduces the flask `config.py:208-209` inversion: a `with open(f)`
    /// FileOpen sink on line N is paired with the `f.read()` source on line
    /// N+1 (read produces tainted data, open is the file-handle sink). The
    /// engine's source/sink classification is correct in isolation, but the
    /// resulting flow has `source.line > sink.line` which is causally
    /// impossible — the read CANNOT have tainted the earlier open.
    /// `compute_taint_with_tree` must drop these flows at emission time.
    ///
    /// Acceptance: every emitted flow MUST satisfy `source.line <= sink.line`.
    #[test]
    fn test_taint_flow_causal_ordering_open_then_read_no_inversion() {
        // Mirrors the flask config.py shape that triggered the bug.
        let py = r#"
def from_pyfile(filename):
    with open(filename, mode="rb") as config_file:
        exec(compile(config_file.read(), filename, "exec"), d.__dict__)
    return True
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("inversion_repro.py");
        std::fs::write(&file, py).unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        for f in &findings {
            assert!(
                f.source.line <= f.sink.line,
                "Causal ordering violated: source.line={} > sink.line={} \
                 (vuln_type={:?}, file={:?})",
                f.source.line,
                f.sink.line,
                f.vuln_type,
                f.file
            );
        }
    }

    fn assert_detects_vuln(
        filename: &str,
        content: &str,
        vuln_type: VulnType,
    ) -> TldrResult<Vec<VulnFinding>> {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(filename);
        fs::write(&path, content).unwrap();
        scan_file_vulns(&path, Some(vuln_type))
    }

    #[test]
    fn test_e2e_rust_command_injection() {
        let findings = assert_detects_vuln(
            "main.rs",
            "fn main() {\n    let cmd = std::env::args().nth(1).unwrap();\n    std::process::Command::new(cmd);\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_ruby_command_injection() {
        let findings = assert_detects_vuln(
            "app.rb",
            "def handler\n  cmd = params[:cmd]\n  system(cmd)\nend\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_c_command_injection() {
        let findings = assert_detects_vuln(
            "main.c",
            "int main(int argc, char **argv) {\n    char *cmd = argv[1];\n    system(cmd);\n    return 0;\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_cpp_command_injection() {
        let findings = assert_detects_vuln(
            "main.cpp",
            "int main(int argc, char **argv) {\n    char *cmd = argv[1];\n    system(cmd);\n    return 0;\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_php_command_injection() {
        let findings = assert_detects_vuln(
            "index.php",
            "<?php\nfunction handler() {\n    $cmd = $_GET['cmd'];\n    system($cmd);\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_kotlin_command_injection() {
        let findings = assert_detects_vuln(
            "Main.kt",
            "fun handler(call: ApplicationCall) {\n    val cmd = call.request.queryParameters[\"cmd\"] ?: \"\"\n    Runtime.getRuntime().exec(cmd)\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_swift_command_injection() {
        let findings = assert_detects_vuln(
            "main.swift",
            "func handler() {\n    let cmd = CommandLine.arguments[1]\n    system(cmd)\n}\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_csharp_command_injection() {
        let findings = assert_detects_vuln(
            "Program.cs",
            "public class C { public void H(HttpRequest Request) { var cmd = Request.Query[\"cmd\"]; Process.Start(cmd); } }\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_scala_command_injection() {
        let findings = assert_detects_vuln(
            "Main.scala",
            "object M { def handler(request: Request): Unit = { val cmd = request.getQueryString(\"cmd\").get; Runtime.getRuntime.exec(cmd) } }\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_elixir_command_injection() {
        let findings = assert_detects_vuln(
            "app.ex",
            "defmodule App do\n  def handler(conn) do\n    cmd = conn.params[\"cmd\"]\n    System.cmd(\"sh\", [cmd])\n  end\nend\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_lua_command_injection() {
        let findings = assert_detects_vuln(
            "app.lua",
            "function handler()\n  local cmd = ngx.req.get_uri_args()['cmd']\n  os.execute(cmd)\nend\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_luau_command_injection() {
        let findings = assert_detects_vuln(
            "app.luau",
            "local function handler()\n  local cmd = os.getenv(\"CMD\")\n  os.execute(cmd)\nend\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_e2e_ocaml_command_injection() {
        let findings = assert_detects_vuln(
            "main.ml",
            "let handler () =\n  let cmd = Sys.getenv \"CMD\" in\n  Sys.command cmd\n",
            VulnType::CommandInjection,
        )
        .unwrap();
        assert!(!findings.is_empty());
    }

    // --- VAL-007 (M7): SSRF detection rule --------------------------------
    //
    // Per validator mandate e2e_test_preservation_mandatory, the SSRF rule
    // E2E tests are preserved across M3. The bank-content assertion
    // (test_get_sinks_ssrf_has_per_language_coverage) was deleted because
    // get_sinks itself is gone post-M3; coverage now lives in the canonical
    // AST sink banks at taint.rs:1700+ (audited by reports/M2-parity-audit.json).

    #[test]
    fn test_e2e_python_ssrf_requests_get() {
        let findings = assert_detects_vuln(
            "vuln.py",
            "def h():\n    target = request.args.get(\"url\")\n    requests.get(target)\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(
            !findings.is_empty(),
            "VAL-007: Python `requests.get(target)` with tainted target must produce >= 1 SSRF finding."
        );
        assert!(findings.iter().all(|f| f.vuln_type == VulnType::Ssrf));
    }

    #[test]
    fn test_e2e_python_ssrf_urllib_urlopen() {
        let findings = assert_detects_vuln(
            "vuln.py",
            "def h():\n    target = request.args.get(\"url\")\n    urllib.request.urlopen(target)\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Python `urllib.request.urlopen(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_python_ssrf_httpx_get() {
        let findings = assert_detects_vuln(
            "vuln.py",
            "def h():\n    target = request.args.get(\"url\")\n    httpx.get(target)\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Python `httpx.get(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_typescript_ssrf_fetch() {
        let findings = assert_detects_vuln(
            "vuln.ts",
            "async function h(req: Request) {\n    const target = req.query.url;\n    await fetch(target);\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: TypeScript `fetch(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_typescript_ssrf_axios_get() {
        let findings = assert_detects_vuln(
            "vuln.ts",
            "async function h(req: any) {\n    const target = req.query.url;\n    await axios.get(target);\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: TypeScript `axios.get(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_javascript_ssrf_fetch() {
        let findings = assert_detects_vuln(
            "vuln.js",
            "function h(req) {\n    const target = req.query.url;\n    fetch(target);\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: JavaScript `fetch(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_go_ssrf_http_get() {
        let findings = assert_detects_vuln(
            "vuln.go",
            "package main\nimport \"net/http\"\nfunc h(r *http.Request) {\n    target := r.URL.Query().Get(\"url\")\n    http.Get(target)\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Go `http.Get(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_go_ssrf_http_post() {
        let findings = assert_detects_vuln(
            "vuln.go",
            "package main\nimport \"net/http\"\nfunc h(r *http.Request, body []byte) {\n    target := r.URL.Query().Get(\"url\")\n    http.Post(target, \"application/json\", nil)\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Go `http.Post(target, ...)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_go_ssrf_http_newrequest() {
        let findings = assert_detects_vuln(
            "vuln.go",
            "package main\nimport \"net/http\"\nfunc h(r *http.Request) {\n    target := r.URL.Query().Get(\"url\")\n    http.NewRequest(\"GET\", target, nil)\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Go `http.NewRequest(method, target, body)` with tainted target must produce >= 1 SSRF finding.");
    }

    // --- Stretch languages: Java, Rust, Ruby, PHP ---

    #[test]
    fn test_e2e_java_ssrf_url_openconnection() {
        let findings = assert_detects_vuln(
            "Vuln.java",
            "public class V { public void h(HttpServletRequest request) throws Exception { String target = request.getParameter(\"url\"); new URL(target).openConnection(); } }\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Java `new URL(target).openConnection()` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_rust_ssrf_reqwest_get() {
        let findings = assert_detects_vuln(
            "main.rs",
            "fn handler() {\n    let target = std::env::var(\"URL\").unwrap();\n    reqwest::get(target);\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Rust `reqwest::get(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_ruby_ssrf_net_http_get() {
        let findings = assert_detects_vuln(
            "app.rb",
            "def handler\n  target = params[:url]\n  Net::HTTP.get(target)\nend\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: Ruby `Net::HTTP.get(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    #[test]
    fn test_e2e_php_ssrf_file_get_contents() {
        let findings = assert_detects_vuln(
            "index.php",
            "<?php\nfunction handler() {\n    $target = $_GET['url'];\n    file_get_contents($target);\n}\n",
            VulnType::Ssrf,
        )
        .unwrap();
        assert!(!findings.is_empty(),
            "VAL-007: PHP `file_get_contents(target)` with tainted target must produce >= 1 SSRF finding.");
    }

    /// VAL-007: SSRF must be part of the default `vuln_types` list scanned
    /// when the caller passes `vuln_filter = None`. Pre-fix the default list
    /// excluded Ssrf — silently skipping all SSRF scans on the default
    /// `tldr vuln` invocation.
    #[test]
    fn test_e2e_ssrf_in_default_vuln_types() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vuln.go");
        std::fs::write(
            &file,
            "package main\nimport \"net/http\"\nfunc h(r *http.Request) { target := r.URL.Query().Get(\"u\"); http.Get(target) }\n",
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        let ssrf_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::Ssrf)
            .collect();
        assert!(
            !ssrf_findings.is_empty(),
            "VAL-007: SSRF must be included in the default vuln_types list. Got findings: {:?}",
            findings.iter().map(|f| f.vuln_type).collect::<Vec<_>>()
        );
    }

    // ========================================================================
    // VULN-FASTPATH-SUBSTRING-PREFILTER-V1 — fast-path skip correctness tests
    // ========================================================================

    /// FAST-PATH-1: A function containing only arithmetic — no source AND
    /// no sink call-name in the body — must produce zero findings (the
    /// substring prefilter is expected to skip CFG/DFG/taint construction
    /// entirely; we observe the externally-visible contract: 0 findings,
    /// no panic, no CFG construction errors leaking through).
    #[test]
    fn test_fastpath_skip_function_with_no_taint_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("arith.py");
        // Pure arithmetic — no source-name (no `request.`, no `input(`,
        // no `sys.stdin`, no `os.environ`, no `.read`) and no sink-name
        // (no `.execute`, no `eval`, no `exec`, no `subprocess.`,
        // no `os.system`, no `open(`, no `Path(`).
        std::fs::write(
            &file,
            "def add(a, b):\n    total = a + b\n    return total * 2\n",
        )
        .unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            findings.is_empty(),
            "FAST-PATH-1: pure-arithmetic function must produce 0 findings; got: {:?}",
            findings.iter().map(|f| f.vuln_type).collect::<Vec<_>>()
        );
        // Independent assertion: verify the prefilter predicate itself
        // returns false on this body (the externally observable contract
        // that drives the skip).
        let body = "def add(a, b):\n    total = a + b\n    return total * 2\n";
        assert!(
            !crate::security::taint::function_body_has_taint_pattern(
                body,
                Language::Python
            ),
            "FAST-PATH-1: prefilter must report no source/sink pattern in pure-arithmetic body."
        );
    }

    /// FAST-PATH-2: A function that DOES contain a source (or a sink)
    /// must run the full analysis. Here we use a body with the source
    /// `request.args.get` (Python HttpParam) AND the sink `cursor.execute`
    /// (SqlQuery) so a flow IS produced — proving that the prefilter
    /// correctly admits real-pattern bodies into the full pipeline.
    #[test]
    fn test_fastpath_no_skip_function_with_source_or_sink() {
        // Source-only — no sink: prefilter MUST still admit (because
        // `request.args` substring is present); the AST analysis then
        // returns 0 flows because there is no sink. The point is
        // proving the predicate fired (admit, not skip).
        let body_source_only = "def h():\n    target = request.args.get(\"q\")\n    return target.upper()\n";
        assert!(
            crate::security::taint::function_body_has_taint_pattern(
                body_source_only,
                Language::Python
            ),
            "FAST-PATH-2: prefilter must admit a body containing the source pattern `request.args`."
        );

        // Sink-only — no source: prefilter MUST still admit (because
        // `.execute` substring is present).
        let body_sink_only = "def h(q):\n    cursor.execute(\"SELECT 1\")\n";
        assert!(
            crate::security::taint::function_body_has_taint_pattern(
                body_sink_only,
                Language::Python
            ),
            "FAST-PATH-2: prefilter must admit a body containing the sink pattern `.execute`."
        );

        // End-to-end: source + sink → finding produced (full analysis ran).
        let findings = assert_detects_vuln(
            "vuln.py",
            "def h():\n    q = request.args.get(\"q\")\n    cursor.execute(q)\n",
            VulnType::SqlInjection,
        )
        .unwrap();
        assert!(
            !findings.is_empty(),
            "FAST-PATH-2: source + sink in same function must yield >= 1 SqlInjection finding (proves full analysis ran)."
        );
    }

    /// FAST-PATH-3: A function in which the source-name appears ONLY
    /// inside a string literal must run the full analysis (substring
    /// prefilter is a SUPERSET of the AST detector — string literals
    /// match it). The canonical AST detector is expected to suppress
    /// the literal at the detector layer (`is_in_string`), so the final
    /// finding count is 0 — but the prefilter MUST have admitted the
    /// body into the full pipeline (otherwise it would have produced 0
    /// findings via skip, not via the AST suppression we are
    /// validating).
    #[test]
    fn test_fastpath_runs_full_analysis_on_string_literal_match() {
        // A function whose body contains "request.args" only inside a
        // string literal. The prefilter sees the substring and admits;
        // the AST detector's string-literal filter suppresses the FP,
        // yielding 0 findings.
        let body = "def doc():\n    msg = \"see request.args in flask docs\"\n    return msg\n";
        assert!(
            crate::security::taint::function_body_has_taint_pattern(
                body,
                Language::Python
            ),
            "FAST-PATH-3: prefilter must admit a body where the source substring appears inside a string literal (correctness — superset of AST detector)."
        );
        // End-to-end: 0 findings expected (canonical AST `is_in_string`
        // suppresses the literal at the detector layer).
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("doc.py");
        std::fs::write(&file, body).unwrap();
        let findings = scan_file_vulns(&file, None).unwrap();
        assert!(
            findings.is_empty(),
            "FAST-PATH-3: string-literal-only match must produce 0 findings via AST suppression (not via prefilter skip); got: {:?}",
            findings.iter().map(|f| (f.vuln_type, f.sink.line)).collect::<Vec<_>>()
        );
    }

    /// FAST-PATH-NEEDLES: Sanity check the per-language needle set is
    /// non-empty for every supported language and contains the canonical
    /// shapes we expect from the spec (Python `.execute`, `.read`, `eval`,
    /// `exec`, `request.args`, `os.system`, `os.environ`).
    #[test]
    fn test_fastpath_needle_set_python_canonical() {
        let needles = crate::security::taint::fastpath_pattern_strings(Language::Python);
        assert!(!needles.is_empty(), "Python needle set must not be empty.");
        for canonical in &[".execute", ".read", "eval", "exec", "request.args", "os.system", "os.environ"] {
            assert!(
                needles.contains(canonical),
                "Python needle set missing canonical needle `{}`. Got: {:?}",
                canonical,
                needles
            );
        }
    }

    /// FAST-PATH-NEEDLES-ALL-LANGS: every supported language must have a
    /// non-empty needle set (otherwise the prefilter would skip every
    /// function in that language → false-negative).
    #[test]
    fn test_fastpath_needle_set_nonempty_all_langs() {
        for lang in [
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go,
            Language::Java,
            Language::Rust,
            Language::C,
            Language::Cpp,
            Language::Ruby,
            Language::Kotlin,
            Language::Swift,
            Language::CSharp,
            Language::Scala,
            Language::Php,
            Language::Lua,
            Language::Luau,
            Language::Elixir,
            Language::Ocaml,
        ] {
            let needles = crate::security::taint::fastpath_pattern_strings(lang);
            assert!(
                !needles.is_empty(),
                "FAST-PATH-NEEDLES-ALL-LANGS: needle set empty for {:?} — prefilter would skip every function and produce false-negatives.",
                lang
            );
        }
    }
}
