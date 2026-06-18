//! Shared types for remaining commands
//!
//! This module defines all data types used across the remaining analysis
//! commands. Types are designed for JSON serialization with serde.

use std::collections::HashMap;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// =============================================================================
// Output Format
// =============================================================================

/// Output format for all commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON output (default)
    #[default]
    Json,
    /// Human-readable text output
    Text,
    /// SARIF format (only for vuln command)
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Text => write!(f, "text"),
            Self::Sarif => write!(f, "sarif"),
        }
    }
}

// =============================================================================
// Severity Level
// =============================================================================

/// Severity level for findings.
///
/// m024-severity-normalize-v1 (v0.4.2 M-117 / M-024, BREAKING): the
/// in-memory enum keeps its 5 variants for `--severity <level>`
/// filtering and `order()` ranking, but JSON serialization is now
/// projected onto the canonical 3-level vocabulary:
///
///   ```text
///   Critical → "error"
///   High     → "error"
///   Medium   → "warn"
///   Low      → "info"
///   Info     → "info"
///   ```
///
/// Deserialize accepts both the canonical 3-level strings AND the
/// legacy 5-level strings so config files and pre-fix daemon payloads
/// still parse. Unknown strings default to `Medium`.
///
/// `Display` (used by human-readable text output, sort headers, CLI
/// `--help`) is preserved at the legacy 5-level vocabulary.
/// `ValueEnum` (used by `--severity <level>` clap parsing) is
/// preserved at the legacy 5-level vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, Default)]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Returns ordering value (lower = more severe)
    pub fn order(&self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
            Self::Info => 4,
        }
    }

    /// m024-severity-normalize-v1: project to the canonical 3-level
    /// vocabulary emitted in JSON output.
    pub fn canonical_str(&self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warn",
            Self::Low | Self::Info => "info",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.canonical_str())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Ok(match s.as_str() {
            // Canonical 3-level (post-M-024)
            "info" => Self::Info,
            "warn" => Self::Medium,
            "error" => Self::High,
            // Legacy 5-level (pre-M-024) — accepted for back-compat on
            // round-trip of stored payloads and user config files.
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "warning" => Self::Medium,
            "hint" | "note" => Self::Info,
            _ => Self::Medium,
        })
    }
}

// =============================================================================
// Location
// =============================================================================

/// A location in source code (shared across multiple commands).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

impl Location {
    /// Create a new location
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    /// Create a location with column information
    pub fn with_column(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            end_line: None,
            end_column: None,
        }
    }
}

// =============================================================================
// Todo Types
// =============================================================================

/// A single improvement item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    /// Category of improvement (e.g., "dead_code", "complexity", "cohesion")
    pub category: String,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Human-readable description
    pub description: String,
    /// File where the issue was found
    #[serde(default)]
    pub file: String,
    /// Line number
    #[serde(default)]
    pub line: u32,
    /// Severity level
    #[serde(default)]
    pub severity: String,
    /// Score from sub-analysis (0.0-1.0 typically)
    #[serde(default)]
    pub score: f64,
}

impl TodoItem {
    /// Create a new TodoItem
    pub fn new(category: impl Into<String>, priority: u32, description: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            priority,
            description: description.into(),
            file: String::new(),
            line: 0,
            severity: String::new(),
            score: 0.0,
        }
    }

    /// Set file and line
    pub fn with_location(mut self, file: impl Into<String>, line: u32) -> Self {
        self.file = file.into();
        self.line = line;
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }

    /// Set score
    pub fn with_score(mut self, score: f64) -> Self {
        self.score = score;
        self
    }
}

/// Summary of todo analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TodoSummary {
    /// Number of dead code items found
    pub dead_count: u32,
    /// Number of similar code pairs found
    pub similar_pairs: u32,
    /// Number of classes with low cohesion
    pub low_cohesion_count: u32,
    /// Number of complexity hotspots
    pub hotspot_count: u32,
    /// Number of equivalence groups (redundant expressions)
    pub equivalence_groups: u32,
}

/// Todo analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoReport {
    /// Command identifier
    pub wrapper: String,
    /// Path that was analyzed
    pub path: String,
    /// Improvement items sorted by priority
    pub items: Vec<TodoItem>,
    /// Summary statistics
    pub summary: TodoSummary,
    /// Raw results from sub-analyses (only present when `--detail <name>`
    /// is used; otherwise omitted from JSON output).
    ///
    /// WRAPPER-CROSS-CONSISTENCY-V1 (BUG-19): previously serialized as
    /// `sub_results: {}` on every todo invocation. The empty `{}` was
    /// misleading: todo does not populate sub_results unless `--detail`
    /// is passed. Skipped when empty.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sub_results: HashMap<String, Value>,
    /// Total elapsed time in milliseconds
    pub total_elapsed_ms: f64,
}

impl TodoReport {
    /// Create a new TodoReport
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            wrapper: "todo".to_string(),
            path: path.into(),
            items: Vec::new(),
            summary: TodoSummary::default(),
            sub_results: HashMap::new(),
            total_elapsed_ms: 0.0,
        }
    }
}

// =============================================================================
// Secure Types
// =============================================================================

/// A security finding from the secure command.
///
/// m024-severity-normalize-v1 (v0.4.2 M-117 / M-024): the in-memory
/// `severity` string is preserved at its legacy 5-level vocabulary
/// (`critical|high|medium|low|info` and a few legacy variants) because
/// internal sort / filter / text-colorization paths inside
/// `commands/remaining/secure.rs` compare on those literal strings.
/// JSON serialization is projected onto the canonical 3-level set
/// via a manual `Serialize` impl. Deserialize is unchanged (passes the
/// raw string through).
#[derive(Debug, Clone, Deserialize)]
pub struct SecureFinding {
    /// Category of finding (e.g., "taint", "resource_leak", "bounds")
    pub category: String,
    /// Severity level (in-memory: legacy 5-level vocabulary; JSON:
    /// canonical 3-level vocabulary projected at serialize time).
    pub severity: String,
    /// Human-readable description
    pub description: String,
    /// File where the issue was found
    #[serde(default)]
    pub file: String,
    /// Line number
    #[serde(default)]
    pub line: u32,
}

/// m024-severity-normalize-v1: project a legacy severity literal onto
/// the canonical 3-level vocabulary emitted by every M-024 command.
fn secure_canonical_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "info" | "note" | "hint" | "low" => "info",
        "warn" | "warning" | "medium" => "warn",
        "error" | "high" | "critical" => "error",
        _ => "error",
    }
}

impl Serialize for SecureFinding {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = ser.serialize_struct("SecureFinding", 5)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("severity", secure_canonical_severity(&self.severity))?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("file", &self.file)?;
        state.serialize_field("line", &self.line)?;
        state.end()
    }
}

impl SecureFinding {
    /// Create a new SecureFinding
    pub fn new(
        category: impl Into<String>,
        severity: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            category: category.into(),
            severity: severity.into(),
            description: description.into(),
            file: String::new(),
            line: 0,
        }
    }

    /// Set file and line
    pub fn with_location(mut self, file: impl Into<String>, line: u32) -> Self {
        self.file = file.into();
        self.line = line;
        self
    }
}

/// Security summary.
///
/// WRAPPER-CROSS-CONSISTENCY-V1: every `*_count` field is computed from the
/// FINAL `SecureReport.findings` array via category group-by. The sum of
/// all category counters in this struct (taint + leak + bounds + behavioral
/// + unsafe_blocks + raw_pointer_ops + unwrap_calls + todo_markers +
/// missing_contracts + mutable_params) MUST equal `findings.len()`.
/// `taint_critical` is a sub-count of `taint_count` (severity refinement,
/// not its own category) and is excluded from that invariant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecureSummary {
    /// Number of taint-related findings
    pub taint_count: u32,
    /// Number of critical taint findings
    pub taint_critical: u32,
    /// Number of resource leak findings
    pub leak_count: u32,
    /// Number of bounds/overflow warnings
    pub bounds_warnings: u32,
    /// Number of behavioral findings (e.g. bare `except:`)
    ///
    /// WRAPPER-CROSS-CONSISTENCY-V1 (BUG-15): previously the `behavioral`
    /// category was emitted into `findings[]` but had no corresponding
    /// summary counter, so `sum(*_count) != findings.len()`. Adding this
    /// counter restores the invariant.
    #[serde(default)]
    pub behavioral_count: u32,
    /// Number of missing contracts
    pub missing_contracts: u32,
    /// Number of mutable parameter issues
    pub mutable_params: u32,
    /// Number of Rust unsafe blocks
    #[serde(default)]
    pub unsafe_blocks: u32,
    /// Number of Rust raw pointer operations
    #[serde(default)]
    pub raw_pointer_ops: u32,
    /// Number of Rust unwrap calls
    #[serde(default)]
    pub unwrap_calls: u32,
    /// Number of todo!/unimplemented! markers in non-test code
    #[serde(default)]
    pub todo_markers: u32,
}

/// Secure analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureReport {
    /// Command identifier
    pub wrapper: String,
    /// Path that was analyzed.
    ///
    /// cross-command-consistency-v1 (BUG-14): renamed in JSON to `root`
    /// so project-root field naming is identical across commands. The Rust
    /// field is still `path` for backwards compatibility; JSON callers see
    /// `root`. The `alias` keeps deserialisation of older bodies working.
    #[serde(rename = "root", alias = "path")]
    pub path: String,
    /// Security findings sorted by severity
    pub findings: Vec<SecureFinding>,
    /// Summary statistics
    pub summary: SecureSummary,
    /// Raw results from sub-analyses (only present when `--detail <name>`
    /// is used; otherwise omitted from JSON output).
    ///
    /// WRAPPER-CROSS-CONSISTENCY-V1 (BUG-19): previously serialized as
    /// `sub_results: {}` on every secure invocation — a cargo-cult of
    /// `verify`'s schema. The empty `{}` was misleading: secure does not
    /// populate sub_results unless `--detail` is passed. Skipped when
    /// empty so consumers don't conflate "no detail requested" with "no
    /// sub-analyses ran".
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sub_results: HashMap<String, Value>,
    /// Total elapsed time in milliseconds
    pub total_elapsed_ms: f64,
    /// Number of files skipped (e.g. non-UTF-8 input).
    ///
    /// SECURE-UTF8-TOLERANCE-V1: parser-test corpora (notably the Luau
    /// `tests/conformance/literals.luau`, `pm.luau`, `sort.luau`) contain
    /// raw non-UTF-8 bytes. Pre-fix, `tldr secure --lang luau` aborted
    /// the entire scan on the first such file with `Error: stream did
    /// not contain valid UTF-8`. Post-fix, those files are skipped and
    /// surfaced via `files_skipped` + `warnings` while the rest of the
    /// scan completes. Skipped from JSON when zero so existing consumers
    /// don't observe a schema delta on UTF-8-clean inputs.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub files_skipped: u32,
    /// Per-file warnings (e.g. non-UTF-8 skip messages with byte offsets).
    ///
    /// SECURE-UTF8-TOLERANCE-V1: companion to `files_skipped`. Each entry
    /// pinpoints the file path and first invalid-UTF-8 byte offset so
    /// callers can audit what was skipped. Skipped from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Helper for `serde(skip_serializing_if)` on `u32` count fields that should
/// be omitted from JSON when zero (preserves backward-compat schema).
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

impl SecureReport {
    /// Create a new SecureReport
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            wrapper: "secure".to_string(),
            path: path.into(),
            findings: Vec::new(),
            summary: SecureSummary::default(),
            sub_results: HashMap::new(),
            total_elapsed_ms: 0.0,
            files_skipped: 0,
            warnings: Vec::new(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_serialization() {
        let json = serde_json::to_string(&OutputFormat::Json).unwrap();
        assert_eq!(json, r#""json""#);

        let text = serde_json::to_string(&OutputFormat::Text).unwrap();
        assert_eq!(text, r#""text""#);

        let sarif = serde_json::to_string(&OutputFormat::Sarif).unwrap();
        assert_eq!(sarif, r#""sarif""#);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical.order() < Severity::High.order());
        assert!(Severity::High.order() < Severity::Medium.order());
        assert!(Severity::Medium.order() < Severity::Low.order());
        assert!(Severity::Low.order() < Severity::Info.order());
    }

    #[test]
    fn test_location_serialization() {
        let loc = Location::new("test.py", 42);
        let json = serde_json::to_string(&loc).unwrap();
        assert!(json.contains(r#""file":"test.py""#));
        assert!(json.contains(r#""line":42"#));
    }

    #[test]
    fn test_todo_report_serialization() {
        let mut report = TodoReport::new("/path/to/file.py");
        report
            .items
            .push(TodoItem::new("dead_code", 1, "Unused function"));
        report.summary.dead_count = 1;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""wrapper":"todo""#));
        assert!(json.contains(r#""dead_count":1"#));
    }

    #[test]
    fn test_todo_item_builder() {
        let item = TodoItem::new("complexity", 2, "High cyclomatic complexity")
            .with_location("src/main.py", 100)
            .with_severity("high")
            .with_score(0.85);

        assert_eq!(item.category, "complexity");
        assert_eq!(item.file, "src/main.py");
        assert_eq!(item.line, 100);
        assert_eq!(item.severity, "high");
        assert!((item.score - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_secure_report_serialization() {
        let mut report = SecureReport::new("/path/to/file.py");
        report
            .findings
            .push(SecureFinding::new("taint", "critical", "SQL injection"));
        report.summary.taint_count = 1;
        report.summary.taint_critical = 1;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""wrapper":"secure""#));
        assert!(json.contains(r#""taint_count":1"#));
        assert!(json.contains(r#""taint_critical":1"#));
    }

    #[test]
    fn test_secure_finding_builder() {
        let finding = SecureFinding::new("resource_leak", "high", "File not closed")
            .with_location("src/db.py", 42);

        assert_eq!(finding.category, "resource_leak");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.file, "src/db.py");
        assert_eq!(finding.line, 42);
    }
}

// =============================================================================
// Explain Types
// =============================================================================

/// Parameter information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamInfo {
    /// Parameter name
    pub name: String,
    /// Type hint if present
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_hint: Option<String>,
    /// Default value if present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

impl ParamInfo {
    /// Create a new ParamInfo
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_hint: None,
            default: None,
        }
    }

    /// Set type hint
    pub fn with_type(mut self, type_hint: impl Into<String>) -> Self {
        self.type_hint = Some(type_hint.into());
        self
    }

    /// Set default value
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
}

/// Function signature information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Parameters
    pub params: Vec<ParamInfo>,
    /// Return type if annotated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    /// Decorators
    #[serde(default)]
    pub decorators: Vec<String>,
    /// Whether the function is async
    #[serde(default)]
    pub is_async: bool,
    /// Docstring content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring: Option<String>,
}

impl SignatureInfo {
    /// Create a new SignatureInfo
    pub fn new() -> Self {
        Self {
            params: Vec::new(),
            return_type: None,
            decorators: Vec::new(),
            is_async: false,
            docstring: None,
        }
    }

    /// Add a parameter
    pub fn with_param(mut self, param: ParamInfo) -> Self {
        self.params.push(param);
        self
    }

    /// Set return type
    pub fn with_return_type(mut self, return_type: impl Into<String>) -> Self {
        self.return_type = Some(return_type.into());
        self
    }

    /// Set docstring
    pub fn with_docstring(mut self, docstring: impl Into<String>) -> Self {
        self.docstring = Some(docstring.into());
        self
    }

    /// Set async flag
    pub fn set_async(mut self, is_async: bool) -> Self {
        self.is_async = is_async;
        self
    }
}

impl Default for SignatureInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Purity analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurityInfo {
    /// Classification: "pure", "impure", or "unknown"
    pub classification: String,
    /// List of detected effects (empty if pure)
    #[serde(default)]
    pub effects: Vec<String>,
    /// Confidence: "high", "medium", or "low"
    pub confidence: String,
}

impl PurityInfo {
    /// Create a pure classification
    pub fn pure() -> Self {
        Self {
            classification: "pure".to_string(),
            effects: Vec::new(),
            confidence: "high".to_string(),
        }
    }

    /// Create an impure classification
    pub fn impure(effects: Vec<String>) -> Self {
        Self {
            classification: "impure".to_string(),
            effects,
            confidence: "high".to_string(),
        }
    }

    /// Create an unknown classification
    pub fn unknown() -> Self {
        Self {
            classification: "unknown".to_string(),
            effects: Vec::new(),
            confidence: "low".to_string(),
        }
    }

    /// Set confidence level
    pub fn with_confidence(mut self, confidence: impl Into<String>) -> Self {
        self.confidence = confidence.into();
        self
    }
}

impl Default for PurityInfo {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Complexity metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityInfo {
    /// Cyclomatic complexity
    pub cyclomatic: u32,
    /// Number of basic blocks
    pub num_blocks: u32,
    /// Number of edges in CFG
    pub num_edges: u32,
    /// Whether the function contains loops
    pub has_loops: bool,
    /// Cognitive complexity (SonarSource algorithm).
    ///
    /// rust-explain-cognitive-v1 (v0.4.2 bug-C6 / VAL-RUST-EXPLAIN):
    /// joins `tldr cognitive`'s per-function value into `tldr
    /// explain`'s complexity block so the two commands agree on the
    /// same function. `None` only when the cognitive analysis cannot
    /// be run (parse error, language unsupported by the cognitive
    /// crate, or function not found) — the field is then omitted
    /// from JSON via `skip_serializing_if`. Wiring is
    /// language-agnostic: every language `tldr cognitive` supports
    /// gets populated.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cognitive: Option<u32>,
}

impl ComplexityInfo {
    /// Create new complexity info
    pub fn new(cyclomatic: u32, num_blocks: u32, num_edges: u32, has_loops: bool) -> Self {
        Self {
            cyclomatic,
            num_blocks,
            num_edges,
            has_loops,
            cognitive: None,
        }
    }
}

impl Default for ComplexityInfo {
    fn default() -> Self {
        Self {
            cyclomatic: 1,
            num_blocks: 1,
            num_edges: 0,
            has_loops: false,
            cognitive: None,
        }
    }
}

/// Caller/callee information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallInfo {
    /// Function name
    pub name: String,
    /// File path
    pub file: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (0-indexed). cluster-misc-v2 (M-020): add column field
    /// so explain callers/callees carry position parity with all other
    /// location-bearing types (Location, FuncDef, etc.).
    #[serde(default)]
    pub column: u32,
}

impl CallInfo {
    /// Create new call info
    pub fn new(name: impl Into<String>, file: impl Into<String>, line: u32) -> Self {
        Self {
            name: name.into(),
            file: file.into(),
            line,
            column: 0,
        }
    }

    /// Create new call info with column.
    pub fn with_column(
        name: impl Into<String>,
        file: impl Into<String>,
        line: u32,
        column: u32,
    ) -> Self {
        Self {
            name: name.into(),
            file: file.into(),
            line,
            column,
        }
    }
}

/// Full explain report for a function.
///
/// schema-unification-v1 BUG-17: emits an additional `line` field
/// (mapped from `line_start`) so consumers can use a unified `line`
/// field name across `vuln`/`dead`/`extract`/`explain`/`health`.
/// `line_start` and `line_end` remain for callers that need ranges.
#[derive(Debug, Clone, Deserialize)]
pub struct ExplainReport {
    /// Function name.
    ///
    /// cross-command-consistency-v1 (BUG-14): emitted in JSON as
    /// `function` so the function-name field is identical across commands
    /// (`slice`, `dead-stores`, `resources`, `reaching-defs`, `taint`,
    /// `explain`, ...). The custom `Serialize` impl below handles the
    /// rename; deserialise still accepts both names via `alias`.
    #[serde(alias = "function")]
    pub function_name: String,
    /// File path
    pub file: String,
    /// Start line of function
    pub line_start: u32,
    /// End line of function
    pub line_end: u32,
    /// Detected language
    pub language: String,
    /// Signature information
    pub signature: SignatureInfo,
    /// Purity analysis
    pub purity: PurityInfo,
    /// Complexity metrics (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<ComplexityInfo>,
    /// Functions that call this function
    #[serde(default)]
    pub callers: Vec<CallInfo>,
    /// Functions called by this function
    #[serde(default)]
    pub callees: Vec<CallInfo>,
}

// schema-unification-v1 BUG-17: manual Serialize impl emits `line`
// alongside the existing `line_start`/`line_end` pair.
impl Serialize for ExplainReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut count = 8; // function_name, file, line_start, line_end, line, language, signature, purity
        if self.complexity.is_some() {
            count += 1;
        }
        // callers/callees always emitted (matches original derive — `default`
        // applies only to deserialize side).
        count += 2;
        let mut s = serializer.serialize_struct("ExplainReport", count)?;
        // cross-command-consistency-v1 (BUG-14): emit canonical `function`
        // (replaces the older `function_name`).
        s.serialize_field("function", &self.function_name)?;
        s.serialize_field("file", &self.file)?;
        s.serialize_field("line_start", &self.line_start)?;
        s.serialize_field("line_end", &self.line_end)?;
        s.serialize_field("line", &self.line_start)?;
        s.serialize_field("language", &self.language)?;
        s.serialize_field("signature", &self.signature)?;
        s.serialize_field("purity", &self.purity)?;
        if let Some(c) = &self.complexity {
            s.serialize_field("complexity", c)?;
        }
        s.serialize_field("callers", &self.callers)?;
        s.serialize_field("callees", &self.callees)?;
        s.end()
    }
}

impl ExplainReport {
    /// Create a new ExplainReport
    pub fn new(
        function_name: impl Into<String>,
        file: impl Into<String>,
        line_start: u32,
        line_end: u32,
        language: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            file: file.into(),
            line_start,
            line_end,
            language: language.into(),
            signature: SignatureInfo::default(),
            purity: PurityInfo::default(),
            complexity: None,
            callers: Vec::new(),
            callees: Vec::new(),
        }
    }

    /// Set signature
    pub fn with_signature(mut self, signature: SignatureInfo) -> Self {
        self.signature = signature;
        self
    }

    /// Set purity
    pub fn with_purity(mut self, purity: PurityInfo) -> Self {
        self.purity = purity;
        self
    }

    /// Set complexity
    pub fn with_complexity(mut self, complexity: ComplexityInfo) -> Self {
        self.complexity = Some(complexity);
        self
    }

    /// Add a caller
    pub fn add_caller(&mut self, caller: CallInfo) {
        self.callers.push(caller);
    }

    /// Add a callee
    pub fn add_callee(&mut self, callee: CallInfo) {
        self.callees.push(callee);
    }
}

// =============================================================================
// Definition Types
// =============================================================================

/// Symbol kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Class,
    Method,
    Variable,
    Parameter,
    Constant,
    Module,
    Type,
    Interface,
    Property,
    #[default]
    Unknown,
}

/// Symbol information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// Symbol name
    pub name: String,
    /// Symbol kind
    pub kind: SymbolKind,
    /// Location in source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Type annotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_annotation: Option<String>,
    /// Docstring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring: Option<String>,
    /// Whether this is a builtin
    #[serde(default)]
    pub is_builtin: bool,
    /// Module path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

impl SymbolInfo {
    /// Create a new SymbolInfo
    pub fn new(name: impl Into<String>, kind: SymbolKind) -> Self {
        Self {
            name: name.into(),
            kind,
            location: None,
            type_annotation: None,
            docstring: None,
            is_builtin: false,
            module: None,
        }
    }
}

/// Definition lookup result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionResult {
    /// Symbol information
    pub symbol: SymbolInfo,
    /// Definition location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition: Option<Location>,
    /// Type definition location (for types)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_definition: Option<Location>,
}

// =============================================================================
// Diff Types
// =============================================================================

/// Type of AST change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Insert,
    Delete,
    Update,
    Move,
    Rename,
    Extract,
    Inline,
    Format,
}

/// Diff granularity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffGranularity {
    /// Token-level diff (L1)
    Token,
    /// Expression-level diff (L2)
    Expression,
    /// Statement-level diff (L3)
    Statement,
    /// Function-level diff (L4) - default
    #[default]
    Function,
    /// Class-level diff (L5)
    Class,
    /// File-level diff (L6)
    File,
    /// Module-level diff (L7)
    Module,
    /// Architecture-level diff (L8)
    Architecture,
}

/// Base class changes for class-level diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseChanges {
    /// Base classes added
    pub added: Vec<String>,
    /// Base classes removed
    pub removed: Vec<String>,
}

/// Kind of AST node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Function,
    Class,
    Method,
    Field,
    Statement,
    Expression,
    Block,
}

/// A single AST change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ASTChange {
    /// Type of change
    pub change_type: ChangeType,
    /// Kind of node changed
    pub node_kind: NodeKind,
    /// Name of the changed element
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Old location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_location: Option<Location>,
    /// New location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_location: Option<Location>,
    /// Old text (for updates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_text: Option<String>,
    /// New text (for updates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_text: Option<String>,
    /// Similarity score (for moves/renames)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f64>,
    /// Nested member changes (for class-level diff)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ASTChange>>,
    /// Base class changes (for class-level diff)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_changes: Option<BaseChanges>,
}

/// Diff summary statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Total changes
    pub total_changes: u32,
    /// Semantic changes (excluding format)
    pub semantic_changes: u32,
    /// Number of inserts
    pub inserts: u32,
    /// Number of deletes
    pub deletes: u32,
    /// Number of updates
    pub updates: u32,
    /// Number of moves
    pub moves: u32,
    /// Number of renames
    pub renames: u32,
    /// Number of format-only changes
    pub formats: u32,
    /// Number of extracts
    pub extracts: u32,
}

// =============================================================================
// L6: File-Level Types
// =============================================================================

/// L6: File-level structural fingerprint change.
///
/// Represents a single file's structural change between two directory snapshots.
/// The fingerprint is a hash of sorted function/class signatures, so two files
/// with the same structure but different formatting will produce the same hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLevelChange {
    /// Relative path of the file within the compared directory
    pub relative_path: String,
    /// Type of change (Insert=added, Delete=removed, Update=modified)
    pub change_type: ChangeType,
    /// Structural fingerprint of the file in dir_a (None if added)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_fingerprint: Option<u64>,
    /// Structural fingerprint of the file in dir_b (None if removed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_fingerprint: Option<u64>,
    /// Which signatures changed (only for Update)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_changes: Option<Vec<String>>,
}

// =============================================================================
// L7: Module-Level Types
// =============================================================================

/// L7: An import edge in the module dependency graph.
///
/// Represents a single `from X import Y` or `import X` statement,
/// capturing the source file, target module, and imported names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEdge {
    /// Source file that contains the import statement
    pub source_file: String,
    /// Target module being imported from
    pub target_module: String,
    /// Specific names imported (empty for `import X`)
    pub imported_names: Vec<String>,
}

/// L7: Module-level change combining import graph and structural diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLevelChange {
    /// Module path (relative file path)
    pub module_path: String,
    /// Type of change at the module level
    pub change_type: ChangeType,
    /// Import edges added in dir_b
    pub imports_added: Vec<ImportEdge>,
    /// Import edges removed from dir_a
    pub imports_removed: Vec<ImportEdge>,
    /// L6 file-level change data (if structure also changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_change: Option<FileLevelChange>,
}

/// L7: Summary of import graph differences between two directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGraphSummary {
    /// Total import edges in dir_a
    pub total_edges_a: usize,
    /// Total import edges in dir_b
    pub total_edges_b: usize,
    /// Number of edges added (present in B but not A)
    pub edges_added: usize,
    /// Number of edges removed (present in A but not B)
    pub edges_removed: usize,
    /// Number of modules whose import set changed
    pub modules_with_import_changes: usize,
}

// =============================================================================
// L8: Architecture-Level Types
// =============================================================================

/// L8: Type of architectural change detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchChangeType {
    /// A directory migrated from one architectural layer to another
    LayerMigration,
    /// A new directory/layer was added
    Added,
    /// A directory/layer was removed
    Removed,
    /// The composition of a directory changed significantly
    CompositionChanged,
    /// A new dependency cycle was introduced
    CycleIntroduced,
    /// An existing dependency cycle was resolved
    CycleResolved,
}

/// L8: Architecture-level change for a single directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchLevelChange {
    /// Directory path (relative)
    pub directory: String,
    /// Type of architectural change
    pub change_type: ArchChangeType,
    /// Previous layer classification (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_layer: Option<String>,
    /// New layer classification (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_layer: Option<String>,
    /// Functions that migrated between layers
    #[serde(default)]
    pub migrated_functions: Vec<String>,
}

/// L8: Summary of architecture-level differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchDiffSummary {
    /// Number of directories that migrated between layers
    pub layer_migrations: usize,
    /// Number of new directories added
    pub directories_added: usize,
    /// Number of directories removed
    pub directories_removed: usize,
    /// Number of new dependency cycles introduced
    pub cycles_introduced: usize,
    /// Number of dependency cycles resolved
    pub cycles_resolved: usize,
    /// Overall stability score (1.0 = no changes, 0.0 = everything changed)
    pub stability_score: f64,
}

// =============================================================================
// Diff Report
// =============================================================================

/// Diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// First file
    pub file_a: String,
    /// Second file
    pub file_b: String,
    /// Whether files are identical
    pub identical: bool,
    /// List of changes
    pub changes: Vec<ASTChange>,
    /// Summary statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<DiffSummary>,
    /// Granularity level of this diff
    #[serde(default)]
    pub granularity: DiffGranularity,
    /// L6: File-level structural changes (directory diff)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_changes: Option<Vec<FileLevelChange>>,
    /// L7: Module-level changes with import graph diff
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_changes: Option<Vec<ModuleLevelChange>>,
    /// L7: Import graph summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_graph_summary: Option<ImportGraphSummary>,
    /// L8: Architecture-level changes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_changes: Option<Vec<ArchLevelChange>>,
    /// L8: Architecture diff summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_summary: Option<ArchDiffSummary>,
}

impl DiffReport {
    /// Create a new DiffReport
    pub fn new(file_a: impl Into<String>, file_b: impl Into<String>) -> Self {
        Self {
            file_a: file_a.into(),
            file_b: file_b.into(),
            identical: true,
            changes: Vec::new(),
            summary: Some(DiffSummary::default()),
            granularity: DiffGranularity::Function,
            file_changes: None,
            module_changes: None,
            import_graph_summary: None,
            arch_changes: None,
            arch_summary: None,
        }
    }
}

// =============================================================================
// Diff Impact Types
// =============================================================================

/// A function affected by changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFunction {
    /// Function name
    pub name: String,
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Functions that call this function
    #[serde(default)]
    pub callers: Vec<CallInfo>,
}

/// Diff impact summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffImpactSummary {
    /// Number of files changed
    pub files_changed: u32,
    /// Number of functions changed
    pub functions_changed: u32,
    /// Number of tests to run
    pub tests_to_run: u32,
}

/// Diff impact report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffImpactReport {
    /// Changed functions
    pub changed_functions: Vec<ChangedFunction>,
    /// Suggested tests to run
    pub suggested_tests: Vec<String>,
    /// Summary
    pub summary: DiffImpactSummary,
}

impl DiffImpactReport {
    /// Create a new DiffImpactReport
    pub fn new() -> Self {
        Self {
            changed_functions: Vec::new(),
            suggested_tests: Vec::new(),
            summary: DiffImpactSummary::default(),
        }
    }
}

impl Default for DiffImpactReport {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// API Check Types
// =============================================================================

/// Categories of API misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum MisuseCategory {
    CallOrder,
    ErrorHandling,
    Parameters,
    Resources,
    Crypto,
    Concurrency,
    Security,
}

/// Severity of API misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum MisuseSeverity {
    Info,
    Low,
    Medium,
    High,
}

/// An API rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIRule {
    /// Rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Category
    pub category: MisuseCategory,
    /// Severity
    pub severity: MisuseSeverity,
    /// Description
    pub description: String,
    /// Example of correct usage
    pub correct_usage: String,
}

/// A detected API misuse.
///
/// cluster-misc-v1 (M-042): `description` is emitted as a top-level field
/// in the JSON output (mirroring `rule.description`) so consumers can read
/// `finding.description` without drilling into the nested `rule` object.
/// The struct stores no extra field; the manual `Serialize` impl derives the
/// value from `self.rule.description` at serialization time.
#[derive(Debug, Clone, Deserialize)]
pub struct MisuseFinding {
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Rule that was violated
    pub rule: APIRule,
    /// The API call that violated the rule
    pub api_call: String,
    /// Human-readable message
    pub message: String,
    /// Suggested fix
    pub fix_suggestion: String,
    /// Code context
    #[serde(default)]
    pub code_context: String,
}

// cluster-misc-v1 (M-042): manual Serialize that mirrors `rule.description`
// to a top-level `description` key so findings emitted by `tldr api-check`
// expose the description without requiring callers to drill into `.rule`.
impl serde::Serialize for MisuseFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MisuseFinding", 9)?;
        state.serialize_field("file", &self.file)?;
        state.serialize_field("line", &self.line)?;
        state.serialize_field("column", &self.column)?;
        state.serialize_field("rule", &self.rule)?;
        state.serialize_field("api_call", &self.api_call)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("fix_suggestion", &self.fix_suggestion)?;
        state.serialize_field("code_context", &self.code_context)?;
        // Top-level mirror of rule.description (M-042).
        state.serialize_field("description", &self.rule.description)?;
        state.end()
    }
}

/// API check summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct APICheckSummary {
    /// Total findings
    pub total_findings: u32,
    /// Findings by category
    #[serde(default)]
    pub by_category: HashMap<String, u32>,
    /// Findings by severity
    #[serde(default)]
    pub by_severity: HashMap<String, u32>,
    /// APIs that were checked
    #[serde(default)]
    pub apis_checked: Vec<String>,
    /// Number of files scanned
    pub files_scanned: u32,
}

/// API check report.
#[derive(Debug, Clone, Deserialize)]
pub struct APICheckReport {
    /// Findings
    pub findings: Vec<MisuseFinding>,
    /// Summary
    pub summary: APICheckSummary,
    /// Number of rules applied
    pub rules_applied: u32,
}

// residual-bugs-v1 (P15.AGG15-4): manual Serialize that mirrors
// `summary.total_findings` and `summary.files_scanned` to top-level
// keys `total_findings` and `files_scanned`. Audit P15 observed
// `tldr api-check … | jq '.total_findings'` returning `null` despite
// `.summary.total_findings` being correct, breaking the documented
// top-level-mirror pattern that peer commands honour.
impl Serialize for APICheckReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("APICheckReport", 5)?;
        state.serialize_field("findings", &self.findings)?;
        state.serialize_field("summary", &self.summary)?;
        state.serialize_field("rules_applied", &self.rules_applied)?;
        // Top-level mirrors (P15.AGG15-4).
        state.serialize_field("total_findings", &self.summary.total_findings)?;
        state.serialize_field("files_scanned", &self.summary.files_scanned)?;
        state.end()
    }
}

impl APICheckReport {
    /// Create a new APICheckReport
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            summary: APICheckSummary::default(),
            rules_applied: 0,
        }
    }
}

impl Default for APICheckReport {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Equivalence (GVN) Types
// =============================================================================

/// Reference to an expression in source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionRef {
    /// Expression text
    pub text: String,
    /// Line number
    pub line: u32,
    /// Value number (GVN)
    pub value_number: u32,
}

/// A group of expressions sharing the same value number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GVNEquivalence {
    /// Value number for this group
    pub value_number: u32,
    /// Expressions in this equivalence class
    pub expressions: Vec<ExpressionRef>,
    /// Reason for equivalence
    #[serde(default)]
    pub reason: String,
}

/// A redundant expression pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redundancy {
    /// Original expression
    pub original: ExpressionRef,
    /// Redundant expression
    pub redundant: ExpressionRef,
    /// Reason why it's redundant
    #[serde(default)]
    pub reason: String,
}

/// GVN summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GVNSummary {
    /// Total expressions analyzed
    pub total_expressions: u32,
    /// Unique values (value numbers)
    pub unique_values: u32,
    /// Compression ratio (unique/total)
    pub compression_ratio: f64,
}

impl Default for GVNSummary {
    fn default() -> Self {
        Self {
            total_expressions: 0,
            unique_values: 0,
            compression_ratio: 1.0,
        }
    }
}

/// GVN report for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GVNReport {
    /// Function name
    pub function: String,
    /// Equivalence classes
    #[serde(default)]
    pub equivalences: Vec<GVNEquivalence>,
    /// Redundant expressions
    #[serde(default)]
    pub redundancies: Vec<Redundancy>,
    /// Summary statistics
    pub summary: GVNSummary,
}

impl GVNReport {
    /// Create a new GVNReport
    pub fn new(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            equivalences: Vec::new(),
            redundancies: Vec::new(),
            summary: GVNSummary::default(),
        }
    }
}

// =============================================================================
// Vuln Types
// =============================================================================

/// Types of vulnerabilities detected.
///
/// `Ord`/`PartialOrd` are derived (analysis-precision-v1, BUG-10) so that
/// `VulnFinding` lists can be sorted by `(file, line, vuln_type)` ascending
/// — producing the same enumeration order across JSON, text, and SARIF
/// output formats. Variant declaration order defines the `Ord` ranking;
/// callers SHOULD treat the relative ordering as opaque (only stability
/// matters).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum VulnType {
    SqlInjection,
    Xss,
    CommandInjection,
    Ssrf,
    PathTraversal,
    Deserialization,
    UnsafeCode,
    MemorySafety,
    Panic,
    Xxe,
    OpenRedirect,
    LdapInjection,
    XpathInjection,
    /// (v0.5.0 SOL-011 solidity-vuln-v1) Solidity tx.origin authorization
    TxOrigin,
    /// (v0.5.0 SOL-011 solidity-vuln-v1) Solidity state-variable shadowing
    ShadowingState,
    /// (v0.5.0 SOL-011 solidity-vuln-v1) Solidity unprotected selfdestruct
    Suicidal,
    /// (v0.5.0 SOL-011 solidity-vuln-v1) Solidity unchecked low-level call
    UncheckedLowlevel,
    /// (v0.5.0 SOL-011 solidity-vuln-v1) Solidity locked ether
    LockedEther,
    /// (v0.5.0 PACK-VULN pack-vuln-v1) Solidity reentrancy (CEI violation)
    Reentrancy,
    /// (v0.5.0 PACK-VULN pack-vuln-v1) Solidity unchecked `.send` return
    UncheckedSend,
    /// (v0.5.0 PACK-VULN pack-vuln-v1) Solidity arbitrary send (value to
    /// caller-controlled destination)
    ArbitrarySend,
    /// (v0.5.0 PACK-VULN pack-vuln-v1) Solidity delegatecall to a
    /// caller-controlled target
    DelegatecallTainted,
}

impl VulnType {
    /// Get the CWE identifier for this vulnerability type.
    pub fn cwe_id(&self) -> &'static str {
        match self {
            Self::SqlInjection => "CWE-89",
            Self::Xss => "CWE-79",
            Self::CommandInjection => "CWE-78",
            Self::Ssrf => "CWE-918",
            Self::PathTraversal => "CWE-22",
            Self::Deserialization => "CWE-502",
            Self::UnsafeCode => "CWE-242",
            Self::MemorySafety => "CWE-119",
            Self::Panic => "CWE-703",
            Self::Xxe => "CWE-611",
            Self::OpenRedirect => "CWE-601",
            Self::LdapInjection => "CWE-90",
            Self::XpathInjection => "CWE-643",
            // v0.5.0 SOL-011 solidity-vuln-v1
            Self::TxOrigin => "CWE-477",
            Self::ShadowingState => "CWE-1109",
            Self::Suicidal => "CWE-284",
            Self::UncheckedLowlevel => "CWE-252",
            Self::LockedEther => "CWE-664",
            // v0.5.0 PACK-VULN pack-vuln-v1
            Self::Reentrancy => "CWE-841",
            Self::UncheckedSend => "CWE-252",
            Self::ArbitrarySend => "CWE-862",
            Self::DelegatecallTainted => "CWE-829",
        }
    }

    /// Get the default severity for this vulnerability type.
    pub fn default_severity(&self) -> Severity {
        match self {
            Self::SqlInjection
            | Self::CommandInjection
            | Self::Deserialization
            | Self::MemorySafety => Severity::Critical,
            Self::Xxe
            | Self::Xss
            | Self::Ssrf
            | Self::PathTraversal
            | Self::LdapInjection
            | Self::XpathInjection
            | Self::UnsafeCode => Severity::High,
            Self::OpenRedirect | Self::Panic => Severity::Medium,
            // v0.5.0 SOL-011 solidity-vuln-v1
            Self::ShadowingState | Self::Suicidal => Severity::High,
            Self::TxOrigin | Self::UncheckedLowlevel | Self::LockedEther => Severity::Medium,
            // v0.5.0 PACK-VULN pack-vuln-v1
            Self::Reentrancy | Self::ArbitrarySend | Self::DelegatecallTainted => Severity::High,
            Self::UncheckedSend => Severity::Medium,
        }
    }
}

/// A step in the taint flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Code snippet
    pub code_snippet: String,
    /// Description of this step
    pub description: String,
}

/// A vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    /// Vulnerability type
    pub vuln_type: VulnType,
    /// Severity
    pub severity: Severity,
    /// CWE identifier
    pub cwe_id: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Enclosing function name (None if the finding's line is at module
    /// scope and not inside any function/method body).
    ///
    /// schema-cleanup-v2 (P2.BUG-9): pre-fix, vuln findings carried no
    /// indication of which function contained the source line, blocking
    /// clean piping into `tldr taint <file> <function>` and `tldr slice
    /// <file> <function> <line>`. The enclosing function is resolved
    /// post-analysis via `extract_file` over `(file, line)` —
    /// reusing the same module-info AST extractor that `taint`/`slice`
    /// rely on, rather than rebuilding language-aware function-range
    /// scanning inside the vuln pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Taint flow from source to sink. When `direct_sink` is `true` this is
    /// a single-element vec describing the call site (the source-and-sink
    /// collapse to the same statement).
    pub taint_flow: Vec<TaintFlow>,
    /// Remediation advice
    pub remediation: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// True when the source and sink resolve to the same statement (e.g.
    /// `let file = File::open(path)?` — `path` is tainted untrusted data
    /// and is consumed by the FileOpen sink in the same expression). The
    /// `taint_flow` is collapsed to a single entry to avoid emitting two
    /// identical source/sink records. Omitted from JSON when false.
    /// (M3 detection-accuracy-v1 BUG-17.)
    #[serde(default, skip_serializing_if = "is_false")]
    pub direct_sink: bool,
}

/// Helper for `skip_serializing_if` on `direct_sink` — keeps the JSON shape
/// stable for non-degenerate findings (no spurious `direct_sink: false`).
fn is_false(b: &bool) -> bool {
    !*b
}

/// Vulnerability summary statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnSummary {
    /// Total findings
    pub total_findings: u32,
    /// Findings by severity
    #[serde(default)]
    pub by_severity: HashMap<String, u32>,
    /// Findings by type
    #[serde(default)]
    pub by_type: HashMap<String, u32>,
    /// Files with vulnerabilities
    pub files_with_vulns: u32,
}

/// Vulnerability report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    /// Findings
    pub findings: Vec<VulnFinding>,
    /// Summary (optional for incremental results)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<VulnSummary>,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Number of files scanned
    pub files_scanned: u32,
    /// Number of files skipped (e.g. non-UTF-8 input).
    ///
    /// SECURE-UTF8-TOLERANCE-V1: parser-test corpora intentionally
    /// contain raw non-UTF-8 bytes. Pre-fix the vuln scanner silently
    /// dropped those files via an `if let Ok(..)` guard around
    /// `analyze_file`, so the user had no way to tell coverage was
    /// degraded. Post-fix the count is surfaced explicitly. Skipped from
    /// JSON when zero so UTF-8-clean inputs see no schema delta.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub files_skipped: u32,
    /// Per-file warnings (e.g. non-UTF-8 skip messages with byte offsets).
    ///
    /// SECURE-UTF8-TOLERANCE-V1: companion to `files_skipped`. Skipped
    /// from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl VulnReport {
    /// Create a new VulnReport
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            summary: None,
            scan_duration_ms: 0,
            files_scanned: 0,
            files_skipped: 0,
            warnings: Vec::new(),
        }
    }
}

impl Default for VulnReport {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Unit Tests for Types
// =============================================================================

#[cfg(test)]
mod unit_types_tests {
    use super::*;

    // =========================================================================
    // Output Format Tests
    // =========================================================================

    #[test]
    fn test_output_format_serialization() {
        let json = serde_json::to_string(&OutputFormat::Json).unwrap();
        assert_eq!(json, r#""json""#);

        let text = serde_json::to_string(&OutputFormat::Text).unwrap();
        assert_eq!(text, r#""text""#);

        let sarif = serde_json::to_string(&OutputFormat::Sarif).unwrap();
        assert_eq!(sarif, r#""sarif""#);
    }

    #[test]
    fn test_output_format_deserialization() {
        let json: OutputFormat = serde_json::from_str(r#""json""#).unwrap();
        assert_eq!(json, OutputFormat::Json);

        let text: OutputFormat = serde_json::from_str(r#""text""#).unwrap();
        assert_eq!(text, OutputFormat::Text);
    }

    // =========================================================================
    // Severity Tests
    // =========================================================================

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical.order() < Severity::High.order());
        assert!(Severity::High.order() < Severity::Medium.order());
        assert!(Severity::Medium.order() < Severity::Low.order());
        assert!(Severity::Low.order() < Severity::Info.order());
    }

    #[test]
    fn test_severity_serialization() {
        // m024-severity-normalize-v1 (v0.4.2 M-117 / M-024, BREAKING):
        // serialization is projected onto the canonical 3-level
        // vocabulary `{info, warn, error}`. Pre-fix this test pinned
        // the legacy 5-level strings (e.g. `"critical"`); post-fix
        // every legacy variant collapses per the M-024 mapping table.
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            r#""error""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::High).unwrap(),
            r#""error""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Medium).unwrap(),
            r#""warn""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Low).unwrap(),
            r#""info""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Info).unwrap(),
            r#""info""#
        );

        // Deserialize accepts BOTH the canonical 3-level form and the
        // legacy 5-level form so user config files / pre-fix daemon
        // payloads still parse.
        assert_eq!(
            serde_json::from_str::<Severity>(r#""error""#).unwrap(),
            Severity::High // canonical "error" decodes to the more
                           // common High (Critical is reserved for the
                           // explicit legacy literal)
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""warn""#).unwrap(),
            Severity::Medium
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""info""#).unwrap(),
            Severity::Info
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""critical""#).unwrap(),
            Severity::Critical
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""high""#).unwrap(),
            Severity::High
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""medium""#).unwrap(),
            Severity::Medium
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""low""#).unwrap(),
            Severity::Low
        );
    }

    // =========================================================================
    // Location Tests
    // =========================================================================

    #[test]
    fn test_location_serialization() {
        let loc = Location::new("test.py", 42);
        let json = serde_json::to_string(&loc).unwrap();
        assert!(json.contains(r#""file":"test.py""#));
        assert!(json.contains(r#""line":42"#));
    }

    #[test]
    fn test_location_with_column() {
        let loc = Location::with_column("test.py", 42, 10);
        assert_eq!(loc.column, 10);
    }

    // =========================================================================
    // Todo Types Tests
    // =========================================================================

    #[test]
    fn test_todo_report_serialization() {
        let mut report = TodoReport::new("/path/to/file.py");
        report
            .items
            .push(TodoItem::new("dead_code", 1, "Unused function"));
        report.summary.dead_count = 1;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""wrapper":"todo""#));
        assert!(json.contains(r#""dead_count":1"#));
    }

    #[test]
    fn test_todo_item_builder() {
        let item = TodoItem::new("complexity", 2, "High cyclomatic complexity")
            .with_location("src/main.py", 100)
            .with_severity("high")
            .with_score(0.85);

        assert_eq!(item.category, "complexity");
        assert_eq!(item.file, "src/main.py");
        assert_eq!(item.line, 100);
        assert_eq!(item.severity, "high");
        assert!((item.score - 0.85).abs() < 0.001);
    }

    // =========================================================================
    // Explain Types Tests
    // =========================================================================

    #[test]
    fn test_explain_report_serialization() {
        let mut report = ExplainReport::new("calculate_total", "/path/file.py", 10, 20, "python");
        report.purity = PurityInfo::pure();

        let json = serde_json::to_string(&report).unwrap();
        // cross-command-consistency-v1 (BUG-14): canonical key is `function`.
        assert!(json.contains(r#""function":"calculate_total""#));
        assert!(json.contains(r#""classification":"pure""#));
    }

    #[test]
    fn test_signature_info_builder() {
        let sig = SignatureInfo::new()
            .with_param(ParamInfo::new("x").with_type("int"))
            .with_return_type("int")
            .with_docstring("Doubles the input");

        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].name, "x");
        assert_eq!(sig.return_type.unwrap(), "int");
    }

    // =========================================================================
    // Secure Types Tests
    // =========================================================================

    #[test]
    fn test_secure_report_serialization() {
        let mut report = SecureReport::new("/path/to/file.py");
        report
            .findings
            .push(SecureFinding::new("taint", "critical", "SQL injection"));

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""wrapper":"secure""#));
    }

    // =========================================================================
    // Definition Types Tests
    // =========================================================================

    #[test]
    fn test_definition_result_serialization() {
        let result = DefinitionResult {
            symbol: SymbolInfo::new("my_func", SymbolKind::Function),
            definition: Some(Location::new("file.py", 10)),
            type_definition: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""name":"my_func""#));
        assert!(json.contains(r#""kind":"function""#));
    }

    #[test]
    fn test_symbol_kind_serialization() {
        let kind = SymbolKind::Function;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, r#""function""#);
    }

    // =========================================================================
    // Diff Types Tests
    // =========================================================================

    #[test]
    fn test_diff_report_serialization() {
        let mut report = DiffReport::new("a.py", "b.py");
        report.identical = false;
        if let Some(ref mut summary) = report.summary {
            summary.inserts = 1;
        }

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""file_a":"a.py""#));
        assert!(json.contains(r#""identical":false"#));
    }

    #[test]
    fn test_change_type_serialization() {
        let insert = serde_json::to_string(&ChangeType::Insert).unwrap();
        assert_eq!(insert, r#""insert""#);

        let rename = serde_json::to_string(&ChangeType::Rename).unwrap();
        assert_eq!(rename, r#""rename""#);
    }

    // =========================================================================
    // API Check Types Tests
    // =========================================================================

    #[test]
    fn test_api_check_report_serialization() {
        let mut report = APICheckReport::new();
        report.rules_applied = 5;
        report.summary.total_findings = 2;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""rules_applied":5"#));
        assert!(json.contains(r#""total_findings":2"#));
    }

    // =========================================================================
    // GVN Types Tests
    // =========================================================================

    #[test]
    fn test_gvn_report_serialization() {
        let mut report = GVNReport::new("test_func");
        report.summary.total_expressions = 10;
        report.summary.unique_values = 7;
        report.summary.compression_ratio = 0.7;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""function":"test_func""#));
        assert!(json.contains(r#""compression_ratio":0.7"#));
    }

    // =========================================================================
    // Vuln Types Tests
    // =========================================================================

    #[test]
    fn test_vuln_report_serialization() {
        let mut report = VulnReport::new();
        report.files_scanned = 5;
        report.scan_duration_ms = 100;

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""files_scanned":5"#));
        assert!(json.contains(r#""scan_duration_ms":100"#));
    }

    #[test]
    fn test_vuln_type_cwe_mapping() {
        assert_eq!(VulnType::SqlInjection.cwe_id(), "CWE-89");
        assert_eq!(VulnType::Xss.cwe_id(), "CWE-79");
        assert_eq!(VulnType::CommandInjection.cwe_id(), "CWE-78");
        assert_eq!(VulnType::Ssrf.cwe_id(), "CWE-918");
        assert_eq!(VulnType::PathTraversal.cwe_id(), "CWE-22");
        assert_eq!(VulnType::Deserialization.cwe_id(), "CWE-502");
        assert_eq!(VulnType::UnsafeCode.cwe_id(), "CWE-242");
        assert_eq!(VulnType::MemorySafety.cwe_id(), "CWE-119");
        assert_eq!(VulnType::Panic.cwe_id(), "CWE-703");
        assert_eq!(VulnType::Xxe.cwe_id(), "CWE-611");
        assert_eq!(VulnType::OpenRedirect.cwe_id(), "CWE-601");
        assert_eq!(VulnType::LdapInjection.cwe_id(), "CWE-90");
        assert_eq!(VulnType::XpathInjection.cwe_id(), "CWE-643");
    }

    #[test]
    fn test_vuln_type_default_severity() {
        assert_eq!(
            VulnType::SqlInjection.default_severity(),
            Severity::Critical
        );
        assert_eq!(
            VulnType::CommandInjection.default_severity(),
            Severity::Critical
        );
        assert_eq!(
            VulnType::MemorySafety.default_severity(),
            Severity::Critical
        );
        assert_eq!(VulnType::Xss.default_severity(), Severity::High);
        assert_eq!(VulnType::UnsafeCode.default_severity(), Severity::High);
        assert_eq!(VulnType::OpenRedirect.default_severity(), Severity::Medium);
        assert_eq!(VulnType::Panic.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_vuln_type_serialization() {
        let sql_inj = serde_json::to_string(&VulnType::SqlInjection).unwrap();
        assert_eq!(sql_inj, r#""sql_injection""#);

        let xss = serde_json::to_string(&VulnType::Xss).unwrap();
        assert_eq!(xss, r#""xss""#);
    }
}
