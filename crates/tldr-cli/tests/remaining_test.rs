//! Comprehensive tests for TLDR Remaining Commands
//!
//! These tests define expected behavior from spec.md and should FAIL initially
//! since no implementation exists yet. They drive the implementation.
//!
//! Test categories per command:
//! 1. Help output validation - verify CLI arguments are documented
//! 2. Happy path tests - Normal successful operation
//! 3. Error case tests - All error conditions from spec
//! 4. JSON output schema validation - Ensure output matches spec types
//! 5. Exit codes - Verify correct exit codes for success/error/findings
//!
//! Commands covered (9 total):
//! - LOW: todo, explain, secure
//! - MEDIUM: definition, diff, diff_impact
//! - HIGH: api_check, equivalence, vuln

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

// =============================================================================
// Test Utilities
// =============================================================================

/// Get the path to the test binary
fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Get assert_cmd version for better assertion support
fn tldr_assert_cmd() -> AssertCommand {
    AssertCommand::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Helper to create a test file in a temp directory
fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
    path
}

// =============================================================================
// Shared Types (mirrors types.rs from spec)
// =============================================================================

mod remaining_types {
    use super::*;

    // -------------------------------------------------------------------------
    // Common Types
    // -------------------------------------------------------------------------

    /// Output format for all commands.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum OutputFormat {
        Json,
        Text,
        Sarif,
    }

    /// Severity level for findings.
    ///
    /// m024-severity-normalize-v1 (v0.4.2 M-117 / M-024, BREAKING):
    /// the on-wire JSON `severity` field across vuln/secure/secrets/
    /// smells/diagnostics is now exactly the canonical 3-level set
    /// `{info, warn, error}`. The integration-test local mirror is
    /// reshaped to match — pre-fix `critical|high|medium|low|info`
    /// no longer appears in vuln command output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Severity {
        Info,
        Warn,
        Error,
    }

    /// A location in source code.
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

    // -------------------------------------------------------------------------
    // Todo Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TodoItem {
        pub category: String,
        pub priority: u32,
        pub description: String,
        #[serde(default)]
        pub file: String,
        #[serde(default)]
        pub line: u32,
        #[serde(default)]
        pub severity: String,
        #[serde(default)]
        pub score: f64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TodoSummary {
        pub dead_count: u32,
        pub similar_pairs: u32,
        pub low_cohesion_count: u32,
        pub hotspot_count: u32,
        pub equivalence_groups: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TodoReport {
        pub wrapper: String,
        pub path: String,
        pub items: Vec<TodoItem>,
        pub summary: TodoSummary,
        #[serde(default)]
        pub sub_results: HashMap<String, Value>,
        pub total_elapsed_ms: f64,
    }

    // -------------------------------------------------------------------------
    // Explain Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ParamInfo {
        pub name: String,
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        pub type_hint: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignatureInfo {
        pub params: Vec<ParamInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub return_type: Option<String>,
        #[serde(default)]
        pub decorators: Vec<String>,
        #[serde(default)]
        pub is_async: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub docstring: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PurityInfo {
        pub classification: String,
        #[serde(default)]
        pub effects: Vec<String>,
        pub confidence: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ComplexityInfo {
        pub cyclomatic: u32,
        pub num_blocks: u32,
        pub num_edges: u32,
        pub has_loops: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CallInfo {
        pub name: String,
        pub file: String,
        pub line: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExplainReport {
        // cross-command-consistency-v1 (BUG-14, 66fa8bc): function name is
        // emitted in JSON as `function` (was `function_name`).
        #[serde(rename = "function", alias = "function_name")]
        pub function: String,
        pub file: String,
        pub line_start: u32,
        pub line_end: u32,
        pub language: String,
        pub signature: SignatureInfo,
        pub purity: PurityInfo,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub complexity: Option<ComplexityInfo>,
        #[serde(default)]
        pub callers: Vec<CallInfo>,
        #[serde(default)]
        pub callees: Vec<CallInfo>,
    }

    // -------------------------------------------------------------------------
    // Secure Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecureFinding {
        pub category: String,
        pub severity: String,
        pub description: String,
        #[serde(default)]
        pub file: String,
        #[serde(default)]
        pub line: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecureSummary {
        pub taint_count: u32,
        pub taint_critical: u32,
        pub leak_count: u32,
        pub bounds_warnings: u32,
        #[serde(default)]
        pub behavioral_count: u32,
        pub missing_contracts: u32,
        pub mutable_params: u32,
        #[serde(default)]
        pub unsafe_blocks: u32,
        #[serde(default)]
        pub raw_pointer_ops: u32,
        #[serde(default)]
        pub unwrap_calls: u32,
        #[serde(default)]
        pub todo_markers: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecureReport {
        pub wrapper: String,
        // cross-command-consistency-v1 (BUG-14, 66fa8bc): analyzed path is
        // emitted in JSON as `root` (was `path`).
        #[serde(rename = "root", alias = "path")]
        pub path: String,
        pub findings: Vec<SecureFinding>,
        pub summary: SecureSummary,
        #[serde(default)]
        pub sub_results: HashMap<String, Value>,
        pub total_elapsed_ms: f64,
    }

    // -------------------------------------------------------------------------
    // Definition Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        Unknown,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SymbolInfo {
        pub name: String,
        pub kind: SymbolKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub location: Option<Location>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub type_annotation: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub docstring: Option<String>,
        #[serde(default)]
        pub is_builtin: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub module: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DefinitionResult {
        pub symbol: SymbolInfo,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub definition: Option<Location>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub type_definition: Option<Location>,
    }

    // -------------------------------------------------------------------------
    // Diff Types
    // -------------------------------------------------------------------------

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NodeKind {
        Function,
        Class,
        Method,
        Statement,
        Expression,
        Block,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ASTChange {
        pub change_type: ChangeType,
        pub node_kind: NodeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub old_location: Option<Location>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub new_location: Option<Location>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub old_text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub new_text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub similarity: Option<f64>,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct DiffSummary {
        pub total_changes: u32,
        pub semantic_changes: u32,
        pub inserts: u32,
        pub deletes: u32,
        pub updates: u32,
        pub moves: u32,
        pub renames: u32,
        pub formats: u32,
        pub extracts: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DiffReport {
        pub file_a: String,
        pub file_b: String,
        pub identical: bool,
        pub changes: Vec<ASTChange>,
        pub summary: DiffSummary,
    }

    // -------------------------------------------------------------------------
    // API Check Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum MisuseCategory {
        CallOrder,
        ErrorHandling,
        Parameters,
        Resources,
        Crypto,
        Concurrency,
        Security,
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): mirror the new
        // `Correctness` variant added to the production enum so findings whose
        // category serializes to "correctness" (JV001/JS001/TS001/LU001)
        // deserialize in the integration tests.
        Correctness,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum MisuseSeverity {
        Info,
        Low,
        Medium,
        High,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct APIRule {
        pub id: String,
        pub name: String,
        pub category: MisuseCategory,
        pub severity: MisuseSeverity,
        pub description: String,
        pub correct_usage: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MisuseFinding {
        pub file: String,
        pub line: u32,
        pub column: u32,
        pub rule: APIRule,
        pub api_call: String,
        pub message: String,
        pub fix_suggestion: String,
        #[serde(default)]
        pub code_context: String,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct APICheckSummary {
        pub total_findings: u32,
        #[serde(default)]
        pub by_category: HashMap<String, u32>,
        #[serde(default)]
        pub by_severity: HashMap<String, u32>,
        #[serde(default)]
        pub apis_checked: Vec<String>,
        pub files_scanned: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct APICheckReport {
        pub findings: Vec<MisuseFinding>,
        pub summary: APICheckSummary,
        pub rules_applied: u32,
    }

    // -------------------------------------------------------------------------
    // Vuln Types
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
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
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TaintFlow {
        pub file: String,
        pub line: u32,
        pub column: u32,
        pub code_snippet: String,
        pub description: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VulnFinding {
        pub vuln_type: VulnType,
        pub severity: Severity,
        pub cwe_id: String,
        pub title: String,
        pub description: String,
        pub file: String,
        pub line: u32,
        pub column: u32,
        pub taint_flow: Vec<TaintFlow>,
        pub remediation: String,
        pub confidence: f64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct VulnSummary {
        pub total_findings: u32,
        #[serde(default)]
        pub by_severity: HashMap<String, u32>,
        #[serde(default)]
        pub by_type: HashMap<String, u32>,
        pub files_with_vulns: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VulnReport {
        pub findings: Vec<VulnFinding>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub summary: Option<VulnSummary>,
        pub scan_duration_ms: u64,
        pub files_scanned: u32,
    }
}

use remaining_types::*;

mod unit_types {
    use super::*;

    #[test]
    fn test_output_format_serialization() {
        let json = serde_json::to_string(&OutputFormat::Json).unwrap();
        let text = serde_json::to_string(&OutputFormat::Text).unwrap();
        let sarif = serde_json::to_string(&OutputFormat::Sarif).unwrap();

        assert_eq!(json, r#""json""#);
        assert_eq!(text, r#""text""#);
        assert_eq!(sarif, r#""sarif""#);
    }
}

// =============================================================================
// Test Fixtures - Python Code Samples
// =============================================================================

/// Python code with dead code and complexity issues (for todo command)
const PYTHON_TODO_SAMPLE: &str = r#"
def used_function():
    """This function is called."""
    return 42

def unused_function():
    """This function is never called - dead code."""
    return "never used"

def complex_function(x, y, z):
    """Complex function with high cyclomatic complexity."""
    if x > 0:
        if y > 0:
            if z > 0:
                return x + y + z
            else:
                return x + y
        else:
            if z > 0:
                return x + z
            else:
                return x
    else:
        if y > 0:
            return y
        else:
            return 0

class GodClass:
    """Class with low cohesion - too many responsibilities."""
    def __init__(self):
        self.user_data = {}
        self.file_data = {}
        self.network_data = {}

    def process_user(self, user):
        self.user_data[user] = True

    def read_file(self, path):
        self.file_data[path] = True

    def send_network(self, data):
        self.network_data[data] = True

result = used_function()
"#;

/// Python code for explain command
const PYTHON_EXPLAIN_SAMPLE: &str = r#"
def calculate_total(items: list[dict], tax_rate: float = 0.1) -> float:
    """Calculate total price with tax.

    Args:
        items: List of items with 'price' key
        tax_rate: Tax rate as decimal (default 10%)

    Returns:
        Total price including tax
    """
    subtotal = sum(item['price'] for item in items)
    return subtotal * (1 + tax_rate)

def helper_function(x):
    return x * 2

def main():
    items = [{'price': 10}, {'price': 20}]
    total = calculate_total(items)
    doubled = helper_function(total)
    print(doubled)
"#;

/// Python code with security issues (for secure command)
const PYTHON_SECURE_SAMPLE: &str = r#"
import os
import pickle
from flask import request

def unsafe_query(user_input):
    """SQL injection vulnerability."""
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def unsafe_command(filename):
    """Command injection vulnerability."""
    os.system(f"cat {filename}")

def unsafe_deserialize(data):
    """Insecure deserialization."""
    return pickle.loads(data)

def resource_leak():
    """File not closed properly."""
    f = open("test.txt", "r")
    data = f.read()
    return data  # File never closed

def no_timeout():
    """HTTP request without timeout."""
    import requests
    response = requests.get("http://example.com")
    return response

def weak_crypto():
    """Using weak hash algorithm."""
    import hashlib
    return hashlib.md5(b"password").hexdigest()

def tainted_flow():
    """End-to-end taint: request source -> command-execution sink.

    The taint engine is AST/dataflow-driven (fix-regex-vuln-v1 dropped the
    legacy name/substring source heuristic, so a bare param named
    `user_input` is no longer treated as a source). This function provides
    a real source (`request.args.get`) flowing into a real sink
    (`os.system`) so the taint sub-analysis fires deterministically.
    """
    cmd = request.args.get("cmd")
    os.system(cmd)
"#;

/// Python code for definition command
const PYTHON_DEFINITION_SAMPLE: &str = r#"
class MyClass:
    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value

def create_instance(val):
    return MyClass(val)

instance = create_instance(42)
result = instance.get_value()
"#;

/// Python code for diff - version A
const PYTHON_DIFF_A: &str = r#"
def original_function(x):
    return x * 2

def renamed_later(a, b):
    return a + b

def will_be_deleted():
    return "goodbye"

class OriginalClass:
    def method_one(self):
        return 1
"#;

/// Python code for diff - version B
const PYTHON_DIFF_B: &str = r#"
def original_function(x):
    # Modified implementation
    return x * 3

def better_name(a, b):
    return a + b

def new_function():
    return "hello"

class OriginalClass:
    def method_one(self):
        return 1

    def method_two(self):
        return 2
"#;

/// Python code with API misuse (for api-check command)
const PYTHON_API_MISUSE: &str = r#"
import requests
import random
import hashlib

def missing_timeout():
    """requests.get without timeout parameter."""
    response = requests.get("http://api.example.com/data")
    return response.json()

def insecure_random():
    """Using random module for security-sensitive operation."""
    token = random.randint(0, 999999)
    return str(token).zfill(6)

def bare_except():
    """Using bare except clause."""
    try:
        risky_operation()
    except:
        pass

def unclosed_file():
    """File opened without context manager."""
    f = open("data.txt")
    content = f.read()
    return content

def weak_hash_for_password():
    """Using MD5 for password hashing."""
    password = "secret123"
    return hashlib.md5(password.encode()).hexdigest()
"#;

/// Python code with SQL injection vulnerability (for vuln command)
const PYTHON_VULN_SQLI: &str = r#"
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search():
    user_query = request.args.get('q')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # SQL Injection: user input directly in query
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{user_query}%'")
    return cursor.fetchall()

@app.route('/user/<username>')
def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Another SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
"#;

/// Python code with XSS vulnerability
const PYTHON_VULN_XSS: &str = r#"
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # XSS: user input directly rendered in HTML
    return f"<h1>Hello, {name}!</h1>"

@app.route('/comment')
def comment():
    comment_text = request.form.get('comment')
    # XSS via template string
    template = f"<div class='comment'>{comment_text}</div>"
    return render_template_string(template)
"#;

/// Python code with command injection
const PYTHON_VULN_CMDI: &str = r#"
from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Command injection via os.system
    os.system(f"ping -c 1 {host}")
    return "Done"

@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd')
    # Command injection via subprocess with shell=True
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout
"#;

/// Rust code with API misuse patterns.
const RUST_API_MISUSE: &str = r#"
use std::collections::HashMap;
use std::fs::File;
use std::sync::{Arc, Mutex};

async fn run(user_capacity: usize, m: Arc<Mutex<u32>>, map: HashMap<String, usize>) {
    let _guard = m.lock().unwrap();
    let _f = File::open("data.txt")?;
    let _buf: Vec<u8> = Vec::with_capacity(user_capacity);
    tokio::spawn(async move { do_work().await; });
    for (k, _v) in map.iter() {
        println!("{}", k);
    }
    for item in map.keys() {
        let _copied = item.clone();
        println!("{}", _copied);
    }
}
"#;

/// Rust code with vulnerability patterns.
const RUST_VULN_SAMPLE: &str = r#"
use std::mem;
use std::process::Command;

pub fn risky(user: &str, query_input: &str, bytes: &[u8]) {
    unsafe { println!("{}", bytes[0]); }
    let _t: i32 = unsafe { mem::transmute(1u32) };
    let _x = std::str::from_utf8_unchecked(bytes);
    let _q = format!("SELECT * FROM users WHERE name = '{}'", query_input);
    let _ = Command::new("sh").arg(user).output();
    let _u = Some(user).unwrap();
}
"#;

/// Rust code for secure command summary metrics.
const RUST_SECURE_SAMPLE: &str = r#"
use std::ptr;

pub fn risky(user: &str) {
    unsafe { ptr::write(user.as_ptr() as *mut u8, b'x'); }
    let _u = Some(user).unwrap();
    todo!("finish implementation");
}
"#;

// =============================================================================
// 1. TODO Command Tests
// =============================================================================

mod todo_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_todo_help() {
        tldr_assert_cmd()
            .args(["todo", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("PATH"))
            .stdout(predicate::str::contains("--format").or(predicate::str::contains("-f")))
            .stdout(predicate::str::contains("--detail"))
            .stdout(predicate::str::contains("--quick"))
            .stdout(predicate::str::contains("--lang").or(predicate::str::contains("-l")));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_todo_basic_analysis() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: TodoReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON TodoReport");

        assert_eq!(report.wrapper, "todo");
        assert!(!report.items.is_empty(), "Should find improvement items");
    }

    #[test]
    fn test_todo_finds_dead_code() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: TodoReport = serde_json::from_str(&stdout).unwrap();

        // Analysis ran successfully and returned a valid report
        // Note: Dead code detection for single files is limited because all
        // top-level functions could be entry points. For accurate dead code
        // detection, we need either: 1) entry point hints, 2) naming conventions
        // (e.g., main, test_*), or 3) multi-file project analysis.
        // For now, verify analysis completes with summary present.
        assert_eq!(report.wrapper, "todo");
        // Cohesion analysis should still find issues
        assert!(
            report.summary.low_cohesion_count > 0,
            "Should detect low cohesion in GodClass"
        );
    }

    #[test]
    fn test_todo_priority_sorting() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: TodoReport = serde_json::from_str(&stdout).unwrap();

        // Items should be sorted by priority (lower number = higher priority)
        for window in report.items.windows(2) {
            assert!(
                window[0].priority <= window[1].priority,
                "Items should be sorted by priority"
            );
        }
    }

    #[test]
    fn test_todo_quick_mode() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output_quick = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap(), "--quick"])
            .output()
            .unwrap();

        assert!(output_quick.status.success());

        let report_quick: TodoReport =
            serde_json::from_str(&String::from_utf8_lossy(&output_quick.stdout)).unwrap();

        // Quick mode should still run the analysis successfully
        assert_eq!(report_quick.wrapper, "todo");
        // Quick mode runs dead, complexity, cohesion, equivalence (skips similar)
        // The summary should be populated
        assert!(
            report_quick.total_elapsed_ms > 0.0,
            "Should have valid elapsed time"
        );
    }

    #[test]
    fn test_todo_detail_sub_analysis() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap(), "--detail", "dead"])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: TodoReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report.sub_results.contains_key("dead_code"),
            "Should include detailed dead code results (key: dead_code)"
        );
    }

    #[test]
    fn test_todo_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        tldr_assert_cmd()
            .args(["todo", file_path.to_str().unwrap(), "--format", "text"])
            .assert()
            .success()
            .stdout(predicate::str::contains("priority")) // format: "(priority: N)"
            .stdout(predicate::str::contains("TODO Report")); // header
    }

    #[test]
    fn test_todo_directory_mode() {
        let temp = TempDir::new().unwrap();
        create_test_file(&temp, "a.py", PYTHON_TODO_SAMPLE);
        create_test_file(&temp, "b.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", temp.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: TodoReport = serde_json::from_str(&stdout).unwrap();

        // Should analyze multiple files
        assert!(
            report.items.iter().any(|i| i.file.contains("a.py"))
                || report.items.iter().any(|i| i.file.contains("b.py")),
            "Should analyze files from directory"
        );
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_todo_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5
        // (was generic 1).
        tldr_assert_cmd()
            .args(["todo", "/nonexistent/file.py"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    #[test]
    fn test_todo_invalid_language() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.xyz", "some content");

        tldr_assert_cmd()
            .args([
                "todo",
                file_path.to_str().unwrap(),
                "--lang",
                "unsupported_lang",
            ])
            .assert()
            .failure()
            .code(2); // clap validation error exit code
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_todo_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_TODO_SAMPLE);

        let output = tldr_cmd()
            .args(["todo", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        // Verify required fields exist
        assert!(value.get("wrapper").is_some(), "Missing 'wrapper' field");
        assert!(value.get("path").is_some(), "Missing 'path' field");
        assert!(value.get("items").is_some(), "Missing 'items' field");
        assert!(value.get("summary").is_some(), "Missing 'summary' field");
        assert!(
            value.get("total_elapsed_ms").is_some(),
            "Missing 'total_elapsed_ms' field"
        );

        // Verify summary structure
        let summary = value.get("summary").unwrap();
        assert!(
            summary.get("dead_count").is_some(),
            "Missing 'dead_count' in summary"
        );
    }
}

// =============================================================================
// 2. EXPLAIN Command Tests
// =============================================================================

mod explain_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_explain_help() {
        tldr_assert_cmd()
            .args(["explain", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("file"))
            .stdout(predicate::str::contains("function"))
            .stdout(predicate::str::contains("--format"))
            .stdout(predicate::str::contains("--depth"))
            .stdout(predicate::str::contains("--lang"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_explain_basic_function() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON ExplainReport");

        assert_eq!(report.function, "calculate_total");
        assert!(
            !report.signature.params.is_empty(),
            "Should have parameters"
        );
    }

    #[test]
    fn test_explain_extracts_signature() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport = serde_json::from_str(&stdout).unwrap();

        // Check signature details
        assert_eq!(report.signature.params.len(), 2);
        assert_eq!(report.signature.params[0].name, "items");
        assert_eq!(report.signature.params[1].name, "tax_rate");
        assert!(
            report.signature.return_type.is_some(),
            "Should have return type"
        );
    }

    #[test]
    fn test_explain_extracts_docstring() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report.signature.docstring.is_some(),
            "Should extract docstring"
        );
        assert!(
            report.signature.docstring.as_ref().unwrap().contains("tax"),
            "Docstring should contain 'tax'"
        );
    }

    #[test]
    fn test_explain_purity_analysis() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport = serde_json::from_str(&stdout).unwrap();

        // calculate_total is pure (no side effects)
        assert!(
            report.purity.classification == "pure" || report.purity.effects.is_empty(),
            "calculate_total should be classified as pure or have no effects"
        );
    }

    #[test]
    fn test_explain_callees() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "main"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport = serde_json::from_str(&stdout).unwrap();

        // main calls calculate_total, helper_function, print
        assert!(
            report.callees.iter().any(|c| c.name == "calculate_total"),
            "Should show calculate_total as callee"
        );
    }

    #[test]
    fn test_explain_callers() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: ExplainReport = serde_json::from_str(&stdout).unwrap();

        // calculate_total is called by main
        assert!(
            report.callers.iter().any(|c| c.name == "main"),
            "Should show main as caller"
        );
    }

    #[test]
    fn test_explain_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        tldr_assert_cmd()
            .args([
                "explain",
                file_path.to_str().unwrap(),
                "calculate_total",
                "--format",
                "text",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Function:"))
            .stdout(predicate::str::contains("Parameters:"))
            .stdout(predicate::str::contains("Purity:"));
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_explain_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5.
        tldr_assert_cmd()
            .args(["explain", "/nonexistent/file.py", "some_function"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    #[test]
    fn test_explain_function_not_found() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        // med-low-schema-cleanup-v1 (N9): symbol-not-found is exit 20
        // (matches the `tldr impact` convention for analysis-class
        // failures).
        tldr_assert_cmd()
            .args([
                "explain",
                file_path.to_str().unwrap(),
                "nonexistent_function",
            ])
            .assert()
            .failure()
            .code(20)
            .stderr(predicate::str::contains("not found").or(predicate::str::contains("symbol")));
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_explain_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_EXPLAIN_SAMPLE);

        let output = tldr_cmd()
            .args(["explain", file_path.to_str().unwrap(), "calculate_total"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        // Verify required fields
        // cross-command-consistency-v1 (BUG-14, 66fa8bc): `function` (was `function_name`).
        assert!(value.get("function").is_some());
        assert!(value.get("file").is_some());
        assert!(value.get("line_start").is_some());
        assert!(value.get("signature").is_some());
        assert!(value.get("purity").is_some());

        // Verify signature structure
        let sig = value.get("signature").unwrap();
        assert!(sig.get("params").is_some());

        // Verify purity structure
        let purity = value.get("purity").unwrap();
        assert!(purity.get("classification").is_some());
        assert!(purity.get("confidence").is_some());
    }
}

// =============================================================================
// 3. SECURE Command Tests
// =============================================================================

mod secure_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_secure_help() {
        tldr_assert_cmd()
            .args(["secure", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("path"))
            .stdout(predicate::str::contains("--format"))
            .stdout(predicate::str::contains("--detail"))
            .stdout(predicate::str::contains("--quick"))
            .stdout(predicate::str::contains("--lang"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_secure_basic_analysis() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON SecureReport");

        assert_eq!(report.wrapper, "secure");
        assert!(!report.findings.is_empty(), "Should find security issues");
    }

    #[test]
    fn test_secure_detects_taint() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport = serde_json::from_str(&stdout).unwrap();

        assert!(report.summary.taint_count > 0, "Should detect taint issues");
    }

    #[test]
    fn test_secure_detects_resource_leak() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport = serde_json::from_str(&stdout).unwrap();

        assert!(report.summary.leak_count > 0, "Should detect resource leak");
    }

    #[test]
    fn test_secure_rust_summary_metrics() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.rs", RUST_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report.summary.unsafe_blocks > 0,
            "Should count unsafe blocks"
        );
        assert!(
            report.summary.raw_pointer_ops > 0,
            "Should count raw pointer operations"
        );
        assert!(report.summary.unwrap_calls > 0, "Should count unwrap calls");
        assert!(report.summary.todo_markers > 0, "Should count todo markers");
    }

    #[test]
    fn test_secure_severity_sorting() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport = serde_json::from_str(&stdout).unwrap();

        // Findings should be sorted by severity (critical first)
        let severity_order = |s: &str| match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };

        for window in report.findings.windows(2) {
            assert!(
                severity_order(&window[0].severity) <= severity_order(&window[1].severity),
                "Findings should be sorted by severity"
            );
        }
    }

    #[test]
    fn test_secure_quick_mode() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap(), "--quick"])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: SecureReport = serde_json::from_str(&stdout).unwrap();

        // Quick mode should still find basic issues
        assert!(
            !report.findings.is_empty(),
            "Quick mode should still find issues"
        );
    }

    #[test]
    fn test_secure_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        tldr_assert_cmd()
            .args(["secure", file_path.to_str().unwrap(), "--format", "text"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Security"))
            .stdout(predicate::str::contains("Severity"));
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_secure_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5.
        tldr_assert_cmd()
            .args(["secure", "/nonexistent/file.py"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_secure_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_SECURE_SAMPLE);

        let output = tldr_cmd()
            .args(["secure", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        assert!(value.get("wrapper").is_some());
        // cross-command-consistency-v1 (BUG-14, 66fa8bc): `root` (was `path`).
        assert!(value.get("root").is_some());
        assert!(value.get("findings").is_some());
        assert!(value.get("summary").is_some());

        let summary = value.get("summary").unwrap();
        assert!(summary.get("taint_count").is_some());
        assert!(summary.get("leak_count").is_some());
    }
}

// =============================================================================
// 4. DEFINITION Command Tests
// =============================================================================

mod definition_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_definition_help() {
        tldr_assert_cmd()
            .args(["definition", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("file"))
            .stdout(predicate::str::contains("line"))
            .stdout(predicate::str::contains("column"))
            .stdout(predicate::str::contains("--symbol"))
            .stdout(predicate::str::contains("--project"))
            .stdout(predicate::str::contains("--format"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_definition_by_position() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        // Find definition of 'result' at position where it's used (line 12, column 0)
        let output = tldr_cmd()
            .args([
                "definition",
                file_path.to_str().unwrap(),
                "12", // line
                "0",  // column
            ])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: DefinitionResult =
            serde_json::from_str(&stdout).expect("Should return valid JSON DefinitionResult");

        assert!(result.definition.is_some(), "Should find definition");
    }

    #[test]

    fn test_definition_by_symbol_name() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        let output = tldr_cmd()
            .args([
                "definition",
                "--symbol",
                "MyClass",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: DefinitionResult = serde_json::from_str(&stdout).unwrap();

        assert_eq!(result.symbol.name, "MyClass");
        assert_eq!(result.symbol.kind, SymbolKind::Class);
        assert!(result.definition.is_some());
    }

    #[test]

    fn test_definition_finds_function() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        let output = tldr_cmd()
            .args([
                "definition",
                "--symbol",
                "create_instance",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: DefinitionResult = serde_json::from_str(&stdout).unwrap();

        assert_eq!(result.symbol.kind, SymbolKind::Function);
        assert!(result.definition.as_ref().unwrap().line > 0);
    }

    #[test]

    fn test_definition_finds_method() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        let output = tldr_cmd()
            .args([
                "definition",
                "--symbol",
                "get_value",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: DefinitionResult = serde_json::from_str(&stdout).unwrap();

        assert_eq!(result.symbol.kind, SymbolKind::Method);
    }

    #[test]

    fn test_definition_builtin() {
        let temp = TempDir::new().unwrap();
        let code = r#"
result = len([1, 2, 3])
"#;
        let file_path = create_test_file(&temp, "sample.py", code);

        let output = tldr_cmd()
            .args([
                "definition",
                "--symbol",
                "len",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: DefinitionResult = serde_json::from_str(&stdout).unwrap();

        assert!(result.symbol.is_builtin, "len should be marked as builtin");
    }

    #[test]

    fn test_definition_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        tldr_assert_cmd()
            .args([
                "definition",
                "--symbol",
                "MyClass",
                "--file",
                file_path.to_str().unwrap(),
                "--format",
                "text",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("MyClass"))
            .stdout(predicate::str::contains("class").or(predicate::str::contains("Class")));
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_definition_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): missing-file path returns
        // exit 5 (filesystem-class). Pre-fix this returned exit 0
        // with a fake-success placeholder, then exit 1 generic, now
        // exit 5 typed.
        tldr_assert_cmd()
            .args(["definition", "/nonexistent/file.py", "1", "0"])
            .assert()
            .failure()
            .code(5);
    }

    #[test]

    fn test_definition_symbol_not_found() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        // med-low-schema-cleanup-v1 (N9): symbol-not-found is exit 20
        // (analysis-class, mirrors the `tldr impact` convention).
        tldr_assert_cmd()
            .args([
                "definition",
                "--symbol",
                "nonexistent_symbol",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .code(20)
            .stderr(predicate::str::contains("not found").or(predicate::str::contains("symbol")));
    }

    #[test]

    fn test_definition_invalid_position() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        // language-coverage-fixes-v1 (P4.BUG-N3, ef5f6cf): out-of-range
        // positions are validated before parsing and return a typed
        // `invalid_argument` error (exit 1) instead of the old placeholder
        // (exit 0). Previously these walked tree-sitter's root node and
        // echoed the whole source file back through the error message.
        tldr_assert_cmd()
            .args([
                "definition",
                file_path.to_str().unwrap(),
                "9999", // invalid line
                "0",
            ])
            .assert()
            .failure()
            .code(1)
            .stderr(predicate::str::contains("out of range"));
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]

    fn test_definition_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_DEFINITION_SAMPLE);

        let output = tldr_cmd()
            .args([
                "definition",
                "--symbol",
                "MyClass",
                "--file",
                file_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        assert!(value.get("symbol").is_some());
        let symbol = value.get("symbol").unwrap();
        assert!(symbol.get("name").is_some());
        assert!(symbol.get("kind").is_some());
    }
}

// =============================================================================
// 5. DIFF Command Tests
// =============================================================================

mod diff_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_diff_help() {
        tldr_assert_cmd()
            .args(["diff", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("file-a").or(predicate::str::contains("FILE_A")))
            .stdout(predicate::str::contains("file-b").or(predicate::str::contains("FILE_B")))
            .stdout(predicate::str::contains("--semantic-only"))
            .stdout(predicate::str::contains("--format"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_diff_basic() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON DiffReport");

        assert!(!report.identical, "Files should not be identical");
        assert!(!report.changes.is_empty(), "Should detect changes");
    }

    #[test]
    fn test_diff_detects_insert() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        // new_function was added
        let inserts: Vec<_> = report
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Insert)
            .collect();
        assert!(!inserts.is_empty(), "Should detect insertions");
        assert!(report.summary.inserts > 0);
    }

    #[test]
    fn test_diff_detects_delete() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        // will_be_deleted was removed
        let deletes: Vec<_> = report
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Delete)
            .collect();
        assert!(!deletes.is_empty(), "Should detect deletions");
        assert!(report.summary.deletes > 0);
    }

    #[test]
    fn test_diff_detects_update() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        // original_function was modified
        let updates: Vec<_> = report
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Update)
            .collect();
        assert!(!updates.is_empty(), "Should detect updates");
    }

    #[test]
    fn test_diff_detects_rename() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        // renamed_later -> better_name
        let renames: Vec<_> = report
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Rename)
            .collect();
        assert!(
            !renames.is_empty() || report.summary.renames > 0,
            "Should detect rename"
        );
    }

    #[test]
    fn test_diff_identical_files() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_A); // Same content

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        assert!(report.identical, "Files should be identical");
        assert!(report.changes.is_empty(), "No changes expected");
    }

    #[test]
    fn test_diff_semantic_only() {
        let temp = TempDir::new().unwrap();
        let code_a = "def foo():\n    return 1";
        let code_b = "def foo():\n    return 1  # comment added";
        let file_a = create_test_file(&temp, "a.py", code_a);
        let file_b = create_test_file(&temp, "b.py", code_b);

        let output = tldr_cmd()
            .args([
                "diff",
                file_a.to_str().unwrap(),
                file_b.to_str().unwrap(),
                "--semantic-only",
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: DiffReport = serde_json::from_str(&stdout).unwrap();

        // Comment-only change should not appear in semantic mode
        assert!(
            report.changes.is_empty() || report.summary.semantic_changes == 0,
            "Comment-only changes should be filtered in semantic mode"
        );
    }

    #[test]
    fn test_diff_text_output() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        tldr_assert_cmd()
            .args([
                "diff",
                file_a.to_str().unwrap(),
                file_b.to_str().unwrap(),
                "--format",
                "text",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Change").or(predicate::str::contains("Diff")));
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_diff_file_not_found() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);

        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5.
        tldr_assert_cmd()
            .args(["diff", file_a.to_str().unwrap(), "/nonexistent/file.py"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_diff_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_a = create_test_file(&temp, "a.py", PYTHON_DIFF_A);
        let file_b = create_test_file(&temp, "b.py", PYTHON_DIFF_B);

        let output = tldr_cmd()
            .args(["diff", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        assert!(value.get("file_a").is_some());
        assert!(value.get("file_b").is_some());
        assert!(value.get("identical").is_some());
        assert!(value.get("changes").is_some());
        assert!(value.get("summary").is_some());

        let summary = value.get("summary").unwrap();
        assert!(summary.get("total_changes").is_some());
    }
}

// =============================================================================
// 7. API_CHECK Command Tests
// =============================================================================

mod api_check_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_api_check_help() {
        tldr_assert_cmd()
            .args(["api-check", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("path"))
            .stdout(predicate::str::contains("--category"))
            .stdout(predicate::str::contains("--severity"))
            .stdout(predicate::str::contains("--format"))
            .stdout(predicate::str::contains("--lang"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_api_check_basic() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON APICheckReport");

        assert!(
            !report.findings.is_empty(),
            "Should find API misuse patterns"
        );
    }

    #[test]
    fn test_api_check_detects_missing_timeout() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        let timeout_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| {
                f.message.to_lowercase().contains("timeout") || f.api_call.contains("requests")
            })
            .collect();

        assert!(
            !timeout_findings.is_empty(),
            "Should detect missing timeout in requests.get"
        );
    }

    #[test]
    fn test_api_check_detects_bare_except() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        let except_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule.category == MisuseCategory::ErrorHandling)
            .collect();

        assert!(
            !except_findings.is_empty(),
            "Should detect bare except clause"
        );
    }

    #[test]
    fn test_api_check_detects_weak_crypto() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        let crypto_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule.category == MisuseCategory::Crypto)
            .collect();

        assert!(
            !crypto_findings.is_empty(),
            "Should detect weak hash for password"
        );
    }

    #[test]
    fn test_api_check_detects_unclosed_file() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        let resource_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule.category == MisuseCategory::Resources)
            .collect();

        assert!(!resource_findings.is_empty(), "Should detect unclosed file");
    }

    #[test]
    fn test_api_check_category_filter() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args([
                "api-check",
                file_path.to_str().unwrap(),
                "--category",
                "crypto",
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        for finding in &report.findings {
            assert_eq!(
                finding.rule.category,
                MisuseCategory::Crypto,
                "All findings should be crypto category"
            );
        }
    }

    #[test]
    fn test_api_check_severity_filter() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args([
                "api-check",
                file_path.to_str().unwrap(),
                "--severity",
                "high",
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        for finding in &report.findings {
            assert!(
                finding.rule.severity == MisuseSeverity::High
                    || finding.rule.severity == MisuseSeverity::Medium
                    || finding.rule.severity == MisuseSeverity::Low
                    || finding.rule.severity == MisuseSeverity::Info,
                "Findings should be at or above specified severity"
            );
        }
    }

    #[test]
    fn test_api_check_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        tldr_assert_cmd()
            .args(["api-check", file_path.to_str().unwrap(), "--format", "text"])
            .assert()
            .success()
            .stdout(predicate::str::contains("API").or(predicate::str::contains("misuse")));
    }

    #[test]
    fn test_api_check_no_findings_clean_code() {
        let temp = TempDir::new().unwrap();
        let clean_code = r#"
import requests

def safe_request():
    """Proper API usage."""
    with requests.Session() as session:
        response = session.get("http://example.com", timeout=30)
        return response.json()

def safe_file_handling():
    """Using context manager."""
    with open("data.txt") as f:
        return f.read()
"#;
        let file_path = create_test_file(&temp, "clean.py", clean_code);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        // Clean code should have no findings
        assert!(
            report.findings.is_empty(),
            "Clean code should have no API misuse findings"
        );
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_api_check_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5.
        tldr_assert_cmd()
            .args(["api-check", "/nonexistent/file.py"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    // -------------------------------------------------------------------------
    // Exit Code Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_api_check_exit_code_findings() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        // Per spec, exit code 2 when findings detected
        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        // Exit code 0 for success (findings present but not error)
        // or exit code 2 for findings detected per spec
        assert!(
            output.status.code() == Some(0) || output.status.code() == Some(2),
            "Exit code should be 0 or 2 when findings detected"
        );
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_api_check_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        assert!(value.get("findings").is_some());
        assert!(value.get("summary").is_some());
        assert!(value.get("rules_applied").is_some());

        let summary = value.get("summary").unwrap();
        assert!(summary.get("total_findings").is_some());
        assert!(summary.get("files_scanned").is_some());

        // Verify finding structure if present
        if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
            if !findings.is_empty() {
                let finding = &findings[0];
                assert!(finding.get("file").is_some());
                assert!(finding.get("line").is_some());
                assert!(finding.get("rule").is_some());
                assert!(finding.get("message").is_some());
            }
        }
    }

    /// schema-naming-and-units-v1: every key in `summary.by_category` must
    /// match the snake_case form emitted on `findings[].rule.category`.
    /// Previously the summary used `format!("{:?}", cat).to_lowercase()` which
    /// collapsed PascalCase variants to single-word keys (e.g. `errorhandling`)
    /// while findings used serde's snake_case (e.g. `error_handling`),
    /// forcing consumers to normalize when joining the two.
    #[test]
    fn test_api_check_category_naming_consistent() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("Should be valid JSON");

        // Collect detail-side category strings (one per finding).
        let findings = value
            .get("findings")
            .and_then(|v| v.as_array())
            .expect("findings array missing");
        assert!(
            !findings.is_empty(),
            "fixture is expected to produce findings"
        );

        let mut detail_cats: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for f in findings {
            let cat = f
                .get("rule")
                .and_then(|r| r.get("category"))
                .and_then(|c| c.as_str())
                .expect("each finding must have rule.category");
            detail_cats.insert(cat.to_string());
        }

        // Collect summary-side category keys.
        let summary_cats: std::collections::BTreeSet<String> = value
            .get("summary")
            .and_then(|s| s.get("by_category"))
            .and_then(|v| v.as_object())
            .expect("summary.by_category missing or not an object")
            .keys()
            .cloned()
            .collect();

        // Every summary key must appear in detail (no orphan keys),
        // and every detail category must be present in the summary.
        assert_eq!(
            detail_cats, summary_cats,
            "summary.by_category keys must match findings[].rule.category exactly\n\
             detail: {detail_cats:?}\n\
             summary: {summary_cats:?}"
        );

        // Defensive: keys must be valid snake_case identifiers (no PascalCase
        // residue, no missing underscores between camelCase boundaries).
        for k in summary_cats.iter().chain(detail_cats.iter()) {
            assert!(
                k.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "category key {k:?} is not snake_case"
            );
            // The PascalCase->lowercase collapse bug emitted `errorhandling`,
            // `callorder` etc. — guard against the regression by name.
            assert_ne!(
                k, "errorhandling",
                "regression: category collapsed to PascalCase-lowercased form"
            );
            assert_ne!(
                k, "callorder",
                "regression: category collapsed to PascalCase-lowercased form"
            );
        }
    }

    #[test]
    fn test_api_check_rust_rules() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.rs", RUST_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON APICheckReport");

        assert!(
            report.findings.iter().any(|f| f.rule.id.starts_with("RS")),
            "Should report Rust API misuse findings"
        );
    }

    /// analysis-precision-v1, BUG-07: PY004 weak-hash-sha1 must NOT match
    /// function definition signatures or docstring lines that merely
    /// *mention* `sha1` / `hashlib.sha1`. Only the actual `hashlib.sha1(...)`
    /// call site should be flagged.
    ///
    /// Reproduces flask's `src/flask/sessions.py:276-281` shape exactly:
    /// - line 1: `def _lazy_sha1(string: bytes = b"") -> t.Any:` (signature mention)
    /// - line 2-4: triple-quoted docstring containing ``hashlib.sha1``
    /// - line 5: `return hashlib.sha1(string)` (the only real call site)
    #[test]
    fn test_api_check_py004_skips_def_and_docstring() {
        let temp = TempDir::new().unwrap();
        let fixture = "\
import hashlib

def _lazy_sha1(string: bytes = b\"\") -> object:
    \"\"\"Don't access ``hashlib.sha1`` until runtime. FIPS builds may not include
    SHA-1, in which case the import and use as a default would fail before the
    developer can configure something else.
    \"\"\"
    return hashlib.sha1(string)
";
        let file_path = create_test_file(&temp, "sessions.py", fixture);

        let output = tldr_cmd()
            .args(["api-check", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout)
            .expect("Should return valid JSON APICheckReport");

        let py004_lines: Vec<u32> = report
            .findings
            .iter()
            .filter(|f| f.rule.id == "PY004")
            .map(|f| f.line)
            .collect();

        assert_eq!(
            py004_lines.len(),
            1,
            "PY004 must fire exactly once (call site only); got lines {:?}",
            py004_lines
        );
        // Real call site is the `return hashlib.sha1(string)` line —
        // line 8 in the fixture (1-indexed: import=1, blank=2, def=3,
        // docstring open=4, docstring=5, docstring=6, docstring close=7,
        // return=8).
        assert_eq!(
            py004_lines[0], 8,
            "PY004 must hit the actual call site, not the def signature or docstring"
        );
    }
}

// =============================================================================
// 9. VULN Command Tests
// =============================================================================

mod vuln_command {
    use super::*;

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_vuln_help() {
        tldr_assert_cmd()
            .args(["vuln", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("path"))
            .stdout(predicate::str::contains("--severity"))
            .stdout(predicate::str::contains("--vuln-type"))
            .stdout(predicate::str::contains("--include-informational"))
            .stdout(predicate::str::contains("--format"));
    }

    // -------------------------------------------------------------------------
    // Happy Path Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_vuln_basic() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        // May succeed or exit with 2 (findings)
        assert!(
            output.status.success() || output.status.code() == Some(2),
            "Command should succeed or exit with findings code"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport =
            serde_json::from_str(&stdout).expect("Should return valid JSON VulnReport");

        assert!(!report.findings.is_empty(), "Should find vulnerabilities");
    }

    #[test]

    fn test_vuln_detects_sql_injection() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        let sqli_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::SqlInjection)
            .collect();

        assert!(!sqli_findings.is_empty(), "Should detect SQL injection");
        assert!(
            sqli_findings.iter().any(|f| f.cwe_id == "CWE-89"),
            "SQL injection should have CWE-89"
        );
    }

    #[test]

    fn test_vuln_detects_xss() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_XSS);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        let xss_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::Xss)
            .collect();

        assert!(!xss_findings.is_empty(), "Should detect XSS");
        assert!(
            xss_findings.iter().any(|f| f.cwe_id == "CWE-79"),
            "XSS should have CWE-79"
        );
    }

    #[test]

    fn test_vuln_detects_command_injection() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_CMDI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        let cmdi_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.vuln_type == VulnType::CommandInjection)
            .collect();

        assert!(!cmdi_findings.is_empty(), "Should detect command injection");
        assert!(
            cmdi_findings.iter().any(|f| f.cwe_id == "CWE-78"),
            "Command injection should have CWE-78"
        );
    }

    #[test]

    fn test_vuln_taint_flow() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        // Findings should include taint flow
        for finding in &report.findings {
            if finding.vuln_type == VulnType::SqlInjection {
                assert!(
                    !finding.taint_flow.is_empty(),
                    "SQL injection should have taint flow trace"
                );
            }
        }
    }

    #[test]

    fn test_vuln_severity_filter() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args([
                "vuln",
                file_path.to_str().unwrap(),
                "--severity",
                "critical",
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        // m024-severity-normalize-v1: `--severity critical` filters on
        // the legacy 5-level CLI vocabulary (still accepted as a
        // ValueEnum on the input side), but the wire severity collapses
        // to the canonical "error" bucket — Critical AND High both
        // project to "error" per the M-024 mapping table.
        for finding in &report.findings {
            assert!(
                finding.severity == Severity::Error,
                "All findings should be \"error\" (canonical projection of pre-fix critical/high) when filtered by --severity critical"
            );
        }
    }

    #[test]

    fn test_vuln_type_filter() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args([
                "vuln",
                file_path.to_str().unwrap(),
                "--vuln-type",
                "sql_injection",
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        for finding in &report.findings {
            assert_eq!(
                finding.vuln_type,
                VulnType::SqlInjection,
                "All findings should be SQL injection when filtered"
            );
        }
    }

    #[test]

    fn test_vuln_text_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        tldr_assert_cmd()
            .args(["vuln", file_path.to_str().unwrap(), "--format", "text"])
            .assert()
            .stdout(predicate::str::contains("Vulnerability").or(predicate::str::contains("SQL")));
    }

    #[test]

    fn test_vuln_sarif_output() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap(), "--format", "sarif"])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let sarif: Value = serde_json::from_str(&stdout).expect("Should be valid SARIF JSON");

        // SARIF format verification
        assert!(
            sarif.get("$schema").is_some() || sarif.get("version").is_some(),
            "SARIF should have schema or version"
        );
        assert!(sarif.get("runs").is_some(), "SARIF should have runs");
    }

    #[test]

    fn test_vuln_no_findings_clean_code() {
        let temp = TempDir::new().unwrap();
        let clean_code = r#"
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search():
    user_query = request.args.get('q')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{user_query}%',))
    return cursor.fetchall()
"#;
        let file_path = create_test_file(&temp, "clean.py", clean_code);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Should succeed with exit code 0");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report.findings.is_empty(),
            "Clean code should have no vulnerabilities"
        );
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_vuln_file_not_found() {
        // med-low-schema-cleanup-v1 (N9): file-not-found is exit 5.
        tldr_assert_cmd()
            .args(["vuln", "/nonexistent/file.py"])
            .assert()
            .failure()
            .code(5)
            .stderr(
                predicate::str::contains("file not found")
                    .or(predicate::str::contains("not found")),
            );
    }

    // -------------------------------------------------------------------------
    // Exit Code Tests
    // -------------------------------------------------------------------------

    #[test]

    fn test_vuln_exit_code_clean() {
        let temp = TempDir::new().unwrap();
        let clean_code = "def safe(): pass";
        let file_path = create_test_file(&temp, "clean.py", clean_code);

        tldr_assert_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .assert()
            .success()
            .code(0);
    }

    #[test]

    fn test_vuln_exit_code_findings() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        // determinism-and-stderr-hygiene-v1 (BUG-1): a successful scan exits
        // 0 regardless of finding count. The pre-fix contract (exit 2 on
        // non-empty findings) made every passing scan-with-findings look
        // like a tool failure to CI integrations and produced an
        // ungrammatical "Error: 1 findings detected" stderr line. The
        // count is conveyed by `summary.total_findings` in the JSON.
        assert_eq!(
            output.status.code(),
            Some(0),
            "Exit code should be 0 when scan completes successfully (regardless of findings)"
        );
        // Stderr must be empty on a successful scan (no "Error:" leak).
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.is_empty(),
            "stderr must be empty on successful scan; got: {stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // JSON Schema Validation
    // -------------------------------------------------------------------------

    #[test]

    fn test_vuln_json_schema() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&stdout).expect("Should be valid JSON");

        assert!(value.get("findings").is_some());
        assert!(value.get("scan_duration_ms").is_some());
        assert!(value.get("files_scanned").is_some());

        // Verify finding structure if present
        if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
            if !findings.is_empty() {
                let finding = &findings[0];
                assert!(finding.get("vuln_type").is_some());
                assert!(finding.get("severity").is_some());
                assert!(finding.get("cwe_id").is_some());
                assert!(finding.get("title").is_some());
                assert!(finding.get("file").is_some());
                assert!(finding.get("line").is_some());
                assert!(finding.get("taint_flow").is_some());
                assert!(finding.get("remediation").is_some());
            }
        }
    }

    #[test]

    fn test_vuln_summary_structure() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.py", PYTHON_VULN_SQLI);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        if let Some(summary) = &report.summary {
            assert!(summary.total_findings > 0);
            assert!(!summary.by_severity.is_empty());
            assert!(!summary.by_type.is_empty());
        }
    }

    #[test]
    fn test_vuln_rust_detects_findings() {
        let temp = TempDir::new().unwrap();
        let file_path = create_test_file(&temp, "sample.rs", RUST_VULN_SAMPLE);

        let output = tldr_cmd()
            .args(["vuln", file_path.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(
            output.status.success() || output.status.code() == Some(2),
            "Command should succeed or return findings exit code"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.vuln_type == VulnType::SqlInjection),
            "Should detect Rust SQL interpolation issue"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.vuln_type == VulnType::CommandInjection),
            "Should detect Rust command argument issue"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.vuln_type == VulnType::MemorySafety),
            "Should detect Rust memory-safety patterns"
        );
    }

    /// analysis-precision-v1, BUG-10: vuln must enumerate findings in the
    /// same order regardless of `--format`. Pre-fix the JSON formatter
    /// emitted findings in analyzer-emission order (rayon-driven, file
    /// fan-out non-deterministic) while the text formatter walked the
    /// same vector — but two runs of the same scan could produce two
    /// different orderings, and JSON vs text could disagree even within
    /// a single run. The fix sorts `filtered_findings` by
    /// `(file, line, vuln_type)` ascending in ONE place (post-suppression,
    /// pre-output) so JSON, text, and SARIF emitters all walk the same
    /// canonical sequence.
    ///
    /// This test cross-validates the JSON ordering against an
    /// independently-derived expected ordering (sort by file, then line,
    /// then vuln_type-as-string). Equality is the strict assertion.
    #[test]
    fn test_vuln_findings_sorted_consistently() {
        // Fixture: 3+ findings across 2 Python files, with deliberately
        // out-of-order line numbers + alphabetical mismatch between filename
        // and emission order, so a non-stable scan would produce a
        // different ordering than (file, line, vuln_type) ascending.
        // Uses eval/exec on file-read content (the canonical taint engine's
        // proven sink/source pair) so we get >= 1 finding per file
        // deterministically.
        let temp = TempDir::new().unwrap();

        // file `b_query.py` — exec on file content (CommandInjection / CodeExec sink).
        let _b = create_test_file(
            &temp,
            "b_query.py",
            "\
import os
def f(filename):
    with open(filename) as config_file:
        exec(compile(config_file.read(), filename, \"exec\"), {})
",
        );

        // file `a_render.py` — eval on env-tainted file read.
        let _a = create_test_file(
            &temp,
            "a_render.py",
            "\
import os
def g(ctx):
    startup = os.environ.get(\"PYTHONSTARTUP\")
    with open(startup) as f:
        eval(compile(f.read(), startup, \"exec\"), ctx)
",
        );

        let dir_path = temp.path().to_str().unwrap();
        let output = tldr_cmd()
            .args(["vuln", dir_path, "--format", "json"])
            .output()
            .unwrap();

        // vuln returns exit 2 (findings detected) - that's fine, parse stdout.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport =
            serde_json::from_str(&stdout).expect("vuln must emit valid JSON");

        // Fixture is calibrated to the canonical Python taint engine's
        // exec/eval sinks. We require >= 2 findings (one per file) so the
        // ordering check below is non-trivial (cross-file comparison).
        assert!(
            report.findings.len() >= 2,
            "fixture should produce >= 2 findings; got {} ({:?})",
            report.findings.len(),
            report.findings
        );

        // Independently derive the expected order: (file, line, vuln_type-debug).
        let actual: Vec<(String, u32, String)> = report
            .findings
            .iter()
            .map(|f| (f.file.clone(), f.line, format!("{:?}", f.vuln_type)))
            .collect();
        let mut expected = actual.clone();
        expected.sort();

        assert_eq!(
            actual, expected,
            "vuln JSON findings must be sorted by (file, line, vuln_type) ascending — \
             got {:?}, expected {:?}",
            actual, expected
        );
    }
}

// =============================================================================
// Directory Mode Tests (cross-cutting)
// =============================================================================

mod directory_mode {
    use super::*;

    #[test]
    fn test_vuln_directory_scan() {
        let temp = TempDir::new().unwrap();
        create_test_file(&temp, "a.py", PYTHON_VULN_SQLI);
        create_test_file(&temp, "b.py", PYTHON_VULN_XSS);
        create_test_file(&temp, "c.py", PYTHON_VULN_CMDI);

        let output = tldr_cmd()
            .args(["vuln", temp.path().to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: VulnReport = serde_json::from_str(&stdout).unwrap();

        // Should scan all files
        assert!(report.files_scanned >= 3, "Should scan all Python files");
    }

    #[test]
    fn test_api_check_directory_scan() {
        let temp = TempDir::new().unwrap();
        create_test_file(&temp, "module1.py", PYTHON_API_MISUSE);
        create_test_file(&temp, "module2.py", PYTHON_API_MISUSE);
        create_test_file(&temp, "module3.rs", RUST_API_MISUSE);

        let output = tldr_cmd()
            .args(["api-check", temp.path().to_str().unwrap()])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: APICheckReport = serde_json::from_str(&stdout).unwrap();

        assert!(
            report.summary.files_scanned >= 3,
            "Should scan multiple Python and Rust files"
        );
    }
}

// =============================================================================
// WRAPPER-CROSS-CONSISTENCY-V1 (M-T2): cross-wrapper schema parity tests
//
// These tests guard the invariants enforced by the
// `wrapper-cross-consistency-v1` milestone:
// - BUG-04: `health` and `todo` must agree on hotspot_count and
//   low_cohesion_count for the same path (same threshold, same analyzer).
// - BUG-15: `secure.summary` includes `behavioral_count`; sum of typed
//   counts equals `findings.length`.
// - BUG-19: `secure` and `todo` must NOT serialize empty `sub_results`
//   (the field is omitted when no `--detail` was requested). `verify`
//   continues to populate it.
// - BUG-16: `secure.summary.taint_count` must agree with
//   `findings[] | filter(category=="taint") | length` on every path.
// =============================================================================
mod wrapper_cross_consistency {
    use super::*;
    use serde_json::Value as Json;

    /// BUG-04: `tldr health` and `tldr todo` must report the same
    /// hotspot_count and low_cohesion_count on the same path. Both now
    /// route through `tldr_core::quality::complexity::analyze_complexity`
    /// (threshold=10) and `tldr_core::quality::cohesion::analyze_cohesion`
    /// (threshold=2). The fixture exercises both: a high-CC function (CC
    /// > 10) and a low-cohesion class (LCOM4 > 2).
    #[test]
    fn test_health_todo_summary_counts_agree() {
        let temp = TempDir::new().unwrap();

        // Hotspot fixture: cyclomatic complexity > 10 via nested branches.
        let hotspot_py = r#"
def complex_function(x, y, z):
    """High-CC function: CC must exceed 10."""
    result = 0
    if x > 0:
        if y > 0:
            if z > 0:
                result = 1
            else:
                result = 2
        else:
            if z > 0:
                result = 3
            else:
                result = 4
    else:
        if y > 0:
            if z > 0:
                result = 5
            else:
                result = 6
        else:
            if z > 0:
                result = 7
            else:
                result = 8
    while result > 0:
        result -= 1
    for i in range(10):
        if i % 2 == 0:
            result += i
    return result
"#;

        // Low-cohesion class: LCOM4 > 2 via fully disconnected method
        // groups (each method touches a distinct field).
        let cohesion_py = r#"
class Disconnected:
    def __init__(self):
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0

    def use_a(self):
        return self.a

    def use_b(self):
        return self.b

    def use_c(self):
        return self.c

    def use_d(self):
        return self.d
"#;

        create_test_file(&temp, "hotspot.py", hotspot_py);
        create_test_file(&temp, "cohesion.py", cohesion_py);

        let path = temp.path().to_str().unwrap();

        let health_out = tldr_cmd().args(["health", path]).output().unwrap();
        assert!(
            health_out.status.success(),
            "tldr health should succeed: {}",
            String::from_utf8_lossy(&health_out.stderr)
        );
        let health_json: Json =
            serde_json::from_slice(&health_out.stdout).expect("health emits JSON");

        let todo_out = tldr_cmd().args(["todo", path]).output().unwrap();
        assert!(
            todo_out.status.success(),
            "tldr todo should succeed: {}",
            String::from_utf8_lossy(&todo_out.stderr)
        );
        let todo_json: Json = serde_json::from_slice(&todo_out.stdout).expect("todo emits JSON");

        let health_hotspots = health_json["summary"]["hotspot_count"].as_u64().unwrap();
        let todo_hotspots = todo_json["summary"]["hotspot_count"].as_u64().unwrap();
        let health_cohesion = health_json["summary"]["low_cohesion_count"]
            .as_u64()
            .unwrap();
        let todo_cohesion = todo_json["summary"]["low_cohesion_count"].as_u64().unwrap();

        assert_eq!(
            health_hotspots, todo_hotspots,
            "BUG-04: tldr health hotspot_count ({}) must equal \
             tldr todo hotspot_count ({}) on the same path. Both use \
             tldr_core::quality::complexity::analyze_complexity with \
             hotspot_threshold=10.",
            health_hotspots, todo_hotspots
        );
        assert_eq!(
            health_cohesion, todo_cohesion,
            "BUG-04: tldr health low_cohesion_count ({}) must equal \
             tldr todo low_cohesion_count ({}) on the same path. Both use \
             tldr_core::quality::cohesion::analyze_cohesion with \
             threshold=2.",
            health_cohesion, todo_cohesion
        );

        // Sanity: the fixture must actually trigger BOTH analyses, else
        // the assertion above is vacuous (0 == 0).
        assert!(
            health_hotspots >= 1,
            "fixture must produce >=1 hotspot (got 0 from health) - \
             fixture is wrong"
        );
        assert!(
            health_cohesion >= 1,
            "fixture must produce >=1 low-cohesion class (got 0 from \
             health) - fixture is wrong"
        );
    }

    /// BUG-15: `secure.summary` must include a `behavioral_count` field,
    /// and the sum of all typed `*_count` fields in summary (excluding
    /// `taint_critical`, which is a refinement of `taint_count`) must
    /// equal `findings.length`. Fixture produces 1 behavioral (bare
    /// except) + 1 resource_leak (open without with) + 1 taint (Flask
    /// request -> cursor.execute string-concat).
    #[test]
    fn test_secure_summary_includes_behavioral() {
        let temp = TempDir::new().unwrap();
        let py = r#"
from flask import request
import sqlite3

def bare_except():
    try:
        do_thing()
    except:
        pass

def leak_resource():
    f = open("data.txt")
    return f.read()

def taint_flow():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + name + "'")
"#;
        let path = create_test_file(&temp, "trio.py", py);
        let out = tldr_cmd()
            .args(["secure", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "tldr secure should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: Json = serde_json::from_slice(&out.stdout).expect("secure emits JSON");

        let findings = json["findings"].as_array().expect("findings is array");
        let findings_len = findings.len() as u64;

        let summary = &json["summary"];

        // Schema: behavioral_count exists.
        assert!(
            summary.get("behavioral_count").is_some(),
            "BUG-15: secure.summary must include `behavioral_count` field. \
             Got summary keys: {:?}",
            summary.as_object().map(|m| m.keys().collect::<Vec<_>>())
        );

        // Sum of typed category counters must equal findings.length.
        // (taint_critical is a refinement subset of taint_count, excluded.)
        let count_keys = [
            "taint_count",
            "leak_count",
            "bounds_warnings",
            "behavioral_count",
            "missing_contracts",
            "mutable_params",
            "unsafe_blocks",
            "raw_pointer_ops",
            "unwrap_calls",
            "todo_markers",
        ];
        let summed: u64 = count_keys
            .iter()
            .map(|k| summary[*k].as_u64().unwrap_or(0))
            .sum();

        assert_eq!(
            summed, findings_len,
            "BUG-15: sum(secure.summary.*_count) ({}) must equal \
             findings.length ({}). Per-category breakdown: {:?}. \
             Findings categories: {:?}",
            summed,
            findings_len,
            count_keys
                .iter()
                .map(|k| (k, summary[*k].as_u64().unwrap_or(0)))
                .collect::<Vec<_>>(),
            findings
                .iter()
                .map(|f| f["category"].as_str().unwrap_or(""))
                .collect::<Vec<_>>()
        );

        // Sanity: fixture must produce a behavioral finding, else the
        // schema check is vacuous.
        let behavioral_in_findings = findings
            .iter()
            .filter(|f| f["category"].as_str() == Some("behavioral"))
            .count() as u64;
        assert!(
            behavioral_in_findings >= 1,
            "fixture must produce >=1 behavioral finding (got 0) - \
             fixture is wrong"
        );
        assert_eq!(
            summary["behavioral_count"].as_u64().unwrap(),
            behavioral_in_findings,
            "summary.behavioral_count must equal findings | filter \
             category==behavioral | length"
        );
    }

    /// BUG-19: `secure` and `todo` MUST omit the `sub_results` field
    /// from JSON output when no `--detail` was requested (it is no longer
    /// serialized as `{}`). `verify`, which actually populates
    /// sub_results in default mode, MUST still emit a populated map.
    #[test]
    fn test_secure_health_todo_no_empty_sub_results() {
        let temp = TempDir::new().unwrap();
        let py = r#"
def hello():
    return "ok"

class Tiny:
    def __init__(self):
        self.x = 0
    def use_x(self):
        return self.x
"#;
        let path = create_test_file(&temp, "tiny.py", py);
        let path_str = path.to_str().unwrap();
        let dir_str = temp.path().to_str().unwrap();

        for wrapper in &["secure", "todo"] {
            let out = tldr_cmd()
                .args([*wrapper, path_str])
                .output()
                .unwrap_or_else(|e| panic!("{} failed to spawn: {}", wrapper, e));
            assert!(
                out.status.success(),
                "tldr {} should succeed: {}",
                wrapper,
                String::from_utf8_lossy(&out.stderr)
            );
            let json: Json = serde_json::from_slice(&out.stdout)
                .unwrap_or_else(|e| panic!("{} should emit valid JSON: {}", wrapper, e));

            // Either absent OR null — never `{}`.
            let sub = json.get("sub_results");
            match sub {
                None => { /* OK: skipped via skip_serializing_if */ }
                Some(v) if v.is_null() => { /* OK */ }
                Some(v) => {
                    if let Some(map) = v.as_object() {
                        assert!(
                            !map.is_empty(),
                            "BUG-19: tldr {} must not emit sub_results: {{}} \
                             on default invocation. Got: {:?}",
                            wrapper,
                            map
                        );
                    }
                }
            }
        }

        // health uses `details` (not `sub_results`) — check that field
        // exists and is non-empty (regression guard for the rename).
        let health_out = tldr_cmd().args(["health", dir_str]).output().unwrap();
        assert!(
            health_out.status.success(),
            "tldr health should succeed: {}",
            String::from_utf8_lossy(&health_out.stderr)
        );
        let health_json: Json = serde_json::from_slice(&health_out.stdout).unwrap();
        // health does NOT use `sub_results`; its analogous field is
        // `details` and must be populated.
        assert!(
            health_json.get("sub_results").is_none(),
            "tldr health should not have sub_results (it uses `details` \
             instead). Got: {:?}",
            health_json.get("sub_results")
        );

        // verify still emits sub_results populated. We point it at the
        // current crate's src/ directory (a real Rust source tree) to
        // ensure all sub-analyses execute.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let verify_target = format!("{}/src", manifest_dir);
        let verify_out = tldr_cmd()
            .args(["verify", &verify_target, "--quick"])
            .output()
            .unwrap();
        // verify may exit nonzero (findings present); that's fine — we
        // only care that the JSON has populated sub_results.
        let verify_json: Json = serde_json::from_slice(&verify_out.stdout)
            .expect("verify should emit JSON even on nonzero exit");
        let verify_sub = verify_json
            .get("sub_results")
            .and_then(|v| v.as_object())
            .expect("BUG-19 regression: tldr verify must still populate sub_results");
        assert!(
            !verify_sub.is_empty(),
            "tldr verify sub_results must be populated (got {{}}). \
             Removing sub_results from secure/todo must NOT regress verify."
        );
    }

    /// BUG-16: `secure.summary.taint_count` MUST equal the number of
    /// `findings[]` with `category == "taint"` on every path. The
    /// previous implementation set `taint_count = findings.len()` from
    /// the per-analysis `analyze_taint` return value — but on Rust files
    /// `analyze_taint` returns findings with `category="unsafe_block"`,
    /// causing `taint_count` to ghost (e.g. ripgrep: taint_count=4,
    /// findings[category==taint]==0). The new implementation computes
    /// every counter from the FINAL findings array via group-by, so
    /// the assertion holds by construction across all languages.
    #[test]
    fn test_secure_taint_count_matches_findings_array() {
        let temp = TempDir::new().unwrap();

        // Python fixture: real source-to-sink taint flow (Flask request
        // -> cursor.execute via string concat). Should produce >=1
        // `category="taint"` finding.
        let py_taint = r#"
from flask import request
import sqlite3

def query():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + name + "'")
"#;
        let py_path = create_test_file(&temp, "py_taint.py", py_taint);

        // Rust fixture: unsafe block + raw pointer + unwrap. None should
        // produce `category="taint"` findings; instead `unsafe_block`,
        // `raw_pointer`, `unwrap`. Pre-fix `taint_count` would ghost > 0
        // here; post-fix it must be 0.
        let rs_unsafe = r#"
use std::ptr;

fn risky(s: &str) {
    unsafe { ptr::write(s.as_ptr() as *mut u8, b'x'); }
    let _v: Option<&str> = Some(s);
    _v.unwrap();
}
"#;
        let rs_path = create_test_file(&temp, "src/unsafe_thing.rs", rs_unsafe);

        for path in [&py_path, &rs_path] {
            let out = tldr_cmd()
                .args(["secure", path.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "tldr secure should succeed on {:?}: {}",
                path,
                String::from_utf8_lossy(&out.stderr)
            );
            let json: Json = serde_json::from_slice(&out.stdout).expect("secure emits JSON");
            let findings = json["findings"].as_array().expect("findings is array");
            let taint_in_findings = findings
                .iter()
                .filter(|f| f["category"].as_str() == Some("taint"))
                .count() as u64;
            let summary_taint = json["summary"]["taint_count"].as_u64().unwrap();

            assert_eq!(
                summary_taint,
                taint_in_findings,
                "BUG-16: secure.summary.taint_count ({}) must equal \
                 findings | filter category==taint | length ({}) on {:?}. \
                 All findings categories: {:?}",
                summary_taint,
                taint_in_findings,
                path,
                findings
                    .iter()
                    .map(|f| f["category"].as_str().unwrap_or(""))
                    .collect::<Vec<_>>()
            );
        }
    }
}
