//! Security Module Integration Tests
//!
//! Tests for security analysis modules:
//! - secrets: Hardcoded secret detection
//! - taint: Taint analysis for vulnerability detection
//! - vuln: Vulnerability scanning via taint flow
//! - ast_utils: AST utility functions for security analysis

use std::collections::{HashMap, HashSet};
use tempfile::TempDir;

// Security module imports
use tldr_core::security::ast_utils::{assignment_node_kinds, call_node_kinds, string_node_kinds};
use tldr_core::security::taint::{
    build_line_to_block, build_predecessors, build_successors, compute_taint, detect_sources,
    validate_cfg, SanitizerType, TaintInfo, TaintSink, TaintSinkType, TaintSourceType,
};
use tldr_core::security::{
    scan_secrets, scan_vulnerabilities, Severity as SecretSeverity, VulnType,
};
use tldr_core::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};
use tldr_core::Language;

// =============================================================================
// Test Fixtures
// =============================================================================

fn create_test_cfg() -> CfgInfo {
    CfgInfo {
        function: "test_func".to_string(),
        blocks: vec![
            CfgBlock {
                id: 0,
                block_type: BlockType::Entry,
                lines: (1, 3),
                calls: vec![],
            },
            CfgBlock {
                id: 1,
                block_type: BlockType::Body,
                lines: (4, 6),
                calls: vec![],
            },
            CfgBlock {
                id: 2,
                block_type: BlockType::Exit,
                lines: (7, 8),
                calls: vec![],
            },
        ],
        edges: vec![
            CfgEdge {
                from: 0,
                to: 1,
                edge_type: EdgeType::Unconditional,
                condition: None,
            },
            CfgEdge {
                from: 1,
                to: 2,
                edge_type: EdgeType::Unconditional,
                condition: None,
            },
        ],
        entry_block: 0,
        exit_blocks: vec![2],
        cyclomatic_complexity: 1,
        nested_functions: HashMap::new(),
    }
}

fn make_def(name: &str, line: u32) -> VarRef {
    VarRef {
        name: name.to_string(),
        ref_type: RefType::Definition,
        line,
        column: 0,
        context: None,
        group_id: None,
    }
}

fn make_use(name: &str, line: u32) -> VarRef {
    VarRef {
        name: name.to_string(),
        ref_type: RefType::Use,
        line,
        column: 0,
        context: None,
        group_id: None,
    }
}

// =============================================================================
// Secrets Module Tests
// =============================================================================

#[test]
fn test_secrets_scan_empty_directory() {
    let temp_dir = TempDir::new().unwrap();
    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.findings.len(), 0);
}

#[test]
fn test_secrets_scan_aws_key() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("config.py");

    std::fs::write(
        &test_file,
        r#"
# AWS Configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#,
    )
    .unwrap();

    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect at least the AWS key
    let aws_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "AWS Access Key" || f.pattern == "AWS Secret Key")
        .collect();

    assert!(!aws_findings.is_empty(), "Should detect AWS keys");
}

#[test]
#[ignore = "BUG: .pem is not in scan_secrets' scanned-extension allowlist, so this file is never walked"]
fn test_secrets_scan_private_key() {
    // BUG DOCUMENTATION (verified against secrets.rs): the regex itself matches
    // "-----BEGIN RSA PRIVATE KEY-----" fine. The real bug is that scan_secrets'
    // directory walk filters by extension, and "pem" is absent from that
    // allowlist, so this fixture is skipped before the regex ever runs.
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("private.pem");

    std::fs::write(
        &test_file,
        r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MQ0sL52/luJ1LhJv
-----END RSA PRIVATE KEY-----
"#,
    )
    .unwrap();

    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();

    let key_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "Private Key")
        .collect();

    // Document actual behavior - may not detect
    println!("Found {} private key findings", key_findings.len());
}

#[test]
fn test_secrets_scan_github_token() {
    let temp_dir = TempDir::new().unwrap();
    // why: ".txt" is not in scan_secrets' scanned-extension allowlist, so a
    // file with that extension is skipped before the regex ever runs. Use
    // ".env", which is allowlisted, so the assertion below tests the real
    // detection path instead of a file that is silently never scanned.
    let test_file = temp_dir.path().join("tokens.env");

    std::fs::write(
        &test_file,
        r#"
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"#,
    )
    .unwrap();

    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();

    let token_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "GitHub Token")
        .collect();

    assert!(!token_findings.is_empty(), "Should detect GitHub token");
}

#[test]
fn test_secrets_scan_password_assignment() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("config.env");

    std::fs::write(
        &test_file,
        r#"
DB_PASSWORD = "super_secret_password_123"
API_KEY = "sk-abcdefghijklmnop"
"#,
    )
    .unwrap();

    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect password
    let pwd_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "Password")
        .collect();

    assert!(
        !pwd_findings.is_empty(),
        "Should detect password assignment"
    );
}

#[test]
#[ignore = "BUG: Rust's Path::extension() returns None for dotfiles like \".env\", so this fixture is never scanned"]
fn test_secrets_scan_database_url() {
    // BUG DOCUMENTATION (verified against secrets.rs): the regex itself matches
    // "postgres://user:password@" fine. The real bug is that the fixture is
    // named ".env" and `Path::extension()` returns `None` for a filename that
    // *begins* with a dot and has no other dot in it, so the extension
    // allowlist filter drops this file before the regex ever runs.
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join(".env");

    std::fs::write(
        &test_file,
        r#"
DATABASE_URL=postgres://user:password@localhost:5432/mydb
"#,
    )
    .unwrap();

    let result = scan_secrets(temp_dir.path(), 4.5, false, None);

    assert!(result.is_ok());
    let report = result.unwrap();

    let db_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.pattern == "Database URL")
        .collect();

    // Document actual behavior - may not detect
    println!("Found {} database URL findings", db_findings.len());
}

#[test]
fn test_secrets_scan_with_severity_filter() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("mixed.txt");

    std::fs::write(
        &test_file,
        r#"
# Critical: AWS Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
# Medium: JWT
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
"#,
    )
    .unwrap();

    // Filter for critical only
    let result = scan_secrets(temp_dir.path(), 4.5, false, Some(SecretSeverity::Critical));

    assert!(result.is_ok());
    let report = result.unwrap();

    // Should only have critical findings
    for finding in &report.findings {
        assert!(
            finding.severity >= SecretSeverity::Critical,
            "Should only have Critical or higher severity"
        );
    }
}

#[test]
fn test_secrets_severity_ordering() {
    assert!(SecretSeverity::Critical > SecretSeverity::High);
    assert!(SecretSeverity::High > SecretSeverity::Medium);
    assert!(SecretSeverity::Medium > SecretSeverity::Low);
}

// =============================================================================
// Taint Analysis Tests
// =============================================================================

#[test]
fn test_taint_source_type_variants() {
    // Verify all expected variants exist
    let _variants = [
        TaintSourceType::UserInput,
        TaintSourceType::Stdin,
        TaintSourceType::HttpParam,
        TaintSourceType::HttpBody,
        TaintSourceType::EnvVar,
        TaintSourceType::FileRead,
    ];
}

#[test]
fn test_taint_sink_type_variants() {
    let _variants = [
        TaintSinkType::SqlQuery,
        TaintSinkType::CodeEval,
        TaintSinkType::CodeExec,
        TaintSinkType::CodeCompile,
        TaintSinkType::ShellExec,
        TaintSinkType::FileWrite,
    ];
}

#[test]
fn test_taint_info_new() {
    let info = TaintInfo::new("test_function");

    assert_eq!(info.function_name, "test_function");
    assert!(info.tainted_vars.is_empty());
    assert!(info.sources.is_empty());
    assert!(info.sinks.is_empty());
    assert!(info.flows.is_empty());
    assert!(info.sanitized_vars.is_empty());
}

#[test]
fn test_taint_info_is_tainted() {
    let mut info = TaintInfo::new("test");
    let mut block_vars = HashSet::new();
    block_vars.insert("user_input".to_string());
    info.tainted_vars.insert(0, block_vars);

    assert!(info.is_tainted(0, "user_input"));
    assert!(!info.is_tainted(0, "other_var"));
    assert!(!info.is_tainted(1, "user_input")); // Block doesn't exist
}

#[test]
fn test_taint_info_get_vulnerabilities() {
    let mut info = TaintInfo::new("test");

    // Add tainted sink (vulnerability)
    info.sinks.push(TaintSink {
        var: "query".to_string(),
        line: 5,
        sink_type: TaintSinkType::SqlQuery,
        tainted: true,
        statement: Some("cursor.execute(query)".to_string()),
    });

    // Add safe sink
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
// sanitizer-removal-v1 M4 (ATOMIC): three Python `test_detect_sanitizer_*`
// tests deleted (`_python_int`, `_python_shlex`, `_python_html_escape`).
// They asserted directly on the regex bank via `detect_sanitizer`. The
// regex bank is now empty; AST-based dispatch via `compute_taint_with_tree`
// covers the same fixtures and is exercised by
// `test_compute_taint_sanitizer_removes_taint` (~L509).

// =============================================================================
// CFG Helper Tests
// =============================================================================

#[test]
fn test_build_predecessors() {
    let cfg = create_test_cfg();
    let preds = build_predecessors(&cfg);

    assert_eq!(preds.get(&0).unwrap().len(), 0); // Entry has no predecessors
    assert_eq!(preds.get(&1).unwrap(), &vec![0]);
    assert_eq!(preds.get(&2).unwrap(), &vec![1]);
}

#[test]
fn test_build_successors() {
    let cfg = create_test_cfg();
    let succs = build_successors(&cfg);

    assert_eq!(succs.get(&0).unwrap(), &vec![1]);
    assert_eq!(succs.get(&1).unwrap(), &vec![2]);
    assert_eq!(succs.get(&2).unwrap().len(), 0); // Exit has no successors
}

#[test]
fn test_build_line_to_block() {
    let cfg = create_test_cfg();
    let mapping = build_line_to_block(&cfg);

    // Line 1 should be in block 0 (lines 1-3)
    assert_eq!(mapping.get(&1), Some(&0));
    // Line 5 should be in block 1 (lines 4-6)
    assert_eq!(mapping.get(&5), Some(&1));
    // Line 7 should be in block 2 (lines 7-8)
    assert_eq!(mapping.get(&7), Some(&2));
}

#[test]
fn test_validate_cfg_valid() {
    let cfg = create_test_cfg();

    assert!(validate_cfg(&cfg).is_ok());
}

#[test]
fn test_validate_cfg_empty_blocks() {
    let cfg = CfgInfo {
        function: "empty".to_string(),
        blocks: vec![],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![],
        cyclomatic_complexity: 0,
        nested_functions: HashMap::new(),
    };

    let result = validate_cfg(&cfg);
    assert!(result.is_err());
}

#[test]
fn test_validate_cfg_invalid_entry() {
    let mut cfg = create_test_cfg();
    cfg.entry_block = 999; // Invalid entry

    let result = validate_cfg(&cfg);
    assert!(result.is_err());
}

#[test]
fn test_validate_cfg_invalid_edge() {
    let mut cfg = create_test_cfg();
    cfg.edges.push(CfgEdge {
        from: 999, // Invalid source
        to: 1,
        edge_type: EdgeType::Unconditional,
        condition: None,
    });

    let result = validate_cfg(&cfg);
    assert!(result.is_err());
}

// =============================================================================
// Taint Propagation Tests
// =============================================================================

#[test]
fn test_compute_taint_simple_propagation() {
    let cfg = create_test_cfg();
    let refs = vec![make_def("x", 1), make_use("x", 4), make_def("y", 4)];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(4, "y = x".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python);

    assert!(result.is_ok());
    let taint_info = result.unwrap();

    // x should be tainted at block 0
    assert!(taint_info.is_tainted(0, "x"));
}

#[test]
fn test_compute_taint_sanitizer_removes_taint() {
    let cfg = create_test_cfg();
    let refs = vec![
        make_def("user_id", 1),
        make_use("user_id", 4),
        make_def("safe_id", 4),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "user_id = request.args.get('id')".to_string());
    statements.insert(4, "safe_id = int(user_id)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python);

    assert!(result.is_ok());
    let taint_info = result.unwrap();

    // safe_id should be in sanitized_vars
    assert!(taint_info.sanitized_vars.contains("safe_id"));
}

#[test]
fn test_compute_taint_no_sources() {
    let cfg = create_test_cfg();
    let refs = vec![make_def("x", 1), make_def("y", 4)];

    let mut statements = HashMap::new();
    statements.insert(1, "x = 42".to_string()); // Constant, not a source
    statements.insert(4, "y = x + 1".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python);

    assert!(result.is_ok());
    let taint_info = result.unwrap();

    // Should have no sources
    assert!(taint_info.sources.is_empty());
}

// =============================================================================
// Vulnerability Scanner Tests
// =============================================================================

#[test]
fn test_scan_vulnerabilities_empty() {
    let temp_dir = TempDir::new().unwrap();
    let result = scan_vulnerabilities(temp_dir.path(), None, None);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.findings.len(), 0);
}

#[test]
fn test_scan_vulnerabilities_sql_injection() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("db.py");

    std::fs::write(
        &test_file,
        r#"
from flask import request

def get_user():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"#,
    )
    .unwrap();

    let result = scan_vulnerabilities(temp_dir.path(), Some(Language::Python), None);

    assert!(result.is_ok());
    let report = result.unwrap();

    // why: the old test filtered into `_sql_injections` and asserted nothing
    // about the result — a regression that stopped detecting this pattern
    // entirely would never fail the test.
    let sql_injections: Vec<_> = report
        .findings
        .iter()
        .filter(|f| matches!(f.vuln_type, VulnType::SqlInjection))
        .collect();
    assert!(
        !sql_injections.is_empty(),
        "should detect SQL injection from request.args -> cursor.execute: {:?}",
        report.findings
    );
}

#[test]
fn test_scan_vulnerabilities_command_injection() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("cmd.py");

    std::fs::write(
        &test_file,
        r#"
from flask import request
import os

def run_command():
    cmd = request.args.get('cmd')
    os.system(cmd)
"#,
    )
    .unwrap();

    let result = scan_vulnerabilities(temp_dir.path(), Some(Language::Python), None);

    assert!(result.is_ok());
    let report = result.unwrap();

    // why: same issue as test_scan_vulnerabilities_sql_injection above — the
    // filtered `_cmd_injections` was never asserted on.
    let cmd_injections: Vec<_> = report
        .findings
        .iter()
        .filter(|f| matches!(f.vuln_type, VulnType::CommandInjection))
        .collect();
    assert!(
        !cmd_injections.is_empty(),
        "should detect command injection from request.args -> os.system: {:?}",
        report.findings
    );
}

// =============================================================================
// AST Utils Tests
// =============================================================================

#[test]
fn test_call_node_kinds() {
    let python_kinds = call_node_kinds(Language::Python);
    assert!(python_kinds.contains(&"call"));

    let ts_kinds = call_node_kinds(Language::TypeScript);
    assert!(ts_kinds.contains(&"call_expression"));

    let go_kinds = call_node_kinds(Language::Go);
    assert!(go_kinds.contains(&"call_expression"));

    let rust_kinds = call_node_kinds(Language::Rust);
    assert!(rust_kinds.contains(&"call_expression"));
    assert!(rust_kinds.contains(&"macro_invocation"));
}

#[test]
fn test_string_node_kinds() {
    let python_kinds = string_node_kinds(Language::Python);
    assert!(python_kinds.contains(&"string"));

    let rust_kinds = string_node_kinds(Language::Rust);
    assert!(rust_kinds.contains(&"string_literal"));
    assert!(rust_kinds.contains(&"raw_string_literal"));
}

#[test]
fn test_assignment_node_kinds() {
    let python_kinds = assignment_node_kinds(Language::Python);
    assert!(python_kinds.contains(&"assignment"));

    let rust_kinds = assignment_node_kinds(Language::Rust);
    assert!(rust_kinds.contains(&"let_declaration"));
}

// =============================================================================
// Language-Specific Pattern Tests
//
// sanitizer-removal-v1 M4 (ATOMIC): `test_detect_sanitizer_typescript`
// deleted. It asserted on the TypeScript regex sanitizer bank, which is now
// empty. AST-based dispatch via `compute_taint_with_tree` covers the same
// `parseInt(val)` fixture; integration coverage lives in
// `tests/sanitize_breaks_flow_per_language.rs`.
// =============================================================================

// =============================================================================
// Serialization Tests
// =============================================================================

#[test]
fn test_taint_source_type_serialization() {
    let source_type = TaintSourceType::HttpParam;
    let json = serde_json::to_string(&source_type).unwrap();
    assert_eq!(json, "\"http_param\"");
}

#[test]
fn test_taint_sink_type_serialization() {
    let sink_type = TaintSinkType::SqlQuery;
    let json = serde_json::to_string(&sink_type).unwrap();
    assert_eq!(json, "\"sql_query\"");
}

#[test]
fn test_sanitizer_type_serialization() {
    let sanitizer = SanitizerType::Numeric;
    let json = serde_json::to_string(&sanitizer).unwrap();
    assert_eq!(json, "\"numeric\"");
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_security_scan() {
    let temp_dir = TempDir::new().unwrap();

    // Create a file with secrets and vulnerabilities
    let test_file = temp_dir.path().join("app.py");
    std::fs::write(
        &test_file,
        r#"
from flask import request
import os

API_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

def run_cmd():
    cmd = request.form.get('cmd')
    os.system(cmd)
"#,
    )
    .unwrap();

    // Test secrets scan
    let secrets_result = scan_secrets(temp_dir.path(), 4.5, false, None);
    assert!(secrets_result.is_ok());

    // Test vulnerability scan
    let vuln_result = scan_vulnerabilities(temp_dir.path(), Some(Language::Python), None);
    assert!(vuln_result.is_ok());
}

// =============================================================================
// Bug Documentation Tests
// =============================================================================

/// Test to document behavior: extract_call_name with invalid node
/// This may fail or return None - documenting expected behavior
#[test]
#[ignore = "Documents potential issue with extract_call_name on invalid nodes"]
fn test_extract_call_name_invalid_node() {
    // This test is ignored because it documents a potential issue
    // where extract_call_name may panic or return incorrect results
    // when given an invalid node
}

/// Test to document behavior: compute_taint with malformed CFG
/// The function should handle invalid CFGs gracefully
#[test]
fn test_compute_taint_malformed_cfg() {
    // Empty CFG should fail validation
    let empty_cfg = CfgInfo {
        function: "empty".to_string(),
        blocks: vec![],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![],
        cyclomatic_complexity: 0,
        nested_functions: HashMap::new(),
    };

    let refs: Vec<VarRef> = vec![];
    let statements: HashMap<u32, String> = HashMap::new();

    let result = compute_taint(&empty_cfg, &refs, &statements, Language::Python);

    // Should return an error for empty CFG
    assert!(result.is_err());
}

/// Test to document behavior: detect_sources with edge cases
/// Some edge cases may not be handled correctly
#[test]
fn test_detect_sources_edge_cases() {
    // Empty statement
    let sources = detect_sources("", 1, Language::Python);
    assert!(sources.is_empty());

    // Statement without assignment
    let sources = detect_sources("print('hello')", 1, Language::Python);
    assert!(sources.is_empty());

    // Multiple sources in one statement
    let sources = detect_sources("x = input() + os.environ['KEY']", 1, Language::Python);
    // why: a prior edit asserted `!sources.is_empty()` on the theory that
    // `input()`/`os.environ` are regex source patterns in taint.rs. They are
    // not: PYTHON_PATTERNS.sources is `vec![]` by design (Wave-2-atomic
    // regex-removal-v1 M8 — see taint.rs) because Python source detection is
    // now exclusively AST-based via `detect_sources_ast`, which this
    // regex-only `detect_sources` entry point never calls. So `detect_sources`
    // returns empty for every Python statement, always — restoring the HEAD
    // behavior here.
    assert!(sources.is_empty());
}
