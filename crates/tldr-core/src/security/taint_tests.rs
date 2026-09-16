//! Taint Analysis Tests
//!
//! Comprehensive test suite for CFG-based taint analysis as defined in
//! session11-taint-spec.md. These tests define expected behavior for:
//!
//! 1. Type Definition Tests - Enum variants and struct fields
//! 2. Pattern Matching Tests - Source/sink/sanitizer detection
//! 3. Worklist Algorithm Tests - Taint propagation
//! 4. Vulnerability Detection Tests - Source to sink flows
//! 5. Edge Case Tests - Empty functions, no sources, etc.
//!
//! All tests are marked #[ignore] as the taint module is not yet implemented.
//! Reference: session11-taint-spec.md Section 8

use std::collections::{HashMap, HashSet};

// Phase 1: Type imports (enabled)
use super::taint::{TaintInfo, TaintSink, TaintSinkType, TaintSourceType};

// Phase 3: Pattern matching function imports (implemented)
//
// Wave-2-atomic (regex-removal-v1 M10): `find_sources_in_statement` and
// `find_sinks_in_statement` aliases were deleted along with the obsolete
// Section 2/3 Python detection tests that used them.
//
// field_access_info-extension-v1 M5 (ATOMIC): the Ruby / Elixir / OCaml
// `test_<lang>_detect_sources/sinks` tests were deleted along with the
// regex source+sink banks they exercised, so `detect_sources` and
// `detect_sinks` are no longer imported here.
//
// sanitizer-removal-v1 M4 (ATOMIC): `detect_sanitizer`, `is_sanitizer`,
// and `find_sanitizers_in_statement` imports removed too — the per-language
// regex sanitizer-bank tests that exercised them have been deleted. The
// public APIs are preserved as no-ops (iterate empty Vec) for external
// callers; AST-based dispatch via `compute_taint_with_tree` is canonical.

// Phase 4: Worklist algorithm (implemented)
use super::taint::compute_taint;

use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, RefType, VarRef};
use crate::Language;

// =============================================================================
// Test Fixtures
// =============================================================================

mod fixtures {
    use super::*;

    /// Create a basic block with given id and line range
    pub fn make_block(id: usize, start: u32, end: u32) -> CfgBlock {
        CfgBlock {
            id,
            block_type: BlockType::Body,
            lines: (start, end),
            calls: Vec::new(),
        }
    }

    /// Create a definition VarRef
    pub fn make_def(name: &str, line: u32) -> VarRef {
        VarRef {
            name: name.to_string(),
            ref_type: RefType::Definition,
            line,
            column: 0,
            context: None,
            group_id: None,
        }
    }

    /// Create a use VarRef
    pub fn make_use(name: &str, line: u32) -> VarRef {
        VarRef {
            name: name.to_string(),
            ref_type: RefType::Use,
            line,
            column: 0,
            context: None,
            group_id: None,
        }
    }

    /// Linear CFG: Block 0 -> Block 1 -> Block 2
    /// Used for simple taint propagation tests
    pub fn linear_cfg() -> CfgInfo {
        CfgInfo {
            function: "linear".to_string(),
            blocks: vec![
                make_block(0, 1, 2),
                make_block(1, 3, 4),
                make_block(2, 5, 6),
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

    /// Loop CFG for convergence tests:
    /// Block 0 -> Block 1 (loop header) -> Block 2 (body) -back-> Block 1
    ///                                  -> Block 3 (exit)
    pub fn loop_cfg() -> CfgInfo {
        CfgInfo {
            function: "loop".to_string(),
            blocks: vec![
                make_block(0, 1, 2), // entry
                make_block(1, 3, 4), // loop header
                make_block(2, 5, 6), // loop body
                make_block(3, 7, 8), // exit
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
                    edge_type: EdgeType::True,
                    condition: Some("i < n".to_string()),
                },
                CfgEdge {
                    from: 1,
                    to: 3,
                    edge_type: EdgeType::False,
                    condition: Some("i < n".to_string()),
                },
                CfgEdge {
                    from: 2,
                    to: 1,
                    edge_type: EdgeType::BackEdge,
                    condition: None,
                },
            ],
            entry_block: 0,
            exit_blocks: vec![3],
            cyclomatic_complexity: 2,
            nested_functions: HashMap::new(),
        }
    }

    /// Empty CFG for edge case tests
    pub fn empty_cfg() -> CfgInfo {
        CfgInfo {
            function: "empty".to_string(),
            blocks: vec![make_block(0, 1, 1)],
            edges: vec![],
            entry_block: 0,
            exit_blocks: vec![0],
            cyclomatic_complexity: 1,
            nested_functions: HashMap::new(),
        }
    }
}

// =============================================================================
// Section 1: Type Definition Tests
// =============================================================================

/// Tests that TaintSourceType enum has all required variants
#[test]
fn test_taint_source_type_variants() {
    // TaintSourceType should have these variants per spec Section 1.2:
    // - UserInput: input(), sys.stdin.read()
    // - Stdin: sys.stdin.read(), sys.stdin.readline()
    // - HttpParam: request.args, request.form, request.values
    // - HttpBody: request.json, request.data, request.body
    // - EnvVar: os.environ, os.getenv()
    // - FileRead: optional, context-dependent

    let variants = [
        TaintSourceType::UserInput,
        TaintSourceType::Stdin,
        TaintSourceType::HttpParam,
        TaintSourceType::HttpBody,
        TaintSourceType::EnvVar,
        TaintSourceType::FileRead,
    ];
    assert_eq!(variants.len(), 6);
}

/// Tests that TaintSinkType enum has all required variants
#[test]
fn test_taint_sink_type_variants() {
    // TaintSinkType should have these variants per spec Section 1.3:
    // - SqlQuery: cursor.execute(), .execute()
    // - CodeEval: eval()
    // - CodeExec: exec()
    // - CodeCompile: compile()
    // - ShellExec: os.system(), subprocess.run()
    // - FileWrite: open(..., 'w'), .write_text()
    // - HtmlOutput: HTML/template raw output (XSS sink)
    // - FileOpen: file system path access (path-traversal sink, distinct from FileWrite)
    // - HttpRequest: outbound HTTP/URL request (SSRF sink)
    // - Deserialize: untrusted-data deserialization (RCE-via-deser sink)

    let variants = [
        TaintSinkType::SqlQuery,
        TaintSinkType::CodeEval,
        TaintSinkType::CodeExec,
        TaintSinkType::CodeCompile,
        TaintSinkType::ShellExec,
        TaintSinkType::FileWrite,
        TaintSinkType::HtmlOutput,
        TaintSinkType::FileOpen,
        TaintSinkType::HttpRequest,
        TaintSinkType::Deserialize,
    ];
    assert_eq!(variants.len(), 10);
}

/// Tests that TaintInfo struct has required fields
#[test]
fn test_taint_info_struct_fields() {
    // TaintInfo should have these fields per spec Section 1.1:
    // - tainted_vars: HashMap<usize, HashSet<String>>
    // - sources: Vec<TaintSource>
    // - sinks: Vec<TaintSink>
    // - flows: Vec<TaintFlow>
    // - sanitized_vars: HashSet<String>
    // - function_name: String

    let info = TaintInfo::new("test_func");
    assert_eq!(info.function_name, "test_func");
    assert!(info.tainted_vars.is_empty());
    assert!(info.sources.is_empty());
    assert!(info.sinks.is_empty());
    assert!(info.flows.is_empty());
    assert!(info.sanitized_vars.is_empty());
}

/// Tests TaintInfo::is_tainted method
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

/// Tests TaintInfo::is_tainted returns false for nonexistent block
#[test]
fn test_taint_info_is_tainted_nonexistent_block() {
    let info = TaintInfo::new("test");
    assert!(!info.is_tainted(999, "any_var"));
}

/// Tests TaintInfo::get_vulnerabilities returns only tainted sinks
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

/// Tests TaintInfo default values
#[test]
fn test_taint_info_default_values() {
    let info = TaintInfo::default();
    assert!(info.function_name.is_empty());
    assert!(info.tainted_vars.is_empty());
    assert!(info.sources.is_empty());
    assert!(info.sinks.is_empty());
    assert!(info.flows.is_empty());
    assert!(info.sanitized_vars.is_empty());
}

// =============================================================================
// Section 2: Pattern Matching Tests - Source Detection
// =============================================================================
//
// Wave-2-atomic (regex-removal-v1 M10): the Python `test_detect_*_as_source`
// unit tests have been deleted along with the `find_sources_in_statement`
// alias and the Python sources regex bank. Source detection is now
// exclusively AST-based (see `compute_taint_with_tree`); end-to-end coverage
// lives in the Section 5/6/7 worklist + vulnerability tests and the
// rr_baseline / rr_framework integration tests.

// =============================================================================
// Section 3: Pattern Matching Tests - Sink Detection
// =============================================================================
//
// Wave-2-atomic (regex-removal-v1 M10): the Python `test_detect_*_as_*_sink`
// unit tests have been deleted along with the `find_sinks_in_statement`
// alias and the Python sinks regex bank. See the Section 2 comment above.

// =============================================================================
// Section 4: Pattern Matching Tests - Sanitizer Detection
//
// sanitizer-removal-v1 M4 (ATOMIC): the three Python regex-bank-shaped
// tests previously here (`test_int_sanitizes_sql_injection`,
// `test_shlex_quote_sanitizes_command_injection`,
// `test_html_escape_sanitizes_xss`) are deleted. They asserted directly on
// the regex bank's behaviour via `is_sanitizer` / `find_sanitizers_in_statement`,
// which now iterate the (empty) Vec and return false / empty.
// Coverage of the same behaviour at the worklist level lives in
// `test_sanitizer_removes_taint` (Section 5) and the
// `sanitize_breaks_flow_per_language` integration suite.
// =============================================================================

// =============================================================================
// Section 5: Worklist Algorithm Tests - Taint Propagation
// =============================================================================

/// Tests simple assignment propagates taint: x = input(); y = x -> y is tainted
#[test]
fn test_propagate_through_assignment() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 1: y = x
        make_use("x", 3),
        make_def("y", 3),
        // Block 2: use y
        make_use("y", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(3, "y = x".to_string());
    statements.insert(5, "print(y)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    assert!(result.is_tainted(0, "x"), "x should be tainted at block 0");
    assert!(result.is_tainted(1, "x"), "x should be tainted at block 1");
    assert!(
        result.is_tainted(1, "y"),
        "y should be tainted at block 1 (via x)"
    );
    assert!(result.is_tainted(2, "y"), "y should be tainted at block 2");
}

/// Tests taint propagates through string concatenation
#[test]
fn test_propagate_through_concatenation() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: user = input()
        make_def("user", 1),
        // Block 1: query = "SELECT * FROM users WHERE name = '" + user + "'"
        make_use("user", 3),
        make_def("query", 3),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "user = input()".to_string());
    statements.insert(
        3,
        "query = \"SELECT * FROM users WHERE name = '\" + user + \"'\"".to_string(),
    );

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();
    assert!(
        result.is_tainted(1, "query"),
        "query should be tainted via concatenation"
    );
}

/// Tests taint propagates across CFG blocks
#[test]
fn test_propagate_across_blocks() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 2: use x (skipping block 1)
        make_use("x", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(5, "print(x)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();
    assert!(
        result.is_tainted(2, "x"),
        "taint should propagate to block 2"
    );
}

/// Tests taint does NOT propagate backward (forward analysis only)
#[test]
fn test_taint_does_not_propagate_backward() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: use x (before definition)
        make_use("x", 1),
        // Block 2: x = input() (definition comes later)
        make_def("x", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "print(x)".to_string());
    statements.insert(5, "x = input()".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();
    // x at block 0 should NOT be tainted because the source is at block 2
    assert!(
        !result.is_tainted(0, "x"),
        "taint should not propagate backward"
    );
}

/// Tests taint propagates through loop iterations
#[test]
fn test_propagate_through_loop() {
    use fixtures::*;

    let cfg = loop_cfg();
    let refs = vec![
        // Block 0 (entry): data = input()
        make_def("data", 1),
        // Block 2 (loop body): result = process(data)
        make_use("data", 5),
        make_def("result", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "data = input()".to_string());
    statements.insert(5, "result = process(data)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();
    assert!(
        result.is_tainted(2, "data"),
        "data should be tainted in loop body"
    );
    assert!(result.is_tainted(2, "result"), "result should be tainted");
}

/// Tests sanitizer removes taint
#[test]
fn test_sanitizer_removes_taint() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 1: y = int(x)  <- sanitizer
        make_use("x", 3),
        make_def("y", 3),
        // Block 2: use y
        make_use("y", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(3, "y = int(x)".to_string());
    statements.insert(5, "print(y)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    assert!(result.is_tainted(0, "x"), "x should be tainted");
    assert!(result.is_tainted(1, "x"), "x should still be tainted");
    assert!(
        !result.is_tainted(1, "y"),
        "y should NOT be tainted (sanitized)"
    );
    assert!(
        result.sanitized_vars.contains("y"),
        "y should be in sanitized_vars"
    );
}

/// Tests multiple sources merge correctly
#[test]
fn test_multiple_sources_merge() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input(); y = os.environ['KEY']
        make_def("x", 1),
        make_def("y", 2),
        // Block 1: z = x + y
        make_use("x", 3),
        make_use("y", 3),
        make_def("z", 3),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(2, "y = os.environ['KEY']".to_string());
    statements.insert(3, "z = x + y".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    // Both x and y are sources, so z should be tainted
    assert!(
        result.is_tainted(1, "z"),
        "z should be tainted from multiple sources"
    );

    // Should have 2 sources
    assert_eq!(result.sources.len(), 2);
}

/// Tests worklist algorithm converges on loops (no infinite loop)
#[test]
fn test_convergence_with_cycles() {
    use fixtures::*;

    let cfg = loop_cfg();
    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 1 (header): condition uses x
        make_use("x", 3),
        // Block 2 (body): x = x + 1
        make_use("x", 5),
        make_def("x", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(3, "while x < 10:".to_string());
    statements.insert(5, "x = x + 1".to_string());

    // Should complete without infinite loop
    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    // Verify it converged correctly
    assert!(result.is_tainted(1, "x"));
    assert!(result.is_tainted(2, "x"));
}

// =============================================================================
// Section 6: Vulnerability Detection Tests
// =============================================================================

/// Tests detection of SQL injection: tainted data flows to cursor.execute()
#[test]
fn test_detect_sql_injection() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: user_input = input()
        make_def("user_input", 1),
        // Block 1: query = "SELECT * FROM users WHERE id = " + user_input
        make_use("user_input", 3),
        make_def("query", 3),
        // Block 2: cursor.execute(query)
        make_use("query", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "user_input = input()".to_string());
    statements.insert(
        3,
        "query = \"SELECT * FROM users WHERE id = \" + user_input".to_string(),
    );
    statements.insert(5, "cursor.execute(query)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert_eq!(vulns.len(), 1, "Should detect 1 SQL injection");
    assert!(matches!(vulns[0].sink_type, TaintSinkType::SqlQuery));

    // Should also have a flow recorded
    assert_eq!(result.flows.len(), 1);
    assert_eq!(result.flows[0].source.var, "user_input");
    assert_eq!(result.flows[0].sink.var, "query");
}

/// Tests detection of command injection: tainted data flows to os.system()
#[test]
fn test_detect_command_injection() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: cmd = input()
        make_def("cmd", 1),
        // Block 2: os.system(cmd)
        make_use("cmd", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "cmd = input()".to_string());
    statements.insert(5, "os.system(cmd)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert_eq!(vulns.len(), 1, "Should detect 1 command injection");
    assert!(matches!(vulns[0].sink_type, TaintSinkType::ShellExec));
}

/// Tests detection of code injection: tainted data flows to eval()
#[test]
fn test_detect_code_injection() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: code = request.json['code']
        make_def("code", 1),
        // Block 2: eval(code)
        make_use("code", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "code = request.json['code']".to_string());
    statements.insert(5, "eval(code)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert_eq!(vulns.len(), 1, "Should detect 1 code injection");
    assert!(matches!(vulns[0].sink_type, TaintSinkType::CodeEval));
}

/// Tests NO vulnerability when data is sanitized before sink
#[test]
fn test_no_vulnerability_when_sanitized() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: user_id = input()
        make_def("user_id", 1),
        // Block 1: safe_id = int(user_id)  <- sanitizer
        make_use("user_id", 3),
        make_def("safe_id", 3),
        // Block 2: cursor.execute("SELECT * FROM users WHERE id = " + str(safe_id))
        make_use("safe_id", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "user_id = input()".to_string());
    statements.insert(3, "safe_id = int(user_id)".to_string());
    statements.insert(
        5,
        "cursor.execute(\"SELECT * FROM users WHERE id = \" + str(safe_id))".to_string(),
    );

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert!(
        vulns.is_empty(),
        "Should NOT detect vulnerability (sanitized)"
    );
    assert!(result.sanitized_vars.contains("safe_id"));
}

/// Tests NO vulnerability when sink uses untainted data
#[test]
fn test_no_vulnerability_when_untainted() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: query = "SELECT * FROM users"  (not from user input)
        make_def("query", 1),
        // Block 2: cursor.execute(query)
        make_use("query", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "query = \"SELECT * FROM users\"".to_string());
    statements.insert(5, "cursor.execute(query)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert!(
        vulns.is_empty(),
        "Should NOT detect vulnerability (untainted)"
    );
    assert!(result.sources.is_empty(), "Should have no sources");
}

/// Tests detection of multiple vulnerabilities
#[test]
fn test_multiple_vulnerabilities() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: data = input()
        make_def("data", 1),
        // Block 1: cursor.execute(data)
        make_use("data", 3),
        // Block 2: os.system(data)
        make_use("data", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "data = input()".to_string());
    statements.insert(3, "cursor.execute(data)".to_string());
    statements.insert(5, "os.system(data)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    let vulns = result.get_vulnerabilities();
    assert_eq!(vulns.len(), 2, "Should detect 2 vulnerabilities");
}

// =============================================================================
// Section 7: Edge Case Tests
// =============================================================================

/// Tests empty function produces valid (empty) TaintInfo
#[test]
fn test_empty_function() {
    use fixtures::*;

    let cfg = empty_cfg();
    let refs: Vec<VarRef> = vec![];

    let result = compute_taint(&cfg, &refs, &HashMap::new(), Language::Python).unwrap();

    assert_eq!(result.function_name, "empty");
    assert!(result.sources.is_empty());
    assert!(result.sinks.is_empty());
    assert!(result.flows.is_empty());
    assert!(result.get_vulnerabilities().is_empty());
}

/// Tests function with no sources produces no tainted vars
#[test]
fn test_no_sources_in_function() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = 42  (constant, not user input)
        make_def("x", 1),
        // Block 1: y = x
        make_use("x", 3),
        make_def("y", 3),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = 42".to_string());
    statements.insert(3, "y = x".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    assert!(result.sources.is_empty(), "Should have no sources");
    // All blocks should have empty taint sets
    for vars in result.tainted_vars.values() {
        assert!(vars.is_empty(), "No variables should be tainted");
    }
}

/// Tests function with no sinks produces no vulnerabilities
#[test]
fn test_no_sinks_in_function() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input()  (source)
        make_def("x", 1),
        // Block 1: y = x  (no sink)
        make_use("x", 3),
        make_def("y", 3),
        // Block 2: print(y)  (not a sink)
        make_use("y", 5),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(3, "y = x".to_string());
    statements.insert(5, "print(y)".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    assert!(!result.sources.is_empty(), "Should have sources");
    assert!(result.sinks.is_empty(), "Should have no sinks");
    assert!(
        result.get_vulnerabilities().is_empty(),
        "Should have no vulns"
    );
}

/// Tests taint analysis handles unreachable code gracefully
#[test]
fn test_unreachable_code() {
    use fixtures::*;

    // Create a CFG with an unreachable block (no predecessors except itself)
    let mut cfg = linear_cfg();
    cfg.blocks.push(make_block(3, 7, 8)); // Unreachable block
                                          // No edge TO block 3, so it's unreachable

    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 3 (unreachable): y = x
        make_use("x", 7),
        make_def("y", 7),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(7, "y = x".to_string());

    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    // Block 3 should not have tainted variables (unreachable)
    assert!(!result.is_tainted(3, "y"));
}

/// Tests indirect taint through function call (conservative assumption)
#[test]
fn test_indirect_taint_through_function_call() {
    use fixtures::*;

    let cfg = linear_cfg();
    let refs = vec![
        // Block 0: x = input()
        make_def("x", 1),
        // Block 1: y = unknown_func(x)  <- conservative: might propagate taint
        make_use("x", 3),
        make_def("y", 3),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "x = input()".to_string());
    statements.insert(3, "y = unknown_func(x)".to_string());

    // Conservative analysis: if a tainted variable is used in a function call,
    // the result is considered tainted (unless it's a known sanitizer)
    let result = compute_taint(&cfg, &refs, &statements, Language::Python).unwrap();

    // Conservative: y might be tainted
    // The spec says to use conservative assumptions for unknown functions
    assert!(
        result.is_tainted(1, "y"),
        "Conservative: function result is tainted"
    );
}

// =============================================================================
// Section 8: JSON Serialization Tests
// =============================================================================

/// Tests TaintInfo serializes to expected JSON structure
#[test]
#[ignore = "Phase 7: TaintInfo::to_json_value not implemented"]
fn test_taint_info_to_json() {
    // Phase 7: JSON Serialization
    // let mut info = TaintInfo::new("test_func");
    // info.sources.push(TaintSource {
    //     var: "user_input".to_string(),
    //     line: 2,
    //     source_type: TaintSourceType::UserInput,
    //     statement: Some("user_input = input()".to_string()),
    // });
    //
    // let json = info.to_json_value();
    //
    // assert_eq!(json["function"], "test_func");
    // assert!(json["sources"].is_array());
    // assert_eq!(json["sources"][0]["var"], "user_input");
    // assert_eq!(json["sources"][0]["line"], 2);
    // assert_eq!(json["vulnerability_count"], 0);
    todo!("Implement TaintInfo::to_json_value");
}

/// Tests TaintSourceType serializes with snake_case
#[test]
fn test_taint_source_type_serialization() {
    let source_type = TaintSourceType::HttpParam;
    let json = serde_json::to_string(&source_type).unwrap();
    assert_eq!(json, "\"http_param\"");

    let source_type = TaintSourceType::UserInput;
    let json = serde_json::to_string(&source_type).unwrap();
    assert_eq!(json, "\"user_input\"");
}

/// Tests TaintSinkType serializes with snake_case
#[test]
fn test_taint_sink_type_serialization() {
    let sink_type = TaintSinkType::SqlQuery;
    let json = serde_json::to_string(&sink_type).unwrap();
    assert_eq!(json, "\"sql_query\"");

    let sink_type = TaintSinkType::ShellExec;
    let json = serde_json::to_string(&sink_type).unwrap();
    assert_eq!(json, "\"shell_exec\"");
}

// =============================================================================
// Section 10: Language-Specific Taint Pattern Tests (Phase 2 TDD)
//
// These tests define the expected behavior for taint pattern detection
// across all 18 supported languages. Each test is marked #[ignore] because
// the language-specific patterns have not yet been implemented (Phase 3).
//
// Languages are grouped by similarity:
//   - TypeScript + JavaScript (share patterns)
//   - Lua + Luau (share patterns)
//   - All others have unique test groups
// =============================================================================

// =========================================================================
// Per-language `test_<lang>_detect_sanitizers` tests
//
// sanitizer-removal-v1 M4 (ATOMIC): the 17 per-language regex-bank
// detect_sanitizer assertions previously here (typescript, javascript, go,
// java, rust, c, cpp, ruby, kotlin, swift, csharp, scala, php, lua, luau,
// elixir, ocaml) are deleted. Each one called `detect_sanitizer(<text>,
// <Language>)` and asserted `Some(SanitizerType::*)`. Post-M4 the regex
// banks are empty Vecs and `detect_sanitizer` always returns None.
//
// AST-equivalent coverage lives at the worklist level via the
// `sanitize_breaks_flow_per_language` integration suite (3 sections:
// regular sanitizes-flow, in-string-literal-does-not-sanitize, and
// AST-only mirrors).
// =========================================================================

// =============================================================================
// Section 11: AST-Based Detection Tests (Phase 9)
//
// These tests verify that AST-based taint detection correctly:
// 1. Detects sources/sinks/sanitizers in actual code
// 2. Rejects false positives from comments and string literals
// 3. Works with compute_taint_with_tree
// =============================================================================

use super::taint::{compute_taint_with_tree, detect_sinks_ast, detect_sources_ast};
use crate::ast::parser::ParserPool;

// =========================================================================
// AST False Positive Rejection Tests
// =========================================================================

/// Tests that eval() in a Python comment is NOT detected as a sink
#[test]
fn test_ast_python_eval_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "# eval(user_code) - dangerous, don't use\nx = 1";
    let tree = pool.parse(source, Language::Python).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Python, None);
    assert!(
        sinks.is_empty(),
        "eval in comment should NOT be detected as sink, got: {:?}",
        sinks
    );
}

/// Tests that input() in a Python string is NOT detected as a source
#[test]
fn test_ast_python_input_in_string_not_source() {
    let pool = ParserPool::new();
    let source = "msg = \"use input() to get data\"";
    let tree = pool.parse(source, Language::Python).unwrap();
    let root = tree.root_node();

    let sources = detect_sources_ast(&root, source.as_bytes(), Language::Python, None);
    // Should not detect input() inside a string as a source
    assert!(
        sources.is_empty(),
        "input() in string should NOT be detected as source, got: {:?}",
        sources
    );
}

/// Tests that eval() in actual Python code IS detected as a sink
#[test]
fn test_ast_python_eval_in_code_is_sink() {
    let pool = ParserPool::new();
    let source = "result = eval(user_code)";
    let tree = pool.parse(source, Language::Python).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Python, None);
    assert!(
        !sinks.is_empty(),
        "eval in actual code should be detected as sink"
    );
    assert!(
        sinks.iter().any(|s| s.sink_type == TaintSinkType::CodeEval),
        "eval should be CodeEval, got: {:?}",
        sinks
    );
}

/// Tests that input() in actual Python code IS detected as a source
#[test]
fn test_ast_python_input_in_code_is_source() {
    let pool = ParserPool::new();
    let source = "user_input = input()";
    let tree = pool.parse(source, Language::Python).unwrap();
    let root = tree.root_node();

    let sources = detect_sources_ast(&root, source.as_bytes(), Language::Python, None);
    assert!(
        !sources.is_empty(),
        "input() in code should be detected as source"
    );
    assert!(
        sources
            .iter()
            .any(|s| s.source_type == TaintSourceType::UserInput),
        "input should be UserInput, got: {:?}",
        sources
    );
    assert_eq!(sources[0].var, "user_input");
}

/// Tests that os.system() in a Python comment is NOT detected as a sink
#[test]
fn test_ast_python_os_system_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "# os.system(cmd) is dangerous\nresult = 42";
    let tree = pool.parse(source, Language::Python).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Python, None);
    assert!(
        sinks.is_empty(),
        "os.system in comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for TypeScript
// =========================================================================

#[test]
fn test_ast_typescript_eval_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "// eval(code) - never do this\nconst x = 1;";
    let tree = pool.parse(source, Language::TypeScript).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::TypeScript, None);
    assert!(
        sinks.is_empty(),
        "eval in TS comment should NOT be detected as sink"
    );
}

#[test]
fn test_ast_typescript_eval_in_code_is_sink() {
    let pool = ParserPool::new();
    let source = "eval(userInput);";
    let tree = pool.parse(source, Language::TypeScript).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::TypeScript, None);
    assert!(
        !sinks.is_empty(),
        "eval in TS code should be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for Go
// =========================================================================

#[test]
fn test_ast_go_exec_command_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "package main\n// exec.Command(cmd) is dangerous\nfunc main() {}";
    let tree = pool.parse(source, Language::Go).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Go, None);
    assert!(
        sinks.is_empty(),
        "exec.Command in Go comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for C
// =========================================================================

#[test]
fn test_ast_c_system_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "// system(cmd) is dangerous\nint main() { return 0; }";
    let tree = pool.parse(source, Language::C).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::C, None);
    assert!(
        sinks.is_empty(),
        "system() in C comment should NOT be detected as sink"
    );
}

#[test]
fn test_ast_c_system_in_code_is_sink() {
    let pool = ParserPool::new();
    let source = "int main() { system(cmd); return 0; }";
    let tree = pool.parse(source, Language::C).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::C, None);
    assert!(
        !sinks.is_empty(),
        "system() in C code should be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for Java
// =========================================================================

#[test]
fn test_ast_java_runtime_exec_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "class Main {\n// Runtime.getRuntime().exec(cmd)\nvoid f() {} }";
    let tree = pool.parse(source, Language::Java).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Java, None);
    assert!(
        sinks.is_empty(),
        "Runtime.exec in Java comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for Rust
// =========================================================================

#[test]
fn test_ast_rust_command_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "fn main() {\n// Command::new(cmd).spawn()\nlet x = 1;\n}";
    let tree = pool.parse(source, Language::Rust).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Rust, None);
    assert!(
        sinks.is_empty(),
        "Command::new in Rust comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for Ruby
// =========================================================================

#[test]
fn test_ast_ruby_eval_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "# eval(code) is dangerous\nx = 1";
    let tree = pool.parse(source, Language::Ruby).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Ruby, None);
    assert!(
        sinks.is_empty(),
        "eval in Ruby comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for PHP
// =========================================================================

#[test]
fn test_ast_php_eval_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "<?php\n// eval($code) is dangerous\n$x = 1;\n?>";
    let tree = pool.parse(source, Language::Php).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Php, None);
    assert!(
        sinks.is_empty(),
        "eval in PHP comment should NOT be detected as sink"
    );
}

// =========================================================================
// AST-Based Detection for Lua
// =========================================================================

#[test]
fn test_ast_lua_loadstring_in_comment_not_sink() {
    let pool = ParserPool::new();
    let source = "-- loadstring(code) is dangerous\nlocal x = 1";
    let tree = pool.parse(source, Language::Lua).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source.as_bytes(), Language::Lua, None);
    assert!(
        sinks.is_empty(),
        "loadstring in Lua comment should NOT be detected as sink"
    );
}

// =========================================================================
// compute_taint_with_tree Tests
// =========================================================================

// Wave-2-atomic (regex-removal-v1 M10): `test_compute_taint_with_tree_no_tree`
// has been deleted. It exercised the legacy regex-only path of
// `compute_taint_with_tree` (passing `tree=None, source=None` with Python
// fixtures `"x = input()"` / `"eval(x)"`) and asserted that the Python
// regex source/sink banks would still detect them. With the Python regex
// banks now empty, AST is the canonical detection path; this test no
// longer reflects intended behaviour. End-to-end coverage of taint
// analysis lives in `test_compute_taint_with_tree_sql_injection` (which
// passes a real parsed tree) and the rr_baseline / rr_framework
// integration tests that use the shared `analyze` helper.

/// Tests that compute_taint_with_tree detects SQL injection with a tree
#[test]
fn test_compute_taint_with_tree_sql_injection() {
    use fixtures::*;

    let pool = ParserPool::new();
    let source_code = "user_input = input()\nquery = \"SELECT * FROM users WHERE id = \" + user_input\ncursor.execute(query)";
    let tree = pool.parse(source_code, Language::Python).unwrap();

    let cfg = linear_cfg();
    let refs = vec![
        make_def("user_input", 1),
        make_use("user_input", 2),
        make_def("query", 2),
        make_use("query", 3),
    ];

    let mut statements = HashMap::new();
    statements.insert(1, "user_input = input()".to_string());
    statements.insert(
        2,
        "query = \"SELECT * FROM users WHERE id = \" + user_input".to_string(),
    );
    statements.insert(3, "cursor.execute(query)".to_string());

    let result = compute_taint_with_tree(
        &cfg,
        &refs,
        &statements,
        Some(&tree),
        Some(source_code.as_bytes()),
        Language::Python,
        None,
    )
    .unwrap();

    assert!(
        !result.sources.is_empty(),
        "Should detect input() as source"
    );
}
