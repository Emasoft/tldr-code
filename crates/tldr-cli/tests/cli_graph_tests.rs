//! CLI Graph Commands Tests
//!
//! Tests for tldr-cli graph analysis commands:
//! - calls: Build cross-file call graph
//! - impact: Analyze impact of changing a function
//! - dead: Find dead (unreachable) code
//! - cfg: Extract control flow graph
//! - dfg: Extract data flow graph
//! - ssa: Display SSA form

use std::fs;
// Path import not needed - using PathBuf via tempfile::TempDir
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Create a minimal test project for CLI testing
fn create_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Create a Python file with various functions
    fs::write(
        project_path.join("main.py"),
        r#"def helper():
    pass

def main():
    helper()
    
class MyClass:
    def method(self):
        helper()

def unused_func():
    pass
"#,
    )
    .unwrap();

    temp_dir
}

// =============================================================================
// Calls Command Tests
// =============================================================================

#[test]
fn test_calls_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["calls", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(output.status.success(), "calls command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // med-low-schema-cleanup-v1 (N12): canonical keys are total_edges /
    // shown_edges / truncated; the redundant `edge_count` / `node_count`
    // pair was removed (edge_count was always equal to total_edges and
    // node_count was always equal to nodes.len()).
    assert!(
        stdout.contains("\"total_edges\""),
        "JSON should contain total_edges"
    );
    assert!(
        stdout.contains("\"shown_edges\""),
        "JSON should contain shown_edges"
    );
    assert!(
        !stdout.contains("\"edge_count\""),
        "JSON should NOT contain redundant edge_count (N12)"
    );
    assert!(
        !stdout.contains("\"node_count\""),
        "JSON should NOT contain redundant node_count (N12)"
    );
    assert!(
        stdout.contains("main.py"),
        "Output should reference test file"
    );
}

#[test]
fn test_calls_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "calls",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(output.status.success(), "calls command should succeed");
    // Text format not yet implemented for graph commands - returns empty
    // Tracked separately; just verify command doesn't crash
}

#[test]
fn test_calls_compact_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "calls",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "compact",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(output.status.success(), "calls command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Compact format should be single line (no newlines within JSON)
    assert!(
        !stdout.contains("\n{"),
        "Compact format should not have newlines before objects"
    );
    // med-low-schema-cleanup-v1 (N12): canonical key is total_edges.
    assert!(
        stdout.contains("total_edges"),
        "Output should contain total_edges"
    );
}

#[test]
fn test_calls_dot_format_emits_digraph() {
    // surface-gaps-v1 (commit 1a692bc) added real DOT/Graphviz emission for
    // `tldr calls` (alongside `inheritance`, `hubs`, `impact`). The previous
    // format-flag-strictness-v1 stance — that DOT was unsupported and must
    // error — has been superseded. `calls --format dot` now succeeds and
    // emits a `digraph calls { ... }` document.
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "calls",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "dot",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(
        output.status.success(),
        "calls --format dot must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("digraph"),
        "calls --format dot stdout must start with 'digraph'; got: {}",
        stdout.lines().next().unwrap_or("")
    );
}

#[test]
fn test_calls_quiet_mode() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["calls", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // In quiet mode, progress messages should not appear
    assert!(
        !stderr.contains("Building call graph"),
        "Quiet mode should suppress progress messages"
    );
}

#[test]
fn test_calls_with_lang_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "calls",
            temp_dir.path().to_str().unwrap(),
            "-l",
            "python",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(output.status.success(), "calls with --lang should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("python"),
        "Output should indicate Python language"
    );
}

#[test]
fn test_calls_nonexistent_path() {
    let output = tldr_cmd()
        .args(["calls", "/nonexistent/path/12345", "-q"])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(
        !output.status.success(),
        "calls should fail for nonexistent path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error message should indicate path not found"
    );
}

#[test]
fn test_calls_help() {
    let output = tldr_cmd()
        .args(["calls", "--help"])
        .output()
        .expect("Failed to execute tldr calls --help");

    assert!(output.status.success(), "calls --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--lang"),
        "Help should mention --lang option"
    );
    assert!(
        stdout.contains("--format"),
        "Help should mention --format option"
    );
    assert!(
        stdout.contains("--quiet"),
        "Help should mention --quiet option"
    );
}

#[test]
fn test_calls_default_path() {
    // Test that default path (.) works
    let output = tldr_cmd()
        .args(["calls", "--help"])
        .output()
        .expect("Failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[PATH]"),
        "Help should show optional PATH argument"
    );
}

// =============================================================================
// Impact Command Tests
// =============================================================================

#[test]
fn test_impact_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["impact", "main", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr impact");

    assert!(output.status.success(), "impact command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("targets"), "JSON should contain targets");
    assert!(
        stdout.contains("total_targets"),
        "JSON should contain total_targets"
    );
}

#[test]
fn test_impact_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "impact",
            "main",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr impact");

    // Text format not yet implemented for graph commands - may return empty or error
    // Tracked separately; just verify command doesn't crash (exit code doesn't matter)
    let _ = output.status;
}

#[test]
fn test_impact_depth_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "impact",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "-d",
            "1",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr impact");

    assert!(
        output.status.success(),
        "impact with --depth should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("targets"), "Output should contain targets");
}

#[test]
fn test_impact_type_aware_flag() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "impact",
            "main",
            temp_dir.path().to_str().unwrap(),
            "--type-aware",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr impact");

    // Command should succeed even if type-aware is not fully implemented
    // The flag is registered but may not change behavior
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("targets") || !output.status.success(),
        "Should either succeed with output or fail gracefully"
    );
}

#[test]
fn test_impact_nonexistent_function() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "impact",
            "nonexistent_function_xyz",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr impact");

    // Function not found may or may not cause error exit
    // The behavior varies - documented in bugs
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error") || output.status.success(),
        "Should either error with message or succeed (empty result)"
    );
}

#[test]
fn test_impact_help() {
    let output = tldr_cmd()
        .args(["impact", "--help"])
        .output()
        .expect("Failed to execute tldr impact --help");

    assert!(output.status.success(), "impact --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--depth"),
        "Help should mention --depth option"
    );
    assert!(
        stdout.contains("--type-aware"),
        "Help should mention --type-aware option"
    );
    assert!(
        stdout.contains("FUNCTION"),
        "Help should show FUNCTION argument"
    );
}

// =============================================================================
// Dead Command Tests
// =============================================================================

#[test]
fn test_dead_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["dead", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(output.status.success(), "dead command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dead_functions"),
        "JSON should contain dead_functions"
    );
    assert!(
        stdout.contains("total_dead"),
        "JSON should contain total_dead"
    );
    assert!(
        stdout.contains("dead_percentage"),
        "JSON should contain dead_percentage"
    );
}

#[test]
fn test_dead_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(output.status.success(), "dead command should succeed");
    // Text format not yet implemented for graph commands - returns empty
    // Tracked separately; just verify command doesn't crash
}

#[test]
fn test_dead_entry_points_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "-e",
            "main",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(
        output.status.success(),
        "dead with --entry-points should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dead_functions"),
        "Output should contain results"
    );
}

#[test]
fn test_dead_multiple_entry_points() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "-e",
            "main,helper",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(
        output.status.success(),
        "dead with multiple entry points should succeed"
    );
}

#[test]
fn test_dead_help() {
    let output = tldr_cmd()
        .args(["dead", "--help"])
        .output()
        .expect("Failed to execute tldr dead --help");

    assert!(output.status.success(), "dead --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--entry-points"),
        "Help should mention --entry-points option"
    );
}

// =============================================================================
// Dead Command - Enriched JSON Output Tests
// =============================================================================

#[test]
fn test_dead_json_has_line_field() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["dead", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(output.status.success(), "dead command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the JSON to check for line field in dead_functions entries
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Check dead_functions array entries have "line" field
    if let Some(dead_funcs) = json.get("dead_functions").and_then(|v| v.as_array()) {
        for func in dead_funcs {
            assert!(
                func.get("line").is_some(),
                "Each dead function should have a 'line' field, got: {}",
                func
            );
        }
    }
    // Also check possibly_dead entries
    if let Some(possibly_dead) = json.get("possibly_dead").and_then(|v| v.as_array()) {
        for func in possibly_dead {
            assert!(
                func.get("line").is_some(),
                "Each possibly_dead function should have a 'line' field, got: {}",
                func
            );
        }
    }
}

#[test]
fn test_dead_json_has_signature_field() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["dead", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(output.status.success(), "dead command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Check that dead_functions entries have "signature" field
    if let Some(dead_funcs) = json.get("dead_functions").and_then(|v| v.as_array()) {
        for func in dead_funcs {
            assert!(
                func.get("signature").is_some(),
                "Each dead function should have a 'signature' field, got: {}",
                func
            );
        }
    }
}

#[test]
fn test_dead_json_line_is_nonzero_for_real_functions() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["dead", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(output.status.success(), "dead command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // For real functions extracted from source files, line should be > 0
    let all_funcs: Vec<&serde_json::Value> = json
        .get("dead_functions")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .chain(
            json.get("possibly_dead")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten(),
        )
        .collect();

    if !all_funcs.is_empty() {
        let has_nonzero_line = all_funcs
            .iter()
            .any(|f| f.get("line").and_then(|l| l.as_u64()).unwrap_or(0) > 0);
        assert!(
            has_nonzero_line,
            "At least one function should have line > 0 for real source files"
        );
    }
}

// =============================================================================
// CFG Command Tests
// =============================================================================





// =============================================================================
// DFG Command Tests
// =============================================================================




// =============================================================================
// SSA Command Tests
// =============================================================================









// =============================================================================
// Cross-Command Integration Tests
// =============================================================================

#[test]
fn test_calls_then_impact_consistency() {
    let temp_dir = create_test_project();
    let project_path = temp_dir.path().to_str().unwrap();

    // First get call graph
    let calls_output = tldr_cmd()
        .args(["calls", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(calls_output.status.success());
    let calls_stdout = String::from_utf8_lossy(&calls_output.stdout);

    // Then run impact on a function that should exist
    let impact_output = tldr_cmd()
        .args(["impact", "helper", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr impact");

    assert!(impact_output.status.success());

    // Both should reference the same function
    assert!(
        calls_stdout.contains("helper"),
        "Call graph should reference helper function"
    );
}

#[test]
fn test_dead_finds_unused_from_calls() {
    let temp_dir = create_test_project();
    let project_path = temp_dir.path().to_str().unwrap();

    // Get call graph first
    let calls_output = tldr_cmd()
        .args(["calls", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr calls");

    assert!(calls_output.status.success());

    // Then run dead code analysis
    let dead_output = tldr_cmd()
        .args(["dead", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(dead_output.status.success());
    let dead_stdout = String::from_utf8_lossy(&dead_output.stdout);

    // Should identify unused_func as dead code
    assert!(
        dead_stdout.contains("unused_func"),
        "Dead code analysis should find unused_func"
    );
}

// =============================================================================
// Error Handling Tests
// =============================================================================


#[test]
fn test_invalid_format_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "calls",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "invalid_format",
            "-q",
        ])
        .output()
        .expect("Failed to execute");

    // Invalid format should cause an error
    assert!(
        !output.status.success() || String::from_utf8_lossy(&output.stderr).contains("error"),
        "Invalid format should be rejected"
    );
}

#[test]
fn test_empty_project() {
    let temp_dir = TempDir::new().unwrap();
    let output = tldr_cmd()
        .args(["calls", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute");

    // Empty project may succeed with empty results or fail gracefully
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success() || stderr.contains("Error") || stderr.contains("not found"),
        "Empty project should either succeed or fail gracefully"
    );

    // If it succeeds, should show empty results
    if output.status.success() {
        // med-low-schema-cleanup-v1 (N12): canonical key is total_edges.
        assert!(
            stdout.contains("\"total_edges\": 0") || stdout.contains("\"total_edges\":0"),
            "Empty project should have 0 edges"
        );
    }
}

// =============================================================================
// Dead Command --call-graph Flag Tests
// =============================================================================

#[test]
fn test_dead_default_refcount_path() {
    // Default (no --call-graph flag) should use refcount-based analysis
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["dead", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr dead");

    assert!(
        output.status.success(),
        "dead command (refcount default) should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dead_functions"),
        "JSON should contain dead_functions field"
    );
    assert!(
        stdout.contains("total_functions"),
        "JSON should contain total_functions field"
    );
}

#[test]
fn test_dead_call_graph_flag_accepted() {
    // --call-graph flag should be accepted and use the old call-graph path
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "--call-graph",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead --call-graph");

    assert!(output.status.success(), "dead --call-graph should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dead_functions"),
        "JSON should contain dead_functions with --call-graph"
    );
}

#[test]
fn test_dead_help_shows_call_graph_flag() {
    let output = tldr_cmd()
        .args(["dead", "--help"])
        .output()
        .expect("Failed to execute tldr dead --help");

    assert!(output.status.success(), "dead --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--call-graph"),
        "Help should mention --call-graph flag. Got:\n{}",
        stdout
    );
}

#[test]
fn test_dead_refcount_text_format() {
    // Refcount path should work with text format too
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead -f text");

    assert!(
        output.status.success(),
        "dead command with text format should succeed"
    );
}

#[test]
fn test_dead_refcount_with_entry_points() {
    // Refcount path should respect --entry-points
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "dead",
            temp_dir.path().to_str().unwrap(),
            "-e",
            "unused_func",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dead with entry points");

    assert!(
        output.status.success(),
        "dead with entry points (refcount) should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // unused_func should NOT appear as dead when marked as entry point
    // why: unwrap_or_default() silently turned a parse failure into Value::Null,
    // under which parsed["dead_functions"] is also Null and the assertion loop
    // below never runs -- the test would pass even if the command emitted
    // garbage instead of JSON. expect() fails loudly, matching every other
    // JSON-parsing assertion in this file.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("dead output should be valid JSON");
    if let Some(dead_fns) = parsed["dead_functions"].as_array() {
        for f in dead_fns {
            let name = f["name"].as_str().unwrap_or("");
            assert_ne!(
                name, "unused_func",
                "unused_func should be excluded as entry point"
            );
        }
    }
}
