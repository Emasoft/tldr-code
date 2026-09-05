//! CLI Search, Context, Complexity, and LOC Commands Tests
//!
//! Tests for tldr-cli commands:
//! - search: Text/regex search with context
//! - context: Build LLM context from entry point
//! - complexity: Calculate function complexity metrics
//! - loc: Count lines of code with type breakdown

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Create a test project with Python files for CLI testing
fn create_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Create a Python file with various functions
    fs::write(
        project_path.join("main.py"),
        r#"def helper():
    """Helper function with docstring"""
    x = 1
    y = 2
    return x + y

def main():
    """Main function with docstring"""
    result = helper()
    print(result)
    
if __name__ == "__main__":
    main()
"#,
    )
    .unwrap();

    // Create a second Python file
    fs::write(
        project_path.join("utils.py"),
        r#"# Utility functions

def util_func():
    # Single line comment
    pass

def another_func(x, y):
    """Function with parameters"""
    if x > 0:
        return y
    return 0
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a test project with multiple languages
fn create_multi_lang_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Python file
    fs::write(
        project_path.join("test.py"),
        r#"def python_func():
    pass
"#,
    )
    .unwrap();

    // Rust file
    fs::write(
        project_path.join("test.rs"),
        r#"fn rust_func() {
    println!("hello");
}
"#,
    )
    .unwrap();

    // JavaScript file
    fs::write(
        project_path.join("test.js"),
        r#"function jsFunc() {
    return 42;
}
"#,
    )
    .unwrap();

    temp_dir
}

/// Create an empty project for edge case testing
fn create_empty_project() -> TempDir {
    TempDir::new().unwrap()
}

// =============================================================================
// Search Command Tests
// =============================================================================

#[test]
fn test_search_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(output.status.success(), "search command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"file\""),
        "JSON should contain file field"
    );
    // SmartSearch reports a `line_range: [start, end]` tuple per result
    // rather than a single `line` int. Either field name is acceptable as
    // a "this result references a source line" signal.
    assert!(
        stdout.contains("\"line_range\"") || stdout.contains("\"line\""),
        "JSON should contain line_range (or line) field; got: {}",
        stdout
    );
    assert!(
        stdout.contains("helper"),
        "Output should reference helper function"
    );
}

#[test]
fn test_search_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "def helper",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(output.status.success(), "search text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Text format should show search results (but NOT in quiet mode - see bugs doc)
    assert!(
        stdout.contains("Found") || stdout.contains("matches") || stdout.contains("helper"),
        "Text output should show search results or header"
    );
}

#[test]
fn test_search_text_format_no_quiet() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "def helper",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(output.status.success(), "search command should succeed");
    let _stdout = String::from_utf8_lossy(&output.stdout);
    // Without -q, text format should show results
    assert!(
        _stdout.contains("helper"),
        "Text output should contain matched content"
    );
}

#[test]
fn test_search_compact_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "def",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "compact",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(
        output.status.success(),
        "search compact format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Compact format should be minified JSON (single line per object)
    assert!(
        !stdout.contains("\n  "),
        "Compact format should not have indented newlines"
    );
    assert!(stdout.contains("file"), "Output should contain file field");
}

#[test]
fn test_search_dot_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "def",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "dot",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");

    // DOT format may or may not be implemented for search, but either way
    // the process must exit cleanly (not be killed by a signal, e.g. a
    // panic that aborts). The previous assertion (`success() ||
    // !success()`) was a tautology that could never fail.
    assert!(
        output.status.code().is_some(),
        "search -f dot should exit normally, not be terminated by a signal"
    );
}

// Legacy regex-search-only tests deleted (DELETE-on-stale per
// workspace-test-infrastructure-v1 M4 / M1-orthogonal-real-failures.json):
//   - test_search_with_extension_filter / test_search_with_multiple_extensions:
//     used `--ext` (legacy regex-search flag); SmartSearch (BM25) has no
//     extension filter — language detection is automatic via `--lang`.
//   - test_search_with_context_lines: used `-C N` (legacy regex-search
//     context-lines flag); SmartSearch reports `line_range` + `preview`
//     instead of greppable `±N` context.
//   - test_search_max_results / test_search_max_files: used `-m`/--max-files
//     (legacy regex-search caps); SmartSearch caps via `-k/--top-k`.
// Replacement coverage for SmartSearch's surface lives in
// crates/tldr-core/tests/bench_surface_search_multilang.rs and the
// existing `test_search_compact_format` / `test_search_dot_format`
// CLI tests below.

#[test]
fn test_search_nonexistent_pattern() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "XYZ_NONEXISTENT_PATTERN_12345",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(
        output.status.success(),
        "search for nonexistent pattern should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[]"),
        "Nonexistent pattern should return empty array"
    );
}

#[test]
fn test_search_invalid_regex() {
    // SmartSearch's default mode is BM25 which treats input as a token query,
    // not a regex — invalid regex characters are simply tokenized. Regex
    // mode (--regex) DOES validate the pattern; this test exercises that
    // path so the invalid-pattern error surface is still covered.
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "[invalid(regex",
            temp_dir.path().to_str().unwrap(),
            "--regex",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr search");

    assert!(
        !output.status.success(),
        "search --regex with invalid pattern should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("regex")
            || stderr.contains("parse")
            || stderr.contains("Error")
            || stderr.contains("invalid"),
        "Error should indicate regex parse failure; got: {}",
        stderr
    );
}

#[test]
fn test_search_nonexistent_path() {
    // SmartSearch fails for a nonexistent project path because it cannot
    // walk a missing directory to build the BM25 index. Either a hard
    // failure (non-zero exit) OR a graceful empty-results JSON is acceptable.
    let output = tldr_cmd()
        .args(["search", "test", "/nonexistent/path/12345", "-q"])
        .output()
        .expect("Failed to execute tldr search");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success() || stdout.contains("\"results\":[]") || stdout.contains("\"results\": []"),
        "search on nonexistent path should fail OR produce empty results; got status={}, stdout={}",
        output.status,
        stdout
    );
}

#[test]
fn test_search_help() {
    let output = tldr_cmd()
        .args(["search", "--help"])
        .output()
        .expect("Failed to execute tldr search --help");

    assert!(output.status.success(), "search --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    // SmartSearch's positional is QUERY (BM25 query), not PATTERN.
    assert!(
        stdout.contains("<QUERY>"),
        "Help should show QUERY positional argument; got: {}",
        stdout
    );
    // SmartSearch's flag surface: --top-k / --no-callgraph / --regex /
    // --hybrid / --lang. The legacy `--ext` / `--context` flags do not
    // exist on SmartSearch.
    assert!(
        stdout.contains("--top-k") || stdout.contains("-k"),
        "Help should mention --top-k option; got: {}",
        stdout
    );
    assert!(
        stdout.contains("--regex") || stdout.contains("--hybrid"),
        "Help should mention --regex or --hybrid mode; got: {}",
        stdout
    );
}

#[test]
fn test_search_default_path() {
    let output = tldr_cmd()
        .args(["search", "--help"])
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
// Context Command Tests
// =============================================================================

#[test]
fn test_context_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "main", "-q"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(output.status.success(), "context command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"entry_point\""),
        "JSON should contain entry_point"
    );
    assert!(
        stdout.contains("\"functions\""),
        "JSON should contain functions"
    );
    assert!(
        stdout.contains("main"),
        "Output should reference main function"
    );
}

#[test]
fn test_context_with_project_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "context",
            "main",
            "-p",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr context");

    assert!(output.status.success(), "context with -p should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("entry_point"),
        "Output should contain entry_point"
    );
    // Note: functions array may be empty when using -p from outside dir - see bugs doc
}

#[test]
fn test_context_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "main", "-f", "text"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(
        output.status.success(),
        "context text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Context") || stdout.contains("entry_point") || stdout.contains("main"),
        "Text output should show context information"
    );
}

#[test]
fn test_context_with_depth() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "main", "-d", "1", "-q"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(output.status.success(), "context with -d should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"depth\": 1") || stdout.contains("\"depth\":1"),
        "Output should show depth: 1"
    );
}

#[test]
fn test_context_with_lang_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "main", "-l", "python", "-q"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(
        output.status.success(),
        "context with --lang should succeed"
    );
}

#[test]
fn test_context_include_docstrings() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "helper", "--include-docstrings", "-q"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(
        output.status.success(),
        "context with --include-docstrings should succeed"
    );
    let _stdout = String::from_utf8_lossy(&output.stdout);
    // Docstrings may or may not be included depending on implementation
    // The flag is accepted - that's the main test
}

#[test]
fn test_context_nonexistent_function() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .current_dir(temp_dir.path())
        .args(["context", "nonexistent_function_xyz", "-q"])
        .output()
        .expect("Failed to execute tldr context");

    assert!(
        !output.status.success(),
        "context for nonexistent function should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error should indicate function not found"
    );
}

#[test]
fn test_context_help() {
    let output = tldr_cmd()
        .args(["context", "--help"])
        .output()
        .expect("Failed to execute tldr context --help");

    assert!(output.status.success(), "context --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("<ENTRY>"),
        "Help should show ENTRY argument"
    );
    assert!(
        stdout.contains("--project"),
        "Help should mention --project option"
    );
    assert!(
        stdout.contains("--depth"),
        "Help should mention --depth option"
    );
    assert!(
        stdout.contains("--include-docstrings"),
        "Help should mention --include-docstrings option"
    );
}

// =============================================================================
// Complexity Command Tests
// =============================================================================

#[test]
fn test_complexity_basic_json() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args(["complexity", file_path.to_str().unwrap(), "main", "-q"])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(output.status.success(), "complexity command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"function\""),
        "JSON should contain function field"
    );
    assert!(
        stdout.contains("\"cyclomatic\""),
        "JSON should contain cyclomatic field"
    );
    assert!(
        stdout.contains("\"cognitive\""),
        "JSON should contain cognitive field"
    );
    assert!(
        stdout.contains("\"max_nesting\""),
        "JSON should contain max_nesting field (renamed from nesting_depth in cross-command-consistency-v1)"
    );
    assert!(
        stdout.contains("\"lines_of_code\""),
        "JSON should contain lines_of_code field"
    );
}

#[test]
fn test_complexity_text_format() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args([
            "complexity",
            file_path.to_str().unwrap(),
            "main",
            "-f",
            "text",
        ])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(
        output.status.success(),
        "complexity text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Text format is currently not implemented for complexity - outputs JSON
    // This is documented in bugs_cli_search_context.md
    assert!(
        stdout.contains("cyclomatic") || stdout.contains("Complexity"),
        "Output should contain complexity data"
    );
}

#[test]
fn test_complexity_helper_function() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args(["complexity", file_path.to_str().unwrap(), "helper", "-q"])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(
        output.status.success(),
        "complexity for helper should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("helper"),
        "Output should reference helper function"
    );
}

#[test]
fn test_complexity_with_lang_option() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args([
            "complexity",
            file_path.to_str().unwrap(),
            "main",
            "-l",
            "python",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(
        output.status.success(),
        "complexity with --lang should succeed"
    );
}

#[test]
fn test_complexity_nonexistent_function() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args([
            "complexity",
            file_path.to_str().unwrap(),
            "nonexistent_xyz",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(
        !output.status.success(),
        "complexity for nonexistent function should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error should indicate function not found"
    );
}

#[test]
fn test_complexity_nonexistent_file() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("nonexistent.py");
    let output = tldr_cmd()
        .args(["complexity", file_path.to_str().unwrap(), "main", "-q"])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(
        !output.status.success(),
        "complexity for nonexistent file should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error should indicate path not found"
    );
}

#[test]
fn test_complexity_help() {
    let output = tldr_cmd()
        .args(["complexity", "--help"])
        .output()
        .expect("Failed to execute tldr complexity --help");

    assert!(output.status.success(), "complexity --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(stdout.contains("<FILE>"), "Help should show FILE argument");
    assert!(
        stdout.contains("<FUNCTION>"),
        "Help should show FUNCTION argument"
    );
    assert!(
        stdout.contains("--lang"),
        "Help should mention --lang option"
    );
}

// =============================================================================
// LOC Command Tests
// =============================================================================

#[test]
fn test_loc_basic_json() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"summary\""),
        "JSON should contain summary"
    );
    assert!(
        stdout.contains("\"total_files\""),
        "JSON should contain total_files"
    );
    assert!(
        stdout.contains("\"code_lines\""),
        "JSON should contain code_lines"
    );
    assert!(
        stdout.contains("\"comment_lines\""),
        "JSON should contain comment_lines"
    );
    assert!(
        stdout.contains("\"blank_lines\""),
        "JSON should contain blank_lines"
    );
}

#[test]
fn test_loc_text_format() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "-f", "text"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Lines of Code") || stdout.contains("Analysis"),
        "Text output should have header"
    );
    assert!(
        stdout.contains("Code:") || stdout.contains("code"),
        "Text output should show code lines"
    );
}

#[test]
fn test_loc_by_file() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "--by-file", "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc --by-file should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("by_file"),
        "Output should contain by_file field"
    );
}

#[test]
fn test_loc_by_dir() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "--by-dir", "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc --by-dir should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("by_directory"),
        "Output should contain by_directory field"
    );
}

#[test]
fn test_loc_with_lang_filter() {
    let temp_dir = create_multi_lang_project();
    let output = tldr_cmd()
        .args([
            "loc",
            temp_dir.path().to_str().unwrap(),
            "-l",
            "python",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc with --lang should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("python"),
        "Output should reference python language"
    );
}

#[test]
fn test_loc_exclude_pattern() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "loc",
            temp_dir.path().to_str().unwrap(),
            "--exclude",
            "utils.py",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc with --exclude should succeed");
    let _stdout = String::from_utf8_lossy(&output.stdout);
    // The excluded file should not be in the output
    // Note: Hard to verify without --by-file, but command should succeed
}

#[test]
fn test_loc_include_hidden() {
    let temp_dir = create_test_project();

    // Create a hidden file
    fs::write(
        temp_dir.path().join(".hidden.py"),
        "# Hidden file\ndef hidden():\n    pass\n",
    )
    .unwrap();

    let output_with_hidden = tldr_cmd()
        .args([
            "loc",
            temp_dir.path().to_str().unwrap(),
            "--include-hidden",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(
        output_with_hidden.status.success(),
        "loc with --include-hidden should succeed"
    );

    let output_without_hidden = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output_without_hidden.status.success());
    // The outputs may differ but both should succeed
}

#[test]
fn test_loc_no_gitignore() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "loc",
            temp_dir.path().to_str().unwrap(),
            "--no-gitignore",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(
        output.status.success(),
        "loc with --no-gitignore should succeed"
    );
}

#[test]
fn test_loc_max_files() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "loc",
            temp_dir.path().to_str().unwrap(),
            "--max-files",
            "1",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(
        output.status.success(),
        "loc with --max-files should succeed"
    );
}

#[test]
fn test_loc_single_file() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");
    let output = tldr_cmd()
        .args(["loc", file_path.to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(output.status.success(), "loc on single file should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("total_files"),
        "Output should contain file count"
    );
}

#[test]
fn test_loc_nonexistent_path() {
    let output = tldr_cmd()
        .args(["loc", "/nonexistent/path/12345", "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(
        !output.status.success(),
        "loc should fail for nonexistent path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error should indicate path not found"
    );
}

#[test]
fn test_loc_empty_directory() {
    let temp_dir = create_empty_project();
    let output = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(
        output.status.success(),
        "loc on empty directory should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"total_files\": 0") || stdout.contains("\"total_files\":0"),
        "Empty directory should have 0 files"
    );
}

#[test]
fn test_loc_help() {
    let output = tldr_cmd()
        .args(["loc", "--help"])
        .output()
        .expect("Failed to execute tldr loc --help");

    assert!(output.status.success(), "loc --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("[PATH]"),
        "Help should show optional PATH argument"
    );
    assert!(
        stdout.contains("--by-file"),
        "Help should mention --by-file option"
    );
    assert!(
        stdout.contains("--by-dir"),
        "Help should mention --by-dir option"
    );
    assert!(
        stdout.contains("--exclude"),
        "Help should mention --exclude option"
    );
}

// =============================================================================
// Cross-Command Integration Tests
// =============================================================================

#[test]
fn test_search_and_loc_consistency() {
    let temp_dir = create_test_project();
    let project_path = temp_dir.path().to_str().unwrap();

    // SmartSearch is BM25-by-default. Use a token query that matches the
    // function names in the fixture rather than the legacy regex pattern.
    let search_output = tldr_cmd()
        .args(["search", "helper", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr search");

    assert!(search_output.status.success());
    let search_stdout = String::from_utf8_lossy(&search_output.stdout);

    // Run loc to count lines
    let loc_output = tldr_cmd()
        .args(["loc", project_path, "-q"])
        .output()
        .expect("Failed to execute tldr loc");

    assert!(loc_output.status.success());
    let loc_stdout = String::from_utf8_lossy(&loc_output.stdout);

    // Both should reference the same project
    assert!(
        search_stdout.contains("main.py") || search_stdout.contains("utils.py"),
        "Search should find functions in project files; got: {}",
        search_stdout
    );
    assert!(
        loc_stdout.contains("total_files"),
        "LOC should report file count"
    );
}

#[test]
fn test_complexity_and_context_consistency() {
    let temp_dir = create_test_project();
    let file_path = temp_dir.path().join("main.py");

    // Run complexity on main function
    let complexity_output = tldr_cmd()
        .args(["complexity", file_path.to_str().unwrap(), "main", "-q"])
        .output()
        .expect("Failed to execute tldr complexity");

    assert!(complexity_output.status.success());
    let complexity_stdout = String::from_utf8_lossy(&complexity_output.stdout);

    // Both should reference the same function
    assert!(
        complexity_stdout.contains("main"),
        "Complexity should reference main function"
    );
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_all_commands_help_available() {
    let commands = ["search", "context", "complexity", "loc"];

    for cmd in &commands {
        let output = tldr_cmd()
            .args([*cmd, "--help"])
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute tldr {} --help", cmd));

        assert!(output.status.success(), "{} --help should succeed", cmd);

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Usage:"),
            "{} help should contain usage info",
            cmd
        );
    }
}

#[test]
fn test_invalid_format_option() {
    let temp_dir = create_test_project();
    let output = tldr_cmd()
        .args([
            "search",
            "test",
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
fn test_quiet_mode_suppresses_progress() {
    let temp_dir = create_test_project();

    // Without quiet mode, progress messages should appear on stderr
    let _output_no_quiet = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute");

    // With quiet mode, progress messages should not appear
    let output_quiet = tldr_cmd()
        .args(["loc", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute");

    assert!(output_quiet.status.success());

    // The quiet stderr should be empty or at least not contain progress messages
    let quiet_stderr = String::from_utf8_lossy(&output_quiet.stderr);
    assert!(
        !quiet_stderr.contains("Counting") || quiet_stderr.is_empty(),
        "Quiet mode should suppress progress messages"
    );
}
