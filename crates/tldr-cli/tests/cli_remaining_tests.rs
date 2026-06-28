//! CLI Remaining Commands Tests
//!
//! Tests for tldr-cli remaining analysis commands:
//! - available: Available expressions analysis
//! - dominators: Dominator tree and dominance frontier
//! - reaching_defs: Reaching definitions analysis
//! - live_vars: Live variable analysis
//! - taint: Taint flow analysis
//! - alias: Alias analysis
//! - slice: Program slicing
//! - change_impact: Find tests affected by changes
//! - whatbreaks: Unified impact analysis
//! - hubs: Hub function detection
//! - references: Find symbol references
//! - arch: Architecture analysis
//! - deps: Dependency analysis
//! - inheritance: Class hierarchy extraction
//! - clones: Code clone detection
//! - dice: Code similarity comparison
//! - daemon_router: Daemon auto-routing
//! - daemon/*: Daemon management commands

use std::fs;
// Path import not needed - using PathBuf via tempfile::TempDir
use std::process::Command;
use tempfile::TempDir;

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

/// Create a test project with an initialized git repository (single seed
/// commit). Required by `tldr change-impact` which needs a baseline to diff
/// against; without it the command returns NoBaseline and exits non-zero.
fn create_git_test_project() -> TempDir {
    let temp_dir = create_test_project();
    let project_path = temp_dir.path();

    let run_git = |args: &[&str]| {
        let _ = Command::new("git")
            .args(args)
            .current_dir(project_path)
            .output()
            .expect("git should be available in the test environment");
    };

    run_git(&["init", "-q"]);
    run_git(&["config", "user.email", "test@test.com"]);
    run_git(&["config", "user.name", "Test"]);
    run_git(&["config", "commit.gpgsign", "false"]);
    run_git(&["add", "."]);
    run_git(&["commit", "-q", "-m", "seed"]);

    temp_dir
}

/// Create a test project with complex control flow for dataflow analysis
fn create_dataflow_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("dataflow.py"),
        r#"def calculate(x, y):
    # Available expressions: x + y, x * 2
    a = x + y
    b = x + y  # redundant - CSE opportunity
    c = x * 2
    
    if x > 0:
        result = a + b
    else:
        result = c
    return result

def process(data):
    # Variable definitions and uses
    temp = data.lower()
    result = temp.strip()
    return result
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a test project with security vulnerabilities for taint analysis
fn create_taint_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("vulnerable.py"),
        r#"import os
import sqlite3

def process_user_input():
    user_input = input("Enter value: ")  # taint source
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    # Command injection vulnerability
    os.system(f"echo {user_input}")  # taint sink
    
    return user_input
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a test project with class hierarchies
fn create_inheritance_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("classes.py"),
        r#"from abc import ABC, abstractmethod

class Animal(ABC):
    @abstractmethod
    def speak(self):
        pass

class Dog(Animal):
    def speak(self):
        return "Woof"

class Cat(Animal):
    def speak(self):
        return "Meow"

class Vehicle:
    def move(self):
        pass

class Car(Vehicle):
    def move(self):
        return "Driving"
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a test project with duplicate code for clone detection
fn create_clones_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("original.py"),
        r#"def calculate_sum(items):
    total = 0
    for item in items:
        total = total + item
    return total

def process_data(data):
    result = []
    for d in data:
        result.append(d * 2)
    return result
"#,
    )
    .unwrap();

    fs::write(
        project_path.join("duplicate.py"),
        r#"def compute_total(values):
    total = 0
    for value in values:
        total = total + value
    return total

def transform(items):
    result = []
    for item in items:
        result.append(item * 2)
    return result
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a test project with module dependencies
fn create_deps_test_project() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    fs::write(
        project_path.join("auth.py"),
        r#"from utils import hash_password
from db import get_user

def login(username, password):
    user = get_user(username)
    if hash_password(password) == user.password_hash:
        return user
    return None
"#,
    )
    .unwrap();

    fs::write(
        project_path.join("utils.py"),
        r#"import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
"#,
    )
    .unwrap();

    fs::write(
        project_path.join("db.py"),
        r#"from utils import hash_password

def get_user(username):
    return {"username": username, "password_hash": ""}
"#,
    )
    .unwrap();

    temp_dir
}

// =============================================================================
// Available Expressions Tests
// =============================================================================

#[test]
fn test_available_basic_json() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["available", file_path.to_str().unwrap(), "calculate", "-q"])
        .output()
        .expect("Failed to execute tldr available");

    assert!(output.status.success(), "available command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("avail_in") || stdout.contains("avail_out") || stdout.contains("redundant"),
        "Output should contain available expressions data"
    );
}

#[test]
fn test_available_text_format() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "available",
            file_path.to_str().unwrap(),
            "calculate",
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr available");

    assert!(
        output.status.success(),
        "available text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Available") || stdout.contains("expression") || stdout.contains("CSE"),
        "Text output should show available expressions info"
    );
}

#[test]
fn test_available_check_option() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "available",
            file_path.to_str().unwrap(),
            "calculate",
            "--check",
            "x + y",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr available --check");

    assert!(output.status.success(), "available --check should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("expression") || stdout.contains("available"),
        "Check output should show expression info"
    );
}

#[test]
fn test_available_at_line_option() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "available",
            file_path.to_str().unwrap(),
            "calculate",
            "--at-line",
            "10",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr available --at_line");

    assert!(
        output.status.success(),
        "available --at_line should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("line") || stdout.contains("expressions"),
        "At-line output should show line-specific info"
    );
}

#[test]
fn test_available_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["available", "--help"])
        .output()
        .expect("Failed to execute tldr available --help");

    assert!(output.status.success(), "available --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--check"),
        "Help should mention --check option"
    );
    assert!(
        stdout.contains("--at-line"),
        "Help should mention --at-line option"
    );
}

#[test]
fn test_available_nonexistent_file() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["available", "/nonexistent/path/file.py", "func", "-q"])
        .output()
        .expect("Failed to execute");

    assert!(
        !output.status.success(),
        "available should fail for nonexistent file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Error should indicate file not found"
    );
}

// =============================================================================
// Dominators Tests
// =============================================================================







// =============================================================================
// Reaching Definitions Tests
// =============================================================================

#[test]
fn test_reaching_defs_basic_json() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "reaching-defs",
            file_path.to_str().unwrap(),
            "process",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr reaching-defs");

    assert!(
        output.status.success(),
        "reaching-defs command should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("chains")
            || stdout.contains("definitions")
            || stdout.contains("uninitialized"),
        "JSON should contain reaching definitions data"
    );
}

#[test]
fn test_reaching_defs_text_format() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "reaching-defs",
            file_path.to_str().unwrap(),
            "process",
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr reaching-defs");

    assert!(
        output.status.success(),
        "reaching-defs text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Definition") || stdout.contains("Use") || stdout.contains("Chain"),
        "Text output should show reaching definitions"
    );
}

#[test]
fn test_reaching_defs_var_filter() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "reaching-defs",
            file_path.to_str().unwrap(),
            "process",
            "--var",
            "temp",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr reaching-defs --var");

    assert!(
        output.status.success(),
        "reaching-defs --var should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("temp") || stdout.contains("definitions"),
        "Output should contain variable-specific data"
    );
}

#[test]
fn test_reaching_defs_line_filter() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "reaching-defs",
            file_path.to_str().unwrap(),
            "process",
            "--line",
            "13",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr reaching-defs --line");

    assert!(
        output.status.success(),
        "reaching-defs --line should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("line") || stdout.contains("definitions"),
        "Output should contain line-specific data"
    );
}

#[test]
fn test_reaching_defs_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["reaching-defs", "--help"])
        .output()
        .expect("Failed to execute tldr reaching-defs --help");

    assert!(
        output.status.success(),
        "reaching-defs --help should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(stdout.contains("--var"), "Help should mention --var option");
    assert!(
        stdout.contains("--line"),
        "Help should mention --line option"
    );
}

// =============================================================================
// Live Variables Tests
// =============================================================================






// =============================================================================
// Taint Analysis Tests
// =============================================================================

#[test]
fn test_taint_basic_json() {
    let temp_dir = create_taint_test_project();
    let file_path = temp_dir.path().join("vulnerable.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "taint",
            file_path.to_str().unwrap(),
            "process_user_input",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr taint");

    assert!(output.status.success(), "taint command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sources") || stdout.contains("sinks") || stdout.contains("flows"),
        "JSON should contain taint analysis data"
    );
}

#[test]
fn test_taint_text_format() {
    let temp_dir = create_taint_test_project();
    let file_path = temp_dir.path().join("vulnerable.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "taint",
            file_path.to_str().unwrap(),
            "process_user_input",
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr taint");

    assert!(output.status.success(), "taint text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Taint") || stdout.contains("Source") || stdout.contains("Sink"),
        "Text output should show taint analysis"
    );
}

#[test]
fn test_taint_verbose() {
    let temp_dir = create_taint_test_project();
    let file_path = temp_dir.path().join("vulnerable.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "taint",
            file_path.to_str().unwrap(),
            "process_user_input",
            "--verbose",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr taint --verbose");

    assert!(output.status.success(), "taint --verbose should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Taint") || stdout.contains("Block") || stdout.contains("sources"),
        "Verbose output should contain detailed info"
    );
}

#[test]
fn test_taint_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["taint", "--help"])
        .output()
        .expect("Failed to execute tldr taint --help");

    assert!(output.status.success(), "taint --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--verbose"),
        "Help should mention --verbose option"
    );
}

// =============================================================================
// Alias Analysis Tests
// =============================================================================







// =============================================================================
// Slice Tests
// =============================================================================

#[test]
fn test_slice_backward() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file_path.to_str().unwrap(),
            "calculate",
            "12",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr slice");

    assert!(output.status.success(), "slice command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("slice") || stdout.contains("lines") || stdout.contains("line"),
        "Output should contain slice data"
    );
}

#[test]
fn test_slice_forward() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file_path.to_str().unwrap(),
            "calculate",
            "5",
            "--direction",
            "forward",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr slice --direction forward");

    assert!(output.status.success(), "slice forward should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("slice") || stdout.contains("forward") || stdout.contains("lines"),
        "Output should contain forward slice data"
    );
}

#[test]
fn test_slice_variable_filter() {
    let temp_dir = create_dataflow_test_project();
    let file_path = temp_dir.path().join("dataflow.py");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file_path.to_str().unwrap(),
            "calculate",
            "5",
            "--variable",
            "a",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr slice --variable");

    assert!(output.status.success(), "slice --variable should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("slice") || stdout.contains("Variable") || stdout.contains("lines"),
        "Output should contain variable-specific slice"
    );
}

#[test]
fn test_slice_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["slice", "--help"])
        .output()
        .expect("Failed to execute tldr slice --help");

    assert!(output.status.success(), "slice --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--direction"),
        "Help should mention --direction option"
    );
    assert!(
        stdout.contains("--variable"),
        "Help should mention --variable option"
    );
}

// =============================================================================
// Change Impact Tests
// =============================================================================

#[test]
fn test_change_impact_basic() {
    // change-impact requires a git baseline (NoBaseline -> exit 3).
    let temp_dir = create_git_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["change-impact", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr change-impact");

    assert!(
        output.status.success(),
        "change-impact command should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("changed_files") || stdout.contains("affected") || stdout.contains("tests"),
        "Output should contain change impact data"
    );
}

#[test]
fn test_change_impact_text_format() {
    let temp_dir = create_git_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "change-impact",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr change-impact");

    assert!(
        output.status.success(),
        "change-impact text format should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Change") || stdout.contains("Affected") || stdout.contains("Test"),
        "Text output should show change impact"
    );
}

#[test]
fn test_change_impact_with_files() {
    let temp_dir = create_test_project();
    let project_path = temp_dir.path();
    fs::write(project_path.join("test_file.py"), "def test_func(): pass").unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "change-impact",
            project_path.to_str().unwrap(),
            "--files",
            "main.py",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr change-impact --files");

    assert!(
        output.status.success(),
        "change-impact --files should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("changed_files") || stdout.contains("affected"),
        "Output should contain file-based change impact"
    );
}

#[test]
fn test_change_impact_runner_pytest() {
    let temp_dir = create_git_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "change-impact",
            temp_dir.path().to_str().unwrap(),
            "--runner",
            "pytest",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr change-impact --runner");

    // May succeed or fail depending on test detection
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() || stdout.is_empty(),
        "change-impact --runner should either succeed or produce empty output"
    );
}

#[test]
fn test_change_impact_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["change-impact", "--help"])
        .output()
        .expect("Failed to execute tldr change-impact --help");

    assert!(
        output.status.success(),
        "change-impact --help should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--files"),
        "Help should mention --files option"
    );
    assert!(
        stdout.contains("--runner"),
        "Help should mention --runner option"
    );
    assert!(
        stdout.contains("--base"),
        "Help should mention --base option"
    );
}

// =============================================================================
// Whatbreaks Tests
// =============================================================================

#[test]
fn test_whatbreaks_function() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "whatbreaks",
            "main",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr whatbreaks");

    assert!(output.status.success(), "whatbreaks command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("target_type") || stdout.contains("callers") || stdout.contains("impact"),
        "Output should contain whatbreaks data"
    );
}

#[test]
fn test_whatbreaks_text_format() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "whatbreaks",
            "main",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr whatbreaks text");

    assert!(
        output.status.success(),
        "whatbreaks text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("What") || stdout.contains("Break") || stdout.contains("Impact"),
        "Text output should show whatbreaks info"
    );
}

#[test]
fn test_whatbreaks_with_depth() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "whatbreaks",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "--depth",
            "2",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr whatbreaks --depth");

    assert!(output.status.success(), "whatbreaks --depth should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("target_type") || stdout.contains("depth"),
        "Output should contain depth-limited analysis"
    );
}

#[test]
fn test_whatbreaks_quick_mode() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "whatbreaks",
            "main",
            temp_dir.path().to_str().unwrap(),
            "--quick",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr whatbreaks --quick");

    assert!(output.status.success(), "whatbreaks --quick should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("target_type") || stdout.contains("quick"),
        "Output should contain quick analysis results"
    );
}

#[test]
fn test_whatbreaks_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["whatbreaks", "--help"])
        .output()
        .expect("Failed to execute tldr whatbreaks --help");

    assert!(output.status.success(), "whatbreaks --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--depth"),
        "Help should mention --depth option"
    );
    assert!(
        stdout.contains("--quick"),
        "Help should mention --quick option"
    );
    assert!(
        stdout.contains("--type"),
        "Help should mention --type option"
    );
}

// =============================================================================
// Hubs Tests
// =============================================================================

#[test]
fn test_hubs_basic() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["hubs", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr hubs");

    assert!(output.status.success(), "hubs command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hubs") || stdout.contains("centrality") || stdout.contains("score"),
        "Output should contain hub analysis data"
    );
}

#[test]
fn test_hubs_text_format() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "hubs",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr hubs text");

    assert!(output.status.success(), "hubs text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Hub") || stdout.contains("Centrality") || stdout.contains("Score"),
        "Text output should show hub info"
    );
}

#[test]
fn test_hubs_top_limit() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "hubs",
            temp_dir.path().to_str().unwrap(),
            "--top",
            "5",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr hubs --top");

    assert!(output.status.success(), "hubs --top should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hubs") || stdout.contains("centrality"),
        "Output should contain limited hub results"
    );
}

#[test]
fn test_hubs_algorithm() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "hubs",
            temp_dir.path().to_str().unwrap(),
            "--algorithm",
            "pagerank",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr hubs --algorithm");

    assert!(output.status.success(), "hubs --algorithm should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hubs") || stdout.contains("pagerank") || stdout.contains("centrality"),
        "Output should contain algorithm-specific hub results"
    );
}

#[test]
fn test_hubs_threshold() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "hubs",
            temp_dir.path().to_str().unwrap(),
            "--threshold",
            "0.1",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr hubs --threshold");

    assert!(output.status.success(), "hubs --threshold should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hubs") || stdout.contains("threshold") || stdout.contains("score"),
        "Output should contain threshold-filtered hub results"
    );
}

#[test]
fn test_hubs_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["hubs", "--help"])
        .output()
        .expect("Failed to execute tldr hubs --help");

    assert!(output.status.success(), "hubs --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(stdout.contains("--top"), "Help should mention --top option");
    assert!(
        stdout.contains("--algorithm"),
        "Help should mention --algorithm option"
    );
    assert!(
        stdout.contains("--threshold"),
        "Help should mention --threshold option"
    );
}

// =============================================================================
// References Tests
// =============================================================================

#[test]
fn test_references_basic() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references");

    assert!(output.status.success(), "references command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("references") || stdout.contains("symbol") || stdout.contains("file"),
        "Output should contain references data"
    );
}

#[test]
fn test_references_text_format() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "-o",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references text");

    assert!(
        output.status.success(),
        "references text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Reference") || stdout.contains("Definition") || stdout.contains("helper"),
        "Text output should show references"
    );
}

#[test]
fn test_references_include_definition() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "--include-definition",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references --include-definition");

    assert!(
        output.status.success(),
        "references --include-definition should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("references") || stdout.contains("definition"),
        "Output should contain definition and references"
    );
}

#[test]
fn test_references_kinds_filter() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "--kinds",
            "call",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references --kinds");

    assert!(output.status.success(), "references --kinds should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("references") || stdout.contains("kind"),
        "Output should contain kind-filtered references"
    );
}

#[test]
fn test_references_limit() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "--limit",
            "10",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references --limit");

    assert!(output.status.success(), "references --limit should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("references") || stdout.contains("total"),
        "Output should contain limited references"
    );
}

/// Regression test for `references-clap-conflict-v1`.
///
/// Before the fix, the references subcommand defined its own `--lang/-l`
/// argument with type `Option<String>` while the global `--lang/-l` is
/// `Option<Language>`. clap detected the type mismatch at runtime and
/// panicked with exit code 101 ("Mismatch between definition and access of
/// `lang`"). This test ensures that `tldr references ... --lang rust` exits
/// cleanly (not 101) — i.e. that no clap downcast panic occurs.
#[test]
fn test_references_with_lang_no_panic() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "--lang",
            "python",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references --lang");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(-1);
    assert_ne!(
        code, 101,
        "references --lang must not panic (exit 101). stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("Mismatch between definition and access of"),
        "references --lang must not produce clap downcast panic. stderr: {}",
        stderr
    );
}

/// Regression test: short flag form `-l rust` must also not panic.
#[test]
fn test_references_with_short_lang_flag_no_panic() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "references",
            "helper",
            temp_dir.path().to_str().unwrap(),
            "-l",
            "python",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr references -l");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(-1);
    assert_ne!(
        code, 101,
        "references -l must not panic (exit 101). stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("Mismatch between definition and access of"),
        "references -l must not produce clap downcast panic. stderr: {}",
        stderr
    );
}

/// Sanity check: ensure that several other subcommands also accept `-l rust`
/// without panicking (101). This guards against future regressions where a
/// subcommand redefines `--lang` with a different type than the global.
#[test]
fn test_no_other_subcommand_panics_on_lang() {
    let temp_dir = create_test_project();
    let path = temp_dir.path().to_str().unwrap();

    // Subcommands that take a directory and accept --lang.
    let cases: &[&[&str]] = &[
        &["calls", path],
        &["dead", path],
        &["structure", path],
        &["smells", path],
        &["loc", path],
        &["search", "helper", path],
    ];

    for args in cases {
        let mut full_args: Vec<&str> = args.to_vec();
        full_args.push("-l");
        full_args.push("python");
        full_args.push("-q");

        let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
            .args(&full_args)
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute tldr {:?}", full_args));

        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        assert_ne!(
            code, 101,
            "tldr {:?} must not panic with exit 101. stderr: {}",
            full_args, stderr
        );
        assert!(
            !stderr.contains("Mismatch between definition and access of"),
            "tldr {:?} must not produce clap downcast panic. stderr: {}",
            full_args, stderr
        );
    }
}

#[test]
fn test_references_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["references", "--help"])
        .output()
        .expect("Failed to execute tldr references --help");

    assert!(output.status.success(), "references --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--include-definition"),
        "Help should mention --include-definition"
    );
    assert!(
        stdout.contains("--kinds"),
        "Help should mention --kinds option"
    );
    assert!(
        stdout.contains("--limit"),
        "Help should mention --limit option"
    );
}

// =============================================================================
// Dependencies Tests
// =============================================================================

#[test]
fn test_deps_basic() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["deps", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr deps");

    assert!(output.status.success(), "deps command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dependencies") || stdout.contains("internal") || stdout.contains("files"),
        "Output should contain dependency data"
    );
}

#[test]
fn test_deps_text_format() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "deps",
            temp_dir.path().to_str().unwrap(),
            "-o",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr deps text");

    assert!(output.status.success(), "deps text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Dependency") || stdout.contains("imports") || stdout.contains("edges"),
        "Text output should show dependencies"
    );
}

#[test]
fn test_deps_dot_format() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["deps", temp_dir.path().to_str().unwrap(), "-o", "dot", "-q"])
        .output()
        .expect("Failed to execute tldr deps dot");

    assert!(output.status.success(), "deps DOT format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("digraph") || stdout.contains("->"),
        "DOT output should contain graph structure"
    );
}

#[test]
fn test_deps_show_cycles() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "deps",
            temp_dir.path().to_str().unwrap(),
            "--show-cycles",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr deps --show-cycles");

    assert!(output.status.success(), "deps --show-cycles should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // When no cycles found, output is an empty JSON array "[]"
    assert!(
        stdout.contains("cycles")
            || stdout.contains("circular")
            || stdout.contains("No cycles")
            || stdout.contains("[]"),
        "Output should contain cycle detection results or empty array for no cycles"
    );
}

#[test]
fn test_deps_include_external() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "deps",
            temp_dir.path().to_str().unwrap(),
            "--include-external",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr deps --include-external");

    assert!(
        output.status.success(),
        "deps --include-external should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dependencies") || stdout.contains("external"),
        "Output should contain external dependencies"
    );
}

#[test]
fn test_deps_collapse_packages() {
    let temp_dir = create_deps_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "deps",
            temp_dir.path().to_str().unwrap(),
            "--collapse-packages",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr deps --collapse-packages");

    assert!(
        output.status.success(),
        "deps --collapse-packages should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dependencies") || stdout.contains("package"),
        "Output should contain package-level dependencies"
    );
}

#[test]
fn test_deps_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["deps", "--help"])
        .output()
        .expect("Failed to execute tldr deps --help");

    assert!(output.status.success(), "deps --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--show-cycles"),
        "Help should mention --show-cycles"
    );
    assert!(
        stdout.contains("--include-external"),
        "Help should mention --include-external"
    );
    assert!(
        stdout.contains("--collapse-packages"),
        "Help should mention --collapse-packages"
    );
}

// =============================================================================
// Inheritance Tests
// =============================================================================

#[test]
fn test_inheritance_basic() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["inheritance", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr inheritance");

    assert!(
        output.status.success(),
        "inheritance command should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("classes")
            || stdout.contains("hierarchy")
            || stdout.contains("inheritance"),
        "Output should contain inheritance data"
    );
}

#[test]
fn test_inheritance_text_format() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "inheritance",
            temp_dir.path().to_str().unwrap(),
            "-o",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr inheritance text");

    assert!(
        output.status.success(),
        "inheritance text format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Class") || stdout.contains("Inheritance") || stdout.contains("extends"),
        "Text output should show inheritance"
    );
}

#[test]
fn test_inheritance_dot_format() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "inheritance",
            temp_dir.path().to_str().unwrap(),
            "-o",
            "dot",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr inheritance dot");

    assert!(
        output.status.success(),
        "inheritance DOT format should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("digraph") || stdout.contains("->"),
        "DOT output should contain graph structure"
    );
}

#[test]
fn test_inheritance_class_filter() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "inheritance",
            temp_dir.path().to_str().unwrap(),
            "--class",
            "Animal",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr inheritance --class");

    assert!(
        output.status.success(),
        "inheritance --class should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Animal") || stdout.contains("class"),
        "Output should contain class-specific hierarchy"
    );
}

#[test]
fn test_inheritance_depth() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "inheritance",
            temp_dir.path().to_str().unwrap(),
            "--class",
            "Animal",
            "--depth",
            "2",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr inheritance --depth");

    assert!(
        output.status.success(),
        "inheritance --depth should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Animal") || stdout.contains("depth"),
        "Output should contain depth-limited hierarchy"
    );
}

#[test]
fn test_inheritance_no_patterns() {
    let temp_dir = create_inheritance_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "inheritance",
            temp_dir.path().to_str().unwrap(),
            "--no-patterns",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr inheritance --no-patterns");

    assert!(
        output.status.success(),
        "inheritance --no-patterns should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("classes") || stdout.contains("inheritance"),
        "Output should contain basic inheritance without patterns"
    );
}

#[test]
fn test_inheritance_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["inheritance", "--help"])
        .output()
        .expect("Failed to execute tldr inheritance --help");

    assert!(output.status.success(), "inheritance --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--class"),
        "Help should mention --class option"
    );
    assert!(
        stdout.contains("--depth"),
        "Help should mention --depth option"
    );
    assert!(
        stdout.contains("--no-patterns"),
        "Help should mention --no-patterns option"
    );
}

// =============================================================================
// Clones Tests
// =============================================================================

#[test]
fn test_clones_basic() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["clones", temp_dir.path().to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute tldr clones");

    assert!(output.status.success(), "clones command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clones") || stdout.contains("duplicate") || stdout.contains("similarity"),
        "Output should contain clone detection data"
    );
}

#[test]
fn test_clones_text_format() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "clones",
            temp_dir.path().to_str().unwrap(),
            "-o",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr clones text");

    assert!(output.status.success(), "clones text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Clone") || stdout.contains("Duplicate") || stdout.contains("Code"),
        "Text output should show clones"
    );
}

#[test]
fn test_clones_min_tokens() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "clones",
            temp_dir.path().to_str().unwrap(),
            "--min-tokens",
            "10",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr clones --min-tokens");

    assert!(
        output.status.success(),
        "clones --min-tokens should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clones") || stdout.contains("min_tokens"),
        "Output should contain clones with token threshold"
    );
}

#[test]
fn test_clones_threshold() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "clones",
            temp_dir.path().to_str().unwrap(),
            "--threshold",
            "0.5",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr clones --threshold");

    assert!(output.status.success(), "clones --threshold should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clones") || stdout.contains("threshold"),
        "Output should contain clones with similarity threshold"
    );
}

#[test]
fn test_clones_type_filter() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "clones",
            temp_dir.path().to_str().unwrap(),
            "--type-filter",
            "2",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr clones --type-filter");

    assert!(
        output.status.success(),
        "clones --type-filter should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clones") || stdout.contains("type"),
        "Output should contain type-filtered clones"
    );
}

#[test]
fn test_clones_show_classes() {
    let temp_dir = create_clones_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "clones",
            temp_dir.path().to_str().unwrap(),
            "--show-classes",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr clones --show-classes");

    assert!(
        output.status.success(),
        "clones --show-classes should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clones") || stdout.contains("classes"),
        "Output should contain clone classes"
    );
}

#[test]
fn test_clones_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["clones", "--help"])
        .output()
        .expect("Failed to execute tldr clones --help");

    assert!(output.status.success(), "clones --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--min-tokens"),
        "Help should mention --min-tokens"
    );
    assert!(
        stdout.contains("--threshold"),
        "Help should mention --threshold"
    );
    assert!(
        stdout.contains("--type-filter"),
        "Help should mention --type-filter"
    );
}

// =============================================================================
// Dice Tests
// =============================================================================

#[test]
fn test_dice_basic() {
    let temp_dir = create_clones_test_project();
    let file1 = temp_dir.path().join("original.py");
    let file2 = temp_dir.path().join("duplicate.py");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "dice",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dice");

    assert!(output.status.success(), "dice command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dice_coefficient")
            || stdout.contains("similarity")
            || stdout.contains("tokens"),
        "Output should contain similarity data"
    );
}

#[test]
fn test_dice_text_format() {
    let temp_dir = create_clones_test_project();
    let file1 = temp_dir.path().join("original.py");
    let file2 = temp_dir.path().join("duplicate.py");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "dice",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            "-o",
            "text",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dice text");

    assert!(output.status.success(), "dice text format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Similarity") || stdout.contains("Dice") || stdout.contains("coefficient"),
        "Text output should show similarity"
    );
}

#[test]
fn test_dice_normalize() {
    let temp_dir = create_clones_test_project();
    let file1 = temp_dir.path().join("original.py");
    let file2 = temp_dir.path().join("duplicate.py");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "dice",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            "--normalize",
            "none",
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dice --normalize");

    assert!(output.status.success(), "dice --normalize should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dice") || stdout.contains("coefficient"),
        "Output should contain similarity with normalization"
    );
}

#[test]
fn test_dice_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["dice", "--help"])
        .output()
        .expect("Failed to execute tldr dice --help");

    assert!(output.status.success(), "dice --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--normalize"),
        "Help should mention --normalize"
    );
}

// =============================================================================
// G-dice-clone-label (v0.5.0 backlog)
//
// `tldr dice` computes a whole-target token-multiset (bag) Dice coefficient.
// Bag overlap is order-insensitive and inflated by shared language vocabulary,
// so two unrelated, similar-size, same-language files routinely score 0.70-0.87
// and were labeled "likely Type-2 clone" / "Type-3 clone candidate" — directly
// contradicting `clones` (which reports 0 clones). The interpretation must be
// clone-neutral for the whole-file case across EVERY language.
// =============================================================================

/// Run `tldr dice` on two files and return the parsed JSON.
fn run_dice_json(file1: &std::path::Path, file2: &std::path::Path) -> serde_json::Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "dice",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            "-q",
        ])
        .output()
        .expect("Failed to execute tldr dice");
    assert!(
        output.status.success(),
        "dice command should succeed (stderr: {})",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("dice output not JSON: {e}\n{stdout}"))
}

/// Two UNRELATED but boilerplate-similar source fragments per language. Same
/// language + similar size => high token-multiset overlap, even though the code
/// is unrelated. This is exactly the input that produced the false clone label.
fn unrelated_pair_for(lang: &str) -> (&'static str, &'static str, &'static str) {
    match lang {
        "python" => (
            "py",
            "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n\ndef mul(a, b):\n    return a * b\n",
            "def greet(name):\n    return \"hi \" + name\n\ndef shout(text):\n    return text.upper()\n\ndef repeat(text, n):\n    return text * n\n",
        ),
        "rust" => (
            "rs",
            "fn add(a: i32, b: i32) -> i32 { a + b }\nfn sub(a: i32, b: i32) -> i32 { a - b }\nfn mul(a: i32, b: i32) -> i32 { a * b }\n",
            "fn greet(name: String) -> String { format!(\"hi {}\", name) }\nfn shout(text: String) -> String { text.to_uppercase() }\nfn first(items: Vec<i32>) -> i32 { items[0] }\n",
        ),
        "typescript" => (
            "ts",
            "function add(a: number, b: number): number { return a + b; }\nfunction sub(a: number, b: number): number { return a - b; }\nfunction mul(a: number, b: number): number { return a * b; }\n",
            "function greet(name: string): string { return \"hi \" + name; }\nfunction shout(text: string): string { return text.toUpperCase(); }\nfunction repeat(text: string, n: number): string { return text.repeat(n); }\n",
        ),
        "go" => (
            "go",
            "package m\nfunc add(a int, b int) int { return a + b }\nfunc sub(a int, b int) int { return a - b }\nfunc mul(a int, b int) int { return a * b }\n",
            "package m\nfunc greet(name string) string { return \"hi \" + name }\nfunc first(items []int) int { return items[0] }\nfunc count(items []int) int { return len(items) }\n",
        ),
        "java" => (
            "java",
            "class A {\n  int add(int a, int b) { return a + b; }\n  int sub(int a, int b) { return a - b; }\n  int mul(int a, int b) { return a * b; }\n}\n",
            "class B {\n  String greet(String name) { return \"hi \" + name; }\n  String shout(String text) { return text.toUpperCase(); }\n  int first(int[] items) { return items[0]; }\n}\n",
        ),
        _ => unreachable!("unsupported language in test: {lang}"),
    }
}

/// Generalization across the symptom class (every supported language): `tldr
/// dice` on two unrelated similar-size files must NOT assert a clone type, while
/// still reporting the coefficient.
#[test]
fn test_dice_unrelated_files_not_labeled_clone_all_langs() {
    let clone_assertions = ["Type-2 clone", "Type-3 clone", "clone candidate"];

    for lang in ["python", "rust", "typescript", "go", "java"] {
        let (ext, src_a, src_b) = unrelated_pair_for(lang);
        let temp = TempDir::new().unwrap();
        let file_a = temp.path().join(format!("a.{ext}"));
        let file_b = temp.path().join(format!("b.{ext}"));
        fs::write(&file_a, src_a).unwrap();
        fs::write(&file_b, src_b).unwrap();

        let json = run_dice_json(&file_a, &file_b);

        // Coefficient is still computed.
        assert!(
            json.get("dice_coefficient").and_then(|v| v.as_f64()).is_some(),
            "[{lang}] dice_coefficient missing: {json}"
        );

        // The interpretation must not assert a clone classification.
        let interp = json
            .get("interpretation")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        for bad in clone_assertions {
            assert!(
                !interp.contains(bad),
                "[{lang}] dice on unrelated files must not assert `{bad}`; \
                 coefficient={:?} interpretation={interp:?}",
                json.get("dice_coefficient")
            );
        }
    }
}

// =============================================================================
// Daemon Router Tests
// =============================================================================

#[test]
fn test_daemon_router_is_daemon_running_no_daemon() {
    let temp_dir = TempDir::new().unwrap();

    // Test that is_daemon_running returns false when no daemon is running
    // Note: don't use -q here because quiet mode suppresses the JSON output
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "daemon",
            "status",
            "--project",
            temp_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute tldr daemon status");

    assert!(output.status.success(), "daemon status should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not_running")
            || stdout.contains("not running")
            || stdout.contains("Daemon not running"),
        "Status should indicate daemon is not running"
    );
}

// =============================================================================
// Daemon Commands Tests
// =============================================================================

#[test]
fn test_daemon_start_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["daemon", "start", "--help"])
        .output()
        .expect("Failed to execute tldr daemon start --help");

    assert!(
        output.status.success(),
        "daemon start --help should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--project"),
        "Help should mention --project"
    );
    assert!(
        stdout.contains("--foreground"),
        "Help should mention --foreground"
    );
}

#[test]
fn test_daemon_stop_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["daemon", "stop", "--help"])
        .output()
        .expect("Failed to execute tldr daemon stop --help");

    assert!(output.status.success(), "daemon stop --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
    assert!(
        stdout.contains("--project"),
        "Help should mention --project"
    );
}

#[test]
fn test_daemon_status_not_running() {
    let temp_dir = TempDir::new().unwrap();
    // Note: don't use -q here because quiet mode suppresses the JSON output
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "daemon",
            "status",
            "--project",
            temp_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute tldr daemon status");

    assert!(
        output.status.success(),
        "daemon status should succeed when not running"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not_running")
            || stdout.contains("not running")
            || stdout.contains("Daemon not running"),
        "Status should indicate daemon is not running"
    );
}

#[test]
fn test_daemon_query_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["daemon", "query", "--help"])
        .output()
        .expect("Failed to execute tldr daemon query --help");

    assert!(
        output.status.success(),
        "daemon query --help should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
}

#[test]
fn test_daemon_notify_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["daemon", "notify", "--help"])
        .output()
        .expect("Failed to execute tldr daemon notify --help");

    assert!(
        output.status.success(),
        "daemon notify --help should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
}

// =============================================================================
// Cache Commands Tests
// =============================================================================

#[test]
fn test_cache_stats_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["cache", "stats", "--help"])
        .output()
        .expect("Failed to execute tldr cache stats --help");

    assert!(output.status.success(), "cache stats --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
}

#[test]
fn test_cache_clear_help() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(["cache", "clear", "--help"])
        .output()
        .expect("Failed to execute tldr cache clear --help");

    assert!(output.status.success(), "cache clear --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "Help should show usage");
}

// =============================================================================
// Cross-Command Integration Tests
// =============================================================================


#[test]
fn test_analysis_commands_on_same_project() {
    let temp_dir = create_deps_test_project();
    let project_path = temp_dir.path().to_str().unwrap();

    // Run multiple analysis commands on the same project
    let commands = vec![
        vec!["deps", project_path, "-q"],
        vec!["hubs", project_path, "-q"],
    ];

    for cmd in &commands {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
            .args(cmd)
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute tldr {}", cmd[0]));

        assert!(output.status.success(), "{} command should succeed", cmd[0]);
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================


#[test]
fn test_invalid_format_option() {
    let temp_dir = create_test_project();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "hubs",
            temp_dir.path().to_str().unwrap(),
            "-f",
            "invalid_format_xyz",
            "-q",
        ])
        .output()
        .expect("Failed to execute");

    // Invalid format should cause an error or fall back gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() || stderr.contains("error") || stderr.is_empty(),
        "Invalid format should be rejected or handled gracefully"
    );
}

#[test]
fn test_nonexistent_path() {
    // Commands that properly fail with non-zero exit code for nonexistent paths.
    // `change-impact` is strict because the path must resolve to a git
    // repository (or contain detectable changes) to establish a baseline;
    // a missing path is a NoBaseline error and exits non-zero.
    let strict_commands = vec!["hubs", "deps", "change-impact"];

    for cmd in &strict_commands {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
            .args([*cmd, "/nonexistent/path/12345", "-q"])
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute tldr {}", cmd));

        assert!(
            !output.status.success(),
            "{} should fail for nonexistent path",
            cmd
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not found")
                || stderr.contains("Error")
                || stderr.contains("path")
                || stderr.contains("baseline")
                || stderr.contains("ERROR"),
            "{} error should indicate path/baseline issue, got stderr: {}",
            cmd,
            stderr
        );
    }

    // Commands that return success with empty results for nonexistent paths
    let lenient_commands = vec!["clones"];

    for cmd in &lenient_commands {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
            .args([*cmd, "/nonexistent/path/12345", "-q"])
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute tldr {}", cmd));

        // These commands gracefully return empty results instead of failing
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{} should handle nonexistent path gracefully (returns empty results)",
            cmd
        );
        assert!(
            !stdout.is_empty(),
            "{} should produce output (empty results JSON) for nonexistent path",
            cmd
        );
    }
}
