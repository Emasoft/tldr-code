//! Integration tests for the patterns module
//!
//! Tests cover:
//! - PatternMiner with various configurations
//! - PatternDetector for all supported languages
//! - PatternSignals merging and calculations
//! - Constraint generation
//! - Pattern confidence thresholds

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use tldr_core::patterns::signals::{
    ApiConventionSignals, AsyncPatternSignals, ErrorHandlingSignals, ResourceManagementSignals,
    SoftDeleteSignals, TestIdiomSignals, TypeCoverageSignals, ValidationSignals,
};
use tldr_core::patterns::{
    detect_patterns, detect_patterns_with_config, generate_constraints, DetectedPatterns,
    PatternConfig, PatternDetector, PatternMiner, PatternSignals,
};
use tldr_core::types::{
    Language, NamingConvention, NamingPattern, PatternCategory, SoftDeletePattern,
};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_dir() -> TempDir {
    TempDir::new().unwrap()
}

fn write_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
    path
}

// ============================================================================
// PatternMiner Tests
// ============================================================================

#[test]
fn test_pattern_miner_new_with_default_config() {
    let config = PatternConfig::default();
    let _miner = PatternMiner::new(config);
    // Should create successfully
}

#[test]
fn test_pattern_config_default_values() {
    let config = PatternConfig::default();
    assert_eq!(config.min_confidence, 0.5);
    assert_eq!(config.max_files, 1000);
    assert_eq!(config.evidence_limit, 3);
    assert!(config.categories.is_empty());
    assert!(config.generate_constraints);
}

#[test]
fn test_pattern_config_custom_values() {
    let config = PatternConfig {
        min_confidence: 0.7,
        max_files: 100,
        evidence_limit: 5,
        categories: vec![PatternCategory::ErrorHandling, PatternCategory::Naming],
        generate_constraints: false,
    };
    assert_eq!(config.min_confidence, 0.7);
    assert_eq!(config.max_files, 100);
    assert_eq!(config.evidence_limit, 5);
    assert_eq!(config.categories.len(), 2);
    assert!(!config.generate_constraints);
}

#[test]
fn test_detect_patterns_empty_directory() {
    let dir = create_test_dir();
    let result = detect_patterns(dir.path(), None);

    // Should succeed even with empty directory
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.metadata.files_analyzed, 0);
    assert_eq!(report.metadata.files_skipped, 0);
}

#[test]
fn test_detect_patterns_python_soft_delete() {
    let dir = create_test_dir();
    let content = r#"
class User:
    is_deleted = False
    deleted_at = None
    
    def delete(self):
        self.is_deleted = True
        self.deleted_at = "2024-01-01"
"#;
    write_file(&dir, "models.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect soft delete pattern
    assert!(report.soft_delete.is_some());
    let pattern = report.soft_delete.unwrap();
    assert!(pattern.detected);
    assert!(pattern.confidence > 0.0);
    assert!(pattern.column_names.contains(&"is_deleted".to_string()));
}

#[test]
fn test_detect_patterns_python_error_handling() {
    let dir = create_test_dir();
    let content = r#"
try:
    process_data()
except ValueError as e:
    logger.error(f"Error: {e}")

class ValidationError(Exception):
    pass
"#;
    write_file(&dir, "service.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect error handling pattern
    assert!(report.error_handling.is_some());
    let pattern = report.error_handling.unwrap();
    assert!(pattern.confidence > 0.0);
    assert!(pattern.patterns.contains(&"try_catch".to_string()));
}

#[test]
fn test_detect_patterns_python_naming() {
    let dir = create_test_dir();
    let content = r#"
def process_user_data():
    pass

class UserManager:
    pass

MAX_RETRY_COUNT = 3
"#;
    write_file(&dir, "utils.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect naming pattern
    assert!(report.naming.is_some());
    let pattern = report.naming.unwrap();
    assert!(pattern.consistency_score > 0.0);
}

#[test]
fn test_detect_patterns_python_validation() {
    let dir = create_test_dir();
    let content = r#"
from pydantic import BaseModel

class UserModel(BaseModel):
    name: str
    email: str
    
    def validate(self):
        assert self.name is not None
        assert isinstance(self.email, str)
"#;
    write_file(&dir, "schemas.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect validation pattern
    assert!(report.validation.is_some());
    let pattern = report.validation.unwrap();
    assert!(pattern.confidence > 0.0);
    assert!(pattern.frameworks.contains(&"pydantic".to_string()));
}

#[test]
fn test_detect_patterns_python_test_idioms() {
    let dir = create_test_dir();
    let content = r#"
import pytest
from unittest import mock

@pytest.fixture
def user_data():
    return {"name": "test"}

@mock.patch("service.get_user")
def test_process_user(mock_get_user, user_data):
    mock_get_user.return_value = user_data
    result = process_user(1)
    assert result is not None
"#;
    write_file(&dir, "test_service.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect test idiom pattern
    assert!(report.test_idioms.is_some());
    let pattern = report.test_idioms.unwrap();
    assert!(pattern.confidence > 0.0);
    assert_eq!(pattern.framework, Some("pytest".to_string()));
}

#[test]
fn test_detect_patterns_python_import_patterns() {
    let dir = create_test_dir();
    let content = r#"
import os
import sys
from typing import List, Optional
from .models import User
from ..utils import helper
"#;
    write_file(&dir, "main.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect import pattern
    assert!(report.import_patterns.is_some());
    let _pattern = report.import_patterns.unwrap();
}

#[test]
fn test_detect_patterns_python_type_coverage() {
    let dir = create_test_dir();
    let content = r#"
from typing import List, Optional

def process(items: List[str]) -> Optional[str]:
    if items:
        return items[0]
    return None

class Manager:
    def get_user(self, id: int) -> dict:
        return {}
"#;
    write_file(&dir, "typed.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect type coverage pattern
    assert!(report.type_coverage.is_some());
    let pattern = report.type_coverage.unwrap();
    assert!(pattern.coverage_overall > 0.0);
}

#[test]
fn test_detect_patterns_python_api_conventions() {
    let dir = create_test_dir();
    let content = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def get_users():
    return []

@app.post("/users")
def create_user():
    return {}
"#;
    write_file(&dir, "api.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect API convention pattern
    assert!(report.api_conventions.is_some());
    let pattern = report.api_conventions.unwrap();
    assert!(pattern.confidence > 0.0);
}

/// fix-PW4-bug1-patterns-py-fastapi: Flask 2.0+ exposes @app.get/@app.post/...
/// route shortcuts that are byte-identical to FastAPI's. Framework detection
/// must gate the FastAPI verdict on an actual `fastapi` import; a repo that
/// imports `flask` and uses @app.get must be reported as Flask, not FastAPI.
#[test]
fn test_flask_route_shortcuts_not_misdetected_as_fastapi() {
    let dir = create_test_dir();
    let content = r#"
import flask
from flask import Flask

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    return "hi"

@app.get("/users")
def get_users():
    return []

@app.post("/users")
def create_user():
    return {}
"#;
    write_file(&dir, "app.py", content);

    let report = detect_patterns(dir.path(), Some(Language::Python)).unwrap();
    let pattern = report
        .api_conventions
        .expect("api conventions should be detected");
    assert_eq!(
        pattern.framework,
        Some("flask".to_string()),
        "Flask repo using @app.get/@app.post shortcuts must be detected as flask, not fastapi"
    );
}

/// Counterpart: a genuine FastAPI repo (imports fastapi, uses @app.get) must
/// still be detected as FastAPI — the import gate must not over-correct.
#[test]
fn test_fastapi_route_shortcuts_still_detected_as_fastapi() {
    let dir = create_test_dir();
    let content = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def get_users():
    return []

@app.post("/users")
def create_user():
    return {}
"#;
    write_file(&dir, "api.py", content);

    let report = detect_patterns(dir.path(), Some(Language::Python)).unwrap();
    let pattern = report
        .api_conventions
        .expect("api conventions should be detected");
    assert_eq!(pattern.framework, Some("fastapi".to_string()));
}

/// R7 cluster[9] #25/#235: `error_handling` is language-specific and must
/// be derived from the PRIMARY language's signals, not the cross-language
/// aggregate. A C++-majority repo with a stray vendored `.py` must NOT
/// report Python exception types (the bleed that surfaced
/// `DocoptLanguageError`/`CompilerError` on cpp-fmt / swift-collections).
#[test]
fn test_error_handling_does_not_bleed_foreign_python_exceptions() {
    let dir = create_test_dir();
    // C++ is the primary language (3 files) with its own try/catch idiom.
    for i in 0..3 {
        let cpp = format!(
            r#"
#include <stdexcept>
class Widget{i} {{
public:
  void run() {{
    try {{ work(); }} catch (const std::runtime_error& e) {{ handle(e); }}
  }}
}};
"#
        );
        write_file(&dir, &format!("widget{i}.cc", i = i), &cpp);
    }
    // A single stray vendored Python file defining a custom exception.
    write_file(
        &dir,
        "vendor/support.py",
        r#"
class DocoptLanguageError(Exception):
    pass

try:
    parse()
except DocoptLanguageError as e:
    raise
"#,
    );

    // Auto-detect the language (no explicit filter) so the primary-language
    // logic runs over the polyglot directory.
    let report = detect_patterns(dir.path(), None).expect("detect_patterns ok");
    if let Some(eh) = report.error_handling {
        assert!(
            !eh.exception_types.iter().any(|t| t == "DocoptLanguageError"),
            "Python exception `DocoptLanguageError` must NOT bleed into a \
             C++-primary repo's error_handling; got {:?}",
            eh.exception_types
        );
    }
}

/// R7 cluster[9] #25/#26: the C++ naming-convention majority must be
/// computed from LIBRARY source, not the (often larger) test tree. A
/// snake_case library with many PascalCase gtest files must still report
/// `function_convention = snake_case`, and its snake_case functions must
/// not be flagged as violations. Pre-fix the 42-vs-19 test/source file
/// ratio in cpp-fmt flipped the global majority to pascal_case.
#[test]
fn test_cpp_naming_majority_excludes_test_dir() {
    let dir = create_test_dir();
    // Library source: snake_case free functions (the real convention).
    write_file(
        &dir,
        "src/format.cc",
        r#"
int parse_format_spec(int a) { return a; }
void write_buffer(int x) {}
int convert_arg(int y) { return y; }
void grow_storage() {}
"#,
    );
    // A large test tree with PascalCase function/method names (gtest-style).
    for i in 0..8 {
        write_file(
            &dir,
            &format!("test/case{i}-test.cc", i = i),
            &format!(
                r#"
void RunFormatTest{i}() {{}}
void CheckBufferGrows{i}() {{}}
int ComputeExpected{i}(int v) {{ return v; }}
"#
            ),
        );
    }

    let report = detect_patterns(dir.path(), Some(Language::Cpp)).expect("detect_patterns ok");
    let naming = report.naming.expect("cpp repo must produce naming");

    // The LIBRARY convention (snake_case) must win over the test tree.
    assert_eq!(
        naming.functions,
        NamingConvention::SnakeCase,
        "C++ function convention must be snake_case from library source, \
         not pascal_case from the test tree; got {:?}",
        naming.functions
    );
    // The real snake_case library functions must NOT be flagged.
    for libfn in ["parse_format_spec", "write_buffer", "convert_arg", "grow_storage"] {
        assert!(
            !naming.violations.iter().any(|v| v.name == libfn),
            "library snake_case fn `{}` must not be a violation; got {:?}",
            libfn,
            naming.violations.iter().map(|v| &v.name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_detect_patterns_python_async_patterns() {
    let dir = create_test_dir();
    let content = r#"
import asyncio

async def fetch_data():
    return await http_client.get("/api/data")

async def process():
    data = await fetch_data()
    return data
"#;
    write_file(&dir, "async_service.py", content);

    // Small fixture yields confidence 0.4 (below default 0.5 threshold),
    // so use a lower min_confidence to verify detection works.
    let config = PatternConfig {
        min_confidence: 0.3,
        ..PatternConfig::default()
    };
    let result = detect_patterns_with_config(dir.path(), Some(Language::Python), config);
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect async pattern
    assert!(report.async_patterns.is_some());
    let pattern = report.async_patterns.unwrap();
    assert!(pattern.concurrency_confidence > 0.0);
}

#[test]
fn test_detect_patterns_rust_error_handling() {
    let dir = create_test_dir();
    let content = r#"
use std::io;

#[derive(Debug)]
struct ValidationError;

fn process() -> Result<String, io::Error> {
    let data = read_file()?;
    Ok(data)
}

enum MyError {
    NotFound,
    InvalidInput,
}
"#;
    write_file(&dir, "main.rs", content);

    let result = detect_patterns(dir.path(), Some(Language::Rust));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect error handling pattern
    assert!(report.error_handling.is_some());
}

#[test]
fn test_detect_patterns_go_error_handling() {
    let dir = create_test_dir();
    let content = r#"
package main

import "errors"

func process() error {
    err := doSomething()
    if err != nil {
        return err
    }
    return nil
}

func TestProcess(t *testing.T) {
    err := process()
    if err != nil {
        t.Errorf("failed: %v", err)
    }
}
"#;
    write_file(&dir, "main.go", content);

    let result = detect_patterns(dir.path(), Some(Language::Go));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect error handling pattern
    assert!(report.error_handling.is_some());
}

#[test]
fn test_detect_patterns_typescript_api() {
    let dir = create_test_dir();
    let content = r#"
import express from 'express';

const app = express();

app.get('/users', (req, res) => {
    res.json([]);
});

app.listen(3000);
"#;
    write_file(&dir, "server.ts", content);

    let result = detect_patterns(dir.path(), Some(Language::TypeScript));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should detect API convention pattern
    assert!(report.api_conventions.is_some());
}

#[test]
fn test_detect_patterns_with_config_filtering() {
    let dir = create_test_dir();
    let content = r#"
def test_something():
    assert True

def helper():
    pass
"#;
    write_file(&dir, "test_file.py", content);

    let config = PatternConfig {
        min_confidence: 0.9, // High threshold
        max_files: 10,
        evidence_limit: 2,
        categories: vec![],
        generate_constraints: true,
    };

    let result = detect_patterns_with_config(dir.path(), Some(Language::Python), config);
    assert!(result.is_ok());
}

#[test]
fn test_detect_patterns_single_file() {
    let dir = create_test_dir();
    let content = r#"
class User:
    is_deleted = False
"#;
    let path = write_file(&dir, "user.py", content);

    let result = detect_patterns(&path, Some(Language::Python));
    assert!(result.is_ok());
}

#[test]
fn test_pattern_report_metadata() {
    let dir = create_test_dir();
    let content = r#"
class User:
    is_deleted = False
"#;
    write_file(&dir, "user.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Check metadata fields exist
    let _ = report.metadata.duration_ms;
    let _ = report.metadata.patterns_before_filter;
    let _ = report.metadata.patterns_after_filter;
}

#[test]
fn test_pattern_report_constraints() {
    let dir = create_test_dir();
    let content = r#"
class User:
    is_deleted = False
"#;
    write_file(&dir, "user.py", content);

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should have constraints generated
    assert!(!report.constraints.is_empty());
}

// ============================================================================
// PatternSignals Tests
// ============================================================================

#[test]
fn test_pattern_signals_default() {
    let _signals = PatternSignals::default();
    // Should create successfully with all fields initialized
}

#[test]
fn test_pattern_signals_merge() {
    let mut signals1 = PatternSignals::default();
    let signals2 = PatternSignals::default();

    signals1.merge(&signals2);
    // Should merge without error
}

#[test]
fn test_soft_delete_signals_calculate_confidence() {
    let signals = SoftDeleteSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);

    let mut signals = SoftDeleteSignals::default();
    signals
        .is_deleted_fields
        .push(tldr_core::types::Evidence::new(
            "file.py".to_string(),
            1,
            "is_deleted = False".to_string(),
        ));
    let confidence = signals.calculate_confidence();
    assert!(confidence > 0.0);
}

#[test]
fn test_error_handling_signals_calculate_confidence() {
    let signals = ErrorHandlingSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);
}

#[test]
#[ignore = "BUG: detect_naming_case is not exported from patterns module"]
fn test_naming_case_detection() {
    // This test is blocked because detect_naming_case is not re-exported
    // from patterns/mod.rs even though it's pub in signals.rs
}

#[test]
fn test_resource_management_signals_calculate_confidence() {
    let signals = ResourceManagementSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);
}

#[test]
fn test_validation_signals_calculate_confidence() {
    let signals = ValidationSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);
}

#[test]
fn test_test_idiom_signals_calculate_confidence() {
    let signals = TestIdiomSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);
}

#[test]
fn test_type_coverage_signals_calculate_coverage() {
    let signals = TypeCoverageSignals::default();
    assert_eq!(signals.calculate_function_coverage(), 0.0);
    assert_eq!(signals.calculate_variable_coverage(), 0.0);
    assert_eq!(signals.calculate_overall_coverage(), 0.0);

    let signals = TypeCoverageSignals {
        typed_params: 5,
        untyped_params: 5,
        ..Default::default()
    };
    assert_eq!(signals.calculate_function_coverage(), 0.5);
}

#[test]
fn test_api_convention_signals_detect_framework() {
    let signals = ApiConventionSignals::default();
    assert_eq!(signals.detect_framework(), None);

    let mut signals = ApiConventionSignals::default();
    signals
        .fastapi_decorators
        .push(tldr_core::types::Evidence::new(
            "api.py".to_string(),
            1,
            "@app.get".to_string(),
        ));
    assert_eq!(signals.detect_framework(), Some("fastapi".to_string()));
}

#[test]
fn test_async_pattern_signals_calculate_confidence() {
    let signals = AsyncPatternSignals::default();
    let confidence = signals.calculate_confidence();
    assert_eq!(confidence, 0.0);
}

// ============================================================================
// Constraint Generation Tests
// ============================================================================

#[test]
fn test_generate_constraints_with_soft_delete() {
    let soft_delete = Some(SoftDeletePattern {
        detected: true,
        confidence: 0.8,
        column_names: vec!["is_deleted".to_string()],
        evidence: vec![],
    });

    let constraints = generate_constraints(&DetectedPatterns {
        soft_delete: &soft_delete,
        error_handling: &None,
        naming: &None,
        resource_management: &None,
        validation: &None,
        test_idioms: &None,
        import_patterns: &None,
        type_coverage: &None,
        api_conventions: &None,
        async_patterns: &None,
    });

    assert!(!constraints.is_empty());
}

#[test]
fn test_generate_constraints_with_naming() {
    let naming = Some(NamingPattern {
        functions: NamingConvention::SnakeCase,
        classes: NamingConvention::PascalCase,
        constants: NamingConvention::UpperSnakeCase,
        private_prefix: Some("_".to_string()),
        consistency_score: 0.9,
        violations: vec![],
    });

    let constraints = generate_constraints(&DetectedPatterns {
        soft_delete: &None,
        error_handling: &None,
        naming: &naming,
        resource_management: &None,
        validation: &None,
        test_idioms: &None,
        import_patterns: &None,
        type_coverage: &None,
        api_conventions: &None,
        async_patterns: &None,
    });

    assert!(!constraints.is_empty());
    assert!(constraints.iter().any(|c| c.rule.contains("snake_case")));
}

#[test]
fn test_generate_constraints_no_patterns() {
    let constraints = generate_constraints(&DetectedPatterns {
        soft_delete: &None,
        error_handling: &None,
        naming: &None,
        resource_management: &None,
        validation: &None,
        test_idioms: &None,
        import_patterns: &None,
        type_coverage: &None,
        api_conventions: &None,
        async_patterns: &None,
    });

    assert!(constraints.is_empty());
}

// ============================================================================
// PatternDetector Tests
// ============================================================================

#[test]
fn test_pattern_detector_new() {
    let _detector = PatternDetector::new(Language::Python, PathBuf::from("test.py"));
    // Should create successfully
}

#[test]
#[ignore = "Requires parser - cannot test without tree-sitter parse"]
fn test_pattern_detector_detect_all_empty() {
    // This test requires actual tree-sitter parsing
}

#[test]
fn test_pattern_detector_detect_fallback() {
    let detector = PatternDetector::new(Language::Python, PathBuf::from("test.py"));
    let source = r#"
is_deleted = True
deleted_at = None
async def process():
    pass
try:
    pass
except:
    pass
"#;
    let _signals = detector.detect_fallback(source);
    // Should extract some signals via regex fallback
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_detect_patterns_multiple_files() {
    let dir = create_test_dir();

    write_file(
        &dir,
        "models.py",
        r#"
class User:
    is_deleted = False
"#,
    );

    write_file(
        &dir,
        "service.py",
        r#"
def process():
    try:
        data = fetch()
    except Exception as e:
        logger.error(e)
"#,
    );

    write_file(
        &dir,
        "test_models.py",
        r#"
def test_user():
    assert True
"#,
    );

    let result = detect_patterns(dir.path(), Some(Language::Python));
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should find patterns from all files
    assert!(report.metadata.files_analyzed >= 3);
}

#[test]
fn test_detect_patterns_with_unsupported_file() {
    let dir = create_test_dir();
    write_file(&dir, "readme.txt", "This is a text file");

    let result = detect_patterns(dir.path(), None);
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should skip unsupported files
    assert_eq!(report.metadata.files_analyzed, 0);
}

#[test]
#[ignore = "May panic on parse errors - needs investigation"]
fn test_detect_patterns_invalid_syntax() {
    let dir = create_test_dir();
    write_file(&dir, "broken.py", "def invalid syntax here {[");

    let result = detect_patterns(dir.path(), Some(Language::Python));
    // Should handle parse errors gracefully
    assert!(result.is_ok());
}

// ============================================================================
// OCaml: reserved-keyword tokens must never leak as module / module-type
// names (bug5-patterns-ocaml-struct)
// ============================================================================

/// The OCaml reserved-keyword set, mirrored from the extractor guard so the
/// test can assert the cross-cutting invariant "no design-pattern subject or
/// naming violation is ever anchored on a keyword".
fn is_ocaml_kw(name: &str) -> bool {
    matches!(
        name,
        "and" | "as"
            | "assert"
            | "asr"
            | "begin"
            | "class"
            | "constraint"
            | "do"
            | "done"
            | "downto"
            | "else"
            | "end"
            | "exception"
            | "external"
            | "false"
            | "for"
            | "fun"
            | "function"
            | "functor"
            | "if"
            | "in"
            | "include"
            | "inherit"
            | "initializer"
            | "land"
            | "lazy"
            | "let"
            | "lor"
            | "lsl"
            | "lsr"
            | "lxor"
            | "match"
            | "method"
            | "mod"
            | "module"
            | "mutable"
            | "new"
            | "nonrec"
            | "object"
            | "of"
            | "open"
            | "or"
            | "private"
            | "rec"
            | "sig"
            | "struct"
            | "then"
            | "to"
            | "true"
            | "try"
            | "type"
            | "val"
            | "virtual"
            | "when"
            | "while"
            | "with"
    )
}

/// `module type of struct … end` is misparsed by tree-sitter-ocaml under
/// error recovery into a `module_type_definition` whose `module_type_name`
/// is the bare keyword `struct`. It must NOT mint a `struct`-named
/// `ModuleSignature` nor a `struct` naming violation — while genuine module
/// types / modules in the same file are still detected.
#[test]
fn test_ocaml_module_type_of_struct_not_minted_as_module() {
    let dir = create_test_dir();
    let content = r#"include module type of struct
  include Stdlib.Sys
end

module type COMPARABLE = sig
  type t
  val compare : t -> t -> int
end

module IntPair = struct
  type t = int * int
end
"#;
    write_file(&dir, "sys.mli", content);

    let report = detect_patterns(dir.path(), Some(Language::Ocaml)).unwrap();

    // (1) No design pattern may be anchored on an OCaml reserved keyword.
    for dp in &report.design_patterns {
        assert!(
            !is_ocaml_kw(&dp.subject),
            "keyword `{}` leaked as a design-pattern subject: {:?}",
            dp.subject,
            dp
        );
    }
    // Specifically: the previously-minted bogus `struct` ModuleSignature.
    assert!(
        !report.design_patterns.iter().any(|d| d.subject == "struct"),
        "bogus struct-named pattern still minted: {:?}",
        report.design_patterns
    );

    // (2) The genuine `module type COMPARABLE = sig … end` IS still surfaced
    //     — the keyword guard must not suppress real signatures.
    assert!(
        report
            .design_patterns
            .iter()
            .any(|d| d.pattern == "ModuleSignature" && d.subject == "COMPARABLE"),
        "real module type COMPARABLE was lost: {:?}",
        report.design_patterns
    );

    // (3) No naming violation may be anchored on a reserved keyword.
    if let Some(naming) = &report.naming {
        for v in &naming.violations {
            assert!(
                !is_ocaml_kw(&v.name),
                "keyword `{}` leaked as a naming violation: {:?}",
                v.name,
                v
            );
        }
    }
}

/// Path-form `module type of` variants found in real corpora (dune) — the
/// LHS name is a genuine identifier, so we only assert the invariant that no
/// keyword leaks into any subject regardless of how the RHS error-recovers.
#[test]
fn test_ocaml_module_type_of_path_no_keyword_leak() {
    let dir = create_test_dir();
    let content = r#"module type New_console = module type of Console

module type S = module type of B.A

include module type of Imp_lib
"#;
    write_file(&dir, "variants.ml", content);

    let report = detect_patterns(dir.path(), Some(Language::Ocaml)).unwrap();

    for dp in &report.design_patterns {
        assert!(
            !is_ocaml_kw(&dp.subject),
            "keyword `{}` leaked as a design-pattern subject: {:?}",
            dp.subject,
            dp
        );
    }
    if let Some(naming) = &report.naming {
        for v in &naming.violations {
            assert!(
                !is_ocaml_kw(&v.name),
                "keyword `{}` leaked as a naming violation: {:?}",
                v.name,
                v
            );
        }
    }
}
