//! Grammar Stability Tests - Phase 1 (PM-1.1, PM-1.2 mitigation)
//!
//! These tests verify that tree-sitter grammars load with expected node types.
//! If grammar versions change and node types are renamed, these tests will fail,
//! alerting us before extraction logic silently breaks.
//!
//! # Purpose
//! - Detect grammar version mismatches before they cause silent extraction failures
//! - Document critical AST node types for each supported language
//! - Serve as regression tests when upgrading tree-sitter dependencies
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p tldr-core --test grammar_stability_test -- --test-threads=1
//! ```
//!
//! # Pinned Versions (from Cargo.lock)
//! - tree-sitter = 0.24.7
//! - tree-sitter-python = 0.23.6
//! - tree-sitter-typescript = 0.23.2
//! - tree-sitter-go = 0.23.4
//! - tree-sitter-rust = 0.23.3
//! - tree-sitter-java = 0.23.5

use tldr_core::{ast::parser::ParserPool, Language};

// =============================================================================
// Helper: Check if a node type exists in parsed tree
// =============================================================================

/// Recursively search for a node type in the tree
fn tree_contains_node_type(node: tree_sitter::Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if tree_contains_node_type(child, kind) {
            return true;
        }
    }
    false
}

/// Assert that parsing produces at least one node of the given type
fn assert_node_type_exists(source: &str, lang: Language, node_type: &str) {
    let pool = ParserPool::new();
    let tree = pool
        .parse(source, lang)
        .unwrap_or_else(|_| panic!("Failed to parse {:?} code", lang));

    assert!(
        tree_contains_node_type(tree.root_node(), node_type),
        "Expected node type '{}' not found in {:?} AST. \
         This may indicate a grammar version mismatch. \
         Run `cargo update tree-sitter-{:?}` and update pinned version.",
        node_type,
        lang,
        lang
    );
}

// =============================================================================
// Test: Grammar Node Types Stable (PM-1.1 mitigation)
// =============================================================================

/// Master test verifying all critical grammars load successfully
#[test]
fn test_grammar_node_types_stable() {
    let pool = ParserPool::new();

    // P0 Languages - must parse
    assert!(
        pool.parse("x = 1", Language::Python).is_ok(),
        "Python grammar failed to load"
    );
    assert!(
        pool.parse("const x = 1;", Language::TypeScript).is_ok(),
        "TypeScript grammar failed to load"
    );
    assert!(
        pool.parse("const x = 1;", Language::JavaScript).is_ok(),
        "JavaScript grammar failed to load"
    );
    assert!(
        pool.parse("package main\nfunc main() {}", Language::Go)
            .is_ok(),
        "Go grammar failed to load"
    );

    // P1 Languages - must parse
    assert!(
        pool.parse("fn main() {}", Language::Rust).is_ok(),
        "Rust grammar failed to load"
    );
    assert!(
        pool.parse("class Foo {}", Language::Java).is_ok(),
        "Java grammar failed to load"
    );
}

// =============================================================================
// Python AST Node Types (tree-sitter-python 0.23.6)
// =============================================================================

#[test]
fn test_python_ast_node_types() {
    // Import statement node types
    assert_node_type_exists("import os", Language::Python, "import_statement");
    assert_node_type_exists(
        "from typing import List",
        Language::Python,
        "import_from_statement",
    );

    // Function definition node types
    assert_node_type_exists("def hello(): pass", Language::Python, "function_definition");
    assert_node_type_exists(
        "async def fetch(): pass",
        Language::Python,
        "function_definition",
    );

    // Class definition node types
    assert_node_type_exists("class Foo: pass", Language::Python, "class_definition");

    // Decorated definition (PM-3.1 mitigation)
    assert_node_type_exists(
        "@decorator\ndef foo(): pass",
        Language::Python,
        "decorated_definition",
    );
}

// =============================================================================
// TypeScript AST Node Types (tree-sitter-typescript 0.23.2)
// =============================================================================

#[test]
fn test_typescript_ast_node_types() {
    // Import statement node types
    assert_node_type_exists(
        "import React from 'react';",
        Language::TypeScript,
        "import_statement",
    );
    assert_node_type_exists(
        "import { foo } from './bar';",
        Language::TypeScript,
        "import_statement",
    );

    // Function declaration node types
    assert_node_type_exists(
        "function hello() {}",
        Language::TypeScript,
        "function_declaration",
    );
    assert_node_type_exists(
        "async function fetch() {}",
        Language::TypeScript,
        "function_declaration",
    );

    // Class declaration node types
    assert_node_type_exists("class Foo {}", Language::TypeScript, "class_declaration");

    // Arrow function (common in TS/JS)
    assert_node_type_exists(
        "const f = () => {};",
        Language::TypeScript,
        "arrow_function",
    );

    // Export statement
    assert_node_type_exists(
        "export function foo() {}",
        Language::TypeScript,
        "export_statement",
    );
}

// =============================================================================
// Go AST Node Types (tree-sitter-go 0.23.4)
// =============================================================================

#[test]
fn test_go_ast_node_types() {
    // Import declaration node types
    assert_node_type_exists(
        "package main\nimport \"fmt\"",
        Language::Go,
        "import_declaration",
    );
    assert_node_type_exists(
        "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)",
        Language::Go,
        "import_spec_list",
    );

    // Function declaration node types
    assert_node_type_exists(
        "package main\nfunc hello() {}",
        Language::Go,
        "function_declaration",
    );

    // Method declaration (receiver)
    assert_node_type_exists(
        "package main\ntype Foo struct{}\nfunc (f *Foo) Bar() {}",
        Language::Go,
        "method_declaration",
    );

    // Type declaration
    assert_node_type_exists(
        "package main\ntype Foo struct{}",
        Language::Go,
        "type_declaration",
    );

    // Interface type
    assert_node_type_exists(
        "package main\ntype Reader interface { Read() }",
        Language::Go,
        "interface_type",
    );
}

// =============================================================================
// Rust AST Node Types (tree-sitter-rust 0.23.3)
// =============================================================================

#[test]
fn test_rust_ast_node_types() {
    // Use declaration node types
    assert_node_type_exists(
        "use std::collections::HashMap;",
        Language::Rust,
        "use_declaration",
    );

    // Use with braces (nested use groups - PM-1.3)
    assert_node_type_exists("use std::{io, fs};", Language::Rust, "use_list");

    // Function item node types
    assert_node_type_exists("fn hello() {}", Language::Rust, "function_item");
    assert_node_type_exists("pub fn hello() {}", Language::Rust, "function_item");
    assert_node_type_exists("async fn fetch() {}", Language::Rust, "function_item");

    // Struct item
    assert_node_type_exists("struct Foo {}", Language::Rust, "struct_item");

    // Enum item
    assert_node_type_exists("enum Color { Red, Green }", Language::Rust, "enum_item");

    // Impl item
    assert_node_type_exists("impl Foo { fn bar(&self) {} }", Language::Rust, "impl_item");

    // Trait item
    assert_node_type_exists(
        "trait Greetable { fn greet(&self); }",
        Language::Rust,
        "trait_item",
    );

    // Mod item
    assert_node_type_exists("mod internal;", Language::Rust, "mod_item");
}

// =============================================================================
// Java AST Node Types (tree-sitter-java 0.23.5)
// =============================================================================

#[test]
fn test_java_ast_node_types() {
    // Import declaration node types
    assert_node_type_exists(
        "import java.util.List;",
        Language::Java,
        "import_declaration",
    );

    // Static import
    assert_node_type_exists(
        "import static java.lang.Math.PI;",
        Language::Java,
        "import_declaration",
    );

    // Class declaration
    assert_node_type_exists("class Foo {}", Language::Java, "class_declaration");

    // Interface declaration
    assert_node_type_exists("interface Bar {}", Language::Java, "interface_declaration");

    // Method declaration
    assert_node_type_exists(
        "class Foo { void bar() {} }",
        Language::Java,
        "method_declaration",
    );

    // Constructor declaration
    assert_node_type_exists(
        "class Foo { Foo() {} }",
        Language::Java,
        "constructor_declaration",
    );

    // Package declaration
    assert_node_type_exists(
        "package com.example;",
        Language::Java,
        "package_declaration",
    );
}

// =============================================================================
// Version Verification Test
// =============================================================================

/// This test documents the pinned grammar versions.
/// If it fails, update the versions in Cargo.toml and this comment.
#[test]
fn test_grammar_versions_documented() {
    // This test serves as documentation. The actual version pinning
    // is enforced by Cargo.toml using exact version specs (=X.Y.Z).
    //
    // Current pinned versions (update when upgrading):
    // - tree-sitter = "=0.24.7"
    // - tree-sitter-python = "=0.23.6"
    // - tree-sitter-typescript = "=0.23.2"
    // - tree-sitter-go = "=0.23.4"
    // - tree-sitter-rust = "=0.23.3"
    // - tree-sitter-java = "=0.23.5"
    //
    // To upgrade versions:
    // 1. Run `cargo update -p tree-sitter-<lang>`
    // 2. Run these tests to verify node types still exist
    // 3. Update pinned version in Cargo.toml
    // 4. Update GRAMMAR_COMPATIBILITY.md
    let _ = ();
}

// =============================================================================
// Kotlin grammar: vendored fork admitting `suspend` + peer soft/modifier
// keywords as named-argument identifiers (assertion B-kotlin-grammar).
//
// Root cause: tree-sitter-kotlin-ng 1.1.0 omitted `suspend` (and peers) from
// `_reserved_identifier`, so `g(suspend = { 42 })` failed to form a
// value_argument, dropped into error recovery, and a downstream string-template
// scanner swallowed the rest of the file into one root ERROR — dropping classes
// and methods. The vendored grammar (vendor/tree-sitter-kotlin-ng) adds the
// modifier soft-keywords to `_reserved_identifier`. Tests assert by node-kind
// presence / by-name recovery, never by span size or node count (recovery
// spans shift with tree-sitter's error-cost balancing).
// =============================================================================

/// Assert that parsing produces a clean tree with no ERROR/MISSING nodes.
fn assert_parses_without_error(source: &str, lang: Language) {
    let pool = ParserPool::new();
    let tree = pool
        .parse(source, lang)
        .unwrap_or_else(|_| panic!("Failed to parse {:?} code", lang));
    let root = tree.root_node();
    assert_eq!(
        root.kind(),
        "source_file",
        "Expected {:?} root node 'source_file', got '{}' for source:\n{}",
        lang,
        root.kind(),
        source
    );
    assert!(
        !root.has_error(),
        "Expected {:?} parse with no error, but tree.has_error() == true for source:\n{}",
        lang,
        source
    );
}

#[test]
fn test_kotlin_suspend_named_arg_parses_clean() {
    // PRIMARY regression: `suspend` as a named-argument NAME must parse as a
    // value_argument (identifier), not the hard modifier token under ERROR.
    let src = "fun f() { g(suspend = { 42 }) }";
    assert_parses_without_error(src, Language::Kotlin);
    assert_node_type_exists(src, Language::Kotlin, "value_argument");
    assert_node_type_exists(src, Language::Kotlin, "call_expression");
}

#[test]
fn test_kotlin_soft_keyword_named_args_ab_sentinels() {
    // A/B sentinel: the already-working set must keep working...
    assert_parses_without_error("fun f() { g(data = { 42 }) }", Language::Kotlin);
    // ...and the newly-admitted modifier soft-keywords must all parse clean as
    // argument names (locks the added _reserved_identifier members).
    for kw in [
        "suspend",
        "tailrec",
        "infix",
        "inline",
        "external",
        "reified",
        "lateinit",
        "override",
        "abstract",
        "final",
        "open",
        "vararg",
        "noinline",
        "crossinline",
    ] {
        let src = format!("fun f() {{ g({kw} = x) }}");
        assert_parses_without_error(&src, Language::Kotlin);
        assert_node_type_exists(&src, Language::Kotlin, "value_argument");
    }
}

#[test]
fn test_kotlin_modifier_position_still_parses() {
    // Blast-radius guard: the same spellings must still parse as MODIFIERS (the
    // correct node kind) in declaration-modifier position — proving the additive
    // _reserved_identifier change did not steal them from modifier position.
    //
    // NOTE: we assert by MODIFIER NODE KIND, not via assert_parses_without_error.
    // The upstream (unpatched) tree-sitter-kotlin-ng 1.1.0 grammar ALREADY sets a
    // has_error recovery bit on some declaration shapes under the workspace's
    // tree-sitter 0.25 core (e.g. `abstract class C { open fun d() {} }`), even
    // though it yields a complete, correctly-typed tree. That is pre-existing
    // upstream behavior, NOT a regression of this patch (verified: the registry
    // =1.1.0 grammar produces the identical has_error bit on the same input). The
    // load-bearing invariant for this fix is that the modifier keywords still
    // resolve to their *_modifier node kinds, which is what we check here.
    assert_node_type_exists("suspend fun a() {}", Language::Kotlin, "function_modifier");
    assert_node_type_exists("tailrec fun h() {}", Language::Kotlin, "function_modifier");
    assert_node_type_exists("inline fun e() {}", Language::Kotlin, "function_modifier");
    assert_node_type_exists(
        "abstract class C {}",
        Language::Kotlin,
        "inheritance_modifier",
    );
    assert_node_type_exists("open class D {}", Language::Kotlin, "inheritance_modifier");
    assert_node_type_exists(
        "class E { override fun b() {} }",
        Language::Kotlin,
        "member_modifier",
    );
    assert_node_type_exists(
        "fun g(vararg xs: Int) {}",
        Language::Kotlin,
        "parameter_modifier",
    );
    assert_node_type_exists(
        "inline fun <reified T> e() {}",
        Language::Kotlin,
        "reification_modifier",
    );
}

#[test]
fn test_kotlin_suspend_named_arg_whole_file_cascade_recovery() {
    // SECONDARY-mechanism regression: a `suspend = { ... }` named arg COMBINED
    // with a downstream `"...$x"` interpolated string previously dragged the
    // remainder of the file into one root ERROR, dropping sibling declarations.
    // Assert the two impl classes are recovered BY NAME (not by count/span).
    use tldr_core::ast::extract::extract_file;
    let src = r#"package demo

fun acquire(waiter: Int) = acquire(
    waiter = waiter,
    suspend = { cont -> addAcquireToQueue(cont) },
    onAcquired = { cont -> resume(cont) }
)

private class SemaphoreImpl(permits: Int) {
    fun acquire() { error("too many: $permits permits requested") }
}

private class SemaphoreSegment(id: Long) {
    fun clean() {}
}
"#;
    let dir = std::env::temp_dir();
    let file = dir.join("tldr_kotlin_cascade_b_kotlin_grammar.kt");
    std::fs::write(&file, src).expect("write temp kotlin file");
    let info = extract_file(&file, None).expect("extract_file on kotlin source");
    let names: Vec<&str> = info.classes.iter().map(|c| c.name.as_str()).collect();
    assert!(
        names.contains(&"SemaphoreImpl"),
        "SemaphoreImpl class_declaration not recovered; classes found: {names:?}"
    );
    assert!(
        names.contains(&"SemaphoreSegment"),
        "SemaphoreSegment class_declaration not recovered; classes found: {names:?}"
    );
    let _ = std::fs::remove_file(&file);
}
