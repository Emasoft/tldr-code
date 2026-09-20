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

    // Formats extension - must parse (formats batch + latex + markdown)
    assert!(
        pool.parse("\\section{Intro}\nbody", Language::Latex)
            .is_ok(),
        "LaTeX grammar failed to load"
    );
    assert!(
        pool.parse("# Heading\n\nbody", Language::Markdown).is_ok(),
        "Markdown grammar failed to load"
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
// LaTeX AST Node Types (codebook-tree-sitter-latex 0.6.1 — republished
// latex-lsp/tree-sitter-latex grammar)
// =============================================================================

#[test]
fn test_latex_ast_node_types() {
    // Sectioning commands: DEDICATED node kinds, one per level (starred and
    // KOMA variants fold into the same kind). The element walker
    // (ast::elements::walk_latex) keys on exactly these names.
    assert_node_type_exists("\\section{Intro}\nbody", Language::Latex, "section");
    assert_node_type_exists("\\subsection{Sub}\nbody", Language::Latex, "subsection");
    assert_node_type_exists("\\chapter{Ch}\nbody", Language::Latex, "chapter");

    // Environments: generic + grammar-specialized kinds, all with
    // begin/end fields; the `begin` node carries the `name` field.
    assert_node_type_exists(
        "\\begin{itemize}\n\\item x\n\\end{itemize}",
        Language::Latex,
        "generic_environment",
    );
    assert_node_type_exists(
        "\\begin{equation}\nE = mc^2\n\\end{equation}",
        Language::Latex,
        "math_environment",
    );
    assert_node_type_exists(
        "\\begin{verbatim}\nraw\n\\end{verbatim}",
        Language::Latex,
        "verbatim_environment",
    );
    assert_node_type_exists(
        "\\begin{document}\n\\end{document}",
        Language::Latex,
        "begin",
    );
}

// =============================================================================
// Markdown AST Node Types (tree-sitter-md 0.5.3 — BLOCK grammar
// `tree_sitter_md::LANGUAGE`; the crate also ships INLINE_LANGUAGE, which is
// deliberately not wired — see ParserPool + ast::elements::walk_markdown)
// =============================================================================

#[test]
fn test_markdown_ast_node_types() {
    // Headings: ATX (markers are separate `atx_hN_marker` children, the text
    // lives in the `heading_content` field) and setext (the `heading_content`
    // field is the paragraph; the underline is a sibling child). The element
    // walker (ast::elements::walk_markdown) keys on exactly these names.
    assert_node_type_exists("# Title\n\nbody", Language::Markdown, "atx_heading");
    assert_node_type_exists("### Deep\n\nbody", Language::Markdown, "atx_h3_marker");
    assert_node_type_exists(
        "Setext\n======\n\nbody",
        Language::Markdown,
        "setext_heading",
    );
    assert_node_type_exists(
        "Setext\n======\n\nbody",
        Language::Markdown,
        "setext_h1_underline",
    );

    // Code blocks: fenced (open delimiter + info_string with a named
    // `language` child) and indented (a dedicated kind in this grammar —
    // 4-space indented code emits its own node).
    assert_node_type_exists(
        "```rust\nfn main() {}\n```\n\nbody",
        Language::Markdown,
        "fenced_code_block",
    );
    assert_node_type_exists(
        "```rust\nfn main() {}\n```\n\nbody",
        Language::Markdown,
        "info_string",
    );
    assert_node_type_exists(
        "```rust\nfn main() {}\n```\n\nbody",
        Language::Markdown,
        "language",
    );
    assert_node_type_exists(
        "```rust\nfn main() {}\n```\n\nbody",
        Language::Markdown,
        "fenced_code_block_delimiter",
    );
    assert_node_type_exists(
        "# T\n\n    indented code\n",
        Language::Markdown,
        "indented_code_block",
    );

    // Tables: pipe_table with a header row (cells), delimiter row, body rows.
    assert_node_type_exists(
        "| A | B |\n| - | - |\n| 1 | 2 |\n",
        Language::Markdown,
        "pipe_table",
    );
    assert_node_type_exists(
        "| A | B |\n| - | - |\n| 1 | 2 |\n",
        Language::Markdown,
        "pipe_table_header",
    );
    assert_node_type_exists(
        "| A | B |\n| - | - |\n| 1 | 2 |\n",
        Language::Markdown,
        "pipe_table_cell",
    );
    assert_node_type_exists(
        "| A | B |\n| - | - |\n| 1 | 2 |\n",
        Language::Markdown,
        "pipe_table_delimiter_row",
    );

    // Block structure: the root is `document`; content nests inside
    // `section` wrappers (one per top-level heading).
    assert_node_type_exists("# Title\n\nbody", Language::Markdown, "document");
    assert_node_type_exists("# Title\n\nbody", Language::Markdown, "section");
    assert_node_type_exists("# Title\n\nbody", Language::Markdown, "inline");
}

/// yaml grammar stability (V-YAML, 2026-09): the YAML grammar is now the
/// VENDORED int32-row patched fork of tree-sitter-yaml 0.7.0
/// (`vendor/tree-sitter-yaml`), so this test both pins the node kinds the
/// element walker needs AND proves the patched scanner parses past the old
/// 32,768-row int16 overflow abort — node kinds are UNCHANGED from upstream
/// (parser.c is byte-identical upstream 0.7.0; only scanner.c counters were
/// widened), so a re-vendor onto a fixed upstream release keeps this green.
#[test]
fn test_yaml_vendored_grammar_node_types_stable() {
    // Block structure: the element walker (`ast::elements::walk_yaml`) keys
    // on `stream` → `document` → `block_mapping_pair`/`flow_pair`.
    assert_node_type_exists("name: tldr\ncount: 42\n", Language::Yaml, "stream");
    assert_node_type_exists("name: tldr\ncount: 42\n", Language::Yaml, "document");
    assert_node_type_exists("name: tldr\ncount: 42\n", Language::Yaml, "block_mapping");
    assert_node_type_exists(
        "name: tldr\ncount: 42\n",
        Language::Yaml,
        "block_mapping_pair",
    );
    assert_node_type_exists(
        "name: tldr\nitems:\n  - one\n  - two\n",
        Language::Yaml,
        "block_sequence",
    );
    assert_node_type_exists(
        "name: tldr\nitems:\n  - one\n  - two\n",
        Language::Yaml,
        "block_sequence_item",
    );
    assert_node_type_exists("{a: 1, b: 2}\n", Language::Yaml, "flow_mapping");
    assert_node_type_exists("{a: 1, b: 2}\n", Language::Yaml, "flow_pair");
    assert_node_type_exists("name: tldr\n", Language::Yaml, "plain_scalar");
}

/// yaml past the old int16 abort (V-YAML, 2026-09): 40,000-line single and
/// multi-document sources must parse CLEAN through the vendored patched
/// grammar — upstream 0.7.0 aborted into a root `ERROR` at row 32768. This
/// is the grammar-level half of the pin; `yaml_vendored_grammar_v1` covers
/// the end-to-end extraction.
#[test]
fn test_yaml_vendored_grammar_parses_past_the_old_int16_abort() {
    let pool = ParserPool::new();

    // (a) a single 40,000-key block mapping (40,000 lines) — un-splittable,
    // this exact shape forced the yaml-native-outline workaround before.
    let single: String = (0..40_000)
        .map(|i| format!("key-{i}: value-{i}\n"))
        .collect();
    assert_eq!(single.lines().count(), 40_000);
    let tree = pool
        .parse(&single, Language::Yaml)
        .expect("yaml single-document parse must succeed");
    assert!(
        !tree.root_node().has_error(),
        "40k-line single-document yaml must parse clean through the vendored grammar"
    );

    // (b) a 40,000-line `---`-delimited stream (8,000 documents) — this
    // shape forced the yaml-chunk-v1 splitter before.
    let multi: String = (0..8_000)
        .map(|i| format!("---\nid: {i}\nitems:\n  - x\n  - y\n"))
        .collect();
    assert_eq!(multi.lines().count(), 40_000);
    let tree = pool
        .parse(&multi, Language::Yaml)
        .expect("yaml multi-document parse must succeed");
    assert!(
        !tree.root_node().has_error(),
        "40k-line multi-document yaml must parse clean through the vendored grammar"
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
