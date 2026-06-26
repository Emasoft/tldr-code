//! Language-specific import parsing (spec Section 2.1.4)
//!
//! Parses import statements from source files for various languages:
//! - Python: import X, from X import Y, relative imports
//! - TypeScript: import, require, dynamic import
//! - Go: import "pkg", import alias
//! - Rust: use, mod, extern crate

use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::types::{ImportInfo, Language};
use crate::TldrResult;

use super::parser::parse_file_with_lang;

/// Parse imports from a source file.
///
/// The supplied `language` is forwarded as a hint to the parser, so
/// extensionless files (e.g. `tldr imports myscript --lang python`)
/// parse correctly instead of failing path-extension detection inside
/// the parser pool.
///
/// # Arguments
/// * `file_path` - Path to source file
/// * `language` - Programming language; overrides extension detection
///
/// # Returns
/// * `Ok(Vec<ImportInfo>)` - List of imports
/// * `Err(TldrError::PathNotFound)` - File doesn't exist
pub fn get_imports(file_path: &Path, language: Language) -> TldrResult<Vec<ImportInfo>> {
    let (tree, source, _) = parse_file_with_lang(file_path, Some(language))?;
    extract_imports_from_tree(&tree, &source, language)
}

/// Extract imports from a parsed tree
pub fn extract_imports_from_tree(
    tree: &Tree,
    source: &str,
    language: Language,
) -> TldrResult<Vec<ImportInfo>> {
    let root = tree.root_node();

    let imports = match language {
        Language::Python => extract_python_imports(&root, source),
        Language::TypeScript | Language::JavaScript => extract_ts_imports(&root, source),
        Language::Go => extract_go_imports(&root, source),
        Language::Rust => extract_rust_imports(&root, source),
        Language::Java => extract_java_imports(&root, source),
        Language::C => extract_c_imports(&root, source),
        Language::Cpp => extract_cpp_imports(&root, source),
        Language::Ruby => extract_ruby_imports(&root, source),
        Language::CSharp => extract_csharp_imports(&root, source),
        Language::Scala => extract_scala_imports(&root, source),
        Language::Elixir => extract_elixir_imports(&root, source),
        Language::Ocaml => extract_ocaml_imports(&root, source),
        Language::Php => extract_php_imports(&root, source),
        Language::Lua | Language::Luau => extract_lua_imports(&root, source),
        Language::Kotlin => extract_kotlin_imports(&root, source),
        Language::Swift => extract_swift_imports(&root, source),
        // v0.5.0 SOL-007 solidity-deps-v1: extract all 5 Solidity
        // import forms (plain / `as` alias / `* as` /
        // selective `{ X, Y }` / selective with alias). Source path
        // comes from the `source` field (a `string` literal); aliases
        // are surfaced via `alias` (whole-file `as` form) or `names`
        // (selective form, including `X as Y`).
        Language::Solidity => extract_solidity_imports(&root, source),
    };

    Ok(imports)
}

// =============================================================================
// Python imports
// =============================================================================

fn extract_python_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_python_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_python_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        // importers-ast-anchored-v1 (M-035): pin line to the AST node.
        let stmt_line = node_line(&child);
        match child.kind() {
            "import_statement" => {
                // import X, Y, Z
                let mut import_cursor = child.walk();
                for import_child in child.children(&mut import_cursor) {
                    if import_child.kind() == "dotted_name" {
                        let module = get_node_text(&import_child, source);
                        imports.push(ImportInfo {
                            module,
                            names: Vec::new(),
                            is_from: Some(false),
                            alias: None,
                            line: stmt_line,
                        });
                    } else if import_child.kind() == "aliased_import" {
                        let module = import_child
                            .child_by_field_name("name")
                            .map(|n| get_node_text(&n, source))
                            .unwrap_or_default();
                        let alias = import_child
                            .child_by_field_name("alias")
                            .map(|n| get_node_text(&n, source));
                        imports.push(ImportInfo {
                            module,
                            names: Vec::new(),
                            is_from: Some(false),
                            alias,
                            line: stmt_line,
                        });
                    }
                }
            }
            "future_import_statement" => {
                // from __future__ import annotations
                //
                // (path-and-schema-cleanup-v3 P3.BUG-N3) Tree-sitter Python
                // emits a dedicated `future_import_statement` node for
                // `from __future__ import X` (distinct from the regular
                // `import_from_statement` because `__future__` triggers
                // compile-time pragma behaviour). The previous extractor
                // did not handle this node kind, so `__future__` imports
                // were silently dropped. Treat them like any other
                // `from M import X, Y` — `__future__` is a real module
                // reference that downstream consumers (deps, change-impact,
                // imports surface) should see.
                let mut names = Vec::new();
                let mut import_cursor = child.walk();
                for import_child in child.children(&mut import_cursor) {
                    match import_child.kind() {
                        // Each imported feature: `annotations`,
                        // `division`, etc. Tree-sitter exposes these as
                        // bare `dotted_name`/`identifier` children of the
                        // future_import_statement node.
                        "dotted_name" | "identifier" => {
                            let text = get_node_text(&import_child, source);
                            // Skip the literal `__future__` keyword if
                            // tree-sitter ever surfaces it as an
                            // identifier-shaped child (defensive).
                            if text != "__future__" {
                                names.push(text);
                            }
                        }
                        "aliased_import" => {
                            let name = import_child
                                .child_by_field_name("name")
                                .map(|n| get_node_text(&n, source))
                                .unwrap_or_default();
                            let alias = import_child
                                .child_by_field_name("alias")
                                .map(|n| get_node_text(&n, source));
                            imports.push(ImportInfo {
                                module: "__future__".to_string(),
                                names: vec![name],
                                is_from: Some(true),
                                alias,
                                line: stmt_line,
                            });
                        }
                        _ => {}
                    }
                }
                if !names.is_empty() {
                    imports.push(ImportInfo {
                        module: "__future__".to_string(),
                        names,
                        is_from: Some(true),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            "import_from_statement" => {
                // from X import Y, Z
                let module = child
                    .child_by_field_name("module_name")
                    .map(|n| get_node_text(&n, source))
                    .unwrap_or_else(|| {
                        // Handle relative imports (from . import X)
                        let mut module_parts = Vec::new();
                        let mut c = child.walk();
                        for part in child.children(&mut c) {
                            if part.kind() == "." || part.kind() == "relative_import" {
                                module_parts.push(".".to_string());
                            } else if part.kind() == "dotted_name" {
                                module_parts.push(get_node_text(&part, source));
                            }
                        }
                        module_parts.join("")
                    });

                let mut names = Vec::new();
                let mut import_cursor = child.walk();

                for import_child in child.children(&mut import_cursor) {
                    match import_child.kind() {
                        "dotted_name" | "identifier" => {
                            // Skip if this is the module name
                            if import_child.start_byte()
                                > child
                                    .child_by_field_name("module_name")
                                    .map(|n| n.end_byte())
                                    .unwrap_or(0)
                            {
                                names.push(get_node_text(&import_child, source));
                            }
                        }
                        "aliased_import" => {
                            // For aliased imports, create a separate ImportInfo entry
                            let name = import_child
                                .child_by_field_name("name")
                                .map(|n| get_node_text(&n, source))
                                .unwrap_or_default();
                            let alias = import_child
                                .child_by_field_name("alias")
                                .map(|n| get_node_text(&n, source));

                            imports.push(ImportInfo {
                                module: module.clone(),
                                names: vec![name],
                                is_from: Some(true),
                                alias,
                                line: stmt_line,
                            });
                        }
                        "wildcard_import" => {
                            names.push("*".to_string());
                        }
                        _ => {}
                    }
                }

                // Only push a general import if we collected non-aliased names
                if !names.is_empty() {
                    imports.push(ImportInfo {
                        module,
                        names,
                        is_from: Some(true),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            _ => {
                extract_python_imports_recursive(&child, source, imports);
            }
        }
    }
}

// =============================================================================
// TypeScript/JavaScript imports
// =============================================================================

fn extract_ts_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_ts_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_ts_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            // high-bundle-progress-determinism-coverage-v1 (N5): CommonJS
            // `require('module')` calls. Many production JS files (express,
            // most legacy npm packages) use CJS exclusively, so the previous
            // ESM-only parser returned `imports: []` for files like
            // `express/index.js` that contained only `module.exports =
            // require('./lib/express');`. Detect `require(<string>)` and
            // emit it as a from-style import with `is_from = true` so
            // downstream consumers (call graph builder, dependency graphs)
            // see the edge.
            "call_expression" => {
                if let Some(mut import) = parse_cjs_require(&child, source) {
                    import.line = node_line(&child);
                    imports.push(import);
                }
                // Still recurse — `require()` may be nested inside an
                // assignment, an array literal, etc.
                extract_ts_imports_recursive(&child, source, imports);
            }
            // CommonJS shorthand exports rely on `require` as a callee at
            // the top of an assignment. The grammar wraps the call in
            // `variable_declarator`, `lexical_declaration`, or
            // `assignment_expression` — the recursion below handles those,
            // but we need an explicit case for the top-level
            // `expression_statement` form to ensure we don't bail.
            "import_statement" => {
                let module = child
                    .child_by_field_name("source")
                    .map(|n| get_string_content(&n, source))
                    .unwrap_or_default();

                let mut names = Vec::new();
                let mut is_default = false;

                // Parse import clause
                if let Some(clause) = child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "import_clause")
                {
                    let mut clause_cursor = clause.walk();
                    for clause_child in clause.children(&mut clause_cursor) {
                        match clause_child.kind() {
                            "identifier" => {
                                // Default import
                                is_default = true;
                                names.push(get_node_text(&clause_child, source));
                            }
                            "named_imports" => {
                                // { a, b, c }
                                let mut named_cursor = clause_child.walk();
                                for named in clause_child.children(&mut named_cursor) {
                                    if named.kind() == "import_specifier" {
                                        if let Some(name) = named.child_by_field_name("name") {
                                            names.push(get_node_text(&name, source));
                                        }
                                    }
                                }
                            }
                            "namespace_import" => {
                                // import * as X — extract X as alias
                                names.push("*".to_string());
                                // Find the identifier after "as" in namespace_import
                                let mut ns_cursor = clause_child.walk();
                                for ns_child in clause_child.children(&mut ns_cursor) {
                                    if ns_child.kind() == "identifier" {
                                        is_default = false; // mark as namespace, not default
                                                            // Store alias name temporarily — will be set below
                                        names.push(get_node_text(&ns_child, source));
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                imports.push(ImportInfo {
                    module,
                    names,
                    is_from: Some(!is_default),
                    alias: None,
                    line: node_line(&child),
                });
            }
            "export_statement" => {
                // export { x } from 'module' - re-exports
                if let Some(source_node) = child.child_by_field_name("source") {
                    let module = get_string_content(&source_node, source);
                    imports.push(ImportInfo {
                        module,
                        names: Vec::new(),
                        is_from: Some(true),
                        alias: None,
                        line: node_line(&child),
                    });
                }
            }
            _ => {
                extract_ts_imports_recursive(&child, source, imports);
            }
        }
    }
}

// =============================================================================
// Go imports
// =============================================================================

fn extract_go_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_go_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_go_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_declaration" => {
                let mut decl_cursor = child.walk();
                for decl_child in child.children(&mut decl_cursor) {
                    match decl_child.kind() {
                        "import_spec" => {
                            // importers-ast-anchored-v1 (M-035): use the
                            // import_spec line so multi-spec `import (...)`
                            // blocks surface the row where the module
                            // string actually sits, not the outer
                            // `import` keyword line.
                            let spec_line = node_line(&decl_child);
                            let module = decl_child
                                .child_by_field_name("path")
                                .map(|n| get_string_content(&n, source))
                                .unwrap_or_default();

                            let alias = decl_child
                                .child_by_field_name("name")
                                .map(|n| get_node_text(&n, source));

                            imports.push(ImportInfo {
                                module,
                                names: Vec::new(),
                                is_from: Some(false),
                                alias,
                                line: spec_line,
                            });
                        }
                        "import_spec_list" => {
                            let mut list_cursor = decl_child.walk();
                            for spec in decl_child.children(&mut list_cursor) {
                                if spec.kind() == "import_spec" {
                                    let spec_line = node_line(&spec);
                                    let module = spec
                                        .child_by_field_name("path")
                                        .map(|n| get_string_content(&n, source))
                                        .unwrap_or_default();

                                    let alias = spec
                                        .child_by_field_name("name")
                                        .map(|n| get_node_text(&n, source));

                                    imports.push(ImportInfo {
                                        module,
                                        names: Vec::new(),
                                        is_from: Some(false),
                                        alias,
                                        line: spec_line,
                                    });
                                }
                            }
                        }
                        "interpreted_string_literal" => {
                            // Single import without parentheses
                            let spec_line = node_line(&decl_child);
                            let module = get_string_content(&decl_child, source);
                            imports.push(ImportInfo {
                                module,
                                names: Vec::new(),
                                is_from: Some(false),
                                alias: None,
                                line: spec_line,
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                extract_go_imports_recursive(&child, source, imports);
            }
        }
    }
}

// =============================================================================
// Rust imports
// =============================================================================

fn extract_rust_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_rust_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_rust_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let stmt_line = node_line(&child);
        match child.kind() {
            "use_declaration" => {
                // use std::collections::HashMap;
                // use crate::module::{A, B};
                // Extract the path and names
                if let Some(arg) = child.child_by_field_name("argument") {
                    let (module, names) = parse_rust_use_path(&arg, source);
                    imports.push(ImportInfo {
                        module,
                        names,
                        is_from: Some(true),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            "mod_item" => {
                // fix-R7 (cluster[11] RC8b): distinguish a module *declaration*
                // (`mod foo;`) from an inline module *definition*
                // (`mod tests { ... }`).
                //
                // A declaration brings an external module into the tree -> it is
                // a legitimate module reference and is emitted. An inline
                // definition is NOT an import (it defines, not imports); emitting
                // it as one (module="tests") was wrong, and worse, the body was
                // never descended so nested `use super::*` / `use crate::..`
                // statements inside the module were lost. So: when the mod has a
                // `body` (a `declaration_list`), recurse into it and emit nothing
                // for the mod itself; only bodyless declarations are emitted.
                if let Some(body) = child.child_by_field_name("body") {
                    extract_rust_imports_recursive(&body, source, imports);
                } else if let Some(name) = child.child_by_field_name("name") {
                    let module = get_node_text(&name, source);
                    imports.push(ImportInfo {
                        module,
                        names: Vec::new(),
                        is_from: Some(false),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            "extern_crate_declaration" => {
                // extern crate foo;
                if let Some(name) = child.child_by_field_name("name") {
                    let module = get_node_text(&name, source);
                    let alias = child
                        .child_by_field_name("alias")
                        .map(|n| get_node_text(&n, source));
                    imports.push(ImportInfo {
                        module,
                        names: Vec::new(),
                        is_from: Some(false),
                        alias,
                        line: stmt_line,
                    });
                }
            }
            _ => {
                extract_rust_imports_recursive(&child, source, imports);
            }
        }
    }
}

fn parse_rust_use_path(node: &Node, source: &str) -> (String, Vec<String>) {
    // Use proper AST traversal for complex use statements
    let mut imports = Vec::new();
    collect_rust_use_paths(node, source, String::new(), &mut imports);

    // If we collected imports, use the first one's module and all names
    if !imports.is_empty() {
        // Find the common module prefix
        let first_module = imports[0].0.clone();
        let names: Vec<String> = imports.into_iter().map(|(_, name)| name).collect();
        return (first_module, names);
    }

    // Fallback to simple text parsing for edge cases
    let text = get_node_text(node, source);

    // Simple heuristic: split on :: and handle {a, b}
    if let Some(brace_pos) = text.find('{') {
        let module = text[..brace_pos].trim_end_matches("::").to_string();
        let names_part = &text[brace_pos..];
        let names: Vec<String> = names_part
            .trim_matches(|c| c == '{' || c == '}')
            .split(',')
            .map(|s| {
                // Handle "self" and aliases like "HashMap as Map"
                let s = s.trim();
                if let Some(as_pos) = s.find(" as ") {
                    s[..as_pos].trim().to_string()
                } else {
                    s.to_string()
                }
            })
            .filter(|s| !s.is_empty())
            .collect();
        (module, names)
    } else {
        // No braces - extract last segment as name
        let parts: Vec<&str> = text.split("::").collect();
        if parts.len() > 1 {
            let module = parts[..parts.len() - 1].join("::");
            let name = parts.last().unwrap().to_string();
            (module, vec![name])
        } else {
            (text, Vec::new())
        }
    }
}

/// Recursively collect all imports from a Rust use tree
/// Handles nested use groups like `use std::{io::{self, Read}, collections::HashMap}`
fn collect_rust_use_paths(
    node: &Node,
    source: &str,
    prefix: String,
    imports: &mut Vec<(String, String)>,
) {
    match node.kind() {
        "scoped_identifier" | "identifier" => {
            // Simple path like `std::collections::HashMap`
            let text = get_node_text(node, source);
            let full_path = if prefix.is_empty() {
                text.clone()
            } else {
                format!("{}::{}", prefix, text)
            };

            // Extract the module and name parts
            let parts: Vec<&str> = full_path.split("::").collect();
            if parts.len() > 1 {
                let module = parts[..parts.len() - 1].join("::");
                let name = parts.last().unwrap().to_string();
                imports.push((module, name));
            } else {
                imports.push((String::new(), full_path));
            }
        }
        "scoped_use_list" => {
            // Handle `std::io::{Read, Write}`
            // First child is the path, second is the use_list
            if let Some(path_node) = node.child_by_field_name("path") {
                let path_text = get_node_text(&path_node, source);
                let new_prefix = if prefix.is_empty() {
                    path_text
                } else {
                    format!("{}::{}", prefix, path_text)
                };

                // Find the use_list child
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "use_list" {
                        collect_rust_use_paths(&child, source, new_prefix.clone(), imports);
                    }
                }
            }
        }
        "use_list" => {
            // Handle `{Read, Write, self}`
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_rust_use_paths(&child, source, prefix.clone(), imports);
            }
        }
        "use_as_clause" => {
            // Handle `HashMap as Map`
            if let Some(path_node) = node.child_by_field_name("path") {
                collect_rust_use_paths(&path_node, source, prefix, imports);
            }
        }
        "use_wildcard" => {
            // Handle `use foo::*`, `use self::Bar::*`, `use crate::x::*`.
            //
            // fix-R7 (cluster[11] RC8a): the wildcard's path lives in its first
            // *named* child (a `scoped_identifier`, bare `identifier`, or a
            // `self`/`super`/`crate` path keyword) followed by the `::` and `*`
            // tokens. Previously we pushed `(prefix, "*")` and dropped that
            // child entirely, so `use clap_builder::*` reported module="".
            // Recover the path and join it with any inherited prefix.
            let path = node
                .children(&mut node.walk())
                .find(|c| {
                    c.is_named()
                        && matches!(
                            c.kind(),
                            "scoped_identifier"
                                | "identifier"
                                | "self"
                                | "super"
                                | "crate"
                                | "metavariable"
                        )
                })
                .map(|c| get_node_text(&c, source))
                .unwrap_or_default();
            let module = match (prefix.is_empty(), path.is_empty()) {
                (true, _) => path,
                (false, true) => prefix,
                (false, false) => format!("{}::{}", prefix, path),
            };
            imports.push((module, "*".to_string()));
        }
        "self" => {
            // Handle `{self, Read}` - self imports the module itself
            imports.push((prefix, "self".to_string()));
        }
        _ => {
            // Recursively check children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_rust_use_paths(&child, source, prefix.clone(), imports);
            }
        }
    }
}

// =============================================================================
// Java imports
// =============================================================================

fn extract_java_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_java_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_java_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "import_declaration" {
            let mut is_static = false;
            let mut is_wildcard = false;
            let mut module = String::new();

            let mut import_cursor = child.walk();
            for import_child in child.children(&mut import_cursor) {
                match import_child.kind() {
                    "static" => is_static = true,
                    "scoped_identifier" | "identifier" => {
                        module = get_node_text(&import_child, source);
                    }
                    "asterisk" => is_wildcard = true,
                    _ => {}
                }
            }

            // Handle wildcard
            if is_wildcard {
                module = format!("{}.*", module);
            }

            imports.push(ImportInfo {
                module,
                names: Vec::new(),
                is_from: Some(is_static),
                alias: None,
                line: node_line(&child),
            });
        } else {
            extract_java_imports_recursive(&child, source, imports);
        }
    }
}

// =============================================================================
// C imports (#include directives)
// =============================================================================

fn extract_c_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_c_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_c_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "preproc_include" {
            // #include <header.h> or #include "header.h"
            if let Some(path_node) = child.child_by_field_name("path") {
                let path_kind = path_node.kind();
                let raw_text = get_node_text(&path_node, source);

                // rc3-external-deps-c-lua-php-v1 (v0.5.0 CLOSEOUT): the
                // tree-sitter-c grammar hands us the system-vs-local bit via
                // two distinct `path`-child node kinds. Preserve it on
                // `is_from` (Some(true) = `<...>` system / toolchain header,
                // Some(false) = `"..."` local header) so `classify_import`
                // can route system headers to Stdlib instead of inflating the
                // third-party External axis. The `path` field's grammar type
                // set is EXACTLY four kinds (tree-sitter-c node-types.json):
                // `system_lib_string`, `string_literal`, `identifier`,
                // `call_expression`. The latter two are macro indirections
                // (`#include MACRO` / `#include MACRO(args)`) whose target is
                // unknowable without preprocessing — drop them rather than
                // leak fabricated deps (e.g. `HDR_MALLOC_INCLUDE`).
                let (module, is_from) = match path_kind {
                    "system_lib_string" => {
                        // <stdio.h> -> strip < and >; system/toolchain header.
                        (
                            raw_text.trim_matches(|c| c == '<' || c == '>').to_string(),
                            Some(true),
                        )
                    }
                    "string_literal" => {
                        // "local.h" -> strip quotes; local/project header.
                        (raw_text.trim_matches('"').to_string(), Some(false))
                    }
                    // `identifier` / `call_expression`: macro indirection —
                    // drop (defensive `_` covers the grammar-impossible 5th).
                    _ => continue,
                };

                imports.push(ImportInfo {
                    module,
                    names: Vec::new(),
                    is_from,
                    alias: None,
                    line: node_line(&child),
                });
            }
        } else {
            // Recurse into other nodes
            extract_c_imports_recursive(&child, source, imports);
        }
    }
}

// =============================================================================
// C++ imports (#include directives)
// =============================================================================

fn extract_cpp_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    // C++ uses the same #include syntax as C
    // The tree-sitter-cpp grammar also uses preproc_include
    let mut imports = Vec::new();
    extract_cpp_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_cpp_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "preproc_include" {
            // #include <header> or #include "header"
            if let Some(path_node) = child.child_by_field_name("path") {
                let path_kind = path_node.kind();
                let raw_text = get_node_text(&path_node, source);

                // rc3-external-deps-c-lua-php-v1: C++ shares the C
                // `preproc_include` grammar (tree-sitter-cpp re-uses
                // tree-sitter-c's rule). Preserve the system-vs-local bit on
                // `is_from` and drop macro indirections — see
                // `extract_c_imports_recursive` for the full rationale.
                let (module, is_from) = match path_kind {
                    "system_lib_string" => (
                        raw_text.trim_matches(|c| c == '<' || c == '>').to_string(),
                        Some(true),
                    ),
                    "string_literal" => (raw_text.trim_matches('"').to_string(), Some(false)),
                    _ => continue,
                };

                imports.push(ImportInfo {
                    module,
                    names: Vec::new(),
                    is_from,
                    alias: None,
                    line: node_line(&child),
                });
            }
        } else {
            extract_cpp_imports_recursive(&child, source, imports);
        }
    }
}

// =============================================================================
// Ruby imports (require/require_relative)
// =============================================================================

fn extract_ruby_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_ruby_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_ruby_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let stmt_line = node_line(&child);
        if child.kind() == "call" {
            // Check if this is a require/require_relative call
            let mut call_cursor = child.walk();
            let mut method_name = String::new();
            let mut arg_value = String::new();

            for call_child in child.children(&mut call_cursor) {
                match call_child.kind() {
                    "identifier" => {
                        method_name = get_node_text(&call_child, source);
                    }
                    "argument_list" => {
                        // Get the string argument
                        let mut arg_cursor = call_child.walk();
                        for arg_child in call_child.children(&mut arg_cursor) {
                            if arg_child.kind() == "string" {
                                // Look for string_content inside the string node
                                let mut str_cursor = arg_child.walk();
                                for str_child in arg_child.children(&mut str_cursor) {
                                    if str_child.kind() == "string_content" {
                                        arg_value = get_node_text(&str_child, source);
                                        break;
                                    }
                                }
                                if arg_value.is_empty() {
                                    // Fallback: use the whole string text with quotes stripped
                                    arg_value = get_string_content(&arg_child, source);
                                }
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Handle different require patterns
            match method_name.as_str() {
                "require" => {
                    if !arg_value.is_empty() {
                        // imports-is-from-schema-v1 (v0.4.2 M-021): Ruby omits
                        // `is_from`; the relative-vs-absolute distinction is
                        // recoverable from the module string (`./`/`../`).
                        imports.push(ImportInfo {
                            module: arg_value,
                            names: Vec::new(),
                            is_from: None,
                            alias: None,
                            line: stmt_line,
                        });
                    }
                }
                "require_relative" => {
                    if !arg_value.is_empty() {
                        // require_relative './path' - always relative
                        imports.push(ImportInfo {
                            module: arg_value,
                            names: Vec::new(),
                            is_from: None, // is_from = true for require_relative (relative import)
                            alias: None,
                            line: stmt_line,
                        });
                    }
                }
                _ => {}
            }
        }

        // Recurse into other nodes
        extract_ruby_imports_recursive(&child, source, imports);
    }
}

// =============================================================================
// C# imports (using directives)
// =============================================================================

fn extract_csharp_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_csharp_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_csharp_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "using_directive" {
            // C# using directives:
            // - using System;
            // - using static System.Math;
            // - global using System;
            // - using Alias = System.Collections.Generic;
            //
            // importers-ast-anchored-v1 (v0.4.2 M-035): tree-sitter-c-sharp
            // grammar variants differ on alias shape. Some emit a
            // `name_equals` parent wrapping `identifier "Alias"` + `=`; older
            // grammars (and the version pinned here) emit a bare `=` literal
            // child of the using_directive with `Alias` as the FIRST
            // `identifier` child and the RHS qualified_name AFTER the `=`.
            // The previous code assumed only the `name_equals` shape, so on
            // grammars without that node the alias name was captured as
            // `module` (wrong), with `alias = None`. The corrected pass
            // below handles both shapes.

            let text = get_node_text(&child, source);
            let is_static = text.contains("static");
            let is_global = text.contains("global");

            let mut module = String::new();
            let mut alias: Option<String> = None;

            // Single pass: track whether we've passed an `=` token. The
            // first qualified-name-shaped child BEFORE `=` is the alias;
            // the first one AFTER `=` is the real module. If no `=` is
            // present (no alias), the first qualified-name-shaped child
            // IS the module.
            let mut past_equals = false;
            let mut using_cursor = child.walk();
            for using_child in child.children(&mut using_cursor) {
                match using_child.kind() {
                    "=" => {
                        past_equals = true;
                        // Whatever we captured before `=` was actually the
                        // alias, not the module — re-assign.
                        if !module.is_empty() && alias.is_none() {
                            alias = Some(std::mem::take(&mut module));
                        }
                    }
                    "name_equals" => {
                        // Grammar variant: `name_equals` wraps `identifier =`.
                        past_equals = true;
                        if alias.is_none() {
                            let mut name_cursor = using_child.walk();
                            for name_child in using_child.children(&mut name_cursor) {
                                if name_child.kind() == "identifier" {
                                    alias = Some(get_node_text(&name_child, source));
                                    break;
                                }
                            }
                        }
                        // Clear module: anything captured before this is
                        // discarded (would have been the alias).
                        module.clear();
                    }
                    "qualified_name" | "identifier" | "name" => {
                        if past_equals {
                            // Always prefer the post-= name as module.
                            module = get_node_text(&using_child, source);
                        } else if module.is_empty() {
                            module = get_node_text(&using_child, source);
                        }
                    }
                    _ => {}
                }
            }

            if !module.is_empty() {
                imports.push(ImportInfo {
                    module,
                    names: Vec::new(),
                    // Use is_from to indicate static imports (similar to Java pattern)
                    is_from: Some(is_static || is_global),
                    alias,
                    line: node_line(&child),
                });
            }
        } else {
            // Recurse into other nodes (e.g., namespace declarations)
            extract_csharp_imports_recursive(&child, source, imports);
        }
    }
}

// =============================================================================
// Scala imports
// =============================================================================

fn extract_scala_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_scala_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_scala_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "import_declaration" {
            // Scala import syntax:
            // - import scala.util.Try                    (simple)
            // - import scala.collection._               (wildcard)
            // - import scala.util.{Try, Success}        (selective)
            // - import scala.util.{Try => T}            (rename with =>)
            // - import scala.util.{Try, Success => S, _} (mixed)

            // Get the full import text for parsing
            let import_text = get_node_text(&child, source);

            // Remove "import " prefix
            let text = import_text
                .strip_prefix("import ")
                .unwrap_or(&import_text)
                .trim();

            // Parse the import text
            parse_scala_import_text(text, imports, node_line(&child));
        } else {
            // Recurse into other nodes
            extract_scala_imports_recursive(&child, source, imports);
        }
    }
}

/// Parse Scala import text and extract ImportInfo entries
fn parse_scala_import_text(text: &str, imports: &mut Vec<ImportInfo>, line: u32) {
    // Check for selective imports with braces: import scala.util.{Try, Success}
    if let Some(brace_pos) = text.find('{') {
        let base_path = text[..brace_pos].trim_end_matches('.').to_string();
        let selectors_part = &text[brace_pos..];

        // Extract content between braces
        let selectors_content = selectors_part
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();

        // Parse each selector
        for selector in selectors_content.split(',') {
            let selector = selector.trim();
            if selector.is_empty() {
                continue;
            }

            // Check for rename: member => alias (Scala uses => for rename)
            if selector.contains("=>") {
                let parts: Vec<&str> = selector.split("=>").collect();
                if parts.len() == 2 {
                    let orig = parts[0].trim();
                    let alias = parts[1].trim();

                    // Skip if original is "_" (hide import)
                    if orig == "_" {
                        continue;
                    }

                    let full_module = if base_path.is_empty() {
                        orig.to_string()
                    } else {
                        format!("{}.{}", base_path, orig)
                    };

                    imports.push(ImportInfo {
                        module: full_module,
                        names: Vec::new(),
                        is_from: Some(false),
                        // alias is None if it's "_" (hide), otherwise the alias name
                        alias: if alias == "_" {
                            None
                        } else {
                            Some(alias.to_string())
                        },
                        line,
                    });
                }
            } else if selector == "_" {
                // Wildcard import inside braces: import scala.util.{_, ...}
                imports.push(ImportInfo {
                    module: base_path.clone(),
                    names: vec!["*".to_string()],
                    is_from: Some(true),
                    alias: None,
                    line,
                });
            } else {
                // Simple selector: import scala.util.{Try}
                let full_module = if base_path.is_empty() {
                    selector.to_string()
                } else {
                    format!("{}.{}", base_path, selector)
                };

                imports.push(ImportInfo {
                    module: full_module,
                    names: Vec::new(),
                    is_from: Some(false),
                    alias: None,
                    line,
                });
            }
        }
    } else if text.ends_with("._") {
        // Wildcard import: import scala.collection.mutable._
        let base_path = text.strip_suffix("._").unwrap_or(text).to_string();
        imports.push(ImportInfo {
            module: base_path,
            names: vec!["*".to_string()],
            is_from: Some(true),
            alias: None,
            line,
        });
    } else {
        // Simple import: import scala.collection.mutable.ListBuffer
        imports.push(ImportInfo {
            module: text.to_string(),
            names: Vec::new(),
            is_from: Some(false),
            alias: None,
            line,
        });
    }
}

// =============================================================================
// Elixir imports (import, alias, require, use)
// =============================================================================

/// Extract imports from Elixir source code.
///
/// Handles:
/// - `import Phoenix.Controller` — imports all functions from a module
/// - `alias Phoenix.LiveView` — creates alias using last segment as short name
/// - `alias Phoenix.LiveView, as: LV` — explicit alias
/// - `require Logger` — requires module for macros
/// - `use GenServer` — imports and extends with macros
fn extract_elixir_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_elixir_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_elixir_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let stmt_line = node_line(&child);
        if child.kind() == "call" {
            // Elixir import-like statements are all `call` nodes.
            // Structure: call -> identifier (keyword) + arguments -> alias (module name)
            let mut call_cursor = child.walk();
            let mut keyword = String::new();
            let mut module_name = String::new();
            // Multi-alias expansion (`alias Plug.{Conn, Router}`): each expanded
            // submodule is collected here. Non-empty iff the directive used the
            // brace-tuple form.
            let mut multi_modules: Vec<String> = Vec::new();
            let mut explicit_alias: Option<String> = None;

            for call_child in child.children(&mut call_cursor) {
                match call_child.kind() {
                    "identifier" => {
                        keyword = get_node_text(&call_child, source);
                    }
                    "arguments" => {
                        // First alias child is the module name
                        let mut args_cursor = call_child.walk();
                        for arg_child in call_child.children(&mut args_cursor) {
                            match arg_child.kind() {
                                "alias" if module_name.is_empty() => {
                                    module_name = get_node_text(&arg_child, source);
                                }
                                // Multi-alias / multi-require form
                                // `alias Plug.{Conn, Router}`. tree-sitter-elixir
                                // parses this as a `dot` node: a left `alias`
                                // prefix (`Plug`), a `.`, and a `tuple` of member
                                // `alias`/`identifier` nodes. Expand to one
                                // fully-qualified module per member so downstream
                                // consumers (deps/coupling/context/importers) see
                                // every dependency edge instead of silently
                                // dropping the whole directive.
                                "dot" if module_name.is_empty()
                                    && multi_modules.is_empty() =>
                                {
                                    multi_modules =
                                        expand_elixir_multi_alias(&arg_child, source);
                                }
                                "keywords" => {
                                    // Parse `as: ShortName` from keywords -> pair -> keyword + alias
                                    let mut kw_cursor = arg_child.walk();
                                    for kw_child in arg_child.children(&mut kw_cursor) {
                                        if kw_child.kind() == "pair" {
                                            let mut pair_cursor = kw_child.walk();
                                            let mut is_as_pair = false;
                                            for pair_child in kw_child.children(&mut pair_cursor) {
                                                match pair_child.kind() {
                                                    "keyword" => {
                                                        let kw_text =
                                                            get_node_text(&pair_child, source);
                                                        // keyword text includes trailing colon+space: "as: "
                                                        if kw_text.trim().trim_end_matches(':')
                                                            == "as"
                                                        {
                                                            is_as_pair = true;
                                                        }
                                                    }
                                                    "alias" if is_as_pair => {
                                                        explicit_alias = Some(get_node_text(
                                                            &pair_child,
                                                            source,
                                                        ));
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Modules targeted by this directive. The single-module form yields
            // exactly one; the multi-alias brace form (`alias Plug.{Conn,
            // Router}`) yields one per expanded submodule.
            let modules: Vec<String> = if !multi_modules.is_empty() {
                multi_modules
            } else if !module_name.is_empty() {
                vec![module_name]
            } else {
                Vec::new()
            };

            // Only process recognized Elixir import keywords
            match keyword.as_str() {
                "import" => {
                    for m in modules {
                        imports.push(ImportInfo {
                            module: m,
                            names: vec!["*".to_string()],
                            is_from: Some(true),
                            alias: None,
                            line: stmt_line,
                        });
                    }
                }
                "alias" => {
                    for m in &modules {
                        // If no explicit alias, Elixir uses the last segment.
                        // The explicit `as:` form is only valid for the
                        // single-module shape, so it applies when there is one
                        // module; the multi-alias members each take their own
                        // last segment.
                        let resolved_alias = if modules.len() == 1 {
                            explicit_alias
                                .clone()
                                .or_else(|| m.rsplit('.').next().map(|s| s.to_string()))
                        } else {
                            m.rsplit('.').next().map(|s| s.to_string())
                        };
                        imports.push(ImportInfo {
                            module: m.clone(),
                            names: Vec::new(),
                            is_from: Some(false),
                            alias: resolved_alias,
                            line: stmt_line,
                        });
                    }
                }
                "require" => {
                    for m in modules {
                        imports.push(ImportInfo {
                            module: m,
                            names: Vec::new(),
                            is_from: Some(false),
                            alias: None,
                            line: stmt_line,
                        });
                    }
                }
                "use" => {
                    for m in modules {
                        imports.push(ImportInfo {
                            module: m,
                            names: vec!["*".to_string()],
                            is_from: Some(true),
                            alias: None,
                            line: stmt_line,
                        });
                    }
                }
                _ => {
                    // Non-import call nodes (e.g., defmodule, def, defp) may contain import statements
                    // Recurse into the call node to find nested imports
                    extract_elixir_imports_recursive(&child, source, imports);
                }
            }
        } else {
            // Recurse into other nodes
            extract_elixir_imports_recursive(&child, source, imports);
        }
    }
}

/// Expand an Elixir multi-alias `dot` node into fully-qualified module names.
///
/// The brace form `alias Plug.{Conn, Router}` parses as a `dot` node whose
/// children are a left `alias` prefix (`Plug`), a `.`, and a `tuple` of member
/// `alias`/`identifier` nodes (`Conn`, `Router`). Returns one joined module per
/// member, e.g. `["Plug.Conn", "Plug.Router"]`. The Sourceror
/// `expand_multi_alias` expansion. Valid for `alias`/`require`/`import` (never
/// `use`).
fn expand_elixir_multi_alias(dot_node: &Node, source: &str) -> Vec<String> {
    let mut prefix = String::new();
    let mut members: Vec<String> = Vec::new();
    let mut cursor = dot_node.walk();
    for child in dot_node.children(&mut cursor) {
        match child.kind() {
            "alias" if prefix.is_empty() => {
                prefix = get_node_text(&child, source);
            }
            "tuple" => {
                let mut tcursor = child.walk();
                for member in child.children(&mut tcursor) {
                    if matches!(member.kind(), "alias" | "identifier") {
                        members.push(get_node_text(&member, source));
                    }
                }
            }
            _ => {}
        }
    }
    if prefix.is_empty() {
        return Vec::new();
    }
    members
        .into_iter()
        .map(|m| format!("{}.{}", prefix, m))
        .collect()
}

// =============================================================================
// OCaml imports (open, module alias, include)
// =============================================================================

/// Extract imports from OCaml source code.
///
/// Handles:
/// - `open ModuleName` — opens a module (like import *)
/// - `module M = ModuleName` — module alias
/// - `include ModuleName` — includes module contents
fn extract_ocaml_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_ocaml_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_ocaml_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let stmt_line = node_line(&child);
        match child.kind() {
            "open_module" => {
                // Structure: open_module -> "open" + module_path -> module_name
                if let Some(module) = extract_ocaml_module_path(&child, source) {
                    imports.push(ImportInfo {
                        module,
                        names: vec!["*".to_string()],
                        is_from: Some(true),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            "module_definition" => {
                // Structure: module_definition -> "module" + module_binding
                //   module_binding -> module_name (alias) + "=" + module_path (target)
                let mut def_cursor = child.walk();
                for def_child in child.children(&mut def_cursor) {
                    if def_child.kind() == "module_binding" {
                        let mut alias_name: Option<String> = None;
                        let mut target_module: Option<String> = None;

                        let mut bind_cursor = def_child.walk();
                        for bind_child in def_child.children(&mut bind_cursor) {
                            match bind_child.kind() {
                                "module_name" if alias_name.is_none() => {
                                    alias_name = Some(get_node_text(&bind_child, source));
                                }
                                "module_path" => {
                                    target_module =
                                        Some(extract_ocaml_module_path_text(&bind_child, source));
                                }
                                _ => {}
                            }
                        }

                        if let Some(target) = target_module {
                            imports.push(ImportInfo {
                                module: target,
                                names: Vec::new(),
                                is_from: Some(false),
                                alias: alias_name,
                                line: stmt_line,
                            });
                        }
                    }
                }
                // Recurse into module_definition body to find nested open/include statements
                // (e.g., module M = struct open List end)
                extract_ocaml_imports_recursive(&child, source, imports);
            }
            "include_module" => {
                // Structure: include_module -> "include" + module_path -> module_name
                if let Some(module) = extract_ocaml_module_path(&child, source) {
                    imports.push(ImportInfo {
                        module,
                        names: vec!["*".to_string()],
                        is_from: Some(true),
                        alias: None,
                        line: stmt_line,
                    });
                }
            }
            // RC15 (v0.5.0 R3): harvest IMPLICIT qualified value/constructor/
            // type/field references (e.g. `Dune_lang.parse x`) that carry a
            // leading `module_path` qualifier but are NOT introduced by an
            // explicit `open`/`include`/`module =` directive. Without this the
            // dependency graph only saw explicit import directives, so a file
            // that uses `Dune_lang.X` 200 times but never `open`s it minted
            // zero inbound edges (afferent coupling `ca=0`, `instability=1.0`).
            //
            // Per tree-sitter-ocaml `value_path = path(module_path, value_name)`
            // (and the structurally identical `constructor_path` /
            // `type_constructor_path` / `field_path`): the qualifier is
            // `named_child(0)` iff its kind is `module_path`; a bare/local ref
            // has no `module_path` child and is therefore NOT harvested. The
            // emitted module is the full dotted qualifier; downstream
            // `resolve_ocaml_import` (stdlib-gated, index-backed) maps it to a
            // project file or drops it (stdlib/external).
            "value_path" | "constructor_path" | "type_constructor_path" | "field_path" => {
                if let Some(qualifier) = extract_ocaml_path_qualifier(&child, source) {
                    let names = extract_ocaml_path_leaf(&child, source)
                        .map(|leaf| vec![leaf])
                        .unwrap_or_default();
                    imports.push(ImportInfo {
                        module: qualifier,
                        names,
                        is_from: Some(false),
                        alias: None,
                        line: stmt_line,
                    });
                }
                // Path nodes contain only the qualifier + leaf — no further
                // references to harvest, so we do not recurse.
            }
            _ => {
                // Recurse into other nodes
                extract_ocaml_imports_recursive(&child, source, imports);
            }
        }
    }
}

/// Harvest the module qualifier of an OCaml path node (`value_path`,
/// `constructor_path`, `type_constructor_path`, `field_path`).
///
/// These nodes carry an OPTIONAL leading `module_path` named child (the
/// qualifier) followed by the trailing leaf name. Per tree-sitter-ocaml's
/// grammar `value_path = path(module_path, value_name)` the qualifier is
/// `named_child(0)` iff its kind is `module_path`; a bare/local reference has
/// no `module_path` child. Returns the full dotted qualifier (e.g.
/// `"Dune_lang.Blang"` for `Dune_lang.Blang.value`) or `None` when unqualified.
fn extract_ocaml_path_qualifier(path_node: &Node, source: &str) -> Option<String> {
    let first = path_node.named_child(0)?;
    if first.kind() != "module_path" {
        return None;
    }
    Some(extract_ocaml_module_path_text(&first, source))
}

/// Extract the trailing leaf name of an OCaml path node (the last named child
/// that is not the leading `module_path` qualifier).
fn extract_ocaml_path_leaf(path_node: &Node, source: &str) -> Option<String> {
    let mut leaf = None;
    let mut cursor = path_node.walk();
    for ch in path_node.named_children(&mut cursor) {
        if ch.kind() != "module_path" {
            leaf = Some(get_node_text(&ch, source));
        }
    }
    leaf
}

/// Extract module path from an OCaml node that contains a module_path child.
/// Returns the dot-separated module path (e.g., "Stdlib.Map").
fn extract_ocaml_module_path(node: &Node, source: &str) -> Option<String> {
    let mut node_cursor = node.walk();
    for child in node.children(&mut node_cursor) {
        if child.kind() == "module_path" {
            return Some(extract_ocaml_module_path_text(&child, source));
        }
    }
    None
}

/// Extract text from a module_path node, joining nested module_name children with dots.
fn extract_ocaml_module_path_text(node: &Node, source: &str) -> String {
    let mut parts = Vec::new();
    let mut path_cursor = node.walk();
    for child in node.children(&mut path_cursor) {
        if child.kind() == "module_name" {
            parts.push(get_node_text(&child, source));
        } else if child.kind() == "module_path" {
            // Nested module_path for dotted names
            parts.push(extract_ocaml_module_path_text(&child, source));
        }
    }
    if parts.is_empty() {
        // Fallback: use the entire node text
        get_node_text(node, source)
    } else {
        parts.join(".")
    }
}

// =============================================================================
// Lua imports (require calls)
// =============================================================================

/// Extract Lua imports from `require()` calls.
///
/// Lua patterns:
/// - `local socket = require("socket")`     -- standard with parentheses
/// - `local dict = require"socket.dict"`    -- no parentheses, direct string
/// - `local mime = require "mime"`          -- space before string
/// - `require("module")`                    -- bare require without local
fn extract_lua_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_lua_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_lua_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        // Look for function_call nodes where the function is "require"
        if child.kind() == "function_call" {
            if let Some(mut import) = extract_lua_require(&child, source) {
                import.line = node_line(&child);
                imports.push(import);
                continue;
            }
        }

        // Also check variable_declaration / assignment_statement that may contain require
        // The require call could be nested inside these
        extract_lua_imports_recursive(&child, source, imports);
    }
}

/// Extract a single require() import from a Lua function_call node.
fn extract_lua_require(node: &Node, source: &str) -> Option<ImportInfo> {
    // Structure varies by tree-sitter-lua grammar:
    // function_call -> name: identifier("require") + arguments: (string | arguments(string))
    // OR
    // function_call -> prefix: identifier("require") + arguments(string)

    let mut is_require = false;
    let mut module_name = String::new();

    let mut call_cursor = node.walk();
    for child in node.children(&mut call_cursor) {
        match child.kind() {
            // The function name (could be in "name" field or as first identifier child)
            "identifier" => {
                let text = get_node_text(&child, source);
                if text == "require" {
                    is_require = true;
                }
            }
            // Arguments with parentheses: require("socket"), require(script.Parent.X), ...
            "arguments" => {
                if is_require {
                    module_name = extract_string_from_arguments(&child, source);
                }
            }
            // Direct string argument without parens: require"socket.dict" or require "mime"
            "string" => {
                if is_require {
                    module_name = get_string_content(&child, source);
                }
            }
            _ => {}
        }
    }

    if is_require && !module_name.is_empty() {
        Some(ImportInfo {
            module: module_name,
            names: Vec::new(),
            is_from: None,
            alias: None,
                    line: 0,
        })
    } else {
        None
    }
}

/// Extract the require() module name from a Lua/Luau `arguments` node.
///
/// v0.5.0 AUDIT-FIX (W2-lua-require): historically this only accepted a
/// `string` child, so every non-string-literal `require(...)` argument was
/// silently dropped — which meant the dominant Roblox / Luau DataModel idioms
/// (`require(script.Parent.Foo)`, `require(game.X.Y)`,
/// `require(script:WaitForChild("Config"))`, `require(script["Bar"])`)
/// produced ZERO imports (and therefore zero internal `deps` edges).
///
/// We now reconstruct a module path from the first argument expression,
/// AST-driven (mirroring `extract_lua_lhs_name` / `lua_bracket_index_name` in
/// `extract.rs`) rather than slicing source text, so nested chains and
/// whitespace are handled correctly. `string` literals keep their fast path.
fn extract_string_from_arguments(node: &Node, source: &str) -> String {
    let mut arg_cursor = node.walk();
    for child in node.children(&mut arg_cursor) {
        // Only consider real argument expressions, skip the `(` / `,` / `)`
        // anonymous tokens.
        if !child.is_named() {
            continue;
        }
        let path = lua_require_module_path(&child, source);
        if !path.is_empty() {
            return path;
        }
        // First named argument decided the outcome (require takes one module
        // argument); stop so a trailing arg can't override it.
        return String::new();
    }
    String::new()
}

/// Reconstruct a module path string from a single Lua/Luau `require()`
/// argument expression, AST-driven.
///
/// Accepted shapes (node kinds verified against tree-sitter-lua 0.2.0 and
/// tree-sitter-luau 1.2.0 `node-types.json`):
/// - `string`                       -> the literal contents (`"mod.a"` -> `mod.a`)
/// - `dot_index_expression`         -> `script.Parent.Foo` (recurse on `table`,
///                                     join with `.field`)
/// - `bracket_index_expression`     -> `script.Bar` (string subscript) or
///                                     `table[<expr>]` when the subscript is not
///                                     a plain string literal
/// - `function_call` whose callee is a `method_index_expression` with method
///   `WaitForChild` / `FindFirstChild` -> the string-literal argument
///   (`require(script:WaitForChild("Config"))` -> `Config`)
/// - `identifier`                   -> the variable name (`require(modVar)`),
///   the best resolvable token we have for a dynamic require
///
/// Returns an empty string for shapes we cannot resolve (e.g. `require()` with
/// no argument), so the caller drops the import rather than emitting a bogus
/// empty module — matching the established "only emit resolvable shapes"
/// policy (cf. `parse_cjs_require`).
fn lua_require_module_path(node: &Node, source: &str) -> String {
    match node.kind() {
        "string" => get_string_content(node, source),
        "identifier" => get_node_text(node, source),
        "dot_index_expression" => lua_dot_index_path(node, source),
        "bracket_index_expression" => lua_bracket_index_path(node, source),
        // `script:WaitForChild("Config")` / `:FindFirstChild("X")` — the module
        // name is the string argument to the lookup method.
        "function_call" => lua_require_method_call_path(node, source),
        // `(expr)` — unwrap and recurse on the inner expression.
        "parenthesized_expression" => node
            .named_child(0)
            .map(|inner| lua_require_module_path(&inner, source))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Build a dotted path from a `dot_index_expression` (`a.b.c`).
///
/// The node exposes `table` (the receiver, possibly another
/// `dot_index_expression`) and `field` (an `identifier`). We recurse on the
/// receiver so arbitrarily deep chains like `script.Parent.Parent.Util` are
/// reconstructed segment-by-segment from the AST.
fn lua_dot_index_path(node: &Node, source: &str) -> String {
    let field = match node.child_by_field_name("field") {
        Some(f) => get_node_text(&f, source),
        None => return String::new(),
    };
    match node.child_by_field_name("table") {
        Some(table) => {
            let base = lua_require_path_segment(&table, source);
            if base.is_empty() {
                field
            } else {
                format!("{base}.{field}")
            }
        }
        None => field,
    }
}

/// Build a path from a `bracket_index_expression` (`t["k"]` / `t[expr]`).
///
/// When the subscript is a string literal we treat it like a dotted segment
/// (`script["Bar"]` -> `script.Bar`) so it joins naturally with surrounding
/// dot chains; otherwise we preserve the bracket form (`t[expr]`) built from
/// the AST `table`/`field` fields.
fn lua_bracket_index_path(node: &Node, source: &str) -> String {
    let table = node.child_by_field_name("table");
    let field = node.child_by_field_name("field");
    let (table, field) = match (table, field) {
        (Some(t), Some(f)) => (t, f),
        _ => return String::new(),
    };
    let base = lua_require_path_segment(&table, source);

    if field.kind() == "string" {
        let key = get_string_content(&field, source);
        if base.is_empty() {
            return key;
        }
        return format!("{base}.{key}");
    }

    // Non-string subscript: keep an explicit bracket form so the edge is still
    // uniquely identifiable.
    let field_text = get_node_text(&field, source);
    if base.is_empty() {
        field_text
    } else {
        format!("{base}[{field_text}]")
    }
}

/// Reconstruct a path segment for the `table`/receiver side of an index
/// expression. Receivers are themselves index expressions or identifiers
/// (the `variable` supertype flattens to these concrete kinds in real trees).
fn lua_require_path_segment(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => get_node_text(node, source),
        "dot_index_expression" => lua_dot_index_path(node, source),
        "bracket_index_expression" => lua_bracket_index_path(node, source),
        "parenthesized_expression" => node
            .named_child(0)
            .map(|inner| lua_require_path_segment(&inner, source))
            .unwrap_or_default(),
        // `script:GetService(...)` style receivers are unusual inside a require
        // path; fall back to the raw text so we still produce a stable segment.
        _ => get_node_text(node, source),
    }
}

/// Handle `require(script:WaitForChild("Config"))` and
/// `require(script:FindFirstChild("X"))`.
///
/// The argument is a `function_call` whose `name` is a
/// `method_index_expression` (`table` = receiver, `method` = the lookup
/// method). The module name is the string-literal argument to that lookup, so
/// we pull it from the call's `arguments`. Only the recognised DataModel
/// lookup methods are treated this way; any other call shape returns empty so
/// we don't fabricate a module name from an arbitrary function call.
fn lua_require_method_call_path(node: &Node, source: &str) -> String {
    let name = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return String::new(),
    };
    if name.kind() != "method_index_expression" {
        return String::new();
    }
    let method = match name.child_by_field_name("method") {
        Some(m) => get_node_text(&m, source),
        None => return String::new(),
    };
    if method != "WaitForChild" && method != "FindFirstChild" {
        return String::new();
    }
    // The looked-up child name is the string-literal argument.
    if let Some(args) = node.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for arg in args.children(&mut cursor) {
            if arg.kind() == "string" {
                return get_string_content(&arg, source);
            }
        }
    }
    String::new()
}

// =============================================================================
// PHP imports (use statements, require/include)
// =============================================================================

fn extract_php_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_php_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_php_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let stmt_line = node_line(&child);
        match child.kind() {
            // PHP use statements: use App\Models\User;
            "namespace_use_declaration" => {
                extract_php_use_declaration(&child, source, imports, stmt_line);
            }
            // PHP require/include expressions
            "expression_statement" => {
                // Check if this contains a require/include
                let mut expr_cursor = child.walk();
                for expr_child in child.children(&mut expr_cursor) {
                    match expr_child.kind() {
                        "require_expression"
                        | "require_once_expression"
                        | "include_expression"
                        | "include_once_expression" => {
                            if let Some(mut import_info) =
                                extract_php_require_include(&expr_child, source)
                            {
                                import_info.line = stmt_line;
                                imports.push(import_info);
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Direct require/include at statement level
            "require_expression"
            | "require_once_expression"
            | "include_expression"
            | "include_once_expression" => {
                if let Some(mut import_info) = extract_php_require_include(&child, source) {
                    import_info.line = stmt_line;
                    imports.push(import_info);
                }
            }
            _ => {
                // Recurse into other nodes
                extract_php_imports_recursive(&child, source, imports);
            }
        }
    }
}

/// Extract PHP use declarations
/// Handles:
/// - Simple: use App\Models\User;
/// - Grouped: use App\Models\{User, Post};
/// - Aliased: use App\Models\User as UserModel;
/// - Function use: use function App\helper;
/// - Const use: use const App\CONSTANT;
fn extract_php_use_declaration(
    node: &Node,
    source: &str,
    imports: &mut Vec<ImportInfo>,
    stmt_line: u32,
) {
    let mut use_cursor = node.walk();

    // Check if this is a grouped import by looking for namespace_use_group
    let has_group = node
        .children(&mut use_cursor)
        .any(|c| c.kind() == "namespace_use_group");

    if has_group {
        // Grouped imports: use App\Models\{User, Post};
        let mut prefix = String::new();
        let mut group_cursor = node.walk();

        for use_child in node.children(&mut group_cursor) {
            match use_child.kind() {
                "namespace_name" | "qualified_name" | "name" => {
                    // This is the base namespace prefix
                    prefix = get_node_text(&use_child, source);
                }
                "namespace_use_group" => {
                    // Parse each clause in the group
                    let mut group_items_cursor = use_child.walk();
                    for group_item in use_child.children(&mut group_items_cursor) {
                        if group_item.kind() == "namespace_use_clause" {
                            let clause_text = get_node_text(&group_item, source).trim().to_string();

                            // Handle alias: User as UserModel
                            let (name, alias) = parse_php_use_alias(&clause_text);

                            let full_module = if prefix.is_empty() {
                                name
                            } else {
                                format!("{}\\{}", prefix, name)
                            };

                            imports.push(ImportInfo {
                                module: full_module,
                                names: Vec::new(),
                                is_from: Some(true), // use is similar to "from X import Y"
                                alias,
                                line: stmt_line,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    } else {
        // Simple or aliased imports
        let mut simple_cursor = node.walk();
        for use_child in node.children(&mut simple_cursor) {
            if use_child.kind() == "namespace_use_clause" {
                let clause_text = get_node_text(&use_child, source).trim().to_string();

                // Handle alias: App\Models\User as UserModel
                let (module, alias) = parse_php_use_alias(&clause_text);

                imports.push(ImportInfo {
                    module,
                    names: Vec::new(),
                    is_from: Some(true),
                    alias,
                    line: stmt_line,
                });
            }
        }
    }
}

/// Parse PHP use clause for potential alias
/// Returns (module, Option<alias>)
fn parse_php_use_alias(clause: &str) -> (String, Option<String>) {
    // Check for " as " (case insensitive)
    let lower = clause.to_lowercase();
    if let Some(as_pos) = lower.find(" as ") {
        let module = clause[..as_pos].trim().to_string();
        let alias = clause[as_pos + 4..].trim().to_string();
        (module, Some(alias))
    } else {
        (clause.to_string(), None)
    }
}

/// Extract PHP require/include expressions
/// Handles:
/// - require 'config.php';
/// - require_once __DIR__ . '/file.php';
/// - include 'another.php';
fn extract_php_require_include(node: &Node, source: &str) -> Option<ImportInfo> {
    let node_type = node.kind();

    // Determine import type based on node kind
    let is_require = node_type.starts_with("require");
    let is_once = node_type.contains("_once");

    // Find the path argument
    let mut module = String::new();
    let mut arg_cursor = node.walk();

    for child in node.children(&mut arg_cursor) {
        match child.kind() {
            // String literal: 'file.php' or "file.php"
            "string" | "encapsed_string" => {
                let text = get_node_text(&child, source);
                // Strip quotes
                module = text.trim_matches(|c| c == '"' || c == '\'').to_string();
                break;
            }
            // Binary expression: __DIR__ . '/file.php'
            "binary_expression" => {
                // For complex expressions, capture the whole expression
                module = get_node_text(&child, source);
                break;
            }
            // Parenthesized expression: require('file.php')
            "parenthesized_expression" => {
                // Look inside for string
                let mut paren_cursor = child.walk();
                for paren_child in child.children(&mut paren_cursor) {
                    if paren_child.kind() == "string" || paren_child.kind() == "encapsed_string" {
                        let text = get_node_text(&paren_child, source);
                        module = text.trim_matches(|c| c == '"' || c == '\'').to_string();
                        break;
                    }
                }
                if module.is_empty() {
                    // Fallback to whole expression
                    module = get_node_text(&child, source);
                }
                break;
            }
            _ => {}
        }
    }

    if module.is_empty() {
        // Last resort: extract from the whole node text
        let full_text = get_node_text(node, source);
        // Try to extract path from require 'path' or require('path')
        for pattern in ["require_once", "require", "include_once", "include"] {
            if let Some(pos) = full_text.find(pattern) {
                let rest = full_text[pos + pattern.len()..].trim();
                // Remove parentheses and quotes
                let cleaned = rest
                    .trim_start_matches(['(', ' '])
                    .trim_end_matches([')', ';', ' '])
                    .trim_matches(['"', '\'']);
                if !cleaned.is_empty() {
                    module = cleaned.to_string();
                    break;
                }
            }
        }
    }

    if module.is_empty() {
        return None;
    }

    Some(ImportInfo {
        module,
        names: Vec::new(),
        // Use is_from to distinguish require vs include
        // is_from = true for require (must exist), false for include (optional)
        is_from: Some(is_require),
        // Use alias to track _once variants - store "once" if applicable
        alias: if is_once {
            Some("once".to_string())
        } else {
            None
        },
                    line: 0,
    })
}

// =============================================================================
// Helper functions
// =============================================================================

/// Get text content of a node
fn get_node_text(node: &Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

/// 1-indexed line of the node's start position.
///
/// importers-ast-anchored-v1 (v0.4.2 M-035): used by every per-language
/// import extractor to populate `ImportInfo.line` from the AST so the
/// `importers` command can emit a precise line number instead of
/// falling back to a text-substring scan.
fn node_line(node: &Node) -> u32 {
    node.start_position().row as u32 + 1
}

/// Get string content (strips quotes)
fn get_string_content(node: &Node, source: &str) -> String {
    let text = get_node_text(node, source);
    text.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .to_string()
}

/// Parse a CommonJS `require('module')` call expression as an `ImportInfo`.
///
/// high-bundle-progress-determinism-coverage-v1 (N5): tree-sitter sees a
/// CJS require as `call_expression(function: identifier "require",
/// arguments: arguments(string))`. We accept a single string-literal
/// argument (or template_string with no substitutions) and reject any
/// other shape — a dynamic `require(somevar)` is unresolvable as an
/// import edge, so emitting it would be misleading.
///
/// Returns `None` if the call is not a require, or if the argument is
/// not a literal string we can extract.
fn parse_cjs_require(node: &Node, source: &str) -> Option<ImportInfo> {
    // Must be a call_expression whose function is the bare identifier "require".
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    if get_node_text(&function, source) != "require" {
        return None;
    }

    let args = node.child_by_field_name("arguments")?;
    if args.kind() != "arguments" {
        return None;
    }

    // First non-punctuation child of `arguments` must be a string-like literal.
    let mut arg_cursor = args.walk();
    let module = args
        .children(&mut arg_cursor)
        .find(|c| matches!(c.kind(), "string" | "template_string"))
        .map(|c| {
            // Reject template strings with substitutions — those resolve
            // dynamically and we can't emit a stable module name for them.
            if c.kind() == "template_string" {
                let mut tcursor = c.walk();
                let has_substitution = c
                    .children(&mut tcursor)
                    .any(|cc| cc.kind() == "template_substitution");
                if has_substitution {
                    return None;
                }
            }
            Some(get_string_content(&c, source))
        })
        .flatten()?;

    if module.is_empty() {
        return None;
    }

    Some(ImportInfo {
        module,
        names: Vec::new(),
        is_from: Some(true),
        alias: None,
                    line: 0,
    })
}

// =============================================================================
// Swift imports
// =============================================================================
//
// cross-language-extraction-v2 P2.BUG-2: Swift `import_declaration` recognition.
//
// tree-sitter-swift emits `import_declaration` nodes for every `import` line.
// The grammar exposes the imported module / submodule path either as child
// `identifier` nodes or as `dot_expression` nodes (for compound paths like
// `UIKit.UIView`). Swift also supports submodule kind specifiers such as
// `import struct Foo.Bar`, `import class A.B`, etc.; we parse via the raw
// text of the node which keeps us robust across grammar versions and avoids
// brittle field-name lookups that vary between tree-sitter-swift releases.
//
// Examples:
//   `import Foundation`              -> module="Foundation"
//   `import UIKit.UIView`            -> module="UIKit.UIView"
//   `import struct PackageDescription` -> module="PackageDescription"
//   `@testable import MyModule`      -> module="MyModule"

fn extract_swift_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_swift_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_swift_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "import_declaration" {
            if let Some(mut info) = parse_swift_import_text(&get_node_text(&child, source)) {
                info.line = node_line(&child);
                imports.push(info);
            }
        } else {
            extract_swift_imports_recursive(&child, source, imports);
        }
    }
}

/// Parse the raw text of a Swift `import_declaration` node into an
/// `ImportInfo`. Returns `None` if the text does not contain a recognisable
/// module path. Handles attributes (`@testable`), submodule kind specifiers
/// (`import struct Foo.Bar`), and compound module paths (`UIKit.UIView`).
fn parse_swift_import_text(raw: &str) -> Option<ImportInfo> {
    // Submodule kind keywords that may follow the `import` keyword. The next
    // token after one of these is the module path.
    const KIND_KEYWORDS: &[&str] = &[
        "struct", "class", "enum", "protocol", "typealias", "func", "var", "let",
    ];

    // Strip a leading attribute like `@testable`, `@_implementationOnly`, etc.
    let trimmed = raw.trim();
    let after_attr = if let Some(rest) = trimmed.strip_prefix('@') {
        // Skip until whitespace.
        rest.split_whitespace().skip(1).collect::<Vec<_>>().join(" ")
    } else {
        trimmed.to_string()
    };

    // Tokenise on whitespace, find the `import` keyword, then take the next
    // non-kind token as the module path.
    let mut tokens = after_attr.split_whitespace();
    // Find `import`.
    loop {
        match tokens.next() {
            Some("import") => break,
            Some(_) => continue,
            None => return None,
        }
    }
    // Skip optional kind keyword.
    let module_token = match tokens.next() {
        Some(t) if KIND_KEYWORDS.contains(&t) => tokens.next()?,
        Some(t) => t,
        None => return None,
    };

    // Trim a possible trailing semicolon (rare in Swift but tolerated).
    let module = module_token.trim_end_matches(';').trim().to_string();
    if module.is_empty() {
        return None;
    }
    Some(ImportInfo {
        module,
        names: Vec::new(),
        is_from: None,
        alias: None,
                    line: 0,
    })
}

// =============================================================================
// Solidity imports
// =============================================================================
//
// solidity-deps-v1 (v0.5.0 SOL-007): Solidity `import_directive`
// recognition. tree-sitter-solidity 1.2.13 exposes the AST shape:
//
//   import_directive
//     ├─ "import"                  (keyword)
//     ├─ source: string            (path literal, REQUIRED)
//     │    └─ "<path>"             (one leaf `string` token, quoted)
//     ├─ alias?: identifier        (whole-file `as <X>` form)
//     └─ import_name?: identifier  (selective `{ A, B }` names; repeated)
//
// Solidity has 5 import forms, all mapped to one `import_directive`:
//   1. `import "./Foo.sol";`
//   2. `import "./Foo.sol" as Foo;`
//   3. `import * as Foo from "./Foo.sol";`
//   4. `import { A, B } from "./Foo.sol";`
//   5. `import { A as Alias, B } from "./Foo.sol";`
//
// We surface:
//   * `module` -> the unquoted source path (used by the deps classifier
//     for Internal vs External routing).
//   * `alias`  -> the whole-file alias if present (forms 2 and 3).
//   * `names`  -> the selective name list (form 4 and 5). Renames in
//     form 5 are surfaced as `Original as Alias` to preserve the
//     original-name link required by `importers` / surface graph.
//   * `is_from` -> `None`; Solidity has no static-vs-dynamic distinction
//     that maps onto this field.
//   * `line`   -> 1-indexed line of the `import_directive`.

fn extract_solidity_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_solidity_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_solidity_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "import_directive" {
            if let Some(info) = parse_solidity_import_directive(&child, source) {
                imports.push(info);
            }
        } else {
            extract_solidity_imports_recursive(&child, source, imports);
        }
    }
}

/// Parse a single `import_directive` node into an `ImportInfo`.
///
/// Uses the grammar field names where possible (`source`) and falls
/// back to a child-walk for repeated fields (`alias`, `import_name`)
/// that tree-sitter exposes as `child_by_field_name` returning only
/// the first match. For renames inside a selective import
/// (`{ Original as Alias }`), the grammar emits paired
/// `import_name` + `alias` children in source order — we walk them
/// pairwise and emit `Original as Alias` so the `as`-link survives
/// into downstream `names` consumers.
fn parse_solidity_import_directive(node: &Node, source: &str) -> Option<ImportInfo> {
    // Extract the source path (REQUIRED per grammar). The `source`
    // field points at a `string` node whose text includes the quotes.
    let source_node = node.child_by_field_name("source")?;
    let module = get_string_content(&source_node, source);
    if module.is_empty() {
        return None;
    }

    // Collect import_name + alias children in source order so we can
    // pair them up for the selective `{ A as Alias }` form.
    let mut import_names: Vec<(usize, String)> = Vec::new(); // (byte_offset, text)
    let mut aliases: Vec<(usize, String)> = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                // tree-sitter-solidity 1.2.13 surfaces both `alias` and
                // `import_name` children as bare `identifier` nodes.
                // Disambiguate by checking which field the node belongs
                // to (parent's field name).
                //
                // The simplest robust check: re-query the parent via
                // child_by_field_name on each field and compare
                // identity. We instead use the byte range pairing
                // below.
                let text = get_node_text(&child, source);
                let off = child.start_byte();
                // Heuristic — we'll classify after the loop using
                // the parent field name iteration.
                // For now, push to both lists with a marker; resolve
                // after the loop.
                let _ = (text, off);
            }
            _ => {}
        }
    }

    // Resolve `alias` field children — tree-sitter exposes this as
    // a `multiple: true` field, so we iterate child indices and
    // match by field name using `field_name_for_child`.
    let mut walk = node.walk();
    let mut idx = 0u32;
    for child in node.children(&mut walk) {
        if let Some(field_name) = node.field_name_for_child(idx) {
            match field_name {
                "alias" => {
                    aliases.push((child.start_byte(), get_node_text(&child, source)));
                }
                "import_name" => {
                    import_names.push((child.start_byte(), get_node_text(&child, source)));
                }
                _ => {}
            }
        }
        idx += 1;
    }

    // Sort by byte offset so we preserve source order.
    import_names.sort_by_key(|(off, _)| *off);
    aliases.sort_by_key(|(off, _)| *off);

    let line = node_line(node);

    // Form 4 / 5: selective import — at least one `import_name`.
    if !import_names.is_empty() {
        // Pair each import_name with the alias whose byte offset
        // immediately follows it (and precedes the next import_name).
        // If `aliases.len() == import_names.len()`, that's form 5 with
        // every name renamed; otherwise renames are partial.
        let mut names: Vec<String> = Vec::new();
        for (i, (name_off, name)) in import_names.iter().enumerate() {
            let next_name_off = import_names
                .get(i + 1)
                .map(|(off, _)| *off)
                .unwrap_or(usize::MAX);
            let alias = aliases
                .iter()
                .find(|(off, _)| *off > *name_off && *off < next_name_off)
                .map(|(_, a)| a.clone());
            if let Some(a) = alias {
                names.push(format!("{} as {}", name, a));
            } else {
                names.push(name.clone());
            }
        }
        return Some(ImportInfo {
            module,
            names,
            is_from: None,
            alias: None,
            line,
        });
    }

    // Form 2 / 3: whole-file alias — exactly one `alias` and no
    // `import_name`. (Form 3 `* as Bar from "./X"` parses with the
    // same alias child on tree-sitter-solidity 1.2.13.)
    let alias = aliases.first().map(|(_, a)| a.clone());

    Some(ImportInfo {
        module,
        names: Vec::new(),
        is_from: None,
        alias,
        line,
    })
}

// =============================================================================
// Kotlin imports
// =============================================================================
//
// cross-language-extraction-v2 P2.BUG-2: Kotlin `import` recognition.
//
// `tree-sitter-kotlin-ng` (used since the workspace migration) emits a single
// `import` node per `import` line — children are the literal `import` keyword,
// a `qualified_identifier`, an optional `.` + `*` for wildcards, and an
// optional `as <identifier>` alias suffix. (Older / vanilla `tree-sitter-kotlin`
// grammars use `import_header` inside an `import_list` — we accept both kinds
// to stay compatible across grammar versions.)
//
// Examples:
//   `import kotlin.collections.List`            — simple
//   `import kotlin.collections.*`                — wildcard
//   `import kotlin.collections.List as MyList`   — aliased
//
// We parse via the raw text rather than walking grammar-specific child
// fields; this is the same strategy `extract_scala_imports` uses for the
// same reason.

fn extract_kotlin_imports(node: &Node, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    extract_kotlin_imports_recursive(node, source, &mut imports);
    imports
}

fn extract_kotlin_imports_recursive(node: &Node, source: &str, imports: &mut Vec<ImportInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Accept both grammar variants:
        //   tree-sitter-kotlin-ng: `import` (top-level statement node)
        //   tree-sitter-kotlin (vanilla): `import_header` inside `import_list`
        if child.kind() == "import_header" || is_kotlin_import_statement(&child) {
            if let Some(mut info) = parse_kotlin_import_text(&get_node_text(&child, source)) {
                info.line = node_line(&child);
                imports.push(info);
            }
        } else {
            extract_kotlin_imports_recursive(&child, source, imports);
        }
    }
}

/// True for an `import` statement node in tree-sitter-kotlin-ng. We must
/// disambiguate against the `import` *keyword* token (also of kind `"import"`)
/// that appears as the first child of the statement node itself: only the
/// statement has children we recognise (`qualified_identifier`).
fn is_kotlin_import_statement(node: &Node) -> bool {
    if node.kind() != "import" {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), "qualified_identifier" | "identifier") {
            return true;
        }
    }
    false
}

fn parse_kotlin_import_text(raw: &str) -> Option<ImportInfo> {
    // Strip leading `import` keyword and optional trailing semicolon/newline.
    let body = raw.trim().strip_prefix("import")?.trim();
    if body.is_empty() {
        return None;
    }

    // Split off optional `as <alias>` clause.
    let (path_part, alias_part) = if let Some(idx) = find_kotlin_as_split(body) {
        let (left, right) = body.split_at(idx);
        // right starts with " as <alias>"
        let alias = right.trim_start();
        let alias = alias.strip_prefix("as").unwrap_or(alias).trim();
        (left.trim(), Some(alias.trim_end_matches(';').to_string()))
    } else {
        (body.trim_end_matches(';').trim(), None)
    };

    if path_part.is_empty() {
        return None;
    }

    Some(ImportInfo {
        module: path_part.to_string(),
        names: Vec::new(),
        // Treat wildcard imports as "from"-style (matches the convention used
        // for Java `static`/wildcard and Scala `_` selectors).
        is_from: None,
        alias: alias_part.filter(|s| !s.is_empty()),
                    line: 0,
    })
}

/// Locate the byte index of the standalone ` as ` token inside a Kotlin import
/// path, returning `None` when no alias is present. Whitespace-bounded matching
/// avoids false positives like `kotlin.assert.something`.
fn find_kotlin_as_split(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i].is_ascii_whitespace()
            && bytes[i + 1] == b'a'
            && bytes[i + 2] == b's'
            && (i + 3 == bytes.len() || bytes[i + 3].is_ascii_whitespace())
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    #[test]
    fn test_c_include_system() {
        let source = "#include <stdio.h>";
        let tree = parse(source, Language::C).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::C).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "stdio.h");
        // rc3-external-deps-c-lua-php-v1: `<...>` system header restores
        // is_from = Some(true) (system/toolchain).
        assert_eq!(imports[0].is_from, Some(true));
    }

    #[test]
    fn test_c_include_local() {
        let source = r#"#include "local.h""#;
        let tree = parse(source, Language::C).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::C).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "local.h");
        // rc3-external-deps-c-lua-php-v1: `"..."` local header restores
        // is_from = Some(false) (local/project).
        assert_eq!(imports[0].is_from, Some(false));
    }

    #[test]
    fn test_c_include_macro_is_dropped() {
        // rc3-external-deps-c-lua-php-v1: `#include MACRO` and
        // `#include MACRO(args)` parse to `path: (identifier)` /
        // `(call_expression)` — macro indirections whose target is unknowable
        // without preprocessing. They must NOT leak in as fabricated deps.
        let source = r#"
#include <stdio.h>
#include MALLOC_INCLUDE
#include MACRO(arg1, arg2)
#include "local.h"
"#;
        let tree = parse(source, Language::C).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::C).unwrap();

        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"stdio.h"));
        assert!(modules.contains(&"local.h"));
        assert!(!modules.contains(&"MALLOC_INCLUDE"));
        // The macro forms contribute no ImportInfo entries.
        assert_eq!(imports.len(), 2);
    }

    #[test]
    fn test_c_multiple_includes() {
        let source = r#"
#include <stdio.h>
#include <stdlib.h>
#include "myheader.h"
"#;
        let tree = parse(source, Language::C).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::C).unwrap();

        assert_eq!(imports.len(), 3);
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"stdio.h"));
        assert!(modules.contains(&"stdlib.h"));
        assert!(modules.contains(&"myheader.h"));
    }

    #[test]
    fn test_cpp_includes() {
        let source = r#"
#include <iostream>
#include <string>
#include "local.hpp"
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Cpp).unwrap();

        assert_eq!(imports.len(), 3);
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"iostream"));
        assert!(modules.contains(&"string"));
        assert!(modules.contains(&"local.hpp"));
    }

    #[test]
    fn test_python_import() {
        let source = "import os";
        let tree = parse(source, Language::Python).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Python).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "os");
        assert_eq!(imports[0].is_from, Some(false));
    }

    #[test]
    fn test_python_from_import() {
        let source = "from typing import List, Optional";
        let tree = parse(source, Language::Python).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Python).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "typing");
        assert_eq!(imports[0].is_from, Some(true));
        assert!(imports[0].names.contains(&"List".to_string()));
        assert!(imports[0].names.contains(&"Optional".to_string()));
    }

    #[test]
    fn test_typescript_import() {
        let source = "import { foo, bar } from './module';";
        let tree = parse(source, Language::TypeScript).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::TypeScript).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "./module");
        assert!(imports[0].names.contains(&"foo".to_string()));
    }

    #[test]
    fn test_go_import() {
        let source = r#"
package main

import "fmt"
"#;
        let tree = parse(source, Language::Go).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Go).unwrap();

        assert!(!imports.is_empty());
        assert!(imports.iter().any(|i| i.module == "fmt"));
    }

    #[test]
    fn test_rust_use() {
        let source = "use std::collections::HashMap;";
        let tree = parse(source, Language::Rust).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Rust).unwrap();

        assert_eq!(imports.len(), 1);
        assert!(imports[0].module.contains("std::collections"));
    }

    /// fix-R7 (cluster[11] RC8a): a glob `use path::*` must keep the module
    /// path. Previously the `use_wildcard` arm emitted `(prefix, "*")` and
    /// dropped the `scoped_identifier`/`identifier` child holding the path,
    /// so `use clap_builder::*` reported module="" (an empty, useless edge).
    #[test]
    fn test_rust_use_glob_keeps_module_bare() {
        let source = "use clap_builder::*;";
        let tree = parse(source, Language::Rust).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Rust).unwrap();

        assert_eq!(imports.len(), 1, "one glob import");
        assert_eq!(
            imports[0].module, "clap_builder",
            "glob must keep the module path, not drop it to empty"
        );
        assert!(imports[0].names.contains(&"*".to_string()));
    }

    /// fix-R7 (cluster[11] RC8a): glob over a scoped path
    /// `use self::ParseSizeErrorKind::*` must keep the full scoped module.
    #[test]
    fn test_rust_use_glob_keeps_scoped_module() {
        let source = "use self::ParseSizeErrorKind::*;";
        let tree = parse(source, Language::Rust).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Rust).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(
            imports[0].module, "self::ParseSizeErrorKind",
            "scoped glob must keep the full path"
        );
        assert!(imports[0].names.contains(&"*".to_string()));
    }

    /// fix-R7 (cluster[11] RC8b): an inline module definition
    /// `mod tests { ... }` is NOT an import and must not be emitted as one;
    /// its body MUST be recursed so nested `use` statements are captured.
    /// Previously `mod tests` was reported as import module="tests" and the
    /// body was never descended, so `use super::*` inside it was lost.
    #[test]
    fn test_rust_inline_mod_not_import_and_body_recursed() {
        let source = "\
mod tests {
    use super::*;
    use crate::foo::Bar;
}
";
        let tree = parse(source, Language::Rust).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Rust).unwrap();

        // The `mod tests { ... }` definition is not an import.
        assert!(
            !imports.iter().any(|i| i.module == "tests" && i.names.is_empty()),
            "inline `mod tests {{}}` must not be reported as an import, got {:?}",
            imports
        );
        // Nested uses inside the module body must be captured.
        assert!(
            imports.iter().any(|i| i.module == "super" && i.names.contains(&"*".to_string())),
            "nested `use super::*` inside mod body must be captured, got {:?}",
            imports
        );
        assert!(
            imports.iter().any(|i| i.module == "crate::foo" && i.names.contains(&"Bar".to_string())),
            "nested `use crate::foo::Bar` inside mod body must be captured, got {:?}",
            imports
        );
    }

    /// fix-R7 (cluster[11] RC8b): a bare module declaration `mod foo;`
    /// (no body) IS still surfaced as a module reference (regression guard:
    /// the body-aware fix must not suppress declaration-only `mod`).
    #[test]
    fn test_rust_bare_mod_declaration_still_emitted() {
        let source = "mod foo;\nmod bar;\n";
        let tree = parse(source, Language::Rust).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Rust).unwrap();

        assert!(
            imports.iter().any(|i| i.module == "foo"),
            "bare `mod foo;` should still be emitted, got {:?}",
            imports
        );
        assert!(
            imports.iter().any(|i| i.module == "bar"),
            "bare `mod bar;` should still be emitted, got {:?}",
            imports
        );
    }

    #[test]
    fn test_ruby_require_gem() {
        let source = "require 'json'";
        let tree = parse(source, Language::Ruby).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ruby).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "json");
        // imports-is-from-schema-v1: Ruby omits is_from entirely.
        assert_eq!(imports[0].is_from, None);
    }

    #[test]
    fn test_ruby_require_relative() {
        let source = "require_relative './helper'";
        let tree = parse(source, Language::Ruby).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ruby).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "./helper");
        // imports-is-from-schema-v1: Ruby omits is_from entirely.
        assert_eq!(imports[0].is_from, None);
    }

    #[test]
    fn test_ruby_require_explicit_relative() {
        let source = "require './lib/util'";
        let tree = parse(source, Language::Ruby).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ruby).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "./lib/util");
        // imports-is-from-schema-v1: Ruby omits is_from entirely.
        assert_eq!(imports[0].is_from, None);
    }

    #[test]
    fn test_ruby_multiple_requires() {
        let source = r##"
require 'json'
require 'net/http'
require_relative './local_module'
"##;
        let tree = parse(source, Language::Ruby).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ruby).unwrap();

        assert_eq!(imports.len(), 3);
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"json"));
        assert!(modules.contains(&"net/http"));
        assert!(modules.contains(&"./local_module"));
    }

    // =========================================================================
    // Elixir import tests
    // =========================================================================

    #[test]
    fn test_elixir_import() {
        let source = "import Phoenix.Controller";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Phoenix.Controller");
        assert_eq!(imports[0].is_from, Some(true));
    }

    #[test]
    fn test_elixir_alias_simple() {
        let source = "alias Phoenix.LiveView";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Phoenix.LiveView");
        // Simple alias uses last segment as short name
        assert_eq!(imports[0].alias, Some("LiveView".to_string()));
    }

    #[test]
    fn test_elixir_alias_with_as() {
        let source = "alias Phoenix.LiveView, as: LV";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Phoenix.LiveView");
        assert_eq!(imports[0].alias, Some("LV".to_string()));
    }

    #[test]
    fn test_elixir_multi_alias_expands() {
        // elixir-importers-kind-gate-v1 Part 2 (#52): the brace form
        // `alias Plug.{Conn, Router}` must expand to TWO alias-signed entries,
        // not be silently dropped.
        let source = "alias Plug.{Conn, Router}";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 2, "multi-alias should expand to two entries");
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"Plug.Conn"));
        assert!(modules.contains(&"Plug.Router"));
        for i in &imports {
            assert_eq!(i.is_from, Some(false), "alias signature: is_from=false");
            assert!(i.alias.is_some(), "alias signature: alias=Some(_)");
            assert!(i.names.is_empty(), "alias signature: names empty");
        }
        // Each member takes its own last segment as the short name.
        let conn = imports.iter().find(|i| i.module == "Plug.Conn").unwrap();
        assert_eq!(conn.alias.as_deref(), Some("Conn"));
    }

    #[test]
    fn test_elixir_require() {
        let source = "require Logger";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Logger");
    }

    #[test]
    fn test_elixir_use() {
        let source = "use GenServer";
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "GenServer");
        assert_eq!(imports[0].is_from, Some(true));
    }

    #[test]
    fn test_elixir_multiple_imports() {
        let source = r#"import Phoenix.Controller
alias Phoenix.LiveView, as: LV
require Logger
use GenServer
"#;
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(imports.len(), 4);
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"Phoenix.Controller"));
        assert!(modules.contains(&"Phoenix.LiveView"));
        assert!(modules.contains(&"Logger"));
        assert!(modules.contains(&"GenServer"));
    }

    #[test]
    fn test_elixir_imports_inside_defmodule() {
        let source = r#"defmodule MyApp.Router do
  alias Phoenix.Socket
  import Plug.Conn
  use Phoenix.Router
  require Logger
end"#;
        let tree = parse(source, Language::Elixir).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Elixir).unwrap();

        assert_eq!(
            imports.len(),
            4,
            "Should find all 4 imports inside defmodule"
        );
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(
            modules.contains(&"Phoenix.Socket"),
            "Should find alias Phoenix.Socket"
        );
        assert!(
            modules.contains(&"Plug.Conn"),
            "Should find import Plug.Conn"
        );
        assert!(
            modules.contains(&"Phoenix.Router"),
            "Should find use Phoenix.Router"
        );
        assert!(modules.contains(&"Logger"), "Should find require Logger");
    }

    // =========================================================================
    // OCaml import tests
    // =========================================================================

    #[test]
    fn test_ocaml_open() {
        let source = "open List";
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "List");
        assert_eq!(imports[0].is_from, Some(true));
    }

    #[test]
    fn test_ocaml_module_alias() {
        let source = "module M = Hashtbl";
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Hashtbl");
        assert_eq!(imports[0].alias, Some("M".to_string()));
    }

    #[test]
    fn test_ocaml_include() {
        let source = "include Set";
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Set");
        assert_eq!(imports[0].is_from, Some(true), "include should have is_from=Some(true)");
    }

    #[test]
    fn test_ocaml_multiple_imports() {
        let source = r#"open List
module M = Hashtbl
include Set
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(imports.len(), 3);
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"List"));
        assert!(modules.contains(&"Hashtbl"));
        assert!(modules.contains(&"Set"));
    }

    #[test]
    fn test_ocaml_nested_module() {
        let source = "open Stdlib.Map";
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "Stdlib.Map");
    }

    #[test]
    fn test_ocaml_open_inside_module() {
        let source = r#"module M = struct
  open List
  open Hashtbl
end"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Ocaml).unwrap();

        assert_eq!(
            imports.len(),
            2,
            "Should find 2 open statements inside module struct"
        );
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"List"), "Should find open List");
        assert!(modules.contains(&"Hashtbl"), "Should find open Hashtbl");
    }

    // =========================================================================
    // PHP import tests
    // =========================================================================

    #[test]
    fn test_php_use_simple() {
        let source = "<?php\nuse App\\Models\\User;";
        let tree = parse(source, Language::Php).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Php).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "App\\Models\\User");
    }

    #[test]
    fn test_php_use_alias() {
        let source = "<?php\nuse App\\Models\\User as UserModel;";
        let tree = parse(source, Language::Php).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Php).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "App\\Models\\User");
        assert_eq!(imports[0].alias, Some("UserModel".to_string()));
    }

    #[test]
    fn test_php_require() {
        let source = "<?php\nrequire 'config.php';";
        let tree = parse(source, Language::Php).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Php).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "config.php");
        assert_eq!(imports[0].is_from, Some(true), "require should have is_from=Some(true)");
    }

    #[test]
    fn test_php_require_once() {
        let source = "<?php\nrequire_once 'autoload.php';";
        let tree = parse(source, Language::Php).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Php).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module, "autoload.php");
        assert_eq!(
            imports[0].alias,
            Some("once".to_string()),
            "require_once should have alias='once'"
        );
    }

    #[test]
    fn test_php_multiple_imports() {
        let source = r#"<?php
use App\Models\User;
use App\Models\Post as BlogPost;
require_once 'vendor/autoload.php';
"#;
        let tree = parse(source, Language::Php).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Php).unwrap();

        assert!(
            imports.len() >= 3,
            "Expected at least 3 imports, got {}",
            imports.len()
        );
    }

    // =========================================================================
    // Lua imports
    // =========================================================================

    /// Test: Lua standard require with parentheses
    /// `local socket = require("socket")`
    #[test]
    fn test_lua_require_standard() {
        let source = r#"local socket = require("socket")"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "socket");
    }

    /// Test: Lua require without parentheses
    /// `local dict = require"socket.dict"`
    #[test]
    fn test_lua_require_no_parens() {
        let source = r#"local dict = require"socket.dict""#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "socket.dict");
    }

    /// Test: Lua require with space before string (no parens)
    /// `local mime = require "mime"`
    #[test]
    fn test_lua_require_space_string() {
        let source = r#"local mime = require "mime""#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "mime");
    }

    /// Test: Lua local require with nested module path
    /// `local http = require("socket.http")`
    #[test]
    fn test_lua_require_local() {
        let source = r#"local http = require("socket.http")"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "socket.http");
    }

    /// Test: Multiple Lua requires in a file
    #[test]
    fn test_lua_multiple_requires() {
        let source = r#"
local socket = require("socket")
local url = require("socket.url")
local ltn12 = require("ltn12")
local mime = require("mime")
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert!(
            imports.len() >= 4,
            "Expected at least 4 imports, got {}",
            imports.len()
        );
        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"socket"), "Missing 'socket' import");
        assert!(
            modules.contains(&"socket.url"),
            "Missing 'socket.url' import"
        );
        assert!(modules.contains(&"ltn12"), "Missing 'ltn12' import");
        assert!(modules.contains(&"mime"), "Missing 'mime' import");
    }

    // -------------------------------------------------------------------------
    // v0.5.0 AUDIT-FIX (W2-lua-require): non-string-literal require() arguments
    // (Roblox / Luau DataModel paths) were silently dropped because the
    // argument reader only accepted a `string` child. These tests pin the new
    // AST-driven module-path reconstruction for dot/bracket index and
    // `:WaitForChild("x")` forms across BOTH Lua and Luau (shared code path).
    // -------------------------------------------------------------------------

    /// Test: Lua `require(script.Parent.Foo)` -> module `script.Parent.Foo`
    /// (dot_index_expression argument, no string literal).
    #[test]
    fn test_lua_require_datamodel_dot_path() {
        let source = r#"local Foo = require(script.Parent.Foo)"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "script.Parent.Foo");
    }

    /// Test: deeply nested DataModel path
    /// `require(script.Parent.Parent.Util)` and a `game.X.Y.Z` root.
    #[test]
    fn test_lua_require_datamodel_nested_paths() {
        let source = r#"
local Util = require(script.Parent.Parent.Util)
local Net = require(game.ReplicatedStorage.Shared.Net)
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(
            modules.contains(&"script.Parent.Parent.Util"),
            "Missing nested 'script.Parent.Parent.Util', got {modules:?}"
        );
        assert!(
            modules.contains(&"game.ReplicatedStorage.Shared.Net"),
            "Missing 'game.ReplicatedStorage.Shared.Net', got {modules:?}"
        );
    }

    /// Test: `require(script:WaitForChild("Config"))` -> module `Config`
    /// (method_index_expression call; the string literal is the module name).
    #[test]
    fn test_lua_require_wait_for_child() {
        let source = r#"local Config = require(script:WaitForChild("Config"))"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "Config");
    }

    /// Test: `require(script["Bracketed"])` -> module `script.Bracketed`
    /// (bracket_index_expression with a string subscript).
    #[test]
    fn test_lua_require_bracket_index() {
        let source = r#"local B = require(script["Bracketed"])"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        assert_eq!(imports.len(), 1, "Expected 1 import, got {}", imports.len());
        assert_eq!(imports[0].module, "script.Bracketed");
    }

    /// Test: the SAME non-string forms must resolve under the Luau grammar
    /// (Luau shares the Lua import path; node kinds are identical). This is the
    /// primary regression target since DataModel requires are a Luau idiom.
    #[test]
    fn test_luau_require_datamodel_forms() {
        let source = r#"
local Net = require(script.Parent.Net)
local Cfg = require(script:WaitForChild("Config"))
local Shared = require(game.ReplicatedStorage.Shared)
"#;
        let tree = parse(source, Language::Luau).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Luau).unwrap();

        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(
            modules.contains(&"script.Parent.Net"),
            "Luau: missing 'script.Parent.Net', got {modules:?}"
        );
        assert!(
            modules.contains(&"Config"),
            "Luau: missing WaitForChild 'Config', got {modules:?}"
        );
        assert!(
            modules.contains(&"game.ReplicatedStorage.Shared"),
            "Luau: missing 'game.ReplicatedStorage.Shared', got {modules:?}"
        );
    }

    /// Test: mixed file (string + local + DataModel) yields ALL three — the
    /// exact CHAR-TEST shape from the task brief.
    #[test]
    fn test_lua_require_mixed_string_and_datamodel() {
        let source = r#"
require("m")
local x = require("y")
local Foo = require(script.Parent.Foo)
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();

        let modules: Vec<&str> = imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"m"), "Missing string require 'm', got {modules:?}");
        assert!(modules.contains(&"y"), "Missing local require 'y', got {modules:?}");
        assert!(
            modules.contains(&"script.Parent.Foo"),
            "Missing DataModel require 'script.Parent.Foo', got {modules:?}"
        );
    }

    /// Negative guard: a require with a truly unresolvable bare-identifier
    /// argument (e.g. `require(modVar)`) is still acceptable to surface by its
    /// identifier text, but a require with NO argument must not crash / emit.
    #[test]
    fn test_lua_require_no_argument_is_dropped() {
        let source = r#"require()"#;
        let tree = parse(source, Language::Lua).unwrap();
        let imports = extract_imports_from_tree(&tree, source, Language::Lua).unwrap();
        assert!(
            imports.is_empty(),
            "require() with no argument must not emit an import, got {imports:?}"
        );
    }
}
