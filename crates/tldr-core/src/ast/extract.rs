//! Full file extraction (spec Section 2.1.3)
//!
//! Extracts complete module information from a single file including:
//! - Module docstring
//! - All imports
//! - Function details (name, params, return type, docstring, decorators)
//! - Class details (name, bases, methods)
//! - Intra-file call graph

use std::collections::HashMap;
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::error::TldrError;
use crate::types::{
    ClassInfo, ErrorInfo, EventInfo, EventParamInfo, FieldInfo, FunctionInfo, IntraFileCallGraph,
    Language, ModifierInfo, ModuleInfo, ParamInfo,
};
use crate::TldrResult;

use super::imports::extract_imports_from_tree;
use super::parser::parse_file_with_lang;

/// Extract complete module information from a file.
///
/// # Arguments
/// * `file_path` - Path to the source file
/// * `base_path` - Optional base path for relative file paths in output
///
/// # Returns
/// * `Ok(ModuleInfo)` - Complete module information
/// * `Err(TldrError::PathNotFound)` - File doesn't exist
/// * `Err(TldrError::PathTraversal)` - Path escapes base_path
/// * `Err(TldrError::UnsupportedLanguage)` - Unknown file extension
/// * `Err(TldrError::ParseError)` - Syntax error
pub fn extract_file(file_path: &Path, base_path: Option<&Path>) -> TldrResult<ModuleInfo> {
    extract_file_with_lang(file_path, base_path, None)
}

/// Extract complete module information from a file with an optional language hint.
///
/// When `lang_hint` is `Some(_)`, that language is used directly instead of
/// path-extension detection. This is required so callers (e.g. the `tldr extract`
/// CLI receiving `--lang cpp`) can correctly classify files whose canonical
/// extension would otherwise be misdetected — most importantly the `.h`
/// header ambiguity (`from_path` returns `Language::C`, but headers in C++
/// projects must be parsed as C++ so `class` declarations populate `classes`
/// instead of leaking through `functions[].return_type == "class"`).
///
/// When `lang_hint` is `None`, behavior matches [`extract_file`]: the language
/// is inferred from the path extension via the parser pool.
///
/// # Arguments
/// * `file_path` - Path to the source file
/// * `base_path` - Optional base path for relative file paths in output
/// * `lang_hint` - Optional language override that takes precedence over
///   path-extension detection
///
/// # Returns
/// * `Ok(ModuleInfo)` - Complete module information
/// * `Err(TldrError::PathNotFound)` - File doesn't exist
/// * `Err(TldrError::PathTraversal)` - Path escapes base_path
/// * `Err(TldrError::UnsupportedLanguage)` - Unknown extension and no hint
/// * `Err(TldrError::ParseError)` - Syntax error
pub fn extract_file_with_lang(
    file_path: &Path,
    base_path: Option<&Path>,
    lang_hint: Option<crate::types::Language>,
) -> TldrResult<ModuleInfo> {
    // Check for path traversal if base_path provided
    if let Some(base) = base_path {
        let canonical_file = dunce::canonicalize(file_path)
            .map_err(|_| TldrError::PathNotFound(file_path.to_path_buf()))?;
        let canonical_base =
            dunce::canonicalize(base).map_err(|_| TldrError::PathNotFound(base.to_path_buf()))?;

        if !canonical_file.starts_with(&canonical_base) {
            return Err(TldrError::PathTraversal(file_path.to_path_buf()));
        }
    }

    let (tree, source, language) = parse_file_with_lang(file_path, lang_hint)?;

    extract_from_tree(&tree, &source, language, file_path, base_path)
}

/// Extract complete module information from a pre-parsed syntax tree.
///
/// This function is useful when you already have a parsed tree and want to extract
/// module information without re-parsing. This enables combined passes where parsing
/// happens once and multiple extractions can be performed.
///
/// # Arguments
/// * `tree` - Pre-parsed syntax tree
/// * `source` - Source code text
/// * `language` - Programming language of the source
/// * `file_path` - Path to the source file (used for output path)
/// * `base_path` - Optional base path for relative file paths in output
///
/// # Returns
/// * `Ok(ModuleInfo)` - Complete module information
/// * `Err(TldrError)` - Extraction error
pub fn extract_from_tree(
    tree: &Tree,
    source: &str,
    language: Language,
    file_path: &Path,
    base_path: Option<&Path>,
) -> TldrResult<ModuleInfo> {
    // Compute relative path if base provided
    let output_path = if let Some(base) = base_path {
        file_path
            .strip_prefix(base)
            .unwrap_or(file_path)
            .to_path_buf()
    } else {
        file_path.to_path_buf()
    };

    // Extract module docstring
    let docstring = extract_module_docstring(tree, source, language);

    // Extract imports
    let imports = extract_imports_from_tree(tree, source, language)?;

    // Extract functions with full details
    let functions = extract_functions_detailed(tree, source, language);

    // Extract classes with full details
    let classes = extract_classes_detailed(tree, source, language);

    // Extract module-level constants (Gap 3)
    let constants = extract_module_constants(tree, source, language);

    // Build intra-file call graph
    let call_graph = build_intra_file_call_graph(tree, source, language, &functions, &classes);

    // solidity-ast-extract-v1 (v0.5.0 SOL-003): extract file-scope
    // Solidity declarations. For non-Solidity languages these are
    // always empty (preserving the pre-v1 JSON shape via
    // `skip_serializing_if = "Vec::is_empty"` on each field).
    let (modifiers, events, errors) = match language {
        Language::Solidity => {
            let root = tree.root_node();
            (
                extract_solidity_modifiers(&root, source, /* file_scope = */ true),
                extract_solidity_events(&root, source, /* file_scope = */ true),
                extract_solidity_errors(&root, source, /* file_scope = */ true),
            )
        }
        _ => (Vec::new(), Vec::new(), Vec::new()),
    };

    Ok(ModuleInfo {
        file_path: output_path,
        language,
        docstring,
        imports,
        functions,
        classes,
        constants,
        call_graph,
        modifiers,
        events,
        errors,
    })
}

/// Extract parameter names for a single function-like AST node.
///
/// explain-signature-params-v1 (v0.4.2 M-001): the `tldr explain` pipeline
/// historically built its own simplified param walker that only handled
/// python-style tree-sitter node kinds (`identifier`, `typed_parameter`,
/// `default_parameter`), so on 15 other languages `signature.params`
/// silently emitted `[]` even though `tldr extract` on the same file
/// already returned the correct list. Rather than duplicating the
/// per-language walkers inside `crates/tldr-cli/src/commands/remaining/explain.rs`,
/// this function exposes the canonical extract-side dispatcher so explain
/// (and any future consumer) can reuse it.
///
/// # Arguments
/// * `func_node` - The AST node identified by the per-language function
///   kinds in `crates/tldr-cli/src/commands/remaining/explain.rs::get_function_node_kinds`.
///   For ocaml this is a `value_definition` (this dispatcher finds the
///   inner `let_binding`). For elixir this is the outer `call` node
///   (this dispatcher finds the `arguments` call_args inside).
/// * `source` - Source-file UTF-8 string.
/// * `language` - Language hint matching the parser that produced the tree.
///
/// # Returns
/// A `Vec<String>` of parameter name fragments (or short snippets for
/// pattern-matched / receiver-style params like rust `&mut self`). The
/// list is empty when the language has no parameter list, when the node
/// is not a function-like node, or when no params can be extracted.
///
/// # Notes
/// - This is additive: it does NOT alter the per-language extractors;
///   it simply forwards to them.
/// - Returning `Vec<String>` matches the schema of
///   `tldr_core::types::FunctionInfo::params`, so callers that need a
///   richer `{name, type, default}` shape (like the `explain` command's
///   `ParamInfo`) should treat each entry as a parameter name and
///   construct their richer type around it.
pub fn extract_function_params(
    func_node: &Node,
    source: &str,
    language: Language,
) -> Vec<String> {
    match language {
        Language::Python => extract_python_params(func_node, source),
        Language::TypeScript | Language::JavaScript => {
            // Try the regular extractor first (function_declaration /
            // method_definition / function expressions). Fall back to the
            // arrow-style extractor for `arrow_function` nodes.
            let p = extract_ts_params(func_node, source);
            if !p.is_empty() {
                p
            } else {
                extract_ts_arrow_params(func_node, source)
            }
        }
        Language::Go => extract_go_params(func_node, source),
        Language::Rust => extract_rust_params(func_node, source),
        Language::Java => extract_java_params(func_node, source),
        Language::C | Language::Cpp => extract_c_params(func_node, source),
        Language::CSharp => extract_csharp_params(func_node, source),
        Language::Kotlin => extract_kotlin_params(func_node, source),
        Language::Scala => extract_scala_params(func_node, source),
        Language::Php => extract_php_params(func_node, source),
        Language::Ruby => extract_ruby_params(func_node, source),
        Language::Lua => extract_lua_params(func_node, source),
        Language::Luau => extract_luau_params(func_node, source),
        Language::Swift => extract_swift_params(func_node, source),
        Language::Ocaml => {
            // explain identifies ocaml function nodes as `value_definition`,
            // but `extract_ocaml_params` expects the inner `let_binding`.
            // Find the first `let_binding` child and dispatch on that.
            let mut cursor = func_node.walk();
            for child in func_node.children(&mut cursor) {
                if child.kind() == "let_binding" {
                    return extract_ocaml_params(&child, source);
                }
            }
            // If the caller already passed a `let_binding`, dispatch directly.
            if func_node.kind() == "let_binding" {
                return extract_ocaml_params(func_node, source);
            }
            Vec::new()
        }
        // solidity-ast-extract-v1 (v0.5.0 SOL-003): walk `parameter`
        // children of a `function_definition` / `constructor_definition`
        // / `fallback_receive_definition` / `modifier_definition` node
        // and collect their `name` field values.
        Language::Solidity => extract_solidity_params(func_node, source)
            .into_iter()
            .map(|p| p.name)
            .collect(),
        Language::Elixir => {
            // explain identifies elixir function nodes as the outer `call`
            // node (def/defp ...). The actual params live inside
            // `arguments > call > arguments` (or `arguments > binary_operator > call > arguments`
            // when a guard is present). Walk into the structure mirroring
            // `extract_elixir_functions_detailed` so we share the proven path.
            elixir_params_from_def_call(func_node, source)
        }
    }
}

/// Helper for `extract_function_params` (elixir branch). Mirrors the
/// nesting walked by `extract_elixir_functions_detailed`.
fn elixir_params_from_def_call(node: &Node, source: &str) -> Vec<String> {
    // The outer `call` has children: identifier "def"/"defp" + arguments.
    // The `arguments` wraps either the function-as-call or a binary_operator
    // (when there's a guard).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "arguments" {
            // First child of `arguments` is either:
            //   * `call` — the signature with its own arguments wrapper
            //   * `binary_operator` — `call ... when guard`
            //   * `identifier` — zero-arg def with no parens
            if let Some(first) = child.child(0) {
                match first.kind() {
                    "call" => {
                        // call.child(1) is the inner `arguments` containing the params.
                        if let Some(inner_args) = first.child(1) {
                            if inner_args.kind() == "arguments" {
                                return extract_elixir_params(&inner_args, source);
                            }
                        }
                    }
                    "binary_operator" => {
                        let mut bin_cursor = first.walk();
                        for bin_child in first.children(&mut bin_cursor) {
                            if bin_child.kind() == "call" {
                                if let Some(inner_args) = bin_child.child(1) {
                                    if inner_args.kind() == "arguments" {
                                        return extract_elixir_params(&inner_args, source);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            break;
        }
    }
    Vec::new()
}

/// Extract module-level docstring
fn extract_module_docstring(tree: &Tree, source: &str, language: Language) -> Option<String> {
    let root = tree.root_node();

    match language {
        Language::Python => {
            // First expression statement that is a string
            let mut cursor = root.walk();
            for child in root.children(&mut cursor) {
                if child.kind() == "expression_statement" {
                    if let Some(expr) = child.child(0) {
                        if expr.kind() == "string" {
                            return Some(extract_string_content(&expr, source));
                        }
                    }
                } else if child.kind() != "comment" {
                    // Stop at first non-comment, non-docstring
                    break;
                }
            }
            None
        }
        Language::TypeScript | Language::JavaScript => {
            // JSDoc comment at start
            let mut cursor = root.walk();
            for child in root.children(&mut cursor) {
                if child.kind() == "comment" {
                    let text = get_node_text(&child, source);
                    if text.starts_with("/**") {
                        return Some(text);
                    }
                } else {
                    break;
                }
            }
            None
        }
        Language::Rust => {
            // //! or /*! doc comments
            let mut cursor = root.walk();
            let mut doc_lines = Vec::new();
            for child in root.children(&mut cursor) {
                let text = get_node_text(&child, source);
                if child.kind() == "line_comment" && text.starts_with("//!") {
                    doc_lines.push(text.trim_start_matches("//!").trim().to_string());
                } else if child.kind() == "block_comment" && text.starts_with("/*!") {
                    return Some(text);
                } else if !doc_lines.is_empty() || child.kind() != "line_comment" {
                    break;
                }
            }
            if doc_lines.is_empty() {
                None
            } else {
                Some(doc_lines.join("\n"))
            }
        }
        _ => None,
    }
}

/// Parse a `/** ... */` block doc comment, stripping delimiters and leading `*` per line.
fn parse_block_doc_comment(text: &str) -> Option<String> {
    let inner = text.trim_start_matches("/**").trim_end_matches("*/");
    let cleaned: Vec<String> = inner
        .lines()
        .map(|l| {
            let t = l.trim();
            let t = t
                .strip_prefix("* ")
                .unwrap_or(t.strip_prefix('*').unwrap_or(t));
            t.to_string()
        })
        .collect();
    let start = cleaned
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(cleaned.len());
    let end = cleaned
        .iter()
        .rposition(|l| !l.is_empty())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end {
        None
    } else {
        Some(cleaned[start..end].join("\n"))
    }
}

/// Extract functions with full details
///
/// (vuln-migration-v1 M3, premortem T3/DR3 amendment) Visibility extended from
/// private `fn` to `pub(crate)` so `tldr_core::security::vuln::scan_file_vulns`
/// can enumerate functions with line ranges for the per-function
/// `compute_taint_with_tree` dispatch loop. NOT part of the external library
/// API; internal-only consumers within tldr-core.
pub(crate) fn extract_functions_detailed(tree: &Tree, source: &str, language: Language) -> Vec<FunctionInfo> {
    let mut functions = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Python => extract_python_functions_detailed(&root, source, &mut functions, false),
        Language::TypeScript | Language::JavaScript => {
            extract_ts_functions_detailed(&root, source, &mut functions, false)
        }
        Language::Go => extract_go_functions_detailed(&root, source, &mut functions),
        Language::Rust => extract_rust_functions_detailed(&root, source, &mut functions),
        Language::Java => extract_java_functions_detailed(&root, source, &mut functions),
        Language::C => extract_c_functions_detailed(&root, source, &mut functions),
        Language::Cpp => extract_cpp_functions_detailed(&root, source, &mut functions),
        Language::Ruby => extract_ruby_functions_detailed(&root, source, &mut functions),
        Language::Php => extract_php_functions_detailed(&root, source, &mut functions),
        Language::CSharp => extract_csharp_functions_detailed(&root, source, &mut functions),
        Language::Kotlin => extract_kotlin_functions_detailed(&root, source, &mut functions),
        Language::Scala => extract_scala_functions_detailed(&root, source, &mut functions),
        Language::Elixir => extract_elixir_functions_detailed(&root, source, &mut functions),
        Language::Lua => extract_lua_functions_detailed(&root, source, &mut functions),
        Language::Luau => extract_luau_functions_detailed(&root, source, &mut functions),
        Language::Swift => extract_swift_functions_detailed(&root, source, &mut functions),
        Language::Ocaml => extract_ocaml_functions_detailed(&root, source, &mut functions),
        // solidity-ast-extract-v1 (v0.5.0 SOL-003): walk
        // `function_definition` / `constructor_definition` /
        // `fallback_receive_definition` at file scope. Functions
        // inside contracts/interfaces/libraries are picked up by
        // `extract_solidity_classes_detailed` via the
        // `contract_body` walker.
        Language::Solidity => {
            extract_solidity_functions_detailed(&root, source, &mut functions, false);
        }
    }

    functions
}

/// Extract classes with full details
///
/// (vuln-migration-v1 M3) Visibility extended from private `fn` to `pub(crate)`
/// alongside `extract_functions_detailed` so `vuln::scan_file_vulns` can
/// enumerate per-method ranges for languages whose method definitions live
/// only inside class/object/trait bodies (Scala `object M { def f ... }`,
/// Java `class C { void f(){} }`, etc.). NOT part of the external library API.
pub(crate) fn extract_classes_detailed(tree: &Tree, source: &str, language: Language) -> Vec<ClassInfo> {
    let mut classes = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Python => extract_python_classes_detailed(&root, source, &mut classes),
        Language::TypeScript | Language::JavaScript => {
            extract_ts_classes_detailed(&root, source, &mut classes)
        }
        Language::Rust => extract_rust_structs_detailed(&root, source, &mut classes),
        Language::Java => extract_java_classes_detailed(&root, source, &mut classes),
        Language::Cpp => extract_cpp_classes_detailed(&root, source, &mut classes),
        Language::Ruby => extract_ruby_classes_detailed(&root, source, &mut classes),
        Language::Php => extract_php_classes_detailed(&root, source, &mut classes),
        Language::CSharp => extract_csharp_classes_detailed(&root, source, &mut classes),
        Language::Kotlin => extract_kotlin_classes_detailed(&root, source, &mut classes),
        Language::Scala => extract_scala_classes_detailed(&root, source, &mut classes),
        Language::Elixir => extract_elixir_classes_detailed(&root, source, &mut classes),
        Language::Go => extract_go_structs_detailed(&root, source, &mut classes),
        Language::Swift => extract_swift_classes_detailed(&root, source, &mut classes),
        // W2-lua-structure (v0.5.0 AUDIT-FIX): Lua/Luau have no `class`
        // keyword, but the canonical idiom is a table bound to a
        // local/global with attached `function T.m()` (dot/static) and
        // `function T:m()` (colon/method) declarations. Group those
        // table-receiver functions into `ClassInfo` entries (mirrors the
        // Ruby module-as-class precedent + the Python self-field
        // precedent). Luau reuses the same walker (identical AST kinds)
        // and additionally carries method return types.
        Language::Lua => extract_lua_classes_detailed(&root, source, &mut classes, Language::Lua),
        Language::Luau => extract_lua_classes_detailed(&root, source, &mut classes, Language::Luau),
        Language::C | Language::Ocaml => {} // No classes
        // solidity-ast-extract-v1 (v0.5.0 SOL-003): walk
        // `contract_declaration` / `interface_declaration` /
        // `library_declaration` and emit `ClassInfo` with
        // `kind: Some("contract"|"interface"|"library")`. Each
        // class collects nested modifiers/events/errors/methods
        // from the `contract_body`.
        Language::Solidity => extract_solidity_classes_detailed(&root, source, &mut classes),
    }

    classes
}

// =============================================================================
// extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002)
// =============================================================================
//
// tree-sitter's `method_declaration` / `function_declaration` /
// `function_definition` nodes start at their first child. For
// annotation-decorated declarations, that first child is a `modifiers`
// container holding the annotations (Java `@Override`, Kotlin
// `@Deprecated(...)`) or a leading `annotation` / `attribute` /
// `modifier` sibling node (Scala `@deprecated`, Swift `@inlinable`).
// The result: `node.start_position()` reports the annotation line, not
// the decl-keyword line — so `extract`'s `line_number`, `explain`'s
// `line_start`, and any consumer that pulls bounds via
// `find_function_bounds` all attribute the function to the wrong line.
//
// `decl_keyword_line_from_node` walks the AST children in order and
// returns the start line (1-indexed) of the first child that is NOT in
// the annotation/modifier kind set for the language family. Returns the
// fallback `node.start_position()` line if all children look like
// annotations (e.g. malformed input) or the node has no children.
//
// The fix is AST-only — no source-text scanning. We accept the union of
// annotation/modifier kinds across the four affected grammars
// (java/kotlin/scala/swift). Other languages' extractors are not
// touched: their grammars place the decl keyword (`def`, `fn`, `pub`)
// directly as the first child, so `node.start_position()` already
// agrees with the decl-keyword line.

/// Kinds that should be skipped when locating the decl-keyword line of
/// a function/method/class declaration node.
///
/// - `modifiers` — Java/Kotlin container holding annotations + access
///   keywords (`@Override`, `@Deprecated`, `public`, `static`, etc.).
/// - `annotation` / `marker_annotation` / `single_member_annotation`
///   / `normal_annotation` — Java grammar variants for `@Foo`,
///   `@Foo(x)`, `@Foo(x = 1)`.
/// - `attribute` / `attributes` / `modifier` — Swift grammar variants
///   for `@inlinable`, `@available(...)`, `@objc`, etc.
/// - `attribute_list` — C# grammar variant for `[Test]`, `[Serializable]`,
///   `[Obsolete(...)]`, etc.
/// - `block_comment` / `line_comment` / `comment` — leading doc
///   comments are tree-sitter children of the declaration in some
///   grammars; they should not anchor the decl line.
/// - `simple_identifier` / `identifier` keyword-prefix shapes are NOT
///   skipped — they are real decl content.
const ANNOTATION_LIKE_KINDS: &[&str] = &[
    // Java + Kotlin grammars
    "modifiers",
    "annotation",
    "marker_annotation",
    "single_member_annotation",
    "normal_annotation",
    // Kotlin grammar additions
    "annotation_modifier",
    "function_modifier",
    "platform_modifier",
    "member_modifier",
    "inheritance_modifier",
    "parameter_modifier",
    "reification_modifier",
    "visibility_modifier",
    // Scala grammar
    "annotations",
    // Swift grammar variants
    "attribute",
    "attributes",
    "modifier",
    "type_modifiers",
    "user_type",
    // C# grammar: `[Attribute]` declaration prefixes are emitted as
    // `attribute_list` children of the declaration node (v0.5.0 CL-10,
    // GH #81). A method `[Test]\npublic void Foo()` would otherwise
    // anchor to the `[Test]` line.
    "attribute_list",
    // Leading doc / comments (defensive — most grammars don't make
    // these children of the decl node, but if they do they should not
    // anchor the line).
    "block_comment",
    "line_comment",
    "comment",
    // Decorators (only when grammar emits them as a separate child;
    // python uses `decorated_definition` parent which is handled
    // separately).
    "decorator",
];

/// Return the 1-indexed start line of the first child of `node` whose
/// kind is NOT annotation-like (per `ANNOTATION_LIKE_KINDS`). Falls back
/// to `node.start_position()` if every child is annotation-like or the
/// node has no children.
///
/// This is the AST-only normaliser shared across the
/// java/kotlin/scala/swift function and class extractors so that
/// `extract`/`slice`/`explain` all report the decl-keyword line rather
/// than the leading-annotation line. v0.4.2 M-002.
///
/// Public so `find_function_bounds` (slice consumer) and `explain` can
/// reuse the same normalisation for the function/method/class node
/// returned by `find_function_node`.
pub fn decl_keyword_line_from_node(node: &Node) -> u32 {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !ANNOTATION_LIKE_KINDS.contains(&child.kind()) {
            return child.start_position().row as u32 + 1;
        }
    }
    node.start_position().row as u32 + 1
}

// =============================================================================
// Python detailed extraction
// =============================================================================

fn extract_python_functions_detailed(
    node: &Node,
    source: &str,
    functions: &mut Vec<FunctionInfo>,
    is_method: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Check if this is inside a class
                let in_class = is_inside_class(&child);
                if in_class && !is_method {
                    continue; // Skip methods when extracting functions
                }
                if !in_class && is_method {
                    continue; // Skip functions when extracting methods
                }

                let info = extract_python_function_info(&child, source, in_class);
                functions.push(info);
            }
            "decorated_definition" => {
                // Handle decorated functions
                if let Some(def) = child.child_by_field_name("definition") {
                    if def.kind() == "function_definition" {
                        let in_class = is_inside_class(&child);
                        if (in_class && is_method) || (!in_class && !is_method) {
                            let mut info = extract_python_function_info(&def, source, in_class);
                            info.decorators = extract_decorators(&child, source);
                            functions.push(info);
                        }
                    }
                }
            }
            "class_definition" => {
                // Don't recurse into classes for top-level functions
                if !is_method {
                    continue;
                }
                if let Some(body) = child.child_by_field_name("body") {
                    extract_python_functions_detailed(&body, source, functions, true);
                }
            }
            _ => {
                if !is_method {
                    extract_python_functions_detailed(&child, source, functions, false);
                }
            }
        }
    }
}

fn extract_python_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_python_params(node, source);
    let return_type = node
        .child_by_field_name("return_type")
        .map(|n| get_node_text(&n, source));

    let docstring = extract_python_docstring(node, source);
    let is_async = node
        .prev_sibling()
        .map(|s| s.kind() == "async")
        .unwrap_or(false)
        || has_async_keyword(node, source);

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async,
        decorators: Vec::new(), // Set by caller for decorated functions
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_python_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    params.push(get_node_text(&child, source));
                }
                "typed_parameter" | "default_parameter" | "typed_default_parameter" => {
                    // The identifier is the first child, not a named field
                    let mut inner_cursor = child.walk();
                    for inner_child in child.children(&mut inner_cursor) {
                        if inner_child.kind() == "identifier" {
                            params.push(get_node_text(&inner_child, source));
                            break;
                        }
                    }
                }
                "list_splat_pattern" | "dictionary_splat_pattern" => {
                    params.push(get_node_text(&child, source));
                }
                _ => {}
            }
        }
    }

    params
}

fn extract_python_docstring(node: &Node, source: &str) -> Option<String> {
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        let mut children = body.children(&mut cursor);
        if let Some(child) = children.next() {
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.child(0) {
                    if expr.kind() == "string" {
                        return Some(extract_string_content(&expr, source));
                    }
                }
            }
        }
    }
    None
}

fn extract_decorators(node: &Node, source: &str) -> Vec<String> {
    let mut decorators = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "decorator" {
            let text = get_node_text(&child, source);
            // Remove leading @
            decorators.push(text.trim_start_matches('@').to_string());
        }
    }

    decorators
}

fn extract_python_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_definition" => {
                let info = extract_python_class_info(&child, source);
                classes.push(info);
            }
            "decorated_definition" => {
                if let Some(def) = child.child_by_field_name("definition") {
                    if def.kind() == "class_definition" {
                        let mut info = extract_python_class_info(&def, source);
                        info.decorators = extract_decorators(&child, source);
                        classes.push(info);
                    }
                }
            }
            _ => {
                extract_python_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_python_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let bases = extract_python_bases(node, source);
    let docstring = extract_python_class_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_python_functions_detailed(&body, source, &mut methods, true);
    }

    // Extract class fields (Gap 3)
    let fields = extract_python_class_fields(node, source);

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields,
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_python_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();

    if let Some(superclasses) = node.child_by_field_name("superclasses") {
        let mut cursor = superclasses.walk();
        for child in superclasses.children(&mut cursor) {
            if child.kind() == "identifier" || child.kind() == "attribute" {
                bases.push(get_node_text(&child, source));
            }
        }
    }

    bases
}

fn extract_python_class_docstring(node: &Node, source: &str) -> Option<String> {
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        let mut children = body.children(&mut cursor);
        if let Some(child) = children.next() {
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.child(0) {
                    if expr.kind() == "string" {
                        return Some(extract_string_content(&expr, source));
                    }
                }
            }
        }
    }
    None
}

// =============================================================================
// Gap 3: Python class field extraction
// =============================================================================

/// Helper: check if a name is UPPER_CASE (constant convention)
pub(crate) fn is_upper_case_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
        && name.chars().any(|c| c.is_alphabetic())
}

/// Extract class-level fields and __init__ self.x assignments from a Python class
fn extract_python_class_fields(node: &Node, source: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();

    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            match child.kind() {
                "expression_statement" => {
                    // Class-level assignment: x = 10 or x: int = 5
                    if let Some(inner) = child.child(0) {
                        if inner.kind() == "assignment" {
                            if let Some(field) =
                                extract_python_field_from_assignment(&inner, source, true)
                            {
                                fields.push(field);
                            }
                        }
                    }
                }
                "function_definition" | "decorated_definition" => {
                    // Check for __init__ and extract self.x assignments
                    let def_node = if child.kind() == "decorated_definition" {
                        child.child_by_field_name("definition")
                    } else {
                        Some(child)
                    };
                    if let Some(def) = def_node {
                        if def.kind() == "function_definition" {
                            let fname = def
                                .child_by_field_name("name")
                                .map(|n| get_node_text(&n, source));
                            if fname.as_deref() == Some("__init__") {
                                extract_python_init_fields(&def, source, &mut fields);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fields
}

/// Extract a field from a Python assignment node (class-level)
fn extract_python_field_from_assignment(
    node: &Node,
    source: &str,
    is_static: bool,
) -> Option<FieldInfo> {
    // Assignment: left = right  OR  left: type = right
    let left = node.child_by_field_name("left")?;

    // Only handle simple identifiers (not self.x or tuple unpacking)
    if left.kind() != "identifier" {
        return None;
    }

    let name = get_node_text(&left, source);

    // Extract type annotation if present
    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    // Extract default value
    let default_value = node
        .child_by_field_name("right")
        .map(|n| get_node_text(&n, source));

    let is_constant = is_upper_case_name(&name);
    let visibility = if name.starts_with('_') {
        Some("private".to_string())
    } else {
        Some("public".to_string())
    };
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static,
        is_constant,
        visibility,
        line_number,
        line_end,
    })
}

/// Extract self.x assignments from __init__ method body
fn extract_python_init_fields(init_node: &Node, source: &str, fields: &mut Vec<FieldInfo>) {
    if let Some(body) = init_node.child_by_field_name("body") {
        extract_python_self_assignments(&body, source, fields);
    }
}

/// Recursively walk a function body to find self.x = ... assignments
fn extract_python_self_assignments(node: &Node, source: &str, fields: &mut Vec<FieldInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "expression_statement" {
            if let Some(inner) = child.child(0) {
                if inner.kind() == "assignment" {
                    if let Some(left) = inner.child_by_field_name("left") {
                        if left.kind() == "attribute" {
                            // Check if it's self.x
                            if let Some(obj) = left.child_by_field_name("object") {
                                if get_node_text(&obj, source) == "self" {
                                    if let Some(attr) = left.child_by_field_name("attribute") {
                                        let name = get_node_text(&attr, source);
                                        let default_value = inner
                                            .child_by_field_name("right")
                                            .map(|n| get_node_text(&n, source));
                                        let visibility = if name.starts_with('_') {
                                            Some("private".to_string())
                                        } else {
                                            Some("public".to_string())
                                        };
                                        let line_number = inner.start_position().row as u32 + 1;
                                        let line_end = inner.end_position().row as u32 + 1;

                                        fields.push(FieldInfo {
                                            name,
                                            field_type: None,
                                            default_value,
                                            is_static: false,
                                            is_constant: false,
                                            visibility,
                                            line_number,
                                            line_end,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Recurse into if/for/try blocks inside __init__
        extract_python_self_assignments(&child, source, fields);
    }
}

// =============================================================================
// Gap 3: Module-level constants extraction
// =============================================================================

/// Extract module-level constants for all languages
fn extract_module_constants(tree: &Tree, source: &str, language: Language) -> Vec<FieldInfo> {
    let root = tree.root_node();
    match language {
        Language::Python => extract_python_module_constants(&root, source),
        Language::Rust => extract_rust_module_constants(&root, source),
        Language::Go => extract_go_module_constants(&root, source),
        Language::TypeScript | Language::JavaScript => extract_ts_module_constants(&root, source),
        Language::Java => Vec::new(), // Java constants are always in classes
        Language::C => extract_c_module_constants(&root, source),
        Language::Cpp => extract_cpp_module_constants(&root, source),
        Language::Ruby => extract_ruby_module_constants(&root, source),
        Language::Kotlin => extract_kotlin_module_constants(&root, source),
        Language::Swift => extract_swift_module_constants(&root, source),
        Language::CSharp => extract_csharp_module_constants(&root, source),
        Language::Scala => extract_scala_module_constants(&root, source),
        Language::Php => extract_php_module_constants(&root, source),
        Language::Lua => extract_lua_module_constants(&root, source),
        Language::Luau => extract_luau_module_constants(&root, source),
        Language::Elixir => extract_elixir_module_constants(&root, source),
        Language::Ocaml => extract_ocaml_module_constants(&root, source),
        // solidity-ast-extract-v1 (v0.5.0 SOL-003): emit
        // `constant_variable_declaration` at file-scope as a
        // `FieldInfo` with `is_constant = true`. State variables
        // inside contracts are collected per-contract by
        // `extract_solidity_classes_detailed` into `ClassInfo.fields`.
        Language::Solidity => extract_solidity_module_constants(&root, source),
    }
}

/// Extract UPPER_CASE top-level assignments as Python module constants
fn extract_python_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "expression_statement" {
            if let Some(inner) = child.child(0) {
                if inner.kind() == "assignment" {
                    if let Some(left) = inner.child_by_field_name("left") {
                        if left.kind() == "identifier" {
                            let name = get_node_text(&left, source);
                            if is_upper_case_name(&name) {
                                let default_value = inner
                                    .child_by_field_name("right")
                                    .map(|n| get_node_text(&n, source));
                                let field_type = inner
                                    .child_by_field_name("type")
                                    .map(|n| get_node_text(&n, source));
                                let line_number = inner.start_position().row as u32 + 1;
                                let line_end = inner.end_position().row as u32 + 1;
                                constants.push(FieldInfo {
                                    name,
                                    field_type,
                                    default_value,
                                    is_static: true,
                                    is_constant: true,
                                    visibility: None,
                                    line_number,
                                    line_end,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    constants
}

/// Extract const/static items as Rust module constants
fn extract_rust_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    extract_rust_constants_recursive(root, source, &mut constants);
    constants
}

fn extract_rust_constants_recursive(node: &Node, source: &str, constants: &mut Vec<FieldInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "const_item" => {
                if let Some(field) = extract_rust_const_or_static(&child, source, true) {
                    constants.push(field);
                }
            }
            "static_item" => {
                if let Some(field) = extract_rust_const_or_static(&child, source, false) {
                    constants.push(field);
                }
            }
            _ => {
                // Don't recurse into functions/impl blocks
                if child.kind() != "function_item"
                    && child.kind() != "impl_item"
                    && child.kind() != "struct_item"
                {
                    extract_rust_constants_recursive(&child, source, constants);
                }
            }
        }
    }
}

fn extract_rust_const_or_static(node: &Node, source: &str, is_const: bool) -> Option<FieldInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))?;

    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));

    let visibility = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "visibility_modifier")
        .map(|n| {
            let text = get_node_text(&n, source);
            if text == "pub" {
                "public".to_string()
            } else {
                text
            }
        })
        .or_else(|| Some("private".to_string()));

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static: !is_const, // static items are is_static, const items are not (they're inlined)
        is_constant: true,
        visibility,
        line_number,
        line_end,
    })
}

/// Extract Go const declarations as module constants
fn extract_go_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "const_declaration" {
            let mut spec_cursor = child.walk();
            for spec in child.children(&mut spec_cursor) {
                if spec.kind() == "const_spec" {
                    if let Some(field) = extract_go_const_spec(&spec, source) {
                        constants.push(field);
                    }
                }
            }
        } else if child.kind() == "var_declaration" {
            // Go package-level var declarations: `var X = value` or `var ( ... )`
            // Single var: var_declaration -> var_spec (direct child)
            // Grouped var: var_declaration -> var_spec_list -> var_spec (nested)
            extract_go_var_specs(&child, source, &mut constants);
        }
    }
    constants
}

fn extract_go_const_spec(node: &Node, source: &str) -> Option<FieldInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))?;

    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));

    let visibility = if name
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        Some("public".to_string())
    } else {
        Some("private".to_string())
    };

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static: true,
        is_constant: true,
        visibility,
        line_number,
        line_end,
    })
}

/// Recursively extract var_spec nodes from a var_declaration or var_spec_list.
///
/// Handles both single `var X = value` (var_spec is a direct child of
/// var_declaration) and grouped `var ( ... )` (var_spec nodes are inside
/// a var_spec_list wrapper).
fn extract_go_var_specs(node: &Node, source: &str, constants: &mut Vec<FieldInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "var_spec" {
            if let Some(field) = extract_go_var_spec(&child, source) {
                constants.push(field);
            }
        } else if child.kind() == "var_spec_list" {
            // Grouped var block: recurse into the list
            extract_go_var_specs(&child, source, constants);
        }
    }
}

/// Extract a single Go var_spec as a FieldInfo.
///
/// Go var_spec AST structure (parallel to const_spec):
/// ```text
/// var_spec
///   name: identifier "ErrNotFound"
///   type: type_identifier? "error"
///   value: expression_list? (call_expression ...)
/// ```
fn extract_go_var_spec(node: &Node, source: &str) -> Option<FieldInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))?;

    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));

    let visibility = if name
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        Some("public".to_string())
    } else {
        Some("private".to_string())
    };

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static: true,
        is_constant: false, // var, not const
        visibility,
        line_number,
        line_end,
    })
}

/// Extract UPPER_CASE const declarations as TS/JS module constants
fn extract_ts_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "lexical_declaration" {
            // Check if it's a `const` declaration
            let text = get_node_text(&child, source);
            if text.starts_with("const ") {
                let mut decl_cursor = child.walk();
                for decl_child in child.children(&mut decl_cursor) {
                    if decl_child.kind() == "variable_declarator" {
                        let name = decl_child
                            .child_by_field_name("name")
                            .map(|n| get_node_text(&n, source));
                        if let Some(name) = name {
                            if is_upper_case_name(&name) {
                                let default_value = decl_child
                                    .child_by_field_name("value")
                                    .map(|n| get_node_text(&n, source));
                                let line_number = decl_child.start_position().row as u32 + 1;
                                let line_end = decl_child.end_position().row as u32 + 1;
                                constants.push(FieldInfo {
                                    name,
                                    field_type: None,
                                    default_value,
                                    is_static: true,
                                    is_constant: true,
                                    visibility: None,
                                    line_number,
                                    line_end,
                                });
                            }
                        }
                    }
                }
            }
        } else if child.kind() == "export_statement" {
            // Handle: export const X = ...
            let mut export_cursor = child.walk();
            for export_child in child.children(&mut export_cursor) {
                if export_child.kind() == "lexical_declaration" {
                    let text = get_node_text(&export_child, source);
                    if text.starts_with("const ") {
                        let mut decl_cursor = export_child.walk();
                        for decl_child in export_child.children(&mut decl_cursor) {
                            if decl_child.kind() == "variable_declarator" {
                                let name = decl_child
                                    .child_by_field_name("name")
                                    .map(|n| get_node_text(&n, source));
                                if let Some(name) = name {
                                    if is_upper_case_name(&name) {
                                        let default_value = decl_child
                                            .child_by_field_name("value")
                                            .map(|n| get_node_text(&n, source));
                                        let line_number =
                                            decl_child.start_position().row as u32 + 1;
                                        let line_end =
                                            decl_child.end_position().row as u32 + 1;
                                        constants.push(FieldInfo {
                                            name,
                                            field_type: None,
                                            default_value,
                                            is_static: true,
                                            is_constant: true,
                                            visibility: None,
                                            line_number,
                                            line_end,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    constants
}

/// Extract C module constants: `#define UPPER_CASE value` and `const type UPPER_CASE = value;`
fn extract_c_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    extract_c_cpp_module_constants(root, source, &["const"])
}

/// Extract C++ module constants: same as C plus `constexpr` declarations
fn extract_cpp_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    extract_c_cpp_module_constants(root, source, &["const", "constexpr"])
}

/// Shared extraction for C and C++ module constants.
///
/// Handles `#define UPPER_CASE value` and `declaration` nodes with const/constexpr qualifiers.
fn extract_c_cpp_module_constants(
    root: &Node,
    source: &str,
    const_qualifiers: &[&str],
) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "preproc_def" => {
                // #define NAME value -- children: #define, identifier, preproc_arg
                extract_preproc_def_constant(&child, source, &mut constants);
            }
            "declaration" => {
                // Check for a type_qualifier matching one of the allowed qualifiers
                let has_qualifier = {
                    let mut inner_cursor = child.walk();
                    let mut found = false;
                    for c in child.children(&mut inner_cursor) {
                        if c.kind() == "type_qualifier" {
                            let text = get_node_text(&c, source);
                            if const_qualifiers.contains(&text.as_str()) {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                if has_qualifier {
                    extract_c_const_declaration(&child, source, &mut constants);
                }
            }
            _ => {}
        }
    }
    constants
}

/// Extract an UPPER_CASE `#define` preprocessor constant
fn extract_preproc_def_constant(node: &Node, source: &str, constants: &mut Vec<FieldInfo>) {
    let mut inner_cursor = node.walk();
    let mut name = None;
    let mut default_value = None;
    for inner in node.children(&mut inner_cursor) {
        match inner.kind() {
            "identifier" => name = Some(get_node_text(&inner, source)),
            "preproc_arg" => default_value = Some(get_node_text(&inner, source).trim().to_string()),
            _ => {}
        }
    }
    if let Some(name) = name {
        if is_upper_case_name(&name) {
            let line_number = node.start_position().row as u32 + 1;
            let line_end = node.end_position().row as u32 + 1;
            constants.push(FieldInfo {
                name,
                field_type: None,
                default_value,
                is_static: true,
                is_constant: true,
                visibility: None,
                line_number,
                line_end,
            });
        }
    }
}

/// Extract name and value from a C/C++ `const`/`constexpr` declaration via init_declarator
fn extract_c_const_declaration(node: &Node, source: &str, constants: &mut Vec<FieldInfo>) {
    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    // Find init_declarator children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "init_declarator" {
            // Fields: declarator (identifier), value (literal)
            let name = child
                .child_by_field_name("declarator")
                .map(|n| get_node_text(&n, source));
            let default_value = child
                .child_by_field_name("value")
                .map(|n| get_node_text(&n, source));

            if let Some(name) = name {
                if is_upper_case_name(&name) {
                    let line_number = node.start_position().row as u32 + 1;
                    let line_end = node.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: field_type.clone(),
                        default_value,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
    }
}

/// Extract Ruby module constants: UPPER_CASE assignments at top level
///
/// In Ruby, constants are identifiers starting with uppercase. The tree-sitter
/// grammar uses `constant` node kind (vs `identifier` for lowercase).
fn extract_ruby_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "assignment" {
            // Left child is either `constant` (UPPER_CASE) or `identifier` (lowercase)
            let mut inner_cursor = child.walk();
            let mut left_node = None;
            let mut right_text = None;
            let mut seen_equals = false;
            for inner in child.children(&mut inner_cursor) {
                if !seen_equals && inner.kind() == "constant" {
                    left_node = Some(inner);
                } else if inner.kind() == "=" {
                    seen_equals = true;
                } else if seen_equals && right_text.is_none() {
                    right_text = Some(get_node_text(&inner, source));
                }
            }
            if let Some(left) = left_node {
                let name = get_node_text(&left, source);
                if is_upper_case_name(&name) {
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: None,
                        default_value: right_text,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
    }
    constants
}

/// Extract Kotlin module constants: `const val NAME`, `val UPPER_NAME`
///
/// AST: property_declaration > [modifiers("const")] [val/var] variable_declaration > simple_identifier
fn extract_kotlin_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "property_declaration" {
            let mut inner_cursor = child.walk();
            let mut is_val = false;
            let mut has_const_modifier = false;
            let mut name = None;
            let mut default_value = None;
            let mut seen_equals = false;

            for inner in child.children(&mut inner_cursor) {
                match inner.kind() {
                    "modifiers" => {
                        let mod_text = get_node_text(&inner, source);
                        if mod_text.contains("const") {
                            has_const_modifier = true;
                        }
                    }
                    "val" => is_val = true,
                    "variable_declaration" => {
                        // The variable_declaration contains an identifier child
                        let mut var_cursor = inner.walk();
                        for var_child in inner.children(&mut var_cursor) {
                            if var_child.kind() == "identifier"
                                || var_child.kind() == "simple_identifier"
                            {
                                name = Some(get_node_text(&var_child, source));
                            }
                        }
                    }
                    "=" => seen_equals = true,
                    _ => {
                        if seen_equals && default_value.is_none() {
                            default_value = Some(get_node_text(&inner, source));
                        }
                    }
                }
            }

            if let Some(name) = name {
                // Extract if: const val (explicit const), or val with UPPER_CASE name
                if has_const_modifier || (is_val && is_upper_case_name(&name)) {
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: None,
                        default_value,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
    }
    constants
}

/// Extract Swift module constants: `let UPPER_NAME = value`
///
/// AST: property_declaration > value_binding_pattern("let"/"var") + pattern > simple_identifier
fn extract_swift_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "property_declaration" {
            let mut inner_cursor = child.walk();
            let mut is_let = false;
            let mut name = None;
            let mut default_value = None;
            let mut seen_equals = false;

            for inner in child.children(&mut inner_cursor) {
                match inner.kind() {
                    "value_binding_pattern" => {
                        let text = get_node_text(&inner, source);
                        is_let = text == "let";
                    }
                    "pattern" => {
                        // Contains simple_identifier
                        let mut pat_cursor = inner.walk();
                        for pat_child in inner.children(&mut pat_cursor) {
                            if pat_child.kind() == "simple_identifier" {
                                name = Some(get_node_text(&pat_child, source));
                            }
                        }
                    }
                    "=" => seen_equals = true,
                    _ => {
                        if seen_equals && default_value.is_none() {
                            default_value = Some(get_node_text(&inner, source));
                        }
                    }
                }
            }

            if let Some(name) = name {
                if is_let && is_upper_case_name(&name) {
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: None,
                        default_value,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
    }
    constants
}

/// Extract C# module constants: `const type NAME = value;` at top-level
///
/// AST: global_statement > local_declaration_statement > modifier("const") +
///      variable_declaration > variable_declarator(name=identifier)
fn extract_csharp_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "global_statement" {
            // Look for local_declaration_statement with const modifier
            let mut stmt_cursor = child.walk();
            for stmt_child in child.children(&mut stmt_cursor) {
                if stmt_child.kind() == "local_declaration_statement" {
                    let has_const = {
                        let mut mod_cursor = stmt_child.walk();
                        let mut found = false;
                        for c in stmt_child.children(&mut mod_cursor) {
                            if c.kind() == "modifier" && get_node_text(&c, source).contains("const")
                            {
                                found = true;
                                break;
                            }
                        }
                        found
                    };
                    if has_const {
                        extract_csharp_const_from_declaration(&stmt_child, source, &mut constants);
                    }
                }
            }
        }
    }
    constants
}

/// Extract variable names from a C# local_declaration_statement with const modifier
fn extract_csharp_const_from_declaration(
    node: &Node,
    source: &str,
    constants: &mut Vec<FieldInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declaration" {
            let field_type = child
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source));

            let mut decl_cursor = child.walk();
            for decl_child in child.children(&mut decl_cursor) {
                if decl_child.kind() == "variable_declarator" {
                    let name = decl_child
                        .child_by_field_name("name")
                        .map(|n| get_node_text(&n, source));

                    if let Some(name) = name {
                        if is_upper_case_name(&name) {
                            // Get the value after the equals sign
                            let default_value = {
                                let mut val_cursor = decl_child.walk();
                                let mut found_eq = false;
                                let mut val = None;
                                for vc in decl_child.children(&mut val_cursor) {
                                    if vc.kind() == "=" {
                                        found_eq = true;
                                    } else if found_eq && val.is_none() {
                                        val = Some(get_node_text(&vc, source));
                                    }
                                }
                                val
                            };
                            let line_number = node.start_position().row as u32 + 1;
                            let line_end = node.end_position().row as u32 + 1;
                            constants.push(FieldInfo {
                                name,
                                field_type: field_type.clone(),
                                default_value,
                                is_static: true,
                                is_constant: true,
                                visibility: None,
                                line_number,
                                line_end,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Extract Scala module constants: `val UPPER_NAME = value` at top level
///
/// AST: val_definition > identifier + value, var_definition > identifier + value
fn extract_scala_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "val_definition" {
            // val_definition children: val, identifier, =, literal
            let mut inner_cursor = child.walk();
            let mut name = None;
            let mut default_value = None;
            let mut seen_equals = false;

            for inner in child.children(&mut inner_cursor) {
                match inner.kind() {
                    "identifier" if name.is_none() => {
                        name = Some(get_node_text(&inner, source));
                    }
                    "=" => seen_equals = true,
                    _ => {
                        if seen_equals && default_value.is_none() && inner.kind() != "val" {
                            default_value = Some(get_node_text(&inner, source));
                        }
                    }
                }
            }

            if let Some(name) = name {
                if is_upper_case_name(&name) {
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: None,
                        default_value,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
        // var_definition is mutable, so we skip it
    }
    constants
}

/// Extract PHP module constants: `const NAME = value;` and `define('NAME', value);`
///
/// AST: const_declaration > const_element > name; expression_statement > function_call_expression
fn extract_php_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "const_declaration" => {
                // const NAME = value;
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "const_element" {
                        let mut elem_cursor = inner.walk();
                        let mut name = None;
                        let mut default_value = None;
                        let mut seen_equals = false;
                        for elem in inner.children(&mut elem_cursor) {
                            match elem.kind() {
                                "name" => name = Some(get_node_text(&elem, source)),
                                "=" => seen_equals = true,
                                _ => {
                                    if seen_equals && default_value.is_none() {
                                        default_value = Some(get_node_text(&elem, source));
                                    }
                                }
                            }
                        }
                        if let Some(name) = name {
                            let line_number = child.start_position().row as u32 + 1;
                            let line_end = child.end_position().row as u32 + 1;
                            constants.push(FieldInfo {
                                name,
                                field_type: None,
                                default_value,
                                is_static: true,
                                is_constant: true,
                                visibility: None,
                                line_number,
                                line_end,
                            });
                        }
                    }
                }
            }
            "expression_statement" => {
                // define('NAME', value);
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "function_call_expression" {
                        let func_name = inner
                            .child_by_field_name("function")
                            .map(|n| get_node_text(&n, source));
                        if func_name.as_deref() == Some("define") {
                            if let Some(args) = inner.child_by_field_name("arguments") {
                                extract_php_define_call(&args, source, &mut constants, &child);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    constants
}

/// Extract name and value from a PHP define('NAME', value) call arguments
fn extract_php_define_call(
    args: &Node,
    source: &str,
    constants: &mut Vec<FieldInfo>,
    parent: &Node,
) {
    // Arguments: ( argument(string('NAME')) , argument(value) )
    let mut arg_cursor = args.walk();
    let mut first_arg = None;
    let mut second_arg = None;
    let mut arg_count = 0;
    for arg in args.children(&mut arg_cursor) {
        if arg.kind() == "argument" {
            match arg_count {
                0 => first_arg = Some(arg),
                1 => second_arg = Some(arg),
                _ => {}
            }
            arg_count += 1;
        }
    }

    if let Some(first) = first_arg {
        // The first argument should be a string containing the constant name
        let full_text = get_node_text(&first, source);
        // Strip quotes: 'NAME' or "NAME"
        let name = full_text
            .trim_matches(|c| c == '\'' || c == '"')
            .to_string();

        if !name.is_empty() {
            let default_value = second_arg.map(|a| get_node_text(&a, source));
            let line_number = parent.start_position().row as u32 + 1;
            let line_end = parent.end_position().row as u32 + 1;
            constants.push(FieldInfo {
                name,
                field_type: None,
                default_value,
                is_static: true,
                is_constant: true,
                visibility: None,
                line_number,
                line_end,
            });
        }
    }
}

/// Extract Lua module constants: UPPER_CASE assignments at top level
///
/// AST: assignment_statement > variable_list + expression_list
///      variable_declaration > local + assignment_statement
fn extract_lua_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "assignment_statement" => {
                // Top-level assignment: NAME = value
                extract_lua_constant_from_assignment(&child, source, &mut constants);
            }
            "variable_declaration" => {
                // local NAME = value
                // Contains assignment_statement as child
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "assignment_statement" {
                        extract_lua_constant_from_assignment(&inner, source, &mut constants);
                    }
                }
            }
            _ => {}
        }
    }
    constants
}

/// Extract a constant from a Lua assignment_statement if the LHS is UPPER_CASE
fn extract_lua_constant_from_assignment(node: &Node, source: &str, constants: &mut Vec<FieldInfo>) {
    let mut cursor = node.walk();
    let mut var_list = None;
    let mut expr_list = None;
    for child in node.children(&mut cursor) {
        match child.kind() {
            "variable_list" => var_list = Some(child),
            "expression_list" => expr_list = Some(child),
            _ => {}
        }
    }

    if let Some(vars) = var_list {
        let mut var_cursor = vars.walk();
        for var_child in vars.children(&mut var_cursor) {
            if var_child.kind() == "identifier" {
                let name = get_node_text(&var_child, source);
                if is_upper_case_name(&name) {
                    let default_value = expr_list.as_ref().map(|e| get_node_text(e, source));
                    let line_number = node.start_position().row as u32 + 1;
                    let line_end = node.end_position().row as u32 + 1;
                    constants.push(FieldInfo {
                        name,
                        field_type: None,
                        default_value,
                        is_static: true,
                        is_constant: true,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
    }
}

/// Extract Luau module constants: `local UPPER_NAME = value` at top level
///
/// Luau uses same AST as Lua: variable_declaration > local + assignment_statement
fn extract_luau_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    // Luau and Lua share the same AST structure for variable declarations
    extract_lua_module_constants(root, source)
}

/// Extract Elixir module constants: `@UPPER_NAME value` module attributes
///
/// AST: unary_operator(operator=@, operand=alias("UPPER_NAME"))
/// The value is the next sibling node.
fn extract_elixir_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let child_count = root.child_count();
    for i in 0..child_count {
        if let Some(child) = root.child(i) {
            if child.kind() == "unary_operator" {
                let operator = child.child_by_field_name("operator");
                let operand = child.child_by_field_name("operand");

                if let (Some(op), Some(name_node)) = (operator, operand) {
                    if get_node_text(&op, source) == "@" {
                        let name = get_node_text(&name_node, source);
                        if is_upper_case_name(&name) {
                            // The value is the next sibling
                            let default_value =
                                root.child(i + 1).map(|n| get_node_text(&n, source));
                            let line_number = child.start_position().row as u32 + 1;
                            let line_end = child.end_position().row as u32 + 1;
                            constants.push(FieldInfo {
                                name,
                                field_type: None,
                                default_value,
                                is_static: true,
                                is_constant: true,
                                visibility: None,
                                line_number,
                                line_end,
                            });
                        }
                    }
                }
            }
        }
    }
    constants
}

/// Extract OCaml module constants: `let UPPER_NAME = value` at top level
///
/// AST: value_definition > let_binding(pattern=constructor_path/value_name, body=expr)
/// UPPER_CASE names are parsed as constructor_path > constructor_name.
fn extract_ocaml_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut constants = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "value_definition" {
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "let_binding" {
                    // Only extract non-function bindings (no parameter children)
                    if ocaml_binding_has_params(&inner) {
                        continue;
                    }

                    // Get the pattern (name)
                    let name = inner
                        .child_by_field_name("pattern")
                        .map(|n| get_node_text(&n, source));

                    let default_value = inner
                        .child_by_field_name("body")
                        .map(|n| get_node_text(&n, source));

                    if let Some(name) = name {
                        if is_upper_case_name(&name) {
                            let line_number = child.start_position().row as u32 + 1;
                            let line_end = child.end_position().row as u32 + 1;
                            constants.push(FieldInfo {
                                name,
                                field_type: None,
                                default_value,
                                is_static: true,
                                is_constant: true,
                                visibility: None,
                                line_number,
                                line_end,
                            });
                        }
                    }
                }
            }
        }
    }
    constants
}

// =============================================================================
// TypeScript detailed extraction
// =============================================================================

/// (fix-T3-G3G2-args-v1, GAP 3 / Option 3A) Return true iff `node` is a
/// descendant of an `arguments` node — i.e. it sits inside a call's argument
/// list, e.g. `defineGetter(req, 'query', function query(){...})`.
///
/// Walking parents is purely structural (node.kind()); no source text is
/// inspected to make this decision.
fn ts_node_is_in_call_arguments(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "arguments" {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// (fix-T3-G3G2-args-v1, GAP 2 / Option 2B) If `assignment` is a
/// computed-member assignment whose LHS is a `subscript_expression` with an
/// `object:(identifier)` and an `index:(identifier)` and whose RHS is a
/// function-like node, emit ONE virtual/computed placeholder def keyed on the
/// object as `obj.[computed]`, WITHOUT resolving the dynamic index name.
///
/// A static string index (`obj["x"] = fn`, `index:(string)`) is NOT the
/// computed case and is intentionally left out of scope. The placeholder's
/// `.[computed]` suffix guarantees it can never collide with a bare method
/// name, so it cannot masquerade as a syntactic def or feed a bare-name
/// collapse. Callgraph LINKAGE for computed members (const/import propagation)
/// is out of scope — this records the def's existence only.
fn extract_ts_computed_member_assignment(
    assignment: &Node,
    source: &str,
    functions: &mut Vec<FunctionInfo>,
) {
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "subscript_expression" {
        return;
    }
    let Some(right) = assignment.child_by_field_name("right") else {
        return;
    };
    // RHS must be a function-like node. `generator_function` is included for
    // parity with the sibling arms (extract_assignment_function_name /
    // collect_definitions in callgraph/languages/typescript.rs) so that
    // `app[method] = function*(){}` also emits a placeholder.
    if !matches!(
        right.kind(),
        "arrow_function" | "function_expression" | "function" | "generator_function"
    ) {
        return;
    }
    // Object must be a bare identifier; index must be an identifier (dynamic
    // key). A `string` index is a static key and is out of scope.
    let Some(object) = left.child_by_field_name("object") else {
        return;
    };
    if object.kind() != "identifier" {
        return;
    }
    let Some(index) = left.child_by_field_name("index") else {
        return;
    };
    if index.kind() != "identifier" {
        return;
    }

    let obj_name = get_node_text(&object, source);
    if obj_name.is_empty() {
        return;
    }
    // Virtual placeholder name: `obj.[computed]`. The `.[computed]` marker is
    // not a valid bare identifier, so this can never create a false bare edge.
    let name = format!("{}.[computed]", obj_name);
    let line_number = assignment.start_position().row as u32 + 1;
    let line_end = assignment.end_position().row as u32 + 1;

    functions.push(FunctionInfo {
        name,
        params: Vec::new(),
        return_type: None,
        docstring: None,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        // Member-style assignment is an externally-visible binding shape.
        visibility: Some("public".to_string()),
        line_number,
        line_end,
        state_mutability: None,
    });
}

fn extract_ts_functions_detailed(
    node: &Node,
    source: &str,
    functions: &mut Vec<FunctionInfo>,
    is_method: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if !is_method {
                    let info = extract_ts_function_info(&child, source, false);
                    functions.push(info);
                }
            }
            "function_signature" => {
                // Ambient / declaration-only top-level functions in `.d.ts`
                // files: `export function f(): T;` (and bare
                // `declare function g(): U;`) parse as `function_signature`
                // (bodyless) rather than `function_declaration`. Previously
                // only `function_declaration` was handled at the top level, so
                // every ambient exported function was dropped (e.g. axios's
                // `index.d.ts` getAdapter/create/etc.). Emit them as top-level
                // functions; the node carries the same `name` field as a
                // `function_declaration`, so `extract_ts_function_info` resolves
                // the name and (empty) body correctly.
                if !is_method {
                    let info = extract_ts_function_info(&child, source, false);
                    if !info.name.is_empty() {
                        functions.push(info);
                    }
                }
            }
            "method_definition" | "method_signature" => {
                if is_method {
                    // (fix-T3-G4-overload-v1) TypeScript overload signatures.
                    // A `method_signature` — or a `method_definition` that
                    // lacks a `body` field — is a declaration-only entry. When
                    // an implementation sibling (a `method_definition` WITH a
                    // body) exists in this SAME class_body and shares the same
                    // (name, static?, accessor-kind) key, this declaration is
                    // a redundant overload signature and is suppressed so the
                    // single implementation is kept exactly once. Decision is
                    // purely structural (body-field presence + name/static/
                    // accessor match), never source-text heuristics.
                    if !ts_method_has_body(&child)
                        && ts_method_has_impl_sibling(node, &child, source)
                    {
                        continue;
                    }
                    let info = extract_ts_function_info(&child, source, true);
                    functions.push(info);
                } else if let Some(parent) = child.parent() {
                    // Object literal method shorthand: { foo() {} } — emit as
                    // a top-level function so consumers can find it via name.
                    // (js-extract-function-expressions-v1)
                    if parent.kind() == "object" {
                        let info = extract_ts_function_info(&child, source, false);
                        functions.push(info);
                    }
                }
            }
            "class_declaration" | "class" => {
                if is_method {
                    if let Some(body) = child.child_by_field_name("body") {
                        extract_ts_functions_detailed(&body, source, functions, true);
                    }
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                // Handle: const foo = () => {} or const foo = function() {}
                if !is_method {
                    extract_ts_variable_functions(&child, source, functions);
                }
                // Also recurse for nested declarations
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
            "export_statement" => {
                // Handle: export const foo = () => {} and export function foo() {}
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
            "function_expression" | "arrow_function" | "generator_function" => {
                // (fix-T3-G3G2-args-v1, GAP 3 / Option 3A) A NAMED function
                // expression passed as a call ARGUMENT — the Express
                // `defineGetter(req,'query',function query(){...})` getter
                // pattern — surfaces as a def keyed by its OWN name. The
                // named/anonymous split is self-enforcing: anonymous callbacks
                // have no `name` field, so the guard below excludes them.
                if !is_method
                    && child.child_by_field_name("name").is_some()
                    && ts_node_is_in_call_arguments(&child)
                {
                    let info = extract_ts_function_info(&child, source, false);
                    if !info.name.is_empty() {
                        functions.push(info);
                    }
                }
                // Recurse into the body for any nested definitions.
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
            "assignment_expression" => {
                // js-extract-function-expressions-v1: handle
                //   app.use = function() {}
                //   Foo.prototype.bar = function() {}
                //   handler = () => {}
                // and recurse for any nested function definitions in the RHS.
                if !is_method {
                    extract_ts_assignment_function(&child, source, functions);
                    // (fix-T3-G3G2-args-v1, GAP 2 / Option 2B) computed-member
                    // assignment `app[method] = fn` -> virtual `app.[computed]`
                    // placeholder (the regular extractor above skips subscript
                    // LHS because the name is dynamic).
                    extract_ts_computed_member_assignment(&child, source, functions);
                }
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
            "pair" => {
                // js-extract-function-expressions-v1: object literal pairs like
                //   { foo: function() {} }  or  { bar: () => {} }
                if !is_method {
                    extract_ts_pair_function(&child, source, functions);
                }
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
            _ => {
                extract_ts_functions_detailed(&child, source, functions, is_method);
            }
        }
    }
}

/// (js-extract-function-expressions-v1) Extract a function from an
/// `assignment_expression` whose right-hand side is a function-like node.
///
/// Supports:
/// - `name = function() {}` / `name = () => {}` (simple identifier LHS)
/// - `app.use = function use() {}` (member expression — uses last property)
/// - `Foo.prototype.bar = function() {}` (prototype assignment — uses last property)
///
/// Skips non-function RHS values silently and ignores subscript/computed LHS
/// (e.g., `app[name] = function() {}`) since the name is dynamic.
fn extract_ts_assignment_function(
    assignment: &Node,
    source: &str,
    functions: &mut Vec<FunctionInfo>,
) {
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return;
    };

    if !matches!(
        right.kind(),
        "arrow_function" | "function_expression" | "function"
    ) {
        return;
    }

    // Resolve the symbol name from the LHS, and capture whether the
    // assignment shape is a member-export pattern (which we treat as
    // public for is-public-visibility-v1 M-007).
    let mut is_member_export = false;
    let name = match left.kind() {
        "identifier" => get_node_text(&left, source),
        "member_expression" => {
            // For `app.use` use property "use"; for `Foo.prototype.bar`
            // also resolves to "bar" (the trailing property). Any
            // member-expression LHS (`obj.x = function () {}`, including
            // `exports.foo = ...` and `module.exports = ...`) signals
            // an externally-visible binding.
            is_member_export = true;
            match left.child_by_field_name("property") {
                Some(p) if p.kind() == "property_identifier" || p.kind() == "identifier" => {
                    get_node_text(&p, source)
                }
                _ => return,
            }
        }
        // subscript_expression (`app[name] = ...`) and other dynamic LHS
        // are skipped — the name is not statically resolvable.
        _ => return,
    };

    if name.is_empty() {
        return;
    }

    let params = extract_ts_arrow_params(&right, source);
    let return_type = right.child_by_field_name("return_type").map(|n| {
        get_node_text(&n, source)
            .trim_start_matches(':')
            .trim()
            .to_string()
    });
    let is_async = get_node_text(&right, source).starts_with("async");
    let line_number = assignment.start_position().row as u32 + 1;
    let line_end = assignment.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): member-export shape
    // (`app.foo = function () {}`, `exports.bar = function () {}`,
    // `module.exports = function () {}`) is treated as public.
    let visibility = if is_member_export {
        Some("public".to_string())
    } else {
        None
    };

    // Walk up through expression_statement / parenthesized_expression to
    // find a leading JSDoc comment.
    let docstring_anchor = assignment
        .parent()
        .filter(|p| p.kind() == "expression_statement")
        .unwrap_or(*assignment);
    let docstring = extract_jsdoc_docstring(&docstring_anchor, source);

    functions.push(FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: false,
        is_async,
        decorators: Vec::new(),
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    });
}

/// (js-resources-and-dead-fps-v1 F2) Return true iff `s` is shaped like a
/// JavaScript identifier — `[A-Za-z_$][A-Za-z0-9_$]*`. This is the ASCII
/// approximation used by the object-literal-pair extractor to filter
/// non-function string keys (MIME types, headers, URL fragments) out of
/// the dead-code analysis function set.
///
/// Identifiers in the full ECMAScript grammar additionally permit certain
/// Unicode categories (ID_Start / ID_Continue) and escape sequences; the
/// ASCII subset is strictly more conservative — it accepts every name a
/// runtime would also bind via plain `var`/`let`/`const`/function-name
/// declaration without unicode-escape rewriting, which covers the
/// real-world dead-code consumer surface.
fn is_js_identifier_shape(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '$') {
            return false;
        }
    }
    true
}

/// is-public-visibility-v1 (v0.4.2 M-007): JavaScript convention-based
/// visibility for a plain `function` declaration. Leading underscore =
/// private; otherwise unset (we leave `None` rather than asserting
/// `public` because JS has no language-level visibility for plain
/// functions and a top-level declaration may or may not be exported
/// — that determination requires whole-module export analysis).
fn js_name_visibility(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    if name.starts_with('_') {
        Some("private".to_string())
    } else {
        None
    }
}

/// (js-extract-function-expressions-v1) Extract a function from an object
/// literal `pair` whose value is a function-like node:
///   `{ foo: function() {} }` / `{ foo: () => {} }`
fn extract_ts_pair_function(pair: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let Some(value) = pair.child_by_field_name("value") else {
        return;
    };
    if !matches!(
        value.kind(),
        "arrow_function" | "function_expression" | "function"
    ) {
        return;
    }
    let Some(key) = pair.child_by_field_name("key") else {
        return;
    };
    let name = match key.kind() {
        "property_identifier" | "identifier" => get_node_text(&key, source),
        "string" => {
            // "foo": function() {} — strip surrounding quotes if present.
            let raw = get_node_text(&key, source);
            let unquoted = raw
                .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                .to_string();
            // js-resources-and-dead-fps-v1 F2: object-literal string keys are
            // legitimate function-name carriers ONLY when they shape like a
            // JavaScript identifier. Real-world FP class: MIME-type / header
            // / URL-fragment string keys passed to APIs like
            //   res.format({ "text/plain": function() {...},
            //                "application/json; q=0.5": function() {...} })
            // are content-negotiation handler entries, not named function
            // definitions. We filter those by requiring the unquoted key to
            // match the ASCII JavaScript identifier grammar
            // `[A-Za-z_$][A-Za-z0-9_$]*`. This preserves the legitimate
            // `{ "foo": function() {} }` case while rejecting
            // `text/plain`, `application/json`, `text/html; charset=utf-8`,
            // `image/svg+xml`, `with space`, `*/*`, etc.
            if !is_js_identifier_shape(&unquoted) {
                return;
            }
            unquoted
        }
        // computed_property_name has dynamic key — skip.
        _ => return,
    };
    if name.is_empty() {
        return;
    }

    let params = extract_ts_arrow_params(&value, source);
    let return_type = value.child_by_field_name("return_type").map(|n| {
        get_node_text(&n, source)
            .trim_start_matches(':')
            .trim()
            .to_string()
    });
    let is_async = get_node_text(&value, source).starts_with("async");
    let line_number = pair.start_position().row as u32 + 1;
    let line_end = pair.end_position().row as u32 + 1;

    functions.push(FunctionInfo {
        name,
        params,
        return_type,
        docstring: extract_jsdoc_docstring(pair, source),
        is_method: false,
        is_async,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    });
}

/// Extract functions from variable declarations with arrow function or function expression values.
/// Handles patterns like: `const foo = () => {}`, `const foo = function() {}`,
/// `export const foo = async () => {}`
fn extract_ts_variable_functions(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    // Extract docstring from the declaration node (JSDoc sits before the
    // lexical_declaration / variable_declaration, not the inner declarator).
    let decl_docstring = extract_jsdoc_docstring(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();

            if name.is_empty() {
                continue;
            }

            let value = child.child_by_field_name("value");
            if let Some(val) = value {
                let is_func = matches!(
                    val.kind(),
                    "arrow_function" | "function_expression" | "function"
                );
                if is_func {
                    let params = extract_ts_arrow_params(&val, source);
                    let return_type = val.child_by_field_name("return_type").map(|n| {
                        get_node_text(&n, source)
                            .trim_start_matches(':')
                            .trim()
                            .to_string()
                    });
                    let is_async = get_node_text(&val, source).starts_with("async")
                        || get_node_text(&child, source).starts_with("async");
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;

                    functions.push(FunctionInfo {
                        name,
                        params,
                        return_type,
                        docstring: decl_docstring.clone(),
                        is_method: false,
                        is_async,
                        decorators: Vec::new(),
                        visibility: None,
                        line_number,
                        line_end,
                        state_mutability: None,
                    });
                }
            }
        }
    }
}

/// Extract parameters from an arrow function or function expression node.
fn extract_ts_arrow_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "required_parameter" | "optional_parameter" => {
                    if let Some(pattern) = child.child_by_field_name("pattern") {
                        params.push(get_node_text(&pattern, source));
                    }
                }
                "identifier" => {
                    // Simple arrow function params: (x) => {} or x => {}
                    params.push(get_node_text(&child, source));
                }
                _ => {}
            }
        }
    } else if let Some(param) = node.child_by_field_name("parameter") {
        // Single-param arrow: x => {}
        params.push(get_node_text(&param, source));
    }

    params
}

/// (fix-T3-G4-overload-v1) True iff a TypeScript class member node owns a
/// method body. The tree-sitter-typescript grammar attaches the implementation
/// block under the `body` field (a `statement_block`) on `method_definition`;
/// `method_signature` nodes (overload declarations, ambient/`declare class`
/// members) have no `body` field. This is the structural discriminator between
/// an implementation and a declaration-only signature.
fn ts_method_has_body(node: &Node) -> bool {
    node.child_by_field_name("body").is_some()
}

/// (fix-T3-G4-overload-v1) True iff this class member is declared `static`. In
/// tree-sitter-typescript the `static` modifier is an anonymous child token of
/// kind `"static"` on the `method_definition` / `method_signature` node (not a
/// named field), so we scan the direct children for it.
fn ts_method_is_static(node: &Node) -> bool {
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        if c.kind() == "static" {
            return true;
        }
    }
    false
}

/// (fix-T3-G4-overload-v1) The accessor kind of a class member, if any:
/// `Some("get")` / `Some("set")` for accessors, `None` for a plain method. In
/// tree-sitter-typescript `get` / `set` appear as anonymous child tokens of
/// kind `"get"` / `"set"`. Accessor kind participates in the overload dedup key
/// so a `get x()` and `set x()` pair (same name) are never collapsed together.
fn ts_method_accessor_kind(node: &Node) -> Option<&'static str> {
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        match c.kind() {
            "get" => return Some("get"),
            "set" => return Some("set"),
            _ => {}
        }
    }
    None
}

/// (fix-T3-G4-overload-v1) True iff `class_body` contains an implementation
/// sibling (a member WITH a body) that shares the overload dedup key —
/// `(name, static?, accessor-kind)` — with the declaration-only `decl` node.
///
/// Scope is STRICTLY the direct children of the supplied `class_body` node, so
/// two classes in one file that each define a same-named method are never
/// collapsed across class boundaries. The accessor kind keeps `get`/`set`
/// distinct, and the static flag keeps a static overload from matching an
/// instance implementation (and vice versa). When no implementation sibling
/// exists (ambient / `declare class` / `.d.ts` declaration-only members) this
/// returns false and the declaration is retained.
fn ts_method_has_impl_sibling(class_body: &Node, decl: &Node, source: &str) -> bool {
    let decl_name = decl
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source));
    let Some(decl_name) = decl_name else {
        return false;
    };
    let decl_static = ts_method_is_static(decl);
    let decl_accessor = ts_method_accessor_kind(decl);

    let mut cursor = class_body.walk();
    for sibling in class_body.children(&mut cursor) {
        // Only `method_definition` nodes can carry an implementation body.
        if sibling.kind() != "method_definition" {
            continue;
        }
        // Skip the decl itself; an impl sibling is a different node.
        if sibling.id() == decl.id() {
            continue;
        }
        if !ts_method_has_body(&sibling) {
            continue;
        }
        let same_name = sibling
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source))
            .is_some_and(|n| n == decl_name);
        if !same_name {
            continue;
        }
        if ts_method_is_static(&sibling) != decl_static {
            continue;
        }
        if ts_method_accessor_kind(&sibling) != decl_accessor {
            continue;
        }
        return true;
    }
    false
}

fn extract_ts_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_ts_params(node, source);
    let return_type = node.child_by_field_name("return_type").map(|n| {
        get_node_text(&n, source)
            .trim_start_matches(':')
            .trim()
            .to_string()
    });

    let is_async = get_node_text(node, source).starts_with("async");
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): JavaScript has no
    // syntactic access modifier on plain `function` declarations.
    // Convention: identifiers leading with `_` are treated as private.
    // TypeScript class methods support `public`/`private`/`protected`
    // accessibility modifiers (see TS-specific class-body handling).
    let visibility = js_name_visibility(&name);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring: extract_jsdoc_docstring(node, source),
        is_method,
        is_async,
        decorators: Vec::new(),
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_ts_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "required_parameter" || child.kind() == "optional_parameter" {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    params.push(get_node_text(&pattern, source));
                }
            }
        }
    }

    params
}

/// Extract JSDoc comments (`/** */`) from preceding sibling nodes.
///
/// Walks up through wrapping constructs (export_statement, lexical_declaration)
/// to find the doc comment even when the declaration is nested.
fn extract_jsdoc_docstring(node: &Node, source: &str) -> Option<String> {
    let mut target = *node;
    for _ in 0..3 {
        if let Some(doc) = try_jsdoc_prev_sibling(&target, source) {
            return Some(doc);
        }
        if let Some(parent) = target.parent() {
            if matches!(
                parent.kind(),
                "export_statement"
                    | "lexical_declaration"
                    | "variable_declaration"
                    | "variable_declarator"
            ) {
                target = parent;
                continue;
            }
        }
        break;
    }
    None
}

/// Try to find a `/** */` JSDoc comment as the previous sibling of a node.
fn try_jsdoc_prev_sibling(node: &Node, source: &str) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() != "comment" {
        return None;
    }
    let text = get_node_text(&prev, source);
    if !text.starts_with("/**") {
        return None;
    }
    parse_block_doc_comment(&text)
}

fn extract_ts_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "class" | "interface_declaration" => {
                let info = extract_ts_class_info(&child, source);
                classes.push(info);
            }
            "type_alias_declaration" => {
                // Type aliases like `type Foo = string | number` are represented
                // as ClassInfo entries so the surface extractor can detect them via
                // `determine_ts_class_kind` and tag them as TypeAlias.
                let name = child
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source))
                    .unwrap_or_default();
                let line_number = child.start_position().row as u32 + 1;
                let line_end = child.end_position().row as u32 + 1;
                classes.push(ClassInfo {
                    name,
                    bases: Vec::new(),
                    docstring: extract_jsdoc_docstring(&child, source),
                    methods: Vec::new(),
                    fields: Vec::new(),
                    decorators: Vec::new(),
                    line_number,
                    line_end,
                    kind: None,
                    modifiers: Vec::new(),
                    events: Vec::new(),
                    errors: Vec::new(),
                });
            }
            _ => {
                extract_ts_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_ts_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_ts_functions_detailed(&body, source, &mut methods, true);
    }

    // Extract extends clause
    let mut bases = Vec::new();
    let mut c = node.walk();
    for child in node.children(&mut c) {
        if child.kind() == "class_heritage" {
            let text = get_node_text(&child, source);
            if text.starts_with("extends") {
                let base = text.trim_start_matches("extends").split_whitespace().next();
                if let Some(b) = base {
                    bases.push(b.to_string());
                }
            }
        }
    }

    // Extract class fields (Gap 3)
    let fields = if let Some(body) = node.child_by_field_name("body") {
        extract_ts_class_fields(&body, source)
    } else {
        Vec::new()
    };

    ClassInfo {
        name,
        bases,
        docstring: extract_jsdoc_docstring(node, source),
        methods,
        fields,
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

// =============================================================================
// Gap 3: TypeScript class field extraction
// =============================================================================

/// Extract fields from a TypeScript class body
/// Looks for public_field_definition and property-like nodes
fn extract_ts_class_fields(body: &Node, source: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        // TypeScript/JavaScript field definitions:
        // public_field_definition or property_definition (depending on grammar)
        match child.kind() {
            "public_field_definition" | "field_definition" => {
                if let Some(field) = extract_ts_field_from_definition(&child, source) {
                    fields.push(field);
                }
            }
            // Handle property_identifier with modifiers
            _ => {}
        }
    }
    fields
}

fn extract_ts_field_from_definition(node: &Node, source: &str) -> Option<FieldInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source));

    // Fallback: first identifier child
    let name = name.or_else(|| {
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if ch.kind() == "property_identifier" || ch.kind() == "identifier" {
                return Some(get_node_text(&ch, source));
            }
        }
        None
    })?;

    let field_type = node.child_by_field_name("type").map(|n| {
        let text = get_node_text(&n, source);
        text.trim_start_matches(':').trim().to_string()
    });

    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));

    // Check for static keyword
    let text = get_node_text(node, source);
    let is_static = text.starts_with("static ");

    // Check for visibility modifiers
    let visibility = if text.contains("private ") {
        Some("private".to_string())
    } else if text.contains("protected ") {
        Some("protected".to_string())
    } else {
        Some("public".to_string())
    };

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    let is_constant = is_static && is_upper_case_name(&name);

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static,
        is_constant,
        visibility,
        line_number,
        line_end,
    })
}

// =============================================================================
// Go detailed extraction
// =============================================================================

fn extract_go_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_declaration" {
            // Only top-level functions; method_declaration nodes are handled
            // by extract_go_methods_to_classes and associated with their receiver structs.
            let info = extract_go_function_info(&child, source);
            functions.push(info);
        }
        extract_go_functions_detailed(&child, source, functions);
    }
}

fn extract_go_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let is_method = node.kind() == "method_declaration";
    let params = extract_go_params(node, source);
    let return_type = node
        .child_by_field_name("result")
        .map(|n| get_node_text(&n, source));

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;
    let docstring = extract_go_docstring(node, source);

    // is-public-visibility-v1 (v0.4.2 M-007): Go uses idiomatic case-as-
    // visibility. An uppercase first letter exports the identifier from
    // the package; lowercase keeps it package-private. We materialize
    // the convention into an explicit `visibility` field so that
    // downstream consumers do not have to re-derive it from the name.
    let visibility = go_name_visibility(&name);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async: false,
        decorators: Vec::new(),
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// Extract Go doc comments from preceding sibling comment nodes.
///
/// Go doc comments are `//` line comments immediately preceding a declaration.
/// They are represented as `comment` sibling nodes in the tree-sitter Go grammar.
/// This function walks backwards from the given node collecting contiguous comment
/// siblings, then joins them with newlines after stripping the `// ` prefix.
fn extract_go_docstring(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();
    let mut comment_lines: Vec<String> = Vec::new();

    while let Some(prev_node) = prev {
        if prev_node.kind() == "comment" {
            let text = get_node_text(&prev_node, source);
            // Block comment: return immediately if no line comments collected yet
            if text.starts_with("/*") {
                if !comment_lines.is_empty() {
                    break;
                }
                // Strip /* and */ delimiters, trim whitespace
                let inner = text.trim_start_matches("/*").trim_end_matches("*/").trim();
                if inner.is_empty() {
                    return None;
                }
                return Some(inner.to_string());
            }
            // Line comment: strip "// " or "//" prefix
            if text.starts_with("//") {
                let stripped = text
                    .strip_prefix("// ")
                    .unwrap_or(text.strip_prefix("//").unwrap_or(&text));
                comment_lines.push(stripped.to_string());
            } else {
                break;
            }
            prev = prev_node.prev_sibling();
        } else {
            break;
        }
    }

    if comment_lines.is_empty() {
        None
    } else {
        comment_lines.reverse();
        Some(comment_lines.join("\n"))
    }
}

fn extract_go_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                // Go allows grouped parameters: `a, b, c int` produces a single
                // parameter_declaration with multiple identifier children as names.
                // child_by_field_name("name") only returns the first one, so we
                // iterate all children to collect every identifier (name).
                let mut inner_cursor = child.walk();
                let mut found_any = false;
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "identifier" {
                        params.push(get_node_text(&inner, source));
                        found_any = true;
                    }
                }
                // Fallback: if no identifier children found, try field_identifier
                // (used in some tree-sitter-go versions)
                if !found_any {
                    if let Some(name) = child.child_by_field_name("name") {
                        params.push(get_node_text(&name, source));
                    }
                }
            }
        }
    }

    params
}

// =============================================================================
// Gap 2+3: Go struct/interface extraction and method association
// =============================================================================

/// Extract Go struct and interface type declarations as ClassInfo, then
/// associate method_declaration nodes with their receiver types (two-pass).
///
/// Pass 1: Walk the AST for type_declaration nodes to find structs and interfaces.
///   - Structs become ClassInfo with empty methods (fields extracted).
///   - Interfaces become ClassInfo with methods extracted from method_spec nodes.
///
/// Pass 2: Walk the AST for method_declaration nodes (Go methods with receivers).
///   - Extract the receiver type (normalizing pointer receivers: *Server -> Server).
///   - Find or auto-vivify a ClassInfo for the receiver type.
///   - Add the method to its ClassInfo.methods.
fn extract_go_structs_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    // Pass 1: Extract structs and interfaces
    extract_go_types_pass1(node, source, classes);

    // Pass 2: Associate methods with receiver types
    extract_go_methods_to_classes(node, source, classes);
}

/// Pass 1: Extract Go struct and interface type declarations as ClassInfo.
fn extract_go_types_pass1(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_declaration" {
            // Doc comments are siblings of type_declaration, not type_spec
            let docstring = extract_go_docstring(&child, source);
            let mut spec_cursor = child.walk();
            for spec in child.children(&mut spec_cursor) {
                if spec.kind() == "type_spec" {
                    let name = spec
                        .child_by_field_name("name")
                        .map(|n| get_node_text(&n, source))
                        .unwrap_or_default();
                    let type_node = spec.child_by_field_name("type");
                    if let Some(tn) = type_node {
                        if tn.kind() == "struct_type" {
                            let line_number = spec.start_position().row as u32 + 1;
                            let line_end = spec.end_position().row as u32 + 1;
                            let fields = extract_go_struct_fields(&tn, source);
                            classes.push(ClassInfo {
                                name,
                                bases: Vec::new(),
                                docstring: docstring.clone(),
                                methods: Vec::new(),
                                fields,
                                decorators: Vec::new(),
                                line_number,
                                line_end,
                                kind: None,
                                modifiers: Vec::new(),
                                events: Vec::new(),
                                errors: Vec::new(),
                            });
                        } else if tn.kind() == "interface_type" {
                            let line_number = spec.start_position().row as u32 + 1;
                            let line_end = spec.end_position().row as u32 + 1;
                            let methods = extract_go_interface_methods(&tn, source);
                            classes.push(ClassInfo {
                                name,
                                bases: Vec::new(),
                                docstring: docstring.clone(),
                                methods,
                                fields: Vec::new(),
                                decorators: Vec::new(),
                                line_number,
                                line_end,
                                kind: None,
                                modifiers: Vec::new(),
                                events: Vec::new(),
                                errors: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Extract method signatures from a Go interface_type node.
///
/// Go interfaces contain method_spec nodes (method signatures without bodies):
/// ```text
/// interface_type
///   method_spec_list (or direct children)
///     method_spec
///       name: field_identifier "Handle"
///       parameters: parameter_list
///       result: ...
/// ```
fn extract_go_interface_methods(interface_node: &Node, source: &str) -> Vec<FunctionInfo> {
    let mut methods = Vec::new();
    // Walk all descendants looking for method_spec nodes
    extract_go_interface_methods_recursive(interface_node, source, &mut methods);
    methods
}

fn extract_go_interface_methods_recursive(
    node: &Node,
    source: &str,
    methods: &mut Vec<FunctionInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "method_elem" || child.kind() == "method_spec" {
            // The method name is a field_identifier child node.
            // Extract it by finding the first field_identifier.
            let mut name = String::new();
            let mut params = Vec::new();
            let mut return_type = None;
            let line_number = child.start_position().row as u32 + 1;
            let line_end = child.end_position().row as u32 + 1;

            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                match inner.kind() {
                    "field_identifier" => {
                        name = get_node_text(&inner, source);
                    }
                    "parameter_list" => {
                        // Extract parameter names from the parameter list
                        let mut param_cursor = inner.walk();
                        for param in inner.children(&mut param_cursor) {
                            if param.kind() == "parameter_declaration" {
                                if let Some(pname) = param.child_by_field_name("name") {
                                    params.push(get_node_text(&pname, source));
                                }
                            }
                        }
                    }
                    "type_identifier" | "qualified_type" | "pointer_type" | "slice_type"
                    | "map_type" | "channel_type" | "function_type" | "interface_type"
                    | "struct_type" | "parenthesized_type" => {
                        // This is the return type (simple single return)
                        return_type = Some(get_node_text(&inner, source));
                    }
                    _ => {}
                }
            }

            // Also check for result field (tuple return types)
            if return_type.is_none() {
                if let Some(result) = child.child_by_field_name("result") {
                    return_type = Some(get_node_text(&result, source));
                }
            }

            if !name.is_empty() {
                let visibility = go_name_visibility(&name);
                methods.push(FunctionInfo {
                    name,
                    params,
                    return_type,
                    docstring: extract_go_docstring(&child, source),
                    is_method: true,
                    is_async: false,
                    decorators: Vec::new(),
                    visibility,
                    line_number,
                    line_end,
                    state_mutability: None,
                });
            }
        } else {
            extract_go_interface_methods_recursive(&child, source, methods);
        }
    }
}

/// is-public-visibility-v1 (v0.4.2 M-007): Go uses case-as-visibility.
/// Returns `Some("public")` for names starting with an uppercase ASCII
/// letter, `Some("private")` for names starting with anything else, and
/// `None` for empty names.
fn go_name_visibility(name: &str) -> Option<String> {
    let first = name.chars().next()?;
    if first.is_ascii_uppercase() {
        Some("public".to_string())
    } else {
        Some("private".to_string())
    }
}

/// Pass 2: Walk the AST for method_declaration nodes, extract receiver type,
/// and associate each method with its receiver's ClassInfo.
///
/// If a receiver type has no matching ClassInfo (orphan method), a new ClassInfo
/// is auto-vivified for that type.
fn extract_go_methods_to_classes(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            let method_info = extract_go_function_info(&child, source);
            let receiver_type = extract_go_receiver_type(&child, source);

            if !receiver_type.is_empty() {
                // Find existing ClassInfo or auto-vivify
                if let Some(class) = classes.iter_mut().find(|c| c.name == receiver_type) {
                    class.methods.push(method_info);
                } else {
                    // Auto-vivify: method for type not defined in this file
                    classes.push(ClassInfo {
                        name: receiver_type,
                        bases: Vec::new(),
                        docstring: None,
                        methods: vec![method_info],
                        fields: Vec::new(),
                        decorators: Vec::new(),
                        line_number: 0, // Unknown, defined elsewhere
                        line_end: 0,
                        kind: None,
                        modifiers: Vec::new(),
                        events: Vec::new(),
                        errors: Vec::new(),
                    });
                }
            }
        }
        extract_go_methods_to_classes(&child, source, classes);
    }
}

/// Extract the receiver type from a Go method_declaration node.
///
/// Go method_declaration AST structure:
/// ```text
/// method_declaration
///   receiver: parameter_list
///     parameter_declaration
///       name: identifier "s"
///       type: pointer_type → type_identifier "Server"   (pointer receiver)
///       type: type_identifier "Server"                   (value receiver)
/// ```
///
/// Normalizes pointer receivers: `*Server` -> `Server`.
fn extract_go_receiver_type(method_node: &Node, source: &str) -> String {
    if let Some(receiver) = method_node.child_by_field_name("receiver") {
        let mut cursor = receiver.walk();
        for child in receiver.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                if let Some(type_node) = child.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    // Normalize: strip pointer prefix "*Server" -> "Server"
                    return type_text.trim_start_matches('*').to_string();
                }
            }
        }
    }
    String::new()
}

/// Extract fields from a Go struct_type node
fn extract_go_struct_fields(struct_node: &Node, source: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut cursor = struct_node.walk();
    for child in struct_node.children(&mut cursor) {
        if child.kind() == "field_declaration_list" {
            let mut field_cursor = child.walk();
            for field in child.children(&mut field_cursor) {
                if field.kind() == "field_declaration" {
                    let field_type = field
                        .child_by_field_name("type")
                        .map(|n| get_node_text(&n, source));

                    // Go allows multiple names per field_declaration: X, Y int
                    // Collect all field_identifier children as separate FieldInfo
                    let mut names = Vec::new();
                    let mut name_cursor = field.walk();
                    for fc in field.children(&mut name_cursor) {
                        if fc.kind() == "field_identifier" {
                            names.push(get_node_text(&fc, source));
                        }
                    }

                    let line_number = field.start_position().row as u32 + 1;
                    let line_end = field.end_position().row as u32 + 1;
                    for name in names {
                        let visibility = if name
                            .chars()
                            .next()
                            .map(|c| c.is_uppercase())
                            .unwrap_or(false)
                        {
                            Some("public".to_string())
                        } else {
                            Some("private".to_string())
                        };
                        fields.push(FieldInfo {
                            name,
                            field_type: field_type.clone(),
                            default_value: None,
                            is_static: false,
                            is_constant: false,
                            visibility,
                            line_number,
                            line_end,
                        });
                    }
                }
            }
        }
    }
    fields
}

// =============================================================================
// Rust detailed extraction
// =============================================================================

fn extract_rust_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_item" {
            // Only top-level functions
            if !is_inside_impl(&child) {
                let info = extract_rust_function_info(&child, source, false);
                functions.push(info);
            }
        }
        extract_rust_functions_detailed(&child, source, functions);
    }
}

fn extract_rust_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_rust_params(node, source);
    let return_type = node.child_by_field_name("return_type").map(|n| {
        get_node_text(&n, source)
            .trim_start_matches("->")
            .trim()
            .to_string()
    });

    let is_async = get_node_text(node, source).contains("async fn");
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;
    let decorators = extract_rust_function_attributes(node, source);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring: extract_rust_docstring(node, source),
        is_method,
        is_async,
        decorators,
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// Collect attributes ("decorators") that influence test-detection for a Rust function.
///
/// This walks `attribute_item` siblings preceding the function (e.g. `#[test]`,
/// `#[tokio::test]`, `#[cfg(test)]`, `#[rstest]`, `#[proptest]`) AND the chain of
/// enclosing `mod_item` ancestors. If any ancestor module is named `test`/`tests`/
/// `*test*` or carries a `#[cfg(test)]` attribute, a synthetic `cfg(test)` decorator
/// is appended so dead-code analysis can treat the inner function as test code.
fn extract_rust_function_attributes(node: &Node, source: &str) -> Vec<String> {
    let mut decorators: Vec<String> = Vec::new();

    // 1. Collect direct preceding `attribute_item` siblings (`#[test]`, etc.)
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {
                if let Some(s) = parse_rust_attribute_item(&p, source) {
                    decorators.push(s);
                }
                prev = p.prev_sibling();
            }
            "line_comment" | "block_comment" => {
                // Skip doc comments; attributes may be interleaved with them.
                prev = p.prev_sibling();
            }
            _ => break,
        }
    }

    // 2. Walk up the enclosing `mod_item` chain. If any module looks like a test
    //    module (by name or `#[cfg(test)]` attribute), surface that as a decorator.
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item" {
            let mod_name = parent
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();
            let lower = mod_name.to_lowercase();
            let name_says_test = lower == "test"
                || lower == "tests"
                || lower.starts_with("test_")
                || lower.ends_with("_test")
                || lower.ends_with("_tests")
                || lower.contains("testutil");
            if name_says_test {
                decorators.push(format!("cfg(test)/* via mod {mod_name} */"));
            }
            // Check for `#[cfg(test)]` on this module
            let mut mod_prev = parent.prev_sibling();
            while let Some(mp) = mod_prev {
                match mp.kind() {
                    "attribute_item" => {
                        if let Some(s) = parse_rust_attribute_item(&mp, source) {
                            if s.contains("cfg") && s.contains("test") {
                                decorators.push(s);
                            }
                        }
                        mod_prev = mp.prev_sibling();
                    }
                    "line_comment" | "block_comment" => {
                        mod_prev = mp.prev_sibling();
                    }
                    _ => break,
                }
            }
        }
        current = parent.parent();
    }

    decorators
}

/// Strip `#[ ... ]` wrapping from an `attribute_item` node, returning the inner text.
/// Returns lowercase-friendly normalized form preserving structural content like
/// `cfg(test)` or `tokio::test`.
fn parse_rust_attribute_item(node: &Node, source: &str) -> Option<String> {
    let raw = get_node_text(node, source);
    // Strip `#[` ... `]` (and `#![` ... `]` for inner attributes)
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix("#![")
        .or_else(|| trimmed.strip_prefix("#["))
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    let inner = inner.trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

fn extract_rust_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter" {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    params.push(get_node_text(&pattern, source));
                }
            } else if child.kind() == "self_parameter" {
                params.push(get_node_text(&child, source));
            }
        }
    }

    params
}

/// Extract Rust doc comments (`///` line comments or `/** */` blocks) from
/// preceding sibling nodes, skipping `#[...]` attribute items.
fn extract_rust_docstring(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();
    let mut comment_lines: Vec<String> = Vec::new();

    while let Some(prev_node) = prev {
        match prev_node.kind() {
            "line_comment" => {
                let text = get_node_text(&prev_node, source);
                if text.starts_with("///") {
                    let stripped = text
                        .strip_prefix("/// ")
                        .unwrap_or(text.strip_prefix("///").unwrap_or(&text));
                    comment_lines.push(stripped.to_string());
                } else {
                    break;
                }
            }
            "block_comment" => {
                let text = get_node_text(&prev_node, source);
                if text.starts_with("/**") {
                    if !comment_lines.is_empty() {
                        break;
                    }
                    return parse_block_doc_comment(&text);
                }
                break;
            }
            "attribute_item" => {
                // Skip #[...] attributes between doc comment and item
                prev = prev_node.prev_sibling();
                continue;
            }
            _ => break,
        }
        prev = prev_node.prev_sibling();
    }

    if comment_lines.is_empty() {
        None
    } else {
        comment_lines.reverse();
        Some(comment_lines.join("\n"))
    }
}

fn extract_rust_structs_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    // Two-pass approach (Gap 1):
    // Pass 1: Collect all struct/enum definitions
    // Pass 2: Walk impl blocks and associate methods with their target types

    // Pass 1: Collect structs and enums
    collect_rust_struct_defs(node, source, classes);

    // Build name -> index map for O(1) lookup during impl association
    let mut struct_map: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, class) in classes.iter().enumerate() {
        struct_map.entry(class.name.clone()).or_default().push(idx);
    }

    // Pass 2: Associate impl block methods with their target types
    associate_rust_impl_methods(node, source, classes, &struct_map);
}

/// Pass 1: Recursively collect struct/enum/trait definitions into ClassInfo entries
fn collect_rust_struct_defs(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "struct_item"
            || child.kind() == "enum_item"
            || child.kind() == "trait_item"
        {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();

            let line_number = child.start_position().row as u32 + 1;
            let line_end = child.end_position().row as u32 + 1;

            // Extract struct fields (Gap 3)
            let fields = if child.kind() == "struct_item" {
                extract_rust_struct_fields(&child, source)
            } else {
                Vec::new() // enum variants and trait items handled separately
            };

            // Extract methods declared directly in trait body (declaration_list)
            let methods = if child.kind() == "trait_item" {
                extract_methods_from_trait_body(&child, source)
            } else {
                Vec::new()
            };

            classes.push(ClassInfo {
                name,
                bases: Vec::new(),
                docstring: extract_rust_docstring(&child, source),
                methods,
                fields,
                decorators: Vec::new(),
                line_number,
                line_end,
                kind: None,
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            });
        }
        collect_rust_struct_defs(&child, source, classes);
    }
}

/// Extract method signatures from a trait body (`declaration_list`).
///
/// Trait methods can be either:
/// - `function_signature_item`: Declaration without body (e.g., `fn greet(&self) -> String;`)
/// - `function_item`: Default implementation (e.g., `fn default_greet(&self) -> String { ... }`)
fn extract_methods_from_trait_body(trait_node: &Node, source: &str) -> Vec<FunctionInfo> {
    let mut methods = Vec::new();
    let mut cursor = trait_node.walk();
    for child in trait_node.children(&mut cursor) {
        if child.kind() == "declaration_list" {
            let mut body_cursor = child.walk();
            for item in child.children(&mut body_cursor) {
                if item.kind() == "function_signature_item" || item.kind() == "function_item" {
                    if item.kind() == "function_item" {
                        let info = extract_rust_function_info(&item, source, true);
                        methods.push(info);
                    } else {
                        // function_signature_item: `fn greet(&self) -> String;`
                        let name = item
                            .child_by_field_name("name")
                            .map(|n| get_node_text(&n, source))
                            .unwrap_or_default();

                        let params = extract_rust_params(&item, source);
                        let return_type = item.child_by_field_name("return_type").map(|n| {
                            get_node_text(&n, source)
                                .trim_start_matches("->")
                                .trim()
                                .to_string()
                        });

                        let is_async = get_node_text(&item, source).contains("async fn");
                        let line_number = item.start_position().row as u32 + 1;
                        let line_end = item.end_position().row as u32 + 1;

                        methods.push(FunctionInfo {
                            name,
                            params,
                            return_type,
                            docstring: extract_rust_docstring(&item, source),
                            is_method: true,
                            is_async,
                            decorators: Vec::new(),
                            visibility: None,
                            line_number,
                            line_end,
                            state_mutability: None,
                        });
                    }
                }
            }
        }
    }
    methods
}

/// Pass 2: Walk all impl blocks and associate methods with matching ClassInfo (Gap 1)
fn associate_rust_impl_methods(
    node: &Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
    struct_map: &HashMap<String, Vec<usize>>,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "impl_item" {
            if let Some(type_name) = get_impl_type_name(&child, source) {
                // fix-R7-cl6-rust-trait-impl (v0.5.0 CLOSEOUT): tree-sitter-rust
                // exposes a `trait` field on `impl_item` ONLY for
                // `impl Trait for Type` (absent on an inherent `impl Type`).
                // This is the same authoritative signal the inheritance walker
                // uses (inheritance/rust.rs). A method defined inside a
                // trait-impl block (`fn eq` in `impl PartialEq for Glob`,
                // `fn deref` in `impl Deref for Tokens`) is dispatched through
                // the trait, not called by a free name — so dead-code analysis
                // must treat it as a trait method (it was flagged possibly_dead
                // because the receiver STRUCT is not a trait). Tag each such
                // method with a synthetic `"trait_impl"` decorator that
                // `collect_all_functions` (dead.rs) maps onto
                // `is_trait_method`.
                let is_trait_impl = child.child_by_field_name("trait").is_some();
                let methods = extract_methods_from_impl_body(&child, source, is_trait_impl);
                if let Some(indices) = struct_map.get(&type_name) {
                    // Associate with the first matching struct/enum
                    if let Some(&idx) = indices.first() {
                        classes[idx].methods.extend(methods);
                    }
                }
                // Orphan impls (no matching struct in file) are silently skipped
            }
        }
        associate_rust_impl_methods(&child, source, classes, struct_map);
    }
}

/// Extract the target type name from an impl block.
///
/// Handles:
/// - `impl Foo { ... }` -> "Foo"
/// - `impl Trait for Foo { ... }` -> "Foo" (the type, not the trait)
/// - `impl<T> Foo<T> { ... }` -> "Foo" (strips generic params)
/// - `impl std::fmt::Display for Foo { ... }` -> "Foo"
fn get_impl_type_name(impl_node: &Node, source: &str) -> Option<String> {
    let type_node = impl_node.child_by_field_name("type")?;

    match type_node.kind() {
        "type_identifier" => {
            // Simple case: `impl Foo { ... }` or `impl Trait for Foo { ... }`
            Some(get_node_text(&type_node, source))
        }
        "generic_type" => {
            // Generic case: `impl<T> Container<T> { ... }`
            // The type_identifier is nested under the "type" field of generic_type
            type_node
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source))
        }
        "scoped_type_identifier" => {
            // Scoped case: `impl some::module::Type { ... }`
            // Take the last segment (the actual type name)
            type_node
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
        }
        _ => {
            // Fallback: extract text and strip any generics
            let text = get_node_text(&type_node, source);
            let name = text.split('<').next().unwrap_or(&text).trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        }
    }
}

/// Extract all methods (FunctionInfo) from an impl block's body.
///
/// fix-R7-cl6-rust-trait-impl (v0.5.0 CLOSEOUT): when `is_trait_impl` is true
/// (the enclosing block is `impl Trait for Type`), each method is tagged with a
/// synthetic `"trait_impl"` decorator so downstream dead-code analysis treats it
/// as a trait method (dispatched, never directly named).
fn extract_methods_from_impl_body(
    impl_node: &Node,
    source: &str,
    is_trait_impl: bool,
) -> Vec<FunctionInfo> {
    let mut methods = Vec::new();

    if let Some(body) = impl_node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for item in body.children(&mut cursor) {
            if item.kind() == "function_item" {
                let mut info = extract_rust_function_info(&item, source, true);
                if is_trait_impl && !info.decorators.iter().any(|d| d == "trait_impl") {
                    info.decorators.push("trait_impl".to_string());
                }
                methods.push(info);
            }
        }
    }

    methods
}

// =============================================================================
// Gap 3: Rust struct field extraction
// =============================================================================

/// Extract fields from a Rust struct_item node
fn extract_rust_struct_fields(struct_node: &Node, source: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut cursor = struct_node.walk();
    for child in struct_node.children(&mut cursor) {
        if child.kind() == "field_declaration_list" {
            let mut field_cursor = child.walk();
            for field in child.children(&mut field_cursor) {
                if field.kind() == "field_declaration" {
                    let name = field
                        .child_by_field_name("name")
                        .map(|n| get_node_text(&n, source));
                    let field_type = field
                        .child_by_field_name("type")
                        .map(|n| get_node_text(&n, source));

                    if let Some(name) = name {
                        // Check for visibility modifier (pub, pub(crate), etc.)
                        let visibility = field
                            .children(&mut field.walk())
                            .find(|c| c.kind() == "visibility_modifier")
                            .map(|n| {
                                let text = get_node_text(&n, source);
                                if text == "pub" {
                                    "public".to_string()
                                } else {
                                    text
                                }
                            })
                            .or_else(|| Some("private".to_string()));

                        let line_number = field.start_position().row as u32 + 1;
                        let line_end = field.end_position().row as u32 + 1;
                        fields.push(FieldInfo {
                            name,
                            field_type,
                            default_value: None,
                            is_static: false,
                            is_constant: false,
                            visibility,
                            line_number,
                            line_end,
                        });
                    }
                }
            }
        }
    }
    fields
}

// =============================================================================
// Java detailed extraction
// =============================================================================

fn extract_java_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        // m007-m036-hubs-line-is-public-v1 (v0.4.2 M-113): also emit
        // `constructor_declaration` so that call-graph edges that resolve
        // `new Foo(...)` to `Foo` (or `Foo.Foo`) find a definition line
        // and visibility instead of silently dropping to `line: 0`.
        if child.kind() == "method_declaration" || child.kind() == "constructor_declaration" {
            let info = extract_java_function_info(&child, source);
            functions.push(info);
        }
        extract_java_functions_detailed(&child, source, functions);
    }
}

fn extract_java_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_java_params(node, source);
    let return_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): Java
    // `method_declaration` starts at its `modifiers` child for
    // annotation-decorated methods (`@Override`, `@Deprecated`).
    // Anchor to the first non-modifier child so the reported line is
    // the decl-keyword line, matching what `definition`/`references`
    // already do via forward-scan.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): Java method_declaration
    // nodes carry their access modifiers as a `modifiers` named child
    // (or as `public` / `private` / `protected` direct keyword
    // children, depending on tree-sitter-java grammar). Package-private
    // declarations have no modifier at all; we surface `None` in that
    // case rather than fabricating a value.
    let visibility = extract_java_visibility(node, source);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring: extract_java_docstring(node, source),
        is_method: true,
        is_async: false,
        decorators: Vec::new(),
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// is-public-visibility-v1 (v0.4.2 M-007): scan the `modifiers` child of
/// a Java method/constructor declaration for one of the access keywords.
/// Returns `None` for package-private (no modifier) declarations.
fn extract_java_visibility(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mcursor = child.walk();
            for m in child.children(&mut mcursor) {
                match m.kind() {
                    "public" => return Some("public".to_string()),
                    "private" => return Some("private".to_string()),
                    "protected" => return Some("protected".to_string()),
                    _ => {
                        // Some grammars expose modifiers as raw text inside
                        // a generic node; fall back to the keyword string.
                        let t = get_node_text(&m, source);
                        match t.as_str() {
                            "public" => return Some("public".to_string()),
                            "private" => return Some("private".to_string()),
                            "protected" => return Some("protected".to_string()),
                            _ => {}
                        }
                    }
                }
            }
        }
        // Older / partial grammars may place the keyword directly under
        // the declaration node rather than nested in `modifiers`.
        match child.kind() {
            "public" => return Some("public".to_string()),
            "private" => return Some("private".to_string()),
            "protected" => return Some("protected".to_string()),
            _ => {}
        }
    }
    None
}

fn extract_java_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "formal_parameter" {
                if let Some(name) = child.child_by_field_name("name") {
                    params.push(get_node_text(&name, source));
                }
            }
        }
    }

    params
}

/// Extract Javadoc comments (`/** */`) from preceding sibling nodes,
/// skipping annotation nodes (`marker_annotation`, `annotation`).
fn extract_java_docstring(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();
    while let Some(prev_node) = prev {
        match prev_node.kind() {
            "block_comment" | "comment" => {
                let text = get_node_text(&prev_node, source);
                if text.starts_with("/**") {
                    return parse_block_doc_comment(&text);
                }
                return None;
            }
            "marker_annotation" | "annotation" => {
                // Skip @Entity, @Override etc. between Javadoc and declaration
                prev = prev_node.prev_sibling();
                continue;
            }
            _ => return None,
        }
    }
    None
}

fn extract_java_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration"
            || child.kind() == "interface_declaration"
            || child.kind() == "enum_declaration"
            || child.kind() == "record_declaration"
        {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();

            // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002):
            // annotation-decorated classes (`@Entity public class Foo`)
            // would otherwise report the annotation line.
            let line_number = decl_keyword_line_from_node(&child);
            let line_end = child.end_position().row as u32 + 1;

            // Extract methods
            let mut methods = Vec::new();
            if let Some(body) = child.child_by_field_name("body") {
                extract_java_functions_detailed(&body, source, &mut methods);
            }

            // Extract extends/implements bases
            let bases = extract_java_class_bases(&child, source);

            // Extract class fields (Gap 3)
            let fields = if let Some(body) = child.child_by_field_name("body") {
                extract_java_class_fields(&body, source)
            } else {
                Vec::new()
            };

            classes.push(ClassInfo {
                name,
                bases,
                docstring: extract_java_docstring(&child, source),
                methods,
                fields,
                decorators: Vec::new(),
                line_number,
                line_end,
                kind: None,
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            });
        }
        extract_java_classes_detailed(&child, source, classes);
    }
}

/// Extract base class/interface names from a Java class/interface/enum/record declaration
fn extract_java_class_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();

    // Extract superclass (extends for classes)
    if let Some(superclass) = node.child_by_field_name("superclass") {
        extract_java_type_names(&superclass, source, &mut bases);
    }

    // Extract implements (for classes, enums, records)
    if let Some(interfaces) = node.child_by_field_name("interfaces") {
        extract_java_type_list(&interfaces, source, &mut bases);
    }

    // Extract extends for interfaces (extends_interfaces child node)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "extends_interfaces" {
            extract_java_type_list(&child, source, &mut bases);
        }
    }

    bases
}

/// Extract type names directly from a node's children
fn extract_java_type_names(node: &Node, source: &str, bases: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = extract_java_type_name(&child, source) {
            bases.push(name);
        }
    }
}

/// Extract types from a node containing a type_list child
fn extract_java_type_list(node: &Node, source: &str, bases: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_list" {
            let mut inner_cursor = child.walk();
            for type_child in child.children(&mut inner_cursor) {
                if let Some(name) = extract_java_type_name(&type_child, source) {
                    bases.push(name);
                }
            }
        } else if let Some(name) = extract_java_type_name(&child, source) {
            bases.push(name);
        }
    }
}

/// Extract a single type name, handling generics and scoped types
fn extract_java_type_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => Some(get_node_text(node, source)),
        "generic_type" => {
            // Generic<T> -> base type name only
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "type_identifier" => return Some(get_node_text(&child, source)),
                        "scoped_type_identifier" => return Some(get_node_text(&child, source)),
                        _ => {}
                    }
                }
            }
            None
        }
        "scoped_type_identifier" => Some(get_node_text(node, source)),
        _ => None,
    }
}

// =============================================================================
// Gap 3: Java class field extraction
// =============================================================================

/// Extract field declarations from a Java class body
fn extract_java_class_fields(body: &Node, source: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "field_declaration" {
            // field_declaration has modifiers, type, and declarator(s)
            let field_type = child
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source));

            // Check modifiers for static, final, visibility
            let text = get_node_text(&child, source);
            let is_static = text.contains("static ");
            let is_final = text.contains("final ");

            let visibility = if text.contains("private ") {
                Some("private".to_string())
            } else if text.contains("protected ") {
                Some("protected".to_string())
            } else if text.contains("public ") {
                Some("public".to_string())
            } else {
                Some("package".to_string())
            };

            // Extract each variable_declarator
            let mut decl_cursor = child.walk();
            for decl_child in child.children(&mut decl_cursor) {
                if decl_child.kind() == "variable_declarator" {
                    let name = decl_child
                        .child_by_field_name("name")
                        .map(|n| get_node_text(&n, source));

                    if let Some(name) = name {
                        let default_value = decl_child
                            .child_by_field_name("value")
                            .map(|n| get_node_text(&n, source));

                        let is_constant = is_static && is_final && is_upper_case_name(&name);
                        let line_number = child.start_position().row as u32 + 1;
                        let line_end = child.end_position().row as u32 + 1;

                        fields.push(FieldInfo {
                            name,
                            field_type: field_type.clone(),
                            default_value,
                            is_static,
                            is_constant,
                            visibility: visibility.clone(),
                            line_number,
                            line_end,
                        });
                    }
                }
            }
        }
    }
    fields
}

// =============================================================================
// Lua detailed extraction
// =============================================================================

fn extract_lua_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // Named function: `function foo() end` or `local function foo() end`.
                //
                // W2-lua-structure: SKIP table-qualified declarations
                // (`function M.new()` / `function M:greet()`). Those are
                // grouped into a `ClassInfo` by
                // `extract_lua_classes_detailed` and counting them here too
                // would double-count them (mirrors the Ruby
                // `extract_ruby_functions_detailed` skip of class methods).
                if !lua_function_decl_is_table_qualified(&child) {
                    let info = extract_lua_function_info(&child, source);
                    functions.push(info);
                }
            }
            "assignment_statement" => {
                // Check for: M.func = function() end
                extract_lua_assignment_functions(&child, source, functions);
            }
            "variable_declaration" => {
                // Check for: local myFunc = function() end
                // variable_declaration wraps an assignment_statement
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "assignment_statement" {
                        extract_lua_assignment_functions(&inner, source, functions);
                    }
                }
                // Do NOT recurse further -- the assignment_statement is fully handled above
            }
            _ => {
                extract_lua_functions_detailed(&child, source, functions);
            }
        }
    }
}

/// Extract a function from an assignment statement if the RHS is a function_definition.
/// Handles patterns like:
///   M.request = function(url) end        -- dot_index_expression LHS
///   myFunc = function(a, b) end          -- identifier LHS
fn extract_lua_assignment_functions(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    // Find the variable_list and expression_list children
    let mut var_list = None;
    let mut expr_list = None;
    let mut assign_cursor = node.walk();
    for child in node.children(&mut assign_cursor) {
        match child.kind() {
            "variable_list" => var_list = Some(child),
            "expression_list" => expr_list = Some(child),
            _ => {}
        }
    }

    let (var_list, expr_list) = match (var_list, expr_list) {
        (Some(v), Some(e)) => (v, e),
        _ => return,
    };

    // Check if RHS contains a function_definition
    let mut func_def = None;
    let mut el_cursor = expr_list.walk();
    for child in expr_list.children(&mut el_cursor) {
        if child.kind() == "function_definition" {
            func_def = Some(child);
            break;
        }
    }

    let func_def = match func_def {
        Some(f) => f,
        None => return,
    };

    // Extract the name from the LHS
    let name = extract_lua_lhs_name(&var_list, source);
    if name.is_empty() {
        return;
    }

    let params = extract_lua_params(&func_def, source);
    let docstring = extract_lua_docstring_before(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    functions.push(FunctionInfo {
        name,
        params,
        return_type: None, // Lua is dynamically typed
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    });
}

/// Extract the function name from the LHS of a Lua assignment.
/// For `M.request`, returns "request". For `myFunc`, returns "myFunc".
fn extract_lua_lhs_name(var_list: &Node, source: &str) -> String {
    let mut vl_cursor = var_list.walk();
    for child in var_list.children(&mut vl_cursor) {
        match child.kind() {
            "dot_index_expression" => {
                // M.request -> extract "request" from the field
                if let Some(field) = child.child_by_field_name("field") {
                    return get_node_text(&field, source);
                }
                // Fallback: take text after last '.'
                let text = get_node_text(&child, source);
                if let Some(name) = text.rsplit('.').next() {
                    return name.to_string();
                }
            }
            "bracket_index_expression" => {
                // t["key"] = function() end  /  method_handlers["textDocument/x"] = ...
                // The LHS uses a string (or other expression) subscript instead of
                // dot syntax. Build a qualified name `table["key"]` from the AST
                // `table` and `field` fields so the definition is uniquely named
                // and visible (matching how dotted handlers are qualified).
                let name = lua_bracket_index_name(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
            "identifier" => {
                return get_node_text(&child, source);
            }
            _ => {}
        }
    }
    String::new()
}

/// Build a qualified function name from a Lua `bracket_index_expression` LHS.
///
/// For `method_handlers["textDocument/completion"]` this returns
/// `method_handlers["textDocument/completion"]`. The node exposes `table` and
/// `field` fields (tree-sitter-lua); we read both directly from the AST rather
/// than slicing source text, so nested/whitespace forms are handled correctly.
fn lua_bracket_index_name(node: &Node, source: &str) -> String {
    let table = node.child_by_field_name("table");
    let field = node.child_by_field_name("field");

    let (table, field) = match (table, field) {
        (Some(t), Some(f)) => (t, f),
        _ => return String::new(),
    };

    let table_text = get_node_text(&table, source);
    let field_text = get_node_text(&field, source);
    if table_text.is_empty() || field_text.is_empty() {
        return String::new();
    }

    format!("{}[{}]", table_text, field_text)
}

fn extract_lua_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_lua_params(node, source);
    let docstring = extract_lua_docstring_before(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type: None, // Lua is dynamically typed
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

// =============================================================================
// W2-lua-structure (v0.5.0 AUDIT-FIX): Lua / Luau table-class extraction
// =============================================================================
//
// Lua has no `class` keyword — a "class" is a CONVENTION over tables +
// functions. The canonical idiom (verified against luvit/Roblox code and the
// tree-sitter-lua 0.2.0 / tree-sitter-luau 1.2.0 grammars, whose class-relevant
// node kinds are IDENTICAL):
//
//   local M = {}              -- receiver-defining anchor
//   M.__index = M            -- metatable self-index (class marker)
//   function M.new(...)       -- dot method  => name is `dot_index_expression`
//   function M:greet()        -- colon method => name is `method_index_expression`
//   M.VERSION = "1.0"        -- table field (non-function)
//
// We model each distinct table receiver that has at least one attached function
// declaration as ONE `ClassInfo{ kind: Some("table") }`, gathering its
// `function T.x` / `function T:x` declarations as `is_method=true` methods
// (dot => decorator "static", colon => decorator "method", mirroring how the
// Ruby precedent tags `singleton_method` with "self"). Receiver text comes from
// the `table` field of the name node — AST-driven, never source slicing.
//
// Anchoring: a receiver introduced by `local M = {}` / `M = {}` (optionally with
// `M.__index = M`) gets a stable `line_number` from that anchor site, so a
// colon-only class still reports the `local M = {}` line. Without an anchor we
// fall back to the first method's line.
//
// Fields: top-level `M.field = <non-function>` assignments plus constructor
// `self.x = ...` assignments inside the grouped methods (the Python
// `extract_python_self_assignments` precedent).
//
// A plain module/config table with NO attached functions is NOT emitted as a
// class — only receivers with >=1 method qualify. This keeps cohesion (Wave 3)
// honest: module tables are never misreported as classes.

/// True if a Lua/Luau `function_declaration` node's `name` field is a
/// `dot_index_expression` (`function T.m`) or `method_index_expression`
/// (`function T:m`) — i.e. the function is qualified by a table receiver and
/// therefore belongs to that table's `ClassInfo`, not the module-level
/// `functions` list.
fn lua_function_decl_is_table_qualified(node: &Node) -> bool {
    node.child_by_field_name("name")
        .map(|name| {
            matches!(
                name.kind(),
                "dot_index_expression" | "method_index_expression"
            )
        })
        .unwrap_or(false)
}

/// One in-progress Lua table-class being assembled during the AST walk.
struct LuaClassBuilder {
    name: String,
    /// Anchor line from `local M = {}` / `M = {}`; `None` until seen.
    anchor_line: Option<u32>,
    /// Last line covered by the class (max of anchor / method ends).
    line_end: u32,
    methods: Vec<FunctionInfo>,
    fields: Vec<FieldInfo>,
    /// Insertion order index so output is deterministic (first-seen order).
    order: usize,
}

/// Extract Lua/Luau table-classes from a parsed tree.
///
/// `language` selects the per-method param / return-type helpers (Luau carries
/// typed params + return types; Lua does not).
fn extract_lua_classes_detailed(
    root: &Node,
    source: &str,
    classes: &mut Vec<ClassInfo>,
    language: Language,
) {
    use std::collections::HashMap;

    let mut builders: HashMap<String, LuaClassBuilder> = HashMap::new();
    let mut next_order: usize = 0;

    // Pass 1: collect every table-qualified function declaration, grouped by
    // receiver. This is the authoritative signal that a table is a class.
    collect_lua_class_methods(root, source, language, &mut builders, &mut next_order);

    // Pass 2: anchors (`local M = {}` / `M = {}`) + `M.__index = M` markers +
    // top-level `M.field = <non-function>` fields. Only enrich receivers that
    // already qualified as classes in pass 1 (so plain module tables that
    // happen to share a name are never resurrected).
    collect_lua_class_anchors_and_fields(root, source, &mut builders);

    // Emit in first-seen order for deterministic output.
    let mut ordered: Vec<LuaClassBuilder> = builders.into_values().collect();
    ordered.sort_by_key(|b| b.order);

    for b in ordered {
        // A receiver only qualifies as a class if it has at least one attached
        // method. A bare `M.__index = ...` metatable marker (e.g.
        // `headerMeta.__index = function...`) alone is NOT a class — it is just
        // a metatable, so function-less tables are correctly excluded.
        if b.methods.is_empty() {
            continue;
        }

        let line_number = b
            .anchor_line
            .unwrap_or_else(|| b.methods.iter().map(|m| m.line_number).min().unwrap_or(0));
        let line_end = b
            .line_end
            .max(b.methods.iter().map(|m| m.line_end).max().unwrap_or(line_number));

        classes.push(ClassInfo {
            name: b.name,
            bases: Vec::new(),
            docstring: None,
            methods: b.methods,
            fields: b.fields,
            // Tag like Solidity's `kind: Some("contract")`: marks this as a
            // table-convention class rather than a native language class.
            decorators: Vec::new(),
            line_number,
            line_end,
            kind: Some("table".to_string()),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
        });
    }
}

/// Pass 1 walker: find `function T.m()` / `function T:m()` declarations and
/// group them under receiver `T`.
fn collect_lua_class_methods(
    node: &Node,
    source: &str,
    language: Language,
    builders: &mut std::collections::HashMap<String, LuaClassBuilder>,
    next_order: &mut usize,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declaration" {
            if let Some(name) = child.child_by_field_name("name") {
                if let Some((receiver, member, is_colon)) =
                    lua_split_qualified_name(&name, source)
                {
                    // `setmetatable(self, M)` constructors bind to `self`/`_`;
                    // never treat those as a class receiver.
                    if !receiver.is_empty()
                        && receiver != "self"
                        && receiver != "_"
                        && !member.is_empty()
                    {
                        let method = lua_build_method_info(&child, source, language, &member, is_colon);
                        let order = *next_order;
                        let entry = builders.entry(receiver.clone()).or_insert_with(|| {
                            *next_order += 1;
                            LuaClassBuilder {
                                name: receiver.clone(),
                                anchor_line: None,
                                line_end: 0,
                                methods: Vec::new(),
                                fields: Vec::new(),
                                order,
                            }
                        });
                        entry.line_end = entry.line_end.max(method.line_end);
                        // Constructor `self.x = ...` fields belong to the class.
                        collect_lua_self_fields(&child, source, &mut entry.fields);
                        entry.methods.push(method);
                    }
                }
            }
        }
        // Recurse so nested scopes (e.g. functions defined inside `do ... end`
        // blocks) are still discovered. function_declaration recursion is
        // harmless — its body has no further table-qualified declarations of
        // the same receivers in idiomatic code, and any that exist are real.
        collect_lua_class_methods(&child, source, language, builders, next_order);
    }
}

/// Split a `function_declaration` name node into (receiver, member, is_colon).
///
/// - `method_index_expression{ table, method }` => `function T:m` (colon).
/// - `dot_index_expression{ table, field }`      => `function T.m` (dot/static).
///
/// The receiver text is read from the `table` field directly (AST-driven). For a
/// simple `M` receiver the `table` is an `identifier`; for a nested
/// `a.b.c.m` we take the full dotted `table` text so distinct receivers stay
/// distinct. Returns `None` for a bare `identifier` name (plain function).
fn lua_split_qualified_name(name: &Node, source: &str) -> Option<(String, String, bool)> {
    match name.kind() {
        "method_index_expression" => {
            let table = name.child_by_field_name("table")?;
            let method = name.child_by_field_name("method")?;
            Some((
                get_node_text(&table, source),
                get_node_text(&method, source),
                true,
            ))
        }
        "dot_index_expression" => {
            let table = name.child_by_field_name("table")?;
            let field = name.child_by_field_name("field")?;
            Some((
                get_node_text(&table, source),
                get_node_text(&field, source),
                false,
            ))
        }
        _ => None,
    }
}

/// Build a `FunctionInfo` for a grouped class method, reusing the Luau-aware
/// param / return-type extractors when `language == Luau`.
fn lua_build_method_info(
    node: &Node,
    source: &str,
    language: Language,
    member: &str,
    is_colon: bool,
) -> FunctionInfo {
    let (params, return_type) = if matches!(language, Language::Luau) {
        (
            extract_luau_params(node, source),
            extract_luau_return_type(node, source),
        )
    } else {
        (extract_lua_params(node, source), None)
    };
    let docstring = extract_lua_docstring_before(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Colon form has an implicit `self`; tag "method". Dot form is a
    // static/constructor; tag "static" (mirrors Ruby's "self" tag on
    // singleton methods).
    let decorators = vec![if is_colon { "method" } else { "static" }.to_string()];

    FunctionInfo {
        name: member.to_string(),
        params,
        return_type,
        docstring,
        is_method: true,
        is_async: false,
        decorators,
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// Recursively collect `self.x = ...` assignments inside a method body into
/// `fields` (the Python `extract_python_self_assignments` precedent, adapted to
/// the Lua grammar: `assignment_statement` with a `dot_index_expression` LHS
/// whose `table` is `self`).
fn collect_lua_self_fields(node: &Node, source: &str, fields: &mut Vec<FieldInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "assignment_statement" {
            let mut ac = child.walk();
            let var_list = child
                .children(&mut ac)
                .find(|c| c.kind() == "variable_list");
            if let Some(var_list) = var_list {
                let mut vl = var_list.walk();
                for lhs in var_list.children(&mut vl) {
                    if lhs.kind() == "dot_index_expression" {
                        if let (Some(table), Some(field)) = (
                            lhs.child_by_field_name("table"),
                            lhs.child_by_field_name("field"),
                        ) {
                            if get_node_text(&table, source) == "self" {
                                let fname = get_node_text(&field, source);
                                if !fname.is_empty() && !fields.iter().any(|f| f.name == fname) {
                                    let line_number = child.start_position().row as u32 + 1;
                                    let line_end = child.end_position().row as u32 + 1;
                                    fields.push(FieldInfo {
                                        name: fname,
                                        field_type: None,
                                        default_value: None,
                                        is_static: false,
                                        is_constant: false,
                                        visibility: None,
                                        line_number,
                                        line_end,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        collect_lua_self_fields(&child, source, fields);
    }
}

/// Pass 2 walker: record receiver anchors (`local M = {}` / `M = {}`),
/// `M.__index = ...` markers, and top-level `M.field = <non-function>` fields,
/// but ONLY for receivers that already qualified as classes in pass 1.
fn collect_lua_class_anchors_and_fields(
    node: &Node,
    source: &str,
    builders: &mut std::collections::HashMap<String, LuaClassBuilder>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // `local M = {}` wraps an assignment_statement.
            "variable_declaration" => {
                let mut inner = child.walk();
                for ic in child.children(&mut inner) {
                    if ic.kind() == "assignment_statement" {
                        lua_record_anchor_or_field(&ic, source, builders);
                    }
                }
            }
            // `M = {}` / `M.__index = M` / `M.field = value`.
            "assignment_statement" => {
                lua_record_anchor_or_field(&child, source, builders);
            }
            _ => {}
        }
        collect_lua_class_anchors_and_fields(&child, source, builders);
    }
}

/// Inspect one `assignment_statement` for: a receiver anchor (`M = {}`), a
/// metatable marker (`M.__index = ...`), or a class field
/// (`M.field = <non-function>`). Mutates the matching builder if (and only if)
/// the receiver already qualified as a class in pass 1.
fn lua_record_anchor_or_field(
    assign: &Node,
    source: &str,
    builders: &mut std::collections::HashMap<String, LuaClassBuilder>,
) {
    let mut var_list = None;
    let mut expr_list = None;
    let mut c = assign.walk();
    for ch in assign.children(&mut c) {
        match ch.kind() {
            "variable_list" => var_list = Some(ch),
            "expression_list" => expr_list = Some(ch),
            _ => {}
        }
    }
    let (var_list, expr_list) = match (var_list, expr_list) {
        (Some(v), Some(e)) => (v, e),
        _ => return,
    };

    // Single LHS / RHS is the common idiom; multi-assign is rare for class
    // setup and intentionally ignored for anchors/fields.
    let lhs = var_list.named_child(0);
    let rhs = expr_list.named_child(0);
    let (lhs, rhs) = match (lhs, rhs) {
        (Some(l), Some(r)) => (l, r),
        _ => return,
    };

    match lhs.kind() {
        // `M = {}`  => anchor for receiver M (only if M is already a class).
        "identifier" => {
            if rhs.kind() == "table_constructor" {
                let name = get_node_text(&lhs, source);
                if let Some(b) = builders.get_mut(&name) {
                    let line = assign.start_position().row as u32 + 1;
                    b.anchor_line = Some(b.anchor_line.map_or(line, |a| a.min(line)));
                    b.line_end = b.line_end.max(assign.end_position().row as u32 + 1);
                }
            }
        }
        // `M.__index = ...`  (marker) or `M.field = <non-function>` (field).
        "dot_index_expression" => {
            if let (Some(table), Some(field)) = (
                lhs.child_by_field_name("table"),
                lhs.child_by_field_name("field"),
            ) {
                let receiver = get_node_text(&table, source);
                let field_name = get_node_text(&field, source);
                let b = match builders.get_mut(&receiver) {
                    Some(b) => b,
                    None => return,
                };
                b.line_end = b.line_end.max(assign.end_position().row as u32 + 1);

                if field_name == "__index" {
                    // Metatable self-index marker — not a data field. Recorded
                    // implicitly via the line_end bump above; nothing to store.
                    return;
                }
                // Skip function-valued RHS (`M.helper = function() end`) — that
                // is a method, already surfaced via the assignment-function
                // path; do not also record it as a field.
                if rhs.kind() == "function_definition" {
                    return;
                }
                if !field_name.is_empty() && !b.fields.iter().any(|f| f.name == field_name) {
                    let is_constant = is_upper_case_name(&field_name);
                    let default_value = Some(get_node_text(&rhs, source));
                    let line_number = assign.start_position().row as u32 + 1;
                    let line_end = assign.end_position().row as u32 + 1;
                    b.fields.push(FieldInfo {
                        name: field_name,
                        field_type: None,
                        default_value,
                        is_static: true,
                        is_constant,
                        visibility: None,
                        line_number,
                        line_end,
                    });
                }
            }
        }
        _ => {}
    }
}

fn extract_lua_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    params.push(get_node_text(&child, source));
                }
                "spread" | "vararg_expression" => {
                    // ... varargs
                    params.push("...".to_string());
                }
                _ => {}
            }
        }
    }

    params
}

/// Extract doc comment lines preceding a node.
/// Lua doc comments use `---` (LuaDoc) or `--` (regular comment).
/// We collect consecutive comment nodes immediately before the target node.
fn extract_lua_docstring_before(node: &Node, source: &str) -> Option<String> {
    let mut doc_lines = Vec::new();
    let mut prev = node.prev_sibling();
    // Track the row each collected comment starts on so we can reject a
    // comment that is separated from the function by a blank line (a blank
    // line is not an AST node, so adjacency must be checked via row numbers).
    let mut nearest_attached_row = node.start_position().row;

    // Walk backwards through consecutive comment siblings
    while let Some(sibling) = prev {
        if sibling.kind() == "comment" {
            let text = get_node_text(&sibling, source);

            // Luau mode pragmas (`--!nocheck`, `--!strict`, `--!nonstrict`,
            // `--!native`, `--!optimize`) are FILE-scope directives, not doc
            // comments. They sit at the top of the file, typically separated
            // from the first function by a blank line. Never treat them as a
            // docstring.
            let trimmed = text.trim_start();
            if trimmed.starts_with("--!") {
                break;
            }

            // Reject a comment that is not directly adjacent to the run of
            // comments already attached to the function (a blank-line gap means
            // a detached file-header / section comment, not this fn's doc).
            let comment_end_row = sibling.end_position().row;
            if comment_end_row + 1 < nearest_attached_row {
                break;
            }
            nearest_attached_row = sibling.start_position().row;

            doc_lines.push(text);
            prev = sibling.prev_sibling();
        } else {
            break;
        }
    }

    if doc_lines.is_empty() {
        return None;
    }

    // Reverse since we collected bottom-to-top
    doc_lines.reverse();

    // Clean up: strip leading --, ---, and whitespace
    let cleaned: Vec<String> = doc_lines
        .iter()
        .map(|line| {
            let stripped = line.trim();
            let stripped = stripped.strip_prefix("---").unwrap_or(stripped);
            let stripped = stripped.strip_prefix("--").unwrap_or(stripped);
            stripped.trim().to_string()
        })
        .collect();

    Some(cleaned.join("\n"))
}

// =============================================================================
// Luau detailed extraction
// =============================================================================

fn extract_luau_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // W2-lua-structure: SKIP table-qualified declarations
                // (`function T.m()` / `function T:m()`) — grouped into a
                // class by `extract_lua_classes_detailed`, so excluded here
                // to avoid double counting.
                if !lua_function_decl_is_table_qualified(&child) {
                    let info = extract_luau_function_info(&child, source);
                    functions.push(info);
                }
            }
            "assignment_statement" | "variable_assignment" => {
                extract_luau_assignment_functions(&child, source, functions);
            }
            "variable_declaration" => {
                // local myFunc = function() end
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "assignment_statement"
                        || inner.kind() == "variable_assignment"
                    {
                        extract_luau_assignment_functions(&inner, source, functions);
                    }
                }
                // Do NOT recurse further -- the assignment_statement is fully handled above
            }
            _ => {
                extract_luau_functions_detailed(&child, source, functions);
            }
        }
    }
}

/// Extract functions from Luau assignment statements (same pattern as Lua).
fn extract_luau_assignment_functions(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    // Find the variable_list / assignment_variable_list and expression_list
    let mut var_list = None;
    let mut expr_list = None;
    let mut assign_cursor = node.walk();
    for child in node.children(&mut assign_cursor) {
        match child.kind() {
            "variable_list" | "assignment_variable_list" | "binding_list" => var_list = Some(child),
            "expression_list" | "assignment_expression_list" => expr_list = Some(child),
            _ => {}
        }
    }

    let (var_list, expr_list) = match (var_list, expr_list) {
        (Some(v), Some(e)) => (v, e),
        _ => return,
    };

    // Check if RHS contains a function_definition
    let mut func_def = None;
    let mut el_cursor = expr_list.walk();
    for child in expr_list.children(&mut el_cursor) {
        if child.kind() == "function_definition" {
            func_def = Some(child);
            break;
        }
    }

    let func_def = match func_def {
        Some(f) => f,
        None => return,
    };

    let name = extract_lua_lhs_name(&var_list, source);
    if name.is_empty() {
        return;
    }

    let params = extract_luau_params(&func_def, source);
    let return_type = extract_luau_return_type(&func_def, source);
    let docstring = extract_lua_docstring_before(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    functions.push(FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    });
}

fn extract_luau_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_luau_params(node, source);
    let return_type = extract_luau_return_type(node, source);
    let docstring = extract_lua_docstring_before(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_luau_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    // Simple parameter without type annotation (fallback)
                    params.push(get_node_text(&child, source));
                }
                "parameter" => {
                    // Luau typed parameter: `name: Type`
                    // The first identifier child is the parameter name
                    let mut inner_cursor = child.walk();
                    for inner in child.children(&mut inner_cursor) {
                        if inner.kind() == "identifier" {
                            params.push(get_node_text(&inner, source));
                            break;
                        }
                    }
                }
                "spread" | "vararg_expression" => {
                    params.push("...".to_string());
                }
                _ => {}
            }
        }
    }

    params
}

/// Extract return type from a Luau function declaration.
/// In tree-sitter-luau, the return type appears as a `:` + type node
/// after the `parameters` node but before the `body` node.
fn extract_luau_return_type(node: &Node, source: &str) -> Option<String> {
    // Walk children: find `:` after parameters, then the next type node is the return type
    let mut found_params = false;
    let mut found_colon = false;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "parameters" {
            found_params = true;
            continue;
        }
        if found_params && child.kind() == ":" {
            found_colon = true;
            continue;
        }
        if found_colon && child.kind() != "block" && child.kind() != "end" {
            // This should be the return type node
            let type_text = get_node_text(&child, source).trim().to_string();
            if !type_text.is_empty() {
                return Some(type_text);
            }
        }
        if child.kind() == "block" || child.kind() == "end" {
            break;
        }
    }

    None
}

// =============================================================================
// Swift detailed extraction
// =============================================================================
//
fn extract_swift_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // Skip methods inside class/struct bodies -- those are handled
                // by extract_swift_classes_detailed
                if !is_inside_swift_type(&child) {
                    let info = extract_swift_function_info(&child, source, false);
                    functions.push(info);
                }
            }
            "class_declaration" | "struct_declaration" | "class_body" | "struct_body" => {
                // Don't recurse into class/struct bodies for top-level function extraction
            }
            _ => {
                extract_swift_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn extract_swift_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_swift_params(node, source);
    let return_type = extract_swift_return_type(node, source);
    let docstring = extract_swift_docstring_before(node, source);
    let is_async = get_node_text(node, source).contains("async ");
    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): Swift
    // `function_declaration` starts at its `attribute`/`modifiers`
    // children for `@inlinable`/`@available(...)` decorated funcs.
    // Anchor to the first non-attribute child.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): Swift allows
    // `public`/`open`/`internal`/`fileprivate`/`private` as
    // visibility_modifier children. The Swift default is `internal`,
    // but we keep `None` for unspecified declarations so consumers can
    // distinguish "explicit internal" from "default" if they wish.
    let visibility = extract_swift_visibility(node, source);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async,
        decorators: Vec::new(),
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// is-public-visibility-v1 (v0.4.2 M-007): Swift access modifiers.
/// `tree-sitter-swift` exposes these as either a `visibility_modifier`
/// named child or as the raw keyword inline before the `func` token.
fn extract_swift_visibility(node: &Node, source: &str) -> Option<String> {
    const KEYWORDS: &[&str] = &["public", "open", "internal", "fileprivate", "private"];

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" || child.kind() == "modifiers" {
            let mut mcursor = child.walk();
            for m in child.children(&mut mcursor) {
                let raw = get_node_text(&m, source);
                let raw = raw.trim();
                if KEYWORDS.contains(&raw) {
                    return Some(raw.to_string());
                }
                if m.kind() == "visibility_modifier" {
                    // Nested visibility_modifier — text is the keyword.
                    let nested = get_node_text(&m, source);
                    let nested = nested.trim();
                    if KEYWORDS.contains(&nested) {
                        return Some(nested.to_string());
                    }
                }
            }
            // The `visibility_modifier` node itself may carry the keyword as text.
            let raw = get_node_text(&child, source);
            let raw = raw.trim();
            if KEYWORDS.contains(&raw) {
                return Some(raw.to_string());
            }
        }
        // Some grammars place the keyword as a direct sibling token.
        let txt = get_node_text(&child, source);
        let txt = txt.trim();
        if KEYWORDS.contains(&txt) {
            return Some(txt.to_string());
        }
    }
    None
}

fn extract_swift_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    // Swift parameters are inside a parameter_clause or parameters node
    let params_node = node.child_by_field_name("parameters");

    let search_node = match params_node {
        Some(ref n) => n,
        None => {
            // Try to find parameter_clause child
            let mut cursor = node.walk();
            let mut found = None;
            for child in node.children(&mut cursor) {
                if child.kind() == "parameter_clause" || child.kind() == "parameter_list" {
                    found = Some(child);
                    break;
                }
            }
            match found {
                Some(ref _n) => {
                    // Extract params inline from the found node
                    let mut cursor2 = _n.walk();
                    for child in _n.children(&mut cursor2) {
                        if child.kind() == "parameter" {
                            let mut inner_cursor = child.walk();
                            for inner in child.children(&mut inner_cursor) {
                                if inner.kind() == "simple_identifier"
                                    || inner.kind() == "identifier"
                                {
                                    params.push(get_node_text(&inner, source));
                                    break;
                                }
                            }
                        }
                    }
                    return params;
                }
                None => return params,
            }
        }
    };

    let mut cursor = search_node.walk();
    for child in search_node.children(&mut cursor) {
        if child.kind() == "parameter" {
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "simple_identifier" || inner.kind() == "identifier" {
                    params.push(get_node_text(&inner, source));
                    break;
                }
            }
        }
    }

    params
}

fn extract_swift_return_type(node: &Node, source: &str) -> Option<String> {
    let mut found_arrow = false;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "->" || get_node_text(&child, source) == "->" {
            found_arrow = true;
            continue;
        }
        if found_arrow {
            let kind = child.kind();
            // The next meaningful node after -> should be the return type
            if kind == "type_identifier"
                || kind == "type_annotation"
                || kind == "simple_identifier"
                || kind == "user_type"
                || kind == "optional_type"
                || kind == "array_type"
                || kind == "dictionary_type"
                || kind == "tuple_type"
            {
                return Some(get_node_text(&child, source));
            }
            // If it's the function body, stop
            if kind == "function_body" || kind == "code_block" {
                break;
            }
        }
    }

    None
}

fn extract_swift_docstring_before(node: &Node, source: &str) -> Option<String> {
    let mut doc_lines = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        if sibling.kind() == "comment" || sibling.kind() == "multiline_comment" {
            let text = get_node_text(&sibling, source);
            doc_lines.push(text);
            prev = sibling.prev_sibling();
        } else {
            break;
        }
    }

    if doc_lines.is_empty() {
        return None;
    }

    doc_lines.reverse();

    let cleaned: Vec<String> = doc_lines
        .iter()
        .map(|line| {
            let stripped = line.trim();
            // Handle /// doc comments
            if let Some(rest) = stripped.strip_prefix("///") {
                return rest.trim().to_string();
            }
            // Handle /** */ block comments
            if stripped.starts_with("/**") && stripped.ends_with("*/") {
                let inner = &stripped[3..stripped.len() - 2];
                return inner.trim().to_string();
            }
            stripped.to_string()
        })
        .collect();

    Some(cleaned.join("\n"))
}

fn is_inside_swift_type(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_declaration"
            | "struct_declaration"
            | "class_body"
            | "struct_body"
            | "extension_declaration"
            | "protocol_declaration" => return true,
            _ => current = parent.parent(),
        }
    }
    false
}

fn extract_swift_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "struct_declaration" => {
                let info = extract_swift_class_info(&child, source);
                classes.push(info);
            }
            _ => {
                extract_swift_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_swift_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            // Fallback: look for type_identifier child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "type_identifier" || child.kind() == "simple_identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    let bases = extract_swift_bases(node, source);
    let docstring = extract_swift_docstring_before(node, source);
    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): anchor
    // to the first non-attribute child for `@objc class` etc.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from the body
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "class_body" || kind == "struct_body" || kind == "body" {
            let mut body_cursor = child.walk();
            for body_child in child.children(&mut body_cursor) {
                if body_child.kind() == "function_declaration" {
                    let info = extract_swift_function_info(&body_child, source, true);
                    methods.push(info);
                }
            }
        }
    }
    // Also check for body via field name
    if methods.is_empty() {
        if let Some(body) = node.child_by_field_name("body") {
            let mut body_cursor = body.walk();
            for body_child in body.children(&mut body_cursor) {
                if body_child.kind() == "function_declaration" {
                    let info = extract_swift_function_info(&body_child, source, true);
                    methods.push(info);
                }
            }
        }
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract base types (inheritance clause) from a Swift class/struct/enum/
/// protocol/extension declaration. Shared with `tldr interface` so both the
/// schema extractor and the interface command resolve the same bases.
pub fn extract_swift_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "inheritance_clause" || child.kind() == "type_inheritance_clause" {
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "type_identifier"
                    || inner.kind() == "user_type"
                    || inner.kind() == "simple_identifier"
                {
                    bases.push(get_node_text(&inner, source));
                }
                // Also check for inheritance_specifier wrapping type nodes
                if inner.kind() == "inheritance_specifier"
                    || inner.kind() == "annotated_inheritance_specifier"
                {
                    let mut spec_cursor = inner.walk();
                    for spec_child in inner.children(&mut spec_cursor) {
                        if spec_child.kind() == "type_identifier"
                            || spec_child.kind() == "user_type"
                            || spec_child.kind() == "simple_identifier"
                        {
                            bases.push(get_node_text(&spec_child, source));
                        }
                    }
                }
            }
        }
    }

    bases
}

// =============================================================================
// OCaml detailed extraction
// =============================================================================

fn extract_ocaml_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "value_definition" {
            // m114-adapter-tail-v1 (v0.4.2 M-114): tree-sitter-ocaml emits
            // a `value_definition` wrapper for BOTH top-level
            // `let f = ...` bindings (parented by `compilation_unit` /
            // `module_definition` / `module_binding`) AND inner
            // `let f = ... in body` bindings (parented by
            // `let_expression`). Without this guard the recursive walk
            // leaks inner let-in helpers as if they were top-level
            // definitions (e.g. `let helper z = ... in body` nested
            // inside another function would surface as a sibling
            // function on the file's `functions[]`). Only emit when the
            // parent is NOT `let_expression` — that's the AST shape
            // that distinguishes the let-in form from a true module-
            // level binding.
            let is_let_in = child
                .parent()
                .map(|p| p.kind() == "let_expression")
                .unwrap_or(false);
            if !is_let_in {
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "let_binding" {
                        // Only extract if it looks like a function (has parameters)
                        if ocaml_binding_has_params(&inner) {
                            let info = extract_ocaml_function_info(&inner, &child, source);
                            functions.push(info);
                        }
                    }
                }
            }
        }
        extract_ocaml_functions_detailed(&child, source, functions);
    }
}

/// Check whether an OCaml `let_binding` defines a FUNCTION (as opposed to a
/// plain value binding like `let all = [1; 2]`).
///
/// Two function shapes exist:
///   * Parameterised: `let f x y = ...` — has `parameter` children.
///   * Point-free: `let code = function | ... -> ...` (or `= fun x -> ...`) —
///     has NO `parameter` node, but its bound expression is a
///     `function_expression` / `fun_expression`. The previous params-only check
///     dropped these (e.g. dune's `exit_code.ml` `let code`/`let doc`).
///
/// Mirrors `ocaml_let_binding_is_function` in `extractor.rs` so the `extract`
/// and `structure` pipelines agree on what counts as an OCaml function.
fn ocaml_binding_has_params(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "parameter" => return true,
            // Point-free function bound directly to the name.
            "function_expression" | "fun_expression" => return true,
            _ => {}
        }
    }
    false
}

fn extract_ocaml_function_info(binding: &Node, definition: &Node, source: &str) -> FunctionInfo {
    // Name: the pattern field of the let_binding (value_name)
    let name = binding
        .child_by_field_name("pattern")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_ocaml_params(binding, source);
    let return_type = extract_ocaml_return_type(binding, source);
    let docstring = extract_ocaml_docstring_before(definition, source);
    let line_number = definition.start_position().row as u32 + 1;
    let line_end = definition.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_ocaml_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameter" {
            // Parameter can have:
            //   - value_pattern (simple: `x`)
            //   - typed_pattern (typed: `(x : int)`)
            // Look for the pattern field
            if let Some(pattern) = child.child_by_field_name("pattern") {
                match pattern.kind() {
                    "value_pattern" => {
                        params.push(get_node_text(&pattern, source));
                    }
                    "typed_pattern" => {
                        // Inside typed_pattern, the pattern field holds the value_pattern
                        if let Some(inner_pat) = pattern.child_by_field_name("pattern") {
                            params.push(get_node_text(&inner_pat, source));
                        } else {
                            // Fallback: first value_pattern or identifier child
                            let mut inner_cursor = pattern.walk();
                            for inner in pattern.children(&mut inner_cursor) {
                                if inner.kind() == "value_pattern" || inner.kind() == "value_name" {
                                    params.push(get_node_text(&inner, source));
                                    break;
                                }
                            }
                        }
                    }
                    "tuple_pattern" | "cons_pattern" | "unit" => {
                        // Complex patterns -- use the whole text
                        params.push(get_node_text(&pattern, source));
                    }
                    _ => {
                        params.push(get_node_text(&pattern, source));
                    }
                }
            } else {
                // No pattern field, try first child that's a value_pattern
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "value_pattern" || inner.kind() == "value_name" {
                        params.push(get_node_text(&inner, source));
                        break;
                    }
                }
            }
        }
    }

    params
}

/// Extract return type annotation from an OCaml let_binding.
/// Pattern: `let add (x : int) (y : int) : int = ...`
/// The `:` + type appears after all parameters and before `=`.
fn extract_ocaml_return_type(node: &Node, source: &str) -> Option<String> {
    // Walk children in order: look for `:` after the last parameter
    // and before `=`.
    let mut last_was_colon = false;
    let mut past_all_params = false;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let kind = child.kind();

        if kind == "parameter" {
            past_all_params = false; // Still have params
            last_was_colon = false;
            continue;
        }

        // After the last parameter
        if kind != "parameter" && !past_all_params {
            past_all_params = true;
        }

        if past_all_params && kind == ":" {
            last_was_colon = true;
            continue;
        }

        if last_was_colon && kind == "=" {
            // The colon was part of the binding, not a return type annotation
            return None;
        }

        if last_was_colon && kind != "=" {
            // This is the return type node
            let type_text = get_node_text(&child, source).trim().to_string();
            if !type_text.is_empty() {
                return Some(type_text);
            }
            last_was_colon = false;
        }

        if kind == "=" {
            break;
        }
    }

    None
}

/// Extract OCaml doc comment before a value_definition node.
/// OCaml doc comments use `(** ... *)` format.
fn extract_ocaml_docstring_before(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        if sibling.kind() == "comment" {
            let text = get_node_text(&sibling, source);
            let trimmed = text.trim();
            if trimmed.starts_with("(**") {
                // OCaml doc comment
                let inner = trimmed
                    .strip_prefix("(**")
                    .and_then(|s| s.strip_suffix("*)"))
                    .unwrap_or(trimmed);
                return Some(inner.trim().to_string());
            }
            // Regular comment, keep looking
            prev = sibling.prev_sibling();
        } else {
            break;
        }
    }

    None
}

// =============================================================================
// Call graph building
// =============================================================================

fn build_intra_file_call_graph(
    tree: &Tree,
    source: &str,
    language: Language,
    functions: &[FunctionInfo],
    classes: &[ClassInfo],
) -> IntraFileCallGraph {
    let mut calls: HashMap<String, Vec<String>> = HashMap::new();
    let mut called_by: HashMap<String, Vec<String>> = HashMap::new();

    // Build set of known function and class names
    let known_functions: std::collections::HashSet<String> = functions
        .iter()
        .map(|f| f.name.clone())
        .chain(classes.iter().map(|c| c.name.clone()))
        .chain(
            classes
                .iter()
                .flat_map(|c| c.methods.iter().map(|m| m.name.clone())),
        )
        .collect();

    let root = tree.root_node();

    // Extract calls from each function
    for func in functions {
        let func_calls =
            extract_calls_in_function(&root, source, &func.name, &known_functions, language);
        if !func_calls.is_empty() {
            calls.insert(func.name.clone(), func_calls.clone());
            for callee in func_calls {
                called_by.entry(callee).or_default().push(func.name.clone());
            }
        }
    }

    // Extract calls from each method
    for class in classes {
        for method in &class.methods {
            let method_calls =
                extract_calls_in_function(&root, source, &method.name, &known_functions, language);
            if !method_calls.is_empty() {
                calls.insert(method.name.clone(), method_calls.clone());
                for callee in method_calls {
                    called_by
                        .entry(callee)
                        .or_default()
                        .push(method.name.clone());
                }
            }
        }
    }

    // For class-based languages (Java, Kotlin-via-flatten, …) the SAME method
    // appears in BOTH `functions[]` and `classes[].methods[]`, so the two loops
    // above push each caller into `called_by` twice. Forward `calls` uses
    // `.insert()` so it overwrites and stays clean, but `called_by` accumulates
    // — duplicating every caller. Dedup each list while PRESERVING first-seen
    // order so the reverse call graph reports each caller exactly once.
    for callers in called_by.values_mut() {
        let mut seen = std::collections::HashSet::new();
        callers.retain(|c| seen.insert(c.clone()));
    }

    IntraFileCallGraph { calls, called_by }
}

fn extract_calls_in_function(
    root: &Node,
    source: &str,
    function_name: &str,
    known_functions: &std::collections::HashSet<String>,
    language: Language,
) -> Vec<String> {
    let mut calls = Vec::new();

    // Find the function node and extract calls from it
    find_and_extract_calls(
        root,
        source,
        function_name,
        known_functions,
        &mut calls,
        language,
    );

    calls.sort();
    calls.dedup();
    calls
}

fn find_and_extract_calls(
    node: &Node,
    source: &str,
    target_name: &str,
    known_functions: &std::collections::HashSet<String>,
    calls: &mut Vec<String>,
    language: Language,
) {
    let func_kinds: &[&str] = match language {
        Language::Python => &["function_definition"],
        Language::TypeScript | Language::JavaScript => {
            &["function_declaration", "method_definition"]
        }
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Rust => &["function_item"],
        Language::Java => &["method_declaration"],
        _ => &[],
    };

    // Use cursor-based tree walk to find ALL functions matching the target name.
    // When multiple classes define methods with the same name, we must extract
    // calls from ALL of them (their calls get merged into one entry).
    let mut cursor = node.walk();
    let mut reached_root = false;
    loop {
        let walk_node = cursor.node();

        let is_matching_func = if func_kinds.contains(&walk_node.kind()) {
            // Standard function/method declaration
            walk_node
                .child_by_field_name("name")
                .is_some_and(|n| get_node_text(&n, source) == target_name)
        } else if walk_node.kind() == "variable_declarator" {
            // Arrow function or function expression: const foo = () => {}
            let name_matches = walk_node
                .child_by_field_name("name")
                .is_some_and(|n| get_node_text(&n, source) == target_name);
            let has_func_value = walk_node.child_by_field_name("value").is_some_and(|v| {
                matches!(
                    v.kind(),
                    "arrow_function" | "function_expression" | "function"
                )
            });
            name_matches && has_func_value
        } else {
            false
        };

        if is_matching_func {
            // Found a matching function, extract calls from its body
            extract_call_expressions(&walk_node, source, known_functions, calls, language);
            // Do NOT return early -- continue searching for other
            // functions with the same name (e.g., same-named methods
            // in different classes). Skip children of this function
            // to avoid re-processing.
            if !cursor.goto_next_sibling() {
                loop {
                    if !cursor.goto_parent() {
                        reached_root = true;
                        break;
                    }
                    if cursor.goto_next_sibling() {
                        break;
                    }
                }
                if reached_root {
                    break;
                }
            }
            continue;
        }

        // Advance cursor: depth-first traversal
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                reached_root = true;
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
        if reached_root {
            break;
        }
    }
}

fn extract_call_expressions(
    node: &Node,
    source: &str,
    known_functions: &std::collections::HashSet<String>,
    calls: &mut Vec<String>,
    language: Language,
) {
    let call_kinds: &[&str] = match language {
        Language::Python => &["call"],
        Language::TypeScript | Language::JavaScript => &["call_expression"],
        Language::Go => &["call_expression"],
        Language::Rust => &["call_expression"],
        Language::Java => &["method_invocation"],
        _ => &[],
    };

    // Use cursor-based tree walk to visit ALL descendant nodes.
    // This is more robust than recursive children iteration and ensures
    // no nodes are missed inside conditional branches, loops, try/except,
    // match statements, comprehensions, or any other nested structure.
    let mut cursor = node.walk();
    let mut reached_root = false;
    loop {
        let walk_node = cursor.node();

        if call_kinds.contains(&walk_node.kind()) {
            // Get the function name being called
            let callee_name = match language {
                Language::Python => walk_node
                    .child_by_field_name("function")
                    .map(|n| get_node_text(&n, source)),
                Language::TypeScript | Language::JavaScript | Language::Go => walk_node
                    .child_by_field_name("function")
                    .map(|n| get_node_text(&n, source)),
                Language::Rust => walk_node
                    .child_by_field_name("function")
                    .map(|n| get_node_text(&n, source)),
                Language::Java => walk_node
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source)),
                _ => None,
            };

            if let Some(callee) = callee_name {
                // For cross-file call detection, we need ALL calls, not just local ones.
                // Include the full callee name (e.g., "module.func") for cross-file resolution,
                // and also the simple name for intra-file matching.
                let simple_name = callee.split('.').next_back().unwrap_or(&callee).to_string();
                if known_functions.contains(&simple_name) {
                    // Local function call - use simple name
                    calls.push(simple_name);
                } else {
                    // Potentially cross-file call - preserve full callee name for resolution
                    calls.push(callee.to_string());
                }
            }
        }

        // Advance cursor: depth-first traversal
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        // Walk back up until we can go to a sibling
        loop {
            if !cursor.goto_parent() {
                reached_root = true;
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
        if reached_root {
            break;
        }
    }
}

// =============================================================================
// Helper functions
// =============================================================================

fn get_node_text(node: &Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

fn extract_string_content(node: &Node, source: &str) -> String {
    let text = get_node_text(node, source);
    // Remove string delimiters
    text.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim_matches('"')
        .to_string()
}

fn is_inside_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_definition" | "class_declaration" | "class" | "class_body" => return true,
            _ => current = parent.parent(),
        }
    }
    false
}

fn is_inside_impl(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "impl_item" {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn has_async_keyword(node: &Node, source: &str) -> bool {
    get_node_text(node, source).starts_with("async")
}

// =============================================================================
// C detailed extraction
// =============================================================================

fn extract_c_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_definition" {
            let info = extract_c_function_info(&child, source);
            functions.push(info);
        }
        extract_c_functions_detailed(&child, source, functions);
    }
}

fn extract_c_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = extract_c_function_name(node, source).unwrap_or_default();

    let params = extract_c_params(node, source);
    let return_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let docstring = extract_c_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// Extract function name from C/C++ function_definition node.
/// Handles: `int foo(...)`, `void *foo(...)`, `int (*foo)(...)` patterns.
/// AST: function_definition -> declarator (function_declarator) -> declarator (identifier)
/// May have pointer_declarator wrapping the identifier.
fn extract_c_function_name(node: &Node, source: &str) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;

    if declarator.kind() == "function_declarator" {
        return extract_name_from_function_declarator(&declarator, source);
    }

    // Sometimes the declarator is a pointer_declarator wrapping a function_declarator
    if declarator.kind() == "pointer_declarator" {
        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                return extract_name_from_function_declarator(&child, source);
            }
        }
    }

    // Fallback: declarator is directly an identifier (rare)
    if declarator.kind() == "identifier" {
        return Some(get_node_text(&declarator, source));
    }

    None
}

/// Extract the identifier name from a function_declarator node.
///
/// Handles the C and C++ tree-sitter grammars' declarator chains.
/// For plain C: `int foo(...)` -> declarator is `identifier`.
/// For C with pointer: `void *get_ptr(...)` -> `pointer_declarator(identifier)`.
/// For C++ inline class methods: `void bar() {}` inside a class body emits
/// `field_identifier` (NOT `identifier`) — cpp-method-name-extraction-v1.
/// For C++ out-of-class definitions: `void Foo::bar() {}` emits
/// `qualified_identifier` (we extract the unqualified `name` field so the
/// returned name matches the inline-method form, which is what overload
/// distinction and `methods: [String]` consumers expect).
/// For C++ destructors: `~Foo()` -> `destructor_name`.
/// For C++ operators: `operator+()` -> `operator_name`.
fn extract_name_from_function_declarator(func_decl: &Node, source: &str) -> Option<String> {
    let name_node = func_decl.child_by_field_name("declarator")?;
    extract_name_from_declarator_inner(&name_node, source)
}

/// Recursively unwrap a declarator chain to find the leaf identifier.
/// Walks through `pointer_declarator` / `reference_declarator` wrappers
/// (e.g., `*get_ptr`, `&value`) and resolves C++ qualified / destructor /
/// operator names. Returns `None` if the chain bottoms out on something
/// we don't recognise (caller substitutes "" — see `extract_c_function_name`).
fn extract_name_from_declarator_inner(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        // Plain identifier (C functions, parameter names).
        "identifier" => Some(get_node_text(node, source)),
        // C++ class/struct member declarator (inline method bodies).
        // tree-sitter-cpp 0.23.x emits `field_identifier` here, not `identifier`.
        "field_identifier" => Some(get_node_text(node, source)),
        // C++ destructor: `~Foo`.
        "destructor_name" => Some(get_node_text(node, source)),
        // C++ operator: `operator+`, `operator()`, etc. Stored verbatim.
        "operator_name" => Some(get_node_text(node, source)),
        // C++ qualified out-of-class method: `void Foo::bar() {}`.
        // We return the unqualified name so it matches the inline form
        // (and so `methods: [String]` shows "bar" not "Foo::bar").
        "qualified_identifier" | "scoped_identifier" => {
            if let Some(name) = node.child_by_field_name("name") {
                return extract_name_from_declarator_inner(&name, source);
            }
            // Fallback: full text (preserves backward-compat for unusual cases).
            Some(get_node_text(node, source))
        }
        // Wrappers: `*name`, `&name`, etc. Recurse on inner declarator field.
        "pointer_declarator" | "reference_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                return extract_name_from_declarator_inner(&inner, source);
            }
            // Some grammars don't expose a `declarator` field on these
            // wrappers — fall back to scanning children.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = extract_name_from_declarator_inner(&child, source) {
                    return Some(name);
                }
            }
            None
        }
        _ => None,
    }
}

fn extract_c_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    // Navigate: function_definition -> declarator (function_declarator) -> parameters
    let declarator = match node.child_by_field_name("declarator") {
        Some(d) => d,
        None => return params,
    };

    let func_decl = if declarator.kind() == "function_declarator" {
        declarator
    } else if declarator.kind() == "pointer_declarator" {
        // Find function_declarator inside pointer_declarator
        let mut found = None;
        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                found = Some(child);
                break;
            }
        }
        match found {
            Some(f) => f,
            None => return params,
        }
    } else {
        return params;
    };

    if let Some(params_node) = func_decl.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                // The parameter name is in the "declarator" field
                if let Some(decl) = child.child_by_field_name("declarator") {
                    let name = extract_c_param_name(&decl, source);
                    if !name.is_empty() {
                        params.push(name);
                    }
                }
                // If no declarator field, this is a type-only param (e.g., `void`)
            }
        }
    }

    params
}

/// Extract parameter name from a declarator node, handling pointer wrappers.
fn extract_c_param_name(decl: &Node, source: &str) -> String {
    match decl.kind() {
        "identifier" => get_node_text(decl, source),
        "pointer_declarator" => {
            // *name / **name / ***name. A double/triple pointer parses as
            // nested pointer_declarators: pointer_declarator > pointer_declarator
            // > identifier. Recurse through the `declarator` field (mirroring the
            // array_declarator arm) so the inner name is reached for any pointer
            // depth, instead of only finding a DIRECT identifier child (which
            // dropped `char **argv` while keeping single `char *sep`).
            if let Some(inner) = decl.child_by_field_name("declarator") {
                return extract_c_param_name(&inner, source);
            }
            // Fallback: scan for a direct identifier child if the grammar did
            // not expose the `declarator` field.
            let mut cursor = decl.walk();
            for child in decl.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        }
        "array_declarator" => {
            // name[] or name[N]
            if let Some(inner) = decl.child_by_field_name("declarator") {
                return extract_c_param_name(&inner, source);
            }
            String::new()
        }
        _ => get_node_text(decl, source),
    }
}

/// Extract docstring from comment node immediately before the function_definition.
/// Supports both /* ... */ block comments and consecutive // line comments.
fn extract_c_docstring(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();

    // Collect consecutive comment nodes immediately before the function
    let mut comment_lines: Vec<String> = Vec::new();

    while let Some(prev_node) = prev {
        if prev_node.kind() == "comment" {
            let text = get_node_text(&prev_node, source);
            // Block comment: return immediately
            if text.starts_with("/*") {
                // If we already collected line comments, those are closer to the function
                if !comment_lines.is_empty() {
                    break;
                }
                return Some(text);
            }
            // Line comment: collect (we're going backwards)
            if text.starts_with("//") {
                comment_lines.push(text);
            } else {
                break;
            }
            prev = prev_node.prev_sibling();
        } else {
            break;
        }
    }

    if comment_lines.is_empty() {
        None
    } else {
        comment_lines.reverse();
        Some(comment_lines.join("\n"))
    }
}

// =============================================================================
// C++ detailed extraction
// =============================================================================

fn extract_cpp_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();
    let source_bytes = source.as_bytes();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_definition" {
            // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): a
            // `function_definition` that is actually a macro-decorated
            // class header (e.g. `class TINYXML2_LIB XMLDocument {…}`)
            // is NOT a free function. Skipping it here prevents
            // `XMLDocument` (a class) from polluting the free-function
            // list AND prevents the body from being walked as a function
            // body. The body is reached via `extract_cpp_classes_detailed`
            // which recurses into the recovered body for nested classes.
            if crate::ast::cpp_macro::is_macro_decorated_class(&child, source_bytes) {
                // Body methods are emitted by `extract_cpp_classes_detailed`
                // as `ClassInfo::methods`, not as free functions. Skip
                // the body walk entirely to keep the free-function list
                // disjoint from the method list (mirrors the
                // `class_specifier` / `struct_specifier` skip below).
                continue;
            }
            // Only top-level functions (not inside class/struct bodies)
            if !is_inside_cpp_class(&child) {
                let info = extract_cpp_function_info(&child, source, false);
                // fix-R7-cl6-cpp-blank-ghost (v0.5.0 CLOSEOUT): the C++ name
                // resolver returns an EMPTY name for declarators it cannot map
                // to a function name — chiefly a variable-bound lambda
                // (`auto pop_one = [](...){...}`, which is a local, not a free
                // function) and some trailing-return-type forms. Emitting a
                // nameless `FunctionInfo` produced ghost entries with malformed
                // `() -> <fragment>` signatures that polluted `extract` /
                // `explain` and (pre the dead.rs backstop) `dead` (cpp-fmt:
                // 72/180). A nameless top-level entity is never a real free
                // function, so drop it at the source. (The dead-analysis guard
                // remains as defense-in-depth.)
                if !info.name.trim().is_empty() {
                    functions.push(info);
                }
            }
        }
        // Recurse, but skip class/struct bodies (methods handled in class extraction)
        if child.kind() != "class_specifier"
            && child.kind() != "struct_specifier"
            && child.kind() != "field_declaration_list"
        {
            extract_cpp_functions_detailed(&child, source, functions);
        }
    }
}

fn extract_cpp_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = extract_c_function_name(node, source).unwrap_or_default();

    let params = extract_c_params(node, source);
    let return_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let docstring = extract_c_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Check for virtual keyword in the source text of the function
    let text = get_node_text(node, source);
    let mut decorators = Vec::new();
    if text.contains("virtual ") {
        decorators.push("virtual".to_string());
    }
    if text.contains("static ") {
        decorators.push("static".to_string());
    }

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async: false,
        decorators,
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn is_inside_cpp_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_specifier" | "struct_specifier" | "field_declaration_list" => return true,
            _ => current = parent.parent(),
        }
    }
    false
}

fn extract_cpp_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    let source_bytes = source.as_bytes();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_specifier" | "struct_specifier" => {
                // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110):
                // skip the inner `class_specifier`/`struct_specifier`
                // forward-decl shell produced by the macro-misparse
                // (`class TINYXML2_LIB` with no `field_declaration_list`).
                // Those shells emit the MACRO as their `name` field; the
                // real class is recovered at the enclosing
                // `function_definition` arm below.
                let is_macro_shell = child.child_by_field_name("body").is_none()
                    && matches!(
                        child.parent().map(|p| p.kind()),
                        Some("function_definition") | Some("declaration")
                    );
                if !is_macro_shell {
                    let info = extract_cpp_class_info(&child, source);
                    if !info.name.is_empty() {
                        classes.push(info);
                    }
                }
            }
            "function_definition" | "declaration" => {
                // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110):
                // recover the real class name from the
                // `function_definition`/`declaration` produced by
                // tree-sitter-cpp when it encounters an
                // unrecognized-attribute-macro-prefixed class header
                // (`class TINYXML2_LIB XMLDocument : public XMLNode {…}`).
                if let Some((name, body)) =
                    crate::ast::cpp_macro::macro_decorated_class_name_and_body(&child, source_bytes)
                {
                    let line_number = child.start_position().row as u32 + 1;
                    let line_end = child.end_position().row as u32 + 1;
                    let mut methods = Vec::new();
                    extract_cpp_methods_from_body(&body, source, &mut methods);
                    classes.push(ClassInfo {
                        name,
                        bases: Vec::new(),
                        docstring: extract_c_docstring(&child, source),
                        methods,
                        fields: Vec::new(),
                        decorators: Vec::new(),
                        line_number,
                        line_end,
                        kind: None,
                        modifiers: Vec::new(),
                        events: Vec::new(),
                        errors: Vec::new(),
                    });
                    // Recurse INTO the recovered body so inner classes
                    // (e.g. tinyxml2's `class DynArray` nested under
                    // `class TINYXML2_LIB StrPair { … class DynArray …}`)
                    // are emitted too.
                    extract_cpp_classes_detailed(&body, source, classes);
                    continue;
                }
            }
            _ => {}
        }
        extract_cpp_classes_detailed(&child, source, classes);
    }
}

fn extract_cpp_class_info(node: &Node, source: &str) -> ClassInfo {
    // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): prefer the
    // grammar's `name` field, but fall back to the first
    // `type_identifier` child when that field is missing or empty.
    // tree-sitter-cpp does NOT always expose `name` as a field on
    // `class_specifier` (the same gap that drove the
    // `extract_cpp_class_name` fallback in `extractor.rs::extract_cpp_classes`).
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "type_identifier" {
                    let text = get_node_text(&child, source);
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }
            None
        })
        .unwrap_or_default();

    let bases = extract_cpp_bases(node, source);
    let docstring = extract_c_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from class body
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_cpp_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract base classes from C++ class/struct specifier.
/// Looks for base_class_clause child, then extracts type_identifier children.
fn extract_cpp_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "base_class_clause" {
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "type_identifier"
                    || inner.kind() == "qualified_identifier"
                    || inner.kind() == "template_type"
                {
                    bases.push(get_node_text(&inner, source));
                }
            }
        }
    }

    bases
}

/// Extract method definitions from a C++ class body (field_declaration_list).
///
/// m007-m036-hubs-line-is-public-v1 (v0.4.2 M-113): track the current
/// `access_specifier` (`public:` / `private:` / `protected:`) as we walk
/// so each method's `visibility` reflects the section it lives under.
/// Without this, every C++ class method came out `visibility: None` and
/// downstream consumers (e.g. `tldr hubs`) under-reported `is_public`.
/// C++ default visibility is `private` for `class` and `public` for
/// `struct`; we receive only the body here, so we default to `private`
/// — callers that need struct semantics should pre-seed a `public:`
/// access specifier before calling, which tree-sitter naturally does
/// for struct bodies anyway (the grammar inserts none, but the field
/// list starts implicitly public; callers using this helper for struct
/// bodies should keep that in mind).
fn extract_cpp_methods_from_body(body: &Node, source: &str, methods: &mut Vec<FunctionInfo>) {
    let mut cursor = body.walk();
    let mut current_access: Option<String> = None;

    for child in body.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                let mut info = extract_cpp_function_info(&child, source, true);
                if info.visibility.is_none() {
                    info.visibility = current_access.clone();
                }
                methods.push(info);
            }
            "declaration" => {
                // Handle inline method declarations that have a body
                // e.g., `int foo() { ... }` inside a class that tree-sitter parses as declaration
                // Usually these are just declarations without body, skip them
            }
            "access_specifier" => {
                // public: / private: / protected: — capture the keyword
                // (first identifier-like child or the node text) so the
                // next function_definition inherits it. The grammar
                // exposes the keyword as a direct named child of
                // `access_specifier` (e.g. `public`) for tree-sitter-cpp.
                let text = get_node_text(&child, source);
                // The node text typically includes the trailing colon — strip
                // it for a clean keyword.
                let kw = text.trim().trim_end_matches(':').trim().to_string();
                match kw.as_str() {
                    "public" | "private" | "protected" => {
                        current_access = Some(kw);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// =============================================================================
// Ruby detailed extraction
// =============================================================================

fn extract_ruby_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "method" | "singleton_method" => {
                // Only top-level functions (not inside class/module)
                if !is_inside_ruby_class(&child) {
                    let info = extract_ruby_function_info(&child, source, false);
                    functions.push(info);
                }
            }
            "class" | "module" => {
                // Don't recurse into classes for top-level function extraction
            }
            _ => {
                extract_ruby_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn extract_ruby_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_ruby_params(node, source);
    let docstring = extract_ruby_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // singleton_method => class method (self.foo)
    let is_singleton = node.kind() == "singleton_method";

    let mut decorators = Vec::new();
    if is_singleton {
        decorators.push("self".to_string());
    }

    FunctionInfo {
        name,
        params,
        return_type: None, // Ruby is dynamically typed
        docstring,
        is_method,
        is_async: false,
        decorators,
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_ruby_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    params.push(get_node_text(&child, source));
                }
                "optional_parameter" => {
                    // name = default_value
                    if let Some(name_node) = child.child_by_field_name("name") {
                        params.push(get_node_text(&name_node, source));
                    }
                }
                "splat_parameter" => {
                    // *args
                    let text = get_node_text(&child, source);
                    params.push(text);
                }
                "hash_splat_parameter" => {
                    // **kwargs
                    let text = get_node_text(&child, source);
                    params.push(text);
                }
                "block_parameter" => {
                    // &block
                    let text = get_node_text(&child, source);
                    params.push(text);
                }
                "keyword_parameter" => {
                    // name: or name: default
                    if let Some(name_node) = child.child_by_field_name("name") {
                        params.push(get_node_text(&name_node, source));
                    }
                }
                "destructured_parameter" => {
                    // (a, b) - destructured
                    let text = get_node_text(&child, source);
                    params.push(text);
                }
                _ => {}
            }
        }
    }

    params
}

/// Extract docstring from consecutive comment nodes immediately before the method.
/// Ruby uses # style comments. Consecutive # lines form a docstring.
/// Extract docstring from consecutive comment nodes immediately before the method.
/// Ruby uses # style comments. Consecutive # lines form a docstring.
///
/// In Ruby's tree-sitter grammar, methods inside a class are wrapped in
/// `body_statement`, but comments sit as siblings of `body_statement`
/// under the `class` node. So when `node.prev_sibling()` yields nothing
/// (method is first child of body_statement), we try
/// `node.parent(body_statement).prev_sibling()` to reach the comment.
fn extract_ruby_docstring(node: &Node, source: &str) -> Option<String> {
    // Try direct prev sibling first, then walk up through body_statement
    let first_prev = node.prev_sibling().or_else(|| {
        node.parent()
            .filter(|p| p.kind() == "body_statement")
            .and_then(|p| p.prev_sibling())
    });
    let mut prev = first_prev;
    let mut comment_lines: Vec<String> = Vec::new();
    while let Some(prev_node) = prev {
        if prev_node.kind() == "comment" {
            let text = get_node_text(&prev_node, source);
            comment_lines.push(text);
            prev = prev_node.prev_sibling();
        } else {
            break;
        }
    }
    if comment_lines.is_empty() {
        None
    } else {
        comment_lines.reverse();
        Some(comment_lines.join("\n"))
    }
}

fn is_inside_ruby_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class" | "module" | "body_statement" => {
                // body_statement is the body of a class/module
                // Check if its parent is a class/module
                if parent.kind() == "body_statement" {
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "class" || grandparent.kind() == "module" {
                            return true;
                        }
                    }
                    current = parent.parent();
                    continue;
                }
                return true;
            }
            _ => current = parent.parent(),
        }
    }
    false
}

/// Recursively enumerate Ruby `class` and `module` declarations.
///
/// language-coverage-fixes-v1 (P4.BUG-N2): the previous version stopped
/// at the first `class`/`module` node it encountered and never recursed
/// into the body. Real Ruby code (e.g. Rails::HTML::Sanitizer) nests
/// 26+ modules and classes under a top-level `module Rails`; only the
/// outermost wrapper was reported, with zero methods, because every
/// method actually lived inside a nested class. Mirrors the recursion
/// pattern in `quality::cohesion::extract_ruby_classes_recursive`.
///
/// Each nested class/module is emitted as its own `ClassInfo` entry,
/// and `extract_ruby_methods_from_body` (which already filters out
/// nested `class`/`module` nodes per M7) attributes methods to the
/// nearest enclosing class — so a method on `class Sanitizer` inside
/// `module Rails` is reported on `Sanitizer`, not on `Rails`.
fn extract_ruby_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class" => {
                let info = extract_ruby_class_info(&child, source);
                classes.push(info);
                // P4.BUG-N2: descend into the class body so nested
                // class/module declarations are emitted as their own
                // ClassInfo entries.
                if let Some(body) = child.child_by_field_name("body") {
                    extract_ruby_classes_detailed(&body, source, classes);
                }
            }
            "module" => {
                // Treat modules as class-like constructs
                let info = extract_ruby_module_info(&child, source);
                classes.push(info);
                // P4.BUG-N2: descend into the module body so nested
                // class/module declarations (the common Rails pattern)
                // are emitted as their own ClassInfo entries.
                if let Some(body) = child.child_by_field_name("body") {
                    extract_ruby_classes_detailed(&body, source, classes);
                }
            }
            _ => {
                extract_ruby_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_ruby_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let mut bases = Vec::new();
    if let Some(superclass) = node.child_by_field_name("superclass") {
        bases.push(get_node_text(&superclass, source));
    }

    let docstring = extract_ruby_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from class body
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_ruby_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_ruby_module_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let docstring = extract_ruby_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from module body
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_ruby_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases: Vec::new(), // Modules don't have superclasses
        docstring,
        methods,
        fields: Vec::new(),
        decorators: vec!["module".to_string()],
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract methods from a Ruby class/module body.
/// The body is a body_statement node containing method definitions.
///
/// med-cleanup-bundle-v1 / M7: do NOT recurse into nested `class` /
/// `module` declarations. Those are reported as their own ClassInfo
/// entries by `extract_ruby_classes_detailed` and counting their
/// methods against the enclosing module produced spurious God Class
/// findings (e.g. `module Rails` reported with 27 methods on
/// rails-html-sanitizer where every method actually lived in nested
/// classes).
fn extract_ruby_methods_from_body(body: &Node, source: &str, methods: &mut Vec<FunctionInfo>) {
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        match child.kind() {
            "method" | "singleton_method" => {
                let info = extract_ruby_function_info(&child, source, true);
                methods.push(info);
            }
            // M7: skip nested classes/modules. Their methods belong to
            // the nested ClassInfo entry, not this body's owner.
            "class" | "module" => {}
            _ => {
                // Recurse to find methods in nested blocks (e.g., inside
                // `begin`/`rescue`). Nested `class`/`module` nodes are
                // already filtered above.
                extract_ruby_methods_from_body(&child, source, methods);
            }
        }
    }
}

// =============================================================================
// PHP detailed extraction
// =============================================================================

fn extract_php_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Standalone function (not a method)
                let info = extract_php_function_info(&child, source, false);
                functions.push(info);
            }
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                // Don't recurse into classes for top-level function extraction
            }
            _ => {
                extract_php_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn extract_php_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let params = extract_php_params(node, source);
    let return_type = extract_php_return_type(node, source);
    let docstring = extract_php_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Check for visibility and static modifiers on method_declaration
    let mut decorators = Vec::new();
    if is_method {
        let text = get_node_text(node, source);
        if text.starts_with("public ") || text.contains(" public ") {
            decorators.push("public".to_string());
        } else if text.starts_with("private ") || text.contains(" private ") {
            decorators.push("private".to_string());
        } else if text.starts_with("protected ") || text.contains(" protected ") {
            decorators.push("protected".to_string());
        }
        if text.contains("static ") {
            decorators.push("static".to_string());
        }
        if text.contains("abstract ") {
            decorators.push("abstract".to_string());
        }
    }

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async: false,
        decorators,
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_php_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        // params_node is formal_parameters
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "simple_parameter" || child.kind() == "variadic_parameter" {
                // The parameter name is in the "name" field (starts with $)
                if let Some(name_node) = child.child_by_field_name("name") {
                    params.push(get_node_text(&name_node, source));
                }
            } else if child.kind() == "property_promotion_parameter" {
                // PHP 8 constructor promotion: public readonly string $name
                if let Some(name_node) = child.child_by_field_name("name") {
                    params.push(get_node_text(&name_node, source));
                }
            }
        }
    }

    params
}

/// Extract return type from PHP function/method.
/// Looks for a return_type field on the node.
fn extract_php_return_type(node: &Node, source: &str) -> Option<String> {
    // tree-sitter-php uses "return_type" field
    if let Some(rt) = node.child_by_field_name("return_type") {
        let text = get_node_text(&rt, source);
        // Remove leading colon and whitespace if present
        let cleaned = text.trim_start_matches(':').trim().to_string();
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }

    // Fallback: scan children for a ":" followed by a type node
    // This handles cases where the grammar doesn't expose a return_type field
    let mut cursor = node.walk();
    let mut found_colon = false;
    for child in node.children(&mut cursor) {
        if child.kind() == ":" {
            found_colon = true;
            continue;
        }
        if found_colon {
            let kind = child.kind();
            // Type nodes in PHP grammar
            if kind == "named_type"
                || kind == "primitive_type"
                || kind == "optional_type"
                || kind == "union_type"
                || kind == "intersection_type"
                || kind == "name"
                || kind == "qualified_name"
            {
                return Some(get_node_text(&child, source));
            }
            found_colon = false;
        }
    }

    None
}

/// Extract docstring from PHPDoc comment (/** ... */) immediately before the function/method.
fn extract_php_docstring(node: &Node, source: &str) -> Option<String> {
    if let Some(prev_node) = node.prev_sibling() {
        if prev_node.kind() == "comment" {
            let text = get_node_text(&prev_node, source);
            if text.starts_with("/**") {
                return Some(text);
            }
            // Regular // or /* comment - also accept as docstring
            if text.starts_with("/*") || text.starts_with("//") {
                return Some(text);
            }
        }
    }

    None
}

fn extract_php_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => {
                let info = extract_php_class_info(&child, source);
                classes.push(info);
            }
            "interface_declaration" => {
                let info = extract_php_interface_info(&child, source);
                classes.push(info);
            }
            "trait_declaration" => {
                let info = extract_php_trait_info(&child, source);
                classes.push(info);
            }
            _ => {
                extract_php_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_php_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let bases = extract_php_bases(node, source);
    let docstring = extract_php_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from class body
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_php_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_php_interface_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let docstring = extract_php_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_php_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases: Vec::new(),
        docstring,
        methods,
        fields: Vec::new(),
        decorators: vec!["interface".to_string()],
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_php_trait_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let docstring = extract_php_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        extract_php_methods_from_body(&body, source, &mut methods);
    }

    ClassInfo {
        name,
        bases: Vec::new(),
        docstring,
        methods,
        fields: Vec::new(),
        decorators: vec!["trait".to_string()],
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract base classes from PHP class_declaration.
/// Looks for base_clause (extends) and class_interface_clause (implements).
/// Shared with `tldr interface` so both pipelines resolve the same bases.
pub fn extract_php_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "base_clause" {
            // extends ClassName
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "name"
                    || inner.kind() == "qualified_name"
                    || inner.kind() == "named_type"
                {
                    bases.push(get_node_text(&inner, source));
                }
            }
        } else if child.kind() == "class_interface_clause" {
            // implements Interface1, Interface2
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "name"
                    || inner.kind() == "qualified_name"
                    || inner.kind() == "named_type"
                {
                    bases.push(get_node_text(&inner, source));
                }
            }
        }
    }

    bases
}

/// Extract method declarations from a PHP class body (declaration_list).
fn extract_php_methods_from_body(body: &Node, source: &str, methods: &mut Vec<FunctionInfo>) {
    let mut cursor = body.walk();

    for child in body.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            let info = extract_php_function_info(&child, source, true);
            methods.push(info);
        }
    }
}

// =============================================================================
// CSharp detailed extraction
// =============================================================================

fn extract_csharp_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "method_declaration" | "constructor_declaration" => {
                let info = extract_csharp_function_info(&child, source);
                functions.push(info);
            }
            // Skip into class/struct/namespace bodies to find methods
            "class_declaration"
            | "struct_declaration"
            | "namespace_declaration"
            | "interface_declaration" => {
                if let Some(body) = child.child_by_field_name("body") {
                    extract_csharp_functions_detailed(&body, source, functions);
                }
            }
            _ => {
                extract_csharp_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn extract_csharp_function_info(node: &Node, source: &str) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            // For constructors, name might be the type_identifier child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    let params = extract_csharp_params(node, source);

    let return_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));

    let docstring = extract_csharp_docstring(node, source);

    // Check for async modifier
    let is_async = {
        let mut cursor = node.walk();
        let mut found = false;
        for child in node.children(&mut cursor) {
            if child.kind() == "modifier" || child.kind() == "async" {
                let text = get_node_text(&child, source);
                if text == "async" {
                    found = true;
                    break;
                }
            }
        }
        found
    };

    let decorators = extract_csharp_attributes(node, source);
    // v0.5.0 CL-10 (GH #81): C# methods/constructors emit leading
    // `attribute_list` (`[Test]`, `[Serializable]`, …) children that shift
    // the bare `node.start_position()` line off the `public void Foo` decl
    // keyword. Route through `decl_keyword_line_from_node` (which now lists
    // `attribute_list` in `ANNOTATION_LIKE_KINDS`) so `extract` agrees with
    // `structure` / `cognitive` / `contracts` on the decl-keyword line.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): C# uses `modifier` children
    // on method/constructor/property nodes for access keywords. We pick
    // the most-restrictive keyword in declaration order; combined
    // modifiers (e.g. `protected internal`, `private protected`) keep
    // the first keyword seen so callers receive a determinist string.
    let visibility = extract_csharp_visibility(node, source);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method: true, // C# methods are always inside classes/structs
        is_async,
        decorators,
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// is-public-visibility-v1 (v0.4.2 M-007): scan `modifier` children for a
/// C# access keyword. The tree-sitter-c-sharp grammar wraps each modifier
/// token (including `public`/`private`/`protected`/`internal`) in a
/// `modifier` named child whose text is the keyword.
fn extract_csharp_visibility(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifier" {
            let t = get_node_text(&child, source);
            match t.as_str() {
                "public" | "private" | "protected" | "internal" => {
                    return Some(t);
                }
                _ => {}
            }
        }
    }
    None
}

fn extract_csharp_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter" {
                // Parameter name is the "name" field or the last identifier
                if let Some(name) = child.child_by_field_name("name") {
                    params.push(get_node_text(&name, source));
                } else {
                    // Fallback: find last identifier child
                    let mut inner_cursor = child.walk();
                    let mut last_ident = None;
                    for inner in child.children(&mut inner_cursor) {
                        if inner.kind() == "identifier" {
                            last_ident = Some(get_node_text(&inner, source));
                        }
                    }
                    if let Some(name) = last_ident {
                        params.push(name);
                    }
                }
            }
        }
    }

    params
}

fn extract_csharp_docstring(node: &Node, source: &str) -> Option<String> {
    // Look for preceding XML doc comments (/// comments)
    let mut prev = node.prev_sibling();
    let mut doc_lines = Vec::new();

    while let Some(sibling) = prev {
        if sibling.kind() == "comment" {
            let text = get_node_text(&sibling, source);
            if text.starts_with("///") {
                doc_lines.push(text.trim_start_matches("///").trim().to_string());
                prev = sibling.prev_sibling();
                continue;
            }
        }
        break;
    }

    if doc_lines.is_empty() {
        None
    } else {
        doc_lines.reverse();
        Some(doc_lines.join("\n"))
    }
}

fn extract_csharp_attributes(node: &Node, source: &str) -> Vec<String> {
    // Look for attribute_list siblings before the method
    let mut attrs = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        if sibling.kind() == "attribute_list" {
            let text = get_node_text(&sibling, source);
            // Remove surrounding brackets [...]
            let trimmed = text
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            attrs.push(trimmed);
            prev = sibling.prev_sibling();
            continue;
        }
        break;
    }

    attrs.reverse();
    attrs
}

fn extract_csharp_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "struct_declaration" | "interface_declaration" => {
                let info = extract_csharp_class_info(&child, source);
                classes.push(info);
            }
            _ => {
                extract_csharp_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_csharp_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    // v0.5.0 CL-10 (GH #81): normalise past a leading `[Attribute]`
    // (`attribute_list`) child so the class line matches the `class Foo`
    // decl keyword — consistent with the `structure` C# path.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // Extract base types from base_list
    let bases = extract_csharp_bases(node, source);

    // Extract methods from body
    let mut methods = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        // Only extract methods directly inside this class body
        let mut body_cursor = body.walk();
        for body_child in body.children(&mut body_cursor) {
            if body_child.kind() == "method_declaration"
                || body_child.kind() == "constructor_declaration"
            {
                let info = extract_csharp_function_info(&body_child, source);
                methods.push(info);
            }
        }
    }

    let docstring = extract_csharp_docstring(node, source);

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract base types from a C# type declaration's `base_list`. Shared with
/// `tldr interface` so both pipelines resolve the same bases.
pub fn extract_csharp_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();

    if let Some(base_list) = node.child_by_field_name("bases") {
        let mut cursor = base_list.walk();
        for child in base_list.children(&mut cursor) {
            if child.kind() == "identifier"
                || child.kind() == "generic_name"
                || child.kind() == "qualified_name"
            {
                bases.push(get_node_text(&child, source));
            }
        }
    } else {
        // Fallback: look for base_list child node
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "base_list" {
                let mut inner = child.walk();
                for base_child in child.children(&mut inner) {
                    if base_child.kind() == "identifier"
                        || base_child.kind() == "generic_name"
                        || base_child.kind() == "qualified_name"
                    {
                        bases.push(get_node_text(&base_child, source));
                    }
                }
            }
        }
    }

    bases
}

// =============================================================================
// Kotlin detailed extraction
// =============================================================================

fn extract_kotlin_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // Skip methods inside classes (they get extracted by class extractor)
                if !is_inside_kotlin_class(&child) {
                    let info = extract_kotlin_function_info(&child, source, false);
                    functions.push(info);
                }
            }
            "class_declaration" | "object_declaration" => {
                // Don't recurse into classes for top-level functions
            }
            _ => {
                extract_kotlin_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn is_inside_kotlin_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_declaration" | "object_declaration" | "class_body" => return true,
            _ => current = parent.parent(),
        }
    }
    false
}

fn extract_kotlin_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    // Kotlin uses simple_identifier for function names, not a "name" field
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            // Fallback: find simple_identifier child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "simple_identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    let params = extract_kotlin_params(node, source);
    let return_type = extract_kotlin_return_type(node, source);
    let docstring = extract_kotlin_docstring(node, source);

    // Check for suspend modifier (Kotlin's async)
    let is_async = {
        let mut cursor = node.walk();
        let mut found = false;
        for child in node.children(&mut cursor) {
            if child.kind() == "modifiers" {
                let mut mod_cursor = child.walk();
                for mod_child in child.children(&mut mod_cursor) {
                    let text = get_node_text(&mod_child, source);
                    if text == "suspend" {
                        found = true;
                        break;
                    }
                }
            }
        }
        found
    };

    let decorators = extract_kotlin_annotations(node, source);
    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): Kotlin
    // `function_declaration` starts at its `modifiers` child for
    // annotation-decorated funs (`@Deprecated(...) public fun ...`).
    // Anchor to the first non-modifier child so the reported line is
    // `fun`/`val`/`public`, not the leading annotation.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // is-public-visibility-v1 (v0.4.2 M-007): Kotlin nests its access
    // keyword under `modifiers > visibility_modifier`. The Kotlin spec
    // defaults declarations to `public` when no modifier is present, so
    // we leave `None` for those cases and let downstream consumers
    // treat `None` as public.
    let visibility = extract_kotlin_visibility(node, source);

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async,
        decorators,
        visibility,
        line_number,
        line_end,
        state_mutability: None,
    }
}

/// is-public-visibility-v1 (v0.4.2 M-007): scan `modifiers >
/// visibility_modifier` for a Kotlin access keyword. The text of the
/// modifier node IS the keyword. We accept `public`, `private`,
/// `protected`, `internal`.
fn extract_kotlin_visibility(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mcursor = child.walk();
            for m in child.children(&mut mcursor) {
                if m.kind() == "visibility_modifier" {
                    let t = get_node_text(&m, source);
                    let t = t.trim();
                    if matches!(t, "public" | "private" | "protected" | "internal") {
                        return Some(t.to_string());
                    }
                }
                // Some grammars expose the keyword directly under `modifiers`.
                let raw = get_node_text(&m, source);
                let raw = raw.trim();
                if matches!(raw, "public" | "private" | "protected" | "internal") {
                    return Some(raw.to_string());
                }
            }
        }
    }
    None
}

fn extract_kotlin_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    // Look for function_value_parameters child (a named child, NOT a field).
    // Two grammar generations are supported:
    //  * tree-sitter-kotlin (legacy): `parameter` > `simple_identifier`
    //  * tree-sitter-kotlin-ng 1.1.0+ : `parameter` > `identifier`
    // We also tolerate `function_value_parameter` from intermediate grammars
    // that wrap the parameter under a "parameter" field.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_value_parameters" {
            let mut inner = child.walk();
            for param_wrapper in child.children(&mut inner) {
                let target = match param_wrapper.kind() {
                    "parameter" => Some(param_wrapper),
                    "function_value_parameter" => param_wrapper
                        .child_by_field_name("parameter")
                        .or(Some(param_wrapper)),
                    _ => None,
                };
                if let Some(param_node) = target {
                    let mut param_cursor = param_node.walk();
                    for param_child in param_node.children(&mut param_cursor) {
                        // The first identifier-shaped child is the param name.
                        // Skip type qualifiers / modifiers by accepting only
                        // the well-known identifier kinds.
                        if param_child.kind() == "simple_identifier"
                            || param_child.kind() == "identifier"
                        {
                            params.push(get_node_text(&param_child, source));
                            break;
                        }
                    }
                }
            }
            break;
        }
    }

    params
}

fn extract_kotlin_return_type(node: &Node, source: &str) -> Option<String> {
    // Look for user_type or type_reference after the colon following parameters
    let mut cursor = node.walk();
    let mut found_params = false;
    let mut found_colon = false;

    for child in node.children(&mut cursor) {
        if child.kind() == "function_value_parameters" {
            found_params = true;
            continue;
        }
        if found_params && get_node_text(&child, source) == ":" {
            found_colon = true;
            continue;
        }
        if found_colon {
            match child.kind() {
                "user_type" | "nullable_type" | "type_identifier" | "function_type"
                | "type_reference" => {
                    return Some(get_node_text(&child, source));
                }
                _ => {
                    // Might be the return type under a different node kind
                    if child.kind() != "function_body" && child.kind() != "{" {
                        return Some(get_node_text(&child, source));
                    }
                    break;
                }
            }
        }
    }

    None
}

fn extract_kotlin_docstring(node: &Node, source: &str) -> Option<String> {
    // KDoc: /** ... */ comment before the function
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        if sibling.kind() == "multiline_comment" {
            let text = get_node_text(&sibling, source);
            if text.starts_with("/**") {
                return Some(text);
            }
        }
        // Skip over annotations/modifiers to find the doc comment
        if sibling.kind() == "modifiers" || sibling.kind() == "annotation" {
            prev = sibling.prev_sibling();
            continue;
        }
        break;
    }

    None
}

fn extract_kotlin_annotations(node: &Node, source: &str) -> Vec<String> {
    let mut annotations = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for mod_child in child.children(&mut mod_cursor) {
                if mod_child.kind() == "annotation" {
                    let text = get_node_text(&mod_child, source);
                    // Remove leading @
                    annotations.push(text.trim_start_matches('@').to_string());
                }
            }
        }
    }

    annotations
}

fn extract_kotlin_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => {
                let info = extract_kotlin_class_info(&child, source);
                classes.push(info);
            }
            "object_declaration" => {
                let info = extract_kotlin_object_info(&child, source);
                classes.push(info);
            }
            _ => {
                extract_kotlin_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_kotlin_class_info(node: &Node, source: &str) -> ClassInfo {
    // kotlin-extract-and-cpp-extensions-v1 (P6.BUG-N1): Kotlin's
    // tree-sitter grammar emits class names as `simple_identifier` (or
    // occasionally `type_identifier` for type aliases). The historical
    // implementation only looked for `type_identifier`, which produced
    // empty `name` strings on every real Kotlin class — and cascaded
    // into `tldr impact <Class>.<method>` returning "Function not
    // found" because the impact name index was keyed under "". Mirror
    // the working `extract_kotlin_function_info` pattern: prefer the
    // `name` field, fall back to a `simple_identifier` /
    // `type_identifier` child scan.
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "simple_identifier" || child.kind() == "type_identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002):
    // anchor to the first non-modifier child so `@Deprecated class Foo`
    // reports the `class` line, not the annotation line.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;
    let bases = extract_kotlin_bases(node, source);
    let docstring = extract_kotlin_docstring(node, source);

    // Extract methods from class_body.
    //
    // m007-m036-hubs-line-is-public-v1 (v0.4.2 M-113): also recurse into
    // nested `object_declaration` / `companion_object` children inside the
    // class body so companion-object factory methods (e.g. Kotlin's
    // `UtcOffset.ofSeconds`, `Instant.fromEpochSeconds`) are surfaced as
    // class methods. Without this, downstream consumers (`tldr hubs`,
    // line lookup, etc.) miss them entirely and report `line: 0` for
    // call-graph references that resolve to the bare factory name.
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_body" {
            collect_kotlin_methods_from_body(&child, source, &mut methods);
        }
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Walk a Kotlin `class_body` collecting `function_declaration` children,
/// including those nested inside `companion_object` / `object_declaration`
/// blocks (which Kotlin uses for static/factory methods).
///
/// m007-m036-hubs-line-is-public-v1 (M-113): nested-object recursion.
fn collect_kotlin_methods_from_body(body: &Node, source: &str, methods: &mut Vec<FunctionInfo>) {
    let mut body_cursor = body.walk();
    for body_child in body.children(&mut body_cursor) {
        match body_child.kind() {
            "function_declaration" => {
                let info = extract_kotlin_function_info(&body_child, source, true);
                methods.push(info);
            }
            "companion_object" | "object_declaration" => {
                // Nested object: scan its class_body for function_declaration.
                let mut nested_cursor = body_child.walk();
                for nested in body_child.children(&mut nested_cursor) {
                    if nested.kind() == "class_body" {
                        collect_kotlin_methods_from_body(&nested, source, methods);
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_kotlin_object_info(node: &Node, source: &str) -> ClassInfo {
    // kotlin-extract-and-cpp-extensions-v1 (P6.BUG-N1): same name-field
    // bug as `extract_kotlin_class_info` — Kotlin's `object_declaration`
    // emits `simple_identifier` for the singleton name. Prefer the
    // `name` field, fall back to a `simple_identifier` /
    // `type_identifier` child scan.
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "simple_identifier" || child.kind() == "type_identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): anchor
    // to the first non-modifier child for annotation-decorated objects.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    // Extract methods from class_body (using the shared helper that also
    // recurses into nested object_declaration / companion_object).
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_body" {
            collect_kotlin_methods_from_body(&child, source, &mut methods);
        }
    }

    ClassInfo {
        name,
        bases: Vec::new(),
        docstring: extract_kotlin_docstring(node, source),
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

/// Extract base types from a Kotlin class/object declaration's
/// `delegation_specifiers`. Shared with `tldr interface` so both pipelines
/// resolve the same bases.
pub fn extract_kotlin_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "delegation_specifiers" {
            let mut inner = child.walk();
            for spec in child.children(&mut inner) {
                if spec.kind() == "delegation_specifier" {
                    // The user_type or constructor_invocation inside
                    let mut spec_cursor = spec.walk();
                    for spec_child in spec.children(&mut spec_cursor) {
                        if spec_child.kind() == "user_type"
                            || spec_child.kind() == "constructor_invocation"
                        {
                            // For constructor_invocation, get just the type name
                            let mut type_cursor = spec_child.walk();
                            for type_child in spec_child.children(&mut type_cursor) {
                                if type_child.kind() == "type_identifier"
                                    || type_child.kind() == "user_type"
                                {
                                    bases.push(get_node_text(&type_child, source));
                                    break;
                                }
                            }
                            break;
                        }
                        if spec_child.kind() == "type_identifier" {
                            bases.push(get_node_text(&spec_child, source));
                            break;
                        }
                    }
                }
                // Some grammars put user_type directly under delegation_specifiers
                if spec.kind() == "user_type" || spec.kind() == "constructor_invocation" {
                    let mut type_cursor = spec.walk();
                    for type_child in spec.children(&mut type_cursor) {
                        if type_child.kind() == "type_identifier" {
                            bases.push(get_node_text(&type_child, source));
                            break;
                        }
                    }
                }
            }
        }
    }

    bases
}

// =============================================================================
// Scala detailed extraction
// =============================================================================

fn extract_scala_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" | "function_declaration" => {
                // Skip methods inside classes (they get extracted by class extractor)
                if !is_inside_scala_class(&child) {
                    let info = extract_scala_function_info(&child, source, false);
                    functions.push(info);
                }
            }
            "class_definition" | "object_definition" | "trait_definition" => {
                // Don't recurse into class-like constructs for top-level functions
            }
            _ => {
                extract_scala_functions_detailed(&child, source, functions);
            }
        }
    }
}

fn is_inside_scala_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "template_body" => {
                return true
            }
            _ => current = parent.parent(),
        }
    }
    false
}

fn extract_scala_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            // Fallback: find identifier child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    let params = extract_scala_params(node, source);
    let return_type = extract_scala_return_type(node, source);
    let docstring = extract_scala_docstring(node, source);
    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): Scala
    // `function_definition`/`function_declaration` may have leading
    // `annotation` children (`@deprecated`, `@tailrec`) before `def`.
    // Anchor to the first non-annotation child.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async: false, // Scala handles async via Futures, not a keyword
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_scala_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    // cl4-interface-v1 (IT3-scala-01/02/03, GH #78): a Scala
    // `function_definition` exposes its `type_parameters` (`[F[_], A]`) AND
    // every curried value `parameters` clause (`(capacity: Int)(implicit
    // F: ...)`) under the SAME field name `parameters`. The previous code
    // used `child_by_field_name("parameters")`, which returns only the FIRST
    // such child — the type-parameter list — so curried value parameters
    // (e.g. `capacity`) were silently dropped (context emitted `bounded()`).
    // Walk every child whose node KIND is a value parameter clause
    // (`parameters` / `class_parameters`); `type_parameters` is excluded by
    // kind so type variables are never mistaken for value parameters.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameters" || child.kind() == "class_parameters" {
            extract_scala_params_from_list(&child, source, &mut params);
        }
    }

    params
}

fn extract_scala_params_from_list(node: &Node, source: &str, params: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_parameter" | "parameter" => {
                // Name is the first identifier
                if let Some(name) = child.child_by_field_name("name") {
                    params.push(get_node_text(&name, source));
                } else {
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "identifier" {
                            params.push(get_node_text(&inner_child, source));
                            break;
                        }
                    }
                }
            }
            // Nested parameter lists (curried functions)
            "parameters" | "class_parameters" => {
                extract_scala_params_from_list(&child, source, params);
            }
            _ => {}
        }
    }
}

fn extract_scala_return_type(node: &Node, source: &str) -> Option<String> {
    // Look for the return type after `:` and before `=` or `{`
    let mut cursor = node.walk();
    let mut found_colon = false;

    for child in node.children(&mut cursor) {
        if get_node_text(&child, source) == ":" {
            found_colon = true;
            continue;
        }
        if found_colon {
            let text = get_node_text(&child, source);
            if text == "=" || text == "{" {
                break;
            }
            match child.kind() {
                "type_identifier"
                | "generic_type"
                | "compound_type"
                | "infix_type"
                | "tuple_type"
                | "function_type"
                | "parametrized_type"
                | "stable_type_identifier" => {
                    return Some(text);
                }
                _ => {
                    // Accept any non-punctuation node as potential return type
                    if !text.is_empty() && text != "=" && text != "{" {
                        return Some(text);
                    }
                    break;
                }
            }
        }
    }

    None
}

fn extract_scala_docstring(node: &Node, source: &str) -> Option<String> {
    // ScalaDoc: /** ... */ before the function
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        match sibling.kind() {
            "comment" | "block_comment" => {
                let text = get_node_text(&sibling, source);
                if text.starts_with("/**") {
                    return Some(text);
                }
            }
            // Skip annotations/modifiers
            "annotation" | "modifiers" => {
                prev = sibling.prev_sibling();
                continue;
            }
            _ => break,
        }
        break;
    }

    None
}

fn extract_scala_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_definition" => {
                let info = extract_scala_class_info(&child, source);
                classes.push(info);
            }
            "object_definition" => {
                let info = extract_scala_object_info(&child, source);
                classes.push(info);
            }
            "trait_definition" => {
                let info = extract_scala_trait_info(&child, source);
                classes.push(info);
            }
            _ => {
                extract_scala_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn extract_scala_class_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): anchor
    // to the first non-annotation child for `@inline class Foo` etc.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;
    let bases = extract_scala_bases(node, source);
    let docstring = extract_scala_docstring(node, source);

    // Extract methods from template_body
    let mut methods = Vec::new();
    extract_scala_methods_from_body(node, source, &mut methods);

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_scala_object_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002):
    // anchor to the first non-annotation child for decorated objects.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;
    let bases = extract_scala_bases(node, source);
    let docstring = extract_scala_docstring(node, source);

    let mut methods = Vec::new();
    extract_scala_methods_from_body(node, source, &mut methods);

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_scala_trait_info(node: &Node, source: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source);
                }
            }
            String::new()
        });

    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): anchor
    // to the first non-annotation child for decorated traits.
    let line_number = decl_keyword_line_from_node(node);
    let line_end = node.end_position().row as u32 + 1;
    let bases = extract_scala_bases(node, source);
    let docstring = extract_scala_docstring(node, source);

    let mut methods = Vec::new();
    extract_scala_methods_from_body(node, source, &mut methods);

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_scala_methods_from_body(node: &Node, source: &str, methods: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "template_body" || child.kind() == "body" {
            let mut body_cursor = child.walk();
            for body_child in child.children(&mut body_cursor) {
                if body_child.kind() == "function_definition"
                    || body_child.kind() == "function_declaration"
                {
                    let info = extract_scala_function_info(&body_child, source, true);
                    methods.push(info);
                }
            }
        }
    }
}

fn extract_scala_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "extends_clause" {
            let mut inner = child.walk();
            for inner_child in child.children(&mut inner) {
                match inner_child.kind() {
                    "type_identifier" | "generic_type" | "stable_type_identifier" => {
                        bases.push(get_node_text(&inner_child, source));
                    }
                    _ => {}
                }
            }
        }
    }

    bases
}

// =============================================================================
// Elixir detailed extraction
// =============================================================================

fn extract_elixir_functions_detailed(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some(first) = child.child(0) {
                let text = get_node_text(&first, source);
                if text == "def" || text == "defp" {
                    let info = extract_elixir_function_info(&child, source);
                    functions.push(info);
                } else if text != "defmodule" {
                    // Recurse into non-module calls
                    extract_elixir_functions_detailed(&child, source, functions);
                }
                // For defmodule, recurse into its do_block to find nested functions
                if text == "defmodule" {
                    let mut mod_cursor = child.walk();
                    for mod_child in child.children(&mut mod_cursor) {
                        if mod_child.kind() == "do_block" {
                            extract_elixir_functions_detailed(&mod_child, source, functions);
                        }
                    }
                }
            } else {
                extract_elixir_functions_detailed(&child, source, functions);
            }
        } else {
            extract_elixir_functions_detailed(&child, source, functions);
        }
    }
}

fn extract_elixir_function_info(node: &Node, source: &str) -> FunctionInfo {
    // Structure: (call (identifier "def") (arguments (call (identifier "func_name") (arguments ...))))
    // Or: (call (identifier "def") (arguments (identifier "func_name")) (do_block ...))
    let mut name = String::new();
    let mut params = Vec::new();
    let is_private;

    // First child is "def" or "defp"
    if let Some(first) = node.child(0) {
        let text = get_node_text(&first, source);
        is_private = text == "defp";
    } else {
        is_private = false;
    }

    // Second child is arguments containing the function clause
    if let Some(args) = node.child(1) {
        if args.kind() == "arguments" {
            // First child of arguments could be an identifier (no-param function)
            // or a call (function with params)
            if let Some(first_arg) = args.child(0) {
                if first_arg.kind() == "identifier" {
                    name = get_node_text(&first_arg, source);
                } else if first_arg.kind() == "call" {
                    // call node: first child is function name, rest are arguments
                    if let Some(fname) = first_arg.child(0) {
                        if fname.kind() == "identifier" {
                            name = get_node_text(&fname, source);
                        }
                    }
                    // Extract params from the call's arguments
                    if let Some(call_args) = first_arg.child(1) {
                        if call_args.kind() == "arguments" {
                            params = extract_elixir_params(&call_args, source);
                        }
                    }
                } else if first_arg.kind() == "binary_operator" {
                    // Pattern: def func(args) when guard do ... end
                    // The binary_operator wraps the function clause with a guard
                    let mut bin_cursor = first_arg.walk();
                    for bin_child in first_arg.children(&mut bin_cursor) {
                        if bin_child.kind() == "call" {
                            if let Some(fname) = bin_child.child(0) {
                                if fname.kind() == "identifier" {
                                    name = get_node_text(&fname, source);
                                }
                            }
                            if let Some(call_args) = bin_child.child(1) {
                                if call_args.kind() == "arguments" {
                                    params = extract_elixir_params(&call_args, source);
                                }
                            }
                            break;
                        }
                        if bin_child.kind() == "identifier" && name.is_empty() {
                            name = get_node_text(&bin_child, source);
                        }
                    }
                }
            }
        } else if args.kind() == "call" {
            // Direct call without arguments wrapper
            if let Some(fname) = args.child(0) {
                if fname.kind() == "identifier" {
                    name = get_node_text(&fname, source);
                }
            }
            if let Some(call_args) = args.child(1) {
                if call_args.kind() == "arguments" {
                    params = extract_elixir_params(&call_args, source);
                }
            }
        } else if args.kind() == "identifier" {
            name = get_node_text(&args, source);
        }
    }

    let docstring = extract_elixir_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    let _ = is_private; // Could be used for decorators but not needed per spec

    FunctionInfo {
        name,
        params,
        return_type: None, // Elixir is dynamically typed
        docstring,
        is_method: false,
        is_async: false,
        decorators: Vec::new(),
        visibility: None,
        line_number,
        line_end,
        state_mutability: None,
    }
}

fn extract_elixir_params(node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                params.push(get_node_text(&child, source));
            }
            "binary_operator" => {
                // Two distinct Elixir param shapes share the `binary_operator`
                // node kind and must be told apart by the OPERATOR token:
                //   * `opt \\ default` (default value) — the bound name is the
                //     LEFT identifier.
                //   * `%Struct{} = var` / `[h | t] = list` (a match pattern) —
                //     the bound name is on the RIGHT (the left is a map/list/
                //     tuple pattern, not an identifier), so taking the left side
                //     dropped the param entirely and undercounted arity.
                // Inspect the operator child; for `=` take the right identifier,
                // otherwise (default `\\`) keep the historic left-identifier
                // behaviour. As a final fallback, grab the lone identifier among
                // the children so other binder shapes still yield a name.
                let op_is_match = {
                    let mut oc = child.walk();
                    let mut found = false;
                    for c in child.children(&mut oc) {
                        if c.kind() == "=" && get_node_text(&c, source) == "=" {
                            found = true;
                            break;
                        }
                    }
                    found
                };
                if op_is_match {
                    // `pattern = var` — the bound variable is the right side.
                    if let Some(right) = child.child_by_field_name("right") {
                        if right.kind() == "identifier" {
                            params.push(get_node_text(&right, source));
                        } else if let Some(id) = elixir_first_identifier(&right, source) {
                            params.push(id);
                        }
                    } else {
                        // Fallback: last identifier child is the bound var.
                        let mut last_id = None;
                        let mut rc = child.walk();
                        for c in child.children(&mut rc) {
                            if c.kind() == "identifier" {
                                last_id = Some(get_node_text(&c, source));
                            }
                        }
                        if let Some(id) = last_id {
                            params.push(id);
                        }
                    }
                } else if let Some(left) = child.child(0) {
                    // Default value `opt \\ default`: name on the left.
                    if left.kind() == "identifier" {
                        params.push(get_node_text(&left, source));
                    }
                }
            }
            "unary_operator" => {
                // Pattern match like ^pin or \\ operator
                params.push(get_node_text(&child, source));
            }
            "tuple" | "map" | "list" | "sigil" | "string" | "atom" => {
                // Pattern-matched params - use the full text
                params.push(get_node_text(&child, source));
            }
            // Skip commas and parens
            "," | "(" | ")" => {}
            _ => {
                // For other patterns, include as-is
                let text = get_node_text(&child, source);
                if !text.is_empty() && text != "," && text != "(" && text != ")" {
                    params.push(text);
                }
            }
        }
    }

    params
}

/// Find the first `identifier` leaf inside an Elixir pattern node (used to
/// recover the bound variable on the right of a `pattern = var` match param,
/// e.g. the `t` in `[h | t] = var` is not the target — the right side `var`
/// is — but for shapes where the bound name is nested we descend to the first
/// identifier). Returns None if no identifier leaf exists.
fn elixir_first_identifier(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(get_node_text(node, source));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = elixir_first_identifier(&child, source) {
            return Some(found);
        }
    }
    None
}

fn extract_elixir_docstring(node: &Node, source: &str) -> Option<String> {
    // @doc attribute before the function
    // It's a call node with identifier "@doc" followed by the doc content
    let mut prev = node.prev_sibling();

    while let Some(sibling) = prev {
        if sibling.kind() == "call" || sibling.kind() == "unary_operator" {
            let text = get_node_text(&sibling, source);
            if text.starts_with("@doc") {
                // Extract the string content after @doc
                let doc = text.trim_start_matches("@doc").trim();
                if !doc.is_empty() {
                    return Some(doc.to_string());
                }
            }
        }
        // Skip past @spec and other attributes
        if sibling.kind() == "call" || sibling.kind() == "unary_operator" {
            let text = get_node_text(&sibling, source);
            if text.starts_with("@spec") || text.starts_with("@impl") {
                prev = sibling.prev_sibling();
                continue;
            }
        }
        break;
    }

    None
}

fn extract_elixir_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    // Elixir modules (defmodule) are extracted as ClassInfo
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some(first) = child.child(0) {
                let text = get_node_text(&first, source);
                if text == "defmodule" {
                    let info = extract_elixir_module_info(&child, source);
                    classes.push(info);
                } else {
                    extract_elixir_classes_detailed(&child, source, classes);
                }
            }
        } else {
            extract_elixir_classes_detailed(&child, source, classes);
        }
    }
}

fn extract_elixir_module_info(node: &Node, source: &str) -> ClassInfo {
    // defmodule Name do ... end
    // Structure: (call (identifier "defmodule") (arguments (alias "ModuleName")) (do_block ...))
    let mut name = String::new();

    if let Some(args) = node.child(1) {
        if args.kind() == "arguments" {
            let mut cursor = args.walk();
            for child in args.children(&mut cursor) {
                if child.kind() == "alias" {
                    name = get_node_text(&child, source);
                    break;
                }
                // Sometimes it's a dot-qualified alias
                if child.kind() == "call" || child.kind() == "dot" {
                    name = get_node_text(&child, source);
                    break;
                }
            }
        } else if args.kind() == "alias" {
            name = get_node_text(&args, source);
        }
    }

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    // Extract functions from do_block
    let mut methods = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "do_block" {
            extract_elixir_module_functions(&child, source, &mut methods);
        }
    }

    let docstring = extract_elixir_module_docstring(node, source);

    ClassInfo {
        name,
        bases: Vec::new(), // Elixir doesn't have class inheritance
        docstring,
        methods,
        fields: Vec::new(),
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: None,
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
    }
}

fn extract_elixir_module_functions(node: &Node, source: &str, functions: &mut Vec<FunctionInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some(first) = child.child(0) {
                let text = get_node_text(&first, source);
                if text == "def" || text == "defp" {
                    let info = extract_elixir_function_info(&child, source);
                    functions.push(info);
                }
            }
        }
        // Recurse into nested structures (but not nested modules)
        if child.kind() != "call" {
            extract_elixir_module_functions(&child, source, functions);
        }
    }
}

fn extract_elixir_module_docstring(node: &Node, source: &str) -> Option<String> {
    // @moduledoc inside the do_block
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "do_block" {
            let mut body_cursor = child.walk();
            for body_child in child.children(&mut body_cursor) {
                if body_child.kind() == "call" || body_child.kind() == "unary_operator" {
                    let text = get_node_text(&body_child, source);
                    if text.starts_with("@moduledoc") {
                        let doc = text.trim_start_matches("@moduledoc").trim();
                        if !doc.is_empty() {
                            return Some(doc.to_string());
                        }
                    }
                }
                // Only check the first few statements for moduledoc
                if body_child.kind() == "call" {
                    if let Some(first) = body_child.child(0) {
                        let first_text = get_node_text(&first, source);
                        if first_text == "def" || first_text == "defp" {
                            break;
                        }
                    }
                }
            }
        }
    }

    None
}

// =============================================================================
// solidity-ast-extract-v1 (v0.5.0 SOL-003): Solidity detailed extraction.
//
// Modeled on the Kotlin extractor template (per oracle research): Solidity's
// `function_definition` carries `visibility` / `state_mutability` /
// `modifier_invocation` / `virtual` / `override_specifier` as named sibling
// children of the decl node — the same shape Kotlin uses for its
// `modifiers > visibility_modifier` + `modifiers > annotation` pattern.
// Cross-references Java's `extract_java_class_bases` for the unified
// inheritance-list flattening pattern (Solidity `is A, B` -> `bases =
// ["A", "B"]`).
//
// AST node kinds covered:
//   - `function_definition`, `constructor_definition`,
//     `fallback_receive_definition`           (functions/methods)
//   - `modifier_definition`                   (ModifierInfo)
//   - `event_definition` / `event_parameter`  (EventInfo + indexed flag)
//   - `error_declaration` / `error_parameter` (ErrorInfo)
//   - `contract_declaration`, `interface_declaration`,
//     `library_declaration`                   (ClassInfo with `kind`)
//   - `inheritance_specifier > user_defined_type > identifier`
//   - `state_variable_declaration`,
//     `constant_variable_declaration`         (FieldInfo / FieldInfo[is_constant])
//   - `parameter` / `return_parameter`        (name/type field walk)
//   - `visibility`, `state_mutability`        (named keyword nodes — text IS the keyword)
//   - `modifier_invocation`                   (first identifier child IS the modifier name)
//
// NatSpec docstring handling: NatSpec comments (`///` single-line and `/** */`
// block) are emitted as `comment` nodes inside `source_file` or
// `contract_body`. We walk preceding sibling `comment` nodes upward, joining
// consecutive `///` lines into one docstring; `/**` block comments are
// delivered verbatim (Phase 10 will further structure `@notice` / `@param`).
// =============================================================================

/// Walk `node` (typically `source_file` or `contract_body`) collecting
/// `function_definition` / `constructor_definition` /
/// `fallback_receive_definition` children. When `is_method` is `true`,
/// the produced `FunctionInfo` will be tagged accordingly.
///
/// This is called both at file-scope (`source_file`, `is_method=false`)
/// and inside contract/interface/library bodies (via
/// `extract_solidity_classes_detailed`, `is_method=true`).
fn extract_solidity_functions_detailed(
    node: &Node,
    source: &str,
    functions: &mut Vec<FunctionInfo>,
    is_method: bool,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                let info = extract_solidity_function_info(&child, source, is_method);
                functions.push(info);
            }
            "constructor_definition" => {
                let info = extract_solidity_constructor_info(&child, source, is_method);
                functions.push(info);
            }
            "fallback_receive_definition" => {
                let info = extract_solidity_fallback_info(&child, source, is_method);
                functions.push(info);
            }
            // Stop at contract-like boundaries when walking file scope —
            // their member functions are emitted via class extraction.
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration"
            | "contract_body" => { /* handled by class extractor */ }
            _ => {
                // Recurse to find functions nested under non-decl wrappers.
                extract_solidity_functions_detailed(&child, source, functions, is_method);
            }
        }
    }
}

fn extract_solidity_function_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let param_infos = extract_solidity_params(node, source);
    let params: Vec<String> = param_infos.into_iter().map(|p| p.name).collect();
    let return_type = extract_solidity_return_type(node, source);
    let docstring = extract_solidity_docstring(node, source);
    let visibility = extract_solidity_visibility(node, source);
    // solidity-sol013-cluster-v1 (v0.5.0 SOL-013 M3): state_mutability
    // (pure/view/payable) is grammatically a Solidity "function modifier"
    // (slotted alongside `visibility` / `modifier_invocation` in the
    // tree-sitter grammar), but semantically distinct from user-defined
    // modifier invocations like `onlyOwner` / `nonReentrant`. SOL-003
    // originally stuffed it into `decorators` alongside modifier
    // invocations, conflating two distinct concepts. Now we populate
    // `FunctionInfo.state_mutability` as its own slot and `decorators`
    // carries ONLY the user-defined modifier invocations.
    let state_mutability = extract_solidity_state_mutability(node, source);
    let decorators = extract_solidity_modifier_invocations(node, source);

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type,
        docstring,
        is_method,
        is_async: false, // Solidity has no async keyword
        decorators,
        visibility,
        line_number,
        line_end,
        state_mutability,
    }
}

fn extract_solidity_constructor_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    let param_infos = extract_solidity_params(node, source);
    let params: Vec<String> = param_infos.into_iter().map(|p| p.name).collect();
    let docstring = extract_solidity_docstring(node, source);
    let modifier_invocations = extract_solidity_modifier_invocations(node, source);
    // solidity-sol013-cluster-v1 M3: a constructor may be `payable`
    // (`constructor() payable { ... }`). Surface that as
    // state_mutability rather than letting it leak into decorators.
    let state_mutability = extract_solidity_state_mutability(node, source);

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name: "constructor".to_string(),
        params,
        return_type: None,
        docstring,
        is_method,
        is_async: false,
        decorators: modifier_invocations,
        visibility: extract_solidity_visibility(node, source),
        line_number,
        line_end,
        state_mutability,
    }
}

fn extract_solidity_fallback_info(node: &Node, source: &str, is_method: bool) -> FunctionInfo {
    // `fallback_receive_definition` covers both `fallback() external` and
    // `receive() external payable`. The keyword (`fallback` / `receive`)
    // is the first unnamed child token; use it as the function name.
    let mut name = String::from("fallback");
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "fallback" || kind == "receive" {
            name = kind.to_string();
            break;
        }
        let txt = get_node_text(&child, source);
        if txt == "fallback" || txt == "receive" {
            name = txt;
            break;
        }
    }

    let param_infos = extract_solidity_params(node, source);
    let params: Vec<String> = param_infos.into_iter().map(|p| p.name).collect();
    let docstring = extract_solidity_docstring(node, source);
    // solidity-sol013-cluster-v1 M3: separate state_mutability (typically
    // `payable` on `receive() external payable { ... }`) from user-defined
    // modifier invocations. See `extract_solidity_function_info` for the
    // rationale.
    let state_mutability = extract_solidity_state_mutability(node, source);
    let decorators = extract_solidity_modifier_invocations(node, source);

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    FunctionInfo {
        name,
        params,
        return_type: None,
        docstring,
        is_method,
        is_async: false,
        decorators,
        visibility: extract_solidity_visibility(node, source),
        line_number,
        line_end,
        state_mutability,
    }
}

/// Walk `parameter` children of a Solidity decl node. Each `parameter`
/// has a `type` field and an optional `name` field. Returns one
/// `ParamInfo` per parameter (preserving anonymous params with empty
/// names).
fn extract_solidity_params(node: &Node, source: &str) -> Vec<ParamInfo> {
    let mut params = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameter" {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();
            let type_ = child
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source));
            params.push(ParamInfo {
                name,
                type_,
                default_value: None,
            });
        }
    }
    params
}

/// Walk `event_parameter` children of an `event_definition`. Each carries
/// a `type` field, an optional `name` field, AND an unnamed `indexed`
/// keyword token between the type and name when the param is indexed.
fn extract_solidity_event_params(node: &Node, source: &str) -> Vec<EventParamInfo> {
    let mut params = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "event_parameter" {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();
            let type_ = child
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();
            // `indexed` is an anonymous (unnamed) child token. Look for
            // a child whose text equals "indexed".
            let mut indexed = false;
            let mut ec = child.walk();
            for ec_child in child.children(&mut ec) {
                if ec_child.kind() == "indexed"
                    || get_node_text(&ec_child, source) == "indexed"
                {
                    indexed = true;
                    break;
                }
            }
            params.push(EventParamInfo {
                name,
                type_,
                indexed,
            });
        }
    }
    params
}

/// Walk `error_parameter` children of an `error_declaration`. Like
/// `extract_solidity_params` but for the slightly different
/// `error_parameter` node kind (same field shape: `name` + `type`).
fn extract_solidity_error_params(node: &Node, source: &str) -> Vec<ParamInfo> {
    let mut params = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "error_parameter" {
            let name = child
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))
                .unwrap_or_default();
            let type_ = child
                .child_by_field_name("type")
                .map(|n| get_node_text(&n, source));
            params.push(ParamInfo {
                name,
                type_,
                default_value: None,
            });
        }
    }
    params
}

/// Extract the return type as joined `parameter` type-text from the
/// `return_type_definition` child of a `function_definition`. Returns
/// `None` when no `returns (...)` clause is present.
fn extract_solidity_return_type(node: &Node, source: &str) -> Option<String> {
    let rt = node.child_by_field_name("return_type")?;
    let mut parts = Vec::new();
    let mut cursor = rt.walk();
    for child in rt.children(&mut cursor) {
        if child.kind() == "parameter" {
            if let Some(t) = child.child_by_field_name("type") {
                parts.push(get_node_text(&t, source));
            }
        }
    }
    if parts.is_empty() {
        None
    } else if parts.len() == 1 {
        Some(parts.into_iter().next().unwrap())
    } else {
        Some(format!("({})", parts.join(", ")))
    }
}

/// Scan the `visibility` named child of a Solidity decl. The grammar
/// emits a `visibility` node whose text IS the keyword
/// (`public` / `external` / `internal` / `private`).
fn extract_solidity_visibility(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility" {
            let t = get_node_text(&child, source);
            let t = t.trim();
            if matches!(t, "public" | "external" | "internal" | "private") {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Scan the `state_mutability` named child of a Solidity function decl.
/// Returns `"pure"` / `"view"` / `"payable"` when present. `None` means
/// the default (`nonpayable`) was used — we don't synthesize the
/// default so callers can distinguish "unspecified" from "explicit".
///
/// solidity-sol013-cluster-v1 (v0.5.0 SOL-013 M3): the tree-sitter-solidity
/// 1.2.13 grammar emits a named `state_mutability` child for
/// `function_definition` and `fallback_receive_definition` but NOT for
/// `constructor_definition` — there `payable` appears as an unnamed
/// terminal token child with `kind() == "payable"` directly under the
/// `constructor_definition` node (s-expr: `(constructor_definition body:
/// (function_body))` with `payable` consumed silently). We therefore
/// also accept the unnamed-token form so `constructor() payable {}`
/// surfaces `state_mutability="payable"`. This is still AST-driven —
/// we read the kinds the grammar produces, no regex over source text.
fn extract_solidity_state_mutability(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Named-child form: function_definition, fallback_receive_definition
        if child.kind() == "state_mutability" {
            let t = get_node_text(&child, source);
            let t = t.trim();
            if matches!(t, "pure" | "view" | "payable") {
                return Some(t.to_string());
            }
        }
        // Unnamed-token form: constructor_definition swallows the keyword
        // as a terminal child whose `kind()` is the keyword itself.
        if !child.is_named() {
            let k = child.kind();
            if matches!(k, "pure" | "view" | "payable") {
                return Some(k.to_string());
            }
        }
    }
    None
}

/// Walk `modifier_invocation` children of a Solidity function/constructor/
/// fallback/receive decl and collect the modifier names. Each
/// `modifier_invocation` has the modifier name as its first
/// `identifier` child (e.g. `onlyOwner`, `nonReentrant`) plus optional
/// `call_argument` children we ignore for v1.
fn extract_solidity_modifier_invocations(node: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifier_invocation" {
            let mut mc = child.walk();
            for mc_child in child.children(&mut mc) {
                if mc_child.kind() == "identifier" {
                    names.push(get_node_text(&mc_child, source));
                    break;
                }
            }
        }
    }
    names
}

/// Whether `node` carries the `virtual` keyword as a named child.
fn solidity_has_virtual(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "virtual" {
            return true;
        }
    }
    false
}

/// Whether `node` carries an `override_specifier` named child.
fn solidity_has_override(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "override_specifier" {
            return true;
        }
    }
    false
}

/// Public re-export of [`extract_solidity_docstring`] so downstream
/// crates (e.g. `tldr-cli`'s contracts command) can re-collect the raw
/// NatSpec text from a Solidity function/contract node before feeding it
/// to [`parse_solidity_natspec`].
pub fn collect_solidity_natspec_text(node: &Node, source: &str) -> Option<String> {
    extract_solidity_docstring(node, source)
}

/// Walk preceding sibling `comment` nodes and collect contiguous NatSpec
/// comments. Returns `None` when no NatSpec is present. Preserves leading
/// `///`-stripped lines verbatim (per Phase 10 plan; structured `@notice`
/// / `@param` parsing is downstream).
///
/// - `///` (single-line NatSpec): walk back, accept consecutive lines.
/// - `/** ... */` (block NatSpec): single comment, return verbatim
///   (preserving `@notice`/`@param`/`@dev` markup).
fn extract_solidity_docstring(node: &Node, source: &str) -> Option<String> {
    let mut prev = node.prev_sibling();
    let mut single_line_docs: Vec<String> = Vec::new();

    while let Some(sib) = prev {
        if sib.kind() == "comment" {
            let text = get_node_text(&sib, source);
            let trimmed = text.trim_start();
            if trimmed.starts_with("/**") {
                // Block NatSpec: if we already collected single-line
                // docs, the block predates them — those single-line docs
                // win (they're closer to the decl). Otherwise return the
                // block comment verbatim.
                if single_line_docs.is_empty() {
                    return Some(text);
                } else {
                    break;
                }
            }
            if trimmed.starts_with("///") {
                // Strip the leading `///` and one space.
                let stripped = trimmed.trim_start_matches("///");
                let stripped = stripped.strip_prefix(' ').unwrap_or(stripped);
                single_line_docs.push(stripped.to_string());
                prev = sib.prev_sibling();
                continue;
            }
            // Plain `//` comment — not NatSpec, stop.
            break;
        }
        // Skip non-comment whitespace / inheritance markers that may
        // appear between the decl and its docstring (defensive — the
        // grammar generally doesn't emit such nodes here).
        break;
    }

    if single_line_docs.is_empty() {
        None
    } else {
        // We walked backward, so reverse to source order.
        single_line_docs.reverse();
        Some(single_line_docs.join("\n"))
    }
}

// =============================================================================
// solidity-natspec-v1 (v0.5.0 SOL-010): NatSpec doc-comment parser.
//
// NatSpec lives in regular `comment` nodes (`///` single-line or `/** */`
// block). This module converts the *text* of one such comment block into
// a structured `NatSpecDoc` so downstream consumers (e.g. the contracts
// command) can map `@param NAME text` onto preconditions and
// `@return [NAME] text` onto postconditions without re-implementing the
// comment-text grammar.
//
// Reference: https://docs.soliditylang.org/en/latest/natspec-format.html
// Supported tags (v1):
//   - `@title <text>`         → metadata
//   - `@author <text>`        → metadata
//   - `@notice <text>`        → user-facing notice
//   - `@dev <text>`           → developer-facing notes
//   - `@param NAME <text>`    → parameter doc (precondition material)
//   - `@return [NAME] <text>` → return doc (postcondition material)
//   - `@inheritdoc CONTRACT`  → inherits docs from `CONTRACT`
//   - `@custom:KEY <text>`    → arbitrary custom tag
// =============================================================================

/// A NatSpec `@param NAME text` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatSpecParam {
    /// Parameter name (token after `@param`).
    pub name: String,
    /// Free-form description text following the name.
    pub text: String,
}

/// A NatSpec `@return [NAME] text` entry.
///
/// The `name` slot is optional: `@return result The product` carries
/// `name = Some("result")` and `text = "The product"`, while
/// `@return The product` carries `name = None` and `text = "The product"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatSpecReturn {
    /// Optional return-value name (when the function declares named returns).
    pub name: Option<String>,
    /// Free-form description text.
    pub text: String,
}

/// Structured representation of a Solidity NatSpec doc-comment block.
///
/// Multi-line tag values are joined with single spaces. Tags appearing
/// multiple times for the same key (e.g. `@param`) produce one entry per
/// occurrence; `@custom:KEY` aggregates multiple values under the same
/// key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatSpecDoc {
    /// `@title <text>`
    pub title: Option<String>,
    /// `@author <text>`
    pub author: Option<String>,
    /// `@notice <text>` (user-facing).
    pub notice: Option<String>,
    /// `@dev <text>` (developer-facing).
    pub dev: Option<String>,
    /// All `@param NAME <text>` entries in source order.
    pub params: Vec<NatSpecParam>,
    /// All `@return [NAME] <text>` entries in source order.
    pub returns: Vec<NatSpecReturn>,
    /// `@inheritdoc CONTRACT` target (when present).
    pub inheritdoc: Option<String>,
    /// `@custom:KEY <text>` entries — KEY → list of texts.
    pub custom_tags: std::collections::HashMap<String, Vec<String>>,
}

/// Parse a Solidity NatSpec doc-comment text block into a [`NatSpecDoc`].
///
/// Accepts both `///`-stripped single-line accumulations (one tag per
/// line) and verbatim `/** ... */` block-comment text. For block text,
/// the parser strips the surrounding `/**` / `*/` markers and the
/// leading `*` / `* ` per-line continuation marker before scanning for
/// `@tag` lines.
///
/// Continuation lines (lines that do not start with `@`) are appended to
/// the previous tag's text with a single space separator.
pub fn parse_solidity_natspec(text: &str) -> NatSpecDoc {
    let mut doc = NatSpecDoc::default();

    // Normalize: strip block comment markers and `*` line prefixes so
    // both `///`-stripped accumulations and verbatim `/** */` blocks
    // produce the same line set.
    let normalized = normalize_natspec_text(text);

    // Walk lines, collecting tag → text pairs. Continuation lines (lines
    // not starting with `@`) extend the previous tag's text.
    let mut entries: Vec<(String, String)> = Vec::new();
    for raw in normalized.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('@') {
            // New tag. Split on the first whitespace into (tag_key, body).
            let (tag_key, body) = match rest.find(char::is_whitespace) {
                Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].trim().to_string()),
                None => (rest.to_string(), String::new()),
            };
            entries.push((tag_key, body));
        } else if let Some(last) = entries.last_mut() {
            // Continuation: append to previous tag's body.
            if !last.1.is_empty() {
                last.1.push(' ');
            }
            last.1.push_str(line);
        }
        // Lines before the first tag are ignored (free-form prose).
    }

    // Dispatch tag → field. Order matters for first-wins semantics on
    // singleton tags (title/author/notice/dev/inheritdoc).
    for (tag, body) in entries {
        match tag.as_str() {
            "title" => {
                if doc.title.is_none() {
                    doc.title = Some(body);
                }
            }
            "author" => {
                if doc.author.is_none() {
                    doc.author = Some(body);
                }
            }
            "notice" => {
                if doc.notice.is_none() {
                    doc.notice = Some(body);
                }
            }
            "dev" => {
                if doc.dev.is_none() {
                    doc.dev = Some(body);
                }
            }
            "param" => {
                // `@param NAME rest...` — split on first whitespace.
                let (name, text) = match body.find(char::is_whitespace) {
                    Some(idx) => (body[..idx].to_string(), body[idx + 1..].trim().to_string()),
                    None => (body, String::new()),
                };
                if !name.is_empty() {
                    doc.params.push(NatSpecParam { name, text });
                }
            }
            "return" => {
                // `@return NAME text...` OR `@return text...` (no name).
                // Heuristic: if the first whitespace-delimited token is a
                // valid identifier (starts with letter or `_`, followed
                // by alphanumerics/underscore) AND there is more text
                // after it, treat as named. Otherwise, no name.
                let (maybe_name, rest) = match body.find(char::is_whitespace) {
                    Some(idx) => (
                        body[..idx].to_string(),
                        body[idx + 1..].trim().to_string(),
                    ),
                    None => (body.clone(), String::new()),
                };
                if is_natspec_identifier(&maybe_name) && !rest.is_empty() {
                    doc.returns.push(NatSpecReturn {
                        name: Some(maybe_name),
                        text: rest,
                    });
                } else {
                    doc.returns.push(NatSpecReturn {
                        name: None,
                        text: body,
                    });
                }
            }
            "inheritdoc" => {
                if doc.inheritdoc.is_none() && !body.is_empty() {
                    // `@inheritdoc CONTRACT` — first token is the contract name.
                    let target = body
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if !target.is_empty() {
                        doc.inheritdoc = Some(target);
                    }
                }
            }
            other => {
                // `@custom:KEY value` aggregates under custom_tags["KEY"].
                if let Some(key) = other.strip_prefix("custom:") {
                    if !key.is_empty() {
                        doc.custom_tags
                            .entry(key.to_string())
                            .or_default()
                            .push(body);
                    }
                }
                // Unknown tags are dropped silently in v1 (consistent with
                // the JSDoc / Sphinx parsers above).
            }
        }
    }

    doc
}

/// Strip block-comment markers (`/**`, `*/`) and leading `*` / `* `
/// continuation markers from a NatSpec text block. Single-line `///`
/// accumulations pass through untouched.
fn normalize_natspec_text(text: &str) -> String {
    // Strip `/**` opener and `*/` closer if present.
    let trimmed = text.trim();
    let inner = trimmed
        .strip_prefix("/**")
        .map(|s| s.strip_suffix("*/").unwrap_or(s))
        .unwrap_or(trimmed);

    let mut out = String::new();
    for line in inner.lines() {
        let t = line.trim();
        // Block-comment continuation: lines often start with `* ` or `*`.
        let t = t.strip_prefix("* ").unwrap_or(t.strip_prefix('*').unwrap_or(t));
        out.push_str(t);
        out.push('\n');
    }
    out
}

/// Return `true` if `s` is a *likely* Solidity return-value name (used
/// to decide whether `@return TOKEN rest...` carries a name slot).
///
/// We cannot resolve this perfectly from text alone — the NatSpec spec
/// says the first token is the name iff the function declares named
/// returns, which the parser does not see. We approximate with: starts
/// with `_` or an ASCII lowercase letter (Solidity camelCase / snake_case
/// convention) AND every subsequent char is alphanumeric or `_`. This
/// rejects English prose tokens like `"The"` while accepting `result`,
/// `out_`, `_x`, etc.
fn is_natspec_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Walk a Solidity scope (`source_file` or `contract_body`) and emit
/// `ModifierInfo` for every `modifier_definition` child. When
/// `file_scope = true` ONLY top-level modifiers are emitted (skipping
/// contract bodies, which are handled by `extract_solidity_classes_detailed`).
fn extract_solidity_modifiers(node: &Node, source: &str, file_scope: bool) -> Vec<ModifierInfo> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "modifier_definition" => {
                out.push(build_solidity_modifier_info(&child, source));
            }
            "contract_declaration" | "interface_declaration" | "library_declaration" => {
                // At file scope, do not descend into contract bodies —
                // their member modifiers belong to the ClassInfo.
                if !file_scope {
                    extract_solidity_modifiers_into(&child, source, &mut out);
                }
            }
            _ => {
                // Recurse into other wrappers (rare).
                extract_solidity_modifiers_into(&child, source, &mut out);
            }
        }
    }
    out
}

fn extract_solidity_modifiers_into(node: &Node, source: &str, out: &mut Vec<ModifierInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifier_definition" {
            out.push(build_solidity_modifier_info(&child, source));
        } else {
            extract_solidity_modifiers_into(&child, source, out);
        }
    }
}

fn build_solidity_modifier_info(node: &Node, source: &str) -> ModifierInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();
    let params = extract_solidity_params(node, source);
    let is_virtual = solidity_has_virtual(node);
    let is_override = solidity_has_override(node);
    let body_present = node.child_by_field_name("body").is_some();
    let line_number = node.start_position().row as u32 + 1;

    ModifierInfo {
        name,
        line_number,
        params,
        is_virtual,
        is_override,
        body_present,
    }
}

/// Walk a Solidity scope and emit `EventInfo` for every `event_definition`.
fn extract_solidity_events(node: &Node, source: &str, file_scope: bool) -> Vec<EventInfo> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "event_definition" => {
                out.push(build_solidity_event_info(&child, source));
            }
            "contract_declaration" | "interface_declaration" | "library_declaration" => {
                if !file_scope {
                    extract_solidity_events_into(&child, source, &mut out);
                }
            }
            _ => {
                extract_solidity_events_into(&child, source, &mut out);
            }
        }
    }
    out
}

fn extract_solidity_events_into(node: &Node, source: &str, out: &mut Vec<EventInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "event_definition" {
            out.push(build_solidity_event_info(&child, source));
        } else {
            extract_solidity_events_into(&child, source, out);
        }
    }
}

fn build_solidity_event_info(node: &Node, source: &str) -> EventInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();
    let params = extract_solidity_event_params(node, source);
    // `anonymous` is an unnamed token child when present.
    let mut is_anonymous = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "anonymous" || get_node_text(&child, source) == "anonymous" {
            is_anonymous = true;
            break;
        }
    }
    let line_number = node.start_position().row as u32 + 1;

    EventInfo {
        name,
        line_number,
        params,
        is_anonymous,
    }
}

/// Walk a Solidity scope and emit `ErrorInfo` for every `error_declaration`.
fn extract_solidity_errors(node: &Node, source: &str, file_scope: bool) -> Vec<ErrorInfo> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "error_declaration" => {
                out.push(build_solidity_error_info(&child, source));
            }
            "contract_declaration" | "interface_declaration" | "library_declaration" => {
                if !file_scope {
                    extract_solidity_errors_into(&child, source, &mut out);
                }
            }
            _ => {
                extract_solidity_errors_into(&child, source, &mut out);
            }
        }
    }
    out
}

fn extract_solidity_errors_into(node: &Node, source: &str, out: &mut Vec<ErrorInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "error_declaration" {
            out.push(build_solidity_error_info(&child, source));
        } else {
            extract_solidity_errors_into(&child, source, out);
        }
    }
}

fn build_solidity_error_info(node: &Node, source: &str) -> ErrorInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();
    let params = extract_solidity_error_params(node, source);
    let line_number = node.start_position().row as u32 + 1;

    ErrorInfo {
        name,
        line_number,
        params,
    }
}

/// Walk a Solidity source file and emit `ClassInfo` for every
/// `contract_declaration` / `interface_declaration` /
/// `library_declaration`. Each `ClassInfo` gets:
/// - `kind = Some("contract" | "interface" | "library")`
/// - `bases = [...]` flattened from `inheritance_specifier` children
///   (Java-template pattern: the unified base list).
/// - `methods` from `function_definition` / `constructor_definition` /
///   `fallback_receive_definition` children of `contract_body`.
/// - `modifiers`, `events`, `errors` from the same scope.
/// - `fields` from `state_variable_declaration` and
///   `constant_variable_declaration` children.
fn extract_solidity_classes_detailed(node: &Node, source: &str, classes: &mut Vec<ClassInfo>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "contract_declaration" => {
                let info = build_solidity_class_info(&child, source, "contract");
                classes.push(info);
            }
            "interface_declaration" => {
                let info = build_solidity_class_info(&child, source, "interface");
                classes.push(info);
            }
            "library_declaration" => {
                let info = build_solidity_class_info(&child, source, "library");
                classes.push(info);
            }
            _ => {
                // Recurse to find nested or wrapped decls (rare).
                extract_solidity_classes_detailed(&child, source, classes);
            }
        }
    }
}

fn build_solidity_class_info(node: &Node, source: &str, kind: &str) -> ClassInfo {
    let name = node
        .child_by_field_name("name")
        .map(|n| get_node_text(&n, source))
        .unwrap_or_default();

    let bases = extract_solidity_class_bases(node, source);
    let docstring = extract_solidity_docstring(node, source);
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    let mut methods = Vec::new();
    let mut modifiers = Vec::new();
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut fields = Vec::new();

    if let Some(body) = node.child_by_field_name("body") {
        // Collect methods directly from the contract body. `is_method=true`
        // because they are class members.
        extract_solidity_functions_detailed(&body, source, &mut methods, true);
        // Collect contract-scope modifiers/events/errors. `file_scope=false`
        // is the wrong term here — we just want to harvest direct children
        // of this body. Use the `_into` helpers which collect from a
        // specific scope without the file/contract dispatch.
        let mut bc = body.walk();
        for body_child in body.children(&mut bc) {
            match body_child.kind() {
                "modifier_definition" => {
                    modifiers.push(build_solidity_modifier_info(&body_child, source));
                }
                "event_definition" => {
                    events.push(build_solidity_event_info(&body_child, source));
                }
                "error_declaration" => {
                    errors.push(build_solidity_error_info(&body_child, source));
                }
                "state_variable_declaration" => {
                    if let Some(f) = build_solidity_state_variable_field(&body_child, source) {
                        fields.push(f);
                    }
                }
                "constant_variable_declaration" => {
                    if let Some(f) = build_solidity_constant_field(&body_child, source) {
                        fields.push(f);
                    }
                }
                _ => {}
            }
        }
    }

    ClassInfo {
        name,
        bases,
        docstring,
        methods,
        fields,
        decorators: Vec::new(),
        line_number,
        line_end,
        kind: Some(kind.to_string()),
        modifiers,
        events,
        errors,
    }
}

/// Flatten `is A, B` inheritance into `Vec<String>`, modeled on Java's
/// `extract_java_class_bases` (which similarly unifies superclass +
/// implements into a single list). For Solidity each
/// `inheritance_specifier` has an `ancestor` field of type
/// `user_defined_type`; we walk inside to find the bare identifier.
fn extract_solidity_class_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "inheritance_specifier" {
            if let Some(ancestor) = child.child_by_field_name("ancestor") {
                if let Some(name) = solidity_user_defined_type_name(&ancestor, source) {
                    bases.push(name);
                }
            } else {
                // Fallback: scan for user_defined_type child directly.
                let mut ic = child.walk();
                for ichild in child.children(&mut ic) {
                    if ichild.kind() == "user_defined_type" {
                        if let Some(name) = solidity_user_defined_type_name(&ichild, source) {
                            bases.push(name);
                        }
                        break;
                    }
                }
            }
        }
    }
    bases
}

/// Extract the bare identifier of a `user_defined_type` node. The grammar
/// wraps the name in an identifier child (possibly `member_expression`
/// for namespaced types like `OpenZeppelin.Ownable` — for v1 we surface
/// just the leaf name when nested, or the full text otherwise).
fn solidity_user_defined_type_name(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => return Some(get_node_text(&child, source)),
            "member_expression" => return Some(get_node_text(&child, source)),
            _ => {}
        }
    }
    // Fallback to the whole node text.
    Some(get_node_text(node, source))
}

/// Build a `FieldInfo` for a contract-scope `state_variable_declaration`.
fn build_solidity_state_variable_field(node: &Node, source: &str) -> Option<FieldInfo> {
    let name = node.child_by_field_name("name")?;
    let name = get_node_text(&name, source);
    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));
    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));
    let visibility = node
        .child_by_field_name("visibility")
        .map(|n| {
            let t = get_node_text(&n, source);
            t.trim().to_string()
        })
        .filter(|s| matches!(s.as_str(), "public" | "external" | "internal" | "private"));

    // `immutable` is a child token. Treat immutable state vars as
    // constants for downstream consumers (they cannot be reassigned).
    let mut is_immutable = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "immutable" {
            is_immutable = true;
            break;
        }
    }

    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static: false,
        is_constant: is_immutable,
        visibility,
        line_number,
        line_end,
    })
}

/// Build a `FieldInfo` for `constant_variable_declaration` (top-level
/// or contract-scope `uint256 constant FOO = 1`).
fn build_solidity_constant_field(node: &Node, source: &str) -> Option<FieldInfo> {
    let name = node.child_by_field_name("name")?;
    let name = get_node_text(&name, source);
    let field_type = node
        .child_by_field_name("type")
        .map(|n| get_node_text(&n, source));
    let default_value = node
        .child_by_field_name("value")
        .map(|n| get_node_text(&n, source));
    let line_number = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;

    Some(FieldInfo {
        name,
        field_type,
        default_value,
        is_static: true,
        is_constant: true,
        visibility: None,
        line_number,
        line_end,
    })
}

/// Extract file-scope `constant_variable_declaration` as module constants.
fn extract_solidity_module_constants(root: &Node, source: &str) -> Vec<FieldInfo> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "constant_variable_declaration" {
            if let Some(f) = build_solidity_constant_field(&child, source) {
                out.push(f);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_python_file() {
        let mut file = NamedTempFile::with_suffix(".py").unwrap();
        write!(
            file,
            r#"
"""Module docstring."""

def foo():
    """Function docstring."""
    bar()

def bar():
    pass
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();

        assert_eq!(info.language, Language::Python);
        assert!(info.docstring.is_some());
        assert_eq!(info.functions.len(), 2);
        assert!(info.functions.iter().any(|f| f.name == "foo"));
        assert!(info.call_graph.calls.contains_key("foo"));
    }

    #[test]
    fn test_extract_handles_file_not_found() {
        let result = extract_file(Path::new("/nonexistent/file.py"), None);
        assert!(matches!(result, Err(TldrError::PathNotFound(_))));
    }

    #[test]
    fn test_extract_handles_unsupported_language() {
        let mut file = NamedTempFile::with_suffix(".xyz").unwrap();
        write!(file, "unknown language").unwrap();

        let result = extract_file(file.path(), None);
        assert!(matches!(result, Err(TldrError::UnsupportedLanguage(_))));
    }

    #[test]
    fn test_extract_calls_in_conditional_branches() {
        let mut file = NamedTempFile::with_suffix(".py").unwrap();
        write!(
            file,
            r#"
def get_imports(file, lang):
    if lang == "python":
        return parse_imports(file)
    elif lang == "go":
        return parse_go_imports(file)
    elif lang == "java":
        return parse_java_imports(file)
    else:
        return default_imports(file)

def parse_imports(f):
    pass

def parse_go_imports(f):
    pass

def parse_java_imports(f):
    pass

def default_imports(f):
    pass
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let calls = info
            .call_graph
            .calls
            .get("get_imports")
            .expect("get_imports should have calls");
        assert!(
            calls.contains(&"parse_imports".to_string()),
            "should find parse_imports in if branch"
        );
        assert!(
            calls.contains(&"parse_go_imports".to_string()),
            "should find parse_go_imports in elif branch"
        );
        assert!(
            calls.contains(&"parse_java_imports".to_string()),
            "should find parse_java_imports in elif branch"
        );
        assert!(
            calls.contains(&"default_imports".to_string()),
            "should find default_imports in else branch"
        );
    }

    #[test]
    fn test_extract_calls_in_for_while_with_try() {
        let mut file = NamedTempFile::with_suffix(".py").unwrap();
        write!(
            file,
            r#"
def process(items):
    for item in items:
        transform(item)
    while check_pending():
        flush()
    with open_resource() as r:
        read_data(r)
    try:
        risky_op()
    except Exception:
        handle_error()

def transform(x):
    pass

def check_pending():
    pass

def flush():
    pass

def open_resource():
    pass

def read_data(r):
    pass

def risky_op():
    pass

def handle_error():
    pass
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let calls = info
            .call_graph
            .calls
            .get("process")
            .expect("process should have calls");
        assert!(
            calls.contains(&"transform".to_string()),
            "should find transform in for loop"
        );
        assert!(
            calls.contains(&"check_pending".to_string()),
            "should find check_pending in while"
        );
        assert!(
            calls.contains(&"flush".to_string()),
            "should find flush in while body"
        );
        assert!(
            calls.contains(&"open_resource".to_string()),
            "should find open_resource in with"
        );
        assert!(
            calls.contains(&"read_data".to_string()),
            "should find read_data in with body"
        );
        assert!(
            calls.contains(&"risky_op".to_string()),
            "should find risky_op in try"
        );
        assert!(
            calls.contains(&"handle_error".to_string()),
            "should find handle_error in except"
        );
    }

    #[test]
    fn test_extract_calls_duplicate_method_names_across_classes() {
        // BUG: When multiple classes have methods with the same name,
        // find_and_extract_calls only finds the FIRST matching method,
        // causing all same-named methods to share the same call list.
        let mut file = NamedTempFile::with_suffix(".py").unwrap();
        write!(
            file,
            r#"
class Alpha:
    def process(self):
        alpha_helper()

    def visit(self):
        visit_alpha()

class Beta:
    def process(self):
        beta_helper()

    def visit(self):
        visit_beta()

def alpha_helper():
    pass

def beta_helper():
    pass

def visit_alpha():
    pass

def visit_beta():
    pass
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let calls = &info.call_graph.calls;

        // The "process" key should contain calls from BOTH Alpha.process AND Beta.process
        let process_calls = calls.get("process").expect("process should have calls");
        assert!(
            process_calls.contains(&"alpha_helper".to_string()),
            "should find alpha_helper from Alpha.process, got: {:?}",
            process_calls
        );
        assert!(
            process_calls.contains(&"beta_helper".to_string()),
            "should find beta_helper from Beta.process, got: {:?}",
            process_calls
        );

        // The "visit" key should contain calls from BOTH Alpha.visit AND Beta.visit
        let visit_calls = calls.get("visit").expect("visit should have calls");
        assert!(
            visit_calls.contains(&"visit_alpha".to_string()),
            "should find visit_alpha from Alpha.visit, got: {:?}",
            visit_calls
        );
        assert!(
            visit_calls.contains(&"visit_beta".to_string()),
            "should find visit_beta from Beta.visit, got: {:?}",
            visit_calls
        );
    }

    #[test]
    fn test_extract_python_params() {
        use crate::ast::parser::parse;

        let source = r#"
def foo(x, y):
    pass

def bar(items: list) -> int:
    return 0

def baz(a: int, b: str = "default") -> None:
    pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Python);

        let foo = functions.iter().find(|f| f.name == "foo").unwrap();
        assert_eq!(foo.params, vec!["x".to_string(), "y".to_string()]);

        let bar = functions.iter().find(|f| f.name == "bar").unwrap();
        assert_eq!(bar.params, vec!["items".to_string()]);

        let baz = functions.iter().find(|f| f.name == "baz").unwrap();
        assert_eq!(baz.params, vec!["a".to_string(), "b".to_string()]);
    }

    // =========================================================================
    // Lua extraction tests
    // =========================================================================

    #[test]
    fn test_extract_lua_named_functions() {
        use crate::ast::parser::parse;

        let source = r#"--- A docstring for greet
function greet(name, age)
    print("Hello " .. name)
end

local function helper(x)
    return x + 1
end
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Lua);

        assert_eq!(
            functions.len(),
            2,
            "Should find 2 named functions, got: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let greet = functions.iter().find(|f| f.name == "greet").unwrap();
        assert_eq!(greet.params, vec!["name", "age"]);
        assert!(greet.docstring.is_some(), "greet should have a docstring");
        assert!(greet
            .docstring
            .as_ref()
            .unwrap()
            .contains("docstring for greet"));
        assert_eq!(greet.return_type, None);
        assert!(!greet.is_async);

        let helper = functions.iter().find(|f| f.name == "helper").unwrap();
        assert_eq!(helper.params, vec!["x"]);
    }

    #[test]
    fn test_extract_lua_assignment_functions() {
        use crate::ast::parser::parse;

        let source = r#"M.request = function(url, opts)
    return http.get(url)
end

local myFunc = function(a, b)
    return a + b
end
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Lua);

        assert!(
            functions.len() >= 2,
            "Should find at least 2 assignment functions, got: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let request = functions.iter().find(|f| f.name == "request").unwrap();
        assert_eq!(request.params, vec!["url", "opts"]);

        let my_func = functions.iter().find(|f| f.name == "myFunc").unwrap();
        assert_eq!(my_func.params, vec!["a", "b"]);
    }

    #[test]
    fn test_extract_lua_file_integration() {
        let mut file = NamedTempFile::with_suffix(".lua").unwrap();
        write!(
            file,
            r#"--- Module function
function greet(name)
    print("Hello " .. name)
end

local function helper()
    return 42
end
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        assert_eq!(info.language, Language::Lua);
        assert!(info.functions.len() >= 2);
        assert!(info.functions.iter().any(|f| f.name == "greet"));
        assert!(info.functions.iter().any(|f| f.name == "helper"));
    }

    // =========================================================================
    // Luau extraction tests
    // =========================================================================

    #[test]
    fn test_extract_luau_typed_functions() {
        use crate::ast::parser::parse;

        let source = r#"--- Typed function
function greet(name: string, age: number): string
    return "Hello " .. name
end

local function helper(x: number): number
    return x + 1
end
"#;
        let tree = parse(source, Language::Luau).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Luau);

        assert_eq!(
            functions.len(),
            2,
            "Should find 2 functions, got: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let greet = functions.iter().find(|f| f.name == "greet").unwrap();
        assert_eq!(greet.params, vec!["name", "age"]);
        assert!(
            greet.return_type.is_some(),
            "greet should have a return type"
        );
        let rt = greet.return_type.as_ref().unwrap();
        assert!(
            rt.contains("string"),
            "return type should contain 'string', got: {}",
            rt
        );
        assert!(greet.docstring.is_some(), "greet should have a docstring");

        let helper = functions.iter().find(|f| f.name == "helper").unwrap();
        assert_eq!(helper.params, vec!["x"]);
        assert!(helper.return_type.is_some());
    }

    #[test]
    fn test_extract_luau_file_integration() {
        let mut file = NamedTempFile::with_suffix(".luau").unwrap();
        write!(
            file,
            r#"--!strict
function add(a: number, b: number): number
    return a + b
end
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        assert_eq!(info.language, Language::Luau);
        assert!(!info.functions.is_empty());
        let add = info.functions.iter().find(|f| f.name == "add").unwrap();
        assert_eq!(add.params, vec!["a", "b"]);
    }

    // =========================================================================
    // OCaml extraction tests
    // =========================================================================

    #[test]
    fn test_extract_ocaml_simple_functions() {
        use crate::ast::parser::parse;

        let source = r#"(** A greeting function *)
let greet name age =
  Printf.printf "Hello %s, age %d\n" name age

let rec factorial n =
  if n <= 1 then 1
  else n * factorial (n - 1)
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Ocaml);

        assert!(
            functions.len() >= 2,
            "Should find at least 2 functions, got: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let greet = functions.iter().find(|f| f.name == "greet").unwrap();
        assert_eq!(greet.params, vec!["name", "age"]);
        assert!(greet.docstring.is_some(), "greet should have a docstring");
        assert!(greet
            .docstring
            .as_ref()
            .unwrap()
            .contains("greeting function"));
        assert_eq!(greet.return_type, None); // No return type annotation
        assert!(!greet.is_async);

        let factorial = functions.iter().find(|f| f.name == "factorial").unwrap();
        assert_eq!(factorial.params, vec!["n"]);
    }

    #[test]
    fn test_extract_ocaml_typed_functions() {
        use crate::ast::parser::parse;

        let source = r#"let add (x : int) (y : int) : int =
  x + y
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let functions = extract_functions_detailed(&tree, source, Language::Ocaml);

        assert_eq!(functions.len(), 1, "Should find 1 function");
        let add = &functions[0];
        assert_eq!(add.name, "add");
        assert_eq!(add.params, vec!["x", "y"]);
        assert!(add.return_type.is_some(), "add should have a return type");
        assert_eq!(add.return_type.as_ref().unwrap(), "int");
    }

    #[test]
    fn test_extract_ocaml_file_integration() {
        let mut file = NamedTempFile::with_suffix(".ml").unwrap();
        write!(
            file,
            r#"(** Add two numbers *)
let add x y = x + y

let mul x y = x * y
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        assert_eq!(info.language, Language::Ocaml);
        assert!(info.functions.len() >= 2);
        assert!(info.functions.iter().any(|f| f.name == "add"));
        assert!(info.functions.iter().any(|f| f.name == "mul"));
    }

    #[test]
    fn test_extract_ocaml_no_classes() {
        let mut file = NamedTempFile::with_suffix(".ml").unwrap();
        writeln!(file, r#"let add x y = x + y"#).unwrap();

        let info = extract_file(file.path(), None).unwrap();
        assert!(info.classes.is_empty(), "OCaml should have no classes");
    }

    #[test]
    fn test_extract_lua_no_classes() {
        // A bare top-level `function foo()` with NO table receiver is a plain
        // module function, not a class member — so it must NOT synthesize a
        // class. (The table-class idiom is covered by the dedicated tests
        // below.)
        let mut file = NamedTempFile::with_suffix(".lua").unwrap();
        writeln!(file, r#"function foo() end"#).unwrap();

        let info = extract_file(file.path(), None).unwrap();
        assert!(
            info.classes.is_empty(),
            "A bare top-level function is not a class, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(info.functions.len(), 1, "foo should be a module function");
    }

    #[test]
    fn test_extract_lua_table_class_with_methods() {
        // W2-lua-structure (v0.5.0 AUDIT-FIX): the canonical Lua "class" is a
        // table bound to a local/global with attached functions. `function
        // M.new()` (dot/static) and `function M:greet()` (colon/method) must
        // group under ONE class `M`, and the table-qualified functions must be
        // EXCLUDED from the module-level `functions` list (no double counting).
        use crate::ast::parser::parse;
        let source = r#"local M = {}
M.__index = M
M.VERSION = "1.0"

function M.new(name)
  local self = setmetatable({}, M)
  self.name = name
  return self
end

function M:greet()
  return "hi " .. self.name
end

local function helper()
  return 1
end
"#;
        let tree = parse(source, Language::Lua).unwrap();

        // RED before fix: classes is empty.
        let classes = extract_classes_detailed(&tree, source, Language::Lua);
        assert_eq!(
            classes.len(),
            1,
            "expected exactly one class M, got: {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let m = &classes[0];
        assert_eq!(m.name, "M");
        assert_eq!(m.kind.as_deref(), Some("table"));
        // Anchored on `local M = {}` (line 1), not the first method.
        assert_eq!(m.line_number, 1, "class M should anchor on `local M = {{}}`");

        let method_names: Vec<&str> = m.methods.iter().map(|x| x.name.as_str()).collect();
        assert!(
            method_names.contains(&"new"),
            "M should have method `new`, got {:?}",
            method_names
        );
        assert!(
            method_names.contains(&"greet"),
            "M should have method `greet`, got {:?}",
            method_names
        );
        // Both members are flagged as methods.
        assert!(
            m.methods.iter().all(|x| x.is_method),
            "all grouped members must have is_method=true"
        );
        // Colon form => "method" decorator, dot form => "static".
        let greet = m.methods.iter().find(|x| x.name == "greet").unwrap();
        assert!(
            greet.decorators.iter().any(|d| d == "method"),
            "colon method `greet` should be tagged `method`, got {:?}",
            greet.decorators
        );
        let new = m.methods.iter().find(|x| x.name == "new").unwrap();
        assert!(
            new.decorators.iter().any(|d| d == "static"),
            "dot method `new` should be tagged `static`, got {:?}",
            new.decorators
        );

        // The table field `M.VERSION` (non-function) is captured as a field.
        assert!(
            m.fields.iter().any(|f| f.name == "VERSION"),
            "M should capture field VERSION, got {:?}",
            m.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        // The constructor `self.name = ...` is captured as a field.
        assert!(
            m.fields.iter().any(|f| f.name == "name"),
            "M should capture constructor field `name`, got {:?}",
            m.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        // Double-counting guard: table-qualified functions are EXCLUDED from
        // module-level functions; only the un-qualified `helper` remains.
        let functions = extract_functions_detailed(&tree, source, Language::Lua);
        let fn_names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            fn_names.contains(&"helper"),
            "module functions should contain helper, got {:?}",
            fn_names
        );
        assert!(
            !fn_names.iter().any(|n| n.contains("M.new") || n.contains("M:greet") || *n == "new"),
            "table-qualified M.new / M:greet must NOT appear as module functions, got {:?}",
            fn_names
        );
    }

    #[test]
    fn test_extract_lua_two_classes_grouped_separately() {
        // Two distinct receivers => two classes; colon-only class still
        // anchors on its `local X = {}` site.
        use crate::ast::parser::parse;
        let source = r#"local History = {}
History.__index = History
function History.new() return setmetatable({}, History) end
function History:add(line) self.line = line end

local Editor = {}
function Editor:refresh() end
function Editor:insert(c) end
Editor.__index = Editor
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let classes = extract_classes_detailed(&tree, source, Language::Lua);
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"History"), "expected History, got {:?}", names);
        assert!(names.contains(&"Editor"), "expected Editor, got {:?}", names);
        assert_eq!(classes.len(), 2, "exactly two classes, got {:?}", names);

        let editor = classes.iter().find(|c| c.name == "Editor").unwrap();
        let em: Vec<&str> = editor.methods.iter().map(|x| x.name.as_str()).collect();
        assert!(em.contains(&"refresh") && em.contains(&"insert"), "Editor methods {:?}", em);
    }

    #[test]
    fn test_extract_luau_table_class_with_methods() {
        // Luau shares the exact same class/method AST kinds as Lua; methods
        // additionally carry typed return types.
        use crate::ast::parser::parse;
        let source = r#"local Account = {}
Account.__index = Account

function Account.new(name: string): Account
  local self = setmetatable({}, Account)
  self.name = name
  return self
end

function Account:greet(): string
  return "hi"
end
"#;
        let tree = parse(source, Language::Luau).unwrap();
        let classes = extract_classes_detailed(&tree, source, Language::Luau);
        assert_eq!(
            classes.len(),
            1,
            "expected one Luau class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let acc = &classes[0];
        assert_eq!(acc.name, "Account");
        let mnames: Vec<&str> = acc.methods.iter().map(|x| x.name.as_str()).collect();
        assert!(mnames.contains(&"new") && mnames.contains(&"greet"), "methods {:?}", mnames);
        // Luau method return types must be carried through.
        let greet = acc.methods.iter().find(|x| x.name == "greet").unwrap();
        assert!(
            greet.return_type.as_deref().map(|t| t.contains("string")).unwrap_or(false),
            "greet should carry return type string, got {:?}",
            greet.return_type
        );
    }

    #[test]
    fn test_extract_lua_module_table_not_a_class() {
        // A plain config/module table with NO attached functions must NOT be
        // reported as a class (keeps cohesion honest in Wave 3).
        use crate::ast::parser::parse;
        let source = r#"local config = {}
config.timeout = 30
config.retries = 3
return config
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let classes = extract_classes_detailed(&tree, source, Language::Lua);
        assert!(
            classes.is_empty(),
            "a function-less table is not a class, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_from_tree_matches_extract_file() {
        // Verify that extract_from_tree produces the same result as extract_file
        let mut file = NamedTempFile::with_suffix(".py").unwrap();
        write!(
            file,
            r#"
"""Module docstring."""

def foo():
    """Function docstring."""
    bar()

def bar():
    pass
"#
        )
        .unwrap();

        // Extract using extract_file
        let info_from_file = extract_file(file.path(), None).unwrap();

        // Extract using extract_from_tree (parse manually first)
        use crate::ast::parser::parse_file;
        let (tree, source, language) = parse_file(file.path()).unwrap();
        let info_from_tree =
            extract_from_tree(&tree, &source, language, file.path(), None).unwrap();

        // Both should produce identical results
        assert_eq!(info_from_file.language, info_from_tree.language);
        assert_eq!(info_from_file.docstring, info_from_tree.docstring);
        assert_eq!(
            info_from_file.functions.len(),
            info_from_tree.functions.len()
        );
        assert_eq!(info_from_file.classes.len(), info_from_tree.classes.len());
        assert_eq!(info_from_file.imports.len(), info_from_tree.imports.len());

        // Verify function names match
        for func in &info_from_file.functions {
            assert!(info_from_tree.functions.iter().any(|f| f.name == func.name));
        }
    }

    // =========================================================================
    // Module-level constants extraction tests for missing languages
    // =========================================================================

    #[test]
    fn test_extract_c_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
#define MAX_SIZE 1024
#define VERSION "1.0.0"

const int BUFFER_LEN = 256;
int mutable_var = 42;
"#;
        let tree = parse(source, Language::C).unwrap();
        let constants = extract_module_constants(&tree, source, Language::C);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract #define MAX_SIZE. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "VERSION" && c.is_constant),
            "Should extract #define VERSION. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "BUFFER_LEN" && c.is_constant),
            "Should extract const int BUFFER_LEN. Got: {:?}",
            constants
        );
        // mutable_var should NOT be extracted (not const, not UPPER_CASE define)
        assert!(
            !constants.iter().any(|c| c.name == "mutable_var"),
            "Should not extract non-const mutable_var"
        );
    }

    #[test]
    fn test_extract_cpp_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
#define MAX_THREADS 8

const int BUFFER_SIZE = 4096;
constexpr int CACHE_LINE = 64;
int global_var = 0;
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Cpp);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_THREADS" && c.is_constant),
            "Should extract #define MAX_THREADS. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "BUFFER_SIZE" && c.is_constant),
            "Should extract const int BUFFER_SIZE. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "CACHE_LINE" && c.is_constant),
            "Should extract constexpr int CACHE_LINE. Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "global_var"),
            "Should not extract non-const global_var"
        );
    }

    #[test]
    fn test_extract_ruby_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30
local_var = "hello"
"#;
        let tree = parse(source, Language::Ruby).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Ruby);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_RETRIES" && c.is_constant),
            "Should extract UPPER_CASE constant MAX_RETRIES. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_TIMEOUT" && c.is_constant),
            "Should extract UPPER_CASE constant DEFAULT_TIMEOUT. Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "local_var"),
            "Should not extract lowercase local_var"
        );
    }

    #[test]
    fn test_extract_kotlin_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
const val MAX_SIZE = 1024
val DEFAULT_NAME = "hello"
var mutableVar = 42
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Kotlin);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract const val MAX_SIZE. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_NAME" && c.is_constant),
            "Should extract val DEFAULT_NAME (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "mutableVar"),
            "Should not extract var mutableVar"
        );
    }

    #[test]
    fn test_extract_php_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"<?php
const MAX_CONNECTIONS = 100;
define('API_VERSION', '2.0');
$regular_var = "hello";
"#;
        let tree = parse(source, Language::Php).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Php);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_CONNECTIONS" && c.is_constant),
            "Should extract const MAX_CONNECTIONS. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "API_VERSION" && c.is_constant),
            "Should extract define('API_VERSION', ...). Got: {:?}",
            constants
        );
    }

    #[test]
    fn test_extract_lua_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
MAX_RETRIES = 5
DEFAULT_TIMEOUT = 30
local lower_case = "not a constant"
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Lua);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_RETRIES" && c.is_constant),
            "Should extract UPPER_CASE assignment MAX_RETRIES. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_TIMEOUT" && c.is_constant),
            "Should extract UPPER_CASE assignment DEFAULT_TIMEOUT. Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "lower_case"),
            "Should not extract lowercase variable"
        );
    }

    #[test]
    fn test_extract_luau_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
local MAX_SIZE = 100
local DEFAULT_NAME = "world"
local mutable_value = 42
"#;
        let tree = parse(source, Language::Luau).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Luau);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract UPPER_CASE local MAX_SIZE. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_NAME" && c.is_constant),
            "Should extract UPPER_CASE local DEFAULT_NAME. Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "mutable_value"),
            "Should not extract lowercase mutable_value"
        );
    }

    #[test]
    fn test_extract_elixir_module_constants() {
        use crate::ast::parser::parse;

        // Elixir module attributes use @ prefix. UPPER_CASE names at top level
        // are parsed as unary_operator(@) with alias operand.
        let source = r#"
@MAX_RETRIES 3
@DEFAULT_TIMEOUT 30
"#;
        let tree = parse(source, Language::Elixir).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Elixir);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_RETRIES" && c.is_constant),
            "Should extract @MAX_RETRIES module attribute. Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_TIMEOUT" && c.is_constant),
            "Should extract @DEFAULT_TIMEOUT module attribute. Got: {:?}",
            constants
        );
    }

    #[test]
    fn test_extract_scala_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
val MAX_SIZE = 1024
val DEFAULT_NAME = "hello"
var mutableVar = 42
"#;
        let tree = parse(source, Language::Scala).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Scala);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract val MAX_SIZE (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_NAME" && c.is_constant),
            "Should extract val DEFAULT_NAME (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "mutableVar"),
            "Should not extract var mutableVar"
        );
    }

    #[test]
    fn test_extract_csharp_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
const int MAX_SIZE = 1024;
"#;
        let tree = parse(source, Language::CSharp).unwrap();
        let constants = extract_module_constants(&tree, source, Language::CSharp);

        // C# rarely has top-level constants outside classes, but when present they should be extracted
        // If the tree-sitter grammar puts this inside an implicit compilation_unit, it may still work
        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract const int MAX_SIZE. Got: {:?}",
            constants
        );
    }

    #[test]
    fn test_extract_ocaml_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
let MAX_SIZE = 1024
let DEFAULT_NAME = "hello"
let lowercase_val = 42
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Ocaml);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract let MAX_SIZE (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_NAME" && c.is_constant),
            "Should extract let DEFAULT_NAME (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "lowercase_val"),
            "Should not extract lowercase lowercase_val"
        );
    }

    #[test]
    fn test_extract_swift_module_constants() {
        use crate::ast::parser::parse;

        let source = r#"
let MAX_SIZE = 1024
let DEFAULT_NAME = "hello"
var mutableVar = 42
"#;
        let tree = parse(source, Language::Swift).unwrap();
        let constants = extract_module_constants(&tree, source, Language::Swift);

        assert!(
            constants
                .iter()
                .any(|c| c.name == "MAX_SIZE" && c.is_constant),
            "Should extract let MAX_SIZE (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            constants
                .iter()
                .any(|c| c.name == "DEFAULT_NAME" && c.is_constant),
            "Should extract let DEFAULT_NAME (UPPER_CASE). Got: {:?}",
            constants
        );
        assert!(
            !constants.iter().any(|c| c.name == "mutableVar"),
            "Should not extract var mutableVar"
        );
    }

    #[test]
    fn test_go_var_declaration_extraction() {
        use crate::ast::parser::parse;

        let source = "package mypkg\n\nimport \"errors\"\n\nvar (\n\tErrTimeout  = errors.New(\"timeout\")\n\tErrCanceled = errors.New(\"canceled\")\n)\n";
        let tree = parse(source, Language::Go).unwrap();

        let constants = extract_module_constants(&tree, source, Language::Go);
        let names: Vec<&str> = constants.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"ErrTimeout"),
            "Should extract ErrTimeout from grouped var block, got: {:?}",
            names
        );
        assert!(
            names.contains(&"ErrCanceled"),
            "Should extract ErrCanceled from grouped var block, got: {:?}",
            names
        );
        // Verify they're not marked as constants
        for c in &constants {
            assert!(!c.is_constant, "var entries should have is_constant=false");
        }
    }

    // =====================================================================
    // js-extract-function-expressions-v1
    //
    // Coverage for function-expression assignment patterns that were
    // previously missed by `tldr extract` on JS/TS files (e.g.,
    // express's `app.use = function use() {}` exports).
    // =====================================================================

    #[test]
    fn test_extract_js_function_expression_assignment() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
var app = exports = module.exports = {{}};

app.use = function use(fn) {{ return fn; }};
app.engine = function engine(ext, fn) {{ return ext; }};
app.set = function set(setting, val) {{ return val; }};
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();

        assert!(
            info.functions.len() >= 3,
            "Expected >=3 functions for app.X = function X() {{}} pattern, got {}: {:?}",
            info.functions.len(),
            names
        );
        assert!(names.contains(&"use"), "Missing 'use' in {:?}", names);
        assert!(names.contains(&"engine"), "Missing 'engine' in {:?}", names);
        assert!(names.contains(&"set"), "Missing 'set' in {:?}", names);

        // Param extraction must work for the assigned function expression.
        let use_fn = info.functions.iter().find(|f| f.name == "use").unwrap();
        assert_eq!(use_fn.params, vec!["fn".to_string()]);
    }

    #[test]
    fn test_extract_js_arrow_function_assignment() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
const handler = (req, res) => {{ res.end(); }};
let asyncHandler = async (x) => x + 1;
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"handler"),
            "Missing 'handler' in {:?}",
            names
        );
        assert!(
            names.contains(&"asyncHandler"),
            "Missing 'asyncHandler' in {:?}",
            names
        );
        let async_fn = info
            .functions
            .iter()
            .find(|f| f.name == "asyncHandler")
            .unwrap();
        assert!(async_fn.is_async, "asyncHandler should be async");
    }

    #[test]
    fn test_extract_js_prototype_method_pattern() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
function Foo() {{}}

Foo.prototype.bar = function bar(x) {{ return x; }};
Foo.prototype.baz = function (y) {{ return y; }};
Foo.prototype.qux = (z) => z;
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"bar"), "Missing 'bar' in {:?}", names);
        assert!(names.contains(&"baz"), "Missing 'baz' in {:?}", names);
        assert!(names.contains(&"qux"), "Missing 'qux' in {:?}", names);
    }

    #[test]
    fn test_extract_js_object_method_shorthand() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
module.exports = {{
  foo() {{ return 1; }},
  bar: function bar(x) {{ return x; }},
  baz: (y) => y,
}};
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"foo"),
            "Missing 'foo' (method shorthand) in {:?}",
            names
        );
        assert!(
            names.contains(&"bar"),
            "Missing 'bar' (pair: function) in {:?}",
            names
        );
        assert!(
            names.contains(&"baz"),
            "Missing 'baz' (pair: arrow) in {:?}",
            names
        );
    }

    /// (fix-T3-G3G2-args-v1, GAP 3 / Option 3A) A NAMED function expression
    /// passed as a call ARGUMENT — the Express `defineGetter(req, 'query',
    /// function query(){...})` getter pattern — must surface as a definition
    /// keyed by the function's OWN name (`query`). Anonymous callbacks have no
    /// `name` field and are excluded by construction.
    ///
    /// The named AND anonymous cases are mixed into ONE source so the
    /// discrimination is proven in a single place: the named arg IS collected
    /// while its anonymous sibling is NOT. This fails on pre-3A code (where
    /// named-in-args was never collected, so `query`/`protocol` are absent).
    #[test]
    fn test_extract_js_named_function_expression_argument() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
defineGetter(req, 'query', function query() {{ return 1; }});
defineGetter(req, 'protocol', function protocol() {{ return 2; }});
defineGetter(req, 'fresh', function() {{ return 3; }});
arr.forEach((x) => x);
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"query"),
            "named function-expression arg `function query()` must be collected, got {:?}",
            names
        );
        assert!(
            names.contains(&"protocol"),
            "named function-expression arg `function protocol()` must be collected, got {:?}",
            names
        );
        // Discrimination, proven in the SAME source: the anonymous callback arg
        // (`function() {}`) carries no `name` field and must NOT be collected,
        // and the dynamic string label `'fresh'` must NOT become a def name.
        assert!(
            !names.contains(&"fresh"),
            "anonymous callback arg must NOT be collected under the string label, got {:?}",
            names
        );
    }

    /// (fix-T3-G3G2-args-v1, GAP 3 / Option 3A) An ANONYMOUS callback passed
    /// as a call argument has no `name` field, so it must NOT be collected.
    /// The named/anonymous split is self-enforcing.
    #[test]
    fn test_extract_js_anonymous_callback_argument_not_collected() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
defineGetter(req, 'fresh', function() {{ return 3; }});
arr.forEach(function(x) {{ return x; }});
list.map((y) => y + 1);
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        // The only top-level call targets here are `defineGetter`/`forEach`/`map`
        // (call sites, not defs). No anonymous callback may appear as a def.
        assert!(
            !names.contains(&"fresh"),
            "anonymous callback must NOT be collected under the string-arg name, got {:?}",
            names
        );
        assert!(
            names.is_empty(),
            "no anonymous argument callback may produce a def, got {:?}",
            names
        );
    }

    /// (fix-T3-G3G2-args-v1, GAP 2 / Option 2B) A computed-member assignment
    /// `app[method] = function() {}` (LHS subscript_expression with an
    /// identifier index) must emit ONE virtual/computed placeholder def keyed
    /// on the object as `app.[computed]`, WITHOUT resolving the dynamic name.
    /// A static string key (`obj["x"] = fn`) is NOT the computed case and is
    /// left out of scope.
    #[test]
    fn test_extract_js_computed_member_assignment_placeholder() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        // Two DISTINCT objects each take one computed-member assignment (one
        // `function` RHS, one arrow RHS) -> two distinct placeholders. A third
        // assignment uses a STATIC string key (`index:(string)`), which is out
        // of scope and must NOT produce any placeholder.
        write!(
            file,
            r#"
app[method] = function() {{ return 1; }};
router[other] = (x) => x;
obj["key"] = function() {{ return 2; }};
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"app.[computed]"),
            "computed-member assignment must emit a `app.[computed]` placeholder, got {:?}",
            names
        );
        // The dynamic index name must NOT be resolved into a bare def.
        assert!(
            !names.contains(&"method"),
            "the dynamic index `method` must NOT be resolved as a def name, got {:?}",
            names
        );
        assert!(
            !names.contains(&"other"),
            "the dynamic index `other` must NOT be resolved as a def name, got {:?}",
            names
        );
        // The static string key is out of scope: no `obj.[computed]` placeholder.
        assert!(
            !names.contains(&"obj.[computed]"),
            "static string key `obj[\"key\"]` must NOT emit a computed placeholder, got {:?}",
            names
        );

        // EXACTLY ONE `app.[computed]` placeholder must exist. This count fails
        // if 2B stops emitting the placeholder (drops to 0) or double-emits.
        let app_placeholders: Vec<&FunctionInfo> = info
            .functions
            .iter()
            .filter(|f| f.name == "app.[computed]")
            .collect();
        assert_eq!(
            app_placeholders.len(),
            1,
            "expected exactly one `app.[computed]` placeholder, got {:?}",
            names
        );
        let placeholder = app_placeholders[0];
        // The placeholder is a member-style binding, NOT a method body. This is
        // a semantic field that DIFFERS from the name (so it is not a tautology
        // over `name`): it fails if 2B regresses is_method to true.
        assert!(
            !placeholder.is_method,
            "computed placeholder must have is_method == false"
        );
        // Member-style assignment is an externally-visible binding shape.
        assert_eq!(
            placeholder.visibility.as_deref(),
            Some("public"),
            "computed placeholder must be public-visibility"
        );
        // Line bounds must be sane: 1-based, start <= end, within file.
        assert!(
            placeholder.line_number >= 1 && placeholder.line_number <= placeholder.line_end,
            "placeholder line bounds must satisfy 1 <= start ({}) <= end ({})",
            placeholder.line_number,
            placeholder.line_end
        );
        // Total computed placeholders across both distinct objects: exactly two
        // (`app.[computed]` + `router.[computed]`), proving both the `function`
        // and arrow RHS shapes are covered and the static key is excluded.
        let total_placeholders = info
            .functions
            .iter()
            .filter(|f| f.name.ends_with(".[computed]"))
            .count();
        assert_eq!(
            total_placeholders, 2,
            "expected exactly two computed placeholders (app + router), got {:?}",
            names
        );
    }

    /// (POLISH T3-G3G2) Generator RHS parity: `app[method] = function*(){}` is a
    /// `generator_function` on the RHS, which the sibling arms in
    /// callgraph/languages/typescript.rs already accept. The computed-member
    /// placeholder extractor must accept it too, so a generator-valued
    /// computed-member assignment also emits exactly one `app.[computed]`.
    /// This fails on code that omits `generator_function` from the RHS match.
    #[test]
    fn test_extract_js_computed_member_generator_rhs_placeholder() {
        let mut file = NamedTempFile::with_suffix(".js").unwrap();
        write!(
            file,
            r#"
app[method] = function*() {{ yield 1; }};
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        let count = info
            .functions
            .iter()
            .filter(|f| f.name == "app.[computed]")
            .count();
        assert_eq!(
            count, 1,
            "generator RHS `function*(){{}}` must emit exactly one `app.[computed]` placeholder, got {:?}",
            names
        );
        // The dynamic index name must NOT leak as a bare def.
        assert!(
            !names.contains(&"method"),
            "the dynamic index `method` must NOT be resolved as a def name, got {:?}",
            names
        );
    }

    /// (POLISH T3-G3G2) .tsx parity: the named-function-expression-in-args path
    /// (Option 3A) must behave identically under LANGUAGE_TSX, not just
    /// LANGUAGE_TYPESCRIPT. Same source, `.tsx` suffix — `function query()`
    /// passed as a call argument must still surface keyed by its OWN name, and
    /// the paired ANONYMOUS callback must still be excluded.
    #[test]
    fn test_extract_tsx_named_function_expression_argument() {
        let mut file = NamedTempFile::with_suffix(".tsx").unwrap();
        write!(
            file,
            r#"
defineGetter(req, 'query', function query() {{ return 1; }});
defineGetter(req, 'fresh', function() {{ return 2; }});
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        // Named-in-args is collected under TSX identically.
        assert!(
            names.contains(&"query"),
            "TSX: named function-expression arg `function query()` must be collected, got {:?}",
            names
        );
        // The anonymous sibling in the SAME source is NOT collected, proving the
        // named/anonymous discrimination holds under the TSX grammar too.
        assert!(
            !names.contains(&"fresh"),
            "TSX: anonymous callback must NOT be collected under the string arg, got {:?}",
            names
        );
    }

    #[test]
    fn test_extract_ts_same_patterns() {
        let mut file = NamedTempFile::with_suffix(".ts").unwrap();
        write!(
            file,
            r#"
const app: any = {{}};

app.use = function use(fn: Function): any {{ return fn; }};
app.engine = (ext: string, fn: Function): any => ext;

const handler = (x: number): number => x + 1;

const obj = {{
  foo(n: number): number {{ return n; }},
  bar: function (s: string) {{ return s; }},
}};

function Klass() {{}}
Klass.prototype.method = function method(arg: number) {{ return arg; }};
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"use"), "TS: missing 'use' in {:?}", names);
        assert!(
            names.contains(&"engine"),
            "TS: missing 'engine' in {:?}",
            names
        );
        assert!(
            names.contains(&"handler"),
            "TS: missing 'handler' in {:?}",
            names
        );
        assert!(names.contains(&"foo"), "TS: missing 'foo' in {:?}", names);
        assert!(names.contains(&"bar"), "TS: missing 'bar' in {:?}", names);
        assert!(
            names.contains(&"method"),
            "TS: missing 'method' (prototype) in {:?}",
            names
        );
    }

    /// (fix-T3-G4-overload-v1) TypeScript overload signatures must collapse to
    /// the single implementation. A `method_signature` (or body-less
    /// `method_definition`) that shares (name, static?, accessor-kind) with an
    /// implementation sibling in the SAME class_body is dropped — but only the
    /// signatures, the impl (with body) is kept exactly once.
    #[test]
    fn test_extract_ts_overload_signatures_collapse_to_impl() {
        let mut file = NamedTempFile::with_suffix(".ts").unwrap();
        write!(
            file,
            r#"
class NestFactoryStatic {{
  public create(a: string): void;
  public create(a: number): void;
  public create(a: any): void {{
    return;
  }}

  static make(): void;
  static make(): void {{
    return;
  }}

  get value(): string {{
    return "x";
  }}
  set value(v: string) {{}}
}}
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let class = info
            .classes
            .iter()
            .find(|c| c.name == "NestFactoryStatic")
            .expect("NestFactoryStatic class");
        let method_names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();

        // Three `create` overload entries collapse to one implementation.
        let create_count = method_names.iter().filter(|n| **n == "create").count();
        assert_eq!(
            create_count, 1,
            "overloaded `create` should collapse to one impl, got {:?}",
            method_names
        );

        // The retained `create` must be the implementation (the one with a body):
        // its source line range spans multiple lines, not the single-line sigs.
        let create = class
            .methods
            .iter()
            .find(|m| m.name == "create")
            .expect("create method retained");
        assert!(
            create.line_end > create.line_number,
            "retained `create` should be the multi-line impl, got lines {}-{}",
            create.line_number,
            create.line_end
        );

        // Static overload also collapses to its impl.
        let make_count = method_names.iter().filter(|n| **n == "make").count();
        assert_eq!(
            make_count, 1,
            "overloaded static `make` should collapse to one impl, got {:?}",
            method_names
        );

        // get/set accessors share a name but must NOT be collapsed — both kept.
        let value_count = method_names.iter().filter(|n| **n == "value").count();
        assert_eq!(
            value_count, 2,
            "get/set `value` accessors must both be retained, got {:?}",
            method_names
        );
    }

    /// (fix-T3-G4-overload-v1) Guard: a declaration-only method with NO
    /// implementation sibling (ambient / `declare class` / `.d.ts`) must be
    /// retained — there is nothing to dedup against.
    #[test]
    fn test_extract_ts_ambient_declaration_only_method_retained() {
        let mut file = NamedTempFile::with_suffix(".ts").unwrap();
        write!(
            file,
            r#"
declare class Ambient {{
  onlyDecl(x: number): void;
  alsoDecl(): string;
}}
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let class = info
            .classes
            .iter()
            .find(|c| c.name == "Ambient")
            .expect("Ambient class");
        let method_names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            method_names.contains(&"onlyDecl"),
            "declaration-only `onlyDecl` must be retained, got {:?}",
            method_names
        );
        assert!(
            method_names.contains(&"alsoDecl"),
            "declaration-only `alsoDecl` must be retained, got {:?}",
            method_names
        );
    }

    /// (fix-T3-G4-overload-v1) Guard: two classes in one file may each define a
    /// `create`. Dedup is scoped STRICTLY to one class_body — both must survive.
    #[test]
    fn test_extract_ts_same_name_methods_in_different_classes_both_kept() {
        let mut file = NamedTempFile::with_suffix(".ts").unwrap();
        write!(
            file,
            r#"
class First {{
  create(): void {{
    return;
  }}
}}

class Second {{
  create(): void {{
    return;
  }}
}}
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let first = info
            .classes
            .iter()
            .find(|c| c.name == "First")
            .expect("First class");
        let second = info
            .classes
            .iter()
            .find(|c| c.name == "Second")
            .expect("Second class");
        assert_eq!(
            first.methods.iter().filter(|m| m.name == "create").count(),
            1,
            "First::create must be kept"
        );
        assert_eq!(
            second.methods.iter().filter(|m| m.name == "create").count(),
            1,
            "Second::create must be kept (never deduped across classes)"
        );
    }

    /// (fix-T3-G4-overload-v1) Coverage for the `method_definition` arm of the
    /// dedup at the point where a body-less declaration is collapsed onto a
    /// `method_definition` IMPLEMENTATION sibling.
    ///
    /// The existing collapse test only inspects the observable method *list*; it
    /// does not pin the two structural predicates the `method_definition` branch
    /// relies on:
    ///   1. `ts_method_has_body` — the body-field discriminator that decides
    ///      whether a member is an implementation (kept) or a declaration-only
    ///      signature (a drop candidate).
    ///   2. `ts_method_has_impl_sibling` — which (line: `sibling.kind() !=
    ///      "method_definition"`) recognises ONLY a bodied `method_definition`
    ///      as the surviving implementation. A `method_signature` is never a
    ///      valid impl sibling, so a class with no `method_definition` keeps all
    ///      its declarations.
    ///
    /// Verified against tree-sitter-typescript 0.23.2, whose `node-types.json`
    /// marks `method_definition.body` as a *required* field: a well-formed
    /// implementation is always a `method_definition` WITH a body, and a
    /// body-less member is always a `method_signature`. We assert exactly that
    /// structural split, then the end-to-end drop-and-keep outcome.
    #[test]
    fn test_extract_ts_overload_bodyless_method_definition_dedup() {
        // One body-less `method_signature` overload + one bodied
        // `method_definition` implementation, same name, same class_body.
        let src = "class Svc {\n  build(a: string): void;\n  build(a: any): void {\n    return;\n  }\n}\n";
        let mut file = NamedTempFile::with_suffix(".ts").unwrap();
        write!(file, "{src}").unwrap();
        let (tree, source, _lang) = crate::ast::parser::parse_file(file.path()).unwrap();
        let source = source.as_str();

        // Locate the class_body and its two `build` members structurally.
        fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
            if node.kind() == kind {
                return Some(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(found) = find_kind(child, kind) {
                    return Some(found);
                }
            }
            None
        }
        let class_body = find_kind(tree.root_node(), "class_body").expect("class_body present");

        let mut sig: Option<Node> = None;
        let mut imp: Option<Node> = None;
        let mut cursor = class_body.walk();
        for member in class_body.children(&mut cursor) {
            match member.kind() {
                "method_signature" => sig = Some(member),
                "method_definition" => imp = Some(member),
                _ => {}
            }
        }
        let sig = sig.expect("body-less overload must parse as a method_signature");
        let imp = imp.expect("the implementation must parse as a method_definition");

        // Predicate 1: the body discriminator splits impl from declaration.
        assert!(
            ts_method_has_body(&imp),
            "the `method_definition` implementation must own a body"
        );
        assert!(
            !ts_method_has_body(&sig),
            "the body-less overload declaration must report no body"
        );

        // Predicate 2: the body-less declaration HAS an impl sibling (the
        // `method_definition`), so it is a drop candidate. The impl itself does
        // NOT (its only same-name sibling is the body-less declaration, which is
        // not a `method_definition` and so cannot be an impl sibling).
        assert!(
            ts_method_has_impl_sibling(&class_body, &sig, source),
            "body-less `build` declaration must see the `method_definition` impl as its sibling"
        );
        assert!(
            !ts_method_has_impl_sibling(&class_body, &imp, source),
            "the `method_definition` impl has no impl sibling -> it is never the dropped member"
        );

        // End-to-end outcome: exactly the implementation survives, kept once.
        let info = extract_file(file.path(), None).unwrap();
        let class = info
            .classes
            .iter()
            .find(|c| c.name == "Svc")
            .expect("Svc class");
        let build_methods: Vec<&FunctionInfo> =
            class.methods.iter().filter(|m| m.name == "build").collect();
        assert_eq!(
            build_methods.len(),
            1,
            "the body-less `build` overload must be dropped, leaving one entry, got {:?}",
            class.methods.iter().map(|m| m.name.as_str()).collect::<Vec<_>>()
        );
        let kept = build_methods[0];
        assert!(
            kept.line_end > kept.line_number,
            "the surviving `build` must be the multi-line `method_definition` impl, got lines {}-{}",
            kept.line_number,
            kept.line_end
        );
    }

    /// (fix-R7-cl2-c-doubleptr-v1) C/C++ double-pointer params `char **argv`
    /// parse as pointer_declarator > pointer_declarator > identifier. The
    /// pointer_declarator arm of extract_c_param_name only scanned for a DIRECT
    /// identifier child, so the nested case dropped the param entirely while
    /// single `*sep` (direct identifier child) worked. Guards the recursive
    /// descent through nested pointer_declarators.
    #[test]
    fn test_extract_c_double_pointer_param_kept() {
        let mut file = NamedTempFile::with_suffix(".c").unwrap();
        write!(
            file,
            "char *sdsjoin(char **argv, int argc, char *sep) {{ return 0; }}\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "sdsjoin")
            .expect("sdsjoin function");
        // The double-pointer param `argv` must be present (was dropped before fix),
        // alongside the single-pointer `sep` and plain `argc`.
        assert!(
            f.params.iter().any(|p| p == "argv"),
            "double-pointer param `char **argv` must be captured, got {:?}",
            f.params
        );
        assert!(
            f.params.iter().any(|p| p == "sep"),
            "single-pointer param `char *sep` must be captured, got {:?}",
            f.params
        );
        assert!(
            f.params.iter().any(|p| p == "argc"),
            "plain param `int argc` must be captured, got {:?}",
            f.params
        );
        // Arity is exactly 3 — no phantom/empty entries from the recursion.
        assert_eq!(
            f.params.len(),
            3,
            "sdsjoin must have exactly 3 params, got {:?}",
            f.params
        );
    }

    /// (fix-R7-cl2-c-doubleptr-v1) Triple-pointer and pointer-to-array params
    /// must also resolve through the recursive descent.
    #[test]
    fn test_extract_c_triple_pointer_param_kept() {
        let mut file = NamedTempFile::with_suffix(".c").unwrap();
        write!(file, "void f(char ***matrix, int n) {{ }}\n").unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "f")
            .expect("f function");
        assert!(
            f.params.iter().any(|p| p == "matrix"),
            "triple-pointer param `char ***matrix` must be captured, got {:?}",
            f.params
        );
        assert_eq!(f.params.len(), 2, "got {:?}", f.params);
    }

    /// (fix-R7-cl2-elixir-structparam-v1) An Elixir parameter that is a match
    /// pattern `%Struct{} = var` binds `var` on the RIGHT of the `=`. The
    /// binary_operator arm previously assumed `\\ default` semantics (name on
    /// the LEFT) and, since the left is a map/struct, dropped the param —
    /// undercounting arity. The bound variable must be captured.
    #[test]
    fn test_extract_elixir_struct_pattern_param_kept() {
        let mut file = NamedTempFile::with_suffix(".ex").unwrap();
        write!(
            file,
            "defmodule M do\n  def basic_auth(%Plug.Conn{{}} = conn, options) do\n    conn\n  end\nend\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "basic_auth")
            .expect("basic_auth function");
        assert!(
            f.params.iter().any(|p| p == "conn"),
            "struct-pattern param `%Plug.Conn{{}} = conn` must bind `conn`, got {:?}",
            f.params
        );
        assert!(
            f.params.iter().any(|p| p == "options"),
            "plain param `options` must be captured, got {:?}",
            f.params
        );
        assert_eq!(
            f.params.len(),
            2,
            "basic_auth arity must be 2, got {:?}",
            f.params
        );
    }

    /// (fix-R7-cl2-elixir-structparam-v1) The `=` match-vs-`\\` default split
    /// must not regress default-value params: `opts \\ []` still binds `opts`.
    #[test]
    fn test_extract_elixir_default_param_still_left() {
        let mut file = NamedTempFile::with_suffix(".ex").unwrap();
        write!(
            file,
            "defmodule M do\n  def run(opts \\\\ []) do\n    opts\n  end\nend\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "run")
            .expect("run function");
        assert!(
            f.params.iter().any(|p| p == "opts"),
            "default-value param `opts \\\\ []` must bind `opts`, got {:?}",
            f.params
        );
    }

    /// (fix-R7-cl2-ocaml-pointfree-v1) A point-free OCaml function
    /// `let code = function | ... -> ...` has no `parameter` node but its body
    /// is a `function_expression`. The params-only `ocaml_binding_has_params`
    /// check dropped it; broadening to count function-expression bodies keeps
    /// it. A genuine value binding (`let all = [...]`) must STILL be excluded.
    #[test]
    fn test_extract_ocaml_pointfree_function_kept() {
        let mut file = NamedTempFile::with_suffix(".ml").unwrap();
        write!(
            file,
            "let all = [ 1; 2 ]\nlet code = function\n  | 0 -> 1\n  | _ -> 2\nlet info e = code e\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"code"),
            "point-free `let code = function ...` must be a function, got {:?}",
            names
        );
        assert!(
            names.contains(&"info"),
            "parameterised `let info e = ...` must be a function, got {:?}",
            names
        );
        assert!(
            !names.contains(&"all"),
            "value binding `let all = [..]` must NOT be a function, got {:?}",
            names
        );
    }

    /// (fix-R7-cl2-java-calledby-v1) In class-based languages a method appears
    /// in BOTH functions[] and classes[].methods[], so called_by accumulated
    /// each caller twice. Every called_by list must contain each caller exactly
    /// once.
    #[test]
    fn test_java_called_by_not_doubled() {
        let mut file = NamedTempFile::with_suffix(".java").unwrap();
        write!(
            file,
            r#"
class C {{
    void caller() {{
        callee();
    }}
    void callee() {{
    }}
}}
"#
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let callers = info
            .call_graph
            .called_by
            .get("callee")
            .expect("callee should have callers");
        let caller_count = callers.iter().filter(|c| *c == "caller").count();
        assert_eq!(
            caller_count, 1,
            "caller `caller` must appear exactly once in callee's called_by, got {:?}",
            callers
        );
    }

    /// (fix-R7-cl2-luau-pragma-v1) A Luau `--!nocheck` mode pragma at file scope
    /// (separated from the first function by a blank line) must NOT be captured
    /// as that function's docstring.
    #[test]
    fn test_luau_mode_pragma_not_docstring() {
        let mut file = NamedTempFile::with_suffix(".luau").unwrap();
        write!(
            file,
            "--!nocheck\n\nlocal function expectpass(s, f)\n  f()\nend\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "expectpass")
            .expect("expectpass function");
        assert!(
            f.docstring.is_none(),
            "Luau `--!nocheck` pragma must not be a docstring, got {:?}",
            f.docstring
        );
    }

    /// (fix-R7-cl2-luau-pragma-v1) A genuine doc comment directly above a
    /// function (no blank-line gap) must STILL be captured — the pragma fix
    /// must not suppress real docstrings.
    #[test]
    fn test_lua_real_docstring_still_captured() {
        let mut file = NamedTempFile::with_suffix(".lua").unwrap();
        write!(
            file,
            "-- Adds two numbers\nlocal function add(a, b)\n  return a + b\nend\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let f = info
            .functions
            .iter()
            .find(|f| f.name == "add")
            .expect("add function");
        assert_eq!(
            f.docstring.as_deref(),
            Some("Adds two numbers"),
            "adjacent doc comment must be captured, got {:?}",
            f.docstring
        );
    }

    /// (fix-R7-cl2-ts-ambient-fn-v1) Ambient `export function f(): T;` in a
    /// `.d.ts` file parses as `function_signature` (bodyless), not
    /// `function_declaration`. These were dropped from the top-level functions
    /// list (axios index.d.ts reported functions=0). They must be captured.
    #[test]
    fn test_ts_ambient_export_function_captured() {
        let mut file = NamedTempFile::with_suffix(".d.ts").unwrap();
        write!(
            file,
            "export function getAdapter(a: string): object;\nexport function create(c?: number): any;\n"
        )
        .unwrap();

        let info = extract_file(file.path(), None).unwrap();
        let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"getAdapter"),
            "ambient `export function getAdapter` must be captured, got {:?}",
            names
        );
        assert!(
            names.contains(&"create"),
            "ambient `export function create` must be captured, got {:?}",
            names
        );
    }
}
