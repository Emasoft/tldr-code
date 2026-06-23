//! Interface command - Public API extraction
//!
//! Extracts the public interface (API surface) from source files.
//! Supports all languages with tree-sitter grammars: Python, Rust, Go,
//! TypeScript, JavaScript, Java, C, C++, Ruby, C#, Scala, PHP, Lua, Luau,
//! Elixir, and OCaml.
//!
//! # Features
//!
//! - Extracts public functions (language-appropriate visibility rules)
//! - Extracts public classes/structs/traits with their public methods
//! - Captures export declarations when present (e.g., Python `__all__`)
//! - Marks async functions/methods
//! - Includes function signatures with type annotations
//! - Includes docstrings/doc comments when present
//!
//! # Example
//!
//! ```bash
//! tldr interface src/api.py
//! tldr interface src/lib.rs
//! tldr interface src/ --format text
//! ```

use std::path::{Path, PathBuf};

use clap::Args;
use tldr_core::walker::walk_project;
use tree_sitter::Node;

use super::error::{PatternsError, PatternsResult};
use super::types::{ClassInfo, FunctionInfo, InterfaceInfo, MethodInfo};
use super::validation::{read_file_safe, validate_directory_path, validate_file_path};
use crate::output::OutputFormat;
use tldr_core::ast::ParserPool;
use tldr_core::types::Language;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Arguments for the interface command.
#[derive(Debug, Clone, Args)]
pub struct InterfaceArgs {
    /// File or directory to analyze
    #[arg(required = true)]
    pub path: PathBuf,

    /// Project root for path validation
    #[arg(long)]
    pub project_root: Option<PathBuf>,
}

// =============================================================================
// Language-Aware Node Kind Configuration
// =============================================================================

/// Node kinds that represent function definitions for a given language.
fn function_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["function_definition"],
        Language::Rust => &["function_item"],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::TypeScript | Language::JavaScript => &[
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        // interface-per-lang-v1 (v0.4.2 M-022): C headers expose public API
        // as `declaration` nodes whose declarator is a `function_declarator`
        // (function prototypes, e.g. `int foo(int x);` in sds.h). The
        // walker filters non-function declarations via
        // `is_c_function_prototype` so fields/typedefs do not surface.
        Language::C | Language::Cpp => &["function_definition", "declaration"],
        Language::Ruby => &["method", "singleton_method"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        // tree-sitter-scala emits `function_declaration` for bodyless/abstract
        // `def f(): T` (trait & abstract-class contracts) and
        // `function_definition` for defs WITH a body. Both must be collected or
        // the entire abstract surface of a trait is dropped (#207: zio Clock
        // listed only the one concrete `unsafe`). Matches the precedent in
        // function_finder.rs / clones / the scala callgraph.
        Language::Scala => &["function_definition", "function_declaration", "def_definition"],
        Language::Php => &["function_definition", "method_declaration"],
        Language::Lua | Language::Luau => {
            &["function_declaration", "function_definition_statement"]
        }
        Language::Elixir => &["call"], // `def` and `defp` are calls in elixir tree-sitter
        Language::Ocaml => &["let_binding", "value_definition"],
        // real-repo-fixes-v1 (P9.BUG-R6/R7): wire kotlin/swift surface forms
        // for top-level/standalone function definitions.
        Language::Kotlin | Language::Swift => &["function_declaration"],
        // v0.5.0 SOL-001
        Language::Solidity => &[
            "function_definition",
            "constructor_definition",
            "fallback_function_definition",
            "receive_function_definition",
            "modifier_definition",
        ],
    }
}

/// Node kinds that represent class/struct/trait definitions for a given language.
fn class_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["class_definition"],
        Language::Rust => &["struct_item", "impl_item", "trait_item", "enum_item"],
        Language::Go => &["type_declaration"],
        Language::Java => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
        Language::TypeScript | Language::JavaScript => &[
            "class_declaration",
            "interface_declaration",
            "type_alias_declaration",
        ],
        Language::C => &["struct_specifier"],
        Language::Cpp => &["struct_specifier", "class_specifier"],
        Language::Ruby => &["class", "module"],
        Language::CSharp => &[
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
        ],
        Language::Scala => &["class_definition", "object_definition", "trait_definition"],
        Language::Php => &["class_declaration", "interface_declaration"],
        Language::Lua | Language::Luau => &[], // Lua doesn't have class syntax
        Language::Elixir => &["call"],         // defmodule is a call in elixir tree-sitter
        Language::Ocaml => &["module_definition", "type_definition"],
        // real-repo-fixes-v1 (P9.BUG-R6): kotlin classes/objects/interfaces.
        // Kotlin's tree-sitter grammar emits `class_declaration` for
        // `class`, `interface`, `enum class`, `data class`, etc., and
        // `object_declaration` for singleton `object` blocks.
        Language::Kotlin => &["class_declaration", "object_declaration"],
        // real-repo-fixes-v1 (P9.BUG-R7): swift classes/protocols. The
        // tree-sitter-swift grammar uses `class_declaration` for
        // class/struct/enum/actor/extension and `protocol_declaration`
        // separately. Including all gives a useful interface surface even
        // when files only contain extensions (e.g.
        // swift-collections/.../Span+Extras.swift).
        Language::Swift => &["class_declaration", "protocol_declaration"],
        // v0.5.0 SOL-001: Solidity contract / interface / library are
        // the three class-shaped containers.
        Language::Solidity => &[
            "contract_declaration",
            "interface_declaration",
            "library_declaration",
        ],
    }
}

/// Node kinds that represent decorated/annotated definitions.
fn decorator_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["decorated_definition"],
        Language::Java => &["annotation"],
        Language::TypeScript | Language::JavaScript => &["decorator"],
        Language::CSharp => &["attribute_list"],
        Language::Rust => &["attribute_item"],
        _ => &[],
    }
}

/// Node kinds for method definitions inside classes/structs.
fn method_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["function_definition"],
        Language::Rust => &["function_item"],
        Language::Go => &["method_declaration"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::TypeScript | Language::JavaScript => {
            &["method_definition", "public_field_definition"]
        }
        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
        // include `declaration` and `field_declaration` so member-function
        // *declarations* in header files (e.g. `int Parse(const char* xml);`)
        // surface as methods, not just inline `function_definition` bodies.
        // Non-function declarations (fields, typedefs) are filtered out by
        // `is_cpp_member_function_declaration` inside collect_methods_from_body.
        Language::C | Language::Cpp => {
            &["function_definition", "field_declaration", "declaration"]
        }
        Language::Ruby => &["method", "singleton_method"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        // Include `function_declaration` (bodyless/abstract `def f(): T`) so
        // trait/abstract-class method contracts surface as methods, not just
        // defs with bodies (#207). See function_node_kinds(Scala) above.
        Language::Scala => &["function_definition", "function_declaration", "def_definition"],
        Language::Php => &["method_declaration"],
        Language::Elixir => &["call"],
        Language::Ocaml => &["let_binding", "value_definition"],
        // interface-per-lang-v1 (v0.4.2 M-022): Kotlin/Swift class
        // bodies hold methods as `function_declaration` nodes. Without
        // this entry, every Kotlin class and every Swift class /
        // extension reported `methods: []`.
        Language::Kotlin | Language::Swift => &["function_declaration"],
        // v0.5.0 SOL-015a (M7): Solidity contract/interface/library
        // bodies (`contract_body`) hold methods as
        // `function_definition` / `constructor_definition` /
        // `fallback_function_definition` / `receive_function_definition`
        // / `modifier_definition` nodes. Without this arm,
        // `tldr interface TokenVault.sol` reported `methods: []` for
        // every contract.
        Language::Solidity => &[
            "function_definition",
            "constructor_definition",
            "fallback_function_definition",
            "receive_function_definition",
            "modifier_definition",
        ],
        _ => &[],
    }
}

// =============================================================================
// Public Name Detection (Language-Aware)
// =============================================================================

/// Check if a name is public based on language conventions.
///
/// - Python: names not starting with `_`
/// - Rust: `pub` keyword (checked at node level, not name level)
/// - Go: names starting with uppercase
/// - Ruby: methods not starting with `_` (private is keyword-based)
/// - Other languages: generally all names are considered public
///   (visibility modifiers are checked at the node level)
#[inline]
pub fn is_public_name(name: &str) -> bool {
    !name.starts_with('_')
}

/// Check if a name is public based on language-specific rules.
fn is_public_for_lang(name: &str, lang: Language) -> bool {
    match lang {
        Language::Python | Language::Ruby | Language::Lua | Language::Luau => {
            !name.starts_with('_')
        }
        Language::Go => {
            // Go exports start with an uppercase letter
            name.chars().next().is_some_and(|c| c.is_uppercase())
        }
        // For Rust, Java, TS, C#, etc. - visibility is determined by modifiers,
        // not naming. We check modifiers at the node level.
        _ => true,
    }
}

/// Check if a Rust node has truly public visibility (`pub`).
///
/// interface-per-lang-v1 (v0.4.2 M-022): the legacy check returned true
/// for any visibility_modifier text starting with `"pub"`, which also
/// matched the restricted forms `pub(crate)`, `pub(super)`, and
/// `pub(in crate::foo)`. Those items are not part of the crate's public
/// API and must not surface in `tldr interface`. Only accept bare
/// `"pub"` (no parenthesized scope) here.
fn is_rust_pub(node: Node, source: &[u8]) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "visibility_modifier" {
                let text = node_text(child, source).trim();
                // True public: exactly `pub` (no `pub(crate)` / `pub(super)` / `pub(in …)`).
                return text == "pub";
            }
        }
    }
    false
}

/// Check if a Java/C#/TS node has public access modifier.
fn has_public_modifier(node: Node, source: &[u8]) -> bool {
    // Check modifiers child
    if let Some(modifiers) = node.child_by_field_name("modifiers") {
        let text = node_text(modifiers, source);
        return text.contains("public");
    }
    // Also check for direct modifier children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if kind == "modifiers" || kind == "modifier" || kind == "access_modifier" {
                let text = node_text(child, source);
                if text.contains("public") {
                    return true;
                }
            }
            // For TypeScript: check for accessibility_modifier
            if kind == "accessibility_modifier" {
                let text = node_text(child, source);
                return text == "public";
            }
        }
    }
    // In Java, default (package-private) is not public, but for interface extraction
    // we treat non-private as public for utility
    true
}

/// Check if a C/C++ function is `static` (file-local, not public).
fn is_c_static(node: Node, source: &[u8]) -> bool {
    // Check for storage_class_specifier "static" before the function
    if let Some(prev) = node.prev_sibling() {
        if prev.kind() == "storage_class_specifier" {
            return node_text(prev, source) == "static";
        }
    }
    // Check declarator specifiers
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "storage_class_specifier" && node_text(child, source) == "static" {
                return true;
            }
        }
    }
    false
}

/// Language-aware visibility check for a node.
fn is_node_public(node: Node, source: &[u8], lang: Language) -> bool {
    let name = get_node_name(node, source, lang);
    let name_str = name.as_deref().unwrap_or("");

    match lang {
        Language::Rust => {
            // language-specific-bugs-v1 (P14.AGG14-10): `impl_item` blocks
            // are not declarations; they are method-collecting containers
            // and never carry their own `pub` modifier. Always treat them
            // as visible — the methods inside still get their own
            // `is_method_public` filtering. Without this, every
            // `impl Foo { pub fn ... }` block was filtered out at the
            // class layer, so `tldr interface` reported every struct with
            // `methods: 0` even when the inherent impl exposed dozens of
            // public methods.
            if node.kind() == "impl_item" {
                return true;
            }
            is_rust_pub(node, source)
        }
        Language::Go => name_str.chars().next().is_some_and(|c| c.is_uppercase()),
        Language::Python | Language::Ruby | Language::Lua | Language::Luau => {
            !name_str.starts_with('_')
        }
        Language::Java | Language::CSharp => has_public_modifier(node, source),
        Language::C | Language::Cpp => !is_c_static(node, source),
        // interface-per-lang-v1 (v0.4.2 M-022): scala default is public.
        // Filter only when an explicit `private` / `protected`
        // access_modifier appears inside a `modifiers` wrapper.
        Language::Scala => !is_scala_non_public(node, source),
        // For other languages, default to public
        _ => true,
    }
}

/// interface-per-lang-v1 (v0.4.2 M-022): return true when a Scala
/// definition carries an explicit `private` or `protected` access
/// modifier. tree-sitter-scala emits these under a `modifiers >
/// access_modifier` child whose text is the keyword.
fn is_scala_non_public(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mc = child.walk();
            for m in child.children(&mut mc) {
                if m.kind() == "access_modifier" {
                    let txt = node_text(m, source).trim();
                    if txt == "private" || txt == "protected" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// =============================================================================
// Name Extraction
// =============================================================================

/// Get the name of a definition node based on language.
fn get_node_name<'a>(node: Node<'a>, source: &'a [u8], lang: Language) -> Option<String> {
    // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE): when
    // tree-sitter-cpp misparses `class TINYXML2_LIB Foo { ... };` as a
    // function_definition wrapping a `class_specifier` whose `name` field
    // points at the export-macro identifier (`TINYXML2_LIB`, `MYLIB_EXPORT`,
    // …), the canonical `child_by_field_name("name")` lookup below would
    // surface the MACRO as the class name. Detect the misparse shape
    // (class_specifier with no body field, parent is function_definition,
    // followed by an `identifier` sibling) and return the corrected real
    // class name instead. See BUG-CPP-P20-02 / tinyxml2.h regression.
    if matches!(lang, Language::Cpp)
        && matches!(node.kind(), "class_specifier" | "struct_specifier")
    {
        if let Some(corrected) = extract_cpp_macro_misparsed_class_name(node, source) {
            return Some(corrected);
        }
    }

    // First try the common "name" field
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(node_text(name_node, source).to_string());
    }

    match lang {
        Language::C | Language::Cpp => {
            // C/C++ function_definition has a "declarator" field
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_c_declarator_name(declarator, source);
            }
        }
        Language::Go => {
            // Go type_declaration wraps type_spec which has the name
            if node.kind() == "type_declaration" {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_spec" {
                            if let Some(name_node) = child.child_by_field_name("name") {
                                return Some(node_text(name_node, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        Language::Rust => {
            // Rust impl_item doesn't always have a "name" field
            if node.kind() == "impl_item" {
                // Look for the type being implemented
                if let Some(type_node) = node.child_by_field_name("type") {
                    return Some(node_text(type_node, source).to_string());
                }
                // Fallback: find type_identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_identifier" || child.kind() == "generic_type" {
                            return Some(node_text(child, source).to_string());
                        }
                    }
                }
            }
        }
        Language::Elixir => {
            // In Elixir, `def` and `defmodule` are call nodes
            // The first argument is the name
            if node.kind() == "call" {
                if let Some(target) = node.child(0) {
                    let target_text = node_text(target, source);
                    if target_text == "def"
                        || target_text == "defp"
                        || target_text == "defmacro"
                        || target_text == "defmacrop"
                        || target_text == "defmodule"
                    {
                        // The Elixir tree-sitter grammar exposes the
                        // arguments either via a named "arguments" field
                        // or as the second positional child depending on
                        // grammar version. Try field first, fall back to
                        // child(1) — and accept either an `arguments`
                        // wrapper or a bare `call`/`identifier`.
                        let args_node = node
                            .child_by_field_name("arguments")
                            .or_else(|| node.child(1));
                        if let Some(args) = args_node {
                            // If args is the `arguments` wrapper, peel one
                            // level. Otherwise `args` itself is the first
                            // argument node (call / identifier / alias).
                            let first_arg = if args.kind() == "arguments" {
                                args.child(0)
                            } else {
                                Some(args)
                            };
                            if let Some(first_arg) = first_arg {
                                // For def/defp, the first arg may be a call (name + params)
                                if first_arg.kind() == "call" {
                                    if let Some(fn_name) = first_arg.child(0) {
                                        return Some(node_text(fn_name, source).to_string());
                                    }
                                }
                                // For def with a guard: `def fn(x) when guard`,
                                // the first arg is a `binary_operator` whose
                                // left side is the call we want.
                                if first_arg.kind() == "binary_operator" {
                                    let mut bin_cursor = first_arg.walk();
                                    for bin_child in first_arg.children(&mut bin_cursor) {
                                        if bin_child.kind() == "call" {
                                            if let Some(fname) = bin_child.child(0) {
                                                return Some(
                                                    node_text(fname, source).to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                                return Some(node_text(first_arg, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        Language::Ocaml => {
            // OCaml `value_definition` wraps one or more `let_binding` children.
            // The function name lives on `let_binding.pattern` (a `value_name`).
            // BUG-AGG-8 (P11): the interface extractor was walking
            // `value_definition` directly and querying `child_by_field_name("name")`
            // which doesn't exist for OCaml — leaving every name empty.
            if node.kind() == "value_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "let_binding" {
                        if let Some(pat) = child.child_by_field_name("pattern") {
                            return Some(node_text(pat, source).to_string());
                        }
                    }
                }
            }
            if node.kind() == "let_binding" {
                if let Some(pat) = node.child_by_field_name("pattern") {
                    return Some(node_text(pat, source).to_string());
                }
            }
            // language-adapters-completeness-v1 (BUG-AGG12-9): the
            // synthetic class node for an OCaml file is a
            // `module_definition` (e.g. `module Make (V) = struct ... end`
            // in dune's dag.ml). The grammar does not expose a `name`
            // field on `module_definition`; the name lives on the
            // first `module_name` child of the inner `module_binding`.
            // P11's BUG-AGG-8 fix only addressed the function-level
            // extractor (`value_definition` / `let_binding`); module
            // wrappers remained nameless, surfacing as empty strings in
            // every interface report for files that wrap their content
            // in a functor or named module.
            if node.kind() == "module_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "module_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if bind_child.kind() == "module_name" {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                }
            }
            // `type t = { ... }` and similar — the type name is the
            // first `type_constructor` (or fallback identifier) child.
            if node.kind() == "type_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "type_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if matches!(
                                bind_child.kind(),
                                "type_constructor" | "type_constructor_path"
                            ) {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                    if matches!(child.kind(), "type_constructor" | "type_constructor_path") {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Lua | Language::Luau => {
            // Try the "name" field first (already done above), then check child nodes
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" || child.kind() == "dot_index_expression" {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Ruby => {
            // Ruby methods: first identifier child after "def"
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" || child.kind() == "constant" {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        _ => {}
    }

    None
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
/// Detect the export-macro misparse shape and return the real class name.
///
/// tree-sitter-cpp parses `class TINYXML2_LIB Foo { ... };` as:
///   function_definition
///     class_specifier (name=type_identifier "TINYXML2_LIB", no body field)
///     identifier "Foo"             <-- the REAL class name
///     [ERROR : public Base]?       <-- base-clause hint (optional)
///     compound_statement { ... }   <-- the REAL class body
///
/// Returns `Some(real_name)` only when the class_specifier:
///   1. has no `body` field of its own (would have been `field_declaration_list`),
///   2. has a `function_definition` parent, AND
///   3. an `identifier` sibling appears after it inside that parent.
///
/// Otherwise returns `None` so callers fall back to the canonical name field.
fn extract_cpp_macro_misparsed_class_name(
    class_node: Node,
    source: &[u8],
) -> Option<String> {
    // Real class declarations have a field_declaration_list body. If a body
    // is present, this is NOT the macro-misparse shape.
    if class_node.child_by_field_name("body").is_some() {
        return None;
    }
    // Defense-in-depth: also reject if the class_specifier has a
    // field_declaration_list anywhere among its direct children (some
    // grammar versions may not expose it via the "body" field name).
    let mut self_cursor = class_node.walk();
    for child in class_node.children(&mut self_cursor) {
        if child.kind() == "field_declaration_list" {
            return None;
        }
    }

    // Look up to a function_definition parent — that's the misparse wrapper.
    let parent = class_node.parent()?;
    if parent.kind() != "function_definition" {
        return None;
    }

    // Find the class_specifier's position among parent's children, then
    // scan forward for the first `identifier` (the real class name).
    let mut pcursor = parent.walk();
    let mut saw_class_specifier = false;
    for sib in parent.children(&mut pcursor) {
        if !saw_class_specifier {
            if sib.id() == class_node.id() {
                saw_class_specifier = true;
            }
            continue;
        }
        // After the class_specifier, the next bare `identifier` is the
        // real class name. Skip ERROR / compound_statement wrappers.
        if sib.kind() == "identifier" {
            let text = node_text(sib, source).to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): return the
/// `compound_statement` sibling that holds the real class body when
/// `class_specifier` is the macro-misparse shape. Returns `None` for the
/// canonical (well-parsed) shape so callers fall back to
/// `field_declaration_list`.
fn extract_cpp_macro_misparsed_class_body<'a>(class_node: Node<'a>) -> Option<Node<'a>> {
    if class_node.child_by_field_name("body").is_some() {
        return None;
    }
    let parent = class_node.parent()?;
    if parent.kind() != "function_definition" {
        return None;
    }
    let mut pcursor = parent.walk();
    let mut saw_class_specifier = false;
    for sib in parent.children(&mut pcursor) {
        if !saw_class_specifier {
            if sib.id() == class_node.id() {
                saw_class_specifier = true;
            }
            continue;
        }
        if sib.kind() == "compound_statement" {
            return Some(sib);
        }
    }
    None
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): true iff this
/// `function_definition` is actually a macro-prefixed class declaration
/// (e.g. `class TINYXML2_LIB Foo { ... };`) that tree-sitter-cpp misparsed.
/// Used by the deep walker so the misparsed wrapper is not emitted as a
/// top-level function (the inner class_specifier produces the class entry
/// instead).
fn is_cpp_macro_misparsed_class_wrapper(func_def: Node) -> bool {
    if func_def.kind() != "function_definition" {
        return false;
    }
    let mut cursor = func_def.walk();
    for child in func_def.children(&mut cursor) {
        if matches!(child.kind(), "class_specifier" | "struct_specifier") {
            if child.child_by_field_name("body").is_some() {
                continue;
            }
            // No own body — confirm there's a compound_statement sibling
            // so the misparse shape is unambiguous (otherwise the
            // class_specifier could be a forward declaration nested in
            // an unrelated function signature).
            let mut sib_cursor = func_def.walk();
            let mut saw = false;
            for sib in func_def.children(&mut sib_cursor) {
                if !saw {
                    if sib.id() == child.id() {
                        saw = true;
                    }
                    continue;
                }
                if sib.kind() == "compound_statement" {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract name from a C/C++ declarator (which may be nested).
///
/// cl6-interface-v1 (GH #78): besides the plain `identifier` /
/// `field_identifier` leaves, C++ member-function declarators terminate in
/// three other named leaves that the legacy extractor dropped (producing an
/// empty name → the member silently vanished from `tldr interface`):
///
///   * `destructor_name`     → `~StrPair`
///   * `operator_name`       → `operator[]`, `operator=`, `operator==`
///   * `qualified_identifier` / `scoped_identifier`
///     → out-of-class definitions `Foo::method`; we keep the trailing
///     name segment (`method`) so the member matches its in-class
///     spelling, falling back to the full qualified text only when the
///     segment cannot be resolved.
///
/// This mirrors the canonical leaf handling in
/// `tldr-core::analysis::references::find_cpp_declarator_match`.
fn extract_c_declarator_name(declarator: Node, source: &[u8]) -> Option<String> {
    match declarator.kind() {
        // Plain leaves and the C++ operator / destructor leaves all carry the
        // member name verbatim as their own text.
        "identifier" | "field_identifier" | "destructor_name" | "operator_name" => {
            return Some(node_text(declarator, source).to_string());
        }
        "qualified_identifier" | "scoped_identifier" => {
            // `Foo::bar` — the trailing `name` field is the member's own
            // (possibly further-qualified) name. Recurse into it so a
            // `Foo::Inner::method` resolves to `method`.
            if let Some(name_node) = declarator.child_by_field_name("name") {
                if let Some(resolved) = extract_c_declarator_name(name_node, source) {
                    return Some(resolved);
                }
            }
            // Couldn't resolve the trailing segment — keep the full
            // qualified text so the member doesn't disappear entirely.
            return Some(node_text(declarator, source).to_string());
        }
        _ => {}
    }
    // function_declarator (and the pointer/reference/parenthesized/init
    // wrappers a return type introduces) carries the name via its
    // `declarator` field.
    if let Some(inner) = declarator.child_by_field_name("declarator") {
        return extract_c_declarator_name(inner, source);
    }
    // cl6-interface-v1 (GH #78): some wrapper declarators do NOT expose the
    // inner declarator via the `declarator` field — notably
    // `reference_declarator` / `pointer_declarator` for a `T& operator[]()` /
    // `T* foo()` return type, where the inner `function_declarator` is a bare
    // positional child after the `&` / `*` token. Scan all children for the
    // next recursable declarator or named leaf so these names are not dropped.
    let mut cursor = declarator.walk();
    for child in declarator.children(&mut cursor) {
        if matches!(
            child.kind(),
            "identifier"
                | "field_identifier"
                | "destructor_name"
                | "operator_name"
                | "qualified_identifier"
                | "scoped_identifier"
                | "function_declarator"
                | "pointer_declarator"
                | "reference_declarator"
                | "parenthesized_declarator"
                | "init_declarator"
        ) {
            if let Some(resolved) = extract_c_declarator_name(child, source) {
                return Some(resolved);
            }
        }
    }
    None
}

// =============================================================================
// __all__ Extraction (Python-specific)
// =============================================================================

/// Extract the contents of `__all__` if defined in the module (Python only).
pub fn extract_all_exports(root: Node, source: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        if child.kind() == "expression_statement" {
            if let Some(assignment) = child.child(0) {
                if assignment.kind() == "assignment" {
                    if let Some(left) = assignment.child_by_field_name("left") {
                        if left.kind() == "identifier" {
                            let name = node_text(left, source);
                            if name == "__all__" {
                                if let Some(right) = assignment.child_by_field_name("right") {
                                    return extract_list_strings(right, source);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Extract string elements from a list node.
fn extract_list_strings(node: Node, source: &[u8]) -> Option<Vec<String>> {
    if node.kind() != "list" {
        return None;
    }

    let mut exports = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "string" {
            let text = node_text(child, source);
            let cleaned = text
                .trim_start_matches(['"', '\''])
                .trim_end_matches(['"', '\'']);
            exports.push(cleaned.to_string());
        }
    }

    if exports.is_empty() {
        None
    } else {
        Some(exports)
    }
}

// =============================================================================
// Signature Extraction (Language-Aware)
// =============================================================================

/// Extract the function signature from a definition node.
///
/// For Python, reconstructs from parameter nodes.
/// For other languages, extracts the raw text of parameters and return type.
pub fn extract_function_signature(func_node: Node, source: &[u8], lang: Language) -> String {
    match lang {
        Language::Python => extract_python_signature(func_node, source),
        Language::Rust => extract_rust_signature(func_node, source),
        Language::Go => extract_go_signature(func_node, source),
        Language::Java | Language::CSharp => extract_java_like_signature(func_node, source),
        Language::TypeScript | Language::JavaScript => extract_ts_signature(func_node, source),
        Language::C | Language::Cpp => extract_c_signature(func_node, source),
        Language::Ruby => extract_ruby_signature(func_node, source),
        Language::Php => extract_php_signature(func_node, source),
        Language::Scala => extract_scala_signature(func_node, source),
        Language::Ocaml => extract_ocaml_signature(func_node, source),
        Language::Elixir => extract_elixir_signature(func_node, source),
        Language::Swift => extract_swift_signature(func_node, source),
        _ => extract_generic_signature(func_node, source),
    }
}

/// Swift signature: the parameter clause plus any `async`/`throws` effects and
/// the `-> ReturnType`. tree-sitter-swift does NOT expose a `parameters` field
/// (params are loose `parameter` children between `(` and `)`), so the generic
/// `child_by_field_name("parameters")` extractor returned an empty string for
/// EVERY Swift method (#239). Reconstruct AST-driven by slicing the source from
/// the opening `(` up to (but excluding) the `function_body` — this captures
/// `(using e: Encoder) throws -> URLRequest` verbatim while dropping the body.
/// For `init`/bodyless/protocol requirements the same span logic applies.
fn extract_swift_signature(func_node: Node, source: &[u8]) -> String {
    // Find the opening `(` of the parameter clause and the body (if any).
    let mut open_paren: Option<Node> = None;
    let mut body: Option<Node> = None;
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "(" && open_paren.is_none() {
            open_paren = Some(child);
        }
        if child.kind() == "function_body" {
            body = Some(child);
        }
    }

    let Some(open) = open_paren else {
        // No parameter clause found — fall back to the generic extractor.
        return extract_generic_signature(func_node, source);
    };

    let start = open.start_byte();
    // End at the body's start (dropping `{ ... }`), else at the node end
    // (bodyless protocol/abstract requirement).
    let end = match body {
        Some(b) => b.start_byte(),
        None => func_node.end_byte(),
    };
    if start >= end || end > source.len() {
        return extract_generic_signature(func_node, source);
    }
    std::str::from_utf8(&source[start..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// OCaml signature: walk the `let_binding` parameters and optional return type.
///
/// BUG-AGG-8 (P11): without an OCaml-specific signature extractor the
/// generic fallback (`child_by_field_name("parameters")`) returns nothing,
/// so signatures are empty strings even when names are present.
fn extract_ocaml_signature(func_node: Node, source: &[u8]) -> String {
    // Find the inner let_binding if we were handed a value_definition.
    let binding_owned;
    let binding = if func_node.kind() == "value_definition" {
        let mut found: Option<Node> = None;
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                found = Some(child);
                break;
            }
        }
        match found {
            Some(b) => {
                binding_owned = b;
                binding_owned
            }
            None => return String::new(),
        }
    } else {
        func_node
    };

    let mut params = Vec::new();
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if child.kind() == "parameter" {
            // Parameter may have a "pattern" field with value_pattern /
            // typed_pattern / unit / tuple_pattern, or fall back to the
            // raw text.
            if let Some(pattern) = child.child_by_field_name("pattern") {
                let text = node_text(pattern, source).trim();
                if !text.is_empty() {
                    params.push(text.to_string());
                    continue;
                }
            }
            // Fallback: walk children for value_pattern / value_name.
            let mut inner_cursor = child.walk();
            let mut handled = false;
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "value_pattern" || inner.kind() == "value_name" {
                    params.push(node_text(inner, source).to_string());
                    handled = true;
                    break;
                }
            }
            if !handled {
                let text = node_text(child, source).trim();
                if !text.is_empty() {
                    params.push(text.to_string());
                }
            }
        }
    }

    let mut sig = format!("({})", params.join(", "));

    // Optional return type: `: type` between the last parameter and `=`.
    let return_type = extract_ocaml_signature_return_type(binding, source);
    if let Some(ret) = return_type {
        sig.push_str(" : ");
        sig.push_str(&ret);
    }

    sig
}

fn extract_ocaml_signature_return_type(binding: Node, source: &[u8]) -> Option<String> {
    let mut last_was_colon = false;
    let mut past_all_params = false;
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        let kind = child.kind();
        if kind == "parameter" {
            past_all_params = false;
            last_was_colon = false;
            continue;
        }
        if kind != "parameter" && !past_all_params {
            past_all_params = true;
        }
        if past_all_params && kind == ":" {
            last_was_colon = true;
            continue;
        }
        if last_was_colon && kind == "=" {
            return None;
        }
        if last_was_colon && kind != "=" {
            let t = node_text(child, source).trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
            last_was_colon = false;
        }
        if kind == "=" {
            break;
        }
    }
    None
}

/// Elixir signature: extract the parameter list of a `def`/`defp`/`defmacro`
/// call node. BUG-AGG-9 (P11): without an Elixir-specific signature
/// extractor, `tldr interface` would emit empty signatures for Elixir
/// modules even after wiring up name extraction.
fn extract_elixir_signature(func_node: Node, source: &[u8]) -> String {
    if func_node.kind() != "call" {
        return String::new();
    }
    // Structure: (call (identifier "def") (arguments (call (identifier "name") (arguments ...))))
    let args_node = match func_node
        .child_by_field_name("arguments")
        .or_else(|| func_node.child(1))
    {
        Some(a) => a,
        None => return String::new(),
    };
    let first_arg = if args_node.kind() == "arguments" {
        match args_node.child(0) {
            Some(a) => a,
            None => return String::new(),
        }
    } else {
        args_node
    };

    // Identifier-only def (no params): `def foo do ... end`
    if first_arg.kind() == "identifier" {
        return "()".to_string();
    }

    // call form: `def foo(a, b)` -> first_arg is a call(name, arguments)
    let inner_call = match first_arg.kind() {
        "call" => first_arg,
        "binary_operator" => {
            // `def foo(...) when guard` — find the inner call.
            let mut found: Option<Node> = None;
            let mut cursor = first_arg.walk();
            for c in first_arg.children(&mut cursor) {
                if c.kind() == "call" {
                    found = Some(c);
                    break;
                }
            }
            match found {
                Some(c) => c,
                None => return String::new(),
            }
        }
        _ => return String::new(),
    };

    // The call's second child is its `arguments` block. The arguments
    // text is the raw source slice — for `def foo(a, b)` that's `(a, b)`,
    // so just emit it verbatim. When it's a bareword call (no parens) the
    // text won't have surrounding parens; wrap it in that case.
    if let Some(call_args) = inner_call.child(1) {
        if call_args.kind() == "arguments" {
            let raw = node_text(call_args, source).trim();
            if raw.starts_with('(') && raw.ends_with(')') {
                return raw.to_string();
            }
            return format!("({})", raw);
        }
    }
    "()".to_string()
}

/// Python signature: reconstruct from parameter nodes.
fn extract_python_signature(func_node: Node, source: &[u8]) -> String {
    let mut params = Vec::new();

    if let Some(params_node) = func_node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    params.push(node_text(child, source).to_string());
                }
                "typed_parameter" => {
                    params.push(extract_typed_parameter(child, source));
                }
                "default_parameter" => {
                    params.push(extract_default_parameter(child, source));
                }
                "typed_default_parameter" => {
                    params.push(extract_typed_default_parameter(child, source));
                }
                "list_splat_pattern" | "dictionary_splat_pattern" => {
                    params.push(node_text(child, source).to_string());
                }
                _ => {}
            }
        }
    }

    let params_str = params.join(", ");
    let mut signature = format!("({})", params_str);

    if let Some(return_type) = func_node.child_by_field_name("return_type") {
        let return_text = node_text(return_type, source);
        signature.push_str(" -> ");
        signature.push_str(return_text);
    }

    signature
}

/// Rust signature: extract parameters and return type.
fn extract_rust_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(" -> ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Go signature: extract parameters and return type.
fn extract_go_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(result) = func_node.child_by_field_name("result") {
        sig.push(' ');
        sig.push_str(node_text(result, source));
    }

    sig
}

/// Java/C# signature: extract parameters from formal_parameters.
fn extract_java_like_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    // Try "parameters" field first, then look for "formal_parameters" or a parameter_list child
    let params_node = func_node.child_by_field_name("parameters").or_else(|| {
        // Search for formal_parameters or parameter_list node among children
        let mut cursor = func_node.walk();
        let found = func_node
            .children(&mut cursor)
            .find(|&child| child.kind() == "formal_parameters" || child.kind() == "parameter_list");
        found
    });

    if let Some(params) = params_node {
        sig.push_str(node_text(params, source));
    }

    // For Java, check for return type (it's the "type" field)
    if let Some(ret) = func_node.child_by_field_name("type") {
        // Prepend return type
        let ret_text = node_text(ret, source);
        sig = format!("{}: {}", sig, ret_text);
    }

    sig
}

/// TypeScript/JavaScript signature.
fn extract_ts_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(": ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// C/C++ signature: extract from declarator.
fn extract_c_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        // The declarator includes function name and parameter list
        // We want just the parameters portion
        if let Some(params) = declarator.child_by_field_name("parameters") {
            sig.push_str(node_text(params, source));
        }
    }

    // Return type is typically the first child (type specifier)
    if let Some(type_node) = func_node.child_by_field_name("type") {
        let type_text = node_text(type_node, source);
        if !type_text.is_empty() {
            sig = format!("{}: {}", sig, type_text);
        }
    }

    sig
}

/// Ruby signature.
fn extract_ruby_signature(func_node: Node, source: &[u8]) -> String {
    if let Some(params) = func_node.child_by_field_name("parameters") {
        node_text(params, source).to_string()
    } else {
        // Check for method_parameters child
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "method_parameters" {
                return node_text(child, source).to_string();
            }
        }
        "()".to_string()
    }
}

/// PHP signature.
fn extract_php_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(": ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Scala signature.
fn extract_scala_signature(func_node: Node, source: &[u8]) -> String {
    // cl4-interface-v1 (IT3-scala-01/02/03, GH #78): a Scala
    // `function_definition` exposes BOTH its type-parameter list and every
    // (possibly curried) value-parameter clause under the SAME field name
    // `parameters`. The tree-sitter-scala grammar models them as distinct
    // node KINDS, though: `type_parameters` for `[F[_], A]` and `parameters`
    // for `(capacity: Int)` / `(implicit F: ...)`. The previous extractor
    // used `child_by_field_name("parameters")`, which returns only the FIRST
    // such child — the `type_parameters` list — so the real value parameter
    // `capacity` was dropped and the type parameters were reported as params.
    // Walk all field-`parameters` children and keep the curried value
    // clauses (kind == "parameters"), preserving the leading type-parameter
    // list separately so generic methods still surface their type variables.
    let mut type_params = String::new();
    let mut value_clauses = String::new();
    let mut cursor = func_node.walk();
    let mut idx = 0u32;
    for child in func_node.children(&mut cursor) {
        if func_node.field_name_for_child(idx) == Some("parameters") {
            match child.kind() {
                "type_parameters" => {
                    // Only one type-parameter list is legal; keep the first.
                    if type_params.is_empty() {
                        type_params.push_str(node_text(child, source));
                    }
                }
                "parameters" => {
                    // Curried value clauses: concatenate each `(...)` clause
                    // verbatim so `(capacity: Int)(implicit F: ...)` is kept.
                    value_clauses.push_str(node_text(child, source));
                }
                _ => {}
            }
        }
        idx += 1;
    }

    let mut sig = String::new();
    sig.push_str(&type_params);
    sig.push_str(&value_clauses);

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(": ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Generic signature: try to find parameters/return type fields.
fn extract_generic_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    sig
}

/// Extract a typed parameter (name: type) - Python-specific.
fn extract_typed_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child(0)
        .filter(|c| c.kind() == "identifier")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let type_hint = node
        .child_by_field_name("type")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    if type_hint.is_empty() {
        name.to_string()
    } else {
        format!("{}: {}", name, type_hint)
    }
}

/// Extract a default parameter (name=default) - Python-specific.
fn extract_default_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let value = node
        .child_by_field_name("value")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    format!("{} = {}", name, value)
}

/// Extract a typed default parameter (name: type = default) - Python-specific.
fn extract_typed_default_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let type_hint = node
        .child_by_field_name("type")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let value = node
        .child_by_field_name("value")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    if type_hint.is_empty() {
        format!("{} = {}", name, value)
    } else {
        format!("{}: {} = {}", name, type_hint, value)
    }
}

// =============================================================================
// Function Info Extraction (Language-Aware)
// =============================================================================

/// Extract function information from a function definition node.
pub fn extract_function_info(func_node: Node, source: &[u8], lang: Language) -> FunctionInfo {
    let name = get_node_name(func_node, source, lang).unwrap_or_default();
    let signature = extract_function_signature(func_node, source, lang);
    let lineno = func_node.start_position().row as u32 + 1;
    let is_async = detect_async(func_node, source, lang);
    let docstring = extract_docstring(func_node, source, lang);

    FunctionInfo {
        name,
        signature,
        docstring,
        lineno,
        is_async,
    }
}

/// Detect if a function is async.
fn detect_async(func_node: Node, source: &[u8], lang: Language) -> bool {
    match lang {
        Language::Python => {
            let func_text = node_text(func_node, source);
            func_text.starts_with("async ")
        }
        Language::Rust => {
            // Check for "async" keyword child
            for i in 0..func_node.child_count() {
                if let Some(child) = func_node.child(i) {
                    if node_text(child, source) == "async" {
                        return true;
                    }
                }
            }
            false
        }
        Language::TypeScript | Language::JavaScript => {
            // Check for async keyword
            let func_text = node_text(func_node, source);
            func_text.starts_with("async ")
        }
        Language::CSharp => {
            // interface-per-lang-v1 (v0.4.2 M-022): tree-sitter-c-sharp
            // emits `modifier` nodes (singular, one per keyword) as
            // direct children of `method_declaration`, not under a
            // `modifiers` field. The legacy `child_by_field_name`
            // lookup therefore always returned None and every method
            // reported `is_async:false`.
            let mut cursor = func_node.walk();
            for child in func_node.children(&mut cursor) {
                if child.kind() == "modifier" && node_text(child, source) == "async" {
                    return true;
                }
            }
            // Defense-in-depth: also accept the legacy `modifiers` field
            // shape for grammar versions that may wrap them.
            if let Some(modifiers) = func_node.child_by_field_name("modifiers") {
                return node_text(modifiers, source).contains("async");
            }
            false
        }
        Language::Elixir => {
            // Elixir doesn't have async keyword in the traditional sense
            false
        }
        _ => false,
    }
}

// =============================================================================
// Docstring / Doc Comment Extraction (Language-Aware)
// =============================================================================

/// Extract docstring or doc comment from a function or class node.
fn extract_docstring(node: Node, source: &[u8], lang: Language) -> Option<String> {
    match lang {
        Language::Python => extract_python_docstring(node, source),
        Language::Rust => extract_rust_doc_comment(node, source),
        Language::Go => extract_go_doc_comment(node, source),
        Language::Java | Language::CSharp | Language::Scala | Language::Php => {
            extract_javadoc_comment(node, source)
        }
        Language::TypeScript | Language::JavaScript => extract_jsdoc_comment(node, source),
        Language::Ruby => extract_ruby_comment(node, source),
        Language::Elixir => extract_elixir_doc(node, source),
        _ => None,
    }
}

/// Python docstring: first string in function/class body.
fn extract_python_docstring(node: Node, source: &[u8]) -> Option<String> {
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        let first_stmt = body.children(&mut cursor).next();
        if let Some(child) = first_stmt {
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.child(0) {
                    if expr.kind() == "string" {
                        let text = node_text(expr, source);
                        let cleaned = text
                            .trim_start_matches("\"\"\"")
                            .trim_start_matches("'''")
                            .trim_end_matches("\"\"\"")
                            .trim_end_matches("'''")
                            .trim();
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Rust doc comments: /// or //! preceding the node.
fn extract_rust_doc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        let kind = sib.kind();
        if kind == "line_comment" {
            let text = node_text(sib, source);
            if text.starts_with("///") || text.starts_with("//!") {
                let content = text
                    .trim_start_matches("///")
                    .trim_start_matches("//!")
                    .trim();
                comments.push(content.to_string());
            } else {
                break;
            }
        } else if kind == "attribute_item" {
            // Skip attributes between doc comments
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Go doc comment: preceding line comment block.
fn extract_go_doc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "comment" {
            let text = node_text(sib, source);
            let content = text.trim_start_matches("//").trim();
            comments.push(content.to_string());
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Javadoc-style: /** ... */ preceding the node.
fn extract_javadoc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        let kind = sib.kind();
        if kind == "block_comment" || kind == "comment" || kind == "multiline_comment" {
            let text = node_text(sib, source);
            if text.starts_with("/**") {
                let cleaned = text
                    .trim_start_matches("/**")
                    .trim_end_matches("*/")
                    .lines()
                    .map(|l| l.trim().trim_start_matches('*').trim())
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Some(cleaned);
            }
        } else if kind == "annotation" || kind == "marker_annotation" || kind == "attribute_list" {
            // Skip annotations/attributes
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }
    None
}

/// JSDoc: /** ... */ preceding the node.
fn extract_jsdoc_comment(node: Node, source: &[u8]) -> Option<String> {
    extract_javadoc_comment(node, source)
}

/// Ruby: # comments preceding the node.
fn extract_ruby_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "comment" {
            let text = node_text(sib, source);
            let content = text.trim_start_matches('#').trim();
            comments.push(content.to_string());
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Elixir: @doc or @moduledoc preceding the node.
fn extract_elixir_doc(node: Node, source: &[u8]) -> Option<String> {
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "unary_operator" || sib.kind() == "call" {
            let text = node_text(sib, source);
            if text.starts_with("@doc") || text.starts_with("@moduledoc") {
                // Extract the string content
                let cleaned = text
                    .trim_start_matches("@moduledoc")
                    .trim_start_matches("@doc")
                    .trim()
                    .trim_start_matches("\"\"\"")
                    .trim_end_matches("\"\"\"")
                    .trim_start_matches('"')
                    .trim_end_matches('"')
                    .trim();
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
        } else if sib.kind() == "comment" {
            // skip
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }
    None
}

// =============================================================================
// Class Info Extraction (Language-Aware)
// =============================================================================

/// Extract class/struct/trait information from a definition node.
pub fn extract_class_info(class_node: Node, source: &[u8], lang: Language) -> ClassInfo {
    let name = get_node_name(class_node, source, lang).unwrap_or_default();
    let lineno = class_node.start_position().row as u32 + 1;

    // Extract base classes / implemented interfaces
    let bases = extract_base_classes(class_node, source, lang);

    // Extract methods
    let mut methods = Vec::new();
    let mut private_method_count = 0u32;

    let method_kinds = method_node_kinds(lang);
    let body_node = find_body_node(class_node, lang);

    if let Some(body) = body_node {
        collect_methods_from_body(
            body,
            source,
            lang,
            method_kinds,
            &mut methods,
            &mut private_method_count,
        );
    }

    ClassInfo {
        name,
        lineno,
        bases,
        methods,
        private_method_count,
    }
}

/// Find the body/block node of a class/struct definition.
fn find_body_node<'a>(class_node: Node<'a>, lang: Language) -> Option<Node<'a>> {
    // Try common field names
    if let Some(body) = class_node.child_by_field_name("body") {
        return Some(body);
    }
    if let Some(body) = class_node.child_by_field_name("members") {
        return Some(body);
    }

    match lang {
        Language::Rust => {
            // For impl_item, look for declaration_list
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "declaration_list" {
                    return Some(child);
                }
            }
            None
        }
        Language::Java | Language::CSharp => {
            // class_body or interface_body
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_body"
                    || child.kind() == "interface_body"
                    || child.kind() == "enum_body"
                    || child.kind() == "declaration_list"
                {
                    return Some(child);
                }
            }
            None
        }
        Language::TypeScript | Language::JavaScript => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_body" {
                    return Some(child);
                }
            }
            None
        }
        Language::Cpp => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "field_declaration_list" {
                    return Some(child);
                }
            }
            // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): macro-misparsed
            // class bodies live on the `compound_statement` sibling of the
            // class_specifier inside the wrapping function_definition.
            extract_cpp_macro_misparsed_class_body(class_node)
        }
        Language::Ruby => {
            // Ruby class body is inside a body_statement child
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "body_statement" {
                    return Some(child);
                }
            }
            // Fallback: use the class node itself
            Some(class_node)
        }
        _ => {
            // Default: try common body kinds
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                let kind = child.kind();
                if kind.contains("body")
                    || kind.contains("block")
                    || kind == "declaration_list"
                    || kind == "template_body"
                {
                    return Some(child);
                }
            }
            None
        }
    }
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): true iff this
/// `declaration`/`field_declaration` node wraps a member-function
/// declaration (declarator chain reaches a `function_declarator`). Field
/// and typedef declarations are rejected so non-method members don't get
/// mis-counted in `methods[]`.
fn is_cpp_member_function_declaration(node: Node) -> bool {
    let kind = node.kind();
    if kind != "declaration" && kind != "field_declaration" {
        return false;
    }
    // Walk the `declarator` field chain, peeling pointer_declarator /
    // reference_declarator wrappers, until we either hit a
    // `function_declarator` (yes) or a leaf identifier (no).
    let mut current = node.child_by_field_name("declarator");
    let mut hops = 0usize;
    while let Some(decl) = current {
        if hops > 6 {
            return false;
        }
        match decl.kind() {
            "function_declarator" => return true,
            "pointer_declarator"
            | "reference_declarator"
            | "init_declarator"
            | "parenthesized_declarator" => {
                // cl6-interface-v1 (GH #78): a `reference_declarator` /
                // `pointer_declarator` introduced by a `T&` / `T*` return
                // type does NOT expose its inner declarator via the
                // `declarator` field — the inner `function_declarator` is a
                // bare positional child after the `&` / `*` token. Without
                // scanning positional children too, `Vec& operator=(...)`
                // (a bodiless `field_declaration`) was wrongly rejected and
                // dropped from `methods[]`. Prefer the field, fall back to
                // the first wrapper/function declarator child.
                current = decl.child_by_field_name("declarator");
                if current.is_none() {
                    let mut c = decl.walk();
                    current = decl.children(&mut c).find(|ch| {
                        matches!(
                            ch.kind(),
                            "function_declarator"
                                | "pointer_declarator"
                                | "reference_declarator"
                                | "init_declarator"
                                | "parenthesized_declarator"
                        )
                    });
                }
            }
            _ => return false,
        }
        hops += 1;
    }
    false
}

/// Collect methods from a class body node.
fn collect_methods_from_body(
    body: Node,
    source: &[u8],
    lang: Language,
    method_kinds: &[&str],
    methods: &mut Vec<MethodInfo>,
    private_count: &mut u32,
) {
    let mut cursor = body.walk();
    let decorator_kinds = decorator_node_kinds(lang);

    for child in body.children(&mut cursor) {
        let kind = child.kind();

        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): in a macro-misparsed
        // class body (`compound_statement`), tree-sitter-cpp nests
        // declarations under a `labeled_statement` whose label is the
        // access-specifier keyword (`public:` / `private:` / `protected:`).
        // Recurse so the inner method declarations still surface.
        if matches!(lang, Language::C | Language::Cpp) && kind == "labeled_statement" {
            // Heuristic: only treat as access-specifier wrapper when the
            // label is one of the cpp visibility keywords; otherwise it's
            // a real labeled_statement (goto target) and should be skipped.
            let label_text = child
                .child(0)
                .map(|c| node_text(c, source))
                .unwrap_or("");
            if matches!(label_text, "public" | "private" | "protected") {
                collect_methods_from_body(
                    child,
                    source,
                    lang,
                    method_kinds,
                    methods,
                    private_count,
                );
            }
            continue;
        }

        // cl6-interface-v1 (GH #78): in a macro-misparsed class body
        // (`class TINYXML2_LIB StrPair { ... }` → `compound_statement`),
        // tree-sitter-cpp cannot reconcile a bodiless destructor / operator
        // declaration with the function-body context and emits the member's
        // `function_declarator` orphaned inside a bare `ERROR` node — e.g.
        // `~StrPair();` becomes `ERROR > function_declarator > destructor_name`
        // followed by a stray `expression_statement > ;`. The standard
        // `method_kinds` match below never sees these, so the destructor /
        // operator silently vanished. Recover them AST-driven: when a cpp
        // `ERROR` (or recurse-worthy wrapper) directly carries a
        // `function_declarator`, extract the member name from that declarator
        // (its `destructor_name` / `operator_name` / `field_identifier` leaf).
        if matches!(lang, Language::C | Language::Cpp) && kind == "ERROR" {
            let mut ec = child.walk();
            for ec_child in child.children(&mut ec) {
                if ec_child.kind() == "function_declarator" {
                    if let Some(decl) = ec_child.child_by_field_name("declarator") {
                        if let Some(method_name) = extract_c_declarator_name(decl, source) {
                            if !method_name.is_empty()
                                && is_method_public(&method_name, ec_child, source, lang)
                            {
                                let signature =
                                    extract_function_signature(ec_child, source, lang);
                                let is_async = detect_async(ec_child, source, lang);
                                methods.push(MethodInfo {
                                    name: method_name,
                                    signature,
                                    lineno: ec_child.start_position().row as u32 + 1,
                                    is_async,
                                });
                            }
                        }
                    }
                }
            }
            continue;
        }

        if method_kinds.contains(&kind) {
            // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): `declaration` /
            // `field_declaration` nodes match both member functions AND
            // non-method members (fields, typedefs). Filter so only
            // function declarations become methods.
            if matches!(lang, Language::C | Language::Cpp)
                && matches!(kind, "declaration" | "field_declaration")
                && !is_cpp_member_function_declaration(child)
            {
                continue;
            }
            let method_name = get_node_name(child, source, lang).unwrap_or_default();
            if method_name.is_empty() {
                continue;
            }
            if is_method_public(&method_name, child, source, lang) {
                methods.push(extract_method_info(child, source, lang));
            } else {
                *private_count += 1;
            }
        } else if decorator_kinds.contains(&kind) {
            // Handle decorated methods (Python, Java annotations, etc.)
            if let Some(def) = find_definition_in_decorated(child, method_kinds) {
                let method_name = get_node_name(def, source, lang).unwrap_or_default();
                if is_method_public(&method_name, def, source, lang) {
                    methods.push(extract_method_info(def, source, lang));
                } else {
                    *private_count += 1;
                }
            }
        }
    }
}

/// Check if a method is public based on language conventions.
fn is_method_public(name: &str, node: Node, source: &[u8], lang: Language) -> bool {
    match lang {
        Language::Python | Language::Ruby | Language::Lua | Language::Luau => {
            is_public_for_lang(name, lang)
        }
        Language::Rust => is_rust_pub(node, source),
        Language::Go => name.chars().next().is_some_and(|c| c.is_uppercase()),
        Language::Java | Language::CSharp => has_public_modifier(node, source),
        // interface-per-lang-v1 (v0.4.2 M-022): exclude scala `private`
        // / `protected` methods from the public method list.
        Language::Scala => !is_scala_non_public(node, source),
        // v0.5.0 SOL-015a (M7): exclude Solidity contract methods marked
        // `internal` or `private`. Methods without a visibility keyword
        // surface (legacy pre-0.5 Solidity defaulted to `public`).
        // `fallback_function_definition` / `receive_function_definition`
        // / `constructor_definition` are always externally observable
        // (constructor is one-time but is part of the contract's typed
        // ABI for deployment, which differs from the runtime-surface
        // semantics in `surface/solidity.rs`).
        Language::Solidity => !solidity_method_is_internal_or_private(node, source),
        _ => true,
    }
}

/// v0.5.0 SOL-015a (M7): inspect a Solidity function/modifier definition's
/// `visibility` child. Returns true if the function is declared
/// `internal` or `private`. Functions with no `visibility` child OR with
/// `public`/`external` return false (i.e. they remain in the public
/// method list).
fn solidity_method_is_internal_or_private(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility" {
            let t = node_text(child, source).trim();
            return matches!(t, "internal" | "private");
        }
    }
    false
}

/// Extract base classes / superclasses / implemented interfaces.
fn extract_base_classes(class_node: Node, source: &[u8], lang: Language) -> Vec<String> {
    let mut bases = Vec::new();

    match lang {
        Language::Python => {
            if let Some(superclasses) = class_node.child_by_field_name("superclasses") {
                let mut cursor = superclasses.walk();
                for child in superclasses.children(&mut cursor) {
                    if child.kind() == "identifier" || child.kind() == "attribute" {
                        bases.push(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Java => {
            // Java exposes the parent via the `superclass` field and the
            // implemented interfaces via the `interfaces` field.
            if let Some(super_node) = class_node.child_by_field_name("superclass") {
                bases.push(node_text(super_node, source).to_string());
            }
            if let Some(interfaces) = class_node.child_by_field_name("interfaces") {
                let mut cursor = interfaces.walk();
                for child in interfaces.children(&mut cursor) {
                    if child.kind() == "type_identifier" || child.kind() == "generic_type" {
                        bases.push(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::CSharp => {
            // tree-sitter-c-sharp does NOT use Java's `superclass`/`interfaces`
            // fields — it groups the base type + interfaces under a `base_list`
            // node. Using the Java field names left C# bases ALWAYS empty (#38:
            // newtonsoft-bson 0/61 classes had bases though `inheritance` found
            // 28 edges). Delegate to the shared extractor used by the
            // `inheritance` command so both agree.
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_csharp_bases(
                    &class_node,
                    src,
                ));
            }
        }
        // #153: PHP previously had NO arm here (fell through to `_ => {}`), so
        // `extends`/`implements` were never captured (guzzle ServerException
        // reported bases=[] though it extends BadResponseException). Delegate to
        // the shared PHP base extractor (reads base_clause + class_interface_clause).
        Language::Php => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_php_bases(&class_node, src));
            }
        }
        // Kotlin/Swift also lacked arms (no bases at all). Delegate to the
        // shared extractors (delegation_specifiers / inheritance clause).
        Language::Kotlin => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_kotlin_bases(
                    &class_node,
                    src,
                ));
            }
        }
        Language::Swift => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_swift_bases(
                    &class_node,
                    src,
                ));
            }
        }
        Language::Rust => {
            // For trait_item, look for trait bounds
            // For impl_item, look for the trait being implemented
            if class_node.kind() == "impl_item" {
                if let Some(trait_node) = class_node.child_by_field_name("trait") {
                    bases.push(node_text(trait_node, source).to_string());
                }
            }
        }
        Language::TypeScript | Language::JavaScript => {
            // Check for extends_clause or implements_clause
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_heritage" {
                    let mut inner_cursor = child.walk();
                    for clause in child.children(&mut inner_cursor) {
                        if clause.kind() == "extends_clause" || clause.kind() == "implements_clause"
                        {
                            let mut type_cursor = clause.walk();
                            for type_child in clause.children(&mut type_cursor) {
                                if type_child.kind() == "identifier"
                                    || type_child.kind() == "type_identifier"
                                {
                                    bases.push(node_text(type_child, source).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Language::Ruby => {
            if let Some(super_node) = class_node.child_by_field_name("superclass") {
                bases.push(node_text(super_node, source).to_string());
            }
        }
        Language::Go => {
            // Go type_declaration doesn't have base classes per se
            // But embedded structs could be found in struct fields
        }
        Language::Scala => {
            if let Some(extends) = class_node.child_by_field_name("extends") {
                bases.push(node_text(extends, source).to_string());
            }
        }
        // v0.5.0 SOL-015a (M7): Solidity inheritance is flattened from
        // `inheritance_specifier` children. Each specifier has an
        // `ancestor` field of kind `user_defined_type` (which itself
        // wraps an `identifier` or `member_expression`). Mirrors the
        // extractor's `extract_solidity_class_bases` semantics
        // (see crates/tldr-core/src/ast/extract.rs) so that
        // `tldr interface` and the schema extractor agree on `bases`.
        Language::Solidity => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    if let Some(ancestor) = child.child_by_field_name("ancestor") {
                        if let Some(name) = solidity_user_defined_type_leaf(ancestor, source) {
                            bases.push(name);
                        }
                    } else {
                        // Fallback: scan for a `user_defined_type` child directly.
                        let mut ic = child.walk();
                        for ichild in child.children(&mut ic) {
                            if ichild.kind() == "user_defined_type" {
                                if let Some(name) = solidity_user_defined_type_leaf(ichild, source)
                                {
                                    bases.push(name);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    bases
}

/// v0.5.0 SOL-015a (M7): extract the leaf identifier of a
/// `user_defined_type` node. The grammar wraps the name in either an
/// `identifier` (bare `Ownable`) or a `member_expression` (namespaced
/// `OpenZeppelin.Ownable`). Mirrors `solidity_user_defined_type_name`
/// in `crates/tldr-core/src/ast/extract.rs`.
fn solidity_user_defined_type_leaf<'a>(node: Node<'a>, source: &'a [u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => return Some(node_text(child, source).to_string()),
            "member_expression" => return Some(node_text(child, source).to_string()),
            _ => {}
        }
    }
    Some(node_text(node, source).to_string())
}

/// Find a function/class definition inside a decorated_definition node.
fn find_definition_in_decorated<'a>(node: Node<'a>, target_kinds: &[&str]) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .find(|&child| target_kinds.contains(&child.kind()));
    found
}

/// Extract method information from a function definition node.
fn extract_method_info(func_node: Node, source: &[u8], lang: Language) -> MethodInfo {
    let name = get_node_name(func_node, source, lang).unwrap_or_default();
    let signature = extract_function_signature(func_node, source, lang);
    let is_async = detect_async(func_node, source, lang);
    // cl4-interface-v1 (IT3-java-03, GH #78): capture the method's own
    // declaration line so the flat `functions[]` view no longer collapses
    // every method to the enclosing class line. Anchor to the decl-keyword
    // line (skipping leading `@Override` / `@ModelAttribute` annotation and
    // modifier children) via the SAME normaliser `extract` / `explain` /
    // `slice` use, so the per-method line agrees across every pipeline
    // (v0.4.2 M-002 convention).
    let lineno = tldr_core::ast::extract::decl_keyword_line_from_node(&func_node);

    MethodInfo {
        name,
        signature,
        lineno,
        is_async,
    }
}

// =============================================================================
// Interface Extraction (Language-Aware)
// =============================================================================

/// Extract the public interface from a source file.
///
/// Detects the language from the file extension and uses the appropriate
/// tree-sitter grammar and node kinds. Uses sibling-aware detection so a
/// `.h` header next to `.cpp` translation units is parsed with the C++
/// grammar — without this, `tldr interface tinyxml2.h` parses as C and
/// returns zero classes (real-repo-fixes-v1 P9.BUG-R2).
pub fn extract_interface(path: &Path, source: &str) -> PatternsResult<InterfaceInfo> {
    let lang = Language::from_path_with_siblings(path).unwrap_or(Language::Python);
    extract_interface_with_lang(path, source, lang)
}

/// interface-per-lang-v1 (v0.4.2 M-022): parse a `.mli` file using
/// tree-sitter-ocaml's dedicated `LANGUAGE_OCAML_INTERFACE` grammar and
/// emit `val name : type` declarations as public functions. The
/// implementation grammar (`LANGUAGE_OCAML`) cannot represent these
/// declarations, so without this routing every `.mli` reported
/// `functions:[]`.
fn extract_ocaml_mli_interface(path: &Path, source: &str) -> PatternsResult<InterfaceInfo> {
    use tree_sitter::Parser;

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ocaml::LANGUAGE_OCAML_INTERFACE.into())
        .map_err(|e| {
            PatternsError::parse_error(
                path,
                format!("Failed to load OCaml interface grammar: {}", e),
            )
        })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        PatternsError::parse_error(path, "OCaml interface parser returned no tree".to_string())
    })?;
    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut classes: Vec<ClassInfo> = Vec::new();

    walk_ocaml_mli(root, source_bytes, &mut functions, &mut classes);

    let mut names: Vec<String> = functions
        .iter()
        .map(|f| f.name.clone())
        .chain(classes.iter().map(|c| c.name.clone()))
        .collect();
    names.sort();
    names.dedup();

    Ok(InterfaceInfo {
        file: path.display().to_string(),
        all_exports: names,
        functions,
        classes,
    })
}

/// Walk an OCaml `.mli` AST collecting `value_specification` (val decl)
/// and `type_definition` / `module_type_definition` nodes.
fn walk_ocaml_mli(
    node: Node,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        match kind {
            "value_specification" => {
                // children: `val` `value_name` `:` <type_expr>
                let mut name: Option<String> = None;
                let mut type_text: Option<String> = None;
                let mut name_cursor = child.walk();
                for sub in child.children(&mut name_cursor) {
                    match sub.kind() {
                        "value_name" => {
                            name = Some(node_text(sub, source).trim().to_string());
                        }
                        "val" | ":" => {}
                        _ => {
                            if name.is_some() && type_text.is_none() {
                                type_text =
                                    Some(node_text(sub, source).trim().to_string());
                            }
                        }
                    }
                }
                if let Some(n) = name {
                    let lineno = child.start_position().row as u32 + 1;
                    let signature = type_text
                        .map(|t| format!(": {}", t))
                        .unwrap_or_default();
                    functions.push(FunctionInfo {
                        name: n,
                        signature,
                        docstring: None,
                        lineno,
                        is_async: false,
                    });
                }
            }
            "type_definition" => {
                // Surface as a class entry for parity with the .ml path.
                let lineno = child.start_position().row as u32 + 1;
                let mut tcursor = child.walk();
                for sub in child.children(&mut tcursor) {
                    if sub.kind() == "type_binding" {
                        let mut bcursor = sub.walk();
                        for b in sub.children(&mut bcursor) {
                            if matches!(b.kind(), "type_constructor" | "type_constructor_path") {
                                let name = node_text(b, source).trim().to_string();
                                if !name.is_empty() {
                                    classes.push(ClassInfo {
                                        name,
                                        lineno,
                                        bases: Vec::new(),
                                        methods: Vec::new(),
                                        private_method_count: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Recurse into nested module-types / signature bodies.
                walk_ocaml_mli(child, source, functions, classes);
            }
        }
    }
}

/// Extract the public interface from a source file with an explicit language.
pub fn extract_interface_with_lang(
    path: &Path,
    source: &str,
    lang: Language,
) -> PatternsResult<InterfaceInfo> {
    let source_bytes = source.as_bytes();

    // interface-per-lang-v1 (v0.4.2 M-022): `.mli` interface files use a
    // dedicated tree-sitter-ocaml grammar (`LANGUAGE_OCAML_INTERFACE`).
    // The standard OCaml grammar mis-parses `val name : type` because
    // that form is only legal in `.mli`. Route `.mli` to the dedicated
    // grammar before falling back to ParserPool.
    let is_ocaml_interface = lang == Language::Ocaml
        && path
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| e.eq_ignore_ascii_case("mli"))
            .unwrap_or(false);
    if is_ocaml_interface {
        return extract_ocaml_mli_interface(path, source);
    }

    // Parse with ParserPool (multi-language)
    let pool = ParserPool::new();
    let tree = pool
        .parse(source, lang)
        .map_err(|e| PatternsError::parse_error(path, format!("Failed to parse: {}", e)))?;

    let root = tree.root_node();

    // Extract __all__ exports (Python-specific)
    let explicit_all_exports = if lang == Language::Python {
        extract_all_exports(root, source_bytes)
    } else {
        None
    };

    // Determine node kinds for this language
    let func_kinds = function_node_kinds(lang);
    let class_kinds = class_node_kinds(lang);
    let decorator_kinds = decorator_node_kinds(lang);

    // Extract public functions and classes
    let (functions, classes) = collect_top_level_definitions(
        root,
        source_bytes,
        lang,
        func_kinds,
        class_kinds,
        decorator_kinds,
    );

    // schema-cleanup-v1 BUG-22: populate `all_exports` as a non-null
    // array. Prefer the explicit `__all__` (Python only); otherwise
    // fall back to the union of public function and class names —
    // mirroring "import *" semantics. Empty modules → `[]`.
    let all_exports = if let Some(explicit) = explicit_all_exports {
        explicit
    } else {
        let mut names: Vec<String> = functions
            .iter()
            .map(|f| f.name.clone())
            .chain(classes.iter().map(|c| c.name.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    };

    Ok(InterfaceInfo {
        file: path.display().to_string(),
        all_exports,
        functions,
        classes,
    })
}

/// Container node kinds whose children should be treated as top-level for
/// the purpose of public-interface extraction.
///
/// Real-world repos commonly wrap top-level classes/functions in:
/// * C++: `namespace foo { ... }`, `extern "C" { ... }`, `#if/#elif` preproc
/// * C#: `namespace Foo { ... }` and `namespace Foo;` (file-scoped)
/// * C/C++: preproc conditional branches gating typedefs and inline functions
///
/// Without recursion, `tldr interface` reported zero classes for cpp/csharp
/// even though `tldr extract` listed them — real-repo-fixes-v1 (P9.BUG-R2/R5).
fn is_interface_container(kind: &str) -> bool {
    matches!(
        kind,
        "namespace_definition"
            | "namespace_declaration"
            | "file_scoped_namespace_declaration"
            | "linkage_specification"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_elifdef"
            | "declaration_list"
            // tree-sitter-cpp commonly produces ERROR / function_definition
            // wrappers in real-world headers (e.g. tinyxml2.h) when macro
            // names like `TINYXML2_LIB` confuse the parser. Recurse into
            // these so embedded class_specifier nodes still surface.
            | "ERROR"
            | "compound_statement"
            // C# wraps the whole file content under various namespace forms
            // and global_statement/file_scoped_namespace bodies.
            | "global_statement"
    )
}

/// Languages where misparses are common enough that we should walk the full
/// AST looking for class/function nodes, not just direct children of root.
///
/// For these languages `tldr extract` already does a deep walk; matching that
/// behaviour for `tldr interface` keeps the two commands consistent.
/// real-repo-fixes-v1 (P9.BUG-R2/R5/R6/R7).
fn needs_deep_walk(lang: Language) -> bool {
    matches!(
        lang,
        Language::Cpp
            | Language::C
            | Language::CSharp
            | Language::Kotlin
            | Language::Swift
    )
}

/// interface-per-lang-v1 (v0.4.2 M-022): scan a JS/TS file for top-level
/// member-export forms that pre-class JavaScript modules used to declare
/// public API:
///
/// * `Foo.prototype.bar = function (...) { ... }`     -> method `bar` on `Foo`
/// * `Foo.prototype.bar = (...) => { ... }`           -> method `bar` on `Foo`
/// * `exports.X = function (...) { ... }`             -> top-level function `X`
/// * `module.exports.X = function (...) { ... }`      -> top-level function `X`
///
/// The walker scans direct children of the file root for
/// `expression_statement > assignment_expression`. Without this, Express
/// `app.render`, `app.handle`, etc. were invisible to `tldr interface`.
fn collect_js_member_exports(
    root: Node,
    source: &[u8],
    lang: Language,
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
) {
    use std::collections::HashSet;
    let mut existing_funcs: HashSet<(String, u32)> = HashSet::new();
    for f in functions.iter() {
        existing_funcs.insert((f.name.clone(), f.lineno));
    }

    // First pass: collect identifiers that alias `module.exports` /
    // `exports`. Express's `lib/application.js` does
    // `var app = exports = module.exports = {};` — every subsequent
    // `app.X = function …` is part of the public API but would
    // otherwise be invisible because `app` is just an identifier.
    let module_export_aliases = collect_js_module_export_aliases(root, source);

    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        // `expression_statement` wraps a single assignment_expression in JS.
        if child.kind() != "expression_statement" {
            continue;
        }
        let assign = match child.child(0) {
            Some(c) if c.kind() == "assignment_expression" => c,
            _ => continue,
        };
        let lhs = match assign.child_by_field_name("left") {
            Some(n) => n,
            None => continue,
        };
        let rhs = match assign.child_by_field_name("right") {
            Some(n) => n,
            None => continue,
        };
        if !is_js_function_value(rhs) {
            continue;
        }
        // Inspect the LHS member expression. We accept either:
        //   - <ident>.prototype.<name>         -> attach to class <ident>
        //   - exports.<name>                   -> top-level function
        //   - module.exports.<name>            -> top-level function
        //   - module.exports = <function>      -> ignored (default export)
        let resolved = resolve_js_export_lhs(lhs, source, &module_export_aliases);
        let lineno = assign.start_position().row as u32 + 1;
        let signature = extract_js_member_signature(rhs, source);
        let is_async = is_js_function_async(rhs, source);
        match resolved {
            Some(JsExportTarget::Prototype { class_name, member }) => {
                if !is_public_name(&member) {
                    continue;
                }
                let class_entry = classes
                    .iter_mut()
                    .find(|c| c.name == class_name);
                let method = MethodInfo {
                    name: member.clone(),
                    signature: signature.clone(),
                    lineno,
                    is_async,
                };
                if let Some(entry) = class_entry {
                    // Avoid duplicating an existing method record.
                    let already = entry
                        .methods
                        .iter()
                        .any(|m| m.name == method.name);
                    if !already {
                        entry.methods.push(method);
                    }
                } else {
                    // No class entry exists yet — synthesize one so the
                    // method is reachable. The lineno of the class entry
                    // points at the first prototype assignment.
                    classes.push(ClassInfo {
                        name: class_name.clone(),
                        lineno,
                        bases: Vec::new(),
                        methods: vec![method],
                        private_method_count: 0,
                    });
                }
            }
            Some(JsExportTarget::ModuleExport { name }) => {
                if !is_public_name(&name) {
                    continue;
                }
                let key = (name.clone(), lineno);
                if existing_funcs.contains(&key) {
                    continue;
                }
                existing_funcs.insert(key);
                functions.push(FunctionInfo {
                    name,
                    signature,
                    docstring: None,
                    lineno,
                    is_async,
                });
            }
            None => {}
        }
    }
    let _ = lang;
}

/// Resolved target of a JS member-export assignment LHS.
enum JsExportTarget {
    /// `Class.prototype.method = ...`
    Prototype { class_name: String, member: String },
    /// `exports.X = ...` or `module.exports.X = ...`
    ModuleExport { name: String },
}

/// Parse `Foo.prototype.bar`, `exports.bar`, `module.exports.bar`, or
/// `<alias>.bar` (where `<alias>` is a known `module.exports` alias)
/// from the LHS of an assignment. Returns `None` for any other shape.
fn resolve_js_export_lhs(
    lhs: Node,
    source: &[u8],
    module_export_aliases: &std::collections::HashSet<String>,
) -> Option<JsExportTarget> {
    if lhs.kind() != "member_expression" {
        return None;
    }
    // The terminal property name is the `property` child.
    let prop = lhs.child_by_field_name("property")?;
    let prop_name = node_text(prop, source).to_string();
    let object = lhs.child_by_field_name("object")?;

    // Case 1: <ident>.prototype.<name>
    if object.kind() == "member_expression" {
        if let (Some(inner_obj), Some(inner_prop)) = (
            object.child_by_field_name("object"),
            object.child_by_field_name("property"),
        ) {
            let inner_prop_text = node_text(inner_prop, source);
            if inner_prop_text == "prototype" && inner_obj.kind() == "identifier" {
                return Some(JsExportTarget::Prototype {
                    class_name: node_text(inner_obj, source).to_string(),
                    member: prop_name,
                });
            }
            // module.exports.<name>
            if inner_obj.kind() == "identifier"
                && node_text(inner_obj, source) == "module"
                && inner_prop_text == "exports"
            {
                return Some(JsExportTarget::ModuleExport { name: prop_name });
            }
        }
    }
    // Case 2: exports.<name>
    if object.kind() == "identifier" && node_text(object, source) == "exports" {
        return Some(JsExportTarget::ModuleExport { name: prop_name });
    }
    // Case 3: <alias>.<name>, where <alias> was bound to
    // `module.exports` (e.g. `var app = exports = module.exports = {};`
    // in express's application.js).
    if object.kind() == "identifier" {
        let ident = node_text(object, source);
        if module_export_aliases.contains(ident) {
            return Some(JsExportTarget::ModuleExport { name: prop_name });
        }
    }
    None
}

/// interface-per-lang-v1 (v0.4.2 M-022): scan the program root for
/// `var X = exports = module.exports = ...` (or `let`/`const`) and
/// return the set of identifier names bound to `module.exports`.
fn collect_js_module_export_aliases(
    root: Node,
    source: &[u8],
) -> std::collections::HashSet<String> {
    let mut aliases = std::collections::HashSet::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        let kind = child.kind();
        if !matches!(kind, "lexical_declaration" | "variable_declaration") {
            continue;
        }
        let mut ic = child.walk();
        for decl in child.children(&mut ic) {
            if decl.kind() != "variable_declarator" {
                continue;
            }
            let name_node = match decl.child_by_field_name("name") {
                Some(n) => n,
                None => continue,
            };
            let value = match decl.child_by_field_name("value") {
                Some(v) => v,
                None => continue,
            };
            if name_node.kind() != "identifier" {
                continue;
            }
            // The value can be `exports = module.exports = {}` (a
            // chained assignment_expression), or directly
            // `module.exports`. Walk the chain looking for either form.
            if js_value_is_module_exports_chain(value, source) {
                aliases.insert(node_text(name_node, source).to_string());
            }
        }
    }
    aliases
}

/// Returns true when the expression is `module.exports`, `exports`, or
/// an assignment chain that includes either (the typical idiom
/// `exports = module.exports = {}`).
fn js_value_is_module_exports_chain(node: Node, source: &[u8]) -> bool {
    match node.kind() {
        "member_expression" => {
            // module.exports
            let obj = node.child_by_field_name("object");
            let prop = node.child_by_field_name("property");
            if let (Some(o), Some(p)) = (obj, prop) {
                if o.kind() == "identifier"
                    && node_text(o, source) == "module"
                    && node_text(p, source) == "exports"
                {
                    return true;
                }
            }
            false
        }
        "identifier" => node_text(node, source) == "exports",
        "assignment_expression" => {
            // Walk both sides of the chain.
            let l = node.child_by_field_name("left");
            let r = node.child_by_field_name("right");
            if let Some(l) = l {
                if js_value_is_module_exports_chain(l, source) {
                    return true;
                }
            }
            if let Some(r) = r {
                if js_value_is_module_exports_chain(r, source) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_js_function_value(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "arrow_function" | "function" | "generator_function"
    )
}

fn is_js_function_async(node: Node, source: &[u8]) -> bool {
    let text = node_text(node, source);
    text.starts_with("async ") || text.starts_with("async(")
}

fn extract_js_member_signature(rhs: Node, source: &[u8]) -> String {
    // Both function_expression and arrow_function carry a `parameters`
    // field (formal_parameters). Fall back to scanning children for
    // formal_parameters / parenthesized parameter list.
    if let Some(params) = rhs.child_by_field_name("parameters") {
        return node_text(params, source).to_string();
    }
    let mut cursor = rhs.walk();
    for child in rhs.children(&mut cursor) {
        if child.kind() == "formal_parameters" {
            return node_text(child, source).to_string();
        }
    }
    String::new()
}

/// Collect top-level function and class definitions from the AST root.
///
/// Recurses one level into language-appropriate container nodes (PHP
/// declaration list; C++/C# namespaces; cpp preprocessor branches) so that
/// public types defined inside `namespace { ... }` or `#if ... #endif`
/// blocks are surfaced — without this, real cpp/csharp codebases report zero
/// classes (P9.BUG-R2/R5).
fn collect_top_level_definitions(
    root: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    decorator_kinds: &[&str],
) -> (Vec<FunctionInfo>, Vec<ClassInfo>) {
    let mut functions = Vec::new();
    let mut classes = Vec::new();
    if needs_deep_walk(lang) {
        // Walk the whole AST, collecting top-level (non-method) functions
        // and class-like nodes wherever they appear. Mirrors `tldr extract`'s
        // behaviour for languages where misparses or namespace wrapping are
        // common in real-world code.
        deep_collect(
            root,
            source,
            lang,
            func_kinds,
            class_kinds,
            &mut functions,
            &mut classes,
            0,
        );
    } else {
        visit_top_level(
            root,
            source,
            lang,
            func_kinds,
            class_kinds,
            decorator_kinds,
            &mut functions,
            &mut classes,
            0,
        );
    }

    // language-specific-bugs-v1 (P14.AGG14-10): post-process Rust class
    // entries to merge `impl Foo { ... }` blocks into the corresponding
    // `struct Foo` / `enum Foo` / `trait Foo` entry. Without this, the
    // output contained both a `struct GlobSet` (methods=[]) AND an
    // `impl GlobSet` (whose methods were the actual API surface) — and
    // the user saw `methods: 0` on the struct.
    if matches!(lang, Language::Rust) {
        merge_rust_impl_entries(&mut classes);
    }

    // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
    // collapse duplicate cpp class entries that arise when a forward
    // declaration (`class XMLDocument;` at file top, methods=[]) and the
    // real definition (`class TINYXML2_LIB XMLDocument { ... };` later,
    // methods populated) both surface. Keep the entry with the richer
    // methods/bases and drop the other. Without this pass, `tldr interface
    // tinyxml2.h` would emit two XMLDocument entries.
    if matches!(lang, Language::Cpp) {
        dedupe_cpp_class_entries(&mut classes);
    }

    // language-specific-bugs-v1 (P14.AGG14-17): for Java (and the same
    // class-only languages where every public function lives inside a
    // class and the top-level `functions[]` would otherwise always be
    // empty), copy each public method into the top-level
    // `functions[]` array as a flat entry. Method entries stay inside
    // the class entry so consumers that index by class still work; the
    // flat `functions[]` array now matches the convention python /
    // typescript already follow (every callable a downstream consumer
    // could call is reachable without dereferencing a `classes[]`
    // entry first).
    if matches!(lang, Language::Java | Language::Kotlin) {
        flatten_class_methods_to_functions(&classes, &mut functions);
    }

    // interface-per-lang-v1 (v0.4.2 M-022): javascript prototype
    // assignments (`Foo.prototype.bar = function () {}`) and
    // module-export forms (`exports.create = function () {}`,
    // `module.exports.foo = function () {}`) are how pre-ES6 modules
    // (Express, much of node's core) declare their public API. Without
    // this pass they were invisible to `tldr interface`.
    if matches!(lang, Language::JavaScript | Language::TypeScript) {
        collect_js_member_exports(root, source, lang, &mut functions, &mut classes);
    }

    (functions, classes)
}

/// language-specific-bugs-v1 (P14.AGG14-17): flatten every public method
/// from `classes` into `functions` as a top-level entry, deduplicated by
/// `(name, lineno)`. Used for class-only languages (Java, Kotlin) so that
/// `tldr interface SomeController.java | jq '.functions | length'` is
/// non-zero whenever the file declares a class with public methods —
/// matching the contract Python / TypeScript already satisfy at the
/// schema level (every public callable is enumerable from `functions[]`
/// without dereferencing `classes[]`).
fn flatten_class_methods_to_functions(
    classes: &[ClassInfo],
    functions: &mut Vec<FunctionInfo>,
) {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    for f in functions.iter() {
        seen.insert((f.name.clone(), f.lineno));
    }
    for class in classes {
        for method in &class.methods {
            // cl4-interface-v1 (IT3-java-03, GH #78): `MethodInfo` now
            // carries its own declaration line, so the flat `functions[]`
            // view reports the real per-method line (matching `structure` /
            // `extract`) instead of collapsing every method to the enclosing
            // class line. Dedup on `(name, method_line)` — two overloads now
            // remain distinct because their lines differ.
            let key = (method.name.clone(), method.lineno);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            functions.push(FunctionInfo {
                name: method.name.clone(),
                signature: method.signature.clone(),
                docstring: None,
                lineno: method.lineno,
                is_async: method.is_async,
            });
        }
    }
}

/// language-specific-bugs-v1 (P14.AGG14-10): coalesce duplicate Rust class
/// entries. After the walker has gathered `struct`/`enum`/`trait` entries
/// AND every `impl <Type>` block as separate `ClassInfo`s (because both
/// node kinds are listed in `class_node_kinds(Language::Rust)`), this pass
/// finds each impl whose `name` matches an existing struct/enum/trait
/// entry and folds the impl's methods into the matching entry. impl
/// blocks with no struct/enum/trait counterpart in the same file (e.g.
/// `impl SomeTrait for ExternalType { ... }` where `ExternalType` lives
/// elsewhere) are dropped entirely — we cannot attach them to anything in
/// this file's interface and surfacing them with the trait/type name as a
/// "class" was misleading.
fn merge_rust_impl_entries(classes: &mut Vec<ClassInfo>) {
    use std::collections::HashSet;

    // Step 1: index the lineno of every non-impl class entry so we keep
    // their stable ordering when re-inserting methods.
    let mut struct_like_indices: HashSet<String> = HashSet::new();
    for c in classes.iter() {
        // We treat any entry whose name doesn't carry generic / for-clause
        // syntax as struct-like. impl entries carry the impl'd type name
        // verbatim (which may include generics like `Foo<T>`), so we
        // strip generics on lookup keys.
        let key = strip_generics(&c.name);
        struct_like_indices.insert(key);
    }
    let _ = struct_like_indices; // (only used implicitly via the merge)

    // Step 2: separate impl entries from struct/enum/trait entries by
    // lineno - we don't have a `kind` discriminator, so we re-scan: any
    // entry whose name appears more than once is an impl-block duplicate.
    let mut name_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for c in classes.iter() {
        *name_counts.entry(strip_generics(&c.name)).or_insert(0) += 1;
    }

    // Step 3: walk classes in order. For each entry whose name is a
    // duplicate, fold its methods into the FIRST entry with the same
    // name (the canonical struct/enum/trait location). Mark folded
    // entries for removal.
    let mut canonical_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut to_remove: Vec<usize> = Vec::new();
    for (i, c) in classes.iter().enumerate() {
        let key = strip_generics(&c.name);
        canonical_index.entry(key).or_insert(i);
    }

    for i in 0..classes.len() {
        let key = strip_generics(&classes[i].name);
        let canonical = match canonical_index.get(&key) {
            Some(&idx) => idx,
            None => continue,
        };
        if i == canonical {
            continue;
        }
        // Fold methods (and bases) into canonical.
        let methods = std::mem::take(&mut classes[i].methods);
        let bases = std::mem::take(&mut classes[i].bases);
        let private_count = classes[i].private_method_count;

        let canonical_entry = &mut classes[canonical];
        for m in methods {
            let already = canonical_entry.methods.iter().any(|existing| {
                existing.name == m.name && existing.signature == m.signature
            });
            if !already {
                canonical_entry.methods.push(m);
            }
        }
        for b in bases {
            if !canonical_entry.bases.contains(&b) {
                canonical_entry.bases.push(b);
            }
        }
        canonical_entry.private_method_count =
            canonical_entry.private_method_count.saturating_add(private_count);
        to_remove.push(i);
    }

    // Remove duplicates in reverse order so indices remain valid.
    for idx in to_remove.into_iter().rev() {
        classes.remove(idx);
    }

    // Step 4: drop any remaining entries whose name count was originally
    // > 1 but which are now empty placeholders (this happens for
    // `impl Trait for ExternalType` where ExternalType has no
    // struct/enum/trait declaration in the same file — the impl entry
    // was folded into the canonical, leaving the canonical entry as a
    // duplicate-of-self; nothing to drop in that case). Reserved for
    // future expansion.
    let _ = name_counts;
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
/// collapse cpp class entries that share a name. Forward declarations
/// (`class Foo;`) and real definitions (`class TINYXML2_LIB Foo { ... };`)
/// both produce a `ClassInfo` for `Foo`; we keep the one with non-empty
/// methods and drop the other. If both are empty (multiple forward decls)
/// the first occurrence wins. Bases/methods are unioned into the surviving
/// entry to preserve any info from the dropped duplicate.
fn dedupe_cpp_class_entries(classes: &mut Vec<ClassInfo>) {
    use std::collections::HashMap;

    if classes.len() <= 1 {
        return;
    }

    // First pass: pick a canonical index per name — prefer the entry with
    // the most methods, tie-break by lowest line number for stability.
    let mut canonical_for: HashMap<String, usize> = HashMap::new();
    for (i, c) in classes.iter().enumerate() {
        if c.name.is_empty() {
            continue;
        }
        match canonical_for.get(&c.name).copied() {
            None => {
                canonical_for.insert(c.name.clone(), i);
            }
            Some(prev) => {
                let prev_methods = classes[prev].methods.len();
                let cur_methods = c.methods.len();
                let take_current = cur_methods > prev_methods
                    || (cur_methods == prev_methods && c.lineno < classes[prev].lineno);
                if take_current {
                    canonical_for.insert(c.name.clone(), i);
                }
            }
        }
    }

    // Second pass: union methods/bases from each non-canonical duplicate
    // into the canonical entry, then mark for removal.
    let mut to_remove: Vec<usize> = Vec::new();
    let mut transfers: Vec<(usize, usize)> = Vec::new(); // (from, to)
    for (i, c) in classes.iter().enumerate() {
        if c.name.is_empty() {
            continue;
        }
        if let Some(&canonical) = canonical_for.get(&c.name) {
            if canonical != i {
                transfers.push((i, canonical));
                to_remove.push(i);
            }
        }
    }
    for (from, to) in transfers {
        // Take methods/bases out of `from` (it's about to be removed).
        let from_methods = std::mem::take(&mut classes[from].methods);
        let from_bases = std::mem::take(&mut classes[from].bases);
        let from_private = classes[from].private_method_count;
        let target = &mut classes[to];
        for m in from_methods {
            let already = target
                .methods
                .iter()
                .any(|e| e.name == m.name && e.signature == m.signature);
            if !already {
                target.methods.push(m);
            }
        }
        for b in from_bases {
            if !target.bases.contains(&b) {
                target.bases.push(b);
            }
        }
        target.private_method_count =
            target.private_method_count.saturating_add(from_private);
    }
    // Remove in reverse so indices stay valid.
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.into_iter().rev() {
        classes.remove(idx);
    }
}

/// Strip generic / lifetime parameters from a Rust type name.
/// `Vec<T>` -> `Vec`, `Foo<'a>` -> `Foo`, `Bar` -> `Bar`.
fn strip_generics(name: &str) -> String {
    if let Some(idx) = name.find('<') {
        name[..idx].trim().to_string()
    } else {
        name.trim().to_string()
    }
}

/// Walk the entire AST of a file, collecting class-like nodes and any
/// function definitions that are NOT methods inside a class.
///
/// Used for cpp/c/csharp/kotlin/swift where:
/// * cpp headers often have macro-prefixed `class TINYXML2_LIB Foo` that
///   confuse tree-sitter into emitting ERROR / function_definition wrappers
///   around the namespace body, so plain root-children iteration misses them.
/// * csharp wraps everything under one or more `namespace_declaration` /
///   `file_scoped_namespace_declaration` nodes.
/// * kotlin/swift normally have classes at the file root, but extension-only
///   files (Span+Extras.swift) and nested object_declaration trees benefit
///   from a full walk.
#[allow(clippy::too_many_arguments)]
fn deep_collect(
    node: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    // review-followup-v1 (Concern 4): defense-in-depth bound matching
    // `visit_top_level`'s `MAX_CONTAINER_DEPTH = 8`. Tree-sitter limits
    // real-code nesting in practice, but a corrupt or adversarial AST
    // could still produce deep recursion; cap it here for consistency.
    const MAX_DEEP_WALK_DEPTH: usize = 8;
    if depth > MAX_DEEP_WALK_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if class_kinds.contains(&kind) {
            // C/C++ `struct_specifier` / `class_specifier` with NO `body` field
            // is a TYPE REFERENCE, not a definition: `sizeof(struct sdshdr5)`,
            // a cast `(struct list*)x`, a param `struct Bar *p`, `extern struct
            // T v`, or a forward decl `class Foo;`. Emitting these listed
            // phantom "classes" named by the referenced type (c-sds reported
            // sdshdr5/8/16/32/64 as classes from `sizeof`; c-redis reported a
            // bogus `list` from a cast). `structure`'s extract_c_structs already
            // requires a body; mirror that here so the two pipelines agree.
            //
            // EXCEPTION (cpp-interface-macro-filter-v1 regression fix): the
            // export-macro misparse `class TINYXML2_LIB Foo { ... };` ALSO has
            // no `body` field on its `class_specifier` — tree-sitter-cpp hangs
            // the real `compound_statement` body off the wrapping
            // `function_definition` instead (verified by AST dump:
            // function_definition -> [class_specifier(name=MACRO, no body),
            // identifier(Foo), compound_statement{...}]). That node IS a real
            // class definition, so it must NOT be filtered as a type-ref.
            // `extract_cpp_macro_misparsed_class_body` returns `Some` exactly
            // for this shape (and `None` for genuine bodyless type-refs /
            // forward-decls), so it cleanly distinguishes the two. The same
            // helper feeds `get_node_name` (real name) and `find_body_node`
            // (real methods), so once admitted the entry resolves correctly.
            let is_cpp_macro_misparsed_class = matches!(lang, Language::Cpp)
                && kind == "class_specifier"
                && extract_cpp_macro_misparsed_class_body(child).is_some();
            let is_bodyless_c_type_ref = matches!(lang, Language::C | Language::Cpp)
                && matches!(kind, "struct_specifier" | "class_specifier")
                && child.child_by_field_name("body").is_none()
                && !is_cpp_macro_misparsed_class;

            // Avoid double-counting nested classes when an enclosing class
            // already collected its inner methods/types via extract_class_info.
            // Top-level rule: a class node is "top-level" iff it isn't itself
            // contained in another class-kind ancestor.
            if !is_bodyless_c_type_ref
                && !is_inside_class_ancestor(child, class_kinds)
                && is_node_public(child, source, lang)
            {
                let info = extract_class_info(child, source, lang);
                // Skip empty/anonymous misparses where extract returned no name.
                if !info.name.is_empty() {
                    classes.push(info);
                }
            }
            // Still recurse into the body — nested classes that are themselves
            // public should also surface (mirrors tree-walk behaviour of
            // `tldr extract` for cpp / csharp).
            deep_collect(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }
        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
        // suppress the synthetic `function_definition` wrapper that
        // tree-sitter-cpp emits around `class TINYXML2_LIB Foo { ... };`.
        // The inner `class_specifier` already produced the (corrected)
        // class entry above, so adding this wrapper to `functions[]` would
        // surface a phantom function (e.g. `StrPair` at line 133 with
        // signature `": class TINYXML2_LIB"`). We still recurse into the
        // wrapper because the misparsed body (`compound_statement`) may
        // itself contain nested macro-prefixed classes worth surfacing.
        if matches!(lang, Language::Cpp)
            && kind == "function_definition"
            && is_cpp_macro_misparsed_class_wrapper(child)
        {
            deep_collect(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }
        if func_kinds.contains(&kind)
            && !is_inside_class_ancestor(child, class_kinds)
            && is_node_public(child, source, lang)
        {
            // interface-per-lang-v1 (v0.4.2 M-022): C / C++ also list
            // `declaration` under `func_kinds` so function prototypes
            // (e.g. `int foo(int);` in a `.h`) surface. Non-function
            // declarations (typedefs, struct fields, externs) must be
            // filtered here so they do not contaminate `functions[]`.
            if matches!(lang, Language::C | Language::Cpp)
                && kind == "declaration"
                && !is_cpp_member_function_declaration(child)
            {
                deep_collect(
                    child,
                    source,
                    lang,
                    func_kinds,
                    class_kinds,
                    functions,
                    classes,
                    depth + 1,
                );
                continue;
            }
            functions.push(extract_function_info(child, source, lang));
        }
        deep_collect(
            child,
            source,
            lang,
            func_kinds,
            class_kinds,
            functions,
            classes,
            depth + 1,
        );
    }
}

/// cl6-interface-v1 (GH #78): true when `node` is a wrapper that holds
/// top-level-style class / function definitions but is not itself a class
/// or function. The non-deep-walk walker (`visit_top_level`) descends into
/// these so their inner public definitions surface as top-level exports.
///
/// Recognised wrappers, per the tree-sitter grammars (verified against the
/// pinned corpora):
///   * TS / JS `export_statement`
///     `export class Foo`, `export function f`, `export default class D`,
///     `@Dec() export class Foo` — the definition is a child of the
///     `export_statement`, never of the program root.
///   * Scala `package_clause` BLOCK form
///     `package p { class C; object O }` — the nested definitions live in
///     a `template_body` sibling of the `package_identifier`. The
///     file-level form `package p` (no block) has no `template_body` and
///     is intentionally NOT treated as a wrapper: its definitions are
///     already direct children of the compilation unit.
fn is_interface_wrapper(node: Node, lang: Language) -> bool {
    match lang {
        Language::TypeScript | Language::JavaScript => node.kind() == "export_statement",
        Language::Scala => {
            // Only the block form (carrying a `template_body`) wraps nested
            // definitions; the bare `package p` clause does not.
            if node.kind() == "package_clause" {
                let mut cursor = node.walk();
                return node
                    .children(&mut cursor)
                    .any(|c| c.kind() == "template_body");
            }
            // The package block's definitions live one level deeper, inside
            // the `package_clause`'s `template_body`. Recurse into that body
            // (but ONLY when it belongs to a `package_clause` — a
            // `template_body` owned by a `class`/`object`/`trait` is that
            // type's own member block and is handled by `extract_class_info`
            // / `collect_nested_classes`, not as a top-level container).
            node.kind() == "template_body"
                && node
                    .parent()
                    .map(|p| p.kind() == "package_clause")
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// cl6-interface-v1 (GH #78): collect public *nested* class-like definitions
/// declared inside a class/object body, recursing so arbitrarily deep
/// nesting surfaces. Only class-kind nodes are emitted — methods inside the
/// body belong to the enclosing class's `methods[]` and must not leak into
/// the top-level `functions[]` array.
fn collect_nested_classes(
    body: Node,
    source: &[u8],
    lang: Language,
    class_kinds: &[&str],
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    const MAX_NESTED_DEPTH: usize = 8;
    if depth > MAX_NESTED_DEPTH {
        return;
    }
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if class_kinds.contains(&child.kind()) {
            if is_node_public(child, source, lang) {
                let info = extract_class_info(child, source, lang);
                if !info.name.is_empty() {
                    classes.push(info);
                }
            }
            // Recurse into this nested class's body for deeper nesting.
            if let Some(inner_body) = find_body_node(child, lang) {
                collect_nested_classes(
                    inner_body,
                    source,
                    lang,
                    class_kinds,
                    classes,
                    depth + 1,
                );
            }
        } else {
            // Descend through non-class structural nodes (e.g. Ruby
            // `body_statement`, decorator wrappers) to reach nested
            // class declarations that aren't direct children of `body`.
            // Stop short of re-entering a class body we've already
            // handled above (guarded by the class-kind branch).
            collect_nested_classes(child, source, lang, class_kinds, classes, depth + 1);
        }
    }
}

/// Check whether a node is contained within a class/struct/interface ancestor.
/// Used to distinguish top-level functions from methods.
fn is_inside_class_ancestor(node: Node, class_kinds: &[&str]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if class_kinds.contains(&parent.kind()) {
            return true;
        }
        current = parent.parent();
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn visit_top_level(
    node: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    decorator_kinds: &[&str],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    // Bound recursion conservatively — we only ever need to descend through
    // a handful of namespace/preproc levels in real-world code.
    const MAX_CONTAINER_DEPTH: usize = 8;
    if depth > MAX_CONTAINER_DEPTH {
        return;
    }

    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let kind = child.kind();

        // Elixir-specific dispatch: `call` nodes match BOTH func_kinds and
        // class_kinds, so the original logic always took the function
        // branch and `defmodule` calls were dropped. BUG-AGG-9 (P11):
        // restructure so we route on the call target name.
        //
        // - `def` / `defmacro` -> public function
        // - `defp` / `defmacrop` -> private, skip
        // - `defmodule` -> recurse into its `do_block` so nested public
        //   `def`s surface as top-level exports (matches `tldr extract`'s
        //   walk; mirrors how the Plug.Conn module exposes its public
        //   API even though every function lives one level deep).
        if lang == Language::Elixir && kind == "call" {
            let target_text = child.child(0).map(|t| node_text(t, source)).unwrap_or("");
            match target_text {
                "def" | "defmacro" => {
                    functions.push(extract_function_info(child, source, lang));
                }
                "defp" | "defmacrop" => {
                    // private, skip
                }
                "defmodule" => {
                    // Recurse into the module body. Module body is a `do_block`
                    // child of the call node.
                    let mut mod_cursor = child.walk();
                    for mod_child in child.children(&mut mod_cursor) {
                        if mod_child.kind() == "do_block" {
                            visit_top_level(
                                mod_child,
                                source,
                                lang,
                                func_kinds,
                                class_kinds,
                                decorator_kinds,
                                functions,
                                classes,
                                depth + 1,
                            );
                        }
                    }
                }
                _ => {}
            }
            continue;
        }

        // cl6-interface-v1 (GH #78): descend into wrapper nodes that hold
        // class / function definitions but are not themselves classes or
        // functions. Without this, the pre-fix walker (which only iterated
        // *direct children* of the file root and recursed for PHP only)
        // silently dropped:
        //   * TS/JS `export class Foo` / `export function f` / `export
        //     default class D` — the definition is a child of an
        //     `export_statement` wrapper, not of the program root.
        //   * Scala `package p { class C }` — `package_clause` carries the
        //     nested definitions in a `template_body` sibling of the
        //     `package_identifier`.
        // These wrappers are recursed into with the SAME `visit_top_level`
        // logic so their inner definitions surface as top-level exports.
        if is_interface_wrapper(child, lang) {
            visit_top_level(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                decorator_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }

        if func_kinds.contains(&kind) {
            if is_node_public(child, source, lang) {
                functions.push(extract_function_info(child, source, lang));
            }
        } else if class_kinds.contains(&kind) {
            if is_node_public(child, source, lang) {
                classes.push(extract_class_info(child, source, lang));
            }
            // cl6-interface-v1 (GH #78): a class body may itself declare
            // public *nested* classes (Ruby `class Outer; class Inner;
            // end; end`, Scala `object O { class C }`). The pre-fix walker
            // stopped at the outer class and never recursed, so `Inner`
            // vanished. Recurse into the body collecting ONLY nested
            // class-like definitions — methods inside the body are part of
            // the enclosing class's own `methods[]` (gathered by
            // `extract_class_info`) and must NOT leak into top-level
            // `functions[]`.
            if let Some(body) = find_body_node(child, lang) {
                collect_nested_classes(
                    body,
                    source,
                    lang,
                    class_kinds,
                    classes,
                    depth + 1,
                );
            }
        } else if decorator_kinds.contains(&kind) {
            // Handle decorated definitions (Python)
            if let Some(def) = find_definition_in_decorated(child, func_kinds) {
                if is_node_public(def, source, lang) {
                    functions.push(extract_function_info(def, source, lang));
                }
            } else if let Some(class_def) = find_definition_in_decorated(child, class_kinds) {
                if is_node_public(class_def, source, lang) {
                    classes.push(extract_class_info(class_def, source, lang));
                }
            }
        } else if is_interface_container(kind) {
            // Recurse into namespace / preproc / linkage containers so that
            // classes defined inside `namespace foo { ... }` (cpp/csharp) or
            // gated by `#if ... #endif` (cpp) surface as top-level exports.
            visit_top_level(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                decorator_kinds,
                functions,
                classes,
                depth + 1,
            );
        } else if lang == Language::Php {
            // PHP wraps everything in a program > php_tag + declaration list.
            // Recurse one level for these.
            let mut inner_cursor = child.walk();
            for inner_child in child.children(&mut inner_cursor) {
                let inner_kind = inner_child.kind();
                if func_kinds.contains(&inner_kind) {
                    if is_node_public(inner_child, source, lang) {
                        functions.push(extract_function_info(inner_child, source, lang));
                    }
                } else if class_kinds.contains(&inner_kind)
                    && is_node_public(inner_child, source, lang)
                {
                    classes.push(extract_class_info(inner_child, source, lang));
                }
            }
        }
    }
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format interface info as human-readable text.
pub fn format_interface_text(info: &InterfaceInfo) -> String {
    let mut lines = Vec::new();

    // Header
    lines.push(format!("File: {}", info.file));
    lines.push(String::new());

    // Public exports (from __all__ if present, else inferred from
    // public function/class names — see InterfaceInfo::all_exports).
    if !info.all_exports.is_empty() {
        lines.push("Exports:".to_string());
        for name in &info.all_exports {
            lines.push(format!("  {}", name));
        }
        lines.push(String::new());
    }

    // Functions
    if !info.functions.is_empty() {
        lines.push("Functions:".to_string());
        for func in &info.functions {
            let async_marker = if func.is_async { "async " } else { "" };
            lines.push(format!(
                "  {}def {}{}  [line {}]",
                async_marker, func.name, func.signature, func.lineno
            ));
            if let Some(ref doc) = func.docstring {
                // Truncate long docstrings
                let doc_preview = if doc.len() > 60 {
                    format!("{}...", &doc[..57])
                } else {
                    doc.clone()
                };
                lines.push(format!("      \"{}\"", doc_preview));
            }
        }
        lines.push(String::new());
    }

    // Classes
    if !info.classes.is_empty() {
        lines.push("Classes:".to_string());
        for class in &info.classes {
            let bases_str = if class.bases.is_empty() {
                String::new()
            } else {
                format!("({})", class.bases.join(", "))
            };
            lines.push(format!(
                "  class {}{}  [line {}]",
                class.name, bases_str, class.lineno
            ));

            for method in &class.methods {
                let async_marker = if method.is_async { "async " } else { "" };
                lines.push(format!(
                    "    {}def {}{}",
                    async_marker, method.name, method.signature
                ));
            }

            if class.private_method_count > 0 {
                lines.push(format!(
                    "    ({} private methods)",
                    class.private_method_count
                ));
            }
        }
        lines.push(String::new());
    }

    // Summary
    let total_methods: u32 = info.classes.iter().map(|c| c.methods.len() as u32).sum();
    lines.push(format!(
        "Summary: {} functions, {} classes, {} public methods",
        info.functions.len(),
        info.classes.len(),
        total_methods
    ));

    lines.join("\n")
}

// =============================================================================
// Entry Point
// =============================================================================

/// Check if a file has a supported source code extension.
fn is_supported_source_file(path: &Path) -> bool {
    Language::from_path(path).is_some()
}

/// Run the interface command.
pub fn run(args: InterfaceArgs, format: OutputFormat) -> anyhow::Result<()> {
    let path = &args.path;

    if path.is_dir() {
        // Validate directory
        let canonical_dir = if let Some(ref root) = args.project_root {
            super::validation::validate_file_path_in_project(path, root)?
        } else {
            validate_directory_path(path)?
        };

        // Collect all supported source files recursively
        let mut results = Vec::new();
        let mut entries: Vec<PathBuf> = walk_project(&canonical_dir)
            .filter(|e| e.path().is_file() && is_supported_source_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        // Sort for deterministic output
        entries.sort();

        for file_path in entries {
            // W1-interface-utf8 (v0.5.0 AUDIT-FIX): the directory walk must
            // never abort the whole run on a single non-UTF-8 / binary file.
            // Previously this used the patterns-local `read_file_safe`, which
            // does a HARD `String::from_utf8` and propagated `?` out of
            // `run()` — so one stray `life.lua` / `literals.luau` byte
            // (0xA5) aborted with exit 1 and zero output even though
            // hundreds of valid files remained. Use the SAME tolerant reader
            // the resilient commands (`structure`/`loc`) use via
            // `get_code_structure` -> `parse_file` (`encoding::read_source_file`
            // -> `from_utf8_lossy`): lossy files are still analyzed (with a
            // warning), binary files are skipped, and per-file IO errors are
            // non-fatal. Warnings go to stderr — the SAME non-silent channel
            // the core recoverable-skip arm uses
            // (`extractor.rs`: `eprintln!("Warning: Skipping ...")`) — so the
            // JSON/text report on stdout stays a clean `Vec<InterfaceInfo>`
            // and warnings are never swallowed.
            let source = match tldr_core::encoding::read_source_file(&file_path) {
                Ok(tldr_core::encoding::FileReadResult::Ok(content)) => content,
                Ok(tldr_core::encoding::FileReadResult::Lossy { content, warning }) => {
                    eprintln!("Warning: {}", warning);
                    content
                }
                Ok(tldr_core::encoding::FileReadResult::Binary) => {
                    eprintln!(
                        "Warning: Skipping {} - appears to be a binary file",
                        file_path.display()
                    );
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Skipping {} - {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            };
            match extract_interface(&file_path, &source) {
                Ok(info) => results.push(info),
                Err(_) => {
                    // Skip files that fail to parse (unsupported grammars, etc.)
                    continue;
                }
            }
        }

        // Output
        match format {
            OutputFormat::Text => {
                for info in &results {
                    println!("{}", format_interface_text(info));
                    println!();
                }
            }
            OutputFormat::Compact => {
                let json = serde_json::to_string(&results)?;
                println!("{}", json);
            }
            _ => {
                let json = serde_json::to_string_pretty(&results)?;
                println!("{}", json);
            }
        }
    } else {
        // Single file
        let canonical_path = if let Some(ref root) = args.project_root {
            super::validation::validate_file_path_in_project(path, root)?
        } else {
            validate_file_path(path)?
        };

        let source = read_file_safe(&canonical_path)?;
        let mut info = extract_interface(&canonical_path, &source)?;

        // (path-and-schema-cleanup-v3 P3.BUG-N2) Echo the user-supplied
        // path in the JSON `file` field. The canonical path is used for
        // the actual read, but the emit path mirrors the input verbatim
        // so macOS does not rewrite `/tmp/...` to `/private/tmp/...`.
        info.file = path.display().to_string();

        // Output
        match format {
            OutputFormat::Text => {
                println!("{}", format_interface_text(&info));
            }
            OutputFormat::Compact => {
                let json = serde_json::to_string(&info)?;
                println!("{}", json);
            }
            _ => {
                let json = serde_json::to_string_pretty(&info)?;
                println!("{}", json);
            }
        }
    }

    Ok(())
}

// =============================================================================
// Utilities
// =============================================================================

/// Get the text content of a node.
fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // is_public_name tests (backward-compatible)
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_public_name_public() {
        assert!(is_public_name("my_function"));
        assert!(is_public_name("MyClass"));
        assert!(is_public_name("process"));
        assert!(is_public_name("x"));
    }

    #[test]
    fn test_is_public_name_private() {
        assert!(!is_public_name("_private"));
        assert!(!is_public_name("__dunder__"));
        assert!(!is_public_name("_PrivateClass"));
        assert!(!is_public_name("__init__"));
    }

    // -------------------------------------------------------------------------
    // Python: extract_all_exports tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_all_exports_present() {
        let source = r#"
__all__ = ['foo', 'bar', 'Baz']

def foo():
    pass
"#;
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();

        let exports = extract_all_exports(root, source.as_bytes());
        assert!(exports.is_some());
        let exports = exports.unwrap();
        assert_eq!(exports.len(), 3);
        assert!(exports.contains(&"foo".to_string()));
        assert!(exports.contains(&"bar".to_string()));
        assert!(exports.contains(&"Baz".to_string()));
    }

    #[test]
    fn test_extract_all_exports_absent() {
        let source = r#"
def foo():
    pass
"#;
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();

        let exports = extract_all_exports(root, source.as_bytes());
        assert!(exports.is_none());
    }

    // -------------------------------------------------------------------------
    // Python: extract_function_signature tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_function_signature_simple() {
        let source = "def foo(x, y): pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert_eq!(sig, "(x, y)");
    }

    #[test]
    fn test_extract_function_signature_typed() {
        let source = "def foo(x: int, y: str) -> bool: pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert!(sig.contains("x: int"), "sig = {:?}", sig);
        assert!(sig.contains("y: str"), "sig = {:?}", sig);
        assert!(sig.contains("-> bool"), "sig = {:?}", sig);
    }

    #[test]
    fn test_extract_function_signature_default() {
        let source = "def foo(x: int = 10): pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert!(sig.contains("x: int = 10") || sig.contains("x: int=10"));
    }

    // -------------------------------------------------------------------------
    // Python: extract_interface tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_public_functions() {
        let source = r#"
def public_func():
    """A public function."""
    pass

def _private_func():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.functions.len(), 1);
        assert_eq!(info.functions[0].name, "public_func");
    }

    #[test]
    fn test_extract_interface_public_classes() {
        let source = r#"
class PublicClass:
    def public_method(self):
        pass

    def _private_method(self):
        pass

class _PrivateClass:
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.classes.len(), 1);
        assert_eq!(info.classes[0].name, "PublicClass");
        assert_eq!(info.classes[0].methods.len(), 1);
        assert_eq!(info.classes[0].methods[0].name, "public_method");
        assert_eq!(info.classes[0].private_method_count, 1);
    }

    #[test]
    fn test_extract_interface_async_function() {
        let source = r#"
async def async_func():
    pass

def sync_func():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.functions.len(), 2);

        let async_fn = info.functions.iter().find(|f| f.name == "async_func");
        assert!(async_fn.is_some());
        assert!(async_fn.unwrap().is_async);

        let sync_fn = info.functions.iter().find(|f| f.name == "sync_func");
        assert!(sync_fn.is_some());
        assert!(!sync_fn.unwrap().is_async);
    }

    #[test]
    fn test_extract_interface_with_all() {
        let source = r#"
__all__ = ['foo', 'Bar']

def foo():
    pass

def bar():
    pass

class Bar:
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        // schema-cleanup-v1 BUG-22: all_exports is now Vec<String>
        // (never null). When `__all__` is present, it carries those.
        assert!(!info.all_exports.is_empty());
        assert!(info.all_exports.contains(&"foo".to_string()));
        assert!(info.all_exports.contains(&"Bar".to_string()));
    }

    #[test]
    fn test_extract_interface_docstrings() {
        let source = r#"
def documented():
    """This is a docstring."""
    pass

def undocumented():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        let documented = info.functions.iter().find(|f| f.name == "documented");
        assert!(documented.is_some());
        assert!(documented.unwrap().docstring.is_some());
        assert!(documented
            .unwrap()
            .docstring
            .as_ref()
            .unwrap()
            .contains("docstring"));

        let undocumented = info.functions.iter().find(|f| f.name == "undocumented");
        assert!(undocumented.is_some());
        assert!(undocumented.unwrap().docstring.is_none());
    }

    #[test]
    fn test_extract_interface_class_bases() {
        let source = r#"
class Child(Parent, Mixin):
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.classes.len(), 1);
        assert_eq!(info.classes[0].bases.len(), 2);
        assert!(info.classes[0].bases.contains(&"Parent".to_string()));
        assert!(info.classes[0].bases.contains(&"Mixin".to_string()));
    }

    // -------------------------------------------------------------------------
    // format_interface_text tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_format_interface_text() {
        let info = InterfaceInfo {
            file: "test.py".to_string(),
            all_exports: vec!["foo".to_string()],
            functions: vec![FunctionInfo {
                name: "foo".to_string(),
                signature: "(x: int) -> str".to_string(),
                docstring: Some("A function.".to_string()),
                lineno: 5,
                is_async: false,
            }],
            classes: vec![ClassInfo {
                name: "MyClass".to_string(),
                lineno: 10,
                bases: vec!["Base".to_string()],
                methods: vec![MethodInfo {
                    name: "method".to_string(),
                    signature: "(self)".to_string(),
                    lineno: 11,
                    is_async: false,
                }],
                private_method_count: 2,
            }],
        };

        let text = format_interface_text(&info);
        assert!(text.contains("File: test.py"));
        assert!(text.contains("foo"));
        assert!(text.contains("MyClass"));
        assert!(text.contains("Base"));
        assert!(text.contains("method"));
        assert!(text.contains("2 private methods"));
    }

    // =========================================================================
    // Multi-language tests
    // =========================================================================

    // -------------------------------------------------------------------------
    // Rust
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_rust_pub_functions() {
        let source = r#"
/// Adds two numbers.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn private_helper() -> bool {
    true
}

pub async fn async_fetch() -> String {
    String::new()
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        assert_eq!(
            info.functions.len(),
            2,
            "Should find 2 pub functions, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let add_fn = info.functions.iter().find(|f| f.name == "add");
        assert!(add_fn.is_some(), "Should find 'add' function");
        let add_fn = add_fn.unwrap();
        assert!(
            add_fn.signature.contains("a: i32"),
            "sig = {:?}",
            add_fn.signature
        );
        assert!(
            add_fn.signature.contains("-> i32"),
            "sig = {:?}",
            add_fn.signature
        );
        assert!(add_fn.docstring.is_some(), "Should have doc comment");
        assert!(add_fn
            .docstring
            .as_ref()
            .unwrap()
            .contains("Adds two numbers"));
        assert!(!add_fn.is_async);

        let async_fn = info.functions.iter().find(|f| f.name == "async_fetch");
        assert!(async_fn.is_some(), "Should find 'async_fetch' function");
        assert!(async_fn.unwrap().is_async);
    }

    #[test]
    fn test_extract_interface_rust_struct_impl() {
        let source = r#"
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Point { x, y }
    }

    fn internal(&self) {}
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        // Should find struct and impl as classes
        assert!(
            !info.classes.is_empty(),
            "Should find at least struct/impl, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        // Check the struct
        let point_struct = info.classes.iter().find(|c| c.name == "Point");
        assert!(point_struct.is_some(), "Should find Point struct/impl");
    }

    #[test]
    fn test_extract_interface_rust_trait() {
        let source = r#"
pub trait Drawable {
    fn draw(&self);
    fn resize(&mut self, factor: f64);
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        let trait_info = info.classes.iter().find(|c| c.name == "Drawable");
        assert!(trait_info.is_some(), "Should find Drawable trait");
    }

    // -------------------------------------------------------------------------
    // Go
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_go_exported_functions() {
        let source = r#"
package main

// ProcessData handles data processing.
func ProcessData(input string) (string, error) {
    return input, nil
}

func internalHelper() bool {
    return true
}
"#;
        let info = extract_interface(Path::new("test.go"), source).unwrap();

        // Go: exported functions start with uppercase
        assert_eq!(
            info.functions.len(),
            1,
            "Should find 1 exported function, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert_eq!(info.functions[0].name, "ProcessData");
        assert!(
            info.functions[0].docstring.is_some(),
            "Should have doc comment"
        );
    }

    // -------------------------------------------------------------------------
    // TypeScript
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_typescript_class() {
        let source = r#"
class UserService {
    async fetchUser(id: string): Promise<User> {
        return {} as User;
    }

    private internalMethod(): void {}
}

function processData(input: string): number {
    return input.length;
}
"#;
        let info = extract_interface(Path::new("test.ts"), source).unwrap();

        // Should find both the class and the function
        assert!(
            !info.functions.is_empty() || !info.classes.is_empty(),
            "Should find definitions: functions={:?}, classes={:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_interface_typescript_interface() {
        let source = r#"
interface User {
    id: string;
    name: string;
    email: string;
}

type Status = "active" | "inactive";
"#;
        let info = extract_interface(Path::new("test.ts"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find interface/type declarations, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    // -------------------------------------------------------------------------
    // Java
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_java_class() {
        let source = r#"
/**
 * Service for managing users.
 */
public class UserService {
    public String getUser(String id) {
        return id;
    }

    private void internalCleanup() {}
}
"#;
        let info = extract_interface(Path::new("test.java"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find Java class, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        if let Some(cls) = info.classes.iter().find(|c| c.name == "UserService") {
            assert!(!cls.methods.is_empty(), "Should find public methods");
        }
    }

    // -------------------------------------------------------------------------
    // C
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_c_functions() {
        let source = r#"
int add(int a, int b) {
    return a + b;
}

static int internal_helper(void) {
    return 42;
}
"#;
        let info = extract_interface(Path::new("test.c"), source).unwrap();

        // Non-static C functions should be public
        assert_eq!(
            info.functions.len(),
            1,
            "Should find 1 non-static function, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert_eq!(info.functions[0].name, "add");
    }

    // -------------------------------------------------------------------------
    // Ruby
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_ruby_class() {
        let source = r#"
class UserManager
  def find_user(id)
    # find user
  end

  def _private_method
    # private
  end
end
"#;
        let info = extract_interface(Path::new("test.rb"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find Ruby class, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        if let Some(cls) = info.classes.iter().find(|c| c.name == "UserManager") {
            assert_eq!(
                cls.methods.len(),
                1,
                "Should find 1 public method, got: {:?}",
                cls.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
            );
            assert_eq!(cls.methods[0].name, "find_user");
            assert_eq!(cls.private_method_count, 1);
        }
    }

    // -------------------------------------------------------------------------
    // is_public_for_lang tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_public_for_go() {
        assert!(is_public_for_lang("ProcessData", Language::Go));
        assert!(!is_public_for_lang("processData", Language::Go));
    }

    #[test]
    fn test_is_public_for_python() {
        assert!(is_public_for_lang("process_data", Language::Python));
        assert!(!is_public_for_lang("_private", Language::Python));
    }

    // -------------------------------------------------------------------------
    // is_supported_source_file tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_supported_source_file() {
        assert!(is_supported_source_file(Path::new("test.py")));
        assert!(is_supported_source_file(Path::new("test.rs")));
        assert!(is_supported_source_file(Path::new("test.go")));
        assert!(is_supported_source_file(Path::new("test.ts")));
        assert!(is_supported_source_file(Path::new("test.java")));
        assert!(is_supported_source_file(Path::new("test.c")));
        assert!(is_supported_source_file(Path::new("test.rb")));
        assert!(is_supported_source_file(Path::new("test.cs")));
        assert!(!is_supported_source_file(Path::new("test.txt")));
        assert!(!is_supported_source_file(Path::new("test.md")));
    }

    /// (fix-R7-cl2-c-structref-v1) A C `struct_specifier` used only as a TYPE
    /// REFERENCE — `sizeof(struct sdshdr5)`, a cast, a param type — has no body
    /// and must NOT be reported as a class/export. Only the struct WITH a body
    /// is a definition.
    #[test]
    fn test_interface_c_struct_type_reference_not_class() {
        let source = r#"
struct sdshdr5 {
    unsigned char flags;
    char buf[];
};

int sdslen(void) {
    return sizeof(struct sdshdr8) + sizeof(struct sdshdr16);
}
"#;
        let info = extract_interface(Path::new("test.c"), source).unwrap();
        let class_names: Vec<&str> = info.classes.iter().map(|c| c.name.as_str()).collect();
        // The bodyless type references must NOT appear as classes.
        assert!(
            !class_names.contains(&"sdshdr8"),
            "`sizeof(struct sdshdr8)` (no body) must not be a class, got {:?}",
            class_names
        );
        assert!(
            !class_names.contains(&"sdshdr16"),
            "`sizeof(struct sdshdr16)` (no body) must not be a class, got {:?}",
            class_names
        );
        assert!(
            !info.all_exports.iter().any(|e| e == "sdshdr8"),
            "type-reference `sdshdr8` must not be an export, got {:?}",
            info.all_exports
        );
        // The real definition (with body) IS a class.
        assert!(
            class_names.contains(&"sdshdr5"),
            "the defined `struct sdshdr5` (with body) must be a class, got {:?}",
            class_names
        );
    }

    /// (fix-R7-cl2-csharp-bases-v1) C# bases live under a `base_list` node, not
    /// Java's `superclass`/`interfaces` fields. The C# arm must capture the base
    /// type (was always empty: #38).
    #[test]
    fn test_interface_csharp_bases_captured() {
        let source = r#"
public class JsonException : Exception
{
    public void Throw() {}
}
"#;
        let info = extract_interface(Path::new("test.cs"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "JsonException")
            .expect("JsonException class");
        assert!(
            cls.bases.iter().any(|b| b == "Exception"),
            "C# base `Exception` must be captured, got {:?}",
            cls.bases
        );
    }

    /// (fix-R7-cl2-php-bases-v1) PHP had no base arm (#153). `extends` must be
    /// captured.
    #[test]
    fn test_interface_php_bases_captured() {
        let source = r#"<?php
class ServerException extends BadResponseException
{
    public function getResponse() {}
}
"#;
        let info = extract_interface(Path::new("test.php"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "ServerException")
            .expect("ServerException class");
        assert!(
            cls.bases.iter().any(|b| b == "BadResponseException"),
            "PHP base `BadResponseException` must be captured, got {:?}",
            cls.bases
        );
    }

    /// (fix-R7-cl2-swift-signature-v1) Swift method signatures were always
    /// empty in `interface` (#239) because the generic signature builder used a
    /// `parameters` field that tree-sitter-swift does not expose. The Swift arm
    /// must reconstruct `(params) throws -> ReturnType` from the AST.
    #[test]
    fn test_interface_swift_method_signature_not_empty() {
        let source = r#"
public class Api {
    public func asURLRequest(using e: Encoder) throws -> URLRequest {
        return r
    }
}
"#;
        let info = extract_interface(Path::new("test.swift"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "Api")
            .expect("Api class");
        let m = cls
            .methods
            .iter()
            .find(|m| m.name == "asURLRequest")
            .expect("asURLRequest method");
        assert!(
            !m.signature.trim().is_empty(),
            "Swift method signature must not be empty"
        );
        // The signature must carry the parameter and the return type.
        assert!(
            m.signature.contains("Encoder"),
            "signature must include the param type `Encoder`, got {:?}",
            m.signature
        );
        assert!(
            m.signature.contains("URLRequest"),
            "signature must include return type `URLRequest`, got {:?}",
            m.signature
        );
        // Body braces must NOT appear in the signature.
        assert!(
            !m.signature.contains('{'),
            "signature must drop the body, got {:?}",
            m.signature
        );
    }

    /// (fix-R7-cl2-scala-abstract-v1) A Scala trait's abstract (bodyless) `def`s
    /// parse as `function_declaration` and must surface as methods — the whole
    /// point of `interface` for a trait contract (#207 dropped all but the one
    /// concrete def).
    #[test]
    fn test_interface_scala_abstract_trait_methods() {
        let source = r#"
trait Clock {
  def currentTime(unit: TimeUnit): Long
  def nanoTime: Long
  def instant: Instant
}
"#;
        let info = extract_interface(Path::new("test.scala"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "Clock")
            .expect("Clock trait");
        let method_names: Vec<&str> = cls.methods.iter().map(|m| m.name.as_str()).collect();
        for expected in ["currentTime", "nanoTime", "instant"] {
            assert!(
                method_names.contains(&expected),
                "abstract trait method `{}` must surface, got {:?}",
                expected,
                method_names
            );
        }
    }
}
