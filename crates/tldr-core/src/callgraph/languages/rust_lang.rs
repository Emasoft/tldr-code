//! Rust language handler for call graph analysis.
//!
//! This module provides Rust call graph support using tree-sitter-rust.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `use crate::mod::item` | `{module: "crate::mod", names: ["item"]}` |
//! | `use self::item` | `{module: "self", names: ["item"]}` |
//! | `use super::item` | `{module: "super", names: ["item"]}` |
//! | `use mod::{a, b}` | `{module: "mod", names: ["a", "b"]}` |
//! | `use mod::*` | `{module: "mod", names: ["*"]}` |
//! | `use mod::item as alias` | `{module: "mod", names: ["item"], aliases: {"alias": "item"}}` |
//! | `mod foo;` | `{module: "foo", is_mod: true}` |
//! | `extern crate foo;` | `{module: "foo"}` |
//!
//! # Call Extraction
//!
//! - Direct calls: `func()` -> CallType::Direct or CallType::Intra
//! - Method calls: `obj.method()` -> CallType::Attr
//! - Static/associated calls: `Type::method()` -> CallType::Attr
//! - Trait method calls: Resolved via trait bounds (limited support)
//! - Macro calls: Limited support (name extraction only)
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.2 for Rust-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::common::{extend_calls_if_any, insert_calls_if_any};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// Rust Handler
// =============================================================================

/// Rust language handler using tree-sitter-rust.
///
/// Supports:
/// - Use declaration parsing (simple, grouped, glob)
/// - Mod declarations
/// - Call extraction (direct, method, associated functions)
/// - Struct/enum/trait definitions
#[derive(Debug, Default)]
pub struct RustLangHandler;

impl RustLangHandler {
    /// Creates a new RustLangHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set Rust language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Parse a use declaration node.
    fn parse_use_declaration(&self, node: &Node, source: &[u8]) -> Vec<ImportDef> {
        let mut imports = Vec::new();

        // Get the full use path text
        let text = get_node_text(node, source);

        // Strip "use " prefix, "pub use " prefix, and trailing semicolon
        let text = text
            .strip_prefix("pub use ")
            .or_else(|| text.strip_prefix("use "))
            .unwrap_or(text)
            .trim_end_matches(';')
            .trim();

        // Parse the use tree
        self.parse_use_tree(text, &mut imports);

        imports
    }

    /// Parse a use tree (handles grouped imports, glob, aliases).
    fn parse_use_tree(&self, text: &str, imports: &mut Vec<ImportDef>) {
        // Handle grouped imports: use mod::{a, b, c}
        if let Some(brace_start) = text.find('{') {
            let module = text[..brace_start].trim_end_matches("::").to_string();
            let brace_end = text.rfind('}').unwrap_or(text.len());
            let items = &text[brace_start + 1..brace_end];

            // Split by comma, handling nested groups
            let mut names = Vec::new();
            let mut aliases = HashMap::new();
            let mut depth = 0;
            let mut current = String::new();

            for c in items.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        current.push(c);
                    }
                    '}' => {
                        depth -= 1;
                        current.push(c);
                    }
                    ',' if depth == 0 => {
                        self.parse_single_import(current.trim(), &mut names, &mut aliases);
                        current.clear();
                    }
                    _ => {
                        current.push(c);
                    }
                }
            }
            if !current.trim().is_empty() {
                self.parse_single_import(current.trim(), &mut names, &mut aliases);
            }

            let mut imp = ImportDef::from_import(module, names);
            if !aliases.is_empty() {
                imp.aliases = Some(aliases);
            }
            imports.push(imp);
        } else if text.ends_with("::*") {
            // Glob import: use mod::*
            let module = text.trim_end_matches("::*").to_string();
            imports.push(ImportDef::wildcard_import(module));
        } else if text.contains("::") {
            // Simple path import: use mod::item
            let parts: Vec<&str> = text.rsplitn(2, "::").collect();
            if parts.len() == 2 {
                let item = parts[0].trim();
                let module = parts[1].trim().to_string();

                // Check for alias: use mod::item as alias
                if item.contains(" as ") {
                    let alias_parts: Vec<&str> = item.splitn(2, " as ").collect();
                    let name = alias_parts[0].trim().to_string();
                    let alias = alias_parts[1].trim().to_string();

                    let mut imp = ImportDef::from_import(module, vec![name.clone()]);
                    let mut aliases = HashMap::new();
                    aliases.insert(alias, name);
                    imp.aliases = Some(aliases);
                    imports.push(imp);
                } else {
                    imports.push(ImportDef::from_import(module, vec![item.to_string()]));
                }
            } else {
                // Just a module path without trailing item
                imports.push(ImportDef::simple_import(text.to_string()));
            }
        } else {
            // Simple import: use item
            imports.push(ImportDef::simple_import(text.to_string()));
        }
    }

    /// Parse a single import item (possibly with alias).
    fn parse_single_import(
        &self,
        item: &str,
        names: &mut Vec<String>,
        aliases: &mut HashMap<String, String>,
    ) {
        let item = item.trim();
        if item.is_empty() {
            return;
        }

        if item.contains(" as ") {
            let parts: Vec<&str> = item.splitn(2, " as ").collect();
            let name = parts[0].trim().to_string();
            let alias = parts[1].trim().to_string();
            names.push(name.clone());
            aliases.insert(alias, name);
        } else if item == "self" {
            names.push("self".to_string());
        } else if item == "*" {
            names.push("*".to_string());
        } else {
            names.push(item.to_string());
        }
    }

    /// Parse a mod declaration node.
    fn parse_mod_declaration(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        // Check if it's a mod declaration (not an inline module)
        let mut has_body = false;
        let mut name = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        name = Some(get_node_text(&child, source).to_string());
                    }
                    "declaration_list" => {
                        has_body = true;
                    }
                    _ => {}
                }
            }
        }

        // Only return for mod declarations without body (mod foo;)
        if !has_body {
            if let Some(n) = name {
                let mut imp = ImportDef::simple_import(n);
                imp.is_mod = true;
                return Some(imp);
            }
        }

        None
    }

    /// Collect all function, struct, enum, and trait definitions.
    fn collect_definitions(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> (HashSet<String>, HashSet<String>) {
        let mut functions = HashSet::new();
        let mut types = HashSet::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        functions.insert(get_node_text(&name_node, source).to_string());
                    }
                }
                "struct_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source).to_string();
                        types.insert(name.clone());
                        functions.insert(name);
                    }
                }
                "enum_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source).to_string();
                        types.insert(name.clone());
                        functions.insert(name);
                    }
                }
                "trait_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source).to_string();
                        types.insert(name.clone());
                        functions.insert(name);
                    }
                }
                "impl_item" => {
                    // Collect methods from impl blocks, keyed under the
                    // IMPLEMENTING type (impl_item `type` field), not the trait.
                    let type_name = self.impl_owner_type(&node, source);

                    if let Some(body) = node.child_by_field_name("body") {
                        for j in 0..body.named_child_count() {
                            if let Some(item) = body.named_child(j) {
                                if item.kind() == "function_item" {
                                    if let Some(name_node) = item.child_by_field_name("name") {
                                        let method_name =
                                            get_node_text(&name_node, source).to_string();
                                        functions.insert(method_name.clone());

                                        // Also add as Type::method
                                        if let Some(ref tn) = type_name {
                                            functions.insert(format!("{tn}::{method_name}"));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        (functions, types)
    }

    /// Heuristically extract function calls from macro invocation token trees.
    ///
    /// Since tree-sitter treats macro bodies as opaque token_tree nodes,
    /// we use regex to find patterns that look like function calls:
    /// `identifier(` or `path::identifier(`.
    ///
    /// We are conservative: only extract names that look like real function calls,
    /// excluding Rust keywords and common false positives.
    fn extract_calls_from_macro_body(
        &self,
        text: &str,
        defined_funcs: &HashSet<String>,
        caller: &str,
        line: u32,
    ) -> Vec<CallSite> {
        // Keywords that should never be treated as function calls
        static KEYWORDS: &[&str] = &[
            "if", "else", "for", "while", "loop", "match", "fn", "let", "mut", "ref", "type",
            "pub", "use", "mod", "impl", "trait", "struct", "enum", "where", "as", "in", "return",
            "break", "continue", "move", "async", "await", "unsafe", "extern", "crate", "self",
            "super", "Self", "true", "false", "const", "static", "dyn", "box", "yield",
        ];

        let keyword_set: HashSet<&str> = KEYWORDS.iter().copied().collect();

        let mut calls = Vec::new();

        // Match patterns: `identifier(` or `path::identifier(`
        // The regex captures: (optional_path::)identifier followed by (
        let re = Regex::new(r"([a-zA-Z_][\w]*(?:::[a-zA-Z_][\w]*)*)\s*\(").unwrap();

        for cap in re.captures_iter(text) {
            let full_match = cap.get(1).unwrap().as_str();

            // Extract the bare function name (last segment for path calls)
            let bare_name = full_match.rsplit("::").next().unwrap_or(full_match);

            // Skip keywords
            if keyword_set.contains(bare_name) {
                continue;
            }

            // Skip if it looks like a macro name (contains !)
            // (shouldn't happen with our regex, but be safe)
            if full_match.contains('!') {
                continue;
            }

            // Determine call type
            let call_type = if defined_funcs.contains(full_match) {
                CallType::Intra
            } else if full_match.contains("::") {
                CallType::Attr
            } else {
                CallType::Direct
            };

            let receiver = if full_match.contains("::") {
                full_match.rsplitn(2, "::").last().map(|s| s.to_string())
            } else {
                None
            };

            calls.push(CallSite::new(
                caller.to_string(),
                full_match.to_string(),
                call_type,
                Some(line),
                None,
                receiver,
                None,
            ));
        }

        calls
    }

    /// Find the enclosing function for a given node.
    ///
    /// Walks up the AST parent chain to find the nearest enclosing function_item.
    /// If inside an impl block, returns "Type::method". If inside a trait default
    /// method, returns "Trait::method". If at module level, returns "<module>".
    fn find_enclosing_function(&self, node: &Node, source: &[u8]) -> String {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_item" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    let func_name = get_node_text(&name_node, source).to_string();

                    // Check if this function is inside an impl or trait block
                    if let Some(decl_list) = parent.parent() {
                        if decl_list.kind() == "declaration_list" {
                            if let Some(container) = decl_list.parent() {
                                match container.kind() {
                                    "impl_item" => {
                                        // Use the implementing type (impl_item
                                        // `type` field), not the trait of an
                                        // `impl Trait for Type` block.
                                        if let Some(owner) =
                                            self.impl_owner_type(&container, source)
                                        {
                                            return format!("{owner}::{func_name}");
                                        }
                                    }
                                    "trait_item" => {
                                        // Find the trait name
                                        for i in 0..container.child_count() {
                                            if let Some(child) = container.child(i) {
                                                if child.kind() == "type_identifier" {
                                                    return format!(
                                                        "{}::{}",
                                                        get_node_text(&child, source),
                                                        func_name
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    return func_name;
                }
            }
            current = parent.parent();
        }
        "<module>".to_string()
    }

    /// Extract calls from a function body.
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        for child in walk_tree(*node) {
            if child.kind() == "call_expression" {
                let line = child.start_position().row as u32 + 1;

                // Get the function being called
                if let Some(func_node) = child.child(0) {
                    match func_node.kind() {
                        "identifier" => {
                            // Direct call: func()
                            let target = get_node_text(&func_node, source).to_string();
                            let call_type = if defined_funcs.contains(&target) {
                                CallType::Intra
                            } else {
                                CallType::Direct
                            };
                            calls.push(CallSite::new(
                                caller.to_string(),
                                target,
                                call_type,
                                Some(line),
                                None,
                                None,
                                None,
                            ));
                        }
                        "scoped_identifier" => {
                            // Path call: module::func() or Type::method()
                            let target = get_node_text(&func_node, source).to_string();

                            // Extract receiver (the part before ::)
                            let receiver = if target.contains("::") {
                                target.rsplitn(2, "::").last().map(|s| s.to_string())
                            } else {
                                None
                            };

                            // Check if it's a local associated function
                            let call_type = if defined_funcs.contains(&target) {
                                CallType::Intra
                            } else if receiver.is_some() {
                                CallType::Attr
                            } else {
                                CallType::Direct
                            };

                            calls.push(CallSite::new(
                                caller.to_string(),
                                target,
                                call_type,
                                Some(line),
                                None,
                                receiver,
                                None,
                            ));
                        }
                        "field_expression" => {
                            // Method call: obj.method()
                            let mut method_name: Option<String> = None;
                            let mut receiver: Option<String> = None;

                            for i in 0..func_node.child_count() {
                                if let Some(fc) = func_node.child(i) {
                                    match fc.kind() {
                                        "field_identifier" => {
                                            method_name =
                                                Some(get_node_text(&fc, source).to_string());
                                        }
                                        "identifier" => {
                                            receiver = Some(get_node_text(&fc, source).to_string());
                                        }
                                        "self" => {
                                            receiver = Some("self".to_string());
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            if let Some(method) = method_name {
                                if receiver.is_none() {
                                    if let Some(value_node) = func_node.child_by_field_name("value")
                                    {
                                        let value_text =
                                            get_node_text(&value_node, source).to_string();
                                        if !value_text.is_empty() {
                                            receiver = Some(value_text);
                                        }
                                    }
                                }

                                let target = if let Some(ref recv) = receiver {
                                    format!("{}.{}", recv, method)
                                } else {
                                    method.clone()
                                };

                                let call_type = if defined_funcs.contains(&method) {
                                    CallType::Intra
                                } else if receiver.is_some() {
                                    CallType::Attr
                                } else {
                                    CallType::Direct
                                };

                                calls.push(CallSite::new(
                                    caller.to_string(),
                                    target,
                                    call_type,
                                    Some(line),
                                    None,
                                    receiver,
                                    None,
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        calls
    }

    fn process_function_item_calls(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        let inside_container = node
            .parent()
            .is_some_and(|parent| parent.kind() == "declaration_list")
            && node
                .parent()
                .and_then(|parent| parent.parent())
                .is_some_and(|grand_parent| {
                    grand_parent.kind() == "impl_item" || grand_parent.kind() == "trait_item"
                });
        if inside_container {
            return;
        }

        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let func_name = get_node_text(&name_node, source).to_string();
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };

        let calls = self.extract_calls_from_node(&body, source, defined_funcs, &func_name);
        insert_calls_if_any(calls_by_func, func_name, calls);
    }

    /// Resolve the bare name of the type an `impl_item` is *for*.
    ///
    /// tree-sitter-rust exposes the implemented type under the `type` field of
    /// an `impl_item` and (only for `impl Trait for Type`) the trait under a
    /// separate `trait` field. Reading the `type` field is what makes
    /// `impl Trait for Type { fn m }` key `m` under `Type` rather than `Trait`:
    /// a flat left-to-right child scan would otherwise hit the trait's
    /// `type_identifier` first. Plain `impl Type` has no `trait` field, so the
    /// `type` field is still the implementing type.
    ///
    /// The implementing type may be wrapped: generic (`Type<T>`), reference
    /// (`&Type`), pointer/array, or module-qualified (`module::Type`). Those
    /// wrappers are peeled down to the bare `type_identifier`.
    fn impl_owner_type(&self, impl_node: &Node, source: &[u8]) -> Option<String> {
        let type_node = impl_node.child_by_field_name("type")?;
        Self::bare_type_name(&type_node, source)
    }

    /// Peel generic/reference/scoped wrappers down to a bare `type_identifier`.
    fn bare_type_name(node: &Node, source: &[u8]) -> Option<String> {
        match node.kind() {
            "type_identifier" => Some(get_node_text(node, source).to_string()),
            _ => {
                // `Type<T>`, `&Type`, `*const Type`, `[Type; N]`, ... all carry
                // the inner type under a `type` field.
                if let Some(inner) = node.child_by_field_name("type") {
                    return Self::bare_type_name(&inner, source);
                }
                // `module::Type` exposes the final segment under `name`.
                if let Some(name) = node.child_by_field_name("name") {
                    return Self::bare_type_name(&name, source);
                }
                // Fallback: first named descendant resolving to a type_identifier.
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        if let Some(found) = Self::bare_type_name(&child, source) {
                            return Some(found);
                        }
                    }
                }
                None
            }
        }
    }

    fn process_impl_item_calls(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        // Key outgoing edges under the IMPLEMENTING type (impl_item `type`
        // field), never the trait of an `impl Trait for Type` block.
        let type_name = self.impl_owner_type(node, source);

        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        for j in 0..body.named_child_count() {
            let Some(item) = body.named_child(j) else {
                continue;
            };
            if item.kind() != "function_item" {
                continue;
            }
            let Some(name_node) = item.child_by_field_name("name") else {
                continue;
            };
            let method_name = get_node_text(&name_node, source).to_string();
            let full_name = if let Some(type_name) = type_name.as_deref() {
                format!("{type_name}::{method_name}")
            } else {
                method_name
            };
            let Some(item_body) = item.child_by_field_name("body") else {
                continue;
            };
            let calls =
                self.extract_calls_from_node(&item_body, source, defined_funcs, &full_name);
            insert_calls_if_any(calls_by_func, full_name, calls);
        }
    }

    fn process_trait_item_calls(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        let mut trait_name: Option<String> = None;

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            match child.kind() {
                "type_identifier" => {
                    trait_name = Some(get_node_text(&child, source).to_string());
                }
                "declaration_list" => {
                    for j in 0..child.named_child_count() {
                        let Some(item) = child.named_child(j) else {
                            continue;
                        };
                        if item.kind() != "function_item" {
                            continue;
                        }
                        let Some(name_node) = item.child_by_field_name("name") else {
                            continue;
                        };
                        let method_name = get_node_text(&name_node, source).to_string();
                        let full_name = if let Some(trait_name) = trait_name.as_deref() {
                            format!("{trait_name}::{method_name}")
                        } else {
                            method_name
                        };
                        let Some(body) = item.child_by_field_name("body") else {
                            continue;
                        };
                        let calls =
                            self.extract_calls_from_node(&body, source, defined_funcs, &full_name);
                        insert_calls_if_any(calls_by_func, full_name, calls);
                    }
                }
                _ => {}
            }
        }
    }

    fn process_const_or_static_calls(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        let calls = self.extract_calls_from_node(&value, source, defined_funcs, "<module>");
        extend_calls_if_any(calls_by_func, "<module>".to_string(), calls);
    }

    fn process_macro_invocation_calls(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        let line = node.start_position().row as u32 + 1;
        let caller = self.find_enclosing_function(node, source);

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() != "token_tree" {
                continue;
            }

            let token_text = get_node_text(&child, source);
            let inner = if (token_text.starts_with('(') && token_text.ends_with(')'))
                || (token_text.starts_with('{') && token_text.ends_with('}'))
                || (token_text.starts_with('[') && token_text.ends_with(']'))
            {
                &token_text[1..token_text.len() - 1]
            } else {
                token_text
            };

            let macro_calls =
                self.extract_calls_from_macro_body(inner, defined_funcs, &caller, line);
            extend_calls_if_any(calls_by_func, caller.clone(), macro_calls);
            break;
        }
    }
}

impl CallGraphLanguageSupport for RustLangHandler {
    fn name(&self) -> &str {
        "rust"
    }

    fn extensions(&self) -> &[&str] {
        &[".rs"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "use_declaration" => {
                    imports.extend(self.parse_use_declaration(&node, source_bytes));
                }
                "mod_item" => {
                    if let Some(imp) = self.parse_mod_declaration(&node, source_bytes) {
                        imports.push(imp);
                    }
                }
                "extern_crate_declaration" => {
                    // extern crate foo;
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "identifier" {
                                imports.push(ImportDef::simple_import(
                                    get_node_text(&child, source_bytes).to_string(),
                                ));
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(imports)
    }

    fn extract_calls(
        &self,
        _path: &Path,
        source: &str,
        tree: &Tree,
    ) -> Result<HashMap<String, Vec<CallSite>>, ParseError> {
        let source_bytes = source.as_bytes();
        let (defined_funcs, _defined_types) = self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_item" => {
                    self.process_function_item_calls(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &mut calls_by_func,
                    );
                }
                "impl_item" => {
                    self.process_impl_item_calls(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &mut calls_by_func,
                    );
                }
                "trait_item" => {
                    self.process_trait_item_calls(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &mut calls_by_func,
                    );
                }
                "const_item" | "static_item" => {
                    self.process_const_or_static_calls(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &mut calls_by_func,
                    );
                }
                "macro_invocation" => {
                    self.process_macro_invocation_calls(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &mut calls_by_func,
                    );
                }
                _ => {}
            }
        }

        Ok(calls_by_func)
    }

    fn extract_definitions(
        &self,
        source: &str,
        _path: &Path,
        tree: &Tree,
    ) -> Result<(Vec<FuncDef>, Vec<ClassDef>), super::ParseError> {
        let source_bytes = source.as_bytes();
        let mut funcs = Vec::new();
        let mut classes = Vec::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source_bytes).to_string();
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;

                        // Check if inside an impl block OR a trait block.
                        //
                        // Issue #23 fix: Previously only `impl_item` was checked here,
                        // which meant trait default methods were emitted as
                        // `FuncDef::function(name)` and collided with free `fn name()`
                        // under the bare-name key `(module, name)` in `FuncIndex`
                        // (see builder_v2.rs:148-182). The fix is to ALSO recognize
                        // `trait_item` parents and emit `FuncDef::method(name, trait_name, ...)`
                        // so that builder_v2 inserts BOTH the bare-name key and the
                        // qualified-name key, mirroring the existing impl_item path.
                        //
                        // Note: abstract trait method signatures (no body) parse as
                        // `function_signature_item` in tree-sitter-rust, not as
                        // `function_item`, so they are naturally excluded here and
                        // do NOT need an explicit body-presence check.
                        let mut method_owner: Option<String> = None;
                        let mut parent = node.parent();
                        while let Some(p) = parent {
                            if p.kind() == "declaration_list" {
                                if let Some(gp) = p.parent() {
                                    match gp.kind() {
                                        "impl_item" => {
                                            // Key the method under the IMPLEMENTING
                                            // type (the impl_item `type` field), not
                                            // the trait. For `impl Trait for Type`
                                            // a flat child scan would hit the
                                            // trait's `type_identifier` first and
                                            // mis-file the method under the trait,
                                            // merging distinct types' same-named
                                            // methods into one node.
                                            method_owner =
                                                self.impl_owner_type(&gp, source_bytes);
                                        }
                                        "trait_item" => {
                                            // Find the trait name. trait_item carries
                                            // a single `type_identifier` child for the
                                            // trait's own name (no generic_type wrapper
                                            // at this position).
                                            for i in 0..gp.child_count() {
                                                if let Some(child) = gp.child(i) {
                                                    if child.kind() == "type_identifier" {
                                                        method_owner = Some(
                                                            get_node_text(&child, source_bytes)
                                                                .to_string(),
                                                        );
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                break;
                            }
                            parent = p.parent();
                        }

                        if let Some(owner_name) = method_owner {
                            funcs.push(FuncDef::method(name, owner_name, line, end_line));
                        } else {
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                "struct_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source_bytes).to_string();
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(name, line, end_line));
                    }
                }
                "enum_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source_bytes).to_string();
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(name, line, end_line));
                    }
                }
                "trait_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source_bytes).to_string();
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(name, line, end_line));
                    }
                }
                _ => {}
            }
        }

        Ok((funcs, classes))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_imports(source: &str) -> Vec<ImportDef> {
        let handler = RustLangHandler::new();
        handler.parse_imports(source, Path::new("test.rs")).unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = RustLangHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("test.rs"), source, &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_use_simple() {
            let imports = parse_imports("use std::io;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "std");
            assert!(imports[0].names.contains(&"io".to_string()));
        }

        #[test]
        fn test_parse_use_crate() {
            let imports = parse_imports("use crate::utils::helper;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "crate::utils");
            assert!(imports[0].names.contains(&"helper".to_string()));
        }

        #[test]
        fn test_parse_use_self() {
            let imports = parse_imports("use self::inner::Item;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "self::inner");
            assert!(imports[0].names.contains(&"Item".to_string()));
        }

        #[test]
        fn test_parse_use_super() {
            let imports = parse_imports("use super::parent::helper;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "super::parent");
            assert!(imports[0].names.contains(&"helper".to_string()));
        }

        #[test]
        fn test_parse_use_grouped() {
            let imports = parse_imports("use std::collections::{HashMap, HashSet};");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "std::collections");
            assert!(imports[0].names.contains(&"HashMap".to_string()));
            assert!(imports[0].names.contains(&"HashSet".to_string()));
        }

        #[test]
        fn test_parse_use_glob() {
            let imports = parse_imports("use std::collections::*;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "std::collections");
            assert!(imports[0].is_wildcard());
        }

        #[test]
        fn test_parse_use_alias() {
            let imports = parse_imports("use std::collections::HashMap as Map;");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].names.contains(&"HashMap".to_string()));
            let aliases = imports[0].aliases.as_ref().unwrap();
            assert_eq!(aliases.get("Map"), Some(&"HashMap".to_string()));
        }

        #[test]
        fn test_parse_mod_declaration() {
            let imports = parse_imports("mod utils;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "utils");
            assert!(imports[0].is_mod);
        }

        #[test]
        fn test_parse_pub_use() {
            let imports = parse_imports("pub use crate::types::*;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "crate::types");
            assert!(imports[0].is_wildcard());
        }

        #[test]
        fn test_parse_multiple_imports() {
            let source = r#"
use std::io;
use std::collections::HashMap;
mod utils;
"#;
            let imports = parse_imports(source);
            assert_eq!(imports.len(), 3);
        }
    }

    // -------------------------------------------------------------------------
    // Call Extraction Tests
    // -------------------------------------------------------------------------

    mod call_tests {
        use super::*;

        #[test]
        fn test_extract_calls_direct() {
            let source = r#"
fn main() {
    println!("hello");
    some_func();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            assert!(main_calls.iter().any(|c| c.target == "some_func"));
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
fn helper() -> i32 {
    42
}

fn main() {
    helper();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            let helper_call = main_calls.iter().find(|c| c.target == "helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_method() {
            let source = r#"
fn main() {
    let v = Vec::new();
    v.push(1);
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();

            let new_call = main_calls.iter().find(|c| c.target == "Vec::new").unwrap();
            assert_eq!(new_call.call_type, CallType::Attr);

            let push_call = main_calls.iter().find(|c| c.target == "v.push").unwrap();
            assert_eq!(push_call.call_type, CallType::Attr);
            assert_eq!(push_call.receiver, Some("v".to_string()));
        }

        #[test]
        fn test_extract_calls_associated_function() {
            let source = r#"
struct MyStruct;

impl MyStruct {
    fn new() -> Self {
        MyStruct
    }

    fn helper(&self) -> i32 {
        42
    }
}

fn main() {
    let obj = MyStruct::new();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();

            let new_call = main_calls
                .iter()
                .find(|c| c.target == "MyStruct::new")
                .unwrap();
            assert_eq!(new_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_self_method() {
            let source = r#"
struct MyStruct;

impl MyStruct {
    fn helper(&self) -> i32 {
        42
    }

    fn main(&self) {
        self.helper();
    }
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("MyStruct::main").unwrap();

            let helper_call = main_calls
                .iter()
                .find(|c| c.target == "self.helper")
                .unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
            assert_eq!(helper_call.receiver, Some("self".to_string()));
        }

        #[test]
        fn test_extract_calls_with_line_numbers() {
            let source = r#"fn main() {
    first();
    second();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();

            let first = main_calls.iter().find(|c| c.target == "first").unwrap();
            let second = main_calls.iter().find(|c| c.target == "second").unwrap();

            assert!(first.line.is_some());
            assert!(second.line.is_some());
            assert!(second.line.unwrap() > first.line.unwrap());
        }

        /// Test that methods in different impl blocks calling the same top-level function
        /// are recorded separately with qualified names like "TypeA::method" and "TypeB::method".
        #[test]
        fn test_extract_calls_method_to_toplevel() {
            let source = r#"
fn top_level_helper() -> i32 {
    42
}

struct TypeA;

impl TypeA {
    fn method_a(&self) -> i32 {
        top_level_helper()
    }
}

struct TypeB;

impl TypeB {
    fn method_b(&self) -> i32 {
        top_level_helper()
    }
}
"#;
            let calls = extract_calls(source);

            // Verify that calls are recorded with qualified caller names
            assert!(
                calls.contains_key("TypeA::method_a"),
                "Should have TypeA::method_a as caller (qualified with impl type)"
            );
            assert!(
                calls.contains_key("TypeB::method_b"),
                "Should have TypeB::method_b as caller (qualified with impl type)"
            );

            // Verify that TypeA::method_a calls top_level_helper
            let type_a_calls = calls
                .get("TypeA::method_a")
                .expect("TypeA::method_a should have calls");
            assert!(
                type_a_calls.iter().any(|c| c.target == "top_level_helper"),
                "TypeA::method_a should call top_level_helper"
            );
            assert!(
                type_a_calls.iter().any(|c| c.call_type == CallType::Intra),
                "Call to top_level_helper should be Intra (same file)"
            );

            // Verify that TypeB::method_b calls top_level_helper
            let type_b_calls = calls
                .get("TypeB::method_b")
                .expect("TypeB::method_b should have calls");
            assert!(
                type_b_calls.iter().any(|c| c.target == "top_level_helper"),
                "TypeB::method_b should call top_level_helper"
            );
            assert!(
                type_b_calls.iter().any(|c| c.call_type == CallType::Intra),
                "Call to top_level_helper should be Intra (same file)"
            );

            // Verify that the calls are recorded separately (different callers)
            assert_ne!(
                type_a_calls, type_b_calls,
                "Calls from different impl methods should be separate entries"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Trait Default Method Body Tests (#26)
    // -------------------------------------------------------------------------

    mod trait_default_method_tests {
        use super::*;

        #[test]
        fn test_trait_default_method_extracts_direct_call() {
            let source = r#"
trait Processor {
    fn process(&self) {
        validate();
    }
}
"#;
            let calls = extract_calls(source);
            let proc_calls = calls.get("Processor::process").expect(
                "Should extract calls from trait default method with caller Processor::process",
            );
            assert!(
                proc_calls.iter().any(|c| c.target == "validate"),
                "Should find validate() call inside trait default method body"
            );
        }

        #[test]
        fn test_trait_default_method_extracts_self_call() {
            let source = r#"
trait Processor {
    fn transform(&self) -> i32 { 42 }
    fn process(&self) {
        self.transform();
    }
}
"#;
            let calls = extract_calls(source);
            let proc_calls = calls
                .get("Processor::process")
                .expect("Should extract calls from trait default method");
            assert!(
                proc_calls.iter().any(|c| c.target == "self.transform"),
                "Should find self.transform() call inside trait default method body"
            );
        }

        #[test]
        fn test_trait_default_method_extracts_associated_call() {
            let source = r#"
trait Builder {
    fn build(&self) {
        Config::new();
        Self::default_config();
    }
}
"#;
            let calls = extract_calls(source);
            let build_calls = calls
                .get("Builder::build")
                .expect("Should extract calls from trait default method");
            assert!(
                build_calls.iter().any(|c| c.target == "Config::new"),
                "Should find Config::new() inside trait default method body"
            );
        }

        #[test]
        fn test_trait_abstract_method_not_extracted() {
            // Abstract methods (no body) should NOT produce call entries
            let source = r#"
trait Processor {
    fn process(&self);
    fn validate(&self);
}
"#;
            let calls = extract_calls(source);
            assert!(
                !calls.contains_key("Processor::process"),
                "Abstract trait method without body should not be in call map"
            );
            assert!(
                !calls.contains_key("Processor::validate"),
                "Abstract trait method without body should not be in call map"
            );
        }

        #[test]
        fn test_trait_mixed_methods() {
            // Mix of abstract and default methods
            let source = r#"
trait Handler {
    fn abstract_method(&self);
    fn default_method(&self) {
        do_something();
    }
}
"#;
            let calls = extract_calls(source);
            assert!(
                !calls.contains_key("Handler::abstract_method"),
                "Abstract method should not be in call map"
            );
            let default_calls = calls
                .get("Handler::default_method")
                .expect("Default method with body should be extracted");
            assert!(
                default_calls.iter().any(|c| c.target == "do_something"),
                "Should find do_something() in default method body"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Const/Static Initializer Tests (#22/#10)
    // -------------------------------------------------------------------------

    mod const_static_tests {
        use super::*;

        #[test]
        fn test_const_initializer_call() {
            let source = r#"
const HANDLER: Handler = create_handler();
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("Should extract calls from const initializer with caller <module>");
            assert!(
                module_calls.iter().any(|c| c.target == "create_handler"),
                "Should find create_handler() in const initializer"
            );
        }

        #[test]
        fn test_static_initializer_call() {
            let source = r#"
static CONFIG: Config = Config::new();
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("Should extract calls from static initializer with caller <module>");
            assert!(
                module_calls.iter().any(|c| c.target == "Config::new"),
                "Should find Config::new() in static initializer"
            );
        }

        #[test]
        fn test_static_mut_initializer_call() {
            let source = r#"
static mut COUNTER: u32 = compute_initial();
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("Should extract calls from static mut initializer with caller <module>");
            assert!(
                module_calls.iter().any(|c| c.target == "compute_initial"),
                "Should find compute_initial() in static mut initializer"
            );
        }

        #[test]
        fn test_const_literal_no_calls() {
            // Literal initializers should NOT produce entries
            let source = r#"
const MAX_SIZE: usize = 100;
static NAME: &str = "hello";
"#;
            let calls = extract_calls(source);
            assert!(
                !calls.contains_key("<module>"),
                "Literal const/static should not produce call entries"
            );
        }

        #[test]
        fn test_const_with_associated_function() {
            let source = r#"
const DEFAULT: Vec<i32> = Vec::new();
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("Should extract associated function call from const initializer");
            assert!(
                module_calls.iter().any(|c| c.target == "Vec::new"),
                "Should find Vec::new() in const initializer"
            );
        }

        #[test]
        fn test_multiple_const_static_initializers() {
            let source = r#"
const A: i32 = compute_a();
static B: i32 = compute_b();
const C: i32 = 42;
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("Should collect calls from multiple const/static items");
            assert!(
                module_calls.iter().any(|c| c.target == "compute_a"),
                "Should find compute_a()"
            );
            assert!(
                module_calls.iter().any(|c| c.target == "compute_b"),
                "Should find compute_b()"
            );
            assert_eq!(
                module_calls.len(),
                2,
                "Should only have 2 calls (not the literal 42)"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Closure Body Tests (#15) — Verify already handled by walk_tree
    // -------------------------------------------------------------------------

    mod closure_tests {
        use super::*;

        #[test]
        fn test_closure_calls_extracted() {
            let source = r#"
fn main() {
    let f = |x| transform(x);
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls
                .get("main")
                .expect("Should extract calls from closure body within function");
            assert!(
                main_calls.iter().any(|c| c.target == "transform"),
                "Should find transform() call inside closure body"
            );
        }

        #[test]
        fn test_closure_in_iterator_chain() {
            let source = r#"
fn process_items() {
    let items = vec![1, 2, 3];
    items.iter().map(|x| compute(x));
}
"#;
            let calls = extract_calls(source);
            let calls = calls
                .get("process_items")
                .expect("Should extract calls from closure in iterator chain");
            assert!(
                calls.iter().any(|c| c.target == "compute"),
                "Should find compute() call inside closure in iterator chain"
            );
        }

        #[test]
        fn test_move_closure_calls() {
            let source = r#"
fn setup() {
    let g = move || { initialize(); };
}
"#;
            let calls = extract_calls(source);
            let setup_calls = calls
                .get("setup")
                .expect("Should extract calls from move closure body");
            assert!(
                setup_calls.iter().any(|c| c.target == "initialize"),
                "Should find initialize() call inside move closure body"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Macro Invocation Heuristic Tests (#18)
    // -------------------------------------------------------------------------

    mod macro_heuristic_tests {
        use super::*;

        #[test]
        fn test_macro_with_function_call_arg() {
            let source = r#"
fn main() {
    assert_eq!(compute(), 42);
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls
                .get("main")
                .expect("Should extract calls from macro arguments");
            assert!(
                main_calls.iter().any(|c| c.target == "compute"),
                "Should find compute() call inside assert_eq! macro"
            );
        }

        #[test]
        fn test_macro_vec_with_calls() {
            let source = r#"
fn build() {
    let v = vec![init_value(), other()];
}
"#;
            let calls = extract_calls(source);
            let build_calls = calls
                .get("build")
                .expect("Should extract calls from vec! macro arguments");
            assert!(
                build_calls.iter().any(|c| c.target == "init_value"),
                "Should find init_value() inside vec! macro"
            );
            assert!(
                build_calls.iter().any(|c| c.target == "other"),
                "Should find other() inside vec! macro"
            );
        }

        #[test]
        fn test_macro_println_with_call() {
            let source = r#"
fn display() {
    println!("{}", format_data());
}
"#;
            let calls = extract_calls(source);
            let display_calls = calls
                .get("display")
                .expect("Should extract calls from println! macro arguments");
            assert!(
                display_calls.iter().any(|c| c.target == "format_data"),
                "Should find format_data() inside println! macro"
            );
        }

        #[test]
        fn test_macro_does_not_extract_keywords() {
            // Keywords like if, for, while should NOT be extracted as calls
            let source = r#"
fn check() {
    assert!(if true { valid() } else { false });
}
"#;
            let calls = extract_calls(source);
            if let Some(check_calls) = calls.get("check") {
                assert!(
                    !check_calls.iter().any(|c| c.target == "if"),
                    "Should NOT extract 'if' keyword as a call"
                );
                // valid() might or might not be extracted depending on tree-sitter parsing
                // but 'if' definitely should NOT be
            }
        }

        #[test]
        fn test_macro_with_path_call() {
            let source = r#"
fn configure() {
    assert!(Config::validate());
}
"#;
            let calls = extract_calls(source);
            let cfg_calls = calls
                .get("configure")
                .expect("Should extract path calls from macro arguments");
            assert!(
                cfg_calls.iter().any(|c| c.target == "Config::validate"),
                "Should find Config::validate() inside assert! macro"
            );
        }

        #[test]
        fn test_module_level_macro_call() {
            let source = r#"
lazy_static! {
    static ref INSTANCE: Config = Config::create();
}

fn main() {
    use_instance();
}
"#;
            let calls = extract_calls(source);
            let module_calls = calls.get("<module>");
            // Module-level macro should extract calls with <module> as caller
            if let Some(mc) = module_calls {
                assert!(
                    mc.iter().any(|c| c.target == "Config::create"),
                    "Should find Config::create() inside module-level lazy_static! macro"
                );
            } else {
                panic!("Should extract Config::create() from module-level lazy_static! macro with caller <module>");
            }
        }

        #[test]
        fn test_macro_no_false_positive_on_macro_name() {
            // The macro name itself (e.g., println!) should NOT be extracted as a call
            let source = r#"
fn greet() {
    println!("hello");
}
"#;
            let calls = extract_calls(source);
            // greet might or might not have calls (println has no function call args)
            if let Some(greet_calls) = calls.get("greet") {
                assert!(
                    !greet_calls.iter().any(|c| c.target == "println"),
                    "Should NOT extract the macro name 'println' as a function call"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = RustLangHandler::new();
            assert_eq!(handler.name(), "rust");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = RustLangHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".rs"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = RustLangHandler::new();
            assert!(handler.supports("rust"));
            assert!(handler.supports("Rust"));
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = RustLangHandler::new();
            assert!(handler.supports_extension(".rs"));
            assert!(!handler.supports_extension(".py"));
        }
    }

    // -------------------------------------------------------------------------
    // Trait Default Method Indexing Tests (issue #23)
    //
    // These tests cover the FuncDef shape emitted by `extract_definitions`
    // for methods defined inside `trait_item` declaration blocks.
    //
    // Pre-fix bug: trait default methods were emitted as `FuncDef::function(name)`,
    // colliding with free `fn name()` under the bare-name index key
    // `(module, name)` in `FuncIndex` (see `builder_v2.rs:148-182`).
    //
    // Post-fix invariants:
    // 1. Default methods (with body) emit `FuncDef::method(name, trait_name, ...)`
    //    so `is_method == true` and `class_name == Some(trait_name)`.
    // 2. Abstract trait method signatures (no body) are NOT emitted at all,
    //    because they are not callable definitions.
    // 3. The combination of FuncDef::method + builder_v2 indexing yields BOTH a
    //    bare-name key `(module, "greet")` AND a qualified-name key
    //    `(module, "Greeter.greet")` in the resulting FuncIndex (parity with
    //    the existing `impl_item` path).
    // -------------------------------------------------------------------------
    mod trait_default_method_extraction_tests {
        use super::*;

        fn extract_defs(source: &str) -> (Vec<FuncDef>, Vec<ClassDef>) {
            let handler = RustLangHandler::new();
            let tree = handler.parse_source(source).unwrap();
            handler
                .extract_definitions(source, Path::new("test.rs"), &tree)
                .unwrap()
        }

        #[test]
        fn test_trait_default_methods_indexed_as_functions() {
            // GIVEN: A trait with a default method body
            let source = r#"
trait Greeter {
    fn greet(&self) -> &'static str {
        "hi"
    }
}
"#;

            // WHEN: We extract definitions
            let (funcs, _classes) = extract_defs(source);

            // THEN: The default method must be present and emitted as a
            // FuncDef::method (is_method=true, class_name=Some("Greeter")),
            // NOT as a bare FuncDef::function.
            let greet = funcs
                .iter()
                .find(|f| f.name == "greet")
                .expect("Trait default method 'greet' should be in funcs");
            assert!(
                greet.is_method,
                "Trait default method should have is_method=true, got: {:?}",
                greet
            );
            assert_eq!(
                greet.class_name.as_deref(),
                Some("Greeter"),
                "Trait default method should carry trait_name in class_name, got: {:?}",
                greet.class_name
            );
        }

        #[test]
        fn test_trait_abstract_method_signatures_not_indexed_as_callables() {
            // GIVEN: A trait with both an abstract signature (no body) and a
            //        default method (with body)
            let source = r#"
trait Greeter {
    fn greet(&self) -> &'static str;
    fn shout(&self) -> &'static str {
        "HI"
    }
}
"#;

            // WHEN: We extract definitions
            let (funcs, _classes) = extract_defs(source);

            // THEN: Only `shout` (default method with body) should be emitted.
            //       `greet` (abstract signature) must NOT be emitted, because
            //       it has no body and is not a callable definition.
            assert!(
                funcs.iter().any(|f| f.name == "shout"),
                "Default method 'shout' should be emitted, got: {:?}",
                funcs.iter().map(|f| &f.name).collect::<Vec<_>>()
            );
            assert!(
                !funcs.iter().any(|f| f.name == "greet"),
                "Abstract signature 'greet' must NOT be emitted as a callable, got: {:?}",
                funcs.iter().map(|f| &f.name).collect::<Vec<_>>()
            );
        }

        #[test]
        fn test_func_index_no_overwrite_between_trait_method_and_free_fn() {
            // GIVEN: A free function `greet` AND a trait `Greeter` with a default
            //        method also called `greet`. Pre-fix, both would be inserted
            //        into FuncIndex under the bare key (module, "greet") and the
            //        last writer would clobber the first.
            let source = r#"
fn greet() -> &'static str {
    "free"
}

trait Greeter {
    fn greet(&self) -> &'static str {
        "trait"
    }
}
"#;

            // WHEN: We extract definitions
            let (funcs, _classes) = extract_defs(source);

            // THEN: Two distinct FuncDef entries with the name "greet" must exist:
            //   - one is_method=false (the free fn)
            //   - one is_method=true with class_name=Some("Greeter")
            //
            // builder_v2.rs:158 inserts (module, "greet") and lines 169-181 insert
            // (module, "Greeter.greet") -- so the qualified key disambiguates and
            // the trait-default form is reachable via Greeter.greet even when the
            // bare key resolves to whichever is inserted last.
            //
            // The patch shape mandate (V-bundle augmentation #1) is that the
            // trait method MUST be emitted as FuncDef::method so the qualified
            // key is generated; otherwise (FuncDef::function) the qualified key
            // never exists and the collision is irrecoverable.
            let greet_entries: Vec<&FuncDef> =
                funcs.iter().filter(|f| f.name == "greet").collect();
            assert_eq!(
                greet_entries.len(),
                2,
                "Expected 2 FuncDefs named 'greet' (free fn + trait default), got {}: {:?}",
                greet_entries.len(),
                greet_entries
            );

            let free_fn_count = greet_entries.iter().filter(|f| !f.is_method).count();
            let trait_method_count = greet_entries
                .iter()
                .filter(|f| f.is_method && f.class_name.as_deref() == Some("Greeter"))
                .count();

            assert_eq!(
                free_fn_count, 1,
                "Expected exactly 1 free fn 'greet' (is_method=false), got {}: {:?}",
                free_fn_count, greet_entries
            );
            assert_eq!(
                trait_method_count, 1,
                "Expected exactly 1 trait default method 'greet' (is_method=true, class_name=Some(\"Greeter\")), got {}: {:?}",
                trait_method_count, greet_entries
            );
        }
    }

    // -------------------------------------------------------------------------
    // Impl Owner Keying Tests (FEATURE-1 stage d.1)
    //
    // An impl method must key under the IMPLEMENTING type, read from the
    // `impl_item` `type` field, in EVERY impl shape. The pre-fix code
    // flat-scanned children for the first `type_identifier`, so for
    // `impl Trait for Type` the *trait* name came first and the method was
    // mis-filed under the trait. That merged distinct types' same-named
    // methods into one node and broke receiver-type resolution.
    // -------------------------------------------------------------------------
    mod impl_owner_keying_tests {
        use super::*;

        fn extract_defs(source: &str) -> (Vec<FuncDef>, Vec<ClassDef>) {
            let handler = RustLangHandler::new();
            let tree = handler.parse_source(source).unwrap();
            handler
                .extract_definitions(source, Path::new("test.rs"), &tree)
                .unwrap()
        }

        /// Owner of `m` for a given impl shape, asserting exactly one method
        /// FuncDef named `m` is emitted.
        fn method_owner(source: &str) -> Option<String> {
            let (funcs, _) = extract_defs(source);
            let methods: Vec<&FuncDef> =
                funcs.iter().filter(|f| f.name == "m" && f.is_method).collect();
            assert_eq!(
                methods.len(),
                1,
                "expected exactly one method FuncDef named 'm', got {:?}",
                funcs.iter().map(|f| (&f.name, f.is_method, &f.class_name)).collect::<Vec<_>>()
            );
            methods[0].class_name.clone()
        }

        // (a) Every impl SHAPE keys the method under the implementing Type,
        //     never under the trait.
        #[test]
        fn test_plain_impl_keys_under_type() {
            assert_eq!(
                method_owner("struct Foo; impl Foo { fn m(&self) {} }").as_deref(),
                Some("Foo"),
                "`impl Foo` must key m under Foo"
            );
        }

        #[test]
        fn test_impl_trait_for_type_keys_under_type_not_trait() {
            // The trait name (`Tr`) precedes the type (`Foo`) in source order;
            // the method MUST still key under Foo.
            assert_eq!(
                method_owner("struct Foo; trait Tr {} impl Tr for Foo { fn m(&self) {} }")
                    .as_deref(),
                Some("Foo"),
                "`impl Tr for Foo` must key m under Foo, NOT the trait Tr"
            );
        }

        #[test]
        fn test_generic_impl_trait_for_type_keys_under_bare_type() {
            // `impl<T> Tr for Foo<T>` -> bare type identifier `Foo`.
            assert_eq!(
                method_owner(
                    "struct Foo<T>(T); trait Tr {} impl<T> Tr for Foo<T> { fn m(&self) {} }"
                )
                .as_deref(),
                Some("Foo"),
                "generic `impl<T> Tr for Foo<T>` must key m under bare Foo, NOT Tr"
            );
        }

        #[test]
        fn test_reference_and_where_clause_impls_key_under_type() {
            // reference receiver type
            assert_eq!(
                method_owner("struct Foo; trait Tr {} impl Tr for &Foo { fn m(&self) {} }")
                    .as_deref(),
                Some("Foo"),
                "`impl Tr for &Foo` must key m under Foo"
            );
            // where-clause variant
            assert_eq!(
                method_owner(
                    "struct Foo; trait Tr {} impl<T> Tr for Foo where T: Clone { fn m(&self) {} }"
                )
                .as_deref(),
                Some("Foo"),
                "`impl<T> Tr for Foo where ...` must key m under Foo"
            );
        }

        // (b) Two structs implementing the SAME trait must produce DISTINCT
        //     call-graph nodes (the un-merge), not one merged trait node.
        #[test]
        fn test_same_trait_two_structs_unmerge() {
            let source = r#"
fn a_helper() {}
fn b_helper() {}
trait Runner { fn run(&self); }
struct A;
struct B;
impl Runner for A { fn run(&self) { a_helper(); } }
impl Runner for B { fn run(&self) { b_helper(); } }
"#;
            // DEF side: `run` keyed under both A and B, never merged under Runner.
            let (funcs, _) = extract_defs(source);
            let run_owners: Vec<Option<String>> = funcs
                .iter()
                .filter(|f| f.name == "run" && f.is_method)
                .map(|f| f.class_name.clone())
                .collect();
            assert!(
                run_owners.contains(&Some("A".to_string())),
                "run must be keyed under A, got {run_owners:?}"
            );
            assert!(
                run_owners.contains(&Some("B".to_string())),
                "run must be keyed under B, got {run_owners:?}"
            );
            assert!(
                !run_owners.contains(&Some("Runner".to_string())),
                "run must NOT be keyed under the trait Runner (the merge bug), got {run_owners:?}"
            );

            // CALL side: distinct callers A::run -> a_helper, B::run -> b_helper.
            let calls = extract_calls(source);
            assert!(
                calls
                    .get("A::run")
                    .is_some_and(|cs| cs.iter().any(|c| c.target == "a_helper")),
                "A::run must call a_helper; got callers {:?}",
                calls.keys().collect::<Vec<_>>()
            );
            assert!(
                calls
                    .get("B::run")
                    .is_some_and(|cs| cs.iter().any(|c| c.target == "b_helper")),
                "B::run must call b_helper; got callers {:?}",
                calls.keys().collect::<Vec<_>>()
            );
        }

        // (c) `let p = JsonParser::new(); p.parse()` precondition: the concrete
        //     `parse` method must key under JsonParser (the implementing type),
        //     so the JsonParser.parse node exists for receiver-type resolution,
        //     and the call site is recorded.
        #[test]
        fn test_concrete_parse_keyed_under_struct_for_resolution() {
            let source = r#"
pub trait Parser { fn parse(&self) -> i32; }
pub struct JsonParser;
impl JsonParser {
    pub fn new() -> Self { JsonParser }
}
impl Parser for JsonParser {
    fn parse(&self) -> i32 { 0 }
}
fn run() {
    let p = JsonParser::new();
    p.parse();
}
"#;
            let (funcs, _) = extract_defs(source);
            // The concrete `parse` (impl Parser for JsonParser) must key under
            // JsonParser, NOT the Parser trait. The abstract trait signature has
            // no body and is not emitted, so this is the only `parse` method.
            let parse = funcs
                .iter()
                .find(|f| f.name == "parse" && f.is_method)
                .expect("concrete parse method should be emitted");
            assert_eq!(
                parse.class_name.as_deref(),
                Some("JsonParser"),
                "concrete parse must key under JsonParser, not the Parser trait"
            );

            // The call site `p.parse()` is recorded under `run` (receiver `p`,
            // method `parse`), so receiver-type resolution has an edge to attach
            // to JsonParser.parse.
            let calls = extract_calls(source);
            let run_calls = calls.get("run").expect("run should have recorded calls");
            assert!(
                run_calls.iter().any(|c| {
                    c.receiver.as_deref() == Some("p")
                        && c.target.rsplit(['.', ':']).next() == Some("parse")
                }),
                "run must record the p.parse() method call; got {run_calls:?}"
            );
        }
    }
}
