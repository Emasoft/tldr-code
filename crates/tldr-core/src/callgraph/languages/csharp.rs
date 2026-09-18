//! C# language handler for call graph analysis.
//!
//! This module provides C#-specific call graph support using tree-sitter-c-sharp.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `using System;` | `{module: "System"}` |
//! | `using System.IO;` | `{module: "System.IO"}` |
//! | `using static System.Math;` | `{module: "System.Math", is_static: true}` |
//! | `using Alias = System.Collections;` | `{module: "System.Collections", alias: "Alias"}` |
//! | `global using System;` | `{module: "System", is_namespace: true}` |
//!
//! # Call Extraction
//!
//! - Direct calls: `Method()` -> CallType::Direct or CallType::Intra
//! - Method calls: `obj.Method()` -> CallType::Attr
//! - Static calls: `Type.StaticMethod()` -> CallType::Attr
//! - Constructor calls: `new Class()` -> CallType::Direct
//!
//! # Inherited Calls (issue #87)
//!
//! A bare call (`Run()`) inside a class that declares base types is
//! classified as `CallType::Intra` even when the method is not defined in
//! the current file: the builder resolves such calls through the base-class
//! chain (`resolve_method_in_bases` BFS over `ClassIndex`), which spans
//! files. Base types are extracted from `base_list` for `identifier`,
//! `generic_name` (`Base<T>` -> `Base`) and `qualified_name` (`NS.Base`)
//! nodes, mirroring `crate::inheritance::csharp`.
//!
//! Base classes that live outside the analyzed project (framework types
//! such as `ControllerBase`) stay unresolved: the BFS finds nothing in the
//! `ClassIndex` and the generic resolver runs — no edge is fabricated for
//! external bases.
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.14 for C#-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::common::{extend_calls_if_any, insert_calls_if_any};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// C# Handler
// =============================================================================

/// C# language handler using tree-sitter-c-sharp.
///
/// Supports:
/// - Using directive parsing (standard, static, global, aliased)
/// - Call extraction (direct, method, constructor, static)
/// - Class, interface, and struct method tracking
/// - Namespace support
#[derive(Debug, Default)]
pub struct CsharpHandler;

/// Context for processing C# property accessor calls.
struct PropertyAccessorContext<'a> {
    source: &'a [u8],
    defined_methods: &'a HashSet<String>,
    defined_classes: &'a HashSet<String>,
    calls_by_func: &'a mut HashMap<String, Vec<CallSite>>,
    class: &'a str,
    prop_name: Option<&'a str>,
    /// Base types declared by `class` (issue #87: bare calls inside
    /// accessors can target inherited members too).
    enclosing_bases: Option<&'a [String]>,
}

impl CsharpHandler {
    /// Creates a new CsharpHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set C# language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Parse a using directive node.
    fn parse_using_node(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        if node.kind() != "using_directive" {
            return None;
        }

        let text = get_node_text(node, source);
        let is_static = text.contains("static ");
        let is_global = text.starts_with("global ");

        // Find the qualified name or identifier for the import path
        let mut module: Option<String> = None;
        let mut alias: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "qualified_name" => {
                        module = Some(get_node_text(&child, source).to_string());
                    }
                    "identifier" => {
                        // Could be a simple namespace or an alias.
                        // why: tree-sitter-c-sharp 0.23.1 has no "name_equals"
                        // node -- the alias identifier is a plain "identifier"
                        // child directly followed by the "=" token, detected
                        // via the sibling check below.
                        // Check if next sibling is "=" for alias detection
                        let mut is_alias = false;
                        if i + 1 < node.child_count() {
                            if let Some(next) = node.child(i + 1) {
                                if next.kind() == "=" {
                                    is_alias = true;
                                }
                            }
                        }
                        if is_alias {
                            alias = Some(get_node_text(&child, source).to_string());
                        } else if module.is_none() {
                            module = Some(get_node_text(&child, source).to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        let module = module?;

        let mut import_def = ImportDef::simple_import(module);

        if is_static {
            // Mark as static import using is_type_checking field (same hack as Java)
            import_def.is_type_checking = true;
        }

        if is_global {
            import_def.is_namespace = true;
        }

        if let Some(a) = alias {
            import_def.alias = Some(a);
        }

        Some(import_def)
    }

    /// Collect all class, interface, struct, and method definitions.
    ///
    /// Returns `(methods, classes, class_bases)` where `class_bases` maps
    /// each declared type name to the base types named in its `base_list`
    /// (issue #87: needed to classify bare calls inside a type that can
    /// inherit members).
    fn collect_definitions(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> (
        HashSet<String>,
        HashSet<String>,
        HashMap<String, Vec<String>>,
    ) {
        let mut methods = HashSet::new();
        let mut classes = HashSet::new();
        let mut class_bases: HashMap<String, Vec<String>> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "method_declaration" => {
                    if let Some(name) = self.get_identifier_from_node(&node, source) {
                        methods.insert(name);
                    }
                }
                "constructor_declaration" => {
                    if let Some(name) = self.get_identifier_from_node(&node, source) {
                        methods.insert(name.clone());
                        classes.insert(name);
                    }
                }
                "class_declaration" | "interface_declaration" | "struct_declaration" => {
                    if let Some(name) = self.get_identifier_from_node(&node, source) {
                        classes.insert(name.clone());
                        class_bases.insert(name, Self::extract_base_types(&node, source));
                    }
                }
                _ => {}
            }
        }

        (methods, classes, class_bases)
    }

    /// Extract base type names from the `base_list` child of a type
    /// declaration.
    ///
    /// Handles `identifier` (simple name), `generic_name` (e.g.
    /// `RepositoryBase<User>` -> `RepositoryBase`) and `qualified_name`
    /// (e.g. `NS.Base`) nodes — the complete extraction previously found
    /// only in `crate::inheritance::csharp`. The callgraph parser used to
    /// collect `identifier` bases only, which silently dropped generic and
    /// namespace-qualified bases and broke cross-file base-chain
    /// resolution for subclasses of such types (issue #87).
    fn extract_base_types(node: &Node, source: &[u8]) -> Vec<String> {
        let mut bases = Vec::new();

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() != "base_list" {
                continue;
            }
            for j in 0..child.child_count() {
                let Some(base) = child.child(j) else {
                    continue;
                };
                match base.kind() {
                    "identifier" => bases.push(get_node_text(&base, source).to_string()),
                    "generic_name" => {
                        if let Some(name) = Self::generic_type_name(&base, source) {
                            bases.push(name);
                        }
                    }
                    "qualified_name" => {
                        bases.push(get_node_text(&base, source).to_string());
                    }
                    _ => {}
                }
            }
        }

        bases
    }

    /// Get the base type name from a `generic_name` node
    /// (`RepositoryBase<User>` -> `RepositoryBase`).
    fn generic_type_name(node: &Node, source: &[u8]) -> Option<String> {
        if let Some(name) = node.child_by_field_name("name") {
            return Some(get_node_text(&name, source).to_string());
        }
        // Fallback: first identifier child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Get the identifier (name) from a declaration node.
    ///
    /// For C# method declarations, we need to find the method name identifier,
    /// which comes after the return type. Tree-sitter-c-sharp uses field names
    /// to distinguish between type and name identifiers.
    fn get_identifier_from_node(&self, node: &Node, source: &[u8]) -> Option<String> {
        // First, try to get the "name" field (works for method_declaration)
        if let Some(name_node) = node.child_by_field_name("name") {
            return Some(get_node_text(&name_node, source).to_string());
        }

        // For method declarations, the name is the second identifier
        // (first is return type)
        if node.kind() == "method_declaration" {
            let mut found_first = false;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        if found_first {
                            // Second identifier is the method name
                            return Some(get_node_text(&child, source).to_string());
                        }
                        found_first = true;
                    }
                }
            }
        }

        // Fallback: for classes, interfaces, structs, find the last identifier
        // before any parameter list or body
        let mut last_identifier: Option<String> = None;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        last_identifier = Some(get_node_text(&child, source).to_string());
                    }
                    // Stop when we hit parameter list or body
                    "parameter_list"
                    | "block"
                    | "declaration_list"
                    | "type_parameter_list"
                    | "base_list" => {
                        break;
                    }
                    _ => {}
                }
            }
        }
        last_identifier
    }

    /// Extract calls from a method/constructor body.
    ///
    /// `enclosing_bases` carries the base types declared by the class (or
    /// struct/interface) enclosing the call site, when the call site is
    /// inside one. A bare call to a method not defined in this file may
    /// still target an inherited member, so it is classified `Intra` (not
    /// `Direct`) whenever the enclosing type declares any base — the
    /// builder's `resolve_intra_call` then resolves it via
    /// `resolve_method_in_bases` across files, falling back to the generic
    /// resolver when the chain misses (issue #87).
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        caller: &str,
        enclosing_bases: Option<&[String]>,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        for child in walk_tree(*node) {
            match child.kind() {
                "invocation_expression" => {
                    let line = child.start_position().row as u32 + 1;

                    // Parse invocation: obj.Method() or Method()
                    let mut func_part: Option<Node> = None;
                    for i in 0..child.child_count() {
                        if let Some(c) = child.child(i) {
                            if c.kind() == "argument_list" {
                                break;
                            }
                            func_part = Some(c);
                        }
                    }

                    if let Some(func_node) = func_part {
                        match func_node.kind() {
                            "member_access_expression" => {
                                // obj.Method() or Class.StaticMethod()
                                let target = get_node_text(&func_node, source).to_string();

                                // Extract receiver (everything before the last dot)
                                let receiver = if target.contains('.') {
                                    Some(
                                        target
                                            .rsplit_once('.')
                                            .map(|(r, _)| r.to_string())
                                            .unwrap_or_default(),
                                    )
                                } else {
                                    None
                                };

                                calls.push(CallSite::new(
                                    caller.to_string(),
                                    target,
                                    CallType::Attr,
                                    Some(line),
                                    None,
                                    receiver,
                                    None,
                                ));
                            }
                            "identifier" => {
                                // Simple call: Method()
                                let method_name = get_node_text(&func_node, source).to_string();
                                let call_type = if defined_methods.contains(&method_name)
                                    || enclosing_bases.is_some_and(|bases| !bases.is_empty())
                                {
                                    CallType::Intra
                                } else {
                                    CallType::Direct
                                };
                                calls.push(CallSite::new(
                                    caller.to_string(),
                                    method_name,
                                    call_type,
                                    Some(line),
                                    None,
                                    None,
                                    None,
                                ));
                            }
                            "generic_name" => {
                                // Generic method call: Method<T>()
                                if let Some(name) =
                                    self.get_identifier_from_node(&func_node, source)
                                {
                                    let call_type = if defined_methods.contains(&name)
                                        || enclosing_bases.is_some_and(|bases| !bases.is_empty())
                                    {
                                        CallType::Intra
                                    } else {
                                        CallType::Direct
                                    };
                                    calls.push(CallSite::new(
                                        caller.to_string(),
                                        name,
                                        call_type,
                                        Some(line),
                                        None,
                                        None,
                                        None,
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "object_creation_expression" => {
                    // new ClassName()
                    let line = child.start_position().row as u32 + 1;

                    for i in 0..child.child_count() {
                        if let Some(c) = child.child(i) {
                            match c.kind() {
                                // C# uses "identifier" or "type_identifier" for the class name
                                "identifier" | "type_identifier" => {
                                    let class_name = get_node_text(&c, source).to_string();
                                    let call_type = if defined_classes.contains(&class_name) {
                                        CallType::Intra
                                    } else {
                                        CallType::Direct
                                    };
                                    calls.push(CallSite::new(
                                        caller.to_string(),
                                        class_name,
                                        call_type,
                                        Some(line),
                                        None,
                                        None,
                                        None,
                                    ));
                                    break;
                                }
                                "qualified_name" => {
                                    // Fully qualified: new Namespace.ClassName()
                                    let target = get_node_text(&c, source).to_string();
                                    calls.push(CallSite::new(
                                        caller.to_string(),
                                        target,
                                        CallType::Attr,
                                        Some(line),
                                        None,
                                        None,
                                        None,
                                    ));
                                    break;
                                }
                                "generic_name" => {
                                    // Generic: new List<T>()
                                    if let Some(name) = self.get_identifier_from_node(&c, source) {
                                        let call_type = if defined_classes.contains(&name) {
                                            CallType::Intra
                                        } else {
                                            CallType::Direct
                                        };
                                        calls.push(CallSite::new(
                                            caller.to_string(),
                                            name,
                                            call_type,
                                            Some(line),
                                            None,
                                            None,
                                            None,
                                        ));
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        calls
    }

    fn recurse_children_for_call_extraction(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &mut Option<String>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.process_extract_calls_node(
                    child,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
        }
    }

    fn process_extract_calls_node(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &mut Option<String>,
    ) {
        match node.kind() {
            "class_declaration" | "interface_declaration" | "struct_declaration" => {
                self.handle_type_declaration_calls(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
            "method_declaration" | "constructor_declaration" => {
                self.handle_method_or_constructor_calls(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
            "field_declaration" => {
                self.handle_field_declaration_calls(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
            "property_declaration" => {
                self.handle_property_declaration_calls(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
            "global_statement" => {
                self.handle_global_statement_calls(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    calls_by_func,
                );
            }
            _ => {
                self.recurse_children_for_call_extraction(
                    node,
                    source,
                    defined_methods,
                    defined_classes,
                    class_bases,
                    calls_by_func,
                    current_class,
                );
            }
        }
    }

    fn handle_type_declaration_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &mut Option<String>,
    ) {
        let mut class_name: Option<String> = None;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    class_name = Some(get_node_text(&child, source).to_string());
                    break;
                }
            }
        }

        let old_class = current_class.take();
        *current_class = class_name;
        self.recurse_children_for_call_extraction(
            node,
            source,
            defined_methods,
            defined_classes,
            class_bases,
            calls_by_func,
            current_class,
        );
        *current_class = old_class;
    }

    fn handle_method_or_constructor_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &Option<String>,
    ) {
        let mut body: Option<Node> = None;
        let mut arrow: Option<Node> = None;
        let mut constructor_init: Option<Node> = None;
        let mut identifiers: Vec<String> = Vec::new();
        let mut is_static = false;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => identifiers.push(get_node_text(&child, source).to_string()),
                    "modifier" => {
                        if get_node_text(&child, source) == "static" {
                            is_static = true;
                        }
                    }
                    "block" => body = Some(child),
                    "arrow_expression_clause" => arrow = Some(child),
                    "constructor_initializer" => constructor_init = Some(child),
                    _ => {}
                }
            }
        }

        let method_name = if node.kind() == "constructor_declaration" {
            identifiers.first().cloned()
        } else if identifiers.len() >= 2 {
            identifiers.get(1).cloned()
        } else {
            identifiers.first().cloned()
        };
        let Some(name) = method_name else {
            return;
        };

        let full_name = if node.kind() == "constructor_declaration" && is_static {
            if let Some(class) = current_class {
                format!("{class}.<clinit>")
            } else {
                "<clinit>".to_string()
            }
        } else if node.kind() == "constructor_declaration" {
            if let Some(class) = current_class {
                format!("{class}.<init>")
            } else {
                name.clone()
            }
        } else if let Some(class) = current_class {
            format!("{class}.{name}")
        } else {
            name.clone()
        };

        let mut all_calls = Vec::new();
        // issue #87: bare calls in a method of a class that declares bases may
        // target inherited members -- pass the bases down for Intra
        // classification.
        let enclosing_bases = current_class
            .as_deref()
            .and_then(|c| class_bases.get(c))
            .map(|b| b.as_slice());
        if let Some(body_node) = body {
            all_calls.extend(self.extract_calls_from_node(
                &body_node,
                source,
                defined_methods,
                defined_classes,
                &full_name,
                enclosing_bases,
            ));
        }
        if let Some(arrow_node) = arrow {
            all_calls.extend(self.extract_calls_from_node(
                &arrow_node,
                source,
                defined_methods,
                defined_classes,
                &full_name,
                enclosing_bases,
            ));
        }
        if let Some(init_node) = constructor_init {
            all_calls.extend(self.extract_calls_from_node(
                &init_node,
                source,
                defined_methods,
                defined_classes,
                &full_name,
                enclosing_bases,
            ));
        }

        if all_calls.is_empty() {
            return;
        }

        extend_calls_if_any(calls_by_func, full_name.clone(), all_calls.clone());
        if !full_name.contains("<init>") && !full_name.contains("<clinit>") {
            insert_calls_if_any(calls_by_func, name, all_calls);
        }
    }

    fn handle_field_declaration_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &Option<String>,
    ) {
        let Some(class) = current_class.as_deref() else {
            return;
        };

        let is_static = (0..node.child_count()).any(|i| {
            node.child(i).is_some_and(|child| {
                child.kind() == "modifier" && get_node_text(&child, source) == "static"
            })
        });
        let caller = if is_static {
            format!("{class}.<clinit>")
        } else {
            format!("{class}.<init>")
        };
        let enclosing_bases = class_bases.get(class).map(|b| b.as_slice());
        let calls = self.extract_calls_from_node(
            &node,
            source,
            defined_methods,
            defined_classes,
            &caller,
            enclosing_bases,
        );
        extend_calls_if_any(calls_by_func, caller, calls);
    }

    fn handle_property_declaration_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        class_bases: &HashMap<String, Vec<String>>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        current_class: &Option<String>,
    ) {
        let Some(class) = current_class.as_deref() else {
            return;
        };
        let enclosing_bases = class_bases.get(class).map(|b| b.as_slice());
        let prop_name = node
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source).to_string());
        // why: a static auto-property initializer runs in the type initializer
        // (<clinit>), not the instance constructor (<init>) -- mirrors the
        // is_static handling already done for field_declaration below.
        let is_static = (0..node.child_count()).any(|i| {
            node.child(i).is_some_and(|child| {
                child.kind() == "modifier" && get_node_text(&child, source) == "static"
            })
        });

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            match child.kind() {
                "accessor_list" => {
                    let mut context = PropertyAccessorContext {
                        source,
                        defined_methods,
                        defined_classes,
                        calls_by_func,
                        class,
                        prop_name: prop_name.as_deref(),
                        enclosing_bases,
                    };
                    self.handle_property_accessor_list_calls(child, &mut context);
                }
                "arrow_expression_clause" => {
                    let caller = if let Some(name) = prop_name.as_deref() {
                        format!("{class}.get_{name}")
                    } else {
                        format!("{class}.get")
                    };
                    let calls = self.extract_calls_from_node(
                        &child,
                        source,
                        defined_methods,
                        defined_classes,
                        &caller,
                        enclosing_bases,
                    );
                    extend_calls_if_any(calls_by_func, caller, calls);
                }
                "equals_value_clause" | "invocation_expression" | "object_creation_expression" => {
                    let caller = if is_static {
                        format!("{class}.<clinit>")
                    } else {
                        format!("{class}.<init>")
                    };
                    let calls = self.extract_calls_from_node(
                        &child,
                        source,
                        defined_methods,
                        defined_classes,
                        &caller,
                        enclosing_bases,
                    );
                    extend_calls_if_any(calls_by_func, caller, calls);
                }
                _ => {}
            }
        }
    }

    fn handle_property_accessor_list_calls(
        &self,
        accessor_list: Node,
        context: &mut PropertyAccessorContext<'_>,
    ) {
        for i in 0..accessor_list.child_count() {
            let Some(accessor) = accessor_list.child(i) else {
                continue;
            };
            if accessor.kind() != "accessor_declaration" {
                continue;
            }

            // why: the "name" field (get/set/init/add/remove) is not always
            // child(0) -- a modifier like `private set` or an attribute list
            // can precede it, which previously produced callers such as
            // "Class.private_Value" instead of "Class.set_Value".
            let accessor_type = accessor
                .child_by_field_name("name")
                .map(|c| get_node_text(&c, context.source).to_string())
                .unwrap_or_default();
            let caller = if let Some(name) = context.prop_name {
                format!("{}.{accessor_type}_{name}", context.class)
            } else {
                format!("{}.{accessor_type}", context.class)
            };

            for j in 0..accessor.child_count() {
                let Some(acc_child) = accessor.child(j) else {
                    continue;
                };
                if acc_child.kind() != "block" && acc_child.kind() != "arrow_expression_clause" {
                    continue;
                }

                let calls = self.extract_calls_from_node(
                    &acc_child,
                    context.source,
                    context.defined_methods,
                    context.defined_classes,
                    &caller,
                    context.enclosing_bases,
                );
                extend_calls_if_any(context.calls_by_func, caller.clone(), calls);
            }
        }
    }

    fn handle_global_statement_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
    ) {
        let caller = "<top-level>".to_string();
        // Top-level statements have no enclosing class, so no bases: bare
        // calls keep the historical Direct classification.
        let calls = self.extract_calls_from_node(
            &node,
            source,
            defined_methods,
            defined_classes,
            &caller,
            None,
        );
        extend_calls_if_any(calls_by_func, caller, calls);
    }
}

impl CallGraphLanguageSupport for CsharpHandler {
    fn name(&self) -> &str {
        "csharp"
    }

    fn extensions(&self) -> &[&str] {
        &[".cs"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            if node.kind() == "using_directive" {
                if let Some(imp) = self.parse_using_node(&node, source_bytes) {
                    imports.push(imp);
                }
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
        let (defined_methods, defined_classes, class_bases) =
            self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();
        let mut current_class: Option<String> = None;
        self.process_extract_calls_node(
            tree.root_node(),
            source_bytes,
            &defined_methods,
            &defined_classes,
            &class_bases,
            &mut calls_by_func,
            &mut current_class,
        );

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
                "method_declaration" | "constructor_declaration" => {
                    if let Some(name) = self.get_identifier_from_node(&node, source_bytes) {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;

                        // Check if inside a class
                        let mut class_name = None;
                        let mut parent = node.parent();
                        while let Some(p) = parent {
                            if p.kind() == "declaration_list" {
                                if let Some(gp) = p.parent() {
                                    if gp.kind() == "class_declaration"
                                        || gp.kind() == "interface_declaration"
                                        || gp.kind() == "struct_declaration"
                                    {
                                        class_name =
                                            self.get_identifier_from_node(&gp, source_bytes);
                                    }
                                }
                                break;
                            }
                            parent = p.parent();
                        }

                        if let Some(cn) = class_name {
                            funcs.push(FuncDef::method(name, cn, line, end_line));
                        } else {
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                "class_declaration" | "interface_declaration" | "struct_declaration" => {
                    if let Some(name) = self.get_identifier_from_node(&node, source_bytes) {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;

                        // Collect method names and base classes. issue #87:
                        // extract_base_types handles identifier, generic_name
                        // and qualified_name base nodes (previously only
                        // identifier was collected, dropping e.g.
                        // `RepositoryBase<User>` and `NS.Base` from the
                        // inheritance graph).
                        let mut methods = Vec::new();
                        let bases = Self::extract_base_types(&node, source_bytes);

                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                if child.kind() == "declaration_list" {
                                    for j in 0..child.named_child_count() {
                                        if let Some(member) = child.named_child(j) {
                                            if member.kind() == "method_declaration"
                                                || member.kind() == "constructor_declaration"
                                            {
                                                if let Some(mn) = self
                                                    .get_identifier_from_node(&member, source_bytes)
                                                {
                                                    methods.push(mn);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        classes.push(ClassDef::new(name, line, end_line, methods, bases));
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
        let handler = CsharpHandler::new();
        handler.parse_imports(source, Path::new("Test.cs")).unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = CsharpHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("Test.cs"), source, &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_simple_using() {
            let imports = parse_imports("using System;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "System");
            assert!(!imports[0].is_type_checking); // is_static marker
        }

        #[test]
        fn test_parse_qualified_using() {
            let imports = parse_imports("using System.IO;");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "System.IO");
        }

        #[test]
        fn test_parse_static_using() {
            let imports = parse_imports("using static System.Math;");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].module.contains("System.Math"));
            assert!(imports[0].is_type_checking); // is_static marker
        }

        #[test]
        fn test_parse_aliased_using() {
            let imports = parse_imports("using Col = System.Collections;");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].module.contains("System.Collections"));
            assert_eq!(imports[0].alias, Some("Col".to_string()));
        }

        #[test]
        fn test_parse_global_using() {
            let imports = parse_imports("global using System;");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].is_namespace); // global marker
        }

        #[test]
        fn test_parse_multiple_usings() {
            let source = r#"
using System;
using System.Collections.Generic;
using System.IO;
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
        fn test_extract_calls_simple() {
            let source = r#"
public class Test {
    public void Main() {
        Console.WriteLine("hello");
        Helper();
    }
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("Main").or(calls.get("Test.Main")).unwrap();
            assert!(main_calls.iter().any(|c| c.target.contains("WriteLine")));
            assert!(main_calls.iter().any(|c| c.target == "Helper"));
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
public class Calculator {
    public int Add(int a, int b) {
        return a + b;
    }

    public int Calculate() {
        return Add(1, 2);
    }
}
"#;
            let calls = extract_calls(source);
            let calc_calls = calls.get("Calculator.Calculate");
            assert!(
                calc_calls.is_some(),
                "Expected calls from Calculator.Calculate, got keys: {:?}",
                calls.keys().collect::<Vec<_>>()
            );
            let calc_calls = calc_calls.unwrap();
            let add_call = calc_calls.iter().find(|c| c.target == "Add").unwrap();
            assert_eq!(add_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_method_to_toplevel() {
            // In C#, "top-level" functions are typically static methods in another class
            // or in a static utility class in the same file
            let source = r#"
public class Service {
    public void Process() {
        Helper();
    }
}

public static class Utils {
    public static void Helper() {}
}
"#;
            let calls = extract_calls(source);
            // Should have calls from Service.Process (qualified name)
            let process_calls = calls.get("Service.Process");
            assert!(
                process_calls.is_some(),
                "Expected calls from Service.Process, got keys: {:?}",
                calls.keys().collect::<Vec<_>>()
            );
            let process_calls = process_calls.unwrap();
            // Should call Helper() - in C# this is Utils.Helper()
            let helper_call = process_calls.iter().find(|c| c.target.contains("Helper"));
            assert!(
                helper_call.is_some(),
                "Expected call to Helper from Service.Process, got: {:?}",
                process_calls.iter().map(|c| &c.target).collect::<Vec<_>>()
            );
            assert_eq!(helper_call.unwrap().caller, "Service.Process");
        }

        #[test]
        fn test_extract_calls_constructor() {
            let source = r#"
public class Factory {
    public User CreateUser() {
        return new User();
    }
}
"#;
            let calls = extract_calls(source);
            let create_calls = calls
                .get("CreateUser")
                .or(calls.get("Factory.CreateUser"))
                .unwrap();
            assert!(create_calls.iter().any(|c| c.target == "User"));
        }

        #[test]
        fn test_extract_calls_method_on_object() {
            let source = r#"
public class Service {
    private Repository repo;

    public void Process() {
        repo.Save(data);
    }
}
"#;
            let calls = extract_calls(source);
            let process_calls = calls
                .get("Process")
                .or(calls.get("Service.Process"))
                .unwrap();
            assert!(process_calls.iter().any(|c| c.target.contains("Save")));
        }

        #[test]
        fn test_extract_calls_static_method() {
            let source = r#"
public class MathUtils {
    public double Calculate() {
        return Math.Sqrt(16);
    }
}
"#;
            let calls = extract_calls(source);
            let calc_calls = calls
                .get("Calculate")
                .or(calls.get("MathUtils.Calculate"))
                .unwrap();
            assert!(calc_calls.iter().any(|c| c.target.contains("Sqrt")));
        }

        #[test]
        fn test_extract_calls_with_line_numbers() {
            let source = r#"public class Test {
    public void TestMethod() {
        First();
        Second();
    }
}"#;
            let calls = extract_calls(source);
            let test_calls = calls
                .get("TestMethod")
                .or(calls.get("Test.TestMethod"))
                .unwrap();

            let first = test_calls.iter().find(|c| c.target == "First").unwrap();
            let second = test_calls.iter().find(|c| c.target == "Second").unwrap();

            assert!(first.line.is_some());
            assert!(second.line.is_some());
            assert!(second.line.unwrap() > first.line.unwrap());
        }

        #[test]
        fn test_extract_calls_interface() {
            let source = r#"
public interface IService {
    void Process();
}

public class Service : IService {
    public void Process() {
        Helper();
    }

    private void Helper() {
        Console.WriteLine("help");
    }
}
"#;
            let calls = extract_calls(source);
            let process_calls = calls
                .get("Process")
                .or(calls.get("Service.Process"))
                .unwrap();
            let helper_call = process_calls.iter().find(|c| c.target == "Helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_struct() {
            let source = r#"
public struct Point {
    public int X;
    public int Y;

    public double Distance() {
        return Math.Sqrt(X * X + Y * Y);
    }
}
"#;
            let calls = extract_calls(source);
            let dist_calls = calls
                .get("Distance")
                .or(calls.get("Point.Distance"))
                .unwrap();
            assert!(dist_calls.iter().any(|c| c.target.contains("Sqrt")));
        }
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = CsharpHandler::new();
            assert_eq!(handler.name(), "csharp");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = CsharpHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".cs"));
            assert_eq!(exts.len(), 1);
        }

        #[test]
        fn test_handler_supports() {
            let handler = CsharpHandler::new();
            assert!(handler.supports("csharp"));
            assert!(handler.supports("CSharp"));
            assert!(handler.supports("CSHARP"));
            assert!(!handler.supports("java"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = CsharpHandler::new();
            assert!(handler.supports_extension(".cs"));
            assert!(handler.supports_extension(".CS"));
            assert!(!handler.supports_extension(".java"));
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #3: Field Initializers
    // -------------------------------------------------------------------------
    mod field_initializer_tests {
        use super::*;

        #[test]
        fn test_instance_field_initializer() {
            let source = r#"
public class Config {
    private Handler handler = CreateHandler();
    public void Process() {
        handler.Run();
    }
}
"#;
            let calls = extract_calls(source);
            let init_calls = calls
                .get("Config.<init>")
                .expect("Config.<init> should have calls for field initializers");
            assert!(
                init_calls.iter().any(|c| c.target == "CreateHandler"),
                "Config.<init> should contain CreateHandler call, got: {:?}",
                init_calls
            );
        }

        #[test]
        fn test_static_field_initializer() {
            let source = r#"
public class Config {
    private static Logger logger = Logger.Create();
}
"#;
            let calls = extract_calls(source);
            let clinit_calls = calls
                .get("Config.<clinit>")
                .expect("Config.<clinit> should have calls for static field initializers");
            assert!(
                clinit_calls.iter().any(|c| c.target.contains("Create")),
                "Config.<clinit> should contain Logger.Create call, got: {:?}",
                clinit_calls
            );
        }

        #[test]
        fn test_static_readonly_field_initializer() {
            let source = r#"
public class Config {
    static readonly Config instance = new Config();
}
"#;
            let calls = extract_calls(source);
            let clinit_calls = calls
                .get("Config.<clinit>")
                .expect("Config.<clinit> should have calls for static readonly field initializers");
            assert!(
                clinit_calls.iter().any(|c| c.target == "Config"),
                "Config.<clinit> should contain new Config() call, got: {:?}",
                clinit_calls
            );
        }

        #[test]
        fn test_mixed_field_initializers() {
            let source = r#"
public class Multi {
    private Handler a = CreateA();
    private static Handler b = CreateB();
    private Handler c = CreateC();
}
"#;
            let calls = extract_calls(source);

            // Instance fields -> Multi.<init>
            let init_calls = calls
                .get("Multi.<init>")
                .expect("Multi.<init> should have calls");
            assert!(
                init_calls.iter().any(|c| c.target == "CreateA"),
                "should have CreateA: {:?}",
                init_calls
            );
            assert!(
                init_calls.iter().any(|c| c.target == "CreateC"),
                "should have CreateC: {:?}",
                init_calls
            );

            // Static field -> Multi.<clinit>
            let clinit_calls = calls
                .get("Multi.<clinit>")
                .expect("Multi.<clinit> should have calls");
            assert!(
                clinit_calls.iter().any(|c| c.target == "CreateB"),
                "should have CreateB: {:?}",
                clinit_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #4: Static Constructor
    // -------------------------------------------------------------------------
    mod static_constructor_tests {
        use super::*;

        #[test]
        fn test_static_constructor() {
            let source = r#"
public class Registry {
    static Registry() {
        Initialize();
        Logger.Setup();
    }
}
"#;
            let calls = extract_calls(source);
            let clinit_calls = calls
                .get("Registry.<clinit>")
                .expect("Registry.<clinit> should have calls");
            assert!(
                clinit_calls.iter().any(|c| c.target == "Initialize"),
                "should have Initialize: {:?}",
                clinit_calls
            );
            assert!(
                clinit_calls.iter().any(|c| c.target.contains("Setup")),
                "should have Logger.Setup: {:?}",
                clinit_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #11: Base/this Constructor Args
    // -------------------------------------------------------------------------
    mod base_constructor_tests {
        use super::*;

        #[test]
        fn test_base_constructor_args() {
            let source = r#"
public class Child : Base {
    public Child() : base(Compute()) {
        DoWork();
    }
}
"#;
            let calls = extract_calls(source);
            let ctor_calls = calls
                .get("Child.<init>")
                .or(calls.get("Child.Child"))
                .expect("should have constructor calls");
            assert!(
                ctor_calls.iter().any(|c| c.target == "Compute"),
                "should have Compute from base(): {:?}",
                ctor_calls
            );
            assert!(
                ctor_calls.iter().any(|c| c.target == "DoWork"),
                "should have DoWork from body: {:?}",
                ctor_calls
            );
        }

        #[test]
        fn test_this_constructor_args() {
            let source = r#"
public class Config {
    public Config(int x) : this(Transform(x)) {
    }
    public Config(string s) {
        Process(s);
    }
}
"#;
            let calls = extract_calls(source);
            // The constructor with : this() should have Transform call
            let has_transform = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Transform"));
            assert!(
                has_transform,
                "should have Transform from :this(): {:?}",
                calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #13: Property Getter/Setter Bodies
    // -------------------------------------------------------------------------
    mod property_tests {
        use super::*;

        #[test]
        fn test_property_getter_setter() {
            let source = r#"
public class Config {
    public int Value {
        get { return Compute(); }
        set { Validate(value); }
    }
}
"#;
            let calls = extract_calls(source);
            // Property getter -> Config.get_Value or similar
            let has_compute = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Compute"));
            assert!(has_compute, "should have Compute from getter: {:?}", calls);
            let has_validate = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Validate"));
            assert!(
                has_validate,
                "should have Validate from setter: {:?}",
                calls
            );
        }

        #[test]
        fn test_expression_bodied_property() {
            let source = r#"
public class Config {
    public string Name => GetName();
}
"#;
            let calls = extract_calls(source);
            let has_getname = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "GetName"));
            assert!(
                has_getname,
                "should have GetName from expression-bodied property: {:?}",
                calls
            );
        }

        #[test]
        fn test_expression_bodied_method() {
            let source = r#"
public class Math {
    public int Double(int x) => Multiply(x, 2);
}
"#;
            let calls = extract_calls(source);
            let has_multiply = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Multiply"));
            assert!(
                has_multiply,
                "should have Multiply from expression-bodied method: {:?}",
                calls
            );
        }

        #[test]
        fn test_auto_property_initializer() {
            let source = r#"
public class Config {
    public string Name { get; set; } = GetDefault();
}
"#;
            let calls = extract_calls(source);
            let has_getdefault = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "GetDefault"));
            assert!(
                has_getdefault,
                "should have GetDefault from auto-property initializer: {:?}",
                calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #2: Top-Level Statements (C# 9)
    // -------------------------------------------------------------------------
    mod top_level_tests {
        use super::*;

        #[test]
        fn test_top_level_statements() {
            let source = r#"Console.WriteLine("hello");
Process();
var x = Create();
"#;
            let calls = extract_calls(source);
            let has_writeline = calls
                .values()
                .any(|v| v.iter().any(|c| c.target.contains("WriteLine")));
            assert!(
                has_writeline,
                "should have Console.WriteLine from top-level: {:?}",
                calls
            );
            let has_process = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Process"));
            assert!(
                has_process,
                "should have Process from top-level: {:?}",
                calls
            );
            let has_create = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Create"));
            assert!(has_create, "should have Create from top-level: {:?}", calls);
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #15: Lambda/Closure Bodies
    // -------------------------------------------------------------------------
    mod lambda_tests {
        use super::*;

        #[test]
        fn test_lambda_in_method_body() {
            let source = r#"
public class Service {
    public void Setup() {
        Action a = () => DoSomething();
        items.ForEach(x => Process(x));
    }
}
"#;
            let calls = extract_calls(source);
            let setup_calls = calls
                .get("Setup")
                .or(calls.get("Service.Setup"))
                .expect("should have Setup calls");
            assert!(
                setup_calls.iter().any(|c| c.target == "DoSomething"),
                "should have DoSomething from lambda: {:?}",
                setup_calls
            );
            assert!(
                setup_calls.iter().any(|c| c.target == "Process"),
                "should have Process from lambda: {:?}",
                setup_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #22: Static Readonly Initializers
    // -------------------------------------------------------------------------
    mod static_readonly_tests {
        use super::*;

        #[test]
        fn test_static_readonly_with_new() {
            let source = r#"
public class Constants {
    public static readonly HttpClient client = new HttpClient();
    public static readonly string value = ComputeValue();
}
"#;
            let calls = extract_calls(source);
            let clinit = calls
                .get("Constants.<clinit>")
                .expect("Constants.<clinit> should have calls");
            assert!(
                clinit.iter().any(|c| c.target == "HttpClient"),
                "should have HttpClient constructor: {:?}",
                clinit
            );
            assert!(
                clinit.iter().any(|c| c.target == "ComputeValue"),
                "should have ComputeValue: {:?}",
                clinit
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #28: Using Declarations
    // -------------------------------------------------------------------------
    mod using_declaration_tests {
        use super::*;

        #[test]
        fn test_using_var_declaration() {
            // using var is a local_declaration_statement; the calls inside
            // should be extracted in the normal method body walk (invocation_expression).
            // This test verifies that calls inside using statements are captured.
            let source = r#"
public class Service {
    public void Process() {
        using var conn = CreateConnection();
        conn.Execute();
    }
}
"#;
            let calls = extract_calls(source);
            let proc_calls = calls
                .get("Process")
                .or(calls.get("Service.Process"))
                .expect("should have Process calls");
            assert!(
                proc_calls.iter().any(|c| c.target == "CreateConnection"),
                "should have CreateConnection: {:?}",
                proc_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #31: Object Initializer Values
    // -------------------------------------------------------------------------
    mod object_initializer_tests {
        use super::*;

        #[test]
        fn test_object_initializer_calls() {
            let source = r#"
public class Factory {
    public Config Create() {
        return new Config { Timeout = ComputeTimeout(), Name = GetName() };
    }
}
"#;
            let calls = extract_calls(source);
            let create_calls = calls
                .get("Create")
                .or(calls.get("Factory.Create"))
                .expect("should have Create calls");
            assert!(
                create_calls.iter().any(|c| c.target == "ComputeTimeout"),
                "should have ComputeTimeout from object initializer: {:?}",
                create_calls
            );
            assert!(
                create_calls.iter().any(|c| c.target == "GetName"),
                "should have GetName from object initializer: {:?}",
                create_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #24: String Interpolation
    // -------------------------------------------------------------------------
    mod interpolation_tests {
        use super::*;

        #[test]
        fn test_string_interpolation_calls() {
            let source = r#"
public class Service {
    public void Log() {
        var s = $"Hello {GetName()} world {ComputeValue()}";
    }
}
"#;
            let calls = extract_calls(source);
            let log_calls = calls
                .get("Log")
                .or(calls.get("Service.Log"))
                .expect("should have Log calls");
            assert!(
                log_calls.iter().any(|c| c.target == "GetName"),
                "should have GetName from interpolation: {:?}",
                log_calls
            );
            assert!(
                log_calls.iter().any(|c| c.target == "ComputeValue"),
                "should have ComputeValue from interpolation: {:?}",
                log_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #17: Ternary/Conditional
    // -------------------------------------------------------------------------
    mod ternary_tests {
        use super::*;

        #[test]
        fn test_ternary_calls() {
            let source = r#"
public class Service {
    public int Choose() {
        return condition ? Foo() : Bar();
    }
}
"#;
            let calls = extract_calls(source);
            let choose_calls = calls
                .get("Choose")
                .or(calls.get("Service.Choose"))
                .expect("should have Choose calls");
            assert!(
                choose_calls.iter().any(|c| c.target == "Foo"),
                "should have Foo from ternary: {:?}",
                choose_calls
            );
            assert!(
                choose_calls.iter().any(|c| c.target == "Bar"),
                "should have Bar from ternary: {:?}",
                choose_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #19: Return/Yield/Throw
    // -------------------------------------------------------------------------
    mod return_yield_tests {
        use super::*;

        #[test]
        fn test_return_call() {
            let source = r#"
public class Service {
    public int Get() {
        return Compute();
    }
}
"#;
            let calls = extract_calls(source);
            let get_calls = calls
                .get("Get")
                .or(calls.get("Service.Get"))
                .expect("should have Get calls");
            assert!(
                get_calls.iter().any(|c| c.target == "Compute"),
                "should have Compute from return: {:?}",
                get_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #25: Collection Literals / Array Initializers
    // -------------------------------------------------------------------------
    mod collection_tests {
        use super::*;

        #[test]
        fn test_array_initializer_calls() {
            let source = r#"
public class Service {
    public void Setup() {
        var arr = new int[] { Foo(), Bar() };
    }
}
"#;
            let calls = extract_calls(source);
            let setup_calls = calls
                .get("Setup")
                .or(calls.get("Service.Setup"))
                .expect("should have Setup calls");
            assert!(
                setup_calls.iter().any(|c| c.target == "Foo"),
                "should have Foo from array init: {:?}",
                setup_calls
            );
            assert!(
                setup_calls.iter().any(|c| c.target == "Bar"),
                "should have Bar from array init: {:?}",
                setup_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Combined Pattern Tests
    // -------------------------------------------------------------------------
    mod combined_tests {
        use super::*;

        #[test]
        fn test_field_init_plus_static_ctor() {
            let source = r#"
public class Combined {
    private Handler handler = CreateHandler();
    private static Logger logger = Logger.Create();

    static Combined() {
        Bootstrap();
    }

    public void Process() {
        handler.Run();
    }
}
"#;
            let calls = extract_calls(source);

            // Instance field init -> Combined.<init>
            let init_calls = calls
                .get("Combined.<init>")
                .expect("Combined.<init> should have calls");
            assert!(
                init_calls.iter().any(|c| c.target == "CreateHandler"),
                "init should have CreateHandler: {:?}",
                init_calls
            );

            // Static field init + static ctor -> Combined.<clinit>
            let clinit_calls = calls
                .get("Combined.<clinit>")
                .expect("Combined.<clinit> should have calls");
            assert!(
                clinit_calls.iter().any(|c| c.target.contains("Create")),
                "clinit should have Logger.Create: {:?}",
                clinit_calls
            );
            assert!(
                clinit_calls.iter().any(|c| c.target == "Bootstrap"),
                "clinit should have Bootstrap: {:?}",
                clinit_calls
            );
        }

        #[test]
        fn test_interface_default_method() {
            let source = r#"
public interface IProcessor {
    void Process() {
        Fallback();
        Logger.Log("default");
    }
}
"#;
            let calls = extract_calls(source);
            let has_fallback = calls
                .values()
                .any(|v| v.iter().any(|c| c.target == "Fallback"));
            assert!(
                has_fallback,
                "should have Fallback from interface default method: {:?}",
                calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Inherited Call Tests (issue #87)
    // -------------------------------------------------------------------------
    mod inherited_call_tests {
        use super::*;

        fn extract_defs(source: &str) -> Vec<ClassDef> {
            let handler = CsharpHandler::new();
            let tree = handler.parse_source(source).unwrap();
            handler
                .extract_definitions(source, Path::new("Test.cs"), &tree)
                .unwrap()
                .1
        }

        #[test]
        fn test_bare_call_in_class_with_bases_classified_intra() {
            // The method `Run` is NOT defined in this file, but the enclosing
            // class declares a base: the call may target an inherited member,
            // so it must be classified Intra for the builder to route it
            // through resolve_method_in_bases (which walks ClassIndex across
            // files). Direct here was the #87 bug: cross-file inherited calls
            // never reached inheritance-aware resolution.
            let source = r#"
public class Derived : Base
{
    public void Go()
    {
        Run();
    }
}
"#;
            let calls = extract_calls(source);
            let go_calls = calls.get("Derived.Go").expect("Derived.Go call sites");
            let run_call = go_calls
                .iter()
                .find(|c| c.target == "Run")
                .expect("bare Run() call");
            assert_eq!(run_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_bare_call_in_class_without_bases_stays_direct() {
            // No declared bases -> nothing to inherit -> historical Direct
            // classification is preserved (no behavior change for unrelated
            // bare calls).
            let source = r#"
public class Foo
{
    public void Go()
    {
        External();
    }
}
"#;
            let calls = extract_calls(source);
            let go_calls = calls.get("Foo.Go").expect("Foo.Go call sites");
            let ext_call = go_calls
                .iter()
                .find(|c| c.target == "External")
                .expect("bare External() call");
            assert_eq!(ext_call.call_type, CallType::Direct);
        }

        #[test]
        fn test_bare_call_in_generic_base_class_classified_intra() {
            // Generic method call inside a class with bases: same Intra
            // routing as plain bare calls.
            let source = r#"
public class Repo : RepositoryBase<object>
{
    public void SaveAll()
    {
        Save<object>(new object());
    }
}
"#;
            let calls = extract_calls(source);
            let saveall_calls = calls.get("Repo.SaveAll").expect("Repo.SaveAll call sites");
            let save_call = saveall_calls
                .iter()
                .find(|c| c.target == "Save")
                .expect("generic Save<T>() call");
            assert_eq!(save_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_base_list_extracts_generic_and_qualified_bases() {
            // extract_definitions must collect identifier, generic_name and
            // qualified_name bases (previously identifier-only, which dropped
            // these from ClassIndex and broke base-chain BFS).
            let source = r#"
public class Repo : RepositoryBase<User>, NS.IRepo
{
}
"#;
            let classes = extract_defs(source);
            assert_eq!(classes.len(), 1);
            let repo = &classes[0];
            assert_eq!(repo.name, "Repo");
            assert_eq!(
                repo.bases,
                vec!["RepositoryBase".to_string(), "NS.IRepo".to_string()]
            );
        }

        #[test]
        fn test_base_list_simple_identifiers() {
            let source = r#"
public class Derived : Base, IService
{
}
"#;
            let classes = extract_defs(source);
            let derived = classes.iter().find(|c| c.name == "Derived").unwrap();
            assert_eq!(
                derived.bases,
                vec!["Base".to_string(), "IService".to_string()]
            );
        }

        #[test]
        fn test_class_without_base_list_has_empty_bases() {
            let source = r#"
public class Standalone
{
}
"#;
            let classes = extract_defs(source);
            assert_eq!(classes.len(), 1);
            assert!(classes[0].bases.is_empty());
        }
    }
}
