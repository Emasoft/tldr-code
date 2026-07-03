//! Luau (Roblox) language handler for call graph analysis.
//!
//! This module provides Luau-specific call graph support using tree-sitter-luau.
//! Luau is a Lua variant used by Roblox with additional features like type annotations.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `require(script.Module)` | `{module: "script.Module", is_from: false}` |
//! | `require(script.Parent.Module)` | `{module: "script.Parent.Module", level: 1}` |
//! | `require("@pkg/json")` | `{module: "@pkg/json", is_from: false}` |
//! | `game:GetService("Players")` | `{module: "Players", is_namespace: true}` (Roblox service) |
//!
//! # Call Extraction
//!
//! - Direct calls: `func()` -> CallType::Direct or CallType::Intra
//! - Attribute calls: `Module.func()` -> CallType::Attr
//! - Method calls: `obj:method()` -> CallType::Method (colon syntax)
//! - Service calls: `game:GetService("X")` -> Special handling
//!
//! # Roblox-Specific Patterns
//!
//! - `script.Module` - Script-relative requires
//! - `script.Parent.Module` - Parent-relative requires
//! - `game:GetService("ServiceName")` - Roblox service access
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` for the full specification.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

/// FEATURE-1 d.6: record a luau class table's presence and widen its line span,
/// preserving first-seen order for deterministic ClassDef emission.
fn register_luau_class(
    order: &mut Vec<String>,
    span: &mut HashMap<String, (u32, u32)>,
    name: &str,
    line: u32,
    end_line: u32,
) {
    if name.is_empty() {
        return;
    }
    match span.get_mut(name) {
        Some(e) => {
            e.0 = e.0.min(line);
            e.1 = e.1.max(end_line);
        }
        None => {
            order.push(name.to_string());
            span.insert(name.to_string(), (line, end_line));
        }
    }
}

/// FEATURE-1 d.6: if `value` is the class-extension idiom `Y:extend(...)` or
/// `Y.extend(Y, ...)` (a `function_call` whose callee is a method/dot index
/// expression named `extend` on a bare base identifier `Y`), return the base
/// table name `Y`. Purely AST-node-kind/field driven.
fn luau_extend_base(value: &Node, source: &[u8]) -> Option<String> {
    if value.kind() != "function_call" {
        return None;
    }
    let name = value.child_by_field_name("name")?;
    let (table, member) = match name.kind() {
        "method_index_expression" => (
            name.child_by_field_name("table")?,
            name.child_by_field_name("method")?,
        ),
        "dot_index_expression" => (
            name.child_by_field_name("table")?,
            name.child_by_field_name("field")?,
        ),
        _ => return None,
    };
    if get_node_text(&member, source) != "extend" || table.kind() != "identifier" {
        return None;
    }
    let base = get_node_text(&table, source).to_string();
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

// =============================================================================
// Luau Handler
// =============================================================================

/// Luau (Roblox) language handler using tree-sitter-luau.
///
/// Supports:
/// - Import parsing (require, GetService)
/// - Call extraction (direct, attribute, method calls)
/// - Roblox script-relative paths
/// - Colon method syntax (`obj:method()`)
#[derive(Debug, Default)]
pub struct LuauHandler;

impl LuauHandler {
    /// Creates a new LuauHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_luau::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set Luau language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Extract string content from a Luau string node.
    ///
    /// Handles both string_content child nodes and manual quote stripping.
    fn extract_luau_string(&self, node: &Node, source: &[u8]) -> Option<String> {
        // Check for string_content child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "string_content" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }

        // Fallback: strip quotes manually
        let text = get_node_text(node, source);
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
        {
            Some(text[1..text.len() - 1].to_string())
        } else {
            Some(text.to_string())
        }
    }

    /// Parse a single Luau require or GetService call.
    ///
    /// Handles:
    /// - `require(script.Utils)`
    /// - `require(script.Parent.Module)`
    /// - `require("@pkg/json")`
    /// - `game:GetService("Players")`
    fn parse_luau_import_node(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        // Check for method call (GetService pattern)
        let mut method_expr: Option<Node> = None;
        let mut func_name: Option<String> = None;
        let mut arguments: Option<Node> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "method_index_expression" => {
                        method_expr = Some(child);
                    }
                    "identifier" => {
                        if func_name.is_none() {
                            func_name = Some(get_node_text(&child, source).to_string());
                        }
                    }
                    "arguments" => {
                        arguments = Some(child);
                    }
                    _ => {}
                }
            }
        }

        // Handle GetService pattern: game:GetService("ServiceName")
        if let Some(method_node) = method_expr {
            let mut method_name: Option<String> = None;
            for i in 0..method_node.child_count() {
                if let Some(child) = method_node.child(i) {
                    if child.kind() == "identifier" {
                        method_name = Some(get_node_text(&child, source).to_string());
                    }
                }
            }

            if method_name.as_deref() == Some("GetService") {
                if let Some(args) = arguments {
                    for i in 0..args.child_count() {
                        if let Some(arg_child) = args.child(i) {
                            if arg_child.kind() == "string" {
                                if let Some(service_name) =
                                    self.extract_luau_string(&arg_child, source)
                                {
                                    // Create ImportDef for Roblox service
                                    let mut imp = ImportDef::simple_import(service_name);
                                    imp.is_namespace = true; // Mark as service
                                    return Some(imp);
                                }
                            }
                        }
                    }
                }
            }
            return None;
        }

        // Handle require pattern
        if func_name.as_deref() != Some("require") {
            return None;
        }

        let args = arguments?;

        // Get the module argument - can be dot_index_expression or string
        for i in 0..args.child_count() {
            if let Some(arg_child) = args.child(i) {
                match arg_child.kind() {
                    "dot_index_expression" => {
                        // require(script.Utils) or require(script.Parent.Module)
                        let module_path = get_node_text(&arg_child, source).to_string();

                        // Check if it's a relative require (contains "Parent")
                        let level = if module_path.contains("Parent") {
                            module_path.matches("Parent").count() as u8
                        } else {
                            0
                        };

                        if level > 0 {
                            return Some(ImportDef::relative_import(module_path, vec![], level));
                        } else {
                            return Some(ImportDef::simple_import(module_path));
                        }
                    }
                    "string" => {
                        // require("@pkg/json")
                        if let Some(module_name) = self.extract_luau_string(&arg_child, source) {
                            return Some(ImportDef::simple_import(module_name));
                        }
                    }
                    "identifier" => {
                        // require(someVar) - variable reference
                        let module_name = get_node_text(&arg_child, source).to_string();
                        return Some(ImportDef::simple_import(module_name));
                    }
                    _ => {}
                }
            }
        }

        None
    }

    /// VAL-011: Extract an aliased require from a variable_declaration.
    ///
    /// In Luau, `local util = require('./util')` desugars to:
    /// ```text
    /// variable_declaration
    ///   assignment_statement
    ///     variable_list -> identifier "util"   (the alias)
    ///     expression_list -> function_call -> require("./util")
    /// ```
    ///
    /// Returns `(alias, ImportDef, call_node_id)` so the caller can mark
    /// the require call as already-processed and avoid double-emitting.
    fn extract_aliased_require(
        &self,
        node: &Node,
        source: &[u8],
    ) -> Option<(String, ImportDef, usize)> {
        for i in 0..node.child_count() {
            let assignment = node.child(i)?;
            if assignment.kind() != "assignment_statement" {
                continue;
            }

            let mut var_name: Option<String> = None;
            let mut import_info: Option<(ImportDef, usize)> = None;

            for j in 0..assignment.child_count() {
                let Some(child) = assignment.child(j) else {
                    continue;
                };
                match child.kind() {
                    "variable_list" => {
                        for k in 0..child.child_count() {
                            if let Some(var) = child.child(k) {
                                if var.kind() == "identifier" {
                                    var_name = Some(get_node_text(&var, source).to_string());
                                    break;
                                }
                            }
                        }
                    }
                    "expression_list" => {
                        for inner in walk_tree(child) {
                            if inner.kind() == "function_call" {
                                if let Some(imp) = self.parse_luau_import_node(&inner, source) {
                                    import_info = Some((imp, inner.id()));
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if let (Some(alias), Some((import_def, call_id))) = (var_name, import_info) {
                return Some((alias, import_def, call_id));
            }
        }
        None
    }

    /// Collect all function definitions from the AST.
    fn collect_definitions(&self, tree: &Tree, source: &[u8]) -> HashSet<String> {
        let mut functions = HashSet::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    // Get function name from identifier or dot/method expression
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "identifier" => {
                                    functions.insert(get_node_text(&child, source).to_string());
                                    break;
                                }
                                "dot_index_expression" | "method_index_expression" => {
                                    // function M.foo() or function M:foo() -> extract "foo"
                                    let identifiers: Vec<_> = (0..child.child_count())
                                        .filter_map(|j| child.child(j))
                                        .filter(|c| c.kind() == "identifier")
                                        .collect();
                                    if identifiers.len() >= 2 {
                                        let last = identifiers.last().unwrap();
                                        functions.insert(get_node_text(last, source).to_string());
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "variable_declaration" => {
                    // Handle variable declarations with function values
                    // local foo = function() end
                    self.collect_func_from_var_decl(&node, source, &mut functions);
                }
                _ => {}
            }
        }

        functions
    }

    /// Extract function name from variable declaration with function value.
    fn collect_func_from_var_decl(
        &self,
        node: &Node,
        source: &[u8],
        functions: &mut HashSet<String>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_statement" {
                    let mut var_list: Option<Node> = None;
                    let mut expr_list: Option<Node> = None;

                    for j in 0..child.child_count() {
                        if let Some(subchild) = child.child(j) {
                            match subchild.kind() {
                                "variable_list" => var_list = Some(subchild),
                                "expression_list" => expr_list = Some(subchild),
                                _ => {}
                            }
                        }
                    }

                    if let (Some(vl), Some(el)) = (var_list, expr_list) {
                        // Check if expression_list contains a function_definition
                        let has_func = (0..el.child_count())
                            .filter_map(|k| el.child(k))
                            .any(|c| c.kind() == "function_definition");

                        if has_func {
                            // Get variable name
                            for k in 0..vl.child_count() {
                                if let Some(var_child) = vl.child(k) {
                                    if var_child.kind() == "identifier" {
                                        functions
                                            .insert(get_node_text(&var_child, source).to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract calls from a function body node.
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        for child in walk_tree(*node) {
            if child.kind() == "function_call" {
                let line = child.start_position().row as u32 + 1;

                // Determine call type and target
                let mut call_type = CallType::Direct;
                let mut call_target: Option<String> = None;
                let mut receiver: Option<String> = None;

                for i in 0..child.child_count() {
                    if let Some(c) = child.child(i) {
                        match c.kind() {
                            "identifier" => {
                                // Simple call: foo()
                                let name = get_node_text(&c, source).to_string();
                                if defined_funcs.contains(&name) {
                                    call_type = CallType::Intra;
                                } else {
                                    call_type = CallType::Direct;
                                }
                                call_target = Some(name);
                                break;
                            }
                            "dot_index_expression" => {
                                // Module.func() or obj.method()
                                let identifiers: Vec<_> = (0..c.child_count())
                                    .filter_map(|j| c.child(j))
                                    .filter(|n| n.kind() == "identifier")
                                    .collect();

                                if identifiers.len() >= 2 {
                                    let obj_name =
                                        get_node_text(identifiers.first().unwrap(), source);
                                    let method_name =
                                        get_node_text(identifiers.last().unwrap(), source);

                                    receiver = Some(obj_name.to_string());

                                    if defined_funcs.contains(method_name) {
                                        call_type = CallType::Intra;
                                        call_target = Some(method_name.to_string());
                                    } else {
                                        call_type = CallType::Attr;
                                        call_target = Some(format!("{}.{}", obj_name, method_name));
                                    }
                                } else if identifiers.len() == 1 {
                                    call_target = Some(get_node_text(&c, source).to_string());
                                    call_type = CallType::Attr;
                                    receiver = Some(get_node_text(&c, source).to_string());
                                }
                                break;
                            }
                            "method_index_expression" => {
                                // obj:method() - colon syntax for method call
                                // Also handles complex receivers:
                                //   button.Activated:Connect() -> dot_index_expression as first child
                                //   obj:Method1():Method2()    -> function_call as first child
                                let identifiers: Vec<_> = (0..c.child_count())
                                    .filter_map(|j| c.child(j))
                                    .filter(|n| n.kind() == "identifier")
                                    .collect();

                                if identifiers.len() >= 2 {
                                    // Simple case: obj:method() with both obj and method as identifiers
                                    let obj_name =
                                        get_node_text(identifiers.first().unwrap(), source);
                                    let method_name =
                                        get_node_text(identifiers.last().unwrap(), source);

                                    receiver = Some(obj_name.to_string());

                                    // Check for game:GetService pattern
                                    if obj_name == "game" && method_name == "GetService" {
                                        // Extract service name from arguments
                                        if let Some(service_name) =
                                            self.extract_service_name(&child, source)
                                        {
                                            call_type = CallType::Attr;
                                            call_target =
                                                Some(format!("GetService:{}", service_name));
                                            receiver = Some("game".to_string());
                                        } else {
                                            call_type = CallType::Method;
                                            call_target =
                                                Some(format!("{}:{}", obj_name, method_name));
                                        }
                                    } else if obj_name != "self"
                                        && defined_funcs.contains(method_name)
                                    {
                                        call_type = CallType::Intra;
                                        call_target = Some(method_name.to_string());
                                    } else {
                                        // FEATURE-1 d.6: a `self:m()` colon call is
                                        // never receiverless — keep the receiver so
                                        // type resolution can climb `self`'s class
                                        // (and its bases) to the defining method,
                                        // instead of dropping to a bare same-file
                                        // name-match. Only genuinely receiverless
                                        // calls take the Intra branch above.
                                        call_type = CallType::Method;
                                        call_target = Some(format!("{}:{}", obj_name, method_name));
                                    }
                                } else if identifiers.len() == 1 {
                                    // Complex receiver: the first child is not an identifier
                                    // e.g. button.Activated:Connect() (dot_index_expression)
                                    //      obj:Method1():Method2()    (function_call)
                                    let method_name =
                                        get_node_text(identifiers.first().unwrap(), source)
                                            .to_string();

                                    // Get the receiver expression (first non-punctuation child)
                                    let receiver_node = (0..c.child_count())
                                        .filter_map(|j| c.child(j))
                                        .find(|n| n.kind() != "identifier" && n.kind() != ":");

                                    let recv_text = receiver_node
                                        .map(|n| get_node_text(&n, source).to_string());
                                    receiver = recv_text;

                                    call_type = CallType::Method;
                                    if let Some(ref recv) = receiver {
                                        call_target = Some(format!("{}:{}", recv, method_name));
                                    } else {
                                        call_target = Some(method_name);
                                    }
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }

                // Skip require calls (imports)
                if let Some(ref target) = call_target {
                    if target == "require" {
                        continue;
                    }
                }

                // Create CallSite if we found a target
                if let Some(target) = call_target {
                    match call_type {
                        CallType::Intra | CallType::Direct => {
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
                        CallType::Attr | CallType::Method => {
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
                        _ => {
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
                }
            }
        }

        calls
    }

    /// Extract service name from GetService call arguments.
    fn extract_service_name(&self, call_node: &Node, source: &[u8]) -> Option<String> {
        for i in 0..call_node.child_count() {
            if let Some(child) = call_node.child(i) {
                if child.kind() == "arguments" {
                    for j in 0..child.child_count() {
                        if let Some(arg) = child.child(j) {
                            if arg.kind() == "string" {
                                return self.extract_luau_string(&arg, source);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Get a function declaration's `(simple_name, qualified_name)`.
    ///
    /// - `function foo()`       -> `("foo", "foo")`
    /// - `function M.foo()`     -> `("foo", "M.foo")`
    /// - `function M:foo()`     -> `("foo", "M.foo")`   (colon normalized to dot)
    /// - `function M.sub.foo()` -> `("foo", "M.sub.foo")`
    ///
    /// The qualified name keeps a colon/dot method distinct from a same-named
    /// free `function foo()`. Keying `calls_by_func` by the qualified name is
    /// what stops a method (e.g. `a:deep`) from colliding with a free `deep` and
    /// clobbering its call list. Both dot and colon methods normalize to the
    /// same `table.member` form so they key identically. Purely AST-node-kind
    /// driven.
    fn get_function_names(&self, node: &Node, source: &[u8]) -> Option<(String, String)> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        let name = get_node_text(&child, source).to_string();
                        return Some((name.clone(), name));
                    }
                    "dot_index_expression" | "method_index_expression" => {
                        let identifiers: Vec<_> = (0..child.child_count())
                            .filter_map(|j| child.child(j))
                            .filter(|c| c.kind() == "identifier")
                            .collect();
                        if identifiers.len() >= 2 {
                            let simple =
                                get_node_text(identifiers.last().unwrap(), source).to_string();
                            // Dot-normalize `M.foo` and `M:foo` alike to `M.foo`.
                            let qualified = identifiers
                                .iter()
                                .map(|id| get_node_text(id, source))
                                .collect::<Vec<_>>()
                                .join(".");
                            return Some((simple, qualified));
                        }
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Get function name from variable declaration with function value.
    fn get_func_name_from_var_decl<'a>(
        &self,
        node: &Node<'a>,
        source: &[u8],
    ) -> Option<(String, Node<'a>)> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_statement" {
                    let mut var_list: Option<Node> = None;
                    let mut expr_list: Option<Node> = None;

                    for j in 0..child.child_count() {
                        if let Some(subchild) = child.child(j) {
                            match subchild.kind() {
                                "variable_list" => var_list = Some(subchild),
                                "expression_list" => expr_list = Some(subchild),
                                _ => {}
                            }
                        }
                    }

                    if let (Some(vl), Some(el)) = (var_list, expr_list) {
                        // Find function_definition in expression_list
                        let mut func_node: Option<Node> = None;
                        for k in 0..el.child_count() {
                            if let Some(ec) = el.child(k) {
                                if ec.kind() == "function_definition" {
                                    func_node = Some(ec);
                                    break;
                                }
                            }
                        }

                        if let Some(fn_node) = func_node {
                            // Get variable name
                            for k in 0..vl.child_count() {
                                if let Some(var_child) = vl.child(k) {
                                    if var_child.kind() == "identifier" {
                                        return Some((
                                            get_node_text(&var_child, source).to_string(),
                                            fn_node,
                                        ));
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
}

impl CallGraphLanguageSupport for LuauHandler {
    fn name(&self) -> &str {
        "luau"
    }

    fn extensions(&self) -> &[&str] {
        &[".luau", ".lua"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        // VAL-011: Two-pass extraction (parity with Lua handler).
        //
        // First pass: walk variable_declarations to capture aliased requires
        // (`local util = require('./util')`). Without this, the import
        // emitted has no `alias`, and `build_import_map` keys
        // `module_imports` under the literal `./util` rather than the
        // bound name `util`. Receiver lookup then misses.
        let mut processed_calls: HashSet<usize> = HashSet::new();
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "variable_declaration" {
                if let Some((alias, mut import_def, call_id)) =
                    self.extract_aliased_require(&node, source_bytes)
                {
                    import_def.alias = Some(alias);
                    imports.push(import_def);
                    processed_calls.insert(call_id);
                }
            }
        }

        // Second pass: standalone `require(...)` calls not bound to a local.
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "function_call" {
                let call_id = node.id();
                if processed_calls.contains(&call_id) {
                    continue;
                }
                if let Some(imp) = self.parse_luau_import_node(&node, source_bytes) {
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
        let defined_funcs = self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();

        // Process all function declarations and variable declarations with function values
        fn process_node(
            node: Node,
            source: &[u8],
            defined_funcs: &HashSet<String>,
            calls_by_func: &mut HashMap<String, Vec<CallSite>>,
            handler: &LuauHandler,
        ) {
            match node.kind() {
                "function_declaration" => {
                    if let Some((simple_name, qualified_name)) =
                        handler.get_function_names(&node, source)
                    {
                        let calls = handler.extract_calls_from_node(
                            &node,
                            source,
                            defined_funcs,
                            &qualified_name,
                        );
                        if !calls.is_empty() {
                            // Key by the QUALIFIED name so a colon/dot method
                            // (`a:deep`, `a.deep`) never collides with a free
                            // `function deep()`. MERGE (never overwrite) so that
                            // when two definitions DO share a key, no call list
                            // is ever clobbered — this preserves the free
                            // functions' self-recursion calls that an
                            // insert-overwrite would silently drop.
                            calls_by_func
                                .entry(qualified_name.clone())
                                .or_default()
                                .extend(calls.clone());
                            // Also key by the simple name for backward-compatible
                            // lookups (`calls.get("bar")` for `function Foo:bar`).
                            if simple_name != qualified_name {
                                calls_by_func.entry(simple_name).or_default().extend(calls);
                            }
                        }
                    }
                }
                "variable_declaration" => {
                    if let Some((func_name, func_node)) =
                        handler.get_func_name_from_var_decl(&node, source)
                    {
                        let calls = handler.extract_calls_from_node(
                            &func_node,
                            source,
                            defined_funcs,
                            &func_name,
                        );
                        if !calls.is_empty() {
                            // MERGE rather than overwrite (see above).
                            calls_by_func.entry(func_name).or_default().extend(calls);
                        }
                    }
                }
                _ => {}
            }

            // Recurse into children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    process_node(child, source, defined_funcs, calls_by_func, handler);
                }
            }
        }

        process_node(
            tree.root_node(),
            source_bytes,
            &defined_funcs,
            &mut calls_by_func,
            self,
        );

        // Extract module-level calls into synthetic <module> function
        let mut module_calls = Vec::new();
        for i in 0..tree.root_node().child_count() {
            if let Some(child) = tree.root_node().child(i) {
                // Skip function declarations and variable declarations with functions
                if child.kind() == "function_declaration" {
                    continue;
                }
                if child.kind() == "variable_declaration" {
                    // Check if it's a function definition
                    let is_func_def =
                        (0..child.child_count())
                            .filter_map(|j| child.child(j))
                            .any(|c| {
                                c.kind() == "assignment_statement"
                                    && (0..c.child_count()).filter_map(|k| c.child(k)).any(|sc| {
                                        sc.kind() == "expression_list"
                                            && (0..sc.child_count())
                                                .filter_map(|l| sc.child(l))
                                                .any(|ec| ec.kind() == "function_definition")
                                    })
                            });
                    if is_func_def {
                        continue;
                    }
                }

                let calls =
                    self.extract_calls_from_node(&child, source_bytes, &defined_funcs, "<module>");
                module_calls.extend(calls);
            }
        }

        if !module_calls.is_empty() {
            calls_by_func.insert("<module>".to_string(), module_calls);
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

        // FEATURE-1 d.6: model luau "class tables" so a subclass method's
        // `self:call()` can climb to an inherited base method (the Roact
        // `Component:setState` case). A table that owns colon-methods
        // (`function T:m()`) is a class whose method set includes `m`; the
        // `local X = Y:extend(...)` idiom makes X a class deriving from Y.
        // Emitting these ClassDefs lets `resolve_method_in_bases` traverse
        // X -> Y -> ... -> Component. The FuncDef emission is UNCHANGED (colon
        // methods still register under their simple name), so bare-name / same
        // file resolution is preserved — the class `methods` list is what the
        // base climb consults (`class_entry.methods.contains(m)`), keeping this
        // strictly additive. Purely AST-node-kind/field driven.
        let mut class_order: Vec<String> = Vec::new();
        let mut class_methods: HashMap<String, Vec<String>> = HashMap::new();
        let mut class_bases: HashMap<String, Vec<String>> = HashMap::new();
        let mut class_span: HashMap<String, (u32, u32)> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "identifier" => {
                                    let name = get_node_text(&child, source_bytes).to_string();
                                    funcs.push(FuncDef::function(name, line, end_line));
                                    break;
                                }
                                "dot_index_expression" | "method_index_expression" => {
                                    // function M.foo() or function M:foo() -> extract last identifier
                                    let identifiers: Vec<_> = (0..child.child_count())
                                        .filter_map(|j| child.child(j))
                                        .filter(|c| c.kind() == "identifier")
                                        .collect();
                                    if identifiers.len() >= 2 {
                                        let last = identifiers.last().unwrap();
                                        let name = get_node_text(last, source_bytes).to_string();
                                        // A colon method `function T:m()` makes T a
                                        // class owning method m.
                                        if child.kind() == "method_index_expression" {
                                            let table =
                                                get_node_text(identifiers.first().unwrap(), source_bytes)
                                                    .to_string();
                                            register_luau_class(
                                                &mut class_order,
                                                &mut class_span,
                                                &table,
                                                line,
                                                end_line,
                                            );
                                            class_methods
                                                .entry(table)
                                                .or_default()
                                                .push(name.clone());
                                        }
                                        funcs.push(FuncDef::function(name, line, end_line));
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "variable_declaration" => {
                    // Handle: local foo = function() end  AND  local X = Y:extend(...)
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    let mut var_names: Vec<String> = Vec::new();
                    let mut values: Vec<Node> = Vec::new();
                    let mut has_function = false;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "assignment_statement" {
                                for j in 0..child.child_count() {
                                    if let Some(subchild) = child.child(j) {
                                        if subchild.kind() == "variable_list" {
                                            for k in 0..subchild.child_count() {
                                                if let Some(var) = subchild.child(k) {
                                                    if var.kind() == "identifier" {
                                                        var_names.push(
                                                            get_node_text(&var, source_bytes)
                                                                .to_string(),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        if subchild.kind() == "expression_list" {
                                            for k in 0..subchild.named_child_count() {
                                                if let Some(expr) = subchild.named_child(k) {
                                                    if expr.kind() == "function_definition" {
                                                        has_function = true;
                                                    }
                                                    values.push(expr);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if has_function {
                        for name in &var_names {
                            funcs.push(FuncDef::function(name.clone(), line, end_line));
                        }
                    }

                    // `local X = Y:extend(...)` / `Y.extend(Y, ...)` -> class X : Y.
                    for (idx, name) in var_names.iter().enumerate() {
                        if let Some(value) = values.get(idx) {
                            if let Some(base) = luau_extend_base(value, source_bytes) {
                                register_luau_class(
                                    &mut class_order,
                                    &mut class_span,
                                    name,
                                    line,
                                    end_line,
                                );
                                class_bases.entry(name.clone()).or_default().push(base);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let mut classes = Vec::new();
        for name in class_order {
            let (line, end_line) = class_span.get(&name).copied().unwrap_or((1, 1));
            let methods = class_methods.remove(&name).unwrap_or_default();
            let bases = class_bases.remove(&name).unwrap_or_default();
            classes.push(ClassDef::new(name, line, end_line, methods, bases));
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
        let handler = LuauHandler::new();
        handler
            .parse_imports(source, Path::new("test.luau"))
            .unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = LuauHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("test.luau"), source, &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_require_script() {
            let imports = parse_imports("local Utils = require(script.Utils)");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "script.Utils");
            assert!(!imports[0].is_relative());
        }

        #[test]
        fn test_parse_require_parent() {
            let imports = parse_imports("local Module = require(script.Parent.Module)");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "script.Parent.Module");
            assert!(imports[0].is_relative());
            assert_eq!(imports[0].level, 1);
        }

        #[test]
        fn test_parse_require_parent_parent() {
            let imports = parse_imports("local M = require(script.Parent.Parent.Module)");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].module.contains("Parent.Parent"));
            assert!(imports[0].is_relative());
            assert_eq!(imports[0].level, 2);
        }

        #[test]
        fn test_parse_get_service() {
            let imports = parse_imports("local Players = game:GetService(\"Players\")");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "Players");
            assert!(imports[0].is_namespace); // Marked as service
        }

        #[test]
        fn test_parse_regular_require() {
            let imports = parse_imports("local json = require(\"@pkg/json\")");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "@pkg/json");
            assert!(!imports[0].is_relative());
        }

        #[test]
        fn test_parse_multiple_imports() {
            let source = r#"
local Utils = require(script.Utils)
local Players = game:GetService("Players")
local json = require("@pkg/json")
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
local function main()
    print("hello")
    helper()
end
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            assert!(main_calls.iter().any(|c| c.target == "print"));
            assert!(main_calls.iter().any(|c| c.target == "helper"));
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
local function helper()
    return "help"
end

local function main()
    helper()
end
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            let helper_call = main_calls.iter().find(|c| c.target == "helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_method() {
            let source = r#"
local function process()
    local player = Players:GetPlayerByUserId(userId)
    player:Kick()
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process").unwrap();
            assert!(process_calls
                .iter()
                .any(|c| c.target.contains("GetPlayerByUserId")));
            assert!(process_calls.iter().any(|c| c.target.contains("Kick")));
        }

        #[test]
        fn test_extract_calls_attr() {
            let source = r#"
local function init()
    Utils.setup()
    Module.configure()
end
"#;
            let calls = extract_calls(source);
            let init_calls = calls.get("init").unwrap();
            assert!(init_calls.iter().any(|c| c.target.contains("Utils.setup")));
            assert!(init_calls
                .iter()
                .any(|c| c.target.contains("Module.configure")));
        }

        #[test]
        fn test_extract_calls_get_service() {
            let source = r#"
local function setup()
    local Players = game:GetService("Players")
end
"#;
            let calls = extract_calls(source);
            let setup_calls = calls.get("setup").unwrap();
            assert!(setup_calls
                .iter()
                .any(|c| c.target.contains("GetService:Players")));
        }

        #[test]
        fn test_extract_calls_module_level() {
            let source = r#"
local function helper()
    return "help"
end

-- Module-level call
local result = helper()
"#;
            let calls = extract_calls(source);
            assert!(calls.contains_key("<module>"));
            let module_calls = calls.get("<module>").unwrap();
            assert!(module_calls.iter().any(|c| c.target == "helper"));
        }

        #[test]
        fn test_extract_calls_var_function() {
            let source = r#"
local process = function()
    doWork()
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process").unwrap();
            assert!(process_calls.iter().any(|c| c.target == "doWork"));
        }
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = LuauHandler::new();
            assert_eq!(handler.name(), "luau");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = LuauHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".luau"));
            assert!(exts.contains(&".lua"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = LuauHandler::new();
            assert!(handler.supports("luau"));
            assert!(handler.supports("Luau"));
            assert!(handler.supports("LUAU"));
            assert!(!handler.supports("lua")); // Only "luau" name, not "lua"
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = LuauHandler::new();
            assert!(handler.supports_extension(".luau"));
            assert!(handler.supports_extension(".lua"));
            assert!(handler.supports_extension(".LUAU"));
            assert!(!handler.supports_extension(".py"));
        }
    }

    // -------------------------------------------------------------------------
    // Pattern Parity Tests (new)
    // -------------------------------------------------------------------------

    mod parity_tests {
        use super::*;

        #[test]
        fn test_self_method_calls() {
            // self:method() inside function Foo:bar() should be captured
            let source = r#"
function Foo:bar()
    self:method()
    self:other()
end
"#;
            let calls = extract_calls(source);
            let bar_calls = calls.get("bar").unwrap();
            assert!(
                bar_calls.iter().any(|c| c.target.contains("method")),
                "Expected self:method() call, got: {:?}",
                bar_calls
            );
            assert!(
                bar_calls.iter().any(|c| c.target.contains("other")),
                "Expected self:other() call, got: {:?}",
                bar_calls
            );
            // Verify receiver is "self"
            let method_call = bar_calls
                .iter()
                .find(|c| c.target.contains("method"))
                .unwrap();
            assert_eq!(method_call.receiver, Some("self".to_string()));
            assert_eq!(method_call.call_type, CallType::Method);
        }

        #[test]
        fn test_chained_method_calls() {
            // obj:Method1():Method2() should capture both calls
            let source = r#"
function test()
    obj:Method1():Method2()
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target.contains("Method1")),
                "Expected obj:Method1() call, got: {:?}",
                test_calls
            );
            assert!(
                test_calls.iter().any(|c| c.target.contains("Method2")),
                "Expected :Method2() chained call, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_instance_new_pattern() {
            // Instance.new("Part") is a Roblox constructor pattern
            let source = r#"
function test()
    local part = Instance.new("Part")
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target.contains("Instance.new")),
                "Expected Instance.new() call, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_connect_pattern() {
            // button.Activated:Connect(callback) is a Roblox event pattern
            // The method_index_expression has dot_index_expression as first child
            let source = r#"
function test()
    button.Activated:Connect(function()
        print("clicked")
    end)
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target.contains("Connect")),
                "Expected :Connect() call, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_waitforchild_pattern() {
            // player:WaitForChild("PlayerGui") is a common Roblox pattern
            let source = r#"
function test()
    local gui = player:WaitForChild("PlayerGui")
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target.contains("WaitForChild")),
                "Expected :WaitForChild() call, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_table_constructor_calls() {
            // Calls inside table constructors should be captured
            let source = r#"
function test()
    local t = { field = func(), other = bar() }
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target == "func"),
                "Expected func() call inside table constructor, got: {:?}",
                test_calls
            );
            assert!(
                test_calls.iter().any(|c| c.target == "bar"),
                "Expected bar() call inside table constructor, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_nested_function_calls() {
            // foo(bar()) should capture both calls
            let source = r#"
function test()
    foo(bar())
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target == "foo"),
                "Expected foo() call, got: {:?}",
                test_calls
            );
            assert!(
                test_calls.iter().any(|c| c.target == "bar"),
                "Expected bar() nested call, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_type_annotation_calls() {
            // local x: Foo = Foo.new() - the call should still be captured
            let source = r#"
function test()
    local x: Foo = Foo.new()
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls.get("test").unwrap();
            assert!(
                test_calls.iter().any(|c| c.target.contains("Foo.new")),
                "Expected Foo.new() call with type annotation, got: {:?}",
                test_calls
            );
        }

        #[test]
        fn test_method_definition_tracked() {
            // function Foo:bar() should be tracked as a definition named "bar"
            let source = r#"
function Foo:bar()
    print("hello")
end

function Foo:baz()
    bar()
end
"#;
            let handler = LuauHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _classes) = handler
                .extract_definitions(source, Path::new("test.luau"), &tree)
                .unwrap();
            let func_names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
            assert!(
                func_names.contains(&"bar"),
                "Expected 'bar' definition from function Foo:bar(), got: {:?}",
                func_names
            );
            assert!(
                func_names.contains(&"baz"),
                "Expected 'baz' definition from function Foo:baz(), got: {:?}",
                func_names
            );
        }

        #[test]
        fn test_complex_roblox_pattern() {
            // Real-world Roblox pattern combining multiple features
            let source = r#"
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

function PlayerModule:OnPlayerAdded(player)
    local character = player.Character or player.CharacterAdded:Wait()
    local humanoid = character:WaitForChild("Humanoid")
    humanoid.Died:Connect(function()
        self:HandleDeath(player)
    end)
end
"#;
            let calls = extract_calls(source);

            // Module-level GetService calls
            assert!(
                calls.contains_key("<module>"),
                "Expected <module> key for module-level calls"
            );
            let module_calls = calls.get("<module>").unwrap();
            assert!(
                module_calls.iter().any(|c| c.target.contains("GetService")),
                "Expected GetService at module level, got: {:?}",
                module_calls
            );

            // Method body calls
            let method_calls = calls.get("OnPlayerAdded").unwrap();
            assert!(
                method_calls
                    .iter()
                    .any(|c| c.target.contains("WaitForChild")),
                "Expected WaitForChild call, got: {:?}",
                method_calls
            );
        }

        #[test]
        fn test_dot_method_index_connect() {
            // event:Connect where event is accessed via dot notation
            // In AST, method_index_expression has dot_index_expression as first child
            let source = r#"
function test()
    workspace.ChildAdded:Connect(onChildAdded)
    game.Players.PlayerAdded:Connect(onPlayerAdded)
end
"#;
            let calls = extract_calls(source);
            let test_calls = calls
                .get("test")
                .expect("Expected 'test' function to have calls");
            // Should find both Connect calls
            let connect_calls: Vec<_> = test_calls
                .iter()
                .filter(|c| c.target.contains("Connect"))
                .collect();
            assert!(
                connect_calls.len() >= 2,
                "Expected 2 Connect calls, got: {:?}",
                test_calls
            );
        }

        /// BUG 2: a colon method `function a:deep(n)` that shares the bare name
        /// `deep` with two free `function deep(n)` self-recursive definitions must
        /// NOT clobber their call lists.
        ///
        /// Before the fix, `get_function_name` stripped the `a:` qualifier so
        /// `a:deep` keyed as bare `deep`, and `calls_by_func.insert` overwrote the
        /// key: the method (processed last) clobbered both free functions' call
        /// lists, deleting the real `deep -> deep` self-recursion and leaving only
        /// a spurious `deep -> a.deep`.
        ///
        /// The fix keys the method by its QUALIFIED name (`a.deep`) AND merges
        /// (never overwrites) same-key call lists, so:
        ///   - both free `deep` self-recursion calls survive under key `deep`, and
        ///   - `a:deep` is keyed distinctly under `a.deep`.
        #[test]
        fn test_method_name_collision_preserves_free_recursion() {
            let source = r#"
function deep(n)
    return deep(n - 1)
end

function deep(n)
    return deep(n - 1)
end

function a:deep(n)
    return self:deep(n - 1)
end
"#;
            let calls = extract_calls(source);

            // (b) MERGE: the two free `function deep` self-recursion calls both
            // survive under the bare `deep` key (an overwrite would drop one or
            // both).
            let deep_calls = calls
                .get("deep")
                .expect("expected a `deep` key for the free functions");
            let free_recursions = deep_calls
                .iter()
                .filter(|c| c.target == "deep")
                .count();
            assert_eq!(
                free_recursions, 2,
                "both free `deep` self-recursion calls must survive; got {:?}",
                deep_calls
            );

            // (a) QUALIFIED KEY: `a:deep` is keyed distinctly as `a.deep`, so it
            // does not collide with the free `deep`.
            let method_calls = calls
                .get("a.deep")
                .expect("colon method `a:deep` must be keyed distinctly as `a.deep`");
            assert!(
                method_calls.iter().any(|c| c.target.contains("deep")),
                "`a.deep` must retain its own `self:deep` call; got {:?}",
                method_calls
            );
            // The distinct `a.deep` bucket must not have absorbed the free
            // functions' bare `deep` self-recursion calls.
            assert!(
                !method_calls.iter().any(|c| c.target == "deep"),
                "`a.deep` bucket must be the method's own calls, not the free \
                 functions'; got {:?}",
                method_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // FEATURE-1 d.6: extend() inheritance modeling
    // -------------------------------------------------------------------------

    mod inheritance_tests {
        use super::*;

        #[test]
        fn test_d6_luau_extend_emits_classdef_and_methods() {
            let handler = LuauHandler::new();
            let source = r#"
local Component = require(script.Parent.Component)

local Consumer = Component:extend("Consumer")

function Consumer:render()
    return nil
end

function Consumer:doThing()
    self:setState({})
end
"#;
            let tree = handler.parse_source(source).unwrap();
            let (_funcs, classes) = handler
                .extract_definitions(source, Path::new("Consumer.luau"), &tree)
                .unwrap();

            let consumer = classes
                .iter()
                .find(|c| c.name == "Consumer")
                .expect("Consumer class emitted from the extend() idiom");
            assert_eq!(
                consumer.bases,
                vec!["Component".to_string()],
                "extend() base recorded so resolve_method_in_bases can climb"
            );
            assert!(
                consumer.methods.contains(&"render".to_string())
                    && consumer.methods.contains(&"doThing".to_string()),
                "colon methods registered on the class table: {:?}",
                consumer.methods
            );
        }

        #[test]
        fn test_d6_luau_dot_extend_form() {
            // `Y.extend(Y, name)` is the desugared colon form and must also derive.
            let handler = LuauHandler::new();
            let source = r#"
local Sub = Base.extend(Base, "Sub")
"#;
            let tree = handler.parse_source(source).unwrap();
            let (_funcs, classes) = handler
                .extract_definitions(source, Path::new("Sub.luau"), &tree)
                .unwrap();
            let sub = classes
                .iter()
                .find(|c| c.name == "Sub")
                .expect("Sub class from dot-form extend");
            assert_eq!(sub.bases, vec!["Base".to_string()]);
        }

        #[test]
        fn test_d6_luau_self_colon_call_keeps_receiver() {
            // A `self:setState()` colon call must stay a receiver-bearing Method
            // call even though `setState` is defined in the same file, so type
            // resolution can climb self's class to the inherited base method.
            let source = r#"
local Base = {}
function Base:setState(s)
end

local Sub = Base:extend("Sub")
function Sub:doThing()
    self:setState({})
end
"#;
            let calls = extract_calls(source);
            let do_calls = calls.get("doThing").expect("doThing calls present");
            let ss = do_calls
                .iter()
                .find(|c| c.target == "self:setState")
                .expect("self:setState kept as a receiver-bearing Method call");
            assert_eq!(ss.receiver.as_deref(), Some("self"));
            assert_eq!(ss.call_type, CallType::Method);
        }
    }
}
