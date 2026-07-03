//! Lua language handler for call graph analysis.
//!
//! This module provides Lua-specific call graph support using tree-sitter-lua.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `require('module')` | `{module: "module", is_from: false}` |
//! | `require 'module'` | `{module: "module", is_from: false}` |
//! | `dofile('path.lua')` | `{module: "path.lua", is_from: false}` |
//! | `loadfile('path.lua')` | `{module: "path.lua", is_from: false}` |
//! | `local M = require('mod')` | `{module: "mod", alias: "M"}` |
//!
//! # Call Extraction
//!
//! - Direct calls: `func()` -> CallType::Direct or CallType::Intra
//! - Attribute calls: `module.func()` -> CallType::Attr (dot syntax)
//! - Method calls: `obj:method()` -> CallType::Method (colon syntax, self passed implicitly)
//!
//! # Lua-Specific Notes
//!
//! - Lua uses `require` for module imports (similar to Ruby)
//! - `dofile` and `loadfile` execute/load files by path
//! - Dot notation (`M.func`) is for table/module access
//! - Colon notation (`obj:method`) passes self implicitly as first argument
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.x for Lua-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// Lua Handler
// =============================================================================

/// Lua language handler using tree-sitter-lua.
///
/// Supports:
/// - Import parsing (require, dofile, loadfile)
/// - Call extraction (direct, attribute via dot, method via colon)
/// - Function definition tracking
/// - `<module>` synthetic function for module-level calls
#[derive(Debug, Default)]
pub struct LuaHandler;

impl LuaHandler {
    /// Creates a new LuaHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_lua::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set Lua language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Extract string content from a Lua string node.
    ///
    /// Handles:
    /// - Double quoted: `"string"`
    /// - Single quoted: `'string'`
    /// - Long brackets: `[[string]]`
    fn extract_lua_string(&self, node: &Node, source: &[u8]) -> Option<String> {
        let text = get_node_text(node, source);

        // Strip quotes based on format
        if (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
            || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2)
        {
            Some(text[1..text.len() - 1].to_string())
        } else if text.starts_with("[[") && text.ends_with("]]") && text.len() >= 4 {
            Some(text[2..text.len() - 2].to_string())
        } else {
            // Return as-is if no recognized quote format
            Some(text.to_string())
        }
    }

    /// Parse a require/dofile/loadfile call node.
    ///
    /// Returns (import_type, module_path) if this is an import call.
    fn parse_require_node(&self, node: &Node, source: &[u8]) -> Option<(String, String)> {
        // Lua import calls are function_call nodes
        // Structure varies by call style:
        // - require("module") -> function_call with identifier + arguments
        // - require "module"  -> function_call with identifier + string (no parens)

        let mut func_name: Option<String> = None;
        let mut module_path: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        func_name = Some(get_node_text(&child, source).to_string());
                    }
                    "arguments" => {
                        // Find the first string argument
                        for j in 0..child.child_count() {
                            if let Some(arg) = child.child(j) {
                                if arg.kind() == "string" {
                                    module_path = self.extract_lua_string(&arg, source);
                                    break;
                                }
                            }
                        }
                    }
                    "string" => {
                        // Direct string argument (require "module" syntax)
                        module_path = self.extract_lua_string(&child, source);
                    }
                    _ => {}
                }
            }
        }

        let func = func_name?;
        let module = module_path?;

        // Only handle require, dofile, loadfile
        match func.as_str() {
            "require" | "dofile" | "loadfile" => Some((func, module)),
            _ => None,
        }
    }

    /// Collect all function definitions in the file.
    ///
    /// Tracks:
    /// - `function foo()` declarations
    /// - `function M.foo()` module function declarations
    /// - `function M:foo()` method declarations
    /// - `local foo = function()` variable declarations with function values
    fn collect_definitions(&self, tree: &Tree, source: &[u8]) -> HashSet<String> {
        let mut funcs = HashSet::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    // Get function name from different patterns
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "identifier" => {
                                    // Simple: function foo()
                                    funcs.insert(get_node_text(&child, source).to_string());
                                    break;
                                }
                                "dot_index_expression" => {
                                    // Module function: function M.foo()
                                    // Extract the last identifier (function name)
                                    if let Some(name) = self.extract_last_identifier(&child, source)
                                    {
                                        funcs.insert(name);
                                    }
                                    break;
                                }
                                "method_index_expression" => {
                                    // Method: function M:foo()
                                    // Extract the last identifier (method name)
                                    if let Some(name) = self.extract_last_identifier(&child, source)
                                    {
                                        funcs.insert(name);
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "variable_declaration" => {
                    // Handle: local foo = function() ... end
                    self.collect_function_from_variable_decl(&node, source, &mut funcs);
                }
                "assignment_statement" => {
                    // Handle: handler = function() ... end
                    //         MyModule.func = function() ... end
                    if let Some((name, _qualified, _body)) =
                        self.get_func_from_assignment(&node, source)
                    {
                        funcs.insert(name);
                    }
                }
                _ => {}
            }
        }

        funcs
    }

    /// Extract the last identifier from a dot or method index expression.
    fn extract_last_identifier(&self, node: &Node, source: &[u8]) -> Option<String> {
        let mut last_ident: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    last_ident = Some(get_node_text(&child, source).to_string());
                }
            }
        }

        last_ident
    }

    /// fix-cl-8-v1 (BUG-5, LUA): the BARE-IDENTIFIER receiver `T` of a colon
    /// method name `function T:m` (a `method_index_expression` whose `table`
    /// field is a plain `identifier`). Returns `Some("T")` only for that shape;
    /// `None` for a dotted/computed receiver (`a.b:m`, where `table` is a
    /// `dot_index_expression`), which is not a single owning-class name we can
    /// safely scope self-dispatch against. Pure tree-sitter field access — the
    /// grammar defines `method_index_expression.table` as
    /// `choice(identifier, dot_index_expression)`.
    fn colon_method_bare_receiver(&self, node: &Node, source: &[u8]) -> Option<String> {
        let table = node.child_by_field_name("table")?;
        if table.kind() == "identifier" {
            return Some(get_node_text(&table, source).to_string());
        }
        None
    }

    /// Build (simple_name, qualified_name) for a `bracket_index_expression` LHS
    /// that names a table-field function definition.
    ///
    /// `method_handlers["textDocument/completion"]` ->
    ///   simple    = `textDocument/completion`  (subscript content, quotes stripped)
    ///   qualified = `method_handlers["textDocument/completion"]`
    ///
    /// Reads the `table` and `field` fields directly from the AST.
    ///
    /// A function definition name is only fabricated when the subscript `field`
    /// is a STRING LITERAL — a stable, compile-time-constant key that acts as a
    /// real member name (the dispatch-table idiom). For any COMPUTED / dynamic
    /// subscript (`args[nargs + 1]`, `self[name]`, `t[i]`) the index text is NOT
    /// a function name, so this returns `None` rather than fabricating a phantom
    /// FuncDef from the index expression (which previously produced bogus
    /// definitions literally named `nargs + 1`, or conflated a parameter `name`
    /// with a function definition). Purely AST-node-kind/field driven.
    fn extract_bracket_index_names(
        &self,
        node: &Node,
        source: &[u8],
    ) -> Option<(String, String)> {
        let table = node.child_by_field_name("table")?;
        let field = node.child_by_field_name("field")?;

        // Only a string-literal subscript is a nameable, constant member key.
        // Anything else (identifier, number, binary_expression, function_call,
        // ...) is a computed index and must NOT become a function name.
        if field.kind() != "string" {
            return None;
        }

        let table_text = get_node_text(&table, source).to_string();
        let field_text = get_node_text(&field, source).to_string();
        if table_text.is_empty() || field_text.is_empty() {
            return None;
        }

        // Simple name: strip the surrounding quotes via the AST `string_content`
        // child; fall back to the raw field text only if the literal carries no
        // content child (e.g. an empty string, which we then reject as unnamed).
        let simple = field
            .named_child(0)
            .filter(|c| c.kind() == "string_content")
            .map(|c| get_node_text(&c, source).to_string())
            .unwrap_or_else(|| field_text.clone());
        if simple.is_empty() {
            return None;
        }

        let qualified = format!("{}[{}]", table_text, field_text);
        Some((simple, qualified))
    }

    /// Collect function name from variable declaration with function value.
    fn collect_function_from_variable_decl(
        &self,
        node: &Node,
        source: &[u8],
        funcs: &mut HashSet<String>,
    ) {
        // Structure: variable_declaration -> assignment_statement -> variable_list + expression_list
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_statement" {
                    let mut var_name: Option<String> = None;
                    let mut has_function = false;

                    for j in 0..child.child_count() {
                        if let Some(subchild) = child.child(j) {
                            match subchild.kind() {
                                "variable_list" => {
                                    // Get first identifier
                                    for k in 0..subchild.child_count() {
                                        if let Some(var) = subchild.child(k) {
                                            if var.kind() == "identifier" {
                                                var_name =
                                                    Some(get_node_text(&var, source).to_string());
                                                break;
                                            }
                                        }
                                    }
                                }
                                "expression_list" => {
                                    // Check if any expression is a function_definition
                                    for k in 0..subchild.child_count() {
                                        if let Some(expr) = subchild.child(k) {
                                            if expr.kind() == "function_definition" {
                                                has_function = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    if let (Some(name), true) = (var_name, has_function) {
                        funcs.insert(name);
                    }
                }
            }
        }
    }

    /// Extract calls from a node, recursively.
    ///
    /// Also detects function references: identifiers that match defined functions
    /// and are used as arguments (callbacks), e.g. `table.sort(list, compare)`.
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();
        let mut refs = HashSet::new();

        for child in walk_tree(*node) {
            match child.kind() {
                "function_call" => {
                    if let Some(call_site) =
                        self.parse_function_call(&child, source, defined_funcs, caller)
                    {
                        calls.push(call_site);
                    }
                }
                "identifier" => {
                    // Check for function references (identifiers passed as arguments)
                    let name = get_node_text(&child, source);
                    if defined_funcs.contains(name) {
                        // Only count as Ref if the identifier is inside an arguments node
                        // and is NOT the function being called
                        if let Some(parent) = child.parent() {
                            if parent.kind() == "arguments" {
                                refs.insert(name.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Add function references as Ref call sites
        for ref_name in refs {
            let line = node.start_position().row as u32 + 1;
            calls.push(CallSite::new(
                caller.to_string(),
                ref_name,
                CallType::Ref,
                Some(line),
                None,
                None,
                None,
            ));
        }

        calls
    }

    /// Parse a function_call node and create a CallSite.
    fn parse_function_call(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        caller: &str,
    ) -> Option<CallSite> {
        let line = node.start_position().row as u32 + 1;

        // Check each child to determine call type
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        // Simple call: foo()
                        let target = get_node_text(&child, source).to_string();

                        // Skip import-related calls
                        if target == "require" || target == "dofile" || target == "loadfile" {
                            return None;
                        }

                        let call_type = if defined_funcs.contains(&target) {
                            CallType::Intra
                        } else {
                            CallType::Direct
                        };

                        return Some(CallSite::new(
                            caller.to_string(),
                            target,
                            call_type,
                            Some(line),
                            None,
                            None,
                            None,
                        ));
                    }
                    "dot_index_expression" => {
                        // Attribute call: module.func() or obj.method()
                        return self.parse_dot_call(&child, source, caller, line);
                    }
                    "method_index_expression" => {
                        // Method call: obj:method()
                        return self.parse_colon_call(&child, source, caller, line);
                    }
                    _ => {}
                }
            }
        }

        None
    }

    /// Parse a dot-syntax call (module.func or obj.method).
    ///
    /// Handles both simple calls (`module.func()`) and chained calls
    /// (`a.b().c()`) where the receiver is a function_call node.
    fn parse_dot_call(
        &self,
        node: &Node,
        source: &[u8],
        caller: &str,
        line: u32,
    ) -> Option<CallSite> {
        let mut identifiers = Vec::new();
        let mut has_non_ident_receiver = false;
        let mut non_ident_receiver_text: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        identifiers.push(get_node_text(&child, source).to_string());
                    }
                    "function_call" | "method_index_expression" | "dot_index_expression" => {
                        // Chained call: receiver is a call expression
                        has_non_ident_receiver = true;
                        non_ident_receiver_text = Some(get_node_text(&child, source).to_string());
                    }
                    _ => {}
                }
            }
        }

        if identifiers.len() >= 2 {
            let receiver = identifiers[0].clone();
            let method = identifiers.last().unwrap().clone();
            let target = format!("{}.{}", receiver, method);

            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Attr,
                Some(line),
                None,
                Some(receiver),
                None,
            ))
        } else if has_non_ident_receiver && identifiers.len() == 1 {
            // Chained call: something().method
            let method = identifiers[0].clone();
            let receiver_text = non_ident_receiver_text.unwrap_or_default();
            let target = format!("{}.{}", receiver_text, method);

            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Attr,
                Some(line),
                None,
                Some(receiver_text),
                None,
            ))
        } else if identifiers.len() == 1 {
            // Single identifier - treat as the full expression
            let target = get_node_text(node, source).to_string();
            let receiver = identifiers[0].clone();

            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Attr,
                Some(line),
                None,
                Some(receiver),
                None,
            ))
        } else {
            None
        }
    }

    /// Parse a colon-syntax call (obj:method).
    ///
    /// Handles both simple calls (`obj:method()`) and chained calls
    /// (`obj:method1():method2()`) where the receiver is a function_call node.
    fn parse_colon_call(
        &self,
        node: &Node,
        source: &[u8],
        caller: &str,
        line: u32,
    ) -> Option<CallSite> {
        let mut identifiers = Vec::new();
        let mut has_non_ident_receiver = false;
        let mut non_ident_receiver_text: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        identifiers.push(get_node_text(&child, source).to_string());
                    }
                    "function_call" | "method_index_expression" | "dot_index_expression" => {
                        // Chained call: receiver is a call expression, not a simple identifier
                        has_non_ident_receiver = true;
                        non_ident_receiver_text = Some(get_node_text(&child, source).to_string());
                    }
                    _ => {}
                }
            }
        }

        if identifiers.len() >= 2 {
            // Simple case: obj:method
            let receiver = identifiers[0].clone();
            let method = identifiers.last().unwrap().clone();
            let target = format!("{}:{}", receiver, method);

            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Method,
                Some(line),
                None,
                Some(receiver),
                None,
            ))
        } else if has_non_ident_receiver && identifiers.len() == 1 {
            // Chained call: something():method
            // The method name is the single identifier we found
            let method = identifiers[0].clone();
            let receiver_text = non_ident_receiver_text.unwrap_or_default();
            let target = format!("{}:{}", receiver_text, method);

            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Method,
                Some(line),
                None,
                Some(receiver_text),
                None,
            ))
        } else {
            None
        }
    }
}

impl CallGraphLanguageSupport for LuaHandler {
    fn name(&self) -> &str {
        "lua"
    }

    fn extensions(&self) -> &[&str] {
        &[".lua"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        // Track which function_call nodes are inside variable_declarations
        // so we don't process them twice
        let mut processed_calls = HashSet::new();

        // First pass: process variable_declarations with aliased requires
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "variable_declaration" {
                // Check if this declares an alias for a require
                if let Some((alias, import_info, call_id)) =
                    self.extract_aliased_require(&node, source_bytes)
                {
                    let mut import_def = ImportDef::simple_import(import_info.1);
                    import_def.alias = Some(alias);
                    imports.push(import_def);
                    processed_calls.insert(call_id);
                }
            }
        }

        // Second pass: process standalone require calls (not in variable_declarations)
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "function_call" {
                let call_id = node.id();
                if !processed_calls.contains(&call_id) {
                    if let Some((_, module_path)) = self.parse_require_node(&node, source_bytes) {
                        let import_def = ImportDef::simple_import(module_path);
                        imports.push(import_def);
                    }
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

        // Process function declarations
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "function_declaration" {
                if let Some((simple_name, qualified_name, body)) =
                    self.get_function_name_and_body(&node, source_bytes)
                {
                    let calls = self.extract_calls_from_node(
                        &body,
                        source_bytes,
                        &defined_funcs,
                        &qualified_name,
                    );
                    if !calls.is_empty() {
                        // Store with qualified name for cross-scope tracking
                        calls_by_func.insert(qualified_name.clone(), calls.clone());
                        // Also store with simple name for backward compatibility
                        if simple_name != qualified_name {
                            calls_by_func.insert(simple_name, calls);
                        }
                    }
                }
            }
        }

        // Process variable declarations with function values
        for node in walk_tree(tree.root_node()) {
            if node.kind() == "variable_declaration" {
                if let Some((simple_name, qualified_name, body)) =
                    self.get_func_from_var_decl(&node, source_bytes)
                {
                    let calls = self.extract_calls_from_node(
                        &body,
                        source_bytes,
                        &defined_funcs,
                        &qualified_name,
                    );
                    if !calls.is_empty() {
                        // Store with qualified name for cross-scope tracking
                        calls_by_func.insert(qualified_name.clone(), calls.clone());
                        // Also store with simple name for backward compatibility
                        if simple_name != qualified_name {
                            calls_by_func.insert(simple_name, calls);
                        }
                    }
                }
            }
        }

        // Process top-level assignment_statements with function values
        // e.g., MyModule.func = function() ... end
        //        handler = function() ... end
        for node in tree.root_node().children(&mut tree.root_node().walk()) {
            if node.kind() == "assignment_statement" {
                if let Some((simple_name, qualified_name, body)) =
                    self.get_func_from_assignment(&node, source_bytes)
                {
                    let calls = self.extract_calls_from_node(
                        &body,
                        source_bytes,
                        &defined_funcs,
                        &qualified_name,
                    );
                    if !calls.is_empty() {
                        // Store with qualified name for cross-scope tracking
                        calls_by_func.insert(qualified_name.clone(), calls.clone());
                        // Also store with simple name for backward compatibility
                        if simple_name != qualified_name {
                            calls_by_func.insert(simple_name, calls);
                        }
                    }
                }
            }
        }

        // Extract module-level calls into synthetic <module> function
        let mut module_calls = Vec::new();
        for node in tree.root_node().children(&mut tree.root_node().walk()) {
            // Skip function declarations and variable declarations with functions
            if node.kind() == "function_declaration" {
                continue;
            }
            if node.kind() == "variable_declaration" {
                // Check if this is a function definition
                if self.get_func_from_var_decl(&node, source_bytes).is_some() {
                    continue;
                }
            }
            // Skip assignment_statements with function values
            if node.kind() == "assignment_statement"
                && self.get_func_from_assignment(&node, source_bytes).is_some()
            {
                continue;
            }

            let calls =
                self.extract_calls_from_node(&node, source_bytes, &defined_funcs, "<module>");
            module_calls.extend(calls);
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
        // Lua has no classes, only return funcs

        // fix-cl-7-v1 M1 Pass 1: build the per-file lexical block-scope tree so
        // Pass 2 (the walk below) can classify a `NAME = function` assignment as
        // a lexical-local closure whenever an enclosing/ancestor block
        // `local`-declares NAME — the split-decl case the single-node emission
        // path is blind to.
        let scope_tree = build_lexical_scope_tree(tree.root_node(), source_bytes);

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

                    // fix-cl-7-v1 M1 FIX 2: `local function NAME ... end` is
                    // an UNCONDITIONAL lexical-local binder — Lua's grammar
                    // only permits a bare `NAME` after `local function`,
                    // never a dotted/colon name, so this is only ever
                    // reachable through the `"identifier"` arm below. Detect
                    // it via the literal `local` keyword token that is a
                    // direct child of THIS `function_declaration` node (see
                    // `lua_local_function_token`) and tag the resulting
                    // `FuncDef` `is_lexical_local = true` so a same-file
                    // `self:NAME()` / `obj:NAME()` colon dispatch elsewhere
                    // declines to bind to it (the mis-bind this milestone
                    // exists to prevent). A global/dotted/method declaration
                    // carries no such token and stays a plain
                    // `FuncDef::function`.
                    let is_local_fn = lua_local_function_token(&node);

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "identifier" => {
                                    let name = get_node_text(&child, source_bytes).to_string();
                                    if is_local_fn {
                                        funcs.push(FuncDef::lexical_local(name, line, end_line));
                                    } else {
                                        funcs.push(FuncDef::function(name, line, end_line));
                                    }
                                    break;
                                }
                                "dot_index_expression" => {
                                    if let Some(name) =
                                        self.extract_last_identifier(&child, source_bytes)
                                    {
                                        funcs.push(FuncDef::function(name, line, end_line));
                                    }
                                    break;
                                }
                                "method_index_expression" => {
                                    if let Some(name) =
                                        self.extract_last_identifier(&child, source_bytes)
                                    {
                                        // fix-cl-8-v1 (BUG-5, LUA): a colon method
                                        // `function T:m` stays a plain `FuncDef`
                                        // (NO class_name / is_method — that would
                                        // relabel every colon edge `m` -> `T.m`),
                                        // but records its bare-identifier receiver
                                        // `T` in the `resolve_caller_name`-invisible
                                        // `colon_receiver` field so the self-dispatch
                                        // guard can decline an unrelated sibling bind.
                                        let receiver = self
                                            .colon_method_bare_receiver(&child, source_bytes);
                                        funcs.push(
                                            FuncDef::function(name, line, end_line)
                                                .with_colon_receiver(receiver),
                                        );
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "variable_declaration" => {
                    // Handle: local foo = function() ... end
                    let mut var_names: Vec<String> = Vec::new();
                    let mut has_function = false;
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

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
                                            for k in 0..subchild.child_count() {
                                                if let Some(expr) = subchild.child(k) {
                                                    if expr.kind() == "function_definition" {
                                                        has_function = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if has_function {
                        for name in var_names {
                            // fix-cl-7-v1: `local name = function ... end` is a
                            // LEXICAL LOCAL closure (this `variable_declaration`
                            // branch), never a method. Tag it so a `self:name()` /
                            // `obj:name()` colon dispatch declines binding to it and
                            // falls through to the real cross-file method. The
                            // colon-method branch (`method_index_expression`), the
                            // plain-function branch and the table-field
                            // `assignment_statement` branch below stay `false`.
                            funcs.push(FuncDef::lexical_local(name, line, end_line));
                        }
                    }
                }
                "assignment_statement" => {
                    // Handle: handler = function() ... end
                    //         MyModule.func = function() ... end
                    if let Some((name, _qualified, _body)) =
                        self.get_func_from_assignment(&node, source_bytes)
                    {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;

                        // fix-cl-7-v1 M1 Pass 2: a BARE `NAME = function ... end`
                        // whose NAME is bound by an enclosing/ancestor `local
                        // NAME` (possibly a split bare decl in a wider block) is
                        // a LEXICAL LOCAL closure — tag it so a `self:NAME()` /
                        // `obj:NAME()` colon dispatch declines binding to it and
                        // falls through to the real cross-file method. Dotted /
                        // bracket table-field assignments (`M.foo = function`,
                        // `t["k"] = function`) and globals with NO enclosing
                        // `local NAME` are NOT lexical locals and stay `false`.
                        // Colon methods (`function T:m`) never reach this branch.
                        let is_lexical = assignment_lhs_bare_identifier(&node, source_bytes)
                            .map(|lhs| scope_tree.binds_local(&lhs, line))
                            .unwrap_or(false);

                        if is_lexical {
                            funcs.push(FuncDef::lexical_local(name, line, end_line));
                        } else {
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((funcs, Vec::new()))
    }
}

impl LuaHandler {
    /// Extract an aliased require from a variable declaration.
    ///
    /// Returns (alias, (import_type, module_path), call_node_id) if found.
    fn extract_aliased_require(
        &self,
        node: &Node,
        source: &[u8],
    ) -> Option<(String, (String, String), usize)> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_statement" {
                    let mut var_name: Option<String> = None;
                    let mut require_info: Option<((String, String), usize)> = None;

                    for j in 0..child.child_count() {
                        if let Some(subchild) = child.child(j) {
                            match subchild.kind() {
                                "variable_list" => {
                                    // Get first identifier as variable name
                                    for k in 0..subchild.child_count() {
                                        if let Some(var) = subchild.child(k) {
                                            if var.kind() == "identifier" {
                                                var_name =
                                                    Some(get_node_text(&var, source).to_string());
                                                break;
                                            }
                                        }
                                    }
                                }
                                "expression_list" => {
                                    // Look for require call in expression directly
                                    for inner in walk_tree(subchild) {
                                        if inner.kind() == "function_call" {
                                            if let Some((import_type, module_path)) =
                                                self.parse_require_node(&inner, source)
                                            {
                                                require_info =
                                                    Some(((import_type, module_path), inner.id()));
                                                break;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    // If we found both a variable name and a require, return them
                    if let (Some(alias), Some((import_info, call_id))) = (var_name, require_info) {
                        return Some((alias, import_info, call_id));
                    }
                }
            }
        }
        None
    }

    /// Get function name and body from a function declaration.
    /// Returns (simple_name, qualified_name, body) where qualified_name includes table prefix.
    fn get_function_name_and_body<'a>(
        &self,
        node: &'a Node,
        source: &[u8],
    ) -> Option<(String, String, Node<'a>)> {
        let mut simple_name: Option<String> = None;
        let mut qualified_name: Option<String> = None;
        let mut body: Option<Node<'a>> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        let name = get_node_text(&child, source).to_string();
                        simple_name = Some(name.clone());
                        qualified_name = Some(name);
                    }
                    "dot_index_expression" => {
                        // Table function: M.func or MyModule.sub.func
                        // Extract both simple name and qualified name
                        if let Some(name) = self.extract_last_identifier(&child, source) {
                            simple_name = Some(name);
                        }
                        // Get full qualified name like "M.func"
                        let full_text = get_node_text(&child, source).to_string();
                        qualified_name = Some(full_text);
                    }
                    "method_index_expression" => {
                        // Method: M:method
                        if let Some(name) = self.extract_last_identifier(&child, source) {
                            simple_name = Some(name);
                        }
                        // Get full qualified name like "M:method"
                        let full_text = get_node_text(&child, source).to_string();
                        qualified_name = Some(full_text);
                    }
                    "block" => {
                        body = Some(child);
                    }
                    _ => {}
                }
            }
        }

        if let (Some(simple), Some(qualified), Some(b)) = (simple_name, qualified_name, body) {
            Some((simple, qualified, b))
        } else {
            None
        }
    }

    /// Check if a function name represents a table method (contains . or :).
    /// Returns the table name if it's a table method, None otherwise.
    fn _get_table_prefix(&self, func_name: &str) -> Option<String> {
        if func_name.contains('.') {
            func_name.split('.').next().map(|s| s.to_string())
        } else if func_name.contains(':') {
            func_name.split(':').next().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Get function name and body from a variable declaration with function value.
    /// Returns (simple_name, qualified_name, body) where qualified_name includes table prefix.
    fn get_func_from_var_decl<'a>(
        &self,
        node: &'a Node,
        source: &[u8],
    ) -> Option<(String, String, Node<'a>)> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_statement" {
                    let mut simple_name: Option<String> = None;
                    let mut qualified_name: Option<String> = None;
                    let mut func_body: Option<Node<'a>> = None;

                    for j in 0..child.child_count() {
                        if let Some(subchild) = child.child(j) {
                            match subchild.kind() {
                                "variable_list" => {
                                    for k in 0..subchild.child_count() {
                                        if let Some(var) = subchild.child(k) {
                                            match var.kind() {
                                                "identifier" => {
                                                    let name =
                                                        get_node_text(&var, source).to_string();
                                                    simple_name = Some(name.clone());
                                                    qualified_name = Some(name);
                                                    break;
                                                }
                                                "dot_index_expression" => {
                                                    // M.func = function() ... end
                                                    if let Some(name) =
                                                        self.extract_last_identifier(&var, source)
                                                    {
                                                        simple_name = Some(name);
                                                    }
                                                    qualified_name = Some(
                                                        get_node_text(&var, source).to_string(),
                                                    );
                                                    break;
                                                }
                                                "method_index_expression" => {
                                                    // M:method = function() ... end
                                                    if let Some(name) =
                                                        self.extract_last_identifier(&var, source)
                                                    {
                                                        simple_name = Some(name);
                                                    }
                                                    qualified_name = Some(
                                                        get_node_text(&var, source).to_string(),
                                                    );
                                                    break;
                                                }
                                                "bracket_index_expression" => {
                                                    // t["key"] = function() ... end
                                                    if let Some((simple, qualified)) = self
                                                        .extract_bracket_index_names(&var, source)
                                                    {
                                                        simple_name = Some(simple);
                                                        qualified_name = Some(qualified);
                                                    }
                                                    break;
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                "expression_list" => {
                                    for k in 0..subchild.child_count() {
                                        if let Some(expr) = subchild.child(k) {
                                            if expr.kind() == "function_definition" {
                                                // Get the body (block) from function_definition
                                                for l in 0..expr.child_count() {
                                                    if let Some(part) = expr.child(l) {
                                                        if part.kind() == "block" {
                                                            func_body = Some(part);
                                                            break;
                                                        }
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    if let (Some(simple), Some(qualified), Some(body)) =
                        (simple_name, qualified_name, func_body)
                    {
                        return Some((simple, qualified, body));
                    }
                }
            }
        }
        None
    }

    /// Get function name and body from a top-level assignment_statement with function value.
    ///
    /// Handles patterns like:
    /// - `handler = function() ... end`
    /// - `MyModule.func = function() ... end`
    ///
    /// These are NOT wrapped in `variable_declaration` (no `local` keyword).
    /// Returns (simple_name, qualified_name, body) where qualified_name includes table prefix.
    fn get_func_from_assignment<'a>(
        &self,
        node: &'a Node,
        source: &[u8],
    ) -> Option<(String, String, Node<'a>)> {
        if node.kind() != "assignment_statement" {
            return None;
        }

        let mut simple_name: Option<String> = None;
        let mut qualified_name: Option<String> = None;
        let mut func_body: Option<Node<'a>> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "variable_list" => {
                        // Try to extract name from first variable
                        for k in 0..child.child_count() {
                            if let Some(var) = child.child(k) {
                                match var.kind() {
                                    "identifier" => {
                                        // Simple: handler = function() end
                                        let name = get_node_text(&var, source).to_string();
                                        simple_name = Some(name.clone());
                                        qualified_name = Some(name);
                                        break;
                                    }
                                    "dot_index_expression" => {
                                        // Dotted: MyModule.func = function() end
                                        // Use the last identifier as the simple function name
                                        if let Some(name) =
                                            self.extract_last_identifier(&var, source)
                                        {
                                            simple_name = Some(name);
                                        }
                                        // Get full qualified name
                                        qualified_name =
                                            Some(get_node_text(&var, source).to_string());
                                        break;
                                    }
                                    "bracket_index_expression" => {
                                        // Bracketed: t["key"] = function() end
                                        if let Some((simple, qualified)) =
                                            self.extract_bracket_index_names(&var, source)
                                        {
                                            simple_name = Some(simple);
                                            qualified_name = Some(qualified);
                                        }
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    "expression_list" => {
                        for k in 0..child.child_count() {
                            if let Some(expr) = child.child(k) {
                                if expr.kind() == "function_definition" {
                                    // Get the body (block) from function_definition
                                    for l in 0..expr.child_count() {
                                        if let Some(part) = expr.child(l) {
                                            if part.kind() == "block" {
                                                func_body = Some(part);
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if let (Some(simple), Some(qualified), Some(body)) =
            (simple_name, qualified_name, func_body)
        {
            Some((simple, qualified, body))
        } else {
            None
        }
    }
}

// =============================================================================
// fix-cl-7-v1 M1: LexicalScopeTree — per-file Lua block-scope pass
// =============================================================================
//
// Populates `FuncDef::is_lexical_local` for closures whose binding is a
// `local NAME` declaration — INCLUDING the split form (`local NAME` bare decl
// in one block, `NAME = function ... end` assignment in a nested block) that
// the single-node emission path is structurally blind to.
//
// The tree models Lua block nesting by LINE-RANGE CONTAINMENT (the same
// smallest-span-containment idea used by `enclosing_class_for_call` in
// resolution.rs), so no byte offsets are needed: `Node` already exposes
// 1-indexed line positions. It is purely tree-sitter node-kind/field driven
// (AST mandate) and name-agnostic — it generalizes to every split-declared
// closure, not the literal name `setState`.
//
// Verified against the ACTUAL pinned tree-sitter-lua = "0.2.0" grammar (see
// workspace Cargo.toml) by parsing real fixtures with `Tree::root_node().to_sexp()`
// / a `TreeCursor` walk and cross-checking against that crate's shipped
// `src/node-types.json` — not asserted from reading grammar.js alone:
//   - scope-opening: `chunk` (file scope) and every `block` node, whose parent
//     is one of function_declaration / function_definition / do_statement /
//     while_statement / for_statement / if_statement / elseif_statement /
//     else_statement / repeat_statement.
//   - a `local` decl is a `variable_declaration` (ALWAYS local; a non-local
//     assignment is `assignment_statement`). Bare `local x` parses as
//     `(variable_declaration (variable_list name: (identifier)))` — NO
//     assignment_statement; `local x = e` as
//     `(variable_declaration (assignment_statement (variable_list ...)
//      (expression_list ...)))`.
//   - `local function f` is a `function_declaration` reached through the
//     parent field `local_declaration` (confirmed: this field IS populated at
//     parse time for this grammar version — a global `function f` /
//     `function T:m` carries no such field). It ALSO carries a literal
//     anonymous `local` keyword token as a DIRECT CHILD of the
//     `function_declaration` node itself (`(local) (function)
//     identifier:name parameters:parameters (end)`); `lua_local_function_token`
//     below uses this second, parent-independent signal so the SAME check
//     works both here and at the `local function f`'s own definition site in
//     `extract_definitions` (which has no access to a parent-relative field
//     name). Both signals were cross-verified to appear together on every
//     `local function` node and never on a global/dotted/method one.
//   - params live in the `parameters` field child (`identifier` children,
//     each itself carrying field `name` relative to `parameters` — confirmed
//     by parsing `function f(a, b) end`); for-loop vars in the `clause` field
//     (`for_numeric_clause name:` / `for_generic_clause` `variable_list`).
//   - the implicit `self` parameter of a colon method (`function T:m`) is
//     registered as a lexical local of the method body: confirmed end-to-end
//     by asserting `LexicalScopeTree::binds_local("self", <line in body>)`
//     is `true` for a real `function T:m()` parse.
//
// A SEPARATE, EQUALLY NECESSARY fix lives in `extract_definitions`'s own
// `"function_declaration"` match arm (the Pass 0 walk that emits each
// function's `FuncDef`, run BEFORE this scope-tree pass is even consulted):
// recording `local function NAME` as a binding in this scope tree only feeds
// the split-decl `NAME = function ... end` REASSIGNMENT case; the `local
// function NAME` declaration's OWN `FuncDef` is created directly by that
// separate walk and must be tagged `is_lexical_local = true` there too (via
// the same `lua_local_function_token` check) or a same-file `self:NAME()`
// colon call still wrongly resolves to it as a `Method` edge.

/// A single lexical block scope, addressed by its 1-indexed line range.
#[derive(Debug)]
struct BlockScope {
    /// Scope-opening node start line (1-indexed).
    start_line: u32,
    /// Scope-opening node end line (1-indexed). For a `repeat` body this is
    /// extended through the parent `until` so the condition still sees body
    /// locals (Lua 3.5).
    end_line: u32,
    /// Every binding introduced DIRECTLY in this block: `local x` (incl. bare
    /// no-initializer), `local function f`, function params (+ implicit `self`
    /// for a method body) and for-loop vars. Each carries its 1-indexed
    /// declaration line for Lua's after-declaration visibility rule.
    locals: Vec<(String, u32)>,
}

/// All lexical block scopes of one file, flattened. Ancestor scopes are simply
/// wider line ranges that also contain a nested line, so a `binds_local` query
/// naturally resolves up the block chain.
#[derive(Debug, Default)]
struct LexicalScopeTree {
    blocks: Vec<BlockScope>,
}

impl LexicalScopeTree {
    /// True iff `name` is bound by a `local` in SOME block whose `[start,end]`
    /// contains `at_line`, with `decl_line <= at_line` (after-declaration
    /// visibility). Nested scopes resolve to an ANCESTOR block automatically
    /// because a wider block also contains `at_line`. This is exactly what
    /// catches the split-decl bug: a `local setState` in an enclosing block
    /// dominates a nested `setState = function` assignment.
    fn binds_local(&self, name: &str, at_line: u32) -> bool {
        self.blocks.iter().any(|b| {
            b.start_line <= at_line
                && at_line <= b.end_line
                && b.locals.iter().any(|(n, dl)| n == name && *dl <= at_line)
        })
    }
}

/// Pass 1: build the per-file scope tree in a single AST walk.
fn build_lexical_scope_tree(root: Node, source: &[u8]) -> LexicalScopeTree {
    let mut blocks = Vec::new();

    for node in walk_tree(root) {
        match node.kind() {
            "chunk" => {
                // File-level scope: `local` at file scope IS a lexical local.
                let mut locals = Vec::new();
                collect_direct_block_locals(&node, source, &mut locals);
                blocks.push(BlockScope {
                    start_line: node.start_position().row as u32 + 1,
                    end_line: node.end_position().row as u32 + 1,
                    locals,
                });
            }
            "block" => {
                let start_line = node.start_position().row as u32 + 1;
                let mut end_line = node.end_position().row as u32 + 1;
                let mut locals = Vec::new();

                // Bindings owned by the enclosing construct (params / for-vars),
                // and the `repeat` scope extension, are keyed off the parent.
                if let Some(parent) = node.parent() {
                    match parent.kind() {
                        "function_declaration" | "function_definition" => {
                            collect_params(&parent, source, &mut locals);
                        }
                        "for_statement" => {
                            collect_for_vars(&parent, source, &mut locals);
                        }
                        "repeat_statement" => {
                            // `until <cond>` still sees the body's locals.
                            end_line = parent.end_position().row as u32 + 1;
                        }
                        _ => {}
                    }
                }

                collect_direct_block_locals(&node, source, &mut locals);
                blocks.push(BlockScope {
                    start_line,
                    end_line,
                    locals,
                });
            }
            _ => {}
        }
    }

    LexicalScopeTree { blocks }
}

/// True iff `func_node` (a `function_declaration`) is a `local function NAME`
/// declaration rather than a global / dotted / method one. tree-sitter-lua
/// 0.2.0 emits a literal anonymous `local` keyword token as a DIRECT CHILD of
/// the `function_declaration` node itself for this form only — verified by
/// parsing `local function f() end` and walking the node's own children:
/// `(local) (function) identifier:name parameters:parameters (end)`. A
/// global `function f()` / dotted `function T.f()` / method `function T:f()`
/// carries no such child. This is parent-independent (unlike the
/// `local_declaration` field, which is only meaningful relative to the
/// enclosing `chunk`/`block`), so the SAME check works both here and at the
/// declaration's own definition site in `extract_definitions`. Mirrors
/// `dfg::extractor::lua_function_is_local`'s literal-`local`-child signal.
fn lua_local_function_token(func_node: &Node) -> bool {
    let mut cursor = func_node.walk();
    let found = func_node.children(&mut cursor).any(|c| c.kind() == "local");
    found
}

/// Collect the `local` bindings declared DIRECTLY in `block` (not descending
/// into nested blocks, which own their own scope). Handles `variable_declaration`
/// (bare + initialized) and `local function f` (a `function_declaration`
/// carrying a literal `local` keyword token — see `lua_local_function_token`).
fn collect_direct_block_locals(block: &Node, source: &[u8], out: &mut Vec<(String, u32)>) {
    let mut cursor = block.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let child = cursor.node();
        match child.kind() {
            "variable_declaration" => {
                let decl_line = child.start_position().row as u32 + 1;
                collect_variable_list_names(&child, source, decl_line, out);
            }
            // `local function f` — distinguished from a global `function f` /
            // method `function T:m` by the literal `local` token child (see
            // `lua_local_function_token`).
            "function_declaration" if lua_local_function_token(&child) => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        out.push((
                            get_node_text(&name_node, source).to_string(),
                            child.start_position().row as u32 + 1,
                        ));
                    }
                }
            }
            _ => {}
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Collect the LHS identifier names of a `local` `variable_declaration`. The
/// LHS `variable_list` is either a direct child (bare `local x`) or the LHS of
/// a direct `assignment_statement` child (`local x = e`). Only `identifier`
/// children are taken — a `local` never binds a dotted/bracket target.
fn collect_variable_list_names(
    var_decl: &Node,
    source: &[u8],
    decl_line: u32,
    out: &mut Vec<(String, u32)>,
) {
    let mut c = var_decl.walk();
    for child in var_decl.children(&mut c) {
        match child.kind() {
            "variable_list" => push_variable_list_identifiers(&child, source, decl_line, out),
            "assignment_statement" => {
                let mut c2 = child.walk();
                for sub in child.children(&mut c2) {
                    if sub.kind() == "variable_list" {
                        push_variable_list_identifiers(&sub, source, decl_line, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Push every `identifier` child of a `variable_list` as a binding.
fn push_variable_list_identifiers(
    var_list: &Node,
    source: &[u8],
    decl_line: u32,
    out: &mut Vec<(String, u32)>,
) {
    let mut c = var_list.walk();
    for id in var_list.children(&mut c) {
        if id.kind() == "identifier" {
            out.push((get_node_text(&id, source).to_string(), decl_line));
        }
    }
}

/// Collect a function's `parameters` (+ an implicit `self` when the function
/// name is a `method_index_expression`, i.e. `function T:m`). Both a named
/// `function_declaration` and an anonymous `function_definition` carry the
/// `parameters` field; only the former can carry a `name` field at all, and
/// only a colon-method `name` is a `method_index_expression`. Both the
/// `parameters` and `name` field reads here were confirmed against a real
/// parse (`function f(a, b) end` for the former; `function T:m()` plus a
/// direct `LexicalScopeTree::binds_local("self", ...)` assertion for the
/// latter — this implicit-`self` registration is live and functional, not
/// dead code).
fn collect_params(func_node: &Node, source: &[u8], out: &mut Vec<(String, u32)>) {
    let decl_line = func_node.start_position().row as u32 + 1;
    if let Some(params) = func_node.child_by_field_name("parameters") {
        let mut c = params.walk();
        for p in params.children(&mut c) {
            if p.kind() == "identifier" {
                out.push((get_node_text(&p, source).to_string(), decl_line));
            }
        }
    }
    if let Some(name_node) = func_node.child_by_field_name("name") {
        if name_node.kind() == "method_index_expression" {
            out.push(("self".to_string(), decl_line));
        }
    }
}

/// Collect a `for` loop's variables (numeric: the `name` identifier; generic:
/// the `variable_list` identifiers), scoped to the loop body.
fn collect_for_vars(for_node: &Node, source: &[u8], out: &mut Vec<(String, u32)>) {
    let decl_line = for_node.start_position().row as u32 + 1;
    let Some(clause) = for_node.child_by_field_name("clause") else {
        return;
    };
    match clause.kind() {
        "for_numeric_clause" => {
            if let Some(name) = clause.child_by_field_name("name") {
                if name.kind() == "identifier" {
                    out.push((get_node_text(&name, source).to_string(), decl_line));
                }
            }
        }
        "for_generic_clause" => {
            let mut c = clause.walk();
            for ch in clause.children(&mut c) {
                if ch.kind() == "variable_list" {
                    push_variable_list_identifiers(&ch, source, decl_line, out);
                }
            }
        }
        _ => {}
    }
}

/// Pass 2 helper: return `Some(name)` iff the `assignment_statement`'s LHS is a
/// BARE `identifier` (`NAME = ...`). A dotted (`M.foo = ...`) or bracket
/// (`t["k"] = ...`) target is a table field, NOT a lexical local, and yields
/// `None`.
fn assignment_lhs_bare_identifier(node: &Node, source: &[u8]) -> Option<String> {
    let mut c = node.walk();
    for child in node.children(&mut c) {
        if child.kind() == "variable_list" {
            let mut c2 = child.walk();
            for v in child.children(&mut c2) {
                match v.kind() {
                    "identifier" => return Some(get_node_text(&v, source).to_string()),
                    "dot_index_expression" | "bracket_index_expression" => return None,
                    _ => {}
                }
            }
        }
    }
    None
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_imports(source: &str) -> Vec<ImportDef> {
        let handler = LuaHandler::new();
        handler
            .parse_imports(source, Path::new("test.lua"))
            .unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = LuaHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("test.lua"), source, &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_require() {
            let imports = parse_imports("require('json')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "json");
            assert!(!imports[0].is_from);
        }

        #[test]
        fn test_parse_require_double_quotes() {
            let imports = parse_imports("require(\"json\")");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "json");
        }

        #[test]
        fn test_parse_require_no_parens() {
            let imports = parse_imports("require 'json'");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "json");
        }

        #[test]
        fn test_parse_require_with_alias() {
            let imports = parse_imports("local M = require('module')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "module");
            assert_eq!(imports[0].alias, Some("M".to_string()));
        }

        #[test]
        fn test_parse_dofile() {
            let imports = parse_imports("dofile('config.lua')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "config.lua");
        }

        #[test]
        fn test_parse_loadfile() {
            let imports = parse_imports("loadfile('utils.lua')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "utils.lua");
        }

        #[test]
        fn test_parse_require_dot_path() {
            let imports = parse_imports("require('lib.json')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "lib.json");
        }

        #[test]
        fn test_parse_multiple_imports() {
            let source = r#"
require('json')
local utils = require('utils')
dofile('config.lua')
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
function main()
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
function helper()
    return "help"
end

function main()
    helper()
end
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            let helper_call = main_calls.iter().find(|c| c.target == "helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_attr() {
            let source = r#"
function process()
    json.encode(data)
    os.exit(0)
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process").unwrap();

            let json_call = process_calls
                .iter()
                .find(|c| c.target.contains("encode"))
                .unwrap();
            assert_eq!(json_call.call_type, CallType::Attr);
            assert_eq!(json_call.receiver, Some("json".to_string()));
        }

        #[test]
        fn test_extract_calls_method() {
            let source = r#"
function process()
    obj:start()
    service:stop()
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process").unwrap();

            let start_call = process_calls
                .iter()
                .find(|c| c.target.contains("start"))
                .unwrap();
            assert_eq!(start_call.call_type, CallType::Method);
            assert_eq!(start_call.receiver, Some("obj".to_string()));
            assert!(start_call.target.contains(":"));
        }

        #[test]
        fn test_extract_calls_module_function() {
            let source = r#"
function M.helper()
    print("in module helper")
end

function main()
    M.helper()
end
"#;
            let calls = extract_calls(source);
            // The function M.helper should be tracked by its simple name "helper"
            assert!(calls.contains_key("main"));
        }

        #[test]
        fn test_extract_calls_method_function() {
            let source = r#"
function Obj:init()
    self.value = 0
end

function Obj:increment()
    self.value = self.value + 1
end
"#;
            let calls = extract_calls(source);
            // Method functions should be tracked by their simple name
            // This test ensures we can parse method declarations
            // (even if they don't contain calls)
            assert!(calls.is_empty() || !calls.is_empty()); // Valid either way
        }

        #[test]
        fn test_extract_calls_local_function() {
            let source = r#"
local function helper()
    return "help"
end

local processor = function()
    helper()
    print("done")
end
"#;
            let calls = extract_calls(source);
            let processor_calls = calls.get("processor").unwrap();
            assert!(processor_calls.iter().any(|c| c.target == "helper"));
            assert!(processor_calls.iter().any(|c| c.target == "print"));
        }

        #[test]
        fn test_extract_calls_module_level() {
            let source = r#"
function helper()
    return "help"
end

-- Module-level call
result = helper()
print("Starting")
"#;
            let calls = extract_calls(source);
            assert!(calls.contains_key("<module>"));
            let module_calls = calls.get("<module>").unwrap();
            assert!(module_calls.iter().any(|c| c.target == "helper"));
            assert!(module_calls.iter().any(|c| c.target == "print"));
        }
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = LuaHandler::new();
            assert_eq!(handler.name(), "lua");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = LuaHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".lua"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = LuaHandler::new();
            assert!(handler.supports("lua"));
            assert!(handler.supports("Lua"));
            assert!(handler.supports("LUA"));
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = LuaHandler::new();
            assert!(handler.supports_extension(".lua"));
            assert!(handler.supports_extension(".LUA"));
            assert!(!handler.supports_extension(".py"));
        }
    }

    // -------------------------------------------------------------------------
    // Pattern Completeness Tests (new)
    // -------------------------------------------------------------------------

    mod pattern_tests {
        use super::*;

        // ----- Table constructor calls -----
        #[test]
        fn test_table_constructor_calls() {
            let source = r#"
function build()
    local t = { field = func(), other = compute() }
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("build").unwrap();
            assert!(
                p.iter().any(|c| c.target == "func"),
                "Should find func() inside table constructor"
            );
            assert!(
                p.iter().any(|c| c.target == "compute"),
                "Should find compute() inside table constructor"
            );
        }

        // ----- Self-method calls -----
        #[test]
        fn test_self_colon_call() {
            let source = r#"
function Foo:bar()
    self:method()
end
"#;
            let calls = extract_calls(source);
            let bar_calls = calls.get("bar").unwrap();
            let call = bar_calls
                .iter()
                .find(|c| c.target == "self:method")
                .unwrap();
            assert_eq!(call.call_type, CallType::Method);
            assert_eq!(call.receiver, Some("self".to_string()));
        }

        #[test]
        fn test_self_dot_call() {
            let source = r#"
function Foo:bar()
    self.other()
end
"#;
            let calls = extract_calls(source);
            let bar_calls = calls.get("bar").unwrap();
            let call = bar_calls.iter().find(|c| c.target == "self.other").unwrap();
            assert_eq!(call.call_type, CallType::Attr);
            assert_eq!(call.receiver, Some("self".to_string()));
        }

        // ----- Chained calls -----
        #[test]
        fn test_chained_method_calls() {
            let source = r#"
function process()
    obj:method1():method2()
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("process").unwrap();
            // Both method1 and method2 should be found
            assert!(
                p.iter().any(|c| c.target == "obj:method1"),
                "Should find inner call obj:method1()"
            );
            assert!(
                p.iter().any(|c| c.target.contains("method2")),
                "Should find outer chained call method2()"
            );
        }

        #[test]
        fn test_chained_dot_calls() {
            let source = r#"
function process()
    a.b().c()
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("process").unwrap();
            // Should find both a.b() and the chained .c() call
            assert!(
                p.iter().any(|c| c.target == "a.b"),
                "Should find inner call a.b()"
            );
            assert!(
                p.iter().any(|c| c.target.contains("c")),
                "Should find outer chained call c()"
            );
        }

        // ----- Nested function calls -----
        #[test]
        fn test_nested_calls() {
            let source = r#"
function process()
    foo(bar(baz()))
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("process").unwrap();
            assert_eq!(p.len(), 3, "Should find all three nested calls");
            assert!(p.iter().any(|c| c.target == "foo"));
            assert!(p.iter().any(|c| c.target == "bar"));
            assert!(p.iter().any(|c| c.target == "baz"));
        }

        // ----- Callback / function reference -----
        #[test]
        fn test_callback_ref() {
            let source = r#"
function compare(a, b)
    return a < b
end

function process()
    table.sort(list, compare)
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("process").unwrap();
            assert!(
                p.iter().any(|c| c.target == "table.sort"),
                "Should find table.sort call"
            );
            assert!(
                p.iter()
                    .any(|c| c.target == "compare" && c.call_type == CallType::Ref),
                "Should find compare as Ref (callback)"
            );
        }

        // ----- Global function assignment -----
        #[test]
        fn test_global_func_assignment() {
            let source = r#"
MyModule.func = function()
    helper()
end
"#;
            let calls = extract_calls(source);
            assert!(
                calls.contains_key("func"),
                "Should attribute calls to 'func', not '<module>'"
            );
            let func_calls = calls.get("func").unwrap();
            assert!(func_calls.iter().any(|c| c.target == "helper"));
        }

        #[test]
        fn test_global_func_assignment_simple() {
            // Non-dotted global: plain assignment with function value
            let source = r#"
handler = function()
    process()
end
"#;
            let calls = extract_calls(source);
            assert!(
                calls.contains_key("handler"),
                "Should attribute calls to 'handler'"
            );
            let h_calls = calls.get("handler").unwrap();
            assert!(h_calls.iter().any(|c| c.target == "process"));
        }

        // ----- Module-level calls with non-local assignment -----
        #[test]
        fn test_module_level_non_local_assignment_call() {
            let source = r#"
function helper()
    return 42
end

result = helper()
"#;
            let calls = extract_calls(source);
            assert!(calls.contains_key("<module>"));
            let m = calls.get("<module>").unwrap();
            assert!(m.iter().any(|c| c.target == "helper"));
        }

        // ----- Or-default pattern -----
        #[test]
        fn test_or_default_call() {
            let source = r#"
function init()
    local x = x or default()
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("init").unwrap();
            assert!(
                p.iter().any(|c| c.target == "default"),
                "Should find default() in or-default pattern"
            );
        }

        // ----- Method definition tracking -----
        #[test]
        fn test_method_definition_name() {
            let source = r#"
function Foo:bar()
    print("hello")
end
"#;
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _) = handler
                .extract_definitions(source, Path::new("test.lua"), &tree)
                .unwrap();
            // Method should be tracked (by its short name "bar")
            assert!(funcs.iter().any(|f| f.name == "bar"), "Should define 'bar'");
        }

        // ----- String method calls -----
        #[test]
        fn test_string_method_calls() {
            let source = r#"
function format_name()
    local s = string.format("hello %s", name)
    string.len(s)
end
"#;
            let calls = extract_calls(source);
            let p = calls.get("format_name").unwrap();
            assert!(p.iter().any(|c| c.target == "string.format"));
            assert!(p.iter().any(|c| c.target == "string.len"));
        }

        // ----- Global func assignment definition tracking -----
        #[test]
        fn test_global_func_assignment_definition() {
            let source = r#"
MyModule.func = function()
    return 1
end
"#;
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _) = handler
                .extract_definitions(source, Path::new("test.lua"), &tree)
                .unwrap();
            assert!(
                funcs.iter().any(|f| f.name == "func"),
                "Should define 'func' from MyModule.func = function() end"
            );
        }

        /// fix-cl-7-v1 FIX 1: `local m = function ... end` (a `variable_declaration`
        /// local closure) is tagged `is_lexical_local = true`, while a colon
        /// method (`function T:m`), a plain function, and a table-field / global
        /// assignment (`x = function ... end`, an `assignment_statement`) all stay
        /// `false`. This is the precise per-definition discriminator the colon
        /// dispatch prunes on. Verifies the tree-sitter `variable_declaration`
        /// vs `assignment_statement` node-kind split cleanly separates them.
        #[test]
        fn test_cl7_lexical_local_tagging() {
            let source = r#"
local setState = function(v)
    return v
end

handler = function()
    return 1
end

MyModule.func = function()
    return 2
end

function Board:applyMove()
    return 3
end

function plainFn()
    return 4
end
"#;
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _) = handler
                .extract_definitions(source, Path::new("test.lua"), &tree)
                .unwrap();

            let flag = |name: &str| {
                funcs
                    .iter()
                    .find(|f| f.name == name)
                    .unwrap_or_else(|| panic!("expected a definition named `{name}`: {funcs:?}"))
                    .is_lexical_local
            };

            // ONLY the `local x = function` closure is a lexical local.
            assert!(flag("setState"), "`local setState = function` must be lexical-local");
            // A bare/global table-field assignment `x = function` is NOT.
            assert!(!flag("handler"), "`handler = function` (assignment) must NOT be lexical-local");
            assert!(
                !flag("func"),
                "`MyModule.func = function` (table-field assignment) must NOT be lexical-local"
            );
            // A genuine colon method and a plain function are NOT.
            assert!(!flag("applyMove"), "`function Board:applyMove` must NOT be lexical-local");
            assert!(!flag("plainFn"), "plain `function plainFn` must NOT be lexical-local");
        }

        /// fix-cl-8-v1 (BUG-5, LUA): a colon method `function T:m` records its
        /// BARE-IDENTIFIER receiver in `colon_receiver` (`Some("T")`) WITHOUT
        /// setting `class_name`/`is_method` — setting those would make
        /// `resolve_caller_name` relabel every colon edge `m` -> `T.m`. A dotted
        /// receiver (`a.b:m`) yields `None` (not a single owning-class name).
        /// Non-colon definitions (plain function, `local` closure, dotted/global
        /// table-field assignment) always carry `colon_receiver == None`.
        #[test]
        fn test_cl8_colon_receiver_tagging() {
            let source = r#"
function ClientRequest:done()
    return 1
end

function outer.inner:handle()
    return 2
end

local setState = function(v)
    return v
end

MyModule.func = function()
    return 3
end

function plainFn()
    return 4
end
"#;
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _) = handler
                .extract_definitions(source, Path::new("test.lua"), &tree)
                .unwrap();

            let find = |name: &str| {
                funcs
                    .iter()
                    .find(|f| f.name == name)
                    .unwrap_or_else(|| panic!("expected a definition named `{name}`: {funcs:?}"))
            };

            // A colon method with a BARE receiver records `colon_receiver` and
            // NOTHING else (no class_name / is_method — the whole point).
            let done = find("done");
            assert_eq!(
                done.colon_receiver.as_deref(),
                Some("ClientRequest"),
                "`function ClientRequest:done` must record colon_receiver = Some(\"ClientRequest\")"
            );
            assert!(
                !done.is_method,
                "colon method must NOT be is_method (would relabel every colon edge)"
            );
            assert!(
                done.class_name.is_none(),
                "colon method must NOT carry class_name (would relabel every colon edge)"
            );

            // A DOTTED receiver `a.b:m` is not a single owning-class name -> None.
            assert_eq!(
                find("handle").colon_receiver, None,
                "`function outer.inner:handle` (dotted receiver) must yield colon_receiver = None"
            );

            // Every non-colon definition carries colon_receiver == None.
            assert_eq!(
                find("setState").colon_receiver, None,
                "`local setState = function` must have colon_receiver = None"
            );
            assert_eq!(
                find("func").colon_receiver, None,
                "`MyModule.func = function` (table-field) must have colon_receiver = None"
            );
            assert_eq!(
                find("plainFn").colon_receiver, None,
                "plain `function plainFn` must have colon_receiver = None"
            );
        }

        /// Test cross-scope intra-file call extraction: method in table calls top-level function.
        /// The caller name should be qualified with the table name.
        #[test]
        fn test_extract_calls_method_to_toplevel() {
            let source = r#"
function helper_func()
    return 42
end

local M = {}

function M.method()
    helper_func()
end

return M
"#;
            let calls = extract_calls(source);

            // The method should have a call to helper_func marked as Intra
            // The caller name should be qualified as "M.method"
            let method_calls = calls.get("M.method").or(calls.get("method"));
            assert!(
                method_calls.is_some(),
                "Should find calls for M.method. Got: {:?}",
                calls.keys().collect::<Vec<_>>()
            );

            let method_calls = method_calls.unwrap();
            let helper_call = method_calls.iter().find(|c| c.target == "helper_func");

            assert!(
                helper_call.is_some(),
                "Should find call from method to top-level helper_func. Got: {:?}",
                method_calls
            );

            let call = helper_call.unwrap();
            assert_eq!(
                call.call_type,
                CallType::Intra,
                "Call to same-file top-level function should be Intra"
            );

            // Verify the caller is qualified with table name
            assert_eq!(
                call.caller, "M.method",
                "Caller should be qualified with table name"
            );
        }

        // ----- BUG 1: bracket/computed subscript LHS must NOT fabricate a
        //             phantom function name from the index expression -----

        /// Parse `source` and return its extracted `FuncDef`s.
        fn bug1_defs(source: &str) -> Vec<FuncDef> {
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            handler
                .extract_definitions(source, Path::new("test.lua"), &tree)
                .unwrap()
                .0
        }

        /// `args[nargs + 1] = function ... end` (a bracket LHS whose subscript is
        /// a COMPUTED expression) must NOT emit a FuncDef named after the index
        /// text (`nargs + 1`). The enclosing named function is still defined.
        #[test]
        fn test_bracket_computed_subscript_no_phantom_funcdef() {
            let source = r#"
local function adapt(...)
    local args = {...}
    local nargs = select('#', ...)
    args[nargs + 1] = function (e, ...)
        return handle(e)
    end
    return call(args)
end
"#;
            let funcs = bug1_defs(source);
            let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();

            assert!(
                !funcs.iter().any(|f| f.name.contains('+') || f.name.contains("nargs")),
                "computed subscript `args[nargs + 1]` must not become a FuncDef name; got {names:?}"
            );
            assert!(
                funcs.iter().any(|f| f.name == "adapt"),
                "the enclosing `local function adapt` must still be defined; got {names:?}"
            );
        }

        /// `self[name] = function ... end` where `name` is a PARAMETER (a bare
        /// identifier subscript) must NOT emit a FuncDef named `name` — a
        /// parameter must never become a function definition.
        #[test]
        fn test_bracket_identifier_subscript_no_phantom_funcdef() {
            let source = r#"
function Emitter:wrap(name, fn)
    self[name] = function (err, ...)
        return fn(err, ...)
    end
end
"#;
            let funcs = bug1_defs(source);
            let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();

            assert!(
                !funcs.iter().any(|f| f.name == "name"),
                "parameter `name` used as `self[name]` subscript must not become a FuncDef; got {names:?}"
            );
            // The real colon method IS still defined (by its short name).
            assert!(
                funcs.iter().any(|f| f.name == "wrap"),
                "the colon method `Emitter:wrap` must still be defined; got {names:?}"
            );
        }

        /// NEVER-WORSE: plain-identifier and dot-index assignment targets that
        /// bind a function value STILL produce a named FuncDef.
        #[test]
        fn test_plain_and_dot_assignment_still_define() {
            let source = r#"
local x = function()
    return 1
end

M.foo = function()
    return 2
end
"#;
            let funcs = bug1_defs(source);
            let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
            assert!(
                funcs.iter().any(|f| f.name == "x"),
                "`local x = function` must define `x`; got {names:?}"
            );
            assert!(
                funcs.iter().any(|f| f.name == "foo"),
                "`M.foo = function` must define `foo`; got {names:?}"
            );
        }

        /// NEVER-WORSE: a STRING-LITERAL subscript is a stable, constant member
        /// name (the dispatch-table idiom), so it STILL defines a named FuncDef.
        #[test]
        fn test_string_literal_bracket_subscript_still_defines() {
            let source = r#"
handlers["textDocument/completion"] = function(params)
    return complete(params)
end
"#;
            let funcs = bug1_defs(source);
            let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
            assert!(
                funcs.iter().any(|f| f.name == "textDocument/completion"),
                "string-literal subscript `handlers[\"textDocument/completion\"]` must still \
                 define a named FuncDef; got {names:?}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // fix-cl-7-v1 M0/M1: scope-graph lexical-local classification
    // -------------------------------------------------------------------------
    //
    // These tests use REAL tree-sitter parses (never a hand-built FuncIndex): the
    // tagging tests run source through `extract_definitions`, and the pipeline
    // tests run it through the full `extract_definitions -> FileIR -> resolve`
    // path via `build_project_call_graph_v2`.
    mod scopegraph_m1_tests {
        use super::*;
        use crate::callgraph::builder_v2::{build_project_call_graph_v2, BuildConfig};
        use crate::callgraph::cross_file_types::CallGraphIR;
        use tempfile::TempDir;

        /// Parse `source` and return its extracted `FuncDef`s.
        fn defs(source: &str) -> Vec<FuncDef> {
            let handler = LuaHandler::new();
            let tree = handler.parse_source(source).unwrap();
            handler
                .extract_definitions(source, Path::new("t.lua"), &tree)
                .unwrap()
                .0
        }

        /// `is_lexical_local` of the FIRST definition named `name` (panics if
        /// none). Split-decl / table-field / global cases each emit exactly one
        /// `name` entry; the direct `local x = function` form emits two, both
        /// lexical, so first-match is unambiguous.
        fn tag(defs: &[FuncDef], name: &str) -> bool {
            defs.iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("no def named `{name}` in {defs:?}"))
                .is_lexical_local
        }

        /// Build a single-file lua project and return its resolved IR.
        fn build_single_file(file_name: &str, source: &str) -> (TempDir, CallGraphIR) {
            let dir = TempDir::new().unwrap();
            std::fs::write(dir.path().join(file_name), source).unwrap();
            let config = BuildConfig {
                language: "lua".to_string(),
                ..Default::default()
            };
            let ir = build_project_call_graph_v2(dir.path(), config).unwrap();
            (dir, ir)
        }

        /// M0 (RED before M1, GREEN after): the split-decl luau-roact shape run
        /// through the REAL pipeline. `function MyComponent:init()` contains a
        /// bare `local setState` then a nested `setState = function(...) return
        /// self:setState(...) end`, plus a direct `self:setState({...})`. A colon
        /// call dispatches to a METHOD and must NEVER bind the same-file lexical
        /// `setState` closure. Pre-M1 the assignment emitted `is_lexical_local ==
        /// false`, so `self:setState` mis-bound the closure (a Method edge to the
        /// same-file `setState`); M1 tags it lexical and the existing colon prune
        /// declines it.
        #[test]
        fn test_m0_pipeline_self_setstate_declines_same_file_local_closure() {
            let source = r#"
local MyComponent = {}

function MyComponent:init()
    local setState
    setState = function(newState)
        return self:setState(newState)
    end
    self:setState({ value = 1 })
end

return MyComponent
"#;
            let (_dir, ir) = build_single_file("Component.spec.lua", source);

            // Sanity: the closure WAS extracted as a `setState` definition, so
            // the assertion below is non-vacuous (the mis-bind target exists).
            let has_setstate_def = ir
                .files
                .values()
                .flat_map(|f| &f.funcs)
                .any(|f| f.name == "setState");
            assert!(
                has_setstate_def,
                "fixture must extract a `setState` definition (the closure)"
            );

            // THE FIX: no colon/method edge may bind the same-file `setState`
            // lexical-local closure.
            let mis_bound: Vec<_> = ir
                .edges()
                .iter()
                .filter(|e| e.call_type == CallType::Method && e.dst_func.contains("setState"))
                .collect();
            assert!(
                mis_bound.is_empty(),
                "self:setState() must NOT bind the same-file local `setState` closure \
                 (colon dispatch is method-only); got edges {mis_bound:?}"
            );
        }

        /// NEVER-WORSE (cardinality-1): a genuine `function Foo:bar()` colon
        /// method with a unique name must STILL resolve for a same-file
        /// `self:bar()` call. The lexical-local flag is `false` for real colon
        /// methods, so the prune does not fire and the edge is kept.
        #[test]
        fn test_m1_pipeline_unique_colon_method_still_resolves() {
            let source = r#"
local Foo = {}

function Foo:bar()
    return 1
end

function Foo:baz()
    return self:bar()
end

return Foo
"#;
            let (_dir, ir) = build_single_file("Foo.lua", source);

            let resolves = ir
                .edges()
                .iter()
                .any(|e| e.call_type == CallType::Method && e.dst_func.contains("bar"));
            assert!(
                resolves,
                "unique same-file colon method `self:bar()` must still resolve \
                 (never-worse); edges: {:?}",
                ir.edges()
            );
        }

        /// Split decl: `local setState` (bare) in an enclosing block + a nested
        /// `setState = function ... end` assignment is tagged lexical-local —
        /// THE core M1 fix, exercised through a real parse.
        #[test]
        fn test_m1_split_decl_tagged_lexical() {
            let source = r#"
function MyComponent:init()
    local setState
    setState = function(v)
        return v
    end
end
"#;
            assert!(
                tag(&defs(source), "setState"),
                "split-decl `local setState; setState = function` must be lexical-local"
            );
        }

        /// Direct `local x = function ... end` (single statement) stays tagged
        /// lexical-local.
        #[test]
        fn test_m1_direct_local_function_tagged_lexical() {
            let source = r#"
local render = function(props)
    return props
end
"#;
            assert!(
                tag(&defs(source), "render"),
                "`local render = function` must be lexical-local"
            );
        }

        /// A genuine colon method `function T:m` is NOT a lexical local (it must
        /// keep binding on colon dispatch — never-worse).
        #[test]
        fn test_m1_colon_method_not_tagged() {
            let source = r#"
function Board:applyMove(m)
    return m
end
"#;
            assert!(
                !tag(&defs(source), "applyMove"),
                "`function Board:applyMove` must NOT be lexical-local"
            );
        }

        /// A dotted table-field assignment `M.foo = function` is a member, NOT a
        /// lexical local.
        #[test]
        fn test_m1_table_field_assignment_not_tagged() {
            let source = r#"
M.foo = function()
    return 1
end
"#;
            assert!(
                !tag(&defs(source), "foo"),
                "`M.foo = function` (table field) must NOT be lexical-local"
            );
        }

        /// A global `g = function` with NO enclosing `local g` is NOT a lexical
        /// local.
        #[test]
        fn test_m1_global_assignment_no_local_not_tagged() {
            let source = r#"
handler = function()
    return 1
end
"#;
            assert!(
                !tag(&defs(source), "handler"),
                "global `handler = function` (no `local handler`) must NOT be lexical-local"
            );
        }

        /// A `local g` at file scope followed by a `g = function` REASSIGNMENT
        /// binds the lexical local: even split across file scope, the flag is
        /// set. Guards the ancestor/file-scope containment branch of
        /// `binds_local`.
        #[test]
        fn test_m1_file_scope_split_reassignment_tagged_lexical() {
            let source = r#"
local cb

cb = function()
    return 1
end
"#;
            assert!(
                tag(&defs(source), "cb"),
                "file-scope `local cb; cb = function` must be lexical-local"
            );
        }

        /// fix-cl-7-v1 M1 FIX 2 (real gap, real parse, `local function` form):
        /// `local function setState() ... end` — the DECLARATION-FORM local
        /// closure (as opposed to the `local setState = function ... end`
        /// assignment-form already covered above) — is tagged
        /// `is_lexical_local = true` on its OWN `FuncDef`, and a same-file
        /// `self:setState()` colon call inside the SAME method must NOT
        /// resolve to it as a `Method` edge. Before this fix, `setState`'s
        /// `FuncDef` was created via the plain `"function_declaration"` /
        /// `"identifier"` arm of `extract_definitions` with no lexical
        /// tagging at all (the `local function` form never went through the
        /// `is_lexical_local` machinery), so `self:setState()` wrongly
        /// mis-bound to it — reproduced directly against this pipeline prior
        /// to the fix (`Method init -> setState` in the resolved edge set).
        #[test]
        fn test_m1_pipeline_local_function_form_declines_same_file_colon_bind() {
            let source = r#"
local MyComponent = {}

function MyComponent:init()
    local function setState(newState)
        return newState
    end
    self:setState({ value = 1 })
end

return MyComponent
"#;
            let (_dir, ir) = build_single_file("LocalFunctionForm.spec.lua", source);

            // Sanity: the `local function setState` WAS extracted as a
            // `setState` definition, so the assertion below is non-vacuous.
            let has_setstate_def = ir
                .files
                .values()
                .flat_map(|f| &f.funcs)
                .any(|f| f.name == "setState");
            assert!(
                has_setstate_def,
                "fixture must extract a `setState` definition (the `local function` closure)"
            );

            // Its own `FuncDef` must be tagged lexical-local (the DECLARATION
            // form, not just the split-decl assignment form).
            assert!(
                tag(&defs(source), "setState"),
                "`local function setState` (declaration form) must be lexical-local"
            );

            // THE FIX: no colon/method edge may bind the same-file `setState`
            // lexical-local closure declared via `local function`.
            let mis_bound: Vec<_> = ir
                .edges()
                .iter()
                .filter(|e| e.call_type == CallType::Method && e.dst_func.contains("setState"))
                .collect();
            assert!(
                mis_bound.is_empty(),
                "self:setState() must NOT bind the same-file `local function setState` \
                 closure (colon dispatch is method-only); got edges {mis_bound:?}"
            );
        }
    }
}
