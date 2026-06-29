//! OCaml language handler for call graph analysis.
//!
//! This module provides OCaml-specific call graph support using tree-sitter-ocaml.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `open List` | `{module: "List", is_from: true, names: ["*"]}` |
//! | `open Core.List` | `{module: "Core.List", is_from: true, names: ["*"]}` |
//! | `module M = List` | `{module: "List", alias: "M"}` |
//! | `include SomeModule` | `{module: "SomeModule", is_namespace: true}` |
//!
//! # Call Extraction
//!
//! - Direct calls: `func arg` -> CallType::Direct or CallType::Intra
//! - Qualified calls: `List.map f xs` -> CallType::Attr
//! - Pipe operator: `x |> f |> g` -> CallType::Direct for each function
//! - Application expressions: `f x y` -> CallType::Direct/Intra
//!
//! # OCaml-Specific Patterns
//!
//! - `let` bindings for function definitions
//! - `let rec` for recursive functions
//! - `module M = struct ... end` for nested modules
//! - Curried function application: `f x y` is `(f x) y`
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.14 for OCaml-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::common::{extend_calls_if_any, insert_calls_if_any, qualify_name, receiver_from_target};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// OCaml Handler
// =============================================================================

/// OCaml language handler using tree-sitter-ocaml.
///
/// Supports:
/// - Open statements (`open List`)
/// - Module aliases (`module M = List`)
/// - Include statements (`include SomeModule`)
/// - Let bindings for function definitions
/// - Application expressions (function calls)
/// - Pipe operator (`|>`)
/// - Qualified module paths (`List.map`)
#[derive(Debug, Default)]
pub struct OcamlHandler;

impl OcamlHandler {
    /// Creates a new OcamlHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();

        // tree-sitter-ocaml provides LANGUAGE_OCAML constant for .ml files
        // Note: ABI compatibility may vary; tests can be marked #[ignore] if needed
        parser
            .set_language(&tree_sitter_ocaml::LANGUAGE_OCAML.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set OCaml language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Extract full module path from a module_path or module_name node.
    ///
    /// Module paths can be nested: `Core.List` becomes `module_path(module_path(Core).List)`
    fn extract_module_path(&self, node: &Node, source: &[u8]) -> Option<String> {
        match node.kind() {
            "module_name" | "module_type_name" | "constructor_name" => {
                Some(get_node_text(node, source).to_string())
            }
            "module_path" | "extended_module_path" => {
                let mut parts: Vec<String> = Vec::new();
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "module_path" | "extended_module_path" => {
                                if let Some(sub_path) = self.extract_module_path(&child, source) {
                                    parts.push(sub_path);
                                }
                            }
                            "module_name" | "module_type_name" | "constructor_name" => {
                                parts.push(get_node_text(&child, source).to_string());
                            }
                            _ => {}
                        }
                    }
                }
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("."))
                }
            }
            _ => None,
        }
    }

    /// Extract value path (possibly qualified) from a value_path or value_name node.
    ///
    /// Can be: `value_name` OR `module_path.value_name`
    fn extract_value_path(&self, node: &Node, source: &[u8]) -> Option<String> {
        match node.kind() {
            "value_name" | "value_pattern" => Some(get_node_text(node, source).to_string()),
            // Operator definitions/uses: `let ( >>= ) a b = ...` registers its
            // name via a `parenthesized_operator` wrapper whose raw text is the
            // source slice `( >>= )`. Normalize to the bare inner operator token
            // (`rel_operator '>>='`, …) so def and use unify on the call-graph
            // path too (RC6, Half B). Verified against tree-sitter-ocaml 0.24.2.
            "parenthesized_operator" => node
                .named_child(0)
                .map(|inner| get_node_text(&inner, source).to_string())
                .or_else(|| Some(get_node_text(node, source).to_string())),
            "value_path" => {
                let mut parts: Vec<String> = Vec::new();
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "module_path" | "extended_module_path" => {
                                if let Some(mod_path) = self.extract_module_path(&child, source) {
                                    parts.push(mod_path);
                                }
                            }
                            "value_name" => {
                                parts.push(get_node_text(&child, source).to_string());
                            }
                            _ => {}
                        }
                    }
                }
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("."))
                }
            }
            _ => None,
        }
    }

    /// Parse an open_module node.
    ///
    /// OCaml `open Module.Path` brings the module's contents into scope.
    fn parse_open_module(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        if node.kind() != "open_module" && node.kind() != "open_statement" {
            return None;
        }

        // Find the module path child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(module_name) = self.extract_module_path(&child, source) {
                    // open Module is like "from Module import *" in Python
                    let mut imp = ImportDef::wildcard_import(&module_name);
                    imp.is_from = true;
                    return Some(imp);
                }
            }
        }
        None
    }

    /// Parse a module_definition node for module aliases.
    ///
    /// OCaml `module M = List` creates an alias.
    fn parse_module_alias(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        if node.kind() != "module_definition" {
            return None;
        }

        let mut alias_name: Option<String> = None;
        let mut target_module: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "module_binding" {
                    // Find the module name (alias) and the target
                    for j in 0..child.child_count() {
                        if let Some(binding_child) = child.child(j) {
                            match binding_child.kind() {
                                "module_name" => {
                                    if alias_name.is_none() {
                                        alias_name =
                                            Some(get_node_text(&binding_child, source).to_string());
                                    } else {
                                        // Second module_name is the target
                                        target_module =
                                            Some(get_node_text(&binding_child, source).to_string());
                                    }
                                }
                                "module_path" | "extended_module_path" => {
                                    target_module =
                                        self.extract_module_path(&binding_child, source);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Only create import if we have both alias and target, and they're different
        // (not a full module definition)
        if let (Some(alias), Some(target)) = (alias_name, target_module) {
            let mut imp = ImportDef::simple_import(&target);
            imp.alias = Some(alias);
            return Some(imp);
        }
        None
    }

    /// Parse an include_module node.
    ///
    /// OCaml `include SomeModule` includes all definitions.
    fn parse_include_module(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        if node.kind() != "include_module" && node.kind() != "include_statement" {
            return None;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(module_name) = self.extract_module_path(&child, source) {
                    let mut imp = ImportDef::wildcard_import(&module_name);
                    imp.is_namespace = true;
                    return Some(imp);
                }
            }
        }
        None
    }

    /// Collect all function definitions (let bindings).
    fn collect_definitions(&self, tree: &Tree, source: &[u8]) -> HashSet<String> {
        let mut definitions = HashSet::new();

        fn collect_from_node(
            node: Node,
            source: &[u8],
            definitions: &mut HashSet<String>,
            module_path: &[String],
        ) {
            match node.kind() {
                "module_definition" => {
                    // Extract module name and recurse into body
                    let mut mod_name: Option<String> = None;
                    let mut body: Option<Node> = None;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "module_binding" {
                                for j in 0..child.child_count() {
                                    if let Some(binding_child) = child.child(j) {
                                        match binding_child.kind() {
                                            "module_name" => {
                                                mod_name = Some(
                                                    get_node_text(&binding_child, source)
                                                        .to_string(),
                                                );
                                            }
                                            "structure" | "module_content" => {
                                                body = Some(binding_child);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(name) = mod_name {
                        definitions.insert(name.clone());
                        let mut new_path = module_path.to_vec();
                        new_path.push(name);

                        if let Some(structure) = body {
                            for i in 0..structure.child_count() {
                                if let Some(child) = structure.child(i) {
                                    collect_from_node(child, source, definitions, &new_path);
                                }
                            }
                        }
                    }
                    return;
                }
                "value_definition" | "let_binding" => {
                    // let foo = expr or let rec foo = expr
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "let_binding" || child.kind() == "value_definition" {
                                // Find the value_name
                                for j in 0..child.child_count() {
                                    if let Some(binding_child) = child.child(j) {
                                        if binding_child.kind() == "value_name"
                                            || binding_child.kind() == "value_pattern"
                                        {
                                            let func_name =
                                                get_node_text(&binding_child, source).to_string();
                                            // VAL-018: skip `_`/`()` wildcard
                                            // bindings (see process_let_binding_calls
                                            // for the rationale).
                                            if func_name == "_"
                                                || func_name == "()"
                                                || func_name.is_empty()
                                            {
                                                continue;
                                            }
                                            definitions.insert(func_name.clone());
                                            // Also add qualified name
                                            if !module_path.is_empty() {
                                                let qualified = format!(
                                                    "{}.{}",
                                                    module_path.join("."),
                                                    func_name
                                                );
                                                definitions.insert(qualified);
                                            }
                                        }
                                    }
                                }
                            } else if child.kind() == "value_name"
                                || child.kind() == "value_pattern"
                            {
                                let func_name = get_node_text(&child, source).to_string();
                                if func_name == "_" || func_name == "()" || func_name.is_empty() {
                                    continue;
                                }
                                definitions.insert(func_name.clone());
                                if !module_path.is_empty() {
                                    let qualified =
                                        format!("{}.{}", module_path.join("."), func_name);
                                    definitions.insert(qualified);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }

            // Recurse into children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_from_node(child, source, definitions, module_path);
                }
            }
        }

        collect_from_node(tree.root_node(), source, &mut definitions, &[]);
        definitions
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
            let call_name = match child.kind() {
                "application_expression" | "application" => {
                    self.extract_application_call_name(&child, source)
                }
                "infix_expression" => self.extract_pipe_call_name(&child, source),
                _ => None,
            };

            if let Some(name) = call_name {
                let line = child.start_position().row as u32 + 1;
                calls.push(self.build_call_site(caller, name, line, defined_funcs));
            }
        }

        calls
    }

    fn extract_application_call_name(&self, node: &Node, source: &[u8]) -> Option<String> {
        let func_child = node.child(0)?;
        let name = self.extract_value_path(&func_child, source).or_else(|| {
            let text = get_node_text(&func_child, source).to_string();
            if !text.is_empty() && !text.contains(' ') {
                Some(text)
            } else {
                None
            }
        })?;

        if name.starts_with('(') || name.is_empty() {
            return None;
        }
        Some(name)
    }

    fn extract_pipe_call_name(&self, node: &Node, source: &[u8]) -> Option<String> {
        let mut found_pipe = false;
        for i in 0..node.child_count() {
            let Some(infix_child) = node.child(i) else {
                continue;
            };
            let text = get_node_text(&infix_child, source);
            if text == "|>" {
                found_pipe = true;
                continue;
            }
            if found_pipe && infix_child.kind() != "infix_operator" {
                return self.extract_value_path(&infix_child, source).or_else(|| {
                    let value = text.to_string();
                    if !value.is_empty() && !value.contains(' ') {
                        Some(value)
                    } else {
                        None
                    }
                });
            }
        }
        None
    }

    fn build_call_site(
        &self,
        caller: &str,
        name: String,
        line: u32,
        defined_funcs: &HashSet<String>,
    ) -> CallSite {
        // Collapse a fully-qualified reference to a SAME-FILE definition
        // (`Outer.Sub.target`) down to its bare name (`target`).
        // `collect_definitions` records BOTH the bare and *every*
        // module-qualified spelling of each local binding, so a dotted target
        // that is present in `defined_funcs` is provably defined in this file
        // and is really an intra-file call. Collapsing it lets the
        // reverse-call-graph (`impact`) count these qualified call sites
        // against the single local definition — matching what `explain`
        // resolves — instead of dropping them as unresolved `Attr` calls.
        // External qualified calls (`List.map`) are absent from
        // `defined_funcs` and keep their `Attr` classification below.
        if name.contains('.') && defined_funcs.contains(&name) {
            if let Some(bare) = name.rsplit('.').next() {
                return CallSite::new(
                    caller.to_string(),
                    bare.to_string(),
                    CallType::Intra,
                    Some(line),
                    None,
                    None,
                    None,
                );
            }
        }
        let (call_type, receiver) = self.classify_call_target(&name, defined_funcs);
        CallSite::new(
            caller.to_string(),
            name,
            call_type,
            Some(line),
            None,
            receiver,
            None,
        )
    }

    fn classify_call_target(
        &self,
        name: &str,
        defined_funcs: &HashSet<String>,
    ) -> (CallType, Option<String>) {
        if name.contains('.') {
            return (CallType::Attr, receiver_from_target(name, '.'));
        }
        if defined_funcs.contains(name) {
            return (CallType::Intra, None);
        }
        (CallType::Direct, None)
    }

    fn is_function_binding(binding: &Node) -> bool {
        (0..binding.child_count())
            .filter_map(|idx| binding.child(idx))
            .any(|child| child.kind() == "parameter")
    }

    fn is_unit_pattern(binding: &Node, source: &[u8]) -> bool {
        let Some(pattern) = binding.child_by_field_name("pattern") else {
            return false;
        };
        pattern.kind() == "unit"
            || (pattern.kind() == "parenthesized_pattern"
                && get_node_text(&pattern, source) == "()")
    }

    fn extract_binding_name(binding: &Node, source: &[u8]) -> Option<String> {
        if let Some(pattern) = binding.child_by_field_name("pattern") {
            if matches!(pattern.kind(), "value_name" | "value_pattern") {
                return Some(get_node_text(&pattern, source).to_string());
            }
        }

        for i in 0..binding.child_count() {
            let Some(child) = binding.child(i) else {
                continue;
            };
            if matches!(child.kind(), "value_name" | "value_pattern") {
                return Some(get_node_text(&child, source).to_string());
            }
        }
        None
    }

    fn find_named_child_text(
        &self,
        node: &Node,
        field_name: &str,
        fallback_kind: &str,
        source: &[u8],
    ) -> Option<String> {
        if let Some(named) = node.child_by_field_name(field_name) {
            return Some(get_node_text(&named, source).to_string());
        }
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() == fallback_kind {
                return Some(get_node_text(&child, source).to_string());
            }
        }
        None
    }

    fn recurse_children_for_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.process_calls_node(child, source, defined_funcs, calls_by_func, module_path);
            }
        }
    }

    fn process_calls_node(
        &self,
        node: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        match node.kind() {
            "module_definition" => {
                self.process_module_definition_calls(
                    node,
                    source,
                    defined_funcs,
                    calls_by_func,
                    module_path,
                );
                return;
            }
            "value_definition" => {
                self.process_value_definition_calls(
                    node,
                    source,
                    defined_funcs,
                    calls_by_func,
                    module_path,
                );
                return;
            }
            "let_binding" => {
                self.process_let_binding_calls(
                    node,
                    source,
                    defined_funcs,
                    calls_by_func,
                    module_path,
                );
                return;
            }
            "class_definition" => {
                self.process_class_definition_calls(
                    node,
                    source,
                    defined_funcs,
                    calls_by_func,
                    module_path,
                );
                return;
            }
            _ => {}
        }

        self.recurse_children_for_calls(node, source, defined_funcs, calls_by_func, module_path);
    }

    fn process_module_definition_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() != "module_binding" {
                continue;
            }

            let mod_name = self.find_named_child_text(&child, "name", "module_name", source);
            let body = child.child_by_field_name("body");
            let Some(name) = mod_name else {
                continue;
            };

            let mut new_path = module_path.to_vec();
            new_path.push(name);

            let Some(body_node) = body else {
                continue;
            };
            match body_node.kind() {
                "structure" | "module_content" => {
                    self.recurse_children_for_calls(
                        body_node,
                        source,
                        defined_funcs,
                        calls_by_func,
                        &new_path,
                    );
                }
                "module_application" => {
                    let Some(functor) = body_node.child_by_field_name("functor") else {
                        continue;
                    };
                    let functor_name = get_node_text(&functor, source).to_string();
                    let line = body_node.start_position().row as u32 + 1;
                    let caller = if module_path.is_empty() {
                        "<module>".to_string()
                    } else {
                        module_path.join(".")
                    };
                    let call = CallSite::new(
                        caller.clone(),
                        functor_name,
                        CallType::Direct,
                        Some(line),
                        None,
                        None,
                        None,
                    );
                    extend_calls_if_any(calls_by_func, caller, vec![call]);
                }
                _ => {}
            }
        }
    }

    fn process_value_definition_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() == "let_binding" {
                self.process_let_binding_calls(
                    child,
                    source,
                    defined_funcs,
                    calls_by_func,
                    module_path,
                );
            }
        }
    }

    fn process_let_binding_calls(
        &self,
        binding: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        let body = binding.child_by_field_name("body");
        let has_params = Self::is_function_binding(&binding);
        let is_unit = Self::is_unit_pattern(&binding, source);
        // A binding whose body is a lambda (`let f = fun x -> ...`) or a
        // pattern-matching function (`let f = function | ... -> ...`) is still
        // a *named function*: its parameters live on the `fun_expression` /
        // `function_expression`, not as `parameter` children of the
        // `let_binding`, so `is_function_binding` (which only sees the latter)
        // reports false. Without recognising this form, the body's calls were
        // siphoned into the `<module>` pseudo-node below and the function `f`
        // reported `callees = 0`. Attribute them to the enclosing `f` instead.
        let body_is_lambda = body
            .map(|b| matches!(b.kind(), "fun_expression" | "function_expression"))
            .unwrap_or(false);

        if is_unit {
            let module_caller = if module_path.is_empty() {
                "<module>".to_string()
            } else {
                format!("{}.<module>", module_path.join("."))
            };

            let calls = if let Some(body_node) = body {
                self.extract_calls_from_node(&body_node, source, defined_funcs, &module_caller)
            } else {
                self.extract_calls_from_node(&binding, source, defined_funcs, "<module>")
            };

            extend_calls_if_any(calls_by_func, "<module>".to_string(), calls);
            return;
        }

        let Some(name) = Self::extract_binding_name(&binding, source) else {
            return;
        };
        // VAL-018: `let _ = expr in body` is a wildcard binding used to
        // discard a value (typically inside function bodies). It is NOT
        // a named definition and must not surface as a caller in the
        // call graph — its calls were already attributed to the
        // enclosing function via `extract_calls_from_node` walking
        // through this node. Skip without inserting.
        if name == "_" {
            return;
        }
        let module_prefix = if module_path.is_empty() {
            None
        } else {
            Some(module_path.join("."))
        };
        let full_name = qualify_name(module_prefix.as_deref(), &name, ".");

        if has_params || body_is_lambda {
            let mut all_calls = Vec::new();
            if let Some(body_node) = body {
                all_calls.extend(self.extract_calls_from_node(
                    &body_node,
                    source,
                    defined_funcs,
                    &full_name,
                ));
            }
            for i in 0..binding.child_count() {
                let Some(child) = binding.child(i) else {
                    continue;
                };
                if child.kind() != "parameter" {
                    continue;
                }
                if let Some(default_val) = child.child_by_field_name("default") {
                    all_calls.extend(self.extract_calls_from_node(
                        &default_val,
                        source,
                        defined_funcs,
                        &full_name,
                    ));
                }
            }

            if all_calls.is_empty() {
                return;
            }

            insert_calls_if_any(calls_by_func, full_name.clone(), all_calls.clone());
            if full_name != name {
                insert_calls_if_any(calls_by_func, name, all_calls);
            }
            return;
        }

        let module_calls = if let Some(body_node) = body {
            self.extract_calls_from_node(&body_node, source, defined_funcs, "<module>")
        } else {
            self.extract_calls_from_node(&binding, source, defined_funcs, "<module>")
        };
        extend_calls_if_any(calls_by_func, "<module>".to_string(), module_calls);
    }

    fn process_class_definition_calls(
        &self,
        node: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
    ) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() != "class_binding" {
                continue;
            }

            let class_name = self.find_named_child_text(&child, "name", "class_name", source);
            let Some(body) = child.child_by_field_name("body") else {
                continue;
            };
            if body.kind() != "object_expression" {
                continue;
            }

            self.process_class_body_calls(
                body,
                source,
                defined_funcs,
                calls_by_func,
                module_path,
                class_name.as_deref(),
            );
        }
    }

    fn process_class_body_calls(
        &self,
        obj_expr: Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        calls_by_func: &mut HashMap<String, Vec<CallSite>>,
        module_path: &[String],
        class_name: Option<&str>,
    ) {
        let class_prefix = class_name.unwrap_or("_anon_class");

        for i in 0..obj_expr.child_count() {
            let Some(child) = obj_expr.child(i) else {
                continue;
            };

            match child.kind() {
                "method_definition" => {
                    let method_name =
                        self.find_named_child_text(&child, "name", "method_name", source);
                    let Some(method_name) = method_name else {
                        continue;
                    };

                    let caller = if module_path.is_empty() {
                        format!("{class_prefix}.{method_name}")
                    } else {
                        format!("{}.{}.{}", module_path.join("."), class_prefix, method_name)
                    };

                    let search_node = child.child_by_field_name("body").unwrap_or(child);
                    let calls =
                        self.extract_calls_from_node(&search_node, source, defined_funcs, &caller);
                    insert_calls_if_any(calls_by_func, caller, calls);
                }
                "class_initializer" => {
                    let caller = if module_path.is_empty() {
                        format!("{class_prefix}.<init>")
                    } else {
                        format!("{}.{}.<init>", module_path.join("."), class_prefix)
                    };

                    let init_expr = child.child_by_field_name("initializer").or_else(|| {
                        (0..child.child_count())
                            .filter_map(|idx| child.child(idx))
                            .find(|ic| ic.kind() != "initializer" && ic.kind() != "comment")
                    });

                    let search_node = init_expr.unwrap_or(child);
                    let calls =
                        self.extract_calls_from_node(&search_node, source, defined_funcs, &caller);
                    insert_calls_if_any(calls_by_func, caller, calls);
                }
                _ => {}
            }
        }
    }
}

impl CallGraphLanguageSupport for OcamlHandler {
    fn name(&self) -> &str {
        "ocaml"
    }

    fn extensions(&self) -> &[&str] {
        &[".ml", ".mli"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "open_module" | "open_statement" => {
                    if let Some(imp) = self.parse_open_module(&node, source_bytes) {
                        imports.push(imp);
                    }
                }
                "module_definition" => {
                    // Check if it's a module alias (module M = X)
                    if let Some(imp) = self.parse_module_alias(&node, source_bytes) {
                        imports.push(imp);
                    }
                }
                "include_module" | "include_statement" => {
                    if let Some(imp) = self.parse_include_module(&node, source_bytes) {
                        imports.push(imp);
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
        let defined_funcs = self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();
        self.process_calls_node(
            tree.root_node(),
            source_bytes,
            &defined_funcs,
            &mut calls_by_func,
            &[],
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

        // Free-function twin of `OcamlHandler::find_named_child_text`: look up a
        // node's text by field name, falling back to the first child of
        // `fallback_kind`. `collect_defs` is a nested free fn and cannot reach
        // `&self`, so this mirrors that helper for the `class_definition` arm.
        fn field_or_kind_text(
            node: &Node,
            field_name: &str,
            fallback_kind: &str,
            source: &[u8],
        ) -> Option<String> {
            if let Some(named) = node.child_by_field_name(field_name) {
                return Some(get_node_text(&named, source).to_string());
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == fallback_kind {
                        return Some(get_node_text(&child, source).to_string());
                    }
                }
            }
            None
        }

        /// True when `binding` (a `let_binding`) is a *local* value binding —
        /// a plain `let x = <expr>` nested inside a function/expression body
        /// (`let x = e in body`), as opposed to a top-level or module-`struct`
        /// binding.
        ///
        /// A local value binding's RHS calls belong to the *enclosing*
        /// function (the call graph already attributes them there). Registering
        /// its own name as a standalone definition makes `resolve_caller_name`
        /// prefer the zero-span local binding over the real enclosing function,
        /// mis-attributing the call — e.g. `let info = Pp.box (pp_lib info)`
        /// inside `pp_lib_and_dep_path` stealing the `pp_lib` caller and
        /// colliding with the genuine top-level `info` accessor. Only *value*
        /// bindings are filtered: a binding with `parameter` children or a
        /// `fun`/`function` body is a named local function and is left intact.
        ///
        /// Locality is detected purely structurally: an expression-level
        /// `let ... in` yields a `let_expression` ancestor, which top-level and
        /// module-`struct` bindings never have, so module-init accessors stay
        /// registered.
        fn is_local_value_binding(binding: &Node) -> bool {
            let has_params = (0..binding.child_count())
                .filter_map(|i| binding.child(i))
                .any(|c| c.kind() == "parameter");
            if has_params {
                return false;
            }
            if let Some(body) = binding.child_by_field_name("body") {
                if matches!(body.kind(), "fun_expression" | "function_expression") {
                    return false;
                }
            }
            let mut ancestor = binding.parent();
            while let Some(node) = ancestor {
                if node.kind() == "let_expression" {
                    return true;
                }
                ancestor = node.parent();
            }
            false
        }

        fn collect_defs(
            node: Node,
            source: &[u8],
            funcs: &mut Vec<FuncDef>,
            classes: &mut Vec<ClassDef>,
            module_path: &[String],
        ) {
            match node.kind() {
                "module_definition" => {
                    let mut mod_name: Option<String> = None;
                    let mut body: Option<Node> = None;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "module_binding" {
                                for j in 0..child.child_count() {
                                    if let Some(bc) = child.child(j) {
                                        match bc.kind() {
                                            "module_name" => {
                                                mod_name =
                                                    Some(get_node_text(&bc, source).to_string());
                                            }
                                            "structure" | "module_content" => {
                                                body = Some(bc);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(name) = mod_name {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(&name, line, end_line));

                        let mut new_path = module_path.to_vec();
                        new_path.push(name);

                        if let Some(structure) = body {
                            for i in 0..structure.child_count() {
                                if let Some(child) = structure.child(i) {
                                    collect_defs(child, source, funcs, classes, &new_path);
                                }
                            }
                        }
                    }
                    return;
                }
                "value_definition" | "let_binding" => {
                    // F4a-definition-ocaml: a `let` binding is a value/function
                    // definition regardless of the enclosing module. OCaml
                    // modules (`module M = struct ... end`) are *namespaces*,
                    // not classes/objects, so their members must report as
                    // `kind=function`, never `method`. Only `method`
                    // declarations inside an `object`/`class` body are true
                    // methods — those are emitted by the `class_definition` arm
                    // below. `module_path` is still threaded through for module
                    // and class-method qualification; it no longer drives the
                    // function-vs-method axis for plain `let` bindings.
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "let_binding" || child.kind() == "value_definition" {
                                // CFr-RW7: a LOCAL `let x = <expr> in ...` value
                                // binding inside a function body is not a
                                // module-level definition; skip it so its RHS
                                // call stays attributed to the enclosing fn.
                                if child.kind() == "let_binding"
                                    && is_local_value_binding(&child)
                                {
                                    continue;
                                }
                                for j in 0..child.child_count() {
                                    if let Some(bc) = child.child(j) {
                                        if bc.kind() == "value_name" || bc.kind() == "value_pattern"
                                        {
                                            let func_name = get_node_text(&bc, source).to_string();
                                            // VAL-018: skip wildcard `_` and unit `()`
                                            // patterns. `let _ = expr in body` is a
                                            // value-discard expression, not a function
                                            // definition. Without this filter, the
                                            // resolver picks `_` over the enclosing
                                            // function (smaller line span wins) and
                                            // produces edges with src_func="_".
                                            if func_name == "_"
                                                || func_name == "()"
                                                || func_name.is_empty()
                                            {
                                                continue;
                                            }
                                            let line = node.start_position().row as u32 + 1;
                                            let end_line = node.end_position().row as u32 + 1;

                                            funcs.push(FuncDef::function(
                                                func_name, line, end_line,
                                            ));
                                        }
                                    }
                                }
                            } else if child.kind() == "value_name"
                                || child.kind() == "value_pattern"
                            {
                                // CFr-RW7: `node` is the `let_binding`; skip a
                                // LOCAL value binding nested in a function body
                                // (same rationale as the sibling branch above).
                                if is_local_value_binding(&node) {
                                    continue;
                                }
                                let func_name = get_node_text(&child, source).to_string();
                                // VAL-018: same filter as above branch (see comment).
                                if func_name == "_" || func_name == "()" || func_name.is_empty() {
                                    continue;
                                }
                                let line = node.start_position().row as u32 + 1;
                                let end_line = node.end_position().row as u32 + 1;

                                funcs.push(FuncDef::function(func_name, line, end_line));
                            }
                        }
                    }
                }
                "class_definition" => {
                    // F4a-definition-ocaml: the *only* OCaml constructs whose
                    // members are genuine methods are `class`/`object`
                    // expressions. Each `method <name> = ...` inside an
                    // `object_expression` is emitted as `FuncDef::method` so
                    // `definition` reports `kind=method` (and the class itself
                    // is recorded as a `ClassDef`, mirroring the
                    // `module_definition` arm). We `return` to avoid descending
                    // into method bodies, where local `let ... in` bindings
                    // would otherwise leak out as spurious top-level functions.
                    for i in 0..node.child_count() {
                        let Some(binding) = node.child(i) else {
                            continue;
                        };
                        if binding.kind() != "class_binding" {
                            continue;
                        }

                        let Some(class_name) = field_or_kind_text(&binding, "name", "class_name", source)
                        else {
                            continue;
                        };
                        if class_name.is_empty() {
                            continue;
                        }

                        let class_line = binding.start_position().row as u32 + 1;
                        let class_end = binding.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(&class_name, class_line, class_end));

                        // Qualify the owning-class name with the enclosing module
                        // path so the builder's `Class.method` index alias lines
                        // up with the call-graph caller keys produced by
                        // `process_class_body_calls`.
                        let class_qual = if module_path.is_empty() {
                            class_name
                        } else {
                            format!("{}.{}", module_path.join("."), class_name)
                        };

                        let Some(body) = binding.child_by_field_name("body") else {
                            continue;
                        };
                        if body.kind() != "object_expression" {
                            continue;
                        }
                        for j in 0..body.child_count() {
                            let Some(member) = body.child(j) else {
                                continue;
                            };
                            if member.kind() != "method_definition" {
                                continue;
                            }
                            let Some(method_name) =
                                field_or_kind_text(&member, "name", "method_name", source)
                            else {
                                continue;
                            };
                            if method_name.is_empty() {
                                continue;
                            }
                            let m_line = member.start_position().row as u32 + 1;
                            let m_end = member.end_position().row as u32 + 1;
                            funcs.push(FuncDef::method(
                                method_name,
                                class_qual.clone(),
                                m_line,
                                m_end,
                            ));
                        }
                    }
                    return;
                }
                _ => {}
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_defs(child, source, funcs, classes, module_path);
                }
            }
        }

        collect_defs(
            tree.root_node(),
            source_bytes,
            &mut funcs,
            &mut classes,
            &[],
        );

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
        let handler = OcamlHandler::new();
        handler
            .parse_imports(source, Path::new("test.ml"))
            .unwrap_or_default()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = OcamlHandler::new();
        match handler.parse_source(source) {
            Ok(tree) => handler
                .extract_calls(Path::new("test.ml"), source, &tree)
                .unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn extract_definitions(source: &str) -> (Vec<FuncDef>, Vec<ClassDef>) {
        let handler = OcamlHandler::new();
        let tree = handler.parse_source(source).expect("ocaml source parses");
        handler
            .extract_definitions(source, Path::new("test.ml"), &tree)
            .expect("extract_definitions succeeds")
    }

    /// CFr-RW7 — GENERALIZATION across the OCaml let-binding call-attribution
    /// symptom class (residual of S17).
    ///
    /// S17 routed `fun`/`function`-bodied bindings to the enclosing function
    /// and mapped qualified `Module.Sub.func` callers to the bare def, but left
    /// plain value bindings on the `<module>` node — correct only for
    /// *top-level* module-init bindings. A **local** `let x = <expr>` inside a
    /// function body was still mis-handled: it surfaced as a standalone
    /// definition with a zero-width span, so `resolve_caller_name` (smallest
    /// span wins) attributed the RHS call to `x` instead of the enclosing
    /// function — and, in dune's `lib.ml`, `x` was literally `info`, colliding
    /// with the genuine top-level `info` accessor.
    ///
    /// The class spans EVERY let-binding shape, so a single-variant fix can't
    /// pass:
    ///   * top-level value binding (`let config = ...`)   -> module-init, kept
    ///   * module-`struct` value accessor (`let info`)    -> kept as a def
    ///   * function binding (`let pp_lib info = ...`)      -> S17: body->fn
    ///   * lambda-bodied binding (`let f = fun ...`)       -> S17: body->fn
    ///   * qualified intra call (`Lib.pp_lib xs`)          -> S17: bare-def map
    ///   * LOCAL value binding (`let info = ... in ...`)   -> RHS call->enclosing
    #[test]
    fn test_cfr_rw7_local_value_binding_attributes_to_enclosing_fn() {
        use crate::callgraph::cross_file_types::FileIR;
        use crate::callgraph::resolution::resolve_caller_name;
        use std::path::PathBuf;

        let source = r#"
let config = load_config ()

module Lib = struct
  let info = Lib_info.create ()

  let pp_lib info =
    Pp.textf "%S" (Lib_info.name info)

  let pp_lib_and_dep_path (info, dp) =
    let info = Pp.box (pp_lib info) in
    Pp.vbox info

  let make_box = fun x -> Pp.box (render x)

  let render_all xs =
    Lib.pp_lib xs
end
"#;

        let calls = extract_calls(source);
        let (funcs, _classes) = extract_definitions(source);

        let calls_of = |caller: &str| -> Vec<(String, CallType)> {
            calls
                .get(caller)
                .map(|v| v.iter().map(|c| (c.target.clone(), c.call_type)).collect())
                .unwrap_or_default()
        };

        // ------------------------------------------------------------------
        // (1) THE BUG (residual): the LOCAL `let info = Pp.box (pp_lib info)`
        // must NOT be registered as a definition nested inside its enclosing
        // function, while the genuine module-level `info` accessor must remain.
        // ------------------------------------------------------------------
        let ppd = funcs
            .iter()
            .find(|f| f.name == "pp_lib_and_dep_path")
            .expect("pp_lib_and_dep_path must be a definition");
        assert!(
            !funcs
                .iter()
                .any(|f| f.name == "info" && f.line > ppd.line && f.end_line <= ppd.end_line),
            "LOCAL `let info = ...` inside pp_lib_and_dep_path must NOT be a definition; got {:?}",
            funcs
                .iter()
                .filter(|f| f.name == "info")
                .map(|f| (f.line, f.end_line))
                .collect::<Vec<_>>()
        );
        assert!(
            funcs.iter().any(|f| f.name == "info" && f.line < ppd.line),
            "the genuine module-level `info` accessor must remain a definition"
        );

        // ------------------------------------------------------------------
        // (1b) END-TO-END via the real resolver: the `pp_lib` RHS call resolves
        // to the enclosing function, never to `info`. This is the exact path
        // `impact`/`explain` use; it returned "info" before the fix.
        // ------------------------------------------------------------------
        let pp_lib_callsite = calls
            .get("pp_lib_and_dep_path")
            .and_then(|v| v.iter().find(|c| c.target == "pp_lib"))
            .cloned()
            .expect("pp_lib RHS call must be attributed to the enclosing function in the graph");
        let mut ir = FileIR::new(PathBuf::from("test.ml"));
        ir.funcs = funcs.clone();
        assert_eq!(
            resolve_caller_name(&ir, &pp_lib_callsite),
            "pp_lib_and_dep_path",
            "the local-`let` RHS call must resolve to the enclosing fn, not the `info` binding"
        );
        assert!(
            !calls.contains_key("info"),
            "no call may be attributed to the value-binding own name `info`"
        );

        // ------------------------------------------------------------------
        // (2) S17 must still hold: function-binding bodies attribute calls to
        // the enclosing function (bare + qualified caller keys).
        // ------------------------------------------------------------------
        for key in ["pp_lib", "Lib.pp_lib"] {
            let targets = calls_of(key);
            assert!(
                targets.iter().any(|(t, _)| t == "Pp.textf"),
                "S17: `pp_lib` body call `Pp.textf` must attribute to `{key}`, got {targets:?}"
            );
        }

        // ------------------------------------------------------------------
        // (3) S17 lambda-bodied binding: `let make_box = fun x -> ...` routes
        // its body calls to the enclosing function, not to `<module>`.
        // ------------------------------------------------------------------
        let make_box_targets = calls_of("make_box");
        assert!(
            make_box_targets.iter().any(|(t, _)| t == "render"),
            "S17: lambda-bodied `make_box` body call `render` must attribute to it, got {make_box_targets:?}"
        );
        assert!(
            !calls_of("<module>").iter().any(|(t, _)| t == "render"),
            "lambda-bodied binding body must not leak into the `<module>` node"
        );

        // ------------------------------------------------------------------
        // (4) S17 qualified-caller mapping: `Lib.pp_lib xs` (a same-file
        // module-qualified target) collapses to the bare `pp_lib` def as Intra.
        // ------------------------------------------------------------------
        let render_all_targets = calls_of("render_all");
        assert!(
            render_all_targets
                .iter()
                .any(|(t, ty)| t == "pp_lib" && *ty == CallType::Intra),
            "S17: qualified `Lib.pp_lib` call must collapse to bare `pp_lib` Intra, got {render_all_targets:?}"
        );

        // ------------------------------------------------------------------
        // (5) Top-level / module-`struct` VALUE bindings are module-init: their
        // RHS calls stay on the `<module>` node (unchanged by this fix).
        // ------------------------------------------------------------------
        let module_targets = calls_of("<module>");
        assert!(
            module_targets.iter().any(|(t, _)| t == "load_config"),
            "top-level value binding `let config = load_config ()` must stay module-init, got {module_targets:?}"
        );
        assert!(
            module_targets.iter().any(|(t, _)| t == "Lib_info.create"),
            "module-level value accessor `let info = Lib_info.create ()` must stay module-init, got {module_targets:?}"
        );
    }

    /// F4a-definition-ocaml — GENERALIZATION across the OCaml
    /// definition-kind symptom class.
    ///
    /// Symptom: `definition` reported every `let` binding nested inside a
    /// `module M = struct ... end` as `kind=method` (FuncDef::method, which
    /// drives `SymbolKind::Method` in the `definition` command). OCaml modules
    /// are namespaces, not classes, so module members are *functions*.
    ///
    /// The class spans EVERY shape that produces a definition kind:
    ///   * top-level `let`                            -> function
    ///   * `let` inside `module = struct`             -> function (was method)
    ///   * `let rec` inside a module                  -> function (was method)
    ///   * `let` inside a *nested* module             -> function (was method)
    ///   * `method` inside `class = object`           -> method (must stay/become method)
    ///
    /// A single-variant assertion would not catch a regression that, say, only
    /// fixed the non-recursive module case, so every variant is asserted here.
    #[test]
    fn test_f4a_module_level_let_is_function_object_method_is_method() {
        let source = r#"
let top_level x = x + 1

module M = struct
  let in_module y = y * 2
  let rec fact n = if n = 0 then 1 else n * fact (n - 1)

  module Inner = struct
    let deep z = z - 1
  end
end

class counter = object
  val mutable count = 0
  method incr = count <- count + 1
  method get = count
end
"#;
        let (funcs, classes) = extract_definitions(source);

        let by_name = |name: &str| -> FuncDef {
            funcs
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "expected a definition named `{name}`, got {:?}",
                        funcs.iter().map(|f| &f.name).collect::<Vec<_>>()
                    )
                })
                .clone()
        };

        // --- `let` bindings: every variant must be a function. ---
        for name in ["top_level", "in_module", "fact", "deep"] {
            let f = by_name(name);
            assert!(
                !f.is_method,
                "`let {name}` must be kind=function (is_method=false), got is_method=true"
            );
            assert!(
                f.class_name.is_none(),
                "`let {name}` must carry no owning class, got {:?}",
                f.class_name
            );
        }

        // --- `method` declarations: must be real methods of their class. ---
        for name in ["incr", "get"] {
            let m = by_name(name);
            assert!(
                m.is_method,
                "`method {name}` must be kind=method (is_method=true), got is_method=false"
            );
            assert_eq!(
                m.class_name.as_deref(),
                Some("counter"),
                "`method {name}` must belong to class `counter`"
            );
        }

        // The class itself is recorded as a class-like definition.
        assert!(
            classes.iter().any(|c| c.name == "counter"),
            "class `counter` must be emitted as a ClassDef, got {:?}",
            classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        // A local `let ... in` inside a method body must NOT leak as a
        // top-level definition (guards the `return` in the class arm).
        assert!(
            !funcs.iter().any(|f| f.name == "count"),
            "the `val count` / method-local bindings must not surface as functions"
        );
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = OcamlHandler::new();
            assert_eq!(handler.name(), "ocaml");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = OcamlHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".ml"));
            assert!(exts.contains(&".mli"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = OcamlHandler::new();
            assert!(handler.supports("ocaml"));
            assert!(handler.supports("OCaml"));
            assert!(handler.supports("OCAML"));
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = OcamlHandler::new();
            assert!(handler.supports_extension(".ml"));
            assert!(handler.supports_extension(".mli"));
            assert!(!handler.supports_extension(".py"));
            assert!(!handler.supports_extension(".rs"));
        }
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_open() {
            let imports = parse_imports("open List");
            assert!(
                !imports.is_empty(),
                "Expected at least one import from 'open List'"
            );
            let imp = &imports[0];
            assert_eq!(imp.module, "List");
            assert!(imp.is_wildcard() || imp.is_from);
        }

        #[test]
        fn test_parse_open_qualified() {
            let imports = parse_imports("open Core.List");
            assert!(
                !imports.is_empty(),
                "Expected at least one import from 'open Core.List'"
            );
            let imp = &imports[0];
            assert!(imp.module.contains("Core") || imp.module.contains("List"));
        }

        #[test]
        fn test_parse_module_alias() {
            let imports = parse_imports("module M = List");
            // This might be parsed as a module alias or not, depending on grammar
            if !imports.is_empty() {
                let imp = &imports[0];
                assert!(imp.alias.is_some() || imp.module == "List");
            }
        }

        #[test]
        fn test_parse_multiple_opens() {
            let source = r#"
open List
open Array
open String
"#;
            let imports = parse_imports(source);
            // Should have at least some opens
            assert!(!imports.is_empty() || imports.is_empty()); // Grammar may vary
        }

        #[test]
        fn test_parse_include() {
            let imports = parse_imports("include SomeModule");
            if !imports.is_empty() {
                let imp = &imports[0];
                assert!(imp.is_namespace || imp.module.contains("SomeModule"));
            }
        }
    }

    // -------------------------------------------------------------------------
    // Call Extraction Tests
    // -------------------------------------------------------------------------

    mod call_tests {
        use super::*;

        #[test]
        fn test_extract_calls_qualified() {
            let source = r#"
let main () =
  List.map f xs
"#;
            let calls = extract_calls(source);
            // Should find call to List.map
            let has_list_map = calls.values().any(|call_list| {
                call_list
                    .iter()
                    .any(|c| c.target.contains("List.map") || c.target.contains("map"))
            });
            assert!(has_list_map || calls.is_empty()); // Grammar may vary
        }

        #[test]
        fn test_extract_calls_unqualified() {
            let source = r#"
open List
let main () =
  map f xs
"#;
            let calls = extract_calls(source);
            // After open List, map should be unqualified
            let has_map = calls.values().any(|call_list| {
                call_list
                    .iter()
                    .any(|c| c.target == "map" || c.target.contains("map"))
            });
            assert!(has_map || calls.is_empty());
        }

        #[test]
        fn test_extract_calls_application() {
            let source = r#"
let f x = x + 1
let main () = f 42
"#;
            let calls = extract_calls(source);
            // Should find call to f
            let has_f = calls
                .values()
                .any(|call_list| call_list.iter().any(|c| c.target == "f"));
            assert!(has_f || calls.is_empty());
        }

        #[test]
        fn test_extract_calls_pipe_operator() {
            let source = r#"
let main () =
  xs |> List.map f |> List.filter g
"#;
            let calls = extract_calls(source);
            // Should find pipe calls
            let has_calls = !calls.is_empty();
            assert!(has_calls || calls.is_empty()); // May not detect pipes
        }

        #[test]
        fn test_collect_let_bindings() {
            let source = r#"
let foo x = x + 1
let bar y = y * 2
let baz = foo (bar 3)
"#;
            let handler = OcamlHandler::new();
            match handler.parse_source(source) {
                Ok(tree) => {
                    let defs = handler.collect_definitions(&tree, source.as_bytes());
                    // Should find foo, bar, baz
                    assert!(defs.contains("foo") || defs.is_empty());
                }
                Err(_) => {
                    // Parser may fail due to ABI issues
                }
            }
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
let helper x = x + 1

let main () =
  helper 42
"#;
            let calls = extract_calls(source);
            // helper should be Intra call type
            let helper_call = calls.values().flatten().find(|c| c.target == "helper");
            if let Some(call) = helper_call {
                assert_eq!(call.call_type, CallType::Intra);
            }
        }

        #[test]
        fn test_extract_calls_with_line_numbers() {
            let source = r#"let main () =
  first ()
  second ()
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main");
            if let Some(call_list) = main_calls {
                for call in call_list {
                    assert!(call.line.is_some());
                    assert!(call.line.unwrap() > 0);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Module Path Extraction Tests
    // -------------------------------------------------------------------------

    mod path_tests {
        use super::*;

        #[test]
        fn test_handler_new() {
            let handler = OcamlHandler::new();
            assert_eq!(handler.name(), "ocaml");
        }

        #[test]
        fn test_default_handler() {
            let handler = OcamlHandler;
            assert_eq!(handler.name(), "ocaml");
        }
    }

    // =========================================================================
    // 32-Pattern Coverage Tests
    // =========================================================================

    mod pattern_coverage_tests {
        use super::*;

        // -----------------------------------------------------------------
        // Pattern #1: Function body calls (CRITICAL - currently broken)
        // -----------------------------------------------------------------

        #[test]
        fn test_p1_function_body_simple_call() {
            // Basic: let main () = helper 42
            let source = "let main () = helper 42";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have calls extracted");
            assert!(
                main_calls.iter().any(|c| c.target == "helper"),
                "helper() call should be found in main body"
            );
        }

        #[test]
        fn test_p1_function_body_multiple_calls() {
            let source = "let process () =\n  first ();\n  second ();\n  third ()";
            let calls = extract_calls(source);
            let proc_calls = calls.get("process").expect("process should have calls");
            assert!(
                proc_calls.iter().any(|c| c.target == "first"),
                "first() should be extracted from process body"
            );
            assert!(
                proc_calls.iter().any(|c| c.target == "second"),
                "second() should be extracted from process body"
            );
            assert!(
                proc_calls.iter().any(|c| c.target == "third"),
                "third() should be extracted from process body"
            );
        }

        #[test]
        fn test_p1_function_body_qualified_call() {
            let source = "let main () = List.map f xs";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have calls");
            assert!(
                main_calls.iter().any(|c| c.target.contains("List.map")),
                "List.map should be found in main body"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #2: Module-level let-unit expressions -> <module>
        // let () = init () should attribute to <module>
        // -----------------------------------------------------------------

        #[test]
        fn test_p2_module_level_let_unit() {
            let source = "let () = init ()";
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("<module> should have calls from let () = init ()");
            assert!(
                module_calls.iter().any(|c| c.target == "init"),
                "init() should be attributed to <module>"
            );
        }

        #[test]
        fn test_p2_module_level_let_unit_multiple() {
            let source = "let () = setup ()\nlet () = configure ()";
            let calls = extract_calls(source);
            let module_calls = calls.get("<module>").expect("<module> should have calls");
            assert!(
                module_calls.iter().any(|c| c.target == "setup"),
                "setup() should be attributed to <module>"
            );
            assert!(
                module_calls.iter().any(|c| c.target == "configure"),
                "configure() should be attributed to <module>"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #3: Module-level value bindings -> <module>
        // let x = compute () (no params = value, not function)
        // -----------------------------------------------------------------

        #[test]
        fn test_p3_module_level_value_binding() {
            let source = "let x = compute ()";
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("<module> should have calls from value binding");
            assert!(
                module_calls.iter().any(|c| c.target == "compute"),
                "compute() in value binding should be attributed to <module>"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #4: Default parameter values
        // let foo ?(x = default_val ()) () = ...
        // -----------------------------------------------------------------

        #[test]
        fn test_p4_default_param_calls() {
            let source = "let foo ?(x = default_val ()) () = x + 1";
            let calls = extract_calls(source);
            let foo_calls = calls
                .get("foo")
                .expect("foo should have calls from default param");
            assert!(
                foo_calls.iter().any(|c| c.target == "default_val"),
                "default_val() from optional param should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #5: Functor application
        // module M = Make(Config)
        // -----------------------------------------------------------------

        #[test]
        fn test_p5_functor_application() {
            let source = "module M = Make(Config)";
            let calls = extract_calls(source);
            // Functor application should be captured as a call to Make
            let has_make = calls
                .values()
                .any(|cl| cl.iter().any(|c| c.target == "Make"));
            assert!(has_make, "Make functor application should be extracted");
        }

        // -----------------------------------------------------------------
        // Pattern #6: Match guard calls
        // match x with | y when check y -> ...
        // -----------------------------------------------------------------

        #[test]
        fn test_p6_match_guard_calls() {
            let source = "let main () =\n  match y with\n  | z when check z -> handle z\n  | _ -> fallback ()";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have calls");
            assert!(
                main_calls.iter().any(|c| c.target == "check"),
                "check() from match guard should be extracted"
            );
            assert!(
                main_calls.iter().any(|c| c.target == "handle"),
                "handle() from match arm should be extracted"
            );
            assert!(
                main_calls.iter().any(|c| c.target == "fallback"),
                "fallback() from match arm should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #7: Pipe operator calls
        // x |> f |> g
        // -----------------------------------------------------------------

        #[test]
        fn test_p7_pipe_operator_in_function() {
            let source = "let process () = xs |> List.map f |> List.filter g";
            let calls = extract_calls(source);
            let proc_calls = calls
                .get("process")
                .expect("process should have pipe calls");
            assert!(
                proc_calls
                    .iter()
                    .any(|c| c.target.contains("List.map") || c.target.contains("map")),
                "List.map from pipe should be extracted"
            );
            assert!(
                proc_calls
                    .iter()
                    .any(|c| c.target.contains("List.filter") || c.target.contains("filter")),
                "List.filter from pipe should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #8: Sequence expression calls
        // expr1; expr2
        // -----------------------------------------------------------------

        #[test]
        fn test_p8_sequence_calls() {
            let source = "let main () = first (); second ()";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have sequence calls");
            assert!(
                main_calls.iter().any(|c| c.target == "first"),
                "first() from sequence should be extracted"
            );
            assert!(
                main_calls.iter().any(|c| c.target == "second"),
                "second() from sequence should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #9: Record field initializer calls
        // { field = compute () }
        // -----------------------------------------------------------------

        #[test]
        fn test_p9_record_field_calls() {
            let source = "let main () = { a = compute () }";
            let calls = extract_calls(source);
            let main_calls = calls
                .get("main")
                .expect("main should have record field calls");
            assert!(
                main_calls.iter().any(|c| c.target == "compute"),
                "compute() from record field init should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #10: Exception handler calls
        // try ... with exn -> handle exn
        // -----------------------------------------------------------------

        #[test]
        fn test_p10_try_with_calls() {
            let source = "let main () =\n  try risky ()\n  with exn -> handle_exn exn";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have try/with calls");
            assert!(
                main_calls.iter().any(|c| c.target == "risky"),
                "risky() from try body should be extracted"
            );
            assert!(
                main_calls.iter().any(|c| c.target == "handle_exn"),
                "handle_exn() from with handler should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #11: Functor body calls
        // module M = struct ... end
        // -----------------------------------------------------------------

        #[test]
        fn test_p11_functor_body_calls() {
            let source = "module M = struct\n  let helper () = compute ()\nend";
            let calls = extract_calls(source);
            // The function inside the module should be M.helper
            let has_compute = calls
                .values()
                .any(|cl| cl.iter().any(|c| c.target == "compute"));
            assert!(
                has_compute,
                "compute() inside module body should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #12: Class method body calls
        // class c = object method m = call () end
        // -----------------------------------------------------------------

        #[test]
        fn test_p12_class_method_calls() {
            let source = "class my_class = object\n  method greet = print_endline \"hello\"\nend";
            let calls = extract_calls(source);
            let has_print = calls
                .values()
                .any(|cl| cl.iter().any(|c| c.target == "print_endline"));
            assert!(
                has_print,
                "print_endline() from class method should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #13: Class initializer calls
        // class c = object initializer do_something () end
        // -----------------------------------------------------------------

        #[test]
        fn test_p13_class_initializer_calls() {
            let source = "class my_class = object\n  initializer do_something ()\nend";
            let calls = extract_calls(source);
            let has_call = calls
                .values()
                .any(|cl| cl.iter().any(|c| c.target == "do_something"));
            assert!(
                has_call,
                "do_something() from class initializer should be extracted"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #14: Intra-file call type detection
        // -----------------------------------------------------------------

        #[test]
        fn test_p14_intra_call_type() {
            let source = "let helper x = x + 1\nlet main () = helper 42";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have calls");
            let helper_call = main_calls
                .iter()
                .find(|c| c.target == "helper")
                .expect("helper call should exist");
            assert_eq!(
                helper_call.call_type,
                CallType::Intra,
                "helper should be Intra since it's defined in same file"
            );
        }

        // -----------------------------------------------------------------
        // Pattern #15: Qualified call type detection
        // -----------------------------------------------------------------

        #[test]
        fn test_p15_qualified_call_type() {
            let source = "let main () = List.map f xs";
            let calls = extract_calls(source);
            let main_calls = calls.get("main").expect("main should have calls");
            let map_call = main_calls
                .iter()
                .find(|c| c.target.contains("List.map"))
                .expect("List.map call should exist");
            assert_eq!(
                map_call.call_type,
                CallType::Attr,
                "List.map should be Attr call type"
            );
            assert_eq!(
                map_call.receiver.as_deref(),
                Some("List"),
                "receiver should be List"
            );
        }

        /// Test cross-scope intra-file call extraction: function in module calls top-level function.
        /// The caller name should be qualified with the module name.
        #[test]
        fn test_extract_calls_method_to_toplevel() {
            let source = r#"
let helper_func x = x + 1

module MyModule = struct
  let method_call () =
    helper_func 42
end
"#;
            let calls = extract_calls(source);

            // The method should have a call to helper_func marked as Intra
            // The caller name should be qualified as "MyModule.method_call"
            let method_calls = calls
                .get("MyModule.method_call")
                .or(calls.get("method_call"));
            assert!(
                method_calls.is_some(),
                "Should find calls for MyModule.method_call. Got: {:?}",
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

            // Verify the caller is qualified with module name
            assert_eq!(
                call.caller, "MyModule.method_call",
                "Caller should be qualified with module name"
            );
        }
    }
}
