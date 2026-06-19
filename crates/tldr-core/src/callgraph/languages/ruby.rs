//! Ruby language handler for call graph analysis.
//!
//! This module provides Ruby-specific call graph support using tree-sitter-ruby.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `require 'json'` | `{module: "json", is_from: false}` |
//! | `require_relative 'helper'` | `{module: "helper", level: 1}` |
//! | `load 'file.rb'` | `{module: "file.rb", is_from: false}` |
//! | `include ModuleName` | `{module: "ModuleName", is_from: true}` |
//! | `extend ModuleName` | `{module: "ModuleName", is_from: true}` |
//!
//! # Call Extraction
//!
//! - Direct calls: `func()` -> CallType::Direct or CallType::Intra
//! - Method calls: `obj.method()` -> CallType::Attr
//! - Class method calls: `Class.method()` -> CallType::Attr
//! - Scoped calls: `Module::method()` -> CallType::Attr
//! - Block calls: `items.each { |x| }` -> CallType::Attr
//! - Constructor calls: `Class.new()` -> CallType::Attr
//! - DSL/class-body calls: `has_many :posts` -> caller is ClassName
//! - Constant initializers: `CONST = compute()` -> caller is ClassName or `<module>`
//! - Default parameter calls: `def foo(x = default())` -> caller is method
//! - Lambda/proc body calls: `-> { compute() }` -> caller is enclosing method
//! - String interpolation: `"#{compute()}"` -> caller is enclosing method
//! - Return/yield/raise args: `return compute()` -> caller is enclosing method
//! - Array/hash literal calls: `[foo(), bar()]` -> caller is enclosing method
//! - Ternary calls: `cond ? foo() : bar()` -> caller is enclosing method
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.6 for Ruby-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// Ruby Handler
// =============================================================================

/// Ruby language handler using tree-sitter-ruby.
///
/// Supports:
/// - Import parsing (require, require_relative, load, include, extend)
/// - Call extraction (direct, method, scoped, block calls)
/// - Class and module method tracking
/// - `<module>` synthetic function for module-level calls
#[derive(Debug, Default)]
pub struct RubyHandler;

impl RubyHandler {
    /// Creates a new RubyHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set Ruby language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Parse a require/require_relative/load call node.
    fn parse_require_call(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        // Ruby require calls are method calls: require 'module'
        // Node structure: call -> identifier (method name) + argument_list -> string

        if node.kind() != "call" {
            return None;
        }

        // Get method name
        let mut method_name: Option<String> = None;
        let mut module_path: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        let text = get_node_text(&child, source);
                        if method_name.is_none() {
                            method_name = Some(text.to_string());
                        }
                    }
                    "argument_list" => {
                        // Find string argument
                        for j in 0..child.child_count() {
                            if let Some(arg) = child.child(j) {
                                if arg.kind() == "string" {
                                    // Get string content, strip quotes
                                    let text = get_node_text(&arg, source);
                                    module_path = Some(
                                        text.trim_matches(|c| c == '"' || c == '\'').to_string(),
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    "string" => {
                        // Direct string argument (no parentheses)
                        let text = get_node_text(&child, source);
                        module_path =
                            Some(text.trim_matches(|c| c == '"' || c == '\'').to_string());
                    }
                    _ => {}
                }
            }
        }

        let method = method_name?;
        let module = module_path?;

        match method.as_str() {
            "require" => Some(ImportDef::simple_import(module)),
            "require_relative" => Some(ImportDef::relative_import(module, vec![], 1)),
            "load" => Some(ImportDef::simple_import(module)),
            _ => None,
        }
    }

    /// Parse an include/extend/prepend statement.
    fn parse_include_extend(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        // include ModuleName, extend ModuleName, or prepend ModuleName
        if node.kind() != "call" {
            return None;
        }

        let mut method_name: Option<String> = None;
        let mut module_name: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        let text = get_node_text(&child, source);
                        if method_name.is_none() {
                            method_name = Some(text.to_string());
                        }
                    }
                    "constant" => {
                        module_name = Some(get_node_text(&child, source).to_string());
                    }
                    "scope_resolution" => {
                        // Module::Submodule
                        module_name = Some(get_node_text(&child, source).to_string());
                    }
                    "argument_list" => {
                        // include(ModuleName)
                        for j in 0..child.child_count() {
                            if let Some(arg) = child.child(j) {
                                if arg.kind() == "constant" || arg.kind() == "scope_resolution" {
                                    module_name = Some(get_node_text(&arg, source).to_string());
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let method = method_name?;
        if method != "include" && method != "extend" && method != "prepend" {
            return None;
        }

        let module = module_name?;
        Some(ImportDef::from_import(module, vec![]))
    }

    /// Collect all method, class, and module definitions.
    fn collect_definitions(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> (HashSet<String>, HashSet<String>) {
        let mut methods = HashSet::new();
        let mut classes = HashSet::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "method" | "singleton_method" => {
                    // Get method name (identifier child)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "identifier" {
                                methods.insert(get_node_text(&child, source).to_string());
                                break;
                            }
                        }
                    }
                }
                "class" => {
                    // Get class name (constant child)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "constant" {
                                classes.insert(get_node_text(&child, source).to_string());
                                break;
                            }
                        }
                    }
                }
                "module" => {
                    // Get module name (constant child)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "constant" {
                                classes.insert(get_node_text(&child, source).to_string());
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        (methods, classes)
    }

    /// Extract calls from a method body node.
    ///
    /// Handles two Ruby method-dispatch shapes:
    ///
    /// 1. Parenthesized / sugared / receiver calls — `helper()`, `puts "x"`,
    ///    `obj.method`, `Class.new`, `Module::method` — all parsed as `call`
    ///    nodes by tree-sitter-ruby and processed by the existing `call` arm.
    ///
    /// 2. **Bareword** method dispatch — `helper` (no parens) — parsed as a
    ///    plain `identifier`. Ruby's semantics: any identifier in expression
    ///    position that is NOT bound as a local variable or parameter is a
    ///    method call (see Ruby spec, "Bareword method invocation"). The
    ///    bareword arm collects local bindings from the surrounding scope and
    ///    emits a `CallSite` for any identifier that is not bound, not a
    ///    declaration site, and not already counted as part of an enclosing
    ///    `call` node.
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        caller: &str,
    ) -> Vec<CallSite> {
        self.extract_calls_from_node_with_params(
            node,
            source,
            defined_methods,
            defined_classes,
            caller,
            None,
        )
    }

    /// Like `extract_calls_from_node`, but also factors method parameters
    /// (declared on the surrounding `method`/`singleton_method` node) into the
    /// local-binding set used for bareword filtering.
    ///
    /// Callers that have access to the parameters node (the per-method
    /// dispatch in `extract_calls`) should use this entry point. Module-level
    /// and class-body callers — which have no parameters — go through the
    /// thin wrapper `extract_calls_from_node`.
    fn extract_calls_from_node_with_params(
        &self,
        node: &Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        defined_classes: &HashSet<String>,
        caller: &str,
        params_node: Option<Node>,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        // -----------------------------------------------------------------
        // First pass: collect local bindings (parameters + assignment LHS).
        //
        // Ruby's bareword-vs-local-variable disambiguation depends on which
        // names are bound in the surrounding scope. We approximate the scope
        // by collecting:
        //   * Method parameters (positional, optional, keyword, splat,
        //     block, hash-splat) from the method's `method_parameters` node.
        //   * Block parameters declared inside the body.
        //   * Identifiers on the LHS of assignment / operator_assignment /
        //     left_assignment_list (multi-assign).
        //   * Loop induction variables (`for x in …` desugars to a
        //     `for`/`left_assignment_list` shape).
        // Nested-block bindings are conservatively hoisted into the enclosing
        // method's binding set — this is a documented approximation that
        // matches Ruby's lexical scope for top-level method bodies and only
        // produces false negatives (a real method call that happens to share
        // a name with a block-local variable would be missed). Tests cover
        // the common shapes; broader scoping can be refined later.
        // -----------------------------------------------------------------
        let mut bindings: HashSet<String> = HashSet::new();

        if let Some(params) = params_node {
            collect_param_bindings(&params, source, &mut bindings);
        }
        collect_body_bindings(node, source, &mut bindings);

        // -----------------------------------------------------------------
        // Second pass: walk the body, emit one CallSite per `call` node and
        // (new) one CallSite per bareword `identifier` node in expression
        // position not bound to a local.
        // -----------------------------------------------------------------
        for child in walk_tree(*node) {
            if child.kind() == "call" {
                // Metaprogramming: skip calls that live inside a synthesized
                // `define_method(:literal)` block body — those are re-parented
                // to `Class.method` by the synthesis path, not the current
                // caller.
                if is_in_define_method_literal_body(&child, source, node) {
                    continue;
                }

                // Metaprogramming: a literal `define_method(:name) { … }` call
                // itself defines a method; it is NOT a call edge to a function
                // named `define_method`. Its block body is handled by the
                // synthesis path. (A computed-name `define_method(expr)` falls
                // through to ordinary handling below and stays a plain call.)
                if define_method_literal(&child, source).is_some() {
                    continue;
                }

                // Metaprogramming: rewrite a literal `send`/`public_send`/
                // `__send__` to an Attr call on its receiver so the normal
                // receiver-resolution chain can bind it.
                if let Some(method) = child.child_by_field_name("method") {
                    if method.kind() == "identifier"
                        && metaprogramming_kind(get_node_text(&method, source))
                            == Some(MetaprogrammingKind::Send)
                    {
                        if let Some(site) = rewrite_send_call(&child, source, caller) {
                            calls.push(site);
                        }
                        // Whether or not arg0 was a literal we can resolve, do
                        // NOT fall through: a computed `send(var)` must be left
                        // UNRESOLVED (no spurious `obj.send` edge, no guess).
                        continue;
                    }
                }

                let line = child.start_position().row as u32 + 1;

                // Parse call structure
                let mut receiver: Option<String> = None;
                let mut method_name: Option<String> = None;
                let mut saw_dot = false;

                for i in 0..child.child_count() {
                    if let Some(c) = child.child(i) {
                        match c.kind() {
                            "identifier" => {
                                let text = get_node_text(&c, source).to_string();
                                if saw_dot || receiver.is_some() {
                                    method_name = Some(text);
                                } else if method_name.is_none() {
                                    // Could be either receiver or method
                                    method_name = Some(text);
                                }
                            }
                            "constant" => {
                                // Class/Module name as receiver
                                receiver = Some(get_node_text(&c, source).to_string());
                            }
                            "instance_variable" => {
                                receiver = Some(get_node_text(&c, source).to_string());
                            }
                            "scope_resolution" => {
                                // Module::Class receiver
                                receiver = Some(get_node_text(&c, source).to_string());
                            }
                            "." | "::" => {
                                saw_dot = true;
                                // If we already have a method_name, it was actually the receiver
                                if let Some(m) = method_name.take() {
                                    receiver = Some(m);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Skip import-related calls
                if let Some(ref m) = method_name {
                    if m == "require"
                        || m == "require_relative"
                        || m == "load"
                        || m == "include"
                        || m == "extend"
                        || m == "prepend"
                    {
                        continue;
                    }
                }

                // Determine call type and create CallSite
                if let Some(method) = method_name {
                    if let Some(recv) = receiver {
                        // Method call on receiver: obj.method() or Class.method()
                        let target = format!("{}.{}", recv, method);
                        calls.push(CallSite::new(
                            caller.to_string(),
                            target,
                            CallType::Attr,
                            Some(line),
                            None,
                            Some(recv),
                            None,
                        ));
                    } else {
                        // Direct call
                        let call_type = if defined_methods.contains(&method)
                            || defined_classes.contains(&method)
                        {
                            CallType::Intra
                        } else {
                            CallType::Direct
                        };
                        calls.push(CallSite::new(
                            caller.to_string(),
                            method,
                            call_type,
                            Some(line),
                            None,
                            None,
                            None,
                        ));
                    }
                }
            } else if child.kind() == "identifier"
                && is_bareword_method_call(&child, source, &bindings)
            {
                // Metaprogramming: a bareword inside a synthesized
                // `define_method(:literal)` block body belongs to the
                // synthesized method, not the current caller.
                if is_in_define_method_literal_body(&child, source, node) {
                    continue;
                }

                // Metaprogramming: the dynamic-name argument of a `send`-family
                // call is data, not a call. `send(some_var)` must not surface
                // `some_var` as a call edge (the computed dispatch is left
                // UNRESOLVED).
                if is_send_call_argument(&child, source) {
                    continue;
                }

                let text = get_node_text(&child, source).to_string();

                // Skip import-related barewords (defensive — these usually
                // appear with arguments and so parse as `call`, but cover
                // the edge case).
                if matches!(
                    text.as_str(),
                    "require" | "require_relative" | "load" | "include" | "extend" | "prepend"
                ) {
                    continue;
                }

                let line = child.start_position().row as u32 + 1;
                let call_type =
                    if defined_methods.contains(&text) || defined_classes.contains(&text) {
                        CallType::Intra
                    } else {
                        CallType::Direct
                    };
                calls.push(CallSite::new(
                    caller.to_string(),
                    text,
                    call_type,
                    Some(line),
                    None,
                    None,
                    None,
                ));
            }
        }

        calls
    }

    fn extract_method_name_from_node(&self, node: &Node, source: &[u8]) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    fn extract_constant_or_scope_name(&self, node: &Node, source: &[u8]) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "constant" || child.kind() == "scope_resolution" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    fn find_enclosing_class_or_module_name(&self, node: &Node, source: &[u8]) -> Option<String> {
        let mut parent = node.parent();
        while let Some(current) = parent {
            if current.kind() == "class" || current.kind() == "module" {
                return self.extract_constant_or_scope_name(&current, source);
            }
            parent = current.parent();
        }
        None
    }

    fn collect_class_methods_and_bases(
        &self,
        class_node: &Node,
        source: &[u8],
    ) -> (Vec<String>, Vec<String>) {
        let mut bases = Vec::new();
        let mut methods = Vec::new();

        for i in 0..class_node.child_count() {
            let Some(child) = class_node.child(i) else {
                continue;
            };
            if child.kind() == "superclass" {
                for j in 0..child.child_count() {
                    if let Some(base) = child.child(j) {
                        if base.kind() == "constant" || base.kind() == "scope_resolution" {
                            bases.push(get_node_text(&base, source).to_string());
                        }
                    }
                }
            }
            if child.kind() != "body_statement" {
                continue;
            }
            for j in 0..child.named_child_count() {
                let Some(member) = child.named_child(j) else {
                    continue;
                };
                if member.kind() == "method" || member.kind() == "singleton_method" {
                    if let Some(method_name) = self.extract_method_name_from_node(&member, source) {
                        methods.push(method_name);
                    }
                }
                if member.kind() == "call" {
                    if let Some(imp) = self.parse_include_extend(&member, source) {
                        if !bases.contains(&imp.module) {
                            bases.push(imp.module);
                        }
                    }
                }
            }
        }

        (methods, bases)
    }
}

// =============================================================================
// Bareword method-call helpers (VAL-012)
// =============================================================================

/// Collect identifier names declared as method/lambda/block parameters.
///
/// Walks the parameters subtree and accumulates the leaf `identifier` from
/// every parameter shape: positional, optional (`x = default`), keyword
/// (`x:`), keyword-with-default (`x: default`), splat (`*args`), double-splat
/// (`**opts`), block (`&blk`), and destructured tuple parameters.
fn collect_param_bindings(params: &Node, source: &[u8], bindings: &mut HashSet<String>) {
    for node in walk_tree(*params) {
        if node.kind() != "identifier" {
            // Splat / block / hash-splat parameters wrap their identifier in
            // the parameter shape itself; the inner `identifier` is caught
            // when the walker yields it.
            continue;
        }

        // Only count this identifier if its parent is a parameter shape —
        // not, e.g., a default-value expression like `def foo(x = bar)`
        // where `bar` should NOT be added as a binding.
        let Some(parent) = node.parent() else {
            continue;
        };
        if !is_param_shape(parent.kind()) {
            continue;
        }

        // For optional/keyword parameters, the identifier is typically the
        // FIRST named child (the name), not any subsequent expression
        // children. tree-sitter-ruby emits the name as the leftmost
        // identifier, so we only add it when this node is the first
        // identifier child of the parameter shape.
        if is_first_identifier_child(&parent, &node) {
            bindings.insert(get_node_text(&node, source).to_string());
        }
    }
}

/// Walk the body and add all locally-bound identifiers (assignment LHS,
/// block parameters, for-loop induction vars) to the bindings set.
///
/// This is approximate: nested-block bindings are conservatively hoisted to
/// the enclosing scope rather than being properly lexically scoped. The
/// approximation favors correctness for the call-graph use case (a binding
/// flagged anywhere in the body causes us to NOT emit a spurious call edge).
fn collect_body_bindings(body: &Node, source: &[u8], bindings: &mut HashSet<String>) {
    for node in walk_tree(*body) {
        match node.kind() {
            "assignment" => {
                if let Some(lhs) = node.child_by_field_name("left") {
                    add_lhs_bindings(&lhs, source, bindings);
                }
            }
            "operator_assignment" => {
                // `x += 1` — the LHS is also a binding (and a read, but the
                // read uses the existing binding so no false positive).
                if let Some(lhs) = node.child_by_field_name("left") {
                    add_lhs_bindings(&lhs, source, bindings);
                }
            }
            "left_assignment_list" => {
                // Inside `multiple_assignment`: `a, b = 1, 2` — every leaf
                // identifier is a new binding.
                for c in walk_tree(node) {
                    if c.kind() == "identifier" {
                        bindings.insert(get_node_text(&c, source).to_string());
                    }
                }
            }
            "block_parameters" | "lambda_parameters" => {
                // `do |x, y| … end` / `->(x) { … }` — each identifier is a
                // block-local binding. Conservative hoisting (see fn doc).
                collect_param_bindings(&node, source, bindings);
            }
            "for" => {
                // `for x in items; … end` — `x` is the induction variable.
                // tree-sitter-ruby exposes it as a `pattern` field, but we
                // can also catch it via the leftmost identifier child.
                if let Some(pat) = node.child_by_field_name("pattern") {
                    add_lhs_bindings(&pat, source, bindings);
                }
            }
            "rescue" => {
                // `rescue => e` — the captured exception name is a binding.
                // tree-sitter-ruby uses an `exception_variable` shape.
                for i in 0..node.named_child_count() {
                    if let Some(c) = node.named_child(i) {
                        if c.kind() == "exception_variable" {
                            for cc in walk_tree(c) {
                                if cc.kind() == "identifier" {
                                    bindings.insert(get_node_text(&cc, source).to_string());
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Add identifier bindings from a generic LHS expression (single var,
/// destructured tuple, splat-target, etc.).
fn add_lhs_bindings(lhs: &Node, source: &[u8], bindings: &mut HashSet<String>) {
    match lhs.kind() {
        "identifier" => {
            bindings.insert(get_node_text(lhs, source).to_string());
        }
        // Destructured / splat / nested LHS — collect every leaf identifier.
        _ => {
            for c in walk_tree(*lhs) {
                if c.kind() == "identifier" {
                    bindings.insert(get_node_text(&c, source).to_string());
                }
            }
        }
    }
}

/// True iff the given node kind is one of the parameter container kinds.
fn is_param_shape(kind: &str) -> bool {
    matches!(
        kind,
        "method_parameters"
            | "block_parameters"
            | "lambda_parameters"
            | "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "block_parameter"
            | "hash_splat_parameter"
            | "destructured_parameter"
    )
}

/// True iff `child` is the first `identifier` child of `parent`.
fn is_first_identifier_child(parent: &Node, child: &Node) -> bool {
    for i in 0..parent.child_count() {
        if let Some(c) = parent.child(i) {
            if c.kind() == "identifier" {
                return c.id() == child.id();
            }
        }
    }
    false
}

/// Decide whether an `identifier` node represents a bareword method call.
///
/// Filter rules (any → not a call):
///   1. The identifier text is bound as a local variable / parameter in
///      `bindings`.
///   2. The identifier's parent is itself a `call` node (the identifier is
///      already accounted for by the call-arm — as the method name or
///      receiver — so emitting a separate edge would double-count).
///   3. The identifier sits in a parameter declaration position (parent is
///      one of the `*_parameter` / `*_parameters` kinds).
///   4. The identifier is the name of a method/class/module/lambda
///      definition (parent is `method` / `singleton_method` / `class` /
///      `module` / `block` etc., and node is the name field).
///   5. The identifier is the LHS of an assignment (parent is `assignment`
///      / `operator_assignment` / `left_assignment_list` and node is on the
///      left side).
///   6. The identifier is part of a `scope_resolution` (`Module::method`)
///      receiver-side — the call arm already handles this.
///   7. The identifier is a hash-key (parent is `pair` and node is the
///      `key` field) or a symbol (`:foo` is a `simple_symbol`, not an
///      identifier — naturally excluded).
///   8. The identifier is a label (`foo:` in keyword arg syntax) — these
///      tree-sitter-ruby surfaces as `hash_key_symbol` not `identifier`,
///      so naturally excluded.
///   9. The identifier is the receiver of an existing `call` chain
///      (`helper.foo` — `helper` is the receiver; the call arm does not
///      currently emit an edge for the bareword receiver, but the
///      identifier's parent IS the `call` node, so rule 2 covers this).
fn is_bareword_method_call(node: &Node, source: &[u8], bindings: &HashSet<String>) -> bool {
    debug_assert_eq!(node.kind(), "identifier");

    let text = get_node_text(node, source);

    // Rule 1: local variable / parameter
    if bindings.contains(text) {
        return false;
    }

    let Some(parent) = node.parent() else {
        return false;
    };

    let parent_kind = parent.kind();

    // Rule 2: parent is a `call` (identifier is part of that call's
    // method name / receiver — already counted by the call arm).
    if parent_kind == "call" {
        return false;
    }

    // Rule 3: parameter declaration position.
    if is_param_shape(parent_kind) {
        return false;
    }

    // Rule 4: name of a definition.
    if matches!(
        parent_kind,
        "method" | "singleton_method" | "class" | "module" | "alias"
    ) {
        // tree-sitter-ruby uses field names like `name` for the method
        // identifier; if the field name is `name`, this is a declaration.
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return false;
            }
        }
        // Fallback: first identifier child of a method definition is its
        // name.
        if is_first_identifier_child(&parent, node) {
            return false;
        }
    }

    // Rule 5: LHS of assignment.
    if matches!(parent_kind, "assignment" | "operator_assignment") {
        if let Some(left) = parent.child_by_field_name("left") {
            if left.id() == node.id() {
                return false;
            }
        }
    }
    if parent_kind == "left_assignment_list" {
        return false;
    }

    // Rule 6: part of scope_resolution.
    if parent_kind == "scope_resolution" {
        return false;
    }

    // Rule 7: hash key.
    if parent_kind == "pair" {
        if let Some(key) = parent.child_by_field_name("key") {
            if key.id() == node.id() {
                return false;
            }
        }
    }

    // Rule 8: rescue exception variable / for-loop pattern — also a
    // declaration, not a use.
    if parent_kind == "exception_variable" {
        return false;
    }
    if parent_kind == "for" {
        if let Some(pat) = parent.child_by_field_name("pattern") {
            if pat.id() == node.id() {
                return false;
            }
        }
    }

    // Rule 9: argument keyword label — `foo(name: value)`.
    // tree-sitter-ruby surfaces these as `hash_key_symbol` for `name:`,
    // so naturally excluded; nothing to do here.

    // Rule 10: ancestor is already a `call` whose method/receiver we've
    // processed. The body walk processes a `call` node and its child
    // identifiers later. We must not double-count when an identifier is
    // a child of a `call` (handled by Rule 2 above), but we DO want to
    // emit edges for identifiers nested deeper inside the call's argument
    // list (`puts helper` → `helper` is inside `argument_list` whose
    // parent is the `call`; `helper`'s parent is `argument_list`, not
    // `call`, so Rule 2 doesn't apply and we emit `helper` correctly).

    true
}

// =============================================================================
// Metaprogramming: define_method / send / public_send / __send__
//
// Ruby ships a small, fixed set of reflective dispatch built-ins. This is a
// LANGUAGE-DEFINED set (like `require`/`include`), NOT a curated framework DSL
// dictionary — we deliberately do NOT recognize Rails/ActiveSupport macros
// (has_many, validates, …); those stay opaque and flow through the normal
// class-body DSL path. We only handle the literal-argument subset (Option B):
// when the dynamic name is given as a `simple_symbol` (`:foo`) or string
// literal we can resolve it AST-only; when it is a computed expression we
// leave it UNRESOLVED rather than guess.
// =============================================================================

/// The reflective-dispatch Ruby built-in a `call`'s method name denotes, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetaprogrammingKind {
    /// `define_method(:name) { … }` / `define_method(:name) do … end`.
    DefineMethod,
    /// `send` / `public_send` / `__send__` — dynamic dispatch.
    Send,
}

/// Classify a bareword method name against the fixed Ruby reflective-dispatch
/// built-in set. Returns `None` for anything outside that language-defined set.
fn metaprogramming_kind(name: &str) -> Option<MetaprogrammingKind> {
    match name {
        "define_method" => Some(MetaprogrammingKind::DefineMethod),
        "send" | "public_send" | "__send__" => Some(MetaprogrammingKind::Send),
        _ => None,
    }
}

/// Extract a method name from arg0 of an `argument_list` IFF it is a literal:
/// a `simple_symbol` (`:foo` → `foo`) or a `string` literal (`"foo"` → `foo`).
///
/// AST-only: we read the first NAMED child of the `argument_list` (skipping the
/// `(`/`)`/`,` anonymous tokens) and inspect its node kind. A `simple_symbol`'s
/// own text carries a leading `:` which we strip by reading the symbol's leaf
/// content; a `string` exposes its content via a `string_content` child. Any
/// other arg0 kind (notably a computed `identifier`) yields `None` — the caller
/// must then leave the dispatch UNRESOLVED.
fn literal_symbol_or_string_arg0(arg_list: &Node, source: &[u8]) -> Option<String> {
    let arg0 = arg_list.named_child(0)?;
    match arg0.kind() {
        "simple_symbol" => {
            // `:foo` — the literal text includes the leading colon. Strip the
            // single leading `:` by slicing past it on the byte text rather
            // than trimming arbitrary characters.
            let text = get_node_text(&arg0, source);
            text.strip_prefix(':')
                .filter(|rest| !rest.is_empty())
                .map(|rest| rest.to_string())
        }
        "string" => {
            // Read the `string_content` child to get the bare contents,
            // avoiding the surrounding quote tokens. Skip interpolated /
            // empty strings (no single static `string_content`).
            let mut content: Option<String> = None;
            for i in 0..arg0.named_child_count() {
                let Some(child) = arg0.named_child(i) else {
                    continue;
                };
                match child.kind() {
                    "string_content" => {
                        if content.is_some() {
                            // Multiple content chunks (interpolation) — not a
                            // simple literal; bail out.
                            return None;
                        }
                        content = Some(get_node_text(&child, source).to_string());
                    }
                    "interpolation" => return None,
                    _ => {}
                }
            }
            content.filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

/// Given a `call` node whose method name is a `send`-family built-in with a
/// literal arg0, build the rewritten Attr `CallSite` (target = the resolved
/// method name on the receiver). Returns `None` when the call is not a literal
/// `send` we can resolve (no method-name field, not a send built-in, or a
/// computed arg0) so the caller can fall back to UNRESOLVED handling.
///
/// The receiver is taken from the `call`'s `receiver` field when present
/// (`obj.send(:m)` → receiver `obj`); a receiverless `send(:m)` denotes
/// implicit-self dispatch and uses the `"self"` receiver convention so the
/// type-aware resolver binds it to the enclosing class.
fn rewrite_send_call(call: &Node, source: &[u8], caller: &str) -> Option<CallSite> {
    // Confirm this is a `send`-family built-in via the method-name field.
    let method = call.child_by_field_name("method")?;
    if method.kind() != "identifier" {
        return None;
    }
    if metaprogramming_kind(get_node_text(&method, source)) != Some(MetaprogrammingKind::Send) {
        return None;
    }

    // arg0 must be a literal symbol / string, else leave UNRESOLVED.
    let args = call.child_by_field_name("arguments")?;
    let target_method = literal_symbol_or_string_arg0(&args, source)?;

    // Receiver: explicit `obj.send(...)` receiver, or implicit `self`.
    let receiver = match call.child_by_field_name("receiver") {
        Some(recv) => get_node_text(&recv, source).to_string(),
        None => "self".to_string(),
    };

    let line = call.start_position().row as u32 + 1;
    let target = format!("{}.{}", receiver, target_method);
    Some(CallSite::new(
        caller.to_string(),
        target,
        CallType::Attr,
        Some(line),
        None,
        Some(receiver),
        None,
    ))
}

/// If `call` is `define_method(:literal) { … }` / `… do … end` with a literal
/// symbol arg0, return `(method_name, block_body_node)`. The block body is the
/// `body` field of the `block` (brace form, body kind `block_body`) or
/// `do_block` (do/end form, body kind `body_statement`). Returns `None` for a
/// computed arg0 (leave UNRESOLVED — do not guess) or a blockless call.
fn define_method_literal<'a>(call: &Node<'a>, source: &[u8]) -> Option<(String, Node<'a>)> {
    let method = call.child_by_field_name("method")?;
    if method.kind() != "identifier" {
        return None;
    }
    if metaprogramming_kind(get_node_text(&method, source)) != Some(MetaprogrammingKind::DefineMethod)
    {
        return None;
    }

    let args = call.child_by_field_name("arguments")?;
    let name = literal_symbol_or_string_arg0(&args, source)?;

    // Require a block to re-parent. tree-sitter-ruby exposes the block via the
    // `block` field for both the brace (`block`) and do/end (`do_block`) forms.
    let block = call.child_by_field_name("block")?;
    if !matches!(block.kind(), "block" | "do_block") {
        return None;
    }
    let body = block.child_by_field_name("body")?;
    Some((name, body))
}

/// True iff `node` lives inside the block body of a `define_method(:literal)`
/// call (a `block`/`do_block` whose parent `call` is a literal define_method),
/// searching only the ancestors strictly between `node` and `stop_at`.
///
/// Such nodes are owned by the SYNTHESIZED method and must NOT be attributed to
/// the enclosing caller during the ordinary body walk; the synthesis path
/// re-parents them to `Class.method`. The `stop_at` bound is the body node the
/// caller is currently scanning, so we never look past the method/class scope.
fn is_in_define_method_literal_body(node: &Node, source: &[u8], stop_at: &Node) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.id() == stop_at.id() {
            return false;
        }
        if matches!(n.kind(), "block" | "do_block") {
            if let Some(parent_call) = n.parent() {
                if parent_call.kind() == "call"
                    && define_method_literal(&parent_call, source).is_some()
                {
                    return true;
                }
            }
        }
        current = n.parent();
    }
    false
}

/// True iff `node` is an argument inside the `argument_list` of a `send`-family
/// call (`send`/`public_send`/`__send__`). Used to suppress bareword edges for
/// the dynamic-name argument: `send(some_var)` must not surface `some_var` as a
/// call, and `send(:sym)`'s symbol is naturally not an identifier.
fn is_send_call_argument(node: &Node, source: &[u8]) -> bool {
    let Some(arg_list) = node.parent() else {
        return false;
    };
    if arg_list.kind() != "argument_list" {
        return false;
    }
    let Some(call) = arg_list.parent() else {
        return false;
    };
    if call.kind() != "call" {
        return false;
    }
    let Some(method) = call.child_by_field_name("method") else {
        return false;
    };
    method.kind() == "identifier"
        && metaprogramming_kind(get_node_text(&method, source)) == Some(MetaprogrammingKind::Send)
}

impl CallGraphLanguageSupport for RubyHandler {
    fn name(&self) -> &str {
        "ruby"
    }

    fn extensions(&self) -> &[&str] {
        &[".rb", ".rake"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            if node.kind() == "call" {
                // Try parsing as require/require_relative/load
                if let Some(imp) = self.parse_require_call(&node, source_bytes) {
                    imports.push(imp);
                    continue;
                }
                // Try parsing as include/extend
                if let Some(imp) = self.parse_include_extend(&node, source_bytes) {
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
        let (defined_methods, defined_classes) = self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();

        // Track current class/module context
        let mut current_class: Option<String> = None;

        fn process_node(
            node: Node,
            source: &[u8],
            defined_methods: &HashSet<String>,
            defined_classes: &HashSet<String>,
            calls_by_func: &mut HashMap<String, Vec<CallSite>>,
            current_class: &mut Option<String>,
            handler: &RubyHandler,
        ) {
            match node.kind() {
                "class" | "module" => {
                    // Get class/module name
                    let mut class_name: Option<String> = None;
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "constant" {
                                class_name = Some(get_node_text(&child, source).to_string());
                                break;
                            }
                        }
                    }

                    let old_class = current_class.take();
                    *current_class = class_name;

                    // Extract class-body level calls (DSL calls, constant inits)
                    // These are calls that appear directly in the class body,
                    // not inside method definitions (e.g., has_many, validates,
                    // belongs_to, before_action, scope, CONSTANT = compute())
                    if let Some(ref class_nm) = *current_class {
                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                if child.kind() == "body_statement" {
                                    let mut class_body_calls = Vec::new();
                                    for j in 0..child.named_child_count() {
                                        if let Some(member) = child.named_child(j) {
                                            // Skip method/class/module defs - they have their own callers
                                            if matches!(
                                                member.kind(),
                                                "method" | "singleton_method" | "class" | "module"
                                            ) {
                                                continue;
                                            }
                                            // Extract calls from this body-level node
                                            let calls = handler.extract_calls_from_node(
                                                &member,
                                                source,
                                                defined_methods,
                                                defined_classes,
                                                class_nm,
                                            );
                                            class_body_calls.extend(calls);
                                        }
                                    }
                                    if !class_body_calls.is_empty() {
                                        calls_by_func
                                            .entry(class_nm.clone())
                                            .or_default()
                                            .extend(class_body_calls);
                                    }
                                }
                            }
                        }
                    }

                    // Process children (recurse into methods, nested classes, etc.)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            process_node(
                                child,
                                source,
                                defined_methods,
                                defined_classes,
                                calls_by_func,
                                current_class,
                                handler,
                            );
                        }
                    }

                    *current_class = old_class;
                }
                "method" | "singleton_method" => {
                    // Get method name, body, and parameters
                    let mut method_name: Option<String> = None;
                    let mut body: Option<Node> = None;
                    let mut params: Option<Node> = None;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "identifier" => {
                                    if method_name.is_none() {
                                        method_name =
                                            Some(get_node_text(&child, source).to_string());
                                    }
                                }
                                "body_statement" => {
                                    body = Some(child);
                                }
                                "method_parameters" => {
                                    params = Some(child);
                                }
                                _ => {}
                            }
                        }
                    }

                    if let Some(name) = method_name {
                        let full_name = if let Some(ref class) = current_class {
                            format!("{}.{}", class, name)
                        } else {
                            name.clone()
                        };

                        let mut all_calls = Vec::new();

                        // Extract calls from method body, with the surrounding
                        // method's parameters factored into the bareword
                        // bindings set so parameter reads aren't misclassified
                        // as method calls.
                        if let Some(body_node) = body {
                            let calls = handler.extract_calls_from_node_with_params(
                                &body_node,
                                source,
                                defined_methods,
                                defined_classes,
                                &full_name,
                                params,
                            );
                            all_calls.extend(calls);
                        }

                        // Extract calls from default parameter values
                        // e.g., def foo(x = compute_default()) -> compute_default is a call
                        if let Some(params_node) = params {
                            for child in walk_tree(params_node) {
                                if child.kind() == "optional_parameter" {
                                    // The optional_parameter has: identifier, =, expression
                                    // Extract calls from the default value expression
                                    let param_calls = handler.extract_calls_from_node(
                                        &child,
                                        source,
                                        defined_methods,
                                        defined_classes,
                                        &full_name,
                                    );
                                    all_calls.extend(param_calls);
                                }
                            }
                        }

                        if !all_calls.is_empty() {
                            calls_by_func.insert(full_name.clone(), all_calls.clone());
                            // Also store with simple name
                            if current_class.is_some() {
                                calls_by_func.insert(name, all_calls);
                            }
                        }
                    }
                }
                "call" => {
                    // Metaprogramming: `define_method(:literal) { … }` /
                    // `… do … end` SYNTHESIZES a method on the enclosing class
                    // (Option B). We create a real `Class.method` (or top-level
                    // `method`) entry and re-parent the block body's calls to
                    // it, instead of letting them fall through to the enclosing
                    // class/module caller. A computed `define_method(expr)` is
                    // left UNRESOLVED (no synthesis) and flows through the
                    // ordinary recursion below.
                    if let Some((method_name, block_body)) =
                        define_method_literal(&node, source)
                    {
                        let full_name = if let Some(ref class) = current_class {
                            format!("{}.{}", class, method_name)
                        } else {
                            method_name.clone()
                        };

                        // Factor the block's own parameters (`do |x| …`) into
                        // the bareword-binding set so block-param reads inside
                        // the body aren't misclassified as calls.
                        let block_params = node
                            .child_by_field_name("block")
                            .and_then(|b| b.child_by_field_name("parameters"));

                        let body_calls = handler.extract_calls_from_node_with_params(
                            &block_body,
                            source,
                            defined_methods,
                            defined_classes,
                            &full_name,
                            block_params,
                        );

                        if !body_calls.is_empty() {
                            calls_by_func
                                .entry(full_name.clone())
                                .or_default()
                                .extend(body_calls.clone());
                            // Mirror the `def` convention: also index under the
                            // simple name when nested in a class/module.
                            if current_class.is_some() {
                                calls_by_func
                                    .entry(method_name)
                                    .or_default()
                                    .extend(body_calls);
                            }
                        } else {
                            // Ensure the synthesized method exists as a node
                            // even with an empty body so downstream consumers
                            // can see the definition.
                            calls_by_func.entry(full_name).or_default();
                        }
                    }

                    // Recurse into children regardless: a non-define_method
                    // `call` (or a computed define_method) may still contain
                    // nested defs / calls to process.
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            process_node(
                                child,
                                source,
                                defined_methods,
                                defined_classes,
                                calls_by_func,
                                current_class,
                                handler,
                            );
                        }
                    }
                }
                _ => {
                    // Recurse for other nodes
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            process_node(
                                child,
                                source,
                                defined_methods,
                                defined_classes,
                                calls_by_func,
                                current_class,
                                handler,
                            );
                        }
                    }
                }
            }
        }

        process_node(
            tree.root_node(),
            source_bytes,
            &defined_methods,
            &defined_classes,
            &mut calls_by_func,
            &mut current_class,
            self,
        );

        // Extract module-level calls into synthetic <module> function
        let mut module_calls = Vec::new();
        for node in tree.root_node().children(&mut tree.root_node().walk()) {
            // Skip class, module, and method definitions
            if matches!(
                node.kind(),
                "class" | "module" | "method" | "singleton_method"
            ) {
                continue;
            }

            let calls = self.extract_calls_from_node(
                &node,
                source_bytes,
                &defined_methods,
                &defined_classes,
                "<module>",
            );
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
        let mut classes = Vec::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "method" | "singleton_method" => {
                    let Some(name) = self.extract_method_name_from_node(&node, source_bytes) else {
                        continue;
                    };
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    if let Some(class_name) =
                        self.find_enclosing_class_or_module_name(&node, source_bytes)
                    {
                        funcs.push(FuncDef::method(name, class_name, line, end_line));
                    } else {
                        funcs.push(FuncDef::function(name, line, end_line));
                    }
                }
                "class" => {
                    let Some(class_name) = self.extract_constant_or_scope_name(&node, source_bytes)
                    else {
                        continue;
                    };
                    let (methods, bases) =
                        self.collect_class_methods_and_bases(&node, source_bytes);
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    classes.push(ClassDef::new(class_name, line, end_line, methods, bases));
                }
                "module" => {
                    let Some(module_name) =
                        self.extract_constant_or_scope_name(&node, source_bytes)
                    else {
                        continue;
                    };
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    classes.push(ClassDef::simple(module_name, line, end_line));
                }
                "call" => {
                    // Metaprogramming: `define_method(:literal) { … }` /
                    // `… do … end` SYNTHESIZES a real method node (Option B),
                    // mirroring the `def` convention so `impact`/`dead`/the
                    // callgraph node listing see the generated method as
                    // DEFINED. We emit ONE `FuncDef`; the indexer registers it
                    // under BOTH the bare name and `Class.method` exactly as it
                    // does for a normal method (see builder_v2 indexing).
                    //
                    // A computed `define_method(expr)` arg0 yields `None` from
                    // `define_method_literal` (no literal symbol/string), so we
                    // synthesize NOTHING and leave the method unresolved — we do
                    // not guess a name. `send`/`public_send`/`__send__` are not
                    // definitions and never reach this branch.
                    if let Some((method_name, _block_body)) =
                        define_method_literal(&node, source_bytes)
                    {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        if let Some(class_name) =
                            self.find_enclosing_class_or_module_name(&node, source_bytes)
                        {
                            funcs.push(FuncDef::method(method_name, class_name, line, end_line));
                        } else {
                            funcs.push(FuncDef::function(method_name, line, end_line));
                        }
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
        let handler = RubyHandler::new();
        handler.parse_imports(source, Path::new("test.rb")).unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = RubyHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("test.rb"), source, &tree)
            .unwrap()
    }

    fn extract_definitions(source: &str) -> (Vec<FuncDef>, Vec<ClassDef>) {
        let handler = RubyHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_definitions(source, Path::new("test.rb"), &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_require() {
            let imports = parse_imports("require 'json'");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "json");
            assert!(!imports[0].is_relative());
        }

        #[test]
        fn test_parse_require_with_parens() {
            let imports = parse_imports("require('json')");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "json");
        }

        #[test]
        fn test_parse_require_relative() {
            let imports = parse_imports("require_relative 'helper'");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "helper");
            assert!(imports[0].is_relative());
            assert_eq!(imports[0].level, 1);
        }

        #[test]
        fn test_parse_load() {
            let imports = parse_imports("load 'config.rb'");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "config.rb");
        }

        #[test]
        fn test_parse_include() {
            let imports = parse_imports("include Comparable");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "Comparable");
            assert!(imports[0].is_from);
        }

        #[test]
        fn test_parse_extend() {
            let imports = parse_imports("extend ActiveSupport::Concern");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].module.contains("ActiveSupport"));
        }

        #[test]
        fn test_parse_multiple_imports() {
            let source = r#"
require 'json'
require_relative 'helper'
include Comparable
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
def main
  puts "hello"
  helper()
end
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            assert!(main_calls.iter().any(|c| c.target == "puts"));
            assert!(main_calls.iter().any(|c| c.target == "helper"));
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
def helper
  "help"
end

def main
  helper()
end
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            let helper_call = main_calls.iter().find(|c| c.target == "helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_method_on_object() {
            let source = r#"
def process
  @repo.find(id)
  user.save()
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process").unwrap();
            assert!(process_calls.iter().any(|c| c.target.contains("find")));
            assert!(process_calls.iter().any(|c| c.target.contains("save")));
        }

        #[test]
        fn test_extract_calls_class_method() {
            let source = r#"
def create_user
  User.create(name: "test")
end
"#;
            let calls = extract_calls(source);
            let calls_list = calls.get("create_user").unwrap();
            let create_call = calls_list
                .iter()
                .find(|c| c.target.contains("create"))
                .unwrap();
            assert_eq!(create_call.call_type, CallType::Attr);
            assert!(create_call.receiver.as_ref().unwrap().contains("User"));
        }

        #[test]
        fn test_extract_calls_in_class() {
            let source = r#"
class Calculator
  def add(a, b)
    validate(a)
    a + b
  end

  def validate(n)
    raise "Invalid" if n.nil?
  end
end
"#;
            let calls = extract_calls(source);
            // Should have both Calculator.add and add
            assert!(calls.contains_key("Calculator.add") || calls.contains_key("add"));
        }

        #[test]
        fn test_extract_calls_with_block() {
            let source = r#"
def process_items
  items.each do |item|
    transform(item)
  end
end
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process_items").unwrap();
            assert!(process_calls.iter().any(|c| c.target.contains("each")));
        }

        #[test]
        fn test_extract_calls_module_level() {
            let source = r#"
def helper
  "help"
end

# Module-level call
result = helper()
"#;
            let calls = extract_calls(source);
            assert!(calls.contains_key("<module>"));
            let module_calls = calls.get("<module>").unwrap();
            assert!(module_calls.iter().any(|c| c.target == "helper"));
        }

        // ---------------------------------------------------------------
        // VAL-012: Bareword (parens-free) method dispatch
        //
        // tree-sitter-ruby parses `helper` (no parens) as an `identifier`
        // node, not a `call` node. The handler must resolve barewords in
        // expression position to method calls — but must NOT misclassify
        // local-variable reads or parameter references as method calls.
        // ---------------------------------------------------------------

        #[test]
        fn test_extract_calls_bareword_free_function() {
            let source = "def helper\n  1\nend\n\ndef main\n  helper\nend\n";
            let calls = extract_calls(source);
            let main_calls = calls
                .get("main")
                .expect("main should have at least one call");
            assert!(
                main_calls.iter().any(|c| c.target == "helper"),
                "bareword `helper` should be extracted as a call from main. Got: {:?}",
                main_calls,
            );
            // `helper` is defined in this file, so the edge type is Intra.
            let helper_call = main_calls
                .iter()
                .find(|c| c.target == "helper")
                .expect("helper call must exist");
            assert_eq!(helper_call.call_type, CallType::Intra);
        }

        #[test]
        fn test_extract_calls_bareword_does_not_trigger_for_local_var() {
            let source = "def main\n  x = 1\n  x\nend\n";
            let calls = extract_calls(source);
            // `x` is a local variable bound by assignment; reading it must
            // NOT produce a call edge.
            if let Some(main_calls) = calls.get("main") {
                assert!(
                    !main_calls.iter().any(|c| c.target == "x"),
                    "local variable read `x` should NOT be a call. Got: {:?}",
                    main_calls,
                );
            }
        }

        #[test]
        fn test_extract_calls_bareword_does_not_trigger_for_parameter() {
            let source = "def main(x)\n  x\nend\n";
            let calls = extract_calls(source);
            // `x` is a method parameter; reading it must NOT produce a call.
            if let Some(main_calls) = calls.get("main") {
                assert!(
                    !main_calls.iter().any(|c| c.target == "x"),
                    "parameter read `x` should NOT be a call. Got: {:?}",
                    main_calls,
                );
            }
        }

        #[test]
        fn test_extract_calls_bareword_in_argument_position() {
            let source = "def main\n  puts helper\nend\n";
            let calls = extract_calls(source);
            let main_calls = calls
                .get("main")
                .expect("main should have at least one call");
            assert!(
                main_calls.iter().any(|c| c.target == "puts"),
                "`puts` call should be extracted. Got: {:?}",
                main_calls,
            );
            assert!(
                main_calls.iter().any(|c| c.target == "helper"),
                "bareword `helper` in argument position should be extracted. Got: {:?}",
                main_calls,
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #21: DSL/Class-Body Method Calls (P0 Critical)
    // -------------------------------------------------------------------------

    mod dsl_class_body_tests {
        use super::*;

        #[test]
        fn test_rails_dsl_has_many() {
            let source = r#"
class User < ApplicationRecord
  has_many :posts
  belongs_to :organization
  validates :name, presence: true
end
"#;
            let calls = extract_calls(source);
            let user_calls = calls.get("User").expect("User class should have DSL calls");
            assert!(
                user_calls.iter().any(|c| c.target == "has_many"),
                "has_many should be extracted as call from User. Got: {:?}",
                user_calls
            );
            assert!(
                user_calls.iter().any(|c| c.target == "belongs_to"),
                "belongs_to should be extracted as call from User. Got: {:?}",
                user_calls
            );
            assert!(
                user_calls.iter().any(|c| c.target == "validates"),
                "validates should be extracted as call from User. Got: {:?}",
                user_calls
            );
        }

        #[test]
        fn test_rails_dsl_callbacks() {
            let source = r#"
class PostsController < ApplicationController
  before_action :authenticate
  after_action :log_activity
  skip_before_action :verify_token
end
"#;
            let calls = extract_calls(source);
            let ctrl_calls = calls
                .get("PostsController")
                .expect("PostsController should have DSL calls");
            assert!(
                ctrl_calls.iter().any(|c| c.target == "before_action"),
                "before_action should be extracted. Got: {:?}",
                ctrl_calls
            );
            assert!(
                ctrl_calls.iter().any(|c| c.target == "after_action"),
                "after_action should be extracted. Got: {:?}",
                ctrl_calls
            );
            assert!(
                ctrl_calls.iter().any(|c| c.target == "skip_before_action"),
                "skip_before_action should be extracted. Got: {:?}",
                ctrl_calls
            );
        }

        #[test]
        fn test_class_body_attr_accessor() {
            let source = r#"
class Config
  attr_accessor :name, :value
  attr_reader :id
end
"#;
            let calls = extract_calls(source);
            let config_calls = calls.get("Config").expect("Config should have DSL calls");
            assert!(
                config_calls.iter().any(|c| c.target == "attr_accessor"),
                "attr_accessor should be extracted. Got: {:?}",
                config_calls
            );
            assert!(
                config_calls.iter().any(|c| c.target == "attr_reader"),
                "attr_reader should be extracted. Got: {:?}",
                config_calls
            );
        }

        #[test]
        fn test_class_body_scope_dsl() {
            let source = r#"
class Product < ApplicationRecord
  scope :active, -> { where(active: true) }
  scope :recent, -> { order(created_at: :desc) }
end
"#;
            let calls = extract_calls(source);
            let product_calls = calls.get("Product").expect("Product should have DSL calls");
            assert!(
                product_calls.iter().any(|c| c.target == "scope"),
                "scope should be extracted. Got: {:?}",
                product_calls
            );
        }

        #[test]
        fn test_class_body_include_as_call() {
            // include/extend are imports, but should also show as calls from the class
            let source = r#"
class User
  include Comparable
  extend ClassMethods
  prepend Validatable
end
"#;
            let calls = extract_calls(source);
            // include/extend/prepend are filtered as imports, so they won't appear as calls
            // This is correct behavior -- we verify no crash
            assert!(
                calls.is_empty()
                    || !calls.contains_key("User")
                    || calls.get("User").is_none_or(|c| c.is_empty()),
                "include/extend/prepend are handled as imports, not calls"
            );
        }

        #[test]
        fn test_class_body_mixed_dsl_and_methods() {
            let source = r#"
class Order < ApplicationRecord
  has_many :line_items
  belongs_to :customer
  validates :total, numericality: true

  def calculate_total
    line_items.sum(:price)
  end
end
"#;
            let calls = extract_calls(source);
            // Class body DSL calls
            let order_calls = calls.get("Order").expect("Order should have DSL calls");
            assert!(
                order_calls.iter().any(|c| c.target == "has_many"),
                "has_many should be extracted. Got: {:?}",
                order_calls
            );
            // Method calls
            assert!(
                calls.contains_key("Order.calculate_total")
                    || calls.contains_key("calculate_total"),
                "calculate_total method should also be tracked"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Metaprogramming: define_method / send / public_send / __send__
    // (Option B — literal-argument subset, AST-only)
    // -------------------------------------------------------------------------

    mod metaprogramming_tests {
        use super::*;

        #[test]
        fn test_define_method_literal_symbol_synthesizes_method() {
            // define_method(:greet) { ... } should SYNTHESIZE a method
            // `Widget.greet`, and the block body's calls must attach to
            // `Widget.greet`, NOT to the enclosing class `Widget`.
            let source = r#"
class Widget
  define_method(:greet) do
    build_greeting
    other.render
  end
end
"#;
            let calls = extract_calls(source);

            // The synthesized method key must exist.
            let greet_calls = calls.get("Widget.greet").unwrap_or_else(|| {
                panic!(
                    "define_method(:greet) should synthesize `Widget.greet`. Keys: {:?}",
                    calls.keys().collect::<Vec<_>>()
                )
            });

            // Block body calls attach to the synthesized method.
            assert!(
                greet_calls.iter().any(|c| c.target == "build_greeting"),
                "bareword call inside define_method body should attach to Widget.greet. Got: {:?}",
                greet_calls
            );
            assert!(
                greet_calls
                    .iter()
                    .any(|c| c.target == "other.render" && c.call_type == CallType::Attr),
                "receiver call inside define_method body should attach to Widget.greet. Got: {:?}",
                greet_calls
            );

            // CRITICAL: those body calls must NOT be re-parented to the
            // enclosing class `Widget`.
            if let Some(widget_calls) = calls.get("Widget") {
                assert!(
                    !widget_calls.iter().any(|c| c.target == "build_greeting"),
                    "define_method body call must NOT attach to enclosing class Widget. Got: {:?}",
                    widget_calls
                );
                assert!(
                    !widget_calls.iter().any(|c| c.target == "other.render"),
                    "define_method body receiver call must NOT attach to Widget. Got: {:?}",
                    widget_calls
                );
            }
        }

        #[test]
        fn test_define_method_brace_block_synthesizes_method() {
            // Brace-block form `define_method(:wave) { ... }` (block node,
            // block_body body) must behave the same as the do/end form.
            let source = r#"
class Widget
  define_method(:wave) { wave_helper }
end
"#;
            let calls = extract_calls(source);
            let wave_calls = calls.get("Widget.wave").unwrap_or_else(|| {
                panic!(
                    "define_method(:wave) {{ }} should synthesize `Widget.wave`. Keys: {:?}",
                    calls.keys().collect::<Vec<_>>()
                )
            });
            assert!(
                wave_calls.iter().any(|c| c.target == "wave_helper"),
                "brace-block body call should attach to Widget.wave. Got: {:?}",
                wave_calls
            );
        }

        #[test]
        fn test_define_method_literal_synthesizes_funcdef_computed_does_not() {
            // DISCRIMINATION PROOF (one test, two arms):
            //  * A LITERAL `define_method(:greet)` MUST synthesize a real
            //    `FuncDef` for `Widget.greet` in the definitions index — so
            //    `impact`/`dead`/the callgraph node listing see it as DEFINED.
            //    This arm fails on code that does not synthesize literal defs.
            //  * A COMPUTED `define_method(:"x_#{n}")` (delimited/interpolated
            //    symbol, NOT a static literal) MUST synthesize NOTHING — we do
            //    not guess a name.
            let source = r#"
class Widget
  define_method(:greet) do
    build_greeting
  end

  define_method(:"x_#{n}") do
    inner_call
  end
end
"#;
            let (funcs, _classes) = extract_definitions(source);

            // --- Literal arm: the synthesized method MUST be a real FuncDef. ---
            let greet = funcs
                .iter()
                .find(|f| f.qualified_name() == "Widget.greet")
                .unwrap_or_else(|| {
                    panic!(
                        "literal define_method(:greet) must synthesize a FuncDef \
                         `Widget.greet`. Got defs: {:?}",
                        funcs
                            .iter()
                            .map(|f| f.qualified_name())
                            .collect::<Vec<_>>()
                    )
                });
            assert_eq!(greet.name, "greet", "synthesized def keeps the bare name");
            assert!(greet.is_method, "synthesized def must be a method");
            assert_eq!(greet.class_name.as_deref(), Some("Widget"));

            // --- Computed arm: NO fabricated name from the interpolated arg. ---
            // The `delimited_symbol` `:"x_#{n}"` is not a static literal, so no
            // FuncDef may be invented for it. We assert no synthesized def
            // carries the interpolation fragment, AND that the only synthesized
            // method on Widget is the literal one.
            assert!(
                !funcs.iter().any(|f| f.name.contains("x_") || f.name.contains('#')),
                "computed define_method(:\"x_#{{n}}\") must not fabricate a FuncDef. \
                 Got defs: {:?}",
                funcs.iter().map(|f| f.qualified_name()).collect::<Vec<_>>()
            );
            assert_eq!(
                funcs
                    .iter()
                    .filter(|f| f.class_name.as_deref() == Some("Widget"))
                    .count(),
                1,
                "exactly one method (the literal :greet) should be synthesized on \
                 Widget; the computed one must be skipped. Got defs: {:?}",
                funcs.iter().map(|f| f.qualified_name()).collect::<Vec<_>>()
            );

            // The call-graph view must mirror the same discrimination: the
            // literal key exists, the computed name is never guessed.
            let calls = extract_calls(source);
            assert!(
                calls.contains_key("Widget.greet"),
                "literal define_method(:greet) should also surface in the call \
                 graph. Keys: {:?}",
                calls.keys().collect::<Vec<_>>()
            );
            assert!(
                !calls.keys().any(|k| k.contains("x_") || k.contains('#')),
                "computed define_method arg must not be guessed into a call key. \
                 Keys: {:?}",
                calls.keys().collect::<Vec<_>>()
            );
        }

        #[test]
        fn test_send_literal_symbol_resolves_via_attr() {
            // obj.send(:do_thing) -> Attr call, target = obj.do_thing.
            let source = r#"
class Runner
  def run
    obj.send(:do_thing)
  end
end
"#;
            let calls = extract_calls(source);
            let run_calls = calls
                .get("Runner.run")
                .or_else(|| calls.get("run"))
                .expect("Runner.run should have calls");
            assert!(
                run_calls.iter().any(|c| {
                    c.target == "obj.do_thing"
                        && c.call_type == CallType::Attr
                        && c.receiver.as_deref() == Some("obj")
                }),
                "obj.send(:do_thing) should rewrite to Attr obj.do_thing. Got: {:?}",
                run_calls
            );
            // The literal `send` itself must not leak as a Direct call target.
            assert!(
                !run_calls.iter().any(|c| c.target == "send"),
                "rewritten send must not also emit a `send` call. Got: {:?}",
                run_calls
            );
        }

        #[test]
        fn test_public_send_string_literal_resolves_via_attr() {
            // obj.public_send("do_thing") with a string literal arg0.
            let source = r#"
class Runner
  def run
    obj.public_send("do_thing")
  end
end
"#;
            let calls = extract_calls(source);
            let run_calls = calls
                .get("Runner.run")
                .or_else(|| calls.get("run"))
                .expect("Runner.run should have calls");
            assert!(
                run_calls.iter().any(|c| {
                    c.target == "obj.do_thing"
                        && c.call_type == CallType::Attr
                        && c.receiver.as_deref() == Some("obj")
                }),
                "obj.public_send(\"do_thing\") should rewrite to Attr obj.do_thing. Got: {:?}",
                run_calls
            );
        }

        #[test]
        fn test_send_receiverless_literal_resolves_self() {
            // send(:do_thing) with no explicit receiver -> implicit self.
            let source = r#"
class Runner
  def run
    send(:do_thing)
  end
end
"#;
            let calls = extract_calls(source);
            let run_calls = calls
                .get("Runner.run")
                .or_else(|| calls.get("run"))
                .expect("Runner.run should have calls");
            assert!(
                run_calls.iter().any(|c| {
                    c.target == "self.do_thing"
                        && c.call_type == CallType::Attr
                        && c.receiver.as_deref() == Some("self")
                }),
                "receiverless send(:do_thing) should rewrite to Attr self.do_thing. Got: {:?}",
                run_calls
            );
        }

        #[test]
        fn test_dunder_send_literal_symbol_resolves_via_attr() {
            // obj.__send__(:do_thing) -> Attr call, target = obj.do_thing.
            // `__send__` is in the send-family vocab and must resolve exactly
            // like `send`/`public_send`.
            let source = r#"
class Runner
  def run
    obj.__send__(:do_thing)
  end
end
"#;
            let calls = extract_calls(source);
            let run_calls = calls
                .get("Runner.run")
                .or_else(|| calls.get("run"))
                .expect("Runner.run should have calls");
            assert!(
                run_calls.iter().any(|c| {
                    c.target == "obj.do_thing"
                        && c.call_type == CallType::Attr
                        && c.receiver.as_deref() == Some("obj")
                }),
                "obj.__send__(:do_thing) should rewrite to Attr obj.do_thing. Got: {:?}",
                run_calls
            );
            // The literal `__send__` itself must not leak as a Direct call.
            assert!(
                !run_calls.iter().any(|c| c.target == "__send__"),
                "rewritten __send__ must not also emit a `__send__` call. Got: {:?}",
                run_calls
            );
        }

        #[test]
        fn test_send_variable_arg_stays_unresolved() {
            // send(some_var) -> arg0 is a computed identifier. We must NOT
            // guess. No Attr edge for a fabricated method name, and no
            // bareword `some_var` call edge (it is the send argument).
            let source = r#"
class Runner
  def run
    obj.send(some_var)
  end
end
"#;
            let calls = extract_calls(source);
            let run_calls = calls
                .get("Runner.run")
                .or_else(|| calls.get("run"))
                .cloned()
                .unwrap_or_default();
            // No Attr edge targeting a fabricated method name.
            assert!(
                !run_calls
                    .iter()
                    .any(|c| c.target == "obj.some_var" && c.call_type == CallType::Attr),
                "computed send arg must not be guessed into an Attr edge. Got: {:?}",
                run_calls
            );
            // The variable name must not leak as a bareword Direct call.
            assert!(
                !run_calls.iter().any(|c| c.target == "some_var"),
                "send argument identifier must not become a call. Got: {:?}",
                run_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #22: Constant Initializers
    // -------------------------------------------------------------------------

    mod constant_initializer_tests {
        use super::*;

        #[test]
        fn test_class_constant_with_call() {
            let source = r#"
class Config
  TIMEOUT = compute_timeout()
  MAX_RETRIES = calculate_retries(3)
end
"#;
            let calls = extract_calls(source);
            let config_calls = calls
                .get("Config")
                .expect("Config should have constant init calls");
            assert!(
                config_calls.iter().any(|c| c.target == "compute_timeout"),
                "compute_timeout() in constant init should be extracted. Got: {:?}",
                config_calls
            );
            assert!(
                config_calls.iter().any(|c| c.target == "calculate_retries"),
                "calculate_retries() in constant init should be extracted. Got: {:?}",
                config_calls
            );
        }

        #[test]
        fn test_module_level_constant_with_call() {
            let source = r#"
GLOBAL_TIMEOUT = compute_timeout()
DEFAULT_CONFIG = build_config()
"#;
            let calls = extract_calls(source);
            let module_calls = calls
                .get("<module>")
                .expect("<module> should have constant init calls");
            assert!(
                module_calls.iter().any(|c| c.target == "compute_timeout"),
                "Module-level constant init call should be in <module>. Got: {:?}",
                module_calls
            );
            assert!(
                module_calls.iter().any(|c| c.target == "build_config"),
                "Module-level constant init call should be in <module>. Got: {:?}",
                module_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #6/#7: Default Parameters
    // -------------------------------------------------------------------------

    mod default_param_tests {
        use super::*;

        #[test]
        fn test_constructor_default_param_call() {
            let source = r#"
class Processor
  def initialize(config = default_config())
    @config = config
  end
end
"#;
            let calls = extract_calls(source);
            // Default param calls should be attributed to the method
            let init_calls = calls
                .get("Processor.initialize")
                .or_else(|| calls.get("initialize"));
            assert!(
                init_calls.is_some(),
                "initialize should have calls. All keys: {:?}",
                calls.keys().collect::<Vec<_>>()
            );
            let init_calls = init_calls.unwrap();
            assert!(
                init_calls.iter().any(|c| c.target == "default_config"),
                "default_config() in default param should be extracted. Got: {:?}",
                init_calls
            );
        }

        #[test]
        fn test_method_default_param_call() {
            let source = r#"
def process(data, format = detect_format(data))
  transform(data)
end
"#;
            let calls = extract_calls(source);
            let proc_calls = calls.get("process").expect("process should have calls");
            assert!(
                proc_calls.iter().any(|c| c.target == "detect_format"),
                "detect_format() in default param should be extracted. Got: {:?}",
                proc_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #16: Block Bodies
    // -------------------------------------------------------------------------

    mod block_body_tests {
        use super::*;

        #[test]
        fn test_block_body_calls_extracted() {
            let source = r#"
def process
  items.each do |item|
    transform(item)
    validate(item)
  end
end
"#;
            let calls = extract_calls(source);
            let proc_calls = calls.get("process").expect("process should have calls");
            assert!(
                proc_calls.iter().any(|c| c.target == "transform"),
                "transform() inside block should be extracted. Got: {:?}",
                proc_calls
            );
            assert!(
                proc_calls.iter().any(|c| c.target == "validate"),
                "validate() inside block should be extracted. Got: {:?}",
                proc_calls
            );
        }

        #[test]
        fn test_curly_block_body_calls() {
            let source = r#"
def process
  items.map { |item| transform(item) }
end
"#;
            let calls = extract_calls(source);
            let proc_calls = calls.get("process").expect("process should have calls");
            assert!(
                proc_calls.iter().any(|c| c.target == "transform"),
                "transform() inside curly block should be extracted. Got: {:?}",
                proc_calls
            );
        }

        #[test]
        fn test_method_reference_block_arg() {
            let source = r#"
def process
  items.map(&method(:transform))
end
"#;
            let calls = extract_calls(source);
            let proc_calls = calls.get("process").expect("process should have calls");
            assert!(
                proc_calls.iter().any(|c| c.target.contains("method")),
                "method(:transform) call should be extracted. Got: {:?}",
                proc_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #15: Lambda/Closure Bodies
    // -------------------------------------------------------------------------

    mod lambda_closure_tests {
        use super::*;

        #[test]
        fn test_lambda_body_calls() {
            let source = r#"
def setup
  handler = -> (x) { process_event(x) }
  callback = lambda { compute_result() }
end
"#;
            let calls = extract_calls(source);
            let setup_calls = calls.get("setup").expect("setup should have calls");
            assert!(
                setup_calls.iter().any(|c| c.target == "process_event"),
                "process_event() in lambda body should be extracted. Got: {:?}",
                setup_calls
            );
            assert!(
                setup_calls.iter().any(|c| c.target == "compute_result"),
                "compute_result() in lambda block body should be extracted. Got: {:?}",
                setup_calls
            );
        }

        #[test]
        fn test_proc_body_calls() {
            let source = r#"
def setup
  handler = proc { handle_request() }
  handler = Proc.new { create_response() }
end
"#;
            let calls = extract_calls(source);
            let setup_calls = calls.get("setup").expect("setup should have calls");
            assert!(
                setup_calls.iter().any(|c| c.target == "handle_request"),
                "handle_request() in proc body should be extracted. Got: {:?}",
                setup_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #24: String Interpolation Calls
    // -------------------------------------------------------------------------

    mod string_interpolation_tests {
        use super::*;

        #[test]
        fn test_string_interpolation_call() {
            let source = r##"
def greet
  name = compute_name()
  "Hello #{format_name(name)}, welcome!"
end
"##;
            let calls = extract_calls(source);
            let greet_calls = calls.get("greet").expect("greet should have calls");
            assert!(
                greet_calls.iter().any(|c| c.target == "compute_name"),
                "compute_name() should be extracted. Got: {:?}",
                greet_calls
            );
            assert!(
                greet_calls.iter().any(|c| c.target == "format_name"),
                "format_name() in string interpolation should be extracted. Got: {:?}",
                greet_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #25: Array/Collection Literal Calls
    // -------------------------------------------------------------------------

    mod collection_literal_tests {
        use super::*;

        #[test]
        fn test_array_literal_calls() {
            let source = r#"
def build_list
  [create_first(), create_second(), compute_third()]
end
"#;
            let calls = extract_calls(source);
            let list_calls = calls
                .get("build_list")
                .expect("build_list should have calls");
            assert!(
                list_calls.iter().any(|c| c.target == "create_first"),
                "create_first() in array literal should be extracted. Got: {:?}",
                list_calls
            );
            assert!(
                list_calls.iter().any(|c| c.target == "create_second"),
                "create_second() in array literal should be extracted. Got: {:?}",
                list_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #31: Hash Literal Value Calls
    // -------------------------------------------------------------------------

    mod hash_literal_tests {
        use super::*;

        #[test]
        fn test_hash_literal_value_calls() {
            let source = r#"
def build_config
  { timeout: compute_timeout(), retries: compute_retries() }
end
"#;
            let calls = extract_calls(source);
            let config_calls = calls
                .get("build_config")
                .expect("build_config should have calls");
            assert!(
                config_calls.iter().any(|c| c.target == "compute_timeout"),
                "compute_timeout() in hash value should be extracted. Got: {:?}",
                config_calls
            );
            assert!(
                config_calls.iter().any(|c| c.target == "compute_retries"),
                "compute_retries() in hash value should be extracted. Got: {:?}",
                config_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #11: Super Constructor Args
    // -------------------------------------------------------------------------

    mod super_call_tests {
        use super::*;

        #[test]
        fn test_super_with_call_args() {
            let source = r#"
class Child < Parent
  def initialize(x)
    super(validate(x))
  end
end
"#;
            let calls = extract_calls(source);
            let init_calls = calls
                .get("Child.initialize")
                .or_else(|| calls.get("initialize"))
                .expect("initialize should have calls");
            assert!(
                init_calls.iter().any(|c| c.target == "validate"),
                "validate() in super() args should be extracted. Got: {:?}",
                init_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #19: Return/Yield/Raise Calls
    // -------------------------------------------------------------------------

    mod return_yield_raise_tests {
        use super::*;

        #[test]
        fn test_return_with_call() {
            let source = r#"
def compute
  return calculate_result()
end
"#;
            let calls = extract_calls(source);
            let compute_calls = calls.get("compute").expect("compute should have calls");
            assert!(
                compute_calls.iter().any(|c| c.target == "calculate_result"),
                "calculate_result() in return should be extracted. Got: {:?}",
                compute_calls
            );
        }

        #[test]
        fn test_raise_with_call() {
            let source = r#"
def validate
  raise create_error("invalid")
end
"#;
            let calls = extract_calls(source);
            let validate_calls = calls.get("validate").expect("validate should have calls");
            assert!(
                validate_calls.iter().any(|c| c.target == "create_error"),
                "create_error() in raise should be extracted. Got: {:?}",
                validate_calls
            );
        }

        #[test]
        fn test_yield_with_call() {
            let source = r#"
def each_transformed
  items.each do |item|
    yield transform(item)
  end
end
"#;
            let calls = extract_calls(source);
            let each_calls = calls
                .get("each_transformed")
                .expect("each_transformed should have calls");
            assert!(
                each_calls.iter().any(|c| c.target == "transform"),
                "transform() in yield should be extracted. Got: {:?}",
                each_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #17: Conditional/Ternary Calls
    // -------------------------------------------------------------------------

    mod conditional_tests {
        use super::*;

        #[test]
        fn test_ternary_calls() {
            let source = r#"
def decide
  valid? ? accept() : reject()
end
"#;
            let calls = extract_calls(source);
            let decide_calls = calls.get("decide").expect("decide should have calls");
            assert!(
                decide_calls.iter().any(|c| c.target == "accept"),
                "accept() in ternary should be extracted. Got: {:?}",
                decide_calls
            );
            assert!(
                decide_calls.iter().any(|c| c.target == "reject"),
                "reject() in ternary should be extracted. Got: {:?}",
                decide_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #26: Module Method Bodies
    // -------------------------------------------------------------------------

    mod module_method_tests {
        use super::*;

        #[test]
        fn test_module_method_calls() {
            let source = r#"
module Helpers
  def helper_method
    compute()
    transform(data)
  end
end
"#;
            let calls = extract_calls(source);
            let helper_calls = calls
                .get("Helpers.helper_method")
                .or_else(|| calls.get("helper_method"))
                .expect("helper_method should have calls");
            assert!(
                helper_calls.iter().any(|c| c.target == "compute"),
                "compute() in module method should be extracted. Got: {:?}",
                helper_calls
            );
            assert!(
                helper_calls.iter().any(|c| c.target == "transform"),
                "transform() in module method should be extracted. Got: {:?}",
                helper_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Pattern #14: Anonymous Class Bodies
    // -------------------------------------------------------------------------

    mod anonymous_class_tests {
        use super::*;

        #[test]
        fn test_anonymous_class_new_block() {
            let source = r#"
def create_handler
  Class.new do
    def process
      handle_request()
    end
  end
end
"#;
            let calls = extract_calls(source);
            // The Class.new call itself should be extracted
            let handler_calls = calls
                .get("create_handler")
                .expect("create_handler should have calls");
            assert!(
                handler_calls.iter().any(|c| c.target.contains("new")),
                "Class.new should be extracted. Got: {:?}",
                handler_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Comprehensive Integration Test
    // -------------------------------------------------------------------------

    mod integration_tests {
        use super::*;

        #[test]
        fn test_rails_model_comprehensive() {
            let source = r##"
class User < ApplicationRecord
  has_many :posts
  has_many :comments
  belongs_to :organization
  validates :name, presence: true
  validates :email, uniqueness: true
  before_save :normalize_email
  after_create :send_welcome_email
  scope :active, -> { where(active: true) }

  ROLE_ADMIN = freeze_role("admin")

  def initialize(attrs = default_attrs())
    super
    @created_at = Time.now
  end

  def full_name
    "#{first_name()} #{last_name()}"
  end

  def process_orders
    orders.each { |o| validate_order(o) }
    return compute_total()
  end
end
"##;
            let calls = extract_calls(source);

            // DSL class-body calls
            let user_calls = calls.get("User").expect("User should have DSL calls");
            assert!(
                user_calls.iter().any(|c| c.target == "has_many"),
                "has_many missing"
            );
            assert!(
                user_calls.iter().any(|c| c.target == "belongs_to"),
                "belongs_to missing"
            );
            assert!(
                user_calls.iter().any(|c| c.target == "validates"),
                "validates missing"
            );
            assert!(
                user_calls.iter().any(|c| c.target == "before_save"),
                "before_save missing"
            );
            assert!(
                user_calls.iter().any(|c| c.target == "after_create"),
                "after_create missing"
            );
            assert!(
                user_calls.iter().any(|c| c.target == "scope"),
                "scope missing"
            );

            // Constant init
            assert!(
                user_calls.iter().any(|c| c.target == "freeze_role"),
                "freeze_role() in constant init should be in User. Got: {:?}",
                user_calls
            );

            // Method calls
            let full_name_calls = calls
                .get("User.full_name")
                .or_else(|| calls.get("full_name"));
            assert!(
                full_name_calls.is_some(),
                "full_name method should have calls"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Cross-Scope Intra-File Call Tests (Method to Top-Level)
    // -------------------------------------------------------------------------

    mod cross_scope_tests {
        use super::*;

        #[test]
        fn test_extract_calls_method_to_toplevel() {
            let source = r#"
def helper_func
  "helper"
end

class MyClass
  def method
    helper_func()
  end
end
"#;
            let calls = extract_calls(source);

            // The method should have a call to helper_func marked as Intra
            // The caller name is qualified as "MyClass.method"
            let method_calls = calls
                .get("MyClass.method")
                .expect("MyClass.method should have calls");
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
        }
    }

    // -------------------------------------------------------------------------
    // Handler Trait Tests
    // -------------------------------------------------------------------------

    mod trait_tests {
        use super::*;

        #[test]
        fn test_handler_name() {
            let handler = RubyHandler::new();
            assert_eq!(handler.name(), "ruby");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = RubyHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".rb"));
            assert!(exts.contains(&".rake"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = RubyHandler::new();
            assert!(handler.supports("ruby"));
            assert!(handler.supports("Ruby"));
            assert!(handler.supports("RUBY"));
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = RubyHandler::new();
            assert!(handler.supports_extension(".rb"));
            assert!(handler.supports_extension(".rake"));
            assert!(handler.supports_extension(".RB"));
            assert!(!handler.supports_extension(".py"));
        }
    }
}
