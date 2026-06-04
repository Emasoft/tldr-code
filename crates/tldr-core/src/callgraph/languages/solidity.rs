//! Solidity language handler for call graph analysis.
//!
//! v0.5.0 SOL-005a: per-language callgraph adapter built on
//! tree-sitter-solidity 1.2.13. Mirrors the Kotlin adapter (modifiers ⇆
//! visibility-modifier ⇆ modifier-invocation map 1:1) and flattens
//! Solidity's `is A, B` inheritance list the same way Java's
//! `extract_java_class_bases` does.
//!
//! # Call extraction rules
//!
//! - `foo()` and `this.foo()` inside a contract  → same-contract call
//!   (`CallType::Intra` when target is a method of the enclosing contract
//!   or an inherited contract, `CallType::Direct` otherwise).
//! - `super.foo()`                              → parent-contract dispatch
//!   (`CallType::Method`, receiver = "super"). builder_v2 resolves this
//!   against the inheritance chain.
//! - `ContractName.foo()`                       → cross-contract static
//!   call (`CallType::Attr`, receiver = "ContractName").
//! - `address(0x...).call(...)` / `.send` / `.delegatecall` / `.staticcall`
//!   on any other receiver                      → low-level external
//!   (`CallType::Attr`, receiver kept as-is; no resolution attempted).
//! - Modifier invocations on a function decl    → `CallType::Direct` edges
//!   from the function to each modifier name. Resolved against the
//!   contract's modifier table at link time.
//! - `emit EventName(...)`                      → `CallType::Direct` edge
//!   with target = `<emit:EventName>`. The `<emit:>` prefix lets
//!   downstream tooling distinguish event emissions from real calls
//!   without losing the edge.
//!
//! # Import patterns supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `import "./Foo.sol";`                         | `simple_import("./Foo.sol")` |
//! | `import "./Foo.sol" as Bar;`                  | `import_as("./Foo.sol","Bar")` |
//! | `import * as Bar from "./Foo.sol";`           | `is_namespace=true, alias="Bar"` |
//! | `import {X, Y} from "./Foo.sol";`             | `from_import("./Foo.sol", [X,Y])` |
//! | `import {X as A, Y} from "./Foo.sol";`        | `from_import` + `aliases:{A:X}` |
//! | `import "@openzeppelin/contracts/...";`       | npm-style — passed through as-is |
//!
//! No module-system stdlib — `is_solidity_stdlib` is always `false`.
//! Builtins (`msg.sender`, `block.timestamp`, `keccak256`, etc.) are
//! intrinsic, not imports.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// Solidity Handler
// =============================================================================

/// Solidity language handler using tree-sitter-solidity 1.2.13.
///
/// Supports:
/// - Import parsing (5 Solidity import forms)
/// - Contract / interface / library declarations (all surfaced as `ClassDef`)
/// - Function / modifier / constructor / fallback / receive definitions
/// - super-call dispatch, modifier-invocation edges, emit-event edges
/// - Low-level external calls (`.call`, `.send`, `.delegatecall`,
///   `.staticcall`) kept as `CallType::Attr` with no resolution attempted.
#[derive(Debug, Default)]
pub struct SolidityHandler;

impl SolidityHandler {
    /// Creates a new SolidityHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse Solidity source into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_solidity::LANGUAGE.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set Solidity language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Parse a single `import_directive` node.
    ///
    /// tree-sitter-solidity uses the following shape:
    /// ```text
    /// import_directive
    ///   source: string
    ///   import_name?: identifier  (named imports {X, Y} OR namespace `* as X`)
    ///   alias?: identifier        (rename for the matching import_name)
    /// ```
    ///
    /// The grammar collapses `import {X as A} from "..."` so we walk the
    /// children in order to pair each `import_name` with the optional
    /// following `alias`. Plain `import "X"` and `import "X" as Y` are
    /// handled via a text-based fallback because the grammar does not
    /// surface the trailing identifier under a field.
    fn parse_import_node(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        if node.kind() != "import_directive" {
            return None;
        }

        // Pull the source string (always a `string` node). Strip the
        // surrounding quotes — tree-sitter keeps them.
        let mut module: Option<String> = None;
        let mut import_names: Vec<String> = Vec::new();
        let mut aliases: Vec<String> = Vec::new();
        // Walk children in source order so we can pair {name, alias}.
        // The grammar surfaces `import_name`/`alias` as named children
        // and uses field names of the same string for cursor-based
        // lookup. We fall back to plain text inspection for the
        // namespace (`* as X`) and module-alias (`"./X" as Y`) forms.
        let raw_text = get_node_text(node, source).trim().to_string();

        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i) {
                match child.kind() {
                    "string" => {
                        // Strip leading/trailing quote (single or double).
                        let s = get_node_text(&child, source);
                        let trimmed = s
                            .trim()
                            .trim_start_matches('"')
                            .trim_end_matches('"')
                            .trim_start_matches('\'')
                            .trim_end_matches('\'');
                        module = Some(trimmed.to_string());
                    }
                    "identifier" => {
                        // The grammar emits all named imports first,
                        // then their aliases. We re-pair them via raw
                        // text after the loop because the field-name
                        // distinction is not preserved through
                        // `named_child`.
                        import_names.push(get_node_text(&child, source).to_string());
                    }
                    _ => {}
                }
            }
        }

        let module = module?;

        // Form A: `import "./Foo.sol";`
        // Form B: `import "./Foo.sol" as Bar;`
        // Form C: `import * as Bar from "./Foo.sol";`
        // Form D: `import {X, Y} from "./Foo.sol";`
        // Form E: `import {X as A, Y} from "./Foo.sol";`

        // Use the raw text to discriminate between the forms because
        // the grammar collapses identifiers under one bucket.
        let has_braces = raw_text.contains('{');
        let has_star = raw_text.contains('*');
        let has_from = raw_text.contains(" from ");

        if has_braces {
            // Form D/E: named imports. Build a per-pair (name, alias)
            // map by re-scanning the brace-delimited segment so we can
            // distinguish `X` vs `X as A`.
            let mut names: Vec<String> = Vec::new();
            let mut alias_map: HashMap<String, String> = HashMap::new();
            if let (Some(lb), Some(rb)) = (raw_text.find('{'), raw_text.find('}')) {
                let inner = &raw_text[lb + 1..rb];
                for part in inner.split(',') {
                    let p = part.trim();
                    if p.is_empty() {
                        continue;
                    }
                    if let Some((orig, alias)) = p.split_once(" as ") {
                        let orig = orig.trim().to_string();
                        let alias = alias.trim().to_string();
                        names.push(orig.clone());
                        alias_map.insert(alias, orig);
                    } else {
                        names.push(p.to_string());
                    }
                }
            }
            let mut imp = ImportDef::from_import(module, names);
            if !alias_map.is_empty() {
                imp.aliases = Some(alias_map);
            }
            return Some(imp);
        }

        if has_star && has_from {
            // Form C: `import * as Bar from "./Foo.sol";`
            // Namespace import — alias is the last identifier we saw.
            let mut imp = ImportDef::simple_import(module);
            imp.is_namespace = true;
            if let Some(alias) = import_names.last().cloned() {
                imp.alias = Some(alias);
            } else if let Some((_, after_as)) = raw_text.split_once(" as ") {
                if let Some((alias, _)) = after_as.trim().split_once(' ') {
                    imp.alias = Some(alias.to_string());
                }
            }
            return Some(imp);
        }

        // Form B: `import "./Foo.sol" as Bar;`  (no braces, no star)
        if let Some((before, after)) = raw_text.split_once(" as ") {
            // Make sure the `as` lies AFTER the source string, not as
            // part of a brace-segment (already handled above).
            if before.contains('"') || before.contains('\'') {
                let alias = after
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .split_whitespace()
                    .next()
                    .map(|s| s.to_string());
                let mut imp = ImportDef::simple_import(module);
                imp.alias = alias;
                aliases.clear();
                return Some(imp);
            }
        }

        // Form A: plain `import "./Foo.sol";`
        Some(ImportDef::simple_import(module))
    }

    /// Collect every callable name (functions, modifiers, contract
    /// names usable as constructors), every contract/interface/library
    /// name, and the inheritance map (contract → bases) at file scope.
    fn collect_definitions(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> (HashSet<String>, HashSet<String>, HashMap<String, Vec<String>>) {
        let mut methods: HashSet<String> = HashSet::new();
        let mut classes: HashSet<String> = HashSet::new();
        let mut inheritance: HashMap<String, Vec<String>> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "contract_declaration" | "interface_declaration" | "library_declaration" => {
                    if let Some(name) = self.get_field_identifier(&node, "name", source) {
                        classes.insert(name.clone());
                        // A bare `ContractName(args)` expression invokes
                        // the constructor — index it as a callable so
                        // `defined_methods.contains(target)` resolves.
                        methods.insert(name.clone());
                        let bases = self.collect_inheritance(&node, source);
                        if !bases.is_empty() {
                            inheritance.insert(name, bases);
                        }
                    }
                }
                "function_definition" | "modifier_definition" => {
                    if let Some(name) = self.get_field_identifier(&node, "name", source) {
                        methods.insert(name);
                    }
                }
                "constructor_definition" => {
                    methods.insert("constructor".to_string());
                }
                "fallback_receive_definition" => {
                    // The grammar uses a single node for both `fallback`
                    // and `receive` — disambiguate via raw text.
                    let txt = get_node_text(&node, source);
                    if txt.starts_with("receive") {
                        methods.insert("receive".to_string());
                    } else {
                        methods.insert("fallback".to_string());
                    }
                }
                _ => {}
            }
        }

        (methods, classes, inheritance)
    }

    /// Flatten the `is A, B` inheritance list on a contract /
    /// interface declaration. Mirrors `extract_java_class_bases`.
    fn collect_inheritance(&self, node: &Node, source: &[u8]) -> Vec<String> {
        let mut bases = Vec::new();
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i) {
                if child.kind() == "inheritance_specifier" {
                    // ancestor field is a `user_defined_type` whose
                    // first named child is the identifier.
                    if let Some(ancestor) = child.child_by_field_name("ancestor") {
                        if let Some(name) = self.first_identifier(&ancestor, source) {
                            bases.push(name);
                        }
                    }
                }
            }
        }
        bases
    }

    /// Get the text of a named field that is itself an identifier.
    fn get_field_identifier(&self, node: &Node, field: &str, source: &[u8]) -> Option<String> {
        let f = node.child_by_field_name(field)?;
        if f.kind() == "identifier" {
            Some(get_node_text(&f, source).to_string())
        } else {
            self.first_identifier(&f, source)
        }
    }

    /// Find the first `identifier` descendant of `node`.
    fn first_identifier(&self, node: &Node, source: &[u8]) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        for i in 0..node.named_child_count() {
            if let Some(c) = node.named_child(i) {
                if let Some(found) = self.first_identifier(&c, source) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Extract the call edges inside a function body.
    ///
    /// `caller` is the qualified caller name (`Contract.method`).
    fn extract_calls_from_body(
        &self,
        body: &Node,
        source: &[u8],
        defined_methods: &HashSet<String>,
        _defined_classes: &HashSet<String>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();
        if caller.is_empty() {
            return calls;
        }

        for n in walk_tree(*body) {
            match n.kind() {
                "call_expression" => {
                    let line = n.start_position().row as u32 + 1;
                    // Resolve the call function via the `function` field.
                    let fn_node = match n.child_by_field_name("function") {
                        Some(f) => f,
                        None => continue,
                    };
                    let inner = unwrap_expression(&fn_node);
                    match self.classify_callee(&inner, source) {
                        Callee::Direct(target) => {
                            // Bare `foo()` — intra if it resolves to a
                            // known callable in this file, otherwise
                            // direct (likely imported or builtin).
                            let call_type = if defined_methods.contains(&target) {
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
                        Callee::This(method) => {
                            // `this.foo()` — same-contract call. Treat
                            // identically to a bare call so the
                            // resolver picks up the enclosing class.
                            let call_type = if defined_methods.contains(&method) {
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
                        Callee::Super(method) => {
                            // `super.foo()` — parent-contract dispatch.
                            // Use `receiver = "super"` so builder_v2
                            // walks the inheritance chain.
                            calls.push(CallSite::new(
                                caller.to_string(),
                                method,
                                CallType::Method,
                                Some(line),
                                None,
                                Some("super".to_string()),
                                None,
                            ));
                        }
                        Callee::Member { receiver, method } => {
                            // `ContractName.foo()` or `addr.call(...)`.
                            // Both look identical in the AST — keep the
                            // receiver verbatim and let cross-file
                            // resolution decide. The low-level builtins
                            // (`call`, `send`, `delegatecall`,
                            // `staticcall`) are intrinsic; the resolver
                            // will simply fail to bind them.
                            calls.push(CallSite::new(
                                caller.to_string(),
                                method,
                                CallType::Attr,
                                Some(line),
                                None,
                                Some(receiver),
                                None,
                            ));
                        }
                        Callee::Unknown => {}
                    }
                }
                "emit_statement" => {
                    // `emit EventName(args)` — the grammar surfaces the
                    // event name under the `name` field as an
                    // `expression` wrapping an identifier.
                    let line = n.start_position().row as u32 + 1;
                    if let Some(name_node) = n.child_by_field_name("name") {
                        let inner = unwrap_expression(&name_node);
                        if let Some(event) = self.first_identifier(&inner, source) {
                            // Prefix `<emit:>` so the edge is
                            // disambiguable from a real function call
                            // (events and functions live in different
                            // namespaces in Solidity).
                            calls.push(CallSite::new(
                                caller.to_string(),
                                format!("<emit:{}>", event),
                                CallType::Direct,
                                Some(line),
                                None,
                                None,
                                None,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        calls
    }

    /// Classify a call function expression after `unwrap_expression`.
    fn classify_callee(&self, node: &Node, source: &[u8]) -> Callee {
        match node.kind() {
            "identifier" => Callee::Direct(get_node_text(node, source).to_string()),
            "member_expression" => {
                let obj = node.child_by_field_name("object");
                let prop = node.child_by_field_name("property");
                let method = match prop {
                    Some(p) => get_node_text(&p, source).to_string(),
                    None => return Callee::Unknown,
                };
                let receiver_text = match obj {
                    Some(o) => get_node_text(&o, source).to_string(),
                    None => return Callee::Unknown,
                };
                // Cheap discrimination — the grammar gives us the raw
                // text of the object expression. `this` and `super` are
                // single tokens; everything else is a free-form
                // expression.
                if receiver_text == "this" {
                    Callee::This(method)
                } else if receiver_text == "super" {
                    Callee::Super(method)
                } else {
                    Callee::Member {
                        receiver: receiver_text,
                        method,
                    }
                }
            }
            // Calls like `Foo({a: 1})` use call_struct_argument but the
            // callee is still an expression — unwrap and recurse.
            "expression" => {
                let inner = unwrap_expression(node);
                if inner.id() == node.id() {
                    Callee::Unknown
                } else {
                    self.classify_callee(&inner, source)
                }
            }
            _ => Callee::Unknown,
        }
    }

    /// Pull the modifier-invocation identifiers off a function /
    /// constructor / fallback declaration and emit them as direct call
    /// edges from `caller` to each modifier.
    fn extract_modifier_invocations(
        &self,
        decl: &Node,
        source: &[u8],
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();
        if caller.is_empty() {
            return calls;
        }
        for i in 0..decl.named_child_count() {
            if let Some(child) = decl.named_child(i) {
                if child.kind() == "modifier_invocation" {
                    let line = child.start_position().row as u32 + 1;
                    // The first identifier child is the modifier name.
                    if let Some(name) = self.first_identifier(&child, source) {
                        // Skip override/virtual specifiers that might
                        // be misclassified as bare identifiers — they
                        // live under override_specifier nodes, but
                        // guard defensively.
                        if name == "virtual" || name == "override" {
                            continue;
                        }
                        // Modifiers may be defined in the enclosing
                        // contract OR an inherited one. Emit as a
                        // CallType::Method with receiver = "this" so
                        // the cross-file resolver (a) sets
                        // receiver_type to the enclosing class via
                        // `set_self_receiver_types_in_calls` and (b)
                        // walks the inheritance chain through
                        // `resolve_method_in_bases`. A bare
                        // CallType::Direct edge cannot resolve
                        // cross-contract because modifiers aren't
                        // imported by name in Solidity.
                        calls.push(CallSite::new(
                            caller.to_string(),
                            name,
                            CallType::Method,
                            Some(line),
                            None,
                            Some("this".to_string()),
                            None,
                        ));
                    }
                }
            }
        }
        calls
    }
}

/// Internal helper: classify a `call_expression`'s function expression.
enum Callee {
    Direct(String),
    This(String),
    Super(String),
    Member { receiver: String, method: String },
    Unknown,
}

/// The tree-sitter-solidity grammar wraps almost every operand in a
/// generic `expression` node that has exactly one named child. Walk
/// through these wrappers until we hit a structural node.
fn unwrap_expression<'a>(node: &Node<'a>) -> Node<'a> {
    let mut cur = *node;
    while cur.kind() == "expression" && cur.named_child_count() == 1 {
        match cur.named_child(0) {
            Some(c) => cur = c,
            None => break,
        }
    }
    cur
}

impl CallGraphLanguageSupport for SolidityHandler {
    fn name(&self) -> &str {
        "solidity"
    }

    fn extensions(&self) -> &[&str] {
        &[".sol"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            if node.kind() == "import_directive" {
                if let Some(imp) = self.parse_import_node(&node, source_bytes) {
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
        let (defined_methods, defined_classes, _inheritance) =
            self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();

        // Track the enclosing contract / interface / library so that
        // members get the `Contract.method` qualified name.
        let mut current_class: Option<String> = None;

        fn process(
            node: Node,
            source: &[u8],
            defined_methods: &HashSet<String>,
            defined_classes: &HashSet<String>,
            calls_by_func: &mut HashMap<String, Vec<CallSite>>,
            current_class: &mut Option<String>,
            handler: &SolidityHandler,
        ) {
            match node.kind() {
                "contract_declaration"
                | "interface_declaration"
                | "library_declaration" => {
                    let class_name = handler.get_field_identifier(&node, "name", source);
                    let old = current_class.take();
                    *current_class = class_name;
                    for i in 0..node.named_child_count() {
                        if let Some(child) = node.named_child(i) {
                            process(
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
                    *current_class = old;
                }
                "function_definition" | "modifier_definition" => {
                    let name = handler.get_field_identifier(&node, "name", source);
                    let body = node.child_by_field_name("body");
                    if let Some(n) = name {
                        let full_name = if let Some(ref cls) = current_class {
                            format!("{}.{}", cls, n)
                        } else {
                            n.clone()
                        };

                        // Modifier-invocation edges (functions only —
                        // modifiers themselves can't take modifiers).
                        if node.kind() == "function_definition" {
                            let mod_calls = handler.extract_modifier_invocations(
                                &node,
                                source,
                                &full_name,
                            );
                            if !mod_calls.is_empty() {
                                calls_by_func
                                    .entry(full_name.clone())
                                    .or_default()
                                    .extend(mod_calls);
                            }
                        }

                        // Body call edges.
                        if let Some(body_node) = body {
                            let body_calls = handler.extract_calls_from_body(
                                &body_node,
                                source,
                                defined_methods,
                                defined_classes,
                                &full_name,
                            );
                            if !body_calls.is_empty() {
                                calls_by_func
                                    .entry(full_name)
                                    .or_default()
                                    .extend(body_calls);
                            }
                        }
                    }
                }
                "constructor_definition" => {
                    if let Some(ref cls) = current_class {
                        let full_name = format!("{}.constructor", cls);
                        let mod_calls = handler.extract_modifier_invocations(
                            &node,
                            source,
                            &full_name,
                        );
                        if !mod_calls.is_empty() {
                            calls_by_func
                                .entry(full_name.clone())
                                .or_default()
                                .extend(mod_calls);
                        }
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let body_calls = handler.extract_calls_from_body(
                                &body_node,
                                source,
                                defined_methods,
                                defined_classes,
                                &full_name,
                            );
                            if !body_calls.is_empty() {
                                calls_by_func
                                    .entry(full_name)
                                    .or_default()
                                    .extend(body_calls);
                            }
                        }
                    }
                }
                "fallback_receive_definition" => {
                    if let Some(ref cls) = current_class {
                        let txt = get_node_text(&node, source);
                        let kind = if txt.starts_with("receive") {
                            "receive"
                        } else {
                            "fallback"
                        };
                        let full_name = format!("{}.{}", cls, kind);
                        let mod_calls = handler.extract_modifier_invocations(
                            &node,
                            source,
                            &full_name,
                        );
                        if !mod_calls.is_empty() {
                            calls_by_func
                                .entry(full_name.clone())
                                .or_default()
                                .extend(mod_calls);
                        }
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let body_calls = handler.extract_calls_from_body(
                                &body_node,
                                source,
                                defined_methods,
                                defined_classes,
                                &full_name,
                            );
                            if !body_calls.is_empty() {
                                calls_by_func
                                    .entry(full_name)
                                    .or_default()
                                    .extend(body_calls);
                            }
                        }
                    }
                }
                _ => {
                    for i in 0..node.named_child_count() {
                        if let Some(child) = node.named_child(i) {
                            process(
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

        process(
            tree.root_node(),
            source_bytes,
            &defined_methods,
            &defined_classes,
            &mut calls_by_func,
            &mut current_class,
            self,
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

        // Walk top-level once, recursing manually so we can track the
        // enclosing contract for per-method FuncDef emission.
        fn walk(
            node: Node,
            source: &[u8],
            funcs: &mut Vec<FuncDef>,
            classes: &mut Vec<ClassDef>,
            current_class: &mut Option<String>,
            handler: &SolidityHandler,
        ) {
            match node.kind() {
                "contract_declaration"
                | "interface_declaration"
                | "library_declaration" => {
                    let name = handler.get_field_identifier(&node, "name", source);
                    let bases = handler.collect_inheritance(&node, source);
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

                    let mut methods = Vec::new();
                    if let Some(body) = node.child_by_field_name("body") {
                        for i in 0..body.named_child_count() {
                            if let Some(m) = body.named_child(i) {
                                match m.kind() {
                                    "function_definition" | "modifier_definition" => {
                                        if let Some(mn) =
                                            handler.get_field_identifier(&m, "name", source)
                                        {
                                            methods.push(mn);
                                        }
                                    }
                                    "constructor_definition" => {
                                        methods.push("constructor".to_string());
                                    }
                                    "fallback_receive_definition" => {
                                        let t = get_node_text(&m, source);
                                        methods.push(
                                            if t.starts_with("receive") {
                                                "receive"
                                            } else {
                                                "fallback"
                                            }
                                            .to_string(),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if let Some(n) = name.clone() {
                        classes.push(ClassDef::new(n, line, end_line, methods, bases));
                    }

                    // Recurse into the body so member functions get
                    // proper FuncDef entries with class_name set.
                    let old = current_class.take();
                    *current_class = name;
                    if let Some(body) = node.child_by_field_name("body") {
                        for i in 0..body.named_child_count() {
                            if let Some(m) = body.named_child(i) {
                                walk(
                                    m,
                                    source,
                                    funcs,
                                    classes,
                                    current_class,
                                    handler,
                                );
                            }
                        }
                    }
                    *current_class = old;
                }
                "function_definition" | "modifier_definition" => {
                    if let Some(name) = handler.get_field_identifier(&node, "name", source) {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        if let Some(ref cls) = current_class {
                            funcs.push(FuncDef::method(name, cls.clone(), line, end_line));
                        } else {
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                "constructor_definition" => {
                    if let Some(ref cls) = current_class {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        funcs.push(FuncDef::method(
                            "constructor".to_string(),
                            cls.clone(),
                            line,
                            end_line,
                        ));
                    }
                }
                "fallback_receive_definition" => {
                    if let Some(ref cls) = current_class {
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        let t = get_node_text(&node, source);
                        let kind = if t.starts_with("receive") {
                            "receive"
                        } else {
                            "fallback"
                        };
                        funcs.push(FuncDef::method(
                            kind.to_string(),
                            cls.clone(),
                            line,
                            end_line,
                        ));
                    }
                }
                _ => {}
            }
        }

        for i in 0..tree.root_node().named_child_count() {
            if let Some(child) = tree.root_node().named_child(i) {
                let mut current_class: Option<String> = None;
                walk(
                    child,
                    source_bytes,
                    &mut funcs,
                    &mut classes,
                    &mut current_class,
                    self,
                );
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

    fn handler() -> SolidityHandler {
        SolidityHandler::new()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let h = handler();
        let tree = h.parse_source(source).unwrap();
        h.extract_calls(Path::new("Test.sol"), source, &tree)
            .unwrap()
    }

    fn parse_imports(source: &str) -> Vec<ImportDef> {
        handler()
            .parse_imports(source, Path::new("Test.sol"))
            .unwrap()
    }

    // ----- Import tests -----

    #[test]
    fn import_plain() {
        let imps = parse_imports("import \"./Foo.sol\";");
        assert_eq!(imps.len(), 1);
        assert_eq!(imps[0].module, "./Foo.sol");
        assert!(!imps[0].is_from);
        assert!(imps[0].alias.is_none());
    }

    #[test]
    fn import_with_alias() {
        let imps = parse_imports("import \"./Foo.sol\" as Bar;");
        assert_eq!(imps.len(), 1);
        assert_eq!(imps[0].module, "./Foo.sol");
        assert_eq!(imps[0].alias.as_deref(), Some("Bar"));
    }

    #[test]
    fn import_namespace_star_as() {
        let imps = parse_imports("import * as Bar from \"./Foo.sol\";");
        assert_eq!(imps.len(), 1);
        assert_eq!(imps[0].module, "./Foo.sol");
        assert!(imps[0].is_namespace);
        assert_eq!(imps[0].alias.as_deref(), Some("Bar"));
    }

    #[test]
    fn import_named() {
        let imps = parse_imports("import { X, Y } from \"./Foo.sol\";");
        assert_eq!(imps.len(), 1);
        assert!(imps[0].is_from);
        assert_eq!(imps[0].names, vec!["X".to_string(), "Y".to_string()]);
    }

    #[test]
    fn import_named_with_aliases() {
        let imps = parse_imports("import { X as A, Y } from \"./Foo.sol\";");
        assert_eq!(imps.len(), 1);
        assert!(imps[0].is_from);
        assert_eq!(imps[0].names, vec!["X".to_string(), "Y".to_string()]);
        let aliases = imps[0].aliases.as_ref().expect("aliases populated");
        assert_eq!(aliases.get("A").map(String::as_str), Some("X"));
    }

    #[test]
    fn import_npm_style_path_passthrough() {
        let imps = parse_imports("import \"@openzeppelin/contracts/X.sol\";");
        assert_eq!(imps.len(), 1);
        assert_eq!(imps[0].module, "@openzeppelin/contracts/X.sol");
    }

    // ----- Call extraction -----

    const FIXTURE_SUPER_AND_MOD: &str = "\
pragma solidity ^0.8.20;
contract B {
    event Bumped(uint256 v);
    modifier onlyOwner() { _; }
    function bar() public virtual { emit Bumped(1); }
}
contract A is B {
    function foo() external onlyOwner {
        super.bar();
        this.baz();
    }
    function baz() internal { B.bar(); }
}
";

    #[test]
    fn super_call_emits_method_with_super_receiver() {
        let calls = extract_calls(FIXTURE_SUPER_AND_MOD);
        let foo_calls = calls.get("A.foo").expect("A.foo present");
        let super_bar = foo_calls
            .iter()
            .find(|c| c.target == "bar" && c.receiver.as_deref() == Some("super"))
            .expect("expected super.bar edge");
        assert!(matches!(super_bar.call_type, CallType::Method));
    }

    #[test]
    fn this_call_resolves_to_intra() {
        let calls = extract_calls(FIXTURE_SUPER_AND_MOD);
        let foo_calls = calls.get("A.foo").expect("A.foo present");
        let this_baz = foo_calls
            .iter()
            .find(|c| c.target == "baz")
            .expect("expected this.baz → baz edge");
        // baz is defined in the file, so it must be Intra.
        assert!(matches!(this_baz.call_type, CallType::Intra));
        // The grammar collapses `this.baz()` into a member_expression
        // with receiver "this" — we rewrote that to bare-call form,
        // so no receiver remains.
        assert!(this_baz.receiver.is_none());
    }

    #[test]
    fn cross_contract_static_call_keeps_receiver() {
        let calls = extract_calls(FIXTURE_SUPER_AND_MOD);
        let baz_calls = calls.get("A.baz").expect("A.baz present");
        let b_bar = baz_calls
            .iter()
            .find(|c| c.target == "bar" && c.receiver.as_deref() == Some("B"))
            .expect("expected B.bar edge with receiver=B");
        assert!(matches!(b_bar.call_type, CallType::Attr));
    }

    #[test]
    fn modifier_invocation_becomes_call_edge() {
        let calls = extract_calls(FIXTURE_SUPER_AND_MOD);
        let foo_calls = calls.get("A.foo").expect("A.foo present");
        let mod_edge = foo_calls
            .iter()
            .find(|c| c.target == "onlyOwner")
            .expect("expected modifier-invocation edge to onlyOwner");
        // Modifier edges are emitted as Method with receiver = "this"
        // so the cross-file resolver can walk the contract's
        // inheritance chain to find a modifier defined in a parent
        // contract. See `extract_modifier_invocations` for the
        // rationale.
        assert!(matches!(mod_edge.call_type, CallType::Method));
        assert_eq!(mod_edge.receiver.as_deref(), Some("this"));
    }

    #[test]
    fn emit_statement_becomes_emit_prefixed_edge() {
        let calls = extract_calls(FIXTURE_SUPER_AND_MOD);
        let bar_calls = calls.get("B.bar").expect("B.bar present");
        let emit_edge = bar_calls
            .iter()
            .find(|c| c.target == "<emit:Bumped>")
            .expect("expected <emit:Bumped> edge from B.bar");
        assert!(matches!(emit_edge.call_type, CallType::Direct));
    }

    #[test]
    fn low_level_external_call_keeps_receiver() {
        let src = "\
pragma solidity ^0.8.20;
contract Sink {
    function poke(address a) external {
        a.call(\"\");
    }
}
";
        let calls = extract_calls(src);
        let poke_calls = calls.get("Sink.poke").expect("Sink.poke present");
        let call_edge = poke_calls
            .iter()
            .find(|c| c.target == "call")
            .expect("expected low-level .call edge");
        assert!(matches!(call_edge.call_type, CallType::Attr));
        assert_eq!(call_edge.receiver.as_deref(), Some("a"));
    }

    #[test]
    fn handler_metadata() {
        let h = handler();
        assert_eq!(h.name(), "solidity");
        assert!(h.extensions().contains(&".sol"));
        assert!(h.supports("solidity"));
        assert!(h.supports("Solidity"));
        assert!(h.supports_extension(".sol"));
        assert!(h.supports_extension(".SOL"));
    }

    #[test]
    fn definitions_classify_contract_interface_library() {
        let src = "\
pragma solidity ^0.8.20;
interface I { function ping() external; }
library L { function add(uint a) internal pure returns (uint) { return a; } }
contract C is I {
    function ping() external override {}
}
";
        let h = handler();
        let tree = h.parse_source(src).unwrap();
        let (funcs, classes) = h
            .extract_definitions(src, Path::new("X.sol"), &tree)
            .unwrap();
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"I"));
        assert!(names.contains(&"L"));
        assert!(names.contains(&"C"));
        let c = classes.iter().find(|c| c.name == "C").unwrap();
        assert_eq!(c.bases, vec!["I".to_string()]);
        assert!(funcs.iter().any(|f| f.name == "ping" && f.is_method));
        assert!(funcs.iter().any(|f| f.name == "add" && f.is_method));
    }
}
