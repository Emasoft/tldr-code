//! TypeScript/JavaScript language handler for call graph analysis.
//!
//! This module provides TypeScript and JavaScript call graph support using
//! tree-sitter-typescript.
//!
//! # Import Patterns Supported
//!
//! | Pattern | ImportDef |
//! |---------|-----------|
//! | `import x from 'pkg'` | `{module: "pkg", is_default: true}` |
//! | `import { x, y } from 'pkg'` | `{module: "pkg", is_from: true, names: ["x", "y"]}` |
//! | `import { x as z } from 'pkg'` | `{module: "pkg", names: ["x"], aliases: {"z": "x"}}` |
//! | `import * as x from 'pkg'` | `{module: "pkg", is_namespace: true, alias: "x"}` |
//! | `import 'pkg'` | `{module: "pkg"}` (side-effect) |
//! | `require('pkg')` | `{module: "pkg"}` |
//! | `export { x } from 'pkg'` | `{module: "pkg", names: ["x"]}` (re-export) |
//!
//! # Call Extraction
//!
//! - Direct calls: `func()` -> CallType::Direct or CallType::Intra
//! - Method calls: `obj.method()` -> CallType::Attr
//! - Constructor calls: `new Class()` -> CallType::Direct
//! - JSX calls: `<Component />` -> CallType::Direct
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 9.2 for TypeScript-specific details.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::base::{get_node_text, walk_tree};
use super::common::{extend_calls_if_any, insert_calls_if_any};
use super::{CallGraphLanguageSupport, ParseError};
use crate::callgraph::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef};

// =============================================================================
// TypeScript Handler
// =============================================================================

/// TypeScript/JavaScript language handler using tree-sitter-typescript.
///
/// Supports:
/// - Import parsing (ES modules, CommonJS require)
/// - Call extraction (direct, method, constructor, JSX)
/// - Arrow function tracking
/// - Class method extraction
#[derive(Debug, Default)]
pub struct TypeScriptHandler;

/// Accumulator for parsed TypeScript import clause components.
#[derive(Default)]
struct ImportClauseResult {
    default_name: Option<String>,
    named_imports: Vec<String>,
    aliases: HashMap<String, String>,
    is_namespace: bool,
    namespace_alias: Option<String>,
}

impl TypeScriptHandler {
    /// Creates a new TypeScriptHandler.
    pub fn new() -> Self {
        Self
    }

    /// Parse the source code into a tree-sitter Tree.
    fn parse_source(&self, source: &str) -> Result<Tree, ParseError> {
        let mut parser = Parser::new();
        // Use TSX parser which handles both TypeScript and JSX
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .map_err(|e| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: format!("Failed to set TypeScript language: {}", e),
            })?;

        parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed {
                file: std::path::PathBuf::new(),
                message: "Parser returned None".to_string(),
            })
    }

    /// Parse an import statement node.
    fn parse_import_statement(&self, node: &Node, source: &[u8]) -> Vec<ImportDef> {
        let mut imports = Vec::new();

        // Find module path (string literal)
        let mut module = String::new();
        let mut import_clause = ImportClauseResult::default();

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "string" | "string_fragment" => {
                        // Module path - strip quotes
                        let text = get_node_text(&child, source);
                        module = text.trim_matches(|c| c == '"' || c == '\'').to_string();
                    }
                    "import_clause" => {
                        self.parse_import_clause(&child, source, &mut import_clause);
                    }
                    _ => {}
                }
            }
        }

        if module.is_empty() {
            return imports;
        }

        // Create ImportDef based on what we found
        if import_clause.is_namespace {
            // import * as m from 'module'
            let mut imp = ImportDef::simple_import(module);
            imp.is_namespace = true;
            imp.alias = import_clause.namespace_alias;
            imports.push(imp);
        } else if !import_clause.named_imports.is_empty() || import_clause.default_name.is_some() {
            // Named or default imports
            let mut imp = if !import_clause.named_imports.is_empty() {
                ImportDef::from_import(module.clone(), import_clause.named_imports)
            } else {
                ImportDef::simple_import(module.clone())
            };

            if import_clause.default_name.is_some() {
                imp.is_default = true;
                imp.alias = import_clause.default_name;
            }

            if !import_clause.aliases.is_empty() {
                imp.aliases = Some(import_clause.aliases);
            }

            imports.push(imp);
        } else {
            // Side-effect import: import 'module'
            imports.push(ImportDef::simple_import(module));
        }

        imports
    }

    /// Parse the import clause (what's being imported).
    fn parse_import_clause(&self, node: &Node, source: &[u8], result: &mut ImportClauseResult) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        // Default import: import Foo from 'module'
                        result.default_name = Some(get_node_text(&child, source).to_string());
                    }
                    "named_imports" => {
                        // Named imports: import { foo, bar as baz } from 'module'
                        self.parse_named_imports(
                            &child,
                            source,
                            &mut result.named_imports,
                            &mut result.aliases,
                        );
                    }
                    "namespace_import" => {
                        // Namespace import: import * as m from 'module'
                        result.is_namespace = true;
                        for j in 0..child.child_count() {
                            if let Some(ns_child) = child.child(j) {
                                if ns_child.kind() == "identifier" {
                                    result.namespace_alias =
                                        Some(get_node_text(&ns_child, source).to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Parse named imports: { foo, bar as baz }
    fn parse_named_imports(
        &self,
        node: &Node,
        source: &[u8],
        named_imports: &mut Vec<String>,
        aliases: &mut HashMap<String, String>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "import_specifier" {
                    let mut orig_name: Option<String> = None;
                    let mut alias: Option<String> = None;

                    for j in 0..child.child_count() {
                        if let Some(spec_child) = child.child(j) {
                            if spec_child.kind() == "identifier" {
                                if orig_name.is_none() {
                                    orig_name =
                                        Some(get_node_text(&spec_child, source).to_string());
                                } else {
                                    alias = Some(get_node_text(&spec_child, source).to_string());
                                }
                            }
                        }
                    }

                    if let Some(name) = orig_name {
                        named_imports.push(name.clone());
                        if let Some(a) = alias {
                            aliases.insert(a, name);
                        }
                    }
                }
            }
        }
    }

    /// Parse a require call: const x = require('module')
    fn parse_require_call(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        // Look for call_expression with identifier "require"
        if node.kind() != "call_expression" {
            return None;
        }

        let mut is_require = false;
        let mut module_path = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        if get_node_text(&child, source) == "require" {
                            is_require = true;
                        }
                    }
                    "arguments" => {
                        // Find the string argument
                        for j in 0..child.child_count() {
                            if let Some(arg) = child.child(j) {
                                if arg.kind() == "string" {
                                    let text = get_node_text(&arg, source);
                                    module_path = Some(
                                        text.trim_matches(|c| c == '"' || c == '\'').to_string(),
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if is_require {
            if let Some(module) = module_path {
                return Some(ImportDef::simple_import(module));
            }
        }

        None
    }

    /// Parse aliased require/import assignments:
    /// - const foo = require('mod')
    /// - foo = require('mod')
    fn parse_require_alias(&self, node: &Node, source: &[u8]) -> Option<ImportDef> {
        match node.kind() {
            "variable_declarator" => {
                let mut alias: Option<String> = None;
                let mut imp: Option<ImportDef> = None;

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "identifier" => {
                                if alias.is_none() {
                                    alias = Some(get_node_text(&child, source).to_string());
                                }
                            }
                            "call_expression" => {
                                if imp.is_none() {
                                    imp = self.parse_require_call(&child, source);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if let (Some(mut import), Some(name)) = (imp, alias) {
                    import.alias = Some(name);
                    return Some(import);
                }
            }
            "assignment_expression" => {
                let mut alias: Option<String> = None;
                let mut imp: Option<ImportDef> = None;

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "identifier" => {
                                if alias.is_none() {
                                    alias = Some(get_node_text(&child, source).to_string());
                                }
                            }
                            "call_expression" => {
                                if imp.is_none() {
                                    imp = self.parse_require_call(&child, source);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if let (Some(mut import), Some(name)) = (imp, alias) {
                    import.alias = Some(name);
                    return Some(import);
                }
            }
            _ => {}
        }
        None
    }

    /// Test whether an `assignment_expression` is a top-level statement
    /// in the program (i.e. its enclosing structure is
    /// `program > expression_statement > assignment_expression`).
    ///
    /// language-adapters-completeness-v1 (BUG-AGG12-7): the
    /// CommonJS-method pattern is only a *definition* when it lives at
    /// module scope. Assignments nested inside a function body
    /// (`function foo() { obj.method = function inner() {} }`) are local
    /// behavior — surfacing them as additional call-graph definitions
    /// would double-count calls under both the outer function and the
    /// inner assignment.
    fn is_top_level_assignment(node: &Node) -> bool {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "expression_statement" {
            return false;
        }
        match parent.parent().map(|p| p.kind()) {
            Some("program") => true,
            // Module-level wrappers in TS files may add namespace
            // declarations around top-level statements; treat those as
            // module-scope too.
            Some("module") | Some("internal_module") | Some("statement_block") => {
                // statement_block can be the body of a function — only
                // accept it when its parent is `program` (i.e. an IIFE
                // pattern is intentionally still local).
                false
            }
            _ => false,
        }
    }

    /// Extract the function name from an `assignment_expression` whose
    /// right-hand side is a function-like expression. Returns the name
    /// the assigned function should be discoverable under for call-graph
    /// resolution purposes.
    ///
    /// Handles these CommonJS / prototype-style patterns:
    /// - `app.init = function init() { ... }` → `"init"` (named function preferred)
    /// - `app.init = function() { ... }`      → `"init"` (property name fallback)
    /// - `Foo.prototype.bar = function() {}`  → `"bar"`
    /// - `obj.method = (x) => { ... }`        → `"method"`
    /// - `handler = function() { ... }`       → `"handler"` (LHS identifier)
    ///
    /// Returns `None` when the RHS isn't a function-like expression or
    /// no name can be extracted.
    ///
    /// language-adapters-completeness-v1 (BUG-AGG12-7): without this
    /// extractor, the TS/JS handler skipped `obj.prop = function ...`
    /// assignments entirely; Express-style codebases reported zero
    /// resolved callers for every `app.method()` site.
    fn extract_assignment_function_name(node: &Node, source: &[u8]) -> Option<String> {
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;

        // RHS must be a function-like expression.
        if !matches!(
            right.kind(),
            "function_expression" | "function" | "arrow_function" | "generator_function"
        ) {
            return None;
        }

        // Prefer the named function expression's own name (preserves
        // the most specific identifier). E.g. `app.init = function init()`
        // — we use `init` rather than the LHS property which happens to
        // also be `init`. For the more general
        // `Express.application.method = function specific()` pattern,
        // the named-function form is what call sites actually
        // reference recursively.
        if let Some(name_node) = right.child_by_field_name("name") {
            let text = get_node_text(&name_node, source).to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }

        // Fall back to the LHS to recover the property/identifier name.
        match left.kind() {
            "identifier" => Some(get_node_text(&left, source).to_string()),
            "member_expression" => {
                // app.init / Foo.prototype.bar — final property is the
                // method name.
                if let Some(prop) = left.child_by_field_name("property") {
                    return Some(get_node_text(&prop, source).to_string());
                }
                // Field-name lookup failed; pick the last
                // property_identifier child as a defensive fallback.
                let mut last_prop: Option<String> = None;
                for i in 0..left.child_count() {
                    if let Some(child) = left.child(i) {
                        if child.kind() == "property_identifier" {
                            last_prop = Some(get_node_text(&child, source).to_string());
                        }
                    }
                }
                last_prop
            }
            _ => None,
        }
    }

    /// Extract the receiver ROOT of a CommonJS / prototype-style method
    /// assignment's left-hand side. The receiver root is the base object the
    /// method is hung off of, so it can be matched against the `obj` of an
    /// `obj.method()` call site.
    ///
    /// - `app.init = ...`            → root `"app"`
    /// - `Foo.prototype.bar = ...`   → root `"Foo"` (walk the nested
    ///   `member_expression` → object chain down to the base identifier)
    /// - `this.handler = ...`        → root `"this"`
    /// - `handler = ...` (plain id)  → `None` (no receiver object)
    ///
    /// CLUSTER T3-G1 (1A): without a receiver-keyed index, the call-site
    /// classifier only checks whether the bare method name exists, producing
    /// false self/cross edges like `router.use → use`.
    fn extract_assignment_receiver_root(node: &Node, source: &[u8]) -> Option<String> {
        let left = node.child_by_field_name("left")?;
        if left.kind() != "member_expression" {
            // Plain identifier LHS (`handler = ...`) has no receiver object.
            return None;
        }
        // Walk the `object` field chain inward until we reach the base of the
        // member access. For `Foo.prototype.bar`, the outer object is
        // `Foo.prototype` (another member_expression) whose object is `Foo`.
        let mut current = left.child_by_field_name("object")?;
        loop {
            match current.kind() {
                "member_expression" => {
                    current = current.child_by_field_name("object")?;
                }
                "identifier" | "this" => {
                    return Some(get_node_text(&current, source).to_string());
                }
                _ => return None,
            }
        }
    }

    /// CLUSTER T3-G3 (3A): return true iff `node` is a descendant of an
    /// `arguments` node — i.e. it sits inside a call's argument list, e.g.
    /// `defineGetter(req, 'query', function query(){...})`. Decision is purely
    /// structural (`node.kind()` of ancestors); no source text is inspected.
    fn node_is_in_call_arguments(node: &Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "arguments" {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    /// Collect all function, class, and arrow function definitions, plus a
    /// receiver-keyed index mapping each CommonJS / prototype method name to
    /// the set of receiver roots it was defined on.
    ///
    /// CLUSTER T3-G1 (1A): the receiver map lets the call-site classifier
    /// distinguish `app.init()` (collapses to Intra — `app` is the receiver
    /// root of `app.init = ...`) from `router.use()` (stays Attr — `router`
    /// is NOT a receiver root of `use`).
    fn collect_definitions(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> (
        HashSet<String>,
        HashSet<String>,
        HashMap<String, HashSet<String>>,
    ) {
        let mut functions = HashSet::new();
        let mut classes = HashSet::new();
        let mut method_receivers: HashMap<String, HashSet<String>> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        functions.insert(get_node_text(&name_node, source).to_string());
                    }
                }
                "class_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source).to_string();
                        classes.insert(name.clone());
                        functions.insert(name); // Classes can be "called" as constructors
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    // Check for arrow functions: const foo = () => {}
                    for i in 0..node.named_child_count() {
                        if let Some(decl) = node.named_child(i) {
                            if decl.kind() == "variable_declarator" {
                                let mut var_name: Option<String> = None;
                                let mut is_arrow = false;

                                for j in 0..decl.child_count() {
                                    if let Some(child) = decl.child(j) {
                                        match child.kind() {
                                            "identifier" => {
                                                var_name =
                                                    Some(get_node_text(&child, source).to_string());
                                            }
                                            "arrow_function" => {
                                                is_arrow = true;
                                            }
                                            _ => {}
                                        }
                                    }
                                }

                                if is_arrow {
                                    if let Some(name) = var_name {
                                        functions.insert(name);
                                    }
                                }
                            }
                        }
                    }
                }
                "method_definition" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        functions.insert(get_node_text(&name_node, source).to_string());
                    }
                }
                "function_expression" | "arrow_function" | "generator_function" => {
                    // CLUSTER T3-G3 (3A): a NAMED function expression passed as
                    // a call ARGUMENT — the Express `defineGetter(req,'query',
                    // function query(){...})` getter pattern — is collected as
                    // a def keyed by its OWN name. The named/anonymous split is
                    // self-enforcing: anonymous callbacks have no `name` field
                    // and are excluded by construction. Lands AFTER T3-G1 (1A)
                    // so these names are contained by receiver-keying and do
                    // NOT widen the flat collapse (they register no receiver
                    // root, so `obj.method()` collapse is unaffected).
                    if Self::node_is_in_call_arguments(&node) {
                        if let Some(name_node) = node.child_by_field_name("name") {
                            let name = get_node_text(&name_node, source).to_string();
                            if !name.is_empty() {
                                functions.insert(name);
                            }
                        }
                    }
                }
                "assignment_expression" => {
                    // language-adapters-completeness-v1 (BUG-AGG12-7):
                    // CommonJS method-on-object pattern is ubiquitous in
                    // Express-style JS code:
                    //   app.init = function init() { ... }
                    //   Foo.prototype.bar = function() { ... }
                    //   handler = () => { ... }
                    // Without this branch, the assigned function name
                    // never reaches `defined_funcs`, so call sites like
                    // `app.init()` route to `resolve_method_or_attr_call`
                    // and silently fail to resolve in-project.
                    if Self::is_top_level_assignment(&node) {
                        if let Some(name) =
                            Self::extract_assignment_function_name(&node, source)
                        {
                            // CLUSTER T3-G1 (1A): record the receiver root the
                            // method was hung off of, so `obj.method()` sites
                            // only collapse to Intra when `obj` matches a
                            // receiver root of `method`.
                            if let Some(root) =
                                Self::extract_assignment_receiver_root(&node, source)
                            {
                                method_receivers
                                    .entry(name.clone())
                                    .or_default()
                                    .insert(root);
                            }
                            functions.insert(name);
                        }
                    }
                }
                "export_statement" => {
                    // Handle exported declarations
                    for i in 0..node.named_child_count() {
                        if let Some(child) = node.named_child(i) {
                            match child.kind() {
                                "function_declaration" => {
                                    if let Some(name_node) = child.child_by_field_name("name") {
                                        functions
                                            .insert(get_node_text(&name_node, source).to_string());
                                    }
                                }
                                "class_declaration" => {
                                    if let Some(name_node) = child.child_by_field_name("name") {
                                        let name = get_node_text(&name_node, source).to_string();
                                        classes.insert(name.clone());
                                        functions.insert(name);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        (functions, classes, method_receivers)
    }

    /// Build a one-hop alias map for a function body: `const r = app` /
    /// `let r = app` / `const self = this` produce `r → app` / `self → this`.
    ///
    /// CLUSTER T3-G1 (1C): same-scope simple-identifier aliases only. The
    /// initializer must be a single `identifier` or `this` node — anything
    /// more complex (member access, call, etc.) is ignored, so this is a
    /// deliberately shallow alias hop, not a dataflow analysis. No shadowing
    /// machinery: the last simple binding for a name wins.
    fn collect_body_aliases(&self, body: &Node, source: &[u8]) -> HashMap<String, String> {
        let mut aliases: HashMap<String, String> = HashMap::new();
        for child in walk_tree(*body) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            if name_node.kind() != "identifier" {
                continue;
            }
            let Some(value_node) = child.child_by_field_name("value") else {
                continue;
            };
            // Only single-identifier / `this` initializers qualify as aliases.
            match value_node.kind() {
                "identifier" | "this" => {
                    let alias = get_node_text(&name_node, source).to_string();
                    let target = get_node_text(&value_node, source).to_string();
                    aliases.insert(alias, target);
                }
                _ => {}
            }
        }
        aliases
    }

    /// Extract calls from a function body.
    fn extract_calls_from_node(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        // CLUSTER T3-G1 (1C): resolve same-scope simple aliases (one hop)
        // before the receiver-root check so `const r = app; r.use()` is
        // classified using `app` as the receiver.
        let aliases = self.collect_body_aliases(node, source);

        for child in walk_tree(*node) {
            match child.kind() {
                "call_expression" => {
                    let line = child.start_position().row as u32 + 1;

                    // Get the function being called
                    if let Some(func_node) = child.child(0) {
                        match func_node.kind() {
                            "identifier" => {
                                // Direct call: func()
                                let target = get_node_text(&func_node, source).to_string();

                                // Skip require calls - those are imports, not function calls
                                if target == "require" {
                                    continue;
                                }

                                let call_type = if defined_funcs.contains(&target)
                                    || defined_classes.contains(&target)
                                {
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
                            "member_expression" => {
                                // Method call: obj.method() — classified via
                                // the `object`/`property` fields so nested
                                // receivers (`this.router.param`) are handled
                                // structurally rather than by flattening raw
                                // children.
                                let method_name = func_node
                                    .child_by_field_name("property")
                                    .filter(|p| p.kind() == "property_identifier")
                                    .map(|p| get_node_text(&p, source).to_string());
                                let object_node = func_node.child_by_field_name("object");

                                if let (Some(method), Some(obj_node)) =
                                    (method_name, object_node)
                                {
                                    // A bare receiver is a single identifier or
                                    // `this`; anything else (nested member,
                                    // call, etc.) is a complex receiver that
                                    // must NOT collapse to a bare self-edge.
                                    let bare_receiver = match obj_node.kind() {
                                        "identifier" | "this" => {
                                            Some(get_node_text(&obj_node, source).to_string())
                                        }
                                        _ => None,
                                    };

                                    match bare_receiver {
                                        Some(obj) if obj == "this" => {
                                            // CLUSTER T3-G1: this.method() with
                                            // a plain local method name resolves
                                            // Intra; otherwise Attr.
                                            let call_type = if defined_funcs.contains(&method) {
                                                CallType::Intra
                                            } else {
                                                CallType::Attr
                                            };
                                            let target = if call_type == CallType::Intra {
                                                method.clone()
                                            } else {
                                                format!("this.{}", method)
                                            };
                                            calls.push(CallSite::new(
                                                caller.to_string(),
                                                target,
                                                call_type,
                                                Some(line),
                                                None,
                                                Some("this".to_string()),
                                                None,
                                            ));
                                        }
                                        Some(obj) => {
                                            // CLUSTER T3-G1 (1A + 1C): resolve
                                            // `obj` through one alias hop, then
                                            // collapse `obj.method()` to Intra
                                            // ONLY when the resolved receiver is
                                            // a known receiver root of `method`.
                                            // Preserves BUG-AGG12-7 (app.init
                                            // resolves because `app` is the
                                            // receiver root of `app.init = ...`)
                                            // while rejecting false self/cross
                                            // edges (router.use → use).
                                            let resolved =
                                                aliases.get(&obj).cloned().unwrap_or_else(|| obj.clone());
                                            let is_receiver_match = method_receivers
                                                .get(&method)
                                                .is_some_and(|roots| roots.contains(&resolved));

                                            if is_receiver_match {
                                                calls.push(CallSite::new(
                                                    caller.to_string(),
                                                    method.clone(),
                                                    CallType::Intra,
                                                    Some(line),
                                                    None,
                                                    Some(obj),
                                                    None,
                                                ));
                                            } else {
                                                let target = format!("{}.{}", obj, method);
                                                calls.push(CallSite::new(
                                                    caller.to_string(),
                                                    target,
                                                    CallType::Attr,
                                                    Some(line),
                                                    None,
                                                    Some(obj),
                                                    None,
                                                ));
                                            }
                                        }
                                        None => {
                                            // Complex/nested receiver
                                            // (`this.router.param`,
                                            // `a.b.c.method`): emit an Attr edge
                                            // keyed on the full receiver text.
                                            // Never collapse to a bare self-edge.
                                            let receiver_text =
                                                get_node_text(&obj_node, source).to_string();
                                            let target =
                                                format!("{}.{}", receiver_text, method);
                                            calls.push(CallSite::new(
                                                caller.to_string(),
                                                target,
                                                CallType::Attr,
                                                Some(line),
                                                None,
                                                Some(receiver_text),
                                                None,
                                            ));
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "new_expression" => {
                    // Constructor call: new Class()
                    let line = child.start_position().row as u32 + 1;

                    for i in 0..child.child_count() {
                        if let Some(name_node) = child.child(i) {
                            if name_node.kind() == "identifier" {
                                let target = get_node_text(&name_node, source).to_string();
                                let call_type = if defined_classes.contains(&target) {
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
                                break;
                            }
                        }
                    }
                }
                "jsx_self_closing_element" | "jsx_opening_element" => {
                    // JSX component: <Component /> or <Component>
                    let line = child.start_position().row as u32 + 1;

                    if let Some(name_node) = child.child_by_field_name("name") {
                        let (target, is_component) = match name_node.kind() {
                            "identifier" => {
                                let t = get_node_text(&name_node, source).to_string();
                                let is_cap =
                                    t.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                                (t, is_cap)
                            }
                            "member_expression" => {
                                // <UI.Modal /> — extract property as call target
                                let prop = name_node
                                    .child_by_field_name("property")
                                    .map(|p| get_node_text(&p, source).to_string());
                                let obj = name_node
                                    .child_by_field_name("object")
                                    .map(|o| get_node_text(&o, source).to_string());
                                match (obj, prop) {
                                    (Some(o), Some(p)) => {
                                        let is_cap = o
                                            .chars()
                                            .next()
                                            .map(|c| c.is_uppercase())
                                            .unwrap_or(false)
                                            || p.chars()
                                                .next()
                                                .map(|c| c.is_uppercase())
                                                .unwrap_or(false);
                                        (p, is_cap)
                                    }
                                    _ => (String::new(), false),
                                }
                            }
                            "jsx_namespace_name" => {
                                // <Foo:Bar /> — rare XML namespace form
                                let mut last_ident = None;
                                for k in 0..name_node.child_count() {
                                    if let Some(seg) = name_node.child(k) {
                                        if seg.kind() == "identifier" {
                                            last_ident =
                                                Some(get_node_text(&seg, source).to_string());
                                        }
                                    }
                                }
                                match last_ident {
                                    Some(t) => {
                                        let is_cap = t
                                            .chars()
                                            .next()
                                            .map(|c| c.is_uppercase())
                                            .unwrap_or(false);
                                        (t, is_cap)
                                    }
                                    None => (String::new(), false),
                                }
                            }
                            _ => (String::new(), false),
                        };

                        if is_component && !target.is_empty() {
                            let call_type = if defined_classes.contains(&target)
                                || defined_funcs.contains(&target)
                            {
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
                    }
                }
                _ => {}
            }
        }

        calls
    }

    /// Extract calls from formal_parameters (default values).
    /// Tree-sitter: formal_parameters -> required_parameter/optional_parameter -> call_expression
    fn extract_calls_from_params(
        &self,
        params_node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();
        for i in 0..params_node.named_child_count() {
            if let Some(param) = params_node.named_child(i) {
                let kind = param.kind();
                if kind == "required_parameter" || kind == "optional_parameter" {
                    // Walk the parameter node for call_expression children (default values)
                    // Skip the first identifier child (the parameter name itself)
                    let param_calls = self.extract_calls_from_node(
                        &param,
                        source,
                        defined_funcs,
                        defined_classes,
                        method_receivers,
                        caller,
                    );
                    calls.extend(param_calls);
                }
            }
        }
        calls
    }

    /// Extract calls from decorator nodes.
    /// Tree-sitter: decorator -> call_expression
    fn extract_calls_from_decorators(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
        caller: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "decorator" {
                    let decorator_calls = self.extract_calls_from_node(
                        &child,
                        source,
                        defined_funcs,
                        defined_classes,
                        method_receivers,
                        caller,
                    );
                    calls.extend(decorator_calls);
                }
            }
        }
        calls
    }

    /// Extract calls from class body for field initializers, static blocks, and decorators.
    /// Returns calls attributed to the class name.
    fn extract_class_body_calls(
        &self,
        class_body: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
        class_name: &str,
    ) -> Vec<CallSite> {
        let mut calls = Vec::new();

        for i in 0..class_body.named_child_count() {
            if let Some(member) = class_body.named_child(i) {
                match member.kind() {
                    // Pattern #3: Class field initializers
                    "public_field_definition" | "field_definition" | "property_declaration" => {
                        let field_calls = self.extract_calls_from_node(
                            &member,
                            source,
                            defined_funcs,
                            defined_classes,
                            method_receivers,
                            class_name,
                        );
                        calls.extend(field_calls);
                    }
                    // Pattern #4: Static initializer blocks
                    "class_static_block" => {
                        let static_calls = self.extract_calls_from_node(
                            &member,
                            source,
                            defined_funcs,
                            defined_classes,
                            method_receivers,
                            class_name,
                        );
                        calls.extend(static_calls);
                    }
                    _ => {}
                }
            }
        }

        calls
    }

    fn extract_calls_for_function_declaration(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Option<(String, Vec<CallSite>)> {
        let name_node = node.child_by_field_name("name")?;
        let func_name = get_node_text(&name_node, source).to_string();

        let mut caller_name = func_name.clone();
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "class_body" || parent.kind() == "statement_block" {
                if let Some(grand_parent) = parent.parent() {
                    if grand_parent.kind() == "class_declaration" || grand_parent.kind() == "class"
                    {
                        if let Some(class_name_node) = grand_parent.child_by_field_name("name") {
                            let class_name = get_node_text(&class_name_node, source);
                            caller_name = format!("{class_name}.{func_name}");
                        }
                        break;
                    }
                }
            }
            current = parent.parent();
        }

        let mut calls = Vec::new();
        if let Some(params) = node.child_by_field_name("parameters") {
            calls.extend(self.extract_calls_from_params(
                &params,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &caller_name,
            ));
        }
        if let Some(body) = node.child_by_field_name("body") {
            calls.extend(self.extract_calls_from_node(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &caller_name,
            ));
        }

        Some((caller_name, calls))
    }

    /// Extract calls from the body of a CommonJS / prototype-style
    /// function assignment such as `app.init = function init() { ... }`.
    ///
    /// language-adapters-completeness-v1 (BUG-AGG12-7).
    fn extract_calls_for_assignment_expression(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Option<(String, Vec<CallSite>)> {
        let caller_name = Self::extract_assignment_function_name(node, source)?;
        let right = node.child_by_field_name("right")?;
        if !matches!(
            right.kind(),
            "function_expression" | "function" | "arrow_function" | "generator_function"
        ) {
            return None;
        }

        let mut calls = Vec::new();
        if let Some(params) = right.child_by_field_name("parameters") {
            calls.extend(self.extract_calls_from_params(
                &params,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &caller_name,
            ));
        }
        if let Some(body) = right.child_by_field_name("body") {
            calls.extend(self.extract_calls_from_node(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &caller_name,
            ));
        }

        Some((caller_name, calls))
    }

    fn extract_calls_for_method_definition(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Option<(String, Vec<CallSite>)> {
        let name_node = node.child_by_field_name("name")?;
        let method_name = get_node_text(&name_node, source).to_string();

        let mut class_name = None;
        let mut parent = node.parent();
        while let Some(current) = parent {
            if current.kind() == "class_declaration" {
                if let Some(class_name_node) = current.child_by_field_name("name") {
                    class_name = Some(get_node_text(&class_name_node, source).to_string());
                }
                break;
            }
            if current.kind() == "class" {
                if let Some(grand_parent) = current.parent() {
                    if grand_parent.kind() == "variable_declarator" {
                        for i in 0..grand_parent.child_count() {
                            if let Some(child) = grand_parent.child(i) {
                                if child.kind() == "identifier" {
                                    class_name = Some(get_node_text(&child, source).to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
            parent = current.parent();
        }

        let full_name = if let Some(class_name) = class_name {
            format!("{class_name}.{method_name}")
        } else {
            method_name
        };

        let mut calls = Vec::new();
        calls.extend(self.extract_calls_from_preceding_decorators(
            node,
            source,
            defined_funcs,
            defined_classes,
            method_receivers,
            &full_name,
        ));
        if let Some(params) = node.child_by_field_name("parameters") {
            calls.extend(self.extract_calls_from_params(
                &params,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &full_name,
            ));
        }
        if let Some(body) = node.child_by_field_name("body") {
            calls.extend(self.extract_calls_from_node(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &full_name,
            ));
        }

        Some((full_name, calls))
    }

    fn extract_calls_from_preceding_decorators(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
        caller: &str,
    ) -> Vec<CallSite> {
        let Some(class_body_parent) = node.parent() else {
            return Vec::new();
        };
        if class_body_parent.kind() != "class_body" {
            return Vec::new();
        }

        let mut cursor = class_body_parent.walk();
        let mut found_self = false;
        let mut decorator_nodes: Vec<Node> = Vec::new();

        for child in class_body_parent.children(&mut cursor) {
            if child.id() == node.id() {
                found_self = true;
                break;
            }
            if child.kind() == "decorator" {
                decorator_nodes.push(child);
            } else {
                decorator_nodes.clear();
            }
        }
        if !found_self {
            return Vec::new();
        }

        let mut calls = Vec::new();
        for decorator in &decorator_nodes {
            calls.extend(self.extract_calls_from_node(
                decorator,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                caller,
            ));
        }
        calls
    }

    fn extract_calls_for_variable_declaration(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Vec<(String, Vec<CallSite>)> {
        let mut extracted = Vec::new();

        for i in 0..node.named_child_count() {
            let Some(decl) = node.named_child(i) else {
                continue;
            };
            if decl.kind() != "variable_declarator" {
                continue;
            }

            let mut var_name: Option<String> = None;
            let mut arrow_node: Option<Node> = None;
            let mut arrow_body: Option<Node> = None;

            for j in 0..decl.child_count() {
                let Some(child) = decl.child(j) else {
                    continue;
                };
                match child.kind() {
                    "identifier" => var_name = Some(get_node_text(&child, source).to_string()),
                    "arrow_function" => {
                        arrow_node = Some(child);
                        for k in 0..child.child_count() {
                            if let Some(arrow_child) = child.child(k) {
                                if arrow_child.kind() == "statement_block" {
                                    arrow_body = Some(arrow_child);
                                    break;
                                }
                            }
                        }
                        if arrow_body.is_none() {
                            arrow_body = Some(child);
                        }
                    }
                    _ => {}
                }
            }

            let (Some(name), Some(body)) = (var_name, arrow_body) else {
                continue;
            };

            let mut calls = Vec::new();
            if let Some(arrow) = arrow_node {
                for k in 0..arrow.child_count() {
                    let Some(arrow_child) = arrow.child(k) else {
                        continue;
                    };
                    if arrow_child.kind() == "formal_parameters" {
                        calls.extend(self.extract_calls_from_params(
                            &arrow_child,
                            source,
                            defined_funcs,
                            defined_classes,
                            method_receivers,
                            &name,
                        ));
                        break;
                    }
                }
            }

            calls.extend(self.extract_calls_from_node(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &name,
            ));
            extracted.push((name, calls));
        }

        extracted
    }

    fn extract_calls_for_export_statement(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Vec<(String, Vec<CallSite>)> {
        let mut extracted = Vec::new();

        for i in 0..node.named_child_count() {
            let Some(child) = node.named_child(i) else {
                continue;
            };
            if child.kind() != "function_declaration" {
                continue;
            }

            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let func_name = get_node_text(&name_node, source).to_string();
            let Some(body) = child.child_by_field_name("body") else {
                continue;
            };
            let calls = self.extract_calls_from_node(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &func_name,
            );
            extracted.push((func_name, calls));
        }

        extracted
    }

    fn extract_calls_for_class_declaration(
        &self,
        node: &Node,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Option<(String, Vec<CallSite>)> {
        let name_node = node.child_by_field_name("name")?;
        let class_name = get_node_text(&name_node, source).to_string();
        let mut class_calls = self.extract_calls_from_decorators(
            node,
            source,
            defined_funcs,
            defined_classes,
            method_receivers,
            &class_name,
        );

        if let Some(body) = node.child_by_field_name("body") {
            class_calls.extend(self.extract_class_body_calls(
                &body,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                &class_name,
            ));
        }

        Some((class_name, class_calls))
    }

    fn collect_module_level_calls(
        &self,
        tree: &Tree,
        source: &[u8],
        defined_funcs: &HashSet<String>,
        defined_classes: &HashSet<String>,
        method_receivers: &HashMap<String, HashSet<String>>,
    ) -> Vec<CallSite> {
        let mut module_calls = Vec::new();
        for child in tree.root_node().children(&mut tree.root_node().walk()) {
            if matches!(
                child.kind(),
                "function_declaration"
                    | "class_declaration"
                    | "export_statement"
                    | "import_statement"
            ) {
                continue;
            }
            // language-adapters-completeness-v1 (BUG-AGG12-7): skip
            // expression statements that wrap a CommonJS function
            // assignment (`app.init = function init() { ... }`). Those
            // calls are now attributed to the assigned function (caller
            // = `init`) by `extract_calls_for_assignment_expression`,
            // so including them again here would double-count every
            // line of the assigned function under `<module>`.
            if child.kind() == "expression_statement" {
                if let Some(inner) = child.named_child(0) {
                    if inner.kind() == "assignment_expression" {
                        if let Some(right) = inner.child_by_field_name("right") {
                            if matches!(
                                right.kind(),
                                "function_expression"
                                    | "function"
                                    | "arrow_function"
                                    | "generator_function"
                            ) {
                                continue;
                            }
                        }
                    }
                }
            }
            module_calls.extend(self.extract_calls_from_node(
                &child,
                source,
                defined_funcs,
                defined_classes,
                method_receivers,
                "<module>",
            ));
        }
        module_calls
    }

    fn extract_class_definition(
        &self,
        node: &Node,
        source: &[u8],
        funcs: &mut Vec<FuncDef>,
    ) -> Option<ClassDef> {
        let name_node = node.child_by_field_name("name")?;
        let class_name = get_node_text(&name_node, source).to_string();
        let line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;
        let mut methods = Vec::new();
        let mut bases = Vec::new();

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else {
                continue;
            };
            if child.kind() == "class_heritage" {
                for j in 0..child.child_count() {
                    let Some(heritage_child) = child.child(j) else {
                        continue;
                    };
                    if heritage_child.kind() != "extends_clause"
                        && heritage_child.kind() != "implements_clause"
                    {
                        continue;
                    }
                    for k in 0..heritage_child.child_count() {
                        if let Some(base) = heritage_child.child(k) {
                            if base.kind() == "identifier" || base.kind() == "type_identifier" {
                                bases.push(get_node_text(&base, source).to_string());
                            }
                        }
                    }
                }
            }
            if child.kind() != "class_body" {
                continue;
            }
            for j in 0..child.named_child_count() {
                let Some(member) = child.named_child(j) else {
                    continue;
                };
                if member.kind() == "method_definition" {
                    if let Some(method_name_node) = member.child_by_field_name("name") {
                        let method_name = get_node_text(&method_name_node, source).to_string();
                        methods.push(method_name.clone());
                        funcs.push(FuncDef::method(
                            method_name,
                            &class_name,
                            member.start_position().row as u32 + 1,
                            member.end_position().row as u32 + 1,
                        ));
                    }
                }
                if member.kind() == "constructor" {
                    let ctor_name = "constructor".to_string();
                    methods.push(ctor_name.clone());
                    funcs.push(FuncDef::method(
                        ctor_name,
                        &class_name,
                        member.start_position().row as u32 + 1,
                        member.end_position().row as u32 + 1,
                    ));
                }
            }
        }

        Some(ClassDef::new(class_name, line, end_line, methods, bases))
    }

    fn extract_variable_arrow_function_defs(
        &self,
        node: &Node,
        source: &[u8],
        funcs: &mut Vec<FuncDef>,
    ) {
        for i in 0..node.named_child_count() {
            let Some(decl) = node.named_child(i) else {
                continue;
            };
            if decl.kind() != "variable_declarator" {
                continue;
            }
            let mut var_name: Option<String> = None;
            let mut is_arrow = false;
            for j in 0..decl.child_count() {
                let Some(child) = decl.child(j) else {
                    continue;
                };
                match child.kind() {
                    "identifier" => var_name = Some(get_node_text(&child, source).to_string()),
                    "arrow_function" => is_arrow = true,
                    _ => {}
                }
            }
            if is_arrow {
                if let Some(name) = var_name {
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    funcs.push(FuncDef::function(name, line, end_line));
                }
            }
        }
    }

    fn extract_exported_definitions(
        &self,
        node: &Node,
        source: &[u8],
        funcs: &mut Vec<FuncDef>,
        classes: &mut Vec<ClassDef>,
    ) {
        for i in 0..node.named_child_count() {
            let Some(child) = node.named_child(i) else {
                continue;
            };
            match child.kind() {
                "function_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source).to_string();
                        let line = child.start_position().row as u32 + 1;
                        let end_line = child.end_position().row as u32 + 1;
                        funcs.push(FuncDef::function(name, line, end_line));
                    }
                }
                "class_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let class_name = get_node_text(&name_node, source).to_string();
                        let line = child.start_position().row as u32 + 1;
                        let end_line = child.end_position().row as u32 + 1;
                        classes.push(ClassDef::simple(class_name, line, end_line));
                    }
                }
                _ => {}
            }
        }
    }
}

impl CallGraphLanguageSupport for TypeScriptHandler {
    fn name(&self) -> &str {
        "typescript"
    }

    fn extensions(&self) -> &[&str] {
        &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
    }

    fn parse_imports(&self, source: &str, _path: &Path) -> Result<Vec<ImportDef>, ParseError> {
        let tree = self.parse_source(source)?;
        let source_bytes = source.as_bytes();
        let mut imports = Vec::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "import_statement" => {
                    imports.extend(self.parse_import_statement(&node, source_bytes));
                }
                "variable_declarator" | "assignment_expression" => {
                    if let Some(imp) = self.parse_require_alias(&node, source_bytes) {
                        imports.push(imp);
                    }
                }
                "call_expression" => {
                    // Check for require() calls
                    if let Some(parent) = node.parent() {
                        let parent_kind = parent.kind();
                        if parent_kind == "variable_declarator"
                            || parent_kind == "assignment_expression"
                        {
                            continue;
                        }
                    }
                    if let Some(imp) = self.parse_require_call(&node, source_bytes) {
                        imports.push(imp);
                    }
                }
                "export_statement" => {
                    // Check for re-exports: export { x } from 'module'
                    let mut module = None;
                    let mut names = Vec::new();
                    let mut is_star = false;

                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            match child.kind() {
                                "string" => {
                                    let text = get_node_text(&child, source_bytes);
                                    module = Some(
                                        text.trim_matches(|c| c == '"' || c == '\'').to_string(),
                                    );
                                }
                                "asterisk" => {
                                    is_star = true;
                                }
                                "export_clause" => {
                                    for j in 0..child.child_count() {
                                        if let Some(spec) = child.child(j) {
                                            if spec.kind() == "export_specifier" {
                                                for k in 0..spec.child_count() {
                                                    if let Some(id) = spec.child(k) {
                                                        if id.kind() == "identifier" {
                                                            names.push(
                                                                get_node_text(&id, source_bytes)
                                                                    .to_string(),
                                                            );
                                                            break;
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
                    }

                    if let Some(m) = module {
                        if is_star {
                            let mut imp = ImportDef::from_import(m, vec!["*".to_string()]);
                            imp.is_namespace = true;
                            imports.push(imp);
                        } else if !names.is_empty() {
                            imports.push(ImportDef::from_import(m, names));
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
        let (defined_funcs, defined_classes, method_receivers) =
            self.collect_definitions(tree, source_bytes);
        let mut calls_by_func: HashMap<String, Vec<CallSite>> = HashMap::new();

        for node in walk_tree(tree.root_node()) {
            match node.kind() {
                "function_declaration" => {
                    if let Some((caller_name, calls)) = self.extract_calls_for_function_declaration(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &defined_classes,
                        &method_receivers,
                    ) {
                        insert_calls_if_any(&mut calls_by_func, caller_name, calls);
                    }
                }
                "method_definition" => {
                    if let Some((caller_name, calls)) = self.extract_calls_for_method_definition(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &defined_classes,
                        &method_receivers,
                    ) {
                        insert_calls_if_any(&mut calls_by_func, caller_name, calls);
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    for (caller_name, calls) in self.extract_calls_for_variable_declaration(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &defined_classes,
                        &method_receivers,
                    ) {
                        insert_calls_if_any(&mut calls_by_func, caller_name, calls);
                    }
                }
                "assignment_expression" => {
                    // language-adapters-completeness-v1 (BUG-AGG12-7):
                    // CommonJS pattern `app.method = function () { ... }`.
                    // Walk the function body to capture every call made
                    // FROM the assigned function so the call graph
                    // includes both the assignment as a definition AND
                    // the calls it makes.
                    //
                    // Limit to top-level assignment statements so we
                    // don't double-attribute calls when the pattern
                    // appears inside an enclosing function body.
                    if Self::is_top_level_assignment(&node) {
                        if let Some((caller_name, calls)) = self
                            .extract_calls_for_assignment_expression(
                                &node,
                                source_bytes,
                                &defined_funcs,
                                &defined_classes,
                                &method_receivers,
                            )
                        {
                            insert_calls_if_any(&mut calls_by_func, caller_name, calls);
                        }
                    }
                }
                "export_statement" => {
                    for (caller_name, calls) in self.extract_calls_for_export_statement(
                        &node,
                        source_bytes,
                        &defined_funcs,
                        &defined_classes,
                        &method_receivers,
                    ) {
                        insert_calls_if_any(&mut calls_by_func, caller_name, calls);
                    }
                }
                // Pattern #3, #4, #9: Class field initializers, static blocks, class decorators
                "class_declaration" => {
                    if let Some((class_name, class_calls)) = self
                        .extract_calls_for_class_declaration(
                            &node,
                            source_bytes,
                            &defined_funcs,
                            &defined_classes,
                            &method_receivers,
                        )
                    {
                        extend_calls_if_any(&mut calls_by_func, class_name, class_calls);
                    }
                }
                _ => {}
            }
        }

        let module_calls = self.collect_module_level_calls(
            tree,
            source_bytes,
            &defined_funcs,
            &defined_classes,
            &method_receivers,
        );
        insert_calls_if_any(&mut calls_by_func, "<module>".to_string(), module_calls);

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
                "function_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source_bytes).to_string();
                        let line = node.start_position().row as u32 + 1;
                        let end_line = node.end_position().row as u32 + 1;
                        funcs.push(FuncDef::function(name, line, end_line));
                    }
                }
                "class_declaration" => {
                    if let Some(class_def) =
                        self.extract_class_definition(&node, source_bytes, &mut funcs)
                    {
                        classes.push(class_def);
                    }
                }
                "method_definition" => {
                    // Only capture top-level methods not already captured inside class_declaration
                    // Check if parent is a class_body whose parent is class_declaration
                    let already_captured = node.parent().is_some_and(|p| {
                        p.kind() == "class_body"
                            && p.parent()
                                .is_some_and(|gp| gp.kind() == "class_declaration")
                    });
                    if !already_captured {
                        if let Some(name_node) = node.child_by_field_name("name") {
                            let name = get_node_text(&name_node, source_bytes).to_string();
                            let line = node.start_position().row as u32 + 1;
                            let end_line = node.end_position().row as u32 + 1;
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    self.extract_variable_arrow_function_defs(&node, source_bytes, &mut funcs);
                }
                "assignment_expression" => {
                    // language-adapters-completeness-v1 (BUG-AGG12-7):
                    // mirror `collect_definitions` — recognize CommonJS
                    // method-on-object assignments (`obj.method = function
                    // name() { ... }`) so the FuncIndex contains the
                    // assigned function. Without this entry,
                    // cross-file/in-file resolution of `app.method()`
                    // call sites silently fails.
                    if Self::is_top_level_assignment(&node) {
                        if let Some(name) =
                            Self::extract_assignment_function_name(&node, source_bytes)
                        {
                            let line = node.start_position().row as u32 + 1;
                            let end_line = node.end_position().row as u32 + 1;
                            funcs.push(FuncDef::function(name, line, end_line));
                        }
                    }
                }
                "export_statement" => {
                    self.extract_exported_definitions(
                        &node,
                        source_bytes,
                        &mut funcs,
                        &mut classes,
                    );
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
        let handler = TypeScriptHandler::new();
        handler.parse_imports(source, Path::new("test.ts")).unwrap()
    }

    fn extract_calls(source: &str) -> HashMap<String, Vec<CallSite>> {
        let handler = TypeScriptHandler::new();
        let tree = handler.parse_source(source).unwrap();
        handler
            .extract_calls(Path::new("test.ts"), source, &tree)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Import Parsing Tests
    // -------------------------------------------------------------------------

    mod import_tests {
        use super::*;

        #[test]
        fn test_parse_import_named() {
            let imports = parse_imports("import { foo, bar } from './mod';");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./mod");
            assert!(imports[0].is_from);
            assert!(imports[0].names.contains(&"foo".to_string()));
            assert!(imports[0].names.contains(&"bar".to_string()));
        }

        #[test]
        fn test_parse_import_default() {
            let imports = parse_imports("import Foo from './mod';");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./mod");
            assert!(imports[0].is_default);
            assert_eq!(imports[0].alias, Some("Foo".to_string()));
        }

        #[test]
        fn test_parse_import_namespace() {
            let imports = parse_imports("import * as mod from './mod';");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./mod");
            assert!(imports[0].is_namespace);
            assert_eq!(imports[0].alias, Some("mod".to_string()));
        }

        #[test]
        fn test_parse_import_with_alias() {
            let imports = parse_imports("import { foo as f } from './mod';");
            assert_eq!(imports.len(), 1);
            assert!(imports[0].names.contains(&"foo".to_string()));
            let aliases = imports[0].aliases.as_ref().unwrap();
            assert_eq!(aliases.get("f"), Some(&"foo".to_string()));
        }

        #[test]
        fn test_parse_import_side_effect() {
            let imports = parse_imports("import './polyfill';");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./polyfill");
            assert!(!imports[0].is_from);
            assert!(imports[0].names.is_empty());
        }

        #[test]
        fn test_parse_require() {
            let imports = parse_imports("const fs = require('fs');");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "fs");
        }

        #[test]
        fn test_parse_require_with_alias() {
            let imports = parse_imports("const utils = require('./utils');");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./utils");
            assert_eq!(imports[0].alias.as_deref(), Some("utils"));
        }

        #[test]
        fn test_parse_reexport() {
            let imports = parse_imports("export { foo, bar } from './helpers';");
            assert_eq!(imports.len(), 1);
            assert_eq!(imports[0].module, "./helpers");
            assert!(imports[0].names.contains(&"foo".to_string()));
        }

        #[test]
        fn test_parse_multiple_imports() {
            let source = r#"
import fs from 'fs';
import { readFile } from 'fs/promises';
import * as path from 'path';
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
function main() {
    console.log("hello");
    someFunc();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            assert!(main_calls.iter().any(|c| c.target == "console.log"));
            assert!(main_calls.iter().any(|c| c.target == "someFunc"));
        }

        #[test]
        fn test_extract_calls_intra_file() {
            let source = r#"
function helper() {
    return 42;
}

function main() {
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
function main() {
    obj.method();
    arr.push(1);
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();

            let obj_method = main_calls
                .iter()
                .find(|c| c.target == "obj.method")
                .unwrap();
            assert_eq!(obj_method.call_type, CallType::Attr);
            assert_eq!(obj_method.receiver, Some("obj".to_string()));
        }

        #[test]
        fn test_extract_calls_arrow_function() {
            let source = r#"
const helper = () => console.log("hi");

const main = () => {
    helper();
};
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();
            assert!(main_calls.iter().any(|c| c.target == "helper"));
        }

        #[test]
        fn test_extract_calls_new_expression() {
            let source = r#"
class MyClass {}

function main() {
    const obj = new MyClass();
    const date = new Date();
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("main").unwrap();

            let myclass_call = main_calls.iter().find(|c| c.target == "MyClass").unwrap();
            assert_eq!(myclass_call.call_type, CallType::Intra);

            let date_call = main_calls.iter().find(|c| c.target == "Date").unwrap();
            assert_eq!(date_call.call_type, CallType::Direct);
        }

        #[test]
        fn test_extract_calls_class_method() {
            let source = r#"
class MyClass {
    helper() {
        return 42;
    }

    main() {
        this.helper();
        console.log("hi");
    }
}
"#;
            let calls = extract_calls(source);
            let main_calls = calls.get("MyClass.main").unwrap();

            // this.helper() should resolve to local method
            let helper_call = main_calls.iter().find(|c| c.target == "helper").unwrap();
            assert_eq!(helper_call.call_type, CallType::Intra);
            assert_eq!(helper_call.receiver, Some("this".to_string()));
        }

        #[test]
        fn test_extract_calls_with_line_numbers() {
            let source = r#"function main() {
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
    }

    // -------------------------------------------------------------------------
    // New Pattern Tests (TDD - patterns #3, #4, #6, #7, #9, #11, #13, #14)
    // -------------------------------------------------------------------------

    mod new_pattern_tests {
        use super::*;

        // Pattern #3: Class field initializers
        #[test]
        fn test_class_field_initializer() {
            let source = r#"
class Config {
    handler = createHandler();
}
"#;
            let calls = extract_calls(source);
            // createHandler() should be extracted with caller = Config
            let config_calls = calls
                .get("Config")
                .expect("Config should have calls from field initializers");
            assert!(
                config_calls.iter().any(|c| c.target == "createHandler"),
                "createHandler() should be called from Config field initializer"
            );
        }

        #[test]
        fn test_class_static_field_initializer() {
            let source = r#"
class Config {
    static instance = Config.create();
}
"#;
            let calls = extract_calls(source);
            let config_calls = calls
                .get("Config")
                .expect("Config should have calls from static field initializers");
            assert!(
                config_calls.iter().any(|c| c.target == "Config.create"),
                "Config.create() should be called from Config static field initializer"
            );
        }

        #[test]
        fn test_class_field_initializer_multiple() {
            let source = r#"
class Config {
    handler = createHandler();
    timeout = computeTimeout();
    static instance = Config.create();
}
"#;
            let calls = extract_calls(source);
            let config_calls = calls
                .get("Config")
                .expect("Config should have calls from field initializers");
            assert!(config_calls.iter().any(|c| c.target == "createHandler"));
            assert!(config_calls.iter().any(|c| c.target == "computeTimeout"));
            assert!(config_calls.iter().any(|c| c.target == "Config.create"));
        }

        // Pattern #6: Function default params
        #[test]
        fn test_function_default_params() {
            let source = r#"
function greet(name = getDefault()) {
    doSomething();
}
"#;
            let calls = extract_calls(source);
            let greet_calls = calls.get("greet").expect("greet should have calls");
            assert!(
                greet_calls.iter().any(|c| c.target == "getDefault"),
                "getDefault() in default param should be extracted with caller = greet"
            );
            assert!(
                greet_calls.iter().any(|c| c.target == "doSomething"),
                "doSomething() in body should still be extracted"
            );
        }

        #[test]
        fn test_arrow_function_default_params() {
            let source = r#"
const process2 = (data = loadData()) => {
    transform();
};
"#;
            let calls = extract_calls(source);
            let process_calls = calls.get("process2").expect("process2 should have calls");
            assert!(
                process_calls.iter().any(|c| c.target == "loadData"),
                "loadData() in arrow function default param should be extracted"
            );
            assert!(
                process_calls.iter().any(|c| c.target == "transform"),
                "transform() in body should still be extracted"
            );
        }

        // Pattern #7: Constructor default params
        #[test]
        fn test_constructor_default_params() {
            let source = r#"
class Service {
    constructor(db = connectDb()) {
        this.init();
    }
}
"#;
            let calls = extract_calls(source);
            let ctor_calls = calls
                .get("Service.constructor")
                .expect("Service.constructor should have calls");
            assert!(
                ctor_calls.iter().any(|c| c.target == "connectDb"),
                "connectDb() in constructor default param should be extracted"
            );
        }

        // Pattern #9: Decorator calls
        #[test]
        fn test_class_decorator_call() {
            let source = r#"
function Component(opts: any) { return (target: any) => target; }

@Component({ selector: 'app' })
class AppComponent { }
"#;
            let calls = extract_calls(source);
            let app_calls = calls
                .get("AppComponent")
                .expect("AppComponent should have decorator calls");
            assert!(
                app_calls.iter().any(|c| c.target == "Component"),
                "Component() decorator call should be extracted with caller = AppComponent"
            );
        }

        #[test]
        fn test_decorator_with_nested_call() {
            let source = r#"
@Component({ template: getTemplate() })
class AppComponent { }
"#;
            let calls = extract_calls(source);
            let app_calls = calls
                .get("AppComponent")
                .expect("AppComponent should have decorator calls");
            assert!(
                app_calls.iter().any(|c| c.target == "Component"),
                "Component() decorator call should be extracted"
            );
            assert!(
                app_calls.iter().any(|c| c.target == "getTemplate"),
                "getTemplate() nested in decorator args should be extracted"
            );
        }

        #[test]
        fn test_method_decorator_call() {
            let source = r#"
class Controller {
    @Get("/api")
    handleRequest() {
        processRequest();
    }
}
"#;
            let calls = extract_calls(source);
            let handler_calls = calls
                .get("Controller.handleRequest")
                .expect("Controller.handleRequest should have calls");
            assert!(
                handler_calls.iter().any(|c| c.target == "Get"),
                "Get() method decorator should be extracted with caller = Controller.handleRequest"
            );
            assert!(
                handler_calls.iter().any(|c| c.target == "processRequest"),
                "processRequest() in body should still be extracted"
            );
        }

        // Pattern #4: Static initializer blocks
        #[test]
        fn test_static_block() {
            let source = r#"
class Database {
    static {
        initialize();
        configure();
    }
}
"#;
            let calls = extract_calls(source);
            let db_calls = calls
                .get("Database")
                .expect("Database should have calls from static block");
            assert!(
                db_calls.iter().any(|c| c.target == "initialize"),
                "initialize() in static block should be extracted with caller = Database"
            );
            assert!(
                db_calls.iter().any(|c| c.target == "configure"),
                "configure() in static block should be extracted with caller = Database"
            );
        }

        // Pattern #13: Getter/Setter (should already work)
        #[test]
        fn test_getter_setter() {
            let source = r#"
class Cache {
    get size() { return computeSize(); }
    set limit(v: number) { validateLimit(v); }
}
"#;
            let calls = extract_calls(source);
            let getter_calls = calls
                .get("Cache.size")
                .expect("Cache.size getter should have calls");
            assert!(
                getter_calls.iter().any(|c| c.target == "computeSize"),
                "computeSize() in getter body should be extracted"
            );

            let setter_calls = calls
                .get("Cache.limit")
                .expect("Cache.limit setter should have calls");
            assert!(
                setter_calls.iter().any(|c| c.target == "validateLimit"),
                "validateLimit() in setter body should be extracted"
            );
        }

        // Pattern #11: Super constructor args (should already work for nested calls)
        #[test]
        fn test_super_constructor_args() {
            let source = r#"
class Child extends Parent {
    constructor() {
        super(createArg(), computeValue());
    }
}
"#;
            let calls = extract_calls(source);
            let ctor_calls = calls
                .get("Child.constructor")
                .expect("Child.constructor should have calls");
            assert!(
                ctor_calls.iter().any(|c| c.target == "createArg"),
                "createArg() in super() args should be extracted"
            );
            assert!(
                ctor_calls.iter().any(|c| c.target == "computeValue"),
                "computeValue() in super() args should be extracted"
            );
        }

        // Pattern #14: Anonymous class expression
        #[test]
        fn test_anonymous_class_expression() {
            let source = r#"
const handler = class {
    process() { compute(); }
};
"#;
            let calls = extract_calls(source);
            // The method inside anonymous class should still have calls extracted
            // The class is assigned to "handler", so methods should be "handler.process"
            let process_calls = calls
                .get("handler.process")
                .expect("handler.process should have calls");
            assert!(
                process_calls.iter().any(|c| c.target == "compute"),
                "compute() inside anonymous class method should be extracted"
            );
        }

        // Pattern #14 alternative: named variable used as class name
        #[test]
        fn test_anonymous_class_with_methods() {
            let source = r#"
const MyHandler = class {
    init() { setup(); }
    run() { execute(); }
};
"#;
            let calls = extract_calls(source);
            let init_calls = calls
                .get("MyHandler.init")
                .expect("MyHandler.init should have calls");
            assert!(init_calls.iter().any(|c| c.target == "setup"));

            let run_calls = calls
                .get("MyHandler.run")
                .expect("MyHandler.run should have calls");
            assert!(run_calls.iter().any(|c| c.target == "execute"));
        }

        // Test that class methods calling top-level functions record calls with qualified caller names
        // This verifies the fix for cross-scope intra-file call extraction
        #[test]
        fn test_extract_calls_method_to_toplevel() {
            let source = r#"
function helper_func() {
    return 42;
}

class MyClass {
    method() {
        helper_func();
    }
}
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

        // Test that multiple methods with same name in different classes
        // have their calls recorded separately with qualified caller names
        #[test]
        fn test_multiple_methods_same_name() {
            let source = r#"
function _helper() {
    return 1;
}

class Command {
    shell_complete() {
        _helper();
    }
}

class Group extends Command {
    shell_complete() {
        _helper();
    }
}
"#;
            let calls = extract_calls(source);

            // After the fix, calls should be recorded with qualified names
            // Command.shell_complete and Group.shell_complete should both exist
            let command_calls = calls
                .get("Command.shell_complete")
                .expect("Command.shell_complete should have calls");
            assert!(
                command_calls.iter().any(|c| c.target == "_helper"),
                "Command.shell_complete should have a call to _helper"
            );

            let group_calls = calls
                .get("Group.shell_complete")
                .expect("Group.shell_complete should have calls");
            assert!(
                group_calls.iter().any(|c| c.target == "_helper"),
                "Group.shell_complete should have a call to _helper"
            );

            // There should be NO unqualified "shell_complete" entry (the bug behavior)
            assert!(!calls.contains_key("shell_complete"),
                "Should not have unqualified 'shell_complete' - all method calls should use Class.method format");
        }
    }

    // -------------------------------------------------------------------------
    // JSX Call Extraction Tests
    // -------------------------------------------------------------------------

    mod jsx_tests {
        use super::*;

        #[test]
        fn test_jsx_self_closing() {
            let source = r#"
function Button() { return null; }
function App() {
    return <Button />;
}
"#;
            let calls = extract_calls(source);
            let app_calls = calls.get("App").unwrap();
            let btn = app_calls.iter().find(|c| c.target == "Button").unwrap();
            assert_eq!(btn.call_type, CallType::Intra);
        }

        #[test]
        fn test_jsx_opening_element() {
            let source = r#"
function Modal() { return null; }
function Page() {
    return <Modal><p>content</p></Modal>;
}
"#;
            let calls = extract_calls(source);
            let page_calls = calls.get("Page").unwrap();
            assert!(page_calls
                .iter()
                .any(|c| c.target == "Modal" && c.call_type == CallType::Intra));
        }

        #[test]
        fn test_jsx_external_component() {
            let source = r#"
function App() {
    return <Button />;
}
"#;
            let calls = extract_calls(source);
            let app_calls = calls.get("App").unwrap();
            let btn = app_calls.iter().find(|c| c.target == "Button").unwrap();
            assert_eq!(btn.call_type, CallType::Direct);
        }

        #[test]
        fn test_jsx_ignores_html_elements() {
            let source = r#"
function App() {
    return <div><span>hello</span></div>;
}
"#;
            let calls = extract_calls(source);
            let empty = vec![];
            let app_calls = calls.get("App").unwrap_or(&empty);
            assert!(!app_calls.iter().any(|c| c.target == "div"));
            assert!(!app_calls.iter().any(|c| c.target == "span"));
        }

        #[test]
        fn test_jsx_member_expression() {
            let source = r#"
function App() {
    return <UI.Modal />;
}
"#;
            let calls = extract_calls(source);
            let app_calls = calls.get("App").unwrap();
            assert!(app_calls.iter().any(|c| c.target == "Modal"));
        }

        #[test]
        fn test_jsx_expression_call() {
            // {fn(arg)} inside JSX expression container
            let source = r#"
function formatDate(d) { return d.toISOString(); }
function App() {
    return <div>{formatDate(new Date())}</div>;
}
"#;
            let calls = extract_calls(source);
            let app_calls = calls.get("App").unwrap();
            assert!(
                app_calls
                    .iter()
                    .any(|c| c.target == "formatDate" && c.call_type == CallType::Intra),
                "Expected formatDate call inside JSX expression, got: {:?}",
                app_calls
            );
        }
    }

    // -------------------------------------------------------------------------
    // Receiver-keyed method resolution (CLUSTER T3-G1)
    //
    // The TS callgraph must only collapse `obj.method()` to an Intra edge when
    // `obj` actually matches the receiver root of `obj.method = ...` (or it is
    // `this.method()` resolving to a plain local name). A bare HashSet of method
    // names produces false self/cross edges (router.use -> use, render ->
    // render). These tests pin the receiver-keyed behaviour and the one-hop
    // alias map, while preserving the BUG-AGG12-7 win (app.init resolves).
    // -------------------------------------------------------------------------

    mod receiver_keyed_tests {
        use super::*;

        // (a) router.use() must emit an Attr edge, NOT a false use->use
        // self-edge. There IS a `use` definition in scope, but its receiver
        // root is `app`, not `router`, so the call cannot collapse to Intra.
        #[test]
        fn test_router_use_is_attr_not_self_edge() {
            let source = r#"
app.use = function use(fn) { return fn; };

function mount() {
    router.use(handler);
}
"#;
            let calls = extract_calls(source);
            let mount_calls = calls.get("mount").expect("mount should have calls");

            let use_call = mount_calls
                .iter()
                .find(|c| c.target == "router.use" || (c.target == "use" && c.receiver.as_deref() == Some("router")))
                .expect("expected a router.use call site");

            assert_eq!(
                use_call.call_type,
                CallType::Attr,
                "router.use() must be Attr (receiver `router` != receiver-root `app` of `use`); got {:?}",
                use_call
            );
            assert_eq!(
                use_call.target, "router.use",
                "Attr target must keep the obj.method form, not collapse to bare `use`"
            );

            // There must be NO false self-edge `use -> use`.
            assert!(
                !mount_calls
                    .iter()
                    .any(|c| c.target == "use" && c.call_type == CallType::Intra),
                "router.use() must not produce a false Intra self-edge to `use`; got {:?}",
                mount_calls
            );
        }

        // (b) app.init() still resolves Intra — BUG-AGG12-7 preserved. The
        // receiver `app` matches the receiver root of `app.init = ...`.
        #[test]
        fn test_app_init_resolves_intra_agg12_7_preserved() {
            let source = r#"
app.init = function init() { configure(); };

function boot() {
    app.init();
}
"#;
            let calls = extract_calls(source);
            let boot_calls = calls.get("boot").expect("boot should have calls");

            let init_call = boot_calls
                .iter()
                .find(|c| c.target == "init")
                .expect("app.init() should resolve to bare `init` (AGG12-7)");
            assert_eq!(
                init_call.call_type,
                CallType::Intra,
                "app.init() must stay Intra because `app` is the receiver root of `app.init = ...`; got {:?}",
                init_call
            );
            assert_eq!(
                init_call.receiver,
                Some("app".to_string()),
                "Intra method call should retain the receiver `app`"
            );
        }

        // (c) const r = app; r.use() resolves via the one-hop alias to app's
        // method, producing an Intra edge to `use`.
        #[test]
        fn test_alias_const_r_app_resolves_intra() {
            let source = r#"
app.use = function use(fn) { return fn; };

function mount() {
    const r = app;
    r.use(handler);
}
"#;
            let calls = extract_calls(source);
            let mount_calls = calls.get("mount").expect("mount should have calls");

            let use_call = mount_calls
                .iter()
                .find(|c| c.target == "use" && c.call_type == CallType::Intra)
                .expect("r.use() should resolve Intra via alias r -> app");
            // Receiver should reflect the alias actually written at the call site.
            assert_eq!(
                use_call.receiver,
                Some("r".to_string()),
                "Intra alias call should retain the written receiver `r`; got {:?}",
                use_call
            );

            // And there must be no leftover Attr `r.use` edge.
            assert!(
                !mount_calls.iter().any(|c| c.target == "r.use"),
                "alias-resolved call must not also emit an Attr `r.use` edge; got {:?}",
                mount_calls
            );
        }

        // (d) this.router.param(...) must NOT collapse to a bare `param`
        // self-edge. The receiver is the nested member `this.router`, not a
        // plain `this.method()`, so it stays an Attr edge.
        #[test]
        fn test_nested_this_member_does_not_collapse() {
            let source = r#"
app.param = function param() {};

function setup() {
    this.router.param(cb);
}
"#;
            let calls = extract_calls(source);
            let setup_calls = calls.get("setup").expect("setup should have calls");

            // No bare-`param` Intra self-edge.
            assert!(
                !setup_calls
                    .iter()
                    .any(|c| c.target == "param" && c.call_type == CallType::Intra),
                "this.router.param() must not collapse to a bare `param` self-edge; got {:?}",
                setup_calls
            );

            // It should surface as an Attr edge keyed on the nested receiver.
            let param_call = setup_calls
                .iter()
                .find(|c| c.target.ends_with(".param") && c.call_type == CallType::Attr)
                .expect("this.router.param() should be an Attr edge");
            assert_eq!(
                param_call.receiver.as_deref(),
                Some("this.router"),
                "nested receiver should be captured as `this.router`; got {:?}",
                param_call
            );
        }
    }

    // -------------------------------------------------------------------------
    // CLUSTER T3-G3+G2: named function-expression arguments + computed-member
    // placeholder defs.
    //
    // GAP 3 (3A): named function expressions / arrows passed as call arguments
    // (the Express `defineGetter(req,'query',function query(){...})` getter
    // pattern) are collected as defs keyed by their OWN name. Anonymous
    // callbacks have no `name` field and are excluded by construction.
    //
    // GAP 2 (2B): `app[method] = fn` (subscript LHS with an identifier index)
    // emits a virtual/computed placeholder keyed on the object (`app.[computed]`)
    // that must NOT enter the bare `defined_funcs` collapse set, so it cannot
    // create a false bare-name Intra edge.
    // -------------------------------------------------------------------------

    mod arg_and_computed_tests {
        use super::*;

        fn collect_defs(source: &str) -> (HashSet<String>, HashMap<String, HashSet<String>>) {
            let handler = TypeScriptHandler::new();
            let tree = handler.parse_source(source).unwrap();
            let (funcs, _classes, receivers) = handler.collect_definitions(&tree, source.as_bytes());
            (funcs, receivers)
        }

        // (a) A named function expression passed as a call argument is
        // collected as a def keyed by its own name.
        #[test]
        fn test_named_function_expression_arg_collected_by_own_name() {
            let source = r#"
defineGetter(req, 'query', function query() { return 1; });
defineGetter(req, 'protocol', function protocol() { return 2; });
"#;
            let (funcs, _receivers) = collect_defs(source);
            assert!(
                funcs.contains("query"),
                "named function-expression arg `function query()` must be in defined_funcs; got {:?}",
                funcs
            );
            assert!(
                funcs.contains("protocol"),
                "named function-expression arg `function protocol()` must be in defined_funcs; got {:?}",
                funcs
            );
        }

        // (b) An anonymous callback argument is NOT collected (no `name`
        // field). The string arg name (`fresh`) must never become a def.
        #[test]
        fn test_anonymous_callback_arg_not_collected() {
            let source = r#"
defineGetter(req, 'fresh', function() { return 3; });
arr.forEach(function(x) { return x; });
list.map((y) => y + 1);
"#;
            let (funcs, _receivers) = collect_defs(source);
            assert!(
                !funcs.contains("fresh"),
                "anonymous callback must NOT be collected under the string arg name; got {:?}",
                funcs
            );
            // No function-like name should leak from anonymous argument callbacks.
            // (defineGetter / forEach / map are call targets, not defs.)
            assert!(
                funcs.is_empty(),
                "no anonymous argument callback may enter defined_funcs; got {:?}",
                funcs
            );
        }

        // (c) `app[method] = fn` produces a computed/virtual placeholder def on
        // `app` that is NOT added to the bare-name collapse set (defined_funcs),
        // and cannot create a false bare-name Intra edge at a call site.
        #[test]
        fn test_computed_member_assignment_not_in_collapse_set() {
            let source = r#"
app[method] = function() { return 1; };

function dispatch() {
    method();
}
"#;
            let (funcs, receivers) = collect_defs(source);

            // The dynamic index name must NOT become a bare def.
            assert!(
                !funcs.contains("method"),
                "computed index `method` must NOT enter the bare defined_funcs collapse set; got {:?}",
                funcs
            );
            // No `.[computed]` placeholder may pollute the callgraph collapse set
            // either — the bare set must stay clean of computed members.
            assert!(
                !funcs.iter().any(|f| f.contains(".[computed]")),
                "computed-member placeholder must not enter defined_funcs; got {:?}",
                funcs
            );
            // And it must not register a receiver root for `method` (no false
            // receiver-keyed collapse for `app.method()` either).
            assert!(
                !receivers.contains_key("method"),
                "computed member must not register a receiver root for `method`; got {:?}",
                receivers
            );

            // A bare `method()` call site must therefore resolve Direct (the
            // computed assignment created no statically-known `method` def).
            let calls = extract_calls(source);
            let dispatch_calls = calls.get("dispatch").expect("dispatch should have calls");
            let method_call = dispatch_calls
                .iter()
                .find(|c| c.target == "method")
                .expect("expected a bare method() call");
            assert_eq!(
                method_call.call_type,
                CallType::Direct,
                "computed member must not create a false Intra/bare edge for method(); got {:?}",
                method_call
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
            let handler = TypeScriptHandler::new();
            assert_eq!(handler.name(), "typescript");
        }

        #[test]
        fn test_handler_extensions() {
            let handler = TypeScriptHandler::new();
            let exts = handler.extensions();
            assert!(exts.contains(&".ts"));
            assert!(exts.contains(&".tsx"));
            assert!(exts.contains(&".js"));
            assert!(exts.contains(&".jsx"));
        }

        #[test]
        fn test_handler_supports() {
            let handler = TypeScriptHandler::new();
            assert!(handler.supports("typescript"));
            assert!(handler.supports("TypeScript"));
            assert!(!handler.supports("python"));
        }

        #[test]
        fn test_handler_supports_extension() {
            let handler = TypeScriptHandler::new();
            assert!(handler.supports_extension(".ts"));
            assert!(handler.supports_extension(".tsx"));
            assert!(handler.supports_extension(".js"));
            assert!(!handler.supports_extension(".py"));
        }
    }
}
