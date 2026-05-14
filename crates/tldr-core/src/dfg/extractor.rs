//! DFG extraction from source code
//!
//! Extracts data flow graphs from functions using tree-sitter parsing.
//!
//! # Algorithm
//! 1. Parse source with tree-sitter
//! 2. Find function by name
//! 3. Extract all variable references (defs, uses, updates)
//! 4. Build CFG for the function
//! 5. Apply reaching definitions analysis
//! 6. Connect definitions to uses via edges
//!
//! # Variable Reference Identification (M7 documentation)
//!
//! ## Definitions
//! - Assignment targets: `x = ...`
//! - For loop variables: `for x in ...`
//! - Function parameters: `def f(x):`
//! - With statement variables: `with ... as x:`
//! - Exception handlers: `except E as x:`
//!
//! ## Updates
//! - Augmented assignment: `x += ...`, `x -= ...`
//! - Method calls that mutate: `x.append(...)`, `x.clear()`
//!
//! ## Uses
//! - Expression reads: `y = x + 1`
//! - Function arguments: `f(x)`
//! - Condition checks: `if x:`
//! - Return values: `return x`

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::function_finder::{find_function_node, get_function_body};
use crate::ast::parser::parse;
use crate::cfg::get_cfg_context;
use crate::dfg::reaching::compute_reaching_definitions;
use crate::types::{CfgInfo, DataflowEdge, DfgInfo, Language, RefType, VarRef};
use crate::TldrError;
use crate::TldrResult;

/// Maximum recursion depth for nested structures
const MAX_DEPTH: usize = 50;

/// Extract DFG for a function from source code or file path
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to extract DFG for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(DfgInfo)` - DFG with variable refs, edges, and variable list
/// * `Err(FunctionNotFound)` - If function doesn't exist
///
/// # Example
/// ```ignore
/// use tldr_core::dfg::get_dfg_context;
/// use tldr_core::Language;
///
/// let dfg = get_dfg_context("def foo(x): return x + 1", "foo", Language::Python)?;
/// assert_eq!(dfg.function, "foo");
/// assert!(dfg.variables.contains(&"x".to_string()));
/// ```
pub fn get_dfg_context(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    // Determine if input is a file path or source code
    let (tree, source) = if Path::new(source_or_path).exists() {
        // Read file content
        let source = std::fs::read_to_string(Path::new(source_or_path))
            .map_err(crate::TldrError::IoError)?;
        // Parse with the provided language (not detected from extension)
        let tree = parse(&source, language)?;
        (tree, source)
    } else {
        let tree = parse(source_or_path, language)?;
        (tree, source_or_path.to_string())
    };

    // Extract DFG from the parsed tree
    extract_dfg_from_tree(&tree, &source, function_name, language)
}

/// Extract DFG from a parsed tree
///
/// (vuln-migration-v1 M3) Visibility extended from private `fn` to `pub(crate)`
/// so `vuln::scan_file_vulns` can avoid the per-function re-parse implicit in
/// `get_dfg_context(&content, ...)`. Mirrors `extract_cfg_from_tree`.
pub(crate) fn extract_dfg_from_tree(
    tree: &Tree,
    source: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    let root = tree.root_node();

    // Find the function node
    let func_node = find_function_node(root, function_name, language, source);

    match func_node {
        // AGG13-15: pass file root so the builder can collect imports.
        Some(node) => build_dfg_for_function(node, root, function_name, source, language),
        None => Err(TldrError::function_not_found(function_name)),
    }
}

/// Build DFG when the caller already has the CFG in hand (skips an internal
/// re-parse).
///
/// (vuln-migration-v1 M3 perf) `extract_dfg_from_tree`'s inner
/// `build_dfg_for_function` calls `get_cfg_context(source, ...)` for
/// reaching-defs, which unconditionally re-parses the file. In
/// `vuln::scan_file_vulns` the CFG is already in hand from the call site —
/// pass it in to skip the re-parse + re-build.
pub(crate) fn extract_dfg_from_tree_with_cfg(
    tree: &Tree,
    source: &str,
    function_name: &str,
    language: Language,
    cfg: &crate::types::CfgInfo,
) -> TldrResult<DfgInfo> {
    let root = tree.root_node();
    let func_node = find_function_node(root, function_name, language, source)
        .ok_or_else(|| TldrError::function_not_found(function_name))?;

    let mut builder = DfgBuilder::new(function_name.to_string(), source, language);
    // AGG13-15: pre-populate import set BEFORE extracting refs so
    // is_use_context can consult it during traversal.
    builder.collect_imports(root);
    builder.extract_parameters(func_node)?;
    let body_node = get_function_body(func_node, language);
    if let Some(body) = body_node {
        builder.extract_refs_from_node(body, 0)?;
    }
    builder.build_def_use_chains(cfg)?;
    builder.finalize()
}

/// Build DFG for a function node
fn build_dfg_for_function(
    func_node: Node,
    root: Node,
    function_name: &str,
    source: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    let mut builder = DfgBuilder::new(function_name.to_string(), source, language);

    // AGG13-15: collect file-level imports so Java/C# `PageRequest`
    // / `Sort` style identifiers can be classified as not-a-use.
    builder.collect_imports(root);

    // First, extract function parameters as definitions
    builder.extract_parameters(func_node)?;

    // Get the function body and extract all variable references
    let body_node = get_function_body(func_node, language);
    if let Some(body) = body_node {
        builder.extract_refs_from_node(body, 0)?;
    }

    // Get CFG for reaching definitions analysis
    let cfg = get_cfg_context(source, function_name, language)?;

    // Build def-use chains using reaching definitions
    builder.build_def_use_chains(&cfg)?;

    builder.finalize()
}

/// Builder for constructing DFG
struct DfgBuilder<'a> {
    function_name: String,
    source: &'a str,
    language: Language,
    refs: Vec<VarRef>,
    variables: HashSet<String>,
    /// AGG13-15 (quality-metrics-and-schema-v1): file-level imported
    /// type/class names. For Java / C# the reaching-defs analyzer was
    /// flagging imported class identifiers (e.g. `PageRequest`,
    /// `Sort`) as uninitialized variable uses because every static
    /// method call `PageRequest.of(...)` exposes `PageRequest` as a
    /// bare `identifier` in the AST. Tracking the set of imported
    /// simple names lets `is_use_context` reject such identifiers
    /// when they are the receiver of a `method_invocation` /
    /// `field_access`. Empty for languages that don't need this filter.
    imported_type_names: HashSet<String>,
}

impl<'a> DfgBuilder<'a> {
    fn new(function_name: String, source: &'a str, language: Language) -> Self {
        Self {
            function_name,
            source,
            language,
            refs: Vec::new(),
            variables: HashSet::new(),
            imported_type_names: HashSet::new(),
        }
    }

    /// AGG13-15: populate `imported_type_names` from a Java/C# file root.
    /// Java `import_declaration` is `import a.b.C;` — the simple name is
    /// the last dotted segment (`C`). `import static a.b.C.method;`
    /// imports a static member; we capture the last segment as well.
    /// For other languages this is a no-op (the field stays empty).
    ///
    /// language-specific-bugs-v1 (P14.AGG14-12): also collect the names
    /// of class-level fields declared in the same file. Java DI patterns
    /// (`private final OwnerRepository owners; public OwnerController(
    /// OwnerRepository owners) { this.owners = owners; }`) make `owners`
    /// available to every method as a class field — but the per-method
    /// reaching-defs analyzer only sees the method body, so the use of
    /// `owners` looks like an undefined variable and was flagged
    /// `severity: definite`. Treating class fields the same way as
    /// imported type names (suppress them as not-a-use when they are
    /// the receiver of a `method_invocation` / `field_access`) avoids
    /// the false positive without losing precision: the field cannot be
    /// unintentionally shadowed by a local of the same name without that
    /// local also showing up as a definition.
    fn collect_imports(&mut self, root: Node) {
        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // extend AGG13-15's Java/C# collector to TS / JS / Lua / Luau /
        // OCaml + JS hoisted-function-declaration names + well-known
        // built-in globals. All of these are file-level names that the
        // identifier-vs-variable classifier was previously treating as
        // bare variable uses inside function bodies, producing many
        // false-positive uninit reports.
        match self.language {
            Language::Java | Language::CSharp => {}
            Language::TypeScript | Language::JavaScript => {
                // Built-in globals: NEVER local-variable uses. Seeding
                // the set lets `is_use_context` reject `Array.isArray`,
                // `new Error(...)`, etc. as not-a-use receivers, which
                // is how the reachability analyzer learns that
                // `Array`/`Error` are pre-defined.
                for g in JS_TS_GLOBALS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Lua | Language::Luau => {
                for g in LUA_LUAU_GLOBALS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Ocaml => {} // OCaml uses value_path-based suppression
            _ => return,
        }
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let kind = node.kind();
            // Java: import_declaration child layout is roughly
            //   "import" ("static")? scoped_identifier ("." "*")? ";"
            // The scoped_identifier holds the last identifier we want.
            // C#: using_directive child layout is
            //   "using" ("static")? qualified_name ";"
            if kind == "import_declaration" || kind == "using_directive" {
                if let Some(name) = last_identifier_text(node, self.source) {
                    self.imported_type_names.insert(name);
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // TS / JS `import_statement`:
            //   - `import { a, b as c } from "..."` -> a, c (alias takes
            //     precedence over name)
            //   - `import * as Ns from "..."` -> Ns (namespace_import)
            //   - `import Default from "..."` -> Default (the
            //     import_clause's direct identifier child)
            // Walk the import_statement subtree once and collect every
            // local-binding identifier — this is robust to the
            // grammar's nested layout (`import_clause` ->
            // `named_imports`/`namespace_import`/`identifier`).
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && kind == "import_statement"
            {
                collect_ts_js_import_bindings(
                    node,
                    self.source,
                    &mut self.imported_type_names,
                );
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // JS hoisted top-level `function foo(...) {}` makes `foo`
            // available throughout the file, including in earlier
            // function bodies. Without this collection the pre-fix
            // code flagged `tryRender(...)` inside express.render as
            // definite-uninitialized even though it is defined further
            // down the same file.
            //
            // We DO descend into nested function bodies so that
            // function-declaration names declared INSIDE another
            // function (e.g. `compareName`, `convertDomTypeToTsType`
            // inside ts-dom-gen's `emitWebIdl`) are also collected as
            // available names. The cost is a slightly over-permissive
            // suppression set when analyzing a sibling function — at
            // worst this misses a local-variable use whose name happens
            // to collide with a nested function defined elsewhere in
            // the file, which is a precision loss bounded by the
            // file's naming conventions. The win is that 100+ TS
            // false positives stop firing.
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && matches!(
                    kind,
                    "function_declaration"
                        | "function_expression"
                        | "arrow_function"
                        | "function"
                        | "generator_function_declaration"
                        | "generator_function"
                        | "method_definition"
                )
            {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Also collect parameter names of every nested function.
                // When the OUTER function being analyzed has nested
                // helpers (e.g. ts-dom-gen's `emitWebIdl` -> inner
                // `convertDomTypeToTsTypeBase(obj, ...)`), the nested
                // function's parameter scope is inside the outer
                // function's CFG span. Without registering the param
                // names, identifiers like `obj`, `t`, `prefix`, `s`,
                // `i` inside those nested bodies were flagged as
                // definite-uninitialized by the outer reaching-defs
                // pass. Mirror that here by walking the parameters
                // subtree once and capturing every named binding.
                if let Some(params) = node.child_by_field_name("parameters") {
                    collect_ts_js_param_names(
                        params,
                        self.source,
                        &mut self.imported_type_names,
                    );
                }
                // Descend into the body so we collect names of
                // nested function declarations as well.
                for child in node.children(&mut node.walk()) {
                    stack.push(child);
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // Lua/Luau file-level locals. `local m = {}` at the top of
            // a module makes `m` available to every function — but the
            // per-function reaching-defs analyzer would otherwise flag
            // it as uninitialized. We capture every `local` declared
            // name OUTSIDE function bodies. The lua/luau grammar uses
            // `variable_declaration` for `local x = ...` and
            // `function_declaration` / `local_function` for functions,
            // so we stop the walk at function entry points.
            if matches!(self.language, Language::Lua | Language::Luau)
                && kind == "variable_declaration"
            {
                collect_lua_local_names(node, self.source, &mut self.imported_type_names);
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // TypeScript / JavaScript file-level `const x = ...` /
            // `let x = ...` / `var x = ...`. These are module-scoped
            // bindings visible to every function in the file. Without
            // tracking them, ts-dom-gen flagged `extendConflictsBaseTypes`,
            // `namespacesAsInterfaces`, and `sequenceTypedefMap` —
            // file-level const declarations — as uninitialized.
            //
            // We only collect bindings whose direct ancestor on the
            // walk stack is NOT a function body (the stop-at-function
            // guards earlier in this loop already handle that).
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && matches!(kind, "lexical_declaration" | "variable_declaration")
            {
                collect_ts_js_variable_names(
                    node,
                    self.source,
                    &mut self.imported_type_names,
                );
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // OCaml top-level `open Foo` / `open! Foo` / `include Foo`
            // bring `Foo`'s value bindings into the module's namespace.
            // The trailing identifier of the open_module / include_module
            // is the module name (already a module ref, not a value), so
            // we don't collect it as a value-suppression name — but
            // value-path suppression in `is_ocaml_use_context` handles
            // the module-qualified case directly.
            // language-specific-bugs-v1 (P14.AGG14-12): collect class
            // field names. Java `field_declaration` carries one or more
            // `variable_declarator { name: <ident>, ... }` children — pull
            // every variable name into the same suppression set as
            // imported types. C# `field_declaration` uses the same
            // grammar layout in tree-sitter-c-sharp. Recurse INTO class
            // bodies so we see the fields (the early-return below for
            // class_declaration is now overridden for field collection).
            if kind == "field_declaration" {
                for declarator in node.children(&mut node.walk()) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        let name = name_node
                            .utf8_text(self.source.as_bytes())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !name.is_empty() {
                            self.imported_type_names.insert(name);
                        }
                    } else {
                        // Fallback: first identifier child of the declarator.
                        for inner in declarator.children(&mut declarator.walk()) {
                            if inner.kind() == "identifier" {
                                let name = inner
                                    .utf8_text(self.source.as_bytes())
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();
                                if !name.is_empty() {
                                    self.imported_type_names.insert(name);
                                }
                                break;
                            }
                        }
                    }
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // C# / Java: collect the name of every same-file type
            // declaration AND every method declaration so that bare-
            // identifier callees / type references (`BsonReaderState`,
            // `ReadNormalAsync`) inside a method body are classified as
            // not-a-use. Without this rule, `case BsonReaderState.X:`
            // flags `BsonReaderState`, and `t = ReadNormalAsync(...)`
            // flags `ReadNormalAsync`.
            //
            // We also explicitly collect the `name` of method/
            // constructor declarations BEFORE returning (without
            // descending into the body), so the next two early-returns
            // also serve as collectors.
            if matches!(
                self.language,
                Language::Java | Language::CSharp
            ) && matches!(
                kind,
                "class_declaration"
                    | "enum_declaration"
                    | "interface_declaration"
                    | "struct_declaration"
                    | "record_declaration"
            ) {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // continue walking — class bodies hold nested
                // fields/methods we still want to register.
            }
            if matches!(
                self.language,
                Language::Java | Language::CSharp
            ) && matches!(kind, "method_declaration" | "constructor_declaration") {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // Don't descend into method bodies — fields are class-level
                // declarations, never inside a method.
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // for TS/JS/Lua/Luau, stop the walk at any function-body
            // boundary EXCEPT `function_declaration` (handled above —
            // we descend into JS/TS function bodies to collect nested
            // function-declaration names too). For other function
            // shapes (arrow_function, function_expression, etc.) the
            // contents are block-scoped expressions, NOT hoisted
            // declarations, so we stop here.
            if matches!(
                self.language,
                Language::TypeScript
                    | Language::JavaScript
                    | Language::Lua
                    | Language::Luau
            ) && matches!(
                kind,
                "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "function"
                    | "generator_function_declaration"
                    | "generator_function"
                    | "local_function"
                    | "function_definition"
            ) {
                continue;
            }
            for child in node.children(&mut node.walk()) {
                stack.push(child);
            }
        }
    }

    /// Extract function parameters as definitions
    fn extract_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        let params_node = match self.language {
            Language::Python => func_node.child_by_field_name("parameters"),
            Language::TypeScript | Language::JavaScript => {
                func_node.child_by_field_name("parameters")
            }
            Language::Go => func_node.child_by_field_name("parameters"),
            Language::Rust => func_node.child_by_field_name("parameters"),
            Language::Java => func_node.child_by_field_name("parameters"),
            Language::C | Language::Cpp => func_node
                .child_by_field_name("declarator")
                .and_then(|d| d.child_by_field_name("parameters")),
            Language::Ruby => func_node.child_by_field_name("parameters"),
            Language::Php => func_node.child_by_field_name("parameters"),
            Language::CSharp => func_node.child_by_field_name("parameters"),
            Language::Kotlin => {
                // Kotlin: function_declaration uses function_value_parameters (not "parameters" field)
                func_node.child_by_field_name("parameters").or_else(|| {
                    (0..func_node.child_count())
                        .filter_map(|i| func_node.child(i))
                        .find(|child| child.kind() == "function_value_parameters")
                })
            }
            // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala's
            // tree-sitter grammar names BOTH `[B]` (type_parameters) and
            // `(f: A => IO[B])` (parameters) with field name "parameters".
            // `child_by_field_name("parameters")` returns the FIRST match
            // (the type params), so the value-parameter node was never
            // walked. Find by kind == "parameters" explicitly.
            Language::Scala => (0..func_node.child_count())
                .filter_map(|i| func_node.child(i))
                .find(|child| child.kind() == "parameters"),
            Language::Lua | Language::Luau => func_node.child_by_field_name("parameters"),
            Language::Swift => None, // Swift parameters are direct children (handled below)
            _ => None,
        };

        if let Some(params) = params_node {
            self.extract_params_from_node(params)?;
        }

        // Elixir: parameters are identifiers inside the def call's arguments
        // Structure: (call "def" (arguments (call (identifier "foo") (arguments (identifier "x")))))
        if matches!(self.language, Language::Elixir) {
            self.extract_elixir_parameters(func_node)?;
        }

        // OCaml: parameters are "parameter" nodes containing "value_pattern" inside let_binding
        if matches!(self.language, Language::Ocaml) {
            self.extract_ocaml_parameters(func_node)?;
        }

        // Swift: parameters are direct "parameter" children of function_declaration
        // Each parameter has a simple_identifier child (the param name)
        if matches!(self.language, Language::Swift) {
            self.extract_swift_parameters(func_node)?;
        }

        Ok(())
    }

    /// Extract parameter names from a parameters node
    fn extract_params_from_node(&mut self, params_node: Node) -> TldrResult<()> {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            self.extract_param_from_child(child);
        }

        Ok(())
    }

    fn extract_param_from_child(&mut self, child: Node) {
        match self.language {
            Language::Python => self.extract_python_param(child),
            Language::TypeScript | Language::JavaScript => self.extract_ts_js_param(child),
            Language::Go => self.extract_go_param(child),
            Language::Rust => self.extract_rust_param(child),
            Language::Java | Language::CSharp => self.extract_java_csharp_param(child),
            Language::Scala => self.extract_scala_param(child),
            Language::Kotlin => self.extract_kotlin_param(child),
            Language::C | Language::Cpp => self.extract_c_cpp_param(child),
            Language::Ruby => self.extract_ruby_param(child),
            Language::Php => self.extract_php_param(child),
            Language::Lua | Language::Luau => self.extract_lua_param(child),
            Language::Swift => self.extract_swift_param(child),
            _ => {}
        }
    }

    fn extract_python_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "typed_parameter" && child.kind() != "default_parameter" {
            return;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            self.add_ref_from_node(name_node, RefType::Definition);
            return;
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    fn extract_ts_js_param(&mut self, child: Node) {
        if child.kind() != "identifier" && child.kind() != "required_parameter" {
            return;
        }
        if let Some(pattern) = child.child_by_field_name("pattern") {
            self.add_ref_from_node(pattern, RefType::Definition);
        } else if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
        }
    }

    fn extract_go_param(&mut self, child: Node) {
        if child.kind() != "parameter_declaration" {
            return;
        }
        let mut inner = child.walk();
        for inner_child in child.children(&mut inner) {
            if inner_child.kind() == "identifier" {
                self.add_ref_from_node(inner_child, RefType::Definition);
            }
        }
    }

    fn extract_rust_param(&mut self, child: Node) {
        if child.kind() != "parameter" {
            return;
        }
        if let Some(pattern) = child.child_by_field_name("pattern") {
            if pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        }
    }

    fn extract_java_csharp_param(&mut self, child: Node) {
        if child.kind() != "formal_parameter"
            && child.kind() != "spread_parameter"
            && child.kind() != "parameter"
        {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
    }

    fn extract_kotlin_param(&mut self, child: Node) {
        if child.kind() != "parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
                return;
            }
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    /// cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala parameter
    /// extraction. The grammar shape is `parameters -> ( ... parameter ... )`
    /// where each `parameter` node has an `identifier` child for the param
    /// name (e.g. `f` in `def flatMap[B](f: A => IO[B])`). Without this
    /// dispatch, scala function parameters are NEVER added as Definitions
    /// and reaching-defs flags every parameter use as definite-uninitialized.
    fn extract_scala_param(&mut self, child: Node) {
        if child.kind() != "parameter" && child.kind() != "class_parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
                return;
            }
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    fn extract_c_cpp_param(&mut self, child: Node) {
        if child.kind() != "parameter_declaration" {
            return;
        }
        let Some(declarator) = child.child_by_field_name("declarator") else {
            return;
        };
        if declarator.kind() == "identifier" {
            self.add_ref_from_node(declarator, RefType::Definition);
            return;
        }
        if declarator.kind() == "pointer_declarator" {
            if let Some(identifier) = first_child_of_kind(declarator, "identifier") {
                self.add_ref_from_node(identifier, RefType::Definition);
            }
        }
    }

    fn extract_ruby_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "optional_parameter"
            && child.kind() != "keyword_parameter"
            && child.kind() != "splat_parameter"
            && child.kind() != "hash_splat_parameter"
        {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
    }

    fn extract_php_param(&mut self, child: Node) {
        if child.kind() != "simple_parameter" && child.kind() != "variadic_parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            self.add_ref_from_node(name, RefType::Definition);
        }
    }

    fn extract_lua_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // tree-sitter-luau wraps each parameter in a `parameter` node
        // whose children are `type` / `vararg_expression`. The `type`
        // node, in turn, has the param identifier as its `identifier`
        // subtype child. tree-sitter-lua, by contrast, lists parameter
        // identifiers directly as children of `parameters` — so the
        // pre-fix code (above) handled lua but silently dropped every
        // luau parameter, surfacing as 9 FPs (incl. `t, na, nh`) on
        // `tldr reaching-defs tables.luau check`.
        //
        // We accept either a `parameter` wrapper (luau) or a bare
        // identifier (lua); descend at most one extra level to find the
        // first `identifier` child.
        if child.kind() == "parameter" {
            if let Some(ident) = first_descendant_identifier_under(child, "identifier") {
                self.add_ref_from_node(ident, RefType::Definition);
            }
        }
    }

    fn extract_swift_param(&mut self, child: Node) {
        if child.kind() == "simple_identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "parameter" {
            return;
        }
        if let Some(identifier) = first_child_of_kind(child, "simple_identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    /// Add a variable reference from an AST node
    fn add_ref_from_node(&mut self, node: Node, ref_type: RefType) {
        let name = node
            .utf8_text(self.source.as_bytes())
            .unwrap_or("")
            .to_string();
        if name.is_empty() || is_keyword(&name, self.language) {
            return;
        }

        let line = node.start_position().row as u32 + 1; // 1-indexed
        let column = node.start_position().column as u32;

        self.variables.insert(name.clone());
        self.refs.push(VarRef {
            name,
            ref_type,
            line,
            column,
            context: None,
            group_id: None,
        });
    }

    /// Extract all variable references from an AST node
    ///
    /// This is the core multi-language dispatch. Each language has different
    /// AST node kinds for assignments, declarations, and loops. We match
    /// on all known kinds and delegate to language-specific processing.
    fn extract_refs_from_node(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if depth > MAX_DEPTH {
            return Ok(());
        }

        match node.kind() {
            // =================================================================
            // Python/Ruby assignment statements (Swift handled separately below)
            // =================================================================
            "assignment" if !matches!(self.language, Language::Swift) => {
                self.process_assignment(node, depth)?;
            }

            // Python expression_statement (may wrap assignment or other exprs)
            "expression_statement" => {
                self.process_expression_statement(node, depth)?;
            }

            // Python augmented assignment: x += 1
            "augmented_assignment" => {
                self.process_augmented_assignment(node)?;
            }

            // =================================================================
            // TypeScript/JavaScript declarations + Lua/Luau local declarations
            // =================================================================
            // JS/TS: let x = ...; const x = ...; var x = ...;
            // Lua/Luau: local x = ...
            "lexical_declaration" | "variable_declaration" => match self.language {
                Language::Lua | Language::Luau => {
                    self.process_lua_local_declaration(node, depth)?;
                }
                _ => {
                    self.process_js_ts_declaration(node, depth)?;
                }
            },

            // =================================================================
            // TypeScript/JavaScript/Java/C/C++/Rust assignment expressions
            // =================================================================
            "assignment_expression" => {
                self.process_c_style_assignment(node, depth)?;
            }

            // =================================================================
            // TypeScript/JavaScript/Java/C/C++ augmented assignment
            // =================================================================
            "augmented_assignment_expression" => {
                self.process_c_style_augmented_assignment(node, depth)?;
            }

            // =================================================================
            // Rust let declarations: let x = ...; let mut x = ...;
            // rust-dataflow-v1 (v0.4.2 bug-C2): `let_condition` is the AST
            // node for the `let pat = expr` form that appears INSIDE
            // `while let`, `if let`, and `let_chain` (`if let A && let B`).
            // tree-sitter-rust does NOT reuse `let_declaration` for those —
            // they share the same field layout (`pattern` / `value`), so
            // we route both kinds through `process_rust_let`. Without this
            // arm the loop binding in `while let Some(c) = self.bump()`
            // was never registered as a definition, leaving rust
            // reaching-defs with empty gen/kill sets everywhere.
            // =================================================================
            "let_declaration" | "let_condition" => {
                self.process_rust_let(node, depth)?;
            }

            // =================================================================
            // Go short var declaration: x := ...
            // =================================================================
            "short_var_declaration" => {
                self.process_go_short_var(node, depth)?;
            }

            // Go var declaration: var x = ...
            "var_declaration" => {
                self.process_go_var_declaration(node, depth)?;
            }

            // Go/Lua/Luau assignment statement: x = ...; x += ...
            "assignment_statement" => match self.language {
                Language::Lua | Language::Luau => {
                    self.process_lua_assignment_statement(node, depth)?;
                }
                _ => {
                    self.process_go_assignment(node, depth)?;
                }
            },

            // =================================================================
            // Java/C# local variable declaration: int x = ...;
            // =================================================================
            "local_variable_declaration" => {
                self.process_java_local_var(node, depth)?;
            }

            // =================================================================
            // C/C++ declaration: int x = ...;
            // =================================================================
            "declaration" if matches!(self.language, Language::C | Language::Cpp) => {
                self.process_c_declaration(node, depth)?;
            }

            // =================================================================
            // Ruby assignment: x = ...
            // Ruby uses "assignment" (same as Python, handled above)
            // =================================================================
            // Ruby operator_assignment: x += ...
            "operator_assignment" => {
                self.process_augmented_assignment(node)?;
            }

            // =================================================================
            // Kotlin/Swift property declaration: val x = ...; var x = ...; let x = ...
            // =================================================================
            "property_declaration"
                if matches!(self.language, Language::Kotlin | Language::Swift) =>
            {
                match self.language {
                    Language::Swift => self.process_swift_property(node, depth)?,
                    _ => self.process_kotlin_property(node, depth)?,
                }
            }

            // =================================================================
            // Swift assignment: z = z + 1
            // AST: assignment -> directly_assignable_expression -> simple_identifier, =, expression
            // =================================================================
            "assignment" if matches!(self.language, Language::Swift) => {
                self.process_swift_assignment(node, depth)?;
            }

            // =================================================================
            // Scala val/var definitions
            // =================================================================
            "val_definition" | "var_definition" => {
                self.process_scala_val_var(node, depth)?;
            }

            // =================================================================
            // Elixir match operator: x = ... (pattern matching assignment)
            // Elixir grammar uses binary_operator with "=" for pattern matching
            // =================================================================
            "match_operator" if matches!(self.language, Language::Elixir) => {
                self.process_elixir_match(node, depth)?;
            }

            "binary_operator" if matches!(self.language, Language::Elixir) => {
                // Check if this is an assignment (= operator)
                let is_match = node.children(&mut node.walk()).any(|c| {
                    !c.is_named() && c.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                });
                if is_match {
                    self.process_elixir_match(node, depth)?;
                } else {
                    // Other binary operators: recurse into children for uses
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }

            // =================================================================
            // OCaml let bindings: let x = ... in ...
            // =================================================================
            "let_expression" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_let_expression(node, depth)?;
            }

            "value_definition" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_value_definition(node, depth)?;
            }

            "let_binding" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_let_binding(node, depth)?;
            }

            // =================================================================
            // For loops (loop variable is a definition)
            // =================================================================
            // Python: for x in items:
            // Go: for ... { }
            "for_statement" => {
                self.process_for_loop(node, depth)?;
            }

            // Python/JS: for x in items / for (x in obj)
            "for_in_statement" => {
                self.process_for_loop(node, depth)?;
            }

            // Rust: for x in items { }
            "for_expression" => {
                self.process_rust_for(node, depth)?;
            }

            // JS/TS: for (const x of items) { }
            "for_of_statement" => {
                self.process_js_for_of(node, depth)?;
            }

            // Java: for (int x : items) { }
            "enhanced_for_statement" => {
                self.process_java_enhanced_for(node, depth)?;
            }

            // PHP: foreach ($arr as $key => $val) { }
            "foreach_statement" => {
                self.process_php_foreach(node, depth)?;
            }

            // Go: for i, v := range items { }
            "range_clause" => {
                self.process_go_range(node, depth)?;
            }

            // Ruby: for x in items do ... end
            "for" if matches!(self.language, Language::Ruby) => {
                self.process_for_loop(node, depth)?;
            }

            // =================================================================
            // With statements (Python-specific)
            // =================================================================
            "with_statement" => {
                self.process_with_statement(node, depth)?;
            }

            // =================================================================
            // Exception handlers (multi-language)
            // =================================================================
            "except_clause" | "catch_clause" => {
                self.process_exception_handler(node, depth)?;
            }

            // =================================================================
            // Identifiers (potential uses) - all languages
            // =================================================================
            "identifier" => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty() && !is_keyword(name, self.language) && self.is_use_context(node)
                {
                    // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): in Scala,
                    // identifiers whose first letter is uppercase are
                    // overwhelmingly type names, class names, or companion
                    // objects (Scala convention is strict: types/objects
                    // start uppercase, vars/methods start lowercase). They
                    // resolve at compile time to top-level singletons that
                    // are always available — flagging them as
                    // definite-uninitialized in reaching-defs is a false
                    // positive (e.g. `IO`, `FlatMap`, `Tracing` in
                    // `IO(FlatMap(this, f, Tracing.calculateTracingEvent(f)))`).
                    if matches!(self.language, Language::Scala) {
                        if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                            // Recurse into children so any nested identifiers
                            // (rare for an identifier node) are not lost.
                            let mut cursor = node.walk();
                            for child in node.children(&mut cursor) {
                                self.extract_refs_from_node(child, depth + 1)?;
                            }
                            return Ok(());
                        }
                    }
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // PHP variable names: $x
            "variable_name" if matches!(self.language, Language::Php) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty() && self.is_use_context(node) {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // OCaml: value_name is used instead of identifier for variable names
            "value_name" if matches!(self.language, Language::Ocaml) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty()
                    && !is_keyword(name, self.language)
                    && self.is_ocaml_use_context(node)
                {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // Swift: simple_identifier is used instead of identifier
            "simple_identifier" if matches!(self.language, Language::Swift) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty()
                    && !is_keyword(name, self.language)
                    && self.is_swift_use_context(node)
                {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // =================================================================
            // Recurse into other nodes
            // =================================================================
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Process a Python expression_statement (may wrap assignment, augmented_assignment, etc.)
    fn process_expression_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_refs_from_node(child, depth + 1)?;
        }
        Ok(())
    }

    /// Process an assignment statement (Python "assignment", Ruby "assignment")
    fn process_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // assignment has "left" and "right" fields
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_assignment_targets(left)?;
        }

        // Process the right side for uses
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Extract assignment targets (definitions)
    fn extract_assignment_targets(&mut self, target: Node) -> TldrResult<()> {
        match target.kind() {
            "identifier" => {
                self.add_ref_from_node(target, RefType::Definition);
            }
            // Python unpacking
            "tuple" | "list" | "pattern_list" => {
                let mut cursor = target.walk();
                for child in target.children(&mut cursor) {
                    self.extract_assignment_targets(child)?;
                }
            }
            // TS/JS destructuring patterns
            "object_pattern" | "array_pattern" => {
                let mut cursor = target.walk();
                for child in target.children(&mut cursor) {
                    if child.kind() == "identifier"
                        || child.kind() == "shorthand_property_identifier_pattern"
                        || child.kind() == "shorthand_property_identifier"
                    {
                        self.add_ref_from_node(child, RefType::Definition);
                    } else {
                        self.extract_assignment_targets(child)?;
                    }
                }
            }
            // Python: x.attr = ...
            "attribute" => {
                if let Some(obj) = target.child_by_field_name("object") {
                    if obj.kind() == "identifier" {
                        self.add_ref_from_node(obj, RefType::Update);
                    }
                }
            }
            // TS/JS/Java: x.field = ...
            "member_expression" => {
                if let Some(obj) = target.child_by_field_name("object") {
                    if obj.kind() == "identifier" {
                        self.add_ref_from_node(obj, RefType::Update);
                    }
                }
            }
            // Go: x.field = ...
            "selector_expression" => {
                if let Some(operand) = target.child_by_field_name("operand") {
                    if operand.kind() == "identifier" {
                        self.add_ref_from_node(operand, RefType::Update);
                    }
                }
            }
            // Rust: x.field = ...
            "field_expression" => {
                if let Some(value) = target.child_by_field_name("value") {
                    if value.kind() == "identifier" {
                        self.add_ref_from_node(value, RefType::Update);
                    }
                }
            }
            // Python: x[i] = ...
            "subscript" => {
                if let Some(obj) = target.child_by_field_name("value") {
                    if obj.kind() == "identifier" {
                        self.add_ref_from_node(obj, RefType::Update);
                    }
                }
            }
            // TS/JS/Java: x[i] = ...
            "subscript_expression" => {
                if let Some(obj) = target.child_by_field_name("object") {
                    if obj.kind() == "identifier" {
                        self.add_ref_from_node(obj, RefType::Update);
                    }
                }
            }
            // Go: x[i] = ...
            "index_expression" => {
                if let Some(operand) = target.child_by_field_name("operand") {
                    if operand.kind() == "identifier" {
                        self.add_ref_from_node(operand, RefType::Update);
                    }
                }
            }
            // PHP variable name
            "variable_name" => {
                self.add_ref_from_node(target, RefType::Definition);
            }
            _ => {}
        }

        Ok(())
    }

    /// Process augmented assignment (x += ...)
    fn process_augmented_assignment(&mut self, node: Node) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Update);
            }
        }

        // The right side contains uses
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, 1)?;
        }

        Ok(())
    }

    /// Process for loop (loop variable is a definition)
    fn process_for_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Python: for_statement has "left" (loop var) and "right" (iterable)
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_assignment_targets(left)?;
        }

        // The iterable is a use
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        // Process the body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// Process with statement
    fn process_with_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "with_item" {
                // Process the context expression (use)
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
                // Process the alias (definition)
                if let Some(alias) = child.child_by_field_name("alias") {
                    if alias.kind() == "identifier" {
                        self.add_ref_from_node(alias, RefType::Definition);
                    }
                }
            }
        }

        // Process the body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// Process exception handler
    fn process_exception_handler(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // except Exception as e: -> e is a definition
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // Process the body
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "block" {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // TypeScript/JavaScript processing
    // =====================================================================

    /// Process JS/TS declaration: let x = ...; const x = ...; var x = ...;
    /// AST: lexical_declaration -> variable_declarator (name, value)
    ///      variable_declaration -> variable_declarator (name, value)
    fn process_js_ts_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    } else {
                        // Could be destructuring pattern
                        self.extract_assignment_targets(name_node)?;
                    }
                }
                // "value" field is the initializer
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// Process JS/TS for-of: for (const item of items) { ... }
    fn process_js_for_of(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // left field: the loop variable declaration or identifier
        if let Some(left) = node.child_by_field_name("left") {
            // Could be a lexical_declaration like "const item"
            if left.kind() == "lexical_declaration" || left.kind() == "variable_declaration" {
                let mut cursor = left.walk();
                for child in left.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                self.add_ref_from_node(name_node, RefType::Definition);
                            }
                        }
                    }
                }
            } else if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Definition);
            }
        }

        // right field: the iterable (use)
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        // body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // C-style assignment processing (TS/JS/Java/C/C++/Rust)
    // =====================================================================

    /// Process C-style assignment expression: x = ...
    /// Used by TS/JS, Java, C, C++, Rust
    fn process_c_style_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Definition);
            } else {
                // Could be member expression, subscript, etc.
                self.extract_assignment_targets(left)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Process C-style augmented assignment: x += ..., x -= ...
    fn process_c_style_augmented_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Update);
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Rust processing
    // =====================================================================

    /// Process Rust let declaration: let x = ...; let mut x = ...;
    /// Also handles the `let_condition` form used inside `while let` /
    /// `if let` (rust-dataflow-v1 / v0.4.2 bug-C2).
    ///
    /// AST: let_declaration -> pattern, value
    ///      let_condition   -> pattern, value (same fields)
    ///
    /// Pattern kinds recognised (each adds the bound identifier(s) as
    /// `RefType::Definition` via [`extract_rust_binding_identifiers`]):
    /// * `identifier`               — `let x = ...`
    /// * `mut_pattern`              — `let mut x = ...`
    /// * `tuple_pattern`            — `let (a, b) = ...`
    /// * `tuple_struct_pattern`     — `let Some(c) = ...`, `let Ok(v) = ...`
    /// * `reference_pattern`        — `let &x = ...`, `let &mut y = ...`,
    ///                                 also `let &Some(z) = ...` (recurses)
    /// * `or_pattern`               — `let Some(a) | None = ...` (recurses
    ///                                 into each alternative; the same
    ///                                 binding name appears in each)
    /// * `struct_pattern`           — `let Foo { field: x, y } = ...`
    ///   (handles both `field: binding` and shorthand `field`)
    /// * `_` (wildcard)             — produces no binding (intentional)
    ///
    /// Anything else falls through silently to preserve forward-compat
    /// with future tree-sitter-rust grammar updates.
    fn process_rust_let(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field contains the binding
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_rust_binding_identifiers(pattern);
        }

        // "value" field contains the initializer (a use)
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // let-else: `let Pat = expr else { diverge };` carries an `else`
        // block of arbitrary statements which may themselves declare or
        // use variables. tree-sitter exposes the block as an unnamed
        // child after the `else` keyword. Visit any block child(ren)
        // that follow the value to capture refs inside the divergence.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "block" {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Recursively descend a Rust binding pattern and register every
    /// bound identifier as `RefType::Definition`.
    ///
    /// Used by `process_rust_let` and `process_rust_for` to support the
    /// full set of pattern kinds that real Rust code uses (see
    /// `process_rust_let` doc for the matrix). The walker is a small
    /// hand-written recursive descent rather than a generic visitor
    /// because the binding/constructor distinction inside
    /// `tuple_struct_pattern` (first identifier is the constructor, not
    /// a binding) and the field-vs-binding split inside `struct_pattern`
    /// require kind-aware handling.
    fn extract_rust_binding_identifiers(&mut self, pattern: Node) {
        match pattern.kind() {
            "identifier" => {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
            "mut_pattern" => {
                // `let mut x = ...` — single inner identifier.
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        self.add_ref_from_node(child, RefType::Definition);
                        break;
                    } else if child.is_named() && child.kind() != "mutable_specifier" {
                        // Recurse into nested patterns (rare but valid).
                        self.extract_rust_binding_identifiers(child);
                        break;
                    }
                }
            }
            "tuple_pattern" => {
                // `let (a, b) = ...` — every named pattern child is a binding.
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "tuple_struct_pattern" => {
                // `let Some(c) = ...`, `let Ok(v) = ...`, `let Variant(a, b) = ...`.
                // tree-sitter shape: [identifier(ctor) | scoped_identifier(ctor),
                //                     (, <pattern>*, )].
                // The first named child is the constructor — NOT a binding —
                // every subsequent named pattern child is.
                let mut cursor = pattern.walk();
                let mut seen_ctor = false;
                for child in pattern.children(&mut cursor) {
                    if !child.is_named() {
                        continue;
                    }
                    if !seen_ctor {
                        seen_ctor = true;
                        // Constructor identifier is not a variable binding.
                        continue;
                    }
                    self.extract_rust_binding_identifiers(child);
                }
            }
            "reference_pattern" => {
                // `let &x = ...`, `let &mut y = ...`, `let &Some(z) = ...`.
                // Layout: [&, mutable_specifier?, <inner_pattern>].
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() && child.kind() != "mutable_specifier" {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "or_pattern" => {
                // `let Some(a) | None = ...` — each alternative is a pattern;
                // recurse into all of them. Rust requires every alternative
                // to bind the same identifiers, but emitting per-arm
                // definitions is harmless (the reaching-defs analyzer
                // deduplicates by name+line).
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "struct_pattern" => {
                // `let Foo { field: x, y } = ...`.
                // Children: [type_identifier(or scoped), {, field_pattern*, }].
                // Each field_pattern is `[field_identifier, :, pattern]`
                // (with binding) or `[field_identifier]` (shorthand: the
                // field_identifier itself IS the binding name).
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.kind() == "field_pattern" {
                        let mut fcursor = child.walk();
                        let named_children: Vec<Node> =
                            child.children(&mut fcursor).filter(|c| c.is_named()).collect();
                        match named_children.len() {
                            0 => {}
                            1 => {
                                // Shorthand `{ y }` — the lone child is the
                                // field_identifier and also the binding.
                                let only = named_children[0];
                                if only.kind() == "field_identifier"
                                    || only.kind() == "identifier"
                                {
                                    self.add_ref_from_node(only, RefType::Definition);
                                }
                            }
                            _ => {
                                // `field: pattern` — the LAST named child is
                                // the binding pattern, the first is the
                                // field_identifier (which is NOT a binding).
                                let last = named_children[named_children.len() - 1];
                                self.extract_rust_binding_identifiers(last);
                            }
                        }
                    }
                }
            }
            // `_` wildcard, range_pattern, literal_pattern, etc. — no
            // identifier is bound, intentionally a no-op.
            _ => {}
        }
    }

    /// Process Rust for expression: for x in items { ... }
    /// AST: for_expression -> pattern, value, body
    ///
    /// rust-dataflow-v1: delegate the pattern walk to the shared
    /// `extract_rust_binding_identifiers` so `for &x in &items`,
    /// `for Some(c) in iter`, `for (k, v) in map`, etc. all register
    /// their bindings.
    fn process_rust_for(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field: loop variable(s)
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_rust_binding_identifiers(pattern);
        }

        // "value" field: the iterable (use)
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // "body" field: loop body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Go processing
    // =====================================================================

    /// Process Go short var declaration: x := ...
    /// AST: short_var_declaration -> left (expression_list), right (expression_list)
    fn process_go_short_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_go_lhs_identifiers(left)?;
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Process Go var declaration: var x int = 10
    /// AST: var_declaration -> var_spec (name, type, value)
    fn process_go_var_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "var_spec" {
                // "name" field contains identifier(s)
                if let Some(name) = child.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        self.add_ref_from_node(name, RefType::Definition);
                    }
                }
                // Also try iterating children for multiple names
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "identifier" {
                        // Check if this is before the type/value (it's a name)
                        let name_text = inner_child.utf8_text(self.source.as_bytes()).unwrap_or("");
                        if !name_text.is_empty() && !is_keyword(name_text, self.language) {
                            // Only add if not already added via field name
                            let already_added = self.refs.iter().any(|r| {
                                r.name == name_text
                                    && r.line == inner_child.start_position().row as u32 + 1
                                    && r.ref_type == RefType::Definition
                            });
                            if !already_added {
                                self.add_ref_from_node(inner_child, RefType::Definition);
                            }
                        }
                    }
                }
                // Process value for uses
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Process Go assignment statement: x = ...; x += ...
    fn process_go_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            // Check for operator: if it's += etc, it's an update
            let is_update = node.children(&mut node.walk()).any(|c| {
                let text = c.utf8_text(self.source.as_bytes()).unwrap_or("");
                text.ends_with('=') && text != "="
            });

            if is_update {
                self.extract_go_lhs_identifiers_as(left, RefType::Update)?;
            } else {
                self.extract_go_lhs_identifiers_as(left, RefType::Definition)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Extract Go left-hand-side identifiers as definitions
    fn extract_go_lhs_identifiers(&mut self, node: Node) -> TldrResult<()> {
        self.extract_go_lhs_identifiers_as(node, RefType::Definition)
    }

    /// Extract Go left-hand-side identifiers with specified ref type
    fn extract_go_lhs_identifiers_as(&mut self, node: Node, ref_type: RefType) -> TldrResult<()> {
        if node.kind() == "identifier" {
            let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if name != "_" {
                self.add_ref_from_node(node, ref_type);
            }
        } else if node.kind() == "expression_list" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    let name = child.utf8_text(self.source.as_bytes()).unwrap_or("");
                    if name != "_" {
                        self.add_ref_from_node(child, ref_type);
                    }
                }
            }
        }
        Ok(())
    }

    /// Process Go range clause: for i, v := range items { }
    fn process_go_range(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Range clause has "left" (expression_list with i, v) and "right" (iterable)
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_go_lhs_identifiers(left)?;
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Java processing
    // =====================================================================

    /// Process Java local variable declaration: int x = ...;
    /// AST: local_variable_declaration -> type, declarator (variable_declarator)
    fn process_java_local_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    }
                }
                // "value" field is the initializer
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Process Java enhanced for: for (int item : items) { ... }
    /// AST: enhanced_for_statement -> type, name, value, body
    fn process_java_enhanced_for(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "name" field: loop variable
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // "value" field: the iterable
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // "body" field: loop body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // C/C++ processing
    // =====================================================================

    /// Process C/C++ declaration: int x = ...; int x, y;
    /// AST: declaration -> type, declarator (init_declarator or identifier)
    fn process_c_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                // init_declarator has "declarator" and "value" fields
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if declarator.kind() == "identifier" {
                        self.add_ref_from_node(declarator, RefType::Definition);
                    } else if declarator.kind() == "pointer_declarator" {
                        // *x = ... -> find the identifier
                        let mut inner = declarator.walk();
                        for inner_child in declarator.children(&mut inner) {
                            if inner_child.kind() == "identifier" {
                                self.add_ref_from_node(inner_child, RefType::Definition);
                                break;
                            }
                        }
                    }
                }
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            } else if child.kind() == "identifier" {
                // Plain declaration without initializer: int x;
                let text = child.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !text.is_empty() && !is_keyword(text, self.language) {
                    self.add_ref_from_node(child, RefType::Definition);
                }
            }
        }

        Ok(())
    }

    // =====================================================================
    // PHP processing
    // =====================================================================

    /// Process PHP foreach: foreach ($arr as $key => $val) { }
    fn process_php_foreach(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Iterate children to find the loop variable(s)
        let mut cursor = node.walk();
        let mut found_as = false;
        for child in node.children(&mut cursor) {
            if child.kind() == "as" {
                found_as = true;
                continue;
            }
            if found_as && (child.kind() == "variable_name" || child.kind() == "pair") {
                if child.kind() == "variable_name" {
                    self.add_ref_from_node(child, RefType::Definition);
                } else {
                    // pair: $key => $val
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "variable_name" {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                        }
                    }
                }
                break;
            }
        }

        // Process body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Scala processing
    // =====================================================================

    /// Process Scala val/var: val x = ...; var x = ...
    fn process_scala_val_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field contains the binding
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        }
        // Also try "name" field
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // "value" or "body" field for the initializer
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Elixir processing
    // =====================================================================

    /// Process Elixir match operator: x = ... (pattern matching)
    /// Handles both "match_operator" and "binary_operator" with "=" operator
    fn process_elixir_match(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Try field names first (match_operator uses "left"/"right")
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");

        if let Some(l) = left {
            if l.kind() == "identifier" {
                self.add_ref_from_node(l, RefType::Definition);
            }
        } else {
            // binary_operator: first named child is the LHS
            let mut cursor = node.walk();
            let named_children: Vec<_> = node
                .children(&mut cursor)
                .filter(|c| c.is_named())
                .collect();
            if named_children.len() >= 2 && named_children[0].kind() == "identifier" {
                self.add_ref_from_node(named_children[0], RefType::Definition);
            }
        }

        if let Some(r) = right {
            self.extract_refs_from_node(r, depth + 1)?;
        } else {
            // binary_operator: last named child is the RHS
            let mut cursor = node.walk();
            let named_children: Vec<_> = node
                .children(&mut cursor)
                .filter(|c| c.is_named())
                .collect();
            if named_children.len() >= 2 {
                self.extract_refs_from_node(*named_children.last().unwrap(), depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // Lua/Luau processing
    // =====================================================================

    /// Process Lua local declaration: local x = ...
    /// AST: variable_declaration -> local, assignment_statement -> variable_list -> identifier(s), = , expression_list
    /// Also handles simpler form: variable_declaration -> local, identifier(s)
    fn process_lua_local_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                // Simple form: local x (no assignment)
                self.add_ref_from_node(child, RefType::Definition);
            } else if child.kind() == "assignment_statement" {
                // Full form: local y = x + 1
                // assignment_statement has variable_list and expression_list children
                self.process_lua_assignment_statement(child, depth)?;
            }
        }
        Ok(())
    }

    /// Process Lua assignment statement: x = expr or x, y = expr1, expr2
    /// AST: assignment_statement -> variable_list -> identifier(s), = , expression_list -> expression(s)
    fn process_lua_assignment_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_list" {
                // Extract all identifiers as definitions
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                    } else if inner_child.kind() == "dot_index_expression"
                        || inner_child.kind() == "bracket_index_expression"
                    {
                        // x.field = ... or x[i] = ... -> update
                        let mut deep = inner_child.walk();
                        for deep_child in inner_child.children(&mut deep) {
                            if deep_child.kind() == "identifier" {
                                self.add_ref_from_node(deep_child, RefType::Update);
                                break;
                            }
                        }
                    }
                }
            } else if child.kind() == "expression_list" {
                // Process the value expressions for uses
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    // =====================================================================
    // Kotlin processing
    // =====================================================================

    /// Process Kotlin property declaration: val x = ...; var x = ...
    /// AST: property_declaration -> (val/var) variable_declaration (identifier) = expression
    fn process_kotlin_property(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Find the variable_declaration child which contains the identifier
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                // variable_declaration has an identifier child
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                        break;
                    }
                }
            }
        }

        // Process the value expression (after "=")
        // The value is typically the last named child after "="
        let mut cursor2 = node.walk();
        let mut found_eq = false;
        for child in node.children(&mut cursor2) {
            if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "=" {
                found_eq = true;
                continue;
            }
            if found_eq && child.is_named() {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // Swift processing
    // =====================================================================

    /// Process Swift property declaration: let y = ...; var z = ...
    /// AST: property_declaration -> value_binding_pattern (let/var), pattern -> simple_identifier, =, expression
    /// Also handles: property_declaration -> value_binding_pattern, typed_pattern -> pattern -> simple_identifier, type_annotation
    fn process_swift_property(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Find the variable name: look for pattern -> simple_identifier or simple_identifier
        let mut cursor = node.walk();
        let mut found_name = false;
        let mut found_eq = false;

        for child in node.children(&mut cursor) {
            match child.kind() {
                "pattern" => {
                    // pattern -> simple_identifier
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "simple_identifier" {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                            found_name = true;
                            break;
                        }
                    }
                }
                "typed_pattern" => {
                    // typed_pattern -> pattern -> simple_identifier, type_annotation
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "pattern" {
                            let mut deep = inner_child.walk();
                            for deep_child in inner_child.children(&mut deep) {
                                if deep_child.kind() == "simple_identifier" {
                                    self.add_ref_from_node(deep_child, RefType::Definition);
                                    found_name = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                "simple_identifier" if !found_name => {
                    // Direct simple_identifier child
                    self.add_ref_from_node(child, RefType::Definition);
                    found_name = true;
                }
                _ => {
                    if !child.is_named()
                        && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                    {
                        found_eq = true;
                        continue;
                    }
                    if found_eq && child.is_named() {
                        // Process the value expression for uses
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process Swift assignment: z = z + 1
    /// AST: assignment -> directly_assignable_expression -> simple_identifier, =, expression
    fn process_swift_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        let mut found_eq = false;
        let mut processed_target = false;

        for child in node.children(&mut cursor) {
            if child.kind() == "directly_assignable_expression" {
                // Find simple_identifier inside directly_assignable_expression
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "simple_identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                        processed_target = true;
                        break;
                    }
                }
                // If no simple_identifier found, it could be a navigation_expression (member access)
                if !processed_target {
                    let mut inner2 = child.walk();
                    for inner_child in child.children(&mut inner2) {
                        if inner_child.kind() == "navigation_expression" {
                            // obj.field = ... -> obj is an Update
                            let mut deep = inner_child.walk();
                            for deep_child in inner_child.children(&mut deep) {
                                if deep_child.kind() == "simple_identifier" {
                                    self.add_ref_from_node(deep_child, RefType::Update);
                                    break;
                                }
                            }
                            processed_target = true;
                            break;
                        }
                    }
                }
            } else if !child.is_named()
                && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
            {
                found_eq = true;
            } else if found_eq && child.is_named() {
                // Process the value expression for uses
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Extract Swift function parameters as definitions
    /// Swift: function_declaration -> ... parameter (simple_identifier "x", :, user_type) ...
    /// Parameters are direct children of the function_declaration node.
    fn extract_swift_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "parameter" {
                // Find the first simple_identifier inside the parameter (the name)
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "simple_identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    // =====================================================================
    // Elixir parameter extraction
    // =====================================================================

    /// Extract Elixir function parameters as definitions.
    ///
    /// Two AST shapes are recognized:
    ///
    /// 1. No guard:
    ///    `(call (identifier "def") (arguments (call (identifier "foo") (arguments (identifier "x")))))`
    /// 2. With guard (`def foo(x) when is_atom(x)`):
    ///    `(call (identifier "def")
    ///           (arguments (binary_operator
    ///                          left:  (call (identifier "foo") (arguments (identifier "x")))
    ///                          op:    "when"
    ///                          right: (guard expr))
    ///                      (do_block ...)))`
    ///
    /// Without recognizing the `binary_operator` wrapper (P11.BUG-AGG-16),
    /// guarded functions had their parameters silently dropped from the
    /// DFG which made `reaching-defs`/`slice`/`taint` unable to resolve them.
    fn extract_elixir_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        if func_node.kind() != "call" {
            return Ok(());
        }

        // Find the inner call with the function name and its arguments
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "arguments" {
                // Inside arguments, look for a call node (function name + params).
                // For guarded functions, descend through binary_operator first.
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "call" {
                        self.extract_elixir_param_idents_from_call(inner_child);
                    } else if inner_child.kind() == "binary_operator" {
                        // Guard clause `LHS when RHS`: function signature lives
                        // on the left of the binary_operator.
                        let mut bin = inner_child.walk();
                        for bin_child in inner_child.children(&mut bin) {
                            if bin_child.kind() == "call" {
                                self.extract_elixir_param_idents_from_call(bin_child);
                                // The function-call form is the LHS; the RHS
                                // is the guard expression itself, which is
                                // not a parameter source.
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Helper: given an Elixir `call` node representing the function head
    /// (`foo(x, y)`), extract each `arguments`-level identifier as a
    /// parameter definition.
    fn extract_elixir_param_idents_from_call(&mut self, call_node: Node) {
        if let Some(args) = call_node.child(1) {
            if args.kind() == "arguments" {
                let mut args_cursor = args.walk();
                for arg in args.children(&mut args_cursor) {
                    if arg.kind() == "identifier" {
                        self.add_ref_from_node(arg, RefType::Definition);
                    }
                }
            }
        }
    }

    // =====================================================================
    // OCaml processing
    // =====================================================================

    /// Extract OCaml function parameters as definitions
    /// OCaml: (let_binding (value_name "foo") (parameter (value_pattern "x")) body: ...)
    fn extract_ocaml_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        // For value_definition, drill into let_binding
        let binding = if func_node.kind() == "value_definition" {
            let mut cursor = func_node.walk();
            let mut found = None;
            for child in func_node.children(&mut cursor) {
                if child.kind() == "let_binding" {
                    found = Some(child);
                    break;
                }
            }
            found
        } else if func_node.kind() == "let_binding" {
            Some(func_node)
        } else {
            None
        };

        if let Some(binding) = binding {
            let mut cursor = binding.walk();
            for child in binding.children(&mut cursor) {
                if child.kind() == "parameter" {
                    // parameter contains value_pattern with the param name
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "value_pattern"
                            || inner_child.kind() == "value_name"
                            || inner_child.kind() == "identifier"
                        {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process OCaml let_expression: let x = expr in body
    /// AST: (let_expression (value_definition (let_binding ...)) "in" body)
    fn process_ocaml_let_expression(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_refs_from_node(child, depth + 1)?;
        }
        Ok(())
    }

    /// Process OCaml value_definition: let binding(s)
    fn process_ocaml_value_definition(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                self.process_ocaml_let_binding(child, depth)?;
            }
        }
        Ok(())
    }

    /// Process OCaml let_binding: pattern = expression
    /// AST: (let_binding (value_name "y") = (expression))
    fn process_ocaml_let_binding(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // The pattern/name is the first value_name child
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if pattern.kind() == "value_name" || pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        } else {
            // Fallback: find first value_name child (before "=")
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "value_name" {
                    self.add_ref_from_node(child, RefType::Definition);
                    break;
                }
                if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                {
                    break; // Stop before the RHS
                }
            }
        }

        // Process the body/value for uses
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        } else {
            // Fallback: process children after "=" for uses
            let mut cursor = node.walk();
            let mut found_eq = false;
            for child in node.children(&mut cursor) {
                if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                {
                    found_eq = true;
                    continue;
                }
                if found_eq && child.is_named() {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Check if an OCaml value_name is in a use context
    fn is_ocaml_use_context(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                // Not a use if we're the pattern in a let_binding
                "let_binding" => {
                    if let Some(pattern) = parent.child_by_field_name("pattern") {
                        if self.node_contains(pattern, node) {
                            return false;
                        }
                    }
                    // Also check: first value_name before "=" is a definition
                    let mut cursor = parent.walk();
                    for child in parent.children(&mut cursor) {
                        if child.kind() == "value_name" && child.id() == node.id() {
                            return false; // This is the binding name
                        }
                        if !child.is_named()
                            && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                        {
                            break;
                        }
                    }
                }
                // Not a use if we're a parameter
                "parameter" => {
                    return false;
                }
                "value_definition" => {
                    return false; // Will be handled by value_definition processor
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Module-qualified value access `Io.read_file` is parsed
                // as `value_path` -> `module_path` + `value_name`. The
                // `value_name` is a name-segment of a path, not a local
                // variable reference. Without this rule, the audit on
                // `ocaml-dune/.../run_expect_test` flagged `read_file`,
                // `async`, `unlink_no_err`, `to_string`, etc. as
                // definite-uninitialized.
                //
                // We treat ANY `value_name` whose parent is `value_path`
                // as not-a-use — even an unqualified `value_path`
                // wrapping a single `value_name`. Bare unqualified
                // value references in OCaml that have no in-function
                // definition are typically top-level let bindings,
                // module-included values, or std-library functions —
                // none of which is a local-variable use in the
                // reaching-defs sense. (Function arguments and let-
                // bound names still carry their definitions, which
                // populate the reaching-defs report normally.)
                "value_path" => {
                    return false;
                }
                // Field-of-record access `r.f`: `f` is on the RHS of
                // `field_get_expression` and is a record-field name,
                // never a local variable use.
                "field_get_expression" => {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if self.node_contains(field, node) {
                            return false;
                        }
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// Check if a Swift simple_identifier is in a use context (not assignment target)
    fn is_swift_use_context(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                // Not a use if we're a definition target inside property_declaration
                "pattern" => {
                    // pattern is inside property_declaration -> this is a definition
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "property_declaration"
                            || grandparent.kind() == "typed_pattern"
                        {
                            return false;
                        }
                    }
                }
                "property_declaration" => {
                    return false; // Handled by process_swift_property
                }
                // Not a use if we're the target of an assignment
                "directly_assignable_expression" => {
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "assignment" {
                            return false; // Handled by process_swift_assignment
                        }
                    }
                }
                // Not a use if we're a parameter name
                "parameter" => {
                    return false;
                }
                // Not a use if we're in a function declaration name position
                "function_declaration" => {
                    return false;
                }
                // Not a use if it's a type annotation (like Int)
                "type_identifier" | "user_type" | "type_annotation" => {
                    return false;
                }
                // Navigation expression (member access): foo.bar -> foo is a use, bar is not
                "navigation_expression" => {
                    // The suffix (after .) is not a use - only the target object is
                    if let Some(suffix) = parent.child_by_field_name("suffix") {
                        if suffix.id() == node.id() {
                            return false;
                        }
                    }
                    // Check if this is the last simple_identifier (method/field name)
                    let mut cursor = parent.walk();
                    let children: Vec<_> = parent
                        .children(&mut cursor)
                        .filter(|c| c.kind() == "simple_identifier")
                        .collect();
                    if children.len() >= 2 {
                        if let Some(last) = children.last() {
                            if last.id() == node.id() {
                                return false; // This is the field/method name, not a use
                            }
                        }
                    }
                }
                // Value binding pattern (let/var keyword) - not relevant
                "value_binding_pattern" => {
                    return false;
                }
                _ => {}
            }
        }
        // Also check grandparent for nested cases
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                // typed_pattern -> pattern -> simple_identifier (this is a definition)
                if parent.kind() == "pattern" && grandparent.kind() == "typed_pattern" {
                    return false;
                }
            }
        }
        true
    }

    /// Check if an identifier is in a "use" context (not assignment target)
    ///
    /// Multi-language: checks parent node kinds for all supported languages
    /// to determine if this identifier is a target of assignment/declaration
    /// (and therefore NOT a use).
    fn is_use_context(&self, node: Node) -> bool {
        // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala method/field
        // names on the rhs of `field_expression` (`Tracing.calculateTracingEvent`
        // -> `calculateTracingEvent`) are member references, not local
        // variable uses. They have no defining write in the function body
        // and would otherwise be flagged as definite-uninitialized.
        if matches!(self.language, Language::Scala) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "field_expression" {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Method name in `obj.method(args)` / `method(args)` —
                // call_expression's `function` field is the callee. When
                // that callee is a bare identifier (no dot), it's a
                // free-function or local-method invocation; treat the
                // callee identifier as not-a-variable-use to avoid
                // flagging compile-time-resolved methods like
                // `calculateTracingEvent` (or local DSL helpers) as
                // uninitialized.
                if parent.kind() == "call_expression" {
                    if let Some(func_field) = parent.child_by_field_name("function") {
                        if func_field.id() == node.id() {
                            return false;
                        }
                    }
                }
            }
        }
        // AGG13-15 (quality-metrics-and-schema-v1): Java/C# method-name
        // and imported-type identifiers are NOT variable uses. The
        // pre-fix output flagged `PageRequest`, `Sort`, `of`,
        // `findByLastNameStartingWith` (in `PageRequest.of(...)` and
        // `owners.findByLastNameStartingWith(...)`) as `uninitialized`
        // variables with `severity: definite`. Classify these out of
        // the use-context set so they never enter the reaching-defs
        // analyzer in the first place.
        if matches!(self.language, Language::Java | Language::CSharp) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                // Method name: `obj.method()` -> `method` is the `name`
                // field of `method_invocation` / `invocation_expression`.
                // It is never a variable reference.
                if matches!(pkind, "method_invocation" | "invocation_expression") {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // C# `member_access_expression` and Java `field_access`
                // member name. `BsonReaderState.Normal` -> `Normal` is
                // the `name` field. It's an enum-member / type-member /
                // method-group reference, never a local variable use.
                // (The receiver suppression below already handles the
                // `BsonReaderState` half via imported_type_names; the
                // `Normal` half stays flagged without this rule.)
                if matches!(pkind, "member_access_expression" | "field_access") {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Field-access receiver / method-invocation receiver
                // matching an imported type name: `PageRequest.of(...)`,
                // `Sort.by(...)`. The text of the identifier matches a
                // simple name we collected from the file's
                // `import_declaration` list.
                if matches!(
                    pkind,
                    "method_invocation"
                        | "invocation_expression"
                        | "field_access"
                        | "member_access_expression"
                ) {
                    let object_field = parent
                        .child_by_field_name("object")
                        .or_else(|| parent.child_by_field_name("expression"));
                    if let Some(obj) = object_field {
                        if obj.id() == node.id() {
                            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                            if !text.is_empty() && self.imported_type_names.contains(text) {
                                return false;
                            }
                        }
                    }
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Bare-identifier callee: `ReadNormalAsync(token)` ->
                // the `function` field of `invocation_expression` is a
                // bare identifier matching a same-file method
                // declaration name. When collect_imports has registered
                // the method name, the receiver-less call is a known
                // method reference, not a local variable use.
                if matches!(pkind, "method_invocation" | "invocation_expression") {
                    if let Some(func_field) = parent.child_by_field_name("function") {
                        if func_field.id() == node.id() {
                            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                            if !text.is_empty() && self.imported_type_names.contains(text) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // TypeScript / JavaScript classification rules:
        //   1. `obj.property` -> `property` (the `property` field of
        //      `member_expression`) is a member reference, not a use.
        //      This catches `Array.isArray`, `util.compute`, `Ns.frob`,
        //      `obj.method` etc. — none of which are local-variable uses.
        //   2. Receiver/callee/constructor/type-annotation suppression
        //      when the identifier matches an import / hoisted-function
        //      / built-in global (collected at file level by
        //      `collect_imports`). Position-independent so type-
        //      annotation positions (`x: Browser.Interface`) are
        //      classified as not-a-use without needing a separate per-
        //      parent rule for every TS type-position node.
        if matches!(self.language, Language::TypeScript | Language::JavaScript) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                if pkind == "member_expression" {
                    if let Some(prop) = parent.child_by_field_name("property") {
                        if prop.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Shorthand property in an object: `{ engines: engines }`
                // — only the value (right) is a use, not the key (left).
                if pkind == "pair" {
                    if let Some(key) = parent.child_by_field_name("key") {
                        if key.id() == node.id() {
                            return false;
                        }
                    }
                }
            }
            // Position-independent suppression: if the bare identifier
            // matches a file-level import / hoisted function decl /
            // built-in global, it is never a local-variable use.
            // (Locals shadowing imports are still added as defs via
            // their own declaration node, so the shadowed use is not
            // missed — the def line will simply equal the use line for
            // single-statement locals, which the reaching-defs analyzer
            // handles correctly.)
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if !text.is_empty() && self.imported_type_names.contains(text) {
                return false;
            }
        }

        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // Lua / Luau classification rules:
        //   1. `m.field` -> `field` (the `field` field of
        //      `dot_index_expression`) is a table-member reference,
        //      not a use. This catches `m.onWatch`, `T.querytab`.
        //   2. `{ key = value }` -> `key` (the `name` field of `field`
        //      inside `table_constructor`) is a string key, not a use.
        //      Catches `cache = {}` in `m.openMap = { cache = {} }`.
        //   3. Receiver suppression when receiver matches a file-level
        //      local / built-in global.
        if matches!(self.language, Language::Lua | Language::Luau) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                if pkind == "dot_index_expression" {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if field.id() == node.id() {
                            return false;
                        }
                    }
                }
                if pkind == "field" {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Method invocation `m:method(...)`: `method` is on the
                // RHS of `method_index_expression`. Suppress.
                if pkind == "method_index_expression" {
                    if let Some(method) = parent.child_by_field_name("method") {
                        if method.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Identifier matches a file-level local or global —
                // suppress it as a not-a-use entirely. This handles
                // module-table receivers (`m` in `m.open`) and globals
                // like `print` / `assert`.
                let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !text.is_empty() && self.imported_type_names.contains(text) {
                    return false;
                }
                // Suppress identifiers whose grandparent is a variable
                // node (lua `variable` wraps `identifier`) only when the
                // node was already filtered above. We don't need extra
                // handling here.
                let _ = pkind;
            }
        }

        if let Some(parent) = node.parent() {
            if let Some(is_use) = self.parent_use_context(parent, node) {
                return is_use;
            }
        }
        if let Some(is_use) = self.expression_list_grandparent_use_context(node) {
            return is_use;
        }
        true
    }

    fn parent_use_context(&self, parent: Node, node: Node) -> Option<bool> {
        let kind = parent.kind();

        if matches!(
            kind,
            "assignment" | "for_statement" | "for_in_statement" | "augmented_assignment"
        ) {
            return self
                .left_field_contains(parent, node)
                .map(|contains| !contains);
        }
        if matches!(
            kind,
            "parameters"
                | "parameter"
                | "typed_parameter"
                | "default_parameter"
                | "formal_parameters"
                | "required_parameter"
                | "optional_parameter"
                | "parameter_declaration"
                | "formal_parameter"
                | "function_value_parameters"
        ) {
            return Some(false);
        }
        if matches!(self.language, Language::Kotlin)
            && matches!(kind, "property_declaration" | "variable_declaration")
        {
            return Some(false);
        }

        if kind == "variable_declarator" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }
        if matches!(kind, "lexical_declaration" | "variable_declaration")
            && !matches!(self.language, Language::Lua | Language::Luau)
        {
            return Some(false);
        }
        if matches!(
            kind,
            "assignment_expression" | "augmented_assignment_expression"
        ) {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if kind == "let_declaration" || kind == "for_expression" {
            if let Some(pattern) = parent.child_by_field_name("pattern") {
                if self.node_contains(pattern, node) {
                    return Some(false);
                }
            }
        }
        if kind == "mut_pattern" {
            return Some(false);
        }

        if matches!(
            kind,
            "short_var_declaration" | "assignment_statement" | "range_clause"
        ) {
            if let Some(left) = parent.child_by_field_name("left") {
                if self.node_contains(left, node) {
                    return Some(false);
                }
            }
        }
        if kind == "var_spec" {
            if let Some(name) = parent.child_by_field_name("name") {
                if self.node_contains(name, node) {
                    return Some(false);
                }
            }
        }

        if kind == "local_variable_declaration" {
            return Some(false);
        }
        if kind == "enhanced_for_statement" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if kind == "declaration" && matches!(self.language, Language::C | Language::Cpp) {
            return Some(false);
        }
        if kind == "init_declarator" {
            if let Some(declarator) = parent.child_by_field_name("declarator") {
                if self.node_contains(declarator, node) {
                    return Some(false);
                }
            }
        }

        if kind == "operator_assignment" {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if matches!(kind, "val_definition" | "var_definition") {
            if let Some(pattern) = parent.child_by_field_name("pattern") {
                if self.node_contains(pattern, node) {
                    return Some(false);
                }
            }
            if let Some(name) = parent.child_by_field_name("name") {
                if self.node_contains(name, node) {
                    return Some(false);
                }
            }
        }

        if matches!(self.language, Language::Elixir) && kind == "match_operator" {
            if let Some(left) = parent.child_by_field_name("left") {
                if self.node_contains(left, node) {
                    return Some(false);
                }
            }
        }
        if matches!(self.language, Language::Elixir)
            && kind == "binary_operator"
            && self.is_elixir_match_lhs(parent, node)
        {
            return Some(false);
        }

        None
    }

    fn expression_list_grandparent_use_context(&self, node: Node) -> Option<bool> {
        let parent = node.parent()?;
        if parent.kind() != "expression_list" {
            return None;
        }
        let grandparent = parent.parent()?;
        if !matches!(
            grandparent.kind(),
            "short_var_declaration" | "assignment_statement" | "range_clause"
        ) {
            return None;
        }
        let left = grandparent.child_by_field_name("left")?;
        Some(!self.node_contains(left, node))
    }

    fn left_field_contains(&self, node: Node, target: Node) -> Option<bool> {
        node.child_by_field_name("left")
            .map(|left| self.node_contains(left, target))
    }

    fn is_elixir_match_lhs(&self, parent: Node, node: Node) -> bool {
        let is_match = parent.children(&mut parent.walk()).any(|child| {
            !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
        });
        if !is_match {
            return false;
        }

        let mut cursor = parent.walk();
        for child in parent.children(&mut cursor) {
            if child.is_named() && child.id() == node.id() {
                return true;
            }
            if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "=" {
                break;
            }
        }
        false
    }

    /// Check if ancestor node contains the target node
    fn node_contains(&self, ancestor: Node, target: Node) -> bool {
        if ancestor.id() == target.id() {
            return true;
        }
        let mut cursor = ancestor.walk();
        for child in ancestor.children(&mut cursor) {
            if self.node_contains(child, target) {
                return true;
            }
        }
        false
    }

    /// Build def-use chains using reaching definitions analysis
    fn build_def_use_chains(&mut self, cfg: &CfgInfo) -> TldrResult<()> {
        if cfg.blocks.is_empty() {
            return Ok(());
        }

        // Compute reaching definitions
        let _reaching = compute_reaching_definitions(cfg, &self.refs);

        // Build edges by connecting uses to their reaching definitions
        // (Edges will be added during finalize)

        Ok(())
    }

    /// Finalize and produce the DfgInfo
    fn finalize(self) -> TldrResult<DfgInfo> {
        // Build edges by connecting definitions to uses for the same variable
        let mut edges = Vec::new();

        // Group refs by variable
        let mut defs_by_var: HashMap<String, Vec<&VarRef>> = HashMap::new();
        let mut uses_by_var: HashMap<String, Vec<&VarRef>> = HashMap::new();

        for r in &self.refs {
            match r.ref_type {
                RefType::Definition | RefType::Update => {
                    defs_by_var.entry(r.name.clone()).or_default().push(r);
                }
                RefType::Use => {
                    uses_by_var.entry(r.name.clone()).or_default().push(r);
                }
            }
        }

        // For each variable, connect defs to uses
        // Simple heuristic: connect each def to uses that come after it
        for (var, defs) in &defs_by_var {
            if let Some(uses) = uses_by_var.get(var) {
                for def in defs {
                    for use_ref in uses {
                        // Connect if use comes after def (simple heuristic)
                        // A more sophisticated analysis would use reaching definitions
                        if use_ref.line >= def.line {
                            edges.push(DataflowEdge {
                                var: var.clone(),
                                def_line: def.line,
                                use_line: use_ref.line,
                                def_ref: (*def).clone(),
                                use_ref: (*use_ref).clone(),
                            });
                        }
                    }
                }
            }
        }

        let variables: Vec<String> = self.variables.into_iter().collect();

        Ok(DfgInfo {
            function: self.function_name,
            refs: self.refs,
            edges,
            variables,
        })
    }
}

fn first_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
/// Built-in JS / TS globals that are universally available at module
/// scope. Listing them as "imported type names" lets the use-context
/// classifier reject `Array.isArray(...)`, `new Error(...)`, etc. as
/// not-a-variable-use so they never enter the uninit detector.
///
/// We list ECMAScript built-ins, common Node.js globals, and DOM-host
/// globals (TypeScript dom-gen audit corpus). Adding a global here is
/// a precision improvement; missing one means a false positive
/// (mechanical false positive, recoverable via this list).
const JS_TS_GLOBALS: &[&str] = &[
    // ECMAScript built-ins
    "Array", "ArrayBuffer", "Atomics", "BigInt", "BigInt64Array", "BigUint64Array", "Boolean",
    "DataView", "Date", "Error", "EvalError", "Float32Array", "Float64Array", "Function",
    "Infinity", "Int16Array", "Int32Array", "Int8Array", "Intl", "JSON", "Map", "Math", "NaN",
    "Number", "Object", "Promise", "Proxy", "RangeError", "ReferenceError", "Reflect", "RegExp",
    "Set", "String", "Symbol", "SyntaxError", "TypeError", "URIError", "Uint16Array",
    "Uint32Array", "Uint8Array", "Uint8ClampedArray", "WeakMap", "WeakRef", "WeakSet",
    "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "eval", "globalThis",
    "isFinite", "isNaN", "parseFloat", "parseInt", "undefined",
    // Common Node.js globals
    "Buffer", "console", "exports", "global", "module", "process", "require",
    "setImmediate", "setInterval", "setTimeout", "clearImmediate", "clearInterval", "clearTimeout",
    "__dirname", "__filename",
    // Browser / DOM host
    "document", "window", "navigator", "self", "location", "history",
    "fetch", "XMLHttpRequest", "FormData", "URL", "URLSearchParams",
    "localStorage", "sessionStorage",
];

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
/// Lua / Luau standard-library globals — always pre-defined.
/// Listing them lets `m.open` etc. avoid flagging `print`, `assert`,
/// `require`, `pairs`, etc. as uninitialized.
const LUA_LUAU_GLOBALS: &[&str] = &[
    // Basic functions (Lua 5.x reference manual §6.1)
    "assert", "collectgarbage", "dofile", "error", "getmetatable", "ipairs", "load",
    "loadfile", "loadstring", "next", "pairs", "pcall", "print", "rawequal", "rawget",
    "rawlen", "rawset", "require", "select", "setmetatable", "tonumber", "tostring",
    "type", "unpack", "xpcall",
    // Std-library modules (referenced as Module.fn)
    "coroutine", "debug", "io", "math", "os", "package", "string", "table", "utf8",
    // Globals
    "_G", "_VERSION", "_ENV", "arg",
    // Luau-specific globals (Roblox / Luau runtime)
    "bit32", "buffer", "task", "vector",
];

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): walk a TS/JS
/// `import_statement` subtree and collect every local binding name.
/// Handles three import shapes:
///   - default: `import Foo from "mod"` -> Foo
///   - named: `import { a, b as c } from "mod"` -> a, c
///   - namespace: `import * as Ns from "mod"` -> Ns
/// Alias takes precedence over name in named imports.
fn collect_ts_js_import_bindings(
    import_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = Vec::new();
    let mut cursor = import_node.walk();
    for c in import_node.children(&mut cursor) {
        stack.push(c);
    }
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        match kind {
            "import_specifier" => {
                // `alias` (when present) is the local binding; else `name`.
                let bound = n
                    .child_by_field_name("alias")
                    .or_else(|| n.child_by_field_name("name"));
                if let Some(b) = bound {
                    let text = b.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
            }
            "namespace_import" => {
                // `import * as Ns from ...` — the single identifier child
                // is the namespace binding.
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    if ic.kind() == "identifier" {
                        let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                        if !text.is_empty() {
                            out.insert(text.to_string());
                        }
                    }
                }
            }
            "import_clause" => {
                // The direct `identifier` child of import_clause (NOT
                // nested inside named_imports / namespace_import) is the
                // default-import binding: `import Foo from "..."`.
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    if ic.kind() == "identifier" {
                        let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                        if !text.is_empty() {
                            out.insert(text.to_string());
                        }
                    } else {
                        // Recurse into named_imports / namespace_import.
                        stack.push(ic);
                    }
                }
            }
            _ => {
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    stack.push(ic);
                }
            }
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): walk a TS/JS
/// parameters subtree and collect every identifier that is a binding
/// name. Handles plain identifiers, required_parameter / optional_parameter
/// nodes, and destructuring patterns (`{ a, b: alias }`, `[x, y]`).
///
/// The walk is intentionally aggressive: we capture every identifier
/// child anywhere under the parameter list. False positives are bounded
/// by the parameter syntax — only binding sites contain identifiers.
fn collect_ts_js_param_names(
    params_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = vec![params_node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        // Skip type annotations entirely — they reference types, not
        // bindings. `function f(x: SomeType)` should bind `x` only.
        if matches!(kind, "type_annotation" | "type_identifier") {
            continue;
        }
        if kind == "identifier" {
            // Filter out the property-key half of `{ key: alias }` —
            // when parent is `pair_pattern` and node is the `key`, it's
            // a destructuring key referencing a property name, not a
            // binding. The alias (value field) is the real binding.
            if let Some(parent) = n.parent() {
                if parent.kind() == "pair_pattern" {
                    if let Some(key) = parent.child_by_field_name("key") {
                        if key.id() == n.id() {
                            continue;
                        }
                    }
                }
            }
            let text = n.utf8_text(source.as_bytes()).unwrap_or("").trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }
        let mut inner = n.walk();
        for ic in n.children(&mut inner) {
            stack.push(ic);
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): collect
/// binding identifier names from a TS/JS `lexical_declaration` or
/// `variable_declaration` subtree. The grammar layout is
///   lexical_declaration
///     variable_declarator
///       name: identifier | destructuring_pattern
///       value: ...
/// We only capture the `name` field of each `variable_declarator` to
/// avoid pulling in identifiers from the initializer expression.
fn collect_ts_js_variable_names(
    decl_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut cursor = decl_node.walk();
    for declarator in decl_node.children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        if let Some(name) = declarator.child_by_field_name("name") {
            if name.kind() == "identifier" {
                let text = name.utf8_text(source.as_bytes()).unwrap_or("").trim();
                if !text.is_empty() {
                    out.insert(text.to_string());
                }
            } else {
                // Destructuring pattern: collect every identifier
                // child of the pattern subtree.
                collect_ts_js_param_names(name, source, out);
            }
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): collect
/// identifier names defined by a top-level `variable_declaration`
/// (the lua/luau `local x = ...` form). The grammar layout is
///   variable_declaration
///     [variable_list | assignment_statement]
///       (assignment_statement.variable_list)
///         identifier+
/// We walk the subtree looking for identifiers that appear in a
/// `variable_list` context — those are the local-binding names.
fn collect_lua_local_names(
    decl_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = vec![decl_node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if kind == "variable_list" {
            let mut inner = n.walk();
            for ic in n.children(&mut inner) {
                if ic.kind() == "identifier" {
                    let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
            }
            continue;
        }
        let mut inner = n.walk();
        for ic in n.children(&mut inner) {
            stack.push(ic);
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): depth-first
/// search under `node` (skipping `node` itself) for the first descendant
/// whose `kind()` equals `kind`. Used by `extract_lua_param` to peel a
/// tree-sitter-luau `parameter` -> `type` -> `identifier` chain.
fn first_descendant_identifier_under<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = Vec::new();
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        stack.push(c);
    }
    while let Some(n) = stack.pop() {
        if n.kind() == kind {
            return Some(n);
        }
        let mut inner = n.walk();
        for c in n.children(&mut inner) {
            stack.push(c);
        }
    }
    None
}

/// AGG13-15 (quality-metrics-and-schema-v1): walk a node in source order
/// (depth-first, children left-to-right) and return the text of the
/// *last* `identifier` / `type_identifier` / `name` child encountered.
/// Used by `DfgBuilder::collect_imports` to peel `java.util.List` -> `List`
/// and `import a.b.C.method` -> `method`.
///
/// We deliberately use a recursive walk (not a stack) so the
/// "last identifier in source order" semantics is unambiguous.
fn last_identifier_text(node: Node, source: &str) -> Option<String> {
    fn walk(n: Node, source: &str, last: &mut Option<String>) {
        let kind = n.kind();
        if matches!(kind, "identifier" | "type_identifier" | "name") {
            *last = Some(n.utf8_text(source.as_bytes()).unwrap_or("").to_string());
        }
        for child in n.children(&mut n.walk()) {
            walk(child, source, last);
        }
    }
    let mut last = None;
    walk(node, source, &mut last);
    last.filter(|s| !s.is_empty())
}

/// Check if a name is a language keyword
fn is_keyword(name: &str, language: Language) -> bool {
    match language {
        Language::Python => matches!(
            name,
            "False"
                | "None"
                | "True"
                | "and"
                | "as"
                | "assert"
                | "async"
                | "await"
                | "break"
                | "class"
                | "continue"
                | "def"
                | "del"
                | "elif"
                | "else"
                | "except"
                | "finally"
                | "for"
                | "from"
                | "global"
                | "if"
                | "import"
                | "in"
                | "is"
                | "lambda"
                | "nonlocal"
                | "not"
                | "or"
                | "pass"
                | "raise"
                | "return"
                | "try"
                | "while"
                | "with"
                | "yield"
        ),
        Language::TypeScript | Language::JavaScript => matches!(
            name,
            "break"
                | "case"
                | "catch"
                | "class"
                | "const"
                | "continue"
                | "debugger"
                | "default"
                | "delete"
                | "do"
                | "else"
                | "enum"
                | "export"
                | "extends"
                | "false"
                | "finally"
                | "for"
                | "function"
                | "if"
                | "import"
                | "in"
                | "instanceof"
                | "let"
                | "new"
                | "null"
                | "return"
                | "static"
                | "super"
                | "switch"
                | "this"
                | "throw"
                | "true"
                | "try"
                | "typeof"
                | "undefined"
                | "var"
                | "void"
                | "while"
                | "with"
                | "yield"
        ),
        Language::Go => matches!(
            name,
            "break"
                | "case"
                | "chan"
                | "const"
                | "continue"
                | "default"
                | "defer"
                | "else"
                | "fallthrough"
                | "for"
                | "func"
                | "go"
                | "goto"
                | "if"
                | "import"
                | "interface"
                | "map"
                | "package"
                | "range"
                | "return"
                | "select"
                | "struct"
                | "switch"
                | "type"
                | "var"
                | "nil"
                | "true"
                | "false"
        ),
        Language::Rust => matches!(
            name,
            "as" | "break"
                | "const"
                | "continue"
                | "crate"
                | "else"
                | "enum"
                | "extern"
                | "false"
                | "fn"
                | "for"
                | "if"
                | "impl"
                | "in"
                | "let"
                | "loop"
                | "match"
                | "mod"
                | "move"
                | "mut"
                | "pub"
                | "ref"
                | "return"
                | "self"
                | "Self"
                | "static"
                | "struct"
                | "super"
                | "trait"
                | "true"
                | "type"
                | "unsafe"
                | "use"
                | "where"
                | "while"
                | "async"
                | "await"
                | "dyn"
        ),
        Language::Java => matches!(
            name,
            "abstract"
                | "assert"
                | "boolean"
                | "break"
                | "byte"
                | "case"
                | "catch"
                | "char"
                | "class"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "implements"
                | "import"
                | "instanceof"
                | "int"
                | "interface"
                | "long"
                | "native"
                | "new"
                | "null"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "return"
                | "short"
                | "static"
                | "strictfp"
                | "super"
                | "switch"
                | "synchronized"
                | "this"
                | "throw"
                | "throws"
                | "transient"
                | "true"
                | "try"
                | "void"
                | "volatile"
                | "while"
        ),
        Language::C | Language::Cpp => matches!(
            name,
            "auto"
                | "break"
                | "case"
                | "char"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extern"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "int"
                | "long"
                | "register"
                | "return"
                | "short"
                | "signed"
                | "sizeof"
                | "static"
                | "struct"
                | "switch"
                | "typedef"
                | "union"
                | "unsigned"
                | "void"
                | "volatile"
                | "while"
                | "NULL"
        ),
        Language::Ruby => matches!(
            name,
            "alias"
                | "and"
                | "begin"
                | "break"
                | "case"
                | "class"
                | "def"
                | "do"
                | "else"
                | "elsif"
                | "end"
                | "ensure"
                | "false"
                | "for"
                | "if"
                | "in"
                | "module"
                | "next"
                | "nil"
                | "not"
                | "or"
                | "redo"
                | "rescue"
                | "retry"
                | "return"
                | "self"
                | "super"
                | "then"
                | "true"
                | "undef"
                | "unless"
                | "until"
                | "when"
                | "while"
                | "yield"
                | "puts"
                | "print"
        ),
        Language::Php => matches!(
            name,
            "abstract"
                | "and"
                | "array"
                | "as"
                | "break"
                | "callable"
                | "case"
                | "catch"
                | "class"
                | "clone"
                | "const"
                | "continue"
                | "declare"
                | "default"
                | "die"
                | "do"
                | "echo"
                | "else"
                | "elseif"
                | "empty"
                | "enddeclare"
                | "endfor"
                | "endforeach"
                | "endif"
                | "endswitch"
                | "endwhile"
                | "eval"
                | "exit"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "fn"
                | "for"
                | "foreach"
                | "function"
                | "global"
                | "goto"
                | "if"
                | "implements"
                | "include"
                | "instanceof"
                | "interface"
                | "isset"
                | "list"
                | "match"
                | "namespace"
                | "new"
                | "null"
                | "or"
                | "print"
                | "private"
                | "protected"
                | "public"
                | "require"
                | "return"
                | "static"
                | "switch"
                | "throw"
                | "trait"
                | "true"
                | "try"
                | "unset"
                | "use"
                | "var"
                | "while"
                | "xor"
                | "yield"
        ),
        Language::Kotlin => matches!(
            name,
            "abstract"
                | "annotation"
                | "as"
                | "break"
                | "by"
                | "catch"
                | "class"
                | "companion"
                | "const"
                | "constructor"
                | "continue"
                | "crossinline"
                | "data"
                | "do"
                | "else"
                | "enum"
                | "external"
                | "false"
                | "final"
                | "finally"
                | "for"
                | "fun"
                | "if"
                | "import"
                | "in"
                | "infix"
                | "init"
                | "inline"
                | "inner"
                | "interface"
                | "internal"
                | "is"
                | "lateinit"
                | "noinline"
                | "null"
                | "object"
                | "open"
                | "operator"
                | "out"
                | "override"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "reified"
                | "return"
                | "sealed"
                | "super"
                | "suspend"
                | "this"
                | "throw"
                | "true"
                | "try"
                | "typealias"
                | "val"
                | "var"
                | "vararg"
                | "when"
                | "where"
                | "while"
        ),
        Language::Elixir => matches!(
            name,
            "after"
                | "and"
                | "case"
                | "catch"
                | "cond"
                | "def"
                | "defp"
                | "defmodule"
                | "defstruct"
                | "defprotocol"
                | "defimpl"
                | "defmacro"
                | "do"
                | "else"
                | "end"
                | "false"
                | "fn"
                | "for"
                | "if"
                | "import"
                | "in"
                | "nil"
                | "not"
                | "or"
                | "raise"
                | "receive"
                | "require"
                | "rescue"
                | "true"
                | "try"
                | "unless"
                | "use"
                | "when"
                | "with"
        ),
        Language::Ocaml => matches!(
            name,
            "and"
                | "as"
                | "assert"
                | "begin"
                | "class"
                | "constraint"
                | "do"
                | "done"
                | "downto"
                | "else"
                | "end"
                | "exception"
                | "external"
                | "false"
                | "for"
                | "fun"
                | "function"
                | "functor"
                | "if"
                | "in"
                | "include"
                | "inherit"
                | "initializer"
                | "lazy"
                | "let"
                | "match"
                | "method"
                | "mod"
                | "module"
                | "mutable"
                | "new"
                | "nonrec"
                | "object"
                | "of"
                | "open"
                | "or"
                | "private"
                | "rec"
                | "sig"
                | "struct"
                | "then"
                | "to"
                | "true"
                | "try"
                | "type"
                | "val"
                | "virtual"
                | "when"
                | "while"
                | "with"
        ),
        Language::Swift => matches!(
            name,
            "associatedtype"
                | "break"
                | "case"
                | "catch"
                | "class"
                | "continue"
                | "default"
                | "defer"
                | "deinit"
                | "do"
                | "else"
                | "enum"
                | "extension"
                | "fallthrough"
                | "false"
                | "fileprivate"
                | "for"
                | "func"
                | "guard"
                | "if"
                | "import"
                | "in"
                | "init"
                | "inout"
                | "internal"
                | "is"
                | "let"
                | "nil"
                | "open"
                | "operator"
                | "private"
                | "protocol"
                | "public"
                | "repeat"
                | "rethrows"
                | "return"
                | "self"
                | "Self"
                | "static"
                | "struct"
                | "subscript"
                | "super"
                | "switch"
                | "throw"
                | "throws"
                | "true"
                | "try"
                | "typealias"
                | "var"
                | "where"
                | "while"
                | "Int"
                | "String"
                | "Bool"
                | "Double"
                | "Float"
                | "Array"
        ),
        // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala keyword set so
        // `this` (and other reserved identifiers) are not flagged as
        // uninitialized variable uses by reaching-defs. Without this arm,
        // `_ => false` falls through and `this` slips through as an
        // identifier use with no defining write — definite false positive.
        Language::Scala => matches!(
            name,
            "abstract"
                | "case"
                | "catch"
                | "class"
                | "def"
                | "do"
                | "else"
                | "enum"
                | "export"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "for"
                | "forSome"
                | "given"
                | "if"
                | "implicit"
                | "import"
                | "lazy"
                | "match"
                | "new"
                | "null"
                | "object"
                | "override"
                | "package"
                | "private"
                | "protected"
                | "return"
                | "sealed"
                | "super"
                | "then"
                | "this"
                | "throw"
                | "trait"
                | "true"
                | "try"
                | "type"
                | "val"
                | "var"
                | "while"
                | "with"
                | "yield"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function() {
        let source = r#"
def foo(x):
    y = x + 1
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(dfg.variables.contains(&"x".to_string()));
        assert!(dfg.variables.contains(&"y".to_string()));
    }

    #[test]
    fn test_extracts_definitions() {
        let source = r#"
def foo():
    x = 1
    y = 2
    return x + y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .collect();

        assert!(defs.iter().any(|r| r.name == "x"));
        assert!(defs.iter().any(|r| r.name == "y"));
    }

    #[test]
    fn test_extracts_uses() {
        let source = r#"
def foo(x):
    return x + 1
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .collect();

        assert!(uses.iter().any(|r| r.name == "x"));
    }

    #[test]
    fn test_function_not_found() {
        let source = "def foo(): pass";
        let result = get_dfg_context(source, "bar", Language::Python);
        assert!(result.is_err());
    }

    #[test]
    fn test_for_loop_variable() {
        let source = r#"
def foo(items):
    for item in items:
        print(item)
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        // 'item' should be both a definition (loop var) and a use (in print)
        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();

        assert!(
            !item_defs.is_empty(),
            "for loop variable should be a definition"
        );
    }

    #[test]
    fn test_augmented_assignment() {
        let source = r#"
def foo():
    x = 0
    x += 1
    return x
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Update)
            .collect();

        assert!(
            !updates.is_empty(),
            "augmented assignment should be an update"
        );
    }

    #[test]
    fn test_def_use_edges() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        // Should have an edge from x's definition to x's use
        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();

        assert!(!x_edges.is_empty(), "should have def-use edge for x");
    }

    // =========================================================================
    // Multi-language DFG tests
    // =========================================================================

    // --- TypeScript / JavaScript ---

    #[test]
    fn test_typescript_let_const_declaration() {
        let source = r#"
function foo(x: number) {
    let y = x + 1;
    const z = y * 2;
    return z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "should find param x"
        );
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find let y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find const z"
        );

        // y and z should be definitions
        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_typescript_assignment_expression() {
        let source = r#"
function foo() {
    let x = 0;
    x = 5;
    x += 3;
    return x;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();

        let x_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!x_defs.is_empty(), "x should have at least one definition");

        let x_updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Update)
            .collect();
        assert!(!x_updates.is_empty(), "x += 3 should produce an update ref");
    }

    #[test]
    fn test_typescript_for_of_loop() {
        let source = r#"
function foo(items: number[]) {
    for (const item of items) {
        console.log(item);
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find loop var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "for-of loop variable should be a definition"
        );
    }

    #[test]
    fn test_javascript_var_declaration() {
        let source = r#"
function foo(x) {
    var y = x + 1;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::JavaScript).unwrap();
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find var y"
        );

        let y_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "y" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!y_defs.is_empty(), "var y should be a definition");
    }

    // --- Rust ---

    #[test]
    fn test_rust_let_declaration() {
        let source = r#"
fn foo(x: i32) -> i32 {
    let y = x + 1;
    let z = y * 2;
    z
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find let y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find let z"
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_rust_assignment_expression() {
        let source = r#"
fn foo() -> i32 {
    let mut x = 0;
    x = 5;
    x += 3;
    x
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();

        // x = 5 should be a definition or update
        let x_all: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        assert!(
            x_all.len() >= 3,
            "x should have at least 3 refs (def, reassign, use), got {}",
            x_all.len()
        );
    }

    #[test]
    fn test_rust_for_expression() {
        let source = r#"
fn foo(items: Vec<i32>) {
    for item in items.iter() {
        println!("{}", item);
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find loop var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "for loop variable should be a definition"
        );
    }

    // --- Go ---

    #[test]
    fn test_go_short_var_declaration() {
        let source = r#"
func foo(x int) int {
    y := x + 1
    z := y * 2
    return z
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find y from :="
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find z from :="
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_go_var_declaration() {
        let source = r#"
func foo() int {
    var x int = 10
    var y = x + 1
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "should find var x"
        );
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find var y"
        );
    }

    #[test]
    fn test_go_assignment_statement() {
        let source = r#"
func foo() int {
    x := 0
    x = 5
    return x
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();

        let x_refs: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        // Should have: definition (:=), definition or update (=), use (return)
        assert!(
            x_refs.len() >= 3,
            "x should have at least 3 refs, got {}",
            x_refs.len()
        );
    }

    #[test]
    fn test_go_range_loop() {
        let source = r#"
func foo(items []int) {
    for i, v := range items {
        fmt.Println(i, v)
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert!(
            dfg.variables.contains(&"i".to_string()),
            "should find range var i"
        );
        assert!(
            dfg.variables.contains(&"v".to_string()),
            "should find range var v"
        );
    }

    // --- Java ---

    #[test]
    fn test_java_local_variable_declaration() {
        let source = r#"
class Foo {
    int foo(int x) {
        int y = x + 1;
        int z = y * 2;
        return z;
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find int y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find int z"
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_java_assignment_expression() {
        let source = r#"
class Foo {
    void foo() {
        int x = 0;
        x = 5;
        x += 3;
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();

        let x_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!x_defs.is_empty(), "x should have at least one definition");
    }

    #[test]
    fn test_java_enhanced_for() {
        let source = r#"
class Foo {
    void foo(int[] items) {
        for (int item : items) {
            System.out.println(item);
        }
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find enhanced for var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "enhanced for variable should be a definition"
        );
    }

    // --- C ---

    #[test]
    fn test_c_declaration() {
        let source = r#"
int foo(int x) {
    int y = x + 1;
    int z = y * 2;
    return z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::C).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find int y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find int z"
        );
    }

    #[test]
    fn test_c_assignment_expression() {
        let source = r#"
void foo() {
    int x = 0;
    x = 5;
    x += 3;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::C).unwrap();

        let x_refs: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        assert!(
            x_refs.len() >= 2,
            "x should have at least 2 refs, got {}: {:?}",
            x_refs.len(),
            x_refs
                .iter()
                .map(|r| (&r.name, &r.ref_type, r.line))
                .collect::<Vec<_>>()
        );
    }

    // --- Ruby ---

    #[test]
    fn test_ruby_assignment() {
        let source = r#"
def foo(x)
    y = x + 1
    z = y * 2
    z
end
"#;
        let dfg = get_dfg_context(source, "foo", Language::Ruby).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(dfg.variables.contains(&"y".to_string()), "should find y");
        assert!(dfg.variables.contains(&"z".to_string()), "should find z");
    }

    // --- PHP ---

    #[test]
    fn test_php_assignment() {
        let source = r#"<?php
function foo($x) {
    $y = $x + 1;
    $z = $y * 2;
    return $z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Php).unwrap();
        assert_eq!(dfg.function, "foo");
        // PHP variables include $ prefix in tree-sitter
        assert!(
            dfg.variables.contains(&"$y".to_string()) || dfg.variables.contains(&"y".to_string()),
            "should find y variable, got: {:?}",
            dfg.variables
        );
    }

    // --- Cross-language def-use edges ---

    #[test]
    fn test_typescript_def_use_edges() {
        let source = r#"
function foo() {
    let x = 1;
    let y = x + 2;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(
            !x_edges.is_empty(),
            "should have def-use edge for x in TypeScript"
        );
    }

    #[test]
    fn test_go_def_use_edges() {
        let source = r#"
func foo() int {
    x := 1
    y := x + 2
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(!x_edges.is_empty(), "should have def-use edge for x in Go");
    }

    #[test]
    fn test_rust_def_use_edges() {
        let source = r#"
fn foo() -> i32 {
    let x = 1;
    let y = x + 2;
    y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(
            !x_edges.is_empty(),
            "should have def-use edge for x in Rust"
        );
    }

    // --- Python regression tests ---

    #[test]
    fn test_python_still_works_after_multilang() {
        let source = r#"
def foo(x):
    y = x + 1
    for item in [1, 2, 3]:
        y += item
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();
        assert!(dfg.variables.contains(&"x".to_string()));
        assert!(dfg.variables.contains(&"y".to_string()));
        assert!(dfg.variables.contains(&"item".to_string()));

        let y_updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "y" && r.ref_type == RefType::Update)
            .collect();
        assert!(!y_updates.is_empty(), "y += item should be an update");

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!item_defs.is_empty(), "for item should be a definition");
    }

    // =========================================================================
    // NOGK language fix tests - These must produce definitions
    // =========================================================================

    #[test]
    fn test_kotlin_val_extraction() {
        let source = r#"
fun foo(x: Int): Int {
    val y = x + 1
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Kotlin).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Kotlin val y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "Kotlin param x should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_kotlin_var_extraction() {
        let source = r#"
fun foo(): Int {
    var count = 0
    count = count + 1
    return count
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Kotlin).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !defs.is_empty(),
            "Kotlin var count should produce definitions, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_elixir_match_extraction() {
        let source = r#"
def foo(x) do
  y = x + 1
  y
end
"#;
        let dfg = get_dfg_context(source, "foo", Language::Elixir).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Elixir y = x + 1 should produce a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_scala_val_extraction() {
        let source = r#"
def foo(x: Int): Int = {
  val y = x + 1
  y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Scala).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Scala val y should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_cpp_declaration_extraction() {
        let source = r#"
int foo(int x) {
    int y = x + 1;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Cpp).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "C++ int y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "C++ param x should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_php_assignment_extraction() {
        let source = r#"<?php
function foo($x) {
    $y = $x + 1;
    return $y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Php).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !defs.is_empty(),
            "PHP $y = $x + 1 should produce a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_ocaml_let_extraction() {
        let source = r#"
let foo x =
  let y = x + 1 in
  y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Ocaml).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y") || defs.contains(&"x"),
            "OCaml let y = x + 1 should produce definitions, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_python_assignment_extracts_defs() {
        // Regression: Python should produce definitions in reaching-defs context
        let source = r#"
def foo(x):
    y = x + 1
    z = y * 2
    return z
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Python y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "Python z should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "Python param x should be a definition, got defs: {:?}",
            defs
        );
    }

    // =========================================================================
    // Reaching-defs NOGK fix tests
    // These tests verify that Lua and Swift DFG extraction produces
    // definitions for local variable declarations and assignments.
    // =========================================================================

    // --- Lua ---

    #[test]
    fn test_lua_local_declaration_produces_defs() {
        // Lua: `local y = x + 1` should produce a definition for y
        // AST: variable_declaration -> assignment_statement -> variable_list -> identifier
        let source = r#"function foo(x)
    local y = x + 1
    return y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Lua local y should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_lua_assignment_produces_defs() {
        // Lua: `z = y * 2` should produce a definition for z
        // AST: assignment_statement -> variable_list -> identifier
        let source = r#"function foo(x)
    local y = x + 1
    z = y * 2
    return z
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"z"),
            "Lua z = ... should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_lua_local_declaration_uses() {
        // Lua: `local y = x + 1` should produce a use for x
        let source = r#"function foo(x)
    local y = x + 1
    return y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            uses.contains(&"x"),
            "Lua x in `local y = x + 1` should be a use, got uses: {:?}",
            uses
        );
        assert!(
            uses.contains(&"y"),
            "Lua y in `return y` should be a use, got uses: {:?}",
            uses
        );
    }

    #[test]
    fn test_lua_param_extraction() {
        // Lua: function parameters should be definitions
        let source = r#"function foo(x, y)
    return x + y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"x"),
            "Lua param x should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"y"),
            "Lua param y should be a definition, got defs: {:?}",
            defs
        );
    }

    // --- Swift ---

    #[test]
    fn test_swift_let_declaration_produces_defs() {
        // Swift: `let y = x + 1` should produce a definition for y
        // AST: property_declaration -> pattern -> simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    let y = x + 1
    return y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Swift let y should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_swift_var_declaration_produces_defs() {
        // Swift: `var z = y * 2` should produce a definition for z
        let source = r#"func foo(x: Int) -> Int {
    var z = x * 2
    z = z + 1
    return z
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"z"),
            "Swift var z should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_swift_assignment_produces_defs() {
        // Swift: `z = z + 1` should produce a definition for z
        // AST: assignment -> directly_assignable_expression -> simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    var z = x
    z = z + 1
    return z
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let z_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| {
                r.name == "z" && matches!(r.ref_type, RefType::Definition | RefType::Update)
            })
            .collect();
        // At minimum: var z = x (def) and z = z + 1 (def)
        assert!(
            z_defs.len() >= 2,
            "Swift z should have at least 2 def/update refs (var z = x; z = z + 1), got {}: {:?}",
            z_defs.len(),
            z_defs
        );
    }

    #[test]
    fn test_swift_uses_extraction() {
        // Swift: uses should be extracted via simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    let y = x + 1
    return y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            uses.contains(&"x"),
            "Swift x in `let y = x + 1` should be a use, got uses: {:?}",
            uses
        );
        assert!(
            uses.contains(&"y"),
            "Swift y in `return y` should be a use, got uses: {:?}",
            uses
        );
    }

    #[test]
    fn test_swift_param_extraction() {
        // Swift: function parameters should be definitions
        let source = r#"func foo(x: Int, y: Int) -> Int {
    return x + y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"x"),
            "Swift param x should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"y"),
            "Swift param y should be a definition, got defs: {:?}",
            defs
        );
    }
}
